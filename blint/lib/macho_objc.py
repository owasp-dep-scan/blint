"""Objective-C runtime metadata parsing for Mach-O binaries.

LIEF's community build does not expose Objective-C metadata, so this module
recovers classes, protocols, categories and referenced selectors by walking the
raw ``__objc_*`` sections. Pointers in modern arm64(e) binaries are stored in the
chained-fixup format; rather than decoding the chain by hand we use LIEF's
resolved relocation targets (``relocation.target``) as an address -> target map,
and fall back to the dyld binding table for pointers that bind to external
symbols (e.g. an Apple framework superclass).

Struct layouts (64-bit) follow Apple's objc4 runtime:
``class_t`` { isa, superclass, cache, vtable, data } and the read-only
``class_ro_t`` reached via ``data & ~7``. Method lists use the modern "small"
(relative offset) format as well as the legacy pointer format.
"""

import contextlib
import struct

import lief

from blint.logger import LOG

# class_t offsets
_CLASS_SUPERCLASS = 8
_CLASS_DATA = 32
# class_ro_t offsets
_RO_NAME = 0x18
_RO_BASE_METHODS = 0x20
_RO_BASE_PROTOCOLS = 0x28
# protocol_t offsets
_PROTO_NAME = 8
_PROTO_INSTANCE_METHODS = 0x18
# method_list_t small-format flag in entsizeAndFlags
_SMALL_METHOD_FLAG = 0x80000000
_ENTSIZE_MASK = 0xFFFF

# Safety caps to keep parsing bounded on hostile/corrupt inputs.
_MAX_CLASSES = 20000
_MAX_METHODS_PER_LIST = 4000
_MAX_PROTOCOLS = 10000
_MAX_STRING = 512


# Mach-O ABI64 flag in the cpu_type field; set for arm64/x86_64 binaries.
_CPU_ARCH_ABI64 = 0x01000000


class _MachoReader:
    """Reads bytes/pointers from a Mach-O by virtual address."""

    def __init__(self, parsed_obj):
        self._obj = parsed_obj
        self.imagebase = 0
        with contextlib.suppress(Exception):
            self.imagebase = parsed_obj.imagebase
        # 64-bit pointer width is assumed everywhere below; 32-bit binaries use
        # a different runtime struct layout and are handled by the caller.
        self.is_64 = True
        with contextlib.suppress(Exception):
            self.is_64 = bool(int(parsed_obj.header.cpu_type.value) & _CPU_ARCH_ABI64)
        # address -> resolved target for internal (rebased) pointers.
        self.ptr_map = {}
        with contextlib.suppress(Exception):
            for reloc in parsed_obj.relocations:
                self.ptr_map[reloc.address] = reloc.target
        # address -> external symbol name for bound pointers.
        self.bind_map = {}
        with contextlib.suppress(Exception):
            for binding in parsed_obj.bindings:
                if binding.symbol is not None and binding.symbol.name:
                    self.bind_map[binding.address] = binding.symbol.name
        # Virtual-address ranges of the mapped sections, used to validate
        # pointers recovered from the raw chained-fixup fallback.
        self._va_ranges = []
        with contextlib.suppress(Exception):
            for section in parsed_obj.sections:
                start = section.virtual_address
                if start:
                    self._va_ranges.append((start, start + section.size))

    def bytes_at(self, va, size):
        with contextlib.suppress(Exception):
            data = bytes(self._obj.get_content_from_virtual_address(va, size))
            if len(data) == size:
                return data
        return None

    def u32(self, va):
        data = self.bytes_at(va, 4)
        return struct.unpack("<I", data)[0] if data else None

    def i32(self, va):
        data = self.bytes_at(va, 4)
        return struct.unpack("<i", data)[0] if data else None

    def u64(self, va):
        data = self.bytes_at(va, 8)
        return struct.unpack("<Q", data)[0] if data else None

    def _in_image(self, va):
        return any(start <= va < end for start, end in self._va_ranges)

    def _decode_chained_pointer(self, va):
        """Recover a pointer target from a raw chained-fixup slot.

        Modern arm64(e) binaries store ``__objc_*`` pointers as dyld chained
        fixups rather than plain rebased pointers, so ``relocations`` is empty
        and ``ptr_map`` misses. The encoded entry packs the target as an offset
        from the image base; the exact field width varies by pointer format
        (auth vs rebase), so we try the documented offset widths and accept the
        first interpretation that lands inside a mapped section.
        """
        raw = self.u64(va)
        if not raw:
            return None
        candidates = (
            raw,  # already a full virtual address
            self.imagebase + (raw & 0xFFFFFFFF),  # arm64e auth: low 32-bit offset
            self.imagebase + (raw & 0xFFFFFFFFF),  # 64-bit rebase: 36-bit offset
            raw & 0x7FFFFFFFFF,  # masked direct virtual address
        )
        for candidate in candidates:
            if candidate and self._in_image(candidate):
                return candidate
        return None

    def ptr(self, va):
        """Resolved pointer stored at ``va`` (rebase target), or None."""
        target = self.ptr_map.get(va)
        if target is not None:
            return target
        return self._decode_chained_pointer(va)

    def cstring(self, va):
        if not va:
            return ""
        out = bytearray()
        for off in range(0, _MAX_STRING, 32):
            chunk = self.bytes_at(va + off, 32)
            if chunk is None:
                break
            if 0 in chunk:
                out += chunk[: chunk.index(0)]
                return out.decode("utf-8", "replace")
            out += chunk
        return out.decode("utf-8", "replace")


def _section_map(parsed_obj):
    sections = {}
    for section in parsed_obj.sections:
        # ObjC section names are unique across the binary; last one wins is fine.
        sections[section.name] = section
    return sections


def _iter_method_entries(reader, mlist_va):
    """Yield ``(name, imp)`` for each method in a method_list_t.

    ``name`` is the selector string and ``imp`` is the resolved virtual address
    of the method implementation (or ``None`` when it cannot be recovered, as is
    the case for protocol method descriptions which carry no implementation).
    Both the modern "small" relative-offset format and the legacy pointer format
    are supported.
    """
    if not mlist_va:
        return
    entsize_and_flags = reader.u32(mlist_va)
    count = reader.u32(mlist_va + 4)
    if entsize_and_flags is None or not count:
        return
    count = min(count, _MAX_METHODS_PER_LIST)
    is_small = bool(entsize_and_flags & _SMALL_METHOD_FLAG)
    entsize = entsize_and_flags & _ENTSIZE_MASK
    if entsize <= 0:
        entsize = 12 if is_small else 24
    entries_base = mlist_va + 8
    for i in range(count):
        entry = entries_base + i * entsize
        if is_small:
            # name/types/imp are stored as three self-relative int32 offsets.
            # nameOffset points at a selref slot whose pointer resolves to the
            # selector string; impOffset points directly at the implementation.
            name_off = reader.i32(entry)
            if name_off is None:
                continue
            selref = reader.ptr(entry + name_off)
            name = reader.cstring(selref) if selref else ""
            imp_off = reader.i32(entry + 8)
            imp = (entry + 8 + imp_off) if imp_off else None
        else:
            sel_ptr = reader.ptr(entry)
            name = reader.cstring(sel_ptr) if sel_ptr else ""
            imp = reader.ptr(entry + 16)
        if name:
            yield name, imp


def _parse_method_list(reader, mlist_va):
    """Return the list of method (selector) names for a method_list_t."""
    return [name for name, _imp in _iter_method_entries(reader, mlist_va)]


def _parse_protocol_list(reader, plist_va):
    """Return protocol names referenced by a protocol_list_t."""
    if not plist_va:
        return []
    count = reader.u32(plist_va)
    if not count:
        return []
    count = min(count, _MAX_PROTOCOLS)
    names = []
    for i in range(count):
        proto_va = reader.ptr(plist_va + 8 + i * 8)
        if not proto_va:
            continue
        name = reader.cstring(reader.ptr(proto_va + _PROTO_NAME))
        if name:
            names.append(name)
    return names


def _superclass_name(reader, class_va):
    """Resolve a class's superclass: internal class name or bound symbol."""
    # External superclasses bind to _OBJC_CLASS_$_<Name>.
    bound = reader.bind_map.get(class_va + _CLASS_SUPERCLASS)
    if bound:
        return bound.replace("_OBJC_CLASS_$_", "").lstrip("_")
    super_va = reader.ptr(class_va + _CLASS_SUPERCLASS)
    if not super_va:
        return ""
    ro = reader.ptr(super_va + _CLASS_DATA)
    if ro is None:
        return ""
    return reader.cstring(reader.ptr((ro & ~7) + _RO_NAME))


def _parse_class(reader, class_va, method_imps=None):
    data = reader.ptr(class_va + _CLASS_DATA)
    if data is None:
        return None
    ro = data & ~7
    name = reader.cstring(reader.ptr(ro + _RO_NAME))
    if not name:
        return None
    methods = []
    for sel, imp in _iter_method_entries(reader, reader.ptr(ro + _RO_BASE_METHODS)):
        methods.append(sel)
        # Record recovered implementation addresses so the disassembler can seed
        # functions with readable ``-[Class selector]`` names even when the
        # symbol table has been stripped.
        if imp is not None and method_imps is not None:
            method_imps.append({"name": f"-[{name} {sel}]", "address": imp})
    protocols = _parse_protocol_list(reader, reader.ptr(ro + _RO_BASE_PROTOCOLS))
    entry = {
        "name": name,
        "superclass": _superclass_name(reader, class_va),
        "method_count": len(methods),
        "methods": methods,
    }
    if protocols:
        entry["protocols"] = protocols
    return entry


def _parse_pointer_array_section(sections, name, ptr_size=8):
    """Yield (slot_va) for each pointer slot in a pointer-array section."""
    section = sections.get(name)
    if section is None:
        return
    for i in range(section.size // ptr_size):
        yield section.virtual_address + i * ptr_size


def parse_objc_metadata(parsed_obj) -> dict:
    """Parse Objective-C classes, protocols, categories and selector refs.

    Returns an empty dict for binaries without Objective-C metadata.
    """
    if not isinstance(parsed_obj, lief.MachO.Binary):
        return {}
    sections = _section_map(parsed_obj)
    if "__objc_classlist" not in sections and "__objc_protolist" not in sections:
        return {}

    reader = _MachoReader(parsed_obj)
    # The struct offsets and pointer arithmetic below follow the 64-bit objc4
    # runtime ABI. 32-bit (armv7/i386) binaries use a different layout; rather
    # than emit wrong data we skip them (they are legacy, iOS 11+ is 64-bit).
    if not reader.is_64:
        LOG.debug("Skipping ObjC metadata parsing for 32-bit Mach-O binary")
        return {}
    ptr_size = 8
    method_imps = []
    classes = []
    for slot in _parse_pointer_array_section(sections, "__objc_classlist", ptr_size):
        if len(classes) >= _MAX_CLASSES:
            break
        class_va = reader.ptr(slot)
        if not class_va:
            continue
        with contextlib.suppress(Exception):
            parsed = _parse_class(reader, class_va, method_imps)
            if parsed:
                classes.append(parsed)

    protocols = []
    for slot in _parse_pointer_array_section(sections, "__objc_protolist", ptr_size):
        proto_va = reader.ptr(slot)
        if not proto_va:
            continue
        with contextlib.suppress(Exception):
            name = reader.cstring(reader.ptr(proto_va + _PROTO_NAME))
            if not name:
                continue
            methods = _parse_method_list(reader, reader.ptr(proto_va + _PROTO_INSTANCE_METHODS))
            protocols.append({"name": name, "methods": methods})

    # Referenced selectors (__objc_selrefs) and external classes (bindings to
    # _OBJC_CLASS_$_*) are strong capability signals at message-send sites.
    selectors = []
    seen_sel = set()
    for slot in _parse_pointer_array_section(sections, "__objc_selrefs", ptr_size):
        sel = reader.cstring(reader.ptr(slot))
        if sel and sel not in seen_sel:
            seen_sel.add(sel)
            selectors.append(sel)

    external_classes = sorted(
        {
            name.replace("_OBJC_CLASS_$_", "").lstrip("_")
            for addr, name in reader.bind_map.items()
            if "_OBJC_CLASS_$_" in name
        }
    )

    if not (classes or protocols or selectors):
        return {}

    LOG.debug(
        "Parsed ObjC metadata: %d classes, %d protocols, %d selectors",
        len(classes),
        len(protocols),
        len(selectors),
    )
    # Deduplicate recovered implementations by address (the same imp can appear
    # in both a class and its metaclass method list).
    seen_imp = set()
    unique_imps = []
    for entry in method_imps:
        addr = entry["address"]
        if addr and addr not in seen_imp:
            seen_imp.add(addr)
            unique_imps.append(entry)

    return {
        "class_count": len(classes),
        "protocol_count": len(protocols),
        "selector_count": len(selectors),
        "classes": classes,
        "protocols": protocols,
        "selectors": selectors,
        "external_classes": external_classes,
        "method_imps": unique_imps,
    }
