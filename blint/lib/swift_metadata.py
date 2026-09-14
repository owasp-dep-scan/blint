"""Swift reflection metadata parsing (``__swift5_*`` / ``.swift5_*``).

Swift embeds reflection sections in every binary built from Swift code —
Mach-O (``__swift5_types``, ``__swift5_protos``, ``__swift5_fieldmd``,
``__swift5_reflstr``) and, since Swift on Linux targets the same runtime
(issue #109), ELF (``.swift5_types`` and friends). The sections survive
stripping and name every Swift type in the binary, its field names, and the
type-metadata access functions — a function oracle for exactly the binaries
where symbol tables have been removed.

Everything is 4-byte relative offsets: each member points relative to its
own field's address, so the parser needs only the bytes plus section base
addresses — no relocation state. Kind values were pinned empirically against
a real Swift binary (otool-free, cross-checked by name semantics):
``class = 16 (0x10), struct = 17 (0x11), enum = 18 (0x12)``, with the
modern 5/6/7 spellings accepted for forward compatibility.
"""

import contextlib
import struct

from blint.logger import LOG

# Mach-O and ELF spellings, normalized to one vocabulary.
_SECTION_ALIASES = {
    "swift5_types": ("__swift5_types", ".swift5_types"),
    "swift5_protos": ("__swift5_protos", ".swift5_protos"),
    "swift5_fieldmd": ("__swift5_fieldmd", ".swift5_fieldmd"),
    "swift5_reflstr": ("__swift5_reflstr", ".swift5_reflstr"),
}

# Context-descriptor kind bytes seen in type descriptors. The 5/6/7 spellings
# are the current Swift header values; 16/17/18 are what binaries shipped
# through the entire Swift 5 era actually carry.
_KIND_CLASS = (16, 5)
_KIND_STRUCT = (17, 6)
_KIND_ENUM = (18, 7)

# Safety caps: a hostile or truncated section must degrade into a counted
# truncation, not a scan that never ends.
_MAX_TYPES = 8000
_MAX_PROTOCOLS = 4000
_MAX_FIELDS_PER_TYPE = 64
_MAX_STRING = 256


class _SwiftReader:
    """Byte and relative-pointer reads over a binary's virtual address space."""

    def __init__(self, parsed_obj) -> None:
        self._obj = parsed_obj
        self.sections: dict[str, tuple[int, int]] = {}
        for section in parsed_obj.sections:
            try:
                name = section.name.lstrip("._")
                va = section.virtual_address
                if va and section.size:
                    self.sections[name] = (va, section.size)
            except (AttributeError, TypeError):
                continue

    def has_section(self, name: str) -> bool:
        return name in self.sections

    def read(self, va: int, size: int) -> bytes | None:
        with contextlib.suppress(Exception):
            data = bytes(self._obj.get_content_from_virtual_address(va, size))
            if len(data) == size:
                return data
        return None

    def rel32(self, va: int) -> int:
        """The 4-byte relative pointer stored at ``va``, resolved."""
        data = self.read(va, 4)
        if data is None:
            return 0
        return va + struct.unpack("<i", data)[0]

    def cstring(self, va: int) -> str:
        """The NUL-terminated string at ``va``, up to ``_MAX_STRING`` bytes.

        Read directly rather than through ``read``, which requires the full
        width: a string sitting within the last ``_MAX_STRING`` bytes of
        readable space — the reflection string section is commonly the last
        thing in the image — would otherwise read as absent.
        """
        if not va:
            return ""
        data = b""
        with contextlib.suppress(Exception):
            data = bytes(self._obj.get_content_from_virtual_address(va, _MAX_STRING))
        if not data:
            return ""
        nul = data.find(b"\x00")
        return data[: nul if nul != -1 else len(data)].decode("utf-8", "replace")


def _kind_name(kind: int) -> str:
    if kind in _KIND_CLASS:
        return "class"
    if kind in _KIND_STRUCT:
        return "struct"
    if kind in _KIND_ENUM:
        return "enum"
    return "other"


def _parse_field_descriptor(reader: _SwiftReader, fd_va: int) -> list[str]:
    """Field names of one field descriptor, in declaration order.

    Header: relative mangled-type name (+0), relative superclass (+4),
    uint16 kind (+8), uint16 record size (+0xA), uint32 count (+0xC).
    Records follow at +0x10; the field name is the third member (offset +8
    in every record size seen in practice: 12 and 16).
    """
    if not fd_va:
        return []
    header = reader.read(fd_va + 8, 8)
    if header is None:
        return []
    _kind, record_size, count = struct.unpack("<HHI", header)
    if record_size < 12 or count == 0:
        return []
    count = min(count, _MAX_FIELDS_PER_TYPE)
    names = []
    for i in range(count):
        record = fd_va + 0x10 + i * record_size
        name_va = reader.rel32(record + 8)
        name = reader.cstring(name_va)
        if name:
            names.append(name)
    return names


def _parse_type_section(
    reader: _SwiftReader,
) -> tuple[list[dict], list[dict], dict[str, int], bool]:
    """Walk ``__swift5_types``: one entry per Swift type in the binary.

    Returns ``(types, access_functions, kind_counts, truncated)``. Type entries carry
    the fields that name and locate the type; access functions are real
    code addresses the disassembler can seed even on stripped binaries.
    """
    types: list[dict] = []
    access_functions: list[dict] = []
    kind_counts: dict[str, int] = {}
    if not reader.has_section("swift5_types"):
        return types, access_functions, kind_counts, False
    section_va, section_size = reader.sections["swift5_types"]
    count = min(section_size // 4, _MAX_TYPES)
    truncated = section_size // 4 > _MAX_TYPES
    for i in range(count):
        descriptor = reader.rel32(section_va + i * 4)
        if not descriptor:
            continue
        flags_word = reader.read(descriptor, 4)
        if flags_word is None:
            continue
        kind = struct.unpack("<I", flags_word)[0] & 0x1F
        kind_name = _kind_name(kind)
        kind_counts[kind_name] = kind_counts.get(kind_name, 0) + 1
        name = reader.cstring(reader.rel32(descriptor + 8))
        if not name:
            continue
        entry = {"name": name, "kind": kind_name}
        # The metadata access function is a real function body; +0x0C is the
        # relative pointer to it.
        access_va = reader.rel32(descriptor + 0x0C)
        if access_va:
            entry["access_function"] = f"0x{access_va:x}"
            access_functions.append(
                {"name": f"metadata_access_function_for_{name}", "address": access_va}
            )
        if fields := _parse_field_descriptor(reader, reader.rel32(descriptor + 0x10)):
            entry["fields"] = fields
            entry["field_count"] = len(fields)
        types.append(entry)
    if truncated:
        # Kept out of kind_counts: that dict is a histogram over type kinds,
        # and a cap notice counted as a kind reads as a type that exists.
        LOG.debug("Swift type section exceeds the %d-type cap; the rest is not parsed", _MAX_TYPES)
    return types, access_functions, kind_counts, truncated


def _parse_protos_section(reader: _SwiftReader) -> list[str]:
    """Walk ``__swift5_protos``: protocol names declared by this binary."""
    names: list[str] = []
    if not reader.has_section("swift5_protos"):
        return names
    section_va, section_size = reader.sections["swift5_protos"]
    count = min(section_size // 4, _MAX_PROTOCOLS)
    for i in range(count):
        descriptor = reader.rel32(section_va + i * 4)
        if not descriptor:
            continue
        # Protocol descriptors share the leading name layout: name is the
        # relative pointer at +8.
        name = reader.cstring(reader.rel32(descriptor + 8))
        if name:
            names.append(name)
    return names


def parse_swift_metadata(parsed_obj) -> dict:
    """Parse Swift reflection metadata into a bounded ``swift_metadata`` block.

    Works for Mach-O (``__swift5_*``) and ELF (``.swift5_*``). Returns an
    empty dict for binaries without the sections. The type list, protocol
    names and per-type field names are the exported evidence; the access
    functions are additionally consumed by :func:`merge_swift_functions` to
    seed function discovery.
    """
    if parsed_obj is None:
        return {}
    reader = _SwiftReader(parsed_obj)
    if not reader.has_section("swift5_types"):
        return {}

    types, access_functions, kind_counts, truncated = _parse_type_section(reader)
    protocols = _parse_protos_section(reader)
    if not types:
        return {}

    LOG.debug(
        "Parsed Swift metadata: %d types (%s), %d protocols, %d access functions",
        len(types),
        {k: v for k, v in kind_counts.items() if v},
        len(protocols),
        len(access_functions),
    )
    out: dict = {
        "type_count": len(types),
        "kind_counts": kind_counts,
        "types": types,
        "protocol_count": len(protocols),
        "protocols": protocols,
        "access_function_count": len(access_functions),
        "access_functions": access_functions,
    }
    if truncated:
        out["types_truncated"] = True
    return out


def merge_swift_functions(metadata: dict) -> dict:
    """Seed/label functions from Swift type-metadata access functions.

    Mirrors the Objective-C merge: an address already claimed by a symbol or
    another source is left alone, and only unknown addresses become new
    ``sub_<address>``-replacing entries — so the function *set* can only
    grow, and existing entries are never renamed.
    """
    swift_metadata = metadata.get("swift_metadata")
    if not swift_metadata:
        return metadata
    access_functions = swift_metadata.get("access_functions")
    if not access_functions:
        return metadata
    functions = list(metadata.get("functions") or [])
    by_address = {}
    for fn in functions:
        addr = fn.get("address")
        try:
            # Metadata addresses are hex strings, but an int must not be
            # silently re-read as hex digits (int(str(0x10), 16) == 16 != 0x10).
            parsed = addr if isinstance(addr, int) else int(str(addr), 16)
        except (TypeError, ValueError):
            continue
        by_address[parsed] = fn
    added = 0
    for entry in access_functions:
        addr = entry.get("address")
        name = entry.get("name")
        if not isinstance(addr, int) or not name:
            continue
        existing = by_address.get(addr)
        if existing is not None:
            continue
        fn_entry = {
            "index": len(functions),
            "name": name,
            "address": f"0x{addr:x}",
            "size": 0,
            "flags": None,
        }
        functions.append(fn_entry)
        by_address[addr] = fn_entry
        added += 1
    if added:
        swift_metadata["functions_seeded"] = added
    metadata["functions"] = functions
    return metadata


def swift_field_names(metadata: dict) -> list[str]:
    """All Swift type and field names in a binary, for haystack matching.

    Consumed by the privacy-marker matcher alongside symbols and ObjC
    selectors: a Swift property named ``creationDate`` is the same
    required-reason signal as the C symbol spellings.
    """
    swift_metadata = metadata.get("swift_metadata")
    if not swift_metadata:
        return []
    names: list[str] = []
    for entry in swift_metadata.get("types") or []:
        if isinstance(entry, dict):
            if entry.get("name"):
                names.append(entry["name"])
            names.extend(f for f in entry.get("fields") or [] if f)
    return names
