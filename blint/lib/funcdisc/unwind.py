"""Unwind-table function discovery for Mach-O and ELF.

Both formats carry one unwind record per function in structures the runtime
needs to throw exceptions and walk frames, so they list every function start
with compiler-grade accuracy and they survive ``strip``:

- Mach-O ``__TEXT,__unwind_info``: compact unwind. The section header points
  at second-level pages (regular or compressed) whose entries hold a function
  offset relative to the ``__TEXT`` segment start. Offsets are sorted, so
  function sizes fall out of the gaps.
- ELF ``.eh_frame_hdr``: a binary-search table of ``(initial_location, fde)``
  pairs, one row per function. ``initial_location`` is usually ``DW_EH_PE_``
  ``datarel|sdata4``, i.e. an offset from the ``.eh_frame_hdr`` section start.
  When the header table is missing or malformed, a CIE/FDE walk over
  ``.eh_frame`` recovers the same starts from each FDE's ``pc_begin``.

Everything here is pure ``struct`` parsing over section bytes. The output is a
sorted list of ``{address, size, source}`` dicts with absolute virtual
addresses; callers decide how to merge them (see ``merge_discovered_functions``).
"""

import contextlib
import struct

import lief

# DW_EH_PE application/encoding constants we know how to decode. Anything
# else in the table descriptors is left alone rather than guessed at.
DW_EH_PE_ABSPTR = 0x00
DW_EH_PE_PCREL = 0x10
DW_EH_PE_DATAREL = 0x30
DW_EH_PE_SDATA4 = 0x0B
DW_EH_PE_SDATA8 = 0x0C
DW_EH_PE_UDATA4 = 0x03
DW_EH_PE_UDATA8 = 0x04

_EH_PTR_SIZE = {DW_EH_PE_SDATA4: 4, DW_EH_PE_UDATA4: 4, DW_EH_PE_SDATA8: 8, DW_EH_PE_UDATA8: 8}
_EH_STRUCT_FMT = {
    DW_EH_PE_SDATA4: "<i",
    DW_EH_PE_UDATA4: "<I",
    DW_EH_PE_SDATA8: "<q",
    DW_EH_PE_UDATA8: "<Q",
}

MACHO_UNWIND_INFO_SECTION = ("__TEXT", "__unwind_info")
MACHO_TEXT_SEGMENT = "__TEXT"
MACHO_UNWIND_REGULAR_PAGE = 2
MACHO_UNWIND_COMPRESSED_PAGE = 3

# A compressed second-level entry packs a 24-bit function offset and a 7-bit
# encoding index; the index only matters for unwinding, not for discovery.
_COMPRESSED_FUNC_OFFSET_MASK = 0x00FFFFFF

# Compact unwind layout constants (Apple's compact_unwind_encoding.h): the
# section header carries seven 32-bit fields, a top-level index entry three,
# and second-level page entries pack offset+encoding into one word. Compressed
# page offsets are relative to the base function offset of the top-level index
# entry that owns the page; regular page offsets are absolute image offsets.
_HEADER_FMT = "<7I"
_INDEX_ENTRY_FMT = "<3I"
_HEADER_SIZE = struct.calcsize(_HEADER_FMT)
_INDEX_ENTRY_SIZE = struct.calcsize(_INDEX_ENTRY_FMT)

# ELF sections consulted for eh_frame discovery.
ELF_EH_FRAME_HDR = ".eh_frame_hdr"
ELF_EH_FRAME = ".eh_frame"
ELF_TEXT = ".text"

# Discovery is expected to be exact, so malformed structures degrade to
# "return what parsed so far" instead of raising into the parse path.
MAX_FUNCTION_ENTRIES = 1 << 20


def _section_bytes(parsed_obj, name: str):
    """Return (virtual_address, bytes) for a named section, or (None, None)."""
    try:
        section = parsed_obj.get_section(name)
    except (AttributeError, TypeError):
        return None, None
    if section is None or isinstance(section, lief.lief_errors):
        return None, None
    try:
        content = section.content
        if not content:
            return None, None
        return int(section.virtual_address), bytes(content)
    except (AttributeError, TypeError, ValueError):
        return None, None


def _macho_text_vmaddr(parsed_obj) -> int | None:
    """Return the virtual address of the __TEXT segment (the unwind base)."""
    try:
        for segment in parsed_obj.segments:
            name = getattr(segment, "name", "")
            if name == MACHO_TEXT_SEGMENT:
                return int(segment.virtual_address)
    except (AttributeError, TypeError):
        pass
    return None


def _read_u32(data: bytes, offset: int) -> int | None:
    if offset < 0 or offset + 4 > len(data):
        return None
    return struct.unpack_from("<I", data, offset)[0]


def _read_u16(data: bytes, offset: int) -> int | None:
    if offset < 0 or offset + 2 > len(data):
        return None
    return struct.unpack_from("<H", data, offset)[0]


def discover_macho_unwind_functions(parsed_obj) -> list[dict]:
    """Parse ``__unwind_info`` into ``[{address, size, source}, ...]``.

    Compact unwind stores function offsets relative to the ``__TEXT`` segment
    start. LIEF's Mach-O function lists (and therefore the rest of blint) use
    that same imagebase-relative space, so addresses are emitted relative to
    the imagebase rather than as absolute virtual addresses. Sizes come from
    the gap to the next function, which the sorted offset list makes exact.
    The last top-level index entry is a sentinel whose function offset marks
    the end of the covered functions, bounding the final entry.
    """
    text_vmaddr = _macho_text_vmaddr(parsed_obj)
    if text_vmaddr is None:
        return []
    _, data = _section_bytes(parsed_obj, MACHO_UNWIND_INFO_SECTION[1])
    if not data or len(data) < _HEADER_SIZE:
        return []
    results: dict[int, int] = {}
    end_offset = 0
    try:
        header = struct.unpack_from(_HEADER_FMT, data, 0)
        (version, _, _, _, _, index_offset, index_count) = header
        if version != 1:
            return []
        if index_offset + index_count * _INDEX_ENTRY_SIZE > len(data):
            return []
        for idx in range(index_count):
            (
                index_function_offset,
                page_offset,
                _lsda_offset,
            ) = struct.unpack_from(_INDEX_ENTRY_FMT, data, index_offset + idx * _INDEX_ENTRY_SIZE)
            if not page_offset or page_offset > len(data):
                # A zero page offset marks the sentinel entry: its function
                # offset is the end boundary for sizes, not a function start.
                end_offset = max(end_offset, index_function_offset)
                continue
            kind = _read_u32(data, page_offset)
            if kind == MACHO_UNWIND_REGULAR_PAGE:
                page_offsets = _read_regular_page(data, page_offset)
            elif kind == MACHO_UNWIND_COMPRESSED_PAGE:
                page_offsets = _read_compressed_page(data, page_offset, index_function_offset)
            else:
                continue
            for function_offset in page_offsets:
                if 0 < function_offset:
                    results[function_offset] = 0
    except (struct.error, TypeError, ValueError):
        pass
    imagebase = getattr(parsed_obj, "imagebase", None)
    rebase = text_vmaddr - imagebase if isinstance(imagebase, int) else 0
    entries = _offsets_to_entries(results, 0, end_offset or None)
    for entry in entries:
        entry["address"] += rebase
    return entries


def _read_regular_page(data: bytes, page_offset: int) -> list[int]:
    """Read a regular second-level page.

    Apple's regular entry is
    ``unwind_info_regular_second_level_entry { uint32_t functionOffset;
    compact_unwind_encoding_t encoding; }`` — 8 bytes per entry with a full
    32-bit image offset in the first word. Unlike the compressed page there
    is no 24-bit mask: the offset uses the whole word.
    """
    entry_page_offset = _read_u16(data, page_offset + 4)
    entry_count = _read_u16(data, page_offset + 6)
    if not entry_page_offset or not entry_count:
        return []
    entries = []
    for idx in range(min(entry_count, MAX_FUNCTION_ENTRIES)):
        function_offset = _read_u32(data, page_offset + entry_page_offset + 8 * idx)
        if function_offset is None:
            break
        entries.append(function_offset)
    return entries


def _read_compressed_page(data: bytes, page_offset: int, base_function_offset: int) -> list[int]:
    """Read a compressed second-level page; offsets are page-base relative."""
    entry_page_offset = _read_u16(data, page_offset + 4)
    entry_count = _read_u16(data, page_offset + 6)
    if not entry_page_offset or not entry_count:
        return []
    entries = []
    for idx in range(min(entry_count, MAX_FUNCTION_ENTRIES)):
        entry = _read_u32(data, page_offset + entry_page_offset + 4 * idx)
        if entry is None:
            break
        entries.append(base_function_offset + (entry & _COMPRESSED_FUNC_OFFSET_MASK))
    return entries


def _offsets_to_entries(
    offsets: dict[int, int], base_va: int, end_offset: int | None
) -> list[dict]:
    """Convert sorted function offsets into {address, size, source} entries."""
    entries = []
    sorted_offsets = sorted(offsets)
    for idx, offset in enumerate(sorted_offsets):
        if idx + 1 < len(sorted_offsets):
            size = sorted_offsets[idx + 1] - offset
        elif end_offset and end_offset > offset:
            size = end_offset - offset
        else:
            size = 0
        entries.append(
            {
                "address": base_va + offset,
                "size": size,
                "source": "unwind",
            }
        )
    return entries


def discover_elf_eh_frame_functions(parsed_obj) -> list[dict]:
    """Parse ``.eh_frame_hdr`` (or walk ``.eh_frame``) into function entries.

    The header's binary-search table yields starts directly; the FDE records
    carry exact ``pc_range`` sizes, so when both are available the starts come
    from the table and the sizes from the FDE walk. When the header is absent
    or malformed the FDE walk alone recovers everything.
    """
    hdr_va, hdr_data = _section_bytes(parsed_obj, ELF_EH_FRAME_HDR)
    frame_va, frame_data = _section_bytes(parsed_obj, ELF_EH_FRAME)
    entries = []
    if hdr_data and len(hdr_data) >= 12:
        entries = _parse_eh_frame_hdr(hdr_va, hdr_data)
    if frame_data:
        fde_entries = _parse_eh_frame_fdes(frame_va, frame_data)
        if entries:
            exact_sizes = {e["address"]: e["size"] for e in fde_entries}
            for entry in entries:
                exact = exact_sizes.get(entry["address"])
                if exact:
                    entry["size"] = exact
        else:
            entries = fde_entries
    return entries


def _decode_eh_value(data: bytes, offset: int, encoding: int, section_va: int) -> tuple[int | None, int]:
    """Decode one DW_EH_PE value, returning (value, bytes_consumed).

    The value is the raw field content; callers apply the relocation flavor
    (pcrel/datarel) themselves because the base differs per field.
    """
    base = encoding & 0x0F
    if encoding == DW_EH_PE_ABSPTR:
        # ABSPTR uses the pointer size of the target; 8 bytes is the only
        # 64-bit case blint's parser handles and 4 covers 32-bit ELFs.
        size = 8 if len(data) >= offset + 8 else 4
        fmt = "<Q" if size == 8 else "<I"
        if offset + size > len(data):
            return None, 0
        return struct.unpack_from(fmt, data, offset)[0], size
    size = _EH_PTR_SIZE.get(base)
    if size is None:
        return None, 0
    fmt = _EH_STRUCT_FMT.get(base, "<I")
    if offset + size > len(data):
        return None, 0
    value = struct.unpack_from(fmt, data, offset)[0]
    if (encoding & 0x70) == DW_EH_PE_PCREL:
        value += section_va + offset
    elif (encoding & 0x70) == DW_EH_PE_DATAREL:
        value += section_va
    return value, size


def _parse_eh_frame_hdr(hdr_va: int, data: bytes) -> list[dict]:
    """Read the binary-search table of a well-formed ``.eh_frame_hdr``."""
    try:
        version, ptr_enc, count_enc, table_enc = data[0], data[1], data[2], data[3]
    except IndexError:
        return []
    if version != 1:
        return []
    value, size = _decode_eh_value(data, 4, ptr_enc, hdr_va)
    if value is None:
        return []
    cursor = 4 + size
    fde_count, size = _decode_eh_value(data, cursor, count_enc, hdr_va)
    if fde_count is None or fde_count > MAX_FUNCTION_ENTRIES:
        return []
    cursor += size
    # Only flat 4/8-byte table rows are worth parsing; indirections would mean
    # guessing at relocations this parser deliberately does not model.
    if _EH_PTR_SIZE.get(table_enc & 0x0F) is None:
        return []
    starts = {}
    row_size = 2 * _EH_PTR_SIZE[table_enc & 0x0F]
    max_rows = min(fde_count, (len(data) - cursor) // row_size)
    for idx in range(max_rows):
        row_offset = cursor + idx * row_size
        location, _ = _decode_eh_value(data, row_offset, table_enc, hdr_va)
        if location is None or location <= 0:
            continue
        starts[location] = 0
    return _offsets_to_entries(starts, 0, None)


def _parse_eh_frame_fdes(section_va: int, data: bytes) -> list[dict]:
    """Walk CIE/FDE records in a raw ``.eh_frame`` section.

    Each FDE's ``pc_begin``/``pc_range`` pair gives one function start and its
    exact size. Exotic encodings or malformed records stop the walk; anything
    decoded before that point is still useful discovery evidence.
    """
    entries: dict[int, int] = {}
    cie_encodings: dict[int, int] = {}
    offset = 0
    length = len(data)
    while offset + 4 <= length and len(entries) < MAX_FUNCTION_ENTRIES:
        record_length = _read_u32(data, offset)
        if record_length == 0:  # terminator
            break
        is_64 = record_length == 0xFFFFFFFF
        if is_64:
            if offset + 12 > length:
                break
            record_length = struct.unpack_from("<Q", data, offset + 4)[0]
            header_size = 12
        else:
            header_size = 4
        if record_length > length - offset - header_size:
            break
        record_end = offset + header_size + record_length
        if is_64:
            cie_id = struct.unpack_from("<Q", data, offset + header_size)[0]
            body = offset + header_size + 8
        else:
            cie_id = _read_u32(data, offset + header_size)
            body = offset + header_size + 4
        if cie_id == 0:
            encoding = _parse_cie(data, body, record_end)
            if encoding is not None:
                cie_encodings[offset] = encoding
        else:
            # The CIE pointer is the byte distance from this FDE's start back
            # to the CIE's start. A sentinel default covers CIEs whose parse
            # failed; note the lookup must distinguish a parsed 0 (absptr)
            # from a missing entry.
            cie_offset = offset - cie_id
            encoding = cie_encodings.get(cie_offset)
            if encoding is None:
                encoding = DW_EH_PE_PCREL | DW_EH_PE_SDATA4
            start, consumed = _decode_eh_value(data, body, encoding, section_va)
            if start is not None and start > 0:
                range_value, _ = _decode_eh_value(
                    data, body + consumed, encoding & 0x0F, section_va
                )
                size = range_value if range_value and range_value > 0 else 0
                entries[start] = size
        # The length field already counts any trailing alignment padding the
        # compiler emitted, so the next record starts right at record_end.
        offset = record_end
    return [
        {"address": address, "size": size, "source": "eh_frame"}
        for address, size in sorted(entries.items())
    ]


def _parse_cie(data: bytes, body: int, record_end: int) -> int | None:
    """Parse a CIE far enough to learn the FDE ``pc_begin`` encoding."""
    cursor = body
    # version: ubyte for CIE versions 1/3/4 as emitted by every toolchain
    # blint targets.
    if cursor + 1 > record_end:
        return None
    version = data[cursor]
    cursor += 1
    augmentation_end = data.find(b"\x00", cursor, record_end)
    if augmentation_end < 0:
        return None
    augmentation = data[cursor:augmentation_end]
    cursor = augmentation_end + 1
    # code alignment factor (uleb128), data alignment factor (sleb128) and
    # return address register (uleb128; a uword for CIE version 1) are skipped
    # because only the augmentation's 'R' encoding byte matters here.
    cursor = _skip_uleb128(data, cursor, record_end)
    cursor = _skip_uleb128(data, cursor, record_end)
    if cursor is None:
        return None
    if version >= 3:
        cursor = _skip_uleb128(data, cursor, record_end)
        if cursor is None:
            return None
    else:
        cursor += 1
    if cursor > record_end:
        return None
    if not augmentation.startswith(b"z"):
        # No augmentation data: the canonical pcrel/sdata4 encoding is what
        # GCC/Clang emit, so fall back to it rather than failing discovery.
        return DW_EH_PE_PCREL | DW_EH_PE_SDATA4
    aug_length, next_cursor = _read_uleb128(data, cursor, record_end)
    if aug_length is None:
        return None
    aug_end = next_cursor + aug_length
    if aug_end > record_end:
        return None
    cursor = next_cursor
    encoding = None
    for flag in augmentation[1:]:
        if flag == 0x52:  # 'R': FDE encoding follows
            if cursor + 1 > aug_end:
                return None
            encoding = data[cursor]
            cursor += 1
        elif flag == 0x50:  # 'P': personality encoding + routine
            if cursor + 1 > aug_end:
                return None
            per_enc = data[cursor]
            cursor += 1
            _, size = _decode_eh_value(data, cursor, per_enc, 0)
            if not size:
                return None
            cursor += size
        elif flag == 0x4C:  # 'L': LSDA encoding byte
            cursor += 1
        # 'S' (signal frame) and any other marker are payload-free: only
        # 'R', 'P' and 'L' consume augmentation bytes, so an unrecognized
        # flag leaves the cursor where it is rather than abandoning the CIE.
        if cursor > aug_end:
            return None
    if encoding is None:
        return DW_EH_PE_PCREL | DW_EH_PE_SDATA4
    return encoding


def _read_uleb128(data: bytes, offset: int, end: int) -> tuple[int | None, int]:
    result = 0
    shift = 0
    while offset < end:
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, offset
        shift += 7
        if shift > 63:
            return None, offset
    return None, offset


def _skip_uleb128(data: bytes, offset: int | None, end: int) -> int | None:
    if offset is None:
        return None
    _, offset = _read_uleb128(data, offset, end)
    return offset


def discover_functions(parsed_obj) -> list[dict]:
    """Discover functions from the unwind tables the parsed object carries."""
    if isinstance(parsed_obj, lief.MachO.Binary):
        return discover_macho_unwind_functions(parsed_obj)
    if isinstance(parsed_obj, lief.ELF.Binary):
        return discover_elf_eh_frame_functions(parsed_obj)
    # PE x64 discovery comes from .pdata via parse_pe_exceptions; 32-bit PE
    # has no unwind tables, so prologue scanning (funcdisc.complete) covers it.
    return []


def merge_discovered_functions(metadata: dict, discovered: list[dict]) -> dict:
    """Record discovered functions and merge the new ones into the list.

    ``metadata["discovered_functions"]`` exposes every finding — including
    addresses the symbol buckets already cover — because its exact sizes are
    load-bearing for downstream passes (disassembly bounding, call-target
    promotion checks). Entries whose address already exists carry the real
    symbol name; the rest are additionally merged into
    ``metadata["functions"]`` as ``sub_<address>`` with the exact unwind
    size, and already-listed entries are enriched with that size when theirs
    is unknown. Disassembly only ever gains new entries from the merge;
    enriching a size narrows truncation to the function's real extent.
    """
    if not discovered:
        return metadata
    existing = _existing_function_entries(metadata)
    fresh = []
    record_entries = []
    by_source: dict[str, int] = {}
    for entry in discovered:
        address = entry["address"]
        source = entry.get("source", "unknown")
        by_source[source] = by_source.get(source, 0) + 1
        size = entry.get("size", 0)
        claimed = existing.get(address)
        symbol_name = claimed.get("name") if claimed else None
        record = {
            "name": symbol_name if symbol_name else f"sub_{address:x}",
            "address": f"0x{address:x}",
            "size": size,
            "source": source,
        }
        if claimed is not None:
            if not symbol_name:
                # A nameless claim (LC_FUNCTION_STARTS entry and friends):
                # the discovery record supplies the readable identity.
                claimed["name"] = f"sub_{address:x}"
                record["name"] = f"sub_{address:x}"
            # Enrich unknown sizes with the exact unwind-table value.
            if not isinstance(claimed.get("size"), int) or claimed.get("size", 0) <= 0:
                claimed["size"] = size
        else:
            fresh.append(entry)
        record_entries.append(record)
    # Sort for a deterministic metadata block; addresses are unique after the
    # dedupe pass in _existing_function_entries.
    fresh.sort(key=lambda item: (item["address"], item.get("source", "")))
    metadata["discovered_functions"] = record_entries
    functions = list(metadata.get("functions") or [])
    next_index = max(
        (int(fn.get("index", -1)) for fn in functions if isinstance(fn.get("index"), int)),
        default=-1,
    ) + 1
    for entry in fresh:
        functions.append(
            {
                "index": next_index,
                "name": f"sub_{entry['address']:x}",
                "address": f"0x{entry['address']:x}",
                # The unwind size is the real extent, so disassembly bounds
                # the function exactly instead of falling back to its blind
                # 4096-byte guess. Trailing padding inside the extent is
                # stripped downstream by _find_function_end_index.
                "size": int(entry.get("size") or 0),
                "flags": None,
                "discovered": entry.get("source", "unknown"),
            }
        )
        next_index += 1
    if fresh:
        metadata["functions"] = functions
    metadata["function_discovery"] = {
        "sources": dict(sorted(by_source.items())),
        "merged_count": len(fresh),
    }
    return metadata


def _existing_function_entries(metadata: dict) -> dict[int, dict]:
    """Map every address already claimed by a function bucket to its entry.

    A claimed address with an empty name still blocks the merge (the address
    exists); the mapped entry is enriched in place with discovery sizes and
    names, so the value is the dict itself rather than a copy. Read each
    entry's ``name`` to learn whether a real symbol claims the address.
    """
    from blint.lib.disassembler import FUNCTION_SYMBOLS

    existing: dict[int, dict] = {}
    for func_list_key in FUNCTION_SYMBOLS:
        for func_entry in metadata.get(func_list_key, []):
            if not isinstance(func_entry, dict):
                continue
            raw = func_entry.get("address") or func_entry.get("rva_start")
            address = None
            if isinstance(raw, int):
                address = raw
            elif isinstance(raw, str) and raw.strip():
                with contextlib.suppress(ValueError):
                    address = int(raw.strip(), 16)
            if address is None or address in existing:
                continue
            existing[address] = func_entry
    return existing
