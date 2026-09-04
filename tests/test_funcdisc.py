"""Tests for unwind-table function discovery (blint.lib.funcdisc)."""

import struct

from blint.lib.funcdisc.complete import (
    ARM64_MOV_FP_SP,
    ARM64_PACIASP,
    ARM64_STP_FP_MASK,
    ARM64_STP_FP_VALUE,
    promotable_call_target,
)
from blint.lib.funcdisc.unwind import (
    _parse_eh_frame_fdes,
    _parse_eh_frame_hdr,
    discover_elf_eh_frame_functions,
    discover_macho_unwind_functions,
    merge_discovered_functions,
)


class _FakeMacho:
    """Minimal Mach-O stand-in exposing just what discovery reads."""

    def __init__(self, sections, segments):
        self._sections = sections
        self._segments = segments

    def get_section(self, name):
        return self._sections.get(name)

    @property
    def segments(self):
        return self._segments

    @property
    def imagebase(self):
        return 0x100000000


class _FakeSection:
    def __init__(self, name, virtual_address, content):
        self.name = name
        self.virtual_address = virtual_address
        self.content = content
        self.size = len(content)


class _FakeSegment:
    def __init__(self, name, virtual_address):
        self.name = name
        self.virtual_address = virtual_address


def _build_unwind_info(function_offsets, base=0x460, common_encodings=(), kind=3):
    """Build a compact `__unwind_info` section image."""
    header = struct.pack(
        "<7I",
        1,  # version
        28,  # common encodings offset
        len(common_encodings),  # common encodings count
        0,  # personality offset
        0,  # personality count
        28 + 4 * len(common_encodings),  # index offset
        2,  # index count, including the sentinel entry (llvm-objdump counts it)
    )
    common = b"".join(struct.pack("<I", e) for e in common_encodings)
    index_offset = 28 + len(common)
    index_size = 2 * 12  # one real entry + the sentinel
    page_offset = index_offset + index_size
    # compressed page: kind, entryPageOffset(12), entryCount, encPages, encCount
    page = struct.pack("<IHHHH", kind, 12, len(function_offsets), 12 + 4 * len(function_offsets), 0)
    entries = b"".join(struct.pack("<I", off - base) for off in function_offsets)
    index = struct.pack("<3I", base, page_offset, 0) + struct.pack("<3I", base + 0x200, 0, 0)
    return header + common + index + page + entries


def test_macho_compressed_page_discovery():
    data = _build_unwind_info([0x460, 0x534, 0x5C8])
    section = _FakeSection("__unwind_info", 0x100000660, data)
    segment = _FakeSegment("__TEXT", 0x100000000)
    fake = _FakeMacho({"__unwind_info": section}, [segment])
    entries = discover_macho_unwind_functions(fake)
    # The sentinel sits at base + 0x200 and bounds the last function.
    assert [(e["address"], e["size"]) for e in entries] == [
        (0x460, 0xD4),
        (0x534, 0x94),
        (0x5C8, 0x98),
    ]
    assert all(e["source"] == "unwind" for e in entries)


def test_macho_sentinel_bounds_last_function():
    data = _build_unwind_info([0x460, 0x534], base=0x460)
    section = _FakeSection("__unwind_info", 0x100000660, data)
    fake = _FakeMacho(
        {"__unwind_info": section}, [_FakeSegment("__TEXT", 0x100000000)]
    )
    entries = discover_macho_unwind_functions(fake)
    # The sentinel offset (0x460 + 0x200) bounds the final entry.
    assert entries[-1]["size"] == 0x660 - 0x534


def test_macho_bad_version_returns_empty():
    data = _build_unwind_info([0x460])
    data = b"\x99\x00\x00\x00" + data[4:]
    section = _FakeSection("__unwind_info", 0x100000660, data)
    fake = _FakeMacho(
        {"__unwind_info": section}, [_FakeSegment("__TEXT", 0x100000000)]
    )
    assert discover_macho_unwind_functions(fake) == []


def test_eh_frame_hdr_binary_search_table():
    # .eh_frame_hdr: version 1, sdata4 pcrel ptr, udata4 count, datarel table.
    hdr_va = 0x10B58
    fde_count = 2
    table = b""
    for location in (0x19070, 0x190E0):
        # datarel: relative to the eh_frame_hdr start
        table += struct.pack("<i", location - hdr_va)
        table += struct.pack("<I", 0x11E30)
    body = struct.pack("<BBBB", 1, 0x1B, 0x03, 0x3B)
    body += struct.pack("<i", 0x11E18 - hdr_va)  # pcrel eh_frame_ptr
    body += struct.pack("<I", fde_count)
    body += table
    entries = _parse_eh_frame_hdr(hdr_va, body)
    assert [(e["address"], e["size"]) for e in entries] == [
        (0x19070, 0x70),
        (0x190E0, 0),
    ]


def test_eh_frame_fde_walk_recovers_starts_and_sizes():
    section_va = 0x1000
    target = 0x2000
    # CIE: length 20, id 0, version, "zR" augmentation, caf/daf/rar, aug len 1,
    # R encoding = pcrel|sdata4 (0x1B). Padded to its declared length.
    cie_body = bytes([1]) + b"zR\x00" + bytes([0x1C, 0x1C, 0x1C, 0x01, 0x1B])
    cie = struct.pack("<I", 20) + struct.pack("<I", 0) + cie_body
    cie += b"\x00" * (24 - len(cie))
    # FDE at offset 24: the length field counts bytes after itself, so 12
    # covers cie_ptr + pc_begin + pc_range. pc_begin sits at section offset
    # 32 (pcrel), pc_range is 0x100.
    pc_begin_field_offset = 32
    fde = (
        struct.pack("<I", 12)
        + struct.pack("<I", 24)
        + struct.pack("<i", target - (section_va + pc_begin_field_offset))
        + struct.pack("<I", 0x100)
    )
    entries = _parse_eh_frame_fdes(section_va, cie + fde)
    assert len(entries) == 1
    assert entries[0]["address"] == target
    assert entries[0]["size"] == 0x100
    assert entries[0]["source"] == "eh_frame"


def test_merge_discovered_functions_records_all_and_merges_fresh():
    metadata = {
        "functions": [{"index": 0, "name": "known_fn", "address": "0x1000", "size": 16}],
    }
    discovered = [
        {"address": 0x1000, "size": 16, "source": "unwind"},
        {"address": 0x2000, "size": 32, "source": "unwind"},
    ]
    merged = merge_discovered_functions(metadata, discovered)
    # The discovery record lists everything, including the already-known one.
    assert len(merged["discovered_functions"]) == 2
    known_entry = next(d for d in merged["discovered_functions"] if d["address"] == "0x1000")
    assert known_entry["symbol_name"] == "known_fn"
    # Only the fresh address is appended to the function list.
    assert len(merged["functions"]) == 2
    fresh = merged["functions"][1]
    assert fresh["name"] == "sub_2000"
    assert fresh["size"] == 0
    assert fresh["discovered"] is True
    assert merged["function_discovery"]["merged_count"] == 1


def test_merge_discovered_dedupes_nameless_entries():
    metadata = {
        "functions": [{"index": 0, "name": "", "address": "0x460", "size": 0}],
    }
    merged = merge_discovered_functions(
        metadata, [{"address": 0x460, "size": 212, "source": "unwind"}]
    )
    # Claimed even without a name: the function list must not grow.
    assert len(merged["functions"]) == 1
    assert merged["discovered_functions"][0]["size"] == 212


def _span_extents():
    return [(0x1000, 0x1100), (0x2000, 0x2100)]


def test_promotable_call_target_accepts_gap_addresses():
    assert (
        promotable_call_target(
            0x1800, [0x1000, 0x2000], _span_extents(), [(0x1000, 0x3000)]
        )
        == 0x1800
    )


def test_promotable_call_target_declines_disassembled_extents():
    assert (
        promotable_call_target(
            0x1050, [0x1000, 0x2000], _span_extents(), [(0x1000, 0x3000)]
        )
        is None
    )
    assert (
        promotable_call_target(
            0x1000, [0x1000, 0x2000], _span_extents(), [(0x1000, 0x3000)]
        )
        is None
    )


def test_promotable_call_target_declines_outside_executable_memory():
    assert (
        promotable_call_target(0x9000, [0x1000], [], [(0x1000, 0x3000)]) is None
    )


def test_arm64_prologue_encoding_constants():
    # stp x29, x30, [sp, #-16]! encodes to 0xA9827BFD; the mask check must
    # accept any immediate and reject unrelated encodings.
    assert 0xA9827BFD & ARM64_STP_FP_MASK == ARM64_STP_FP_VALUE
    assert 0xA9BF7BFD & ARM64_STP_FP_MASK == ARM64_STP_FP_VALUE
    assert 0xA9427BFD & ARM64_STP_FP_MASK != ARM64_STP_FP_VALUE
    assert ARM64_PACIASP == 0xD503233F
    assert ARM64_MOV_FP_SP == 0x910003FD
