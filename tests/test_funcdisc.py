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
    discover_macho_unwind_functions,
    merge_discovered_functions,
)


class _FakeMacho:
    """Minimal Mach-O stand-in exposing just what discovery reads."""

    def __init__(self, sections, segments, imagebase=0x100000000):
        self._sections = sections
        self._segments = segments
        self._imagebase = imagebase

    def get_section(self, name):
        return self._sections.get(name)

    @property
    def segments(self):
        return self._segments

    @property
    def imagebase(self):
        return self._imagebase


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
    # The discovery record lists everything; the already-symbolized address
    # carries its real name directly.
    assert len(merged["discovered_functions"]) == 2
    known_entry = next(d for d in merged["discovered_functions"] if d["address"] == "0x1000")
    assert known_entry["name"] == "known_fn"
    # Only the fresh address is appended to the function list.
    assert len(merged["functions"]) == 2
    fresh = merged["functions"][1]
    assert fresh["name"] == "sub_2000"
    assert fresh["size"] == 0
    assert fresh["discovered"] == "unwind"
    assert merged["function_discovery"]["merged_count"] == 1


def test_merge_discovered_enriches_nameless_claims_with_names_and_sizes():
    metadata = {
        "functions": [
            {"index": 0, "name": "", "address": "0x460", "size": 0},
        ],
    }
    merged = merge_discovered_functions(
        metadata, [{"address": 0x460, "size": 212, "source": "unwind"}]
    )
    # Claimed even without a name: the function list must not grow, but the
    # claim is upgraded with the readable identity and the exact size.
    assert len(merged["functions"]) == 1
    assert merged["functions"][0]["name"] == "sub_460"
    assert merged["functions"][0]["size"] == 212
    assert merged["discovered_functions"][0]["size"] == 212
    assert merged["function_discovery"]["merged_count"] == 0


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

def _build_unwind_info_regular_page(function_offsets, base=0x100000):
    """Build an `__unwind_info` whose second-level page is a *regular* page.

    Regular entries are 8 bytes each: a full 32-bit image offset followed by
    a 32-bit encoding word. The encoding words interleaved between offsets
    are exactly what a stride-4 reader would misread as offsets.
    """
    header = struct.pack(
        "<7I", 1, 28, 0, 0, 0, 28, 2,
    )
    index_offset = 28
    page_offset = index_offset + 24
    page = struct.pack("<IHH", 2, 8, len(function_offsets))
    entries = b"".join(
        struct.pack("<II", off, 0x04000000) for off in function_offsets
    )
    index = struct.pack("<3I", base, page_offset, 0) + struct.pack("<3I", base + 0x300, 0, 0)
    return header + index + page + entries


def test_macho_regular_page_stride8_full_offsets():
    # Offsets chosen so a 24-bit truncation or a stride-4 read (which would
    # pick up the 0x04000000 encoding words) yields garbage.
    offsets = [0x100000, 0x1000D4, 0x100168]
    data = _build_unwind_info_regular_page(offsets)
    section = _FakeSection("__unwind_info", 0x600, data)
    fake = _FakeMacho({"__unwind_info": section}, [_FakeSegment("__TEXT", 0)], imagebase=0)
    entries = discover_macho_unwind_functions(fake)
    assert [(e["address"], e["size"]) for e in entries] == [
        (0x100000, 0xD4),
        (0x1000D4, 0x94),
        (0x100168, 0x300 - 0x168),
    ]


def test_eh_frame_absptr_fde_encoding():
    # DW_EH_PE_absptr (encoding 0x00): pc_begin is an absolute 8-byte value,
    # not relative to anything.
    section_va = 0x1000
    target = 0x2000
    cie_body = bytes([1]) + b"zR\x00" + bytes([0x1C, 0x1C, 0x1C, 0x01, 0x00])
    cie = struct.pack("<I", 20) + struct.pack("<I", 0) + cie_body
    cie += b"\x00" * (24 - len(cie))
    fde = (
        struct.pack("<I", 16)
        + struct.pack("<I", 24)
        + struct.pack("<Q", target)
        + struct.pack("<I", 0x80)
    )
    entries = _parse_eh_frame_fdes(section_va, cie + fde)
    assert len(entries) == 1
    assert entries[0]["address"] == target
    assert entries[0]["size"] == 0x80


def test_prologue_scan_x86_patterns():
    from blint.lib.funcdisc.complete import _scan_x86_prologues

    base = 0x401000
    def at(offset, payload):
        buf = bytearray(b"\x90" * 64)
        buf[offset : offset + len(payload)] = payload
        return bytes(buf)

    # push rbp; mov rbp, rsp at a 16-byte-aligned slot
    found = _scan_x86_prologues(base, at(0, b"\x55\x48\x89\xe5"))
    assert base in found
    # not aligned: rejected
    found = _scan_x86_prologues(base, at(8, b"\x55\x48\x89\xe5"))
    assert base + 8 not in found
    # endbr64 + frame setup at an aligned slot
    found = _scan_x86_prologues(base, at(16, b"\xf3\x0f\x1e\xfa\x55\x48\x89\xe5"))
    assert base + 16 in found
    # Go small frame: guard + jbe rel8
    found = _scan_x86_prologues(base, at(32, b"\x49\x3b\x66\x10\x76\x18"))
    assert base + 32 in found
    # Go small frame: guard + jbe rel32
    found = _scan_x86_prologues(base, at(48, b"\x49\x3b\x66\x10\x0f\x86\x7c\x00\x00\x00"))
    assert base + 48 in found
    # Go large frame: lea r12 + guard + jbe rel8
    found = _scan_x86_prologues(base, at(0, b"\x4c\x8d\x64\x24\xd8\x49\x3b\x66\x10\x76\x18"))
    assert base in found
    # bare lea r12 without the guard/branch: rejected
    found = _scan_x86_prologues(base, at(0, b"\x4c\x8d\x64\x24\xd8" + b"\x90" * 12))
    assert base not in found


def test_prologue_scan_arm64_patterns():
    from blint.lib.funcdisc.complete import _scan_arm64_prologues

    base = 0x10000
    buf = bytearray(b"\x00" * 64)

    def put_word(offset, word):
        struct.pack_into("<I", buf, offset, word)

    put_word(0, 0xD503233F)  # paciasp
    put_word(4, 0xA9827BFD)  # stp x29, x30, [sp, #-16]!
    put_word(8, 0x910003FD)  # mov x29, sp
    put_word(16, 0xA9BF7BFD)  # stp x29, x30, [sp, #-16]! + mov x29, sp
    put_word(20, 0x910003FD)
    put_word(28, 0xF9400B90)  # Go: ldr x16, [x28, #16]
    found = _scan_arm64_prologues(base, bytes(buf))
    assert base in found  # paciasp
    assert base + 16 in found  # stp + mov x29, sp pair
    assert base + 28 in found  # Go guard
    assert base + 4 in found  # the stp at +4 is also followed by mov x29, sp

    # A bare stp without the mov x29, sp that always follows in a prologue
    # is not enough.
    buf2 = bytearray(b"\x00" * 32)
    struct.pack_into("<I", buf2, 0, 0xA9827BFD)
    assert not _scan_arm64_prologues(base, bytes(buf2))
