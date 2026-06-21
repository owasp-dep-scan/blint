"""Tests for the raw Objective-C metadata parser.

The pointer-walking entry points are exercised against a synthetic in-memory
layout via a fake reader, which lets us validate the tricky small/relative
method-list format (with the selref indirection) without a real Mach-O fixture.
"""

import struct

from blint.lib import macho_objc
from blint.lib.macho_objc import (
    _iter_method_entries,
    _parse_method_list,
    _parse_protocol_list,
    parse_objc_metadata,
)


class FakeReader:
    """Minimal reader over an explicit {address: value} memory model."""

    def __init__(self, *, mem=None, ptrs=None, strings=None):
        self.mem = mem or {}  # address -> raw bytes (for u32/i32)
        self.ptrs = ptrs or {}  # address -> resolved pointer target
        self.strings = strings or {}  # address -> python str

    def u32(self, va):
        data = self.mem.get(va)
        return struct.unpack("<I", data)[0] if data else None

    def i32(self, va):
        data = self.mem.get(va)
        return struct.unpack("<i", data)[0] if data else None

    def ptr(self, va):
        return self.ptrs.get(va)

    def cstring(self, va):
        return self.strings.get(va, "")


def test_parse_small_method_list_resolves_selrefs():
    # method_list_t header at 0x1000: entsize=12 with small flag, count=2.
    mlist = 0x1000
    entsize_and_flags = 12 | macho_objc._SMALL_METHOD_FLAG
    mem = {
        mlist: struct.pack("<I", entsize_and_flags),
        mlist + 4: struct.pack("<I", 2),
    }
    # Two small entries (12 bytes each) start at mlist + 8.
    e0 = mlist + 8
    e1 = e0 + 12
    # nameOffset is self-relative; it points at a selref slot.
    mem[e0] = struct.pack("<i", 0x100)  # selref slot at e0 + 0x100
    mem[e1] = struct.pack("<i", 0x200)
    ptrs = {e0 + 0x100: 0xAAA0, e1 + 0x200: 0xBBB0}
    strings = {0xAAA0: "viewDidLoad", 0xBBB0: "dealloc"}
    reader = FakeReader(mem=mem, ptrs=ptrs, strings=strings)
    assert _parse_method_list(reader, mlist) == ["viewDidLoad", "dealloc"]


def test_parse_big_method_list_resolves_pointers():
    mlist = 0x2000
    mem = {
        mlist: struct.pack("<I", 24),  # big format, entsize 24, no small flag
        mlist + 4: struct.pack("<I", 1),
    }
    entry = mlist + 8
    ptrs = {entry: 0xCCC0}  # SEL pointer for the single method
    strings = {0xCCC0: "init"}
    reader = FakeReader(mem=mem, ptrs=ptrs, strings=strings)
    assert _parse_method_list(reader, mlist) == ["init"]


def test_parse_method_list_handles_missing_list():
    reader = FakeReader()
    assert _parse_method_list(reader, 0) == []
    assert _parse_method_list(reader, 0x9999) == []


def test_parse_protocol_list_collects_names():
    plist = 0x3000
    mem = {plist: struct.pack("<I", 2)}  # count (read as u32)
    ptrs = {
        plist + 8: 0x4000,  # protocol_t #0
        plist + 16: 0x5000,  # protocol_t #1
        0x4000 + macho_objc._PROTO_NAME: 0x4100,
        0x5000 + macho_objc._PROTO_NAME: 0x5100,
    }
    strings = {0x4100: "NSCopying", 0x5100: "NSCoding"}
    reader = FakeReader(mem=mem, ptrs=ptrs, strings=strings)
    assert _parse_protocol_list(reader, plist) == ["NSCopying", "NSCoding"]


def test_iter_small_method_entries_recovers_imp_addresses():
    # Small entries store name/types/imp as three self-relative int32 offsets.
    mlist = 0x1000
    entsize_and_flags = 12 | macho_objc._SMALL_METHOD_FLAG
    mem = {
        mlist: struct.pack("<I", entsize_and_flags),
        mlist + 4: struct.pack("<I", 1),
    }
    e0 = mlist + 8
    mem[e0] = struct.pack("<i", 0x100)  # name offset -> selref slot
    mem[e0 + 8] = struct.pack("<i", 0x40)  # imp offset, self-relative to e0 + 8
    ptrs = {e0 + 0x100: 0xAAA0}
    strings = {0xAAA0: "doWork"}
    reader = FakeReader(mem=mem, ptrs=ptrs, strings=strings)
    entries = list(_iter_method_entries(reader, mlist))
    assert entries == [("doWork", e0 + 8 + 0x40)]


def test_iter_big_method_entries_reads_imp_pointer():
    mlist = 0x2000
    mem = {
        mlist: struct.pack("<I", 24),  # big format, no small flag
        mlist + 4: struct.pack("<I", 1),
    }
    entry = mlist + 8
    ptrs = {entry: 0xCCC0, entry + 16: 0xD000}  # SEL pointer and imp pointer
    strings = {0xCCC0: "init"}
    reader = FakeReader(mem=mem, ptrs=ptrs, strings=strings)
    entries = list(_iter_method_entries(reader, mlist))
    assert entries == [("init", 0xD000)]
    # The name-only helper stays backwards compatible.
    assert _parse_method_list(reader, mlist) == ["init"]


class _FakeSection:
    def __init__(self, va, size):
        self.virtual_address = va
        self.size = size


class _FakeCpuType:
    def __init__(self, value):
        self.value = value


class _FakeHeader:
    def __init__(self, cpu_type):
        self.cpu_type = _FakeCpuType(cpu_type)


class _FakeBinary:
    """Minimal stand-in exercising the chained-fixup pointer fallback."""

    def __init__(self, raw_by_va, *, imagebase, sections, cpu_type=0x0100000C):
        self._raw = raw_by_va
        self.imagebase = imagebase
        self.relocations = []
        self.bindings = []
        self.sections = [_FakeSection(va, size) for va, size in sections]
        self.header = _FakeHeader(cpu_type)

    def get_content_from_virtual_address(self, va, size):
        return self._raw.get((va, size), b"")


def test_reader_decodes_chained_rebase_pointer_without_relocations():
    # 64-bit rebase chained pointer: low 36 bits hold the offset from the image
    # base; nothing is in the relocation map so the raw fallback must decode it.
    imagebase = 0x100000000
    target = imagebase + 0x4000
    raw = 0x4000  # 36-bit rebase offset
    binary = _FakeBinary(
        {(0x200, 8): struct.pack("<Q", raw)},
        imagebase=imagebase,
        sections=[(imagebase, 0x100000)],
    )
    reader = macho_objc._MachoReader(binary)
    assert reader.is_64 is True
    assert reader.ptr(0x200) == target


def test_reader_rejects_out_of_image_candidate():
    binary = _FakeBinary(
        {(0x200, 8): struct.pack("<Q", 0xDEADBEEFDEADBEEF)},
        imagebase=0x100000000,
        sections=[(0x100000000, 0x1000)],
    )
    reader = macho_objc._MachoReader(binary)
    assert reader.ptr(0x200) is None


def test_reader_detects_32bit_binary():
    binary = _FakeBinary({}, imagebase=0x4000, sections=[(0x4000, 0x100)], cpu_type=0x0000000C)
    reader = macho_objc._MachoReader(binary)
    assert reader.is_64 is False


def test_parse_objc_metadata_empty_for_non_macho():
    assert parse_objc_metadata(object()) == {}
