"""Tests for the raw Objective-C metadata parser.

The pointer-walking entry points are exercised against a synthetic in-memory
layout via a fake reader, which lets us validate the tricky small/relative
method-list format (with the selref indirection) without a real Mach-O fixture.
"""

import struct

import pytest

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


def test_parse_ivar_list_legacy_entsize_32():
    # ivar_list_t at 0x2000: entsize 32 (legacy ivar_t), count 2.
    ilist = 0x2000
    mem = {ilist: struct.pack("<I", 32), ilist + 4: struct.pack("<I", 2)}
    ptrs, strings = {}, {}
    for i, (name, ivar_type) in enumerate((("_count", "q"), ("_items", '@"NSArray"'))):
        entry = ilist + 8 + i * 32
        off_slot, name_va, type_va = 0x3000 + i * 16, 0x4000 + i * 32, 0x5000 + i * 64
        ptrs[entry] = off_slot
        ptrs[entry + 8] = name_va
        ptrs[entry + 16] = type_va
        strings[name_va] = name
        strings[type_va] = ivar_type
    ivars = macho_objc._parse_ivar_list(FakeReader(mem=mem, ptrs=ptrs, strings=strings), ilist)
    assert ivars == [{"name": "_count", "type": "q"}, {"name": "_items", "type": '@"NSArray"'}]


def test_parse_ivar_list_relative_entsize_20():
    # Relative ivar_t (20 bytes): name/type are int32 offsets from their own
    # field address — the encoding chained-fixup binaries use.
    ilist = 0x2100
    mem = {ilist: struct.pack("<I", 20), ilist + 4: struct.pack("<I", 1)}
    entry = ilist + 8
    name_field = entry + 4
    type_field = entry + 8
    mem[name_field] = struct.pack("<i", 0x40)
    mem[type_field] = struct.pack("<i", 0x80)
    ptrs = {name_field + 0x40: 0x6000, type_field + 0x80: 0x6100}
    strings = {0x6000: "_flag", 0x6100: "B"}
    ivars = macho_objc._parse_ivar_list(FakeReader(mem=mem, ptrs=ptrs, strings=strings), ilist)
    assert ivars == [{"name": "_flag", "type": "B"}]


def test_parse_ivar_list_unknown_entsize_degrades_to_partial():
    # An entsize blint does not model must return nothing rather than guess.
    ilist = 0x2200
    reader = FakeReader(mem={ilist: struct.pack("<I", 24), ilist + 4: struct.pack("<I", 1)})
    assert macho_objc._parse_ivar_list(reader, ilist) == []


def test_parse_property_list_legacy_and_relative():
    # Legacy: entsize 16, name pointer, attributes pointer.
    props = 0x2300
    mem = {props: struct.pack("<I", 16), props + 4: struct.pack("<I", 1)}
    ptrs = {props + 8: 0x7000, props + 16: 0x7100}
    strings = {0x7000: "bundleIdentifier", 0x7100: 'T@"NSString",R,N'}
    out = macho_objc._parse_property_list(FakeReader(mem=mem, ptrs=ptrs, strings=strings), props)
    assert out == [{"name": "bundleIdentifier", "attributes": 'T@"NSString",R,N'}]
    # Relative: entsize 8, two int32 offsets from each field's own address.
    props = 0x2400
    mem = {props: struct.pack("<I", 8), props + 4: struct.pack("<I", 1)}
    name_field, attr_field = props + 8, props + 12
    mem[name_field] = struct.pack("<i", 0x30)
    mem[attr_field] = struct.pack("<i", 0x60)
    ptrs = {name_field + 0x30: 0x7200, attr_field + 0x60: 0x7300}
    strings = {0x7200: "tag", 0x7300: 'T@"NSString",C,N'}
    out = macho_objc._parse_property_list(FakeReader(mem=mem, ptrs=ptrs, strings=strings), props)
    assert out == [{"name": "tag", "attributes": 'T@"NSString",C,N'}]


def test_parse_category_fields_and_imp_names():
    # category_t at 0x100: clsName +0, cls +8, instanceMethods +0x10,
    # classMethods +0x18, protocols +0x20, instanceProperties +0x28.
    cat = 0x100
    ptrs = {
        cat: 0x8000,  # clsName string
        cat + 8: 0x9000,  # internal class_t
        cat + 0x10: 0x1000,  # instance method list (small, 1 method)
        cat + 0x18: 0x1100,  # class method list (small, 1 method)
        cat + 0x28: 0x1200,  # property list
    }
    strings = {0x8000: "Sentry", 0x9001: "NSProcessInfo"}
    mem = {cat + 8: b"\x00" * 8}
    # instanceMethods: entsize 12 small flag, count 1; nameOffset -> selref.
    mem[0x1000] = struct.pack("<I", 12 | macho_objc._SMALL_METHOD_FLAG)
    mem[0x1004] = struct.pack("<I", 1)
    mem[0x1008] = struct.pack("<i", 0x10)
    ptrs[0x1008 + 0x10] = 0xA000
    strings[0xA000] = "swizzleForCrash"
    mem[0x1010] = struct.pack("<i", 0x20)  # impOffset, at entry+8
    # classMethods
    mem[0x1100] = struct.pack("<I", 12 | macho_objc._SMALL_METHOD_FLAG)
    mem[0x1104] = struct.pack("<I", 1)
    mem[0x1108] = struct.pack("<i", 0x10)
    ptrs[0x1108 + 0x10] = 0xA100
    strings[0xA100] = "setup"
    mem[0x1110] = struct.pack("<i", 0x20)
    # property list (legacy entsize 16)
    mem[0x1200] = struct.pack("<I", 16)
    mem[0x1204] = struct.pack("<I", 1)
    ptrs[0x1208] = 0xA200
    ptrs[0x1210] = 0xA210
    strings[0xA200] = "crashConfig"
    strings[0xA210] = 'T@"NSDictionary",C,N'

    reader = FakeReader(mem=mem, ptrs=ptrs, strings=strings)
    # The category extends an external class via a binding slot.
    reader.bind_map = {cat + 8: "_OBJC_CLASS_$_NSProcessInfo"}
    imps = []
    parsed = macho_objc._parse_category(reader, cat, imps)
    assert parsed["name"] == "Sentry"
    assert parsed["class_name"] == "NSProcessInfo"
    assert parsed["methods"] == ["swizzleForCrash"]
    assert parsed["class_methods"] == ["setup"]
    assert parsed["properties"] == [{"name": "crashConfig", "attributes": 'T@"NSDictionary",C,N'}]
    names = {imp["name"] for imp in imps}
    assert "-[NSProcessInfo(Sentry) swizzleForCrash]" in names
    assert "+[NSProcessInfo(Sentry) setup]" in names


def test_find_load_imp_walks_the_metaclass():
    # class_t at 0x100, its isa (+0) the metaclass at 0x200; the metaclass
    # data (+32) & ~7 -> ro whose baseMethods (+0x20) carries "load".
    mem = {}
    ptrs = {0x100: 0x200}  # isa
    ptrs[0x200 + 32] = 0x8051  # metaclass data, low bits set (swift/flag)
    strings = {}
    # metaclass ro at 0x8050; baseMethods at ro + 0x20.
    ro = 0x8050
    ptrs[ro + 0x20] = 0x1300
    mem[0x1300] = struct.pack("<I", 12 | macho_objc._SMALL_METHOD_FLAG)
    mem[0x1304] = struct.pack("<I", 1)
    mem[0x1308] = struct.pack("<i", 0x10)
    ptrs[0x1308 + 0x10] = 0xB000
    strings[0xB000] = "load"
    mem[0x1310] = struct.pack("<i", 0x20)  # impOffset, at entry+8
    reader = FakeReader(mem=mem, ptrs={**ptrs, 0x1308 + 0x10: 0xB000}, strings=strings)
    # imp = entry + 8 + impOffset = 0x1308 + 8 + 0x20.
    assert macho_objc._find_load_imp(reader, 0x100) == 0x1308 + 8 + 0x20
    # A class without +load: metaclass method list selects something else.
    strings[0xB000] = "initialize"
    assert macho_objc._find_load_imp(reader, 0x100) is None


def test_real_binary_categories_and_nonlazy_classes():
    """Ground truth on a real binary, when one is present: OrbStack's main
    binary carries __objc_catlist/__objc_nlclslist whose contents otool(1)
    printed (5 categories; Sentry classes own the +load methods)."""
    import os

    import lief

    real = "/Applications/OrbStack.app/Contents/MacOS/OrbStack"
    if not os.path.exists(real):
        pytest.skip("OrbStack.app not installed on this machine")
    md = parse_objc_metadata(lief.MachO.parse(real).at(0))
    assert md, "ObjC metadata expected in this binary"
    assert md.get("category_count") == 5  # otool -o catlist entry count
    assert md.get("parse_degradation_count", 0) == 0
    extended = {c["class_name"] for c in md["categories"]}
    assert "NSTextView" in extended  # patches a framework class
    nonlazy_names = {n["name"] for n in md.get("nonlazy_classes") or []}
    assert any(n.startswith("Sentry") for n in nonlazy_names)
    assert all(n.get("load_imp") for n in md.get("nonlazy_classes") or [])
