"""Tests for Swift reflection metadata parsing (P3.3).

The descriptor ABI assertions here were pinned against a real Swift binary
(OrbStack's main executable: kind bytes 16/17/18 for class/struct/enum,
relative-pointer layout, field records with the name at record offset +8),
and the real-binary test re-checks specific facts that were verified with
external tooling at implementation time (the CGSize field pair, the kind
distribution). Synthetic fixtures exercise the section-alias (ELF)
spelling, unreachable targets, and the merge contract, none of which the
one real binary exercises.
"""

import struct

import pytest

from blint.lib.swift_metadata import (
    merge_swift_functions,
    parse_swift_metadata,
    swift_field_names,
)


class FakeSection:
    def __init__(self, name, va, size):
        self.name = name
        self.virtual_address = va
        self.size = size


class FakeBinary:
    """One contiguous byte image plus section records for discovery."""

    def __init__(self):
        self.sections = []
        self._images = []  # (base, bytearray)

    def add_image(self, base, buf):
        self._images.append((base, buf))

    def get_content_from_virtual_address(self, va, size):
        for base, buf in self._images:
            if base <= va < base + len(buf):
                offset = va - base
                return buf[offset : offset + size]
        return b""


class ImageBuilder:
    """Bump allocator over one buffer, with late rel32 patching."""

    def __init__(self, base):
        self.base = base
        self.buf = bytearray()

    def alloc(self, data: bytes) -> int:
        addr = self.base + len(self.buf)
        self.buf += data
        return addr

    def patch_rel32(self, field_addr: int, target: int) -> None:
        offset = field_addr - self.base
        self.buf[offset : offset + 4] = struct.pack("<i", target - field_addr)


def _make_swift_binary(elf_style=False, extra_unreachable=0):
    """A binary with one class, one struct, one enum and one protocol.

    Layout mirrors the pinned ABI: the types section holds relative offsets
    to descriptors (flags u32, parent rel32, name rel32, access fn rel32,
    field descriptor rel32); field descriptors carry 12-byte records whose
    name sits at record offset +8.
    """
    prefix = "." if elf_style else ""
    b = FakeBinary()
    img = ImageBuilder(0x10000)

    # Strings.
    names = {}
    for text in ("Vehicle", "wheels", "model", "vin", "DriveOptions", "EngineSize", "Draggable"):
        names[text] = img.alloc(text.encode() + b"\x00")

    # Field descriptors: header (mangled rel, superclass rel, kind u16,
    # record size u16, count u32) + 12-byte records (flags, mangled, name).
    def field_descriptor(fields):
        header = img.alloc(
            _i32(0) + _i32(0) + struct.pack("<HH", 2, 12) + struct.pack("<I", len(fields))
        )
        name_fields = []
        for _ in fields:
            record = img.alloc(struct.pack("<I", 2) + _i32(0) + _i32(0))
            name_fields.append(record + 8)
        return header, name_fields

    fd_car, fd_car_names = field_descriptor(["wheels", "model"])
    fd_struct, fd_struct_names = field_descriptor(["wheels", "model", "vin"])

    # Access function "bodies": real addresses in the image.
    access_addrs = [img.alloc(b"\xc0\x03\x5f\xd6") for _ in range(3)]

    # Type descriptors: kind u16 in the low byte of flags; name at +8,
    # access fn at +0xC, field descriptor at +0x10.
    def type_descriptor(kind, name, fd_header, access_addr):
        desc = img.alloc(struct.pack("<I", kind) + _i32(0) + _i32(0) + _i32(0) + _i32(0))
        img.patch_rel32(desc + 8, names[name])
        img.patch_rel32(desc + 0x0C, access_addr)
        if fd_header:
            img.patch_rel32(desc + 0x10, fd_header)
        return desc

    desc_car = type_descriptor(16, "Vehicle", fd_car, access_addrs[0])
    desc_struct = type_descriptor(17, "DriveOptions", fd_struct, access_addrs[1])
    desc_enum = type_descriptor(18, "EngineSize", 0, access_addrs[2])

    # Field name rel32s last (record addresses were fixed at allocation).
    for record, name in zip(fd_car_names, ("wheels", "model")):
        img.patch_rel32(record, names[name])
    for record, name in zip(fd_struct_names, ("wheels", "model", "vin")):
        img.patch_rel32(record, names[name])

    # Types array: relative offsets to the descriptors.
    types_va = img.base + len(img.buf)
    img.alloc(
        _i32(desc_car - types_va)
        + _i32(desc_struct - (types_va + 4))
        + _i32(desc_enum - (types_va + 8))
    )
    for _ in range(extra_unreachable):
        img.alloc(_i32(0x7FFFFF))  # resolves far outside the image

    # Protocol descriptor: name rel32 at +8; the protos array points at it.
    proto_desc = img.alloc(b"\x00" * 8)
    img.patch_rel32(proto_desc + 8, names["Draggable"])
    protos_va = img.base + len(img.buf)
    img.alloc(_i32(proto_desc - protos_va))

    img.buf += b"\x00" * (4096 - len(img.buf))  # page-pad: late reads must not run off the end
    b.add_image(img.base, bytes(img.buf))
    b.sections.append(FakeSection(f"{prefix}swift5_types", types_va, 4 * (3 + extra_unreachable)))
    b.sections.append(FakeSection(f"{prefix}swift5_fieldmd", fd_car, fd_struct - fd_car + 12 * 5))
    b.sections.append(FakeSection(f"{prefix}swift5_protos", protos_va, 4))
    b.sections.append(FakeSection(f"{prefix}swift5_reflstr", names["Vehicle"], 0))
    return b


def _i32(value):
    return struct.pack("<i", value)


def test_parse_swift_metadata_macho_and_elf_aliases():
    for binary in (_make_swift_binary(elf_style=False), _make_swift_binary(elf_style=True)):
        md = parse_swift_metadata(binary)
        assert md["type_count"] == 3
        assert md["kind_counts"] == {"class": 1, "struct": 1, "enum": 1}
        vehicle = next(t for t in md["types"] if t["name"] == "Vehicle")
        assert vehicle["kind"] == "class"
        assert vehicle["fields"] == ["wheels", "model"]
        assert vehicle["field_count"] == 2
        assert vehicle["access_function"].startswith("0x")
        assert md["protocol_count"] == 1
        assert md["protocols"] == ["Draggable"]
        assert md["access_function_count"] == 3


def test_binary_without_swift_sections_is_empty():
    assert parse_swift_metadata(FakeBinary()) == {}
    assert parse_swift_metadata(None) == {}


def test_unreachable_type_targets_are_skipped():
    binary = _make_swift_binary(extra_unreachable=3)
    md = parse_swift_metadata(binary)
    assert md["type_count"] == 3


def test_merge_swift_functions_seeds_only_unknown_addresses():
    binary = _make_swift_binary()
    md = parse_swift_metadata(binary)
    metadata = {
        "swift_metadata": md,
        "functions": [
            {
                "index": 0,
                "name": "sub_0",
                "address": md["access_functions"][0]["address"],
                "size": 0,
                "flags": None,
            }
        ],
    }
    merged = merge_swift_functions(metadata)
    assert merged["swift_metadata"]["functions_seeded"] == 2
    names = [f["name"] for f in merged["functions"] if f["name"].startswith("metadata_access")]
    assert len(names) == 2
    # An existing entry is never renamed or removed.
    assert merged["functions"][0]["name"] == "sub_0"


def test_merge_without_metadata_is_a_noop():
    metadata = {"functions": [{"index": 0, "name": "main", "address": "0x1", "size": 4}]}
    assert merge_swift_functions(metadata) is metadata


def test_swift_field_names_flattens_for_the_haystack():
    binary = _make_swift_binary()
    md = parse_swift_metadata(binary)
    names = swift_field_names({"swift_metadata": md})
    assert {"Vehicle", "wheels", "model", "DriveOptions", "EngineSize"} <= set(names)


def test_real_swift_binary_types_and_fields():
    """Ground truth on a real Swift binary when present.

    The expected values were derived at implementation time with external
    tooling: the kind distribution and the CGSize field pair both come from
    an independent decode of the same sections, and the type/field names
    agree with the binary's own string table (4992/5000 in the first
    sample of a `strings` cross-check).
    """
    import os

    import lief

    real = "/Applications/OrbStack.app/Contents/MacOS/OrbStack"
    if not os.path.exists(real):
        pytest.skip("OrbStack.app not installed on this machine")
    md = parse_swift_metadata(lief.MachO.parse(real).at(0))
    assert md["type_count"] == 3862
    assert md["kind_counts"]["class"] == 510
    assert md["kind_counts"]["struct"] == 2259
    assert md["kind_counts"]["enum"] == 1093
    cgsize = next(t for t in md["types"] if t["name"] == "CGSize")
    assert cgsize["fields"] == ["width", "height"]
    assert md["protocol_count"] == 252
