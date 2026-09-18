# SPDX-License-Identifier: Apache-2.0
"""Tests for the PE debug directory and rich header decoding (W1.1)."""

import struct

import pytest

from blint.lib.binary import parse
from blint.lib.pe_debug import (
    compute_rich_checksum,
    decode_comp_id,
    decode_rich_header,
    format_pdb_guid,
    parse_codeview_payload,
    pdb_filename,
)

PYTHON313_HEADER = "tests/data/pe/python313-amd64-header.bin"
# RSDS GUID payload bytes for Data1=0x7F0F7557, Data2=0x29F5, Data3=0x47E3:
# the first three fields are little-endian, which is how dumpbin prints it.
LE_GUID = bytes.fromhex("57750F7FF529E34789CCE15613B51A64")


def _pe64_image(dll_characteristics: int = 0, subsystem: int = 3) -> bytes:
    """A minimal PE32+ image, mirroring the W0.1 builder in test_binary."""
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0xF0, 0x0022)
    optional = bytearray(0xF0)
    struct.pack_into("<H", optional, 0, 0x20B)
    struct.pack_into("<I", optional, 16, 0x1000)
    struct.pack_into("<I", optional, 32, 0x1000)
    struct.pack_into("<I", optional, 36, 0x200)
    struct.pack_into("<H", optional, 68, subsystem)
    struct.pack_into("<H", optional, 70, dll_characteristics)
    section_raw, section_rva = 0x400, 0x1000
    struct.pack_into("<I", optional, 56, section_rva + section_raw)
    struct.pack_into("<I", optional, 60, section_raw)
    struct.pack_into("<I", optional, 108, 16)
    sec_header = struct.pack(
        "<8sIIIIIIHHI", b".text\0\0\0", 0x400, section_rva, 0x400, section_raw, 0, 0, 0, 0,
        0x60000020,
    )
    return b"".join([bytes(dos), b"PE\x00\x00", coff, bytes(optional), sec_header]).ljust(
        section_raw, b"\x00"
    )


def _debug_directory_image(entries: list[tuple[int, bytes]]) -> bytes:
    """A PE32+ image whose debug directory holds the given (type, payload)
    pairs, laid out the way the Windows linker lays them out: the payload
    bytes first, then the IMAGE_DEBUG_DIRECTORY array, with data directory
    index 6 pointing at the array. Payloads live in the mapped section, so
    LIEF reads them through it."""
    section_rva = 0x1000
    section_raw = 0x1000
    headers_end = 0x400  # file offset of the section's raw data

    payload_area = bytearray()
    payload_offsets = []
    for _dtype, payload in entries:
        payload_offsets.append(len(payload_area))
        payload_area += payload
        # Real linkers 4-align each payload and the directory itself; LIEF
        # reads the array through aligned pointers only.
        while len(payload_area) % 4:
            payload_area += b"\x00"
    directory_offset = len(payload_area)

    body = bytearray(section_raw)
    body[0 : len(payload_area)] = payload_area
    offset = directory_offset
    timestamp = 1727000000
    for (dtype, payload), payload_offset in zip(entries, payload_offsets):
        struct.pack_into(
            "<IIHHIIII",
            body,
            offset,
            0,  # Characteristics
            timestamp,
            0,
            0,
            dtype,
            len(payload),
            section_rva + payload_offset,  # AddressOfRawData
            headers_end + payload_offset,  # PointerToRawData
        )
        offset += 28

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0xF0, 0x0022)
    optional = bytearray(0xF0)
    struct.pack_into("<H", optional, 0, 0x20B)
    struct.pack_into("<I", optional, 16, 0x1000)
    struct.pack_into("<I", optional, 32, 0x1000)
    struct.pack_into("<I", optional, 36, 0x200)
    struct.pack_into("<H", optional, 68, 3)
    struct.pack_into("<I", optional, 56, section_rva + section_raw)
    struct.pack_into("<I", optional, 60, headers_end)
    struct.pack_into("<I", optional, 108, 16)
    struct.pack_into(
        "<II", optional, 112 + 6 * 8, section_rva + directory_offset, 28 * len(entries)
    )
    sec_header = struct.pack(
        "<8sIIIIIIHHI",
        b".rdata\0\0", 0x1000, section_rva, section_raw, headers_end, 0, 0, 0, 0,
        0x40000040,
    )
    image = b"".join([bytes(dos), b"PE\x00\x00", coff, bytes(optional), sec_header])
    return image.ljust(headers_end, b"\x00") + bytes(body)


def _rsds_payload(path: bytes, guid: bytes, age: int = 1) -> bytes:
    return b"RSDS" + guid + struct.pack("<I", age) + path + b"\x00"


def _nb10_payload(path: bytes, timestamp: int, age: int = 2) -> bytes:
    return b"NB10" + struct.pack("<III", 0, timestamp, age) + path + b"\x00"


def test_parse_codeview_payload_rsds():
    guid = bytes.fromhex("57 75 0f 7f 2b 29 e3 47 89 cc e1 56 13 b5 1a 64".replace(" ", ""))
    info = parse_codeview_payload(_rsds_payload(b"D:\\bld\\foo.pdb", guid, age=7))
    assert info["signature"] == "RSDS"
    # dumpbin prints the GUID with the first three fields little-endian.
    assert info["guid"] == "7F0F7557-292B-47E3-89CC-E15613B51A64"
    assert info["age"] == 7
    assert info["pdb_path"] == "D:\\bld\\foo.pdb"


def test_parse_codeview_payload_nb10():
    info = parse_codeview_payload(_nb10_payload(b"C:\\src\\old.pdb", 123456789))
    assert info["signature"] == "NB10"
    assert info["guid"] is None
    assert info["age"] == 2
    assert info["pdb_path"] == "C:\\src\\old.pdb"


def test_parse_codeview_payload_unknown_signature():
    info = parse_codeview_payload(b"ZZZZ" + b"\x00" * 24)
    assert info["signature"] == "ZZZZ"
    assert info["guid"] is None and info["pdb_path"] is None


def test_format_pdb_guid_short_payload():
    assert format_pdb_guid(b"RSDS") is None


def test_pdb_filename_windows_and_posix():
    assert pdb_filename("D:\\a\\1\\b\\bin\\amd64\\python313.pdb") == "python313.pdb"
    assert pdb_filename("/home/user/build/x.pdb") == "x.pdb"
    assert pdb_filename("x.pdb") == "x.pdb"


def test_decode_comp_id_known_and_fallback():
    # The pair this packet validated against python313.dll's linker record.
    row = decode_comp_id(0x0102, 35213)
    assert row["tool"] == "LNK"
    assert "VS2022" in row["label"]
    # Unknown pair, known product: tool from the product id, no label.
    row = decode_comp_id(0x0104, 99999)
    assert row["tool"] == "C" and row["label"] == ""
    # Unknown pair and product: visible UNKNOWN, never a silent guess.
    row = decode_comp_id(0x777, 1)
    assert row["tool"] == "UNKNOWN(1911)"


def test_decode_rich_header_real_artifact_slice():
    """The committed slice is the first 512 bytes of tier-0 python313.dll:
    a real MSVC rich header whose checksum validates and whose linker
    record names the exact toolset."""
    block = decode_rich_header(PYTHON313_HEADER)
    assert block is not None
    assert block["checksum_valid"] is True
    assert block["key"] == "0x22e37547"
    assert len(block["entries"]) == 12
    linker = [row for row in block["decoded"] if row["tool"] == "LNK"]
    assert linker and linker[0]["build_id"] == 35213
    assert "VS2022" in linker[0]["label"]
    assert block["toolchain"]["linker_build_id"] == 35213
    # python.org builds with PGO (234 POC objects) and carries parts built
    # by more than one toolchain drop.
    tools = {row["tool"] for row in block["decoded"]}
    assert "POC" in tools
    assert block["toolchain"]["mixed_toolchain"] is True


def test_decode_rich_header_non_pe(tmp_path):
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"not a pe" * 100)
    assert decode_rich_header(str(junk)) is None


def test_decode_rich_header_tampered_checksum(tmp_path):
    """A flipped byte in the DOS stub breaks the checksum but the header
    still decodes — a forensic signal, not a parse error."""
    with open(PYTHON313_HEADER, "rb") as handle:
        data = bytearray(handle.read())
    data[0x60] ^= 0xFF
    tampered = tmp_path / "tampered.bin"
    tampered.write_bytes(bytes(data))
    block = decode_rich_header(str(tampered))
    assert block is not None
    assert block["checksum_valid"] is False
    assert block["entries"]  # entries still decoded


def test_compute_rich_checksum_zeroes_lfanew():
    """The e_lfanew bytes are excluded from the DOS-stub sum (the linker
    rewrites them after checksumming) — flipping them must not change the
    computed value."""
    with open(PYTHON313_HEADER, "rb") as handle:
        data = handle.read()
    entries = [(0x0102898D, 1)]
    base = compute_rich_checksum(data, 0x80, entries)
    flipped = bytearray(data)
    flipped[0x3C] ^= 0xFF
    assert compute_rich_checksum(bytes(flipped), 0x80, entries) == base


def test_parse_pe_debug_directory_entries(tmp_path):
    guid = LE_GUID
    payloads = [
        (2, _rsds_payload(b"D:\\a\\1\\b\\x.pdb", guid)),
        (16, bytes(range(16))),  # REPRO
        (20, struct.pack("<I", 0x03)),  # EX_DLLCHARACTERISTICS
    ]
    exe_file = tmp_path / "debug.exe"
    exe_file.write_bytes(_debug_directory_image(payloads))
    metadata = parse(str(exe_file))
    debug = metadata["debug"]
    types = [entry["type"] for entry in debug["entries"]]
    assert types == ["CODEVIEW", "REPRO", "EX_DLLCHARACTERISTICS"]
    assert debug["codeview"]["signature"] == "RSDS"
    assert debug["codeview"]["pdb_path"] == "D:\\a\\1\\b\\x.pdb"
    assert debug["codeview"]["pdb_filename"] == "x.pdb"
    assert debug["codeview"]["guid"] == "7F0F7557-29F5-47E3-89CC-E15613B51A64"
    # REPRO is a computed False when the directory exists without one, and
    # a computed True with the hash when it does.
    assert debug["repro"] == {"present": True, "hash": bytes(range(16)).hex()}
    assert debug["ex_dllcharacteristics"] == ["CET_COMPAT", "CET_COMPAT_STRICT_MODE"]
    # security_properties reads the same block, not a second parse.
    properties = metadata["security_properties"]
    assert properties["cet_shadow_stack"] is True
    assert properties["cet_shadow_stack_strict"] is True
    assert properties["debug_info"] == "full"
    assert properties["debug_info_pdb_path"] == "D:\\a\\1\\b\\x.pdb"


def test_parse_pe_debug_without_repro_entry(tmp_path):
    guid = LE_GUID
    exe_file = tmp_path / "no_repro.exe"
    exe_file.write_bytes(
        _debug_directory_image([(2, _rsds_payload(b"x.pdb", guid))])
    )
    debug = parse(str(exe_file))["debug"]
    assert debug["repro"] == {"present": False}
    assert "ex_dllcharacteristics" not in debug
    properties = parse(str(exe_file))["security_properties"]
    assert properties["cet_shadow_stack"] is False


def test_parse_pe_debug_absent_directory(tmp_path):
    exe_file = tmp_path / "nodebug.exe"
    exe_file.write_bytes(_pe64_image())
    metadata = parse(str(exe_file))
    assert metadata["debug"] == {}
    properties = metadata["security_properties"]
    assert "debug_info" not in properties
    assert "cet_shadow_stack" not in properties
    gaps = metadata["security_properties_gaps"]
    assert "debug_info" in gaps and "cet_shadow_stack" in gaps


def test_parse_pe_debug_hostile_oversized_entry(tmp_path):
    """A hostile SizeOfData is capped: the payload fallback read never
    copies more than 4 KiB, and the entry still decodes."""
    guid = LE_GUID
    exe_file = tmp_path / "hostile.exe"
    exe_file.write_bytes(
        _debug_directory_image([(2, _rsds_payload(b"D:\\x\\a.pdb" + b"\x41" * 8, guid))])
    )
    debug = parse(str(exe_file))["debug"]
    assert debug["codeview"]["pdb_path"].startswith("D:\\x\\a.pdb")


def test_build_path_leak_rule_fires_on_absolute_path():
    from blint.lib.analysis import load_default_rules, run_checks

    load_default_rules()
    metadata = {
        "exe_type": "PE64",
        "debug": {"codeview": {"pdb_path": "D:\\a\\1\\b\\bin\\amd64\\x.pdb"}},
    }
    results = run_checks("x.exe", metadata)
    rule = next(r for r in results if r["id"] == "CHECK_BUILD_PATH_LEAK")
    assert rule["severity"] == "low"
    assert "D:\\a\\1\\b" in rule["title"]


@pytest.mark.parametrize(
    "pdb_path",
    ["obj\\x64\\release\\x.pdb", "x.pdb", "", None],
)
def test_build_path_leak_rule_passes_relative_or_absent(pdb_path):
    from blint.lib.analysis import load_default_rules, run_checks

    load_default_rules()
    codeview = {"pdb_path": pdb_path} if pdb_path else {}
    metadata = {"exe_type": "PE64", "debug": {"codeview": codeview}}
    ids = {r["id"] for r in run_checks("x.exe", metadata)}
    assert "CHECK_BUILD_PATH_LEAK" not in ids

# The committed hello.exe was built on the Windows VM with MSVC 19.44.35228
# (VS2022 17.14.34, x64, /Zi) and an rc.exe VERSIONINFO+manifest+icon pass.
# The values below are its ground truth from the build machine (dumpbin
# /headers: RSDS GUID/age/path and the feat "Counts" line; the linker
# version line "14.44"); see scripts/windows/debug_richheader_check.ps1.
HELLO = "tests/data/pe/msvc-hello-x64.exe"
HELLO_PDB_PATH = "C:\\Users\\appthreat\\hello\\hello.pdb"


def test_real_msvc_fixture_rich_header_and_debug():
    block = parse(HELLO)["debug"]
    assert block["codeview"] == {
        "signature": "RSDS",
        "guid": "D4311FC4-1CF0-447C-AF99-5C180313F75C",
        "age": 1,
        "pdb_path": HELLO_PDB_PATH,
        "pdb_filename": "hello.pdb",
    }
    # dumpbin: "Counts: Pre-VC++ 11.00=0, C/C++=210, /GS=210, /sdl=0, guardN=209"
    assert block["vc_feature"] == {
        "c_cpp": 210,
        "gs": 210,
        "guards": 209,
        "sdl": 0,
        "pre_vcpp": 0,
    }
    assert block["repro"] == {"present": False}


def test_real_msvc_fixture_rich_header_names_its_toolchain():
    rich = parse(HELLO)["rich_header"]
    assert rich["checksum_valid"] is True
    # The freshly built binary names the exact toolchain that built it:
    # the VM's link 14.44 build 35228.
    linker = [row for row in rich["decoded"] if row["tool"] == "LNK"]
    assert linker and linker[0]["build_id"] == 35228
    assert rich["toolchain"]["linker_build_id"] == 35228
    assert "VS2022" in rich["toolchain"]["linker_label"]
    # The CRT objects came from older drops than the linker.
    assert rich["toolchain"]["mixed_toolchain"] is True


def test_real_msvc_fixture_build_path_leak_fires():
    from blint.lib.analysis import load_default_rules, run_checks

    load_default_rules()
    metadata = parse(HELLO)
    ids = {r["id"]: r for r in run_checks(HELLO, metadata)}
    rule = ids["CHECK_BUILD_PATH_LEAK"]
    assert HELLO_PDB_PATH in rule["title"]

def test_rich_toolchain_ignores_build_zero_imports():
    """The (1, 0) import-count record is present in nearly every image and
    must never make a single-toolchain build read as mixed."""
    from blint.lib.pe_debug import _rich_toolchain

    decoded = [
        {"product_id": 1, "tool": "IMP", "label": "", "build_id": 0, "count": 393},
        {"product_id": 0x0102, "tool": "LNK", "label": "VS2022 v17.14.9 build 35213",
         "build_id": 35213, "count": 1},
    ]
    toolchain = _rich_toolchain(decoded)
    assert toolchain["mixed_toolchain"] is False
    assert toolchain["comp_id_builds"] == [35213]


def test_debug_type_name_unknown_value_renders_visible():
    from blint.lib.pe_constants import debug_type_name

    assert debug_type_name(0x63) == "UNKNOWN(99)"

