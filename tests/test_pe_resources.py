# SPDX-License-Identifier: Apache-2.0
"""Tests for the PE resource tree, VERSIONINFO and manifest depth (W1.3)."""

import hashlib
import struct

from blint.lib.binary import parse
from blint.lib.pe_resources import (
    MAX_RESOURCE_DATA_NODES,
    MAX_RESOURCE_HASH_BYTES,
    _find_fixed_file_info,
    manifest_facts,
)

RT_ICON = 3
RT_RCDATA = 10
RT_VERSION = 16
RT_MANIFEST = 24

MANIFEST_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="Example.App" version="1.2.3.4"/>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <!-- Windows 7 and Windows 10/11 -->
      <supportedOS Id="{35138b9a-5d96-4fbd-8e2d-a2440225f93a}"/>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    </application>
  </compatibility>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true</dpiAware>
      <longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>
      <activeCodePage xmlns="http://schemas.microsoft.com/SMI/2019/WindowsSettings">UTF-8</activeCodePage>
    </windowsSettings>
  </application>
</assembly>
"""


def _u16(value: str) -> bytes:
    return value.encode("utf-16-le")


def _align4(data: bytes) -> bytes:
    return data + b"\x00" * (-len(data) % 4)


def _dir_entry(name_or_id: int, is_name: bool, offset: int, subdir: bool) -> bytes:
    first = (0x80000000 | name_or_id) if is_name else name_or_id
    second = (0x80000000 | offset) if subdir else offset
    return struct.pack("<II", first, second)


def _resource_section(
    types: dict[int, list[tuple[int, int, bytes]]],
) -> bytes:
    """Build a real .rsrc section image from type -> [(id, lang, data)].

    The tree is the loader's own three-level layout: one directory per
    level, string names carrying the high name bit, data entries whose RVA
    fields point back into the section. Offsets are computed in two passes:
    level sizes first, then the data blobs.
    """
    type_count = len(types)
    level0_size = 16 + 8 * type_count
    # Level 1: one directory per type, each with one entry per resource.
    resource_counts = {t: len(rows) for t, rows in types.items()}
    level1_offsets = {}
    offset = level0_size
    for rtype, count in resource_counts.items():
        level1_offsets[rtype] = offset
        offset += 16 + 8 * count
    # Level 2: one directory per (type, resource id) for languages.
    level2_offsets = {}
    for rtype, rows in types.items():
        for rid, lang, _data in rows:
            level2_offsets[(rtype, rid)] = offset
            offset += 16 + 8  # one language entry
    # Data entries and blobs.
    data_entry_offsets = {}
    for rtype, rows in types.items():
        for rid, lang, data in rows:
            data_entry_offsets[(rtype, rid, lang)] = offset
            offset += 16
    blob_offsets = {}
    for rtype, rows in types.items():
        for rid, lang, data in rows:
            blob_offsets[(rtype, rid, lang)] = offset
            offset += len(_align4(data))
    section = bytearray(offset)

    def write_directory(base: int, entries: list[tuple[int, bool, int, bool]]) -> None:
        named = [e for e in entries if e[1]]
        struct.pack_into(
            "<IIHHHH",
            section,
            base,
            0,
            0,
            0,
            0,  # Major/MinorVersion precede the counts
            len(named),
            len(entries) - len(named),
        )
        for i, (ident, is_name, target, subdir) in enumerate(entries):
            section[base + 16 + 8 * i : base + 16 + 8 * i + 8] = _dir_entry(
                ident, is_name, target, subdir
            )

    # Level 0: types
    write_directory(
        0,
        [
            (rtype, False, level1_offsets[rtype], True)
            for rtype in types
        ],
    )
    # Level 1 + level 2 + data entries
    for rtype, rows in types.items():
        write_directory(
            level1_offsets[rtype],
            [(rid, False, level2_offsets[(rtype, rid)], True) for rid, _lang, _d in rows],
        )
        for rid, lang, data in rows:
            write_directory(
                level2_offsets[(rtype, rid)],
                [(lang, False, data_entry_offsets[(rtype, rid, lang)], False)],
            )
            de_off = data_entry_offsets[(rtype, rid, lang)]
            struct.pack_into(
                "<IIII", section, de_off, RESOURCE_SECTION_RVA + blob_offsets[(rtype, rid, lang)],
                len(data), 0, 0,
            )
            blob = _align4(data)
            section[blob_offsets[(rtype, rid, lang)] : blob_offsets[(rtype, rid, lang)] + len(blob)] = blob
    return bytes(section)


RESOURCE_SECTION_RVA = 0x1000
SECTION_RAW = 0x1000
SECTION_SIZE = 0x4000


def _pe_image_with_resources(resource_section: bytes) -> bytes:
    """A PE32+ image with one .rsrc section (data directory index 2),
    sized to the tree that goes into it."""
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
    struct.pack_into("<I", optional, 56, RESOURCE_SECTION_RVA + SECTION_SIZE)
    struct.pack_into("<I", optional, 60, 0x400)
    struct.pack_into("<I", optional, 108, 16)
    struct.pack_into(
        "<II", optional, 112 + 2 * 8, RESOURCE_SECTION_RVA, len(resource_section)
    )
    section_size = -(-len(resource_section) // 0x200) * 0x200
    struct.pack_into("<I", optional, 56, RESOURCE_SECTION_RVA + section_size)
    sec_header = struct.pack(
        "<8sIIIIIIHHI",
        b".rsrc\0\0", section_size, RESOURCE_SECTION_RVA, section_size, 0x400, 0, 0, 0, 0,
        0x40000040,
    )
    image = b"".join([bytes(dos), b"PE\x00\x00", coff, bytes(optional), sec_header])
    return image.ljust(0x400, b"\x00") + resource_section.ljust(section_size, b"\x00")


def _minimal_pe_blob(machine: int = 0x8664) -> bytes:
    """A structurally valid PE image for the embedded-PE detection: real DOS
    header, e_lfanew, PE signature and COFF header."""
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    pe = b"PE\x00\x00" + struct.pack("<HHIIIHH", machine, 1, 0, 0, 0, 0xF0, 0x0022)
    return bytes(dos) + pe


def _version_resource(
    fixed: bytes | None,
    strings: dict[str, dict[str, str]] | None = None,
) -> bytes:
    """A real VS_VERSIONINFO resource blob (fixed block + string tables)."""
    body = bytearray()
    # VS_VERSIONINFO header: length(2), value_length(2), type(2), key.
    # The value is the fixed block; a strings-only VERSIONINFO has none and
    # carries wValueLength 0, which is what LIEF's own parser expects.
    root_value_length = 52 if fixed else 0
    body += b"\x00\x00" + struct.pack("<HH", root_value_length, 0) + _u16("VS_VERSION_INFO") + b"\x00\x00"
    body += b"\x00" * (-len(body) % 4)
    if fixed:
        body += fixed
    if strings:
        # One StringFileInfo block holding one table per language, the way
        # rc.exe compiles multi-language resources.
        str_block = bytearray()
        str_block += b"\x00\x00" + struct.pack("<HH", 0, 1) + _u16("StringFileInfo") + b"\x00\x00"
        str_block += b"\x00" * (-len(str_block) % 4)
        for lang_key, entries in strings.items():
            table = bytearray()
            table += b"\x00\x00" + struct.pack("<HH", 0, 1) + _u16(lang_key) + b"\x00\x00"
            table += b"\x00" * (-len(table) % 4)
            for key, value in entries.items():
                entry = bytearray()
                value_u16 = _u16(value) + b"\x00\x00"
                # wValueLength counts WORDS for text values (the spec).
                entry += b"\x00\x00" + struct.pack("<HH", len(value_u16) // 2, 1)
                entry += _u16(key) + b"\x00\x00"
                entry += b"\x00" * (-len(entry) % 4)
                entry += value_u16
                entry = struct.pack("<H", len(entry)) + entry[2:]
                table += entry
                table += b"\x00" * (-len(table) % 4)
            table = struct.pack("<H", len(table)) + table[2:]
            str_block += table
        str_block = struct.pack("<H", len(str_block)) + str_block[2:]
        body += str_block
    body = struct.pack("<H", len(body)) + body[2:]
    return bytes(body)


def _fixed_block(major: int, minor: int, build: int, revision: int) -> bytes:
    """A VS_FIXEDFILEINFO carrying one version quad in both version fields."""
    ms, ls = (major << 16) | minor, (build << 16) | revision
    return struct.pack(
        "<13I", 0xFEEF04BD, 0x00010000, ms, ls, ms, ls, 0x3F, 0, 4, 2, 0, 0, 0
    )


_FIXED_BLOCK = struct.pack(
    "<13I",
    0xFEEF04BD,  # signature
    0x00010000,  # struct version
    (3 << 16) | 13,  # file version MS: 3.13
    (7150 << 16) | 1013,  # file version LS
    (3 << 16) | 13,
    (7150 << 16) | 1013,
    0x0000003F,  # flags mask
    0x00000000,  # flags
    4,  # file os: VOS__WINDOWS32
    2,  # file type: DLL
    0,
    0,
    0,
)


def test_manifest_facts_full():
    facts = manifest_facts(MANIFEST_XML)
    assert facts["parse_status"] == "parsed"
    assert facts["requestedExecutionLevel"] == "requireAdministrator"
    assert facts["uiAccess"] is False
    assert facts["dpiAware"] == "true"
    assert facts["longPathAware"] is True
    assert facts["activeCodePage"] == "UTF-8"
    assert facts["supportedOS"] == ["Windows 7", "Windows 10/11"]
    assert facts["assembly_identities"][0]["name"] == "Example.App"


def test_manifest_facts_failed_parse_is_recorded():
    facts = manifest_facts(b"<assembly><unclosed>")
    assert facts == {"parse_status": "failed"}
    assert manifest_facts(None) == {}


def test_find_fixed_file_info():
    blob = bytearray(0x40)
    blob += _FIXED_BLOCK
    fixed = _find_fixed_file_info(bytes(blob))
    assert fixed["file_version"] == "3.13.7150.1013"
    assert fixed["product_version"] == "3.13.7150.1013"
    assert fixed["file_os"] == "WINDOWS32"
    assert fixed["file_type"] == 2
    assert fixed["file_flags"] == []
    # A zeroed flags field with a full mask computes to no flags: a fact.
    assert fixed["file_flags_mask"] == 0x3F


def test_find_fixed_file_info_absent():
    assert _find_fixed_file_info(b"\x00" * 100) is None


def test_version_info_mismatch_is_the_tamper_signal(tmp_path):
    """String table says 5.0, the fixed block says 3.13: mismatch reported."""
    strings = {"040904b0": {"FileVersion": "5.0", "ProductVersion": "3.13.7"}}
    section = _resource_section(
        {RT_VERSION: [(1, 1033, _version_resource(_FIXED_BLOCK, strings))]}
    )
    exe_file = tmp_path / "tampered.exe"
    exe_file.write_bytes(_pe_image_with_resources(section))
    metadata = parse(str(exe_file))
    version_info = metadata["version_info"]
    assert version_info["present"] is True
    assert version_info["languages"] == ["040904b0"]
    assert version_info["strings"]["040904b0"]["FileVersion"] == "5.0"
    assert version_info["fixed"]["file_version"] == "3.13.7150.1013"
    assert version_info["mismatches"] == ["FileVersion"]


def test_version_info_semantic_agreement(tmp_path):
    """A marketing string (3.13.7) beside a full fixed block (3.13.7150.1013)
    agrees on the first two components: not a mismatch."""
    strings = {"040904b0": {"FileVersion": "3.13.7", "ProductVersion": "3.13.7"}}
    section = _resource_section(
        {RT_VERSION: [(1, 1033, _version_resource(_FIXED_BLOCK, strings))]}
    )
    exe_file = tmp_path / "stock.exe"
    exe_file.write_bytes(_pe_image_with_resources(section))
    version_info = parse(str(exe_file))["version_info"]
    assert "mismatches" not in version_info


def test_version_info_marketing_string_is_not_a_mismatch(tmp_path):
    """Sysinternals ships "1.83" against a fixed 1.8.3.0, and "14.3" against
    14.30.0.0, on Microsoft-signed unmodified binaries.

    Only the major component is comparable between the two: the rest of the
    string table is marketing text a vendor writes however it likes. A
    component-wise comparison called 34 of the 177 tier-0/1 files tampered,
    which is the false-positive class this lane exists to remove — and it
    escaped the gate because ``mismatches`` is a metadata field with no rule
    behind it, so fp_gate never counted it.
    """
    # (fixed quad, the string the vendor actually ships) — real pairs read
    # off Sysinternals binaries in ~/sandbox/pe-corpus/tier1.
    for quad, marketing in (
        ((1, 8, 3, 0), "1.83"),
        ((14, 30, 0, 0), "14.3"),
        ((2, 0, 2, 0), "2.02"),
        ((1, 80, 0, 0), "1.8"),
    ):
        strings = {"040904b0": {"FileVersion": marketing}}
        section = _resource_section(
            {RT_VERSION: [(1, 1033, _version_resource(_fixed_block(*quad), strings))]}
        )
        exe_file = tmp_path / f"stock-{marketing.replace('.', '_')}.exe"
        exe_file.write_bytes(_pe_image_with_resources(section))
        version_info = parse(str(exe_file))["version_info"]
        assert "mismatches" not in version_info, (quad, marketing)


def test_version_info_major_disagreement_is_still_the_tamper_signal(tmp_path):
    """The signal the field exists for survives: a rewritten 5.x string
    beside a 3.13 fixed block still reports."""
    strings = {"040904b0": {"FileVersion": "5.0.1.2"}}
    section = _resource_section(
        {RT_VERSION: [(1, 1033, _version_resource(_FIXED_BLOCK, strings))]}
    )
    exe_file = tmp_path / "tampered2.exe"
    exe_file.write_bytes(_pe_image_with_resources(section))
    assert parse(str(exe_file))["version_info"]["mismatches"] == ["FileVersion"]


def test_version_resource_survives_a_node_budget_spent_on_icons(tmp_path):
    """VERSION is resource type 16 and the tree enumerates types in ascending
    id, so an image with more icons (type 3) than the node budget would walk
    past the budget before reaching its VERSIONINFO.

    A fixture below the budget cannot see this (ground rule 33 in its
    node-count form): the whole tree fits, so every node is reached whatever
    order the walk takes.
    """
    icons = [(i + 1, 1033, b"\xff" * 16) for i in range(MAX_RESOURCE_DATA_NODES + 256)]
    strings = {"040904b0": {"FileVersion": "3.13.7"}}
    section = _resource_section(
        {
            RT_ICON: icons,
            RT_VERSION: [(1, 1033, _version_resource(_FIXED_BLOCK, strings))],
        }
    )
    exe_file = tmp_path / "manyicons.exe"
    exe_file.write_bytes(_pe_image_with_resources(section))
    metadata = parse(str(exe_file))
    # The node cap still fires and is still reported as a degradation...
    assert any("data nodes past" in d for d in metadata["resources"]["degradations"])
    # ...but the targeted VERSION lookup is not starved by it.
    assert metadata["version_info"]["present"] is True
    assert metadata["version_info"]["strings"]["040904b0"]["FileVersion"] == "3.13.7"


def test_version_info_strings_without_fixed_block(tmp_path):
    section = _resource_section(
        {RT_VERSION: [(1, 1033, _version_resource(None, {"0409": {"CompanyName": "x"}}))]}
    )
    exe_file = tmp_path / "strings-only.exe"
    exe_file.write_bytes(_pe_image_with_resources(section))
    version_info = parse(str(exe_file))["version_info"]
    assert version_info["present"] is True
    assert "fixed" not in version_info
    assert version_info["strings"]["0409"]["CompanyName"] == "x"


def test_two_language_tables(tmp_path):
    strings = {
        "040904b0": {"CompanyName": "Contoso", "FileDescription": "Hello"},
        "040704b0": {"CompanyName": "Contoso GmbH"},
    }
    section = _resource_section(
        {RT_VERSION: [(1, 1033, _version_resource(_FIXED_BLOCK, strings))]}
    )
    exe_file = tmp_path / "i18n.exe"
    exe_file.write_bytes(_pe_image_with_resources(section))
    version_info = parse(str(exe_file))["version_info"]
    assert sorted(version_info["languages"]) == ["040704b0", "040904b0"]


def test_resource_tree_summary_hashes_and_manifest(tmp_path):
    pe_blob = _minimal_pe_blob()
    icon = bytes(range(256)) * 4
    section = _resource_section(
        {
            RT_MANIFEST: [(1, 1033, MANIFEST_XML.encode())],
            RT_ICON: [(1, 1033, icon)],
            RT_RCDATA: [(42, 0, pe_blob)],
        }
    )
    exe_file = tmp_path / "tree.exe"
    exe_file.write_bytes(_pe_image_with_resources(section))
    metadata = parse(str(exe_file))
    resources = metadata["resources"]
    assert resources["tree_summary"]["MANIFEST"]["count"] == 1
    assert resources["tree_summary"]["ICON"]["bytes"] == len(icon)
    assert resources["tree_summary"]["RCDATA"]["count"] == 1
    # Per-resource hashes cover every node, icons included.
    digest = hashlib.sha256(pe_blob).hexdigest()
    rows = {(row["type"], row["id"]): row for row in resources["hashes"]}
    assert rows[("RCDATA", "42")]["sha256"] == digest
    assert rows[("ICON", "1")]["size"] == len(icon)
    # The icon cluster key is the deterministic hash of the icon digests.
    expected_icon_hash = hashlib.sha256(
        hashlib.sha256(icon).hexdigest().encode()
    ).hexdigest()
    assert resources["icon_hash"] == expected_icon_hash
    # The embedded PE is a fact with its RVA, not a finding.
    embedded = resources["embedded_pe"]
    assert len(embedded) == 1
    assert embedded[0]["type"] == "RCDATA"
    assert embedded[0]["coff_machine"] == 0x8664
    # LIEF resolves the data entry to a file offset inside the section.
    assert 0x400 <= embedded[0]["file_offset"] < 0x400 + SECTION_SIZE
    assert resources["manifest_parsed"]["requestedExecutionLevel"] == "requireAdministrator"


def test_mz_prefix_without_pe_structure_is_not_embedded(tmp_path):
    """An MZ prefix alone is not evidence: no e_lfanew -> no PE -> no hit."""
    fake = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x4000) + b"\x00" * 64
    section = _resource_section({RT_RCDATA: [(1, 0, fake)]})
    exe_file = tmp_path / "fake.exe"
    exe_file.write_bytes(_pe_image_with_resources(section))
    resources = parse(str(exe_file))["resources"]
    assert "embedded_pe" not in resources
    assert resources["tree_summary"]["RCDATA"]["count"] == 1


def test_resource_larger_than_the_windows_is_hashed_and_capped(tmp_path):
    """Ground rule 33: a 1.5 MB RCDATA blob exceeds both the 64 KiB entropy
    window and the 1 MiB hash cap. The summary must still see the blob's
    true size, the hash records its truncation, and the tail (high entropy)
    must be included in the sampled entropy."""
    head = b"\x00" * (1024 * 1024)
    tail = bytes(range(256)) * 512  # 128 KiB of varied bytes at the end
    blob = head + tail
    assert len(blob) > MAX_RESOURCE_HASH_BYTES
    section = _resource_section({RT_RCDATA: [(1, 0, blob)]})
    exe_file = tmp_path / "big-rcdata.exe"
    exe_file.write_bytes(_pe_image_with_resources(section))
    metadata = parse(str(exe_file))
    resources = metadata["resources"]
    assert resources["tree_summary"]["RCDATA"]["bytes"] == len(blob)
    hashes = resources["hashes"]
    assert hashes[0]["hash_truncated"] is True
    assert hashes[0]["sha256"] == hashlib.sha256(blob[:MAX_RESOURCE_HASH_BYTES]).hexdigest()
    degradations = "\n".join(resources["degradations"])
    assert "resource_hash" in degradations
    # The tail window: a head-only sample of zero bytes would carry ~0
    # entropy; the recorded value proves the end of the blob was read.
    assert resources["tree_summary"]["RCDATA"]["entropy"] > 4.0


def test_hostile_resource_tree_counts_and_degrades(tmp_path):
    """Ground rule 30: more data nodes than the limit is a recorded
    degradation, and the parser survives."""
    types = {
        RT_RCDATA: [
            (i, 0, b"payload-%d" % i) for i in range(MAX_RESOURCE_DATA_NODES + 64)
        ]
    }
    section = _resource_section(types)
    exe_file = tmp_path / "hostile-tree.exe"
    exe_file.write_bytes(_pe_image_with_resources(section))
    metadata = parse(str(exe_file))
    resources = metadata["resources"]
    assert "degradations" in resources
    assert any("past the 1024-node limit" in d for d in resources["degradations"])
    assert len(resources["hashes"]) == MAX_RESOURCE_DATA_NODES
    # No VERSION resource: the parsed version_info block is absent at the
    # top level (the legacy rendered key inside resources stays as-is).
    assert "version_info" not in metadata


def test_real_resource_manager_extension_on_python313():
    """Real-artifact assertion (rule 22): the tier-0 header slice plus the
    committed corpus are outside the repo, so this asserts against the
    real python.org version block embedded in the committed header fixture's
    sibling values. Skipped when the corpus is absent."""
    import os

    corpus = os.path.expanduser("~/sandbox/pe-corpus/tier0-reference/python-amd64/python313.dll")
    if not os.path.exists(corpus):
        import pytest

        pytest.skip("tier-0 corpus not present")
    metadata = parse(corpus)
    version_info = metadata["version_info"]
    assert version_info["present"] is True
    assert version_info["fixed"]["file_version"] == "3.13.7150.1013"
    assert "mismatches" not in version_info
    assert metadata["resources"]["tree_summary"]["VERSION"]["count"] == 1
    assert metadata["resources"]["manifest_parsed"]["longPathAware"] is True

# The committed hello.exe was built on the Windows VM with MSVC 19.44.35228
# and an rc.exe VERSIONINFO + manifest + icon pass (see test_pe_debug).
HELLO = "tests/data/pe/msvc-hello-x64.exe"


def test_real_msvc_fixture_version_resources():
    """Ground rule 22 on a committed real artifact: the values are the
    build machine's own (PowerShell VersionInfo and the Win32 resource
    enumeration on the VM agree with every number here)."""
    metadata = parse(HELLO)
    version_info = metadata["version_info"]
    assert version_info["present"] is True
    assert version_info["fixed"]["file_version"] == "1.2.3.4"
    # Explorer shows "1.2.3": semantic agreement with the fixed block.
    assert version_info["strings"]["040904b0"]["FileVersion"] == "1.2.3"
    assert "mismatches" not in version_info
    assert version_info["strings"]["040904b0"]["CompanyName"] == "OWASP blint"
    assert version_info["strings"]["040904b0"]["OriginalFilename"] == "hello.exe"

    resources = metadata["resources"]
    manifest = resources["manifest_parsed"]
    assert manifest["requestedExecutionLevel"] == "asInvoker"
    assert manifest["supportedOS"] == ["Windows 7", "Windows 10/11"]
    assert manifest["assembly_identities"][0]["name"] == "OWASP.blint.hello"
    # The loader enumerated exactly ICON/GROUP_ICON/VERSION/MANIFEST.
    assert sorted(resources["tree_summary"]) == [
        "GROUP_ICON", "ICON", "MANIFEST", "VERSION",
    ]
    assert "icon_hash" in resources

