"""Tests for the MSI reader (W4.2).

Builds a real database over the byte-level CFBF builder (test_cfbf): encoded
table-stream names, ``_StringPool``/``_StringData``, the schema tables and a
``CustomAction`` table with hostile flags. The name encoding is the inverse
of msitools' decoder, which the reader was verified against on the real
7z-x64.msi corpus artifact (ground rule 29 test below, skipped without the
corpus).
"""

import os
import struct

import pytest

from blint.lib.cfbf import CfbfReader
from blint.lib.msi import MsiDatabase, decode_custom_action_type, decode_stream_name, parse_msi
from tests.test_cfbf import build_cfbf

SECTOR = 512


def encode_stream_name(name: str) -> str:
    """Inverse of decode_stream_name: table names get the U+4840 prefix and
    pairs of alphabet characters packed into 0x3800..0x47ff codepoints."""
    def utf2mime(ch: str) -> int:
        if ch.isdigit():
            return int(ch)
        if ch.isupper():
            return ord(ch) - ord("A") + 10
        if ch.islower():
            return ord(ch) - ord("a") + 36
        if ch == ".":
            return 62
        if ch == "_":
            return 63
        raise ValueError(ch)

    out = []
    body = name.removeprefix("!")
    if name.startswith("!"):
        out.append(chr(0x4840))
    pending = None
    for ch in body:
        value = utf2mime(ch)
        if pending is None:
            pending = value
            continue
        out.append(chr(0x3800 | (pending << 6) | value))
        pending = None
    if pending is not None:
        out.append(chr(0x4800 | pending))
    return "".join(out)


def build_string_pool(strings: list[str]):
    """``(_StringPool, _StringData)`` pair; id i is strings[i]."""
    pool = struct.pack("<HH", 1252, 0)
    data = b""
    for text in strings[1:]:
        encoded = text.encode("cp1252")
        pool += struct.pack("<HH", len(encoded), 1)
        data += encoded
    return pool, data


def build_table(rows: list[list[int]], columns) -> bytes:
    """Column-major table stream: columns list (name, type, width)."""
    out = b""
    for col_index, (_name, _col_type, width) in enumerate(columns):
        for row in rows:
            out += row[col_index].to_bytes(width, "little")
    return out


def build_msi(
    strings: list[str],
    tables: dict[str, bytes],
    schemas: dict[str, list[tuple[str, int, int]]],
) -> bytes:
    """schemas: table -> [(column_name, type, width)]; ``_Columns`` rows are
    derived with real column-name string ids."""
    streams: dict[str, bytes] = {}
    pool, data = build_string_pool(strings)
    streams["!_StringPool"] = pool
    streams["!_StringData"] = data

    def col_width(col_type: int) -> int:
        if (col_type & ~0x1000) == (0x0800 | 0x0100):
            return 2
        if col_type & 0x0800:
            return 2
        return 2 if (col_type & 0xFF) <= 2 else 4

    all_schemas = {
        "_Tables": [("Name", 0x2940, 2)],
        "_Columns": [("Table", 0x2940, 2), ("Number", 0x0102, 2), ("Name", 0x2940, 2), ("Type", 0x0102, 2)],
        **schemas,
    }
    column_rows = []
    for table_name, columns in all_schemas.items():
        if table_name not in strings:
            continue
        table_id = strings.index(table_name)
        for position, (col_name, col_type, _width) in enumerate(columns, start=1):
            column_rows.append([table_id, position, strings.index(col_name), col_type])
    table_name_ids = [strings.index(name) for name in tables]
    streams["!_Tables"] = build_table([[i] for i in table_name_ids], all_schemas["_Tables"])
    streams["!_Columns"] = build_table(column_rows, all_schemas["_Columns"])
    for table_name, payload in tables.items():
        streams[f"!{table_name}"] = payload
    return build_cfbf(streams)


def test_decode_stream_name_matches_msitools():
    assert decode_stream_name([ord(c) for c in "䡀䌏䈯"]) == "!File"
    assert decode_stream_name([ord(c) for c in "yyySummaryInformation".replace("yyy", "\x05")]) == "\x05SummaryInformation"
    assert decode_stream_name([ord(c) for c in "䡀䈛㵪䆲䗤䕲"]) == "!RegLocator"


def test_custom_action_type_decode():
    decoded = decode_custom_action_type(0x0806)  # vbScript + no impersonate
    assert decoded["kind"] == "vbscript"
    assert decoded["source"] == "binary_table"
    assert decoded["no_impersonate"] is True
    decoded = decode_custom_action_type(0x0402)  # exe, deferred in script
    assert decoded["kind"] == "exe"
    assert decoded["deferred_in_script"] is True


def test_parse_msi_reads_identity_and_custom_actions():
    # String table: id 0 is the empty string per the format.
    strings = [
        "",
        "Property", "Value", "Action", "Type", "Source", "Target",
        "Name", "Table", "Number",
        "ProductName", "Acme Installer", "ProductVersion", "1.0.0",
        "ProductCode", "{ACME-GUID}", "CustomAction", "RunScript",
        "Installer", " upgrades ", "UpgradeCode",
        "_Tables", "_Columns",
    ]
    schemas = {
        "Property": [("Property", 0x2940, 2), ("Value", 0x2940, 2)],
        "CustomAction": [("Action", 0x2940, 2), ("Type", 0x0102, 2), ("Source", 0x2940, 2), ("Target", 0x2940, 2)],
    }

    def sid(name: str) -> int:
        return strings.index(name)

    property_rows = [
        [sid("ProductName"), sid("Acme Installer")],
        [sid("ProductVersion"), sid("1.0.0")],
        [sid("ProductCode"), sid("{ACME-GUID}")],
    ]
    custom_action_rows = [
        [sid("RunScript"), 0x0806, sid("RunScript"), sid("Installer")],
    ]
    tables = {
        "Property": build_table(property_rows, schemas["Property"]),
        "CustomAction": build_table(custom_action_rows, schemas["CustomAction"]),
    }
    image = build_msi(strings, tables, schemas)
    import os
    import tempfile

    path = os.path.join(tempfile.mkdtemp(), "acme.msi")
    with open(path, "wb") as handle:
        handle.write(image)
    refusals: list[str] = []
    degradations: list[str] = []
    block = parse_msi(path, refusals, degradations)
    assert block["parse_status"] == "parsed"
    assert "Property" in block["tables"] and "CustomAction" in block["tables"]
    assert block["identity"]["product_name"] == "Acme Installer"
    assert block["identity"]["product_version"] == "1.0.0"
    assert block["custom_action_count"] == 1
    action = block["custom_actions"][0]
    assert action["action"] == "RunScript"
    assert action["kind"] == "vbscript"
    assert action["no_impersonate"] is True
    assert block["refusals"] == []


def test_parse_msi_without_string_pool_refuses_by_name(tmp_path):
    image = build_cfbf({"!File": b"\x01\x00"})
    path = tmp_path / "broken.msi"
    path.write_bytes(image)
    refusals: list[str] = []
    block = parse_msi(str(path), refusals, [])
    assert "string_pool_missing" in block["refusals"] or "archive_unreadable" in block["refusals"]


def test_msi_database_corrupt_table_names_degradation():
    strings = ["", "T", "C"]
    streams = {
        "!_StringPool": build_string_pool(strings)[0],
        "!_StringData": build_string_pool(strings)[1],
        "!_Tables": b"\x01\x00",
        "!_Columns": b"\x01\x00\x02",  # not a multiple of the row size
    }
    image = build_cfbf(streams)
    refusals: list[str] = []
    degradations: list[str] = []
    database = MsiDatabase(CfbfReader(image, refusals, degradations), refusals, degradations)
    database.table_names()
    # The _Columns stream is 3 bytes — not a multiple of its 8-byte row —
    # which only surfaces when the schema table is actually read; the
    # corrupt schema yields no columns, never invented ones.
    assert database.columns("_Tables") == []
    assert "msi_table_corrupt" in degradations
    assert database.table_names() == ["T"]


@pytest.mark.skipif(
    not os.path.isfile("/Users/appthreat/sandbox/pe-corpus/tier3-packaged/7z-x64.msi"),
    reason="corpus tier3 not present",
)
def test_real_7z_msi_ground_truth():
    """Rules 22/29: the real 7-Zip MSI, facts cross-checked on the Windows
    11 VM against the WindowsInstaller COM database dump (see the packet's
    gate block)."""
    refusals: list[str] = []
    degradations: list[str] = []
    block = parse_msi(
        "/Users/appthreat/sandbox/pe-corpus/tier3-packaged/7z-x64.msi", refusals, degradations
    )
    assert block["parse_status"] == "parsed"
    assert block["identity"]["product_name"].startswith("7-Zip")
    assert block["identity"]["product_code"].startswith("{23170F69")
    assert block["identity"]["manufacturer"] == "Igor Pavlov"
    assert block["file_count"] == 106
    assert block["summary"]["application_name"].startswith("Windows Installer XML")
    assert block["identity"]["package_code"].startswith("{23170F69")
    cabinets = block["embedded_cabinets"]
    assert len(cabinets) == 1 and cabinets[0]["name"] == "product.cab"
    assert cabinets[0]["embedded"] is True
    assert len(block["binaries"]) == 4


@pytest.mark.skipif(
    not os.path.isfile("/Users/appthreat/sandbox/pe-corpus/tier3-packaged/msi-cache/1929f5.msi"),
    reason="corpus msi-cache not present",
)
def test_real_version4_cfbf_msi_ground_truth():
    """A version-4 (4,096-byte sector) CFBF database from the VM's Windows
    Installer cache: 5 custom actions per the WindowsInstaller COM dump."""
    refusals: list[str] = []
    degradations: list[str] = []
    block = parse_msi(
        "/Users/appthreat/sandbox/pe-corpus/tier3-packaged/msi-cache/1929f5.msi", refusals, degradations
    )
    assert block["parse_status"] == "parsed"
    assert block["custom_action_count"] == 5
    assert block["table_count"] == 35


@pytest.mark.skipif(
    not os.path.isfile("/Users/appthreat/sandbox/pe-corpus/tier3-packaged/msi-cache/35e8f.msi"),
    reason="corpus msi-cache not present",
)
def test_real_custom_action_msi_ground_truth():
    """14 custom actions per the WindowsInstaller COM dump on the VM,
    including deferred no-impersonate DLL actions."""
    refusals: list[str] = []
    degradations: list[str] = []
    block = parse_msi(
        "/Users/appthreat/sandbox/pe-corpus/tier3-packaged/msi-cache/35e8f.msi", refusals, degradations
    )
    assert block["custom_action_count"] == 14
    kinds = {action["kind"] for action in block["custom_actions"]}
    assert "dll" in kinds
    deferred = [a for a in block["custom_actions"] if a["deferred_in_script"]]
    assert deferred and all(a["no_impersonate"] for a in deferred)
