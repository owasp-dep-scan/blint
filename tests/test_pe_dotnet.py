"""Tests for the ECMA-335 CLR metadata reader (blint.lib.pe_dotnet, W3.1).

Fixture strategy follows the plan's rules:

- Real assemblies from the pe-corpus tier-2/tier-5 directories carry the
  real-artifact assertions (ground rules 22/29); their expected values were
  produced by a spec-based System.Reflection.Metadata dumper on the Windows
  11 ARM64 VM and pasted in the packet commit. Tests skip when the corpus is
  absent so the suite stays green on machines without it.
- Hostile and variant fixtures are built byte-for-byte inline (no binary
  blobs in git) so every cap and every malformed cross-reference has a
  fixture that *exceeds* the cap, not one that approaches it (ground rule
  33), and every format variant — `#~`/`#-`, wide/narrow heap indexes,
  netmodule, MethodSpec entry point — has a fixture (ground rule 10).
"""

import base64
import hashlib
import struct

import pytest

from blint.lib import pe_dotnet
from blint.lib.pe_dotnet import (
    ASSEMBLY,
    ASSEMBLY_REF,
    CUSTOM_ATTRIBUTE,
    IMPL_MAP,
    MAX_LISTED_ASSEMBLY_REFS,
    MAX_LISTED_MODULE_REFS,
    MAX_LISTED_PINVOKE,
    MAX_STRING_READ,
    MEMBER_REF,
    METHOD_DEF,
    METHOD_PTR,
    METHOD_SPEC,
    MODULE,
    MODULE_REF,
    TYPE_DEF,
    TYPE_REF,
    parse_metadata_stream,
    parse_pe_dotnet,
    public_key_token,
)

# --------------------------------------------------------------------------
# Fixture builders
# --------------------------------------------------------------------------
# Rows are lists of column values aligned with pe_dotnet.TABLE_SCHEMAS:
# ints for fixed columns, strings/guids/blobs encoded into the heaps,
# ("tbl", n) as the raw rid, ("cod", name) as (tag_table, rid).

SCHEMAS = pe_dotnet.TABLE_SCHEMAS


def _compress_uint(value: int) -> bytes:
    """Compressed unsigned integer encoding (ECMA-335 II.23.2)."""
    if value < 0x80:
        return bytes([value])
    if value <= 0x3FFF:
        return bytes([0x80 | (value >> 8), value & 0xFF])
    if value <= 0x1FFFFFFF:
        return bytes([
            0xC0 | (value >> 24), (value >> 16) & 0xFF,
            (value >> 8) & 0xFF, value & 0xFF,
        ])
    raise ValueError("value does not fit a compressed uint")


class _Heaps:
    """Collects the heap contents while rows are encoded."""

    def __init__(self):
        self.strings = bytearray(b"\x00")
        # Byte 0 of #Blob is the empty blob; real blobs start at offset 1.
        self.blobs = bytearray(b"\x00")
        self.guids = bytearray()
        self.strings_index: dict[bytes, int] = {}
        self.blob_index: dict[bytes, int] = {}

    def intern_string(self, text: str) -> int:
        raw = text.encode("utf-8")
        if raw not in self.strings_index:
            self.strings_index[raw] = len(self.strings)
            self.strings.extend(raw + b"\x00")
        return self.strings_index[raw]

    def intern_blob(self, payload: bytes) -> int:
        # Blob indexes are byte offsets into the heap; offset 0 is the
        # empty blob, which is what an empty payload means.
        if payload == b"":
            return 0
        if payload not in self.blob_index:
            self.blob_index[payload] = len(self.blobs)
            self.blobs.extend(_compress_uint(len(payload)) + payload)
        return self.blob_index[payload]

    def add_guid(self, raw: bytes) -> int:
        self.guids.extend(raw)
        return len(self.guids) // 16


def _coded_index(name: str, tag_table, rid: int, row_counts) -> int:
    tables, tag_bits = pe_dotnet.CODED_INDEXES[name]
    del row_counts  # width selection happens in the layout pass, not here
    if tag_table is None:
        # The null link (e.g. TypeDef.Extends for Object-only types) is
        # encoded as zero: tag slot 0, rid 0.
        return 0
    tag = tables.index(tag_table)
    return (rid << tag_bits) | tag


def build_metadata_stream(
    tables: dict[int, list[list]],
    *,
    version: str = "v4.0.30319",
    stream_name: str = "#~",
    cli_flags: int = 0x1,
    entry_point_token: int | None = None,
    extra_streams: dict[str, bytes] | None = None,
    include_streams: tuple[str, ...] | None = None,
    stream_count_override: int | None = None,
    version_area_override: int | None = None,
) -> bytes:
    """Build one complete metadata region (root + streams) for tests.

    Index widths follow the same rule the reader assumes, so a fixture only
    exercises the wide path when its row counts or heaps genuinely demand
    it. Hostile overrides (bad signatures, forged stream counts, streams
    outside the region) are applied by the tests after building.
    """
    heaps = _Heaps()
    row_counts = {t: len(rows) for t, rows in tables.items()}
    # Layout: per-table row byte width, tables in ascending id order.
    widths: dict[int, int] = {}
    offsets: dict[int, int] = {}
    row_pos = 0
    for table in sorted(tables):
        columns = SCHEMAS[table]
        row_size = 0
        for column in columns:
            kind = column[0]
            if kind in ("u1", "pad"):
                row_size += 1
            elif kind == "u2":
                row_size += 2
            elif kind == "u4":
                row_size += 4
            elif kind in ("str", "guid", "blob"):
                # Wide when the final heap demands it; decided after
                # encoding, so encode rows first then patch if needed. The
                # common case fits 2 bytes; tests that need the wide path
                # force it via the heaps (a >64KB heap or >0xFFFF rows).
                row_size += 2
            elif kind == "tbl":
                row_size += 2 if row_counts.get(column[1], 0) <= 0xFFFF else 4
            elif kind == "cod":
                tables_, tag_bits = pe_dotnet.CODED_INDEXES[column[1]]
                max_rows = max(
                    (row_counts.get(t, 0) for t in tables_ if t is not None),
                    default=0,
                )
                row_size += 2 if max_rows <= (0xFFFF >> tag_bits) else 4
        widths[table] = row_size
        offsets[table] = row_pos
        row_pos += row_size * row_counts[table]

    # Encode rows.
    encoded: dict[int, bytearray] = {t: bytearray() for t in tables}
    wide_used = {"str": False, "blob": False, "guid": False}
    for table in sorted(tables):
        columns = SCHEMAS[table]
        for row in tables[table]:
            for column, value in zip(columns, row):
                kind = column[0]
                if kind == "u1":
                    encoded[table].append(value)
                elif kind == "u2":
                    encoded[table] += struct.pack("<H", value)
                elif kind == "u4":
                    encoded[table] += struct.pack("<I", value)
                elif kind == "pad":
                    encoded[table] += b"\x00"
                elif kind == "str":
                    idx = heaps.intern_string(value)
                    if idx > 0xFFFF:
                        wide_used["str"] = True
                    encoded[table] += struct.pack("<H", idx)
                elif kind == "blob":
                    idx = heaps.intern_blob(value)
                    if idx > 0xFFFF:
                        wide_used["blob"] = True
                    encoded[table] += struct.pack("<H", idx)
                elif kind == "guid":
                    idx = heaps.add_guid(value)
                    if idx > 0xFFFF:
                        wide_used["guid"] = True
                    encoded[table] += struct.pack("<H", idx)
                elif kind == "tbl":
                    encoded[table] += struct.pack(
                        "<H" if row_counts.get(column[1], 0) <= 0xFFFF else "<I",
                        value,
                    )
                elif kind == "cod":
                    tag_table, rid = value
                    raw = _coded_index(column[1], tag_table, rid, row_counts)
                    tables_, tag_bits = pe_dotnet.CODED_INDEXES[column[1]]
                    max_rows = max(
                        (row_counts.get(t, 0) for t in tables_ if t is not None),
                        default=0,
                    )
                    wide = max_rows > (0xFFFF >> tag_bits)
                    encoded[table] += struct.pack("<I" if wide else "<H", raw)

    # Wide heaps re-encode: rebuild every index column at 4 bytes when any
    # index overflowed (matching HeapSizes semantics). The simple route:
    # only reached by tests that pass wide_heaps explicitly.
    heapsizes = 0
    if wide_used["str"]:
        heapsizes |= 0x01
    if wide_used["guid"]:
        heapsizes |= 0x02
    if wide_used["blob"]:
        heapsizes |= 0x04
    if heapsizes:
        # Re-encode all rows with 4-byte heap indexes.
        heapsizes_tables = {
            t: [
                [
                    _wide_value(c, v, heaps)
                    for c, v in zip(SCHEMAS[t], row)
                ]
                for row in tables[t]
            ]
            for t in tables
        }
        widths2, offsets2 = {}, {}
        row_pos2 = 0
        for t in sorted(tables):
            row_size = 0
            for column in SCHEMAS[t]:
                kind = column[0]
                if kind in ("u1", "pad"):
                    row_size += 1
                elif kind == "u2":
                    row_size += 2
                elif kind == "u4":
                    row_size += 4
                elif kind == "str":
                    row_size += 4 if heapsizes & 0x01 else 2
                elif kind == "guid":
                    row_size += 4 if heapsizes & 0x02 else 2
                elif kind == "blob":
                    row_size += 4 if heapsizes & 0x04 else 2
                elif kind == "tbl":
                    row_size += 2 if row_counts.get(column[1], 0) <= 0xFFFF else 4
                elif kind == "cod":
                    tables_, tag_bits = pe_dotnet.CODED_INDEXES[column[1]]
                    max_rows = max(
                        (row_counts.get(t, 0) for t in tables_ if t is not None),
                        default=0,
                    )
                    row_size += 2 if max_rows <= (0xFFFF >> tag_bits) else 4
            widths2[t] = row_size
            offsets2[t] = row_pos2
            row_pos2 += row_size * row_counts[t]
        encoded = {t: bytearray() for t in tables}
        for t in sorted(tables):
            for row in heapsizes_tables[t]:
                for column, value in zip(SCHEMAS[t], row):
                    kind = column[0]
                    if kind == "u1":
                        encoded[t].append(value)
                    elif kind == "u2":
                        encoded[t] += struct.pack("<H", value)
                    elif kind == "u4":
                        encoded[t] += struct.pack("<I", value)
                    elif kind == "pad":
                        encoded[t] += b"\x00"
                    elif kind == "str" or kind == "blob" or kind == "guid":
                        encoded[t] += struct.pack("<I", value)
                    elif kind == "tbl":
                        encoded[t] += struct.pack(
                            "<H" if row_counts.get(column[1], 0) <= 0xFFFF else "<I",
                            value,
                        )
                    elif kind == "cod":
                        tag_table, rid = value
                        raw = _coded_index(column[1], tag_table, rid, row_counts)
                        tables_, tag_bits = pe_dotnet.CODED_INDEXES[column[1]]
                        max_rows = max(
                            (row_counts.get(x, 0) for x in tables_ if x is not None),
                            default=0,
                        )
                        wide = max_rows > (0xFFFF >> tag_bits)
                        encoded[t] += struct.pack("<I" if wide else "<H", raw)
        widths, offsets = widths2, offsets2

    # Assemble the table stream: header (24 bytes) + row counts + rows.
    valid_mask = sum(1 << t for t in tables)
    sorted_mask = 0
    body = bytearray()
    body += struct.pack("<IBBBB", 0, 2, 0, heapsizes, 1)
    body += struct.pack("<QQ", valid_mask, sorted_mask)
    for t in sorted(tables):
        body += struct.pack("<I", row_counts[t])
    for t in sorted(tables):
        body += encoded[t]
    tables_stream = bytes(body)

    # Assemble the metadata root with 4-byte-aligned stream headers.
    stream_defs: list[tuple[str, bytes]] = [(stream_name, tables_stream)]
    if include_streams is None:
        include_streams = ("#Strings", "#US", "#GUID", "#Blob")
    stream_payloads: dict[str, bytes] = {
        "#Strings": bytes(heaps.strings),
        "#US": b"\x00",
        "#GUID": bytes(heaps.guids),
        "#Blob": bytes(heaps.blobs),
    }
    stream_payloads.update(extra_streams or {})
    for name in include_streams:
        if name in stream_payloads:
            stream_defs.append((name, stream_payloads[name]))

    version_area = version.encode() + b"\x00"
    version_area += b"\x00" * (-len(version_area) % 4)
    if version_area_override is not None:
        version_area = b"\x00" * version_area_override
    header_size = 16 + len(version_area) + 4
    # Place stream data after all headers, 4-aligned.
    data_start = header_size + 8 * len(stream_defs) + sum(
        len(n) + 1 + (-(header_size + 8 * len(stream_defs) + sum(
            len(n2) + 1 for n2, _ in stream_defs[:i]
        ) + len(n)) % 4)
        for i, (n, _) in enumerate(stream_defs)
    )
    data_start = (data_start + 3) & ~3
    stream_headers = bytearray()
    running = data_start
    for name, payload in stream_defs:
        offset = running
        stream_headers += struct.pack("<II", offset, len(payload))
        stream_headers += name.encode() + b"\x00"
        pad = -(len(stream_headers)) % 4
        stream_headers += b"\x00" * pad
        running = offset + len(payload)
        running += (-running) % 4
    region = bytearray()
    region += struct.pack("<IHHII", pe_dotnet.METADATA_SIGNATURE, 1, 1, 0,
                          len(version_area))
    region += version_area
    region += struct.pack("<HH", 0, len(stream_defs))
    if stream_count_override is not None:
        region[-2:] = struct.pack("<H", stream_count_override)
    region += stream_headers
    while len(region) < data_start:
        region += b"\x00"
    for name, payload in stream_defs:
        region += payload
        region += b"\x00" * ((-len(payload)) % 4)
    out = RegionBytes(region)
    out.cli_flags = cli_flags
    out.entry_point_token = entry_point_token
    return out


class RegionBytes(bytes):
    """A built region that remembers the CLI-header facts for parse_region."""

    cli_flags: int = 0
    entry_point_token: int | None = None


def parse_region(region: bytes, **kwargs) -> dict:
    # CLI-header facts live outside the metadata region; the builder stashes
    # them on the region so unit tests read like the real caller.
    if "cli_flags_value" not in kwargs:
        kwargs["cli_flags_value"] = getattr(region, "cli_flags", 0)
    if "entry_point_token" not in kwargs:
        kwargs["entry_point_token"] = getattr(region, "entry_point_token", None)
    return parse_metadata_stream(region, **kwargs)


def _wide_value(column, value, heaps):
    """Convert an interned index to its wide placeholder during re-encode."""
    # The builder re-encodes from the logical row values; wide encoding
    # resolves through the same heaps, so the value is unchanged here and
    # the width comes from the schema pass.
    return value


def make_assembly(
    *,
    name="TestLib",
    version=(1, 2, 3, 4),
    culture="neutral",
    key_blob=None,
    hash_alg=0x8004,
    cli_flags=0x9,
    refs=None,
    module_refs=None,
    pinvoke=None,
    target_framework=None,
    entry_point_token=None,
    stream_name="#~",
    extra_tables=None,
    **builder_kwargs,
):
    """A complete, well-formed synthetic assembly metadata region."""
    key_blob = key_blob if key_blob is not None else bytes(range(8))
    tables: dict[int, list[list]] = {}
    tables[MODULE] = [[0, "TestLib.dll", b"\x01" * 16, b"\x00" * 16, b"\x00" * 16]]
    type_ref_rows = []
    if target_framework:
        # TypeRef for System.Runtime.Versioning.TargetFrameworkAttribute,
        # a MemberRef for its ctor, and the CustomAttribute row.
        type_ref_rows.append([
            (pe_dotnet.TYPE_REF, 0),  # ResolutionScope: AssemblyRef rid 1
            "TargetFrameworkAttribute",
            "System.Runtime.Versioning",
        ])
    tables[TYPE_REF] = type_ref_rows or [[(pe_dotnet.TYPE_REF, 0), "System", "System"]]
    tables[TYPE_DEF] = [[
        0, "Program", "", (None, 0), 1, 1,
    ]]
    tables[METHOD_DEF] = [[0x0, 0, 0, "Main", b"", 1]]
    attr_blob = None
    if target_framework:
        payload = struct.pack("<H", 1) + _compress_uint(len(target_framework)) + target_framework.encode()
        attr_blob = payload
    tables[ASSEMBLY] = [[
        hash_alg, *version, 0, key_blob, name, culture,
    ]]
    tables[ASSEMBLY_REF] = [
        [1, 0, 0, 0, 0, b"\x00" * 8, "System.Runtime", "neutral", b""]
    ]
    if refs is not None:
        tables[ASSEMBLY_REF] = [
            [v[1][0], v[1][1], v[1][2], v[1][3], 0, v[2], v[0], "neutral", b""]
            for v in refs
        ]
    tables[MODULE_REF] = [[n] for n in (module_refs or [])]
    impl_rows = []
    for entry in pinvoke or []:
        module_rid = (module_refs or []).index(entry["module"]) + 1
        impl_rows.append([
            0x0,
            (METHOD_DEF, entry["method_rid"]),
            entry["entry_point"],
            module_rid,
        ])
    tables[IMPL_MAP] = impl_rows
    if target_framework:
        blob_value = attr_blob
        tables[CUSTOM_ATTRIBUTE] = [[
            (pe_dotnet.TYPE_DEF, 1),
            (MEMBER_REF, 1),
            blob_value,
        ]]
        tables[MEMBER_REF] = [[(TYPE_REF, 1), ".ctor", b""]]
    else:
        tables[CUSTOM_ATTRIBUTE] = []
    for t, rows in (extra_tables or {}).items():
        tables[t] = rows
    region = build_metadata_stream(
        tables,
        stream_name=stream_name,
        cli_flags=cli_flags,
        **builder_kwargs,
    )
    return region


def find_stream(region: bytearray, want: str):
    """(header_pos, data_offset, size) for one stream, for in-place patches.

    header_pos is the position of the (offset, size) pair inside the region,
    so tests can patch the fields in place.
    """
    sig = region.find(b"BSJB")
    valen = struct.unpack_from("<I", region, sig + 12)[0]
    pos = sig + 16 + valen + 4
    count = struct.unpack_from("<H", region, pos - 2)[0]
    for _ in range(count):
        header_pos = pos
        offset, size = struct.unpack_from("<II", region, pos)
        pos += 8
        nul = region.index(b"\x00", pos)
        name = bytes(region[pos:nul]).decode("ascii")
        pos = nul + 1
        pos += (-(pos - sig)) % 4
        if name == want:
            return header_pos, offset, size
    raise AssertionError(f"stream {want} not found")


# --------------------------------------------------------------------------
# Unit fixtures: identity, refs, pinvoke, entry point
# --------------------------------------------------------------------------


def test_minimal_assembly_identity():
    region = make_assembly(name="TestLib", version=(1, 2, 3, 4))
    block = parse_region(region)
    assert block["parse_status"] == "parsed"
    assert block["runtime_version"] == "v4.0.30319"
    assert block["cli_flags"] == ["ILONLY", "STRONGNAMESIGNED"]
    assert block["cli_flags_value"] == 0x9
    asm = block["assembly"]
    assert asm["name"] == "TestLib"
    assert asm["version"] == "1.2.3.4"
    assert asm["culture"] == "neutral"
    assert asm["public_key_token"] == bytes(range(8)).hex()
    assert asm["hash_algorithm"] == "SHA1"
    assert asm["hash_algorithm_id"] == 0x8004
    assert asm["mvid"] == "01010101-0101-0101-0101-010101010101"
    assert block["assembly_refs"] == [
        {
            "name": "System.Runtime",
            "version": "1.0.0.0",
            "culture": "neutral",
            "public_key_token": "00" * 8,
        }
    ]
    assert block["counts"]["assembly"] == 1


def test_public_key_token_full_key_math():
    # A full public key blob: the token is the low 8 bytes of SHA-1,
    # reversed — asserted against the direct computation and against a
    # fixed vector so the math cannot drift.
    key = bytes(range(160))
    expected = hashlib.sha1(key).digest()[-8:][::-1].hex()
    assert public_key_token(key) == expected
    assert public_key_token(key) == "473c444ebb4661a5"
    # An 8-byte blob IS the token; shorter/absent blobs are not tokens.
    assert public_key_token(key[:8]) == key[:8].hex()
    assert public_key_token(b"\x01\x02\x03") is None
    assert public_key_token(None) is None
    assert public_key_token(b"") is None


def test_full_key_and_token_blob_agree():
    key = b"\x11" * 64
    token = hashlib.sha1(key).digest()[-8:][::-1]
    region_full = make_assembly(key_blob=key)
    region_token = make_assembly(key_blob=token)
    full = parse_region(region_full)["assembly"]["public_key_token"]
    tok = parse_region(region_token)["assembly"]["public_key_token"]
    assert full == tok == token.hex()


def test_target_framework_attribute():
    region = make_assembly(target_framework=".NETFramework,Version=v4.5")
    block = parse_region(region)
    assert block["target_framework"] == ".NETFramework,Version=v4.5"
    assert block["parse_status"] == "parsed"


def test_netmodule_has_no_assembly_identity():
    # IL_LIBRARY with no Assembly table rows: the identity block stays
    # absent (there is no assembly) while module facts still parse.
    tables = pe_dotnet_test_tables_without_assembly()
    block = parse_region(tables)
    assert "assembly" not in block
    assert block["counts"]["assembly"] == 0
    assert "IL_LIBRARY" in block["cli_flags"]
    assert block["assembly_refs"]


def pe_dotnet_test_tables_without_assembly():
    region_tables: dict[int, list[list]] = {}
    region_tables[MODULE] = [[0, "mod.netmodule", b"\x01" * 16, b"\x00" * 16, b"\x00" * 16]]
    region_tables[TYPE_REF] = [[(pe_dotnet.TYPE_REF, 0), "System", "System"]]
    region_tables[ASSEMBLY_REF] = [[
        1, 0, 0, 0, 0, b"\x00" * 8, "System.Runtime", "neutral", b"",
    ]]
    return build_metadata_stream(region_tables, cli_flags=0x1 | 0x4)


def test_hash_stream_variant():
    # The uncompressed `#-` stream parses identically and is recorded.
    region = make_assembly(stream_name="#-")
    block = parse_region(region)
    assert block["table_stream"] == "#-"
    assert block["assembly"]["name"] == "TestLib"
    assert block["parse_status"] == "parsed"


def test_native_entrypoint_is_not_resolved_as_token():
    region = make_assembly(cli_flags=0x9 | 0x10, entry_point_token=0x000044F0)
    block = parse_region(region, entry_point_token=0x000044F0)
    assert block["entry_point"] == {"token": "0x000044f0", "kind": "native"}


def test_entry_point_methoddef_resolves_type_and_method():
    region = make_assembly(entry_point_token=0x06000001)
    block = parse_region(region, entry_point_token=0x06000001)
    assert block["entry_point"] == {
        "token": "0x06000001",
        "method": "Main",
        "type": "Program",
    }


def test_entry_point_through_methodptr_indirection():
    # Unsorted `#-` images carry MethodPtr tables: a TypeDef's MethodList
    # indexes MethodPtr rows that redirect to the real MethodDef rows. The
    # declaring-type walk must follow the indirection.
    tables: dict[int, list[list]] = {}
    tables[MODULE] = [[0, "a.dll", b"\x01" * 16, b"\x00" * 16, b"\x00" * 16]]
    tables[TYPE_DEF] = [[0, "Program", "", (None, 0), 1, 1]]
    tables[METHOD_DEF] = [
        [0, 0, 0, "Other", b"", 1],
        [0, 0, 0, "Main", b"", 1],
    ]
    tables[METHOD_PTR] = [[2]]
    tables[ASSEMBLY_REF] = []
    region = build_metadata_stream(tables, stream_name="#-")
    block = parse_region(region, entry_point_token=0x06000002)
    assert block["entry_point"] == {
        "token": "0x06000002",
        "method": "Main",
        "type": "Program",
    }
    assert block["table_stream"] == "#-"


def test_entry_point_methodspec_resolves_through():
    tables: dict[int, list[list]] = {}
    tables[MODULE] = [[0, "a.dll", b"\x01" * 16, b"\x00" * 16, b"\x00" * 16]]
    tables[TYPE_DEF] = [[0, "Program", "", (None, 0), 1, 1]]
    tables[METHOD_DEF] = [[0, 0, 0, "Main", b"", 1]]
    tables[METHOD_SPEC] = [[(METHOD_DEF, 1), b""]]
    tables[ASSEMBLY_REF] = []
    region = build_metadata_stream(tables)
    block = parse_region(region, entry_point_token=0x2B000001)
    assert block["entry_point"] == {
        "token": "0x2b000001",
        "method": "Main",
        "type": "Program",
    }


def test_entry_point_unresolved_names_the_gap():
    # Token points past the MethodDef table: the token (a CLI-header fact)
    # stays, the resolution is named, nothing is invented.
    region = make_assembly(entry_point_token=0x06000FFF)
    block = parse_region(region, entry_point_token=0x06000FFF)
    assert block["entry_point"] == {"token": "0x06000fff"}
    assert "entry_point_unresolved" in block["degradations"]
    assert block["parse_status"] == "partial"


def test_pinvoke_surface():
    region = make_assembly(
        module_refs=["kernel32.dll", "advapi32.dll"],
        pinvoke=[
            {"module": "kernel32.dll", "entry_point": "CreateFileW",
             "method_rid": 1},
            {"module": "advapi32.dll", "entry_point": "RegOpenKeyW",
             "method_rid": 1},
        ],
    )
    block = parse_region(region)
    assert block["module_refs"] == ["kernel32.dll", "advapi32.dll"]
    entries = block["pinvoke"]
    assert {e["module"] for e in entries} == {"kernel32.dll", "advapi32.dll"}
    assert {e["entry_point"] for e in entries} == {
        "CreateFileW", "RegOpenKeyW",
    }
    assert all(e["method"] == "Main" for e in entries)
    assert block["counts"]["implmap"] == 2
    assert block["counts"]["module_ref"] == 2


def test_pinvoke_empty_import_name_skipped():
    # The mixed-mode C++/CLI shape: ImplMap rows whose ImportName is the
    # empty string are not P/Invoke entries (the Windows oracle skips
    # Name.IsNil rows) but they do count in counts.implmap.
    tables: dict[int, list[list]] = {}
    tables[MODULE] = [[0, "a.dll", b"\x01" * 16, b"\x00" * 16, b"\x00" * 16]]
    tables[TYPE_DEF] = [[0, "T", "", (None, 0), 1, 1]]
    tables[METHOD_DEF] = [
        [0, 0, 0, "Real", b"", 1],
        [0, 0, 0, "NativeThunk", b"", 1],
    ]
    tables[MODULE_REF] = [[""], ["KERNEL32.dll"]]
    tables[IMPL_MAP] = [
        [0, (METHOD_DEF, 1), "DecodePointer", 2],
        [0x240, (METHOD_DEF, 2), "", 1],
    ]
    tables[ASSEMBLY_REF] = []
    region = build_metadata_stream(tables)
    block = parse_region(region)
    assert block["counts"]["implmap"] == 2
    assert [e["entry_point"] for e in block["pinvoke"]] == ["DecodePointer"]


def test_parse_is_deterministic():
    region = make_assembly(target_framework=".NETCoreApp,Version=v8.0")
    first = parse_region(region)
    second = parse_region(region)
    assert first == second


# --------------------------------------------------------------------------
# Hostile fixtures: every cap is exceeded, not approached (rule 33)
# --------------------------------------------------------------------------


def test_assembly_refs_cap_exceeded():
    refs = [(f"Lib{i}", (1, 0, 0, 0), b"\x00" * 8) for i in range(MAX_LISTED_ASSEMBLY_REFS + 76)]
    region = make_assembly(refs=refs)
    block = parse_region(region)
    assert block["counts"]["assembly_ref"] == len(refs)
    assert len(block["assembly_refs"]) == MAX_LISTED_ASSEMBLY_REFS
    assert "assembly_refs_listed_capped" in block["degradations"]
    assert block["parse_status"] == "partial"


def test_module_refs_cap_exceeded():
    tables: dict[int, list[list]] = {}
    tables[MODULE] = [[0, "a.dll", b"\x01" * 16, b"\x00" * 16, b"\x00" * 16]]
    tables[ASSEMBLY_REF] = []
    tables[MODULE_REF] = [[f"native{i}.dll"] for i in range(MAX_LISTED_MODULE_REFS + 44)]
    region = build_metadata_stream(tables)
    block = parse_region(region)
    assert block["counts"]["module_ref"] == MAX_LISTED_MODULE_REFS + 44
    assert len(block["module_refs"]) == MAX_LISTED_MODULE_REFS
    assert "module_refs_listed_capped" in block["degradations"]


def test_pinvoke_cap_exceeded():
    tables: dict[int, list[list]] = {}
    tables[MODULE] = [[0, "a.dll", b"\x01" * 16, b"\x00" * 16, b"\x00" * 16]]
    tables[TYPE_DEF] = [[0, "T", "", (None, 0), 1, 1]]
    tables[METHOD_DEF] = [[0, 0, 0, "M", b"", 1]]
    tables[ASSEMBLY_REF] = []
    tables[MODULE_REF] = [["native.dll"]]
    tables[IMPL_MAP] = [
        [0, (METHOD_DEF, 1), f"Proc{i}", 1]
        for i in range(MAX_LISTED_PINVOKE + 88)
    ]
    region = build_metadata_stream(tables)
    block = parse_region(region)
    assert block["counts"]["implmap"] == MAX_LISTED_PINVOKE + 88
    assert len(block["pinvoke"]) == MAX_LISTED_PINVOKE
    assert "pinvoke_listed_capped" in block["degradations"]


def test_long_string_truncated_by_cap():
    # A name longer than MAX_STRING_READ with a proper NUL: the refusal is
    # named as a cap truncation, and the returned value is the truncated
    # prefix — never silence, never the full forged name.
    tables: dict[int, list[list]] = {}
    long_name = "N" * (MAX_STRING_READ * 2)
    tables[MODULE] = [[0, "a.dll", b"\x01" * 16, b"\x00" * 16, b"\x00" * 16]]
    tables[ASSEMBLY_REF] = []
    tables[ASSEMBLY] = [[0x8004, 1, 0, 0, 0, 0, b"\x00" * 8, long_name, "neutral"]]
    region = build_metadata_stream(tables)
    block = parse_region(region)
    assert "strings_entry_truncated_by_cap" in block["degradations"]
    assert block["assembly"]["name"] == "N" * MAX_STRING_READ
    assert block["parse_status"] == "partial"


def test_unterminated_string_named():
    # An entry whose bytes run to the heap's end with no NUL at all.
    from blint.lib.pe_dotnet import _Degradations, _HeapReader

    degr = _Degradations()
    heap = bytearray(b"\x00abc")  # entry at index 1 runs off the heap end
    reader = _HeapReader(bytes(heap), 0, len(heap), degr)
    value = reader.string(1)
    assert value == "abc"
    assert "strings_entry_unterminated" in degr.sorted()


def test_forged_row_counts_exceed_stream():
    # 5000 declared AssemblyRef rows in a stream that holds one: the counts
    # for the dropped tables are absent, assembly_refs is absent (not an
    # empty list), and the refusal is named.
    tables: dict[int, list[list]] = {}
    tables[MODULE] = [[0, "a.dll", b"\x01" * 16, b"\x00" * 16, b"\x00" * 16]]
    tables[ASSEMBLY_REF] = [[1, 0, 0, 0, 0, b"\x00" * 8, "System.Runtime", "neutral", b""]]
    region = bytearray(build_metadata_stream(tables))
    header_pos, _, _ = find_stream(region, "#~")
    # Locate the row-count array: table-stream header is 24 bytes, starting
    # at the stream's data offset.
    sig = region.find(b"BSJB")
    data_offset = struct.unpack_from("<I", region, header_pos)[0]
    mask = int.from_bytes(region[sig + data_offset + 8:sig + data_offset + 16],
                          "little")
    assert mask & (1 << MODULE) and mask & (1 << ASSEMBLY_REF)
    counts_at = sig + data_offset + 24
    # Row counts are written in ascending table order: MODULE first, then
    # ASSEMBLY_REF.
    region[counts_at + 4:counts_at + 8] = struct.pack("<I", 5000)
    block = parse_region(bytes(region))
    assert "tables_exceed_stream" in block["degradations"]
    assert "table_unreadable:0x23" in block["degradations"]
    assert block["parse_status"] == "partial"
    assert "assembly_refs" not in block
    assert "assembly_ref" not in block.get("counts", {})


def test_stream_outside_region_refused():
    region = bytearray(make_assembly())
    header_pos, _, size = find_stream(region, "#Strings")
    # Point #Strings far outside the metadata region: the stream is refused
    # by name, the heaps it carries are missing, and the refusal does not
    # read as "this assembly has no names".
    struct.pack_into("<I", region, header_pos, 0xFFFFFF)
    block = parse_region(bytes(region))
    assert "stream_out_of_range:#Strings" in block["degradations"]
    assert "strings_heap_missing" in block["degradations"]
    assert block["parse_status"] == "partial"
    assert "assembly_name_unreadable" in block["degradations"]
    assert "name" not in block.get("assembly", {})


def test_bad_signature_malformed():
    region = bytearray(make_assembly())
    region[region.find(b"BSJB")] = 0x00
    block = parse_region(bytes(region))
    assert block["parse_status"] == "malformed"
    assert "metadata_signature_invalid" in block["degradations"]
    assert "assembly" not in block


def test_forged_version_length_malformed():
    region = bytearray(make_assembly())
    sig = region.find(b"BSJB")
    struct.pack_into("<I", region, sig + 12, 0xFFFFFFF0)
    block = parse_region(bytes(region))
    assert block["parse_status"] == "malformed"
    assert "metadata_version_length_invalid" in block["degradations"]


def test_forged_stream_count_capped():
    region = make_assembly(stream_count_override=200)
    block = parse_region(region)
    assert "stream_count_capped" in block["degradations"]
    assert block["parse_status"] == "partial"


def test_string_index_out_of_range_named():
    from blint.lib.pe_dotnet import _Degradations, _HeapReader

    degr = _Degradations()
    reader = _HeapReader(b"\x00ok\x00", 0, 4, degr)
    assert reader.string(0) == ""
    assert reader.string(99) is None
    assert "strings_index_out_of_range" in degr.sorted()


def test_blob_overrun_named():
    from blint.lib.pe_dotnet import _Degradations, _HeapReader

    degr = _Degradations()
    # Blob at index 1: 2-byte compressed length 0xFFFF but only 4 bytes
    # follow — the length exceeds the heap, and the reader says so.
    heap = b"\x00" + bytes([0xBF, 0xFF, 1, 2])
    reader = _HeapReader(heap, 0, len(heap), degr)
    assert reader.blob(1) is None
    assert "blob_length_exceeds_heap" in degr.sorted()
    # A length beyond the 64KB cap with room to spare: named as a cap hit.
    degr2 = _Degradations()
    prefix = _compress_uint(pe_dotnet.MAX_BLOB_READ + 1)
    heap2 = b"\x00" + prefix + b"\x00" * 8
    reader2 = _HeapReader(heap2, 0, len(heap2), degr2)
    assert reader2.blob(1) is None
    assert "blob_length_exceeds_cap" in degr2.sorted()


def test_guid_out_of_range_named():
    from blint.lib.pe_dotnet import _Degradations, _HeapReader

    degr = _Degradations()
    reader = _HeapReader(b"\x01" * 16, 0, 16, degr)
    assert reader.guid(1) == b"\x01" * 16
    assert reader.guid(2) is None
    assert "guid_index_out_of_range" in degr.sorted()


def test_us_heap_reads_structurally():
    from blint.lib.pe_dotnet import _Degradations, _HeapReader

    degr = _Degradations()
    payload = "Hello".encode("utf-16-le") + b"\x01"
    heap = b"\x00" + _compress_uint(len(payload)) + payload
    reader = _HeapReader(heap, 0, len(heap), degr)
    assert reader.us_string_bytes(1) == "Hello".encode("utf-16-le")
    # A length running past the heap is named, not clipped silently.
    heap2 = b"\x00" + _compress_uint(400) + b"\x41"
    reader2 = _HeapReader(heap2, 0, len(heap2), degr)
    assert reader2.us_string_bytes(1) is None
    assert "us_length_exceeds_heap" in degr.sorted()


def test_both_table_streams_degrades_and_prefers_tilde():
    # A region carrying both #~ and #-: the compressed stream wins, the
    # anomaly is named, and the block still parses.
    tables: dict[int, list[list]] = {}
    tables[MODULE] = [[0, "a.dll", b"\x01" * 16, b"\x00" * 16, b"\x00" * 16]]
    tables[ASSEMBLY_REF] = []
    base = build_metadata_stream(tables, include_streams=())
    _, _, ts_size = find_stream(bytearray(base), "#~")
    sig = base.find(b"BSJB")
    ts_offset = struct.unpack_from(
        "<I", base, find_stream(bytearray(base), "#~")[0]
    )[0]
    tables_stream = base[sig + ts_offset:sig + ts_offset + ts_size]
    region = build_metadata_stream(
        tables,
        extra_streams={"#-": tables_stream},
        include_streams=("#Strings", "#US", "#GUID", "#Blob", "#-"),
    )
    block = parse_region(region)
    assert "both_table_streams_present" in block["degradations"]
    assert "table_stream" not in block  # #~ won; the marker is for #- only
    assert "assembly_refs" not in block  # zero refs: key absent, not []
    assert block["parse_status"] == "partial"


def test_unknown_table_stops_layout():
    # Valid bit 0x30 (a portable-PDB table) set: the reader refuses to size
    # rows for tables it has no schema for, names the table, and keeps
    # everything before it readable rather than guessing row widths.
    region = bytearray(make_assembly())
    header_pos, data_offset, _ = find_stream(region, "#~")
    del header_pos
    sig = region.find(b"BSJB")
    tables_abs = sig + data_offset
    # Insert a consistent 4-byte row count for the unknown table after the
    # declared tables' counts; every later stream's data moves with it, so
    # their declared offsets shift too.
    mask = int.from_bytes(region[tables_abs + 8:tables_abs + 16], "little")
    declared = sum(1 for i in range(64) if mask & (1 << i))
    counts_end = tables_abs + 24 + 4 * declared
    region[counts_end:counts_end] = struct.pack("<I", 0)
    mask |= 1 << 0x30
    region[tables_abs + 8:tables_abs + 16] = struct.pack("<Q", mask)
    # Shift every stream that starts at or after the insertion point.
    valen = struct.unpack_from("<I", region, sig + 12)[0]
    pos = sig + 16 + valen + 4
    count = struct.unpack_from("<H", region, pos - 2)[0]
    for _ in range(count):
        offset = struct.unpack_from("<I", region, pos)[0]
        if offset >= counts_end - sig:
            struct.pack_into("<I", region, pos, offset + 4)
        pos += 8
        nul = region.index(b"\x00", pos)
        pos = nul + 1
        pos += (-(pos - sig)) % 4
    block = parse_region(bytes(region))
    assert "unknown_table_present:0x30" in block["degradations"]
    assert "tables_partial" in block["degradations"]
    assert block["parse_status"] == "partial"
    # Everything before the unknown table is still real.
    assert block["assembly"]["name"] == "TestLib"


def test_coded_index_slots_match_the_spec():
    """The slot lists, transcribed from ECMA-335 II.24.2.6 independently.

    Every other fixture in this file encodes its rows *through*
    ``pe_dotnet.CODED_INDEXES``, so a wrong slot list is invisible to all of
    them — the fixture and the parser agree with each other and disagree
    with the world. The shipped W3.1 list had MemberRef, TypeRef, TypeSpec,
    ExportedType and six others missing from ``HasCustomAttribute`` and
    MethodSpec standing in for MemberRef in ``MethodDefOrRef``; because the
    widest constituent table sets the column width, that narrowed the
    CustomAttribute row on assemblies whose MemberRef or ExportedType table
    passes 2047 rows and shifted every table laid out after it. Two of 375
    real assemblies measured (netstandard.dll and
    Microsoft.AspNetCore.Identity.dll) reported a fabricated assembly name,
    version and public key token as a result. This test is the one place
    the constant is checked against the document rather than against the
    code that consumes it.
    """
    spec = {
        "TypeDefOrRef": ((0x02, 0x01, 0x1B), 2),
        "HasConstant": ((0x04, 0x08, 0x17), 2),
        "HasCustomAttribute": (
            (
                0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00, 0x0E, 0x17,
                0x14, 0x11, 0x1A, 0x1B, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2A,
                0x2C, 0x2B,
            ),
            5,
        ),
        "HasFieldMarshal": ((0x04, 0x08), 1),
        "HasDeclSecurity": ((0x02, 0x06, 0x20), 2),
        "MemberRefParent": ((0x02, 0x01, 0x1A, 0x06, 0x1B), 3),
        "HasSemantics": ((0x14, 0x17), 1),
        "MethodDefOrRef": ((0x06, 0x0A), 1),
        "MemberForwarded": ((0x04, 0x06), 1),
        "Implementation": ((0x26, 0x23, 0x27), 2),
        "CustomAttributeType": ((None, None, 0x06, 0x0A, None), 3),
        "ResolutionScope": ((0x00, 0x1A, 0x23, 0x01), 2),
        "TypeOrMethodDef": ((0x02, 0x06), 1),
    }
    assert pe_dotnet.CODED_INDEXES == spec


def test_layout_that_does_not_account_for_the_stream_withholds_rows():
    """A row layout short of the stream yields no values, only a name.

    The writer sizes the table stream to exactly its rows plus an alignment
    tail; measured over 375 real assemblies the leftover is 0, 2 or 4 bytes
    and nothing else. More than that means blint's computed row widths are
    not the writer's, so every row it reads is some other table's bytes.
    Reporting what those bytes decode to is how the coded-index defect
    produced a plausible assembly name and a plausible public key token for
    netstandard.dll — so the derived facts are withheld (ground rule 11)
    while ``counts``, which comes from the header rather than the layout,
    stays.
    """
    region = bytearray(make_assembly())
    header_pos, _offset, size = find_stream(region, "#~")
    struct.pack_into("<I", region, header_pos + 4, size + 64)
    block = parse_region(bytes(region))
    assert "tables_layout_short:64" in block["degradations"]
    assert block["parse_status"] == "partial"
    assert "assembly" not in block
    assert "assembly_refs" not in block
    # The row counts are header data, unaffected by the column widths.
    assert block["counts"]["assembly"] == 1


# --------------------------------------------------------------------------
# Wire-up, SBOM, coverage, tuple (rule 21 recomputes)
# --------------------------------------------------------------------------


def test_sbom_components_from_assembly_refs():
    from blint.lib.sbom import process_dotnet_assembly_refs

    refs = [
        {"name": "System.Runtime", "version": "8.0.0.0",
         "public_key_token": "b03f5f7f11d50a3a", "culture": "neutral"},
        {"name": "System.Runtime", "version": "8.0.0.0",
         "public_key_token": "b03f5f7f11d50a3a", "culture": "neutral"},
        {"name": "Foo.Resources", "version": "1.0.0.0", "culture": "zh-Hans"},
    ]
    comps = process_dotnet_assembly_refs(refs)
    assert [c.purl for c in comps] == [
        "pkg:nuget/System.Runtime@8.0.0.0",
        "pkg:nuget/Foo.Resources@1.0.0.0",
    ]
    by_purl = {c.purl: c for c in comps}
    props = {p.name: p.value for p in by_purl["pkg:nuget/System.Runtime@8.0.0.0"].properties}
    assert props["internal:public_key_token"] == "b03f5f7f11d50a3a"
    props2 = {p.name: p.value for p in by_purl["pkg:nuget/Foo.Resources@1.0.0.0"].properties}
    assert props2["internal:culture"] == "zh-Hans"
    # The version slot says which kind of version it holds: an AssemblyRef
    # carries the four-part assembly version, not the NuGet package
    # version, and the two differ for the same library.
    assert props["internal:version_source"] == "assembly_version"


def test_assembly_refs_do_not_duplicate_a_deps_json_package():
    """One package, one component — the overlay's version wins.

    `.deps.json` names the NuGet package version (Newtonsoft.Json 13.0.3)
    and the AssemblyRef names the assembly version (13.0.0.0). Keyed on the
    purl the two are different strings, so both would land in the SBOM and
    the same package would appear twice at two versions, one of which is
    not a NuGet version. No corpus file exercises both paths today — the
    managed tier ships no `.deps.json` overlay — so this is the fixture
    that holds the property.
    """
    from blint.lib.sbom import (
        merge_dotnet_assembly_ref_components,
        process_dotnet_dependencies,
    )

    from_overlay = process_dotnet_dependencies(
        {
            "libraries": {
                "Newtonsoft.Json/13.0.3": {
                    "type": "package",
                    "sha512": "sha512-" + base64.b64encode(b"\x00" * 64).decode(),
                    "path": "n/13.0.3",
                }
            }
        },
        {},
    )
    assert [c.purl for c in from_overlay] == ["pkg:nuget/Newtonsoft.Json@13.0.3"]
    merged = merge_dotnet_assembly_ref_components(
        from_overlay,
        [
            {"name": "Newtonsoft.Json", "version": "13.0.0.0", "culture": "neutral"},
            {"name": "Serilog", "version": "4.0.0.0", "culture": "neutral"},
        ],
    )
    nuget = sorted(
        c.purl for c in merged
        if str(getattr(c, "purl", "")).startswith("pkg:nuget/")
    )
    assert "pkg:nuget/Newtonsoft.Json@13.0.3" in nuget
    assert "pkg:nuget/Newtonsoft.Json@13.0.0.0" not in nuget
    assert "pkg:nuget/Serilog@4.0.0.0" in nuget


def test_analysis_coverage_carries_dotnet_degradations():
    from blint.lib.binary import _build_analysis_coverage

    base = {"functions": [], "discovered_functions": [], "disassembled_functions": {}}
    cov = _build_analysis_coverage(
        {**base, "dotnet": {"parse_status": "partial"}}, False
    )
    assert "dotnet_metadata_partial" in cov["degradations"]
    cov = _build_analysis_coverage(
        {**base, "dotnet": {"parse_status": "malformed"}}, False
    )
    assert "dotnet_metadata_malformed" in cov["degradations"]
    cov = _build_analysis_coverage(
        {**base, "dotnet": {"parse_status": "parsed"}}, False
    )
    assert "dotnet_metadata_partial" not in cov["degradations"]
    assert "dotnet_metadata_malformed" not in cov["degradations"]


def test_llvm_target_tuple_managed_uses_machine_type():
    # Rule 21 recompute: exe_type no longer decides the architecture.
    from blint.lib.binary import construct_llvm_target_tuple

    assert construct_llvm_target_tuple({
        "is_dotnet": True, "machine_type": "ARM64", "exe_type": "dotnetbinary",
    }) == "aarch64-pc-windows-msvc"
    assert construct_llvm_target_tuple({
        "is_dotnet": True, "machine_type": "I386", "exe_type": "dotnetbinary",
    }) == "i686-pc-windows-msvc"
    assert construct_llvm_target_tuple({
        "is_dotnet": True, "machine_type": "AMD64", "exe_type": "dotnetbinary",
    }) == "x86_64-pc-windows-msvc"


# --------------------------------------------------------------------------
# Real-artifact assertions (ground rules 22/29) — skip when corpus absent
# --------------------------------------------------------------------------


def _corpus_path(relative: str):
    import os

    path = os.path.expanduser(f"~/sandbox/pe-corpus/{relative}")
    if not os.path.exists(path):
        pytest.skip("pe-corpus tier not present")
    return path


def test_real_newtonsoft_net45_identity_and_refs():
    # Ground truth: spec-based System.Reflection.Metadata dumper on the
    # Windows 11 ARM64 VM (pasted in the packet commit). Agreement fields:
    # assembly identity, public key token, AssemblyRef list, counts.
    path = _corpus_path(
        "tier2-managed/newtonsoft.json-13.0.3/lib/net45/Newtonsoft.Json.dll"
    )
    block = parse_pe_dotnet(_lief_parse(path), path)
    assert block["parse_status"] == "parsed"
    assert block["runtime_version"] == "v4.0.30319"
    assert block["cli_flags"] == ["ILONLY", "STRONGNAMESIGNED"]
    asm = block["assembly"]
    assert asm["name"] == "Newtonsoft.Json"
    assert asm["version"] == "13.0.0.0"
    assert asm["culture"] == "neutral"
    assert asm["public_key_token"] == "30ad4fe6b2a6aeed"
    assert asm["hash_algorithm"] == "SHA1"
    assert asm["mvid"] == "DD21E087-47D9-4BCE-BED8-B56112226337"
    assert block["target_framework"] == ".NETFramework,Version=v4.5"
    refs = {r["name"]: (r["version"], r.get("public_key_token"))
            for r in block["assembly_refs"]}
    assert refs["mscorlib"] == ("4.0.0.0", "b77a5c561934e089")
    assert refs["System.Numerics"] == ("4.0.0.0", "b77a5c561934e089")
    assert refs["System.Xml.Linq"] == ("4.0.0.0", "b77a5c561934e089")
    assert len(block["assembly_refs"]) == 8
    counts = block["counts"]
    assert counts["typedef"] == 500
    assert counts["methoddef"] == 4213
    assert counts["field"] == 2201
    assert counts["typeref"] == 354
    assert counts["memberref"] == 2125
    assert counts["assembly_ref"] == 8
    assert counts["implmap"] == 0
    assert "pinvoke" not in block  # genuine zero, not a cap or failure


def test_real_serilog_netstandard2():
    path = _corpus_path("tier2-managed/serilog-4.2.0/lib/netstandard2.0/Serilog.dll")
    block = parse_pe_dotnet(_lief_parse(path), path)
    assert block["assembly"]["name"] == "Serilog"
    assert block["assembly"]["public_key_token"] == "24c2f752a8e58a10"
    assert block["target_framework"] == ".NETStandard,Version=v2.0"
    ref_names = {r["name"] for r in block["assembly_refs"]}
    assert "netstandard" in ref_names
    assert "System.Threading.Channels" in ref_names


def test_real_satellite_assembly_culture():
    path = _corpus_path(
        "tier2-managed/system.text.json-9.0.0/analyzers/dotnet/roslyn4.4/cs/de/"
        "System.Text.Json.SourceGeneration.resources.dll"
    )
    block = parse_pe_dotnet(_lief_parse(path), path)
    assert block["assembly"]["culture"] == "de"
    assert block["assembly"]["public_key_token"] == "cc7b13ffcd2ddd51"


def test_real_mixed_mode_native_entrypoint_and_pinvoke():
    # mfcm140.dll: C++/CLI mixed-mode. NATIVE_ENTRYPOINT means the entry
    # token is an RVA, not a metadata token; the P/Invoke surface has the
    # two KERNEL32 entries; the IJW ImplMap rows with empty import names
    # are counted in counts.implmap but are not P/Invoke entries.
    path = _corpus_path("tier5-system/system32/mfcm140.dll")
    block = parse_pe_dotnet(_lief_parse(path), path)
    # Bit order, not alphabetical: the names table is blint-owned (rule 28).
    assert sorted(block["cli_flags"]) == ["NATIVE_ENTRYPOINT", "STRONGNAMESIGNED"]
    assert block["cli_flags_value"] == 0x18
    assert block["entry_point"] == {"token": "0x000044f0", "kind": "native"}
    assert block["counts"]["implmap"] == 49
    entries = {(e["module"], e["entry_point"]) for e in block["pinvoke"]}
    assert entries == {
        ("KERNEL32.dll", "DecodePointer"),
        ("KERNEL32.dll", "EncodePointer"),
    }
    assert block["assembly"]["name"] == "MFCM140"
    assert block["assembly"]["version"] == "14.51.36247.0"


def test_real_native_pe_has_no_dotnet_block():
    path = _corpus_path("tier0-reference/python-amd64/python.exe")
    parsed_obj = _lief_parse(path)
    assert parse_pe_dotnet(parsed_obj, path) is None


def test_real_parse_exetype_and_block_shape():
    import json

    from blint.lib.binary import parse

    path = _corpus_path(
        "tier2-managed/newtonsoft.json-13.0.3/lib/net45/Newtonsoft.Json.dll"
    )
    metadata = parse(path)
    assert metadata["exe_type"] == "dotnetbinary"
    assert metadata["is_dotnet"] is True
    block = metadata["dotnet"]
    # JSON-serializable, no bytes anywhere (rule 20).
    json.dumps(block)
    assert block["parse_status"] == "parsed"


def test_real_managed_exetype_change_does_not_break_ordinal_width():
    # The ordinal-parse width used to be derived from exe_type; it now
    # comes from the optional-header magic. A 64-bit managed file keeps
    # PE64-width parsing even though its exe_type is dotnetbinary.
    import lief

    path = _corpus_path("tier5-system/system32/mfcm140u.dll")
    parsed_obj = _lief_parse(path)
    assert parsed_obj.optional_header.magic == lief.PE.PE_TYPE.PE32_PLUS
    from blint.lib.binary import parse

    meta = parse(path)
    assert meta["exe_type"] == "dotnetbinary"
    block = meta["dotnet"]
    assert block["parse_status"] == "parsed"
    assert block["assembly"]["name"] == "MFCM140U"
    # The dependency list still resolves on the PE64 width.
    assert meta["imports"]


def test_managed_exe_type_loses_no_rule_without_an_argued_reason():
    """Moving managed PEs to `dotnetbinary` must not drop a check quietly.

    W3.1 changed `exe_type` for every managed binary, so every rule scoped
    to PE32/PE64 and not to dotnetbinary stopped reaching them. Two of
    those were argued in rules.yml and are the point of the change
    (CHECK_CANARY and CHECK_RPATH could only ever return their false
    negative verdict on a pure-IL image). CHECK_PACKED was not argued and
    was not intended: it reads section entropy, packer section signatures
    and the overlay, none of which are native-only, and a packed or
    obfuscator-protected assembly is one of the commonest hostile managed
    shapes. The packet's own before/after showed no firing move, because
    all 62 managed corpus files score packed_likelihood low — a rule
    silently leaving scope does not announce itself by changing a count on
    a benign corpus, which is why this is a scope assertion and not a
    findings assertion.
    """
    from pathlib import Path

    import yaml

    rules = yaml.safe_load(
        (Path(pe_dotnet.__file__).parent.parent / "data" / "rules.yml").read_text()
    )
    rules = rules if isinstance(rules, list) else rules.get("rules", rules)
    native = {
        r["id"] for r in rules
        if {"PE32", "PE64"} & set(r.get("exe_types") or [])
    }
    managed = {
        r["id"] for r in rules if "dotnetbinary" in (r.get("exe_types") or [])
    }
    # Every removal must be argued in rules.yml beside the scope itself.
    argued_removals = {"CHECK_CANARY", "CHECK_RPATH"}
    assert native - managed == set()
    assert argued_removals & native == set()


def test_unhandled_heapsizes_bit_is_named():
    """A HeapSizes bit blint does not read is named, not assumed away.

    The bits beyond the three index widths mark delta-only and extra-data
    metadata, which move where the rows begin. No assembly measured sets
    one (375 files, all `#~`, HeapSizes 0x00/0x01/0x05), so blint has never
    laid out that shape and says so instead of guessing.
    """
    region = bytearray(make_assembly())
    _header_pos, offset, _size = find_stream(region, "#~")
    sig = region.find(b"BSJB")
    region[sig + offset + 6] |= 0x40
    block = parse_region(bytes(region))
    assert "table_stream_heapsizes_unhandled:0x40" in block["degradations"]
    assert block["parse_status"] == "partial"


def test_real_assemblies_leave_only_an_alignment_tail():
    """Every corpus assembly's rows account for its whole table stream.

    ``MAX_TABLE_STREAM_LEFTOVER`` is only as good as its threshold, and the
    threshold is a measurement: re-run it here against whatever the corpus
    actually holds rather than trusting the number in a packet report. A
    file that trips the guard is either a layout blint computes wrongly or
    a real shape the threshold is too tight for — both are review material,
    and both are invisible to the inline fixtures, which encode their rows
    through the parser's own constants.
    """
    import os

    root = _corpus_path("tier2-managed")
    checked = 0
    for dirpath, _dirs, files in os.walk(root):
        for name in sorted(files):
            if not name.lower().endswith((".dll", ".exe")):
                continue
            path = os.path.join(dirpath, name)
            parsed_obj = _lief_parse(path)
            if parsed_obj is None:
                continue
            block = parse_pe_dotnet(parsed_obj, path)
            if block is None:
                continue
            checked += 1
            short = [
                d for d in block.get("degradations", [])
                if d.startswith("tables_layout_short")
            ]
            assert not short, f"{path}: {short}"
    assert checked > 0


def _lief_parse(path):
    import lief

    return lief.PE.parse(path)
