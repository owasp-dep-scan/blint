"""MSI (Microsoft Installer) reader on top of the CFBF reader (W4.2).

An ``.msi`` is a CFBF storage whose streams are database tables. Table
streams carry encoded names (the MSI name encoding — see
:func:`decode_stream_name`, verified against msitools' decoder and against
the real 7z-x64.msi corpus artifact); row data lives in ``!_StringPool`` /
``!_StringData`` plus one stream per table.

What blint extracts, per the plan's ``03/B`` row: product/package/upgrade
codes, the ``File``/``Component``/``Binary`` tables, the ``CustomAction``
table with its deferred/impersonated flags and embedded script text — the
persistent-install attack surface — embedded CABs (the ``Media`` table's
cabinet column plus the binary streams they name), the summary information
stream and the digital-signature stream presence.

Bounds: table row counts are capped per table (``MAX_ROWS_PER_TABLE``,
listed rows fewer — the count stays exact so a capped table never reads as
small), stream reads go through the CFBF reader's budget, and Binary-table
stream *bytes* are never read at all (only names and sizes: script bodies
are the reviewer's job, and reading them would be an arbitrary-code-shaped
blob in metadata). Hostile fixtures exceed every cap in
``tests/test_msi.py``.
"""

# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
# SPDX-License-Identifier: Apache-2.0

import codecs
import struct
from typing import ClassVar

from blint.lib.cfbf import CfbfReader, iter_summary_information
from blint.logger import LOG

# Measured: the 7z-x64.msi reference carries 38 streams and its largest
# table (_StringPool excluded) is a few thousand rows; 65,535 is the
# two-byte string-reference ceiling at which the format itself switches
# encoding, so no real two-byte database exceeds this.
MAX_ROWS_PER_TABLE = 65535
MAX_LISTED_ROWS = 512
MAX_LISTED_BINARIES = 256
MAX_LISTED_CUSTOM_ACTIONS = 512

# Column type flags (MS-DB "SQL column types"; the constants msitools and
# wine both carry).
MSITYPE_VALID = 0x0100
MSITYPE_LOCALIZABLE = 0x0200
MSITYPE_STRING = 0x0800
MSITYPE_NULLABLE = 0x1000
MSITYPE_KEY = 0x2000
MSITYPE_TEMPORARY = 0x4000

# CustomAction type field bits (MSDN Custom Action Tables).
CA_SOURCE_BINARY = 0x00
CA_SOURCE_FILE = 0x10
CA_SOURCE_DIRECTORY = 0x20
CA_SOURCE_PROPERTY = 0x30
CA_TYPE_DLL = 0x01
CA_TYPE_EXE = 0x02
CA_TYPE_TEXTDATA = 0x04
CA_TYPE_JSCRIPT = 0x05
CA_TYPE_VBSCRIPT = 0x06
CA_TYPE_INSTALL = 0x07
CA_ASYNC = 0x40
CA_CONTINUE = 0x80
CA_ROLLBACK = 0x100
CA_IN_SCRIPT = 0x400
CA_NO_IMPERSONATE = 0x800
CA_TS_AWARE = 0x4000


def mime2utf(value: int) -> str:
    """The MSI 'mime' alphabet back to a character (msitools table.c)."""
    if value < 10:
        return chr(value + ord("0"))
    if value < 36:
        return chr(value - 10 + ord("A"))
    if value < 62:
        return chr(value - 36 + ord("a"))
    if value == 62:
        return "."
    return "_"


def decode_stream_name(codepoints: list[int]) -> str:
    """Decode one encoded MSI stream name from its UTF-16 codepoints.

    A table stream's name begins with U+4840; every following codepoint in
    0x3800..0x47ff packs two alphabet characters (low 6 bits = first, next
    6 bits with the 0x20 flip = second), and 0x4800..0x483f packs one
    trailing character. Verified against the real corpus MSI: the stream
    msitools names ``!Component`` decodes to ``!Component`` here too.
    """
    out: list[str] = []
    position = 0
    is_table = bool(codepoints) and codepoints[0] == 0x4840
    if is_table:
        position = 1
    while position < len(codepoints):
        point = codepoints[position]
        if 0x3800 <= point <= 0x47FF:
            out.append(mime2utf(point & 0x3F))
            out.append(mime2utf(((point >> 6) & 0x3F) ^ 0x20))
        elif 0x4800 <= point <= 0x483F:
            out.append(mime2utf(point & 0x3F))
        elif point:
            out.append(chr(point))
        position += 1
    return ("!" if is_table else "") + "".join(out)


class MsiDatabase:
    """Table access over one MSI's CFBF image."""

    def __init__(self, reader: CfbfReader, refusals: list[str], degradations: list[str]):
        self.reader = reader
        self.refusals = refusals
        self.degradations = degradations
        self.strings: list[str] = []
        self.bytes_per_strref = 2
        self._tables: dict[str, list[list]] = {}
        self._column_cache: dict[str, list[tuple[int, str, int]]] = {}
        self._load_strings()

    # -- string pool -------------------------------------------------------

    def _load_strings(self) -> None:
        pool_entry = self._find_stream("!_StringPool")
        data_entry = self._find_stream("!_StringData")
        if pool_entry is None or data_entry is None:
            # A database with no string pool: only the SummaryInformation
            # remains, which the caller reads directly.
            self.refusals.append("string_pool_missing")
            return
        pool = self.reader.read_entry(pool_entry)
        data = self.reader.read_entry(data_entry)
        if len(pool) < 4 or not data:
            self.refusals.append("string_pool_missing")
            return
        codepage, flag = struct.unpack("<HH", pool[:4])
        self.codepage = codepage or 1252
        if flag & 0x8000:
            self.bytes_per_strref = 3
            self.degradations.append("msi_wide_string_refs")
        strings: list[str] = [""]
        offset = 0
        index = 1
        count = len(pool) // 4
        try:
            decoder = codecs.lookup(f"cp{self.codepage}").incrementaldecoder("replace")
        except (LookupError, TypeError):
            decoder = None
        while index < count and len(strings) <= MAX_ROWS_PER_TABLE:
            # Entry layout: (length u16, reference count u16) — the length
            # word comes first (msitools string.c pool[i*2] = len).
            length_field, refs = struct.unpack("<HH", pool[index * 4 : index * 4 + 4])
            if length_field == 0 and refs == 0:
                strings.append("")
                index += 1
                continue
            if length_field == 0:
                # Long string: the length's high word hides in the next
                # entry's length field.
                if index * 4 + 8 > len(pool):
                    self.degradations.append("string_pool_corrupt")
                    break
                extra = struct.unpack("<HH", pool[index * 4 + 4 : index * 4 + 8])
                length = (extra[1] << 16) | extra[0]
                index += 2
            else:
                length = length_field
                index += 1
            chunk = data[offset : offset + length]
            offset += length
            if decoder is not None:
                strings.append(decoder.decode(chunk))
            else:
                strings.append(chunk.decode("latin-1", "replace"))
        self.strings = strings

    def _find_stream(self, name: str):
        """Find a stream by its *decoded* name (linear over the tree)."""
        for entry in self.reader.tree():
            if entry["type"] != "stream":
                continue
            if entry["name"] == name:
                return entry
            raw = [ord(c) for c in entry["name"]]
            if decode_stream_name(raw) == name:
                return entry
        return None

    def lookup(self, string_id: int) -> str:
        if 0 < string_id < len(self.strings):
            return self.strings[string_id]
        return ""

    # -- tables ------------------------------------------------------------

    def _read_table_stream(self, table: str) -> bytes | None:
        entry = self._find_stream(f"!{table}")
        if entry is None:
            return None
        return self.reader.read_entry(entry)

    # Fixed layouts of the two schema tables, which by definition cannot be
    # read through _Columns itself (that would recurse forever).
    _SCHEMA_LAYOUTS: ClassVar[dict] = {
        "_Tables": [(1, "Name", MSITYPE_STRING | MSITYPE_VALID | MSITYPE_KEY)],
        "_Columns": [
            (1, "Table", MSITYPE_STRING | MSITYPE_VALID | MSITYPE_KEY),
            (2, "Number", MSITYPE_VALID | MSITYPE_KEY),
            (3, "Name", MSITYPE_STRING | MSITYPE_VALID),
            (4, "Type", MSITYPE_VALID),
        ],
    }

    def columns(self, table: str) -> list[tuple[int, str, int]]:
        """``(position, name, type)`` rows from ``_Columns``, cached."""
        if table in self._column_cache:
            return self._column_cache[table]
        result: list[tuple[int, str, int]] = []
        for layout_row in self._raw_rows("_Columns", 4):
            if len(layout_row) != 4:
                continue
            if self.lookup(layout_row[0]) == table:
                result.append((layout_row[1], self.lookup(layout_row[2]), layout_row[3]))
        result.sort()
        self._column_cache[table] = result
        return result

    def table_names(self) -> list[str]:
        rows = self._raw_rows("_Tables", 1)
        return sorted({self.lookup(row[0]) for row in rows if row})

    def _raw_rows(self, table: str, expected_columns: int) -> list[list[int]]:
        """Rows as raw integer/string-id tuples, before value decoding."""
        if table in self._tables:
            return self._tables[table]
        data = self._read_table_stream(table)
        rows: list[list[int]] = []
        if data is None:
            self._tables[table] = rows
            return rows
        columns = self._SCHEMA_LAYOUTS.get(table) or self.columns(table)
        if not columns:
            self._tables[table] = rows
            return rows
        row_size = 0
        for position, _name, col_type in columns:
            if (col_type & ~MSITYPE_NULLABLE) == (MSITYPE_STRING | MSITYPE_VALID):
                row_size += 2  # binary column: 2-byte stream id
            elif col_type & MSITYPE_STRING:
                row_size += self.bytes_per_strref
            elif (col_type & 0xFF) <= 2:
                row_size += 2
            elif (col_type & 0xFF) == 4:
                row_size += 4
            else:
                self.degradations.append("msi_unknown_column_width")
                return rows
        if row_size == 0 or len(data) % row_size != 0:
            self.degradations.append("msi_table_corrupt")
            self._tables[table] = rows
            return rows
        total_rows = len(data) // row_size
        # The table stream is stored COLUMN-MAJOR (msitools' read_table_from_
        # storage indexes rawdata[ofs * row_count + i * n]): each column's
        # row_count values are contiguous, one column after another.
        widths = []
        for _position, _name, col_type in columns:
            if (col_type & ~MSITYPE_NULLABLE) == (MSITYPE_STRING | MSITYPE_VALID):
                widths.append(2)
            elif col_type & MSITYPE_STRING:
                widths.append(self.bytes_per_strref)
            elif (col_type & 0xFF) <= 2:
                widths.append(2)
            else:
                widths.append(4)

        def column_value(block_offset: int, value_offset: int, width: int, col_type: int):
            start = block_offset + value_offset
            raw = data[start : start + width]
            if width == 2:
                return struct.unpack("<H", raw)[0]
            if width == 3:
                return raw[0] | (raw[1] << 8) | (raw[2] << 16)
            if width == 4:
                return struct.unpack("<I", raw)[0]
            return None

        for row_index in range(min(total_rows, MAX_ROWS_PER_TABLE)):
            row = []
            block_offset = 0
            for width, (_position, _name, col_type) in zip(widths, columns):
                row.append(column_value(block_offset, row_index * width, width, col_type))
                block_offset += width * total_rows
            rows.append(row)
        if total_rows > MAX_ROWS_PER_TABLE:
            self.refusals.append("msi_row_count_exceeds_cap")
        self._tables[table] = rows
        return rows

    def rows(self, table: str) -> list[dict]:
        """Rows decoded to ``{column: value}`` with strings resolved.

        Binary columns (``Data`` in the Binary table) carry stream ids, not
        string ids — their raw value is kept and resolved to the stream by
        the caller, never through the string table.
        """
        columns = self.columns(table)
        raw_rows = self._raw_rows(table, len(columns))
        decoded = []
        for row in raw_rows:
            entry = {}
            for (_position, name, col_type), value in zip(columns, row):
                if col_type & MSITYPE_STRING and (col_type & ~MSITYPE_NULLABLE) != (
                    MSITYPE_STRING | MSITYPE_VALID
                ):
                    entry[name] = self.lookup(value)
                else:
                    entry[name] = value
            decoded.append(entry)
        return decoded


def decode_custom_action_type(action_type: int) -> dict:
    """The CustomAction Type field into named facts (MSDN flags)."""
    kind = {
        CA_TYPE_DLL: "dll",
        CA_TYPE_EXE: "exe",
        CA_TYPE_TEXTDATA: "text_data",
        CA_TYPE_JSCRIPT: "jscript",
        CA_TYPE_VBSCRIPT: "vbscript",
        CA_TYPE_INSTALL: "install",
    }.get(action_type & 0x0F, "unknown")
    source = {
        CA_SOURCE_BINARY: "binary_table",
        CA_SOURCE_FILE: "installed_file",
        CA_SOURCE_DIRECTORY: "directory",
        CA_SOURCE_PROPERTY: "property",
    }.get(action_type & 0x30, "unknown")
    return {
        "kind": kind,
        "source": source,
        "async": bool(action_type & CA_ASYNC),
        "continue_on_error": bool(action_type & CA_CONTINUE),
        "rollback": bool(action_type & CA_ROLLBACK),
        "deferred_in_script": bool(action_type & CA_IN_SCRIPT),
        "no_impersonate": bool(action_type & CA_NO_IMPERSONATE),
        "terminal_server_aware": bool(action_type & CA_TS_AWARE),
    }


def parse_msi(path: str, refusals: list[str], degradations: list[str]) -> dict:
    """Parse one ``.msi`` file into blint's facts block.

    Reads the tables the plan names plus the summary and signature streams;
    never reads Binary-table stream bytes (names and sizes only).
    """

    block: dict = {
        "parse_status": "parsed",
        "table_count": 0,
        "tables": [],
        "identity": {},
        "summary": {},
        "file_count": 0,
        "component_count": 0,
        "custom_action_count": 0,
        "custom_actions": [],
        "binaries": [],
        "embedded_cabinets": [],
        "digital_signature_present": False,
        "refusals": [],
        "degradations": [],
    }
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError:
        block["parse_status"] = "failed"
        block["refusals"].append("archive_unreadable")
        return block
    try:
        reader = CfbfReader(data, refusals, degradations)
    except Exception:
        block["parse_status"] = "failed"
        block["refusals"].append("archive_unreadable")
        return block
    database = MsiDatabase(reader, refusals, degradations)
    tables = database.table_names()
    block["tables"] = tables
    block["table_count"] = len(tables)
    block["summary"] = iter_summary_information(reader)
    # Identity: Property table plus the PackageCode from the summary's
    # template property (its last hex token).
    properties = {}
    if "Property" in tables:
        for row in database.rows("Property"):
            properties[row.get("Property", "")] = row.get("Value", "")
    block["identity"] = {
        "product_code": properties.get("ProductCode"),
        "upgrade_code": properties.get("UpgradeCode"),
        "product_name": properties.get("ProductName"),
        "product_version": properties.get("ProductVersion"),
        "manufacturer": properties.get("Manufacturer"),
        # The PackageCode is the summary information's Revision Number
        # property (PID_REVNUMBER), a GUID.
        "package_code": block["summary"].get("revision_number"),
    }
    if "File" in tables:
        block["file_count"] = len(database._raw_rows("File", 0))
    if "Component" in tables:
        block["component_count"] = len(database._raw_rows("Component", 0))
    if "CustomAction" in tables:
        actions = database.rows("CustomAction")
        block["custom_action_count"] = len(actions)
        for action in actions[:MAX_LISTED_CUSTOM_ACTIONS]:
            decoded = decode_custom_action_type(int(action.get("Type", 0)))
            decoded.update(
                {
                    "action": action.get("Action"),
                    "source": decoded.pop("source"),
                    "source_name": action.get("Source"),
                    "target": action.get("Target"),
                }
            )
            block["custom_actions"].append(decoded)
        if len(actions) > MAX_LISTED_CUSTOM_ACTIONS:
            block["refusals"].append("custom_actions_listed_capped")
    if "Binary" in tables:
        binary_rows = database.rows("Binary")
        block["binary_count"] = len(binary_rows)
        for row in binary_rows[:MAX_LISTED_BINARIES]:
            name = row.get("Name") or row.get("Binary")
            stream = database._find_stream(f"Binary.{name}") if name else None
            block["binaries"].append(
                {"name": name, "stream_size": stream["size"] if stream else None}
            )
        if len(binary_rows) > MAX_LISTED_BINARIES:
            block["refusals"].append("binaries_listed_capped")
    # Embedded cabinets: Media table's Cabinet column names them; each is a
    # CFBF stream (optionally the value names a file outside the database).
    if "Media" in tables:
        for row in database.rows("Media"):
            cabinet = row.get("Cabinet") or ""
            if not cabinet:
                continue
            name = cabinet.removeprefix("#")
            stream = database._find_stream(f"!{name}") or database._find_stream(name)
            block["embedded_cabinets"].append(
                {
                    "name": name,
                    "embedded": stream is not None,
                    "size": stream["size"] if stream else None,
                }
            )
    # Digital signature streams (MsiDigitalSignature / MsiDigitalSignatureEx).
    signature_entries = [
        entry
        for entry in reader.tree()
        if entry["type"] == "stream"
        and decode_stream_name([ord(c) for c in entry["name"]]) in ("!DigitalSignature", "!MsiDigitalSignatureEx")
    ]
    block["digital_signature_present"] = bool(signature_entries)
    block["refusals"] = sorted(set(block["refusals"] + refusals))
    block["degradations"] = sorted(set(block["degradations"] + degradations))
    if degradations and block["parse_status"] == "parsed":
        block["parse_status"] = "partial"
    LOG.debug("MSI parsed: %d tables, %d custom actions", block["table_count"], block["custom_action_count"])
    return block
