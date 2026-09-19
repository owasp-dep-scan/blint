"""ECMA-335 CLI (.NET) metadata reader for managed PE binaries.

Reads the `#~` (compressed) or `#-` (uncompressed) table stream plus the
`#Strings`, `#Blob`, `#GUID` and `#US` heaps of a managed assembly and
reports the identity-and-references block (plan 03/A.1): assembly identity,
AssemblyRefs, ModuleRefs, the P/Invoke surface, table counts, the entry
point, the CLI header flags and the target framework attribute.

Everything here is attacker-controlled input with cross-references: a row's
string is an index into `#Strings`, a type is a coded index into another
table, and a malformed file points them anywhere. Every heap read and every
table walk is bounds-checked against the region the CLI header declared,
and every refusal is recorded as a named degradation in the block rather
than read as clean (ground rule 30). Counts and listings are separate facts
(ground rule 14): ``counts`` carries the row counts the stream header
declared for tables whose rows were verifiably within the stream, while the
listed blocks (``assembly_refs``, ``module_refs``, ``pinvoke``) are capped
listings and stay absent entirely when their table could not be read —
absent is never written as an empty list, so "no AssemblyRefs" and "the
AssemblyRef table was unreadable" are different outputs.
"""

import hashlib
import struct

# Metadata root signature "BSJB" (ECMA-335 II.24.2.1).
METADATA_SIGNATURE = 0x424A5342

# COMIMAGE_FLAGS (ECMA-335 II.25.3.3.1), bit, blint-owned name.
CLI_FLAG_NAMES = (
    (0x00000001, "ILONLY"),
    (0x00000002, "32BITREQUIRED"),
    (0x00000004, "IL_LIBRARY"),
    (0x00000008, "STRONGNAMESIGNED"),
    (0x00000010, "NATIVE_ENTRYPOINT"),
    (0x00010000, "TRACKDEBUGDATA"),
    (0x00020000, "32BITPREFERRED"),
)

# Assembly hash algorithm identifiers (ECMA-335 II.23.1.1, CorAlgId).
HASH_ALGORITHM_NAMES = {
    0x0000: "NONE",
    0x8003: "MD5",
    0x8004: "SHA1",
    0x800C: "SHA256",
    0x800D: "SHA384",
    0x800E: "SHA512",
}

# Table numbers (ECMA-335 II.22).
MODULE = 0x00
TYPE_REF = 0x01
TYPE_DEF = 0x02
FIELD_PTR = 0x03
FIELD = 0x04
METHOD_PTR = 0x05
METHOD_DEF = 0x06
PARAM_PTR = 0x07
PARAM = 0x08
MEMBER_REF = 0x0A
CUSTOM_ATTRIBUTE = 0x0C
MODULE_REF = 0x1A
IMPL_MAP = 0x1C
ASSEMBLY = 0x20
ASSEMBLY_REF = 0x23
FILE_TABLE = 0x26
EXPORTED_TYPE = 0x27
METHOD_SPEC = 0x2B
GENERIC_PARAM = 0x2A
MAX_KNOWN_TABLE = 0x2C

# Coded indexes (ECMA-335 II.24.2.6): the full tag slot list, including the
# None slots the spec reserves, and the tag-bit count. Tag values index the
# slot list positionally, so a None slot never silently shifts a tag.
#
# These lists are not only a tag mapping: the widest constituent table sets
# the column's byte width, so a table missing from a list can narrow a
# column and shift every byte after it — including the rows of every table
# laid out later. ``test_coded_index_slots_match_the_spec`` pins each list
# against II.24.2.6 transcribed independently, and ``_table_layout``'s
# leftover check catches a width that is wrong for any other reason.
CODED_INDEXES = {
    "TypeDefOrRef": ((TYPE_DEF, TYPE_REF, 0x1B), 2),
    "HasConstant": ((FIELD, PARAM, 0x17), 2),
    "HasCustomAttribute": (
        (
            METHOD_DEF, FIELD, TYPE_REF, TYPE_DEF, PARAM, 0x09, MEMBER_REF,
            MODULE, 0x0E, 0x17, 0x14, 0x11, MODULE_REF, 0x1B, ASSEMBLY,
            ASSEMBLY_REF, FILE_TABLE, EXPORTED_TYPE, 0x28, GENERIC_PARAM,
            0x2C, METHOD_SPEC,
        ),
        5,
    ),
    "HasFieldMarshal": ((FIELD, PARAM), 1),
    "HasDeclSecurity": ((TYPE_DEF, METHOD_DEF, ASSEMBLY), 2),
    "MemberRefParent": ((TYPE_DEF, TYPE_REF, MODULE_REF, METHOD_DEF, 0x1B), 3),
    "HasSemantics": ((0x14, 0x17), 1),
    "MethodDefOrRef": ((METHOD_DEF, MEMBER_REF), 1),
    "MemberForwarded": ((FIELD, METHOD_DEF), 1),
    "Implementation": ((FILE_TABLE, ASSEMBLY_REF, EXPORTED_TYPE), 2),
    "CustomAttributeType": ((None, None, METHOD_DEF, MEMBER_REF, None), 3),
    "ResolutionScope": ((MODULE, MODULE_REF, ASSEMBLY_REF, TYPE_REF), 2),
    "TypeOrMethodDef": ((TYPE_DEF, METHOD_DEF), 1),
}

# Column kinds: ("u1"|"u2"|"u4",) fixed widths, ("pad", n) reserved bytes,
# ("str",)/("guid",)/("blob",) heap indexes, ("tbl", t) simple table indexes
# and ("cod", name) coded indexes (II.24.2.6).
TABLE_SCHEMAS = {
    0x00: (("u2",), ("str",), ("guid",), ("guid",), ("guid",)),  # Module
    0x01: (("cod", "ResolutionScope"), ("str",), ("str",)),  # TypeRef
    0x02: (  # TypeDef
        ("u4",), ("str",), ("str",), ("cod", "TypeDefOrRef"),
        ("tbl", FIELD), ("tbl", METHOD_DEF),
    ),
    0x03: (("tbl", FIELD),),  # FieldPtr
    0x04: (("u2",), ("str",), ("blob",)),  # Field
    0x05: (("tbl", METHOD_DEF),),  # MethodPtr
    0x06: (  # MethodDef
        ("u4",), ("u2",), ("u2",), ("str",), ("blob",), ("tbl", PARAM),
    ),
    0x07: (("tbl", PARAM),),  # ParamPtr
    0x08: (("u2",), ("u2",), ("str",)),  # Param
    0x09: (("tbl", TYPE_DEF), ("cod", "TypeDefOrRef")),  # InterfaceImpl
    0x0A: (("cod", "MemberRefParent"), ("str",), ("blob",)),  # MemberRef
    0x0B: (("u1",), ("pad", 1), ("cod", "HasConstant"), ("blob",)),  # Constant
    0x0C: (  # CustomAttribute
        ("cod", "HasCustomAttribute"), ("cod", "CustomAttributeType"),
        ("blob",),
    ),
    0x0D: (("cod", "HasFieldMarshal"), ("blob",)),  # FieldMarshal
    0x0E: (("u2",), ("cod", "HasDeclSecurity"), ("blob",)),  # DeclSecurity
    0x0F: (("u2",), ("u4",), ("tbl", TYPE_DEF)),  # ClassLayout
    0x10: (("u4",), ("tbl", FIELD)),  # FieldLayout
    0x11: (("blob",),),  # StandAloneSig
    0x12: (("tbl", TYPE_DEF), ("tbl", 0x14)),  # EventMap
    0x13: (("tbl", 0x14),),  # EventPtr
    0x14: (("u2",), ("str",), ("cod", "TypeDefOrRef")),  # Event
    0x15: (("tbl", TYPE_DEF), ("tbl", 0x17)),  # PropertyMap
    0x16: (("tbl", 0x17),),  # PropertyPtr
    0x17: (("u2",), ("str",), ("blob",)),  # Property
    0x18: (("u2",), ("tbl", METHOD_DEF), ("cod", "HasSemantics")),  # MethodSemantics
    0x19: (  # MethodImpl
        ("tbl", TYPE_DEF), ("cod", "MethodDefOrRef"),
        ("cod", "MethodDefOrRef"),
    ),
    0x1A: (("str",),),  # ModuleRef
    0x1B: (("blob",),),  # TypeSpec
    0x1C: (  # ImplMap
        ("u2",), ("cod", "MemberForwarded"), ("str",), ("tbl", MODULE_REF),
    ),
    0x1D: (("u4",), ("tbl", FIELD)),  # FieldRVA
    0x1E: (("u4",), ("u4",)),  # EncLog
    0x1F: (("u4",),),  # EncMap
    0x20: (  # Assembly
        ("u4",), ("u2",), ("u2",), ("u2",), ("u2",), ("u4",), ("blob",),
        ("str",), ("str",),
    ),
    0x21: (("u4",),),  # AssemblyProcessor
    0x22: (("u4",), ("u4",), ("u4",)),  # AssemblyOS
    0x23: (  # AssemblyRef
        ("u2",), ("u2",), ("u2",), ("u2",), ("u4",), ("blob",), ("str",),
        ("str",), ("blob",),
    ),
    0x24: (("u4",), ("tbl", ASSEMBLY_REF)),  # AssemblyRefProcessor
    0x25: (("u4",), ("u4",), ("u4",), ("tbl", ASSEMBLY_REF)),  # AssemblyRefOS
    0x26: (("u4",), ("str",), ("blob",)),  # File
    0x27: (  # ExportedType
        ("u4",), ("u4",), ("str",), ("str",), ("cod", "Implementation"),
    ),
    0x28: (("u4",), ("u4",), ("str",), ("cod", "Implementation")),  # ManifestResource
    0x29: (("tbl", TYPE_DEF), ("tbl", TYPE_DEF)),  # NestedClass
    0x2A: (("u2",), ("u2",), ("cod", "TypeOrMethodDef"), ("str",)),  # GenericParam
    0x2B: (("cod", "MethodDefOrRef"), ("blob",)),  # MethodSpec
    0x2C: (("tbl", GENERIC_PARAM), ("cod", "TypeDefOrRef")),  # GenericParamConstraint
}

# Bounds. Every limit here ships with a hostile fixture that exceeds it.
MAX_STREAMS = 16  # Real assemblies declare five.
MAX_STREAM_NAME_LEN = 64
MAX_VERSION_AREA_BYTES = 1024  # "v4.0.30319" is 10 bytes.
MAX_STRING_READ = 4096  # Longest real #Strings entry: a few hundred bytes.
MAX_BLOB_READ = 65536  # Public-key blobs top out near 2 KB.
MAX_LISTED_ASSEMBLY_REFS = 1024  # Real counts: low hundreds at most.
MAX_LISTED_MODULE_REFS = 256
MAX_LISTED_PINVOKE = 512
MAX_TARGET_FRAMEWORK_VALUES = 8
MAX_TABLES = 64  # The Valid mask is an 8-byte bitmask.
# A correct layout accounts for the whole table stream bar an alignment
# tail: measured over 375 real assemblies (the .NET 10 shared framework
# plus corpus tiers 0/1/2/5), the leftover is 0, 2 or 4 bytes and nothing
# else. More than that means the computed row widths are wrong, and the
# rows read under them are some other table's bytes.
MAX_TABLE_STREAM_LEFTOVER = 4


def public_key_token(blob: bytes | None) -> str | None:
    """The eight-byte public key token for an assembly public key blob.

    A blob longer than eight bytes is a full public key (``afPublicKey``):
    the token is the low eight bytes of its SHA-1, reversed. An eight-byte
    blob is the token itself. Anything else (absent, empty) yields None —
    "no public key" is not a token of zeroes.
    """
    if not blob or len(blob) < 8:
        return None
    if len(blob) == 8:
        return blob.hex()
    # The token is the low eight bytes of the SHA-1, reversed.
    return bytes(hashlib.sha1(blob).digest()[-8:][::-1]).hex()


def format_guid(raw: bytes) -> str | None:
    """Render a 16-byte GUID the way dumpbin renders CodeView GUIDs."""
    if not raw or len(raw) != 16:
        return None
    d1, d2, d3 = struct.unpack_from("<IHH", raw, 0)
    return (
        f"{d1:08X}-{d2:04X}-{d3:04X}-{raw[8:10].hex().upper()}-"
        f"{raw[10:16].hex().upper()}"
    )


def rva_to_offset(sections, rva: int) -> int:
    """Map an RVA through the PE section table to a file offset (-1 on miss).

    Mirrors the PE loader rule: an RVA inside a section's virtual range maps
    into that section's raw data. Unmapped RVAs return -1 so the caller can
    degrade instead of reading a wrong offset.
    """
    for section in sections:
        va = int(getattr(section, "virtual_address", 0) or 0)
        raw_size = int(getattr(section, "sizeof_raw_data", 0) or 0)
        raw_ptr = int(getattr(section, "offset", 0) or 0)
        if raw_size > 0 and va <= rva < va + raw_size:
            return raw_ptr + (rva - va)
    return -1


def find_cli_directory(parsed_obj) -> tuple[int, int] | None:
    """Locate the CLR runtime header data directory as (rva, size).

    Returns None when the file declares no CLI header (data directory 14
    empty), which is the native-PE case.
    """
    try:
        for index, directory in enumerate(parsed_obj.data_directories):
            if index != 14:  # IMAGE_DIRECTORY_ENTRY_COMHEADER
                continue
            rva = int(getattr(directory, "rva", 0) or 0)
            size = int(getattr(directory, "size", 0) or 0)
            if rva <= 0 or size <= 0:
                return None
            return rva, size
    except (AttributeError, TypeError, ValueError):
        return None
    return None


def read_cli_header(window: bytes) -> dict | None:
    """Decode IMAGE_COR20_HEADER facts from a window at the CLI header.

    ``window`` starts at the CLI header. Returns None when it is shorter
    than the fields read here or the declared ``cb`` is smaller than them —
    a wrong-size header is a malformed claim, not an empty one.
    """
    if len(window) < 24:
        return None
    cb = struct.unpack_from("<I", window, 0)[0]
    if cb < 24:
        return None
    major_runtime, minor_runtime = struct.unpack_from("<HH", window, 4)
    metadata_rva, metadata_size = struct.unpack_from("<II", window, 8)
    flags = struct.unpack_from("<I", window, 16)[0]
    entry_point_token = struct.unpack_from("<I", window, 20)[0]
    return {
        "cb": cb,
        "runtime_major": major_runtime,
        "runtime_minor": minor_runtime,
        "metadata_rva": metadata_rva,
        "metadata_size": metadata_size,
        "flags": int(flags),
        "entry_point_token": int(entry_point_token),
    }


def read_compressed_uint(blob: bytes, pos: int) -> tuple[int, int] | None:
    """A compressed unsigned integer inside a byte string (II.23.2).

    Returns (value, bytes consumed), or None when the encoding is invalid
    or truncated.
    """
    if pos < 0 or pos >= len(blob):
        return None
    first = blob[pos]
    if first & 0x80 == 0:
        return first, 1
    if first & 0xC0 == 0x80:
        if pos + 2 > len(blob):
            return None
        return ((first & 0x3F) << 8) | blob[pos + 1], 2
    if first & 0xE0 == 0xC0:
        if pos + 4 > len(blob):
            return None
        return (
            ((first & 0x1F) << 24)
            | (blob[pos + 1] << 16)
            | (blob[pos + 2] << 8)
            | blob[pos + 3],
            4,
        )
    return None


class _Degradations:
    """Collects at-most-once named refusals for one metadata parse."""

    def __init__(self):
        self._items: list[str] = []

    def add(self, name: str) -> None:
        if name not in self._items:
            self._items.append(name)

    def sorted(self) -> list[str]:
        return sorted(self._items)


class _HeapReader:
    """Bounds-checked reads over one metadata heap (II.24.2.2-24.2.4).

    Every read validates its index against the heap size the stream header
    declared; refusals are recorded by name and returned as None so a bad
    index can never masquerade as an empty value (ground rule 14).
    """

    def __init__(self, data: bytes, offset: int, size: int, degr: _Degradations):
        self.data = data
        self.offset = offset
        self.size = size
        self.end = offset + size
        self.degr = degr

    def _in_bounds(self, index: int) -> bool:
        return 0 <= index < self.size and self.offset + index < self.end

    def string(self, index: int) -> str | None:
        """A NUL-terminated UTF-8 string from the #Strings heap."""
        if not self._in_bounds(index):
            self.degr.add("strings_index_out_of_range")
            return None
        start = self.offset + index
        limit = min(start + MAX_STRING_READ, self.end)
        nul = self.data.find(b"\x00", start, limit)
        if nul < 0:
            # No terminator inside the read window: either the entry is
            # genuinely unterminated or it is longer than the window. The
            # rest of the heap knows which — search it before naming the
            # refusal (ground rule 14: name what actually happened).
            if self.data.find(b"\x00", limit, self.end) >= 0:
                self.degr.add("strings_entry_truncated_by_cap")
                raw = self.data[start:limit]
            else:
                self.degr.add("strings_entry_unterminated")
                raw = self.data[start:limit]
        else:
            raw = self.data[start:nul]
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            self.degr.add("strings_entry_undecodable")
            return raw.decode("utf-8", errors="replace")

    def guid(self, index: int) -> bytes | None:
        """A 16-byte GUID from the #GUID heap (one-based index)."""
        if index <= 0:
            return None
        start = self.offset + (index - 1) * 16
        if start + 16 > self.end:
            self.degr.add("guid_index_out_of_range")
            return None
        return bytes(self.data[start:start + 16])

    def blob(self, index: int) -> bytes | None:
        """A compressed-length-prefixed blob from the #Blob heap (II.24.2.4)."""
        if index == 0:
            return None
        if not self._in_bounds(index):
            self.degr.add("blob_index_out_of_range")
            return None
        pos = self.offset + index
        first = self.data[pos]
        if first & 0x80 == 0:
            length, header = first, 1
        elif first & 0xC0 == 0x80:
            if pos + 2 > self.end:
                self.degr.add("blob_length_truncated")
                return None
            length = ((first & 0x3F) << 8) | self.data[pos + 1]
            header = 2
        else:
            if pos + 4 > self.end:
                self.degr.add("blob_length_truncated")
                return None
            length = (
                ((first & 0x1F) << 24)
                | (self.data[pos + 1] << 16)
                | (self.data[pos + 2] << 8)
                | self.data[pos + 3]
            )
            header = 4
        start = pos + header
        if length > MAX_BLOB_READ:
            self.degr.add("blob_length_exceeds_cap")
            return None
        if start + length > self.end:
            self.degr.add("blob_length_exceeds_heap")
            return None
        return bytes(self.data[start:start + length])

    def us_string_bytes(self, index: int) -> bytes | None:
        """Raw UTF-16LE payload of a #US entry (terminal flag byte stripped).

        Only structural reads happen this packet; the strings themselves
        feed the review engine in the managed-capability packet (W3.2).
        """
        if index == 0:
            return None
        if not self._in_bounds(index):
            self.degr.add("us_index_out_of_range")
            return None
        pos = self.offset + index
        first = self.data[pos]
        if first & 0x80 == 0:
            length, header = first, 1
        elif first & 0xC0 == 0x80:
            if pos + 2 > self.end:
                self.degr.add("us_length_truncated")
                return None
            length = ((first & 0x3F) << 8) | self.data[pos + 1]
            header = 2
        else:
            if pos + 4 > self.end:
                self.degr.add("us_length_truncated")
                return None
            length = (
                ((first & 0x1F) << 24)
                | (self.data[pos + 1] << 16)
                | (self.data[pos + 2] << 8)
                | self.data[pos + 3]
            )
            header = 4
        if length == 0:
            return b""
        start = pos + header
        if start + length > self.end:
            self.degr.add("us_length_exceeds_heap")
            return None
        # The compressed length includes one trailing flag byte.
        return bytes(self.data[start:start + length - 1])


def _read_streams(data: bytes, root_offset: int, region_size: int,
                  degr: _Degradations):
    """Walk the metadata root and its stream headers (II.24.2.1-24.2.2).

    ``region_size`` is what the CLI header declared for the whole metadata
    region; a stream that claims to lie outside it is refused by name, not
    clamped — the claim is the corruption signal. Stream offsets are
    relative to the metadata root. Returns (version_string, {name: (offset,
    size)}), or (None, {}) when the root itself is unusable.
    """
    if region_size < 20 or root_offset + 20 > len(data):
        degr.add("metadata_root_truncated")
        return None, {}
    signature = struct.unpack_from("<I", data, root_offset)[0]
    if signature != METADATA_SIGNATURE:
        degr.add("metadata_signature_invalid")
        return None, {}
    # Signature(4) major(2) minor(2) reserved(4) length(4), version area.
    version_area_len = struct.unpack_from("<I", data, root_offset + 12)[0]
    header_end = 16 + version_area_len + 4
    if version_area_len > MAX_VERSION_AREA_BYTES or header_end > region_size:
        degr.add("metadata_version_length_invalid")
        return None, {}
    version_raw = data[root_offset + 16:root_offset + 16 + version_area_len]
    version = version_raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    region_end = root_offset + region_size
    pos = root_offset + 16 + version_area_len
    _flags, stream_count = struct.unpack_from("<HH", data, pos)
    pos += 4
    if stream_count > MAX_STREAMS:
        degr.add("stream_count_capped")
        stream_count = MAX_STREAMS
    streams: dict[str, tuple[int, int]] = {}
    for _ in range(stream_count):
        if pos + 8 > region_end:
            degr.add("stream_headers_truncated")
            break
        offset, size = struct.unpack_from("<II", data, pos)
        pos += 8
        name_limit = min(pos + MAX_STREAM_NAME_LEN, len(data))
        nul = data.find(b"\x00", pos, name_limit)
        if nul < 0:
            degr.add("stream_name_unterminated")
            break
        name = data[pos:nul].decode("ascii", errors="replace")
        # Stream header names are padded to a 4-byte boundary.
        pos = nul + 1
        pos += (-(pos - root_offset)) % 4
        if offset > region_size or size > region_size - offset:
            degr.add(f"stream_out_of_range:{name}")
            continue
        streams[name] = (offset, size)
    return version, streams


def _column_width(column, row_counts, heapsizes):
    """Byte width of one schema column given the declared row counts."""
    kind = column[0]
    if kind == "u1" or kind == "pad":
        return 1
    if kind == "u2":
        return 2
    if kind == "u4":
        return 4
    if kind == "str":
        return 4 if heapsizes & 0x01 else 2
    if kind == "guid":
        return 4 if heapsizes & 0x02 else 2
    if kind == "blob":
        return 4 if heapsizes & 0x04 else 2
    if kind == "tbl":
        return 4 if row_counts.get(column[1], 0) > 0xFFFF else 2
    # Coded index: wide when the largest constituent table needs it to be.
    tables, tag_bits = CODED_INDEXES[column[1]]
    max_rows = max(
        (row_counts.get(t, 0) for t in tables if t is not None), default=0
    )
    return 4 if max_rows > (0xFFFF >> tag_bits) else 2


def _table_layout(row_counts: dict[int, int], heapsizes: int,
                  degr: _Degradations):
    """Compute per-table byte extents from the declared row counts.

    Returns ({table: (offset, row_size)}) with offsets relative to the start
    of the table rows. Tables are laid out in ascending id order; the first
    table with no schema (portable-PDB tables, 0x30+) is returned as
    ``first_unknown`` and nothing from it on is sized — the tables laid out
    before it stay readable.
    """
    layout: dict[int, tuple[int, int]] = {}
    pos = 0
    for table in sorted(row_counts):
        if table not in TABLE_SCHEMAS:
            degr.add(f"unknown_table_present:0x{table:02x}")
            return layout, table
        row_size = sum(
            _column_width(c, row_counts, heapsizes) for c in TABLE_SCHEMAS[table]
        )
        layout[table] = (pos, row_size)
        pos += row_counts[table] * row_size
    return layout, None


class _TableReader:
    """Row reads over a laid-out table stream, bounds-checked per row.

    Rows decode to a list of values aligned with TABLE_SCHEMAS[table]:
    fixed columns as ints, heap indexes as raw ints for the caller to
    resolve, coded indexes as (tag_table, rid) with tag_table None for the
    reserved slots.
    """

    def __init__(self, data: bytes, base: int, end: int,
                 layout: dict[int, tuple[int, int]],
                 row_counts: dict[int, int], heapsizes: int,
                 degr: _Degradations):
        self.data = data
        self.base = base
        self.end = end
        self.layout = layout
        self.row_counts = row_counts
        self.heapsizes = heapsizes
        self.degr = degr

    def row(self, table: int, rid: int) -> list | None:
        """Decode one row (1-based rid) of a table."""
        if table not in TABLE_SCHEMAS or table not in self.layout:
            return None
        rows = self.row_counts.get(table, 0)
        if rid < 1 or rid > rows:
            self.degr.add(f"row_index_out_of_range:0x{table:02x}")
            return None
        offset, row_size = self.layout[table]
        start = self.base + offset + (rid - 1) * row_size
        if start + row_size > self.end:
            self.degr.add(f"row_bytes_out_of_range:0x{table:02x}")
            return None
        values: list = []
        pos = start
        for column in TABLE_SCHEMAS[table]:
            width = _column_width(column, self.row_counts, self.heapsizes)
            if column[0] == "pad":
                values.append(None)
                pos += width
                continue
            raw = int.from_bytes(self.data[pos:pos + width], "little")
            if column[0] == "cod":
                tables, tag_bits = CODED_INDEXES[column[1]]
                tag = raw & ((1 << tag_bits) - 1)
                tag_table = tables[tag] if tag < len(tables) else None
                values.append((tag_table, raw >> tag_bits))
            else:
                values.append(raw)
            pos += width
        return values


def _declaring_typedef(reader: _TableReader, row_counts, method_rid: int):
    """The TypeDef row whose MethodList run covers ``method_rid``.

    TypeDef rows own contiguous MethodDef runs through their MethodList
    columns (the last TypeDef's run ends at the MethodDef table's end). With
    a MethodPtr table present (unsorted `#-` images), the run indexes
    MethodPtr rows that redirect to real MethodDef rows.
    """
    typedef_count = row_counts.get(TYPE_DEF, 0)
    if typedef_count == 0:
        return None
    method_count = row_counts.get(METHOD_DEF, 0)
    method_ptr_count = row_counts.get(METHOD_PTR, 0)
    for typedef_rid in range(1, typedef_count + 1):
        row = reader.row(TYPE_DEF, typedef_rid)
        if row is None:
            continue
        start = row[5]
        if typedef_rid < typedef_count:
            next_row = reader.row(TYPE_DEF, typedef_rid + 1)
            end = next_row[5] if next_row else method_count + 1
        else:
            end = method_count + 1
        if method_ptr_count:
            for ptr_rid in range(start, end):
                ptr_row = reader.row(METHOD_PTR, ptr_rid)
                if ptr_row is not None and ptr_row[0] == method_rid:
                    return row
        elif start <= method_rid < end:
            return row
    return None


def _resolve_entry_point_method(reader, row_counts, strings, method_rid: int):
    """(type_name, method_name) for a MethodDef rid, or (None, name/None).

    The type is the declaring TypeDef's namespace-qualified name.
    """
    method_name = None
    method_row = reader.row(METHOD_DEF, method_rid)
    if method_row is not None:
        method_name = strings.string(method_row[3]) if strings else None
    owner = _declaring_typedef(reader, row_counts, method_rid)
    if owner is None:
        return None, method_name
    type_name = strings.string(owner[1]) if strings else None
    type_ns = strings.string(owner[2]) if strings else None
    if type_name is None:
        return None, method_name
    return (f"{type_ns}.{type_name}" if type_ns else type_name), method_name


def parse_metadata_stream(
    data: bytes,
    root_offset: int = 0,
    region_size: int | None = None,
    cli_flags_value: int = 0,
    entry_point_token: int | None = None,
) -> dict:
    """Parse one metadata root region into the 03/A.1 block (pure bytes).

    ``data`` is the byte string holding the metadata region (usually a
    window read at the CLI header's metadata RVA); ``root_offset`` is where
    the BSJB root starts inside it; ``region_size`` is the size the CLI
    header declared for the region (default: data from root_offset to the
    end). All bounds are checked against ``len(data)``; every refusal lands
    in ``degradations`` by name.
    """
    degr = _Degradations()
    block: dict = {"parse_status": "parsed"}
    if region_size is None:
        region_size = len(data) - root_offset
    version, streams = _read_streams(data, root_offset, region_size, degr)
    if version is None:
        block["parse_status"] = "malformed"
        block["degradations"] = degr.sorted()
        return block
    block["runtime_version"] = version
    block["cli_flags"] = [
        name for bit, name in CLI_FLAG_NAMES if cli_flags_value & bit
    ]
    block["cli_flags_value"] = cli_flags_value

    def heap_reader(name: str) -> tuple | None:
        if name in streams:
            offset, size = streams[name]
            return root_offset + offset, size
        return None

    strings_heap = heap_reader("#Strings")
    guid_heap = heap_reader("#GUID")
    blob_heap = heap_reader("#Blob")
    us_heap = heap_reader("#US")
    strings = _HeapReader(data, *strings_heap, degr) if strings_heap else None
    guids = _HeapReader(data, *guid_heap, degr) if guid_heap else None
    blobs = _HeapReader(data, *blob_heap, degr) if blob_heap else None
    if not us_heap:
        # Every managed image ships a #US heap; a region without one is a
        # structural anomaly worth naming (the managed-capability packet
        # W3.2 reads its strings — this packet only requires its presence
        # and its stream bounds, which _read_streams checked).
        degr.add("us_heap_missing")
    if not strings_heap:
        degr.add("strings_heap_missing")
    if not guid_heap:
        degr.add("guid_heap_missing")
    if not blob_heap:
        degr.add("blob_heap_missing")

    tables_stream = streams.get("#~")
    if tables_stream is None and streams.get("#-") is not None:
        tables_stream = streams["#-"]
        block["table_stream"] = "#-"
    elif tables_stream is not None and streams.get("#-") is not None:
        degr.add("both_table_streams_present")
    if tables_stream is None:
        degr.add("tables_stream_missing")
        block["parse_status"] = "partial"
        block["degradations"] = degr.sorted()
        return block

    tables_offset = root_offset + tables_stream[0]
    tables_end = min(len(data), tables_offset + tables_stream[1])
    if tables_offset + 24 > tables_end:
        degr.add("tables_header_truncated")
        block["parse_status"] = "partial"
        block["degradations"] = degr.sorted()
        return block
    heapsizes = data[tables_offset + 6]
    valid_mask = int.from_bytes(data[tables_offset + 8:tables_offset + 16],
                                "little")
    pos = tables_offset + 24
    row_counts: dict[int, int] = {}
    for table in range(MAX_TABLES):
        if not valid_mask & (1 << table):
            continue
        if pos + 4 > tables_end:
            degr.add("row_count_array_truncated")
            break
        row_counts[table] = struct.unpack_from("<I", data, pos)[0]
        pos += 4

    layout, first_unknown = _table_layout(row_counts, heapsizes, degr)
    tables_dropped: set[int] = set()
    tables_partial = False
    if first_unknown is not None:
        # Tables from the unknown one on cannot be laid out; the tables
        # laid out before it stay readable, the rest are undeterminable.
        tables_dropped = {t for t in row_counts if t >= first_unknown}
        degr.add("tables_partial")
        tables_partial = True
    else:
        # The rows' true end: the largest table's (offset + rows * width).
        extent = pos + max(
            (
                layout[t][0] + layout[t][1] * row_counts.get(t, 0)
                for t in layout
            ),
            default=0,
        )
        if extent > tables_end:
            # Some declared rows lie outside the stream: the first table
            # whose rows overrun ends the readable region, and its count
            # (and every later table's) is a corrupt-header claim.
            degr.add("tables_exceed_stream")
            drop_from = None
            for t in sorted(layout):
                offset, row_size = layout[t]
                if pos + offset + row_size * row_counts.get(t, 0) > tables_end:
                    drop_from = t
                    break
            for t in sorted(layout):
                if drop_from is not None and t >= drop_from:
                    degr.add(f"table_unreadable:0x{t:02x}")
            if drop_from is not None:
                tables_dropped = {t for t in layout if t >= drop_from}
                row_counts = {
                    t: c for t, c in row_counts.items() if t not in tables_dropped
                }
                layout = {t: v for t, v in layout.items() if t not in tables_dropped}
            degr.add("tables_partial")
            tables_partial = True
        elif tables_end - extent > MAX_TABLE_STREAM_LEFTOVER:
            # The rows stop well short of the stream the writer sized for
            # them, so the widths blint computed are not the widths the
            # writer used and every row read under them is some other
            # table's bytes. The row counts stay (they come from the
            # header, not the layout); everything derived from a row is
            # withheld rather than reported as a value blint determined
            # (ground rule 11) — a fabricated assembly name is worse than
            # an absent one, and the SBOM would carry it.
            degr.add(f"tables_layout_short:{tables_end - extent}")
            layout = {}

    # Row content starts after the table-stream header and row-count array.
    reader = _TableReader(
        data, pos, tables_end, layout, row_counts, heapsizes, degr,
    )

    def string_at(index: int) -> str | None:
        return strings.string(index) if strings else None

    def blob_at(index: int) -> bytes | None:
        return blobs.blob(index) if blobs else None

    # --- counts: declared rows for tables verifiably inside the stream ----
    # Real streams leave zero-row tables out of the Valid mask, so a mask
    # bit that is simply unset means zero rows (the reader looked). Only a
    # table the overrun logic dropped, or a mask that was never read, is
    # undeterminable — its key stays absent (rule 14).
    counts: dict = {}
    for table, key in (
        (TYPE_DEF, "typedef"), (METHOD_DEF, "methoddef"), (FIELD, "field"),
        (TYPE_REF, "typeref"), (MEMBER_REF, "memberref"),
        (ASSEMBLY_REF, "assembly_ref"), (MODULE_REF, "module_ref"),
        (IMPL_MAP, "implmap"), (ASSEMBLY, "assembly"),
    ):
        if table in tables_dropped or (tables_partial and table not in row_counts):
            continue
        counts[key] = row_counts.get(table, 0)
    if counts:
        block["counts"] = counts

    # --- module: MVID -------------------------------------------------------
    mvid: str | None = None
    if MODULE in row_counts and row_counts[MODULE] >= 1 and guids:
        module_row = reader.row(MODULE, 1)
        if module_row is not None:
            mvid_raw = guids.guid(module_row[2])
            rendered = format_guid(mvid_raw) if mvid_raw else None
            if rendered:
                mvid = rendered
            else:
                degr.add("mvid_unreadable")

    # --- assembly identity ----------------------------------------------------
    if ASSEMBLY in row_counts and row_counts[ASSEMBLY] >= 1:
        asm_row = reader.row(ASSEMBLY, 1)
        if asm_row is not None:
            # Columns: HashAlgId, Major, Minor, Build, Revision, Flags,
            # PublicKey blob, Name str, Culture str (II.22.2).
            name = string_at(asm_row[7])
            culture = string_at(asm_row[8])
            token = public_key_token(blob_at(asm_row[6]))
            assembly: dict = {}
            if name is not None:
                assembly["name"] = name
            else:
                degr.add("assembly_name_unreadable")
            assembly["version"] = (
                f"{asm_row[1]}.{asm_row[2]}.{asm_row[3]}.{asm_row[4]}"
            )
            assembly["culture"] = culture or "neutral"
            if token:
                assembly["public_key_token"] = token
            hash_alg_id = asm_row[0]
            assembly["hash_algorithm"] = HASH_ALGORITHM_NAMES.get(
                hash_alg_id, f"UNKNOWN(0x{hash_alg_id:04x})"
            )
            assembly["hash_algorithm_id"] = hash_alg_id
            if mvid:
                assembly["mvid"] = mvid
            block["assembly"] = assembly
    # An Assembly table with zero rows is a netmodule; the identity block
    # stays absent because there is no assembly (rule 14).

    # --- assembly refs ----------------------------------------------------------
    if ASSEMBLY_REF in row_counts and row_counts[ASSEMBLY_REF] > 0:
        total = row_counts[ASSEMBLY_REF]
        listed = min(total, MAX_LISTED_ASSEMBLY_REFS)
        if listed < total:
            degr.add("assembly_refs_listed_capped")
        refs = []
        for rid in range(1, listed + 1):
            row = reader.row(ASSEMBLY_REF, rid)
            if row is None:
                continue
            # Columns: Major, Minor, Build, Revision, Flags,
            # PublicKeyOrToken blob, Name str, Culture str, HashValue blob.
            name = string_at(row[6])
            if name is None:
                degr.add("assembly_ref_name_unreadable")
                continue
            culture = string_at(row[7])
            ref: dict = {
                "name": name,
                "version": f"{row[0]}.{row[1]}.{row[2]}.{row[3]}",
                "culture": culture or "neutral",
            }
            token = public_key_token(blob_at(row[5]))
            if token:
                ref["public_key_token"] = token
            refs.append(ref)
        if refs:
            block["assembly_refs"] = refs

    # --- module refs ------------------------------------------------------------
    if MODULE_REF in row_counts and row_counts[MODULE_REF] > 0:
        total = row_counts[MODULE_REF]
        listed = min(total, MAX_LISTED_MODULE_REFS)
        if listed < total:
            degr.add("module_refs_listed_capped")
        names = []
        for rid in range(1, listed + 1):
            row = reader.row(MODULE_REF, rid)
            if row is None:
                continue
            name = string_at(row[0])
            if name is None:
                degr.add("module_ref_name_unreadable")
                continue
            names.append(name)
        if names:
            block["module_refs"] = names

    # --- P/Invoke surface ---------------------------------------------------------
    if IMPL_MAP in row_counts and row_counts[IMPL_MAP] > 0:
        total = row_counts[IMPL_MAP]
        listed = min(total, MAX_LISTED_PINVOKE)
        if listed < total:
            degr.add("pinvoke_listed_capped")
        entries = []
        for rid in range(1, listed + 1):
            row = reader.row(IMPL_MAP, rid)
            if row is None:
                continue
            # Columns: MappingFlags, MemberForwarded coded (Field, MethodDef),
            # ImportName str, ImportScope tbl(ModuleRef).
            entry: dict = {}
            import_name = string_at(row[2])
            if import_name is None:
                degr.add("pinvoke_import_name_unreadable")
                continue
            if import_name == "":
                # Mixed-mode C++/CLI images emit ImplMap rows for native
                # (IJW) methods with an empty ImportName and an empty
                # ModuleRef scope. The Windows oracle treats an empty
                # import name as no P/Invoke entry (SRM skips
                # Name.IsNil rows); the rows still count in
                # ``counts.implmap``.
                continue
            member_tag, member_rid = row[1]
            entry["entry_point"] = import_name
            if member_tag == METHOD_DEF and METHOD_DEF in row_counts:
                method_row = reader.row(METHOD_DEF, member_rid)
                if method_row is not None:
                    method_name = string_at(method_row[3])
                    if method_name is not None:
                        entry["method"] = method_name
            elif member_tag not in (FIELD, METHOD_DEF):
                degr.add("pinvoke_member_forwarded_unresolved")
                continue
            scope_rid = row[3]
            if scope_rid and MODULE_REF in row_counts:
                scope_row = reader.row(MODULE_REF, scope_rid)
                if scope_row is not None:
                    module_name = string_at(scope_row[0])
                    if module_name is not None:
                        entry["module"] = module_name
            if entry:
                entries.append(entry)
        if entries:
            block["pinvoke"] = entries

    # --- target framework attribute ----------------------------------------------
    if CUSTOM_ATTRIBUTE in row_counts and row_counts[CUSTOM_ATTRIBUTE] > 0:
        target_frameworks = []
        for rid in range(1, row_counts[CUSTOM_ATTRIBUTE] + 1):
            row = reader.row(CUSTOM_ATTRIBUTE, rid)
            if row is None:
                continue
            # Columns: Parent coded, Type coded (CustomAttributeType), Value.
            type_tag_table, type_rid = row[1]
            if type_tag_table != MEMBER_REF or MEMBER_REF not in layout:
                continue
            member_row = reader.row(MEMBER_REF, type_rid)
            if member_row is None:
                continue
            class_tag_table, class_rid = member_row[0]
            if class_tag_table != TYPE_REF or TYPE_REF not in layout:
                continue
            type_row = reader.row(TYPE_REF, class_rid)
            if type_row is None:
                continue
            type_name = string_at(type_row[1])
            type_ns = string_at(type_row[2])
            if type_name != "TargetFrameworkAttribute":
                continue
            if type_ns != "System.Runtime.Versioning":
                continue
            value_blob = blob_at(row[2])
            if value_blob is None or len(value_blob) < 4:
                degr.add("target_framework_value_invalid")
                continue
            # Custom attribute blob: prolog 0x0001, then the ctor's fixed
            # args. TargetFrameworkAttribute(string) is a SerString:
            # compressed length + UTF-8 bytes (II.23.3).
            if value_blob[0] != 0x01 or value_blob[1] != 0x00:
                continue
            decoded = read_compressed_uint(value_blob, 2)
            if decoded is None:
                degr.add("target_framework_value_invalid")
                continue
            length, consumed = decoded
            pos = 2 + consumed
            if pos + length > len(value_blob):
                degr.add("target_framework_value_invalid")
                continue
            target_frameworks.append(
                value_blob[pos:pos + length].decode("utf-8", errors="replace")
            )
            if len(target_frameworks) >= MAX_TARGET_FRAMEWORK_VALUES:
                degr.add("target_framework_values_capped")
                break
        distinct = sorted(set(target_frameworks))
        if len(distinct) > 1:
            degr.add("multiple_target_framework_values")
        if distinct:
            block["target_framework"] = distinct[0]

    # --- entry point ----------------------------------------------------------------
    if entry_point_token is not None and entry_point_token:
        table_id = (entry_point_token >> 24) & 0xFF
        rid = entry_point_token & 0x00FFFFFF
        entry: dict = {"token": f"0x{entry_point_token:08x}"}
        if cli_flags_value & 0x00000010:  # COMIMAGE_FLAGS_NATIVE_ENTRYPOINT
            # The token field is an RVA into native code, not a metadata
            # token (mixed-mode C++/CLI images).
            entry["kind"] = "native"
        elif table_id == METHOD_DEF and METHOD_DEF in row_counts:
            type_name, method_name = _resolve_entry_point_method(
                reader, row_counts, strings, rid
            )
            if method_name is not None:
                entry["method"] = method_name
            if type_name is not None:
                entry["type"] = type_name
            if type_name is None or method_name is None:
                degr.add("entry_point_unresolved")
        elif table_id == METHOD_SPEC and METHOD_SPEC in row_counts:
            spec_row = reader.row(METHOD_SPEC, rid)
            if spec_row is not None:
                spec_tag, spec_rid = spec_row[0]
                if spec_tag == METHOD_DEF:
                    type_name, method_name = _resolve_entry_point_method(
                        reader, row_counts, strings, spec_rid
                    )
                    if method_name is not None:
                        entry["method"] = method_name
                    if type_name is not None:
                        entry["type"] = type_name
                    if type_name is None or method_name is None:
                        degr.add("entry_point_unresolved")
                else:
                    degr.add("entry_point_unresolved")
            else:
                degr.add("entry_point_unresolved")
        else:
            degr.add("entry_point_unresolved")
        block["entry_point"] = entry

    block["degradations"] = degr.sorted()
    if block["parse_status"] == "parsed" and block["degradations"]:
        block["parse_status"] = "partial"
    return block


def parse_pe_dotnet(parsed_obj, exe_file: str) -> dict | None:
    """Build the dotnet block for one PE file, or None when not managed.

    Locates the CLI header through data directory 14 (the directory the
    native path already reads), maps the header and the metadata region
    into the file through the section table with bounded reads, and hands
    the region to ``parse_metadata_stream``.
    """
    cli = find_cli_directory(parsed_obj)
    if cli is None:
        return None
    cli_rva, cli_size = cli
    cli_offset = rva_to_offset(parsed_obj.sections, cli_rva)
    if cli_offset < 0:
        return {
            "parse_status": "malformed",
            "degradations": ["cli_header_rva_unmapped"],
        }
    try:
        with open(exe_file, "rb") as handle:
            handle.seek(cli_offset)
            window = handle.read(min(max(cli_size, 24), 4096))
            header = read_cli_header(window)
            if header is None or header["metadata_rva"] <= 0:
                return {
                    "parse_status": "malformed",
                    "degradations": ["cli_header_unreadable"],
                }
            md_offset = rva_to_offset(parsed_obj.sections, header["metadata_rva"])
            if md_offset < 0:
                return {
                    "parse_status": "malformed",
                    "degradations": ["metadata_rva_unmapped"],
                }
            md_size = header["metadata_size"]
            file_size = handle.seek(0, 2)
            if md_offset + md_size > file_size:
                # A region past EOF is clipped so the reads stay in-file;
                # the streams validate themselves against what is really
                # there and name the shortfall.
                md_size = max(0, file_size - md_offset)
            if md_size <= 0:
                return {
                    "parse_status": "malformed",
                    "degradations": ["metadata_size_invalid"],
                }
            handle.seek(md_offset)
            metadata = handle.read(md_size)
    except OSError:
        return {
            "parse_status": "malformed",
            "degradations": ["file_unreadable"],
        }
    return parse_metadata_stream(
        metadata,
        root_offset=0,
        region_size=len(metadata),
        cli_flags_value=header["flags"],
        entry_point_token=header["entry_point_token"],
    )
