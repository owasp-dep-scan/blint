# SPDX-License-Identifier: Apache-2.0
"""PE debug directory, CodeView/PDB and rich header decoding (W1.1, 01/A.4-A.5).

The debug directory answers "who built this and how do I find its symbols":
per-entry facts, the CodeView PDB lookup key (GUID + age + path), the
``/Brepro`` marker that is the real answer to "is this a reproducible build",
and the extended DLL characteristics. The rich header answers "with which
Microsoft tools": its comp.id records name the exact compiler/linker drops,
and its checksum detects a tampered or spoofed header.

Ground rule 28 applies throughout: entry types and comp.id products come
from blint-owned tables keyed by numeric values (pe_constants, the generated
``blint/data/pe_rich_compids.yml``), never from a dependency's rendered
enums. A rich header that fails its checksum is a forensic signal reported
as ``checksum_valid: false``, not a parse error.
"""

import contextlib
import importlib.resources
import struct

import yaml

from blint.lib.pe_constants import (
    EX_DLL_CHARACTERISTICS,
    IMAGE_DEBUG_TYPE_CODEVIEW,
    IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS,
    IMAGE_DEBUG_TYPE_POGO,
    IMAGE_DEBUG_TYPE_REPRO,
    IMAGE_DEBUG_TYPE_VC_FEATURE,
    debug_type_name,
    decode_flag_bits,
)
from blint.logger import LOG

# The rich header lives in the DOS stub, which is tiny in every real image
# (e_lfanew is typically 0x80-0x400). The scan window is capped well below
# the 64 KiB overlay windows: a hostile e_lfanew must not drive a read.
RICH_SCAN_LIMIT = 0x4000
# Bounded read for debug payloads: a CodeView entry's payload is the
# signature, the GUID, the age and a path — 4 KiB covers every real PDB path
# many times over, so anything longer is treated as hostile.
DEBUG_PAYLOAD_MAX_READ = 0x1000
# A debug directory with thousands of entries is a hostile input, not an
# image. The extra entries are counted, not decoded.
MAX_DEBUG_ENTRIES = 64
MAX_POGO_SECTIONS = 256
MAX_RICH_ENTRIES = 256

# LIEF renders the CodeView revision as an enum; blint's own names for the
# two on-disk layouts it covers, keyed by that enum's last name segment.
CODEVIEW_SIGNATURES = {"PDB_70": "RSDS", "PDB_20": "NB10"}

_COMPID_TABLES_CACHE: dict | None = None


def _compid_tables() -> dict:
    """Load (once) the generated comp.id tables."""
    global _COMPID_TABLES_CACHE
    if _COMPID_TABLES_CACHE is None:
        try:
            with importlib.resources.files("blint.data").joinpath(
                "pe_rich_compids.yml"
            ).open("r", encoding="utf-8") as handle:
                _COMPID_TABLES_CACHE = yaml.safe_load(handle) or {}
        except (OSError, yaml.YAMLError) as exc:
            LOG.debug(f"Unable to load pe_rich_compids.yml: {exc}")
            _COMPID_TABLES_CACHE = {}
    return _COMPID_TABLES_CACHE


def decode_comp_id(product_id: int, build_id: int) -> dict:
    """Name one comp.id record through the generated tables.

    The full 32-bit ``(product_id << 16) | build_id`` value is looked up
    first (ancient build numbers are reused across releases, so the pair is
    the only safe join); an unknown pair still names the tool from the
    16-bit product id, and a wholly unknown product renders UNKNOWN(id).
    """
    tables = _compid_tables()
    comp_ids = tables.get("comp_ids") or {}
    # PyYAML resolves the tables' 0x hex keys to ints; look them up as ints.
    row = comp_ids.get((product_id << 16) | build_id)
    label = ""
    tool = None
    if row:
        row_tool, _, label = str(row).partition("|")
        # "---" marks a row with no product recorded; keep its label but
        # still name the tool from the product id.
        tool = row_tool if row_tool and row_tool != "---" else None
    if tool is None:
        product_ids = tables.get("product_ids") or {}
        tool = product_ids.get(product_id)
    if tool:
        return {"product_id": product_id, "tool": str(tool), "label": label}
    return {"product_id": product_id, "tool": f"UNKNOWN({product_id})", "label": label}


def pdb_filename(pdb_path: str) -> str:
    """The path's last segment, split on both Windows and POSIX separators."""
    return pdb_path.replace("\\", "/").rsplit("/", maxsplit=1)[-1]


def format_pdb_guid(payload: bytes) -> str | None:
    """Render a CodeView RSDS GUID in the canonical dumpbin form.

    The first three fields are little-endian; the rest is raw bytes, so
    ``7F0F7557-29F5-47E3-89CC-E15613B51A64`` is how dumpbin prints it.
    """
    if len(payload) < 20:
        return None
    guid = payload[4:20]
    d1, d2, d3 = struct.unpack_from("<IHH", guid, 0)
    return (
        f"{d1:08X}-{d2:04X}-{d3:04X}-"
        f"{guid[8:10].hex().upper()}-{guid[10:16].hex().upper()}"
    )


def parse_codeview_payload(payload: bytes) -> dict:
    """Decode one CodeView debug entry payload (RSDS or NB10 layout).

    RSDS (PDB 7.0): signature, 16-byte GUID, 4-byte age, path.
    NB10 (PDB 2.0): signature, 4-byte offset, 4-byte timestamp, 4-byte age,
    path — no GUID. The path is NUL-terminated; anything after it is
    ignored. Unknown signatures keep their name and decode nothing.
    """
    info: dict = {"signature": None, "guid": None, "age": None, "pdb_path": None}
    if len(payload) < 8:
        return info
    # A truncated payload decodes to whatever it carries and stops: the debug
    # directory is attacker-controlled, and an entry whose SizeOfData is short
    # of its own layout must not raise through the caller's parse.
    path_bytes = b""
    signature = payload[:4]
    info["signature"] = signature.decode("ascii", errors="replace")
    if signature == b"RSDS":
        if guid := format_pdb_guid(payload):
            info["guid"] = guid
        if len(payload) >= 28:
            info["age"] = int.from_bytes(payload[20:24], "little")
            path_bytes = payload[24:]
    elif signature == b"NB10":
        if len(payload) >= 20:
            info["age"] = int.from_bytes(payload[12:16], "little")
            path_bytes = payload[16:]
    else:
        return info
    path = path_bytes.split(b"\x00", 1)[0]
    if not path:
        # Either a truncated payload or a genuinely empty path: both say
        # nothing, and ``pdb_path`` stays None so the caller's fallback runs.
        return info
    try:
        info["pdb_path"] = path.decode("utf-8")
    except UnicodeDecodeError:
        info["pdb_path"] = path.decode("latin-1", errors="replace")
    return info


def _entry_payload(entry, exe_file: str) -> bytes:
    """Read one debug entry's payload, falling back to the file.

    LIEF reads payloads through the mapped section; an entry whose raw data
    pointer lands outside the mapped sections (the EX_DLLCHARACTERISTICS
    case W0.3 met) yields nothing, so the raw file offset is used instead —
    capped so a hostile SizeOfData cannot drive a large read.
    """
    try:
        payload = bytes(entry.payload or b"")
    except (AttributeError, TypeError, ValueError):
        payload = b""
    if len(payload) >= 4:
        return payload
    try:
        file_offset = int(entry.pointerto_rawdata)
        size = min(int(entry.sizeof_data), DEBUG_PAYLOAD_MAX_READ)
        if file_offset <= 0 or size <= 0:
            return payload
        with open(exe_file, "rb") as handle:
            handle.seek(file_offset)
            data = handle.read(size)
        return data if len(data) > len(payload) else payload
    except (OSError, AttributeError, TypeError, ValueError):
        return payload


def parse_pe_debug(parsed_obj, exe_file: str) -> dict:
    """Build the ``debug`` block for one PE image (01/A.5).

    Every key is computed from the named source: ``entries`` from the debug
    directory itself, ``codeview`` from the first CODEVIEW payload,
    ``repro`` from a REPRO entry (present and absent both computed when the
    directory exists), ``vc_feature`` and ``pogo`` and
    ``ex_dllcharacteristics`` from their typed payloads. An image with no
    debug directory reports nothing — for security_properties that absence
    is a declared gap, never a thin false.
    """
    block: dict = {}
    try:
        if not parsed_obj.has_debug:
            return block
        entries = list(parsed_obj.debug)
    except (AttributeError, TypeError, ValueError) as exc:
        LOG.debug(f"Unable to enumerate PE debug directory for {exe_file}: {exc}")
        return block
    if not entries:
        return block

    entry_rows = []
    codeview: dict | None = None
    repro_hash = None
    vc_feature: dict | None = None
    pogo_sections: list[str] | None = None
    pogo_signature = None
    ex_payload = b""
    truncated = len(entries) > MAX_DEBUG_ENTRIES
    for entry in entries[:MAX_DEBUG_ENTRIES]:
        with contextlib.suppress(AttributeError, TypeError, ValueError):
            type_value = int(entry.type.value)
            row = {
                "type": debug_type_name(type_value),
                "type_value": type_value,
                "timestamp": int(entry.timestamp),
                "size": int(entry.sizeof_data),
            }
            for src, dst in (
                ("addressof_rawdata", "addressof_rawdata"),
                ("pointerto_rawdata", "pointerto_rawdata"),
                ("major_version", "major_version"),
                ("minor_version", "minor_version"),
            ):
                with contextlib.suppress(AttributeError, TypeError, ValueError):
                    row[dst] = int(getattr(entry, src))
            entry_rows.append(row)

            payload = _entry_payload(entry, exe_file)
            if type_value == IMAGE_DEBUG_TYPE_CODEVIEW and codeview is None:
                codeview = parse_codeview_payload(payload)
                if not codeview.get("pdb_path"):
                    # Payload read fell short (unmapped or hostile entry):
                    # fall back to LIEF's filename, and name the signature
                    # from the entry's own revision marker, not a guess.
                    lief_name = getattr(entry, "filename", None)
                    if isinstance(lief_name, str) and lief_name.strip():
                        codeview["pdb_path"] = lief_name.strip()
                        rendered = str(getattr(entry, "cv_signature", "")).rsplit(
                            ".", maxsplit=1
                        )[-1]
                        codeview["signature"] = CODEVIEW_SIGNATURES.get(
                            rendered, rendered
                        )
            elif type_value == IMAGE_DEBUG_TYPE_REPRO and repro_hash is None:
                # /Brepro records the image hash as a 4-byte length followed
                # by that many hash bytes (dumpbin prints the hash only);
                # fall back to a bare 16-byte hash for lengthless payloads.
                if len(payload) >= 20:
                    claimed = int.from_bytes(payload[:4], "little")
                    if claimed and 4 + claimed <= len(payload):
                        repro_hash = payload[4 : 4 + claimed].hex()
                if repro_hash is None and len(payload) >= 16:
                    repro_hash = payload[:16].hex()
            elif type_value == IMAGE_DEBUG_TYPE_VC_FEATURE and vc_feature is None:
                if len(payload) >= 4:
                    vc_feature = {
                        "c_cpp": getattr(entry, "c_cpp", None),
                        "gs": getattr(entry, "gs", None),
                        "guards": getattr(entry, "guards", None),
                        "sdl": getattr(entry, "sdl", None),
                        "pre_vcpp": getattr(entry, "pre_vcpp", None),
                    }
            elif type_value == IMAGE_DEBUG_TYPE_POGO and pogo_sections is None:
                pogo_signature = str(getattr(entry, "signature", "")).rsplit(
                    ".", maxsplit=1
                )[-1]
                pogo_sections = []
                with contextlib.suppress(AttributeError, TypeError, ValueError):
                    for pogo_entry in entry.entries:
                        name = getattr(pogo_entry, "name", None)
                        if name:
                            pogo_sections.append(name)
            elif type_value == IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS and not ex_payload:
                if len(payload) >= 4:
                    ex_payload = payload[:4]

    block["entries"] = entry_rows
    if truncated:
        block["entries_truncated"] = True
    if codeview:
        if codeview.get("pdb_path"):
            codeview["pdb_filename"] = pdb_filename(codeview["pdb_path"])
        block["codeview"] = codeview
    # The directory was read and said no: a computed False, not a gap.
    block["repro"] = {"present": repro_hash is not None}
    if repro_hash:
        block["repro"]["hash"] = repro_hash
    if vc_feature:
        block["vc_feature"] = vc_feature
    if pogo_sections is not None:
        block["pogo"] = {"signature": pogo_signature}
        block["pogo"]["sections"] = sorted(pogo_sections[:MAX_POGO_SECTIONS])
        if len(pogo_sections) > MAX_POGO_SECTIONS:
            block["pogo"]["sections_truncated"] = True
            block["pogo"]["sections_total"] = len(pogo_sections)
    if ex_payload:
        value = int.from_bytes(ex_payload, "little")
        block["ex_dllcharacteristics"] = decode_flag_bits(value, EX_DLL_CHARACTERISTICS)
    return block


def _rol32(value: int, num: int) -> int:
    num %= 32
    return ((value << num) & 0xFFFFFFFF) | (value >> (32 - num))


def compute_rich_checksum(data: bytes, start_index: int, entries: list[tuple[int, int]]) -> int:
    """Recompute the Rich header checksum (the XOR key) the way link.exe does.

    Three parts, all modulo 2^32 (algorithm per the RichHeaderResearch
    RichPE tooling, validated against real MSVC images): the offset of the
    header start, a per-byte rotated sum of everything before it with the
    e_lfanew bytes zeroed (the linker rewrites those last), and a per-entry
    ``rol(comp.id, count & 0x1F)`` sum.
    """
    checksum = start_index
    for i in range(start_index):
        byte = data[i] if not 0x3C <= i <= 0x3F else 0
        checksum += _rol32(byte, i)
    for comp_id, count in entries:
        checksum += _rol32(comp_id, count & 0x1F)
    return checksum & 0xFFFFFFFF


def decode_rich_header(exe_file: str) -> dict | None:
    """Decode and validate the rich header of a PE file (01/A.4).

    Reads at most the first ``RICH_SCAN_LIMIT`` bytes. Returns None when the
    file is not a PE with a rich header; a header whose checksum does not
    validate is still decoded, with ``checksum_valid: false`` — a mismatched
    checksum is a repacking/tampering signal, not a parse error.
    """
    try:
        with open(exe_file, "rb") as handle:
            data = handle.read(RICH_SCAN_LIMIT)
    except OSError as exc:
        LOG.debug(f"Unable to read {exe_file} for the rich header: {exc}")
        return None
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    rich_marker = data.find(b"Rich", 0x40)
    if rich_marker == -1 or rich_marker + 8 > len(data):
        return None
    key = int.from_bytes(data[rich_marker + 4 : rich_marker + 8], "little")
    if not key:
        return None
    # The three padding DWORDs after DanS store the checksum (== the XOR
    # key) in the clear, which locates the header without a reverse scan.
    start_marker = struct.pack("<IIII", 0x536E6144 ^ key, key, key, key)
    start_index = data.find(start_marker, 0x40, rich_marker)
    if start_index == -1:
        return None
    entries: list[tuple[int, int]] = []
    truncated = False
    offset = start_index + 16
    while offset + 8 <= rich_marker:
        comp_id = int.from_bytes(data[offset : offset + 4], "little") ^ key
        count = int.from_bytes(data[offset + 4 : offset + 8], "little") ^ key
        entries.append((comp_id, count))
        offset += 8
        if len(entries) >= MAX_RICH_ENTRIES:
            truncated = True
            break
    checksum_valid = not truncated and compute_rich_checksum(
        data, start_index, entries
    ) == key
    decoded = []
    for comp_id, count in entries:
        row = decode_comp_id(comp_id >> 16, comp_id & 0xFFFF)
        row["build_id"] = comp_id & 0xFFFF
        row["count"] = count
        decoded.append(row)
    block = {
        "key": hex(key),
        "checksum_valid": checksum_valid,
        "entries": [
            {"id": comp_id >> 16, "build_id": comp_id & 0xFFFF, "count": count}
            for comp_id, count in entries
        ],
        "decoded": decoded,
        "toolchain": _rich_toolchain(decoded),
    }
    if truncated:
        block["entries_truncated"] = True
    return block


def _rich_toolchain(decoded: list[dict]) -> dict:
    """Derive the toolchain contribution from decoded comp.id records.

    The linker record carries the exact MSVC toolset (its build number is
    the cl/link build); ``mixed_toolchain`` flags objects from a different
    drop than the linker — common with vendored static libraries, and a
    tamper tell when the optional header's linker version disagrees with the
    record. The build-0 imports record is present in nearly every image and
    never counts as a second toolchain.
    """
    toolchain: dict = {}
    linker_rows = [row for row in decoded if row["tool"] == "LNK"]
    if linker_rows:
        linker = linker_rows[0]
        if linker.get("label"):
            toolchain["linker_label"] = linker["label"]
        toolchain["linker_build_id"] = linker["build_id"]
    builds = sorted({row["build_id"] for row in decoded if row["build_id"]})
    if builds:
        toolchain["comp_id_builds"] = builds
        toolchain["mixed_toolchain"] = len(builds) > 1
    return toolchain
