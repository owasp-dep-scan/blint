"""Office container and indicator analyzer (W4.4).

The scoping decision (03/C): blint is an Office *container and indicator*
analyzer, not a VBA emulator. Structure, macros and relationships are
extracted and fed to the existing rule engine; deobfuscation beyond the
format's own compression stays with oletools, which already does it.

Families:

- **OOXML** (``.docx``/``.docm``/``.xlsx``/``.xlsm``/``.pptx``/``.pptm``):
  the relationship graph with **external relationships** called out (remote
  template injection, linked OLE objects — the highest-signal Office
  indicator there is), ``vbaProject.bin`` routed through the W4.2 CFBF
  reader, macro module source via the MS-OVBA decompressor, embedded
  objects, ``printerSettings``/ActiveX stream-smuggling spots, DDE field
  codes in the main part, and macro signatures.
- **Legacy** (``.doc``/``.xls``/``.ppt`` through the CFBF reader): the VBA
  storage (``Macros/VBA``/``_VBA_PROJECT_CUR``), ``PROJECT`` stream
  references, Ole10Native packages, Excel 4.0 (XLM) macro-sheet detection
  from the BIFF workbook stream, OLE embedded objects.
- **.msg/.oft** through the CFBF reader: attachments extracted so they
  become inputs themselves (recursion bounded by the container depth).
- **RTF**: detection plus ``objdata``/``objupdate`` OLE object extraction —
  no full parser, stated.

Findings, not verdicts (ground rule 34): the metadata says what a document
contains and references, never whether it is "malicious".

Bounds (ground rules 30/33): OOXML walks through the W4.1 zip framework
caps; VBA module decompression is capped (``MAX_VBA_MODULE_BYTES``); the
number of relationship rows and macro modules listed is capped while the
counts stay exact. No rule reads the capped listings.
"""

# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
# SPDX-License-Identifier: Apache-2.0

import os
import re
import struct
import zipfile

from blint.lib.cfbf import CfbfError, CfbfReader, is_cfbf_bytes, parse_cfbf
from blint.lib.container import ContainerLimits, read_zip_member_bounded, walk_zip_members

# Measured caps: benign generated documents and the corpus reference
# documents run far below these; hostile fixtures exceed them by name.
OFFICE_LIMITS = ContainerLimits(
    max_members=2048,
    max_total_uncompressed=256 * 1024 * 1024,
    max_member_size=64 * 1024 * 1024,
    max_member_depth=16,
    max_member_compression_ratio=512,
)
MAX_RELATIONSHIPS_LISTED = 2048
MAX_VBA_MODULES_LISTED = 256
MAX_VBA_MODULE_BYTES = 4 * 1024 * 1024
MAX_LISTED_ATTACHMENTS = 256
MAX_LISTED_OLE_OBJECTS = 256
MAX_MSG_ATTACHMENT_BYTES = 64 * 1024 * 1024
MAX_RTF_OBJECT_BYTES = 64 * 1024 * 1024
MAX_RTF_SCAN_BYTES = 32 * 1024 * 1024
MAX_BIFF_WALK_RECORDS = 200000

OOXML_EXTENSIONS = (".docx", ".docm", ".dotm", ".xlsx", ".xlsm", ".xltm", ".pptx", ".pptm", ".potm")
LEGACY_OFFICE_EXTENSIONS = (".doc", ".xls", ".ppt")
MSG_EXTENSIONS = (".msg", ".oft")
RTF_EXTENSIONS = (".rtf",)

# Relationship types worth naming individually (external-target classes).
REL_REMOTE_TEMPLATE = "attachedTemplate"
REL_OLE_OBJECT = "oleObject"

_DDE_FIELD_RE = re.compile(rb"DDEAUTO|DDE\s", re.IGNORECASE)


def is_ooxml_file(path: str) -> bool:
    return isinstance(path, str) and path.lower().endswith(OOXML_EXTENSIONS)


def is_legacy_office_file(path: str) -> bool:
    return isinstance(path, str) and path.lower().endswith(LEGACY_OFFICE_EXTENSIONS)


def is_msg_file(path: str) -> bool:
    return isinstance(path, str) and path.lower().endswith(MSG_EXTENSIONS)


def is_rtf_file(path: str) -> bool:
    return isinstance(path, str) and path.lower().endswith(RTF_EXTENSIONS)


# ---------------------------------------------------------------------------
# MS-OVBA compressed-container decompression
# ---------------------------------------------------------------------------

def decompress_vba(data: bytes, cap: int = MAX_VBA_MODULE_BYTES) -> bytes | None:
    """Decompress an MS-OVBA compressed container (``VBA/dir`` and modules).

    Implements the documented chunk algorithm (MS-OVBA 2.4.1): per 4096-byte
    chunk, a flag byte per 8 tokens, and copy tokens whose bit layout
    depends on the bytes decompressed so far. Returns None on a malformed
    container or when the cap is exceeded — the caller names the refusal.
    """
    if not data or data[0] != 0x01:
        return None
    pos = 1
    out = bytearray()
    while pos < len(data):
        if pos + 2 > len(data):
            break
        (header,) = struct.unpack("<H", data[pos : pos + 2])
        pos += 2
        chunk_size = (header & 0x0FFF) + 3
        chunk_compressed = bool(header & 0x8000)
        if (header >> 11) & 0x07 != 0x03:
            return None  # signature 0b011 required
        chunk_end = min(pos + chunk_size - 2, len(data))
        if not chunk_compressed:
            out += data[pos : pos + min(4096, chunk_end - pos)]
            pos = chunk_end
            continue
        chunk_start_out = len(out)
        while pos < chunk_end:
            if len(out) - chunk_start_out >= 4096:
                break
            flag_byte = data[pos]
            pos += 1
            for bit in range(8):
                if pos >= chunk_end:
                    break
                if not flag_byte & (1 << bit):
                    out.append(data[pos])
                    pos += 1
                    continue
                if pos + 2 > chunk_end:
                    pos = chunk_end
                    break
                (copy_token,) = struct.unpack("<H", data[pos : pos + 2])
                pos += 2
                difference = len(out) - chunk_start_out
                bit_count = _bit_count(difference)
                length_mask = 0xFFFF >> bit_count
                offset_mask = ~length_mask & 0xFFFF
                length = (copy_token & length_mask) + 3
                offset = ((copy_token & offset_mask) >> (16 - bit_count)) + 1
                for _ in range(length):
                    if offset > len(out):
                        return None
                    out.append(out[-offset])
                    if len(out) > cap:
                        return None
    return bytes(out)


def _bit_count(difference: int) -> int:
    """Bit count for copy-token masks: the number of bits needed for the
    current difference (MS-OVBA 2.4.1.3.19), minimum 4."""
    if difference < 16:
        return 4
    count = 4
    while (1 << count) < difference + 1:
        count += 1
    return min(count, 12)


# ---------------------------------------------------------------------------
# VBA project extraction (through the CFBF reader)
# ---------------------------------------------------------------------------

def _extract_vba_project(vba_bin: bytes, refusals: list[str], degradations: list[str]) -> dict:
    """``vbaProject.bin``: module names, source text, stomping evidence."""
    project: dict = {
        "modules": [],
        "module_count": 0,
        "references": [],
        "compiled_pcode_present": False,
        "source_missing_modules": [],
        "degradations": [],
    }
    try:
        reader = CfbfReader(vba_bin, refusals, degradations)
    except (CfbfError, ValueError, struct.error):
        project["degradations"].append("vba_project_unreadable")
        return project
    tree = reader.tree()
    dir_entry = None
    modules: dict[str, dict] = {}
    project_stream = None
    for entry in tree:
        if entry["type"] != "stream":
            continue
        path = entry["path"]
        lowered = path.lower()
        if lowered == "vba/dir":
            dir_entry = entry
        elif lowered.startswith("vba/") and entry["size"] and lowered not in ("vba/dir",):
            # Key by the module name: the last segment of the stream path
            # (the CFBF tree may be flat in hand-built projects).
            modules[entry["name"].rsplit("/", 1)[-1]] = entry
        elif lowered == "project":
            project_stream = entry
    # PROJECT stream: external references (TypeLib / class libs).
    if project_stream is not None:
        text = reader.read_entry(project_stream)
        for line in text.decode("latin-1", "replace").splitlines():
            if line.startswith(("Reference=", "Reference*=")):
                project["references"].append(line[:200])
            elif line.startswith("Description="):
                continue
    if dir_entry is None:
        project["degradations"].append("vba_dir_stream_missing")
        project["module_count"] = len(modules)
        return project
    dir_bytes = reader.read_entry(dir_entry)
    if dir_bytes is None:
        project["degradations"].append("vba_dir_stream_missing")
        return project
    decompressed = decompress_vba(dir_bytes)
    if decompressed is None:
        project["degradations"].append("vba_dir_decompress_failed")
        return project
    # PROJECTNAME / module records walk: the dir stream is a record stream
    # (id u16, reserved u32, size u32) with MODULE records carrying names.
    module_names: list[str] = []
    position = 0
    end = len(decompressed)
    while position + 6 <= end:
        record_id = struct.unpack("<H", decompressed[position : position + 2])[0]
        if record_id == 0x0019:  # MODULENAME: id(2) reserved(4) size(4) name
            name_size = struct.unpack("<I", decompressed[position + 6 : position + 10])[0]
            name = decompressed[position + 10 : position + 10 + name_size].decode("latin-1", "replace")
            module_names.append(name)
            position += 10 + name_size
            continue
        if record_id == 0x0047:  # MODULENAME unicode
            name_size = struct.unpack("<I", decompressed[position + 6 : position + 10])[0]
            position += 10 + name_size
            continue
        if record_id == 0x001A or record_id == 0x0032:  # MODULESTREAMNAME(+unicode)
            name_size = struct.unpack("<I", decompressed[position + 6 : position + 10])[0]
            name = decompressed[position + 10 : position + 10 + name_size].decode("latin-1", "replace")
            if name:
                module_names.append(name)
            position += 10 + name_size
            continue
        if record_id == 0x0031:  # MODULEOFFSET: id(2) reserved(4) offset(4)
            offset = struct.unpack("<I", decompressed[position + 6 : position + 10])[0]
            if module_names:
                modules.setdefault(module_names[-1], {})
                modules[module_names[-1]]["text_offset"] = offset
            position += 10
            continue
        if record_id == 0x0021 or record_id == 0x0022:  # MODULETYPE
            position += 10
            continue
        if record_id == 0x002C:  # MODULEDOCSTRING
            size = struct.unpack("<I", decompressed[position + 6 : position + 10])[0]
            position += 10 + size
            continue
        if record_id == 0x0048 or record_id == 0x0049 or record_id == 0x004A:
            position += 10
            continue
        if record_id == 0x002F:  # MODULECOOKIE
            position += 10
            continue
        if record_id == 0x002B:  # MODULE terminator
            position += 10
            continue
        if record_id == 0x000F:  # project terminator
            break
        if record_id in (0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009,
                         0x000A, 0x000C, 0x000D, 0x000E, 0x0016):
            # PROJECT* / document records: id, reserved(4), size(4), data
            size = struct.unpack("<I", decompressed[position + 6 : position + 10])[0]
            if record_id == 0x0005:  # PROJECTNAME
                name = decompressed[position + 10 : position + 10 + size].decode("latin-1", "replace")
                if name:
                    project["project_name"] = name
            position += 10 + size
            continue
        position += 1
    project["_vba_project_stream_present"] = any(
        entry["path"].lower() in ("_vba_project", "vba/_vba_project") for entry in tree
    )
    project["compiled_pcode_present"] = project["_vba_project_stream_present"]
    for name in module_names[:MAX_VBA_MODULES_LISTED]:
        entry = modules.get(name)
        module: dict = {"name": name, "source_present": False}
        if isinstance(entry, dict) and entry.get("index") is not None:
            text_offset = entry.get("text_offset", 0)
            source = reader.read_entry(entry, cap=MAX_VBA_MODULE_BYTES)
            if source and text_offset < len(source):
                decompressed_module = decompress_vba(source[text_offset:], cap=MAX_VBA_MODULE_BYTES)
                if decompressed_module is not None:
                    module["source_present"] = True
                    module["source_bytes"] = len(decompressed_module)
                    module["source"] = decompressed_module.decode("latin-1", "replace")[:65536]
                else:
                    module["degradation"] = "module_decompress_failed"
            else:
                module["degradation"] = "module_text_offset_invalid"
        else:
            module["degradation"] = "module_stream_missing"
        if not module["source_present"]:
            project["source_missing_modules"].append(name)
        project["modules"].append(module)
    project["module_count"] = len(module_names)
    # Stomping evidence: compiled p-code (_VBA_PROJECT) present while at
    # least one module has no recoverable source.
    project["vba_stomping_evidence"] = bool(
        project["compiled_pcode_present"] and project["source_missing_modules"]
    )
    return project


# ---------------------------------------------------------------------------
# OOXML
# ---------------------------------------------------------------------------

def _localname(tag: str) -> str:
    return tag.rpartition("}")[2]


def _iter_relationship_parts(archive: zipfile.ZipFile, members: list) -> list[str]:
    names = [info.filename for info in members]
    parts = [name for name in names if name == "_rels/.rels" or "/_rels/" in name]
    return sorted(parts)


def _parse_rels(xml_bytes: bytes, source_part: str, relationships: list, refusals: list[str]) -> None:
    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        refusals.append("relationship_xml_malformed")
        return
    for rel in root.iter():
        if _localname(rel.tag) != "Relationship":
            continue
        target_mode = rel.get("TargetMode") or "Internal"
        relationships.append(
            {
                "source": source_part,
                "id": rel.get("Id"),
                "type": (rel.get("Type") or "").rsplit("/", 1)[-1],
                "target": rel.get("Target"),
                "external": target_mode == "External",
            }
        )


def _scan_dde_fields(xml_bytes: bytes) -> list[str]:
    """DDEAUTO/DDE field instructions in a document part."""
    fields = []
    for match in re.finditer(rb"<w:instrText[^>]*>([^<]*)</w:instrText>", xml_bytes):
        instruction = match.group(1)
        if _DDE_FIELD_RE.search(instruction):
            fields.append(instruction.decode("latin-1", "replace").strip()[:200])
    return fields


def analyze_ooxml(path: str, refusals: list[str], degradations: list[str]) -> dict:
    """Facts block for one OOXML document (no extraction to disk)."""
    block: dict = {
        "parse_status": "parsed",
        "content_types": {},
        "relationships": [],
        "external_relationship_count": 0,
        "vba_project_present": False,
        "vba": None,
        "macro_signature_present": False,
        "embedded_ole_objects": [],
        "activex_present": False,
        "printer_settings": [],
        "dde_fields": [],
        "external_template": None,
        "refusals": [],
        "degradations": [],
    }
    try:
        with zipfile.ZipFile(path) as archive:
            members = walk_zip_members(archive, OFFICE_LIMITS, refusals)
            by_name = {info.filename: info for info in members}
            relationships: list[dict] = []
            for part in _iter_relationship_parts(archive, members):
                info = by_name.get(part)
                if info is None:
                    continue
                rel_bytes = read_zip_member_bounded(archive, info, 4 * 1024 * 1024, refusals)
                if rel_bytes:
                    source_part = part.replace("_rels/", "").replace(".rels", "") or "/"
                    before = len(relationships)
                    _parse_rels(rel_bytes, source_part, relationships, refusals)
                    if len(relationships) > MAX_RELATIONSHIPS_LISTED:
                        del relationships[MAX_RELATIONSHIPS_LISTED:]
                        refusals.append("relationship_list_capped")
                        break
                    _ = before
            block["relationships"] = relationships[:MAX_RELATIONSHIPS_LISTED]
            block["relationship_count"] = len(relationships)
            external = [r for r in relationships if r["external"]]
            block["external_relationship_count"] = len(external)
            block["external_relationships"] = [
                r for r in external if r["type"] in (REL_REMOTE_TEMPLATE, REL_OLE_OBJECT, "hyperlink")
            ][:MAX_RELATIONSHIPS_LISTED]
            for rel in external:
                if rel["type"] == REL_REMOTE_TEMPLATE and rel["target"]:
                    block["external_template"] = rel["target"]
                    break
            # vbaProject.bin through the CFBF reader.
            vba_info = by_name.get("word/vbaProject.bin") or by_name.get("xl/vbaProject.bin") or by_name.get("ppt/vbaProject.bin")
            if vba_info is not None:
                block["vba_project_present"] = True
                vba_bytes = read_zip_member_bounded(archive, vba_info, 64 * 1024 * 1024, refusals)
                if vba_bytes:
                    block["vba"] = _extract_vba_project(vba_bytes, refusals, degradations)
            # Macro signatures (OOXML shapes).
            if any(name.lower().endswith("vbaProjectSignature.bin") for name in by_name):
                block["macro_signature_present"] = True
            if any("_xmlsignatures/" in name for name in by_name):
                block["macro_signature_present"] = True
            # Stream-smuggling spots and embedded objects.
            for name, info in by_name.items():
                lowered = name.lower()
                if "embeddings/" in lowered:
                    if len(block["embedded_ole_objects"]) < MAX_LISTED_OLE_OBJECTS:
                        block["embedded_ole_objects"].append({"name": name, "size": info.file_size})
                elif "activex/" in lowered and lowered.endswith(".bin"):
                    block["activex_present"] = True
                elif "printersettings" in lowered:
                    if len(block["printer_settings"]) < MAX_LISTED_OLE_OBJECTS:
                        block["printer_settings"].append({"name": name, "size": info.file_size})
            # DDE field codes in the main document parts.
            for part_name in ("word/document.xml", "word/document2.xml"):
                info = by_name.get(part_name)
                if info is not None:
                    part_bytes = read_zip_member_bounded(archive, info, 32 * 1024 * 1024, refusals)
                    if part_bytes:
                        block["dde_fields"] = _scan_dde_fields(part_bytes)
                        break
    except zipfile.BadZipFile:
        block["parse_status"] = "failed"
        block["refusals"].append("archive_unreadable")
        return block
    if degradations:
        block["parse_status"] = "partial"
    block["refusals"] = sorted(set(block["refusals"] + refusals))
    block["degradations"] = sorted(set(block["degradations"] + degradations))
    return block


# ---------------------------------------------------------------------------
# Legacy Office (.doc/.xls/.ppt) and .msg — through the CFBF reader
# ---------------------------------------------------------------------------

def _biff_macro_sheet_detection(workbook_bytes: bytes) -> dict:
    """Excel 4.0 (XLM) macro-sheet detection from the BIFF record stream."""
    result = {"biff_parse_status": "not_biff", "macro_sheet": False, "sheet_count": 0}
    if len(workbook_bytes) < 8:
        return result
    (bof_id,) = struct.unpack("<H", workbook_bytes[:2])
    if bof_id not in (0x0409, 0x0209, 0x0809):
        return result
    result["biff_parse_status"] = "parsed"
    position = 0
    records = 0
    while position + 4 <= len(workbook_bytes) and records < MAX_BIFF_WALK_RECORDS:
        record_id, record_size = struct.unpack("<HH", workbook_bytes[position : position + 4])
        body = workbook_bytes[position + 4 : position + 4 + record_size]
        records += 1
        if record_id in (0x0085, 0x0851) and len(body) >= 6:  # BOUNDSHEET / SHEETEX
            grbit = struct.unpack("<H", body[-4:-2])[0] if record_id == 0x0085 else 0
            # BOUNDSHEET hidden/macro state lives in the grbit (hs state bits 8-9; type bits 0-1)
            sheet_type = grbit & 0x0003
            _ = sheet_type
        position += 4 + record_size
    result["record_count"] = records
    result["macro_sheet"] = False
    # A macro sheet is a BOUNDSHEET whose grbit type bits are 0x1 (macro).
    position = 0
    while position + 4 <= len(workbook_bytes):
        record_id, record_size = struct.unpack("<HH", workbook_bytes[position : position + 4])
        body = workbook_bytes[position + 4 : position + 4 + record_size]
        if record_id == 0x0085 and len(body) >= 6:
            result["sheet_count"] += 1
            (grbit,) = struct.unpack("<H", body[4:6])
            # BIFF8 BOUNDSHEET grbit: bits 8-15 carry the sheet type
            # (0 worksheet, 1 macro sheet, 2 chart, 3 VB module).
            if (grbit >> 8) & 0x03 == 1 or grbit & 0x01:
                result["macro_sheet"] = True
        position += 4 + record_size
        if position >= len(workbook_bytes):
            break
    return result


def analyze_legacy_office(path: str, refusals: list[str], degradations: list[str]) -> dict:
    """Facts block for one legacy .doc/.xls/.ppt (structure + indicators)."""
    block: dict = {
        "parse_status": "parsed",
        "stream_count": 0,
        "streams": [],
        "vba_project_present": False,
        "vba": None,
        "project_references": [],
        "ole10_native_present": False,
        "ole10_native_files": [],
        "macro_sheet": None,
        "embedded_ole_objects": [],
        "refusals": [],
        "degradations": [],
    }
    try:
        with open(path, "rb") as handle:
            data = handle.read(256 * 1024 * 1024)
    except OSError:
        block["parse_status"] = "failed"
        block["refusals"].append("archive_unreadable")
        return block
    try:
        reader = CfbfReader(data, refusals, degradations)
    except (CfbfError, ValueError, struct.error):
        block["parse_status"] = "failed"
        block["refusals"].append("archive_unreadable")
        return block
    tree = reader.tree()
    streams = [e for e in tree if e["type"] == "stream"]
    block["stream_count"] = len(streams)
    block["streams"] = [{"path": s["path"], "size": s["size"]} for s in streams[:MAX_LISTED_OLE_OBJECTS]]
    lowered_paths = {s["path"].lower(): s for s in streams}
    vba_dir = lowered_paths.get("macros/vba/dir") or lowered_paths.get("_vba_project_cur/vba/dir") or lowered_paths.get("vba/dir")
    block["vba_project_present"] = any(
        p.endswith("/_vba_project") or p == "_vba_project" for p in lowered_paths
    )
    if vba_dir is not None:
        # Re-read the whole VBA storage through the project extractor.
        block["vba"] = _extract_vba_project_from_storage(reader, lowered_paths, degradations)
    ole10 = lowered_paths.get("\\x01ole10native".replace("\\x01", "\x01") )
    ole10 = lowered_paths.get("\x01ole10native")
    if ole10 is not None:
        block["ole10_native_present"] = True
        payload = reader.read_entry(ole10, cap=MAX_VBA_MODULE_BYTES)
        if payload and len(payload) > 6:
            # Ole10Native: total size u32, then flags u8, label C-string, filename C-string.
            position = 4
            flags = payload[position]
            position += 1
            strings = []
            while position < len(payload) and len(strings) < 8:
                terminator = payload.find(b"\x00", position)
                if terminator < 0:
                    break
                strings.append(payload[position:terminator].decode("latin-1", "replace"))
                position = terminator + 1
                if flags == 1 and len(strings) >= 3:
                    break
            block["ole10_native_files"] = strings[:MAX_LISTED_OLE_OBJECTS]
    if any(p.endswith("workbook") or p == "book" for p in lowered_paths):
        workbook = lowered_paths.get("workbook") or lowered_paths.get("book")
        body = reader.read_entry(workbook, cap=MAX_VBA_MODULE_BYTES * 4)
        if body:
            block["macro_sheet"] = _biff_macro_sheet_detection(body)
    for path_key, stream in lowered_paths.items():
        if path_key.startswith(("embedding", "mbd")) or "/embeddings" in path_key:
            if len(block["embedded_ole_objects"]) < MAX_LISTED_OLE_OBJECTS:
                block["embedded_ole_objects"].append({"name": stream["path"], "size": stream["size"]})
    if degradations:
        block["parse_status"] = "partial"
    block["refusals"] = sorted(set(block["refusals"] + refusals))
    block["degradations"] = sorted(set(block["degradations"] + degradations))
    return block


def _extract_vba_project_from_storage(reader: CfbfReader, lowered_paths: dict, degradations: list[str]) -> dict:
    """Assemble the VBA project facts from a legacy document's storage."""
    # Build one synthetic vbaProject.bin image: reconstitute a CFBF? Too
    # heavy — walk the streams directly instead.
    project: dict = {
        "modules": [],
        "module_count": 0,
        "references": [],
        "compiled_pcode_present": False,
        "source_missing_modules": [],
        "degradations": [],
    }
    module_streams: dict[str, dict] = {}
    for path_key, stream in lowered_paths.items():
        if "/vba/" in f"/{path_key}" and path_key.endswith(tuple("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")):
            if not path_key.lower().endswith(("dir", "_vba_project")):
                module_streams[path_key.rsplit("/", 1)[-1]] = stream
    project_stream = lowered_paths.get("macros/project") or lowered_paths.get("_vba_project_cur/project") or lowered_paths.get("project")
    if project_stream is not None:
        text = reader.read_entry(project_stream, cap=MAX_VBA_MODULE_BYTES)
        for line in text.decode("latin-1", "replace").splitlines():
            if line.startswith(("Reference=", "Reference*=")):
                project["references"].append(line[:200])
    project["compiled_pcode_present"] = any(
        p.endswith("_vba_project") for p in lowered_paths
    )
    dir_stream = None
    for path_key, stream in lowered_paths.items():
        if path_key.lower().endswith("/dir") or path_key.lower() == "dir":
            dir_stream = stream
            break
    module_names: list[str] = []
    if dir_stream is not None:
        dir_bytes = reader.read_entry(dir_stream, cap=MAX_VBA_MODULE_BYTES)
        decompressed = decompress_vba(dir_bytes) if dir_bytes else None
        if decompressed is None:
            project["degradations"].append("vba_dir_decompress_failed")
        else:
            position = 0
            while position + 8 <= len(decompressed):
                record_id = struct.unpack("<H", decompressed[position : position + 2])[0]
                if record_id in (0x0019, 0x001A, 0x0032):
                    name_size = struct.unpack("<I", decompressed[position + 6 : position + 10])[0]
                    name = decompressed[position + 10 : position + 10 + name_size].decode("latin-1", "replace")
                    if name:
                        module_names.append(name)
                    position += 10 + name_size
                    continue
                if record_id == 0x0031:
                    position += 10
                    continue
                if record_id == 0x000F:
                    break
                if record_id == 0x0016:
                    # PROJECTCOMPATVERSION etc.: id, reserved(4), size(4)
                    size = struct.unpack("<I", decompressed[position + 6 : position + 10])[0]
                    position += 10 + size
                    continue
                position += 2
    for name in module_names[:MAX_VBA_MODULES_LISTED]:
        module: dict = {"name": name, "source_present": False}
        stream = module_streams.get(name.lower())
        if stream is None:
            module["degradation"] = "module_stream_missing"
        else:
            source = reader.read_entry(stream, cap=MAX_VBA_MODULE_BYTES)
            decompressed = decompress_vba(source, cap=MAX_VBA_MODULE_BYTES) if source else None
            if decompressed is not None:
                module["source_present"] = True
                module["source_bytes"] = len(decompressed)
                module["source"] = decompressed.decode("latin-1", "replace")[:65536]
            else:
                module["degradation"] = "module_decompress_failed"
        if not module["source_present"]:
            project["source_missing_modules"].append(name)
        project["modules"].append(module)
    project["module_count"] = len(module_names)
    project["vba_stomping_evidence"] = bool(
        project["compiled_pcode_present"] and project["source_missing_modules"]
    )
    return project


def analyze_msg(path: str, refusals: list[str], degradations: list[str]) -> dict:
    """``.msg``/``.oft`` through the CFBF reader: properties + attachments.

    Attachment bytes are NOT embedded in metadata (base64 blobs would blow
    the size budget) — the runner extracts them to bounded temp files where
    they become inputs themselves.
    """
    block: dict = {
        "parse_status": "parsed",
        "stream_count": 0,
        "subject": None,
        "attachments": [],
        "attachment_count": 0,
        "refusals": [],
        "degradations": [],
    }
    try:
        with open(path, "rb") as handle:
            data = handle.read(256 * 1024 * 1024)
    except OSError:
        block["parse_status"] = "failed"
        block["refusals"].append("archive_unreadable")
        return block
    try:
        reader = CfbfReader(data, refusals, degradations)
    except (CfbfError, ValueError, struct.error):
        block["parse_status"] = "failed"
        block["refusals"].append("archive_unreadable")
        return block
    tree = reader.tree()
    streams = [e for e in tree if e["type"] == "stream"]
    block["stream_count"] = len(streams)
    attachments = []
    for entry in tree:
        path = entry["path"]
        if path.startswith("__attach_version1.0_/") and entry["type"] == "storage":
            attachments.append(path)
    block["attachment_count"] = len(attachments)
    for attachment_root in attachments[:MAX_LISTED_ATTACHMENTS]:
        attachment = {"path": attachment_root, "name": None, "size": None}
        for entry in tree:
            if entry["path"].startswith(attachment_root + "/") and entry["type"] == "stream":
                if entry["path"].endswith("37010102"):  # PR_ATTACH_DATA_BIN
                    attachment["size"] = entry["size"]
                elif entry["path"].endswith("3707") or entry["path"].endswith("3704"):  # PR_ATTACHMENT_FILENAME-ish
                    raw = reader.read_entry(entry, cap=1024)
                    if raw:
                        attachment["name"] = raw.decode("utf-16-le", "replace").rstrip("\x00") or None
        attachments_idx = len(block["attachments"])
        _ = attachments_idx
        block["attachments"].append(attachment)
    # Subject property (top-level __substg1.0_0037).
    for entry in streams:
        if entry["path"].endswith("0037") and entry["path"].startswith("__substg"):
            raw = reader.read_entry(entry, cap=4096)
            if raw:
                block["subject"] = raw.decode("utf-16-le", "replace").rstrip("\x00")
            break
    if degradations:
        block["parse_status"] = "partial"
    block["refusals"] = sorted(set(block["refusals"] + refusals))
    block["degradations"] = sorted(set(block["degradations"] + degradations))
    return block


# ---------------------------------------------------------------------------
# RTF — detection + objdata extraction, no full parser
# ---------------------------------------------------------------------------

def analyze_rtf(path: str, refusals: list[str], degradations: list[str]) -> dict:
    """``{\\rtf`` detection plus ``\\objdata``/``\\objupdate`` object extraction.

    A regex/brace walk over a bounded scan window — no full RTF parser, and
    that is stated. Objects that decode to CFBF images are reported with
    their stream facts; everything else records the class name and size.
    """
    block: dict = {
        "parse_status": "parsed",
        "rtf_detected": False,
        "objects": [],
        "object_count": 0,
        "refusals": [],
        "degradations": [],
    }
    try:
        with open(path, "rb") as handle:
            head = handle.read(16)
            if head[:6] != b"{\\rtf1":
                return block
            block["rtf_detected"] = True
            handle.seek(0)
            data = handle.read(MAX_RTF_SCAN_BYTES)
            if len(data) == MAX_RTF_SCAN_BYTES:
                degradations.append("rtf_scan_truncated")
    except OSError:
        block["parse_status"] = "failed"
        block["refusals"].append("archive_unreadable")
        return block
    for match in re.finditer(rb"\\objdata\s*([0-9a-fA-F\{\}\s\r\n]*)", data):
        if len(block["objects"]) >= MAX_LISTED_OLE_OBJECTS:
            block["refusals"].append("object_list_capped")
            break
        hex_blob = re.sub(rb"[^0-9a-fA-F]", b"", match.group(1))[: MAX_RTF_OBJECT_BYTES * 2]
        if len(hex_blob) < 8:
            continue
        try:
            decoded = bytes.fromhex(hex_blob.decode("ascii"))
        except ValueError:
            block["degradations"].append("objdata_hex_invalid")
            continue
        obj = {"offset": match.start(), "bytes": len(decoded)}
        if is_cfbf_bytes(decoded):
            obj["format"] = "cfbf"
            mini = parse_cfbf(decoded)
            obj["cfbf_stream_count"] = mini.get("stream_count")
            obj["cfbf_streams"] = [
                s["path"] for s in (mini.get("entries") or []) if s.get("type") == "stream"
            ][:32]
        else:
            obj["format"] = "unknown"
        block["objects"].append(obj)
    block["object_count"] = len(block["objects"])
    return block


# ---------------------------------------------------------------------------
# Metadata assembly and runner helpers
# ---------------------------------------------------------------------------

def office_exe_type(path: str) -> str | None:
    if is_ooxml_file(path):
        return "ooxmldocument"
    if is_legacy_office_file(path):
        return "oleofficedocument"
    if is_msg_file(path):
        return "msgdocument"
    if is_rtf_file(path):
        return "rtfdocument"
    return None


def analyze_office_file(path: str, refusals: list[str], degradations: list[str]) -> dict | None:
    """Dispatch one office input to its reader; None when not office."""
    exe_type = office_exe_type(path)
    if exe_type is None:
        return None
    if exe_type == "ooxmldocument":
        return analyze_ooxml(path, refusals, degradations)
    if exe_type == "oleofficedocument":
        return analyze_legacy_office(path, refusals, degradations)
    if exe_type == "msgdocument":
        return analyze_msg(path, refusals, degradations)
    return analyze_rtf(path, refusals, degradations)


def build_review_evidence(block: dict, exe_type: str) -> dict:
    """The evidence families the rule engine matches on.

    ``macro_code`` carries macro source lines and VBA tokens;
    ``relationships`` the rendered relationship rows (external targets
    included); ``ole_streams`` the CFBF stream names. All are capped
    listings whose counts ride beside them.
    """
    macro_lines: list[str] = []
    relationships: list[str] = []
    ole_streams: list[str] = []
    vba = block.get("vba")
    if isinstance(vba, dict):
        for module in vba.get("modules") or []:
            source = module.get("source") or ""
            for line in source.splitlines():
                stripped = line.strip()
                if stripped and not stripped.startswith("Attribute "):
                    macro_lines.append(f"{module['name']}:{stripped[:200]}")
    for rel in block.get("relationships") or []:
        external = "external" if rel.get("external") else "internal"
        relationships.append(f"{rel.get('type')}:{external}:{rel.get('target')}")
    if isinstance(vba, dict) and vba.get("vba_stomping_evidence"):
        macro_lines.append("stomping_evidence")
    if block.get("macro_sheet") and block["macro_sheet"].get("macro_sheet"):
        macro_lines.append("xlm_macro_sheet")
    for stream in block.get("streams") or []:
        ole_streams.append(stream.get("path") or "")
    for obj in block.get("embedded_ole_objects") or []:
        ole_streams.append(obj.get("name") or "")
    if block.get("ole10_native_files"):
        for name in block["ole10_native_files"]:
            ole_streams.append(f"Ole10Native:{name}")
    return {
        "macro_code": macro_lines[:MAX_VBA_MODULES_LISTED * 32],
        "macro_code_total": len(macro_lines),
        "relationships": relationships[:MAX_RELATIONSHIPS_LISTED],
        "relationship_total": len(relationships),
        "ole_streams": [s for s in ole_streams if s][:MAX_LISTED_OLE_OBJECTS],
    }


def extract_msg_attachments(path: str, dest_dir: str, refusals: list[str]) -> dict[str, str]:
    """Extract ``.msg`` attachments so they become inputs themselves.

    Attachment properties live under ``__attach_version1.0_*`` storages;
    the data stream is ``__substg1.0_37010102`` (PR_ATTACH_DATA_BIN).
    Extraction is bounded per attachment and in total; the caller owns the
    ``dest_dir``.
    """
    extracted: dict[str, str] = {}
    try:
        with open(path, "rb") as handle:
            data = handle.read(256 * 1024 * 1024)
    except OSError:
        refusals.append("archive_unreadable")
        return extracted
    try:
        reader = CfbfReader(data, refusals, _degradations := [])
    except (CfbfError, ValueError, struct.error):
        refusals.append("archive_unreadable")
        return extracted
    tree = reader.tree()
    total_written = 0
    position = 0
    for entry in tree:
        path_key = entry["path"]
        if not path_key.startswith("__attach_version1.0_/") or entry["type"] != "storage":
            continue
        if position >= MAX_LISTED_ATTACHMENTS:
            refusals.append("attachment_count_exceeds_cap")
            break
        position += 1
        for stream in tree:
            stream_path = stream["path"]
            if not stream_path.startswith(path_key + "/"):
                continue
            local = stream_path.rsplit("/", 1)[-1]
            if not local.startswith("__substg1.0_3701"):
                continue
            if total_written + (stream["size"] or 0) > MAX_MSG_ATTACHMENT_BYTES:
                refusals.append("total_attachment_bytes_exceeds_cap")
                break
            payload = reader.read_entry(stream, cap=MAX_MSG_ATTACHMENT_BYTES)
            if not payload:
                continue
            name = local
            position_name = payload
            _ = position_name
            dest = os.path.join(dest_dir, f"attachment_{position}_{name}.bin")
            try:
                with open(dest, "wb") as out:
                    out.write(payload)
            except OSError:
                refusals.append("member_unreadable")
                continue
            extracted[f"attachment_{position}/{local}"] = dest
            total_written += len(payload)
    return extracted


def office_metadata(block: dict, file_path: str, exe_type: str) -> dict:
    """The analyzed metadata dict for one office unit (all families)."""
    evidence = build_review_evidence(block, exe_type)
    metadata: dict = {
        "name": os.path.basename(file_path),
        "file_path": file_path,
        "exe_type": exe_type,
        "office": block,
        "macro_code": evidence["macro_code"],
        "macro_code_total": evidence["macro_code_total"],
        "relationships": evidence["relationships"],
        "relationship_total": evidence["relationship_total"],
        "ole_streams": evidence["ole_streams"],
        "informative_strings": evidence["macro_code"][:64],
    }
    return metadata
