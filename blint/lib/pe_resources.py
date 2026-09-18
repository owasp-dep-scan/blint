# SPDX-License-Identifier: Apache-2.0
"""PE resource tree, VERSIONINFO and manifest depth (W1.3, 01/A.7).

The resource tree is attacker-controlled input and this parser treats it
like one (ground rule 30): every traversal and every read is bounded, and a
limit that fires records a ``degradation`` — never a silent skip. What the
module recovers:

- ``version_info``: the full StringFileInfo table for every language, the
  fixed-block FileVersion/ProductVersion decoded from the raw resource
  (LIEF 1.0 does not expose it), and the fixed-vs-string mismatch flag —
  a well-known tampering tell.
- ``manifest_parsed``: the embedded manifest's requestedExecutionLevel,
  uiAccess, supportedOS versions, side-by-side assembly identities and the
  rest of what the raw XML dump cannot answer.
- ``tree_summary``: type -> count/bytes/entropy, so an 8 MB RCDATA blob in a
  9 MB binary is visible.
- ``hashes``: per-resource SHA-256 (icons included) plus a combined
  ``icon_hash`` for clustering, and embedded-PE detection with the
  resource's RVA.
"""

import contextlib
import hashlib
import struct
from xml.etree import ElementTree as ET

import lief

from blint.lib.entropy import shannon_entropy
from blint.lib.pe_constants import VS_FILE_FLAGS, VS_FILE_OS, decode_flag_bits, resource_type_name
from blint.logger import LOG

# Ground rule 30 limits. A hostile resource section can declare thousands of
# entries, tree depths, and sizes; everything past a limit is counted and
# recorded as a degradation instead of being processed or silently dropped.
MAX_RESOURCE_DATA_NODES = 1024
MAX_RESOURCE_DEPTH = 8
# Per-resource hash cap (first N bytes) and the cumulative hash budget: an
# installer-sized RCDATA blob must not turn a scan into a full-file digest.
MAX_RESOURCE_HASH_BYTES = 1024 * 1024
MAX_RESOURCE_TOTAL_HASH_BYTES = 32 * 1024 * 1024
# Entropy is measured over two windows (start and end) of each resource so a
# large resource is never copied or scanned in full; the type summary samples
# the first window of the type's resources. Ground rule 33 shapes the
# fixtures that prove where these windows end.
RESOURCE_ENTROPY_WINDOW = 0x10000
MAX_EMBEDDED_PE_REPORTS = 32
VS_FIXEDFILEINFO_SIGNATURE = 0xFEEF04BD

# Windows versions named by the supportedOS GUIDs a manifest can declare.
SUPPORTED_OS_GUIDS: dict[str, str] = {
    "{8E0F7A12-BFB3-4FE8-B9A5-48FD50A15A9A}": "Windows 10/11",
    "{1F676C76-80E1-4239-95BB-83D0F6D0DA78}": "Windows 8.1",
    "{4A2F28E3-53B9-4441-BA9C-D69D4A4A6E38}": "Windows 8",
    "{35138B9A-5D96-4FBD-8E2D-A2440225F93A}": "Windows 7",
    "{E2011457-1546-43C5-A5FE-008DEEE3D3F0}": "Windows Vista",
}


def manifest_facts(manifest_xml: str | bytes | None) -> dict:
    """Parse the embedded manifest into its security-relevant facts (01/A.7).

    ``requestedExecutionLevel`` (with ``uiAccess``), the dpi awareness
    declarations, ``longPathAware``, ``activeCodePage``, the supportedOS
    GUIDs mapped to Windows versions and the side-by-side
    ``assemblyIdentity`` dependencies. A manifest that is present but
    unparseable reports ``parse_status: failed`` rather than an empty dict —
    a failed parse must not read as "no elevation requested".
    """
    facts: dict = {}
    if not manifest_xml:
        return facts
    if isinstance(manifest_xml, str):
        manifest_xml = manifest_xml.encode("utf-8", errors="replace")
    try:
        root = ET.fromstring(manifest_xml)
    except ET.ParseError as exc:
        LOG.debug(f"Unable to parse PE manifest: {exc}")
        facts["parse_status"] = "failed"
        return facts
    facts["parse_status"] = "parsed"

    def local(tag: str) -> str:
        return tag.rpartition("}")[-1]

    for elem in root.iter():
        tag = local(elem.tag)
        if tag == "requestedExecutionLevel":
            level = elem.get("level")
            if level:
                facts["requestedExecutionLevel"] = level
            ui_access = elem.get("uiAccess")
            if ui_access is not None:
                facts["uiAccess"] = ui_access.lower() == "true"
        elif tag == "dpiAware" and elem.text:
            facts["dpiAware"] = elem.text.strip()
        elif tag == "dpiAwareness" and elem.text:
            facts["dpiAwareness"] = elem.text.strip()
        elif tag == "activeCodePage" and elem.text:
            facts["activeCodePage"] = elem.text.strip()
        elif tag == "longPathAware" and elem.text:
            facts["longPathAware"] = elem.text.strip().lower() == "true"
        elif tag == "supportedOS":
            guid = elem.get("Id") or ""
            facts.setdefault("supportedOS", []).append(
                SUPPORTED_OS_GUIDS.get(guid.upper(), guid)
            )
        elif tag == "assemblyIdentity":
            identity = {k: v for k, v in elem.attrib.items() if v}
            facts.setdefault("assembly_identities", []).append(identity)
    return facts


def _data_nodes(
    root, degradations: list[str], want_type: str | None = None
) -> list[tuple[str, str, int, object]]:
    """Walk the resource tree to its data nodes, bounded.

    Returns (type_name, resource_id, language, node) tuples. The type name
    comes from blint's RT_* table for numeric types and from the tree itself
    for string-named custom types. Depth and node-count limits feed the
    caller's degradations.

    ``want_type`` restricts the walk to one resource type, so a targeted
    lookup spends the node budget on the type it came for: the tree is
    enumerated in ascending type id and VERSION is 16, so an image with 1024
    icons (3) or strings (6) would otherwise exhaust the budget before its
    VERSIONINFO — the one resource every consumer of this block needs.
    """
    rows: list[tuple[str, str, int, object]] = []
    overflow = 0
    truncated_depth = False

    def visit(node, type_name: str, resource_id: str, depth: int) -> None:
        nonlocal overflow, truncated_depth
        if depth > MAX_RESOURCE_DEPTH:
            truncated_depth = True
            return
        try:
            childs = list(node.childs)
        except (AttributeError, TypeError, ValueError):
            return
        for child in childs:
            if child.is_data:
                if len(rows) >= MAX_RESOURCE_DATA_NODES:
                    overflow += 1
                    continue
                lang = child.id if not child.has_name else 0
                rows.append((type_name, resource_id, int(lang), child))
            elif depth == 0:
                # First level: the resource type.
                child_type = (
                    str(child.name)
                    if child.has_name
                    else resource_type_name(int(child.id))
                )
                if want_type is not None and child_type != want_type:
                    continue
                visit(child, child_type, "", 1)
            else:
                # Second level: the resource id or name; anything deeper
                # (some compilers nest further) keeps that id.
                child_id = resource_id or (
                    str(child.name) if child.has_name else str(int(child.id))
                )
                visit(child, type_name, child_id, depth + 1)

    with contextlib.suppress(AttributeError, TypeError, ValueError):
        visit(root, "", "", 0)
    if overflow:
        degradations.append(
            f"resource_tree: {overflow} data nodes past the {MAX_RESOURCE_DATA_NODES}-node limit"
        )
    if truncated_depth:
        degradations.append(f"resource_tree: deeper than {MAX_RESOURCE_DEPTH} levels")
    return rows


def _node_content(node) -> bytes:
    with contextlib.suppress(AttributeError, TypeError, ValueError):
        return bytes(node.content or b"")
    return b""


def _entropy_windows(content: bytes) -> bytes:
    """Two bounded windows — the start and the end of a resource.

    The tail matters as much as the head: an appended payload hides at the
    end of a large blob (the W0.2 overlay lesson, ground rule 33).
    """
    if len(content) <= RESOURCE_ENTROPY_WINDOW * 2:
        return content
    return content[:RESOURCE_ENTROPY_WINDOW] + content[-RESOURCE_ENTROPY_WINDOW:]


def _embedded_pe_facts(content: bytes) -> dict | None:
    """Recognize an embedded PE at the start of a resource, defensively.

    An MZ prefix alone is not evidence — the DOS header must name an
    e_lfanew within the resource, and a PE signature must sit there. A
    resource that fails the structure check is just data.
    """
    if len(content) < 0x40 or content[:2] != b"MZ":
        return None
    e_lfanew = int.from_bytes(content[0x3C:0x40], "little")
    if e_lfanew < 0x40 or e_lfanew + 4 > len(content):
        return None
    if content[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return None
    machine = int.from_bytes(content[e_lfanew + 4 : e_lfanew + 6], "little")
    return {"e_lfanew": e_lfanew, "coff_machine": machine}


def parse_pe_resources(parsed_obj: lief.PE.Binary, resources: dict) -> dict:
    """Build the W1.3 resource extensions from an already-parsed tree.

    ``resources`` is the dict ``process_pe_resources`` produced (it carries
    the raw manifest and the has_* booleans); the returned dict holds only
    the new keys so the caller merges them additively. Every failure path
    returns fewer keys, never raises — the resource section is untrusted
    input and the rest of the parse must survive a hostile tree.
    """
    extra: dict = {}
    if not resources:
        return extra
    degradations: list[str] = []

    if resources.get("manifest"):
        extra["manifest_parsed"] = manifest_facts(resources["manifest"])

    try:
        root = parsed_obj.resources
    except (AttributeError, TypeError, ValueError) as exc:
        LOG.debug(f"Unable to walk PE resource tree: {exc}")
        return extra

    # One bounded pass over the tree's data nodes feeds the summary, the
    # hashes, the icon cluster key and the embedded-PE detection alike.
    rows = _data_nodes(root, degradations)
    buckets: dict[str, dict] = {}
    entropy_samples: dict[str, bytes] = {}
    hashes = []
    embedded_pe = []
    icon_digests: set[str] = set()
    total_hashed = 0
    hash_budget_exhausted = False
    embedded_overflows = 0
    for type_name, resource_id, lang, node in rows:
        content = _node_content(node)
        bucket = buckets.setdefault(type_name, {"count": 0, "bytes": 0})
        bucket["count"] += 1
        bucket["bytes"] += len(content)
        # Per-type entropy sample: the two windows of each resource, until
        # one type's sample spans two windows.
        sample = entropy_samples.setdefault(type_name, b"")
        if len(sample) < RESOURCE_ENTROPY_WINDOW * 2:
            entropy_samples[type_name] = sample + _entropy_windows(content)[
                : RESOURCE_ENTROPY_WINDOW * 2 - len(sample)
            ]

        if total_hashed < MAX_RESOURCE_TOTAL_HASH_BYTES:
            capped = content[:MAX_RESOURCE_HASH_BYTES]
            digest = hashlib.sha256(capped).hexdigest()
            total_hashed += len(capped)
            row = {
                "type": type_name,
                "id": resource_id,
                "lang": lang,
                "sha256": digest,
                "size": len(content),
            }
            if len(capped) < len(content):
                row["hash_truncated"] = True
                degradations.append(
                    f"resource_hash: {type_name} id {resource_id} hashed first "
                    f"{MAX_RESOURCE_HASH_BYTES} of {len(content)} bytes"
                )
            hashes.append(row)
            if type_name in ("ICON", "GROUP_ICON", "CURSOR", "GROUP_CURSOR"):
                icon_digests.add(digest)
        elif not hash_budget_exhausted:
            hash_budget_exhausted = True
        if (
            facts := _embedded_pe_facts(content)
        ) and len(embedded_pe) < MAX_EMBEDDED_PE_REPORTS:
            embedded_pe.append(
                {
                    "type": type_name,
                    "id": resource_id,
                    "lang": lang,
                    # LIEF's ResourceData.offset is the data's file offset
                    # (its RVA resolved through the section mapping).
                    "file_offset": int(node.offset),
                    "size": len(content),
                    **facts,
                }
            )
        elif facts:
            embedded_overflows += 1
    if hash_budget_exhausted:
        degradations.append(
            f"resource_hash: total budget of {MAX_RESOURCE_TOTAL_HASH_BYTES} bytes exhausted"
        )
    if embedded_overflows:
        degradations.append(
            f"embedded_pe: {embedded_overflows} further hits past the "
            f"{MAX_EMBEDDED_PE_REPORTS}-report limit"
        )

    extra["tree_summary"] = {
        name: {
            **bucket,
            "entropy": round(shannon_entropy(entropy_samples.get(name, b"")), 4),
        }
        for name, bucket in buckets.items()
    }
    if hashes:
        extra["hashes"] = hashes
    if icon_digests:
        # Deterministic cluster key over the icon digests, whatever their
        # order in the tree.
        extra["icon_hash"] = hashlib.sha256(
            "\n".join(sorted(icon_digests)).encode()
        ).hexdigest()
    if embedded_pe:
        extra["embedded_pe"] = embedded_pe
    if degradations:
        extra["degradations"] = degradations

    if resources.get("has_version"):
        extra["version_info"] = parse_version_info(parsed_obj)
    return extra


def _format_version(ms: int, ls: int) -> str:
    return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"


def _version_major(value: str) -> int | None:
    """The leading numeric component of a version string, when it has one."""
    head = value.strip().split(".", maxsplit=1)[0].strip()
    return int(head) if head.isdigit() else None


def _is_mismatch(fixed_version: str, string_version: str) -> bool:
    """Fixed vs string versions disagree on the major component.

    The string table is what Explorer shows, the fixed block is what
    installers compare, and a rebuilt or tampered image often updates only
    one. Only the major component is comparable: everything after it is
    marketing text that vendors write however they like, and the reference
    corpus proves it — Sysinternals ships ``1.83`` against a fixed 1.8.3.0
    and ``14.3`` against 14.30.0.0 on Microsoft-signed, unmodified binaries,
    so a component-wise comparison calls 34 of 177 tier-0/1 files tampered.
    A rewritten ``5.0`` beside a 3.13 fixed block still reports, which is the
    signal this field exists for. Versions with no leading number compare
    literally.
    """
    fixed_major = _version_major(fixed_version)
    string_major = _version_major(string_version)
    if fixed_major is None or string_major is None:
        return fixed_version != string_version
    return fixed_major != string_major


def _find_fixed_file_info(content: bytes) -> dict | None:
    """Decode VS_FIXEDFILEINFO from the raw VERSION resource bytes.

    LIEF 1.0 exposes the string table but not the fixed block, so the
    signature (0xFEEF04BD) is located within the resource header region and
    the 52-byte structure decoded from there. Returns None when the fixed
    block is absent — a VERSIONINFO with strings but no fixed block is
    legal, and its absence must be visible instead of a zero-version guess.
    """
    signature_bytes = struct.pack("<I", VS_FIXEDFILEINFO_SIGNATURE)
    index = content.find(signature_bytes, 0, 0x200)
    if index == -1 or index + 52 > len(content):
        return None
    (
        _signature,
        _struct_version,
        file_version_ms,
        file_version_ls,
        product_version_ms,
        product_version_ls,
        file_flags_mask,
        file_flags,
        file_os,
        file_type,
        file_subtype,
        _file_date_ms,
        _file_date_ls,
    ) = struct.unpack_from("<13I", content, index)
    return {
        "file_version": _format_version(file_version_ms, file_version_ls),
        "product_version": _format_version(product_version_ms, product_version_ls),
        "file_flags_mask": file_flags_mask,
        "file_flags_value": file_flags & file_flags_mask,
        "file_flags": decode_flag_bits(file_flags & file_flags_mask, VS_FILE_FLAGS),
        "file_os": VS_FILE_OS.get(file_os, f"UNKNOWN({file_os})"),
        "file_type": int(file_type),
        "file_subtype": int(file_subtype),
    }


def _version_resource_content(parsed_obj: lief.PE.Binary) -> bytes | None:
    """The raw bytes of the first VERSION resource data node."""
    try:
        root = parsed_obj.resources
    except (AttributeError, TypeError, ValueError):
        return None
    for _type_name, _resource_id, _lang, node in _data_nodes(root, [], want_type="VERSION"):
        content = _node_content(node)
        if content:
            return content
    return None


def _walk_version_structures(
    content: bytes, start: int, end: int
) -> list[dict]:
    """Walk a VERSIONINFO node chain: [{key, value_bytes, children}].

    Every node is ``wLength, wValueLength, wType, szKey (UTF-16LE, NUL),
    padded, value (wValueLength bytes), children``. Bounds are checked on
    every read; a malformed node ends the chain with what decoded so far.
    """
    nodes: list[dict] = []
    offset = start
    while offset + 6 <= end:
        w_length, w_value_length, w_type = struct.unpack_from("<HHH", content, offset)
        if w_length < 6 or offset + w_length > end:
            break
        key_start = offset + 6
        key_end = content.find(b"\x00\x00", key_start, offset + w_length)
        if key_end == -1:
            break
        if (key_end - key_start) % 2:
            # The scan matched the high byte of the last key character
            # followed by the terminator's low byte; shift to the true NUL.
            key_end += 1
        try:
            key = content[key_start:key_end].decode("utf-16-le")
        except UnicodeDecodeError:
            break
        value_start = _align32(key_end + 2)
        # wValueLength counts bytes for binary values (wType 0, the fixed
        # block) and WORDS for text values (wType 1, keys and tables).
        value_bytes = w_value_length * 2 if w_type == 1 else w_value_length
        value_end = value_start + value_bytes
        if value_end > len(content):
            break
        value = content[value_start:value_end]
        children_start = _align32(value_end)
        nodes.append(
            {
                "key": key,
                "value": value,
                "w_type": w_type,
                "children_start": children_start,
                "end": offset + w_length,
            }
        )
        # Structures are DWORD-aligned; wLength can exclude the trailing
        # pad before the next sibling (real MSVC blobs do).
        offset = _align32(offset + w_length)
    return nodes


def _align32(offset: int) -> int:
    return offset + (-offset % 4)


def _parse_version_blob(content: bytes) -> tuple[dict | None, dict[str, dict[str, str]]]:
    """Decode VS_FIXEDFILEINFO and every language's string table.

    LIEF 1.0's version parser merges adjacent language tables (observed on
    a well-formed two-table blob), so the raw VERSION resource is decoded
    here instead — the fixed block, then the StringFileInfo tree, one dict
    per language key. Malformed regions contribute what decoded cleanly.
    """
    fixed = _find_fixed_file_info(content)
    strings: dict[str, dict[str, str]] = {}
    root = _walk_version_structures(content, 0, min(len(content), 0x400))
    if not root or root[0]["key"] != "VS_VERSION_INFO":
        return fixed, strings
    for child in _walk_version_structures(
        content, root[0]["children_start"], root[0]["end"]
    ):
        if child["key"] != "StringFileInfo" or child["w_type"] != 1:
            continue
        for table in _walk_version_structures(
            content, child["children_start"], child["end"]
        ):
            entries = strings.setdefault(table["key"], {})
            for entry in _walk_version_structures(
                content, table["children_start"], table["end"]
            ):
                if entry["w_type"] != 1 or not entry["value"]:
                    continue
                try:
                    entries[entry["key"]] = entry["value"].decode("utf-16-le").rstrip("\x00")
                except UnicodeDecodeError:
                    continue
    return fixed, strings


def parse_version_info(parsed_obj: lief.PE.Binary) -> dict:
    """Full VERSIONINFO: strings per language, fixed block, mismatch flag.

    ``present`` is a computed True (the caller gates on ``has_version``);
    the strings, the fixed block and the mismatches are separate keys so a
    consumer can tell a stringless fixed block from a parse that found
    nothing at all.
    """
    info: dict = {"present": False}
    try:
        rm = parsed_obj.resources_manager
        if not rm or isinstance(rm, lief.lief_errors) or not rm.has_version:
            return info
        # The raw resource is the single source: LIEF 1.0's own version
        # parse drops valid tables (and merges adjacent language tables),
        # so the block is decoded by _parse_version_blob instead.
        version_content = _version_resource_content(parsed_obj)
        if not version_content:
            return info
        fixed, strings = _parse_version_blob(version_content)
        mismatches = set()
        for field, fixed_key in (
            ("FileVersion", "file_version"),
            ("ProductVersion", "product_version"),
        ):
            fixed_version = fixed.get(fixed_key) if fixed else None
            for table in strings.values():
                string_version = table.get(field)
                if string_version and fixed_version and _is_mismatch(
                    fixed_version, string_version
                ):
                    mismatches.add(field)
        info = {
            "present": True,
            "languages": sorted(strings),
            "strings": strings,
        }
        if fixed:
            info["fixed"] = fixed
        if mismatches:
            info["mismatches"] = sorted(mismatches)
        return info
    except (AttributeError, TypeError, ValueError) as exc:
        LOG.debug(f"Unable to parse VERSIONINFO: {exc}")
        return info
