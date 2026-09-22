"""Cabinet (MSCF) archive reader (W4.2).

CABs are what MSI carries (drivers, update packages, the merged installer
payload), so a scanner that cannot open one cannot see what an installer
actually ships. Format: a CFHEADER, per-folder CFFOLDER entries (each with
its compression method and CFDATA block count) and per-file CFFILE entries;
data blocks are per-folder. Stored (0) and MSZIP (1) decode with the
stdlib; Quantum (2/3) and LZX (4) do not — a member whose folder uses them
refuses by name (``member_compression_unsupported``) rather than silently
listing as analyzable.

Bounds (ground rules 30/33) measured on the corpus CABs plus the merged
``product.cab`` inside 7z-x64.msi (1.9 MB, thousands of members): 16,384
members listed (cap), 512 MiB total uncompressed (cap), 256 MiB per member
(cap), 64 MiB per CFDATA block decode (cap), member path depth 16 (cap).
Hostile fixtures exceed each cap in ``tests/test_cab.py``.

Extraction goes through the shared bounded framework (``container.py``):
streamed per-member writes under the size cap, cleanup owned by the caller
through the standard try/finally contract, leak tests asserting the
temp-directory delta rather than reading code.
"""

# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
# SPDX-License-Identifier: Apache-2.0

import os
import struct
import zlib

from blint.lib.container import member_path_unsafe
from blint.logger import LOG

CAB_MAGIC = b"MSCF"

# Per-folder compression methods.
METHOD_NONE = 0
METHOD_MSZIP = 1
METHOD_QUANTUM = 2
METHOD_LZX = 3
METHOD_NAMES = {METHOD_NONE: "none", METHOD_MSZIP: "mszip", 2: "quantum", 3: "lzx"}

# Measured caps — see module docstring.
MAX_CAB_MEMBERS = 16384
MAX_CAB_TOTAL_UNCOMPRESSED = 512 * 1024 * 1024
MAX_CAB_MEMBER_SIZE = 256 * 1024 * 1024
MAX_CAB_MEMBER_DEPTH = 16
MAX_CAB_DATA_BLOCK = 64 * 1024 * 1024

# MSZIP blocks carry a two-byte signature ahead of the deflate stream.
_MSZIP_SIG = b"CK"


def is_cab_file(path: str) -> bool:
    try:
        with open(path, "rb") as handle:
            return handle.read(4) == CAB_MAGIC
    except OSError:
        return False


def _read_entries(data: bytes, refusals: list[str]) -> dict:
    """Parse CFHEADER, folders and file entries from the cabinet image."""
    out: dict = {"folders": [], "files": [], "flags": 0, "set_id": None, "version": None}
    if len(data) < 36:
        refusals.append("archive_unreadable")
        return out
    (
        _sig,
        _res1,
        cb_cabinet,
        _res2,
        coff_files,
        _res3,
        version_minor,
        version_major,
        num_folders,
        num_files,
        flags,
        set_id,
        _cab_id,
    ) = struct.unpack("<4sIIIIIBBHHHHH", data[:36])
    out["flags"] = flags
    out["set_id"] = set_id
    out["version"] = f"{version_major}.{version_minor}"
    if len(data) < cb_cabinet:
        refusals.append("archive_truncated")
    offset = 36
    if flags & 0x4:  # reserve present
        (reserve_size,) = struct.unpack("<H", data[offset : offset + 2])
        offset += 4 + reserve_size
    if flags & 0x1:
        refusals.append("prev_cabinet_not_followed")
        offset += 256  # szCabinetPrev (null-terminated, 256 max)
    if flags & 0x2:
        refusals.append("prev_disk_not_followed")
        offset += 256
    folders = []
    for index in range(min(num_folders, 4096)):
        if offset + 8 > len(data):
            refusals.append("archive_truncated")
            break
        (coff_data, num_data_blocks, method_ab) = struct.unpack("<IHH", data[offset : offset + 8])
        folders.append(
            {
                "index": index,
                "data_offset": coff_data,
                "num_blocks": num_data_blocks,
                "method": method_ab & 0x0F,
            }
        )
        offset += 8
    out["folders"] = folders
    entries = []
    file_base = coff_files
    if num_files > MAX_CAB_MEMBERS:
        refusals.append("member_count_exceeds_cap")
    for _index in range(min(num_files, MAX_CAB_MEMBERS)):
        if file_base + 17 > len(data):
            refusals.append("archive_truncated")
            break
        (size, uncomp_offset, folder_index, _date, _time, attrs_raw) = struct.unpack(
            "<IIHHHH", data[file_base : file_base + 16]
        )
        # The name runs to the NUL; attribs bit 0x80 marks it UTF-8.
        name_bytes = data[file_base + 16 :]
        name = name_bytes.split(b"\x00", 1)[0]
        if attrs_raw & 0x80:
            member_name = name.decode("utf-8", "replace")
        else:
            member_name = name.decode("latin-1", "replace")
        entries.append(
            {
                "name": member_name,
                "size": size,
                "offset": uncomp_offset,
                "folder": folder_index & 0x3FFF,
                "attrs": attrs_raw,
                "is_utf8": bool(attrs_raw & 0x80),
            }
        )
        file_base += 16 + len(name) + 1
    out["files"] = entries
    return out


def _decode_folder(data: bytes, folder: dict, refusals: list[str]) -> bytes | None:
    """Decode one folder's CFDATA blocks into its uncompressed bytes.

    Bounded: the cumulative decode is capped at MAX_CAB_DATA_BLOCK and the
    loop at the folder's declared block count. Method outside none/mszip
    refuses by name.
    """
    method = folder["method"]
    if method not in (METHOD_NONE, METHOD_MSZIP):
        refusals.append("member_compression_unsupported")
        return None
    out = []
    total = 0
    offset = folder["data_offset"]
    for _index in range(folder["num_blocks"]):
        if offset + 8 > len(data):
            refusals.append("archive_truncated")
            break
        _checksum, raw_size, uncomp_size = struct.unpack("<IHH", data[offset : offset + 8])
        block = data[offset + 8 : offset + 8 + raw_size]
        if uncomp_size and total + uncomp_size > MAX_CAB_DATA_BLOCK:
            refusals.append("member_size_exceeds_cap")
            break
        if method == METHOD_NONE:
            out.append(block[:uncomp_size])
            total += len(block[:uncomp_size])
        else:
            if len(block) < 2 or block[:2] != _MSZIP_SIG:
                refusals.append("member_unreadable")
                break
            try:
                chunk = zlib.decompressobj(wbits=-15).decompress(block[2:])
            except zlib.error:
                refusals.append("member_unreadable")
                break
            out.append(chunk)
            total += len(chunk)
        offset += 8 + raw_size
        if total > MAX_CAB_DATA_BLOCK:
            refusals.append("member_size_exceeds_cap")
            break
    return b"".join(out) if out else b""


def parse_cab(path: str) -> dict:
    """Parse one cabinet file into blint's facts block.

    Members are listed with sizes, folder method and path-safety verdicts;
    refused members are named (unsafe paths, unsupported compression,
    truncated archives) and never read as absent (rule 32). No member bytes
    are decompressed on this path.
    """
    block: dict = {
        "parse_status": "parsed",
        "version": None,
        "member_count": 0,
        "members": [],
        "folder_count": 0,
        "methods": [],
        "total_uncompressed": 0,
        "refusals": [],
        "degradations": [],
    }
    refusals = block["refusals"]
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError:
        block["parse_status"] = "failed"
        block["refusals"].append("archive_unreadable")
        return block
    if data[:4] != CAB_MAGIC:
        block["parse_status"] = "failed"
        block["refusals"].append("not_a_cab")
        return block
    parsed = _read_entries(data, refusals)
    block["version"] = parsed["version"]
    block["folder_count"] = len(parsed["folders"])
    block["methods"] = sorted({METHOD_NAMES.get(f["method"], "unknown") for f in parsed["folders"]})
    members = []
    total = 0
    for entry in parsed["files"]:
        if len(members) >= MAX_CAB_MEMBERS:
            refusals.append("member_count_exceeds_cap")
            break
        normalized = entry["name"].replace("\\", "/")
        unsafe = member_path_unsafe(normalized)
        total += entry["size"]
        if total > MAX_CAB_TOTAL_UNCOMPRESSED:
            refusals.append("total_uncompressed_exceeds_cap")
            break
        members.append(
            {
                "name": normalized,
                "size": entry["size"],
                "unsafe_path": unsafe,
            }
        )
    block["member_count"] = len(parsed["files"])
    block["members"] = members
    if block["member_count"] > len(members):
        refusals.append("member_count_exceeds_cap")
    if len(members) < len(parsed["files"]):
        block["member_count"] = len(parsed["files"])
    block["total_uncompressed"] = sum(m["size"] for m in members)
    if refusals:
        block["parse_status"] = "partial"
    LOG.debug("CAB parsed: %d members, %d folders", block["member_count"], block["folder_count"])
    return block


def extract_cab_members(
    path: str,
    dest_dir: str,
    refusals: list[str],
    *,
    member_size_cap: int = MAX_CAB_MEMBER_SIZE,
) -> dict[str, str]:
    """Extract (some) members of a cabinet into ``dest_dir``.

    Only members in folders whose method the stdlib can decode are written;
    refusals name the rest. Returns member name → extracted path for the
    members that extracted cleanly. The caller owns ``dest_dir`` cleanup.
    """
    extracted: dict[str, str] = {}
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError:
        refusals.append("archive_unreadable")
        return extracted
    if data[:4] != CAB_MAGIC:
        refusals.append("not_a_cab")
        return extracted
    parsed = _read_entries(data, refusals)
    folder_cache: dict[int, bytes | None] = {}
    written = 0
    for entry in parsed["files"]:
        if len(extracted) + len(refusals) > MAX_CAB_MEMBERS:
            refusals.append("member_count_exceeds_cap")
            break
        normalized = entry["name"].replace("\\", "/")
        if member_path_unsafe(normalized):
            refusals.append("member_path_unsafe")
            continue
        if entry["size"] > member_size_cap:
            refusals.append("member_size_exceeds_cap")
            continue
        folder_index = entry["folder"]
        if folder_index not in folder_cache:
            folder = next(
                (f for f in parsed["folders"] if f.get("index") == folder_index),
                None,
            )
            folder_cache[folder_index] = _decode_folder(data, folder, refusals) if folder else None
        blob = folder_cache[folder_index]
        if blob is None:
            continue
        chunk = blob[entry["offset"] : entry["offset"] + entry["size"]]
        if len(chunk) < entry["size"]:
            refusals.append("archive_truncated")
            continue
        dest = os.path.join(dest_dir, *normalized.split("/"))
        parent = os.path.dirname(dest)
        if parent:
            os.makedirs(parent, exist_ok=True)
        try:
            with open(dest, "wb") as out:
                out.write(chunk)
        except OSError:
            refusals.append("member_unreadable")
            continue
        written += len(chunk)
        if written > MAX_CAB_TOTAL_UNCOMPRESSED:
            refusals.append("total_uncompressed_exceeds_cap")
            break
        extracted[normalized] = dest
    return extracted
