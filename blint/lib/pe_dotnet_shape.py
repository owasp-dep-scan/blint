"""The shape a .NET application was published in (PE lane W3.3, plan 03/A.3).

`03/A.1` and `A.2` read the CLI metadata of an assembly that *has* CLI
metadata. Modern .NET also ships in three shapes where that reader alone
answers the wrong question:

- **ReadyToRun** carries IL *and* precompiled native code, so a report that
  says only "managed" understates what actually executes.
- **Single-file** publishes are a native apphost with every assembly
  appended after the sections. The host has no CLI header, so the managed
  payload - the assemblies that actually ship - is invisible to a reader
  that stops at the section table.
- **NativeAOT** has no CLI header at all. A file whose entire reason for
  existing is C#, reported as an ordinary native PE, is the failure this
  packet exists to prevent: absence of CLI metadata must not read as
  "not .NET" (ground rule 32).

Everything here is decided from measured facts, and the measurements are in
``tests/test_pe_dotnet_shape.py`` against the six publish shapes built with
the .NET 11 SDK on the Windows ARM64 VM (2026-09-21).

Two of those measurements shaped the code and are worth stating here:

- **The bundle signature is in every apphost, bundled or not.** The
  framework-dependent, self-contained and trimmed apphosts all carry the
  32-byte bundle signature at offset 71,856 - the .NET host template embeds
  it as a placeholder so the bundler can find where to write the header
  offset. What separates a real bundle is the ``int64`` immediately *before*
  the signature: 0 in an unbundled apphost, and the in-file offset of the
  bundle manifest in a bundled one (88,078,328 in the measured single-file
  app). Keying on the signature alone would label every .NET apphost on
  earth a single-file bundle.
- **ReadyToRun must be decided before the ILONLY flag.** The measured R2R
  assembly has ``cli_flags_value = 0x4`` - ILONLY is *clear* - so a
  mixed-mode test that runs first would claim C++/CLI for an ordinary R2R
  build.

False positives, measured before this shipped: over a full
``C:\\Windows\\System32`` on the VM - 3,984 PEs, 0 parse errors - the
classifier emits a shape for 15 files and stays silent on 3,969. The 15 are
7 ``il_only`` (genuine managed assemblies: AuthFWSnapin, srmlib, tzsync,
Windows.Help.Runtime and three Microsoft.Windows.Storage ones) and 8
``mixed_mode``, every one of them a real C++/CLI image - the MFC managed
interop DLLs (mfcm140 and its variants), dnscmmc and NAPCRYPT. There is not
one ``native_aot``, ``single_file_bundle`` or ``apphost`` among the 3,969
native PEs. The mixed-mode population is the only one with no synthetic
fixture behind it, because the SDK on the VM cannot produce a C++/CLI
assembly for ARM64; those eight files are its ground truth instead.

What this module deliberately does not claim: whether a publish was
framework-dependent, self-contained or trimmed. Those differ only in what
sits in the output *directory* (5, 200 and 27 files in the measurement),
not in any byte of the binary blint is handed, so reporting them would be a
value blint did not determine (ground rule 11).
"""

from __future__ import annotations

import contextlib
import os
import struct
from typing import Any

# The .NET single-file bundle signature (Microsoft.NET.HostModel
# BundleManifest.BundleSignature). Kept here rather than imported from
# pe_overlay so this module states the constant it reasons about; the two
# are pinned equal by a test.
BUNDLE_SIGNATURE = bytes(
    [
        0x8B, 0x12, 0x02, 0xB9, 0x6A, 0x61, 0x20, 0x38,
        0x72, 0x7B, 0x93, 0x02, 0x14, 0xD7, 0xA0, 0x32,
        0x13, 0xF5, 0xB9, 0xE6, 0xEF, 0xAE, 0x33, 0x18,
        0xEE, 0x3B, 0x2D, 0xCE, 0x24, 0xB3, 0x6A, 0xAE,
    ]
)

# The ReadyToRun header signature (READYTORUN_SIGNATURE, "RTR\0").
R2R_SIGNATURE = b"RTR\x00"

# COMIMAGE_FLAGS_ILONLY (ECMA-335 II.25.3.3.1).
COMIMAGE_FLAGS_ILONLY = 0x00000001

# Runtime data symbols a NativeAOT image exports. Measured: the NativeAOT
# console app exports exactly one name, DotNetRuntimeContractDescriptor.
# coreclr.dll exports it too, which is why the export alone is not the test
# - it is one of two conditions, and coreclr.dll fails the other.
NATIVE_AOT_EXPORTS = frozenset(
    {"DotNetRuntimeContractDescriptor", "DotNetRuntimeDebugHeader"}
)

# How many bundle members are listed. A single-file publish of an empty
# console app already carries 184, and a real application is larger, so the
# bound is set well above the shapes measured rather than at them. No rule
# reads this list - it is metadata for a reader and for the SBOM, not a
# detection surface - so the cap bounds metadata size and nothing else
# (the W3.2 lesson: a cap a rule reads is a detection boundary; this one is
# not, and that is why it may be a round number).
MAX_LISTED_BUNDLE_MEMBERS = 4096

# Bounds on the manifest walk itself, because the header offset comes from
# the file being analysed (ground rule 30). A path longer than this, or a
# member count beyond it, is a malformed claim rather than something to
# allocate for.
MAX_BUNDLE_MEMBER_PATH = 1024
MAX_BUNDLE_DECLARED_MEMBERS = 65536

# Bundle member types (Microsoft.NET.HostModel FileType).
BUNDLE_FILE_TYPES = {
    0: "unknown",
    1: "assembly",
    2: "native_binary",
    3: "deps_json",
    4: "runtime_config_json",
    5: "symbols",
}

# How far back from the end of the file the signature is looked for. The
# host writes it into the apphost's own data, so it sits inside the
# sections, not the overlay - the whole file is searched, but the search is
# a single rfind rather than a scan.
_READ_CHUNK = 1 << 20


def _read_7bit_length(data: bytes, pos: int) -> tuple[int, int] | None:
    """A .NET 7-bit-encoded length prefix. Returns (value, next position)."""
    value = 0
    shift = 0
    while True:
        if pos >= len(data) or shift > 28:
            return None
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7


def _read_bundle_string(data: bytes, pos: int) -> tuple[str, int] | None:
    header = _read_7bit_length(data, pos)
    if header is None:
        return None
    length, pos = header
    if length < 0 or length > MAX_BUNDLE_MEMBER_PATH or pos + length > len(data):
        return None
    return data[pos : pos + length].decode("utf-8", "replace"), pos + length


def read_bundle_manifest(data: bytes, header_offset: int) -> dict[str, Any] | None:
    """Decode the single-file bundle manifest at ``header_offset``.

    The layout is Microsoft.NET.HostModel's ``BundleManifest``: version
    pair, file count, bundle id, then (from major 2) the deps.json and
    runtimeconfig.json locations and a flags word, then one entry per
    embedded file. From major 6 each entry also carries a compressed size.
    Every field is bounds-checked against the buffer, because the offset
    that got us here came out of the file (ground rule 30).
    """
    if header_offset <= 0 or header_offset + 12 > len(data):
        return None
    major, minor, declared = struct.unpack_from("<IIi", data, header_offset)
    if major == 0 or major > 64 or declared < 0 or declared > MAX_BUNDLE_DECLARED_MEMBERS:
        return None
    pos = header_offset + 12
    parsed_id = _read_bundle_string(data, pos)
    if parsed_id is None:
        return None
    bundle_id, pos = parsed_id
    manifest: dict[str, Any] = {
        "version": f"{major}.{minor}",
        "bundle_id": bundle_id,
        "member_count": declared,
    }
    if major >= 2:
        if pos + 40 > len(data):
            return None
        fields = struct.unpack_from("<qqqqQ", data, pos)
        pos += 40
        if fields[1] > 0:
            manifest["deps_json_offset"] = fields[0]
            manifest["deps_json_size"] = fields[1]
        if fields[3] > 0:
            manifest["runtime_config_json_offset"] = fields[2]
            manifest["runtime_config_json_size"] = fields[3]
    members: list[dict[str, Any]] = []
    entry_size = 17 + (8 if major >= 6 else 0)
    for _index in range(declared):
        if pos + entry_size > len(data):
            manifest["members_truncated"] = True
            break
        offset, size = struct.unpack_from("<qq", data, pos)
        pos += 16
        compressed = 0
        if major >= 6:
            (compressed,) = struct.unpack_from("<q", data, pos)
            pos += 8
        file_type = data[pos]
        pos += 1
        parsed_path = _read_bundle_string(data, pos)
        if parsed_path is None:
            manifest["members_truncated"] = True
            break
        path, pos = parsed_path
        if len(members) < MAX_LISTED_BUNDLE_MEMBERS:
            member: dict[str, Any] = {
                "path": path,
                "offset": offset,
                "size": size,
                "type": BUNDLE_FILE_TYPES.get(file_type, f"unknown_{file_type}"),
            }
            if compressed:
                member["compressed_size"] = compressed
            members.append(member)
    manifest["members"] = members
    if declared > len(members) and not manifest.get("members_truncated"):
        manifest["members_listing_capped"] = True
    return manifest


def _find_bundle_signature(data: bytes) -> int:
    return data.rfind(BUNDLE_SIGNATURE)


def _section_rows(parsed_obj) -> list[tuple[str, int, int, int, int]]:
    """(name, virtual address, mapped size, raw offset, characteristics)."""
    rows: list[tuple[str, int, int, int, int]] = []
    with contextlib.suppress(AttributeError, TypeError, ValueError):
        for section in parsed_obj.sections:
            name = str(getattr(section, "name", "") or "")
            vaddr = int(getattr(section, "virtual_address", 0) or 0)
            vsize = int(getattr(section, "virtual_size", 0) or 0)
            raw = int(getattr(section, "sizeof_raw_data", 0) or 0)
            offset = int(getattr(section, "offset", 0) or 0)
            flags = int(getattr(section, "characteristics", 0) or 0)
            rows.append((name, vaddr, max(vsize, raw), offset, flags))
    return rows


def _export_names(metadata: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    for entry in metadata.get("exports") or []:
        if isinstance(entry, dict) and entry.get("name"):
            names.add(str(entry["name"]))
    return names


def _has_readytorun_header(data: bytes, sections) -> bool:
    """An RTR\\0 header sitting in initialized, non-executable data.

    NativeAOT emits a ReadyToRun header but publishes no data directory
    pointing at it, so it is found by its signature. A raw byte search is
    not enough on its own: the measured NativeAOT image also contains the
    four bytes inside ``.text`` as instruction encoding. Restricting the
    search to initialized non-executable sections, and requiring a
    plausible major version in the two bytes that follow, is what makes
    this a structural fact rather than a string hit - coreclr.dll, an
    ordinary native runtime DLL full of the same .NET strings, has no such
    header at all.
    """
    # IMAGE_SCN_CNT_INITIALIZED_DATA / IMAGE_SCN_MEM_EXECUTE.
    initialized, executable = 0x00000040, 0x20000000
    for _name, _vaddr, size, offset, flags in sections:
        if not flags & initialized or flags & executable:
            continue
        if offset <= 0 or size <= 0:
            continue
        window = data[offset : offset + size]
        start = 0
        while True:
            hit = window.find(R2R_SIGNATURE, start)
            if hit < 0:
                break
            if hit % 4 == 0 and hit + 8 <= len(window):
                major = struct.unpack_from("<H", window, hit + 4)[0]
                if 1 <= major <= 99:
                    return True
            start = hit + 4
    return False


def _readytorun_from_cli(parsed_obj, data: bytes, dotnet: dict[str, Any]) -> bool:
    """The managed path: the CLI header's ManagedNativeHeader is an R2R one."""
    rva = int(dotnet.get("managed_native_header_rva") or 0)
    size = int(dotnet.get("managed_native_header_size") or 0)
    if rva <= 0 or size <= 0:
        return False
    for _name, vaddr, mapped, offset, _flags in _section_rows(parsed_obj):
        if vaddr <= rva < vaddr + mapped and offset > 0:
            at = offset + (rva - vaddr)
            return data[at : at + 4] == R2R_SIGNATURE
    return False


def classify_dotnet_shape(
    parsed_obj, exe_file: str, metadata: dict[str, Any], dotnet: dict[str, Any] | None
) -> dict[str, Any] | None:
    """The ``shape`` block for one PE, or None when the file says nothing.

    Returns ``{"kind": ..., "evidence": [...]}`` and, for a single-file
    bundle, the decoded ``bundle`` manifest. ``None`` means "this file
    carries no evidence of being a .NET artifact of any shape" - it is not
    a claim that it is native, and nothing downstream may read it as one.
    """
    try:
        size = os.path.getsize(exe_file)
    except OSError:
        return None
    if size <= 0:
        return None
    try:
        with open(exe_file, "rb") as handle:
            data = handle.read()
    except (OSError, MemoryError):
        return None
    sections = _section_rows(parsed_obj)

    if dotnet is not None and dotnet.get("parse_status") != "malformed":
        evidence: list[str] = ["cli_header_present"]
        # Order matters and the measurement is why: the R2R assembly built
        # by the .NET 11 SDK has cli_flags_value 0x4, so ILONLY is clear on
        # an ordinary ReadyToRun build. A mixed-mode test that ran first
        # would call every R2R assembly C++/CLI.
        if _readytorun_from_cli(parsed_obj, data, dotnet):
            evidence.append("managed_native_header_readytorun")
            return {"kind": "ready_to_run", "evidence": evidence}
        if int(dotnet.get("managed_native_header_rva") or 0) > 0:
            # A native header blint cannot identify is named as that, not
            # folded into a shape it might not be (ground rule 14).
            evidence.append("managed_native_header_unrecognised")
            return {"kind": "native_image_unknown", "evidence": evidence}
        flags = int(dotnet.get("cli_flags_value") or 0)
        if not flags & COMIMAGE_FLAGS_ILONLY:
            evidence.append("ilonly_clear")
            return {"kind": "mixed_mode", "evidence": evidence}
        evidence.append("ilonly_set")
        return {"kind": "il_only", "evidence": evidence}

    # No CLI header. The remaining shapes are native images whose managed
    # origin has to be evidenced positively.
    marker = _find_bundle_signature(data)
    if marker >= 8:
        (header_offset,) = struct.unpack_from("<q", data, marker - 8)
        if 0 < header_offset < len(data):
            manifest = read_bundle_manifest(data, header_offset)
            if manifest is not None:
                return {
                    "kind": "single_file_bundle",
                    "evidence": [
                        "bundle_signature_present",
                        "bundle_header_offset_resolves",
                    ],
                    "bundle": manifest,
                }
            # The signature and a plausible offset, but no manifest we can
            # decode: say that, rather than downgrading to "apphost" and
            # implying the file carries no payload (rule 14).
            return {
                "kind": "single_file_bundle",
                "evidence": [
                    "bundle_signature_present",
                    "bundle_header_unreadable",
                ],
            }
        return {
            "kind": "apphost",
            "evidence": ["bundle_signature_placeholder_unwritten"],
        }
    exports = _export_names(metadata)
    aot_export = sorted(exports & NATIVE_AOT_EXPORTS)
    if aot_export and _has_readytorun_header(data, sections):
        return {
            "kind": "native_aot",
            "evidence": [
                f"runtime_export:{aot_export[0]}",
                "readytorun_header_in_data_section",
            ],
        }
    return None


# A deps.json past this is not a dependency manifest blint will read into
# memory: the largest measured (a self-contained console app, 184 members)
# is 27,856 bytes, and an application with thousands of packages is still
# far below this (ground rule 30 - the size comes out of the file).
MAX_DEPS_JSON_BYTES = 32 * 1024 * 1024


def read_bundle_deps_json(exe_file: str, manifest: dict[str, Any]) -> bytes | None:
    """The embedded ``deps.json`` of a single-file bundle, by offset.

    ``parse_overlay`` finds a deps.json by scanning the overlay for the
    ``{"runtimeTarget`` prefix, which is how a framework-dependent publish
    with an appended deps.json is read. It returns nothing on a real
    single-file bundle - measured, ``dotnet_dependencies`` is ``{}`` on the
    88 MB single-file publish - so the SBOM of the one shape that carries
    its whole dependency set inside the executable was empty. The manifest
    says exactly where the file is, so here it is read by offset instead of
    searched for.
    """
    offset = int(manifest.get("deps_json_offset") or 0)
    size = int(manifest.get("deps_json_size") or 0)
    if offset <= 0 or not 0 < size <= MAX_DEPS_JSON_BYTES:
        return None
    try:
        with open(exe_file, "rb") as handle:
            file_size = handle.seek(0, 2)
            if offset + size > file_size:
                return None
            handle.seek(offset)
            return handle.read(size)
    except OSError:
        return None
