# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT
"""Embedded native code that leaves no version banner.

The banner layer (``blint.lib.banners``) claims a library only from a string
that names it together with a version. Two kinds of embedded code that matter
for vulnerability work leave no such string, so they are identified here
from other exact evidence and stored under ``metadata["embedded_libraries"]``:

- The google/brotli C decoder. ``BrotliDecoderErrorString`` (c/dec/decode.c)
  compiles the decoder's error names into the binary as plain C strings, so
  the table survives stripping and hidden visibility. Brotli 1.0.x returns
  the bare name (``EXUBERANT_NIBBLE``); 1.1.0 onwards returns it with its
  prefix (``_ERROR_FORMAT_EXUBERANT_NIBBLE``). lld ``-O2`` and
  ``lld-link /OPT:ICF`` merge string tails, so the decoder's names can be
  left only as the tails of Node.js's ``BROTLI_DECODER_ERROR_FORMAT_*``
  constants; next to the decoder's own tables (``kCodeLengthCodeOrder`` and
  ``kCodeLengthPrefixValue``) or its defined API, those constants stand for
  the decoder's names. When a build compiles the names out (.NET's
  ``libSystem.IO.Compression.Native``, ``--gc-sections``, LTO), the
  decoder's own defined API or its tables are the evidence instead and the
  fix state is unknown. The Rust port (brotli-decompressor), which is not
  affected, defines the same C API in its FFI shim and carries the same
  tables, so neither counts when its crate name is in the artifact; nor do
  the tables in a Go binary, where they are the Go port's. The record never
  carries a version: ``BrotliDecoderVersion`` returns an immediate, and
  nothing else in the decoder records one as data. What the table does
  record is whether the CVE-2026-111497 fix is in. google/brotli 0ed4268
  added the ``BLOCK_SWITCH`` error
  (``BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH``, -17), and every fixed build
  measured carries its name in the table, including the 1.0.9 backports
  (Debian ``1.0.9-2+deb12u1``) and the copies Node.js 24.22.1 bundles, whose
  own ``process.versions.brotli`` still reads 1.2.0. Every slice of a
  universal Mach-O is read, and the weakest state of any copy wins.
- The .NET runtime pack's native libraries (``libcoreclr``, ``libhostfxr``,
  ``libhostpolicy``, ``libSystem.*.Native`` and their PE and Mach-O
  equivalents). They are recognised by their own export families. The native
  build stamps each one with ``@(#)Version <file version> @Commit: <sha>``
  (dotnet/runtime eng/native/version), and the product version is taken only
  when an exact source names it: the PE ``ProductVersion`` resource, or a
  ``<major>.<minor>.<patch>`` string that agrees with the stamped file
  version (whose build part is ``patch * 100 + yy`` in the Arcade scheme).
  The file version alone maps a release candidate onto the same number as
  its GA release, so a stamp without a matching product string stays
  versionless and records the file version and commit instead.

Each record is ``{library, purl, version?, cpe?, evidence, properties}``.
``evidence`` uses the ``{what, where, value}`` shape the framework records
use; ``properties`` describe the copy in this file (its fix state, its build
stamp), so the SBOM puts them on the file's own component, while the
library component the file depends on is shared by every file that embeds
the same library. Absence of the key means nothing matched, never
"verified absent".
"""

from __future__ import annotations

import re

import lief

from blint.lib.binary_common import is_string_bearing_section
from blint.logger import LOG

# The shared component every embedding file depends on, named as cdxgen names
# it (lib/inventory/brotliDecoder.js): the vcs_url keeps it apart from a file
# whose own name is brotli, and from blintdb rows for packaged builds.
BROTLI_PURL = "pkg:generic/brotli?vcs_url=git%2Bhttps:%2F%2Fgithub.com%2Fgoogle%2Fbrotli"
BROTLI_BOM_REF = "pkg:generic/brotli?vcs_url=git+https://github.com/google/brotli"
DOTNET_RUNTIME_PURL = "pkg:github/dotnet/runtime"
DOTNET_RUNTIME_CPE = "cpe:2.3:a:microsoft:.net:{version}:*:*:*:*:*:*:*"

# Error names only the brotli decoder's own table carries. Generic members of
# the table (RESERVED, DISTANCE, TRANSFORM) are left out: on their own they
# are ordinary words, so they could never identify the decoder.
BROTLI_DISTINCTIVE_ERROR_NAMES = (
    "EXUBERANT_NIBBLE",
    "EXUBERANT_META_NIBBLE",
    "SIMPLE_HUFFMAN_ALPHABET",
    "SIMPLE_HUFFMAN_SAME",
    "CONTEXT_MAP_REPEAT",
)
BROTLI_FORMAT_ERROR_PREFIX = "_ERROR_FORMAT_"
# Node.js's zlib.constants names: the brotli headers' enum, compiled as data.
# Alone they are no decoder (a Node.js linked to a shared libbrotlidec has
# them); see _brotli_record for when they stand for the decoder's names.
BROTLI_CONSTANT_PREFIX = "BROTLI_DECODER_ERROR_FORMAT_"
BROTLI_FIX_ERROR_NAME = "BLOCK_SWITCH"
# How many distinctive names make a table: one name could be a coincidence,
# the full table carries all five.
BROTLI_MIN_DISTINCTIVE_NAMES = 3
# The decoder's public API. Two defined names are required, so a wrapper
# that happens to define one function of the same name is not a decoder.
BROTLI_DECODER_API_RE = re.compile(
    r"^_?BrotliDecoder(?:CreateInstance|DecompressStream|Decompress|SetParameter"
    r"|DestroyInstance|ErrorString|GetErrorCode)$"
)
BROTLI_MIN_API_NAMES = 2
# static const uint8_t kCodeLengthCodeOrder[18] and kCodeLengthPrefixValue[16]
# (c/dec/decode.c). They stay when a linker drops the error-name table; the
# encoder keeps the first but not the second.
BROTLI_DECODER_TABLES = (
    bytes([1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
    bytes([0, 4, 3, 2, 0, 4, 3, 1, 0, 4, 3, 2, 0, 4, 3, 5]),
)
# The Rust port (brotli-decompressor) is not affected. Its crate name marks it:
# legacy and v0 mangling length-prefix it, demangled names path it, and panic
# messages name its source. The Ruby extension's C functions
# (brotli_decompressor_*) match none of these.
BROTLI_RUST_BYTE_MARKERS = (b"19brotli_decompressor", b"brotli-decompressor-")
BROTLI_RUST_NAME_MARKERS = ("19brotli_decompressor", "brotli_decompressor::")
# Weakest first: two copies, one fixed and one not, still ship the vulnerable one.
BROTLI_FIX_STATE_RANK = {"absent": 0, "unknown": 1, "present": 2}

# Export families only the .NET runtime pack's native libraries define.
DOTNET_EXPORT_RE = re.compile(
    r"^_?(?:coreclr_initialize$|hostfxr_|corehost_|SystemNative_|CompressionNative_"
    r"|CryptoNative_|GlobalizationNative_|SystemIOPortsNative_|AndroidCryptoNative_"
    r"|AppleCryptoNative_|jitStartup$|getJit$|jitBuildString$)"
)
# The .NET host executables (the dotnet muxer and every app's apphost) export
# nothing; they load hostfxr through these names and honour this variable.
DOTNET_HOST_STRINGS = ("hostfxr_main_startupinfo", "COREHOST_TRACE")
DOTNET_SCCSID_MARKER = b"@(#)Version "
DOTNET_SCCSID_RE = re.compile(
    rb"@\(#\)Version (?P<file_version>\d+\.\d+\.\d+\.\d+) @Commit: (?P<commit>[0-9a-f]{7,40})"
)
DOTNET_PRODUCT_VERSION_RE = re.compile(
    r"^(?P<version>\d+\.\d+\.\d+)(?:\+(?P<commit>[0-9a-f]{7,40}))?$"
)


# PE resources hold icons, manifests and an installer's payload, never the
# decoder or a runtime's strings, and can be hundreds of MB; the version
# resource is read by the PE parser instead.
SKIPPED_SECTIONS = {".rsrc"}


def _section_contents(parsed_obj) -> list[bytes]:
    """Contents of the sections that hold program strings and data."""
    contents: list[bytes] = []
    sections = getattr(parsed_obj, "sections", None)
    if not sections or isinstance(sections, lief.lief_errors):
        return contents
    for section in sections:
        if not is_string_bearing_section(section):
            continue
        if (getattr(section, "name", "") or "").lower() in SKIPPED_SECTIONS:
            continue
        try:
            content = bytes(section.content)
        except (AttributeError, TypeError, ValueError):
            continue
        if content:
            contents.append(content)
    return contents


def _count_c_string(contents: list[bytes], value: str) -> int:
    """How many times ``value`` occurs as a whole NUL-terminated C string.

    The byte before the match must not be printable, so ``RESERVED`` is not
    found inside ``_ERROR_FORMAT_RESERVED`` and a prefixed name is not read
    as its bare form.
    """
    needle = value.encode("ascii") + b"\x00"
    count = 0
    for content in contents:
        start = 0
        while (index := content.find(needle, start)) != -1:
            if index == 0 or not 0x20 <= content[index - 1] <= 0x7E:
                count += 1
            start = index + 1
    return count


def _has_c_string(contents: list[bytes], value: str) -> bool:
    """Whether ``value`` occurs as a whole NUL-terminated C string."""
    return _count_c_string(contents, value) > 0


def _has_bytes(contents: list[bytes], needle: bytes) -> bool:
    return any(needle in content for content in contents)


def _defined_symbol_names(metadata: dict) -> set[str]:
    """Names the artifact defines itself: exports and non-imported symbols."""
    names: set[str] = set()
    for bucket in ("dynamic_symbols", "symtab_symbols"):
        for symbol in metadata.get(bucket) or []:
            if not isinstance(symbol, dict) or symbol.get("is_imported"):
                continue
            name = symbol.get("short_name") or symbol.get("name")
            if name:
                names.add(str(name))
    for export in metadata.get("exports") or []:
        if isinstance(export, dict) and export.get("name"):
            names.add(str(export["name"]))
    return names


def _symbol_names(metadata: dict) -> set[str]:
    """Every symbol name the artifact carries, defined or imported."""
    names: set[str] = set()
    for bucket in ("dynamic_symbols", "symtab_symbols", "imports", "exports"):
        for symbol in metadata.get(bucket) or []:
            if isinstance(symbol, dict) and (name := symbol.get("name")):
                names.add(str(name))
    return names


def _is_rust_brotli(contents: list[bytes], names: set[str]) -> bool:
    """Whether the artifact carries the Rust port's crate."""
    if any(marker in name for name in names for marker in BROTLI_RUST_NAME_MARKERS):
        return True
    return any(_has_bytes(contents, marker) for marker in BROTLI_RUST_BYTE_MARKERS)


def _table_fix_state(contents: list[bytes], prefix: str) -> tuple[list[str], str] | None:
    """The distinctive names found under ``prefix`` and the fix state they show.

    One copy of the table holds each name once. When the distinctive names
    occur more often than the fix name, some copy lacks the fix, so the
    state is ``absent`` even though the name is present. Copies a linker
    merged into one string cannot be counted apart.
    """
    counts = {
        name: count
        for name in BROTLI_DISTINCTIVE_ERROR_NAMES
        if (count := _count_c_string(contents, f"{prefix}{name}"))
    }
    if len(counts) < BROTLI_MIN_DISTINCTIVE_NAMES:
        return None
    copies = max(counts.values())
    fixed = _count_c_string(contents, f"{prefix}{BROTLI_FIX_ERROR_NAME}")
    return sorted(counts), "present" if fixed and fixed >= copies else "absent"


def _brotli_record(
    contents: list[bytes],
    defined: set[str],
    names: set[str] | None = None,
    is_go: bool = False,
) -> dict | None:
    """The brotli decoder record, or None when no witness is present."""
    evidence: list[dict] = []
    tables: list[tuple[str, str]] = []
    for form, prefix in (("prefixed", BROTLI_FORMAT_ERROR_PREFIX), ("bare", "")):
        if not (found := _table_fix_state(contents, prefix)):
            continue
        found_names, state = found
        tables.append((form, state))
        evidence.append(
            {
                "what": f"BrotliDecoderErrorString error-name table ({form} names)",
                "where": "strings",
                "value": ", ".join(f"{prefix}{name}" for name in found_names),
            }
        )
        evidence.append(
            {
                "what": "CVE-2026-111497 fix marker (google/brotli 0ed4268)",
                "where": "strings",
                "value": f"{prefix}{BROTLI_FIX_ERROR_NAME} "
                + ("present" if state == "present" else "absent"),
            }
        )
    rust = _is_rust_brotli(contents, names if names is not None else defined)
    api_names = sorted(name for name in defined if BROTLI_DECODER_API_RE.match(name))
    has_api = len(api_names) >= BROTLI_MIN_API_NAMES and not rust
    has_tables = (
        not rust and not is_go and all(_has_bytes(contents, t) for t in BROTLI_DECODER_TABLES)
    )
    if not tables and (has_api or has_tables):
        # lld -O2 and lld-link /OPT:ICF leave the decoder's names only as the
        # tails of Node.js's constants. Beside the decoder itself (its API or
        # its tables) the constants come from the same brotli headers.
        if found := _table_fix_state(contents, BROTLI_CONSTANT_PREFIX):
            found_names, state = found
            tables.append(("constant", state))
            evidence.append(
                {
                    "what": "Node.js BROTLI_DECODER_ERROR_FORMAT_* constants beside the decoder",
                    "where": "strings",
                    "value": ", ".join(f"{BROTLI_CONSTANT_PREFIX}{n}" for n in found_names),
                }
            )
            evidence.append(
                {
                    "what": "CVE-2026-111497 fix marker (google/brotli 0ed4268)",
                    "where": "strings",
                    "value": f"{BROTLI_CONSTANT_PREFIX}{BROTLI_FIX_ERROR_NAME} "
                    + ("present" if state == "present" else "absent"),
                }
            )
    if has_api:
        evidence.append(
            {
                "what": "brotli decoder API defined in this artifact",
                "where": "symbols",
                "value": ", ".join(api_names[:6]),
            }
        )
    if has_tables:
        evidence.append(
            {
                "what": "brotli decoder tables (kCodeLengthCodeOrder, kCodeLengthPrefixValue)",
                "where": "data",
                "value": "present",
            }
        )
    if not tables and not has_api and not has_tables:
        return None
    fix_state = (
        min((state for _, state in tables), key=BROTLI_FIX_STATE_RANK.__getitem__)
        if tables
        else "unknown"
    )
    return {
        "library": "brotli",
        "purl": BROTLI_PURL,
        "evidence": evidence,
        "properties": {
            "brotli_block_switch_fix": fix_state,
            "brotli_error_table": "+".join(form for form, _ in tables) or "none",
        },
    }


def _merge_slice_records(records: list[tuple[str, dict]]) -> dict:
    """One brotli record for a universal Mach-O, the weakest slice winning."""
    if len(records) == 1:
        return records[0][1]
    states = [(arch, record["properties"]["brotli_block_switch_fix"]) for arch, record in records]
    merged = dict(records[0][1])
    merged["evidence"] = [
        {**item, "what": f"{arch}: {item['what']}"}
        for arch, record in records
        for item in record["evidence"]
    ]
    forms = []
    for _, record in records:
        for form in record["properties"]["brotli_error_table"].split("+"):
            if form != "none" and form not in forms:
                forms.append(form)
    merged["properties"] = {
        "brotli_block_switch_fix": min(
            (state for _, state in states), key=BROTLI_FIX_STATE_RANK.__getitem__
        ),
        "brotli_error_table": "+".join(forms) or "none",
        "brotli_slice_fix_states": ", ".join(f"{arch}={state}" for arch, state in states),
    }
    return merged


def _dotnet_version(
    metadata: dict, contents: list[bytes], file_version: str | None
) -> tuple[str | None, dict | None]:
    """The .NET product version from exact evidence, with that evidence."""
    product = (
        ((metadata.get("resources") or {}).get("version_metadata") or {}).get("ProductVersion")
        or ""
    )
    candidate = None
    if file_version:
        major, minor, build, _ = file_version.split(".")
        candidate = f"{major}.{minor}.{int(build) // 100}"
    if match := DOTNET_PRODUCT_VERSION_RE.match(str(product).strip()):
        if candidate and match.group("version") != candidate:
            # A resource that disagrees with the stamped build is not taken
            # over the stamp.
            return None, {
                "what": "PE ProductVersion resource disagreeing with the stamped file version",
                "where": "resources",
                "value": str(product).strip()[:80],
            }
        return match.group("version"), {
            "what": "PE ProductVersion resource",
            "where": "resources",
            "value": str(product).strip()[:80],
        }
    if candidate and _has_c_string(contents, candidate):
        return candidate, {
            "what": "product version string agreeing with the stamped file version",
            "where": "strings",
            "value": candidate,
        }
    return None, None


def _dotnet_stamp(contents: list[bytes]):
    """The first well-formed native build stamp in any section, or None.

    Every occurrence of the marker is tried: another ``@(#)Version`` string
    (an SCCS what-string of some other component) can come first.
    """
    for content in contents:
        start = 0
        while (index := content.find(DOTNET_SCCSID_MARKER, start)) != -1:
            if match := DOTNET_SCCSID_RE.match(content, index):
                return match
            start = index + 1
    return None


def _dotnet_record(metadata: dict, contents: list[bytes], defined: set[str]) -> dict | None:
    """The .NET runtime record for a runtime-pack native library, or None."""
    exports = sorted(name for name in defined if DOTNET_EXPORT_RE.match(name))
    if exports:
        evidence = [
            {
                "what": ".NET runtime pack native export family",
                "where": "symbols",
                "value": ", ".join(exports[:4]),
            }
        ]
    elif all(_has_c_string(contents, value) for value in DOTNET_HOST_STRINGS):
        evidence = [
            {
                "what": ".NET host (muxer or apphost) strings",
                "where": "strings",
                "value": ", ".join(DOTNET_HOST_STRINGS),
            }
        ]
    else:
        return None
    properties: dict[str, str] = {}
    file_version = None
    if match := _dotnet_stamp(contents):
        file_version = match.group("file_version").decode("ascii")
        properties["dotnet_file_version"] = file_version
        properties["dotnet_source_commit"] = match.group("commit").decode("ascii")
        evidence.append(
            {
                "what": "native build stamp (dotnet/runtime eng/native/version)",
                "where": "data",
                "value": match.group(0).decode("ascii"),
            }
        )
    version, version_evidence = _dotnet_version(metadata, contents, file_version)
    if version_evidence:
        evidence.append(version_evidence)
    if not version and not file_version:
        # An export family alone is a hint, not an identification: without
        # the build stamp or a version resource, nothing ties the file to a
        # runtime build.
        return None
    record = {
        "library": "dotnet-runtime",
        "purl": DOTNET_RUNTIME_PURL,
        "evidence": evidence,
        "properties": properties,
    }
    if version:
        record["version"] = version
        record["cpe"] = DOTNET_RUNTIME_CPE.format(version=version)
    return record


def _slice_contents_and_names(slice_obj) -> tuple[list[bytes], set[str], set[str]]:
    """Section bytes, defined names and all names of one universal slice."""
    contents = _section_contents(slice_obj)
    defined: set[str] = set()
    names: set[str] = set()
    for symbol in getattr(slice_obj, "symbols", None) or []:
        name = getattr(symbol, "name", "")
        if not name:
            continue
        names.add(name)
        # The same n_type category the primary slice's symbol buckets use.
        if not str(getattr(symbol, "category", "") or "").upper().endswith("UNDEFINED"):
            defined.add(name)
    return contents, defined, names


def _slice_label(slice_obj, index: int) -> str:
    try:
        return str(slice_obj.header.cpu_type).rsplit(".", 1)[-1].lower()
    except AttributeError:
        return f"slice{index}"


def identify_embedded_libraries(
    parsed_obj, metadata: dict, exe_file: str | None = None, contents: list[bytes] | None = None
) -> list[dict]:
    """Run the embedded-code detectors over one parsed ELF, PE or Mach-O.

    For a universal Mach-O, ``parsed_obj`` is the first slice; the brotli
    detector reads every slice from ``exe_file``, since each slice is a
    separate build and one may carry a different decoder.
    """
    if contents is None:
        contents = _section_contents(parsed_obj)
    defined = _defined_symbol_names(metadata)
    names = _symbol_names(metadata) | defined
    is_go = bool(metadata.get("go_formulation") or metadata.get("go_dependencies"))
    records = []
    brotli = _brotli_record(contents, defined, names, is_go)
    if metadata.get("is_universal") and exe_file:
        slice_records = []
        if brotli:
            slice_records.append((_slice_label(parsed_obj, 0), brotli))
        fat = lief.MachO.parse(exe_file)
        if fat and not isinstance(fat, lief.lief_errors):
            for index in range(1, len(fat)):
                slice_obj = fat.at(index)
                if not slice_obj or isinstance(slice_obj, lief.lief_errors):
                    continue
                slice_contents, slice_defined, slice_names = _slice_contents_and_names(slice_obj)
                if record := _brotli_record(slice_contents, slice_defined, slice_names, is_go):
                    slice_records.append((_slice_label(slice_obj, index), record))
        brotli = _merge_slice_records(slice_records) if slice_records else None
    if brotli:
        records.append(brotli)
    if record := _dotnet_record(metadata, contents, defined):
        records.append(record)
    return records


def attach_embedded_libraries(metadata: dict, parsed_obj, exe_file: str | None = None) -> dict:
    """Wire-up for ``parse()``: store identifications under ``embedded_libraries``."""
    try:
        contents = _section_contents(parsed_obj)
        records = identify_embedded_libraries(parsed_obj, metadata, exe_file, contents)
    except (AttributeError, TypeError, ValueError) as e:
        LOG.debug(f"Embedded library identification failed: {type(e).__name__}: {e}")
        return metadata
    if records:
        metadata["embedded_libraries"] = records
    return metadata
