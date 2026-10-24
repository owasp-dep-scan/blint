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
  prefix (``_ERROR_FORMAT_EXUBERANT_NIBBLE``). When a build compiles the
  table out (.NET's ``libSystem.IO.Compression.Native``), the decoder's own
  defined API (``BrotliDecoderCreateInstance`` and friends) is the evidence
  instead. The record never carries a version: ``BrotliDecoderVersion``
  returns an immediate, and nothing else in the decoder records one as
  data. What the table does record is whether the CVE-2026-111497 fix is in.
  google/brotli 0ed4268 added the ``BLOCK_SWITCH`` error
  (``BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH``, -17), and every fixed build
  measured carries its name in the table, including the 1.0.9 backports
  (Debian ``1.0.9-2+deb12u1``) and the copies Node.js 24.22.1 bundles, whose
  own ``process.versions.brotli`` still reads 1.2.0.
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
use; ``properties`` become ``internal:`` properties on the SBOM component.
Absence of the key means nothing matched, never "verified absent".
"""

from __future__ import annotations

import re

import lief

from blint.lib.binary_common import is_string_bearing_section
from blint.logger import LOG

BROTLI_PURL = "pkg:generic/brotli"
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

# Export families only the .NET runtime pack's native libraries define.
DOTNET_EXPORT_RE = re.compile(
    r"^_?(?:coreclr_initialize$|hostfxr_|corehost_|SystemNative_|CompressionNative_"
    r"|CryptoNative_|GlobalizationNative_|SystemIOPortsNative_|AndroidCryptoNative_"
    r"|AppleCryptoNative_)"
)
DOTNET_SCCSID_MARKER = b"@(#)Version "
DOTNET_SCCSID_RE = re.compile(
    rb"@\(#\)Version (?P<file_version>\d+\.\d+\.\d+\.\d+) @Commit: (?P<commit>[0-9a-f]{7,40})"
)
DOTNET_PRODUCT_VERSION_RE = re.compile(
    r"^(?P<version>\d+\.\d+\.\d+)(?:\+(?P<commit>[0-9a-f]{7,40}))?$"
)


def _section_contents(parsed_obj) -> list[bytes]:
    """Contents of the sections that hold program strings and data."""
    contents: list[bytes] = []
    sections = getattr(parsed_obj, "sections", None)
    if not sections or isinstance(sections, lief.lief_errors):
        return contents
    for section in sections:
        if not is_string_bearing_section(section):
            continue
        try:
            content = bytes(section.content)
        except (AttributeError, TypeError, ValueError):
            continue
        if content:
            contents.append(content)
    return contents


def _has_c_string(contents: list[bytes], value: str) -> bool:
    """Whether ``value`` occurs as a whole NUL-terminated C string.

    The byte before the match must not be printable, so ``RESERVED`` is not
    found inside ``_ERROR_FORMAT_RESERVED`` and a prefixed name is not read
    as its bare form.
    """
    needle = value.encode("ascii") + b"\x00"
    for content in contents:
        start = 0
        while (index := content.find(needle, start)) != -1:
            if index == 0 or not 0x20 <= content[index - 1] <= 0x7E:
                return True
            start = index + 1
    return False


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


def _brotli_record(contents: list[bytes], defined: set[str]) -> dict | None:
    """The brotli decoder record, or None when neither witness is present."""
    evidence: list[dict] = []
    tables: list[tuple[str, bool]] = []
    for form, prefix in (("prefixed", BROTLI_FORMAT_ERROR_PREFIX), ("bare", "")):
        found = [
            name for name in BROTLI_DISTINCTIVE_ERROR_NAMES
            if _has_c_string(contents, f"{prefix}{name}")
        ]
        if len(found) < BROTLI_MIN_DISTINCTIVE_NAMES:
            continue
        fixed = _has_c_string(contents, f"{prefix}{BROTLI_FIX_ERROR_NAME}")
        tables.append((form, fixed))
        evidence.append(
            {
                "what": f"BrotliDecoderErrorString error-name table ({form} names)",
                "where": "strings",
                "value": ", ".join(f"{prefix}{name}" for name in found),
            }
        )
        evidence.append(
            {
                "what": "CVE-2026-111497 fix marker (google/brotli 0ed4268)",
                "where": "strings",
                "value": f"{prefix}{BROTLI_FIX_ERROR_NAME} "
                + ("present" if fixed else "absent"),
            }
        )
    api_names = sorted(name for name in defined if BROTLI_DECODER_API_RE.match(name))
    if len(api_names) >= BROTLI_MIN_API_NAMES:
        evidence.append(
            {
                "what": "brotli decoder API defined in this artifact",
                "where": "symbols",
                "value": ", ".join(api_names[:6]),
            }
        )
    elif not tables:
        return None
    if not tables:
        fix_state = "unknown"
    elif all(fixed for _, fixed in tables):
        fix_state = "present"
    else:
        # Two copies of the decoder, one fixed and one not, still ship the
        # vulnerable one: report the weaker state.
        fix_state = "absent"
    return {
        "library": "brotli",
        "purl": BROTLI_PURL,
        "evidence": evidence,
        "properties": {
            "brotli_block_switch_fix": fix_state,
            "brotli_error_table": "+".join(form for form, _ in tables) or "none",
        },
    }


def _dotnet_version(
    metadata: dict, contents: list[bytes], file_version: str | None
) -> tuple[str | None, dict | None]:
    """The .NET product version from exact evidence, with that evidence."""
    product = (
        ((metadata.get("resources") or {}).get("version_metadata") or {}).get("ProductVersion")
        or ""
    )
    if match := DOTNET_PRODUCT_VERSION_RE.match(str(product).strip()):
        return match.group("version"), {
            "what": "PE ProductVersion resource",
            "where": "resources",
            "value": str(product).strip()[:80],
        }
    if not file_version:
        return None, None
    major, minor, build, _ = file_version.split(".")
    candidate = f"{major}.{minor}.{int(build) // 100}"
    if _has_c_string(contents, candidate):
        return candidate, {
            "what": "product version string agreeing with the stamped file version",
            "where": "strings",
            "value": candidate,
        }
    return None, None


def _dotnet_record(metadata: dict, contents: list[bytes], defined: set[str]) -> dict | None:
    """The .NET runtime record for a runtime-pack native library, or None."""
    exports = sorted(name for name in defined if DOTNET_EXPORT_RE.match(name))
    if not exports:
        return None
    evidence = [
        {
            "what": ".NET runtime pack native export family",
            "where": "symbols",
            "value": ", ".join(exports[:4]),
        }
    ]
    properties: dict[str, str] = {}
    file_version = None
    for content in contents:
        index = content.find(DOTNET_SCCSID_MARKER)
        if index == -1:
            continue
        if match := DOTNET_SCCSID_RE.match(content, index):
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
            break
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


def identify_embedded_libraries(parsed_obj, metadata: dict) -> list[dict]:
    """Run the embedded-code detectors over one parsed ELF, PE or Mach-O."""
    contents = _section_contents(parsed_obj)
    defined = _defined_symbol_names(metadata)
    records = []
    if record := _brotli_record(contents, defined):
        records.append(record)
    if record := _dotnet_record(metadata, contents, defined):
        records.append(record)
    return records


def attach_embedded_libraries(metadata: dict, parsed_obj) -> dict:
    """Wire-up for ``parse()``: store identifications under ``embedded_libraries``."""
    try:
        records = identify_embedded_libraries(parsed_obj, metadata)
    except (AttributeError, TypeError, ValueError) as e:
        LOG.debug(f"Embedded library identification failed: {type(e).__name__}: {e}")
        return metadata
    if records:
        metadata["embedded_libraries"] = records
    return metadata
