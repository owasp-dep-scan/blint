# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT
"""Vendored-source banner detection for static-linkage recovery.

A statically linked binary embeds whole libraries, and many vendored C
libraries leave a version banner in ``.rodata``. A banner is a strong claim
about a version and easy to misread from an unrelated string, so every
signature here requires the version to appear *inside* a string that also
names the library. A bare ``"3.46.0"`` is never a sqlite banner no matter how
likely that looks.

A banner string alone does not prove the code is in the artifact (F2b.2).
macOS measured both shapes on one system: ``libcrypto.0.9.7.dylib`` carries
"AES part of OpenSSL 0.9.7l 28 Sep 2006" AND exports the OpenSSL API
(BN_new, EVP_*, 2714 symbols) - the library itself, the banner true as
vendored code. ``assetutil`` links ``/usr/lib/libz.1.dylib`` dynamically,
defines no zlib symbol at all, and still carries "deflate 1.2.5 Copyright" -
a stale build-time banner naming a zlib that is not even the linked one
(1.2.12): a mention, not code. So a detected banner is a *mention* -
recorded for visibility, never a component - only when the artifact
defines none of the library's API *and* shows the code living elsewhere
(it links the library's shared object or imports its API). Absence of
defined symbols alone is not enough: a stripped image with
hidden-visibility vendored code has none in its dynamic table.
"""

import re

# Named states for the banner layer, reported alongside its matches so that
# "scanned and found nothing" is never indistinguishable from "no strings to
# scan".
BANNER_LAYER_ACTIVE = "active"
BANNER_LAYER_INACTIVE_NO_STRINGS = "inactive_no_strings"

# Each signature: the library name, the generic purl base (version appended at
# detection time), and a regex that must match within a single extracted
# string. The regex carries a ``version`` named group; a string can match a
# signature at most once (re.IGNORECASE where the upstream banner case varies).
# API anchor per library: symbols the library itself exports (prefix form -
# API families share prefixes: deflateInit_/_end are deflate's). A detected
# banner corroborated by at least one such *defined* (not imported) symbol
# means the artifact carries the library's code; imports do not count,
# because a dynamically linked client imports the API while owning none of
# it. Compact family prefixes only - never a full symbol dump.
# Leading underscore (Mach-O) and case-insensitive: the same export reads
# _BN_new in nm, _bn_new in a dyld-cache symtab and BN_new in an ELF dynsym.
BANNER_API_ANCHORS = {
    "zlib": re.compile(r"^_?(?:deflate|inflate|zlibVersion|compress|uncompress|crc32|adler32)", re.IGNORECASE),
    "lua": re.compile(r"^_?(?:lua_|luaL_)", re.IGNORECASE),
    "openssl": re.compile(
        r"^_?(?:BN_|EVP_|AES_|RSA_|DH_|DSA_|SHA[0-9]|SHA3|MD5|SSLeay|OPENSSL_|ERR_|X509|ASN1)",
        re.IGNORECASE,
    ),
    "curl": re.compile(r"^_?curl_", re.IGNORECASE),
    "expat": re.compile(r"^_?(?:XML_|expat_)", re.IGNORECASE),
    "libpng": re.compile(r"^_?png_", re.IGNORECASE),
    "zstd": re.compile(r"^_?ZSTD_", re.IGNORECASE),
}

# The library's own shared object, by name, for deciding whether a banner's
# code demonstrably lives outside the artifact (the artifact links it).
BANNER_LIBRARY_LINK_NAMES = {
    "zlib": re.compile(r"(?:^|/)libz\.", re.IGNORECASE),
    "lua": re.compile(r"(?:^|/)liblua", re.IGNORECASE),
    "openssl": re.compile(r"(?:^|/)lib(?:crypto|ssl)\.", re.IGNORECASE),
    "curl": re.compile(r"(?:^|/)libcurl\.", re.IGNORECASE),
    "expat": re.compile(r"(?:^|/)libexpat\.", re.IGNORECASE),
    "libpng": re.compile(r"(?:^|/)libpng", re.IGNORECASE),
    "zstd": re.compile(r"(?:^|/)libzstd\.", re.IGNORECASE),
}

BANNER_SIGNATURES = (
    {
        "library": "zlib",
        "purl": "pkg:generic/zlib",
        # "deflate"/"inflate" name an algorithm, not the library, and both are
        # ordinary verbs — "failed to inflate 1.5 MB" is not a zlib banner. The
        # copyright line is what makes the string zlib's own; every real copy
        # emits it (deflate.c and inflate.c both carry it verbatim).
        "regex": re.compile(
            r"\bdeflate (?P<version>\d+\.\d+(?:\.\d+)?)\s+Copyright", re.IGNORECASE
        ),
    },
    {
        "library": "zlib",
        "purl": "pkg:generic/zlib",
        "regex": re.compile(
            r"\binflate (?P<version>\d+\.\d+(?:\.\d+)?)\s+Copyright", re.IGNORECASE
        ),
    },
    {
        "library": "lua",
        "purl": "pkg:generic/lua",
        "regex": re.compile(r"\bLua (?P<version>\d+\.\d+(?:\.\d+)?)\s+Copyright", re.IGNORECASE),
    },
    {
        "library": "openssl",
        "purl": "pkg:generic/openssl",
        "regex": re.compile(r"\bOpenSSL[ /](?P<version>\d+\.\d+\.\d+[a-z]*)\b", re.IGNORECASE),
    },
    {
        "library": "curl",
        "purl": "pkg:generic/curl",
        "regex": re.compile(r"\blibcurl/(?P<version>\d+\.\d+(?:\.\d+)?)\b", re.IGNORECASE),
    },
    {
        "library": "expat",
        "purl": "pkg:generic/expat",
        "regex": re.compile(r"\bexpat_(?P<version>\d+\.\d+(?:\.\d+)?)\b", re.IGNORECASE),
    },
    {
        "library": "libpng",
        "purl": "pkg:generic/libpng",
        "regex": re.compile(r"\blibpng version (?P<version>\d+\.\d+(?:\.\d+)?)\b", re.IGNORECASE),
    },
    {
        "library": "zstd",
        "purl": "pkg:generic/zstandard",
        "regex": re.compile(r"\bZstandard v(?P<version>\d+\.\d+\.\d+)\b", re.IGNORECASE),
    },
)

# Candidate libraries measured and deliberately left out. Each entry records
# what the measurement found, so a future change re-measures instead of
# re-litigating from memory.
REJECTED_SIGNATURES = (
    {
        "library": "sqlite3",
        "reason": (
            "version is not an extractable string in current amalgamations: "
            "SQLITE_SOURCE_ID carries only 'date time hash' and SQLITE_VERSION "
            "('3.46.0') is merged into neighboring data rather than emitted as "
            "a standalone string, so neither an in-string banner nor an "
            "anchor+bare-version pairing can claim a version precisely. "
            "Version recovery for sqlite belongs to the hash layers."
        ),
    },
)


def _iter_string_values(metadata: dict) -> list[str]:
    """Return the extracted string values a banner scan reads."""
    strings = metadata.get("strings")
    if not isinstance(strings, list):
        return []
    values = []
    for entry in strings:
        if isinstance(entry, dict) and entry.get("value"):
            values.append(str(entry["value"]))
        elif isinstance(entry, str) and entry:
            values.append(entry)
    return values


def is_probable_banner_string(value: str) -> bool:
    """Whether a raw string matches one of the banner signatures.

    Used by the string extractor to keep banner-bearing strings whose entropy
    and length would otherwise drop them (a version banner is short, plain
    text). The keep set is bounded by the signature table — library-name
    anchored only, never a generic version-shape rule — so the metadata size
    cost is a handful of strings per binary.
    """
    return any(signature["regex"].search(value) for signature in BANNER_SIGNATURES)


def _defined_api_symbol_counts(metadata: dict) -> dict[str, int]:
    """Count the artifact's *defined* symbols matching each library's API.

    Imported symbols do not count: a dynamically linked client imports the
    whole API while owning none of the code.
    """
    counts: dict[str, int] = {library: 0 for library in BANNER_API_ANCHORS}
    for bucket in ("dynamic_symbols", "symtab_symbols"):
        for symbol in metadata.get(bucket) or []:
            if not isinstance(symbol, dict) or symbol.get("is_imported"):
                continue
            name = symbol.get("name") or ""
            if not name:
                continue
            for library, anchor in BANNER_API_ANCHORS.items():
                if anchor.match(name):
                    counts[library] += 1
    return counts


def _provided_externally(metadata: dict, library: str) -> bool:
    """Whether the library's code demonstrably lives outside the artifact.

    Two witnesses: the artifact links the library's own shared object
    (DT_NEEDED / LC_LOAD_DYLIB), or it imports symbols from the library's
    API. Absence of defined API symbols alone is not a witness - a stripped
    shared object that embeds OpenSSL with hidden visibility defines none in
    its dynamic table and still carries the code.
    """
    link_name = BANNER_LIBRARY_LINK_NAMES.get(library)
    if link_name:
        for entry in metadata.get("dynamic_entries") or []:
            if (
                isinstance(entry, dict)
                and entry.get("tag") == "NEEDED"
                and link_name.search(str(entry.get("name") or ""))
            ):
                return True
        for dylib in metadata.get("libraries") or []:
            if isinstance(dylib, dict) and link_name.search(str(dylib.get("name") or "")):
                return True
    anchor = BANNER_API_ANCHORS.get(library)
    if anchor:
        for bucket in ("dynamic_symbols", "symtab_symbols", "imports"):
            for symbol in metadata.get(bucket) or []:
                if (
                    isinstance(symbol, dict)
                    and (symbol.get("is_imported") or bucket == "imports")
                    and anchor.match(str(symbol.get("name") or "").rsplit("::", 1)[-1])
                ):
                    return True
    return False


def detect_vendored_banners(metadata: dict) -> dict:
    """Scan extracted strings for vendored-source version banners.

    Returns a dict with a ``banners`` list of corroborated matches
    (``library``, ``version``, ``purl``, ``banner`` — the matched string,
    truncated — and ``api_symbol_count``), a ``mentions`` list of
    banner-shaped strings the artifact's own symbols do not corroborate
    (same entry shape), and a ``state`` naming why the layer did or did not
    run. Multiple versions of the same library are reported separately:
    merging them into one would hide the ambiguity a conflicting pair
    reveals.
    """
    string_values = _iter_string_values(metadata)
    if not string_values:
        return {"banners": [], "mentions": [], "state": BANNER_LAYER_INACTIVE_NO_STRINGS}
    api_counts = _defined_api_symbol_counts(metadata)
    banners = []
    mentions = []
    seen = set()
    for value in string_values:
        # A single string is scanned against every signature; banners are
        # short, so a length bound keeps the scan proportional to the
        # interesting strings rather than every extracted blob.
        if len(value) > 512:
            continue
        for signature in BANNER_SIGNATURES:
            match = signature["regex"].search(value)
            if not match:
                continue
            version = match.group("version")
            key = (signature["library"], version)
            if key in seen:
                continue
            seen.add(key)
            entry = {
                "library": signature["library"],
                "version": version,
                "purl": f"{signature['purl']}@{version}",
                "banner": value[:256],
            }
            # A mention only when the artifact defines none of the API and the
            # code demonstrably lives elsewhere (it links or imports the
            # library): a stale build-time string. Otherwise a component
            # claim - corroborated by defined API symbols, or undisproved in
            # a stripped image that has nowhere else for the code to be.
            api_count = api_counts.get(signature["library"], 0)
            if api_count == 0 and _provided_externally(metadata, signature["library"]):
                mentions.append(entry)
            else:
                entry["api_symbol_count"] = api_count
                banners.append(entry)
    return {"banners": banners, "mentions": mentions, "state": BANNER_LAYER_ACTIVE}
