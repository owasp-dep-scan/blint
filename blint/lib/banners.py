# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT
"""Vendored-source banner detection (P4.3 static-linkage recovery).

A statically linked binary embeds whole libraries, and many vendored C
libraries leave a version banner in ``.rodata``. A banner is a strong claim
about a version and easy to misread from an unrelated string, so every
signature here requires the version to appear *inside* a string that also
names the library. A bare ``"3.46.0"`` is never a sqlite banner no matter how
likely that looks.
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
        "regex": re.compile(
            r"\bLua (?P<version>\d+\.\d+(?:\.\d+)?)\s+Copyright", re.IGNORECASE
        ),
    },
    {
        "library": "openssl",
        "purl": "pkg:generic/openssl",
        "regex": re.compile(
            r"\bOpenSSL[ /](?P<version>\d+\.\d+\.\d+[a-z]*)\b", re.IGNORECASE
        ),
    },
    {
        "library": "curl",
        "purl": "pkg:generic/curl",
        "regex": re.compile(
            r"\blibcurl/(?P<version>\d+\.\d+(?:\.\d+)?)\b", re.IGNORECASE
        ),
    },
    {
        "library": "expat",
        "purl": "pkg:generic/expat",
        "regex": re.compile(
            r"\bexpat_(?P<version>\d+\.\d+(?:\.\d+)?)\b", re.IGNORECASE
        ),
    },
    {
        "library": "libpng",
        "purl": "pkg:generic/libpng",
        "regex": re.compile(
            r"\blibpng version (?P<version>\d+\.\d+(?:\.\d+)?)\b", re.IGNORECASE
        ),
    },
    {
        "library": "zstd",
        "purl": "pkg:generic/zstandard",
        "regex": re.compile(
            r"\bZstandard v(?P<version>\d+\.\d+\.\d+)\b", re.IGNORECASE
        ),
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


def detect_vendored_banners(metadata: dict) -> dict:
    """Scan extracted strings for vendored-source version banners.

    Returns a dict with a ``banners`` list of matches
    (``library``, ``version``, ``purl``, ``banner`` — the matched string,
    truncated) and a ``state`` naming why the layer did or did not run.
    Multiple versions of the same library are reported separately: merging
    them into one would hide the ambiguity a conflicting pair reveals.
    """
    string_values = _iter_string_values(metadata)
    if not string_values:
        return {"banners": [], "state": BANNER_LAYER_INACTIVE_NO_STRINGS}
    banners = []
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
            banners.append(
                {
                    "library": signature["library"],
                    "version": version,
                    "purl": f"{signature['purl']}@{version}",
                    "banner": value[:256],
                }
            )
    return {"banners": banners, "state": BANNER_LAYER_ACTIVE}
