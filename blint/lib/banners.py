# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT
"""Version-bearing strings: vendored-source banners, and version attribution.

A statically linked binary embeds whole libraries, and many vendored C
libraries leave a version banner in ``.rodata``. A banner is a strong claim
about a version and easy to misread from an unrelated string, so every
signature here requires the version to appear *inside* a string that also
names the library. A bare ``"3.46.0"`` is never a sqlite banner no matter how
likely that looks.

A banner string alone does not prove the code is in the artifact.
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

The same rule table dates a project that symbol evidence already identified
(``artifact_version``, blintdb's Android path). There a rule need not name
the library: a bare ``x.y.z`` counts when it is the artifact's only one, and
SQLite's build stamp is dated through sqlite.org's release chronology. A
component version never comes from the database row.
"""

import re

# Named states for the banner layer, reported alongside its matches so that
# "scanned and found nothing" is never indistinguishable from "no strings to
# scan".
BANNER_LAYER_ACTIVE = "active"
BANNER_LAYER_INACTIVE_NO_STRINGS = "inactive_no_strings"

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
}

# OPENSSL_VERSION_TEXT as a whole string, "OpenSSL 3.0.2 15 Mar 2022": the
# form the framework detector needs before it calls a file OpenSSL.
OPENSSL_VERSION_TEXT_RE = re.compile(
    r"^OpenSSL (?P<version>\d+\.\d+\.\d+[a-z]*) (?P<date>\d{1,2} [A-Za-z]+ \d{4})$"
)

# SQLITE_SOURCE_ID, "2024-08-13 09:16:08 c9c2ab54...": the check-in stamp of
# the amalgamation. It names no library, so it only dates an identified
# sqlite3, through sqlite.org's chronology.html (rows from 2019 on, fetched
# 2026-09-28). An unlisted date stays versionless.
SQLITE_SOURCE_ID_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2}) \d{2}:\d{2}:\d{2} [0-9a-f]{16,64}$"
)
SQLITE_CHRONOLOGY: dict[str, str] = {
    "2019-02-07": "3.27.0",
    "2019-02-08": "3.27.1",
    "2019-02-25": "3.27.2",
    "2019-04-16": "3.28.0",
    "2019-07-10": "3.29.0",
    "2019-10-04": "3.30.0",
    "2019-10-10": "3.30.1",
    "2020-01-22": "3.31.0",
    "2020-01-27": "3.31.1",
    "2020-05-22": "3.32.0",
    "2020-05-25": "3.32.1",
    "2020-06-04": "3.32.2",
    "2020-06-18": "3.32.3",
    "2020-08-14": "3.33.0",
    "2020-12-01": "3.34.0",
    "2021-01-20": "3.34.1",
    "2021-03-12": "3.35.0",
    "2021-03-15": "3.35.1",
    "2021-03-17": "3.35.2",
    "2021-03-26": "3.35.3",
    "2021-04-02": "3.35.4",
    "2021-04-19": "3.35.5",
    "2021-06-18": "3.36.0",
    "2021-11-27": "3.37.0",
    "2021-12-30": "3.37.1",
    "2022-01-06": "3.37.2",
    "2022-02-22": "3.38.0",
    "2022-03-12": "3.38.1",
    "2022-03-26": "3.38.2",
    "2022-04-27": "3.38.3",
    "2022-05-04": "3.38.4",
    "2022-05-06": "3.38.5",
    "2022-06-25": "3.39.0",
    "2022-07-13": "3.39.1",
    "2022-07-21": "3.39.2",
    "2022-09-05": "3.39.3",
    "2022-09-29": "3.39.4",
    "2022-11-16": "3.40.0",
    "2022-12-28": "3.40.1",
    "2023-02-21": "3.41.0",
    "2023-03-10": "3.41.1",
    "2023-03-22": "3.41.2",
    "2023-05-16": "3.42.0",
    "2023-08-24": "3.43.0",
    "2023-09-11": "3.43.1",
    "2023-10-10": "3.43.2",
    "2023-11-01": "3.44.0",
    "2023-11-22": "3.44.1",
    "2023-11-24": "3.44.2",
    "2024-01-15": "3.45.0",
    "2024-01-30": "3.45.1",
    "2024-03-12": "3.45.2",
    "2024-04-15": "3.45.3",
    "2024-05-23": "3.46.0",
    "2024-08-13": "3.46.1",
    "2024-10-21": "3.47.0",
    "2024-11-25": "3.47.1",
    "2024-12-07": "3.47.2",
    "2025-01-14": "3.48.0",
    "2025-02-06": "3.49.0",
    "2025-02-18": "3.49.1",
    "2025-05-07": "3.49.2",
    "2025-05-29": "3.50.0",
    "2025-06-06": "3.50.1",
    "2025-06-28": "3.50.2",
    "2025-07-17": "3.50.3",
    "2025-07-30": "3.50.4",
    "2025-11-04": "3.51.0",
    "2025-11-28": "3.51.1",
    "2026-01-09": "3.51.2",
    "2026-03-06": "3.52.0",
    "2026-03-13": "3.51.3",
    "2026-04-09": "3.53.0",
    "2026-05-05": "3.53.1",
    "2026-06-03": "3.53.2",
    "2026-06-26": "3.53.3",
    "2026-07-24": "3.53.4",
}

_BARE_VERSION_RE = re.compile(r"^(?P<version>\d+\.\d+\.\d+)$")

# One rule per version-bearing string, naming the upstream file that defines
# it. Each regex has a ``version`` group (``date`` for a chronology rule) and
# is searched within one extracted string.
# - ``banner``: the string names the library, so the standalone layer may
#   emit a component from it alone (precision measured by
#   tests/scripts/measure_banner_precision.py). ``purl`` is that component's
#   base.
# - otherwise the rule only dates a project other evidence identified;
#   ``unique`` rules count only as the artifact's single distinct match, and
#   ``chronology`` maps the date group to a version.
VERSION_RULES: tuple[dict, ...] = (
    {
        "project": "zlib",
        "purl": "pkg:generic/zlib",
        "banner": True,
        # "deflate"/"inflate" name an algorithm, not the library, and both are
        # ordinary verbs — "failed to inflate 1.5 MB" is not a zlib banner. The
        # copyright line is what makes the string zlib's own.
        "regex": re.compile(
            r"\bdeflate (?P<version>\d+\.\d+(?:\.\d+)?)\s+Copyright", re.IGNORECASE
        ),
        "what": "deflate_copyright",
        "source": "zlib deflate.c",
    },
    {
        "project": "zlib",
        "purl": "pkg:generic/zlib",
        "banner": True,
        "regex": re.compile(
            r"\binflate (?P<version>\d+\.\d+(?:\.\d+)?)\s+Copyright", re.IGNORECASE
        ),
        "what": "inflate_copyright",
        "source": "zlib inftrees.c",
    },
    {
        "project": "lua",
        "purl": "pkg:generic/lua",
        "banner": True,
        "regex": re.compile(r"\bLua (?P<version>\d+\.\d+(?:\.\d+)?)\s+Copyright", re.IGNORECASE),
        "what": "LUA_COPYRIGHT",
        "source": "Lua lua.h",
    },
    {
        "project": "openssl",
        "purl": "pkg:generic/openssl",
        "banner": True,
        "regex": re.compile(r"\bOpenSSL[ /](?P<version>\d+\.\d+\.\d+[a-z]*)\b", re.IGNORECASE),
        "what": "OPENSSL_VERSION_TEXT",
        "source": "OpenSSL include/openssl/opensslv.h",
    },
    {
        "project": "curl",
        "purl": "pkg:generic/curl",
        "banner": True,
        "regex": re.compile(r"\blibcurl/(?P<version>\d+\.\d+(?:\.\d+)?)\b", re.IGNORECASE),
        "what": "curl_version()",
        "source": "curl lib/version.c",
    },
    {
        "project": "expat",
        "purl": "pkg:generic/expat",
        "banner": True,
        "regex": re.compile(r"\bexpat_(?P<version>\d+\.\d+(?:\.\d+)?)\b", re.IGNORECASE),
        "what": "XML_ExpatVersion()",
        "source": "expat lib/xmlparse.c",
    },
    {
        "project": "libpng",
        "purl": "pkg:generic/libpng",
        "banner": True,
        "regex": re.compile(r"\blibpng version (?P<version>\d+\.\d+(?:\.\d+)?)\b", re.IGNORECASE),
        "what": "PNG_HEADER_VERSION_STRING",
        "source": "libpng png.h",
    },
    {
        "project": "libpng",
        "regex": _BARE_VERSION_RE,
        "unique": True,
        "what": "PNG_LIBPNG_VER_STRING",
        "source": "libpng png.h",
    },
    {
        "project": "opus",
        "regex": re.compile(r"^libopus (?P<version>\d+\.\d+\.\d+)$"),
        "what": "opus_get_version_string()",
        "source": "libopus celt/celt.c",
    },
    {
        "project": "proj",
        "regex": re.compile(r"^Rel\. (?P<version>\d+\.\d+\.\d+), "),
        "what": "pj_release",
        "source": "PROJ src/release.cpp",
    },
    {
        "project": "sentry-native",
        "regex": _BARE_VERSION_RE,
        "unique": True,
        "what": "SENTRY_SDK_VERSION",
        "source": "sentry-native include/sentry.h",
    },
    {
        "project": "sqlite3",
        "regex": SQLITE_SOURCE_ID_RE,
        "chronology": SQLITE_CHRONOLOGY,
        "what": "SQLITE_SOURCE_ID",
        "source": "SQLite sqlite3.h, dated by sqlite.org chronology.html",
    },
    {
        "project": "zstd",
        "regex": _BARE_VERSION_RE,
        "unique": True,
        "what": "ZSTD_VERSION_STRING",
        "source": "zstd lib/zstd.h",
    },
)

# The standalone layer's signatures: the rules whose string names the library.
BANNER_SIGNATURES = tuple(rule for rule in VERSION_RULES if rule.get("banner"))

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
            "a standalone string, so no in-string banner names both sqlite "
            "and a version. The source id's date dates an sqlite3 that symbol "
            "evidence already identified (the chronology rule), never alone."
        ),
    },
    {
        "library": "zstd",
        "reason": (
            "no upstream zstd file defines a 'Zstandard v<version>' string: the "
            "CLI stores 'Zstandard CLI' and formats the version at run time "
            "(programs/zstdcli.c), and the library carries ZSTD_VERSION_STRING "
            "bare ('1.5.7', lib/zstd.h), which names no library. The bare "
            "string dates an identified zstd (a unique rule), never alone."
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
            key = (signature["project"], version)
            if key in seen:
                continue
            seen.add(key)
            entry = {
                "library": signature["project"],
                "version": version,
                "purl": f"{signature['purl']}@{version}",
                "banner": value[:256],
            }
            # A mention only when the artifact defines none of the API and the
            # code demonstrably lives elsewhere (it links or imports the
            # library): a stale build-time string. Otherwise a component
            # claim - corroborated by defined API symbols, or undisproved in
            # a stripped image that has nowhere else for the code to be.
            api_count = api_counts.get(signature["project"], 0)
            if api_count == 0 and _provided_externally(metadata, signature["project"]):
                mentions.append(entry)
            else:
                entry["api_symbol_count"] = api_count
                banners.append(entry)
    return {"banners": banners, "mentions": mentions, "state": BANNER_LAYER_ACTIVE}


def _rule_evidence(rule: dict, text: str) -> dict:
    return {"what": f"{rule['what']} ({rule['source']})", "where": "strings", "value": text[:120]}


def artifact_version(project: str, strings) -> tuple[str | None, list[dict]]:
    """The version an identified project's own strings carry, with evidence.

    Named rules come first, and when their matches disagree (or a source id
    has no chronology row) the project stays versionless, as a version
    conflict does elsewhere. A ``unique`` rule is read only when no named
    rule matched. ``(None, evidence)`` means the artifact did not settle the
    version; the database row never does.
    """
    texts = []
    for raw in strings or []:
        text = raw.decode("ascii", "ignore") if isinstance(raw, (bytes, bytearray)) else str(raw)
        if text := text.strip():
            texts.append(text)
    rules = [rule for rule in VERSION_RULES if rule["project"] == project]
    evidence: list[dict] = []
    found: set[str | None] = set()
    for rule in (r for r in rules if not r.get("unique")):
        chronology = rule.get("chronology")
        for text in texts:
            if not (match := rule["regex"].search(text)):
                continue
            version = chronology.get(match.group("date")) if chronology else match.group("version")
            if version in found:
                continue
            found.add(version)
            evidence.append(_rule_evidence(rule, text))
            if chronology and version:
                evidence.append(
                    {
                        "what": "sqlite.org chronology.html",
                        "where": "published table",
                        "value": f"{match.group('date')} -> {version}",
                    }
                )
    if found:
        return (found.pop() if len(found) == 1 else None), evidence
    for rule in (r for r in rules if r.get("unique")):
        candidates = sorted({m.group("version") for t in texts if (m := rule["regex"].search(t))})
        if len(candidates) == 1:
            return candidates[0], [_rule_evidence(rule, candidates[0])]
        if candidates:
            return None, [_rule_evidence(rule, f"ambiguous: {', '.join(candidates[:4])}")]
    return None, []
