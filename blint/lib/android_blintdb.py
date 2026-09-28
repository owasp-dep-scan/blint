"""blintdb identification of Android native libraries (A6.3, rule 38).

A blintdb match is symbol evidence, not identity: a library that statically
links a project's code matches that project without *being* it.

- Nesting: a match is a static copy inside the host ``.so`` and becomes a
  child component of the host. It replaces the host's identity only when the
  host's DT_SONAME is one of the project's own library names in the
  database. A file name alone is a hint.
- Versions come from the artifact, never from the database row, which holds
  the vcpkg port's version (the corpus OsmAnd bundles PROJ 8.2.0; the port
  row says 9.8.1). A string counts only under a named published mapping.
- A framework record for the same bytes wins over a match it contradicts or
  duplicates (``framework_claims``).
"""

from __future__ import annotations

import re

# A framework record naming a different implementation of the project's API.
# BoringSSL shares OpenSSL's EVP/X509/SSL surface, so an openssl match on
# BoringSSL bytes is wrong on every path.
CONTRADICTED_BY_FRAMEWORK: dict[str, set[str]] = {"boringssl": {"openssl"}}
# A framework record for the project itself. The APK path emits the record
# as a component, so the match would be a second copy; the standalone path
# emits no framework components and keeps the match.
DUPLICATED_BY_FRAMEWORK: dict[str, set[str]] = {"openssl": {"openssl"}, "nss": {"nss"}}

# OpenSSL 3's namespaces: the public OSSL_* API, exported by its libcrypto
# and libssl and imported by their callers, and the internal ossl_* one,
# exported only by a static copy linked without OpenSSL's version script.
# No tier-0 BoringSSL libcrypto.so/libssl.so defines or imports either
# (tests/data/android/openssl3-evidence.json).
OPENSSL3_NAME_RE = re.compile(r"^(?:OSSL|ossl)_")
# The unversioned libcrypto.so/libssl.so SONAMEs BoringSSL ships under,
# vendor-prefixed ones (stable_cronet_libssl.so) included.
TLS_PROVIDER_SONAME_RE = re.compile(r"(?:^|_)(?:libcrypto|libssl)\.so$")

# --- Version-bearing strings (rule 38) -------------------------------------
# Each rule names the published source that defines the string, per project
# (the blint-db project name). A bare ``x.y.z`` is accepted only where the
# project's own source defines exactly that string as its version.
_BARE_VERSION_RE = re.compile(r"^(\d+\.\d+\.\d+)$")

VERSION_STRING_RULES: dict[str, list[dict]] = {
    # ZSTD_VERSION_STRING, built from ZSTD_VERSION_MAJOR/MINOR/RELEASE in
    # zstd's lib/zstd.h and returned by ZSTD_versionString().
    "zstd": [
        {"re": _BARE_VERSION_RE, "what": "ZSTD_VERSION_STRING", "source": "zstd lib/zstd.h"}
    ],
    # opus_get_version_string() returns "libopus x.y.z" (libopus src/opus.c).
    "opus": [
        {
            "re": re.compile(r"^libopus (\d+\.\d+\.\d+)$"),
            "what": "opus_get_version_string",
            "source": "libopus src/opus.c",
        }
    ],
    # PNG_LIBPNG_VER_STRING in libpng's png.h; png_get_copyright renders it
    # as "libpng version x.y.z".
    "libpng": [
        {
            "re": re.compile(r"^libpng version (\d+\.\d+\.\d+)$"),
            "what": "PNG_LIBPNG_VER_STRING (png_get_copyright form)",
            "source": "libpng png.h",
        },
        {"re": _BARE_VERSION_RE, "what": "PNG_LIBPNG_VER_STRING", "source": "libpng png.h"},
    ],
    # SENTRY_SDK_VERSION in sentry-native's include/sentry.h.
    "sentry-native": [
        {
            "re": _BARE_VERSION_RE,
            "what": "SENTRY_SDK_VERSION",
            "source": "sentry-native include/sentry.h",
        }
    ],
    # PROJ's release banner, "Rel. 9.4.0, November 7th, 2024" - the string
    # pj_get_release() returns.
    "proj": [
        {
            "re": re.compile(r"^Rel\. (\d+\.\d+\.\d+), "),
            "what": "PROJ release banner (pj_get_release)",
            "source": "PROJ src/fileapi.cpp",
        }
    ],
}

# SQLITE_SOURCE_ID, "2024-08-13 09:16:08 c9c2ab54...": the amalgamation's
# build stamp (sqlite3.c's SQLITE_SOURCE_ID macro). The release date maps to
# the version through sqlite.org's published chronology; the table below
# carries its 2019-01 onward rows (fetched 2026-09-28). A date not in the
# table yields no version - reported as the source id only, never guessed.
SQLITE_SOURCE_ID_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2}) (?P<time>\d{2}:\d{2}:\d{2}) (?P<hash>[0-9a-f]{16,64})$"
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
# OpenSSL 3's banner, "OpenSSL 3.0.2 15 Mar 2022" (OPENSSL_VERSION_TEXT) -
# the same evidence H4's detector uses.
OPENSSL_BANNER_RE = re.compile(
    r"^OpenSSL (?P<version>\d+\.\d+\.\d+[a-z]*) (?P<date>\d{1,2} [A-Za-z]+ \d{4})$"
)


def _iter_text_strings(raw_strings) -> list[str]:
    """Printable runs as stripped text, so anchored patterns see whole strings."""
    texts = (
        raw.decode("ascii", "ignore") if isinstance(raw, (bytes, bytearray)) else str(raw)
        for raw in raw_strings or []
    )
    return [stripped for text in texts if (stripped := text.strip())]


def _bare_version_candidates(strings: list[str]) -> list[str]:
    """Distinct bare ``x.y.z`` strings the artifact carries."""
    return sorted({text for text in strings if _BARE_VERSION_RE.match(text)})


def _unique_bare_version(strings: list[str]) -> str | None:
    """The artifact's single bare ``x.y.z`` string, or None.

    A host library routinely carries several bare version strings (VLC's
    libvlc holds both 1.6.50 and 1.3.1); with more than one distinct
    candidate no rule can say which belongs to the matched project, so the
    component stays versionless (rule 38) instead of guessing.
    """
    candidates = _bare_version_candidates(strings)
    return candidates[0] if len(candidates) == 1 else None


def artifact_version(project: str, raw_strings) -> tuple[str | None, list[dict]]:
    """The version a matched project's own strings carry, with evidence.

    Returns ``(version, evidence)``; ``(None, evidence)`` when the artifact
    carries no version-bearing string for the project - the component then
    stays versionless (rule 38), never falling back to the database's port
    version.
    """
    strings = _iter_text_strings(raw_strings)
    evidence: list[dict] = []
    if project == "sqlite3":
        for text in strings:
            if match := SQLITE_SOURCE_ID_RE.match(text):
                version = SQLITE_CHRONOLOGY.get(match.group("date"))
                evidence.append(
                    {
                        "what": "SQLITE_SOURCE_ID (sqlite3.c build stamp)",
                        "where": "strings",
                        "value": text[:60],
                    }
                )
                if version:
                    evidence.append(
                        {
                            "what": "sqlite.org chronology.html date mapping",
                            "where": "published table",
                            "value": f"{match.group('date')} -> {version}",
                        }
                    )
                    return version, evidence
                return None, evidence
        return None, evidence
    if project == "openssl":
        for text in strings:
            if match := OPENSSL_BANNER_RE.match(text):
                evidence.append(
                    {
                        "what": "OPENSSL_VERSION_TEXT banner",
                        "where": "strings",
                        "value": text,
                    }
                )
                return match.group("version"), evidence
        return None, evidence
    rules = VERSION_STRING_RULES.get(project) or []
    # The bare x.y.z rule is the ambiguous one; it is excluded from the
    # direct pass and only accepted as the artifact's single distinct bare
    # version string. Several bare versions mean the string cannot be
    # attributed to this project (measured: libvlc carries both 1.6.50 and
    # 1.3.1).
    for rule in rules:
        if rule["re"] is _BARE_VERSION_RE:
            continue
        for text in strings:
            if match := rule["re"].match(text):
                evidence.append(
                    {
                        "what": f"{rule['what']} ({rule['source']})",
                        "where": "strings",
                        "value": text,
                    }
                )
                return match.group(1), evidence
    if any(rule["re"] is _BARE_VERSION_RE for rule in rules):
        bare = _unique_bare_version(strings)
        if bare:
            rule = next(rule for rule in rules if rule["re"] is _BARE_VERSION_RE)
            evidence.append(
                {
                    "what": f"unique bare version string ({rule['what']}, {rule['source']})",
                    "where": "strings",
                    "value": bare,
                }
            )
            return bare, evidence
    return None, evidence


def metadata_soname(metadata: dict) -> str | None:
    for entry in metadata.get("dynamic_entries") or []:
        if isinstance(entry, dict) and entry.get("tag") == "SONAME" and entry.get("name"):
            return str(entry["name"])
    return None


def dynamic_symbol_names(metadata: dict) -> list[str]:
    """Every dynamic symbol name, exported or imported."""
    return [
        str(sym["name"])
        for sym in metadata.get("dynamic_symbols") or []
        if isinstance(sym, dict) and sym.get("name")
    ]


def blintdb_records(
    so_metadata: dict,
    detected: set,
    evidence: dict,
    raw_strings,
) -> list[dict]:
    """Turn one library's blintdb matches into identification records.

    ``soname_match`` marks the one shape allowed to replace the host: its
    DT_SONAME is one of the project's own library names in the database.
    """
    soname = metadata_soname(so_metadata)
    records: list[dict] = []
    for purl in sorted(detected):
        match = evidence.get(purl) or {}
        project = match.get("project_name")
        if not project:
            continue
        matched_names = list(match.get("matched_binary_names") or [])
        version, version_evidence = artifact_version(project, raw_strings)
        symbols = sorted(match.get("matched_symbols") or [])
        count = match.get("matched_symbol_count", 0)
        records.append(
            {
                "project": project,
                "project_purl": purl,
                "version": version,
                "score": match.get("score"),
                "matched_binary_names": matched_names[:4],
                "soname": soname,
                "soname_match": bool(soname and soname in matched_names),
                "evidence": [
                    {
                        "what": "blintdb symbol match",
                        "where": "symbols",
                        "value": f"{count} symbols"
                        + (f" (e.g. {', '.join(symbols[:3])})" if symbols else ""),
                    },
                    *version_evidence,
                ],
            }
        )
    return records


def framework_claims(framework_keys, *, emitted: bool) -> dict[str, str]:
    """project -> the framework whose record claims it.

    ``emitted`` says the caller turns framework records into components, so
    a duplicated project is claimed as well as a contradicted one.
    """
    tables = [CONTRADICTED_BY_FRAMEWORK]
    if emitted:
        tables.append(DUPLICATED_BY_FRAMEWORK)
    claims: dict[str, str] = {}
    for key in sorted(k for k in framework_keys or () if k):
        for table in tables:
            for project in table.get(key, ()):
                claims.setdefault(project, key)
    return claims


def refuses_openssl_match(soname: str | None, names, framework_keys=()) -> bool:
    """Whether an openssl match on this host must be refused.

    On a TLS provider SONAME, BoringSSL and OpenSSL share the whole SSL_*/
    EVP_* surface, and the platform's BoringSSL libssl.so carries no
    BORINGSSL_* export or string for a framework record to name it by. Only
    OpenSSL 3's own namespaces tell the two apart. A TLS framework record
    already speaks for the bytes.
    """
    if not soname or not TLS_PROVIDER_SONAME_RE.search(soname):
        return False
    if {"openssl", "boringssl"} & set(framework_keys or ()):
        return False
    return not any(isinstance(n, str) and OPENSSL3_NAME_RE.match(n) for n in names or ())


def superseded_by_framework(
    records: list[dict], framework_keys, *, emitted: bool = True
) -> tuple[list[dict], list[str]]:
    """Split records into kept ones and ``"<framework>:<project>"`` drops."""
    claims = framework_claims(framework_keys, emitted=emitted)
    kept: list[dict] = []
    superseded: list[str] = []
    for record in records:
        if claimant := claims.get(record["project"]):
            superseded.append(f"{claimant}:{record['project']}")
        else:
            kept.append(record)
    return kept, superseded


def screen_standalone_matches(
    metadata: dict, detected: set, evidence: dict
) -> tuple[set, list[str], str | None]:
    """Apply the TLS rules to a standalone binary's blintdb matches.

    Returns the kept purls, the superseded ``"<framework>:<project>"``
    entries and, when an openssl match was refused, the host's SONAME.
    """
    framework_keys = {r.get("framework") for r in metadata.get("frameworks") or []}
    claims = framework_claims(framework_keys, emitted=False)
    kept: set = set()
    superseded: list[str] = []
    refused = False
    soname = metadata_soname(metadata)
    names = dynamic_symbol_names(metadata)
    for purl in detected:
        project = (evidence.get(purl) or {}).get("project_name")
        if claimant := claims.get(project):
            superseded.append(f"{claimant}:{project}")
        elif project == "openssl" and refuses_openssl_match(soname, names, framework_keys):
            refused = True
        else:
            kept.add(purl)
    return kept, sorted(superseded), soname if refused else None
