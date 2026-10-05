"""blintdb identification of Android native libraries.

A blintdb match is symbol evidence, not identity: a library that statically
links a project's code matches that project without *being* it.

- Nesting: a match is a static copy inside the host ``.so`` and becomes a
  child component of the host. It replaces the host's identity only when the
  host's DT_SONAME is one of the project's own library names in the
  database. A file name alone is a hint.
- Versions come from the artifact, never from the database row, which
  holds the vcpkg port's version, not the bundled upstream one (OsmAnd
  bundles PROJ 8.2.0 while its port row says 9.8.1). The strings are read
  under ``blint.lib.banners``' rules.
- A framework record for the same bytes wins over a match it contradicts or
  duplicates (``framework_claims``).
"""

from __future__ import annotations

import re

from blint.lib.banners import artifact_version

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
