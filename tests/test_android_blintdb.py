"""blintdb identification of Android native libraries (A6.3 J1).

R1 of the packet's ladder: a v3 database built in the test whose rows are
symbol names extracted from the real I2 build output, and query metadata
whose exports come from ``llvm-nm -D --defined-only`` on the corpus library
- both stored in ``tests/data/android/blintdb-zstd-evidence.json`` with the
extracting commands. The oracle for the overlap is llvm-nm, not blint's
matching rule.
"""

import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace

from blint.db import detect_binaries_utilized
from blint.lib.android import (
    _blintdb_replace_record,
    _collect_group_blintdb_records,
)
from blint.lib.android_blintdb import (
    blintdb_records,
    refuses_openssl_match,
    screen_standalone_matches,
    superseded_by_framework,
)
from blint.lib.banners import artifact_version
from blint.lib.sbom import process_exe_file

EVIDENCE = Path(__file__).resolve().parent / "data" / "android" / "blintdb-zstd-evidence.json"


def _load_evidence() -> dict:
    assert EVIDENCE.exists(), f"missing evidence file: {EVIDENCE}"
    return json.loads(EVIDENCE.read_text(encoding="utf-8"))


def _create_android_v3_blintdb(db_file, evidence: dict) -> None:
    """A v3 database carrying the real build output's symbol names."""
    project = evidence["db_project"]
    connection = sqlite3.connect(db_file)
    connection.executescript(
        """
        CREATE TABLE SchemaMeta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE Projects (project_id INTEGER PRIMARY KEY, name TEXT NOT NULL, purl TEXT);
        CREATE TABLE Builds (build_id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL,
            llvm_target_tuple TEXT, FOREIGN KEY (project_id) REFERENCES Projects(project_id));
        CREATE TABLE Binaries (binary_id INTEGER PRIMARY KEY, build_id INTEGER NOT NULL,
            name TEXT, binary_type TEXT, llvm_target_tuple TEXT,
            FOREIGN KEY (build_id) REFERENCES Builds(build_id));
        CREATE TABLE Symbols (symbol_id INTEGER PRIMARY KEY, binary_id INTEGER NOT NULL,
            name TEXT NOT NULL, source TEXT NOT NULL,
            FOREIGN KEY (binary_id) REFERENCES Binaries(binary_id));
        CREATE TABLE FunctionFingerprints (function_id INTEGER PRIMARY KEY,
            binary_id INTEGER NOT NULL, function_key TEXT NOT NULL, instruction_hash TEXT,
            assembly_hash TEXT, fuzzy_hash TEXT, cfg_hash TEXT,
            FOREIGN KEY (binary_id) REFERENCES Binaries(binary_id));
        """
    )
    connection.executemany(
        "INSERT INTO SchemaMeta(key, value) VALUES(?, ?)",
        (("schema_family", "blint-db"), ("schema_version", "3")),
    )
    connection.execute(
        "INSERT INTO Projects(project_id, name, purl) VALUES(1, ?, ?)",
        (project["name"], project["purl"]),
    )
    connection.execute(
        "INSERT INTO Builds(build_id, project_id, llvm_target_tuple) VALUES(1, 1, ?)",
        (project["llvm_target_tuple"],),
    )
    connection.execute(
        "INSERT INTO Binaries(binary_id, build_id, name, binary_type, llvm_target_tuple)"
        " VALUES(1, 1, ?, ?, ?)",
        (project["binary"], project["binary_type"], project["llvm_target_tuple"]),
    )
    connection.executemany(
        "INSERT INTO Symbols(binary_id, name, source) VALUES(1, ?, 'dynamic_symbols')",
        [(name,) for name in evidence["db_rows"]],
    )
    connection.commit()
    connection.close()


def _query_metadata(evidence: dict) -> dict:
    query = evidence["query"]
    return {
        "name": query["name"],
        "binary_type": query["binary_type"],
        "llvm_target_tuple": query["llvm_target_tuple"],
        "dynamic_symbols": [{"name": name, "is_exported": True} for name in query["exports"]],
        "dynamic_entries": [{"tag": "SONAME", "name": query["soname"]}],
    }


def test_r1_real_build_output_matches_corpus_library(tmp_path):
    """The vcpkg zstd build's symbols identify the corpus libzstd-jni copy.

    The database rows and the query exports both come from llvm-nm runs on
    the real artifacts (see the evidence file's extracting_commands); the
    571-name overlap is the oracle, computed without blint's matcher.
    """
    evidence = _load_evidence()
    db_file = tmp_path / "android-r1.db"
    _create_android_v3_blintdb(db_file, evidence)
    query = evidence["query"]
    overlap = set(evidence["db_rows"]) & set(query["exports"])
    assert len(overlap) >= 500, f"evidence overlap shrank: {len(overlap)}"

    from blint.db import build_symbol_source_map

    so_metadata = _query_metadata(evidence)
    detected, match_evidence = detect_binaries_utilized(
        symbol_source_map=build_symbol_source_map(so_metadata),
        binary_metadata=so_metadata,
        db_file=str(db_file),
    )
    assert detected == {evidence["db_project"]["purl"]}
    record = match_evidence[evidence["db_project"]["purl"]]
    assert record["matched_symbol_count"] >= 500
    assert record["binary_name_match"] is False

    records = blintdb_records(
        so_metadata, detected, match_evidence, [b"1.5.7"]
    )
    assert len(records) == 1
    match = records[0]
    # Version from the artifact's own string, never the database row.
    assert match["version"] == "1.5.7"
    # The host is a jni wrapper (SONAME libzstd-jni-1.5.7-7.so, the
    # database's library is libzstd.so): a static copy that nests, not a
    # replace.
    assert match["soname_match"] is False
    assert any("ZSTD_VERSION_STRING" in e["what"] for e in match["evidence"])


def test_r1_replace_requires_soname_agreement(tmp_path):
    """A host whose DT_SONAME is the project's own library replaces."""
    evidence = _load_evidence()
    db_file = tmp_path / "android-r1-replace.db"
    _create_android_v3_blintdb(db_file, evidence)
    so_metadata = _query_metadata(evidence)
    # The host is the project's own library: SONAME libzstd.so.
    so_metadata["dynamic_entries"] = [{"tag": "SONAME", "name": "libzstd.so"}]
    so_metadata["name"] = "libzstd.so"
    from blint.db import build_symbol_source_map

    detected, match_evidence = detect_binaries_utilized(
        symbol_source_map=build_symbol_source_map(so_metadata),
        binary_metadata=so_metadata,
        db_file=str(db_file),
    )
    records = blintdb_records(so_metadata, detected, match_evidence, [b"1.5.7"])
    assert records[0]["soname_match"] is True
    members = [({}, {"blintdb_records": records})]
    assert _blintdb_replace_record(members, records) is records[0]
    # A second member without the record (a multi-ABI build whose other ABI
    # the database does not cover) keeps the file identity and nests.
    members.append(({}, {"blintdb_records": []}))
    assert _blintdb_replace_record(members, records) is None


def test_artifact_version_refuses_ambiguous_bare_versions():
    """Several bare x.y.z strings cannot be attributed to one project."""
    version, _ = artifact_version("zstd", [b"1.5.7"])
    assert version == "1.5.7"
    # libvlc carries both 1.6.50 and 1.3.1 (measured); no rule can pick.
    version, evidence = artifact_version("zstd", [b"1.6.50", b"1.3.1"])
    assert version is None


def test_artifact_version_named_published_mappings():
    # opus: the prefixed, unambiguous form.
    assert artifact_version("opus", [b"libopus 1.5.2"])[0] == "1.5.2"
    # sqlite3: SOURCE_ID date through sqlite.org's chronology.
    version, evidence = artifact_version(
        "sqlite3", [b"2024-08-13 09:16:08 " + b"c9c2ab54ba1f5f46360f1b4f35d849cd3f080e6f"]
    )
    assert version == "3.46.1"
    assert any("chronology" in e["what"] for e in evidence)
    # A date outside the carried chronology window: the source id is still
    # evidence, the version is refused.
    version, evidence = artifact_version(
        "sqlite3", [b"2013-05-20 09:23:38 " + b"c9c2ab54ba1f5f46360f1b4f35d849cd3f080e6f"]
    )
    assert version is None
    assert any("SQLITE_SOURCE_ID" in e["what"] for e in evidence)
    # proj: the release banner.
    assert artifact_version("proj", [b"Rel. 8.2.0, November 1st, 2021"])[0] == "8.2.0"
    # libpng: prefixed banner beats the bare string.
    assert artifact_version("libpng", [b"1.3.1", b"libpng version 1.6.50"])[0] == "1.6.50"
    # openssl: the H4 banner, or nothing (the artifact decides, not the row).
    assert artifact_version("openssl", [b"OpenSSL 3.0.2 15 Mar 2022"])[0] == "3.0.2"
    assert artifact_version("openssl", [b"ossl provider"])[0] is None
    # freetype has no accepted mapping: versionless.
    assert artifact_version("freetype", [b"2.13.2"])[0] is None
    # The banner rules date an identified project on this path too.
    assert artifact_version("zlib", [b" deflate 1.3.1 Copyright 1995-2024 Jean-loup Gailly "])[
        0
    ] == "1.3.1"


def test_artifact_version_refuses_conflicting_named_strings():
    """Two versions of one project in one artifact: neither is claimed."""
    version, evidence = artifact_version(
        "openssl", [b"OpenSSL 3.0.2 15 Mar 2022", b"OpenSSL/1.1.1w"]
    )
    assert version is None and len(evidence) == 2
    # Repeated strings of one version are one claim (OpenSSL's per-module
    # "part of OpenSSL" banners).
    assert artifact_version(
        "openssl", [b"OpenSSL 3.0.2 15 Mar 2022", b"OpenSSL 3.0.2 15 Mar 2022"]
    )[0] == "3.0.2"
    # A dated and an undated source id are two copies: versionless.
    source_id = b" 09:16:08 c9c2ab54ba1f5f46360f1b4f35d849cd3f080e6f"
    version, _ = artifact_version("sqlite3", [b"2024-08-13" + source_id, b"2013-05-20" + source_id])
    assert version is None
    # A named string outranks the bare one.
    assert artifact_version("libpng", [b"1.6.58", b"libpng version 1.6.50"])[0] == "1.6.50"


def test_superseded_by_framework_drops_boringssl_shadowed_openssl():
    """An A6.1 BoringSSL record wins over an openssl port match."""
    records = [
        {"project": "openssl", "project_purl": "pkg:generic/openssl@3.6.2"},
        {"project": "zstd", "project_purl": "pkg:generic/zstd@1.5.7"},
    ]
    kept, superseded = superseded_by_framework(records, {"boringssl"})
    assert [r["project"] for r in kept] == ["zstd"]
    assert superseded == ["boringssl:openssl"]
    # No framework record: everything stays.
    kept, superseded = superseded_by_framework(records, set())
    assert len(kept) == 2 and not superseded


def test_collect_group_blintdb_records_merges_by_project():
    members = [
        (
            {},
            {
                "blintdb_records": [
                    {"project": "zstd", "score": 577, "soname_match": False},
                ]
            },
        ),
        (
            {},
            {
                "blintdb_records": [
                    {"project": "zstd", "score": 610, "soname_match": True},
                ]
            },
        ),
    ]
    records, superseded = _collect_group_blintdb_records(members, set())
    assert not superseded
    assert len(records) == 1
    # The strongest member evidence represents the group.
    assert records[0]["score"] == 610


def test_standalone_path_never_reports_openssl_for_boringssl(tmp_path, monkeypatch):
    """J2 on the standalone path: the platform libcrypto.so stays BoringSSL.

    The names are llvm-nm's from the api36 system image's BoringSSL
    libcrypto.so and from librealm-jni.so (committed openssl3 evidence):
    the BoringSSL provider's EVP/X509 surface matches the openssl port,
    and only the A6.1 BoringSSL record stops the component.
    process_exe_file drops the match and counts it in
    internal:blintdb_superseded_by_framework.
    """
    import json as _json

    from tests.test_sbom_blintdb import _create_typed_blintdb

    evidence = _json.loads(
        (Path(__file__).resolve().parent / "data" / "android" / "openssl3-evidence.json")
        .read_text(encoding="utf-8")
    )
    boring = evidence["boringssl_libcrypto_boringssl_exports"]
    evp_names = evidence["realm_sample_other"]
    db_file = tmp_path / "boringssl-gate.db"
    _create_typed_blintdb(
        db_file,
        [
            (
                "libcrypto.so",
                "ELF",
                "openssl",
                "pkg:generic/openssl@3.6.2",
                evp_names + boring[:8],
            ),
        ],
    )
    metadata = {
        "name": "/system/lib64/libcrypto.so",
        "binary_type": "ELF",
        "llvm_target_tuple": "aarch64-unknown-linux-android",
        # symtab, the bucket the typed fixture stores under - the
        # provider exports its surface and also carries it in symtab.
        "symtab_symbols": [
            {"name": name, "is_exported": True} for name in evp_names + boring[:8]
        ],
        "dynamic_entries": [{"tag": "SONAME", "name": "libcrypto.so"}],
        "frameworks": [
            {
                "framework": "boringssl",
                "evidence": [
                    {
                        "what": "BORINGSSL_* exported symbol prefix",
                        "where": "symbols",
                        "value": "BORINGSSL_*",
                    }
                ],
                "hints": [],
                "static": False,
            }
        ],
    }
    sbom = SimpleNamespace(metadata=SimpleNamespace(component=SimpleNamespace(components=[])))
    monkeypatch.setattr("blint.db.BLINTDB_LOC", str(db_file))
    monkeypatch.setattr(
        "blint.lib.sbom.parse",
        lambda _exe, disassemble=False, sdk_path=None: metadata,
    )

    components = process_exe_file(
        {}, False, "/system/lib64/libcrypto.so", sbom, [], {}, True, False
    )

    # No openssl component anywhere: the BoringSSL record wins for the
    # same bytes.
    everywhere = list(components) + list(
        getattr(sbom.metadata.component, "components", None) or []
    )
    assert not any("openssl" in (comp.purl or "") for comp in everywhere)
    # The drop is counted on the parent component.
    superseded = [
        prop.value
        for comp in everywhere
        for prop in (comp.properties or [])
        if prop.name == "internal:blintdb_superseded_by_framework"
    ]
    assert superseded == ["boringssl:openssl"]


def test_refuses_openssl_match_without_openssl3_names():
    """The BoringSSL libssl.so shape never becomes an OpenSSL match.

    Names are llvm-nm's (committed openssl3 evidence). The 78 tier-0
    BoringSSL libcrypto.so/libssl.so files define and import no OSSL_* or
    ossl_* name. A real OpenSSL 3.6.2 libssl.so, SONAME libssl.so, defines
    five OSSL_* names and imports 45, and must stay matchable.
    """
    evidence = json.loads(
        (Path(__file__).resolve().parent / "data" / "android" / "openssl3-evidence.json")
        .read_text(encoding="utf-8")
    )
    assert evidence["boringssl_tier0_file_count"] == 78
    assert evidence["boringssl_tier0_OSSL_or_ossl_count"] == 0
    ssl_surface = ["SSL_new", "SSL_free", "SSL_connect", "SSL_read", "SSL_write"]
    assert refuses_openssl_match("libssl.so", ssl_surface)
    assert refuses_openssl_match("libcrypto.so", ssl_surface)
    assert refuses_openssl_match("stable_cronet_libcrypto.so", ssl_surface)
    # OpenSSL 3's shared libssl.so: its own OSSL_* exports, or the OSSL_*
    # API it imports from libcrypto.
    exports = evidence["openssl3_shared_libssl_defined_OSSL"]
    imports = evidence["openssl3_shared_libssl_imported_OSSL_sample"]
    assert not refuses_openssl_match("libssl.so", ssl_surface + exports)
    assert not refuses_openssl_match("libssl.so", ssl_surface + imports)
    # A static copy's internal namespace.
    assert not refuses_openssl_match("libssl.so", ssl_surface + ["ossl_provider_init"])
    # A TLS framework record already speaks for the bytes.
    assert not refuses_openssl_match("libssl.so", ssl_surface, {"openssl"})
    assert not refuses_openssl_match("libssl.so", ssl_surface, {"boringssl"})
    # Versioned OpenSSL SONAMEs and other hosts nest as usual.
    assert not refuses_openssl_match("libssl.so.3", ssl_surface)
    assert not refuses_openssl_match("librealm-jni.so", ssl_surface)
    assert not refuses_openssl_match(None, ssl_surface)


def test_standalone_path_keeps_openssl_match_under_an_openssl_record():
    """Only a contradicting framework record drops a standalone match.

    The standalone path emits no framework components, so an OpenSSL banner
    record must not remove the blintdb openssl match for the same library:
    it would leave the SBOM with no OpenSSL at all. The APK path, which
    emits the record, still drops the duplicate.
    """
    detected = {"pkg:generic/openssl@3.6.2"}
    evidence = {"pkg:generic/openssl@3.6.2": {"project_name": "openssl"}}
    metadata = {
        "dynamic_entries": [{"tag": "SONAME", "name": "libcrypto.so"}],
        "dynamic_symbols": [{"name": "OSSL_PARAM_construct_end"}],
        "frameworks": [{"framework": "openssl", "version": "3.6.2", "static": False}],
    }
    kept, superseded, refused = screen_standalone_matches(metadata, detected, evidence)
    assert kept == detected and not superseded and refused is None
    records = [{"project": "openssl", "project_purl": "pkg:generic/openssl@3.6.2"}]
    kept, superseded = superseded_by_framework(records, {"openssl"})
    assert not kept and superseded == ["openssl:openssl"]
    kept, superseded = superseded_by_framework(records, {"openssl"}, emitted=False)
    assert kept == records and not superseded


def test_nested_child_carries_only_the_abis_whose_copy_matched():
    """Rule 36: a static copy found in one ABI's build is a fact for that ABI."""
    members = [
        (
            {"locations": [{"abi": "arm64-v8a"}]},
            {"blintdb_records": [{"project": "zstd", "score": 577, "soname_match": False}]},
        ),
        ({"locations": [{"abi": "x86_64"}]}, {"blintdb_records": []}),
    ]
    records, _ = _collect_group_blintdb_records(members, set())
    assert records[0]["abis"] == ["arm64-v8a"]
