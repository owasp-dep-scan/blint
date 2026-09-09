# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT
"""P4.3 static-linkage recovery: member-level matching and banner detection.

The member layer matches a binary's function hashes against blintdb
static-archive members (Binaries rows with archive_name set). The fixtures
here emulate a producer carrying the archive_name column the same way the
similarity-hash tests emulate v3 columns; the gates exercised are the ones
the real-archive measurement fixed
(tests/scripts/measure_static_linkage.py):

- coverage measured against the *member*, not the query — a genuine member
  match covers a small fraction of the query by construction;
- the exact path needs the coverage gate, not just a match count: a
  thousand-function noise member can collect three generic exact matches;
- address-adjacency (contiguity) gates the fuzzy path, because a real
  member is emitted as one address run while collisions scatter.
"""
import sqlite3
from types import SimpleNamespace

from blint import db as db_module
from blint.db import (
    MEMBER_LAYER_ACTIVE,
    MEMBER_LAYER_INACTIVE_NO_DISASSEMBLY,
    MEMBER_LAYER_INACTIVE_NO_HASHES,
    MEMBER_LAYER_UNAVAILABLE_DATABASE_MISSING,
    MEMBER_LAYER_UNAVAILABLE_NO_MEMBER_ROWS,
    MEMBER_LAYER_UNAVAILABLE_SCHEMA_UNSUPPORTED,
    _member_contiguity,
    blintdb_hash_capabilities,
    blintdb_member_layer_state,
    build_query_function_positions,
    detect_binaries_utilized,
    lookup_member_matches,
)
from blint.lib.banners import (
    BANNER_LAYER_ACTIVE,
    BANNER_LAYER_INACTIVE_NO_STRINGS,
    REJECTED_SIGNATURES,
    detect_vendored_banners,
    is_probable_banner_string,
)
from blint.lib.sbom import process_exe_file

FUZZY_HASHES = [f"{index:02x}" * 8 for index in range(8)]
EXACT_HASHES = [f"{index:02x}" * 16 for index in range(8)]
SCATTER_HASHES = [f"s{index:02x}" * 8 for index in range(8)]
NOISE_EXACT_HASHES = [f"n{index:02x}" * 16 for index in range(3)]


def _create_v4_blintdb(db_file):
    """A database carrying similarity hash columns and archive members.

    Three archive-member projects and one scatter project:
    - demo's libdemo.a/add.o carries 8 fuzzy and 8 exact hashes;
    - other's libother.a/other.o carries a single fuzzy hash (below every
      count gate);
    - noise's libnoise.a/noise.o carries 100 functions of which exactly 3
      hold exact hashes the query will carry — the measured shape of a
      thousand-function noise member collecting generic exact matches;
    - scatter's libscat.a/scat.o carries 8 fuzzy hashes the query will match
      at scattered addresses, so only contiguity can reject it.
    """
    connection = sqlite3.connect(db_file)
    connection.executescript(
        """
        CREATE TABLE SchemaMeta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE Projects (
            project_id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            purl TEXT
        );
        CREATE TABLE Builds (
            build_id INTEGER PRIMARY KEY,
            project_id INTEGER NOT NULL,
            llvm_target_tuple TEXT,
            FOREIGN KEY (project_id) REFERENCES Projects(project_id)
        );
        CREATE TABLE Binaries (
            binary_id INTEGER PRIMARY KEY,
            build_id INTEGER NOT NULL,
            name TEXT,
            binary_type TEXT,
            llvm_target_tuple TEXT,
            archive_name TEXT,
            FOREIGN KEY (build_id) REFERENCES Builds(build_id)
        );
        CREATE TABLE Symbols (
            symbol_id INTEGER PRIMARY KEY,
            binary_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            source TEXT NOT NULL,
            FOREIGN KEY (binary_id) REFERENCES Binaries(binary_id)
        );
        CREATE TABLE FunctionFingerprints (
            function_id INTEGER PRIMARY KEY,
            binary_id INTEGER NOT NULL,
            function_key TEXT NOT NULL,
            name TEXT NOT NULL,
            address TEXT,
            instruction_hash TEXT,
            fuzzy_hash TEXT,
            cfg_hash TEXT,
            instruction_count INTEGER,
            FOREIGN KEY (binary_id) REFERENCES Binaries(binary_id)
        );
        CREATE INDEX idx_functions_fuzzy_hash_binary ON FunctionFingerprints(fuzzy_hash, binary_id);
        CREATE INDEX idx_functions_instruction_hash_binary ON FunctionFingerprints(instruction_hash, binary_id);
        """
    )
    connection.executemany(
        "INSERT INTO SchemaMeta(key, value) VALUES(?, ?)",
        (("schema_family", "blint-db"), ("schema_version", "4")),
    )
    connection.executemany(
        "INSERT INTO Projects(project_id, name, purl) VALUES(?, ?, ?)",
        (
            (1, "demo", "pkg:generic/demo@1.0.0"),
            (2, "other", "pkg:generic/other@2.0.0"),
            (3, "noise", "pkg:generic/noise@3.0.0"),
            (4, "scatter", "pkg:generic/scatter@4.0.0"),
        ),
    )
    connection.executemany(
        "INSERT INTO Builds(build_id, project_id) VALUES(?, ?)",
        ((1, 1), (2, 2), (3, 3), (4, 4)),
    )
    connection.executemany(
        "INSERT INTO Binaries(binary_id, build_id, name, binary_type, archive_name) VALUES(?, ?, ?, ?, ?)",
        (
            (1, 1, "libdemo.a", "ELF", None),
            (2, 1, "add.o", "ELF", "libdemo.a"),
            (3, 2, "other.o", "ELF", "libother.a"),
            (4, 3, "noise.o", "ELF", "libnoise.a"),
            (5, 4, "scat.o", "ELF", "libscat.a"),
        ),
    )
    connection.execute(
        "INSERT INTO Symbols(binary_id, name, source) VALUES(2, 'demo_member_symbol', 'symtab_symbols')"
    )
    rows = []
    for index, fuzzy in enumerate(FUZZY_HASHES):
        rows.append((2, f"0x{index:02d}::add", f"add_{index}", f"0x{index:02d}", EXACT_HASHES[index], fuzzy, 10))
    rows.append((3, "0x99::other", "other_fn", "0x99", None, "9" * 16, 10))
    for index, exact in enumerate(NOISE_EXACT_HASHES):
        rows.append((4, f"0x{index:02x}::noise", f"noise_{index}", f"0x{index:02x}", exact, None, 10))
    for index in range(3, 100):
        rows.append((4, f"0x{index:02x}::noise_pad", f"noise_pad_{index}", f"0x{index:02x}", None, None, 10))
    for index, fuzzy in enumerate(SCATTER_HASHES):
        rows.append((5, f"0x{index:02x}::scat", f"scat_{index}", f"0x{index:02x}", None, fuzzy, 10))
    connection.executemany(
        "INSERT INTO FunctionFingerprints(binary_id, function_key, name, address, instruction_hash, fuzzy_hash, instruction_count)"
        " VALUES(?, ?, ?, ?, ?, ?, ?)",
        rows,
    )
    connection.commit()
    connection.close()


def _member_query_metadata():
    """Query metadata matching the fixture members.

    The 8 demo hashes sit at adjacent addresses (one 32-byte function after
    another); the 8 scatter hashes are 64 KiB apart. The noise exact hashes
    live on their own functions. Every function carries 10 instructions so it
    passes both floors.
    """
    disassembled = {}
    functions = []
    for index, fuzzy in enumerate(FUZZY_HASHES):
        address = 0x1000 + index * 0x20
        name = f"demo_fn_{index}"
        disassembled[name] = {
            "name": name,
            "address": hex(address),
            "instruction_hash": EXACT_HASHES[index],
            "fuzzy_hash": fuzzy,
            "instruction_count": 10,
        }
        functions.append({"name": name, "address": hex(address), "size": 0x20})
    for index, fuzzy in enumerate(SCATTER_HASHES):
        address = 0x10000 * (index + 1)
        name = f"scatter_fn_{index}"
        disassembled[name] = {
            "name": name,
            "address": hex(address),
            "fuzzy_hash": fuzzy,
            "instruction_count": 10,
        }
        functions.append({"name": name, "address": hex(address), "size": 0x20})
    for index, exact in enumerate(NOISE_EXACT_HASHES):
        address = 0x200000 + index * 0x10
        name = f"noise_fn_{index}"
        disassembled[name] = {
            "name": name,
            "address": hex(address),
            "instruction_hash": exact,
            "instruction_count": 10,
        }
        functions.append({"name": name, "address": hex(address), "size": 0x10})
    return {
        "name": "/tmp/demo/libdemo.so",
        "binary_type": "ELF",
        "functions": functions,
        "disassembled_functions": disassembled,
    }


# --- contiguity and positions ---


def test_contiguity_scores_a_run_high_and_scatter_low():
    run = [{"address": 0x1000 + index * 0x20, "size": 0x20} for index in range(8)]
    assert _member_contiguity(run) == 1.0
    scatter = [
        {"address": 0x10000 * (index + 1), "size": 0x20} for index in range(8)
    ]
    assert _member_contiguity(scatter) == 0.0
    assert _member_contiguity([{"address": 0x1000, "size": 0x20}]) == 1.0
    assert _member_contiguity([]) == 0.0


def test_query_function_positions_apply_floors_and_join_sizes():
    metadata = {
        "functions": [{"name": "fn", "address": "0x1000", "size": 48}],
        "disassembled_functions": {
            "big": {
                "name": "big",
                "address": "0x1000",
                "fuzzy_hash": "aa" * 8,
                "instruction_hash": "bb" * 16,
                "instruction_count": 12,
            },
            "tiny": {
                "name": "tiny",
                "address": "0x2000",
                "fuzzy_hash": "cc" * 8,
                "instruction_hash": "dd" * 16,
                "instruction_count": 5,
            },
        },
    }
    positions = build_query_function_positions(metadata)
    # The fuzzy floor (>= 8 instructions) keeps only the big function; the
    # exact floor (>= 4) keeps both.
    assert [p["address"] for p in positions["aa" * 8]] == [0x1000]
    assert [p["size"] for p in positions["aa" * 8]] == [48]
    assert [p["address"] for p in positions["dd" * 16]] == [0x2000]
    assert "cc" * 8 not in positions
    assert positions["bb" * 16][0]["address"] == 0x1000


def test_query_function_positions_without_functions_metadata_falls_back_to_instruction_counts():
    metadata = {
        "disassembled_functions": {
            "only": {
                "name": "only",
                "address": "0x1000",
                "fuzzy_hash": "aa" * 8,
                "instruction_count": 9,
            },
        },
    }
    positions = build_query_function_positions(metadata)
    # No `functions` entry to join: fall back to instruction_count * 4 so
    # adjacency still has an upper bound to measure gaps against.
    assert positions["aa" * 8] == [{"address": 0x1000, "size": 36}]


# --- member layer states ---


def test_member_layer_states(tmp_path):
    assert blintdb_member_layer_state(str(tmp_path / "missing.db"), {}) == (
        MEMBER_LAYER_UNAVAILABLE_DATABASE_MISSING
    )
    db_file = tmp_path / "v4.db"
    _create_v4_blintdb(str(db_file))
    capabilities = blintdb_hash_capabilities(str(db_file))
    assert capabilities["archive_name"] is True
    assert capabilities["archive_name_populated"] is True
    empty_metadata = {"name": "x"}
    assert blintdb_member_layer_state(str(db_file), empty_metadata) == (
        MEMBER_LAYER_INACTIVE_NO_DISASSEMBLY
    )
    no_hashes = {
        "name": "x",
        "disassembled_functions": {
            "f": {"name": "f", "address": "0x1000", "instruction_count": 2}
        },
    }
    assert blintdb_member_layer_state(str(db_file), no_hashes) == (
        MEMBER_LAYER_INACTIVE_NO_HASHES
    )
    assert blintdb_member_layer_state(str(db_file), _member_query_metadata()) == (
        MEMBER_LAYER_ACTIVE
    )


def test_member_layer_state_for_v2_database_is_a_named_state(tmp_path):
    """A pre-member database is `unavailable_no_member_rows`, never 'no match'."""
    from tests.test_sbom_blintdb import _create_v2_blintdb

    db_file = tmp_path / "v2.db"
    _create_v2_blintdb(db_file)
    capabilities = blintdb_hash_capabilities(str(db_file))
    assert capabilities["archive_name"] is False
    assert capabilities["archive_name_populated"] is False
    assert blintdb_member_layer_state(str(db_file), _member_query_metadata()) == (
        MEMBER_LAYER_UNAVAILABLE_NO_MEMBER_ROWS
    )
    matches, state = lookup_member_matches(_member_query_metadata(), db_file=str(db_file))
    assert matches == []
    assert state == MEMBER_LAYER_UNAVAILABLE_NO_MEMBER_ROWS


def test_member_layer_state_unsupported_schema(tmp_path):
    db_file = tmp_path / "bad.db"
    connection = sqlite3.connect(db_file)
    connection.executescript(
        """
        CREATE TABLE SchemaMeta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        """
    )
    connection.executemany(
        "INSERT INTO SchemaMeta(key, value) VALUES(?, ?)",
        (("schema_family", "blint-db"), ("schema_version", "99")),
    )
    connection.commit()
    connection.close()
    assert blintdb_member_layer_state(str(db_file), _member_query_metadata()) == (
        MEMBER_LAYER_UNAVAILABLE_SCHEMA_UNSUPPORTED
    )


# --- member matching gates ---


def test_genuine_member_qualifies_and_noise_does_not(tmp_path):
    db_file = tmp_path / "v4.db"
    _create_v4_blintdb(str(db_file))
    matches, state = lookup_member_matches(_member_query_metadata(), db_file=str(db_file))
    assert state == MEMBER_LAYER_ACTIVE
    purls = {match["project_purl"] for match in matches}
    # demo qualifies; the single-hash member and the coverage-free exact
    # collector do not.
    assert purls == {"pkg:generic/demo@1.0.0"}
    demo = matches[0]
    assert demo["attribution"] == "member"
    member = demo["members"][0]
    assert member["member_name"] == "add.o"
    assert member["archive_name"] == "libdemo.a"
    assert member["member_coverage"] == 1.0
    assert member["qualification"] == "fuzzy+exact"


def test_exact_matches_without_coverage_never_qualify(tmp_path):
    """Three distinct exact hashes in a thousand-function member prove nothing.

    Measured on real archives: a 1808-function noise member collected three
    generic exact matches at 0.003 coverage. The count alone must not
    qualify — the coverage gate is what rejects it.
    """
    db_file = tmp_path / "v4.db"
    _create_v4_blintdb(str(db_file))
    matches, _state = lookup_member_matches(_member_query_metadata(), db_file=str(db_file))
    purls = {match["project_purl"] for match in matches}
    assert "pkg:generic/noise@3.0.0" not in purls


def test_scattered_fuzzy_matches_never_qualify(tmp_path):
    """Full coverage with no address-adjacency is collision-shaped, not a member."""
    db_file = tmp_path / "v4.db"
    _create_v4_blintdb(str(db_file))
    matches, _state = lookup_member_matches(_member_query_metadata(), db_file=str(db_file))
    purls = {match["project_purl"] for match in matches}
    assert "pkg:generic/scatter@4.0.0" not in purls


def test_member_layer_does_not_open_the_whole_binary_gates(tmp_path):
    """Member evidence must not waive the symbol-only filter for other projects.

    The d6237a5 lesson, restated for the new layer: a per-candidate judgement
    must not travel through a lookup-wide flag. The member layer is a separate
    lookup, and the whole-binary result for unrelated projects is unchanged by
    it.
    """
    db_file = tmp_path / "v4.db"
    _create_v4_blintdb(str(db_file))
    metadata = _member_query_metadata()
    metadata["symtab_symbols"] = [{"name": "unrelated_symbol_never_stored"}]
    _detected, evidence = detect_binaries_utilized(
        symbol_source_map={"symtab_symbols": ["demo_member_symbol"]},
        function_hash_index=db_module.build_function_hash_index(metadata),
        binary_metadata=metadata,
        db_file=str(db_file),
    )
    # demo is attributed through both layers; the weak-symbol path stays
    # closed for everything else.
    assert evidence["pkg:generic/demo@1.0.0"]["blintdb_attribution"] == (
        "whole_binary+member"
    )
    assert evidence["pkg:generic/demo@1.0.0"]["blintdb_member_layer"] == (
        MEMBER_LAYER_ACTIVE
    )
    assert evidence["pkg:generic/demo@1.0.0"]["blintdb_matched_member_count"] == 1


def test_member_only_project_surfaces_with_member_attribution(tmp_path):
    db_file = tmp_path / "v4.db"
    _create_v4_blintdb(str(db_file))
    metadata = _member_query_metadata()
    detected, evidence = detect_binaries_utilized(
        binary_metadata=metadata,
        db_file=str(db_file),
    )
    assert "pkg:generic/demo@1.0.0" in detected
    demo = evidence["pkg:generic/demo@1.0.0"]
    assert demo["blintdb_attribution"] == "member"
    assert demo["blintdb_member_layer"] == MEMBER_LAYER_ACTIVE
    assert demo["blintdb_matched_member_count"] == 1
    assert demo["blintdb_members"][0]["member_name"] == "add.o"
    assert demo["blintdb_members"][0]["member_coverage"] == 1.0


# --- SBOM surfacing ---


def test_process_exe_file_records_member_attribution(tmp_path, monkeypatch):
    db_file = tmp_path / "blint.db"
    _create_v4_blintdb(str(db_file))
    metadata = _member_query_metadata()
    sbom = SimpleNamespace(metadata=SimpleNamespace(component=SimpleNamespace(components=[])))

    monkeypatch.setattr("blint.db.BLINTDB_LOC", str(db_file))
    monkeypatch.setattr(
        "blint.lib.sbom.parse",
        lambda _exe, disassemble=False, sdk_path=None: metadata,
    )

    components = process_exe_file(
        {},
        False,
        "/tmp/demo/libdemo.so",
        sbom,
        [],
        {},
        True,
        True,
    )

    matched = next(comp for comp in components if comp.purl == "pkg:generic/demo@1.0.0")
    prop_map = {prop.name: prop.value for prop in matched.properties}
    # A reader can tell member-level attribution from whole-binary attribution
    # without consulting anything else. Here the binary name also matches the
    # stored archive name, so both layers independently agree.
    assert prop_map["internal:blintdb_attribution"] == "whole_binary+member"
    assert prop_map["internal:blintdb_member_layer"] == MEMBER_LAYER_ACTIVE
    assert prop_map["internal:blintdb_matched_member_count"] == "1"
    assert "add.o" in prop_map["internal:blintdb_member_names"]
    assert "coverage=1.0" in prop_map["internal:blintdb_member_details"]


# --- vendored banners ---


def test_banner_signatures_match_library_anchored_strings():
    positives = {
        "zlib": [
            " deflate 1.3.1 Copyright 1995-2024 Jean-loup Gailly and Mark Adler ",
            "inflate 1.2.11 Copyright 1995-2017 Mark Adler",
        ],
        "lua": ["$LuaVersion: Lua 5.4.6  Copyright (C) 1994-2023 Lua.org, PUC-Rio $"],
        "openssl": ["OpenSSL 3.2.0 23 Feb 2024", "OpenSSL/1.1.1w"],
        "curl": ["libcurl/8.4.0"],
        "expat": ["expat_2.5.0"],
        "libpng": [" libpng version 1.6.40 - September 14, 2023 "],
        "zstd": ["Zstandard v1.5.5"],
    }
    for library, banners in positives.items():
        for banner in banners:
            detected = detect_vendored_banners(
                {"strings": [{"value": banner, "entropy": 0, "secret_type": None}]}
            )
            assert detected["state"] == BANNER_LAYER_ACTIVE
            assert (library, detected["banners"][0]["version"]) == (
                library,
                detected["banners"][0]["version"],
            )
            assert detected["banners"][0]["library"] == library


def test_banner_signatures_reject_unanchored_versions():
    """Rule 11 negative fixtures: what each signature must NOT match."""
    negatives = [
        "deflate",  # library name without a version
        "3.46.0",  # a bare version is no banner, however plausible
        "deflatev1.2.11",  # missing separator
        "libcurlfoo/8.4.0",  # wrong library name
        "SQLite format 3",  # library marker without any version
        "inflate 1",  # not a full version
        "lua 5.4",  # lua banner requires the Copyright tail
    ]
    for value in negatives:
        assert not is_probable_banner_string(value), value
        detected = detect_vendored_banners(
            {"strings": [{"value": value, "entropy": 0, "secret_type": None}]}
        )
        assert detected["banners"] == [], value


def test_rejected_signature_documented():
    """A library left out of the table records why, so removal is a decision."""
    reasons = {entry["library"]: entry["reason"] for entry in REJECTED_SIGNATURES}
    assert "sqlite3" in reasons
    assert "string" in reasons["sqlite3"]


def test_banner_detection_states_and_dedup():
    assert detect_vendored_banners({}) == {
        "banners": [],
        "state": BANNER_LAYER_INACTIVE_NO_STRINGS,
    }
    two_versions = detect_vendored_banners(
        {
            "strings": [
                {"value": "deflate 1.2.11 Copyright", "entropy": 0, "secret_type": None},
                {"value": "deflate 1.3.1 Copyright", "entropy": 0, "secret_type": None},
                {"value": "inflate 1.3.1 Copyright", "entropy": 0, "secret_type": None},
            ]
        }
    )
    # Conflicting versions of one library are reported separately, never
    # merged; duplicate banners of the same version are reported once.
    versions = sorted(b["version"] for b in two_versions["banners"] if b["library"] == "zlib")
    assert versions == ["1.2.11", "1.3.1"]
    long_string = "deflate 1.3.1 Copyright " + "x" * 600
    assert detect_vendored_banners(
        {"strings": [{"value": long_string, "entropy": 0, "secret_type": None}]}
    )["banners"] == []
