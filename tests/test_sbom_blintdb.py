import sqlite3
from types import SimpleNamespace

from blint import db as db_module
from blint.config import BlintOptions
from blint.db import (
    CFG_HASH_MATCH_WEIGHT,
    FUZZY_ONLY_MATCH_THRESHOLD,
    HASH_LAYER_ACTIVE,
    HASH_LAYER_INACTIVE_NO_DISASSEMBLY,
    HASH_LAYER_INACTIVE_NO_FUZZY_HASHES,
    HASH_LAYER_UNAVAILABLE_COLUMNS_ABSENT,
    HASH_LAYER_UNAVAILABLE_COLUMNS_UNPOPULATED,
    MIN_FUNCTION_INSTRUCTION_COUNT_FOR_FUZZY_HASH_LOOKUP,
    blintdb_fuzzy_layer_state,
    blintdb_hash_capabilities,
    build_function_hash_index,
    build_symbol_source_map,
    detect_binaries_utilized,
    is_supported_blintdb,
    lookup_project_matches,
)
from blint.lib.sbom import process_exe_file


def _create_v2_blintdb(db_file):
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
            instruction_hash TEXT,
            assembly_hash TEXT,
            FOREIGN KEY (binary_id) REFERENCES Binaries(binary_id)
        );
        CREATE INDEX idx_symbols_lookup ON Symbols(name, source, binary_id);
        CREATE INDEX idx_functions_instruction_hash_binary ON FunctionFingerprints(instruction_hash, binary_id);
        CREATE INDEX idx_functions_assembly_hash_binary ON FunctionFingerprints(assembly_hash, binary_id);
        """
    )
    connection.executemany(
        "INSERT INTO SchemaMeta(key, value) VALUES(?, ?)",
        (("schema_family", "blint-db"), ("schema_version", "2")),
    )
    connection.execute(
        "INSERT INTO Projects(project_id, name, purl) VALUES(1, 'demo', 'pkg:generic/demo@1.0.0')"
    )
    connection.execute(
        "INSERT INTO Projects(project_id, name, purl) VALUES(2, 'other', 'pkg:generic/other@2.0.0')"
    )
    connection.execute(
        "INSERT INTO Builds(build_id, project_id, llvm_target_tuple) VALUES(1, 1, 'x86_64-pc-linux-gnu')"
    )
    connection.execute(
        "INSERT INTO Builds(build_id, project_id, llvm_target_tuple) VALUES(2, 2, 'x86_64-pc-linux-gnu')"
    )
    connection.execute(
        "INSERT INTO Binaries(binary_id, build_id, name, binary_type, llvm_target_tuple) VALUES(1, 1, 'libdemo.so', 'ELF', 'x86_64-pc-linux-gnu')"
    )
    connection.execute(
        "INSERT INTO Binaries(binary_id, build_id, name, binary_type, llvm_target_tuple) VALUES(2, 2, 'libother.so', 'ELF', 'x86_64-pc-linux-gnu')"
    )
    connection.executemany(
        "INSERT INTO Symbols(binary_id, name, source) VALUES(?, ?, ?)",
        [
            # F2b.1: each project carries its own identity names. A name two
            # projects share (the old fixture had helper and puts in both) is
            # low information by definition - spread suppression drops it -
            # and imports never identify a project anyway.
            (1, "helper", "symtab_symbols"),
            (1, "puts", "imports"),
            (1, "strlen", "dynamic_symbols"),
            (2, "other_helper", "symtab_symbols"),
        ],
    )
    connection.executemany(
        "INSERT INTO FunctionFingerprints(binary_id, function_key, instruction_hash, assembly_hash) VALUES(?, ?, ?, ?)",
        [
            (1, f"0x401000::fn{digit}", "b" * 63 + digit, "a" * 64)
            for digit in "01234567"
        ]
        + [
            (1, "0x401000::helper", "b" * 64, "a" * 64),
            (2, "0x501000::helper", "d" * 64, "c" * 64),
        ],
    )
    connection.commit()
    connection.close()


def _sample_metadata():
    return {
        "name": "/tmp/demo/libdemo.so",
        "binary_type": "ELF",
        "llvm_target_tuple": "x86_64-pc-linux-gnu",
        "symtab_symbols": [{"name": "helper", "is_function": True}],
        "imports": [{"name": "puts", "is_imported": True, "is_function": True}],
        "dynamic_symbols": [{"name": "strlen", "is_imported": True, "is_function": True}],
        "disassembled_functions": {
            "0x401000::helper": {
                "name": "helper",
                "address": "0x401000",
                "rvaOrAddress": "0x1000",
                "instruction_hash": "b" * 64,
                "assembly_hash": "a" * 64,
            }
        },
    }


# --- similarity hash columns (fuzzy_hash / cfg_hash / import_hash) ---
#
# blint reads blintdb; it never builds one. A producer carrying the new
# columns is emulated here with a v3 fixture built the same way the v2 one
# is, and the three degradation states below are named, tested outcomes:
# v2 (columns absent), v3 populated, v3 columns present but NULL.


def _create_v3_blintdb(db_file, *, populate=True):
    """A database carrying the similarity hash columns (schema_version 3).

    With populate=False the columns exist but hold only NULL/empty values,
    which is a distinct, named degradation state — never "nothing matched".
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
            import_hash TEXT,
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
            instruction_hash TEXT,
            assembly_hash TEXT,
            fuzzy_hash TEXT,
            cfg_hash TEXT,
            instruction_count INTEGER,
            FOREIGN KEY (binary_id) REFERENCES Binaries(binary_id)
        );
        CREATE INDEX idx_functions_fuzzy_hash ON FunctionFingerprints(fuzzy_hash);
        CREATE INDEX idx_functions_cfg_hash ON FunctionFingerprints(cfg_hash);
        CREATE INDEX idx_binaries_import_hash ON Binaries(import_hash);
        """
    )
    connection.executemany(
        "INSERT INTO SchemaMeta(key, value) VALUES(?, ?)",
        (("schema_family", "blint-db"), ("schema_version", "3")),
    )
    connection.execute(
        "INSERT INTO Projects(project_id, name, purl) VALUES(1, 'demo', 'pkg:generic/demo@1.0.0')"
    )
    connection.execute(
        "INSERT INTO Projects(project_id, name, purl) VALUES(2, 'other', 'pkg:generic/other@2.0.0')"
    )
    connection.execute(
        "INSERT INTO Builds(build_id, project_id, llvm_target_tuple) VALUES(1, 1, 'x86_64-pc-linux-gnu')"
    )
    connection.execute(
        "INSERT INTO Builds(build_id, project_id, llvm_target_tuple) VALUES(2, 2, 'x86_64-pc-linux-gnu')"
    )
    # demo carries a matching import set; other does not (static, empty).
    connection.execute(
        "INSERT INTO Binaries(binary_id, build_id, name, binary_type, llvm_target_tuple, import_hash)"
        " VALUES(1, 1, 'libdemo.so', 'ELF', 'x86_64-pc-linux-gnu', ?)",
        ("1a2b3c4d5e6f7081" if populate else None,),
    )
    connection.execute(
        "INSERT INTO Binaries(binary_id, build_id, name, binary_type, llvm_target_tuple, import_hash)"
        " VALUES(2, 2, 'libother.so', 'ELF', 'x86_64-pc-linux-gnu', NULL)"
    )
    connection.executemany(
        "INSERT INTO Symbols(binary_id, name, source) VALUES(?, ?, ?)",
        [
            # distinct identity names per project (F2b.1 spread suppression)
            (1, "helper", "symtab_symbols"),
            (1, "puts", "imports"),
            (2, "other_helper", "symtab_symbols"),
        ],
    )
    fuzzy_values = [f"{i:016x}" for i in range(8)] if populate else [None] * 8
    cfg_values = ["0fedcba987654321"] if populate else [None]
    rows = []
    for index, fuzzy in enumerate(fuzzy_values):
        rows.append(
            # demo: same code under compiler drift — exact hashes differ from
            # the query side below, fuzzy hashes match it.
            (
                1,
                f"0x401000::alpha{index}",
                f"a{index:063x}",
                f"b{index:063x}",
                fuzzy,
                cfg_values[0] if index == 0 else None,
                24 + index,
            )
        )
    # other: an unrelated project sharing one generic fuzzy shape.
    rows.append((2, "0x501000::gamma", "5" * 64, "4" * 64, fuzzy_values[0], None, 24))
    connection.executemany(
        "INSERT INTO FunctionFingerprints(binary_id, function_key, instruction_hash,"
        " assembly_hash, fuzzy_hash, cfg_hash, instruction_count) VALUES(?, ?, ?, ?, ?, ?, ?)",
        rows,
    )
    connection.commit()
    connection.close()


def _fuzzy_metadata(fuzzy_count=8, total=8, **overrides):
    """A drifted recompile of libdemo: exact hashes differ, fuzzy hashes match.

    Yields ``total`` disassembled functions of which the first ``fuzzy_count``
    carry fuzzy hashes stored under the demo project, so tests can place the
    query on either side of the count and coverage gates.
    """
    functions = {}
    for index in range(total):
        functions[f"0x601000::alpha{index}"] = {
            "name": f"alpha{index}",
            "instruction_hash": f"c{index:063x}",
            "assembly_hash": f"d{index:063x}",
            "fuzzy_hash": f"{index:016x}" if index < fuzzy_count else f"ffff{index:012x}",
            "cfg_hash": "0fedcba987654321" if index == 0 else None,
            "instruction_count": 24 + index,
        }
    metadata = {
        "name": "/tmp/mystery/libdemo",
        "binary_type": "ELF",
        "llvm_target_tuple": "x86_64-pc-linux-gnu",
        "import_hash": "1a2b3c4d5e6f7081",
        "disassembled_functions": functions,
    }
    metadata.update(overrides)
    return metadata


def _v3_query_metadata(**overrides):
    return _fuzzy_metadata(**overrides)


def test_lookup_project_matches_prefers_function_hashes(tmp_path):
    db_file = tmp_path / "blint.db"
    _create_v2_blintdb(db_file)

    # A population of exact hashes (HASH_ONLY_MATCH_THRESHOLD = 8): one
    # shared 4-instruction thunk is a compiler artifact, not a shared project
    # (measured on tier-0 deep mode, F2b.1).
    instruction_hashes = ["b" * 63 + digit for digit in "01234567"]
    matches = lookup_project_matches(
        {
            "symtab_symbols": ["helper"],
            # The imports bucket is skipped entirely (F2b.1): it names what
            # the artifact links against, not what it is.
            "imports": ["puts"],
            "dynamic_symbols": ["strlen"],
        },
        function_hash_index={
            "instruction_hashes": instruction_hashes,
            "assembly_hashes": ["a" * 64],
        },
        binary_metadata={
            "binary_type": "ELF",
            "llvm_target_tuple": "x86_64-pc-linux-gnu",
        },
        db_file=str(db_file),
    )

    assert matches
    assert matches[0]["project_purl"] == "pkg:generic/demo@1.0.0"
    assert matches[0]["matched_instruction_hash_count"] == 8
    assert matches[0]["matched_symbol_count"] == 2
    assert matches[0]["score"] >= 20.0


def test_detect_binaries_utilized_returns_rich_evidence(tmp_path):
    db_file = tmp_path / "blint.db"
    _create_v2_blintdb(db_file)

    binaries_detected, evidence = detect_binaries_utilized(
        symbol_source_map={"imports": ["puts"], "symtab_symbols": ["helper"]},
        function_hash_index={"instruction_hashes": ["b" * 64]},
        binary_metadata={
            "name": "libdemo.so",
            "binary_type": "ELF",
            "llvm_target_tuple": "x86_64-pc-linux-gnu",
        },
        db_file=str(db_file),
    )

    assert binaries_detected == {"pkg:generic/demo@1.0.0"}
    assert evidence["pkg:generic/demo@1.0.0"]["matched_instruction_hash_count"] == 1
    assert evidence["pkg:generic/demo@1.0.0"]["matched_symbols"] == ["helper"]


def test_process_exe_file_uses_blintdb_hash_matches(tmp_path, monkeypatch):
    db_file = tmp_path / "blint.db"
    _create_v2_blintdb(db_file)
    metadata = _sample_metadata()
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

    assert matched.purl == "pkg:generic/demo@1.0.0"
    assert prop_map["internal:blintdb_matched_instruction_hash_count"] == "1"
    assert prop_map["internal:blintdb_binary_name_match"] == "True"
    # F2b.1: puts and strlen are libc imports of the demo binary - an import
    # names the provider library, not the artifact, so only the demo's own
    # defined symbol counts as a match.
    assert prop_map["internal:blintdb_matched_symbols"] == "helper"


def test_blint_options_auto_enable_disassembly_for_deep_blintdb_sbom():
    options = BlintOptions(
        sbom_mode=True,
        deep_mode=True,
        use_blintdb=True,
        src_dir_image=["."],
    )

    assert options.disassemble is True


# --- Regression tests for apsw ExecutionCompleteError on zero-row queries ---
#
# apsw raises ExecutionCompleteError from cursor.getdescription() when an
# aggregate (GROUP BY) query completes without yielding any rows. The stdlib
# sqlite3 driver never exhibits this (cursor.description is always available),
# so these tests deliberately open the database through apsw (via blint.db.get)
# to exercise the real code path that ``blint sbom --use-blintdb`` uses.


def test_execute_returns_empty_for_zero_row_aggregate(tmp_path):
    """_execute must return [] (not raise) for a GROUP BY with no matching rows."""
    db_file = tmp_path / "blint.db"
    _create_v2_blintdb(db_file)
    connection = db_module.get(str(db_file))
    assert connection is not None
    try:
        rows = db_module._execute(
            connection,
            "SELECT binary_id, COUNT(*) FROM Symbols WHERE name = ? GROUP BY binary_id",
            ["this_symbol_does_not_exist"],
        )
        assert rows == []
    finally:
        connection.close()


def test_execute_returns_rows_for_matching_aggregate(tmp_path):
    """_execute still returns dict rows when the GROUP BY query has matches."""
    db_file = tmp_path / "blint.db"
    _create_v2_blintdb(db_file)
    connection = db_module.get(str(db_file))
    assert connection is not None
    try:
        rows = db_module._execute(
            connection,
            "SELECT binary_id, COUNT(*) AS cnt FROM Symbols WHERE name = ? GROUP BY binary_id",
            ["helper"],
        )
        # helper is demo's identity name alone since F2b.1 - the shared-name
        # fixture rows were low information and are gone.
        assert len(rows) == 1
        assert rows[0]["binary_id"] == 1
        assert rows[0]["cnt"] == 1
    finally:
        connection.close()


def test_lookup_project_matches_with_no_matching_symbols(tmp_path):
    """A lookup whose symbols match nothing must return [] without crashing."""
    db_file = tmp_path / "blint.db"
    _create_v2_blintdb(db_file)

    matches = lookup_project_matches(
        {"symtab_symbols": ["does_not_exist", "also_missing"]},
        binary_metadata={
            "binary_type": "ELF",
            "llvm_target_tuple": "x86_64-pc-linux-gnu",
        },
        db_file=str(db_file),
    )
    assert matches == []


def test_lookup_project_matches_with_no_matching_hashes(tmp_path):
    """A hash lookup that matches nothing exercises the GROUP BY zero-row path."""
    db_file = tmp_path / "blint.db"
    _create_v2_blintdb(db_file)

    matches = lookup_project_matches(
        function_hash_index={
            "instruction_hashes": ["0" * 64],
            "assembly_hashes": ["0" * 64],
        },
        binary_metadata={
            "binary_type": "ELF",
            "llvm_target_tuple": "x86_64-pc-linux-gnu",
        },
        db_file=str(db_file),
    )
    assert matches == []


def test_detect_binaries_utilized_with_no_matches(tmp_path):
    """detect_binaries_utilized must degrade to empty results, not crash."""
    db_file = tmp_path / "blint.db"
    _create_v2_blintdb(db_file)

    detected, evidence = detect_binaries_utilized(
        symbol_source_map={"symtab_symbols": ["nonexistent_symbol"]},
        function_hash_index={"instruction_hashes": ["0" * 64]},
        binary_metadata={
            "binary_type": "ELF",
            "llvm_target_tuple": "x86_64-pc-linux-gnu",
        },
        db_file=str(db_file),
    )
    assert detected == set()
    assert evidence == {}


# --- Degradation state 1: v2 database, columns absent ---


def test_v2_database_hash_columns_absent(tmp_path):
    """A v2 database reports its missing hash columns and keeps working."""
    db_file = tmp_path / "blint.db"
    _create_v2_blintdb(db_file)

    capabilities = blintdb_hash_capabilities(str(db_file))
    assert capabilities["fuzzy_hash"] is False
    assert capabilities["cfg_hash"] is False
    assert capabilities["import_hash"] is False
    assert "fuzzy_hash_populated" in capabilities
    assert blintdb_fuzzy_layer_state(str(db_file)) == HASH_LAYER_UNAVAILABLE_COLUMNS_ABSENT
    assert is_supported_blintdb(str(db_file)) is True

    # The exact, symbol and name layers behave exactly as before: an exact
    # instruction-hash hit, a shared symbol and the binary-name bonus score 44
    # and no fuzzy counts appear anywhere.
    metadata = _fuzzy_metadata(symtab_symbols=[{"name": "helper", "is_function": True}])
    for function_data in metadata["disassembled_functions"].values():
        function_data["instruction_hash"] = "b" * 64
        function_data["assembly_hash"] = "0" * 64
    matches = lookup_project_matches(
        symbol_source_map={"symtab_symbols": ["helper"]},
        function_hash_index=build_function_hash_index(metadata),
        binary_metadata=metadata,
        db_file=str(db_file),
    )
    demo = next(m for m in matches if m["project_purl"] == "pkg:generic/demo@1.0.0")
    assert demo["matched_fuzzy_hash_count"] == 0
    assert demo["matched_import_hash_count"] == 0
    assert demo["matched_symbol_count"] == 1
    assert demo["matched_instruction_hash_count"] == 1
    assert demo["binary_name_match"] is True
    assert demo["score"] == 44.0


# --- Degradation state 2: v3 database, columns populated ---


def test_v3_populated_fuzzy_hashes_attribute(tmp_path):
    """A drifted recompile attributes through the fuzzy layer alone."""
    db_file = tmp_path / "blint.db"
    _create_v3_blintdb(db_file)
    metadata = _fuzzy_metadata()
    assert blintdb_fuzzy_layer_state(str(db_file), metadata) == HASH_LAYER_ACTIVE

    matches = lookup_project_matches(
        function_hash_index=build_function_hash_index(metadata),
        binary_metadata=metadata,
        db_file=str(db_file),
    )
    assert matches, "fuzzy-only attribution must surface the drifted recompile"
    top = matches[0]
    assert top["project_purl"] == "pkg:generic/demo@1.0.0"
    assert top["matched_fuzzy_hash_count"] == FUZZY_ONLY_MATCH_THRESHOLD
    # The unrelated project sharing one generic fuzzy shape stays out.
    assert all(m["project_purl"] != "pkg:generic/other@2.0.0" for m in matches)
    # Fuzzy evidence ranks below exact evidence: it never outvotes it.
    assert top["matched_instruction_hash_count"] == 0

    detected, evidence = detect_binaries_utilized(
        function_hash_index=build_function_hash_index(metadata),
        binary_metadata=metadata,
        db_file=str(db_file),
    )
    assert detected == {"pkg:generic/demo@1.0.0"}
    assert evidence["pkg:generic/demo@1.0.0"]["matched_fuzzy_hash_count"] == (
        FUZZY_ONLY_MATCH_THRESHOLD
    )


def test_v3_fuzzy_below_count_threshold_never_attributes(tmp_path):
    """Two colliding generic fuzzy functions are corroboration, not attribution."""
    db_file = tmp_path / "blint.db"
    _create_v3_blintdb(db_file)
    # Only 2 of the query's 8 functions carry demo's fuzzy hashes; import
    # hash and binary name are neutralized so fuzzy really is the only channel.
    metadata = _fuzzy_metadata(
        fuzzy_count=2, total=8, import_hash=None, name="/tmp/unknown/mystery-binary"
    )

    matches = lookup_project_matches(
        function_hash_index=build_function_hash_index(metadata),
        binary_metadata=metadata,
        db_file=str(db_file),
    )
    assert matches == []


def test_v3_fuzzy_below_coverage_threshold_never_attributes(tmp_path):
    """A 40% fuzzy overlap is a shared shape, not the same project."""
    db_file = tmp_path / "blint.db"
    _create_v3_blintdb(db_file)
    # All 8 demo fuzzy hashes match, but the query has 20 floor-passing
    # functions, so coverage is 40% — below FUZZY_ONLY_MIN_QUERY_COVERAGE.
    metadata = _fuzzy_metadata(
        fuzzy_count=8, total=20, import_hash=None, name="/tmp/unknown/mystery-binary"
    )

    matches = lookup_project_matches(
        function_hash_index=build_function_hash_index(metadata),
        binary_metadata=metadata,
        db_file=str(db_file),
    )
    assert matches == []


def test_v3_cfg_hash_is_evidence_without_weight(tmp_path):
    """cfg_hash matches are recorded but never move the score."""
    db_file = tmp_path / "blint.db"
    _create_v3_blintdb(db_file)
    metadata = _fuzzy_metadata(import_hash=None, name="/tmp/unknown/mystery-binary")
    index = build_function_hash_index(metadata)
    assert "cfg_hashes" in index

    with_cfg = lookup_project_matches(
        function_hash_index=index, binary_metadata=metadata, db_file=str(db_file)
    )
    # Same query minus the cfg hashes: the score must not move by a single
    # point, proving CFG_HASH_MATCH_WEIGHT really is zero.
    for functions in metadata["disassembled_functions"].values():
        functions.pop("cfg_hash", None)
    without_cfg = lookup_project_matches(
        function_hash_index=build_function_hash_index(metadata),
        binary_metadata=metadata,
        db_file=str(db_file),
    )
    assert with_cfg[0]["matched_cfg_hash_count"] == 1
    assert without_cfg[0]["matched_cfg_hash_count"] == 0
    assert with_cfg[0]["score"] == without_cfg[0]["score"]
    assert CFG_HASH_MATCH_WEIGHT == 0.0


def test_v3_import_hash_corroborates_but_never_attributes_alone(tmp_path):
    """A matching import set adds score but can never surface a match alone."""
    db_file = tmp_path / "blint.db"
    _create_v3_blintdb(db_file)
    # Symbol, exact-hash and name evidence qualify the match; the import set
    # digest only adds its weight on top, proven by running the same query
    # with an empty import set.
    base_metadata = {
        "name": "/tmp/mystery/libdemo",
        "binary_type": "ELF",
        "llvm_target_tuple": "x86_64-pc-linux-gnu",
        "symtab_symbols": [{"name": "helper", "is_function": True}],
        "disassembled_functions": {
            "0x601000::alpha0": {
                "name": "alpha0",
                "instruction_hash": f"a{0:063x}",
                "instruction_count": 24,
            }
        },
    }
    with_import = dict(base_metadata, import_hash="1a2b3c4d5e6f7081")
    without_import = dict(base_metadata, import_hash="")
    matches = lookup_project_matches(
        symbol_source_map={"symtab_symbols": ["helper"]},
        function_hash_index={"instruction_hashes": [f"a{0:063x}"]},
        binary_metadata=with_import,
        db_file=str(db_file),
    )
    demo = next(m for m in matches if m["project_purl"] == "pkg:generic/demo@1.0.0")
    assert demo["matched_import_hash_count"] == 1
    matches_no_import = lookup_project_matches(
        symbol_source_map={"symtab_symbols": ["helper"]},
        function_hash_index={"instruction_hashes": [f"a{0:063x}"]},
        binary_metadata=without_import,
        db_file=str(db_file),
    )
    demo_without = next(
        m for m in matches_no_import if m["project_purl"] == "pkg:generic/demo@1.0.0"
    )
    assert demo_without["matched_import_hash_count"] == 0
    # The whole contribution of the import layer is its single weight.
    assert demo["score"] == demo_without["score"] + 4.0 == 48.0

    # Import evidence alone is not a lookup at all: nothing but the binary's
    # import hash means nothing to attribute, whatever the database holds.
    lone = lookup_project_matches(
        binary_metadata={
            "name": "/tmp/mystery/unknown-binary",
            "binary_type": "ELF",
            "import_hash": "1a2b3c4d5e6f7081",
        },
        db_file=str(db_file),
    )
    assert lone == []


def test_v3_import_hash_empty_never_matches(tmp_path):
    """An empty import hash must not attribute a binary to other empty ones."""
    db_file = tmp_path / "blint.db"
    _create_v3_blintdb(db_file)
    # libother.so stores a NULL import hash; the query is static (empty) and
    # carries real hash/symbol/name evidence for libother, so attribution
    # comes from those layers — never from the empty import set.
    metadata = {
        "name": "/tmp/mystery/libother.so",
        "binary_type": "ELF",
        "llvm_target_tuple": "x86_64-pc-linux-gnu",
        "import_hash": "",
        "symtab_symbols": [{"name": "puts", "is_function": True}],
        "disassembled_functions": {
            "0x501000::gamma": {
                "name": "gamma",
                "instruction_hash": "5" * 64,
                "instruction_count": 24,
            }
        },
    }
    matches = lookup_project_matches(
        symbol_source_map={"imports": ["puts"]},
        function_hash_index={"instruction_hashes": ["5" * 64]},
        binary_metadata=metadata,
        db_file=str(db_file),
    )
    other = next(m for m in matches if m["project_purl"] == "pkg:generic/other@2.0.0")
    assert other["matched_import_hash_count"] == 0
    assert other["matched_instruction_hash_count"] == 1
    assert other["binary_name_match"] is True


def test_v3_exact_lookup_unaffected_by_similarity_columns(tmp_path):
    """Exact instruction-hash matching works unchanged on a v3 database."""
    db_file = tmp_path / "blint.db"
    _create_v3_blintdb(db_file, populate=False)
    metadata = {
        "name": "/tmp/mystery/libdemo",
        "binary_type": "ELF",
        "llvm_target_tuple": "x86_64-pc-linux-gnu",
        "disassembled_functions": {
            "0x601000::alpha0": {
                "name": "alpha0",
                "instruction_hash": f"a{0:063x}",
                "assembly_hash": f"b{0:063x}",
                "instruction_count": 24,
            }
        },
    }
    matches = lookup_project_matches(
        function_hash_index=build_function_hash_index(metadata),
        binary_metadata=metadata,
        db_file=str(db_file),
    )
    assert matches
    top = matches[0]
    assert top["project_purl"] == "pkg:generic/demo@1.0.0"
    assert top["matched_instruction_hash_count"] == 1
    assert top["matched_fuzzy_hash_count"] == 0


# --- Degradation state 3: v3 database, columns present but NULL ---


def test_v3_unpopulated_columns_named_not_silent(tmp_path):
    """NULL hash columns are a named state; exact matching keeps working."""
    db_file = tmp_path / "blint.db"
    _create_v3_blintdb(db_file, populate=False)

    capabilities = blintdb_hash_capabilities(str(db_file))
    assert capabilities["fuzzy_hash"] is True
    assert capabilities["fuzzy_hash_populated"] is False
    assert capabilities["cfg_hash_populated"] is False
    assert capabilities["import_hash"] is True
    assert capabilities["import_hash_populated"] is False
    assert (
        blintdb_fuzzy_layer_state(str(db_file), _fuzzy_metadata())
        == HASH_LAYER_UNAVAILABLE_COLUMNS_UNPOPULATED
    )

    # A fuzzy-only query must not report zero-matched silence: the lookup
    # finds nothing, and the state names why.
    metadata = _fuzzy_metadata()
    matches = lookup_project_matches(
        function_hash_index=build_function_hash_index(metadata),
        binary_metadata=metadata,
        db_file=str(db_file),
    )
    assert matches == []
    assert (
        blintdb_fuzzy_layer_state(str(db_file), metadata)
        == HASH_LAYER_UNAVAILABLE_COLUMNS_UNPOPULATED
    )


# --- Layer availability on the binary side ---


def test_fuzzy_layer_state_without_disassembly(tmp_path):
    """No disassembled functions means the layer could not run, not zero."""
    db_file = tmp_path / "blint.db"
    _create_v3_blintdb(db_file)
    metadata = _fuzzy_metadata()
    del metadata["disassembled_functions"]
    assert blintdb_fuzzy_layer_state(str(db_file), metadata) == HASH_LAYER_INACTIVE_NO_DISASSEMBLY
    # Disassembly ran but produced no fuzzy hashes (e.g. no assembly text).
    metadata_bare = _fuzzy_metadata()
    for function_data in metadata_bare["disassembled_functions"].values():
        function_data.pop("fuzzy_hash")
    assert (
        blintdb_fuzzy_layer_state(str(db_file), metadata_bare)
        == HASH_LAYER_INACTIVE_NO_FUZZY_HASHES
    )


def test_fuzzy_layer_state_database_problems(tmp_path):
    """Missing and unsupported databases are named states, never lookups."""
    assert blintdb_fuzzy_layer_state("/nonexistent/blint.db") == "unavailable_database_missing"
    db_file = tmp_path / "future.db"
    connection = sqlite3.connect(db_file)
    connection.execute("CREATE TABLE SchemaMeta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    connection.executemany(
        "INSERT INTO SchemaMeta(key, value) VALUES(?, ?)",
        # Schema 4 is in the supported set; use a version no
        # producer has ever stamped as the unsupported case.
        (("schema_family", "blint-db"), ("schema_version", "99")),
    )
    connection.commit()
    connection.close()
    assert is_supported_blintdb(str(db_file)) is False
    assert blintdb_fuzzy_layer_state(str(db_file)) == "unavailable_schema_unsupported"


# --- Query index construction ---


def test_build_function_hash_index_fuzzy_floor():
    """Fuzzy hashes need a known instruction count at the fuzzy floor."""
    metadata = {
        "disassembled_functions": {
            "small": {
                "instruction_hash": "s-i",
                "assembly_hash": "s-a",
                "fuzzy_hash": "s-f",
                "instruction_count": MIN_FUNCTION_INSTRUCTION_COUNT_FOR_FUZZY_HASH_LOOKUP - 1,
            },
            "big": {
                "instruction_hash": "b-i",
                "assembly_hash": "b-a",
                "fuzzy_hash": "b-f",
                "cfg_hash": "b-c",
                "instruction_count": MIN_FUNCTION_INSTRUCTION_COUNT_FOR_FUZZY_HASH_LOOKUP,
            },
            "unknown_size": {"instruction_hash": "u-i", "fuzzy_hash": "u-f"},
        }
    }
    index = build_function_hash_index(metadata)
    assert index["instruction_hashes"] == ["b-i", "s-i", "u-i"]
    assert index["fuzzy_hashes"] == ["b-f"]
    assert index["cfg_hashes"] == ["b-c"]


def test_build_function_hash_index_without_disassembly():
    """No disassembled functions means no hash keys at all — not emptiness."""
    assert build_function_hash_index({"name": "x"}) == {}
    assert build_function_hash_index(None) == {}


# --- SBOM end-to-end on a v3 database ---


def test_process_exe_file_surfaces_fuzzy_evidence_and_layer_state(tmp_path, monkeypatch):
    db_file = tmp_path / "blint.db"
    _create_v3_blintdb(db_file)
    metadata = _fuzzy_metadata()
    sbom = SimpleNamespace(metadata=SimpleNamespace(component=SimpleNamespace(components=[])))

    monkeypatch.setattr("blint.db.BLINTDB_LOC", str(db_file))
    monkeypatch.setattr(
        "blint.lib.sbom.parse",
        lambda _exe, disassemble=False, sdk_path=None: metadata,
    )

    components = process_exe_file(
        {},
        False,
        "/tmp/mystery/libdemo",
        sbom,
        [],
        {},
        True,
        True,
    )

    matched = next(comp for comp in components if comp.purl == "pkg:generic/demo@1.0.0")
    prop_map = {prop.name: prop.value for prop in matched.properties}
    assert prop_map["internal:blintdb_matched_fuzzy_hash_count"] == str(FUZZY_ONLY_MATCH_THRESHOLD)
    assert prop_map["internal:blintdb_fuzzy_layer"] == HASH_LAYER_ACTIVE
    # Layer evidence follows the existing contract: present with its value.
    # Exact and assembly hashes found nothing here and read as zero, while the
    # fuzzy layer names itself active.
    assert prop_map["internal:blintdb_matched_instruction_hash_count"] == "0"
    assert prop_map["internal:blintdb_matched_assembly_hash_count"] == "0"
    assert prop_map["internal:blintdb_matched_import_hash_count"] == "1"


def test_fuzzy_hit_does_not_waive_the_symbol_only_filter(tmp_path):
    """One project's fuzzy match must not admit another project's weak symbols.

    Symbol-only candidates are held to SYMBOL_ONLY_MATCH_THRESHOLD distinct
    symbols unless some hash or callgraph evidence exists. That gate is global,
    so a fuzzy hit anywhere in the lookup would waive it for every candidate —
    attributing a component on evidence the fuzzy gates themselves reject.
    """
    db_file = tmp_path / "blint.db"
    _create_v3_blintdb(db_file)
    connection = sqlite3.connect(db_file)
    # Give the unrelated project enough symbols to clear the score gate in
    # _finalize_project_matches while staying under the symbol-count gate.
    connection.executemany(
        "INSERT INTO Symbols(binary_id, name, source) VALUES(?, ?, ?)",
        [(2, "memcpy", "imports"), (2, "malloc", "imports"), (2, "free", "imports")],
    )
    connection.commit()
    connection.close()

    metadata = _fuzzy_metadata(import_hash=None, name="/tmp/unknown/mystery-binary")
    matches = lookup_project_matches(
        {"imports": ["puts", "memcpy", "malloc", "free"]},
        function_hash_index=build_function_hash_index(metadata),
        binary_metadata=metadata,
        db_file=str(db_file),
    )

    purls = {match["project_purl"] for match in matches}
    # demo earns its place through the fuzzy gates; other has four generic
    # libc imports and a single colliding fuzzy shape.
    assert "pkg:generic/demo@1.0.0" in purls
    assert "pkg:generic/other@2.0.0" not in purls


def test_supported_version_stamp_with_a_foreign_layout_is_refused_not_raised(tmp_path):
    """Accepting more than one schema version means meeting unknown layouts.

    The lookup queries do not swallow SQLite errors, so a database that stamps
    a supported version without carrying the expected tables must be skipped
    the way an unsupported one is — never raised out of an SBOM run.
    """
    db_file = tmp_path / "blint.db"
    connection = sqlite3.connect(db_file)
    connection.executescript(
        """
        CREATE TABLE SchemaMeta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE Components (component_id INTEGER PRIMARY KEY, purl TEXT);
        """
    )
    connection.executemany(
        "INSERT INTO SchemaMeta(key, value) VALUES(?, ?)",
        (("schema_family", "blint-db"), ("schema_version", "3")),
    )
    connection.commit()
    connection.close()

    assert is_supported_blintdb(str(db_file)) is True
    assert lookup_project_matches({"imports": ["puts"]}, db_file=str(db_file)) == []


# --- F2a.2: banner attribution merges into the qualified blintdb component ----


def _create_blintdb_with_purl(db_file, project_purl, binary_name="libz.1.dylib"):
    """A v2-shaped database with one project whose purl carries qualifiers."""
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
            binary_id INTEGER NOT NULL, function_key TEXT NOT NULL,
            instruction_hash TEXT, assembly_hash TEXT,
            FOREIGN KEY (binary_id) REFERENCES Binaries(binary_id));
        """
    )
    connection.executemany(
        "INSERT INTO SchemaMeta(key, value) VALUES(?, ?)",
        (("schema_family", "blint-db"), ("schema_version", "2")),
    )
    connection.execute("INSERT INTO Projects(project_id, name, purl) VALUES(1, 'zlib', ?)", (project_purl,))
    connection.execute("INSERT INTO Builds(build_id, project_id) VALUES(1, 1)")
    connection.execute(
        "INSERT INTO Binaries(binary_id, build_id, name, binary_type) VALUES(1, 1, ?, 'MachO')",
        (binary_name,),
    )
    # Six symbols: symbol-only matches surface at >= 5 distinct symbols
    # (SYMBOL_ONLY_MATCH_THRESHOLD with MIN_MATCH_SCORE at its default 10).
    connection.executemany(
        "INSERT INTO Symbols(symbol_id, binary_id, name, source) VALUES(?, 1, ?, 'symtab_symbols')",
        (
            (1, "deflate"),
            (2, "inflate"),
            (3, "zlibVersion"),
            (4, "compress2"),
            (5, "uncompress"),
            (6, "crc32"),
        ),
    )
    connection.commit()
    connection.close()


def _banner_metadata(version="1.3.2"):
    return {
        "name": "libz.1.dylib",
        "binary_type": "MachO",
        "strings": [
            {"value": f"deflate {version} Copyright (Jean-loup Gailly)"},
            {"value": "inflate 1.3.2 Copyright (Mark Adler)"},
        ],
        "symtab_symbols": [
            {"name": "deflate"},
            {"name": "inflate"},
            {"name": "zlibVersion"},
            {"name": "compress2"},
            {"name": "uncompress"},
            {"name": "crc32"},
        ],
    }


def _run_process_exe_with_db(tmp_path, monkeypatch, project_purl, metadata, binary_name="libz.1.dylib"):
    db_file = tmp_path / "blint.db"
    _create_blintdb_with_purl(db_file, project_purl, binary_name=binary_name)
    sbom = SimpleNamespace(metadata=SimpleNamespace(component=SimpleNamespace(components=[])))
    monkeypatch.setattr("blint.db.BLINTDB_LOC", str(db_file))
    monkeypatch.setattr(
        "blint.lib.sbom.parse",
        lambda _exe, disassemble=False, sdk_path=None: metadata,
    )
    return process_exe_file(
        {},
        False,
        "/tmp/demo/libz.1.dylib",
        sbom,
        [],
        {},
        True,
        True,
    )


def test_banner_merges_into_qualified_blintdb_component(tmp_path, monkeypatch):
    """One component, both evidence sources (F2a.2's defect shape).

    The blintdb match carries ?source_hash in its purl; the banner's purl is
    unqualified. An exact-string compare left both components in the BOM,
    which broke exact-match validation on the small corpus.
    """
    components = _run_process_exe_with_db(
        tmp_path,
        monkeypatch,
        "pkg:generic/zlib@1.3.2?source_hash=d7a0654783a4da529d1bb793b7ad9c3318020af77667bcae35f95d0e42a792f3",
        _banner_metadata(),
    )
    zlib_components = [c for c in components if "zlib" in (c.purl or "")]
    assert len(zlib_components) == 1, [c.purl for c in zlib_components]
    merged = zlib_components[0]
    assert merged.purl.endswith("?source_hash=d7a0654783a4da529d1bb793b7ad9c3318020af77667bcae35f95d0e42a792f3")
    prop_names = {prop.name for prop in merged.properties}
    assert "internal:blintdb_matched_symbols" in prop_names
    assert "internal:vendored_banner" in prop_names
    assert "internal:vendored_attribution" in prop_names
    assert merged.purl != "pkg:generic/zlib@1.3.2"


def test_banner_merges_into_homebrew_versioned_formula_component(tmp_path, monkeypatch):
    """openssl@3@3.6.3 (formula name with its own versioned suffix) merges
    with the plain openssl 3.6.3 banner."""
    components = _run_process_exe_with_db(
        tmp_path,
        monkeypatch,
        "pkg:generic/openssl@3@3.6.3?package_manager=homebrew&tap=homebrew/core",
        {
            "name": "openssl",
            "binary_type": "MachO",
            "strings": [{"value": "OpenSSL 3.6.3 1 Jan 2026"}],
            "symtab_symbols": [
                {"name": "deflate"},
                {"name": "inflate"},
                {"name": "zlibVersion"},
                {"name": "compress2"},
                {"name": "uncompress"},
                {"name": "crc32"},
            ],
        },
        # the DB binary carries the artifact's name so the six symbols ride
        # the name-match door (F2b.1); the floor for nameless matches is 30.
        binary_name="openssl",
    )
    openssl_components = [c for c in components if "openssl" in (c.purl or "")]
    assert len(openssl_components) == 1, [c.purl for c in openssl_components]
    prop_names = {prop.name for prop in openssl_components[0].properties}
    assert "internal:vendored_banner" in prop_names
    assert "internal:blintdb_matched_symbols" in prop_names


def test_banner_of_a_different_version_stays_separate(tmp_path, monkeypatch):
    """A banner naming a different version than the match is real
    information (the binary carries two copies) and is not merged away."""
    components = _run_process_exe_with_db(
        tmp_path,
        monkeypatch,
        "pkg:generic/zlib@1.3.1?source_hash=abc",
        _banner_metadata(version="1.3.2"),
    )
    zlib_purls = sorted(c.purl for c in components if "zlib" in (c.purl or ""))
    assert zlib_purls == [
        "pkg:generic/zlib@1.3.1?source_hash=abc",
        "pkg:generic/zlib@1.3.2",
    ]


# --- F2b.2: vendored banners vs version-mention strings -------------------


def test_mention_only_banner_is_not_a_component(tmp_path, monkeypatch):
    """The assetutil shape at SBOM level.

    A dynamically linked artifact whose only zlib tie is a stale banner
    string emits no pkg:generic/zlib component; the mention is recorded on
    the parent so the string is visible without asserting code.
    """
    components = _run_process_exe_with_db(
        tmp_path,
        monkeypatch,
        "pkg:generic/otherlib@1.0.0",
        {
            "name": "assetutil",
            "binary_type": "MachO",
            "strings": [{"value": " deflate 1.2.5 Copyright 1995-2010 Jean-loup Gailly "}],
            "dynamic_entries": [{"tag": "NEEDED", "name": "/usr/lib/libz.1.dylib"}],
            "dynamic_symbols": [{"name": "_deflate", "is_imported": True}],
        },
    )
    assert [c.purl for c in components if "zlib" in (c.purl or "")] == []


def test_vendored_banner_component_carries_the_corroboration_count(tmp_path, monkeypatch):
    """The libcrypto.0.9.7 shape at SBOM level: banner + the library's own
    exported API in the artifact - the component stays and its evidence
    states how many API symbols corroborate it."""
    components = _run_process_exe_with_db(
        tmp_path,
        monkeypatch,
        "pkg:generic/otherlib@1.0.0",
        {
            "name": "libcrypto.0.9.7.dylib",
            "binary_type": "MachO",
            "strings": [{"value": "Big Number part of OpenSSL 0.9.7l 28 Sep 2006"}],
            "dynamic_symbols": [
                {"name": "_BN_new", "is_imported": False},
                {"name": "_EVP_Digest", "is_imported": False},
            ],
        },
    )
    openssl_components = [c for c in components if "openssl@" in (c.purl or "")]
    assert [c.purl for c in openssl_components] == ["pkg:generic/openssl@0.9.7l"]
    props = {p.name: p.value for p in openssl_components[0].properties}
    assert props["internal:vendored_banner_api_symbols"] == "2"
    assert props["internal:vendored_attribution"] == "vendored_banner"


# --- F2a.3: version conflicts between matched versions of one project ----


def _create_two_version_blintdb(db_file):
    """One project name ingested at two versions, like two Homebrew kegs."""
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
            binary_id INTEGER NOT NULL, function_key TEXT NOT NULL,
            instruction_hash TEXT, assembly_hash TEXT,
            FOREIGN KEY (binary_id) REFERENCES Binaries(binary_id));
        """
    )
    connection.executemany(
        "INSERT INTO SchemaMeta(key, value) VALUES(?, ?)",
        (("schema_family", "blint-db"), ("schema_version", "2")),
    )
    for project_id, version in ((1, "3.6.3"), (2, "3.6.4")):
        connection.execute(
            "INSERT INTO Projects(project_id, name, purl) VALUES(?, 'openssl@3', ?)",
            (project_id, f"pkg:generic/openssl@3@{version}?package_manager=homebrew&tap=homebrew/core"),
        )
        connection.execute(
            "INSERT INTO Builds(build_id, project_id) VALUES(?, ?)", (project_id, project_id)
        )
        connection.execute(
            "INSERT INTO Binaries(binary_id, build_id, name, binary_type) VALUES(?, ?, 'openssl', 'MachO')",
            (project_id, project_id),
        )
    # Both versions carry the same symbols so both matches surface.
    connection.executemany(
        "INSERT INTO Symbols(symbol_id, binary_id, name, source) VALUES(?, ?, ?, 'symtab_symbols')",
        [
            (1, 1, "EVP_DigestSignInit"),
            (2, 1, "SSL_new"),
            (3, 1, "SSL_CTX_new"),
            (4, 1, "X509_new"),
            (5, 1, "RSA_new"),
            (6, 2, "EVP_DigestSignInit"),
            (7, 2, "SSL_new"),
            (8, 2, "SSL_CTX_new"),
            (9, 2, "X509_new"),
            (10, 2, "RSA_new"),
        ],
    )
    connection.commit()
    connection.close()


def _openssl_metadata():
    return {
        "name": "openssl",
        "binary_type": "MachO",
        "strings": [{"value": "OpenSSL 3.6.3 1 Jan 2026"}],
        "symtab_symbols": [
            {"name": "EVP_DigestSignInit"},
            {"name": "SSL_new"},
            {"name": "SSL_CTX_new"},
            {"name": "X509_new"},
            {"name": "RSA_new"},
        ],
    }


def _run_openssl_sbom(tmp_path, monkeypatch, exe_path, metadata):
    db_file = tmp_path / "blint.db"
    _create_two_version_blintdb(db_file)
    sbom = SimpleNamespace(metadata=SimpleNamespace(component=SimpleNamespace(components=[])))
    monkeypatch.setattr("blint.db.BLINTDB_LOC", str(db_file))
    monkeypatch.setattr(
        "blint.lib.sbom.parse",
        lambda _exe, disassemble=False, sdk_path=None: metadata,
    )
    return process_exe_file(
        {},
        False,
        exe_path,
        sbom,
        [],
        {},
        True,
        True,
    )


def test_version_conflict_resolved_by_artifact_path(tmp_path, monkeypatch):
    """The artifact's own install path names the keg it came from; that
    evidence outranks score and drops the other version (F2a.3)."""
    components = _run_openssl_sbom(
        tmp_path,
        monkeypatch,
        "/opt/homebrew/Cellar/openssl@3/3.6.3/bin/openssl",
        _openssl_metadata(),
    )
    purls = [c.purl for c in components if "openssl" in (c.purl or "")]
    assert purls == ["pkg:generic/openssl@3@3.6.3?package_manager=homebrew&tap=homebrew/core"]
    props = {p.name: p.value for p in components[0].properties}
    assert "internal:blintdb_version_evidence" in props
    assert "path=3.6.3" in props["internal:blintdb_version_evidence"]


def test_version_conflict_without_artifact_evidence_records_ambiguity(tmp_path, monkeypatch):
    """No version-bearing evidence: neither version is emitted, and the
    ambiguity is a named property instead of a score-picked winner."""
    metadata = _openssl_metadata()
    metadata["strings"] = []  # no banner either side can lean on
    components = _run_openssl_sbom(
        tmp_path,
        monkeypatch,
        "/tmp/demo/openssl",
        metadata,
    )
    purls = [c.purl for c in components if "openssl" in (c.purl or "")]
    assert purls == ["pkg:generic/openssl@3?package_manager=homebrew&tap=homebrew/core"]
    props = {p.name: p.value for p in components[0].properties}
    assert "internal:blintdb_version_ambiguity" in props
    assert "3.6.3" in props["internal:blintdb_version_ambiguity"]
    assert "3.6.4" in props["internal:blintdb_version_ambiguity"]


def test_version_conflict_resolved_by_banner_naming_the_project(tmp_path, monkeypatch):
    """A version banner for the project under decision is artifact evidence:
    it separates the kegs, and the banner then corroborates the kept
    component instead of standing beside it (review of F2a.2/F2a.3)."""
    components = _run_openssl_sbom(
        tmp_path, monkeypatch, "/tmp/demo/openssl", _openssl_metadata()
    )
    purls = [c.purl for c in components if "openssl" in (c.purl or "")]
    assert purls == ["pkg:generic/openssl@3@3.6.3?package_manager=homebrew&tap=homebrew/core"]
    props = {p.name: p.value for p in components[0].properties}
    assert "banner=3.6.3" in props["internal:blintdb_version_evidence"]


def test_linked_dylib_versions_never_decide_a_version_conflict(tmp_path, monkeypatch):
    """A dependency's current_version describes the dependency, not the
    artifact, so it must not pick between candidate versions."""
    metadata = _openssl_metadata()
    metadata["strings"] = []
    metadata["libraries"] = [{"name": "/usr/lib/libfoo.dylib", "version": "3.6.4"}]
    components = _run_openssl_sbom(tmp_path, monkeypatch, "/tmp/demo/openssl", metadata)
    purls = [c.purl for c in components if "openssl" in (c.purl or "")]
    assert purls == ["pkg:generic/openssl@3?package_manager=homebrew&tap=homebrew/core"]


def test_deep_elf_abi_floor_is_a_parent_property_not_a_component(monkeypatch):
    """F2a.4 end to end: under --deep the GLIBC floor is recorded on the
    binary's own component and no pkg:generic/gnu/libc component appears."""
    metadata = {
        "name": "demo",
        "binary_type": "ELF",
        # fake.dll: a .dll-suffixed GNU version node must never become a
        # component of any type, NuGet or otherwise.
        "symbols_version": [{"name": "GLIBC_2.34"}, {"name": "fake.dll"}],
        "abi_analysis": {
            "requirements": [
                {
                    "provider": "GLIBC",
                    "min_version": "2.34",
                    "package_name": "libc",
                    "package_group": "gnu",
                    "symbol_count": 3,
                    "determining_symbols": ["__libc_start_main"],
                }
            ]
        },
    }
    sbom = SimpleNamespace(metadata=SimpleNamespace(component=SimpleNamespace(components=[])))
    monkeypatch.setattr(
        "blint.lib.sbom.parse",
        lambda _exe, disassemble=False, sdk_path=None: metadata,
    )
    components = process_exe_file({}, True, "/tmp/demo/demo", sbom, [], {}, False, False)
    everything = components + list(sbom.metadata.component.components)
    assert not [c for c in everything if "gnu/libc" in (c.purl or "")]
    assert not [c for c in everything if "fake" in (c.purl or "") or "nuget" in (c.purl or "")]
    props = {
        p.name: p.value for c in everything for p in (getattr(c, "properties", None) or [])
    }
    assert props["internal:abi_requirements"].startswith("GLIBC>=2.34 (3 symbols)")
    assert props["internal:symbols_version"] == "GLIBC_2.34, fake.dll"


# --- F2b.1: a fixture crossing every suppression ---------------------------


def _create_typed_blintdb(db_file, rows, fingerprints=None):
    """A v2-shaped database with explicit binary_type and project names.

    rows: (binary_name, binary_type, project_name, project_purl, symbols)
    fingerprints: optional (binary_id, function_key, instruction_hash) tuples
    """
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
            assembly_hash TEXT, FOREIGN KEY (binary_id) REFERENCES Binaries(binary_id));
        """
    )
    connection.executemany(
        "INSERT INTO SchemaMeta(key, value) VALUES(?, ?)",
        (("schema_family", "blint-db"), ("schema_version", "2")),
    )
    for index, (binary_name, binary_type, project_name, project_purl, symbols) in enumerate(
        rows, start=1
    ):
        connection.execute(
            "INSERT INTO Projects(project_id, name, purl) VALUES(?, ?, ?)",
            (index, project_name, project_purl),
        )
        connection.execute(
            "INSERT INTO Builds(build_id, project_id) VALUES(?, ?)", (index, index)
        )
        connection.execute(
            "INSERT INTO Binaries(binary_id, build_id, name, binary_type) VALUES(?, ?, ?, ?)",
            (index, index, binary_name, binary_type),
        )
        connection.executemany(
            "INSERT INTO Symbols(binary_id, name, source) VALUES(?, ?, 'symtab_symbols')",
            [(index, name) for name in symbols],
        )
    if fingerprints:
        connection.executemany(
            "INSERT INTO FunctionFingerprints(binary_id, function_key, instruction_hash)"
            " VALUES(?, ?, ?)",
            fingerprints,
        )
    connection.commit()
    connection.close()


def test_imported_symbols_never_enter_the_query_map():
    """Query-side import suppression: flag, library:: form, imports bucket.

    /bin/cat's five false projects on tier-0 all matched on
    libSystem.B.dylib::_close-shaped imports; an import names the provider,
    not the artifact.
    """
    source_map = build_symbol_source_map(
        {
            "symtab_symbols": [
                {"name": "/usr/lib/libSystem.B.dylib::_close", "is_imported": True},
                {"name": "/usr/lib/libSystem.B.dylib::__stack_chk_fail", "is_imported": True},
                {"name": "cat_read", "is_imported": False},
                {"name": "cat_write"},
            ],
            "imports": [
                {"name": "KERNEL32.dll::CreateFileW", "is_imported": True},
                {"name": "plain_import", "is_imported": True},
            ],
        }
    )
    assert source_map == {"symtab_symbols": ["cat_read", "cat_write"]}
    # and the lookup refuses the imports bucket even when handed one directly
    matches = lookup_project_matches(
        {"imports": ["CreateFileW"]},
        binary_metadata={"binary_type": "PE"},
        db_file="/nonexistent",
    )
    assert matches == []


def test_fallback_retry_never_crosses_binary_type(tmp_path):
    """The retry keeps the format predicate (F2b.1).

    A static ELF Rust binary matched the Mach-O ripgrep build on 984 shared
    Rust-std names through the previously unfiltered retry; identical
    symbols behind a different binary_type must not match. Rows that never
    recorded a binary_type stay eligible, so an untyped database keeps
    working.
    """
    db_file = tmp_path / "typed.db"
    _create_typed_blintdb(
        db_file,
        [
            (
                "rg",
                "MachO",
                "ripgrep",
                "pkg:generic/ripgrep@15.2.0",
                ["_ZN4core6result", "_ZN3std5alloc", "rg_main"],
            )
        ],
    )
    elf_query = {
        "binary_type": "ELF",
        "llvm_target_tuple": "aarch64-unknown-linux-musl",
        "name": "wasm-tools",
    }
    matches = lookup_project_matches(
        {"symtab_symbols": ["_ZN4core6result", "_ZN3std5alloc", "rg_main"]},
        binary_metadata=elf_query,
        db_file=str(db_file),
    )
    assert matches == []
    # A Mach-O query still finds it through the first pass (the artifact
    # carries the project's binary name, so the name door applies)...
    macho_query = dict(elf_query, binary_type="MachO", llvm_target_tuple="aarch64-apple-darwin", name="rg")
    matches = lookup_project_matches(
        {"symtab_symbols": ["_ZN4core6result", "_ZN3std5alloc", "rg_main"]},
        binary_metadata=macho_query,
        db_file=str(db_file),
    )
    assert [m["project_purl"] for m in matches] == ["pkg:generic/ripgrep@15.2.0"]
    # ...and an untyped row is reachable through the retry.
    untyped = tmp_path / "untyped.db"
    _create_typed_blintdb(
        untyped,
        [
            (
                "rg",
                None,
                "ripgrep",
                "pkg:generic/ripgrep@15.2.0",
                ["_ZN4core6result", "_ZN3std5alloc", "rg_main"],
            )
        ],
    )
    matches = lookup_project_matches(
        {"symtab_symbols": ["_ZN4core6result", "_ZN3std5alloc", "rg_main"]},
        binary_metadata=dict(elf_query, name="rg"),
        db_file=str(untyped),
    )
    assert [m["project_purl"] for m in matches] == ["pkg:generic/ripgrep@15.2.0"]


def test_low_information_spread_suppression(tmp_path):
    """A name two project names define cannot identify either (F2b.1).

    _main, __mh_execute_header and _OUTLINED_FUNCTION_N reached every
    project; the boundary fixture asserts exactly two defining project
    names suppress while one keeps.
    """
    db_file = tmp_path / "spread.db"
    shared = ["_main", "__mh_execute_header"]
    _create_typed_blintdb(
        db_file,
        [
            ("openssl", "MachO", "openssl@3", "pkg:generic/openssl@3@3.6.3", shared + ["ssl_only"]),
            ("rg", "MachO", "ripgrep", "pkg:generic/ripgrep@15.2.0", shared + ["rg_only"]),
        ],
    )
    csh = {"binary_type": "MachO", "llvm_target_tuple": "aarch64-apple-darwin", "name": "csh"}
    # The shared names are gone, so csh (which only ever matched those)
    # identifies nothing.
    matches = lookup_project_matches(
        {"symtab_symbols": shared}, binary_metadata=csh, db_file=str(db_file)
    )
    assert matches == []
    # ssl_only still identifies the openssl project for a nameless artifact
    # below the symbol floor it cannot - the suppression and the floor are
    # independent layers - but for the project's own binary the name door
    # applies.
    matches = lookup_project_matches(
        {"symtab_symbols": shared + ["ssl_only"]},
        binary_metadata=dict(csh, name="openssl"),
        db_file=str(db_file),
    )
    assert [m["project_purl"] for m in matches] == ["pkg:generic/openssl@3@3.6.3"]


def test_mechanically_emitted_names_never_match(tmp_path):
    """Toolchain-emitted names are not identity (F2b.1).

    frc.dylib matched ripgrep on 31 _OUTLINED_FUNCTION_<n> names - clang
    numbers outlined functions per binary and the numbers happened to
    overlap. The names are blocked by shape, project-chosen names are not.
    """
    from blint.db import MECHANICALLY_EMITTED_SYMBOL_RE

    db_file = tmp_path / "mechanical.db"
    outlined = [f"_OUTLINED_FUNCTION_{i}" for i in range(31)]
    _create_typed_blintdb(
        db_file,
        [
            ("rg", "MachO", "ripgrep", "pkg:generic/ripgrep@15.2.0", outlined + ["rg_main"]),
        ],
    )
    metadata = {"binary_type": "MachO", "llvm_target_tuple": "aarch64-apple-darwin", "name": "frc.dylib"}
    assert lookup_project_matches(
        {"symtab_symbols": outlined}, binary_metadata=metadata, db_file=str(db_file)
    ) == []
    # the project's own chosen name still identifies it
    matches = lookup_project_matches(
        {"symtab_symbols": outlined + ["rg_main"]},
        binary_metadata=dict(metadata, name="rg"),
        db_file=str(db_file),
    )
    assert [m["project_purl"] for m in matches] == ["pkg:generic/ripgrep@15.2.0"]
    for chosen in ("deflate", "rg_main", "png_create_read_struct"):
        assert not MECHANICALLY_EMITTED_SYMBOL_RE.match(chosen), chosen
    for mechanical in ("_OUTLINED_FUNCTION_0", "__mh_execute_header", "_main", "main", "_start", "init", "fini"):
        assert MECHANICALLY_EMITTED_SYMBOL_RE.match(mechanical), mechanical


def test_nameless_symbol_only_floor(tmp_path):
    """A nameless symbol-only match needs 30 identity symbols (F2b.1).

    The measured false shapes matched 6-9 coincidental local names; a real
    identity match carries 79-338. 29 stays out, 30 passes, and a
    name-matched candidate rides the name door at any count.
    """
    db_file = tmp_path / "floor.db"
    _create_typed_blintdb(
        db_file,
        [
            ("libz.1.dylib", "MachO", "zlib", "pkg:generic/zlib@1.3.2",
             [f"zsym_{i}" for i in range(40)]),
        ],
    )
    metadata = {"binary_type": "MachO", "llvm_target_tuple": "aarch64-apple-darwin", "name": "mystery"}
    nameless_29 = lookup_project_matches(
        {"symtab_symbols": [f"zsym_{i}" for i in range(29)]},
        binary_metadata=metadata,
        db_file=str(db_file),
    )
    assert nameless_29 == []
    nameless_30 = lookup_project_matches(
        {"symtab_symbols": [f"zsym_{i}" for i in range(30)]},
        binary_metadata=metadata,
        db_file=str(db_file),
    )
    assert [m["project_purl"] for m in nameless_30] == ["pkg:generic/zlib@1.3.2"]
    # the name door: three symbols and the artifact's name is enough
    named = lookup_project_matches(
        {"symtab_symbols": ["zsym_0", "zsym_1", "zsym_2"]},
        binary_metadata=dict(metadata, name="libz.1.dylib"),
        db_file=str(db_file),
    )
    assert [m["project_purl"] for m in named] == ["pkg:generic/zlib@1.3.2"]


class TestDeepModeQualification:
    """F2b.1 deep measurement: every false attribution found on tier-0 in
    --deep mode, and the door that keeps each true shape."""

    def _db(self, tmp_path, name="deep.db"):
        db_file = tmp_path / name
        _create_typed_blintdb(
            db_file,
            [
                ("bzip2", "MachO", "bzip2", "pkg:generic/bzip2@1.0.8", ["bz_decompress"]),
                ("fmt", "MachO", "fmt", "pkg:generic/fmt@12.0.0", ["fmt_vformat"]),
            ],
            fingerprints=[(1, "0x1000::thunk", "e" * 64)]
            + [(1, f"0x1001::fn{i}", "f" * 63 + str(i)) for i in range(9)],
        )
        return db_file

    def test_single_hash_without_name_or_symbols_never_attributes(self, tmp_path):
        # wasm-tools-aarch64-macos -> bzip2 on tier-0: one instruction hash
        # (plus one fuzzy hash), zero symbols, no name agreement. A shared
        # 4-instruction thunk is a compiler artifact, not a shared project.
        matches = lookup_project_matches(
            {"symtab_symbols": ["unrelated_own_symbol"]},
            function_hash_index={"instruction_hashes": ["e" * 64], "fuzzy_hashes": ["f" * 64]},
            binary_metadata={"binary_type": "MachO", "llvm_target_tuple": "arm64-apple-darwin", "name": "wasm-tools"},
            db_file=str(self._db(tmp_path)),
        )
        assert matches == []

    def test_hash_population_attributes_without_a_name(self, tmp_path):
        # A genuine whole-binary embed shares a population of exact hashes.
        population = ["f" * 63 + str(i) for i in range(8)]
        matches = lookup_project_matches(
            {"symtab_symbols": ["unrelated_own_symbol"]},
            function_hash_index={"instruction_hashes": population},
            binary_metadata={"binary_type": "MachO", "llvm_target_tuple": "arm64-apple-darwin", "name": "mystery"},
            db_file=str(self._db(tmp_path)),
        )
        assert [m["project_purl"] for m in matches] == ["pkg:generic/bzip2@1.0.8"]

    def test_hash_population_below_query_coverage_never_attributes(self, tmp_path):
        # libGPUCompilerImpl.dylib -> ripgrep on tier-0 deep: nine identical
        # instruction hashes, zero symbols, no name. Nine crossed the count
        # bar; what makes it false is that those nine are a fraction of a
        # percent of the query's own hashed functions - compiler-emitted
        # functions compile identically everywhere. A real whole-binary
        # embed is most of the query's code.
        query = ["f" * 63 + str(i) for i in range(9)] + [
            "a" * 63 + str(i) for i in range(100)
        ]
        matches = lookup_project_matches(
            {"symtab_symbols": ["unrelated_own_symbol"]},
            function_hash_index={"instruction_hashes": query},
            binary_metadata={"binary_type": "MachO", "llvm_target_tuple": "arm64-apple-darwin", "name": "libGPUCompilerImpl.dylib"},
            db_file=str(self._db(tmp_path)),
        )
        assert matches == []

    def test_name_with_zero_agreement_never_attributes(self, tmp_path):
        # /usr/bin/fmt (Apple's formatter) -> fmt on tier-0: name agreement
        # with libfmt.dylib and not one matched symbol, hash or callgraph.
        matches = lookup_project_matches(
            {"symtab_symbols": ["format_paragraph"]},
            binary_metadata={"binary_type": "MachO", "llvm_target_tuple": "arm64-apple-darwin", "name": "fmt"},
            db_file=str(self._db(tmp_path)),
        )
        assert matches == []

    def test_name_with_one_symbol_attributes(self, tmp_path):
        # the libfmt.12.1.0.dylib validator shape: the name plus one matched
        # own symbol identifies a thin client library.
        matches = lookup_project_matches(
            {"symtab_symbols": ["fmt_vformat"]},
            binary_metadata={"binary_type": "MachO", "llvm_target_tuple": "arm64-apple-darwin", "name": "fmt"},
            db_file=str(self._db(tmp_path)),
        )
        assert [m["project_purl"] for m in matches] == ["pkg:generic/fmt@12.0.0"]

    def test_weak_symbols_do_not_ride_another_projects_hash_hit(self, tmp_path):
        # libsystem_c.dylib -> c-ares on tier-0: 3 coincidental symbols, no
        # name; surfaced only because another file's hash evidence waived
        # the floor for every candidate. The per-candidate gate ends that.
        db_file = self._db(tmp_path)
        # query carries the hash population (hash evidence present in the
        # lookup) AND three symbols of fmt's, naming neither project's binary
        population = ["f" * 63 + str(i) for i in range(8)]
        matches = lookup_project_matches(
            {"symtab_symbols": ["fmt_vformat", "extra_a", "extra_b"]},
            function_hash_index={"instruction_hashes": population},
            binary_metadata={"binary_type": "MachO", "llvm_target_tuple": "arm64-apple-darwin", "name": "libsystem_c.dylib"},
            db_file=str(db_file),
        )
        # fmt has a name mismatch and 1 symbol; bzip2 has the hashes (8) and
        # no symbols: only the hash-population candidate qualifies.
        assert [m["project_purl"] for m in matches] == ["pkg:generic/bzip2@1.0.8"]


def test_spread_names_still_identify_a_name_matched_library(tmp_path):
    """Spread suppression must not scale into lost recall.

    In a large corpus, every project that statically embeds zlib defines
    deflate/inflate/crc32, so zlib's own identity names are its most widely
    spread ones. They cannot attribute a nameless artifact, but the library's
    own binary, whose name agrees, must still be identified from them.
    """
    db_file = tmp_path / "embedders.db"
    zlib_names = ["deflate", "inflate", "crc32", "adler32"]
    _create_typed_blintdb(
        db_file,
        [
            ("libz.1.dylib", "MachO", "zlib", "pkg:generic/zlib@1.3.2", zlib_names),
            ("libpng16.dylib", "MachO", "libpng", "pkg:generic/libpng@1.6.58", zlib_names + ["png_read"]),
            ("libcurl.dylib", "MachO", "curl", "pkg:generic/curl@8.16.0", zlib_names + ["curl_easy_init"]),
        ],
    )
    libz = {"binary_type": "MachO", "llvm_target_tuple": "aarch64-apple-darwin", "name": "libz.1.dylib"}
    matches = lookup_project_matches(
        {"symtab_symbols": zlib_names}, binary_metadata=libz, db_file=str(db_file)
    )
    assert [m["project_purl"] for m in matches] == ["pkg:generic/zlib@1.3.2"]
    # The same names on an unrelated artifact attribute nothing: they cannot
    # say which of the three projects the code came from.
    other = dict(libz, name="someapp")
    assert lookup_project_matches(
        {"symtab_symbols": zlib_names}, binary_metadata=other, db_file=str(db_file)
    ) == []


def test_toolchain_names_never_corroborate_a_name_match(tmp_path):
    """/usr/bin/fmt shares a name with the fmt project and nothing else:
    _main alone must not turn the name agreement into an attribution."""
    db_file = tmp_path / "fmt.db"
    _create_typed_blintdb(
        db_file,
        [("fmt", "MachO", "fmt", "pkg:generic/fmt@12.1.0", ["_main", "_ZN3fmt2v126detail9vformatE"])],
    )
    usr_bin_fmt = {"binary_type": "MachO", "llvm_target_tuple": "aarch64-apple-darwin", "name": "fmt"}
    assert lookup_project_matches(
        {"symtab_symbols": ["_main", "_usage"]}, binary_metadata=usr_bin_fmt, db_file=str(db_file)
    ) == []
