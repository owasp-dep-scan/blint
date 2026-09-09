import sqlite3
from types import SimpleNamespace

from blint.config import BlintOptions
from blint import db as db_module
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
            (1, "helper", "symtab_symbols"),
            (1, "puts", "imports"),
            (1, "strlen", "dynamic_symbols"),
            (2, "helper", "symtab_symbols"),
            (2, "puts", "imports"),
        ],
    )
    connection.executemany(
        "INSERT INTO FunctionFingerprints(binary_id, function_key, instruction_hash, assembly_hash) VALUES(?, ?, ?, ?)",
        [
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


# --- P4.2a: similarity hash columns (fuzzy_hash / cfg_hash / import_hash) ---
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
            (1, "helper", "symtab_symbols"),
            (1, "puts", "imports"),
            (2, "helper", "symtab_symbols"),
            (2, "puts", "imports"),
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

    matches = lookup_project_matches(
        {
            "symtab_symbols": ["helper"],
            "imports": ["puts"],
            "dynamic_symbols": ["strlen"],
        },
        function_hash_index={
            "instruction_hashes": ["b" * 64],
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
    assert matches[0]["matched_instruction_hash_count"] == 1
    assert matches[0]["matched_symbol_count"] == 3
    assert matches[0]["score"] >= 24.0


def test_detect_binaries_utilized_returns_rich_evidence(tmp_path):
    db_file = tmp_path / "blint.db"
    _create_v2_blintdb(db_file)

    binaries_detected, evidence = detect_binaries_utilized(
        symbol_source_map={"imports": ["puts"], "symtab_symbols": ["helper"]},
        function_hash_index={"instruction_hashes": ["b" * 64]},
        binary_metadata={
            "binary_type": "ELF",
            "llvm_target_tuple": "x86_64-pc-linux-gnu",
        },
        db_file=str(db_file),
    )

    assert binaries_detected == {"pkg:generic/demo@1.0.0"}
    assert evidence["pkg:generic/demo@1.0.0"]["matched_instruction_hash_count"] == 1
    assert evidence["pkg:generic/demo@1.0.0"]["matched_symbols"] == ["helper", "puts"]


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
    assert prop_map["internal:blintdb_matched_symbols"] == "helper, puts, strlen"


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
        assert len(rows) == 2
        assert {row["binary_id"] for row in rows} == {1, 2}
        assert all(row["cnt"] == 1 for row in rows)
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
    metadata = _fuzzy_metadata(
        import_hash=None, name="/tmp/unknown/mystery-binary"
    )
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
    assert (
        blintdb_fuzzy_layer_state(str(db_file), metadata)
        == HASH_LAYER_INACTIVE_NO_DISASSEMBLY
    )
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
    assert (
        blintdb_fuzzy_layer_state("/nonexistent/blint.db")
        == "unavailable_database_missing"
    )
    db_file = tmp_path / "future.db"
    connection = sqlite3.connect(db_file)
    connection.execute("CREATE TABLE SchemaMeta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    connection.executemany(
        "INSERT INTO SchemaMeta(key, value) VALUES(?, ?)",
        (("schema_family", "blint-db"), ("schema_version", "4")),
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
    assert prop_map["internal:blintdb_matched_fuzzy_hash_count"] == str(
        FUZZY_ONLY_MATCH_THRESHOLD
    )
    assert prop_map["internal:blintdb_fuzzy_layer"] == HASH_LAYER_ACTIVE
    # Layer evidence follows the existing contract: present with its value.
    # Exact and assembly hashes found nothing here and read as zero, while the
    # fuzzy layer names itself active.
    assert prop_map["internal:blintdb_matched_instruction_hash_count"] == "0"
    assert prop_map["internal:blintdb_matched_assembly_hash_count"] == "0"
    assert prop_map["internal:blintdb_matched_import_hash_count"] == "1"
