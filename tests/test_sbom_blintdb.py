import sqlite3
from types import SimpleNamespace

from blint.config import BlintOptions
from blint.db import detect_binaries_utilized, lookup_project_matches
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
        lambda _exe, disassemble=False: metadata,
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
