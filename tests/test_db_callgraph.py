# -*- coding: utf-8 -*-
"""Tests for blintdb callgraph-corpus matching in blint.db."""

import sqlite3

from blint.db import (
    build_callgraph_canon_names,
    detect_binaries_utilized,
    lookup_project_matches,
)

# A binary whose callgraph functions canonicalize onto the source corpus below.
_METADATA = {
    "name": "/tmp/app",
    "binary_type": "ELF",
    "llvm_target_tuple": "x86_64-pc-linux-gnu",
    "callgraph": {
        "version": 2,
        "nodes": [
            {
                "id": i,
                "key": f"0x{i:x}::{name}",
                "name": name,
                "address": f"0x{i:x}",
            }
            for i, name in enumerate([f"app::module::func_{n}" for n in range(10)])
        ],
        "edges": [],
    },
    "disassembled_functions": {},
}

_SOURCE_FUNCS = [f"app::module::func_{n}" for n in range(10)]


def _create_blintdb_with_callgraph(db_file, *, with_callgraph_tables=True):
    connection = sqlite3.connect(db_file)
    connection.executescript(
        """
        CREATE TABLE SchemaMeta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE Projects (
            project_id INTEGER PRIMARY KEY, name TEXT NOT NULL, purl TEXT
        );
        CREATE TABLE Builds (
            build_id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL,
            llvm_target_tuple TEXT
        );
        CREATE TABLE Binaries (
            binary_id INTEGER PRIMARY KEY, build_id INTEGER NOT NULL, name TEXT,
            binary_type TEXT, llvm_target_tuple TEXT
        );
        CREATE TABLE Symbols (
            symbol_id INTEGER PRIMARY KEY, binary_id INTEGER NOT NULL,
            name TEXT NOT NULL, source TEXT NOT NULL
        );
        CREATE TABLE FunctionFingerprints (
            function_id INTEGER PRIMARY KEY, binary_id INTEGER NOT NULL,
            function_key TEXT NOT NULL, instruction_hash TEXT, assembly_hash TEXT
        );
        """
    )
    connection.executemany(
        "INSERT INTO SchemaMeta(key, value) VALUES(?, ?)",
        (("schema_family", "blint-db"), ("schema_version", "2")),
    )
    if with_callgraph_tables:
        connection.executescript(
            """
            CREATE TABLE SourceGraphs (
                source_graph_id INTEGER PRIMARY KEY, source_key TEXT UNIQUE,
                project_id INTEGER, name TEXT, purl TEXT, tool TEXT,
                node_count INTEGER
            );
            CREATE TABLE CallGraphNodes (
                node_id INTEGER PRIMARY KEY, graph_kind TEXT NOT NULL,
                owner_id INTEGER NOT NULL, node_ref TEXT NOT NULL,
                canon_name TEXT
            );
            CREATE INDEX idx_cgnodes_canon ON CallGraphNodes(canon_name, graph_kind);
            """
        )
        connection.execute(
            "INSERT INTO SourceGraphs(source_graph_id, source_key, name, purl, tool, node_count) "
            "VALUES(1, 'app@1.0.0', 'app', 'pkg:cargo/app@1.0.0', 'rusi', 5)"
        )
        connection.execute(
            "INSERT INTO SourceGraphs(source_graph_id, source_key, name, purl, tool, node_count) "
            "VALUES(2, 'other@2.0.0', 'other', 'pkg:cargo/other@2.0.0', 'rusi', 1)"
        )
        connection.executemany(
            "INSERT INTO CallGraphNodes(graph_kind, owner_id, node_ref, canon_name) "
            "VALUES('source', ?, ?, ?)",
            [(1, name, name) for name in _SOURCE_FUNCS] + [(2, "other::thing", "other::thing")],
        )
    connection.commit()
    connection.close()


def test_build_callgraph_canon_names_from_metadata():
    names = build_callgraph_canon_names(_METADATA)
    assert "app::module::func_0" in names
    assert "app::module::func_9" in names
    assert len(names) == 10
    # No callgraph means no names.
    assert build_callgraph_canon_names({"name": "x"}) == []


def test_callgraph_match_identifies_project(tmp_path):
    db_file = tmp_path / "blint.db"
    _create_blintdb_with_callgraph(str(db_file))

    canon_names = build_callgraph_canon_names(_METADATA)
    matches = lookup_project_matches(
        callgraph_canon_names=canon_names,
        binary_metadata=_METADATA,
        db_file=str(db_file),
    )
    assert matches
    top = matches[0]
    assert top["project_purl"] == "pkg:cargo/app@1.0.0"
    assert top["matched_callgraph_count"] == 10
    # The decoy source graph sharing nothing is excluded.
    assert all(m["project_purl"] != "pkg:cargo/other@2.0.0" for m in matches)


def test_callgraph_evidence_surfaced_in_detect(tmp_path):
    db_file = tmp_path / "blint.db"
    _create_blintdb_with_callgraph(str(db_file))

    detected, evidence = detect_binaries_utilized(
        callgraph_canon_names=build_callgraph_canon_names(_METADATA),
        binary_metadata=_METADATA,
        db_file=str(db_file),
    )
    assert "pkg:cargo/app@1.0.0" in detected
    app_evidence = evidence["pkg:cargo/app@1.0.0"]
    assert app_evidence["matched_callgraph_count"] == 10
    assert "app::module::func_0" in app_evidence["matched_callgraph_functions"]


def test_graceful_when_callgraph_tables_absent(tmp_path):
    # Older blintdb images without the corpus tables must not error.
    db_file = tmp_path / "blint.db"
    _create_blintdb_with_callgraph(str(db_file), with_callgraph_tables=False)

    matches = lookup_project_matches(
        callgraph_canon_names=build_callgraph_canon_names(_METADATA),
        binary_metadata=_METADATA,
        db_file=str(db_file),
    )
    assert matches == []
