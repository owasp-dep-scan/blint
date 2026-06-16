# -*- coding: utf-8 -*-
"""Tests for the callgraph-match command orchestration and console rendering."""

import json

from blint.lib.callgraph.command import (
    _evidence_rows,
    _verdict,
    render_match_report,
    run_callgraph_match,
)

_SOURCE = {
    "call_graph": {
        "nodes": [
            {"id": f"cg-{n}", "qualified_name": n, "local": True}
            for n in ("app::main", "app::helper", "app::leaf")
        ],
        "edges": [
            {"source_id": "cg-app::main", "target_id": "cg-app::helper"},
            {"source_id": "cg-app::helper", "target_id": "cg-app::leaf"},
        ],
    }
}
_BINARY = {
    "file_path": "/tmp/app",
    "callgraph": {
        "nodes": [
            {"id": 0, "key": "0x10::app::main", "name": "app::main", "address": "0x10"},
            {"id": 1, "key": "0x20::app::helper", "name": "app::helper", "address": "0x20"},
            {"id": 2, "key": "0x30::app::leaf", "name": "app::leaf", "address": "0x30"},
        ],
        "edges": [
            {"src": 0, "dst": 1, "kind": "direct", "confidence": "high"},
            {"src": 1, "dst": 2, "kind": "direct", "confidence": "high"},
        ],
    },
    "disassembled_functions": {},
}


def _write(tmp_path, name, payload):
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def test_verdict_language_reflects_outcome():
    assert "consistent with the provided source" in _verdict(
        {"anchors": 5, "binary_matched": 5, "source_functions_identified": 5}
    )
    assert "No functions" in _verdict(
        {"anchors": 0, "binary_matched": 0, "source_functions_identified": 0}
    )
    assert "structure only" in _verdict(
        {"anchors": 0, "binary_matched": 3, "source_functions_identified": 3}
    )


def test_evidence_rows_diversify_across_layers():
    matches = [
        {"confidence": "high", "score": 0, "layer": "anchor", "source": "a"},
        {"confidence": "high", "score": 0, "layer": "anchor", "source": "b"},
        {"confidence": "medium", "score": 3, "layer": "propagation", "source": "c"},
        {"confidence": "low", "score": 2, "layer": "fingerprint", "source": "d"},
    ]
    rows = _evidence_rows(matches, limit=3)
    layers = {row["layer"] for row in rows}
    # All three matching methods are represented despite anchors being strongest.
    assert layers == {"anchor", "propagation", "fingerprint"}


def test_run_callgraph_match_writes_report_and_renders(tmp_path):
    source = _write(tmp_path, "source.json", _SOURCE)
    metadata = _write(tmp_path, "metadata.json", _BINARY)
    out = tmp_path / "report.json"

    report = run_callgraph_match(
        source_callgraph=source,
        binary=None,
        binary_metadata=metadata,
        output=str(out),
        quiet=False,
    )

    assert report["summary"]["anchors"] == 3
    assert report["algorithm"] == "layered"
    written = json.loads(out.read_text(encoding="utf-8"))
    assert written["summary"]["binary_matched"] == 3
    # Rendering the report must not raise.
    render_match_report(report)


def test_quiet_run_still_returns_report(tmp_path):
    source = _write(tmp_path, "source.json", _SOURCE)
    metadata = _write(tmp_path, "metadata.json", _BINARY)
    report = run_callgraph_match(
        source_callgraph=source,
        binary=None,
        binary_metadata=metadata,
        output=None,
        quiet=True,
    )
    assert report["summary"]["binary_nodes"] == 3
