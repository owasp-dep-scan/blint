from pathlib import Path

import orjson

from blint.lib.analysis import (
    _filter_callgraph_by_min_confidence,
    _build_mermaid_callgraph_text,
    _safe_mermaid_label,
    load_default_rules,
    run_checks,
)
from blint.lib.runners import ReviewRunner

load_default_rules()


def test_gobinary():
    test_go_file = Path(__file__).parent / "data" / "ngrok-elf.json"
    with open(test_go_file) as fp:
        file_content = fp.read()
    metadata = orjson.loads(file_content)
    results = run_checks(test_go_file.name, metadata)
    assert results
    assert results[0]["id"] == "CHECK_PIE"
    reviewer = ReviewRunner()
    reviewer.run_review(metadata)
    results = reviewer.process_review(test_go_file, test_go_file.name)
    assert results


def test_genericbinary():
    test_gnu_file = Path(__file__).parent / "data" / "netstat-elf.json"
    with open(test_gnu_file) as fp:
        file_content = fp.read()
    metadata = orjson.loads(file_content)
    results = run_checks(test_gnu_file.name, metadata)
    assert not results
    reviewer = ReviewRunner()
    reviewer.run_review(metadata)
    results = reviewer.process_review("data/netstat-elf.json", test_gnu_file.name)
    assert not results


def test_safe_mermaid_label_sanitizes_parser_unsafe_chars():
    raw_label = ' unsafe extern "C" fn(*mut u8)\n\t\\windows\\path|core::fmt `tick` '
    normalized = _safe_mermaid_label(raw_label)
    assert normalized == "unsafe extern 'C' fn(*mut u8) /windows/path/core::fmt 'tick'"
    assert '"' not in normalized
    assert "\\" not in normalized
    assert "|" not in normalized


def test_build_mermaid_callgraph_text_with_unsafe_labels():
    callgraph = {
        "nodes": [
            {
                "id": 0,
                "name": 'unsafe extern "C" fn(*mut u8)',
                "address": "0x10",
            }
        ],
        "edges": [],
        "external": [
            {
                "src": 0,
                "target": 'std::ffi::CString::new|"quoted"',
                "reason": "unresolved",
                "count": 1,
            }
        ],
    }
    mermaid_text = _build_mermaid_callgraph_text(callgraph)
    assert "graph TD" in mermaid_text
    assert "unsafe extern 'C' fn(*mut u8) (0x10)" in mermaid_text
    assert "std::ffi::CString::new/'quoted'" in mermaid_text
    assert '\\"' not in mermaid_text


def test_filter_callgraph_by_min_confidence_filters_edges_and_externals():
    callgraph = {
        "nodes": [{"id": 0, "name": "a", "address": "0x10"}],
        "edges": [
            {"src": 0, "dst": 0, "count": 1, "kind": "direct", "confidence": "high"},
            {
                "src": 0,
                "dst": 0,
                "count": 1,
                "kind": "tailcall",
                "confidence": "medium",
            },
        ],
        "external": [
            {
                "src": 0,
                "target": "x",
                "reason": "unresolved",
                "count": 1,
                "confidence": "low",
            }
        ],
        "edge_count": 2,
    }

    filtered = _filter_callgraph_by_min_confidence(callgraph, "high")

    assert filtered["edge_count"] == 1
    assert len(filtered["edges"]) == 1
    assert filtered["edges"][0]["confidence"] == "high"
    assert filtered["external"] == []
