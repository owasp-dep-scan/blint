"""Tests for the wasm-tools 2.2 report mapping in blint.lib.binary_wasm."""

import copy
import json
import logging
from pathlib import Path

import pytest

import blint.lib.binary_wasm as wasm_module
from blint.lib.binary_wasm import build_wasm_callgraph, parse_wasm_metadata

DATA_DIR = Path(__file__).parent / "data"
REPORT_DIR = DATA_DIR / "wasm-tools-2.2"


def load_report(name: str) -> dict:
    with open(REPORT_DIR / f"{name}.report.json", encoding="utf-8") as handle:
        return json.load(handle)


def as_21_report(report: dict) -> dict:
    """Derives the shape wasm-tools 2.1 produces from a real 2.2 report."""
    report = copy.deepcopy(report)
    for fn in report.get("functions") or []:
        fn.pop("body_offset", None)
        fn.pop("core_module", None)
    graph = report.get("call_graph") or {}
    graph["nodes"] = [
        {k: v for k, v in node.items() if k not in ("module_id", "synthetic")}
        for node in graph.get("nodes") or []
        if not node.get("synthetic")
    ]
    graph["edges"] = [
        {k: v for k, v in edge.items() if k not in ("from_module", "to_module")}
        for edge in graph.get("edges") or []
        if edge.get("kind") != "canon"
    ]
    return report


def metadata_for(monkeypatch, report: dict) -> dict:
    monkeypatch.setattr(wasm_module, "parse_wasm_file", lambda *_a, **_k: copy.deepcopy(report))
    return parse_wasm_metadata("sample.wasm", {})


@pytest.fixture(name="component")
def component_fixture():
    return load_report("wit_lift_lower")


def test_function_address_prefers_body_offset(monkeypatch):
    report = load_report("complex_flow")
    first = report["functions"][0]
    assert first["body_offset"] != first["offset"]
    metadata = metadata_for(monkeypatch, report)
    assert metadata["functions"][0]["address"] == f"0x{first['body_offset']:x}"
    callgraph = build_wasm_callgraph(report)
    by_name = {node["name"]: node for node in callgraph["nodes"]}
    exported = next(fn for fn in report["functions"] if fn["index"] == 1)
    assert by_name["complex_flow"]["address"] == f"0x{exported['body_offset']:x}"
    assert by_name["complex_flow"]["key"].startswith(by_name["complex_flow"]["address"])
    # The docstring promise: node and function addresses match by string.
    addresses = {fn["address"] for fn in metadata["functions"]}
    assert {node["address"] for node in callgraph["nodes"]} <= addresses


def test_function_address_falls_back_to_offset_for_21_reports(monkeypatch):
    report = as_21_report(load_report("complex_flow"))
    assert all("body_offset" not in fn for fn in report["functions"])
    metadata = metadata_for(monkeypatch, report)
    assert metadata["functions"][0]["address"] == f"0x{report['functions'][0]['offset']:x}"
    callgraph = build_wasm_callgraph(report)
    assert {node["address"] for node in callgraph["nodes"]} <= {
        fn["address"] for fn in metadata["functions"]
    }


@pytest.mark.parametrize("bad", [None, -1, "12", True])
def test_function_address_ignores_unusable_body_offset(bad):
    assert wasm_module._wasm_function_offset({"body_offset": bad, "offset": 40}) == 40
    assert wasm_module._wasm_function_offset({"body_offset": bad}) is None


def node_by_name(callgraph: dict, name: str) -> dict:
    return next(node for node in callgraph["nodes"] if node["name"] == name)


def test_component_nodes_are_keyed_by_module_and_index(component):
    callgraph = build_wasm_callgraph(component)
    # Module 0 defines indices 1-6; module 1 only imports index 0.
    assert callgraph["node_count"] == len(callgraph["nodes"]) == 6
    names = [node["name"] for node in callgraph["nodes"]]
    assert all(name.startswith("module[0]::") for name in names)
    assert "module[0]::cm32p2_initialize" in names
    first = callgraph["nodes"][0]
    body_offset = next(fn for fn in component["functions"] if fn["index"] == 1)["body_offset"]
    assert first["address"] == f"0x{body_offset:x}"
    assert first["key"] == f"{first['address']}::{first['name']}"


def test_same_index_in_two_modules_does_not_collide(component):
    """Before module-scoped keys, module 1's node 0 replaced module 0's node 0.

    Module 0 node 0 is the import ``cm32p2.x`` and module 1 node 0 is the import
    ``main::cm32p2_initialize``. The real report has no edge into either, so a
    direct edge to each is added in the shape wasm-tools 2.2 emits.
    """
    report = copy.deepcopy(component)
    report["call_graph"]["edges"] += [
        {"from": 1, "from_module": 0, "to": 0, "to_module": 0, "kind": "direct", "offset": 5},
        {"from": 2, "from_module": 0, "to": 0, "to_module": 1, "kind": "direct", "offset": 6},
    ]
    callgraph = build_wasm_callgraph(report)
    ids = {node["name"]: node["id"] for node in callgraph["nodes"]}
    targets = {
        (item["src"], item["target"]) for item in callgraph["external"]
    }
    assert (ids["module[0]::cm32p2||run"], "cm32p2::x") in targets
    assert (ids["module[0]::cm32p2||run_post"], "main::cm32p2_initialize") in targets


def test_defined_functions_in_two_modules_stay_apart(component):
    """Two modules defining the same index must yield two nodes and own edges."""
    report = copy.deepcopy(component)
    graph = report["call_graph"]
    graph["nodes"].append(
        {"index": 1, "name": "cm32p2||run", "imported": False, "exported": False, "module_id": 1}
    )
    graph["edges"].append(
        {"from": 1, "from_module": 1, "to": 0, "to_module": 1, "kind": "direct", "offset": 9}
    )
    callgraph = build_wasm_callgraph(report)
    names = [node["name"] for node in callgraph["nodes"]]
    assert "module[0]::cm32p2||run" in names and "module[1]::cm32p2||run" in names
    module_one = next(n for n in callgraph["nodes"] if n["name"] == "module[1]::cm32p2||run")
    assert module_one["address"] == ""
    assert {
        (item["src"], item["target"]) for item in callgraph["external"]
    } == {(module_one["id"], "main::cm32p2_initialize")}


def test_core_module_graph_is_unchanged_by_module_support():
    report = load_report("complex_flow")
    callgraph = build_wasm_callgraph(report)
    assert [node["name"] for node in callgraph["nodes"]] == ["func[0]", "complex_flow"]
    assert callgraph["edge_count"] == 2
    assert all("module[" not in node["name"] for node in callgraph["nodes"])


def test_21_shaped_component_report_keeps_integer_keys(component):
    report = as_21_report(component)
    callgraph = build_wasm_callgraph(report)
    assert callgraph["edges"] == []
    assert all("module[" not in node["name"] for node in callgraph["nodes"])
    # With one flattened index space, index 0 is the last import seen.
    assert callgraph["node_count"] == 6


def test_synthetic_nodes_are_never_external_targets(component):
    report = copy.deepcopy(component)
    # A defined function calling the synthetic node must not produce an
    # external edge either.
    report["call_graph"]["edges"].append(
        {"from": 1, "from_module": 0, "to": 10000001, "to_module": None, "kind": "direct"}
    )
    callgraph = build_wasm_callgraph(report)
    assert callgraph["external"] == []
    assert callgraph["edges"] == []
    assert not any("component:type" in node["name"] for node in callgraph["nodes"])


def test_canon_lift_target_is_marked_exported(component):
    report = copy.deepcopy(component)
    for node in report["call_graph"]["nodes"]:
        node["exported"] = False
    callgraph = build_wasm_callgraph(report)
    exported = {node["name"] for node in callgraph["nodes"] if node["exported"]}
    # The two canon edges lift module 0 functions 1 and 3 (run and run2).
    assert exported == {"module[0]::cm32p2||run", "module[0]::cm32p2||run2"}


def test_canon_edges_do_not_change_21_shaped_output(component):
    """Without synthetic nodes there is nothing to mark, so exported stays as reported."""
    report = as_21_report(component)
    for node in report["call_graph"]["nodes"]:
        node["exported"] = False
    callgraph = build_wasm_callgraph(report)
    assert not any(node["exported"] for node in callgraph["nodes"])
