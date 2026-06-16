# -*- coding: utf-8 -*-
"""Tests for the callgraph model loaders and the binary-to-source matcher."""

from blint.lib.callgraph.match import (
    MatchOptions,
    build_report,
    match_callgraphs,
)
from blint.lib.callgraph.model import (
    load_binary_callgraph,
    load_source_callgraph,
    strip_names,
)

# A small workspace callgraph:
#   main -> helper, main -> util, helper -> target, util -> target, target -> sink
# ``target`` is reachable only through helper and util and itself calls sink,
# which makes its structural position unambiguous once the others are anchored.
_FUNCS = ["app::main", "app::helper", "app::util", "app::target", "app::sink"]
_EDGES = [
    ("app::main", "app::helper"),
    ("app::main", "app::util"),
    ("app::helper", "app::target"),
    ("app::util", "app::target"),
    ("app::target", "app::sink"),
]


def _source_payload():
    return {
        "call_graph": {
            "nodes": [
                {"id": f"cg-{name}", "qualified_name": name, "local": True} for name in _FUNCS
            ],
            "edges": [{"source_id": f"cg-{src}", "target_id": f"cg-{dst}"} for src, dst in _EDGES],
        }
    }


def _binary_payload():
    index = {name: i for i, name in enumerate(_FUNCS)}
    return {
        "file_path": "/tmp/app",
        "callgraph": {
            "nodes": [
                {
                    "id": i,
                    "key": f"0x{i:x}::{name}",
                    "name": name,
                    "address": f"0x{i:x}",
                }
                for name, i in index.items()
            ],
            "edges": [
                {"src": index[src], "dst": index[dst], "kind": "direct"} for src, dst in _EDGES
            ],
        },
        "disassembled_functions": {
            f"0x{i:x}::{name}": {"instruction_count": 10 + i, "has_loop": False}
            for name, i in index.items()
        },
    }


def test_source_loader_collapses_on_canonical_name():
    graph = load_source_callgraph(_source_payload())
    assert len(graph) == len(_FUNCS)
    assert graph.successors("app::main") == {"app::helper", "app::util"}
    assert graph.predecessors("app::target") == {"app::helper", "app::util"}


def test_binary_loader_keeps_per_address_nodes_and_features():
    graph = load_binary_callgraph(_binary_payload())
    assert len(graph) == len(_FUNCS)
    main_id = next(n.id for n in graph.nodes.values() if n.canon.value == "app::main")
    assert graph.nodes[main_id].features["instruction_count"] == 10


def test_anchor_matching_maps_all_named_functions():
    source = load_source_callgraph(_source_payload())
    binary = load_binary_callgraph(_binary_payload())
    result = match_callgraphs(source, binary, MatchOptions(enable_propagation=False))
    assert len(result) == len(_FUNCS)
    assert all(m.layer == "anchor" and m.confidence == "high" for m in result.matches.values())


def test_propagation_recovers_a_stripped_function():
    binary_payload = _binary_payload()
    # Strip only the ``target`` function's name to force structural recovery.
    for node in binary_payload["callgraph"]["nodes"]:
        if node["name"] == "app::target":
            node["name"] = ""

    source = load_source_callgraph(_source_payload())
    binary = load_binary_callgraph(binary_payload)

    anchors_only = match_callgraphs(source, binary, MatchOptions(enable_propagation=False))
    assert len(anchors_only) == len(_FUNCS) - 1

    recovered = match_callgraphs(source, binary, MatchOptions(min_votes=2, margin=1))
    target_id = next(n.id for n in binary.nodes.values() if not n.canon.value)
    assert target_id in recovered
    match = recovered.matches[target_id]
    assert match.source_canon == "app::target"
    assert match.layer == "propagation"
    assert match.evidence == "structural"


def test_fully_stripped_binary_is_recovered_from_anchorless_graph():
    source = load_source_callgraph(_source_payload())
    stripped = strip_names(_binary_payload())
    binary = load_binary_callgraph(stripped)

    # No names survive, so there are zero anchors and nothing to propagate from.
    assert all(not node.canon.value for node in binary.nodes.values())
    result = match_callgraphs(source, binary)
    assert len(result) == 0


def test_strip_names_preserves_topology_and_features():
    original = _binary_payload()
    stripped = strip_names(original)
    assert original["callgraph"]["nodes"][0]["name"]  # original untouched
    assert all(node["name"] == "" for node in stripped["callgraph"]["nodes"])
    assert len(stripped["callgraph"]["edges"]) == len(original["callgraph"]["edges"])
    # Disassembly features remain joinable via the address-only key.
    feature_entry = next(iter(stripped["disassembled_functions"].values()))
    assert "instruction_count" in feature_entry


def test_build_report_summary_and_confidence_filter():
    source = load_source_callgraph(_source_payload())
    binary = load_binary_callgraph(_binary_payload())
    result = match_callgraphs(source, binary)
    report = build_report(source, binary, result, min_confidence="low", binary_file="/tmp/app")

    assert report["summary"]["binary_nodes"] == len(_FUNCS)
    assert report["summary"]["anchors"] == len(_FUNCS)
    assert report["summary"]["coverage"] == 1.0
    assert len(report["matches"]) == len(_FUNCS)

    high_only = build_report(source, binary, result, min_confidence="high")
    assert all(m["confidence"] == "high" for m in high_only["matches"])
    # Summary counters always reflect every match regardless of the filter.
    assert high_only["summary"]["binary_matched"] == len(_FUNCS)


def test_propagation_can_be_disabled():
    source = load_source_callgraph(_source_payload())
    binary = load_binary_callgraph(_binary_payload())
    options = MatchOptions(enable_propagation=False)
    result = match_callgraphs(source, binary, options)
    assert all(m.layer == "anchor" for m in result.matches.values())
