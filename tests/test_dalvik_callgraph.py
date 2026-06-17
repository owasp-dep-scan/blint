from types import SimpleNamespace

from blint.lib.callgraph.model import load_binary_callgraph
from blint.lib.dalvik import DexPools
from blint.lib.dalvik_callgraph import (
    build_callgraph,
    callgraph_stats,
    export_callgraph,
    merge_callgraphs,
    to_dot,
    to_graphml,
)


def _method(index, bytecode):
    return SimpleNamespace(index=index, bytecode=bytecode, name=f"m{index}")


def _pools(methods):
    return DexPools(strings=[], types=[], fields=[], methods=methods)


def _graph_with_one_call():
    # method 0 (has body) invoke-static {v0}, method@1
    bytecode = bytes([0x71, 0x10, 0x01, 0x00, 0x00, 0x00])
    pools = _pools(["La/A;->caller()V", "Lb/B;->callee()V"])
    md = {"methods": [_method(0, bytecode)]}
    return build_callgraph(md, pools=pools)


def test_build_callgraph_nodes_and_edges():
    cg = _graph_with_one_call()
    ids = {n["id"]: n for n in cg["nodes"]}
    assert set(ids) == {"0", "1"}
    assert ids["0"]["local"] is True  # caller has a body
    assert ids["1"]["local"] is False  # callee is external (no body here)
    assert cg["edges"] == [{"src": "0", "dst": "1"}]


def test_callgraph_loads_into_binary_model():
    cg = _graph_with_one_call()
    graph = load_binary_callgraph({"callgraph": cg})
    assert len(graph) == 2
    assert graph.successors("0") == {"1"}


def test_callgraph_stats():
    assert callgraph_stats(_graph_with_one_call()) == {
        "nodes": 2,
        "edges": 1,
        "local_nodes": 1,
    }


def test_merge_namespaces_ids():
    g = _graph_with_one_call()
    merged = merge_callgraphs([g, g])
    ids = {n["id"] for n in merged["nodes"]}
    assert ids == {"0:0", "0:1", "1:0", "1:1"}
    assert {"src": "0:0", "dst": "0:1"} in merged["edges"]
    assert {"src": "1:0", "dst": "1:1"} in merged["edges"]


def test_dot_and_graphml_export():
    cg = _graph_with_one_call()
    dot = to_dot(cg)
    assert "digraph" in dot and '"0" -> "1"' in dot
    gml = to_graphml(cg)
    assert "<graphml" in gml and "Lb/B;-&gt;callee" in gml
    assert export_callgraph(cg, "dot").startswith("digraph")


def test_export_unknown_format_raises():
    try:
        export_callgraph(_graph_with_one_call(), "svg")
    except ValueError:
        return
    raise AssertionError("expected ValueError for unsupported format")


def test_empty_metadata():
    assert build_callgraph({"methods": []}) == {"nodes": [], "edges": []}
