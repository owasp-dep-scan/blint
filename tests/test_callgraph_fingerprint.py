# -*- coding: utf-8 -*-
"""Tests for Layer 2 structural fingerprint matching."""

from blint.lib.callgraph.canon import CanonicalName, NameKind
from blint.lib.callgraph.fingerprint import (
    gather_khop_voters,
    is_fingerprintable,
)
from blint.lib.callgraph.match import Match, MatchOptions, MatchResult, match_callgraphs
from blint.lib.callgraph.model import (
    CallGraph,
    GraphNode,
    load_binary_callgraph,
    load_source_callgraph,
)


def _bin_node(node_id, canon_value="", instruction_count=10):
    return GraphNode(
        id=str(node_id),
        canon=CanonicalName(canon_value, NameKind.FUNCTION, canon_value, False),
        address=f"0x{int(node_id):x}",
        features={"instruction_count": instruction_count},
    )


def test_is_fingerprintable_rejects_tiny_stubs():
    assert is_fingerprintable({"instruction_count": 10}) is True
    assert is_fingerprintable({"instruction_count": 1}) is False
    # Missing or malformed counts are allowed through.
    assert is_fingerprintable({}) is True
    assert is_fingerprintable({"instruction_count": "n/a"}) is True


def test_gather_khop_voters_weights_by_distance_and_direction():
    binary = CallGraph("binary")
    for i in range(4):
        binary.add_node(_bin_node(i))
    # Chain: 0 -> 1 -> 2 -> 3, query node is 2.
    binary.add_edge("0", "1")
    binary.add_edge("1", "2")
    binary.add_edge("2", "3")

    result = MatchResult()
    # Node 0 (two hops upstream) and node 3 (one hop downstream) are matched.
    result.add(Match("0", "app::root", "high", "anchor", "symbol"))
    result.add(Match("3", "app::sink", "high", "anchor", "symbol"))

    voters = {
        (v.source_canon, v.direction): v.weight
        for v in gather_khop_voters(binary, result, "2", k=2)
    }
    # Upstream root is two hops away -> weight 1/2 in the predecessor direction.
    assert voters[("app::root", "pred")] == 0.5
    # Downstream sink is one hop away -> weight 1 in the successor direction.
    assert voters[("app::sink", "succ")] == 1.0


def test_gather_khop_voters_respects_hop_limit():
    binary = CallGraph("binary")
    for i in range(3):
        binary.add_node(_bin_node(i))
    binary.add_edge("0", "1")
    binary.add_edge("1", "2")
    result = MatchResult()
    result.add(Match("0", "app::root", "high", "anchor", "symbol"))

    # With k=1 the matched node two hops away is not reached.
    assert gather_khop_voters(binary, result, "2", k=1) == []
    # With k=2 it is reached.
    assert any(v.source_canon == "app::root" for v in gather_khop_voters(binary, result, "2", k=2))


# Inlining scenario. In the source, ``app::a`` calls ``app::real`` directly and
# ``app::real`` calls ``app::c``. In the binary an extra thunk ``app::t`` sits
# between ``a`` and ``real`` (as if a wrapper was emitted), so when ``real`` is
# stripped its only anchored predecessor is two hops away. One-hop propagation
# cannot see it; k-hop fingerprinting can.
_INLINE_SOURCE_FUNCS = ["app::a", "app::real", "app::c"]
_INLINE_SOURCE_EDGES = [("app::a", "app::real"), ("app::real", "app::c")]
# Binary order includes the thunk ``app::t`` that has no source counterpart.
_INLINE_BINARY_FUNCS = ["app::a", "app::t", "app::real", "app::c"]
_INLINE_BINARY_EDGES = [
    ("app::a", "app::t"),
    ("app::t", "app::real"),
    ("app::real", "app::c"),
]


def _inline_source():
    return {
        "call_graph": {
            "nodes": [
                {"id": f"cg-{n}", "qualified_name": n, "local": True} for n in _INLINE_SOURCE_FUNCS
            ],
            "edges": [
                {"source_id": f"cg-{s}", "target_id": f"cg-{d}"} for s, d in _INLINE_SOURCE_EDGES
            ],
        }
    }


def _inline_binary(hide="app::real"):
    index = {n: i for i, n in enumerate(_INLINE_BINARY_FUNCS)}
    nodes = [
        {
            "id": i,
            "key": f"0x{i:x}::{name}",
            "name": "" if name == hide else name,
            "address": f"0x{i:x}",
        }
        for name, i in index.items()
    ]
    return {
        "callgraph": {
            "nodes": nodes,
            "edges": [
                {"src": index[s], "dst": index[d], "kind": "direct"}
                for s, d in _INLINE_BINARY_EDGES
            ],
        },
        "disassembled_functions": {
            f"0x{i:x}::{name}": {"instruction_count": 20} for name, i in index.items()
        },
    }


def test_fingerprint_recovers_node_behind_an_inlined_thunk():
    source = load_source_callgraph(_inline_source())
    binary = load_binary_callgraph(_inline_binary(hide="app::real"))
    hidden_id = next(n.id for n in binary.nodes.values() if not n.canon.value)

    # One-hop propagation alone leaves the node unmatched: its only anchored
    # predecessor is two hops away through the thunk.
    one_hop = match_callgraphs(source, binary, MatchOptions(enable_fingerprint=False))
    assert hidden_id not in one_hop

    # k-hop fingerprinting reaches the upstream anchor and recovers it.
    options = MatchOptions(enable_fingerprint=True, khop=2)
    result = match_callgraphs(source, binary, options)
    assert hidden_id in result
    match = result.matches[hidden_id]
    assert match.source_canon == "app::real"
    assert match.layer == "fingerprint"
    assert match.evidence == "structural"


def test_fingerprint_is_opt_in_and_off_by_default():
    source = load_source_callgraph(_inline_source())
    binary = load_binary_callgraph(_inline_binary(hide="app::real"))
    default_result = match_callgraphs(source, binary)
    assert all(m.layer != "fingerprint" for m in default_result.matches.values())
