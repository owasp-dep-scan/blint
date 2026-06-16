# -*- coding: utf-8 -*-
"""Tests for the pluggable callgraph matcher algorithm registry."""

import pytest

from blint.lib.callgraph.algorithms import (
    DEFAULT_ALGORITHM,
    CallgraphMatcher,
    algorithm_descriptions,
    available_algorithms,
    get_algorithm,
    register_algorithm,
)
from blint.lib.callgraph.match import MatchResult
from blint.lib.callgraph.model import load_binary_callgraph, load_source_callgraph

_SOURCE = {
    "call_graph": {
        "nodes": [
            {"id": f"cg-{n}", "qualified_name": n, "local": True}
            for n in ("app::main", "app::helper")
        ],
        "edges": [{"source_id": "cg-app::main", "target_id": "cg-app::helper"}],
    }
}
_BINARY = {
    "callgraph": {
        "nodes": [
            {"id": 0, "key": "0x10::app::main", "name": "app::main", "address": "0x10"},
            {
                "id": 1,
                "key": "0x20::app::helper",
                "name": "app::helper",
                "address": "0x20",
            },
        ],
        "edges": [{"src": 0, "dst": 1, "kind": "direct"}],
    },
    "disassembled_functions": {},
}


def test_default_and_available_algorithms():
    names = available_algorithms()
    assert "layered" in names and "anchors" in names
    assert DEFAULT_ALGORITHM == "layered"
    assert set(algorithm_descriptions()) == set(names)


def test_get_algorithm_defaults_and_rejects_unknown():
    assert get_algorithm(None).name == DEFAULT_ALGORITHM
    assert get_algorithm("anchors").name == "anchors"
    with pytest.raises(ValueError):
        get_algorithm("does-not-exist")


def test_anchors_and_layered_produce_matches():
    source = load_source_callgraph(_SOURCE)
    binary = load_binary_callgraph(_BINARY)
    anchors = get_algorithm("anchors").match(source, binary)
    layered = get_algorithm("layered").match(source, binary)
    assert len(anchors) == 2
    assert all(m.layer == "anchor" for m in anchors.matches.values())
    # Layered never produces fewer matches than anchors-only.
    assert len(layered) >= len(anchors)


def test_register_custom_algorithm():
    class NullMatcher(CallgraphMatcher):
        name = "null-test"
        description = "Matches nothing."

        def match(self, source, binary, options=None):
            return MatchResult()

    register_algorithm(NullMatcher())
    assert "null-test" in available_algorithms()
    assert len(get_algorithm("null-test").match(None, None)) == 0


def test_register_requires_name():
    class Nameless(CallgraphMatcher):
        pass

    with pytest.raises(ValueError):
        register_algorithm(Nameless())
