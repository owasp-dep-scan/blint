# -*- coding: utf-8 -*-
"""
In-memory callgraph model shared by the source and binary loaders.

Two very different inputs are normalized into one :class:`CallGraph` shape:

* a *source* callgraph produced by a Rust source analyzer (rusi), whose nodes
  are demangled qualified names, and
* a *binary* callgraph produced by blint disassembly, whose nodes are functions
  located at concrete addresses.

Source nodes are keyed by their :class:`~blint.lib.callgraph.canon.CanonicalName`
so that every declaration and call site referring to the same function collapses
to a single node. Binary nodes keep their per-address identity, because a single
source definition is commonly emitted as several monomorphized binary functions
and because a stripped binary has no names to collapse on at all.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Optional, Union

from blint.lib.callgraph.canon import CanonicalName, NameKind, canonicalize

# Per-function disassembly features that survive stripping. They are the
# structural fingerprint used when no symbol names are available.
_BINARY_FEATURE_KEYS = (
    "instruction_count",
    "has_loop",
    "has_system_call",
    "has_crypto_call",
    "has_indirect_call",
    "has_security_feature",
)


@dataclass
class GraphNode:
    """A single function in a :class:`CallGraph`.

    Attributes:
        id: A graph-unique identifier. Canonical name for source nodes, the
            binary node index (as a string) for binary nodes.
        canon: The :class:`CanonicalName` for the function. May be empty for a
            stripped binary function that has no recoverable name.
        address: The function address for binary nodes, ``None`` for source.
        local: ``True`` when the function belongs to the analyzed workspace
            rather than an external dependency or the runtime.
        features: Disassembly-derived numeric/boolean features keyed by name.
    """

    id: str
    canon: CanonicalName
    address: Optional[str] = None
    local: bool = True
    features: dict[str, Any] = field(default_factory=dict)


class CallGraph:
    """A directed callgraph with canonical-name indexing.

    The graph stores nodes by id and maintains forward and reverse adjacency
    sets plus an index from canonical name to the node ids carrying it.
    """

    def __init__(self, side: str) -> None:
        #: Either ``"source"`` or ``"binary"``.
        self.side = side
        self.nodes: dict[str, GraphNode] = {}
        self._out: dict[str, set[str]] = defaultdict(set)
        self._in: dict[str, set[str]] = defaultdict(set)
        self._by_canon: dict[str, set[str]] = defaultdict(set)

    def add_node(self, node: GraphNode) -> GraphNode:
        """Insert ``node`` if absent and return the stored node for its id."""
        existing = self.nodes.get(node.id)
        if existing is not None:
            return existing
        self.nodes[node.id] = node
        if node.canon.value:
            self._by_canon[node.canon.value].add(node.id)
        return node

    def add_edge(self, src_id: str, dst_id: str) -> None:
        """Add a directed call edge from ``src_id`` to ``dst_id``.

        Self-loops are ignored. Endpoints are expected to already exist as
        nodes; missing endpoints are skipped so adjacency never references an
        unknown id.
        """
        if src_id == dst_id:
            return
        if src_id not in self.nodes or dst_id not in self.nodes:
            return
        self._out[src_id].add(dst_id)
        self._in[dst_id].add(src_id)

    def successors(self, node_id: str) -> set[str]:
        """Return the set of node ids called by ``node_id``."""
        return self._out.get(node_id, set())

    def predecessors(self, node_id: str) -> set[str]:
        """Return the set of node ids that call ``node_id``."""
        return self._in.get(node_id, set())

    def out_degree(self, node_id: str) -> int:
        return len(self._out.get(node_id, ()))

    def in_degree(self, node_id: str) -> int:
        return len(self._in.get(node_id, ()))

    def ids_for_canon(self, canon_value: str) -> set[str]:
        """Return the node ids whose canonical name equals ``canon_value``."""
        return self._by_canon.get(canon_value, set())

    @property
    def canon_index(self) -> dict[str, set[str]]:
        """Mapping from canonical name to the node ids that carry it."""
        return self._by_canon

    def __len__(self) -> int:
        return len(self.nodes)


def _as_payload(source: Union[str, Path, dict[str, Any]]) -> dict[str, Any]:
    """Accept a path or an already-parsed mapping and return the mapping."""
    if isinstance(source, dict):
        return source
    return json.loads(Path(source).read_text(encoding="utf-8"))


def load_source_callgraph(source: Union[str, Path, dict[str, Any]]) -> CallGraph:
    """Load a rusi source callgraph into a canonical-name-keyed :class:`CallGraph`.

    Args:
        source: Path to ``callgraph.json`` or its parsed contents.

    Returns:
        A :class:`CallGraph` whose node ids are canonical names. Nodes and call
        sites referring to the same function are merged. Edges are added between
        the canonical names of their resolved endpoints.
    """
    payload = _as_payload(source)
    call_graph = payload.get("call_graph") or {}
    graph = CallGraph("source")

    # rusi edges reference endpoints by id, drawing on two id spaces:
    # ``cg-node-*`` ids in the node list and ``decl-*`` ids in the declarations
    # list. Build one id -> (qualified_name, local) resolver across both. When the
    # analyzer already emits a normalized ``canonical_name`` we prefer it as the
    # authoritative join key instead of re-deriving it here.
    id_to_name: dict[str, str] = {}
    id_to_canon: dict[str, str] = {}
    id_local: dict[str, bool] = {}

    for decl in payload.get("declarations") or []:
        qname = decl.get("qualified_name")
        if decl.get("id") and qname:
            id_to_name[decl["id"]] = qname
            if decl.get("canonical_name"):
                id_to_canon[decl["id"]] = decl["canonical_name"]
            id_local[decl["id"]] = True

    for raw in call_graph.get("nodes") or []:
        qname = raw.get("qualified_name")
        if not (raw.get("id") and qname):
            continue
        id_to_name[raw["id"]] = qname
        if raw.get("canonical_name"):
            id_to_canon[raw["id"]] = raw["canonical_name"]
        id_local[raw["id"]] = bool(raw.get("local"))

    def _ensure(node_id: str) -> Optional[str]:
        """Resolve a rusi id to a canonical node, creating it on first use."""
        qname = id_to_name.get(node_id)
        if not qname:
            return None
        canon = canonicalize(qname)
        # Prefer the analyzer-provided canonical name, keeping the locally
        # derived kind and generic flag for classification.
        provided = id_to_canon.get(node_id)
        if provided and provided != canon.value:
            canon = replace(canon, value=provided)
        if not canon.value:
            return None
        graph.add_node(
            GraphNode(
                id=canon.value,
                canon=canon,
                local=id_local.get(node_id, False),
            )
        )
        return canon.value

    for node_id in id_to_name:
        _ensure(node_id)

    for edge in call_graph.get("edges") or []:
        src = _ensure(edge.get("source_id", ""))
        dst = _ensure(edge.get("target_id", ""))
        if src and dst:
            graph.add_edge(src, dst)

    return graph


def load_binary_callgraph(metadata: Union[str, Path, dict[str, Any]]) -> CallGraph:
    """Load a blint binary callgraph into an address-keyed :class:`CallGraph`.

    Args:
        metadata: Path to a ``*-metadata.json`` file or its parsed contents.
            The metadata must contain a ``callgraph`` payload; disassembly
            features are read from ``disassembled_functions`` when present.

    Returns:
        A :class:`CallGraph` whose node ids are the binary callgraph node
        indices. Each node carries a canonical name (empty for stripped
        functions) and disassembly features used for structural matching.
    """
    payload = _as_payload(metadata)
    callgraph = payload.get("callgraph") or {}
    disassembled = payload.get("disassembled_functions") or {}
    graph = CallGraph("binary")

    for raw in callgraph.get("nodes") or []:
        if "id" not in raw:
            continue
        node_id = str(raw["id"])
        name = raw.get("name") or ""
        canon = canonicalize(name)
        features = _extract_features(disassembled.get(raw.get("key", "")))
        graph.add_node(
            GraphNode(
                id=node_id,
                canon=canon,
                address=raw.get("address"),
                local=True,
                features=features,
            )
        )

    for edge in callgraph.get("edges") or []:
        src = edge.get("src")
        dst = edge.get("dst")
        if src is None or dst is None:
            continue
        graph.add_edge(str(src), str(dst))

    return graph


def _extract_features(disassembly: Optional[dict[str, Any]]) -> dict[str, Any]:
    """Pull the structural feature subset from a disassembled-function entry."""
    if not disassembly:
        return {}
    return {key: disassembly[key] for key in _BINARY_FEATURE_KEYS if key in disassembly}


def strip_names(metadata: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of binary metadata with all function names removed.

    This simulates a stripped binary while preserving the callgraph topology and
    per-function disassembly features. It is used to validate that the matcher
    can recover the source mapping without relying on symbol names.

    Node ``key`` fields are rewritten to their address component so disassembly
    features remain joinable, and node/disassembly ``name`` fields are blanked.
    """
    clone = json.loads(json.dumps(metadata))
    callgraph = clone.get("callgraph") or {}

    for node in callgraph.get("nodes") or []:
        node["name"] = ""
        node.pop("aliases", None)
        if node.get("key") and "::" in node["key"]:
            node["key"] = node["key"].split("::", 1)[0]

    rekeyed: dict[str, Any] = {}
    for key, entry in (clone.get("disassembled_functions") or {}).items():
        if isinstance(entry, dict):
            entry["name"] = ""
        new_key = key.split("::", 1)[0] if "::" in key else key
        rekeyed[new_key] = entry
    if "disassembled_functions" in clone:
        clone["disassembled_functions"] = rekeyed

    for bucket in ("symtab_symbols", "dynamic_symbols"):
        for symbol in clone.get(bucket) or []:
            if isinstance(symbol, dict):
                symbol["name"] = ""

    return clone
