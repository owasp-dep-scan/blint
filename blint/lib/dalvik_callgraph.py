"""
Dalvik (DEX) callgraph construction and export.

Every ``invoke-*`` instruction names its callee by a method-pool index, and a
method's own pool index identifies the caller. Both live in the same index
space, so the disassembler's resolved operands yield a directed callgraph
directly: an edge ``caller.index -> invoke.index`` for each call site.

The emitted graph uses the same JSON shape as blint's native binary callgraph
(``{"nodes": [...], "edges": [...]}``) so it can be consumed by
:func:`blint.lib.callgraph.model.load_binary_callgraph` and the existing
fingerprint / match tooling. DOT and GraphML exporters are provided for
visualization and interchange.
"""

from typing import Iterable, List, Optional
from xml.sax.saxutils import escape, quoteattr

from blint.lib.dalvik import INDEX_POOL_BY_OPCODE, DexPools, disassemble_method
from blint.lib.dalvik_semantics import is_invoke
from blint.logger import LOG


def build_callgraph(metadata: dict, pools: Optional[DexPools] = None) -> dict:
    """
    Build a DEX callgraph from a ``parse_dex`` metadata dict.

    Args:
        metadata: A ``parse_dex`` metadata dict (lief methods + constant pools).
        pools: Optional pre-built constant pools (defaults to building from
            ``metadata``).

    Returns:
        A dict ``{"nodes": [...], "edges": [...]}``. Each node is
        ``{"id", "name", "key", "address", "local"}`` where ``id`` is the method
        pool index (as a string), ``name`` the resolved descriptor and ``local``
        is ``True`` when the method has a body in this dex. Edges are
        ``{"src", "dst"}`` index pairs.
    """
    methods = metadata.get("methods") or []
    if not methods:
        return {"nodes": [], "edges": []}
    if pools is None:
        pools = DexPools.from_metadata(metadata)

    nodes: dict[str, dict] = {}
    edges: set = set()
    defined: set = set()  # indices of methods that have a body in this dex

    def _ensure(idx: int) -> str:
        node_id = str(idx)
        if node_id not in nodes:
            name = pools.methods[idx] if 0 <= idx < len(pools.methods) else ""
            nodes[node_id] = {
                "id": node_id,
                "name": name,
                "key": name,
                "address": None,
                "local": False,
            }
        return node_id

    for method in methods:
        caller_idx = getattr(method, "index", None)
        bytecode = getattr(method, "bytecode", None)
        if caller_idx is None or not bytecode:
            continue
        defined.add(caller_idx)
        _ensure(caller_idx)
        try:
            instructions = disassemble_method(method, pools)
        except Exception as e:  # one bad method must not drop the whole graph
            LOG.debug(f"Failed to disassemble a dex method for callgraph: {e}")
            continue
        for inst in instructions:
            # Only method-pool invokes name a callee index. invoke-custom names a
            # call site (a different table), so it does not yield a method edge.
            if inst.index is None or not is_invoke(inst):
                continue
            if INDEX_POOL_BY_OPCODE.get(inst.opcode) != "method":
                continue
            callee_idx = inst.index
            _ensure(callee_idx)
            if callee_idx != caller_idx:
                edges.add((str(caller_idx), str(callee_idx)))

    for idx in defined:
        node = nodes.get(str(idx))
        if node:
            node["local"] = True

    return {
        "nodes": sorted(nodes.values(), key=lambda n: int(n["id"])),
        "edges": [{"src": s, "dst": d} for s, d in sorted(edges)],
    }


def merge_callgraphs(graphs: Iterable[dict]) -> dict:
    """
    Merge per-dex callgraphs into one.

    Method pool indices are local to each dex, so ids are namespaced by the
    graph's ordinal position (``"<dexn>:<index>"``) to keep them distinct.
    """
    nodes: dict[str, dict] = {}
    edges: set = set()
    for ordinal, graph in enumerate(graphs):
        for node in graph.get("nodes") or []:
            ns_id = f"{ordinal}:{node['id']}"
            merged = dict(node)
            merged["id"] = ns_id
            nodes[ns_id] = merged
        for edge in graph.get("edges") or []:
            edges.add((f"{ordinal}:{edge['src']}", f"{ordinal}:{edge['dst']}"))
    return {
        "nodes": list(nodes.values()),
        "edges": [{"src": s, "dst": d} for s, d in sorted(edges)],
    }


def callgraph_stats(callgraph: dict) -> dict:
    """Summary counts for a callgraph (nodes / edges / defined-local nodes)."""
    nodes = callgraph.get("nodes") or []
    return {
        "nodes": len(nodes),
        "edges": len(callgraph.get("edges") or []),
        "local_nodes": sum(1 for n in nodes if n.get("local")),
    }


def to_dot(callgraph: dict, name: str = "dex") -> str:
    """Render a callgraph as Graphviz DOT text."""
    lines = [f"digraph {quoteattr(name)} {{", "  rankdir=LR;"]
    for node in callgraph.get("nodes") or []:
        label = node.get("name") or node["id"]
        style = "" if node.get("local") else " style=dashed color=gray"
        lines.append(f"  {quoteattr(node['id'])} [label={quoteattr(label)}{style}];")
    for edge in callgraph.get("edges") or []:
        lines.append(f"  {quoteattr(edge['src'])} -> {quoteattr(edge['dst'])};")
    lines.append("}")
    return "\n".join(lines)


def to_graphml(callgraph: dict) -> str:
    """Render a callgraph as GraphML XML."""
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
        '  <key id="name" for="node" attr.name="name" attr.type="string"/>',
        '  <key id="local" for="node" attr.name="local" attr.type="boolean"/>',
        '  <graph edgedefault="directed">',
    ]
    for node in callgraph.get("nodes") or []:
        lines.append(f"    <node id={quoteattr(node['id'])}>")
        lines.append(f'      <data key="name">{escape(node.get("name") or "")}</data>')
        lines.append(f'      <data key="local">{"true" if node.get("local") else "false"}</data>')
        lines.append("    </node>")
    for idx, edge in enumerate(callgraph.get("edges") or []):
        lines.append(
            f'    <edge id="e{idx}" source={quoteattr(edge["src"])} '
            f"target={quoteattr(edge['dst'])}/>"
        )
    lines.append("  </graph>")
    lines.append("</graphml>")
    return "\n".join(lines)


def export_callgraph(callgraph: dict, fmt: str, name: str = "dex") -> str:
    """Export a callgraph to one of ``dot`` / ``graphml`` as text."""
    fmt = (fmt or "").lower()
    if fmt == "dot":
        return to_dot(callgraph, name)
    if fmt == "graphml":
        return to_graphml(callgraph)
    raise ValueError(f"Unsupported callgraph export format: {fmt}")


def build_app_callgraph(metadatas: List[dict]) -> dict:
    """Build a merged callgraph for an app from a list of per-dex metadata dicts."""
    return merge_callgraphs(build_callgraph(md) for md in metadatas)
