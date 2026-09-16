"""WebAssembly module parsing and callgraph construction.

Split out of ``binary.py``; imports only ``binary_common``, never the
orchestrator that imports it.
"""

# pylint: disable=too-many-lines,consider-using-f-string
from collections import Counter
from typing import Any

from wasm_tools.api import parse_wasm_file

from blint.config import (
    BLINT_MAX_WASM_INSTRUCTIONS,
)
from blint.lib.binary_common import (
    ADDRESS_FMT,
    _default_confidence_for_kind,
)
from blint.lib.utils import (
    demangle_symbolic_name,
)
from blint.logger import LOG


def is_wasm_file(exe_file: str) -> bool:
    """Detects wasm files using extension or magic bytes."""
    if str(exe_file).lower().endswith(".wasm"):
        return True
    try:
        with open(exe_file, "rb") as file_handle:
            return file_handle.read(4) == b"\x00asm"
    except OSError:
        return False


def trim_wasm_instruction_streams(report: dict) -> int:
    """
    Bounds the raw instruction streams in a wasm report to a total budget.

    wasm-tools caps strings (1000 entries) and call-graph edges (5000), but
    per-function instruction streams are unbounded and dominate report size
    for large modules (a 1 MB module produced a 33 MB report, 98% of it
    instruction streams). A single budget is shared across the whole report
    and divided max-min fair: every function is offered an equal share, and
    whatever the short ones do not need is redistributed to the long ones. A
    greedy first-come split would instead spend the whole budget on the first
    functions in section order and empty the rest, making what survives an
    artifact of layout rather than a sample of the module.

    Counts stay truthful: ``instruction_count`` keeps the original length and
    ``instructions_truncated`` records how many instructions were dropped. A
    ``blint_truncation`` block is added to the report when anything was
    dropped, so a reader of the artifact alone can tell a small module from a
    trimmed large one without the log line that reported it.

    Args:
        report (dict): The wasm_tools parser report, modified in place.

    Returns:
        int: The number of instructions dropped from the report.
    """
    budget = BLINT_MAX_WASM_INSTRUCTIONS
    if budget <= 0:
        return 0
    # Component reports alias the same function dicts from several places
    # (the aggregated top-level list and the per-core-module lists). Visiting
    # one twice would charge the budget twice and overwrite its truthful
    # instructions_truncated count, so each dict is collected exactly once.
    seen: set[int] = set()
    streams: list[dict] = []

    def collect(fn: Any) -> None:
        if not isinstance(fn, dict) or id(fn) in seen:
            return
        seen.add(id(fn))
        instructions = fn.get("instructions")
        if isinstance(instructions, list) and instructions:
            streams.append(fn)

    def walk(node: Any) -> None:
        if not isinstance(node, dict) or id(node) in seen:
            return
        seen.add(id(node))
        for fn in node.get("functions") or []:
            collect(fn)
        # A top-level report keeps its component tree under "component"; a
        # nested component entry (section id 4) is itself that shape, holding
        # core_modules and any further nesting at its own top level. Reading
        # both levels covers either without a special case per depth.
        for level in (node, node.get("component")):
            if not isinstance(level, dict):
                continue
            for child in (level.get("core_modules") or []) + (
                level.get("nested_components") or []
            ):
                walk(child)

    walk(report)
    if not streams:
        return 0
    # Max-min fair share: hand out the budget shortest stream first, so a
    # function needing less than an equal share releases the remainder to the
    # ones that need more. Allotments are decided here, then applied in walk
    # order below to keep the result deterministic.
    remaining = budget
    allotments: dict[int, int] = {}
    for position, fn in enumerate(sorted(streams, key=lambda fn: len(fn["instructions"]))):
        share = remaining // (len(streams) - position)
        allot = min(len(fn["instructions"]), share)
        allotments[id(fn)] = allot
        remaining -= allot
    dropped_total = 0
    functions_truncated = 0
    for fn in streams:
        instructions = fn["instructions"]
        allot = allotments[id(fn)]
        if allot >= len(instructions):
            continue
        dropped = len(instructions) - allot
        dropped_total += dropped
        functions_truncated += 1
        fn["instructions_truncated"] = dropped
        fn["instructions"] = instructions[:allot]
    if dropped_total and isinstance(report, dict):
        report["blint_truncation"] = {
            "instruction_budget": budget,
            "instructions_dropped": dropped_total,
            "functions_truncated": functions_truncated,
        }
    return dropped_total


def parse_wasm_metadata(
    exe_file: str,
    metadata: dict,
    include_strings: bool = True,
    include_call_graph: bool = True,
) -> dict:
    """Parses WebAssembly metadata via wasm_tools and maps it to blint schema."""
    metadata.update(
        {
            "binary_type": "WASM",
            "name": exe_file,
            "exe_type": "wasmbinary",
        }
    )
    try:
        report = (
            parse_wasm_file(
                exe_file,
                include_strings=include_strings,
                include_call_graph=include_call_graph,
            )
            or {}
        )
    except (AttributeError, TypeError, ValueError, OSError) as exc:
        metadata["errors"] = [f"Failed to parse wasm file {exe_file}: {exc}"]
        return metadata

    dropped = trim_wasm_instruction_streams(report)
    if dropped:
        LOG.info(
            f"Trimmed {dropped} instruction(s) from the wasm report of {exe_file} "
            f"to bound its size. Tune BLINT_MAX_WASM_INSTRUCTIONS (or set to 0 "
            "to disable truncation)."
        )

    imports = report.get("imports") or []
    exports = report.get("exports") or []
    functions = report.get("functions") or []
    imported_modules = sorted(
        {
            str(imp.get("module", "")).strip()
            for imp in imports
            if str(imp.get("module", "")).strip()
        }
    )
    wasm_analysis = report.get("analysis") or {}
    # wasm-tools 2.1 detects 64-bit memories in the import section too
    # (Emscripten-style modules), surfaced as the isa.memory64 capability.
    has_wasm64_memory = any(
        bool((mem.get("limits") or {}).get("is_64"))
        for mem in (report.get("memories") or [])
        if isinstance(mem, dict)
    ) or "isa.memory64" in set(wasm_analysis.get("capabilities") or [])
    metadata["machine_type"] = "WASM64" if has_wasm64_memory else "WASM32"
    metadata["module_version"] = report.get("module_version")
    metadata["section_count"] = report.get("section_count", 0)
    metadata["sections"] = report.get("sections", [])
    metadata["wasm_errors"] = report.get("errors", [])
    metadata["wasm_analysis"] = wasm_analysis
    metadata["wasm_report"] = report

    # wasm-tools 2.x surfaces; summaries only, the full payload stays in the
    # companion *-wasm-report.json export.
    metadata["is_component"] = bool(report.get("is_component"))
    toolchain = report.get("toolchain") or {}
    metadata["wasm_toolchain"] = toolchain
    metadata["wasm_unknown_opcodes"] = list(
        (wasm_analysis.get("summary") or {}).get("unknown_opcodes") or []
    )
    metadata["wasm_isa_capabilities"] = sorted(
        str(cap)
        for cap in (wasm_analysis.get("capabilities") or [])
        if str(cap).startswith("isa.")
    )
    type_kinds = Counter(
        str(t.get("kind", "func")) for t in (report.get("types") or []) if isinstance(t, dict)
    )
    metadata["wasm_types_summary"] = {
        "total": type_kinds.total(),
        "func": type_kinds.get("func", 0),
        "struct": type_kinds.get("struct", 0),
        "array": type_kinds.get("array", 0),
        # Any composite kind a newer wasm-tools starts decoding lands here, so
        # the per-kind counts always add up to total.
        **{
            kind: count
            for kind, count in sorted(type_kinds.items())
            if kind not in ("func", "struct", "array")
        },
    }
    format_detection = (wasm_analysis.get("detections") or {}).get("format") or {}
    metadata["wasm_debug_info_present"] = "debug_info_present" in (
        format_detection.get("signals") or []
    )
    call_graph = report.get("call_graph") or {}
    edge_kind_counts = Counter(
        str(edge.get("kind", "unknown"))
        for edge in (call_graph.get("edges") or [])
        if isinstance(edge, dict)
    )
    metadata["wasm_call_graph_summary"] = {
        "node_count": call_graph.get("node_count", 0),
        "edge_count": call_graph.get("edge_count", edge_kind_counts.total()),
        "truncated": bool(call_graph.get("truncated", False)),
        "edge_kinds": dict(sorted(edge_kind_counts.items())),
    }
    strings_detection = (wasm_analysis.get("detections") or {}).get("strings") or {}
    metadata["wasm_strings_summary"] = {
        "detected": bool(strings_detection.get("detected")),
        "string_count": strings_detection.get("string_count", 0),
        "signals": list(strings_detection.get("signals") or []),
        "counts": dict(strings_detection.get("counts") or {}),
        "samples": dict(strings_detection.get("samples") or {}),
    }

    metadata["dynamic_entries"] = [
        {
            "name": mod,
            "tag": "NEEDED",
        }
        for mod in imported_modules
    ]
    metadata["imports"] = metadata["dynamic_entries"]
    metadata["wasm_imports"] = [
        {
            "module": str(imp.get("module", "")),
            "name": demangle_symbolic_name(str(imp.get("name", ""))),
            "kind": str(imp.get("kind", "")),
            "type_index": imp.get("type_index"),
        }
        for imp in imports
    ]
    metadata["exports"] = [
        {
            "name": demangle_symbolic_name(str(exp.get("name", ""))),
            "kind": str(exp.get("kind", "")),
            "ref_index": exp.get("ref_index"),
        }
        for exp in exports
    ]
    metadata["functions"] = [
        {
            "index": fn.get("index"),
            "name": demangle_symbolic_name(str(fn.get("name", ""))),
            "address": ADDRESS_FMT.format(int(fn.get("offset", 0))).strip(),
            "size": fn.get("body_size", 0),
            "instruction_count": fn.get("instruction_count", 0),
        }
        for fn in functions
    ]
    metadata["dynamic_symbols"] = [
        {
            "name": f"{imp.get('module', '')}::{demangle_symbolic_name(str(imp.get('name', '')))}",
            "is_imported": True,
            "is_exported": False,
            "is_function": imp.get("kind") == "func",
            "is_static": False,
            "is_variable": imp.get("kind") == "global",
        }
        for imp in imports
    ]
    metadata["symtab_symbols"] = [
        {
            "name": demangle_symbolic_name(str(exp.get("name", ""))),
            "is_imported": False,
            "is_exported": True,
            "is_function": exp.get("kind") == "func",
            "is_static": False,
            "is_variable": exp.get("kind") == "global",
        }
        for exp in exports
    ]

    build_info = {}
    detections = wasm_analysis.get("detections") or {}
    if (wasi := detections.get("wasi")) and wasi.get("detected"):
        build_info["runtime"] = "WASI"
        build_info["wasi_variants"] = wasi.get("variants", [])
    if (js_interface := detections.get("js_interface")) and js_interface.get("detected"):
        build_info["host_interface"] = "JavaScript"
    if languages := toolchain.get("languages"):
        build_info["languages"] = languages
    if processed_by := toolchain.get("processed_by"):
        build_info["processed_by"] = processed_by
    if metadata["is_component"]:
        component_info = report.get("component") or {}
        for key in ("component_version", "layer_version"):
            if (value := component_info.get(key)) is not None:
                build_info[key] = value
    if build_info:
        metadata["build_info"] = build_info
    if metadata["wasm_errors"]:
        metadata["errors"] = metadata["wasm_errors"]
    return metadata


def build_wasm_callgraph(wasm_report: dict) -> dict:
    """Converts a wasm_tools report call graph into blint's callgraph payload.

    Imported functions become ``external`` targets rather than nodes because
    they are host functions, not module code; the remaining nodes are the
    locally defined functions. The wasm-tools edge kinds are preserved so the
    approximated candidates stay distinguishable from exact evidence, and they
    drive confidence for the ``--callgraph-min-confidence`` filter through the
    same :func:`_default_confidence_for_kind` mapping the native builder uses:
    ``direct`` edges are exact (high) while ``indirect-approx`` /
    ``typed-approx`` are candidates (low). Imports are the one place wasm
    outranks natives: the target of an import edge is named exactly by the
    module, not attributed from evidence, so it stays high.

    For multi-core-module components the wasm-tools graph itself is approximate
    (per-module index spaces may collide), so this conversion inherits that
    limitation rather than adding one.

    Args:
        wasm_report: The full wasm_tools parser report.

    Returns:
        A blint callgraph payload (version 2 schema), or {} when the report
        carries no usable call graph.

    """
    wasm_graph = (wasm_report or {}).get("call_graph") or {}
    wasm_nodes = [
        node
        for node in (wasm_graph.get("nodes") or [])
        if isinstance(node, dict) and isinstance(node.get("index"), int) and node["index"] >= 0
    ]
    if not wasm_nodes:
        return {}

    # ADDRESS_FMT keeps these node addresses identical to the ones in
    # metadata["functions"], so a node can be cross-referenced by string match.
    addresses = {}
    for fn in (wasm_report or {}).get("functions") or []:
        if isinstance(fn, dict) and isinstance(fn.get("index"), int):
            offset = fn.get("offset")
            if isinstance(offset, int) and offset >= 0:
                addresses[fn["index"]] = ADDRESS_FMT.format(offset).strip()

    imported_names: dict[int, str] = {}
    nodes: list[dict[str, Any]] = []
    index_to_id: dict[int, int] = {}
    for wasm_node in sorted(wasm_nodes, key=lambda node: node["index"]):
        index = wasm_node["index"]
        name = demangle_symbolic_name(str(wasm_node.get("name") or "")).strip() or f"func[{index}]"
        if wasm_node.get("imported"):
            # Match the "module::name" form used for wasm imports in
            # metadata["dynamic_symbols"] so external targets line up with the
            # import table.
            module = str(wasm_node.get("module") or "")
            import_name = demangle_symbolic_name(str(wasm_node.get("import_name") or ""))
            imported_names[index] = f"{module}::{import_name}" if module or import_name else name
            continue
        address = addresses.get(index, "")
        index_to_id[index] = len(nodes)
        nodes.append(
            {
                "id": len(nodes),
                "key": f"{address}::{name}" if address else name,
                "name": name,
                "address": address,
                "exported": bool(wasm_node.get("exported")),
            }
        )

    if not nodes:
        return {}

    edge_counts: Counter = Counter()
    external_counts: Counter = Counter()
    for edge in wasm_graph.get("edges") or []:
        if not isinstance(edge, dict):
            continue
        src = index_to_id.get(edge.get("from"))
        if src is None:
            continue
        kind = str(edge.get("kind") or "direct")
        dst_index = edge.get("to")
        dst = index_to_id.get(dst_index)
        if dst is not None:
            edge_counts[(src, dst, kind)] += 1
        elif target := imported_names.get(dst_index):
            reason = "import" if kind == "direct" else f"import:{kind}"
            external_counts[(src, target, reason)] += 1

    edges = [
        {
            "src": src,
            "dst": dst,
            "count": count,
            "kind": kind,
            "confidence": _default_confidence_for_kind(kind),
        }
        for (src, dst, kind), count in sorted(edge_counts.items(), key=lambda item: item[0])
    ]
    external = [
        {
            "src": src,
            "target": target,
            "count": count,
            "reason": reason,
            "confidence": "high" if reason == "import" else "low",
        }
        for (src, target, reason), count in sorted(
            external_counts.items(), key=lambda item: item[0]
        )
    ]
    return {
        "version": 2,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": nodes,
        "edges": edges,
        "external": external,
    }
