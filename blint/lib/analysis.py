import contextlib
import html
import importlib  # noqa
import os
import re
import sys
import uuid
from collections import defaultdict
from datetime import datetime
from itertools import islice
from pathlib import Path
from typing import Optional
from xml.etree import ElementTree as ET

import yaml
from rich.terminal_theme import MONOKAI

from blint.config import FIRST_STAGE_WORDS, PII_WORDS, BlintOptions, get_int_from_env

# pylint: disable-next=unused-import
from blint.lib.checks import (
    check_authenticode,
    check_canary,
    check_codesign,
    check_dll_characteristics,
    check_nx,
    check_pie,
    check_relro,
    check_rpath,
    check_security_property,
    check_trust_info,
    check_virtual_size,
)
from blint.lib.utils import (
    create_findings_table,
    export_metadata,
    is_fuzzable_name,
    print_findings_table,
)
from blint.logger import LOG, console

check_pac = check_security_property
check_pac_strict = check_security_property
check_xfg = check_security_property
check_cet = check_security_property
check_enclave = check_security_property
check_cfg_export_suppression = check_security_property

try:
    import importlib.resources  # pylint: disable=ungrouped-imports

    HAVE_RESOURCE_READER = True
except ImportError:
    HAVE_RESOURCE_READER = False

review_files = []
if HAVE_RESOURCE_READER:
    with contextlib.suppress(NameError, FileNotFoundError):
        review_files = (
            resource.name
            for resource in importlib.resources.files(
                "blint.data.annotations"
            ).iterdir()
            if resource.is_file() and resource.name.endswith(".yml")
        )
if not review_files:
    review_methods_dir = Path(__file__).parent / "data" / "annotations"
    review_files = [p.as_posix() for p in Path(review_methods_dir).rglob("*.yml")]

rules_dict = {}
review_exe_dict = defaultdict(list)
review_methods_dict = defaultdict(list)
review_symbols_dict = defaultdict(list)
review_imports_dict = defaultdict(list)
review_entries_dict = defaultdict(list)
review_functions_dict = defaultdict(list)

review_rules_cache = {
    "PII_READ": {
        "id": "PII_READ",
        "title": "Detect PII Read Operations",
        "summary": "Can Retrieve Sensitive PII data",
        "description": "Contains logic to retrieve sensitive data such as names, email, passwords etc.",
        "patterns": PII_WORDS,
    },
    "LOADER_SYMBOLS": {
        "id": "LOADER_SYMBOLS",
        "title": "Detect Initial Loader",
        "summary": "Behaves like a loader",
        "description": "The binary behaves like a loader by downloading and executing additional payloads.",
        "patterns": FIRST_STAGE_WORDS,
    },
}

# Debug mode
DEBUG_MODE = os.getenv("SCAN_DEBUG_MODE") == "debug"

# No of evidences per category
EVIDENCE_LIMIT = get_int_from_env("EVIDENCE_LIMIT", 5)


def get_resource(package, resource):
    """Return a file handle on a named resource in a Package."""

    # Prefer ResourceReader APIs, as they are newest.
    if HAVE_RESOURCE_READER:
        # If we're in the context of a module, we could also use
        # ``__loader__.get_resource_reader(__name__).open_resource(resource)``.
        # We use open_binary() because it is simple.
        return (
            importlib.resources.files(package)
            .joinpath(resource)
            .open("r", encoding="utf-8")
        )

    # Fall back to __file__.

    # We need to first import the package so we can find its location.
    # This could raise an exception!
    mod = importlib.import_module(package)

    # Undefined __file__ will raise NameError on variable access.
    try:
        package_path = os.path.abspath(os.path.dirname(mod.__file__))
    except NameError:
        package_path = None

    if package_path is not None:
        # Warning: there is a path traversal attack possible here if
        # resource contains values like ../../../../etc/password. Input
        # must be trusted or sanitized before blindly opening files or
        # you may have a security vulnerability!
        resource_path = os.path.join(package_path, resource)

        return open(resource_path, "r", encoding="utf-8")

    # Could not resolve package path from __file__.
    LOG.warning(f"Unable to load resource: {package}:{resource}")
    return None


# Load the rules
with get_resource("blint.data", "rules.yml") as fp:
    raw_rules = fp.read().split("---")
for tmp_data in raw_rules:
    if not tmp_data:
        continue
    rules_list = yaml.safe_load(tmp_data)
    for rule in rules_list:
        rules_dict[rule.get("id")] = rule


def load_default_rules():
    """Load default rules from package resources."""
    with get_resource("blint.data", "rules.yml") as fp:
        raw_rules = fp.read().split("---")
    for tmp_data in raw_rules:
        if not tmp_data:
            continue
        rules_list = yaml.safe_load(tmp_data)
        for rule in rules_list:
            rules_dict[rule.get("id")] = rule
    for review_methods_file in review_files:
        with get_resource("blint.data.annotations", review_methods_file) as fp:
            raw_annotations = fp.read().split("---")
            for tmp_data in raw_annotations:
                if not tmp_data:
                    continue
                methods_reviews_groups = yaml.safe_load(tmp_data)
                exe_type_list = methods_reviews_groups.get("exe_type")
                if isinstance(exe_type_list, str):
                    exe_type_list = [exe_type_list]
                all_rules = methods_reviews_groups.get("rules")
                method_rules_dict = {}
                for rule in all_rules:
                    rule_id = rule.get("id")
                    if rule_id:
                        method_rules_dict[rule_id] = rule
                        review_rules_cache[rule_id] = rule
                    else:
                        LOG.warning("Default rule has no 'id'. Skipping.")
                        continue
                for etype in exe_type_list:
                    group = methods_reviews_groups.get("group")
                    if group == "METHOD_REVIEWS":
                        review_methods_dict[etype].append(method_rules_dict)
                    elif group == "EXE_REVIEWS":
                        review_exe_dict[etype].append(method_rules_dict)
                    elif group == "SYMBOL_REVIEWS":
                        review_symbols_dict[etype].append(method_rules_dict)
                    elif group == "IMPORT_REVIEWS":
                        review_imports_dict[etype].append(method_rules_dict)
                    elif group == "ENTRIES_REVIEWS":
                        review_entries_dict[etype].append(method_rules_dict)
                    elif group == "FUNCTION_REVIEWS":
                        review_functions_dict[etype].append(method_rules_dict)


def load_custom_rules(
    custom_dir_path: Optional[str],
    review_rules_cache,
    review_exe_dict,
    review_methods_dict,
    review_symbols_dict,
    review_imports_dict,
    review_entries_dict,
    review_functions_dict,
):
    """
    Loads custom review rules from a specified directory.
    """
    if not custom_dir_path:
        return
    if not os.path.isdir(custom_dir_path):
        LOG.debug(
            f"Custom rules directory '{custom_dir_path}' does not exist or is not a directory. Skipping custom rules."
        )
        return

    LOG.debug(f"Loading custom review rules from '{custom_dir_path}'")
    custom_path = Path(custom_dir_path)
    custom_rule_files = list(custom_path.glob("*.yml")) + list(
        custom_path.glob("*.yaml")
    )

    for rule_file_path in custom_rule_files:
        LOG.debug(f"Loading custom rules from {rule_file_path}")
        try:
            with open(rule_file_path, "r", encoding="utf-8") as f:
                raw_annotations = f.read().split("---")
                for tmp_data in raw_annotations:
                    if not tmp_data:
                        continue
                    methods_reviews_groups = yaml.safe_load(tmp_data)
                    if not methods_reviews_groups:
                        continue
                    exe_type_list = methods_reviews_groups.get("exe_type")
                    if isinstance(exe_type_list, str):
                        exe_type_list = [exe_type_list]
                    all_rules = methods_reviews_groups.get("rules")
                    if not all_rules:
                        LOG.info(f"No 'rules' found in block of {rule_file_path}")
                        continue
                    method_rules_dict = {}
                    for rule in all_rules:
                        rule_id = rule.get("id")
                        if rule_id:
                            method_rules_dict[rule_id] = rule
                            review_rules_cache[rule_id] = rule
                        else:
                            LOG.warning(
                                f"Rule in {rule_file_path} has no 'id'. Skipping."
                            )
                            continue

                    for etype in exe_type_list:
                        group = methods_reviews_groups.get("group")
                        if group == "METHOD_REVIEWS":
                            review_methods_dict[etype].append(method_rules_dict)
                        elif group == "EXE_REVIEWS":
                            review_exe_dict[etype].append(method_rules_dict)
                        elif group == "SYMBOL_REVIEWS":
                            review_symbols_dict[etype].append(method_rules_dict)
                        elif group == "IMPORT_REVIEWS":
                            review_imports_dict[etype].append(method_rules_dict)
                        elif group == "ENTRIES_REVIEWS":
                            review_entries_dict[etype].append(method_rules_dict)
                        elif group == "FUNCTION_REVIEWS":
                            review_functions_dict[etype].append(method_rules_dict)
                        else:
                            LOG.warning(
                                f"Unknown group '{methods_reviews_groups.get('group')}' in {rule_file_path}. Skipping block."
                            )
        except Exception as e:
            LOG.error(f"Error loading custom rules from {rule_file_path}: {e}")


def initialize_rules(blint_options: BlintOptions):
    """
    Loads default and custom rules based on blint_options.
    """
    rules_dict.clear()
    review_exe_dict.clear()
    review_methods_dict.clear()
    review_symbols_dict.clear()
    review_imports_dict.clear()
    review_entries_dict.clear()
    review_functions_dict.clear()
    review_rules_cache.clear()
    review_rules_cache.update(
        {
            "PII_READ": {
                "id": "PII_READ",
                "title": "Detect PII Read Operations",
                "summary": "Can Retrieve Sensitive PII data",
                "description": "Contains logic to retrieve sensitive data such as names, email, passwords etc.",
                "patterns": PII_WORDS,
            },
            "LOADER_SYMBOLS": {
                "id": "LOADER_SYMBOLS",
                "title": "Detect Initial Loader",
                "summary": "Behaves like a loader",
                "description": "The binary behaves like a loader by downloading and executing additional payloads.",
                "patterns": FIRST_STAGE_WORDS,
            },
        }
    )
    load_default_rules()
    load_custom_rules(
        blint_options.custom_rules_dir,
        review_rules_cache,
        review_exe_dict,
        review_methods_dict,
        review_symbols_dict,
        review_imports_dict,
        review_entries_dict,
        review_functions_dict,
    )


def run_checks(f, metadata):
    """Runs the checks on the provided metadata using the loaded rules.

    Args:
        f: The metadata of the functions.
        metadata: The metadata containing information about the executable.

    Returns:
        A list of result dictionaries representing the outcomes of the checks.

    """
    results = []
    if not rules_dict:
        LOG.warning("No rules loaded!")
        return results
    if not metadata:
        return results
    exe_type = metadata.get("exe_type")
    for cid, rule_obj in rules_dict.items():
        rule_exe_types = rule_obj.get("exe_types")
        # Skip rules that are not valid for this exe type
        if exe_type and rule_exe_types and exe_type not in rule_exe_types:
            continue
        if result := run_rule(f, metadata, rule_obj, exe_type, cid):
            results.append(result)
    return results


def run_rule(f, metadata, rule_obj, exe_type, cid):
    """
    Runs a rule on a file with the provided metadata, rule object, executable
    type, and component ID.

    Args:
        f (str): The file path to run the rule on.
        metadata (dict): The metadata of the file.
        rule_obj (dict): The rule object to compare against.
        exe_type (str): The executable type of the file.
        cid (str): The component ID.

    Returns:
        str or dict: The result of running the rule on the file
    """
    if cfn := getattr(sys.modules[__name__], cid.lower(), None):
        result = cfn(f, metadata, rule_obj=rule_obj)
        if result is False or isinstance(result, str):
            aresult = {**rule_obj, "filename": f}
            return process_result(metadata, aresult, exe_type, result)
    return ""


def process_result(metadata, aresult, exe_type, result):
    """Processes the result by modifying the provided result dictionary.

    Args:
        metadata: The metadata containing information about the executable.
        aresult: The result dictionary to be modified.
        exe_type: The type of the executable.
        result: The result value to be processed.

    Returns:
        The modified result dictionary.

    """
    if isinstance(result, str):
        aresult["title"] = f"{aresult['title']} ({result})"
    if metadata.get("name"):
        aresult["exe_name"] = metadata.get("name")
    aresult["exe_type"] = exe_type
    return aresult


def run_prefuzz(metadata):
    """Runs the pre-fuzzing process on the given metadata.

    Generates a list of fuzzable methods from the provided metadata by
    extracting the function names and addresses.

    Args:
        metadata: The metadata containing the functions.

    Returns:
        A list of fuzzable methods with their names and addresses.

    """
    functions_list = [
        {
            "name": re.sub(r"[*&()]", "", f.get("name", "")),
            "address": f.get("address", ""),
        }
        for f in metadata.get("functions", [])
    ]
    functions_list += [
        {
            "name": re.sub(r"[*&()]", "", f.get("name", "")),
            "address": f.get("address", ""),
        }
        for f in metadata.get("ctor_functions", [])
    ]
    functions_list += [
        {
            "name": re.sub(r"[*&()]", "", f.get("name", "")),
            "address": f.get("address", ""),
        }
        for f in metadata.get("exception_functions", [])
    ]
    functions_list += [
        {
            "name": re.sub(r"[*&()]", "", f.get("name", "")),
            "address": f.get("address", ""),
        }
        for f in metadata.get("unwind_functions", [])
    ]
    functions_list += [
        {"name": f.get("name", ""), "address": f.get("address", "")}
        for f in metadata.get("exports", [])
    ]
    fuzzables = [
        {"name": f.get("name"), "address": f.get("address", "").strip()}
        for f in functions_list
        if is_fuzzable_name(f.get("name"))
    ]
    LOG.debug(f"Found {len(fuzzables)} fuzzable methods")
    return fuzzables


def print_reviews_table(reviews, files):
    """Prints the capability review table.

    Args:
        reviews: A list of dictionaries representing the capability reviews.
        files: A list of file names associated with the reviews.

    """
    table = create_findings_table(files, "BLint Capability Review")
    table.add_column("Capabilities")
    table.add_column("Evidence (Top 5)", overflow="fold")
    for r in reviews:
        evidences = [e.get("function") for e in r.get("evidence")]
        evidences = list(islice(evidences, EVIDENCE_LIMIT))
        if len(files) > 1:
            table.add_row(
                r.get("id"),
                os.path.basename(r.get("exe_name")),
                r.get("summary"),
                "\n".join(evidences),
            )
        else:
            table.add_row(
                r.get("id"),
                r.get("summary"),
                "\n".join(evidences),
            )
    console.print(table)


def _safe_mermaid_label(value: str) -> str:
    """Normalizes Mermaid labels to a parser-safe single-line representation."""
    label = str(value or "")
    label = (
        label.replace("\r", " ")
        .replace("\n", " ")
        .replace("\t", " ")
        .replace("\\", "/")
        .replace('"', "'")
        .replace("|", "/")
        .replace("`", "'")
    )
    label = "".join(ch if ch.isprintable() else " " for ch in label)
    return " ".join(label.split()).strip()


def _build_mermaid_callgraph_text(callgraph: dict) -> str:
    """Builds Mermaid graph text from a blint callgraph object."""
    lines = ["graph TD"]
    nodes = callgraph.get("nodes") or []
    edges = callgraph.get("edges") or []
    external = callgraph.get("external") or []
    for node in nodes:
        node_id = node.get("id")
        if node_id is None:
            continue
        node_name = node.get("name") or "unknown"
        node_addr = node.get("address") or ""
        label = _safe_mermaid_label(
            f"{node_name} ({node_addr})" if node_addr else node_name
        )
        lines.append(f'    N{node_id}["{label}"]')
    for edge in edges:
        src = edge.get("src")
        dst = edge.get("dst")
        if src is None or dst is None:
            continue
        count = edge.get("count", 1)
        edge_label = f"|{count}|" if count and count > 1 else ""
        lines.append(f"    N{src} -->{edge_label} N{dst}")
    for idx, ext in enumerate(external):
        src = ext.get("src")
        if src is None:
            continue
        target = _safe_mermaid_label(ext.get("target") or "unknown")
        reason = _safe_mermaid_label(ext.get("reason") or "unresolved")
        count = ext.get("count", 1)
        ext_id = f"X{idx}"
        lines.append(f'    {ext_id}["{_safe_mermaid_label(f"{target} ({reason})")}"]')
        edge_label = f"|{count}|" if count and count > 1 else ""
        lines.append(f"    N{src} -.->{edge_label} {ext_id}")
    return "\n".join(lines) + "\n"


def _sanitize_stem(name: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", str(name or "")).strip("_")
    return stem or "binary"


def _filter_callgraph_by_min_confidence(callgraph: dict, min_confidence: str) -> dict:
    rank = {"low": 1, "medium": 2, "high": 3}
    threshold = rank.get((min_confidence or "low").lower(), 1)
    if threshold <= 1:
        return callgraph

    filtered = dict(callgraph)
    filtered["edges"] = [
        edge
        for edge in (callgraph.get("edges") or [])
        if rank.get((edge.get("confidence") or "low").lower(), 1) >= threshold
    ]
    filtered["external"] = [
        ext
        for ext in (callgraph.get("external") or [])
        if rank.get((ext.get("confidence") or "low").lower(), 1) >= threshold
    ]
    filtered["edge_count"] = len(filtered["edges"])
    return filtered


def _iter_callgraph_exports(
    callgraphs: list[dict], min_confidence: str = "low"
) -> list[dict]:
    """Builds stable per-binary export metadata with collision-safe file stems."""
    exports = []
    stem_counts = defaultdict(int)
    for entry in callgraphs:
        if not isinstance(entry, dict):
            continue
        callgraph = _filter_callgraph_by_min_confidence(
            entry.get("callgraph") or {}, min_confidence
        )
        if not isinstance(callgraph, dict) or not callgraph.get("nodes"):
            continue
        stem = _sanitize_stem(entry.get("exe_name", "binary"))
        stem_counts[stem] += 1
        suffix = f"-{stem_counts[stem]}" if stem_counts[stem] > 1 else ""
        file_stem = f"{stem}{suffix}-callgraph"
        exports.append(
            {
                "exe_name": entry.get("exe_name") or stem,
                "callgraph": callgraph,
                "file_stem": file_stem,
            }
        )
    return exports


def _render_mermaid_callgraphs(
    reports_dir: str, callgraphs: list[dict], min_confidence: str = "low"
) -> list[dict]:
    """Writes Mermaid callgraph files and returns render metadata for HTML injection."""
    rendered = []
    for entry in _iter_callgraph_exports(callgraphs, min_confidence=min_confidence):
        file_name = f"{entry['file_stem']}.mmd"
        mermaid_text = _build_mermaid_callgraph_text(entry["callgraph"])
        mmd_file = Path(reports_dir) / file_name
        mmd_file.write_text(mermaid_text, encoding="utf-8")
        rendered.append(
            {
                "exe_name": entry["exe_name"],
                "file_name": file_name,
                "mermaid_text": mermaid_text,
            }
        )
    return rendered


def _build_graphml_tree(callgraph: dict) -> ET.Element:
    """Builds a GraphML XML tree for a callgraph."""
    root = ET.Element("graphml", xmlns="http://graphml.graphdrawing.org/xmlns")
    ET.SubElement(
        root,
        "key",
        id="node_label",
        **{"for": "node", "attr.name": "label", "attr.type": "string"},
    )
    ET.SubElement(
        root,
        "key",
        id="node_kind",
        **{"for": "node", "attr.name": "kind", "attr.type": "string"},
    )
    ET.SubElement(
        root,
        "key",
        id="edge_kind",
        **{"for": "edge", "attr.name": "kind", "attr.type": "string"},
    )
    ET.SubElement(
        root,
        "key",
        id="edge_count",
        **{"for": "edge", "attr.name": "count", "attr.type": "int"},
    )
    graph = ET.SubElement(root, "graph", edgedefault="directed")

    for node in callgraph.get("nodes") or []:
        node_id = node.get("id")
        if node_id is None:
            continue
        n = ET.SubElement(graph, "node", id=f"n{node_id}")
        label = _safe_mermaid_label(
            f"{node.get('name') or 'unknown'} ({node.get('address') or ''})"
        )
        ET.SubElement(n, "data", key="node_label").text = label
        ET.SubElement(n, "data", key="node_kind").text = "internal"

    ext_node_base = len(callgraph.get("nodes") or [])
    for idx, ext in enumerate(callgraph.get("external") or []):
        ext_node_id = f"x{ext_node_base + idx}"
        n = ET.SubElement(graph, "node", id=ext_node_id)
        ext_label = _safe_mermaid_label(
            f"{ext.get('target') or 'unknown'} ({ext.get('reason') or 'unresolved'})"
        )
        ET.SubElement(n, "data", key="node_label").text = ext_label
        ET.SubElement(n, "data", key="node_kind").text = "external"

    edge_index = 0
    for edge in callgraph.get("edges") or []:
        src = edge.get("src")
        dst = edge.get("dst")
        if src is None or dst is None:
            continue
        e = ET.SubElement(
            graph, "edge", id=f"e{edge_index}", source=f"n{src}", target=f"n{dst}"
        )
        ET.SubElement(e, "data", key="edge_kind").text = edge.get("kind", "direct")
        ET.SubElement(e, "data", key="edge_count").text = str(edge.get("count", 1))
        edge_index += 1

    for idx, ext in enumerate(callgraph.get("external") or []):
        src = ext.get("src")
        if src is None:
            continue
        target = f"x{ext_node_base + idx}"
        e = ET.SubElement(
            graph,
            "edge",
            id=f"e{edge_index}",
            source=f"n{src}",
            target=target,
        )
        ET.SubElement(e, "data", key="edge_kind").text = ext.get("reason", "unresolved")
        ET.SubElement(e, "data", key="edge_count").text = str(ext.get("count", 1))
        edge_index += 1
    return root


def _render_graphml_callgraphs(
    reports_dir: str, callgraphs: list[dict], min_confidence: str = "low"
) -> list[str]:
    """Writes GraphML callgraph files and returns generated filenames."""
    generated = []
    for entry in _iter_callgraph_exports(callgraphs, min_confidence=min_confidence):
        file_name = f"{entry['file_stem']}.graphml"
        graphml_tree = ET.ElementTree(_build_graphml_tree(entry["callgraph"]))
        graphml_tree.write(
            Path(reports_dir) / file_name,
            encoding="utf-8",
            xml_declaration=True,
        )
        generated.append(file_name)
    return generated


def _build_gexf_tree(callgraph: dict) -> ET.Element:
    """Builds a GEXF XML tree for a callgraph."""
    root = ET.Element("gexf", xmlns="http://www.gexf.net/1.2draft", version="1.2")
    graph = ET.SubElement(root, "graph", mode="static", defaultedgetype="directed")
    nodes = ET.SubElement(graph, "nodes")
    edges = ET.SubElement(graph, "edges")

    for node in callgraph.get("nodes") or []:
        node_id = node.get("id")
        if node_id is None:
            continue
        label = _safe_mermaid_label(
            f"{node.get('name') or 'unknown'} ({node.get('address') or ''})"
        )
        ET.SubElement(nodes, "node", id=f"n{node_id}", label=label)

    ext_node_base = len(callgraph.get("nodes") or [])
    for idx, ext in enumerate(callgraph.get("external") or []):
        ext_id = f"x{ext_node_base + idx}"
        ext_label = _safe_mermaid_label(
            f"{ext.get('target') or 'unknown'} ({ext.get('reason') or 'unresolved'})"
        )
        ET.SubElement(nodes, "node", id=ext_id, label=ext_label)

    edge_index = 0
    for edge in callgraph.get("edges") or []:
        src = edge.get("src")
        dst = edge.get("dst")
        if src is None or dst is None:
            continue
        ET.SubElement(
            edges,
            "edge",
            id=f"e{edge_index}",
            source=f"n{src}",
            target=f"n{dst}",
            weight=str(edge.get("count", 1)),
            label=edge.get("kind", "direct"),
        )
        edge_index += 1

    for idx, ext in enumerate(callgraph.get("external") or []):
        src = ext.get("src")
        if src is None:
            continue
        ET.SubElement(
            edges,
            "edge",
            id=f"e{edge_index}",
            source=f"n{src}",
            target=f"x{ext_node_base + idx}",
            weight=str(ext.get("count", 1)),
            label=ext.get("reason", "unresolved"),
        )
        edge_index += 1
    return root


def _render_gexf_callgraphs(
    reports_dir: str, callgraphs: list[dict], min_confidence: str = "low"
) -> list[str]:
    """Writes GEXF callgraph files and returns generated filenames."""
    generated = []
    for entry in _iter_callgraph_exports(callgraphs, min_confidence=min_confidence):
        file_name = f"{entry['file_stem']}.gexf"
        gexf_tree = ET.ElementTree(_build_gexf_tree(entry["callgraph"]))
        gexf_tree.write(
            Path(reports_dir) / file_name,
            encoding="utf-8",
            xml_declaration=True,
        )
        generated.append(file_name)
    return generated


def _inject_mermaid_into_html(html_file: Path, rendered_callgraphs: list[dict]) -> None:
    """Injects Mermaid diagrams and script into the console HTML report."""
    if not rendered_callgraphs or not html_file.exists():
        return
    html_text = html_file.read_text(encoding="utf-8", errors="ignore")
    if "blint-mermaid-callgraphs" in html_text:
        return

    diagrams = []
    for item in rendered_callgraphs:
        title = html.escape(str(item.get("exe_name", "binary")))
        file_name = html.escape(str(item.get("file_name", "")))
        mermaid_block = html.escape(item.get("mermaid_text", ""))
        diagrams.append(
            f'<section><h3>{title}</h3><p><code>{file_name}</code></p><pre class="mermaid">{mermaid_block}</pre></section>'
        )

    mermaid_section = (
        '<section id="blint-mermaid-callgraphs">'
        "<h2>Mermaid Callgraphs</h2>" + "".join(diagrams) + "</section>"
        '<script type="module">'
        "import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs';"
        "mermaid.initialize({startOnLoad:true,securityLevel:'loose'});"
        "</script>"
    )
    if "</body>" in html_text:
        html_text = html_text.replace("</body>", mermaid_section + "</body>", 1)
    else:
        html_text += mermaid_section
    html_file.write_text(html_text, encoding="utf-8")


def report(blint_options, exe_files, findings, reviews, fuzzables, callgraphs=None):
    """Generates a report based on the analysis results.

    Args:
        blint_options: A BlintOptions object containing settings.
        exe_files: A list of file names associated with the findings and reviews.
        findings: A list of dictionaries representing the findings.
        reviews: A list of dictionaries representing the reviews.
        fuzzables: A list of fuzzable methods.

    """
    should_render_callgraphs = bool(
        blint_options.render_mermaid_callgraph and callgraphs
    )
    should_export_graphml_callgraphs = bool(
        blint_options.export_callgraph_graphml and callgraphs
    )
    should_export_gexf_callgraphs = bool(
        blint_options.export_callgraph_gexf and callgraphs
    )
    should_emit_any_callgraph = (
        should_render_callgraphs
        or should_export_graphml_callgraphs
        or should_export_gexf_callgraphs
    )
    if not findings and not reviews and not should_emit_any_callgraph:
        LOG.info(
            f":white_heavy_check_mark: No issues found in {blint_options.src_dir_image}!"
        )
        return
    if not findings and not reviews:
        LOG.info(
            f":white_heavy_check_mark: No issues found in {blint_options.src_dir_image}. Rendering callgraph artifacts."
        )
    if not os.path.exists(blint_options.reports_dir):
        os.makedirs(blint_options.reports_dir)
    run_uuid = os.environ.get("SCAN_ID", str(uuid.uuid4()))
    common_metadata = {
        "scan_id": run_uuid,
        "created": f"{datetime.now():%Y-%m-%d %H:%M:%S%z}",
    }
    if findings:
        print_findings_table(findings, exe_files)
        export_metadata(
            blint_options.reports_dir,
            {**common_metadata, "findings": findings},
            "Findings",
        )
    if reviews:
        print_reviews_table(reviews, exe_files)
        export_metadata(
            blint_options.reports_dir,
            {**common_metadata, "reviews": reviews},
            "Reviews",
        )
    if fuzzables:
        export_metadata(
            blint_options.reports_dir,
            {**common_metadata, "fuzzables": fuzzables},
            "Fuzzables",
        )
    else:
        LOG.debug("No suggestion available for fuzzing")
    # Try console output as html
    html_file = Path(blint_options.reports_dir) / "blint-output.html"
    console.save_html(html_file, theme=MONOKAI)
    if should_render_callgraphs:
        rendered_callgraphs = _render_mermaid_callgraphs(
            blint_options.reports_dir,
            callgraphs,
            min_confidence=blint_options.callgraph_min_confidence,
        )
        _inject_mermaid_into_html(html_file, rendered_callgraphs)
    if should_export_graphml_callgraphs:
        _render_graphml_callgraphs(
            blint_options.reports_dir,
            callgraphs,
            min_confidence=blint_options.callgraph_min_confidence,
        )
    if should_export_gexf_callgraphs:
        _render_gexf_callgraphs(
            blint_options.reports_dir,
            callgraphs,
            min_confidence=blint_options.callgraph_min_confidence,
        )
    LOG.debug(f"HTML report written to {html_file}")
