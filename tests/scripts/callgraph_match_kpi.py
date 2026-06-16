#!/usr/bin/env python3
"""
Validate binary-to-source callgraph matching via a stripped-recovery experiment.

The experiment is fully reproducible and uses the binary itself as ground truth:

1. Anchor the unstripped binary against the source callgraph by name equality.
   These Layer 0 anchors are treated as the gold mapping.
2. Deterministically hide a fraction of the binary function names (simulating a
   partially stripped binary) and re-run the matcher.
3. Score how well structural propagation recovers the hidden mappings against
   the gold mapping: precision, recall, and accuracy over the hidden set.

A hide fraction of ``1.0`` removes every name and documents the point at which
name-and-structure matching can no longer start, which motivates pure structural
fingerprinting as a later layer.

Baselines are stored per platform, mirroring ``callgraph_kpi_baseline.py``.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from blint.lib.binary import parse
from blint.lib.callgraph.match import MatchOptions, match_callgraphs
from blint.lib.callgraph.model import load_binary_callgraph, load_source_callgraph


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load_metadata(args: argparse.Namespace) -> dict[str, Any]:
    if args.metadata:
        return _load_json(Path(args.metadata))
    if args.binary:
        return parse(args.binary, disassemble=True)
    raise ValueError("Pass either --metadata or --binary")


def _should_hide(address: str, hide_fraction: float) -> bool:
    """Deterministically decide whether to hide a function name.

    A stable hash of the address keeps the selection reproducible across runs
    without relying on a random seed.
    """
    if hide_fraction <= 0:
        return False
    if hide_fraction >= 1:
        return True
    digest = hashlib.sha256(address.encode("utf-8")).digest()
    bucket = int.from_bytes(digest[:4], "big") % 10000
    return bucket < hide_fraction * 10000


def _hide_names(metadata: dict[str, Any], hide_fraction: float) -> tuple[dict[str, Any], set[str]]:
    """Return a metadata copy with a fraction of names hidden and the hidden ids."""
    clone = copy.deepcopy(metadata)
    hidden_ids: set[str] = set()
    for node in (clone.get("callgraph") or {}).get("nodes") or []:
        address = node.get("address") or ""
        if node.get("name") and _should_hide(address, hide_fraction):
            node["name"] = ""
            node.pop("aliases", None)
            hidden_ids.add(str(node.get("id")))
    return clone, hidden_ids


def _gold_mapping(source_path: str, metadata: dict[str, Any]) -> dict[str, str]:
    """Compute the Layer 0 (name-based) gold mapping for the unstripped binary."""
    source = load_source_callgraph(source_path)
    binary = load_binary_callgraph(metadata)
    anchors_only = match_callgraphs(
        source,
        binary,
        MatchOptions(enable_propagation=False, enable_fingerprint=False),
    )
    return {bid: m.source_canon for bid, m in anchors_only.matches.items()}


def evaluate(
    source_path: str,
    metadata: dict[str, Any],
    hide_fraction: float,
    options: MatchOptions,
) -> dict[str, Any]:
    """Run the stripped-recovery experiment and return its metrics."""
    gold = _gold_mapping(source_path, metadata)

    stripped, hidden_ids = _hide_names(metadata, hide_fraction)
    source = load_source_callgraph(source_path)
    binary = load_binary_callgraph(stripped)
    result = match_callgraphs(source, binary, options)

    # Restrict scoring to nodes that had a gold mapping and were hidden.
    hidden_gold = {bid for bid in hidden_ids if bid in gold}
    recovered = correct = 0
    for bid in hidden_gold:
        match = result.matches.get(bid)
        if match is None:
            continue
        recovered += 1
        if match.source_canon == gold[bid]:
            correct += 1

    surviving_anchors = sum(1 for bid in gold if bid not in hidden_ids)
    attempts = len(hidden_gold)
    precision = round(correct / recovered, 4) if recovered else 0.0
    recall = round(correct / attempts, 4) if attempts else 0.0

    return {
        "hide_fraction": hide_fraction,
        "gold_anchors": len(gold),
        "surviving_anchors": surviving_anchors,
        "hidden_with_gold": attempts,
        "recovered": recovered,
        "correct": correct,
        "precision": precision,
        "recall": recall,
        "matcher": {
            "min_votes": options.min_votes,
            "margin": options.margin,
            "max_iterations": options.max_iterations,
        },
    }


def _print_report(report: dict[str, Any]) -> None:
    metrics = report["metrics"]
    print(f"platform: {report['platform']}")
    print(f"binary: {report.get('binary_name', 'unknown')}")
    print(f"hide_fraction: {metrics['hide_fraction']}")
    print(f"gold_anchors: {metrics['gold_anchors']}")
    print(f"surviving_anchors: {metrics['surviving_anchors']}")
    print(f"hidden_with_gold: {metrics['hidden_with_gold']}")
    print(f"recovered: {metrics['recovered']}")
    print(f"correct: {metrics['correct']}")
    print(f"precision: {metrics['precision']}")
    print(f"recall: {metrics['recall']}")
    for failure in report.get("regressions") or []:
        print(f"  regression: {failure}")


def _compare(metrics: dict[str, Any], baseline: dict[str, Any]) -> list[str]:
    """Flag drops below baseline precision/recall and recovered counts."""
    regressions: list[str] = []
    for key in ("precision", "recall", "correct"):
        current = metrics.get(key, 0)
        previous = baseline.get(key, 0)
        if current < previous:
            regressions.append(f"{key} dropped from {previous} to {current}")
    return regressions


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate binary-to-source callgraph matching via stripped recovery"
    )
    parser.add_argument("--source", required=True, help="Path to source callgraph JSON")
    parser.add_argument("--metadata", help="Path to *-metadata.json")
    parser.add_argument("--binary", help="Path to binary to parse with disassembly")
    parser.add_argument(
        "--platform", help="Override platform key (default: metadata llvm_target_tuple)"
    )
    parser.add_argument(
        "--hide-fraction",
        type=float,
        default=0.5,
        help="Fraction of binary names to hide (0..1). Defaults to 0.5.",
    )
    parser.add_argument("--min-votes", type=int, default=2)
    parser.add_argument("--margin", type=int, default=1)
    parser.add_argument("--max-iterations", type=int, default=6)
    parser.add_argument(
        "--with-fingerprint",
        action="store_true",
        help="Enable experimental Layer 2 structural fingerprint matching",
    )
    parser.add_argument("--baseline", help="Baseline JSON file path")
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="Update baseline entry for this platform with current metrics",
    )
    parser.add_argument("--output", help="Write full report JSON to this path")
    args = parser.parse_args()

    metadata = _load_metadata(args)
    platform = args.platform or metadata.get("llvm_target_tuple") or "unknown"
    options = MatchOptions(
        min_votes=args.min_votes,
        margin=args.margin,
        max_iterations=args.max_iterations,
        enable_fingerprint=args.with_fingerprint,
    )
    metrics = evaluate(args.source, metadata, args.hide_fraction, options)

    report: dict[str, Any] = {
        "platform": platform,
        "binary_name": Path(metadata.get("file_path") or "").name,
        "metrics": metrics,
    }

    regressions: list[str] = []
    if args.baseline:
        baseline_path = Path(args.baseline)
        baseline = _load_json(baseline_path) if baseline_path.exists() else {"entries": {}}
        entries = baseline.setdefault("entries", {})
        if args.update_baseline:
            entries[platform] = {"metrics": metrics}
            baseline.setdefault("schema_version", 1)
            _write_json(baseline_path, baseline)
        else:
            entry = entries.get(platform)
            if not entry:
                regressions.append(
                    f"No baseline entry for platform '{platform}'. Run with --update-baseline first."
                )
            else:
                regressions.extend(_compare(metrics, entry.get("metrics") or {}))

    report["regressions"] = regressions
    _print_report(report)

    if args.output:
        _write_json(Path(args.output), report)

    return 1 if regressions else 0


if __name__ == "__main__":
    sys.exit(main())
