#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from blint.lib.binary import parse
from blint.lib.callgraph_kpi import compare_kpi, evaluate_accuracy, extract_kpi


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


def _print_report(report: dict[str, Any]) -> None:
    kpi = report["kpi"]
    print(f"platform: {report['platform']}")
    print(f"binary: {report.get('binary_name', 'unknown')}")
    print(f"functions_total: {kpi['functions_total']}")
    print(f"functions_with_direct_targets: {kpi['functions_with_direct_targets']}")
    print(f"internal_edges: {kpi['internal_edges']}")
    print(f"external_edges: {kpi['external_edges']}")
    print(f"internal_edge_kinds: {kpi['internal_edge_kinds']}")
    print(f"external_reason_buckets: {kpi['external_reason_buckets']}")

    if accuracy := report.get("accuracy"):
        print("accuracy:")
        print(f"  assertions: {accuracy['assertions']}")
        print(f"  false_positives: {accuracy['false_positives']}")
        print(f"  false_negatives: {accuracy['false_negatives']}")
        print(f"  precision: {accuracy['precision']}")
        print(f"  recall: {accuracy['recall']}")

    if failures := report.get("regressions"):
        print("regressions:")
        for failure in failures:
            print(f"  - {failure}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract and compare callgraph KPI counters for one binary/platform"
    )
    parser.add_argument("--metadata", help="Path to *-metadata.json")
    parser.add_argument("--binary", help="Path to binary to parse with disassembly")
    parser.add_argument(
        "--platform", help="Override platform key (default: metadata llvm_target_tuple)"
    )
    parser.add_argument("--baseline", help="Baseline JSON file path")
    parser.add_argument("--labels", help="Labels JSON file path")
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="Update baseline entry for this platform with current KPI",
    )
    parser.add_argument("--output", help="Write full report JSON to this path")
    args = parser.parse_args()

    metadata = _load_metadata(args)
    platform = args.platform or metadata.get("llvm_target_tuple") or "unknown"
    report: dict[str, Any] = {
        "platform": platform,
        "binary_name": Path(metadata.get("file_path") or "").name,
        "kpi": extract_kpi(metadata),
    }

    regressions: list[str] = []
    if args.baseline:
        baseline_path = Path(args.baseline)
        baseline = (
            _load_json(baseline_path) if baseline_path.exists() else {"entries": {}}
        )
        entries = baseline.setdefault("entries", {})

        if args.update_baseline:
            entry = entries.setdefault(platform, {})
            entry["kpi"] = report["kpi"]
            entry.setdefault(
                "allowed_drop",
                {
                    "functions_total": 0,
                    "functions_with_direct_targets": 0,
                    "internal_edges": 0,
                    "external_edges": 0,
                    "internal_edge_kinds": {"*": 0},
                    "external_reason_buckets": {"*": 0},
                },
            )
            baseline.setdefault("schema_version", 1)
            _write_json(baseline_path, baseline)
        else:
            entry = entries.get(platform)
            if not entry:
                regressions.append(
                    f"No baseline entry for platform '{platform}'. Run with --update-baseline first."
                )
            else:
                regressions.extend(
                    compare_kpi(
                        report["kpi"],
                        entry.get("kpi") or {},
                        entry.get("allowed_drop") or {},
                    )
                )

    if args.labels:
        labels_payload = _load_json(Path(args.labels))
        labels = ((labels_payload.get("entries") or {}).get(platform) or {}).get(
            "assertions", []
        )
        if labels:
            report["accuracy"] = evaluate_accuracy(metadata, labels)

    report["regressions"] = regressions
    _print_report(report)

    if args.output:
        _write_json(Path(args.output), report)

    return 1 if regressions else 0


if __name__ == "__main__":
    sys.exit(main())
