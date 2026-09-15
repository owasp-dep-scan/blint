#!/usr/bin/env python3
"""Extract and compare callgraph KPI counters for one binary/platform.

An unusable input — a metadata file that is not valid JSON, a path that
does not parse as a supported binary, or metadata carrying no
`llvm_target_tuple` while no `--platform` was given — is an *unknown*:
the script exits 2 with a message naming the missing precondition. It
never falls back to a platform named `unknown`. An input that produced
no callgraph at all is the same unknown: against a baseline every
counter reads as a total regression, and written to one it could never
fail again, because `compare_kpi`'s `drop = expected - actual` is never
positive against an expected 0. Both directions are refused.

Exit codes: 0 no regressions, 1 regressions found, 2 unusable input.

A legitimate new-platform bootstrap is `--update-baseline` over an input
that parsed and disassembled into a non-zero KPI; the entry is created
with `allowed_drop` all 0.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from blint.lib.binary import parse
from blint.lib.callgraph_kpi import compare_kpi, evaluate_accuracy, extract_kpi


class Unusable(Exception):
    """An input the script cannot measure; reported as an unknown, never a count."""


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _unusable(reason: str) -> int:
    print(f"ERROR: {reason}", file=sys.stderr)
    print(
        "  no measurement happened — this is an unusable input, not a KPI regression",
        file=sys.stderr,
    )
    return 2


def _kpi_is_all_zero(kpi: dict[str, Any]) -> bool:
    return not (
        kpi.get("functions_total")
        or kpi.get("functions_with_direct_targets")
        or kpi.get("internal_edges")
        or kpi.get("external_edges")
        or kpi.get("internal_edge_kinds")
        or kpi.get("external_reason_buckets")
    )


def _load_metadata(args: argparse.Namespace) -> dict[str, Any]:
    if args.metadata:
        path = Path(args.metadata)
        try:
            return _load_json(path)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise Unusable(f"{path} is not valid JSON: {exc}") from None
        except OSError as exc:
            raise Unusable(f"{path} could not be read: {exc}") from None
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


def main(argv: list[str] | None = None) -> int:
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
    args = parser.parse_args(argv)

    try:
        metadata = _load_metadata(args)
    except Unusable as exc:
        return _unusable(str(exc))
    if not args.platform and not metadata.get("llvm_target_tuple"):
        source = args.metadata or args.binary
        return _unusable(
            f"{source}: the metadata carries no llvm_target_tuple, so no platform can be "
            "named — the file likely did not parse as a supported binary. Refusing to "
            "record or compare a platform called 'unknown'. Pass --platform only to "
            "name the platform deliberately."
        )
    platform = args.platform or metadata.get("llvm_target_tuple")
    report: dict[str, Any] = {
        "platform": platform,
        "binary_name": Path(metadata.get("file_path") or "").name,
        "kpi": extract_kpi(metadata),
    }

    regressions: list[str] = []
    if args.baseline:
        # Gate mode. An empty callgraph is an unknown in both directions:
        # written to the baseline it can never regress again, and compared
        # against one it reports the whole baseline as a loss the change
        # did not cause.
        if _kpi_is_all_zero(report["kpi"]):
            return _unusable(
                f"the input produced no callgraph at all for platform '{platform}' — it did "
                "not disassemble (nyxstone needs LLVM 18: set NYXSTONE_LLVM_PREFIX), or the "
                "binary has no code. Every counter would read as a total regression, and a "
                "zeroed baseline entry could never regress again: compare_kpi's "
                "drop = expected - actual is never positive against an expected 0."
            )
        baseline_path = Path(args.baseline)
        baseline = _load_json(baseline_path) if baseline_path.exists() else {"entries": {}}
        entries = baseline.setdefault("entries", {})

        if args.update_baseline:
            if platform == "unknown":
                return _unusable(
                    "'unknown' is the fallback spelling this script no longer emits; "
                    "pass the real platform name"
                )
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
        labels = ((labels_payload.get("entries") or {}).get(platform) or {}).get("assertions", [])
        if labels:
            report["accuracy"] = evaluate_accuracy(metadata, labels)

    report["regressions"] = regressions
    _print_report(report)

    if args.output:
        _write_json(Path(args.output), report)

    return 1 if regressions else 0


if __name__ == "__main__":
    sys.exit(main())
