from __future__ import annotations

from collections import Counter
from typing import Any


def _edge_key(name: str, address: str) -> str:
    return f"{name}@{address}"


def _normalize_external_target(target: str) -> str:
    """Normalize bracketed operand spacing for stable label matching."""
    target = (target or "").strip()
    if "[" not in target:
        return target

    out: list[str] = []
    bracket_depth = 0
    for ch in target:
        if ch == "[":
            bracket_depth += 1
            out.append(ch)
            continue
        if ch == "]":
            bracket_depth = max(0, bracket_depth - 1)
            out.append(ch)
            continue
        if bracket_depth > 0 and ch.isspace():
            continue
        out.append(ch)
    return "".join(out)


def build_edge_indexes(callgraph: dict[str, Any]) -> tuple[set[str], set[str]]:
    """Build stable internal/external edge indexes from a callgraph payload."""
    nodes = callgraph.get("nodes") or []
    internal_index: set[str] = set()
    external_index: set[str] = set()

    for edge in callgraph.get("edges") or []:
        src = (
            nodes[edge.get("src", -1)] if 0 <= edge.get("src", -1) < len(nodes) else {}
        )
        dst = (
            nodes[edge.get("dst", -1)] if 0 <= edge.get("dst", -1) < len(nodes) else {}
        )
        src_ref = _edge_key(src.get("name", ""), src.get("address", ""))
        dst_ref = _edge_key(dst.get("name", ""), dst.get("address", ""))
        kind = edge.get("kind") or "direct"
        internal_index.add(f"{src_ref}->{dst_ref}::{kind}")

    for edge in callgraph.get("external") or []:
        src = (
            nodes[edge.get("src", -1)] if 0 <= edge.get("src", -1) < len(nodes) else {}
        )
        src_ref = _edge_key(src.get("name", ""), src.get("address", ""))
        target = _normalize_external_target(edge.get("target") or "")
        reason = edge.get("reason") or ""
        external_index.add(f"{src_ref}->{target}::{reason}")

    return internal_index, external_index


def extract_kpi(metadata: dict[str, Any]) -> dict[str, Any]:
    """Extract stable callgraph KPI counters from metadata."""
    disassembled = metadata.get("disassembled_functions") or {}
    callgraph = metadata.get("callgraph") or {}

    kinds = Counter(
        edge.get("kind") or "direct" for edge in callgraph.get("edges") or []
    )
    reasons = Counter(
        edge.get("reason") or "unknown" for edge in callgraph.get("external") or []
    )

    return {
        "functions_total": len(disassembled),
        "functions_with_direct_targets": sum(
            1 for func in disassembled.values() if func.get("direct_call_targets")
        ),
        "internal_edges": len(callgraph.get("edges") or []),
        "external_edges": len(callgraph.get("external") or []),
        "internal_edge_kinds": dict(sorted(kinds.items())),
        "external_reason_buckets": dict(sorted(reasons.items())),
    }


def compare_kpi(
    actual_kpi: dict[str, Any],
    baseline_kpi: dict[str, Any],
    allowed_drop: dict[str, Any] | None = None,
) -> list[str]:
    """Compare KPI values and report regressions where counters dropped beyond allowed values."""
    allowed_drop = allowed_drop or {}
    failures: list[str] = []

    numeric_keys = [
        "functions_total",
        "functions_with_direct_targets",
        "internal_edges",
        "external_edges",
    ]

    for key in numeric_keys:
        expected = int(baseline_kpi.get(key, 0))
        actual = int(actual_kpi.get(key, 0))
        drop = expected - actual
        max_drop = int(allowed_drop.get(key, 0))
        if drop > max_drop:
            failures.append(
                f"{key} regressed by {drop} (expected {expected}, actual {actual}, allowed {max_drop})"
            )

    for group_key in ("internal_edge_kinds", "external_reason_buckets"):
        baseline_group = baseline_kpi.get(group_key) or {}
        actual_group = actual_kpi.get(group_key) or {}
        group_drop = allowed_drop.get(group_key) or {}
        wildcard = int(group_drop.get("*", 0)) if isinstance(group_drop, dict) else 0

        for name, expected in baseline_group.items():
            expected = int(expected)
            actual = int(actual_group.get(name, 0))
            drop = expected - actual
            max_drop = (
                int(group_drop.get(name, wildcard))
                if isinstance(group_drop, dict)
                else wildcard
            )
            if drop > max_drop:
                failures.append(
                    f"{group_key}.{name} regressed by {drop} "
                    f"(expected {expected}, actual {actual}, allowed {max_drop})"
                )

    return failures


def evaluate_accuracy(
    metadata: dict[str, Any],
    labels: list[dict[str, Any]],
) -> dict[str, Any]:
    """Evaluate FP/FN counts using curated edge assertions for one platform."""
    callgraph = metadata.get("callgraph") or {}
    internal_index, external_index = build_edge_indexes(callgraph)

    false_positives = 0
    false_negatives = 0
    true_positives = 0
    true_negatives = 0

    for item in labels:
        label_type = item.get("type")
        expect_present = bool(item.get("expect_present", True))

        if label_type == "internal":
            key = (
                f"{item.get('src', '')}->{item.get('dst', '')}::"
                f"{item.get('kind', 'direct')}"
            )
            present = key in internal_index
        elif label_type == "external":
            target = _normalize_external_target(item.get("target", ""))
            key = f"{item.get('src', '')}->{target}::{item.get('reason', '')}"
            present = key in external_index
        else:
            continue

        if expect_present and present:
            true_positives += 1
        elif expect_present and not present:
            false_negatives += 1
        elif not expect_present and present:
            false_positives += 1
        else:
            true_negatives += 1

    positives = true_positives + false_positives
    recalls = true_positives + false_negatives

    precision = true_positives / positives if positives else 1.0
    recall = true_positives / recalls if recalls else 1.0

    return {
        "assertions": len(labels),
        "true_positives": true_positives,
        "true_negatives": true_negatives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
    }
