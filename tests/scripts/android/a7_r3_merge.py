#!/usr/bin/env python3
"""A7 K3 — merge the R3 sweep shards into one result file.

The tier-0 sweep runs sharded (``--shard-index i --shard-count n``); this
merges the shard JSONs plus the apps result into the shape one unsharded
run would have produced. The median rules fired per library is
reconstructed exactly from the merged per-rule findings (every finding
names its file), so the sharded run needs no extra exports.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def merge_rule_maps(maps: list[dict]) -> dict:
    merged: dict[str, dict] = {}
    for per_rule in maps:
        for rule, info in (per_rule or {}).items():
            target = merged.setdefault(rule, {"fires": 0, "findings": []})
            target["findings"].extend(info.get("findings", []))
    for rule, target in merged.items():
        target["findings"].sort(key=lambda f: str(f.get("file")))
        target["fires"] = len(target["findings"])
    return merged


def merge_notes(maps: list[dict]) -> dict:
    merged: dict = {}
    for notes in maps:
        for rule, reasons in (notes or {}).items():
            bucket = merged.setdefault(rule, {})
            for reason, count in reasons.items():
                bucket[reason] = bucket.get(reason, 0) + count
    return merged


def median_from_findings(per_rule: dict, libraries: int) -> int:
    """The median distinct rules fired per library, from the findings lists."""
    fired = {}
    for info in per_rule.values():
        for finding in info["findings"]:
            fired[finding["file"]] = fired.get(finding["file"], 0) + 1
    counts = sorted(fired.values())
    # Libraries with zero fires are part of the distribution.
    counts.extend([0] * (libraries - len(counts)))
    return counts[len(counts) // 2] if counts else 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", help="shard JSONs (tier0 shards, then apps)")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    parts = [json.loads(Path(p).read_text(encoding="utf-8")) for p in args.inputs]
    tier0_parts = [p["tier0"] for p in parts if p.get("tier0")]
    apps_parts = [p["apps"] for p in parts if p.get("apps")]
    result: dict = {"tier0": None, "apps": None}
    if tier0_parts:
        libraries = sum(p["libraries"] for p in tier0_parts)
        per_rule = merge_rule_maps([p["per_rule"] for p in tier0_parts])
        result["tier0"] = {
            "libraries": libraries,
            "per_rule": per_rule,
            "not_evaluated_notes": merge_notes([p["not_evaluated_notes"] for p in tier0_parts]),
            "median_rules_per_library_real": median_from_findings(per_rule, libraries),
            "libraries_with_zero_real_rules": libraries
            - len(
                {
                    finding["file"]
                    for info in per_rule.values()
                    for finding in info["findings"]
                }
            ),
            "wall_time_s": max(p["wall_time_s"] for p in tier0_parts),
            "shards": len(tier0_parts),
        }
    if apps_parts:
        result["apps"] = {
            "apps": sum(p["apps"] for p in apps_parts),
            "per_rule": merge_rule_maps([p["per_rule"] for p in apps_parts]),
            "not_evaluated_notes": merge_notes([p["not_evaluated_notes"] for p in apps_parts]),
            "wall_time_s": max(p["wall_time_s"] for p in apps_parts),
        }
    Path(args.out).write_text(json.dumps(result, indent=1, sort_keys=True), encoding="utf-8")
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
