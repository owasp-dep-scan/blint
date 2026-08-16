#!/usr/bin/env python3
"""Measure how often the driver rules fire on legitimate signed drivers.

The LOLDrivers corpus contains only known-vulnerable drivers, so it measures
recall and says nothing about noise. Windows ships several hundred signed
Microsoft drivers in System32\\drivers, which is the corpus for the other half of
the question: a rule that fires on most of them is not identifying a flaw.

    python contrib/win-driver-fixture/inbox_sweep.py --drivers-dir C:/Windows/System32/drivers

The output is a hit rate per rule, not a pass/fail. Some hits are expected and
correct - plenty of inbox drivers legitimately map physical memory - so the
number worth watching is the change from one run to the next, and any rule that
climbs towards firing on everything.
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from blint.config import BlintOptions  # noqa: E402
from blint.lib.analysis import initialize_rules, review_methods_dict  # noqa: E402
from blint.lib.binary import parse  # noqa: E402
from blint.lib.review_runner import ReviewRunner  # noqa: E402

DRIVER_RULE_PREFIXES = ("DRIVER_", "BYOVD_")


def sweep(driver_paths: list) -> dict:
    """Run the driver rules over each image and tally the hits."""
    # Without this the rule tables are empty, every review returns nothing, and
    # the sweep reports a clean zero-hit run that means nothing at all.
    initialize_rules(BlintOptions())
    if not review_methods_dict:
        raise RuntimeError("no rules were loaded; a zero-hit result would be meaningless")
    hits = Counter()
    interface_hits = Counter()
    analysed = 0
    failed = []
    for path in driver_paths:
        try:
            metadata = parse(str(path))
        except Exception as exc:  # noqa: BLE001 - one bad image must not stop the sweep
            failed.append((path.name, str(exc)))
            continue
        if not metadata:
            failed.append((path.name, "no metadata"))
            continue
        analysed += 1
        reviewer = ReviewRunner()
        reviewer.run_review(metadata)
        for result in reviewer.process_review(str(path), path.name):
            if result["id"].startswith(DRIVER_RULE_PREFIXES):
                hits[result["id"]] += 1
        for key, values in (metadata.get("driver_interface") or {}).items():
            if values:
                interface_hits[key] += 1
    return {
        "analysed": analysed,
        "failed": failed,
        "rule_hits": dict(hits),
        "interface_hits": dict(interface_hits),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--drivers-dir", default="C:/Windows/System32/drivers")
    parser.add_argument("--limit", type=int, default=250, help="how many images to analyse")
    parser.add_argument("--report", help="write the raw tally to this JSON file")
    args = parser.parse_args()

    drivers_dir = Path(args.drivers_dir)
    if not drivers_dir.is_dir():
        print(f"no such directory: {drivers_dir}")
        return 2

    # Smallest first, so a capped run still covers many distinct drivers.
    paths = sorted(drivers_dir.glob("*.sys"), key=lambda p: p.stat().st_size)[: args.limit]
    if not paths:
        print(f"no .sys files under {drivers_dir}")
        return 2

    summary = sweep(paths)
    analysed = summary["analysed"] or 1

    print(f"analysed {summary['analysed']} of {len(paths)} inbox drivers")
    if summary["failed"]:
        print(f"failed to parse {len(summary['failed'])}: {summary['failed'][:5]}")
    print("\nrule hit rate (a high rate means the rule is not discriminating):")
    for rule_id, count in sorted(summary["rule_hits"].items(), key=lambda kv: -kv[1]):
        print(f"  {rule_id:<45} {count:>4} / {analysed}  ({100 * count / analysed:.1f}%)")
    if not summary["rule_hits"]:
        print("  (no driver rule fired on any inbox driver)")
    print("\nkernel object namespace strings recovered:")
    for key, count in sorted(summary["interface_hits"].items()):
        print(f"  {key:<45} {count:>4} / {analysed}")

    if args.report:
        Path(args.report).write_text(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
