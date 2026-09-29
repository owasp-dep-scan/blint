#!/usr/bin/env python3
"""A7 R2 — the rules over RootBeer 0.1.2 and the benign carriers.

R1's fixtures are synthetic shapes; R2 runs the K2 rules on the real
libraries the census named. The oracle is ``llvm-objdump -d`` read by
hand (the reads are recorded in ``a7-r2-carriers.md``); the budget is
the sub-minute iteration set — the carriers whose disassembly exceeds it
(libxul, libvlc, libart, libflutter, libbluetooth_jni) are skipped here
and covered by the R3 sweep at packet end.

Writes ``a7-r2-carriers.json`` (verdicts + the rule-relevant recovered
constants) beside this script.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from a7_k0_census import RULE_CALLEES, materialize_carriers

from blint.config import BlintOptions
from blint.lib.analysis import initialize_rules
from blint.lib.binary import parse
from blint.lib.review_runner import ReviewRunner

# The sub-minute set (K0 wall times on this host); the heavy carriers are
# R3's. RootBeer rides in from the committed K1 fixtures, all three ABIs.
SKIP_HEAVY = frozenset(
    {
        "libart.so",
        "libbluetooth_jni.so",
        "libflutter.so",
        "libvlc.so",
        "libxul.so",
    }
)
ROOTBEER_FIXTURES = ("libtoolChecker_arm64-v8a.so", "libtoolChecker_x86_64.so")


def rule_verdicts(metadata: dict) -> dict[str, list[dict]]:
    runner = ReviewRunner()
    runner.run_review(metadata)
    return {key: value for key, value in runner.results.items() if key.startswith("ANDROID_")}


def rule_relevant_entries(metadata: dict) -> list[dict]:
    wanted = {name for table in RULE_CALLEES.values() for name in table}
    out = []
    for entry in metadata.get("call_site_arguments") or []:
        callee = str(entry.get("callee") or "").strip().lower()
        if callee in wanted or callee.endswith("appendepkc"):
            out.append(
                {
                    "callee": entry.get("callee"),
                    "argument": entry.get("argument"),
                    "value": entry.get("value"),
                    "string": entry.get("string"),
                    "functions": entry.get("functions"),
                }
            )
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=None)
    args = parser.parse_args()
    initialize_rules(BlintOptions())
    result: dict = {}
    # The parse loop must run inside the temp directory's lifetime: the
    # app carriers are materialized copies there, and parse() on a missing
    # path returns near-empty metadata instead of raising (AGENTS.md).
    with tempfile.TemporaryDirectory(prefix="a7_r2_") as tmp:
        paths: dict[str, str] = {
            name: path
            for name, path in materialize_carriers(Path(tmp)).items()
            if name not in SKIP_HEAVY
        }
        for name in ROOTBEER_FIXTURES:
            paths[f"rootbeer:{name}"] = str(
                Path(__file__).parents[2] / "data" / "android" / name
            )
        for name, path in sorted(paths.items()):
            started = time.monotonic()
            metadata = parse(path, True)
            elapsed = round(time.monotonic() - started, 2)
            verdicts = rule_verdicts(metadata)
            summary = {}
            for rule, entries in sorted(verdicts.items()):
                real = [e for e in entries if e.get("status") != "not_evaluated"]
                summary[rule] = {
                    "fires": len(real),
                    "evidence": [
                        {
                            k: e.get(k)
                            for k in (
                                "path",
                                "callee",
                                "via",
                                "property",
                                "request_name",
                                "site_total",
                                "function",
                                "reason",
                            )
                        }
                        for e in real
                    ],
                    "not_evaluated": len(entries) - len(real),
                }
            result[name] = {
                "wall_time_s": elapsed,
                "callsite_entries": len(metadata.get("call_site_arguments") or []),
                "truncated": bool(
                    (metadata.get("call_site_arguments_coverage") or {}).get("entries_truncated")
                ),
                "rules": summary,
                "rule_relevant_constants": rule_relevant_entries(metadata),
            }
            print(
                f"{name}: {elapsed}s -> "
                f"{json.dumps({r: s['fires'] for r, s in summary.items()})}"
            )
    out = Path(args.out) if args.out else Path(__file__).parent / "a7-r2-carriers.json"
    out.write_text(json.dumps(result, indent=1, sort_keys=True), encoding="utf-8")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
