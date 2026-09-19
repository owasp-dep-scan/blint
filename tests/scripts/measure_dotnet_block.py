#!/usr/bin/env python3
"""W3.1 measurements: the rule-15 exe_type before/after and the rule-34
distributions the packet commit must report.

The before/after is computed mechanically with the real rule machinery: for
each file the packet tree's metadata is produced once, then run_checks runs
twice — once with the metadata as the pre-W3.1 tree would have shaped it
(exe_type PE32/PE64 from the optional-header magic, no dotnet block) and
once as shaped now (dotnetbinary + dotnet block). The per-binary rule-ID
delta is the firing-set change the packet must argue.

Usage: python tests/scripts/measure_dotnet_block.py <tier-dir> [...]
"""

import json
import sys
from collections import Counter
from pathlib import Path

import lief

from blint.config import BlintOptions
from blint.lib.analysis import initialize_rules, run_checks
from blint.lib.binary import construct_llvm_target_tuple
from blint.lib.binary import parse as binary_parse
from blint.lib.review_runner import ReviewRunner


def find_pe_files(tier_dir: Path):
    for path in sorted(tier_dir.rglob("*")):
        if path.suffix.lower() in (".dll", ".exe", ".sys") and path.is_file():
            yield path


def main(tier_dirs):
    initialize_rules(BlintOptions())
    reviewer = ReviewRunner()
    total_files = 0
    managed_files = []
    tuples_delta = []
    rule_moves = Counter()
    move_examples: dict[str, list] = {}
    review_moves = Counter()
    for tier_dir in tier_dirs:
        tier = Path(tier_dir).expanduser()
        for path in find_pe_files(tier):
            try:
                parsed = lief.PE.parse(str(path))
            except Exception:
                continue
            if parsed is None:
                continue
            total_files += 1
            try:
                metadata = binary_parse(str(path))
            except Exception:
                continue
            block = metadata.get("dotnet")
            if block is not None:
                managed_files.append((str(path.relative_to(tier)), metadata))

            # The rule-15 firing-set delta, per binary: the rules and the
            # reviews, each run against the pre-W3.1 shape and the current
            # shape of the same file.
            old_meta = dict(metadata)
            old_meta.pop("dotnet", None)
            if block is not None:
                magic = str(parsed.optional_header.magic)
                old_meta["exe_type"] = (
                    "PE32" if magic == "PE_TYPE.PE32" else "PE64"
                )
                old_findings = {r["id"] for r in run_checks(str(path), old_meta)}
                new_findings = {r["id"] for r in run_checks(str(path), metadata)}
                for rid in sorted(old_findings - new_findings):
                    rule_moves[f"stops: {rid}"] += 1
                    move_examples.setdefault(f"stops: {rid}", []).append(
                        str(path.relative_to(tier))
                    )
                for rid in sorted(new_findings - old_findings):
                    rule_moves[f"starts: {rid}"] += 1
                    move_examples.setdefault(f"starts: {rid}", []).append(
                        str(path.relative_to(tier))
                    )
                old_reviews = {
                    r.get("id")
                    for r in reviewer.run_review(old_meta).get("results", [])
                    if r.get("id")
                }
                new_reviews = {
                    r.get("id")
                    for r in reviewer.run_review(metadata).get("results", [])
                    if r.get("id")
                }
                for rid in sorted(old_reviews - new_reviews):
                    review_moves[f"stops: {rid}"] += 1
                for rid in sorted(new_reviews - old_reviews):
                    review_moves[f"starts: {rid}"] += 1
                # llvm_target_tuple before/after (rule 21 recompute).
                old_tuple = construct_llvm_target_tuple(old_meta)
                new_tuple = construct_llvm_target_tuple(metadata)
                if old_tuple != new_tuple:
                    tuples_delta.append(
                        (str(path.relative_to(tier)), old_tuple, new_tuple)
                    )

    print(f"files parsed: {total_files}, managed (dotnet block): {len(managed_files)}")
    print()
    print("== rule 34: parse_status distribution (managed) ==")
    for status, count in sorted(
        Counter(m.get("dotnet", {}).get("parse_status") for _, m in managed_files).items()
    ):
        print(f"  {status}: {count}")
    degraded = [
        (name, m["dotnet"]["degradations"])
        for name, m in managed_files
        if m.get("dotnet", {}).get("degradations")
    ]
    print(f"  files with degradations: {len(degraded)}")
    for name, degr in degraded[:10]:
        print(f"    {name}: {degr}")
    print()
    print("== rule 34: cli_flags distribution ==")
    for flags, count in sorted(
        Counter(
            tuple(m.get("dotnet", {}).get("cli_flags", []))
            for _, m in managed_files
        ).items(),
        key=lambda kv: -kv[1],
    ):
        print(f"  {list(flags)}: {count}")
    print()
    print("== rule 34: empty P/Invoke census ==")
    empty = [name for name, m in managed_files if not m.get("dotnet", {}).get("pinvoke")]
    print(f"  managed files with no P/Invoke entries: {len(empty)} of {len(managed_files)}")
    for name, m in managed_files:
        pinv = m.get("dotnet", {}).get("pinvoke") or []
        if pinv:
            entries = ", ".join(
                f"{e.get('module')}!{e.get('entry_point')}" for e in pinv[:4]
            )
            print(f"  has P/Invoke: {name} -> {entries}")
    print()
    print("== rule 15 counterfactual: pre-packet rules.yml scopes ==")
    # With exe_type moved, the PRE-packet scope table (dotnetbinary inside
    # CHECK_CANARY and CHECK_RPATH) would have fired both on managed files.
    # Measured by invoking those checks with the old scope restored.
    from blint.lib.checks import check_canary, check_rpath

    counterfactual = Counter()
    for name, metadata in managed_files:
        cf_meta = dict(metadata)
        cf_canary = {"id": "CHECK_CANARY", "exe_types": ["dotnetbinary"]}
        cf_rpath = {"id": "CHECK_RPATH", "exe_types": ["dotnetbinary"]}
        if check_canary(name, cf_meta, cf_canary):
            counterfactual["CHECK_CANARY would fire"] += 1
        if check_rpath(name, cf_meta, cf_rpath):
            counterfactual["CHECK_RPATH would fire"] += 1
    for key, count in sorted(counterfactual.items()):
        print(f"  {key}: {count} of {len(managed_files)}")
    print()
    print("== metadata size delta on managed files (rule 13) ==")
    for name, metadata in sorted(
        managed_files, key=lambda kv: -len(json.dumps(kv[1]))
    )[:3]:
        full = len(json.dumps(metadata))
        without = dict(metadata)
        without.pop("dotnet", None)
        delta = full - len(json.dumps(without))
        refs = metadata.get("dotnet", {}).get("counts", {})
        print(
            f"  {name}: +{delta} bytes ({full} total) — "
            f"assembly_ref rows: {refs.get('assembly_ref')}, "
            f"memberref rows: {refs.get('memberref')}"
        )
    print()
    print("== rule 15: rule firing-set moves across the tier ==")
    if not rule_moves:
        print("  none — identical firing set before and after")
    for key, count in sorted(rule_moves.items()):
        print(f"  {key}: {count} file(s)")
        for example in move_examples[key][:4]:
            print(f"      {example}")
    print()
    print("== rule 15: review firing-set moves across the tier ==")
    if not review_moves:
        print("  none — identical review set before and after")
    for key, count in sorted(review_moves.items()):
        print(f"  {key}: {count} file(s)")
    print()
    print("== rule 21: llvm_target_tuple deltas ==")
    if not tuples_delta:
        print("  none")
    for name, old_t, new_t in tuples_delta[:10]:
        print(f"  {name}: {old_t} -> {new_t}")


if __name__ == "__main__":
    main(sys.argv[1:])
