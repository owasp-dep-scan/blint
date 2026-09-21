#!/usr/bin/env python3
"""W3.2 measurements: the managed capability surface's finding deltas.

Three questions the packet commit must answer with numbers, not adjectives:

1. What fired that did not fire before, per rule, per tier? The "before" is
   the same metadata with this packet's new inputs removed (the dotnet
   block's typerefs/memberrefs/#US fields, the top-level strings
   promotion, the PINVOKE dependency entries) — i.e. the W3.1 tree's view
   of the same file — run through the same rule machinery.
2. Which of the new managed rules fire on benign corpora, how often, and
   with what evidence — the W2.4 CHECK_SIGNER_MISMATCH discipline:
   measure before writing the severity down.
3. The rule-34 distributions for the new fields: parse_status, the new
   degradations, the typespec-parent counts, the #US export sizes.

Usage: python tests/scripts/measure_managed_capability.py <tier-dir> [...]
"""

import json
import sys
from collections import Counter
from copy import deepcopy
from pathlib import Path

import lief

from blint.config import BlintOptions
from blint.lib.analysis import initialize_rules, run_checks
from blint.lib.binary import parse as binary_parse
from blint.lib.binary_common import parse_strings
from blint.lib.review_runner import ReviewRunner


def run_review(metadata: dict) -> dict:
    """One review pass with a fresh runner.

    ReviewRunner accumulates ``self.results`` across run_review calls, so
    a shared instance would leak file A's evidence into file B's "before"
    and make every comparison meaningless.
    """
    return ReviewRunner().run_review(metadata) or {}


def find_pe_files(tier_dir: Path):
    for path in sorted(tier_dir.rglob("*")):
        if path.suffix.lower() in (".dll", ".exe", ".sys") and path.is_file():
            yield path


def strip_new_inputs(metadata: dict, parsed_obj) -> dict:
    """Return the metadata as the W3.1 tree would have shaped it."""
    old = deepcopy(metadata)
    old.pop("strings_source", None)
    # The W3.1 tree's strings key was the native byte scan; this packet
    # replaced it with the promoted #US literals.
    old["strings"] = parse_strings(parsed_obj)
    dotnet = old.get("dotnet")
    if isinstance(dotnet, dict):
        for key in ("typerefs", "memberrefs", "memberrefs_typespec_parents",
                    "user_strings_count", "user_strings_sha256", "strings"):
            dotnet.pop(key, None)
    old["dynamic_entries"] = [
        e for e in old.get("dynamic_entries") or []
        if e.get("tag") != "PINVOKE"
    ]
    return old


def main(tier_dirs):
    initialize_rules(BlintOptions())
    totals = Counter()
    for tier_dir in tier_dirs:
        tier = Path(tier_dir).expanduser()
        tier_name = tier.name
        managed = 0
        parsed = 0
        rule_moves = Counter()
        move_examples: dict[str, list] = {}
        review_before: dict[str, Counter] = {}
        review_after: dict[str, Counter] = {}
        review_evidence: dict[str, list] = {}
        sizes = []
        for path in find_pe_files(tier):
            try:
                parsed_obj = lief.PE.parse(str(path))
            except Exception:
                continue
            if parsed_obj is None:
                continue
            parsed += 1
            try:
                metadata = binary_parse(str(path))
            except Exception:
                continue
            if not metadata.get("dotnet"):
                continue
            managed += 1
            old_meta = strip_new_inputs(metadata, parsed_obj)

            old_findings = {r["id"] for r in run_checks(str(path), old_meta)}
            new_findings = {r["id"] for r in run_checks(str(path), metadata)}
            for rid in sorted(old_findings - new_findings):
                rule_moves[f"stops: {rid}"] += 1
            for rid in sorted(new_findings - old_findings):
                rule_moves[f"starts: {rid}"] += 1
                move_examples.setdefault(f"starts: {rid}", []).append(path.name)

            old_reviews = run_review(old_meta)
            new_reviews = run_review(metadata)
            for rid, evidence in old_reviews.items():
                review_before[rid] = review_before.get(rid, Counter())
                review_before[rid][path.name] += len(evidence)
            for rid, evidence in new_reviews.items():
                review_after.setdefault(rid, Counter())[path.name] += len(evidence)
                if rid not in review_evidence and evidence:
                    review_evidence[rid] = evidence[:2]

            sizes.append(
                (path.name,
                 len(json.dumps(old_meta.get("strings") or [])),
                 len(json.dumps(metadata.get("strings") or [])),
                 metadata.get("dotnet", {}).get("user_strings_count", 0))
            )

        print(f"== tier {tier_name}: {parsed} PE files, {managed} managed ==")
        if rule_moves:
            for move, count in sorted(rule_moves.items()):
                example = (move_examples.get(move) or [])[:3]
                print(f"  {move}: {count}  {example}")
        else:
            print("  no rule firing-set moves")
        print("  -- review rules that newly fire (managed rules, after vs before) --")
        all_review_ids = sorted(set(review_before) | set(review_after))
        for rid in all_review_ids:
            before = review_before.get(rid, Counter())
            after = review_after.get(rid, Counter())
            new_files = sorted(set(after) - set(before))
            grew = sorted(set(after) & set(before),
                          key=lambda n: after[n] - before[n], reverse=True)
            grew = [n for n in grew if after[n] > before[n]]
            if new_files or grew:
                sample = ""
                if rid in review_evidence:
                    ev = review_evidence[rid][0]
                    sample = f"  sample: {ev.get('function', '')!r} via {ev.get('pattern', '')!r}"
                print(f"  {rid}: fires on {len(after)} files "
                      f"(new: {len(new_files)} {new_files[:2]}){sample}")
        print("  -- #US export sizes (strings key bytes before -> after, walk count) --")
        for name, before_size, after_size, us_count in sorted(
            sizes, key=lambda row: row[2] - row[1], reverse=True
        )[:5]:
            print(f"    {name}: {before_size} -> {after_size} bytes "
                  f"({us_count} entries walked)")
        totals["managed"] += managed
        print()

    print(f"total managed across tiers: {totals['managed']}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    main(sys.argv[1:])
