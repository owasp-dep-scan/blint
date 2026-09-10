#!/usr/bin/env python3
# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT
"""Measure member-level static-linkage attribution (P4.3 gate 5 and 8).

Reads the corpus produced by build_static_linkage_corpus.py and reports, per
query binary:

- every candidate member that shares at least one distinct fuzzy or exact
  hash with the query, with the gate quantities (distinct matches, member
  coverage, contiguity) so gate thresholds can be read off the data instead
  of asserted;
- member-level attribution against the linker's own ground truth (ld
  ``-why_load``): which loaded members were recovered, and — the direction
  that catches what recall alone hides — how many attributed members are NOT
  in the binary;
- project-level attribution: which projects surfaced, and whether any project
  the binary does not contain was attributed;
- the same numbers for the query linked only against the archive that is
  deliberately absent from the database (miniz);
- timing of the whole-binary lookup versus the member-level lookup on the
  same database.

Usage:

    python tests/scripts/measure_static_linkage.py \
        --corpus-dir .tmp-static-linkage [--print-candidates]
"""

import argparse
import json
import re
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from blint import db as db_module
from blint.db import (
    build_function_hash_index,
    build_symbol_source_map,
    lookup_member_matches,
    lookup_project_matches,
)

# Archive file name -> project purl prefix, from the corpus builder's project
# list. Only used to label truth rows.
PURL_BY_ARCHIVE = {
    "libz.a": "pkg:generic/zlib",
    "liblua.a": "pkg:generic/lua",
    "libsqlite3.a": "pkg:generic/sqlite",
    "libcjson.a": "pkg:generic/cjson",
}

_TRUTH_RE = re.compile(r"\.a\[\d+\]\((?P<member>[^)]+)\)")


def load_ground_truth(apps_dir: Path, app: str) -> set[str]:
    gt_file = apps_dir / f"gt-{app}.txt"
    if not gt_file.exists():
        return set()
    return {match.group("member") for line in gt_file.read_text().splitlines() for match in [_TRUTH_RE.search(line)] if match}


def candidate_rows(metadata: dict, db_file: str):
    """Every member sharing >= 1 fuzzy or exact hash with the query, ungated."""
    positions = db_module.build_query_function_positions(metadata)
    hash_index = build_function_hash_index(metadata)
    connection = db_module.get(db_file)
    fuzzy_candidates = {}
    for batch in db_module._batched(hash_index.get("fuzzy_hashes") or []):
        for row in db_module._query_member_hash_matches(connection, batch, hash_column="fuzzy_hash"):
            fuzzy_candidates.setdefault(int(row["binary_id"]), row)
    exact_candidates = {}
    for batch in db_module._batched(hash_index.get("instruction_hashes") or []):
        for row in db_module._query_member_hash_matches(connection, batch, hash_column="instruction_hash"):
            exact_candidates.setdefault(int(row["binary_id"]), row)
    totals = db_module._query_member_totals(connection, set(fuzzy_candidates) | set(exact_candidates))
    connection.close()
    rows = []
    seen = set()
    for bid in sorted(set(fuzzy_candidates) | set(exact_candidates)):
        if bid in seen:
            continue
        seen.add(bid)
        row = fuzzy_candidates.get(bid) or exact_candidates[bid]
        matched_fuzzy = {h.strip() for h in str(fuzzy_candidates[bid]["matched_hashes"]).split(",") if h.strip()} if bid in fuzzy_candidates else set()
        matched_exact = {h.strip() for h in str(exact_candidates[bid]["matched_hashes"]).split(",") if h.strip()} if bid in exact_candidates else set()
        total_functions = totals.get(bid, {}).get("total_functions", 0)
        matched_positions = [p for h in matched_fuzzy for p in positions.get(h, [])]
        rows.append(
            {
                "purl": row["project_purl"],
                "member": row["member_name"],
                "fuzzy": len(matched_fuzzy),
                "fuzzy_total": total_functions,
                "fuzzy_cov": (len(matched_fuzzy) / total_functions) if total_functions else 0.0,
                "exact": len(matched_exact),
                "exact_total": total_functions,
                "exact_cov": (len(matched_exact) / total_functions) if total_functions else 0.0,
                "contiguity": db_module._member_contiguity(matched_positions) if matched_positions else 0.0,
            }
        )
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", default=str(REPO_ROOT / ".tmp-static-linkage"))
    parser.add_argument("--print-candidates", action="store_true", help="Print every candidate row, including rejected ones.")
    args = parser.parse_args()
    corpus = Path(args.corpus_dir).resolve()
    db_file = str(corpus / "blintdb-v4.db")
    apps_dir = corpus / "apps"
    reports_dir = corpus / "reports"

    apps = sorted(p.name[len("gt-") : -len(".txt")] for p in apps_dir.glob("gt-*.txt"))
    totals = {
        "claimed": 0,
        "claimed_true": 0,
        "loaded": 0,
        "loaded_judgeable": 0,
        "loaded_out_of_scope": 0,
        "loaded_absent": 0,
        "claimed_true_judgeable": 0,
        "projects": 0,
        "projects_true": 0,
        "false_projects": 0,
    }
    connection = db_module.get(db_file)
    for app in apps:
        metadata = json.loads((reports_dir / f"{app}-metadata.json").read_text())
        truth = load_ground_truth(apps_dir, app)
        started = time.perf_counter()
        member_matches, state = lookup_member_matches(metadata, db_file=db_file)
        member_elapsed = time.perf_counter() - started
        started = time.perf_counter()
        lookup_project_matches(
            build_symbol_source_map(metadata),
            function_hash_index=build_function_hash_index(metadata),
            binary_metadata=metadata,
            db_file=db_file,
        )
        whole_elapsed = time.perf_counter() - started

        claimed = []
        for match in member_matches:
            for member in match["members"]:
                claimed.append((match["project_purl"], member["member_name"]))
        claimed_names = {name for _purl, name in claimed}
        claimed_true = claimed_names & truth
        false_members = claimed_names - truth
        claimed_purls = {purl for purl, _name in claimed}
        # Project truth: archives that contributed loaded members, via the
        # candidate table's project grouping.
        project_truth = {row["purl"] for row in candidate_rows(metadata, db_file) if row["member"] in truth}
        false_purls = claimed_purls - project_truth

        # Recall over the judgeable subset: the raw denominator counts every
        # loaded member, but members below the coverage-judgeability floor are
        # out of scope by design (a member too small for coverage to judge is
        # not evidence), and the corpus deliberately keeps one archive absent
        # from the database as the false-attribution probe. Neither can ever be
        # claimed, so recall is also reported over what is in scope.
        member_functions = {}
        for member in truth:
            row = connection.execute(
                # The empty string means absent here exactly as it does in the
                # lookup's own member filter; counting such a row as judgeable
                # would put a member in the denominator that can never be
                # claimed.
                "SELECT function_count FROM Binaries"
                " WHERE name=? AND archive_name IS NOT NULL AND archive_name != ''",
                (member,),
            ).fetchone()
            member_functions[member] = row[0] if row else None
        judgeable = {
            member
            for member, count in member_functions.items()
            if count is not None and count >= db_module.MEMBER_MIN_COVERAGE_JUDGEABLE_FUNCTIONS
        }
        absent = {member for member, count in member_functions.items() if count is None}

        totals["loaded"] += len(truth)
        totals["claimed"] += len(claimed_names)
        totals["claimed_true"] += len(claimed_true)
        totals["loaded_judgeable"] += len(judgeable)
        totals["loaded_out_of_scope"] += len(truth) - len(judgeable) - len(absent)
        totals["loaded_absent"] += len(absent)
        totals["claimed_true_judgeable"] += len(claimed_true & judgeable)
        totals["projects"] += len(claimed_purls)
        totals["projects_true"] += len(claimed_purls & project_truth)
        totals["false_projects"] += len(false_purls)

        print(f"== {app} (state={state}, members loaded={len(truth)})")
        print(f"   attributed members: {len(claimed_names)} true={len(claimed_true)} false={len(false_members)}")
        if false_members:
            print(f"   FALSE member claims: {sorted(false_members)}")
        print(f"   attributed projects: {sorted(claimed_purls)}")
        print(f"   truth projects:      {sorted(project_truth)}")
        if false_purls:
            print(f"   FALSE project attributions: {sorted(false_purls)}")
        print(f"   timing: whole-binary lookup {whole_elapsed*1000:.1f} ms, member lookup {member_elapsed*1000:.1f} ms")

        if args.print_candidates:
            print("   candidates (>=1 shared hash, before gates):")
            for row in candidate_rows(metadata, db_file):
                in_truth = row["member"] in truth
                flag = "TRUTH" if in_truth else "NOISE"
                print(
                    f"     {flag} {row['purl']:26s} {row['member']:18s}"
                    f" fuzzy={row['fuzzy']:5d}/{row['fuzzy_total']:<5d} cov={row['fuzzy_cov']:.2f}"
                    f" exact={row['exact']:4d}/{row['exact_total']:<5d} ecov={row['exact_cov']:.2f}"
                    f" contig={row['contiguity']:.2f}"
                )

    print("== corpus totals")
    print(
        f"   member claims: {totals['claimed_true']}/{totals['loaded']} loaded members recovered"
        f" ({totals['claimed']} claimed, {totals['claimed'] - totals['claimed_true']} false)"
    )
    print(
        f"   recall over judgeable members: {totals['claimed_true_judgeable']}/{totals['loaded_judgeable']}"
        f" (out of scope: {totals['loaded_out_of_scope']} below the"
        f" {db_module.MEMBER_MIN_COVERAGE_JUDGEABLE_FUNCTIONS}-function judgeability floor,"
        f" {totals['loaded_absent']} absent from the database by design)"
    )
    print(
        f"   project attributions: {totals['projects_true']} true, {totals['false_projects']} false"
    )


if __name__ == "__main__":
    main()
