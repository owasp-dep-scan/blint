#!/usr/bin/env python3
"""Measure blint's driver rule coverage against the LOLDrivers corpus.

The loldrivers.io dataset publishes the imported function list for thousands of
known-vulnerable driver samples. That is enough to evaluate blint's import-based
driver rules at scale without downloading a single binary, which makes it a
practical regression and gap-finding harness.

This script does the deterministic work only: fetch, snapshot-diff, evaluate the
rules, and rank the capability clusters that no rule currently covers. Deciding
what a new rule should say is left to a reviewer (see the loldrivers-rules
skill), because a high hit count is evidence of a gap, not of a good rule.

Usage:
    python contrib/loldrivers/sync_loldrivers.py --report out/coverage.json
    python contrib/loldrivers/sync_loldrivers.py --update-snapshot
"""

import argparse
import json
import sys
import urllib.request
from collections import Counter
from pathlib import Path

# Allow running from a source checkout without installing blint.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from blint.config import BlintOptions  # noqa: E402
from blint.lib.analysis import initialize_rules  # noqa: E402
from blint.lib.review_runner import ReviewRunner  # noqa: E402

LOLDRIVERS_URL = "https://www.loldrivers.io/api/drivers.json"
SNAPSHOT_PATH = Path(__file__).parent / "loldrivers-snapshot.json"

# Rule prefixes that this harness is responsible for.
DRIVER_RULE_PREFIXES = ("DRIVER_", "BYOVD_")

# Imports too common to be useful as rule material; they carry no capability.
UNINTERESTING_IMPORTS = {
    "dbgprint",
    "dbgprintex",
    "rtlinitunicodestring",
    "rtlcopymemory",
    "memcpy",
    "memset",
    "memmove",
    "strlen",
    "wcslen",
    "exallocatepool",
    "exallocatepoolwithtag",
    "exfreepool",
    "exfreepoolwithtag",
    "kebugcheckex",
    "iofcompleterequest",
    "iocreatedevice",
    "iocreatesymboliclink",
    "iodeletedevice",
    "iodeletesymboliclink",
    "zwclose",
    "keinitializespinlock",
    "keacquirespinlockraiselevel",
    "kereleasespinlock",
    "rtlgetversion",
    "psgetcurrentprocessid",
    "obfdereferenceobject",
}


def fetch_dataset(url: str = LOLDRIVERS_URL, timeout: int = 120) -> list:
    """Download the LOLDrivers dataset."""
    with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310
        return json.loads(response.read().decode("utf-8"))


def iter_samples(dataset: list):
    """Yield (entry, sample) pairs that carry an imported function list."""
    for entry in dataset:
        for sample in entry.get("KnownVulnerableSamples") or []:
            if sample.get("ImportedFunctions"):
                yield entry, sample


def build_metadata(sample: dict) -> dict:
    """Build blint metadata from a LOLDrivers sample record.

    Imports are qualified the way real PE metadata qualifies them, so the rules
    are exercised through the same normalization path as a real scan.
    """
    return {
        "exe_type": "PE64",
        "magic": "PE32+",
        "subsystem": "NATIVE",
        "imports": [{"name": f"ntoskrnl.exe::{name}"} for name in sample["ImportedFunctions"]],
    }


def evaluate_sample(metadata: dict) -> set:
    """Return the driver-related rule ids that fire for one sample."""
    reviewer = ReviewRunner()
    reviewer.run_review(metadata)
    results = reviewer.process_review("sample", "sample")
    return {
        result["id"]
        for result in results
        if result["id"].startswith(DRIVER_RULE_PREFIXES)
    }


def sample_key(sample: dict) -> str:
    """Stable identity for a sample."""
    return (sample.get("SHA256") or sample.get("MD5") or "").lower()


def load_snapshot(path: Path) -> set:
    """Load the set of sample keys seen on a previous run."""
    if not path.exists():
        return set()
    try:
        return set(json.loads(path.read_text()).get("seen", []))
    except (json.JSONDecodeError, OSError):
        return set()


def analyse(dataset: list, snapshot: set) -> dict:
    """Evaluate rule coverage and rank uncovered capability clusters."""
    initialize_rules(BlintOptions())

    rule_hits = Counter()
    total = 0
    new_keys = []
    undetected = []
    undetected_imports = Counter()

    for entry, sample in iter_samples(dataset):
        total += 1
        key = sample_key(sample)
        if key and key not in snapshot:
            new_keys.append(key)

        fired = evaluate_sample(build_metadata(sample))
        for rule_id in fired:
            rule_hits[rule_id] += 1

        if not fired:
            undetected.append(
                {
                    "sha256": sample.get("SHA256"),
                    "filename": sample.get("Filename") or sample.get("OriginalFilename"),
                    "category": entry.get("Category"),
                    "tags": entry.get("Tags"),
                }
            )
            for name in sample["ImportedFunctions"]:
                normalized = name.strip().lower().lstrip("_")
                if normalized not in UNINTERESTING_IMPORTS:
                    undetected_imports[normalized] += 1

    return {
        "samples_evaluated": total,
        "samples_new_since_snapshot": len(new_keys),
        "new_sample_keys": new_keys[:200],
        "rule_hits": [
            {"rule": rule, "samples": count, "percent": round(100 * count / total, 1)}
            for rule, count in rule_hits.most_common()
        ],
        "undetected_count": len(undetected),
        "undetected_percent": round(100 * len(undetected) / total, 1) if total else 0.0,
        "undetected_samples": undetected[:100],
        "candidate_imports": [
            {"import": name, "undetected_samples": count}
            for name, count in undetected_imports.most_common(60)
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=LOLDRIVERS_URL, help="dataset URL")
    parser.add_argument(
        "--dataset", type=Path, help="use a local dataset file instead of fetching"
    )
    parser.add_argument("--report", type=Path, help="write the JSON report here")
    parser.add_argument(
        "--update-snapshot",
        action="store_true",
        help="record the current sample set so later runs can report only what is new",
    )
    parser.add_argument("--snapshot", type=Path, default=SNAPSHOT_PATH)
    args = parser.parse_args()

    dataset = json.loads(args.dataset.read_text()) if args.dataset else fetch_dataset(args.url)
    snapshot = load_snapshot(args.snapshot)
    report = analyse(dataset, snapshot)

    print(f"samples evaluated:  {report['samples_evaluated']}")
    print(f"new since snapshot: {report['samples_new_since_snapshot']}")
    print(
        f"undetected:         {report['undetected_count']} "
        f"({report['undetected_percent']}%)"
    )
    print("rule hits:")
    for hit in report["rule_hits"]:
        print(f"  {hit['rule']}: {hit['samples']} ({hit['percent']}%)")
    if report["candidate_imports"]:
        print("top imports among undetected samples (candidate rule material):")
        for candidate in report["candidate_imports"][:15]:
            print(f"  {candidate['import']}: {candidate['undetected_samples']}")

    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2))
        print(f"report written to {args.report}")

    if args.update_snapshot:
        keys = sorted({sample_key(s) for _, s in iter_samples(dataset) if sample_key(s)})
        args.snapshot.parent.mkdir(parents=True, exist_ok=True)
        args.snapshot.write_text(json.dumps({"seen": keys}, indent=2))
        print(f"snapshot updated with {len(keys)} sample keys")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
