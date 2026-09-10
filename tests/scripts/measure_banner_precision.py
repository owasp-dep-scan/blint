#!/usr/bin/env python3
# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT
"""Measure vendored-banner detection precision (P4.3 gate 6).

Banner precision is measured separately from hash matching because a banner
is a strong claim about a version and easy to misread from an unrelated
string. The measurement runs the detection over a set of binaries with
externally derived ground truth: every expected hit is independently
confirmed against the raw bytes with ``strings | grep`` (the extraction
pipeline must not be the judge of its own signal), and every unexpected hit
is reported as a false positive.

Ground truth comes from --truth (JSON: binary name -> {library: version})
and defaults to the static-linkage corpus apps, whose composition the corpus
builder fixes. Binaries without an entry must produce no hits at all.

Usage:

    python tests/scripts/measure_banner_precision.py --corpus-dir .tmp-static-linkage
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from blint.lib.banners import BANNER_SIGNATURES, detect_vendored_banners
from blint.lib.binary import parse

# The corpus builder fixes this composition; the same facts confirmed with
# `strings` are recorded here as externally derived ground truth.
DEFAULT_TRUTH = {
    "app-zlib-lua": {"zlib": "1.3.1", "lua": "5.4.6"},
    "app-cjson-sqlite": {},
    "app-miniz": {},
    "app-zlib-miniz": {"zlib": "1.3.1"},
}


def raw_strings(binary: Path) -> set[str]:
    """The strings `strings(1)` finds, as externally derived evidence."""
    result = subprocess.run(
        ["strings", str(binary)], capture_output=True, text=True, timeout=120, check=False
    )
    if result.returncode != 0:
        return set()
    return set(result.stdout.splitlines())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", default=str(REPO_ROOT / ".tmp-static-linkage"))
    parser.add_argument("--truth", help="JSON file: binary name -> {library: version}.")
    args = parser.parse_args()
    corpus = Path(args.corpus_dir).resolve()
    truth = dict(DEFAULT_TRUTH)
    if args.truth:
        truth.update(json.loads(Path(args.truth).read_text()))

    binaries = sorted(
        p
        for directory in (corpus / "apps", REPO_ROOT / "corpus-build")
        if directory.is_dir()
        for p in directory.iterdir()
        if p.is_file()
        and not p.name.startswith(("gt-", "main", "whyl"))
        and not p.name.endswith((".json", ".txt", ".log", ".c"))
    )

    hits_total = hits_correct = 0
    misses = []
    false_positives = []
    for binary in binaries:
        try:
            metadata = parse(str(binary))
        except Exception as error:  # noqa: BLE001
            print(f"SKIP {binary.name}: {error}")
            continue
        detected = {(b["library"], b["version"]): b for b in detect_vendored_banners(metadata)["banners"]}
        expected = truth.get(binary.name, {})
        for (library, version) in detected:
            hits_total += 1
            if expected.get(library) == version:
                hits_correct += 1
                # Externally derived confirmation: the matched banner text
                # must also be visible to strings(1) on the raw file.
                banner_text = detected[(library, version)]["banner"]
                visible = any(banner_text.strip() in line for line in raw_strings(binary))
                if not visible:
                    print(f"UNCONFIRMED {binary.name}: {library} {version} banner not visible to strings(1)")
            else:
                false_positives.append((binary.name, library, version))
        for library, version in expected.items():
            if (library, version) not in detected:
                misses.append((binary.name, library, version))

    print(f"== banner precision over {len(binaries)} binaries")
    print(f"   hits: {hits_correct}/{hits_total} correct")
    if false_positives:
        print(f"   FALSE positives: {false_positives}")
    if misses:
        print(f"   expected-but-missed (recall gaps): {misses}")
    print(f"   signatures: {len(BANNER_SIGNATURES)} active")


if __name__ == "__main__":
    main()
