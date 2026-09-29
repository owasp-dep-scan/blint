#!/usr/bin/env python3
"""A7 K3 — the R3 sweep: the six rules over tier 0 (all images) and the
tier-2/3 APKs, through the APK member review path.

Tier 0 runs the same pipeline the member path runs (parse with
``--disassemble``, then :class:`ReviewRunner`) over every unique-by-sha256
``.so`` of all four system images at once — a library whose bytes appear in
several images is analyzed once and credited to each. Tiers 2+3 run the
real thing: ``run_default_mode`` per APK with disassembly on, reading the
exported ``Reviews.json`` back, so the findings crossed the production
member-review path, not a parallel one.

Output (``a7-r3-sweep.json`` beside this script) records, per rule id: the
fire counts, every finding with its file/function/evidence (the
hand-check list), how many libraries carry each call-site coverage
degradation (``callsite_abi_not_modelled``, ``callsite_entries_truncated``:
coverage facts, not findings), and the tier-0 median rules fired per
library — the K0 baseline comparison.

Usage:
  python tests/scripts/android/a7_r3_sweep.py [--limit N] [--no-apps]
      [--only-apk name.apk] [--out file.json]
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from blint.config import BlintOptions
from blint.lib.analysis import initialize_rules
from blint.lib.binary import parse
from blint.lib.review_runner import ReviewRunner

CORPUS = Path.home() / "sandbox" / "android-corpus"
TIER0_ROOT = CORPUS / "tier0-system"
IMAGES = ("api34-arm64-v8a", "api35-arm64-v8a", "api36-arm64", "api36-arm64-v8a")
APP_DIRS = ("tier2-fdroid", "tier3-frameworks", "tier3-builds")

CALLSITE_GAPS = ("callsite_abi_not_modelled", "callsite_entries_truncated")

EVIDENCE_FIELDS = (
    "callee",
    "via",
    "path",
    "property",
    "request",
    "request_name",
    "site_count",
    "site_total",
    "function_count",
    "function",
    "functions",
    "su_path_strings",
    "bound_native_declarations",
)


def tier0_unique_files() -> list[dict]:
    """Every unique .so across all four images, credited to each image."""
    by_digest: dict[str, dict] = {}
    for image in IMAGES:
        manifest_path = TIER0_ROOT / image / "MANIFEST.json"
        if not manifest_path.is_file():
            print(f"skip missing image manifest {image}", file=sys.stderr)
            continue
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        for entry in manifest.get("entries", []):
            name = entry.get("file", "")
            if not name.endswith(".so"):
                continue
            digest = entry["sha256"]
            record = by_digest.setdefault(
                digest,
                {
                    "path": str(TIER0_ROOT / image / name),
                    "sha256": digest,
                    "member": name,
                    "images": [],
                },
            )
            if image not in record["images"]:
                record["images"].append(image)
    return sorted(by_digest.values(), key=lambda item: item["member"])


def review_android_rules(metadata: dict) -> dict[str, list[dict]]:
    runner = ReviewRunner()
    runner.run_review(metadata)
    return {key: value for key, value in runner.results.items() if key.startswith("ANDROID_")}


def count_callsite_gaps(metadata: dict, buckets: dict) -> None:
    for reason in (metadata.get("analysis_coverage") or {}).get("degradations") or []:
        if reason in CALLSITE_GAPS:
            bucket = buckets.setdefault("call_site_rules", {})
            bucket[reason] = bucket.get(reason, 0) + 1


def sweep_tier0(limit: int, shard_index: int = 0, shard_count: int = 1) -> dict:
    files = tier0_unique_files()
    if limit:
        files = files[:limit]
    if shard_count > 1:
        files = files[shard_index::shard_count]
    per_rule: dict[str, list] = {}
    not_evaluated: dict[str, dict] = {}
    rules_per_library: list[int] = []
    started = time.monotonic()
    for index, item in enumerate(files):
        metadata = parse(item["path"], True)
        if metadata.get("binary_type") != "ELF":
            continue
        results = review_android_rules(metadata)
        count_callsite_gaps(metadata, not_evaluated)
        for rule_id, entries in sorted(results.items()):
            for entry in entries:
                per_rule.setdefault(rule_id, []).append(
                    {
                        "file": item["member"],
                        "images": item["images"],
                        **{field: entry.get(field) for field in EVIDENCE_FIELDS},
                    }
                )
        rules_per_library.append(len(results))
        if index % 100 == 0:
            elapsed = time.monotonic() - started
            print(f"tier0 {index}/{len(files)} ({elapsed:.0f}s)", flush=True)
    rules_per_library.sort()
    count = len(rules_per_library)
    return {
        "libraries": count,
        "per_rule": {
            rule: {"fires": len(findings), "findings": findings}
            for rule, findings in sorted(per_rule.items())
        },
        "not_evaluated_notes": not_evaluated,
        "median_rules_per_library": rules_per_library[count // 2] if count else 0,
        "mean_rules_per_library": round(sum(rules_per_library) / count, 3) if count else 0,
        "libraries_with_zero_rules": rules_per_library.count(0),
        "wall_time_s": round(time.monotonic() - started, 1),
    }


def sweep_apps(only_apk: str | None, no_apps: bool) -> dict:
    from blint.lib.runners import run_default_mode

    per_rule: dict[str, list] = {}
    app_notes: dict[str, dict] = {}
    wall_start = time.monotonic()
    apk_files: list[Path] = []
    if not no_apps:
        for rel in APP_DIRS:
            app_dir = CORPUS / rel
            if app_dir.is_dir():
                apk_files.extend(sorted(app_dir.glob("*.apk")))
    if only_apk:
        apk_files = [apk for apk in apk_files if apk.name == only_apk]
    for apk in apk_files:
        started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="a7_r3_app_") as tmp:
            options = BlintOptions(
                src_dir_image=[str(apk)],
                reports_dir=tmp,
                disassemble=True,
                quiet_mode=True,
            )
            try:
                run_default_mode(options)
            except Exception as exc:  # a failed app must not abort the sweep
                per_rule.setdefault("_failed_apps", []).append(
                    {"file": apk.name, "error": str(exc)}
                )
                continue
            reviews_path = Path(tmp) / "Reviews.json"
            if not reviews_path.is_file():
                continue
            reviews = json.loads(reviews_path.read_text(encoding="utf-8"))
            for review in reviews.get("reviews", []):
                rule_id = review.get("id")
                if not str(rule_id).startswith("ANDROID_"):
                    continue
                for entry in review.get("evidence") or []:
                    per_rule.setdefault(rule_id, []).append(
                        {
                            "file": review.get("filename") or review.get("exe_name"),
                            **{field: entry.get(field) for field in EVIDENCE_FIELDS},
                        }
                    )
            for member in Path(tmp).glob("*.so-metadata.json"):
                count_callsite_gaps(json.loads(member.read_text(encoding="utf-8")), app_notes)
        print(f"app {apk.name}: {time.monotonic() - started:.0f}s", flush=True)
    return {
        "apps": len(apk_files),
        "per_rule": {
            rule: {"fires": len(findings), "findings": findings}
            for rule, findings in sorted(per_rule.items())
        },
        "not_evaluated_notes": app_notes,
        "wall_time_s": round(time.monotonic() - wall_start, 1),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=0, help="cap tier-0 files (iteration aid)")
    parser.add_argument("--no-apps", action="store_true")
    parser.add_argument("--no-tier0", action="store_true")
    parser.add_argument("--only-apk", help="sweep only this APK name")
    parser.add_argument(
        "--shard-index", type=int, default=0, help="this shard's 0-based index"
    )
    parser.add_argument(
        "--shard-count", type=int, default=1, help="total shards (files[i::n] split)"
    )
    parser.add_argument("--out", default=None)
    args = parser.parse_args()
    initialize_rules(BlintOptions())
    result = {"tier0": None, "apps": None}
    if not args.no_tier0:
        result["tier0"] = sweep_tier0(args.limit, args.shard_index, args.shard_count)
    if not args.no_apps or args.only_apk:
        result["apps"] = sweep_apps(args.only_apk, args.no_apps)
    out = Path(args.out) if args.out else Path(__file__).parent / "a7-r3-sweep.json"
    out.write_text(json.dumps(result, indent=1, sort_keys=True), encoding="utf-8")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
