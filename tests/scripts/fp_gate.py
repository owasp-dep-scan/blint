#!/usr/bin/env python3
"""False-positive gate: findings counts per rule, severity and file, by format and architecture.

This is the F0 measurement instrument for the ELF/Mach-O false-positive lane
(and it covers the PE lane's corpus unchanged — the PE lane's fp_gate.sh was
never committed, so this is written new rather than extended). It is a
*measurement tool*, not a verdict gate: it always exits 0 (unless blint
itself fails to run), and the numbers it emits are the input to the
human-run classification in F0.2.

What it does:

1. Reads a corpus ``MANIFEST.json`` (same entry shape as the PE corpus:
   ``{path, tier, sha256, bytes, source, fetched}``), optionally filtered by
   ``--tier`` (repeatable). Defaults to tier0 — the benign tier.
2. Runs blint over exactly the manifest files' parent directories (default
   mode, no disassembly, ``-q --no-banner``) unless ``--reports`` points at a
   directory that already contains ``findings.json``.
3. Classifies every corpus file by format and architecture using ``file -b``
   (named external tool; its version is recorded in the output). file(1) is
   the grouper precisely because it is not blint.
4. Classifies every corpus file by format and architecture using ``file -b``
   (named external tool; its version is recorded in the output). file(1) is
   the grouper precisely because it is not blint.
5. Splits findings that only exist because a manifest entry is *derived* (a
   reconstruction from another artifact — dyld-cache extractions today) out of
   the headline, and reports them in their own section. Only rules whose
   answer extraction changes are excluded (``EXTRACTION_SENSITIVE_RULES`` —
   see its comment for the per-rule argument); findings the extraction cannot
   change stay in the headline even when they land on a derived file.
6. Emits, split by format and by architecture:
   - findings per rule;
   - findings per severity;
   - findings per file;
   - the median findings per file, over files with at least one finding and
     over all corpus files (both stated — the PE lane's historical medians
     are over files with findings);
   - findings whose ``filename`` does not map to any manifest entry (these
     are reported, not silently dropped: a blint run that analyzed files the
     manifest does not know about is a measurement bug).
7. Writes a JSON sidecar (``--out``, default ``<reports>/fp-gate.json``) so
   before/after deltas can be diffed mechanically, and prints the tables.

Usage:
    python tests/scripts/fp_gate.py --corpus ~/sandbox/fp-corpus
    python tests/scripts/fp_gate.py --corpus ~/sandbox/pe-corpus --tier tier0
"""

from __future__ import annotations

import argparse
import json
import os
import re
import statistics
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CORPUS = Path.home() / "sandbox" / "fp-corpus"
SEVERITY_ORDER = ["critical", "high", "medium", "low", "warning", "info"]

# Rules whose *answer* changes when the corpus file is a reconstruction from
# another artifact (manifest key ``derived``, e.g. "dyld-cache-extraction").
# A finding from one of these rules on a derived file is kept out of the
# headline and reported separately; findings from every other rule stay in the
# headline even on derived files.
#
# CHECK_CODESIGN is the only member, by elimination over the rules that fire
# on this corpus's derived files plus the ones that could:
# - codesign: the dyld shared cache signs the cache as a whole; `ipsw dyld
#   extract` writes each image with no LC_CODE_SIGNATURE at all, so every
#   extraction is unsigned *because of extraction* — while the same libraries
#   on disk (usr/lib) are signed and the rule is silent on them.
# - PIE: the MH_PIE flag is a Mach-O header bit carried verbatim through
#   extraction; the extracted image reports what the original had.
# - UNUSED_DEPENDENCIES: LC_LOAD_DYLIB commands are reconstructed from the
#   cache's own metadata; otool -L of an extraction reads the dependency set
#   the original declared.
# - OBJC_LOAD_METHODS / CANARY: __objc_nlclslist and the symbol tables are
#   image content, not signature content, and survive extraction.
# - every ELF rule: derived files here are Mach-O only.
EXTRACTION_SENSITIVE_RULES = frozenset({"CHECK_CODESIGN"})


def run_blint(corpus_root: Path, reports_dir: Path, input_dirs: list[str]) -> None:
    reports_dir.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable,
        "-m",
        "blint.cli",
        "-q",
        "--no-banner",
        "-i",
        *input_dirs,
        "-o",
        str(reports_dir),
    ]
    print(f"[run] {' '.join(command[:2])} ... ({len(input_dirs)} input dirs)")
    completed = subprocess.run(command, cwd=str(REPO_ROOT), capture_output=True, text=True)
    if completed.returncode != 0:
        sys.stderr.write(completed.stdout[-2000:] + completed.stderr[-2000:])
        raise SystemExit(f"blint failed with exit code {completed.returncode}")


def load_manifest(corpus_root: Path, tiers: list[str]) -> list[dict]:
    manifest_path = corpus_root / "MANIFEST.json"
    entries = json.loads(manifest_path.read_text(encoding="utf-8"))
    if tiers:
        entries = [entry for entry in entries if entry.get("tier") in tiers]
    if not entries:
        raise SystemExit(f"No manifest entries selected from {manifest_path}")
    return entries


def file_version() -> str:
    completed = subprocess.run(["file", "--version"], capture_output=True, text=True)
    return completed.stdout.splitlines()[0].strip() if completed.stdout else "file (unknown)"


FILE_PATTERNS = [
    # (format, arch, kind) resolved from `file -b` output.
    (re.compile(r"^ELF \d+-bit .* (?:x86-64|x86_64)"), "ELF", "x86_64"),
    (re.compile(r"^ELF \d+-bit .* (?:ARM aarch64|AArch64|aarch64)"), "ELF", "aarch64"),
    (re.compile(r"^ELF \d+-bit .* (?:ARM|EABI5?)\b"), "ELF", "arm"),
    (re.compile(r"^ELF \d+-bit .* MIPS"), "ELF", "mips"),
    (re.compile(r"^ELF \d+-bit .* RISC-V"), "ELF", "riscv64"),
    (re.compile(r"^ELF \d+-bit .* ppc"), "ELF", "ppc"),
    (re.compile(r"^ELF \d+-bit .* s390"), "ELF", "s390x"),
    (re.compile(r"^ELF "), "ELF", "unknown"),
    (re.compile(r"^Mach-O .* arm64e"), "Mach-O", "arm64e"),
    (re.compile(r"^Mach-O .* arm64"), "Mach-O", "arm64"),
    (re.compile(r"^Mach-O .* x86_64"), "Mach-O", "x86_64"),
    (re.compile(r"^Mach-O universal"), "Mach-O", "universal"),
    (re.compile(r"^Mach-O "), "Mach-O", "unknown"),
    (re.compile(r"^PE32\+ .* x86-64"), "PE", "x86_64"),
    (re.compile(r"^PE32\+ .* ARM64"), "PE", "arm64"),
    (re.compile(r"^PE32 .* 80386"), "PE", "x86"),
    (re.compile(r"^PE32 .* ARM"), "PE", "arm"),
    (re.compile(r"^PE32\+ "), "PE", "x86_64"),
    (re.compile(r"^PE32 "), "PE", "x86"),
    (re.compile(r"^(WebAssembly|wasm) "), "WASM", "wasm32"),
]


def classify_file_output(description: str) -> tuple[str, str]:
    for pattern, fmt, arch in FILE_PATTERNS:
        if pattern.search(description):
            return fmt, arch
    return "other", "unknown"


def classify_corpus(
    corpus_root: Path, entries: list[dict], cache_path: Path
) -> tuple[dict[str, tuple[str, str]], str]:
    """Run `file -b` over every corpus file, cached by manifest sha256."""
    cache: dict[str, list[str]] = {}
    if cache_path.exists():
        cache = json.loads(cache_path.read_text(encoding="utf-8"))
    descriptions: dict[str, list[str]] = {}
    missing = [
        entry
        for entry in entries
        if entry["sha256"] not in cache or not os.path.exists(corpus_root / entry["path"])
    ]
    if missing:
        for entry in missing:
            path = corpus_root / entry["path"]
            if not path.exists():
                descriptions[entry["sha256"]] = ["<missing>"]
                continue
            completed = subprocess.run(
                ["file", "-b", str(path)], capture_output=True, text=True
            )
            descriptions[entry["sha256"]] = [completed.stdout.strip()]
        cache.update(descriptions)
        cache_path.write_text(json.dumps(cache, indent=1, sort_keys=True), encoding="utf-8")
    resolved: dict[str, tuple[str, str]] = {}
    for entry in entries:
        description = cache.get(entry["sha256"], ["<missing>"])[0]
        resolved[entry["path"]] = classify_file_output(description)
    return resolved, file_version()


def map_findings_to_entries(
    findings: list[dict], entries: list[dict], corpus_root: Path
) -> tuple[list[tuple[dict, dict]], list[str]]:
    """Map each finding's absolute filename back to its manifest entry."""
    by_realpath: dict[str, dict] = {}
    for entry in entries:
        by_realpath[os.path.realpath(corpus_root / entry["path"])] = entry
    unmatched: list[str] = []
    pairs: list[tuple[dict, dict]] = []
    for finding in findings:
        filename = finding.get("filename") or ""
        entry = by_realpath.get(os.path.realpath(filename))
        if entry is None:
            unmatched.append(filename)
            continue
        pairs.append((finding, entry))
    return pairs, unmatched


def median_or_zero(values: list[int]) -> float:
    return statistics.median(values) if values else 0.0


def build_report(
    entries: list[dict],
    classifications: dict[str, tuple[str, str]],
    pairs: list[tuple[dict, dict]],
    unmatched: list[str],
    file_tool: str,
) -> dict:
    derived_paths = {entry["path"] for entry in entries if entry.get("derived")}
    # Headline keeps every finding except those an artifact derivation is
    # solely responsible for: an extraction-sensitive rule firing on a
    # derived file. Everything else — including other rules on the same
    # derived files — stays, so the headline only loses what the derivation,
    # not the binary, caused.
    headline_pairs: list[tuple[dict, dict]] = []
    excluded_pairs: list[tuple[dict, dict]] = []
    for finding, entry in pairs:
        if entry["path"] in derived_paths and str(finding.get("id")) in EXTRACTION_SENSITIVE_RULES:
            excluded_pairs.append((finding, entry))
        else:
            headline_pairs.append((finding, entry))
    per_file: Counter = Counter()
    rule_by_format: dict[str, Counter] = defaultdict(Counter)
    rule_by_arch: dict[str, Counter] = defaultdict(Counter)
    severity_by_format: dict[str, Counter] = defaultdict(Counter)
    rule_totals: Counter = Counter()
    for finding, entry in headline_pairs:
        fmt, arch = classifications[entry["path"]]
        rule = str(finding.get("id") or "UNKNOWN")
        per_file[entry["path"]] += 1
        rule_by_format[fmt][rule] += 1
        rule_by_arch[arch][rule] += 1
        severity_by_format[fmt][str(finding.get("severity") or "unknown")] += 1
        rule_totals[rule] += 1
    files_by_format: Counter = Counter()
    files_by_arch: Counter = Counter()
    for entry in entries:
        fmt, arch = classifications[entry["path"]]
        files_by_format[fmt] += 1
        files_by_arch[arch] += 1
    derived_rules: Counter = Counter()
    derived_files_by_format: Counter = Counter()
    for entry in entries:
        if entry["path"] in derived_paths:
            fmt, _ = classifications[entry["path"]]
            derived_files_by_format[fmt] += 1
    for finding, entry in pairs:
        if entry["path"] in derived_paths:
            derived_rules[str(finding.get("id") or "UNKNOWN")] += 1
    counts_with_findings = [count for count in per_file.values()]
    counts_all = [per_file.get(entry["path"], 0) for entry in entries]
    return {
        "tool": {
            "file": file_tool,
            "corpus_files": len(entries),
            "findings": len(headline_pairs),
            "excluded_derived_findings": len(excluded_pairs),
            "unmatched_findings": len(unmatched),
            "unmatched_examples": sorted(set(unmatched))[:10],
        },
        "derived": {
            "files": len(derived_paths),
            "files_by_format": dict(sorted(derived_files_by_format.items())),
            "kinds": dict(
                sorted(Counter(e["derived"] for e in entries if e.get("derived")).items())
            ),
            "findings_per_rule": dict(sorted(derived_rules.items())),
            "excluded_from_headline": len(excluded_pairs),
            "excluded_rules": sorted(EXTRACTION_SENSITIVE_RULES),
        },
        "corpus_files_by_format": dict(sorted(files_by_format.items())),
        "corpus_files_by_arch": dict(sorted(files_by_arch.items())),
        "findings_per_rule": dict(sorted(rule_totals.items())),
        "findings_per_rule_by_format": {
            fmt: dict(sorted(counter.items())) for fmt, counter in sorted(rule_by_format.items())
        },
        "findings_per_rule_by_arch": {
            arch: dict(sorted(counter.items())) for arch, counter in sorted(rule_by_arch.items())
        },
        "findings_per_severity_by_format": {
            fmt: {
                sev: counter.get(sev, 0)
                for sev in SEVERITY_ORDER + sorted(set(counter) - set(SEVERITY_ORDER))
                if counter.get(sev, 0)
            }
            for fmt, counter in sorted(severity_by_format.items())
        },
        "median_findings_per_file_with_findings": median_or_zero(counts_with_findings),
        "median_findings_per_file_all_files": median_or_zero(counts_all),
        "files_with_findings": len(counts_with_findings),
        "findings_per_file": {
            "median": median_or_zero(counts_all),
            "with_findings_median": median_or_zero(counts_with_findings),
            "zero_files": sum(1 for count in counts_all if count == 0),
            "max": max(counts_all) if counts_all else 0,
        },
        "per_file": dict(sorted(per_file.items())),
    }


def print_report(report: dict) -> None:
    tool = report["tool"]
    derived = report["derived"]
    print(f"\ncorpus files: {tool['corpus_files']}  findings: {tool['findings']}")
    print(f"file(1): {tool['file']}")
    if derived["files"]:
        print(
            f"derived files: {derived['files']} {derived['kinds']} — "
            f"{derived['excluded_from_headline']} findings from "
            f"{', '.join(derived['excluded_rules'])} excluded from the headline above; "
            "findings on derived files by rule: "
            f"{derived['findings_per_rule']}"
        )
    if tool["unmatched_findings"]:
        print(
            f"WARNING: {tool['unmatched_findings']} findings did not map to manifest entries"
        )
        for example in tool["unmatched_examples"]:
            print(f"  e.g. {example}")
    print("\nfiles by format:", report["corpus_files_by_format"])
    print("files by arch:  ", report["corpus_files_by_arch"])
    print(
        "\nmedian findings/file (files with findings): "
        f"{report['median_findings_per_file_with_findings']}  "
        f"over {report['files_with_findings']} files"
    )
    print(
        f"median findings/file (all corpus files):     "
        f"{report['median_findings_per_file_all_files']}  "
        f"({report['findings_per_file']['zero_files']} files with zero findings)"
    )
    print("\nfindings per rule (total | by format):")
    for rule, total in report["findings_per_rule"].items():
        by_format = {
            fmt: counter[rule]
            for fmt, counter in report["findings_per_rule_by_format"].items()
            if counter.get(rule)
        }
        print(f"  {rule:<42} {total:>5}  {by_format}")
    print("\nfindings per severity by format:")
    for fmt, severities in report["findings_per_severity_by_format"].items():
        print(f"  {fmt:<8} {severities}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    parser.add_argument("--tier", action="append", default=None)
    parser.add_argument(
        "--reports",
        help="Reports directory. Reused if it already contains findings.json, else blint runs.",
    )
    parser.add_argument("--out", help="JSON output path (default <reports>/fp-gate.json).")
    parser.add_argument(
        "--force-run", action="store_true", help="Run blint even if findings.json exists."
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    corpus_root = Path(args.corpus).expanduser().resolve()
    entries = load_manifest(corpus_root, args.tier or ["tier0"])
    parent_dirs = {str((corpus_root / entry["path"]).parent) for entry in entries}
    # Only the top-most parent directories are passed to blint: a nested
    # directory (tier0-reference/python-amd64 inside tier0-reference) walked
    # again as its own -i input would analyze those files twice and double
    # every per-file count.
    input_dirs = sorted(
        d for d in parent_dirs if not any(o != d and d.startswith(o + os.sep) for o in parent_dirs)
    )
    reports_dir = Path(args.reports).expanduser() if args.reports else corpus_root / "reports"
    findings_file = reports_dir / "findings.json"
    if args.force_run or not findings_file.exists():
        run_blint(corpus_root, reports_dir, input_dirs)
    findings = json.loads(findings_file.read_text(encoding="utf-8")).get("findings") or []
    classifications, file_tool = classify_corpus(
        corpus_root, entries, reports_dir / "fp-gate-file-cache.json"
    )
    pairs, unmatched = map_findings_to_entries(findings, entries, corpus_root)
    report = build_report(entries, classifications, pairs, unmatched, file_tool)
    out_path = Path(args.out).expanduser() if args.out else reports_dir / "fp-gate.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print_report(report)
    print(f"\nwrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
