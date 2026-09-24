#!/usr/bin/env python3
"""A0.3 — baseline measurements of today's blint over the Android corpus.

Measures, per tier, against the blint checkout this script is run from:

  sbom        tier-2 apps: SBOM components per app and how many use a
              build-id (hex string) where a version belongs (V4).
  standalone  tier-0/tier-1: findings when each .so is scanned standalone,
              per rule and per ABI, with the median findings per file.
  functions   --disassemble functions_total per ABI over tier-1
              symbolised builds, against the symbol count (the
              armeabi-v7a shortfall is stated, not guessed).

Requires NYXSTONE_LLVM_PREFIX + LLVM 18 on PATH for the functions phase
(a run without it silently disassembles nothing and every count reads 0).
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
BLINT = [str(REPO / ".venv" / "bin" / "blint")]

HEX_VERSION = re.compile(r"^[0-9a-fA-F]{16,64}$")


def run_blint(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(BLINT + args, capture_output=True, text=True, cwd=REPO)


def phase_sbom(corpus: Path) -> dict:
    out: dict = {"apps": []}
    tier2 = sorted((corpus / "tier2-fdroid").glob("*.apk"))
    with tempfile.TemporaryDirectory() as td:
        for apk in tier2:
            out_json = Path(td) / f"{apk.stem}.json"
            proc = subprocess.run(
                BLINT + ["sbom", "-i", str(apk), "-o", str(out_json), "-q"],
                capture_output=True, text=True, cwd=REPO,
            )
            if proc.returncode != 0 or not out_json.exists():
                out["apps"].append({"app": apk.name, "error": proc.stderr[-400:]})
                continue
            bom = json.loads(out_json.read_text())
            components = bom.get("components") or []
            [
                c for c in components
                if (c.get("type") == "application" and str(c.get("purl", "")).startswith("pkg:android/"))
            ]
            so_components = [
                c for c in components
                if str(c.get("purl", "")).startswith("pkg:android/") and c.get("type") == "library"
            ]
            build_id_versions = [c for c in so_components if HEX_VERSION.match(str(c.get("version") or ""))]
            out["apps"].append({
                "app": apk.name,
                "components_total": len(components),
                "so_components": len(so_components),
                "so_build_id_versions": len(build_id_versions),
                "purl_samples": [c.get("purl") for c in so_components[:3]],
            })
    totals = [a for a in out["apps"] if "error" not in a]
    out["summary"] = {
        "apps": len(totals),
        "so_components": sum(a["so_components"] for a in totals),
        "so_build_id_versions": sum(a["so_build_id_versions"] for a in totals),
    }
    return out


def _group_dirs(corpus: Path) -> dict[str, list[Path]]:
    """Map a (tier, abi) group label to directories of .so files."""
    groups: dict[str, list[Path]] = defaultdict(list)
    t0 = corpus / "tier0-system"
    if t0.exists():
        for d in sorted(t0.iterdir()):
            if d.is_dir():
                groups[f"tier0/{d.name}"].append(d)
    t1 = corpus / "tier1-ndk"
    if t1.exists():
        for ndk in sorted(t1.iterdir()):
            if ndk.is_dir() and ndk.name not in ("apks", "MANIFEST.json"):
                for abi in sorted(ndk.iterdir()):
                    if abi.is_dir():
                        groups[f"tier1/{ndk.name}/{abi.name}"].append(abi)
    return groups


def phase_standalone(corpus: Path) -> dict:
    out: dict = {"groups": {}}
    with tempfile.TemporaryDirectory() as td:
        for label, dirs in _group_dirs(corpus).items():
            # Only .so files; other ELFs (static exes) are not in scope here.
            so_files = [so for d in dirs for so in sorted(d.rglob("*.so"))]
            if not so_files:
                continue
            staging = Path(td) / re.sub(r"[^0-9a-zA-Z_.-]", "_", label)
            staging.mkdir(parents=True, exist_ok=True)
            for i, so in enumerate(so_files):
                (staging / f"{so.stem}__{i}{so.suffix}").symlink_to(so)
            reports = Path(td) / (staging.name + "-reports")
            proc = run_blint([
                "-q", "--no-banner", "--no-reviews",
                "-i", str(staging), "-o", str(reports),
            ])
            findings = []
            ffile = next(reports.glob("*findings*.json"), None)
            if ffile:
                try:
                    findings = json.loads(ffile.read_text()).get("findings", [])
                except ValueError:
                    findings = []
            per_rule = Counter(f.get("id") for f in findings)
            per_file = Counter(
                Path(f.get("filename", "")).name.rsplit("__", 1)[0] + ".so"
                for f in findings
            )
            counts = sorted(per_file.values())
            median = counts[len(counts) // 2] if counts else 0
            scanned = len(so_files)
            with_findings = len({f.get("filename") for f in findings})
            out["groups"][label] = {
                "scanned": scanned,
                "files_with_findings": with_findings,
                "findings_total": len(findings),
                "median_per_file": median,
                "per_rule": dict(sorted(per_rule.items())),
            }
            if proc.returncode != 0:
                out["groups"][label]["error"] = proc.stderr[-300:]
    return out


def phase_functions(corpus: Path) -> dict:
    sys.path.insert(0, str(REPO))
    from blint.lib.binary import parse

    out: dict = {"groups": {}}
    t1 = corpus / "tier1-ndk"
    if not t1.exists():
        return out
    for ndk in sorted(t1.iterdir()):
        if not ndk.is_dir() or ndk.name in ("apks",):
            continue
        for abi in sorted(ndk.iterdir()):
            if not abi.is_dir():
                continue
            # The unstripped builds (obj/local copies) are the symbolised
            # builds the armeabi-v7a shortfall is measured against.
            for sub, label in ((abi, ""), (abi / "unstripped", "/unstripped")):
                if not sub.is_dir():
                    continue
                per_file = []
                for so in sorted(sub.glob("*.so")):
                    metadata = parse(str(so), True)
                    functions = metadata.get("functions") or []
                    symtab = metadata.get("symtab_symbols") or []
                    dynamic = metadata.get("dynamic_symbols") or []
                    per_file.append({
                        "file": so.name,
                        "functions_total": len(functions),
                        "symtab_symbols": len(symtab),
                        # The shortfall denominator: actual FUNC symbols in
                        # .symtab, per llvm-readelf --dyn-syms/--syms FUNC rows.
                        "symtab_functions": sum(
                            1 for sym in symtab if sym.get("is_function")
                        ),
                        "dynamic_symbols": len(dynamic),
                        "disassembled": sum(
                            1 for f in functions if f.get("instructions") or f.get("instruction_count")
                        ),
                    })
                if per_file:
                    out["groups"][f"{ndk.name}/{abi.name}{label}"] = per_file
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=["sbom", "standalone", "functions", "all"])
    parser.add_argument("--corpus", default=str(Path.home() / "sandbox" / "android-corpus"))
    parser.add_argument("--out", default="a0-baseline-results.json")
    args = parser.parse_args()
    corpus = Path(args.corpus)
    results: dict = {}
    phases = ["sbom", "standalone", "functions"] if args.phase == "all" else [args.phase]
    if "sbom" in phases:
        results["sbom"] = phase_sbom(corpus)
    if "standalone" in phases:
        results["standalone"] = phase_standalone(corpus)
    if "functions" in phases:
        results["functions"] = phase_functions(corpus)
    Path(args.out).write_text(json.dumps(results, indent=1))
    print(f"written: {args.out}")


if __name__ == "__main__":
    main()
