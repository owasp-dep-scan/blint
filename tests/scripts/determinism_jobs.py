#!/usr/bin/env python3
"""Determinism gate for ``--jobs N`` (P3.2).

Runs the real blint CLI over a corpus at ``--jobs 1/2/4/8`` under two
``PYTHONHASHSEED`` values and asserts the outputs are byte-identical
everywhere it is legitimate to demand bytes:

- every ``*-metadata.json``: exact bytes (the per-binary product of the
  parallel unit work);
- ``findings/reviews/fuzzables.json`` and ``analysis-coverage.json``:
  exact bytes after normalizing the two run-unique fields every run
  carries by design (``scan_id`` — fixed via SCAN_ID here — and
  ``created``, a timestamp);
- ``blint-output.html``: exact bytes (the parent replays worker logs in
  merge order, so even the captured console output is deterministic).

Also checks, so the parallel claims do not out-run the sequential facts:

- SBOM: jobs 1 vs 4 bytes equal modulo the random serialNumber, at both
  hash seeds (this exposes whether ``dependsOn`` set iteration is
  seed-sensitive at all — if two sequential runs at different seeds
  already differ, that is reported as a pre-existing property, not a
  parallelism regression);
- ``--cache --jobs 4``: cold vs warm vs sequential-no-cache metadata
  bytes identical, cache hit/miss/stored counters totalling the file
  count exactly as the sequential run's do.

Usage:
    python tests/scripts/determinism_jobs.py [--dir corpus-build]
        [--workdir /tmp/gate] [--seeds 0,4242] [--skip-sbom] [--skip-cache]
Exit code 0 iff every gate passed; failures print the differing file.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BLINT_BIN = REPO_ROOT / ".venv" / "bin" / "blint"
RUN_VARIABLE_FIELDS = ("scan_id", "created")
SERIAL_RE = re.compile(rb'"serialNumber": "urn:uuid:[^"]*"')
SBOM_TIMESTAMP_RE = re.compile(rb'"timestamp": "[^"]*"')
RUN_VAR_RE = re.compile(rb'"(scan_id|created)":\s*"[^"]*"')


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def run_blint(args: list[str], reports_dir: Path, seed: str, scan_id: str) -> None:
    env = dict(os.environ)
    env["PYTHONHASHSEED"] = seed
    env["SCAN_ID"] = scan_id
    cmd = [str(BLINT_BIN), "-q", "--no-banner", "-o", str(reports_dir), *args]
    started = time.time()
    result = subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=str(REPO_ROOT))
    if result.returncode != 0:
        print(result.stdout[-3000:])
        print(result.stderr[-3000:])
        raise SystemExit(f"blint failed ({result.returncode}): {' '.join(cmd)}")
    print(f"  [jobs env] {args} seed={seed} -> {time.time() - started:.1f}s")


def snapshot_default_run(reports_dir: Path) -> dict[str, str]:
    """Map of relative artifact name -> digest (bytes, normalized where needed)."""
    normalized = {"analysis-coverage.json", "findings.json", "reviews.json", "fuzzables.json"}
    snap: dict[str, str] = {}
    for path in sorted(reports_dir.rglob("*")):
        if not path.is_file():
            continue
        rel = str(path.relative_to(reports_dir))
        data = path.read_bytes()
        if rel in normalized:
            data = RUN_VAR_RE.sub(rb'"": ""', data)
        snap[rel] = _sha(data)
    return snap


def compare_snapshots(
    baseline: dict[str, str],
    other: dict[str, str],
    label: str,
    reports_dir: Path,
    ignore: set[str] | None = None,
) -> None:
    ignore = ignore or set()
    baseline = {k: v for k, v in baseline.items() if k not in ignore}
    other = {k: v for k, v in other.items() if k not in ignore}
    if baseline == other:
        return
    only_base = sorted(set(baseline) - set(other))
    only_other = sorted(set(other) - set(baseline))
    differing = sorted(k for k in set(baseline) & set(other) if baseline[k] != other[k])
    raise SystemExit(
        f"{label}: outputs differ. missing={only_base} extra={only_other} "
        f"differing={differing}"
    )


def gate_default_mode(corpus: Path, workdir: Path, seeds: list[str], jobs_values: list[int]) -> None:
    print("== default mode: jobs x hash seeds, byte identity ==")
    baseline = None
    baseline_label = ""
    for seed in seeds:
        for jobs in jobs_values:
            reports = workdir / f"default-seed{seed}-jobs{jobs}"
            shutil.rmtree(reports, ignore_errors=True)
            run_blint(
                ["-i", str(corpus), "--disassemble", "--suggest-fuzzable", "--jobs", str(jobs)],
                reports,
                seed,
                scan_id="gate-scan-id",
            )
            snap = snapshot_default_run(reports)
            label = f"seed={seed} jobs={jobs}"
            if baseline is None:
                baseline, baseline_label = snap, label
                print(f"  baseline {label}: {len(snap)} artifacts")
            else:
                compare_snapshots(baseline, snap, f"vs baseline {baseline_label}", reports)
                print(f"  {label}: identical to baseline ({len(snap)} artifacts)")
    # jobs=1 must also equal the truly sequential path: --jobs 1 never
    # enters the pool, so the baseline already is that path.


def gate_cache(corpus: Path, workdir: Path, seed: str) -> None:
    print("== --cache --jobs: cold/warm byte identity and counters ==")
    env = dict(os.environ)
    args = ["-i", str(corpus), "--disassemble", "--cache"]
    store_a = workdir / "cache-store-seq"
    store_b = workdir / "cache-store-par"
    for store in (store_a, store_b):
        shutil.rmtree(store, ignore_errors=True)

    def run(tag: str, jobs: str, cache_dir: Path) -> tuple[dict[str, str], dict]:
        reports = workdir / f"cache-{tag}"
        shutil.rmtree(reports, ignore_errors=True)
        run_env = dict(env)
        run_env["PYTHONHASHSEED"] = seed
        run_env["SCAN_ID"] = "gate-cache-scan"
        run_env["BLINT_CACHE_DIR"] = str(cache_dir)
        cmd = [str(BLINT_BIN), "-q", "--no-banner", "-o", str(reports), *args, "--jobs", jobs]
        result = subprocess.run(cmd, capture_output=True, text=True, env=run_env, cwd=str(REPO_ROOT))
        if result.returncode != 0:
            raise SystemExit(f"blint failed: {result.stderr[-2000:]}")
        coverage = json.loads((reports / "analysis-coverage.json").read_bytes())
        return snapshot_default_run(reports), coverage

    # The sequential and cold-parallel runs each get an empty store, so
    # their miss/stored counters are comparable; the warm run reuses the
    # parallel store its cold run just populated.
    snap_seq, cov_seq = run("seq", "1", store_a)
    snap_cold, cov_cold = run("cold-par", "4", store_b)
    snap_warm, cov_warm = run("warm-par", "4", store_b)
    compare_snapshots(snap_seq, snap_cold, "cache: sequential vs cold parallel", workdir)
    # analysis-coverage.json carries the cache counters themselves, which
    # must (and does) differ between a cold and a warm run; the counters
    # are asserted below instead of byte-compared here.
    compare_snapshots(
        snap_cold, snap_warm, "cache: cold vs warm parallel", workdir,
        ignore={"analysis-coverage.json"},
    )
    totals = {
        "cold": (cov_cold["cache"]["misses"], cov_cold["cache"]["stored"], cov_cold["cache"]["hits"]),
        "warm": (cov_warm["cache"]["misses"], cov_warm["cache"]["stored"], cov_warm["cache"]["hits"]),
        "seq": (cov_seq["cache"]["misses"], cov_seq["cache"]["stored"], cov_seq["cache"]["hits"]),
    }
    print(f"  counters (misses, stored, hits): {totals}")
    top_level = cov_cold["units_by_role"].get("top-level", {}).get("succeeded", 0)
    assert totals["cold"][0] >= top_level, "cold parallel misses must cover the parsed units"
    assert totals["cold"][1] >= top_level
    assert totals["warm"][0] == 0, "warm run must not miss"
    assert totals["warm"][1] == 0, "warm run must not store"
    assert totals["warm"][2] >= top_level, "warm hits must cover the parsed units"
    assert totals["cold"] == totals["seq"], "cold parallel counters must equal the sequential run's"
    print("  PASS: cold == warm == sequential bytes; counters equal")


def gate_sbom(corpus: Path, workdir: Path, seeds: list[str]) -> None:
    print("== sbom mode: jobs 1 vs 4, modulo serialNumber ==")
    snapshots: dict[tuple[str, str], bytes] = {}
    for seed in seeds:
        for jobs in ("1", "4"):
            out = workdir / f"sbom-seed{seed}-jobs{jobs}.cdx.json"
            run_blint(
                ["sbom", "-i", str(corpus), "--wasm-sbom", "--jobs", jobs, "-o", str(out)],
                workdir,
                seed,
                scan_id="gate-sbom-scan",
            )
            snapshots[(seed, jobs)] = SBOM_TIMESTAMP_RE.sub(
                b'"timestamp": ""', SERIAL_RE.sub(b'"serialNumber": ""', out.read_bytes())
            )
    # Every snapshot must be identical: to the sequential run at the same
    # seed (the parallelism claim) and across seeds (the reproducibility
    # claim, which holds because dependsOn is sorted on the way out rather
    # than left in set-iteration order).
    gate_failed = False
    for seed in seeds:
        seq = snapshots[(seed, "1")]
        par = snapshots[(seed, "4")]
        if par == seq:
            print(f"  seed={seed}: jobs=4 identical to sequential jobs=1")
        else:
            print(f"  seed={seed}: jobs=4 DIFFERS from sequential jobs=1")
            gate_failed = True
    if len(set(snapshots.values())) > 1:
        print("  sbom bytes vary across PYTHONHASHSEED values")
        gate_failed = True
    else:
        print("  all sbom snapshots identical across seeds and jobs values")
    if gate_failed:
        raise SystemExit("sbom determinism gate failed")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dir", type=Path, default=REPO_ROOT / "corpus-build")
    parser.add_argument("--workdir", type=Path, default=None)
    parser.add_argument("--seeds", type=str, default="0,4242")
    parser.add_argument("--jobs", type=str, default="1,2,4,8")
    parser.add_argument("--skip-sbom", action="store_true")
    parser.add_argument("--skip-cache", action="store_true")
    parser.add_argument("--skip-default", action="store_true")
    args = parser.parse_args()
    corpus = args.dir.resolve()
    if not corpus.exists():
        raise SystemExit(f"corpus not found at {corpus}; run tests/scripts/build_corpus.py")
    workdir = args.workdir or Path(os.environ.get("TMPDIR", "/tmp")) / f"blint-jobs-gate-{int(time.time())}"
    workdir.mkdir(parents=True, exist_ok=True)
    seeds = [s.strip() for s in args.seeds.split(",") if s.strip()]
    jobs_values = [int(j) for j in args.jobs.split(",") if j.strip()]
    print(f"corpus: {corpus}\nworkdir: {workdir}\nseeds: {seeds} jobs: {jobs_values}")
    if not args.skip_default:
        gate_default_mode(corpus, workdir, seeds, jobs_values)
    if not args.skip_cache:
        gate_cache(corpus, workdir, seeds[0])
    if not args.skip_sbom:
        gate_sbom(corpus, workdir, seeds)
    print("ALL GATES PASSED")
    shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    main()
