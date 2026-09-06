#!/usr/bin/env python3
"""Wall-clock and peak-RSS curve for ``--jobs N`` (P3.2 gate 5).

Runs the real blint CLI over a corpus at several ``--jobs`` values and
reports, per value:

- wall clock for the whole run;
- peak RSS of the whole blint process tree (parent + workers), sampled
  every 100 ms by walking the PID tree under the launched process.

Memory is the real ceiling for a process pool: every spawn-started worker
pays for its own LIEF, nyxstone LLVM contexts and module-level caches. The
curve is reported as measured — including where more workers stop helping —
so a recommended N can be an honest recommendation rather than marketing.

Usage:
    python tests/scripts/jobs_bench.py [--dir corpus-build] [--jobs 1,2,4,8]
        [--disassemble] [--repeat N]
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BLINT_BIN = REPO_ROOT / ".venv" / "bin" / "blint"


def _process_tree_rss(root_pid: int) -> int:
    """Total RSS (KB) of the process tree rooted at root_pid, via ps."""
    rows = subprocess.run(
        ["ps", "-axo", "pid=,ppid=,rss="], capture_output=True, text=True
    ).stdout.splitlines()
    parent_of: dict[int, int] = {}
    rss_of: dict[int, int] = {}
    for row in rows:
        parts = row.split()
        if len(parts) != 3:
            continue
        pid, ppid, rss = (int(part) for part in parts)
        parent_of[pid] = ppid
        rss_of[pid] = rss
    total = 0
    stack = [root_pid]
    seen: set[int] = set()
    while stack:
        pid = stack.pop()
        if pid in seen:
            continue
        seen.add(pid)
        total += rss_of.get(pid, 0)
        stack.extend(child for child, ppid in parent_of.items() if ppid == pid)
    return total


def run_once(corpus: Path, jobs: int, disassemble: bool, repeat: int) -> dict:
    walls = []
    peaks = []
    for _ in range(repeat):
        args = [str(BLINT_BIN), "-q", "--no-banner", "-i", str(corpus)]
        if disassemble:
            args.append("--disassemble")
        args += ["--jobs", str(jobs)]
        env = dict(os.environ)
        env["SCAN_ID"] = f"jobs-bench-{jobs}"
        started = time.time()
        proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
        peak = 0
        while proc.poll() is None:
            peak = max(peak, _process_tree_rss(proc.pid))
            time.sleep(0.1)
        wall = time.time() - started
        if proc.returncode != 0:
            raise SystemExit(f"blint --jobs {jobs} failed with {proc.returncode}")
        walls.append(wall)
        peaks.append(peak)
    return {
        "jobs": jobs,
        "wall_s": min(walls),
        "peak_rss_mb": max(peaks) / 1024,
        "walls": walls,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dir", type=Path, default=REPO_ROOT / "corpus-build")
    parser.add_argument("--jobs", type=str, default="1,2,4,8")
    parser.add_argument("--disassemble", action="store_true", default=True)
    parser.add_argument("--no-disassemble", dest="disassemble", action="store_false")
    parser.add_argument("--repeat", type=int, default=1)
    args = parser.parse_args()
    corpus = args.dir.resolve()
    if not corpus.exists():
        raise SystemExit(f"corpus not found at {corpus}; run tests/scripts/build_corpus.py")
    jobs_values = [int(j) for j in args.jobs.split(",") if j.strip()]
    print(f"corpus={corpus} disassemble={args.disassemble} repeat={args.repeat}")
    print(f"{'jobs':>5} {'wall_s':>8} {'peak_tree_rss_mb':>18}")
    results = []
    for jobs in jobs_values:
        result = run_once(corpus, jobs, args.disassemble, args.repeat)
        results.append(result)
        print(f"{result['jobs']:>5} {result['wall_s']:>8.1f} {result['peak_rss_mb']:>18.0f}")
    base = results[0]
    for result in results[1:]:
        speedup = base["wall_s"] / result["wall_s"] if result["wall_s"] else 0
        print(
            f"jobs={result['jobs']}: {speedup:.2f}x vs jobs=1, "
            f"peak RSS {result['peak_rss_mb']:.0f} MB vs {base['peak_rss_mb']:.0f} MB"
        )


if __name__ == "__main__":
    main()
