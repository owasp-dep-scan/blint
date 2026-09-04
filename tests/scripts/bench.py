#!/usr/bin/env python3
"""Per-phase timing bench for blint's analysis pipeline (P0.2).

Answers the question that went unanswered when an unbounded per-function
hash accounted for 36% of /usr/bin/ssh's parse time: *which phase did my
change make slower?* Hand-instrumenting the module should not be needed to
see that.

Phases are measured by timing the real pipeline functions around a normal
``parse()`` call (no production code is modified):

- ``parse``          the whole blint.lib.binary.parse call (includes every
                     phase below except ``reviews``)
- ``discovery``      unwind/callsite/prologue function discovery
- ``disassembly``    nyxstone disassembly of the function worklist
- ``similarity``     per-function fuzzy/CFG hash attachment
- ``cfg``            callgraph + per-function block/edge construction
- ``stack_strings``  per-function stack-string recovery
- ``entropy``        section entropy + packing evidence
- ``strings``        string extraction
- ``reviews``        run_checks + ReviewRunner on the parsed metadata

Phases nest inside ``parse``; the unattributed remainder is visible as
``parse_other`` so a phase can never hide inside it.

Every artifact also reports the serialized metadata size and the largest
top-level blocks, because metadata is a budget (03/B.6): ssh's --disassemble
metadata is 16.7 MB and 18% of it is CFG block/edge listings.

Usage:
    python tests/scripts/bench.py [--dir corpus-build] [--output bench.json]
                                  [--repeat N] [--only SUBSTR] [--no-disassemble]
                                  [--compare OLD.json] [--threshold PCT]

Artifacts are the files in --dir (default corpus-build/, materialized by
tests/scripts/build_corpus.py), processed in sorted order. Missing corpus
artifacts are skipped cleanly, so the script works wherever a partial corpus
exists. Exit code is always 0 unless arguments are wrong; compare results
are reported as a table, not an exit status.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

import orjson  # noqa: E402

from blint.config import BlintOptions  # noqa: E402
from blint.lib import binary as binary_mod  # noqa: E402
from blint.lib.analysis import initialize_rules, run_checks  # noqa: E402
from blint.lib.review_runner import ReviewRunner  # noqa: E402

# (module attribute in blint.lib.binary, phase name). All of these are
# resolved as module globals when parse() calls them, so patching the
# attribute on the module is enough to time them.
_TIMED_PHASES = [
    ("discover_and_merge_functions", "discovery"),
    ("disassemble_functions", "disassembly"),
    ("attach_function_hashes", "similarity"),
    ("build_disassembly_callgraph_metadata", "cfg"),
    ("recover_stack_strings", "stack_strings"),
    ("analyze_binary_entropy", "entropy"),
    ("parse_strings", "strings"),
]

_TOP_BLOCK_COUNT = 8


def _timed(original, clock: dict, phase: str):
    def wrapper(*args, **kwargs):
        start = time.perf_counter()
        try:
            return original(*args, **kwargs)
        finally:
            clock[phase] += time.perf_counter() - start

    return wrapper


def _counters(metadata: dict) -> dict:
    disassembled = metadata.get("disassembled_functions") or {}
    callgraph = metadata.get("callgraph") or {}
    instructions = 0
    blocks = 0
    for func in disassembled.values():
        if not isinstance(func, dict):
            continue
        instructions += len(
            [line for line in (func.get("assembly") or "").splitlines() if line.strip()]
        )
        cfg = func.get("cfg") or {}
        blocks += len(cfg.get("blocks") or [])
    return {
        "functions": len(metadata.get("functions") or []),
        "discovered": len(metadata.get("discovered_functions") or []),
        "disassembled": len(disassembled),
        "instructions": instructions,
        "cfg_blocks": blocks,
        "callgraph_nodes": len(callgraph.get("nodes") or []),
        "callgraph_edges": len(callgraph.get("edges") or []),
        "stack_strings": len(metadata.get("stack_strings") or []),
    }


def _metadata_size_profile(metadata: dict) -> tuple[int, list[list]]:
    """Serialized size plus the largest top-level blocks, sorted desc."""
    block_sizes = []
    for key, value in metadata.items():
        try:
            block_sizes.append((key, len(orjson.dumps(value, default=str))))
        except (TypeError, ValueError):
            block_sizes.append((key, -1))
    total = sum(size for _, size in block_sizes)
    block_sizes.sort(key=lambda item: (-item[1], item[0]))
    return total, [[key, size] for key, size in block_sizes[:_TOP_BLOCK_COUNT]]


def bench_artifact(path: str, disassemble: bool, review_options: BlintOptions) -> dict:
    """Time one artifact once, returning phases, counters and size profile."""
    clock: dict = defaultdict(float)
    originals = []
    for attr, phase in _TIMED_PHASES:
        original = getattr(binary_mod, attr)
        setattr(binary_mod, attr, _timed(original, clock, phase))
        originals.append((attr, original))
    try:
        start = time.perf_counter()
        metadata = binary_mod.parse(path, disassemble=disassemble)
        clock["parse"] += time.perf_counter() - start

        reviews_error = None
        review_start = time.perf_counter()
        try:
            run_checks(path, metadata)
            if not review_options.no_reviews:
                ReviewRunner().run_review(metadata)
        except Exception as e:  # noqa: BLE001
            reviews_error = f"{type(e).__name__}: {e}"
        clock["reviews"] += time.perf_counter() - review_start
    finally:
        for attr, original in originals:
            setattr(binary_mod, attr, original)

    phases = dict(clock)
    # Phases nest inside parse; surface the unattributed remainder so no
    # regression can hide inside "parse" without showing up somewhere.
    phases["parse_other"] = phases["parse"] - sum(
        seconds for name, seconds in phases.items() if name not in ("parse", "reviews")
    )
    metadata_bytes, top_blocks = _metadata_size_profile(metadata)
    entry = {
        "name": Path(path).name,
        "path": path,
        "file_size_bytes": Path(path).stat().st_size,
        "metadata_bytes": metadata_bytes,
        "metadata_top_blocks": top_blocks,
        "phases": {k: round(phases[k], 6) for k in sorted(phases)},
        "counters": _counters(metadata),
    }
    if reviews_error:
        entry["reviews_error"] = reviews_error
    return entry


def _human(seconds: float) -> str:
    if seconds >= 1:
        return f"{seconds:8.2f}s"
    return f"{seconds * 1000:8.1f}ms"


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--dir", type=Path, default=REPO_ROOT / "corpus-build", help="corpus artifact directory"
    )
    parser.add_argument("--output", type=Path, help="write JSON results here")
    parser.add_argument("--repeat", type=int, default=1, help="runs per artifact; minimum is kept")
    parser.add_argument("--only", default="", help="substring filter on artifact names")
    parser.add_argument("--no-disassemble", action="store_true", help="skip disassembly")
    parser.add_argument("--compare", type=Path, help="baseline JSON to diff phases against")
    parser.add_argument(
        "--threshold", type=float, default=10.0, help="percent delta flagged as a regression"
    )
    args = parser.parse_args()

    artifacts = sorted(
        p for p in args.dir.iterdir() if p.is_file() and args.only in p.name
    ) if args.dir.is_dir() else []
    if not artifacts:
        print(
            f"No artifacts in {args.dir}; materialize the corpus first with "
            "tests/scripts/build_corpus.py",
            file=sys.stderr,
        )
        return 1

    review_options = BlintOptions(reports_dir=str(REPO_ROOT / ".bench-reports"))
    initialize_rules(review_options)
    disassemble = not args.no_disassemble

    try:
        from importlib.metadata import version as _pkg_version

        blint_version = _pkg_version("blint")
    except Exception:  # noqa: BLE001
        blint_version = "unknown"

    results = []
    print(f"Benching {len(artifacts)} artifact(s), repeat={args.repeat}, "
          f"disassemble={disassemble}\n")
    for path in artifacts:
        # Same isolation contract as the analyzer itself: one bad artifact
        # records an error and the bench continues with the rest.
        try:
            runs = [
                bench_artifact(str(path), disassemble, review_options)
                for _ in range(args.repeat)
            ]
        except Exception as e:  # noqa: BLE001
            results.append({"name": path.name, "path": str(path), "error": f"{type(e).__name__}: {e}"})
            print(f"{path.name:32} ERROR {type(e).__name__}: {e}")
            continue
        # Keep the minimum per phase: the least-noisy estimate of true cost.
        best = dict(runs[0])
        best["phases"] = {
            phase: min(run["phases"][phase] for run in runs) for phase in runs[0]["phases"]
        }
        results.append(best)
        phases = best["phases"]
        print(
            f"{best['name']:32} parse {_human(phases['parse'])}  "
            f"reviews {_human(phases['reviews'])}  "
            f"metadata {best['metadata_bytes'] / 1e6:.1f} MB"
        )
        for phase in sorted(phases):
            if phase not in ("parse", "reviews"):
                print(f"    {phase:16} {_human(phases[phase])}")

    payload = {
        "meta": {
            "blint_version": blint_version,
            "python": sys.version.split()[0],
            "disassemble": disassemble,
            "repeat": args.repeat,
            "corpus_dir": str(args.dir),
        },
        "artifacts": results,
    }
    if args.output:
        args.output.write_text(json.dumps(payload, indent=1, sort_keys=True))
        print(f"\nResults written to {args.output}")

    if args.compare:
        baseline = json.loads(args.compare.read_text())
        base_map = {a["name"]: a for a in baseline.get("artifacts", [])}
        print(f"\nA/B vs {args.compare.name} (flagged at >{args.threshold:g}% slower)\n")
        regressions = 0
        for art in results:
            base = base_map.get(art["name"])
            if not base:
                continue
            for phase in sorted(art["phases"]):
                base_seconds = base.get("phases", {}).get(phase)
                if not base_seconds:
                    continue
                delta_pct = (art["phases"][phase] - base_seconds) / base_seconds * 100
                flag = " <-- SLOWER" if delta_pct > args.threshold else ""
                if delta_pct > args.threshold:
                    regressions += 1
                print(
                    f"{art['name']:32} {phase:16} "
                    f"{_human(base_seconds)} -> {_human(art['phases'][phase])} "
                    f"({delta_pct:+.1f}%){flag}"
                )
            base_bytes = base.get("metadata_bytes", 0)
            if base_bytes:
                size_delta = (art["metadata_bytes"] - base_bytes) / base_bytes * 100
                print(
                    f"{art['name']:32} {'metadata size':16} "
                    f"{base_bytes / 1e6:.1f} MB -> {art['metadata_bytes'] / 1e6:.1f} MB "
                    f"({size_delta:+.1f}%)"
                )
        if regressions:
            print(f"\n{regressions} phase regression(s) above threshold")
        else:
            print("\nNo phase regressions above threshold")

    return 0


if __name__ == "__main__":
    sys.exit(main())
