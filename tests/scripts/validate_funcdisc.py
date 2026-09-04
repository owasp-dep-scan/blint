#!/usr/bin/env python3
"""Run the v4 engine assertions from tests/corpus/manifest.json.

Each assertion is a precision/recall or presence check over artifacts built by
tests/scripts/build_corpus.py. Exit code is non-zero when any assertion fails,
so this doubles as the CI gate for the function-discovery work.

Usage:
    python tests/scripts/validate_funcdisc.py [--dir corpus-build]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from blint.lib.binary import parse  # noqa: E402

MANIFEST_PATH = REPO_ROOT / "tests" / "corpus" / "manifest.json"


def _known_function_addresses(metadata: dict) -> set[int]:
    """Addresses claimed by the symbol-driven function buckets.

    Mach-O metadata mixes two address spaces: LIEF function lists carry
    image-relative addresses while symbol tables carry absolute ones. Both
    are normalized into the image-relative space before comparison.
    """
    imagebase = metadata.get("imagebase")
    imagebase = imagebase if isinstance(imagebase, int) else 0

    def _normalize(value: int) -> int:
        return value - imagebase if imagebase and value >= imagebase else value

    addresses = set()
    for func_entry in metadata.get("functions") or []:
        if not isinstance(func_entry, dict):
            continue
        raw = func_entry.get("address")
        if not raw:
            continue
        try:
            addresses.add(_normalize(int(str(raw).strip(), 16)))
        except ValueError:
            continue
    for discovered in metadata.get("discovered_functions") or []:
        try:
            addresses.add(_normalize(int(str(discovered["address"]).strip(), 16)))
        except (KeyError, ValueError):
            continue
    return addresses


def _disassembled_addresses(metadata: dict) -> set[int]:
    addresses = set()
    for func_data in (metadata.get("disassembled_functions") or {}).values():
        raw = (func_data or {}).get("address")
        if raw:
            try:
                addresses.add(int(str(raw).strip(), 16))
            except ValueError:
                continue
    return addresses


def _load(artifact: str, corpus_dir: Path) -> dict | None:
    path = corpus_dir / artifact
    if not path.exists():
        return None
    return parse(str(path), disassemble=True)


def assert_pair_recall(assertion: dict, corpus_dir: Path, report: list[dict]) -> bool:
    unstripped_md = _load(assertion["unstripped"], corpus_dir)
    stripped_md = _load(assertion["stripped"], corpus_dir)
    if not unstripped_md or not stripped_md:
        report.append({"id": assertion["id"], "status": "SKIP", "detail": "artifact missing"})
        return True
    unstripped_addrs = _known_function_addresses(unstripped_md)
    stripped_set = _known_function_addresses(stripped_md)
    if not unstripped_addrs:
        report.append({"id": assertion["id"], "status": "SKIP", "detail": "empty truth set"})
        return True
    # The gate measures the discovery mechanism against the oracle available
    # to a stripped binary: functions the unstripped binary knows from unwind
    # tables. Static C runtimes (musl) legitimately ship functions without
    # FDEs, which no stripped-side table can name; recall against the full
    # unstripped set is reported as context next to the gated number.
    unwind_starts = set()
    for discovered in unstripped_md.get("discovered_functions") or []:
        try:
            address = int(str(discovered["address"]).strip(), 16)
        except ValueError:
            continue
        imagebase = unstripped_md.get("imagebase")
        if isinstance(imagebase, int) and address >= imagebase:
            address -= imagebase
        unwind_starts.add(address)
    if unwind_starts:
        truth = unwind_starts
    else:
        truth = unstripped_addrs
    recovered = sum(1 for addr in truth if addr in stripped_set)
    recall = recovered / len(truth)
    full_recovered = sum(1 for addr in unstripped_addrs if addr in stripped_set)
    full_recall = full_recovered / len(unstripped_addrs)
    ok = recall >= float(assertion["min_recall"])
    report.append(
        {
            "id": assertion["id"],
            "status": "PASS" if ok else "FAIL",
            "detail": f"unwind-recall {recall:.3f} ({recovered}/{len(truth)}) "
            f">= {assertion['min_recall']}; full-truth recall {full_recall:.3f} "
            f"({full_recovered}/{len(unstripped_addrs)})",
        }
    )
    return ok


def assert_min_functions(assertion: dict, corpus_dir: Path, report: list[dict]) -> bool:
    metadata = _load(assertion["artifact"], corpus_dir)
    if not metadata:
        report.append({"id": assertion["id"], "status": "SKIP", "detail": "artifact missing"})
        return True
    count = len(metadata.get("disassembled_functions") or {})
    minimum = int(assertion["min_disassembled"])
    ok = count >= minimum
    report.append(
        {
            "id": assertion["id"],
            "status": "PASS" if ok else "FAIL",
            "detail": f"disassembled {count} >= {minimum}",
        }
    )
    return ok


def assert_stack_strings(assertion: dict, corpus_dir: Path, report: list[dict]) -> bool:
    metadata = _load(assertion["artifact"], corpus_dir)
    if not metadata:
        report.append({"id": assertion["id"], "status": "SKIP", "detail": "artifact missing"})
        return True
    values = {entry.get("value", "") for entry in metadata.get("stack_strings") or []}
    expected = assertion["expect_value"]
    ok = expected in values
    report.append(
        {
            "id": assertion["id"],
            "status": "PASS" if ok else "FAIL",
            "detail": f"expected {expected!r} in recovered {sorted(values)!r}",
        }
    )
    return ok


def assert_parses(assertion: dict, artifacts: list[str], corpus_dir: Path, report: list[dict]) -> bool:
    expected_keys = assertion.get("expect_metadata") or []
    ok = True
    parsed = 0
    missing = []
    for artifact in artifacts:
        metadata = _load(artifact, corpus_dir)
        if metadata is None:
            missing.append(artifact)
            continue
        parsed += 1
        if not metadata.get("file_path"):
            ok = False
        for key in expected_keys:
            if key not in metadata:
                ok = False
                report.append(
                    {"id": assertion["id"], "status": "FAIL", "detail": f"{artifact} lacks {key}"}
                )
                break
    if missing:
        report.append(
            {"id": assertion["id"], "status": "SKIP", "detail": f"missing {len(missing)} artifacts"}
        )
        return True
    report.append(
        {
            "id": assertion["id"],
            "status": "PASS" if ok else "FAIL",
            "detail": f"{parsed} artifacts parsed with {expected_keys or 'no extra'} keys",
        }
    )
    return ok


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dir", type=Path, default=REPO_ROOT / "corpus-build")
    args = parser.parse_args()
    manifest = json.loads(MANIFEST_PATH.read_text())
    corpus_dir: Path = args.dir

    report: list[dict] = []
    all_ok = True
    collect_map = {}
    for name, spec in (manifest.get("collect") or {}).items():
        collect_map[name] = spec

    for assertion in manifest.get("assertions") or []:
        kind = assertion["kind"]
        if kind == "pair_recall":
            all_ok &= assert_pair_recall(assertion, corpus_dir, report)
        elif kind == "min_functions":
            all_ok &= assert_min_functions(assertion, corpus_dir, report)
        elif kind == "stack_strings":
            all_ok &= assert_stack_strings(assertion, corpus_dir, report)
        elif kind == "parses":
            all_ok &= assert_parses(assertion, [assertion["artifact"]], corpus_dir, report)
        elif kind == "parses_all":
            artifacts = []
            for collect_name in assertion.get("collect") or []:
                spec = collect_map.get(collect_name, {})
                if spec.get("kind") == "paths":
                    artifacts.extend(e["name"] for e in spec.get("entries", []))
                elif spec.get("kind") == "apps":
                    artifacts.extend(
                        p.name for p in corpus_dir.glob("app-*") if p.is_file()
                    )
            all_ok &= assert_parses(assertion, artifacts, corpus_dir, report)
        else:
            report.append({"id": assertion["id"], "status": "SKIP", "detail": f"unknown kind {kind}"})

    print(f"{'id':28} {'status':6} detail")
    for entry in report:
        print(f"{entry['id']:28} {entry['status']:6} {entry['detail']}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
