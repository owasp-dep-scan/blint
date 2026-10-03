#!/usr/bin/env python3
"""A14 W1 gate: the jna_direct join, measured and checked.

Four answers over the corpus APKs (every one that has a join, every ABI):

(a) Before/after: the full row sets of the join with the confirmers on,
    this tree against a before tree (``--before-tree PATH``, run through
    ``--dump-rows`` there), listing cap lifted - every row that moved is
    a jna_direct binding or a jna_exporters ambiguity, and nothing else
    moves.
(b) The jna_direct oracle: every jna_direct row's ``fn_addr`` equals the
    ``llvm-nm`` address of that name in that ABI's library and is a
    function start (dynsym FUNC, eh_frame FDE, or .ARM.exidx on v7a).
    Reported as failures (must be 0) and rows checked.
(c) Precision: every jna_direct row whose declaring class the dex walk
    found no ``Native.register`` evidence for (must be empty), and every
    bound name more than one library exports.
(d) Wall time of the join per APK, with and without the confirmers.

Usage (from the a14 tree):
  PATH="/opt/homebrew/opt/llvm@18/bin:$PATH" NYXSTONE_LLVM_PREFIX=/opt/homebrew/opt/llvm@18 \
  poetry run python tests/scripts/android/a14_w1_gate.py \
      --corpus ~/sandbox/android-corpus --before-tree /tmp/a14-main [--json PATH]

Before-tree dump (run first, from the before tree):
  PYTHONPATH=/tmp/a14-main python tests/scripts/android/a14_w1_gate.py \
      --corpus ~/sandbox/android-corpus --dump-rows /tmp/a14-w1-before.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

NM = "/opt/homebrew/opt/llvm@18/bin/llvm-nm"
READELF = "/opt/homebrew/opt/llvm@18/bin/llvm-readelf"
OBJDUMP = "/opt/homebrew/opt/llvm@18/bin/llvm-objdump"

TIER_DIRS = ("tier2-fdroid", "tier3-frameworks", "tier1-ndk/apks", "tier4-hostile")


def corpus_apks(corpus: Path) -> list[Path]:
    out: list[Path] = []
    for tier in TIER_DIRS:
        base = corpus / tier
        if base.is_dir():
            out.extend(sorted(base.glob("*.apk")))
            out.extend(sorted(base.glob("*.xapk")))
    return out


def run_join(apk: str, confirm: bool) -> tuple[dict | None, float]:
    import blint.lib.jni as jni_module
    from blint.lib.android_native import scan_android_native

    native = scan_android_native(apk)
    original_cap = jni_module.JOIN_LISTING_CAP
    jni_module.JOIN_LISTING_CAP = 10**6
    try:
        t0 = time.monotonic()
        join = jni_module.build_jni_join_summary(apk, native, confirm_findclass=confirm)
        wall = time.monotonic() - t0
    finally:
        jni_module.JOIN_LISTING_CAP = original_cap
    return join, wall


def row_sets(join: dict | None) -> dict:
    """The full row sets of one join, listing cap lifted by the caller."""
    rows: dict[str, set] = {}
    for abi, abi_join in sorted(((join or {}).get("per_abi") or {}).items()):
        for key in ("bound", "bound_dynamic", "ambiguous_dynamic", "unbound_dex_natives"):
            rows[f"{abi}:{key}"] = {
                json.dumps(entry, sort_keys=True, default=str) for entry in abi_join.get(key) or []
            }
    return rows


def oracle_starts(path: Path, abi: str) -> set[int]:
    """Function starts per llvm-readelf/objdump (never blint's discovery):
    dynsym/symtab FUNCs plus eh_frame FDEs, and .ARM.exidx on v7a."""
    # only arm32 FUNC st_values carry the Thumb bit; masking anywhere else
    # corrupts legitimate odd addresses (x86's packed 5-byte uniffi stubs)
    thumb = abi == "armeabi-v7a"
    starts: set[int] = set()
    for flag in ("--dyn-syms", "--syms"):
        out = subprocess.run([READELF, flag, str(path)], capture_output=True, text=True).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 8 and parts[3] == "FUNC" and parts[6] != "UND":
                value = int(parts[1], 16)
                starts.add(value & ~1 if thumb else value)
    frames = subprocess.run(
        [OBJDUMP, "--dwarf=frames", str(path)], capture_output=True, text=True
    ).stdout
    for match in re.finditer(r"pc=0*([0-9a-f]+)\.{2,3}0*[0-9a-f]+", frames):
        starts.add(int(match.group(1), 16) & ~1)
    if abi == "armeabi-v7a":
        dump = subprocess.run(
            [READELF, "-x", ".ARM.exidx", str(path)], capture_output=True, text=True
        ).stdout
        for line in dump.splitlines():
            match = re.match(r"^\s*0x([0-9a-f]+)\s+((?:[0-9a-f]{8}\s+){1,4})", line)
            if not match:
                continue
            base = int(match.group(1), 16)
            for index, group in enumerate(match.group(2).split()):
                if index % 2:
                    continue
                word = int.from_bytes(bytes.fromhex(group), "little")
                offset = word & 0x7FFFFFFF
                if word & 0x40000000:
                    offset -= 1 << 31
                starts.add((base + index * 4 + offset) & ~1)
    return starts


def nm_addresses(path: Path) -> dict[str, int]:
    out = subprocess.run(
        [NM, "-D", "--defined-only", str(path)], capture_output=True, text=True
    ).stdout
    addresses: dict[str, int] = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] in ("T", "t", "W", "w"):
            addresses.setdefault(parts[2].split("@")[0], int(parts[0], 16))
    return addresses


def extract_libraries(apk: Path, tmp: Path) -> dict[tuple[str, str], Path]:
    extracted: dict[tuple[str, str], Path] = {}
    with zipfile.ZipFile(str(apk)) as zf:
        for info in zf.infolist():
            parts = info.filename.split("/")
            if len(parts) != 3 or parts[0] != "lib" or not parts[2].endswith(".so"):
                continue
            out = Path(tmp) / f"{parts[2]}-{parts[1]}"
            if not out.exists():
                out.write_bytes(zf.read(info))
            extracted.setdefault((parts[2], parts[1]), out)
    return extracted


def dump_rows(corpus: Path, out_path: Path) -> None:
    """The --dump-rows mode: the full confirm-join row sets of every
    corpus APK, run from the tree being measured."""
    rows: dict[str, dict] = {}
    for apk in corpus_apks(corpus):
        join, _wall = run_join(str(apk), confirm=True)
        if join is None:
            continue
        rows[apk.name] = {
            "rows": row_sets(join),
            "counts": {
                abi: dict(abi_join.get("counts") or {})
                for abi, abi_join in sorted((join.get("per_abi") or {}).items())
            },
        }
        print(f"dumped {apk.name}")
    out_path.write_text(
        json.dumps(
            {
                apk: {
                    "rows": {key: sorted(values) for key, values in entry["rows"].items()},
                    "counts": entry["counts"],
                }
                for apk, entry in rows.items()
            },
            indent=1,
        )
        + "\n"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--before-tree", type=Path, default=None)
    parser.add_argument(
        "--before-rows",
        type=Path,
        default=None,
        help="a --dump-rows file from the before tree, instead of --before-tree's re-dump",
    )
    parser.add_argument("--dump-rows", type=Path, default=None)
    parser.add_argument("--json", type=Path, default=None)
    args = parser.parse_args(argv)
    if args.dump_rows:
        dump_rows(args.corpus, args.dump_rows)
        return 0

    before: dict[str, dict] = {}
    if args.before_rows and args.before_rows.exists():
        before = json.loads(args.before_rows.read_text())
    elif args.before_tree and args.before_tree.exists():
        dump_path = Path("/tmp/a14-w1-before.json")
        env = dict(os.environ, PYTHONPATH=str(args.before_tree))
        subprocess.run(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--corpus",
                str(args.corpus),
                "--dump-rows",
                str(dump_path),
            ],
            check=True,
            env=env,
        )
        before = json.loads(dump_path.read_text())

    report: dict = {"tools": {"llvm_nm": NM, "llvm_readelf": READELF, "llvm_objdump": OBJDUMP}}
    jna_checked = 0
    jna_failures: list[dict] = []
    precision_no_evidence: list[dict] = []
    precision_multi_export: list[dict] = []
    apps: dict[str, dict] = {}
    starts_cache: dict[tuple[str, str], set[int]] = {}
    nm_cache: dict[tuple[str, str], dict[str, int]] = {}
    with tempfile.TemporaryDirectory() as tmp:
        for apk in corpus_apks(args.corpus):
            join_confirm, wall_confirm = run_join(str(apk), confirm=True)
            join_plain, wall_plain = run_join(str(apk), confirm=False)
            if join_confirm is None and join_plain is None:
                continue
            entry: dict = {
                "wall_s": {"plain": round(wall_plain, 2), "confirm": round(wall_confirm, 2)},
                "counts": {},
            }
            for mode, join in (("plain", join_plain), ("confirm", join_confirm)):
                entry["counts"][mode] = {
                    abi: dict(abi_join.get("counts") or {})
                    for abi, abi_join in sorted(((join or {}).get("per_abi") or {}).items())
                }
            # the jna_direct oracle and the precision lists
            extracted = None
            evidence_classes: set[str] | None = None
            for abi, abi_join in sorted(((join_confirm or {}).get("per_abi") or {}).items()):
                jna_rows = [
                    e
                    for e in abi_join.get("bound_dynamic") or []
                    if e.get("confirmed_by") == "jna_direct"
                ]
                if not jna_rows:
                    continue
                if evidence_classes is None:
                    # the precision check recomputes the dex evidence
                    # independently of the join's own collection
                    from blint.lib.android import _iter_app_dex_files
                    from blint.lib.binary import parse_dex
                    from blint.lib.jni import collect_jna_register_facts

                    evidence_classes = set()
                    for adex, _ in _iter_app_dex_files(str(apk)):
                        evidence_classes.update(collect_jna_register_facts(parse_dex(adex)))
                for row in jna_rows:
                    if row["class"] not in (evidence_classes or set()):
                        precision_no_evidence.append(
                            {"abi": abi, "class": row["class"], "name": row["name"]}
                        )
                if extracted is None:
                    extracted = extract_libraries(apk, Path(tmp))
                for row in jna_rows:
                    key = (row["library"], abi)
                    library_path = extracted.get(key)
                    if library_path is None:
                        jna_failures.append({**row, "problem": "library not in apk"})
                        continue
                    if key not in nm_cache:
                        nm_cache[key] = nm_addresses(library_path)
                    if key not in starts_cache:
                        starts_cache[key] = oracle_starts(library_path, abi)
                    address = nm_cache[key].get(row["name"])
                    try:
                        fn = int(row["fn_addr"], 16)
                    except (KeyError, TypeError, ValueError):
                        fn = None
                    jna_checked += 1
                    # an arm32 FUNC symbol's st_value carries the Thumb bit;
                    # llvm-nm prints the masked address and the starts are
                    # masked, so the comparison masks it too
                    compare = (fn & ~1) if (fn is not None and abi == "armeabi-v7a") else fn
                    if (
                        address is None
                        or compare is None
                        or compare != address
                        or compare not in starts_cache[key]
                    ):
                        jna_failures.append(
                            {
                                "abi": abi,
                                "library": row["library"],
                                "class": row["class"],
                                "name": row["name"],
                                "fn_addr": row["fn_addr"],
                                "nm_address": f"{address:#x}" if address is not None else None,
                                "is_function_start": fn in starts_cache[key]
                                if fn is not None
                                else False,
                            }
                        )
                    # precision: two exporters of a bound name inside one library set
                    for other, other_path in extracted.items():
                        if other[1] != abi or other[0] == row["library"]:
                            continue
                        if other not in nm_cache:
                            nm_cache[other] = nm_addresses(other_path)
                        if row["name"] in nm_cache[other]:
                            precision_multi_export.append(
                                {
                                    "abi": abi,
                                    "name": row["name"],
                                    "libraries": sorted((row["library"], other[0])),
                                }
                            )
            # the before/after row diff
            if before.get(apk.name):
                before_rows = {k: set(v) for k, v in before[apk.name]["rows"].items()}
                after_rows = row_sets(join_confirm)
                gained: dict[str, list[str]] = {}
                lost: dict[str, list[str]] = {}
                for key in set(before_rows) | set(after_rows):
                    new = after_rows.get(key, set()) - before_rows.get(key, set())
                    gone = before_rows.get(key, set()) - after_rows.get(key, set())
                    if new:
                        gained[key] = sorted(new)[:4] + (
                            [f"... {len(new) - 4} more"] if len(new) > 4 else []
                        )
                    if gone:
                        lost[key] = sorted(gone)[:4] + (
                            [f"... {len(gone) - 4} more"] if len(gone) > 4 else []
                        )
                entry["diff"] = {
                    "gained_counts": {
                        k: sum(1 for row in v if not row.startswith("..."))
                        + next(
                            (int(row.split()[1]) for row in v if row.startswith("... ")),
                            0,
                        )
                        for k, v in gained.items()
                    },
                    "lost_counts": {
                        k: sum(1 for row in v if not row.startswith("..."))
                        + next(
                            (int(row.split()[1]) for row in v if row.startswith("... ")),
                            0,
                        )
                        for k, v in lost.items()
                    },
                    "lost_sample": {
                        k: v
                        for k, v in lost.items()
                        if k.endswith(("bound_dynamic", "bound"))
                    },
                    "gained_not_jna": {
                        k: [
                            row
                            for row in v
                            if '"confirmed_by": "jna_direct"' not in row
                            and not row.startswith("... ")
                        ]
                        for k, v in gained.items()
                        if k.endswith("bound_dynamic")
                        and any(
                            '"confirmed_by": "jna_direct"' not in row
                            and not row.startswith("... ")
                            for row in v
                        )
                    },
                }
            apps[apk.name] = entry
            print(
                f"== {apk.name}: plain {wall_plain:.1f}s / confirm {wall_confirm:.1f}s;"
                f" jna rows checked so far {jna_checked}"
            )
            for abi, counts in sorted(entry["counts"]["confirm"].items()):
                if counts.get("jna_direct"):
                    print(f"   {abi}: {json.dumps(counts)}")
    report["apps"] = apps
    report["jna_oracle"] = {"checked": jna_checked, "failures": jna_failures[:20]}
    report["precision"] = {
        "no_register_evidence": precision_no_evidence,
        "multi_exported_bound_names": sorted(
            {json.dumps(e, sort_keys=True) for e in precision_multi_export}
        )[:20],
    }
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=1, default=str) + "\n")
        print(f"wrote {args.json}")
    print(
        f"jna_direct oracle: {jna_checked} checked, {len(jna_failures)} failures;"
        f" multi-exported bound names: {len(precision_multi_export)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
