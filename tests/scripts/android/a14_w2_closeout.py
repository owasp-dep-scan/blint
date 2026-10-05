#!/usr/bin/env python3
"""A14 W2 - the lane close-out: the full-row oracle and the sweep's
identity check.

(a) The independent fn_addr oracle over **every** bound row - `bound`
    (the decoded Java_* exports) and `bound_dynamic` (recovered tables,
    confirmer, runtime tables and jna_direct alike) - on RnHello,
    organicmaps, vlc, element and fennec, per ABI: llvm-readelf FUNC
    symbols plus eh_frame FDEs (and .ARM.exidx on v7a) name the starts;
    llvm-nm names each symbol's own address; a static row's fn_addr must
    equal its symbol's nm address, a dynamic row's fn_addr must be a
    function start.
(b) The sweep's identity check: the corpus join row sets of two trees
    (``--rows-a``/``--rows-b``, each a ``--dump-rows`` file from
    a14_w1_gate.py) must be equal.
(c) The review-identity check: the default analysis's findings and
    reviews over a set of apps, one tree against another
    (``--tree-a``/``--tree-b`` paths to blint checkouts, run through
    their own venv python with PYTHONPATH).

Usage (from the a14 tree):
  PATH="/opt/homebrew/opt/llvm@18/bin:$PATH" NYXSTONE_LLVM_PREFIX=/opt/homebrew/opt/llvm@18 \
  poetry run python tests/scripts/android/a14_w2_closeout.py \
      --corpus ~/sandbox/android-corpus --rows-a X --rows-b Y --json PATH
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

NM = "/opt/homebrew/opt/llvm@18/bin/llvm-nm"
READELF = "/opt/homebrew/opt/llvm@18/bin/llvm-readelf"
OBJDUMP = "/opt/homebrew/opt/llvm@18/bin/llvm-objdump"

ORACLE_APKS = {
    "com.blint.rnhello_1.apk": "tier3-frameworks",
    "app.organicmaps_26082718.apk": "tier2-fdroid",
    "org.videolan.vlc_13070108.apk": "tier2-fdroid",
    "im.vector.app_40106624.apk": "tier2-fdroid",
    "org.mozilla.fennec_fdroid_1560020.apk": "tier2-fdroid",
}


def oracle_starts(path: Path, abi: str) -> set[int]:
    """Function starts per llvm-readelf/objdump (dynsym/symtab FUNCs plus
    eh_frame FDEs, .ARM.exidx on arm32; the arm32 Thumb bit masked, other
    ABIs compared at the exact address)."""
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
    out = subprocess.run([NM, "-D", "--defined-only", str(path)], capture_output=True, text=True)
    addresses: dict[str, int] = {}
    for line in out.stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] in ("T", "t", "W", "w"):
            addresses.setdefault(parts[2].split("@")[0], int(parts[0], 16))
    return addresses


def run_join(apk: str) -> dict:
    import blint.lib.jni as jni_module
    from blint.lib.android_native import scan_android_native

    native = scan_android_native(apk)
    original_cap = jni_module.JOIN_LISTING_CAP
    jni_module.JOIN_LISTING_CAP = 10**6
    try:
        return jni_module.build_jni_join_summary(apk, native, confirm_findclass=True)
    finally:
        jni_module.JOIN_LISTING_CAP = original_cap


def part_a(corpus: Path, report: dict) -> None:
    print("== (a) the full-row oracle")
    checked = {"bound": 0, "bound_dynamic": 0}
    failures: list[dict] = []
    per_app: dict[str, dict] = {}
    with tempfile.TemporaryDirectory() as tmp:
        for apk_name, tier in ORACLE_APKS.items():
            apk = corpus / tier / apk_name
            join = run_join(str(apk))
            extracted: dict[tuple[str, str], Path] = {}
            with zipfile.ZipFile(str(apk)) as zf:
                for info in zf.infolist():
                    parts = info.filename.split("/")
                    if len(parts) != 3 or parts[0] != "lib" or not parts[2].endswith(".so"):
                        continue
                    out = Path(tmp) / f"{apk.stem}-{parts[2]}-{parts[1]}"
                    if not out.exists():
                        out.write_bytes(zf.read(info))
                    extracted.setdefault((parts[2], parts[1]), out)
            starts_cache: dict[tuple[str, str], set[int]] = {}
            nm_cache: dict[tuple[str, str], dict[str, int]] = {}
            app_counts = {}
            for abi, abi_join in sorted(((join or {}).get("per_abi") or {}).items()):
                for row in abi_join.get("bound") or []:
                    key = (row["library"], abi)
                    if key not in extracted:
                        continue
                    if key not in nm_cache:
                        nm_cache[key] = nm_addresses(extracted[key])
                    address = nm_cache[key].get(row["symbol"])
                    try:
                        fn = int(row["fn_addr"], 16)
                    except (KeyError, TypeError, ValueError):
                        fn = None
                    checked["bound"] += 1
                    # arm32 FUNC st_values carry the Thumb bit; llvm-nm
                    # prints the masked address
                    compare_static = (fn & ~1) if (fn is not None and abi == "armeabi-v7a") else fn
                    if address is None or compare_static is None or compare_static != address:
                        failures.append(
                            {"apk": apk_name, "abi": abi, "kind": "bound", "row": row}
                        )
                for row in abi_join.get("bound_dynamic") or []:
                    key = (row["library"], abi)
                    if key not in extracted:
                        continue
                    if key not in starts_cache:
                        starts_cache[key] = oracle_starts(extracted[key], abi)
                    try:
                        fn = int(row["fn_addr"], 16)
                    except (KeyError, TypeError, ValueError):
                        fn = None
                    thumb = abi == "armeabi-v7a"
                    compare = (fn & ~1) if (fn is not None and thumb) else fn
                    checked["bound_dynamic"] += 1
                    if compare is None or compare not in starts_cache[key]:
                        failures.append(
                            {
                                "apk": apk_name,
                                "abi": abi,
                                "kind": "bound_dynamic",
                                "confirmed_by": row.get("confirmed_by"),
                                "row": {k: row.get(k) for k in ("class", "name", "fn_addr", "library")},
                            }
                        )
                app_counts[abi] = {
                    "bound": len(abi_join.get("bound") or []),
                    "bound_dynamic": len(abi_join.get("bound_dynamic") or []),
                }
            per_app[apk_name] = app_counts
            print(f"   {apk_name}: {app_counts}")
    report["a_full_row_oracle"] = {"checked": checked, "failures": failures[:20]}
    print(f"   oracle: {checked} checked, {len(failures)} failures")


def part_b(rows_a: Path, rows_b: Path, report: dict) -> None:
    print("== (b) the sweep's join-row identity check")
    a = json.loads(rows_a.read_text())
    b = json.loads(rows_b.read_text())
    if set(a) != set(b):
        report["b_row_identity"] = {"apks_differ": sorted(set(a) ^ set(b))}
        print("   APK SETS DIFFER")
        return
    differences: dict[str, dict] = {}
    for apk in sorted(a):
        ra = {key: set(values) for key, values in a[apk]["rows"].items()}
        rb = {key: set(values) for key, values in b[apk]["rows"].items()}
        for key in set(ra) | set(rb):
            only_a = ra.get(key, set()) - rb.get(key, set())
            only_b = rb.get(key, set()) - ra.get(key, set())
            if only_a or only_b:
                differences.setdefault(apk, {})[key] = {
                    "only_a": sorted(only_a)[:3],
                    "only_b": sorted(only_b)[:3],
                }
    report["b_row_identity"] = {
        "apks": len(a),
        "trees_identical": not differences,
        "differences": differences,
    }
    print(f"   {len(a)} APKs, row sets {'identical' if not differences else 'DIFFER'}")


def run_blint_tree(tree: Path, apps: list[Path], out_dir: Path) -> dict[str, dict]:
    """Run the default analysis from one checkout over the apps and return
    the findings/reviews JSON per app (PYTHONPATH picks the tree's blint)."""
    results: dict[str, dict] = {}
    venv_blint = REPO / ".venv" / "bin" / "blint"
    env = dict(os.environ, PYTHONPATH=str(tree))
    for apk in apps:
        reports = out_dir / f"{tree.name}-{apk.stem}"
        subprocess.run(
            [str(venv_blint), "-q", "--no-banner", "-i", str(apk), "-o", str(reports)],
            capture_output=True,
            text=True,
            timeout=7200,
            env=env,
        )
        digest: dict[str, list] = {}
        for pattern, key in (("*findings*.json", "findings"), ("*reviews*.json", "reviews")):
            ffile = next(reports.glob(pattern), None)
            if ffile is None:
                digest[key] = []
                continue
            try:
                data = json.loads(ffile.read_text())
            except ValueError:
                digest[key] = ["<unparsable>"]
                continue
            rows = data.get("findings") or data.get("reviews") or []
            digest[key] = sorted(
                json.dumps(
                    {k: row.get(k) for k in sorted(row) if k not in ("id",)}, sort_keys=True
                )
                for row in rows
                if isinstance(row, dict)
            )
        results[apk.name] = digest
    return results


def part_c(tree_a: Path, tree_b: Path, corpus: Path, report: dict) -> None:
    print("== (c) the sweep's review-identity check")
    apps = [
        corpus / "tier3-frameworks" / "com.blint.rnhello_1.apk",
        corpus / "tier2-fdroid" / "org.videolan.vlc_13070108.apk",
        corpus / "tier2-fdroid" / "net.osmand.plus_540403.apk",
        corpus / "tier2-fdroid" / "im.vector.app_40106624.apk",
        corpus / "tier2-fdroid" / "org.mozilla.fennec_fdroid_1560020.apk",
    ]
    with tempfile.TemporaryDirectory() as td:
        a = run_blint_tree(tree_a, apps, Path(td))
        b = run_blint_tree(tree_b, apps, Path(td))
    identical = True
    detail: dict[str, dict] = {}
    for apk in a:
        for key in ("findings", "reviews"):
            if a[apk][key] != b[apk][key]:
                identical = False
                only_a = set(a[apk][key]) - set(b[apk][key])
                only_b = set(b[apk][key]) - set(a[apk][key])
                detail.setdefault(apk, {})[key] = {
                    "only_tree_a": sorted(only_a)[:3],
                    "only_tree_b": sorted(only_b)[:3],
                }
    report["c_review_identity"] = {
        "apps": [p.name for p in apps],
        "identical": identical,
        "differences": detail,
    }
    print(f"   findings and reviews over 5 apps: {'identical' if identical else 'DIFFER'}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--rows-a", type=Path, default=None)
    parser.add_argument("--rows-b", type=Path, default=None)
    parser.add_argument("--tree-a", type=Path, default=None)
    parser.add_argument("--tree-b", type=Path, default=None)
    parser.add_argument("--json", type=Path, default=None)
    args = parser.parse_args(argv)
    report: dict = {"tools": {"llvm_nm": NM, "llvm_readelf": READELF, "llvm_objdump": OBJDUMP}}
    part_a(args.corpus, report)
    if args.rows_a and args.rows_b:
        part_b(args.rows_a, args.rows_b, report)
    if args.tree_a and args.tree_b:
        part_c(args.tree_a, args.tree_b, args.corpus, report)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=1, default=str) + "\n")
        print(f"wrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
