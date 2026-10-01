#!/usr/bin/env python3
"""A11 gate measurements: per APK and every ABI, the join's counts and wall
time on this tree, with and without the confirmers (--disassemble); the
independent fn_addr oracle (llvm-readelf dynsym+symtab FUNCs plus eh_frame
FDEs, or .ARM.exidx on v7a) over every bound_dynamic row of RnHello,
organicmaps, vlc and element; and the runtime-recovered rows' fn_addrs.

Usage (from the a11 tree):
  PATH="/opt/homebrew/opt/llvm@18/bin:$PATH" NYXSTONE_LLVM_PREFIX=/opt/homebrew/opt/llvm@18 \
  poetry run python tests/scripts/android/a11_gate.py \
      --corpus ~/sandbox/android-corpus [--json PATH]
"""

from __future__ import annotations

import argparse
import json
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

APKS = {
    "com.blint.rnhello_1.apk": "tier3-frameworks",
    "app.organicmaps_26082718.apk": "tier2-fdroid",
    "org.videolan.vlc_13070108.apk": "tier2-fdroid",
    "im.vector.app_40106624.apk": "tier2-fdroid",
}
READELF = "/opt/homebrew/opt/llvm@18/bin/llvm-readelf"
OBJDUMP = "/opt/homebrew/opt/llvm@18/bin/llvm-objdump"


def run_join(apk: str, confirm: bool) -> tuple[dict, float]:
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


def oracle_starts(path: Path, abi: str) -> set[int]:
    starts: set[int] = set()
    for flag in ("--dyn-syms", "--syms"):
        out = subprocess.run([READELF, flag, str(path)], capture_output=True, text=True).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 8 and parts[3] == "FUNC" and parts[6] != "UND":
                starts.add(int(parts[1], 16) & ~1)
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


def measure(apk: Path) -> dict:
    print(f"== {apk.name}")
    report: dict = {}
    oracle_checked = 0
    oracle_failures = []
    starts_cache: dict[tuple[str, str], set[int]] = {}
    for confirm in (False, True):
        join, wall = run_join(str(apk), confirm)
        if join is None:
            report[f"confirm_{confirm}"] = {"absent": True}
            continue
        per_abi = {}
        for abi, abi_join in sorted(join["per_abi"].items()):
            per_abi[abi] = dict(abi_join["counts"])
        report[f"confirm_{confirm}"] = {"wall_s": round(wall, 2), "counts": per_abi}
        if not confirm:
            continue
        # the independent oracle over every bound_dynamic fn_addr
        extracted: dict[tuple[str, str], Path] = {}
        with tempfile.TemporaryDirectory() as tmp:
            with zipfile.ZipFile(str(apk)) as zf:
                for info in zf.infolist():
                    parts = info.filename.split("/")
                    if len(parts) != 3 or parts[0] != "lib" or not parts[2].endswith(".so"):
                        continue
                    out = Path(tmp) / f"{parts[2]}-{parts[1]}"
                    out.write_bytes(zf.read(info))
                    extracted[(parts[2], parts[1])] = out
            for abi, abi_join in sorted(join["per_abi"].items()):
                for entry in abi_join.get("bound_dynamic") or []:
                    key = (entry.get("library"), abi)
                    if key not in extracted:
                        continue
                    if key not in starts_cache:
                        starts_cache[key] = oracle_starts(extracted[key], abi)
                    starts = starts_cache[key]
                    try:
                        fn = int(entry["fn_addr"], 16)
                    except (KeyError, TypeError, ValueError):
                        continue
                    oracle_checked += 1
                    if fn not in starts:
                        oracle_failures.append(
                            {
                                "abi": abi,
                                "library": key[0],
                                "class": entry.get("class"),
                                "name": entry.get("name"),
                                "fn_addr": entry.get("fn_addr"),
                                "confirmed_by": entry.get("confirmed_by"),
                            }
                        )
        report["oracle"] = {
            "checked": oracle_checked,
            "failures": oracle_failures[:20],
        }
        print(
            f"  confirm={confirm}: wall {wall:.2f}s oracle {oracle_checked} checked, {len(oracle_failures)} failures"
        )
        for abi in sorted(report[f"confirm_{confirm}"]["counts"]):
            print(f"    {abi}: {json.dumps(report[f'confirm_{confirm}']['counts'][abi])}")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--json", type=Path, default=None)
    args = parser.parse_args(argv)

    report: dict = {"readelf": READELF, "apks": {}}
    for name, tier in APKS.items():
        apk = args.corpus / tier / name
        if not apk.exists():
            print(f"== {name}: missing")
            continue
        report["apks"][name] = measure(apk)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=1, default=str) + "\n")
        print(f"wrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
