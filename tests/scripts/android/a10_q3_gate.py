#!/usr/bin/env python3
"""A10 Q3 gate measurements: per APK and every ABI, the join's counts and
wall time before (main, de1e8e7) and after (this tree), with and without
the FindClass confirmer (--disassemble); the registered-nowhere census on
the after tree; and the independent fn_addr oracle (llvm-readelf symbols
plus eh_frame via llvm-objdump --dwarf=frames, or .ARM.exidx on v7a) over
every bound row of RnHello, organicmaps, vlc and element.

Usage (from the a10 tree):
  PATH="/opt/homebrew/opt/llvm@18/bin:$PATH" NYXSTONE_LLVM_PREFIX=/opt/homebrew/opt/llvm@18 \
  poetry run python tests/scripts/android/a10_q3_gate.py \
      --corpus ~/sandbox/android-corpus [--main-tree /tmp/blint-main] [--json PATH]
"""

from __future__ import annotations

import argparse
import contextlib
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


def run_join(repo: Path, apk: str, confirm: bool) -> tuple[dict, float]:
    """The join from ``repo``'s code (main tree or this tree), listing cap
    lifted so every row is enumerable."""
    import importlib


    for module in [m for m in list(sys.modules) if m.startswith("blint")]:
        del sys.modules[module]
    sys.path.insert(0, str(repo))
    try:
        jni = importlib.import_module("blint.lib.jni")
        android_native = importlib.import_module("blint.lib.android_native")
    finally:
        sys.path.remove(str(repo))
    native = android_native.scan_android_native(apk)
    original_cap = jni.JOIN_LISTING_CAP
    jni_module = sys.modules["blint.lib.jni"]
    jni_module.JOIN_LISTING_CAP = 10**6
    try:
        t0 = time.monotonic()
        join = jni_module.build_jni_join_summary(apk, native, confirm_findclass=confirm)
        wall = time.monotonic() - t0
    finally:
        jni_module.JOIN_LISTING_CAP = original_cap
    return join, wall


def oracle_starts(path: Path, abi: str) -> set[int]:
    """Function starts per llvm-readelf/llvm-objdump (never blint):
    dynsym+symtab FUNC symbols, eh_frame FDE coverage from
    --dwarf=frames, and .ARM.exidx rows on v7a."""
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


def measure(apk: Path, main_tree: Path | None) -> dict:
    print(f"== {apk.name}")
    report: dict = {}
    for label, repo, confirms in (
        ("after", REPO, (False, True)),
        *((( "main", main_tree, (False, True)),) if main_tree else ()),
    ):
        for confirm in confirms:
            join, wall = run_join(repo, str(apk), confirm)
            if join is None:
                report[f"{label}_confirm_{confirm}"] = {"absent": True}
                continue
            per_abi = {}
            marked = []
            for abi, abi_join in sorted(join["per_abi"].items()):
                counts = dict(abi_join["counts"])
                per_abi[abi] = counts
                for entry in abi_join.get("ambiguous_dynamic") or []:
                    if entry.get("candidates_registered_elsewhere"):
                        marked.append(
                            {"abi": abi, "class": entry["class"], "name": entry["name"]}
                        )
            report[f"{label}_confirm_{confirm}"] = {
                "wall_s": round(wall, 2),
                "counts": per_abi,
                "candidates_registered_elsewhere": marked,
            }
            print(
                f"  {label} confirm={confirm}: wall {wall:.2f}s "
                + json.dumps({a: f"{c['bound_dynamic']}/{c['ambiguous_dynamic']}/{c['unbound_dex_natives']}" for a, c in per_abi.items()})
                + (f" marked={len(marked)}" if marked else "")
            )
    return report


def fn_addr_oracle(apk: Path, report: dict) -> None:
    """Every bound row's fn_addr (Thumb bit cleared) is a function start in
    its own ABI's copy, per the readelf/objdump oracle."""
    join, _ = run_join(REPO, str(apk), True)
    if join is None:
        return
    with zipfile.ZipFile(str(apk)) as zf:
        member_abi = {}
        for info in zf.infolist():
            parts = info.filename.split("/")
            if len(parts) == 3 and parts[0] == "lib" and info.filename.endswith(".so"):
                member_abi.setdefault((parts[2], parts[1]), info.filename)
        starts_cache: dict[tuple[str, str], set[int]] = {}
        bad = 0
        checked = 0
        for abi, abi_join in sorted(join["per_abi"].items()):
            for entry in (abi_join.get("bound") or []) + (abi_join.get("bound_dynamic") or []):
                library = entry.get("library")
                fn_addr = entry.get("fn_addr")
                if not library or not fn_addr:
                    continue
                key = (library, abi)
                if key not in starts_cache:
                    member = member_abi.get(key)
                    if not member:
                        continue
                    with tempfile.NamedTemporaryFile(suffix=".so", delete=False) as handle:
                        handle.write(zf.read(member))
                        extracted = Path(handle.name)
                    starts_cache[key] = oracle_starts(extracted, abi)
                    extracted.unlink(missing_ok=True)
                checked += 1
                address = None
                with contextlib.suppress(TypeError, ValueError):
                    address = int(fn_addr, 16) & ~1
                if address is None or address not in starts_cache[key]:
                    bad += 1
                    print(f"   !! {abi} {entry.get('class')}.{entry.get('name')} "
                          f"{fn_addr} in {library} is not an oracle start")
        print(f"  oracle: {checked} bound rows checked, {bad} outside their ABI's starts")
        report["oracle"] = {"checked": checked, "bad": bad}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--main-tree", type=Path, default=None)
    parser.add_argument("--json", type=Path, default=None)
    args = parser.parse_args(argv)

    report: dict = {}
    for name, tier in APKS.items():
        apk = args.corpus / tier / name
        entry = measure(apk, args.main_tree)
        if name in (
            "com.blint.rnhello_1.apk",
            "app.organicmaps_26082718.apk",
            "org.videolan.vlc_13070108.apk",
            "im.vector.app_40106624.apk",
        ):
            fn_addr_oracle(apk, entry)
        report[name] = entry
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=1, default=str))
        print(f"wrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
