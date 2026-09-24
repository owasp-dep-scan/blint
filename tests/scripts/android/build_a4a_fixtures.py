#!/usr/bin/env python3
"""A4a T1 — build the R1-R3 fixture ladder with NDK r28 clang.

Rungs (see the wave's GLM-PROMPT):

- R1: ``a4a_sources/r1_functions.c`` (10 static functions + one export) built
  ``-g -shared -fPIC`` for all five ABIs; armeabi-v7a gets explicit ``-mthumb``
  and ``-marm`` twins so each build is one function set in one mode.
- R2: ``a4a_sources/r2_interwork.c`` (ARM/Thumb interworking, tbb/tbh switch
  tables, literal pools, mapping symbols) built the same way.
- R3: llvm-stripped copies of the armeabi-v7a R1/R2 builds (dynsym only).

Fixtures land in $ANDROID_CORPUS_ROOT/a4a-fixtures (default
~/sandbox/android-corpus/a4a-fixtures) with a MANIFEST.json naming the exact
compiler, flags and versions. ``--commit-set`` additionally copies the small
subset unit tests read into tests/data/android/.

Every machine-code fixture in the repository comes from this real build; the
oracle text comes from the NDK llvm tools in the same run.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SOURCES = Path(__file__).resolve().parent / "a4a_sources"

ABI_CLANG = {
    "arm64-v8a": "aarch64-linux-android24-clang",
    "armeabi-v7a": "armv7a-linux-androideabi24-clang",
    "x86_64": "x86_64-linux-android24-clang",
    "x86": "i686-linux-android24-clang",
    # riscv64 Android exists from API 35; the NDK ships wrappers from there.
    "riscv64": "riscv64-linux-android35-clang",
}

# The fixtures unit tests read (force-added; *.so is gitignored).
COMMIT_SET = (
    "liba4a_r1_thumb.so",
    "liba4a_r1_arm.so",
    "liba4a_r2.so",
    "liba4a_r1_arm64-v8a.so",
    "liba4a_r1_thumb_stripped.so",
    "liba4a_r2_stripped.so",
)


def find_ndk(want_prefix: str = "28.") -> Path:
    root = Path(os.environ.get("ANDROID_SDK_ROOT") or Path.home() / "Android" / "sdk") / "ndk"
    for ndk in sorted((entry for entry in root.iterdir() if entry.name.startswith(want_prefix)), reverse=True):
        return ndk
    raise SystemExit(f"no NDK {want_prefix}* under {root}; set ANDROID_SDK_ROOT")


def run(cmd: list[str]) -> subprocess.CompletedProcess:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        print(f"FAILED: {' '.join(cmd)}\n{proc.stderr}", file=sys.stderr)
        raise SystemExit(proc.returncode)
    return proc


def first_version_line(tool: Path) -> str:
    proc = subprocess.run([str(tool), "--version"], capture_output=True, text=True)
    return (proc.stdout or "").strip().splitlines()[0]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--out",
        type=Path,
        default=Path(os.environ.get("ANDROID_CORPUS_ROOT") or Path.home() / "sandbox" / "android-corpus")
        / "a4a-fixtures",
    )
    parser.add_argument("--commit-set", action="store_true", help="copy the test subset into tests/data/android/")
    args = parser.parse_args(argv)

    ndk = find_ndk()
    bin_dir = next((ndk / "toolchains" / "llvm" / "prebuilt").glob("*/bin"))
    strip_tool = bin_dir / "llvm-strip"
    args.out.mkdir(parents=True, exist_ok=True)
    manifest: dict = {
        "ndk": ndk.name,
        "clang": first_version_line(bin_dir / "clang"),
        "llvm_strip": first_version_line(strip_tool),
        "sources": {p.name: p.read_text(encoding="utf-8").splitlines()[1].strip(" *") for p in sorted(SOURCES.glob("*.c"))},
        "builds": {},
    }

    def build(name: str, source: Path, abi: str, extra: list[str]) -> Path:
        clang = bin_dir / ABI_CLANG[abi]
        out_path = args.out / name
        cmd = [str(clang), "-g", "-O2", "-fno-inline", "-shared", "-fPIC", *extra, "-o", str(out_path), str(source)]
        run(cmd)
        manifest["builds"][name] = {"command": " ".join(cmd), "source": source.name, "abi": abi}
        return out_path

    # R1 across the five ABIs; armeabi-v7a gets explicit-mode twins.
    for abi in ABI_CLANG:
        build(f"liba4a_r1_{abi}.so", SOURCES / "r1_functions.c", abi, [])
    build("liba4a_r1_thumb.so", SOURCES / "r1_functions.c", "armeabi-v7a", ["-mthumb"])
    build("liba4a_r1_arm.so", SOURCES / "r1_functions.c", "armeabi-v7a", ["-marm"])
    # R2 on armeabi-v7a (interworking lives there) plus the other ABIs as controls.
    for abi in ABI_CLANG:
        build(f"liba4a_r2_{abi}.so", SOURCES / "r2_interwork.c", abi, [])
    build("liba4a_r2.so", SOURCES / "r2_interwork.c", "armeabi-v7a", ["-mthumb"])

    # R3: stripped twins (symtab gone, dynsym kept).
    for unstripped, stripped in (
        ("liba4a_r1_thumb.so", "liba4a_r1_thumb_stripped.so"),
        ("liba4a_r1_arm.so", "liba4a_r1_arm_stripped.so"),
        ("liba4a_r2.so", "liba4a_r2_stripped.so"),
    ):
        src = args.out / unstripped
        dst = args.out / stripped
        shutil.copy2(src, dst)
        cmd = [str(strip_tool), "--strip-all", str(dst)]
        run(cmd)
        manifest["builds"][stripped] = {"command": " ".join(cmd), "stripped_from": unstripped}

    (args.out / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"built {len(manifest['builds'])} fixtures in {args.out}")

    if args.commit_set:
        dest = REPO / "tests" / "data" / "android"
        for name in COMMIT_SET:
            shutil.copy2(args.out / name, dest / name)
            print(f"committed-set copy: {dest / name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
