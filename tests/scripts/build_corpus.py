#!/usr/bin/env python3
"""Materialize the evaluation corpus described by tests/corpus/manifest.json.

No binary blobs are stored in git. This script builds the corpus entries from
local toolchains (clang, cargo+rust-lld, go) and collects real-world binaries
from this machine (system executables, installed applications) into a single
directory that tests/scripts/validate_funcdisc.py then runs assertions over.

Usage:
    python tests/scripts/build_corpus.py [--dir corpus-build] [--force]
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = REPO_ROOT / "tests" / "corpus" / "manifest.json"
DEFAULT_OUT = REPO_ROOT / "corpus-build"


def _run(cmd: list[str], cwd: Path | None = None, env: dict | None = None) -> None:
    print(f"  $ {' '.join(str(c) for c in cmd)}")
    merged_env = None
    if env:
        import os

        merged_env = {**os.environ, **{k: str(v) for k, v in env.items()}}
    result = subprocess.run(
        [str(c) for c in cmd], cwd=cwd, env=merged_env, capture_output=True, text=True
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(str(c) for c in cmd)}\n"
            f"{result.stdout}\n{result.stderr}"
        )


def _strip(binary: Path, strip_with: str | None) -> None:
    if strip_with:
        _run([strip_with, binary])
    else:
        _run(["strip", binary])


def build_clang(spec: dict, out_dir: Path) -> list[str]:
    source = REPO_ROOT / spec["source"]
    produced = []
    for artifact in spec["artifacts"]:
        target = out_dir / artifact["name"]
        _run(["clang", *artifact.get("flags", []), "-o", target, source])
        if artifact.get("strip"):
            _strip(target, artifact.get("strip_with"))
        produced.append(artifact["name"])
    for post in spec.get("post") or []:
        if post["kind"] == "lipo":
            _run(
                ["lipo", "-create", *map(lambda i: out_dir / i, post["inputs"]),
                 "-output", out_dir / post["output"]]
            )
            produced.append(post["output"])
        elif post["kind"] == "codesign":
            _run(["codesign", *post.get("flags", []), out_dir / post["input"]])
    return produced


def build_cargo(spec: dict, out_dir: Path) -> list[str]:
    source = REPO_ROOT / spec["source"]
    target = spec["target"]
    linker = "rust-lld"
    cargo_config = source / ".cargo" / "config.toml"
    cargo_config.parent.mkdir(parents=True, exist_ok=True)
    cargo_config.write_text(
        f'[target.{target}]\nlinker = "{linker}"\n'
        f'rustflags = ["-C", "target-feature=+crt-static"]\n'
    )
    built = source / "target" / target / "release" / source.name.replace("-", "_")
    if not built.exists():
        built = source / "target" / target / "release" / source.stem
    _run(["cargo", "build", "--release", "--target", target], cwd=source)
    produced = []
    for artifact in spec["artifacts"]:
        target_path = out_dir / artifact["name"]
        shutil.copy2(built, target_path)
        if artifact.get("strip"):
            _strip(target_path, artifact.get("strip_with") or "llvm-strip")
        produced.append(artifact["name"])
    return produced


def build_go(spec: dict, out_dir: Path) -> list[str]:
    source = REPO_ROOT / spec["source"]
    produced = []
    for artifact in spec["artifacts"]:
        # Resolve before running: go build interprets -o relative to cwd.
        target = (out_dir / artifact["name"]).resolve()
        cmd = ["go", "build"]
        if artifact.get("go_strip_flags"):
            cmd += ["-ldflags", artifact["go_strip_flags"]]
        cmd += ["-o", str(target), "."]
        _run(cmd, cwd=source, env=artifact.get("env"))
        if artifact.get("strip") and not artifact.get("go_strip_flags"):
            _strip(target, artifact.get("strip_with"))
        produced.append(artifact["name"])
    return produced


def _copy_binary(src: Path, target: Path) -> bool:
    """Copy a system binary without inheriting its restricted file flags."""
    try:
        with open(src, "rb") as src_handle, open(target, "wb") as dst_handle:
            shutil.copyfileobj(src_handle, dst_handle)
        target.chmod(0o555)
        return True
    except (OSError, PermissionError) as e:
        print(f"  ! cannot collect {src}: {e}")
        target.unlink(missing_ok=True)
        return False


def collect_entries(spec: dict, out_dir: Path) -> list[str]:
    kind = spec["kind"]
    produced = []
    if kind == "paths":
        for entry in spec["entries"]:
            src = Path(entry["path"])
            if src.exists() and _copy_binary(src, out_dir / entry["name"]):
                produced.append(entry["name"])
            elif not src.exists():
                print(f"  ! skipping missing {src}")
    elif kind == "apps":
        apps = sorted(Path("/Applications").glob("*.app"))
        apps += sorted(Path.home().joinpath("Applications").glob("*.app"))
        count = 0
        for app in apps:
            if count >= int(spec.get("limit", 5)):
                break
            macos_dir = app / "Contents" / "MacOS"
            if not macos_dir.is_dir():
                continue
            for binary in sorted(macos_dir.iterdir()):
                if not binary.is_file() or binary.stat().st_size == 0:
                    continue
                name = f"app-{binary.name}"
                target = out_dir / name
                if target.exists():
                    produced.append(name)
                    count += 1
                    break
                if _copy_binary(binary, target):
                    produced.append(name)
                    count += 1
                    break
    return produced


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dir", type=Path, default=DEFAULT_OUT, help="output directory")
    parser.add_argument("--force", action="store_true", help="rebuild existing artifacts")
    args = parser.parse_args()
    manifest = json.loads(MANIFEST_PATH.read_text())
    out_dir: Path = args.dir
    out_dir.mkdir(parents=True, exist_ok=True)

    failures = []
    for name, spec in (manifest.get("build") or {}).items():
        print(f"build: {name}")
        try:
            builder = {"clang": build_clang, "cargo": build_cargo, "go": build_go}[spec["kind"]]
            for produced in builder(spec, out_dir):
                print(f"  -> {produced}")
        except (RuntimeError, FileNotFoundError, KeyError) as e:
            print(f"  ! build failed: {e}")
            failures.append(name)

    for name, spec in (manifest.get("collect") or {}).items():
        print(f"collect: {name}")
        for produced in collect_entries(spec, out_dir):
            print(f"  -> {produced}")

    print(f"\ncorpus directory: {out_dir}")
    if failures:
        print("build failures:", ", ".join(failures))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
