#!/usr/bin/env python3
"""R3 — identification sweep: every framework identification blint makes.

Walks the given files (ELFs, APKs or directories of either), runs the same
``parse()`` the detectors run inside, and prints one JSON line per
identification: the file, the framework, the version (if the evidence pins
one), and the evidence values - the table the zero-false-identification
gate is graded on. APK members are read in place through the A1.1 model.

Usage:
  poetry run python tests/scripts/android/r3_identification_sweep.py \
      <path>... [--json PATH]

Exit code is always 0 - the sweep is a measurement, the hand check is the
gate.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))


def iter_so_files(root: Path):
    if root.is_file() and root.suffix == ".so":
        yield root
    elif root.is_dir():
        for path in sorted(root.rglob("*.so")):
            if path.is_file():
                yield path


def sweep_so(path: Path) -> list[dict]:
    from blint.lib.binary import parse

    metadata = parse(str(path))
    rows = []
    for record in metadata.get("frameworks") or []:
        rows.append(
            {
                "file": str(path),
                "framework": record.get("framework"),
                "version": record.get("version"),
                "static": bool(record.get("static")),
                "hint_only": bool(record.get("hint_only")),
                "evidence": [
                    f"{e.get('what')} ({e.get('where')}): {e.get('value')}"
                    for e in record.get("evidence") or []
                ],
            }
        )
    return rows


def sweep_apk(path: Path) -> tuple[list[dict], list[dict]]:
    """Identifications + app-level facts for one APK, members read in place."""
    from blint.lib.android import collect_app_metadata

    rows: list[dict] = []
    parent, components = collect_app_metadata(str(path), False)
    for component in components or []:
        for prop in component.properties or []:
            if prop.name == "blint:identification:evidence":
                purl = component.purl or ""
                rows.append(
                    {
                        "file": f"{path.name}:{purl}",
                        "framework": purl,
                        "version": str(component.version.root) if component.version else None,
                        "static": False,
                        "evidence": [prop.value],
                    }
                )
    facts = []
    for prop in (parent.properties if parent else []) or []:
        if prop.name in ("blint:ndk_versions", "blint:hermes_bytecode_version"):
            facts.append({"fact": prop.name, "value": prop.value})
    return rows, facts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("paths", nargs="+")
    parser.add_argument("--json", dest="json_path", help="also write the full table as JSON")
    args = parser.parse_args()

    all_rows: list[dict] = []
    all_facts: list[dict] = []
    for raw in args.paths:
        root = Path(raw).expanduser()
        targets = [root] if root.is_file() else sorted(
            p for p in root.rglob("*") if p.suffix in (".so", ".apk")
            and p.is_file()
        ) if root.is_dir() else []
        if root.is_file() and root.suffix == ".apk":
            targets = [root]
        for target in targets:
            if target.suffix == ".apk":
                rows, facts = sweep_apk(target)
                all_rows.extend(rows)
                all_facts.extend({"file": target.name, **f} for f in facts)
            else:
                all_rows.extend(sweep_so(target))

    for row in all_rows:
        print(json.dumps(row))
    for fact in all_facts:
        print(json.dumps({"app_fact": fact}))
    if args.json_path:
        Path(args.json_path).write_text(
            json.dumps({"identifications": all_rows, "app_facts": all_facts}, indent=2) + "\n"
        )
    print(f"# {len(all_rows)} identifications, {len(all_facts)} app facts", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
