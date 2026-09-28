#!/usr/bin/env python3
"""R3 — identification sweep: every identification blint makes.

Walks the given files (ELFs, APKs or directories of either), runs the same
``parse()`` the detectors run inside, and prints one JSON line per
identification: the file, the engine (framework detector or blintdb), the
grade (replace / nested / hint), the version (if the evidence pins one) and
the version's source - the table the zero-false-identification gate is
graded on. APK members are read in place through the A1.1 model.

With --use-blintdb, APK native libraries are also matched against the local
blintdb exactly as ``blint sbom --use-blintdb`` would, and bare .so files
run the same match.

Usage:
  poetry run python tests/scripts/android/r3_identification_sweep.py \
      <path>... [--json PATH] [--use-blintdb]

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


def sweep_so(path: Path, use_blintdb: bool) -> list[dict]:
    from blint.db import build_symbol_source_map, detect_binaries_utilized
    from blint.lib.binary import parse

    metadata = parse(str(path))
    rows = []
    for record in metadata.get("frameworks") or []:
        rows.append(
            {
                "file": str(path),
                "engine": "framework",
                "framework": record.get("framework"),
                "version": record.get("version"),
                "grade": "hint" if record.get("hint_only") else (
                    "nested" if record.get("static") else "replace"
                ),
                "evidence": [
                    f"{e.get('what')} ({e.get('where')}): {e.get('value')}"
                    for e in record.get("evidence") or []
                ],
            }
        )
    if use_blintdb:
        from blint.lib.android_blintdb import (
            dynamic_symbol_names,
            framework_claims,
            metadata_soname,
            refuses_openssl_match,
        )

        detected, evidence = detect_binaries_utilized(
            symbol_source_map=build_symbol_source_map(metadata),
            binary_metadata=metadata,
        )
        # The APK path's same-bytes rules: the sweep reports framework rows,
        # so a record for the same project claims the match too.
        framework_keys = {r.get("framework") for r in metadata.get("frameworks") or []}
        claims = framework_claims(framework_keys, emitted=True)
        soname = metadata_soname(metadata)
        names = dynamic_symbol_names(metadata)
        for purl in sorted(detected):
            match = evidence.get(purl) or {}
            project = match.get("project_name")
            row = {"file": str(path), "engine": "blintdb", "framework": purl, "version": None}
            if claimant := claims.get(project):
                row.update(grade="superseded", evidence=[f"{claimant}:{project}"])
            elif project == "openssl" and refuses_openssl_match(soname, names, framework_keys):
                row.update(
                    grade="refused",
                    evidence=[f"TLS provider SONAME {soname} without OpenSSL 3 names"],
                )
            else:
                row.update(
                    grade="nested",
                    note=(
                        f"soname_match={soname in (match.get('matched_binary_names') or [])}"
                        f" score={match.get('score')}"
                        f" symbols={match.get('matched_symbol_count')}"
                    ),
                )
            rows.append(row)
    return rows


def sweep_apk(path: Path, use_blintdb: bool) -> tuple[list[dict], list[dict]]:
    """Identifications + app-level facts for one APK, members read in place."""
    from blint.lib.android import collect_app_metadata

    rows: list[dict] = []
    parent, components = collect_app_metadata(str(path), False, use_blintdb=use_blintdb)
    for component in components or []:
        props = component.properties or []
        evidence = [
            p.value for p in props if p.name == "blint:identification:evidence"
        ]
        children = component.components or []
        if not evidence and not children:
            continue
        # Which engine took the slot: a blintdb replace carries the
        # database statistics properties.
        engine = (
            "blintdb"
            if any(p.name.startswith("blint:blintdb:") for p in props)
            else "framework"
        )
        name = component.purl or ""
        if not name.startswith("pkg:android/"):
            rows.append(
                {
                    "file": f"{path.name}:{name}",
                    "engine": engine,
                    "framework": name,
                    "version": str(component.version.root) if component.version else None,
                    "grade": "replace",
                    "evidence": evidence,
                }
            )
        for child in children:
            child_props = child.properties or []
            version_sources = [
                p.value for p in child_props
                if p.name == "blint:identification:evidence" and "(" in p.value
                and any(k in p.value for k in (
                    "VERSION_STRING", "version_string", "banner", "chronology",
                    "SDK_VERSION", "release banner", "lib/zstd.h", "src/opus.c",
                    "png.h", "include/sentry.h", "Rel.",
                ))
            ]
            rows.append(
                {
                    "file": f"{path.name}:{name}",
                    "engine": (
                        "blintdb"
                        if any(p.name.startswith("blint:blintdb:") for p in child_props)
                        else "framework"
                    ),
                    "framework": child.purl or "",
                    "version": str(child.version.root) if child.version else None,
                    "version_source": version_sources[-1] if version_sources else None,
                    "grade": "nested",
                    "evidence": [
                        p.value for p in child_props
                        if p.name == "blint:identification:evidence"
                    ],
                }
            )
        for prop in props:
            if prop.name == "blint:blintdb:superseded_by_framework":
                rows.append(
                    {
                        "file": f"{path.name}:{name}",
                        "engine": "blintdb",
                        "framework": prop.value,
                        "version": None,
                        "grade": "superseded",
                        "evidence": [prop.value],
                    }
                )
        for prop in props:
            if prop.name.startswith("blint:identification:") and prop.name != "blint:identification:evidence":
                rows.append(
                    {
                        "file": f"{path.name}:{name}",
                        "engine": "framework",
                        "framework": prop.name.removeprefix("blint:identification:"),
                        "version": None,
                        "grade": "hint",
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
    parser.add_argument(
        "--use-blintdb", action="store_true", help="match native libraries against the local blintdb"
    )
    args = parser.parse_args()

    all_rows: list[dict] = []
    all_facts: list[dict] = []
    for raw in args.paths:
        root = Path(raw).expanduser()
        if root.is_file():
            targets = [root]
        elif root.is_dir():
            targets = sorted(
                p for p in root.rglob("*") if p.suffix in (".so", ".apk") and p.is_file()
            )
        else:
            targets = []
        for target in targets:
            if target.suffix == ".apk":
                rows, facts = sweep_apk(target, args.use_blintdb)
                all_rows.extend(rows)
                all_facts.extend({"file": target.name, **f} for f in facts)
            else:
                all_rows.extend(sweep_so(target, args.use_blintdb))

    for row in all_rows:
        print(json.dumps(row))
    for fact in all_facts:
        print(json.dumps({"app_fact": fact}))
    if args.json_path:
        Path(args.json_path).write_text(
            json.dumps({"identifications": all_rows, "app_facts": all_facts}, indent=2) + "\n"
        )
    grades = {}
    for row in all_rows:
        grades[row["grade"]] = grades.get(row["grade"], 0) + 1
    print(f"# {len(all_rows)} identifications {grades}, {len(all_facts)} app facts", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
