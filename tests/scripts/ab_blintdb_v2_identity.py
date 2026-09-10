# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT
"""A/B byte-identity gate for the blintdb v2 path (P4.2a, extended by P4.3).

Proves the similarity-hash columns (P4.2a) and the member-level + banner
layers (P4.3) are additive: with a v2 database, matches, scores and SBOM
component attribution are byte-identical to the base commit.

The script builds one v2 blintdb from a fixture binary's own metadata (exact
instruction/assembly hashes, symbols, binary name), then runs the SAME lookup
and SBOM flow against two checkouts — the current tree and a worktree at the
base commit — using this repo's virtualenv for both. Three artifacts are
compared per checkout:

1. the ``lookup_project_matches`` / ``detect_binaries_utilized`` result dump,
2. the SBOM JSON produced by ``blint sbom --use-blintdb``,
3. a no-match control (a binary absent from the database).

Comparison runs twice: raw, and after removing the keys this packet declares
additive (the ``internal:blintdb_matched_{fuzzy,cfg,import}_*`` component
properties and ``internal:blintdb_fuzzy_layer``). The gate passes when the
filtered comparison is byte-identical and the raw comparison differs only by
those declared-additive keys.

Usage:

    git worktree add /tmp/blint-base f2b1cca
    python tests/scripts/ab_blintdb_v2_identity.py --other-checkout /tmp/blint-base \
        --fixture corpus-build/stackstr-arm64 --control corpus-build/bin-ls
"""

import argparse
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# Component properties this packet adds. Everything else in the SBOM and in
# the lookup dumps must be byte-identical to the base commit.
ADDITIVE_PROPERTY_NAMES = {
    "internal:blintdb_matched_fuzzy_hash_count",
    "internal:blintdb_matched_fuzzy_hashes",
    "internal:blintdb_matched_cfg_hash_count",
    "internal:blintdb_matched_cfg_hashes",
    "internal:blintdb_matched_import_hash_count",
    "internal:blintdb_matched_import_hashes",
    "internal:blintdb_fuzzy_layer",
    # P4.3: the attribution label every blintdb component now carries, the
    # member-layer evidence keys, and the vendored-banner properties. On a
    # member-less database the member keys are absent; the attribution label
    # and banner properties are the only ones a v2 run can still emit.
    "internal:blintdb_attribution",
    "internal:blintdb_member_layer",
    "internal:blintdb_matched_member_count",
    "internal:blintdb_member_names",
    "internal:blintdb_member_details",
    "internal:vendored_banner_layer",
    "internal:vendored_attribution",
    "internal:vendored_banner",
}
ADDITIVE_MATCH_KEYS = {
    "matched_fuzzy_hash_count",
    "matched_fuzzy_hashes",
    "matched_cfg_hash_count",
    "matched_cfg_hashes",
    "matched_import_hash_count",
    "matched_import_hashes",
    # P4.3 member-layer evidence keys, present on evidence rows only when the
    # member layer fired.
    "blintdb_attribution",
    "blintdb_member_layer",
    "blintdb_matched_member_count",
    "blintdb_member_score",
    "blintdb_members",
}

DRIVER = """
import json
import sys

from blint.db import (
    build_function_hash_index,
    build_symbol_source_map,
    detect_binaries_utilized,
    lookup_project_matches,
)

db_file, metadata_file, out_file = sys.argv[1], sys.argv[2], sys.argv[3]
metadata = json.load(open(metadata_file))
symbol_source_map = build_symbol_source_map(metadata)
function_hash_index = build_function_hash_index(metadata)
matches = lookup_project_matches(
    symbol_source_map,
    function_hash_index=function_hash_index,
    binary_metadata=metadata,
    db_file=db_file,
)
detected, evidence = detect_binaries_utilized(
    symbol_source_map=symbol_source_map,
    function_hash_index=function_hash_index,
    binary_metadata=metadata,
    db_file=db_file,
)
json.dump(
    {"matches": matches, "detected": sorted(detected), "evidence": evidence},
    open(out_file, "w"),
    sort_keys=True,
    indent=1,
)
"""


def run_blint(
    checkout: Path,
    venv_python: Path,
    blint_args: list[str],
    *,
    blintdb_home: Path | None = None,
) -> None:
    blint_entry = (
        "import sys; sys.argv = ['blint'] + sys.argv[1:];"
        " from blint.cli import main; main()"
    )
    env = dict(os.environ)
    if blintdb_home:
        # Without this the run would silently use the user's default blintdb
        # (or none) and the SBOM comparison would pass vacuously.
        env["BLINTDB_HOME"] = str(blintdb_home)
    subprocess.run(
        [
            str(venv_python),
            "-c",
            blint_entry,
            *blint_args,
        ],
        cwd=checkout,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )


def build_v2_db(db_file: Path, metadata: dict, artifact_name: str) -> None:
    """A v2 blintdb holding one project made of the fixture binary itself."""
    connection = sqlite3.connect(db_file)
    connection.executescript(
        """
        CREATE TABLE SchemaMeta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE Projects (
            project_id INTEGER PRIMARY KEY, name TEXT NOT NULL, purl TEXT
        );
        CREATE TABLE Builds (
            build_id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL,
            llvm_target_tuple TEXT
        );
        CREATE TABLE Binaries (
            binary_id INTEGER PRIMARY KEY, build_id INTEGER NOT NULL, name TEXT,
            binary_type TEXT, llvm_target_tuple TEXT
        );
        CREATE TABLE Symbols (
            symbol_id INTEGER PRIMARY KEY, binary_id INTEGER NOT NULL,
            name TEXT NOT NULL, source TEXT NOT NULL
        );
        CREATE TABLE FunctionFingerprints (
            function_id INTEGER PRIMARY KEY, binary_id INTEGER NOT NULL,
            function_key TEXT NOT NULL, instruction_hash TEXT, assembly_hash TEXT
        );
        CREATE INDEX idx_symbols_lookup ON Symbols(name, source, binary_id);
        CREATE INDEX idx_ff_i ON FunctionFingerprints(instruction_hash, binary_id);
        CREATE INDEX idx_ff_a ON FunctionFingerprints(assembly_hash, binary_id);
        """
    )
    connection.executemany(
        "INSERT INTO SchemaMeta(key, value) VALUES(?, ?)",
        (("schema_family", "blint-db"), ("schema_version", "2")),
    )
    connection.execute(
        "INSERT INTO Projects(project_id, name, purl)"
        " VALUES(1, 'fixture', 'pkg:generic/fixture@1.0.0')"
    )
    connection.execute(
        "INSERT INTO Builds(build_id, project_id, llvm_target_tuple) VALUES(1, 1, ?)",
        (metadata.get("llvm_target_tuple"),),
    )
    connection.execute(
        "INSERT INTO Binaries(binary_id, build_id, name, binary_type, llvm_target_tuple)"
        " VALUES(1, 1, ?, ?, ?)",
        (artifact_name, metadata.get("binary_type"), metadata.get("llvm_target_tuple")),
    )
    symbols = []
    for source in ("symtab_symbols", "dynamic_symbols", "imports"):
        for entry in (metadata.get(source) or [])[:40]:
            if isinstance(entry, dict) and entry.get("name"):
                symbols.append((1, entry["name"], source))
    connection.executemany(
        "INSERT OR IGNORE INTO Symbols(binary_id, name, source) VALUES(?, ?, ?)", symbols
    )
    rows = []
    for function_key, func_data in (metadata.get("disassembled_functions") or {}).items():
        if isinstance(func_data, dict) and (
            func_data.get("instruction_hash") or func_data.get("assembly_hash")
        ):
            rows.append(
                (
                    1,
                    function_key,
                    func_data.get("instruction_hash"),
                    func_data.get("assembly_hash"),
                )
            )
    connection.executemany(
        "INSERT INTO FunctionFingerprints(binary_id, function_key, instruction_hash,"
        " assembly_hash) VALUES(?, ?, ?, ?)",
        rows,
    )
    connection.commit()
    connection.close()


def strip_additive(payload: str) -> str:
    """Remove this packet's additive keys from a lookup-dump artifact."""
    data = json.loads(payload)
    for match in data.get("matches", []):
        for key in ADDITIVE_MATCH_KEYS:
            match.pop(key, None)
    for evidence in data.get("evidence", {}).values():
        for key in ADDITIVE_MATCH_KEYS:
            evidence.pop(key, None)
    return json.dumps(data, sort_keys=True, indent=1)


def strip_sbom_additive(payload: str) -> str:
    data = json.loads(payload)
    # Per-run CycloneDX nondeterminism, not a tree difference.
    data.pop("serialNumber", None)
    if isinstance(data.get("metadata"), dict):
        data["metadata"].pop("timestamp", None)

    def walk(node):
        if isinstance(node, dict):
            properties = node.get("properties")
            if isinstance(properties, list):
                node["properties"] = [
                    prop
                    for prop in properties
                    if prop.get("name") not in ADDITIVE_PROPERTY_NAMES
                ]
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(data)
    return json.dumps(data, sort_keys=True, indent=1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--other-checkout", required=True)
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--control", default=None, help="binary NOT in the database")
    parser.add_argument("--work-dir", default=None)
    args = parser.parse_args()

    other_checkout = Path(args.other_checkout).resolve()
    fixture = Path(args.fixture).resolve()
    control = Path(args.control).resolve() if args.control else None
    venv_python = REPO_ROOT / ".venv" / "bin" / "python"
    if not venv_python.exists():
        print("virtualenv python not found; run inside the repo checkout", file=sys.stderr)
        return 2

    work_dir = (
        Path(args.work_dir).resolve() if args.work_dir else Path(tempfile.mkdtemp()).resolve()
    )
    # blint opens databases through apsw with SQLITE_OPEN_NOFOLLOW, which
    # rejects symlinked path components, so the work dir must be resolved.
    (work_dir / "blintdb").mkdir(parents=True, exist_ok=True)
    artifact_name = fixture.name
    print(f"fixture: {fixture}")
    print(f"base checkout: {other_checkout}")

    # Export metadata once with the current tree; both checkouts read the same
    # disassembly input, so the only variable under test is the db code.
    run_blint(
        REPO_ROOT,
        venv_python,
        [
            "-q",
            "--no-banner",
            "--no-reviews",
            "--disassemble",
            "-i",
            str(fixture),
            "-o",
            str(work_dir / "meta-fixture"),
        ],
    )
    metadata_file = next(
        path
        for path in (work_dir / "meta-fixture").glob("*-metadata.json")
        if path.stem.lower() == f"{artifact_name.lower()}-metadata"
    )
    metadata = json.loads(metadata_file.read_text())
    db_file = work_dir / "blintdb" / "blint.db"
    build_v2_db(db_file, metadata, artifact_name)

    runs = [("fixture", fixture, metadata_file)]
    control_metadata_file = None
    if control:
        run_blint(
            REPO_ROOT,
            venv_python,
            [
                "-q",
                "--no-banner",
                "--no-reviews",
                "--disassemble",
                "-i",
                str(control),
                "-o",
                str(work_dir / "meta-control"),
            ],
        )
        control_metadata_file = next(
            (work_dir / "meta-control").glob("*-metadata.json")
        )
        runs.append(("control", control, control_metadata_file))

    for label, checkout in (("current", REPO_ROOT), ("base", other_checkout)):
        for run_label, binary, meta_file in runs:
            suffix = "" if run_label == "fixture" else f"-{run_label}"
            driver_file = work_dir / "_ab_driver.py"
            driver_file.write_text(DRIVER)
            driver_env = dict(
                os.environ,
                PYTHONPATH=str(checkout),
                BLINTDB_HOME=str(work_dir / "blintdb"),
            )
            subprocess.run(
                [
                    str(venv_python),
                    str(driver_file),
                    str(db_file),
                    str(meta_file),
                    str(work_dir / f"lookup{suffix}-{label}.json"),
                ],
                cwd=checkout,
                env=driver_env,
                check=True,
                capture_output=True,
                text=True,
            )
            run_blint(
                checkout,
                venv_python,
                [
                    "-q",
                    "sbom",
                    "--use-blintdb",
                    "-i",
                    str(binary),
                    "-o",
                    str(work_dir / f"sbom{suffix}-{label}.json"),
                ],
                blintdb_home=work_dir / "blintdb",
            )

    failures = []
    raw_equal = {}
    for suffix in ("", "-control"):
        lookup_current = (work_dir / f"lookup{suffix}-current.json").read_text()
        lookup_base = (work_dir / f"lookup{suffix}-base.json").read_text()
        if strip_additive(lookup_current) != strip_additive(lookup_base):
            failures.append(f"lookup dump{suffix} differs beyond the additive keys")
        sbom_current = (work_dir / f"sbom{suffix}-current.json").read_text()
        sbom_base = (work_dir / f"sbom{suffix}-base.json").read_text()
        if strip_sbom_additive(sbom_current) != strip_sbom_additive(sbom_base):
            failures.append(f"SBOM{suffix} differs beyond the additive component properties")
        raw_equal[suffix or "fixture"] = sbom_current == sbom_base

    current_matches = json.loads((work_dir / "lookup-current.json").read_text())["matches"]
    print(f"\nlookup matches (current tree): {len(current_matches)}")
    for label, equal in raw_equal.items():
        print(f"SBOM {label} raw identical: {equal}")
    if failures:
        print("\nFAIL:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(
        "\nPASS: v2-database behavior is byte-identical to the base commit "
        "outside the declared additive keys."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
