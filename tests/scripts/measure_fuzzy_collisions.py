# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT
"""Measure cross-project collision rates for the blintdb similarity hash columns.

P4.2a ground work: the fuzzy-hash floor (MIN_FUNCTION_INSTRUCTION_COUNT_FOR_FUZZY_HASH_LOOKUP)
and the fuzzy-only attribution threshold must come from this measurement, not taste.

Input: a directory of ``*-metadata.json`` exports produced by running

    blint -q --no-banner --no-reviews --disassemble -i <binary> -o <reports-dir>

over a set of binaries from known projects. Every artifact name is mapped to a
ground-truth project via --project-map (JSON file) or the built-in corpus-build
grouping: the stackstr/go/rust variant families are single projects; every other
artifact is its own project.

For each instruction-count floor the script reports:

- how many functions (and distinct fuzzy hashes) survive the floor,
- how many fuzzy-hash values are shared by two or more *different* projects
  (cross-project collisions) and what fraction of functions they carry,
- the worst per-project-pair overlaps (these bound how much fuzzy evidence an
  unrelated project can accumulate and therefore where the fuzzy-only
  attribution threshold must sit),
- the same collision numbers for cfg_hash (the justification for giving the CFG
  layer zero score weight), and
- import_hash uniqueness across the binaries.

Finally it builds an in-memory v3-style blintdb from all projects, queries it
with every binary through the real ``lookup_project_matches`` path, and reports
every attribution that does not point at the queried binary's own project —
the false-attribution gate.

Usage:

    python tests/scripts/measure_fuzzy_collisions.py --reports-dir corpus-metadata
"""

import argparse
import json
import re
import sqlite3
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from blint import db as db_module
from blint.db import (
    build_function_hash_index,
    build_symbol_source_map,
    lookup_project_matches,
)

# corpus-build artifact name prefix -> ground-truth project.
_CORPUS_PROJECT_RULES = [
    (r"^stackstr", "stackstr"),
    (r"^go-elf", "go"),
    (r"^rust-elf", "rust"),
]

FLOORS = [4, 6, 8, 12, 16, 24]


def load_project_map(path: Path | None) -> dict[str, str]:
    if not path:
        return {}
    return {entry["artifact"]: entry["project"] for entry in json.loads(path.read_text())}


def project_for(artifact: str, overrides: dict[str, str]) -> str:
    if artifact in overrides:
        return overrides[artifact]
    for pattern, project in _CORPUS_PROJECT_RULES:
        if re.match(pattern, artifact):
            return project
    return artifact


def collect_functions(metadata: dict) -> list[dict]:
    functions = []
    for function_key, func_data in (metadata.get("disassembled_functions") or {}).items():
        if not isinstance(func_data, dict):
            continue
        fuzzy_hash = func_data.get("fuzzy_hash")
        if not fuzzy_hash:
            continue
        functions.append(
            {
                "function_key": function_key,
                "instruction_count": int(func_data.get("instruction_count") or 0),
                "fuzzy_hash": fuzzy_hash,
                "cfg_hash": func_data.get("cfg_hash") or "",
            }
        )
    return functions


def collision_report(entries: list[dict], floor: int, hash_key: str) -> dict:
    """Cross-project collision statistics for one hash kind at one floor."""
    at_floor = [entry for entry in entries if entry["instruction_count"] >= floor]
    by_hash: dict[str, set[str]] = defaultdict(set)
    for entry in at_floor:
        by_hash[entry[hash_key]].add(entry["project"])
    colliding_values = {value for value, projects in by_hash.items() if len(projects) > 1}
    colliding_functions = [entry for entry in at_floor if entry[hash_key] in colliding_values]
    # Per-project-pair overlap: distinct shared values between two projects.
    pair_values: dict[tuple[str, str], set[str]] = defaultdict(set)
    for value, projects in by_hash.items():
        if len(projects) < 2:
            continue
        names = sorted(projects)
        for i, left in enumerate(names):
            for right in names[i + 1 :]:
                pair_values[(left, right)].add(value)
    worst_pairs = sorted(
        ((pair, len(values)) for pair, values in pair_values.items()),
        key=lambda item: item[1],
        reverse=True,
    )[:5]
    return {
        "floor": floor,
        "functions": len(at_floor),
        "distinct_values": len(by_hash),
        "colliding_values": len(colliding_values),
        "colliding_functions": len(colliding_functions),
        "collision_rate": (
            len(colliding_functions) / len(at_floor) if at_floor else 0.0
        ),
        "worst_pairs": worst_pairs,
    }


def build_v3_db(connection: sqlite3.Connection, artifacts: dict[str, dict]) -> None:
    """Create a v3-style blintdb subset populated from exported metadata."""
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
            binary_type TEXT, llvm_target_tuple TEXT, import_hash TEXT
        );
        CREATE TABLE Symbols (
            symbol_id INTEGER PRIMARY KEY, binary_id INTEGER NOT NULL,
            name TEXT NOT NULL, source TEXT NOT NULL
        );
        CREATE TABLE FunctionFingerprints (
            function_id INTEGER PRIMARY KEY, binary_id INTEGER NOT NULL,
            function_key TEXT NOT NULL, instruction_hash TEXT, assembly_hash TEXT,
            fuzzy_hash TEXT, cfg_hash TEXT, instruction_count INTEGER
        );
        CREATE INDEX idx_ff_fuzzy ON FunctionFingerprints(fuzzy_hash);
        CREATE INDEX idx_ff_cfg ON FunctionFingerprints(cfg_hash);
        CREATE INDEX idx_binaries_import ON Binaries(import_hash);
        """
    )
    connection.executemany(
        "INSERT INTO SchemaMeta(key, value) VALUES(?, ?)",
        (("schema_family", "blint-db"), ("schema_version", "3")),
    )
    project_ids: dict[str, int] = {}
    binary_id = 0
    for artifact, data in sorted(artifacts.items()):
        project = data["project"]
        if project not in project_ids:
            project_ids[project] = len(project_ids) + 1
            connection.execute(
                "INSERT INTO Projects(project_id, name, purl) VALUES(?, ?, ?)",
                (project_ids[project], project, f"pkg:generic/{project}@1.0.0"),
            )
            connection.execute(
                "INSERT INTO Builds(build_id, project_id) VALUES(?, ?)",
                (project_ids[project], project_ids[project]),
            )
        binary_id += 1
        metadata = data["metadata"]
        connection.execute(
            "INSERT INTO Binaries(binary_id, build_id, name, binary_type, import_hash)"
            " VALUES(?, ?, ?, ?, ?)",
            (
                binary_id,
                project_ids[project],
                artifact,
                metadata.get("binary_type"),
                metadata.get("import_hash") or None,
            ),
        )
        for source, names in build_symbol_source_map(metadata).items():
            connection.executemany(
                "INSERT INTO Symbols(binary_id, name, source) VALUES(?, ?, ?)",
                [(binary_id, name, source) for name in names],
            )
        rows = []
        for function_key, func_data in (
            metadata.get("disassembled_functions") or {}
        ).items():
            if not isinstance(func_data, dict):
                continue
            rows.append(
                (
                    binary_id,
                    function_key,
                    func_data.get("instruction_hash"),
                    func_data.get("assembly_hash"),
                    func_data.get("fuzzy_hash"),
                    func_data.get("cfg_hash"),
                    func_data.get("instruction_count"),
                )
            )
        connection.executemany(
            "INSERT INTO FunctionFingerprints(binary_id, function_key, instruction_hash,"
            " assembly_hash, fuzzy_hash, cfg_hash, instruction_count)"
            " VALUES(?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
    connection.commit()


def false_attribution_probe(
    artifacts: dict[str, dict], db_file: str, floor: int
) -> tuple[list[dict], list[dict]]:
    """Query the db with every artifact through the real lookup path.

    The fuzzy-only gates are patched to their most permissive values so the
    probe records EVERY foreign attribution the fuzzy layer could produce,
    together with the two numbers that gate it for real: the distinct matched
    fuzzy-hash count and its coverage of the query's own floor-passing fuzzy
    functions. The true-positive behavior of each artifact's own project is
    recorded the same way, so the constants can be picked from the separation
    between the two populations. The consumer-side floor is patched per
    iteration so one db serves every floor under test.
    """
    db_module.MIN_FUNCTION_INSTRUCTION_COUNT_FOR_FUZZY_HASH_LOOKUP = floor
    db_module.FUZZY_ONLY_MATCH_THRESHOLD = 1
    db_module.FUZZY_ONLY_MIN_QUERY_COVERAGE = 0.0
    false_findings = []
    true_findings = []
    for artifact, data in sorted(artifacts.items()):
        metadata = data["metadata"]
        function_hash_index = build_function_hash_index(metadata)
        query_fuzzy_count = len(function_hash_index.get("fuzzy_hashes") or [])
        # Pass 1 keeps the artifact's real name: the name-match filter is
        # active, which is how an ordinary SBOM run behaves when the binary
        # name is known. Pass 2 neutralizes the name: no project matches by
        # name, so the name-match filter is skipped and the fuzzy layer stands
        # on its own — the static-linkage-recovery scenario this packet's
        # gates exist for.
        lookup_metadatas = [metadata]
        neutral = dict(metadata)
        neutral["name"] = "/tmp/unknown/mystery-binary"
        lookup_metadatas.append(neutral)
        for lookup_metadata in lookup_metadatas:
            matches = lookup_project_matches(
                build_symbol_source_map(metadata),
                function_hash_index=function_hash_index,
                binary_metadata=lookup_metadata,
                db_file=db_file,
            )
            own_purl = f"pkg:generic/{data['project']}@1.0.0"
            for match in matches:
                finding = {
                    "floor": floor,
                    "artifact": artifact,
                    "name_match": lookup_metadata is metadata,
                    "query_fuzzy_count": query_fuzzy_count,
                    "purl": match["project_purl"],
                    "score": match["score"],
                    "fuzzy": match.get("matched_fuzzy_hash_count", 0),
                    "coverage": (
                        match.get("matched_fuzzy_hash_count", 0) / query_fuzzy_count
                        if query_fuzzy_count
                        else 0.0
                    ),
                    "instruction": match.get("matched_instruction_hash_count", 0),
                    "assembly": match.get("matched_assembly_hash_count", 0),
                    "symbols": match.get("matched_symbol_count", 0),
                    "import": match.get("matched_import_hash_count", 0),
                }
                if match["project_purl"] == own_purl:
                    true_findings.append(finding)
                else:
                    false_findings.append(finding)
    return false_findings, true_findings


def single_project_probe(
    artifacts: dict[str, dict], db_project: str, floor: int
) -> list[dict]:
    """Build a database holding ONE project and query it with every other.

    The packet's headline gate in its rawest form: the db contains a single
    project, so every attribution the lookup returns for a foreign binary is
    by construction a false attribution. Constants run at their real values.
    """
    db_module.MIN_FUNCTION_INSTRUCTION_COUNT_FOR_FUZZY_HASH_LOOKUP = floor
    subset = {
        artifact: data
        for artifact, data in artifacts.items()
        if data["project"] == db_project
    }
    others = {a: d for a, d in artifacts.items() if d["project"] != db_project}
    findings = []
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_file = str((Path(tmp_dir) / "blint.db").resolve())
        connection = sqlite3.connect(db_file)
        build_v3_db(connection, subset)
        connection.close()
        for artifact, data in sorted(others.items()):
            metadata = dict(data["metadata"])
            metadata["name"] = "/tmp/unknown/mystery-binary"
            matches = lookup_project_matches(
                build_symbol_source_map(metadata),
                function_hash_index=build_function_hash_index(metadata),
                binary_metadata=metadata,
                db_file=db_file,
            )
            for match in matches:
                findings.append(
                    {
                        "floor": floor,
                        "artifact": artifact,
                        "db_project": db_project,
                        "purl": match["project_purl"],
                        "score": match["score"],
                        "fuzzy": match.get("matched_fuzzy_hash_count", 0),
                        "coverage": (
                            match.get("matched_fuzzy_hash_count", 0)
                            / max(1, len(build_function_hash_index(data["metadata"]).get("fuzzy_hashes") or []))
                        ),
                        "exact": match.get("matched_instruction_hash_count", 0)
                        + match.get("matched_assembly_hash_count", 0),
                        "symbols": match.get("matched_symbol_count", 0),
                        "import": match.get("matched_import_hash_count", 0),
                    }
                )
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reports-dir", required=True)
    parser.add_argument("--project-map", default=None)
    parser.add_argument("--floors", default=",".join(str(f) for f in FLOORS))
    parser.add_argument(
        "--skip-probe",
        action="store_true",
        help="skip the false-attribution probe (collision stats only)",
    )
    args = parser.parse_args()

    overrides = load_project_map(Path(args.project_map) if args.project_map else None)
    artifacts: dict[str, dict] = {}
    for metadata_file in sorted(Path(args.reports_dir).glob("*-metadata.json")):
        artifact = metadata_file.name[: -len("-metadata.json")]
        metadata = json.loads(metadata_file.read_text())
        if not metadata.get("disassembled_functions"):
            print(f"WARNING: {artifact} has no disassembled_functions; skipping")
            continue
        artifacts[artifact] = {
            "project": project_for(artifact, overrides),
            "metadata": metadata,
        }
    if len(artifacts) < 2:
        print("Need at least two artifacts; run blint --disassemble over a corpus first.")
        return 2
    print(f"Loaded {len(artifacts)} artifacts across "
          f"{len({d['project'] for d in artifacts.values()})} projects")

    entries = []
    for artifact, data in sorted(artifacts.items()):
        for function in collect_functions(data["metadata"]):
            function["project"] = data["project"]
            function["artifact"] = artifact
            entries.append(function)
    print(f"{len(entries)} hashed functions in total")

    for hash_key, label in (("fuzzy_hash", "fuzzy_hash"), ("cfg_hash", "cfg_hash")):
        print(f"\n=== {label}: cross-project collision rate by floor ===")
        print(f"{'floor':>5} {'functions':>10} {'distinct':>9} {'colliding':>10} "
              f"{'rate':>8}  worst project pairs")
        for floor in [int(f) for f in args.floors.split(",")]:
            report = collision_report(entries, floor, hash_key)
            pairs = ", ".join(f"{pair[0]}~{pair[1]}={count}" for pair, count in report["worst_pairs"])
            print(f"{report['floor']:>5} {report['functions']:>10} {report['distinct_values']:>9} "
                  f"{report['colliding_functions']:>10} {report['collision_rate']:>7.2%}  {pairs}")

    print("\n=== import_hash uniqueness across binaries ===")
    by_import: dict[str, list[str]] = defaultdict(list)
    for artifact, data in sorted(artifacts.items()):
        by_import[data["metadata"].get("import_hash") or "<empty>"].append(artifact)
    for import_hash, names in sorted(by_import.items(), key=lambda kv: -len(kv[1])):
        projects = sorted({artifacts[name]["project"] for name in names})
        flag = "CROSS-PROJECT" if len(projects) > 1 else ""
        print(f"  {import_hash:>18} -> {', '.join(names)} {flag}")

    if args.skip_probe:
        return 0

    print("\n=== false-attribution probe (real lookup path, all projects in db) ===")
    print("Gates patched permissive; every foreign attribution is listed with its")
    print("matched-fuzzy count and coverage so the real gates can be picked from data.\n")
    false_findings = []
    true_findings = []
    with tempfile.TemporaryDirectory() as tmp_dir:
        # blint.db opens with SQLITE_OPEN_NOFOLLOW, which refuses paths whose
        # final component is a symlink; macOS TMPDIR lives under /var -> /private/var.
        db_file = str((Path(tmp_dir) / "blint.db").resolve())
        connection = sqlite3.connect(db_file)
        build_v3_db(connection, artifacts)
        connection.close()
        for floor in [int(f) for f in args.floors.split(",")]:
            false_rows, true_rows = false_attribution_probe(artifacts, db_file, floor)
            false_findings.extend(false_rows)
            true_findings.extend(true_rows)

    print("--- foreign attributions (false positives under permissive gates) ---")
    if not false_findings:
        print("  none")
    for finding in false_findings:
        print(
            f"  floor={finding['floor']:>2} name={int(finding['name_match'])} "
            f"{finding['artifact']} -> {finding['purl']} "
            f"fuzzy={finding['fuzzy']} coverage={finding['coverage']:.1%} "
            f"of {finding['query_fuzzy_count']} exact={finding['instruction'] + finding['assembly']} "
            f"symbols={finding['symbols']} import={finding['import']} "
            f"score={finding['score']:.1f}"
        )
    print("\n--- own-project attributions (true positives, same run) ---")
    for finding in true_findings:
        print(
            f"  floor={finding['floor']:>2} name={int(finding['name_match'])} "
            f"{finding['artifact']} -> {finding['purl']} "
            f"fuzzy={finding['fuzzy']} coverage={finding['coverage']:.1%} "
            f"of {finding['query_fuzzy_count']} exact={finding['instruction'] + finding['assembly']} "
            f"symbols={finding['symbols']} import={finding['import']} "
            f"score={finding['score']:.1f}"
        )

    print("\n=== single-project database probe (real gates, name-neutralized) ===")
    print("The db holds exactly one project; any attribution for a foreign binary is false.\n")
    db_projects = sorted({data["project"] for data in artifacts.values()})
    any_false = False
    for db_project in db_projects:
        for floor in [int(f) for f in args.floors.split(",")]:
            for finding in single_project_probe(artifacts, db_project, floor):
                any_false = True
                print(
                    f"  db={finding['db_project']} floor={finding['floor']:>2} "
                    f"{finding['artifact']} -> {finding['purl']} fuzzy={finding['fuzzy']} "
                    f"coverage={finding['coverage']:.1%} exact={finding['exact']} "
                    f"symbols={finding['symbols']} import={finding['import']} "
                    f"score={finding['score']:.1f}"
                )
        if not any_false:
            print(f"  db={db_project}: no foreign attribution at any floor")
    if not any_false:
        print("  no single-project database attributed a foreign binary")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
