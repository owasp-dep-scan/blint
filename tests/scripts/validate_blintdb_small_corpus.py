#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = REPO_ROOT / "tests" / "data" / "blintdb-small-corpus.json"
DEFAULT_OUTPUT_DIR = REPO_ROOT / ".tmp-blintdb-small-corpus"
SUPPORTED_ECOSYSTEMS = ("meson", "vcpkg", "homebrew")
PROJECT_ECOSYSTEMS = {
    "meson": "wrapdb",
    "vcpkg": "vcpkg",
    "homebrew": "homebrew",
}


def default_vcpkg_triplet() -> str | None:
    if sys.platform != "darwin":
        return None
    machine = platform.machine().lower()
    arch = "arm64" if machine in {"arm64", "aarch64"} else "x64"
    return f"{arch}-osx-dynamic"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Build small blint-db corpora, retain artifacts, and validate exact SBOM "
            "matching in symbol-only and deep modes."
        )
    )
    parser.add_argument(
        "--manifest",
        default=str(DEFAULT_MANIFEST),
        help=f"Corpus manifest JSON. Defaults to {DEFAULT_MANIFEST}.",
    )
    parser.add_argument(
        "--output-dir",
        default=str(DEFAULT_OUTPUT_DIR),
        help=f"Output directory for generated databases and summaries. Defaults to {DEFAULT_OUTPUT_DIR}.",
    )
    parser.add_argument(
        "--blint-root",
        default=str(REPO_ROOT),
        help="Path to the blint repository root.",
    )
    parser.add_argument(
        "--blint-db-root",
        default=str(REPO_ROOT / "blint-db"),
        help="Path to the linked blint-db repository root.",
    )
    parser.add_argument(
        "--ecosystems",
        nargs="+",
        choices=SUPPORTED_ECOSYSTEMS,
        default=list(SUPPORTED_ECOSYSTEMS),
        help="One or more ecosystem corpora to build and validate.",
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Reuse existing database files and retained artifacts instead of rebuilding.",
    )
    parser.add_argument(
        "--summary-file",
        help="Optional JSON file for the final summary. Defaults to <output-dir>/summary.json.",
    )
    parser.add_argument(
        "--bootstrap-path",
        help="Optional build bootstrap directory. Defaults to <output-dir>/bootstrap.",
    )
    parser.add_argument(
        "--vcpkg-triplet",
        help="Optional vcpkg triplet override. Defaults to a dynamic macOS triplet on Darwin hosts.",
    )
    return parser


def load_manifest(manifest_file: str | os.PathLike) -> dict[str, list[dict[str, Any]]]:
    manifest_path = Path(manifest_file)
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Manifest at {manifest_path} must contain a JSON object")
    for ecosystem in SUPPORTED_ECOSYSTEMS:
        entries = data.get(ecosystem)
        if not isinstance(entries, list):
            raise ValueError(f"Manifest key '{ecosystem}' must be a list")
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError(f"Manifest entry for {ecosystem} must be an object")
            if not entry.get("selector"):
                raise ValueError(
                    f"Manifest entry for {ecosystem} is missing 'selector'"
                )
    return data


def select_preferred_artifact(
    artifacts: list[str], preferred_artifact_names: list[str] | None = None
) -> str | None:
    if not artifacts:
        return None
    preferred_artifact_names = preferred_artifact_names or []
    artifact_paths = [Path(artifact) for artifact in artifacts]

    def _artifact_rank(path_obj: Path) -> tuple[int, int, str]:
        suffix = path_obj.suffix.lower()
        is_static = suffix in {".a", ".lib"}
        is_debug = "debug" in {part.lower() for part in path_obj.parts}
        return (int(is_static), int(is_debug), path_obj.name.lower())

    for preferred in preferred_artifact_names:
        preferred_lower = preferred.lower()
        matching_paths = [
            artifact_path
            for artifact_path in artifact_paths
            if artifact_path.name.lower() == preferred_lower
            or artifact_path.name.lower().startswith(preferred_lower)
        ]
        if matching_paths:
            return str(sorted(matching_paths, key=_artifact_rank)[0])
    return str(sorted(artifact_paths, key=_artifact_rank)[0])


def _run_command(
    command: list[str], *, cwd: Path, env: dict[str, str], capture_output: bool = False
) -> subprocess.CompletedProcess:
    print(f"[run] cwd={cwd} :: {' '.join(command)}")
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        check=True,
        text=True,
        capture_output=capture_output,
    )


def _pythonpath(blint_root: Path, blint_db_root: Path) -> str:
    existing = [part for part in os.getenv("PYTHONPATH", "").split(os.pathsep) if part]
    combined = [str(blint_root), str(blint_db_root), *existing]
    return os.pathsep.join(dict.fromkeys(combined))


def _import_ecosystem_helpers(blint_root: Path, blint_db_root: Path):
    pythonpath = _pythonpath(blint_root, blint_db_root)
    sys.path[:0] = [
        part for part in pythonpath.split(os.pathsep) if part not in sys.path
    ]
    from blint_db.handlers.language_handlers.homebrew_handler import (  # pylint: disable=import-outside-toplevel
        find_homebrew_artifacts,
        homebrew_info,
        homebrew_keg_roots,
    )
    from blint_db.handlers.language_handlers.meson_handler import (  # pylint: disable=import-outside-toplevel
        find_meson_executables,
    )
    from blint_db.handlers.language_handlers.vcpkg_handler import (  # pylint: disable=import-outside-toplevel
        find_vcpkg_executables,
    )

    return {
        "meson": {"find_artifacts": find_meson_executables},
        "vcpkg": {"find_artifacts": find_vcpkg_executables},
        "homebrew": {
            "find_artifacts": lambda selector: sorted(
                {
                    artifact
                    for keg_root in homebrew_keg_roots(homebrew_info(selector))
                    for artifact in find_homebrew_artifacts(keg_root)
                }
            )
        },
    }


def metadata_file_for_ecosystem(output_dir: Path, ecosystem: str) -> Path:
    return output_dir / f"{ecosystem}-small.metadata.json"


def load_run_metadata(metadata_file: str | os.PathLike) -> dict[str, Any] | None:
    metadata_path = Path(metadata_file)
    if not metadata_path.exists():
        return None
    return json.loads(metadata_path.read_text(encoding="utf-8"))


def build_outcomes_by_selector(
    run_metadata: dict[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    outcomes = ((run_metadata or {}).get("projects") or {}).get("outcomes") or []
    return {
        str(outcome.get("selector")): outcome
        for outcome in outcomes
        if isinstance(outcome, dict) and outcome.get("selector")
    }


def error_record(exc: BaseException) -> dict[str, str]:
    return {
        "exception_type": type(exc).__name__,
        "message": str(exc),
    }


def build_database_for_ecosystem(
    ecosystem: str,
    entries: list[dict[str, Any]],
    *,
    db_file: Path,
    metadata_file: Path,
    blint_root: Path,
    blint_db_root: Path,
    bootstrap_path: Path,
) -> None:
    selectors = [entry["selector"] for entry in entries]
    command = [
        sys.executable,
        "-m",
        "blint_db.cli",
        "--clean-start",
        "--db-file",
        str(db_file),
        "--run-metadata-file",
        str(metadata_file),
        "--disassemble",
        f"build-{ecosystem}",
    ]
    if ecosystem in {"meson", "vcpkg"}:
        command.append("--retain-build-artifacts")
    command.extend(["-s", *selectors])
    env = os.environ.copy()
    env["PYTHONPATH"] = _pythonpath(blint_root, blint_db_root)
    env.setdefault("BLINT_DB_MESON_STRIP", "0")
    env.setdefault("BLINT_DB_BOOTSTRAP_PATH", str(bootstrap_path))
    _run_command(command, cwd=blint_db_root, env=env)


def stage_database_for_blint(db_file: Path, stage_dir: Path) -> Path:
    stage_dir.mkdir(parents=True, exist_ok=True)
    staged_db = stage_dir / "blint.db"
    if staged_db.exists() or staged_db.is_symlink():
        staged_db.unlink()
    shutil.copy2(db_file, staged_db)
    return stage_dir


def query_project_purl(db_file: Path, ecosystem: str, project_name: str) -> str:
    with sqlite3.connect(db_file) as connection:
        row = connection.execute(
            "SELECT purl FROM Projects WHERE ecosystem = ? AND name = ? ORDER BY project_id DESC LIMIT 1",
            (PROJECT_ECOSYSTEMS[ecosystem], project_name),
        ).fetchone()
    if not row or not row[0]:
        raise RuntimeError(
            f"Unable to find project purl for ecosystem={ecosystem} project_name={project_name} in {db_file}"
        )
    return str(row[0])


def run_blint_sbom(
    *,
    blint_root: Path,
    blint_db_root: Path,
    binary_file: str,
    blintdb_home: Path,
    deep: bool,
) -> dict[str, Any]:
    command = [
        sys.executable,
        "-m",
        "blint.cli",
        "sbom",
        "-i",
        binary_file,
        "--use-blintdb",
        "--stdout",
        "-q",
    ]
    if deep:
        command.append("--deep")
    env = os.environ.copy()
    env["PYTHONPATH"] = _pythonpath(blint_root, blint_db_root)
    env["BLINTDB_HOME"] = str(blintdb_home)
    env["USE_BLINTDB"] = "true"
    completed = _run_command(command, cwd=blint_root, env=env, capture_output=True)
    return json.loads(completed.stdout)


def extract_generic_components(sbom: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        component
        for component in sbom.get("components", [])
        if str(component.get("purl") or "").startswith("pkg:generic/")
    ]


def parse_blintdb_evidence(component: dict[str, Any]) -> dict[str, str]:
    return {
        prop["name"]: prop["value"]
        for prop in component.get("properties", [])
        if isinstance(prop, dict)
        and prop.get("name", "").startswith("internal:blintdb_")
    }


def validate_case(
    ecosystem: str,
    entry: dict[str, Any],
    *,
    db_file: Path,
    build_outcome: dict[str, Any] | None,
    staged_db_home: Path,
    helpers: dict[str, Any],
    blint_root: Path,
    blint_db_root: Path,
) -> dict[str, Any]:
    selector = entry["selector"]
    project_name = entry.get("project_name") or selector
    artifacts = helpers[ecosystem]["find_artifacts"](selector)
    artifact_file = select_preferred_artifact(
        artifacts, entry.get("preferred_artifact_names") or []
    )
    if not artifact_file:
        raise RuntimeError(
            f"Unable to find a retained artifact for ecosystem={ecosystem} selector={selector}"
        )
    expected_purl = query_project_purl(db_file, ecosystem, project_name)
    case_result = {
        "selector": selector,
        "project_name": project_name,
        "build_status": (build_outcome or {}).get("status") or "unknown",
        "build_failure": (build_outcome or {}).get("failure"),
        "validation_status": "validated",
        "validation_error": None,
        "artifact_file": artifact_file,
        "expected_purl": expected_purl,
        "normal": None,
        "deep": None,
    }
    for mode_name, deep in (("normal", False), ("deep", True)):
        sbom = run_blint_sbom(
            blint_root=blint_root,
            blint_db_root=blint_db_root,
            binary_file=artifact_file,
            blintdb_home=staged_db_home,
            deep=deep,
        )
        generic_components = extract_generic_components(sbom)
        generic_purls = [component.get("purl") for component in generic_components]
        exact_match = generic_purls == [expected_purl]
        evidence = (
            parse_blintdb_evidence(generic_components[0]) if generic_components else {}
        )
        instruction_hash_count = int(
            evidence.get("internal:blintdb_matched_instruction_hash_count", "0") or "0"
        )
        assembly_hash_count = int(
            evidence.get("internal:blintdb_matched_assembly_hash_count", "0") or "0"
        )
        hash_evidence = instruction_hash_count > 0 or assembly_hash_count > 0
        case_result[mode_name] = {
            "generic_purls": generic_purls,
            "exact_match": exact_match,
            "hash_evidence": hash_evidence,
            "blintdb_evidence": evidence,
        }
    return case_result


def summarize_results(
    results: dict[str, list[dict[str, Any]]],
    provenance: dict[str, dict[str, Any] | None] | None = None,
) -> dict[str, Any]:
    summary: dict[str, Any] = {"ecosystems": {}, "totals": {}}
    total_cases = 0
    total_validated_cases = 0
    total_exact_normal = 0
    total_exact_deep = 0
    total_build_failed = 0
    total_no_artifacts = 0
    total_validation_errors = 0
    provenance = provenance or {}
    for ecosystem, ecosystem_results in results.items():
        exact_normal = sum(
            1
            for case in ecosystem_results
            if case.get("normal") and case["normal"]["exact_match"]
        )
        exact_deep = sum(
            1
            for case in ecosystem_results
            if case.get("deep") and case["deep"]["exact_match"]
        )
        hash_evidence = sum(
            1
            for case in ecosystem_results
            if case.get("deep") and case["deep"]["hash_evidence"]
        )
        validated_cases = sum(
            1
            for case in ecosystem_results
            if case.get("validation_status") == "validated"
        )
        build_failed_cases = sum(
            1
            for case in ecosystem_results
            if case.get("build_status") == "build_failed"
        )
        no_artifacts_cases = sum(
            1
            for case in ecosystem_results
            if case.get("build_status") == "no_artifacts"
        )
        validation_errors = sum(
            1 for case in ecosystem_results if case.get("validation_status") == "error"
        )
        count = len(ecosystem_results)
        total_cases += count
        total_validated_cases += validated_cases
        total_exact_normal += exact_normal
        total_exact_deep += exact_deep
        total_build_failed += build_failed_cases
        total_no_artifacts += no_artifacts_cases
        total_validation_errors += validation_errors
        provenance_payload = provenance.get(ecosystem) or {}
        provenance_projects = provenance_payload.get("projects") or {}
        summary["ecosystems"][ecosystem] = {
            "case_count": count,
            "validated_case_count": validated_cases,
            "build_failed_case_count": build_failed_cases,
            "no_artifacts_case_count": no_artifacts_cases,
            "validation_error_count": validation_errors,
            "exact_normal": exact_normal,
            "exact_deep": exact_deep,
            "deep_hash_evidence": hash_evidence,
            "provenance": {
                "selected_count": provenance_projects.get("selected_count", 0),
                "attempted_count": provenance_projects.get("attempted_count", 0),
                "success_count": provenance_projects.get("success_count", 0),
                "failure_count": provenance_projects.get("failure_count", 0),
                "status_counts": provenance_projects.get("status_counts", {}),
                "build_failures": provenance_projects.get("build_failures", []),
            },
            "cases": ecosystem_results,
        }
    summary["totals"] = {
        "case_count": total_cases,
        "validated_case_count": total_validated_cases,
        "build_failed_case_count": total_build_failed,
        "no_artifacts_case_count": total_no_artifacts,
        "validation_error_count": total_validation_errors,
        "exact_normal": total_exact_normal,
        "exact_deep": total_exact_deep,
        "exact_normal_rate": total_exact_normal / total_cases if total_cases else 0.0,
        "exact_deep_rate": total_exact_deep / total_cases if total_cases else 0.0,
    }
    return summary


def main() -> int:
    args = build_parser().parse_args()
    manifest = load_manifest(args.manifest)
    blint_root = Path(args.blint_root).resolve()
    blint_db_root = Path(args.blint_db_root).resolve()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    bootstrap_path = Path(args.bootstrap_path or (output_dir / "bootstrap")).resolve()
    bootstrap_path.mkdir(parents=True, exist_ok=True)
    os.environ["BLINT_DB_BOOTSTRAP_PATH"] = str(bootstrap_path)
    if args.vcpkg_triplet:
        os.environ["BLINT_DB_VCPKG_TRIPLET"] = args.vcpkg_triplet
    elif default_triplet := default_vcpkg_triplet():
        os.environ["BLINT_DB_VCPKG_TRIPLET"] = default_triplet
    summary_file = (
        Path(args.summary_file).resolve()
        if args.summary_file
        else output_dir / "summary.json"
    )
    helpers = _import_ecosystem_helpers(blint_root, blint_db_root)
    results: dict[str, list[dict[str, Any]]] = {}
    provenance_by_ecosystem: dict[str, dict[str, Any] | None] = {}
    for ecosystem in args.ecosystems:
        entries = manifest[ecosystem]
        db_file = output_dir / f"{ecosystem}-small.db"
        metadata_file = metadata_file_for_ecosystem(output_dir, ecosystem)
        staged_db_home = output_dir / f"{ecosystem}-blintdb-home"
        if not args.skip_build:
            build_database_for_ecosystem(
                ecosystem,
                entries,
                db_file=db_file,
                metadata_file=metadata_file,
                blint_root=blint_root,
                blint_db_root=blint_db_root,
                bootstrap_path=bootstrap_path,
            )
        elif not db_file.exists():
            raise RuntimeError(
                f"Expected existing database file was not found: {db_file}"
            )
        run_metadata = load_run_metadata(metadata_file)
        provenance_by_ecosystem[ecosystem] = run_metadata
        outcomes_by_selector = build_outcomes_by_selector(run_metadata)
        stage_database_for_blint(db_file, staged_db_home)
        ecosystem_results = []
        for entry in entries:
            selector = entry["selector"]
            project_name = entry.get("project_name") or selector
            build_outcome = outcomes_by_selector.get(selector)
            if build_outcome and build_outcome.get("status") != "success":
                case_result = {
                    "selector": selector,
                    "project_name": project_name,
                    "build_status": build_outcome.get("status"),
                    "build_failure": build_outcome.get("failure"),
                    "validation_status": "skipped",
                    "validation_error": None,
                    "artifact_file": None,
                    "expected_purl": None,
                    "normal": None,
                    "deep": None,
                }
            else:
                try:
                    case_result = validate_case(
                        ecosystem,
                        entry,
                        db_file=db_file,
                        build_outcome=build_outcome,
                        staged_db_home=staged_db_home,
                        helpers=helpers,
                        blint_root=blint_root,
                        blint_db_root=blint_db_root,
                    )
                except RuntimeError as exc:
                    case_result = {
                        "selector": selector,
                        "project_name": project_name,
                        "build_status": (build_outcome or {}).get("status")
                        or "unknown",
                        "build_failure": (build_outcome or {}).get("failure"),
                        "validation_status": "error",
                        "validation_error": error_record(exc),
                        "artifact_file": None,
                        "expected_purl": None,
                        "normal": None,
                        "deep": None,
                    }
            ecosystem_results.append(case_result)
            if case_result["validation_status"] == "validated":
                print(
                    f"[{ecosystem}] {entry['selector']}: normal_exact={case_result['normal']['exact_match']} "
                    f"deep_exact={case_result['deep']['exact_match']} "
                    f"deep_hash={case_result['deep']['hash_evidence']}"
                )
            else:
                print(
                    f"[{ecosystem}] {entry['selector']}: build_status={case_result['build_status']} "
                    f"validation_status={case_result['validation_status']}"
                )
        results[ecosystem] = ecosystem_results
    summary = summarize_results(results, provenance=provenance_by_ecosystem)
    summary_file.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"Wrote validation summary to {summary_file}")
    if (
        summary["totals"]["validated_case_count"] != summary["totals"]["case_count"]
        or summary["totals"]["exact_normal"]
        != summary["totals"]["validated_case_count"]
        or summary["totals"]["exact_deep"] != summary["totals"]["validated_case_count"]
    ):
        print(json.dumps(summary["totals"], indent=2))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
