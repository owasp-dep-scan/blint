from __future__ import annotations

import importlib.util
from pathlib import Path


SCRIPT_PATH = (
    Path(__file__).resolve().parent / "scripts" / "validate_blintdb_small_corpus.py"
)


spec = importlib.util.spec_from_file_location(
    "validate_blintdb_small_corpus", SCRIPT_PATH
)
validate_blintdb_small_corpus = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validate_blintdb_small_corpus)


def test_small_corpus_manifest_includes_five_entries_per_ecosystem():
    manifest = validate_blintdb_small_corpus.load_manifest(
        Path(__file__).resolve().parent / "data" / "blintdb-small-corpus.json"
    )

    assert set(manifest) == {"meson", "vcpkg", "homebrew"}
    assert all(len(manifest[ecosystem]) == 5 for ecosystem in manifest)


def test_select_preferred_artifact_prefers_matching_basename_prefix():
    shared_lib = Path("/tmp/demo/libfmt.11.1.4.dylib")
    executable = Path("/tmp/demo/fmt")
    selected = validate_blintdb_small_corpus.select_preferred_artifact(
        [
            str(shared_lib),
            str(executable),
        ],
        ["libfmt", "fmt"],
    )

    assert Path(selected) == shared_lib


def test_select_preferred_artifact_prefers_shared_library_over_static_archive():
    static_archive = Path("/tmp/demo/libpng.a")
    shared_lib = Path("/tmp/demo/libpng.dylib")
    selected = validate_blintdb_small_corpus.select_preferred_artifact(
        [
            str(static_archive),
            str(shared_lib),
        ],
        ["libpng"],
    )

    assert Path(selected) == shared_lib


def test_summarize_results_counts_exact_matches_and_hash_evidence():
    summary = validate_blintdb_small_corpus.summarize_results(
        {
            "meson": [
                {
                    "selector": "zlib",
                    "build_status": "success",
                    "validation_status": "validated",
                    "normal": {"exact_match": True},
                    "deep": {"exact_match": True, "hash_evidence": True},
                },
                {
                    "selector": "bzip2",
                    "build_status": "success",
                    "validation_status": "validated",
                    "normal": {"exact_match": False},
                    "deep": {"exact_match": True, "hash_evidence": False},
                },
            ]
        },
        provenance={
            "meson": {
                "projects": {
                    "selected_count": 2,
                    "attempted_count": 2,
                    "success_count": 2,
                    "failure_count": 0,
                    "status_counts": {"success": 2},
                    "build_failures": [],
                }
            }
        },
    )

    assert summary["ecosystems"]["meson"]["case_count"] == 2
    assert summary["ecosystems"]["meson"]["validated_case_count"] == 2
    assert summary["ecosystems"]["meson"]["exact_normal"] == 1
    assert summary["ecosystems"]["meson"]["exact_deep"] == 2
    assert summary["ecosystems"]["meson"]["deep_hash_evidence"] == 1
    assert summary["ecosystems"]["meson"]["provenance"]["status_counts"] == {
        "success": 2
    }
    assert summary["totals"]["case_count"] == 2
    assert summary["totals"]["validated_case_count"] == 2
    assert summary["totals"]["exact_deep_rate"] == 1.0


def test_summarize_results_tracks_build_failures_from_provenance():
    summary = validate_blintdb_small_corpus.summarize_results(
        {
            "vcpkg": [
                {
                    "selector": "libpng",
                    "build_status": "build_failed",
                    "validation_status": "skipped",
                    "build_failure": {"stage": "build", "message": "compile failed"},
                    "normal": None,
                    "deep": None,
                }
            ]
        },
        provenance={
            "vcpkg": {
                "projects": {
                    "selected_count": 1,
                    "attempted_count": 1,
                    "success_count": 0,
                    "failure_count": 1,
                    "status_counts": {"build_failed": 1},
                    "build_failures": [
                        {
                            "selector": "libpng",
                            "status": "build_failed",
                            "stage": "build",
                            "message": "compile failed",
                        }
                    ],
                }
            }
        },
    )

    assert summary["ecosystems"]["vcpkg"]["build_failed_case_count"] == 1
    assert summary["ecosystems"]["vcpkg"]["validated_case_count"] == 0
    assert summary["ecosystems"]["vcpkg"]["provenance"]["failure_count"] == 1
    assert summary["totals"]["build_failed_case_count"] == 1
    assert summary["totals"]["validated_case_count"] == 0


def test_default_vcpkg_triplet_prefers_dynamic_triplet_on_macos(monkeypatch):
    monkeypatch.setattr(validate_blintdb_small_corpus.sys, "platform", "darwin")
    monkeypatch.setattr(
        validate_blintdb_small_corpus.platform,
        "machine",
        lambda: "arm64",
    )

    assert validate_blintdb_small_corpus.default_vcpkg_triplet() == "arm64-osx-dynamic"
