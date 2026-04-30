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
    selected = validate_blintdb_small_corpus.select_preferred_artifact(
        [
            "/tmp/demo/libfmt.11.1.4.dylib",
            "/tmp/demo/fmt",
        ],
        ["libfmt", "fmt"],
    )

    assert selected == "/tmp/demo/libfmt.11.1.4.dylib"


def test_select_preferred_artifact_prefers_shared_library_over_static_archive():
    selected = validate_blintdb_small_corpus.select_preferred_artifact(
        [
            "/tmp/demo/libpng.a",
            "/tmp/demo/libpng.dylib",
        ],
        ["libpng"],
    )

    assert selected == "/tmp/demo/libpng.dylib"


def test_summarize_results_counts_exact_matches_and_hash_evidence():
    summary = validate_blintdb_small_corpus.summarize_results(
        {
            "meson": [
                {
                    "selector": "zlib",
                    "normal": {"exact_match": True},
                    "deep": {"exact_match": True, "hash_evidence": True},
                },
                {
                    "selector": "bzip2",
                    "normal": {"exact_match": False},
                    "deep": {"exact_match": True, "hash_evidence": False},
                },
            ]
        }
    )

    assert summary["ecosystems"]["meson"]["case_count"] == 2
    assert summary["ecosystems"]["meson"]["exact_normal"] == 1
    assert summary["ecosystems"]["meson"]["exact_deep"] == 2
    assert summary["ecosystems"]["meson"]["deep_hash_evidence"] == 1
    assert summary["totals"]["case_count"] == 2
    assert summary["totals"]["exact_deep_rate"] == 1.0


def test_default_vcpkg_triplet_prefers_dynamic_triplet_on_macos(monkeypatch):
    monkeypatch.setattr(validate_blintdb_small_corpus.sys, "platform", "darwin")
    monkeypatch.setattr(
        validate_blintdb_small_corpus.platform,
        "machine",
        lambda: "arm64",
    )

    assert validate_blintdb_small_corpus.default_vcpkg_triplet() == "arm64-osx-dynamic"
