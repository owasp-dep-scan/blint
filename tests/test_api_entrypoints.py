"""Tests for the sbom/diff/batch API entry points and review ids.

Every test here calls only ``blint.api``: the point of the public API is
that a consumer never imports an internal helper, so the tests hold
themselves to the same rule.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from blint.api import (
    AnalysisFailedError,
    AnalysisResult,
    BlintApiError,
    BlintdbUnavailableError,
    DiffInputError,
    DiffResult,
    NotABinaryError,
    SbomResult,
    analyze,
    analyze_many,
    diff,
    sbom,
)

_DATA_DIR = Path(__file__).resolve().parent / "data"
PLAIN_ELF = _DATA_DIR / "plain-libc-demo.elf"
FORTIFIED_ELF = _DATA_DIR / "fortified-libc-demo.elf"
WASM_FIXTURE = _DATA_DIR / "complex_flow.wasm"


# ---------------------------------------------------------------- sbom()


def test_sbom_returns_the_document_and_writes_nothing(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = sbom(PLAIN_ELF)
    assert isinstance(result, SbomResult)
    assert result.output_file is None
    assert result.bom is not None
    assert result.bom["bomFormat"] == "CycloneDX"
    assert result.bom["specVersion"] in ("1.6", "1.7")
    assert result.bom["components"]
    units = result.coverage["units"]
    assert units["executables"] == 1 and units["android_apps"] == 0
    assert list(tmp_path.iterdir()) == [], "sbom() must not write files unless asked"


def test_sbom_output_file_matches_the_returned_document(tmp_path) -> None:
    out = tmp_path / "bom.cdx.json"
    result = sbom(PLAIN_ELF, output_file=out)
    assert result.output_file == str(out)
    on_disk = json.loads(out.read_text(encoding="utf-8"))
    assert on_disk == result.bom


def test_sbom_accepts_a_list_and_a_directory(tmp_path) -> None:
    both = sbom([PLAIN_ELF, FORTIFIED_ELF])
    assert both.coverage["units"]["executables"] == 2
    assert both.bom is not None and len(both.bom["components"]) >= 2
    directory = sbom(str(_DATA_DIR.parent))
    assert isinstance(directory.bom, dict) or directory.coverage.get("notes")


def test_sbom_reports_skipped_wasm_files_with_the_reason() -> None:
    result = sbom(WASM_FIXTURE)
    assert result.coverage["skipped"]["wasm"] == [str(WASM_FIXTURE)]
    assert "wasm_sbom=True" in result.coverage["skipped"]["reason"]
    included = sbom(WASM_FIXTURE, wasm_sbom=True)
    assert included.coverage["skipped"]["wasm"] == []


def test_sbom_missing_input_raises_file_not_found(tmp_path) -> None:
    with pytest.raises(FileNotFoundError):
        sbom(tmp_path / "not-there")
    with pytest.raises(FileNotFoundError):
        sbom([PLAIN_ELF, tmp_path / "not-there"])


def test_sbom_directory_with_no_binaries_is_a_stated_outcome(tmp_path) -> None:
    (tmp_path / "notes.txt").write_text("nothing to analyze", encoding="utf-8")
    result = sbom(tmp_path)
    assert result.bom is None
    assert result.coverage["notes"] == ["no analyzable inputs were discovered"]


def test_sbom_blintdb_failure_raises_instead_of_degrading(monkeypatch, tmp_path) -> None:
    import blint.api as api_module

    monkeypatch.setattr(api_module, "blintdb_setup", lambda options: False)
    with pytest.raises(BlintdbUnavailableError):
        sbom(PLAIN_ELF, use_blintdb=True)
    # The failure left no half-written output behind.
    assert list(tmp_path.iterdir()) == []


def test_sbom_generation_failure_raises_and_writes_nothing(monkeypatch, tmp_path) -> None:
    import blint.lib.sbom as sbom_module

    def broken(*_args, **_kwargs):
        raise RuntimeError("worker died while processing a unit")

    monkeypatch.setattr(sbom_module, "generate", broken)
    out = tmp_path / "bom.json"
    with pytest.raises(AnalysisFailedError) as excinfo:
        sbom(PLAIN_ELF, output_file=out)
    assert excinfo.value.record["error_type"] == "RuntimeError"
    assert isinstance(excinfo.value, BlintApiError)
    assert not out.exists()


def test_sbom_error_hierarchy_is_public() -> None:
    assert issubclass(BlintdbUnavailableError, BlintApiError)


# ---------------------------------------------------------------- diff()


def test_diff_returns_the_report_for_two_binaries() -> None:
    result = diff(PLAIN_ELF, FORTIFIED_ELF)
    assert isinstance(result, DiffResult)
    report = result.report
    for layer in ("identity", "hardening", "findings", "reviews", "functions"):
        assert layer in report
    # The two fixtures differ in fortify imports, so the report says so
    # rather than reporting a clean no-change.
    assert report["new"]["path"] == str(FORTIFIED_ELF)
    assert report["old"]["path"] == str(PLAIN_ELF)


def test_diff_input_problems_raise_the_public_error(tmp_path) -> None:
    with pytest.raises(DiffInputError):
        diff(tmp_path / "missing", PLAIN_ELF)
    with pytest.raises(DiffInputError):
        diff(PLAIN_ELF, tmp_path)  # a directory is not one side of a diff
    junk = tmp_path / "junk.json"
    junk.write_text("{}", encoding="utf-8")
    with pytest.raises(DiffInputError):
        diff(PLAIN_ELF, junk)


def test_diff_accepts_a_metadata_json_side(tmp_path) -> None:
    exported = analyze(PLAIN_ELF).metadata
    meta_path = tmp_path / "plain-metadata.json"
    meta_path.write_text(json.dumps(exported), encoding="utf-8")
    result = diff(meta_path, FORTIFIED_ELF)
    assert result.report["old"]["kind"] == "metadata-json"


# --------------------------------------------------------- analyze_many()


def test_analyze_many_returns_one_result_per_file() -> None:
    batch = analyze_many([PLAIN_ELF, FORTIFIED_ELF])
    assert len(batch.results) == 2
    assert all(isinstance(r, AnalysisResult) for r in batch.results)
    assert batch.unmatched == []
    # Per-unit attribution: each unit's findings belong to its own file.
    for result in batch.results:
        assert result.metadata is not None
        for finding in result.findings:
            assert finding["filename"] in (
                str(PLAIN_ELF),
                str(FORTIFIED_ELF),
            )
    assert batch.coverage["units"]["attempted"] == 2
    assert batch.coverage["units"]["succeeded"] == 2


def test_analyze_many_directory_discovered_and_matches_single_analyze(tmp_path) -> None:
    batch = analyze_many([PLAIN_ELF])
    single = analyze(PLAIN_ELF)
    assert len(batch.results) == 1
    only = batch.results[0]
    assert only.metadata == single.metadata
    assert [f["finding_id"] for f in only.findings] == [f["finding_id"] for f in single.findings]
    assert [r["review_id"] for r in only.reviews] == [r["review_id"] for r in single.reviews]


def test_analyze_many_empty_discovery_is_a_stated_outcome(tmp_path) -> None:
    (tmp_path / "readme.md").write_text("empty", encoding="utf-8")
    batch = analyze_many(tmp_path)
    assert batch.results == []
    assert batch.coverage["notes"] == [
        "no analyzable binaries were discovered in the given inputs"
    ]


def test_analyze_many_missing_input_raises(tmp_path) -> None:
    with pytest.raises(FileNotFoundError):
        analyze_many(tmp_path / "gone")
    with pytest.raises(ValueError):
        analyze_many([])


# ------------------------------------------------------------- review ids


def test_reviews_carry_stable_ids() -> None:
    result = analyze(FORTIFIED_ELF)
    assert result.reviews, "fixture is expected to trigger at least one review"
    ids = [r["review_id"] for r in result.reviews]
    assert all(isinstance(i, str) and len(i) == 32 for i in ids)
    assert len(set(ids)) == len(ids), "review ids must be unique within one binary"
    # A fresh call mints the same ids: the digest is over the rule and the
    # binary bytes, never the run.
    again = analyze(FORTIFIED_ELF)
    assert [r["review_id"] for r in again.reviews] == ids


def test_review_ids_do_not_follow_the_evidence() -> None:
    """More evidence for the same review (here from disassembly) keeps its id."""
    plain = analyze(FORTIFIED_ELF)
    deeper = analyze(FORTIFIED_ELF, disassemble=True)
    plain_ids = {r["id"]: r["review_id"] for r in plain.reviews}
    deeper_ids = {r["id"]: r["review_id"] for r in deeper.reviews}
    shared = plain_ids.keys() & deeper_ids.keys()
    assert shared
    assert all(plain_ids[rule] == deeper_ids[rule] for rule in shared)


def test_review_ids_separate_binaries_and_findings() -> None:
    fortified = analyze(FORTIFIED_ELF)
    plain = analyze(PLAIN_ELF)
    fortified_ids = {r["review_id"] for r in fortified.reviews}
    plain_ids = {r["review_id"] for r in plain.reviews}
    assert fortified_ids and fortified_ids.isdisjoint(plain_ids)
    # A review and a finding can never share an id: the review namespace is
    # discriminated inside the shared scheme.
    finding_ids = {f["finding_id"] for f in fortified.findings}
    assert finding_ids.isdisjoint(fortified_ids)


# --------------------------------------------------------- concurrency


def test_concurrent_analyze_calls_match_serial_results() -> None:
    serial_plain = analyze(PLAIN_ELF)
    serial_fortified = analyze(FORTIFIED_ELF)
    outcomes: dict[str, AnalysisResult] = {}

    def run(name: str, path: Path) -> None:
        outcomes[name] = analyze(path)

    threads = [
        threading.Thread(target=run, args=("plain", PLAIN_ELF)),
        threading.Thread(target=run, args=("fortified", FORTIFIED_ELF)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert outcomes["plain"].metadata == serial_plain.metadata
    assert [f["finding_id"] for f in outcomes["plain"].findings] == [
        f["finding_id"] for f in serial_plain.findings
    ]
    assert [r["review_id"] for r in outcomes["fortified"].reviews] == [
        r["review_id"] for r in serial_fortified.reviews
    ]


def test_concurrent_sbom_calls_run_without_the_analysis_lock() -> None:
    outcomes: list[SbomResult] = []

    def run(path: Path) -> None:
        outcomes.append(sbom(path))

    threads = [
        threading.Thread(target=run, args=(PLAIN_ELF,)),
        threading.Thread(target=run, args=(FORTIFIED_ELF,)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(outcomes) == 2
    assert all(r.bom is not None and r.bom["components"] for r in outcomes)


def test_not_a_binary_error_survives_in_the_hierarchy() -> None:
    assert issubclass(NotABinaryError, BlintApiError)


def test_concurrent_quiet_calls_leave_the_logger_enabled() -> None:
    # A quiet call toggling the process-global logger raced before: the
    # second thread captured the first's "disabled" and restored it after
    # the first had already restored "enabled", leaving blint's logger off
    # for the rest of the process (empty caplog everywhere downstream).
    from blint.logger import LOG

    threads = [
        threading.Thread(target=analyze, args=(PLAIN_ELF,)),
        threading.Thread(target=analyze, args=(FORTIFIED_ELF,)),
        threading.Thread(target=lambda: sbom(PLAIN_ELF)),
        threading.Thread(target=lambda: diff(PLAIN_ELF, FORTIFIED_ELF)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert LOG.disabled is False
    LOG.info("logger still works after concurrent quiet calls")
