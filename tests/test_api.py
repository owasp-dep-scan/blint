"""Tests for the public Python API (``blint.analyze``, D4)."""

import dataclasses
import json
import os
import plistlib
import subprocess
import sys
import zipfile
from pathlib import Path

import orjson
import pytest

from blint import AnalysisResult, NotABinaryError, analyze

_DATA_DIR = Path(__file__).resolve().parent / "data"
_REPO_ROOT = Path(__file__).resolve().parent.parent
# Corpus fixtures are materialized locally by tests/scripts/build_corpus.py
# and are not in git; tests needing them skip when absent.
_CORPUS_DIR = _REPO_ROOT / "corpus-build"

WASM_FIXTURE = _DATA_DIR / "complex_flow.wasm"
GO_ELF = _CORPUS_DIR / "go-elf-unstripped"
GO_ELF_STRIPPED = _CORPUS_DIR / "go-elf-stripped"
needs_go_elf = pytest.mark.skipif(
    not GO_ELF.exists(), reason="corpus fixture go-elf-unstripped not built"
)


def test_analyze_returns_typed_result_on_wasm_fixture():
    result = analyze(WASM_FIXTURE)

    assert isinstance(result, AnalysisResult)
    assert result.metadata is not None
    assert result.metadata.get("exe_type") == "wasmbinary"
    assert result.coverage["units"] == {
        "attempted": 1,
        "succeeded": 1,
        "failed": 0,
        "skipped": 0,
    }
    # The per-binary blind-spot block stays where it always was (03/A.2);
    # result.coverage is the run-level shape, not a second invention.
    # (Wasm metadata does not carry the per-binary block; native parses do —
    # asserted below on the .ipa member.)
    assert result.coverage["scope"] == "run"


def test_analyze_result_serializes_without_custom_encoder():
    result = analyze(WASM_FIXTURE, suggest_fuzzable=True)

    dumped = json.dumps(dataclasses.asdict(result))
    assert isinstance(orjson.loads(dumped), dict)


def test_analyze_missing_path_raises_file_not_found():
    with pytest.raises(FileNotFoundError):
        analyze(_DATA_DIR / "definitely-not-here.bin")


def test_analyze_unparseable_file_raises_not_a_binary(tmp_path):
    """A file that parses to nothing must not read like an empty analysis.

    parse() returns near-empty metadata for any unparseable input — the
    trap AGENTS.md documents — so the API turns the missing exe_type into
    a distinct exception instead.
    """
    target = tmp_path / "not-a-binary.bin"
    target.write_bytes(b"this is just text, not an executable\n" * 8)

    with pytest.raises(NotABinaryError):
        analyze(target)


def test_analyze_directory_raises_value_error():
    with pytest.raises(ValueError, match="one binary file"):
        analyze(_DATA_DIR)


def test_analyze_writes_no_files_by_default(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    analyze(WASM_FIXTURE)
    assert list(tmp_path.iterdir()) == []


@needs_go_elf
def test_analyze_attaches_finding_ids(tmp_path):
    result = analyze(GO_ELF, no_reviews=True)
    assert result.findings
    for finding in result.findings:
        finding_id = finding.get("finding_id")
        assert isinstance(finding_id, str) and len(finding_id) == 32
        int(finding_id, 16)  # hex digest


def _minimal_ipa(tmp_path, extra_frameworks=(), name="demo.ipa"):
    """An .ipa with the main executable plus any named framework members;
    enough of a Mach-O header for LIEF to parse each."""
    app_info = plistlib.dumps(
        {"CFBundleExecutable": "DemoApp", "CFBundleIdentifier": "com.example.demo"}
    )
    ipa_path = tmp_path / name
    with zipfile.ZipFile(ipa_path, "w") as zf:
        zf.writestr("Payload/DemoApp.app/Info.plist", app_info)
        zf.writestr("Payload/DemoApp.app/DemoApp", b"\xcf\xfa\xed\xfe" + b"\x00" * 256)
        for framework in extra_frameworks:
            zf.writestr(
                f"Payload/DemoApp.app/Frameworks/{framework}.framework/{framework}",
                b"\xcf\xfa\xed\xfe" + b"\x00" * 256,
            )
    return ipa_path


def test_analyze_single_member_ipa_returns_that_metadata(tmp_path):
    """One member means one binary: its metadata is the result's metadata,
    with the per-binary coverage block the native parse stamps."""
    result = analyze(_minimal_ipa(tmp_path), no_reviews=True)

    assert result.metadata is not None
    assert result.metadata.get("binary_type") == "MachO"
    assert "analysis_coverage" in result.metadata
    by_role = result.coverage["units_by_role"]
    assert by_role["top-level"] == {"attempted": 1, "succeeded": 1, "failed": 0, "skipped": 0}
    assert by_role["ipa-member"]["attempted"] == 1


def test_analyze_multi_member_ipa_returns_no_single_metadata(tmp_path):
    """Several members mean no single metadata dict can speak for the
    archive; findings and the member accounting live in the result."""
    result = analyze(_minimal_ipa(tmp_path, extra_frameworks=("First", "Second")), no_reviews=True)

    assert result.metadata is None
    by_role = result.coverage["units_by_role"]
    assert by_role["ipa-member"]["attempted"] == 3


def test_analyze_top_level_failure_raises_with_record(tmp_path, monkeypatch):
    """A failed top-level unit must surface as an exception, not a clean
    empty result — with the structured failure record attached."""
    import blint.lib.runners as runners_mod

    def exploding_parse(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(runners_mod, "parse", exploding_parse)
    target = tmp_path / "target.bin"
    target.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 256)

    from blint import AnalysisFailedError

    with pytest.raises(AnalysisFailedError) as excinfo:
        analyze(target)
    assert excinfo.value.record["exception_type"] == "RuntimeError"
    assert excinfo.value.record["message"] == "boom"


def test_analyze_bad_sdk_path_raises_api_error_not_system_exit(tmp_path):
    """Run-level config failures exit the CLI; through the API they must
    become ordinary exceptions a caller can catch."""
    from blint import BlintApiError

    empty_sdk = tmp_path / "empty-sdk"
    empty_sdk.mkdir()
    with pytest.raises(BlintApiError):
        analyze(WASM_FIXTURE, sdk_path=str(empty_sdk))


def _run_cli(fixture: Path, reports_dir: Path, *extra: str) -> None:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(_REPO_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    subprocess.run(
        [
            sys.executable,
            "-m",
            "blint.cli",
            "-q",
            "--no-banner",
            "-i",
            str(fixture),
            "-o",
            str(reports_dir),
            *extra,
        ],
        check=True,
        env=env,
        cwd=str(_REPO_ROOT),
    )


def _cli_payload(reports_dir: Path, kind: str):
    payload_file = reports_dir / f"{kind.lower()}.json"
    if not payload_file.exists():
        return []
    return orjson.loads(payload_file.read_bytes())[kind]


@pytest.mark.parametrize(
    "fixture",
    [WASM_FIXTURE, GO_ELF, Path("/bin/ls")],
    ids=["wasm", "elf-go", "macho-ls"],
)
def test_analyze_agrees_with_the_cli_field_for_field(tmp_path, fixture):
    """The API and the CLI run the same engine path; prove it per format."""
    if not fixture.exists():
        pytest.skip(f"fixture {fixture} not available on this host")

    reports_dir = tmp_path / "reports"
    _run_cli(fixture, reports_dir)

    result = analyze(fixture)

    cli_findings = _cli_payload(reports_dir, "findings")
    cli_reviews = _cli_payload(reports_dir, "reviews")
    assert result.findings == cli_findings
    assert result.reviews == cli_reviews
    # metadata: the API returns exactly what the CLI exported.
    metadata_file = next(iter(reports_dir.glob("*-metadata.json")), None)
    if metadata_file is not None:
        assert result.metadata == orjson.loads(metadata_file.read_bytes())


@needs_go_elf
def test_analyze_is_reentrant_across_rule_sets(tmp_path):
    """Sequential analyze() calls each see their own rules (gate: the
    module-global rule state is re-initialized per run, so results match
    what two fresh processes would produce)."""
    custom_dir = tmp_path / "custom-rules"
    custom_dir.mkdir()
    (custom_dir / "marker.yml").write_text(
        "---\n"
        "group: EXE_REVIEWS\n"
        "exe_type: gobinary\n"
        "rules:\n"
        "  - id: CUSTOM_TEST_MARKER_REVIEW\n"
        "    title: Custom marker review\n"
        "    summary: Custom rules were loaded for this call\n"
        "    description: Test-only rule.\n"
        "    patterns:\n"
        "      - main.main\n",
        encoding="utf-8",
    )

    def review_ids(**kwargs):
        return {r["id"] for r in analyze(GO_ELF, **kwargs).reviews}

    with_custom = review_ids(custom_rules_dir=str(custom_dir))
    assert "CUSTOM_TEST_MARKER_REVIEW" in with_custom

    # The next call must not inherit the custom rules...
    without_custom = review_ids()
    assert "CUSTOM_TEST_MARKER_REVIEW" not in without_custom

    # ...and re-passing them must work again (no exhausted one-shot state).
    assert "CUSTOM_TEST_MARKER_REVIEW" in review_ids(custom_rules_dir=str(custom_dir))

    # The default-rules call must equal a fresh CLI process's output.
    reports_dir = tmp_path / "reports"
    _run_cli(GO_ELF, reports_dir)
    assert review_ids() == {r["id"] for r in _cli_payload(reports_dir, "reviews")}


@needs_go_elf
def test_analyze_suggest_fuzzable_returns_methods():
    result = analyze(GO_ELF, no_reviews=True, suggest_fuzzable=True)
    assert result.fuzzables
    assert result.fuzzables[0]["methods"]
