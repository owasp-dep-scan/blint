from pathlib import Path

import orjson

from blint.config import BlintOptions
from blint.lib.runners import run_default_mode, run_sbom_mode


def test_run_default_mode_exports_wasm_report_separately(tmp_path):
    wasm_file = Path(__file__).resolve().parent / "data" / "complex_flow.wasm"
    options = BlintOptions(
        src_dir_image=[str(wasm_file)],
        reports_dir=str(tmp_path),
        no_reviews=True,
        quiet_mode=True,
    )

    run_default_mode(options)

    metadata_file = tmp_path / f"{wasm_file.name}-metadata.json"
    wasm_report_file = tmp_path / f"{wasm_file.name}-wasm-report.json"

    assert metadata_file.exists()
    assert wasm_report_file.exists()

    metadata = orjson.loads(metadata_file.read_bytes())
    wasm_report = orjson.loads(wasm_report_file.read_bytes())

    assert metadata.get("binary_type") == "WASM"
    assert "wasm_report" not in metadata
    assert wasm_report.get("file") == str(wasm_file)
    assert wasm_report.get("module_version") == metadata.get("module_version")


def test_run_default_mode_skips_wasm_disassembly(tmp_path):
    wasm_file = Path(__file__).resolve().parent / "data" / "complex_flow.wasm"
    options = BlintOptions(
        src_dir_image=[str(wasm_file)],
        reports_dir=str(tmp_path),
        no_reviews=True,
        quiet_mode=True,
        disassemble=True,
    )

    run_default_mode(options)

    metadata_file = tmp_path / f"{wasm_file.name}-metadata.json"
    metadata = orjson.loads(metadata_file.read_bytes())
    assert "disassembled_functions" not in metadata


def test_run_sbom_mode_skips_wasm_files(tmp_path):
    wasm_file = Path(__file__).resolve().parent / "data" / "complex_flow.wasm"
    options = BlintOptions(
        sbom_mode=True,
        src_dir_image=[str(wasm_file)],
        reports_dir=str(tmp_path),
        quiet_mode=True,
    )

    sbom = run_sbom_mode(options)

    assert sbom
    assert sbom.metadata
    assert options.sbom_output
