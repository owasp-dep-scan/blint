from pathlib import Path

import orjson

from blint.config import BlintOptions
from blint.lib.runners import AnalysisRunner, run_default_mode, run_sbom_mode

_DATA_DIR = Path(__file__).resolve().parent / "data"


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
    assert "callgraph" not in metadata
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


def test_run_default_mode_surfaces_wasm_findings(tmp_path):
    wasm_file = Path(__file__).resolve().parent / "data" / "strings_secrets.wasm"
    options = BlintOptions(
        src_dir_image=[str(wasm_file)],
        reports_dir=str(tmp_path),
        no_reviews=True,
        quiet_mode=True,
    )

    run_default_mode(options)

    findings_file = tmp_path / "findings.json"
    assert findings_file.exists()
    findings_report = orjson.loads(findings_file.read_bytes())
    finding_ids = {f["id"] for f in findings_report["findings"]}
    assert "WASM-STR-007" in finding_ids
    wasm_finding = next(f for f in findings_report["findings"] if f["id"] == "WASM-STR-007")
    assert wasm_finding["severity"] == "high"
    assert wasm_finding["exe_type"] == "wasmbinary"
    assert wasm_finding["exe_name"] == str(wasm_file)


def test_run_default_mode_exports_wasm_callgraph_artifacts(tmp_path):
    wasm_file = Path(__file__).resolve().parent / "data" / "component_minimal.wasm"
    options = BlintOptions(
        src_dir_image=[str(wasm_file)],
        reports_dir=str(tmp_path),
        no_reviews=True,
        quiet_mode=True,
        disassemble=True,
        render_mermaid_callgraph=True,
        export_callgraph_graphml=True,
        export_callgraph_gexf=True,
    )

    run_default_mode(options)

    mmd_file = tmp_path / f"{wasm_file.name}-callgraph.mmd"
    graphml_file = tmp_path / f"{wasm_file.name}-callgraph.graphml"
    gexf_file = tmp_path / f"{wasm_file.name}-callgraph.gexf"
    assert mmd_file.exists()
    assert graphml_file.exists()
    assert gexf_file.exists()

    mmd_text = mmd_file.read_text(encoding="utf-8")
    assert mmd_text.startswith("graph TD")
    assert "N0[" in mmd_text and "N1[" in mmd_text
    assert "<graphml" in graphml_file.read_text(encoding="utf-8")
    assert "<gexf" in gexf_file.read_text(encoding="utf-8")

    metadata = orjson.loads(
        (tmp_path / f"{wasm_file.name}-metadata.json").read_bytes()
    )
    callgraph = metadata["callgraph"]
    assert callgraph["version"] == 2
    assert callgraph["node_count"] == 2
    assert callgraph["edge_count"] == 2


def test_run_default_mode_wasm_opt_outs(tmp_path):
    """--no-wasm-strings and --no-wasm-call-graph remove the derived artifacts."""
    secrets_file = Path(__file__).resolve().parent / "data" / "strings_secrets.wasm"
    options = BlintOptions(
        src_dir_image=[str(secrets_file)],
        reports_dir=str(tmp_path),
        no_reviews=True,
        quiet_mode=True,
        wasm_strings=False,
    )

    run_default_mode(options)

    # The string-derived finding disappears with its evidence source, so no
    # findings report is produced at all for this input.
    assert not (tmp_path / "findings.json").exists()
    wasm_report = orjson.loads(
        (tmp_path / f"{secrets_file.name}-wasm-report.json").read_bytes()
    )
    assert wasm_report["strings"] == []

    component_file = Path(__file__).resolve().parent / "data" / "component_minimal.wasm"
    options = BlintOptions(
        src_dir_image=[str(component_file)],
        reports_dir=str(tmp_path),
        no_reviews=True,
        quiet_mode=True,
        disassemble=True,
        render_mermaid_callgraph=True,
        wasm_call_graph=False,
    )

    run_default_mode(options)

    assert not (tmp_path / f"{component_file.name}-callgraph.mmd").exists()
    metadata = orjson.loads(
        (tmp_path / f"{component_file.name}-metadata.json").read_bytes()
    )
    assert "callgraph" not in metadata


def test_run_default_mode_renders_mermaid_callgraph(tmp_path, monkeypatch):
    fake_binary = tmp_path / "demo-rust"
    fake_binary.write_text("", encoding="utf-8")

    options = BlintOptions(
        src_dir_image=[str(fake_binary)],
        reports_dir=str(tmp_path),
        no_reviews=True,
        quiet_mode=True,
        disassemble=True,
        render_mermaid_callgraph=True,
    )

    fake_metadata = {
        "name": str(fake_binary),
        "exe_type": "genericbinary",
        "callgraph": {
            "version": 1,
            "node_count": 2,
            "edge_count": 1,
            "nodes": [
                {
                    "id": 0,
                    "key": "0x10::core::main",
                    "name": "core::main",
                    "address": "0x10",
                },
                {
                    "id": 1,
                    "key": "0x20::helper",
                    "name": "helper",
                    "address": "0x20",
                },
            ],
            "edges": [{"src": 0, "dst": 1, "count": 1, "kind": "direct"}],
            "external": [],
        },
    }

    monkeypatch.setattr("blint.lib.runners.gen_file_list", lambda _src: [str(fake_binary)])
    monkeypatch.setattr(
        "blint.lib.runners.parse", lambda _f, _d, **_kwargs: dict(fake_metadata)
    )
    monkeypatch.setattr(
        "blint.lib.runners.run_checks",
        lambda _f, _m: [
            {
                "id": "CHECK_TEST",
                "title": "Test finding",
                "severity": "low",
                "filename": str(fake_binary),
                "exe_name": str(fake_binary),
                "exe_type": "genericbinary",
            }
        ],
    )

    run_default_mode(options)

    mmd_file = tmp_path / f"{fake_binary.name}-callgraph.mmd"
    html_file = tmp_path / "blint-output.html"
    assert mmd_file.exists()
    assert html_file.exists()
    assert "graph TD" in mmd_file.read_text(encoding="utf-8")
    html_text = html_file.read_text(encoding="utf-8")
    assert "blint-mermaid-callgraphs" in html_text
    assert 'class="mermaid"' in html_text


def test_run_default_mode_renders_mermaid_without_findings(tmp_path, monkeypatch):
    fake_binary = tmp_path / "clean-bin"
    fake_binary.write_text("", encoding="utf-8")

    options = BlintOptions(
        src_dir_image=[str(fake_binary)],
        reports_dir=str(tmp_path),
        no_reviews=True,
        quiet_mode=True,
        disassemble=True,
        render_mermaid_callgraph=True,
    )

    fake_metadata = {
        "name": str(fake_binary),
        "exe_type": "genericbinary",
        "callgraph": {
            "version": 1,
            "node_count": 1,
            "edge_count": 0,
            "nodes": [
                {
                    "id": 0,
                    "key": "0x10::main",
                    "name": "main",
                    "address": "0x10",
                }
            ],
            "edges": [],
            "external": [],
        },
    }

    monkeypatch.setattr("blint.lib.runners.gen_file_list", lambda _src: [str(fake_binary)])
    monkeypatch.setattr(
        "blint.lib.runners.parse", lambda _f, _d, **_kwargs: dict(fake_metadata)
    )
    monkeypatch.setattr("blint.lib.runners.run_checks", lambda _f, _m: [])

    run_default_mode(options)

    assert (tmp_path / f"{fake_binary.name}-callgraph.mmd").exists()
    assert (tmp_path / "blint-output.html").exists()


def test_run_default_mode_exports_graphml_and_gexf_callgraphs(tmp_path, monkeypatch):
    fake_binary = tmp_path / "graph-export-bin"
    fake_binary.write_text("", encoding="utf-8")

    options = BlintOptions(
        src_dir_image=[str(fake_binary)],
        reports_dir=str(tmp_path),
        no_reviews=True,
        quiet_mode=True,
        disassemble=True,
        export_callgraph_graphml=True,
        export_callgraph_gexf=True,
    )

    fake_metadata = {
        "name": str(fake_binary),
        "exe_type": "genericbinary",
        "callgraph": {
            "version": 1,
            "node_count": 2,
            "edge_count": 1,
            "nodes": [
                {
                    "id": 0,
                    "key": "0x10::main",
                    "name": "main",
                    "address": "0x10",
                },
                {
                    "id": 1,
                    "key": "0x20::helper",
                    "name": "helper",
                    "address": "0x20",
                },
            ],
            "edges": [{"src": 0, "dst": 1, "count": 2, "kind": "direct"}],
            "external": [{"src": 1, "target": "ext::api", "count": 1, "reason": "unresolved"}],
        },
    }

    monkeypatch.setattr("blint.lib.runners.gen_file_list", lambda _src: [str(fake_binary)])
    monkeypatch.setattr(
        "blint.lib.runners.parse", lambda _f, _d, **_kwargs: dict(fake_metadata)
    )
    monkeypatch.setattr("blint.lib.runners.run_checks", lambda _f, _m: [])

    run_default_mode(options)

    graphml_file = tmp_path / f"{fake_binary.name}-callgraph.graphml"
    gexf_file = tmp_path / f"{fake_binary.name}-callgraph.gexf"

    assert graphml_file.exists()
    assert gexf_file.exists()
    assert "<graphml" in graphml_file.read_text(encoding="utf-8")
    assert "<gexf" in gexf_file.read_text(encoding="utf-8")


def test_analysis_runner_coverage_schema():
    """The run-level coverage block has the promised shape from a fresh start."""
    runner = AnalysisRunner()
    coverage = runner.analysis_coverage()
    assert coverage["scope"] == "run"
    assert coverage["units"] == {
        "attempted": 0,
        "succeeded": 0,
        "failed": 0,
        "skipped": 0,
    }
    assert coverage["failures"] == []
    assert coverage["skipped"] == []


def test_run_default_mode_exports_coverage_for_clean_scan(tmp_path):
    """A scan with no findings still exports analysis-coverage.json.

    The export must precede the no-findings early return in report(): a run
    that analyzed everything successfully is exactly the one a caller needs
    to be able to distinguish from a blind one.
    """
    wasm_file = _DATA_DIR / "complex_flow.wasm"
    reports_dir = tmp_path / "reports"
    options = BlintOptions(
        src_dir_image=[str(wasm_file)],
        reports_dir=str(reports_dir),
        no_reviews=True,
        quiet_mode=True,
    )

    run_default_mode(options)

    coverage_file = reports_dir / "analysis-coverage.json"
    assert coverage_file.exists()
    coverage = orjson.loads(coverage_file.read_bytes())
    assert coverage["units"] == {
        "attempted": 1,
        "succeeded": 1,
        "failed": 0,
        "skipped": 0,
    }
    assert coverage["failures"] == []
    assert coverage["skipped"] == []


def test_run_default_mode_isolates_corrupt_binary(tmp_path):
    """A corrupt binary must not abort a scan containing good binaries.

    The corrupt fixture is a real file: an .apk (extension routes it to the
    android analyzer) whose bytes are not a zip, so analyze_android_app
    raises BadZipFile with no mocking involved. The good binary in the same
    scan must still be analyzed and exported, and the failure must be
    machine-readable in analysis-coverage.json.
    """
    good_wasm = _DATA_DIR / "complex_flow.wasm"
    corrupt_apk = tmp_path / "corrupt.apk"
    corrupt_apk.write_bytes(b"PK\x03\x04" + b"\x00" * 64)
    reports_dir = tmp_path / "reports"
    options = BlintOptions(
        src_dir_image=[str(corrupt_apk), str(good_wasm)],
        reports_dir=str(reports_dir),
        no_reviews=True,
        quiet_mode=True,
    )

    run_default_mode(options)

    # The scan continued past the failure: the good binary got analyzed.
    assert (reports_dir / f"{good_wasm.name}-metadata.json").exists()
    assert not (reports_dir / f"{corrupt_apk.name}-metadata.json").exists()

    coverage = orjson.loads((reports_dir / "analysis-coverage.json").read_bytes())
    assert coverage["units"] == {
        "attempted": 2,
        "succeeded": 1,
        "failed": 1,
        "skipped": 0,
    }
    assert len(coverage["failures"]) == 1
    failure = coverage["failures"][0]
    assert failure["file_path"] == str(corrupt_apk)
    assert failure["unit_role"] == "top-level"
    assert failure["stage"] == "process"
    assert failure["exception_type"] == "BadZipFile"
    assert failure["message"]


def test_run_default_mode_isolates_failing_ipa_member(tmp_path, monkeypatch):
    """One bad framework inside an .ipa must not kill the archive's members.

    The archive is a real .ipa fixture; only the poisoned member's parse is
    made to raise (LIEF tolerates arbitrary bytes, so no real Mach-O bytes
    raise from parse). Every non-poisoned member must still be analyzed, and
    the poisoned one recorded as an ipa-member failure.
    """
    import plistlib
    import zipfile

    from blint.lib.runners import parse as runners_parse

    macho_bytes = b"\xcf\xfa\xed\xfe" + b"\x00" * 256
    app_info = plistlib.dumps(
        {
            "CFBundleExecutable": "DemoApp",
            "CFBundleIdentifier": "com.example.demo",
        }
    )
    ipa_path = tmp_path / "demo.ipa"
    with zipfile.ZipFile(ipa_path, "w") as zf:
        zf.writestr("Payload/DemoApp.app/Info.plist", app_info)
        zf.writestr("Payload/DemoApp.app/DemoApp", macho_bytes)
        zf.writestr("Payload/DemoApp.app/Frameworks/Poison.framework/Poison", macho_bytes)
        zf.writestr("Payload/DemoApp.app/Frameworks/Healthy.framework/Healthy", macho_bytes)

    real_parse = runners_parse

    def fake_parse(file_path, disassemble=False, **kwargs):
        if file_path.endswith("Poison"):
            raise ValueError("poisoned member")
        return real_parse(file_path, disassemble, **kwargs)

    monkeypatch.setattr("blint.lib.runners.parse", fake_parse)

    reports_dir = tmp_path / "reports"
    options = BlintOptions(
        src_dir_image=[str(ipa_path)],
        reports_dir=str(reports_dir),
        no_reviews=True,
        quiet_mode=True,
    )

    run_default_mode(options)

    coverage = orjson.loads((reports_dir / "analysis-coverage.json").read_bytes())
    # One archive unit + three member units attempted; the archive itself and
    # two members succeeded, one member failed.
    assert coverage["units"]["attempted"] == 4
    assert coverage["units"]["succeeded"] == 3
    assert coverage["units"]["failed"] == 1
    failure = coverage["failures"][0]
    assert failure["unit_role"] == "ipa-member"
    assert failure["file_path"].endswith("Poison")
    assert failure["exception_type"] == "ValueError"
    assert failure["message"] == "poisoned member"
    # The healthy members were still analyzed and exported.
    exported = {p.name for p in reports_dir.glob("*-metadata.json")}
    assert "demoapp-metadata.json" in exported
    assert "healthy-metadata.json" in exported
    assert "poison-metadata.json" not in exported


def test_run_default_mode_records_unreadable_ipa_skip(tmp_path):
    """An .ipa that cannot even be extracted is a recorded skip, not silence."""
    bad_ipa = tmp_path / "bad.ipa"
    # Binary-looking bytes (so is_exe accepts the file) that are not a zip.
    bad_ipa.write_bytes(b"PK\x03\x04" + b"\x00" * 64)
    reports_dir = tmp_path / "reports"
    options = BlintOptions(
        src_dir_image=[str(bad_ipa)],
        reports_dir=str(reports_dir),
        no_reviews=True,
        quiet_mode=True,
    )

    run_default_mode(options)

    coverage = orjson.loads((reports_dir / "analysis-coverage.json").read_bytes())
    assert coverage["units"]["attempted"] == 1
    assert coverage["units"]["succeeded"] == 0
    assert coverage["units"]["failed"] == 0
    assert coverage["units"]["skipped"] == 1
    skip = coverage["skipped"][0]
    assert skip["file_path"] == str(bad_ipa)
    assert skip["unit_role"] == "top-level"
    assert skip["reason"] == "extract_failed"
