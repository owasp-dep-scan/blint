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
