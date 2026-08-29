"""Opt-in SBOM support for wasm Component Model binaries (--wasm-sbom).

Component imports carry exact dependency evidence: a WIT package identifier
with an optional version (e.g. ``wasi:cli/run@0.2.0``). The tests pin the
purl mapping (namespace/package split with the ``type=wasm`` qualifier), the
grouping of several interfaces into one package component, and the
strictness rules that keep core-module noise and guesses out of the SBOM.
"""

import uuid
from pathlib import Path

import orjson

from blint.config import BlintOptions
from blint.cyclonedx.spec import BomFormat, CycloneDX, Scope, Type
from blint.lib.binary import parse
from blint.lib.sbom import (
    default_metadata,
    generate,
    group_wasm_interface_imports,
    process_wasm_file,
)

DATA_DIR = Path(__file__).resolve().parent / "data"
COMPONENT_FIXTURE = str(DATA_DIR / "component_minimal.wasm")
CORE_FIXTURE = str(DATA_DIR / "complex_flow.wasm")

WASI_CLI_PURL = "pkg:generic/wasi/cli@0.2.0?type=wasm"
WASI_IO_PURL = "pkg:generic/wasi/io@0.3.0?type=wasm"


def _new_sbom() -> CycloneDX:
    sbom = CycloneDX(
        bomFormat=BomFormat.CycloneDX,
        specVersion="1.6",
        version=1,
        serialNumber=f"urn:uuid:{uuid.uuid4()}",
    )
    sbom.metadata = default_metadata([COMPONENT_FIXTURE])
    return sbom


def test_group_wasm_interface_imports_groups_by_package():
    grouped = group_wasm_interface_imports(
        [
            {"kind": "instance", "name": "wasi:cli/run@0.2.0"},
            {"kind": "instance", "name": "wasi:cli/stdio@0.2.0"},
            {"kind": "func", "name": "wasi:io/streams@0.3.0"},
            # Same package at another version stays a separate component.
            {"kind": "instance", "name": "wasi:io/streams@0.2.0"},
            # Unversioned imports keep the package identity without a version.
            {"kind": "instance", "name": "wasi:io/poll"},
        ]
    )
    assert grouped == {
        ("wasi", "cli", "0.2.0"): {"wasi:cli/run@0.2.0", "wasi:cli/stdio@0.2.0"},
        ("wasi", "io", "0.3.0"): {"wasi:io/streams@0.3.0"},
        ("wasi", "io", "0.2.0"): {"wasi:io/streams@0.2.0"},
        ("wasi", "io", None): {"wasi:io/poll"},
    }


def test_group_wasm_interface_imports_drops_unidentifiable_names():
    """Only names following the WIT package grammar produce components."""
    assert (
        group_wasm_interface_imports(
            [
                {"kind": "core-module", "name": "sandbox"},
                {"kind": "func", "name": ""},
                {},
                {"kind": "func", "name": "UPPER:Bad/Name@1.0"},
                {"kind": "func", "name": "wasi_snapshot_preview1"},
            ]
        )
        == {}
    )


def test_process_wasm_file_emits_interface_package_components():
    sbom = _new_sbom()
    dependencies_dict: dict[str, set] = {}
    components = process_wasm_file(dependencies_dict, COMPONENT_FIXTURE, sbom)

    assert {comp.purl for comp in components} == {WASI_CLI_PURL, WASI_IO_PURL}
    cli_comp = next(comp for comp in components if comp.purl == WASI_CLI_PURL)
    assert cli_comp.type == Type.library
    assert cli_comp.name == "cli"
    assert cli_comp.group == "wasi"
    assert cli_comp.version.root == "0.2.0"
    assert cli_comp.scope == Scope.required
    prop_map = {prop.name: prop.value for prop in cli_comp.properties}
    assert prop_map["internal:srcFile"] == COMPONENT_FIXTURE
    assert prop_map["internal:interfaces"] == "wasi:cli/run@0.2.0"
    assert prop_map["internal:wit_package"] == "wasi:cli"

    # The wasm binary itself becomes the application parent with its
    # component-model facts as properties.
    parents = sbom.metadata.component.components
    assert len(parents) == 1
    parent_props = {prop.name: prop.value for prop in parents[0].properties}
    assert parent_props["internal:binary_type"] == "WASM"
    assert parent_props["internal:is_component"] == "true"
    assert parent_props["internal:runtime"] == "WASI"
    assert parent_props["internal:wasi_variants"] == "preview2, preview3"
    assert parent_props["internal:component_version"] == "13"
    # The fixture exports nothing, so no exported-interfaces property.
    assert "internal:exported_interfaces" not in parent_props

    assert dependencies_dict["pkg:generic/component_minimal.wasm"] == {
        WASI_CLI_PURL,
        WASI_IO_PURL,
    }


def test_process_wasm_file_skips_core_modules():
    """Core modules have no reliable dependency evidence and stay skipped."""
    sbom = _new_sbom()
    dependencies_dict: dict[str, set] = {}
    for fixture in (CORE_FIXTURE, str(DATA_DIR / "producers_toolchain.wasm")):
        assert process_wasm_file(dependencies_dict, fixture, sbom) == []
    assert sbom.metadata.component.components in (None, [])
    assert dependencies_dict == {}


def test_process_wasm_file_records_exported_interfaces_without_components(monkeypatch):
    """Exports are capabilities, not dependencies: property, never a component."""
    metadata = parse(COMPONENT_FIXTURE)
    metadata["wasm_report"]["component"]["exports"] = [
        {"name": "my:app/api@1.0.0", "kind": "instance", "index": 0}
    ]
    monkeypatch.setattr("blint.lib.sbom.parse", lambda _exe, **_kwargs: metadata)
    sbom = _new_sbom()
    dependencies_dict: dict[str, set] = {}

    components = process_wasm_file(dependencies_dict, COMPONENT_FIXTURE, sbom)

    # The two imported packages are still components; the export is not.
    assert {comp.purl for comp in components} == {WASI_CLI_PURL, WASI_IO_PURL}
    parents = sbom.metadata.component.components
    parent_props = {prop.name: prop.value for prop in parents[0].properties}
    assert parent_props["internal:exported_interfaces"] == "my:app/api@1.0.0"


def test_generate_includes_wasm_components_only_with_flag(tmp_path):
    with_flag_output = str(tmp_path / "with.cdx.json")
    options = BlintOptions(
        sbom_mode=True,
        quiet_mode=True,
        src_dir_image=[COMPONENT_FIXTURE],
        sbom_output=with_flag_output,
        wasm_sbom=True,
    )
    generate(options, [COMPONENT_FIXTURE], [], [])
    data = orjson.loads(Path(with_flag_output).read_bytes())
    purls = {component["purl"] for component in data["components"]}
    assert {WASI_CLI_PURL, WASI_IO_PURL} <= purls

    without_flag_output = str(tmp_path / "without.cdx.json")
    options = BlintOptions(
        sbom_mode=True,
        quiet_mode=True,
        src_dir_image=[COMPONENT_FIXTURE],
        sbom_output=without_flag_output,
    )
    generate(options, [COMPONENT_FIXTURE], [], [])
    data = orjson.loads(Path(without_flag_output).read_bytes())
    assert not any(
        "type=wasm" in component.get("purl", "") for component in data.get("components", [])
    )
    assert not any(
        WASI_CLI_PURL in str(dep) for dep in data.get("dependencies", [])
    )
