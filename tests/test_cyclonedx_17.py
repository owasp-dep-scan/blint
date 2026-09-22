r"""Tests for CycloneDX 1.7 emission (W6.1).

The generated model (``blint/cyclonedx/spec.py``) is the official 1.7
schema; blint declares ``specVersion`` 1.7 by default and keeps 1.6
selectable via ``--sbom-spec-version``. The load-bearing property this file
pins: **blint populates no 1.7-only field**, so a document declared 1.6 is
exactly the 1.6 shape — the two emissions differ only in ``specVersion``
(and the per-run ``serialNumber``/``timestamp``). That property is why one
generated module serves both emit paths, and it is what was validated by
hand against the official ``bom-1.6.schema.json`` and
``bom-1.7.schema.json`` (jsonschema, Draft7Validator, both PASS for both
declarations — recorded in the W6.1 commit) and against Dependency-Track
ingestion (``POST /api/v1/bom`` on an ephemeral apiserver container, both
declarations parsed with the expected component count).
"""

import os

import orjson
import pytest

from blint.config import BlintOptions
from blint.cyclonedx.spec import Component, CycloneDX
from blint.lib.sbom import generate

_LS = "/bin/ls"


def _emit(tmp_path, spec_version):
    out = tmp_path / f"bom-{spec_version}.cdx.json"
    options = BlintOptions(
        src_dir_image=[_LS],
        sbom_mode=True,
        sbom_output=str(out),
        sbom_spec_version=spec_version,
        quiet_mode=True,
    )
    generate(options, [_LS], [])
    assert out.is_file()
    return orjson.loads(out.read_bytes())


def _stable(doc):
    """The document minus per-run fields (uuid serial, timestamp) and the
    declaration itself — what remains must be identical across versions."""
    doc = dict(doc)
    doc.pop("serialNumber", None)
    doc.pop("specVersion", None)
    metadata = dict(doc.get("metadata") or {})
    metadata.pop("timestamp", None)
    doc["metadata"] = metadata
    return doc


@pytest.mark.skipif(not os.path.isfile(_LS), reason="needs a macOS/Linux /bin/ls")
def test_default_emit_declares_1_7(tmp_path):
    doc = _emit(tmp_path, "1.7")
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.7"
    assert doc["components"]


@pytest.mark.skipif(not os.path.isfile(_LS), reason="needs a macOS/Linux /bin/ls")
def test_1_6_emit_is_exactly_the_1_6_shape(tmp_path):
    doc17 = _emit(tmp_path, "1.7")
    doc16 = _emit(tmp_path, "1.6")
    assert doc16["specVersion"] == "1.6"
    # The W6.1 property: nothing 1.7-only is populated, so apart from the
    # declaration (and per-run uuid/timestamp) the documents are identical.
    assert _stable(doc16) == _stable(doc17)


@pytest.mark.skipif(not os.path.isfile(_LS), reason="needs a macOS/Linux /bin/ls")
def test_unknown_spec_version_falls_back_to_1_7(tmp_path):
    doc = _emit(tmp_path, "")
    assert doc["specVersion"] == "1.7"


def test_generated_model_is_the_1_7_model():
    # Pins the regeneration: the 1.7-only fields exist on the generated
    # model, so a regression to a stale spec.py fails here rather than
    # silently emitting from the old schema.
    assert "citations" in CycloneDX.model_fields
    assert "isExternal" in Component.model_fields
    assert "versionRange" in Component.model_fields


def test_cli_accepts_both_spec_versions():
    from blint.cli import build_parser

    parser = build_parser()
    parsed = parser.parse_args(["sbom", "--sbom-spec-version", "1.6", "-i", "."])
    assert parsed.sbom_spec_version == "1.6"
    parsed = parser.parse_args(["sbom", "-i", "."])
    assert parsed.sbom_spec_version == "1.7"
    with pytest.raises(SystemExit):
        parser.parse_args(["sbom", "--sbom-spec-version", "1.5", "-i", "."])
