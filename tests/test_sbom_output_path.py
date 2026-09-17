"""Regression tests for the output path handling in ``create_sbom``.

``blint sbom -o out/sbom.cdx.json`` (a relative path with a directory part)
used to join the directory twice (``out/out/sbom.cdx.json``). The write then
failed, but ``custom_json_diff.lib.utils.file_write`` only logs ``OSError`` at
debug level, so the command exited 0 without producing a file. Flat relative
paths (#142) and absolute paths were unaffected.
"""

import os
import uuid
from pathlib import Path

import orjson
import pytest

from blint.cyclonedx.spec import BomFormat, CycloneDX
from blint.lib.sbom import create_sbom, default_metadata


def _new_sbom() -> CycloneDX:
    sbom = CycloneDX(
        bomFormat=BomFormat.CycloneDX,
        specVersion="1.6",
        version=1,
        serialNumber=f"urn:uuid:{uuid.uuid4()}",
    )
    sbom.metadata = default_metadata(["app"])
    return sbom


@pytest.mark.parametrize(
    "output_file",
    [
        # relative path with a directory that does not exist yet
        os.path.join("out", "sbom.cdx.json"),
        # relative path with an explicit leading "."
        os.path.join(".", "out", "sbom.cdx.json"),
        # relative path without a directory part (#142)
        "sbom.cdx.json",
    ],
)
def test_create_sbom_writes_relative_output_path(tmp_path, monkeypatch, output_file):
    monkeypatch.chdir(tmp_path)

    create_sbom([], [], output_file, _new_sbom(), False, {})

    written = Path(output_file)
    assert written.is_file(), f"expected {written.resolve()} to be written"
    assert orjson.loads(written.read_bytes())["bomFormat"] == "CycloneDX"


def test_create_sbom_writes_relative_output_path_into_existing_dir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    os.makedirs("out")

    create_sbom([], [], os.path.join("out", "sbom.cdx.json"), _new_sbom(), False, {})

    assert (tmp_path / "out" / "sbom.cdx.json").is_file()


def test_create_sbom_writes_absolute_output_path(tmp_path):
    output_file = str(tmp_path / "out" / "sbom.cdx.json")

    create_sbom([], [], output_file, _new_sbom(), False, {})

    assert Path(output_file).is_file()


def test_create_sbom_logs_when_the_write_fails(tmp_path, monkeypatch, caplog):
    """A destination blint cannot write to must not look like a clean run.

    ``custom_json_diff.lib.utils.file_write`` catches ``OSError`` and logs it at
    debug level, so the failure is otherwise invisible without
    ``SCAN_DEBUG_MODE=debug``.
    """
    monkeypatch.chdir(tmp_path)
    # A directory standing where the output file should go makes the write fail
    # while leaving the makedirs above it happy.
    os.makedirs(os.path.join("out", "sbom.cdx.json"))

    with caplog.at_level("ERROR"):
        create_sbom([], [], os.path.join("out", "sbom.cdx.json"), _new_sbom(), False, {})

    assert any("Unable to write the SBOM" in record.message for record in caplog.records)
