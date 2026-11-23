"""The SBOM names scanned files relative to the scan root and leaves out
the build machine's file records."""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from blint.api import sbom
from blint.lib.sbom import _is_file_record, relativize_scan_paths

PLAIN_ELF = Path(__file__).resolve().parent / "data" / "plain-libc-demo.elf"


def _walk(component):
    yield component
    for child in component.get("components") or []:
        yield from _walk(child)


def _components(bom):
    for component in [bom["metadata"]["component"], *bom.get("components", [])]:
        yield from _walk(component)


def _values(bom, prop):
    return [
        p["value"] for c in _components(bom) for p in c.get("properties", []) if p["name"] == prop
    ]


def test_src_file_is_relative_to_the_scan_root(tmp_path):
    root = tmp_path / "scan"
    (root / "bin" / "release").mkdir(parents=True)
    shutil.copy(PLAIN_ELF, root / "bin" / "release" / "prog")
    result = sbom(str(root))
    text = json.dumps(result.bom)
    assert str(root) not in text
    assert str(tmp_path) not in text
    assert set(_values(result.bom, "internal:srcFile")) == {"bin/release/prog"}
    methods = [
        m["value"]
        for c in _components(result.bom)
        for i in (
            [c["evidence"]["identity"]]
            if isinstance(c.get("evidence", {}).get("identity"), dict)
            else c.get("evidence", {}).get("identity", [])
        )
        for m in i["methods"]
    ]
    assert set(methods) == {"bin/release/prog"}


def test_a_file_given_directly_is_named_by_its_file_name(tmp_path):
    target = tmp_path / "deep" / "prog"
    target.parent.mkdir()
    shutil.copy(PLAIN_ELF, target)
    bom = sbom(str(target)).bom
    assert set(_values(bom, "internal:srcFile")) == {"prog"}


def test_a_path_outside_the_scan_root_is_left_alone(tmp_path):
    from blint.cyclonedx.spec import Component, Property, Type

    outside = str(tmp_path / "elsewhere" / "x.so")
    component = Component(
        type=Type.library,
        name="x",
        properties=[Property(name="internal:srcFile", value=outside)],
    )
    relativize_scan_paths([component], [str(tmp_path / "scan")])
    assert component.properties[0].value == outside


def test_elf_file_symbols_stay_out_of_the_bom(tmp_path):
    result = sbom(str(PLAIN_ELF), deep=True)
    symbols = []
    for value in _values(result.bom, "internal:symtab_symbols"):
        symbols += value.split("~~")
    assert symbols
    assert "prog.c" not in symbols
    assert "crtstuff.c" not in symbols


def test_file_records_are_recognised():
    assert _is_file_record({"name": "a.c", "type": "FILE"})
    assert _is_file_record({"name": "/x/a.o", "debug_map_path": True})
    assert not _is_file_record({"name": "github.com/x/y.Fn", "type": "FUNC"})


@pytest.mark.skipif(sys.platform != "darwin" or not shutil.which("cc"), reason="needs Mach-O cc")
def test_macho_debug_map_paths_are_flagged_and_left_out_of_the_bom(tmp_path):
    from blint.lib.binary import parse

    source = tmp_path / "m.c"
    source.write_text("int main(void) { return 0; }\n")
    binary = tmp_path / "scan" / "m"
    binary.parent.mkdir()
    subprocess.run(["cc", "-g", "-O0", str(source), "-o", str(binary)], check=True)
    flagged = [s for s in parse(str(binary))["symtab_symbols"] if s.get("debug_map_path")]
    assert flagged
    assert any(str(tmp_path) in s["name"] for s in flagged)
    bom = sbom(str(binary.parent), deep=True).bom
    assert str(tmp_path) not in json.dumps(bom)
