# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT
"""The embedded-SBOM reader for GraalVM native images.

The reader looks up the ``sbom`` and ``sbom_length`` global symbols through
LIEF, reads the declared number of bytes at the payload address, inflates it
with a decompressed-size cap, and accepts only a CycloneDX JSON object. Every
malformed variant here must yield nothing rather than an error, and the happy
path must flow all the way into ``blint sbom`` output.
"""

from __future__ import annotations

from pathlib import Path

import lief
import orjson
import pytest

from blint.config import BlintOptions
from blint.lib.binary_common import parse_graalvm_sbom
from blint.lib.sbom import generate, process_graalvm_sbom_dependencies
from tests.graalvm_sbom_fixtures import (
    bomb_document,
    build_elf,
    build_macho,
    cyclonedx_document,
    gzip_document,
)

QUARKUS_PURL = "pkg:maven/io.quarkus/quarkus-core@4.0.1?type=jar"
MUTINY_PURL = "pkg:maven/io.smallrye.reactive/mutiny@3.2.0?type=jar"


def _write(root: Path, name: str, blob: bytes) -> Path:
    exe_file = root / name
    exe_file.write_bytes(blob)
    return exe_file


@pytest.fixture()
def document() -> dict:
    return cyclonedx_document()


def test_elf_reader_reads_the_embedded_document(tmp_path, document):
    exe_file = _write(tmp_path, "app.elf", build_elf(gzip_document(document)))
    parsed = lief.ELF.parse(str(exe_file))
    doc = parse_graalvm_sbom(parsed)
    assert doc is not None
    assert doc["bomFormat"] == "CycloneDX"
    assert [c["purl"] for c in doc["components"]] == [QUARKUS_PURL, MUTINY_PURL]


def test_macho_reader_reads_the_embedded_document(tmp_path, document):
    exe_file = _write(tmp_path, "app.macho", build_macho(gzip_document(document)))
    fat = lief.MachO.parse(str(exe_file))
    doc = parse_graalvm_sbom(fat.at(0))
    assert doc is not None
    assert doc["specVersion"] == "1.7"
    assert doc["components"][0]["name"] == "quarkus-core"


def test_binary_without_the_symbols_yields_nothing(tmp_path):
    exe_file = _write(
        tmp_path, "plain.elf", build_elf(b"\0" * 64, include_sbom=False, include_length=False)
    )
    parsed = lief.ELF.parse(str(exe_file))
    assert parse_graalvm_sbom(parsed) is None


def test_sbom_symbol_alone_yields_nothing(tmp_path, document):
    exe_file = _write(
        tmp_path, "half.elf", build_elf(gzip_document(document), include_length=False)
    )
    parsed = lief.ELF.parse(str(exe_file))
    assert parse_graalvm_sbom(parsed) is None


def test_length_symbol_alone_yields_nothing(tmp_path, document):
    exe_file = _write(
        tmp_path, "half2.elf", build_elf(gzip_document(document), include_sbom=False)
    )
    parsed = lief.ELF.parse(str(exe_file))
    assert parse_graalvm_sbom(parsed) is None


def test_declared_length_over_the_cap_is_refused(tmp_path, document):
    # The cap check must run before the payload read, so a huge declared
    # length never asks LIEF for a read of that size.
    exe_file = _write(
        tmp_path,
        "huge.elf",
        build_elf(gzip_document(document), declared_length=1 << 40),
    )
    parsed = lief.ELF.parse(str(exe_file))
    assert parse_graalvm_sbom(parsed) is None


def test_declared_length_past_the_mapped_memory_is_refused(tmp_path, document):
    payload = gzip_document(document)
    exe_file = _write(
        tmp_path,
        "past.elf",
        build_elf(payload, declared_length=len(payload) * 4, mapped_bytes=0x210),
    )
    parsed = lief.ELF.parse(str(exe_file))
    assert parse_graalvm_sbom(parsed) is None


def test_invalid_gzip_yields_nothing(tmp_path, document):
    exe_file = _write(tmp_path, "garbage.elf", build_elf(b"not really gzip" * 8))
    parsed = lief.ELF.parse(str(exe_file))
    assert parse_graalvm_sbom(parsed) is None


def test_truncated_gzip_yields_nothing(tmp_path, document):
    payload = gzip_document(document)[:-16]
    exe_file = _write(tmp_path, "cut.elf", build_elf(payload))
    parsed = lief.ELF.parse(str(exe_file))
    assert parse_graalvm_sbom(parsed) is None


def test_gzip_bomb_over_the_decompressed_cap_is_refused(tmp_path):
    exe_file = _write(tmp_path, "bomb.elf", build_elf(bomb_document()))
    parsed = lief.ELF.parse(str(exe_file))
    assert parse_graalvm_sbom(parsed) is None


def test_json_that_is_not_cyclonedx_yields_nothing(tmp_path):
    exe_file = _write(
        tmp_path,
        "spdx.elf",
        build_elf(gzip_document({"bomFormat": "SPDX", "spdxVersion": "SPDX-2.3"})),
    )
    parsed = lief.ELF.parse(str(exe_file))
    assert parse_graalvm_sbom(parsed) is None


def test_raw_deflate_instead_of_gzip_yields_nothing(tmp_path, document):
    import zlib

    exe_file = _write(tmp_path, "deflate.elf", build_elf(zlib.compress(_compact_bytes(document))))
    parsed = lief.ELF.parse(str(exe_file))
    assert parse_graalvm_sbom(parsed) is None


def _compact_bytes(document: dict) -> bytes:
    return orjson.dumps(document)


def test_dependencies_carry_over_and_components_record_their_origin(tmp_path, document):
    deps: dict[str, set] = {}
    comps = process_graalvm_sbom_dependencies(document, deps, str(tmp_path / "runner"))
    assert [c.purl for c in comps] == [QUARKUS_PURL, MUTINY_PURL]
    quarkus = comps[0]
    assert quarkus.version.root == "4.0.1"
    assert quarkus.hashes and str(quarkus.hashes[0].content.root) == "a" * 64
    assert quarkus.licenses and quarkus.licenses.root[0].license.root.id.value == "Apache-2.0"
    assert any(p.name == "internal:embedded_sbom" for p in quarkus.properties)
    assert quarkus.evidence.identity.methods[0].value.endswith("!embedded-sbom")
    # The embedded graph's edge is carried into the dependency dict.
    assert deps[QUARKUS_PURL] == {MUTINY_PURL}


def test_scope_group_and_nested_components_are_kept(tmp_path, document):
    document["components"][1]["scope"] = "excluded"
    document["components"][0]["components"] = [
        {
            "type": "library",
            "bom-ref": "shaded-jctools",
            "group": "org.jctools",
            "name": "jctools-core",
            "version": "4.0.7",
            "purl": "pkg:maven/org.jctools/jctools-core@4.0.7?type=jar",
        }
    ]
    comps = process_graalvm_sbom_dependencies(document, {}, str(tmp_path / "runner"))
    by_name = {c.name: c for c in comps}
    assert set(by_name) == {"quarkus-core", "mutiny", "jctools-core"}
    assert by_name["quarkus-core"].group == "io.quarkus"
    assert by_name["quarkus-core"].scope.value == "required"
    assert by_name["mutiny"].scope.value == "excluded"


def test_embedded_refs_are_translated_and_dangling_edges_dropped(tmp_path, document):
    # A producer may use bom-refs that are not purls. Edges are rewritten onto
    # the purls blint uses as bom-refs, and edges that name the document's root
    # or a component without a purl are dropped.
    document["components"][0]["bom-ref"] = "quarkus-core-ref"
    document["components"][1]["bom-ref"] = "mutiny-ref"
    document["components"].append({"type": "library", "bom-ref": "no-purl", "name": "local"})
    document["dependencies"] = [
        {"ref": "app-root", "dependsOn": ["quarkus-core-ref"]},
        {"ref": "quarkus-core-ref", "dependsOn": ["mutiny-ref", "no-purl", "missing"]},
    ]
    deps: dict[str, set] = {}
    comps = process_graalvm_sbom_dependencies(document, deps, str(tmp_path / "runner"))
    assert [c.bom_ref.root for c in comps] == [QUARKUS_PURL, MUTINY_PURL]
    assert deps == {QUARKUS_PURL: {MUTINY_PURL}, MUTINY_PURL: set()}


def test_each_binary_gets_its_own_components(tmp_path, document):
    # The dependency dict is shared by every binary of a run, so a second
    # image with the same libraries must still return them for its own parent.
    deps: dict[str, set] = {}
    first = process_graalvm_sbom_dependencies(document, deps, str(tmp_path / "a-runner"))
    second = process_graalvm_sbom_dependencies(document, deps, str(tmp_path / "b-runner"))
    assert [c.purl for c in first] == [c.purl for c in second] == [QUARKUS_PURL, MUTINY_PURL]
    assert deps[QUARKUS_PURL] == {MUTINY_PURL}


class _Region:
    def __init__(self, virtual_address: int, virtual_size: int):
        self.virtual_address = virtual_address
        self.virtual_size = virtual_size


class _FakePE:
    """The surface of a LIEF PE binary the reader uses: exports reached through
    ``get_symbol`` with RVA values, sections and no segments."""

    def __init__(self, image: bytes, symbols: dict[str, int], sections: list[_Region]):
        self.image = image
        self.symbols = symbols
        self.sections = sections

    def get_symbol(self, name):
        if name not in self.symbols:
            return None
        return type("Export", (), {"value": self.symbols[name]})()

    def get_content_from_virtual_address(self, address, size):
        return memoryview(self.image[address : address + size])


def _fake_pe(payload: bytes, declared_length: int | None = None) -> _FakePE:
    length_rva, sbom_rva = 0x1000, 0x1010
    image = bytearray(sbom_rva + len(payload) + 0x100)
    image[length_rva : length_rva + 8] = (declared_length or len(payload)).to_bytes(8, "little")
    image[sbom_rva : sbom_rva + len(payload)] = payload
    return _FakePE(
        bytes(image),
        {"sbom": sbom_rva, "sbom_length": length_rva},
        [_Region(0x1000, len(image) - 0x1000)],
    )


def test_pe_exports_are_read_within_their_section(document):
    assert parse_graalvm_sbom(_fake_pe(gzip_document(document)))["bomFormat"] == "CycloneDX"


def test_pe_length_past_the_section_is_refused(document):
    payload = gzip_document(document)
    assert parse_graalvm_sbom(_fake_pe(payload, declared_length=len(payload) + 0x200)) is None


def test_sbom_mode_emits_the_embedded_components(tmp_path, document):
    """End to end through blint sbom: the fixture's embedded SBOM reaches the
    generated document as components with their origin recorded, and the
    embedded dependency graph reaches the dependencies section."""
    exe_file = _write(tmp_path, "app.elf", build_elf(gzip_document(document)))
    out = tmp_path / "native-bom.json"
    options = BlintOptions(
        src_dir_image=[str(exe_file)],
        sbom_mode=True,
        sbom_output=str(out),
        quiet_mode=True,
    )
    generate(options, [str(exe_file)], [])
    bom = orjson.loads(out.read_bytes())
    components = bom.get("components") or []
    embedded = [
        c
        for c in components
        if any(p["name"] == "internal:embedded_sbom" for p in (c.get("properties") or []))
    ]
    assert {c["name"] for c in embedded} == {"quarkus-core", "mutiny"}
    quarkus = next(c for c in embedded if c["name"] == "quarkus-core")
    assert quarkus["purl"] == QUARKUS_PURL
    assert quarkus["hashes"][0]["content"] == "a" * 64
    assert quarkus["licenses"][0]["license"]["id"] == "Apache-2.0"
    deps = bom.get("dependencies") or []
    edge = next(d for d in deps if d["ref"] == QUARKUS_PURL)
    assert MUTINY_PURL in edge["dependsOn"]
    # The embedded document's own metadata never reaches the output: the
    # parent is the scanned binary, not the application the document names.
    assert bom["metadata"]["component"]["name"] != "getting-started"
    assert all(c["name"] != "getting-started" for c in components)
    assert "9a8b7c6d-5e4f-4a3b-2c1d-0e9f8a7b6c5d" not in bom.get("serialNumber", "")
