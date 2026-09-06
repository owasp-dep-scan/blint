# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT
"""ELF layout-coherence metadata and reviews.

The checks under test look for the residue of adding code to a finished ELF
without changing one original byte (arXiv 2607.24888). Two things have to be
true for them to be worth shipping, and both are asserted here: they fire on
an image carrying the paper's transformations, and they stay silent on real
binaries. The second is the harder half — the note-coverage rule started out
firing on every Go binary, which is why ``test_go_binary_is_not_reported`` is
here rather than in a corpus script somebody runs occasionally.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from blint.config import BlintOptions
from blint.lib.analysis import initialize_rules
from blint.lib.binary import parse
from blint.lib.implant_reviews import evaluate_implant_rule
from blint.lib.review_runner import ReviewRunner
from tests.elf_layout_fixtures import (
    appended_exec_segment_elf,
    clean_elf,
    implanted_elf,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS = REPO_ROOT / "corpus-build"


def _write(tmp_path: Path, name: str, image: bytearray) -> str:
    path = tmp_path / name
    path.write_bytes(bytes(image))
    return str(path)


def _kinds(metadata: dict) -> list[str]:
    return [anomaly["kind"] for anomaly in metadata.get("layout_anomalies") or []]


def test_clean_fixture_parses_and_reports_nothing(tmp_path):
    """The baseline: a coherent hand-built ELF must produce no anomaly.

    If this fails, every positive assertion below is meaningless — the
    fixture builder, not the implant, would be what the checks detect.
    """
    metadata = parse(_write(tmp_path, "clean", clean_elf()))
    assert metadata["binary_type"] == "ELF"
    assert metadata["entry_point_section"] == ".text"
    assert _kinds(metadata) == []
    # The segment summary is the raw material the reviews and any future
    # build-to-build diff read; assert it is actually populated.
    types = [segment["type"] for segment in metadata["segments_summary"]]
    assert types.count("LOAD") == 2
    assert "NOTE" in types


def test_implanted_fixture_is_reported(tmp_path):
    """The paper's three transformations, detected without a reference build."""
    metadata = parse(_write(tmp_path, "implanted", implanted_elf()))
    # e_entry was redirected into the appended .payload section.
    assert metadata["entry_point_section"] == ".payload"
    assert set(_kinds(metadata)) == {
        "entry_point_in_unexpected_section",
        "note_section_without_note_segment",
    }
    # The executable mapping does not reach EOF in this layout, because the
    # new section header table is appended after the payload. Asserting the
    # absence keeps the fixture honest about which check catches what.
    assert "executable_mapping_at_eof" not in _kinds(metadata)


def test_appended_exec_segment_reaches_eof(tmp_path):
    """The simpler appender: an executable mapping padded to end-of-file."""
    metadata = parse(_write(tmp_path, "appended", appended_exec_segment_elf()))
    assert "executable_mapping_at_eof" in _kinds(metadata)
    evidence = evaluate_implant_rule("ELF_APPENDED_EXECUTABLE_MAPPING", metadata)
    assert evidence and evidence[0]["segment"].startswith("PT_LOAD[")


def test_implanted_fixture_reaches_the_reviews(tmp_path):
    """End to end: parse to review ids, through the real rule loading path."""
    initialize_rules(BlintOptions())
    metadata = parse(_write(tmp_path, "implanted", implanted_elf()))
    results = ReviewRunner().run_review(metadata)
    assert "ELF_ENTRY_POINT_OUTSIDE_CODE" in results
    assert "ELF_NOTE_SECTION_WITHOUT_SEGMENT" in results
    # Evidence must name the section and address so a reviewer can check the
    # claim against readelf rather than trust the label.
    entry_evidence = results["ELF_ENTRY_POINT_OUTSIDE_CODE"][0]
    assert entry_evidence["section"] == ".payload"
    assert entry_evidence["entrypoint"].startswith("0x")


def test_clean_fixture_reaches_the_reviews_with_nothing_to_say(tmp_path):
    initialize_rules(BlintOptions())
    metadata = parse(_write(tmp_path, "clean", clean_elf()))
    results = ReviewRunner().run_review(metadata)
    assert "ELF_ENTRY_POINT_OUTSIDE_CODE" not in results
    assert "ELF_NOTE_SECTION_WITHOUT_SEGMENT" not in results
    assert "ELF_APPENDED_EXECUTABLE_MAPPING" not in results


def test_entry_point_in_a_non_executable_section(tmp_path):
    """Entry redirected into data: the section table and e_entry disagree."""
    from tests import elf_layout_fixtures as fx

    image = clean_elf()
    # Point e_entry at the note section, which is SHF_ALLOC but not
    # SHF_EXECINSTR.
    image[0 : fx.EHDR_SIZE] = fx._ehdr(
        fx.IMAGE_BASE + fx.NOTE_OFF, fx.SHDR_OFF, 3, 4
    )
    metadata = parse(_write(tmp_path, "data-entry", image))
    assert "entry_point_in_non_executable_section" in _kinds(metadata)
    assert metadata["entry_point_section"] == ".note.gnu.build-id"


def test_entry_point_covered_by_no_section(tmp_path):
    """The strong form: e_entry lands where no section header reaches."""
    from tests import elf_layout_fixtures as fx

    image = clean_elf()
    image[0 : fx.EHDR_SIZE] = fx._ehdr(fx.IMAGE_BASE + 0x900000, fx.SHDR_OFF, 3, 4)
    metadata = parse(_write(tmp_path, "nowhere-entry", image))
    assert "entry_point_outside_any_section" in _kinds(metadata)
    assert metadata["entry_point_section"] == ""


def test_build_sandbox_gate_requires_a_structural_finding(tmp_path):
    """The env probe is ordinary alone and evidence only beside an anomaly."""
    metadata = parse(_write(tmp_path, "implanted", implanted_elf()))
    metadata["strings"] = [{"value": "NIX_BUILD_TOP"}, {"value": "unrelated"}]
    evidence = evaluate_implant_rule("ELF_BUILD_SANDBOX_EVASION_GATE", metadata)
    assert [entry["variable"] for entry in evidence] == ["NIX_BUILD_TOP"]
    assert evidence[0]["corroborated_by"]

    innocent = {"layout_anomalies": [], "strings": [{"value": "NIX_BUILD_TOP"}]}
    assert evaluate_implant_rule("ELF_BUILD_SANDBOX_EVASION_GATE", innocent) == []


@pytest.mark.parametrize(
    "fixture_name",
    ["go-elf-stripped", "go-elf-unstripped", "rust-elf-stripped", "rust-elf-unstripped"],
)
def test_real_elf_fixtures_report_no_anomaly(fixture_name):
    """False-positive guard on the real ELFs available locally.

    ``go-elf-*`` is the one that matters most. The Go linker emits a PT_NOTE
    spanning only ``.note.go.buildid`` and leaves the adjacent
    ``.note.gnu.build-id`` outside it, so a per-section note-coverage rule —
    which is what this started as — fires on every Go binary ever built.
    """
    fixture = CORPUS / fixture_name
    if not fixture.exists():
        pytest.skip(f"{fixture} not materialized; run tests/scripts/build_corpus.py")
    metadata = parse(str(fixture))
    assert _kinds(metadata) == []
    assert metadata["entry_point_section"] == ".text"


def test_static_elf_gets_an_exe_type():
    """A static ELF must not fall out of every review group.

    ``detect_exe_type`` tested ``"musl" in metadata["interpreter"]`` on a
    binary with no interpreter, and the TypeError was swallowed by the
    enclosing suppress() — so every statically linked ELF came back with an
    empty ``exe_type``, and ``ReviewRunner.run_review`` returns early on an
    empty one. No review rule of any group could fire on a static binary.
    """
    fixture = CORPUS / "rust-elf-stripped"
    if not fixture.exists():
        pytest.skip(f"{fixture} not materialized; run tests/scripts/build_corpus.py")
    metadata = parse(str(fixture))
    assert not metadata.get("interpreter")
    assert metadata["exe_type"], "static ELF fell back to an empty exe_type"


def test_layout_fields_are_absent_for_non_elf(tmp_path):
    """The fields are ELF-specific and must not appear on other formats."""
    not_elf = tmp_path / "plain.bin"
    not_elf.write_bytes(os.urandom(2048))
    metadata = parse(str(not_elf))
    assert "layout_anomalies" not in metadata
    assert "segments_summary" not in metadata
