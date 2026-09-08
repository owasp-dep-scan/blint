"""Tests for stable finding IDs (D4): determinism, distinctness, and the
documented identity semantics."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from blint import analyze
from blint.lib.finding_ids import (
    attach_finding_ids,
    binary_identity_digest,
    compute_finding_id,
)

_DATA_DIR = Path(__file__).resolve().parent / "data"
_REPO_ROOT = Path(__file__).resolve().parent.parent
_CORPUS_DIR = _REPO_ROOT / "corpus-build"
GO_ELF = _CORPUS_DIR / "go-elf-unstripped"
GO_ELF_STRIPPED = _CORPUS_DIR / "go-elf-stripped"
SECRETS_WASM = _DATA_DIR / "strings_secrets.wasm"

needs_go_elf = pytest.mark.skipif(
    not GO_ELF.exists(), reason="corpus fixture go-elf-unstripped not built"
)


def test_compute_finding_id_depends_only_on_its_three_inputs():
    base = compute_finding_id("CHECK_NX", "a" * 64, "")
    # Stable for identical inputs.
    assert base == compute_finding_id("CHECK_NX", "a" * 64, "")
    # Each axis alone changes the id.
    assert base != compute_finding_id("CHECK_PIE", "a" * 64, "")
    assert base != compute_finding_id("CHECK_NX", "b" * 64, "")
    assert base != compute_finding_id("CHECK_NX", "a" * 64, '{"code":7}')


def test_same_rule_different_evidence_gets_distinct_ids():
    """Two findings of one rule against different evidence must not share
    an id; an ordinal index is exactly what must not be used."""
    id_a = compute_finding_id("WASM-STR-007", "a" * 64, '{"function":1}')
    id_b = compute_finding_id("WASM-STR-007", "a" * 64, '{"function":2}')
    assert id_a != id_b


def test_ids_stay_unique_when_a_rule_repeats_identical_evidence():
    """IDs must be unique within one binary, whatever the engine emits.

    No rule emits two findings with the same evidence today, but consumers
    key suppressions and diffs on these ids, so a collision must break the
    tie rather than collapse the two findings into one.
    """
    metadata = {"hashes": {"sha256": "c" * 64}}
    findings = [
        {"id": "WASM-STR-007", "evidence": {"function": 3}},
        {"id": "WASM-STR-007", "evidence": {"function": 3}},
        {"id": "WASM-STR-007", "evidence": {"function": 4}},
    ]
    attach_finding_ids(str(SECRETS_WASM), metadata, findings)
    ids = [f["finding_id"] for f in findings]
    assert len(set(ids)) == 3
    # The first occurrence keeps the plain id, so adding a duplicate later
    # does not re-track the finding that was already there.
    assert ids[0] == compute_finding_id("WASM-STR-007", "c" * 64, '{"function":3}')


def test_binary_identity_digest_prefers_metadata_hash():
    metadata = {"hashes": {"sha256": "f" * 64}}
    assert binary_identity_digest(metadata, str(SECRETS_WASM)) == "f" * 64


def test_attach_finding_ids_on_wasm_findings():
    result = analyze(SECRETS_WASM)
    assert result.findings, "fixture should emit WASM-STR-007"
    finding = result.findings[0]
    assert finding["id"] == "WASM-STR-007"
    assert len(finding["finding_id"]) == 32


def _finding_ids_via_subprocess(fixture: Path) -> list[str]:
    probe = (
        "from blint import analyze\n"
        "r = analyze(r'" + str(fixture) + "')\n"
        "print('\\n'.join(f['finding_id'] for f in r.findings))"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = str(_REPO_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True,
        check=True,
        env=env,
        cwd=str(_REPO_ROOT),
    )
    return proc.stdout.decode().split()


def test_finding_ids_identical_across_two_processes():
    """Same bytes, two fresh interpreters: identical ids (rule 22 form)."""
    first = _finding_ids_via_subprocess(SECRETS_WASM)
    second = _finding_ids_via_subprocess(SECRETS_WASM)
    in_process = [f["finding_id"] for f in analyze(SECRETS_WASM).findings]
    assert first and second and in_process
    assert first == second == in_process


def test_finding_ids_survive_moving_the_binary(tmp_path):
    """The file path is not in the hash: moving or renaming keeps ids."""
    moved = tmp_path / "renamed-copy.wasm"
    moved.write_bytes(SECRETS_WASM.read_bytes())

    original_ids = [f["finding_id"] for f in analyze(SECRETS_WASM).findings]
    moved_ids = [f["finding_id"] for f in analyze(moved).findings]

    assert original_ids == moved_ids


def test_finding_ids_change_when_bytes_change(tmp_path):
    """Documented identity semantics, pinned on purpose: the identity is
    the whole-file sha256, so any byte change mints new ids — including
    for findings whose own evidence did not change. Rebuild-stable identity
    needs an engine-computed content primitive (P4.4's call), not a second
    parser bolted on here.
    """
    modified = tmp_path / "modified.wasm"
    modified.write_bytes(SECRETS_WASM.read_bytes() + b"\x00\x00\x00\x00")

    original = analyze(SECRETS_WASM).findings
    modified_findings = analyze(modified).findings

    # The appended bytes make wasm-tools report an extra malformation; the
    # point here is the shared finding: same rule, new identity, new id.
    shared = {f["id"] for f in original} & {f["id"] for f in modified_findings}
    assert shared == {"WASM-STR-007"}
    original_id = next(f["finding_id"] for f in original if f["id"] == "WASM-STR-007")
    modified_id = next(f["finding_id"] for f in modified_findings if f["id"] == "WASM-STR-007")
    assert original_id != modified_id


@needs_go_elf
def test_different_binaries_same_rule_get_different_ids():
    a = analyze(GO_ELF, no_reviews=True).findings
    b = analyze(GO_ELF_STRIPPED, no_reviews=True).findings
    common = {f["id"] for f in a} & {f["id"] for f in b}
    assert common, "expected at least one shared rule between the fixtures"
    for rule_id in common:
        id_a = next(f["finding_id"] for f in a if f["id"] == rule_id)
        id_b = next(f["finding_id"] for f in b if f["id"] == rule_id)
        assert id_a != id_b
