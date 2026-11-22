"""Table test over the ELF memory-safety fixtures (issue 273).

Every binary under ``tests/data/elf-memory-safety`` is built from one source
with one flag differing per variant (see the README beside them), so the
expected values below are the build matrix stated as facts: each row says
what blint must report for a binary built exactly that way, including the
cases where the honest answer is "not determined".
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from blint.lib.analysis import load_default_rules, run_checks
from blint.lib.binary import parse

DATA = Path(__file__).parent / "data" / "elf-memory-safety"

load_default_rules()

# One row per fixture: the relative path (os.path.join keeps the test
# runnable on Windows path separators), then the memory_safety facts that
# do not need disassembly. ``cet=None`` means no cet block (non-x86), and
# ``clash`` is the expected verdict under --disassemble, ``SKIP`` when the
# fixture is not part of that table.
CASES = [
    # path, sanitizers, cfi, cet(ibt, shstk), fortify_level, clash
    ("x86_64", "gcc-plain", [], False, (False, False), 0, "unprotected"),
    ("x86_64", "gcc-asan", ["asan"], False, (True, True), 3, "SKIP"),
    ("x86_64", "gcc-ubsan", ["ubsan"], False, (True, True), 3, "SKIP"),
    ("x86_64", "gcc-tsan", ["tsan"], False, (True, True), 3, "SKIP"),
    ("x86_64", "clang-msan", ["msan", "ubsan"], False, (False, False), 2, "SKIP"),
    ("x86_64", "gcc-static-asan", ["asan"], False, (True, True), 3, "SKIP"),
    ("x86_64", "clang-ubsan-trap", [], False, (False, False), 0, "SKIP"),
    ("x86_64", "clang-cfi", [], True, (False, False), 0, "SKIP"),
    ("x86_64", "clang-cfi-none", [], False, (False, False), 0, "SKIP"),
    ("x86_64", "gcc-cet-full", [], False, (True, True), 3, "SKIP"),
    ("x86_64", "gcc-cet-none", [], False, (False, False), 3, "SKIP"),
    ("x86_64", "gcc-cet-full-32", [], False, (False, False), 3, "SKIP"),
    ("x86_64", "gcc-stack-clash-on", [], False, (True, True), 3, "protected"),
    ("x86_64", "gcc-stack-clash-off", [], False, (True, True), 3, "unprotected"),
    ("x86_64", "clang-stack-clash-on", [], False, (False, False), 0, "protected"),
    ("x86_64", "clang-stack-clash-off", [], False, (False, False), 0, "unprotected"),
    ("x86_64", "gcc-small-only", [], False, (True, True), 3, "not determined"),
    ("x86_64", "gcc-fortify0", [], False, (True, True), 0, "SKIP"),
    ("x86_64", "gcc-fortify2", [], False, (True, True), 2, "SKIP"),
    ("x86_64", "gcc-fortify3", [], False, (True, True), 3, "SKIP"),
    ("x86_64", "gcc-static-fortify3", [], False, (True, True), 3, "SKIP"),
    ("musl", "x86_64-musl-plain", [], False, (False, False), None, "SKIP"),
    ("aarch64", "gcc-plain", [], False, None, 0, "unprotected"),
    ("aarch64", "gcc-asan", ["asan"], False, None, 3, "SKIP"),
    ("aarch64", "gcc-ubsan", ["ubsan"], False, None, 3, "SKIP"),
    ("aarch64", "gcc-tsan", ["tsan"], False, None, 3, "SKIP"),
    ("aarch64", "clang-hwasan", ["hwasan", "ubsan"], False, None, 0, "SKIP"),
    ("aarch64", "gcc-static-asan", ["asan"], False, None, 3, "SKIP"),
    ("aarch64", "clang-ubsan-trap", [], False, None, 0, "SKIP"),
    ("aarch64", "clang-cfi", [], True, None, 0, "SKIP"),
    ("aarch64", "clang-cfi-none", [], False, None, 0, "SKIP"),
    ("aarch64", "gcc-stack-clash-on", [], False, None, 3, "protected"),
    ("aarch64", "gcc-stack-clash-off", [], False, None, 3, "unprotected"),
    ("aarch64", "clang-stack-clash-on", [], False, None, 0, "protected"),
    ("aarch64", "clang-stack-clash-off", [], False, None, 0, "unprotected"),
    ("aarch64", "gcc-small-only", [], False, None, 3, "not determined"),
    ("aarch64", "gcc-fortify0", [], False, None, 0, "SKIP"),
    ("aarch64", "gcc-fortify2", [], False, None, 2, "SKIP"),
    ("aarch64", "gcc-fortify3", [], False, None, 3, "SKIP"),
    ("aarch64", "gcc-static-fortify3", [], False, None, 3, "SKIP"),
    ("musl", "aarch64-musl-plain", [], False, None, None, "SKIP"),
]


def fixture_path(arch: str, name: str) -> str:
    parts = ("data", "elf-memory-safety", arch, name)
    return os.path.join(str(Path(__file__).parent), *parts)


@pytest.mark.parametrize(
    "arch,name,sanitizers,cfi,cet,fortify,clash",
    CASES,
    ids=[f"{a}-{n}" for a, n, *_ in CASES],
)
def test_memory_safety_facts(arch, name, sanitizers, cfi, cet, fortify, clash) -> None:
    metadata = parse(fixture_path(arch, name))
    facts = metadata["memory_safety"]
    assert facts["sanitizers"] == sanitizers
    assert facts["cfi"] is cfi
    if cet is None:
        assert "cet" not in facts
    else:
        assert (facts["cet"]["ibt"], facts["cet"]["shstk"]) == cet
    assert facts["fortify"]["level"] == fortify
    assert isinstance(facts["fortify"]["symbols"], list)
    # Without --disassemble the stack-clash verdict does not exist, and the
    # security_properties mirror must not invent one.
    assert "stack_clash_protection" not in facts
    properties = metadata["security_properties"]
    assert "stack_clash_protection" not in properties
    if cet is None:
        assert "cet_ibt" not in properties and "cet_shadow_stack" not in properties
    else:
        assert properties["cet_ibt"] is cet[0]
        assert properties["cet_shadow_stack"] is cet[1]
    if fortify is None:
        assert "fortified" not in properties
    else:
        assert properties["fortified"] is (fortify >= 2)


@pytest.mark.parametrize(
    "arch,name,sanitizers,cfi,cet,fortify,clash",
    [case for case in CASES if case[-1] != "SKIP"],
    ids=[f"{a}-{n}" for a, n, *rest in CASES if rest[-1] != "SKIP"],
)
def test_stack_clash_verdict_needs_disassembly(arch, name, sanitizers, cfi, cet, fortify, clash) -> None:
    metadata = parse(fixture_path(arch, name), disassemble=True)
    if not metadata.get("disassembled_functions"):
        pytest.skip("disassembly unavailable (no nyxstone)")
    verdict = metadata["memory_safety"]["stack_clash_protection"]
    assert verdict["status"] == clash
    properties = metadata["security_properties"]
    if clash == "not determined":
        assert "stack_clash_protection" not in properties
        assert verdict["reason"] == "no_function_with_page_crossing_frame"
    else:
        assert properties["stack_clash_protection"] is (clash == "protected")
        if clash == "protected":
            assert verdict["probe_count"] >= 1
        else:
            assert verdict["large_frame_function_count"] >= 1


def _finding_ids(metadata: dict, file_name: str) -> set[str]:
    return {f["id"] for f in run_checks(file_name, metadata)}


def test_x86_cet_check_marks_the_gap_not_the_marked() -> None:
    marked = parse(fixture_path("x86_64", "gcc-cet-full"))
    assert "CHECK_X86_CET" not in _finding_ids(marked, "gcc-cet-full")
    unmarked = parse(fixture_path("x86_64", "gcc-cet-none"))
    ids = _finding_ids(unmarked, "gcc-cet-none")
    assert "CHECK_X86_CET" in ids
    cet_finding = next(f for f in run_checks("gcc-cet-none", unmarked) if f["id"] == "CHECK_X86_CET")
    assert "IBT" in cet_finding["title"] and "SHSTK" in cet_finding["title"]
    # The AArch64 twin never sees an x86 rule (ground rule 35).
    arm = parse(fixture_path("aarch64", "gcc-plain"))
    assert "CHECK_X86_CET" not in _finding_ids(arm, "gcc-plain")


def test_fortify_check_fires_only_on_level_zero() -> None:
    for name in ("gcc-fortify2", "gcc-fortify3", "gcc-static-fortify3"):
        metadata = parse(fixture_path("x86_64", name))
        assert "CHECK_FORTIFY" not in _finding_ids(metadata, name), name
    plain = parse(fixture_path("x86_64", "gcc-fortify0"))
    assert "CHECK_FORTIFY" in _finding_ids(plain, "gcc-fortify0")
    # A static musl build cannot be judged from imports: level None, no check.
    musl = parse(fixture_path("musl", "x86_64-musl-plain"))
    assert "CHECK_FORTIFY" not in _finding_ids(musl, "x86_64-musl-plain")


def test_stack_clash_check_needs_a_measured_gap(monkeypatch) -> None:
    metadata = parse(fixture_path("x86_64", "gcc-stack-clash-off"), disassemble=True)
    if not metadata.get("disassembled_functions"):
        pytest.skip("disassembly unavailable (no nyxstone)")
    assert "CHECK_STACK_CLASH" in _finding_ids(metadata, "gcc-stack-clash-off")
    protected = parse(fixture_path("x86_64", "gcc-stack-clash-on"), disassemble=True)
    if not protected.get("disassembled_functions"):
        pytest.skip("disassembly unavailable (no nyxstone)")
    assert "CHECK_STACK_CLASH" not in _finding_ids(protected, "gcc-stack-clash-on")
    # Without disassembly the verdict is absent and the check stays silent:
    # not measured must not read as measured and clean.
    no_disassembly = parse(fixture_path("x86_64", "gcc-stack-clash-off"))
    assert "CHECK_STACK_CLASH" not in _finding_ids(no_disassembly, "gcc-stack-clash-off")
