"""Tests for the A4a native accuracy probe (tests/scripts/android/native_probe.py).

The parsing tests assert against real recorded ``llvm-readelf`` /
``llvm-objdump`` output (``tests/data/android/native-probe/``); the commands
and the tool versions that produced each file are named in that directory's
README. The end-to-end tests additionally need the tools themselves and the
corpus fixture, so they skip wherever those are absent.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

SCRIPT_PATH = Path(__file__).parent / "scripts" / "android" / "native_probe.py"
FIXTURE_DIR = Path(__file__).parent / "data" / "android" / "native-probe"
CORPUS_V7A = (
    Path.home()
    / "sandbox"
    / "android-corpus"
    / "tier1-ndk"
    / "r28"
    / "armeabi-v7a"
    / "libhello.so"
)
CORPUS_V7A_UNSTRIPPED = (
    Path.home()
    / "sandbox"
    / "android-corpus"
    / "tier1-ndk"
    / "r28"
    / "armeabi-v7a"
    / "unstripped"
    / "libhello.so"
)
CORPUS_ARM64 = (
    Path.home() / "sandbox" / "android-corpus" / "tier1-ndk" / "r28" / "arm64-v8a" / "libhello.so"
)

spec = importlib.util.spec_from_file_location("native_probe", SCRIPT_PATH)
native_probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native_probe)


def _fixture(name: str) -> str:
    return (FIXTURE_DIR / name).read_text(encoding="utf-8")


def _nyxstone_available() -> bool:
    try:
        from blint.lib.disassembler import NYXSTONE_AVAILABLE

        return NYXSTONE_AVAILABLE
    except ImportError:
        return False


def _tools_available() -> bool:
    try:
        native_probe.resolve_llvm_bin(None)
        return True
    except native_probe.ProbeError:
        return False


# ------------------------------------------------------------------ readelf


def test_readelf_symbols_keep_thumb_bit_and_sizes() -> None:
    functions, mapping = native_probe.parse_readelf_symbols(
        _fixture("libhello-v7a-readelf-symbols.txt")
    )
    # Four defined FUNC symbols; imports (UND) and OBJECT symbols excluded.
    assert sorted(hex(start) for start in functions) == ["0x50c", "0x514", "0x574", "0x59c"]
    assert functions[0x50C] == {
        "name": "JNI_OnLoad",
        "start": 0x50C,
        "size": 8,
        "thumb": True,
    }
    assert functions[0x514]["name"] == "java_add_left"
    assert functions[0x514]["size"] == 96
    assert functions[0x514]["thumb"] is True
    # This build carries no $a/$t/$d mapping symbols (NDK r28 lld).
    assert mapping == {}


def test_readelf_unwind_starts_are_even_and_complete() -> None:
    starts = native_probe.parse_readelf_unwind(_fixture("libhello-v7a-readelf-unwind.txt"))
    assert len(starts) == 10
    assert 0x4C8 in starts and 0x5B0 in starts
    assert all(start % 2 == 0 for start in starts)


# One mapped section (.text is shndx 11 at 0x135c) and one empty section
# table, both derived from the recorded readelf output.
SECTIONS = [(11, 0x135C, 0x1C0)]


def test_function_modes_parity_and_mapping_override() -> None:
    functions = {0x50C: {"thumb": True, "name": "a"}, 0x600: {"thumb": False, "name": "b"}}
    modes = native_probe.function_modes(functions, {}, [])
    assert modes == {0x50C: "thumb", 0x600: "arm"}
    # A same-section $a mapping symbol covering 0x1500+0x50c-style start wins
    # over the symbol parity; a $d island names data, never a code mode.
    functions = {0x1364: {"thumb": True, "name": "a"}, 0x1400: {"thumb": False, "name": "b"}}
    labels = {11: {0x135C: "arm", 0x1368: "data", 0x1380: "thumb"}}
    mapped = native_probe.function_modes(functions, labels, SECTIONS)
    assert mapped == {0x1364: "arm", 0x1400: "thumb"}
    labels = {11: {0x135C: "data"}}
    assert native_probe.function_modes(functions, labels, SECTIONS) == {
        0x1364: "data",
        0x1400: "data",
    }


def test_function_modes_unknown_without_symbol() -> None:
    modes = native_probe.function_modes({0x4C8: {"thumb": None, "name": ""}}, {}, [])
    assert modes == {0x4C8: "unknown"}


# ----------------------------------------------------------------- objdump


def test_objdump_thumb_timeline_and_unknown_words() -> None:
    timeline = native_probe.parse_objdump_timeline(_fixture("libhello-v7a-objdump-thumb.txt"))
    addresses = [instr["address"] for instr in timeline]
    assert addresses == sorted(addresses)
    # java_add_left starts here in Thumb: push {r4, r5, r7, lr}-shaped prologue.
    by_address = {instr["address"]: instr for instr in timeline}
    assert by_address[0x514]["mnemonic"] == "push"
    # Literal-pool words decode to <unknown> or .word lines in the recorded
    # output; the timeline drops both as data, exactly as blint's label-driven
    # spans skip them.
    assert all(instr["mnemonic"] not in native_probe.OBJDUMP_DATA_MNEMONICS for instr in timeline)
    assert "<unknown>" not in {instr["mnemonic"] for instr in timeline}
    # The '@ imm = ...' comment is stripped from operands.
    assert by_address[0x54A]["mnemonic"] == "blx"
    assert by_address[0x54A]["operands"] == "0x5f0"


def test_objdump_comment_marker_also_stripped_for_intel_syntax() -> None:
    timeline = native_probe.parse_objdump_timeline(_fixture("libhello-x86-objdump-intel.txt"))
    by_address = {instr["address"]: instr for instr in timeline}
    assert by_address[0x5C5]["mnemonic"] == "call"
    assert by_address[0x5C5]["operands"] == "0x5ca"


def test_direct_call_targets_slice_java_add_left() -> None:
    timeline = native_probe.parse_objdump_timeline(_fixture("libhello-v7a-objdump-thumb.txt"))
    instructions = native_probe.slice_timeline(
        timeline, [instr["address"] for instr in timeline], 0x514, 0x574
    )
    targets = native_probe.direct_call_targets(
        instructions, native_probe.DIRECT_CALL_MNEMONICS["arm32"], mask_thumb_bit=True
    )
    # blx to the __stack_chk_fail and __cxa_finalize PLT thunks.
    assert targets == {0x5F0, 0x600}


def test_direct_call_targets_mask_is_arm32_only() -> None:
    timeline = native_probe.parse_objdump_timeline(_fixture("libhello-x86-objdump-intel.txt"))
    instructions = native_probe.slice_timeline(
        timeline, [instr["address"] for instr in timeline], 0x670, 0x690
    )
    calls = native_probe.DIRECT_CALL_MNEMONICS["default"]
    # The PIC `call $; pop` idiom targets 0x67f — an odd address; masking it
    # would move the edge to 0x67e, so the mask must stay ARM32-only.
    assert native_probe.direct_call_targets(instructions, calls) == {0x67F}
    assert native_probe.direct_call_targets(instructions, calls, mask_thumb_bit=True) == {0x67E}


def test_trim_padding_matches_on_the_mnemonic_token() -> None:
    # Alignment nops carry operands; membership must be decided on the
    # mnemonic alone, exactly like blint's own truncation split.
    assert native_probe.trim_padding(["ret", "nop word ptr cs:[rax + rax]"]) == ["ret"]
    assert native_probe.trim_padding(
        ["lea rdi, [rip + 4]", "jmp 0x850", "nop dword ptr [rax]"]
    ) == [
        "lea rdi, [rip + 4]",
        "jmp 0x850",
    ]
    assert native_probe.trim_padding(["int3", "int3"]) == []
    # The Thumb zero halfword prints as "movs r0, r0" — not a padding
    # mnemonic, and it decodes identically on both sides, so trimming stops
    # there rather than eating into the function body.
    assert native_probe.trim_padding(["nop", "movs r0, r0", "nop"]) == ["nop", "movs r0, r0"]


# --------------------------------------------------------------- blint side


def test_detect_abi_from_tuple() -> None:
    assert (
        native_probe.detect_abi({"llvm_target_tuple": "aarch64-unknown-linux-android"}, None)
        == "arm64-v8a"
    )
    assert (
        native_probe.detect_abi({"llvm_target_tuple": "arm-unknown-linux-android"}, None)
        == "armeabi-v7a"
    )
    assert (
        native_probe.detect_abi({"llvm_target_tuple": "i686-unknown-linux-android"}, None) == "x86"
    )
    assert (
        native_probe.detect_abi({"llvm_target_tuple": "riscv64-unknown-linux-android"}, None)
        == "riscv64"
    )
    assert native_probe.detect_abi({}, "x86_64") == "x86_64"
    with pytest.raises(native_probe.ProbeError):
        native_probe.detect_abi({"llvm_target_tuple": ""}, None)


# --------------------------------------------------------------- comparison


def _blint_func(start: int, lines: list[str], lengths: list[int], targets: set[int]) -> dict:
    return {
        "name": f"sub_{start:x}",
        "start": start,
        "raw_count": len(lines),
        "lengths": lengths,
        "lines": list(lines),
        "mode": "thumb",
        "targets": set(targets),
        "indirect_count": 0,
    }


def _oracle_func(start: int, trimmed: list[str], last: int, targets: set[int]) -> dict:
    return {
        "name": f"fn_{start:x}",
        "start": start,
        "size": 0,
        "thumb": True,
        "mode": "thumb",
        "raw_count": len(trimmed),
        "trimmed": list(trimmed),
        "trimmed_last": last,
        "targets": set(targets),
    }


def test_compare_agreement_and_categories() -> None:
    blint = {
        0x100: _blint_func(0x100, ["push {r4, lr}", "pop {r4, pc}"], [2, 2], {0x200}),
        0x300: _blint_func(0x300, ["bx lr"], [2], set()),
    }
    oracle = {
        0x100: _oracle_func(0x100, ["push {r4, lr}", "pop {r4, pc}"], 0x102, {0x200}),
        0x200: _oracle_func(0x200, ["nop"], 0x200, {0x100}),
    }
    report = native_probe.compare(native_probe.prepare_blint(blint), oracle, "armeabi-v7a")
    summary = report["summary"]
    assert summary["agreement"] is False
    assert summary["matched"] == 1 and summary["extra"] == 1 and summary["missing"] == 1
    assert summary["edge_precision"] == 1.0 and summary["edge_recall"] == 0.5
    assert summary["boundary_recall"] == 0.5
    assert any(diff.startswith("missing") for diff in summary["diffs"])
    assert any(diff.startswith("extra") for diff in summary["diffs"])
    # A missing function contributes its oracle edges to recall as misses
    # (0.5 here) even though it gets no per-function edge diff.
    assert not any("edges" in diff for diff in summary["diffs"])


def test_compare_boundary_then_count_then_mnemonics() -> None:
    # Same count and end, divergent first mnemonic (operand-only differences
    # are not compared: immediate styles differ legitimately between tools).
    blint = {0x100: _blint_func(0x100, ["adds r0, #1", "bx lr"], [2, 2], set())}
    oracle = {0x100: _oracle_func(0x100, ["movs r0, #1", "bx lr"], 0x102, set())}
    report = native_probe.compare(native_probe.prepare_blint(blint), oracle, "arm64-v8a")
    assert report["functions"][0]["verdict"] == "mnemonics"
    # Divergent counts with the same last instruction address.
    blint = {0x100: _blint_func(0x100, ["nop", "bx lr"], [2, 2], set())}
    oracle = {0x100: _oracle_func(0x100, ["nop", "nop", "bx lr"], 0x102, set())}
    report = native_probe.compare(native_probe.prepare_blint(blint), oracle, "arm64-v8a")
    assert report["functions"][0]["verdict"] == "count"
    assert report["summary"]["agreement"] is False


def test_compare_mode_only_gates_on_stated_oracle_mode() -> None:
    blint = {0x100: _blint_func(0x100, ["bx lr"], [2], set())}
    blint[0x100]["mode"] = "arm(triple)"
    known = {0x100: _oracle_func(0x100, ["bx lr"], 0x100, set())}
    unknown = {0x100: _oracle_func(0x100, ["bx lr"], 0x100, set())}
    unknown[0x100]["mode"] = "unknown"
    assert (
        native_probe.compare(native_probe.prepare_blint(blint), known, "armeabi-v7a")["summary"][
            "mode_mismatch"
        ]
        == 1
    )
    assert (
        native_probe.compare(native_probe.prepare_blint(blint), unknown, "armeabi-v7a")["summary"][
            "mode_mismatch"
        ]
        == 0
    )


# -------------------------------------------------------------- end to end


@pytest.mark.skipif(
    not _nyxstone_available() or not _tools_available() or not CORPUS_V7A_UNSTRIPPED.exists(),
    reason="needs nyxstone, NDK llvm tools and the tier-1 corpus fixture",
)
def test_probe_v7a_unstripped_agrees_after_semantics() -> None:
    """The unstripped twin after T3: full agreement - functions, modes,
    boundaries, counts, mnemonics and every direct bl/blx edge."""
    report_json = FIXTURE_DIR / "probe-v7a-report.json"
    code = native_probe.main([str(CORPUS_V7A_UNSTRIPPED), "--json", str(report_json)])
    summary = __import__("json").loads(report_json.read_text())["summary"]
    assert code == 0
    assert summary["agreement"] is True
    assert summary["edge_precision"] == 1.0 and summary["edge_recall"] == 1.0
    report_json.unlink()


@pytest.mark.skipif(
    not _nyxstone_available() or not _tools_available() or not CORPUS_V7A.exists(),
    reason="needs nyxstone, NDK llvm tools and the tier-1 corpus fixture",
)
def test_probe_v7a_stripped_state_recorded_for_t4() -> None:
    """The stripped twin: functions all found, but with no mapping symbols
    and no parity evidence a few PLT-veneer entries decode in a guessed
    mode. Recorded as the before-picture for T4's discovery rung."""
    report_json = FIXTURE_DIR / "probe-v7a-stripped.json"
    code = native_probe.main([str(CORPUS_V7A), "--json", str(report_json)])
    summary = __import__("json").loads(report_json.read_text())["summary"]
    assert code == 1
    assert summary["missing"] == 0 and summary["extra"] == 0
    assert summary["boundary_recall"] == 1.0
    report_json.unlink()


@pytest.mark.skipif(
    not _nyxstone_available() or not _tools_available() or not CORPUS_ARM64.exists(),
    reason="needs nyxstone, NDK llvm tools and the tier-1 corpus fixture",
)
def test_probe_arm64_control_agrees() -> None:
    """The working-ABI control: blint matches the oracle exactly, exit 0."""
    assert native_probe.main([str(CORPUS_ARM64)]) == 0
