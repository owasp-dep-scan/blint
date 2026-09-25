"""ARM32 disassembly capability tests (A4a T2).

Every input is a real NDK r28 build committed under tests/data/android/
(build commands in tests/data/android/a4a-fixtures-manifest.json). The pure
span/mode helpers run everywhere; the decode-level tests need nyxstone.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path

import lief
import pytest

from blint.lib.binary import parse
from blint.lib.disassembler import (
    _arm32_code_spans,
    _arm32_data_pointer_modes,
    _arm32_function_mode,
    _arm32_mapping_symbol_modes,
    _arm32_mode_at,
    _arm32_mode_triples,
    _arm32_section_for_address,
    _arm32_skipped_regions,
    _disassemble_arm32_span,
    _is_arm32_target,
)

R2 = Path(__file__).parent / "data" / "android" / "liba4a_r2.so"


def _nyxstone_available() -> bool:
    try:
        from blint.lib.disassembler import NYXSTONE_AVAILABLE

        return NYXSTONE_AVAILABLE
    except ImportError:
        return False


def test_is_arm32_target_distinguishes_32bit_from_aarch64() -> None:
    assert _is_arm32_target("arm-unknown-linux-android")
    assert _is_arm32_target("armv7-none-linux-androideabi")
    assert _is_arm32_target("thumbv7-linux-androideabi")
    assert not _is_arm32_target("aarch64-unknown-linux-android")
    assert not _is_arm32_target("arm64-apple-macosx")
    assert not _is_arm32_target("x86_64-unknown-linux-gnu")
    assert not _is_arm32_target("")


def test_mode_triples_upgrade_arch_and_keep_the_rest() -> None:
    assert _arm32_mode_triples("arm-unknown-linux-android") == (
        "armv7-unknown-linux-android",
        "thumbv7-unknown-linux-android",
    )
    assert _arm32_mode_triples("arm") == ("armv7", "thumbv7")


def test_mapping_symbol_table_is_section_local() -> None:
    binary = lief.parse(str(R2))
    table = _arm32_mapping_symbol_modes(binary)
    assert table, "the R2 fixture carries $a/$t/$d labels"
    text_index = _arm32_section_for_address(binary, 0x1374)
    plt_index = _arm32_section_for_address(binary, 0x20B0)
    assert text_index != plt_index
    assert any(addr <= 0x1374 for addr, _mode in table[text_index])
    # The $a/$t/$d set is complete in the fixture's .text.
    assert {mode for _addr, mode in table[text_index]} >= {"arm", "thumb", "data"}


def test_function_mode_sources() -> None:
    # Mapping symbol wins over parity; parity wins when no label; call and
    # data-pointer evidence follow; nothing at all yields (None, None) for
    # the caller's arbiter. The second element names the deciding source.
    labels = [(0x100, "arm"), (0x104, "data"), (0x108, "thumb")]
    assert _arm32_function_mode(0x102, labels, has_symbol=True) == ("arm", "mapping_symbol")
    assert _arm32_function_mode(0x105, labels, has_symbol=True) == ("data", "mapping_symbol")
    assert _arm32_function_mode(0x10A, labels, has_symbol=True) == ("thumb", "mapping_symbol")
    assert _arm32_function_mode(0x10C, [], has_symbol=True) == ("arm", "symbol_parity")
    assert _arm32_function_mode(0x10D, [], has_symbol=True) == ("thumb", "symbol_parity")
    assert _arm32_function_mode(0x200, [], has_symbol=False) == (None, None)
    # A symbol-less start with call evidence: bl states the caller's mode,
    # and evidence is consulted only when parity could not decide.
    assert _arm32_function_mode(0x200, [], has_symbol=False, call_modes={0x200: "arm"}) == (
        "arm",
        "call",
    )
    assert _arm32_function_mode(0x10C, [], has_symbol=True, call_modes={0x10C: "thumb"}) == (
        "arm",
        "symbol_parity",
    )
    assert _arm32_function_mode(0x204, [], has_symbol=False, pointer_modes={0x204: "thumb"}) == (
        "thumb",
        "data_pointer",
    )
    # Call evidence outranks pointer evidence (decoded code over data words).
    assert _arm32_function_mode(
        0x208, [], has_symbol=False, call_modes={0x208: "arm"}, pointer_modes={0x208: "thumb"}
    ) == ("arm", "call")


def test_code_spans_follow_labels_and_cover_the_start() -> None:
    labels = [(0x100, "arm"), (0x110, "data"), (0x120, "thumb")]
    # Extent beginning inside the $a region: the covering label claims the
    # head, the $d island is never a span, and the later $t region follows.
    assert _arm32_code_spans(0x104, 0x28, labels) == [(0x104, 0xC), (0x120, 0xC)]
    # An extent entirely inside one labeled region is one span.
    assert _arm32_code_spans(0x122, 0x4, labels) == [(0x122, 0x4)]
    # No labels at all: the whole extent, single span (stripped binaries).
    assert _arm32_code_spans(0x100, 0x10, []) == [(0x100, 0x10)]
    # A start inside a $d region: only later code labels become spans.
    assert _arm32_code_spans(0x112, 0x14, labels) == [(0x120, 0x6)]


def test_skipped_regions_are_the_complement_of_code_spans() -> None:
    labels = [(0x100, "arm"), (0x110, "data"), (0x120, "thumb")]
    spans = _arm32_code_spans(0x104, 0x28, labels)
    assert _arm32_skipped_regions(0x104, 0x28, spans) == [(0x110, 0x10)]
    assert _arm32_skipped_regions(0x100, 0x10, [(0x100, 0x10)]) == []


@pytest.mark.skipif(not _nyxstone_available(), reason="nyxstone not installed")
def test_span_decoder_resumes_past_undecodable_words() -> None:
    """Real bytes: atexit's extent in the -marm build ends with a literal
    pool whose first word (0xffffffe0) no LLVM 18 ARM decoder accepts; the
    span decoder must still recover the instructions behind it."""
    from nyxstone import Nyxstone

    r1_arm = R2.parent / "liba4a_r1_arm.so"
    binary = lief.parse(str(r1_arm))
    arm_instance = Nyxstone(target_triple="armv7-unknown-linux-android")
    atexit_bytes = list(binary.get_content_from_virtual_address(0x1380, 32))
    assert bytes(atexit_bytes[24:28]) == b"\xe0\xff\xff\xff"  # the pool word that raises
    instructions = _disassemble_arm32_span(arm_instance, atexit_bytes, 0x1380)
    addresses = [instr.address for instr in instructions]
    # The six code instructions before the pool all decode...
    assert addresses[:6] == [0x1380, 0x1384, 0x1388, 0x138C, 0x1390, 0x1394]
    # ...and decoding resumed after the word nyxstone refused.
    assert addresses[-1] >= 0x1398


@pytest.mark.skipif(not _nyxstone_available(), reason="nyxstone not installed")
def test_span_decoder_is_not_capped_by_the_number_of_pools() -> None:
    """The skip budget bounds consecutive undecodable words, not pools per
    function: ten back-to-back copies of atexit's real extent (ten pools)
    must decode through to the last copy."""
    from nyxstone import Nyxstone

    binary = lief.parse(str(R2.parent / "liba4a_r1_arm.so"))
    arm_instance = Nyxstone(target_triple="armv7-unknown-linux-android")
    extent = list(binary.get_content_from_virtual_address(0x1380, 32))
    addresses = {
        instr.address for instr in _disassemble_arm32_span(arm_instance, extent * 10, 0x1380)
    }
    assert 0x1380 + 9 * 32 in addresses


@pytest.mark.skipif(not _nyxstone_available(), reason="nyxstone not installed")
def test_parse_records_mode_and_data_spans() -> None:
    metadata = parse(str(R2), disassemble=True)
    functions = metadata["disassembled_functions"]
    by_name = {entry.get("name"): entry for key, entry in functions.items() if entry.get("name")}
    assert by_name["thumb_leaf"]["instruction_mode"] == "thumb"
    assert by_name["arm_leaf"]["instruction_mode"] == "arm"
    assert by_name["arm_state_step"]["instruction_mode"] == "arm"
    assert by_name["thumb_dispatcher"]["instruction_mode"] == "thumb"
    # The tbb byte table inside thumb_table_jump is a skipped data span.
    spans = by_name["thumb_table_jump"]["data_spans"]
    assert spans and spans[0] == {"address": "0x1480", "size": 16}
    # ARM32 functions without islands omit data_spans entirely.
    assert "data_spans" not in by_name["thumb_leaf"]
    assert "data_spans" not in by_name["arm_leaf"]
    # Other architectures never carry either field (output stays
    # byte-compatible outside ARM32).
    arm64 = parse(str(R2.parent / "liba4a_r1_arm64-v8a.so"), disassemble=True)
    assert arm64["llvm_target_tuple"] == "aarch64-unknown-linux-android"
    for entry in arm64["disassembled_functions"].values():
        assert "instruction_mode" not in entry and "data_spans" not in entry


# ------------------------------------------------------------ T3 semantics


def test_arm32_immediate_styles() -> None:
    from blint.lib.disassembler import _arm32_parse_immediate

    assert _arm32_parse_immediate("#50") == 50
    assert _arm32_parse_immediate("#0x32") == 50
    assert _arm32_parse_immediate("#32h") == 50
    assert _arm32_parse_immediate("#-12") == -12
    assert _arm32_parse_immediate("#-0xc") == -12
    assert _arm32_parse_immediate("#-0ch") == -12
    assert _arm32_parse_immediate("") is None
    assert _arm32_parse_immediate("#r3") is None


def test_arm32_pc_bases() -> None:
    from blint.lib.disassembler import _arm32_pc_base

    assert _arm32_pc_base(0x1000, "thumb") == 0x1004
    assert _arm32_pc_base(0x1000, "arm") == 0x1008
    # Thumb blx interworking: relative to Align(PC, 4).
    assert _arm32_pc_base(0x13DA, "thumb", "blx") == 0x13DC
    assert _arm32_pc_base(0x13D8, "thumb", "blx") == 0x13DC
    assert _arm32_pc_base(0x1000, "thumb", "bl") == 0x1004


def test_arm32_return_and_dispatch_classification() -> None:
    from blint.lib.disassembler import _is_arm32_return, _is_arm32_table_dispatch

    assert _is_arm32_return("bx", "lr")
    assert _is_arm32_return("bxeq", "lr")
    assert not _is_arm32_return("bx", "r3")
    assert _is_arm32_return("pop", "{r4, r5, r6, r7, pc}")
    assert not _is_arm32_return("pop", "{r4, r5}")
    assert _is_arm32_return("ldr", "pc, [sp], #4")
    assert not _is_arm32_return("ldr", "pc, [pc, r1, lsl #2]")
    assert _is_arm32_table_dispatch("tbb", "[pc, r1]")
    assert _is_arm32_table_dispatch("tbh", "[pc, r1, lsl #1]")
    assert _is_arm32_table_dispatch("ldr", "pc, [pc, r2, lsl #2]")
    assert not _is_arm32_table_dispatch("ldr", "pc, [sp], #4")
    assert not _is_arm32_table_dispatch("bl", "#50")


def test_function_end_trims_at_arm32_return() -> None:
    """A size-less window keeps trailing junk without the ARM32 return
    forms; with them the first return followed by padding ends the
    function (the R4-dominant boundary-diff class before T3)."""

    class FakeInstr:
        def __init__(self, text):
            self.assembly = text

    from blint.lib.disassembler import _find_function_end_index

    body = [
        FakeInstr("push {r4, lr}"),
        FakeInstr("adds r0, #3"),
        FakeInstr("pop {r4, pc}"),
        FakeInstr("nop"),
        FakeInstr("movs r0, r0"),
    ]
    # Without arch knowledge nothing terminates (the pre-T3 behavior).
    assert _find_function_end_index(body, has_exact_size=False) == len(body) - 1
    assert (
        _find_function_end_index(
            body, has_exact_size=False, arch_target="arm-unknown-linux-android"
        )
        == 2
    )
    # bx lr ends a window the same way.
    bx_body = [FakeInstr("b #8"), FakeInstr("bx lr"), FakeInstr("nop")]
    assert _find_function_end_index(bx_body, has_exact_size=False, arch_target="thumbv7") == 1


@pytest.mark.skipif(not _nyxstone_available(), reason="nyxstone not installed")
def test_r2_direct_edges_match_the_source_call_list() -> None:
    """The R2 fixture's resolved direct-call targets equal the call list in
    its own source header (a4a_sources/r2_interwork.c), address by address."""
    metadata = parse(str(R2), disassemble=True)
    functions = metadata["disassembled_functions"]
    by_name = {e.get("name"): e for e in functions.values() if e.get("name")}
    symtab = {f["name"]: int(f["address"], 16) & ~1 for f in metadata.get("functions", [])}

    def direct_targets(name):
        return {
            int(t["target_address"], 16)
            for t in by_name[name].get("direct_call_targets", [])
            if t.get("kind") == "direct"
        }

    # a4a_r2_run -> thumb_dispatcher, arm_state_step, thumb_table_jump,
    # wide_table_jump, pool_reader (source call-list oracle).
    assert direct_targets("a4a_r2_run") == {
        symtab["thumb_dispatcher"],
        symtab["arm_state_step"],
        symtab["thumb_table_jump"],
        symtab["wide_table_jump"],
        symtab["pool_reader"],
    }
    # thumb_dispatcher -> arm_leaf, thumb_leaf, arm_state_step.
    assert direct_targets("thumb_dispatcher") == {
        symtab["arm_leaf"],
        symtab["thumb_leaf"],
        symtab["arm_state_step"],
    }
    # arm_state_step -> arm_leaf, thumb_leaf (ARM-state blx interworking).
    assert direct_targets("arm_state_step") == {
        symtab["arm_leaf"],
        symtab["thumb_leaf"],
    }
    # pool_reader -> arm_state_step (arm_absolute was inlined at -O2, so
    # it has no symbol and no edge).
    assert direct_targets("pool_reader") == {symtab["arm_state_step"]}
    # The tbb dispatch does not create call edges: thumb_table_jump's direct
    # targets are exactly the sixteen hop functions.
    hops = {symtab[f"hop{i}"] for i in range(16) if f"hop{i}" in symtab}
    assert hops and direct_targets("thumb_table_jump") == hops


@pytest.mark.skipif(not _nyxstone_available(), reason="nyxstone not installed")
def test_r1_arm_tail_call_to_plt_is_named() -> None:
    """atexit ends with a branch to the __register_atfork PLT thunk: a tail
    call, resolved and named from the GOT relocation."""
    r1_arm = R2.parent / "liba4a_r1_arm.so"
    metadata = parse(str(r1_arm), disassemble=True)
    by_name = {
        e.get("name"): e for e in metadata["disassembled_functions"].values() if e.get("name")
    }
    atexit = by_name["atexit"]
    tailcalls = [t for t in atexit.get("direct_call_targets", []) if t.get("kind") == "tailcall"]
    # One tail call, to the __register_atfork PLT thunk's exact address
    # (llvm-objdump names the same target `0x15d0 <__register_atfork+...>`;
    # the symbol itself is a relocation, so the name stays empty here and
    # the callgraph carries the edge as external).
    assert len(tailcalls) == 1
    assert tailcalls[0]["target_address"] == "0x15d0"


@pytest.mark.skipif(not _nyxstone_available(), reason="nyxstone not installed")
def test_literal_materialisation_tracks_got_slot() -> None:
    """The stringFromJNI shape from the real build (corpus fixture):
    ``ldr r4, [pc, #24]; add r4, pc`` materialises the GOT slot address the
    literal completes, and the JNIEnv call through it yields an unnamed
    indirect hint - the vtable level is the JNI wave's model, not guessing."""
    import os

    so = Path(
        os.path.expanduser(
            "~/sandbox/android-corpus/tier1-ndk/r28/armeabi-v7a/unstripped/libhello.so"
        )
    )
    if not so.exists():
        pytest.skip("tier-1 corpus fixture not present")
    from nyxstone import Nyxstone

    from blint.lib.disassembler import (
        _arm32_extract_literals,
        _arm32_literal_address,
        _disassemble_arm32_span,
        _parse_instruction_text,
        _resolve_direct_calls,
    )

    metadata = parse(str(so), disassemble=True)
    by_name = {
        e.get("name"): e for e in metadata["disassembled_functions"].values() if e.get("name")
    }
    fn = by_name["Java_com_example_blint_fixtures_Hello_stringFromJNI"]
    lines = fn["assembly"].splitlines()
    # The literal operand text, verbatim from the real decode: the Thumb PC
    # is addr+4 rounded to 4, so the word at 0x594 (the function's own
    # literal island, a $d span in this build).
    loader = next(i for i, l in enumerate(lines) if l.startswith("ldr r4, [pc"))
    loader_addr = int(fn["address"], 16) + sum(fn["instruction_lengths"][:loader])
    parsed = _parse_instruction_text(lines[loader])
    literal_addr = _arm32_literal_address(_FakeInstr(loader_addr), parsed.operands[1], "thumb")
    assert literal_addr == 0x594
    # End-to-end: the same instruction list re-run through the resolver with
    # the binary's own name map produces the JNIEnv hint, unnamed.
    binary = lief.parse(str(so))
    thumb = Nyxstone(target_triple="thumbv7-unknown-linux-android")
    start = int(fn["address"], 16)
    raw = list(binary.get_content_from_virtual_address(start, 40))
    instrs = _disassemble_arm32_span(thumb, raw, start)
    from blint.lib.disassembler import _build_addr_to_name_map

    name_map = _build_addr_to_name_map(metadata, binary)
    ctx = {
        "modes": ["thumb"] * len(instrs),
        "default_mode": "thumb",
        "literals": _arm32_extract_literals(
            instrs,
            [_parse_instruction_text(i.assembly) for i in instrs],
            ["thumb"] * len(instrs),
            "thumb",
            binary,
            0,
        ),
    }
    _, targets = _resolve_direct_calls(instrs, name_map, "arm-unknown-linux-android", None, ctx)
    hints = [t for t in targets if t.get("kind") == "indirect_hint"]
    assert any(t.get("raw_operand") == "r2" for t in hints)
    # The JNIEnv vtable level resolves no name - stated, not guessed.
    assert all(not (t.get("target_name") or "") for t in hints)
    # And no callee anywhere is named after a mapping symbol.
    for entry in metadata["disassembled_functions"].values():
        for target in entry.get("direct_call_targets", []):
            assert not (target.get("target_name") or "").startswith("$")


class _FakeInstr:
    def __init__(self, address):
        self.address = address
        self.assembly = ""
        self.bytes = b""


# -------------------------------------------------------------- A4b D1 arbiter


def test_arm32_stream_terminates_classifier() -> None:
    """The arbiter's terminator forms on real instruction spellings: the
    return forms, the PLT slot's indirect tail (``ldr pc, [lr, #…]!``),
    ``bx rN`` tail branches, tail ``b``/``blx`` out of the span, and the
    non-terminators a wrong-mode decode ends in."""
    from blint.lib.disassembler import _arm32_stream_terminates

    def stream(*lines):
        return [_FakeTextInstr(0x1000 + 4 * i, text) for i, text in enumerate(lines)]

    # Trailing filler (ARM andeq pool word, Thumb zero halfword, nop) is
    # skipped before the check.
    assert _arm32_stream_terminates(
        stream("ldr r0, [pc, #4]", "bx lr", "andeq r1, r0, r0, asr sp"), 0x1000, 0x1040, "arm"
    )
    assert _arm32_stream_terminates(
        stream("adds r0, #3", "pop {r4, pc}", "movs r0, r0", "nop"), 0x1000, 0x1040, "thumb"
    )
    # The PLT slot: ldr pc through a non-sp, non-pc base is a tail branch.
    assert _arm32_stream_terminates(
        stream("add lr, pc, #0", "ldr pc, [lr, #400]!"), 0x1000, 0x1040, "arm"
    )
    assert _arm32_stream_terminates(stream("bx r3"), 0x1000, 0x1040, "thumb")
    # A tail b/blx whose target leaves the span.
    assert _arm32_stream_terminates(stream("ldr r0, [pc, #12]", "b #3000"), 0x1000, 0x1040, "arm")
    assert not _arm32_stream_terminates(
        stream("adds r0, #1", "b #-6"), 0x1000, 0x1040, "arm"
    )  # in-span branch: a loop, not an end
    # Non-terminators: the shapes a wrong-mode decode ends in.
    assert not _arm32_stream_terminates(
        stream("vrhadd.u16 d14, d14, d31"), 0x1000, 0x1040, "thumb"
    )
    assert not _arm32_stream_terminates(
        stream("and.w pc, r0, r0, asr #31"), 0x1000, 0x1040, "thumb"
    )
    assert not _arm32_stream_terminates(
        stream("ldr pc, [pc, r2, lsl #2]"), 0x1000, 0x1040, "arm"
    )  # dispatch, not a tail
    assert not _arm32_stream_terminates([], 0x1000, 0x1040, "arm")


class _FakeTextInstr:
    def __init__(self, address, text, size=4):
        self.address = address
        self.assembly = text
        self.bytes = b"\x00" * size


def test_arm32_arbiter_prefers_terminator_over_landing_on_end() -> None:
    """Two candidate streams for the same 4-byte span: the Thumb mis-decode
    (`vrhadd.u16`, lands exactly on the span end) against the ARM decode
    (`bx lr`, return) - the +2 terminator score must outrank +1 exact
    landing, the pre-D1 rule that defaulted these CRT helpers to Thumb."""
    from blint.lib.disassembler import _arm32_arbiter_pick

    thumb = [_FakeTextInstr(0x1384, "vrhadd.u16 d14, d14, d31")]
    arm = [_FakeTextInstr(0x1384, "bx lr")]
    picked = _arm32_arbiter_pick(
        [("thumb", thumb), ("arm", arm)], 0x1384, 4, [(0x1000, 0x2000)], set()
    )
    assert picked == ("arm", arm)


def test_arm32_arbiter_counts_implausible_branch_targets() -> None:
    """The branch-plausibility vote: a stream whose immediate branches name
    known starts scores above one whose branches leave the executable
    ranges, even when both land short of the span end (the PLT-entry shape
    from the R2 grid: ARM `ldr pc` tail with d4 padding vs a Thumb spray of
    nonsense targets)."""
    from blint.lib.disassembler import _arm32_arbiter_pick

    arm = [
        _FakeTextInstr(0x880, "str lr, [sp, #-4]!"),
        _FakeTextInstr(0x884, "add lr, pc, #0"),
        _FakeTextInstr(0x888, "ldr pc, [lr, #400]!"),
        _FakeTextInstr(0x88C, "ldrble sp, [r4], #1236"),
    ]
    thumb = [
        _FakeTextInstr(0x880, "b #204", size=2),  # 0x2e0: below .text
        _FakeTextInstr(0x882, "b #1160", size=2),  # 0xd08: past .plt
        _FakeTextInstr(0x884, "and.w r2, r1, lr"),
        _FakeTextInstr(0x888, "blx #300", size=4),  # far outside
        _FakeTextInstr(0x88C, "bmi #56", size=2),
        _FakeTextInstr(0x88E, "bmi #58", size=2),
    ]
    exec_ranges = [(0x880, 0x8B0)]
    picked = _arm32_arbiter_pick(
        [("thumb", thumb), ("arm", arm)], 0x880, 0x20, exec_ranges, {0x8A0}
    )
    assert picked[0] == "arm"


# ------------------------------------------------------------ T4 discovery


def test_prel31_decode() -> None:
    from blint.lib.funcdisc.unwind import _decode_prel31

    assert _decode_prel31(0x00000010) == 16
    # A 31-bit field signed at bit 30 with bit 31 reserved-clear (real
    # .ARM.exidx words): 0x3FFFFFFF is the maximum positive, 0x40000000 is
    # the most negative, 0x7FFFFFC0 is -64.
    assert _decode_prel31(0x3FFFFFFF) == 0x3FFFFFFF
    assert _decode_prel31(0x40000000) == -(1 << 30)
    assert _decode_prel31(0x7FFFFFC0) == -64


def test_arm_exidx_discovery_on_stripped_fixture() -> None:
    """The committed stripped R1 twin: .ARM.exidx rows become
    discovered_functions with source arm_exidx (no symtab exists to claim
    them through any other bucket)."""
    stripped = R2.parent / "liba4a_r1_thumb_stripped.so"
    metadata = parse(str(stripped))
    discovered = metadata.get("discovered_functions") or []
    exidx = [entry for entry in discovered if entry.get("source") == "arm_exidx"]
    assert len(exidx) == 7
    assert {entry["address"] for entry in exidx} >= {
        "0x135c",
        "0x136c",
        "0x1370",
        "0x1374",
        "0x1380",
        "0x13a0",
    }
    assert metadata["function_discovery"]["sources"]["arm_exidx"] == 7


def test_arm_exidx_matches_readelf_unwind() -> None:
    """Same-run oracle: the parser's starts equal llvm-readelf --unwind's
    FunctionAddress set over the same file."""
    stripped = R2.parent / "liba4a_r1_thumb_stripped.so"
    metadata = parse(str(stripped))
    starts = {
        int(entry["address"], 16)
        for entry in (metadata.get("discovered_functions") or [])
        if entry.get("source") == "arm_exidx"
    }
    import subprocess

    readelf = shutil.which("llvm-readelf")
    if readelf is None:
        bin_dir = Path.home() / "Android" / "sdk" / "ndk"
        candidates = sorted(bin_dir.glob("*/toolchains/llvm/prebuilt/*/bin/llvm-readelf"))
        if not candidates:
            pytest.skip("llvm-readelf not available for the same-run oracle")
        readelf = str(candidates[-1])
    out = subprocess.run(
        [readelf, "--unwind", str(stripped)], capture_output=True, text=True, check=False
    ).stdout
    expected = {
        int(token, 16) & ~1 for token in re.findall(r"FunctionAddress:\s*(0x[0-9a-fA-F]+)", out)
    }
    assert starts == expected


def test_no_eh_frame_regression_for_other_abis() -> None:
    """arm64's .eh_frame path is untouched: the same discovery runs and
    reports eh_frame, never arm_exidx."""
    metadata = parse(str(R2.parent / "liba4a_r1_arm64-v8a.so"))
    sources = (metadata.get("function_discovery") or {}).get("sources") or {}
    assert "arm_exidx" not in sources


# -------------------------------------------------------------- A4b D1 modes

R2_STRIPPED = R2.parent / "liba4a_r2_stripped.so"


def test_data_pointer_modes_read_fini_array_words() -> None:
    """The stripped R2 twin's .fini_array holds 0x1374 and 0x1388 in
    R_ARM_RELATIVE slots (llvm-readelf -x .fini_array in the same run shows
    `88130000 74130000`), both with the Thumb bit clear: ARM evidence for
    exactly those two starts, and nothing for any other candidate."""
    binary = lief.parse(str(R2_STRIPPED))
    modes = _arm32_data_pointer_modes(binary, {0x1374, 0x1388, 0x13C8, 0x1434})
    assert modes == {0x1374: "arm", 0x1388: "arm"}


def test_data_pointer_modes_ignore_non_functions() -> None:
    """A word that names no candidate start contributes nothing - the
    .data.rel.ro self-pointer (0x3100 -> 0x3100) cannot invent evidence."""
    binary = lief.parse(str(R2_STRIPPED))
    assert _arm32_data_pointer_modes(binary, {0x1398}) == {}


@pytest.mark.skipif(not _nyxstone_available(), reason="nyxstone not installed")
def test_arbiter_picks_arm_for_atexit_pool_bytes() -> None:
    """Real bytes from the stripped twin: atexit's extent [0x1398, 0x13b8)
    decodes to a coherent ARM stream (ends `b` out to the PLT, then pool)
    and a garbage Thumb stream; the arbiter must score ARM higher even with
    no known starts to vouch for targets."""
    from nyxstone import Nyxstone

    from blint.lib.disassembler import _arm32_arbiter_pick, executable_ranges

    binary = lief.parse(str(R2_STRIPPED))
    raw = list(binary.get_content_from_virtual_address(0x1398, 0x13B8 - 0x1398))
    arm = Nyxstone(target_triple="armv7-unknown-linux-android")
    thumb = Nyxstone(target_triple="thumbv7-unknown-linux-android")
    picked = _arm32_arbiter_pick(
        [
            ("thumb", _disassemble_arm32_span(thumb, raw, 0x1398)),
            ("arm", _disassemble_arm32_span(arm, raw, 0x1398)),
        ],
        0x1398,
        len(raw),
        executable_ranges(binary),
        set(),
    )
    assert picked[0] == "arm"
    # The same call with the candidates swapped keeps ARM: order cannot
    # change the decision, only break ties.
    swapped = _arm32_arbiter_pick(
        [
            ("arm", _disassemble_arm32_span(arm, raw, 0x1398)),
            ("thumb", _disassemble_arm32_span(thumb, raw, 0x1398)),
        ],
        0x1398,
        len(raw),
        executable_ranges(binary),
        set(),
    )
    assert swapped[0] == "arm"


@pytest.mark.skipif(not _nyxstone_available(), reason="nyxstone not installed")
def test_stripped_twin_modes_match_unstripped_mapping_symbols() -> None:
    """D1's R1 gate: every function the stripped twin decodes carries the
    mode the unstripped twin's $a/$t mapping symbols state for its address
    (the twin's symbol table is the mode oracle; the bytes are identical)."""
    metadata = parse(str(R2_STRIPPED), disassemble=True)
    twin = lief.parse(str(R2))
    text_index = _arm32_section_for_address(twin, 0x1374)
    labels = _arm32_mapping_symbol_modes(twin)[text_index]
    disassembled = metadata["disassembled_functions"]
    assert len(disassembled) >= 44
    for entry in disassembled.values():
        addr = int(entry["address"], 16) & ~1
        expected = _arm32_mode_at(labels, addr)
        assert entry["instruction_mode"] == expected, hex(addr)


@pytest.mark.skipif(not _nyxstone_available(), reason="nyxstone not installed")
def test_instruction_mode_source_names_the_deciding_evidence() -> None:
    """The stripped twin's mode decisions record their source: the surviving
    dynsym export decides by parity, the .fini_array rows by parity too
    (LIEF surfaces them as synthetic ``__dt_fini_array`` functions whose
    even address states ARM - a Thumb entry would arrive odd), the blx
    targets by call evidence, the rest by the decode arbiter."""
    metadata = parse(str(R2_STRIPPED), disassemble=True)
    by_name = {e.get("name"): e for e in metadata["disassembled_functions"].values()}
    assert by_name["a4a_r2_run"]["instruction_mode_source"] == "symbol_parity"
    by_addr = {int(e["address"], 16) & ~1: e for e in metadata["disassembled_functions"].values()}
    assert by_addr[0x1374]["instruction_mode"] == "arm"
    assert by_addr[0x1388]["instruction_mode"] == "arm"
    # arm_state_step is reached by blx from the Thumb a4a_r2_run (ARM at the
    # target) and pool_reader is reached the same way.
    assert by_addr[0x1434]["instruction_mode_source"] == "call"
    assert by_addr[0x1FB0]["instruction_mode_source"] == "call"
    # atexit has no caller and no pointer: the arbiter decided.
    assert by_addr[0x1398]["instruction_mode_source"] == "arbiter"
    # Every entry states a source; other architectures carry none of this.
    for entry in metadata["disassembled_functions"].values():
        assert entry["instruction_mode_source"] in {
            "mapping_symbol",
            "symbol_parity",
            "call",
            "data_pointer",
            "arbiter",
        }
    arm64 = parse(str(R2.parent / "liba4a_r1_arm64-v8a.so"), disassemble=True)
    for entry in arm64["disassembled_functions"].values():
        assert "instruction_mode_source" not in entry
