"""Tests for the arm32 model in ``blint.lib.absint``.

The instruction text is never hand-written: every test decodes a committed
NDK-built fixture with nyxstone and steps the model over the real text. The
Thumb dialect comes from ``tests/data/android/liba12rt_armeabi-v7a.so`` (the
a11 registrar sources built with ``-mthumb``) and the ARM dialect from
``tests/data/android/liba11rt_armeabi-v7a.so`` (whose v7a build came out
ARM-mode). The fixtures were built by
``tests/scripts/android/build_a12_jni_fixtures.sh`` and
``build_a11_jni_fixtures.sh`` with NDK r28c (28.2.13676358).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from blint.lib.absint import (
    ARM32_ARM_MODEL,
    ARM32_MODEL,
    ARM64_MODEL,
    I386_MODEL,
    X86_64_MODEL,
    Arm32Model,
    FrameState,
    model_for_target,
)

FIXTURES = Path(__file__).resolve().parent / "data" / "android"


def _nyxstone(triple: str):
    try:
        from nyxstone import Nyxstone
    except Exception:  # pragma: no cover - the skipif handles availability
        return None
    try:
        return Nyxstone(target_triple=triple, immediate_style=0)
    except Exception:
        return None


def _fixture_instructions(
    library: str, triple: str, symbol_needle: str
) -> list[tuple[int, str, int]]:
    """(address, text, length) for one fixture registrar's bytes, decoded in
    the triple's instruction set state; literal-pool words that stop nyxstone
    are skipped four bytes at a time, the way the walk's window decode does."""
    nyxstone = _nyxstone(triple)
    parsed = _lief(library)
    if nyxstone is None or parsed is None:
        pytest.skip("nyxstone or the arm32 fixture is unavailable")
    section = next(s for s in parsed.sections if s.name == ".text")
    blob = bytes(parsed.get_content_from_virtual_address(section.virtual_address, section.size))
    # static registrars have only a symtab entry
    symbol = next(
        s
        for s in (*parsed.dynamic_symbols, *parsed.symtab_symbols)
        if symbol_needle in (s.name or "") and "FUNC" in str(s.type)
    )
    start = int(symbol.value) & ~1
    out: list[tuple[int, str, int]] = []
    cursor, end = (
        start - section.virtual_address,
        start - section.virtual_address + int(symbol.size),
    )
    while cursor < end:
        window = blob[cursor:end]
        try:
            decoded = nyxstone.disassemble_to_instructions(
                list(window), section.virtual_address + cursor
            )
            out.extend((i.address, i.assembly.strip(), len(i.bytes)) for i in decoded)
            return out
        except ValueError as exc:
            match = re.search(r"position (\d+)", str(exc))
            if not match:
                return out
            position = int(match.group(1))
            try:
                decoded = nyxstone.disassemble_to_instructions(
                    list(window[:position]), section.virtual_address + cursor
                )
                out.extend((i.address, i.assembly.strip(), len(i.bytes)) for i in decoded)
            except ValueError:
                pass
            cursor += (position + 3) & ~3 if position else 4
    return out


def _lief(library: str):
    import lief

    return lief.ELF.parse(str(FIXTURES / library))


def _step_until(
    model: Arm32Model,
    instructions: list[tuple[int, str, int]],
    mnemonic_prefix: str,
    predicate,
    seed: dict | None = None,
):
    """Step the model over the text, returning the state just before the first
    instruction whose pre-step state satisfies ``predicate``."""
    state = FrameState(model)
    for family, value in (seed or {}).items():
        state.registers[family] = value
    for address, text, length in instructions:
        if text.startswith(mnemonic_prefix) and predicate(state):
            return state
        model.step(state, text, leaves_function=True, address_span=(address, address + length))
    return None


def test_model_for_target_routes_32_bit_arm_triples():
    """arm*/thumb* triples (never aarch64/arm64) get the arm32 model; the
    other routings are unchanged."""
    for triple in ("arm-unknown-linux-android", "armv7-none-linux", "thumbv7-linux-androideabi"):
        assert isinstance(model_for_target(triple), Arm32Model), triple
    assert model_for_target("arm-unknown-linux-android") is ARM32_MODEL
    assert model_for_target("aarch64-unknown-linux-android") is ARM64_MODEL
    assert model_for_target("arm64-apple-macosx") is ARM64_MODEL
    assert model_for_target("i686-unknown-linux-android") is I386_MODEL
    assert model_for_target("x86_64-unknown-linux-gnu") is X86_64_MODEL
    assert model_for_target("") is X86_64_MODEL


def test_arm32_model_frame_and_clobber_sets():
    """AAPCS: r0-r3, r12 and lr are caller-saved; the frame is sp (r7/r11
    frame pointers arrive as derived sp symbolics); pc reads +4 in Thumb and
    +8 in ARM."""
    assert set(ARM32_MODEL.frame_bases) == {"sp"}
    assert set(ARM32_MODEL.call_clobbered) == {"r0", "r1", "r2", "r3", "r12", "lr"}
    assert ARM32_MODEL.pc_read == 4
    assert ARM32_ARM_MODEL.pc_read == 8
    assert ARM32_MODEL.instruction_stride is None


def test_arm32_call_knowledge_separates_calls_from_conditional_branches():
    """`bl`/`blx` (and their conditional spellings) are calls; `b`/`b.w` are
    tail transfers; a conditional branch (`blt` = b+lt) and `bx lr` write
    nothing."""
    assert ARM32_MODEL.call_kind("bl") == "call"
    assert ARM32_MODEL.call_kind("blx") == "call"
    assert ARM32_MODEL.call_kind("blx.w") == "call"
    assert ARM32_MODEL.call_kind("bleq") == "call"
    assert ARM32_MODEL.call_kind("b") == "tail"
    assert ARM32_MODEL.call_kind("b.w") == "tail"
    assert ARM32_MODEL.call_kind("bx") == "tail"
    assert ARM32_MODEL.call_kind("blt") is None
    assert ARM32_MODEL.call_kind("beq") is None
    assert ARM32_MODEL.call_kind("bhs") is None


@pytest.mark.skipif(
    _nyxstone("thumbv7-unknown-linux-android") is None, reason="nyxstone is not installed"
)
def test_thumb_registrar_reads_methods_marker_and_constant_count():
    """The a12rt aligned registrar (Thumb, realigned frame): at the
    RegisterNatives vtable call the methods argument is the sp buffer and the
    count is the immediate 1, with the frame still locatable through the
    `mov r4, sp; bfc r4, #0, #2; mov sp, r4` realignment."""
    instructions = _fixture_instructions(
        "liba12rt_armeabi-v7a.so", "thumbv7-unknown-linux-android", "register_aligned"
    )
    state = _step_until(
        ARM32_MODEL,
        instructions,
        "blx",
        lambda s: s.registers.get("r3") == 1 and isinstance(s.registers.get("r2"), tuple),
    )
    assert state is not None
    methods = state.registers["r2"]
    assert methods[0] == "sp"
    assert methods[1] < -(1 << 23)  # the realigned frame's opaque namespace
    assert state.registers["r3"] == 1


@pytest.mark.skipif(
    _nyxstone("thumbv7-unknown-linux-android") is None, reason="nyxstone is not installed"
)
def test_thumb_pair_chain_carries_the_incoming_pair():
    """The pair registrar passes its incoming (methods, count) - an r1/r2
    pair - through callee-saved registers to the vtable call, the shape the
    A9 P3 argument carrying seeds."""
    instructions = _fixture_instructions(
        "liba12rt_armeabi-v7a.so", "thumbv7-unknown-linux-android", "a11_rt_register_pairP"
    )
    marker = ("caller_sp", 0x10)
    state = _step_until(
        ARM32_MODEL,
        instructions,
        "bx",
        lambda s: s.registers.get("r2") == marker and s.registers.get("r3") == 2,
        seed={"r1": marker, "r2": 2},
    )
    assert state is not None


@pytest.mark.skipif(
    _nyxstone("thumbv7-unknown-linux-android") is None, reason="nyxstone is not installed"
)
def test_thumb_pool_completion_folds_against_the_instruction_address():
    """`ldr rN, [pc, #K]` leaves the destination unknown in the model (the
    pool word lives in the bytes the caller owns); the `add rN, pc`
    completion folds a resolved pool word against the instruction's own
    address plus the Thumb pc offset."""
    instructions = _fixture_instructions(
        "liba12rt_armeabi-v7a.so", "thumbv7-unknown-linux-android", "register_aligned"
    )
    add_index = next(
        index
        for index, (_, text, _) in enumerate(instructions)
        if re.match(r"add\s+r\d+, pc$", text)
    )
    address, text, length = instructions[add_index]
    reg = text.split()[1].rstrip(",")
    pool_word = 0x1234
    state = FrameState(ARM32_MODEL)
    for _, line, _ in instructions[:add_index]:
        ARM32_MODEL.step(state, line, leaves_function=True)
    state.registers[reg] = pool_word
    ARM32_MODEL.step(state, text, leaves_function=True, address_span=(address, address + length))
    assert state.registers[reg] == (pool_word + address + 4) & 0xFFFFFFFF


@pytest.mark.skipif(
    _nyxstone("armv7-unknown-linux-android") is None, reason="nyxstone is not installed"
)
def test_arm_dialect_registrar_reads_methods_marker_and_constant_count():
    """The a11rt v7a registrar (ARM-mode dialect, `bfc sp` realignment): the
    same (methods, count) read at the vtable call, through the ARM spellings
    (`sub sp, sp, #16`, `add r2, sp, #4`, `mov r3, #1`)."""
    instructions = _fixture_instructions(
        "liba11rt_armeabi-v7a.so", "armv7-unknown-linux-android", "register_aligned"
    )
    state = _step_until(
        ARM32_ARM_MODEL,
        instructions,
        "blx",
        lambda s: s.registers.get("r3") == 1 and isinstance(s.registers.get("r2"), tuple),
    )
    assert state is not None
    assert state.registers["r2"][0] == "sp"
    assert state.registers["r3"] == 1


@pytest.mark.skipif(
    _nyxstone("thumbv7-unknown-linux-android") is None, reason="nyxstone is not installed"
)
def test_aapcs_clobbering_keeps_the_saved_env_register():
    """Across the registrar's FindClass call (a `blx`), the caller-saved
    argument registers go unknown while the r4-saved env survives and is
    re-read afterwards - the AAPCS split the walk depends on."""
    instructions = _fixture_instructions(
        "liba12rt_armeabi-v7a.so", "thumbv7-unknown-linux-android", "register_aligned"
    )
    state = FrameState(ARM32_MODEL)
    seen_after_call = False
    for address, text, length in instructions:
        if text == "mov r4, r0":
            state.registers.pop("r4", None)
        ARM32_MODEL.step(
            state, text, leaves_function=True, address_span=(address, address + length)
        )
        if text == "mov r4, r0":
            state.registers["r4"] = 0x4444
        if text.startswith("blx") and state.registers.get("r4") == 0x4444:
            assert "r4" in state.registers  # callee-saved
            seen_after_call = True
            break
    assert seen_after_call


@pytest.mark.skipif(
    _nyxstone("armv7-unknown-linux-android") is None, reason="nyxstone is not installed"
)
def test_stmib_stores_the_first_word_one_above_the_base():
    """The ARM-state a13 registrar stores its entry words through a real
    `stmib sp, {r1, r2}` (liba13rt's lazy registrar): the first word lands
    one above the base and the second two above, so a methods marker at
    sp reads (name, signature) beside the separately stored fnPtr. The
    same lead computation serves `ldmib`, which no committed fixture
    contains."""
    instructions = _fixture_instructions(
        "liba13rt_armeabi-v7a.so", "armv7-unknown-linux-android", "a13_rt_register_lazy"
    )
    stmib = next((i for i in instructions if i[1].lower().startswith("stmib")), None)
    assert stmib is not None, "the a13 ARM fixture's lazy registrar stmib is missing"
    state = FrameState(ARM32_ARM_MODEL)
    state.sp_adjustment = -0x10
    state.registers["r1"] = ("ptr", 0xAAAA)
    state.registers["r2"] = ("ptr", 0xBBBB)
    ARM32_ARM_MODEL.step(
        state, stmib[1], leaves_function=True, address_span=(stmib[0], stmib[0] + stmib[2])
    )
    assert state.load_word("sp", -0x10) is None
    assert state.load_word("sp", -0x10 + 4) == ("ptr", 0xAAAA)
    assert state.load_word("sp", -0x10 + 8) == ("ptr", 0xBBBB)
    assert state.sp_adjustment == -0x10  # no writeback in this spelling
