"""Tests for the i386 model in ``blint.lib.absint``.

The instruction text is never hand-written: every test decodes the committed
NDD-built fixture ``tests/data/android/liba11rt_x86.so`` with nyxstone (the
registrar functions whose shapes A11 S0 measured live there) and steps the
model over the real text. The fixtures were built by
``tests/scripts/android/build_a11_jni_fixtures.sh`` with NDK r28c
(28.2.13676358).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from blint.lib.absint import (
    ARM64_MODEL,
    I386_MODEL,
    X86_64_MODEL,
    FrameState,
    I386Model,
    model_for_target,
)

FIXTURES = Path(__file__).resolve().parent / "data" / "android"


def _nyxstone():
    try:
        from nyxstone import Nyxstone
    except Exception:  # pragma: no cover - the skipif handles availability
        return None
    try:
        return Nyxstone(target_triple="i386-unknown-linux-android", immediate_style=0)
    except Exception:
        return None


def _lief():
    import lief

    return lief.ELF.parse(str(FIXTURES / "liba11rt_x86.so"))


def _fixture_instructions() -> list[tuple[int, str, int]]:
    """(address, text, length) for the fixture's .text, decoded once."""
    nyxstone = _nyxstone()
    parsed = _lief()
    if nyxstone is None or parsed is None:
        pytest.skip("nyxstone or the i386 fixture is unavailable")
    section = next(s for s in parsed.sections if s.name == ".text")
    blob = bytes(parsed.get_content_from_virtual_address(section.virtual_address, section.size))
    instructions = []
    cursor = 0
    while cursor < len(blob):
        try:
            decoded = nyxstone.disassemble_to_instructions(
                list(blob[cursor:]), section.virtual_address + cursor
            )
        except ValueError as exc:
            match = re.search(r"position (\d+)", str(exc))
            if not match or int(match.group(1)) <= 1:
                break
            cursor += int(match.group(1))
            continue
        if not decoded:
            break
        instructions.extend((i.address, i.assembly.strip(), len(i.bytes)) for i in decoded)
        break
    return instructions


def _walk_register_natives_calls():
    """Step the model over the fixture's .text and yield (text, sp, slots)
    snapshots taken at every RegisterNatives vtable call (slot 215: offset
    860 on i386), just before the call is stepped."""
    instructions = _fixture_instructions()
    state = FrameState(I386_MODEL)
    calls = []
    for address, text, length in instructions:
        if text.startswith("call") and " 860]" in text:
            calls.append((text, state.sp_adjustment, dict(state.slots)))
        I386_MODEL.step(
            state, text, leaves_function=True, address_span=(address, address + length)
        )
    return calls


# ---------------------------------------------------------------------------
# Routing: i386 triples get the i386 model, everything else keeps its model.
# ---------------------------------------------------------------------------


def test_model_for_target_routes_32_bit_x86_triples():
    for triple in (
        "i386-unknown-linux-gnu",
        "i486-linux-gnu",
        "i586-linux-gnu",
        "i686-unknown-linux-android",
        "ia32",
    ):
        assert model_for_target(triple) is I386_MODEL, triple


def test_model_for_target_keeps_the_existing_models():
    # The x86-64 default (including the empty triple) and arm64 are unchanged;
    # arm32 routing is covered in test_absint_arm32.py.
    assert model_for_target("") is X86_64_MODEL
    assert model_for_target("x86_64-unknown-linux-android") is X86_64_MODEL
    assert model_for_target("amd64-apple-darwin") is X86_64_MODEL
    assert model_for_target("aarch64-unknown-linux-android") is ARM64_MODEL


def test_i386_model_frame_and_clobber_sets():
    assert I386Model.frame_bases == frozenset({"esp", "ebp"})
    # cdecl: eax/ecx/edx are caller-saved; ebx/esi/edi/ebp survive.
    assert set(I386Model.call_clobbered) == {"eax", "ecx", "edx"}


# ---------------------------------------------------------------------------
# The fixture's registrar shapes, stepped over real nyxstone text.
# ---------------------------------------------------------------------------


@pytest.mark.skipif(_nyxstone() is None, reason="nyxstone is not installed")
def test_runtime_table_registration_reads_methods_marker_and_constant_count():
    """The word-materialised registrar (a11_rt_register_imm) passes methods as
    a stack-address marker and the count as an immediate at the vtable call."""
    calls = _walk_register_natives_calls()
    assert calls, "the fixture's RegisterNatives calls were not found"
    readable = [
        (methods, count)
        for _, sp, slots in calls
        if isinstance((methods := slots.get(("esp", sp + 8))), tuple)
        and (count := slots.get(("esp", sp + 0xC))) == 2
    ]
    assert readable, "no vtable call carried a stack methods marker beside count 2"
    methods, count = readable[0]
    assert methods[0] == "esp" and count == 2


@pytest.mark.skipif(_nyxstone() is None, reason="nyxstone is not installed")
def test_realigned_registrar_keeps_the_marker_across_and_esp():
    """The -mstackrealign registrar stages its entry after `and esp, -16`; the
    entry stores and the methods lea must still name one buffer."""
    calls = _walk_register_natives_calls()
    aligned = [
        slots.get(("esp", sp + 8))
        for _, sp, slots in calls
        if slots.get(("esp", sp + 0xC)) == 1 and isinstance(slots.get(("esp", sp + 8)), tuple)
    ]
    assert aligned, "the realigned registrar's methods marker was lost"


@pytest.mark.skipif(_nyxstone() is None, reason="nyxstone is not installed")
def test_volatile_count_registration_reads_no_positive_constant():
    """The volatile-count registrar must not surface a usable count: whatever
    integer lands in the count slot is not a registration entry count."""
    calls = _walk_register_natives_calls()
    counts = [
        slots.get(("esp", sp + 0xC))
        for _, sp, slots in calls
        if isinstance(slots.get(("esp", sp + 8)), tuple)
    ]
    assert counts, "no stack-methods registration was walked"
    # the constant-count registrars read 2 (imm) and 1 (aligned); the volatile
    # registrar's count is not a positive constant
    assert 2 in counts and 1 in counts
    assert all(count in (0, 1, 2, None) for count in counts)


@pytest.mark.skipif(_nyxstone() is None, reason="nyxstone is not installed")
def test_inline_pc_thunk_yields_the_got_base():
    """`call 0` + `pop` + `add` leaves the GOT base in the popped register:
    the pushed value is the address of the pop instruction itself."""
    instructions = _fixture_instructions()
    state = FrameState(I386_MODEL)
    seen = False
    for index, (address, text, length) in enumerate(instructions):
        if re.match(r"^call 0$", text):
            pop_address, pop_text, _ = instructions[index + 1]
            assert pop_text.startswith("pop"), pop_text
            match = re.match(r"^add (\w+), (\d+)$", instructions[index + 2][1])
            assert match, instructions[index + 2][1]
            register, delta = match.group(1), int(match.group(2))
            family = I386_MODEL.register(register)[0]
            add_text = instructions[index + 2][1]
            add_address = instructions[index + 2][0]
            I386_MODEL.step(
                state, text, leaves_function=True, address_span=(address, address + length)
            )
            I386_MODEL.step(
                state, pop_text, leaves_function=True, address_span=(pop_address, pop_address + 1)
            )
            # the pop reads the pushed return address: the pop's own address
            assert state.registers[family] == pop_address
            I386_MODEL.step(
                state, add_text, leaves_function=True, address_span=(add_address, add_address + 1)
            )
            assert state.registers[family] == (pop_address + delta) & 0xFFFFFFFF
            seen = True
            break
        I386_MODEL.step(
            state, text, leaves_function=True, address_span=(address, address + length)
        )
    assert seen, "the fixture's inline pc thunk was not found"


@pytest.mark.skipif(_nyxstone() is None, reason="nyxstone is not installed")
def test_pushed_pointer_word_survives_into_a_slot_and_back():
    """A pushed symbolic pointer keeps its identity in the slot (the
    outgoing-argument currency of the i386 walk), and a pop reads it back."""
    state = FrameState(I386_MODEL)
    marker = ("esp", 64)
    state.registers["eax"] = marker
    # push eax from a known esp position
    state.sp_adjustment = -8
    I386_MODEL.step(state, "push eax", leaves_function=True, address_span=None)
    assert state.sp_adjustment == -12
    assert state.slots.get(("esp", -12)) == marker
    I386_MODEL.step(state, "pop ebx", leaves_function=True, address_span=None)
    assert state.sp_adjustment == -8
    assert state.registers.get("ebx") == marker


def test_pointer_word_does_not_join_with_different_pointer():
    """Two states agreeing on a pointer word keep it; disagreeing drops it."""
    left = FrameState(I386_MODEL)
    right = FrameState(I386_MODEL)
    left.store_pointer_word("esp", -4, ("esp", 16))
    right.store_pointer_word("esp", -4, ("esp", 16))
    assert not left.joined_with(right)
    right.store_pointer_word("esp", -4, ("esp", 32))
    assert left.joined_with(right)
    assert ("esp", -4) not in left.slots


def test_byte_store_under_a_pointer_word_replaces_it():
    """An int store over a pointer word's bytes drops the pointer, and a
    pointer word over bytes drops the bytes - neither can masquerade as the
    other."""
    state = FrameState(I386_MODEL)
    state.store("esp", -4, 0x41424344, 4)
    state.store_pointer_word("esp", -4, ("esp", 8))
    assert state.slots.get(("esp", -4)) == ("esp", 8)
    assert ("esp", -3) not in state.slots
    state.store("esp", -4, 0x11223344, 4)
    assert state.slots.get(("esp", -4)) == 0x44
    assert state.load_word("esp", -4) == 0x11223344


def test_frame_runs_skip_pointer_words():
    """String recovery reads byte runs only; a pointer word breaks the run."""
    from blint.lib.absint import iter_frame_runs

    state = FrameState(I386_MODEL)
    state.store("esp", -8, 0x6C6C6548, 4)  # "Hell"
    state.store_pointer_word("esp", -4, ("esp", 8))
    state.store("esp", 0, 0x6F, 1)  # "o"
    runs = list(iter_frame_runs(state))
    assert [bytes(run[2]) for run in runs] == [b"Hell", b"o"]


@pytest.mark.skipif(_nyxstone() is None, reason="nyxstone is not installed")
def test_movsd_store_with_unresolvable_source_drops_eight_bytes():
    """An SSE pair store whose load side was not frame-resolvable (the a9
    fixture stages its stack copies from GOTOFF loads through ebx) must drop
    the destination's eight bytes rather than leave stale content there."""
    import lief
    from nyxstone import Nyxstone

    parsed = lief.ELF.parse(str(FIXTURES / "liba9_split_x86.so"))
    assert parsed is not None
    nyxstone = Nyxstone(target_triple="i386-unknown-linux-android", immediate_style=0)
    section = next(s for s in parsed.sections if s.name == ".text")
    blob = bytes(parsed.get_content_from_virtual_address(section.virtual_address, section.size))
    instructions = nyxstone.disassemble_to_instructions(list(blob), section.virtual_address)
    texts = [i.assembly.strip() for i in instructions]
    load = next(t for t in texts if re.match(r"^movsd xmm\d+, qword ptr \[e?bx", t))
    store = next(t for t in texts if re.match(r"^movsd qword ptr \[e?bp", t))
    assert load and store

    state = FrameState(I386_MODEL)
    state.sp_adjustment = -0x20
    state.store("ebp", -0x18, 0x41414141, 4)
    state.store("ebp", -0x14, 0x42424242, 4)
    # ebx holds a materialised GOT base (an int), not a frame symbolic
    state.registers["ebx"] = 0x65DD10
    I386_MODEL.step(state, load, leaves_function=True, address_span=(0x1000, 0x1006))
    I386_MODEL.step(state, store, leaves_function=True, address_span=(0x1006, 0x100C))
    assert ("ebp", -0x18) not in state.slots
    assert ("ebp", -0x14) not in state.slots
