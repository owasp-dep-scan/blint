"""The FindClass confirmer for ``ambiguous_dynamic`` entries (A8 N3).

An ``ambiguous_dynamic`` entry is a dex ``native`` declaration whose
(name, signature) pair is claimed by more than one recovered
``RegisterNatives`` table entry or more than one declaring dex class, so
the join cannot pick an implementation. The class that disambiguates it
is the string passed to ``FindClass`` beside the ``RegisterNatives``
call: fennec's generated JNI and the a8 fixture's ``JNI_OnLoad`` do all
of it in one function; fbjni's ``X::registerNatives()`` materializes the
table and calls ``HybridClass<T>::registerHybrid``, which materializes
the class name, calls ``findClassLocal`` and then the JNIEnv
``RegisterNatives`` vtable slot.

This module answers, per library, which address ranges of the recovered
tables are registered for which class:

- Same-function registrations: the absint model (``blint.lib.absint``,
  stepped over nyxstone instruction text the way the call-site recovery
  does) holds the argument registers at each RegisterNatives vtable
  call, so the methods pointer and the count are read from the state -
  ``[methods, methods + count * 24)`` becomes that class's range, paired
  with the most recent class-name materialization above the call. A
  merged run registered piecemeal (the a8 ambig fixture: three classes'
  entries side by side) resolves entry by entry.
- Cross-function registrations (the fbjni chain): the registrar
  stack-copies its slice and calls ``HybridClass<T>::registerHybrid``,
  which materializes the class name and makes the JNIEnv
  ``RegisterNatives`` vtable call. A9 P3 carries the caller's argument
  registers into the callee's first state, so the callee's (methods,
  count) read there; the methods pointer arrives as the stack copy's
  marker and is tied back to the static table by the registrar's memcpy
  (or its single table materialisation, for an inlined copy). A merged
  table registered for two classes splits by range; a count computed at
  run time reads as no constant and stays unconfirmed. A chain the
  carried reads cannot resolve still falls back to confirming its
  registrar's table whole when it names exactly one class.

A cheap byte pre-scan only proposes *where* to decode; the model
recomputes every address and a proposal the model does not confirm is
dropped, so a pre-scan defect can cost recall, never precision.
``armeabi-v7a`` and ``x86`` have no call-site layer here and stay
unconfirmed by design.

Measured carriers (N0(c)): fennec's libxul 7/7 candidate tables, and
RnHello's six ``initHybrid`` registrar chains; element's
runtime-composed soloader registration carries no constant name and
correctly confirms nothing.
"""

from __future__ import annotations

import contextlib
import itertools
import re
import struct

from blint.lib.jni import _read_cstring
from blint.logger import LOG

# JNIEnv vtable slots (the JNINativeInterface order, reserved0-3 first):
# FindClass is entry 6, RegisterNatives entry 215. The slot's byte offset and
# the JNINativeMethod entry stride scale with the ABI's word size: 215*8/24
# on the 64-bit ABIs, 215*4/12 on i386.
REGISTER_NATIVES_VTABLE_OFFSET = 215 * 8


def _vtable_slot_tokens(arch: str) -> tuple[str, ...]:
    """The RegisterNatives vtable access as nyxstone prints it, per arch.

    arm64 loads the slot (``ldr xN, [xM, #1720]``); x86-64 calls or loads
    through it (``call qword ptr [rN + 1720]``); i386 spells the same access
    with the 32-bit offset (``call dword ptr [eN + 860]``). The compact
    text (spaces removed) is what carries the token.
    """
    if arch == "x86":
        return ("+860]", "#860")
    return ("#0x6b8", "#1720", "+0x6b8]", "+1720]")


def _table_entry_stride(arch: str) -> int:
    """JNINativeMethod is three words: 24 bytes on 64-bit ABIs, 12 on i386."""
    return 12 if arch == "x86" else 24


# A Java binary name in slashed form, with fbjni's optional trailing ';'
# (the registrars slice the name out of the middle of an `L...;`
# descriptor, so the materialized address may start after the 'L' and
# the ';' may ride along).
_CLASS_NAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_$]*(/[a-zA-Z0-9_$]+)+;?$")

# nyxstone prints `adr xN, #<delta>` (decimal under immediate_style 0).
_ADR_TEXT_RE = re.compile(
    r"^adr\s+(?P<reg>[a-z]\d+)\s*,\s*(?P<delta>#?-?(?:0x[0-9a-f]+|\d+))$", re.IGNORECASE
)
# The x86 model keeps rsp in the running sp adjustment rather than as a
# register value, so a stack pointer handed onward to a call (`mov rbx,
# rsp; mov rdi, rbx` or `lea rax, [rsp + 8]`) is read beside the model
# the way `adr` is: the ("sp", off) symbolic the ARM64 model produces
# for the same code.
_X86_SP_MOVE_RE = re.compile(
    r"^mov\s+(?P<dst>[re][a-z0-9]{1,4})\s*,\s*(?P<base>rsp|rbp)$", re.IGNORECASE
)
_X86_SP_LEA_RE = re.compile(
    r"^lea\s+(?P<dst>[re][a-z0-9]{1,4})\s*,\s*\[(?P<base>rsp|rbp)\s*(?P<sign>[+-])\s*"
    r"(?P<off>0x[0-9a-f]+|\d+)\]$",
    re.IGNORECASE,
)
# A rip-relative operand names its own address: x86-64's registerHybrid
# copies the class name out of .rodata with `movups xmm0, xmmword ptr
# [rip - N]` (no register ever holds the string's address), so the
# operand is the only carrier - the same pc-relative textual read `adr`
# gets. The class-name shape check filters what it accepts.
# Byte-level pre-scan for rip-relative loads. The lookahead makes the
# matches overlap, so a false match cannot hide a real instruction that
# starts inside its 7 bytes.
_X86_RIP_CANDIDATE_RES = (
    re.compile(rb"(?=[\x48\x4c][\x8b\x8d][\x05\x0d\x15\x1d\x25\x2d\x35\x3d])", re.DOTALL),
    re.compile(rb"(?=\x0f[\x10\x28][\x05\x0d\x15\x1d\x25\x2d\x35\x3d])", re.DOTALL),
)
_RIP_RELATIVE_RE = re.compile(
    r"\[rip\s*(?P<sign>[+-])\s*(?P<off>0x[0-9a-f]+|\d+)\]", re.IGNORECASE
)
# arm64 prints the vtable offset as `ldr xN, [xM, #1720]` (or #0x6b8);
# x86_64 as `call qword ptr [rN + 1720]` - no '#' and the ']' closes the
# operand, which keeps ordinary +1720 immediates out. i386's 860 form is
# added per-arch by _vtable_slot_tokens.
_REGISTER_NATIVES_TOKENS = ("#0x6b8", "#1720", "+0x6b8]", "+1720]")

# Decode bounds: the pre-scan pairs an adrp with an add within 8
# instructions; a registrar body longer than this is truncated (the
# registration sequence sits at the top of every observed registrar).
_MAX_FUNCTION_BYTES = 0x2000
_MAX_HOPS = 2
_TABLE_ENTRY_STRIDE = 24  # 3 words; the join's tables are 64-bit parses

# The integer argument registers of the two call-site ABIs, in position
# order; the RegisterNatives vtable call reads (methods, count) from the
# third and fourth, and a stack-copying registrar passes (methods, count)
# to its callee in the second and third.
_ARGUMENT_REGISTERS = {
    "aarch64": ("x0", "x1", "x2", "x3"),
    "x86_64": ("rdi", "rsi", "rdx", "rcx"),
}


def _walk_function(
    parsed_obj,
    nyxstone,
    model,
    sections,
    sorted_starts,
    plt_stubs,
    plt_names,
    start: int,
    incoming: dict | None = None,
    reloc_map: dict[int, int] | None = None,
    thunks: dict[int, str] | None = None,
):
    """Decode one function and step the absint model over it.

    ``incoming`` seeds the first state with the caller's argument
    registers at its direct call (A9 P3), with caller-frame ``("sp", k)``
    symbolics rewritten to ``("caller_sp", k)`` so a stack copy keeps its
    identity without aliasing this function's own frame. On i386 it also
    carries the caller's whole register map and the outgoing argument
    slots (an internal call may pass arguments in any register under
    clang's i386 convention, and the hardware truth is that every
    register holds exactly what the caller left in it).

    ``reloc_map`` (i386) resolves GOT slot loads beside the model, the way
    rip-relative operands resolve on x86-64; ``thunks`` names the
    ``__x86.get_pc_thunk.*`` start addresses so a call to one leaves the
    return address in the thunk's register as a materialised pointer.

    Returns a record: the ordered class-name materializations; the
    RegisterNatives calls whose methods/count the model could read (on
    i386 from the cdecl argument slots at [esp+8]/[esp+0xc], methods may
    be the carried stack marker), each paired with the most recent class
    name above it; the direct calls with the argument registers as they
    stood (PLT-resolved targets; on i386 the outgoing slot words beside
    them); the memcpy-shaped calls with (dst, src, size); and the
    function's own materialised addresses (adr text plus the model's
    fresh ``("ptr", a)`` writes - on i386 fresh GOTOFF ints too, filtered
    by the class-name shape check below).
    """
    from bisect import bisect_left

    from blint.lib.absint import FrameState

    arch = (
        "aarch64"
        if type(model).__name__ == "Arm64Model"
        else ("x86" if type(model).__name__ == "I386Model" else "x86_64")
    )
    args_order = _ARGUMENT_REGISTERS.get(arch, ())
    slot_tokens = _vtable_slot_tokens(arch)
    index = bisect_left(sorted_starts, start)
    end = (
        sorted_starts[index + 1] if index + 1 < len(sorted_starts) else start + _MAX_FUNCTION_BYTES
    )
    instructions = _disassemble(nyxstone, sections, start, min(end - start, _MAX_FUNCTION_BYTES))
    if not instructions:
        return {
            "class_events": [],
            "registration_events": [],
            "runtime_registrations": [],
            "calls": [],
            "copies": [],
            "targets": set(),
        }
    state = FrameState(model)
    incoming = incoming or {}
    for family, value in incoming.get("registers", incoming).items():
        if isinstance(value, dict):
            continue
        state.registers[family] = value
    for (base, offset), value in (incoming.get("slots") or {}).items():
        if isinstance(value, tuple):
            state.store_pointer_word(base, offset, value)
        elif isinstance(value, int):
            state.store(base, offset, value, 4)
    class_events: list[str] = []
    registration_events: list[dict] = []
    runtime_registrations: list[dict] = []
    calls: list[dict] = []
    copies: list[dict] = []
    materialized_addresses: set[int] = set()
    pending_vtable_reg = None
    last_class: str | None = None
    # The model deliberately does not fold `adr`; nyxstone prints its
    # delta, so the target is read the way the disassembler reads every
    # AArch64 pc-relative operand - instruction address plus the printed
    # delta - and kept beside the model's own materialisations.
    adr_values: dict[str, int] = {}
    for instruction in instructions:
        text = instruction.assembly.strip()
        compact = text.replace(" ", "")
        mnemonic = text.split(None, 1)[0].lower() if text else ""
        # The RegisterNatives vtable access names the call that follows:
        # arm64 loads the slot (`ldr xN, [xM, #1720]`) and branches
        # through it (`blr`/a `br` tail); x86-64 either calls through the
        # slot in one instruction (`call/jmp qword ptr [rN + 1720]`) or
        # loads it (`mov r8, [rcx + 1720]`) and tails out (`jmp r8`); i386
        # spells the same two shapes with the 32-bit offset.
        carries_slot = any(token in compact for token in slot_tokens)
        # Argument registers are read BEFORE stepping the call: a call
        # clobbers them in the model, and they are the evidence.
        vtable_call = False
        if carries_slot:
            pending_vtable_reg = instruction.address
            vtable_call = arch != "aarch64" and mnemonic in ("call", "jmp")
        elif pending_vtable_reg is not None:
            if arch == "aarch64":
                vtable_call = mnemonic in ("blr", "br")
            else:
                vtable_call = mnemonic in ("call", "jmp") and "[" not in compact
        if vtable_call:
            if arch == "x86":
                # cdecl: the four arguments sit in the outgoing slots
                # [esp .. esp+0xc]; methods is the third, count the fourth.
                methods = (
                    state.slots.get(("esp", state.sp_adjustment + 8))
                    if state.sp_adjustment is not None
                    else None
                )
                count = (
                    state.slots.get(("esp", state.sp_adjustment + 0xC))
                    if state.sp_adjustment is not None
                    else None
                )
                methods = methods if isinstance(methods, (int, tuple)) else None
                count = count if isinstance(count, int) and 0 < count <= 4096 else None
            else:
                methods = _carried_register(
                    state, "rdx" if arch != "aarch64" else "x2", adr_values
                )
                count = _int_register(state, "ecx" if arch != "aarch64" else "w3")
            if methods is not None and count and last_class:
                registration_events.append(
                    {"methods": methods, "count": count, "class": last_class}
                )
                if (
                    arch == "x86"
                    and isinstance(methods, tuple)
                    and methods[0]
                    in (
                        "esp",
                        "ebp",
                        "caller_esp",
                        "caller_ebp",
                    )
                ):
                    # A table built at run time: the entry words sit in the
                    # frame slots the methods pointer names. Each word is
                    # whatever a store left - an immediate address, a
                    # materialised pointer, or nothing (unreadable).
                    runtime_registrations.append(
                        {
                            "methods": methods,
                            "count": count,
                            "class": last_class,
                            "words": [
                                state.load_word(methods[0], methods[1] + 4 * index)
                                for index in range(count * 3)
                            ],
                        }
                    )
            last_class = None
            pending_vtable_reg = None
        if mnemonic in ("bl", "call"):
            target = _direct_target(instruction, text, arch, plt_stubs)
            if target is not None:
                args = {}
                if arch == "x86":
                    for offset in (0, 4, 8, 0xC):
                        if state.sp_adjustment is None:
                            break
                        value = state.load_word("esp", state.sp_adjustment + offset)
                        if value is not None:
                            args[offset] = value
                else:
                    for name in args_order:
                        value = state.get_register(name)
                        if value is not None:
                            args[name] = value[0]
                calls.append(
                    {
                        "target": target,
                        "args": args,
                        # the register map as it stood at the call (i386: an
                        # internal call may pass arguments in any register)
                        "registers": dict(state.registers) if arch == "x86" else None,
                        "slots": dict(state.slots) if arch == "x86" else None,
                    }
                )
                if plt_names.get(target) in ("memcpy", "memmove"):
                    if arch == "x86":
                        dst = args.get(0)
                        src = args.get(4)
                        size = args.get(8)
                    else:
                        dst = _raw_register(state, args_order[0])
                        src = _raw_register(state, args_order[1])
                        size = _int_register(state, args_order[2])
                    if (
                        isinstance(dst, (int, tuple))
                        and isinstance(src, (int, tuple))
                        and isinstance(size, int)
                        and size
                    ):
                        copies.append({"dst": dst, "src": src, "size": size})
        span = (instruction.address, instruction.address + len(instruction.bytes))
        before = dict(state.registers)
        with contextlib.suppress(Exception):
            model.step(state, text, leaves_function=True, address_span=span)
        materialized: set[int] = set()
        if arch != "aarch64":
            _apply_x86_sp_symbolic(state, model, text)
            materialized.update(_x86_rip_operands(parsed_obj, instruction, text))
        if arch == "x86":
            # GOTOFF operands (SSE entry copies, string loads through the
            # GOT base register) name addresses beside the model
            materialized.update(_x86_gotoff_operands(state, text))
        if arch == "x86":
            # A call into a named pc thunk leaves the return address in the
            # thunk's register: the GOT base every ebx-relative operand
            # folds against (the inline `call 0` form the model executes
            # itself leaves an int, which the capture below also accepts).
            if mnemonic == "call" and thunks:
                raw_target = _call_target_address(instruction, text)
                thunk_register = thunks.get(raw_target) if raw_target is not None else None
                if thunk_register:
                    state.registers[thunk_register] = ("ptr", span[1])
                    materialized.add(span[1])
            # A GOT slot load (`mov reg, [got_base_reg + K]`) reads a word
            # the linker relocated: resolve it beside the model so the
            # signature/fnPtr words carry real addresses.
            if (
                reloc_map is not None
                and (resolved := _resolve_x86_got_load(state, text, reloc_map)) is not None
            ):
                register, value = resolved
                state.registers[register] = value
        match = _ADR_TEXT_RE.match(text)
        if match:
            with contextlib.suppress(ValueError):
                target = instruction.address + int(match.group("delta").lstrip("#"), 0)
                materialized.add(target)
                adr_values[match.group("reg")] = target
        # Only a pointer this instruction wrote names a class here; one
        # still held from earlier must not pair with a later registration.
        for register, value in state.registers.items():
            if before.get(register) == value:
                continue
            if (
                isinstance(value, tuple)
                and value
                and value[0] == "ptr"
                and isinstance(value[1], int)
            ):
                materialized.add(value[1])
            elif arch == "x86" and isinstance(value, int) and value > 0x1000:
                # i386 materialises addresses as plain ints (the inline pc
                # thunk leaves the GOT base as one); the class-name shape
                # check below filters what survives.
                materialized.add(value)
        materialized_addresses.update(materialized)
        for value in materialized:
            if arch == "x86" and not _starts_a_string_object(parsed_obj, value):
                # a GOTOFF operand can address a string's middle; only an
                # object start (the byte after NUL, or after the L of a
                # descriptor) names a class
                continue
            name = _class_name_at(parsed_obj, value)
            if name:
                class_events.append(name)
                last_class = name
    return {
        "class_events": class_events,
        "registration_events": registration_events,
        "runtime_registrations": runtime_registrations,
        "calls": calls,
        "copies": copies,
        "targets": {call["target"] for call in calls},
        "materialized": materialized_addresses,
    }


def _call_target_address(instruction, text: str) -> int | None:
    """A direct call's raw numeric target (pre-PLT), or None.

    ``bl`` prints a delta from the instruction's own address; an x86
    ``call`` prints the rel32, which encodes from the end of the
    instruction. Shared with ``_direct_target``'s arithmetic.
    """
    mnemonic = text.split(None, 1)[0].lower()
    if mnemonic not in ("bl", "call"):
        return None
    for token in text.split()[1:]:
        with contextlib.suppress(ValueError):
            value = int(token.strip("<>,").lstrip("#"), 0)
            base = (
                instruction.address
                if mnemonic == "bl"
                else instruction.address + len(instruction.bytes)
            )
            return base + value
    return None


_X86_GOT_LOAD_RE = re.compile(
    r"^mov\s+(?P<dest>[a-z]{2,3})\s*,\s*(?:dword\s+ptr\s+)?"
    r"\[\s*(?P<base>[a-z]{2,3})\s*(?P<sign>[+-])\s*(?P<off>\d+|0x[0-9a-f]+)\s*\]$",
    re.IGNORECASE,
)


def _x86_gotoff_operands(state, text: str) -> set[int]:
    """The absolute addresses a GOTOFF operand names: every ``[base ± K]``
    memory operand whose base register holds a known address (the GOT base
    an inline or named pc thunk left). The class-name shape check filters
    what survives wherever these are consumed as materialisations."""
    out: set[int] = set()
    model = _i386_model()
    for match in re.finditer(
        r"\[\s*([a-z]{2,3})\s*(?:([+-])\s*(\d+|0x[0-9a-f]+)\s*)?\]", text, re.IGNORECASE
    ):
        info = model.register(match.group(1))
        if not info:
            continue
        value = state.registers.get(info[0])
        if isinstance(value, tuple):
            if value[0] != "ptr":
                continue
            base = value[1]
        elif isinstance(value, int):
            base = value
        else:
            continue
        offset = int(match.group(3), 0) if match.group(3) else 0
        if match.group(2) == "-":
            offset = -offset
        out.add((base + offset) & 0xFFFFFFFF)
    return out


def _i386_pc_context(nyxstone, sections: list[tuple[int, bytes]], starts: dict[int, str]):
    """The i386 PIC context the walk needs: the GOT base measured from an
    inline ``call .+0; pop; add`` site, and the ``__x86.get_pc_thunk.*``
    start addresses with the register each leaves the return address in.

    Returns ``(got_base, {thunk start: register family})``; the base is
    None when no inline site exists (named-thunk-only binaries keep their
    per-site ``add`` operands, which the walk still folds per function).
    """
    got_base: int | None = None
    for base, blob in sections:
        offset = 0
        while got_base is None and offset < len(blob) - 12:
            offset = blob.find(b"\xe8\x00\x00\x00\x00", offset)
            if offset < 0:
                break
            # a window that ends mid-instruction fails the whole decode;
            # shrink to the reported position and take what decoded
            window = blob[offset : offset + 24]
            decoded = []
            while window:
                try:
                    decoded = nyxstone.disassemble_to_instructions(list(window), base + offset)
                    break
                except ValueError as exc:
                    match = re.search(r"position (\d+)", str(exc))
                    if not match or int(match.group(1)) <= 1:
                        break
                    window = window[: int(match.group(1))]
                except Exception:
                    break
            texts = [i.assembly.strip() for i in decoded[:4]]
            if len(texts) >= 3 and texts[1].startswith("pop ") and texts[2].startswith("add "):
                add_match = re.match(r"^add (\w+), (\d+)$", texts[2])
                pop_match = re.match(r"^pop (\w+)$", texts[1])
                if add_match and pop_match:
                    got_base = (decoded[1].address + int(add_match.group(2))) & 0xFFFFFFFF
            offset += 1
    thunks: dict[int, str] = {}
    model = _i386_model()
    for start, name in starts.items():
        if "__x86.get_pc_thunk" not in name:
            continue
        window = _window_bytes(sections, start, 8)
        if not window:
            continue
        try:
            decoded = nyxstone.disassemble_to_instructions(list(window), start)
        except Exception:
            continue
        texts = [i.assembly.strip() for i in decoded[:3]]
        if len(texts) >= 2 and texts[0].startswith("mov ") and texts[1].startswith("ret"):
            mov_match = re.match(r"^mov (\w+), esp$", texts[0], re.IGNORECASE)
            if mov_match and (info := model.register(mov_match.group(1))):
                thunks[start] = info[0]
    return got_base, thunks


def _resolve_x86_got_load(state, text: str, reloc_map: dict[int, int]):
    """Resolve ``mov reg, [base ± K]`` when base holds a known address whose
    ``base ± K`` slot carries a relocation: the register then holds the
    relocated target (a GOT slot read). Returns (register family, value) or
    None - the relocation lookup is the filter, so a load through any other
    pointer stays unresolved exactly as before."""
    match = _X86_GOT_LOAD_RE.match(text)
    if not match:
        return None
    model = _i386_model()
    info = model.register(match.group("base"))
    if not info:
        return None
    base_value = state.registers.get(info[0])
    if isinstance(base_value, tuple):
        if base_value[0] != "ptr":
            return None
        base = base_value[1]
    elif isinstance(base_value, int):
        base = base_value
    else:
        return None
    offset = int(match.group("off"), 0)
    if match.group("sign") == "-":
        offset = -offset
    target = reloc_map.get((base + offset) & 0xFFFFFFFF)
    if target is None:
        return None
    dest_info = model.register(match.group("dest"))
    if not dest_info:
        return None
    return dest_info[0], ("ptr", target)


def _i386_model():
    """The i386 absint model, imported lazily (the module is optional to the
    import order of this file's callers)."""
    from blint.lib.absint import I386_MODEL

    return I386_MODEL


def _x86_rip_operands(parsed_obj, instruction, text: str) -> set[int]:
    """The absolute addresses a rip-relative operand names (rip reads as
    the end of the instruction), kept only where the addressed byte starts
    a name this pass can use: the registerHybrid copy loads the class name
    with overlapping SSE moves whose later operands address the string's
    middle, and a mid-string address can still decode as a class-shaped
    name. A usable start is the byte after a NUL, or after the ``L`` of an
    ``L...;`` descriptor the registrar sliced the name out of."""
    out: set[int] = set()
    for match in _RIP_RELATIVE_RE.finditer(text):
        with contextlib.suppress(ValueError, Exception):
            offset = int(match.group("off"), 0)
            if match.group("sign") == "-":
                offset = -offset
            address = instruction.address + len(instruction.bytes) + offset
            before = bytes(parsed_obj.get_content_from_virtual_address(address - 1, 1))
            if before in (b"\x00", b"L"):
                out.add(address)
    return out


def _apply_x86_sp_symbolic(state, model, text: str) -> None:
    """Write the frame-pointer symbolic a `mov dst, rsp/rbp` /
    `lea dst, [rsp/rbp + off]` produces (the model keeps the frame bases
    in its adjustment and slot keys rather than as register values)."""
    match = _X86_SP_MOVE_RE.match(text) or _X86_SP_LEA_RE.match(text)
    if not match:
        return
    base = match.group("base").lower()
    offset = 0
    if "off" in match.groupdict() and match.group("off") is not None:
        offset = int(match.group("off"), 0)
        if match.group("sign") == "-":
            offset = -offset
    info = model.register(match.group("dst"))
    if not info:
        return
    if base == "rsp":
        if state.sp_adjustment is None:
            return
        state.registers[info[0]] = ("sp", state.sp_adjustment + offset)
    else:
        state.registers[info[0]] = ("rbp", offset)


def _raw_register(state, name: str):
    """The register's raw value - an int or a symbolic tuple, uninterpreted."""
    value = state.get_register(name)
    return value[0] if value is not None else None


def _carried_register(state, name: str, adr_values: dict[str, int]):
    """The methods argument: an address (int or ``("ptr", a)``) or a
    carried stack marker ``("caller_sp", k)`` / ``("caller_rbp", k)``
    from a seeding caller."""
    value = _raw_register(state, name)
    if isinstance(value, int):
        return value
    if isinstance(value, tuple) and value:
        if value[0] == "ptr" and isinstance(value[1], int):
            return value[1]
        if value[0] in ("caller_sp", "caller_rbp") and isinstance(value[1], int):
            return value
    if adr_values and name in adr_values:
        return adr_values[name]
    return None


def _seed_for_call(
    args: dict, arch: str = "x86_64", registers: dict | None = None, slots: dict | None = None
) -> dict:
    """Rewrite a caller's argument state into the callee's first state.

    Caller-frame ``("sp", k)`` / ``("rbp", k)`` symbolics become
    ``("caller_sp", k)`` / ``("caller_rbp", k)`` so they cannot alias the
    callee's own frame; everything else passes. On i386 the argument
    registers are stack slots keyed by their outgoing offset, so the seed
    carries them as callee slots at the cdecl incoming positions (+4, +8,
    ... - the return address occupies [esp+0]); the caller's whole
    register map rides along too, because an internal i386 call may pass
    arguments in any register under clang's convention, and at entry every
    register holds exactly what the caller left in it.
    """
    if arch == "x86":
        seed: dict = {"registers": {}, "slots": {}}
        for family, value in (registers or {}).items():
            if isinstance(value, tuple) and value and value[0] in ("esp", "ebp"):
                seed["registers"][family] = (f"caller_{value[0]}", value[1])
            else:
                seed["registers"][family] = value
        for offset, value in args.items():
            if isinstance(value, tuple) and value and value[0] in ("esp", "ebp"):
                seed["slots"][("esp", 4 + offset)] = (f"caller_{value[0]}", value[1])
            else:
                seed["slots"][("esp", 4 + offset)] = value
        # the caller's whole frame rides along under caller-prefixed bases:
        # a registration whose entries a caller built at run time reads its
        # words there
        for (base, offset), value in (slots or {}).items():
            seed["slots"][(f"caller_{base}", offset)] = value
        return seed
    out = {}
    for family, value in args.items():
        if isinstance(value, tuple) and value and value[0] in ("sp", "rbp"):
            out[family] = (f"caller_{value[0]}", value[1])
        else:
            out[family] = value
    return out


def _stack_copy_origin(
    marker: tuple,
    copies: list[dict],
    tables: set[int],
    lo: int,
    hi: int,
    count: int,
    stride: int = _TABLE_ENTRY_STRIDE,
) -> int | None:
    """The static-table address a carried stack marker (``("caller_sp",
    k)`` or ``("caller_rbp", k)``) methods pointer was copied from. The
    registrar's memcpy read (dst, src, size) names the source directly
    when the copy is a call (on i386 the source may be a GOTOFF int as
    well as a materialised pointer); an inlined copy leaves the
    registrar's own materialised table addresses as the candidates -
    entry-aligned (the copy's rip/GOTOFF operands address the
    name/signature words and the fn word of each entry, so exactly the
    entry starts are stride-aligned), contiguous, and exactly ``count``
    of them. Anything else decides nothing - the registration stays
    unconfirmed rather than guessed."""
    if len(marker) < 2 or not isinstance(marker[1], int):
        return None
    frame_base = marker[0].removeprefix("caller_")

    def origin_of(source) -> int | None:
        if (
            isinstance(source, tuple)
            and source
            and source[0] == "ptr"
            and isinstance(source[1], int)
        ):
            return source[1]
        if isinstance(source, int) and lo <= source < hi:
            return source
        return None

    origins = {
        origin
        for copy in copies
        if copy["dst"] == (frame_base, marker[1])
        and (origin := origin_of(copy["src"])) is not None
    }
    if len(origins) == 1:
        return next(iter(origins))
    if origins:
        return None
    aligned = {t for t in tables if lo <= t < hi and (t - lo) % stride == 0}
    if len(aligned) == 1:
        return next(iter(aligned))
    ordered = sorted(aligned)
    if len(ordered) == count and all(b - a == stride for a, b in itertools.pairwise(ordered)):
        return ordered[0]
    return None


def _direct_target(instruction, text: str, arch: str, plt_stubs: dict[int, int]) -> int | None:
    """A direct call's target from nyxstone's printed operand, PLT-resolved
    by the caller. ``bl`` prints a delta from the instruction's own
    address; an x86 ``call`` prints the rel32, which encodes from the end
    of the instruction."""
    mnemonic = text.split(None, 1)[0].lower()
    if mnemonic not in ("bl", "call"):
        return None
    for token in text.split()[1:]:
        with contextlib.suppress(ValueError):
            value = int(token.strip("<>,").lstrip("#"), 0)
            base = (
                instruction.address
                if arch == "aarch64"
                else instruction.address + len(instruction.bytes)
            )
            target = base + value
            return plt_stubs.get(target, target)
    return None


def _int_register(state, name: str) -> int | None:
    value = state.get_register(name)
    if value is None:
        return None
    inner = value[0]
    return inner if isinstance(inner, int) and 0 < inner <= 4096 else None


def _starts_a_string_object(parsed_obj, address: int) -> bool:
    """True when ``address`` begins a string object rather than pointing
    into one: the byte before it is a NUL, or the ``L`` of an ``L...;``
    descriptor the registrar sliced a name out of."""
    try:
        before = bytes(parsed_obj.get_content_from_virtual_address(address - 1, 1))
    except Exception:
        return False
    return before in (b"\x00", b"L")


def _class_name_at(parsed_obj, address: int) -> str | None:
    text = _read_cstring(parsed_obj, address)
    if text and 5 < len(text) < 200 and _CLASS_NAME_RE.match(text):
        return text.rstrip(";").replace("/", ".")
    return None


def _exec_sections(parsed_obj) -> list[tuple[int, bytes]]:
    out = []
    for section in parsed_obj.sections:
        try:
            flags = int(section.flags)
            if flags & 0x4 and section.size:
                base = int(section.virtual_address)
                out.append(
                    (
                        base,
                        bytes(
                            parsed_obj.get_content_from_virtual_address(base, int(section.size))
                        ),
                    )
                )
        except Exception:
            continue
    return out


def _naive_materializations(
    sections: list[tuple[int, bytes]],
    arch: str,
    extents: list[tuple[int, int, int]] | None = None,
    got_base: int | None = None,
) -> list[tuple[int, int]]:
    """Candidate (site, target) pairs from a raw scan - *where* to decode.

    arm64: an ``adrp`` word whose destination register is the base of a
    following ``add`` within 8 instructions, or an ``adr`` (one
    instruction, one target). x86_64: a REX ``lea`` with a rip-relative
    operand. i386: the four-byte GOTOFF displacements that would address a
    table entry start against the measured GOT base, found in the byte
    stream (the site is stepped back to the lea's opcode bytes; the model
    confirms or drops). The target here is only a proposal; the absint
    model recomputes it from the decoded instructions and a disagreement
    drops the candidate.
    """
    if arch == "x86":
        import struct as _struct

        out: list[tuple[int, int]] = []
        if got_base is None or not extents:
            return out
        for base, blob in sections:
            for lo, hi, _ in extents:
                for entry in range(lo, hi, _table_entry_stride(arch)):
                    disp = _struct.pack("<i", entry - got_base)
                    offset = 0
                    while True:
                        offset = blob.find(disp, offset)
                        if offset < 0:
                            break
                        for back in (2, 3):
                            out.append((base + offset - back, entry))
                        offset += 1
        return out
    out = []
    if arch == "aarch64":
        for base, blob in sections:
            n = len(blob) // 4
            words = struct.unpack_from(f"<{n}I", blob)
            for i in range(n):
                w = words[i]
                site = base + i * 4
                if (w & 0x9F000000) == 0x10000000:
                    # adr: PC + signed imm21 - one instruction, one target.
                    imm = ((w >> 29) & 3) | (((w >> 5) & 0x7FFFF) << 2)
                    if imm & (1 << 20):
                        imm -= 1 << 21
                    out.append((site, site + imm))
                    continue
                if (w & 0x9F000000) != 0x90000000:
                    continue
                rd = w & 0x1F
                imm = ((w >> 29) & 3) | (((w >> 5) & 0x7FFFF) << 2)
                if imm & (1 << 20):
                    imm -= 1 << 21
                page = site & ~0xFFF
                for j in range(i + 1, min(i + 9, n)):
                    w2 = words[j]
                    if (w2 & 0xFF800000) == 0x91000000 and ((w2 >> 5) & 0x1F) == rd:
                        out.append((site, page + (imm << 12) + ((w2 >> 10) & 0xFFF)))
                        break
    else:
        # The rip-relative lea/mov/SSE-move encodings are 7 bytes each; the
        # matches are only proposals and the model confirms each.
        for base, blob in sections:
            for pattern in _X86_RIP_CANDIDATE_RES:
                for match in pattern.finditer(blob):
                    i = match.start()
                    if i + 7 > len(blob):
                        break
                    disp = struct.unpack_from("<i", blob, i + 3)[0]
                    out.append((base + i, base + i + 7 + disp))
    return out


def _function_starts(parsed_obj) -> dict[int, str]:
    """Defined dynamic FUNCs plus the unwind-table discoveries (F1's set)."""
    from blint.lib.funcdisc.unwind import discover_functions

    starts: dict[int, str] = {}
    for symbol in parsed_obj.dynamic_symbols:
        try:
            if symbol.value and "FUNC" in str(symbol.type) and int(symbol.shndx or 0):
                starts.setdefault(int(symbol.value) & ~1, symbol.name)
        except Exception:
            continue
    for discovered in discover_functions(parsed_obj) or []:
        address = discovered.get("address")
        try:
            starts.setdefault((address if isinstance(address, int) else int(address, 16)) & ~1, "")
        except (TypeError, ValueError):
            continue
    return starts


def _nearest_start(sorted_starts: list[int], address: int):
    lo, hi = 0, len(sorted_starts)
    while lo < hi:
        mid = (lo + hi) // 2
        if sorted_starts[mid] <= address:
            lo = mid + 1
        else:
            hi = mid
    return sorted_starts[lo - 1] if lo else None


def _window_bytes(sections: list[tuple[int, bytes]], start: int, length: int):
    for base, blob in sections:
        if base <= start < base + len(blob):
            return blob[start - base : start - base + length]
    return None


def _disassemble(nyxstone, sections: list[tuple[int, bytes]], start: int, length: int) -> list:
    blob = _window_bytes(sections, start, length)
    if blob is None:
        return []
    # A window that ends mid-instruction makes nyxstone fail the whole
    # call; shrink to the reported position and take what decoded.
    while blob:
        try:
            return nyxstone.disassemble_to_instructions(list(blob), start)
        except ValueError as exc:
            match = re.search(r"position (\d+)", str(exc))
            if not match or int(match.group(1)) <= 1:
                return []
            blob = blob[: int(match.group(1))]
        except Exception:
            return []
    return []


def _plt_targets(parsed_obj) -> dict[int, int]:
    """PLT stub -> the local definition of the symbol it jumps through
    (fbjni's weak template instantiations are called through the PLT)."""
    from blint.lib.disassembler import _elf_plt_stub_names

    defined: dict[str, int] = {}
    for symbol in parsed_obj.dynamic_symbols:
        with contextlib.suppress(AttributeError, TypeError, ValueError):
            if symbol.value and int(symbol.shndx or 0):
                defined.setdefault(symbol.name, int(symbol.value) & ~1)
    return {
        stub: defined[name]
        for stub, name in _elf_plt_stub_names(parsed_obj).items()
        if name in defined
    }


def confirm_table_ranges(parsed_obj, tables: list[dict]) -> list[dict]:
    """``[{begin, end, class}]``: the recovered tables' address ranges,
    each registered for one class through a constant ``FindClass`` name.

    ``tables`` is the recovery's shape (``address`` may be a hex string,
    as the metadata form carries). A same-function registration carries
    its methods pointer and count in the model's argument registers, so
    its range is exactly ``[methods, methods + count * 24)`` - a merged
    run registered piecemeal resolves entry by entry. A registration in
    a callee (the fbjni ``registerHybrid`` shape) resolves the same way
    once the caller's argument registers are carried into the callee's
    first state (A9 P3): the methods pointer arrives as the stack copy's
    marker and its static origin - the registrar's memcpy source or its
    single table materialisation - names the range. What neither path
    resolves (a runtime-computed count, a chain naming two classes)
    stays unconfirmed unless the chain names exactly one class, in which
    case its registrar's table confirms whole. ``arm64``, ``x86_64`` and
    ``x86`` (i386) are modelled - the vtable slot and the entry stride
    scale with the ABI's word size, and on i386 the arguments are read
    from the cdecl stack slots with GOT loads resolved through the
    relocation map beside the model; anything else - or a nyxstone that
    cannot initialise - returns nothing and the caller keeps the entries
    ambiguous.
    """
    if not tables:
        return []
    machine = str(getattr(parsed_obj.header, "machine_type", ""))
    if "AARCH64" in machine:
        arch = "aarch64"
    elif "X86_64" in machine:
        arch = "x86_64"
    elif "I386" in machine or "EM_386" in machine:
        arch = "x86"
    else:
        return []
    stride = _table_entry_stride(arch)
    try:
        from nyxstone import Nyxstone

        from blint.lib.absint import ARM64_MODEL, I386_MODEL, X86_64_MODEL, FrameState
        from blint.lib.disassembler import (
            _default_disassembly_features,
            _merge_features,
            _to_nyxstone_triple,
        )

        nyxstone = Nyxstone(
            target_triple=_to_nyxstone_triple(
                arch if arch != "x86" else "i386-unknown-linux-android"
            ),
            features=_merge_features(_default_disassembly_features(arch), ""),
            immediate_style=0,
        )
        model = {"aarch64": ARM64_MODEL, "x86_64": X86_64_MODEL, "x86": I386_MODEL}[arch]
    except Exception as exc:
        LOG.debug(f"findclass confirmer: decode layer unavailable: {exc}")
        return []

    extents: list[tuple[int, int, int]] = []
    for table in tables:
        address = table.get("address")
        if address is None:
            continue
        if isinstance(address, str):
            with contextlib.suppress(ValueError):
                address = int(address, 16)
        if not isinstance(address, int):
            continue
        count = len(table.get("entries") or [])
        extents.append((address, address + count * stride, address))
    if not extents:
        return []
    # One linker-merged run can split into several recovered tables when
    # an entry fails validation; a registration covers the run as a whole
    # (fbjni memcpy's it), so tables within one entry stride of each
    # other confirm as one extent. Precise ranges still subdivide it, and
    # two adjacent classes' registrars both joining keeps it undecided.
    extents.sort()
    merged: list[tuple[int, int, int]] = []
    for lo, hi, address in extents:
        if merged and lo - merged[-1][1] <= stride:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi), merged[-1][2])
        else:
            merged.append((lo, hi, address))
    extents = merged

    sections = _exec_sections(parsed_obj)
    if not sections:
        return []
    starts = _function_starts(parsed_obj)
    sorted_starts = sorted(starts)
    if not sorted_starts:
        return []
    plt_stubs = _plt_targets(parsed_obj)
    plt_names: dict[int, str] = {}
    with contextlib.suppress(Exception):
        from blint.lib.disassembler import _elf_plt_stub_names

        plt_names = dict(_elf_plt_stub_names(parsed_obj))
    reloc_map: dict[int, int] = {}
    if arch == "x86":
        # i386 GOT slot loads resolve through the join's own relocation maps
        from blint.lib.jni import defined_symbol_relocation_map, relative_relocation_map

        reloc_map = relative_relocation_map(parsed_obj)[0]
        for slot, target in defined_symbol_relocation_map(parsed_obj).items():
            reloc_map.setdefault(slot, target)

    thunks: dict[int, str] = {}
    got_base: int | None = None
    if arch == "x86":
        got_base, thunks = _i386_pc_context(nyxstone, sections, starts)

    def materialized_in_window(site: int) -> tuple[set[int], int]:
        instructions = _disassemble(nyxstone, sections, site, 64)
        if not instructions:
            return set(), site
        materialized: set[int] = set()
        state = FrameState(model)
        if arch == "x86" and got_base is not None:
            # the window starts mid-function, after the pc idiom that set
            # the GOT base register; seed it so GOTOFF operands fold
            state.registers["ebx"] = ("ptr", got_base)
        for instruction in instructions:
            text = instruction.assembly.strip()
            span = (instruction.address, instruction.address + len(instruction.bytes))
            with contextlib.suppress(Exception):
                model.step(state, text, leaves_function=True, address_span=span)
            match = _ADR_TEXT_RE.match(text)
            if match:
                with contextlib.suppress(ValueError):
                    materialized.add(
                        instruction.address + int(match.group("delta").lstrip("#"), 0)
                    )
            if arch != "aarch64":
                # a one-entry registrar can address the table's words only
                # through rip-relative loads - no lea, no register pointer
                materialized.update(_x86_rip_operands(parsed_obj, instruction, text))
            if arch == "x86":
                # GOTOFF operands (loads and SSE copies through the GOT base
                # register) name addresses the model leaves as ints or drops
                materialized.update(_x86_gotoff_operands(state, text))
            for value in state.registers.values():
                if (
                    isinstance(value, tuple)
                    and value
                    and value[0] == "ptr"
                    and isinstance(value[1], int)
                ):
                    materialized.add(value[1])
                elif arch == "x86" and isinstance(value, int) and value > 0x1000:
                    materialized.add(value)
        return materialized, instructions[0].address

    # Phase A: sites whose *proposal* lands inside a table extent; the
    # model confirms and names the registrar function. On i386 the
    # proposals come from the GOTOFF displacements that would address each
    # entry start against the measured GOT base (the model confirms each).
    naive = _naive_materializations(sections, arch, extents=extents, got_base=got_base)
    registrars: dict[int, set[int]] = {address: set() for _, _, address in extents}
    for site, proposed in naive:
        for lo, hi, table_address in extents:
            if lo <= proposed < hi:
                materialized, first_address = materialized_in_window(site)
                if any(lo <= value < hi for value in materialized):
                    start = _nearest_start(sorted_starts, first_address)
                    if start is not None:
                        registrars[table_address].add(start)
                break

    # Phase B/C: the registrar chain. Same-function registrations carry
    # their (methods, count) in the model's registers and resolve as
    # address ranges. A9 P3: the fbjni callee reads its (methods, count)
    # from the caller's argument registers carried across the direct
    # call - the methods pointer arrives as the stack copy's
    # ("caller_sp", k) marker, tied back to the static table by the
    # registrar's own memcpy (dst == that stack slot, src == a
    # materialised table address, size == count * stride) or, where the
    # compiler inlined the copy, by the registrar's single table-address
    # materialisation. A count computed at run time reads as no constant
    # and leaves its slice without a range; the whole-table rule still
    # needs a chain naming exactly one class.
    confirmed_ranges: list[dict] = []
    for table_address, functions in registrars.items():
        if not functions:
            continue
        lo, hi, _ = next(e for e in extents if e[2] == table_address)
        chain_names: set[str] = set()
        precise = 0
        # start -> (the seeded argument registers, the registrar context
        # a carried marker resolves against)
        frontier: dict[int, tuple[dict | None, dict]] = {
            fn: (None, {"copies": [], "tables": set()}) for fn in functions
        }
        seen = set(frontier)
        hops = 0
        while frontier and hops <= _MAX_HOPS:
            hops += 1
            callees: dict[int, tuple[dict | None, dict]] = {}
            for start, (incoming, context) in frontier.items():
                record = _walk_function(
                    parsed_obj,
                    nyxstone,
                    model,
                    sections,
                    sorted_starts,
                    plt_stubs,
                    plt_names,
                    start,
                    incoming,
                    reloc_map=reloc_map if arch == "x86" else None,
                    thunks=thunks or None,
                )
                chain_names.update(record["class_events"])
                own_tables = {t for t in record["materialized"] if lo <= t < hi}
                resolution_copies = context["copies"] if incoming else record["copies"]
                resolution_tables = context["tables"] if incoming else own_tables
                for event in record["registration_events"]:
                    methods = event["methods"]
                    begin = None
                    if isinstance(methods, int):
                        begin = methods
                    elif isinstance(methods, tuple) and methods[0] in (
                        "caller_sp",
                        "caller_rbp",
                        "caller_esp",
                        "caller_ebp",
                    ):
                        begin = _stack_copy_origin(
                            methods,
                            resolution_copies,
                            resolution_tables,
                            lo,
                            hi,
                            event["count"],
                            stride,
                        )
                    if begin is None:
                        continue
                    end = begin + event["count"] * stride
                    if lo <= begin < hi and begin < end <= hi:
                        confirmed_ranges.append(
                            {"begin": begin, "end": end, "class": event["class"]}
                        )
                        precise += 1
                if hops < _MAX_HOPS:
                    carried_context = {
                        "copies": list(record["copies"]) + (context["copies"] if incoming else []),
                        "tables": own_tables | (context["tables"] if incoming else set()),
                    }
                    for call in record["calls"]:
                        target = call["target"]
                        if target in starts and target not in seen:
                            seen.add(target)
                            callees.setdefault(
                                target,
                                (
                                    _seed_for_call(
                                        call["args"],
                                        arch,
                                        call.get("registers"),
                                        call.get("slots"),
                                    ),
                                    carried_context,
                                ),
                            )
            frontier = callees
        if len(chain_names) == 1:
            # The fbjni shape: one registrar, one registerHybrid callee,
            # one class name. The registration's methods argument may be
            # a stack copy the model cannot tie back to the table, so the
            # chain's single name covers whatever the precise ranges left
            # uncovered (overlap-free: it starts past their last end).
            # A second class's registrar would have joined this chain
            # through phase A and its name would have spoiled the count,
            # which is what keeps a two-class table undecided.
            covered = lo
            for entry_range in confirmed_ranges:
                if lo <= entry_range["begin"] < hi:
                    covered = max(covered, entry_range["end"])
            if covered < hi:
                confirmed_ranges.append(
                    {"begin": covered, "end": hi, "class": next(iter(chain_names))}
                )
    return confirmed_ranges


# The i386 RegisterNatives vtable access in the byte stream: `call [reg+860]`
# (ff /2, mod=10) or the slot load `mov reg, [reg+860]` (8b, mod=10). The
# lookaheads keep the matches overlapping, so a false match cannot hide a
# real instruction that starts inside it.
_X86_VTABLE_SITE_RES = (
    re.compile(rb"(?=\xff[\x90-\x97]\x5c\x03\x00\x00)", re.DOTALL),
    re.compile(rb"(?=\x8b[\x80-\x87]\x5c\x03\x00\x00)", re.DOTALL),
)

_RUNTIME_MAX_ENTRIES = 64


def _direct_callers(sections, targets: set[int]) -> set[int]:
    """Addresses of the ``call rel32`` sites whose target is in ``targets``."""
    callers: set[int] = set()
    for base, blob in sections:
        for offset in range(len(blob) - 5):
            if blob[offset] != 0xE8:
                continue
            disp = int.from_bytes(blob[offset + 1 : offset + 5], "little", signed=True)
            if (base + offset + 5 + disp) & 0xFFFFFFFF in targets:
                callers.add(base + offset)
    return callers


def recover_runtime_tables(parsed_obj) -> list[dict]:
    """Registrations whose ``JNINativeMethod`` table no static triple holds.

    The registrar builds the entries at run time (A10's cause B, the fbjni
    32-bit and jni.hpp single-entry shapes); this walk reads the words it
    stored - the name and signature string addresses plus the fnPtr - from
    the frame slots the methods pointer names, in the function that made
    the vtable call or in the caller whose stack buffer the pair carried.

    Entries are never inferred from strings alone: every word must come
    from a store the walk saw, and every fnPtr must land on a function
    start this binary's own sources name (symbols, exports, unwind
    tables). A registration with any unreadable or invalid word is dropped
    whole rather than partially recovered, and a count computed at run
    time reads as no constant and recovers nothing. Only i386 is walked -
    the ABI whose word-store shape S0 measured as readable; other
    architectures return nothing.
    """
    machine = str(getattr(parsed_obj.header, "machine_type", ""))
    if "I386" not in machine and "EM_386" not in machine:
        return []
    try:
        from nyxstone import Nyxstone

        from blint.lib.absint import I386_MODEL
        from blint.lib.disassembler import _default_disassembly_features, _merge_features

        nyxstone = Nyxstone(
            target_triple="i386-unknown-linux-android",
            features=_merge_features(_default_disassembly_features("x86"), ""),
            immediate_style=0,
        )
        model = I386_MODEL
    except Exception as exc:
        LOG.debug(f"runtime-table recovery: decode layer unavailable: {exc}")
        return []
    sections = _exec_sections(parsed_obj)
    starts = _function_starts(parsed_obj)
    sorted_starts = sorted(starts)
    if not sections or not sorted_starts:
        return []
    plt_stubs = _plt_targets(parsed_obj)
    plt_names: dict[int, str] = {}
    with contextlib.suppress(Exception):
        from blint.lib.disassembler import _elf_plt_stub_names

        plt_names = dict(_elf_plt_stub_names(parsed_obj))
    from blint.lib.jni import defined_symbol_relocation_map, relative_relocation_map

    reloc_map = relative_relocation_map(parsed_obj)[0]
    for slot, target in defined_symbol_relocation_map(parsed_obj).items():
        reloc_map.setdefault(slot, target)
    _got_base, thunks = _i386_pc_context(nyxstone, sections, starts)

    # Function starts that make (or contain) a RegisterNatives vtable call,
    # and the callers that pass the {methods, count} pair into them.
    site_functions: set[int] = set()
    for base, blob in sections:
        for pattern in _X86_VTABLE_SITE_RES:
            for match in pattern.finditer(blob):
                start = _nearest_start(sorted_starts, base + match.start())
                if start is not None:
                    site_functions.add(start)
    if not site_functions:
        return []
    stub_targets = {stub for stub, definition in plt_stubs.items() if definition in site_functions}
    caller_sites = _direct_callers(sections, site_functions | stub_targets)
    roots: set[int] = set(site_functions)
    for site in caller_sites:
        start = _nearest_start(sorted_starts, site)
        if start is not None:
            roots.add(start)

    exec_ranges = [(base, base + len(blob)) for base, blob in sections]
    registrations: list[dict] = []
    seen_registrations: set[tuple] = set()
    seen: set[int] = set()
    seeded_seen: set[int] = set()
    frontier: dict[int, dict | None] = {fn: None for fn in roots}
    hops = 0
    while frontier and hops <= _MAX_HOPS:
        hops += 1
        callees: dict[int, dict | None] = {}
        for start, incoming in frontier.items():
            if start in seen and incoming is None:
                continue
            seen.add(start)
            record = _walk_function(
                parsed_obj,
                nyxstone,
                model,
                sections,
                sorted_starts,
                plt_stubs,
                plt_names,
                start,
                incoming,
                reloc_map=reloc_map,
                thunks=thunks or None,
            )
            for event in record.get("runtime_registrations") or []:
                entries = _runtime_entries(parsed_obj, event, exec_ranges, set(sorted_starts))
                if not entries:
                    continue
                # one registrar may sit in several walked functions (two
                # helpers registering the same class, a registrar and its
                # inlined twin): identical registrations count once
                identity = (
                    event["class"],
                    frozenset((e["name"], e["signature"], e["fn_addr"]) for e in entries),
                )
                if identity in seen_registrations:
                    continue
                seen_registrations.add(identity)
                registrations.append(
                    {"class": event["class"], "count": len(entries), "entries": entries}
                )
            if hops < _MAX_HOPS:
                for call in record["calls"]:
                    target = call["target"]
                    # a seeded walk of a vtable function is worth its own
                    # pass even after the unseeded root walk visited it -
                    # the chain's registration only reads with the caller's
                    # frame carried in
                    if target in site_functions and target not in seeded_seen:
                        seeded_seen.add(target)
                        callees.setdefault(
                            target,
                            _seed_for_call(
                                call["args"], "x86", call.get("registers"), call.get("slots")
                            ),
                        )
        frontier = callees
    return registrations


def _runtime_entries(parsed_obj, event: dict, exec_ranges, starts: set[int]) -> list[dict]:
    """Validate and decode one runtime registration's entry words.

    The words must all be present (each a store the walk saw), the name a
    Java identifier, the signature a valid method signature, and the fnPtr
    a function start in an executable section - the same oracle the static
    scan applies. Any miss drops the registration whole.
    """
    from blint.lib.jni import _JAVA_IDENTIFIER_RE, _read_cstring, _valid_method_signature

    words = event.get("words") or []
    if len(words) != event["count"] * 3 or event["count"] > _RUNTIME_MAX_ENTRIES:
        return []
    entries: list[dict] = []
    for index in range(event["count"]):
        name_word, signature_word, fn_word = words[index * 3 : index * 3 + 3]
        name_address = _word_address(name_word)
        signature_address = _word_address(signature_word)
        fn_address = _word_address(fn_word)
        if name_address is None or signature_address is None or fn_address is None:
            return []
        name = _read_cstring(parsed_obj, name_address)
        signature = _read_cstring(parsed_obj, signature_address)
        target = fn_address & ~1
        if (
            not name
            or not _JAVA_IDENTIFIER_RE.match(name)
            or not signature
            or not _valid_method_signature(signature)
            or target not in starts
            or not any(lo <= target < hi for lo, hi in exec_ranges)
        ):
            return []
        entries.append(
            {
                "name": name,
                "signature": signature,
                "fn_addr": hex(target),
                "thumb": bool(fn_address & 1),
                "slot": None,
            }
        )
    return entries


def _word_address(word) -> int | None:
    """The absolute address one entry word names, or None."""
    if isinstance(word, tuple) and word and word[0] == "ptr" and isinstance(word[1], int):
        return word[1]
    if isinstance(word, int) and 0 < word <= 0xFFFFFFFF:
        return word
    return None
