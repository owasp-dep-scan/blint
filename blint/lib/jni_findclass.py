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

from blint.logger import LOG

# JNIEnv vtable slots (the JNINativeInterface order, reserved0-3 first):
# FindClass is entry 6, RegisterNatives entry 215.
REGISTER_NATIVES_VTABLE_OFFSET = 215 * 8

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
_RIP_RELATIVE_RE = re.compile(
    r"\[rip\s*(?P<sign>[+-])\s*(?P<off>0x[0-9a-f]+|\d+)\]", re.IGNORECASE
)
# arm64 prints the vtable offset as `ldr xN, [xM, #1720]` (or #0x6b8);
# x86_64 as `call qword ptr [rN + 1720]` - no '#' and the ']' closes the
# operand, which keeps ordinary +1720 immediates out.
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
):
    """Decode one function and step the absint model over it.

    ``incoming`` seeds the first state with the caller's argument
    registers at its direct call (A9 P3), with caller-frame ``("sp", k)``
    symbolics rewritten to ``("caller_sp", k)`` so a stack copy keeps its
    identity without aliasing this function's own frame.

    Returns a record: the ordered class-name materializations; the
    RegisterNatives calls whose methods/count registers the model could
    read (methods may be the carried stack marker), each paired with the
    most recent class name above it; the direct calls with the argument
    registers as they stood (PLT-resolved targets); the memcpy-shaped
    calls with (dst, src, size); and the function's own materialised
    addresses (adr text plus the model's fresh ``("ptr", a)`` writes).
    """
    from bisect import bisect_left

    from blint.lib.absint import FrameState

    arch = "aarch64" if type(model).__name__ == "Arm64Model" else "x86_64"
    args_order = _ARGUMENT_REGISTERS[arch]
    index = bisect_left(sorted_starts, start)
    end = (
        sorted_starts[index + 1] if index + 1 < len(sorted_starts) else start + _MAX_FUNCTION_BYTES
    )
    instructions = _disassemble(nyxstone, sections, start, min(end - start, _MAX_FUNCTION_BYTES))
    if not instructions:
        return {
            "class_events": [],
            "registration_events": [],
            "calls": [],
            "copies": [],
            "targets": set(),
        }
    state = FrameState(model)
    for family, value in (incoming or {}).items():
        state.registers[family] = value
    class_events: list[str] = []
    registration_events: list[dict] = []
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
        # loads it (`mov r8, [rcx + 1720]`) and tails out (`jmp r8`).
        carries_slot = any(token in compact for token in _REGISTER_NATIVES_TOKENS)
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
            methods = _carried_register(state, "rdx" if arch != "aarch64" else "x2", adr_values)
            count = _int_register(state, "ecx" if arch != "aarch64" else "w3")
            if methods is not None and count and last_class:
                registration_events.append(
                    {"methods": methods, "count": count, "class": last_class}
                )
            last_class = None
            pending_vtable_reg = None
        if mnemonic in ("bl", "call"):
            target = _direct_target(instruction, text, arch, plt_stubs)
            if target is not None:
                args = {}
                for name in args_order:
                    value = state.get_register(name)
                    if value is not None:
                        args[name] = value[0]
                calls.append({"target": target, "args": args})
                if plt_names.get(target) in ("memcpy", "memmove"):
                    dst = _raw_register(state, args_order[0])
                    src = _raw_register(state, args_order[1])
                    size = _int_register(state, args_order[2])
                    if dst is not None and src is not None and size:
                        copies.append({"dst": dst, "src": src, "size": size})
        span = (instruction.address, instruction.address + len(instruction.bytes))
        before = dict(state.registers)
        with contextlib.suppress(Exception):
            model.step(state, text, leaves_function=True, address_span=span)
        materialized: set[int] = set()
        if arch != "aarch64":
            _apply_x86_sp_symbolic(state, model, text)
            materialized.update(_x86_rip_operands(parsed_obj, instruction, text))
        match = _ADR_TEXT_RE.match(text)
        if match:
            with contextlib.suppress(ValueError):
                target = instruction.address + int(match.group("delta").lstrip("#"), 0)
                materialized.add(target)
                adr_values[match.group("reg")] = target
        # Only a pointer this instruction wrote names a class here; one
        # still held from earlier must not pair with a later registration.
        for register, value in state.registers.items():
            if (
                before.get(register) != value
                and isinstance(value, tuple)
                and value
                and value[0] == "ptr"
                and isinstance(value[1], int)
            ):
                materialized.add(value[1])
        materialized_addresses.update(materialized)
        for value in materialized:
            name = _class_name_at(parsed_obj, value)
            if name:
                class_events.append(name)
                last_class = name
    return {
        "class_events": class_events,
        "registration_events": registration_events,
        "calls": calls,
        "copies": copies,
        "targets": {call["target"] for call in calls},
        "materialized": materialized_addresses,
    }


def _x86_rip_operands(parsed_obj, instruction, text: str) -> set[int]:
    """The absolute addresses a rip-relative operand names (rip reads as
    the end of the instruction), kept only where the addressed byte starts
    a name this pass can use: the registerHybrid copy loads the class name
    with overlapping SSE moves whose later operands address the string's
    middle, and a mid-string address can still decode as a class-shaped
    name (measured: ``ct.bridge.CatalystInstanceImpl`` off the real one).
    A usable start is the byte after a NUL, or after the ``L`` of an
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


def _seed_for_call(args: dict) -> dict:
    """Rewrite a caller's argument registers into the callee's first
    state: caller-frame ``("sp", k)`` / ``("rbp", k)`` symbolics become
    ``("caller_sp", k)`` / ``("caller_rbp", k)`` so they cannot alias the
    callee's own frame; everything else passes."""
    out = {}
    for family, value in args.items():
        if isinstance(value, tuple) and value and value[0] in ("sp", "rbp"):
            out[family] = (f"caller_{value[0]}", value[1])
        else:
            out[family] = value
    return out


def _stack_copy_origin(
    marker: tuple, copies: list[dict], tables: set[int], lo: int, hi: int, count: int
) -> int | None:
    """The static-table address a carried stack marker (``("caller_sp",
    k)`` or ``("caller_rbp", k)``) methods pointer was copied from. The
    registrar's memcpy read (dst, src, size) names the source directly
    when the copy is a call; an inlined copy leaves the registrar's own
    materialised table addresses as the candidates - entry-aligned (the
    copy's rip operands address the name/signature words and the fn word
    of each entry, so exactly the entry starts are stride-aligned),
    contiguous, and exactly ``count`` of them. Anything else decides
    nothing - the registration stays unconfirmed rather than guessed."""
    if len(marker) < 2 or not isinstance(marker[1], int):
        return None
    frame_base = marker[0].removeprefix("caller_")
    origins = {
        copy["src"][1]
        for copy in copies
        if copy["dst"] == (frame_base, marker[1])
        and isinstance(copy["src"], tuple)
        and copy["src"]
        and copy["src"][0] == "ptr"
        and isinstance(copy["src"][1], int)
    }
    if len(origins) == 1:
        return next(iter(origins))
    if origins:
        return None
    aligned = {t for t in tables if lo <= t < hi and (t - lo) % _TABLE_ENTRY_STRIDE == 0}
    if len(aligned) == 1:
        return next(iter(aligned))
    ordered = sorted(aligned)
    if len(ordered) == count and all(
        b - a == _TABLE_ENTRY_STRIDE for a, b in itertools.pairwise(ordered)
    ):
        return ordered[0]
    return None


def _direct_target(instruction, text: str, arch: str, plt_stubs: dict[int, int]) -> int | None:
    """A direct call's target from nyxstone's printed operand, PLT-resolved
    by the caller. ``bl`` prints a delta from the instruction's own
    address; an x86 ``call`` prints the rel32, which encodes from the end
    of the instruction (reading it instruction-relative, or as an absolute
    address, lost every x86_64 chain hop - A9 P3's first fix)."""
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


def _read_cstring(parsed_obj, address: int, limit: int = 256) -> str | None:
    try:
        blob = bytes(parsed_obj.get_content_from_virtual_address(address, limit))
    except Exception:
        return None
    end = blob.find(b"\x00")
    if end <= 0:
        return None
    try:
        return blob[:end].decode("utf-8")
    except UnicodeDecodeError:
        return None


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


def _naive_materializations(sections: list[tuple[int, bytes]], arch: str) -> list[tuple[int, int]]:
    """Candidate (site, target) pairs from a raw scan - *where* to decode.

    arm64: an ``adrp`` word whose destination register is the base of a
    following ``add`` within 8 instructions, or an ``adr`` (one
    instruction, one target). x86_64: a REX ``lea`` with a rip-relative
    operand. The target here is only a proposal; the absint model
    recomputes it from the decoded instructions and a disagreement drops
    the candidate.
    """
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
        # C-speed candidate location: the three rip-relative encodings are
        # 7 bytes each (REX opcode modrm disp32 / 0F opcode modrm disp32),
        # so a compiled regex walks the section where a Python loop over
        # every byte costs seconds on a 100 MB .text (measured: libxul
        # x86_64, 934k candidates, 5.5 s -> regex 0.1 s). The matches are
        # only proposals; the model confirms each.
        rex = re.compile(rb"[\x48\x4c][\x8b\x8d][\x05\x0d\x15\x1d\x25\x2d\x35\x3d]....", re.DOTALL)
        sse = re.compile(rb"\x0f[\x10\x28][\x05\x0d\x15\x1d\x25\x2d\x35\x3d]....", re.DOTALL)
        for base, blob in sections:
            for pattern in (rex, sse):
                for match in pattern.finditer(blob):
                    i = match.start()
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
    case its registrar's table confirms whole. Only ``arm64`` and
    ``x86_64`` are modelled (the call-site layer); anything else - or a
    nyxstone that cannot initialise - returns nothing and the caller
    keeps the entries ambiguous.
    """
    if not tables:
        return []
    machine = str(getattr(parsed_obj.header, "machine_type", ""))
    if "AARCH64" in machine:
        arch = "aarch64"
    elif "X86_64" in machine:
        arch = "x86_64"
    else:
        return []
    try:
        from nyxstone import Nyxstone

        from blint.lib.absint import ARM64_MODEL, X86_64_MODEL, FrameState
        from blint.lib.disassembler import (
            _default_disassembly_features,
            _merge_features,
            _to_nyxstone_triple,
        )

        nyxstone = Nyxstone(
            target_triple=_to_nyxstone_triple(arch),
            features=_merge_features(_default_disassembly_features(arch), ""),
            immediate_style=0,
        )
        model = ARM64_MODEL if arch == "aarch64" else X86_64_MODEL
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
        extents.append((address, address + count * _TABLE_ENTRY_STRIDE, address))
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
        if merged and lo - merged[-1][1] <= _TABLE_ENTRY_STRIDE:
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

    def materialized_in_window(site: int) -> tuple[set[int], int]:
        instructions = _disassemble(nyxstone, sections, site, 64)
        if not instructions:
            return set(), site
        materialized: set[int] = set()
        state = FrameState(model)
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
            for value in state.registers.values():
                if (
                    isinstance(value, tuple)
                    and value
                    and value[0] == "ptr"
                    and isinstance(value[1], int)
                ):
                    materialized.add(value[1])
        return materialized, instructions[0].address

    # Phase A: sites whose *proposal* lands inside a table extent; the
    # model confirms and names the registrar function.
    naive = _naive_materializations(sections, arch)
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
                    elif isinstance(methods, tuple) and methods[0] in ("caller_sp", "caller_rbp"):
                        begin = _stack_copy_origin(
                            methods, resolution_copies, resolution_tables, lo, hi, event["count"]
                        )
                    if begin is None:
                        continue
                    end = begin + event["count"] * _TABLE_ENTRY_STRIDE
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
                                target, (_seed_for_call(call["args"]), carried_context)
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
