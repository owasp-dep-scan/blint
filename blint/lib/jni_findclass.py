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
- Cross-function registrations (the fbjni chain): the callee's argument
  is invisible to a fresh frame, so the registrar's table is confirmed
  whole when its chain materializes exactly one class name.

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
        for base, blob in sections:
            for i in range(len(blob) - 7):
                if (
                    blob[i] in (0x48, 0x4C)
                    and blob[i + 1] == 0x8D
                    and (blob[i + 2] & 0xC7) == 0x05
                ):
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


def _walk_function(parsed_obj, nyxstone, model, sections, sorted_starts, start: int):
    """Decode one function and step the absint model over it.

    Returns (class_events, registration_events, call_targets): the
    ordered class-name materializations; the RegisterNatives calls whose
    methods/count registers the model could read, each paired with the
    most recent class name above it; and the direct call targets
    (PLT-resolved by the caller).
    """
    from blint.lib.absint import FrameState

    index = sorted_starts.index(start)
    end = (
        sorted_starts[index + 1] if index + 1 < len(sorted_starts) else start + _MAX_FUNCTION_BYTES
    )
    instructions = _disassemble(nyxstone, sections, start, min(end - start, _MAX_FUNCTION_BYTES))
    if not instructions:
        return [], [], set()
    state = FrameState(model)
    class_events: list[str] = []
    registration_events: list[dict] = []
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
        # The RegisterNatives vtable load names the call that follows.
        if mnemonic == "ldr" and any(token in compact for token in _REGISTER_NATIVES_TOKENS):
            pending_vtable_reg = instruction.address
        # Argument registers are read BEFORE stepping the call: a call
        # clobbers them in the model, and they are the evidence.
        if mnemonic == "call" and any(token in compact for token in _REGISTER_NATIVES_TOKENS):
            methods = _materialized_register(state, "rdx", adr_values)
            count = _int_register(state, "ecx")
            if methods is not None and count and last_class:
                registration_events.append(
                    {"methods": methods, "count": count, "class": last_class}
                )
            last_class = None
        if mnemonic == "blr" and pending_vtable_reg is not None:
            methods = _materialized_register(state, "x2", adr_values)
            count = _int_register(state, "w3")
            if methods is not None and count and last_class:
                registration_events.append(
                    {"methods": methods, "count": count, "class": last_class}
                )
            last_class = None
            pending_vtable_reg = None
        span = (instruction.address, instruction.address + len(instruction.bytes))
        with contextlib.suppress(Exception):
            model.step(state, text, leaves_function=True, address_span=span)
        match = _ADR_TEXT_RE.match(text)
        materialized: set[int] = set()
        if match:
            with contextlib.suppress(ValueError):
                target = instruction.address + int(match.group("delta").lstrip("#"), 0)
                materialized.add(target)
                adr_values[match.group("reg")] = target
        for value in state.registers.values():
            if (
                isinstance(value, tuple)
                and value
                and value[0] == "ptr"
                and isinstance(value[1], int)
            ):
                materialized.add(value[1])
        for value in materialized:
            name = _class_name_at(parsed_obj, value)
            if name:
                class_events.append(name)
                last_class = name
    call_targets = _call_targets(instructions, model, parsed_obj, _plt_targets(parsed_obj))
    return class_events, registration_events, call_targets


def _materialized_register(
    state, name: str, adr_values: dict[str, int] | None = None
) -> int | None:
    value = state.get_register(name)
    inner = value[0] if value is not None else None
    if isinstance(inner, int):
        return inner
    if isinstance(inner, tuple) and inner and inner[0] == "ptr":
        return inner[1]
    if adr_values and name in adr_values:
        return adr_values[name]
    return None


def _int_register(state, name: str) -> int | None:
    value = state.get_register(name)
    if value is None:
        return None
    inner = value[0]
    return inner if isinstance(inner, int) and 0 < inner <= 4096 else None


def _plt_targets(parsed_obj) -> dict[int, int]:
    """PLT stub -> defining address, for direct calls that go through the
    PLT to a weak local definition (fbjni's template instantiations)."""
    got_slot_to_value: dict[int, int] = {}
    for relocation in parsed_obj.relocations:
        if "JUMP_SLOT" not in str(getattr(relocation, "type", "")):
            continue
        symbol = None
        with contextlib.suppress(Exception):
            symbol = relocation.symbol
        if symbol is None:
            continue
        try:
            value = int(symbol.value or 0)
        except Exception:
            continue
        if value:
            got_slot_to_value[int(relocation.address)] = value
    stubs: dict[int, int] = {}
    for section in parsed_obj.sections:
        if (getattr(section, "name", "") or "") != ".plt":
            continue
        base = int(section.virtual_address)
        try:
            blob = bytes(parsed_obj.get_content_from_virtual_address(base, int(section.size)))
        except Exception:
            continue
        # arm64 PLT stub: adrp x17, page; ldr x17, [x17, #off]; br x17
        for off in range(0, len(blob) - 16, 16):
            w0, w1 = struct.unpack_from("<2I", blob, off)
            if (w0 & 0x9F000000) != 0x90000000 or (w1 & 0xFFC00000) != 0xF9400000:
                continue
            imm = ((w0 >> 29) & 3) | (((w0 >> 5) & 0x7FFFF) << 2)
            if imm & (1 << 20):
                imm -= 1 << 21
            slot = ((base + off) & ~0xFFF) + (imm << 12) + (((w1 >> 10) & 0xFFF) * 8)
            if slot in got_slot_to_value:
                stubs[base + off] = got_slot_to_value[slot]
        break
    return stubs


def _call_targets(instructions, model, parsed_obj, plt_stubs: dict[int, int]) -> set[int]:
    """Direct call targets from the decoded text (PLT-resolved).

    nyxstone prints an AArch64 ``bl`` operand as the pc-relative delta
    (``bl #2708680``), so the target is instruction address plus the
    printed delta - the same pc-relative read the disassembler applies to
    every AArch64 branch operand. An x86 ``call`` prints resolved.
    """
    arch = "aarch64" if type(model).__name__ == "Arm64Model" else "x86_64"
    call_mnemonics = ("bl",) if arch == "aarch64" else ("call",)
    out: set[int] = set()
    for instruction in instructions:
        text = (instruction.assembly or "").strip()
        mnemonic = text.split(None, 1)[0].lower() if text else ""
        if mnemonic not in call_mnemonics:
            continue
        for token in text.split()[1:]:
            with contextlib.suppress(ValueError):
                value = int(token.strip("<>,").lstrip("#"), 0)
                target = instruction.address + value if arch == "aarch64" else value
                out.add(plt_stubs.get(target, target))
                break
    return out


def confirm_table_ranges(parsed_obj, tables: list[dict]) -> list[dict]:
    """``[{begin, end, class}]``: the recovered tables' address ranges,
    each registered for one class through a constant ``FindClass`` name.

    ``tables`` is the recovery's shape (``address`` may be a hex string,
    as the metadata form carries). A same-function registration carries
    its methods pointer and count in the model's argument registers, so
    its range is exactly ``[methods, methods + count * 24)`` - a merged
    run registered piecemeal resolves entry by entry. A chain whose
    vtable calls read no arguments (the fbjni callee's fresh frame)
    confirms its registrar's table whole when the chain names exactly
    one class. Only ``arm64`` and ``x86_64`` are modelled (the call-site
    layer); anything else - or a nyxstone that cannot initialise -
    returns nothing and the caller keeps the entries ambiguous.
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
    # address ranges; a chain whose vtable calls read no arguments (the
    # fbjni callee's fresh frame) confirms its registrar's table whole
    # when the chain names exactly one class.
    confirmed_ranges: list[dict] = []
    for table_address, functions in registrars.items():
        if not functions:
            continue
        lo, hi, _ = next(e for e in extents if e[2] == table_address)
        chain_names: set[str] = set()
        precise = 0
        frontier = set(functions)
        seen = set(frontier)
        hops = 0
        while frontier and hops <= _MAX_HOPS:
            hops += 1
            callees: set[int] = set()
            for start in frontier:
                class_events, registration_events, call_targets = _walk_function(
                    parsed_obj, nyxstone, model, sections, sorted_starts, start
                )
                chain_names.update(class_events)
                for event in registration_events:
                    begin = event["methods"]
                    end = begin + event["count"] * _TABLE_ENTRY_STRIDE
                    if lo <= begin < hi:
                        confirmed_ranges.append(
                            {"begin": begin, "end": end, "class": event["class"]}
                        )
                        precise += 1
                if hops < _MAX_HOPS:
                    for target in call_targets:
                        if target in starts and target not in seen:
                            seen.add(target)
                            callees.add(target)
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
