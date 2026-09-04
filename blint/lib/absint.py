"""Architecture-parameterized abstract interpretation for value recovery.

``stack_strings`` implements a deliberately small abstract interpreter for
x86-64: integer register values and the frame stores they feed. This module
generalizes that idea so other architectures can share the decode machinery
without inheriting its x86 register model. The first slice is ARM64, which is
the architecture that matters for iOS/macOS analysis and previously had no
stack-string recovery at all.

ARM64 string construction looks like:

    mov  x8, #291
    stur x8, [x29, #-24]        ; bytes land in a frame slot
    movz x8, #291
    movk x8, #118, lsl #16      ; 16-bit lanes folded into one register
    str  x8, [sp, #64]

or, for adrp-referenced constants, pairs of ``adrp`` + ``add``. The pass
tracks 16-bit lane insertion (``movk``), register moves, add/sub of
immediates, and stores through the two frame pointers (``sp`` and ``x29``).
A ``bl``/``blr`` call clobbers the caller-saved registers x0-x18, exactly as
the ABI demands; callee-saved x19-x28 and the frame registers survive.

Being conservative is what keeps the recovered strings honest: any
instruction writing a register that is not understood invalidates it, stores
through unknown registers are ignored, and the decode filters that
``stack_strings`` applies before reporting a string still run afterwards.
"""

import re

from blint.lib.stack_strings import _decode_runs, _parse_immediate

MIN_RUN_LEN = 3

# Frame bases whose stores land in a recoverable frame slot. x29 is the frame
# pointer (`fp` in some listings); everything else is a pointer this pass
# cannot locate.
ARM64_FRAME_BASES = frozenset({"sp", "x29", "fp"})

# Caller-saved registers under the AAPCS64 ABI. After a call their values are
# unknown; x19-x28 (callee-saved), x29 (fp), x30 (lr) and sp survive.
ARM64_CALL_CLOBBERED = frozenset(
    {f"x{i}" for i in range(19)} | {f"w{i}" for i in range(19)}
)

_REG = r"[wx]\d+|xzr|wzr|sp|fp|lr"
_IMM = r"#?-?(?:0x[0-9a-fA-F]+|[0-9]+)"

_ARM64_MOV_IMM_RE = re.compile(rf"^\s*mov\s+({_REG})\s*,\s*({_IMM})\s*$", re.I)
_ARM64_MOVZ_RE = re.compile(
    rf"^\s*movz\s+({_REG})\s*,\s*({_IMM})(?:\s*,\s*(?:lsl|LSL)\s+#?(\d+))?\s*$", re.I
)
_ARM64_MOVK_RE = re.compile(
    rf"^\s*movk\s+({_REG})\s*,\s*({_IMM})(?:\s*,\s*(?:lsl|LSL)\s+#?(\d+))?\s*$", re.I
)
_ARM64_MOV_REG_RE = re.compile(rf"^\s*mov\s+({_REG})\s*,\s*({_REG})\s*$", re.I)
_ARM64_ARITH_IMM_RE = re.compile(
    rf"^\s*(add|sub)\s+({_REG})\s*,\s*({_REG})\s*,\s*({_IMM})\s*$", re.I
)
_ARM64_STR_RE = re.compile(
    rf"^\s*(stur[bh]?|str[bh]?|stp)\s+({_REG})(?:\s*,\s*({_REG}))?\s*,\s*"
    rf"\[\s*({_REG})\s*(?:,\s*({_IMM})\s*)?\](!?)\s*(?:,\s*({_IMM}))?\s*$",
    re.I,
)

# Any other instruction whose first operand is a register kills the known
# value it held. Keeping this strict is what prevents stale values from being
# decoded as characters they never were.
_ARM64_DEST_REG_RE = re.compile(rf"^\s*[a-z][a-z0-9.]*\s+({_REG})\s*(?:,|$)", re.I)

_STORE_WIDTHS = {
    "strb": 1, "sturb": 1,
    "strh": 2, "sturh": 2,
    "str": None, "stur": None,  # width comes from the register
    "stp": None,
}


def _register_family(name: str) -> tuple[str, int] | None:
    """Map a register name to its (family, width); None for untracked regs."""
    name = name.strip().lower()
    if name in ("xzr", "wzr"):
        return ("xzr", 8 if name == "xzr" else 4)
    if name == "sp":
        return ("sp", 8)
    if name in ("fp", "lr"):
        return ("x29" if name == "fp" else "x30", 8)
    if name.startswith("x") and name[1:].isdigit():
        return (name, 8)
    if name.startswith("w") and name[1:].isdigit():
        return (f"x{name[1:]}", 4)
    return None


class Arm64FrameState:
    """Register values and frame-slot bytes observed so far in one function."""

    def __init__(self) -> None:
        self.registers: dict[str, int] = {}
        self.slots: dict[tuple[str, int], int] = {}

    def set_register(self, family: str, value: int, width: int) -> None:
        if width >= 8:
            self.registers[family] = value & 0xFFFFFFFFFFFFFFFF
            return
        # 32-bit writes zero-extend the upper half of the 64-bit register.
        self.registers[family] = value & 0xFFFFFFFF

    def get_register(self, name: str) -> tuple[int, int] | None:
        """Return the (value, width) a register operand currently reads as."""
        info = _register_family(name)
        if not info:
            return None
        family, width = info
        if family == "xzr":
            return 0, width
        value = self.registers.get(family)
        if value is None:
            return None
        return value & ((1 << (width * 8)) - 1), width

    def invalidate(self, name: str) -> None:
        info = _register_family(name)
        if info and info[0] != "xzr":
            self.registers.pop(info[0], None)

    def store(self, base: str, offset: int, value: int, width: int) -> None:
        base_family = _register_family(base)
        if not base_family or base_family[0] not in ARM64_FRAME_BASES:
            return
        base = "sp" if base_family[0] == "sp" else base_family[0]
        for index in range(width):
            self.slots[(base, offset + index)] = (value >> (index * 8)) & 0xFF

    def drop(self, base: str, offset: int, width: int) -> None:
        base_family = _register_family(base)
        if not base_family:
            return
        base = "sp" if base_family[0] == "sp" else base_family[0]
        for index in range(width):
            self.slots.pop((base, offset + index), None)


def interpret_arm64(lines: list[str]) -> Arm64FrameState:
    """Run the ARM64 forward pass over one function's assembly lines."""
    state = Arm64FrameState()
    for line in lines:
        text = line.strip()
        if not text:
            continue
        lowered = text.split(None, 1)[0].lower() if text else ""
        if lowered in ("bl", "blr", "blraa", "blrab"):
            for register in ARM64_CALL_CLOBBERED:
                state.invalidate(register)
            continue
        if lowered.startswith("b.") or lowered in ("b", "br", "ret", "brk", "cbz", "cbnz", "tbz", "tbnz"):
            # Pure control flow writes nothing.
            continue

        if match := _ARM64_STR_RE.match(text):
            _apply_store(state, match)
            continue

        if match := _ARM64_MOVZ_RE.match(text):
            value = _parse_immediate(match.group(2))
            shift = int(match.group(3) or 0)
            if value is None:
                state.invalidate(match.group(1))
            else:
                info = _register_family(match.group(1))
                if info:
                    state.set_register(info[0], value << shift, 8)
            continue

        if match := _ARM64_MOVK_RE.match(text):
            value = _parse_immediate(match.group(2))
            shift = int(match.group(3) or 0)
            info = _register_family(match.group(1))
            if info is None or value is None:
                state.invalidate(match.group(1))
                continue
            current = state.registers.get(info[0])
            if current is None:
                continue
            lane = 0xFFFF << shift
            state.set_register(
                info[0], (current & ~lane & 0xFFFFFFFFFFFFFFFF) | ((value << shift) & lane), 8
            )
            continue

        if match := _ARM64_MOV_IMM_RE.match(text):
            value = _parse_immediate(match.group(2))
            if value is None:
                state.invalidate(match.group(1))
            else:
                info = _register_family(match.group(1))
                if info:
                    state.set_register(info[0], value, info[1])
            continue

        if match := _ARM64_MOV_REG_RE.match(text):
            source = state.get_register(match.group(2))
            if source is None:
                state.invalidate(match.group(1))
            else:
                info = _register_family(match.group(1))
                if info:
                    state.set_register(info[0], source[0], info[1])
            continue

        if match := _ARM64_ARITH_IMM_RE.match(text):
            _apply_arith(state, match)
            continue

        # Anything else writing its first-operand register invalidates it.
        if match := _ARM64_DEST_REG_RE.match(text):
            state.invalidate(match.group(1))
    return state


def _apply_store(state: Arm64FrameState, match: re.Match) -> None:
    """Apply one str/stur/stp to the frame state."""
    opcode, reg_a, reg_b, base, offset_token, _pre, post_token = match.groups()
    offset = _parse_immediate(offset_token) if offset_token else 0
    if offset is None:
        return
    if post_token:
        # str x0, [sp], #16 writes at the base and then moves it; the slot
        # address is the pre-update base.
        pass

    source_a = state.get_register(reg_a)
    width = _STORE_WIDTHS.get(opcode.lower())
    if opcode.lower() == "stp":
        # Store pair: both registers land side by side.
        width_a = (source_a[1] if source_a else (_register_family(reg_a) or (None, 8))[1]) or 8
        source_b = state.get_register(reg_b) if reg_b else None
        if source_a is not None:
            state.store(base, offset, source_a[0], width_a)
        else:
            state.drop(base, offset, width_a)
        if reg_b:
            if source_b is not None:
                state.store(base, offset + width_a, source_b[0], source_b[1])
            else:
                state.drop(base, offset + width_a, source_b[1] if source_b else width_a)
        return
    if width is None:
        width = source_a[1] if source_a else (_register_family(reg_a) or (None, 8))[1]
    if source_a is None:
        state.drop(base, offset, width)
        return
    state.store(base, offset, source_a[0], width)


def _apply_arith(state: Arm64FrameState, match: re.Match) -> None:
    """Apply an add/sub of an immediate into a register."""
    op, dest, source_reg, immediate_token = match.groups()
    source = state.get_register(source_reg)
    immediate = _parse_immediate(immediate_token)
    if source is None or immediate is None:
        state.invalidate(dest)
        return
    info = _register_family(dest)
    if not info:
        return
    value = source[0] + immediate if op.lower() == "add" else source[0] - immediate
    state.set_register(info[0], value, info[1])


def recover_arm64_stack_strings(assembly: str) -> list[dict]:
    """Recover string literals one ARM64 function builds on its stack.

    Produces the same entry shape as the x86-64 pass so callers can consume
    both without special cases.
    """
    if not assembly:
        return []
    state = interpret_arm64(assembly.split("\n"))
    return _decode_runs(_iter_runs(state))


def _iter_runs(state: Arm64FrameState):
    """Yield (frame base, start offset, bytes) for each contiguous byte run."""
    by_base: dict[str, list[int]] = {}
    for base, offset in state.slots:
        by_base.setdefault(base, []).append(offset)
    for base, offsets in by_base.items():
        offsets.sort()
        run_start = offsets[0]
        current = [state.slots[(base, offsets[0])]]
        for offset in offsets[1:]:
            if offset == run_start + len(current):
                current.append(state.slots[(base, offset)])
                continue
            yield base, run_start, bytes(current)
            run_start = offset
            current = [state.slots[(base, offset)]]
        yield base, run_start, bytes(current)
