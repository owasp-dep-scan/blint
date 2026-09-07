"""Architecture-parameterized abstract interpretation for value recovery.

``stack_strings`` historically carried a deliberately small x86-64
interpreter (integer register values and the frame stores they feed) as a
straight-line pass over the listing. This module generalizes it so every
architecture shares one traversal, one join and one run-decoding tail,
while the per-arch knowledge — register families, frame bases, call
clobbering and the instruction patterns — lives in an :class:`ArchModel`.

ARM64 string construction looks like:

    sub  sp, sp, #0x30
    movz x8, #0x2F
    movk x8, #0x75, lsl #16     ; 16-bit lanes folded into one register
    str  x8, [sp, #24]

and x86-64 builds the same things with ``mov``/``lea`` arithmetic
(SLEEPWALKER assembles ``\\\\.\\VMCI`` entirely from `lea eax, [rcx - N]`
folds of one loaded constant). Both dialects feed the same state machine.

The traversal is a fixed-point dataflow over the function's CFG, not a
straight-line walk. Blocks are visited from the entry over the CFG's edges
with a worklist; at a merge point a register (or frame-slot byte) survives
only when every contributing path agrees on its value — a value assembled
on a not-taken branch path can no longer leak into the reported result,
which is what the decode filters used to compensate for. Unreachable
blocks never enter the worklist and contribute nothing. The recovered
frame picture is the join of the out-states of the reachable exit blocks,
so a string is reported only when every path to leaving the function
leaves those bytes in place. Blocks that follow an indirect branch have no
incoming edge in the CFG (an indirect transfer can land anywhere), so they
are unreachable to this pass as well.

Loops terminate by iteration cap: a block is visited at most
``MAX_BLOCK_VISITS`` times. Registers under loop-carried arithmetic meet
at conflicting values and go unknown within a couple of rounds, so the cap
is a backstop, not the normal exit. When it is hit the function's state is
untrustworthy and *no strings are returned for it*; the caller counts the
event in ``stack_strings_coverage.functions_iteration_cap_hit`` so a cap
hit is observable rather than silent.

Functions whose metadata carries no usable CFG (blocks that do not tile
the assembly text, or no CFG at all) fall back to the straight-line pass,
which is also what the public helpers here run when handed a bare
assembly listing. A ``bl``/``blr`` (ARM64) or ``call`` (x86) clobbers the
caller-saved registers exactly as the ABI demands; callee-saved registers
and the frame registers survive. Any instruction writing a register the
model does not understand invalidates it, and stores through unknown
registers are ignored.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from blint.logger import LOG

# ---------------------------------------------------------------------------
# Shared decode tail (operates on the recovered frame picture, not on how it
# was computed — x86 and ARM64 results both flow through it unchanged).
# ---------------------------------------------------------------------------

# Immediates appear in whichever base the disassembler was configured for;
# blint defaults to decimal. See the IMMEDIATE_RE note in driver_ioctl for
# why all three renderings have to be accepted. The optional '#' prefix is
# the ARM64 operand spelling.
_IMM = r"#?-?(?:0x[0-9a-fA-F]+|[0-9][0-9a-fA-F]*h|[0-9]+)"


def _parse_immediate(token: str) -> int | None:
    """Parse one immediate operand in any of the disassembler's integer bases."""
    if not token:
        return None
    text = token.strip().lstrip("#")
    negative = text.startswith("-")
    if negative:
        text = text[1:]
    try:
        if text.lower().startswith("0x"):
            value = int(text, 16)
        elif text.lower().endswith("h"):
            value = int(text[:-1], 16)
        else:
            value = int(text, 10)
    except ValueError:
        return None
    return -value if negative else value


# Shortest run of bytes accepted as a recovered string. Three characters is
# long enough to exclude the two-byte fragments that ordinary struct
# initialisation leaves in a frame, while keeping short but meaningful values.
MIN_RECOVERED_LEN = 3
# A single function should not yield an unbounded number of candidates; a frame
# holding more than this many distinct string runs is initialising data, not
# building text.
MAX_RUNS_PER_FUNCTION = 64
# Instruction budget per function. Arithmetic string building is a prologue
# activity, and scanning entire large functions costs more than it recovers.
MAX_INSTRUCTIONS = 4000
# A block is visited at most this many times before the function is declared
# non-converged and dropped from recovery (see module docstring).
MAX_BLOCK_VISITS = 32

# Characters that appear in the string literals worth recovering: paths,
# registry keys, device names, module names and API names. The set is ASCII-only
# on purpose. A UTF-16LE run decoded one byte out of phase pairs each character
# with its neighbour's zero byte and yields perfectly well-formed CJK, so a test
# based on `str.isalnum` accepts the misaligned reading of every wide string.
_TEXT_CHARACTERS: frozenset[str] = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\\/.:_-@%$?![]{}()<>+=#'\", "
)


def _looks_like_text(value: str) -> bool:
    """Return True when a decoded run is plausibly a real string literal.

    Frame slots also hold call arguments, structure fields and flags, and any of
    those can decode to a few printable characters by chance. Requiring every
    character to be one that appears in paths, registry keys and API names is
    what separates a recovered literal from arithmetic residue.
    """
    if len(value) < MIN_RECOVERED_LEN:
        return False
    if not any(character.isascii() and character.isalpha() for character in value):
        return False
    return all(character in _TEXT_CHARACTERS for character in value)


def _decode_one(data: bytes, encoding: str) -> str:
    """Decode a byte run up to its first terminator, or return an empty string."""
    if encoding == "utf-16-le":
        usable = data[: len(data) - (len(data) % 2)]
        try:
            text = usable.decode("utf-16-le")
        except (UnicodeDecodeError, ValueError):
            return ""
    else:
        try:
            text = data.decode("ascii")
        except UnicodeDecodeError:
            return ""
    return text.split("\x00", 1)[0].strip()


def _decode_runs(runs: Iterator[tuple[str, int, bytes]]) -> list[dict]:
    """Decode each byte run, keeping the single best reading of each.

    A run is tried as both UTF-16LE and ASCII because a function may build
    either, but only the longer valid reading is kept. Emitting both would report
    the same literal twice, once truncated at the first zero byte of its own wide
    encoding.
    """
    recovered: list[dict] = []
    seen: set[str] = set()
    for base, offset, data in runs:
        if len(recovered) >= MAX_RUNS_PER_FUNCTION:
            break
        best: tuple[str, str] | None = None
        for encoding, label in (("utf-16-le", "utf-16le"), ("ascii", "ascii")):
            if encoding == "utf-16-le" and len(data) < MIN_RECOVERED_LEN * 2:
                continue
            candidate = _decode_one(data, encoding)
            if not candidate or not _looks_like_text(candidate):
                continue
            if best is None or len(candidate) > len(best[0]):
                best = (candidate, label)
        if best is None or best[0].lower() in seen:
            continue
        seen.add(best[0].lower())
        recovered.append(
            {
                "value": best[0],
                "encoding": best[1],
                "frame": f"{base}{offset:+d}",
            }
        )
    return recovered


def iter_frame_runs(state: FrameState) -> Iterator[tuple[str, int, bytes]]:
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


# ---------------------------------------------------------------------------
# The abstract state and its join.
# ---------------------------------------------------------------------------


class FrameState:
    """Register values and frame-slot bytes for one point of one function.

    Register values are plain ints, or tuples naming a symbolic pointer: a
    ``("sp", offset)`` names a slot relative to the *initial* stack pointer
    (so ``add x8, sp, #8`` followed by ``str x9, [x8]`` lands in the frame
    even after ``sub sp`` moved the base) and ``("adrp", 0)`` names a page
    pointer stores through which are not frame slots. ``sp_adjustment`` is
    the ARM64 running sp offset; ``None`` means incoming paths disagree on
    it, after which sp-relative stores cannot be located.

    The state carries its :class:`ArchModel` so operand-named accessors know
    the register families; the join below is model-independent.
    """

    def __init__(self, model: ArchModel) -> None:
        self.model = model
        # family -> int | tuple(symbolic pointer)
        self.registers: dict[str, int | tuple[str, int]] = {}
        # (frame base, signed offset) -> byte value
        self.slots: dict[tuple[str, int], int] = {}
        self.sp_adjustment: int | None = 0

    # -- join ---------------------------------------------------------------

    def joined_with(self, other: FrameState) -> bool:
        """Narrow ``self`` to what both states agree on; return True if it changed.

        A component survives the join only when it is present and equal in
        both states: a register holding different values on two incoming
        paths becomes unknown, and so does a frame byte. This is the whole
        point of the dataflow — the straight-line pass reported whichever
        value the listing happened to reach last.
        """
        changed = False
        for key in list(self.registers):
            if other.registers.get(key) != self.registers[key]:
                del self.registers[key]
                changed = True
        for key in list(self.slots):
            if other.slots.get(key) != self.slots[key]:
                del self.slots[key]
                changed = True
        if self.sp_adjustment != other.sp_adjustment:
            self.sp_adjustment = None
            changed = True
        return changed

    # -- operand-level accessors (arch knowledge comes from the model) -------

    def get_register(self, name: str) -> tuple[int | tuple[str, int], int] | None:
        """Return the (value, width) a register operand currently reads as."""
        info = self.model.register(name)
        if not info:
            return None
        family, width = info
        if self.model.is_zero_register(family):
            return 0, width
        value = self.registers.get(family)
        if value is None:
            return None
        if isinstance(value, int):
            return value & ((1 << (width * 8)) - 1), width
        return value, width

    def write_operand(self, name: str, value: int | tuple[str, int]) -> None:
        """Write through an operand name, applying the arch's sub-register rules."""
        self.model.write_operand(self, name, value)

    def write_family(self, family: str, value: int | tuple[str, int], width: int) -> None:
        """Write a resolved family; only symbolic-aware models need the width."""
        self.model.write_family(self, family, value, width)

    def invalidate(self, name: str) -> None:
        info = self.model.register(name)
        if info and not self.model.is_zero_register(info[0]):
            self.registers.pop(info[0], None)

    def store(self, base: str, offset: int, value: int, width: int) -> None:
        for index in range(width):
            self.slots[(base, offset + index)] = (value >> (index * 8)) & 0xFF

    def drop(self, base: str, offset: int, width: int) -> None:
        for index in range(width):
            self.slots.pop((base, offset + index), None)

    def family_value(self, family: str):
        return self.registers.get(family)


# ---------------------------------------------------------------------------
# Architecture models.
# ---------------------------------------------------------------------------


class ArchModel:
    """The per-architecture knowledge the shared traversal needs.

    Subclasses (and instances) supply register families, frame bases,
    call-clobbered registers and a ``step`` implementing one instruction's
    semantics against the shared :class:`FrameState`. The x86-64 and ARM64
    models below are the two instantiations; the traversal, join and
    run-decoding tail are shared and live outside them.
    """

    frame_bases: frozenset[str] = frozenset()
    call_clobbered: tuple[str, ...] = ()

    def register(self, name: str) -> tuple[str, int] | None:  # pragma: no cover - interface
        raise NotImplementedError

    def is_zero_register(self, family: str) -> bool:
        return False

    def write_operand(self, state: FrameState, name: str, value) -> None:  # pragma: no cover
        raise NotImplementedError

    def write_family(self, state: FrameState, family: str, value, width: int) -> None:  # pragma: no cover
        raise NotImplementedError

    def step(self, state: FrameState, text: str) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def clobber_call_registers(self, state: FrameState) -> None:
        for name in self.call_clobbered:
            state.invalidate(name)


# -- x86-64 -----------------------------------------------------------------

_REGISTER_FAMILIES: tuple[tuple[str, tuple[tuple[str, int], ...]], ...] = (
    ("rax", (("rax", 8), ("eax", 4), ("ax", 2), ("al", 1), ("ah", 1))),
    ("rbx", (("rbx", 8), ("ebx", 4), ("bx", 2), ("bl", 1), ("bh", 1))),
    ("rcx", (("rcx", 8), ("ecx", 4), ("cx", 2), ("cl", 1), ("ch", 1))),
    ("rdx", (("rdx", 8), ("edx", 4), ("dx", 2), ("dl", 1), ("dh", 1))),
    ("rsi", (("rsi", 8), ("esi", 4), ("si", 2), ("sil", 1))),
    ("rdi", (("rdi", 8), ("edi", 4), ("di", 2), ("dil", 1))),
    ("rbp", (("rbp", 8), ("ebp", 4), ("bp", 2), ("bpl", 1))),
    ("rsp", (("rsp", 8), ("esp", 4), ("sp", 2), ("spl", 1))),
)

_X86_REGISTER_INFO: dict[str, tuple[str, int]] = {}
for _family, _members in _REGISTER_FAMILIES:
    for _name, _width in _members:
        _X86_REGISTER_INFO[_name] = (_family, _width)
for _index in range(8, 16):
    _X86_REGISTER_INFO[f"r{_index}"] = (f"r{_index}", 8)
    _X86_REGISTER_INFO[f"r{_index}d"] = (f"r{_index}", 4)
    _X86_REGISTER_INFO[f"r{_index}w"] = (f"r{_index}", 2)
    _X86_REGISTER_INFO[f"r{_index}b"] = (f"r{_index}", 1)

_X86_REG = r"[a-z][a-z0-9]*"
_X86_SIZE_HINTS: dict[str, int] = {"byte": 1, "word": 2, "dword": 4, "qword": 8}

_MOV_REG_IMM_RE = re.compile(rf"^\s*mov\s+({_X86_REG})\s*,\s*({_IMM})\s*$", re.IGNORECASE)
_MOV_REG_REG_RE = re.compile(
    rf"^\s*(?:mov|movzx|movsx|movsxd)\s+({_X86_REG})\s*,\s*({_X86_REG})\s*$", re.IGNORECASE
)
_XOR_SELF_RE = re.compile(rf"^\s*xor\s+({_X86_REG})\s*,\s*({_X86_REG})\s*$", re.IGNORECASE)
_ARITH_REG_IMM_RE = re.compile(
    rf"^\s*(add|sub|or|and|xor)\s+({_X86_REG})\s*,\s*({_IMM})\s*$", re.IGNORECASE
)
# `lea eax, [rcx - 15]` is how a compiler folds "this character minus that one"
# into a single instruction; it is the workhorse of arithmetic string building.
_LEA_RE = re.compile(
    rf"^\s*lea\s+({_X86_REG})\s*,\s*\[\s*({_X86_REG})\s*(?:([+-])\s*({_IMM})\s*)?\]\s*$",
    re.IGNORECASE,
)
# A store into a frame slot, with the value either an immediate or a register.
_STORE_RE = re.compile(
    rf"^\s*mov\s+(?:(byte|word|dword|qword)\s+ptr\s+)?"
    rf"\[\s*({_X86_REG})\s*([+-])\s*({_IMM})\s*\]\s*,\s*({_IMM}|{_X86_REG})\s*$",
    re.IGNORECASE,
)
# Any other instruction writing a register invalidates what is known about it.
_DEST_REG_RE = re.compile(
    rf"^\s*(?:{'mov|movzx|movsx|movsxd|lea|add|sub|or|and|xor|imul|mul|shl|shr|sar|rol|ror|not|neg|inc|dec|pop|cmov[a-z]+|set[a-z]+|bswap|div|idiv'})"
    rf"\s+({_X86_REG})\s*(?:,|$)",
    re.IGNORECASE,
)

# Registers a call clobbers under the Microsoft x64 and SysV ABIs combined.
# After a call, anything volatile in either convention has to be unknown.
_X86_CALL_CLOBBERED = ("rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11")

# Registers that address the stack frame. A store through one of these is a
# frame slot; a store through any other register goes to a heap or parameter
# object this pass cannot locate, so it is ignored rather than guessed at.
_X86_FRAME_REGISTERS: frozenset[str] = frozenset({"rbp", "rsp"})


class X86_64Model(ArchModel):
    """The x86-64 register model and instruction semantics."""

    frame_bases = _X86_FRAME_REGISTERS
    call_clobbered = _X86_CALL_CLOBBERED

    def register(self, name: str) -> tuple[str, int] | None:
        return _X86_REGISTER_INFO.get(name.strip().lower())

    def write_operand(self, state: FrameState, name: str, value) -> None:
        info = self.register(name)
        if not info:
            return
        family, width = info
        # Writing a sub-register leaves the upper bytes of the family intact,
        # except for the 32-bit forms, which zero-extend on x86-64.
        if width == 8 or width == 4:
            state.registers[family] = value & ((1 << (width * 8)) - 1)
            return
        previous = state.registers.get(family)
        if previous is None or not isinstance(previous, int):
            return
        mask = (1 << (width * 8)) - 1
        state.registers[family] = (previous & ~mask) | (value & mask)

    def write_family(self, state: FrameState, family: str, value, width: int) -> None:
        state.registers[family] = value & ((1 << (width * 8)) - 1)

    def step(self, state: FrameState, text: str) -> None:
        if text.startswith(("call", "jmp")):
            # A call returns a value in rax and destroys the volatile registers;
            # keeping stale values across it is how a reconstruction goes wrong.
            self.clobber_call_registers(state)
            return

        if store := _STORE_RE.match(text):
            self._apply_store(state, *store.groups())
            return

        if match := _MOV_REG_IMM_RE.match(text):
            value = _parse_immediate(match.group(2))
            if value is None:
                state.invalidate(match.group(1))
            else:
                state.write_operand(match.group(1), value)
            return

        if (match := _XOR_SELF_RE.match(text)) and match.group(1).lower() == match.group(
            2
        ).lower():
            state.write_operand(match.group(1), 0)
            return
        # A non-self xor falls through to the invalidating handler below.
        if match := _MOV_REG_REG_RE.match(text):
            source = state.get_register(match.group(2))
            if source is None:
                state.invalidate(match.group(1))
            else:
                state.write_operand(match.group(1), source[0])
            return

        if match := _LEA_RE.match(text):
            self._apply_lea(state, match)
            return

        if match := _ARITH_REG_IMM_RE.match(text):
            self._apply_arith(state, match)
            return

        # Anything else that writes a register makes its value unknown. Being
        # conservative here is what stops a stale value from being decoded as a
        # character it never was.
        if match := _DEST_REG_RE.match(text):
            state.invalidate(match.group(1))

    def _apply_store(
        self,
        state: FrameState,
        size_hint: str | None,
        base_reg: str,
        sign: str,
        offset_token: str,
        value_token: str,
    ) -> None:
        """Apply one `mov [frame +/- offset], value` to the frame state."""
        base_info = self.register(base_reg)
        if not base_info or base_info[0] not in self.frame_bases:
            return
        offset = _parse_immediate(offset_token)
        if offset is None:
            return
        if sign == "-":
            offset = -offset

        immediate = _parse_immediate(value_token)
        if immediate is not None and not self.register(value_token):
            width = _X86_SIZE_HINTS.get((size_hint or "").lower())
            if width is None:
                # Without a size hint the store width is unknowable, and guessing it
                # would shift every following byte of the reconstruction.
                return
            state.store(base_info[0], offset, immediate & ((1 << (width * 8)) - 1), width)
            return

        source = state.get_register(value_token)
        if source is None:
            # The slot is written with something unknown, so any earlier bytes there
            # must be dropped rather than read as part of a string.
            width = _X86_SIZE_HINTS.get((size_hint or "").lower()) or 1
            state.drop(base_info[0], offset, width)
            return
        value, width = source
        # An explicit size hint overrides the register width, which matters for the
        # `mov byte ptr [rbp-8], al` form.
        width = _X86_SIZE_HINTS.get((size_hint or "").lower(), width)
        state.store(base_info[0], offset, value, width)

    def _apply_lea(self, state: FrameState, match: re.Match) -> None:
        """Apply `lea dest, [src +/- imm]`, the folded arithmetic form."""
        dest, source_reg, sign, offset_token = match.groups()
        source_info = self.register(source_reg)
        # `lea rcx, [rbp - 32]` takes the address of the frame slot rather than
        # computing a character, so the destination holds a pointer, not a value.
        if source_info and source_info[0] in self.frame_bases:
            state.invalidate(dest)
            return
        source = state.get_register(source_reg)
        if source is None:
            state.invalidate(dest)
            return
        delta = _parse_immediate(offset_token) if offset_token else 0
        if delta is None:
            state.invalidate(dest)
            return
        if sign == "-":
            delta = -delta
        state.write_operand(dest, (source[0] + delta) & 0xFFFFFFFFFFFFFFFF)

    def _apply_arith(self, state: FrameState, match: re.Match) -> None:
        """Apply an `add`/`sub`/`or`/`and`/`xor` of an immediate into a register."""
        op, register, immediate_token = match.groups()
        current = state.get_register(register)
        immediate = _parse_immediate(immediate_token)
        if current is None or immediate is None:
            state.invalidate(register)
            return
        value, _ = current
        if op.lower() == "add":
            result = value + immediate
        elif op.lower() == "sub":
            result = value - immediate
        elif op.lower() == "or":
            result = value | immediate
        elif op.lower() == "and":
            result = value & immediate
        else:
            result = value ^ immediate
        state.write_operand(register, result & 0xFFFFFFFFFFFFFFFF)


# -- ARM64 --------------------------------------------------------------------

# Frame bases whose stores land in a recoverable frame slot. x29 is the frame
# pointer (`fp` in some listings); everything else is a pointer this pass
# cannot locate. Registers derived from these bases (``add x8, sp, #8``)
# inherit the base symbolically.
ARM64_FRAME_BASES = frozenset({"sp", "x29", "fp"})

# Caller-saved registers under the AAPCS64 ABI. After a call their values are
# unknown; x19-x28 (callee-saved), x29 (fp), x30 (lr) and sp survive.
ARM64_CALL_CLOBBERED = tuple(
    sorted({f"x{i}" for i in range(19)} | {f"w{i}" for i in range(19)})
)

_ARM64_REG = r"[wx]\d+|xzr|wzr|sp|fp|lr"

_ARM64_MOV_IMM_RE = re.compile(
    rf"^\s*mov\s+({_ARM64_REG})\s*,\s*({_IMM})\s*$", re.IGNORECASE
)
_ARM64_MOVZ_RE = re.compile(
    rf"^\s*movz\s+({_ARM64_REG})\s*,\s*({_IMM})(?:\s*,\s*(?:lsl|LSL)\s*#?(\d+))?\s*$",
    re.IGNORECASE,
)
_ARM64_MOVK_RE = re.compile(
    rf"^\s*movk\s+({_ARM64_REG})\s*,\s*({_IMM})(?:\s*,\s*(?:lsl|LSL)\s*#?(\d+))?\s*$",
    re.IGNORECASE,
)
_ARM64_MOV_REG_RE = re.compile(
    rf"^\s*mov\s+({_ARM64_REG})\s*,\s*({_ARM64_REG})\s*$", re.IGNORECASE
)
_ARM64_ARITH_IMM_RE = re.compile(
    rf"^\s*(add|sub)\s+({_ARM64_REG})\s*,\s*({_ARM64_REG})\s*,\s*({_IMM})\s*$",
    re.IGNORECASE,
)
_ARM64_STR_RE = re.compile(
    rf"^\s*(stur[bh]?|str[bh]?|stp)\s+({_ARM64_REG})(?:\s*,\s*({_ARM64_REG}))?\s*,\s*"
    rf"\[\s*({_ARM64_REG})\s*(?:,\s*({_IMM})\s*)?\](!?)\s*(?:,\s*({_IMM}))?\s*$",
    re.IGNORECASE,
)

# Any other instruction whose first operand is a register kills the known
# value it held. Keeping this strict is what prevents stale values from being
# decoded as characters they never were.
_ARM64_DEST_REG_RE = re.compile(
    rf"^\s*[a-z][a-z0-9.]*\s+({_ARM64_REG})\s*(?:,|$)", re.IGNORECASE
)

_ARM64_STORE_WIDTHS = {
    "strb": 1, "sturb": 1,
    "strh": 2, "sturh": 2,
    "str": None, "stur": None,  # width comes from the register
    "stp": None,
}


def _arm64_register_family(name: str) -> tuple[str, int] | None:
    """Map an ARM64 register name to its (family, width); None for untracked regs."""
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


class Arm64Model(ArchModel):
    """The AArch64 register model and instruction semantics."""

    frame_bases = ARM64_FRAME_BASES
    call_clobbered = ARM64_CALL_CLOBBERED

    def register(self, name: str) -> tuple[str, int] | None:
        return _arm64_register_family(name)

    def is_zero_register(self, family: str) -> bool:
        return family == "xzr"

    def write_operand(self, state: FrameState, name: str, value) -> None:
        info = self.register(name)
        if info:
            self.write_family(state, info[0], value, info[1])

    def write_family(self, state: FrameState, family: str, value, width: int) -> None:
        if width >= 8:
            state.registers[family] = value
            return
        # 32-bit writes zero-extend the upper half of the 64-bit register and
        # cannot carry a symbolic pointer.
        state.registers[family] = value & 0xFFFFFFFF if isinstance(value, int) else value

    def resolve_base(self, state: FrameState, base_reg: str) -> tuple[str, int] | None:
        """Resolve a store's base operand to a (frame base, offset) pair.

        ``sp`` resolves with the running adjustment applied; ``x29``/``fp``
        resolve as themselves; a register holding a derived ``("sp", off)``
        tuple resolves to that slot. Anything else returns None — the store
        is through a pointer this pass cannot locate.
        """
        info = self.register(base_reg)
        if not info:
            return None
        family = info[0]
        if family == "sp":
            return None if state.sp_adjustment is None else ("sp", state.sp_adjustment)
        if family in ("x29", "fp"):
            return "x29", 0
        value = state.registers.get(family)
        if isinstance(value, tuple) and value[0] == "sp":
            return "sp", value[1]
        return None

    def step(self, state: FrameState, text: str) -> None:
        lowered = text.split(None, 1)[0].lower() if text else ""
        if lowered in ("bl", "blr", "blraa", "blrab"):
            self.clobber_call_registers(state)
            return
        if lowered.startswith("b.") or lowered in (
            "b", "br", "ret", "brk", "cbz", "cbnz", "tbz", "tbnz"
        ):
            # Pure control flow writes nothing.
            return

        if match := _ARM64_STR_RE.match(text):
            self._apply_store(state, match)
            return

        if match := _ARM64_MOVZ_RE.match(text):
            value = _parse_immediate(match.group(2))
            shift = int(match.group(3) or 0)
            if value is None:
                state.invalidate(match.group(1))
            else:
                info = self.register(match.group(1))
                if info:
                    # movz defines the whole register regardless of the w/x form.
                    state.write_family(info[0], value << shift, 8)
            return

        if match := _ARM64_MOVK_RE.match(text):
            value = _parse_immediate(match.group(2))
            shift = int(match.group(3) or 0)
            info = self.register(match.group(1))
            if info is None or value is None:
                state.invalidate(match.group(1))
                return
            current = state.registers.get(info[0])
            if current is None or not isinstance(current, int):
                # movk on a symbolic pointer or an unknown value stays unknown.
                return
            lane = 0xFFFF << shift
            state.write_family(
                info[0], (current & ~lane & 0xFFFFFFFFFFFFFFFF) | ((value << shift) & lane), 8
            )
            return

        if match := _ARM64_MOV_IMM_RE.match(text):
            value = _parse_immediate(match.group(2))
            if value is None:
                state.invalidate(match.group(1))
            else:
                info = self.register(match.group(1))
                if info:
                    state.write_family(info[0], value, info[1])
            return

        if match := _ARM64_MOV_REG_RE.match(text):
            source = state.get_register(match.group(2))
            if source is None:
                state.invalidate(match.group(1))
            else:
                info = self.register(match.group(1))
                if info:
                    state.write_family(info[0], source[0], info[1])
            return

        if match := _ARM64_ARITH_IMM_RE.match(text):
            self._apply_arith(state, match)
            return

        # adrp computes a page address (nyxstone renders the page
        # displacement). Stores through it are not frame slots, so the
        # register is tracked as a non-frame symbolic pointer: it is no longer
        # an integer, and `add xN, xN, #imm` keeps it symbolic instead of
        # producing a bogus value.
        if lowered == "adrp":
            dest = text.split(None, 1)[1].split(",")[0].strip() if len(text.split(None, 1)) > 1 else ""
            if self.register(dest):
                state.write_family(self.register(dest)[0], ("adrp", 0), 8)
            return

        # Anything else writing its first-operand register invalidates it.
        if match := _ARM64_DEST_REG_RE.match(text):
            state.invalidate(match.group(1))

    def _apply_store(self, state: FrameState, match: re.Match) -> None:
        """Apply one str/stur/stp to the frame state."""
        opcode, reg_a, reg_b, base, offset_token, pre_index, post_token = match.groups()
        offset = _parse_immediate(offset_token) if offset_token else 0
        if offset is None:
            return

        resolved = self.resolve_base(state, base)
        if resolved is None:
            return
        frame_base, base_adjustment = resolved
        # Pre-index ([base, #imm]!) folds the offset into the base before the
        # store; post-index ([base], #imm) stores at the base and moves it after.
        effective_offset = offset + base_adjustment
        if pre_index and base.strip().lower() == "sp" and state.sp_adjustment is not None:
            state.sp_adjustment += offset
        if post_token and state.sp_adjustment is not None:
            state.sp_adjustment += _parse_immediate(post_token) or 0

        source_a = state.get_register(reg_a)
        if opcode.lower() == "stp":
            # Store pair: both registers land side by side.
            info_a = self.register(reg_a)
            width_a = (
                source_a[1] if source_a and isinstance(source_a[0], int) else (info_a or (None, 8))[1]
            ) or 8
            if source_a is not None and isinstance(source_a[0], int):
                state.store(frame_base, effective_offset, source_a[0], width_a)
            else:
                state.drop(frame_base, effective_offset, width_a)
            if reg_b:
                source_b = state.get_register(reg_b)
                width_b = (
                    source_b[1]
                    if source_b and isinstance(source_b[0], int)
                    else (self.register(reg_b) or (None, 8))[1]
                )
                if source_b is not None and isinstance(source_b[0], int):
                    state.store(frame_base, effective_offset + width_a, source_b[0], width_b)
                else:
                    state.drop(frame_base, effective_offset + width_a, width_b or 1)
            return
        width = _ARM64_STORE_WIDTHS.get(opcode.lower())
        if width is None:
            width = (
                source_a[1]
                if source_a and isinstance(source_a[0], int)
                else (self.register(reg_a) or (None, 8))[1]
            )
        if source_a is None or not isinstance(source_a[0], int):
            state.drop(frame_base, effective_offset, width)
            return
        state.store(frame_base, effective_offset, source_a[0], width)

    def _apply_arith(self, state: FrameState, match: re.Match) -> None:
        """Apply an add/sub of an immediate into a register.

        Arithmetic with ``sp`` as the source (``add x8, sp, #8``) derives a
        frame pointer: the destination names a slot relative to the initial
        stack pointer. Arithmetic on a derived frame pointer
        (``add x8, x8, #4``) moves the derived slot, and ``add/sub sp, sp,
        #imm`` is the prologue's frame adjustment.
        """
        op, dest, source_reg, immediate_token = match.groups()
        source = state.get_register(source_reg)
        immediate = _parse_immediate(immediate_token)
        info = self.register(dest)
        if not info:
            return
        source_info = self.register(source_reg)
        if source_info and source_info[0] == "sp" and source is None:
            # sp lives in the running adjustment, not in `registers`.
            if state.sp_adjustment is None:
                state.invalidate(dest)
                return
            source = (("sp", state.sp_adjustment), 8)
        if source is not None and isinstance(source[0], tuple):
            base_kind, base_offset = source[0]
            if immediate is None:
                state.invalidate(dest)
                return
            delta = immediate if op.lower() == "add" else -immediate
            state.write_family(info[0], (base_kind, base_offset + delta), 8)
            return
        if info[0] == "sp":
            # `add sp, sp, #imm` / `sub sp, sp, #imm` move the frame base.
            if immediate is not None and state.sp_adjustment is not None:
                state.sp_adjustment += immediate if op.lower() == "add" else -immediate
            return
        if source is None or immediate is None:
            state.invalidate(dest)
            return
        value = source[0] + immediate if op.lower() == "add" else source[0] - immediate
        state.write_family(info[0], value, info[1])


X86_64_MODEL = X86_64Model()
ARM64_MODEL = Arm64Model()


# ---------------------------------------------------------------------------
# Traversals: the shared straight-line pass and the CFG dataflow.
# ---------------------------------------------------------------------------


def interpret(lines: list[str], model: ArchModel) -> FrameState:
    """Run the straight-line forward pass over one function's assembly lines."""
    state = FrameState(model)
    for line in lines[:MAX_INSTRUCTIONS]:
        text = line.strip()
        if not text:
            continue
        model.step(state, text)
    return state


def _block_line_spans(blocks: list[dict]) -> list[tuple[int, int]] | None:
    """Map each CFG block to its [start, end) slice of the assembly lines.

    Returns None unless the blocks tile the text exactly: cumulative
    instruction counts must add up to the line count with no holes or
    overlaps. A mismatch means the CFG and the listing describe different
    functions, and falling back silently would hide exactly that bug.
    """
    spans: list[tuple[int, int]] = []
    cursor = 0
    for block in blocks:
        count = block.get("instructions")
        if not isinstance(count, int) or count <= 0:
            return None
        spans.append((cursor, cursor + count))
        cursor += count
    return spans


def interpret_over_cfg(
    lines: list[str],
    model: ArchModel,
    blocks: list[dict],
    edges: list[dict],
) -> FrameState | None:
    """Iterate the function's blocks to a fixed point; None when the cap is hit.

    The worklist starts at block 0 and follows the CFG's edges, so
    unreachable blocks never contribute values. A block's in-state is the
    join of its visited predecessors' out-states (a copy of the first, then
    narrowed by the rest — the join's identity is the unconstrained state,
    not the empty one); when out-states stop changing the pass has reached
    its fixed point. Blocks are limited to ``MAX_BLOCK_VISITS`` visits —
    loop-carried values meet at conflicts and go unknown long before that,
    so the cap only fires on pathological inputs, and returning None
    (rather than a half-converged state) keeps such a function's residue
    out of the output.

    The state returned is the join over the reachable exit blocks'
    out-states: the frame picture every path out of the function agrees on.
    """
    spans = _block_line_spans(blocks)
    if spans is None:
        raise ValueError("CFG blocks do not tile the assembly text")
    block_count = len(blocks)
    successors: list[list[int]] = [[] for _ in range(block_count)]
    for edge in edges:
        src, dst = edge.get("src"), edge.get("dst")
        if (
            isinstance(src, int)
            and isinstance(dst, int)
            and 0 <= dst < block_count
            and dst not in successors[src]
        ):
            successors[src].append(dst)
    for block_index in range(block_count):
        successors[block_index].sort()
    predecessors: list[list[int]] = [[] for _ in range(block_count)]
    for src, dsts in enumerate(successors):
        for dst in dsts:
            predecessors[dst].append(src)

    out_states: list[FrameState | None] = [None] * block_count
    visits = [0] * block_count
    worklist = [0]
    while worklist:
        index = worklist.pop()
        visits[index] += 1
        if visits[index] > MAX_BLOCK_VISITS:
            return None
        state = None
        for pred in predecessors[index]:
            pred_out = out_states[pred]
            if pred_out is None:
                continue
            if state is None:
                state = FrameState(model)
                state.registers = dict(pred_out.registers)
                state.slots = dict(pred_out.slots)
                state.sp_adjustment = pred_out.sp_adjustment
            else:
                state.joined_with(pred_out)
        if state is None:
            # Block 0 with no visited predecessor: the function entry state.
            # Any other block queued here is retried when a predecessor lands.
            if index != 0:
                visits[index] -= 1
                continue
            state = FrameState(model)
        start, end = spans[index]
        for line in lines[start:end]:
            model.step(state, line.strip())
        previous = out_states[index]
        if (
            previous is None
            or previous.registers != state.registers
            or previous.slots != state.slots
            or previous.sp_adjustment != state.sp_adjustment
        ):
            out_states[index] = state
            for successor in successors[index]:
                if successor not in worklist:
                    worklist.append(successor)

    # Exits: blocks with no successors (ret/trap/unresolved jumps), plus the
    # final block in address order when every block has a successor (a loop
    # back to the top leaves the function only through calls or traps).
    exits = [i for i in range(block_count) if out_states[i] is not None and not successors[i]]
    if not exits:
        exits = [block_count - 1]
    result: FrameState | None = None
    for index in exits:
        exit_state = out_states[index]
        if exit_state is None:
            continue
        if result is None:
            result = FrameState(model)
            result.registers = dict(exit_state.registers)
            result.slots = dict(exit_state.slots)
            result.sp_adjustment = exit_state.sp_adjustment
        else:
            result.joined_with(exit_state)
    return result


def model_for_target(arch_target: str) -> ArchModel:
    """Pick the architecture model for an LLVM triple or Mach-O cpu name."""
    lowered = (arch_target or "").lower()
    if "aarch64" in lowered or "arm64" in lowered:
        return ARM64_MODEL
    return X86_64_MODEL


# ---------------------------------------------------------------------------
# Recovery entry points.
# ---------------------------------------------------------------------------


def interpret_arm64(lines: list[str]) -> FrameState:
    """Run the ARM64 straight-line pass over one function's assembly lines."""
    return interpret(lines, ARM64_MODEL)


def recover_arm64_stack_strings(assembly: str) -> list[dict]:
    """Recover string literals one ARM64 function builds on its stack.

    Produces the same entry shape as the x86-64 pass so callers can consume
    both without special cases.
    """
    if not assembly:
        return []
    state = interpret_arm64(assembly.split("\n"))
    return _decode_runs(iter_frame_runs(state))


def recover_function_stack_strings_with_method(
    func_data: dict, arch_target: str = ""
) -> tuple[list[dict], str]:
    """Recover one function's stack-built strings, preferring the CFG dataflow.

    Returns ``(entries, method)`` where method names how the function was
    analyzed: ``"dataflow"`` (CFG fixed point), ``"fallback"`` (no usable
    CFG — straight-line pass), ``"cap_hit"`` (iteration cap reached; no
    entries, because a half-converged state is exactly the residue this
    pass exists to remove) or ``"skipped"`` (nothing to analyze).
    """
    assembly = func_data.get("assembly") or ""
    if not assembly:
        return [], "skipped"
    lines = assembly.split("\n")
    model = model_for_target(arch_target)
    cfg = func_data.get("cfg") or {}
    blocks = cfg.get("blocks") or []
    edges = cfg.get("edges") or []
    spans = _block_line_spans(blocks) if blocks else None
    blank_lines = any(not line.strip() for line in lines)
    # The dataflow maps block instruction counts onto line positions, so it
    # needs the CFG to tile the text exactly and no blank lines shifting the
    # correspondence. A mismatch means the CFG and the listing describe
    # different functions; falling back silently would hide exactly that bug.
    tiles = spans is not None and spans[-1][1] == len(lines) and not blank_lines
    if tiles and len(lines) <= MAX_INSTRUCTIONS:
        try:
            state = interpret_over_cfg(lines, model, blocks, edges)
        except ValueError:
            LOG.warning(
                "stack strings: CFG blocks do not tile the assembly text for %s;"
                " falling back to the straight-line pass",
                func_data.get("name") or func_data.get("address") or "<unnamed>",
            )
            return _recover_straight_line(lines, model), "fallback"
        if state is None:
            return [], "cap_hit"
        return _decode_runs(iter_frame_runs(state)), "dataflow"
    if blocks and spans is not None and (spans[-1][1] != len(lines) or blank_lines):
        LOG.warning(
            "stack strings: CFG blocks do not tile the %d-line assembly text for %s;"
            " falling back to the straight-line pass",
            len(lines),
            func_data.get("name") or func_data.get("address") or "<unnamed>",
        )
    return _recover_straight_line(lines, model), "fallback"


def recover_function_stack_strings(func_data: dict, arch_target: str = "") -> list[dict]:
    """Recover string literals a single disassembled function builds on its stack.

    The x86-64 and ARM64 dialects are served by the same abstract interpreter
    in this module; functions carrying a usable CFG are analyzed as a
    fixed-point dataflow over its blocks, the rest by the straight-line pass.
    """
    return recover_function_stack_strings_with_method(func_data, arch_target)[0]


def _recover_straight_line(lines: list[str], model: ArchModel) -> list[dict]:
    return _decode_runs(iter_frame_runs(interpret(lines, model)))
