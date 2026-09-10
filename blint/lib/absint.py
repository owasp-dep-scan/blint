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
blocks never enter the worklist and contribute nothing, so residue after a
``ret`` or behind an indirect branch stays excluded. Blocks that follow an
indirect branch have no incoming edge in the CFG (an indirect transfer can
land anywhere), so they are unreachable to this pass as well.

What is *reported* is the set of strings fully assembled in any reachable
block's state (``harvest_strings_over_cfg``): evidence of construction. A
buffer a function builds on one path and reuses for something else on
another makes the slot unknown from the merge onward, but the block that
completed the string still holds it, and a later reuse cannot un-construct
what was built — which is exactly the case an exit-aggregated picture (or
the straight-line pass's last-write-wins scan) loses. Values that conflict
at a merge go unknown and never complete a run downstream of the conflict,
so the convergence, not the decode filters, is what keeps loop-carried and
path-dependent garbage out.

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

The same converged dataflow also powers call-site constant-argument
recovery (``recover_call_site_arguments``): a second, replay pass over the
fixed point snapshots the integer argument registers just before every
call instruction, so an argument assembled on one arm of a conditional —
or after the call, or in a register no argument position reads — is never
reported as reaching the call. Which registers hold arguments is a
property of the binary's ABI (format plus architecture), resolved by
``argument_registers``; there is no straight-line fallback for this
recovery, because a fallback would resurface exactly those leaked values.
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

    def call_kind(self, mnemonic: str) -> str | None:  # pragma: no cover - interface
        """Classify a mnemonic as a call ('call'), a tail transfer ('tail') or None.

        'call' means the mnemonic always transfers control to a callee (x86
        ``call``, ARM64 ``bl``/``blr``); 'tail' means the mnemonic is an
        ordinary branch that only becomes a call when its resolved target
        leaves the function, which the disassembler annotates only for the
        function's final instruction. Callers must not treat a 'tail' line
        as a call site without that annotation.
        """
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

    def call_kind(self, mnemonic: str) -> str | None:
        lowered = mnemonic.strip().lower()
        if lowered.startswith("call"):
            return "call"
        if lowered in ("jmp", "jmpq"):
            return "tail"
        return None

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

    def call_kind(self, mnemonic: str) -> str | None:
        lowered = mnemonic.strip().lower()
        if lowered in ("bl", "blr", "blraa", "blrab"):
            return "call"
        if lowered in ("b", "br"):
            return "tail"
        return None

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


def _block_line_spans(blocks: list[dict], lines: list[str]) -> list[tuple[int, int]] | None:
    """Map each CFG block to its [start, end) slice of the assembly lines.

    Returns None unless the blocks tile the text exactly: every block must
    carry a positive instruction count, the counts must add up to the line
    count, and no line may be blank (a blank line shifts every following
    block's correspondence). A mismatch means the CFG and the listing
    describe different functions, and analyzing one against the other would
    attribute instructions to blocks they do not belong to.
    """
    if not blocks:
        return None
    spans: list[tuple[int, int]] = []
    cursor = 0
    for block in blocks:
        count = block.get("instructions")
        if not isinstance(count, int) or count <= 0:
            return None
        spans.append((cursor, cursor + count))
        cursor += count
    if cursor != len(lines) or any(not line.strip() for line in lines):
        return None
    return spans


def _cfg_spans_and_graph(
    lines: list[str], blocks: list[dict], edges: list[dict]
) -> tuple[list[tuple[int, int]], list[list[int]], list[list[int]]]:
    """Return (block→line spans, successors, predecessors) for one function.

    Raises ValueError unless the blocks tile the text exactly: a mismatch
    means the CFG and the listing describe different functions, and analyzing
    one against the other would attribute instructions to blocks they do not
    belong to. Every edge endpoint is range-checked: an out-of-range ``src``
    would index another block's successor list (or raise), silently rewiring
    the graph the pass reasons over.
    """
    spans = _block_line_spans(blocks, lines)
    if spans is None:
        raise ValueError("CFG blocks do not tile the assembly text")
    block_count = len(blocks)
    successors: list[list[int]] = [[] for _ in range(block_count)]
    for edge in edges:
        src, dst = edge.get("src"), edge.get("dst")
        if (
            isinstance(src, int)
            and isinstance(dst, int)
            and 0 <= src < block_count
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
    return spans, successors, predecessors


def _block_in_state(
    model: ArchModel,
    block_index: int,
    predecessors: list[list[int]],
    out_states: list[FrameState | None],
) -> FrameState | None:
    """Join the visited predecessors' out-states into one block's in-state.

    Block 0 always joins the function entry state, which knows nothing, in
    with its predecessors: control reaches the entry block along the entry
    path as well as along any back edge, so a value the loop body writes is
    not established on the first iteration and must not survive the join. A
    non-entry block whose predecessors have not produced an out-state yet
    returns None and is retried later by the worklist.
    """
    state: FrameState | None = FrameState(model) if block_index == 0 else None
    for pred in predecessors[block_index]:
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
    return state


def _converge_over_cfg(
    lines: list[str],
    model: ArchModel,
    blocks: list[dict],
    edges: list[dict],
) -> tuple[
    list[tuple[int, int]], list[list[int]], list[list[int]], list[FrameState | None]
] | None:
    """Iterate the function's blocks to a fixed point over the CFG.

    The worklist starts at block 0 and follows the CFG's edges, so
    unreachable blocks never contribute values. A block's in-state is the
    join of its visited predecessors' out-states (the join's identity is the
    unconstrained state, not the empty one); when out-states stop changing
    the pass has reached its fixed point. Blocks are limited to
    ``MAX_BLOCK_VISITS`` visits — loop-carried values meet at conflicts and
    go unknown long before that, so the cap only fires on pathological
    inputs, and returning None (rather than a half-converged state) keeps
    such a function's residue out of every result built on this pass.

    Returns the block→line spans, the successor and predecessor lists and
    the final out-state per block (None for blocks never reached), or None
    when the iteration cap was hit. Raises ValueError when the blocks do not
    tile the assembly text.
    """
    spans, successors, predecessors = _cfg_spans_and_graph(lines, blocks, edges)
    block_count = len(blocks)
    out_states: list[FrameState | None] = [None] * block_count
    visits = [0] * block_count
    worklist = [0]
    while worklist:
        index = worklist.pop()
        visits[index] += 1
        if visits[index] > MAX_BLOCK_VISITS:
            return None
        state = _block_in_state(model, index, predecessors, out_states)
        if state is None:
            # A non-entry block queued before any predecessor ran: retried
            # when one lands.
            visits[index] -= 1
            continue
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
    return spans, successors, predecessors, out_states


def interpret_over_cfg(
    lines: list[str],
    model: ArchModel,
    blocks: list[dict],
    edges: list[dict],
) -> FrameState | None:
    """Iterate the function's blocks to a fixed point; None when the cap is hit.

    The state returned is the join over the reachable exit blocks'
    out-states: what holds at every way out of the function. That is the
    right aggregate for a caller that needs a value guaranteed to hold at
    exit, and the wrong one for construction evidence — a string rebuilt for
    a second purpose on another path is gone from every exit's state, so
    string recovery uses :func:`harvest_strings_over_cfg` instead.

    Blocks with no successor (ret/trap/unresolved jumps) are the exits; when
    every block has one - a loop back to the top that leaves the function
    only through a call or a trap - the join runs over every visited block
    instead, which keeps only what holds everywhere in the function.

    Raises ValueError when the blocks do not tile the assembly text; callers
    are expected to check that first and pick their own fallback.
    """
    converged = _converge_over_cfg(lines, model, blocks, edges)
    if converged is None:
        return None
    _, successors, _, out_states = converged
    exits = [i for i in range(len(blocks)) if out_states[i] is not None and not successors[i]]
    if not exits:
        exits = [i for i in range(len(blocks)) if out_states[i] is not None]
    result: FrameState | None = None
    for index in exits:
        exit_state = out_states[index]
        if result is None:
            result = FrameState(model)
            result.registers = dict(exit_state.registers)
            result.slots = dict(exit_state.slots)
            result.sp_adjustment = exit_state.sp_adjustment
        else:
            result.joined_with(exit_state)
    # Reaching here means the pass converged, so an absent result is a
    # function nothing was learned about, not a cap hit. Those are two
    # different outcomes to the caller, so this returns an empty state.
    return result if result is not None else FrameState(model)


def harvest_strings_over_cfg(
    lines: list[str],
    model: ArchModel,
    blocks: list[dict],
    edges: list[dict],
) -> list[dict] | None:
    """Recover the strings a function constructs at any reachable program point.

    Runs the same converged dataflow as :func:`interpret_over_cfg`, but reads
    the result out of every reachable block's out-state instead of one
    exit-aggregated picture. A string a function assembles on one path is
    evidence of construction even when a later merge sees the slot reused for
    something else on another path: the reuse makes the slot unknown from the
    merge onward, so an exit-aggregated reading loses the earlier
    construction, while the block whose state completed it still holds it.
    Unreachable blocks have no out-state and contribute nothing, and values
    conflicting at a merge go unknown exactly as before, so nothing downstream
    of a conflict can complete a run. The same run reported from several
    blocks' states is kept once.

    Returns None when the iteration cap was hit. Raises ValueError when the
    blocks do not tile the assembly text.
    """
    converged = _converge_over_cfg(lines, model, blocks, edges)
    if converged is None:
        return None
    _, _, _, out_states = converged
    recovered: list[dict] = []
    seen: set[str] = set()
    for state in out_states:
        if state is None:
            continue
        for run in _decode_runs(iter_frame_runs(state)):
            key = run["value"].lower()
            if key in seen:
                continue
            seen.add(key)
            recovered.append(run)
            if len(recovered) >= MAX_RUNS_PER_FUNCTION:
                return recovered
    return recovered


# ---------------------------------------------------------------------------
# Call-site constant-argument recovery.
# ---------------------------------------------------------------------------

# Integer argument registers per calling convention, named by the register
# *family* the FrameState keys them under. The convention is a property of
# the binary format plus the architecture, not of the architecture alone:
# see argument_registers.
X86_WIN64_ARGUMENT_REGISTERS = ("rcx", "rdx", "r8", "r9")
X86_SYSV_ARGUMENT_REGISTERS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
ARM64_ARGUMENT_REGISTERS = tuple(f"x{i}" for i in range(8))


def argument_registers(binary_format: str, arch_target: str) -> tuple[str, ...] | None:
    """Integer argument register families for the ABI a binary was built for.

    x86-64 Windows images pass integer arguments in rcx/rdx/r8/r9 (Microsoft
    x64) while ELF and Mach-O images for the same processor use
    rdi/rsi/rdx/rcx/r8/r9 (SysV, whose integer argument registers Apple's
    ABI also shares). AArch64 uses x0-x7 under every mainstream OS ABI. The
    architecture resolution mirrors model_for_target, so the argument
    families always match the model that would decode the function: an
    empty triple means x86-64 there, and it means x86-64 here. Any other
    combination whose convention cannot be determined returns None rather
    than silently assuming one; callers must treat None as "call-site
    arguments are not recoverable", never fall back to a default.
    """
    lowered = (arch_target or "").lower()
    if "aarch64" in lowered or "arm64" in lowered:
        return ARM64_ARGUMENT_REGISTERS
    if not lowered or any(
        marker in lowered for marker in ("x86_64", "x86-64", "amd64", "x64")
    ):
        fmt = (binary_format or "").lower()
        if "pe" in fmt:
            return X86_WIN64_ARGUMENT_REGISTERS
        if "elf" in fmt or "macho" in fmt:
            return X86_SYSV_ARGUMENT_REGISTERS
    return None


def _callee_resolvers(
    direct_call_targets: list[dict] | None,
) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """Index the disassembler's resolved call targets by their operand text.

    Returns two maps, (call-site operands, tail-transfer operands), keyed by
    the normalized operand text of the call instruction (the assembly line
    minus its mnemonic) and holding the set of callee names that operand
    resolved to. A key resolving to more than one name (the same register or
    slot text reaching different callees at different program points) keeps
    both names, and resolution refuses it: an unresolved callee is a
    legitimate result, a wrong one is not.
    """
    call_operands: dict[str, set[str]] = {}
    tail_operands: dict[str, set[str]] = {}
    for entry in direct_call_targets or []:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("target_name") or "").strip()
        operand = " ".join(str(entry.get("raw_operand") or "").split()).lower()
        if not name or not operand:
            continue
        # A name that is just the operand echoed back (the disassembler's
        # stand-in for an unresolved numeric target) carries no resolution.
        if " ".join(name.split()).lower() == operand:
            continue
        table = tail_operands if entry.get("kind") == "tailcall" else call_operands
        table.setdefault(operand, set()).add(name)
    return call_operands, tail_operands


def _call_site_callee(
    model: ArchModel,
    text: str,
    call_operands: dict[str, set[str]],
    tail_operands: dict[str, set[str]],
    is_last_line: bool,
) -> str | None:
    """Resolve one instruction's callee name from the disassembler's targets.

    Only instruction text the disassembler itself annotated is trusted: an
    operand that no target entry resolves to yields None (the callee is
    genuinely unknown), and the tail-branch forms (``jmp``/``b``/``br``)
    resolve only on the function's last line, which is the only place the
    disassembler annotates them — elsewhere they are ordinary branches and
    must not inherit a callee by operand coincidence.
    """
    parts = text.split(None, 1)
    if len(parts) < 2:
        return None
    kind = model.call_kind(parts[0])
    if kind is None:
        return None
    if kind == "tail" and not is_last_line:
        return None
    key = " ".join(parts[1].split()).lower()
    names = (tail_operands if kind == "tail" else call_operands).get(key)
    if names and len(names) == 1:
        return next(iter(names))
    return None


def _call_site_records(
    lines: list[str],
    model: ArchModel,
    spans: list[tuple[int, int]],
    predecessors: list[list[int]],
    out_states: list[FrameState | None],
    arg_families: tuple[str, ...],
    direct_call_targets: list[dict] | None,
) -> list[dict]:
    """Snapshot the argument registers at every call instruction.

    One replay pass over the converged out-states: each block is re-walked
    once from its final in-state (the same join the worklist computed), and
    a record is taken just before a call instruction is stepped — the model
    clobbers the argument registers at the call itself, so this is the only
    point the incoming arguments are observable. Only integer constants are
    reported; a symbolic pointer or an unknown value yields None for that
    position, never a stale value from before the call sequence.

    The replay is O(lines) time and holds one FrameState at a time; the
    records are O(call sites) small dicts, which is the only extra memory
    retained.
    """
    call_operands, tail_operands = _callee_resolvers(direct_call_targets)
    last_line = len(lines) - 1
    records: list[dict] = []
    for block_index, (start, end) in enumerate(spans):
        if out_states[block_index] is None:
            continue  # unreachable to the dataflow: contributes nothing
        state = _block_in_state(model, block_index, predecessors, out_states)
        if state is None:
            continue
        for offset, line in enumerate(lines[start:end]):
            text = line.strip()
            if not text:
                continue
            kind = model.call_kind(text.split(None, 1)[0])
            # A tail branch is a call site only on the function's last line,
            # the only place the disassembler annotates it; elsewhere it is
            # an ordinary branch and must not be recorded at all.
            if kind is not None and (kind == "call" or start + offset == last_line):
                callee = _call_site_callee(
                    model, text, call_operands, tail_operands, start + offset == last_line
                )
                arguments = []
                for family in arg_families:
                    value = state.registers.get(family)
                    arguments.append(value if isinstance(value, int) else None)
                records.append(
                    {
                        "line": start + offset,
                        "instruction": text,
                        "callee": callee,
                        "registers": tuple(arg_families),
                        "arguments": arguments,
                    }
                )
            model.step(state, text)
    return records


def recover_call_site_arguments_with_method(
    func_data: dict, arch_target: str = "", binary_format: str = ""
) -> tuple[list[dict], str]:
    """Recover one function's call-site constant arguments via the CFG dataflow.

    Returns ``(records, method)``. Each record names one call instruction
    (``line`` index into the assembly text, ``instruction`` text), the
    ``callee`` the disassembler resolved it to (None when unresolved), the
    ABI's ``registers`` tuple and the integer constants in ``arguments`` at
    that point (None where the model does not know one). ``method`` names
    how the function was analyzed: ``"dataflow"`` (CFG fixed point),
    ``"no_cfg"`` / ``"cfg_mismatch"`` (no CFG, or one that does not tile the
    text — there is deliberately no straight-line fallback, which would
    report values that leak from not-taken paths), ``"cap_hit"`` (iteration
    cap; no records), ``"no_abi"`` (argument registers undeterminable for
    this format/architecture) or ``"skipped"`` (nothing to analyze, or past
    the instruction budget).
    """
    assembly = func_data.get("assembly") or ""
    if not assembly:
        return [], "skipped"
    arg_families = argument_registers(binary_format, arch_target)
    if not arg_families:
        return [], "no_abi"
    lines = assembly.split("\n")
    if len(lines) > MAX_INSTRUCTIONS:
        return [], "skipped"
    model = model_for_target(arch_target)
    cfg = func_data.get("cfg") or {}
    blocks = cfg.get("blocks") or []
    edges = cfg.get("edges") or []
    if not blocks:
        return [], "no_cfg"
    if _block_line_spans(blocks, lines) is None:
        return [], "cfg_mismatch"
    converged = _converge_over_cfg(lines, model, blocks, edges)
    if converged is None:
        return [], "cap_hit"
    spans, _, predecessors, out_states = converged
    records = _call_site_records(
        lines, model, spans, predecessors, out_states, arg_families,
        func_data.get("direct_call_targets"),
    )
    return records, "dataflow"


def recover_call_site_arguments(
    func_data: dict, arch_target: str = "", binary_format: str = ""
) -> list[dict]:
    """Recover one function's call-site constant arguments (see _with_method)."""
    return recover_call_site_arguments_with_method(func_data, arch_target, binary_format)[0]


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
    analyzed: ``"dataflow"`` (CFG fixed point, harvested from every reachable
    block's state — see :func:`harvest_strings_over_cfg`), ``"fallback"``
    (no usable CFG, or one past the instruction budget — straight-line pass),
    ``"cap_hit"`` (iteration cap reached; no entries, because a
    half-converged state is exactly the residue this pass exists to remove)
    or ``"skipped"`` (nothing to analyze).
    """
    assembly = func_data.get("assembly") or ""
    if not assembly:
        return [], "skipped"
    lines = assembly.split("\n")
    model = model_for_target(arch_target)
    cfg = func_data.get("cfg") or {}
    blocks = cfg.get("blocks") or []
    edges = cfg.get("edges") or []
    # The dataflow maps block instruction counts onto line positions, so it
    # needs the CFG to tile the text exactly. A mismatch means the CFG and
    # the listing describe different functions; falling back silently would
    # hide exactly that bug, so it warns.
    tiles = _block_line_spans(blocks, lines) is not None
    if tiles and len(lines) <= MAX_INSTRUCTIONS:
        runs = harvest_strings_over_cfg(lines, model, blocks, edges)
        if runs is None:
            return [], "cap_hit"
        return runs, "dataflow"
    if blocks and not tiles:
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
