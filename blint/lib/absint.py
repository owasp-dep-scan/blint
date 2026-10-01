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
``MAX_BLOCK_VISITS`` times. Values that conflict at a merge go unknown
within a few rounds, but each out-state change propagates along every
intra-function branch edge, so long functions converge through many revisit
waves before the fixed point; the cap is a backstop for the pathological
remainder. When it is hit the function's state is untrustworthy and *no
strings are returned for it*; the caller counts the event in
``stack_strings_coverage.functions_iteration_cap_hit`` so a cap hit is
observable rather than silent.

Functions whose metadata carries no usable CFG (blocks that do not tile
the assembly text, or no CFG at all) fall back to the straight-line pass,
which is also what the public helpers here run when handed a bare
assembly listing. A ``bl``/``blr`` (ARM64) or ``call`` (x86) clobbers the
caller-saved registers exactly as the ABI demands; callee-saved registers
and the frame registers survive. Tail-kind branches (``jmp`` on x86,
``b``/``br`` on ARM64) share one semantics across the models: a branch
whose target is inside the function is pure control flow — the CFG
carries the edge and the state flows along it — while a branch that
leaves the function is a tail call and clobbers (:meth:`ArchModel.
apply_branch` is the one place that line is drawn; without a CFG the
conservative reading applies). Any instruction writing a register the
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

import contextlib
import re
from collections.abc import Callable, Iterator

from blint.config import get_int_from_env
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
# non-converged and dropped from recovery (see module docstring). Values that
# conflict go unknown within a few rounds, but a change now propagates along
# every intra-function branch edge, so long functions need more revisit waves
# than the pre-edge semantics did; at 64 the functions the cap still drops on
# real Rust binaries are the genuinely pathological handful.
MAX_BLOCK_VISITS = 64

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


def _decode_run(run: tuple[str, int, bytes]) -> dict | None:
    """Decode one byte run, keeping its single best reading, or None.

    A run is tried as both UTF-16LE and ASCII because a function may build
    either, but only the longer valid reading is kept. Emitting both would report
    the same literal twice, once truncated at the first zero byte of its own wide
    encoding.
    """
    base, offset, data = run
    best: tuple[str, str] | None = None
    for encoding, label in (("utf-16-le", "utf-16le"), ("ascii", "ascii")):
        if encoding == "utf-16-le" and len(data) < MIN_RECOVERED_LEN * 2:
            continue
        candidate = _decode_one(data, encoding)
        if not candidate or not _looks_like_text(candidate):
            continue
        if best is None or len(candidate) > len(best[0]):
            best = (candidate, label)
    if best is None:
        return None
    return {"value": best[0], "encoding": best[1], "frame": f"{base}{offset:+d}"}


def _decode_runs(runs: Iterator[tuple[str, int, bytes]]) -> list[dict]:
    """Decode the byte runs, dropping repeats of a value already reported."""
    recovered: list[dict] = []
    seen: set[str] = set()
    for run in runs:
        if len(recovered) >= MAX_RUNS_PER_FUNCTION:
            break
        entry = _decode_run(run)
        if entry is None or entry["value"].lower() in seen:
            continue
        seen.add(entry["value"].lower())
        recovered.append(entry)
    return recovered


def iter_frame_runs(state: FrameState) -> Iterator[tuple[str, int, bytes]]:
    """Yield (frame base, start offset, bytes) for each contiguous byte run.

    A slot holding a symbolic-pointer word (i386 pushes and stores) is not
    bytes and breaks the run around it.
    """
    by_base: dict[str, list[int]] = {}
    for base, offset in state.slots:
        if isinstance(state.slots[(base, offset)], int):
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


def _drop_partial_runs(
    runs: list[tuple[str, int, bytes]],
) -> list[tuple[str, int, bytes]]:
    """Drop each run that is a shorter reading of a longer run in the same slot.

    Reading a frame at several program points catches a string mid-assembly:
    ``'fts'``, ``'ftsv'``, ``'ftsvS'`` and six more readings of the one
    ``'ftsvSOiIpom'`` an OrbStack function builds at ``sp+21``. A run is a
    partial reading when a longer run covers its bytes at the same address and
    those bytes agree, which makes it the same construction seen earlier rather
    than a second string; anything else is kept, including a shorter string
    that merely reads like a prefix of one built elsewhere in the function.

    Only runs that decode are allowed to displace a shorter one. A longer run
    the decoder rejects reports nothing itself, so letting it absorb the
    readings inside it would lose them outright — which cost OrbStack four
    values ('--since', 'Challenge', '[ipv', 'ipv') when this filtered raw
    runs.
    """
    runs = [run for run in runs if _decode_run(run) is not None]
    by_base: dict[str, list[tuple[str, int, bytes]]] = {}
    for run in runs:
        by_base.setdefault(run[0], []).append(run)
    kept = []
    for run in runs:
        base, start, data = run
        if any(
            len(other) > len(data)
            and other_start <= start
            and start + len(data) <= other_start + len(other)
            and other[start - other_start : start - other_start + len(data)] == data
            for _, other_start, other in by_base[base]
        ):
            continue
        kept.append(run)
    return kept


# ---------------------------------------------------------------------------
# The abstract state and its join.
# ---------------------------------------------------------------------------


class FrameState:
    """Register values and frame-slot bytes for one point of one function.

    Register values are plain ints, or tuples naming a symbolic pointer: a
    ``("sp", offset)`` names a slot relative to the *initial* stack pointer
    (so ``add x8, sp, #8`` followed by ``str x9, [x8]`` lands in the frame
    even after ``sub sp`` moved the base), ``("adrp", 0)`` names a page
    pointer whose page could not be computed, and ``("ptr", address)`` names
    a *materialised* pointer whose absolute address the model folded from a
    pc-relative form (ARM64 ``adrp`` [+ ``add``], x86 rip-relative ``lea``).
    Stores through any of these are not frame slots. ``sp_adjustment`` is
    the running sp offset (ARM64 and i386); ``None`` means incoming paths
    disagree on it, after which sp-relative stores cannot be located.

    Slot values are bytes (ints 0-255). The i386 model additionally keeps
    whole words a push or store delivered as a *symbolic pointer* — a frame
    slot that holds ``("esp", k)`` or another tuple rather than bytes
    (:meth:`store_pointer_word`); such a word occupies its four byte keys
    and no byte run is read out of it, so string recovery is unaffected.

    The state carries its :class:`ArchModel` so operand-named accessors know
    the register families; the join below is model-independent.
    """

    def __init__(self, model: ArchModel) -> None:
        self.model = model
        # family -> int | tuple(symbolic pointer)
        self.registers: dict[str, int | tuple[str, int]] = {}
        # (frame base, signed offset) -> byte value | pointer-word tuple
        self.slots: dict[tuple[str, int], int | tuple[str, int]] = {}
        # xmm name -> the frame slot an 8-byte SSE load read (i386 pair moves)
        self.xmm_pairs: dict[str, tuple[str, int]] = {}
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
        for key in list(self.xmm_pairs):
            if other.xmm_pairs.get(key) != self.xmm_pairs[key]:
                del self.xmm_pairs[key]
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
        # A pointer word sitting under any of these bytes is overwritten.
        for index in range(width):
            key = (base, offset + index)
            if isinstance(self.slots.get(key), tuple):
                del self.slots[key]
        for index in range(width):
            self.slots[(base, offset + index)] = (value >> (index * 8)) & 0xFF

    def store_pointer_word(self, base: str, offset: int, value: tuple[str, int]) -> None:
        """Store one word (4 bytes) that holds a symbolic pointer, not bytes."""
        self.drop(base, offset, 4)
        self.slots[(base, offset)] = value

    def load_word(self, base: str, offset: int) -> int | tuple[str, int] | None:
        """Read one aligned word: a pointer word as itself, else its bytes."""
        value = self.slots.get((base, offset))
        if isinstance(value, tuple):
            return value
        byte_values = [self.slots.get((base, offset + index)) for index in range(4)]
        if any(not isinstance(b, int) for b in byte_values):
            return None
        return sum(b << (index * 8) for index, b in enumerate(byte_values))

    def copy_word(self, dst: tuple[str, int], src: tuple[str, int]) -> None:
        """Copy one word slot to another, pointer word or bytes alike."""
        value = self.load_word(*src)
        if isinstance(value, tuple):
            self.store_pointer_word(dst[0], dst[1], value)
        elif isinstance(value, int):
            self.store(dst[0], dst[1], value, 4)
        else:
            self.drop(dst[0], dst[1], 4)

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
    # Fixed instruction encoding size in bytes, or None when instructions
    # vary. The call-site recovery uses it (with the disassembler's exported
    # per-instruction lengths, when available) to reconstruct where a line
    # sits, which is what pc-relative materialisations fold against.
    instruction_stride: int | None = None

    def register(self, name: str) -> tuple[str, int] | None:  # pragma: no cover - interface
        raise NotImplementedError

    def is_zero_register(self, family: str) -> bool:
        return False

    def write_operand(self, state: FrameState, name: str, value) -> None:  # pragma: no cover
        raise NotImplementedError

    def write_family(
        self, state: FrameState, family: str, value, width: int
    ) -> None:  # pragma: no cover
        raise NotImplementedError

    def step(
        self,
        state: FrameState,
        text: str,
        leaves_function: bool = True,
        address_span: tuple[int, int] | None = None,
    ) -> None:  # pragma: no cover - interface
        """Apply one instruction's semantics to the state.

        ``leaves_function`` says what the caller knows about a tail-kind
        branch's target (``jmp`` on x86, ``b``/``br`` on ARM64): False when
        the CFG carries the branch's edge to a block inside the function,
        True when it does not — the straight-line pass, any block whose
        terminator left no edge, and any tail-kind mnemonic off a block's
        final line, where the target cannot be placed. Only tail-kind
        mnemonics consult it; the default is the conservative reading.

        ``address_span`` is the (start, end) virtual address of this
        instruction when the caller can place it — the call-site recovery
        reconstructs them from the CFG blocks' VAs and the disassembler's
        per-instruction lengths; the stack-string paths deliberately do
        not. Only pc-relative address materialisations (``adrp``, rip-relative
        ``lea``) consult it; every other instruction ignores it, and None
        must reproduce exactly the pre-materialisation semantics.
        """
        raise NotImplementedError

    def call_kind(self, mnemonic: str) -> str | None:  # pragma: no cover - interface
        """Classify a mnemonic as a call ('call'), a tail transfer ('tail') or None.

        'call' means the mnemonic always transfers control to a callee (x86
        ``call``, ARM64 ``bl``/``blr``); 'tail' means the mnemonic is an
        ordinary branch that only becomes a call when its resolved target
        leaves the function — the test :meth:`apply_branch` applies, from the
        CFG's edges during the dataflow and from the disassembler's
        last-line annotation when resolving callee names. Callers must not
        treat a 'tail' line as a call site without one of those two tests.
        """
        raise NotImplementedError

    def apply_branch(self, state: FrameState, text: str, leaves_function: bool) -> bool:
        """Consume one control-transfer instruction, applying the branch semantics.

        This is the single place the call-vs-branch clobber decision lives,
        shared by both models. One semantics: a 'call' mnemonic always
        clobbers the caller-saved registers exactly as the ABI demands; a
        'tail' branch clobbers only when it leaves the function, because a
        branch whose target is inside the function is pure control flow —
        the CFG already carries that edge, and destroying the state that
        flows along it truncates recovery at every block ending in an
        unconditional jump. Returns True when the instruction was a
        control transfer, False when the caller must decode it as an
        ordinary instruction.
        """
        parts = text.split(None, 1) if text else []
        kind = self.call_kind(parts[0]) if parts else None
        if kind is None:
            return False
        if kind == "call" or leaves_function:
            self.clobber_call_registers(state)
        return True

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
    instruction_stride = None  # x86 instruction lengths vary

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
        # A materialised pointer passes through untouched at full width:
        # masking it would destroy the address it names (the tuple itself is
        # what the frame store guard and the call-site snapshot read). A
        # narrower write keeps only the low bytes, which are not the address,
        # so the register goes unknown instead of naming a pointer the
        # hardware never formed.
        if isinstance(value, tuple):
            if width < 8:
                state.registers.pop(family, None)
            else:
                state.registers[family] = value
            return
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

    def step(
        self,
        state: FrameState,
        text: str,
        leaves_function: bool = True,
        address_span: tuple[int, int] | None = None,
    ) -> None:
        if self.apply_branch(state, text, leaves_function):
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
                # mov copies a pointer as a pointer, but a widening move
                # (movzx/movsx/movsxd) reads narrow bits of it — that is
                # not the pointer, so the destination goes unknown.
                if not isinstance(source[0], int) and match.group(0).strip().lower().startswith(
                    ("movzx", "movsx", "movsxd")
                ):
                    state.invalidate(match.group(1))
                    return
                state.write_operand(match.group(1), source[0])
            return

        if match := _LEA_RE.match(text):
            self._apply_lea(state, match, address_span)
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
        if source is None or not isinstance(source[0], int):
            # The slot is written with something unknown (or a symbolic or
            # materialised pointer), so any earlier bytes there must be
            # dropped rather than read as part of a string.
            width = _X86_SIZE_HINTS.get((size_hint or "").lower()) or 1
            state.drop(base_info[0], offset, width)
            return
        value, width = source
        # An explicit size hint overrides the register width, which matters for the
        # `mov byte ptr [rbp-8], al` form.
        width = _X86_SIZE_HINTS.get((size_hint or "").lower(), width)
        state.store(base_info[0], offset, value, width)

    def _apply_lea(
        self, state: FrameState, match: re.Match, address_span: tuple[int, int] | None = None
    ) -> None:
        """Apply `lea dest, [src +/- imm]`, the folded arithmetic form."""
        dest, source_reg, sign, offset_token = match.groups()
        source_info = self.register(source_reg)
        # `lea rcx, [rbp - 32]` takes the address of the frame slot rather than
        # computing a character, so the destination holds a pointer, not a value.
        if source_info and source_info[0] in self.frame_bases:
            state.invalidate(dest)
            return
        if source_reg.lower() == "rip":
            # `lea rax, [rip + N]` is how position-independent code
            # materialises the address of a static object: rip reads as the
            # address of the *next* instruction, so the target is known the
            # moment this instruction's own extent is. The target is tracked
            # as a materialised ("ptr", address) pointer — the same encoding
            # ARM64's completed adrp pairs use — so a store through it is
            # not a frame slot and the call-site snapshot reads the address
            # it names. Without the address the destination stays unknown —
            # never a guessed address.
            delta = _parse_immediate(offset_token) if offset_token else 0
            if address_span is None or delta is None:
                state.invalidate(dest)
                return
            if sign == "-":
                delta = -delta
            state.write_operand(dest, ("ptr", (address_span[1] + delta) & 0xFFFFFFFFFFFFFFFF))
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
        if isinstance(source[0], tuple):
            # Folding arithmetic on a symbolic or materialised pointer moves
            # the pointer; it never becomes an integer.
            base_kind, base_offset = source[0]
            state.write_operand(dest, (base_kind, base_offset + delta))
            return
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
        if isinstance(value, tuple):
            # Arithmetic on a materialised pointer: add/sub complete or move
            # it (the same semantics ARM64's adrp completions use); a bitwise
            # op destroys the address, so the register goes unknown.
            base_kind, base_offset = value
            if op.lower() == "add":
                state.write_operand(register, (base_kind, base_offset + immediate))
            elif op.lower() == "sub":
                state.write_operand(register, (base_kind, base_offset - immediate))
            else:
                state.invalidate(register)
            return
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


# -- i386 ---------------------------------------------------------------------

# The 32-bit x86 register set: the first eight families of the x86-64 table
# (no r8-r15), keyed under each family's 32-bit name so the frame bases are
# ``esp``/``ebp``. Sub-register writes merge into the family's low bytes; on
# i386 no write zero-extends above 32 bits.
_I386_REGISTER_INFO: dict[str, tuple[str, int]] = {}
for _family, _members in _REGISTER_FAMILIES:
    _dword_name = next(name for name, width in _members if width == 4)
    for _name, _width in _members:
        _I386_REGISTER_INFO[_name] = (_dword_name, _width)

# cdecl: the caller saves eax/ecx/edx (and every xmm register); ebx, esi, edi,
# ebp and esp survive calls.
_I386_CALL_CLOBBERED = ("eax", "ecx", "edx")

# The opaque base a stack realignment (`and esp, imm`) rebases the frame to:
# far below any entry-relative key a real frame or argument area uses, so
# the realigned namespace can never alias the entry-relative one.
_I386_ALIGNED_FRAME_BASE = -(1 << 24)

_I386_FRAME_REGISTERS: frozenset[str] = frozenset({"esp", "ebp"})

# The i386 store form: the displacement is optional (`mov [esp], esi`).
_I386_STORE_RE = re.compile(
    rf"^\s*mov\s+(?:(byte|word|dword)\s+ptr\s+)?"
    rf"\[\s*({_X86_REG})\s*(?:([+-])\s*({_IMM})\s*)?\]\s*,\s*({_IMM}|{_X86_REG})\s*$",
    re.IGNORECASE,
)
# A push whose source is memory (`push dword ptr [ebp + 12]`): the callee
# re-pushes an incoming argument at its own call.
_I386_PUSH_MEM_RE = re.compile(
    rf"^\s*push\s+(?:(byte|word|dword)\s+ptr\s+)?"
    rf"\[\s*({_X86_REG})\s*(?:([+-])\s*({_IMM})\s*)?\]\s*$",
    re.IGNORECASE,
)
_I386_PUSH_RE = re.compile(rf"^\s*push\s+({_X86_REG}|{_IMM})\s*$", re.IGNORECASE)
_I386_POP_RE = re.compile(rf"^\s*pop\s+({_X86_REG})\s*$", re.IGNORECASE)
# A frame load: `mov reg, [dword ptr] [base +/- imm]`. The base is a frame
# register or any register - resolved through its value when it holds a frame
# symbolic, which is how a callee reads its incoming stack arguments wherever
# its own bytes read them.
_I386_LOAD_RE = re.compile(
    rf"^\s*mov\s+({_X86_REG})\s*,\s*(?:(byte|word|dword)\s+ptr\s+)?"
    rf"\[\s*({_X86_REG})\s*(?:([+-])\s*({_IMM})\s*)?\]\s*$",
    re.IGNORECASE,
)
# SSE pair moves: an 8-byte load into / store out of one xmm register whose
# memory side is frame-relative. Registrar code stages {pointer, count} pairs
# with `movsd [esp+K], xmm0` after `movsd xmm0, [esp+K']`.
_I386_XMM_LOAD_RE = re.compile(
    rf"^\s*mov(?:sd|lps|lpd|ups|aps|q)\s+(xmm\d+)\s*,\s*(?:qword|xmmword|dword)\s+ptr\s+"
    rf"\[\s*({_X86_REG})\s*(?:([+-])\s*({_IMM})\s*)?\]\s*$",
    re.IGNORECASE,
)
_I386_XMM_STORE_RE = re.compile(
    rf"^\s*mov(?:sd|lps|lpd|ups|aps|q)\s+(?:qword|xmmword|dword)\s+ptr\s+"
    rf"\[\s*({_X86_REG})\s*(?:([+-])\s*({_IMM})\s*)?\]\s*,\s*(xmm\d+)\s*$",
    re.IGNORECASE,
)
# `call 0` - the inline pc thunk: a call whose printed operand is zero names
# the next instruction.
_I386_CALL_ZERO_RE = re.compile(r"^\s*call\s+0\s*$", re.IGNORECASE)
# `inc/dec esp` move the frame base by one.
_I386_ESP_UNARY_RE = re.compile(r"^\s*(?:inc|dec)\s+esp\s*$", re.IGNORECASE)


class I386Model(ArchModel):
    """The 32-bit x86 (i386) register model and instruction semantics.

    Text-based over nyxstone instruction text, like the other models. The
    frame is addressed through ``esp``/``ebp``, both keyed relative to the
    *entry* stack pointer through the running ``sp_adjustment`` - the same
    convention the ARM64 model uses for ``sp``. What the 32-bit ABI adds
    over the other models:

    - **Stack arguments.** cdecl passes arguments in memory at ``[esp]``
      upward at the call, written by ``push`` or by ``mov [esp+N]`` stores;
      both land in frame slots (``push`` also moves ``sp_adjustment`` down
      by 4), and a word load reads them back - directly or through a
      register holding a frame symbolic, which is how a callee reads its
      incoming arguments at the slot its own bytes name.
    - **Pointer words in slots.** A pushed or stored symbolic pointer
      (``lea eax, [esp + 0x18]; push eax``) keeps its identity in the slot
      (:meth:`FrameState.store_pointer_word`), so an outgoing-argument area
      can carry a stack-address marker into a callee's walk.
    - **The pc idiom.** ``call 0`` - a call whose printed operand is zero -
      is the i386 PIC prologue: it pushes the address of the *next*
      instruction, which the following ``pop`` takes into the GOT base
      register. The model executes exactly that (the pushed value is the
      instruction's own end address when the caller can place it), so
      ``add ebx, imm`` afterwards yields the GOT base and ebx-relative
      ``lea`` folds GOTOFF operands the way rip-relative ``lea`` folds on
      x86-64.
    - **Alignment rebases.** ``and esp, imm`` moves ``esp`` by an amount
      the bytes do not state, so the post-realignment frame is keyed in
      its own namespace - an opaque base far below any entry-relative
      key (a frame and an argument area are kilobytes at most). Slots
      stored before the realignment keep their entry-relative keys (the
      realignment moves esp *down*; nothing above it moved), and the
      incoming argument slots above the entry stay readable through the
      realignment, which is how a realigned callee still reads the pair
      a caller staged. Within each namespace the naming is exact, and
      the two can never alias.

    Loads through any other pointer (a materialised address, a heap
    pointer) invalidate the destination: their values live in sections
    this module knows nothing about. Sub-dword stores keep byte
    decomposition (string recovery); dword stores may carry pointer words.
    """

    frame_bases = _I386_FRAME_REGISTERS
    call_clobbered = _I386_CALL_CLOBBERED
    instruction_stride = None  # x86 instruction lengths vary

    def register(self, name: str) -> tuple[str, int] | None:
        return _I386_REGISTER_INFO.get(name.strip().lower())

    def call_kind(self, mnemonic: str) -> str | None:
        lowered = mnemonic.strip().lower()
        if lowered.startswith("call"):
            return "call"
        if lowered in ("jmp", "jmpq", "jmpl"):
            return "tail"
        return None

    def is_zero_register(self, family: str) -> bool:
        return False

    def write_operand(self, state: FrameState, name: str, value) -> None:
        info = self.register(name)
        if not info:
            return
        family, width = info
        if isinstance(value, tuple):
            # A symbolic pointer needs all 32 bits; a narrower write keeps
            # bytes that are not the pointer, so the register goes unknown.
            if width < 4:
                state.registers.pop(family, None)
            else:
                state.registers[family] = value
            return
        if width == 4:
            state.registers[family] = value & 0xFFFFFFFF
            return
        previous = state.registers.get(family)
        if not isinstance(previous, int):
            return
        mask = (1 << (width * 8)) - 1
        state.registers[family] = (previous & ~mask & 0xFFFFFFFF) | (value & mask)

    def write_family(self, state: FrameState, family: str, value, width: int) -> None:
        state.registers[family] = value if isinstance(value, tuple) else value & 0xFFFFFFFF

    def clobber_call_registers(self, state: FrameState) -> None:
        super().clobber_call_registers(state)
        # Every xmm register is caller-saved under every i386 ABI that uses
        # them, so a staged pair does not survive a call.
        state.xmm_pairs.clear()

    def step(
        self,
        state: FrameState,
        text: str,
        leaves_function: bool = True,
        address_span: tuple[int, int] | None = None,
    ) -> None:
        # `call 0` is the inline pc thunk (call to the next instruction): it
        # clobbers like any call and pushes the return address - the value
        # the following `pop` takes into the GOT base register. apply_branch
        # would clobber without the push, so this comes first.
        if (match := _I386_CALL_ZERO_RE.match(text)) and address_span is not None:
            self.clobber_call_registers(state)
            if state.sp_adjustment is not None:
                state.sp_adjustment -= 4
                state.store("esp", state.sp_adjustment, address_span[1] & 0xFFFFFFFF, 4)
            return
        if self.apply_branch(state, text, leaves_function):
            return
        mnemonic = text.split(None, 1)[0].lower() if text else ""
        if mnemonic == "leave":
            # mov esp, ebp; pop ebp - esp moves to a register this pass may
            # not relate to the entry sp.
            state.sp_adjustment = None
            state.invalidate("ebp")
            return
        if match := _I386_PUSH_MEM_RE.match(text):
            self._apply_push_memory(state, *match.groups())
            return
        if match := _I386_PUSH_RE.match(text):
            self._apply_push(state, match.group(1))
            return
        if match := _I386_POP_RE.match(text):
            self._apply_pop(state, match.group(1))
            return
        if match := _I386_LOAD_RE.match(text):
            self._apply_load(state, *match.groups())
            return
        if match := _I386_XMM_LOAD_RE.match(text):
            self._apply_xmm_load(state, match)
            return
        if match := _I386_XMM_STORE_RE.match(text):
            self._apply_xmm_store(state, match)
            return
        if match := _I386_STORE_RE.match(text):
            self._apply_store(
                state,
                match.group(1),
                match.group(2),
                match.group(3) or "+",
                match.group(4) or "0",
                match.group(5),
            )
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
        if match := _MOV_REG_REG_RE.match(text):
            self._apply_mov_reg_reg(state, match)
            return
        if match := _LEA_RE.match(text):
            self._apply_lea(state, match)
            return
        if match := _ARITH_REG_IMM_RE.match(text):
            self._apply_arith(state, match)
            return
        if match := _I386_ESP_UNARY_RE.match(text):
            if state.sp_adjustment is not None:
                state.sp_adjustment += 1 if mnemonic == "inc" else -1
            return
        # Anything else that writes a register makes its value unknown.
        if match := _DEST_REG_RE.match(text):
            state.invalidate(match.group(1))

    # -- frame resolution ---------------------------------------------------

    def _resolve_frame_base(self, state: FrameState, base_reg: str) -> tuple[str, int] | None:
        """Resolve a memory operand's base to a (frame base, offset) pair.

        ``esp``/``ebp`` resolve as themselves (esp with the running
        adjustment); a register holding a frame symbolic - including ebp
        after ``mov ebp, esp`` - resolves to the slot it names. Anything
        else returns None: the access is through a pointer this pass cannot
        locate.
        """
        info = self.register(base_reg)
        if not info:
            return None
        family = info[0]
        if family == "esp":
            return None if state.sp_adjustment is None else ("esp", state.sp_adjustment)
        value = state.registers.get(family)
        if isinstance(value, tuple) and value[0] in ("esp", "ebp"):
            return value
        if family == "ebp":
            return ("ebp", 0)
        return None

    def _apply_push(self, state: FrameState, token: str) -> None:
        if state.sp_adjustment is None:
            return
        state.sp_adjustment -= 4
        info = self.register(token)
        if info:
            value = state.registers.get(info[0])
            if isinstance(value, tuple):
                state.store_pointer_word("esp", state.sp_adjustment, value)
            elif isinstance(value, int):
                state.store("esp", state.sp_adjustment, value, 4)
            else:
                state.drop("esp", state.sp_adjustment, 4)
            return
        immediate = _parse_immediate(token)
        if immediate is not None:
            state.store("esp", state.sp_adjustment, immediate, 4)
        else:
            state.drop("esp", state.sp_adjustment, 4)

    def _apply_push_memory(
        self,
        state: FrameState,
        size_hint: str | None,
        base_reg: str,
        sign: str | None,
        offset_token: str | None,
    ) -> None:
        """`push [base +/- K]`: the word a frame slot holds is pushed
        (pointer words keep their identity), and an unresolvable source
        still moves the stack."""
        resolved = self._resolve_frame_base(state, base_reg)
        offset = _parse_immediate(offset_token) if offset_token else 0
        if offset is not None and sign == "-":
            offset = -offset
        value = (
            state.load_word(resolved[0], resolved[1] + offset)
            if resolved is not None and offset is not None
            else None
        )
        if state.sp_adjustment is None:
            return
        state.sp_adjustment -= 4
        if isinstance(value, tuple):
            state.store_pointer_word("esp", state.sp_adjustment, value)
        elif isinstance(value, int):
            state.store("esp", state.sp_adjustment, value, 4)
        else:
            state.drop("esp", state.sp_adjustment, 4)

    def _apply_pop(self, state: FrameState, name: str) -> None:
        if state.sp_adjustment is None:
            state.invalidate(name)
            return
        value = state.load_word("esp", state.sp_adjustment)
        state.drop("esp", state.sp_adjustment, 4)
        state.sp_adjustment += 4
        if isinstance(value, (int, tuple)):
            state.write_operand(name, value)
        else:
            state.invalidate(name)

    def _apply_load(
        self,
        state: FrameState,
        dest: str,
        size_hint: str | None,
        base_reg: str,
        sign: str | None,
        offset_token: str | None,
    ) -> None:
        resolved = self._resolve_frame_base(state, base_reg)
        if resolved is None:
            state.invalidate(dest)
            return
        offset = _parse_immediate(offset_token) if offset_token else 0
        if offset is None:
            state.invalidate(dest)
            return
        if sign == "-":
            offset = -offset
        key = (resolved[0], resolved[1] + offset)
        width = _X86_SIZE_HINTS.get((size_hint or "dword").lower(), 4)
        if width == 4:
            value = state.load_word(*key)
            if isinstance(value, (int, tuple)):
                state.write_operand(dest, value)
            else:
                state.invalidate(dest)
            return
        # A sub-dword read of known bytes; a pointer word's low bytes are not
        # the pointer, so they stay unknown.
        byte = state.slots.get(key)
        if isinstance(byte, int):
            state.write_operand(dest, byte)
        else:
            state.invalidate(dest)

    def _apply_store(
        self,
        state: FrameState,
        size_hint: str | None,
        base_reg: str,
        sign: str,
        offset_token: str,
        value_token: str,
    ) -> None:
        resolved = self._resolve_frame_base(state, base_reg)
        if resolved is None:
            return
        offset = _parse_immediate(offset_token)
        if offset is None:
            return
        if sign == "-":
            offset = -offset
        offset += resolved[1]
        hint = _X86_SIZE_HINTS.get((size_hint or "").lower())
        source_info = self.register(value_token)
        if source_info:
            width = hint or source_info[1]
            value = state.registers.get(source_info[0])
            if width == 4:
                if isinstance(value, tuple):
                    state.store_pointer_word(resolved[0], offset, value)
                elif isinstance(value, int):
                    state.store(resolved[0], offset, value, 4)
                else:
                    state.drop(resolved[0], offset, 4)
            elif isinstance(value, int):
                state.store(resolved[0], offset, value, width)
            else:
                state.drop(resolved[0], offset, width)
            return
        immediate = _parse_immediate(value_token)
        if immediate is None:
            return
        # An i386 immediate store is a dword unless its size hint says
        # otherwise (the byte form prints `byte ptr`).
        width = hint or 4
        if width == 4:
            state.store(resolved[0], offset, immediate, 4)
        else:
            state.store(resolved[0], offset, immediate, width)

    def _apply_xmm_load(self, state: FrameState, match: re.Match) -> None:
        xmm, base_reg, sign, offset_token = match.groups()
        resolved = self._resolve_frame_base(state, base_reg)
        if resolved is None or (offset := self._offset(sign, offset_token)) is None:
            state.xmm_pairs.pop(xmm.lower(), None)
            return
        state.xmm_pairs[xmm.lower()] = (resolved[0], resolved[1] + offset)

    def _apply_xmm_store(self, state: FrameState, match: re.Match) -> None:
        base_reg, sign, offset_token, xmm = match.groups()
        resolved = self._resolve_frame_base(state, base_reg)
        if resolved is None or (offset := self._offset(sign, offset_token)) is None:
            return
        dst = (resolved[0], resolved[1] + offset)
        source_pair = state.xmm_pairs.get(xmm.lower())
        if source_pair is None:
            state.drop(dst[0], dst[1], 8)
            return
        state.copy_word(dst, source_pair)
        state.copy_word((dst[0], dst[1] + 4), (source_pair[0], source_pair[1] + 4))

    @staticmethod
    def _offset(sign: str | None, token: str | None) -> int | None:
        offset = _parse_immediate(token) if token else 0
        if offset is None:
            return None
        return -offset if sign == "-" else offset

    def _apply_mov_reg_reg(self, state: FrameState, match: re.Match) -> None:
        dest, source = match.group(1), match.group(2)
        dest_info = self.register(dest)
        source_info = self.register(source)
        # `mov esp, ebp` restores the frame base; trackable when ebp holds an
        # esp symbolic, unknowable otherwise.
        if dest_info and dest_info[0] == "esp":
            value = state.registers.get("ebp") if source_info and source_info[0] == "ebp" else None
            if isinstance(value, tuple) and value[0] == "esp":
                state.sp_adjustment = value[1]
            else:
                state.sp_adjustment = None
            return
        if source_info and source_info[0] == "esp":
            if state.sp_adjustment is None:
                state.invalidate(dest)
            else:
                state.write_operand(dest, ("esp", state.sp_adjustment))
            return
        value = state.get_register(source)
        if value is None:
            state.invalidate(dest)
            return
        if not isinstance(value[0], int) and match.group(0).strip().lower().startswith(
            ("movzx", "movsx", "movsxd")
        ):
            state.invalidate(dest)
            return
        state.write_operand(dest, value[0])

    def _apply_lea(self, state: FrameState, match: re.Match) -> None:
        """`lea dest, [src +/- imm]`, including a frame-base source, which
        names a slot rather than computing a character."""
        dest, source_reg, sign, offset_token = match.groups()
        resolved = self._resolve_frame_base(state, source_reg)
        if resolved is not None:
            offset = _parse_immediate(offset_token) if offset_token else 0
            if offset is None:
                state.invalidate(dest)
                return
            if sign == "-":
                offset = -offset
            state.write_operand(dest, (resolved[0], resolved[1] + offset))
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
        if isinstance(source[0], tuple):
            base_kind, base_offset = source[0]
            state.write_operand(dest, (base_kind, base_offset + delta))
            return
        state.write_operand(dest, (source[0] + delta) & 0xFFFFFFFF)

    def _apply_arith(self, state: FrameState, match: re.Match) -> None:
        """`add/sub/or/and/xor reg, imm`, with the frame-base and GOT-base
        cases cdecl registrars rely on."""
        op, register, immediate_token = match.groups()
        immediate = _parse_immediate(immediate_token)
        info = self.register(register)
        if not info:
            return
        if info[0] == "esp":
            if state.sp_adjustment is None or immediate is None:
                return
            if op.lower() == "sub":
                state.sp_adjustment -= immediate
            elif op.lower() == "add":
                state.sp_adjustment += immediate
            elif op.lower() == "and":
                # A realignment: the bytes do not state the delta, so the
                # post-realignment frame is keyed from an opaque base no
                # entry-relative key can reach. Nothing above the entry
                # moved, so earlier slots and the incoming arguments keep
                # their entry-relative keys.
                state.sp_adjustment = _I386_ALIGNED_FRAME_BASE
            return
        current = state.get_register(register)
        if current is None or immediate is None:
            state.invalidate(register)
            return
        value = current[0]
        if isinstance(value, tuple):
            base_kind, base_offset = value
            if op.lower() == "add":
                state.write_operand(register, (base_kind, base_offset + immediate))
            elif op.lower() == "sub":
                state.write_operand(register, (base_kind, base_offset - immediate))
            else:
                state.invalidate(register)
            return
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
        state.write_operand(register, result & 0xFFFFFFFF)


# -- ARM64 --------------------------------------------------------------------

# Frame bases whose stores land in a recoverable frame slot. x29 is the frame
# pointer (`fp` in some listings); everything else is a pointer this pass
# cannot locate. Registers derived from these bases (``add x8, sp, #8``)
# inherit the base symbolically.
ARM64_FRAME_BASES = frozenset({"sp", "x29", "fp"})

# Caller-saved registers under the AAPCS64 ABI. After a call their values are
# unknown; x19-x28 (callee-saved), x29 (fp), x30 (lr) and sp survive.
ARM64_CALL_CLOBBERED = tuple(sorted({f"x{i}" for i in range(19)} | {f"w{i}" for i in range(19)}))

_ARM64_REG = r"[wx]\d+|xzr|wzr|sp|fp|lr"

_ARM64_MOV_IMM_RE = re.compile(rf"^\s*mov\s+({_ARM64_REG})\s*,\s*({_IMM})\s*$", re.IGNORECASE)
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
# adrp renders as `adrp x0, #<delta>`: the delta is the page displacement
# from the instruction's own page (`pc & ~0xFFF`), so the computed page is
# `(pc & ~0xFFF) + delta`. Negative when the target lies below the page.
_ARM64_ADRP_RE = re.compile(rf"^\s*adrp\s+({_ARM64_REG})\s*,\s*({_IMM})\s*$", re.IGNORECASE)

# Any other instruction whose first operand is a register kills the known
# value it held. Keeping this strict is what prevents stale values from being
# decoded as characters they never were.
_ARM64_DEST_REG_RE = re.compile(rf"^\s*[a-z][a-z0-9.]*\s+({_ARM64_REG})\s*(?:,|$)", re.IGNORECASE)

_ARM64_STORE_WIDTHS = {
    "strb": 1,
    "sturb": 1,
    "strh": 2,
    "sturh": 2,
    "str": None,
    "stur": None,  # width comes from the register
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
    instruction_stride = 4  # AArch64 instructions are one fixed word

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
        # 32-bit writes zero-extend the upper half of the 64-bit register, so
        # they keep only the low half of a materialised address — which is not
        # that address. Drop it rather than report a pointer the hardware
        # never formed.
        if isinstance(value, tuple):
            if value[0] == "ptr":
                state.registers.pop(family, None)
            else:
                state.registers[family] = value
            return
        state.registers[family] = value & 0xFFFFFFFF

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

    def step(
        self,
        state: FrameState,
        text: str,
        leaves_function: bool = True,
        address_span: tuple[int, int] | None = None,
    ) -> None:
        # bl/blr always call; b/br are tail calls exactly when they leave the
        # function (see apply_branch — the one place that line is drawn).
        if self.apply_branch(state, text, leaves_function):
            return
        lowered = text.split(None, 1)[0].lower() if text else ""
        if lowered.startswith("b.") or lowered in ("ret", "brk", "cbz", "cbnz", "tbz", "tbnz"):
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

        # adrp computes a page address: `pc & ~0xFFF` plus the page
        # displacement the disassembler renders. When the instruction's own
        # address is known the page is computed and tracked as a *materialised
        # pointer* — a ("ptr", address) tuple, so a store through it is still
        # not a frame slot and an `add xN, xN, #imm` completes it into the
        # absolute address instead of manufacturing an integer. A
        # `ldr xN, [xM, #off]` off an adrp base is a load *through* the
        # pointer, not the pointer: it is not matched here and falls through
        # to the invalidating handler below, so a dereference is never
        # reported as the address. Without the instruction's address the
        # page cannot be computed and the register keeps the legacy
        # non-frame symbolic marker.
        if match := _ARM64_ADRP_RE.match(text):
            info = self.register(match.group(1))
            if info is None:
                return
            delta = _parse_immediate(match.group(2))
            if address_span is None or delta is None:
                state.write_family(info[0], ("adrp", 0), 8)
                return
            page = ((address_span[0] & ~0xFFF) + delta) & 0xFFFFFFFFFFFFFFFF
            state.write_family(info[0], ("ptr", page), 8)
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
                source_a[1]
                if source_a and isinstance(source_a[0], int)
                else (info_a or (None, 8))[1]
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
            # The destination's own width decides: a w-register cannot hold a
            # materialised address (write_family drops it), while the derived
            # frame-pointer tuples keep the semantics they have always had.
            state.write_family(info[0], (base_kind, base_offset + delta), info[1])
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


# -- arm32 (ARM and Thumb) -------------------------------------------------------

# The AAPCS caller-saved set: r0-r3 (the argument and return registers), r12
# (ip, the interworking veneer scratch) and lr. r4-r11 and sp survive calls.
_ARM32_CALL_CLOBBERED = ("r0", "r1", "r2", "r3", "r12", "lr")

# Only sp is a frame base. Thumb code keeps its frame pointer in r7 and ARM
# code in r11 (fp), but both derive it from sp in the prologue, so a derived
# ("sp", k) symbolic is what locates their frames - the same convention the
# ARM64 model uses for registers derived off sp.
ARM32_FRAME_BASES = frozenset({"sp"})

# The opaque base a stack realignment rebases the frame to (ARM-mode
# -mstackrealign emits `bfc sp, #0, #2`), far below any entry-relative key a
# real frame or argument area uses - the same namespace split as i386's
# `and esp, imm`.
_ARM32_ALIGNED_FRAME_BASE = -(1 << 24)

_ARM32_ALIASES = {"ip": "r12", "fp": "r11", "sb": "r9", "sl": "r10"}

# ARM condition suffixes, so a branch (b + cond) is never read as a call
# (bl + cond) and vice versa - `blt` branches, `bleq` calls.
_ARM32_CONDITIONS = frozenset(
    [
        "eq",
        "ne",
        "cs",
        "hs",
        "cc",
        "lo",
        "mi",
        "pl",
        "vs",
        "vc",
        "hi",
        "ls",
        "ge",
        "lt",
        "le",
        "gt",
        "al",
    ]
)

_ARM32_REG = r"(?:r\d+|sp|lr|pc|ip|fp|sb|sl)"

_ARM32_PUSH_RE = re.compile(r"^\s*push(?:\.w)?\s+\{(?P<regs>[^}]+)\}\s*$", re.IGNORECASE)
_ARM32_POP_RE = re.compile(r"^\s*pop(?:\.w)?\s+\{(?P<regs>[^}]+)\}\s*$", re.IGNORECASE)
# A stack realignment: the bytes do not state the delta, so the frame moves to
# its own opaque namespace (the i386 `and esp, imm` rule). ARM-mode
# -mstackrealign realigns sp directly; the Thumb spelling routes through a
# register (`mov r4, sp; bfc r4, #0, #2; mov sp, r4`), so the bit-field
# clear's destination is any register.
_ARM32_REALIGN_RE = re.compile(
    rf"^\s*(?:bfc(?:\.w)?\s+(?P<dst>{_ARM32_REG})\s*,\s*#\d+\s*,\s*#\d+"
    rf"|bics?(?:\.w)?\s+(?P<dst2>{_ARM32_REG})\s*,\s*(?P<src>{_ARM32_REG})\s*,\s*{_IMM})\s*$",
    re.IGNORECASE,
)
_ARM32_MOV_RE = re.compile(
    rf"^\s*movs?(?:\.w)?\s+(?P<dst>{_ARM32_REG})\s*,\s*(?P<src>{_ARM32_REG}|{_IMM})\s*$",
    re.IGNORECASE,
)
_ARM32_MOVW_RE = re.compile(
    rf"^\s*movw(?:\.w)?\s+(?P<dst>{_ARM32_REG})\s*,\s*(?P<imm>{_IMM})\s*$",
    re.IGNORECASE,
)
_ARM32_MOVT_RE = re.compile(
    rf"^\s*movt(?:\.w)?\s+(?P<dst>{_ARM32_REG})\s*,\s*(?P<imm>{_IMM})\s*$",
    re.IGNORECASE,
)
_ARM32_ADR_RE = re.compile(
    rf"^\s*adr(?:\.w)?\s+(?P<dst>{_ARM32_REG})\s*,\s*(?P<delta>{_IMM})\s*$",
    re.IGNORECASE,
)
# The two- and three-operand add/sub spellings nyxstone prints: Thumb's
# `adds r1, #1` and `add r0, pc` against ARM's `add r11, sp, #8`.
_ARM32_ARITH_RE = re.compile(
    rf"^\s*(?P<op>add|sub)s?(?:\.w)?\s+(?P<dst>{_ARM32_REG})\s*,\s*(?P<a>{_ARM32_REG}|{_IMM})"
    rf"(?:\s*,\s*(?P<b>{_ARM32_REG}|{_IMM}))?\s*$",
    re.IGNORECASE,
)
# The memory operand shared by every load/store form: [base], [base, #K],
# [base, #K]! (pre-index), [base], #K and [base], rM (post-index), and the
# pc-relative literal-pool forms [pc], [pc, #K] and [pc, rM].
_ARM32_MEM_OPERAND_RE = re.compile(
    rf"^\[\s*(?P<base>{_ARM32_REG})\s*(?:,\s*(?P<off>{_IMM}|{_ARM32_REG}))?\s*\]"
    rf"(?P<pre>!)?(?:\s*,\s*(?P<post>{_IMM}|{_ARM32_REG}))?$"
)
_ARM32_MEM_RE = re.compile(
    rf"^\s*(?P<op>ldrsb|ldrsh|ldrb|strb|ldrh|strh|ldr|str)(?:\.w)?\s+"
    rf"(?P<reg>{_ARM32_REG})\s*,\s*(?P<mem>\[.*\])\s*$",
    re.IGNORECASE,
)
_ARM32_PAIR_RE = re.compile(
    rf"^\s*(?P<op>strd|ldrd)(?:\.w)?\s+(?P<ra>{_ARM32_REG})\s*,\s*(?P<rb>{_ARM32_REG})\s*,"
    rf"\s*(?P<mem>\[.*\])\s*$",
    re.IGNORECASE,
)
_ARM32_BLOCK_RE = re.compile(
    rf"^\s*(?P<op>stm|ldm)(?P<variant>ia|db)?(?:\.w)?\s+(?P<base>{_ARM32_REG})(?P<wb>!)?"
    rf"\s*,\s*\{{(?P<regs>[^}}]+)\}}\s*$",
    re.IGNORECASE,
)
# NEON loads/stores write D registers (unmodelled); only a writeback form
# touches a general-purpose register, and the amount is the element stride.
_ARM32_NEON_RE = re.compile(r"^\s*v(?:ld|st)[a-z0-9.]*", re.IGNORECASE)
_ARM32_NEON_MEM_RE = re.compile(rf"\[\s*({_ARM32_REG})[^\]]*\]\s*(.*)$", re.IGNORECASE)
# Instructions that write no general-purpose register: the flag setters, the
# IT-block predicates, the barriers, the hints and every syscall instruction.
_ARM32_NO_WRITE_RE = re.compile(
    r"^\s*(?:cmp|cmn|tst|teq|cbz|cbnz|dmb|dsb|isb|nop|svc|bkpt|udf|pld|pldw|plli|it[a-z]*)\b",
    re.IGNORECASE,
)
# Any other instruction whose first operand is a register kills the known
# value it held. Stores, loads and the flag-setting mnemonics are matched
# before this, so a source register is never invalidated by its own store;
# the condition-suffixed forms (IT blocks) land here too, which is the
# conservative reading - they may not execute.
_ARM32_DEST_REG_RE = re.compile(rf"^\s*[a-z][a-z0-9.]*\s+({_ARM32_REG})\s*(?:,|$)", re.IGNORECASE)


def _arm32_register_family(name: str) -> tuple[str, int] | None:
    """Map an ARM32 register name to its (family, width); None for untracked."""
    lowered = name.strip().lower()
    if lowered in _ARM32_ALIASES:
        lowered = _ARM32_ALIASES[lowered]
    if lowered == "sp":
        return ("sp", 4)
    if lowered == "lr":
        return ("lr", 4)
    if lowered == "pc":
        return ("pc", 4)
    if lowered.startswith("r") and lowered[1:].isdigit():
        if int(lowered[1:]) <= 12:
            return (lowered, 4)
    return None


def _arm32_register_list(text: str) -> list[str]:
    """Expand a brace register list (`r4, r10, lr` or `r4-r7, r9`)."""
    names: list[str] = []
    for token in text.split(","):
        token = token.strip().lower()
        if not token:
            continue
        head, sep, tail = token.partition("-")
        if sep and head.startswith("r") and head[1:].isdigit() and tail.startswith("r"):
            for number in range(int(head[1:]), int(tail[1:]) + 1):
                names.append(f"r{number}")
        else:
            names.append(token)
    return names


def _arm32_mnemonic_root(mnemonic: str) -> str:
    """The mnemonic without its width suffix (`.w`/`.n`)."""
    return mnemonic.split(".", 1)[0]


class Arm32Model(ArchModel):
    """The 32-bit ARM register model and instruction semantics.

    Text-based over nyxstone instruction text, like the other models, and
    dialect-agnostic: one handler set covers the ARM and Thumb spellings
    (``sub sp, sp, #16`` against ``subs sp, #16``, the two- and three-operand
    ``add`` forms, ``ldr rN, [pc, #K]`` literal pools in both). The one place
    the dialect decides is what ``pc`` reads as - Thumb's
    current-instruction+4 against ARM's +8 - so the model carries
    :attr:`pc_read` and ships as :data:`ARM32_MODEL` (Thumb, the NDK
    armeabi-v7a default) and :data:`ARM32_ARM_MODEL`.

    What the 32-bit ABI adds over the shared machinery:

    - **Frame-pointer derivation.** Thumb keeps its frame pointer in r7 and
      ARM in r11, both derived by ``add rN, sp, #imm`` in the prologue, so a
      store through either resolves by the derived ``("sp", k)`` symbolic -
      the ARM64 model's rule. ``sub sp, rN, #imm`` restores the frame base
      from that symbolic in the epilogue.
    - **Literal pools.** A pc-relative load (``ldr rN, [pc, #K]``, in the
      ``[pc]`` and ``[pc, rM]`` forms too) reads a word this text-based model
      cannot see; the destination stays unknown here, and the caller that
      owns the bytes (the FindClass walk) resolves it beside the model the
      way i386's GOT loads resolve. The completions - ``add rN, pc`` (Thumb)
      and ``add rN, pc, rM`` / ``add rN, rM, pc`` (ARM), plus ``adr`` - fold
      against the instruction's own address when the caller provides it.
    - **Alignment rebases.** ARM-mode ``-mstackrealign`` emits
      ``bfc sp, #0, #2``; like i386's ``and esp, imm`` the bytes do not state
      the delta, so the post-realignment frame is keyed from an opaque base
      while the pre-realignment slots and the incoming arguments keep their
      entry-relative keys.
    - **Register-list stores.** ``push``/``pop``, ``stm``/``ldm`` blocks and
      the ``strd``/``ldrd`` pairs land whole words in the frame, so a
      registrar's entry words survive as pointer words exactly as i386's
      staged stores do.
    """

    frame_bases = ARM32_FRAME_BASES
    call_clobbered = _ARM32_CALL_CLOBBERED
    instruction_stride = None  # Thumb instructions are 2 or 4 bytes

    def __init__(self, thumb: bool = True) -> None:
        super().__init__()
        # pc reads as current-instruction+4 in Thumb and +8 in ARM.
        self.pc_read = 4 if thumb else 8

    def register(self, name: str) -> tuple[str, int] | None:
        return _arm32_register_family(name)

    def call_kind(self, mnemonic: str) -> str | None:
        root = _arm32_mnemonic_root(mnemonic.strip().lower())
        if root in ("bl", "blx"):
            return "call"
        if root in ("b", "bx"):
            return "tail"
        # Conditional spellings: `bleq` calls, `blt` is b+lt and branches -
        # the condition split keeps the two apart.
        if root.startswith("blx") and root[3:] in _ARM32_CONDITIONS:
            return "call"
        if root.startswith("bl") and root[2:] in _ARM32_CONDITIONS:
            return "call"
        if root.startswith("bx") and root[2:] in _ARM32_CONDITIONS:
            return None  # a conditional bx is a return or transfer, not a call site
        return None

    def write_operand(self, state: FrameState, name: str, value) -> None:
        info = self.register(name)
        if not info:
            return
        if isinstance(value, (tuple, int)):
            state.registers[info[0]] = value if isinstance(value, tuple) else value & 0xFFFFFFFF
        else:
            state.registers.pop(info[0], None)

    def write_family(self, state: FrameState, family: str, value, width: int) -> None:
        if isinstance(value, (tuple, int)):
            state.registers[family] = value if isinstance(value, tuple) else value & 0xFFFFFFFF
        else:
            state.registers.pop(family, None)

    def resolve_base(self, state: FrameState, base_reg: str) -> tuple[str, int] | None:
        """Resolve a memory operand's base to a (frame base, offset) pair.

        ``sp`` resolves with the running adjustment applied; a register
        holding a derived ``("sp", off)`` tuple resolves to that slot (r7/r11
        frame pointers arrive this way). Anything else returns None - the
        access is through a pointer this pass cannot locate.
        """
        info = self.register(base_reg)
        if not info:
            return None
        family = info[0]
        if family == "sp":
            return None if state.sp_adjustment is None else ("sp", state.sp_adjustment)
        value = state.registers.get(family)
        if isinstance(value, tuple) and value[0] == "sp":
            return "sp", value[1]
        return None

    def step(
        self,
        state: FrameState,
        text: str,
        leaves_function: bool = True,
        address_span: tuple[int, int] | None = None,
    ) -> None:
        parts = text.split(None, 1)
        mnemonic = parts[0].lower() if parts else ""
        root = _arm32_mnemonic_root(mnemonic)
        # `bx lr` (and its conditional forms) are returns, not transfers: no
        # register is written.
        if root == "bx" or (root.startswith("bx") and root[2:] in _ARM32_CONDITIONS):
            if len(parts) > 1 and parts[1].strip().lower() == "lr":
                return
        if self.apply_branch(state, text, leaves_function):
            return
        if _ARM32_NO_WRITE_RE.match(text):
            return
        if match := _ARM32_PUSH_RE.match(text):
            self._apply_push(state, match.group("regs"))
            return
        if match := _ARM32_POP_RE.match(text):
            self._apply_pop(state, match.group("regs"))
            return
        if match := _ARM32_REALIGN_RE.match(text):
            self._apply_realign(state, match)
            return
        if match := _ARM32_MEM_RE.match(text):
            self._apply_memory(state, match, address_span)
            return
        if match := _ARM32_PAIR_RE.match(text):
            self._apply_pair(state, match)
            return
        if match := _ARM32_BLOCK_RE.match(text):
            self._apply_block(state, match)
            return
        if match := _ARM32_MOV_RE.match(text):
            self._apply_mov(state, match, address_span)
            return
        if match := _ARM32_MOVW_RE.match(text):
            self._apply_movw(state, match)
            return
        if match := _ARM32_MOVT_RE.match(text):
            self._apply_movt(state, match)
            return
        if match := _ARM32_ADR_RE.match(text):
            self._apply_adr(state, match, address_span)
            return
        if match := _ARM32_ARITH_RE.match(text):
            self._apply_arith(state, match, address_span)
            return
        if _ARM32_NEON_RE.match(text):
            # Only a writeback form touches a general-purpose register, and
            # the amount is the element stride - the base goes unknown.
            if mem := _ARM32_NEON_MEM_RE.search(text):
                if mem.group(2).strip():
                    if self.register(mem.group(1))[0] == "sp":
                        state.sp_adjustment = None
                    else:
                        state.invalidate(mem.group(1))
            return
        # Anything else writing a register makes its value unknown.
        if match := _ARM32_DEST_REG_RE.match(text):
            state.invalidate(match.group(1))

    # -- handlers -----------------------------------------------------------

    @staticmethod
    def _offset(token: str | None) -> int | None:
        return _parse_immediate(token) if token else 0

    def _store_word(self, state: FrameState, base: str, offset: int, value) -> None:
        """Store one 4-byte word: a pointer word keeps its identity."""
        if isinstance(value, tuple):
            state.store_pointer_word(base, offset, value)
        elif isinstance(value, int):
            state.store(base, offset, value, 4)
        else:
            state.drop(base, offset, 4)

    def _apply_realign(self, state: FrameState, match: re.Match) -> None:
        """A bit-field clear (or bic) that aligns the frame pointer.

        The bytes do not state the delta, so whatever the destination names -
        sp itself (ARM) or a register holding a derived sp symbolic that a
        following `mov sp, rN` installs (Thumb) - is rebased to the opaque
        namespace. Nothing above the entry moved, so earlier slots and the
        incoming arguments keep their entry-relative keys.
        """
        dst = match.group("dst") or match.group("dst2")
        info = self.register(dst) if dst else None
        if dst and dst.lower() == "sp":
            state.sp_adjustment = _ARM32_ALIGNED_FRAME_BASE
            return
        if info:
            state.registers[info[0]] = ("sp", _ARM32_ALIGNED_FRAME_BASE)

    def _apply_push(self, state: FrameState, regs_text: str) -> None:
        """Store the list's registers low-to-high below sp, moving sp down."""
        names = _arm32_register_list(regs_text)
        if state.sp_adjustment is None:
            return
        state.sp_adjustment -= 4 * len(names)
        for index, name in enumerate(names):
            if name == "pc":
                continue
            if info := self.register(name):
                self._store_word(
                    state, "sp", state.sp_adjustment + 4 * index, state.registers.get(info[0])
                )

    def _apply_pop(self, state: FrameState, regs_text: str) -> None:
        names = _arm32_register_list(regs_text)
        if state.sp_adjustment is None:
            for name in names:
                state.invalidate(name)
            return
        for index, name in enumerate(names):
            if name == "pc":
                continue
            if info := self.register(name):
                value = state.load_word("sp", state.sp_adjustment + 4 * index)
                if isinstance(value, (int, tuple)):
                    state.registers[info[0]] = value
                else:
                    state.registers.pop(info[0], None)
        state.sp_adjustment += 4 * len(names)

    def _apply_memory(self, state: FrameState, match: re.Match, address_span) -> None:
        op = match.group("op").lower()
        reg = match.group("reg")
        mem = _ARM32_MEM_OPERAND_RE.match(match.group("mem"))
        if not mem:
            return
        base = mem.group("base").lower()
        source = mem.group("off")
        offset: int | None
        if source and self.register(source):
            offset = None  # a register offset this model cannot fold
        else:
            offset = self._offset(source)
        width = 1 if op.endswith("b") else 2 if op.endswith("h") else 4
        if base == "pc":
            # The literal pool: a word this model cannot see. The caller that
            # owns the bytes resolves it beside the model.
            state.invalidate(reg)
            return
        resolved = self.resolve_base(state, base)
        if resolved is None or offset is None:
            if op.startswith("ldr"):
                state.invalidate(reg)
            return
        frame_base, base_adjustment = resolved
        effective = base_adjustment + offset
        pre_indexed = bool(mem.group("pre"))
        if pre_indexed and base == "sp" and state.sp_adjustment is not None:
            # Pre-index writeback folds the offset into sp before the access.
            state.sp_adjustment += offset
            effective = state.sp_adjustment
        if op.startswith("ldr"):
            if width == 4:
                value = state.load_word(frame_base, effective)
                if isinstance(value, (int, tuple)):
                    self.write_operand(state, reg, value)
                else:
                    state.invalidate(reg)
            else:
                # A sub-word read of known bytes; a pointer word's low bytes
                # are not the pointer, so they stay unknown.
                byte = state.slots.get((frame_base, effective))
                if isinstance(byte, int):
                    self.write_operand(state, reg, byte)
                else:
                    state.invalidate(reg)
        else:
            value = state.get_register(reg)
            if width == 4:
                self._store_word(state, frame_base, effective, value[0] if value else None)
            elif value and isinstance(value[0], int):
                state.store(frame_base, effective, value[0], width)
            else:
                state.drop(frame_base, effective, width)
        post = mem.group("post")
        if post is not None:
            # Post-index writeback moves the base after the access; only sp's
            # running adjustment tracks that without losing the frame.
            delta = _parse_immediate(post) if not self.register(post) else None
            if base == "sp" and delta is not None and state.sp_adjustment is not None:
                state.sp_adjustment += delta
            else:
                state.invalidate(base)
        elif pre_indexed and base != "sp":
            state.invalidate(base)

    def _apply_pair(self, state: FrameState, match: re.Match) -> None:
        """strd/ldrd: two whole words at [base(+off)] and base(+off)+4."""
        op = match.group("op").lower()
        mem = _ARM32_MEM_OPERAND_RE.match(match.group("mem"))
        if not mem:
            return
        offset = self._offset(mem.group("off"))
        resolved = self.resolve_base(state, mem.group("base"))
        if resolved is None or offset is None:
            if op == "ldrd":
                state.invalidate(match.group("ra"))
                state.invalidate(match.group("rb"))
            return
        base, adjustment = resolved
        slots = (adjustment + offset, adjustment + offset + 4)
        if op == "strd":
            for reg, slot in zip((match.group("ra"), match.group("rb")), slots):
                value = state.get_register(reg)
                self._store_word(state, base, slot, value[0] if value else None)
        else:
            for reg, slot in zip((match.group("ra"), match.group("rb")), slots):
                value = state.load_word(base, slot)
                if isinstance(value, (int, tuple)):
                    self.write_operand(state, reg, value)
                else:
                    state.invalidate(reg)

    def _apply_block(self, state: FrameState, match: re.Match) -> None:
        """stm/ldm: the register list stored or loaded as ascending words."""
        op = match.group("op").lower()
        variant = (match.group("variant") or "ia").lower()
        base_reg = match.group("base")
        names = _arm32_register_list(match.group("regs"))
        resolved = self.resolve_base(state, base_reg)
        if resolved is None or variant != "ia":
            if op == "ldm":
                for name in names:
                    state.invalidate(name)
            state.invalidate(base_reg)
            return
        base, adjustment = resolved
        if op == "stm":
            for index, name in enumerate(names):
                info = self.register(name)
                self._store_word(
                    state,
                    base,
                    adjustment + 4 * index,
                    state.registers.get(info[0]) if info else None,
                )
        else:
            for index, name in enumerate(names):
                if name == "pc":
                    continue
                if info := self.register(name):
                    value = state.load_word(base, adjustment + 4 * index)
                    if isinstance(value, (int, tuple)):
                        state.registers[info[0]] = value
                    else:
                        state.registers.pop(info[0], None)
        if match.group("wb"):
            # The writeback moves the base by the block size; only sp's
            # running adjustment tracks that without losing the frame.
            if base_reg.lower() == "sp" and state.sp_adjustment is not None:
                state.sp_adjustment += 4 * len(names)
            else:
                state.invalidate(base_reg)

    def _apply_mov(self, state: FrameState, match: re.Match, address_span) -> None:
        dst, src = match.group("dst"), match.group("src")
        dst_info = self.register(dst)
        if not dst_info:
            return
        src_lower = src.lower()
        if (imm := _parse_immediate(src)) is not None:
            state.registers[dst_info[0]] = imm & 0xFFFFFFFF
            return
        if src_lower == "pc":
            # pc reads as this instruction's own address plus the dialect's
            # fixed offset, so the value only exists when the caller placed
            # the instruction.
            if address_span is not None:
                state.registers[dst_info[0]] = (address_span[0] + self.pc_read) & 0xFFFFFFFF
            else:
                state.registers.pop(dst_info[0], None)
            return
        if src_lower == "sp":
            if state.sp_adjustment is None:
                state.registers.pop(dst_info[0], None)
            else:
                state.registers[dst_info[0]] = ("sp", state.sp_adjustment)
            return
        if dst_info[0] == "sp":
            # `mov sp, rN`: the frame base moves to whatever rN holds, when
            # that is a derived sp symbolic.
            src_info = self.register(src)
            value = state.registers.get(src_info[0]) if src_info else None
            if isinstance(value, tuple) and value[0] == "sp":
                state.sp_adjustment = value[1]
            else:
                state.sp_adjustment = None
            return
        src_info = self.register(src)
        if not src_info:
            return
        value = state.registers.get(src_info[0])
        if isinstance(value, (int, tuple)):
            state.registers[dst_info[0]] = value
        else:
            state.registers.pop(dst_info[0], None)

    def _apply_movw(self, state: FrameState, match: re.Match) -> None:
        info = self.register(match.group("dst"))
        value = _parse_immediate(match.group("imm"))
        if info and value is not None:
            state.registers[info[0]] = value & 0xFFFF
        elif info:
            state.registers.pop(info[0], None)

    def _apply_movt(self, state: FrameState, match: re.Match) -> None:
        info = self.register(match.group("dst"))
        value = _parse_immediate(match.group("imm"))
        if not info or value is None:
            if info:
                state.registers.pop(info[0], None)
            return
        current = state.registers.get(info[0])
        if not isinstance(current, int):
            state.registers.pop(info[0], None)
            return
        state.registers[info[0]] = (current & 0xFFFF) | ((value & 0xFFFF) << 16)

    def _apply_adr(self, state: FrameState, match: re.Match, address_span) -> None:
        """`adr rN, #delta`: pc + delta, folded when the caller placed it."""
        info = self.register(match.group("dst"))
        delta = _parse_immediate(match.group("delta"))
        if not info or delta is None:
            if info:
                state.registers.pop(info[0], None)
            return
        if address_span is None:
            state.registers.pop(info[0], None)
            return
        state.registers[info[0]] = (address_span[0] + delta) & 0xFFFFFFFF

    def _apply_arith(self, state: FrameState, match: re.Match, address_span) -> None:
        op = match.group("op").lower()
        dst, a, b = match.group("dst"), match.group("a"), match.group("b")
        dst_info = self.register(dst)
        if not dst_info:
            return
        operands = [a] + ([b] if b else [])
        # The sp forms first: `subs sp, #imm` / `sub sp, sp, #imm` move the
        # frame base, and the epilogue `sub sp, rN, #imm` restores it from a
        # derived frame pointer.
        if dst_info[0] == "sp":
            imm = next(
                (parsed for token in operands if (parsed := _parse_immediate(token)) is not None),
                None,
            )
            reg_tokens = [token for token in operands if self.register(token)]
            if imm is None:
                return
            if not reg_tokens or reg_tokens[0].lower() == "sp":
                if state.sp_adjustment is not None:
                    state.sp_adjustment += imm if op == "add" else -imm
                return
            src_info = self.register(reg_tokens[0])
            value = state.registers.get(src_info[0]) if src_info else None
            if isinstance(value, tuple) and value[0] == "sp":
                state.sp_adjustment = value[1] + (imm if op == "add" else -imm)
            else:
                state.sp_adjustment = None
            return
        # The pc completion: `add rN, pc` (Thumb, rN += pc), `add rN, pc, rM`
        # / `add rN, rM, pc` (ARM). The pool word usually arrives as the other
        # operand's value - resolved beside the model by the caller - and the
        # pc side needs this instruction's address.
        pc_position = next(
            (index for index, token in enumerate(operands) if token.lower() == "pc"), None
        )
        if pc_position is not None and op == "add":
            if len(operands) == 1:
                # The two-operand spelling: the other addend is rN itself.
                other_value = state.registers.get(dst_info[0])
            else:
                other = operands[1 - pc_position]
                if (imm := _parse_immediate(other)) is not None:
                    other_value = imm
                else:
                    other_info = self.register(other)
                    other_value = state.registers.get(other_info[0]) if other_info else None
            if isinstance(other_value, int) and address_span is not None:
                state.registers[dst_info[0]] = (
                    other_value + address_span[0] + self.pc_read
                ) & 0xFFFFFFFF
            elif (
                isinstance(other_value, tuple)
                and other_value[0] == "sp"
                and address_span is not None
            ):
                # Folding arithmetic on a frame symbolic moves the pointer.
                state.registers[dst_info[0]] = (
                    "sp",
                    other_value[1] + address_span[0] + self.pc_read,
                )
            else:
                state.registers.pop(dst_info[0], None)
            return
        # A frame-pointer derivation: `add rN, sp[, #imm]`, and the epilogue
        # move of one (`sub.w r4, r7, #8`): arithmetic on a derived sp
        # symbolic moves the symbolic, so a `mov sp, rN` after it restores the
        # frame base instead of losing it.
        sp_position = next(
            (index for index, token in enumerate(operands) if token.lower() == "sp"), None
        )
        symbolic_source = None
        for token in operands:
            if info := self.register(token):
                value = state.registers.get(info[0])
                if isinstance(value, tuple) and value[0] == "sp":
                    symbolic_source = value
        if symbolic_source is not None:
            imm = next(
                (parsed for token in operands if (parsed := _parse_immediate(token)) is not None),
                0,
            )
            delta = imm if op == "add" else -imm
            state.registers[dst_info[0]] = ("sp", symbolic_source[1] + delta)
            return
        if sp_position is not None and op == "add":
            other = operands[1 - sp_position] if len(operands) > 1 else "#0"
            imm = _parse_immediate(other) if not self.register(other) else 0
            if imm is None or state.sp_adjustment is None:
                state.registers.pop(dst_info[0], None)
            else:
                state.registers[dst_info[0]] = ("sp", state.sp_adjustment + imm)
            return
        # Plain register/immediate arithmetic; the two-operand spelling adds
        # into rN itself (adds r1, #0x3a).
        values: list[int] = []
        if len(operands) == 1:
            current = state.registers.get(dst_info[0])
            if not isinstance(current, int):
                state.registers.pop(dst_info[0], None)
                return
            values.append(current)
        for token in operands:
            if (imm := _parse_immediate(token)) is not None:
                values.append(imm)
                continue
            info = self.register(token)
            if not info or info[0] == "sp":
                state.registers.pop(dst_info[0], None)
                return
            value = state.registers.get(info[0])
            if not isinstance(value, int):
                state.registers.pop(dst_info[0], None)
                return
            values.append(value)
        if not values:
            state.registers.pop(dst_info[0], None)
            return
        result = values[0]
        for extra in values[1:]:
            result = result + extra if op == "add" else result - extra
        state.registers[dst_info[0]] = result & 0xFFFFFFFF


X86_64_MODEL = X86_64Model()
I386_MODEL = I386Model()
ARM64_MODEL = Arm64Model()
ARM32_MODEL = Arm32Model(thumb=True)
ARM32_ARM_MODEL = Arm32Model(thumb=False)

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


def _line_address_spans(
    model: ArchModel,
    lines: list[str],
    blocks: list[dict],
    spans: list[tuple[int, int]],
    instruction_lengths: list[int] | None,
) -> tuple[list[tuple[int, int]] | None, str]:
    """Reconstruct each assembly line's (start, end) address, or refuse.

    The CFG blocks carry their start and end VAs and the disassembler
    exports per-instruction lengths (``instruction_lengths``, aligned
    one-to-one with the assembly lines); a line's address is its block's
    start VA plus the strides of the lines before it in that block. On a
    model with a fixed instruction stride (ARM64's 4-byte word) the
    exported lengths may be absent and the stride serves instead.

    Returns ``(address_spans, reason)``. ``reason`` names a refusal so the
    caller can count it rather than stay silent: ``"no_addresses"`` when a
    block carries no usable start/end VAs (or the lengths array does not
    align with the listing), ``"extent_mismatch"`` when a block's extent
    contradicts the strides its lines claim to cover. Any disagreement
    refuses the whole function: a wrong address here would fold into a
    confidently wrong pointer, which is worse than no pointer.
    """
    if len(blocks) != len(spans):
        return None, "no_addresses"
    strides: list[int] | None = None
    if isinstance(instruction_lengths, list) and len(instruction_lengths) == len(lines):
        strides = instruction_lengths
    result: list[tuple[int, int]] = []
    for block, (start, end) in zip(blocks, spans):
        try:
            block_start = int(str(block.get("start")), 16)
            block_end = int(str(block.get("end")), 16)
        except (TypeError, ValueError):
            return None, "no_addresses"
        count = end - start
        extent = block_end - block_start
        if strides is not None:
            block_strides = strides[start:end]
        else:
            stride = model.instruction_stride
            if stride is None:
                # Variable-length encodings cannot be located without the
                # exported lengths.
                return None, "no_addresses"
            block_strides = [stride] * count
        if extent <= 0 or sum(block_strides) != extent:
            return None, "extent_mismatch"
        address = block_start
        for stride in block_strides:
            result.append((address, address + stride))
            address += stride
    if len(result) != len(lines):
        return None, "no_addresses"
    return result, "ok"


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
            state.xmm_pairs = dict(pred_out.xmm_pairs)
            state.sp_adjustment = pred_out.sp_adjustment
        else:
            state.joined_with(pred_out)
    return state


def _converge_over_cfg(
    lines: list[str],
    model: ArchModel,
    blocks: list[dict],
    edges: list[dict],
    address_spans: list[tuple[int, int]] | None = None,
) -> (
    tuple[list[tuple[int, int]], list[list[int]], list[list[int]], list[FrameState | None]] | None
):
    """Iterate the function's blocks to a fixed point over the CFG.

    The worklist starts at block 0 and follows the CFG's edges, so
    unreachable blocks never contribute values. A block's in-state is the
    join of its visited predecessors' out-states (the join's identity is the
    unconstrained state, not the empty one); when out-states stop changing
    the pass has reached its fixed point. Blocks are limited to
    ``MAX_BLOCK_VISITS`` visits — conflicting values go unknown within a few
    rounds, but a change propagates along every intra-function branch edge,
    so a long function reaches its fixed point over many revisit waves and
    the cap is the backstop for the pathological remainder. Returning None
    (rather than a half-converged state) keeps such a function's residue out
    of every result built on this pass.

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
        # A tail-kind terminator clobbers only when it leaves the function:
        # an outgoing edge means the branch stays inside, no edge means the
        # target is outside the window (tail call) or unresolvable
        # (indirect), and both are treated as leaving. Only the block's last
        # line can be its terminator; earlier lines default to the
        # conservative reading.
        block_leaves_function = not successors[index]
        for offset, line in enumerate(lines[start:end]):
            model.step(
                state,
                line.strip(),
                leaves_function=block_leaves_function if offset == end - start - 1 else True,
                address_span=address_spans[start + offset] if address_spans else None,
            )
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
            result.xmm_pairs = dict(exit_state.xmm_pairs)
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
    of a conflict can complete a run.

    Reading every block's state sees one string several times over, because a
    string assembled across block boundaries is complete to a different length
    in each of them. Those partial readings are dropped
    (:func:`_drop_partial_runs`) so a function reports the string it built, not
    the block layout it built it in.

    Returns None when the iteration cap was hit. Raises ValueError when the
    blocks do not tile the assembly text.
    """
    converged = _converge_over_cfg(lines, model, blocks, edges)
    if converged is None:
        return None
    _, _, _, out_states = converged
    runs: list[tuple[str, int, bytes]] = []
    seen_runs: set[tuple[str, int, bytes]] = set()
    for state in out_states:
        if state is None:
            continue
        for run in iter_frame_runs(state):
            if run in seen_runs:
                continue
            seen_runs.add(run)
            runs.append(run)
    return _decode_runs(iter(_drop_partial_runs(runs)))


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

# ---------------------------------------------------------------------------
# Pure thunks: the machine outliner's OUTLINED_FUNCTION_* and hand-written
# forwarders. A call into one is reported as a call to its final callee, with
# the thunk's instructions stepped over the caller's state.
# ---------------------------------------------------------------------------

THUNK_MAX_PREP = 4

_ARM64_THUNK_PREP = re.compile(r"^(?:mov|movz|movk|fmov|nop|adrp)\b", re.IGNORECASE)
_X86_THUNK_PREP = re.compile(r"^(?:mov|nop)\b", re.IGNORECASE)


def _is_thunk_prep(prep: list[str], is_arm64: bool) -> bool:
    """True when every prep line is a register move or constant load.

    ARM64 also accepts the ``adrp`` + ``add`` address pair (an ``add`` only
    directly after an ``adrp``); x86 accepts ``xor`` of a register with
    itself, the zeroing idiom. A memory operand is never accepted.
    """
    previous = ""
    for line in prep:
        if "[" in line:
            return False
        parts = line.split(None, 1)
        mnemonic = parts[0].lower() if parts else ""
        if is_arm64:
            if not (_ARM64_THUNK_PREP.match(line) or (mnemonic == "add" and previous == "adrp")):
                return False
        elif not _X86_THUNK_PREP.match(line):
            match = _XOR_SELF_RE.match(line)
            if not match or match.group(1).lower() != match.group(2).lower():
                return False
        previous = mnemonic
    return True


def _thunk_tail_callee(func_data: dict, last_index: int) -> str | None:
    """The named callee of a function's last-line tail branch, if resolved."""
    for entry in func_data.get("direct_call_targets") or []:
        if not isinstance(entry, dict) or entry.get("kind") != "tailcall":
            continue
        if entry.get("site_index") != last_index:
            continue
        name = str(entry.get("target_name") or "").strip()
        operand = " ".join(str(entry.get("raw_operand") or "").split()).lower()
        # A name that is just the operand echoed back is the disassembler's
        # stand-in for an unresolved numeric target, not a resolution.
        if name and " ".join(name.split()).lower() != operand:
            return name
    return None


def pure_thunk_map(disassembled_functions: dict | None, arch_target: str) -> dict[int, dict]:
    """``{thunk start address: facts}`` for the local pure thunks.

    A pure thunk is at most :data:`THUNK_MAX_PREP` register-move or
    constant-load instructions followed by one unconditional immediate tail
    branch to a callee the disassembler named. It has a single path, so a
    call into it can be resolved through it. Facts carry the thunk's
    ``name``, its final ``callee``, the ``prep`` lines and their
    ``prep_spans`` (virtual address ranges, for pc-relative folds). A
    conditional tail, a branch or a memory operand among the prep, or an
    unnamed callee keeps a function out of the map.
    """
    if not disassembled_functions:
        return {}
    lowered = (arch_target or "").lower()
    is_arm64 = "aarch64" in lowered or "arm64" in lowered
    if not is_arm64 and not any(
        marker in lowered for marker in ("x86_64", "x86-64", "amd64", "x64")
    ):
        return {}
    thunks: dict[int, dict] = {}
    for func_key, func_data in disassembled_functions.items():
        if not isinstance(func_data, dict):
            continue
        lines = [line.strip() for line in str(func_data.get("assembly") or "").split("\n")]
        lengths = func_data.get("instruction_lengths") or []
        if not 2 <= len(lines) <= THUNK_MAX_PREP + 1 or len(lengths) != len(lines):
            continue
        try:
            start = int(str(func_data.get("address")), 16)
        except (TypeError, ValueError):
            continue
        parts = lines[-1].split(None, 1)
        mnemonic = parts[0].lower() if parts else ""
        operand = parts[1].strip() if len(parts) > 1 else ""
        if mnemonic not in (("b",) if is_arm64 else ("jmp", "jmpq", "jmpl")):
            continue
        if _parse_immediate(operand.lstrip("#")) is None:
            continue
        callee = _thunk_tail_callee(func_data, len(lines) - 1)
        if not callee or not _is_thunk_prep(lines[:-1], is_arm64):
            continue
        prep_spans = []
        cursor = start
        for length in lengths[:-1]:
            prep_spans.append((cursor, cursor + int(length)))
            cursor += int(length)
        thunks[start] = {
            "name": str(func_data.get("name") or func_key),
            "callee": callee,
            "prep": lines[:-1],
            "prep_spans": prep_spans,
        }
    return thunks


def _state_after_thunk(model: ArchModel, state: FrameState, thunk: dict) -> FrameState:
    """A copy of ``state`` with the thunk's prep instructions stepped over it."""
    stepped = FrameState(model)
    stepped.registers = dict(state.registers)
    stepped.slots = dict(state.slots)
    stepped.xmm_pairs = dict(state.xmm_pairs)
    stepped.sp_adjustment = state.sp_adjustment
    for text, span in zip(thunk["prep"], thunk["prep_spans"]):
        model.step(stepped, text, address_span=span)
    return stepped


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
    if not lowered or any(marker in lowered for marker in ("x86_64", "x86-64", "amd64", "x64")):
        fmt = (binary_format or "").lower()
        if "pe" in fmt:
            return X86_WIN64_ARGUMENT_REGISTERS
        if "elf" in fmt or "macho" in fmt:
            return X86_SYSV_ARGUMENT_REGISTERS
    return None


def _callee_resolvers(
    direct_call_targets: list[dict] | None,
) -> tuple[dict, dict, dict, dict, dict[int, str]]:
    """Index the disassembler's resolved call targets for site resolution.

    Returns four maps: call and tail-transfer targets keyed by the emitting
    line (``site_index``), then the same keyed by operand text; plus each
    resolved site's hex ``target_address``, which is how a call into a pure
    thunk is recognised. The line key comes first because ARM branch
    operands are pc-relative (``bl #1280``), so one operand text can name
    different callees at different sites. The operand maps serve entries
    recorded without a line. A key that resolves
    to more than one name is refused: an unresolved callee is a legitimate
    result, a wrong one is not.
    """
    call_sites: dict[int, set[str]] = {}
    tail_sites: dict[int, set[str]] = {}
    call_operands: dict[str, set[str]] = {}
    tail_operands: dict[str, set[str]] = {}
    site_addrs: dict[int, str] = {}
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
        is_tail = entry.get("kind") == "tailcall"
        site_index = entry.get("site_index")
        if isinstance(site_index, int):
            (tail_sites if is_tail else call_sites).setdefault(site_index, set()).add(name)
            address = entry.get("target_address")
            if address and isinstance(address, str):
                site_addrs.setdefault(site_index, address)
        (tail_operands if is_tail else call_operands).setdefault(operand, set()).add(name)
    return call_sites, tail_sites, call_operands, tail_operands, site_addrs


def _call_site_callee(
    model: ArchModel,
    text: str,
    call_sites: dict[int, set[str]],
    tail_sites: dict[int, set[str]],
    call_operands: dict[str, set[str]],
    tail_operands: dict[str, set[str]],
    is_last_line: bool,
    line_index: int | None = None,
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
    sites = tail_sites if kind == "tail" else call_sites
    operands = tail_operands if kind == "tail" else call_operands
    names = sites.get(line_index) if line_index is not None else None
    if not names:
        key = " ".join(parts[1].split()).lower()
        names = operands.get(key)
    if names and len(names) == 1:
        return next(iter(names))
    return None


def _call_site_records(
    lines: list[str],
    model: ArchModel,
    spans: list[tuple[int, int]],
    successors: list[list[int]],
    predecessors: list[list[int]],
    out_states: list[FrameState | None],
    arg_families: tuple[str, ...],
    direct_call_targets: list[dict] | None,
    address_spans: list[tuple[int, int]] | None = None,
    thunks: dict[int, dict] | None = None,
) -> list[dict]:
    """Snapshot the argument registers at every call instruction.

    One replay pass over the converged out-states: each block is re-walked
    once from its final in-state (the same join the worklist computed), and
    a record is taken just before a call instruction is stepped — the model
    clobbers the argument registers at the call itself, so this is the only
    point the incoming arguments are observable. Only integer constants are
    reported; a symbolic pointer or an unknown value yields None for that
    position, never a stale value from before the call sequence. A
    *materialised* pointer — a (``"ptr"``, address) tuple the model folded
    from a pc-relative form when the caller could place the instruction —
    is reported as the address it names, and counted in the record's
    ``materialised`` field (``materialised_page`` for bare pages, which an
    uncompleted ``adrp`` leaves behind). Tail-kind branches step with the
    same leaves-function decision the convergence pass used, and the same
    address spans, so the replayed state matches it exactly.

    When ``thunks`` names pure thunks by start address and the site's
    resolved target is one, the record names the thunk's final callee
    (``callee``), keeps the thunk itself in ``callee_via_thunk``, and the
    arguments are read after the thunk's instructions are stepped over a
    copy of the caller's state.

    The replay is O(lines) time and holds one FrameState at a time; the
    records are O(call sites) small dicts, which is the only extra memory
    retained.
    """
    call_sites, tail_sites, call_operands, tail_operands, site_addrs = _callee_resolvers(
        direct_call_targets
    )
    last_line = len(lines) - 1
    records: list[dict] = []
    for block_index, (start, end) in enumerate(spans):
        if out_states[block_index] is None:
            continue  # unreachable to the dataflow: contributes nothing
        state = _block_in_state(model, block_index, predecessors, out_states)
        if state is None:
            continue
        block_leaves_function = not successors[block_index]
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
                    model,
                    text,
                    call_sites,
                    tail_sites,
                    call_operands,
                    tail_operands,
                    start + offset == last_line,
                    line_index=start + offset,
                )
                via_thunk = None
                thunk = None
                if thunks and callee:
                    address = site_addrs.get(start + offset)
                    if address:
                        with contextlib.suppress(ValueError):
                            thunk = thunks.get(int(address, 16))
                snapshot = state
                if thunk is not None:
                    callee = thunk["callee"]
                    via_thunk = thunk["name"]
                    snapshot = _state_after_thunk(model, state, thunk)
                arguments = []
                pointer_positions = []
                materialised = 0
                materialised_page = 0
                for family in arg_families:
                    value = snapshot.registers.get(family)
                    if isinstance(value, int):
                        arguments.append(value)
                        continue
                    if (
                        isinstance(value, tuple)
                        and value[0] == "ptr"
                        and isinstance(value[1], int)
                    ):
                        pointer_positions.append(len(arguments))
                        arguments.append(value[1])
                        materialised += 1
                        if value[1] % 4096 == 0:
                            # A bare page: an adrp its `add` never completed,
                            # or a target that really is page-aligned. The
                            # page is still what the register held, so it is
                            # reported and counted, never hidden.
                            materialised_page += 1
                        continue
                    arguments.append(None)
                records.append(
                    {
                        "line": start + offset,
                        "instruction": text,
                        "callee": callee,
                        "callee_via_thunk": via_thunk,
                        "registers": tuple(arg_families),
                        "arguments": arguments,
                        "pointer_positions": tuple(pointer_positions),
                        "materialised": materialised,
                        "materialised_page": materialised_page,
                    }
                )
            model.step(
                state,
                text,
                leaves_function=block_leaves_function if offset == end - start - 1 else True,
                address_span=address_spans[start + offset] if address_spans else None,
            )
    return records


def recover_call_site_arguments_with_method(
    func_data: dict,
    arch_target: str = "",
    binary_format: str = "",
    thunks: dict[int, dict] | None = None,
) -> tuple[list[dict], str]:
    """Recover one function's call-site constant arguments via the CFG dataflow.

    Returns ``(records, method)``. Each record names one call instruction
    (``line`` index into the assembly text, ``instruction`` text), the
    ``callee`` the disassembler resolved it to (None when unresolved), the
    ABI's ``registers`` tuple and the integer constants in ``arguments`` at
    that point (None where the model does not know one). A constant the
    model materialised from a pc-relative form (ARM64 ``adrp`` [+ ``add``],
    x86 rip-relative ``lea``) is reported as the address it names, counted
    in the record's ``materialised`` field. ``callee_via_thunk`` names the
    local pure thunk (from :func:`pure_thunk_map`, passed as ``thunks``) a
    call goes through; the record then names the thunk's final callee and
    its arguments as they stand after the thunk. ``method`` names how the
    function was analyzed: ``"dataflow"`` (CFG fixed point),
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
    spans = _block_line_spans(blocks, lines)
    if spans is None:
        return [], "cfg_mismatch"
    # Reconstruct where each line sits so pc-relative materialisations
    # (adrp, rip-relative lea) fold into absolute pointers. A refusal is
    # fine — the model then keeps those registers symbolic, and the block
    # builder counts the reason — but the spans must be the same for the
    # convergence and the replay, or the replayed state would not match.
    address_spans, _ = _line_address_spans(
        model, lines, blocks, spans, func_data.get("instruction_lengths")
    )
    converged = _converge_over_cfg(lines, model, blocks, edges, address_spans=address_spans)
    if converged is None:
        return [], "cap_hit"
    spans, successors, predecessors, out_states = converged
    records = _call_site_records(
        lines,
        model,
        spans,
        successors,
        predecessors,
        out_states,
        arg_families,
        func_data.get("direct_call_targets"),
        address_spans=address_spans,
        thunks=thunks,
    )
    return records, "dataflow"


def recover_call_site_arguments(
    func_data: dict, arch_target: str = "", binary_format: str = ""
) -> list[dict]:
    """Recover one function's call-site constant arguments (see _with_method)."""
    return recover_call_site_arguments_with_method(func_data, arch_target, binary_format)[0]


# ---------------------------------------------------------------------------
# The call-site constant-argument metadata block.
# ---------------------------------------------------------------------------

# Size budget of the exported block, stated up front: the block is the *next per-function emitter* after the CFG
# block listing, and without a bound it would carry a record per call site
# with a constant — tens of thousands on a large Rust binary. The exported
# form is therefore one entry per distinct (callee, argument index, value)
# triple, and the bounds below cap it further. All are named when they trip,
# in the coverage counters, never silently.
#
# BLINT_MAX_CALLSITE_ARGUMENTS overrides the per-binary entry bound; 0
# disables the block entirely.
MAX_CALLSITE_ARGUMENT_ENTRIES = 4096
# Distinct entries a single function may contribute before the rest of its
# constants are counted as truncated. A function contributing hundreds of
# distinct constants is initialising data through calls, not expressing
# capability-relevant arguments.
MAX_CALLSITE_ENTRIES_PER_FUNCTION = 256
# Citing functions kept per entry; the full reach stays in ``site_count``.
MAX_CALLSITE_SITES_PER_ENTRY = 3
# Keep at most this many function names in the coverage counter that names
# the functions whose contributions were cut by the per-function cap.
MAX_NAMED_CAPPED_FUNCTIONS = 20
# A plain integer below this is a flag, size or count, so it is never offered
# to the string resolver. A materialised pointer is an address by
# construction and is offered wherever it lands: a shared object maps its
# read-only data from address zero, often well below this bound.
MIN_PLAIN_POINTER_VALUE = 0x10000


def _wide_terminated_prefix(data: bytes) -> bytes:
    """Return the bytes up to the first aligned UTF-16 NUL terminator.

    Pairs are formed from the first byte of the run, so the terminator is a
    ``\\x00\\x00`` at an even offset — the same bytes straddling odd offsets
    are data, not a terminator. A run with no terminator yields its
    even-length prefix: a trailing odd byte cannot be half of a character,
    which is :func:`_decode_one`'s rule for the same situation.
    """
    end = len(data) - (len(data) % 2)
    for i in range(0, end, 2):
        if data[i] == 0 and data[i + 1] == 0:
            return data[:i]
    return data[:end]


def decode_pointer_string(data: bytes, min_length: int = 4) -> str | None:
    """Decode the NUL-terminated text run at the start of ``data``.

    The shared decoder for naming what a recovered call-site constant points
    at, reading both encodings a pointed-at literal uses — ASCII and
    UTF-16LE — under the stack-string decoder's policy (:func:`_decode_run`):
    both encodings are tried and the longer valid reading kept, the wide
    attempt waits for ``min_length * 2`` bytes (a wide character costs two),
    and the same character filter applies (:func:`_looks_like_text`), with a
    longer minimum than the stack-string path because a constant that happens
    to land on three printable bytes is too easy to manufacture. The minimum
    counts decoded characters for both encodings. The two encodings cannot
    both be valid: the filter is ASCII-only, so a valid wide reading forces
    every high byte to zero and truncates the ASCII reading at one byte,
    while a valid ASCII reading puts a non-zero byte inside the first wide
    pair. Byte order is LE only, matching the decoder this policy comes from
    and every Windows target the dataflow recovers constants for.

    The terminator is located *before* decoding, unlike :func:`_decode_one`,
    which decodes its whole input and splits afterwards: a pointer read is a
    fixed-size window that continues past the string into whatever follows it
    in the section, and under a whole-run decode a non-ASCII byte after an
    ASCII string's NUL — or a lone surrogate after a wide string's — would
    veto an otherwise valid reading. Returns None when the bytes do not read
    as text in either encoding.
    """
    if not data:
        return None
    best: str | None = None
    for encoding in ("utf-16-le", "ascii"):
        if encoding == "utf-16-le":
            if len(data) < min_length * 2:
                continue
            usable = _wide_terminated_prefix(data)
        else:
            nul = data.find(b"\x00")
            usable = data if nul == -1 else data[:nul]
        try:
            text = usable.decode(encoding)
        except (UnicodeDecodeError, ValueError):
            continue
        if len(text) < min_length or not _looks_like_text(text):
            continue
        if best is None or len(text) > len(best):
            best = text
    return best


def analyze_call_site_arguments(
    disassembled_functions: dict | None,
    arch_target: str = "",
    binary_format: str = "",
    resolve_string: Callable[[int], str | None] | None = None,
    max_entries: int | None = None,
) -> tuple[list[dict], dict]:
    """Aggregate call-site constant arguments into the exported metadata block.

    Runs :func:`recover_call_site_arguments_with_method` per disassembled
    function and folds the per-site records into one entry per distinct
    ``(callee, argument, value)`` triple, keeping the first citation as the
    example and counting the rest. Records with an unresolved callee
    contribute a counter, not an entry: an integer constant with no resolved
    destination is the noise this block exists to keep out of reports.

    ``resolve_string``, when given, is called once per distinct constant that
    could be an address (a materialised pointer, or a plain integer of at
    least :data:`MIN_PLAIN_POINTER_VALUE`) and may return the string its
    value points at (the caller owns the
    section-level answer; this module deliberately knows nothing about
    sections). ``max_entries`` bounds the block and defaults to the
    ``BLINT_MAX_CALLSITE_ARGUMENTS`` environment value or
    :data:`MAX_CALLSITE_ARGUMENT_ENTRIES`; ``0`` disables the block, and a
    tripped bound is reported in the coverage counters.

    Returns ``(entries, coverage)``. Every way this can fail to recover a
    constant is a named coverage counter — no silent gaps.
    """
    if max_entries is None:
        max_entries = get_int_from_env(
            "BLINT_MAX_CALLSITE_ARGUMENTS", MAX_CALLSITE_ARGUMENT_ENTRIES
        )
    coverage = {
        "functions_total": 0,
        "functions_dataflow": 0,
        "functions_no_cfg": 0,
        "functions_cfg_mismatch": 0,
        "functions_cap_hit": 0,
        "functions_no_abi": 0,
        "functions_skipped": 0,
        "functions_entries_capped": 0,
        "records_unresolved_callee": 0,
        # Pointer materialisation: every way a pc-relative
        # materialisation can fail to light up is named here, never silent.
        "functions_no_line_addresses": 0,
        "functions_extent_mismatch": 0,
        "functions_unmodelled_pc_relative": 0,
        "arguments_materialised": 0,
        "pointer_values_page_only": 0,
        "strings_resolved": 0,
        "max_entries": max(0, max_entries),
    }
    if not max_entries or not disassembled_functions:
        coverage["functions_total"] = len(disassembled_functions or {})
        return [], coverage

    aggregated: dict[tuple[str, int, int], dict] = {}
    truncated_by_function: list[str] = []
    truncated = False
    model = model_for_target(arch_target)
    thunks = pure_thunk_map(disassembled_functions, arch_target)
    for func_key, func_data in disassembled_functions.items():
        if not isinstance(func_data, dict):
            continue
        coverage["functions_total"] += 1
        records, method = recover_call_site_arguments_with_method(
            func_data, arch_target, binary_format, thunks=thunks
        )
        if method == "dataflow":
            coverage["functions_dataflow"] += 1
        elif f"functions_{method}" in coverage:
            coverage[f"functions_{method}"] += 1
        if method != "dataflow":
            continue
        _count_materialisation_coverage(coverage, func_data, model)
        coverage["arguments_materialised"] += sum(
            record.get("materialised") or 0 for record in records
        )
        coverage["pointer_values_page_only"] += sum(
            record.get("materialised_page") or 0 for record in records
        )
        function_name = str(func_data.get("name") or func_key)
        contributed = 0
        function_capped = False
        for record in records:
            callee = record.get("callee")
            if not callee:
                coverage["records_unresolved_callee"] += len(
                    [value for value in record.get("arguments", []) if value is not None]
                )
                continue
            pointer_positions = record.get("pointer_positions") or ()
            for argument, value in enumerate(record.get("arguments") or []):
                if value is None:
                    continue
                key = (callee, argument, value)
                if key in aggregated:
                    aggregated[key]["site_count"] += 1
                    if argument in pointer_positions:
                        aggregated[key]["pointer"] = True
                    if (
                        len(aggregated[key]["functions"]) < MAX_CALLSITE_SITES_PER_ENTRY
                        and function_name not in aggregated[key]["functions"]
                    ):
                        aggregated[key]["functions"].append(function_name)
                    continue
                if truncated:
                    continue
                if contributed >= MAX_CALLSITE_ENTRIES_PER_FUNCTION:
                    if not function_capped:
                        function_capped = True
                        coverage["functions_entries_capped"] += 1
                        if len(truncated_by_function) < MAX_NAMED_CAPPED_FUNCTIONS:
                            truncated_by_function.append(function_name)
                    continue
                contributed += 1
                aggregated[key] = {
                    "callee": callee,
                    "argument": argument,
                    "value": value,
                    "site_count": 1,
                    "functions": [function_name],
                    "example": {
                        "function": function_name,
                        "line": record.get("line"),
                        "instruction": record.get("instruction"),
                    },
                    "pointer": argument in pointer_positions,
                    "callee_via_thunk": record.get("callee_via_thunk"),
                }
                if len(aggregated) >= max_entries:
                    truncated = True
    if truncated:
        coverage["entries_truncated"] = True
    if truncated_by_function:
        coverage["functions_entries_capped_names"] = truncated_by_function

    resolved: dict[int, str | None] = {}
    entries: list[dict] = []
    for key in sorted(aggregated, key=lambda k: (k[0].lower(), k[1], k[2])):
        item = aggregated[key]
        entry = {
            "callee": item["callee"],
            "argument": item["argument"],
            "value": item["value"],
            "site_count": item["site_count"],
            "functions": list(item["functions"]),
            "example": item["example"],
        }
        if item.get("callee_via_thunk"):
            # The first citation's thunk, like its example; later sites into
            # the same callee fold in and are counted by site_count.
            entry["callee_via_thunk"] = item["callee_via_thunk"]
        if resolve_string is not None and (
            item["pointer"] or item["value"] >= MIN_PLAIN_POINTER_VALUE
        ):
            if item["value"] not in resolved:
                resolved[item["value"]] = resolve_string(item["value"])
            if string := resolved[item["value"]]:
                entry["string"] = string
        entries.append(entry)
    coverage["entries"] = len(entries)
    coverage["strings_resolved"] = sum(1 for entry in entries if entry.get("string"))
    return entries, coverage


def _count_materialisation_coverage(coverage: dict, func_data: dict, model: ArchModel) -> None:
    """Name how this function's pc-relative materialisations fared.

    Only functions whose listing actually carries an address-materialising
    form are counted: an ``adrp`` on ARM64 or a rip-relative ``lea`` on
    x86. When the line addresses those forms need could not be
    reconstructed, the reason is counted (``functions_no_line_addresses``
    for blocks without usable VAs or without the exported lengths;
    ``functions_extent_mismatch`` when a block's extent contradicted the
    strides its lines claim). An ``adr`` — ARM64's other pc-relative form,
    which the model deliberately does not fold — is counted as
    ``functions_unmodelled_pc_relative`` so its silence is named.
    """
    assembly = str(func_data.get("assembly") or "")
    if not assembly:
        return
    if isinstance(model, Arm64Model):
        candidates = assembly.count("adrp")
        unmodelled = re.search(r"(?<![\w.])adr\s", assembly) is not None
    elif isinstance(model, X86_64Model):
        candidates = len(re.findall(r"lea\s+[^\s,]+,\s*\[\s*rip", assembly, re.IGNORECASE))
        unmodelled = False
    else:
        return
    if unmodelled:
        coverage["functions_unmodelled_pc_relative"] += 1
    if not candidates:
        return
    lines = assembly.split("\n")
    blocks = (func_data.get("cfg") or {}).get("blocks") or []
    spans = _block_line_spans(blocks, lines)
    if spans is None:
        return  # already counted as functions_cfg_mismatch
    _, reason = _line_address_spans(
        model, lines, blocks, spans, func_data.get("instruction_lengths")
    )
    if reason == "extent_mismatch":
        coverage["functions_extent_mismatch"] += 1
    elif reason == "no_addresses":
        coverage["functions_no_line_addresses"] += 1


# 32-bit x86 triples: i386/i486/i586/i686 and the bare ia32. Everything
# else non-aarch64 (including the empty triple) stays x86-64, as before.
_I386_TARGET_MARKERS = ("i386", "i486", "i586", "i686", "ia32")


def model_for_target(arch_target: str) -> ArchModel:
    """Pick the architecture model for an LLVM triple or Mach-O cpu name."""
    lowered = (arch_target or "").lower()
    if "aarch64" in lowered or "arm64" in lowered:
        return ARM64_MODEL
    arch = lowered.split("-", 1)[0]
    # 32-bit ARM and Thumb triples (arm*/thumb*, armeb/thumbeb included) -
    # never aarch64/arm64, which matched above.
    if arch.startswith(("arm", "thumb")):
        return ARM32_MODEL
    if any(marker in lowered for marker in ("x86_64", "x86-64", "amd64", "x64")):
        return X86_64_MODEL
    if any(marker in lowered for marker in _I386_TARGET_MARKERS):
        return I386_MODEL
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
