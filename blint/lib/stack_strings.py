"""Recovery of string literals a binary builds at runtime instead of storing.

An implant that never stores its device paths, registry keys or module names as
literals defeats every string-based review, because there is nothing in
``.rdata`` to match. The strings still exist - they are just assembled into a
stack buffer one word at a time, from immediates the compiler folded into
arithmetic. SLEEPWALKER builds ``\\\\.\\VMCI`` this way:

    mov  ecx, 92                    ; '\\'
    mov  dword ptr [rbp - 28], 6029358
    lea  eax, [rcx - 15]            ; 'M'
    mov  word ptr [rbp - 32], cx
    mov  word ptr [rbp - 22], ax
    ...

Recovering it needs no emulation of the whole function, only a forward pass that
tracks integer register values and the stores they feed. That is what this module
does: a deliberately small abstract interpreter over the linear instruction
listing, with no control-flow awareness.

The limits follow from that. A string assembled across a loop or a branch is not
recovered, values arriving from memory or a call are unknown, and a frame slot
overwritten later yields whatever the last store put there. Recovered strings are
therefore evidence to confirm, not ground truth - but a false positive is
expensive here, so the decoder only accepts runs that actually look like text.
"""

import re
from collections.abc import Iterator

# Register families, so `mov ecx, 92` followed by `mov word ptr [...], cx` is
# understood as storing the low half of the same value. The width is what decides
# how many bytes a register-sourced store writes.
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

_REGISTER_INFO: dict[str, tuple[str, int]] = {}
for _family, _members in _REGISTER_FAMILIES:
    for _name, _width in _members:
        _REGISTER_INFO[_name] = (_family, _width)
for _index in range(8, 16):
    _REGISTER_INFO[f"r{_index}"] = (f"r{_index}", 8)
    _REGISTER_INFO[f"r{_index}d"] = (f"r{_index}", 4)
    _REGISTER_INFO[f"r{_index}w"] = (f"r{_index}", 2)
    _REGISTER_INFO[f"r{_index}b"] = (f"r{_index}", 1)

# Registers that address the stack frame. A store through one of these is a frame
# slot; a store through any other register goes to a heap or parameter object this
# pass cannot locate, so it is ignored rather than guessed at.
_FRAME_REGISTERS: frozenset[str] = frozenset({"rbp", "rsp"})

_SIZE_HINTS: dict[str, int] = {"byte": 1, "word": 2, "dword": 4, "qword": 8}

# Immediates appear in whichever base the disassembler was configured for; blint
# defaults to decimal. See the IMMEDIATE_RE note in driver_ioctl for why all
# three renderings have to be accepted.
_IMM = r"(?:-?(?:0x[0-9a-fA-F]+|[0-9][0-9a-fA-F]*h|[0-9]+))"
_REG = r"[a-z][a-z0-9]*"

_MOV_REG_IMM_RE = re.compile(rf"^\s*mov\s+({_REG})\s*,\s*({_IMM})\s*$", re.I)
_MOV_REG_REG_RE = re.compile(
    rf"^\s*(?:mov|movzx|movsx|movsxd)\s+({_REG})\s*,\s*({_REG})\s*$", re.I
)
_XOR_SELF_RE = re.compile(rf"^\s*xor\s+({_REG})\s*,\s*({_REG})\s*$", re.I)
_ARITH_REG_IMM_RE = re.compile(rf"^\s*(add|sub|or|and|xor)\s+({_REG})\s*,\s*({_IMM})\s*$", re.I)
# `lea eax, [rcx - 15]` is how a compiler folds "this character minus that one"
# into a single instruction; it is the workhorse of arithmetic string building.
_LEA_RE = re.compile(
    rf"^\s*lea\s+({_REG})\s*,\s*\[\s*({_REG})\s*(?:([+-])\s*({_IMM})\s*)?\]\s*$", re.I
)
# A store into a frame slot, with the value either an immediate or a register.
_STORE_RE = re.compile(
    rf"^\s*mov\s+(?:(byte|word|dword|qword)\s+ptr\s+)?"
    rf"\[\s*({_REG})\s*([+-])\s*({_IMM})\s*\]\s*,\s*({_IMM}|{_REG})\s*$",
    re.I,
)
# Any other instruction writing a register invalidates what is known about it.
_DEST_REG_RE = re.compile(
    rf"^\s*(?:{'|'.join(('mov', 'movzx', 'movsx', 'movsxd', 'lea', 'add', 'sub', 'or', 'and', 'xor', 'imul', 'mul', 'shl', 'shr', 'sar', 'rol', 'ror', 'not', 'neg', 'inc', 'dec', 'pop', 'cmov[a-z]+', 'set[a-z]+', 'bswap', 'div', 'idiv'))})"
    rf"\s+({_REG})\s*(?:,|$)",
    re.I,
)

# Registers a call clobbers under the Microsoft x64 and SysV ABIs combined. After
# a call, anything volatile in either convention has to be treated as unknown.
_CALL_CLOBBERED: frozenset[str] = frozenset(
    {"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"}
)

# Shortest run of bytes accepted as a recovered string. Three characters is long
# enough to exclude the two-byte fragments that ordinary struct initialisation
# leaves in a frame, while keeping short but meaningful values.
MIN_RECOVERED_LEN = 3
# A single function should not yield an unbounded number of candidates; a frame
# holding more than this many distinct string runs is initialising data, not
# building text.
MAX_RUNS_PER_FUNCTION = 64
# Instruction budget per function. Arithmetic string building is a prologue
# activity, and scanning entire large functions costs more than it recovers.
MAX_INSTRUCTIONS = 4000


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


def _register(name: str) -> tuple[str, int] | None:
    """Return the (family, width) of a register operand, or None if unrecognised."""
    return _REGISTER_INFO.get(name.strip().lower())


class _FrameState:
    """Register values and frame-slot bytes observed so far in one function."""

    def __init__(self) -> None:
        # Family name -> full 64-bit value currently held.
        self.registers: dict[str, int] = {}
        # (frame register, signed offset) -> byte value.
        self.slots: dict[tuple[str, int], int] = {}

    def set_register(self, name: str, value: int) -> None:
        info = _register(name)
        if not info:
            return
        family, width = info
        # Writing a sub-register leaves the upper bytes of the family intact,
        # except for the 32-bit forms, which zero-extend on x86-64.
        if width == 8 or width == 4:
            self.registers[family] = value & ((1 << (width * 8)) - 1)
            return
        previous = self.registers.get(family)
        if previous is None:
            return
        mask = (1 << (width * 8)) - 1
        self.registers[family] = (previous & ~mask) | (value & mask)

    def get_register(self, name: str) -> tuple[int, int] | None:
        """Return the (value, width) a register operand currently reads as."""
        info = _register(name)
        if not info:
            return None
        family, width = info
        value = self.registers.get(family)
        if value is None:
            return None
        return value & ((1 << (width * 8)) - 1), width

    def invalidate(self, name: str) -> None:
        info = _register(name)
        if info:
            self.registers.pop(info[0], None)

    def store(self, base: str, offset: int, value: int, width: int) -> None:
        for index in range(width):
            self.slots[(base, offset + index)] = (value >> (index * 8)) & 0xFF


def _interpret(lines: list[str]) -> _FrameState:
    """Run the forward pass, returning the frame state it accumulated."""
    state = _FrameState()
    for line in lines[:MAX_INSTRUCTIONS]:
        text = line.strip()
        if not text:
            continue
        if text.startswith("call") or text.startswith("jmp"):
            # A call returns a value in rax and destroys the volatile registers;
            # keeping stale values across it is how a reconstruction goes wrong.
            for family in _CALL_CLOBBERED:
                state.registers.pop(family, None)
            continue

        if store := _STORE_RE.match(text):
            size_hint, base_reg, sign, offset_token, value_token = store.groups()
            _apply_store(state, size_hint, base_reg, sign, offset_token, value_token)
            continue

        if match := _MOV_REG_IMM_RE.match(text):
            value = _parse_immediate(match.group(2))
            if value is None:
                state.invalidate(match.group(1))
            else:
                state.set_register(match.group(1), value)
            continue

        if match := _XOR_SELF_RE.match(text):
            if match.group(1).lower() == match.group(2).lower():
                state.set_register(match.group(1), 0)
                continue

        if match := _MOV_REG_REG_RE.match(text):
            source = state.get_register(match.group(2))
            if source is None:
                state.invalidate(match.group(1))
            else:
                state.set_register(match.group(1), source[0])
            continue

        if match := _LEA_RE.match(text):
            _apply_lea(state, match)
            continue

        if match := _ARITH_REG_IMM_RE.match(text):
            _apply_arith(state, match)
            continue

        # Anything else that writes a register makes its value unknown. Being
        # conservative here is what stops a stale value from being decoded as a
        # character it never was.
        if match := _DEST_REG_RE.match(text):
            state.invalidate(match.group(1))
    return state


def _apply_store(
    state: _FrameState,
    size_hint: str | None,
    base_reg: str,
    sign: str,
    offset_token: str,
    value_token: str,
) -> None:
    """Apply one `mov [frame +/- offset], value` to the frame state."""
    base_info = _register(base_reg)
    if not base_info or base_info[0] not in _FRAME_REGISTERS:
        return
    offset = _parse_immediate(offset_token)
    if offset is None:
        return
    if sign == "-":
        offset = -offset

    immediate = _parse_immediate(value_token)
    if immediate is not None and not _register(value_token):
        width = _SIZE_HINTS.get((size_hint or "").lower())
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
        width = _SIZE_HINTS.get((size_hint or "").lower()) or 1
        for index in range(width):
            state.slots.pop((base_info[0], offset + index), None)
        return
    value, width = source
    # An explicit size hint overrides the register width, which matters for the
    # `mov byte ptr [rbp-8], al` form.
    width = _SIZE_HINTS.get((size_hint or "").lower(), width)
    state.store(base_info[0], offset, value, width)


def _apply_lea(state: _FrameState, match: re.Match) -> None:
    """Apply `lea dest, [src +/- imm]`, the folded arithmetic form."""
    dest, source_reg, sign, offset_token = match.groups()
    source_info = _register(source_reg)
    # `lea rcx, [rbp - 32]` takes the address of the frame slot rather than
    # computing a character, so the destination holds a pointer, not a value.
    if source_info and source_info[0] in _FRAME_REGISTERS:
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
    state.set_register(dest, (source[0] + delta) & 0xFFFFFFFFFFFFFFFF)


def _apply_arith(state: _FrameState, match: re.Match) -> None:
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
    state.set_register(register, result & 0xFFFFFFFFFFFFFFFF)


def _contiguous_runs(state: _FrameState) -> Iterator[tuple[str, int, bytes]]:
    """Yield (frame register, start offset, bytes) for each contiguous byte run."""
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


def recover_function_stack_strings(func_data: dict) -> list[dict]:
    """Recover string literals a single disassembled function builds on its stack."""
    assembly = func_data.get("assembly") or ""
    if not assembly:
        return []
    return _decode_runs(_contiguous_runs(_interpret(assembly.split("\n"))))


def recover_stack_strings(disassembled_functions: dict | None) -> list[dict]:
    """Recover stack-built string literals across every disassembled function.

    Returns one entry per distinct value, naming the function it was built in so
    a reviewer can go straight to the reconstruction and confirm it.
    """
    if not disassembled_functions:
        return []
    recovered: list[dict] = []
    seen: set[str] = set()
    for func_key, func_data in disassembled_functions.items():
        for entry in recover_function_stack_strings(func_data):
            lowered = entry["value"].lower()
            if lowered in seen:
                continue
            seen.add(lowered)
            recovered.append(
                {
                    **entry,
                    "function": func_data.get("name", func_key),
                    "address": func_data.get("address"),
                }
            )
    recovered.sort(key=lambda entry: entry["value"].lower())
    return recovered
