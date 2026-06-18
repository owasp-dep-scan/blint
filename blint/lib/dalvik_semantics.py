"""
Instruction-level semantics for decoded Dalvik bytecode.

:mod:`blint.lib.dalvik` decodes bytecode *structurally* (opcode, format,
register operands, literal/branch/index). This module adds the *meaning* of each
instruction that higher analyses need without re-matching on mnemonic strings:

- behaviour classification (is this a call, a return, a branch, a field access,
  a move-result, …) via :class:`OpFlags`,
- which registers an instruction defines (writes) and uses (reads), with wide
  (64-bit) operands correctly expanded to the register *pair* they occupy.

Everything here is a pure function of a single :class:`~blint.lib.dalvik.Instruction`;
there is no state. The register-role logic follows the operand semantics in the
Dalvik bytecode specification, including the cases where wideness differs between
operands of the same instruction (for example ``shl-long`` whose shift amount is
a 32-bit ``int`` while its value and result are 64-bit ``long``).
"""

from enum import Flag, auto
from typing import List, Tuple

from blint.lib.dalvik import Instruction


class OpFlags(Flag):
    """Behavioural classification flags for a Dalvik opcode."""

    NONE = 0
    INVOKE = auto()  # invoke-* / invoke-polymorphic / invoke-custom
    RETURN = auto()  # return / return-void / return-*
    THROW = auto()  # throw
    MOVE_RESULT = auto()  # move-result* (consumes the previous invoke's result)
    GOTO = auto()  # unconditional branch
    IF = auto()  # conditional branch
    SWITCH = auto()  # packed-/sparse-switch
    FIELD_READ = auto()  # iget*/sget*
    FIELD_WRITE = auto()  # iput*/sput*
    ARRAY_READ = auto()  # aget*
    ARRAY_WRITE = auto()  # aput*
    NEW_INSTANCE = auto()  # new-instance
    NEW_ARRAY = auto()  # new-array / filled-new-array
    CONST = auto()  # const* (numeric/string/class/method-handle/method-type)
    MONITOR = auto()  # monitor-enter / monitor-exit
    # A control-flow terminator: nothing falls through to the next instruction.
    TERMINATOR = auto()


# Opcodes whose primary destination register (operand 0) is a 64-bit value and
# therefore occupies a register pair (vN, vN+1).
_WIDE_DEST = frozenset(
    {
        0x04,
        0x05,
        0x06,  # move-wide*
        0x0B,  # move-result-wide
        0x16,
        0x17,
        0x18,
        0x19,  # const-wide*
        0x45,  # aget-wide
        0x53,  # iget-wide
        0x61,  # sget-wide
        0x7D,
        0x7E,
        0x80,  # neg-long, not-long, neg-double
        0x81,
        0x83,
        0x86,
        0x88,
        0x89,
        0x8B,  # int/long/float/double -> long/double conversions
    }
)


def _pair(reg: int) -> List[int]:
    """A wide operand occupies the register and its successor."""
    return [reg, reg + 1]


def flags(opcode: int) -> OpFlags:
    """Return the :class:`OpFlags` classification for an opcode byte."""
    return _FLAGS.get(opcode, OpFlags.NONE)


def is_invoke(inst: Instruction) -> bool:
    """True for every call instruction (virtual/super/direct/static/interface,
    range forms, polymorphic and custom)."""
    return bool(_FLAGS.get(inst.opcode, OpFlags.NONE) & OpFlags.INVOKE)


def is_terminator(inst: Instruction) -> bool:
    """True when control does not fall through to the following instruction."""
    return bool(_FLAGS.get(inst.opcode, OpFlags.NONE) & OpFlags.TERMINATOR)


def is_branch_source(inst: Instruction) -> bool:
    """True for goto / conditional-if / switch instructions."""
    return bool(
        _FLAGS.get(inst.opcode, OpFlags.NONE) & (OpFlags.GOTO | OpFlags.IF | OpFlags.SWITCH)
    )


def register_roles(inst: Instruction) -> Tuple[List[int], List[int]]:
    """
    Compute the (defs, uses) register sets for an instruction.

    ``defs`` are the registers written, ``uses`` the registers read, both with
    wide operands expanded to their register pair. Pool indices, literals and
    branch offsets are not registers and are excluded. For call-style
    instructions (invoke / filled-new-array) every operand register is a use;
    their result, if any, is written by a following ``move-result*``.
    """
    op = inst.opcode
    regs = inst.registers
    if not regs:
        return [], []

    # Calls and filled-new-array: all operand registers are arguments (uses).
    fl = _FLAGS.get(op, OpFlags.NONE)
    if fl & OpFlags.INVOKE or op in (0x24, 0x25):
        return [], list(regs)

    defs, uses = _arithmetic_roles(op, regs)
    if defs is not None:
        return defs, uses
    return _other_roles(op, regs)


def _arithmetic_roles(op: int, regs: List[int]):
    """Roles for the regular ALU / conversion / move / const families.

    Returns ``(defs, uses)`` or ``(None, None)`` when ``op`` is not handled here
    (the caller then falls back to :func:`_other_roles`).
    """
    r0 = regs[0]
    # Binary ops vAA, vBB, vCC (0x90-0xAF): dest + two sources.
    if 0x90 <= op <= 0xAF:
        wide = (0x9B <= op <= 0xA5) or (0xAB <= op <= 0xAF)  # long or double
        d = _pair(r0) if wide else [r0]
        b = _pair(regs[1]) if wide else [regs[1]]
        # shl/shr/ushr-long take a 32-bit int shift amount in the third operand.
        c_single = op in (0xA3, 0xA4, 0xA5)
        c = [regs[2]] if (not wide or c_single) else _pair(regs[2])
        return d, b + c
    # Binary /2addr vA, vB (0xB0-0xCF): dest is also a source.
    if 0xB0 <= op <= 0xCF:
        wide = (0xBB <= op <= 0xC5) or (0xCB <= op <= 0xCF)
        d = _pair(r0) if wide else [r0]
        b_single = op in (0xC3, 0xC4, 0xC5)  # shl/shr/ushr-long/2addr shift amount
        b = [regs[1]] if (not wide or b_single) else _pair(regs[1])
        return d, d + b
    # Binary literal vA, vB, #lit (0xD0-0xE2): single dest + single source.
    if 0xD0 <= op <= 0xE2:
        return [r0], [regs[1]]
    # Unary ops and primitive conversions vA, vB (0x7B-0x8F).
    if 0x7B <= op <= 0x8F:
        d = _pair(r0) if op in _WIDE_DEST else [r0]
        src_wide = op in (0x84, 0x85, 0x86, 0x8A, 0x8B, 0x8C) or op in (0x7D, 0x7E, 0x80)
        u = _pair(regs[1]) if src_wide else [regs[1]]
        return d, u
    return None, None


def _other_roles(op: int, regs: List[int]):
    """Roles for non-ALU opcodes (moves, const, mem access, compares, ifs)."""
    r0 = regs[0]
    wide_dest = op in _WIDE_DEST
    # move / move-object (single) and move-wide (pair): dest <- source.
    if op in (0x01, 0x02, 0x03, 0x07, 0x08, 0x09):
        return [r0], [regs[1]]
    if op in (0x04, 0x05, 0x06):
        return _pair(r0), _pair(regs[1])
    # move-result* / move-exception: pure definition (value comes from elsewhere).
    if op in (0x0A, 0x0C, 0x0D):
        return [r0], []
    if op == 0x0B:
        return _pair(r0), []
    # return* read their operand; return-void has no registers (handled earlier).
    if op in (0x0F, 0x11):
        return [], [r0]
    if op == 0x10:
        return [], _pair(r0)
    # const* define a register (pair for the wide forms).
    if op in (0x12, 0x13, 0x14, 0x15, 0x1A, 0x1B, 0x1C, 0xFE, 0xFF):
        return [r0], []
    if op in (0x16, 0x17, 0x18, 0x19):
        return _pair(r0), []
    # monitor-enter/exit, throw, fill-array-data, switch: read one register.
    if op in (0x1D, 0x1E, 0x27, 0x26, 0x2B, 0x2C):
        return [], [r0]
    # check-cast reads the register (its declared type narrows, value unchanged).
    if op == 0x1F:
        return [], [r0]
    # instance-of / array-length / new-array: dest <- source.
    if op in (0x20, 0x21, 0x23):
        return [r0], [regs[1]]
    # new-instance: pure definition.
    if op == 0x22:
        return [r0], []
    # compares vAA, vBB, vCC: int dest, two sources (wide for long/double).
    if 0x2D <= op <= 0x31:
        src_wide = op in (0x2F, 0x30, 0x31)  # cmpl/cmpg-double, cmp-long
        b = _pair(regs[1]) if src_wide else [regs[1]]
        c = _pair(regs[2]) if src_wide else [regs[2]]
        return [r0], b + c
    # if-eq..if-le read two registers; if-eqz..if-lez read one.
    if 0x32 <= op <= 0x37:
        return [], [r0, regs[1]]
    if 0x38 <= op <= 0x3D:
        return [], [r0]
    # aget*: dest <- array[index]; aget-wide dest is a pair.
    if 0x44 <= op <= 0x4A:
        d = _pair(r0) if wide_dest else [r0]
        return d, [regs[1], regs[2]]
    # aput*: array[index] <- value; aput-wide value is a pair.
    if 0x4B <= op <= 0x51:
        v = _pair(r0) if op == 0x4C else [r0]
        return [], v + [regs[1], regs[2]]
    # iget*: dest <- obj.field; iget-wide dest is a pair.
    if 0x52 <= op <= 0x58:
        d = _pair(r0) if wide_dest else [r0]
        return d, [regs[1]]
    # iput*: obj.field <- value; iput-wide value is a pair.
    if 0x59 <= op <= 0x5F:
        v = _pair(r0) if op == 0x5A else [r0]
        return [], v + [regs[1]]
    # sget*: dest <- static field; sget-wide dest is a pair.
    if 0x60 <= op <= 0x66:
        d = _pair(r0) if wide_dest else [r0]
        return d, []
    # sput*: static field <- value; sput-wide value is a pair.
    if 0x67 <= op <= 0x6D:
        v = _pair(r0) if op == 0x68 else [r0]
        return [], v
    return [], []


def _build_flags() -> dict:
    """Build the opcode -> OpFlags table once at import time."""
    table: dict = {}

    def mark(opcodes, fl):
        for op in opcodes:
            table[op] = table.get(op, OpFlags.NONE) | fl

    mark(range(0x6E, 0x73), OpFlags.INVOKE)  # invoke-virtual..interface
    mark(range(0x74, 0x79), OpFlags.INVOKE)  # invoke-*/range
    mark((0xFA, 0xFB, 0xFC, 0xFD), OpFlags.INVOKE)  # polymorphic / custom
    mark(range(0x0E, 0x12), OpFlags.RETURN | OpFlags.TERMINATOR)  # return*
    mark((0x27,), OpFlags.THROW | OpFlags.TERMINATOR)  # throw
    mark(range(0x0A, 0x0E), OpFlags.MOVE_RESULT)  # move-result* / move-exception
    mark((0x28, 0x29, 0x2A), OpFlags.GOTO | OpFlags.TERMINATOR)  # goto*
    mark(range(0x32, 0x3E), OpFlags.IF)  # if-* (fall through, not a terminator)
    mark((0x2B, 0x2C), OpFlags.SWITCH)  # packed-/sparse-switch
    mark(range(0x52, 0x59), OpFlags.FIELD_READ)  # iget*
    mark(range(0x60, 0x67), OpFlags.FIELD_READ)  # sget*
    mark(range(0x59, 0x60), OpFlags.FIELD_WRITE)  # iput*
    mark(range(0x67, 0x6E), OpFlags.FIELD_WRITE)  # sput*
    mark(range(0x44, 0x4B), OpFlags.ARRAY_READ)  # aget*
    mark(range(0x4B, 0x52), OpFlags.ARRAY_WRITE)  # aput*
    mark((0x22,), OpFlags.NEW_INSTANCE)
    mark((0x23, 0x24, 0x25), OpFlags.NEW_ARRAY)
    mark(range(0x12, 0x1D), OpFlags.CONST)  # const* (numeric/string/class)
    mark((0xFE, 0xFF), OpFlags.CONST)  # const-method-handle / const-method-type
    mark((0x1D, 0x1E), OpFlags.MONITOR)
    return table


_FLAGS: dict = _build_flags()
