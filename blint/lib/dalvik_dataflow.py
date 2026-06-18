"""
Intraprocedural data-flow analysis for a decoded Dalvik method.

This is the layer that turns a structurally-decoded, control-flow-aware method
into *semantic* facts. It runs a forward, flow-sensitive analysis over the CFG
that tracks an abstract value per register:

- numeric constants (``const*``),
- string constants (``const-string``) resolved to their text,
- class / method-handle / method-type references (``const-class`` etc.),
- the result of a call (``invoke*`` -> ``move-result*`` linking),
- copies through ``move*``.

From that it derives the facts reviews actually want:

- :class:`CallSite` for every invoke, with each argument's resolved abstract
  value (so a concrete string flowing into a sink is visible at the call),
- the bytes loaded by ``fill-array-data`` (embedded keys / payloads),
- the register state immediately before any instruction (reaching constants).

Values merge to "unknown" at control-flow joins where predecessors disagree, so
a reported constant argument is one that holds on *every* path to the call.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from blint.lib.dalvik import DexPools, Instruction
from blint.lib.dalvik_cfg import CFG, build_cfg
from blint.lib.dalvik_semantics import is_invoke, register_roles

# Abstract value kinds.
INT = "int"
WIDE = "wide"
STRING = "string"
CLASS = "class"
METHOD_REF = "method-ref"  # const-method-handle / const-method-type
NEW_INSTANCE = "new-instance"
INVOKE_RESULT = "invoke-result"
ARRAY = "array"
WIDE_HIGH = "wide-high"  # the upper half of a wide register pair


@dataclass(frozen=True)
class AbstractValue:
    """A flow-sensitive abstract value held by a register at a program point."""

    kind: str
    value: object = None  # int for INT/WIDE, descriptor str for STRING/CLASS/...

    def as_string(self) -> Optional[str]:
        """The concrete string this value represents, if it is one."""
        if self.kind in (STRING, CLASS, METHOD_REF, NEW_INSTANCE, INVOKE_RESULT) and isinstance(
            self.value, str
        ):
            return self.value
        return None


@dataclass
class CallSite:
    """An invoke instruction with its resolved callee and argument values."""

    offset: int
    method: Optional[str]  # resolved method/call-site descriptor
    argument_registers: List[int]
    arguments: List[Optional[AbstractValue]]  # abstract value per argument register

    def string_arguments(self) -> Dict[int, str]:
        """Argument index -> concrete string, for arguments known to be strings."""
        out: Dict[int, str] = {}
        for idx, val in enumerate(self.arguments):
            if val is not None and (s := val.as_string()) is not None:
                out[idx] = s
        return out


@dataclass
class ArrayFill:
    """An array register populated by a ``fill-array-data`` payload."""

    offset: int
    register: int
    element_width: int
    data: bytes


@dataclass
class DataFlow:
    """The result of analysing one method."""

    cfg: CFG
    state_before: Dict[int, Dict[int, AbstractValue]]  # instr offset -> reg -> value
    call_sites: List[CallSite] = field(default_factory=list)
    array_fills: List[ArrayFill] = field(default_factory=list)


def _merge(states: List[Dict[int, AbstractValue]]) -> Dict[int, AbstractValue]:
    """Meet of several register states: keep a register only when all agree."""
    if not states:
        return {}
    common = set(states[0])
    for s in states[1:]:
        common &= set(s)
    merged: Dict[int, AbstractValue] = {}
    for reg in common:
        first = states[0][reg]
        if all(s[reg] == first for s in states):
            merged[reg] = first
    return merged


def _value_producers(inst: Instruction, state: Dict[int, AbstractValue], pending):
    """Abstract values an instruction writes to its destination register(s).

    Returns a ``{register: AbstractValue}`` mapping for the registers this
    instruction defines with a known value. ``pending`` is the value produced by
    the immediately preceding instruction (consumed by ``move-result*``).
    """
    op = inst.opcode
    regs = inst.registers
    r0 = regs[0] if regs else None
    if op in (0x12, 0x13, 0x14, 0x15):  # const/4, const/16, const, const/high16
        return {r0: AbstractValue(INT, inst.literal)}
    if op in (0x16, 0x17, 0x18, 0x19):  # const-wide*
        return {r0: AbstractValue(WIDE, inst.literal), r0 + 1: AbstractValue(WIDE_HIGH)}
    if op in (0x1A, 0x1B):  # const-string / const-string/jumbo
        return {r0: AbstractValue(STRING, inst.target)}
    if op == 0x1C:  # const-class
        return {r0: AbstractValue(CLASS, inst.target)}
    if op in (0xFE, 0xFF):  # const-method-handle / const-method-type
        return {r0: AbstractValue(METHOD_REF, inst.target)}
    if op in (0x01, 0x02, 0x03, 0x07, 0x08, 0x09):  # move / move-object
        src = state.get(regs[1])
        return {r0: src} if src is not None else {}
    if op in (0x04, 0x05, 0x06):  # move-wide
        out = {}
        if (lo := state.get(regs[1])) is not None:
            out[r0] = lo
        if (hi := state.get(regs[1] + 1)) is not None:
            out[r0 + 1] = hi
        return out
    if op in (0x0A, 0x0C, 0x0D):  # move-result / move-result-object / move-exception
        return {r0: pending} if pending is not None else {}
    if op == 0x0B:  # move-result-wide
        return {r0: pending, r0 + 1: AbstractValue(WIDE_HIGH)} if pending is not None else {}
    if op == 0x22:  # new-instance
        return {r0: AbstractValue(NEW_INSTANCE, inst.target)}
    return {}


def _transfer(
    inst: Instruction, state: Dict[int, AbstractValue], pending: Optional[AbstractValue]
) -> Optional[AbstractValue]:
    """Apply one instruction to ``state`` in place; return its produced result.

    The produced result is the value a following ``move-result*`` would read
    (the return of an invoke, or a filled array); ``None`` for everything else.
    """
    produced = _value_producers(inst, state, pending)
    defs, _ = register_roles(inst)
    for d in defs:
        if d in produced:
            state[d] = produced[d]
        else:
            state.pop(d, None)  # defined with an unknown value
    # The result consumed by a subsequent move-result*.
    if is_invoke(inst):
        return AbstractValue(INVOKE_RESULT, inst.target)
    if inst.opcode in (0x24, 0x25):  # filled-new-array
        return AbstractValue(ARRAY, inst.target)
    return None


def analyze(
    instructions: List[Instruction],
    pools: Optional[DexPools] = None,
    cfg: Optional[CFG] = None,
) -> DataFlow:
    """
    Run the intraprocedural data-flow analysis over a method.

    Args:
        instructions: Decoded instructions (with ``target`` resolved when pools
            were supplied to :func:`blint.lib.dalvik.decode`).
        pools: Unused directly, accepted so callers can pass the dex pools
            uniformly; resolution is expected to already be on the instructions.
        cfg: A pre-built CFG; one is constructed when omitted.

    Returns:
        A :class:`DataFlow` with per-instruction register state, call sites and
        array fills.
    """
    del pools  # targets are resolved on the instructions at decode time
    if cfg is None:
        cfg = build_cfg(instructions)
    payloads = {i.offset: i for i in instructions if i.fmt == "payload"}

    # Fixpoint over the CFG: compute the register state entering each block.
    block_in: Dict[int, Dict[int, AbstractValue]] = {b: {} for b in cfg.blocks}
    block_out: Dict[int, Dict[int, AbstractValue]] = {b: {} for b in cfg.blocks}
    worklist = list(cfg.blocks)
    while worklist:
        b = worklist.pop()
        block = cfg.blocks[b]
        if block.predecessors:
            block_in[b] = _merge([block_out[p] for p in block.predecessors])
        state = dict(block_in[b])
        pending = None
        for inst in block.instructions:
            pending = _transfer(inst, state, pending)
        if state != block_out[b]:
            block_out[b] = state
            for s in block.successors:
                if s in cfg.blocks and s not in worklist:
                    worklist.append(s)

    # Final pass: record per-instruction state, call sites and array fills.
    state_before: Dict[int, Dict[int, AbstractValue]] = {}
    call_sites: List[CallSite] = []
    array_fills: List[ArrayFill] = []
    for b in sorted(cfg.blocks):
        block = cfg.blocks[b]
        state = dict(block_in[b])
        pending = None
        for inst in block.instructions:
            state_before[inst.offset] = dict(state)
            if is_invoke(inst):
                args = [state.get(r) for r in inst.registers]
                call_sites.append(
                    CallSite(
                        offset=inst.offset,
                        method=inst.target,
                        argument_registers=list(inst.registers),
                        arguments=args,
                    )
                )
            elif inst.opcode == 0x26 and inst.branch is not None:  # fill-array-data
                payload = payloads.get(inst.offset + inst.branch)
                if payload is not None and payload.payload is not None and inst.registers:
                    array_fills.append(
                        ArrayFill(
                            offset=inst.offset,
                            register=inst.registers[0],
                            element_width=payload.payload.element_width,
                            data=payload.payload.data,
                        )
                    )
            pending = _transfer(inst, state, pending)

    return DataFlow(
        cfg=cfg, state_before=state_before, call_sites=call_sites, array_fills=array_fills
    )
