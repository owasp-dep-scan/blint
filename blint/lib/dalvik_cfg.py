"""
Control-flow graph construction for a decoded Dalvik method.

Given the instruction stream from :func:`blint.lib.dalvik.decode`, this builds a
basic-block control-flow graph: maximal runs of straight-line instructions with
edges for every branch, conditional fall-through, ``goto``, and decoded
``packed``/``sparse`` switch target. Branch offsets are resolved against the
Dalvik convention that an instruction's (and a switch payload's) targets are
relative to the *branching instruction's* address.

Blocks are keyed by the code-unit offset of their first instruction. Dominators
are available on demand for analyses that need them (Phase 3 dataflow). Payload
pseudo-instructions (switch tables, array data) are data, not code, so they are
excluded from blocks but remain addressable for switch-target resolution.

Exception edges (try/catch) are intentionally not modelled here; they require
the try/handler tables that LIEF does not expose and are added by the raw-dex
layer.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from blint.lib.dalvik import Instruction
from blint.lib.dalvik_semantics import OpFlags, flags


@dataclass
class BasicBlock:
    """A maximal straight-line run of instructions with explicit edges."""

    start: int  # code-unit offset of the first instruction
    instructions: List[Instruction] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)  # successor block starts
    predecessors: List[int] = field(default_factory=list)  # predecessor block starts

    @property
    def end(self) -> int:
        """Code-unit offset just past the last instruction (exclusive)."""
        if not self.instructions:
            return self.start
        last = self.instructions[-1]
        return last.offset + last.length


@dataclass
class CFG:
    """A method's control-flow graph, keyed by block start offset."""

    blocks: Dict[int, BasicBlock]
    entry: int

    def block_at(self, offset: int) -> Optional[BasicBlock]:
        """Return the block beginning at ``offset`` (or ``None``)."""
        return self.blocks.get(offset)

    def ordered_blocks(self) -> List[BasicBlock]:
        """Blocks in ascending start-offset order."""
        return [self.blocks[k] for k in sorted(self.blocks)]

    def dominators(self) -> Dict[int, set]:
        """
        Compute the dominator set of every block (iterative data-flow).

        ``dom[b]`` is the set of block starts that dominate ``b`` (every path
        from the entry to ``b`` passes through them, ``b`` included).
        """
        starts = set(self.blocks)
        dom: Dict[int, set] = {b: set(starts) for b in starts}
        if self.entry in dom:
            dom[self.entry] = {self.entry}
        changed = True
        order = [b for b in sorted(self.blocks) if b != self.entry]
        while changed:
            changed = False
            for b in order:
                preds = self.blocks[b].predecessors
                if not preds:
                    new = {b}
                else:
                    new = set(starts)
                    for p in preds:
                        new &= dom.get(p, set())
                    new.add(b)
                if new != dom[b]:
                    dom[b] = new
                    changed = True
        return dom


def _switch_targets(inst: Instruction, payloads: Dict[int, Instruction]) -> List[int]:
    """Absolute targets of a switch instruction via its referenced payload."""
    if inst.branch is None:
        return []
    payload_inst = payloads.get(inst.offset + inst.branch)
    if payload_inst is None or payload_inst.payload is None:
        return []
    # Switch payload targets are relative to the switch instruction's address.
    return [inst.offset + entry.target for entry in payload_inst.payload.switch]


def _find_leaders(reals: List[Instruction], payloads: Dict[int, Instruction]) -> set:
    """Collect the offsets that begin a basic block."""
    if not reals:
        return set()
    leaders = {reals[0].offset}
    for inst in reals:
        fl = flags(inst.opcode)
        fallthrough = inst.offset + inst.length
        if fl & OpFlags.GOTO and inst.branch is not None:
            leaders.add(inst.offset + inst.branch)
            leaders.add(fallthrough)
        elif fl & OpFlags.IF and inst.branch is not None:
            leaders.add(inst.offset + inst.branch)
            leaders.add(fallthrough)
        elif fl & OpFlags.SWITCH:
            for target in _switch_targets(inst, payloads):
                leaders.add(target)
            leaders.add(fallthrough)
        elif fl & OpFlags.TERMINATOR:
            leaders.add(fallthrough)
    return leaders


def _successors(
    block: BasicBlock, payloads: Dict[int, Instruction], real_offsets: set
) -> List[int]:
    """Successor block starts for a block, based on its last instruction."""
    if not block.instructions:
        return []
    last = block.instructions[-1]
    fl = flags(last.opcode)
    fallthrough = last.offset + last.length
    succ: List[int] = []
    if fl & OpFlags.RETURN or fl & OpFlags.THROW:
        return []
    if fl & OpFlags.GOTO and last.branch is not None:
        return [last.offset + last.branch]
    if fl & OpFlags.IF and last.branch is not None:
        succ.append(last.offset + last.branch)
        succ.append(fallthrough)
    elif fl & OpFlags.SWITCH:
        succ.extend(_switch_targets(last, payloads))
        succ.append(fallthrough)  # the default (fall-through) edge
    else:
        succ.append(fallthrough)
    # Keep only edges that land on a real instruction, de-duplicated in order.
    seen: set = set()
    result = []
    for s in succ:
        if s in real_offsets and s not in seen:
            seen.add(s)
            result.append(s)
    return result


def build_cfg(instructions: List[Instruction]) -> CFG:
    """
    Build the control-flow graph for a method's decoded instructions.

    Args:
        instructions: The decoded stream from :func:`blint.lib.dalvik.decode`.

    Returns:
        A :class:`CFG`. An empty method yields a CFG with no blocks and an entry
        of ``0``.
    """
    reals = [i for i in instructions if i.fmt != "payload"]
    payloads = {i.offset: i for i in instructions if i.fmt == "payload"}
    if not reals:
        return CFG(blocks={}, entry=0)

    real_offsets = {i.offset for i in reals}
    leaders = _find_leaders(reals, payloads) & real_offsets
    leader_list = sorted(leaders)

    # Partition the instruction stream into blocks bounded by consecutive leaders.
    blocks: Dict[int, BasicBlock] = {}
    next_leader = {leader_list[i]: leader_list[i + 1] for i in range(len(leader_list) - 1)}
    for leader in leader_list:
        boundary = next_leader.get(leader)
        block_insts = [
            i for i in reals if i.offset >= leader and (boundary is None or i.offset < boundary)
        ]
        blocks[leader] = BasicBlock(start=leader, instructions=block_insts)

    for block in blocks.values():
        block.successors = _successors(block, payloads, set(blocks))
    for block in blocks.values():
        for s in block.successors:
            if s in blocks:
                blocks[s].predecessors.append(block.start)

    return CFG(blocks=blocks, entry=reals[0].offset)
