"""Native control-flow graphs built from already-disassembled functions.

blint's native detection logic historically ran over flat instruction lists
because no block structure existed — the Dalvik analyzer had a CFG while the
native path had none. This module closes that asymmetry for the small price
of classifying the instructions the disassembler already produces.

A block ends at every branch, return or trap, and at every branch target
inside the function; edges follow the terminators. From the block graph come
the structural metrics rules and fingerprints consume: cyclomatic complexity,
loop count (back edges), unreachable blocks, indirect branches, and the
block-size spread that distinguishes compiler-generated layout from control-
flow flattening.

Branch targets are computed from what nyxstone renders. Both x86 and ARM64
print branch operands as signed displacements (``jne -17``, ``b.ne #28``), so
the target address is the instruction's address plus the displacement, plus
the instruction length on x86 where the displacement is measured from the
following instruction. Non-numeric operands (``jmp rax``, ``blr x8``) count
as indirect branches with no target. Calls do not split blocks: intra-function
shape is what this graph describes, and call evidence lives on the callgraph.

Everything here is deterministic: leaders, blocks, edges and traversal orders
are all sorted, so the same instruction list yields byte-identical metrics.
"""

# Displacement-based rendering means the target of an x86 branch is measured
# from the end of the instruction, while ARM64 measures from its start.
_ARCH_PC_RELATIVE_TO_END = ("x86", "8086")

X86_UNCONDITIONAL = ("jmp", "jmpq", "jmpw", "jmpl", "ljmp")
X86_CONDITIONAL_PREFIX = "j"
X86_NON_CONDITIONAL_JUMPS = {"jmp", "jmpq", "jmpw", "jmpl", "ljmp", "jmps"}
X86_RET = ("ret", "retq", "retw", "retl", "retn", "iret", "iretq", "retf")
X86_TRAPS = {"ud2", "int3", "hlt", "int1"}
X86_LOOPS = {"loop", "loope", "loopz", "loopne", "loopnz", "jrcxz"}

ARM64_UNCONDITIONAL = ("b", "br", "braa", "brab", "brka", "brkb", "drps")
ARM64_CONDITIONAL_PREFIXES = ("b.", "cbz", "cbnz", "tbz", "tbnz")
ARM64_CALLS = {"bl", "blr", "blraa", "blrab"}
ARM64_RET = {"ret"}
ARM64_TRAPS = {"brk", "hlt", "udf", "svc", "hvc", "smc"}

MIPS_UNCONDITIONAL = {"j", "jr", "b", "jialc"}
MIPS_CONDITIONAL = {"beq", "bne", "blez", "bgtz", "bltz", "bgez", "beqz", "bnez"}
MIPS_CALLS = {"jal", "jalr", "bal"}
MIPS_RET = {"jr"}  # jr $ra


def _normalize(arch_target: str) -> str:
    return (arch_target or "").lower()


def _is_arm64(arch: str) -> bool:
    return "aarch64" in arch or "arm64" in arch


def _is_mips(arch: str) -> bool:
    return "mips" in arch


def classify_terminator(mnemonic: str, arch: str) -> tuple[str, bool]:
    """Classify a mnemonic into (kind, conditional).

    Kind is one of ``jump`` (block terminator with a target), ``ret``,
    ``trap``, ``call`` (does not split a block) or ``none``. Conditional
    branches additionally take a fallthrough edge.
    """
    mnemonic = mnemonic.lower()
    if _is_arm64(arch):
        if mnemonic in ARM64_CALLS:
            return "call", False
        if mnemonic in ARM64_RET:
            return "ret", False
        if mnemonic in ARM64_TRAPS:
            return "trap", False
        if mnemonic.startswith(ARM64_CONDITIONAL_PREFIXES):
            return "jump", True
        if mnemonic in ARM64_UNCONDITIONAL:
            return "jump", False
        return "none", False
    if _is_mips(arch):
        if mnemonic in MIPS_CALLS:
            return "call", False
        if mnemonic in MIPS_RET:
            return "ret", False
        if mnemonic in MIPS_CONDITIONAL:
            return "jump", True
        if mnemonic in MIPS_UNCONDITIONAL:
            return "jump", False
        return "none", False
    # x86 family by default.
    if mnemonic.startswith("call"):
        return "call", False
    if mnemonic in X86_RET or mnemonic.startswith("ret"):
        return "ret", False
    if mnemonic in X86_TRAPS:
        return "trap", False
    if mnemonic in X86_LOOPS:
        return "jump", True
    if mnemonic in X86_NON_CONDITIONAL_JUMPS:
        return "jump", False
    if mnemonic.startswith(X86_CONDITIONAL_PREFIX) and mnemonic[1:2].isalpha():
        return "jump", True
    return "none", False


def _branch_target(
    instr, parsed_instr, arch: str, index: int, addr_to_index: dict[int, int]
) -> int | None:
    """Resolve the jump/branch target of one instruction, if it has one."""
    operand_text = parsed_instr.operand_text
    if not operand_text:
        return None
    from blint.lib.disassembler import _parse_immediate_token

    displacement = _parse_immediate_token(operand_text.split(",")[-1].strip())
    if displacement is None:
        return None
    if any(prefix in arch for prefix in _ARCH_PC_RELATIVE_TO_END):
        target = instr.address + len(instr.bytes) + displacement
    else:
        target = instr.address + displacement
    return addr_to_index.get(target)


def build_function_cfg(
    instr_list: list, parsed_instrs: list, arch_target: str, func_start: int
) -> dict:
    """Build the block graph and structural metrics for one function.

    ``instr_list`` is the truncated nyxstone instruction list for a function
    starting at virtual address ``func_start``. The returned dict is additive
    metadata: it never changes existing instruction metrics, it only describes
    the shape around them.
    """
    arch = _normalize(arch_target)
    count = len(instr_list)
    if not count:
        return {}
    instr_addrs = [instr.address for instr in instr_list]
    addr_to_index = {addr: i for i, addr in enumerate(instr_addrs)}
    func_end = func_start
    if count:
        last = instr_list[-1]
        func_end = last.address + max(len(last.bytes), 1)

    # Leaders: block starts. The first instruction, every target of an
    # intra-function branch, and every instruction after a terminator.
    leaders = {0}
    kinds = []
    for index, (instr, parsed_instr) in enumerate(zip(instr_list, parsed_instrs)):
        mnemonic = parsed_instr.mnemonic.lower()
        kind, conditional = classify_terminator(mnemonic, arch)
        kinds.append((kind, conditional))
        if kind in ("jump", "ret", "trap"):
            if index + 1 < count:
                leaders.add(index + 1)
            if kind == "jump":
                target_index = _branch_target(instr, parsed_instr, arch, index, addr_to_index)
                if target_index is not None:
                    leaders.add(target_index)
    leader_list = sorted(leaders)

    # Block spans: [leader_i, next_leader) instruction index ranges.
    block_of_instr = [0] * count
    block_bounds: list[tuple[int, int]] = []
    for block_index, leader in enumerate(leader_list):
        end = leader_list[block_index + 1] if block_index + 1 < len(leader_list) else count
        block_bounds.append((leader, end))
        for index in range(leader, end):
            block_of_instr[index] = block_index

    # Edges from each block's terminator.
    successors: list[set[int]] = [set() for _ in block_bounds]
    edge_kinds: list[tuple[int, int, str]] = []
    conditional_count = 0
    indirect_branch_count = 0
    tail_call_count = 0
    for block_index, (start, end) in enumerate(block_bounds):
        last = end - 1
        kind, conditional = kinds[last]
        instr = instr_list[last]
        parsed_instr = parsed_instrs[last]
        if kind == "jump":
            # Every conditional branch is a decision for the cyclomatic
            # count, whether or not its target landed inside the disassembled
            # window; resolution only decides whether an edge exists.
            target_index = _branch_target(instr, parsed_instr, arch, last, addr_to_index)
            if target_index is not None:
                target_block = block_of_instr[target_index]
                successors[block_index].add(target_block)
                edge_kinds.append(
                    (block_index, target_block, "conditional" if conditional else "jump")
                )
            elif not conditional:
                indirect_branch_count += 1
            if conditional:
                conditional_count += 1
                if block_index + 1 < len(block_bounds):
                    successors[block_index].add(block_index + 1)
                    edge_kinds.append((block_index, block_index + 1, "fallthrough"))
            # A final unconditional branch leaving the function is a tail
            # call: it transfers control elsewhere instead of continuing.
            if not conditional and block_index == len(block_bounds) - 1:
                operand_text = parsed_instr.operand_text
                if operand_text:
                    from blint.lib.disassembler import _parse_immediate_token

                    displacement = _parse_immediate_token(operand_text.split(",")[-1].strip())
                    if displacement is not None:
                        if any(prefix in arch for prefix in _ARCH_PC_RELATIVE_TO_END):
                            target = instr.address + len(instr.bytes) + displacement
                        else:
                            target = instr.address + displacement
                        if target >= func_end or target < func_start:
                            tail_call_count += 1
        elif kind == "ret" or kind == "trap":
            pass
        else:
            # Non-terminating block: falls through to the next block.
            if block_index + 1 < len(block_bounds):
                successors[block_index].add(block_index + 1)
                edge_kinds.append((block_index, block_index + 1, "fallthrough"))

    # Loop count via back edges of a DFS from the entry block. Successor sets
    # are iterated in sorted order so the traversal, and therefore the loop
    # count, is deterministic.
    state = [0] * len(block_bounds)  # 0=white 1=grey 2=black
    back_edges = 0
    stack = [(0, iter(sorted(successors[0])))] if block_bounds else []
    state[0] = 1
    while stack:
        node, iterator = stack[-1]
        advanced = False
        for child in iterator:
            if state[child] == 1:
                back_edges += 1
            elif state[child] == 0:
                state[child] = 1
                stack.append((child, iter(sorted(successors[child]))))
                advanced = True
                break
        if not advanced:
            state[node] = 2
            stack.pop()

    # Reachability for the unreachable-block count.
    reachable = set()
    if block_bounds:
        queue = [0]
        reachable.add(0)
        while queue:
            node = queue.pop()
            for child in sorted(successors[node]):
                if child not in reachable:
                    reachable.add(child)
                    queue.append(child)

    return {
        "block_count": len(block_bounds),
        "edge_count": len(edge_kinds),
        "cyclomatic_complexity": conditional_count + 1,
        "loop_count": back_edges,
        "unreachable_block_count": len(block_bounds) - len(reachable),
        "indirect_branch_count": indirect_branch_count,
        "max_block_instructions": max((end - start) for start, end in block_bounds),
        "tail_call_count": tail_call_count,
    }
