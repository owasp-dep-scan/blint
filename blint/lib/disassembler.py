import contextlib
import hashlib
import re

import lief

from blint.config import (
    APPLE_PROPRIETARY_INSTRUCTION_RANGES,
    APPLE_PROPRIETARY_SREGS,
    CRYPTO_INDICATORS,
    GPU_INDICATORS,
    IMPLICIT_REGS_ARM64,
    IMPLICIT_REGS_MIPS,
    IMPLICIT_REGS_X64,
    IMPLICIT_REGS_X86,
    MIPS_ARITH_LOGIC_2_OP_IMM,
    MIPS_ARITH_LOGIC_3_OP,
    MIPS_BRANCH_2_OP,
    MIPS_CALL_INST,
    MIPS_LOAD_STORE,
    MIPS_MOVE,
    MIPS_MULT_DIV,
    MIPS_SHIFT_2_OP_IMM,
    MIPS_SHIFT_3_OP,
    SECURITY_INDICATORS,
    SORTED_ALL_REGS_MIPS,
    SYSCALL_INDICATORS,
)
from blint.logger import LOG

FUNCTION_SYMBOLS = (
    "functions",
    "ctor_functions",
    "dtor_functions",
    "exception_functions",
    "unwind_functions",
    "exports",
    "imports",
    "symtab_symbols",
    "dynamic_symbols",
    "exceptions",
)


def _is_macos_system_symbol_name(symbol_name: str) -> bool:
    """Return True for symbol names that clearly belong to macOS system dylibs."""
    if not symbol_name:
        return False
    name = symbol_name.strip()
    lib_part = name.split("::", 1)[0]
    return lib_part.startswith(("/usr/lib/", "/System/Library/"))


def _should_skip_symbol_list_for_disassembly(parsed_obj, func_list_key: str) -> bool:
    """Skip symbol buckets that are usually non-local to this binary."""
    if isinstance(parsed_obj, lief.PE.Binary) and func_list_key in ("imports",):
        return True
    if isinstance(parsed_obj, lief.MachO.Binary) and func_list_key in (
        "imports",
        "symtab_symbols",
        "dynamic_symbols",
    ):
        return True
    return False


OPERAND_DELIMITERS_PATTERN = re.compile(r"[^a-zA-Z0-9_$]+")

ARITH_INST = [
    "add",
    "sub",
    "imul",
    "mul",
    "div",
    "idiv",
    "inc",
    "dec",
    "neg",
    "not",
    "and",
    "or",
    "xor",
    "adc",
    "sbb",
    "xadd",
    "cmpxchg",
]
SHIFT_INST = [
    "shl",
    "shr",
    "sal",
    "sar",
    "rol",
    "ror",
    "rcl",
    "rcr",
    "psll",
    "psrl",
    "psra",
    "vpsll",
    "vpsrl",
    "vpsra",
]
CONDITIONAL_JMP_INST_X86 = [
    "je",
    "jne",
    "jz",
    "jnz",
    "jg",
    "jge",
    "jl",
    "jle",
    "ja",
    "jae",
    "jb",
    "jbe",
    "jp",
    "jnp",
    "jo",
    "jno",
    "js",
    "jns",
    "loop",
    "loopz",
    "loopnz",
    "jcxz",
    "jecxz",
    "jrcxz",
]
X86_CALL_INST = {"call"}
X86_UNCONDITIONAL_JMP_INST = {"jmp", "jmpq", "jmpl"}
X86_RET_INST = {"ret", "retn", "retf", "iret", "iretd", "iretq"}
ARM64_B_COND_INST = [
    "beq",
    "bne",
    "bge",
    "bgt",
    "ble",
    "blt",
    "bhs",
    "bcs",
    "blo",
    "bcc",
    "bvs",
    "bvc",
    "bmi",
    "bpl",
    "bhi",
    "bls",
]
ARM64_CB_TB_INST = ["cbz", "cbnz", "tbz", "tbnz"]
ARM64_CONDITIONAL_JMP_INST = ARM64_B_COND_INST + ARM64_CB_TB_INST
CONDITIONAL_JMP_INST = CONDITIONAL_JMP_INST_X86 + ARM64_CONDITIONAL_JMP_INST

ARM64_GENERAL_REGS_64 = {f"x{i}" for i in range(31)}
ARM64_GENERAL_REGS_32 = {f"w{i}" for i in range(31)}
ARM64_SPECIAL_REGS = {"sp", "xzr", "wzr"}
ARM64_VFP_NEON_REGS = (
    {f"v{i}" for i in range(32)}
    | {f"s{i}" for i in range(32)}
    | {f"d{i}" for i in range(32)}
    | {f"q{i}" for i in range(32)}
)
ARM64_ALL_REGS = (
    ARM64_GENERAL_REGS_64
    | ARM64_GENERAL_REGS_32
    | ARM64_SPECIAL_REGS
    | ARM64_VFP_NEON_REGS
)
ARM64_CALL_INST = {"bl", "blr", "blraa", "blrab"}
ARM64_UNCONDITIONAL_JMP_INST = {"b", "br", "braa", "brab"}
ARM64_RET_INST = {"ret", "eret"}
ARM64_PAC_INST = {
    "pacia",
    "pacib",
    "pacda",
    "pacdb",
    "autia",
    "autib",
    "autda",
    "autdb",
    "pacibsp",
    "autibsp",
    "pacia1716",
    "autia1716",
    "xpaci",
    "xpacd",
    "retaa",
    "retab",
    "braa",
    "brab",
    "blraa",
    "blrab",
    "ldra",
    "ldrab",
}
# Mapping of ARM64 HINT immediate values to PAC meanings
# 25=paciasp, 27=pacibsp, 29=autiasp, 31=autibsp
ARM64_PAC_HINTS = {"25", "27", "29", "31"}
MIPS_RET_INST = {"jr"}
MIPS_UNCONDITIONAL_JMP_INST = {"j", "jalr", "jalx", "b"}
TERMINATING_INST = X86_RET_INST | ARM64_RET_INST | MIPS_RET_INST
UNCONDITIONAL_JMP_INST_ALL = (
    X86_UNCONDITIONAL_JMP_INST
    | ARM64_UNCONDITIONAL_JMP_INST
    | MIPS_UNCONDITIONAL_JMP_INST
)
SORTED_ARM64_ALL_REGS = sorted(ARM64_ALL_REGS, key=len, reverse=True)

COMMON_REGS_64 = {
    "rax",
    "rbx",
    "rcx",
    "rdx",
    "rsi",
    "rdi",
    "rbp",
    "rsp",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
}
COMMON_REGS_32 = {
    "eax",
    "ebx",
    "ecx",
    "edx",
    "esi",
    "edi",
    "ebp",
    "esp",
    "r8d",
    "r9d",
    "r10d",
    "r11d",
    "r12d",
    "r13d",
    "r14d",
    "r15d",
}
COMMON_REGS_16 = {
    "ax",
    "bx",
    "cx",
    "dx",
    "si",
    "di",
    "bp",
    "sp",
    "r8w",
    "r9w",
    "r10w",
    "r11w",
    "r12w",
    "r13w",
    "r14w",
    "r15w",
}
COMMON_REGS_8l = {
    "al",
    "bl",
    "cl",
    "dl",
    "sil",
    "dil",
    "bpl",
    "spl",
    "r8b",
    "r9b",
    "r10b",
    "r11b",
    "r12b",
    "r13b",
    "r14b",
    "r15b",
}
COMMON_REGS_8h = {"ah", "bh", "ch", "dh"}
READ_WRITE_BOTH_OPS_INST = {"xadd", "cmpxchg", "cmpxchg8b", "cmpxchg16b"}
BIT_MANIPULATION_INST = {
    "bt",
    "bts",
    "bsf",
    "bsr",
    "btr",
    "btc",
    "popcnt",
    "lzcnt",
    "tzcnt",
}
READ_WRITE_ONE_OP_INST = {
    "inc",
    "dec",
    "not",
    "neg",
    "rol",
    "ror",
    "rcl",
    "rcr",
    "shl",
    "shr",
    "sal",
    "sar",
}
WRITE_DST_READ_SRC_INST = {
    "add",
    "adc",
    "sub",
    "sbb",
    "imul",
    "and",
    "or",
    "xor",
    "mov",
    "movzx",
    "movsx",
    "movsxd",
    "lea",
    "cmove",
    "cmovne",
    "cmovz",
    "cmovnz",
    "cmova",
    "cmovnbe",
    "cmovae",
    "cmovnb",
    "cmovb",
    "cmovnae",
    "cmovbe",
    "cmovna",
    "cmovg",
    "cmovnle",
    "cmovge",
    "cmovnl",
    "cmovl",
    "cmovnge",
    "cmovle",
    "cmovng",
    "cmovc",
    "cmovnc",
    "cmovo",
    "cmovno",
    "cmovs",
    "cmovns",
    "cmovp",
    "cmovpe",
    "cmovnp",
    "cmovpo",
}

SEGMENT_REGS = {"cs", "ds", "es", "fs", "gs", "ss"}
FPU_REGS = {f"st({i})" for i in range(8)}
MMX_REGS = {f"mm{i}" for i in range(8)}
XMM_REGS = {f"xmm{i}" for i in range(32)}
YMM_REGS = {f"ymm{i}" for i in range(32)}
ZMM_REGS = {f"zmm{i}" for i in range(32)}
ALL_SIMD_REGS = FPU_REGS | MMX_REGS | XMM_REGS | YMM_REGS | ZMM_REGS
ALL_REGS_X86 = (
    COMMON_REGS_64
    | COMMON_REGS_32
    | COMMON_REGS_16
    | COMMON_REGS_8l
    | COMMON_REGS_8h
    | ALL_SIMD_REGS
    | SEGMENT_REGS
)
SORTED_ALL_REGS_X86 = sorted(ALL_REGS_X86, key=len, reverse=True)

WIN_X64_VOLATILE_REGS = frozenset({"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"})
SYSV_X64_VOLATILE_REGS = frozenset(
    {"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"}
)
CDECL_X86_VOLATILE_REGS = frozenset({"eax", "ecx", "edx"})
X64_RETURN_REGS = frozenset({"rax"})
X86_RETURN_REGS = frozenset({"eax"})

_SREG_TO_CATEGORY_MAP = {
    sreg.lower(): category
    for category, sregs in APPLE_PROPRIETARY_SREGS.items()
    for sreg in sregs
}

# A universal superset of padding, trap, and disassembler artifact mnemonics
PADDING_TRAP_MNEMONICS = {
    "nop",
    "int3",
    "ud2",
    "hlt",
    "pause",
    "brk",
    "udf",
    "trap",
    "break",
    "align",
    "invalid",
    "unallocated",
}

try:
    from nyxstone import Nyxstone

    NYXSTONE_AVAILABLE = True
except ImportError:
    LOG.debug(
        "Nyxstone not found. Disassembly features will be unavailable. Install with 'pip install blint[extended]'."
    )
    NYXSTONE_AVAILABLE = False


def get_arch_reg_set(arch_target):
    """Returns the appropriate set of registers based on the architecture."""
    lower_arch = arch_target.lower()
    if "aarch64" in lower_arch or "arm64" in lower_arch:
        return SORTED_ARM64_ALL_REGS
    if "mips" in lower_arch:
        return SORTED_ALL_REGS_MIPS
    else:
        return SORTED_ALL_REGS_X86


def _get_implicit_regs_map(arch_target):
    """Selects the appropriate implicit registers map based on architecture."""
    lower_arch = arch_target.lower()
    if "64" in lower_arch and "aarch64" not in lower_arch:
        return IMPLICIT_REGS_X64
    if "aarch64" in lower_arch or "arm64" in lower_arch:
        return IMPLICIT_REGS_ARM64
    if "mips" in lower_arch:
        return IMPLICIT_REGS_MIPS
    return IMPLICIT_REGS_X86


def _find_function_end_index(instr_list, has_exact_size=False):
    """
    Scans a list of instructions to find the true end of a function.
    If exact size is known, it strips trailing compiler padding/traps.
    If guessed, it uses heuristics to find the first likely boundary.
    """
    if not instr_list:
        return -1

    if has_exact_size:
        for i in range(len(instr_list) - 1, 0, -1):
            mnemonic = instr_list[i].assembly.split(None, 1)[0].lower()
            if mnemonic not in PADDING_TRAP_MNEMONICS:
                return i
        return 0

    # Fallback heuristic: the size was a blind guess (e.g., 4096 bytes),
    for i, instr in enumerate(instr_list):
        mnemonic = instr.assembly.split(None, 1)[0].lower()
        if mnemonic in TERMINATING_INST or mnemonic in UNCONDITIONAL_JMP_INST_ALL:
            if i + 1 >= len(instr_list):
                return i
            next_mnemonic = instr_list[i + 1].assembly.split(None, 1)[0].lower()
            if next_mnemonic in PADDING_TRAP_MNEMONICS:
                return i

    return len(instr_list) - 1


def _get_abi_volatile_regs(parsed_obj, arch_target):
    """
    Determines the set of volatile (caller-saved) registers based on the
    binary type and architecture.
    """
    is_64bit = "64" in arch_target or "aarch64" in arch_target
    if isinstance(parsed_obj, lief.PE.Binary):
        if is_64bit:
            return WIN_X64_VOLATILE_REGS
        else:
            return CDECL_X86_VOLATILE_REGS
    if is_64bit:
        return SYSV_X64_VOLATILE_REGS
    else:
        return CDECL_X86_VOLATILE_REGS


def extract_regs_from_operand(op, sorted_arch_regs=SORTED_ALL_REGS_X86):
    found_regs = set()
    if not op:
        return found_regs
    potential_tokens = filter(None, OPERAND_DELIMITERS_PATTERN.split(op.lower()))
    for token in potential_tokens:
        if token in sorted_arch_regs:
            found_regs.add(token)
        cleaned_token = token.strip("[]!")
        if cleaned_token in sorted_arch_regs:
            found_regs.add(cleaned_token)
        if " " in cleaned_token:
            sub_tokens = cleaned_token.split()
            for sub_t in sub_tokens:
                sub_cleaned = sub_t.strip("[]!")
                if sub_cleaned in sorted_arch_regs:
                    found_regs.add(sub_cleaned)
    return found_regs


def _extract_register_usage(
    instr_assembly, parsed_obj=None, arch_target="", sorted_arch_regs=None
):
    """
    Performs a first-pass analysis to extract approximate register read/write usage
    from the instruction assembly string.
    """
    implicit_regs_map = _get_implicit_regs_map(arch_target)
    regs_read = set()
    regs_written = set()
    if not instr_assembly:
        return sorted(regs_read), sorted(regs_written)
    is_aarch64 = "aarch64" in arch_target.lower() or "arm64" in arch_target.lower()
    is_mips = "mips" in arch_target.lower()
    if not sorted_arch_regs:
        sorted_arch_regs = get_arch_reg_set(arch_target)
    first_space_idx = instr_assembly.find(" ")
    operands = []
    if first_space_idx == -1:
        mnemonic = instr_assembly.strip().lower().rstrip(":")
    else:
        mnemonic_part = instr_assembly[:first_space_idx].strip().lower().rstrip(":")
        operands_part = instr_assembly[first_space_idx + 1 :].strip()
        mnemonic = mnemonic_part.rstrip(":")
        if operands_part:
            operands = [op.strip() for op in operands_part.split(",")]
    num_operands = len(operands)
    if num_operands > 0:
        operands = [op.rstrip(",") for op in operands]
    has_rep_prefix = False
    if mnemonic.startswith(("rep", "repe", "repne")):
        has_rep_prefix = True
        mnemonic = (
            mnemonic[4:] if len(mnemonic) > 3 and mnemonic[3] == "e" else mnemonic[3:]
        )
    if mnemonic in implicit_regs_map:
        regs_read.update(implicit_regs_map[mnemonic].get("read", set()))
        regs_written.update(implicit_regs_map[mnemonic].get("write", set()))
    if has_rep_prefix:
        is_64bit = "64" in arch_target
        counter_reg = "rcx" if is_64bit else "ecx"
        regs_read.add(counter_reg)
        regs_written.add(counter_reg)
    if is_aarch64:
        if mnemonic in (
            "add",
            "adds",
            "sub",
            "subs",
            "neg",
            "negs",
            "mul",
            "umull",
            "smull",
            "smulh",
            "umulh",
            "div",
            "udiv",
        ):
            if num_operands >= 2:
                dst_regs = extract_regs_from_operand(
                    operands[0].lower(), sorted_arch_regs
                )
                src1_regs = extract_regs_from_operand(
                    operands[1].lower(), sorted_arch_regs
                )
                regs_written.update(dst_regs)
                regs_read.update(src1_regs)
                if num_operands >= 3:
                    src2_regs = extract_regs_from_operand(
                        operands[2].lower(), sorted_arch_regs
                    )
                    regs_read.update(src2_regs)
        elif mnemonic in ("mov", "movz", "movk", "movn", "fmov", "fmov immediate"):
            if num_operands >= 1:
                dst_regs = extract_regs_from_operand(
                    operands[0].lower(), sorted_arch_regs
                )
                regs_written.update(dst_regs)
                if num_operands >= 2 and not operands[1].lower().startswith("#"):
                    src_regs = extract_regs_from_operand(
                        operands[1].lower(), sorted_arch_regs
                    )
                    regs_read.update(src_regs)
        elif mnemonic in ("csel", "csinc", "csinv", "cset", "csetm", "cinc", "cinv"):
            if num_operands >= 3:
                dst_regs = extract_regs_from_operand(
                    operands[0].lower(), sorted_arch_regs
                )
                src1_regs = extract_regs_from_operand(
                    operands[1].lower(), sorted_arch_regs
                )
                src2_regs = extract_regs_from_operand(
                    operands[2].lower(), sorted_arch_regs
                )
                regs_written.update(dst_regs)
                regs_read.update(src1_regs)
                regs_read.update(src2_regs)
                if mnemonic in ("cinc", "cinv"):
                    regs_read.update(dst_regs)
        elif mnemonic in ("cmp", "cmn", "tst"):
            if num_operands >= 2:
                src1_regs = extract_regs_from_operand(
                    operands[0].lower(), sorted_arch_regs
                )
                src2_regs = extract_regs_from_operand(
                    operands[1].lower(), sorted_arch_regs
                )
                regs_read.update(src1_regs)
                regs_read.update(src2_regs)
        elif mnemonic.startswith("ldr") or mnemonic.startswith("str"):
            if num_operands >= 2:
                data_reg = extract_regs_from_operand(
                    operands[0].lower(), sorted_arch_regs
                )
                addr_parts = extract_regs_from_operand(
                    operands[1].lower(), sorted_arch_regs
                )
                if "str" in mnemonic:
                    regs_read.update(data_reg)
                    regs_read.update(addr_parts)
                else:  # ldr
                    regs_written.update(data_reg)
                    regs_read.update(addr_parts)
        elif mnemonic.startswith("ldp") or mnemonic.startswith("stp"):
            if num_operands >= 3:
                data_reg1 = extract_regs_from_operand(
                    operands[0].lower(), sorted_arch_regs
                )
                data_reg2 = extract_regs_from_operand(
                    operands[1].lower(), sorted_arch_regs
                )
                mem_operand = operands[2].lower()
                addr_parts = extract_regs_from_operand(
                    operands[2].lower(), sorted_arch_regs
                )
                if "!" in mem_operand:
                    base_reg = next(iter(addr_parts), None)
                    if base_reg:
                        regs_written.add(base_reg)
                if "str" in mnemonic:
                    regs_read.update(data_reg1)
                    regs_read.update(data_reg2)
                    regs_read.update(addr_parts)
                else:
                    regs_written.update(data_reg1)
                    regs_written.update(data_reg2)
                    regs_read.update(addr_parts)
        elif mnemonic.startswith("cb") or mnemonic.startswith("tb"):
            if num_operands >= 1:
                src_regs = extract_regs_from_operand(
                    operands[0].lower(), sorted_arch_regs
                )
                regs_read.update(src_regs)
        elif mnemonic.startswith("b") and mnemonic not in (
            "bl",
            "blr",
            "blraa",
            "blrab",
            "br",
            "braa",
            "brab",
        ):
            pass
        elif mnemonic in ("bl", "blr", "blraa", "blrab", "br", "braa", "brab"):
            if num_operands >= 1 and mnemonic != "bl":
                target_op = operands[0].lower()
                if not target_op.startswith("#") and not target_op.isdigit():
                    target_regs = extract_regs_from_operand(target_op, sorted_arch_regs)
                    regs_read.update(target_regs)
        elif mnemonic in ("ret", "eret"):
            pass
        elif mnemonic in ("and", "orr", "eor", "bic", "tst"):
            if num_operands >= 2:
                dst_regs = extract_regs_from_operand(
                    operands[0].lower(), sorted_arch_regs
                )
                src1_regs = extract_regs_from_operand(
                    operands[1].lower(), sorted_arch_regs
                )
                regs_written.update(dst_regs)
                regs_read.update(src1_regs)
                if num_operands >= 3:
                    src2_regs = extract_regs_from_operand(
                        operands[2].lower(), sorted_arch_regs
                    )
                    regs_read.update(src2_regs)
        elif mnemonic in (
            "lsl",
            "lsr",
            "asr",
            "ror",
            "uxtw",
            "sxtw",
            "sxtx",
            "uxtb",
            "uxth",
            "sxtb",
            "sxth",
        ):
            if num_operands >= 2:
                dst_regs = extract_regs_from_operand(
                    operands[0].lower(), sorted_arch_regs
                )
                src1_regs = extract_regs_from_operand(
                    operands[1].lower(), sorted_arch_regs
                )
                regs_written.update(dst_regs)
                regs_read.update(src1_regs)
                if num_operands >= 3:
                    src2_regs = extract_regs_from_operand(
                        operands[2].lower(), sorted_arch_regs
                    )
                    regs_read.update(src2_regs)
    elif is_mips:
        if mnemonic in MIPS_ARITH_LOGIC_3_OP or mnemonic in MIPS_SHIFT_3_OP:
            if num_operands >= 3:
                regs_written.update(
                    extract_regs_from_operand(operands[0], sorted_arch_regs)
                )
                regs_read.update(
                    extract_regs_from_operand(operands[1], sorted_arch_regs)
                )
                regs_read.update(
                    extract_regs_from_operand(operands[2], sorted_arch_regs)
                )
        elif mnemonic in MIPS_ARITH_LOGIC_2_OP_IMM or mnemonic in MIPS_SHIFT_2_OP_IMM:
            if num_operands >= 2:
                regs_written.update(
                    extract_regs_from_operand(operands[0], sorted_arch_regs)
                )
                regs_read.update(
                    extract_regs_from_operand(operands[1], sorted_arch_regs)
                )
        elif mnemonic in MIPS_LOAD_STORE:
            if num_operands >= 2:
                data_reg_op = operands[0]
                mem_op = operands[1]
                data_regs = extract_regs_from_operand(data_reg_op, sorted_arch_regs)
                base_addr_regs = extract_regs_from_operand(mem_op, sorted_arch_regs)
                if mnemonic.startswith("s"):
                    regs_read.update(data_regs)
                    regs_read.update(base_addr_regs)
                else:
                    regs_written.update(data_regs)
                    regs_read.update(base_addr_regs)
        elif mnemonic in MIPS_BRANCH_2_OP:
            if num_operands >= 2:
                regs_read.update(
                    extract_regs_from_operand(operands[0], sorted_arch_regs)
                )
                regs_read.update(
                    extract_regs_from_operand(operands[1], sorted_arch_regs)
                )
        elif mnemonic in MIPS_MOVE:
            if num_operands >= 2:
                regs_written.update(
                    extract_regs_from_operand(operands[0], sorted_arch_regs)
                )
                regs_read.update(
                    extract_regs_from_operand(operands[1], sorted_arch_regs)
                )
        elif mnemonic in ("mfhi", "mflo"):
            if num_operands >= 1:
                regs_written.update(
                    extract_regs_from_operand(operands[0], sorted_arch_regs)
                )
        elif mnemonic in MIPS_MULT_DIV:
            if num_operands >= 2:
                regs_read.update(
                    extract_regs_from_operand(operands[0], sorted_arch_regs)
                )
                regs_read.update(
                    extract_regs_from_operand(operands[1], sorted_arch_regs)
                )
        elif mnemonic == "jr":
            if num_operands >= 1:
                regs_read.update(
                    extract_regs_from_operand(operands[0], sorted_arch_regs)
                )
        elif mnemonic in ("jalr", "bal"):
            if num_operands >= 1:
                if num_operands == 2:
                    regs_written.update(
                        extract_regs_from_operand(operands[0], sorted_arch_regs)
                    )
                    regs_read.update(
                        extract_regs_from_operand(operands[1], sorted_arch_regs)
                    )
                else:
                    regs_read.update(
                        extract_regs_from_operand(operands[0], sorted_arch_regs)
                    )
    else:
        if mnemonic in WRITE_DST_READ_SRC_INST or mnemonic.startswith("cmov"):
            if num_operands >= 2:
                dst_regs = extract_regs_from_operand(
                    operands[0].lower(), sorted_arch_regs
                )
                src_regs = extract_regs_from_operand(
                    operands[1].lower(), sorted_arch_regs
                )
                regs_written.update(dst_regs)
                regs_read.update(src_regs)
                if mnemonic not in (
                    "mov",
                    "movzx",
                    "movsx",
                    "movsxd",
                    "lea",
                ) and not mnemonic.startswith("cmov"):
                    regs_read.update(dst_regs)
        elif mnemonic in READ_WRITE_BOTH_OPS_INST:
            if num_operands >= 2:
                op1_regs = extract_regs_from_operand(
                    operands[0].lower(), sorted_arch_regs
                )
                op2_regs = extract_regs_from_operand(
                    operands[1].lower(), sorted_arch_regs
                )
                regs_read.update(op1_regs)
                regs_written.update(op1_regs)
                regs_read.update(op2_regs)
                if mnemonic != "cmpxchg":
                    regs_written.update(op2_regs)
        elif mnemonic in BIT_MANIPULATION_INST:
            if num_operands >= 2:
                dst_regs = extract_regs_from_operand(
                    operands[0].lower(), sorted_arch_regs
                )
                src_regs = extract_regs_from_operand(
                    operands[1].lower(), sorted_arch_regs
                )
                regs_written.update(dst_regs)
                regs_read.update(src_regs)
                if mnemonic not in ("bsf", "bsr", "lzcnt", "tzcnt", "popcnt"):
                    regs_read.update(dst_regs)
        elif mnemonic in READ_WRITE_ONE_OP_INST:
            if num_operands >= 1:
                op_regs = extract_regs_from_operand(
                    operands[0].lower(), sorted_arch_regs
                )
                regs_read.update(op_regs)
                regs_written.update(op_regs)
        elif mnemonic in ("cmp", "test"):
            if num_operands >= 2:
                regs_read.update(
                    extract_regs_from_operand(operands[0].lower(), sorted_arch_regs)
                )
                regs_read.update(
                    extract_regs_from_operand(operands[1].lower(), sorted_arch_regs)
                )
        elif mnemonic in ("push", "pop"):
            is_64bit = "64" in arch_target
            stack_reg = "rsp" if is_64bit else "esp"
            regs_read.add(stack_reg)
            regs_written.add(stack_reg)
            if num_operands >= 1:
                op_regs = extract_regs_from_operand(
                    operands[0].lower(), sorted_arch_regs
                )
                if mnemonic == "push":
                    regs_read.update(op_regs)
                else:
                    regs_written.update(op_regs)
        elif mnemonic == "call":
            volatile_regs = _get_abi_volatile_regs(parsed_obj, arch_target)
            regs_written.update(volatile_regs)
            if num_operands >= 1:
                op = operands[0].lower()
                if not op.startswith("0x") and not op.isdigit():
                    op_regs = extract_regs_from_operand(op, sorted_arch_regs)
                    regs_read.update(op_regs)
        elif mnemonic in TERMINATING_INST:
            is_64bit = "64" in arch_target or "aarch64" in arch_target
            if is_64bit:
                regs_read.update(X64_RETURN_REGS)
            else:
                regs_read.update(X86_RETURN_REGS)
            stack_reg = "rsp" if is_64bit else "esp"
            regs_read.add(stack_reg)
            regs_written.add(stack_reg)
        elif mnemonic.startswith("j"):
            if num_operands >= 1:
                op = operands[0].lower()
                if not op.startswith("0x") and not op.isdigit():
                    op_regs = extract_regs_from_operand(op, sorted_arch_regs)
                    regs_read.update(op_regs)
        elif mnemonic == "xchg":
            if num_operands >= 2:
                op1_regs = extract_regs_from_operand(
                    operands[0].lower(), sorted_arch_regs
                )
                op2_regs = extract_regs_from_operand(
                    operands[1].lower(), sorted_arch_regs
                )
                regs_read.update(op1_regs)
                regs_written.update(op1_regs)
                regs_read.update(op2_regs)
                regs_written.update(op2_regs)
        if mnemonic in ("mul", "imul", "div", "idiv") and num_operands == 1:
            op_regs = extract_regs_from_operand(operands[0].lower(), sorted_arch_regs)
            regs_read.update(op_regs)

    return sorted(regs_read), sorted(regs_written)


def _analyze_instructions(
    instr_list,
    func_addr,
    next_func_addr_in_sec,
    instr_addresses,
    parsed_obj=None,
    arch_target="",
):
    """Analyzes the list of instructions for metrics, loops, and indirect calls."""
    is_aarch64 = "aarch64" in arch_target.lower() or "arm64" in arch_target.lower()
    is_mips = "mips" in arch_target.lower()
    if is_aarch64:
        CALL_INST = ARM64_CALL_INST
        UNCONDITIONAL_JMP_INST = ARM64_UNCONDITIONAL_JMP_INST
        RET_INST = ARM64_RET_INST
    elif is_mips:
        CALL_INST = MIPS_CALL_INST
        UNCONDITIONAL_JMP_INST = MIPS_UNCONDITIONAL_JMP_INST
        RET_INST = MIPS_RET_INST
    else:
        CALL_INST = X86_CALL_INST
        UNCONDITIONAL_JMP_INST = X86_UNCONDITIONAL_JMP_INST
        RET_INST = X86_RET_INST
    instruction_mnemonics = []
    instruction_metrics = {
        "call_count": 0,
        "conditional_jump_count": 0,
        "xor_count": 0,
        "shift_count": 0,
        "arith_count": 0,
        "ret_count": 0,
        "jump_count": 0,
        "simd_fpu_count": 0,
    }
    has_indirect_call = False
    has_loop = False
    has_pac = False
    all_regs_read = set()
    all_regs_written = set()
    used_simd_reg_types = set()
    instructions_with_registers = []
    sorted_arch_regs = get_arch_reg_set(arch_target)
    proprietary_instr_found = set()
    sreg_interactions = set()
    is_apple_silicon = "aarch64" in arch_target.lower() and isinstance(
        parsed_obj, lief.MachO.Binary
    )
    for instr in instr_list:
        instr_assembly = instr.assembly
        parts = instr_assembly.split()
        if is_apple_silicon and len(instr.bytes) == 4:
            opcode = int.from_bytes(instr.bytes, "little")
            for name, (start, end) in APPLE_PROPRIETARY_INSTRUCTION_RANGES.items():
                if start <= opcode <= end:
                    proprietary_instr_found.add(name)
                    break
        mnemonic_and_operands = instr_assembly.split(None, 1)
        mnemonic = mnemonic_and_operands[0].lower()
        if is_apple_silicon and mnemonic in ("mrs", "msr") and len(parts) > 1:
            operands_str = mnemonic_and_operands[1]
            operands = [op.strip().lower() for op in operands_str.split(",")]
            sreg_operand = None
            try:
                if mnemonic == "mrs":
                    sreg_operand = operands[1]
                elif mnemonic == "msr":
                    sreg_operand = operands[0]
            except IndexError:
                pass
            if sreg_operand and sreg_operand in _SREG_TO_CATEGORY_MAP:
                sreg_interactions.add(_SREG_TO_CATEGORY_MAP[sreg_operand])
        instruction_mnemonics.append(mnemonic)
        if mnemonic in ARM64_PAC_INST:
            has_pac = True
        elif mnemonic == "hint":
            if len(parts) > 1:
                operand = parts[1].strip().replace("#", "")
                if operand in ARM64_PAC_HINTS:
                    has_pac = True
        if mnemonic in CALL_INST:
            instruction_metrics["call_count"] += 1
        elif mnemonic in CONDITIONAL_JMP_INST:
            instruction_metrics["conditional_jump_count"] += 1
            if len(parts) >= 2:
                target_part = parts[1]
                if target_part.startswith("0x"):
                    try:
                        target_addr = int(target_part, 16)
                        if (
                            func_addr <= target_addr < next_func_addr_in_sec
                            and target_addr < instr.address
                            and target_addr in instr_addresses
                        ):
                            has_loop = True
                    except ValueError:
                        continue
        elif mnemonic in UNCONDITIONAL_JMP_INST:
            instruction_metrics["jump_count"] += 1
        elif mnemonic == "xor":
            instruction_metrics["xor_count"] += 1
        elif mnemonic in SHIFT_INST:
            instruction_metrics["shift_count"] += 1
        elif mnemonic in ARITH_INST:
            instruction_metrics["arith_count"] += 1
        elif mnemonic in RET_INST:
            instruction_metrics["ret_count"] += 1
        # Check for ARM64 indirect calls and jumps
        if mnemonic in (CALL_INST | UNCONDITIONAL_JMP_INST):
            is_indirect = False
            if len(parts) > 1:
                operand = parts[1].lower().strip()
                reg_token = _extract_register_token(operand, set(sorted_arch_regs))
                if reg_token:
                    is_indirect = True
                elif "[" in operand and "]" in operand:
                    is_indirect = True
            if is_indirect:
                has_indirect_call = True
        regs_read, regs_written = _extract_register_usage(
            instr_assembly, parsed_obj, arch_target, sorted_arch_regs
        )
        all_instr_regs = set(regs_read) | set(regs_written)
        is_simd_fpu = False
        if "aarch64" in arch_target.lower() or "arm64" in arch_target.lower():
            if any(reg in ARM64_VFP_NEON_REGS for reg in all_instr_regs):
                used_simd_reg_types.add("NEON/VFP")
                is_simd_fpu = True
        else:
            if any(reg in FPU_REGS for reg in all_instr_regs):
                used_simd_reg_types.add("FPU")
                is_simd_fpu = True
            if any(reg in MMX_REGS for reg in all_instr_regs):
                used_simd_reg_types.add("MMX")
                is_simd_fpu = True
            if any(reg in XMM_REGS for reg in all_instr_regs):
                used_simd_reg_types.add("SSE/AVX")
                is_simd_fpu = True
            if any(reg in YMM_REGS for reg in all_instr_regs):
                used_simd_reg_types.add("AVX/AVX2")
                is_simd_fpu = True
            if any(reg in ZMM_REGS for reg in all_instr_regs):
                used_simd_reg_types.add("AVX-512")
                is_simd_fpu = True
        if is_simd_fpu:
            instruction_metrics["simd_fpu_count"] += 1
        all_regs_read.update(regs_read)
        all_regs_written.update(regs_written)
        if regs_read or regs_written:
            reg_data = {"position": len(instruction_mnemonics) - 1}
            if regs_read:
                reg_data["regs_read"] = regs_read
            if regs_written:
                reg_data["regs_written"] = regs_written
            instructions_with_registers.append(reg_data)
        instruction_metrics["unique_regs_read_count"] = len(all_regs_read)
        instruction_metrics["unique_regs_written_count"] = len(all_regs_written)
    return (
        instruction_metrics,
        instruction_mnemonics,
        has_indirect_call,
        has_loop,
        sorted(all_regs_read),
        sorted(all_regs_written),
        instructions_with_registers,
        sorted(used_simd_reg_types),
        sorted(proprietary_instr_found),
        sorted(sreg_interactions),
        has_pac,
    )


def _build_addr_to_name_map(metadata, parsed_obj=None):
    """Builds a lookup map from address (int) to name from metadata functions."""
    addr_to_name_map = {}
    for func_list_key in FUNCTION_SYMBOLS:
        for func_entry in metadata.get(func_list_key, []):
            addr_str = func_entry.get("address", "")
            name = func_entry.get("name", "")
            if addr_str and name:
                try:
                    addr_int = int(addr_str, 16)
                    addr_to_name_map[addr_int] = name
                except ValueError:
                    continue
            if name:
                value = func_entry.get("value")
                if isinstance(value, int) and value >= 0:
                    addr_to_name_map[value] = name
                elif isinstance(value, str):
                    with contextlib.suppress(ValueError):
                        addr_to_name_map[int(value, 16)] = name
            # IAT absolute addresses for resolving indirect RIP calls
            iat_addr = func_entry.get("iat_address")
            if iat_addr and name:
                addr_to_name_map[iat_addr] = name

    # For ELF binaries, GOT/PLT relocation slots carry imported symbol names.
    if isinstance(parsed_obj, lief.ELF.Binary):
        for reloc_list in (
            getattr(parsed_obj, "pltgot_relocations", []),
            getattr(parsed_obj, "dynamic_relocations", []),
        ):
            for reloc in reloc_list:
                with contextlib.suppress(AttributeError, TypeError, ValueError):
                    if not reloc.has_symbol:
                        continue
                    sym_name = (reloc.symbol.name or "").strip()
                    if not sym_name:
                        continue
                    addr_to_name_map[int(reloc.address)] = sym_name
    return addr_to_name_map


def _append_unique_target_addr(target_addrs: list[int], addr_val):
    if isinstance(addr_val, int) and addr_val >= 0 and addr_val not in target_addrs:
        target_addrs.append(addr_val)


def _resolve_operand_target_addresses(
    mnemonic: str,
    operand: str,
    instr,
    is_aarch64: bool,
    is_mips: bool,
    is_windows: bool,
):
    """Parse operand forms and return normalized numeric target candidates."""
    operand = (operand or "").strip().rstrip(",")
    if operand.startswith("#"):
        operand = operand[1:]
    target_addrs = []
    try:
        if "rip" in operand.lower():
            match = re.search(
                r"\[rip\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)]", operand.lower()
            )
            if match:
                sign = 1 if match.group(1) == "+" else -1
                offset = (
                    int(match.group(2), 16)
                    if match.group(2).startswith("0x")
                    else int(match.group(2))
                )
                _append_unique_target_addr(
                    target_addrs, instr.address + len(instr.bytes) + (sign * offset)
                )
        else:
            match_hex = re.search(r"[-+]?0x[0-9a-fA-F]+", operand)
            if match_hex:
                _append_unique_target_addr(target_addrs, int(match_hex.group(0), 16))
            elif operand.isdigit() or operand.startswith(("+", "-")):
                val = int(operand)
                if mnemonic == "bal":
                    _append_unique_target_addr(target_addrs, instr.address + 4 + val)
                elif is_aarch64:
                    # Some AArch64 disassembly styles emit branch immediates as
                    # hex-like digits without a 0x prefix (for example #410212).
                    # Try that interpretation first for larger operands, then keep
                    # decimal as fallback.
                    if operand.isdigit() and len(operand) >= 5:
                        with contextlib.suppress(ValueError):
                            _append_unique_target_addr(target_addrs, int(operand, 16))
                    if operand.startswith(("+", "-")):
                        _append_unique_target_addr(target_addrs, instr.address + val)
                        _append_unique_target_addr(
                            target_addrs, instr.address + 4 + val
                        )
                    else:
                        # Unsigned AArch64 branch immediates are frequently emitted
                        # as PC-relative decimal deltas.
                        _append_unique_target_addr(target_addrs, instr.address + val)
                        _append_unique_target_addr(
                            target_addrs, instr.address + 4 + val
                        )
                    _append_unique_target_addr(target_addrs, val)
                elif not is_mips and (
                    mnemonic.startswith("call")
                    or (is_windows and mnemonic.startswith("j"))
                ):
                    _append_unique_target_addr(
                        target_addrs, instr.address + len(instr.bytes) + val
                    )
                    # Keep absolute fallback for call-like operands where disassembly style
                    # can vary between relative and absolute textual forms.
                    if mnemonic.startswith("call"):
                        _append_unique_target_addr(target_addrs, val)
                else:
                    _append_unique_target_addr(target_addrs, val)
    except (ValueError, IndexError, AttributeError):
        return []
    return target_addrs


def _extract_symbol_from_operand(operand: str, arch_reg_set: set[str]) -> str:
    """Symbol extraction fallback for cases where numeric resolution fails."""
    operand = (operand or "").strip()
    if not operand:
        return ""
    if "<" in operand and ">" in operand:
        inside = operand.split("<", 1)[1].split(">", 1)[0]
        inside = inside.split("@", 1)[0].split("+", 1)[0].strip()
        if inside and inside.lower().lstrip("%") not in arch_reg_set:
            return inside
    cleaned = operand.split("+", 1)[0].split("@", 1)[0].strip()
    if (
        cleaned
        and not cleaned.startswith(("0x", "#"))
        and "[" not in cleaned
        and cleaned.lower().lstrip("%") not in arch_reg_set
    ):
        return cleaned
    return ""


def _parse_immediate_token(token: str):
    token = (token or "").strip().lstrip("#")
    if not token:
        return None
    with contextlib.suppress(ValueError):
        if token.lower().startswith(("-0x", "+0x", "0x")):
            return int(token, 16)
        if token.startswith(("+", "-")) or token.isdigit():
            return int(token, 10)
    return None


def _parse_x86_memory_operand_base_disp(
    operand: str, arch_reg_set: set[str]
) -> tuple[str, int]:
    """Parse simple x86 memory operands like [rax + 72] or [r12 + 0x48]."""
    operand = (operand or "").strip().lower()
    match = re.search(r"\[\s*([%a-z0-9]+)\s*([+-])\s*(0x[0-9a-f]+|\d+)\s*\]", operand)
    if match:
        base_reg = match.group(1).lstrip("%")
        if base_reg in arch_reg_set:
            disp = (
                int(match.group(3), 16)
                if match.group(3).startswith("0x")
                else int(match.group(3))
            )
            return base_reg, disp if match.group(2) == "+" else -disp

    match = re.search(r"\[\s*([%a-z0-9]+)\s*\]", operand)
    if match:
        base_reg = match.group(1).lstrip("%")
        if base_reg in arch_reg_set:
            return base_reg, 0

    return "", 0


def _parse_arm64_memory_operand_base_disp(
    operand: str, arch_reg_set: set[str]
) -> tuple[str, int, bool]:
    """Parse ARM64 memory operands like [x8, #0x18], [x8], or [x8], #0x20."""
    operand = (operand or "").strip().lower()
    match = re.search(r"\[([^\]]+)]", operand)
    if not match:
        return "", 0, False

    inner = match.group(1)
    inner_parts = [part.strip() for part in inner.split(",") if part.strip()]
    if not inner_parts:
        return "", 0, True

    base_reg = inner_parts[0].lstrip("%")
    if base_reg not in arch_reg_set:
        return "", 0, True

    displacement = 0
    if len(inner_parts) >= 2:
        imm = _parse_immediate_token(inner_parts[1])
        if imm is not None:
            displacement = imm

    # Post-index form: ldr x0, [x1], #0x20
    tail = operand[match.end() :].strip().lstrip(",").strip()
    if tail:
        imm = _parse_immediate_token(tail)
        if imm is not None:
            displacement += imm

    return base_reg, displacement, True


def _extract_reg_target_candidate_addrs(reg_target: dict) -> list[int]:
    out = []
    for inferred_candidate in reg_target.get("inferred_address_candidates", []):
        with contextlib.suppress(ValueError, TypeError):
            _append_unique_target_addr(out, int(inferred_candidate, 16))
    for candidate in reg_target.get("target_address_candidates", []):
        with contextlib.suppress(ValueError, TypeError):
            _append_unique_target_addr(out, int(candidate, 16))
    if not out and reg_target.get("target_address"):
        with contextlib.suppress(ValueError, TypeError):
            _append_unique_target_addr(out, int(reg_target.get("target_address"), 16))
    return out


def _adjust_candidate_addrs(candidate_addrs: list[int], displacement: int) -> list[int]:
    out = []
    for addr in candidate_addrs:
        _append_unique_target_addr(out, addr + displacement)
    return out


def _get_chain_hops(reg_target: dict) -> int:
    with contextlib.suppress(TypeError, ValueError):
        return int(reg_target.get("chain_hops", 0))
    return 0


def _extract_register_token(operand: str, arch_reg_set: set[str]) -> str:
    cleaned = (operand or "").strip().lower().rstrip(",")
    if not cleaned or "[" in cleaned or "]" in cleaned:
        return ""
    # Branch-auth forms like `blraa x16, x17` carry extra operands; target is first.
    if "," in cleaned:
        cleaned = cleaned.split(",", 1)[0].strip()
    cleaned = cleaned.lstrip("*#")
    parts = cleaned.split()
    token = parts[-1] if parts else cleaned
    token = token.lstrip("%")
    return token if token in arch_reg_set else ""


def _arm64_memory_operand_uses_index_register(
    operand: str, arch_reg_set: set[str]
) -> bool:
    """Return True when ARM64 memory operand address depends on an index register."""
    operand = (operand or "").strip().lower()
    match = re.search(r"\[([^\]]+)]", operand)
    if not match:
        return False
    inner_parts = [part.strip() for part in match.group(1).split(",") if part.strip()]
    if len(inner_parts) < 2:
        return False
    if _parse_immediate_token(inner_parts[1]) is not None:
        return False
    return inner_parts[1].lstrip("%") in arch_reg_set


def _filter_windows_arm64_indirect_candidates(
    candidate_addrs: list[int], is_windows: bool, is_aarch64: bool
) -> list[int]:
    if not (is_windows and is_aarch64):
        return candidate_addrs
    # Keep only canonical low virtual addresses for Windows ARM64 indirect hints.
    return [addr for addr in candidate_addrs if 0 <= addr <= 0x0000FFFFFFFFFFFF]


def _update_register_target(
    instr,
    reg_targets: dict,
    arch_reg_set: set[str],
    is_aarch64: bool,
    is_mips: bool,
    is_windows: bool,
    chain_hop_limit: int = 2,
):
    """Track register assignments used later for indirect call hints."""
    parts = instr.assembly.split(None, 1)
    if len(parts) < 2:
        return
    mnemonic = parts[0].lower()
    operands = [op.strip() for op in parts[1].split(",")]
    if not operands:
        return
    dst_reg = _extract_register_token(operands[0], arch_reg_set)
    if not dst_reg:
        return

    if is_aarch64 and mnemonic.startswith("ldr") and len(operands) >= 2:
        # ARM64 memory operands contain commas inside brackets, so we rebuild
        # the source operand from all remaining tokens.
        src = ",".join(operands[1:]).strip()
        src_base_reg, src_displacement, has_mem_operand = (
            _parse_arm64_memory_operand_base_disp(src, arch_reg_set)
        )
        if has_mem_operand:
            if _arm64_memory_operand_uses_index_register(src, arch_reg_set):
                reg_targets.pop(dst_reg, None)
                return
            if src_base_reg and src_base_reg in reg_targets:
                base_target = reg_targets[src_base_reg]
                next_hops = _get_chain_hops(base_target) + 1
                if next_hops > chain_hop_limit:
                    reg_targets.pop(dst_reg, None)
                    return
                adjusted_addrs = _adjust_candidate_addrs(
                    _extract_reg_target_candidate_addrs(base_target), src_displacement
                )
                adjusted_addrs = _filter_windows_arm64_indirect_candidates(
                    adjusted_addrs, is_windows, is_aarch64
                )
                if adjusted_addrs:
                    reg_targets[dst_reg] = {
                        "target_name": "",
                        "target_address": hex(adjusted_addrs[0]),
                        "target_address_candidates": [hex(a) for a in adjusted_addrs],
                        "raw_operand": src.split("<", 1)[0].strip(),
                        "chain_hops": next_hops,
                    }
                    return
            reg_targets.pop(dst_reg, None)
            return

    if (
        mnemonic in {"mov", "movq", "movabs", "lea", "adr", "adrp"}
        and len(operands) >= 2
    ):
        src = operands[1]
        src_base_reg, src_displacement = _parse_x86_memory_operand_base_disp(
            src, arch_reg_set
        )
        if (
            is_windows
            and src_base_reg
            and src_base_reg != "rip"
            and src_base_reg in reg_targets
        ):
            base_target = reg_targets[src_base_reg]
            next_hops = _get_chain_hops(base_target) + 1
            if next_hops > chain_hop_limit:
                reg_targets.pop(dst_reg, None)
                return
            adjusted_addrs = _adjust_candidate_addrs(
                _extract_reg_target_candidate_addrs(base_target), src_displacement
            )
            if adjusted_addrs:
                reg_targets[dst_reg] = {
                    "target_name": "",
                    "target_address": "",
                    "target_address_candidates": [],
                    "inferred_address_candidates": [hex(a) for a in adjusted_addrs],
                    "raw_operand": "",
                    "chain_hops": next_hops,
                }
                return
            reg_targets.pop(dst_reg, None)
            return

        if is_windows and src_base_reg and src_base_reg != "rip":
            # Avoid treating `[reg + imm]` immediates as absolute constants when
            # chain state is unavailable.
            reg_targets.pop(dst_reg, None)
            return

        addrs = _resolve_operand_target_addresses(
            mnemonic, src, instr, is_aarch64, is_mips, is_windows
        )
        addrs = _filter_windows_arm64_indirect_candidates(addrs, is_windows, is_aarch64)
        name = _extract_symbol_from_operand(src, arch_reg_set)
        raw = src.split("<", 1)[0].strip()
        if addrs or name:
            reg_targets[dst_reg] = {
                "target_name": name,
                "target_address": hex(addrs[0]) if addrs else "",
                "target_address_candidates": [hex(a) for a in addrs],
                "raw_operand": raw,
                "chain_hops": 0,
            }
            return
        reg_targets.pop(dst_reg, None)
        return
    if mnemonic in {"add", "sub"} and len(operands) >= 3:
        src_reg = _extract_register_token(operands[1], arch_reg_set)
        imm = _parse_immediate_token(operands[2])
        if src_reg and imm is not None and src_reg in reg_targets:
            base = reg_targets[src_reg]
            base_candidates = []
            for candidate in base.get("target_address_candidates", []):
                with contextlib.suppress(ValueError):
                    base_candidates.append(int(candidate, 16))
            if not base_candidates and base.get("target_address"):
                with contextlib.suppress(ValueError):
                    base_candidates.append(int(base["target_address"], 16))
            if base_candidates:
                adjusted = [
                    val + imm if mnemonic == "add" else val - imm
                    for val in base_candidates
                ]
                adjusted = _filter_windows_arm64_indirect_candidates(
                    adjusted, is_windows, is_aarch64
                )
                if not adjusted:
                    reg_targets.pop(dst_reg, None)
                    return
                reg_targets[dst_reg] = {
                    "target_name": base.get("target_name", ""),
                    "target_address": hex(adjusted[0]),
                    "target_address_candidates": [hex(a) for a in adjusted],
                    "raw_operand": base.get("raw_operand", ""),
                    "chain_hops": _get_chain_hops(base),
                }
                return
        reg_targets.pop(dst_reg, None)


def _resolve_direct_calls(instr_list, addr_to_name_map, arch_target=""):
    """Identifies direct calls and returns both legacy names and rich call targets."""
    potential_callees = []
    direct_call_targets = []
    is_aarch64 = "aarch64" in arch_target.lower() or "arm64" in arch_target.lower()
    is_mips = "mips" in arch_target.lower()
    is_windows = "windows" in arch_target.lower()
    arch_reg_set = {
        reg.lower() for reg in get_arch_reg_set(arch_target) if isinstance(reg, str)
    }
    reg_targets = {}

    for instr in instr_list:
        instr_assembly = instr.assembly
        parts = instr_assembly.split(None, 1)
        if not parts:
            continue
        mnemonic = parts[0].lower()
        _update_register_target(
            instr,
            reg_targets,
            arch_reg_set,
            is_aarch64=is_aarch64,
            is_mips=is_mips,
            is_windows=is_windows,
        )
        is_direct_call = False
        is_indirect_call = False
        if (
            (is_aarch64 and mnemonic == "bl")
            or (is_mips and mnemonic in MIPS_CALL_INST)
            or (not is_aarch64 and not is_mips and mnemonic.startswith("call"))
        ):
            is_direct_call = True
        if len(parts) > 1:
            operand_text = parts[1]
            operand_reg = _extract_register_token(operand_text, arch_reg_set)
            has_memory_operand = "[" in operand_text and "]" in operand_text
            if (is_aarch64 and mnemonic in {"blr", "blraa", "blrab"}) or (
                not is_aarch64
                and not is_mips
                and mnemonic.startswith("call")
                and (operand_reg or has_memory_operand)
            ):
                is_indirect_call = True
                is_direct_call = False

        if is_indirect_call and len(parts) > 1:
            operand_text = parts[1].strip()
            reg_token = _extract_register_token(operand_text, arch_reg_set)
            if reg_token and reg_token in reg_targets:
                reg_target = reg_targets[reg_token]
                target_name = reg_target.get("target_name", "")
                if not target_name:
                    for candidate_addr in _extract_reg_target_candidate_addrs(
                        reg_target
                    ):
                        target_name = (
                            addr_to_name_map.get(candidate_addr)
                            or addr_to_name_map.get(candidate_addr & ~1)
                            or ""
                        )
                        if target_name:
                            break
                direct_call_targets.append(
                    {
                        "target_name": target_name,
                        "target_address": reg_target.get("target_address", ""),
                        "target_address_candidates": reg_target.get(
                            "target_address_candidates", []
                        ),
                        "raw_operand": reg_target.get("raw_operand", reg_token),
                        "kind": "indirect_hint",
                    }
                )
                continue

            # Preserve memory-indirect and annotated-symbol evidence for
            # unresolved bucketing without pretending the pointer slot is callee VA.
            if "[" in operand_text and "]" in operand_text:
                target_name = ""
                base_reg, displacement = _parse_x86_memory_operand_base_disp(
                    operand_text, arch_reg_set
                )
                if base_reg and base_reg in reg_targets:
                    reg_target = reg_targets[base_reg]
                    for candidate_addr in _adjust_candidate_addrs(
                        _extract_reg_target_candidate_addrs(reg_target), displacement
                    ):
                        target_name = (
                            addr_to_name_map.get(candidate_addr)
                            or addr_to_name_map.get(candidate_addr & ~1)
                            or ""
                        )
                        if target_name:
                            break
                    if not target_name and displacement == 0:
                        target_name = reg_target.get("target_name", "")

                target_addrs = _resolve_operand_target_addresses(
                    mnemonic, operand_text, instr, is_aarch64, is_mips, is_windows
                )
                if not target_name:
                    for candidate_addr in target_addrs:
                        target_name = (
                            addr_to_name_map.get(candidate_addr)
                            or addr_to_name_map.get(candidate_addr & ~1)
                            or ""
                        )
                        if target_name:
                            break
                if not target_name:
                    target_name = _extract_symbol_from_operand(
                        operand_text, arch_reg_set
                    )
                raw_operand = operand_text.split("<", 1)[0].strip()
                if target_name or raw_operand:
                    direct_call_targets.append(
                        {
                            "target_name": target_name,
                            "target_address": "",
                            "target_address_candidates": [],
                            "raw_operand": raw_operand,
                            "kind": "indirect_hint",
                        }
                    )
            continue

        if is_direct_call and len(parts) > 1:
            operand = parts[1].strip()
            target_addrs = _resolve_operand_target_addresses(
                mnemonic, operand, instr, is_aarch64, is_mips, is_windows
            )
            target_addr = target_addrs[0] if target_addrs else None
            target_name = ""
            for candidate_addr in target_addrs:
                target_name = (
                    addr_to_name_map.get(candidate_addr)
                    or addr_to_name_map.get(candidate_addr & ~1)
                    or ""
                )
                if target_name:
                    potential_callees.append(target_name)
                    break
            if not target_name:
                target_name = _extract_symbol_from_operand(operand, arch_reg_set)
                if target_name:
                    potential_callees.append(target_name)
            raw_operand = operand.split("<", 1)[0].strip()
            direct_call_targets.append(
                {
                    "target_name": target_name,
                    "target_address": hex(target_addr)
                    if target_addr is not None
                    else "",
                    "target_address_candidates": [hex(t) for t in target_addrs],
                    "raw_operand": raw_operand,
                    "kind": "direct",
                }
            )

    # This recovers common compiler-emitted tail dispatch patterns that would
    # otherwise appear as disconnected terminal blocks.
    if instr_list:
        tail_instr = instr_list[-1]
        parts = tail_instr.assembly.split(None, 1)
        if parts:
            mnemonic = parts[0].lower()
            jump_set = (
                ARM64_UNCONDITIONAL_JMP_INST
                if is_aarch64
                else MIPS_UNCONDITIONAL_JMP_INST
                if is_mips
                else X86_UNCONDITIONAL_JMP_INST
            )
            if mnemonic in jump_set and len(parts) > 1:
                operand = parts[1].strip()
                reg_token = _extract_register_token(operand, arch_reg_set)
                if reg_token and reg_token in reg_targets:
                    reg_target = reg_targets[reg_token]
                    target_addrs = _extract_reg_target_candidate_addrs(reg_target)
                    target_addr = target_addrs[0] if target_addrs else None
                    target_name = reg_target.get("target_name", "")
                    if not target_name:
                        for candidate_addr in target_addrs:
                            target_name = (
                                addr_to_name_map.get(candidate_addr)
                                or addr_to_name_map.get(candidate_addr & ~1)
                                or ""
                            )
                            if target_name:
                                break
                    raw_operand = operand.split("<", 1)[0].strip()
                    if target_name or target_addr is not None or raw_operand:
                        direct_call_targets.append(
                            {
                                "target_name": target_name,
                                "target_address": hex(target_addr)
                                if target_addr is not None
                                else "",
                                "target_address_candidates": [
                                    hex(t) for t in target_addrs
                                ],
                                "raw_operand": raw_operand,
                                "kind": "tailcall",
                            }
                        )
                elif not any(ch in operand for ch in ("[", "]")):
                    target_addrs = _resolve_operand_target_addresses(
                        mnemonic,
                        operand,
                        tail_instr,
                        is_aarch64,
                        is_mips,
                        is_windows,
                    )
                    target_addr = target_addrs[0] if target_addrs else None
                    target_name = ""
                    for candidate_addr in target_addrs:
                        target_name = (
                            addr_to_name_map.get(candidate_addr)
                            or addr_to_name_map.get(candidate_addr & ~1)
                            or ""
                        )
                        if target_name:
                            break
                    if not target_name:
                        target_name = _extract_symbol_from_operand(
                            operand, arch_reg_set
                        )
                    raw_operand = operand.split("<", 1)[0].strip()
                    if target_name or target_addr is not None or raw_operand:
                        direct_call_targets.append(
                            {
                                "target_name": target_name,
                                "target_address": hex(target_addr)
                                if target_addr is not None
                                else "",
                                "target_address_candidates": [
                                    hex(t) for t in target_addrs
                                ],
                                "raw_operand": raw_operand,
                                "kind": "tailcall",
                            }
                        )
    return potential_callees, direct_call_targets


def _classify_function(
    instruction_metrics,
    instruction_count,
    plain_assembly_text,
    has_system_call,
    has_indirect_call,
):
    """Classifies the function based on metrics and other flags."""
    function_type = ""
    if (
        instruction_metrics["jump_count"] > 0
        and instruction_count <= 5
        and all(
            mnem in ("jmp", "push", "sub")
            for mnem in [
                i.split(None, 1)[0].lower()
                for i in plain_assembly_text.split("\n")
                if i.strip()
            ]
        )
    ):
        function_type = "PLT_Thunk"
    elif instruction_count == 1 and instruction_metrics["ret_count"] == 1:
        function_type = "Simple_Return"
    elif has_system_call:
        function_type = "Has_Syscalls"
    elif has_indirect_call:
        function_type = "Has_Indirect_Calls"
    elif instruction_metrics["conditional_jump_count"] > 0:
        function_type = "Has_Conditional_Jumps"
    return function_type


def _mem_bytes_len(b):
    if isinstance(b, list):
        return len(b)
    if hasattr(b, "nbytes"):
        return getattr(b, "nbytes")
    return None


def _try_disassemble(instance, byte_list, address, inst_count=0):
    """Helper to safely call Nyxstone and handle immediate failures."""
    try:
        instructions = instance.disassemble_to_instructions(
            byte_list, address, inst_count
        )
        return instructions if instructions else None
    except ValueError:
        return None


def disassemble_functions(
    parsed_obj, metadata, arch_target="", cpu="", features="", immediate_style=0
):
    """
    Disassembles functions found in the metadata dictionary using Nyxstone.
    Retrieves section content directly from the parsed_obj.

    Args:
        parsed_obj: The original lief parsed object (lief.ELF.Binary, lief.PE.Binary, lief.MachO.Binary).
        metadata (dict): The metadata dictionary containing parsed binary info (for function addresses/names).
        arch_target (str): The LLVM target triple or architecture (e.g., "x86_64", "aarch64").
        cpu (str): The LLVM CPU specifier (optional).
        features (str): The LLVM feature string (optional).
        immediate_style (int): IntegerBase enum value for immediate printing style (0=Dec, 1=HexPrefix, 2=HexSuffix).

    Returns:
        dict: A dictionary mapping function names/addresses to their disassembly results.
    """
    disassembly_results = {}
    if not NYXSTONE_AVAILABLE:
        LOG.debug("Nyxstone is not available. Cannot perform disassembly.")
        return disassembly_results
    if not arch_target:
        arch_target = metadata.get("llvm_target_tuple")
    if "aarch64" in arch_target.lower() or "arm64" in arch_target.lower():
        if not features:
            features = "+pauth"
        elif "+pauth" not in features:
            features += ",+pauth"
    try:
        LOG.debug(
            f"Attempting to disassemble functions using Nyxstone for target: {arch_target}"
        )
        nyxstone_instance = Nyxstone(
            target_triple=arch_target,
            cpu=cpu,
            features=features,
            immediate_style=immediate_style,
        )
    except ValueError as e:
        LOG.error(f"Failed to initialize Nyxstone for target '{arch_target}': {e}")
        return disassembly_results
    mips16_nyxstone_instance = None
    micromips_nyxstone_instance = None
    is_mips = "mips" in arch_target.lower()
    if is_mips:
        try:
            mips16_features = (features + ",+mips16").strip(",")
            mips16_nyxstone_instance = Nyxstone(
                target_triple=arch_target,
                cpu=cpu,
                features=mips16_features,
                immediate_style=immediate_style,
            )
        except ValueError as e:
            LOG.warning(
                f"Failed to initialize MIPS16 disassembler, fallback will be unavailable: {e}"
            )
        try:
            micromips_features = (features + ",+micromips").strip(",")
            micromips_nyxstone_instance = Nyxstone(
                target_triple=arch_target,
                cpu=cpu,
                features=micromips_features,
                immediate_style=immediate_style,
            )
        except ValueError as e:
            LOG.warning(f"Failed to initialize microMIPS disassembler: {e}")
    addr_to_name_map = _build_addr_to_name_map(metadata, parsed_obj)
    all_func_addrs = []
    for func_list_key in FUNCTION_SYMBOLS:
        for func_entry in metadata.get(func_list_key, []):
            addr_str = func_entry.get("address") or func_entry.get("rva_start")
            if addr_str:
                try:
                    all_func_addrs.append(int(addr_str, 16))
                except ValueError:
                    pass
    all_func_addrs_sorted = sorted(list(set(all_func_addrs)))
    addr_to_index = {addr: i for i, addr in enumerate(all_func_addrs_sorted)}
    base_delta = 0
    if isinstance(parsed_obj, lief.ELF.Binary):
        code_segment = None
        for seg in parsed_obj.segments:
            if seg.type == lief.ELF.Segment.TYPE.LOAD and seg.has(
                lief.ELF.Segment.FLAGS.X
            ):
                code_segment = seg
                break
        if code_segment and all_func_addrs_sorted:
            min_func_addr = all_func_addrs_sorted[0]
            if code_segment.virtual_address != min_func_addr:
                base_delta = code_segment.virtual_address - min_func_addr
                LOG.debug(
                    f"Detected address delta. LIEF VA: {hex(code_segment.virtual_address)}, Symbol VA: {hex(min_func_addr)}. Applying delta: {hex(base_delta)}"
                )
    inst_count = 0
    num_failures = 0
    num_success = 0
    all_funcs = []
    for func_list_key in FUNCTION_SYMBOLS:
        if _should_skip_symbol_list_for_disassembly(parsed_obj, func_list_key):
            continue
        all_funcs.extend(metadata.get(func_list_key, []))
    visited_addrs = set()
    # Merely invoking this method leads to more successful disassembly!
    memoryview(parsed_obj.write_to_bytes())
    for func_entry in all_funcs:
        func_addr_str = func_entry.get("address") or func_entry.get("rva_start")
        if not func_addr_str:
            continue
        func_name = func_entry.get("name")
        try:
            original_func_addr = int(func_addr_str, 16)
        except ValueError:
            LOG.debug(
                f"Could not parse address '{func_addr_str}' for function '{func_name}'. Skipping."
            )
            continue
        if original_func_addr in visited_addrs:
            continue
        visited_addrs.add(original_func_addr)
        if not func_name:
            func_name = f"sub_{original_func_addr:x}"
        if isinstance(parsed_obj, lief.MachO.Binary) and _is_macos_system_symbol_name(
            func_name
        ):
            continue
        func_addr = original_func_addr
        if (is_mips or "arm" in arch_target.lower()) and (func_addr & 1):
            func_addr = func_addr & ~1
        size_to_disasm = func_entry.get("size") or func_entry.get("length")
        has_exact_size = True
        if not isinstance(size_to_disasm, int) or size_to_disasm <= 0:
            current_index = addr_to_index.get(func_addr)
            if current_index is not None and current_index + 1 < len(
                all_func_addrs_sorted
            ):
                next_func_addr = all_func_addrs_sorted[current_index + 1]
                size_to_disasm = next_func_addr - func_addr
            else:
                size_to_disasm = 4096
                has_exact_size = False
        if size_to_disasm <= 0:
            LOG.debug(f"Function '{func_name}' has a size of 0. Skipping.")
            continue
        func_addr_va = func_addr
        if isinstance(parsed_obj, lief.PE.Binary):
            func_addr_va = func_addr + parsed_obj.optional_header.imagebase
        elif isinstance(parsed_obj, lief.MachO.Binary) and hasattr(
            parsed_obj, "imagebase"
        ):
            func_addr_va = func_addr + parsed_obj.imagebase
        lief_lookup_va = func_addr + base_delta
        func_addr_va_hex = hex(func_addr_va)
        is_executable = True
        if isinstance(parsed_obj, lief.PE.Binary) and hasattr(parsed_obj, "sections"):
            is_executable = False
            for sec in parsed_obj.sections:
                sec_start = sec.virtual_address
                sec_size = getattr(sec, "virtual_size", sec.size)
                if sec_size == 0:
                    sec_size = sec.size
                if sec_start <= func_addr < (sec_start + sec_size):
                    if sec.has_characteristic(
                        lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE
                    ):
                        is_executable = True
                    break
        if not is_executable:
            LOG.debug(
                f"Address {func_addr_va_hex} for '{func_name}' is not in an executable section. Skipping disassembly."
            )
            continue
        rebased_bytes_mv = None
        try:
            result = parsed_obj.get_content_from_virtual_address(
                lief_lookup_va, size_to_disasm
            )
            if not isinstance(result, lief.lief_errors):
                rebased_bytes_mv = result
        except (SystemError, Exception):
            pass
        original_bytes_mv = None
        try:
            result = parsed_obj.get_content_from_virtual_address(
                func_addr_va, size_to_disasm
            )
            if not isinstance(result, lief.lief_errors):
                original_bytes_mv = result
        except (SystemError, Exception):
            pass
        if rebased_bytes_mv is None and original_bytes_mv is None:
            LOG.debug(
                f"Could not get bytes for function '{func_name}' at {func_addr_str} using any method."
            )
            continue
        rebased_bytes_list = (
            rebased_bytes_mv.toreadonly() if rebased_bytes_mv is not None else []
        )
        original_bytes_list = (
            original_bytes_mv.toreadonly() if original_bytes_mv is not None else []
        )
        try:
            instr_list = None
            disassemblers_to_try = [(nyxstone_instance, arch_target)]
            if mips16_nyxstone_instance:
                disassemblers_to_try.append((mips16_nyxstone_instance, "MIPS16"))
            if micromips_nyxstone_instance:
                disassemblers_to_try.append((micromips_nyxstone_instance, "MicroMIPS"))
            for offset in range(4):
                if offset >= _mem_bytes_len(
                    original_bytes_list
                ) and offset >= _mem_bytes_len(rebased_bytes_list):
                    break
                addr_to_try = func_addr_va + offset
                for instance, mode_name in disassemblers_to_try:
                    bytes_sets = [
                        (rebased_bytes_list, "rebased"),
                        (original_bytes_list, "original"),
                    ]
                    for byte_source, source_name in bytes_sets:
                        if offset >= _mem_bytes_len(byte_source):
                            continue
                        bytes_to_try = byte_source[offset:]
                        instr_list = _try_disassemble(
                            instance, bytes_to_try, addr_to_try
                        )
                        if not instr_list:
                            instr_list = _try_disassemble(
                                instance, bytes_to_try, addr_to_try, 12
                            )
                        if not instr_list:
                            instr_list = _try_disassemble(
                                instance, bytes_to_try, addr_to_try, 2
                            )
                        if instr_list:
                            LOG.debug(
                                f"Disassembled '{func_name}' in {mode_name} mode at offset +{offset} using {source_name} bytes."
                            )
                            break
                    if instr_list:
                        break
                if instr_list:
                    break
            if not instr_list:
                LOG.debug(
                    f"Could not find valid instructions for function '{func_name}' {func_addr_va} {inst_count}."
                )
                continue
            plain_assembly_text = "\n".join(i.assembly for i in instr_list)
            end_index = _find_function_end_index(instr_list, has_exact_size)
            truncated_instr_list = (
                instr_list[: end_index + 1] if end_index != -1 else instr_list
            )
            if not truncated_instr_list:
                LOG.debug(
                    f"Instruction list for '{func_name}' became empty after truncation. Skipping."
                )
                continue
            lower_assembly = plain_assembly_text.lower()
            assembly_hash = hashlib.sha256(
                plain_assembly_text.encode("utf-8")
            ).hexdigest()
            instruction_count = len(truncated_instr_list)
            instr_addresses = [instr.address for instr in truncated_instr_list]
            next_func_boundary = func_addr_va + size_to_disasm
            (
                instruction_metrics,
                instruction_mnemonics,
                has_indirect_call,
                has_loop,
                regs_read,
                regs_written,
                instructions_with_registers,
                used_simd_reg_types,
                proprietary_instructions,
                sreg_interactions,
                has_pac,
            ) = _analyze_instructions(
                truncated_instr_list,
                func_addr_va,
                next_func_boundary,
                instr_addresses,
                parsed_obj,
                arch_target,
            )
            direct_calls, direct_call_targets = _resolve_direct_calls(
                truncated_instr_list, addr_to_name_map, arch_target
            )
            joined_mnemonics = "\n".join(instruction_mnemonics)
            instruction_hash = hashlib.sha256(
                joined_mnemonics.encode("utf-8")
            ).hexdigest()
            has_system_call = any(
                syscall_pattern in lower_assembly
                for syscall_pattern in SYSCALL_INDICATORS
            )
            has_security_feature = any(
                feature_pattern in lower_assembly
                for feature_pattern in SECURITY_INDICATORS
            )
            has_crypto_call = any(
                f"{indicator} " in lower_assembly
                for indicator in CRYPTO_INDICATORS
                if len(indicator) > 3
            )
            has_gpu_call = any(
                f"{indicator} " in lower_assembly
                for indicator in GPU_INDICATORS
                if len(indicator) > 3
            )
            function_type = _classify_function(
                instruction_metrics,
                instruction_count,
                plain_assembly_text,
                has_system_call,
                has_indirect_call,
            )
            disassembly_results[f"{func_addr_va_hex}::{func_name}"] = {
                "name": func_name,
                "address": func_addr_va_hex,
                "rvaOrAddress": func_addr_str,
                "assembly": plain_assembly_text,
                "assembly_hash": assembly_hash,
                "instruction_hash": instruction_hash,
                "instruction_count": instruction_count,
                "instruction_metrics": instruction_metrics,
                "direct_calls": direct_calls,
                "direct_call_targets": direct_call_targets,
                "has_indirect_call": has_indirect_call,
                "has_pac": has_pac,
                "has_system_call": has_system_call,
                "has_security_feature": has_security_feature,
                "has_crypto_call": has_crypto_call,
                "has_gpu_call": has_gpu_call,
                "has_loop": has_loop,
                "regs_read": regs_read,
                "regs_written": regs_written,
                "used_simd_reg_types": used_simd_reg_types,
                "instructions_with_registers": instructions_with_registers,
                "function_type": function_type,
                "proprietary_instructions": proprietary_instructions,
                "sreg_interactions": sreg_interactions,
            }
            if inst_count == 0:
                num_success += 1
            if num_failures < 10 or num_success > 10:
                inst_count = 0
        except ValueError as e:
            LOG.debug(
                f"Failed to disassemble function '{func_name}' at {func_addr_va_hex}: {e}"
            )
    if not disassembly_results:
        LOG.debug("Disassembly was not successful.")
    return disassembly_results
