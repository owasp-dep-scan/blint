import bisect
import contextlib
import hashlib
import re
import struct
from collections import deque
from functools import cache, lru_cache
from typing import NamedTuple

import lief

from blint.config import (
    APPLE_PROPRIETARY_INSTRUCTION_RANGES,
    APPLE_PROPRIETARY_SREGS,
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
    SORTED_ALL_REGS_MIPS,
)
from blint.lib.cfg import build_function_cfg
from blint.lib.funcdisc.complete import (
    MAX_PROMOTED_FUNCTIONS,
    PROLOGUE_SCAN_MIN_FUNCTIONS,
    executable_ranges,
    find_prologue_candidates,
    promotable_call_target,
)
from blint.lib.indicators import (
    CRYPTO_INDICATORS,
    GPU_INDICATORS,
    SECURITY_INDICATORS,
    SYSCALL_INDICATORS,
)
from blint.lib.utils import demangle_symbolic_name
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
    return bool(
        isinstance(parsed_obj, lief.MachO.Binary)
        and func_list_key in ("imports", "symtab_symbols", "dynamic_symbols")
    )


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
    ARM64_GENERAL_REGS_64 | ARM64_GENERAL_REGS_32 | ARM64_SPECIAL_REGS | ARM64_VFP_NEON_REGS
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
# 32-bit ARM mnemonic tables. nyxstone prints branch/call immediates as
# PC-relative signed deltas ("bl #50", "b #-12"); the target is
# addr + 4 + imm in Thumb state and addr + 8 + imm in ARM state (measured
# against the NDK r28c llvm-objdump oracle over the A4a fixtures; see
# docs/DISASSEMBLE.md). The .w suffixed spellings are Thumb wide encodings.
ARM32_CALL_INST = {"bl", "bl.w", "blx", "blx.w"}
ARM32_UNCONDITIONAL_JMP_INST = {"b", "b.w"}
ARM32_COND_SUFFIXES = (
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
    "gt",
    "le",
)
ARM32_CONDITIONAL_JMP_INST = {f"b{s}" for s in ARM32_COND_SUFFIXES} | {
    f"b{s}.w" for s in ARM32_COND_SUFFIXES
}
# Jump-table dispatch reads its destination from memory: tbb/tbh index a
# PC-relative byte/halfword table, and `ldr pc, [pc, rN, lsl #2]` indexes a
# word table. These are intra-function control flow, never calls.
ARM32_TABLE_DISPATCH_INST = {"tbb", "tbh"}
ARM32_BX_RE = re.compile(r"^bx(" + "|".join(ARM32_COND_SUFFIXES) + r")?$")
ARM32_GPR_TOKEN_RE = re.compile(r"^(r\d\d?|sp|lr|pc|ip|fp|sl)$")
TERMINATING_INST = X86_RET_INST | ARM64_RET_INST | MIPS_RET_INST
UNCONDITIONAL_JMP_INST_ALL = (
    X86_UNCONDITIONAL_JMP_INST | ARM64_UNCONDITIONAL_JMP_INST | MIPS_UNCONDITIONAL_JMP_INST
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
ARCH_REG_SET_ARM64 = frozenset(ARM64_ALL_REGS)
ARCH_REG_SET_MIPS = frozenset(SORTED_ALL_REGS_MIPS)
ARCH_REG_SET_X86 = frozenset(ALL_REGS_X86)

WIN_X64_VOLATILE_REGS = frozenset({"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"})
SYSV_X64_VOLATILE_REGS = frozenset({"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"})
CDECL_X86_VOLATILE_REGS = frozenset({"eax", "ecx", "edx"})
X64_RETURN_REGS = frozenset({"rax"})
X86_RETURN_REGS = frozenset({"eax"})

_SREG_TO_CATEGORY_MAP = {
    sreg.lower(): category for category, sregs in APPLE_PROPRIETARY_SREGS.items() for sreg in sregs
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


@cache
def _normalize_arch_target(arch_target: str) -> str:
    return (arch_target or "").lower()


# LLVM decodes an extension's instructions only when the feature is on, and
# nyxstone starts from the generic CPU, so every extension a shipped binary
# uses has to be named. Disassembly of an existing binary never needs to
# withhold an instruction - llvm-objdump enables all AArch64 extensions for
# the same reason - so each list is every extension LLVM 18 decodes for that
# architecture, minus the ones whose encodings collide with another
# extension's. Measured on shipped binaries (macOS 27 arm64e/arm64e.x1,
# Android system and app libraries, the wasm-tools fixtures): without these,
# LSE atomics, AES/SHA/CRC, SVE/SME, MTE, CSSC, CPA and RCPC3 instructions
# failed to decode, and a riscv64 build lost 85% of its functions to
# compressed instructions alone.
AARCH64_DISASSEMBLY_FEATURES = (
    "+v9.5a,+pauth,+pauth-lr,+lse,+rcpc,+rcpc-immo,+rcpc3,+crc,+aes,+sha2,+sha3,+sm4,"
    "+fullfp16,+fp16fml,+dotprod,+bf16,+i8mm,+rdm,+jsconv,+complxnum,+sve,+sve2,"
    "+sve2-bitperm,+sve2-aes,+sve2-sha3,+sve2-sm4,+sve2p1,+sme,+sme2,+sme2p1,+sme-f64f64,"
    "+sme-i16i64,+sme-f16f16,+mte,+mops,+cssc,+cpa,+d128,+the,+lse128,+gcs,+ls64,+hbc,"
    "+rand,+tme,+spe,+fp8,+faminmax,+lut"
)
# Zcmp/Zcmt reuse the compressed double-precision load/store encodings and
# XTheadVector the V encodings, so they stay off: with D and V on, those
# words mean c.fld/c.fsd and RVV.
RISCV_DISASSEMBLY_FEATURES = (
    "+m,+a,+f,+d,+c,+zicsr,+zifencei,+v,+zba,+zbb,+zbc,+zbs,+zfh,+zfa,+zcb,+zicond,"
    "+zihintpause,+zicbom,+zicboz,+zicbop,+zawrs,+zvbb,+zvbc,+zvkn,+zvksh,+zkn,+zks"
)


def _default_disassembly_features(arch_target: str) -> str:
    """The extension set blint enables for decoding this architecture."""
    arch = (arch_target or "").lower().split("-", 1)[0]
    if arch in ("aarch64", "arm64", "arm64e", "aarch64_be"):
        return AARCH64_DISASSEMBLY_FEATURES
    if arch.startswith("riscv"):
        return RISCV_DISASSEMBLY_FEATURES
    return ""


def _merge_features(defaults: str, requested: str) -> str:
    """Caller features win: they are appended, so a '-feat' can turn one off."""
    seen, merged = set(), []
    for feature in [*defaults.split(","), *(requested or "").split(",")]:
        feature = feature.strip()
        if feature and feature not in seen:
            seen.add(feature)
            merged.append(feature)
    return ",".join(merged)


@cache
def _has_supported_nyxstone_target(arch_target: str) -> bool:
    normalized_target = (arch_target or "").strip()
    if not normalized_target:
        return False
    return normalized_target.split("-", 1)[0].lower() not in ("", "unknown")


# Object-format / OS markers that Nyxstone's LLVM backend rejects because it
# only initializes the ELF streamer. Instruction decoding itself is identical
# across object formats, so we remap these triples onto an ELF-compatible OS
# while preserving the architecture (and any endianness/sub-arch suffix).
_NON_ELF_TRIPLE_MARKERS = (
    "apple",
    "macos",
    "macosx",
    "darwin",
    "ios",
    "tvos",
    "watchos",
    "bridgeos",
    "driverkit",
    "windows",
    "msvc",
    "macho",
    "coff",
    "win32",
    "uefi",
)


@cache
def _to_nyxstone_triple(arch_target: str) -> str:
    """Return an ELF-compatible target triple that Nyxstone can initialize.

    Nyxstone only supports the ELF object format, so MachO (``*-apple-*``) and
    PE/COFF (``*-windows-msvc``) triples fail to initialize even though the
    underlying instruction set is fully supported. For those, we substitute an
    ELF triple that keeps the architecture component intact. ELF triples (and
    bare architectures) are returned unchanged.
    """
    normalized = (arch_target or "").strip()
    if not normalized:
        return normalized
    lowered = normalized.lower()
    if not any(marker in lowered for marker in _NON_ELF_TRIPLE_MARKERS):
        return normalized
    arch = normalized.split("-", 1)[0]
    return f"{arch}-unknown-linux-gnu"


def _is_arm32_target(arch_target: str) -> bool:
    """True for 32-bit ARM triples (arm*/thumb*, never aarch64/arm64)."""
    arch = (arch_target or "").lower().split("-", 1)[0]
    return arch.startswith(("arm", "thumb")) and not arch.startswith(("aarch64", "arm64"))


def _arm32_mode_triples(arch_target: str) -> tuple[str, str]:
    """The (arm, thumb) triple pair that decodes a 32-bit ARM binary.

    nyxstone initializes ``arm-unknown-linux-android`` (the tuple blint
    constructs for armeabi-v7a) but then fails to decode core instructions in
    it — ``bx lr`` among them — while the ``armv7``/``thumbv7`` spellings of
    the same environment decode correctly (measured against nyxstone 0.1.8 /
    LLVM 18 and the NDK r28c llvm-objdump oracle; see docs/DISASSEMBLE.md).
    The arch token is therefore upgraded to v7 with the rest of the tuple
    kept intact; big-endian ``armeb``/``thumbeb`` stay on today's single
    instance (no fixture exercises them).
    """
    parts = (arch_target or "").split("-", 1)
    rest = f"-{parts[1]}" if len(parts) > 1 else ""
    return f"armv7{rest}", f"thumbv7{rest}"


# ARM ELF mapping symbols ($a code-ARM, $t code-Thumb, $d data; the assembler
# appends .N suffixes per section). They are STT_NOTYPE, so nothing else in
# blint's symbol pipeline looks at them.
_ARM32_MAPPING_SYMBOL_RE = re.compile(r"^\$[atd](\.\d+)?$")
_ARM32_MAPPING_MODES = {"a": "arm", "t": "thumb", "d": "data"}


def _arm32_mapping_symbol_modes(parsed_obj) -> dict[int, list[tuple[int, str]]]:
    """Per-section sorted ``{shndx: [(address, mode)]}`` from ``$a/$t/$d``.

    Mapping labels are section-local: a ``.text`` label says nothing about
    ``.plt`` bytes, so the table is keyed by section index and mode lookup
    uses only the function's own section. Only ELF symtabs carry these
    symbols, so a stripped binary gets an empty table and mode selection
    falls back to the symbol's Thumb bit.
    """
    modes = {}
    with contextlib.suppress(AttributeError, TypeError, ValueError):
        symbols = parsed_obj.symtab_symbols
        if symbols and not isinstance(symbols, lief.lief_errors):
            for symbol in symbols:
                name = symbol.name or ""
                if _ARM32_MAPPING_SYMBOL_RE.match(name):
                    modes.setdefault(int(symbol.shndx), []).append(
                        (int(symbol.value) & ~1, _ARM32_MAPPING_MODES[name[1]])
                    )
    for section_modes in modes.values():
        section_modes.sort()
    return modes


def _arm32_mode_at(modes: list[tuple[int, str]], address: int) -> str | None:
    """The mapping-symbol mode covering ``address``, or None when absent."""
    index = bisect.bisect_right(modes, (address, "zz")) - 1
    if index >= 0:
        return modes[index][1]
    return None


def _arm32_section_for_address(parsed_obj, address: int) -> int | None:
    """The section index containing ``address`` (mapping labels are scoped).

    LIEF exposes no shndx on sections, but its ``sections`` list follows the
    section-header table, so the enumeration index is the section index the
    symbol table's shndx values refer to.
    """
    with contextlib.suppress(AttributeError, TypeError, ValueError):
        for shndx, section in enumerate(parsed_obj.sections):
            start = int(section.virtual_address)
            size = int(section.size)
            if start and size and start <= address < start + size:
                return shndx
    return None


def _arm32_function_mode(
    original_func_addr: int,
    modes: list[tuple[int, str]],
    has_symbol: bool,
    call_modes: dict[int, str] | None = None,
    pointer_modes: dict[int, str] | None = None,
) -> tuple[str | None, str | None]:
    """Per-function ARM32 instruction set state, or ``(None, None)`` when unknown.

    Mapping symbols are the stronger source (the assembler states the mode
    per range, which survives where a symbol's parity cannot be recorded);
    otherwise the ELF convention that ``st_value & 1`` marks a Thumb function
    decides. A stripped binary has neither for its unwinding-table
    discoveries, so two weaker sources follow (docs/DISASSEMBLE.md): a call
    or tail branch into the function from already-decoded code, and a data
    pointer whose bit 0 is the interworking Thumb bit (``.init_array`` /
    ``.fini_array`` entries and other linker-relocated pointer slots). The
    second return value names the source that decided the mode, for
    ``instruction_mode_source`` on the function record.
    """
    addr = original_func_addr & ~1
    mapped = _arm32_mode_at(modes, addr)
    if mapped is not None:
        return mapped, "mapping_symbol"
    if has_symbol:
        return ("thumb" if original_func_addr & 1 else "arm"), "symbol_parity"
    if call_modes and addr in call_modes:
        return call_modes[addr], "call"
    if pointer_modes and addr in pointer_modes:
        return pointer_modes[addr], "data_pointer"
    return None, None


def _arm32_data_pointer_modes(parsed_obj, candidate_starts: set[int]) -> dict[int, str]:
    """Mode evidence from function pointers in data: ``{addr: mode}``.

    The interworking convention sets bit 0 on a Thumb function pointer and
    leaves it clear on an ARM one, so every word the linker treats as a
    function address states its target's mode. Read from the two array
    sections the loader walks (``.init_array``/``.fini_array``) and from
    every ``R_ARM_RELATIVE`` slot (whose stored word is the pre-link
    pointer). Only words naming a known function start contribute; a
    coincidental data value cannot invent evidence for an address that is
    not a function. Packed relocations LIEF cannot decode are simply absent
    from the walk — evidence is missed, never guessed.
    """
    pointer_modes: dict[int, str] = {}
    if not candidate_starts or not isinstance(parsed_obj, lief.ELF.Binary):
        return pointer_modes

    def _record_word(word: int) -> None:
        target = word & ~1
        if word and target in candidate_starts and target not in pointer_modes:
            pointer_modes[target] = "thumb" if word & 1 else "arm"

    for section in parsed_obj.sections:
        try:
            section_type = section.type
        except (AttributeError, TypeError):
            continue
        if section_type not in (
            lief.ELF.Section.TYPE.INIT_ARRAY,
            lief.ELF.Section.TYPE.FINI_ARRAY,
        ):
            continue
        try:
            content = bytes(section.content)
        except (AttributeError, TypeError, ValueError):
            continue
        for offset in range(0, len(content) - 3, 4):
            _record_word(struct.unpack_from("<I", content, offset)[0])
    for relocation in parsed_obj.relocations:
        try:
            if relocation.type != lief.ELF.Relocation.TYPE.ARM_RELATIVE:
                continue
            word = _read_u32_at(parsed_obj, int(relocation.address))
        except (AttributeError, TypeError, ValueError):
            continue
        if word is not None:
            _record_word(word)
    return pointer_modes


def _read_u32_at(parsed_obj, address: int) -> int | None:
    """The 4-byte little-endian word at ``address``, or None."""
    try:
        content = parsed_obj.get_content_from_virtual_address(address, 4)
        if content and not isinstance(content, lief.lief_errors):
            return struct.unpack("<I", bytes(content))[0]
    except (SystemError, Exception):
        pass
    return None


def _is_arm32_return(mnemonic: str, operand_text: str) -> bool:
    """True for the ARM32 return forms: ``bx lr`` (with any condition code),
    ``pop {…, pc}`` and the post-indexed stack-slot form ``ldr pc, [sp], #4``.

    A ``bx`` to any register other than ``lr`` is a tail branch, not a
    return; ``ldr pc, [pc, …]`` forms are table dispatches, handled
    separately.
    """
    if ARM32_BX_RE.match(mnemonic):
        return operand_text.split(",")[0].strip().lower() == "lr"
    if mnemonic in ("pop", "pop.w", "ldm", "ldmia", "ldmfd"):
        return "pc" in (operand_text or "")
    if mnemonic in ("ldr", "ldr.w"):
        compact = (operand_text or "").replace(" ", "")
        return compact.startswith("pc,[sp")
    return False


def _is_arm32_table_dispatch(mnemonic: str, operand_text: str) -> bool:
    """True for intra-function jump-table dispatch: ``tbb``/``tbh`` and the
    word-table form ``ldr pc, [pc, rN, lsl #2]``."""
    if mnemonic in ARM32_TABLE_DISPATCH_INST:
        return True
    if mnemonic in ("ldr", "ldr.w"):
        compact = (operand_text or "").replace(" ", "")
        return compact.startswith("pc,[pc")
    return False


def _arm32_parse_immediate(token: str) -> int | None:
    """Parse one ARM32 immediate token in every IntegerBase style nyxstone
    can print: ``#50`` (Dec), ``#0x32`` (HexPrefix), ``#32h`` (HexSuffix)."""
    token = (token or "").strip().lstrip("#")
    if not token:
        return None
    negative = token.startswith("-")
    if negative:
        token = token[1:]
    lowered = token.lower()
    value = None
    with contextlib.suppress(ValueError):
        if lowered.startswith("0x"):
            value = int(lowered, 16)
        elif lowered.endswith("h"):
            value = int(lowered[:-1], 16)
        elif lowered.isdigit():
            value = int(lowered, 10)
    return -value if (value is not None and negative) else value


def _arm32_pc_base(address: int, mode: str | None, mnemonic: str = "") -> int:
    """The PC value a PC-relative ARM32 operand is relative to.

    Thumb state: ``addr+4``, except ``blx #imm`` whose immediate is relative
    to ``Align(addr+4, 4)`` — the interworking form always targets a 4-byte
    aligned ARM address and the architecture rounds the base (measured:
    ``blx #88`` at 0x13da targets 0x13dc+88 = 0x1434, not 0x13de+88).
    ARM state: ``addr+8``.
    """
    if mode == "arm":
        return address + 8
    base = address + 4
    if mnemonic in ("blx", "blx.w"):
        base &= ~3
    return base


def _arm32_branch_target(instr, operand: str, mode: str | None, mnemonic: str = "") -> int | None:
    """Resolve ``bl``/``blx``/``b #imm`` to the absolute target address."""
    imm = _arm32_parse_immediate(operand)
    if imm is None:
        return None
    return _arm32_pc_base(instr.address, mode, mnemonic) + imm


def _arm32_literal_address(instr, operand: str, mode: str | None) -> int | None:
    """Resolve ``ldr rN, [pc, #imm]`` to the address the literal word lives at.

    Thumb's PC is Align(addr+4, 4); ARM's is addr+8 (instructions are
    4-aligned so no rounding is needed there).
    """
    match = re.match(r"^\[pc\s*,\s*(#[^\]]+)\]$", (operand or "").strip())
    if not match:
        return None
    offset = _arm32_parse_immediate(match.group(1))
    if offset is None:
        return None
    base = _arm32_pc_base(instr.address, mode)
    if mode != "arm":
        base &= ~3
    return base + offset


def _arm32_record_call_evidence(
    truncated_instr_list: list,
    parsed_instrs: list,
    line_modes: list,
    default_mode: str | None,
    call_modes: dict[int, str],
) -> None:
    """Feed ``call_modes`` with target modes stated by already-decoded code.

    ``bl`` never changes instruction set state, so its target shares the
    caller's mode; ``blx #imm`` exists to switch state, so its target takes
    the opposite. Tail ``b`` shares the caller's mode like ``bl`` (a state
    change needs ``bx``/``blx``). The per-line mode comes from the decode
    itself, so evidence recorded here is only as good as the caller's own
    mode decision — mapping symbols and symbol parity recorded theirs
    exactly; an arbiter decision propagates with its uncertainty.
    """
    for index, instr in enumerate(truncated_instr_list):
        parsed = parsed_instrs[index] if index < len(parsed_instrs) else None
        if not parsed:
            continue
        mnemonic = parsed.mnemonic
        is_blx = mnemonic in ("blx", "blx.w")
        if not is_blx and mnemonic not in ARM32_CALL_INST | ARM32_UNCONDITIONAL_JMP_INST:
            continue
        operand = parsed.operands_lower[0] if parsed.operands_lower else ""
        if not operand.startswith("#"):
            # Register forms (``blx rN``) have no static target.
            continue
        mode = line_modes[index] if index < len(line_modes) else default_mode
        if mode is None:
            continue
        target = _arm32_branch_target(instr, operand, mode, mnemonic)
        if target is None:
            continue
        target &= ~1
        if target not in call_modes:
            call_modes[target] = ("arm" if mode == "thumb" else "thumb") if is_blx else mode


class ParsedInstruction(NamedTuple):
    mnemonic: str
    operand_text: str
    operand_text_lower: str
    operands: tuple[str, ...]
    operands_lower: tuple[str, ...]


def _split_instruction_operands(operand_text: str) -> tuple[str, ...]:
    if not operand_text:
        return ()
    operands = []
    current = []
    square_depth = 0
    paren_depth = 0
    angle_depth = 0
    for ch in operand_text:
        if ch == "[":
            square_depth += 1
        elif ch == "]" and square_depth:
            square_depth -= 1
        elif ch == "(":
            paren_depth += 1
        elif ch == ")" and paren_depth:
            paren_depth -= 1
        elif ch == "<":
            angle_depth += 1
        elif ch == ">" and angle_depth:
            angle_depth -= 1
        elif ch == "," and not (square_depth or paren_depth or angle_depth):
            operand = "".join(current).strip().rstrip(",")
            if operand:
                operands.append(operand)
            current = []
            continue
        current.append(ch)
    operand = "".join(current).strip().rstrip(",")
    if operand:
        operands.append(operand)
    return tuple(operands)


@lru_cache(maxsize=32768)
def _parse_instruction_text(instr_assembly: str) -> ParsedInstruction:
    assembly = (instr_assembly or "").strip()
    if not assembly:
        return ParsedInstruction("", "", "", (), ())
    parts = assembly.split(None, 1)
    mnemonic = parts[0].lower().rstrip(":")
    operand_text = parts[1].strip() if len(parts) > 1 else ""
    operands = _split_instruction_operands(operand_text)
    return ParsedInstruction(
        mnemonic,
        operand_text,
        operand_text.lower(),
        operands,
        tuple(op.lower() for op in operands),
    )


def _extract_bracket_contents(operand: str) -> tuple[str, int]:
    operand = operand or ""
    start = operand.find("[")
    if start == -1:
        return "", -1
    depth = 0
    inner_start = -1
    for idx, ch in enumerate(operand[start:], start=start):
        if ch == "[":
            depth += 1
            if depth == 1:
                inner_start = idx + 1
        elif ch == "]" and depth:
            depth -= 1
            if depth == 0 and inner_start != -1:
                return operand[inner_start:idx], idx
    return "", -1


def _raw_operand_text(operand: str) -> str:
    return (operand or "").split("<", 1)[0].strip()


def _hex_list(candidate_addrs: list[int]) -> list[str]:
    return [hex(addr) for addr in candidate_addrs]


def _lookup_target_name(candidate_addrs: list[int], addr_to_name_map: dict) -> str:
    for candidate_addr in candidate_addrs:
        target_name = (
            addr_to_name_map.get(candidate_addr) or addr_to_name_map.get(candidate_addr & ~1) or ""
        )
        if target_name:
            return target_name
    return ""


def _find_immediate_token(text: str) -> str:
    token_chars = []
    for ch in text or "":
        if ch.isalnum() or ch in "#+-%":
            token_chars.append(ch)
            continue
        if token_chars:
            token = "".join(token_chars)
            token_chars = []
            if _parse_immediate_token(token) is not None:
                return token
    if token_chars:
        token = "".join(token_chars)
        if _parse_immediate_token(token) is not None:
            return token
    return ""


def _build_reg_target(
    *,
    target_name: str = "",
    target_addrs: list[int] | None = None,
    inferred_addrs: list[int] | None = None,
    raw_operand: str = "",
    chain_hops: int = 0,
) -> dict:
    target_addrs = target_addrs or []
    inferred_addrs = inferred_addrs or []
    return {
        "target_name": target_name,
        "target_address": hex(target_addrs[0]) if target_addrs else "",
        "target_address_candidates": _hex_list(target_addrs),
        "_target_address_candidates_int": list(target_addrs),
        "inferred_address_candidates": _hex_list(inferred_addrs),
        "_inferred_address_candidates_int": list(inferred_addrs),
        "raw_operand": raw_operand,
        "chain_hops": chain_hops,
    }


def _append_call_target(
    direct_call_targets: list[dict],
    *,
    kind: str,
    target_name: str = "",
    target_addr: int | None = None,
    target_addrs: list[int] | None = None,
    raw_operand: str = "",
):
    target_addrs = target_addrs or []
    direct_call_targets.append(
        {
            "target_name": target_name,
            "target_address": hex(target_addr) if target_addr is not None else "",
            "target_address_candidates": _hex_list(target_addrs),
            "raw_operand": raw_operand,
            "kind": kind,
        }
    )


@cache
def get_arch_reg_set(arch_target: str) -> frozenset[str]:
    """Returns the appropriate set of registers based on the architecture."""
    lower_arch = _normalize_arch_target(arch_target)
    if "aarch64" in lower_arch or "arm64" in lower_arch:
        return ARCH_REG_SET_ARM64
    if "mips" in lower_arch:
        return ARCH_REG_SET_MIPS
    return ARCH_REG_SET_X86


@cache
def _get_implicit_regs_map(arch_target: str) -> dict[str, dict[str, set[str]]]:
    """Selects the appropriate implicit registers map based on architecture."""
    lower_arch = _normalize_arch_target(arch_target)
    if "64" in lower_arch and "aarch64" not in lower_arch:
        return IMPLICIT_REGS_X64
    if "aarch64" in lower_arch or "arm64" in lower_arch:
        return IMPLICIT_REGS_ARM64
    if "mips" in lower_arch:
        return IMPLICIT_REGS_MIPS
    return IMPLICIT_REGS_X86


def _addr_in_exec_ranges(addr: int, exec_ranges: list) -> bool:
    """Return True when addr falls inside one of the executable ranges."""
    return any(start <= addr < end for start, end in exec_ranges)


def _find_function_end_index(
    instr_list: list, has_exact_size: bool = False, arch_target: str = ""
) -> int:
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

    is_arm32 = _is_arm32_target(arch_target)

    def _parts(index: int) -> tuple[str, str]:
        pieces = instr_list[index].assembly.split(None, 1)
        return pieces[0].lower(), pieces[1] if len(pieces) > 1 else ""

    def _terminates(index: int) -> bool:
        mnemonic, operand = _parts(index)
        if mnemonic in TERMINATING_INST or mnemonic in UNCONDITIONAL_JMP_INST_ALL:
            return True
        if is_arm32:
            # ARM32 returns (`bx lr`, `pop {…, pc}`, `ldr pc, [sp], #4`) are
            # not in the shared terminating set; without them a size-less
            # window keeps the next function's leading bytes as trailing
            # junk on real libraries.
            return _is_arm32_return(mnemonic, operand)
        return False

    # Fallback heuristic: the size was a blind guess (e.g., 4096 bytes),
    for i, instr in enumerate(instr_list):
        if _terminates(i):
            if i + 1 >= len(instr_list):
                return i
            next_mnemonic = instr_list[i + 1].assembly.split(None, 1)[0].lower()
            if next_mnemonic in PADDING_TRAP_MNEMONICS:
                return i

    return len(instr_list) - 1


def _get_abi_volatile_regs(parsed_obj, arch_target: str) -> frozenset[str]:
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


def extract_regs_from_operand(
    op: str, sorted_arch_regs: frozenset[str] = ARCH_REG_SET_X86
) -> set[str]:
    if not op:
        return set()
    return {
        token
        for token in OPERAND_DELIMITERS_PATTERN.split(op.lower())
        if token and token in sorted_arch_regs
    }


def _extract_register_usage(
    instr_assembly: str,
    parsed_obj=None,
    arch_target: str = "",
    sorted_arch_regs: frozenset[str] | None = None,
    parsed_instr=None,
) -> tuple[list[str], list[str]]:
    """
    Performs a first-pass analysis to extract approximate register read/write usage
    from the instruction assembly string.
    """
    lower_arch = _normalize_arch_target(arch_target)
    implicit_regs_map = _get_implicit_regs_map(lower_arch)
    regs_read: set[str] = set()
    regs_written: set[str] = set()
    if parsed_instr is None:
        parsed_instr = _parse_instruction_text(instr_assembly)
    if not parsed_instr.mnemonic:
        return sorted(regs_read), sorted(regs_written)
    is_aarch64 = "aarch64" in lower_arch or "arm64" in lower_arch
    is_mips = "mips" in lower_arch
    if not sorted_arch_regs:
        sorted_arch_regs = get_arch_reg_set(lower_arch)
    mnemonic = parsed_instr.mnemonic
    operands = parsed_instr.operands_lower
    num_operands = len(operands)
    has_rep_prefix = False
    if mnemonic.startswith(("rep", "repe", "repne")):
        has_rep_prefix = True
        mnemonic = mnemonic[4:] if len(mnemonic) > 3 and mnemonic[3] == "e" else mnemonic[3:]
    if mnemonic in implicit_regs_map:
        regs_read.update(implicit_regs_map[mnemonic].get("read", set()))
        regs_written.update(implicit_regs_map[mnemonic].get("write", set()))
    if has_rep_prefix:
        is_64bit = "64" in lower_arch
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
                dst_regs = extract_regs_from_operand(operands[0], sorted_arch_regs)
                src1_regs = extract_regs_from_operand(operands[1], sorted_arch_regs)
                regs_written.update(dst_regs)
                regs_read.update(src1_regs)
                if num_operands >= 3:
                    src2_regs = extract_regs_from_operand(operands[2], sorted_arch_regs)
                    regs_read.update(src2_regs)
        elif mnemonic in ("mov", "movz", "movk", "movn", "fmov", "fmov immediate"):
            if num_operands >= 1:
                dst_regs = extract_regs_from_operand(operands[0], sorted_arch_regs)
                regs_written.update(dst_regs)
                if num_operands >= 2 and not operands[1].startswith("#"):
                    src_regs = extract_regs_from_operand(operands[1], sorted_arch_regs)
                    regs_read.update(src_regs)
        elif mnemonic in ("csel", "csinc", "csinv", "cset", "csetm", "cinc", "cinv"):
            if num_operands >= 3:
                dst_regs = extract_regs_from_operand(operands[0], sorted_arch_regs)
                src1_regs = extract_regs_from_operand(operands[1], sorted_arch_regs)
                src2_regs = extract_regs_from_operand(operands[2], sorted_arch_regs)
                regs_written.update(dst_regs)
                regs_read.update(src1_regs)
                regs_read.update(src2_regs)
                if mnemonic in ("cinc", "cinv"):
                    regs_read.update(dst_regs)
        elif mnemonic in ("cmp", "cmn", "tst"):
            if num_operands >= 2:
                src1_regs = extract_regs_from_operand(operands[0], sorted_arch_regs)
                src2_regs = extract_regs_from_operand(operands[1], sorted_arch_regs)
                regs_read.update(src1_regs)
                regs_read.update(src2_regs)
        elif mnemonic.startswith(("ldr", "str")):
            if num_operands >= 2:
                data_reg = extract_regs_from_operand(operands[0], sorted_arch_regs)
                addr_parts = extract_regs_from_operand(operands[1], sorted_arch_regs)
                if "str" in mnemonic:
                    regs_read.update(data_reg)
                    regs_read.update(addr_parts)
                else:  # ldr
                    regs_written.update(data_reg)
                    regs_read.update(addr_parts)
        elif mnemonic.startswith(("ldp", "stp")):
            if num_operands >= 3:
                data_reg1 = extract_regs_from_operand(operands[0], sorted_arch_regs)
                data_reg2 = extract_regs_from_operand(operands[1], sorted_arch_regs)
                mem_operand = ",".join(operands[2:]).strip()
                addr_parts = extract_regs_from_operand(mem_operand, sorted_arch_regs)
                if "!" in mem_operand:
                    base_reg = next(iter(addr_parts), None)
                    if base_reg:
                        regs_written.add(base_reg)
                if mnemonic.startswith("stp"):
                    regs_read.update(data_reg1)
                    regs_read.update(data_reg2)
                    regs_read.update(addr_parts)
                else:
                    regs_written.update(data_reg1)
                    regs_written.update(data_reg2)
                    regs_read.update(addr_parts)
        elif mnemonic.startswith(("cb", "tb")):
            if num_operands >= 1:
                src_regs = extract_regs_from_operand(operands[0], sorted_arch_regs)
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
                target_op = operands[0]
                if not target_op.startswith("#") and not target_op.isdigit():
                    target_regs = extract_regs_from_operand(target_op, sorted_arch_regs)
                    regs_read.update(target_regs)
        elif mnemonic in ("ret", "eret"):
            pass
        elif (
            mnemonic in ("and", "orr", "eor", "bic", "tst")
            or mnemonic
            in (
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
            )
        ) and num_operands >= 2:
            dst_regs = extract_regs_from_operand(operands[0], sorted_arch_regs)
            src1_regs = extract_regs_from_operand(operands[1], sorted_arch_regs)
            regs_written.update(dst_regs)
            regs_read.update(src1_regs)
            if num_operands >= 3:
                src2_regs = extract_regs_from_operand(operands[2], sorted_arch_regs)
                regs_read.update(src2_regs)
    elif is_mips:
        if mnemonic in MIPS_ARITH_LOGIC_3_OP or mnemonic in MIPS_SHIFT_3_OP:
            if num_operands >= 3:
                regs_written.update(extract_regs_from_operand(operands[0], sorted_arch_regs))
                regs_read.update(extract_regs_from_operand(operands[1], sorted_arch_regs))
                regs_read.update(extract_regs_from_operand(operands[2], sorted_arch_regs))
        elif mnemonic in MIPS_ARITH_LOGIC_2_OP_IMM or mnemonic in MIPS_SHIFT_2_OP_IMM:
            if num_operands >= 2:
                regs_written.update(extract_regs_from_operand(operands[0], sorted_arch_regs))
                regs_read.update(extract_regs_from_operand(operands[1], sorted_arch_regs))
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
                regs_read.update(extract_regs_from_operand(operands[0], sorted_arch_regs))
                regs_read.update(extract_regs_from_operand(operands[1], sorted_arch_regs))
        elif mnemonic in MIPS_MOVE:
            if num_operands >= 2:
                regs_written.update(extract_regs_from_operand(operands[0], sorted_arch_regs))
                regs_read.update(extract_regs_from_operand(operands[1], sorted_arch_regs))
        elif mnemonic in ("mfhi", "mflo"):
            if num_operands >= 1:
                regs_written.update(extract_regs_from_operand(operands[0], sorted_arch_regs))
        elif mnemonic in MIPS_MULT_DIV:
            if num_operands >= 2:
                regs_read.update(extract_regs_from_operand(operands[0], sorted_arch_regs))
                regs_read.update(extract_regs_from_operand(operands[1], sorted_arch_regs))
        elif mnemonic == "jr":
            if num_operands >= 1:
                regs_read.update(extract_regs_from_operand(operands[0], sorted_arch_regs))
        elif mnemonic in ("jalr", "bal") and num_operands >= 1:
            if num_operands == 2:
                regs_written.update(extract_regs_from_operand(operands[0], sorted_arch_regs))
                regs_read.update(extract_regs_from_operand(operands[1], sorted_arch_regs))
            else:
                regs_read.update(extract_regs_from_operand(operands[0], sorted_arch_regs))
    else:
        if mnemonic in WRITE_DST_READ_SRC_INST or mnemonic.startswith("cmov"):
            if num_operands >= 2:
                dst_regs = extract_regs_from_operand(operands[0], sorted_arch_regs)
                src_regs = extract_regs_from_operand(operands[1], sorted_arch_regs)
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
                op1_regs = extract_regs_from_operand(operands[0], sorted_arch_regs)
                op2_regs = extract_regs_from_operand(operands[1], sorted_arch_regs)
                regs_read.update(op1_regs)
                regs_written.update(op1_regs)
                regs_read.update(op2_regs)
                if mnemonic != "cmpxchg":
                    regs_written.update(op2_regs)
        elif mnemonic in BIT_MANIPULATION_INST:
            if num_operands >= 2:
                dst_regs = extract_regs_from_operand(operands[0], sorted_arch_regs)
                src_regs = extract_regs_from_operand(operands[1], sorted_arch_regs)
                regs_written.update(dst_regs)
                regs_read.update(src_regs)
                if mnemonic not in ("bsf", "bsr", "lzcnt", "tzcnt", "popcnt"):
                    regs_read.update(dst_regs)
        elif mnemonic in READ_WRITE_ONE_OP_INST:
            if num_operands >= 1:
                op_regs = extract_regs_from_operand(operands[0], sorted_arch_regs)
                regs_read.update(op_regs)
                regs_written.update(op_regs)
        elif mnemonic in ("cmp", "test"):
            if num_operands >= 2:
                regs_read.update(extract_regs_from_operand(operands[0], sorted_arch_regs))
                regs_read.update(extract_regs_from_operand(operands[1], sorted_arch_regs))
        elif mnemonic in ("push", "pop"):
            is_64bit = "64" in lower_arch
            stack_reg = "rsp" if is_64bit else "esp"
            regs_read.add(stack_reg)
            regs_written.add(stack_reg)
            if num_operands >= 1:
                op_regs = extract_regs_from_operand(operands[0], sorted_arch_regs)
                if mnemonic == "push":
                    regs_read.update(op_regs)
                else:
                    regs_written.update(op_regs)
        elif mnemonic == "call":
            volatile_regs = _get_abi_volatile_regs(parsed_obj, lower_arch)
            regs_written.update(volatile_regs)
            if num_operands >= 1:
                op = operands[0]
                if not op.startswith("0x") and not op.isdigit():
                    op_regs = extract_regs_from_operand(op, sorted_arch_regs)
                    regs_read.update(op_regs)
        elif mnemonic in TERMINATING_INST:
            is_64bit = "64" in lower_arch or "aarch64" in lower_arch
            if is_64bit:
                regs_read.update(X64_RETURN_REGS)
            else:
                regs_read.update(X86_RETURN_REGS)
            stack_reg = "rsp" if is_64bit else "esp"
            regs_read.add(stack_reg)
            regs_written.add(stack_reg)
        elif mnemonic.startswith("j"):
            if num_operands >= 1:
                op = operands[0]
                if not op.startswith("0x") and not op.isdigit():
                    op_regs = extract_regs_from_operand(op, sorted_arch_regs)
                    regs_read.update(op_regs)
        elif mnemonic == "xchg" and num_operands >= 2:
            op1_regs = extract_regs_from_operand(operands[0], sorted_arch_regs)
            op2_regs = extract_regs_from_operand(operands[1], sorted_arch_regs)
            regs_read.update(op1_regs)
            regs_written.update(op1_regs)
            regs_read.update(op2_regs)
            regs_written.update(op2_regs)
        if mnemonic in ("mul", "imul", "div", "idiv") and num_operands == 1:
            op_regs = extract_regs_from_operand(operands[0], sorted_arch_regs)
            regs_read.update(op_regs)

    return sorted(regs_read), sorted(regs_written)


def _analyze_instructions(
    instr_list: list,
    func_addr: int,
    next_func_addr_in_sec: int,
    instr_addresses: list,
    parsed_obj=None,
    arch_target: str = "",
    parsed_instrs: list | None = None,
    arm32_context: dict | None = None,
) -> tuple[
    dict,
    list[str],
    bool,
    bool,
    list[str],
    list[str],
    list,
    list[str],
    list[str],
    list[str],
    bool,
]:
    """Analyzes the list of instructions for metrics, loops, and indirect calls."""
    lower_arch = _normalize_arch_target(arch_target)
    is_aarch64 = "aarch64" in lower_arch or "arm64" in lower_arch
    is_mips = "mips" in lower_arch
    is_arm32 = _is_arm32_target(lower_arch)
    if is_aarch64:
        CALL_INST = ARM64_CALL_INST
        UNCONDITIONAL_JMP_INST = ARM64_UNCONDITIONAL_JMP_INST
        RET_INST = ARM64_RET_INST
        CONDITIONAL_JMP_SET = set(ARM64_CONDITIONAL_JMP_INST)
    elif is_mips:
        CALL_INST = MIPS_CALL_INST
        UNCONDITIONAL_JMP_INST = MIPS_UNCONDITIONAL_JMP_INST
        RET_INST = MIPS_RET_INST
        CONDITIONAL_JMP_SET = set(CONDITIONAL_JMP_INST_X86)
    elif is_arm32:
        CALL_INST = ARM32_CALL_INST
        UNCONDITIONAL_JMP_INST = ARM32_UNCONDITIONAL_JMP_INST
        # ARM32 returns are operand-shaped (`bx lr`, `pop {…, pc}`), so the
        # mnemonic-set check below consults the helper instead of RET_INST.
        RET_INST = frozenset()
        CONDITIONAL_JMP_SET = ARM32_CONDITIONAL_JMP_INST
    else:
        CALL_INST = X86_CALL_INST
        UNCONDITIONAL_JMP_INST = X86_UNCONDITIONAL_JMP_INST
        RET_INST = X86_RET_INST
        CONDITIONAL_JMP_SET = set(CONDITIONAL_JMP_INST_X86)
    arm32_line_modes = arm32_context.get("modes") if arm32_context else None
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
    all_regs_read: set[str] = set()
    all_regs_written: set[str] = set()
    used_simd_reg_types = set()
    instructions_with_registers = []
    arch_reg_set = get_arch_reg_set(lower_arch)
    instr_address_set = set(instr_addresses)
    proprietary_instr_found = set()
    sreg_interactions = set()
    is_apple_silicon = "aarch64" in lower_arch and isinstance(parsed_obj, lief.MachO.Binary)
    if parsed_instrs is None:
        parsed_instrs = [_parse_instruction_text(instr.assembly) for instr in instr_list]
    for line_index, (instr, parsed_instr) in enumerate(zip(instr_list, parsed_instrs)):
        instr_assembly = instr.assembly
        if not parsed_instr.mnemonic:
            continue
        operand_text = parsed_instr.operand_text
        if is_apple_silicon and len(instr.bytes) == 4:
            opcode = int.from_bytes(instr.bytes, "little")
            for name, (start, end) in APPLE_PROPRIETARY_INSTRUCTION_RANGES.items():
                if start <= opcode <= end:
                    proprietary_instr_found.add(name)
                    break
        mnemonic = parsed_instr.mnemonic
        if is_apple_silicon and mnemonic in ("mrs", "msr") and operand_text:
            operands = parsed_instr.operands_lower
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
        elif mnemonic == "hint" and operand_text:
            operand = operand_text.strip().replace("#", "")
            if operand in ARM64_PAC_HINTS:
                has_pac = True
        if mnemonic in CALL_INST:
            instruction_metrics["call_count"] += 1
        elif is_arm32 and _is_arm32_table_dispatch(mnemonic, operand_text):
            # tbb/tbh and `ldr pc, [pc, rN, lsl #2]` dispatch within the
            # function; they are control flow, never calls.
            instruction_metrics["conditional_jump_count"] += 1
        elif mnemonic in CONDITIONAL_JMP_SET or mnemonic in CONDITIONAL_JMP_INST:
            instruction_metrics["conditional_jump_count"] += 1
            if operand_text:
                target_part = operand_text
                if target_part.startswith("0x"):
                    try:
                        target_addr = int(target_part, 16)
                        if (
                            func_addr <= target_addr < next_func_addr_in_sec
                            and target_addr < instr.address
                            and target_addr in instr_address_set
                        ):
                            has_loop = True
                    except ValueError:
                        continue
                elif is_arm32 and target_part.startswith("#"):
                    # ARM32 conditional branches print a PC-relative delta;
                    # Thumb PC is addr+4, ARM PC is addr+8.
                    mode = (
                        arm32_line_modes[line_index]
                        if arm32_line_modes and len(arm32_line_modes) == len(instr_list)
                        else None
                    )
                    target_addr = _arm32_branch_target(instr, target_part, mode)
                    if (
                        target_addr is not None
                        and func_addr <= target_addr < next_func_addr_in_sec
                        and target_addr < instr.address
                        and target_addr in instr_address_set
                    ):
                        has_loop = True
        elif mnemonic in UNCONDITIONAL_JMP_INST:
            instruction_metrics["jump_count"] += 1
        elif mnemonic == "xor":
            instruction_metrics["xor_count"] += 1
        elif mnemonic in SHIFT_INST:
            instruction_metrics["shift_count"] += 1
        elif mnemonic in ARITH_INST:
            instruction_metrics["arith_count"] += 1
        elif mnemonic in RET_INST or (is_arm32 and _is_arm32_return(mnemonic, operand_text)):
            instruction_metrics["ret_count"] += 1
        # Check for ARM64 indirect calls and jumps
        if mnemonic in (CALL_INST | UNCONDITIONAL_JMP_INST):
            is_indirect = False
            if operand_text:
                operand = parsed_instr.operand_text_lower
                reg_token = _extract_register_token(operand, arch_reg_set)
                if reg_token or "[" in operand and "]" in operand:
                    is_indirect = True
                elif is_arm32 and ARM32_GPR_TOKEN_RE.match(operand.split(",")[0].strip()):
                    # `blx rN` (and `bx rN`): the callee is in a register.
                    is_indirect = True
            if is_indirect:
                has_indirect_call = True
        regs_read, regs_written = _extract_register_usage(
            instr_assembly,
            parsed_obj,
            lower_arch,
            arch_reg_set,
            parsed_instr=parsed_instr,
        )
        all_instr_regs = set(regs_read) | set(regs_written)
        is_simd_fpu = False
        if is_aarch64:
            if all_instr_regs & ARM64_VFP_NEON_REGS:
                used_simd_reg_types.add("NEON/VFP")
                is_simd_fpu = True
        else:
            if all_instr_regs & FPU_REGS:
                used_simd_reg_types.add("FPU")
                is_simd_fpu = True
            if all_instr_regs & MMX_REGS:
                used_simd_reg_types.add("MMX")
                is_simd_fpu = True
            if all_instr_regs & XMM_REGS:
                used_simd_reg_types.add("SSE/AVX")
                is_simd_fpu = True
            if all_instr_regs & YMM_REGS:
                used_simd_reg_types.add("AVX/AVX2")
                is_simd_fpu = True
            if all_instr_regs & ZMM_REGS:
                used_simd_reg_types.add("AVX-512")
                is_simd_fpu = True
        if is_simd_fpu:
            instruction_metrics["simd_fpu_count"] += 1
        all_regs_read.update(regs_read)
        all_regs_written.update(regs_written)
        if regs_read or regs_written:
            reg_data: dict = {"position": len(instruction_mnemonics) - 1}
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


def _build_addr_to_name_map(metadata: dict, parsed_obj=None) -> dict[int, str]:
    """Builds a lookup map from address (int) to name from metadata functions."""
    addr_to_name_map = {}
    for func_list_key in FUNCTION_SYMBOLS:
        for func_entry in metadata.get(func_list_key, []):
            addr_str = func_entry.get("address", "")
            name = func_entry.get("name", "")
            if _ARM32_MAPPING_SYMBOL_RE.match(name or ""):
                # $a/$t/$d are mode labels; a callee named "$a.3" names
                # nothing. They share symtab buckets with real symbols.
                continue
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
    elif isinstance(parsed_obj, lief.MachO.Binary):
        import_map = metadata.get("import_call_addresses")
        if not isinstance(import_map, dict):
            import_map = build_macho_import_address_map(parsed_obj)
        for addr_str, name in import_map.items():
            with contextlib.suppress(ValueError, TypeError):
                addr_to_name_map.setdefault(int(addr_str, 16), name)
    return addr_to_name_map


def build_macho_import_address_map(parsed_obj) -> dict:
    """Map MachO __stubs and GOT/binding slot addresses to imported symbol names.

    MachO has no ELF-style PLT/GOT relocations, so imported calls otherwise land
    on anonymous ``sub_*`` stub nodes. Two address families are resolved here:

    * GOT / lazy-symbol-pointer slots, via the dyld binding table. Swift code on
      AArch64 calls imports through authenticated indirect branches that load the
      target from one of these slots (``adrp x16, got; ldr x16, [x16]; blraa``),
      which the register tracker resolves to the slot address.
    * ``__stubs`` entries, via the indirect symbol table indexed by the section's
      ``reserved1`` field, for the ``bl <stub>`` direct-call form.

    Names are demangled so Swift/C++ call sites surface readable APIs. Returns a
    dict mapping hex slot/stub address strings to demangled imported names.
    """
    import_map: dict[str, str] = {}
    # Binding table: slot address -> imported symbol name (covers __got and
    # lazy/non-lazy symbol pointer sections).
    with contextlib.suppress(AttributeError, TypeError):
        for binding in parsed_obj.bindings:
            with contextlib.suppress(AttributeError, TypeError, ValueError):
                symbol = binding.symbol
                if symbol is None:
                    continue
                sym_name = (symbol.name or "").strip()
                if not sym_name:
                    continue
                import_map[hex(int(binding.address))] = demangle_symbolic_name(sym_name)

    # __stubs sections: stub N maps to indirect_symbols[reserved1 + N].
    indirect_symbols = []
    with contextlib.suppress(AttributeError, TypeError):
        indirect_symbols = list(parsed_obj.dynamic_symbol_command.indirect_symbols)
    if not indirect_symbols:
        return import_map
    for section in parsed_obj.sections:
        with contextlib.suppress(AttributeError, TypeError, ValueError):
            if section.type != lief.MachO.Section.TYPE.SYMBOL_STUBS:
                continue
            entry_size = section.reserved2 or 0
            if entry_size <= 0:
                continue
            base_index = section.reserved1
            stub_count = section.size // entry_size
            for i in range(stub_count):
                idx = base_index + i
                if idx >= len(indirect_symbols):
                    break
                sym_name = (indirect_symbols[idx].name or "").strip()
                if not sym_name:
                    continue
                stub_addr = hex(section.virtual_address + i * entry_size)
                import_map.setdefault(stub_addr, demangle_symbolic_name(sym_name))
    return import_map


def _append_unique_target_addr(target_addrs: list[int], addr_val) -> None:
    if isinstance(addr_val, int) and addr_val >= 0 and addr_val not in target_addrs:
        target_addrs.append(addr_val)


# Branch and address-forming mnemonics whose single immediate operand LLVM
# prints as a byte offset from the instruction's own address.
AARCH64_PC_RELATIVE_MNEMONICS = frozenset({"b", "bl", "adr", "bc"})


def _resolve_operand_target_addresses(
    mnemonic: str,
    operand: str,
    instr,
    is_aarch64: bool,
    is_mips: bool,
    is_windows: bool,
) -> list[int]:
    """Parse operand forms and return normalized numeric target candidates."""
    operand = (operand or "").strip().rstrip(",")
    target_addrs = []
    try:
        lower_operand = operand.lower()
        if "rip" in lower_operand:
            base_reg, displacement = _parse_x86_memory_operand_base_disp(
                lower_operand, ARCH_REG_SET_X86
            )
            if base_reg == "rip":
                _append_unique_target_addr(
                    target_addrs, instr.address + len(instr.bytes) + displacement
                )
        else:
            whole_operand_is_immediate = _parse_immediate_token(operand) is not None
            immediate_token = (
                operand if whole_operand_is_immediate else _find_immediate_token(operand)
            )
            val = _parse_immediate_token(immediate_token)
            is_hex_token = immediate_token.lower().lstrip("#").startswith(("0x", "+0x", "-0x"))
            if val is not None and is_aarch64 and whole_operand_is_immediate:
                # LLVM's AArch64 printer (nyxstone) renders these operands
                # PC-relative in every immediate style: adrp as a delta from
                # the instruction's 4 KiB page, b/bl/adr from its address.
                # That exact target goes first; the guesses below remain as
                # fallbacks for other disassembly text.
                if mnemonic == "adrp":
                    _append_unique_target_addr(target_addrs, (instr.address & ~0xFFF) + val)
                elif mnemonic in AARCH64_PC_RELATIVE_MNEMONICS or mnemonic.startswith("b."):
                    _append_unique_target_addr(target_addrs, instr.address + val)
            if val is not None and is_hex_token:
                _append_unique_target_addr(target_addrs, val)
            elif val is not None:
                if mnemonic == "bal":
                    _append_unique_target_addr(target_addrs, instr.address + 4 + val)
                elif is_aarch64:
                    # Some AArch64 disassembly styles emit branch immediates as
                    # hex-like digits without a 0x prefix (for example #410212).
                    # Try that interpretation first for larger operands, then keep
                    # decimal as fallback.
                    stripped_token = immediate_token.lstrip("#")
                    if stripped_token.isdigit() and len(stripped_token) >= 5:
                        with contextlib.suppress(ValueError):
                            _append_unique_target_addr(target_addrs, int(stripped_token, 16))
                    if whole_operand_is_immediate and immediate_token.startswith(("+", "-")):
                        _append_unique_target_addr(target_addrs, instr.address + val)
                        _append_unique_target_addr(target_addrs, instr.address + 4 + val)
                    elif whole_operand_is_immediate:
                        # Unsigned AArch64 branch immediates are frequently emitted
                        # as PC-relative decimal deltas.
                        _append_unique_target_addr(target_addrs, instr.address + val)
                        _append_unique_target_addr(target_addrs, instr.address + 4 + val)
                    _append_unique_target_addr(target_addrs, val)
                elif (
                    whole_operand_is_immediate
                    and not is_mips
                    and (mnemonic.startswith("call") or (is_windows and mnemonic.startswith("j")))
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


@lru_cache(maxsize=65536)
def _extract_symbol_from_operand_cached(operand: str, arch_reg_set: frozenset[str]) -> str:
    """Symbol extraction fallback for cases where numeric resolution fails."""
    operand = (operand or "").strip()
    if not operand:
        return ""

    def _normalize_symbol(symbol_text: str) -> str:
        symbol_text = symbol_text.strip()
        if not symbol_text:
            return ""
        at_idx = symbol_text.find("@")
        if at_idx != -1:
            symbol_text = symbol_text[:at_idx]
        plus_idx = symbol_text.find("+")
        if plus_idx != -1:
            symbol_text = symbol_text[:plus_idx]
        symbol_text = symbol_text.strip()
        if not symbol_text:
            return ""
        lowered = symbol_text.lower().lstrip("%")
        return "" if lowered in arch_reg_set else symbol_text

    lt_idx = operand.find("<")
    if lt_idx != -1:
        gt_idx = operand.find(">", lt_idx + 1)
        if gt_idx != -1:
            inside = _normalize_symbol(operand[lt_idx + 1 : gt_idx])
            if inside:
                return inside

    if "[" in operand:
        return ""
    cleaned = _normalize_symbol(operand)
    if cleaned and not cleaned.startswith(("0x", "#")):
        return cleaned
    return ""


def _extract_symbol_from_operand(operand: str, arch_reg_set: frozenset[str] | set[str]) -> str:
    return _extract_symbol_from_operand_cached(operand or "", frozenset(arch_reg_set))


@lru_cache(maxsize=65536)
def _parse_immediate_token(token: str) -> int | None:
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
    operand: str, arch_reg_set: frozenset[str] | set[str]
) -> tuple[str, int]:
    """Parse simple x86 memory operands like [rax + 72] or [r12 + 0x48]."""
    operand = (operand or "").strip().lower()
    inner, _ = _extract_bracket_contents(operand)
    if not inner:
        return "", 0
    compact = "".join(inner.split())
    if not compact:
        return "", 0
    split_idx = -1
    for idx, ch in enumerate(compact[1:], start=1):
        if ch in "+-":
            split_idx = idx
            break
    if split_idx == -1:
        base_reg = compact.lstrip("%")
        if "*" not in base_reg and (base_reg == "rip" or base_reg in arch_reg_set):
            return base_reg, 0
        return "", 0
    base_reg = compact[:split_idx].lstrip("%")
    if "*" in base_reg or (base_reg != "rip" and base_reg not in arch_reg_set):
        return "", 0
    displacement = _parse_immediate_token(compact[split_idx:])
    if displacement is None:
        return "", 0
    return base_reg, displacement


def _parse_arm64_memory_operand_base_disp(
    operand: str, arch_reg_set: frozenset[str] | set[str]
) -> tuple[str, int, bool]:
    """Parse ARM64 memory operands like [x8, #0x18], [x8], or [x8], #0x20."""
    operand = (operand or "").strip().lower()
    inner, end_idx = _extract_bracket_contents(operand)
    if end_idx == -1:
        return "", 0, False

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
    tail = operand[end_idx + 1 :].strip().lstrip(",").strip()
    if tail:
        imm = _parse_immediate_token(tail)
        if imm is not None:
            displacement += imm

    return base_reg, displacement, True


def _extract_reg_target_candidate_addrs(reg_target: dict) -> list[int]:
    out = []
    for inferred_candidate in reg_target.get("_inferred_address_candidates_int", []):
        _append_unique_target_addr(out, inferred_candidate)
    for candidate in reg_target.get("_target_address_candidates_int", []):
        _append_unique_target_addr(out, candidate)
    if out:
        return out
    for inferred_candidate in reg_target.get("inferred_address_candidates", []):
        with contextlib.suppress(ValueError, TypeError):
            _append_unique_target_addr(out, int(inferred_candidate, 16))
    for candidate in reg_target.get("target_address_candidates", []):
        with contextlib.suppress(ValueError, TypeError):
            _append_unique_target_addr(out, int(candidate, 16))
    if not out and (target_addr_str := reg_target.get("target_address")):
        with contextlib.suppress(ValueError, TypeError):
            _append_unique_target_addr(out, int(target_addr_str, 16))
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


def _extract_register_token(operand: str, arch_reg_set: frozenset[str] | set[str]) -> str:
    return _extract_register_token_cached(operand or "", frozenset(arch_reg_set))


@lru_cache(maxsize=65536)
def _extract_register_token_cached(operand: str, arch_reg_set: frozenset[str]) -> str:
    cleaned = operand.strip().lower().rstrip(",")
    if not cleaned or "[" in cleaned or "]" in cleaned:
        return ""
    comma_idx = cleaned.find(",")
    if comma_idx != -1:
        cleaned = cleaned[:comma_idx].strip()
    cleaned = cleaned.lstrip("*#")
    if " " in cleaned:
        cleaned = cleaned.rsplit(None, 1)[-1]
    token = cleaned.lstrip("%")
    return token if token in arch_reg_set else ""


def _arm64_memory_operand_uses_index_register(
    operand: str, arch_reg_set: frozenset[str] | set[str]
) -> bool:
    """Return True when ARM64 memory operand address depends on an index register."""
    operand = (operand or "").strip().lower()
    inner, end_idx = _extract_bracket_contents(operand)
    if end_idx == -1:
        return False
    inner_parts = [part.strip() for part in inner.split(",") if part.strip()]
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


# AArch64 loads that write two registers.
AARCH64_PAIR_LOADS = frozenset({"ldp", "ldnp", "ldpsw", "ldxp", "ldaxp", "ldiapp"})
# Mnemonics whose first register operand is only read. Stores name their
# source first; compares, tests and branches write no general register.
_AARCH64_FIRST_OPERAND_READ_PREFIXES = ("st", "cmp", "cmn", "tst", "cb", "tb", "b", "prfm", "ret")
_X86_FIRST_OPERAND_READ = frozenset(
    {"cmp", "test", "push", "bt", "call", "jmp", "ret", "out", "outs", "verr", "verw"}
)


def _writes_first_operand(mnemonic: str, is_aarch64: bool) -> bool:
    if is_aarch64:
        return not mnemonic.startswith(_AARCH64_FIRST_OPERAND_READ_PREFIXES) or mnemonic in {
            "bic",
            "bics",
            "bfi",
            "bfm",
            "bfxil",
            "bsl",
            "bit",
            "bif",
        }
    return mnemonic not in _X86_FIRST_OPERAND_READ and not mnemonic.startswith(("j", "cmp"))


def _update_register_target(
    instr,
    reg_targets: dict,
    arch_reg_set: frozenset[str] | set[str],
    is_aarch64: bool,
    is_mips: bool,
    is_windows: bool,
    chain_hop_limit: int = 2,
    parsed_instr=None,
):
    """Track register assignments used later for indirect call hints."""
    if parsed_instr is None:
        parsed_instr = _parse_instruction_text(instr.assembly)
    if not parsed_instr.operand_text:
        return
    mnemonic = parsed_instr.mnemonic
    operands = parsed_instr.operands
    if not operands:
        return
    dst_reg = _extract_register_token(operands[0], arch_reg_set)
    if not dst_reg:
        return
    if not _writes_first_operand(mnemonic, is_aarch64):
        return
    if is_aarch64 and mnemonic in AARCH64_PAIR_LOADS and len(operands) >= 2:
        # Both destinations are written by a pair load; the tracker models
        # neither (the loaded values are memory, not addresses it knows).
        reg_targets.pop(dst_reg, None)
        if second := _extract_register_token(operands[1], arch_reg_set):
            reg_targets.pop(second, None)
        return

    if is_aarch64 and mnemonic.startswith(("ldr", "ldur")) and len(operands) >= 2:
        src = ",".join(part.strip() for part in operands[1:])
        src_base_reg, src_displacement, has_mem_operand = _parse_arm64_memory_operand_base_disp(
            src, arch_reg_set
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
                    reg_targets[dst_reg] = _build_reg_target(
                        target_addrs=adjusted_addrs,
                        raw_operand=_raw_operand_text(src),
                        chain_hops=next_hops,
                    )
                    return
            # A pointer loaded from memory the tracker cannot place (a vtable
            # slot off a heap object). No address is known, but the load is
            # the evidence a later blr through this register should report
            # as unresolved rather than drop.
            reg_targets[dst_reg] = _build_reg_target(raw_operand=_raw_operand_text(src))
            return

    if mnemonic in {"mov", "movq", "movabs", "lea", "adr", "adrp"} and len(operands) >= 2:
        src = operands[1]
        src_base_reg, src_displacement = _parse_x86_memory_operand_base_disp(src, arch_reg_set)
        if is_windows and src_base_reg and src_base_reg != "rip" and src_base_reg in reg_targets:
            base_target = reg_targets[src_base_reg]
            next_hops = _get_chain_hops(base_target) + 1
            if next_hops > chain_hop_limit:
                reg_targets.pop(dst_reg, None)
                return
            adjusted_addrs = _adjust_candidate_addrs(
                _extract_reg_target_candidate_addrs(base_target), src_displacement
            )
            if adjusted_addrs:
                reg_targets[dst_reg] = _build_reg_target(
                    inferred_addrs=adjusted_addrs,
                    chain_hops=next_hops,
                )
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
        raw = _raw_operand_text(src)
        if addrs or name:
            reg_targets[dst_reg] = _build_reg_target(
                target_name=name,
                target_addrs=addrs,
                raw_operand=raw,
            )
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
                    val + imm if mnemonic == "add" else val - imm for val in base_candidates
                ]
                adjusted = _filter_windows_arm64_indirect_candidates(
                    adjusted, is_windows, is_aarch64
                )
                if not adjusted:
                    reg_targets.pop(dst_reg, None)
                    return
                reg_targets[dst_reg] = _build_reg_target(
                    target_name=base.get("target_name", ""),
                    target_addrs=adjusted,
                    raw_operand=base.get("raw_operand", ""),
                    chain_hops=_get_chain_hops(base),
                )
                return
        reg_targets.pop(dst_reg, None)
        return
    # Any other instruction that writes its first register operand (csel,
    # orr, ldur, pop, xor, ...) leaves a value the tracker does not model;
    # keeping the old target would resolve a later indirect call through a
    # register that no longer holds it.
    reg_targets.pop(dst_reg, None)


def _arm32_extract_literals(
    truncated_instr_list: list,
    parsed_instrs: list,
    line_modes: list[str | None],
    default_mode: str | None,
    parsed_obj,
    base_delta: int,
) -> dict[str, int]:
    """Read the PC-relative literal words a function's ``ldr rN, [pc, #imm]``
    instructions point at, as ``{hex(address): signed_value}``.

    The values are the offset halves of position-independent address
    materialisation (`ldr rN, [pc, #x]` + `add rN, pc`), so the register
    tracker in the call resolver can complete them. Reads go through LIEF
    with the same rebased lookup the function bytes used.
    """
    literals: dict[str, int] = {}
    for index, (instr, parsed) in enumerate(zip(truncated_instr_list, parsed_instrs)):
        mnemonic = parsed.mnemonic
        if mnemonic not in ("ldr", "ldr.w") or len(parsed.operands_lower) < 2:
            continue
        mode = (
            line_modes[index]
            if line_modes and len(line_modes) == len(truncated_instr_list)
            else default_mode
        )
        literal_addr = _arm32_literal_address(instr, parsed.operands_lower[1], mode)
        if literal_addr is None or hex(literal_addr) in literals:
            continue
        with contextlib.suppress(Exception):
            content = parsed_obj.get_content_from_virtual_address(literal_addr + base_delta, 4)
            if content is None or isinstance(content, lief.lief_errors):
                content = parsed_obj.get_content_from_virtual_address(literal_addr, 4)
            if content is None or isinstance(content, lief.lief_errors):
                continue
            raw = bytes(content)
            if len(raw) < 4:
                continue
            value = struct.unpack("<I", raw[:4])[0]
            if value >= 0x80000000:
                value -= 1 << 32
            literals[hex(literal_addr)] = value
    return literals


def _resolve_direct_calls(
    instr_list: list,
    addr_to_name_map: dict[int, str],
    arch_target: str = "",
    parsed_instrs: list | None = None,
    arm32_context: dict | None = None,
) -> tuple[list, list]:
    """Identifies direct calls and returns both legacy names and rich call targets."""
    potential_callees: list[str] = []
    direct_call_targets: list[dict] = []
    lower_arch = _normalize_arch_target(arch_target)
    is_aarch64 = "aarch64" in lower_arch or "arm64" in lower_arch
    is_mips = "mips" in lower_arch
    is_windows = "windows" in lower_arch
    is_arm32 = _is_arm32_target(lower_arch)
    arch_reg_set = get_arch_reg_set(lower_arch)
    reg_targets: dict = {}
    arm32_line_modes = arm32_context.get("modes") if arm32_context else None
    arm32_literals = arm32_context.get("literals") if arm32_context else None
    arm32_reg_state: dict[str, tuple[str, int]] = {}
    if parsed_instrs is None:
        parsed_instrs = [_parse_instruction_text(instr.assembly) for instr in instr_list]

    def _line_mode(index: int) -> str | None:
        if arm32_line_modes and len(arm32_line_modes) == len(instr_list):
            return arm32_line_modes[index]
        return arm32_context.get("default_mode") if arm32_context else None

    def _arm32_track(line_index: int, instr, parsed) -> None:
        """Track the ARM32 pointer-materialisation idioms textually.

        ``ldr rN, [pc, #imm]`` loads a PC-relative literal (the offset half
        of a symbol address), ``add rN, pc`` completes it, and ``ldr rM,
        [rN, #off]`` loads through the completed base — the shape
        position-independent ARM32 code uses for GOT-resolved callees. Any
        other write to a tracked register clears it.
        """
        mnemonic = parsed.mnemonic
        operands = parsed.operands_lower
        if mnemonic in ("ldr", "ldr.w") and len(operands) >= 2:
            dst = operands[0].strip()
            if ARM32_GPR_TOKEN_RE.match(dst):
                literal_addr = _arm32_literal_address(instr, operands[1], _line_mode(line_index))
                if literal_addr is not None and arm32_literals:
                    value = arm32_literals.get(hex(literal_addr))
                    if value is not None:
                        arm32_reg_state[dst] = ("literal_offset", value)
                        return
                # A load through a completed base (the GOT-slot read of the
                # ldr+add pc idiom): the slot address is known even though
                # the loaded pointer is not.
                match = re.match(r"^\[([a-z0-9]+)\s*(?:,\s*(#[^\]]+))?\]$", operands[1].strip())
                if match and match.group(1) in arm32_reg_state:
                    base_state = arm32_reg_state[match.group(1)]
                    if base_state[0] == "absolute":
                        offset = _arm32_parse_immediate(match.group(2) or "#0") or 0
                        arm32_reg_state[dst] = ("memory", base_state[1] + offset)
                        return
                arm32_reg_state.pop(dst, None)
            return
        if mnemonic in ("add", "add.w", "adds", "adds.w") and operands:
            dst = operands[0].strip()
            if ARM32_GPR_TOKEN_RE.match(dst):
                src = operands[1].strip() if len(operands) > 1 else ""
                if src == "pc":
                    state = arm32_reg_state.get(dst)
                    if state and state[0] == "literal_offset":
                        arm32_reg_state[dst] = (
                            "absolute",
                            state[1] + _arm32_pc_base(instr.address, _line_mode(line_index)),
                        )
                        return
                elif src in arm32_reg_state and len(operands) > 2:
                    imm = _arm32_parse_immediate(operands[2])
                    state = arm32_reg_state[src]
                    if imm is not None and state[0] == "absolute":
                        arm32_reg_state[dst] = (
                            "absolute",
                            state[1] + (imm if mnemonic.startswith("add") else -imm),
                        )
                        return
                arm32_reg_state.pop(dst, None)
            return
        # First-operand write outside the tracked idioms clears the register.
        if operands:
            dst = operands[0].strip()
            if ARM32_GPR_TOKEN_RE.match(dst):
                arm32_reg_state.pop(dst, None)

    for line_index, (instr, parsed_instr) in enumerate(zip(instr_list, parsed_instrs)):
        if not parsed_instr.mnemonic:
            continue
        mnemonic = parsed_instr.mnemonic
        operand_text = parsed_instr.operand_text
        _update_register_target(
            instr,
            reg_targets,
            arch_reg_set,
            is_aarch64=is_aarch64,
            is_mips=is_mips,
            is_windows=is_windows,
            parsed_instr=parsed_instr,
        )
        if is_arm32:
            _arm32_track(line_index, instr, parsed_instr)
        is_direct_call = False
        is_indirect_call = False
        if (
            (is_aarch64 and mnemonic == "bl")
            or (is_mips and mnemonic in MIPS_CALL_INST)
            or (not is_aarch64 and not is_mips and mnemonic.startswith("call"))
            or (
                is_arm32
                and mnemonic in ARM32_CALL_INST
                and (operand_text or "").lstrip().startswith("#")
            )
        ):
            is_direct_call = True
        if operand_text:
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
            elif (
                is_arm32
                and mnemonic in ARM32_CALL_INST
                and ARM32_GPR_TOKEN_RE.match(operand_text.split(",")[0].strip().lower())
            ):
                # blx rN: interworking call through a register.
                is_indirect_call = True
                is_direct_call = False

        if is_arm32 and is_direct_call and operand_text:
            target_addr = _arm32_branch_target(
                instr, operand_text, _line_mode(line_index), mnemonic
            )
            if target_addr is not None:
                # A Thumb callee's address carries the interworking bit;
                # the callgraph node is the aligned start.
                target_addr &= ~1
                target_addrs = [target_addr]
                target_name = _lookup_target_name(target_addrs, addr_to_name_map)
                if target_name:
                    potential_callees.append(target_name)
                if not target_name:
                    target_name = _extract_symbol_from_operand(operand_text, arch_reg_set)
                    if target_name:
                        potential_callees.append(target_name)
                _append_call_target(
                    direct_call_targets,
                    kind="direct",
                    target_name=target_name,
                    target_addr=target_addr,
                    target_addrs=target_addrs,
                    raw_operand=_raw_operand_text(operand_text),
                )
            continue

        if is_arm32 and is_indirect_call and operand_text:
            reg = operand_text.split(",")[0].strip().lower()
            state = arm32_reg_state.get(reg)
            if state and state[0] == "absolute":
                target_addrs = [state[1]]
                target_name = _lookup_target_name(target_addrs, addr_to_name_map)
                _append_call_target(
                    direct_call_targets,
                    kind="indirect_hint",
                    target_name=target_name,
                    target_addr=state[1],
                    target_addrs=target_addrs,
                    raw_operand=reg,
                )
                continue
            if state and state[0] == "memory":
                target_name = _lookup_target_name([state[1]], addr_to_name_map)
                _append_call_target(
                    direct_call_targets,
                    kind="indirect_hint",
                    target_name=target_name,
                    raw_operand=reg,
                )
                continue
            _append_call_target(
                direct_call_targets,
                kind="indirect_hint",
                target_name="",
                raw_operand=reg,
            )
            continue

        if is_indirect_call and operand_text:
            operand = operand_text.strip()
            reg_token = _extract_register_token(operand, arch_reg_set)
            if reg_token and reg_token in reg_targets:
                reg_target = reg_targets[reg_token]
                reg_target_candidate_addrs = _extract_reg_target_candidate_addrs(reg_target)
                target_name = reg_target.get("target_name", "")
                if not target_name:
                    target_name = _lookup_target_name(
                        reg_target_candidate_addrs,
                        addr_to_name_map,
                    )
                exposed_target_addrs = list(reg_target.get("_target_address_candidates_int", []))
                exposed_target_addr = exposed_target_addrs[0] if exposed_target_addrs else None
                _append_call_target(
                    direct_call_targets,
                    kind="indirect_hint",
                    target_name=target_name,
                    target_addr=exposed_target_addr,
                    target_addrs=exposed_target_addrs,
                    raw_operand=reg_target.get("raw_operand", reg_token),
                )
                continue

            # Preserve memory-indirect and annotated-symbol evidence for
            # unresolved bucketing without pretending the pointer slot is callee VA.
            if "[" in operand and "]" in operand:
                target_name = ""
                base_reg, displacement = _parse_x86_memory_operand_base_disp(operand, arch_reg_set)
                if base_reg and base_reg in reg_targets:
                    reg_target = reg_targets[base_reg]
                    target_name = _lookup_target_name(
                        _adjust_candidate_addrs(
                            _extract_reg_target_candidate_addrs(reg_target),
                            displacement,
                        ),
                        addr_to_name_map,
                    )
                    if not target_name and displacement == 0:
                        target_name = reg_target.get("target_name", "")

                target_addrs = _resolve_operand_target_addresses(
                    mnemonic, operand, instr, is_aarch64, is_mips, is_windows
                )
                if not target_name:
                    target_name = _lookup_target_name(target_addrs, addr_to_name_map)
                if not target_name:
                    target_name = _extract_symbol_from_operand(operand, arch_reg_set)
                raw_operand = _raw_operand_text(operand)
                if target_name or raw_operand:
                    _append_call_target(
                        direct_call_targets,
                        kind="indirect_hint",
                        target_name=target_name,
                        raw_operand=raw_operand,
                    )
            continue

        if is_direct_call and operand_text:
            operand = operand_text.strip()
            target_addrs = _resolve_operand_target_addresses(
                mnemonic, operand, instr, is_aarch64, is_mips, is_windows
            )
            target_addr = target_addrs[0] if target_addrs else None
            target_name = _lookup_target_name(target_addrs, addr_to_name_map)
            if target_name:
                potential_callees.append(target_name)
            if not target_name:
                target_name = _extract_symbol_from_operand(operand, arch_reg_set)
                if target_name:
                    potential_callees.append(target_name)
            raw_operand = _raw_operand_text(operand)
            _append_call_target(
                direct_call_targets,
                kind="direct",
                target_name=target_name,
                target_addr=target_addr,
                target_addrs=target_addrs,
                raw_operand=raw_operand,
            )

    # This recovers common compiler-emitted tail dispatch patterns that would
    # otherwise appear as disconnected terminal blocks.
    if instr_list:
        tail_instr = instr_list[-1]
        parsed_tail = parsed_instrs[-1]
        if parsed_tail.mnemonic:
            mnemonic = parsed_tail.mnemonic
            jump_set = (
                ARM64_UNCONDITIONAL_JMP_INST
                if is_aarch64
                else MIPS_UNCONDITIONAL_JMP_INST
                if is_mips
                else ARM32_UNCONDITIONAL_JMP_INST
                if is_arm32
                else X86_UNCONDITIONAL_JMP_INST
            )
            if is_arm32 and mnemonic in ARM32_UNCONDITIONAL_JMP_INST and parsed_tail.operand_text:
                # A trailing unconditional `b #imm` whose target lies outside
                # the function is a tail call (PLT thunks and -Oz tail
                # merging); a target inside the extent is a local branch.
                operand = parsed_tail.operand_text.strip()
                target_addr = _arm32_branch_target(
                    tail_instr, operand, _line_mode(len(instr_list) - 1), mnemonic
                )
                func_start = instr_list[0].address
                last = instr_list[-1]
                func_end = last.address + len(last.bytes)
                if target_addr is not None:
                    target_addr &= ~1
                if target_addr is not None and not (func_start <= target_addr < func_end):
                    target_name = _lookup_target_name([target_addr], addr_to_name_map)
                    _append_call_target(
                        direct_call_targets,
                        kind="tailcall",
                        target_name=target_name,
                        target_addr=target_addr,
                        target_addrs=[target_addr],
                        raw_operand=_raw_operand_text(operand),
                    )
            elif mnemonic in jump_set and parsed_tail.operand_text:
                operand = parsed_tail.operand_text.strip()
                reg_token = _extract_register_token(operand, arch_reg_set)
                if reg_token and reg_token in reg_targets:
                    reg_target = reg_targets[reg_token]
                    target_addrs = _extract_reg_target_candidate_addrs(reg_target)
                    target_addr = target_addrs[0] if target_addrs else None
                    target_name = reg_target.get("target_name", "")
                    if not target_name:
                        target_name = _lookup_target_name(target_addrs, addr_to_name_map)
                    raw_operand = _raw_operand_text(operand)
                    if target_name or target_addr is not None or raw_operand:
                        _append_call_target(
                            direct_call_targets,
                            kind="tailcall",
                            target_name=target_name,
                            target_addr=target_addr,
                            target_addrs=target_addrs,
                            raw_operand=raw_operand,
                        )
                elif not is_aarch64 and not is_mips and "[" in operand and "]" in operand:
                    # Tail jump through a pointer slot - jmp qword ptr
                    # [rip + N] is the PLT, -fno-plt and PE import-thunk
                    # shape. Named from the slot, like a call through one;
                    # the slot's address is never offered as the callee's.
                    slot_addrs = _resolve_operand_target_addresses(
                        mnemonic, operand, tail_instr, is_aarch64, is_mips, is_windows
                    )
                    target_name = _lookup_target_name(slot_addrs, addr_to_name_map)
                    if target_name:
                        _append_call_target(
                            direct_call_targets,
                            kind="tailcall",
                            target_name=target_name,
                            raw_operand=_raw_operand_text(operand),
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
                    target_name = _lookup_target_name(target_addrs, addr_to_name_map)
                    if not target_name:
                        target_name = _extract_symbol_from_operand(operand, arch_reg_set)
                    raw_operand = _raw_operand_text(operand)
                    if target_name or target_addr is not None or raw_operand:
                        _append_call_target(
                            direct_call_targets,
                            kind="tailcall",
                            target_name=target_name,
                            target_addr=target_addr,
                            target_addrs=target_addrs,
                            raw_operand=raw_operand,
                        )
    return potential_callees, direct_call_targets


def _promote_call_targets(
    direct_call_targets: list,
    visited_addrs: set,
    known_starts: list,
    disassembled_spans: list[tuple[int, int]],
    exec_ranges_stored: list[tuple[int, int]],
    imagebase: int,
    is_aarch64: bool = False,
) -> list[int]:
    """Return stored-space addresses worth promoting into new functions.

    A resolved direct call whose target sits in an executable range outside
    every known extent proves called code the discovery tables missed, so the
    target becomes a worklist entry. Only the resolver's primary
    ``target_address`` — the displacement-corrected absolute target — is
    consulted. The raw operand and alternate candidates are skipped on
    purpose: nyxstone renders branch operands as signed displacements, so
    reinterpreting them as addresses promotes garbage, and the alternate
    candidates encode other resolution hypotheses rather than the call's
    destination. Everything already visited, already a known start, inside a
    known extent (unwind tables provide exact sizes, disassembly provides the
    rest), or not in executable memory is declined; ARM64 targets must
    additionally be word-aligned. Bounded by the caller's promotion cap.
    """
    promoted: list[int] = []
    promoted_set: set[int] = set()
    for target in direct_call_targets or []:
        if not isinstance(target, dict) or target.get("kind") != "direct":
            continue
        target_addr = target.get("target_address")
        if not target_addr:
            continue
        with contextlib.suppress(ValueError):
            absolute_addr = int(target_addr, 16)
            stored_addr = absolute_addr - imagebase
            if is_aarch64 and stored_addr % 4:
                continue
            if stored_addr in visited_addrs or stored_addr in promoted_set:
                continue
            if (
                promotable_call_target(
                    stored_addr,
                    known_starts,
                    disassembled_spans,
                    exec_ranges_stored,
                )
                is None
            ):
                continue
            promoted.append(stored_addr)
            promoted_set.add(stored_addr)
    return promoted


def _classify_function(
    instruction_metrics: dict,
    instruction_count: int,
    plain_assembly_text: str,
    has_system_call: bool,
    has_indirect_call: bool,
) -> str:
    """Classifies the function based on metrics and other flags."""
    function_type = ""
    if (
        instruction_metrics["jump_count"] > 0
        and instruction_count <= 5
        and all(
            mnem in ("jmp", "push", "sub")
            for mnem in [
                i.split(None, 1)[0].lower() for i in plain_assembly_text.split("\n") if i.strip()
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


def _mem_bytes_len(b) -> int | None:
    if isinstance(b, list):
        return len(b)
    if hasattr(b, "nbytes"):
        return b.nbytes
    return None


def _try_disassemble(instance, byte_list, address: int, inst_count: int = 0) -> list | None:
    """Helper to safely call Nyxstone and handle immediate failures."""
    try:
        instructions = instance.disassemble_to_instructions(byte_list, address, inst_count)
        return instructions if instructions else None
    except ValueError:
        return None


def _longest_decodable_prefix(instance, byte_list, address: int) -> list:
    """The largest instruction prefix of ``byte_list`` nyxstone can decode.

    A full-call failure hides how far decoding got, so probe with rising
    instruction counts (the call succeeds whenever the bad word sits beyond
    the requested count) and binary-search the boundary they bracket.
    """
    lower, upper = 0, 1
    instructions = []
    while True:
        probe = _try_disassemble(instance, byte_list, address, upper)
        if probe is None or len(probe) < upper:
            instructions = probe or []
            break
        if upper >= (1 << 20):
            return probe
        lower, upper = upper, upper * 2
    if len(instructions) == upper:
        return instructions
    good = _try_disassemble(instance, byte_list, address, lower) or []
    # Binary search the largest count that still decodes cleanly.
    while lower + 1 < upper:
        mid = (lower + upper) // 2
        probe = _try_disassemble(instance, byte_list, address, mid)
        if probe is not None and len(probe) == mid:
            lower, good = mid, probe
        else:
            upper = mid
    return good


def _disassemble_arm32_span(instance, byte_list, address: int) -> list:
    """Decode one code span, resuming past words nyxstone cannot decode.

    ARM32 functions carry literal pools and jump tables inline; objdump
    prints those as ``.word``/``<unknown>`` and carries on, while a nyxstone
    call raises and would otherwise truncate the function at the pool. The
    resume skips one 4-byte word (pool entries are word-sized in both
    states). Every iteration advances the cursor, and eight consecutive
    undecodable words end the span.
    """
    instructions: list = []
    cursor = 0
    total = len(byte_list)
    skips = 0
    while cursor < total:
        chunk = _try_disassemble(instance, byte_list[cursor:], address + cursor)
        if chunk:
            instructions.extend(chunk)
            cursor += sum(len(instr.bytes) for instr in chunk)
            skips = 0
            continue
        prefix = _longest_decodable_prefix(instance, byte_list[cursor:], address + cursor)
        if not prefix:
            if skips >= 8:
                break
            skips += 1
            cursor += 4
            continue
        instructions.extend(prefix)
        cursor += sum(len(instr.bytes) for instr in prefix) + 4
        skips = 1
    return instructions


# Trailing words both states decode as filler, so an evidence-less span's
# terminator search skips past them: the shared padding set and ARM's
# zero/pool word (``andeq …``, the ARM NOP idiom). Thumb's zero halfword
# (``movs r0, r0``) matches by operand below; other ``movs`` are real code.
_ARM32_ARBITER_SKIP_MNEMONICS = PADDING_TRAP_MNEMONICS | {"andeq"}


def _arm32_stream_terminates(instrs: list, span_start: int, span_end: int, mode: str) -> bool:
    """True when the instruction stream ends like a function in ``mode``.

    The last non-filler instruction must be a return (``bx lr``, ``pop {…,
    pc}``, ``ldr pc, [sp], #4``), an indirect tail branch (``bx rN``, a
    ``ldr pc, [rN, …]``/``ldm``-to-pc form such as a PLT slot), or an
    immediate ``b``/``blx``/``bl``-style branch whose target leaves the span
    (a tail call). A wrong-mode decode of the same bytes ends in whatever
    the mis-decode produced — NEON moves, data-processing writes to pc —
    and loses the comparison.
    """
    index = len(instrs) - 1
    while index >= 0:
        mnemonic, operand = _split_arm32_instruction(instrs[index].assembly)
        if mnemonic not in _ARM32_ARBITER_SKIP_MNEMONICS and not (
            mnemonic == "movs" and operand.strip() == "r0, r0"
        ):
            break
        index -= 1
    if index < 0:
        return False
    mnemonic, operand = _split_arm32_instruction(instrs[index].assembly)
    if _is_arm32_return(mnemonic, operand):
        return True
    if ARM32_BX_RE.match(mnemonic):
        return True  # bx rN with N != lr: an indirect tail branch
    compact = (operand or "").replace(" ", "")
    if mnemonic in ("ldr", "ldr.w") and compact.startswith("pc,["):
        # `ldr pc, [pc, …]` is a dispatch; `ldr pc, [sp…]` a return (both
        # classified above); any other base is an indirect tail branch -
        # the PLT slot shape.
        return not compact.startswith("pc,[pc")
    if _is_arm32_table_dispatch(mnemonic, operand):
        return False
    if mnemonic in ARM32_UNCONDITIONAL_JMP_INST or mnemonic in ("blx", "blx.w", "bl", "bl.w"):
        target = _arm32_branch_target(instrs[index], operand.split(",")[0].strip(), mode, mnemonic)
        return target is None or not (span_start <= target < span_end)
    return False


def _split_arm32_instruction(assembly: str) -> tuple[str, str]:
    """``mnemonic, operand_text`` from one nyxstone assembly line."""
    pieces = (assembly or "").split(None, 1)
    return pieces[0].lower(), pieces[1] if len(pieces) > 1 else ""


def _arm32_branch_plausibility(
    instrs: list,
    mode: str,
    span_start: int,
    exec_ranges: list,
    known_starts: set[int],
) -> int:
    """Score one mode's immediate branches: coherent code vs mis-decode.

    Every immediate ``b``/``bl``/``blx`` votes: +1 when its target is a
    known function start (calls and tail calls land on entries), −1 when it
    leaves the executable ranges entirely (no real branch does that), 0 for
    the in-exec-but-unknown middle. A wrong-mode decode of ARM code as
    Thumb (or the reverse) misreads halfwords into a spray of branches
    whose targets are mostly nonsense addresses, so the sums separate the
    states on real library code where a single function's own shape may
    not.
    """
    score = 0
    for instr in instrs:
        parsed = _parse_instruction_text(instr.assembly)
        mnemonic = parsed.mnemonic
        if mnemonic not in ARM32_CALL_INST | ARM32_UNCONDITIONAL_JMP_INST:
            continue
        operand = parsed.operands_lower[0] if parsed.operands_lower else ""
        if not operand.startswith("#"):
            continue
        target = _arm32_branch_target(instr, operand, mode, mnemonic)
        if target is None:
            continue
        target &= ~1
        if target in known_starts and target != span_start:
            score += 1
        elif not _addr_in_exec_ranges(target, exec_ranges):
            score -= 1
    return score


def _arm32_arbiter_pick(
    decoded: list[tuple[str, list]],
    span_va: int,
    span_len: int,
    exec_ranges: list,
    known_starts: set[int],
) -> tuple[str, list] | None:
    """Choose the instruction set state for an evidence-less span.

    Both states' decodes are scored: +2 when the stream (minus trailing
    filler) ends on a terminator — a return or a tail branch out of the
    span, the shape a real function ends in; the immediate-branch
    plausibility sum (known-start targets vs addresses outside the
    executable ranges); and +1 when the raw stream lands exactly on the
    span end, the previous A4a rule. Ties keep the caller's order (Thumb
    first, the NDK armeabi-v7a default), so the new score only changes a
    decision the old rule could not make.
    """
    best: tuple[int, str, list] | None = None
    for mode_name, candidate in decoded:
        if not candidate:
            continue
        score = _arm32_branch_plausibility(
            candidate,
            mode_name,
            span_va,
            exec_ranges,
            known_starts,
        )
        last = candidate[-1]
        if last.address + len(last.bytes) == span_va + span_len:
            score += 1
        if _arm32_stream_terminates(candidate, span_va, span_va + span_len, mode_name):
            score += 2
        if best is None or score > best[0]:
            best = (score, mode_name, candidate)
    if best is None:
        return None
    return best[1], best[2]


def _arm32_code_spans(
    start: int, size: int, mapping_modes: list[tuple[int, str]]
) -> list[tuple[int, int]]:
    """Code sub-spans of ``[start, start+size)``, from ``$a``/``$t`` labels.

    With mapping symbols present, only labeled code regions are decoded -
    the same rule objdump applies with mapping-symbol knowledge - so ``$d``
    islands and un-labeled filler (the bytes between sections and before the
    first label) are never disassembled. A span's label also names its
    instruction set state, so ARM and Thumb islands inside one function each
    decode in their own mode. An empty mapping table yields the whole extent
    as one span.
    """
    end = start + size
    if size <= 0:
        return []
    if not mapping_modes:
        return [(start, size)]
    spans: list[tuple[int, int]] = []
    # The label covering the extent start (a function usually begins inside
    # the region its own opening label named, not at a fresh label).
    covering_index = bisect.bisect_right(mapping_modes, (start, "zz")) - 1
    if covering_index >= 0:
        covering_addr, covering_mode = mapping_modes[covering_index]
        if covering_mode != "data" and covering_addr <= start < end:
            next_label = (
                mapping_modes[covering_index + 1][0]
                if covering_index + 1 < len(mapping_modes)
                else end
            )
            span_end = min(next_label, end)
            if span_end > start:
                spans.append((start, span_end - start))
    for index, (addr, mode) in enumerate(mapping_modes):
        if mode == "data" or addr <= start or addr >= end:
            continue
        next_label = mapping_modes[index + 1][0] if index + 1 < len(mapping_modes) else end
        span_end = min(next_label, end)
        if span_end > addr:
            spans.append((addr, span_end - addr))
    if not spans:
        # No code label covers or intersects the extent (an exidx start
        # pointing into label-less filler, or hand-built code); the
        # parity/arbiter path takes over rather than dropping the function.
        return [(start, size)]
    return spans


def _arm32_skipped_regions(
    start: int, size: int, code_spans: list[tuple[int, int]]
) -> list[tuple[int, int]]:
    """Byte ranges inside ``[start, start+size)`` no code span covers."""
    regions: list[tuple[int, int]] = []
    cursor = start
    for span_start, span_len in code_spans:
        if span_start > cursor:
            regions.append((cursor, span_start - cursor))
        cursor = max(cursor, span_start + span_len)
    if start + size > cursor:
        regions.append((cursor, start + size - cursor))
    return regions


def disassemble_functions(
    parsed_obj,
    metadata: dict,
    arch_target: str = "",
    cpu: str = "",
    features: str = "",
    immediate_style: int = 0,
) -> dict:
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
    disassembly_results: dict = {}
    if not NYXSTONE_AVAILABLE:
        LOG.debug("Nyxstone is not available. Cannot perform disassembly.")
        return disassembly_results
    if not arch_target:
        arch_target = str(metadata.get("llvm_target_tuple") or "")
    arch_target = (arch_target or "").strip()
    if not _has_supported_nyxstone_target(arch_target):
        LOG.debug(
            "Skipping disassembly because the LLVM target triple is missing or has an unknown architecture: %s",
            arch_target or "<empty>",
        )
        return disassembly_results
    features = _merge_features(_default_disassembly_features(arch_target), features)
    # Nyxstone's LLVM backend only supports the ELF object format, so MachO and
    # PE triples must be remapped to an ELF-compatible triple for initialization.
    # The original arch_target is retained for the architecture-specific decode
    # heuristics below (and isinstance(parsed_obj, ...) format checks).
    nyxstone_triple = _to_nyxstone_triple(arch_target)
    try:
        LOG.debug(
            f"Attempting to disassemble functions using Nyxstone for target: {arch_target}"
            f" (nyxstone triple: {nyxstone_triple})"
        )
        nyxstone_instance = Nyxstone(
            target_triple=nyxstone_triple,
            cpu=cpu,
            features=features,
            immediate_style=immediate_style,
        )
    except ValueError as e:
        LOG.error(f"Failed to initialize Nyxstone for target '{nyxstone_triple}': {e}")
        return disassembly_results
    mips16_nyxstone_instance = None
    micromips_nyxstone_instance = None
    is_mips = "mips" in arch_target.lower()
    if is_mips:
        try:
            mips16_features = (features + ",+mips16").strip(",")
            mips16_nyxstone_instance = Nyxstone(
                target_triple=nyxstone_triple,
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
                target_triple=nyxstone_triple,
                cpu=cpu,
                features=micromips_features,
                immediate_style=immediate_style,
            )
        except ValueError as e:
            LOG.warning(f"Failed to initialize microMIPS disassembler: {e}")
    # 32-bit ARM binaries mix ARM and Thumb functions (and NDK-built
    # armeabi-v7a code is mostly Thumb), so a second instance decodes the
    # other instruction set state; per-function mode selection happens in the
    # worklist loop below.
    arm32_thumb_nyxstone_instance = None
    is_arm32 = _is_arm32_target(arch_target)
    if is_arm32:
        arm_triple, thumb_triple = _arm32_mode_triples(nyxstone_triple)
        if thumb_triple != nyxstone_triple:
            try:
                arm32_thumb_nyxstone_instance = Nyxstone(
                    target_triple=thumb_triple,
                    cpu=cpu,
                    features=features,
                    immediate_style=immediate_style,
                )
                # The ARM-state instance must also come from the decode-capable
                # v7 spelling: nyxstone accepts the plain ``arm-`` tuple but
                # then fails core instructions (bx lr) mid-stream.
                nyxstone_instance = Nyxstone(
                    target_triple=arm_triple,
                    cpu=cpu,
                    features=features,
                    immediate_style=immediate_style,
                )
            except ValueError as e:
                LOG.warning(
                    f"Failed to initialize Thumb disassembler for '{thumb_triple}', "
                    f"ARM-mode fallback only: {e}"
                )
    arm32_mapping_modes = _arm32_mapping_symbol_modes(parsed_obj) if is_arm32 else {}
    # Call evidence grows during the worklist pass (a decoded function states
    # its targets' modes); pointer evidence is static, from data words. Both
    # only ever name functions the discovery pass already found.
    arm32_call_modes: dict[int, str] = {}
    arm32_pointer_modes: dict[int, str] = {}
    # Resolve MachO import slot/stub addresses once and surface them on the
    # metadata so the callgraph builder can classify these as external import
    # edges instead of misattributing them to internal range-containment nodes.
    if isinstance(parsed_obj, lief.MachO.Binary) and "import_call_addresses" not in metadata:
        metadata["import_call_addresses"] = build_macho_import_address_map(parsed_obj)
    addr_to_name_map = _build_addr_to_name_map(metadata, parsed_obj)
    all_func_addrs = []
    for func_list_key in FUNCTION_SYMBOLS:
        for func_entry in metadata.get(func_list_key, []):
            # ARM32 mapping symbols are mode labels, not function starts;
            # symtab buckets carry them, and letting them into this set
            # truncates the size-less windows at every literal pool.
            if is_arm32 and _ARM32_MAPPING_SYMBOL_RE.match(func_entry.get("name") or ""):
                continue
            addr_str = func_entry.get("address") or func_entry.get("rva_start")
            if addr_str:
                try:
                    addr = int(addr_str, 16)
                    # ARM32 identity is the aligned address: symbols carry
                    # the Thumb bit in st_value, resolved call targets do
                    # not, and mixing the two makes every Thumb callee look
                    # unknown to promotion and the window index.
                    all_func_addrs.append(addr & ~1 if is_arm32 else addr)
                except ValueError:
                    pass
    all_func_addrs_sorted = sorted(set(all_func_addrs))
    if is_arm32:
        arm32_pointer_modes = _arm32_data_pointer_modes(parsed_obj, set(all_func_addrs_sorted))
    # Call targets render as absolute virtual addresses, while stored function
    # addresses are image-relative for PE. Mach-O function metadata is
    # normalized to the virtual space where the list is built, so its
    # stored space *is* the virtual space and the rebase delta is zero. All
    # discovery work below happens in stored space, so executable ranges are
    # rebased once here.
    imagebase = 0
    if isinstance(parsed_obj, lief.PE.Binary):
        imagebase = int(parsed_obj.optional_header.imagebase)
    exec_ranges_true = executable_ranges(parsed_obj)
    exec_ranges_stored = [(start - imagebase, end - imagebase) for start, end in exec_ranges_true]
    addr_to_index = {addr: i for i, addr in enumerate(all_func_addrs_sorted)}
    base_delta = 0
    if isinstance(parsed_obj, lief.ELF.Binary):
        code_segment = None
        for seg in parsed_obj.segments:
            if seg.type == lief.ELF.Segment.TYPE.LOAD and seg.has(lief.ELF.Segment.FLAGS.X):
                code_segment = seg
                break
        if code_segment and all_func_addrs_sorted:
            min_func_addr = all_func_addrs_sorted[0]
            # The delta is a hypothesis that symbol addresses live in a foreign
            # space offset from LIEF's virtual addresses. It is only supported
            # when the lowest function address is not executable memory in its
            # own right: "lowest function above the X segment start" is the
            # normal layout of any binary whose first symbol is not exactly at
            # the segment start, and shifting those reads decodes a *different
            # function's* bytes (x86 decodes almost anything, so the wrong read
            # succeeds and the correct one is never tried).
            if code_segment.virtual_address != min_func_addr and not _addr_in_exec_ranges(
                min_func_addr, exec_ranges_true
            ):
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
        bucket = metadata.get(func_list_key, [])
        if is_arm32:
            bucket = [
                entry
                for entry in bucket
                if not _ARM32_MAPPING_SYMBOL_RE.match(entry.get("name") or "")
            ]
        all_funcs.extend(bucket)
    # A binary whose symbol + unwind discovery produced almost nothing gets a
    # prologue scan so stripped Go ELF binaries and export-less PEs still gain
    # a function set; dense binaries are left untouched.
    if len(all_func_addrs_sorted) < PROLOGUE_SCAN_MIN_FUNCTIONS:
        prologue_addrs = find_prologue_candidates(parsed_obj, arch_target, exec_ranges_stored)
        known_addr_set = set(all_func_addrs_sorted)
        new_addrs = [a for a in prologue_addrs if a not in known_addr_set]
        if new_addrs:
            LOG.debug(f"Prologue scan discovered {len(new_addrs)} candidate function starts.")
            all_func_addrs_sorted = sorted(known_addr_set | set(new_addrs))
            addr_to_index = {addr: i for i, addr in enumerate(all_func_addrs_sorted)}
            # Prologue discoveries feed the worklist directly; they surface in
            # metadata["discovered_functions"] after the loop, exactly like
            # call-site promotions, instead of mutating the function lists.
            all_funcs.extend(
                {
                    "name": f"sub_{a:x}",
                    "address": f"0x{a:x}",
                    "size": 0,
                    "discovered": "prologue",
                }
                for a in new_addrs
            )
    visited_addrs = set()
    # Named symbol entries first (stable): several buckets can claim one
    # address (a dynsym FUNC and a nameless unwind-table row), and after
    # ARM32 alignment merges them into one identity the first processed
    # entry's name wins - it must be the real symbol, not the sub_ twin.
    if is_arm32:
        all_funcs.sort(
            key=lambda entry: (
                0 if entry.get("name") and not str(entry.get("name")).startswith("sub_") else 1
            )
        )
    # Worklist instead of a plain list so direct-call promotion can append
    # newly discovered functions; initial entries keep their existing order.
    worklist: deque = deque(all_funcs)
    promoted_count = 0
    known_starts = list(all_func_addrs_sorted)
    # The arbiter's plausibility score needs membership tests, not order.
    known_start_set = set(known_starts)
    # Sorted, non-overlapping extents of known code: unwind tables contribute
    # exact per-function sizes up front, and every completed disassembly adds
    # its own. Promotion treats these as the ground truth for what is already
    # a function body, so interior call targets are never promoted.
    disassembled_spans: list[tuple[int, int]] = []
    for discovered in metadata.get("discovered_functions") or []:
        with contextlib.suppress(TypeError, ValueError):
            size = int(discovered.get("size") or 0)
            if size > 0:
                disassembled_spans.append(
                    (int(discovered["address"], 16), int(discovered["address"], 16) + size)
                )
    disassembled_spans.sort()
    # Merely invoking this method leads to more successful disassembly!
    memoryview(parsed_obj.write_to_bytes())
    while worklist:
        func_entry = worklist.popleft()
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
        # The raw address carries ARM32's Thumb parity evidence; identity,
        # windows and byte reads use the aligned address.
        arm32_raw_func_addr = original_func_addr
        if is_arm32:
            original_func_addr &= ~1
        if original_func_addr in visited_addrs:
            continue
        visited_addrs.add(original_func_addr)
        if not func_name:
            func_name = f"sub_{original_func_addr:x}"
        if isinstance(parsed_obj, lief.MachO.Binary) and _is_macos_system_symbol_name(func_name):
            continue
        func_addr = original_func_addr
        if (is_mips or is_arm32) and (func_addr & 1):
            func_addr = func_addr & ~1
        # ARM32: which instruction set state this function decodes in. A
        # mapping symbol naming a data island says the entry is not code at
        # all (a literal pool or jump table the symbol pipeline offered as a
        # function) and is skipped rather than decoded as garbage.
        arm32_mode = None
        arm32_data_spans: list[tuple[int, int]] = []
        arm32_section_modes: list[tuple[int, str]] = []
        if is_arm32:
            func_shndx = _arm32_section_for_address(parsed_obj, func_addr)
            if func_shndx is None and isinstance(parsed_obj, lief.ELF.Binary):
                # An exidx entry can name the inter-section padding after
                # .text; bytes in no section are not code and decoding them
                # reads into the neighbour section's stubs.
                LOG.debug(
                    f"Skipping '{func_name}' at {func_addr_str}: address lies in no section."
                )
                continue
            # Mapping labels are section-local; only this function's section
            # has a say in its modes and spans.
            arm32_section_modes = arm32_mapping_modes.get(func_shndx, [])
            # Synthetic sub_ names (the merge's readability rename for
            # nameless claims) are not symbol evidence: trusting them makes
            # even-aligned exidx rows decode as ARM and produces garbage.
            real_name = func_entry.get("name")
            if real_name and str(real_name).startswith("sub_"):
                real_name = None
            has_symbol = bool(real_name and not func_entry.get("discovered")) or bool(
                arm32_raw_func_addr & 1
            )
            arm32_mode, arm32_mode_source = _arm32_function_mode(
                arm32_raw_func_addr,
                arm32_section_modes,
                has_symbol=has_symbol,
                call_modes=arm32_call_modes,
                pointer_modes=arm32_pointer_modes,
            )
            if arm32_mode == "data":
                LOG.debug(
                    f"Skipping '{func_name}' at {func_addr_str}: mapping symbol marks a data island."
                )
                continue
        size_to_disasm = func_entry.get("size") or func_entry.get("length")
        has_exact_size = True
        if not isinstance(size_to_disasm, int) or size_to_disasm <= 0:
            current_index = addr_to_index.get(func_addr)
            if current_index is not None and current_index + 1 < len(all_func_addrs_sorted):
                next_func_addr = all_func_addrs_sorted[current_index + 1]
                size_to_disasm = next_func_addr - func_addr
            elif is_arm32 and func_entry.get("discovered") == "callsite":
                # An ARM32 promoted mid-function entry: window to the next
                # known start (promotions included), never the 4096-byte
                # blind window that swallows the following functions whole.
                # Other architectures keep the blind window their KPI
                # baselines were calibrated against (measured: bounding
                # them here cost PE 48 direct edges).
                next_index = bisect.bisect_right(known_starts, func_addr)
                if next_index < len(known_starts):
                    size_to_disasm = known_starts[next_index] - func_addr
                else:
                    size_to_disasm = 4096
                has_exact_size = False
            else:
                size_to_disasm = 4096
                has_exact_size = False
        if size_to_disasm <= 0:
            LOG.debug(f"Function '{func_name}' has a size of 0. Skipping.")
            continue
        func_addr_va = func_addr
        if isinstance(parsed_obj, lief.PE.Binary):
            func_addr_va = func_addr + imagebase
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
                    if sec.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE):
                        is_executable = True
                    break
        if not is_executable:
            LOG.debug(
                f"Address {func_addr_va_hex} for '{func_name}' is not in an executable section. Skipping disassembly."
            )
            continue
        rebased_bytes_mv = None
        try:
            result = parsed_obj.get_content_from_virtual_address(lief_lookup_va, size_to_disasm)
            if not isinstance(result, lief.lief_errors):
                rebased_bytes_mv = result
        except (SystemError, Exception):
            pass
        original_bytes_mv = None
        try:
            result = parsed_obj.get_content_from_virtual_address(func_addr_va, size_to_disasm)
            if not isinstance(result, lief.lief_errors):
                original_bytes_mv = result
        except (SystemError, Exception):
            pass
        if rebased_bytes_mv is None and original_bytes_mv is None:
            LOG.debug(
                f"Could not get bytes for function '{func_name}' at {func_addr_str} using any method."
            )
            continue
        rebased_bytes_list = rebased_bytes_mv.toreadonly() if rebased_bytes_mv is not None else []
        original_bytes_list = (
            original_bytes_mv.toreadonly() if original_bytes_mv is not None else []
        )
        try:
            instr_list = None
            used_arm32_mode = None
            arm32_line_modes: list[str | None] = []
            disassemblers_to_try = [(nyxstone_instance, arch_target)]
            if mips16_nyxstone_instance:
                disassemblers_to_try.append((mips16_nyxstone_instance, "MIPS16"))
            if micromips_nyxstone_instance:
                disassemblers_to_try.append((micromips_nyxstone_instance, "MicroMIPS"))
            # The byte source whose address is executable memory is tried
            # first. The rebased read only wins when the symbol address
            # itself is not executable (a genuinely foreign symbol address
            # space); when both or neither qualify, the symbol's own address
            # is the honest choice. With a spurious base_delta both can be
            # readable, and x86 decodes almost anything, so rebased-first
            # would silently win with another function's bytes.
            prefer_rebased = not _addr_in_exec_ranges(
                func_addr_va, exec_ranges_true
            ) and _addr_in_exec_ranges(lief_lookup_va, exec_ranges_true)
            bytes_sets = (
                [(rebased_bytes_list, "rebased"), (original_bytes_list, "original")]
                if prefer_rebased
                else [(original_bytes_list, "original"), (rebased_bytes_list, "rebased")]
            )
            if is_arm32 and arm32_thumb_nyxstone_instance:
                # ARM32 decodes through its own path: per-span modes (a
                # function may interleave ARM and Thumb islands), $d data
                # islands never disassembled, and recovery past words nyxstone
                # cannot decode instead of the count-based truncation.
                instr_list = []
                arm32_line_modes: list[str | None] = []
                arm32_spans = _arm32_code_spans(func_addr, size_to_disasm, arm32_section_modes)
                arm32_data_spans = _arm32_skipped_regions(func_addr, size_to_disasm, arm32_spans)
                for span_start, span_len in arm32_spans:
                    span_offset = span_start - func_addr
                    span_bytes = None
                    for byte_source, _source_name in bytes_sets:
                        source_len = _mem_bytes_len(byte_source)
                        if source_len is not None and span_offset < source_len:
                            span_bytes = byte_source[span_offset : span_offset + span_len]
                            break
                    if not span_bytes:
                        continue
                    span_va = func_addr_va + span_offset
                    span_mode = _arm32_mode_at(arm32_section_modes, span_start) or arm32_mode
                    if span_mode == "arm":
                        instance_order = [
                            (nyxstone_instance, "arm"),
                            (arm32_thumb_nyxstone_instance, "thumb"),
                        ]
                    else:
                        instance_order = [
                            (arm32_thumb_nyxstone_instance, "thumb"),
                            (nyxstone_instance, "arm"),
                        ]
                    span_instrs: list | None = None
                    span_used = None
                    if span_mode is None and len(instance_order) == 2:
                        # No stated mode: the arbiter decodes both states and
                        # keeps the one whose stream ends like a function
                        # (terminator beats lands-on-span-end; ties keep this
                        # order, Thumb first — the NDK armeabi-v7a default).
                        picked = _arm32_arbiter_pick(
                            [
                                (
                                    mode_name,
                                    _disassemble_arm32_span(instance, span_bytes, span_va),
                                )
                                for instance, mode_name in instance_order
                            ],
                            span_va,
                            span_len,
                            exec_ranges_true,
                            known_start_set,
                        )
                        if picked:
                            span_used, span_instrs = picked
                    else:
                        for instance, mode_name in instance_order:
                            candidate = _disassemble_arm32_span(instance, span_bytes, span_va)
                            if candidate:
                                span_instrs, span_used = candidate, mode_name
                                break
                    if span_instrs:
                        instr_list.extend(span_instrs)
                        arm32_line_modes.extend([span_used] * len(span_instrs))
                        if used_arm32_mode is None:
                            used_arm32_mode = span_used
                LOG.debug(
                    f"Disassembled '{func_name}' in {used_arm32_mode or 'unknown'} mode"
                    f" across {len(instr_list)} instructions."
                )
            else:
                # ARM32 starts are 2-byte aligned (Thumb) or 4-byte (ARM), so the
                # 1-3 byte probes that recover misaligned symbols elsewhere would
                # decode mid-instruction garbage here.
                for offset in range(1 if is_arm32 else 4):
                    original_len = _mem_bytes_len(original_bytes_list)
                    rebased_len = _mem_bytes_len(rebased_bytes_list)
                    if (
                        original_len is not None
                        and rebased_len is not None
                        and offset >= original_len
                        and offset >= rebased_len
                    ):
                        break
                    addr_to_try = func_addr_va + offset
                    for instance, mode_name in disassemblers_to_try:
                        for byte_source, source_name in bytes_sets:
                            source_len = _mem_bytes_len(byte_source)
                            if source_len is not None and offset >= source_len:
                                continue
                            bytes_to_try = byte_source[offset:]
                            instr_list = _try_disassemble(instance, bytes_to_try, addr_to_try)
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
            end_index = _find_function_end_index(instr_list, has_exact_size, arch_target)
            truncated_instr_list = instr_list[: end_index + 1] if end_index != -1 else instr_list
            if is_arm32 and arm32_line_modes:
                arm32_line_modes = arm32_line_modes[: len(truncated_instr_list)]
            if not truncated_instr_list:
                LOG.debug(
                    f"Instruction list for '{func_name}' became empty after truncation. Skipping."
                )
                continue
            # This function's instructions only. The disassembler reads a
            # fixed-size window that can run well past the function end, and
            # every consumer of this text (fuzzy hashing, stack-string
            # recovery, dispatch-table detection) would otherwise read
            # instructions belonging to later functions. instruction_count
            # and the CFG are already truncated the same way.
            plain_assembly_text = "\n".join(i.assembly for i in truncated_instr_list)
            lower_assembly = plain_assembly_text.lower()
            assembly_hash = hashlib.sha256(plain_assembly_text.encode("utf-8")).hexdigest()
            instruction_count = len(truncated_instr_list)
            # Per-line instruction lengths, aligned one-to-one with the
            # assembly lines. nyxstone hands these back with the text, so
            # this costs nothing to produce; it is what lets a metadata
            # reader reconstruct each line's address (prefix sum from the
            # CFG block's start VA) without re-disassembling. The arm64
            # fixed 4-byte stride needs no array, but exporting it keeps
            # every architecture on one address-reconstruction path.
            instruction_lengths = [len(i.bytes) for i in truncated_instr_list]
            parsed_instrs = [
                _parse_instruction_text(instr.assembly) for instr in truncated_instr_list
            ]
            instr_addresses = [instr.address for instr in truncated_instr_list]
            arm32_context = None
            if is_arm32:
                arm32_context = {
                    "modes": arm32_line_modes or None,
                    "default_mode": used_arm32_mode,
                    "literals": _arm32_extract_literals(
                        truncated_instr_list,
                        parsed_instrs,
                        arm32_line_modes,
                        used_arm32_mode,
                        parsed_obj,
                        base_delta,
                    ),
                }
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
                parsed_instrs,
                arm32_context if is_arm32 else None,
            )
            direct_calls, direct_call_targets = _resolve_direct_calls(
                truncated_instr_list,
                addr_to_name_map,
                arch_target,
                parsed_instrs,
                arm32_context if is_arm32 else None,
            )
            if is_arm32:
                _arm32_record_call_evidence(
                    truncated_instr_list,
                    parsed_instrs,
                    arm32_line_modes,
                    used_arm32_mode,
                    arm32_call_modes,
                )
            joined_mnemonics = "\n".join(instruction_mnemonics)
            instruction_hash = hashlib.sha256(joined_mnemonics.encode("utf-8")).hexdigest()
            has_system_call = any(
                syscall_pattern in lower_assembly for syscall_pattern in SYSCALL_INDICATORS
            )
            has_security_feature = any(
                feature_pattern in lower_assembly for feature_pattern in SECURITY_INDICATORS
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
            function_result = {
                "name": func_name,
                "address": func_addr_va_hex,
                "rvaOrAddress": func_addr_str,
                "assembly": plain_assembly_text,
                "assembly_hash": assembly_hash,
                "instruction_hash": instruction_hash,
                "instruction_count": instruction_count,
                "instruction_lengths": instruction_lengths,
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
            if is_arm32:
                # The instruction set state these bytes were decoded in
                # ("thumb"/"arm"), from the mapping symbol or the symbol's
                # st_value parity (docs/DISASSEMBLE.md); when neither source
                # states a mode, the fallback order's winning instance lands
                # here. Absent on every other architecture.
                function_result["instruction_mode"] = used_arm32_mode
                # What decided that mode: mapping_symbol, symbol_parity,
                # call (a decoded caller's bl/blx), data_pointer
                # (.init_array/.fini_array/relative-relocation words), or
                # arbiter (both-state decode comparison). Absent on every
                # other architecture.
                function_result["instruction_mode_source"] = (
                    (arm32_mode_source or "arbiter") if used_arm32_mode else None
                )
                if arm32_data_spans:
                    # $d islands skipped inside the extent. The
                    # instruction_lengths prefix sum no longer reconstructs
                    # line addresses on its own: these spans sit between the
                    # instructions, and a reader must add their sizes once
                    # the running offset passes each span's address.
                    function_result["data_spans"] = [
                        {"address": hex(region_start), "size": region_len}
                        for region_start, region_len in arm32_data_spans
                    ]
            disassembly_results[f"{func_addr_va_hex}::{func_name}"] = function_result
            # Structural block graph for the truncated instruction list. This
            # is computed after the flat metrics above and is additive: it
            # describes the function's shape without altering any of them.
            with contextlib.suppress(ValueError, IndexError, KeyError):
                function_cfg = build_function_cfg(
                    truncated_instr_list, parsed_instrs, arch_target, func_addr_va
                )
                if function_cfg:
                    disassembly_results[f"{func_addr_va_hex}::{func_name}"]["cfg"] = function_cfg
            if func_entry.get("discovered"):
                disassembly_results[f"{func_addr_va_hex}::{func_name}"]["discovered"] = func_entry[
                    "discovered"
                ]
            if promoted_count < MAX_PROMOTED_FUNCTIONS:
                last_instr = truncated_instr_list[-1]
                span_end = last_instr.address + len(last_instr.bytes) - func_addr_va + func_addr
                bisect.insort(disassembled_spans, (func_addr, span_end))
                promoted = _promote_call_targets(
                    direct_call_targets,
                    visited_addrs,
                    known_starts,
                    disassembled_spans,
                    exec_ranges_stored,
                    imagebase,
                    is_aarch64="aarch64" in arch_target.lower() or "arm64" in arch_target.lower(),
                )
                for promoted_addr in promoted:
                    # Promoted starts join known_starts: they bound each
                    # other's windows (a promoted mid-function entry runs to
                    # the next known thing) without shrinking the
                    # discovery-derived windows of the functions containing
                    # them.
                    bisect.insort(known_starts, promoted_addr)
                    worklist.append(
                        {
                            "name": f"sub_{promoted_addr:x}",
                            "address": f"0x{promoted_addr:x}",
                            "size": 0,
                            "discovered": "callsite",
                        }
                    )
                promoted_count += len(promoted)
            if inst_count == 0:
                num_success += 1
            if num_failures < 10 or num_success > 10:
                inst_count = 0
        except ValueError as e:
            LOG.debug(f"Failed to disassemble function '{func_name}' at {func_addr_va_hex}: {e}")
    if not disassembly_results:
        LOG.debug("Disassembly was not successful.")
    if promoted_count:
        # Surface call-site discoveries in the metadata record so downstream
        # consumers can tell symbol-derived functions from promoted ones.
        # For Mach-O the stored space is the virtual space, so the
        # unwind and callsite discovery records share one address space; PE
        # keeps its image-relative stored space.
        promoted_entries = [
            {
                "name": func.get("name", key.split("::", 1)[1]),
                "address": f"0x{int(key.split('::', 1)[0], 16) - imagebase:x}",
                "source": "callsite",
            }
            for key, func in disassembly_results.items()
            if isinstance(func, dict) and func.get("discovered") == "callsite"
        ]
        if promoted_entries:
            merged_records = list(metadata.get("discovered_functions") or []) + promoted_entries
            # Sort numerically; sorting the hex strings would interleave
            # addresses of different lengths lexicographically.
            merged_records.sort(key=lambda entry: int(entry.get("address", "0x0"), 16))
            metadata["discovered_functions"] = merged_records
    return disassembly_results
