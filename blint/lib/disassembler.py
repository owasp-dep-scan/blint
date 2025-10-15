from blint.logger import LOG
import lief
import hashlib
import re
from blint.config import CRYPTO_INDICATORS, GPU_INDICATORS, SECURITY_INDICATORS, SYSCALL_INDICATORS, IMPLICIT_REGS_X86, IMPLICIT_REGS_X64

OPERAND_DELIMITERS_PATTERN = re.compile(r'[^a-zA-Z0-9_]+')

ARITH_INST = ['add', 'sub', 'imul', 'mul', 'div', 'idiv', 'inc', 'dec', 'neg', 'not', 'and', 'or', 'xor', 'adc', 'sbb', 'xadd', 'cmpxchg']
SHIFT_INST = ['shl', 'shr', 'sal', 'sar', 'rol', 'ror', 'rcl', 'rcr', 'psll', 'psrl', 'psra', 'vpsll', 'vpsrl', 'vpsra']
CONDITIONAL_JMP_INST = ['je', 'jne', 'jz', 'jnz', 'jg', 'jge', 'jl', 'jle', 'ja', 'jae', 'jb', 'jbe',
                'jp', 'jnp', 'jo', 'jno',
                'js', 'jns', 'loop', 'loopz', 'loopnz', 'jcxz', 'jecxz', 'jrcxz']
COMMON_REGS_64 = {'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
                  'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'}
COMMON_REGS_32 = {'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp',
                  'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d'}
COMMON_REGS_16 = {'ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp',
                  'r8w', 'r9w', 'r10w', 'r11w', 'r12w', 'r13w', 'r14w', 'r15w'}
COMMON_REGS_8l = {'al', 'bl', 'cl', 'dl', 'sil', 'dil', 'bpl', 'spl',
                  'r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b'}
COMMON_REGS_8h = {'ah', 'bh', 'ch', 'dh'}

TERMINATING_INST = {'ret', 'retn', 'retf', 'iret', 'iretd', 'iretq'}
UNCONDITIONAL_JMP_INST = {'jmp', 'jmpq', 'jmpl'}
READ_WRITE_BOTH_OPS_INST = {'xadd', 'cmpxchg', 'cmpxchg8b', 'cmpxchg16b'}
BIT_MANIPULATION_INST = {'bt', 'bts', 'bsf', 'bsr', 'btr', 'btc', 'popcnt', 'lzcnt', 'tzcnt'}
READ_WRITE_ONE_OP_INST = {'inc', 'dec', 'not', 'neg', 'rol', 'ror', 'rcl', 'rcr', 'shl', 'shr', 'sal', 'sar'}
WRITE_DST_READ_SRC_INST = {
    'add', 'adc', 'sub', 'sbb', 'imul', 'and', 'or', 'xor',
    'mov', 'movzx', 'movsx', 'movsxd', 'lea',
    'cmove', 'cmovne', 'cmovz', 'cmovnz', 'cmova', 'cmovnbe', 'cmovae', 'cmovnb',
    'cmovb', 'cmovnae', 'cmovbe', 'cmovna', 'cmovg', 'cmovnle', 'cmovge', 'cmovnl',
    'cmovl', 'cmovnge', 'cmovle', 'cmovng', 'cmovc', 'cmovnc', 'cmovo', 'cmovno',
    'cmovs', 'cmovns', 'cmovp', 'cmovpe', 'cmovnp', 'cmovpo'
}

SEGMENT_REGS = {'cs', 'ds', 'es', 'fs', 'gs', 'ss'}
FPU_REGS = {f'st({i})' for i in range(8)}
MMX_REGS = {f'mm{i}' for i in range(8)}
XMM_REGS = {f'xmm{i}' for i in range(32)}
YMM_REGS = {f'ymm{i}' for i in range(32)}
ZMM_REGS = {f'zmm{i}' for i in range(32)}
ALL_SIMD_REGS = FPU_REGS | MMX_REGS | XMM_REGS | YMM_REGS | ZMM_REGS
ALL_REGS = COMMON_REGS_64 | COMMON_REGS_32 | COMMON_REGS_16 | COMMON_REGS_8l | COMMON_REGS_8h | ALL_SIMD_REGS | SEGMENT_REGS
SORTED_ALL_REGS = sorted(ALL_REGS, key=len, reverse=True)

WIN_X64_VOLATILE_REGS = frozenset({'rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11'})
SYSV_X64_VOLATILE_REGS = frozenset({'rax', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11'})
CDECL_X86_VOLATILE_REGS = frozenset({'eax', 'ecx', 'edx'})
X64_RETURN_REGS = frozenset({'rax'})
X86_RETURN_REGS = frozenset({'eax'})

try:
    from nyxstone import Nyxstone
    NYXSTONE_AVAILABLE = True
except ImportError:
    LOG.debug("Nyxstone not found. Disassembly features will be unavailable. Install with 'pip install blint[extended]'.")
    NYXSTONE_AVAILABLE = False

def _get_implicit_regs_map(arch_target):
    """Selects the appropriate implicit registers map based on architecture."""
    if "64" in arch_target:
        return IMPLICIT_REGS_X64
    return IMPLICIT_REGS_X86

def _find_function_end_index(instr_list):
    """
    Scans a list of instructions to find the most likely end of a function.
    Returns the index of the last instruction belonging to the function.
    """
    if not instr_list:
        return -1
    for i, instr in enumerate(instr_list):
        mnemonic = instr.assembly.split(None, 1)[0].lower()
        if mnemonic in TERMINATING_INST:
            if i + 1 < len(instr_list):
                next_mnemonic = instr_list[i+1].assembly.split(None, 1)[0].lower()
                if next_mnemonic in ['int3', 'nop']:
                    return i
            return i
        if mnemonic in UNCONDITIONAL_JMP_INST:
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

def _get_function_ranges(parsed_obj, metadata):
    """Calculates the address ranges for each function based on the next function or section end."""
    section_func_map = {}
    for func_list_key in ["functions", "ctor_functions", "exception_functions", "unwind_functions", "exports"]:
        for func_entry in metadata.get(func_list_key, []):
            func_addr_str = func_entry.get("address", "")
            if func_addr_str:
                try:
                    func_addr = int(func_addr_str, 16)
                except ValueError:
                    continue
                sec_identifier = None
                if isinstance(parsed_obj, lief.ELF.Binary):
                     for sec in parsed_obj.sections:
                         if sec.virtual_address <= func_addr < sec.virtual_address + sec.size:
                             sec_identifier = sec.virtual_address
                             break
                elif isinstance(parsed_obj, lief.PE.Binary):
                     for sec in parsed_obj.sections:
                         sec_start = sec.virtual_address + parsed_obj.optional_header.imagebase
                         if sec_start <= func_addr < sec_start + sec.virtual_size:
                             sec_identifier = sec.virtual_address + parsed_obj.optional_header.imagebase
                             break
                elif isinstance(parsed_obj, lief.MachO.Binary):
                     for seg in parsed_obj.segments:
                         if seg.file_offset <= func_addr - parsed_obj.imagebase < seg.file_offset + seg.file_size:
                             for sec_in_seg in seg.sections:
                                 if sec_in_seg.virtual_address <= func_addr < sec_in_seg.virtual_address + sec_in_seg.size:
                                     sec_identifier = sec_in_seg.virtual_address
                                     break
                             if sec_identifier:
                                 break
                if sec_identifier is not None:
                    if sec_identifier not in section_func_map:
                        section_func_map[sec_identifier] = []
                    section_func_map[sec_identifier].append(func_addr)
    for addr_list in section_func_map.values():
        addr_list.sort()
    return section_func_map

def _build_section_lookup(parsed_obj):
    """
    Creates a sorted list of (start_va, size, section_obj) for fast lookups.
    """
    sections = []
    if not hasattr(parsed_obj, 'sections'):
        return []

    for sec in parsed_obj.sections:
        start_va = sec.virtual_address
        size = sec.virtual_size if hasattr(sec, 'virtual_size') else sec.size
        if isinstance(parsed_obj, lief.PE.Binary):
            start_va += parsed_obj.optional_header.imagebase
        sections.append((start_va, size, sec))
    sections.sort(key=lambda s: s[0])
    return sections

def _find_section_object(func_addr_va, section_lookup):
    """
    Finds the section object for a function VA using the pre-built sorted list.
    """
    for start_va, size, sec_obj in section_lookup:
        if start_va <= func_addr_va < start_va + size:
            return sec_obj
    return None

def _get_disasm_range(func_addr, sec_obj, parsed_obj, section_func_map):
    """Calculates the start offset and size to disassemble for a function."""
    if not sec_obj or not hasattr(sec_obj, 'content'):
         return None, None, None
    sec_content_bytes = sec_obj.content.tobytes()
    sec_start_in_file = sec_obj.virtual_address
    if isinstance(parsed_obj, lief.PE.Binary):
         sec_start_in_file += parsed_obj.optional_header.imagebase
         func_addr_va = func_addr + parsed_obj.optional_header.imagebase
         func_offset_in_sec = func_addr_va - sec_start_in_file
    else:
         func_addr_va = func_addr
         func_offset_in_sec = func_addr - sec_start_in_file

    if func_offset_in_sec < 0 or func_offset_in_sec >= len(sec_content_bytes):
         return None, None, None
    next_func_addr_in_sec = sec_start_in_file + len(sec_content_bytes)
    sec_identifier = sec_obj.virtual_address if isinstance(parsed_obj, (lief.ELF.Binary, lief.PE.Binary)) else sec_obj.virtual_address
    if sec_identifier in section_func_map:
        func_addrs_in_sec = section_func_map[sec_identifier]
        for addr in func_addrs_in_sec:
            if addr > func_addr:
                next_func_addr_in_sec = addr + parsed_obj.optional_header.imagebase if isinstance(parsed_obj, lief.PE.Binary) else addr
                break
    size_to_disasm = next_func_addr_in_sec - func_addr_va
    size_to_disasm = max(0, min(size_to_disasm, len(sec_content_bytes) - func_offset_in_sec))
    return func_offset_in_sec, size_to_disasm, sec_content_bytes

def extract_regs_from_operand(op):
    found_regs = set()
    if not op:
        return found_regs
    potential_tokens = filter(None, OPERAND_DELIMITERS_PATTERN.split(op.lower()))
    for token in potential_tokens:
        if token in SORTED_ALL_REGS:
            found_regs.add(token)
    return found_regs

def _extract_register_usage(instr_assembly, parsed_obj=None, arch_target=""):
    """
    Performs a first-pass analysis to extract approximate register read/write usage
    from the instruction assembly string.
    """
    implicit_regs_map = _get_implicit_regs_map(arch_target)
    regs_read = set()
    regs_written = set()
    if not instr_assembly:
        return list(regs_read), list(regs_written)
    first_space_idx = instr_assembly.find(' ')
    if first_space_idx == -1:
        mnemonic = instr_assembly.strip().lower().rstrip(':')
        operands = []
    else:
        mnemonic_part = instr_assembly[:first_space_idx].strip().lower().rstrip(':')
        operands_part = instr_assembly[first_space_idx + 1:].strip()
        mnemonic = mnemonic_part.rstrip(':')
        comma_idx = operands_part.find(',')
        if comma_idx != -1:
            op1 = operands_part[:comma_idx].strip()
            op2 = operands_part[comma_idx + 1:].strip()
            operands = [op1, op2]
        else:
            operands = [operands_part] if operands_part else []
    num_operands = len(operands)
    if num_operands > 0:
        operands = [op.rstrip(',') for op in operands]

    has_rep_prefix = False
    if mnemonic.startswith(('rep', 'repe', 'repne')):
        has_rep_prefix = True
        mnemonic = mnemonic[4:] if len(mnemonic) > 3 and mnemonic[3] == 'e' else mnemonic[3:]

    if mnemonic in implicit_regs_map:
        regs_read.update(implicit_regs_map[mnemonic].get('read', set()))
        regs_written.update(implicit_regs_map[mnemonic].get('write', set()))

    if has_rep_prefix:
        is_64bit = "64" in arch_target
        counter_reg = 'rcx' if is_64bit else 'ecx'
        regs_read.add(counter_reg)
        regs_written.add(counter_reg)

    if mnemonic in WRITE_DST_READ_SRC_INST or mnemonic.startswith('cmov'):
        if num_operands >= 2:
            dst_regs = extract_regs_from_operand(operands[0].lower())
            src_regs = extract_regs_from_operand(operands[1].lower())
            regs_written.update(dst_regs)
            regs_read.update(src_regs)
            if mnemonic not in ['mov', 'movzx', 'movsx', 'movsxd', 'lea'] and not mnemonic.startswith('cmov'):
                regs_read.update(dst_regs)

    elif mnemonic in READ_WRITE_BOTH_OPS_INST:
        if num_operands >= 2:
            op1_regs = extract_regs_from_operand(operands[0].lower())
            op2_regs = extract_regs_from_operand(operands[1].lower())
            regs_read.update(op1_regs)
            regs_written.update(op1_regs)
            regs_read.update(op2_regs)
            if mnemonic != 'cmpxchg':
                regs_written.update(op2_regs)

    elif mnemonic in BIT_MANIPULATION_INST:
        if num_operands >= 2:
            dst_regs = extract_regs_from_operand(operands[0].lower())
            src_regs = extract_regs_from_operand(operands[1].lower())
            regs_written.update(dst_regs)
            regs_read.update(src_regs)
            if mnemonic not in ['bsf', 'bsr', 'lzcnt', 'tzcnt', 'popcnt']:
                regs_read.update(dst_regs)

    elif mnemonic in READ_WRITE_ONE_OP_INST:
        if num_operands >= 1:
            op_regs = extract_regs_from_operand(operands[0].lower())
            regs_read.update(op_regs)
            regs_written.update(op_regs)

    elif mnemonic in ['cmp', 'test']:
        if num_operands >= 2:
            regs_read.update(extract_regs_from_operand(operands[0].lower()))
            regs_read.update(extract_regs_from_operand(operands[1].lower()))

    elif mnemonic in ['push', 'pop']:
        is_64bit = "64" in arch_target
        stack_reg = 'rsp' if is_64bit else 'esp'
        regs_read.add(stack_reg)
        regs_written.add(stack_reg)
        if num_operands >= 1:
            op_regs = extract_regs_from_operand(operands[0].lower())
            if mnemonic == 'push':
                regs_read.update(op_regs)
            else:
                regs_written.update(op_regs)

    elif mnemonic == 'call':
        volatile_regs = _get_abi_volatile_regs(parsed_obj, arch_target)
        regs_written.update(volatile_regs)
        if num_operands >= 1:
            op = operands[0].lower()
            if not op.startswith('0x') and not op.isdigit():
                 op_regs = extract_regs_from_operand(op)
                 regs_read.update(op_regs)

    elif mnemonic in TERMINATING_INST:
        is_64bit = "64" in arch_target or "aarch64" in arch_target
        if is_64bit:
            regs_read.update(X64_RETURN_REGS)
        else:
            regs_read.update(X86_RETURN_REGS)
        stack_reg = 'rsp' if is_64bit else 'esp'
        regs_read.add(stack_reg)
        regs_written.add(stack_reg)

    elif mnemonic.startswith('j'):
        if num_operands >= 1:
            op = operands[0].lower()
            if not op.startswith('0x') and not op.isdigit():
                op_regs = extract_regs_from_operand(op)
                regs_read.update(op_regs)

    elif mnemonic == 'xchg':
        if num_operands >= 2:
            op1_regs = extract_regs_from_operand(operands[0].lower())
            op2_regs = extract_regs_from_operand(operands[1].lower())
            regs_read.update(op1_regs)
            regs_written.update(op1_regs)
            regs_read.update(op2_regs)
            regs_written.update(op2_regs)

    if mnemonic in ['mul', 'imul', 'div', 'idiv'] and num_operands == 1:
        op_regs = extract_regs_from_operand(operands[0].lower())
        regs_read.update(op_regs)

    return list(regs_read), list(regs_written)

def _analyze_instructions(instr_list, func_addr, next_func_addr_in_sec, instr_addresses, parsed_obj=None, arch_target=""):
    """Analyzes the list of instructions for metrics, loops, and indirect calls."""
    instruction_mnemonics = []
    instruction_metrics = {
        "call_count": 0,
        "conditional_jump_count": 0,
        "xor_count": 0,
        "shift_count": 0,
        "arith_count": 0,
        "ret_count": 0,
        "jump_count": 0,
        "simd_fpu_count": 0
    }
    has_indirect_call = False
    has_loop = False
    all_regs_read = set()
    all_regs_written = set()
    used_simd_reg_types = set()
    instructions_with_registers = []
    for instr in instr_list:
        instr_assembly = instr.assembly
        mnemonic = instr.assembly.split(None, 1)[0].lower()
        instruction_mnemonics.append(mnemonic)
        if mnemonic == 'call':
            instruction_metrics["call_count"] += 1
        elif mnemonic in CONDITIONAL_JMP_INST:
            instruction_metrics["conditional_jump_count"] += 1
            parts = instr_assembly.split()
            if len(parts) >= 2:
                target_part = parts[1]
                if target_part.startswith('0x'):
                    try:
                        target_addr = int(target_part, 16)
                        if func_addr <= target_addr < next_func_addr_in_sec and target_addr < instr.address and target_addr in instr_addresses:
                            has_loop = True
                    except ValueError:
                        continue
        elif mnemonic == 'xor':
            instruction_metrics["xor_count"] += 1
        elif mnemonic in SHIFT_INST:
            instruction_metrics["shift_count"] += 1
        elif mnemonic in ARITH_INST:
            instruction_metrics["arith_count"] += 1
        elif mnemonic == 'ret':
            instruction_metrics["ret_count"] += 1
        elif mnemonic in ['jmp', 'jmpq', 'jmpl']:
            instruction_metrics["jump_count"] += 1
        if instr_assembly.startswith(('call ', 'jmp ')):
            parts = instr_assembly.split(None, 1)
            if len(parts) > 1:
                operand = parts[1].lower().strip()
                if operand.startswith('[') and operand.endswith(']'):
                    has_indirect_call = True
                elif any(operand.startswith(reg) for reg in SORTED_ALL_REGS):
                    if operand.isalnum() or '_' in operand:
                         has_indirect_call = True
        regs_read, regs_written = _extract_register_usage(instr_assembly, parsed_obj, arch_target)
        all_instr_regs = set(regs_read) | set(regs_written)
        is_simd_fpu = False
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
        instructions_with_registers.append({
            "regs_read": regs_read,
            "regs_written": regs_written
        })
        instruction_metrics["unique_regs_read_count"] = len(all_regs_read)
        instruction_metrics["unique_regs_written_count"] = len(all_regs_written)
    return instruction_metrics, instruction_mnemonics, has_indirect_call, has_loop, list(all_regs_read), list(all_regs_written), instructions_with_registers, list(used_simd_reg_types)

def _build_addr_to_name_map(metadata):
    """Builds a lookup map from address (int) to name from metadata functions."""
    addr_to_name_map = {}
    for func_list_key in ["functions", "ctor_functions", "exception_functions", "unwind_functions", "exports"]:
        for func_entry in metadata.get(func_list_key, []):
            addr_str = func_entry.get("address", "")
            name = func_entry.get("name", "")
            if addr_str and name:
                try:
                    addr_int = int(addr_str, 16)
                    addr_to_name_map[addr_int] = name
                except ValueError:
                    continue
    return addr_to_name_map

def _resolve_direct_calls(instr_list, addr_to_name_map):
    """Identifies direct calls in instructions and resolves target addresses to function names.
    Handles both immediate absolute addresses (0x...) and relative offsets."""
    potential_callees = []
    for instr in instr_list:
        instr_assembly = instr.assembly
        if instr_assembly.startswith('call '):
            parts = instr_assembly.split(None, 1)
            if len(parts) > 1:
                operand = parts[1]
                target_addr = None
                if operand.startswith('0x'):
                    try:
                        target_addr = int(operand, 16)
                    except ValueError:
                        continue
                elif operand.isdigit():
                    target_addr = operand
                elif operand.startswith(('+', '-')):
                     offset = int(operand, 10)
                     target_addr = instr.address + offset
                if target_addr is not None:
                    target_name = addr_to_name_map.get(target_addr)
                    if target_name:
                        potential_callees.append(target_name)
    return potential_callees

def _classify_function(instruction_metrics, instruction_count, plain_assembly_text, has_system_call, has_indirect_call):
    """Classifies the function based on metrics and other flags."""
    function_type = ""
    if instruction_metrics["jump_count"] > 0 and instruction_count <= 5 and all(mnem in ['jmp', 'push', 'sub'] for mnem in [i.split(None, 1)[0].lower() for i in plain_assembly_text.split('\n') if i.strip()]):
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

def disassemble_functions(parsed_obj, metadata, arch_target="", cpu="", features="", immediate_style=0):
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
              Structure:
              {
                "function_name_or_address": {
                   "assembly": "disassembled text",
                   "assembly_hash": "sha256_hash_of_assembly_text",
                   "instructions": [
                     {
                       "address": 0x1234,
                       "assembly": "mov rax, rbx",
                       "bytes": [0x48, 0x89, 0xd8],
                       "assembly_hash": "sha256_hash_of_instruction_assembly_string"
                     },
                     ...
                   ]
                },
                ...
              }
    """
    disassembly_results = {}
    if not NYXSTONE_AVAILABLE:
        LOG.debug("Nyxstone is not available. Cannot perform disassembly.")
        return disassembly_results
    cpu_type = metadata.get("cpu_type", "").lower()
    machine_type = metadata.get("machine_type", "").lower()
    if cpu_type and cpu_type != arch_target:
        arch_target = cpu_type
    elif machine_type and machine_type != arch_target:
        arch_target = machine_type
    if arch_target == "arm64" or (metadata.get("binary_type", "") == "MachO" and not arch_target):
        arch_target = "aarch64"
    if not arch_target:
        arch_target = "x86_64"
    try:
        LOG.debug(f"Attempting to disassemble functions using Nyxstone for target: {arch_target}")
        nyxstone_instance = Nyxstone(target_triple=arch_target, cpu=cpu, features=features, immediate_style=immediate_style)
    except ValueError as e:
        LOG.error(f"Failed to initialize Nyxstone for target '{arch_target}': {e}")
        return disassembly_results
    section_func_map = _get_function_ranges(parsed_obj, metadata)
    addr_to_name_map = _build_addr_to_name_map(metadata)
    section_lookup = _build_section_lookup(parsed_obj)
    # Disassembling all instructions for PE binaries is quite fiddly
    inst_count = 0
    num_failures = 0
    num_success = 0
    # Function attributes to inspect
    function_attrs = ["functions", "ctor_functions", "exception_functions", "unwind_functions", "exports"]
    if metadata.get("exe_type", "") in ("gobinary",):
        function_attrs.append("symtab_symbols")
    if metadata.get("exe_type", "") in ("dotnetbinary",):
        function_attrs.append("imports")
    for func_list_key in function_attrs:
        for func_entry in metadata.get(func_list_key, []):
            func_name = func_entry.get("name", "unknown_func")
            func_addr_str = func_entry.get("address", "")
            if not func_addr_str:
                LOG.debug(f"Skipping function '{func_name}' as no address is available.")
                continue
            try:
                func_addr = int(func_addr_str, 16)
            except ValueError:
                LOG.debug(f"Could not parse address '{func_addr_str}' for function '{func_name}'. Skipping.")
                continue
            if isinstance(parsed_obj, lief.PE.Binary):
                func_addr_va = func_addr + parsed_obj.optional_header.imagebase
            else:
                func_addr_va = func_addr
            sec_obj = _find_section_object(func_addr_va, section_lookup)
            func_offset_in_sec, size_to_disasm, sec_content_bytes = _get_disasm_range(func_addr, sec_obj, parsed_obj, section_func_map)
            if func_offset_in_sec is None or size_to_disasm is None or sec_content_bytes is None:
                 LOG.debug(f"Could not determine disassembly range for function '{func_name}' at {func_addr_str}.")
                 continue
            if size_to_disasm <= 0:
                 LOG.debug(f"size_to_disasm is zero for function '{func_name}' at {func_addr_str}.")
                 continue
            func_bytes = sec_content_bytes[func_offset_in_sec:func_offset_in_sec + size_to_disasm]
            if not func_bytes:
                LOG.debug(f"'{func_name}' is empty.")
                continue
            func_bytes_list = list(func_bytes)
            func_addr_va_hex = hex(func_addr_va)
            try:
                plain_assembly_text = ""
                instr_list = []
                try:
                    instr_list = nyxstone_instance.disassemble_to_instructions(func_bytes_list, func_addr_va, inst_count)
                    plain_assembly_text = nyxstone_instance.disassemble(func_bytes_list, func_addr_va, inst_count).strip()
                except ValueError:
                    num_failures += 1
                    # Retry by reducing the instructions count
                    if inst_count == 0:
                        inst_count = 10
                        instr_list = nyxstone_instance.disassemble_to_instructions(func_bytes_list, func_addr_va, inst_count)
                        plain_assembly_text = nyxstone_instance.disassemble(func_bytes_list, func_addr_va, inst_count).strip()
                end_index = _find_function_end_index(instr_list)
                if end_index != -1:
                    truncated_instr_list = instr_list[:end_index + 1]
                else:
                    truncated_instr_list = []
                if not truncated_instr_list:
                    LOG.debug(f"Could not find valid instructions for function '{func_name}'.")
                    continue
                lower_assembly = plain_assembly_text.lower()
                assembly_hash = hashlib.sha256(plain_assembly_text.encode('utf-8')).hexdigest()
                instruction_count = len(truncated_instr_list)
                instr_addresses = [instr.address for instr in truncated_instr_list]
                instruction_metrics, instruction_mnemonics, has_indirect_call, has_loop, regs_read, regs_written, instructions_with_registers, used_simd_reg_types = _analyze_instructions(truncated_instr_list, func_addr, func_addr + size_to_disasm, instr_addresses, parsed_obj, arch_target)
                direct_calls = _resolve_direct_calls(truncated_instr_list, addr_to_name_map)
                joined_mnemonics = "\n".join(instruction_mnemonics)
                instruction_hash = hashlib.sha256(joined_mnemonics.encode('utf-8')).hexdigest()
                has_system_call = any(syscall_pattern in lower_assembly for syscall_pattern in SYSCALL_INDICATORS)
                has_security_feature = any(feature_pattern in lower_assembly for feature_pattern in SECURITY_INDICATORS)
                has_crypto_call = any(indicator in lower_assembly for indicator in CRYPTO_INDICATORS)
                has_gpu_call = any(indicator in lower_assembly for indicator in GPU_INDICATORS)
                function_type = _classify_function(instruction_metrics, instruction_count, plain_assembly_text, has_system_call, has_indirect_call)
                disassembly_results[f"{func_addr_va_hex}::{func_name}"] = {
                    "name": func_name,
                    "address": func_addr_va_hex,
                    "assembly": plain_assembly_text,
                    "assembly_hash": assembly_hash,
                    "instruction_hash": instruction_hash,
                    "instruction_count": instruction_count,
                    "instruction_metrics": instruction_metrics,
                    "direct_calls": direct_calls,
                    "has_indirect_call": has_indirect_call,
                    "has_system_call": has_system_call,
                    "has_security_feature": has_security_feature,
                    "has_crypto_call": has_crypto_call,
                    "has_gpu_call": has_gpu_call,
                    "has_loop": has_loop,
                    "regs_read": regs_read,
                    "regs_written": regs_written,
                    "used_simd_reg_types": used_simd_reg_types,
                    "instructions_with_registers": instructions_with_registers,
                    "function_type": function_type
                }
                if inst_count == 0:
                    num_success += 1
                # Should we go back to full disassembly again
                if num_failures < 10 or num_success > 10:
                    inst_count = 0
            except ValueError as e:
                LOG.debug(f"Failed to disassemble function '{func_name}' at {func_addr_va_hex}: {e}")
    if not disassembly_results:
        LOG.debug("Disassembly was not successful.")
    return disassembly_results
