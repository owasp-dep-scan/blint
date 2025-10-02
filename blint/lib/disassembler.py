from blint.logger import LOG
import lief
import hashlib
from blint.config import CRYPTO_INDICATORS, GPU_INDICATORS

try:
    from nyxstone import Nyxstone
    NYXSTONE_AVAILABLE = True
except ImportError:
    LOG.debug("Nyxstone not found. Disassembly features will be unavailable. Install with 'pip install blint[extended]'.")
    NYXSTONE_AVAILABLE = False

def disassemble_functions(parsed_obj, metadata, arch_target="aarch64", cpu="", features="", immediate_style=0):
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
    LOG.debug(f"Attempting to disassemble functions using Nyxstone for target: {arch_target}")
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
    if arch_target == "arm64":
        arch_target = "aarch64"

    try:
        nyxstone_instance = Nyxstone(target_triple=arch_target, cpu=cpu, features=features, immediate_style=immediate_style)
    except ValueError as e:
        LOG.error(f"Failed to initialize Nyxstone for target '{arch_target}': {e}")
        return disassembly_results

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
                             sec_identifier = sec.virtual_address
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
    for func_list_key in ["functions", "ctor_functions", "exception_functions", "unwind_functions", "exports"]:
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
            sec_obj = None
            sec_identifier = None

            if isinstance(parsed_obj, lief.ELF.Binary):
                 for sec in parsed_obj.sections:
                     if sec.virtual_address <= func_addr < sec.virtual_address + sec.size:
                         sec_obj = sec
                         sec_identifier = sec.virtual_address
                         break
            elif isinstance(parsed_obj, lief.PE.Binary):
                 for sec in parsed_obj.sections:
                     sec_start = sec.virtual_address + parsed_obj.optional_header.imagebase
                     if sec_start <= func_addr < sec_start + sec.virtual_size:
                         sec_obj = sec
                         sec_identifier = sec.virtual_address
                         break
            elif isinstance(parsed_obj, lief.MachO.Binary):
                 for seg in parsed_obj.segments:
                     if seg.file_offset <= func_addr - parsed_obj.imagebase < seg.file_offset + seg.file_size:
                         for sec_in_seg in seg.sections:
                             if sec_in_seg.virtual_address <= func_addr < sec_in_seg.virtual_address + sec_in_seg.size:
                                 sec_obj = sec_in_seg
                                 sec_identifier = sec_in_seg.virtual_address
                                 break
                         if sec_obj:
                             break

            if not sec_obj or not hasattr(sec_obj, 'content'):
                 LOG.debug(f"Could not find or access content of section for function '{func_name}' at {func_addr_str}.")
                 continue

            sec_content_bytes = sec_obj.content.tobytes()
            sec_start_in_file = sec_obj.virtual_address
            if isinstance(parsed_obj, lief.PE.Binary):
                 sec_start_in_file += parsed_obj.optional_header.imagebase

            func_offset_in_sec = func_addr - sec_start_in_file
            if func_offset_in_sec < 0 or func_offset_in_sec >= len(sec_content_bytes):
                 LOG.debug(f"Function address {func_addr_str} for '{func_name}' is outside section bounds.")
                 continue

            next_func_addr_in_sec = sec_start_in_file + len(sec_content_bytes)
            if sec_identifier in section_func_map:
                func_addrs_in_sec = section_func_map[sec_identifier]
                for addr in func_addrs_in_sec:
                    if addr > func_addr:
                        next_func_addr_in_sec = addr
                        break

            size_to_disasm = next_func_addr_in_sec - func_addr
            size_to_disasm = max(0, min(size_to_disasm, len(sec_content_bytes) - func_offset_in_sec))
            if size_to_disasm <= 0:
                 LOG.debug(f"No bytes to disassemble for function '{func_name}' at {func_addr_str} (size_to_disasm={size_to_disasm}).")
                 continue

            func_bytes = sec_content_bytes[func_offset_in_sec:func_offset_in_sec + size_to_disasm]
            func_bytes_list = list(func_bytes)
            try:
                has_indirect_call = False
                has_gpu_related = False
                plain_assembly_text = nyxstone_instance.disassemble(func_bytes_list, func_addr).strip()
                lower_assembly = plain_assembly_text.lower()
                assembly_hash = hashlib.sha256(plain_assembly_text.encode('utf-8')).hexdigest()
                instr_list = nyxstone_instance.disassemble_to_instructions(func_bytes_list, func_addr)
                instruction_count = len(instr_list)
                for instr in instr_list:
                    instr_assembly = instr.assembly
                    if instr_assembly.startswith('call ') or instr_assembly.startswith('jmp '):
                        parts = instr_assembly.split(None, 1)
                        if len(parts) > 1:
                            operand = parts[1].lower()
                            if operand.startswith(('r', 'e', 'a', 'b', 'c', 'd', 's', 'i', 'f', 'g', 'h')) or '[' in operand:
                                if not operand.startswith('0x') and not operand.replace('_', '').replace('.', '').replace('$', '').isalnum():
                                    has_indirect_call = True
                                    break
                # Check for system calls
                # x86/x86-64: syscall, int 0x80 (older Linux), sysenter
                # ARM/AArch64: svc #0 (supervisor call), smc #0
                # RISC-V: ecall
                has_system_call = any(syscall_pattern in lower_assembly for syscall_pattern in ['syscall', 'int 0x80', 'sysenter', 'svc #', 'smc #', 'ecall'])
                # Check for security features (Comprehensive list based on common features)
                # x86/x86-64: CET (Control-flow Enforcement Technology) uses endbr64/endbr32
                #              CET also uses setssbsy, clrssbsy instructions (less common in user code)
                #              IBT (Indirect Branch Tracking) uses enqcmd, enqpad instructions (often part of CET context)
                #              CET also uses rdpkru, wrpkru (MPX related, less common now)
                # ARM: BTI (Branch Target Identification) uses hint instructions like hint #0x7e (for bti c), hint #0x7f (for bti j)
                #      PAC (Pointer Authentication) uses pac*, aut*, xpacd, xpaci, pacia*, pacda*, etc.
                #      MTE (Memory Tagging Extension) uses gmi, irg, subg, addg, ldg, stg, stzg, st2g, st3g, st4g, etc.
                has_security_feature = any(feature_pattern in lower_assembly for feature_pattern in ['endbr64', 'endbr32', 'setssbsy', 'clrssbsy', 'enqcmd', 'enqpad', 'hint #0x7e', 'hint #0x7f', 'pacibsp', 'paciasp', 'autibsp', 'autiasp', 'pacib1', 'pacibz', 'paciasp', 'paciasz', 'autib1', 'autibz', 'autiasp', 'autiaz', 'gmi', 'irg', 'subg', 'addg', 'ldg', 'stg', 'stzg', 'st2g', 'st3g', 'st4g'])
                has_crypto_call = any(indicator in lower_assembly for indicator in CRYPTO_INDICATORS)
                has_gpu_call = any(indicator in lower_assembly for indicator in GPU_INDICATORS)
                disassembly_results[func_name] = {
                    "address": func_addr_str,
                    "instruction_count": instruction_count,
                    "assembly": plain_assembly_text,
                    "assembly_hash": assembly_hash,
                    "has_indirect_call": has_indirect_call,
                    "has_system_call": has_system_call,
                    "has_security_feature": has_security_feature,
                    "has_crypto_call": has_crypto_call,
                    "has_gpu_call": has_gpu_call,
                }
            except ValueError as e:
                LOG.debug(f"Failed to disassemble function '{func_name}' at {func_addr_str} (range: {func_addr_str} to {hex(next_func_addr_in_sec)}, size: {size_to_disasm} bytes): {e}")

    LOG.debug(f"Disassembly complete for {len(disassembly_results)} functions.")
    return disassembly_results
