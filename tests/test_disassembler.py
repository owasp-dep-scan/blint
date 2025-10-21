import pytest
import lief
from unittest.mock import MagicMock

from blint.lib.disassembler import _extract_register_usage, _analyze_instructions, _classify_function


def test_extract_register_usage_mov():
    instr_asm = "mov rax, rbx"
    regs_read, regs_written = _extract_register_usage(instr_asm)
    assert set(regs_read) == {"rbx"}
    assert set(regs_written) == {"rax"}

def test_extract_register_usage_arith():
    instr_asm = "add rax, rcx"
    regs_read, regs_written = _extract_register_usage(instr_asm)
    assert set(regs_read) == {"rax", "rcx"}
    assert set(regs_written) == {"rax"}

def test_extract_register_usage_cmp():
    instr_asm = "cmp rdi, 5"
    regs_read, regs_written = _extract_register_usage(instr_asm, None, 'x86_64')
    assert set(regs_read) == {"rdi"}
    assert set(regs_written) == set()

def test_extract_register_usage_lea():
    instr_asm = "lea r8, [rbx + r9 * 2 + 10]"
    regs_read, regs_written = _extract_register_usage(instr_asm)
    assert set(regs_read) == {"rbx", "r9"}
    assert set(regs_written) == {"r8"}

def test_extract_register_usage_push_pop():
    instr_asm_push = "push rax"
    regs_read_push, regs_written_push = _extract_register_usage(instr_asm_push, {}, "x86_64")
    assert "rsp" in regs_read_push
    assert "rsp" in regs_written_push
    instr_asm_pop = "pop rbx"
    regs_read_pop, regs_written_pop = _extract_register_usage(instr_asm_pop, {}, "x86_64")
    assert "rsp" in regs_read_pop
    assert "rsp" in regs_written_pop

def test_extract_register_usage_call():
    instr_asm = "call 0x123456"
    regs_read, regs_written = _extract_register_usage(instr_asm, {}, "x86_64")
    cc_regs = {'rsi', 'rcx', 'r9', 'r10', 'rax', 'rdi', 'r8', 'r11', 'rdx'}
    assert set(regs_written) == cc_regs
    assert set(regs_read) == set()
    instr_asm_indirect = "blr x12"
    regs_read_indirect, regs_written_indirect = _extract_register_usage(instr_asm_indirect, {}, "aarch64")
    assert "x12" in regs_read_indirect
    assert set(regs_written_indirect) == {'x30'}
    instr_asm_pop = "pop ebx"
    regs_read_pop, regs_written_pop = _extract_register_usage(instr_asm_pop, {}, "x86")
    assert "esp" in regs_read_pop
    assert "esp" in regs_written_pop

def test_extract_register_usage_invalid():
    regs_read, regs_written = _extract_register_usage("")
    assert regs_read == []
    assert regs_written == []
    regs_read, regs_written = _extract_register_usage(None)
    assert regs_read == []
    assert regs_written == []
    instr_asm = "??? invalid_instruction ???"
    regs_read, regs_written = _extract_register_usage(instr_asm)
    assert regs_read == []
    assert regs_written == []


@pytest.fixture
def mock_instructions():
    instrs = []
    instr1 = MagicMock()
    instr1.assembly = "mov rax, 10"
    instr1.address = 0x1000
    instrs.append(instr1)
    instr2 = MagicMock()
    instr2.assembly = "add rax, rbx"
    instr2.address = 0x1003
    instrs.append(instr2)
    instr3 = MagicMock()
    instr3.assembly = "call 0x2000"
    instr3.address = 0x1006
    instrs.append(instr3)
    instr4 = MagicMock()
    instr4.assembly = "call rcx"
    instr4.address = 0x100B
    instrs.append(instr4)
    instr5 = MagicMock()
    instr5.assembly = "ret"
    instr5.address = 0x1010
    instrs.append(instr5)
    instr6 = MagicMock()
    instr6.assembly = "je 0xFF0"
    instr6.address = 0x1011
    instrs.append(instr6)
    instr7 = MagicMock()
    instr7.assembly = "bl #977140"
    instr7.address = 0x1017
    instrs.append(instr7)
    return instrs

def test_analyze_instructions_basic(mock_instructions):
    instr_addresses = [i.address for i in mock_instructions]
    func_addr = 0x1000
    next_func_addr_in_sec = 0x2000
    (metrics, mnemonics, has_indirect_call, has_loop,
     regs_read, regs_written, instrs_with_regs, _, _, _) = _analyze_instructions(
        mock_instructions, func_addr, next_func_addr_in_sec, instr_addresses, {}, "x86_64"
    )
    assert metrics["call_count"] == 2
    assert metrics["arith_count"] == 1
    assert metrics["ret_count"] == 1
    assert metrics["conditional_jump_count"] == 1
    assert "rax" in regs_read
    assert "rbx" in regs_read
    assert "rcx" in regs_read
    assert "rax" in regs_written
    assert has_indirect_call == True
    assert len(instrs_with_regs) == len(mock_instructions)
    assert "rax" in instrs_with_regs[0]["regs_written"]
    assert instrs_with_regs[0]["regs_read"] == []
    assert "rcx" in instrs_with_regs[3]["regs_read"]
    cc_regs = {'rax', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11'}
    assert cc_regs.issubset(set(instrs_with_regs[3]["regs_written"]))

def test_analyze_instructions_loop_detection():
    instrs = []
    instr1 = MagicMock()
    instr1.assembly = "je 0x0FFF"
    instr1.address = 0x1000
    instrs.append(instr1)
    instr_addresses = [i.address for i in instrs]
    func_addr = 0x0FF0
    next_func_addr_in_sec = 0x1100
    target_instr = MagicMock()
    target_instr.address = 0x0FFF
    instr_addresses_with_target = instr_addresses + [target_instr.address]
    (metrics, mnemonics, has_indirect_call, has_loop, _, _, _, _, _, _) = _analyze_instructions(
        instrs, func_addr, next_func_addr_in_sec, instr_addresses_with_target
    )
    instrs_corrected = []
    instr1_corrected = MagicMock()
    instr1_corrected.assembly = "je 0x0FFE"
    instr1_corrected.address = 0x1000
    instrs_corrected.append(instr1_corrected)
    instr_addresses_corrected = [0x0FFE, 0x0FFF, 0x1000]
    (metrics, mnemonics, has_indirect_call, has_loop, _, _, _, _, _, _) = _analyze_instructions(
        instrs_corrected, func_addr, next_func_addr_in_sec, instr_addresses_corrected
    )
    assert has_loop == True

def test_apple_proprietary_instruction_detection():
    func_addr = 0x1000
    next_func_addr_in_sec = 0x2000
    instr1_corrected = MagicMock()
    instr1_corrected.assembly = ".inst 0x00201420"
    instr1_corrected.address = 0x1000
    instr1_corrected.bytes = (0x00201420).to_bytes(4, 'little')
    instrs_corrected = [instr1_corrected]
    instr_addresses_corrected = [0x1000]
    mock_macho = MagicMock(spec=lief.MachO.Binary)
    (metrics, mnemonics, has_indirect_call, has_loop, _, _, _, _, proprietary_instructions, _) = _analyze_instructions(
        instrs_corrected,
        func_addr,
        next_func_addr_in_sec,
        instr_addresses_corrected,
        parsed_obj=mock_macho,
        arch_target="aarch64"
    )
    assert proprietary_instructions == ['GuardedMode']

def test_apple_sreg_interaction_msr():
    func_addr = 0x1000
    next_func_addr_in_sec = 0x2000
    instr = MagicMock()
    instr.assembly = "msr s3_6_c15_c1_0, x0"
    instr.address = 0x1004
    instr.bytes = b'\x00\x00\x00\x00'
    instructions = [instr]
    instr_addresses = [instr.address]
    mock_macho = MagicMock(spec=lief.MachO.Binary)
    (_, _, _, _, _, _, _, _, proprietary_instructions, sreg_interactions) = _analyze_instructions(
        instructions,
        func_addr,
        next_func_addr_in_sec,
        instr_addresses,
        parsed_obj=mock_macho,
        arch_target="aarch64"
    )
    assert proprietary_instructions == []
    assert sreg_interactions == ['SPRR_CONTROL']

def test_apple_sreg_interaction_mrs():
    func_addr = 0x1000
    next_func_addr_in_sec = 0x2000
    instr = MagicMock()
    instr.assembly = "mrs x1, s3_6_c15_c1_0"
    instr.address = 0x1008
    instr.bytes = b'\x00\x00\x00\x00'
    instructions = [instr]
    instr_addresses = [instr.address]
    mock_macho = MagicMock(spec=lief.MachO.Binary)
    (_, _, _, _, _, _, _, _, proprietary_instructions, sreg_interactions) = _analyze_instructions(
        instructions,
        func_addr,
        next_func_addr_in_sec,
        instr_addresses,
        parsed_obj=mock_macho,
        arch_target="aarch64"
    )
    assert proprietary_instructions == []
    assert sreg_interactions == ['SPRR_CONTROL']

def test_classify_function_plt_thunk():
    metrics = {"jump_count": 1, "conditional_jump_count": 0, "call_count": 0, "ret_count": 0, "arith_count": 0, "shift_count": 0, "xor_count": 0}
    instruction_count = 3
    plain_assembly_text = "jmp qword ptr [rip + 0x1234]\npush 0x1\njmp 0x123456"
    has_system_call = False
    has_indirect_call = False

    ftype = _classify_function(metrics, instruction_count, plain_assembly_text, has_system_call, has_indirect_call)
    assert ftype == "PLT_Thunk"

def test_classify_function_simple_return():
    metrics = {"jump_count": 0, "conditional_jump_count": 0, "call_count": 0, "ret_count": 1, "arith_count": 0, "shift_count": 0, "xor_count": 0}
    instruction_count = 1
    plain_assembly_text = "ret"
    has_system_call = False
    has_indirect_call = False

    ftype = _classify_function(metrics, instruction_count, plain_assembly_text, has_system_call, has_indirect_call)
    assert ftype == "Simple_Return"

def test_classify_function_has_syscalls():
    metrics = {"jump_count": 0, "conditional_jump_count": 0, "call_count": 0, "ret_count": 0, "arith_count": 0, "shift_count": 0, "xor_count": 0}
    instruction_count = 10
    plain_assembly_text = "mov rax, 1\nsyscall"
    has_system_call = True
    has_indirect_call = False

    ftype = _classify_function(metrics, instruction_count, plain_assembly_text, has_system_call, has_indirect_call)
    assert ftype == "Has_Syscalls"

def test_classify_function_has_indirect_calls():
    metrics = {"jump_count": 0, "conditional_jump_count": 0, "call_count": 0, "ret_count": 0, "arith_count": 0, "shift_count": 0, "xor_count": 0}
    instruction_count = 5
    plain_assembly_text = "call rax\nmov rbx, 1"
    has_system_call = False
    has_indirect_call = True

    ftype = _classify_function(metrics, instruction_count, plain_assembly_text, has_system_call, has_indirect_call)
    assert ftype == "Has_Indirect_Calls"

def test_classify_function_has_conditional_jumps():
    metrics = {"jump_count": 0, "conditional_jump_count": 2, "call_count": 0, "ret_count": 0, "arith_count": 0, "shift_count": 0, "xor_count": 0}
    instruction_count = 15
    plain_assembly_text = "cmp rax, rbx\nje label\n..."
    has_system_call = False
    has_indirect_call = False

    ftype = _classify_function(metrics, instruction_count, plain_assembly_text, has_system_call, has_indirect_call)
    assert ftype == "Has_Conditional_Jumps"

def test_classify_function_unknown():
    metrics = {"jump_count": 0, "conditional_jump_count": 0, "call_count": 1, "ret_count": 1, "arith_count": 2, "shift_count": 0, "xor_count": 0}
    instruction_count = 20
    plain_assembly_text = "mov rax, rbx\nadd rax, 1\n..."
    has_system_call = False
    has_indirect_call = False

    ftype = _classify_function(metrics, instruction_count, plain_assembly_text, has_system_call, has_indirect_call)
    assert ftype == ""

def test_extract_register_usage_cmov():
    instr_asm = "cmovne rax, rbx"
    regs_read, regs_written = _extract_register_usage(instr_asm)
    assert set(regs_read) == {"rbx"}
    assert set(regs_written) == {"rax"}

def test_extract_register_usage_xadd():
    instr_asm = "xadd rcx, rdx"
    regs_read, regs_written = _extract_register_usage(instr_asm)
    assert set(regs_read) == {"rcx", "rdx"}
    assert set(regs_written) == {"rcx", "rdx"}

def test_extract_register_usage_bsf():
    instr_asm = "bsf eax, [rsi]"
    regs_read, regs_written = _extract_register_usage(instr_asm)
    assert set(regs_read) == {"rsi"}
    assert set(regs_written) == {"eax"}
