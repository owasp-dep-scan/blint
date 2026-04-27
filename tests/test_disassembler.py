from unittest.mock import MagicMock

import lief
import pytest

from blint.lib.disassembler import (
    _analyze_instructions,
    _classify_function,
    _extract_register_usage,
    _is_macos_system_symbol_name,
    _resolve_direct_calls,
    _should_skip_symbol_list_for_disassembly,
)


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
    regs_read, regs_written = _extract_register_usage(instr_asm, None, "x86_64")
    assert set(regs_read) == {"rdi"}
    assert set(regs_written) == set()


def test_extract_register_usage_lea():
    instr_asm = "lea r8, [rbx + r9 * 2 + 10]"
    regs_read, regs_written = _extract_register_usage(instr_asm)
    assert set(regs_read) == {"rbx", "r9"}
    assert set(regs_written) == {"r8"}


def test_extract_register_usage_mixed_case_percent_prefixed():
    instr_asm = "MOV %RAX, %RBX"
    regs_read, regs_written = _extract_register_usage(instr_asm)
    assert set(regs_read) == {"rbx"}
    assert set(regs_written) == {"rax"}


def test_extract_register_usage_push_pop():
    instr_asm_push = "push rax"
    regs_read_push, regs_written_push = _extract_register_usage(
        instr_asm_push, {}, "x86_64"
    )
    assert "rsp" in regs_read_push
    assert "rsp" in regs_written_push
    instr_asm_pop = "pop rbx"
    regs_read_pop, regs_written_pop = _extract_register_usage(
        instr_asm_pop, {}, "x86_64"
    )
    assert "rsp" in regs_read_pop
    assert "rsp" in regs_written_pop


def test_extract_register_usage_call():
    instr_asm = "call 0x123456"
    regs_read, regs_written = _extract_register_usage(instr_asm, {}, "x86_64")
    cc_regs = {"rsi", "rcx", "r9", "r10", "rax", "rdi", "r8", "r11", "rdx"}
    assert set(regs_written) == cc_regs
    assert set(regs_read) == set()
    instr_asm_indirect = "blr x12"
    regs_read_indirect, regs_written_indirect = _extract_register_usage(
        instr_asm_indirect, {}, "aarch64"
    )
    assert "x12" in regs_read_indirect
    assert set(regs_written_indirect) == {"x30"}
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
    (
        metrics,
        mnemonics,
        has_indirect_call,
        has_loop,
        regs_read,
        regs_written,
        instrs_with_regs,
        _,
        _,
        _,
        _,
    ) = _analyze_instructions(
        mock_instructions,
        func_addr,
        next_func_addr_in_sec,
        instr_addresses,
        {},
        "x86_64",
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
    assert len(instrs_with_regs) == 5
    assert "rax" in instrs_with_regs[0]["regs_written"]
    assert instrs_with_regs[1]["regs_read"] == ["rax", "rbx"]
    assert "rcx" in instrs_with_regs[3]["regs_read"]
    cc_regs = {"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"}
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
    (metrics, mnemonics, has_indirect_call, has_loop, _, _, _, _, _, _, _) = (
        _analyze_instructions(
            instrs, func_addr, next_func_addr_in_sec, instr_addresses_with_target
        )
    )
    instrs_corrected = []
    instr1_corrected = MagicMock()
    instr1_corrected.assembly = "je 0x0FFE"
    instr1_corrected.address = 0x1000
    instrs_corrected.append(instr1_corrected)
    instr_addresses_corrected = [0x0FFE, 0x0FFF, 0x1000]
    (metrics, mnemonics, has_indirect_call, has_loop, _, _, _, _, _, _, _) = (
        _analyze_instructions(
            instrs_corrected,
            func_addr,
            next_func_addr_in_sec,
            instr_addresses_corrected,
        )
    )
    assert has_loop == True


def test_apple_proprietary_instruction_detection():
    func_addr = 0x1000
    next_func_addr_in_sec = 0x2000
    instr1_corrected = MagicMock()
    instr1_corrected.assembly = ".inst 0x00201420"
    instr1_corrected.address = 0x1000
    instr1_corrected.bytes = (0x00201420).to_bytes(4, "little")
    instrs_corrected = [instr1_corrected]
    instr_addresses_corrected = [0x1000]
    mock_macho = MagicMock(spec=lief.MachO.Binary)
    (
        metrics,
        mnemonics,
        has_indirect_call,
        has_loop,
        _,
        _,
        _,
        _,
        proprietary_instructions,
        _,
        _,
    ) = _analyze_instructions(
        instrs_corrected,
        func_addr,
        next_func_addr_in_sec,
        instr_addresses_corrected,
        parsed_obj=mock_macho,
        arch_target="aarch64",
    )
    assert proprietary_instructions == ["GuardedMode"]


def test_apple_sreg_interaction_msr():
    func_addr = 0x1000
    next_func_addr_in_sec = 0x2000
    instr = MagicMock()
    instr.assembly = "msr s3_6_c15_c1_0, x0"
    instr.address = 0x1004
    instr.bytes = b"\x00\x00\x00\x00"
    instructions = [instr]
    instr_addresses = [instr.address]
    mock_macho = MagicMock(spec=lief.MachO.Binary)
    (_, _, _, _, _, _, _, _, proprietary_instructions, sreg_interactions, _) = (
        _analyze_instructions(
            instructions,
            func_addr,
            next_func_addr_in_sec,
            instr_addresses,
            parsed_obj=mock_macho,
            arch_target="aarch64",
        )
    )
    assert proprietary_instructions == []
    assert sreg_interactions == ["SPRR_CONTROL"]


def test_apple_sreg_interaction_mrs():
    func_addr = 0x1000
    next_func_addr_in_sec = 0x2000
    instr = MagicMock()
    instr.assembly = "mrs x1, s3_6_c15_c1_0"
    instr.address = 0x1008
    instr.bytes = b"\x00\x00\x00\x00"
    instructions = [instr]
    instr_addresses = [instr.address]
    mock_macho = MagicMock(spec=lief.MachO.Binary)
    (_, _, _, _, _, _, _, _, proprietary_instructions, sreg_interactions, _) = (
        _analyze_instructions(
            instructions,
            func_addr,
            next_func_addr_in_sec,
            instr_addresses,
            parsed_obj=mock_macho,
            arch_target="aarch64",
        )
    )
    assert proprietary_instructions == []
    assert sreg_interactions == ["SPRR_CONTROL"]


def test_classify_function_plt_thunk():
    metrics = {
        "jump_count": 1,
        "conditional_jump_count": 0,
        "call_count": 0,
        "ret_count": 0,
        "arith_count": 0,
        "shift_count": 0,
        "xor_count": 0,
    }
    instruction_count = 3
    plain_assembly_text = "jmp qword ptr [rip + 0x1234]\npush 0x1\njmp 0x123456"
    has_system_call = False
    has_indirect_call = False

    ftype = _classify_function(
        metrics,
        instruction_count,
        plain_assembly_text,
        has_system_call,
        has_indirect_call,
    )
    assert ftype == "PLT_Thunk"


def test_classify_function_simple_return():
    metrics = {
        "jump_count": 0,
        "conditional_jump_count": 0,
        "call_count": 0,
        "ret_count": 1,
        "arith_count": 0,
        "shift_count": 0,
        "xor_count": 0,
    }
    instruction_count = 1
    plain_assembly_text = "ret"
    has_system_call = False
    has_indirect_call = False

    ftype = _classify_function(
        metrics,
        instruction_count,
        plain_assembly_text,
        has_system_call,
        has_indirect_call,
    )
    assert ftype == "Simple_Return"


def test_classify_function_has_syscalls():
    metrics = {
        "jump_count": 0,
        "conditional_jump_count": 0,
        "call_count": 0,
        "ret_count": 0,
        "arith_count": 0,
        "shift_count": 0,
        "xor_count": 0,
    }
    instruction_count = 10
    plain_assembly_text = "mov rax, 1\nsyscall"
    has_system_call = True
    has_indirect_call = False

    ftype = _classify_function(
        metrics,
        instruction_count,
        plain_assembly_text,
        has_system_call,
        has_indirect_call,
    )
    assert ftype == "Has_Syscalls"


def test_classify_function_has_indirect_calls():
    metrics = {
        "jump_count": 0,
        "conditional_jump_count": 0,
        "call_count": 0,
        "ret_count": 0,
        "arith_count": 0,
        "shift_count": 0,
        "xor_count": 0,
    }
    instruction_count = 5
    plain_assembly_text = "call rax\nmov rbx, 1"
    has_system_call = False
    has_indirect_call = True

    ftype = _classify_function(
        metrics,
        instruction_count,
        plain_assembly_text,
        has_system_call,
        has_indirect_call,
    )
    assert ftype == "Has_Indirect_Calls"


def test_classify_function_has_conditional_jumps():
    metrics = {
        "jump_count": 0,
        "conditional_jump_count": 2,
        "call_count": 0,
        "ret_count": 0,
        "arith_count": 0,
        "shift_count": 0,
        "xor_count": 0,
    }
    instruction_count = 15
    plain_assembly_text = "cmp rax, rbx\nje label\n..."
    has_system_call = False
    has_indirect_call = False

    ftype = _classify_function(
        metrics,
        instruction_count,
        plain_assembly_text,
        has_system_call,
        has_indirect_call,
    )
    assert ftype == "Has_Conditional_Jumps"


def test_classify_function_unknown():
    metrics = {
        "jump_count": 0,
        "conditional_jump_count": 0,
        "call_count": 1,
        "ret_count": 1,
        "arith_count": 2,
        "shift_count": 0,
        "xor_count": 0,
    }
    instruction_count = 20
    plain_assembly_text = "mov rax, rbx\nadd rax, 1\n..."
    has_system_call = False
    has_indirect_call = False

    ftype = _classify_function(
        metrics,
        instruction_count,
        plain_assembly_text,
        has_system_call,
        has_indirect_call,
    )
    assert ftype == ""


def test_resolve_direct_calls_supports_callq_and_symbol_decorations():
    instr = MagicMock()
    instr.assembly = "callq 0x2000 <helper@plt>"
    instr.address = 0x1000
    instr.bytes = b"\x90\x90"

    direct_calls, direct_targets = _resolve_direct_calls(
        [instr], {0x2000: "helper"}, "x86_64"
    )

    assert direct_calls == ["helper"]
    assert direct_targets == [
        {
            "target_name": "helper",
            "target_address": "0x2000",
            "target_address_candidates": ["0x2000"],
            "raw_operand": "0x2000",
            "kind": "direct",
        }
    ]


def test_resolve_direct_calls_preserves_unresolved_raw_target():
    instr = MagicMock()
    instr.assembly = "callq std::rt::lang_start"
    instr.address = 0x1000
    instr.bytes = b"\x90\x90"

    direct_calls, direct_targets = _resolve_direct_calls([instr], {}, "x86_64")

    assert direct_calls == ["std::rt::lang_start"]
    assert direct_targets == [
        {
            "target_name": "std::rt::lang_start",
            "target_address": "",
            "target_address_candidates": [],
            "raw_operand": "std::rt::lang_start",
            "kind": "direct",
        }
    ]


def test_resolve_direct_calls_extracts_symbol_from_bracket_annotation():
    instr = MagicMock()
    instr.assembly = (
        "callq qword ptr [rip + 0x10] <std::panicking::begin_panic_handler>"
    )
    instr.address = 0x1000
    instr.bytes = b"\x90\x90"

    direct_calls, direct_targets = _resolve_direct_calls([instr], {}, "x86_64")

    assert direct_calls == []
    assert direct_targets[0]["target_name"] == "std::panicking::begin_panic_handler"


def test_resolve_direct_calls_tailcall_from_final_jump():
    call_instr = MagicMock()
    call_instr.assembly = "callq 0x2000 <helper>"
    call_instr.address = 0x1000
    call_instr.bytes = b"\x90\x90"

    tail_instr = MagicMock()
    tail_instr.assembly = "jmp 0x3000 <tail_target>"
    tail_instr.address = 0x1002
    tail_instr.bytes = b"\x90\x90"

    direct_calls, direct_targets = _resolve_direct_calls(
        [call_instr, tail_instr], {0x2000: "helper", 0x3000: "tail_target"}, "x86_64"
    )

    assert "helper" in direct_calls
    assert any(t.get("kind") == "tailcall" for t in direct_targets)


def test_resolve_direct_calls_indirect_hint_from_register_tracking():
    load_instr = MagicMock()
    load_instr.assembly = "mov rax, 0x2000 <helper>"
    load_instr.address = 0x1000
    load_instr.bytes = b"\x90\x90"

    call_instr = MagicMock()
    call_instr.assembly = "call rax"
    call_instr.address = 0x1002
    call_instr.bytes = b"\x90\x90"

    direct_calls, direct_targets = _resolve_direct_calls(
        [load_instr, call_instr], {0x2000: "helper"}, "x86_64"
    )

    assert direct_calls == []
    assert any(t.get("kind") == "indirect_hint" for t in direct_targets)


def test_resolve_direct_calls_does_not_treat_register_as_symbol():
    instr = MagicMock()
    instr.assembly = "call rcx"
    instr.address = 0x1000
    instr.bytes = b"\x90\x90"

    direct_calls, direct_targets = _resolve_direct_calls([instr], {}, "x86_64")

    assert direct_calls == []
    assert direct_targets == []


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


def test_extract_register_usage_mips_addiu():
    instr_asm = "addiu $sp, $sp, -32"
    regs_read, regs_written = _extract_register_usage(instr_asm, arch_target="mipsel")
    assert set(regs_read) == {"$sp"}
    assert set(regs_written) == {"$sp"}


def test_extract_register_usage_mips_sw():
    instr_asm = "sw $ra, 28($sp)"
    regs_read, regs_written = _extract_register_usage(instr_asm, arch_target="mipsel")
    assert set(regs_read) == {"$ra", "$sp"}
    assert set(regs_written) == set()


def test_extract_register_usage_mips_lw():
    instr_asm = "lw $gp, 24($sp)"
    regs_read, regs_written = _extract_register_usage(instr_asm, arch_target="mipsel")
    assert set(regs_read) == {"$sp"}
    assert set(regs_written) == {"$gp"}


def test_extract_register_usage_mips_move():
    instr_asm = "move $t9, $ra"
    regs_read, regs_written = _extract_register_usage(instr_asm, arch_target="mipsel")
    assert set(regs_read) == {"$ra"}
    assert set(regs_written) == {"$t9"}


def test_extract_register_usage_aarch64_store_pair_writeback():
    instr_asm = "stp x29, x30, [sp, #-16]!"
    regs_read, regs_written = _extract_register_usage(instr_asm, arch_target="aarch64")
    assert set(regs_read) == {"sp", "x29", "x30"}
    assert set(regs_written) == {"sp"}


def test_extract_register_usage_mips_3_operand():
    instr_asm = "addu $v0, $t0, $t1"
    regs_read, regs_written = _extract_register_usage(instr_asm, arch_target="mipsel")
    assert set(regs_read) == {"$t0", "$t1"}
    assert set(regs_written) == {"$v0"}


def test_extract_register_usage_mips_branch():
    instr_asm = "bne $a0, $a1, 0x1234"
    regs_read, regs_written = _extract_register_usage(instr_asm, arch_target="mipsel")
    assert set(regs_read) == {"$a0", "$a1"}
    assert set(regs_written) == set()


def test_extract_register_usage_mips_implicit():
    instr_asm = "jal 0x400000"
    regs_read, regs_written = _extract_register_usage(instr_asm, arch_target="mipsel")
    assert set(regs_read) == set()
    assert set(regs_written) == {"$ra"}

    instr_asm = "jr $ra"
    regs_read, regs_written = _extract_register_usage(instr_asm, arch_target="mipsel")
    assert set(regs_read) == {"$ra"}
    assert set(regs_written) == set()

    instr_asm = "mflo $v0"
    regs_read, regs_written = _extract_register_usage(instr_asm, arch_target="mipsel")
    assert "lo" in regs_read
    assert "$v0" in regs_written

    instr_asm = "mult $a0, $a1"
    regs_read, regs_written = _extract_register_usage(instr_asm, arch_target="mipsel")
    assert set(regs_read) == {"$a0", "$a1"}
    assert set(regs_written) == {"hi", "lo"}


def test_analyze_instructions_pac_detection():
    func_addr = 0x1000
    next_func_addr_in_sec = 0x2000
    instrs = []
    instr1 = MagicMock()
    instr1.assembly = "pacibsp"
    instr1.address = 0x1000
    instrs.append(instr1)
    instr_addresses = [i.address for i in instrs]
    (*_, has_pac) = _analyze_instructions(
        instrs, func_addr, next_func_addr_in_sec, instr_addresses, {}, "aarch64"
    )
    assert has_pac is True
    instrs = []
    instr1 = MagicMock()
    instr1.assembly = "mov x0, x1"
    instr1.address = 0x1000
    instrs.append(instr1)
    instr_addresses = [i.address for i in instrs]
    (*_, has_pac) = _analyze_instructions(
        instrs, func_addr, next_func_addr_in_sec, instr_addresses, {}, "aarch64"
    )
    assert has_pac is False


def test_resolve_direct_calls_x86_decimal_operand_prefers_relative_target():
    instr = MagicMock()
    instr.assembly = "call 16"
    instr.address = 0x1000
    instr.bytes = b"\x90\x90"

    direct_calls, direct_targets = _resolve_direct_calls(
        [instr], {0x1012: "helper"}, "x86_64"
    )

    assert direct_calls == ["helper"]
    assert direct_targets == [
        {
            "target_name": "helper",
            "target_address": "0x1012",
            "target_address_candidates": ["0x1012", "0x10"],
            "raw_operand": "16",
            "kind": "direct",
        }
    ]


def test_resolve_direct_calls_memory_operand_is_indirect_hint():
    instr = MagicMock()
    instr.assembly = "callq qword ptr [rip + 0x10]"
    instr.address = 0x1000
    instr.bytes = b"\x90\x90"

    direct_calls, direct_targets = _resolve_direct_calls([instr], {}, "x86_64")

    assert direct_calls == []
    assert direct_targets == [
        {
            "target_name": "",
            "target_address": "",
            "target_address_candidates": [],
            "raw_operand": "qword ptr [rip + 0x10]",
            "kind": "indirect_hint",
        }
    ]


def test_resolve_direct_calls_memory_operand_recovers_rip_slot_symbol():
    instr = MagicMock()
    instr.assembly = "callq qword ptr [rip + 0x10]"
    instr.address = 0x1000
    instr.bytes = b"\x90\x90"

    direct_calls, direct_targets = _resolve_direct_calls(
        [instr], {0x1012: "puts"}, "x86_64"
    )

    assert direct_calls == []
    assert direct_targets == [
        {
            "target_name": "puts",
            "target_address": "",
            "target_address_candidates": [],
            "raw_operand": "qword ptr [rip + 0x10]",
            "kind": "indirect_hint",
        }
    ]


def test_resolve_direct_calls_memory_operand_recovers_rip_slot_symbol_without_spaces():
    instr = MagicMock()
    instr.assembly = "callq qword ptr [rip+0x10]"
    instr.address = 0x1000
    instr.bytes = b"\x90\x90"

    direct_calls, direct_targets = _resolve_direct_calls(
        [instr], {0x1012: "puts"}, "x86_64"
    )

    assert direct_calls == []
    assert direct_targets == [
        {
            "target_name": "puts",
            "target_address": "",
            "target_address_candidates": [],
            "raw_operand": "qword ptr [rip+0x10]",
            "kind": "indirect_hint",
        }
    ]


def test_resolve_direct_calls_memory_operand_recovers_symbol_from_register_plus_disp():
    mov_instr = MagicMock()
    mov_instr.assembly = "mov rax, qword ptr [rip + 0x10]"
    mov_instr.address = 0x1000
    mov_instr.bytes = b"\x90\x90"

    call_instr = MagicMock()
    call_instr.assembly = "callq qword ptr [rax + 0x8]"
    call_instr.address = 0x1002
    call_instr.bytes = b"\x90\x90"

    direct_calls, direct_targets = _resolve_direct_calls(
        [mov_instr, call_instr], {0x101A: "puts"}, "x86_64-pc-windows-msvc"
    )

    assert direct_calls == []
    assert direct_targets == [
        {
            "target_name": "puts",
            "target_address": "",
            "target_address_candidates": [],
            "raw_operand": "qword ptr [rax + 0x8]",
            "kind": "indirect_hint",
        }
    ]


def test_resolve_direct_calls_memory_operand_recovers_symbol_from_percent_register_base():
    mov_instr = MagicMock()
    mov_instr.assembly = "mov rax, 0x2000 <helper>"
    mov_instr.address = 0x1000
    mov_instr.bytes = b"\x90\x90"

    call_instr = MagicMock()
    call_instr.assembly = "callq qword ptr [%rax]"
    call_instr.address = 0x1002
    call_instr.bytes = b"\x90\x90"

    direct_calls, direct_targets = _resolve_direct_calls(
        [mov_instr, call_instr], {0x2000: "helper"}, "x86_64-pc-windows-msvc"
    )

    assert direct_calls == []
    assert direct_targets == [
        {
            "target_name": "helper",
            "target_address": "",
            "target_address_candidates": [],
            "raw_operand": "qword ptr [%rax]",
            "kind": "indirect_hint",
        }
    ]


def test_resolve_direct_calls_memory_operand_recovers_symbol_from_r12_plus_disp():
    mov_instr = MagicMock()
    mov_instr.assembly = "mov r12, qword ptr [rip + 0x20]"
    mov_instr.address = 0x2000
    mov_instr.bytes = b"\x90\x90"

    call_instr = MagicMock()
    call_instr.assembly = "callq qword ptr [r12 + 72]"
    call_instr.address = 0x2002
    call_instr.bytes = b"\x90\x90"

    direct_calls, direct_targets = _resolve_direct_calls(
        [mov_instr, call_instr], {0x206A: "dispatch_target"}, "x86_64-pc-windows-msvc"
    )

    assert direct_calls == []
    assert direct_targets == [
        {
            "target_name": "dispatch_target",
            "target_address": "",
            "target_address_candidates": [],
            "raw_operand": "qword ptr [r12 + 72]",
            "kind": "indirect_hint",
        }
    ]


def test_resolve_direct_calls_windows_propagates_two_hop_memory_chain_before_call():
    mov_rax = MagicMock()
    mov_rax.assembly = "mov rax, qword ptr [rip + 0x10]"
    mov_rax.address = 0x1000
    mov_rax.bytes = b"\x90\x90"

    mov_rcx = MagicMock()
    mov_rcx.assembly = "mov rcx, qword ptr [rax + 0x8]"
    mov_rcx.address = 0x1002
    mov_rcx.bytes = b"\x90\x90"

    mov_rdx = MagicMock()
    mov_rdx.assembly = "mov rdx, qword ptr [rcx + 0x10]"
    mov_rdx.address = 0x1004
    mov_rdx.bytes = b"\x90\x90"

    call_rdx = MagicMock()
    call_rdx.assembly = "callq qword ptr [rdx + 0x20]"
    call_rdx.address = 0x1006
    call_rdx.bytes = b"\x90\x90"

    direct_calls, direct_targets = _resolve_direct_calls(
        [mov_rax, mov_rcx, mov_rdx, call_rdx],
        {0x104A: "virt_func"},
        "x86_64-pc-windows-msvc",
    )

    assert direct_calls == []
    assert direct_targets == [
        {
            "target_name": "virt_func",
            "target_address": "",
            "target_address_candidates": [],
            "raw_operand": "qword ptr [rdx + 0x20]",
            "kind": "indirect_hint",
        }
    ]


def test_resolve_direct_calls_windows_stops_memory_chain_after_two_hops():
    mov_rax = MagicMock()
    mov_rax.assembly = "mov rax, qword ptr [rip + 0x10]"
    mov_rax.address = 0x1000
    mov_rax.bytes = b"\x90\x90"

    mov_rcx = MagicMock()
    mov_rcx.assembly = "mov rcx, qword ptr [rax + 0x8]"
    mov_rcx.address = 0x1002
    mov_rcx.bytes = b"\x90\x90"

    mov_rdx = MagicMock()
    mov_rdx.assembly = "mov rdx, qword ptr [rcx + 0x10]"
    mov_rdx.address = 0x1004
    mov_rdx.bytes = b"\x90\x90"

    mov_r8 = MagicMock()
    mov_r8.assembly = "mov r8, qword ptr [rdx + 0x18]"
    mov_r8.address = 0x1006
    mov_r8.bytes = b"\x90\x90"

    call_r8 = MagicMock()
    call_r8.assembly = "callq qword ptr [r8 + 0x20]"
    call_r8.address = 0x1008
    call_r8.bytes = b"\x90\x90"

    direct_calls, direct_targets = _resolve_direct_calls(
        [mov_rax, mov_rcx, mov_rdx, mov_r8, call_r8],
        {0x1062: "should_not_resolve"},
        "x86_64-pc-windows-msvc",
    )

    assert direct_calls == []
    assert direct_targets == [
        {
            "target_name": "",
            "target_address": "",
            "target_address_candidates": [],
            "raw_operand": "qword ptr [r8 + 0x20]",
            "kind": "indirect_hint",
        }
    ]


def test_resolve_direct_calls_tailcall_windows_decimal_operand_prefers_relative_target():
    instr = MagicMock()
    instr.assembly = "jmp -16"
    instr.address = 0x2000
    instr.bytes = b"\x90\x90"

    direct_calls, direct_targets = _resolve_direct_calls(
        [instr], {0x1FF2: "tail"}, "x86_64-pc-windows-msvc"
    )

    assert direct_calls == []
    assert direct_targets == [
        {
            "target_name": "tail",
            "target_address": "0x1ff2",
            "target_address_candidates": ["0x1ff2"],
            "raw_operand": "-16",
            "kind": "tailcall",
        }
    ]


def test_resolve_direct_calls_aarch64_large_unsigned_immediate_accepts_hex_style():
    instr = MagicMock()
    instr.assembly = "bl #410212"
    instr.address = 0x1000
    instr.bytes = b"\x90\x90\x90\x90"

    direct_calls, direct_targets = _resolve_direct_calls(
        [instr], {0x410212: "target_fn"}, "aarch64-unknown-linux-gnu"
    )

    assert direct_calls == ["target_fn"]
    assert direct_targets == [
        {
            "target_name": "target_fn",
            "target_address": "0x410212",
            "target_address_candidates": ["0x410212", "0x65264", "0x65268", "0x64264"],
            "raw_operand": "#410212",
            "kind": "direct",
        }
    ]


def test_resolve_direct_calls_aarch64_unsigned_immediate_adds_relative_candidates():
    instr = MagicMock()
    instr.assembly = "bl #600"
    instr.address = 0x1000
    instr.bytes = b"\x90\x90\x90\x90"

    direct_calls, direct_targets = _resolve_direct_calls(
        [instr], {0x1258: "rel_target"}, "aarch64-unknown-linux-gnu"
    )

    assert direct_calls == ["rel_target"]
    assert direct_targets == [
        {
            "target_name": "rel_target",
            "target_address": "0x1258",
            "target_address_candidates": ["0x1258", "0x125c", "0x258"],
            "raw_operand": "#600",
            "kind": "direct",
        }
    ]


def test_resolve_direct_calls_aarch64_ldr_chain_recovers_blr_target_from_base_register():
    adrp_instr = MagicMock()
    adrp_instr.assembly = "adrp x8, #0x400000"
    adrp_instr.address = 0x1000
    adrp_instr.bytes = b"\x90\x90\x90\x90"

    add_instr = MagicMock()
    add_instr.assembly = "add x8, x8, #0x20"
    add_instr.address = 0x1004
    add_instr.bytes = b"\x90\x90\x90\x90"

    ldr_instr = MagicMock()
    ldr_instr.assembly = "ldr x16, [x8, #0x18]"
    ldr_instr.address = 0x1008
    ldr_instr.bytes = b"\x90\x90\x90\x90"

    blr_instr = MagicMock()
    blr_instr.assembly = "blr x16"
    blr_instr.address = 0x100C
    blr_instr.bytes = b"\x90\x90\x90\x90"

    direct_calls, direct_targets = _resolve_direct_calls(
        [adrp_instr, add_instr, ldr_instr, blr_instr],
        {0x400038: "dispatch_target"},
        "aarch64-unknown-linux-gnu",
    )

    assert direct_calls == []
    assert direct_targets[-1] == {
        "target_name": "dispatch_target",
        "target_address": "0x400038",
        "target_address_candidates": ["0x400038"],
        "raw_operand": "[x8, #0x18]",
        "kind": "indirect_hint",
    }


def test_resolve_direct_calls_aarch64_ldr_post_index_preserves_tail_displacement():
    adrp_instr = MagicMock()
    adrp_instr.assembly = "adrp x8, #0x400000"
    adrp_instr.address = 0x1000
    adrp_instr.bytes = b"\x90\x90\x90\x90"

    add_instr = MagicMock()
    add_instr.assembly = "add x8, x8, #0x20"
    add_instr.address = 0x1004
    add_instr.bytes = b"\x90\x90\x90\x90"

    ldr_instr = MagicMock()
    ldr_instr.assembly = "ldr x16, [x8], #0x18"
    ldr_instr.address = 0x1008
    ldr_instr.bytes = b"\x90\x90\x90\x90"

    blr_instr = MagicMock()
    blr_instr.assembly = "blr x16"
    blr_instr.address = 0x100C
    blr_instr.bytes = b"\x90\x90\x90\x90"

    direct_calls, direct_targets = _resolve_direct_calls(
        [adrp_instr, add_instr, ldr_instr, blr_instr],
        {0x400038: "dispatch_target"},
        "aarch64-unknown-linux-gnu",
    )

    assert direct_calls == []
    assert direct_targets[-1] == {
        "target_name": "dispatch_target",
        "target_address": "0x400038",
        "target_address_candidates": ["0x400038"],
        "raw_operand": "[x8],#0x18",
        "kind": "indirect_hint",
    }


def test_resolve_direct_calls_aarch64_br_tailcall_uses_register_target_tracking():
    adrp_instr = MagicMock()
    adrp_instr.assembly = "adrp x16, #0x410000"
    adrp_instr.address = 0x2000
    adrp_instr.bytes = b"\x90\x90\x90\x90"

    add_instr = MagicMock()
    add_instr.assembly = "add x16, x16, #0x88"
    add_instr.address = 0x2004
    add_instr.bytes = b"\x90\x90\x90\x90"

    tail_instr = MagicMock()
    tail_instr.assembly = "br x16"
    tail_instr.address = 0x2008
    tail_instr.bytes = b"\x90\x90\x90\x90"

    direct_calls, direct_targets = _resolve_direct_calls(
        [adrp_instr, add_instr, tail_instr],
        {0x410088: "tail_target"},
        "aarch64-unknown-linux-gnu",
    )

    assert direct_calls == []
    assert direct_targets[-1] == {
        "target_name": "tail_target",
        "target_address": "0x410088",
        "target_address_candidates": ["0x410088"],
        "raw_operand": "x16",
        "kind": "tailcall",
    }


def test_resolve_direct_calls_aarch64_pac_branch_call_uses_first_register_operand():
    mov_instr = MagicMock()
    mov_instr.assembly = "mov x16, 0x410000 <dispatch_target>"
    mov_instr.address = 0x1000
    mov_instr.bytes = b"\x90\x90\x90\x90"

    call_instr = MagicMock()
    call_instr.assembly = "blraa x16, x17"
    call_instr.address = 0x1004
    call_instr.bytes = b"\x90\x90\x90\x90"

    direct_calls, direct_targets = _resolve_direct_calls(
        [mov_instr, call_instr],
        {0x410000: "dispatch_target"},
        "aarch64-pc-windows-msvc",
    )

    assert direct_calls == []
    assert direct_targets[-1] == {
        "target_name": "dispatch_target",
        "target_address": "0x410000",
        "target_address_candidates": ["0x410000"],
        "raw_operand": "0x410000",
        "kind": "indirect_hint",
    }


def test_resolve_direct_calls_windows_arm64_ignores_indexed_ldr_chain_for_indirect_targets():
    adrp_instr = MagicMock()
    adrp_instr.assembly = "adrp x9, #0x400000"
    adrp_instr.address = 0x2000
    adrp_instr.bytes = b"\x90\x90\x90\x90"

    ldr_indexed_instr = MagicMock()
    ldr_indexed_instr.assembly = "ldr x8, [x9, x10, lsl #3]"
    ldr_indexed_instr.address = 0x2004
    ldr_indexed_instr.bytes = b"\x90\x90\x90\x90"

    blr_instr = MagicMock()
    blr_instr.assembly = "blr x8"
    blr_instr.address = 0x2008
    blr_instr.bytes = b"\x90\x90\x90\x90"

    direct_calls, direct_targets = _resolve_direct_calls(
        [adrp_instr, ldr_indexed_instr, blr_instr],
        {0x400000: "should_not_resolve"},
        "aarch64-pc-windows-msvc",
    )

    assert direct_calls == []
    assert direct_targets == []


def test_resolve_direct_calls_windows_arm64_drops_noncanonical_register_target_candidates():
    mov_instr = MagicMock()
    mov_instr.assembly = "mov x9, #9223372036854775807"
    mov_instr.address = 0x3000
    mov_instr.bytes = b"\x90\x90\x90\x90"

    ldr_instr = MagicMock()
    ldr_instr.assembly = "ldr x9, [x9, #24]"
    ldr_instr.address = 0x3004
    ldr_instr.bytes = b"\x90\x90\x90\x90"

    blr_instr = MagicMock()
    blr_instr.assembly = "blr x9"
    blr_instr.address = 0x3008
    blr_instr.bytes = b"\x90\x90\x90\x90"

    direct_calls, direct_targets = _resolve_direct_calls(
        [mov_instr, ldr_instr, blr_instr], {}, "aarch64-pc-windows-msvc"
    )

    assert direct_calls == []
    assert direct_targets == []


def test_macos_system_symbol_name_detection():
    assert _is_macos_system_symbol_name("/usr/lib/libSystem.B.dylib::_close") is True
    assert (
        _is_macos_system_symbol_name(
            "/System/Library/Frameworks/AppKit.framework/AppKit::NSApp"
        )
        is True
    )
    assert _is_macos_system_symbol_name("core::fmt::write") is False


def test_should_skip_symbol_list_for_disassembly_macho_and_pe():
    mock_macho = MagicMock(spec=lief.MachO.Binary)
    mock_pe = MagicMock(spec=lief.PE.Binary)

    assert (
        _should_skip_symbol_list_for_disassembly(mock_macho, "symtab_symbols") is True
    )
    assert (
        _should_skip_symbol_list_for_disassembly(mock_macho, "dynamic_symbols") is True
    )
    assert _should_skip_symbol_list_for_disassembly(mock_macho, "imports") is True
    assert _should_skip_symbol_list_for_disassembly(mock_macho, "functions") is False

    assert _should_skip_symbol_list_for_disassembly(mock_pe, "imports") is True
    assert _should_skip_symbol_list_for_disassembly(mock_pe, "functions") is False
