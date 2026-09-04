"""Tests for the v4 engine modules: cfg, absint, entropy, similarity, toolchain."""

import struct

from blint.lib.absint import interpret_arm64, recover_arm64_stack_strings
from blint.lib.cfg import build_function_cfg, classify_terminator
from blint.lib.entropy import analyze_packing, shannon_entropy
from blint.lib.similarity import (
    compute_import_hash,
    function_cfg_hash,
    function_fuzzy_hash,
)
from blint.lib.toolchain import infer_toolchain


class _Instr:
    def __init__(self, address, assembly, size):
        self.address = address
        self.assembly = assembly
        self.bytes = b"\x90" * size


def _parse(mnemonic, operand=""):
    from blint.lib.disassembler import _parse_instruction_text

    text = f"{mnemonic} {operand}" if operand else mnemonic
    return _parse_instruction_text(text)


class TestClassifyTerminator:
    def test_x86(self):
        assert classify_terminator("jmp", "x86_64") == ("jump", False)
        assert classify_terminator("jne", "x86_64") == ("jump", True)
        assert classify_terminator("call", "x86_64") == ("call", False)
        assert classify_terminator("ret", "x86_64") == ("ret", False)
        assert classify_terminator("ud2", "x86_64") == ("trap", False)
        assert classify_terminator("mov", "x86_64") == ("none", False)

    def test_arm64(self):
        assert classify_terminator("b", "aarch64") == ("jump", False)
        assert classify_terminator("b.eq", "aarch64") == ("jump", True)
        assert classify_terminator("cbz", "aarch64") == ("jump", True)
        assert classify_terminator("bl", "aarch64") == ("call", False)
        assert classify_terminator("ret", "aarch64") == ("ret", False)
        assert classify_terminator("brk", "aarch64") == ("trap", False)


class TestFunctionCfg:
    def test_straight_line(self):
        instrs = [_Instr(0x1000, "mov eax, 1", 3), _Instr(0x1003, "ret", 1)]
        parsed = [_parse("mov", "eax, 1"), _parse("ret")]
        cfg = build_function_cfg(instrs, parsed, "x86_64", 0x1000)
        assert cfg["block_count"] == 1
        assert cfg["cyclomatic_complexity"] == 1
        assert cfg["loop_count"] == 0

    def test_branch_and_loop(self):
        # 0x1000: mov
        # 0x1003: jne 0x1000 (loop back)
        # 0x1005: ret
        instrs = [
            _Instr(0x1000, "mov eax, 1", 3),
            _Instr(0x1003, "jne 4096", 2),
            _Instr(0x1005, "ret", 1),
        ]
        parsed = [_parse("mov", "eax, 1"), _parse("jne", "4096"), _parse("ret")]
        cfg = build_function_cfg(instrs, parsed, "x86_64", 0x1000)
        # x86 displacement is relative to the next instruction: 0x1005 - 4096
        # does not resolve here (operand rendered as displacement -5 in real
        # output), so emulate the real rendering instead.
        parsed[1] = _parse("jne", "-5")
        cfg = build_function_cfg(instrs, parsed, "x86_64", 0x1000)
        assert cfg["block_count"] == 2
        assert cfg["loop_count"] == 1
        assert cfg["cyclomatic_complexity"] == 2

    def test_arm64_conditional(self):
        instrs = [
            _Instr(0x400, "cbz w8, 8", 4),
            _Instr(0x404, "add x0, x0, 1", 4),
            _Instr(0x408, "ret", 4),
        ]
        parsed = [_parse("cbz", "w8, 8"), _parse("add", "x0, x0, 1"), _parse("ret")]
        cfg = build_function_cfg(instrs, parsed, "aarch64", 0x400)
        assert cfg["block_count"] == 3
        assert cfg["cyclomatic_complexity"] == 2
        # taken branch + conditional fallthrough + add-block fallthrough
        assert cfg["edge_count"] == 3

    def test_unreachable_block(self):
        instrs = [
            _Instr(0x1000, "ret", 1),
            _Instr(0x1001, "nop", 1),
            _Instr(0x1002, "ret", 1),
        ]
        parsed = [_parse("ret"), _parse("nop"), _parse("ret")]
        cfg = build_function_cfg(instrs, parsed, "x86_64", 0x1000)
        assert cfg["block_count"] == 2
        assert cfg["unreachable_block_count"] == 1

    def test_deterministic(self):
        instrs = [
            _Instr(0x1000, "xor eax, eax", 2),
            _Instr(0x1002, "jne 4098", 2),
            _Instr(0x1004, "je 4102", 2),
            _Instr(0x1006, "ret", 1),
        ]
        parsed = [_parse("xor", "eax, eax"), _parse("jne", "-4"), _parse("je", "0"), _parse("ret")]
        one = build_function_cfg(instrs, parsed, "x86_64", 0x1000)
        two = build_function_cfg(instrs, parsed, "x86_64", 0x1000)
        assert one == two


class TestArm64Absint:
    def test_movz_movk_builds_value(self):
        state = interpret_arm64(
            ["movz x8, #0x2F", "movk x8, #0x75, lsl #8"]
        )
        value, width = state.get_register("x8")
        assert value == 0x752F
        assert width == 8

    def test_store_into_frame_slot(self):
        state = interpret_arm64(
            [
                "movz x8, #0x41",
                "str x8, [sp, #64]",
            ]
        )
        assert state.slots[("sp", 64)] == 0x41
        assert state.slots[("sp", 65)] == 0

    def test_stur_negative_offset(self):
        state = interpret_arm64(
            [
                "movz x8, #0x41",
                "stur x8, [x29, #-24]",
            ]
        )
        assert state.slots[("x29", -24)] == 0x41

    def test_call_clobbers_caller_saved_only(self):
        state = interpret_arm64(
            [
                "movz x0, #7",
                "movz x19, #9",
                "bl 0x1234",
            ]
        )
        assert state.get_register("x0") is None
        assert state.get_register("x19")[0] == 9

    def test_zero_register_reads_zero(self):
        state = interpret_arm64([])
        assert state.get_register("xzr") == (0, 8)

    def test_unknown_writer_invalidates(self):
        state = interpret_arm64(
            [
                "movz x8, #5",
                "ldr x8, [x9]",
            ]
        )
        assert state.get_register("x8") is None

    def test_recover_stack_string(self):
        # '/usr' as one 32-bit little-endian store: 0x7273752F puts the bytes
        # 2F 75 72 73 at sp+8. movz supplies the low half, movk the high one.
        assembly = "\n".join(
            [
                "movz w8, #0x752F",
                "movk w8, #0x7273, lsl #16",
                "str w8, [sp, #8]",
            ]
        )
        recovered = recover_arm64_stack_strings(assembly)
        values = [entry["value"] for entry in recovered]
        assert "/usr" in values


class TestEntropy:
    def test_shannon_bounds(self):
        assert shannon_entropy(b"") == 0.0
        assert shannon_entropy(b"\x00" * 100) == 0.0
        assert shannon_entropy(bytes(range(256)) * 4) > 7.99

    def test_packer_signature_high(self):
        sections = [
            {"name": ".text", "virtual_address": 0x1000, "virtual_size": 0x100,
             "raw_size": 0x100, "file_offset": 0x400, "executable": True,
             "writable": False, "bytes": b"\x90" * 256},
            {"name": "UPX0", "virtual_address": 0x2000, "virtual_size": 0x100,
             "raw_size": 0x100, "file_offset": 0x800, "executable": True,
             "writable": True, "bytes": bytes(range(256)) * 4},
        ]
        result = analyze_packing(sections, 0x1000, 5, 0x2000)
        assert result["packed_likelihood"] == "high"
        assert result["packers"] == ["UPX"]
        assert "writable_executable_section:UPX0" in result["findings"]

    def test_clean_binary_low(self):
        code = b"".join(struct.pack("<B", i % 7) for i in range(512))
        sections = [
            {"name": ".text", "virtual_address": 0x1000, "virtual_size": 0x200,
             "raw_size": 0x200, "file_offset": 0x400, "executable": True,
             "writable": False, "bytes": code},
        ]
        result = analyze_packing(sections, 0x1000, 40, 0x1000)
        assert result["packed_likelihood"] == "low"
        assert result["packers"] == []

    def test_macho_overlay_skipped(self):
        code = b"\x90" * 32
        sections = [
            {"name": "__text", "virtual_address": 0x1000, "virtual_size": 0x20,
             "raw_size": 0x20, "file_offset": 0x100, "executable": True,
             "writable": False, "bytes": code},
        ]
        # A large tail (the code signature on real binaries) must not fire.
        result = analyze_packing(sections, 0x1000, 30, 0x10000, is_macho=True)
        assert "file_overlay" not in result["findings"]
        result_pe = analyze_packing(sections, 0x1000, 30, 0x10000, is_macho=False)
        assert "file_overlay" in result_pe["findings"]


class TestSimilarity:
    def test_fuzzy_hash_ignores_operands(self):
        one = function_fuzzy_hash("mov eax, 1\npush rbp\nret")
        two = function_fuzzy_hash("mov ebx, 99\npush rdi\nret")
        assert one == two
        three = function_fuzzy_hash("mov eax, 1\nret")
        assert one != three

    def test_fuzzy_hash_empty(self):
        assert function_fuzzy_hash("") == ""

    def test_cfg_hash_shape_only(self):
        base = {"block_count": 3, "edge_count": 3, "cyclomatic_complexity": 2}
        assert function_cfg_hash(base) == function_cfg_hash(dict(base))
        changed = dict(base, block_count=4)
        assert function_cfg_hash(base) != function_cfg_hash(changed)
        assert function_cfg_hash(None) == ""

    def test_import_hash_stable_across_decoration(self):
        elf_names = ["memcpy@GLIBC_2.2.5", "malloc", "__stack_chk_fail@@GLIBC_2.4"]
        pe_names = ["__imp_memcpy", "_malloc", "__stack_chk_fail"]
        assert compute_import_hash(elf_names) == compute_import_hash(pe_names)
        assert compute_import_hash(["memcpy"]) != compute_import_hash(["memset"])
        assert compute_import_hash([]) == ""


class TestToolchain:
    def test_comment_section_compilers(self):
        metadata = {
            "build_info": {
                "compiler_version": "rustc version 1.98.0 (88d9e12ae 2026-08-18)\x00"
                "Linker: LLD 22.1.8\x00GCC: (GNU) 9.4.0"
            }
        }
        toolchain = infer_toolchain(metadata)
        names = {c["name"] for c in toolchain["compilers"]}
        assert {"rustc", "gcc", "lld"} <= names

    def test_macho_build_version_tools(self):
        metadata = {"tools": [{"tool": "clang", "version": "15.0.0"}]}
        toolchain = infer_toolchain(metadata)
        assert toolchain["compilers"][0]["name"] == "clang"
        assert toolchain["compilers"][0]["source"] == "LC_BUILD_VERSION"

    def test_glibc_from_symbol_versions(self):
        metadata = {"symbols_version": [{"name": "GLIBC_2.34"}]}
        toolchain = infer_toolchain(metadata)
        assert toolchain["libc"] == "glibc"

    def test_runtime_symbol_detection(self):
        metadata = {
            "symtab_symbols": [
                {"name": "runtime.morestack_noctxt"},
                {"name": "objc_msgSend"},
                {"name": "_RNvCs806nzKq9KaB_4core3ptr9drop_glue"},
            ]
        }
        toolchain = infer_toolchain(metadata)
        runtimes = {r["name"] for r in toolchain["runtimes"]}
        assert {"go", "objective-c", "rust"} <= runtimes

    def test_empty_metadata_is_honest(self):
        toolchain = infer_toolchain({})
        assert toolchain == {"compilers": [], "runtimes": [], "libc": None}
