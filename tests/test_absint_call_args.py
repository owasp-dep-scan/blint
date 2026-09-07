"""Call-site constant-argument recovery (A4 slice 2).

Two layers:

- Unit tests over synthetic function metadata pin the dataflow contract: a
  value reaches a call site only when every path there agrees on it, an
  unresolved or ambiguous callee is reported absent rather than guessed, and
  the ABI (and with it the argument registers) is selected explicitly from
  the binary format plus the architecture.
- Ground-truth tests parse hand-built but structurally real PE64 and ELF64
  binaries whose machine code was assembled from encodings verified against
  LLVM. The control codes are values chosen in this file, asserted back out
  of the full parse pipeline (LIEF → nyxstone → CFG dataflow), together
  with negatives: a plausible code in a register no argument position reads,
  and a code loaded on only one arm of a branch, must not be reported.
"""

import struct

from blint.lib.absint import (
    ARM64_ARGUMENT_REGISTERS,
    X86_SYSV_ARGUMENT_REGISTERS,
    X86_WIN64_ARGUMENT_REGISTERS,
    argument_registers,
    recover_call_site_arguments,
    recover_call_site_arguments_with_method,
)
from blint.lib.driver_ioctl import extract_client_ioctl_codes

# Control codes chosen for the ground-truth binaries: values this file
# defines, not values any blint model produced.
GROUND_TRUTH_CODE_1 = 0x83352A01
GROUND_TRUTH_CODE_2 = 0x83352A05
# Plausible-looking decoys that must never be reported: one returned in eax,
# one parked in the callee-saved ebp/w9.
RETURNED_DECOY = 0x83352409
CALLEE_SAVED_DECOY = 0x83352411


def _resolved_func(
    assembly: str,
    callee: str = "KERNEL32.dll::DeviceIoControl",
    operand: str = "qword ptr [rip + 4096]",
    kind: str = "indirect_hint",
    blocks: list | None = None,
    edges: list | None = None,
    direct_call_targets: list | None = None,
) -> dict:
    lines = assembly.split("\n")
    return {
        "name": "sub_1400",
        "address": "0x1400",
        "assembly": assembly,
        "instruction_count": len(lines),
        "cfg": {
            "blocks": blocks or [{"instructions": len(lines)}],
            "edges": edges or [],
        },
        "direct_call_targets": (
            direct_call_targets
            if direct_call_targets is not None
            else [{"target_name": callee, "raw_operand": operand, "kind": kind}]
        ),
    }


# ---------------------------------------------------------------------------
# ABI selection.
# ---------------------------------------------------------------------------


def test_argument_registers_covers_every_determined_combination():
    assert argument_registers("PE", "x86_64-pc-windows-msvc") == X86_WIN64_ARGUMENT_REGISTERS
    assert argument_registers("ELF", "x86_64-pc-linux-gnu") == X86_SYSV_ARGUMENT_REGISTERS
    # Apple's x86-64 ABI takes its integer argument registers from SysV.
    assert argument_registers("MachO", "x86_64-apple-macos") == X86_SYSV_ARGUMENT_REGISTERS
    assert argument_registers("ELF", "aarch64-unknown-linux-gnu") == ARM64_ARGUMENT_REGISTERS
    assert argument_registers("PE", "aarch64-pc-windows-msvc") == ARM64_ARGUMENT_REGISTERS
    # An empty triple means x86-64 exactly where model_for_target means x86-64.
    assert argument_registers("PE", "") == X86_WIN64_ARGUMENT_REGISTERS


def test_argument_registers_refuses_undetermined_combinations():
    # An unknown format must not silently inherit SysV.
    assert argument_registers("", "x86_64-pc-linux-gnu") is None
    assert argument_registers("raw", "x86_64-pc-linux-gnu") is None
    # A 32-bit or non-x86/arm64 architecture passes arguments differently
    # (i386 on the stack, arm32 in r0-r3): the x86-64 model cannot decode it
    # honestly, so no argument positions exist.
    assert argument_registers("PE", "armv7-pc-windows-msvc") is None
    assert argument_registers("ELF", "i386-pc-linux-gnu") is None


# ---------------------------------------------------------------------------
# The dataflow contract at call sites.
# ---------------------------------------------------------------------------


def _win64_deviceioctl_func(assembly: str, **kwargs) -> dict:
    return _resolved_func(assembly, **kwargs)


def test_call_site_arguments_report_the_abi_position():
    func = _win64_deviceioctl_func(
        "mov ecx, 409\n"
        "mov edx, 2201297921\n"
        "xor r8d, r8d\n"
        "xor r9d, r9d\n"
        "call qword ptr [rip + 4096]"
    )
    records, method = recover_call_site_arguments_with_method(func, "", "PE")
    assert method == "dataflow"
    assert len(records) == 1
    record = records[0]
    assert record["callee"] == "KERNEL32.dll::DeviceIoControl"
    assert record["line"] == 4
    assert record["registers"] == ("rcx", "rdx", "r8", "r9")
    assert record["arguments"] == [409, 2201297921, 0, 0]  # 0x83352401


def test_value_assembled_on_one_arm_only_never_reaches_the_call():
    # The CFG diamond: edx is zeroed on both paths' common ancestor, then one
    # arm loads a code. The call joins both arms, the values conflict, and
    # neither path's constant may be reported.
    assembly = (
        "xor edx, edx\n"
        "test edi, edi\n"
        "je 2201299700\n"
        "mov edx, 2201299457\n"
        "call qword ptr [rip + 4096]\n"
        "ret"
    )
    func = _win64_deviceioctl_func(
        assembly,
        blocks=[{"instructions": 3}, {"instructions": 1}, {"instructions": 2}],
        edges=[
            {"src": 0, "dst": 1, "kind": "fallthrough"},
            {"src": 0, "dst": 2, "kind": "jump"},
            {"src": 1, "dst": 2, "kind": "fallthrough"},
        ],
    )
    records, method = recover_call_site_arguments_with_method(func, "", "PE")
    assert method == "dataflow"
    assert len(records) == 1
    # The zero from the common ancestor conflicts with the arm's code: unknown.
    assert records[0]["arguments"][1] is None
    assert extract_client_ioctl_codes(func) == []


def test_unconditional_path_constant_survives_where_the_branch_one_dies():
    # Control for the test above: the same load moved onto the straight-line
    # path (both predecessors agree) is recovered.
    assembly = (
        "xor edi, edi\n"
        "mov edx, 2201297921\n"
        "je 2201299700\n"
        "call qword ptr [rip + 4096]\n"
        "ret"
    )
    func = _win64_deviceioctl_func(
        assembly,
        blocks=[{"instructions": 3}, {"instructions": 2}],
        edges=[
            {"src": 0, "dst": 1, "kind": "fallthrough"},
            {"src": 0, "dst": 1, "kind": "jump"},
        ],
    )
    records, _ = recover_call_site_arguments_with_method(func, "", "PE")
    assert records[0]["arguments"] == [None, 2201297921, None, None]  # 0x83352401


def test_unresolved_callee_is_a_record_without_a_name():
    func = _win64_deviceioctl_func(
        "mov edx, 2201297921\ncall qword ptr [rip + 4096]",   # 0x83352401
        direct_call_targets=[],
    )
    records, method = recover_call_site_arguments_with_method(func, "", "PE")
    assert method == "dataflow"
    assert records[0]["callee"] is None
    assert records[0]["arguments"][1] == 2201297921  # 0x83352401
    # The client extraction only reports codes at resolved call sites.
    assert extract_client_ioctl_codes(func) == []


def test_ambiguous_operand_resolves_to_no_callee():
    # The same operand text reaching two different callees (a register or
    # slot reused for both) has no single callee; neither may win.
    func = _win64_deviceioctl_func(
        "mov edx, 2201297921\ncall qword ptr [rip + 4096]",   # 0x83352401
        direct_call_targets=[
            {"target_name": "KERNEL32.dll::DeviceIoControl", "raw_operand": "qword ptr [rip + 4096]", "kind": "indirect_hint"},
            {"target_name": "KERNEL32.dll::CreateFileW", "raw_operand": "qword ptr [rip + 4096]", "kind": "indirect_hint"},
        ],
    )
    records, _ = recover_call_site_arguments_with_method(func, "", "PE")
    assert records[0]["callee"] is None
    assert extract_client_ioctl_codes(func) == []


def test_callee_that_is_not_deviceioctl_contributes_nothing():
    func = _win64_deviceioctl_func(
        "mov edx, 2201297921\ncall qword ptr [rip + 4096]",   # 0x83352401
        callee="KERNEL32.dll::CreateFileW",
    )
    assert extract_client_ioctl_codes(func) == []


def test_stack_passed_control_code_is_out_of_reach_under_win64():
    # NtDeviceIoControlFile's control code is its sixth argument: stack-passed
    # under the Microsoft x64 ABI, whose register file covers four. Nothing is
    # reported rather than a wrong position read.
    func = _resolved_func(
        "mov r9d, 2201299457\ncall qword ptr [rip + 4096]",
        callee="ntdll.dll::NtDeviceIoControlFile",
    )
    assert extract_client_ioctl_codes(func) == []


def test_stack_passed_control_code_is_recoverable_under_sysv():
    # The same sixth argument lives in r9 under SysV, where six integer
    # arguments are register-passed.
    func = _resolved_func(
        "mov r9d, 2201297921\ncall qword ptr [rip + 4096]",   # 0x83352401
        callee="NtDeviceIoControlFile",
    )
    assert extract_client_ioctl_codes(func, arch_target="x86_64-pc-linux-gnu", binary_format="ELF") == [
        0x83352401
    ]


def test_arm64_lane_pair_reaches_a_tail_call_on_the_last_line():
    # AArch64 builds the code as movz/movk lanes in w1 and tail-calls through
    # `b`: the branch is a call site only on the function's last line, where
    # the disassembler annotates it as a tail transfer.
    func = _resolved_func(
        "movz w1, #25752\nmov x0, xzr\nmovk w1, #32768, lsl #16\nb #-48",
        callee="DeviceIoControl",
        operand="#-48",
        kind="tailcall",
    )
    records, method = recover_call_site_arguments_with_method(
        func, "aarch64-pc-windows-msvc", "PE"
    )
    assert method == "dataflow"
    assert len(records) == 1
    assert records[0]["callee"] == "DeviceIoControl"
    assert records[0]["arguments"][1] == 0x80006498
    assert 0x80006498 in extract_client_ioctl_codes(
        func, arch_target="aarch64-pc-windows-msvc"
    )


def test_branch_instruction_off_the_last_line_is_not_a_call_site():
    # An ordinary intra-function `b` whose operand text coincides with a
    # tail-call annotation must not inherit that callee: only the last line
    # is annotated.
    func = _resolved_func(
        "movz w1, #25752\nb #-48\nmovk w1, #32768, lsl #16\nbl #-96",
        callee="DeviceIoControl",
        operand="#-48",
        kind="tailcall",
        direct_call_targets=[
            {"target_name": "DeviceIoControl", "raw_operand": "#-48", "kind": "tailcall"}
        ],
    )
    records, _ = recover_call_site_arguments_with_method(
        func, "aarch64-pc-windows-msvc", "PE"
    )
    assert [r["instruction"] for r in records] == ["bl #-96"]
    assert records[0]["callee"] is None


def test_computed_constant_is_followed_through_arithmetic():
    # `or esi, 4` on top of a loaded lane is how a compiler materializes a
    # code without ever naming it in a `mov` immediate; the dataflow follows it.
    func = _resolved_func(
        "mov esi, 2201297937\nor esi, 4\ncall qword ptr [rip + 4096]",  # 0x83352411 | 4
    )
    # rsi is the second argument register under SysV, not under Win64.
    assert extract_client_ioctl_codes(
        func, arch_target="x86_64-pc-linux-gnu", binary_format="ELF"
    ) == [0x83352415]


# ---------------------------------------------------------------------------
# Degradation outcomes, each named rather than silently empty.
# ---------------------------------------------------------------------------


def test_missing_cfg_and_tiling_mismatch_and_unknown_abi_are_distinguished():
    plain = {"assembly": "mov edx, 2201297921\ncall qword ptr [rip + 4096]"}   # 0x83352401
    records, method = recover_call_site_arguments_with_method(plain, "", "PE")
    assert records == [] and method == "no_cfg"

    # Blocks that do not tile the text: no straight-line fallback exists, so
    # scraped-not-passed values cannot resurface.
    mismatched = _win64_deviceioctl_func(
        "mov edx, 2201297921\ncall qword ptr [rip + 4096]",   # 0x83352401
        blocks=[{"instructions": 1}],
    )
    records, method = recover_call_site_arguments_with_method(mismatched, "", "PE")
    assert records == [] and method == "cfg_mismatch"

    records, method = recover_call_site_arguments_with_method(plain, "", "")
    assert records == [] and method == "no_abi"

    records, method = recover_call_site_arguments_with_method({}, "", "PE")
    assert records == [] and method == "skipped"


def test_iteration_cap_yields_no_records(monkeypatch):
    from blint.lib import absint

    monkeypatch.setattr(absint, "MAX_BLOCK_VISITS", 1)
    func = _win64_deviceioctl_func(
        "mov edx, 2201299457\ncall qword ptr [rip + 4096]\nret",
        blocks=[{"instructions": 3}],
        edges=[{"src": 0, "dst": 0, "kind": "jump"}],
    )
    records, method = recover_call_site_arguments_with_method(func, "", "PE")
    assert records == [] and method == "cap_hit"


# ---------------------------------------------------------------------------
# Ground truth: real binaries, values chosen here.
# ---------------------------------------------------------------------------


def _pe64_client() -> bytes:
    """A minimal PE64 client exporting IoDispatch, which calls
    KERNEL32.dll!DeviceIoControl through the IAT with the two ground-truth
    control codes in edx, plus the two decoys that must not be reported."""
    image_base, text_rva, idata_rva = 0x140000000, 0x1000, 0x2000
    text_file, idata_file = 0x200, 0x400
    iat_slot = image_base + idata_rva + 0x30

    def call_rip(target: int, next_insn: int) -> bytes:
        return b"\xff\x15" + struct.pack("<i", target - next_insn)

    code = b""
    code += b"\x55"                          # push rbp
    code += b"\x48\x89\xe5"                  # mov rbp, rsp
    code += b"\x48\x83\xec\x20"              # sub rsp, 0x20
    code += b"\xb9\x99\x01\x00\x00"          # mov ecx, 0x199
    code += b"\xba" + struct.pack("<I", GROUND_TRUTH_CODE_1)   # mov edx, code 1
    code += b"\x45\x33\xc0"                  # xor r8d, r8d
    code += b"\x45\x33\xc9"                  # xor r9d, r9d
    nxt = image_base + text_rva + len(code) + 6
    code += call_rip(iat_slot, nxt)          # call [rip+..] -> DeviceIoControl
    code += b"\xb9\x99\x01\x00\x00"          # mov ecx, 0x199
    code += b"\xba" + struct.pack("<I", GROUND_TRUTH_CODE_2)   # mov edx, code 2
    code += b"\x45\x33\xc0"                  # xor r8d, r8d
    code += b"\x45\x33\xc9"                  # xor r9d, r9d
    nxt = image_base + text_rva + len(code) + 6
    code += call_rip(iat_slot, nxt)          # call [rip+..] -> DeviceIoControl
    code += b"\xb8" + struct.pack("<I", RETURNED_DECOY)        # mov eax, decoy
    code += b"\xbd" + struct.pack("<I", CALLEE_SAVED_DECOY)    # mov ebp, decoy
    code += b"\x31\xc0"                      # xor eax, eax
    code += b"\xc9"                          # leave
    code += b"\xc3"                          # ret

    idata = bytearray(0x200)
    struct.pack_into("<IIIII", idata, 0x00, 0x2028, 0, 0, 0x2060, 0x2030)
    struct.pack_into("<II", idata, 0x28, idata_rva + 0x40, 0)   # INT
    struct.pack_into("<II", idata, 0x30, idata_rva + 0x40, 0)   # IAT
    idata[0x40:0x42] = b"\x00\x00"
    idata[0x42:0x42 + 16] = b"DeviceIoControl\x00"
    idata[0x60:0x60 + 13] = b"KERNEL32.dll\x00"
    export_rva = idata_rva + 0x100
    struct.pack_into(
        "<IIHHIIIIIII", idata, 0x100,
        0, 0, 0, 0, export_rva + 0x60, 1, 1, 1,
        export_rva + 0x50, export_rva + 0x40, export_rva + 0x58,
    )
    struct.pack_into("<I", idata, 0x140, export_rva + 0x70)
    struct.pack_into("<I", idata, 0x150, text_rva)
    struct.pack_into("<H", idata, 0x158, 0)
    idata[0x160:0x160 + 11] = b"client.exe\x00"
    idata[0x170:0x170 + 11] = b"IoDispatch\x00"

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x8664, 2, 0, 0, 0, 0xF0, 0x0022)
    opt = bytearray(0xF0)
    struct.pack_into("<H", opt, 0x00, 0x20B)
    struct.pack_into("<I", opt, 0x04, len(code))
    struct.pack_into("<I", opt, 0x10, text_rva)              # AddressOfEntryPoint
    struct.pack_into("<Q", opt, 0x18, image_base)
    struct.pack_into("<I", opt, 0x20, 0x200)                 # SectionAlignment
    struct.pack_into("<I", opt, 0x24, 0x200)                 # FileAlignment
    struct.pack_into("<H", opt, 0x30, 6)                     # MajorSubsystemVersion
    struct.pack_into("<I", opt, 0x38, 0x3000)                # SizeOfImage
    struct.pack_into("<I", opt, 0x3C, 0x200)                 # SizeOfHeaders
    struct.pack_into("<H", opt, 0x44, 3)                     # Subsystem: console
    struct.pack_into("<Q", opt, 0x48, 0x100000)
    struct.pack_into("<Q", opt, 0x58, 0x100000)
    struct.pack_into("<I", opt, 0x6C, 16)                    # NumberOfRvaAndSizes
    dd = 0x70
    struct.pack_into("<II", opt, dd + 8 * 0, export_rva, 40)
    struct.pack_into("<II", opt, dd + 8 * 1, idata_rva, 40)
    struct.pack_into("<II", opt, dd + 8 * 12, idata_rva + 0x30, 8)

    def section(name, vsize, va, rsize, rptr, chars):
        return struct.pack(
            "<8sIIIIIIHHI", name, vsize, va, rsize, rptr, 0, 0, 0, 0, chars
        )

    sections = [
        section(b".text", len(code), text_rva, 0x200, text_file, 0x60000020),
        section(b".idata", len(idata), idata_rva, 0x200, idata_file, 0xC0000040),
    ]
    headers = (
        bytes(dos) + b"PE\x00\x00" + coff + bytes(opt) + b"".join(sections)
    ).ljust(0x200, b"\x00")
    image = bytearray(0x3000)
    image[0:len(headers)] = headers
    image[text_file:text_file + len(code)] = code
    image[idata_file:idata_file + len(idata)] = idata
    return bytes(image)


def _elf64_exec(machine: int, text: bytes, symbols: list[tuple[str, int]]) -> bytes:
    """A minimal but well-formed ELF64 executable: one RX LOAD segment, a
    .text section and a static symbol table naming the functions, which is
    what blint's function discovery reads."""
    base = 0x400000
    text_off = 0x100
    shstr = b"\x00.text\x00.symtab\x00.strtab\x00.shstrtab\x00"
    shstr_off = text_off + len(text)
    strtab = b"\x00"
    name_offsets = {}
    for name, _ in symbols:
        name_offsets[name] = len(strtab)
        strtab += name.encode() + b"\x00"
    strtab_off = shstr_off + len(shstr)
    symtab = b"\x00" * 24
    for name, addr in symbols:
        symtab += struct.pack(
            "<IBBHQQ", name_offsets[name], 0x12, 0, 1, base + addr, 0
        )
    symtab_off = strtab_off + len(strtab)
    shoff = (symtab_off + len(symtab) + 7) & ~7

    def shdr(name_off, sh_type, flags, addr, offset, size, link, info, align, entsize):
        return struct.pack(
            "<IIQQQQIIQQ", name_off, sh_type, flags, addr, offset, size, link, info, align, entsize
        )

    shdrs = b"".join(
        [
            shdr(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            shdr(1, 1, 0x6, base + text_off, text_off, len(text), 0, 0, 16, 0),
            shdr(7, 2, 0, 0, symtab_off, len(symtab), 3, 1, 8, 24),
            shdr(15, 3, 0, 0, strtab_off, len(strtab), 0, 0, 1, 0),
            shdr(23, 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0),
        ]
    )
    total = shoff + len(shdrs)
    eh_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        eh_ident,  # e_ident
        2,         # e_type: ET_EXEC
        machine,   # e_machine
        1,         # e_version
        base + text_off,  # e_entry
        64,        # e_phoff
        shoff,     # e_shoff
        0,         # e_flags
        64,        # e_ehsize
        56,        # e_phentsize
        1,         # e_phnum
        64,        # e_shentsize
        5,         # e_shnum
        4,         # e_shstrndx
    )
    phdr = struct.pack(
        "<IIQQQQQQ", 1, 5, 0, base, base, total, total, 0x1000
    )
    image = bytearray(total)
    image[0:len(ehdr)] = ehdr
    image[64:64 + len(phdr)] = phdr
    image[text_off:text_off + len(text)] = text
    image[shstr_off:shstr_off + len(shstr)] = shstr
    image[strtab_off:strtab_off + len(strtab)] = strtab
    image[symtab_off:symtab_off + len(symtab)] = symtab
    image[shoff:shoff + len(shdrs)] = shdrs
    return bytes(image)


def _x86_elf_code() -> tuple[bytes, list[tuple[str, int]]]:
    """Stub + caller + decoy, hand-assembled from encodings verified against
    LLVM: the caller puts the ground-truth code in esi (SysV argument 2) and
    calls the stub; the decoys never sit in an argument register at a call."""
    stub = b"\x31\xc0\xc3"                                    # xor eax, eax; ret
    issue = (
        b"\xbf\x99\x01\x00\x00"                               # mov edi, 0x199
        + b"\xbe" + struct.pack("<I", GROUND_TRUTH_CODE_1)    # mov esi, code 1
        + b"\x31\xd2"                                         # xor edx, edx
    )
    # call stub: rel32 counts from the instruction *after* the call.
    call_addr = 0x103 + len(issue)
    issue += b"\xe8" + struct.pack("<i", 0x100 - (call_addr + 5)) + b"\xc3"
    decoy = (
        b"\xb8" + struct.pack("<I", GROUND_TRUTH_CODE_2)      # mov eax, code 2
        + b"\xbd" + struct.pack("<I", CALLEE_SAVED_DECOY)     # mov ebp, decoy
        + b"\xc3"                                             # ret
    )
    text = stub + issue + decoy
    symbols = [
        ("DeviceIoControl", 0x100),
        ("issue_ioctl", 0x103),
        ("decoy_ioctl", 0x103 + len(issue)),
    ]
    return text, symbols


def _aarch64_elf_code() -> tuple[bytes, list[tuple[str, int]]]:
    stub = struct.pack("<I", 0xD65F03C0)                      # ret
    issue = b"".join(
        struct.pack("<I", w)
        for w in (
            0x52800000 | ((GROUND_TRUTH_CODE_1 & 0xFFFF) << 5) | 1,   # movz w1, #low
            0xAA1F03E0,                                               # mov x0, xzr
            0x72A00000 | ((GROUND_TRUTH_CODE_1 >> 16) << 5) | 1,      # movk w1, #high, lsl 16
        )
    )
    bl_addr = 0x104 + len(issue)
    issue += struct.pack("<I", 0x94000000 | ((0x100 - bl_addr) >> 2 & 0x3FFFFFF))
    issue += struct.pack("<I", 0xD65F03C0)                    # ret
    decoy = (
        struct.pack("<I", 0x52800000 | ((GROUND_TRUTH_CODE_2 & 0xFFFF) << 5) | 9)
        + struct.pack("<I", 0xD65F03C0)                       # movz w9, #low; ret
    )
    text = stub + issue + decoy
    symbols = [
        ("DeviceIoControl", 0x100),
        ("issue_ioctl", 0x104),
        ("decoy_ioctl", 0x104 + len(issue)),
    ]
    return text, symbols


def test_pe64_client_ground_truth(tmp_path, monkeypatch):
    from blint.lib.binary import parse
    from blint.lib.driver_ioctl import collect_client_ioctls

    nyxstone_imports()
    exe = tmp_path / "client_pe64.exe"
    exe.write_bytes(_pe64_client())
    metadata = parse(str(exe), disassemble=True)
    functions = metadata.get("disassembled_functions") or {}
    assert functions, "the hand-built PE must yield disassembled functions"
    entries = collect_client_ioctls(functions, binary_format="PE")
    codes = {entry["code"] for entry in entries}
    assert codes == {"0x83352A01", "0x83352A05"}
    assert {entry["function"] for entry in entries} == {"IoDispatch"}
    # The decoys are plausible codes that never sit in an argument register.
    assert f"0x{RETURNED_DECOY:08X}" not in codes
    assert f"0x{CALLEE_SAVED_DECOY:08X}" not in codes


def nyxstone_imports():
    from blint.lib import disassembler

    if not disassembler.NYXSTONE_AVAILABLE:
        import pytest

        pytest.skip("nyxstone is not available")


def test_x86_elf_client_ground_truth(tmp_path):
    from blint.lib.binary import parse
    from blint.lib.driver_ioctl import collect_client_ioctls

    nyxstone_imports()
    text, symbols = _x86_elf_code()
    exe = tmp_path / "client_elf64"
    exe.write_bytes(_elf64_exec(62, text, symbols))  # EM_X86_64
    metadata = parse(str(exe), disassemble=True)
    functions = metadata.get("disassembled_functions") or {}
    assert functions, "the hand-built ELF must yield disassembled functions"
    entries = collect_client_ioctls(
        functions, arch_target="x86_64-pc-linux-gnu", binary_format="ELF"
    )
    codes = {entry["code"] for entry in entries}
    assert codes == {"0x83352A01"}, f" SysV ground truth mismatch: {codes}"
    assert f"0x{GROUND_TRUTH_CODE_2:08X}" not in codes
    assert f"0x{CALLEE_SAVED_DECOY:08X}" not in codes


def test_aarch64_elf_client_ground_truth(tmp_path):
    from blint.lib.binary import parse
    from blint.lib.driver_ioctl import collect_client_ioctls

    nyxstone_imports()
    text, symbols = _aarch64_elf_code()
    exe = tmp_path / "client_a64"
    exe.write_bytes(_elf64_exec(183, text, symbols))  # EM_AARCH64
    metadata = parse(str(exe), disassemble=True)
    functions = metadata.get("disassembled_functions") or {}
    assert functions, "the hand-built aarch64 ELF must yield disassembled functions"
    entries = collect_client_ioctls(
        functions, arch_target="aarch64-unknown-linux-gnu", binary_format="ELF"
    )
    codes = {entry["code"] for entry in entries}
    assert codes == {"0x83352A01"}, f" aarch64 ground truth mismatch: {codes}"
    assert f"0x{GROUND_TRUTH_CODE_2:08X}" not in codes


def test_recover_call_site_arguments_public_wrapper():
    func = _win64_deviceioctl_func(
        "mov edx, 2201297921\ncall qword ptr [rip + 4096]"   # 0x83352401
    )
    assert recover_call_site_arguments(func, "", "PE")[0]["arguments"][1] == 0x83352401
