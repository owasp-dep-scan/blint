"""Tests for recovery of string literals a binary assembles at runtime.

The assembly listings here are taken from the SLEEPWALKER sample described in
https://r136a1.dev/2026/08/24/sleepwalker-a-passive-backdoor-with-its-own-command-language/
(SHA-256 d347170752a28e2b8c4b8b9f3cab2e3a6541ba11682c94498d26eb9002779d60), which
builds every one of its device paths, registry keys and module names this way and
stores none of them as literals.
"""

from blint.lib.stack_strings import (
    recover_function_stack_strings,
    recover_stack_strings,
)

# The \\.\VMCI reconstruction, as blint disassembles it. Each character arrives
# as `lea eax, [rcx - N]` from the single loaded constant 92 ('\\'), and the
# `mov dword ptr [rbp - 28], 6029358` store carries ".\" as one dword.
VMCI_ASSEMBLY = """mov qword ptr [rsp + 24], rbx
push rbp
mov rbp, rsp
sub rsp, 96
mov ecx, 92
mov dword ptr [rbp - 28], 6029358
lea eax, [rcx - 15]
mov word ptr [rbp - 32], cx
mov word ptr [rbp - 22], ax
lea eax, [rcx - 19]
mov word ptr [rbp - 18], ax
mov eax, dword ptr [rip + 44186]
cmp eax, -1
jne 155
lea eax, [rcx - 6]
mov word ptr [rbp - 30], cx
xor edi, edi
mov word ptr [rbp - 24], ax
lea eax, [rcx - 25]
mov qword ptr [rsp + 48], rdi
lea rcx, [rbp - 32]
mov word ptr [rbp - 20], ax
mov word ptr [rbp - 16], di
call qword ptr [rip + 33959]
ret"""


def test_recovers_arithmetically_built_device_path():
    recovered = recover_function_stack_strings({"assembly": VMCI_ASSEMBLY})
    values = [entry["value"] for entry in recovered]
    assert "\\\\.\\VMCI" in values
    entry = next(e for e in recovered if e["value"] == "\\\\.\\VMCI")
    assert entry["encoding"] == "utf-16le"


def test_lea_of_a_frame_address_is_not_treated_as_a_character():
    """`lea rcx, [rbp - 32]` takes an address; reading it as a value corrupts the run."""
    assembly = "mov ecx, 65\nlea rdx, [rbp - 32]\nmov word ptr [rbp - 8], dx\nret"
    assert recover_function_stack_strings({"assembly": assembly}) == []


def test_wide_string_stored_as_immediates():
    # "PIPE" as two dword stores of UTF-16LE data: "PI" then "PE".
    assembly = "mov dword ptr [rbp - 16], 4784208\nmov dword ptr [rbp - 12], 4522064\nret"
    values = [e["value"] for e in recover_function_stack_strings({"assembly": assembly})]
    assert "PIPE" in values


def test_ascii_registry_value_recovered():
    assembly = "\n".join(
        [
            "mov byte ptr [rbp - 16], 78",  # N
            "mov byte ptr [rbp - 15], 117",  # u
            "mov byte ptr [rbp - 14], 108",  # l
            "mov byte ptr [rbp - 13], 108",  # l
            "mov byte ptr [rbp - 12], 0",
            "ret",
        ]
    )
    values = [e["value"] for e in recover_function_stack_strings({"assembly": assembly})]
    assert "Null" in values


def test_store_from_an_unknown_register_drops_the_slot():
    """A slot written with an unknown value must not keep an earlier byte."""
    assembly = "\n".join(
        [
            "mov byte ptr [rbp - 16], 65",
            "mov byte ptr [rbp - 15], 66",
            "mov byte ptr [rbp - 14], 67",
            "mov rax, qword ptr [rsi + 8]",
            "mov byte ptr [rbp - 15], al",
            "ret",
        ]
    )
    values = [e["value"] for e in recover_function_stack_strings({"assembly": assembly})]
    assert not any(value.startswith("ABC") for value in values)


def test_call_invalidates_volatile_registers():
    """A value in rax before a call must not be stored as a character after it."""
    assembly = "\n".join(
        [
            "mov eax, 65",
            "call qword ptr [rip + 100]",
            "mov byte ptr [rbp - 16], al",
            "mov byte ptr [rbp - 15], 66",
            "mov byte ptr [rbp - 14], 67",
            "mov byte ptr [rbp - 13], 68",
            "ret",
        ]
    )
    values = [e["value"] for e in recover_function_stack_strings({"assembly": assembly})]
    # BCD is recoverable; anything claiming to start with 'A' is not.
    assert not any(value.startswith("A") for value in values)


def test_misaligned_wide_decode_is_rejected():
    """A UTF-16LE run read one byte out of phase yields CJK, which is not text.

    Without an ASCII-only character test this is the single largest source of
    false recoveries, because every wide string has a well-formed misaligned
    reading.
    """
    # 'A\0B\0C\0D\0' shifted by one byte decodes to valid CJK code points.
    assembly = "\n".join(
        [
            "mov byte ptr [rbp - 15], 65",
            "mov byte ptr [rbp - 13], 66",
            "mov byte ptr [rbp - 11], 67",
            "mov byte ptr [rbp - 9], 68",
            "ret",
        ]
    )
    for entry in recover_function_stack_strings({"assembly": assembly}):
        assert entry["value"].isascii()


def test_arithmetic_residue_is_not_reported_as_text():
    """Call arguments and flags in a frame must not decode into findings."""
    assembly = "\n".join(
        [
            "mov dword ptr [rsp + 32], 3",
            "mov dword ptr [rsp + 40], 1073741824",
            "mov edx, 2147483648",
            "xor r9d, r9d",
            "xor r8d, r8d",
            "call qword ptr [rip + 33959]",
            "ret",
        ]
    )
    assert recover_function_stack_strings({"assembly": assembly}) == []


def test_empty_and_missing_assembly_are_handled():
    assert recover_function_stack_strings({}) == []
    assert recover_function_stack_strings({"assembly": ""}) == []
    assert recover_stack_strings(None) == []
    assert recover_stack_strings({}) == []


def test_recovery_names_the_function_and_deduplicates():
    functions = {
        "0x1000::sub_1000": {"name": "sub_1000", "address": "0x1000", "assembly": VMCI_ASSEMBLY},
        "0x2000::sub_2000": {"name": "sub_2000", "address": "0x2000", "assembly": VMCI_ASSEMBLY},
    }
    recovered = recover_stack_strings(functions)
    paths = [e for e in recovered if e["value"] == "\\\\.\\VMCI"]
    assert len(paths) == 1
    assert paths[0]["function"] == "sub_1000"
    assert paths[0]["address"] == "0x1000"


def test_hex_immediates_are_parsed():
    """The disassembler's integer base is a setting, so all renderings must work."""
    decimal = "mov ecx, 92\nmov word ptr [rbp - 8], cx\nmov word ptr [rbp - 6], cx\nret"
    hex_prefix = "mov ecx, 0x5c\nmov word ptr [rbp - 0x8], cx\nmov word ptr [rbp - 0x6], cx\nret"
    assert recover_function_stack_strings({"assembly": decimal}) == (
        recover_function_stack_strings({"assembly": hex_prefix})
    )
