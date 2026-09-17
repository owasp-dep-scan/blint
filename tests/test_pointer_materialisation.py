"""Tests for pointer materialisation.

Every address in these fixtures is ground truth taken from llvm-objdump on
/opt/homebrew/bin/x264 (arm64) — the instruction address, the rendered
operand and the target page were all read off real disassembly, not chosen
to make the arithmetic pass. The adrp sites sit mid-page on purpose: an
implementation missing the ``pc & ~0xFFF`` masking, or off by one
instruction, produces a different number than the asserted one.
"""

from blint.lib.absint import (
    ARM64_MODEL,
    X86_64_MODEL,
    FrameState,
    _line_address_spans,
    analyze_call_site_arguments,
    recover_call_site_arguments_with_method,
)

# llvm-objdump, x264 __text:
#   100000ab4: mov   (a plain instruction, so the adrp is not the block's first line)
#   100000ab8: adrp  x9, 0x10011a000     ; nyxstone renders: adrp x9, #1155072
#   100000abc: add   x9, x9, #1852      ; completes to 0x10011a73c
#   100000ac0: adrp  x20, 0x100134000    ; nyxstone renders: adrp x20, #1261568
#   100000ac4: ldr   x20, [x20, #72]    ; a load THROUGH the pointer
#   100000ad0: adrp  x1, 0x10011a000     ; nyxstone renders: adrp x1, #1155072
#   100000ad4: add   x1, x1, #1860      ; completes to 0x10011a744
_ADRP_COMPLETED = 0x10011A73C
_ADRP_PAGE = 0x100134000
_ADRP_COMPLETED_SECOND = 0x10011A744


def _arm64_func(assembly: str, blocks: list[dict] | None = None, **overrides) -> dict:
    lines = assembly.split("\n")
    func = {
        "name": "smoke_arm64",
        "address": "0x100000ab4",
        "assembly": assembly,
        "instruction_lengths": [4] * len(lines),
        "cfg": {
            "blocks": blocks
            or [
                {
                    "start": "0x100000ab4",
                    "end": hex(0x100000AB4 + 4 * len(lines)),
                    "instructions": len(lines),
                }
            ],
            "edges": [],
        },
        "direct_call_targets": [
            {"target_name": "_printf", "raw_operand": "_printf", "kind": "call"}
        ],
    }
    func.update(overrides)
    return func


def _x86_func(
    assembly: str, lengths: list[int], blocks: list[dict] | None = None, **overrides
) -> dict:
    lines = assembly.split("\n")
    func = {
        "name": "smoke_x86",
        "address": "0x1000",
        "assembly": assembly,
        "instruction_lengths": lengths,
        "cfg": {
            "blocks": blocks
            or [
                {
                    "start": "0x1000",
                    "end": hex(0x1000 + sum(lengths)),
                    "instructions": len(lines),
                }
            ],
            "edges": [],
        },
        "direct_call_targets": [
            {
                "target_name": "KERNEL32.dll::DeviceIoControl",
                "raw_operand": "qword ptr [rip + 4096]",
                "kind": "indirect_hint",
            }
        ],
    }
    func.update(overrides)
    return func


# ---------------------------------------------------------------------------
# ARM64: the adrp/add pair completes into the llvm-objdump address.
# ---------------------------------------------------------------------------


def test_arm64_adrp_add_completes_to_llvm_objdump_address():
    # The adrp is the second line, so its address is block start + 4: an
    # off-by-one here resolves a different page-base than 0x10011a000.
    assembly = "mov x10, #1\nadrp x9, #1155072\nadd x9, x9, #1852\nmov x0, x9\nbl _printf"
    func = _arm64_func(
        assembly,
        blocks=[{"start": "0x100000ab4", "end": "0x100000ac8", "instructions": 5}],
    )
    records, method = recover_call_site_arguments_with_method(
        func, "aarch64-apple-macosx", "MachO"
    )
    assert method == "dataflow"
    calls = [r for r in records if r["instruction"].startswith("bl")]
    assert len(calls) == 1
    assert calls[0]["arguments"][0] == _ADRP_COMPLETED
    assert calls[0]["materialised"] == 1
    assert calls[0]["materialised_page"] == 0


def test_arm64_completed_pointer_moves_between_registers_and_arithmetic():
    assembly = "adrp x1, #1155072\nadd x1, x1, #1860\nmov x0, x1\nbl _printf"
    func = _arm64_func(assembly)
    records, method = recover_call_site_arguments_with_method(
        func, "aarch64-apple-macosx", "MachO"
    )
    assert method == "dataflow"
    calls = [r for r in records if r["instruction"].startswith("bl")]
    assert calls[0]["arguments"][0] == _ADRP_COMPLETED_SECOND
    assert calls[0]["arguments"][0] == 0x10011A000 + 1860


def test_arm64_ldr_through_adrp_base_stays_unknown():
    # adrp x20, 0x100134000; ldr x20, [x20, #72] is a load *through* the
    # pointer. Reporting 0x100134000 — or anything — as the value would
    # manufacture a pointer; the honest result is unknown.
    assembly = "adrp x20, #1261568\nldr x20, [x20, #72]\nmov x0, x20\nbl _printf"
    func = _arm64_func(assembly)
    records, method = recover_call_site_arguments_with_method(
        func, "aarch64-apple-macosx", "MachO"
    )
    assert method == "dataflow"
    calls = [r for r in records if r["instruction"].startswith("bl")]
    assert calls[0]["arguments"][0] is None
    assert calls[0]["materialised"] == 0


def test_arm64_bare_adrp_page_is_reported_and_counted():
    # adrp passed straight to a call: the page is what the register held.
    assembly = "adrp x0, #1261568\nbl _printf"
    func = _arm64_func(assembly)
    records, method = recover_call_site_arguments_with_method(
        func, "aarch64-apple-macosx", "MachO"
    )
    assert method == "dataflow"
    calls = [r for r in records if r["instruction"].startswith("bl")]
    assert calls[0]["arguments"][0] == _ADRP_PAGE
    assert calls[0]["materialised"] == 1
    assert calls[0]["materialised_page"] == 1


def test_arm64_without_line_addresses_keeps_legacy_symbolic():
    # Blocks without start/end VAs (the shape every older fixture has):
    # no address, no materialisation, and the reason named in coverage.
    assembly = "adrp x9, #1155072\nadd x9, x9, #1852\nmov x0, x9\nbl _printf"
    func = _arm64_func(
        assembly,
        blocks=[{"instructions": 4}],
        instruction_lengths=None,
    )
    del func["instruction_lengths"]
    records, method = recover_call_site_arguments_with_method(
        func, "aarch64-apple-macosx", "MachO"
    )
    assert method == "dataflow"
    calls = [r for r in records if r["instruction"].startswith("bl")]
    assert calls[0]["arguments"][0] is None
    assert calls[0]["materialised"] == 0
    _, coverage = analyze_call_site_arguments({"k": func}, "aarch64-apple-macosx", "MachO")
    assert coverage["functions_no_line_addresses"] == 1


def test_arm64_stride_fallback_without_exported_lengths():
    # arm64's fixed 4-byte word serves when the lengths array is absent
    # (metadata cached by an older blint): the addresses stay computable.
    assembly = "adrp x9, #1155072\nadd x9, x9, #1852\nmov x0, x9\nbl _printf"
    func = _arm64_func(assembly)
    del func["instruction_lengths"]
    records, method = recover_call_site_arguments_with_method(
        func, "aarch64-apple-macosx", "MachO"
    )
    assert method == "dataflow"
    calls = [r for r in records if r["instruction"].startswith("bl")]
    assert calls[0]["arguments"][0] == _ADRP_COMPLETED


def test_arm64_block_extent_contradicting_instruction_count_is_named():
    # The block claims 4 instructions but its extent covers 3: the address
    # arithmetic would be built on a lie, so it is refused and counted.
    assembly = "adrp x9, #1155072\nadd x9, x9, #1852\nmov x0, x9\nbl _printf"
    func = _arm64_func(
        assembly,
        blocks=[{"start": "0x100000ab4", "end": "0x100000ac0", "instructions": 4}],
    )
    records, method = recover_call_site_arguments_with_method(
        func, "aarch64-apple-macosx", "MachO"
    )
    assert method == "dataflow"
    calls = [r for r in records if r["instruction"].startswith("bl")]
    assert calls[0]["arguments"][0] is None
    _, coverage = analyze_call_site_arguments({"k": func}, "aarch64-apple-macosx", "MachO")
    assert coverage["functions_extent_mismatch"] == 1


def test_arm64_unmodelled_pc_relative_form_is_named():
    # `adr` (the pc-relative form the model deliberately does not fold).
    assembly = "adr x0, #8\nbl _printf"
    func = _arm64_func(assembly)
    _, coverage = analyze_call_site_arguments({"k": func}, "aarch64-apple-macosx", "MachO")
    assert coverage["functions_unmodelled_pc_relative"] == 1


# ---------------------------------------------------------------------------
# x86-64: rip-relative lea.
# ---------------------------------------------------------------------------


def test_x86_rip_relative_lea_materialises_next_instruction_target():
    # Real nyxstone rendering at 0x1000 (7 bytes): lea rax, [rip + 7978]
    # reads rip as 0x1007, so the target is 0x2f2f.
    assembly = "lea rdi, [rip + 7978]\nxor esi, esi\nxor edx, edx\ncall qword ptr [rip + 4096]"
    func = _x86_func(assembly, [7, 3, 3, 6])
    records, method = recover_call_site_arguments_with_method(func, "x86_64-apple-macosx", "MachO")
    assert method == "dataflow"
    calls = [r for r in records if r["instruction"].startswith("call")]
    assert calls[0]["arguments"][0] == 0x1000 + 7 + 7978
    assert calls[0]["materialised"] == 1


def test_x86_rip_relative_lea_negative_displacement():
    assembly = "lea rax, [rip - 32]\nmov rdi, rax\ncall qword ptr [rip + 4096]"
    func = _x86_func(assembly, [7, 3, 6])
    records, method = recover_call_site_arguments_with_method(func, "x86_64-apple-macosx", "MachO")
    assert method == "dataflow"
    calls = [r for r in records if r["instruction"].startswith("call")]
    assert calls[0]["arguments"][0] == 0x1000 + 7 - 32


def test_x86_lea_rip_without_addresses_is_invalidated_and_named():
    assembly = "lea rdi, [rip + 7978]\ncall qword ptr [rip + 4096]"
    func = _x86_func(
        assembly,
        [7, 6],
        blocks=[{"instructions": 2}],
    )
    del func["instruction_lengths"]
    records, method = recover_call_site_arguments_with_method(func, "x86_64-apple-macosx", "MachO")
    assert method == "dataflow"
    calls = [r for r in records if r["instruction"].startswith("call")]
    assert calls[0]["arguments"][0] is None
    _, coverage = analyze_call_site_arguments({"k": func}, "x86_64-apple-macosx", "MachO")
    assert coverage["functions_no_line_addresses"] == 1


def test_x86_lengths_misaligned_with_listing_are_refused():
    # A lengths array that does not describe this listing would place the
    # lea somewhere else: refused outright.
    assembly = "lea rdi, [rip + 7978]\ncall qword ptr [rip + 4096]"
    func = _x86_func(assembly, [7, 6])
    func["instruction_lengths"] = [7, 5]
    records, _method = recover_call_site_arguments_with_method(
        func, "x86_64-apple-macosx", "MachO"
    )
    calls = [r for r in records if r["instruction"].startswith("call")]
    assert calls[0]["arguments"][0] is None


def test_x86_materialised_pointer_stored_to_frame_is_not_a_string():
    # The materialised address is a pointer, not character data: storing it
    # into the frame must drop the slot bytes, never feed the string
    # decoder with address bytes.
    state = FrameState(X86_64_MODEL)
    X86_64_MODEL.step(state, "lea rax, [rip + 7978]", address_span=(0x1000, 0x1007))
    X86_64_MODEL.step(state, "mov qword ptr [rbp - 8], eax")
    X86_64_MODEL.step(state, "mov qword ptr [rbp - 16], rax")
    assert state.slots == {}


# ---------------------------------------------------------------------------
# The block builder: counters and the resolver seam.
# ---------------------------------------------------------------------------


def test_block_counts_materialised_arguments_and_resolved_strings():
    assembly = "adrp x0, #1155072\nadd x0, x0, #1852\nbl _printf"
    func = _arm64_func(
        assembly,
        direct_call_targets=[{"target_name": "printf", "raw_operand": "_printf", "kind": "call"}],
    )
    entries, coverage = analyze_call_site_arguments(
        {"k": func},
        "aarch64-apple-macosx",
        "MachO",
        resolve_string=lambda value: "/etc/passwd" if value == _ADRP_COMPLETED else None,
    )
    assert coverage["arguments_materialised"] == 1
    assert coverage["strings_resolved"] == 1
    assert len(entries) == 1
    assert entries[0]["value"] == _ADRP_COMPLETED
    assert entries[0]["string"] == "/etc/passwd"


def test_materialised_and_immediate_sites_aggregate_without_conflict():
    # The same callee/position reached once with a materialised pointer and
    # once with an immediate stays two distinct entries: values differ.
    arm = _arm64_func(
        "adrp x0, #1155072\nadd x0, x0, #1852\nbl _printf",
        direct_call_targets=[{"target_name": "printf", "raw_operand": "_printf", "kind": "call"}],
    )
    arm2 = _arm64_func(
        "mov x0, #5\nbl _printf",
        name="arm2",
        direct_call_targets=[{"target_name": "printf", "raw_operand": "_printf", "kind": "call"}],
    )
    entries, coverage = analyze_call_site_arguments(
        {"a": arm, "b": arm2}, "aarch64-apple-macosx", "MachO"
    )
    assert coverage["entries"] == 2
    values = {entry["value"] for entry in entries}
    assert values == {_ADRP_COMPLETED, 5}


def test_line_address_spans_rejects_missing_block_vas():
    spans, reason = _line_address_spans(
        ARM64_MODEL,
        ["nop", "nop"],
        [{"instructions": 2}],
        [(0, 2)],
        [4, 4],
    )
    assert spans is None
    assert reason == "no_addresses"


# ---------------------------------------------------------------------------
# The anti-self-confirmation test: the arithmetic against a real image.
# ---------------------------------------------------------------------------


def test_materialised_strings_resolve_in_a_real_image():
    """Any string the materialised pointer names must really live there.

    Checked against the one authority that did not produce it: the image's
    own bytes, read straight off the recovered address. Re-running the
    resolver would only prove it is deterministic — it is the function that
    produced the string in the first place — so the bytes are compared
    here instead. A fixture cannot certify address arithmetic; this can.
    """
    import lief
    import pytest

    from blint.lib.binary import parse

    parsed = lief.parse("/bin/ls")
    if parsed is None:  # pragma: no cover - platform without the fixture
        pytest.skip("/bin/ls is not parseable here")
    metadata = parse("/bin/ls", disassemble=True)
    entries = metadata.get("call_site_arguments") or []
    resolved = [entry for entry in entries if entry.get("string")]
    if not resolved:  # pragma: no cover - disassembly unavailable on this run
        pytest.skip("no strings resolved on this platform's slice")
    for entry in resolved[:20]:
        expected = entry["string"].encode("utf-8")
        raw = bytes(parsed.get_content_from_virtual_address(entry["value"], len(expected) + 1))
        assert raw == expected + b"\x00"


def test_narrow_write_of_a_materialised_pointer_reports_nothing():
    """A w-register holds the low half of an address, which is not the address.

    Passing the full 64-bit value on would name a pointer the hardware
    never formed — and the block would then resolve whatever string
    happens to live there.
    """
    state = FrameState(ARM64_MODEL)
    ARM64_MODEL.step(state, "adrp x9, #1155072", address_span=(0x100000AB8, 0x100000ABC))
    ARM64_MODEL.step(state, "mov w0, w9")
    assert state.registers.get("x0") is None
    # The same on the completion path: `add w9, w9, #4` cannot carry it either.
    ARM64_MODEL.step(state, "add w9, w9, #4")
    assert state.registers.get("x9") is None

    state = FrameState(X86_64_MODEL)
    X86_64_MODEL.step(state, "lea rax, [rip + 7978]", address_span=(0x1000, 0x1007))
    X86_64_MODEL.step(state, "mov edi, eax")
    assert state.registers.get("rdi") is None
    # The full-width move still carries it.
    X86_64_MODEL.step(state, "mov rsi, rax")
    assert state.registers.get("rsi") == ("ptr", 0x1000 + 7 + 7978)
