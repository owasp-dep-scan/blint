"""Tests for the CFG-ordered abstract interpreter in ``blint.lib.absint``.

The dataflow claims in the module docstring are exercised here one by one:
values merge to *unknown* where incoming paths disagree (registers and
frame slots alike), values assembled on a not-taken branch path do not leak
into the recovered strings, loops converge, the iteration cap is observable
rather than silent, unreachable blocks contribute nothing, and functions
without a usable CFG keep the straight-line pass.

The decode ground truth in ``TestDecodeGroundTruth`` is external to this
codebase's model: the byte sequence is the head of ``__do_fini`` from the
stripped static-PIE Rust corpus binary, read out of that binary with
independent tooling (``objdump -d``, which agrees byte-for-byte with
LIEF's ``get_content_from_virtual_address``). The fixture layout reproduces
the conditions that corrupted that binary's decode before the fix: the
only known function sits above the executable segment's first byte, so a
"rebase everything by the distance to the segment start" heuristic reads a
different function's bytes.
"""

import logging
import struct
import time

import pytest

from blint.lib.absint import (
    X86_64_MODEL,
    interpret_over_cfg,
    recover_function_stack_strings_with_method,
)
from blint.lib.stack_strings import analyze_stack_strings, recover_stack_strings


def _cfg(blocks: list[int], edges: list[tuple[int, int, str]]) -> dict:
    """Build a minimal per-function CFG from instruction counts and edges."""
    block_list = []
    addr = 0x1000
    for count in blocks:
        block_list.append({"start": hex(addr), "end": hex(addr + count), "instructions": count})
        addr += count
    return {
        "blocks": block_list,
        "edges": [{"src": s, "dst": d, "kind": k} for s, d, k in edges],
    }


def _recover(lines: list[str], cfg: dict, arch_target: str = ""):
    return recover_function_stack_strings_with_method(
        {"assembly": "\n".join(lines), "cfg": cfg}, arch_target
    )


# ---------------------------------------------------------------------------
# The join: conflicting values become unknown, agreeing values survive.
# ---------------------------------------------------------------------------


def test_join_drops_register_conflicting_between_paths():
    """A register holding different values on two arms is unknown after the merge."""
    lines = [
        "mov eax, 65",  # block 0: 'A'
        "cmp ecx, 1",
        "jne 4098",
        "mov eax, 66",  # block 1 (taken arm): 'B'
        "jmp 4100",
        "nop",  # block 2 (merge)
        "mov byte ptr [rbp - 8], al",
        "mov byte ptr [rbp - 7], 67",
        "mov byte ptr [rbp - 6], 68",
        "ret",
    ]
    cfg = _cfg(
        [3, 2, 5],
        [(0, 1, "conditional"), (0, 2, "conditional"), (1, 2, "jump")],
    )
    entries, method = _recover(lines, cfg)
    assert method == "dataflow"
    # Neither 'A' nor 'B' is the value at the merge, so nothing starting with
    # either may be reported — the straight-line pass would have stored 'B'.
    assert all(not entry["value"].startswith(("A", "B")) for entry in entries)


def test_string_built_on_one_arm_is_reported_as_construction_evidence():
    """A string assembled on one path is evidence, even though a later merge
    makes the slot unknown from there onward.

    The other arm stores nothing, so the merge's in-state drops the bytes and
    an exit-aggregated reading would report nothing — but the block that
    completed the string still holds it, and the function did construct it.
    This is the shape that cost the exit-aggregated traversal 85 of the 99
    strings the straight-line pass recovered on the measurement corpus:
    buffers rebuilt for a second purpose on the dominant path (dyld's
    ``dlopen`` wrapper, OrbStack's ObjC selectors).
    """
    lines = [
        "cmp ecx, 1",
        "jne 4098",
        "mov dword ptr [rbp - 16], 1145258561",  # 'ABCD' — this arm only
        "jmp 4100",
        "nop",  # merge: the other arm stored nothing
        "ret",
    ]
    cfg = _cfg([2, 2, 2], [(0, 1, "conditional"), (0, 2, "conditional"), (1, 2, "jump")])
    entries, method = _recover(lines, cfg)
    assert method == "dataflow"
    assert [entry["value"] for entry in entries] == ["ABCD"]


def test_string_conflicting_at_a_merge_does_not_leak_past_the_merge():
    """The convergence, not the decode filter, kills conflicting values.

    Both arms build *different* strings in the same slot; each is reported
    from the block that built it, but after the merge the slot's value is
    unknown (the arms disagree), so a post-merge store fed from a register
    the merge made unknown completes no run of its own.
    """
    lines = [
        "cmp ecx, 1",
        "jne 4098",
        "mov dword ptr [rbp - 16], 1145258561",  # arm 1: 'ABCD'
        "jmp 4100",
        "mov dword ptr [rbp - 16], 1212630597",  # arm 2: 'EFGH'
        "nop",  # merge: [rbp - 16] differs per path -> unknown from here
        "mov byte ptr [rbp - 32], al",  # al is unknown at the merge
        "mov byte ptr [rbp - 31], 73",  # 'I'
        "mov byte ptr [rbp - 30], 74",  # 'J'
        "mov byte ptr [rbp - 29], 75",  # 'K'
        "ret",
    ]
    cfg = _cfg([2, 2, 7], [(0, 1, "conditional"), (0, 2, "conditional"), (1, 2, "jump")])
    entries, method = _recover(lines, cfg)
    assert method == "dataflow"
    values = [entry["value"] for entry in entries]
    # Each arm's string is reported from the block that built it; 'IJK' is a
    # real construction of known immediates; and the merge-unknown slot
    # cannot splice any of them together into a longer run.
    assert sorted(values) == ["ABCD", "EFGH", "IJK"]


def test_later_slot_reuse_does_not_un_construct_an_earlier_string():
    """The dyld ``dlopen`` shape: string built late, slot reused on the
    dominant path after a merge, no exit holding the bytes.

    The function builds 'ABCD' at [rbp-16] on one path; the loop before it
    reuses the same slot for a counter value, so the slot is unknown along
    the path that reaches the exit without the string. An exit-aggregated
    picture reports nothing here; the construction still happened and the
    block that completed it carries it.
    """
    lines = [
        "xor ecx, ecx",  # block 0: loop head
        "mov dword ptr [rbp - 16], ecx",  # slot reused for a counter
        "add ecx, 1",
        "cmp ecx, 10",
        "jl 4096",  # back edge to block 0
        "cmp edx, 3",  # block 1: loop exit, branch on something else
        "jne 4104",
        "mov dword ptr [rbp - 16], 1145258561",  # block 2: 'ABCD'
        "jmp 4105",
        "nop",  # block 3: merge — slot is 'ABCD' on one path, counter on the other
        "mov eax, dword ptr [rbp - 16]",  # read (value unknown at the merge)
        "ret",  # block 4: the only exit; no exit state holds 'ABCD'
    ]
    cfg = _cfg(
        [5, 2, 2, 1, 2],
        [
            (0, 0, "conditional"),
            (0, 1, "conditional"),
            (1, 2, "conditional"),
            (1, 3, "conditional"),
            (2, 3, "jump"),
            (3, 4, "fallthrough"),
        ],
    )
    entries, method = _recover(lines, cfg)
    assert method == "dataflow"
    assert "ABCD" in [entry["value"] for entry in entries]


def test_a_string_assembled_across_blocks_is_reported_once_at_full_length():
    """Harvesting every block's state must not report a string per block.

    The three stores build one 12-byte run, but each block's out-state holds
    it complete to a different length, so reading them all sees 'ABCD',
    'ABCDEFGH' and the whole string. Only the last is the string the function
    built. On OrbStack this shape reported nine readings of one 'ftsvSOiIpom'
    built at sp+21, 12 of 104 reported values there being partial readings of
    another.
    """
    lines = [
        "mov dword ptr [rbp - 32], 1145258561",  # 'ABCD'
        "nop",
        "mov dword ptr [rbp - 28], 1212630597",  # 'EFGH'
        "nop",
        "mov dword ptr [rbp - 24], 1280002633",  # 'IJKL'
        "ret",
    ]
    cfg = _cfg([2, 2, 2], [(0, 1, "fallthrough"), (1, 2, "fallthrough")])
    entries, method = _recover(lines, cfg)
    assert method == "dataflow"
    assert [entry["value"] for entry in entries] == ["ABCDEFGHIJKL"]


def test_a_shorter_string_elsewhere_in_the_frame_is_not_a_partial_reading():
    """Only a longer run covering the same bytes at the same address wins.

    'ABCD' built at its own slot is a string in its own right even though the
    other slot's 'ABCDEFGH' begins with the same letters — collapsing on the
    decoded text alone would drop it.
    """
    lines = [
        "mov dword ptr [rbp - 64], 1145258561",  # 'ABCD' at its own slot
        "mov dword ptr [rbp - 32], 1145258561",  # 'ABCD...
        "mov dword ptr [rbp - 28], 1212630597",  # ...EFGH' at another
        "ret",
    ]
    cfg = _cfg([4], [])
    entries, method = _recover(lines, cfg)
    assert method == "dataflow"
    assert sorted(entry["value"] for entry in entries) == ["ABCD", "ABCDEFGH"]


def test_an_undecodable_longer_run_does_not_absorb_the_string_inside_it():
    """A run the decoder rejects must not take a real reading down with it.

    The later store extends 'ABCD' with control bytes, so the 8-byte run is
    not text and reports nothing. Suppressing 'ABCD' as a partial reading of
    it would lose the string entirely — the shape that cost OrbStack
    '--since', 'Challenge', '[ipv' and 'ipv'.
    """
    lines = [
        "mov dword ptr [rbp - 32], 1145258561",  # 'ABCD'
        "nop",
        "mov dword ptr [rbp - 28], 67305985",  # control bytes, not text
        "ret",
    ]
    cfg = _cfg([2, 2], [(0, 1, "fallthrough")])
    entries, method = _recover(lines, cfg)
    assert method == "dataflow"
    assert [entry["value"] for entry in entries] == ["ABCD"]


def test_join_keeps_slot_bytes_written_identically_on_both_arms():
    same_store = "mov dword ptr [rbp - 16], 1145258561"  # 'ABCD'
    lines = [
        "cmp ecx, 1",
        "jne 4098",
        same_store,  # arm 1
        "jmp 4100",
        same_store,  # arm 2
        "ret",
    ]
    cfg = _cfg([2, 2, 2], [(0, 1, "conditional"), (0, 2, "conditional"), (1, 2, "jump")])
    entries, method = _recover(lines, cfg)
    assert method == "dataflow"
    assert "ABCD" in [entry["value"] for entry in entries]


def test_values_after_a_ret_do_not_leak_into_the_result():
    """The docstring's headline: residue from an unexecuted path must not surface.

    The string is assembled entirely after the function's ``ret``, so no
    path from the entry reaches those stores. A straight-line pass reads
    them anyway; the dataflow must not.
    """
    lines = [
        "ret",
        "mov dword ptr [rbp - 8], 1145258561",  # unreachable from the entry
        "mov dword ptr [rbp - 4], 1145258561",
    ]
    cfg = _cfg([1, 2], [])
    entries, method = _recover(lines, cfg)
    assert method == "dataflow"
    assert [entry["value"] for entry in entries] == []


# ---------------------------------------------------------------------------
# Loops and the iteration cap.
# ---------------------------------------------------------------------------


def test_loop_converges_and_outer_string_survives():
    lines = [
        "mov dword ptr [rbp - 16], 1145258561",  # 'ABCD' before the loop
        "xor ecx, ecx",  # block 0
        "nop",  # block 1: loop body
        "add ecx, 1",
        "cmp ecx, 10",
        "jl 4100",  # back edge to block 1's start (0x1000 + 2 instructions)
        "nop",  # block 2: exit
        "ret",
    ]
    cfg = _cfg(
        [2, 4, 2],
        [(0, 1, "fallthrough"), (1, 1, "conditional"), (1, 2, "conditional")],
    )
    entries, method = _recover(lines, cfg)
    assert method == "dataflow"
    assert "ABCD" in [entry["value"] for entry in entries]


def test_iteration_cap_is_observable_not_silent(monkeypatch):
    """Hitting the cap drops the function's strings and says so in the counters."""
    lines = [
        "xor ecx, ecx",
        "add ecx, 1",  # loop body
        "jmp 4102",
        "ret",
    ]
    cfg = _cfg([1, 3], [(0, 1, "fallthrough"), (1, 1, "jump")])
    monkeypatch.setattr("blint.lib.absint.MAX_BLOCK_VISITS", 1)
    entries, method = _recover(lines, cfg)
    assert method == "cap_hit"
    assert entries == []
    functions = {
        "0x1000::sub_1000": {
            "name": "sub_1000",
            "address": "0x1000",
            "assembly": "xor ecx, ecx\nadd ecx, 1\njmp 4102\nret",
            "cfg": cfg,
        }
    }
    recovered, counters = analyze_stack_strings(functions)
    assert recovered == []
    assert counters["functions_iteration_cap_hit"] == 1
    assert counters["functions_dataflow"] == 0


def test_loop_carried_counter_goes_unknown_without_touching_the_cap():
    """Loop-carried arithmetic meets at a conflict within a couple of rounds."""
    lines = [
        "xor ecx, ecx",
        "add ecx, 1",
        "cmp ecx, 1000",
        "jl 4100",
        "ret",
    ]
    cfg = _cfg([1, 4], [(0, 1, "fallthrough"), (1, 1, "conditional")])
    state = interpret_over_cfg(lines, X86_64_MODEL, cfg["blocks"], cfg["edges"])
    assert state is not None  # converged without hitting the cap
    assert state.registers.get("rcx") is None  # and the counter is unknown


# ---------------------------------------------------------------------------
# Coverage bookkeeping and the fallback.
# ---------------------------------------------------------------------------


def test_no_cfg_falls_back_to_straight_line():
    """Rule: the straight-line pass remains for functions with no usable CFG."""
    assembly = (
        "mov byte ptr [rbp - 16], 78\n"  # N
        "mov byte ptr [rbp - 15], 117\n"  # u
        "mov byte ptr [rbp - 14], 108\n"  # l
        "mov byte ptr [rbp - 13], 108\n"  # l
        "ret"
    )
    entries, method = recover_function_stack_strings_with_method({"assembly": assembly})
    assert method == "fallback"
    assert "Null" in [entry["value"] for entry in entries]


def test_mismatched_cfg_tiles_fall_back_loudly(caplog):
    """Blocks that do not tile the text warn and use the straight-line pass."""
    assembly = "mov eax, 1\nret"
    cfg = {"blocks": [{"start": "0x1000", "end": "0x1009", "instructions": 9}], "edges": []}
    with caplog.at_level(logging.WARNING, logger="blint"):
        _, method = recover_function_stack_strings_with_method(
            {"assembly": assembly, "cfg": cfg}
        )
    assert method == "fallback"
    assert any("do not tile" in record.getMessage() for record in caplog.records)


def test_analyze_stack_strings_counters():
    good = "mov dword ptr [rbp - 8], 1145258561\nret"
    cfg = _cfg([2], [])
    functions = {
        "0x1000::sub_1000": {"name": "sub_1000", "address": "0x1000", "assembly": good, "cfg": cfg},
        "0x2000::sub_2000": {"name": "sub_2000", "address": "0x2000", "assembly": good},
        "0x3000::sub_3000": {"name": "sub_3000", "address": "0x3000"},
    }
    recovered, counters = analyze_stack_strings(functions)
    assert counters == {
        "functions_total": 3,
        "functions_dataflow": 1,
        "functions_fallback": 1,
        "functions_iteration_cap_hit": 0,
    }
    assert recover_stack_strings(functions) == recovered


def test_arm64_dataflow_recovers_string():
    """The ARM64 model runs under the same dataflow (gate: /usr/lib must survive)."""
    lines = [
        "movz w8, #0x752F",
        "movk w8, #0x7273, lsl #16",
        "str w8, [sp, #8]",
        "ret",
    ]
    cfg = _cfg([4], [])
    entries, method = _recover(lines, cfg, "aarch64-apple-darwin")
    assert method == "dataflow"
    assert "/usr" in [entry["value"] for entry in entries]


# ---------------------------------------------------------------------------
# Bounded growth (rule 12: per-function algorithms need a wall-clock bound).
# ---------------------------------------------------------------------------


def test_dense_cfg_completes_bounded():
    """A deliberately dense diamond chain must stay far inside its time budget."""
    chain = 300
    blocks: list[int] = []
    edges: list[tuple[int, int, str]] = []
    lines: list[str] = ["cmp ecx, 1", "jne 4102"]  # block 0: entry
    blocks.append(2)
    current = 0
    for i in range(chain):
        arm_a = len(blocks)
        blocks.append(2)
        lines += ["mov dword ptr [rbp - 16], 1145258561", "jmp 8192"]
        arm_b = len(blocks)
        blocks.append(2)
        lines += ["mov dword ptr [rbp - 16], 1145258561", "nop"]
        merge = len(blocks)
        blocks.append(2)
        lines += [f"cmp edx, {i}", "jne 4098"]
        edges += [
            (current, arm_a, "fallthrough"),
            (current, arm_b, "conditional"),
            (arm_a, merge, "jump"),
            (arm_b, merge, "fallthrough"),
        ]
        current = merge
    blocks.append(1)
    lines += ["ret"]
    edges.append((current, len(blocks) - 1, "fallthrough"))
    cfg = _cfg(blocks, edges)
    assert len(blocks) == 3 * chain + 2

    started = time.monotonic()
    entries, method = _recover(lines, cfg)
    elapsed = time.monotonic() - started
    assert method == "dataflow"
    assert "ABCD" in [entry["value"] for entry in entries]
    assert elapsed < 30.0, f"dense synthetic CFG took {elapsed:.1f}s"


# ---------------------------------------------------------------------------
# Decode ground truth (rule 22): raw bytes at a known address.
# ---------------------------------------------------------------------------


def _build_minimal_x86_elf() -> bytes:
    """A minimal static ELF whose single known function sits above .text start.

    Layout: one R+E LOAD whose mapped content begins with a decoy "previous
    function" (``mov eax, 0x1234 ; ret`` plus int3 padding); the function
    under test starts 0x20 bytes in. This is the situation that corrupted
    the corpus fixtures before the fix: with the only known function above
    the executable segment's first byte, the "rebase everything by the
    distance to the segment start" heuristic read the decoy's bytes for the
    function's address (and x86 decodes the decoy happily, so the wrong
    read always won).
    """
    decoy = b"\xb8\x34\x12\x00\x00\xc3" + b"\xcc" * 26  # 32 bytes at .text start
    # Head of __do_fini from corpus-build/rust-elf-stripped at 0x19070,
    # verified against objdump: cmp byte ptr [rip+0x57201], 0 / jne +0x5f.
    function = (
        b"\x80\x3d\x01\x72\x05\x00\x00"  # cmp byte ptr [rip + 356865], 0
        b"\x75\x5f"  # jne +0x5f
        b"\x48\x83\x3d\x57\x4d\x05\x00"  # cmp qword ptr [rip + 347479], 0
        b"\xc3"
        + b"\xcc" * (105 - 7 - 2 - 7 - 1)
    )
    assert len(function) == 105
    code = decoy + function
    code_off = 64 + 56  # after Ehdr + Phdr
    text_addr = 0x1000  # LOAD maps the code (file offset 120) here
    shstr = b"\x00.text\x00.shstrtab\x00"
    shstr_off = code_off + len(code)
    shoff = (shstr_off + len(shstr) + 7) & ~7

    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8,
        2,  # ET_EXEC
        62,  # x86-64
        1,
        text_addr,  # entry
        64,  # phoff
        shoff,
        0,
        64,
        56,
        1,  # ehsize, phentsize, phnum
        64,
        3,
        2,  # shentsize, shnum, shstrndx
    )
    phdr = struct.pack(
        "<IIQQQQQQ",
        1,  # PT_LOAD
        5,  # PF_R | PF_X
        code_off,  # the segment's content is the code, not the headers
        text_addr,
        text_addr,
        len(code),
        len(code),
        0x1000,
    )
    text_sh = struct.pack(
        "<IIQQQQIIQQ", 1, 1, 0x6, text_addr, code_off, len(code), 0, 0, 16, 0
    )
    shstr_sh = struct.pack("<IIQQQQIIQQ", 7, 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0)
    out = bytearray(shoff + 3 * 64)
    out[0:64] = ehdr
    out[64:120] = phdr
    out[code_off : code_off + len(code)] = code
    out[shstr_off : shstr_off + len(shstr)] = shstr
    out[shoff : shoff + 64] = b"\x00" * 64
    out[shoff + 64 : shoff + 128] = text_sh
    out[shoff + 128 : shoff + 192] = shstr_sh
    return bytes(out)


_FUNCTION_ADDR = 0x1000 + 32  # inside .text, 0x20 above its start


def _disassembled_target(tmp_path):
    import lief

    from blint.lib.disassembler import disassemble_functions

    elf_path = tmp_path / "mini.elf"
    elf_path.write_bytes(_build_minimal_x86_elf())
    parsed = lief.ELF.parse(str(elf_path))
    assert parsed is not None, "hand-built ELF failed to parse"
    results = disassemble_functions(
        parsed,
        {"functions": [{"name": "target_fn", "address": hex(_FUNCTION_ADDR), "size": 105}]},
        arch_target="x86_64-unknown-linux-gnu",
    )
    if not results:
        pytest.skip("disassembly unavailable (nyxstone cannot handle this host target)")
    return results


class TestDecodeGroundTruth:
    """The decode reads the bytes at the function's own address, not a neighbour's."""

    def test_function_decodes_its_own_bytes(self, tmp_path):
        results = _disassembled_target(tmp_path)
        entry = results[f"{hex(_FUNCTION_ADDR)}::target_fn"]
        first_line = entry["assembly"].split("\n", 1)[0]
        # Ground truth: bytes 80 3d 01 72 05 00 00 at the function start,
        # cross-checked against objdump on the corpus binary they came from.
        assert first_line == "cmp byte ptr [rip + 356865], 0"
        # 0x1234 rendered in decimal is what the decoy at .text start decodes
        # to; a decode starting there is reading the wrong function.
        assert not entry["assembly"].startswith("mov eax, 4660")
        assert entry["instruction_count"] > 2

    def test_blocks_tile_the_assembly_text(self, tmp_path):
        results = _disassembled_target(tmp_path)
        for entry in results.values():
            lines = entry["assembly"].split("\n")
            blocks = (entry.get("cfg") or {}).get("blocks") or []
            assert blocks, "expected a CFG for the disassembled function"
            total = sum(block["instructions"] for block in blocks)
            assert total == len(lines), "CFG blocks must tile the assembly text"


def test_loop_only_function_is_not_reported_as_a_cap_hit():
    """A function with no successor-free block converged; it did not hit the cap.

    Every reachable block here has a successor (the loop closes back on the
    entry) and the trailing block is unreachable, so there is no exit block
    to read the result from. That is a function nothing was learned about,
    which the caller must not confuse with a non-converged one.
    """
    lines = ["mov eax, 1", "jmp 4096", "nop", "jmp 4096", "ret"]
    cfg = _cfg([2, 2, 1], [(0, 1, "fallthrough"), (1, 0, "jump")])
    entries, method = _recover(lines, cfg)
    assert method == "dataflow"
    assert entries == []
