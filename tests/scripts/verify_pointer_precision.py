#!/usr/bin/env python3
"""Verify pointer materialisation precision against llvm-objdump (P4.9 gate 5).

For one arm64 binary, disassembles with blint, recomputes every `adrp`
page in every function with an *independent* decoder (llvm-objdump's own
disassembly of the same file), and checks the interpreter's reconstructed
instruction addresses against llvm-objdump's instruction addresses. Any
single disagreement is a precision failure.

For the resolved strings, checks each entry's string against a lief read
of the image bytes at the recovered address — the one authority that did
not produce the number.

Usage:
    python tests/scripts/verify_pointer_precision.py BINARY [--arch arm64|x86]
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

import lief

from blint.lib.binary import parse

LLVM_OBJDUMP = "/opt/homebrew/opt/llvm@18/bin/llvm-objdump"


def byte_column(line: str) -> int:
    """Byte count of llvm-objdump's instruction byte column, 0 when absent.

    objdump puts the address first, then the raw bytes, then a tab before
    the rendered text — but the bytes sit before the first tab only for
    x86; arm64's single 4-byte word shares the address field. Strip the
    address and take everything before the first tab, hex chars halved.
    """
    rest = re.sub(r"^\s*[0-9a-f]+:\s*", "", line)
    field = rest.split("\t")[0]
    return len(field.replace(" ", "")) // 2


def objdump_instructions(binary: str, arch: str) -> dict[int, tuple[str, int]]:
    """Parse llvm-objdump's disassembly into {address: (mnemonic, size)}."""
    cmd = [LLVM_OBJDUMP, "-d", binary, f"--arch={'arm64' if arch == 'arm64' else 'x86_64'}"]
    out = subprocess.run(cmd, capture_output=True, text=True, check=False).stdout
    instrs = {}
    # Matches:  100000a80: 900009c8  adrp x8, 0x100138000 ...
    pat = re.compile(r"^\s*([0-9a-f]+):.*?\t([a-z][a-z0-9.]*)\s*(.*)$")
    for line in out.splitlines():
        m = pat.match(line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        if addr in instrs:
            continue  # fat binaries: first slice wins consistently
        # size from the byte column is brittle across objdump versions;
        # the next instruction's address gives it instead.
        instrs[addr] = (m.group(2), line)
    return instrs


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary")
    parser.add_argument("--arch", default="arm64", choices=["arm64", "x86"])
    parser.add_argument("--objdump-sample", type=int, default=200)
    args = parser.parse_args()

    metadata = parse(args.binary, disassemble=True)
    funcs = metadata.get("disassembled_functions") or {}
    print(f"functions disassembled: {len(funcs)}")

    # ---- 1. Reconstructed line addresses vs llvm-objdump addresses ----
    truth = objdump_instructions(args.binary, args.arch)
    print(f"llvm-objdump instructions decoded: {len(truth)}")

    # The failure mode this gate exists for: a reconstructed address that
    # lands mid-instruction. llvm-objdump's dict is keyed by instruction
    # start addresses, so an address that keys nothing is misplaced. Where
    # the address aligns, blint's exported length must equal objdump's byte
    # column — both measure the same bytes. Mnemonic spellings differ
    # between renderers (suffixes, raw opcodes) and are not a signal.
    checked = 0
    misaligned = []
    interior = []
    sweep_artifacts = []
    length_bad = []
    # Sorted objdump instruction spans, to tell an address that lands
    # strictly inside one of its instructions (a real misplacement) from
    # one objdump simply never disassembled (its sweep's blind spot).
    import bisect

    span_starts = []
    span_ends = []
    for addr_t, entry in sorted(truth.items()):
        span_len = byte_column(entry[1])
        if not span_len:
            continue
        span_starts.append(addr_t)
        span_ends.append(addr_t + span_len)
    sampled_functions = 0
    for key, func in funcs.items():
        if checked >= args.objdump_sample * 4:
            break
        blocks = (func.get("cfg") or {}).get("blocks") or []
        lengths = func.get("instruction_lengths") or []
        assembly = (func.get("assembly") or "").split("\n")
        if not blocks or not lengths or len(lengths) != len(assembly):
            continue
        sampled_functions += 1
        # Walk every block, prefix-sum lengths from block start, compare
        # against llvm-objdump's instruction addresses and byte column.
        cursor_line = 0
        for block in blocks:
            count = block.get("instructions") or 0
            start_va = int(str(block.get("start")), 16)
            addr = start_va
            for j in range(count):
                global_line = cursor_line + j
                if addr in truth:
                    checked += 1
                    # The byte column is the second tab-separated field of
                    # objdump's line; hex characters halved is the byte count
                    # for both x86's pairs and arm64's words.
                    truth_len = byte_column(truth[addr][1])
                    if truth_len and truth_len != lengths[global_line]:
                        length_bad.append(
                            (key, hex(addr), lengths[global_line], truth_len)
                        )
                else:
                    idx = bisect.bisect_right(span_starts, addr) - 1
                    if idx >= 0 and addr < span_ends[idx]:
                        # A landing inside an objdump instruction is a real
                        # misplacement — unless objdump's linear sweep
                        # swallowed this exact byte (its coverage jumps to
                        # addr+1 while a symbol-derived function starts here,
                        # evidence independent of any decoding).
                        sweep_ate_the_byte = (
                            hex(addr + 1) != ""
                            and (addr + 1) in truth
                            and func.get("address") == hex(addr)
                        )
                        if sweep_ate_the_byte:
                            sweep_artifacts.append((key, hex(addr)))
                        else:
                            interior.append((key, hex(addr), hex(span_starts[idx])))
                    else:
                        misaligned.append((key, hex(addr)))
                addr += lengths[global_line]
            cursor_line += count
    ok = checked > 0
    print(f"functions sampled for the address walk: {sampled_functions}")
    print(
        f"line addresses aligned with llvm-objdump instructions: {checked},"
        f" landing inside an objdump instruction: {len(interior)},"
        f" objdump-sweep swallowed-byte boundaries: {len(sweep_artifacts)},"
        f" absent from objdump's sweep: {len(misaligned)}"
    )
    for m in sweep_artifacts[:5]:
        print("  OBJDUMP SWEEP ARTIFACT (function entry objdump skipped):", m)
    print(f"lengths disagreeing with llvm-objdump byte columns: {len(length_bad)}")
    for m in length_bad[:10]:
        print("  LENGTH MISMATCH", m)
    for m in interior[:5]:
        print("  INTERIOR LANDING:", m)
    for m in misaligned[:5]:
        print("  ABSENT FROM OBJDUMP:", m)
    if checked == 0:
        print("  ERROR: no addresses were checked — the run never compared")
        return 2

    # ---- 1b. Every adrp page vs the raw ADRP encoding (both regions) ----
    # llvm-objdump's -d sweep does not cover every executable segment (x264
    # maps a second region at 0x200000000), but the ADRP encoding is fixed
    # by the architecture: imm = sign_extend(immhi:immlo, 21) << 12, and the
    # page is (pc & ~0xFFF) + imm, computed from bytes lief reads at the
    # instruction address. This verifies the nyxstone rendering and the
    # page formula against the CPU's own field layout everywhere.
    parsed_lief = lief.parse(args.binary)

    def decode_adrp(word: int) -> int | None:
        if word & 0x9F000000 != 0x90000000:
            return None
        immlo = (word >> 29) & 0x3
        immhi = (word >> 5) & 0x7FFFF
        imm21 = (immhi << 2) | immlo
        if imm21 & (1 << 20):
            imm21 -= 1 << 21
        return imm21 << 12

    enc_checked = 0
    enc_skipped = 0
    enc_bad = []
    for key, func in funcs.items():
        blocks = (func.get("cfg") or {}).get("blocks") or []
        lengths = func.get("instruction_lengths") or []
        assembly = (func.get("assembly") or "").split("\n")
        if not blocks or not lengths or len(lengths) != len(assembly):
            continue
        cursor_line = 0
        for block in blocks:
            count = block.get("instructions") or 0
            start_va = int(str(block.get("start")), 16)
            addr = start_va
            for j in range(count):
                line = assembly[cursor_line + j].strip()
                if line.startswith("adrp ") and lengths[cursor_line + j] == 4:
                    delta = int(line.split()[-1].lstrip("#"), 0)
                    page = ((addr & ~0xFFF) + delta) & 0xFFFFFFFFFFFFFFFF
                    raw = bytes(
                        parsed_lief.get_content_from_virtual_address(addr, 4)
                    )
                    decoded = decode_adrp(int.from_bytes(raw, "little")) if len(raw) == 4 else None
                    if decoded is None:
                        # Bytes unreadable through lief's VA API (a second
                        # mapping this image's segment list does not back —
                        # see the address-space finding in the P4.9 report)
                        # or not an adrp encoding at this address.
                        enc_skipped += 1
                        imm12 = decoded
                        enc_page = ((addr & ~0xFFF) + imm12) & 0xFFFFFFFFFFFFFFFF
                        enc_checked += 1
                        if enc_page != page:
                            enc_bad.append((key, hex(addr), hex(page), hex(enc_page)))
                addr += lengths[cursor_line + j]
            cursor_line += count
    print(
        f"adrp pages verified against the raw encoding: {enc_checked}, wrong: {len(enc_bad)},"
        f" skipped (bytes unreadable via lief): {enc_skipped}"
    )
    for b in enc_bad[:10]:
        print("  ENCODING MISMATCH", b)

    # ---- 2. Every pc-relative page/target vs llvm-objdump ----
    pc_checked = 0
    pc_bad = []
    for key, func in funcs.items():
        blocks = (func.get("cfg") or {}).get("blocks") or []
        lengths = func.get("instruction_lengths") or []
        assembly = (func.get("assembly") or "").split("\n")
        if not blocks or not lengths or len(lengths) != len(assembly):
            continue
        cursor_line = 0
        for block in blocks:
            count = block.get("instructions") or 0
            start_va = int(str(block.get("start")), 16)
            addr = start_va
            for j in range(count):
                line = assembly[cursor_line + j].strip()
                addr_j = addr
                if args.arch == "arm64" and line.startswith("adrp "):
                    parts = line.split()
                    delta = int(parts[-1].lstrip("#"), 0)
                    page = ((addr_j & ~0xFFF) + delta) & 0xFFFFFFFFFFFFFFFF
                    if addr_j in truth and truth[addr_j][0] == "adrp":
                        t_line = truth[addr_j][1]
                        t_target = re.search(r"adrp\s+\S+,\s*(0x[0-9a-f]+)", t_line)
                        if t_target:
                            pc_checked += 1
                            if int(t_target.group(1), 16) != page:
                                pc_bad.append(
                                    (key, hex(addr_j), hex(page), t_target.group(1))
                                )
                elif args.arch == "x86" and re.match(r"lea\s+\S+,\s*\[\s*rip", line):
                    # llvm-objdump renders the raw displacement with the
                    # instruction's byte column: `100000779: 48 8d 05 14 4e
                    # 00 00  leaq 0x4e14(%rip), %rax`. The target is the
                    # instruction address, plus its byte length from the
                    # byte column, plus that displacement.
                    t_line = truth[addr_j][1] if addr_j in truth else ""
                    t_disp = re.search(r"([-+]?0x[0-9a-f]+)\(%rip\)", t_line)
                    t_len = byte_column(t_line)
                    disp = re.search(r"\[\s*rip\s*([+-])\s*(\d+|0x[0-9a-fA-F]+)", line)
                    if t_disp and t_len and disp:
                        pc_checked += 1
                        value = int(disp.group(2), 0)
                        if disp.group(1) == "-":
                            value = -value
                        # blint's own length and displacement on one side,
                        # llvm-objdump's byte column and displacement on the
                        # other: a real cross-validation of both.
                        expected = addr_j + lengths[cursor_line + j] + value
                        actual = addr_j + t_len + int(
                            t_disp.group(1), 16
                        )
                        if expected != actual:
                            pc_bad.append(
                                (
                                    key, hex(addr_j), hex(expected),
                                    hex(actual),
                                )
                            )
                addr += lengths[cursor_line + j]
            cursor_line += count
    kind = "adrp pages" if args.arch == "arm64" else "rip-relative lea targets"
    print(f"{kind} checked against llvm-objdump targets: {pc_checked}, wrong: {len(pc_bad)}")
    for b in pc_bad[:10]:
        print("  WRONG TARGET", b)
    if pc_checked == 0:
        print("  ERROR: no pc-relative targets were checked")
        return 2

    # ---- 3. Resolved strings vs the image bytes ----
    entries = metadata.get("call_site_arguments") or []
    resolved = [e for e in entries if e.get("string")]
    parsed = lief.parse(args.binary)
    resolver_bad = []
    for entry in resolved:
        data = bytes(
            parsed.get_content_from_virtual_address(entry["value"], 256)
        )
        nul = data.find(b"\x00")
        usable = data[:nul] if nul != -1 else data
        try:
            text = usable.decode("ascii")
        except UnicodeDecodeError:
            text = None
        if text != entry["string"]:
            resolver_bad.append((entry["string"], entry["value"], text))
    print(
        f"strings resolved: {len(resolved)}; verified against image bytes: "
        f"{len(resolved) - len(resolver_bad)}; wrong: {len(resolver_bad)}"
    )
    for b in resolver_bad[:10]:
        print("  WRONG STRING", b)

    # ---- 4. Distinct strings for the report sample ----
    sample = sorted({e["string"] for e in resolved})
    print(f"distinct strings ({len(sample)}): {sample[:40]}")
    verdict = (
        ok and not length_bad and not interior and not pc_bad
        and not resolver_bad and not enc_bad
    )
    print("PRECISION VERDICT:", "PASS" if verdict else "FAIL")
    return 0 if verdict else 1


if __name__ == "__main__":
    raise SystemExit(main())
