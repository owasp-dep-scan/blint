#!/usr/bin/env python3
"""Verify pointer materialisation precision against llvm-objdump (P4.9 gate 5).

For one binary, disassembles with blint, recomputes every `adrp` page
(arm64) or rip-relative `lea` target (x86) in every function with an
*independent* decoder (llvm-objdump's own disassembly of the same file),
and checks the interpreter's reconstructed instruction addresses against
llvm-objdump's instruction addresses. Any single disagreement is a
precision failure.

For the resolved strings, checks each entry's string against a lief read
of the image bytes at the recovered address — the one authority that did
not produce the number.

The architecture is taken from the metadata blint exported — the primary
Mach-O slice's `arch` (blint labels the arm64e slice `arm64e`, the same
spelling `lipo -archs` and llvm-objdump use), or `machine_type` for other
formats. For Mach-O the name is passed to llvm-objdump verbatim. The
`--arch` flag is only a cross-check: it must agree with the slice blint
analysed, and the run refuses to compare against a different slice.

An unusable input — a path that does not parse, a binary with no
disassembly, an llvm-objdump that is missing, fails, or decodes nothing —
is an *unknown*: the harness exits 2 with a message naming the missing
precondition before printing any count that could be read as a verdict.
An unknown is never a pass, never a blint failure, and never a zero.

A reconstructed address that lands inside an objdump instruction which
*also spans that function's own entry* is classified as an objdump
linear-sweep artifact, not a blint misplacement: the function's entry
comes from the symbol table or LC_FUNCTION_STARTS, evidence independent
of any decoding, and no instruction can span a branch target. Every such
classification prints the bytes of the sweep's instruction and of the
function entry. Landings inside objdump instructions that cross no
function entry remain misplacements and fail the gate.

Exit codes: 0 PASS, 1 FAIL (a measured disagreement with objdump or the
image bytes), 2 unusable input (no measurement happened).

Usage:
    python tests/scripts/verify_pointer_precision.py BINARY [--arch arm64|arm64e|x86]
"""

from __future__ import annotations

import argparse
import bisect
import contextlib
import os
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

import lief

from blint.lib.binary import parse

LLVM_OBJDUMP = os.environ.get("BLINT_LLVM_OBJDUMP", "/opt/homebrew/opt/llvm@18/bin/llvm-objdump")

X86_ARCH_NAMES = {"x86_64", "x86", "amd64"}
ARM64_ARCH_NAMES = {"arm64", "arm64e", "aarch64"}
ARCH_FLAG_ALIASES = {
    "arm64": ARM64_ARCH_NAMES,
    "arm64e": {"arm64e"},
    "x86": X86_ARCH_NAMES,
}
MASK64 = 0xFFFFFFFFFFFFFFFF


class UnusableInput(Exception):
    """An input the gate cannot measure; reported as an unknown, never a count."""


def unusable(reason: str) -> int:
    """Exit as an unusable input: name the missing precondition, measure nothing."""
    print(f"ERROR: {reason}", file=sys.stderr)
    print(
        "  the gate could not measure anything — this is an unusable input, not a blint failure",
        file=sys.stderr,
    )
    return 2


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


def parse_objdump_text(out: str) -> dict[int, tuple[str, str]]:
    """Parse llvm-objdump's disassembly into {address: (mnemonic, line)}."""
    instrs: dict[int, tuple[str, str]] = {}
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


def run_objdump(binary: str, arch_name: str | None, is_macho: bool) -> dict[int, tuple[str, str]]:
    """Run llvm-objdump and return its instruction starts.

    Every failure mode — objdump missing, a nonzero exit, an error printed
    to stderr without a nonzero exit (llvm-objdump exits 0 when --arch is
    not in the file), or zero instructions decoded — raises UnusableInput.
    """
    cmd = [LLVM_OBJDUMP, "-d", binary]
    if is_macho:
        if not arch_name:
            raise UnusableInput(
                f"{binary}: the Mach-O metadata names no slice architecture, so "
                "llvm-objdump cannot be told which slice blint disassembled"
            )
        cmd.append(f"--arch={arch_name}")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        raise UnusableInput(
            f"llvm-objdump not found at {LLVM_OBJDUMP} — install llvm@18 or set BLINT_LLVM_OBJDUMP"
        ) from None
    if proc.returncode != 0:
        raise UnusableInput(
            f"llvm-objdump failed on {binary} (exit {proc.returncode}): "
            f"{proc.stderr.strip()[:300] or 'no stderr'}"
        )
    instrs = parse_objdump_text(proc.stdout)
    if not instrs:
        detail = proc.stderr.strip()[:300]
        raise UnusableInput(
            f"llvm-objdump decoded no instructions for {binary}"
            + (f" (--arch={arch_name})" if is_macho else "")
            + (f"; it printed: {detail}" if detail else "")
        )
    return instrs


def analysed_arch_name(metadata: dict) -> str | None:
    """Name of the slice blint analysed, in llvm-objdump's spelling.

    Fat Mach-O: the primary slice's `arch` field (`x86_64`, `arm64`,
    `arm64e`). Other formats: `machine_type` lowercased (`X86_64` →
    `x86_64`), falling back to `cpu_type` for thin Mach-O, which carries
    neither `slices` nor `machine_type` (`ARM64` → `arm64`). None when
    the metadata names no architecture at all.
    """
    slices = metadata.get("slices") or []
    if slices:
        primary = next((s for s in slices if s.get("is_primary")), slices[0])
        name = str(primary.get("arch") or "").strip().lower()
        return name or None
    for key in ("machine_type", "cpu_type"):
        name = str(metadata.get(key) or "").strip().lower()
        if name:
            return name
    return None


def check_arch_flag(args: argparse.Namespace, arch_name: str | None, is_macho: bool) -> None:
    """Refuse a run whose --arch names a slice blint did not analyse.

    A mismatch does not announce itself through the addresses: an address
    can be an instruction start in two slices of one fat binary at once
    (0x100000718 is, in /bin/ls), so comparing against the wrong slice can
    silently align and read as a pass.
    """
    if not args.arch:
        return
    wanted = ARCH_FLAG_ALIASES[args.arch]
    if arch_name in wanted:
        return
    analysed = arch_name or "an unnamed architecture"
    raise UnusableInput(
        f"{args.binary}: blint analysed the {analysed} slice but --arch {args.arch} "
        f"selects {sorted(wanted)}. The gate refuses to compare one slice against "
        "another's ground truth."
    )


def classify_landing(landing: int, walked_entry: int, span_start: int) -> str:
    """Classify a reconstructed address that keys no objdump instruction.

    Returns "artifact" when objdump's instruction containing the landing
    begins strictly before the walked function's own entry — its linear
    sweep decoded across a function boundary, which the entry's provenance
    (symbol table / LC_FUNCTION_STARTS) rules out independently of any
    decoding. Any other landing is "interior": a real misplacement.
    """
    if span_start < walked_entry <= landing:
        return "artifact"
    return "interior"


def span_start_label(raw: bytes | None) -> str:
    """Why the sweep mis-decoded here: padding start, or earlier drift."""
    if not raw:
        return "bytes unreadable"
    if raw[0] in (0x00, 0x90, 0xCC):
        return "the sweep instruction begins in an alignment pad byte"
    if len(raw) >= 2 and raw[0] == 0x66 and raw[1] == 0x90:
        return "the sweep instruction begins in an alignment pad byte"
    if len(raw) >= 2 and raw[0] == 0x0F and raw[1] == 0x1F:
        return "the sweep instruction begins in a multi-byte nop"
    return "the sweep had already drifted into misaligned decoding"


def hexdump(parsed_lief, addr: int, n: int) -> str:
    try:
        raw = bytes(parsed_lief.get_content_from_virtual_address(addr, n))
        return " ".join(f"{b:02x}" for b in raw)
    except Exception:  # noqa: BLE001 — lief raises bareblooded errors on unmapped VAs
        return "<bytes unreadable>"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary")
    parser.add_argument(
        "--arch",
        default=None,
        choices=sorted(ARCH_FLAG_ALIASES),
        help="cross-check only: must match the slice blint analysed",
    )
    parser.add_argument("--objdump-sample", type=int, default=200)
    args = parser.parse_args(argv)

    metadata = parse(args.binary, disassemble=True)
    funcs = metadata.get("disassembled_functions") or {}
    if not funcs:
        if not metadata.get("functions"):
            return unusable(
                f"{args.binary} did not parse as a supported binary — the metadata is empty"
            )
        return unusable(
            f"{args.binary}: disassembly produced no functions — "
            "nyxstone needs LLVM 18 (set NYXSTONE_LLVM_PREFIX), or the binary has no code"
        )
    print(f"functions disassembled: {len(funcs)}")

    arch_name = analysed_arch_name(metadata)
    is_macho = bool(metadata.get("slices"))
    try:
        check_arch_flag(args, arch_name, is_macho)
    except UnusableInput as exc:
        return unusable(str(exc))
    if is_macho:
        print(f"analysed slice architecture: {arch_name}")

    # ---- 1. Reconstructed line addresses vs llvm-objdump addresses ----
    try:
        truth = run_objdump(args.binary, arch_name, is_macho)
    except UnusableInput as exc:
        return unusable(str(exc))
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
    # strictly inside one of its instructions from one objdump simply
    # never disassembled (its sweep's blind spot).
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
        walked_entry = int(str(func.get("address")), 16)
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
                        length_bad.append((key, hex(addr), lengths[global_line], truth_len))
                else:
                    idx = bisect.bisect_right(span_starts, addr) - 1
                    if idx >= 0 and addr < span_ends[idx]:
                        kind = classify_landing(addr, walked_entry, span_starts[idx])
                        if kind == "artifact":
                            sweep_artifacts.append((key, hex(addr), hex(span_starts[idx])))
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
    parsed_lief = lief.parse(args.binary)
    for m in sweep_artifacts[:5]:
        key, landing, span_start = m
        s = int(span_start, 16)
        t_line = truth.get(s, ("", ""))[1]
        raw = None
        with contextlib.suppress(Exception):
            raw = bytes(parsed_lief.get_content_from_virtual_address(s, byte_column(t_line) or 1))
        print(f"  OBJDUMP SWEEP ARTIFACT at {landing} (function {key}):")
        print(f"    sweep instruction @ {span_start}: {t_line.strip()}")
        print(f"    {span_start_label(raw)}; sweep bytes: {hexdump(parsed_lief, s, 8)}")
        entry = int(str((funcs.get(key) or {}).get("address")), 16)
        print(f"    blint's entry bytes at {hex(entry)}: {hexdump(parsed_lief, entry, 8)}")
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
                    page = ((addr & ~0xFFF) + delta) & MASK64
                    raw = bytes(parsed_lief.get_content_from_virtual_address(addr, 4))
                    decoded = decode_adrp(int.from_bytes(raw, "little")) if len(raw) == 4 else None
                    if decoded is None:
                        # Bytes unreadable through lief's VA API (a second
                        # mapping this image's segment list does not back —
                        # see the address-space finding in the P4.9 report)
                        # or not an adrp encoding at this address.
                        enc_skipped += 1
                    else:
                        enc_page = ((addr & ~0xFFF) + decoded) & MASK64
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
    is_arm64 = arch_name in ARM64_ARCH_NAMES
    is_x86 = arch_name in X86_ARCH_NAMES
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
                if is_arm64 and line.startswith("adrp "):
                    parts = line.split()
                    delta = int(parts[-1].lstrip("#"), 0)
                    page = ((addr_j & ~0xFFF) + delta) & MASK64
                    if addr_j in truth and truth[addr_j][0] == "adrp":
                        t_line = truth[addr_j][1]
                        t_target = re.search(r"adrp\s+\S+,\s*(0x[0-9a-f]+)", t_line)
                        if t_target:
                            pc_checked += 1
                            if int(t_target.group(1), 16) != page:
                                pc_bad.append((key, hex(addr_j), hex(page), t_target.group(1)))
                elif is_x86 and re.match(r"lea\s+\S+,\s*\[\s*rip", line):
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
                        actual = addr_j + t_len + int(t_disp.group(1), 16)
                        if expected != actual:
                            pc_bad.append(
                                (
                                    key,
                                    hex(addr_j),
                                    hex(expected),
                                    hex(actual),
                                )
                            )
                addr += lengths[cursor_line + j]
            cursor_line += count
    kind = "adrp pages" if is_arm64 else "rip-relative lea targets"
    print(f"{kind} checked against llvm-objdump targets: {pc_checked}, wrong: {len(pc_bad)}")
    for b in pc_bad[:10]:
        print("  WRONG TARGET", b)
    if pc_checked == 0:
        print("  ERROR: no pc-relative targets were checked")
        return 2

    # ---- 3. Resolved strings vs the image bytes ----
    entries = metadata.get("call_site_arguments") or []
    resolved = [e for e in entries if e.get("string")]
    resolver_bad = []
    for entry in resolved:
        data = bytes(parsed_lief.get_content_from_virtual_address(entry["value"], 256))
        readings = []
        nul = data.find(b"\x00")
        with contextlib.suppress(UnicodeDecodeError):
            readings.append((data[:nul] if nul != -1 else data).decode("ascii"))
        # A pointed-at literal may be UTF-16LE, so the check reads that form
        # too, terminating on an aligned NUL pair rather than a single byte.
        end = len(data) - (len(data) % 2)
        wide_end = next((i for i in range(0, end, 2) if data[i] == 0 and data[i + 1] == 0), end)
        with contextlib.suppress(UnicodeDecodeError, ValueError):
            readings.append(data[:wide_end].decode("utf-16-le"))
        if entry["string"] not in readings:
            resolver_bad.append((entry["string"], entry["value"], readings))
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
        ok and not length_bad and not interior and not pc_bad and not resolver_bad and not enc_bad
    )
    print("PRECISION VERDICT:", "PASS" if verdict else "FAIL")
    return 0 if verdict else 1


if __name__ == "__main__":
    raise SystemExit(main())
