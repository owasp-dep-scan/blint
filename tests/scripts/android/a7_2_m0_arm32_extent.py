#!/usr/bin/env python3
"""A7.2 M0(d) — the ARM32 extent overrun, per library, against llvm-objdump.

For every `svc` site llvm-objdump reports in each stripped armeabi-v7a
library, this script prints the three facts M3's terminator analysis needs:

- the function blint decodes the site into: the `.ARM.exidx` start F at or
  below it (the same PREL31 parse blint's discovery uses) and the next
  exidx start N, which is where blint's extent ends today;
- the first function-leaving terminator in [F, N) — `pop {…, pc}`, `bx lr`,
  `ldr pc, …` or an unconditional `b`/`b.w` whose target leaves the extent
  — with its address, and the pool gap N − (terminator end);
- the instruction context around the site, for the true/false hand-read.

The script never classifies sites itself; the classifications in
a7-m0-measurements.md are read by hand from this output.

Usage:
  python tests/scripts/android/a7_2_m0_arm32_extent.py lib1.so lib2.so ...
"""

from __future__ import annotations

import bisect
import re
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

import lief

OBJDUMP_HELP = "llvm-objdump (any LLVM; the committed numbers name the NDK r28c one)"

_OBJDUMP_LINE = re.compile(r"^\s*([0-9a-f]+):\s+(.*)$")
# The prompt's terminator forms: pop {…, pc}, bx lr, and (for bx rN / ldr pc)
# the indirect tail branches _arm32_stream_terminates counts as leaving.
_TERMINATOR = re.compile(
    r"^(?:pop(?:\.w|\.\w+)?\s*\{[^}]*\bpc\b|bx(?:\.\w+)?\s+(?:lr|r\d+)|"
    r"ldr(?:\.\w+)?\s+pc,|ldm(?:\.\w+)?\s+\w+,\s*\{[^}]*\bpc\b)"
)
_BRANCH = re.compile(r"^b(?:\.w|\.n|\.\w+)?\s+#?(-?0x[0-9a-f]+|-?\d+)", re.IGNORECASE)
_SVC = re.compile(r"\bsvc\b")
_SVC_IMM = re.compile(r"\bsvc(?:\.\w+)?\s+#?(-?0x[0-9a-f]+|-?\d+)", re.IGNORECASE)


def _exidx_starts(parsed: lief.ELF.Binary) -> list[int]:
    """Sorted function starts from .ARM.exidx, blint's own PREL31 parse."""
    section = parsed.get_section(".ARM.exidx")
    if section is None:
        return []
    data = bytes(section.content)
    base = int(section.virtual_address)
    starts = set()
    for index in range(len(data) // 8):
        word0 = struct.unpack_from("<I", data, index * 8)[0] & 0x7FFFFFFF
        if word0 & 0x40000000:
            word0 -= 1 << 31
        start = (base + index * 8 + word0) & ~1
        if start:
            starts.add(start)
    return sorted(starts)


def _objdump_instructions(path: Path, objdump: str) -> list[tuple[int, str, int]]:
    """(address, text, next-address) per instruction, objdump's own decode."""
    output = subprocess.run(
        [objdump, "-d", "--no-show-raw-insn", str(path)],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    rows: list[tuple[int, str]] = []
    for line in output.splitlines():
        match = _OBJDUMP_LINE.match(line)
        if match:
            rows.append((int(match.group(1), 16), match.group(2).strip()))
    instructions: list[tuple[int, str, int]] = []
    for index, (address, text) in enumerate(rows):
        next_address = rows[index + 1][0] if index + 1 < len(rows) else address + 4
        instructions.append((address, text, next_address))
    return instructions


def _first_terminator(
    instructions: list[tuple[int, str, int]],
    addresses: list[int],
    start: int,
    end: int,
) -> tuple[int, str, int] | None:
    """The first function-leaving terminator in [start, end), objdump text."""
    index = bisect.bisect_left(addresses, start)
    for address, text, next_address in instructions[index:]:
        if address >= end:
            break
        mnemonic = text.split()[0].lower() if text else ""
        if mnemonic.startswith("b") and not mnemonic.startswith("bl"):
            match = _BRANCH.match(text)
            if match:
                target_token = match.group(1)
                target = (
                    int(target_token, 16)
                    if target_token.lower().startswith("-0x")
                    or target_token.lower().startswith("0x")
                    else int(target_token)
                )
                if not (start <= target < end):
                    return address, text, next_address
            continue
        if _TERMINATOR.match(text):
            return address, text, next_address
    return None


def measure(path_str: str, objdump: str) -> dict:
    path = Path(path_str)
    parsed = lief.parse(path_str)
    starts = _exidx_starts(parsed)
    instructions = _objdump_instructions(path, objdump)
    addresses = [instruction[0] for instruction in instructions]
    svc_sites = [
        (address, text, next_address)
        for address, text, next_address in instructions
        if _SVC.search(text)
    ]
    terminator_cache: dict[tuple[int, int], tuple[int, str, int] | None] = {}

    def _terminator_for(start: int, end: int):
        cache_key = (start, end)
        if cache_key not in terminator_cache:
            terminator_cache[cache_key] = _first_terminator(instructions, addresses, start, end)
        return terminator_cache[cache_key]

    rows: list[dict] = []
    for address, text, next_address in svc_sites:
        index = bisect.bisect_right(starts, address) - 1
        func_start = starts[index] if index >= 0 else 0
        next_start = starts[index + 1] if index + 1 < len(starts) else 0
        terminator = _terminator_for(func_start, next_start) if next_start else None
        rows.append(
            {
                "svc": address,
                "svc_text": text,
                "exidx_start": func_start,
                "exidx_next_start": next_start,
                "first_terminator": (
                    {"address": terminator[0], "text": terminator[1], "end": terminator[2]}
                    if terminator
                    else None
                ),
                "pool_gap": (next_start - terminator[2]) if terminator else None,
                "terminator_precedes_svc": bool(terminator and terminator[2] <= address),
            }
        )
    # The overrun population: exidx intervals whose first function-leaving
    # terminator ends before the next start, i.e. whose extent carries bytes
    # after the function's last instruction (the literal pools M3 stops at).
    overrun_intervals = 0
    gaps: list[int] = []
    exec_lo = addresses[0] if addresses else 0
    exec_hi = addresses[-1] if addresses else 0
    for index, start in enumerate(starts):
        end = starts[index + 1] if index + 1 < len(starts) else 0
        if not end or start < exec_lo or end > exec_hi:
            continue
        terminator = _terminator_for(start, end)
        if terminator and terminator[2] < end:
            overrun_intervals += 1
            gaps.append(end - terminator[2])
    gaps.sort()
    summary = {
        "overrun_intervals": overrun_intervals,
        "intervals_total": len(starts),
        "gap_median": gaps[len(gaps) // 2] if gaps else None,
        "gap_max": gaps[-1] if gaps else None,
    }
    return {
        "file": path.name,
        "exidx_functions": len(starts),
        "summary": summary,
        "svc_sites": rows,
        "instructions": instructions,
    }


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("libs", nargs="+", help="stripped armeabi-v7a .so files")
    parser.add_argument("--objdump", default="llvm-objdump", help=OBJDUMP_HELP)
    parser.add_argument(
        "--context",
        action="store_true",
        help=(
            "print instruction context around the svc sites worth hand-reading: "
            "every immediate-0 site and the first 30 terminator-preceding sites"
        ),
    )
    args = parser.parse_args(argv)
    for lib in args.libs:
        report = measure(lib, args.objdump)
        instructions = report.pop("instructions")
        addresses = [instruction[0] for instruction in instructions]
        sites = report["svc_sites"]
        overrun = [row for row in sites if row["terminator_precedes_svc"]]
        imm_zero = [
            row
            for row in sites
            if (immediate := _SVC_IMM.match(row["svc_text"]))
            and immediate.group(1).lower() in ("0", "0x0", "#0")
        ]
        print(
            f"### {report['file']}: {report['exidx_functions']} exidx functions,"
            f" {len(sites)} objdump svc sites ({len(imm_zero)} immediate-0),"
            f" {len(overrun)} with a terminator before the site"
        )
        summary = report["summary"]
        print(
            f"    overrun intervals: {summary['overrun_intervals']}"
            f" / {summary['intervals_total']}, pool gap median"
            f" {summary['gap_median']} max {summary['gap_max']} bytes"
        )
        for row in sites:
            term = row["first_terminator"]
            immediate = _SVC_IMM.match(row["svc_text"])
            imm_note = f"imm {immediate.group(1)}" if immediate else "imm <other form>"
            print(
                f"  svc {row['svc']:#x} ({row['svc_text']}) [{imm_note}] in exidx"
                f" [{row['exidx_start']:#x}, {row['exidx_next_start']:#x})"
                " first-terminator "
                + (
                    f"{term['address']:#x} {term['text']} -> pool gap {row['pool_gap']} bytes"
                    if term
                    else "none"
                )
                + (" [TERMINATOR PRECEDES SVC]" if row["terminator_precedes_svc"] else "")
            )
        if args.context:
            worth_reading = {row["svc"] for row in imm_zero}
            worth_reading.update(row["svc"] for row in overrun[:30])
            for address in sorted(worth_reading):
                lo = bisect.bisect_left(addresses, address - 48)
                hi = bisect.bisect_right(addresses, address + 48)
                print(f"  ---- context @ {address:#x}")
                for instr_address, text, _ in instructions[lo:hi]:
                    marker = " <== svc" if instr_address == address else ""
                    print(f"      {instr_address:#x}: {text}{marker}")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
