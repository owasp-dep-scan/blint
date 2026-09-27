#!/usr/bin/env python3
"""G0 — function-extent probe: blint's sizes next to .eh_frame FDEs, same run.

LIEF's ``Binary.functions`` hands out wrapped sizes on stripped C++ libraries
(a negative ``int32`` from its eh_frame walk sign-extended into ``uint64``),
and every such function decodes from its start to the end of ``.text`` — on
RnHello's arm64 ``libc++_shared.so`` that is 1,772 MB of metadata in 491 s.
This probe measures, per file, exactly what the reviewer measured:

1. ``entries_past_exec_section`` — function entries from every list
   ``disassemble_functions`` reads (``FUNCTION_SYMBOLS`` buckets, first entry
   per address, arm32 mapping symbols skipped, Thumb bit aligned away) whose
   positive size runs past the end of the executable section holding them.
   A size that has already wrapped past 2**32 is counted here regardless of
   any section geometry.
2. ``disagree_with_fde_oracle`` — of those entries whose start the oracle
   covers, how many carry a *positive* size that traces to neither named
   source: it is not the ``st_size`` the symbol buckets carry for that
   address (a symbol's st_size wins over both other sources) and it is not
   the FDE range ``llvm-dwarfdump --eh-frame`` reports (ground rule 29: the
   oracle is llvm-dwarfdump, named with its version, read in the same run).
   An entry whose size *is* its st_size but whose st_size disagrees with the
   FDE is a source disagreement, not a blint defect; those are reported as
   ``symbol_vs_fde_disagreements`` and do not fail the run. Entries with no
   size take the next-known-start rule, which is blint's designed fallback,
   so they are reported as ``sizeless_despite_oracle`` and do not fail.
3. ``unwind_discovery_correct`` — of blint's own ``discover_functions``
   records the oracle covers, how many match the FDE range exactly. blint's
   own ``.eh_frame`` parse is expected to be right where LIEF's is wrong.

The exit code is non-zero when any entry the disassembler would use is wrong
(past the section end, or a positive size disagreeing with the oracle), so a
packet's gate is ``extent_probe.py <so>...``. arm32 (.ARM.exidx) inputs have
no FDE oracle: counts 2 and 3 are then 0 with ``oracle: none`` printed, and
only count 1 fails the run.

Usage:
  poetry run python tests/scripts/android/extent_probe.py <elf>... \
      [--dwarfdump PATH] [--json PATH] [--limit N]

Exit codes: 0 all entries right, 1 wrong entries found, 2 unusable input.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from blint.lib.binary import parse
from blint.lib.disassembler import (
    _ARM32_MAPPING_SYMBOL_RE,
    FUNCTION_SYMBOLS,
)
from blint.lib.funcdisc.unwind import discover_functions

# llvm-dwarfdump --eh-frame FDE line, e.g.
#   00011eac 0000002c 00000024 FDE cie=00011e8c pc=0009c938...0009ca88
FDE_PC_RE = re.compile(r"FDE\s+cie=\S+\s+pc=([0-9a-f]+)\.\.\.([0-9a-f]+)", re.IGNORECASE)

# SHF_EXECINSTR; matches executable_ranges() in blint.lib.funcdisc.complete.
SHF_EXECINSTR = 0x4
# A wrapped size cannot be a real extent: no section in blint's formats is
# this large (executable_ranges() applies the same 1<<32 sanity bound).
MAX_PLAUSIBLE_SIZE = 1 << 32


def default_dwarfdump() -> str:
    """The NDK's llvm-dwarfdump, preferring the newest NDK under ~/Android/sdk."""
    sdks = os.path.expanduser("~/Android/sdk/ndk")
    if os.path.isdir(sdks):
        for ndk in sorted(os.listdir(sdks), reverse=True):
            candidate = os.path.join(
                sdks, ndk, "toolchains", "llvm", "prebuilt", "darwin-x86_64",
                "bin", "llvm-dwarfdump",
            )
            if os.path.exists(candidate):
                return candidate
    return "llvm-dwarfdump"


def exec_section_ranges(parsed_obj) -> list[tuple[int, int]]:
    """Executable section ranges as [(start, end_exclusive), ...], ELFs only."""
    ranges = []
    try:
        for section in parsed_obj.sections:
            size = int(section.size)
            if not size or size > MAX_PLAUSIBLE_SIZE:
                continue
            if int(section.flags) & SHF_EXECINSTR:
                start = int(section.virtual_address)
                ranges.append((start, start + size))
    except (AttributeError, TypeError, ValueError):
        return []
    return sorted(ranges)


def containing_exec_range(addr: int, ranges: list[tuple[int, int]]):
    for start, end in ranges:
        if start <= addr < end:
            return start, end
    return None


def fde_oracle(dwarfdump: str, path: str) -> dict[int, int] | None:
    """FDE start -> extent size from llvm-dwarfdump --eh-frame on the same file.

    None when the tool is unavailable; {} when the file has no FDEs (arm32
    .ARM.exidx binaries).
    """
    binary = shutil.which(dwarfdump)
    if not binary:
        return None
    try:
        result = subprocess.run(
            [binary, "--eh-frame", path],
            capture_output=True, text=True, timeout=300, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    table: dict[int, int] = {}
    for match in FDE_PC_RE.finditer(result.stdout):
        begin, end = int(match.group(1), 16), int(match.group(2), 16)
        if end > begin:
            table[begin] = end - begin
    return table


def disassembler_entries(metadata: dict, is_arm32: bool) -> list[dict]:
    """The function entries disassemble_functions would consume, in order.

    Mirrors the worklist: buckets in FUNCTION_SYMBOLS order, arm32 mapping
    symbols skipped (they are mode labels, not starts), deduped by aligned
    address keeping the first entry, exactly like the visited_addrs set.
    """
    seen: set[int] = set()
    entries = []
    for func_list_key in FUNCTION_SYMBOLS:
        for entry in metadata.get(func_list_key) or []:
            if not isinstance(entry, dict):
                continue
            raw = entry.get("address") or entry.get("rva_start")
            if not raw:
                continue
            try:
                addr = int(str(raw), 16)
            except ValueError:
                continue
            if is_arm32:
                if _ARM32_MAPPING_SYMBOL_RE.match(entry.get("name") or ""):
                    continue
                addr &= ~1
            if addr in seen:
                continue
            seen.add(addr)
            entries.append(entry | {"_addr": addr})
    return entries


def entry_size(entry: dict) -> int:
    """The size the disassembler takes from this entry (0 = none)."""
    size = entry.get("size") or entry.get("length")
    return size if isinstance(size, int) and size > 0 else 0


def symbol_sizes(metadata: dict) -> dict[int, int]:
    """Address -> positive st_size from the symbol buckets, first source wins.

    parse_symbols() stores a symbol's address under ``value``, while function
    entries store theirs under ``address``; accept both spellings.
    """
    sizes: dict[int, int] = {}
    for func_list_key in ("symtab_symbols", "dynamic_symbols"):
        for symbol in metadata.get(func_list_key) or []:
            if not isinstance(symbol, dict):
                continue
            raw = symbol.get("address") or symbol.get("value")
            if not raw:
                continue
            try:
                addr = int(str(raw), 16)
            except ValueError:
                continue
            size = symbol.get("size")
            if isinstance(size, int) and size > 0 and addr not in sizes:
                sizes[addr] = size
    return sizes


def probe_file(path: str, dwarfdump: str, limit: int) -> tuple[dict, int]:
    """Probe one file; returns (report dict, exit code for this file)."""
    import lief

    parsed_obj = lief.ELF.parse(path)
    if not parsed_obj or not isinstance(parsed_obj, lief.ELF.Binary):
        return {"file": path, "error": "not an ELF binary lief can parse"}, 2
    metadata = parse(path)
    if not (metadata.get("functions") or metadata.get("symtab_symbols")):
        return {"file": path, "error": "blint parse produced no function buckets"}, 2

    is_arm32 = parsed_obj.header.machine_type == lief.ELF.ARCH.ARM
    ranges = exec_section_ranges(parsed_obj)
    oracle = fde_oracle(dwarfdump, path)
    entries = disassembler_entries(metadata, is_arm32)
    sym_sizes = symbol_sizes(metadata)

    past_section = []
    for entry in entries:
        size = entry_size(entry)
        if not size:
            continue
        if size >= MAX_PLAUSIBLE_SIZE:
            entry["_wrapped"] = True
            past_section.append(entry)
            continue
        where = containing_exec_range(entry["_addr"], ranges)
        if where and entry["_addr"] + size > where[1]:
            past_section.append(entry)

    oracle_covered = 0
    sizeless_despite_oracle = 0
    symbol_vs_fde = 0
    disagree = []
    if oracle:
        for entry in entries:
            fde_size = oracle.get(entry["_addr"])
            if fde_size is None:
                continue
            oracle_covered += 1
            size = entry_size(entry)
            if not size:
                sizeless_despite_oracle += 1
            elif size == sym_sizes.get(entry["_addr"]):
                # The size traces to a symbol's st_size, which wins over the
                # FDE by the named precedence; the FDE disagreement is a
                # source disagreement, not a blint defect.
                symbol_vs_fde += 1
            elif size != fde_size:
                disagree.append(
                    {
                        "address": hex(entry["_addr"]),
                        "name": entry.get("name"),
                        "blint_size": size,
                        "fde_size": fde_size,
                        "st_size": sym_sizes.get(entry["_addr"]),
                    }
                )

    discovery = discover_functions(parsed_obj)
    discovery_compared = 0
    discovery_correct = 0
    if oracle:
        for record in discovery:
            fde_size = oracle.get(int(record["address"]))
            if fde_size is None:
                continue
            discovery_compared += 1
            if record.get("size") == fde_size:
                discovery_correct += 1

    report = {
        "file": path,
        "lief_version": lief.__version__,
        "function_entries": len(entries),
        "entries_past_exec_section": len(past_section),
        "oracle_available": oracle is not None,
        "oracle_fdes": len(oracle) if oracle is not None else None,
        "oracle_covered_entries": oracle_covered,
        "disagree_with_fde_oracle": len(disagree) if oracle else 0,
        "symbol_vs_fde_disagreements": symbol_vs_fde,
        "sizeless_despite_oracle": sizeless_despite_oracle,
        "unwind_discovery_compared": discovery_compared,
        "unwind_discovery_correct": discovery_correct,
        "examples": [
            {
                "address": hex(e["_addr"]),
                "name": e.get("name"),
                "size": e.get("size"),
                "wrapped": bool(e.get("_wrapped")),
            }
            for e in past_section[:limit]
        ],
        "disagreement_examples": disagree[:limit],
    }
    exit_code = 1 if (past_section or disagree) else 0
    return report, exit_code


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("files", nargs="+", help="ELF files to probe")
    parser.add_argument("--dwarfdump", default=default_dwarfdump(),
                        help="llvm-dwarfdump binary (default: newest NDK)")
    parser.add_argument("--json", dest="json_path", help="write the full report as JSON")
    parser.add_argument("--limit", type=int, default=5,
                        help="examples printed per file (default 5)")
    args = parser.parse_args()

    import lief

    print(f"lief: {lief.__version__}")
    dd_path = shutil.which(args.dwarfdump) or args.dwarfdump
    dd_version = subprocess.run(
        [dd_path, "--version"], capture_output=True, text=True, check=False,
    )
    oracle_note = (dd_version.stdout or dd_version.stderr).splitlines()[0] if dd_version else ""
    print(f"oracle: {args.dwarfdump} ({oracle_note.strip() or 'version unknown'})")

    reports = []
    worst = 0
    for path in args.files:
        if not os.path.isfile(path):
            print(f"{path}: MISSING")
            worst = max(worst, 2)
            reports.append({"file": path, "error": "missing"})
            continue
        report, code = probe_file(path, args.dwarfdump, args.limit)
        reports.append(report)
        worst = max(worst, code)
        if report.get("error"):
            print(f"{path}: ERROR {report['error']}")
            continue
        print(
            f"{path}: entries={report['function_entries']} "
            f"past_section={report['entries_past_exec_section']} "
            f"disagree_fde={report['disagree_with_fde_oracle']}"
            f"{' (oracle: none)' if not report['oracle_available'] else ''} "
            f"sym_vs_fde={report['symbol_vs_fde_disagreements']} "
            f"discovery_correct={report['unwind_discovery_correct']}"
            f"/{report['unwind_discovery_compared']}"
        )
        for example in report["examples"]:
            size = example["size"]
            note = " (wrapped u64)" if example["wrapped"] else ""
            print(f"    {example['address']} {example['name']}: size={size}{note}")
        for example in report["disagreement_examples"]:
            print(
                f"    {example['address']} {example['name']}: blint={example['blint_size']} "
                f"fde={example['fde_size']}"
            )

    if args.json_path:
        Path(args.json_path).write_text(json.dumps(reports, indent=2) + "\n")
    return worst


if __name__ == "__main__":
    sys.exit(main())
