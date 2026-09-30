#!/usr/bin/env python3
"""A7.2 M0 — measure only: the call-site shapes M1/M2 target, over the corpus.

Three counts per input file, plus the aggregates the commit body quotes:

(a) last-line ``jmp imm`` on x86/x86_64: whether the end-relative reading
    (``instr.address + len + imm``, M1's rule) lands on a PLT entry or a
    named function, whether the absolute reading (today's ELF behaviour)
    does, and whether the disassembler already resolved the site. Sites the
    delta names and the absolute value does not are M1's recovery set;
    sites only the absolute value names are what would justify keeping the
    fallback.
(b) pure thunks: functions of at most four register-move/constant-load
    instructions followed by one tail branch to a named callee (M2's
    definition), and how many resolved call sites name one — the sites M2
    re-resolves through the thunk's final callee.
(c) resolved calls to access/stat/lstat/fopen/open whose path register was
    loaded from a pointer table in ``.data.rel.ro`` (arm64 ``adr`` or
    ``adrp+add`` then ``ldr x0, [base, ...]``; x86-64 ``lea rip`` then
    ``mov rdi, [base + off]``) — the -Os/-Oz root-probe shape that stays
    out of scope, with the pointed-to strings recorded so the su-table
    proposal can be ranked on real numbers.

ARM32 extent overrun (M3's spec input) is measured by
``a7_2_m0_arm32_extent.py`` against llvm-objdump; this script stays on the
modelled ABIs.

Usage:
  python tests/scripts/android/a7_2_m0_measure.py --file a.so [--file b.so ...]
      [--jobs N] [--json out.json]

File lists are built by the caller (see a7-m0-measurements.md for the exact
corpus enumeration commands).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

import lief

from blint.lib.absint import decode_pointer_string
from blint.lib.binary import parse
from blint.lib.disassembler import (
    _build_addr_to_name_map,
    _elf_plt_stub_names,
    _parse_immediate_token,
)

# The path-probe callees count (c) reads; keep in sync with the rule's table
# only for measurement (android_reviews.CALLEE_ARGUMENT_POSITIONS is the
# production list).
PATH_PROBE_CALLEES = frozenset(
    {"access", "stat", "stat64", "lstat", "lstat64", "fopen", "fopen64", "open", "open64"}
)

# (b): instruction forms that only move a register or load a constant. The
# adrp+add pair is an address-constant load; adrp alone is not.
ARM64_MOVE_LOAD = re.compile(r"^(?:mov|movz|movk|fmov|nop)\s", re.IGNORECASE)
X86_MOVE_LOAD = re.compile(r"^(?:mov|nop)\s", re.IGNORECASE)

# ARM64 argument registers (x0-x7 / w0-w7) and x86-64's, for reporting which
# thunk moves are argument positions at all.
ARM64_ARG_RE = re.compile(r"^[xw]([0-7])\b")
X86_ARG_REGS = {"rdi": 0, "rsi": 1, "rdx": 2, "rcx": 3, "r8": 4, "r9": 5}


def _function_lines(func: dict) -> tuple[list[str], list[int], int]:
    """(assembly lines, per-line lengths, start address) or ([], [], 0)."""
    lines = str(func.get("assembly") or "").split("\n")
    lengths = func.get("instruction_lengths") or []
    if not lines or not lines[0] or len(lengths) != len(lines):
        return [], [], 0
    try:
        start = int(str(func.get("address")), 16)
    except (TypeError, ValueError):
        return [], [], 0
    return lines, lengths, start


def _line_address(start: int, lengths: list[int], index: int) -> int:
    return start + sum(lengths[:index])


def _is_arm64(target: str) -> bool:
    return "aarch64" in target or "arm64" in target


def _is_x86(target: str) -> bool:
    return "x86_64" in target or target.startswith("i686") or "i386" in target


def _tail_jmps(funcs: dict, plt: dict[int, str], addr_to_name: dict[int, str]) -> dict:
    """(a): the last-line jmp-immediate sites and what each reading names."""
    stats = Counter()
    unresolved_samples: list[dict] = []
    for func in funcs.values():
        if not isinstance(func, dict):
            continue
        lines, lengths, start = _function_lines(func)
        if not lines:
            continue
        parts = lines[-1].strip().split(None, 1)
        if len(parts) < 2 or parts[0].lower() not in ("jmp", "jmpq"):
            continue
        operand = parts[1].strip()
        if "[" in operand or "]" in operand:
            continue  # a pointer-slot jump, resolved by its own path
        value = _parse_immediate_token(operand)
        if value is None:
            continue
        stats["last_line_jmp_imm"] += 1
        last_index = len(lines) - 1
        resolved = {
            str(entry.get("target_name"))
            for entry in func.get("direct_call_targets") or []
            if isinstance(entry, dict)
            and entry.get("kind") == "tailcall"
            and entry.get("site_index") == last_index
            and entry.get("target_name")
            # A name that is just the operand echoed back (the disassembler's
            # stand-in for an unresolved numeric target, as __on_dlclose's
            # "jmp 964" -> target_name "964" shows) is no resolution.
            and " ".join(str(entry.get("target_name")).split()).lower()
            != " ".join(str(entry.get("raw_operand") or "").split()).lower()
        }
        if resolved:
            stats["already_resolved"] += 1
            continue
        instr_addr = _line_address(start, lengths, last_index)
        delta_target = instr_addr + lengths[-1] + value
        delta_name = plt.get(delta_target) or addr_to_name.get(delta_target)
        absolute_name = plt.get(value) or addr_to_name.get(value)
        if delta_name and not absolute_name:
            stats["delta_only"] += 1
        elif absolute_name and not delta_name:
            stats["absolute_only"] += 1
            unresolved_samples.append(
                {
                    "function": func.get("name"),
                    "operand": operand,
                    "absolute_names": absolute_name,
                }
            )
        elif delta_name and absolute_name:
            stats["both"] += 1
        else:
            stats["neither"] += 1
            if len(unresolved_samples) < 8:
                unresolved_samples.append(
                    {"function": func.get("name"), "operand": operand, "value": value}
                )
    return {"counts": dict(stats), "absolute_only_samples": unresolved_samples[:8]}


def _arm64_materialisation(lines: list[str], lengths: list[int], start: int) -> dict[str, int]:
    """Registers holding an address materialised by adr or adrp+add."""
    bases: dict[str, int] = {}
    pending_page: dict[str, int] = {}
    for index, line in enumerate(lines):
        text = " ".join(line.split())
        mnemonic, _, rest = text.partition(" ")
        mnemonic = mnemonic.lower()
        operands = [op.strip() for op in rest.split(",")] if rest else []
        if mnemonic == "adr" and len(operands) >= 2:
            value = _parse_immediate_token(operands[1])
            if value is not None:
                bases[operands[0].lower()] = _line_address(start, lengths, index) + value
                pending_page.pop(operands[0].lower(), None)
        elif mnemonic == "adrp" and len(operands) >= 2:
            value = _parse_immediate_token(operands[1])
            if value is not None:
                # nyxstone prints adrp's operand as the (shifted) distance to
                # the target page; the disassembler reads the page directly.
                pending_page[operands[0].lower()] = (
                    _line_address(start, lengths, index) & ~0xFFF
                ) + value
        elif mnemonic == "add" and len(operands) >= 3:
            dst, src = operands[0].lower(), operands[1].lower()
            if src in pending_page:
                offset = _parse_immediate_token(operands[2])
                if offset is not None:
                    bases[dst] = pending_page[src] + offset
                    pending_page.pop(src, None)
        elif mnemonic.startswith("ldr"):
            pass  # a load reads a base; it does not clear the materialisation
        else:
            # Any other write to a tracked register invalidates it.
            if operands:
                dst = operands[0].lower()
                bases.pop(dst, None)
                pending_page.pop(dst, None)
    return bases


def _collapse_arm64_addr_constant(prep: list[str]) -> list[str] | None:
    """Collapse an adjacent ``adrp xN`` + ``add xN, xN, #imm`` into one token.

    Returns None when a bare ``adrp`` or a stray ``add`` survives outside
    the pair (not a constant load), else the prep list with the pair
    replaced by ``<addr-constant>``.
    """
    collapsed: list[str] = []
    index = 0
    while index < len(prep):
        line = " ".join(prep[index].split())
        if line.lower().startswith("adrp "):
            parts = prep[index + 1].split() if index + 1 < len(prep) else []
            pair = " ".join(parts).lower()
            reg = line.split()[1].rstrip(",").lower()
            if not re.match(rf"^add\s+{reg},\s*{reg},\s*#", pair):
                return None
            collapsed.append("<addr-constant>")
            index += 2
            continue
        if line.lower().startswith(("add ", "adr ")):
            return None
        collapsed.append(line)
        index += 1
    return collapsed


def _thunk_writes_argument(prep: list[str], arm64: bool) -> bool:
    """True when a prep instruction writes an argument register."""
    for line in prep:
        first_operand = line.split()[1].rstrip(",").lower() if len(line.split()) > 1 else ""
        if arm64:
            if ARM64_ARG_RE.match(first_operand):
                return True
        elif first_operand in X86_ARG_REGS:
            return True
    return False


def _branch_target(arm64: bool, instr_addr: int, length: int, value: int) -> int:
    """The address a branch immediate names, as the disassembler reads it.

    nyxstone prints ARM64 ``b``/``bl``/``adr`` deltas from the instruction's
    own address and x86 ``call``/``jmp`` deltas from its end — the same two
    rules ``_resolve_operand_target_addresses`` applies.
    """
    return instr_addr + value if arm64 else instr_addr + length + value


def _pure_thunks(
    funcs: dict, arch_target: str, plt: dict[int, str], addr_to_name: dict[int, str]
) -> tuple[list[dict], Counter]:
    """(b): the pure-thunk functions and their caller sites."""
    arm64 = _is_arm64(arch_target)
    thunks: list[dict] = []
    rejected_shapes: Counter = Counter()
    for func in funcs.values():
        if not isinstance(func, dict):
            continue
        lines, lengths, start = _function_lines(func)
        if not lines or len(lines) > 5:
            continue
        parts = lines[-1].strip().split(None, 1)
        mnemonic = parts[0].lower()
        operand = parts[1].strip() if len(parts) > 1 else ""
        if "[" in operand or "]" in operand:
            continue
        if arm64 and mnemonic != "b":
            continue
        if not arm64 and mnemonic not in ("jmp", "jmpq"):
            continue
        value = _parse_immediate_token(operand)
        if value is None:
            continue
        instr_addr = _line_address(start, lengths, len(lines) - 1)
        target = _branch_target(arm64, instr_addr, lengths[-1], value)
        # The tail branch must leave the function (a local branch is a loop,
        # not a thunk), and PLT entries are not thunks themselves.
        func_end = start + sum(lengths)
        if start <= target < func_end:
            continue
        if plt.get(start):
            continue
        target_name = addr_to_name.get(target) or plt.get(target)
        if not target_name:
            continue
        prep = [line.strip() for line in lines[:-1]]
        if arm64:
            collapsed = _collapse_arm64_addr_constant(prep)
            forms_ok = collapsed is not None and all(
                ARM64_MOVE_LOAD.match(line) or line == "<addr-constant>"
                for line in collapsed or []
            )
        else:
            forms_ok = all(X86_MOVE_LOAD.match(line) for line in prep)
        if not prep or not forms_ok:
            rejected_shapes[" ".join(line.split()[0].lower() for line in prep)] += 1
            continue
        thunks.append(
            {
                "name": func.get("name"),
                "address": start,
                "target": target,
                "target_name": target_name,
                "lines": len(lines),
                "prep": prep,
                "writes_argument": _thunk_writes_argument(prep, arm64),
            }
        )
    # Which resolved call sites name a thunk (by address, the honest key).
    thunk_by_addr = {thunk["address"]: thunk for thunk in thunks}
    site_counts: Counter = Counter()
    for func in funcs.values():
        if not isinstance(func, dict):
            continue
        for entry in func.get("direct_call_targets") or []:
            if not isinstance(entry, dict) or entry.get("kind") not in (
                "direct",
                "tailcall",
            ):
                continue
            try:
                target_addr_int = int(str(entry.get("target_address")), 16)
            except (TypeError, ValueError):
                continue
            thunk = thunk_by_addr.get(target_addr_int)
            if not thunk:
                continue
            site_counts["sites_into_thunks"] += 1
            site_counts[f"sites_into_{thunk['lines'] - 1}_move_thunks"] += 1
            if thunk["writes_argument"]:
                site_counts["sites_whose_thunk_writes_an_argument"] += 1
    return thunks, site_counts


def _relocated_words(parsed: lief.ELF.Binary) -> dict[int, int]:
    """{slot address: pointer} from RELATIVE relocations.

    A ``.data.rel.ro`` pointer table is zero in the file — the loader fills
    it from ``R_AARCH64_RELATIVE``/``R_X86_64_RELATIVE`` addends — so the
    table's strings are only readable through the relocation table.
    """
    words: dict[int, int] = {}
    relative_types = {
        int(lief.ELF.Relocation.TYPE.AARCH64_RELATIVE),
        int(lief.ELF.Relocation.TYPE.X86_64_RELATIVE),
    }
    for relocation in parsed.relocations:
        try:
            if int(relocation.type) not in relative_types:
                continue
            address = int(relocation.address)
            addend = int(getattr(relocation, "addend", 0) or 0)
            if addend:
                words[address] = addend
        except (AttributeError, TypeError, ValueError):
            continue
    return words


def _read_pointer_table(
    parsed: lief.Binary, base: int, relocated_words: dict[int, int], limit: int = 32
) -> list[str]:
    """Strings pointed at by consecutive words from ``base``, until one misses."""
    strings: list[str] = []
    for offset in range(0, limit * 8, 8):
        try:
            pointer = relocated_words.get(base + offset)
            if pointer is None:
                word_data = parsed.get_content_from_virtual_address(base + offset, 8)
                if not word_data or isinstance(word_data, lief.lief_errors):
                    break
                pointer = int.from_bytes(bytes(word_data), "little")
            if not pointer:
                continue
            content = parsed.get_content_from_virtual_address(pointer, 128)
            if not content or isinstance(content, lief.lief_errors):
                break
            text = decode_pointer_string(bytes(content))
            if not text:
                break
            strings.append(text)
        except (SystemError, Exception):
            break
    return strings


_ARM64_LDR_FROM_BASE = re.compile(r"^ldr\s+(x\d+),\s*\[([x]\d+)\s*(?:,\s*[^]]+)?\]", re.IGNORECASE)
_ARM64_MOV_X0 = re.compile(r"^mov\s+x0,\s*(x\d+)$", re.IGNORECASE)
_ARM64_LDR_IMM = re.compile(r"^ldr\s+(x\d+),\s*\[([x]\d+),\s*(#[^\]]+)\]", re.IGNORECASE)
_ARM64_MOV_REG = re.compile(r"^mov\s+(x\d+),\s*(x\d+)$", re.IGNORECASE)
_X86_LEA_RIP_DEF = re.compile(r"^lea\s+(\w+),\s*\[\s*rip\s*([+-]\s*\d+)\s*\]", re.IGNORECASE)
_X86_MOV_REG = re.compile(r"^mov\s+(\w+),\s*(\w+)$", re.IGNORECASE)
_X86_MOV_SLOT = re.compile(
    r"^mov\s+(\w+),\s*(?:qword ptr\s+)?\[(\w+)\s*(?:\+\s*(\w+|\d+))?\]", re.IGNORECASE
)


def _last_write(lines: list[str], reg: str) -> tuple[int, str] | None:
    """The last line before the end of ``lines`` whose first operand is ``reg``."""
    for index in range(len(lines) - 1, -1, -1):
        text = " ".join(lines[index].split())
        parts = text.split(None, 1)
        if len(parts) > 1 and parts[1].split(",")[0].strip().lower() == reg:
            return index, text
    return None


def _arm64_table_source(
    lines: list[str], lengths: list[int], start: int, bases: dict[str, int], depth: int = 4
) -> int | None:
    """Trace x0 backwards to a load from a materialised table base."""
    reg = "x0"
    for _ in range(depth):
        write = _last_write(lines, reg)
        if write is None:
            return None
        index, text = write
        match = _ARM64_LDR_IMM.match(text)
        if match and match.group(2).lower() in bases:
            offset = _parse_immediate_token(match.group(3))
            return bases[match.group(2).lower()] + (offset or 0)
        match = _ARM64_LDR_FROM_BASE.match(text)
        if match and match.group(1).lower() == reg and match.group(2).lower() in bases:
            return bases[match.group(2).lower()]
        match = _ARM64_MOV_REG.match(text)
        if match and match.group(1).lower() == reg:
            reg = match.group(2).lower()
            lines, lengths = lines[:index], lengths[:index]
            continue
        return None
    return None


def _x86_lea_value(
    lines: list[str], lengths: list[int], start: int, index: int, reg: str
) -> int | None:
    """The absolute address a register's `lea reg, [rip ± d]` materialised."""
    write = _last_write(lines[: index + 1], reg)
    if write is None:
        return None
    lea = _X86_LEA_RIP_DEF.match(write[1])
    if not lea or lea.group(1).lower() != reg:
        return None
    value = _parse_immediate_token(lea.group(2).replace(" ", ""))
    if value is None:
        return None
    line_addr = _line_address(start, lengths, write[0])
    return line_addr + lengths[write[0]] + value


def _x86_table_source(
    lines: list[str], lengths: list[int], start: int, depth: int = 5
) -> int | None:
    """Trace rdi backwards to a load from a rip-materialised table base."""
    reg = "rdi"
    for _ in range(depth):
        write = _last_write(lines, reg)
        if write is None:
            return None
        index, text = write
        match = _X86_MOV_SLOT.match(text)
        if match and match.group(1).lower() == reg:
            # `[base + off]`, `[index + base]` or `[base]`; the materialised
            # register is the lea one, the other operand an index or offset.
            first, second = match.group(2).lower(), (match.group(3) or "").lower()
            for candidate in (first, second):
                if not candidate or candidate.isdigit():
                    continue
                value = _x86_lea_value(lines, lengths, start, index, candidate)
                if value is not None:
                    offset = int(second) if second.isdigit() and candidate == first else 0
                    return value + offset
            return None
        match = _X86_MOV_REG.match(text)
        if match and match.group(1).lower() == reg:
            reg = match.group(2).lower()
            lines = lines[:index]
            continue
        return None
    return None


def _table_load_sites(
    funcs: dict,
    arch_target: str,
    parsed: lief.Binary,
    data_rel_ro: list[tuple[int, int]],
    relocated_words: dict[int, int],
) -> list[dict]:
    """(c): path-probe call sites whose path register holds a table load."""
    if not data_rel_ro:
        return []
    arm64 = _is_arm64(arch_target)
    sites: list[dict] = []
    for func in funcs.values():
        if not isinstance(func, dict):
            continue
        lines, lengths, start = _function_lines(func)
        if not lines:
            continue
        for entry in func.get("direct_call_targets") or []:
            if not isinstance(entry, dict) or entry.get("kind") != "direct":
                continue
            callee = str(entry.get("target_name") or "").split("@")[0]
            if callee not in PATH_PROBE_CALLEES:
                continue
            site_index = entry.get("site_index")
            if not isinstance(site_index, int) or not 0 < site_index <= len(lines):
                continue
            prefix_lines = lines[:site_index]
            prefix_lengths = lengths[:site_index]
            if arm64:
                # The materialisation state at the call, not at function end:
                # an epilogue `ldp x24, …` restores (and so clears) the base
                # register after every call site that uses it.
                bases = _arm64_materialisation(prefix_lines, prefix_lengths, start)
                base_addr = _arm64_table_source(prefix_lines, prefix_lengths, start, bases)
            else:
                base_addr = _x86_table_source(prefix_lines, prefix_lengths, start)
            if base_addr is None:
                continue
            if not any(lo <= base_addr < hi for lo, hi in data_rel_ro):
                continue
            sites.append(
                {
                    "function": func.get("name"),
                    "callee": entry.get("target_name"),
                    "table_base": base_addr,
                    "table_strings": _read_pointer_table(parsed, base_addr, relocated_words),
                }
            )
    return sites


def measure_file(task: tuple[str, str]) -> dict:
    """All three counts for one input; never raises into the shard driver."""
    path, source = task
    record: dict = {"file": path, "source": source, "error": None}
    try:
        md = parse(path, True)
        target = str(md.get("llvm_target_tuple") or "")
        funcs = md.get("disassembled_functions") or {}
        record["arch"] = target
        record["functions"] = len(funcs)
        parsed = lief.parse(path)
        is_elf = isinstance(parsed, lief.ELF.Binary)
        plt = _elf_plt_stub_names(parsed) if is_elf else {}
        addr_to_name = _build_addr_to_name_map(md, parsed) if is_elf else {}
        if _is_x86(target):
            record["tail_jmps"] = _tail_jmps(funcs, plt, addr_to_name)
        if _is_arm64(target) or _is_x86(target):
            thunks, site_counts = _pure_thunks(funcs, target, plt, addr_to_name)
            record["thunk_functions"] = len(thunks)
            record["outlined_named"] = sum(
                1 for thunk in thunks if str(thunk["name"]).startswith("OUTLINED_FUNCTION_")
            )
            record["thunk_sites"] = dict(site_counts)
            record["thunk_examples"] = [
                {"name": t["name"], "prep": t["prep"], "target": t["target_name"]}
                for t in thunks[:4]
            ]
            if is_elf:
                data_rel_ro = [
                    (int(sec.virtual_address), int(sec.virtual_address) + int(sec.size))
                    for sec in parsed.sections
                    if str(sec.name).startswith(".data.rel.ro")
                ]
                sites = _table_load_sites(
                    funcs, target, parsed, data_rel_ro, _relocated_words(parsed)
                )
                record["table_load_sites"] = len(sites)
                record["table_examples"] = sites[:6]
    except Exception as exc:  # a measurement script names its failures
        record["error"] = f"{type(exc).__name__}: {exc}"
    return record


def aggregate(records: list[dict]) -> dict:
    tail = Counter()
    thunk = Counter()
    tables = Counter()
    files_with_functions = 0
    for record in records:
        if record.get("error"):
            tail["errors"] += 1
            continue
        if record.get("functions"):
            files_with_functions += 1
        for key, value in (record.get("tail_jmps") or {}).get("counts", {}).items():
            tail[key] += value
        if record.get("thunk_functions"):
            thunk["files_with_thunks"] += 1
            thunk["thunk_functions"] += record["thunk_functions"]
        if record.get("outlined_named"):
            thunk["outlined_named"] += record["outlined_named"]
        for key, value in (record.get("thunk_sites") or {}).items():
            thunk[key] += value
        if record.get("table_load_sites"):
            tables["files_with_table_loads"] += 1
            tables["sites"] += record["table_load_sites"]
            for example in record.get("table_examples") or []:
                su = [s for s in example.get("table_strings") or [] if s.endswith("/su")]
                if len(su) >= 2:
                    tables["tables_with_two_plus_su_paths"] += 1
                    break
    return {
        "files": len(records),
        "files_disassembled": files_with_functions,
        "tail_jmps": dict(tail),
        "thunks": dict(thunk),
        "table_loads": dict(tables),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", action="append", default=[], help="input .so/.binary")
    parser.add_argument("--source", default="adhoc", help="corpus label for all files")
    parser.add_argument(
        "--list-file", help="file with one path per line (labels: 'path<TAB>source')"
    )
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--json", help="write full per-file records here")
    args = parser.parse_args(argv)

    tasks: list[tuple[str, str]] = [(path, args.source) for path in args.file]
    if args.list_file:
        for line in Path(args.list_file).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "\t" in line:
                path, source = line.split("\t", 1)
            else:
                path, source = line, args.source
            tasks.append((path, source))
    if not tasks:
        parser.error("no inputs: pass --file or --list-file")

    if args.jobs > 1:
        with ProcessPoolExecutor(max_workers=args.jobs) as pool:
            records = list(pool.map(measure_file, tasks, chunksize=1))
    else:
        records = [measure_file(task) for task in tasks]

    print(json.dumps(aggregate(records), indent=2, sort_keys=True))
    if args.json:
        Path(args.json).write_text(json.dumps(records, indent=1, sort_keys=True), encoding="utf-8")
        print(f"per-file records: {args.json}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
