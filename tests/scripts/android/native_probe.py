#!/usr/bin/env python3
"""A4a T0 — per-function accuracy probe: blint's disassembly vs llvm tools.

Prints, for every function an ``.so`` carries, blint's start/end/mode/
instruction count/direct-call targets next to the same facts derived from the
NDK's ``llvm-objdump``/``llvm-readelf`` over the same file in the same run,
with a one-line diff summary per function and a global summary. Exit code is
non-zero on any disagreement, so a packet's gate can be
``native_probe.py <so> && ...``.

Oracle construction (named tools, same run):

- ``llvm-readelf --symbols --wide`` supplies the defined FUNC symbols
  (start, size, name) and, when the symtab carries them, the ``$a``/``$t``
  mapping symbols that pin the mode per address range.
- ``llvm-objdump -d --no-show-raw-insn`` runs once per needed triple; its
  linear instruction timeline is sliced per function extent. NDK-built
  armeabi-v7a libraries carry no mapping symbols and their ELF e_flags do
  not select Thumb, so a plain ``-d`` pass disassembles everything as ARM.
  The per-function mode therefore comes from the symbol's ``st_value`` bit 0
  (Thumb) unless a mapping symbol says otherwise, and the matching
  ``thumbv7``/``armv7`` triple decodes that function's bytes.

The two sides are compared after trimming trailing padding on both with one
rule (a trailing run of ``nop``, Thumb ``movs r0, r0`` or ARM
``andeq r0, r0, r0`` zero words), because blint strips trailing padding
inside a known extent (``_find_function_end_index``) while objdump
linear-decodes the whole extent. Raw counts are reported alongside; only the
trimmed pair gates.

Usage:
  poetry run python tests/scripts/android/native_probe.py <lib.so> \
      [--function NAME] [--abi ABI] [--llvm-bin DIR] [--json PATH]
"""

from __future__ import annotations

import argparse
import bisect
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

# ABI -> the objdump triples the oracle decodes with. armeabi-v7a needs one
# run per instruction set state; every other ABI is a single-triple decode.
ABI_TRIPLES = {
    "arm64-v8a": ("aarch64-linux-android",),
    "armeabi-v7a": ("armv7-linux-androideabi", "thumbv7-linux-androideabi"),
    "x86_64": ("x86_64-linux-android",),
    "x86": ("i686-linux-android",),
    "riscv64": ("riscv64-linux-android",),
}
ARM32_ABIS = {"armeabi-v7a"}
ARM_TRIPLE, THUMB_TRIPLE = "armv7-linux-androideabi", "thumbv7-linux-androideabi"

# Direct-call mnemonics per ABI family. Only immediate-target forms count as
# edges; register/memory forms (blx rN, blr, call rax) are counted, not edges.
DIRECT_CALL_MNEMONICS = {
    "arm32": {"bl", "bl.w", "blx", "blx.w"},
    "arm64": {"bl"},
    "default": {"call", "callq"},
}

# Trailing padding trimmed from both sides before comparing: blint's own
# documented truncation rule (PADDING_TRAP_MNEMONICS strips these inside a
# known extent), applied identically to the oracle's linear decode so the
# two streams are comparable. The oracle's decode stays the named tool's.
from blint.lib.disassembler import PADDING_TRAP_MNEMONICS

PADDING_MNEMONICS = PADDING_TRAP_MNEMONICS

READELF_SYMBOL_RE = re.compile(
    r"^\s*\d+:\s+(?P<value>[0-9a-fA-F]+)\s+(?P<size>\d+)\s+(?P<type>\S+)"
    r"\s+(?P<bind>\S+)\s+(?P<vis>\S+)\s+(?P<ndx>\S+)\s*(?P<name>.*)$"
)
OBJDUMP_LABEL_RE = re.compile(r"^([0-9a-fA-F]+) <([^>]+)>:$")
OBJDUMP_INSTR_RE = re.compile(r"^\s*([0-9a-fA-F]+):\s+(.+?)\s*$")
# objdump appends " @ imm = #..." (ARM) or "# imm = ..." (x86) comments and a
# " <symbol+off>" annotation on branch targets; the operand text proper ends
# at whichever comes first.
OBJDUMP_COMMENT_RE = re.compile(r"\s+[@#]\s.*$")
OBJDUMP_ANNOTATION_RE = re.compile(r"\s+<[^>]*>$")
MAPPING_SYMBOL_RE = re.compile(r"^\$[atd](\.\d+)?$")


class ProbeError(Exception):
    """The probe could not run (missing tools, unparsable input)."""


def resolve_llvm_bin(explicit: str | None) -> tuple[Path, str]:
    """Locate llvm-objdump/llvm-readelf and name the provider.

    Order: --llvm-bin / ANDROID_NATIVE_LLVM_BIN, the newest NDK under
    ANDROID_SDK_ROOT (default ~/Android/sdk) or ~/Library/Android/sdk, then
    PATH. Returns the bin directory and a provenance string for the report.
    """
    candidates: list[tuple[str, str]] = []
    if explicit:
        candidates.append((explicit, f"--llvm-bin {explicit}"))
    elif os.environ.get("ANDROID_NATIVE_LLVM_BIN"):
        env = os.environ["ANDROID_NATIVE_LLVM_BIN"]
        candidates.append((env, f"ANDROID_NATIVE_LLVM_BIN={env}"))
    else:
        for root in (
            os.environ.get("ANDROID_SDK_ROOT") or str(Path.home() / "Android" / "sdk"),
            str(Path.home() / "Library" / "Android" / "sdk"),
        ):
            ndk_root = Path(root) / "ndk"
            if not ndk_root.is_dir():
                continue
            # Newest NDK first: version-named directories sort oldest-first.
            for ndk in sorted(ndk_root.iterdir(), reverse=True):
                for prebuilt in (ndk / "toolchains" / "llvm" / "prebuilt").glob("*"):
                    bin_dir = prebuilt / "bin"
                    if (bin_dir / "llvm-objdump").exists():
                        candidates.append((str(bin_dir), f"NDK {ndk.name}"))
    found_on_path = shutil.which("llvm-objdump")
    if found_on_path:
        candidates.append((str(Path(found_on_path).parent), "PATH"))
    for bin_dir, provenance in candidates:
        path = Path(bin_dir)
        if (path / "llvm-objdump").exists() and (path / "llvm-readelf").exists():
            return path, provenance
    raise ProbeError(
        "llvm-objdump/llvm-readelf not found; pass --llvm-bin, set "
        "ANDROID_NATIVE_LLVM_BIN, install an NDK under $ANDROID_SDK_ROOT, or put them on PATH"
    )


def _run(tool: Path, args: list[str], so: Path) -> str:
    proc = subprocess.run([str(tool), *args, str(so)], capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise ProbeError(f"{tool.name} failed ({proc.returncode}): {proc.stderr[-400:]}")
    return proc.stdout


def tool_version(bin_dir: Path, tool: str) -> str:
    proc = subprocess.run(
        [str(bin_dir / tool), "--version"], capture_output=True, text=True, check=False
    )
    for line in (proc.stdout or "").splitlines():
        if "LLVM version" in line:
            return line.strip()
    return "unknown"


def detect_abi(metadata: dict, override: str | None) -> str:
    """ABI from --abi, else from blint's llvm_target_tuple."""
    if override:
        if override not in ABI_TRIPLES:
            raise ProbeError(f"unknown --abi {override}; choose from {sorted(ABI_TRIPLES)}")
        return override
    tuple_l = str(metadata.get("llvm_target_tuple") or "").lower()
    if "aarch64" in tuple_l or "arm64" in tuple_l:
        return "arm64-v8a"
    if tuple_l.startswith(("thumb", "armv7", "arm-")) or "armeabi" in tuple_l:
        return "armeabi-v7a"
    if "riscv" in tuple_l:
        return "riscv64"
    if "i686" in tuple_l or tuple_l.startswith(("i386", "x86-")):
        return "x86"
    if "x86_64" in tuple_l:
        return "x86_64"
    raise ProbeError(
        f"cannot infer ABI from llvm_target_tuple {metadata.get('llvm_target_tuple')!r}; pass --abi"
    )


# ---------------------------------------------------------------- readelf side


def parse_readelf_symbols(output: str) -> tuple[dict[int, dict], dict[int, str]]:
    """Readelf symbol table -> (defined FUNC symbols by aligned start, modes).

    FUNC symbols: ``{name, start, size, thumb}`` where ``thumb`` is the raw
    st_value bit 0. Mapping symbols (``$a``/``$t``/``$d`` and their ``.N``
    suffixed forms) become a sorted ``{address: mode}`` map, ``data``
    included so callers can see data islands too.
    """
    functions: dict[int, dict] = {}
    mapping: dict[int, str] = {}
    for line in output.splitlines():
        match = READELF_SYMBOL_RE.match(line)
        if not match:
            continue
        sym_type = match.group("type")
        value = int(match.group("value"), 16)
        name = match.group("name").strip()
        ndx = match.group("ndx")
        if sym_type == "FUNC" and ndx != "UND":
            start = value & ~1
            entry = functions.setdefault(
                start,
                {
                    "name": name,
                    "start": start,
                    "size": int(match.group("size")),
                    "thumb": bool(value & 1),
                },
            )
            if name and not entry["name"]:
                entry["name"] = name
        elif sym_type == "NOTYPE" and MAPPING_SYMBOL_RE.match(name):
            mode_char = name[1]
            mapping[value] = {"a": "arm", "t": "thumb", "d": "data"}[mode_char]
    return functions, dict(sorted(mapping.items()))


def parse_readelf_unwind(output: str) -> set[int]:
    """Unwind-table function starts: eh_frame initial_location + exidx FunctionAddress.

    ``llvm-readelf --unwind`` lists one entry per function the runtime can
    unwind, which is exactly the table blint's own discovery reads, so the
    oracle's function set is FUNC symbols plus these starts. exidx addresses
    arrive with the Thumb bit already clear.
    """
    starts: set[int] = set()
    for line in output.splitlines():
        for field in ("initial_location:", "FunctionAddress:"):
            token = line.strip()
            if token.startswith(field):
                value = token[len(field) :].strip()
                with_value = value.split()[0] if value else ""
                if with_value.startswith("0x"):
                    try:
                        starts.add(int(with_value, 16) & ~1)
                    except ValueError:
                        continue
    return starts


def function_modes(functions: dict[int, dict], mapping: dict[int, str]) -> dict[int, str]:
    """Per-function ARM32 mode: mapping symbols win, else the symbol's bit 0."""
    if not mapping:
        return {
            start: (
                "unknown" if entry["thumb"] is None else ("thumb" if entry["thumb"] else "arm")
            )
            for start, entry in functions.items()
        }
    starts = sorted(mapping)
    modes = {}
    for start, entry in functions.items():
        if entry["thumb"] is None:
            mode = "unknown"
        else:
            mode = "thumb" if entry["thumb"] else "arm"
        idx = bisect.bisect_right(starts, start) - 1
        if idx >= 0 and mapping[starts[idx]] != "data":
            mode = mapping[starts[idx]]
        modes[start] = mode
    return modes


# --------------------------------------------------------------- objdump side


def parse_objdump_timeline(output: str) -> list[dict]:
    """One objdump -d pass -> the linear instruction timeline of the file.

    Each entry: ``{address, mnemonic, operands}``; ``<unknown>`` words decode
    to mnemonic ``"<unknown>"`` (data or a failed decode) and stay in the
    timeline so extents keep their positions.
    """
    timeline: list[dict] = []
    for line in output.splitlines():
        if OBJDUMP_LABEL_RE.match(line):
            continue
        instr = OBJDUMP_INSTR_RE.match(line)
        if not instr:
            continue
        address = int(instr.group(1), 16)
        text = OBJDUMP_ANNOTATION_RE.sub("", OBJDUMP_COMMENT_RE.sub("", instr.group(2)).strip())
        parts = text.split(None, 1)
        mnemonic = parts[0] if parts else ""
        operands = parts[1].strip() if len(parts) > 1 else ""
        timeline.append({"address": address, "mnemonic": mnemonic, "operands": operands})
    timeline.sort(key=lambda instr: instr["address"])
    return timeline


def slice_timeline(timeline: list[dict], addresses: list[int], start: int, end: int) -> list[dict]:
    """Instructions with start <= address < end, over a sorted timeline."""
    lo = bisect.bisect_left(addresses, start)
    hi = lo
    while hi < len(timeline) and timeline[hi]["address"] < end:
        hi += 1
    return timeline[lo:hi]


def direct_call_targets(
    instructions: list[dict], call_mnemonics: set[str], mask_thumb_bit: bool = False
) -> set[int]:
    """Immediate-target bl/blx/call addresses (bit 0 cleared on ARM32 only)."""
    targets: set[int] = set()
    for instr in instructions:
        if instr["mnemonic"] not in call_mnemonics:
            continue
        match = re.match(r"^(?:0x)?([0-9a-fA-F]+)\b", instr["operands"])
        if match:
            value = int(match.group(1), 16)
            targets.add(value & ~1 if mask_thumb_bit else value)
    return targets


def build_oracle(so: Path, bin_dir: Path, abi: str) -> tuple[dict[int, dict], dict]:
    """Run readelf + objdump and assemble per-function oracle records."""
    functions, mapping = parse_readelf_symbols(
        _run(bin_dir / "llvm-readelf", ["--symbols", "--wide"], so)
    )
    unwind_starts = parse_readelf_unwind(_run(bin_dir / "llvm-readelf", ["--unwind"], so))
    for start in unwind_starts:
        functions.setdefault(start, {"name": "", "start": start, "size": 0, "thumb": None})
    timelines: dict[str, tuple[list[dict], list[int]]] = {}
    for triple in ABI_TRIPLES[abi]:
        # objdump defaults to AT&T syntax on x86; blint's nyxstone renders
        # Intel, so ask the oracle for the same dialect before comparing.
        extra_args = ["--x86-asm-syntax=intel"] if triple.startswith(("i686", "x86_64")) else []
        output = _run(
            bin_dir / "llvm-objdump",
            ["-d", "--no-show-raw-insn", f"--triple={triple}", *extra_args],
            so,
        )
        timeline = parse_objdump_timeline(output)
        timelines[triple] = (timeline, [instr["address"] for instr in timeline])
    modes = function_modes(functions, mapping) if abi in ARM32_ABIS else {}
    call_mnemonics = DIRECT_CALL_MNEMONICS[
        "arm32" if abi in ARM32_ABIS else ("arm64" if abi == "arm64-v8a" else "default")
    ]
    starts = sorted(functions)
    oracle: dict[int, dict] = {}
    for index, start in enumerate(starts):
        entry = functions[start]
        if entry["size"]:
            end = start + entry["size"]
        elif index + 1 < len(starts):
            end = starts[index + 1]
        else:
            end = start + (1 << 20)
        mode = modes.get(start, "arm") if abi in ARM32_ABIS else "n/a"
        timeline, addresses = (
            timelines[THUMB_TRIPLE if mode == "thumb" else ARM_TRIPLE]
            if abi in ARM32_ABIS
            else timelines[ABI_TRIPLES[abi][0]]
        )
        instructions = slice_timeline(timeline, addresses, start, end)
        trimmed = trim_padding([f"{i['mnemonic']} {i['operands']}".strip() for i in instructions])
        trimmed_last = instructions[len(trimmed) - 1]["address"] if trimmed else start
        oracle[start] = {
            **entry,
            "mode": mode,
            "raw_count": len(instructions),
            "trimmed": trimmed,
            "trimmed_last": trimmed_last,
            "targets": direct_call_targets(instructions, call_mnemonics, abi in ARM32_ABIS),
        }
    provenance = {
        "llvm_bin": str(bin_dir),
        "objdump_version": tool_version(bin_dir, "llvm-objdump"),
        "readelf_version": tool_version(bin_dir, "llvm-readelf"),
        "triples": list(ABI_TRIPLES[abi]),
        "mapping_symbols": {hex(addr): mode for addr, mode in mapping.items()},
    }
    return oracle, provenance


# ----------------------------------------------------------------- blint side


def collect_blint(metadata: dict, abi: str) -> dict[int, dict]:
    """blint's disassembled functions keyed by (aligned) start address.

    The mode column is blint's own when it records one; until it does, the
    ARM32 mode is stated as the one its single nyxstone instance decodes in
    (the triple's ``arm`` arch prefix selects ARM state), so a mode
    disagreement is visible before blint learns per-function modes.
    """
    out: dict[int, dict] = {}
    for func in (metadata.get("disassembled_functions") or {}).values():
        try:
            address = int(func.get("address", "0x0"), 16)
        except ValueError:
            continue
        if abi in ARM32_ABIS:
            address &= ~1
        lengths = func.get("instruction_lengths") or []
        raw_count = int(func.get("instruction_count") or 0)
        assembly_lines = [
            line for line in (func.get("assembly") or "").splitlines() if line.strip()
        ]
        targets: set[int] = set()
        for target in func.get("direct_call_targets") or []:
            if target.get("kind") != "direct" or not target.get("target_address"):
                continue
            value = int(target["target_address"], 16)
            targets.add(value & ~1 if abi in ARM32_ABIS else value)
        mode = func.get("instruction_mode")
        if mode is None and abi in ARM32_ABIS:
            mode = "arm(triple)"
        out[address] = {
            "name": func.get("name", ""),
            "start": address,
            "raw_count": raw_count,
            "lengths": lengths,
            "lines": assembly_lines,
            "mode": mode,
            "targets": targets,
            "indirect_count": sum(
                1
                for target in func.get("direct_call_targets") or []
                if target.get("kind") != "direct"
            ),
        }
    return out


def trim_padding(lines: list[str]) -> list[str]:
    """Drop a trailing padding run (one rule, both sides trimmed alike).

    Membership is decided on the mnemonic token alone, matching how blint's
    truncation splits the first word of each assembly line.
    """
    index = len(lines)
    while index > 0:
        mnemonic = lines[index - 1].split(None, 1)[0].lower().rstrip(":")
        if mnemonic in PADDING_MNEMONICS:
            index -= 1
        else:
            break
    return lines[:index]


def prepare_blint(blint_funcs: dict[int, dict]) -> dict[int, dict]:
    """Attach trimmed lines and last-kept-instruction addresses."""
    for func in blint_funcs.values():
        func["trimmed"] = trim_padding(func["lines"])
        keep = len(func["trimmed"])
        func["trimmed_last"] = (
            func["start"] + sum(func["lengths"][: keep - 1]) if keep else func["start"]
        )
    return blint_funcs


# ---------------------------------------------------------------- comparison


def compare(blint_funcs: dict[int, dict], oracle_funcs: dict[int, dict], abi: str) -> dict:
    """Full comparison report; every disagreement lands in summary['diffs']."""
    report: dict = {"abi": abi, "functions": [], "summary": {}}
    diffs: list[str] = []
    matched = missing = extra = boundary = counts = mnemonics = mode_diff = 0
    edge_matches = blint_edges_total = oracle_edges_total = 0
    for start in sorted(set(blint_funcs) | set(oracle_funcs)):
        bl = blint_funcs.get(start)
        orac = oracle_funcs.get(start)
        entry: dict = {"address": hex(start)}
        if orac:
            entry.update(
                {
                    "oracle_name": orac["name"],
                    "oracle_mode": orac.get("mode", "n/a"),
                    "oracle_count": orac["raw_count"],
                    "oracle_trimmed": len(orac["trimmed"]),
                    "oracle_last": hex(orac["trimmed_last"]),
                    "oracle_targets": sorted(hex(t) for t in orac["targets"]),
                }
            )
        if bl:
            entry.update(
                {
                    "blint_name": bl["name"],
                    "blint_mode": bl.get("mode"),
                    "blint_count": bl["raw_count"],
                    "blint_trimmed": len(bl["trimmed"]),
                    "blint_last": hex(bl["trimmed_last"]),
                    "blint_targets": sorted(hex(t) for t in bl["targets"]),
                }
            )
            # Edge totals count every function, matched or not: a function
            # blint never found contributes its oracle edges to recall as
            # misses, and a spurious function's edges to precision.
            blint_edges_total += len(bl["targets"])
        if orac:
            oracle_edges_total += len(orac["targets"])
        if not bl:
            missing += 1
            diffs.append(f"missing {hex(start)} ({orac['name']})")
            entry["verdict"] = "missing"
        elif not orac:
            extra += 1
            diffs.append(f"extra {hex(start)} ({bl['name']})")
            entry["verdict"] = "extra"
        else:
            matched += 1
            entry["verdict"] = "match"
            # Mode gates only where the oracle states one: parity-derived or
            # mapping-symbol-derived, never an unwind-only "unknown".
            if (
                abi in ARM32_ABIS
                and orac.get("mode") in ("arm", "thumb")
                and bl.get("mode") != orac.get("mode")
            ):
                mode_diff += 1
                diffs.append(
                    f"mode {hex(start)} ({orac['name']}): blint {bl.get('mode')} vs oracle {orac.get('mode')}"
                )
            if bl["trimmed_last"] != orac["trimmed_last"]:
                boundary += 1
                entry["verdict"] = "boundary"
                diffs.append(
                    f"boundary {hex(start)} ({orac['name']}): blint last {hex(bl['trimmed_last'])} "
                    f"vs oracle {hex(orac['trimmed_last'])}"
                )
            elif len(bl["trimmed"]) != len(orac["trimmed"]):
                counts += 1
                entry["verdict"] = "count"
                diffs.append(
                    f"count {hex(start)} ({orac['name']}): blint {len(bl['trimmed'])} "
                    f"vs oracle {len(orac['trimmed'])}"
                )
            else:
                bl_mnemonics = [line.split(None, 1)[0].lower() for line in bl["trimmed"]]
                or_mnemonics = [line.split(None, 1)[0].lower() for line in orac["trimmed"]]
                if bl_mnemonics != or_mnemonics:
                    mnemonics += 1
                    entry["verdict"] = "mnemonics"
                    first = next(
                        (i for i, (b, o) in enumerate(zip(bl_mnemonics, or_mnemonics)) if b != o),
                        None,
                    )
                    diffs.append(
                        f"mnemonics {hex(start)} ({orac['name']}): first divergence at instruction {first}"
                    )
            bl_targets, or_targets = bl["targets"], orac["targets"]
            edge_matches += len(bl_targets & or_targets)
            if missing_edges := sorted(or_targets - bl_targets):
                entry["edges_missing"] = [hex(t) for t in missing_edges]
                diffs.append(f"edges missing in {hex(start)}: {[hex(t) for t in missing_edges]}")
            if extra_edges := sorted(bl_targets - or_targets):
                entry["edges_extra"] = [hex(t) for t in extra_edges]
                diffs.append(f"edges extra in {hex(start)}: {[hex(t) for t in extra_edges]}")
        report["functions"].append(entry)
    report["summary"] = {
        "blint_functions": len(blint_funcs),
        "oracle_functions": len(oracle_funcs),
        "matched": matched,
        "missing": missing,
        "extra": extra,
        "boundary_mismatch": boundary,
        "count_mismatch": counts,
        "mnemonic_mismatch": mnemonics,
        "mode_mismatch": mode_diff,
        "edge_precision": (edge_matches / blint_edges_total) if blint_edges_total else None,
        "edge_recall": (edge_matches / oracle_edges_total) if oracle_edges_total else None,
        "boundary_precision": (matched / len(blint_funcs)) if blint_funcs else None,
        "boundary_recall": (matched / len(oracle_funcs)) if oracle_funcs else None,
        "diffs": diffs,
        "agreement": not diffs,
    }
    return report


def _print_report(report: dict, only_function: str | None) -> None:
    summary = report["summary"]
    print(f"== native probe: {report['file']}")
    print(
        f"oracle: {report['provenance']['objdump_version']} ({report['provenance']['llvm_bin']})"
    )
    print(f"abi: {report['abi']}  triples: {', '.join(report['provenance']['triples'])}")
    print(
        f"functions: blint={summary['blint_functions']} oracle={summary['oracle_functions']} "
        f"matched={summary['matched']} missing={summary['missing']} extra={summary['extra']}"
    )
    print(
        f"mismatches: mode={summary['mode_mismatch']} boundary={summary['boundary_mismatch']} "
        f"count={summary['count_mismatch']} mnemonics={summary['mnemonic_mismatch']}"
    )
    print(
        f"edges: precision={summary['edge_precision']} recall={summary['edge_recall']}; "
        f"boundaries: precision={summary['boundary_precision']} recall={summary['boundary_recall']}"
    )
    print(
        f"{'addr':>10}  {'mode':12} {'verdict':9} {'bl(cnt,last)':>18} {'oracle(cnt,last)':>18}  name"
    )
    for entry in report["functions"]:
        name = entry.get("oracle_name") or entry.get("blint_name") or ""
        if only_function and only_function not in name:
            continue
        bl = (
            f"{entry.get('blint_trimmed', '-')}/{entry.get('blint_last', '-')}"
            if "blint_trimmed" in entry
            else "-"
        )
        orac = (
            f"{entry.get('oracle_count', '-')}/{entry.get('oracle_last', '-')}"
            if "oracle_count" in entry
            else "-"
        )
        print(
            f"{entry['address']:>10}  {entry.get('oracle_mode', 'n/a')!s:12} "
            f"{entry.get('verdict', '?'):9} {bl:>18} {orac:>18}  {name}"
        )
    if summary["diffs"]:
        print("diffs:")
        for diff in summary["diffs"]:
            print(f"  - {diff}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("so", type=Path, help="shared library or executable to probe")
    parser.add_argument("--function", help="filter the per-function table by substring")
    parser.add_argument("--abi", choices=sorted(ABI_TRIPLES), help="override ABI detection")
    parser.add_argument("--llvm-bin", help="directory with llvm-objdump/llvm-readelf")
    parser.add_argument("--json", type=Path, help="write the full report JSON here")
    args = parser.parse_args(argv)

    try:
        bin_dir, llvm_provenance = resolve_llvm_bin(args.llvm_bin)
        from blint.lib.binary import parse

        metadata = parse(str(args.so), disassemble=True)
        abi = detect_abi(metadata, args.abi)
        oracle, provenance = build_oracle(args.so, bin_dir, abi)
        provenance["llvm_bin_source"] = llvm_provenance
        blint_funcs = prepare_blint(collect_blint(metadata, abi))
        report = compare(blint_funcs, oracle, abi)
    except (ProbeError, ImportError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    report["file"] = str(args.so)
    report["provenance"] = provenance
    report["blint_target_tuple"] = metadata.get("llvm_target_tuple")
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=2, sort_keys=True, default=str) + "\n")
    _print_report(report, args.function)
    print(f"agreement: {report['summary']['agreement']}")
    return 0 if report["summary"]["agreement"] else 1


if __name__ == "__main__":
    sys.exit(main())
