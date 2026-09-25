#!/usr/bin/env python3
"""A2 B0 — bionic ELF fact probe: blint's facts next to llvm-readelf's, same run.

For every input ``.so`` this runs blint's ``parse()`` and one
``llvm-readelf -a --notes`` pass over the same file (ground rule 29: the
oracle is named, external, and read in the same run) and prints every fact
from ``02-bionic-elf-depth.md`` section A from both sides with a verdict.
The exit code is non-zero on any disagreement, so a packet's gate is
``elf_facts_probe.py <so>...``.

Facts blint does not emit yet are printed with the packet planned to add
them (B1/B2/B3) and do not fail the run; ``--strict`` turns them into
failures, which is the gate from B1 onward. Facts blint emits are compared
hard: ``AGREE`` or ``DISAGREE``, and the raw oracle values are printed
either way so a disagreement is readable without a rerun.

``shadow_call_stack`` is the one disassembly-only fact: an x18 prologue is
an instruction-stream fact with no readelf oracle, so both sides stay
``None`` until B3 wires the --disassemble comparison.

Usage:
  poetry run python tests/scripts/android/elf_facts_probe.py <so>... \
      [--strict] [--readelf PATH] [--json PATH]

Constants the oracle side decodes were confirmed at named tags (B0 commit
body): DT_ANDROID_REL* and DT_ANDROID_RELR* in bionic's ``elf.h`` (NDK
r28.2 sysroot ``usr/include/elf.h`` lines 235-238, 250-253), the standard
DT_RELR* tags in glibc's ``elf/elf.h`` lines 925-927, NT_ANDROID_TYPE_* and
the NT_MEMTAG_* bits plus GNU_PROPERTY_AARCH64_FEATURE_1_* in LLVM's
``llvm/include/llvm/BinaryFormat/ELF.h`` lines 1826-1873.
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

# LLVM ELF.h enum values (see module docstring for the tag they were
# confirmed at) — the oracle side decodes note descriptions with them.
NT_ANDROID_TYPE_IDENT = "NT_ANDROID_TYPE_IDENT"
NT_ANDROID_TYPE_MEMTAG = "NT_ANDROID_TYPE_MEMTAG"
NT_MEMTAG_LEVEL_ASYNC = 1
NT_MEMTAG_LEVEL_SYNC = 2
NT_MEMTAG_LEVEL_MASK = 3
NT_MEMTAG_HEAP = 4
NT_MEMTAG_STACK = 8

PAGE_16K = 16384

# One llvm-readelf pass; -a carries header, program headers, sections,
# dynamic and notes — everything the oracle side needs.
READELF_FLAGS = ["-a", "--notes"]

PHDR_RE = re.compile(
    r"^\s{2}([A-Z_0-9]+)\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)"
    r"\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+([RWE ]{0,4})\s+0x([0-9a-f]+)\s*$"
)
SECTION_RE = re.compile(r"^\s*\[\s*\d+\]\s+(\S+)\s+([A-Z_0-9]+)\s+")
DYN_RE = re.compile(r"^\s*0x[0-9a-f]+\s+\(([A-Z_0-9]+)\)\s+(.*)$")
SYMBOL_RE = re.compile(
    r"^\s*\d+:\s+[0-9a-f]+\s+\d+\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(\S*)\s*$"
)
NOTE_HEADER_RE = re.compile(r"^\s+(\S+)\s+0x([0-9a-f]+)\s+(\S+)")
NOTE_DATA_RE = re.compile(r"^\s+description data:\s*(.*)$")
HEX_WORD_RE = re.compile(r"[0-9a-f]{2}")

SANITIZER_PREFIXES = {
    "hwasan": "__hwasan_",
    "asan": "__asan_",
    "ubsan": "__ubsan_",
    "tsan": "__tsan_",
    "msan": "__msan_",
}
CFI_SYMBOL = "__cfi_check"


def default_readelf() -> str:
    """The NDK's llvm-readelf, preferring the newest NDK under ~/Android/sdk."""
    sdks = os.path.expanduser("~/Android/sdk/ndk")
    if os.path.isdir(sdks):
        for ndk in sorted(os.listdir(sdks), reverse=True):
            candidate = os.path.join(
                sdks, ndk, "toolchains", "llvm", "prebuilt", "darwin-x86_64",
                "bin", "llvm-readelf",
            )
            if os.path.exists(candidate):
                return candidate
    return "llvm-readelf"


# ---------------------------------------------------------------------------
# The oracle side: parse one `llvm-readelf -a --notes` output into facts.


def parse_readelf(text: str) -> dict:
    """Extract the raw oracle facts from one llvm-readelf -a --notes output."""
    facts: dict = {
        "class": "",
        "machine": "",
        "elf_type": "",
        "loads": [],
        "tls": None,
        "dyn": {},
        "sections": [],
        "symbol_names": set(),
        "notes": [],
    }
    lines = text.splitlines()
    idx = 0
    while idx < len(lines):
        line = lines[idx]
        if line.startswith("Class:"):
            facts["class"] = line.split(":", 1)[1].strip()
        elif line.startswith("Machine:"):
            facts["machine"] = line.split(":", 1)[1].strip()
        elif line.startswith("Type:"):
            facts["elf_type"] = line.split(":", 1)[1].strip()
        elif line.strip() == "Program Headers:":
            idx = _parse_program_headers(lines, idx + 2, facts)
        elif line.startswith("Dynamic section"):
            idx = _parse_dynamic(lines, idx + 2, facts)
        elif line.startswith("Symbol table "):
            idx = _parse_symbols(lines, idx + 1, facts)
        elif line.startswith("Displaying notes found in:"):
            section = line.rsplit(":", 1)[1].strip()
            idx = _parse_notes(lines, idx + 1, section, facts)
        elif SECTION_RE.match(line) and "Name" not in line:
            match = SECTION_RE.match(line)
            facts["sections"].append({"name": match.group(1), "type": match.group(2)})
        idx += 1
    return facts


def _parse_program_headers(lines: list[str], start: int, facts: dict) -> int:
    idx = start
    while idx < len(lines) and lines[idx].strip():
        if match := PHDR_RE.match(lines[idx]):
            segment = {
                "type": match.group(1),
                "offset": int(match.group(2), 16),
                "vaddr": int(match.group(3), 16),
                "flags": match.group(7).replace(" ", ""),
                "align": int(match.group(8), 16),
            }
            if segment["type"] == "LOAD":
                facts["loads"].append(segment)
            elif segment["type"] == "TLS":
                facts["tls"] = segment
        idx += 1
    return idx


def _parse_dynamic(lines: list[str], start: int, facts: dict) -> int:
    idx = start
    while idx < len(lines) and lines[idx].strip():
        if match := DYN_RE.match(lines[idx]):
            facts["dyn"].setdefault(match.group(1), []).append(match.group(2).strip())
        idx += 1
    return idx


def _parse_symbols(lines: list[str], start: int, facts: dict) -> int:
    idx = start
    while idx < len(lines) and lines[idx].strip():
        if match := SYMBOL_RE.match(lines[idx]):
            name = match.group(5).split("@", 1)[0]
            if name and name != "UND":
                facts["symbol_names"].add(name)
        idx += 1
    return idx


def _parse_notes(lines: list[str], start: int, section: str, facts: dict) -> int:
    note: dict = {}
    idx = start
    while idx < len(lines):
        line = lines[idx]
        if line.startswith("Displaying notes found in:"):
            break
        if header := NOTE_HEADER_RE.match(line):
            note = {
                "section": section,
                "owner": header.group(1),
                "size": int(header.group(2), 16),
                "type": header.group(3),
                "desc_hex": "",
                "decoded": [],
            }
            facts["notes"].append(note)
        elif note and line.strip():
            if match := NOTE_DATA_RE.match(line):
                note["desc_hex"] += "".join(HEX_WORD_RE.findall(match.group(1)))
            else:
                note["decoded"].append(line.strip())
        idx += 1
    return idx


def readelf_facts(exe_file: str, readelf: str) -> dict:
    proc = subprocess.run(
        [readelf, *READELF_FLAGS, exe_file], capture_output=True, text=True, check=False
    )
    if proc.returncode != 0:
        raise RuntimeError(f"{readelf} failed: {proc.stderr.strip()[:200]}")
    return parse_readelf(proc.stdout)


def _cstr(raw: bytes) -> str:
    return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")


def _bracketed(value: str) -> str | None:
    if "[" in value and "]" in value:
        return value.split("[", 1)[1].rsplit("]", 1)[0]
    return None


def oracle_android_ident(facts: dict) -> dict | None:
    """min_api + ndk_version from the NT_ANDROID_TYPE_IDENT description.

    Layout (bionic linker, the note writer): word 0 is the API level, then
    NUL-padded NDK version and build-number strings.
    """
    for note in facts["notes"]:
        if note["type"].startswith(NT_ANDROID_TYPE_IDENT):
            desc = bytes.fromhex(note["desc_hex"])
            if len(desc) < 4:
                return None
            return {
                "min_api": int.from_bytes(desc[:4], "little"),
                "ndk_version": _cstr(desc[4:20]),
                "ndk_build_number": _cstr(desc[20:]),
            }
    return None


def oracle_memtag(facts: dict) -> dict | None:
    """Level + target bits from the NT_ANDROID_TYPE_MEMTAG description.

    llvm-readelf decodes this note type, printing ``Tagging Mode`` /
    ``Heap`` / ``Stack`` instead of raw description bytes, so the decoded
    lines are the primary oracle and the hex decode the fallback.
    """
    for note in facts["notes"]:
        if note["type"].startswith(NT_ANDROID_TYPE_MEMTAG):
            if (value := _memtag_value_hex(note)) is not None:
                level = {
                    NT_MEMTAG_LEVEL_ASYNC: "async",
                    NT_MEMTAG_LEVEL_SYNC: "sync",
                }.get(value & NT_MEMTAG_LEVEL_MASK, "none")
                return {
                    "level": level,
                    "heap": bool(value & NT_MEMTAG_HEAP),
                    "stack": bool(value & NT_MEMTAG_STACK),
                }
            return _memtag_value_decoded(note)
    return None


def _memtag_value_hex(note: dict) -> int | None:
    desc = bytes.fromhex(note["desc_hex"])
    if len(desc) < 4:
        return None
    return int.from_bytes(desc[:4], "little")


def _memtag_value_decoded(note: dict) -> dict | None:
    modes = {}
    for line in note["decoded"]:
        key, _, value = line.partition(":")
        modes[key.strip().lower()] = value.strip().upper()
    mode = modes.get("tagging mode", "NONE")
    if mode not in ("NONE", "ASYNC", "SYNC"):
        return None
    return {
        "level": mode.lower(),
        "heap": modes.get("heap") == "ENABLED",
        "stack": modes.get("stack") == "ENABLED",
    }


def oracle_aarch64_features(facts: dict) -> list[str]:
    """BTI/PAC from the .note.gnu.property AArch64 feature word."""
    for note in facts["notes"]:
        if "NT_GNU_PROPERTY_TYPE_0" not in note["type"]:
            continue
        for line in note["decoded"]:
            if "feature" in line.lower() and "Properties:" in line:
                return [f.strip().upper() for f in line.rsplit(":", 1)[1].split(",")]
    return []


def oracle_packed_relocations(facts: dict) -> list[dict] | None:
    """Kind and entry counts from the packed-relocation dynamic tags.

    APS2 is the DT_ANDROID_REL(A)/SZ pair; RELR is the standard DT_RELR
    pair; DT_ANDROID_RELR* is Android's obsolete pre-API-30 RELR spelling.
    """
    dyn = facts["dyn"]
    kinds = []
    if "ANDROID_REL" in dyn or "ANDROID_RELA" in dyn:
        kinds.append({"kind": "aps2", "entry_count": _count(dyn, "ANDROID_RELSZ", 8)
                      or _count(dyn, "ANDROID_RELASZ", 8)})
    if "RELR" in dyn:
        kinds.append({"kind": "relr", "entry_count": _count(dyn, "RELRSZ", None)})
    if "ANDROID_RELR" in dyn:
        kinds.append({"kind": "android_relr", "entry_count": _count(dyn, "ANDROID_RELRSZ", None)})
    return kinds or None


def _count(dyn: dict, sz_tag: str, entry_size: int | None) -> int | None:
    sizes = dyn.get(sz_tag) or []
    if not sizes:
        return None
    try:
        size = int(sizes[0].split()[0], 0)
        return size // entry_size if entry_size else size
    except (ValueError, IndexError):
        return None


def oracle_page_alignment(facts: dict) -> dict:
    """Minimum LOAD align and 16 KB congruence from the program headers."""
    loads = facts["loads"]
    incongruent = [
        {"offset": seg["offset"], "vaddr": seg["vaddr"]}
        for seg in loads
        if (seg["offset"] - seg["vaddr"]) % PAGE_16K
    ]
    return {
        "min_load_align": min((seg["align"] for seg in loads), default=0),
        "mod_16384_incongruent": incongruent,
    }


def oracle_text_relocations(facts: dict) -> bool:
    """DT_TEXTREL present (lld emits the tag, not DF_TEXTREL, for -z notext)."""
    return "TEXTREL" in facts["dyn"]


def oracle_wx_segments(facts: dict) -> list[dict]:
    return [
        {"virtual_address": seg["vaddr"]}
        for seg in facts["loads"]
        if {"W", "E"} <= set(seg["flags"])
    ]


def oracle_needed(facts: dict) -> list[str]:
    needed = []
    for value in facts["dyn"].get("NEEDED", []):
        if (name := _bracketed(value)) is not None:
            needed.append(name)
    return needed


def oracle_soname(facts: dict) -> str | None:
    for value in facts["dyn"].get("SONAME", []):
        if (name := _bracketed(value)) is not None:
            return name
    return None


def oracle_tls_segment(facts: dict) -> dict | None:
    if (tls := facts["tls"]) is None:
        return None
    return {"align": tls["align"], "vaddr": tls["vaddr"]}


def oracle_sanitizers(facts: dict) -> dict | None:
    """Sanitizer runtime imports from the dynamic symbol names."""
    names = facts["symbol_names"]
    found = sorted(
        kind for kind, prefix in SANITIZER_PREFIXES.items()
        if any(name.startswith(prefix) for name in names)
    )
    result = {"sanitizers": found, "cfi": CFI_SYMBOL in names}
    return result if (found or result["cfi"]) else None


# __stack_chk_* is the canary's signal (CHECK_CANARY), not FORTIFY — the
# FORTIFIED_LIBC_IN_USE annotation carries the same exclusion.
CANARY_SYMBOL_PREFIX = "__stack_chk"


def oracle_fortify(facts: dict) -> dict | None:
    """bionic __*_chk imports from the dynamic symbol names."""
    names = facts["symbol_names"]
    fortified = sorted(
        name for name in names
        if name.startswith("__") and name.endswith("_chk")
        and not name.startswith(CANARY_SYMBOL_PREFIX)
    )
    return {"symbols": fortified} if fortified else None


def oracle_unwind(facts: dict) -> dict:
    """Unwind-table and mini-debuginfo section presence."""
    names = {section["name"] for section in facts["sections"]}
    return {
        "eh_frame": ".eh_frame" in names,
        "arm_exidx": ".ARM.exidx" in names,
        "gnu_debugdata": ".gnu_debugdata" in names,
    }


# ---------------------------------------------------------------------------
# The blint side: read the same facts out of parse() metadata.
#
# Readers return MISSING only when the metadata shape has no source for the
# fact (the key does not exist yet); a fact that is legitimately absent on
# this binary (no SONAME, no packing) is a real None and compares against
# the oracle normally.

MISSING = object()


def android_fact(metadata: dict, key: str):
    block = metadata.get("android")
    if not isinstance(block, dict):
        return MISSING
    return block.get(key)


def blint_android_ident(metadata: dict) -> dict | None:
    for note in metadata.get("notes") or []:
        if note.get("type") == "ANDROID_IDENT":
            return {
                "min_api": note.get("sdk_version"),
                "ndk_version": note.get("ndk_version") or None,
                "ndk_build_number": note.get("ndk_build_number") or None,
            }
    return None


def blint_soname(metadata: dict):
    if "dynamic_entries" not in metadata:
        return MISSING
    for entry in metadata.get("dynamic_entries") or []:
        if entry.get("tag") == "SONAME":
            return entry.get("name")
    return None


def blint_wx_segments(metadata: dict):
    if "wx_segments" not in metadata:
        return MISSING
    result = []
    for entry in metadata.get("wx_segments") or []:
        raw = entry.get("virtual_address")
        if raw:
            result.append({"virtual_address": int(raw, 16)})
    return result


# ---------------------------------------------------------------------------
# Fact registry: (name, packet, blint reader, oracle reader, comparator).
#
# A fact whose blint reader is None has no metadata source yet: the row is
# reported as blint-missing with the packet that will add it. Comparators
# compare the blint shape against the oracle shape directly.


def _eq(blint_value, oracle_value):
    return blint_value == oracle_value


FACTS = [
    ("is_targeting_android", "shipped",
     lambda md: md.get("is_targeting_android"),
     lambda orc: any(n["type"].startswith(NT_ANDROID_TYPE_IDENT) for n in orc["notes"]),
     _eq),
    ("android_ident.min_api", "shipped",
     lambda md: (blint_android_ident(md) or {}).get("min_api"),
     lambda orc: (oracle_android_ident(orc) or {}).get("min_api"),
     _eq),
    ("android_ident.ndk_version", "shipped",
     lambda md: (blint_android_ident(md) or {}).get("ndk_version"),
     lambda orc: (oracle_android_ident(orc) or {}).get("ndk_version"),
     _eq),
    ("packed_relocations", "B1",
     lambda md: android_fact(md, "packed_relocations"),
     oracle_packed_relocations, _eq),
    ("memtag", "B1",
     lambda md: android_fact(md, "memtag"),
     oracle_memtag, _eq),
    ("aarch64_features", "B1",
     lambda md: android_fact(md, "aarch64_features"),
     oracle_aarch64_features, _eq),
    ("text_relocations", "B1",
     lambda md: android_fact(md, "text_relocations"),
     oracle_text_relocations, _eq),
    ("soname", "shipped", blint_soname, oracle_soname, _eq),
    ("needed_absolute", "B1",
     lambda md: android_fact(md, "needed_absolute"),
     lambda orc: any("/" in name for name in oracle_needed(orc)), _eq),
    ("tls_segment", "B1",
     lambda md: android_fact(md, "tls_segment"),
     oracle_tls_segment, _eq),
    ("page_alignment", "B2",
     lambda md: android_fact(md, "page_alignment"),
     oracle_page_alignment, _eq),
    ("wx_segments", "shipped", blint_wx_segments, oracle_wx_segments, _eq),
    ("sanitizers", "B3",
     lambda md: android_fact(md, "sanitizers"),
     oracle_sanitizers, _eq),
    ("fortify", "B3",
     lambda md: android_fact(md, "fortify"),
     oracle_fortify, _eq),
    ("unwind", "B3",
     lambda md: android_fact(md, "unwind"),
     oracle_unwind, _eq),
    ("shadow_call_stack", "B3", None, None, None),
]


def probe_file(exe_file: str, readelf: str, strict: bool) -> tuple[bool, dict]:
    """One file: blint parse + one readelf pass, then the fact comparisons."""
    from blint.lib.binary import parse

    metadata = parse(exe_file)
    oracle = readelf_facts(exe_file, readelf)
    rows = []
    ok = True
    for name, packet, blint_reader, oracle_reader, comparator in FACTS:
        if blint_reader is None:
            rows.append({"fact": name, "verdict": "disassembly-only", "packet": packet})
            continue
        blint_value = blint_reader(metadata)
        if oracle_reader is None:
            rows.append({"fact": name, "verdict": "no-oracle", "packet": packet})
            continue
        oracle_value = oracle_reader(oracle)
        if blint_value is MISSING:
            rows.append(
                {"fact": name, "verdict": "blint-missing", "packet": packet,
                 "oracle": oracle_value}
            )
            if strict:
                ok = False
            continue
        if comparator(blint_value, oracle_value):
            rows.append(
                {"fact": name, "verdict": "AGREE", "packet": packet, "blint": blint_value}
            )
        else:
            ok = False
            rows.append(
                {"fact": name, "verdict": "DISAGREE", "packet": packet,
                 "blint": blint_value, "oracle": oracle_value}
            )
    return ok, {"file": exe_file, "facts": rows}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("files", nargs="+", help=".so files to probe")
    parser.add_argument("--strict", action="store_true",
                        help="fail facts blint does not emit yet")
    parser.add_argument("--readelf", default=default_readelf(),
                        help="llvm-readelf binary (default: newest NDK)")
    parser.add_argument("--json", dest="json_path", help="write the report as JSON")
    args = parser.parse_args()
    if not (os.path.exists(args.readelf) or shutil.which(args.readelf)):
        print(f"llvm-readelf not found: {args.readelf}", file=sys.stderr)
        return 3
    all_ok = True
    report = []
    for exe_file in args.files:
        try:
            ok, result = probe_file(exe_file, args.readelf, args.strict)
        except Exception as error:  # a probe reports, never crashes
            print(f"FAIL {exe_file}: {error}", file=sys.stderr)
            all_ok = False
            continue
        report.append(result)
        print(f"== {os.path.basename(exe_file)}")
        for row in result["facts"]:
            verdict = row["verdict"]
            if verdict == "DISAGREE":
                detail = f"  blint={row['blint']!r}  readelf={row['oracle']!r}"
                all_ok = False
            elif verdict == "blint-missing":
                detail = f"  readelf={row['oracle']!r}  (planned {row['packet']})"
            elif verdict == "AGREE":
                detail = f"  {row['blint']!r}"
            else:
                detail = ""
            print(f"  {verdict:<18} {row['fact']}{detail}")
        if not ok:
            all_ok = False
    if args.json_path:
        with open(args.json_path, "w") as fp:
            json.dump(report, fp, indent=1, default=str)
    return 0 if all_ok else 2


if __name__ == "__main__":
    sys.exit(main())
