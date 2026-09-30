#!/usr/bin/env python3
"""A10 Q0 - the 32-bit gap, measured. Measure only; no production change.

For every dex native declaration that is unbound on armeabi-v7a or x86 but
bound on arm64-v8a (the join with the FindClass confirmer, i.e.
``--disassemble``), this answers:

(a) which library holds the arm64 binding, and what that library's 32-bit
    copy does around the declaration's method-name string: every relocated
    word that points at it, the relocation's type, LIEF's addend, the
    stored word, the join's own relocation-map value, and the ground-truth
    value (REL: the addend lives in the stored word; RELA: symbol value
    plus the entry's addend);
(b) whether the JNINativeMethod triple around that word validates under
    the ground-truth values (name identifier, signature grammar, fnPtr on
    a function start of that ABI's own copy) - i.e. whether reading the
    implicit addend correctly is the whole difference;
(c) an independent cross-check of the diagnosed words against
    ``llvm-readelf -r`` and the section hex dumps (``llvm-readelf -x``),
    never against LIEF alone;
(d) the join's counts per APK and ABI (every ABI, not only the gap ones);
(e) which instruction-text models ``blint.lib.absint`` defines and which
    the FindClass confirmer can step - the 32-bit model inventory.

Usage:
  PATH="/opt/homebrew/opt/llvm@18/bin:$PATH" NYXSTONE_LLVM_PREFIX=/opt/homebrew/opt/llvm@18 \
  poetry run python tests/scripts/android/a10_q0_measure.py \
      --corpus ~/sandbox/android-corpus [--json PATH]
"""

from __future__ import annotations

import argparse
import contextlib
import json
import re
import subprocess
import sys
import tempfile
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import lief

# The APKs the A9 review measured, plus organicmaps (the ladder's R2 pair).
APKS = {
    "com.blint.rnhello_1.apk": "tier3-frameworks",
    "app.organicmaps_26082718.apk": "tier2-fdroid",
}
GAP_ABIS = ("armeabi-v7a", "x86")
BASELINE_ABI = "arm64-v8a"

READELF = "/opt/homebrew/opt/llvm@18/bin/llvm-readelf"


def fn_starts_and_names(parsed) -> tuple[set[int], dict[int, str]]:
    """F1's own function-start set for one parsed library copy."""
    from blint.lib.funcdisc.unwind import discover_functions

    starts: set[int] = set()
    addr_to_name: dict[int, str] = {}
    for symbol in parsed.dynamic_symbols:
        try:
            if symbol.value and "FUNC" in str(symbol.type) and int(symbol.shndx or 0):
                address = int(symbol.value) & ~1
                starts.add(address)
                if symbol.name:
                    addr_to_name.setdefault(address, symbol.name)
        except Exception:
            continue
    for discovered in discover_functions(parsed) or []:
        address = discovered.get("address")
        with contextlib.suppress(TypeError, ValueError):
            starts.add((address if isinstance(address, int) else int(address, 16)) & ~1)
    return starts, addr_to_name


def join_relocation_maps(parsed) -> dict[int, int]:
    """The join's own combined relocation map, exactly as production builds it."""
    from blint.lib.jni import defined_symbol_relocation_map, relative_relocation_map

    values, _ = relative_relocation_map(parsed)
    for slot, target in defined_symbol_relocation_map(parsed).items():
        values.setdefault(slot, target)
    return values


def stored_word(parsed, address: int, word_size: int) -> int | None:
    try:
        content = bytes(parsed.get_content_from_virtual_address(address, word_size))
        return int.from_bytes(content, "little")
    except Exception:
        return None


def word_size_of(parsed) -> int:
    try:
        return 8 if int(parsed.header.identity[4]) == 2 else 4
    except Exception:
        return 8


def ground_truth_targets(parsed) -> dict[int, dict]:
    """Per relocated slot: type, LIEF addend, stored word, the ground-truth
    target VA, and LIEF's is_rela flag.

    Ground truth per the ELF spec: R_*_RELATIVE carries the target in the
    addend (RELA) or in the stored word (REL); an absolute relocation
    against a defined symbol resolves to symbol value + addend (RELA) or
    symbol value + stored word (REL - the implicit addend).
    """
    word_size = word_size_of(parsed)
    out: dict[int, dict] = {}
    try:
        relocations = list(parsed.relocations)
    except Exception:
        return out
    for relocation in relocations:
        try:
            address = int(relocation.address)
        except Exception:
            continue
        type_name = str(getattr(relocation, "type", ""))
        addend = 0
        with contextlib.suppress(Exception):
            addend = int(getattr(relocation, "addend", 0) or 0)
        is_rela = bool(getattr(relocation, "is_rela", False))
        word = stored_word(parsed, address, word_size)
        symbol_value = None
        symbol_name = None
        with contextlib.suppress(Exception):
            symbol = relocation.symbol
            if symbol is not None:
                symbol_value = int(symbol.value or 0)
                symbol_name = str(symbol.name or "")
        target = None
        if "RELATIVE" in type_name:
            target = addend if addend else word
        elif symbol_value is not None:
            target = symbol_value + (addend if is_rela else (word or 0))
        out[address] = {
            "type": type_name,
            "lief_addend": addend,
            "is_rela": is_rela,
            "stored_word": word,
            "symbol_value": symbol_value,
            "symbol_name": symbol_name,
            "truth": target,
        }
    return out


def section_address_ranges(parsed) -> list[tuple[str, int, int]]:
    out = []
    for section in parsed.sections:
        try:
            out.append((str(section.name or ""), int(section.virtual_address), int(section.size)))
        except Exception:
            continue
    return out


def string_occurrences(parsed, needle: bytes) -> list[tuple[str, int]]:
    """(section name, address) of every NUL-terminated occurrence of needle."""
    out: list[tuple[str, int]] = []
    for name, base, size in section_address_ranges(parsed):
        if not name.startswith((".rodata", ".data", ".dynstr", ".text")):
            continue
        try:
            blob = bytes(parsed.get_content_from_virtual_address(base, size))
        except Exception:
            continue
        start = 0
        while True:
            at = blob.find(needle, start)
            if at < 0:
                break
            out.append((name, base + at))
            start = at + 1
    return out


def readelf_relocations(path: Path) -> dict[int, str]:
    """offset -> type name, from llvm-readelf -r (the independent oracle)."""
    out: dict[int, str] = {}
    try:
        text = subprocess.run(
            [READELF, "-r", str(path)], capture_output=True, text=True, timeout=120
        ).stdout
    except Exception:
        return out
    for line in text.splitlines():
        match = re.match(r"^([0-9a-f]{8,16})\s+[0-9a-f]+\s+(\S+)", line)
        if match:
            out[int(match.group(1), 16)] = match.group(2)
    return out


# readelf spells types the ELF way (R_ARM_ABS32); LIEF prints its enum
# (TYPE.ARM_ABS32), and i386's R_386_32 is TYPE.X86_32 in LIEF. Both sides
# name the same relocation; compare the semantic token.
_TYPE_ALIASES = {"X86_32": "386_32", "X86_RELATIVE": "386_RELATIVE", "X86_GLOB_DAT": "386_GLOB_DAT"}


def _normalize_type(name: str) -> str:
    token = name.split(".")[-1].lstrip("R_")
    return _TYPE_ALIASES.get(token, token)


def readelf_section_words(path: Path, section: str) -> dict[int, int]:
    """offset -> 4/8-byte little-endian word from llvm-readelf -x hexdump.

    The hexdump prints the bytes as stored, so an 8-hex-digit group is a
    little-endian word on disk and must be byte-reversed when read as a
    number.
    """
    try:
        text = subprocess.run(
            [READELF, "-x", section, str(path)], capture_output=True, text=True, timeout=120
        ).stdout
    except Exception:
        return {}
    words: dict[int, int] = {}
    width: int | None = None
    for line in text.splitlines():
        match = re.match(r"^\s*0x([0-9a-f]+)\s+((?:[0-9a-f]{4,8}\s+){1,4})", line)
        if not match:
            continue
        base = int(match.group(1), 16)
        chunk = [match.group(2)[i : i + 8] for i in range(0, len(match.group(2)), 9)]
        hexwords = [c.replace(" ", "") for c in chunk if c.strip()]
        if width is None and hexwords:
            width = len(hexwords[0])
        for index, hexword in enumerate(hexwords):
            raw = bytes.fromhex(hexword)
            words[base + index * (width // 2)] = int.from_bytes(raw, "little")
    return words


def diagnose_row(
    parsed,
    starts: set[int],
    join_map: dict[int, int],
    truth: dict[int, dict],
    word_size: int,
    method_name: str,
) -> dict:
    """What the 32-bit copy holds around the declaration's method-name string."""
    from blint.lib.jni import _JAVA_IDENTIFIER_RE, _read_cstring, _valid_method_signature

    findings = {
        "name_string_sites": [],
        "candidate_triples": [],
    }
    occurrences = string_occurrences(parsed, method_name.encode() + b"\x00")
    findings["name_string_sites"] = [
        {"section": name, "address": hex(address)} for name, address in occurrences
    ]
    by_target: dict[int, list[int]] = defaultdict(list)
    for slot, record in truth.items():
        if record["truth"]:
            by_target[record["truth"]].append(slot)
    triple_sections = {".data.rel.ro", ".data"}
    section_ranges = {
        name: (base, base + size) for name, base, size in section_address_ranges(parsed)
    }
    for _, name_addr in occurrences:
        for slot in sorted(by_target.get(name_addr, [])):
            section_name = next(
                (
                    name
                    for name, (lo, hi) in section_ranges.items()
                    if lo <= slot < hi and name in triple_sections
                ),
                None,
            )
            words = []
            for offset, role in ((0, "name"), (word_size, "signature"), (2 * word_size, "fnPtr")):
                address = slot + offset
                record = truth.get(address)
                join_value = join_map.get(address)
                entry = {
                    "role": role,
                    "slot": hex(address),
                    "section": section_name,
                    "reloc": (
                        {
                            "type": record["type"],
                            "lief_addend": record["lief_addend"],
                            "is_rela": record["is_rela"],
                            "stored_word": (
                                hex(record["stored_word"]) if record["stored_word"] is not None else None
                            ),
                            "symbol_value": (
                                hex(record["symbol_value"])
                                if record["symbol_value"] is not None
                                else None
                            ),
                            "symbol_name": record["symbol_name"],
                            "truth": (
                                hex(record["truth"]) if record["truth"] is not None else None
                            ),
                        }
                        if record
                        else None
                    ),
                    "join_value": hex(join_value) if join_value is not None else None,
                }
                if role in ("name", "signature") and record and record["truth"]:
                    text = _read_cstring(parsed, record["truth"])
                    entry["string"] = text
                    if role == "name":
                        entry["valid"] = bool(text and _JAVA_IDENTIFIER_RE.match(text))
                    else:
                        entry["valid"] = bool(text and _valid_method_signature(text))
                if role == "fnPtr" and record and record["truth"]:
                    target = record["truth"] & ~1
                    entry["truth_cleared_thumb"] = hex(target)
                    entry["is_function_start"] = target in starts
                words.append(entry)
            findings["candidate_triples"].append({"name_slot": hex(slot), "words": words})
    return findings


def classify(findings: dict) -> str:
    """One cause name per gap row, from the triple diagnosis."""
    triples = findings["candidate_triples"]
    if not triples:
        return "no_relocated_word_points_at_the_name_string"
    for triple in triples:
        words = {word["role"]: word for word in triple["words"]}
        if any(word.get("reloc") is None for word in words.values()):
            continue  # a triple with an unrelocated word is not this row's table
        join_missing = [
            role
            for role, word in words.items()
            if word["reloc"] and word["join_value"] is None
        ]
        join_wrong = []
        for role, word in words.items():
            truth = word["reloc"]["truth"]
            if (
                word["reloc"]
                and word["join_value"] is not None
                and truth is not None
                and int(word["join_value"], 16) != int(truth, 16)
            ):
                join_wrong.append(role)
        truth_validates = (
            words["name"].get("valid")
            and words["signature"].get("valid")
            and words["fnPtr"].get("is_function_start")
        )
        if truth_validates:
            if join_wrong:
                return "join_value_off_by_the_rel_addend"
            if join_missing:
                return "join_map_missing_a_word"
            return "join_map_agrees_row_unbound_for_another_reason"
        if words["fnPtr"].get("reloc") and not words["fnPtr"].get("is_function_start"):
            return "truth_fnptr_not_a_function_start"
        if words["signature"].get("reloc") and not words["signature"].get("valid"):
            return "signature_invalid_under_truth"
        if words["name"].get("reloc") and not words["name"].get("valid"):
            return "name_invalid_under_truth"
    return "no_valid_triple_shape"


def run_join(apk: Path) -> dict:
    """The join with the FindClass confirmer, listing cap lifted so every
    row is enumerable (production caps only the lists, never the counts)."""
    import blint.lib.jni as jni_module
    from blint.lib.android_native import scan_android_native

    native = scan_android_native(str(apk))
    original_cap = jni_module.JOIN_LISTING_CAP
    jni_module.JOIN_LISTING_CAP = 10**6
    try:
        join = jni_module.build_jni_join_summary(str(apk), native, confirm_findclass=True)
    finally:
        jni_module.JOIN_LISTING_CAP = original_cap
    return {"native": native, "join": join}


def row_status(join: dict) -> dict[str, dict[tuple[str, str, str], dict]]:
    """Per ABI: (class, name, descriptor) -> the row's status and library."""
    per_abi: dict[str, dict[tuple[str, str, str], dict]] = {}
    for abi, abi_join in (join.get("per_abi") or {}).items():
        status: dict[tuple[str, str, str], dict] = {}
        for entry in abi_join.get("bound") or []:
            key = (entry["class"], entry["name"], entry["descriptor"])
            status[key] = {"status": "bound", "library": entry.get("library")}
        for entry in abi_join.get("bound_dynamic") or []:
            key = (entry["class"], entry["name"], entry["descriptor"])
            status[key] = {
                "status": "bound_dynamic",
                "library": entry.get("library"),
                "confirmed_by": entry.get("confirmed_by"),
            }
        for entry in abi_join.get("ambiguous_dynamic") or []:
            key = (entry["class"], entry["name"], entry["descriptor"])
            status[key] = {
                "status": "ambiguous_dynamic",
                "table_candidates": entry.get("table_candidates"),
            }
        for entry in abi_join.get("unbound_dex_natives") or []:
            key = (entry["class"], entry["name"], entry["descriptor"])
            status.setdefault(key, {"status": "unbound"})
        per_abi[abi] = status
    return per_abi


def measure_apk(apk: Path) -> dict:
    print(f"== {apk.name}")
    native_join = run_join(apk)
    join = native_join["join"]
    if join is None:
        print("  join absent")
        return {"join_absent": True}
    per_abi = row_status(join)
    counts = {abi: abi_join["counts"] for abi, abi_join in sorted((join["per_abi"]).items())}
    print(f"  counts: {json.dumps(counts)}")

    # (library, abi) -> parsed copy + context, read once.
    copies: dict[tuple[str, str], dict] = {}
    with zipfile.ZipFile(str(apk)) as zf:
        member_by_key: dict[tuple[str, str], str] = {}
        for info in zf.infolist():
            parts = info.filename.split("/")
            if len(parts) != 3 or parts[0] != "lib" or not info.filename.endswith(".so"):
                continue
            member_by_key.setdefault((parts[2], parts[1]), info.filename)
        baseline = per_abi.get(BASELINE_ABI, {})
        gaps: dict[str, list] = {}
        for abi in GAP_ABIS:
            if abi not in per_abi:
                continue
            rows = []
            status32 = per_abi[abi]
            for key, base_row in baseline.items():
                if base_row["status"] not in ("bound", "bound_dynamic"):
                    continue
                row32 = status32.get(key)
                if row32 and row32["status"] == "unbound":
                    rows.append(
                        {
                            "class": key[0],
                            "name": key[1],
                            "descriptor": key[2],
                            "library": base_row["library"],
                            "baseline": base_row["status"],
                        }
                    )
            gaps[abi] = rows
        for abi, rows in gaps.items():
            print(f"  {abi}: {len(rows)} rows unbound here but bound on {BASELINE_ABI}")
            libraries = sorted({row["library"] for row in rows if row["library"]})
            for library in libraries:
                member = member_by_key.get((library, abi))
                if not member or (library, abi) in copies:
                    continue
                data = zf.read(member)
                parsed = lief.ELF.parse(data)
                if parsed is None or isinstance(parsed, lief.lief_errors):
                    continue
                starts, _ = fn_starts_and_names(parsed)
                # the readelf oracle needs the copy on disk
                with tempfile.NamedTemporaryFile(
                    suffix=f"-{library}-{abi}.so", delete=False
                ) as handle:
                    handle.write(data)
                    extracted = Path(handle.name)
                copies[(library, abi)] = {
                    "parsed": parsed,
                    "starts": starts,
                    "join_map": join_relocation_maps(parsed),
                    "truth": ground_truth_targets(parsed),
                    "word_size": word_size_of(parsed),
                    "path": extracted,
                    "member": member,
                }
            for row in rows:
                library = row["library"]
                copy = copies.get((library, abi))
                if not copy:
                    row["cause"] = "library_copy_not_readable"
                    continue
                findings = diagnose_row(
                    copy["parsed"],
                    copy["starts"],
                    copy["join_map"],
                    copy["truth"],
                    copy["word_size"],
                    row["name"],
                )
                row["findings"] = findings
                row["cause"] = classify(findings)

        # (c) readelf cross-check over every diagnosed (library, abi) copy
        cross_check = {}
        for (library, abi), copy in copies.items():
            readelf_types = readelf_relocations(copy["path"])
            mismatches = []
            checked = 0
            for row in gaps.get(abi, []):
                if row.get("library") != library or "findings" not in row:
                    continue
                for triple in row["findings"]["candidate_triples"]:
                    for word in triple["words"]:
                        slot = int(word["slot"], 16)
                        record = word.get("reloc")
                        if not record:
                            continue
                        checked += 1
                        expected = _normalize_type(record["type"])
                        got = readelf_types.get(slot)
                        if got and _normalize_type(got) != expected:
                            mismatches.append(
                                f"{word['slot']}: lief={expected} readelf={got}"
                            )
                        stored = readelf_section_words(copy["path"], word.get("section") or "")
                        if stored:
                            readelf_word = stored.get(slot)
                            if readelf_word is not None and record["stored_word"] is not None:
                                if f"{readelf_word:#x}" != record["stored_word"]:
                                    mismatches.append(
                                        f"{word['slot']}: lief word={record['stored_word']}"
                                        f" readelf word={readelf_word:#x}"
                                    )
            cross_check[f"{library}@{abi}"] = {
                "member": copy["member"],
                "relocations_readelf": len(readelf_types),
                "words_checked": checked,
                "mismatches": mismatches[:10],
            }
            copy["path"].unlink(missing_ok=True)

        causes: dict[str, Counter] = {}
        for abi, rows in gaps.items():
            counter = Counter(row.get("cause", "?") for row in rows)
            per_library = Counter(
                f"{row.get('cause', '?')}@{row.get('library')}" for row in rows
            )
            causes[abi] = {"by_cause": dict(counter), "by_cause_library": dict(per_library)}
            print(f"  {abi} causes: {json.dumps(dict(counter))}")
        return {
            "counts": counts,
            "gap_rows": gaps,
            "causes": causes,
            "readelf_cross_check": cross_check,
        }


def absint_inventory() -> dict:
    """(e) which models exist and which the confirmer can step."""
    import inspect

    from blint.lib import absint as absint_module

    arch_models = [
        name
        for name, obj in inspect.getmembers(absint_module, inspect.isclass)
        if issubclass(obj, absint_module.ArchModel) and obj is not absint_module.ArchModel
    ]
    model_instances = [
        name for name in dir(absint_module) if name.endswith("_MODEL") and name.isupper()
    ]
    return {
        "arch_model_subclasses": arch_models,
        "model_instances": model_instances,
        "model_for_target": inspect.getsource(absint_module.model_for_target),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--json", type=Path, default=None)
    args = parser.parse_args(argv)

    report: dict = {"readelf": READELF, "apks": {}}
    for name, tier in APKS.items():
        apk = args.corpus / tier / name
        report["apks"][name] = measure_apk(apk)
    report["absint_inventory"] = absint_inventory()
    print("absint models: " + json.dumps(report["absint_inventory"], default=str))

    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=1, default=str))
        print(f"wrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
