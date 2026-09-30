#!/usr/bin/env python3
"""A9 P0 — the measurement that decides P1-P3's scope. Measure only; no
production code changes ride along.

(a) The first-location effect: per APK and ABI, how many ``bound_dynamic``
    (and static ``bound``) rows carry an ``fn_addr`` that is not a function
    start in that ABI's own copy of the library - the join on ``main``
    parses each library's first location and applies its tables to every
    ABI (ground rule 36).
(b) The join's wall time per APK on main, with and without the FindClass
    confirmer (``--disassemble``).
(c) RnHello's nine unbound singles (everything that is not a soloader
    ``lib<name>_so`` accessor): which library/ABI/section holds the name
    string, which relocated words reference it, and whether a
    JNINativeMethod triple sits around any of those words.
(d) The ambiguous residue's fbjni shape: whether the callee's
    ``(methods, count)`` are readable at its RegisterNatives vtable call
    when the caller's argument registers are carried across the direct
    call - answered from the absint model's state, not by assumption.

Usage:
  PATH="/opt/homebrew/opt/llvm@18/bin:$PATH" NYXSTONE_LLVM_PREFIX=/opt/homebrew/opt/llvm@18 \
  poetry run python tests/scripts/android/a9_p0_measure.py \
      --corpus ~/sandbox/android-corpus [--json PATH] [--quick]
"""

from __future__ import annotations

import argparse
import contextlib
import json
import sys
import time
import zipfile
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import lief

WORD = 8

# The R2 spot-check APKs (A8's review set), plus RnHello always.
R2_APKS = {
    "com.blint.rnhello_1.apk": "tier3-frameworks",
    "org.mozilla.fennec_fdroid_1560020.apk": "tier2-fdroid",
    "org.videolan.vlc_13070108.apk": "tier2-fdroid",
    "im.vector.app_40106624.apk": "tier2-fdroid",
}


def fn_starts_and_names(parsed) -> tuple[set[int], dict[int, str]]:
    """F1's own function-start set for one parsed library."""
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


def relocation_maps(parsed) -> dict[int, int]:
    """The join's own combined relocation map (relative + defined-symbol)."""
    from blint.lib.jni import defined_symbol_relocation_map, relative_relocation_map

    values, _ = relative_relocation_map(parsed)
    for slot, target in defined_symbol_relocation_map(parsed).items():
        values.setdefault(slot, target)
    return values


# ------------------------------------------------ (a)+(b) per-ABI join state


def measure_first_location(apk: Path, confirm: bool) -> dict:
    """Run the join as main does; then re-parse every (library, abi) copy
    and check each bound row's fn_addr against that ABI's own starts."""
    from blint.lib.android_native import scan_android_native
    from blint.lib.jni import build_jni_join_summary

    native = scan_android_native(str(apk))
    t0 = time.monotonic()
    join = build_jni_join_summary(str(apk), native, confirm_findclass=confirm)
    wall = time.monotonic() - t0
    if join is None:
        return {"wall_s": round(wall, 2), "absent": True}

    # function starts of every (library, abi)'s own copy
    starts_by_key: dict[tuple[str, str], set[int]] = {}
    with contextlib.suppress(Exception):
        from blint.lib.android_native import LibraryReader

        with LibraryReader(str(apk)) as reader:
            for lib in native.get("libraries") or []:
                name = lib.get("name") or ""
                for loc in lib.get("locations") or []:
                    abi = loc.get("abi")
                    if not abi or (name, abi) in starts_by_key:
                        continue
                    data = None
                    with contextlib.suppress(Exception):
                        data = reader.read(loc)
                    if not data:
                        continue
                    parsed = lief.ELF.parse(data)
                    if parsed is None or isinstance(parsed, lief.lief_errors):
                        continue
                    with contextlib.suppress(Exception):
                        starts_by_key[(name, abi)], _ = fn_starts_and_names(parsed)

    per_abi: dict[str, dict] = {}
    for abi, abi_join in sorted((join.get("per_abi") or {}).items()):
        bad_dynamic = bad_static = total_dynamic = total_static = 0
        examples: list[str] = []
        for entry in abi_join.get("bound_dynamic") or []:
            if entry.get("library") is None:
                continue
            total_dynamic += 1
            with contextlib.suppress(TypeError, ValueError):
                # a v7a Thumb export carries bit 0; the starts clear it
                address = int(entry.get("fn_addr") or "0", 16) & ~1
            own = starts_by_key.get((entry["library"], abi))
            if own is not None and address not in own:
                bad_dynamic += 1
                if len(examples) < 4:
                    examples.append(f"{entry['class']}.{entry['name']}@{entry.get('fn_addr')}")
        for entry in abi_join.get("bound") or []:
            if entry.get("library") is None:
                continue
            total_static += 1
            with contextlib.suppress(TypeError, ValueError):
                address = int(entry.get("fn_addr") or "0", 16) & ~1
            own = starts_by_key.get((entry["library"], abi))
            if own is not None and address not in own:
                bad_static += 1
        per_abi[abi] = {
            **{k: v for k, v in abi_join["counts"].items()},
            "bound_dynamic_checked": total_dynamic,
            "bound_dynamic_fn_addr_not_own_start": bad_dynamic,
            "bound_checked": total_static,
            "bound_fn_addr_not_own_start": bad_static,
            "examples": examples,
        }
    return {
        "wall_s": round(wall, 2),
        "confirm_findclass": confirm,
        "per_abi": per_abi,
    }


# ------------------------------------------------------- (c) the nine singles


def measure_singles(apk: Path) -> dict:
    """For every non-soloader unbound declaration on arm64: where the name
    string lives in each ABI copy, which relocated words point at it, and
    whether a JNINativeMethod-shaped triple surrounds such a word."""
    from blint.lib.android_native import scan_android_native
    from blint.lib.jni import build_jni_join_summary

    native = scan_android_native(str(apk))
    join = build_jni_join_summary(str(apk), native)
    unbound = []
    for abi_join in (join.get("per_abi") or {}).values():
        unbound = abi_join.get("unbound_dex_natives") or []
        break
    singles = [
        e for e in unbound if not (e["name"].startswith("lib") and e["name"].endswith("_so"))
    ]
    wanted = {e["name"] for e in singles}

    findings: dict[str, dict] = {}
    with zipfile.ZipFile(str(apk)) as zf:
        for info in zf.infolist():
            parts = info.filename.split("/")
            if len(parts) != 3 or parts[0] != "lib" or not info.filename.endswith(".so"):
                continue
            abi, libname = parts[1], parts[2]
            data = zf.read(info)
            parsed = lief.ELF.parse(data)
            if parsed is None:
                continue
            # raw string occurrences
            occurrences: dict[str, list[int]] = defaultdict(list)
            for section in parsed.sections:
                try:
                    name = section.name or ""
                    if not name.startswith((".rodata", ".data", ".dynstr")):
                        continue
                    blob = bytes(
                        parsed.get_content_from_virtual_address(
                            int(section.virtual_address), int(section.size)
                        )
                    )
                except Exception:
                    continue
                base = int(section.virtual_address)
                for word in wanted:
                    needle = word.encode() + b"\x00"
                    start = 0
                    while True:
                        at = blob.find(needle, start)
                        if at < 0:
                            break
                        occurrences[word].append(base + at)
                        start = at + 1
            if not occurrences:
                continue
            reloc = relocation_maps(parsed)
            # inverted: target address -> slots pointing at it
            target_slots: dict[int, list[int]] = defaultdict(list)
            for slot, target in reloc.items():
                target_slots[target].append(slot)
            starts, _ = fn_starts_and_names(parsed)
            for word, addrs in occurrences.items():
                rec = findings.setdefault(word, {"locations": [], "references": []})
                for address in addrs:
                    rec["locations"].append(
                        {"library": libname, "abi": abi, "address": hex(address)}
                    )
                for address in addrs:
                    for slot in target_slots.get(address, []):
                        # what sits around the referencing word?
                        pair_word = slot + WORD
                        fn_word = slot + 2 * WORD
                        pair_target = reloc.get(pair_word)
                        fn_target = reloc.get(fn_word)
                        sig = None
                        with contextlib.suppress(Exception):
                            blob = bytes(parsed.get_content_from_virtual_address(pair_target, 128))
                            end = blob.find(b"\x00")
                            if 0 < end:
                                sig = blob[:end].decode("utf-8", "replace")
                        rec["references"].append(
                            {
                                "library": libname,
                                "abi": abi,
                                "slot": hex(slot),
                                "sig_word_target": (hex(pair_target) if pair_target else None),
                                "signature": sig,
                                "fn_word_target": hex(fn_target) if fn_target else None,
                                "fn_is_start": fn_target in starts if fn_target else False,
                            }
                        )
    return {
        "singles": [
            {"name": e["name"], "class": e["class"], "descriptor": e["descriptor"]}
            for e in singles
        ],
        "findings": findings,
    }


# ------------------------- (d) fbjni callee (methods, count) across the call


def _exec_sections(parsed) -> list[tuple[int, bytes]]:
    out = []
    for section in parsed.sections:
        try:
            if int(section.flags) & 0x4 and section.size:
                base = int(section.virtual_address)
                out.append(
                    (base, bytes(parsed.get_content_from_virtual_address(base, int(section.size))))
                )
        except Exception:
            continue
    return out


def measure_argument_propagation(apk: Path) -> dict:
    """For each ambiguous pair's holding library: walk the registrar chain
    the confirmer walks, but seed each callee's first FrameState with the
    caller's argument registers at the direct call. Report, per
    RegisterNatives vtable call in a callee, what the model holds in the
    (methods, count) registers."""
    from nyxstone import Nyxstone

    from blint.lib.absint import ARM64_MODEL, FrameState
    from blint.lib.android_native import scan_android_native
    from blint.lib.disassembler import (
        _default_disassembly_features,
        _merge_features,
        _to_nyxstone_triple,
    )
    from blint.lib.jni import build_jni_join_summary, recover_register_natives_tables
    from blint.lib.jni_findclass import (
        _ADR_TEXT_RE,
        _REGISTER_NATIVES_TOKENS,
        _disassemble,
        _function_starts,
        _naive_materializations,
        _nearest_start,
        _plt_targets,
    )

    native = scan_android_native(str(apk))
    join = build_jni_join_summary(str(apk), native)
    # the ambiguous pairs (name, descriptor) with their candidate tables
    pairs: dict[tuple[str, str], int] = {}
    for abi_join in (join.get("per_abi") or {}).values():
        for entry in abi_join.get("ambiguous_dynamic") or []:
            pairs[(entry["name"], entry["descriptor"])] = entry.get("table_candidates") or 0
        break

    # which library holds the tables for those pairs, and the tables' extents
    holder: dict[str, list[tuple[int, int]]] = defaultdict(list)
    with zipfile.ZipFile(str(apk)) as zf:
        for info in zf.infolist():
            parts = info.filename.split("/")
            if len(parts) != 3 or parts[0] != "lib" or parts[1] != "arm64-v8a":
                continue
            data = zf.read(info)
            parsed = lief.ELF.parse(data)
            if parsed is None:
                continue
            starts, names = fn_starts_and_names(parsed)
            tables = recover_register_natives_tables(parsed, starts, names)
            for table in (tables or {}).get("tables") or []:
                if any(
                    (entry.get("name"), entry.get("signature")) in pairs
                    for entry in table.get("entries") or []
                ):
                    address = int(table["address"], 16)
                    holder[parts[2]].append((address, address + len(table["entries"]) * 24))

    results: dict[str, list] = {}
    with zipfile.ZipFile(str(apk)) as zf:
        for libname, extents in holder.items():
            data = zf.read(f"lib/arm64-v8a/{libname}")
            parsed = lief.ELF.parse(data)
            if parsed is None:
                continue
            nyxstone = Nyxstone(
                target_triple=_to_nyxstone_triple("aarch64"),
                features=_merge_features(_default_disassembly_features("aarch64"), ""),
                immediate_style=0,
            )
            model = ARM64_MODEL
            sections = _exec_sections(parsed)
            starts = _function_starts(parsed)
            sorted_starts = sorted(starts)
            plt_stubs = _plt_targets(parsed)

            def walk(
                start: int,
                incoming: dict | None,
                *,
                _nyxstone=nyxstone,
                _model=model,
                _sections=sections,
                _sorted_starts=sorted_starts,
                _plt_stubs=plt_stubs,
                _parsed=parsed,
                _extents=extents,
            ):
                """Decode one function; step the model. ``incoming`` seeds
                the first state (the caller's argument registers at its
                ``bl``). Returns (events, calls) where calls carry the
                argument registers at each direct call."""
                from bisect import bisect_left

                index = bisect_left(_sorted_starts, start)
                end = (
                    _sorted_starts[index + 1]
                    if index + 1 < len(_sorted_starts)
                    else start + 0x2000
                )
                instructions = _disassemble(_nyxstone, _sections, start, min(end - start, 0x2000))
                if not instructions:
                    return [], []
                state = FrameState(_model)
                for family, value in (incoming or {}).items():
                    state.registers[family] = value
                events: list[dict] = []
                calls: list[dict] = []
                pending_vtable = None
                last_class = None
                adr_values: dict[str, int] = {}
                for instruction in instructions:
                    text = instruction.assembly.strip()
                    compact = text.replace(" ", "")
                    mnemonic = text.split(None, 1)[0].lower() if text else ""
                    if mnemonic == "ldr" and any(
                        token in compact for token in _REGISTER_NATIVES_TOKENS
                    ):
                        pending_vtable = instruction.address
                    if mnemonic == "blr" and pending_vtable is not None:
                        methods = None
                        value = state.get_register("x2")
                        if value is not None:
                            inner = value[0]
                            methods = (
                                inner
                                if isinstance(inner, int)
                                else inner[1]
                                if isinstance(inner, tuple) and inner and inner[0] == "ptr"
                                else adr_values.get("x2")
                            )
                        count = None
                        value = state.get_register("w3")
                        if value is not None and isinstance(value[0], int):
                            count = value[0]
                        events.append(
                            {
                                "at": hex(instruction.address),
                                "methods": hex(methods) if isinstance(methods, int) else None,
                                "count": count,
                                "class": last_class,
                                "in_table": any(
                                    lo <= methods < hi
                                    for lo, hi in _extents
                                    if isinstance(methods, int)
                                ),
                            }
                        )
                        last_class = None
                        pending_vtable = None
                    if mnemonic == "bl":
                        # argument registers at the direct call, to carry in
                        args = {}
                        for reg in ("x0", "x1", "x2", "x3"):
                            value = state.get_register(reg)
                            if value is not None:
                                args[reg] = value[0]
                        target = None
                        with contextlib.suppress(ValueError):
                            token = text.split(None, 1)[1].strip().lstrip("#")
                            target = instruction.address + int(token, 0)
                        if target is not None:
                            calls.append(
                                {
                                    "at": hex(instruction.address),
                                    "target": hex(_plt_stubs.get(target, target)),
                                    "args": {
                                        k: (
                                            hex(v)
                                            if isinstance(v, int)
                                            else f"{v[0]}:{hex(v[1])}"
                                            if isinstance(v, tuple) and isinstance(v[1], int)
                                            else str(v)
                                        )
                                        for k, v in args.items()
                                    },
                                }
                            )
                    span = (instruction.address, instruction.address + len(instruction.bytes))
                    before = dict(state.registers)
                    with contextlib.suppress(Exception):
                        _model.step(state, text, leaves_function=True, address_span=span)
                    match = _ADR_TEXT_RE.match(text)
                    materialized: set[int] = set()
                    if match:
                        with contextlib.suppress(ValueError):
                            target = instruction.address + int(match.group("delta").lstrip("#"), 0)
                            materialized.add(target)
                            adr_values[match.group("reg")] = target
                    for register, value in state.registers.items():
                        if (
                            before.get(register) != value
                            and isinstance(value, tuple)
                            and value
                            and value[0] == "ptr"
                            and isinstance(value[1], int)
                        ):
                            materialized.add(value[1])
                    for value in materialized:
                        name = None
                        with contextlib.suppress(Exception):
                            blob = bytes(_parsed.get_content_from_virtual_address(value, 256))
                            end_at = blob.find(b"\x00")
                            if 0 < end_at:
                                text_at = blob[:end_at].decode("utf-8", "replace")
                                if len(text_at) < 200 and text_at.count("/") >= 1:
                                    name = text_at
                        if name:
                            last_class = name
                return events, calls

            # registrars: the naive-materialization sites that land in extents
            naive = _naive_materializations(sections, "aarch64")
            registrars: dict[int, set[int]] = defaultdict(set)
            for site, proposed in naive:
                for lo, hi in extents:
                    if lo <= proposed < hi:
                        registrars[lo].add(_nearest_start(sorted_starts, site))
                        break
            library_report = []
            for lo, functions in sorted(registrars.items()):
                for fn in sorted(x for x in functions if x is not None):
                    events, calls = walk(fn, None)
                    entry = {
                        "registrar": hex(fn),
                        "same_function_events": [e for e in events if e["methods"] is not None],
                        "direct_calls": calls,
                    }
                    # one hop with the caller's argument registers carried in
                    carried: list[dict] = []
                    for call in calls:
                        target = int(call["target"], 16)
                        if target in starts:
                            raw_args = {
                                reg: (
                                    int(v.split(":")[1], 16)
                                    if isinstance(v, str) and v.startswith("ptr:")
                                    else int(v, 16)
                                    if isinstance(v, str) and v.startswith("0x")
                                    else None
                                )
                                for reg, v in call["args"].items()
                            }
                            raw_args = {k: v for k, v in raw_args.items() if v is not None}
                            callee_events, _ = walk(target, raw_args)
                            carried.append(
                                {
                                    "callee": call["target"],
                                    "seeded": {k: hex(v) for k, v in raw_args.items()},
                                    "register_events": [
                                        e for e in callee_events if e["methods"] is not None
                                    ],
                                    "all_vtable_events": callee_events,
                                }
                            )
                    entry["carried"] = carried
                    library_report.append(entry)
            results[libname] = library_report
    return {"pairs": {f"{n} {d}": c for (n, d), c in pairs.items()}, "chains": results}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--json", type=Path, default=None)
    parser.add_argument("--quick", action="store_true", help="R2 spot-check APKs only")
    args = parser.parse_args(argv)

    corpus = args.corpus
    apks = sorted((corpus / "tier2-fdroid").glob("*.apk")) + [
        corpus / "tier3-frameworks" / "com.blint.rnhello_1.apk"
    ]
    if args.quick:
        apks = [corpus / d / n for n, d in R2_APKS.items()]

    report: dict = {"apk_count": len(apks)}

    print("(a)+(b) first-location effect and wall time")
    per_apk = {}
    for apk in apks:
        plain = measure_first_location(apk, confirm=False)
        row = {"plain": plain}
        if apk.name in R2_APKS or apk.name.startswith("com.blint"):
            row["confirm"] = measure_first_location(apk, confirm=True)
        per_apk[apk.name] = row
        interesting = {
            abi: v["bound_dynamic_fn_addr_not_own_start"]
            for abi, v in plain.get("per_abi", {}).items()
            if v.get("bound_dynamic_fn_addr_not_own_start")
        }
        print(
            f"  {apk.name}: wall {plain['wall_s']}s"
            + (f" bad_fn_addr={interesting}" if interesting else "")
        )
    report["join"] = per_apk

    rnhello = corpus / "tier3-frameworks" / "com.blint.rnhello_1.apk"
    print("(c) RnHello's unbound singles")
    singles = measure_singles(rnhello)
    report["singles"] = singles
    for name, rec in singles["findings"].items():
        refs = sum(1 for r in rec["references"])
        print(f"  {name}: {len(rec['locations'])} string sites, {refs} relocated references")

    print("(d) fbjni callee (methods, count) with carried argument registers")
    prop = measure_argument_propagation(rnhello)
    report["argument_propagation"] = prop
    for libname, entries in prop["chains"].items():
        read = sum(
            1
            for e in entries
            for c in e["carried"]
            for ev in c["register_events"]
            if ev["in_table"]
        )
        print(f"  {libname}: {len(entries)} registrars, {read} in-table (methods,count) reads")

    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=1, default=str))
        print(f"wrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
