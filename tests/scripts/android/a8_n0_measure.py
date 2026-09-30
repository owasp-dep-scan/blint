#!/usr/bin/env python3
"""A8 N0 — the measurement that decides N1-N3's scope. Measure only; no
production code changes ride along.

(a) For each J3 recall-gap host (libgkcodecs' opus/libvorbis/libvpx, saber's
    pdfium, vlc's GnuTLS, osmand's GDAL), the target library's exported API
    count per ABI from ``llvm-nm -D --defined-only`` run in the same
    invocation. Only hosts at or above the 30-name gate (and with a vcpkg
    port at the pinned revision) go to N1.
(b) Where RnHello's unbound native declarations live: for every unbound
    name, the library and section that holds the string, the relocation
    type of each word that references it, the stride of the surrounding
    structure, and whether a function pointer sits at a fixed offset. The
    coverage question: how many of the 221 would bind if the F1 relocation
    walk also read absolute relocations against locally-defined symbols
    (fbjni's ``kDescriptor`` / ``MethodWrapper::call``), per ABI, with the
    join's own uniqueness rule.
(c) ``ambiguous_dynamic`` over the 27 corpus APKs (tier2-fdroid + RnHello),
    and for each carrier whether the function that calls RegisterNatives
    also loads a constant class-name string: an arm64 adrp+add scan with
    PLT-resolved direct-call edges (<= 2 hops) to the RegisterNatives
    vtable call. RnHello is also measured in the post-N2 shape (extended
    relocation map).

Usage:
  poetry run python tests/scripts/android/a8_n0_measure.py \
      --corpus ~/sandbox/android-corpus [--llvm-bin DIR] [--json PATH]
"""

from __future__ import annotations

import argparse
import contextlib
import json
import re
import shutil
import struct
import subprocess
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import lief

WORD64 = 8
WORD32 = 4

# --------------------------------------------------------------- tools


def resolve_llvm_nm(explicit: str | None) -> Path:
    if explicit:
        path = Path(explicit) / "llvm-nm"
        if path.exists():
            return path
        raise SystemExit(f"llvm-nm not found under {explicit}")
    found = shutil.which("llvm-nm")
    if found:
        return Path(found)
    for root in (Path.home() / "Android" / "sdk",):
        ndk_root = root / "ndk"
        if ndk_root.is_dir():
            for ndk in sorted(ndk_root.iterdir(), reverse=True):
                for prebuilt in (ndk / "toolchains" / "llvm" / "prebuilt").glob("*"):
                    candidate = prebuilt / "bin" / "llvm-nm"
                    if candidate.exists():
                        return candidate
    raise SystemExit("llvm-nm not found; pass --llvm-bin or install it on PATH")


def nm_defined_names(nm: Path, so_path: Path) -> list[str]:
    proc = subprocess.run(
        [str(nm), "-D", "--defined-only", str(so_path)],
        capture_output=True,
        text=True,
        errors="replace",
        check=False,
    )
    names = []
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            names.append(parts[-1].split("@")[0])
    return names


# --------------------------------------------------------- (a) API counts

# The reviewer's families (A8 prompt table): gnutls_ counted as
# contains-the-token; nettle_ as contains minus the gnutls overlaps.
GAP_HOSTS = [
    # (app apk basename, library member, families: label -> predicate)
    (
        "org.mozilla.fennec_fdroid_1560000.apk",
        "libgkcodecs.so",
        {
            "opus_": lambda n: n.startswith("opus_"),
            "vorbis_": lambda n: n.startswith("vorbis_"),
            "vpx_": lambda n: n.startswith("vpx_"),
        },
    ),
    ("org.mozilla.fennec_fdroid_1560010.apk", "libgkcodecs.so", None),
    ("org.mozilla.fennec_fdroid_1560020.apk", "libgkcodecs.so", None),
    (
        "com.adilhanney.saber_1360101.apk",
        "libpdfium.so",
        {
            "FPDF/PDFium": lambda n: n.startswith(("FPDF", "PDFium")),
        },
    ),
    ("com.adilhanney.saber_1360102.apk", "libpdfium.so", None),
    ("com.adilhanney.saber_1360103.apk", "libpdfium.so", None),
    (
        "org.videolan.vlc_13070105.apk",
        "libvlc.so",
        {
            "gnutls_": lambda n: "gnutls_" in n,
            "nettle_": None,  # filled in: contains minus gnutls overlaps
        },
    ),
    ("org.videolan.vlc_13070106.apk", "libvlc.so", None),
    ("org.videolan.vlc_13070107.apk", "libvlc.so", None),
    ("org.videolan.vlc_13070108.apk", "libvlc.so", None),
    (
        "net.osmand.plus_540401.apk",
        "libOsmAndCoreWithJNI.so",
        {
            "GDAL/OGR/CPL/OSR": lambda n: n.startswith(("GDAL", "OGR", "CPL", "OSR")),
        },
    ),
    ("net.osmand.plus_540402.apk", "libOsmAndCoreWithJNI.so", None),
    ("net.osmand.plus_540403.apk", "libOsmAndCoreWithJNI.so", None),
]


def measure_api_counts(corpus: Path, nm: Path) -> list[dict]:
    rows = []
    active: dict | None = None
    for apk_name, member, families in GAP_HOSTS:
        if families is not None:
            active = families
        apk = corpus / "tier2-fdroid" / apk_name
        with zipfile.ZipFile(apk) as zf:
            abi = next(
                info.filename.split("/")[1]
                for info in zf.infolist()
                if info.filename.startswith("lib/") and info.filename.endswith(".so")
            )
            data = zf.read(f"lib/{abi}/{member}")
        tmp = Path("/tmp") / f"a8n0_{member}"
        tmp.write_bytes(data)
        names = nm_defined_names(nm, tmp)
        row = {"apk": apk_name, "abi": abi, "library": member, "defined_total": len(names)}
        for label, pred in (active or {}).items():
            if label == "nettle_":
                # contains the token minus the gnutls-family overlaps
                row[label] = sum(1 for n in names if "nettle_" in n and "gnutls" not in n)
            else:
                row[label] = sum(1 for n in names if pred(n))
        rows.append(row)
        print(
            f"  {apk_name} {abi} {member}: defined={row['defined_total']} "
            + " ".join(
                f"{k}={v}"
                for k, v in row.items()
                if k not in ("apk", "abi", "library", "defined_total")
            )
        )
    return rows


# ------------------------------------------------- (b) RnHello's unbound


def extended_reloc_map(parsed) -> dict[int, int]:
    """R_*_RELATIVE (addend, or the stored word on REL) plus absolute
    relocations whose symbol is defined in this object (the N2 candidate:
    fbjni's kDescriptor / MethodWrapper::call words)."""
    word = WORD64 if int(parsed.header.identity[4]) == 2 else WORD32
    out: dict[int, int] = {}
    for relocation in parsed.relocations:
        addr = int(relocation.address)
        tname = str(getattr(relocation, "type", ""))
        if "RELATIVE" in tname:
            target = int(getattr(relocation, "addend", 0) or 0)
            if not target:
                with contextlib.suppress(Exception):
                    target = int.from_bytes(
                        bytes(parsed.get_content_from_virtual_address(addr, word)), "little"
                    )
            if target:
                out[addr] = target
            continue
        sym = None
        with contextlib.suppress(Exception):
            sym = relocation.symbol
        if sym is None:
            continue
        try:
            value, shndx = int(sym.value or 0), int(sym.shndx or 0)
        except Exception:
            continue
        if value and shndx:
            out[addr] = value
    return out


def fn_starts(parsed) -> dict[int, str]:
    """defined dynamic FUNCs plus the unwind-table discoveries (F1's set)."""
    from blint.lib.funcdisc.unwind import discover_functions

    starts: dict[int, str] = {}
    for sym in parsed.dynamic_symbols:
        try:
            if sym.value and "FUNC" in str(sym.type) and int(sym.shndx or 0):
                starts.setdefault(int(sym.value) & ~1, sym.name)
        except Exception:
            continue
    for discovered in discover_functions(parsed) or []:
        address = discovered.get("address")
        try:
            starts.setdefault((address if isinstance(address, int) else int(address, 16)) & ~1, "")
        except (TypeError, ValueError):
            continue
    return starts


def walk_tables(parsed, slotmap: dict[int, int], starts: dict[int, str]):
    """F1's triple walk over an arbitrary slot->target map: the same
    validation blint's recover_register_natives_tables applies."""
    from blint.lib.jni import _JAVA_IDENTIFIER_RE, _read_cstring, _valid_method_signature

    word = WORD64 if int(parsed.header.identity[4]) == 2 else WORD32
    exec_ranges = []
    for section in parsed.sections:
        try:
            if int(section.flags) & 0x4 and section.size:
                exec_ranges.append(
                    (
                        int(section.virtual_address),
                        int(section.virtual_address) + int(section.size),
                    )
                )
        except Exception:
            continue
    start_set = set(starts)
    tables = []
    for section in parsed.sections:
        name = getattr(section, "name", "") or ""
        if name not in (".data.rel.ro", ".data"):
            continue
        start, size = int(section.virtual_address), int(section.size)
        stride = 3 * word
        slot = start
        run: list[dict] = []
        run_address: int | None = None
        while slot + stride <= start + size:
            name_ptr = slotmap.get(slot)
            sig_ptr = slotmap.get(slot + word)
            fn_ptr = slotmap.get(slot + 2 * word)
            entry = None
            if name_ptr and sig_ptr and fn_ptr:
                method_name = _read_cstring(parsed, name_ptr)
                signature = _read_cstring(parsed, sig_ptr)
                target = fn_ptr & ~1
                if (
                    method_name
                    and _JAVA_IDENTIFIER_RE.match(method_name)
                    and signature
                    and _valid_method_signature(signature)
                    and target in start_set
                    and any(lo <= target < hi for lo, hi in exec_ranges)
                ):
                    entry = {
                        "name": method_name,
                        "signature": signature,
                        "fn": target,
                        "slot": slot,
                        "fn_name": starts.get(target, ""),
                    }
            if entry is not None:
                if run and slot == run_address + len(run) * stride:
                    run.append(entry)
                else:
                    if run:
                        tables.append({"address": run_address, "entries": run})
                    run = [entry]
                    run_address = slot
                slot += stride
            else:
                if run:
                    tables.append({"address": run_address, "entries": run})
                    run = []
                slot += word
        if run:
            tables.append({"address": run_address, "entries": run})
    return tables


def rel_reloc_map_only(parsed) -> dict[int, int]:
    from blint.lib.jni import relative_relocation_map

    values, _ = relative_relocation_map(parsed)
    return values


def string_locations(parsed, names: set[str]) -> dict[str, list[int]]:
    """Section-tagged addresses of exact NUL-terminated matches."""
    found: dict[str, list[int]] = defaultdict(list)
    for section in parsed.sections:
        try:
            if not section.size or section.type == lief.ELF.Section.TYPE.NOBITS:
                continue
            blob = bytes(
                parsed.get_content_from_virtual_address(section.virtual_address, section.size)
            )
        except Exception:
            continue
        for want in names:
            wa = want.encode() + b"\x00"
            off = blob.find(wa)
            while off >= 0:
                prev = blob[off - 1 : off]
                if not prev or prev == b"\x00":
                    found[want].append(section.virtual_address + off)
                off = blob.find(wa, off + 1)
    return found


def measure_rnhello(corpus: Path) -> dict:
    from blint.lib.android_native import scan_android_native
    from blint.lib.jni import build_jni_join_summary

    apk = str(corpus / "tier3-frameworks" / "com.blint.rnhello_1.apk")
    join = build_jni_join_summary(apk, scan_android_native(apk))
    per_abi = {}
    unbound = None
    for abi, abi_join in (join.get("per_abi") or {}).items():
        per_abi[abi] = dict(abi_join["counts"])
        if abi == "arm64-v8a":
            unbound = list(abi_join["unbound_dex_natives"])
    result = {"join_counts": per_abi, "unbound_arm64": len(unbound)}
    names = {e["name"] for e in unbound}

    string_census: dict[str, dict] = {}
    arm64_tables: dict[str, list] = {}
    coverage: dict[str, dict] = {}
    with zipfile.ZipFile(apk) as zf:
        for abi in sorted(per_abi):
            cov = {"f1_entries": 0, "ext_entries": 0, "reloc_types": Counter()}
            tables_by_pair: dict[tuple[str, str], list[dict]] = defaultdict(list)
            for info in zf.infolist():
                if not info.filename.startswith(f"lib/{abi}/") or not info.filename.endswith(
                    ".so"
                ):
                    continue
                libname = info.filename.rsplit("/", 1)[-1]
                parsed = lief.ELF.parse(zf.read(info))
                if parsed is None:
                    continue
                starts = fn_starts(parsed)
                f1 = walk_tables(parsed, rel_reloc_map_only(parsed), starts)
                ext = walk_tables(parsed, extended_reloc_map(parsed), starts)
                cov["f1_entries"] += sum(len(t["entries"]) for t in f1)
                cov["ext_entries"] += sum(len(t["entries"]) for t in ext)
                for relocation in parsed.relocations:
                    cov["reloc_types"][
                        str(getattr(relocation, "type", "")).replace("TYPE.", "")
                    ] += 1
                if abi == "arm64-v8a":
                    locs = string_locations(parsed, names)
                    for name, addrs in locs.items():
                        string_census.setdefault(name, {"libraries": {}, "referenced_by": 0})
                        string_census[name]["libraries"][libname] = [hex(a) for a in addrs]
                    arm64_tables[libname] = [
                        {"address": hex(t["address"]), "entries": t["entries"]} for t in ext
                    ]
                for table in ext:
                    for entry in table["entries"]:
                        tables_by_pair[(entry["name"], entry["signature"])].append(
                            {**entry, "library": libname}
                        )
            # join-style binding of the unbound declarations against ext tables
            classes_by_pair: dict[tuple[str, str], set[str]] = defaultdict(set)
            for entry in unbound:
                classes_by_pair[(entry["name"], entry["descriptor"])].add(entry["class"])
            bound, ambiguous, unmatched = [], [], []
            for pair, classes in classes_by_pair.items():
                matches = tables_by_pair.get(pair) or []
                if len(matches) == 1 and len(classes) == 1:
                    bound.append(pair)
                elif matches:
                    ambiguous.append(pair)
                else:
                    unmatched.append(pair)
            cov["would_bind"] = sum(len(classes_by_pair[p]) and 1 for p in bound)
            cov["bound_pairs"] = len(bound)
            cov["ambiguous_pairs"] = len(ambiguous)
            cov["unmatched_pairs"] = len(unmatched)
            cov["reloc_types"] = dict(cov["reloc_types"])
            coverage[abi] = cov
    result["string_census_names"] = len(string_census)
    result["coverage"] = coverage
    result["arm64_tables"] = arm64_tables
    result["string_census"] = {name: v for name, v in string_census.items()}
    return result


# ------------------------------------------- (c) ambiguous + FindClass carrier

CLASS_SHAPE_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_$]*(/[a-zA-Z0-9_$]+)+;?$")


def _sections_text(parsed):
    for section in parsed.sections:
        try:
            if int(section.flags) & 0x4 and section.size:
                base = int(section.virtual_address)
                yield base, bytes(parsed.get_content_from_virtual_address(base, int(section.size)))
        except Exception:
            continue


def arm64_adrp_add_pairs(parsed) -> list[tuple[int, int]]:
    """(site, target) for adrp followed by add with the same source reg."""
    pairs = []
    for base, blob in _sections_text(parsed):
        n = len(blob) // 4
        words = struct.unpack_from(f"<{n}I", blob)
        for i in range(n):
            w = words[i]
            if (w & 0x9F000000) != 0x90000000:
                continue
            rd = w & 0x1F
            imm = ((w >> 29) & 3) | (((w >> 5) & 0x7FFFF) << 2)
            if imm & (1 << 20):
                imm -= 1 << 21
            page = (base + i * 4) & ~0xFFF
            for j in range(i + 1, min(i + 9, n)):
                w2 = words[j]
                if (w2 & 0xFF800000) == 0x91000000 and ((w2 >> 5) & 0x1F) == rd:
                    pairs.append((base + i * 4, page + (imm << 12) + ((w2 >> 10) & 0xFFF)))
                    break
    return pairs


def build_plt_map(parsed) -> dict:
    """arm64 PLT stub -> target function start via the stub's GOT slot."""
    stubs = {}
    got_slot_to_target = {}
    for relocation in parsed.relocations:
        if "JUMP_SLOT" not in str(getattr(relocation, "type", "")):
            continue
        with contextlib.suppress(Exception):
            sym = relocation.symbol
            if sym is not None and int(sym.value or 0):
                got_slot_to_target[int(relocation.address)] = int(sym.value)
    for section in parsed.sections:
        if (getattr(section, "name", "") or "") != ".plt":
            continue
        base = int(section.virtual_address)
        try:
            blob = bytes(parsed.get_content_from_virtual_address(base, int(section.size)))
        except Exception:
            continue
        for off in range(0, len(blob) - 16, 16):
            w0, w1 = struct.unpack_from("<2I", blob, off)
            if (w0 & 0x9F000000) != 0x90000000 or (w1 & 0xFFC00000) != 0xF9400000:
                continue
            imm = ((w0 >> 29) & 3) | (((w0 >> 5) & 0x7FFFF) << 2)
            if imm & (1 << 20):
                imm -= 1 << 21
            slot = (base + off) & ~0xFFF
            slot = slot + (imm << 12) + (((w1 >> 10) & 0xFFF) * 8)
            if slot in got_slot_to_target:
                stubs[base + off] = got_slot_to_target[slot]
        return {"stubs": stubs, "range": (base, base + int(section.size))}
    return {"stubs": stubs, "range": (0, 0)}


def arm64_edges_and_regcalls(parsed, plt_map):
    """direct bl edges (PLT resolved) and RegisterNatives vtable-call sites."""
    edges = []
    reg_calls = []
    plt_lo, plt_hi = plt_map["range"]
    for base, blob in _sections_text(parsed):
        n = len(blob) // 4
        words = struct.unpack_from(f"<{n}I", blob)
        for i in range(n):
            w = words[i]
            if (w & 0xFC000000) == 0x94000000:  # bl
                imm = w & 0x3FFFFFF
                if imm & (1 << 25):
                    imm -= 1 << 26
                target = base + i * 4 + imm * 4
                if plt_lo <= target < plt_hi:
                    target = plt_map["stubs"].get(target, target)
                edges.append((base + i * 4, target))
            # ldr xN, [xM, #0x6b8]: JNIEnv RegisterNatives (entry 215)
            if (w & 0xFFC00000) == 0xF9400000 and ((w >> 10) & 0xFFF) == 0xD7:
                reg_calls.append(base + i * 4)
    return edges, reg_calls


def read_cstring(parsed, addr: int, limit: int = 256) -> str | None:
    try:
        blob = bytes(parsed.get_content_from_virtual_address(addr, limit))
    except Exception:
        return None
    end = blob.find(b"\x00")
    if end <= 0:
        return None
    try:
        return blob[:end].decode("utf-8")
    except UnicodeDecodeError:
        return None


def merged_ranges(parsed, starts: dict[int, str]):
    ranges = []
    for sym in parsed.dynamic_symbols:
        try:
            if sym.value and "FUNC" in str(sym.type) and int(sym.shndx or 0) and sym.name:
                ranges.append((int(sym.value) & ~1, int(sym.size or 0), sym.name))
        except Exception:
            continue
    named = {r[0] for r in ranges}
    ranges += [(a, 0, "") for a in sorted(set(starts) - named)]
    ranges.sort()
    return ranges


def nearest_function(ranges, addr):
    lo, hi = 0, len(ranges)
    while lo < hi:
        mid = (lo + hi) // 2
        if ranges[mid][0] <= addr:
            lo = mid + 1
        else:
            hi = mid
    if lo == 0:
        return None
    start, size, name = ranges[lo - 1]
    return (start, name) if (size == 0 or addr < start + size) else None


def carrier_analysis(apk_path: Path, pairs: dict, extended: bool) -> list[dict]:
    """Per candidate table entry: does a constant class-name string sit
    beside the RegisterNatives call that registers this table?"""
    results = []
    with zipfile.ZipFile(apk_path) as zf:
        for info in zf.infolist():
            if not info.filename.startswith("lib/arm64-v8a/") or not info.filename.endswith(".so"):
                continue
            libname = info.filename.rsplit("/", 1)[-1]
            parsed = lief.ELF.parse(zf.read(info))
            if parsed is None:
                continue
            starts = fn_starts(parsed)
            if extended:
                tables = walk_tables(parsed, extended_reloc_map(parsed), starts)
            else:
                from blint.lib.jni import recover_register_natives_tables

                recovered = recover_register_natives_tables(parsed, set(starts), starts)
                tables = []
                for table in (recovered or {}).get("tables") or []:
                    address = int(table["address"], 16)
                    tables.append(
                        {
                            "address": address,
                            "entries": [
                                {"name": e["name"], "signature": e["signature"]}
                                for e in table["entries"]
                            ],
                        }
                    )
            candidates = []
            for table in tables:
                hits = [e for e in table["entries"] if (e["name"], e["signature"]) in pairs]
                if hits:
                    lo = table["address"]
                    candidates.append((lo, lo + len(table["entries"]) * 3 * WORD64, hits))
            # merge touching runs (one entry failing validation splits a table)
            merged = []
            for lo, hi, hits in sorted(candidates):
                if merged and lo <= merged[-1][1]:
                    m = merged[-1]
                    merged[-1] = (m[0], max(m[1], hi), m[2] + hits)
                else:
                    merged.append((lo, hi, list(hits)))
            if not merged:
                continue
            mat = arm64_adrp_add_pairs(parsed)
            cls_targets = {}
            for _, target in mat:
                if target in cls_targets:
                    continue
                text = read_cstring(parsed, target)
                if text and 5 < len(text) < 200 and CLASS_SHAPE_RE.match(text):
                    cls_targets[target] = text.rstrip(";").replace("/", ".")
            ranges = merged_ranges(parsed, starts)
            cls_fns: dict[int, set[str]] = defaultdict(set)
            for site, target in mat:
                cname = cls_targets.get(target)
                if cname:
                    fn = nearest_function(ranges, site)
                    if fn:
                        cls_fns[fn[0]].add(cname)
            table_fns = {}
            for lo, hi, _ in merged:
                fns = set()
                for site, target in mat:
                    if lo <= target < hi:
                        fn = nearest_function(ranges, site)
                        if fn:
                            fns.add(fn)
                table_fns[lo] = fns
            plt_map = build_plt_map(parsed)
            edges, reg_calls = arm64_edges_and_regcalls(parsed, plt_map)
            direct: dict[int, set[int]] = defaultdict(set)
            for src_site, dst in edges:
                fn = nearest_function(ranges, src_site)
                dn = nearest_function(ranges, dst)
                if fn and dn:
                    direct[fn[0]].add(dn[0])
            reg_fns = set()
            for site in reg_calls:
                fn = nearest_function(ranges, site)
                if fn:
                    reg_fns.add(fn[0])
            callers: dict[int, set[int]] = {}
            for f0 in list(direct):
                seen, frontier, hop, hit = {f0}, {f0}, 0, set()
                while hop < 2:
                    hop += 1
                    nxt = set()
                    for f in frontier:
                        nxt |= direct.get(f, set()) - seen
                    frontier = nxt
                    seen |= nxt
                    hit |= frontier & reg_fns
                if hit:
                    callers[f0] = hit
            for lo, hi, hits in merged:
                fns = table_fns[lo]
                beside = set()
                for fn in fns:
                    beside |= cls_fns.get(fn[0], set())
                    for callee in callers.get(fn[0], set()):
                        beside |= cls_fns.get(callee, set())
                for entry in hits:
                    key = (entry["name"], entry["signature"])
                    results.append(
                        {
                            "library": libname,
                            "table": hex(lo),
                            "name": entry["name"],
                            "signature": entry["signature"],
                            "declaring_classes": sorted(pairs[key]),
                            "registering_fns": sorted(n for _, n in fns if n)[:3],
                            "class_names_beside": sorted(beside)[:6],
                            "confirms": sorted(beside & pairs[key]),
                        }
                    )
    return results


def measure_ambiguous(corpus: Path) -> dict:
    from blint.lib.android_native import scan_android_native
    from blint.lib.jni import build_jni_join_summary

    apks = sorted((corpus / "tier2-fdroid").glob("*.apk")) + [
        corpus / "tier3-frameworks" / "com.blint.rnhello_1.apk"
    ]
    census = {}
    for apk in apks:
        join = build_jni_join_summary(str(apk), scan_android_native(str(apk)))
        if join is None:
            census[apk.name] = None
            continue
        per_abi = {}
        for abi, abi_join in (join.get("per_abi") or {}).items():
            entries = [
                {"class": e["class"], "name": e["name"], "descriptor": e["descriptor"]}
                for e in abi_join.get("ambiguous_dynamic") or []
            ]
            if entries:
                per_abi[abi] = entries
        census[apk.name] = per_abi
        total = sum(len(v) for v in per_abi.values())
        if total:
            print(f"  {apk.name}: ambiguous_dynamic={total}")
    # carriers: the apps that carry ambiguity today, plus RnHello post-N2
    carriers = {}
    for apk_name, apk_ambiguities in census.items():
        pairs: dict[tuple[str, str], set[str]] = defaultdict(set)
        for abi_entries in (apk_ambiguities or {}).values():
            for entry in abi_entries:
                pairs[(entry["name"], entry["descriptor"])].add(entry["class"])
        if not pairs:
            continue
        directory = "tier3-frameworks" if apk_name.startswith("com.blint") else "tier2-fdroid"
        res = carrier_analysis(corpus / directory / apk_name, pairs, extended=False)
        carriers[apk_name] = res
        ok = sum(1 for r in res if r["confirms"])
        print(f"  carrier {apk_name}: {len(res)} candidates, {ok} confirmed")
    # RnHello in the post-N2 shape: the pairs the extended relocation map
    # would leave ambiguous (N3's workload), same carrier question.
    apk = corpus / "tier3-frameworks" / "com.blint.rnhello_1.apk"
    from blint.lib.android_native import scan_android_native
    from blint.lib.jni import build_jni_join_summary

    join = build_jni_join_summary(str(apk), scan_android_native(str(apk)))
    unbound = next(iter(join["per_abi"].values()))["unbound_dex_natives"]
    classes_by_pair: dict[tuple[str, str], set[str]] = defaultdict(set)
    for entry in unbound:
        classes_by_pair[(entry["name"], entry["descriptor"])].add(entry["class"])
    matched: dict[tuple[str, str], int] = defaultdict(int)
    with zipfile.ZipFile(apk) as zf:
        for info in zf.infolist():
            if not info.filename.startswith("lib/arm64-v8a/") or not info.filename.endswith(".so"):
                continue
            parsed = lief.ELF.parse(zf.read(info))
            if parsed is None:
                continue
            starts = fn_starts(parsed)
            for table in walk_tables(parsed, extended_reloc_map(parsed), starts):
                for entry in table["entries"]:
                    matched[(entry["name"], entry["signature"])] += 1
    post_n2 = {
        pair: classes
        for pair, classes in classes_by_pair.items()
        if matched.get(pair) and (matched[pair] > 1 or len(classes) > 1)
    }
    res = carrier_analysis(apk, post_n2, extended=True)
    carriers["com.blint.rnhello_1.apk+extended"] = res
    ok = sum(1 for r in res if r["confirms"])
    print(
        f"  carrier RnHello post-N2: {len(post_n2)} pairs, {len(res)} candidates, {ok} confirmed"
    )
    return {"census": census, "carriers": carriers}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--llvm-bin", help="directory with llvm-nm")
    parser.add_argument("--json", type=Path, help="write the full results JSON here")
    args = parser.parse_args(argv)

    nm = resolve_llvm_nm(args.llvm_bin)
    print(f"llvm-nm: {nm}")

    print("(a) exported API counts per recall-gap host")
    api = measure_api_counts(args.corpus, nm)

    print("(b) RnHello's unbound declarations")
    rnhello = measure_rnhello(args.corpus)

    print("(c) ambiguous_dynamic over the 27 APKs + carriers")
    ambiguous = measure_ambiguous(args.corpus)

    report = {"api_counts": api, "rnhello": rnhello, "ambiguous": ambiguous}
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=1, default=str) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
