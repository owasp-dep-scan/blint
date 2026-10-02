#!/usr/bin/env python3
"""A13 U0 - the 32-bit singles and the 64-bit runtime tables, measured.

Measure only; no production change. Three answers:

(a) RnHello's 32-bit residue, classified. The join with the confirmers on
    reproduces the A12 counts; each of v7a's 9 singles and each of x86's 15
    unbound cause-B rows is matched to the registrar the walk names and to
    the store sequence that defeats it (verified against llvm-objdump and,
    for the x86 frame questions, a Unicorn emulation of the registrar).
    The shapes the hand reading found:

    S1  the registrar names its class only on the cold init path, which the
        compiler places at a higher address than the hot path holding the
        RegisterNatives vtable call - the linear walk reaches the call with
        no class. Everything else reads (stack-marker methods, constant
        count, all words stores the walk saw).
    S2  a static table whose last entry's fnPtr lands on a symbol-less,
        exidx-less Thumb leaf - the fn-start oracle refuses it (yoga cause
        A's shape; the runtime walk is not the reader that fails).
    X1  the i386 sret calls (findClassLocal/findClassStatic end in
        ``ret 0x4``: the callee pops its hidden result pointer). The model
        treats calls as stack-neutral, so the caller's compensating
        ``sub esp, 4`` leaves the frame baseline one word low; registrars
        that store the entry words before the call and compute the methods
        lea after it read the name word from the empty slot below.
    X2  the (methods, count) pair passes to the registerHybrid callee as
        ``initializer_list`` - 8 raw bytes through ``movsd`` - which the
        model already tracks; the defeat is inside the seeded callee,
        whose own findClassLocal call (the X1 sret pop) shifts its frame
        one word below the incoming pair.

(b) The 64-bit census: element (x86_64) and RnHello (arm64-v8a), per
    library, the RegisterNatives vtable sites from llvm-objdump and the
    registrations built at run time per shape - jni.hpp bulk copy (the
    generic ``jni::RegisterNatives`` helpers copying whole 24-byte entries
    out of vararg-passed stack temporaries), single-entry word stores, and
    other - with the walk's own reading of each site's (methods, count)
    beside the textual classification.

(c) What U1 and U2 can reach, stated from (a) and (b).

Usage (from the a13 tree):
  PATH="/opt/homebrew/opt/llvm@18/bin:$PATH" NYXSTONE_LLVM_PREFIX=/opt/homebrew/opt/llvm@18 \
  poetry run python tests/scripts/android/a13_u0_measure.py \
      --corpus ~/sandbox/android-corpus [--json PATH] [--windows DIR]
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import zipfile
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

OBJDUMP = "/opt/homebrew/opt/llvm@18/bin/llvm-objdump"
RNHELLO = ("com.blint.rnhello_1.apk", "tier3-frameworks")
ELEMENT = ("im.vector.app_40106624.apk", "tier2-fdroid")

INSN_RE = re.compile(r"^\s*([0-9a-f]+):\s+(.*)$")
FUNC_RE = re.compile(r"^([0-9a-f]+) <(.+)>:")

# v7a's nine singles (the join's unbound rows minus the 54 yoga wrappers and
# the 21 soloader rows); the five the walk names a registrar for carry '*'.
V7A_SINGLES = {
    "com.facebook.imagepipeline.memory.NativeMemoryChunk.nativeReadByte": "*",
    "com.facebook.jni.ThreadScopeSupport.runStdFunctionImpl": "*",
    "com.facebook.react.bridge.CxxCallbackImpl.nativeInvoke": "*",
    "com.facebook.react.bridge.WritableNativeArray.pushLong": "",
    "com.facebook.react.bridge.WritableNativeMap.putLong": "",
    "com.facebook.react.jscexecutor.JSCExecutor.initHybrid": "",
    "com.facebook.react.runtime.ReactInstance.installGlobals": "",
    "com.facebook.react.uimanager.ComponentNameResolverBinding.install": "*",
    "com.facebook.react.uimanager.UIConstantsProviderBinding.install": "*",
}


def objdump(path: Path, triple: str | None = None, start: int | None = None, stop: int | None = None) -> str:
    cmd = [OBJDUMP, "-d", "--no-show-raw-insn", "--x86-asm-syntax=intel"]
    if triple:
        cmd.append(f"--triple={triple}")
    if start is not None:
        cmd.append(f"--start-address={start}")
    if stop is not None:
        cmd.append(f"--stop-address={stop}")
    cmd.append(str(path))
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=1800).stdout
    except subprocess.TimeoutExpired:
        return ""


def parse_functions(text: str):
    """(current function label, [(address, instruction text)]) from objdump."""
    out: list[tuple[str, int, str]] = []
    func = ""
    for line in text.splitlines():
        if match := FUNC_RE.match(line):
            func = match.group(2)
            continue
        if match := INSN_RE.match(line):
            body = match.group(2).strip()
            if body:
                out.append((func, int(match.group(1), 16), body))
    return out


# ---------------------------------------------------------- part (a): 32-bit

def join_rows(apk: Path, abi: str) -> tuple[dict, dict]:
    """(unbound rows set, runtime_table-bound rows set) for one ABI."""
    import blint.lib.jni as jni_module
    from blint.lib.android_native import scan_android_native

    native = scan_android_native(str(apk))
    original = jni_module.JOIN_LISTING_CAP
    jni_module.JOIN_LISTING_CAP = 10**6
    try:
        join = jni_module.build_jni_join_summary(str(apk), native, confirm_findclass=True)
    finally:
        jni_module.JOIN_LISTING_CAP = original
    abi_join = join["per_abi"][abi]
    unbound = {f"{e['class']}.{e['name']}" for e in abi_join["unbound_dex_natives"]}
    runtime = {
        f"{e['class']}.{e['name']}"
        for e in abi_join["bound_dynamic"]
        if e.get("confirmed_by") == "runtime_table"
    }
    return unbound, runtime


def walk_library(parsed, arch: str):
    """The runtime-table walk's own view of one library: per walked function,
    the class events, the registration events (methods shape, count) and the
    runtime words. Mirrors recover_runtime_tables' scaffolding with the
    records kept for inspection."""
    from blint.lib import jni_findclass as jf
    from blint.lib.disassembler import _elf_plt_stub_names
    from blint.lib.jni import defined_symbol_relocation_map, relative_relocation_map

    sections = jf._exec_sections(parsed)
    starts = jf._function_starts(parsed)
    sorted_starts = sorted(starts)
    if not sections or not sorted_starts:
        return []
    plt_stubs = jf._plt_targets(parsed)
    plt_names = dict(_elf_plt_stub_names(parsed))
    reloc_map = relative_relocation_map(parsed)[0]
    for slot, target in defined_symbol_relocation_map(parsed).items():
        reloc_map.setdefault(slot, target)
    thunks: dict[int, str] = {}
    nyxstone = model = None
    decoder_for = None
    if arch == "arm":
        pair = jf._arm32_models()
        if pair is None:
            return []
        thumb_starts, arm_starts, range_modes = jf._arm32_mode_context(parsed)

        def decoder_for(start: int):
            mode = jf._arm32_mode_for_start(start, thumb_starts, arm_starts, range_modes)
            return pair[mode] + (mode,)

    else:
        from nyxstone import Nyxstone

        from blint.lib.absint import I386_MODEL
        from blint.lib.disassembler import _default_disassembly_features, _merge_features

        nyxstone = Nyxstone(
            target_triple="i386-unknown-linux-android",
            features=_merge_features(_default_disassembly_features("x86"), ""),
            immediate_style=0,
        )
        model = I386_MODEL
        _unused, thunks = jf._i386_pc_context(nyxstone, sections, starts)

    vtable_patterns = jf._X86_VTABLE_SITE_RES if arch == "x86" else jf._ARM32_VTABLE_SITE_RES
    site_functions: set[int] = set()
    for base, blob in sections:
        for pattern in vtable_patterns:
            for match in pattern.finditer(blob):
                start = jf._nearest_start(sorted_starts, base + match.start())
                if start is not None:
                    site_functions.add(start)
    if not site_functions:
        return []
    stub_targets = {stub for stub, definition in plt_stubs.items() if definition in site_functions}
    wanted = site_functions | stub_targets
    caller_sites = (
        jf._direct_callers(sections, wanted)
        if arch == "x86"
        else jf._arm32_direct_callers(sections, wanted)
    )
    roots = set(site_functions)
    for site in caller_sites:
        start = jf._nearest_start(sorted_starts, site)
        if start is not None:
            roots.add(start)
    records = []
    for root in sorted(roots):
        walk_nyxstone, walk_model = nyxstone, model
        if arch == "arm":
            walk_nyxstone, walk_model, _mode = decoder_for(root)
        record = jf._walk_function(
            parsed, walk_nyxstone, walk_model, sections, sorted_starts,
            plt_stubs, plt_names, root, None, reloc_map=reloc_map, thunks=thunks or None,
        )
        record["start"] = root
        record["name"] = starts.get(root) or ""
        record["seeded"] = []
        for call in record["calls"]:
            target = call["target"]
            if target in site_functions:
                seed = jf._seed_for_call(call["args"], arch, call.get("registers"), call.get("slots"))
                walk2 = jf._walk_function(
                    parsed, walk_nyxstone, walk_model, sections, sorted_starts,
                    plt_stubs, plt_names, target, seed, reloc_map=reloc_map, thunks=thunks or None,
                )
                walk2["start"] = target
                walk2["name"] = starts.get(target) or ""
                record["seeded"].append(walk2)
        records.append(record)
    return records


def describe(value) -> str:
    if value is None:
        return "None"
    if isinstance(value, int):
        return f"int:{value:#x}"
    return repr(value)


def part_a(corpus: Path, report: dict, windows: Path | None) -> None:
    apk = corpus / RNHELLO[1] / RNHELLO[0]
    print(f"== (a) {apk.name}")
    v7a_unbound, v7a_runtime = join_rows(apk, "armeabi-v7a")
    x86_unbound, x86_runtime = join_rows(apk, "x86")
    report["a_join_counts"] = {
        abi: join_counts(apk, abi) for abi in ("armeabi-v7a", "x86", "arm64-v8a", "x86_64")
    }
    print(f"   v7a unbound {len(v7a_unbound)}, runtime-bound {len(v7a_runtime)}; "
          f"x86 unbound {len(x86_unbound)}, runtime-bound {len(x86_runtime)}")

    with zipfile.ZipFile(str(apk)) as zf:
        libs = {}
        for info in zf.infolist():
            parts = info.filename.split("/")
            if len(parts) == 3 and parts[0] == "lib" and parts[2].endswith(".so"):
                libs.setdefault((parts[2], parts[1]), []).append(info.filename)
    import tempfile

    import lief

    walks: dict[tuple[str, str], list] = {}
    with tempfile.TemporaryDirectory() as tmp:
        for (name, abi), members in sorted(libs.items()):
            if abi not in ("armeabi-v7a", "x86"):
                continue
            with zipfile.ZipFile(str(apk)) as zf:
                data = zf.read(members[0])
            out = Path(tmp) / f"{name}.{abi}"
            out.write_bytes(data)
            parsed = lief.ELF.parse(data)
            if parsed is None or isinstance(parsed, lief.lief_errors):
                continue
            arch = "x86" if abi == "x86" else "arm"
            walks[(name, abi)] = (walk_library(parsed, arch), out)

    # v7a's singles: which function materializes the class, and what did the
    # walk read at the vtable call?
    singles_report = {}
    for row in sorted(V7A_SINGLES):
        cls, method = row.rsplit(".", 1)
        owners = []
        for (name, abi), (records, _) in walks.items():
            if abi != "armeabi-v7a":
                continue
            for record in records:
                if cls not in record["class_events"] and not any(
                    cls in s["class_events"] for s in record["seeded"]
                ):
                    continue
                regs = [
                    {"methods": describe(e["methods"]), "count": e["count"], "class": e["class"]}
                    for e in record["registration_events"]
                ] + [
                    {"methods": describe(e["methods"]), "count": e["count"], "class": e["class"]}
                    for s in record["seeded"]
                    for e in s["registration_events"]
                ]
                words = [describe(w) for e in record["runtime_registrations"] for w in e["words"]] + [
                    describe(w)
                    for s in record["seeded"]
                    for e in s["runtime_registrations"]
                    for w in e["words"]
                ]
                owners.append(
                    {
                        "library": name,
                        "function": f"0x{record['start']:x}",
                        "symbol": record["name"][:80],
                        "classes": sorted(set(record["class_events"])),
                        "registrations": regs,
                        "runtime_word_count": len(words),
                        "none_words": words.count("None"),
                    }
                )
        singles_report[row] = {"walk_named": bool(owners), "owners": owners}
    report["a_v7a_singles"] = singles_report

    # x86's rows that v7a recovers but x86 does not, plus the shared singles.
    x86_gap = sorted(v7a_runtime & x86_unbound)
    shared = sorted((v7a_unbound & x86_unbound) - {
        f"com.facebook.react.soloader.OpenSourceMergedSoMapping.{m}"
        for m in ()
    } - {
        row for row in v7a_unbound if "OpenSourceMergedSoMapping" in row or row.startswith("com.facebook.yoga.")
    })
    report["a_x86_gap"] = x86_gap
    report["a_x86_shared_singles"] = shared
    print(f"   x86 gap rows (v7a runtime-bound, x86 unbound): {len(x86_gap)}")
    print(f"   shared unbound singles: {len(shared)}")

    # evidence windows for hand reading, one representative per shape
    shapes = {
        "v7a_S1_class_after_vtable__CxxCallbackImpl": ("libreactnative.so", "armeabi-v7a", 0x3C58C0, 0x3C5978, "thumbv7a-none-linux-androideabi"),
        "v7a_S1_class_after_vtable__ThreadScope": ("libfbjni.so", "armeabi-v7a", 0x12698, 0x1276C, "thumbv7a-none-linux-androideabi"),
        "v7a_S1_class_after_vtable__install_binding": ("libreactnative.so", "armeabi-v7a", 0x421C8C, 0x421D24, "thumbv7a-none-linux-androideabi"),
        "v7a_S2_static_refusal__imagepipeline_nativeReadByte": ("libimagepipeline.so", "armeabi-v7a", 0xD60, 0xE4A, "thumbv7a-none-linux-androideabi"),
        "x86_S1_class_after_vtable__CxxCallbackImpl": ("libreactnative.so", "x86", 0x54BA50, 0x54BB40, None),
        "x86_X1_sret_ret4__TurboModulePerfLogger": ("libreactnative.so", "x86", 0x5DAAB0, 0x5DAB70, None),
        "x86_X1_sret_ret4__HybridDataOnLoad": ("libfbjni.so", "x86", 0x1E9F0, 0x1EA80, None),
        "x86_X1_sret_callee__findClassLocal": ("libfbjni.so", "x86", 0x1FA30, 0x1FA80, None),
        "x86_X2_movsd_pair__NativeArray_staging": ("libreactnative.so", "x86", 0x54A7E0, 0x54A850, None),
        "x86_X2_movsd_pair__ReadableMapBuffer_staging": ("libreactnative.so", "x86", 0x3D0840, 0x3D08B0, None),
        "x86_working_control__JReactMarker": ("libreactnative.so", "x86", 0x53E950, 0x53EA10, None),
    }
    if windows:
        windows.mkdir(parents=True, exist_ok=True)
        for label, (name, abi, start, stop, triple) in shapes.items():
            _records, path = walks.get((name, abi), (None, None))
            if path is None:
                continue
            text = objdump(path, triple, start, stop)
            (windows / f"{label}.asm").write_text(text)
        print(f"   wrote {len(shapes)} evidence windows under {windows}")


def join_counts(apk: Path, abi: str) -> dict:
    import blint.lib.jni as jni_module
    from blint.lib.android_native import scan_android_native

    native = scan_android_native(str(apk))
    original = jni_module.JOIN_LISTING_CAP
    jni_module.JOIN_LISTING_CAP = 10**6
    try:
        join = jni_module.build_jni_join_summary(str(apk), native, confirm_findclass=True)
    finally:
        jni_module.JOIN_LISTING_CAP = original
    return dict(join["per_abi"][abi]["counts"])


# ---------------------------------------------------------- part (b): 64-bit

def vtable_sites(path: Path, abi: str) -> list[tuple[str, int, str]]:
    triple = "aarch64-unknown-linux-android" if abi == "arm64-v8a" else "x86_64-unknown-linux-android"
    rows = parse_functions(objdump(path, triple))
    out = []
    for func, addr, text in rows:
        low = text.replace(" ", "")
        if abi == "arm64-v8a":
            hit = low.startswith("ldr") and ("#1720" in low or "#0x6b8" in low)
        else:
            hit = ("+1720]" in low or "+0x6b8]" in low) and low.startswith(("call", "jmp"))
        if hit:
            out.append((func, addr, text))
    return out


def part_b(corpus: Path, report: dict, windows: Path | None) -> None:
    import tempfile


    targets = [
        (corpus / RNHELLO[1] / RNHELLO[0], "arm64-v8a"),
        (corpus / ELEMENT[1] / ELEMENT[0], "x86_64"),
    ]
    census: dict[str, dict] = {}
    for apk, abi in targets:
        print(f"== (b) {apk.name} {abi}")
        with zipfile.ZipFile(str(apk)) as zf:
            members = {}
            for info in zf.infolist():
                parts = info.filename.split("/")
                if len(parts) == 3 and parts[0] == "lib" and parts[1] == abi and parts[2].endswith(".so"):
                    members.setdefault(parts[2], info.filename)
        per_lib = {}
        with tempfile.TemporaryDirectory() as tmp:
            for name, member in sorted(members.items()):
                with zipfile.ZipFile(str(apk)) as zf:
                    data = zf.read(member)
                out = Path(tmp) / name
                out.write_bytes(data)
                sites = vtable_sites(out, abi)
                if not sites:
                    continue
                helpers = {f for f, _, _ in sites if "RegisterNativesIJ" in f or f.startswith("_ZN3jni15RegisterNatives")}
                builders = 0
                full = parse_functions(objdump(out, "aarch64-unknown-linux-android" if abi == "arm64-v8a" else "x86_64-unknown-linux-android"))
                calls = [(f, a, t) for f, a, t in full if t.startswith("call")]
                bulk_callers = sorted({
                    f for f, a, t in calls
                    if ("_ZN3jni15RegisterNativesIJ" in t or "_ZN3jni15RegisterNativesI" in t)
                    and f not in helpers
                })
                builders = sorted({
                    f for f, a, t in calls
                    if "_ZN3jni16MakeNativeMethod" in t or "_ZN3jni18RegisterNativePeer" in t
                })
                per_lib[name] = {
                    "sites": len(sites),
                    "helper_functions": len(helpers),
                    "bulk_copy_callers": len(bulk_callers),
                    "builder_callers": len(builders),
                    "site_functions": Counter(f[:70] for f, _, _ in sites),
                }
                print(
                    f"   {name}: {len(sites)} sites, {len(helpers)} jni::RegisterNatives helpers, "
                    f"{len(bulk_callers)} bulk-copy callers, {len(builders)} builder callers"
                )
                if windows and name in ("libmaplibre.so", "libfbjni.so", "libreactnative.so"):
                    windows.mkdir(parents=True, exist_ok=True)
                    # one representative per shape family for hand reading
                    for label, needle in (
                        ("bulk_copy_helper", "RegisterNativesIJ"),
                        ("single_entry_builder", "MakeNativeMethod"),
                    ):
                        for f, addr, _ in sites:
                            if needle in f:
                                stop = min(addr + 0x120, addr + 0x4000)
                                text = objdump(out, None, addr - 0x40 if addr > 0x40 else 0, stop)
                                (windows / f"{apk.stem}.{abi}.{name}.{label}.asm").write_text(text)
                                break
        census[f"{apk.name}:{abi}"] = per_lib
    report["b_census"] = census


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--json", type=Path, default=None)
    parser.add_argument("--windows", type=Path, default=None)
    args = parser.parse_args(argv)
    report: dict = {"objdump": OBJDUMP}
    part_a(args.corpus, report, args.windows)
    part_b(args.corpus, report, args.windows)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        report["b_census"] = {
            apk: {
                lib: {**counts, "site_functions": dict(counts["site_functions"])}
                for lib, counts in libs.items()
            }
            for apk, libs in report["b_census"].items()
        }
        args.json.write_text(json.dumps(report, indent=1, default=str) + "\n")
        print(f"wrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
