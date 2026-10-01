#!/usr/bin/env python3
"""A12 T0 - armeabi-v7a's RnHello rows measured: the confirmer's 22 ambiguous
rows and the 45 non-yoga unbound rows, from ``llvm-objdump`` Thumb text.

Measure only; no production change. Four answers:

(a) The join with the FindClass confirmer on this tree: per-ABI counts, and
    v7a's 99 unbound rows split into the three A10 causes - the 54 yoga
    wrappers (cause A, closed), the rows bound on arm64 but not v7a that are
    not yoga (cause B, the runtime-built or ambiguous-residue rows this wave
    targets), and the rows no ABI binds (out of reach).

(b) For each of v7a's 22 ambiguous rows: the registrar chain in v7a bytes -
    the ``X::registerNatives()`` staging function and the ``registerHybrid``
    instantiation that makes the RegisterNatives vtable call - and the shape
    of the (methods, count) pair (static table, stack copy of a static table,
    run-time word stores).

(c) The same for the 45 non-yoga unbound rows, separating the tables built at
    run time from the rest.

(d) From (a)-(c): what T1/T2/T3 can reach and what stays out of reach.

The disassembly oracle is llvm-objdump from the prefix named below; v7a needs
the Thumb triple forced (the stripped .so files carry no $t mapping symbols),
so ARM-mode islands (the .plt among them) decode as garbage. The PLT is
decoded separately in ARM mode and its stubs resolved through .rel.plt, which
is how the staging calls into the preemptible registerHybrid weak symbols are
named; a window that fails to decode is classified ``other`` and never
counted as runtime-built.

Usage:
  PATH="/opt/homebrew/opt/llvm@18/bin:$PATH" NYXSTONE_LLVM_PREFIX=/opt/homebrew/opt/llvm@18 \
  poetry run python tests/scripts/android/a12_t0_measure.py \
      --corpus ~/sandbox/android-corpus [--json PATH]
"""

from __future__ import annotations

import argparse
import json
import re
import struct
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
ABI = "armeabi-v7a"

INSN_RE = re.compile(r"^\s*([0-9a-f]+):\s+(?:<unknown>\s+)?(.*)$")
FUNC_RE = re.compile(r"^([0-9a-f]+) <(.+)>:")

# The RegisterNatives vtable slot in llvm-objdump Thumb text: JNIEnv slot 215
# at 32-bit word size is 860 (0x35c), loaded then called through with blx.
VTABLE_LOAD = re.compile(r"ldr(\.w)?\s+r\d+,\s*\[r\d+,\s*#(860|0x35c)\]")
BLX_REG = re.compile(r"\bblx(\.w)?\s+r\d+")
# Word stores into a stack buffer (sp-relative str/strd), the run-time build.
WORD_STORE = re.compile(r"str(\.w)?\s+r\d+,\s*\[sp|\bstrd\b")


def run_objdump(path: Path, triple: str, start: int | None = None, stop: int | None = None) -> str:
    cmd = [OBJDUMP, "-d", "--no-show-raw-insn", "--demangle", f"--triple={triple}"]
    if start is not None:
        cmd.append(f"--start-address={start}")
    if stop is not None:
        cmd.append(f"--stop-address={stop}")
    cmd.append(str(path))
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=900).stdout
    except subprocess.TimeoutExpired:
        return ""


def parse_lines(lines: list[str]) -> tuple[list[dict], list[str]]:
    """(instructions, function-name list) aligned by index; names may be ''."""
    insns: list[dict] = []
    funcs: list[str] = []
    current = ""
    for line in lines:
        if match := FUNC_RE.match(line):
            current = match.group(2)
            continue
        if match := INSN_RE.match(line):
            text = match.group(2).strip()
            if not text:
                continue
            insns.append({"address": int(match.group(1), 16), "text": text})
            funcs.append(current)
    return insns, funcs


def arm_plt_stubs(path: Path) -> dict[int, str]:
    """``{stub address: symbol name}`` for the ARM-mode .plt entries.

    Each entry is ``add ip, pc, #A; add ip, ip, #B; ldr pc, [ip, #C]!`` so its
    GOT slot is ``stub + 8 + A + B + C``; the slot's JUMP_SLOT relocation
    names the symbol.
    """

    def rotated(imm12: int) -> int:
        amount = ((imm12 >> 8) & 0xF) * 2
        imm8 = imm12 & 0xFF
        if not amount:
            return imm8
        return ((imm8 >> amount) | (imm8 << (32 - amount))) & 0xFFFFFFFF

    import lief

    parsed = lief.ELF.parse(str(path))
    got_names: dict[int, str] = {}
    for reloc in getattr(parsed, "pltgot_relocations", []) or []:
        with contextlib_suppress():
            if reloc.has_symbol and (reloc.symbol.name or "").strip():
                got_names[int(reloc.address)] = reloc.symbol.name.strip()
    plt = parsed.get_section(".plt")
    data = bytes(plt.content)
    base = int(plt.virtual_address)
    stubs: dict[int, str] = {}
    for offset in range(0, len(data) - 12, 4):
        w0 = struct.unpack_from("<I", data, offset)[0]
        if (w0 & 0xFFFFF000) != 0xE28FC000:
            continue
        w1 = struct.unpack_from("<I", data, offset + 4)[0]
        if (w1 & 0xFFFFF000) != 0xE28CC000:
            continue
        w2 = struct.unpack_from("<I", data, offset + 8)[0]
        if (w2 & 0xFFFFF000) != 0xE5BCF000:
            continue
        slot = base + offset + 8 + rotated(w0 & 0xFFF) + rotated(w1 & 0xFFF) + (w2 & 0xFFF)
        if name := got_names.get(slot):
            stubs[base + offset] = name
    return stubs


def contextlib_suppress():
    import contextlib

    return contextlib.suppress(AttributeError, TypeError, ValueError)


def classify_pair(insns: list[dict], i: int, methods_reg: str, count_reg: str) -> dict:
    """How one staging or vtable site forms (methods, count).

    ``methods_source``: stack (an sp-derived address in the methods register),
    static (a pc-relative pool load plus ``add rN, pc``) or unknown (an
    incoming argument or an untraced register). ``shape`` names the store
    sequence when methods is a stack address: stack_copy_static (a memcpy
    whose PLT stub resolves to memcpy/memmove), runtime_built (three or more
    word stores into the sp buffer, no memcpy) or stack_unknown_source.
    """
    window = "\n".join(insn["text"] for insn in insns[max(0, i - 40) : i + 1])
    methods_source = "unknown"
    shape = "other"
    count_imm = None
    # the count: the last `movs rN, #c` in the eight instructions above the
    # call (the whole 40-instruction window can hold other counts)
    for insn in reversed(insns[max(0, i - 8) : i]):
        if m := re.match(rf"movs\s+{count_reg},\s*#(0x[0-9a-f]+|\d+)", insn["text"]):
            count_imm = int(m.group(1), 0)
            break
    if re.search(
        rf"(adds?(\.w)?\s+{methods_reg},\s*sp(,\s*#(0x[0-9a-f]+|\d+))?|movs?\s+{methods_reg},\s*sp)\b",
        window,
    ):
        methods_source, shape = "stack", "stack_unknown_source"
    elif re.search(rf"movs?\s+{methods_reg},\s+r([0-7])\b", window) and any(
        re.search(rf"movs?\s+{methods_reg},\s+r{saved}\b", window)
        for saved in re.findall(r"movs?\s+r([0-7]),\s*sp\b", window)
    ):
        # mov r0, r4 with r4 saved from sp in the prologue: the methods
        # argument is the stack buffer through one register hop
        methods_source, shape = "stack", "stack_unknown_source"
    elif re.search(rf"ldr(\.w)?\s+{methods_reg},\s*\[pc,", window) and re.search(
        rf"add(\.w)?\s+{methods_reg},\s*pc\b", window
    ):
        methods_source = "static"
    elif re.search(rf"movs?\s+{methods_reg},\s+r\d+", window):
        # any other register move: an incoming argument this window cannot
        # place (the fbjni callee's saved r5)
        methods_source = "register"
    if methods_source == "stack":
        copied = False
        for insn in insns[max(0, i - 40) : i + 1]:
            m = re.match(r"movs?\s+r2,\s*#(0x[0-9a-f]+|\d+)", insn["text"])
            if m and count_imm and int(m.group(1), 0) == count_imm * 12:
                # a copy of exactly count*12 bytes into the buffer: the
                # memcpy shape, whatever thunk the copy call goes through
                copied = True
        if copied:
            shape = "stack_copy_static"
        elif len(WORD_STORE.findall(window)) >= 3:
            shape = "runtime_built"
    return {
        "methods_source": methods_source,
        "shape": shape,
        "count_imm": count_imm,
    }


def library_sites(apk: Path) -> dict[str, dict]:
    """Per library: the staging calls into registerHybrid and the vtable sites,
    each classified, with the instruction lists kept for the verbatim prints."""
    out: dict[str, dict] = {}
    with zipfile.ZipFile(str(apk)) as zf:
        for info in zf.infolist():
            parts = info.filename.split("/")
            if (
                len(parts) != 3
                or parts[0] != "lib"
                or parts[1] != ABI
                or not parts[2].endswith(".so")
            ):
                continue
            library = parts[2]
            tmp = Path(f"/tmp/a12-t0-{library}")
            tmp.write_bytes(zf.read(info))
            insns, funcs = parse_lines(
                run_objdump(tmp, "thumbv7a-none-linux-androideabi").splitlines()
            )
            stubs = arm_plt_stubs(tmp)
            tmp.unlink(missing_ok=True)
            entries = []
            # staging: blx <plt stub> whose symbol names registerHybrid; the
            # pair (initializer_list) is (r0, r1) at the call
            for i, insn in enumerate(insns):
                match = re.match(r"blx\s+0x([0-9a-f]+)", insn["text"])
                if not match:
                    continue
                name = stubs.get(int(match.group(1), 16), "")
                if "registerHybrid" not in name:
                    continue
                entries.append(
                    {
                        "kind": "staging",
                        "index": i,
                        "address": hex(insn["address"]),
                        "function": funcs[i],
                        "target": name,
                        **classify_pair(insns, i, "r0", "r1"),
                    }
                )
            # vtable: ldr rN, [rM, #860] then blx rN within a few instructions;
            # (methods, count) are (r2, r3) at the call
            for i, insn in enumerate(insns):
                if not VTABLE_LOAD.search(insn["text"]):
                    continue
                for j in range(i, min(i + 6, len(insns))):
                    if not BLX_REG.search(insns[j]["text"]):
                        continue
                    entries.append(
                        {
                            "kind": "vtable",
                            "index": j,
                            "address": hex(insns[j]["address"]),
                            "function": funcs[j],
                            "target": "",
                            **classify_pair(insns, j, "r2", "r3"),
                        }
                    )
                    break
            if entries:
                out[library] = {"entries": entries, "insns": insns, "funcs": funcs}
    return out


# The dex class's simple name usually names the C++ registrar exactly
# (CatalystInstanceImpl, WritableNativeArray); a few RN declarations are
# registered by a differently-named C++ class, hand-checked against the
# labels llvm-objdump carries in the v7a bytes.
ALIASES = {
    "BindingImpl": ("Binding",),
    "CompositeReactPackageTurboModuleManagerDelegate": ("CompositeTurboModuleManagerDelegate",),
    "EmptyReactNativeConfig": ("ReactNativeConfig",),
    "ReactInstance": ("JReactInstance",),
    "ReactInstanceManagerInspectorTarget": (
        "ReactInstanceManagerInspectorTarget",
        "JReactInstanceManagerInspectorTarget",
    ),
    "ReactHostInspectorTarget": ("JReactHostInspectorTarget",),
    "DefaultComponentsRegistry": ("DefaultComponentsRegistry",),
    # fbjni's own lifecycle registrations: the dex class names the Java side,
    # the C++ label names the fbjni internal that registers it
    "ThreadScopeSupport": ("ThreadScope",),
}


def _label_tokens(function: str) -> frozenset[str]:
    """The C++ class names a demangled label names, as whole tokens."""
    return frozenset(token for token in re.split(r"[<>,()\s:&*]+", function) if token)


def map_rows_to_sites(rows: list[dict], sites: dict[str, dict]) -> list[dict]:
    """Attach the registrar chain whose function label names the row's class:
    a registerHybrid instantiation (the fbjni callee) or an X::registerNatives
    same-function registrar. The label's class-name tokens are matched whole
    (ReactInstance must not borrow ReactInstanceManagerInspectorTarget's
    registrar), exact class name before the hand-checked aliases."""

    def chains_for(needles: tuple[str, ...]) -> list[dict]:
        chain = []
        for library, data in sites.items():
            for entry in data["entries"]:
                tokens = _label_tokens(entry["function"])
                if not any(needle in tokens for needle in needles):
                    continue
                if entry["kind"] == "staging" and "registerNatives" in entry["function"]:
                    kind = "staging"
                elif entry["kind"] == "vtable" and "registerHybrid" in entry["function"]:
                    kind = "callee"
                elif entry["kind"] == "vtable" and "registerNatives" in entry["function"]:
                    kind = "same-function"
                else:
                    continue
                chain.append(
                    {
                        "library": library,
                        "registrar": f"{kind}:{entry['function'][:80]}",
                        "shape": entry["shape"] or entry["methods_source"],
                        "count_imm": entry["count_imm"],
                        "address": entry["address"],
                        "index": entry["index"],
                        "kind": kind,
                    }
                )
        return chain

    for row in rows:
        simple = row["class"].rsplit(".", 1)[-1]
        chain = (
            chains_for((simple,))
            or chains_for((f"J{simple}",))
            or chains_for(ALIASES.get(simple, ()))
        )
        row["chains"] = chain[:4]
        row["chain"] = (
            f"{chain[0]['registrar'].split(':')[0]}:{chain[0]['shape']}"
            if chain
            else "no-named-registrar"
        )
    return rows


def run_join(corpus: Path) -> dict:
    import blint.lib.jni as jni_module
    from blint.lib.android_native import scan_android_native

    apk = str(corpus / RNHELLO[1] / RNHELLO[0])
    native = scan_android_native(apk)
    original_cap = jni_module.JOIN_LISTING_CAP
    jni_module.JOIN_LISTING_CAP = 10**6
    try:
        return jni_module.build_jni_join_summary(apk, native, confirm_findclass=True)
    finally:
        jni_module.JOIN_LISTING_CAP = original_cap


def row_key(row: dict) -> tuple[str, str, str]:
    return (row["class"], row["name"], row["descriptor"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--json", type=Path, default=None)
    args = parser.parse_args(argv)

    apk = args.corpus / RNHELLO[1] / RNHELLO[0]
    print(f"objdump oracle: {OBJDUMP}")
    print("== (a) the join on this tree, and v7a's three causes")
    join = run_join(args.corpus)
    counts = {abi: abi_join["counts"] for abi, abi_join in sorted(join["per_abi"].items())}
    for abi, abi_counts in counts.items():
        print(f"  {abi}: {json.dumps(abi_counts)}")
    arm64 = join["per_abi"]["arm64-v8a"]
    v7a = join["per_abi"][ABI]
    # what arm64 answers: bound or bound_dynamic. Its one ambiguous residue
    # (JSCInstance.initHybrid) counts with the rows no ABI binds.
    arm64_answered = set()
    for list_name in ("bound", "bound_dynamic"):
        for entry in arm64.get(list_name) or []:
            arm64_answered.add((entry["class"], entry["name"], entry["descriptor"]))
    ambiguous_rows = [
        {"class": e["class"], "name": e["name"], "descriptor": e["descriptor"]}
        for e in v7a["ambiguous_dynamic"]
    ]
    unbound = [
        {"class": e["class"], "name": e["name"], "descriptor": e["descriptor"]}
        for e in v7a["unbound_dex_natives"]
    ]
    yoga = [row for row in unbound if row["class"] == "com.facebook.yoga.YogaNative"]
    gap = [
        row
        for row in unbound
        if row["class"] != "com.facebook.yoga.YogaNative" and row_key(row) in arm64_answered
    ]
    nowhere = [
        row
        for row in unbound
        if row["class"] != "com.facebook.yoga.YogaNative" and row_key(row) not in arm64_answered
    ]
    print(
        f"  v7a unbound {len(unbound)} = {len(yoga)} yoga (cause A, closed; arm64 binds the same"
        f" declarations) + {len(gap)} non-yoga bound on arm64 (cause B) + {len(nowhere)} no ABI binds"
    )

    print("== (b)+(c) the registrar chains in v7a bytes")
    sites = library_sites(apk)
    for library, data in sorted(sites.items()):
        shapes: Counter = Counter(
            f"{e['kind']}:{e['shape'] or e['methods_source']}" for e in data["entries"]
        )
        print(f"  {library}: {dict(shapes)}")

    def report_rows(rows: list[dict], label: str) -> list[dict]:
        mapped = map_rows_to_sites([dict(row) for row in rows], sites)
        shape_counter: Counter = Counter(row["chain"] for row in mapped)
        print(f"  {label}: {len(mapped)} rows; chains: {json.dumps(dict(shape_counter))}")
        for row in mapped:
            print(
                f"    {row['class'].rsplit('.', 1)[-1]}.{row['name']}: {row['chain']}"
                + (
                    f" count={row['chains'][0]['count_imm']}"
                    if row["chains"] and row["chains"][0]["count_imm"]
                    else ""
                )
            )
        return mapped

    ambiguous_mapped = report_rows(ambiguous_rows, "(b) v7a's 22 ambiguous rows")
    gap_mapped = report_rows(gap, "(c) cause B: the 19 non-yoga rows arm64 binds")
    nowhere_mapped = report_rows(nowhere, "(c) the 26 rows no ABI binds")

    print("== verbatim representatives (one per distinct chain shape)")
    seen: set[str] = set()
    for label, rows in (
        ("ambiguous", ambiguous_mapped),
        ("causeB", gap_mapped),
        ("nowhere", nowhere_mapped),
    ):
        for row in rows:
            shape = row["chain"]
            if shape in seen or not row["chains"]:
                continue
            seen.add(shape)
            site = row["chains"][0]
            data = sites[site["library"]]
            insns = data["insns"]
            print(f"  -- {label} {row['class'].rsplit('.', 1)[-1]}.{row['name']} [{shape}]")
            print(f"     {site['library']} {site['registrar']} at {site['address']}")
            for insn in insns[max(0, site["index"] - 20) : site["index"] + 1]:
                print(f"    {insn['address']:x}: {insn['text']}")

    if args.json:
        report = {
            "objdump": OBJDUMP,
            "counts": counts,
            "causes": {"yoga": len(yoga), "cause_b": len(gap), "no_abi_binds": len(nowhere)},
            "ambiguous_rows": ambiguous_mapped,
            "cause_b_rows": gap_mapped,
            "nowhere_rows": [
                {k: row[k] for k in ("class", "name", "chain")} for row in nowhere_mapped
            ],
            "sites": {
                library: [{k: v for k, v in e.items() if k != "index"} for e in data["entries"]]
                for library, data in sites.items()
            },
        }
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=1, default=str) + "\n")
        print(f"wrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
