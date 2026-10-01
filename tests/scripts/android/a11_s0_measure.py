#!/usr/bin/env python3
"""A11 S0 - the i386 confirmer's inputs and the tables built at run time, measured.

Measure only; no production change. Three answers:

(a) For RnHello x86's 22 ``ambiguous_dynamic`` rows (the join with the FindClass
    confirmer), the registrar chain and the instruction sequence that passes
    ``methods`` and ``count`` to ``RegisterNatives``, from ``llvm-objdump``
    text: per row, the ``X::registerNatives()`` function that stages the
    (methods, count) pair (classified: static table, stack copy of a static
    table, or words built at run time) and the ``registerHybrid`` instantiation
    that makes the vtable call. One representative sequence per shape is
    printed verbatim.

(b) Across the 27-APK corpus (26 tier2-fdroid + RnHello), for every ABI and
    every library: how many ``RegisterNatives`` vtable call sites pass a
    ``methods`` pointer that names a table *built at run time* (stack stores,
    no static triple), how many pass a static table address, and how many
    carry a count computed at run time. The store sequence is named per
    family (fbjni, jni.hpp/maplibre, other).

    Classification traces the *last writer* of the methods argument at each
    call site (the register/slot the ABI reads it from), then - where that
    writer is a stack address - looks for the memcpy (stack copy of a static
    table) or the >=3 word stores (table built at run time) that filled the
    buffer. arm32 literal-pool loads count as static: a literal is an
    address in the data segments, never a stack pointer.

(c) From (a)+(b): what S1/S3 can reach and what stays out of reach.

The disassembly oracle is llvm-objdump from the prefix named below; v7a needs
the Thumb triple forced (the stripped .so files carry no $t mapping symbols),
so ARM-mode islands inside a v7a library may decode as garbage; a window that
fails to decode is classified ``other`` and never counted as runtime-built.

Usage:
  PATH="/opt/homebrew/opt/llvm@18/bin:$PATH" NYXSTONE_LLVM_PREFIX=/opt/homebrew/opt/llvm@18 \
  poetry run python tests/scripts/android/a11_s0_measure.py \
      --corpus ~/sandbox/android-corpus [--json PATH] [--rnhello-only]
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

OBJDUMP = "/opt/homebrew/opt/llvm@18/bin/llvm-objdump"

# The 27 APKs of the R3 ladder: 26 tier2-fdroid plus RnHello.
FDROID_DIR = "tier2-fdroid"
RNHELLO = ("com.blint.rnhello_1.apk", "tier3-frameworks")

ABIS = ("arm64-v8a", "armeabi-v7a", "x86", "x86_64")

# The RegisterNatives vtable slot in llvm-objdump text, per ABI (JNIEnv slot
# 215: 215*8 on 64-bit ABIs, 215*4 on 32-bit). AT&T spelling as objdump prints
# it for the indirect call/jump through the slot, or the slot load followed by
# an indirect call through the loaded register.
VTABLE_TOKENS = {
    "arm64-v8a": (re.compile(r"ldr\s+x\d+,\s*\[x\d+,\s*#0x6b8\]"), re.compile(r"\bblr\b")),
    "armeabi-v7a": (
        re.compile(r"ldr(\.w)?\s+r\d+,\s*\[r\d+,\s*#(860|0x35c)\]"),
        re.compile(r"\bblx\b"),
    ),
    "x86": (
        re.compile(r"(calll|jmpl)\s+\*0x35c\(%e[a-z]{2}\)"),
        re.compile(r"calll\s+\*%e[a-z]{2}"),
    ),
    "x86_64": (
        re.compile(r"(callq|jmpq)\s+\*0x6b8\(%r[a-z0-9]{1,3}\)"),
        re.compile(r"callq\s+\*%r[a-z0-9]{1,3}"),
    ),
}
VTABLE_LOAD = {
    "x86": re.compile(r"movl\s+0x35c\(%([a-z]{2,3})\),\s+%([a-z]{2,3})"),
    "x86_64": re.compile(r"movq\s+0x6b8\(%r([a-z0-9]{1,3})\),\s*%r([a-z0-9]{1,3})"),
}

MEMCPY = re.compile(r"call[lq]?\s+0x[0-9a-f]+\s+<mem(move|cpy)@plt>")
# An SSE move whose source is a static address (GOTOFF on i386, rip-relative
# on x86-64, adrp-fed on arm64): a 16-byte copy out of the file's data.
SSE_STATIC_LOAD = re.compile(
    r"mov(?:ups|aps|sd|lps|lpd|q)\s+-?0x[0-9a-f]+\(%(?:e?bx|rip|r1[0-5]|rax|rbp)\),\s*%xmm\d+"
    r"|ldr\s+q\d+,\s*\[x\d+(?:,\s*#-?0x[0-9a-f]+)?\]"
)
INSN_RE = re.compile(r"^\s*([0-9a-f]+):\s+(?:<unknown>\s+)?(.*)$")
FUNC_RE = re.compile(r"^([0-9a-f]+) <(.+)>:")


def objdump(path: Path, abi: str) -> list[str]:
    cmd = [OBJDUMP, "-d", "--no-show-raw-insn", "--demangle"]
    if abi == "armeabi-v7a":
        cmd.append("--triple=thumbv7a-none-linux-androideabi")
    cmd.append(str(path))
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=300).stdout
    except subprocess.TimeoutExpired:
        return []
    return out.splitlines()


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


def vtable_sites(insns: list[dict], abi: str) -> list[int]:
    """Indices of instructions that call (or tail-call) RegisterNatives."""
    load, _ = VTABLE_TOKENS[abi]
    sites: list[int] = []
    for i, insn in enumerate(insns):
        if load.search(insn["text"]):
            sites.append(i)
            continue
        if abi in VTABLE_LOAD:
            if match := VTABLE_LOAD[abi].search(insn["text"]):
                reg = match.group(2)  # the register the slot was loaded into
                callee = re.compile(rf"(calll|callq|jmpl|jmpq)\s+\*%r?{reg}\b")
                for j in range(i + 1, min(i + 8, len(insns))):
                    if callee.search(insns[j]["text"]):
                        sites.append(i)
                        break
    return sites


# -- last-writer tracing ------------------------------------------------------


def last_writer(insns: list[dict], start: int, pattern: re.Pattern) -> tuple[int, re.Match] | None:
    """The closest instruction at or above ``start`` whose text ``pattern`` matches."""
    for j in range(start, max(-1, start - 60), -1):
        if match := pattern.search(insns[j]["text"]):
            return j, match
    return None


def classify_site(insns: list[dict], funcs: list[str], i: int, abi: str) -> dict:
    """How one RegisterNatives site forms (methods, count).

    ``methods_source``: stack (an esp/sp-relative address), static (a data
    address: GOTOFF/GOT/rip/adrp/literal-pool) or unknown (a register this
    window never saw written - an incoming argument, a heap pointer).
    ``shape`` names the store sequence when methods is a stack address:
    ``stack_copy_static`` (a memcpy from a data address), ``runtime_built``
    (three or more word stores into the buffer, no memcpy) or
    ``stack_unknown_source``.
    """
    methods_source = "unknown"
    shape = "other"
    count_imm = None
    writer_text = None
    window = "\n".join(insn["text"] for insn in insns[max(0, i - 48) : i + 1])
    if abi == "x86":
        # cdecl: methods is the third stack argument - stored into 0x8(%esp)
        # at the call (esp unchanged by stores) or pushed second-before the call.
        if (w := last_writer(insns, i, re.compile(r"movl\s+%([a-z]{2,3}),\s*0x8\(%esp\)"))) or (
            w := last_writer(insns, i, re.compile(r"pushl\s+%([a-z]{2,3})"))
        ):
            reg = w[1].group(1)
            methods_source, shape, writer_text = _x86_source(insns, w[0] - 1, reg, window)
        if w := last_writer(insns, i - 1, re.compile(r"movl\s+\$0x([0-9a-f]+),\s*0xc\(%esp\)")):
            count_imm = int(w[1].group(1), 16)
        else:
            # a run of pushes ending at the call passes (env, clazz, methods,
            # count); the count is the first pushed - an immediate there is a
            # constant count, anything else is computed at run time.
            pushes: list[str] = []
            j = i - 1
            while j >= 0 and len(pushes) < 4 and re.match(r"pushl\s", insns[j]["text"]):
                pushes.append(insns[j]["text"])
                j -= 1
            if len(pushes) == 4 and (mm := re.match(r"pushl\s+\$0x([0-9a-f]+)", pushes[-1])):
                count_imm = int(mm.group(1), 16)
    elif abi == "x86_64":
        if w := last_writer(insns, i, re.compile(r"mov[lq]?\s+%([a-z0-9]{2,3}),\s*%rdx")):
            reg = w[1].group(1)
            if reg in ("rsp", "rbp"):
                methods_source, shape = "stack", "stack_unknown_source"
            elif reg == "rip":
                methods_source = "static"
            else:
                traced = last_writer(
                    insns, w[0] - 1, re.compile(rf"(lea|mov|xor)[lq]?\s+[^,]*,\s*%{reg}\b")
                )
                methods_source, shape, writer_text = (
                    _x64_source(insns, traced, reg, window) if traced else ("unknown", "other", "")
                )
            writer_text = insns[w[0]]["text"]
        if w := last_writer(
            insns,
            i - 1,
            re.compile(
                r"mov[lq]?\s+\$0x([0-9a-f]+),\s*%ecx|mov[lq]?\s+\$0x([0-9a-f]+),\s*0xc\(%rsp\)"
            ),
        ):
            count_imm = int(w[1].group(1) or w[1].group(2), 16)
    elif abi == "arm64-v8a":
        if w := last_writer(insns, i, re.compile(r"mov\s+x2,\s*(\w+)|add\s+x2,\s*(\w+),\s*(\w+)")):
            text = insns[w[0]]["text"]
            writer_text = text
            operand = w[1].group(1) or w[1].group(2)
            if operand == "sp":
                methods_source = "stack"
                shape = "stack_unknown_source"
            elif re.match(r"^x\d+$", operand):
                # trace one register-to-register hop (an incoming argument or a
                # callee-saved copy of one); a second hop gives up
                hop = last_writer(insns, w[0] - 1, re.compile(rf"(mov|add)\s+{operand},\s*\w+"))
                if hop and "sp" in insns[hop[0]]["text"].split(",")[-1]:
                    methods_source, shape = "stack", "stack_unknown_source"
                elif hop and re.search(r"adrp|ldr\s+x\d+,\s*\[x\d+,", insns[hop[0]]["text"]):
                    methods_source = "static"
            elif "adrp" in text:
                methods_source = "static"
        m = re.findall(r"mov\s+(?:w|x)3,\s*#0?x?([0-9a-f]+)", window)
        if m:
            count_imm = int(m[-1], 16)
    else:  # armeabi-v7a, Thumb forced
        if w := last_writer(
            insns,
            i,
            re.compile(r"movs?\s+r2,\s*(\w+)|adds?\s+r2,\s*sp(?:,\s*#(0x[0-9a-f]+|[0-9]+))?"),
        ):
            text = insns[w[0]]["text"]
            writer_text = text
            operand = w[1].group(1) or "sp"
            if operand == "sp":
                methods_source = "stack"
                shape = "stack_unknown_source"
            elif operand == "pc" or "ldr" in text and "[pc" in text:
                methods_source = "static"
        elif w := last_writer(insns, i, re.compile(r"ldr(\.w)?\s+r2,\s*\[pc")):
            methods_source, writer_text = "static", insns[w[0]]["text"]
        m = re.findall(r"movs\s+r3,\s*#([0-9]+)", window)
        if m:
            count_imm = int(m[-1])
    if methods_source == "stack" and shape == "stack_unknown_source":
        if MEMCPY.search(window):
            shape = "stack_copy_static"
        elif SSE_STATIC_LOAD.search(window):
            # 16-byte copies out of a static region: the table exists in the
            # file, only the buffer is built at run time.
            shape = "sse_copy_static"
        else:
            stores = re.findall(
                r"mov[lq]?\s+(?:%[er][a-z0-9]+|\$0x[0-9a-f]+),\s*-?0x[0-9a-f]+\(%[er]?sp\)", window
            ) or re.findall(r"str\s+w?\d+,\s*\[sp(?:,\s*#-?\d+)?\]", window)
            if len(stores) >= 3:
                shape = "runtime_built"
    return {
        "methods_source": methods_source,
        "shape": shape
        if methods_source == "stack"
        else ("static" if methods_source == "static" else "other"),
        "count_imm": count_imm,
        "writer": writer_text,
    }


def _x86_source(insns: list[dict], j: int, reg: str, window: str) -> tuple[str, str, str]:
    """The methods register's origin on i386: stack, GOTOFF/GOT static, unknown."""
    writer = last_writer(
        insns, j, re.compile(rf"(lea[lq]?|mov[lq]?|xor[lq]?)\s+[^,]*,\s*%{reg}\b")
    )
    if not writer:
        return "unknown", "other", ""
    text = insns[writer[0]]["text"]
    if re.search(rf"lea[lq]?\s+-?0x[0-9a-f]+\(%esp\),\s*%{reg}", text):
        return "stack", "stack_unknown_source", text
    if re.search(rf"lea[lq]?\s+-?0x[0-9a-f]+\(%e?bx\),\s*%{reg}", text):
        return "static", "static", text
    if re.search(rf"mov[lq]?\s+-?0x[0-9a-f]+\(%e?bx\),\s*%{reg}", text):
        return "static", "static", text
    if re.search(rf"xor[lq]?\s+%{reg},\s*%{reg}", text):
        return "static", "static", text  # NULL methods: GetEnv probe shape
    return "unknown", "other", text


def _x64_source(
    insns: list[dict], traced: tuple[int, re.Match] | None, src: str, window: str
) -> tuple[str, str, str]:
    if not traced:
        return "unknown", "other", ""
    text = insns[traced[0]]["text"]
    if re.search(r"lea[q]?\s+-?0x[0-9a-f]+\(%rsp\),", text) or re.search(
        r"lea[q]?\s+-?0x[0-9a-f]+\(%rbp\),", text
    ):
        return "stack", "stack_unknown_source", text
    if re.search(r"lea[q]?\s+-?0x[0-9a-f]+\(%rip\),", text):
        return "static", "static", text
    if "adrp" in text:
        return "static", "static", text
    return "unknown", "other", text


def family_of(library: str) -> str:
    lowered = library.lower()
    if "maplibre" in lowered:
        return "jni.hpp (maplibre)"
    if "fbjni" in lowered:
        return "fbjni"
    return "other"


# -- part (a): the 22 rows' registrars ----------------------------------------


def rnhello_rows(corpus: Path) -> dict:
    """The join with the confirmer: counts per ABI and x86's ambiguous rows."""
    import blint.lib.jni as jni_module
    from blint.lib.android_native import scan_android_native

    apk = str(corpus / RNHELLO[1] / RNHELLO[0])
    native = scan_android_native(apk)
    original_cap = jni_module.JOIN_LISTING_CAP
    jni_module.JOIN_LISTING_CAP = 10**6
    try:
        join = jni_module.build_jni_join_summary(apk, native, confirm_findclass=True)
    finally:
        jni_module.JOIN_LISTING_CAP = original_cap
    rows = []
    counts = {}
    for abi, abi_join in sorted((join or {}).get("per_abi", {}).items()):
        counts[abi] = abi_join["counts"]
        if abi == "x86":
            rows = [
                {"class": e["class"], "name": e["name"], "descriptor": e["descriptor"]}
                for e in abi_join.get("ambiguous_dynamic") or []
            ]
    return {"counts": counts, "rows": rows}


def extract_x86_library(apk: Path, member: str) -> Path:
    with zipfile.ZipFile(str(apk)) as zf:
        data = zf.read(member)
    tmp = Path(f"/tmp/a11-s0-{Path(member).name}")
    tmp.write_bytes(data)
    return tmp


def rnhello_registrars(corpus: Path) -> dict:
    """RnHello's x86 libraries: the registerHybrid staging sites and the
    vtable sites, each classified."""
    apk_path = corpus / RNHELLO[1] / RNHELLO[0]
    out: dict[str, list[dict]] = {}
    with zipfile.ZipFile(str(apk_path)) as zf:
        for info in zf.infolist():
            parts = info.filename.split("/")
            if (
                len(parts) != 3
                or parts[0] != "lib"
                or parts[1] != "x86"
                or not parts[2].endswith(".so")
            ):
                continue
            library = parts[2]
            tmp = extract_x86_library(apk_path, info.filename)
            insns, funcs = parse_lines(objdump(tmp, "x86"))
            tmp.unlink(missing_ok=True)
            entries = []
            for i, insn in enumerate(insns):
                # the staging call: X::registerNatives() passing {methods,count}
                if re.search(
                    r"calll\s+0x[0-9a-f]+\s+<.*registerHybridESt16initializer_list.*@plt>",
                    insn["text"],
                ):
                    window = "\n".join(x["text"] for x in insns[max(0, i - 20) : i + 1])
                    memcpy = bool(MEMCPY.search(window))
                    sse_static = bool(SSE_STATIC_LOAD.search(window))
                    stores = len(re.findall(r"movl\s+%e[a-z]{2},\s*-?0x[0-9a-f]+\(%esp\)", window))
                    count = re.findall(r"movl\s+\$0x([0-9a-f]+),\s*-?0x[0-9a-f]+\(%esp\)", window)
                    if memcpy:
                        staging_shape = "memcpy_from_static"
                    elif sse_static:
                        staging_shape = "sse_copy_static"
                    elif stores >= 3:
                        staging_shape = "runtime_built"
                    else:
                        staging_shape = "other"
                    entries.append(
                        {
                            "kind": "staging",
                            "address": hex(insn["address"]),
                            "function": funcs[i],
                            "staging_shape": staging_shape,
                            "count_imm": int(count[-1], 16) if count else None,
                        }
                    )
            for i in vtable_sites(insns, "x86"):
                verdict = classify_site(insns, funcs, i, "x86")
                entries.append(
                    {
                        "kind": "vtable",
                        "address": hex(insns[i]["address"]),
                        "function": funcs[i],
                        **verdict,
                    }
                )
            if entries:
                out[library] = entries
    return out


def map_rows_to_registrars(rows: list[dict], registrars: dict) -> list[dict]:
    """Attach the staging registrar and the registerHybrid instantiation whose
    names name the row's class. A few dex classes name a native class that
    differs by a suffix or prefix (BindingImpl is registered by Binding's
    registrar); the aliases cover the ones RnHello ships."""

    aliases = {
        "BindingImpl": ("Binding",),
        "CompositeReactPackageTurboModuleManagerDelegate": ("TurboModuleManagerDelegate",),
    }
    for row in rows:
        simple = row["class"].rsplit(".", 1)[-1]
        needles = (simple, *aliases.get(simple, ()))
        staging, vtable = [], []
        for library, entries in registrars.items():
            for entry in entries:
                if not any(needle in entry["function"] for needle in needles):
                    continue
                if entry["kind"] == "staging" and "::registerNatives" in entry["function"]:
                    staging.append(
                        {
                            "library": library,
                            **{k: entry[k] for k in ("address", "staging_shape", "count_imm")},
                        }
                    )
                elif entry["kind"] == "vtable" and "registerHybrid" in entry["function"]:
                    vtable.append(
                        {
                            "library": library,
                            **{k: entry[k] for k in ("address", "methods_source", "count_imm")},
                        }
                    )
        row["staging_registrars"] = staging
        row["registerHybrid_sites"] = vtable
    return rows


# -- part (b): the corpus census ----------------------------------------------


def corpus_census(corpus: Path, only_rnhello: bool) -> dict:
    apks = [(RNHELLO[0], RNHELLO[1])]
    if not only_rnhello:
        apks += sorted((p.name, FDROID_DIR) for p in (corpus / FDROID_DIR).glob("*.apk"))
    per_library: dict[str, Counter] = defaultdict(Counter)
    staging_shapes: dict[str, Counter] = defaultdict(Counter)
    volatile_counts: dict[str, int] = Counter()
    sites_detail: dict[str, list] = defaultdict(list)
    for name, tier in apks:
        apk = corpus / tier / name
        if not apk.exists():
            continue
        with zipfile.ZipFile(str(apk)) as zf:
            seen = set()
            for info in zf.infolist():
                parts = info.filename.split("/")
                if len(parts) != 3 or parts[0] != "lib" or not parts[2].endswith(".so"):
                    continue
                abi, library = parts[1], parts[2]
                if (library, abi) in seen or abi not in ABIS:
                    continue
                seen.add((library, abi))
                tmp = extract_x86_library(apk, info.filename)
                insns, funcs = parse_lines(objdump(tmp, abi))
                tmp.unlink(missing_ok=True)
                key = f"{library}@{abi}"
                for i in vtable_sites(insns, abi):
                    verdict = classify_site(insns, funcs, i, abi)
                    per_library[key][verdict["shape"]] += 1
                    if verdict["count_imm"] is None:
                        volatile_counts[key] += 1
                    if verdict["shape"] == "runtime_built":
                        sites_detail[key].append(
                            {"address": hex(insns[i]["address"]), "function": funcs[i][:120]}
                        )
                # The fbjni/reactnative chains stage (methods, count) in the
                # registrar and make the vtable call in a shared callee, so
                # the runtime tables of those families count at the staging
                # call instead.
                for i, insn in enumerate(insns):
                    if not re.search(
                        r"call[lq]?\s+0x[0-9a-f]+\s+<.*registerHybridESt16initializer_list.*@plt>",
                        insn["text"],
                    ):
                        continue
                    window = "\n".join(x["text"] for x in insns[max(0, i - 20) : i + 1])
                    if MEMCPY.search(window):
                        shape = "staging_memcpy_from_static"
                    elif SSE_STATIC_LOAD.search(window):
                        shape = "staging_sse_copy_static"
                    elif (
                        len(
                            re.findall(
                                r"mov[lq]?\s+(?:%[er][a-z0-9]+|\$0x[0-9a-f]+),\s*-?0x[0-9a-f]+\(%[er]?sp\)",
                                window,
                            )
                        )
                        >= 3
                    ):
                        shape = "staging_runtime_built"
                    else:
                        shape = "staging_other"
                    staging_shapes[key][shape] += 1
    return {
        "shapes_per_library": {k: dict(v) for k, v in sorted(per_library.items())},
        "staging_shapes_per_library": {k: dict(v) for k, v in sorted(staging_shapes.items())},
        "sites_without_immediate_count": dict(volatile_counts),
        "runtime_built_sites": {k: v for k, v in sites_detail.items()},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--json", type=Path, default=None)
    parser.add_argument("--rnhello-only", action="store_true")
    args = parser.parse_args(argv)

    print(f"objdump oracle: {OBJDUMP}")
    print("== (a) RnHello x86: the 22 ambiguous rows and their registrar chains")
    join = rnhello_rows(args.corpus)
    print(json.dumps(join["counts"]))
    registrars = rnhello_registrars(args.corpus)
    staging_shapes: Counter = Counter()
    vtable_shapes: Counter = Counter()
    for entries in registrars.values():
        for entry in entries:
            if entry["kind"] == "staging":
                staging_shapes[entry["staging_shape"]] += 1
            else:
                vtable_shapes[entry["shape"]] += 1
    print(f"  staging shapes: {json.dumps(dict(staging_shapes))}")
    print(f"  vtable shapes: {json.dumps(dict(vtable_shapes))}")
    rows = map_rows_to_registrars(join["rows"], registrars)
    mapped = sum(1 for row in rows if row["staging_registrars"] or row["registerHybrid_sites"])
    print(f"  {len(rows)} x86 ambiguous rows; {mapped} map to a named registrar chain")
    for row in rows:
        print(
            f"    {row['class'].rsplit('.', 1)[-1]}.{row['name']}: "
            + (
                f"staging={row['staging_registrars'][0]['staging_shape']}"
                if row["staging_registrars"]
                else "no-staging"
            )
            + " | "
            + (
                f"vtable methods={row['registerHybrid_sites'][0]['methods_source']}"
                if row["registerHybrid_sites"]
                else "no-vtable-site"
            )
        )

    print("== (b) corpus census of RegisterNatives site shapes")
    census = corpus_census(args.corpus, args.rnhello_only)
    runtime_total: Counter = Counter()
    shape_totals: dict[str, Counter] = defaultdict(Counter)
    staging_totals: dict[str, Counter] = defaultdict(Counter)
    for key, shapes_counts in census["shapes_per_library"].items():
        library, abi = key.rsplit("@", 1)
        for shape, n in shapes_counts.items():
            shape_totals[abi][shape] += n
        if shapes_counts.get("runtime_built"):
            runtime_total[(abi, family_of(library))] += shapes_counts["runtime_built"]
    for key, shapes_counts in census["staging_shapes_per_library"].items():
        library, abi = key.rsplit("@", 1)
        for shape, n in shapes_counts.items():
            staging_totals[abi][shape] += n
        if shapes_counts.get("staging_runtime_built"):
            runtime_total[(abi, family_of(library))] += shapes_counts["staging_runtime_built"]
    for abi in ABIS:
        print(f"  {abi} vtable:   {json.dumps(dict(shape_totals.get(abi, {})))}")
        print(f"  {abi} staging: {json.dumps(dict(staging_totals.get(abi, {})))}")
    print("  runtime-built registrations per (abi, family) [vtable sites + staging sites]:")
    for (abi, family), count in sorted(runtime_total.items()):
        print(f"    {abi} / {family}: {count}")
    print("  libraries with runtime-built vtable sites:")
    for key in sorted(census["runtime_built_sites"]):
        print(f"    {key}: {len(census['runtime_built_sites'][key])} sites")

    report = {
        "objdump": OBJDUMP,
        "rnhello_counts": join["counts"],
        "rnhello_x86_rows": rows,
        "rnhello_x86_registrars": registrars,
        "census": census,
    }
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=1, default=str) + "\n")
        print(f"wrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
