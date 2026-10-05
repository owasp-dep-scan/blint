#!/usr/bin/env python3
"""A14 W0 - the unbound census, the other groups, and the A0 baseline re-run.

Measure only; no production change. Three answers:

(a) The unbound census. Every unbound row of every corpus APK, every ABI,
    binned by whether the method name equals an exported defined FUNC in
    exactly one same-ABI library, several, or none. For the matching bins
    the row's declaring class carries the dex evidence W1's join needs:
    whether the class (or a method its ``<clinit>`` runs) invokes
    ``com.sun.jna.Native.register``, which overload, whether the library
    name reaches the call as a constant (directly, or as the constant the
    invoked helper returns), and whether ``libjnidispatch.so`` ships for
    that ABI. The JNA version the APK ships is read from the dex
    (``Native.main``'s version constant and the ``<clinit>`` native
    revision check).

(b) The other groups. glean, ``androidx.graphics.path``, Qt5 and
    netty/jansi: the registrar shape (dexdump of the declaring class's
    init, ``llvm-nm``/``llvm-objdump`` of the library that would implement
    them), one representative per shape, and the reason the row is unbound
    today. For glean, where its implementation lives.

(c) The A0.3 baseline re-run on this tree, the "before" for W2's
    close-out table: standalone findings per tier (tier-0 median, any
    high or critical), SBOM components per tier-2 app, JNI join counts
    per ABI with and without the confirmers, and wall time and peak RSS
    of the default analysis with and without ``--disassemble``.

Usage (from the a14 tree):
  poetry run python tests/scripts/android/a14_w0_census.py \
      --corpus ~/sandbox/android-corpus --phase all --json /tmp/a14-w0.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

NM = "/opt/homebrew/opt/llvm@18/bin/llvm-nm"
OBJDUMP = "/opt/homebrew/opt/llvm@18/bin/llvm-objdump"
DEXDUMP = str(Path.home() / "Android/sdk/build-tools/36.0.0/dexdump")
BSD_TIME = "/usr/bin/time"

DEX_NAME_RE = re.compile(r"^classes\d*\.dex$")
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")

# The corpus APKs: tier 2 (F-Droid), tier 3 (framework builds), tier 1's
# app fixtures and tier 4's hostile zips (the join-bearing ones; the
# tier-4 refuse-and-cap cases are listed so their refusals stay visible).
TIER_DIRS = ("tier2-fdroid", "tier3-frameworks", "tier1-ndk/apks", "tier4-hostile")

# The groups the prompt names, keyed by a declaring-class prefix test.
GROUP_MATCHERS = {
    "glean": lambda cls: "glean" in cls.lower(),
    "androidx.graphics.path": lambda cls: cls.startswith("androidx.graphics.path"),
    "qt5": lambda cls: cls.startswith("org.qtproject.qt"),
    "netty": lambda cls: cls.startswith("io.netty"),
    "jansi": lambda cls: cls.startswith("org.fusesource.jansi"),
    "uniffi": lambda cls: cls.startswith(
        ("uniffi.", "mozilla.appservices", "org.matrix.rustcomponents")
    ),
    "soloader": lambda cls: "soloader" in cls.lower(),
    "yoga": lambda cls: ".yoga" in cls or cls.startswith("com.facebook.yoga"),
    "maplibre": lambda cls: cls.startswith("org.maplibre"),
    "react-native": lambda cls: cls.startswith("com.facebook."),
}


def corpus_apks(corpus: Path) -> list[Path]:
    out: list[Path] = []
    for tier in TIER_DIRS:
        base = corpus / tier
        if not base.is_dir():
            continue
        out.extend(sorted(base.glob("*.apk")))
        out.extend(sorted(base.glob("*.xapk")))
    return out


# ------------------------------------------------------------ join plumbing


def join_for(apk: Path, confirm: bool) -> dict | None:
    import blint.lib.jni as jni_module
    from blint.lib.android_native import scan_android_native

    native = scan_android_native(str(apk))
    if not (native.get("libraries") or []):
        return None
    original = jni_module.JOIN_LISTING_CAP
    jni_module.JOIN_LISTING_CAP = 10**6
    try:
        return jni_module.build_jni_join_summary(str(apk), native, confirm_findclass=confirm)
    finally:
        jni_module.JOIN_LISTING_CAP = original


def exported_function_names(apk: Path, native: dict) -> dict[str, dict[str, set[str]]]:
    """Per ABI: ``{exported FUNC name: {library names}}`` over the app's own
    copies (ground rule 36 - one map per ABI, never a shared one)."""
    import lief

    from blint.lib.android_native import LibraryReader
    from blint.lib.binary_common import parse_symbols

    per_abi: dict[str, dict[str, set[str]]] = {}
    parsed_names: dict[tuple[str, str], set[str]] = {}
    with LibraryReader(str(apk)) as reader:
        for lib in native.get("libraries") or []:
            name = lib.get("name") or ""
            if not name or lib.get("not_elf"):
                continue
            for loc in lib.get("locations") or []:
                abi = loc.get("abi")
                if not abi or (name, abi) in parsed_names:
                    continue
                data = reader.read(loc)
                if not data:
                    continue
                parsed = lief.ELF.parse(data)
                if parsed is None or isinstance(parsed, lief.lief_errors):
                    continue
                entries, _ = parse_symbols(parsed.dynamic_symbols)
                names = {
                    entry["name"]
                    for entry in entries or []
                    if isinstance(entry, dict)
                    and entry.get("name")
                    and not entry.get("is_imported")
                    and (entry.get("is_function") or entry.get("type") == "FUNC")
                }
                parsed_names[(name, abi)] = names
                exports = per_abi.setdefault(abi, {})
                for export in names:
                    exports.setdefault(export, set()).add(name)
    return per_abi


def jnidispatch_abis(native: dict) -> set[str]:
    return {
        loc.get("abi")
        for lib in native.get("libraries") or []
        if lib.get("name") == "libjnidispatch.so"
        for loc in lib.get("locations") or []
        if loc.get("abi")
    }


# ------------------------------------------------------- JNA dex evidence


def _method_key(method) -> str:
    """A dex method rendered the way DexPools renders pool entries."""
    try:
        owner = method.cls.fullname if method.has_class else ""
        proto = method.prototype
        params = "".join(str(p) for p in proto.parameters_type)
        return f"{owner}->{method.name}({params}){proto.return_type}"
    except (AttributeError, RuntimeError, TypeError):
        return ""


def _string_argument(instructions, invoke_index: int) -> tuple[str | None, str | None]:
    """The constant that reaches the register call's String argument:
    ``(constant, helper)`` - the const-string at the call itself, or the
    invoke whose returned value reaches it (its own constant is read
    separately, by ``_helper_constant``)."""
    from blint.lib.dalvik_semantics import is_invoke

    invoke = instructions[invoke_index]
    reaching: dict[int, tuple[str, str | None]] = {}
    pending_invoke: str | None = None
    for inst in instructions[:invoke_index]:
        if is_invoke(inst) and inst.target:
            pending_invoke = str(inst.target)
        elif inst.name in ("const-string", "const-string/jumbo") and inst.target is not None:
            if inst.registers:
                reaching[inst.registers[0]] = ("const", inst.target)
        elif inst.name in ("move-result-object", "move-result") and inst.registers:
            reaching[inst.registers[0]] = ("result", pending_invoke)
    for reg in reversed(invoke.registers or []):
        kind, value = reaching.get(reg, (None, None))
        if kind == "const":
            return value, None
        if kind == "result":
            return None, value
    return None, None


def _helper_constant(
    methods_by_key: dict[str, object],
    helper: str | None,
    pools_cache,
    depth: int = 2,
) -> str | None:
    """The one constant a helper returns, when exactly one const-string
    flows into its ``return-object`` (uniffi's findLibraryName fallback).
    An accessor that just returns another method's result is followed."""
    if not helper or depth < 0:
        return None
    method = methods_by_key.get(helper)
    if method is None:
        return None
    from blint.lib.dalvik import disassemble_method
    from blint.lib.dalvik_semantics import is_invoke

    try:
        instructions = disassemble_method(method, pools_cache)
    except Exception:
        return None
    reaching: dict[int, str] = {}
    pending_invoke: str | None = None
    constants: set[str] = set()
    tail_calls: set[str] = set()
    for inst in instructions:
        if is_invoke(inst) and inst.target:
            pending_invoke = str(inst.target)
        elif inst.name in ("const-string", "const-string/jumbo") and inst.target is not None:
            if inst.registers:
                reaching[inst.registers[0]] = inst.target
        elif inst.name in ("move-result-object", "move-result") and inst.registers:
            reaching.pop(inst.registers[0], None)
            if pending_invoke:
                tail_calls.add(pending_invoke)
        elif inst.name == "return-object" and inst.registers:
            value = reaching.get(inst.registers[0])
            if value is not None:
                constants.add(value)
    if len(constants) == 1:
        return next(iter(constants))
    for tail in tail_calls:
        result = _helper_constant(methods_by_key, tail, pools_cache, depth - 1)
        if result is not None:
            return result
    return None


def jna_evidence(apk: Path) -> dict:
    """JNA evidence from the app's dex: the version constants, and per
    declaring class every ``Native.register`` call the class's ``<clinit>``
    runs - directly or through a method the ``<clinit>`` invokes."""
    import lief

    from blint.lib.dalvik import DexPools, disassemble_method
    from blint.lib.dalvik_semantics import is_invoke

    evidence: dict[str, list[dict]] = {}
    version: dict[str, str] = {}
    with zipfile.ZipFile(str(apk)) as zf:
        for name in [n for n in zf.namelist() if DEX_NAME_RE.match(n)]:
            dexp = lief.DEX.parse(list(zf.read(name)))
            if dexp is None or isinstance(dexp, lief.lief_errors):
                continue
            methods = list(dexp.methods)
            if not methods:
                continue
            pools = DexPools.from_dex(dexp)
            methods_by_key: dict[str, object] = {}
            register_indices: set[int] = set()
            for index, method in enumerate(methods):
                key = _method_key(method)
                if key:
                    methods_by_key.setdefault(key, method)
                try:
                    if (
                        index <= 0xFFFF
                        and str(method.name) == "register"
                        and method.has_class
                        and method.cls.fullname == "Lcom/sun/jna/Native;"
                    ):
                        register_indices.add(index)
                except (AttributeError, RuntimeError, TypeError):
                    continue
            if not register_indices:
                continue
            patterns = [index.to_bytes(2, "little") for index in register_indices]
            # every method whose bytecode names a register index
            callers: dict[str, list[dict]] = {}
            for method in methods:
                bytecode = getattr(method, "bytecode", None)
                if not bytecode:
                    continue
                raw = bytes(bytecode)
                if not any(pattern in raw for pattern in patterns):
                    continue
                try:
                    instructions = disassemble_method(method, pools)
                except Exception:
                    continue
                for position, inst in enumerate(instructions):
                    if not (is_invoke(inst) and inst.target):
                        continue
                    target = str(inst.target)
                    if "com/sun/jna/Native;->register" not in target:
                        continue
                    caller = ""
                    try:
                        caller = method.cls.fullname if method.has_class else ""
                    except (AttributeError, RuntimeError, TypeError):
                        pass
                    if not caller:
                        continue
                    constant, helper = _string_argument(instructions, position)
                    if constant is None and helper:
                        constant = _helper_constant(methods_by_key, helper, pools)
                    callers.setdefault(caller, []).append(
                        {
                            "method": str(method.name),
                            "target": target.split("->", 1)[1],
                            "constant": constant,
                            "helper": helper,
                        }
                    )
            # the JNA version constants: Native.main prints the Java
            # version; Native.<clinit> checks the jnidispatch revision
            for method in methods:
                try:
                    if not method.has_class or method.cls.fullname != "Lcom/sun/jna/Native;":
                        continue
                except (AttributeError, RuntimeError, TypeError):
                    continue
                if not getattr(method, "bytecode", None):
                    continue
                try:
                    for inst in disassemble_method(method, pools):
                        if (
                            inst.name in ("const-string", "const-string/jumbo")
                            and inst.target
                            and VERSION_RE.match(inst.target)
                        ):
                            version[str(method.name)] = inst.target
                except Exception:
                    continue
            for caller, sites in callers.items():
                evidence.setdefault(caller, []).extend(sites)
            # evidence a <clinit> reaches only through a method it runs
            for method in methods:
                try:
                    if str(method.name) != "<clinit>" or not method.has_class:
                        continue
                    owner = method.cls.fullname
                except (AttributeError, RuntimeError, TypeError):
                    continue
                bytecode = getattr(method, "bytecode", None)
                if not bytecode or owner in evidence:
                    continue
                try:
                    instructions = disassemble_method(method, pools)
                except Exception:
                    continue
                ran: set[str] = set()
                for inst in instructions:
                    if is_invoke(inst) and inst.target:
                        ran.add(str(inst.target))
                for target in ran:
                    for helper_owner, sites in callers.items():
                        if helper_owner == owner:
                            continue
                        if any(
                            target.startswith(f"{helper_owner}->{site['method']}(")
                            or target == f"{helper_owner}->{site['method']}"
                            for site in sites
                        ):
                            for site in sites:
                                entry = dict(site)
                                entry["via"] = f"<clinit> -> {target}"
                                evidence.setdefault(owner, []).append(entry)
    return {"version": version, "register_classes": evidence}


# ------------------------------------------------------------ part (a)


def _dotted(descriptor: str) -> str:
    if descriptor.startswith("L") and descriptor.endswith(";"):
        descriptor = descriptor[1:-1]
    return descriptor.replace("/", ".")


def family_of(row_class: str) -> str:
    parts = row_class.split(".")
    return ".".join(parts[:3]) if len(parts) > 3 else row_class.rsplit(".", 1)[0]


def part_a(corpus: Path, report: dict) -> None:
    from blint.lib.android_native import scan_android_native

    print("== (a) the unbound census")
    census: dict[str, dict] = {}
    for apk in corpus_apks(corpus):
        native = scan_android_native(str(apk))
        if not (native.get("libraries") or []):
            continue
        confirm_join = join_for(apk, confirm=True)
        if not confirm_join or not confirm_join.get("per_abi"):
            census[apk.name] = {"join": None}
            continue
        exports = exported_function_names(apk, native)
        dispatch = jnidispatch_abis(native)
        entry: dict = {
            "jna": jna_evidence(apk),
            "jnidispatch_abis": sorted(dispatch),
            "abis": {},
        }
        evidence_classes = {_dotted(cls) for cls in entry["jna"]["register_classes"]}
        for abi, abi_join in sorted(confirm_join["per_abi"].items()):
            rows = abi_join.get("unbound_dex_natives") or []
            bins = Counter()
            families: dict[str, Counter] = defaultdict(Counter)
            multi_detail: list[dict] = []
            matched_evidence = 0
            for row in rows:
                libs = (exports.get(abi) or {}).get(row["name"])
                if not libs:
                    bins["none"] += 1
                    families[family_of(row["class"])]["none"] += 1
                    continue
                if len(libs) == 1:
                    bins["unique"] += 1
                    families[family_of(row["class"])]["unique"] += 1
                else:
                    bins["multi"] += 1
                    families[family_of(row["class"])]["multi"] += 1
                    if len(multi_detail) < 16:
                        multi_detail.append({"name": row["name"], "libraries": sorted(libs)})
                if row["class"] in evidence_classes:
                    matched_evidence += 1
            entry["abis"][abi] = {
                "counts": abi_join.get("counts"),
                "bins": dict(bins),
                "families": {name: dict(counts) for name, counts in sorted(families.items())},
                "multi_detail": multi_detail,
                "unique_rows_with_register_evidence": matched_evidence,
            }
            print(
                f"   {apk.name} {abi}: unbound {len(rows)}"
                f" = unique {bins['unique']} / multi {bins['multi']} / none {bins['none']}"
                f" (register evidence on {matched_evidence} of the matching rows;"
                f" jnidispatch {'shipped' if abi in dispatch else 'absent'})"
            )
        census[apk.name] = entry
    report["a_census"] = census


# ------------------------------------------------------------ part (b)


def _read_member(apk: Path, member: str) -> bytes:
    with zipfile.ZipFile(str(apk)) as zf:
        return zf.read(member)


def _lib_members(apk: Path, abi: str) -> dict[str, str]:
    """{library name: zip member} for one ABI (split APKs: first wins)."""
    members: dict[str, str] = {}
    with zipfile.ZipFile(str(apk)) as zf:
        for info in zf.infolist():
            parts = info.filename.split("/")
            if (
                len(parts) == 3
                and parts[0] == "lib"
                and parts[1] == abi
                and parts[2].endswith(".so")
            ):
                members.setdefault(parts[2], info.filename)
    return members


def _dex_dump_class(apk: Path, class_descriptor: str) -> str:
    """dexdump of one declaring class (its natives and its init code)."""
    if not class_descriptor:
        return "(no declaring class)"
    with tempfile.TemporaryDirectory() as td:
        for name in [n for n in zipfile.ZipFile(str(apk)).namelist() if DEX_NAME_RE.match(n)]:
            dex_path = Path(td) / name
            dex_path.write_bytes(_read_member(apk, name))
            proc = subprocess.run(
                [DEXDUMP, "-l", "plain", str(dex_path)],
                capture_output=True,
                timeout=600,
            )
            # dexdump echoes raw string-pool bytes; they are not UTF-8
            text = proc.stdout.decode("utf-8", errors="replace")
            quoted = f"'{class_descriptor}'"
            if quoted in text:
                start = text.index(quoted)
                # the dump starts at the class header line above the descriptor
                head = text.rfind("Class #", 0, start)
                start = head if head >= 0 else start
                stop = text.find("Class #", start + 8)
                return text[start : stop if stop > 0 else len(text)]
    return "(class not found)"


def _nm_defined(path: Path, pattern: str) -> list[str]:
    proc = subprocess.run(
        [NM, "-D", "--defined-only", str(path)],
        capture_output=True,
        text=True,
        timeout=600,
    )
    return [
        line.split()[-1]
        for line in proc.stdout.splitlines()
        if pattern in line and line.split()[-1]
    ]


def part_b(corpus: Path, report: dict) -> None:
    print("== (b) the other groups")
    groups: dict[str, dict] = {}

    # glean (fennec): the registrar shape and where the implementation lives
    fennec = corpus / "tier2-fdroid/org.mozilla.fennec_fdroid_1560020.apk"
    if fennec.exists():
        join = join_for(fennec, confirm=True) or {}
        glean_rows: list[dict] = []
        for abi, abi_join in sorted((join.get("per_abi") or {}).items()):
            for row in abi_join.get("unbound_dex_natives") or []:
                if "glean" in row["class"].lower():
                    glean_rows.append({**row, "abi": abi})
        classes = sorted({row["class"] for row in glean_rows})
        from blint.lib.android_native import scan_android_native

        native_scan = scan_android_native(str(fennec))
        exports = exported_function_names(fennec, native_scan) if native_scan else {}
        answering: Counter = Counter()
        for row in glean_rows:
            for lib in (exports.get(row["abi"]) or {}).get(row["name"]) or ():
                answering[lib] += 1
        members = _lib_members(fennec, "arm64-v8a")
        megazord = members.get("libmegazord.so")
        glean_exports: list[str] = []
        if megazord:
            with tempfile.TemporaryDirectory() as td:
                so = Path(td) / "libmegazord.so"
                so.write_bytes(_read_member(fennec, megazord))
                glean_exports = sorted(
                    set(_nm_defined(so, "glean")) | set(_nm_defined(so, "Glean"))
                )
        groups["glean"] = {
            "rows": len(glean_rows),
            "abis": sorted({row["abi"] for row in glean_rows}),
            "declaring_classes": classes,
            "example_methods": sorted({row["name"] for row in glean_rows})[:8],
            "answering_libraries": dict(answering),
            "megazord_glean_exports": glean_exports[:12],
            "megazord_glean_export_count": len(glean_exports),
            "clinit": _dex_dump_class(fennec, "L" + classes[0].replace(".", "/") + ";")[:2400]
            if classes
            else "",
        }
        print(
            f"   glean: {len(glean_rows)} rows over {len(classes)} classes;"
            f" answered by {dict(answering)};"
            f" libmegazord exports {len(glean_exports)} glean-named symbols"
        )

    # androidx.graphics.path (every Compose app): the 8 rows and the
    # library's own surface
    newpipe = corpus / "tier2-fdroid/org.schabi.newpipe_1015.apk"
    if newpipe.exists():
        join = join_for(newpipe, confirm=True) or {}
        axrows: list[dict] = []
        for abi, abi_join in sorted((join.get("per_abi") or {}).items()):
            for row in abi_join.get("unbound_dex_natives") or []:
                if row["class"].startswith("androidx.graphics.path"):
                    axrows.append({**row, "abi": abi})
        members = _lib_members(newpipe, "arm64-v8a")
        exports: list[str] = []
        member = members.get("libandroidx.graphics.path.so")
        if member:
            with tempfile.TemporaryDirectory() as td:
                so = Path(td) / "libandroidx.graphics.path.so"
                so.write_bytes(_read_member(newpipe, member))
                exports = _nm_defined(so, "")
                proc = subprocess.run(
                    [OBJDUMP, "-d", "--no-show-raw-insn", str(so)],
                    capture_output=True,
                    text=True,
                    timeout=900,
                )
                jni_on_load = next(
                    (line.strip() for line in proc.stdout.splitlines() if "JNI_OnLoad" in line),
                    "",
                )
        groups["androidx.graphics.path"] = {
            "rows": len(axrows),
            "abis": sorted({row["abi"] for row in axrows}),
            "declaring_classes": sorted({row["class"] for row in axrows}),
            "methods": sorted({row["name"] for row in axrows}),
            "library_export_count": len(exports),
            "java_exports": [e for e in exports if e.startswith("Java_")][:12],
            "plain_exports_named_like_methods": [
                e for e in exports if e in {r["name"] for r in axrows}
            ],
            "jni_on_load_line": jni_on_load,
            "clinit": _dex_dump_class(
                newpipe, "Landroidx/graphics/path/PathIteratorPreApi34Impl;"
            )[:2000],
        }
        print(
            f"   androidx.graphics.path: {len(axrows)} rows;"
            f" library exports {len(exports)} symbols"
            f" ({len([e for e in exports if e.startswith('Java_')])} Java_*)"
        )

    # Qt5 (osmand)
    osmand = corpus / "tier2-fdroid/net.osmand.plus_540403.apk"
    if osmand.exists():
        join = join_for(osmand, confirm=True) or {}
        qt_rows: list[dict] = []
        for abi, abi_join in sorted((join.get("per_abi") or {}).items()):
            for row in abi_join.get("unbound_dex_natives") or []:
                if row["class"].startswith("org.qtproject.qt"):
                    qt_rows.append({**row, "abi": abi})
        classes = sorted({row["class"] for row in qt_rows})
        counts = Counter(row["abi"] for row in qt_rows)
        groups["qt5"] = {
            "rows": len(qt_rows),
            "rows_per_abi": dict(counts),
            "declaring_classes": classes,
            "example_methods": sorted({row["name"] for row in qt_rows})[:8],
            "clinit": _dex_dump_class(osmand, "L" + classes[0].replace(".", "/") + ";")[:2000]
            if classes
            else "",
        }
        print(f"   qt5: {len(qt_rows)} rows over {len(classes)} classes ({dict(counts)})")

    # netty + jansi (vlc): no implementing library ships
    vlc = corpus / "tier2-fdroid/org.videolan.vlc_13070108.apk"
    if vlc.exists():
        join = join_for(vlc, confirm=True) or {}
        netty_rows: list[dict] = []
        for abi, abi_join in sorted((join.get("per_abi") or {}).items()):
            for row in abi_join.get("unbound_dex_natives") or []:
                if row["class"].startswith(("io.netty", "org.fusesource.jansi")):
                    netty_rows.append({**row, "abi": abi})
        by_family = Counter(row["class"].rsplit(".", 1)[0] for row in netty_rows)
        groups["netty_jansi"] = {
            "rows": len(netty_rows),
            "rows_per_abi": dict(Counter(row["abi"] for row in netty_rows)),
            "families": dict(by_family.most_common()),
        }
        # the actual registrar shape: the native-declaring class's init
        registrar = next(
            (
                row["class"]
                for row in netty_rows
                if row["class"].startswith("io.netty.channel.unix")
            ),
            netty_rows[0]["class"] if netty_rows else "",
        )
        if registrar:
            descriptor = "L" + registrar.replace(".", "/") + ";"
            groups["netty_jansi"]["registrar_class"] = registrar
            groups["netty_jansi"]["clinit"] = _dex_dump_class(vlc, descriptor)[:2400]
        print(
            f"   netty/jansi: {len(netty_rows)} rows"
            f" ({dict(Counter(row['abi'] for row in netty_rows))}); registrar {registrar}"
        )
    report["b_groups"] = groups


# ------------------------------------------------------------ part (c)


def phase_standalone(corpus: Path) -> dict:
    """A0.3's standalone phase re-run, plus per-severity counts."""
    out: dict = {"groups": {}}
    tier0 = corpus / "tier0-system"
    tier1 = corpus / "tier1-ndk"
    groups: dict[str, list[Path]] = defaultdict(list)
    if tier0.exists():
        for d in sorted(tier0.iterdir()):
            if d.is_dir():
                groups[f"tier0/{d.name}"].append(d)
    if tier1.exists():
        for ndk in sorted(tier1.iterdir()):
            if ndk.is_dir() and ndk.name not in ("apks",):
                for abi in sorted(ndk.iterdir()):
                    if abi.is_dir():
                        groups[f"tier1/{ndk.name}/{abi.name}"].append(abi)
    blint_bin = os.environ.get("A14_BLINT_BIN") or str(REPO / ".venv" / "bin" / "blint")
    with tempfile.TemporaryDirectory() as td:
        for label, dirs in groups.items():
            so_files = [so for d in dirs for so in sorted(d.rglob("*.so"))]
            if not so_files:
                continue
            staging = Path(td) / re.sub(r"[^0-9a-zA-Z_.-]", "_", label)
            staging.mkdir(parents=True, exist_ok=True)
            for i, so in enumerate(so_files):
                (staging / f"{so.stem}__{i}{so.suffix}").symlink_to(so)
            reports = Path(td) / (staging.name + "-reports")
            subprocess.run(
                [
                    blint_bin,
                    "-q",
                    "--no-banner",
                    "--no-reviews",
                    "-i",
                    str(staging),
                    "-o",
                    str(reports),
                ],
                capture_output=True,
                text=True,
                timeout=7200,
            )
            findings = []
            ffile = next(reports.glob("*findings*.json"), None)
            if ffile:
                try:
                    findings = json.loads(ffile.read_text()).get("findings", [])
                except ValueError:
                    findings = []
            per_rule = Counter(f.get("id") for f in findings)
            per_severity = Counter(f.get("severity") for f in findings)
            per_file = Counter(
                Path(f.get("filename", "")).name.rsplit("__", 1)[0] + ".so" for f in findings
            )
            counts = sorted(per_file.values())
            out["groups"][label] = {
                "scanned": len(so_files),
                "files_with_findings": len({f.get("filename") for f in findings}),
                "findings_total": len(findings),
                "median_per_file": counts[len(counts) // 2] if counts else 0,
                "severity": dict(per_severity),
                "per_rule": dict(sorted(per_rule.items())),
            }
            print(
                f"   {label}: median {out['groups'][label]['median_per_file']},"
                f" severity {dict(per_severity)}"
            )
    return out


def phase_sbom(corpus: Path) -> dict:
    out: dict = {"apps": []}
    hex_version = re.compile(r"^[0-9a-fA-F]{16,64}$")
    blint_bin = os.environ.get("A14_BLINT_BIN") or str(REPO / ".venv" / "bin" / "blint")
    with tempfile.TemporaryDirectory() as td:
        for apk in sorted((corpus / "tier2-fdroid").glob("*.apk")):
            out_json = Path(td) / f"{apk.stem}.json"
            proc = subprocess.run(
                [blint_bin, "sbom", "-i", str(apk), "-o", str(out_json), "-q"],
                capture_output=True,
                text=True,
                timeout=3600,
            )
            if proc.returncode != 0 or not out_json.exists():
                out["apps"].append({"app": apk.name, "error": proc.stderr[-300:]})
                continue
            components = json.loads(out_json.read_text()).get("components") or []
            so_components = [
                c
                for c in components
                if str(c.get("purl", "")).startswith("pkg:android/") and c.get("type") == "library"
            ]
            out["apps"].append(
                {
                    "app": apk.name,
                    "components_total": len(components),
                    "so_components": len(so_components),
                    "so_build_id_versions": sum(
                        1 for c in so_components if hex_version.match(str(c.get("version") or ""))
                    ),
                }
            )
            print(f"   sbom {apk.name}: {len(components)} components")
    return out


def phase_join_counts(corpus: Path) -> dict:
    """JNI join counts per ABI, with and without the confirmers."""
    out: dict = {}
    for apk in corpus_apks(corpus):
        plain = join_for(apk, confirm=False)
        deep = join_for(apk, confirm=True)
        if not plain and not deep:
            continue
        row = {}
        for mode, join in (("plain", plain), ("confirm", deep)):
            row[mode] = {
                abi: (abi_join or {}).get("counts")
                for abi, abi_join in sorted(((join or {}).get("per_abi") or {}).items())
            }
        out[apk.name] = row
        print(f"   join {apk.name}: {sorted(row['plain'])}")
    return out


def phase_wall_rss(corpus: Path) -> dict:
    """Wall time and peak RSS of the default analysis, with and without
    --disassemble, per tier-2/tier-3 app."""
    blint_bin = os.environ.get("A14_BLINT_BIN") or str(REPO / ".venv" / "bin" / "blint")
    out: dict = {}
    apps = sorted((corpus / "tier2-fdroid").glob("*.apk")) + sorted(
        (corpus / "tier3-frameworks").glob("*.apk")
    )
    with tempfile.TemporaryDirectory() as td:
        for apk in apps:
            for mode, extra in (("default", []), ("disassemble", ["--disassemble"])):
                reports = Path(td) / f"{apk.stem}-{mode}"
                start = time.monotonic()
                proc = subprocess.run(
                    [
                        BSD_TIME,
                        "-l",
                        blint_bin,
                        "-q",
                        "--no-banner",
                        "-i",
                        str(apk),
                        "-o",
                        str(reports),
                        *extra,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=14400,
                )
                wall = time.monotonic() - start
                peak = None
                for line in proc.stderr.splitlines():
                    if "peak memory footprint" in line:
                        peak = int(line.split()[0])
                        break
                out[apk.name] = out.get(apk.name, {})
                out[apk.name][mode] = {
                    "wall_seconds": round(wall, 1),
                    "peak_rss_bytes": peak,
                    "returncode": proc.returncode,
                }
                print(f"   {apk.name} {mode}: {wall:.1f}s peak {peak}")
    return out


def part_c(corpus: Path, report: dict) -> None:
    print("== (c) the A0 baseline re-run")
    report["c_baseline"] = {
        "standalone": phase_standalone(corpus),
        "sbom": phase_sbom(corpus),
        "join_counts": phase_join_counts(corpus),
        "wall_rss": phase_wall_rss(corpus),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--phase", choices=["census", "groups", "baseline", "all"], default="all")
    parser.add_argument("--json", type=Path, default=None)
    args = parser.parse_args(argv)
    report: dict = {
        "tools": {"llvm_nm": NM, "llvm_objdump": OBJDUMP, "dexdump": DEXDUMP},
        "corpus": str(args.corpus),
    }
    if args.phase in ("census", "all"):
        part_a(args.corpus, report)
    if args.phase in ("groups", "all"):
        part_b(args.corpus, report)
    if args.phase in ("baseline", "all"):
        part_c(args.corpus, report)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=1, default=str) + "\n")
        print(f"wrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
