#!/usr/bin/env python3
"""A5 E0 — JNI surface probe: blint's facts next to the NDK/SDK oracles.

For every input (``.so``, ``.dex`` or ``.apk``) this prints, and checks
against named tools run in the same invocation:

- the ``Java_*`` dynamic exports and their decoded
  ``(class, method, signature?)`` per the JNI specification's
  "Resolving Native Method Names" (Java SE 24): ``Java_`` + escaped
  binary name (``/`` -> ``_``) + ``_`` + escaped name, plus
  ``__`` + escaped parameter descriptors when the declaration is
  overloaded; escapes ``_1`` ``_``, ``_2`` ``;``, ``_3`` ``[``,
  ``_0wxyz`` any other non-alphanumeric-ASCII UTF-16 unit. A ``Java_``
  export that does not decode is reported with ``decode_error``, never
  dropped.
- ``JNI_OnLoad`` / ``JNI_OnUnload`` presence;
- the dex ``native`` methods (access flag 0x100);
- the join between the two sides: bound, unbound dex natives, and
  exported JNI functions with no dex declaration;
- ``System.loadLibrary`` call sites (dex) mapped to ``lib<name>.so``.

Oracles: ``llvm-nm -D --defined-only`` for the export set (from the NDK,
resolved like native_probe.py), ``dexdump -d`` for access flags (from the
SDK build-tools). The dex side also runs LIEF the way blint's
``parse_dex`` does, so the LIEF-vs-dexdump agreement is itself checked.
Exit code is non-zero on any disagreement.

What blint already has (recorded here for the E1/E2 packets): exports
come from ``parse()`` metadata, dex methods from LIEF
``DEX.File.methods`` (``access_flags`` carries ACC_NATIVE), the dex
callgraph node id is the method-pool index (``dalvik_callgraph.py``),
``System.loadLibrary`` is reached by the method review rule
``review_methods_android.yml`` (``Ljava/lang/System;->loadLibrary``), and
an ``apk-so-member`` unit's ``container`` block (runners.py) ties each
``.so`` to its ``(app, abi, library)``.

Usage:
  poetry run python tests/scripts/android/jni_probe.py <apk|so|dex>... \
      [--llvm-bin DIR] [--sdk-bin DIR] [--json PATH]
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

ACC_NATIVE = 0x0100  # dex format spec, method access flags

# Escapes per the JNI spec table (Java SE 24). The reverse mapping is
# positional: _1 _, _2 ;, _3 [, _0wxyz U+wxyz (lowercase hex).
_ESCAPES = {"1": "_", "2": ";", "3": "["}
_HEX4_RE = re.compile(r"^[0-9a-f]{4}$")
_DESCRIPTOR_START = "L[BCSIJFDZ"


class ProbeError(Exception):
    """The probe could not run (missing tools, unparsable input)."""


def resolve_tool(name: str, explicit: str | None, candidates: list[Path]) -> Path:
    """First existing tool among --flag/env/candidates/PATH."""
    if explicit:
        path = Path(explicit) / name
        if path.exists():
            return path
        raise ProbeError(f"{name} not found under {explicit}")
    found = shutil.which(name)
    if found:
        return Path(found)
    for directory in candidates:
        path = directory / name
        if path.exists():
            return path
    raise ProbeError(f"{name} not found; pass --llvm-bin/--sdk-bin or install it on PATH")


def llvm_bin_candidates() -> list[Path]:
    """NDK prebuilt bin dirs, newest NDK first (native_probe.py's order)."""
    out: list[Path] = []
    for root in (Path.home() / "Android" / "sdk",):
        ndk_root = root / "ndk"
        if ndk_root.is_dir():
            for ndk in sorted(ndk_root.iterdir(), reverse=True):
                for prebuilt in (ndk / "toolchains" / "llvm" / "prebuilt").glob("*"):
                    out.append(prebuilt / "bin")
    return out


def sdk_bin_candidates() -> list[Path]:
    return sorted((Path.home() / "Android" / "sdk" / "build-tools").glob("*"), reverse=True)


def run_tool(tool: Path, args: list[str]) -> str:
    proc = subprocess.run([str(tool), *args], capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise ProbeError(f"{tool.name} failed ({proc.returncode}): {proc.stderr[-300:]}")
    return proc.stdout


# ------------------------------------------------------------ name decoding


def _unescape(
    text: str, bare_underscore: str, *, strict_bare: bool = False
) -> tuple[str, str | None]:
    """Decode one escaped component; ``bare_underscore`` is what a plain
    ``_`` means there (``/`` for class names and descriptors). Method names
    never carry a bare ``_`` (a literal underscore encodes as ``_1``), so
    ``strict_bare`` makes one a decode error instead."""
    out: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char != "_":
            out.append(char)
            index += 1
            continue
        if index + 1 >= len(text):
            return "".join(out), "trailing_escape"
        nxt = text[index + 1]
        if nxt in _ESCAPES:
            out.append(_ESCAPES[nxt])
            index += 2
        elif nxt == "0":
            hex4 = text[index + 2 : index + 6]
            if not _HEX4_RE.match(hex4):
                return "".join(out), f"bad_unicode_escape_at_{index}"
            out.append(chr(int(hex4, 16)))
            index += 6
        elif strict_bare:
            return "".join(out), "bare_underscore_in_method_name"
        else:
            out.append(bare_underscore)
            index += 1
    return "".join(out), None


def _valid_param_descriptors(text: str) -> bool:
    """True when ``text`` is a concatenation of field descriptors."""
    index, depth = 0, 0
    seen = 0
    while index < len(text):
        char = text[index]
        if char == "[":
            index += 1
            depth += 1
            if depth > 255:
                return False
            continue
        if char == "L":
            end = text.find(";", index)
            if end < 0:
                return False
            index = end + 1
        elif char in "BCSIJFDZ":
            index += 1
        else:
            return False
        seen += 1
        depth = 0
    return True


def decode_jni_symbol(symbol: str) -> dict:
    """Decode one ``Java_*`` export name into (class, method, signature?).

    The class/method separator is the last ``_`` that does not start an
    escape, and the overload suffix is the first ``__`` whose tail decodes
    to a valid parameter-descriptor run - the two rules that make the
    spec's encoding reversible for every name the spec can produce
    (literal ``_`` encodes as ``_1``, so a bare ``__`` can only be the
    suffix, except when the tail is not a descriptor, which is then the
    ``class _ method-_`` shape).
    """
    if not symbol.startswith("Java_"):
        return {"symbol": symbol, "decode_error": "missing_Java_prefix"}
    rest = symbol[len("Java_") :]

    def attempt(text: str) -> dict:
        head, sep, tail = text.partition("__")
        cut = -1
        for index in range(len(head) - 1):
            if head[index] == "_" and (index + 1 >= len(head) or head[index + 1] not in "0123"):
                cut = index
        if head.endswith("_"):
            cut = len(head) - 1
        if cut < 1 or cut + 1 >= len(head):
            return {"symbol": symbol, "decode_error": "no_class_method_separator"}
        mangled_class, mangled_method = head[:cut], head[cut + 1 :]
        class_name, class_err = _unescape(mangled_class, "/")
        method_name, method_err = _unescape(mangled_method, "", strict_bare=True)
        if method_err:
            return {"symbol": symbol, "decode_error": method_err}
        if class_err:
            return {"symbol": symbol, "decode_error": class_err}
        result = {
            "symbol": symbol,
            "class": class_name.replace("/", "."),
            "method": method_name,
        }
        if sep:
            signature, sig_err = _unescape(tail, "/")
            if sig_err or not _valid_param_descriptors(signature):
                return {"symbol": symbol, "decode_error": f"bad_signature_suffix_{tail}"}
            result["signature"] = signature
        return result

    primary = attempt(rest)
    # A `__` whose tail is not a descriptor is the `_` + `_1`-escape shape:
    # retry as a plain class_method split before reporting a decode error.
    if "decode_error" in primary and "__" in rest:
        fallback = attempt(rest.replace("__", "_11", 1))
        if "decode_error" not in fallback:
            return fallback
    return primary


# ------------------------------------------------------------------ oracles


def oracle_nm_exports(nm: Path, so: Path) -> set[str]:
    """Defined dynamic symbols from llvm-nm -D --defined-only."""
    out = run_tool(nm, ["-D", "--defined-only", str(so)])
    names = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1] in ("T", "W", "t", "w"):
            names.add(parts[-1])
    return names


def oracle_dexdump_natives(dexdump: Path, dex: Path) -> list[dict]:
    """``{class, name, descriptor}`` for every ACC_NATIVE method."""
    out = run_tool(dexdump, ["-d", str(dex)])
    natives: list[dict] = []
    current_class = ""
    method: dict | None = None
    for line in out.splitlines():
        stripped = line.strip()
        match = re.match(r"^Class descriptor\s*:\s*'([^']+)'$", stripped)
        if match:
            current_class = match.group(1)
            continue
        match = re.match(r"^name\s*:\s*'(.*)'$", stripped)
        if match and method is None:
            method = {"name": match.group(1)}
            continue
        match = re.match(r"^type\s*:\s*'(.*)'$", stripped)
        if match and method is not None and "descriptor" not in method:
            method["descriptor"] = match.group(1)
            continue
        match = re.match(r"^access\s*:\s*(0x[0-9a-fA-F]+)", stripped)
        if match and method is not None and "descriptor" in method:
            if int(match.group(1), 16) & ACC_NATIVE:
                method["class"] = current_class
                natives.append(method)
            method = None
            continue
        if stripped.startswith(("Direct method", "Virtual method", "Class #")):
            method = None
    return natives


def oracle_dexdump_load_library(dexdump: Path, dex: Path) -> list[dict]:
    """``System.loadLibrary`` invoke sites with their declaring method."""
    out = run_tool(dexdump, ["-d", str(dex)])
    sites: list[dict] = []
    method_header = re.compile(r"^name\s*:\s*'([^']+)'")
    current = ""
    for line in out.splitlines():
        stripped = line.strip()
        header = method_header.match(stripped)
        if header:
            current = header.group(1)
        if "Ljava/lang/System;.loadLibrary:" in line:
            sites.append({"method": current, "line": stripped[:120]})
    return sites


# ------------------------------------------------------------------ blint side


def blint_so_java_exports(so: Path) -> tuple[set[str], set[str]]:
    """(all defined export names, Java_*/JNI_On* names) from parse()."""
    from blint.lib.binary import parse

    metadata = parse(str(so))
    names: set[str] = set()
    for key in ("exports", "dynamic_symbols"):
        for entry in metadata.get(key) or []:
            name = entry.get("name") or ""
            if name:
                names.add(name)
    jni_names = {n for n in names if n.startswith("Java_") or n in ("JNI_OnLoad", "JNI_OnUnload")}
    return names, jni_names


# str() of a LIEF dex type is the descriptor for class types
# (``Ljava/lang/String;``) but pretty for primitives and arrays (``int``,
# ``int[]``); ``value`` is the PRIMITIVES enum and ``dim`` the array depth.
_PRIMITIVE_LETTERS = {
    "VOID": "V",
    "BOOLEAN": "Z",
    "BYTE": "B",
    "SHORT": "S",
    "CHAR": "C",
    "INT": "I",
    "LONG": "J",
    "FLOAT": "F",
    "DOUBLE": "D",
}


def lief_type_descriptor(t) -> str:
    """One LIEF dex type as its JVM descriptor (``I``, ``[I``, ``L...;``)."""
    try:
        dim = int(t.dim or 0)
    except (AttributeError, TypeError, RuntimeError):
        dim = 0
    try:
        value = t.value
    except (AttributeError, TypeError, RuntimeError):
        value = None
    if value is not None:
        base = _PRIMITIVE_LETTERS[str(value).split(".")[-1].upper()]
    else:
        rendered = str(t)
        base = rendered if rendered.startswith("L") and rendered.endswith(";") else None
        if base is None:
            try:
                return "[" * dim + lief_type_descriptor(t.underlying_array_type)
            except (AttributeError, TypeError, RuntimeError):
                return rendered
    return "[" * dim + base


def blint_dex_natives(dex: Path) -> list[dict]:
    """Native methods via LIEF exactly as parse_dex materializes them.

    This LIEF exposes ``access_flags`` as a list of ACCESS_FLAGS enums
    (some builds return the raw int bitmask); both forms are accepted and
    the NATIVE membership is what matters.
    """
    import lief

    dexfile = lief.DEX.parse(str(dex))
    if dexfile is None or isinstance(dexfile, lief.lief_errors):
        raise ProbeError(f"LIEF could not parse {dex}")
    natives = []

    def _is_native(flags) -> bool:
        if isinstance(flags, int):
            return bool(flags & ACC_NATIVE)
        return any("NATIVE" in str(flag).upper() for flag in flags or [])

    for method in dexfile.methods:
        try:
            if not _is_native(method.access_flags):
                continue
            owner = method.cls.fullname if method.has_class else ""
            proto = method.prototype
            params = "".join(lief_type_descriptor(t) for t in proto.parameters_type)
            ret = lief_type_descriptor(proto.return_type)
            natives.append(
                {"class": owner, "name": str(method.name), "descriptor": f"({params}){ret}"}
            )
        except (AttributeError, RuntimeError, TypeError):
            continue
    return natives


# ----------------------------------------------------------------- the join


def decode_join(export_names: set[str], dex_natives: list[dict]) -> dict:
    """Static half of the dex <-> native join.

    A dex native binds to the decoded export of its class and method name;
    when the dex class overloads the name, or the export carries one, the
    export's decoded parameter descriptors must equal the dex method's
    parameter descriptors (the spec's ``__<sig>`` suffix carries exactly
    those). Exports with no declaration are the undeclared list; dex
    natives with no export are unbound (dynamic registration, another
    library, or missing).
    """
    decoded = [decode_jni_symbol(n) for n in sorted(export_names if export_names else set())]
    decoded = [d for d in decoded if d["symbol"].startswith("Java_")]

    def _dotted(cls: str) -> str:
        if cls.startswith("L") and cls.endswith(";"):
            cls = cls[1:-1]
        return cls.replace("/", ".")

    def _params(descriptor: str) -> str:
        end = descriptor.find(")")
        return descriptor[1:end] if descriptor.startswith("(") and end > 0 else descriptor

    name_counts: dict[tuple[str, str], int] = {}
    for native in dex_natives:
        name_counts[(_dotted(native["class"]), native["name"])] = (
            name_counts.get((_dotted(native["class"]), native["name"]), 0) + 1
        )
    bound: list[dict] = []
    used: set[str] = set()
    unbound: list[dict] = []
    for native in dex_natives:
        cls = _dotted(native["class"])
        overloaded = name_counts[(cls, native["name"])] > 1
        candidates = [
            d
            for d in decoded
            if "decode_error" not in d and d["class"] == cls and d["method"] == native["name"]
        ]
        chosen = None
        if overloaded:
            # An overloaded name needs the __<sig> form: match parameters.
            chosen = next(
                (d for d in candidates if d.get("signature") == _params(native["descriptor"])),
                None,
            )
        else:
            chosen = next((d for d in candidates if "signature" not in d), None) or next(
                (d for d in candidates if d.get("signature") == _params(native["descriptor"])),
                None,
            )
        if chosen:
            used.add(chosen["symbol"])
            bound.append({**native, "class": cls, "symbol": chosen["symbol"]})
        else:
            unbound.append({**native, "class": cls})
    undeclared = [d for d in decoded if "decode_error" not in d and d["symbol"] not in used] + [
        d for d in decoded if "decode_error" in d
    ]
    return {"bound": bound, "unbound_dex_natives": unbound, "undeclared_exports": undeclared}


# ------------------------------------------------------------------- driver


def probe_so(so: Path, nm: Path) -> dict:
    """One .so: decoded exports vs llvm-nm -D, OnLoad/OnUnload presence."""
    oracle = oracle_nm_exports(nm, so)
    blint_names, _ = blint_so_java_exports(so)
    java_exports = sorted(n for n in oracle if n.startswith("Java_"))
    decoded = [decode_jni_symbol(n) for n in java_exports]
    report = {
        "input": str(so),
        "kind": "so",
        "java_exports": decoded,
        "on_load": "JNI_OnLoad" in oracle,
        "on_unload": "JNI_OnUnload" in oracle,
        "oracle_export_count": len(oracle),
        "blint_export_count": len(blint_names),
        "diffs": [],
    }
    blint_jni = {
        n for n in blint_names if n.startswith("Java_") or n in ("JNI_OnLoad", "JNI_OnUnload")
    }
    oracle_jni = set(java_exports) | {n for n in ("JNI_OnLoad", "JNI_OnUnload") if n in oracle}
    if blint_jni != oracle_jni:
        report["diffs"].append(
            f"blint JNI names differ from llvm-nm -D: only-blint={sorted(blint_jni - oracle_jni)} "
            f"only-nm={sorted(oracle_jni - blint_jni)}"
        )
    return report


def probe_dex(dex: Path, dexdump: Path) -> dict:
    """One dex: LIEF natives vs dexdump, plus loadLibrary call sites."""
    lief_natives = blint_dex_natives(dex)
    oracle = oracle_dexdump_natives(dexdump, dex)

    def normalize(entries: list[dict]) -> list[tuple]:
        return sorted((e["class"], e["name"], e["descriptor"]) for e in entries)

    report = {
        "input": str(dex),
        "kind": "dex",
        "dex_natives": normalize(oracle),
        "lief_natives": normalize(lief_natives),
        "load_library_sites": oracle_dexdump_load_library(dexdump, dex),
        "diffs": [],
    }
    if report["dex_natives"] != report["lief_natives"]:
        report["diffs"].append(
            "LIEF native methods differ from dexdump: "
            f"only-lief={sorted(set(report['lief_natives']) - set(report['dex_natives']))} "
            f"only-dexdump={sorted(set(report['dex_natives']) - set(report['lief_natives']))}"
        )
    return report


def probe_apk(apk: Path, nm: Path, dexdump: Path) -> dict:
    """One apk: per-ABI .so surfaces + the dex, then the join per ABI."""
    so_reports: list[dict] = []
    dex_report = None
    join_by_abi: dict[str, dict] = {}
    export_names_by_lib: dict[str, set[str]] = {}
    with tempfile.TemporaryDirectory(prefix="jni_probe_") as tmp:
        with zipfile.ZipFile(apk) as zf:
            members = zf.namelist()
            for member in members:
                if member == "classes.dex" or (
                    member.startswith("lib/") and member.endswith(".so")
                ):
                    target = Path(tmp) / member.replace("/", "__")
                    target.write_bytes(zf.read(member))
        for member in members:
            if member == "classes.dex":
                dex_report = probe_dex(Path(tmp) / "classes.dex", dexdump)
            elif member.startswith("lib/") and member.endswith(".so"):
                path = Path(tmp) / member.replace("/", "__")
                so_report = probe_so(path, nm)
                so_report["entry"] = member
                abi = member.split("/")[1]
                so_report["abi"] = abi
                so_reports.append(so_report)
                export_names_by_lib[f"{abi}:{member}"] = {
                    e["symbol"] for e in so_report["java_exports"]
                }
        dex_natives = dex_report["dex_natives"] if dex_report else []
        # dexdump classes are L-descriptors; decode_join renders dotted names.
        natives = [
            {
                "class": c[1:-1] if c.startswith("L") else c,
                "name": n,
                "descriptor": d,
            }
            for c, n, d in dex_natives
        ]
        for lib_key, exports in sorted(export_names_by_lib.items()):
            join_by_abi[lib_key] = decode_join(exports, natives)
    return {
        "input": str(apk),
        "kind": "apk",
        "so_reports": so_reports,
        "dex": dex_report,
        "join": join_by_abi,
        "diffs": [d for r in so_reports for d in r["diffs"]]
        + (dex_report["diffs"] if dex_report else []),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("inputs", nargs="+", type=Path, help=".so, .dex or .apk files")
    parser.add_argument("--llvm-bin", help="directory with llvm-nm")
    parser.add_argument("--sdk-bin", help="directory with dexdump")
    parser.add_argument("--json", type=Path, help="write the full report JSON here")
    args = parser.parse_args(argv)

    try:
        nm = resolve_tool("llvm-nm", args.llvm_bin, llvm_bin_candidates())
        dexdump = resolve_tool("dexdump", args.sdk_bin, sdk_bin_candidates())
        reports = []
        for path in args.inputs:
            suffix = path.suffix.lower()
            if suffix == ".so":
                reports.append(probe_so(path, nm))
            elif suffix == ".dex":
                reports.append(probe_dex(path, dexdump))
            elif suffix in (".apk", ".apks", ".xapk", ".aab"):
                reports.append(probe_apk(path, nm, dexdump))
            else:
                raise ProbeError(f"unsupported input {path} (want .so/.dex/.apk)")
    except (ProbeError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    for report in reports:
        print(f"== jni probe: {report['input']}")
        if report["kind"] == "so":
            for entry in report["java_exports"]:
                sig = entry.get("signature")
                if "decode_error" in entry:
                    print(
                        f"  Java_ export  {entry['symbol']}  DECODE_ERROR {entry['decode_error']}"
                    )
                else:
                    print(f"  Java_ export  {entry['symbol']}")
                    print(
                        f"      -> {entry['class']}#{entry['method']}"
                        + (f" sig({sig})" if sig else "")
                    )
            print(f"  JNI_OnLoad={report['on_load']} JNI_OnUnload={report['on_unload']}")
        elif report["kind"] == "dex":
            for cls, name, desc in report["dex_natives"]:
                print(f"  dex native    {cls}->{name}{desc}")
            for site in report["load_library_sites"]:
                print(f"  loadLibrary   in {site['method']}")
        else:
            for so_report in report["so_reports"]:
                print(
                    f"  lib {so_report['entry']}: {len(so_report['java_exports'])} Java_ exports, "
                    f"OnLoad={so_report['on_load']}"
                )
            if report["dex"]:
                for cls, name, desc in report["dex"]["dex_natives"]:
                    print(f"  dex native    {cls}->{name}{desc}")
            for lib_key, join in report["join"].items():
                print(f"  join {lib_key}:")
                for b in join["bound"]:
                    print(f"    bound         {b['class']}#{b['name']} <- {b['symbol']}")
                for u in join["unbound_dex_natives"]:
                    print(f"    unbound dex   {u['class']}#{u['name']}{u['descriptor']}")
                for u in join["undeclared_exports"]:
                    label = (
                        u["symbol"]
                        if "decode_error" not in u
                        else f"{u['symbol']} (!{u['decode_error']})"
                    )
                    print(f"    undeclared    {label}")
        for diff in report["diffs"]:
            print(f"  DIFF: {diff}")
    all_diffs = sum(len(r["diffs"]) for r in reports)
    print(f"jni probe: {len(reports)} inputs, {all_diffs} disagreements")
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(reports, indent=2, sort_keys=True, default=str) + "\n")
    return 0 if all_diffs == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
