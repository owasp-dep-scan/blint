#!/usr/bin/env python3
"""Extract the R1 identification-evidence JSONs (H0's committed fixtures).

Rule 39: corpus binaries are never committed; the extracted evidence is.
For one corpus library per framework this writes ``tests/data/android/
<framework>-evidence.json`` holding exactly the inputs blint's framework
detectors consume (blint.lib.framework_ident), in the shape they read
them: the note facts, the demangled symbol names that carry the symbol-set
evidence, and the matched evidence strings. The llvm tools that confirm
the same bytes in the same run (ground rule 29) are recorded per file with
their command and version.

The JSON is consumed by the R1 tests so the detectors run against real
corpus evidence without the corpus. Regenerate with the same command
recorded in each file when the corpus changes.

Usage (one invocation per framework library):
  poetry run python tests/scripts/android/extract_identification_evidence.py \
      --apk <path.apk> --member lib/arm64-v8a/libhermes.so \
      --framework react-native [--hbc-member assets/index.android.bundle]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]

HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
DART_VERSION_RE = re.compile(
    r"^\d+\.\d+\.\d+(?:\.\d+)? \([a-z]+\) \([^)]+\) on \"[a-z0-9_]+\"$"
)
RN_RELEASE_RE = re.compile(r"^for RN \d+\.\d+\.\S+$")
NSS_VERSION_RE = re.compile(r"^Version: NSS \d+\.\d+(?:\.\d+)*$")
VLC_VERSION_RE = re.compile(r"^VLC \d+\.\d+\.\d+$")
QT_VERSION_RE = re.compile(r"^Qt \d+\.\d+\.\d+ \(")
OPENSSL_BANNER_RE = re.compile(r"^OpenSSL \d+\.\d+\.\d+[a-z]* [A-Za-z]+ +\d+ \d{4}$")

# The symbol-set evidence, as parse()'s demangled names spell them.
SYMBOL_EVIDENCE_RE = re.compile(
    r"^(?:std::__ndk1::|facebook::jni::|BORINGSSL_|InternalFlutterGpu_)"
    r"|^_kDart|NSS_VersionCheck|^operator new"
)


def default_ndk_tool(tool: str) -> str:
    """An NDK llvm tool, preferring the newest NDK under ~/Android/sdk."""
    sdks = os.path.expanduser("~/Android/sdk/ndk")
    if os.path.isdir(sdks):
        for ndk in sorted(os.listdir(sdks), reverse=True):
            candidate = os.path.join(
                sdks, ndk, "toolchains", "llvm", "prebuilt", "darwin-x86_64",
                "bin", tool,
            )
            if os.path.exists(candidate):
                return candidate
    return tool


def run_tool(tool: str, args: list[str]) -> list[str]:
    result = subprocess.run(
        [tool, *args], capture_output=True, text=True, check=False
    )
    return (result.stdout or "").splitlines()


def read_member(apk: str, member: str, workdir: str) -> str:
    """Extract one member to workdir and return its path."""
    target = os.path.join(workdir, os.path.basename(member))
    if apk.endswith((".apk", ".apks", ".apkm", ".xapk")):
        with zipfile.ZipFile(apk) as z:
            names = [n for n in z.namelist() if n.endswith(member)]
            if not names:
                raise SystemExit(f"{member} not found in {apk}")
            with open(target, "wb") as fh:
                fh.write(z.read(names[0]))
    else:
        target = apk
    return target


def extract(path: str, tools: dict) -> dict:
    """The detector inputs, cross-checked against the llvm tools' own read."""
    from blint.lib.binary import parse

    metadata = parse(path)  # the same parse() call the detectors run inside
    # parse()'s strings list is entropy-gated, so the version evidence is
    # read from the same LIEF source the detectors use, unevaluated.
    from blint.lib.binary_common import binary_strings
    raw_strings = [s for s in binary_strings(
        __import__("lief").ELF.parse(path)) if isinstance(s, str)]

    def matched(pattern: re.Pattern) -> list[str]:
        return [s.strip() for s in raw_strings if pattern.match(s.strip())]

    symbol_names = [s.get("name") for s in (metadata.get("dynamic_symbols") or [])
                    if s.get("name")]
    exported_names = [
        s.get("name") for s in (metadata.get("dynamic_symbols") or [])
        if s.get("name") and s.get("is_exported")
    ]
    # llvm-nm -D --demangle, defined-only: the oracle read of the same set.
    nm_lines = run_tool(tools["nm"], ["-D", "--demangle", "--defined-only", path])
    oracle_symbols = [
        line.split(" ", 2)[-1].strip() for line in nm_lines
        if line.strip() and not line.startswith("//")
    ]
    oracle_matched = [s for s in oracle_symbols if SYMBOL_EVIDENCE_RE.match(s)]

    notes = metadata.get("notes") or []
    ident_notes = [
        {k: n.get(k) for k in ("type", "sdk_version", "ndk_version",
                               "ndk_build_number")}
        for n in notes if n.get("type") == "ANDROID_IDENT"
    ]

    return {
        "blint_parse": {
            "android_ident": (metadata.get("android") or {}).get("android_ident"),
            "ident_notes": ident_notes,
            "symbol_evidence": {
                "matched_names": sorted({
                    n for n in symbol_names if SYMBOL_EVIDENCE_RE.match(n)
                })[:200],
                "matched_count": sum(
                    1 for n in symbol_names if SYMBOL_EVIDENCE_RE.match(n)
                ),
                "dynamic_symbols_total": len(symbol_names),
                # Explicit flags so an R1 fixture never depends on the
                # matched_names cap.
                "ndk1_namespace": any(n.startswith("std::__ndk1::") for n in symbol_names),
                "operator_new_exported": any(
                    n.startswith("operator new") for n in exported_names
                ),
                "facebook_jni_namespace": any(
                    n.startswith("facebook::jni::") for n in symbol_names
                ),
                "boringssl_prefix": any(
                    n.startswith("BORINGSSL_") for n in symbol_names
                ),
                "flutter_gpu_symbols": any(
                    n.startswith("InternalFlutterGpu_") for n in symbol_names
                ),
                "dart_snapshot_symbols": any(
                    n.startswith("_kDart") for n in symbol_names
                ),
                "nss_version_check": any(n == "NSS_VersionCheck" for n in symbol_names),
            },
            "string_evidence": {
                "dart_vm_version": matched(DART_VERSION_RE),
                "rn_release": matched(RN_RELEASE_RE),
                "nss_version": matched(NSS_VERSION_RE),
                "vlc_version": matched(VLC_VERSION_RE),
                "qt_version": matched(QT_VERSION_RE),
                "openssl_banner": matched(OPENSSL_BANNER_RE),
                "hex40_bare": sorted(set(matched(HEX40_RE))),
                "boringssl_bare": sorted({
                    s for s in raw_strings if s.strip().lower() == "boringssl"
                }),
                "fbjni_uninitialized": sorted({
                    s.strip() for s in raw_strings
                    if "fbjni is uninitialized" in s
                }),
                "raw_strings_scanned": len(raw_strings),
            },
        },
        "oracle_llvm": {
            "nm_matched_symbols": sorted(set(oracle_matched))[:200],
            "nm_matched_count": len(oracle_matched),
            "strings_dart_or_banner": [
                s for s in run_tool(tools["strings"], [path])
                if DART_VERSION_RE.match(s.strip())
                or RN_RELEASE_RE.match(s.strip())
                or NSS_VERSION_RE.match(s.strip())
                or VLC_VERSION_RE.match(s.strip())
                or QT_VERSION_RE.match(s.strip())
                or OPENSSL_BANNER_RE.match(s.strip())
            ],
            "readelf_notes_android_ident": [
                line.strip() for line in run_tool(tools["readelf"], ["-n", path])
                if "ANDROID" in line or "description data" in line
            ][:8],
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--apk", required=True, help="APK (or bare .so) holding the library")
    parser.add_argument("--member", required=True, help="zip member path, e.g. lib/arm64-v8a/libhermes.so")
    parser.add_argument("--framework", required=True, help="framework key for the output file")
    parser.add_argument("--out", help="output JSON path (default tests/data/android/<framework>-evidence.json)")
    parser.add_argument("--hbc-member", help="optional Hermes bundle member for the header bytes")
    args = parser.parse_args()

    tools = {
        "strings": default_ndk_tool("llvm-strings"),
        "nm": default_ndk_tool("llvm-nm"),
        "readelf": default_ndk_tool("llvm-readelf"),
    }
    tool_versions = {
        os.path.basename(path): (run_tool(path, ["--version"]) or ["?"])[0]
        for path in tools.values()
    }

    out_path = Path(
        args.out
        or REPO / "tests" / "data" / "android" / f"{args.framework}-evidence.json"
    )
    with tempfile.TemporaryDirectory(prefix="blint_ident_evidence") as workdir:
        lib = read_member(args.apk, args.member, workdir)
        data = Path(lib).read_bytes()
        result = {
            "framework": args.framework,
            "source": {"apk": os.path.basename(args.apk), "member": args.member},
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
            "extraction": {
                "tools": tool_versions,
                "commands": [
                    f"{os.path.basename(tools['strings'])} {args.member}",
                    f"{os.path.basename(tools['nm'])} -D --demangle --defined-only {args.member}",
                    f"{os.path.basename(tools['readelf'])} -n {args.member}",
                    "blint parse() over the same extracted file (framework_ident inputs)",
                ],
            },
            "evidence": extract(lib, tools),
        }
        if args.hbc_member:
            with zipfile.ZipFile(args.apk) as z:
                hbc = z.read(args.hbc_member)
            result["hbc_header"] = {
                "member": args.hbc_member,
                # BytecodeFileFormat.h: MAGIC = 0x1F1903C103BC1FC6, then the
                # u32 BYTECODE_VERSION (include/hermes/BCGen/HBC/).
                "magic_hex": hbc[:8].hex(),
                "bytecode_version": int.from_bytes(hbc[8:12], "little"),
                "sha256": hashlib.sha256(hbc).hexdigest(),
            }
    out_path.write_text(json.dumps(result, indent=2) + "\n")
    print(f"wrote {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
