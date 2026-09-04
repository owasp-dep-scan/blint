"""Toolchain and provenance inference from binary evidence.

``exe_type`` tries to answer "what is this binary" with one string, and issue
#114 is the symptom: it is being asked to carry language, platform and
architecture at once. The honest fix is a separate ``toolchain`` block built
from evidence the binary cannot help but carry:

- ``.comment`` sections name the compiler and version outright (ELF).
- ``LC_BUILD_VERSION`` tool entries name clang, ld and swift (Mach-O).
- Symbol-version requirements name glibc; musl admits it via the interpreter.
- Runtime symbol signatures: Go's ``runtime.*`` tree, Rust's ``.rustc``
  section and mangled names, Swift's ``swift_`` stdlib symbols, Objective-C's
  ``objc_*`` trampolines.
- PE link versions plus CRT fingerprints separate MSVC from MinGW.

Every signal carries its source and a confidence. When signals disagree, both
are reported — attribution that explains itself beats a confident guess.
"""

import re

# Runtime symbol prefixes that identify a language runtime. Compact on
# purpose: each prefix names a family of thousands of symbols, so one hit is
# already strong evidence.
GO_RUNTIME_PREFIXES = ("runtime.", "internal/cpu.", "sync/atomic.")
# `_ZN` alone is Itanium C++ mangling, not Rust: every C++ binary would
# match. Rust's legacy mangling appends the `17h<16 hex>E` digest, and v0
# starts with `_R` followed by a mangling letter.
RUST_LEGACY_HASH = re.compile(r"17h[0-9a-f]{16}E")
RUST_V0 = re.compile(r"^_R[A-Za-z]")
SWIFT_SYMBOL_PREFIXES = ("swift_", "_swift_")
OBJC_SYMBOL_SUBSTRINGS = ("objc_msgSend", "objc_retain", "objc_release", "_objc_")

# MSVC CRT and MinGW fingerprints.
MSVC_CRT_SYMBOLS = ("__scrt_common_main_seh", "__security_init_cookie", "_CRT_INIT")
MINGW_SYMBOLS = ("__mingw_get_crt_info", "__mingw_raise_matherr", "pei386_runtime_relocator")

_GCC_VERSION = re.compile(r"(?:gcc|GCC)[^\d]*([0-9]+\.[0-9]+\.[0-9]+)")
_CLANG_VERSION = re.compile(r"(?:clang|Apple[ ]clang)[^\d]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.IGNORECASE)
_RUSTC_VERSION = re.compile(r"rustc[ ]version[ ]([0-9a-f.]+)", re.IGNORECASE)
_LLD_VERSION = re.compile(r"LLD[ ]([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.IGNORECASE)


def _extract_comment_compilers(comment_content: str) -> list[dict]:
    """Pull compiler identities out of an ELF ``.comment`` section."""
    compilers = []
    seen = set()
    for chunk in comment_content.split("\x00"):
        chunk = chunk.strip()
        if not chunk or chunk in seen:
            continue
        seen.add(chunk)
        lowered = chunk.lower()
        if "lld " in lowered or lowered.startswith("lld"):
            compilers.append(
                {
                    "name": "lld",
                    "version": _LLD_VERSION.search(chunk).group(1)
                    if _LLD_VERSION.search(chunk)
                    else "",
                    "source": ".comment",
                    "confidence": "medium",
                }
            )
            continue
        if match := _CLANG_VERSION.search(chunk):
            name = "apple-clang" if "apple" in lowered else "clang"
            compilers.append(
                {"name": name, "version": match.group(1), "source": ".comment", "confidence": "high"}
            )
        elif match := _GCC_VERSION.search(chunk):
            compilers.append(
                {
                    "name": "gcc",
                    "version": match.group(1),
                    "source": ".comment",
                    "confidence": "high",
                }
            )
        elif "glibc" in lowered or "gnu" in lowered:
            compilers.append(
                {"name": "gnu-linker", "version": "", "source": ".comment", "confidence": "medium"}
            )
    return compilers


def _symbol_names(metadata: dict) -> list[str]:
    """Collect symbol names from the metadata buckets, capped for speed."""
    names: list[str] = []
    for key in ("symtab_symbols", "dynamic_symbols", "functions", "exports"):
        entries = metadata.get(key) or []
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if isinstance(entry, dict):
                name = entry.get("name") or entry.get("short_name")
                if isinstance(name, str) and name:
                    names.append(name)
        if len(names) > 200_000:
            break
    return names


def infer_toolchain(metadata: dict) -> dict:
    """Infer the toolchain block from already-parsed metadata.

    Runs on every format; each signal contributes only what its format
    actually carries, so a result with a single low-confidence signal is
    possible and is reported as such rather than padded with guesses.
    """
    compilers: list[dict] = []
    runtimes: list[dict] = []
    libc = None

    # --- compilers ------------------------------------------------------
    comment_content = (metadata.get("build_info") or {}).get("compiler_version") or ""
    if comment_content:
        compilers.extend(_extract_comment_compilers(comment_content))
        # Rust toolchains leave a rustc banner in .comment even when the code
        # itself was clang-compiled.
        if _RUSTC_VERSION.search(comment_content) and not any(
            c["name"] == "rustc" for c in compilers
        ):
            version = _RUSTC_VERSION.search(comment_content).group(1)
            compilers.append(
                {
                    "name": "rustc",
                    "version": version,
                    "source": ".comment",
                    "confidence": "high",
                }
            )
    linkers: list[dict] = []
    for tool in metadata.get("tools") or []:
        if not isinstance(tool, dict):
            continue
        tool_name = str(tool.get("tool", "")).lower()
        if "ld" in tool_name:
            # The linker is provenance, not a compiler; keep the distinction
            # honest instead of filing `ld` among the compilers.
            linkers.append(
                {
                    "name": tool_name,
                    "version": tool.get("version", ""),
                    "source": "LC_BUILD_VERSION",
                    "confidence": "medium",
                }
            )
        elif "clang" in tool_name or "swift" in tool_name:
            compilers.append(
                {
                    "name": tool_name,
                    "version": tool.get("version", ""),
                    "source": "LC_BUILD_VERSION",
                    "confidence": "high",
                }
            )
    linker_version = metadata.get("major_linker_version")
    if isinstance(linker_version, int):
        compilers.append(
            {
                "name": "link",
                "version": f"{linker_version}.{metadata.get('minor_linker_version', 0)}",
                "source": "pe_optional_header",
                "confidence": "medium",
            }
        )

    # --- libc ------------------------------------------------------------
    for version_entry in metadata.get("symbols_version") or []:
        if not isinstance(version_entry, dict):
            continue
        name = str(version_entry.get("name", ""))
        if name.startswith("GLIBC_"):
            libc = "glibc"
            break
        if "musl" in name.lower():
            libc = "musl"
            break
    if metadata.get("is_musl"):
        libc = "musl"
    if libc:
        runtimes.append({"name": libc, "source": "symbol_versions" if not metadata.get("is_musl") else "interpreter", "confidence": "high"})

    # --- language runtimes ------------------------------------------------
    if metadata.get("go_dependencies") or metadata.get("go_formulation"):
        runtimes.append({"name": "go", "source": "buildinfo", "confidence": "high"})
    if metadata.get("rust_dependencies"):
        runtimes.append({"name": "rust", "source": "buildinfo", "confidence": "high"})

    names = _symbol_names(metadata)
    found = {"go": False, "rust": False, "swift": False, "objc": False, "msvc": False, "mingw": False}
    for name in names:
        if not found["go"] and name.startswith(GO_RUNTIME_PREFIXES):
            found["go"] = True
        elif not found["rust"] and (
            RUST_V0.match(name) or (name.startswith("_ZN") and RUST_LEGACY_HASH.search(name))
        ):
            found["rust"] = True
        elif not found["swift"] and name.startswith(SWIFT_SYMBOL_PREFIXES):
            found["swift"] = True
        elif not found["objc"] and any(sub in name for sub in OBJC_SYMBOL_SUBSTRINGS):
            found["objc"] = True
        elif not found["msvc"] and any(sym in name for sym in MSVC_CRT_SYMBOLS):
            found["msvc"] = True
        elif not found["mingw"] and any(sym in name for sym in MINGW_SYMBOLS):
            found["mingw"] = True
        if all(found.values()):
            break

    if found["go"]:
        runtimes.append({"name": "go", "source": "runtime_symbols", "confidence": "high"})
    if found["rust"]:
        runtimes.append({"name": "rust", "source": "mangled_symbols", "confidence": "medium"})
    if found["swift"]:
        runtimes.append({"name": "swift", "source": "runtime_symbols", "confidence": "high"})
    if found["objc"]:
        runtimes.append({"name": "objective-c", "source": "runtime_symbols", "confidence": "high"})
    if found["msvc"]:
        runtimes.append({"name": "msvc-crt", "source": "crt_symbols", "confidence": "high"})
    if found["mingw"]:
        runtimes.append({"name": "mingw-crt", "source": "crt_symbols", "confidence": "high"})
    if metadata.get("is_dotnet"):
        runtimes.append({"name": "dotnet", "source": "pe_header", "confidence": "high"})

    # Dedupe runtimes by (name, source), keeping confidence ordering stable.
    seen = set()
    deduped = []
    for runtime in sorted(runtimes, key=lambda item: (item["name"], item["source"])):
        key = (runtime["name"], runtime["source"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(runtime)

    return {
        "compilers": compilers,
        "linkers": linkers,
        "runtimes": deduped,
        "libc": libc,
    }
