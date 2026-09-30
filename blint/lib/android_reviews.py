"""Native Android capability reviews.

The single-signal form of every family here is common in benign code: crash
handlers and unwinders import ``ptrace`` and read ``/proc/self/maps``, most
libraries read system properties or call ``dlopen``, and GPU backends
compare the hardware name against emulator tokens. So no rule keys on an
import or a bare string. Each is a call-site constant (what a resolved call
receives) or a dex-plus-JNI conjunction.

The call-site constants come from the ``call_site_arguments`` block, which
needs ``--disassemble`` and models arm64 and x86_64 only. Where the block
cannot answer, ``analysis_coverage.degradations`` says why
(``callsite_abi_not_modelled``, ``callsite_entries_truncated``), so an empty
result there is not a clean one.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

# The callees each rule reads and the 0-based argument that carries the
# value (``None``: either argument of a two-string compare).
CALLEE_ARGUMENT_POSITIONS: dict[str, dict[str, int | None]] = {
    "ptrace_request": {"ptrace": 0},
    "path_probe": {
        "open": 0,
        "open64": 0,
        "fopen": 0,
        "fopen64": 0,
        "access": 0,
        "stat": 0,
        "stat64": 0,
        "lstat": 0,
        "lstat64": 0,
    },
    "exec_command": {
        "execve": 0,
        "execv": 0,
        "execl": 0,
        "execle": 0,
        "execlp": 0,
        "execvp": 0,
        "popen": 0,
        "system": 0,
    },
    "property_name": {"__system_property_get": 0, "__system_property_find": 0},
    "load_path": {"dlopen": 0, "android_dlopen_ext": 0, "android_load_sphal": 0},
    "compare_token": {"strcmp": None, "strncmp": None, "strcasecmp": None},
}

PTRACE_TRACEME = 0

# A su path ends in the component "su"; an exec-family command may continue
# after it ("/system/bin/su -c id"). Both need the component boundary, so
# "/system/bin/sum" and "/sudo" do not match.
_SU_PATH_SUFFIX_RE = re.compile(r"(?:^|/)su$")
_SU_COMMAND_RE = re.compile(r"(?:^|/)su(?=$|\s)")
# libc++ ``basic_string::append(char const*)``: a command assembled in a
# std::string before an exec receives it.
_STRING_APPEND_RE = re.compile(r"6appendepkc$")

# Properties that exist only to describe an emulator: reading one by name is
# the check itself. The hardware properties are read everywhere and count
# only beside a goldfish/ranchu comparison.
_QEMU_PROPERTY_NAMES = frozenset(
    {"ro.kernel.qemu", "ro.kernel.qemu.gles", "ro.kernel.qemu1", "ro.boot.qemu"}
)
_EMULATOR_COMPARED_PROPERTIES = frozenset({"ro.hardware", "ro.product.device", "ro.product.board"})
_EMULATOR_TOKEN_RE = re.compile(r"^(?:goldfish|ranchu)$", re.IGNORECASE)

# Shared storage and app-writable locations, matched on whole components.
_WRITABLE_LOAD_PREFIXES = ("/data/local/tmp", "/sdcard", "/storage", "/data/data")

# svc #0 (ARM), syscall and int 0x80 (x86), in every immediate style the
# disassembler can print: decimal, 0x-prefixed and h-suffixed.
_INLINE_SYSCALL_RE = re.compile(
    r"\bsvc\s+#?(?:0x0+|0+h?)\b|\bsyscall\b|\bint\s+(?:0x80|128|80h)\b", re.IGNORECASE
)
# Code that legitimately issues raw syscalls: bionic's own wrappers, the
# sanitizer runtimes' internal_* layer, and the Go runtime.
_BIONIC_LIBC_SONAMES = frozenset({"libc.so", "libc.so.0"})
_SANITIZER_RUNTIME_PREFIX = "libclang_rt."

# The directories scottyab/rootbeer's Const.suPaths lists (0.1.2), without
# the generic mount points (/data, /cache, /dev, /sbin, /system/bin) that
# name nothing on their own.
ROOTBEER_SPECIFIC_SU_DIRECTORIES = frozenset(
    {
        "/data/local/xbin/",
        "/su/bin/",
        "/system/bin/.ext/",
        "/system/bin/failsafe/",
        "/system/sd/xbin/",
        "/system/usr/we-need-root/",
        "/system/xbin/",
        "/system_ext/bin/",
    }
)
# One such directory is an ordinary string; a list of them is a root probe.
MIN_SU_DIRECTORIES = 2


def _callsite_entries(metadata: dict, table_key: str) -> list[dict]:
    """The call-site entries for one callee table, filtered by argument."""
    positions = CALLEE_ARGUMENT_POSITIONS[table_key]
    results = []
    for entry in metadata.get("call_site_arguments") or []:
        callee = str(entry.get("callee") or "").strip().lower()
        if callee not in positions:
            continue
        position = positions[callee]
        if position is None or entry.get("argument") == position:
            results.append(entry)
    return results


def _entry_string(entry: dict) -> str:
    return str(entry.get("string") or "")


def _first_function(entry: dict) -> str | None:
    return (entry.get("functions") or [None])[0]


def _soname_or_basename(metadata: dict) -> str:
    android = metadata.get("android") or {}
    for candidate in (android.get("soname"), metadata.get("name")):
        if candidate:
            return str(candidate).replace("\\", "/").rsplit("/", 1)[-1]
    return ""


def _evaluate_ptrace_traceme(metadata: dict) -> list[dict]:
    return [
        {
            "function": _first_function(entry),
            "request": PTRACE_TRACEME,
            "request_name": "PTRACE_TRACEME",
            "site_count": entry.get("site_count"),
            "detail": (
                "A ptrace call site holds request 0 (PTRACE_TRACEME): the process "
                "asks to be traced by its parent, so a debugger can no longer attach."
            ),
        }
        for entry in _callsite_entries(metadata, "ptrace_request")
        if entry.get("value") == PTRACE_TRACEME
    ]


def _su_path_evidence(metadata: dict, table_key: str, pattern: re.Pattern) -> list[dict]:
    evidence = []
    for entry in _callsite_entries(metadata, table_key):
        path = _entry_string(entry)
        if path and pattern.search(path):
            evidence.append(
                {
                    "callee": entry.get("callee"),
                    "path": path,
                    "function": _first_function(entry),
                    "site_count": entry.get("site_count"),
                    "detail": f"'{path}' reaches {entry.get('callee')}.",
                }
            )
    return evidence


def _evaluate_root_path_probe(metadata: dict) -> list[dict]:
    return _su_path_evidence(metadata, "path_probe", _SU_PATH_SUFFIX_RE)


def _evaluate_su_execution(metadata: dict) -> list[dict]:
    evidence = _su_path_evidence(metadata, "exec_command", _SU_COMMAND_RE)
    for entry in metadata.get("call_site_arguments") or []:
        callee = str(entry.get("callee") or "").strip().lower()
        path = _entry_string(entry)
        if (
            entry.get("argument") == 1
            and _STRING_APPEND_RE.search(callee)
            and _SU_COMMAND_RE.search(path)
        ):
            evidence.append(
                {
                    "callee": entry.get("callee"),
                    "via": "string_append",
                    "path": path,
                    "function": _first_function(entry),
                    "site_count": entry.get("site_count"),
                    "detail": (
                        f"'{path}' is appended to a std::string: a command is being "
                        "built around su. What later receives the string is not traced."
                    ),
                }
            )
    return evidence


def _evaluate_emulator_property(metadata: dict) -> list[dict]:
    evidence = []
    compared: set[str] = set()
    for entry in _callsite_entries(metadata, "property_name"):
        name = _entry_string(entry)
        if name in _QEMU_PROPERTY_NAMES:
            evidence.append(
                {
                    "property": name,
                    "function": _first_function(entry),
                    "site_count": entry.get("site_count"),
                    "detail": f"__system_property_get reads '{name}', which only an emulator sets.",
                }
            )
        elif name in _EMULATOR_COMPARED_PROPERTIES:
            compared.add(name)
    if compared and any(
        _EMULATOR_TOKEN_RE.match(_entry_string(entry))
        for entry in _callsite_entries(metadata, "compare_token")
    ):
        evidence.extend(
            {
                "property": name,
                "function": None,
                "detail": (
                    f"__system_property_get reads '{name}' and the library compares a "
                    "string against goldfish or ranchu, the emulator hardware names."
                ),
            }
            for name in sorted(compared)
        )
    return evidence


def _is_writable_load_path(path: str) -> bool:
    return any(
        path == prefix or path.startswith(prefix + "/") for prefix in _WRITABLE_LOAD_PREFIXES
    )


def _evaluate_writable_dlopen(metadata: dict) -> list[dict]:
    return [
        {
            "callee": entry.get("callee"),
            "path": _entry_string(entry),
            "function": _first_function(entry),
            "site_count": entry.get("site_count"),
            "detail": (
                f"{entry.get('callee')} loads '{_entry_string(entry)}', a location other "
                "apps or the user can write to."
            ),
        }
        for entry in _callsite_entries(metadata, "load_path")
        if _is_writable_load_path(_entry_string(entry))
    ]


# 32-bit ARM passes the syscall number in r7, loaded from an immediate or a
# literal just before the svc. Literal-pool words between functions can
# decode as svc too, but not behind such a load in one run of code.
_ARM32_SYSCALL_NUMBER_RE = re.compile(
    r"^(?:mov|movs|movw|movt)(?:\.w|\.n)?\s+r7,\s*(?:#|0x)|^ldr(?:\.w|\.n)?\s+r7,\s*\[pc",
    re.IGNORECASE,
)
# What ends that run: an unconditional transfer away, or a zero halfword or
# word (movs r0, r0 / andeq r0, r0, r0), which compilers never emit and
# pools are full of.
_ARM32_RUN_BREAK_RE = re.compile(
    r"^(?:movs\s+r0,\s*r0$|andeq\s+r0,\s*r0,\s*r0$|b(?:\.w|\.n)?\s|bx(?:\.w)?\s"
    r"|pop(?:\.w)?\s+\{[^}]*\bpc\})",
    re.IGNORECASE,
)
# How many instructions before the svc the r7 load may sit.
_ARM32_SYSCALL_NUMBER_WINDOW = 8


def _is_arm32(metadata: dict) -> bool:
    target = str(metadata.get("llvm_target_tuple") or metadata.get("machine_type") or "").lower()
    if "aarch64" in target or "arm64" in target:
        return False
    return target.startswith(("arm", "thumb")) or "armeabi" in target


def _arm32_syscall_sites(lines: list[str]) -> int:
    """Count svc sites that load their syscall number into r7 first."""
    sites = 0
    for index, line in enumerate(lines):
        if not _INLINE_SYSCALL_RE.search(line):
            continue
        for item in reversed(lines[max(0, index - _ARM32_SYSCALL_NUMBER_WINDOW) : index]):
            text = item.strip()
            if _ARM32_SYSCALL_NUMBER_RE.search(text):
                sites += 1
                break
            if _ARM32_RUN_BREAK_RE.search(text):
                break
    return sites


def _evaluate_inline_syscalls(metadata: dict) -> list[dict]:
    name = _soname_or_basename(metadata)
    if name in _BIONIC_LIBC_SONAMES or name.startswith(_SANITIZER_RUNTIME_PREFIX):
        return []
    if (metadata.get("build_info") or {}).get("go_version"):
        return []
    arm32 = _is_arm32(metadata)
    holders = []
    for key, func_data in (metadata.get("disassembled_functions") or {}).items():
        if not isinstance(func_data, dict):
            continue
        assembly = str(func_data.get("assembly") or "")
        if arm32:
            sites = _arm32_syscall_sites(assembly.split("\n"))
        else:
            sites = len(_INLINE_SYSCALL_RE.findall(assembly))
        if sites:
            holders.append(
                {
                    "function": str(func_data.get("name") or key),
                    "address": func_data.get("address"),
                    "sites": sites,
                }
            )
    if not holders:
        return []
    holders.sort(key=lambda item: (-item["sites"], item["function"]))
    site_total = sum(item["sites"] for item in holders)
    return [
        {
            "site_total": site_total,
            "function_count": len(holders),
            "functions": holders[:64],
            "detail": (
                f"{site_total} raw syscall instructions in {len(holders)} functions of "
                "this library's own code, bypassing bionic's wrappers."
            ),
        }
    ]


def _bound_native_count(join: dict) -> int:
    """Dex native declarations the JNI join bound, statically or dynamically."""
    total = 0
    for abi_summary in (join.get("per_abi") or {}).values():
        if isinstance(abi_summary, dict):
            for key in ("bound", "bound_dynamic"):
                if isinstance(abi_summary.get(key), list):
                    total += len(abi_summary[key])
    return total


def _evaluate_dex_su_paths_to_native(metadata: dict) -> list[dict]:
    join = metadata.get("android_jni")
    if not isinstance(join, dict):
        return []
    strings = {
        str(value.get("value") if isinstance(value, dict) else value)
        for value in metadata.get("informative_strings") or []
    }
    matched = sorted(strings & ROOTBEER_SPECIFIC_SU_DIRECTORIES)
    if len(matched) < MIN_SU_DIRECTORIES:
        return []
    bound = _bound_native_count(join)
    if not bound:
        return []
    return [
        {
            "su_path_strings": matched,
            "bound_native_declarations": bound,
            "detail": (
                f"The dex holds {len(matched)} su directories ({', '.join(matched[:4])}"
                f"{', ...' if len(matched) > 4 else ''}) and declares {bound} native "
                "methods bound to shipped libraries. Whether the paths reach them is "
                "not traced."
            ),
        }
    ]


ANDROID_RULE_EVALUATORS: dict[str, Callable[[dict], list[dict]]] = {
    "ANDROID_PTRACE_TRACEME": _evaluate_ptrace_traceme,
    "ANDROID_ROOT_PATH_PROBE": _evaluate_root_path_probe,
    "ANDROID_SU_EXECUTION": _evaluate_su_execution,
    "ANDROID_EMULATOR_PROPERTY_PROBE": _evaluate_emulator_property,
    "ANDROID_WRITABLE_LOCATION_DLOPEN": _evaluate_writable_dlopen,
    "ANDROID_INLINE_SYSCALLS": _evaluate_inline_syscalls,
    "ANDROID_DEX_SU_PATHS_TO_NATIVE": _evaluate_dex_su_paths_to_native,
}


def evaluate_android_rule(rule_id: str, metadata: dict[str, Any]) -> list[dict]:
    """Evaluate one Android capability rule; empty evidence means no match.

    The native rules run only on Android ELF (an ``android`` facts block);
    the dex rule needs the JNI join.
    """
    evaluator = ANDROID_RULE_EVALUATORS.get(rule_id)
    if evaluator is None or not metadata:
        return []
    if rule_id != "ANDROID_DEX_SU_PATHS_TO_NATIVE" and not isinstance(
        metadata.get("android"), dict
    ):
        return []
    return evaluator(metadata)
