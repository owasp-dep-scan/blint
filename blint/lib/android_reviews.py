"""Native Android capability reviews (A7, plan 04/C).

Every rule in this module exists because the single-signal form of its
family fires only on benign code: the reviewer's corpus census
(GLM-PROMPT.md, measurement 1) found zero true positives among the
``ptrace`` importers (crash handlers and unwinders), the ``/proc`` readers,
the ``__system_property_*`` importers (ubiquitous), the ``dlopen``
importers, the ``/data/local/tmp`` strings and the emulator tokens — and
every "frida" substring was "Friday". So no rule here keys on an import or
a bare string. Each is a conjunction (a call-site constant naming *what*
reaches a resolved call, or a dex-plus-JNI-join pairing) and each rule's
description states what it cannot see.

The census also measured where the strings went: the string extractor's
entropy and length gates drop every plain short path ("/system/xbin/su",
"/data/local/tmp", "ro.kernel.qemu", "goldfish") — only ``/proc/...``
survives (tests/scripts/android/a7-k0-census.json). The call-site
constants are therefore not a refinement of the string path; they are the
only path. They are recovered by the abstract interpreter (arm64 and
x86_64 only), and a rule that cannot evaluate on an ABI says so as a fact
instead of staying silent (ground rule 35).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from blint.lib.absint import argument_registers

# ---------------------------------------------------------------------------
# Shared call-site reading
# ---------------------------------------------------------------------------

# The callees each rule reads, with the 0-based argument position the
# security-relevant value travels in (the call_site_arguments block's own
# indexing; the positions are the C signatures').
CALLEE_ARGUMENT_POSITIONS: dict[str, dict[str, int]] = {
    # ptrace(request, pid, addr, data)
    "ptrace_request": {"ptrace": 0},
    # open/fopen/access/stat family: the path argument.
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
    # exec family: the program path or the command string.
    "exec_command": {
        "execve": 0,
        "execv": 0,
        "execl": 0,
        "execlp": 0,
        "execvp": 0,
        "popen": 0,
        "system": 0,
    },
    # __system_property_get(name, value): the property name.
    "property_name": {"__system_property_get": 0, "__system_property_find": 0},
    # dlopen(filename, ...) / android_dlopen_ext(filename, ...).
    "load_path": {"dlopen": 0, "android_dlopen_ext": 0, "android_load_sphal": 0},
    # strcmp family: either position can carry the token.
    "compare_token": {"strcmp": -1, "strncmp": -1, "strcasecmp": -1},
}

PTRACE_TRACEME = 0

# A constant is a su path when its last path component is exactly "su"
# (RootBeer's native callers pass full paths; dumpstate passes
# "/system/xbin/su"). For the exec family the constant is often the whole
# command ("/system/bin/su -c id"), so there the su path only needs to
# begin it; both forms require the boundary so "/system/bin/sum" and
# "/sudo" do not match.
_SU_PATH_SUFFIX_RE = re.compile(r"(?:^|/)su$")
_SU_COMMAND_RE = re.compile(r"(?:^|/)su(?=$|\s)")

# Emulator fingerprinting in the sharp form (GLM-PROMPT.md candidate 4):
# the qemu properties are emulator-only facts, so reading one is already
# the signal; the hardware/model properties are read by enormous amounts
# of benign code (the census: 475 tier-0 libraries import
# __system_property_*) and only count beside a goldfish/ranchu
# comparison. libflutter, which picks its GPU backend from ro.hardware,
# is the measured no-fire case.
_QEMU_PROPERTY_NAMES = frozenset(
    {
        "ro.kernel.qemu",
        "ro.kernel.qemu.gles",
        "ro.kernel.qemu1",
        "ro.boot.qemu",
    }
)
_EMULATOR_COMPARED_PROPERTIES = frozenset(
    {
        "ro.hardware",
        "ro.product.device",
        "ro.product.board",
    }
)
_EMULATOR_TOKEN_RE = re.compile(r"^(?:goldfish|ranchu)$", re.IGNORECASE)

# Loading code from a writable location (candidate 5). Shared-storage and
# app-data prefixes per the prompt; matched on whole path components so
# "/sdcardx" does not count.
_WRITABLE_LOAD_PREFIXES = (
    "/data/local/tmp",
    "/sdcard",
    "/storage",
    "/data/data",
)

# The inline-syscall instruction forms per ABI, as blint's disassembler
# renders them (x86 immediates are decimal, so 0x80 prints as 128).
_INLINE_SYSCALL_RE = re.compile(r"\bsvc\s+#?0\b|\bsyscall\b|\bint\s+(?:0x80|128)\b")

# The populations that legitimately hold raw syscall sites on Android
# (measurement 2): bionic's own syscall wrappers, the clang sanitizer
# runtimes' internal_* layer, and Go's runtime (which issues syscalls
# directly; its buildinfo identifies it).
_BIONIC_LIBC_SONAMES = frozenset({"libc.so", "libc.so.0"})
_SANITIZER_RUNTIME_PREFIX = "libclang_rt."


def _android_metadata(metadata: dict) -> dict | None:
    """The android facts block, or None for a non-Android image.

    Every rule in this module is Android ELF (or dex) only: the benign
    populations it was measured against are Android's, and the loader and
    property semantics it reasons about are bionic's.
    """
    android = metadata.get("android")
    return android if isinstance(android, dict) else None


def _callsite_entries(metadata: dict, table_key: str) -> list[dict]:
    """The exported call-site entries one rule reads, position-filtered.

    ``compare_token`` entries are returned for either position (the token
    can travel in either operand of a two-argument compare).
    """
    positions = CALLEE_ARGUMENT_POSITIONS[table_key]
    any_position = -1 in positions.values()
    results = []
    for entry in metadata.get("call_site_arguments") or []:
        callee = str(entry.get("callee") or "").strip().lower()
        if callee not in positions:
            continue
        if any_position or entry.get("argument") == positions[callee]:
            results.append(entry)
    return results


def _entry_string(entry: dict) -> str:
    return str(entry.get("string") or "")


def _callsite_evaluation_status(metadata: dict) -> str | None:
    """Why the call-site layer cannot evaluate this image, or None.

    Two refusals are distinct facts, not degrees of failure: the ABI's
    argument registers are not modelled (armeabi-v7a and x86 today), or
    the block the parse exported is unusable (its coverage was
    truncated, so an absence would read as an answer it is not). Both
    are reported only when disassembly actually ran - in a run that did
    not ask for ``--disassemble``, every disassembly-dependent layer
    (stack strings, function reviews, this one) is equally absent and
    the metadata's analysis coverage already names it, so a per-rule
    note would be boilerplate on every Android library rather than a
    fact a reader could mistake for absence.
    """
    coverage = metadata.get("call_site_arguments_coverage")
    if not isinstance(coverage, dict):
        return None
    if coverage.get("entries_truncated"):
        return "callsite_block_truncated"
    registers = argument_registers(
        str(metadata.get("binary_type") or ""), str(metadata.get("llvm_target_tuple") or "")
    )
    if registers is None:
        return "abi_not_modelled"
    return None


def _not_evaluated_for(reason: str, explanation: str) -> list[dict]:
    """One ``not_evaluated`` fact naming its reason, for a rule-specific
    refusal the shared status function does not know about."""
    return [
        {
            "status": "not_evaluated",
            "reason": reason,
            "detail": f"Not evaluated: {explanation}.",
        }
    ]


def _not_evaluated_evidence(metadata: dict) -> list[dict]:
    """The single fact a rule emits when it cannot evaluate.

    A silent no-fire would claim the capability was looked for and absent;
    on an ABI the abstract interpreter does not model, that claim is false
    (ground rule 35 — a rule that cannot apply reports that, it does not
    run as if it had).
    """
    reason = _callsite_evaluation_status(metadata)
    if reason is None:
        return []
    explanations = {
        "abi_not_modelled": (
            "the abstract interpreter models arm64 and x86_64 only; this image is "
            f"{metadata.get('llvm_target_tuple') or metadata.get('machine_type') or 'an unmodelled ABI'}"
        ),
        "callsite_block_truncated": (
            "the exported call-site block hit its entry bound, so an absence here "
            "would not prove the capability absent"
        ),
    }
    return [
        {
            "status": "not_evaluated",
            "reason": reason,
            "detail": (
                "Not evaluated: "
                + explanations.get(reason, reason)
                + ". No conclusion is drawn either way."
            ),
        }
    ]


# C++ command building: dumpstate's RunCommandToFd appends the su path to
# a std::string (libc++ basic_string::append(char const*), argument 1)
# before execvp receives the accumulated buffer — llvm-objdump of the
# api36 library shows the adrp/add of "/system/xbin/su" into that append,
# while execvp's own path argument arrives as a register parameter. The
# mangled name ends in appendEPKc on every libc++ ABI spelling; the
# constant reaching the builder is the recoverable half of the execution.
_STRING_APPEND_RE = re.compile(r"6appendepkc$")


def _string_append_entries(metadata: dict) -> list[dict]:
    """Call-site entries whose constant feeds a C++ string append."""
    results = []
    for entry in metadata.get("call_site_arguments") or []:
        callee = str(entry.get("callee") or "").strip().lower()
        if _STRING_APPEND_RE.search(callee) and entry.get("argument") == 1:
            results.append(entry)
    return results


def _soname_or_basename(metadata: dict) -> str:
    android = _android_metadata(metadata) or {}
    for candidate in (android.get("soname"), metadata.get("name")):
        if candidate:
            return str(candidate).rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    return ""


# ---------------------------------------------------------------------------
# The rule evaluators (one per family; ids live in the annotation file)
# ---------------------------------------------------------------------------


def _evaluate_ptrace_traceme(metadata: dict) -> list[dict]:
    """Family 1: ptrace(PTRACE_TRACEME) — the request constant 0."""
    evidence = []
    for entry in _callsite_entries(metadata, "ptrace_request"):
        if entry.get("value") != PTRACE_TRACEME or entry.get("argument") != 0:
            continue
        evidence.append(
            {
                "function": (entry.get("functions") or [None])[0],
                "request": PTRACE_TRACEME,
                "request_name": "PTRACE_TRACEME",
                "site_count": entry.get("site_count"),
                "detail": (
                    "A resolved ptrace call site holds request constant 0 "
                    "(PTRACE_TRACEME): the process asks to be traced by its own "
                    "parent, the standard self-anti-debug idiom. A ptrace import "
                    "alone is not reported — crash handlers attach to children "
                    "(PTRACE_ATTACH/SEIZE) and were the import's only carriers in "
                    "the corpus census."
                ),
            }
        )
    return evidence or _not_evaluated_evidence(metadata)


def _evaluate_su_paths(metadata: dict, table_key: str) -> list[dict]:
    """Families 2 and 3 share the su test; only the callee table differs.

    The path-probe table gets the strict end-of-path form (the constant is
    a filename); the exec table gets the command form (the constant often
    is the whole command line).
    """
    pattern = _SU_COMMAND_RE if table_key == "exec_command" else _SU_PATH_SUFFIX_RE
    evidence = []
    for entry in _callsite_entries(metadata, table_key):
        path = _entry_string(entry)
        if not path or not pattern.search(path):
            continue
        evidence.append(
            {
                "callee": entry.get("callee"),
                "path": path,
                "function": (entry.get("functions") or [None])[0],
                "site_count": entry.get("site_count"),
                "detail": (
                    f"The dataflow holds the su path '{path}' in the path/command "
                    f"argument of a resolved {entry.get('callee')} call site."
                ),
            }
        )
    if table_key == "exec_command":
        # The dumpstate shape: the su constant reaches a std::string append
        # that builds the command the exec family later receives. What is
        # proven here is the constant at the builder; the consumer of the
        # built string is named, not proven.
        for entry in _string_append_entries(metadata):
            path = _entry_string(entry)
            if not path or not _SU_COMMAND_RE.search(path):
                continue
            evidence.append(
                {
                    "callee": entry.get("callee"),
                    "via": "string_append",
                    "path": path,
                    "function": (entry.get("functions") or [None])[0],
                    "site_count": entry.get("site_count"),
                    "detail": (
                        f"The dataflow holds the su path '{path}' in the char* "
                        "argument of a resolved std::string::append call site: a "
                        "command string is being built around su. The append is "
                        "what is proven - the consumer of the built string (an "
                        "exec, a shell, a log) is not statically linked to this "
                        "evidence. dumpstate's RunCommandToFd reaches exactly this "
                        "shape before execvp."
                    ),
                }
            )
    return evidence


def _evaluate_root_path_probe(metadata: dict) -> list[dict]:
    """Family 2: constant su paths reaching access/stat/fopen/open."""
    evidence = _evaluate_su_paths(metadata, "path_probe")
    if evidence:
        return evidence
    return _not_evaluated_evidence(metadata)


def _evaluate_su_execution(metadata: dict) -> list[dict]:
    """Family 3: execve/execl*/popen/system with a constant su path."""
    evidence = _evaluate_su_paths(metadata, "exec_command")
    if evidence:
        return evidence
    return _not_evaluated_evidence(metadata)


def _evaluate_emulator_property(metadata: dict) -> list[dict]:
    """Family 4: __system_property_get with a constant emulator property name."""
    qemu_hits: list[dict] = []
    compared_properties: set[str] = set()
    for entry in _callsite_entries(metadata, "property_name"):
        name = _entry_string(entry)
        if not name:
            continue
        if name in _QEMU_PROPERTY_NAMES:
            qemu_hits.append(
                {
                    "property": name,
                    "function": (entry.get("functions") or [None])[0],
                    "site_count": entry.get("site_count"),
                }
            )
        elif name in _EMULATOR_COMPARED_PROPERTIES:
            compared_properties.add(name)
    evidence: list[dict] = []
    for hit in qemu_hits:
        evidence.append(
            {
                **hit,
                "detail": (
                    f"A resolved __system_property_get call site holds the constant "
                    f"property name '{hit['property']}' — a property that exists only "
                    "to describe an emulator. Reading it is the emulator-check idiom; "
                    "benign property reads (ro.build.version.sdk and friends) are not "
                    "reported."
                ),
            }
        )
    if compared_properties and _has_emulator_compare_token(metadata):
        for name in sorted(compared_properties):
            evidence.append(
                {
                    "property": name,
                    "function": None,
                    "detail": (
                        f"Resolved __system_property_get sites read '{name}' and the "
                        "same image compares a constant against the emulator hardware "
                        "tokens goldfish/ranchu — the GPU-backend-dispatch shape is "
                        "libflutter's benign use of ro.hardware; this finding is the "
                        "conjunction, read it with the library's purpose."
                    ),
                }
            )
    if evidence:
        return evidence
    return _not_evaluated_evidence(metadata)


def _has_emulator_compare_token(metadata: dict) -> bool:
    """A goldfish/ranchu constant reaching a resolved compare call."""
    for entry in _callsite_entries(metadata, "compare_token"):
        if _EMULATOR_TOKEN_RE.match(_entry_string(entry)):
            return True
    return False


def _is_writable_load_path(path: str) -> bool:
    return any(
        path == prefix or path.startswith(prefix.rstrip("/") + "/")
        for prefix in _WRITABLE_LOAD_PREFIXES
    )


def _evaluate_writable_dlopen(metadata: dict) -> list[dict]:
    """Family 5: dlopen/android_dlopen_ext with a constant writable path."""
    evidence = []
    for entry in _callsite_entries(metadata, "load_path"):
        path = _entry_string(entry)
        if not path or not _is_writable_load_path(path):
            continue
        evidence.append(
            {
                "callee": entry.get("callee"),
                "path": path,
                "function": (entry.get("functions") or [None])[0],
                "site_count": entry.get("site_count"),
                "detail": (
                    f"The dataflow holds '{path}' in the path argument of a resolved "
                    f"{entry.get('callee')} call site: code is loaded from shared "
                    "storage or the app's writable sandbox, where anything on the "
                    "device can replace it. A bare SONAME (the linker's search path) "
                    "is not reported."
                ),
            }
        )
    if evidence:
        return evidence
    return _not_evaluated_evidence(metadata)


def _go_buildinfo_present(metadata: dict) -> bool:
    build_info = metadata.get("build_info")
    return isinstance(build_info, dict) and bool(build_info.get("go_version"))


def _is_arm32(metadata: dict) -> bool:
    """True for 32-bit ARM targets (arm-unknown-linux-android,
    armv7a-…, armeabi-v7a), false for AArch64 and everything else."""
    lowered = str(metadata.get("llvm_target_tuple") or "").lower()
    if not lowered:
        lowered = str(metadata.get("machine_type") or "").lower()
    if "aarch64" in lowered or "arm64" in lowered:
        return False
    return lowered.startswith("arm") or "armeabi" in lowered or "thumb" in lowered


def _evaluate_inline_syscalls(metadata: dict) -> list[dict]:
    """Family 6: raw kernel-transition instructions in the image's own code.

    The exclusions are the measured benign populations (measurement 2):
    bionic libc (its syscall wrappers — 228 sites in the api36 image), the
    clang sanitizer runtimes (internal_* raw-syscall layer, 25-43 sites
    each) and Go-built libraries (the runtime issues syscalls directly).
    What is left is an image that bypasses bionic on its own, which on
    Android means bypassing every seccomp-filtered and hookable libc
    wrapper. Evaluates on arm64 and x86/x86_64, where the recovered site
    counts match the ``llvm-objdump`` oracle (K0: bionic libc 228/228,
    libxul's single app-library site).

    armeabi-v7a reports ``not_evaluated`` instead: on stripped ARM32
    libraries blint's function extents overrun into the literal pools
    ARM32 linkers place between functions, and pool bytes decode as
    ``svc #0`` (Thumb 0xDF00) amid ``movs r0, r0`` padding — measured
    against llvm-objdump (R3 hand-check): libflutter 0 real vs 2
    reported, libhermes 0/1, libvlc 0/2, libxul 1/21, against
    libjnidispatch's genuine 1/1. 25 false sites against 2 true across
    those five, so the ABI's instruction-stream evidence does not carry a
    finding; the fact is stated rather than silenced (ground rule 35's
    recovery-side form). Fixing the overrun is A4-lane work; the numbers
    here are its input.
    """
    name = _soname_or_basename(metadata)
    if name in _BIONIC_LIBC_SONAMES or name.startswith(_SANITIZER_RUNTIME_PREFIX):
        return []
    if _go_buildinfo_present(metadata):
        return []
    disassembled = metadata.get("disassembled_functions") or {}
    if not disassembled:
        # The rule needs the instruction stream; without disassembly there
        # is nothing to evaluate, and the fact says so.
        return _not_evaluated_evidence(metadata)
    if _is_arm32(metadata):
        return _not_evaluated_for(
            "arm32_recovery_unreliable",
            "ARM32 function extents overrun into the literal pools between "
            "functions, so svc #0 sites appear where llvm-objdump decodes none "
            "(R3 hand-check: 25 false sites against 2 true across libflutter, "
            "libhermes, libvlc, libxul and libjnidispatch armeabi-v7a); no "
            "conclusion is drawn on this ABI",
        )
    holders = []
    site_total = 0
    for key, func_data in disassembled.items():
        if not isinstance(func_data, dict):
            continue
        assembly = str(func_data.get("assembly") or "")
        if not assembly:
            continue
        sites = len(_INLINE_SYSCALL_RE.findall(assembly))
        if sites:
            site_total += sites
            holders.append(
                {
                    "function": str(func_data.get("name") or key),
                    "address": func_data.get("address"),
                    "sites": sites,
                }
            )
    if not holders:
        return []
    holders.sort(key=lambda item: (-item["sites"], str(item["function"])))
    return [
        {
            "site_total": site_total,
            "function_count": len(holders),
            "functions": holders[:64],
            "detail": (
                f"{site_total} raw kernel-transition sites (svc/syscall/int 0x80) in "
                f"{len(holders)} functions of this image's own code. bionic libc, the "
                "clang sanitizer runtimes and Go-built libraries are excluded by name "
                "and buildinfo; what remains chose to bypass the libc wrappers, which "
                "on Android also bypasses the seccomp policy applied to them. The "
                "known benign shape is the signal-safety stub - the census's only "
                "app-library carrier (libxul) holds exactly one site, a bare "
                "rt_sigprocmask query - so read the functions listed before "
                "concluding; a single sigmask syscall is not a packer."
            ),
        }
    ]


# The dex-side directories RootBeer's Const.suPaths carries at 0.1.2,
# minus the generic mount points (/data, /cache, /dev, /sbin,
# /system/bin, /data/local[/bin]) that name nothing by themselves. This
# is the path list the dex prong of the root-check rule matches, and its
# source is named in the rule description.
ROOTBEER_012_SPECIFIC_SU_DIRECTORIES = frozenset(
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


def _bound_native_count(join: dict) -> int:
    """Dex native declarations the join bound to a shipped library.

    Both binding halves count: statically (a ``Java_*`` export answered
    the declaration) and dynamically (a recovered ``RegisterNatives``
    table did), since an obfuscated root checker registers at run time
    precisely to keep its name out of the export table.
    """
    total = 0
    for abi_summary in (join.get("per_abi") or {}).values():
        if not isinstance(abi_summary, dict):
            continue
        for key in ("bound", "bound_dynamic"):
            bound = abi_summary.get(key)
            if isinstance(bound, list):
                total += len(bound)
    return total


def _evaluate_dex_su_paths_to_native(metadata: dict) -> list[dict]:
    """Family 2, dex prong: su paths in the dex reaching a native method.

    RootBeer's native check holds no constant of its own (measurement 4):
    Java builds the path list and passes it through JNI. The A5 join
    links the dex declaration to the shipped implementation, so the
    conjunction this rule reports is: the specific RootBeer su-path
    directories appear as dex string constants, and the same app declares
    native methods that the join bound to shipped libraries. The join
    proves the methods are native — it cannot prove these strings reach
    them (the dex-to-native dataflow is not modelled), which is why the
    severity is low and the finding is a review pointer, not a verdict.
    """
    join = metadata.get("android_jni")
    if not isinstance(join, dict):
        return []
    strings = metadata.get("informative_strings") or []
    matched = sorted(
        value
        for value in strings
        if str(value) in ROOTBEER_012_SPECIFIC_SU_DIRECTORIES
    )
    if not matched:
        return []
    bound = _bound_native_count(join)
    if not bound:
        return []
    return [
        {
            "su_path_strings": matched,
            "bound_native_declarations": bound,
            "detail": (
                f"The dex carries {len(matched)} root-probe path constants "
                f"({', '.join(matched[:4])}{'…' if len(matched) > 4 else ''}) — the "
                "directory list RootBeer's Const.suPaths ships at 0.1.2 — and the app "
                f"declares native methods the JNI join bound to shipped libraries "
                f"({bound} bound declarations). RootBeer's own native checker "
                "receives these paths from Java and holds no constant of its own, so "
                "this dex-plus-native conjunction is the only static view of it."
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

    Non-Android images never match: every evaluator's first gate is the
    ``android`` facts block (the dex rule's is the ``android_jni`` join).
    """
    evaluator = ANDROID_RULE_EVALUATORS.get(rule_id)
    if evaluator is None or not metadata:
        return []
    if rule_id != "ANDROID_DEX_SU_PATHS_TO_NATIVE" and not _android_metadata(metadata):
        return []
    return evaluator(metadata)
