import re
from collections import defaultdict
from collections.abc import Iterator
from typing import Any

CLASS_253_IMMEDIATE_RE = re.compile(r"(?<![a-z0-9])(0xfd|253)(?![a-z0-9])")
SYSTEM_BUILD_VERSION_IMMEDIATE_RE = re.compile(r"(?<![a-z0-9])(0xde|222)(?![a-z0-9])")
ZALLOC_RO_MUT_TARGET_LEN_ADD_RE = re.compile(r"\badds?\s+x9\s*,\s*x8\s*,\s*x4\b")
ZALLOC_RO_MUT_OVERFLOW_BRANCH_RE = re.compile(r"\bb\.?hs\b")
ZALLOC_RO_MUT_PATCHED_CCMP_RE = re.compile(r"\bccmp\s+x9\s*,\s*x(?:10|11)\b")

X86_INDIRECT_CALL_REGISTERS: set[str] = {
    "rax",
    "rbx",
    "rcx",
    "rdx",
    "rsi",
    "rdi",
    "rbp",
    "rsp",
    "eax",
    "ebx",
    "ecx",
    "edx",
    "esi",
    "edi",
    "ebp",
    "esp",
}
for _reg_idx in range(8, 16):
    X86_INDIRECT_CALL_REGISTERS.add(f"r{_reg_idx}")
    X86_INDIRECT_CALL_REGISTERS.add(f"r{_reg_idx}d")
    X86_INDIRECT_CALL_REGISTERS.add(f"r{_reg_idx}w")
    X86_INDIRECT_CALL_REGISTERS.add(f"r{_reg_idx}b")
ARM64_INDIRECT_CALL_REGISTERS: set[str] = {f"x{idx}" for idx in range(31)} | {"xzr"}

ZERO_LENGTH_ARG_SETUP_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern)
    for pattern in (
        r"\b(?:xor|sub)\s+r8d,\s*r8d\b",
        r"\b(?:xor|sub)\s+r8,\s*r8\b",
        r"\bmov\s+r8d,\s*(?:0x0+|0)\b",
        r"\bmov\s+r8,\s*(?:0x0+|0)\b",
        r"\bmov\s+w2,\s*wzr\b",
        r"\bmov\s+x2,\s*xzr\b",
        r"\bmovz?\s+w2,\s*#?(?:0x0+|0)\b",
        r"\bmovz?\s+x2,\s*#?(?:0x0+|0)\b",
        r"\bpush\s+(?:0x0+|0)\b",
    )
)

DYNAMIC_RESOLVER_APIS: set[str] = {
    "getprocaddress",
    "ldrgetprocedureaddress",
}
MODULE_RESOLUTION_APIS: set[str] = {
    "getmodulehandle",
    "getmodulehandlea",
    "getmodulehandlew",
    "getmodulehandleex",
    "getmodulehandleexa",
    "getmodulehandleexw",
    "loadlibrary",
    "loadlibrarya",
    "loadlibraryw",
    "loadlibraryexa",
    "loadlibraryexw",
    "loadpackagedlibrary",
    "ldrloaddll",
}

CLOUD_FILTER_ABORT_APIS: set[str] = {
    "cfabortoperation",
}
CLOUD_FILTER_TOKEN_IMPERSONATION_APIS: set[str] = {
    "impersonateanonymoustoken",
    "setthreadtoken",
    "setimpersonationtoken",
    "ntsetinformationthread",
    "zwsetinformationthread",
    "getanonymoustoken",
}
CLOUD_FILTER_REGISTRY_APIS: set[str] = {
    "ntcreatekey",
    "ntopenkey",
    "ntdeletekey",
    "ntsetvaluekey",
    "regcreatekey",
    "regcreatekeyex",
    "regopenkey",
    "regopenkeyex",
    "regdeletekey",
    "regdeletekeyex",
    "regdeletekeyvalue",
    "regsetvalue",
    "regsetvalueex",
}
CLOUD_FILTER_REGISTRY_SECURITY_APIS: set[str] = {
    "ntsetsecurityobject",
    "regsetkeysecurity",
    "setsecuritydescriptor",
    "setsecurityinfo",
    "setnamedsecurityinfo",
}
CLOUD_FILTER_REGISTRY_LINK_APIS: set[str] = {
    "createsymboliclink",
    "ntcreatesymboliclinkobject",
}

# MSR and port I/O are compiler intrinsics, so they are only visible as
# instructions. `in`/`out` need word boundaries to avoid matching operands.
PRIVILEGED_HW_INSTRUCTION_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern)
    for pattern in (
        r"\brdmsr\b",
        r"\bwrmsr\b",
        r"\brdpmc\b",
        r"\binvd\b",
        r"\bwbinvd\b",
        r"\bin\s+(?:al|ax|eax)\s*,",
        r"\bout\s+(?:dx|0x[0-9a-f]+)\s*,",
        r"\bmov\s+cr[0-8]\s*,",
    )
)

PCI_CONFIG_APIS: set[str] = {
    "halgetbusdatabyoffset",
    "halsetbusdatabyoffset",
    "halgetbusdata",
    "halsetbusdata",
}

ACCESS_CHECK_APIS: set[str] = {
    "sesingleprivilegecheck",
    "seaccesscheck",
    "seprivilegecheck",
    "zwqueryinformationtoken",
    "ntqueryinformationtoken",
    "iovalidatedeviceiocontrolaccess",
    "obreferenceobjectbyhandle",
    "rtlvalidsecuritydescriptor",
    "rtlvalidrelativesecuritydescriptor",
}

# Allocation or protection calls that can hand back executable memory. A plain
# heap allocation (malloc, HeapAlloc) cannot, so it is not a loader signal.
EXEC_MEMORY_APIS: set[str] = {
    "virtualalloc",
    "virtualalloc2",
    "virtualallocex",
    "virtualallocexnuma",
    "virtualprotect",
    "virtualprotectex",
    "ntallocatevirtualmemory",
    "zwallocatevirtualmemory",
    "ntprotectvirtualmemory",
    "zwprotectvirtualmemory",
    "mmap",
    "mmap64",
    "mprotect",
    "pkey_mprotect",
    "vm_protect",
    "mach_vm_protect",
}
# Where each API takes its protection argument (0-based) and the bits that
# make the memory executable: PROT_EXEC and VM_PROT_EXECUTE are 4, and the
# Windows PAGE_EXECUTE* constants are 0x10-0x80.
EXEC_PROTECTION_ARGUMENT: dict[str, tuple[int, int]] = {
    "mmap": (2, 0x4),
    "mmap64": (2, 0x4),
    "mprotect": (2, 0x4),
    "pkey_mprotect": (2, 0x4),
    "vm_protect": (4, 0x4),
    "mach_vm_protect": (4, 0x4),
    "virtualalloc": (3, 0xF0),
    "virtualalloc2": (4, 0xF0),
    "virtualallocex": (4, 0xF0),
    "virtualallocexnuma": (4, 0xF0),
    "virtualprotect": (2, 0xF0),
    "virtualprotectex": (3, 0xF0),
    "ntallocatevirtualmemory": (5, 0xF0),
    "zwallocatevirtualmemory": (5, 0xF0),
    "ntprotectvirtualmemory": (3, 0xF0),
    "zwprotectvirtualmemory": (3, 0xF0),
}
# Remote injection: memory allocated in another process, written there, then
# started by a thread or APC rather than by a local indirect call.
REMOTE_ALLOC_APIS: set[str] = {
    "virtualallocex",
    "virtualallocexnuma",
    "virtualprotectex",
    "ntallocatevirtualmemory",
    "zwallocatevirtualmemory",
}
REMOTE_WRITE_APIS: set[str] = {
    "writeprocessmemory",
    "ntwritevirtualmemory",
    "zwwritevirtualmemory",
}
REMOTE_START_APIS: set[str] = {
    "createremotethread",
    "createremotethreadex",
    "ntcreatethreadex",
    "zwcreatethreadex",
    "rtlcreateuserthread",
    "queueuserapc",
    "ntqueueapcthread",
    "setthreadcontext",
    "ntsetcontextthread",
}
DEBUG_APIS: set[str] = {
    "isdebuggerpresent",
    "checkremotedebuggerpresent",
    "outputdebugstring",
    "debugbreak",
    "ptrace",
    "getppid",
    "gettickcount",
    "gettickcount64",
    "queryperformancecounter",
    "timegettime",
    "ntqueryinformationprocess",
    "zwqueryinformationprocess",
    "ntsetinformationthread",
    "zwsetinformationthread",
    "openprocess",
    "setunhandledexceptionfilter",
    "raiseexception",
    "rtladdvectoredexceptionhandler",
    "findwindow",
    "findwindowex",
    "enumwindows",
    "getforegroundwindow",
}


def _normalize_direct_call_name(call_name: str) -> str:
    """Normalize direct-call target names for exact API matching."""
    normalized = str(call_name or "").strip().lower()
    if "::" in normalized:
        normalized = normalized.rsplit("::", maxsplit=1)[-1]
    normalized = normalized.removeprefix("__imp_")
    return normalized.lstrip("_")


def _normalize_function_symbol_name(function_name: str) -> str:
    """Normalize internal function names for cross-function call matching."""
    return _normalize_direct_call_name(function_name)


def _function_has_direct_call(func_data: dict, api_name: str) -> bool:
    """Return True when a function's resolved direct calls include the named API."""
    normalized_api_name = api_name.strip().lower()
    return any(
        _normalize_direct_call_name(call_name) == normalized_api_name
        for call_name in func_data.get("direct_calls", [])
    )


def _function_has_any_direct_call(func_data: dict, api_names: set[str]) -> bool:
    """Return True when any normalized direct call matches one of the APIs."""
    normalized_api_names = {name.strip().lower() for name in api_names}
    return any(
        _normalize_direct_call_name(call_name) in normalized_api_names
        for call_name in func_data.get("direct_calls", [])
    )


def _function_has_any_call_fragment(func_data: dict, api_names: set[str]) -> bool:
    """Return True when any normalized direct call contains a named API fragment."""
    normalized_api_names = {name.strip().lower() for name in api_names}
    for call_name in func_data.get("direct_calls", []):
        normalized_call_name = _normalize_direct_call_name(call_name)
        if any(api_name in normalized_call_name for api_name in normalized_api_names):
            return True
    return False


def _function_has_indirect_target_hint(func_data: dict, api_name: str) -> bool:
    """Return True when an indirect/tail call target hint resolves to the API."""
    normalized_api_name = api_name.strip().lower()
    return any(
        target.get("kind") in ("indirect_hint", "tailcall")
        and _normalize_direct_call_name(target.get("target_name", "")) == normalized_api_name
        for target in func_data.get("direct_call_targets", [])
    )


def _function_has_dynamic_resolution_context(func_data: dict) -> bool:
    """Return True for common GetProcAddress/LdrGetProcedureAddress resolver chains."""
    return _function_has_any_direct_call(
        func_data, DYNAMIC_RESOLVER_APIS
    ) and _function_has_any_direct_call(func_data, MODULE_RESOLUTION_APIS)


def _function_name_is_zalloc_ro_mut(func_data: dict) -> bool:
    """Return True only for the non-atomic _zalloc_ro_mut function."""
    normalized_name = _normalize_function_symbol_name(func_data.get("name", ""))
    return normalized_name == "zalloc_ro_mut"


def _zalloc_ro_mut_has_patched_per_cpu_bounds(assembly: str) -> bool:
    """Return True when the post-patch per-CPU bound-check sequence is present."""
    return "tpidr_el1" in assembly and len(ZALLOC_RO_MUT_PATCHED_CCMP_RE.findall(assembly)) >= 2


def _zalloc_ro_mut_has_prepatch_wrap_check_shape(assembly: str) -> bool:
    """Return True for the pre-patch target+len overflow-check shape."""
    return bool(
        ZALLOC_RO_MUT_TARGET_LEN_ADD_RE.search(assembly)
        and ZALLOC_RO_MUT_OVERFLOW_BRANCH_RE.search(assembly)
    )


def _assembly_matches_any(assembly: str, patterns: tuple[re.Pattern[str], ...]) -> bool:
    """Return True when the assembly text matches any compiled regex pattern."""
    return any(pattern.search(assembly) for pattern in patterns)


def _looks_like_indirect_call_line(line: str) -> bool:
    """Return True for indirect call/jump-call forms used in disassembly windows."""
    normalized = line.strip().lower()
    if not normalized:
        return False
    mnemonic, _, operand = normalized.partition(" ")
    operand = operand.strip()
    if mnemonic in ("blr", "blraa", "blrab"):
        return operand.startswith("x")
    if not mnemonic.startswith("call") or not operand:
        return False
    if "[" in operand and "]" in operand:
        return True
    normalized_operand = operand.removeprefix("%")
    if normalized_operand.startswith("$"):
        return True
    return (
        normalized_operand in X86_INDIRECT_CALL_REGISTERS
        or normalized_operand in ARM64_INDIRECT_CALL_REGISTERS
    )


_REGISTER_CALL_MNEMONICS = {"blr", "blraa", "blrab", "blraaz", "blrabz", "call", "callq", "blx"}
_REGISTER_JUMP_MNEMONICS = {"br", "braa", "brab", "braaz", "brabz", "jmp", "jmpq", "bx"}
_ARM32_TRANSFER_REGISTERS = {f"r{idx}" for idx in range(13)} | {"ip", "sb", "sl", "fp"}
# A frame restore just before a register jump marks it as a tail call; a
# switch's jump-table branch never follows one.
_FRAME_RESTORE_RE = re.compile(
    r"^(?:ldp\s+x29,\s*x30|ldr\s+x30,|pop\b|leave\b|add\s+[re]?sp,|ldm\w*\s+sp!|"
    r"pop\.w\b|ldr\s+lr,)"
)


def _transfer_register(mnemonic: str, operand: str) -> bool:
    """True when a call/jump operand is a bare general-purpose register."""
    operand = operand.removeprefix("%").removeprefix("*%").strip()
    if not operand or "[" in operand or "," in operand:
        return False
    if mnemonic in ("blx", "bx"):
        return operand in _ARM32_TRANSFER_REGISTERS
    if operand == "x30":
        return False
    return operand in X86_INDIRECT_CALL_REGISTERS or operand in ARM64_INDIRECT_CALL_REGISTERS


def _has_register_indirect_transfer(assembly: str) -> bool:
    """True when control passes to an address held in a register: a register
    call, or a register jump in tail position. Memory-operand calls (x86-64
    import calls through the IAT or GOT) and jump-table branches do not count.
    """
    lines = [line.strip().lower() for line in assembly.splitlines() if line.strip()]
    for idx, line in enumerate(lines):
        mnemonic, _, operand = line.partition(" ")
        if mnemonic in _REGISTER_CALL_MNEMONICS and _transfer_register(mnemonic, operand):
            return True
        if mnemonic in _REGISTER_JUMP_MNEMONICS and _transfer_register(mnemonic, operand):
            if any(_FRAME_RESTORE_RE.match(prev) for prev in lines[max(0, idx - 4) : idx]):
                return True
    return False


def _requests_executable_memory(func_data: dict, arch_target: str, binary_format: str) -> bool:
    """True unless every executable-capable call in the function provably asks
    for non-executable memory.

    The protection argument is read from the call-site dataflow
    (:func:`blint.lib.absint.recover_call_site_arguments_with_method`). A call
    whose protection the dataflow cannot pin to one constant, or a function it
    cannot analyse, counts as executable: only a known constant without the
    execute bits clears a call.
    """
    if not _function_has_any_direct_call(func_data, EXEC_MEMORY_APIS):
        return False
    from blint.lib.absint import recover_call_site_arguments_with_method

    try:
        records, method = recover_call_site_arguments_with_method(
            func_data, arch_target, binary_format
        )
    except Exception:  # pylint: disable=broad-except
        return True
    if method != "dataflow":
        return True
    resolved_sites = 0
    for record in records:
        callee = _normalize_direct_call_name(record.get("callee") or "")
        if callee not in EXEC_MEMORY_APIS:
            continue
        resolved_sites += 1
        position, exec_bits = EXEC_PROTECTION_ARGUMENT[callee]
        arguments = record.get("arguments") or []
        protection = arguments[position] if position < len(arguments) else None
        if not isinstance(protection, int) or protection & exec_bits:
            return True
    expected_sites = sum(
        1
        for call_name in func_data.get("direct_calls", [])
        if _normalize_direct_call_name(call_name) in EXEC_MEMORY_APIS
    )
    # a call the records did not cover is not proven non-executable
    return resolved_sites < expected_sites


def _iter_indirect_call_windows(assembly: str, window_size: int = 8) -> Iterator[str]:
    """Yield short instruction windows ending at each indirect call site."""
    lines = [line.strip().lower() for line in assembly.splitlines() if line.strip()]
    for idx, line in enumerate(lines):
        if _looks_like_indirect_call_line(line):
            start = max(0, idx - window_size)
            yield "\n".join(lines[start : idx + 1])


def _function_has_indirect_call_window(
    func_data: dict, selector_pattern: re.Pattern[str], require_zero_length: bool = False
) -> bool:
    """Return True when an indirect-call instruction window matches the selector pattern."""
    if not func_data.get("has_indirect_call"):
        return False
    assembly = func_data.get("assembly", "").lower()
    for window in _iter_indirect_call_windows(assembly):
        if not selector_pattern.search(window):
            continue
        if require_zero_length and not _assembly_matches_any(
            window, ZERO_LENGTH_ARG_SETUP_PATTERNS
        ):
            continue
        return True
    return False


def _collect_dynamic_resolver_helpers(disassembled_functions: dict) -> dict[str, str]:
    """Map normalized helper names to display names for resolver-like internal helpers."""
    resolver_helpers: dict[str, str] = {}
    for func_data in disassembled_functions.values():
        if _function_has_dynamic_resolution_context(func_data):
            function_name = func_data.get("name", "")
            normalized_name = _normalize_function_symbol_name(function_name)
            if normalized_name:
                resolver_helpers[normalized_name] = function_name
    return resolver_helpers


def _find_called_resolver_helper(func_data: dict, resolver_helpers: dict[str, str]) -> str:
    """Return the first called internal resolver helper name for this function."""
    for call_name in func_data.get("direct_calls", []):
        normalized_name = _normalize_function_symbol_name(call_name)
        if normalized_name in resolver_helpers:
            return resolver_helpers[normalized_name]
    return ""


def _evaluate_function_metric(rule_obj: dict, func_data: dict) -> bool:
    """Evaluate generic function_metric review rules."""
    check_field = rule_obj.get("check_field")
    operator_str = rule_obj.get("operator")
    threshold = rule_obj.get("threshold")
    patterns = rule_obj.get("patterns")
    if not check_field or not operator_str:
        return False
    value: Any = func_data
    for key in check_field.split("."):
        if isinstance(value, dict):
            value = value.get(key)
        else:
            value = None
        if value is None:
            break
    if value is None:
        return False
    if threshold is not None:
        if operator_str == ">":
            return value > threshold
        if operator_str == ">=":
            return value >= threshold
        if operator_str == "<":
            return value < threshold
        if operator_str == "<=":
            return value <= threshold
        if operator_str == "==":
            return value == threshold
        if operator_str == "!=":
            return value != threshold
        return False
    if patterns is None:
        return False
    if operator_str == "contains_all":
        if isinstance(value, list):
            return all(any(p.lower() in str(v).lower() for v in value) for p in patterns)
        if isinstance(value, str):
            return all(p.lower() in value.lower() for p in patterns)
    elif operator_str in ("contains_any", "contains"):
        if isinstance(value, list):
            return any(any(p.lower() in str(v).lower() for v in value) for p in patterns)
        if isinstance(value, str):
            return any(p.lower() in value.lower() for p in patterns)
    return False


def _evaluate_function_analysis(
    rule_id: str,
    func_data: dict,
    resolver_helpers: dict[str, str],
    arch_target: str = "",
    binary_format: str = "",
) -> tuple[bool, str]:
    """Evaluate rule-specific function_analysis heuristics."""
    metrics = func_data.get("instruction_metrics", {})
    icount = func_data.get("instruction_count", 0)
    assembly = func_data.get("assembly", "").lower()
    direct_calls = [dc.lower() for dc in func_data.get("direct_calls", [])]
    related_function = ""
    passed = False

    if rule_id == "CRYPTO_BEHAVIOR":
        if icount > 10:
            shift_xor = metrics.get("shift_count", 0) + metrics.get("xor_count", 0)
            if (shift_xor / icount > 0.2) and metrics.get("simd_fpu_count", 0) > 0:
                passed = True
    elif rule_id == "ANTI_DISASSEMBLY_TRICKS":
        if icount <= 6 and metrics.get("jump_count", 0) > 0:
            passed = True
    elif rule_id == "HIGH_ENTROPY_INDIRECT_CALL":
        if func_data.get("has_indirect_call"):
            math_ops = (
                metrics.get("arith_count", 0)
                + metrics.get("shift_count", 0)
                + metrics.get("xor_count", 0)
            )
            if icount > 0 and (math_ops / icount) > 0.3:
                passed = True
    elif rule_id == "POTENTIAL_STACK_STRING":
        mov_count = assembly.count("mov")
        if icount > 15 and (mov_count / icount) > 0.6:
            passed = True
    elif rule_id == "SUSPICIOUS_MEMORY_ALLOC":
        local_loader = _has_register_indirect_transfer(assembly) and (
            _requests_executable_memory(func_data, arch_target, binary_format)
        )
        remote_injection = (
            _function_has_any_direct_call(func_data, REMOTE_ALLOC_APIS)
            and _function_has_any_direct_call(func_data, REMOTE_WRITE_APIS)
            and _function_has_any_direct_call(func_data, REMOTE_START_APIS)
        )
        if local_loader or remote_injection:
            passed = True
    elif rule_id == "POTENTIAL_ANTI_DEBUG":
        if "rdtsc" in assembly or any(api in c for c in direct_calls for api in DEBUG_APIS):
            passed = True
    elif rule_id == "POTENTIAL_SHELLCODE_CHARS":
        if func_data.get("has_system_call") and func_data.get("has_indirect_call"):
            passed = True
    elif rule_id == "LOOP_WITH_SELF_MODIFY_HINT":
        if func_data.get("has_loop") and metrics.get("xor_count", 0) > 0:
            passed = True
    elif rule_id == "DYNAMIC_API_RESOLUTION_HINT":
        if func_data.get("has_indirect_call") and (
            metrics.get("shift_count", 0) > 0 or metrics.get("xor_count", 0) > 0
        ):
            passed = True
    elif rule_id == "POTENTIAL_ROP_GADGET":
        if 1 <= icount <= 8 and metrics.get("ret_count", 0) > 0:
            passed = True
    elif rule_id == "UNUSUAL_CALLING_CONVENTION":
        regs_written = func_data.get("regs_written", [])
        if ("rsp" in regs_written or "esp" in regs_written) and (
            "mov rsp" in assembly or "xchg rsp" in assembly
        ):
            passed = True
    elif rule_id == "POTENTIAL_IAT_MANIPULATION":
        if func_data.get("sreg_interactions"):
            passed = True
    elif rule_id == "NTQSI_CLASS253_ZERO_LENGTH_CALL":
        if _function_has_direct_call(
            func_data, "ntquerysysteminformation"
        ) and CLASS_253_IMMEDIATE_RE.search(assembly):
            if _assembly_matches_any(assembly, ZERO_LENGTH_ARG_SETUP_PATTERNS):
                passed = True
    elif rule_id == "NTQSIEX_SYSTEM_BUILD_VERSION_QUERY":
        if _function_has_direct_call(
            func_data, "ntquerysysteminformationex"
        ) and SYSTEM_BUILD_VERSION_IMMEDIATE_RE.search(assembly):
            passed = True
    elif rule_id == "NTQSI_CLASS253_DYNAMIC_INDIRECT_CALL":
        if _function_has_indirect_call_window(
            func_data,
            CLASS_253_IMMEDIATE_RE,
            require_zero_length=True,
        ) and (
            _function_has_indirect_target_hint(func_data, "ntquerysysteminformation")
            or _function_has_dynamic_resolution_context(func_data)
        ):
            passed = True
    elif rule_id == "NTQSIEX_SYSTEM_BUILD_VERSION_DYNAMIC_INDIRECT_QUERY":
        if _function_has_indirect_call_window(
            func_data,
            SYSTEM_BUILD_VERSION_IMMEDIATE_RE,
        ) and (
            _function_has_indirect_target_hint(func_data, "ntquerysysteminformationex")
            or _function_has_dynamic_resolution_context(func_data)
        ):
            passed = True
    elif rule_id == "NTQSI_CLASS253_CROSS_FUNCTION_RESOLVER_CHAIN":
        related_function = _find_called_resolver_helper(func_data, resolver_helpers)
        if related_function and _function_has_indirect_call_window(
            func_data,
            CLASS_253_IMMEDIATE_RE,
            require_zero_length=True,
        ):
            passed = True
    elif rule_id == "NTQSIEX_SYSTEM_BUILD_VERSION_CROSS_FUNCTION_RESOLVER_CHAIN":
        related_function = _find_called_resolver_helper(func_data, resolver_helpers)
        if related_function and _function_has_indirect_call_window(
            func_data,
            SYSTEM_BUILD_VERSION_IMMEDIATE_RE,
        ):
            passed = True
    elif rule_id == "CLOUDFILTER_ABORT_TOKEN_IMPERSONATION_CHAIN":
        if _function_has_any_call_fragment(
            func_data, CLOUD_FILTER_ABORT_APIS
        ) and _function_has_any_call_fragment(func_data, CLOUD_FILTER_TOKEN_IMPERSONATION_APIS):
            passed = True
    elif rule_id == "CLOUDFILTER_ABORT_LOOP":
        if _function_has_any_call_fragment(func_data, CLOUD_FILTER_ABORT_APIS) and (
            func_data.get("has_loop") or metrics.get("jump_count", 0) > 0
        ):
            passed = True
    elif rule_id == "CLOUDFILTER_REGISTRY_POLICY_LINK_CHAIN":
        has_registry_link = (
            _function_has_any_call_fragment(func_data, CLOUD_FILTER_REGISTRY_LINK_APIS)
            or "symboliclinkvalue" in assembly
        )
        has_registry_security = _function_has_any_call_fragment(
            func_data, CLOUD_FILTER_REGISTRY_SECURITY_APIS
        )
        has_registry_write = _function_has_any_call_fragment(func_data, CLOUD_FILTER_REGISTRY_APIS)
        has_policy_strings = all(
            marker in assembly for marker in ("cloudfiles", "blockedapps", "volatile environment")
        )
        if (has_registry_link and has_registry_security and has_registry_write) or (
            has_policy_strings and (has_registry_link or has_registry_security)
        ):
            passed = True
    elif rule_id == "WER_ENVIRONMENT_PROCESS_CHAIN":
        has_pipe_session = _function_has_any_call_fragment(
            func_data, {"getnamedpipeserversessionid"}
        )
        has_process_launch = _function_has_any_call_fragment(
            func_data,
            {"createprocessasuser", "createprocessasusera", "createprocessasuserw"},
        )
        has_wer_strings = any(
            marker in assembly for marker in ("queuereporting", "wermgr.exe", "miniplasmawerpipe")
        )
        if has_pipe_session and has_process_launch and has_wer_strings:
            passed = True
    elif rule_id == "BYOVD_PORT_IO_MSR_INSTRUCTIONS":
        if _assembly_matches_any(assembly, PRIVILEGED_HW_INSTRUCTION_PATTERNS):
            passed = True
    elif rule_id == "BYOVD_PCI_CONFIG_UNVALIDATED_DISPATCH":
        if _function_has_any_call_fragment(
            func_data, PCI_CONFIG_APIS
        ) and not _function_has_any_call_fragment(func_data, ACCESS_CHECK_APIS):
            passed = True
    elif rule_id == "APPLE_MIE_ZALLOC_RO_MUT_PREPATCH_BOUNDS" and (
        _function_name_is_zalloc_ro_mut(func_data)
        and _zalloc_ro_mut_has_prepatch_wrap_check_shape(assembly)
        and not _zalloc_ro_mut_has_patched_per_cpu_bounds(assembly)
    ):
        passed = True

    return passed, related_function


def review_disassembled_functions(
    review_functions_list: list[dict[str, Any]],
    disassembled_functions: dict,
    evidence_limit: int,
    arch_target: str = "",
    binary_format: str = "",
) -> dict[str, list]:
    """Run all FUNCTION_REVIEWS against disassembled function metadata.

    ``arch_target`` and ``binary_format`` (the metadata's ``llvm_target_tuple``
    and ``binary_type``) let a rule read call-site arguments; without them
    those rules assume the unknown argument.
    """
    if not disassembled_functions:
        return {}

    results: defaultdict[str, list] = defaultdict(list)
    found_cid: defaultdict[str, int] = defaultdict(int)
    resolver_helpers = _collect_dynamic_resolver_helpers(disassembled_functions)

    for review_group in review_functions_list:
        for rule_id, rule_obj in review_group.items():
            for func_key, func_data in disassembled_functions.items():
                if found_cid[rule_id] >= evidence_limit:
                    continue
                check_type = rule_obj.get("check_type")
                passed = False
                related_function = ""
                if check_type == "function_flag":
                    check_field = rule_obj.get("check_field")
                    if func_data.get(check_field):
                        passed = True
                elif check_type == "function_metric":
                    passed = _evaluate_function_metric(rule_obj, func_data)
                elif check_type == "function_analysis":
                    passed, related_function = _evaluate_function_analysis(
                        rule_id, func_data, resolver_helpers, arch_target, binary_format
                    )
                if passed:
                    evidence = {
                        "function": func_data.get("name", func_key),
                        "address": func_data.get("address"),
                        "snippet": func_data.get("assembly", "").split("\n")[0],
                    }
                    if related_function:
                        evidence["related_function"] = related_function
                    results[rule_id].append(evidence)
                    found_cid[rule_id] += 1
    return results
