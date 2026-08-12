"""Static recovery of the IOCTL attack surface exposed by Windows kernel drivers.

A kernel driver's user-mode attack surface is the set of control codes accepted
by its ``IRP_MJ_DEVICE_CONTROL`` dispatch routine. Recovering that set turns
driver triage into a data problem: reviewers can spot undocumented control codes
sitting next to documented ones (the LnvMSRIO.sys / CVE-2025-8061 case, where
functions 0x851/0x852 were reachable but absent from the advisory).

This module is deliberately heuristic. It reads the disassembly metadata blint
already produces, so it cannot prove reachability the way runtime probing can.
Control codes are recovered from compare immediates, so a driver that computes
its codes at runtime will be missed.
"""

import re

# DRIVER_OBJECT.MajorFunction lives at offset 0x70 on x64 and each slot is a
# pointer, so the device-control dispatch slots are at fixed offsets.
MAJOR_FUNCTION_OFFSET_X64 = 0x70
IRP_MJ_DEVICE_CONTROL = 0x0E
IRP_MJ_INTERNAL_DEVICE_CONTROL = 0x0F

DISPATCH_SLOTS = {
    MAJOR_FUNCTION_OFFSET_X64 + IRP_MJ_DEVICE_CONTROL * 8: "IRP_MJ_DEVICE_CONTROL",
    MAJOR_FUNCTION_OFFSET_X64
    + IRP_MJ_INTERNAL_DEVICE_CONTROL * 8: "IRP_MJ_INTERNAL_DEVICE_CONTROL",
}

TRANSFER_METHODS = {
    0: "METHOD_BUFFERED",
    1: "METHOD_IN_DIRECT",
    2: "METHOD_OUT_DIRECT",
    3: "METHOD_NEITHER",
}

REQUIRED_ACCESS = {
    0: "FILE_ANY_ACCESS",
    1: "FILE_READ_ACCESS",
    2: "FILE_WRITE_ACCESS",
    3: "FILE_READ_ACCESS|FILE_WRITE_ACCESS",
}

# FILE_DEVICE_UNKNOWN plus the vendor-reserved range are what custom drivers
# overwhelmingly use. Restricting to these keeps unrelated 32-bit constants
# (magic values, timestamps, hashes) out of the recovered surface.
#
# The ceiling matters as much as the floor. Device types of 0xC000 and above
# overlap the NTSTATUS and HRESULT failure space, so without it every
# STATUS_INVALID_PARAMETER (0xC000000D), C++ EH magic (0xE06D7363), division
# reciprocal (0xCCCCCCCD) and -1 sentinel in the image decodes as a "control
# code". A driver using a documented device type below 0x8000 other than
# FILE_DEVICE_UNKNOWN will be missed; that is the deliberate trade.
FILE_DEVICE_UNKNOWN = 0x22
VENDOR_DEVICE_TYPE_FLOOR = 0x8000
VENDOR_DEVICE_TYPE_CEILING = 0xBFFF

# Microsoft reserves function codes 0x000-0x7FF and leaves 0x800-0xFFF to third
# parties, so a custom driver's codes sit at or above 0x800. Requiring this drops
# constants that merely happen to fall in the vendor device-type range, notably
# 0x80000000 (INT_MIN / sign bit), which is otherwise everywhere in ordinary
# arithmetic. Both documented CVE code sets satisfy it: LnvMSRIO.sys uses
# 0x841/0x842/0x851/0x852 and ThrottleStop.sys uses 0x926/0x927. A driver that
# ignores the convention and uses a low function code will be missed.
VENDOR_FUNCTION_CODE_FLOOR = 0x800

# A driver's dispatch routine compares the control code, so `switch
# (IoControlCode)` lowers to cmp/sub/add chains. A user-mode client instead
# passes the code as the second argument to DeviceIoControl, which materialises
# as `mov edx, <code>`.
DISPATCH_MNEMONIC_RE = re.compile(r"^\s*(?:cmp|sub|add|xor)\b")
CLIENT_MNEMONIC_RE = re.compile(r"^\s*mov\b")

# The base used for immediates is a disassembler setting, not a property of the
# architecture. nyxstone's IntegerBase option renders the same instruction three
# ways, and blint defaults to Dec (see disassemble_functions immediate_style):
#   Dec        mov edx, 2147509400
#   HexPrefix  mov edx, 0x80006498
#   HexSuffix  mov edx, 80006498h
# All three must be recognised, or a caller that changes the style silently gets
# no results. AArch64 additionally prefixes immediates with '#'.
IMMEDIATE_RE = re.compile(r"(?<![\w.$])#?(0x[0-9a-f]+|[0-9][0-9a-f]*h|[0-9]{5,10})\b")

# Bracketed memory operands hold frame offsets and displacements, never control
# codes, so they are removed before scanning a line for immediates.
MEMORY_OPERAND_RE = re.compile(r"\[[^\]]*\]")

# Match only a pointer-sized *store* whose destination is the dispatch slot:
# `mov [rcx+0xe0], rax` / `mov qword ptr [rcx + 224], rax`.
#
# Three things keep ordinary code out. The trailing `],` requires the memory
# operand to be the destination, so loads (`mov rbx, qword ptr [rbp+232]`) are
# rejected. The base register cannot be rsp/rbp/esp/ebp, because a DRIVER_OBJECT
# pointer is never addressed through the stack frame the way a local at the same
# offset is. And a `dword ptr` size hint is rejected, since a dispatch slot holds
# a 64-bit function pointer. The offset itself is matched in all three rendering
# styles (0xe0 / 224 / 0e0h) for the reasons given above IMMEDIATE_RE.
_DISPATCH_STORE_TEMPLATE = (
    r"\bmov\s+(?:qword\s+ptr\s+)?"
    r"\[\s*(?!rsp|rbp|esp|ebp)([a-z][a-z0-9]*)\s*\+\s*"
    r"(?:{hex_off}|{dec_off}|{suffix_off})\s*\]\s*,"
)


def _dispatch_store_patterns():
    """Build one assembly regex per device-control dispatch slot."""
    patterns = {}
    for offset, slot_name in DISPATCH_SLOTS.items():
        patterns[slot_name] = re.compile(
            _DISPATCH_STORE_TEMPLATE.format(
                hex_off=f"0x{offset:x}",
                dec_off=str(offset),
                suffix_off=f"0*{offset:x}h",
            )
        )
    return patterns


DISPATCH_STORE_PATTERNS = _dispatch_store_patterns()

# A kernel driver runs in the native subsystem; user-mode PE files do not.
NATIVE_SUBSYSTEM_MARKERS = ("native",)

# Imports that only a kernel-mode image resolves, used as a fallback when the
# subsystem field is missing or unhelpful.
KERNEL_ONLY_IMPORTS = {
    "iocreatedevice",
    "iocreatedevicesecure",
    "iocreatesymboliclink",
    "iodeletedevice",
    "iofcompleterequest",
    "iocompleterequest",
    "kegetcurrentirql",
    "exallocatepool",
    "exallocatepool2",
    "exallocatepoolwithtag",
    "psgetcurrentprocessid",
    "mmgetsystemroutineaddress",
    "wdfversionbind",
}


def is_kernel_driver(metadata: dict) -> bool:
    """Return True when the metadata describes a Windows kernel-mode image.

    The IOCTL surface is only meaningful for kernel drivers. Without this gate a
    user-mode PE can produce spurious dispatch-slot hits from ordinary struct
    accesses that happen to land on the same offsets.
    """
    if not metadata:
        return False
    subsystem = str(metadata.get("subsystem", "")).lower()
    if any(marker in subsystem for marker in NATIVE_SUBSYSTEM_MARKERS):
        return True
    import_names = set()
    for entry in metadata.get("imports", []) or []:
        name = entry.get("name") if isinstance(entry, dict) else entry
        if not name:
            continue
        # PE imports are qualified as `library::function`.
        normalized = str(name).strip().lower().rsplit("::", 1)[-1].lstrip("_")
        import_names.add(normalized)
    return bool(import_names & KERNEL_ONLY_IMPORTS)


def decode_ioctl(code: int) -> dict:
    """Decode a Windows IOCTL control code into its CTL_CODE components."""
    return {
        "code": f"0x{code:08X}",
        "device_type": f"0x{(code >> 16) & 0xFFFF:04X}",
        "function_code": f"0x{(code >> 2) & 0xFFF:03X}",
        "method": TRANSFER_METHODS[code & 0x3],
        "access": REQUIRED_ACCESS[(code >> 14) & 0x3],
    }


def is_plausible_ioctl(code: int) -> bool:
    """Return True when an immediate looks like a custom-driver control code."""
    if code <= 0xFFFF or code > 0xFFFFFFFF:
        return False
    if ((code >> 2) & 0xFFF) < VENDOR_FUNCTION_CODE_FLOOR:
        return False
    device_type = (code >> 16) & 0xFFFF
    if device_type == FILE_DEVICE_UNKNOWN:
        return True
    return VENDOR_DEVICE_TYPE_FLOOR <= device_type <= VENDOR_DEVICE_TYPE_CEILING


def find_dispatch_handlers(disassembled_functions: dict) -> list:
    """Find functions that install an IRP_MJ_DEVICE_CONTROL dispatch routine."""
    handlers = []
    for func_key, func_data in disassembled_functions.items():
        assembly = func_data.get("assembly", "").lower()
        if not assembly:
            continue
        for slot_name, pattern in DISPATCH_STORE_PATTERNS.items():
            if pattern.search(assembly):
                handlers.append(
                    {
                        "slot": slot_name,
                        "function": func_data.get("name", func_key),
                        "address": func_data.get("address"),
                    }
                )
    return handlers


def _immediates_in_line(line: str) -> list:
    """Return integer immediates in one instruction, in either base.

    Memory operands are stripped first so stack displacements cannot be mistaken
    for control codes.
    """
    stripped = MEMORY_OPERAND_RE.sub("", line)
    values = []
    for match in IMMEDIATE_RE.finditer(stripped):
        token = match.group(1)
        try:
            if token.startswith("0x"):
                values.append(int(token, 16))
            elif token.endswith("h"):
                values.append(int(token[:-1], 16))
            else:
                values.append(int(token, 10))
        except ValueError:
            continue
    return values


def _extract_codes(func_data: dict, mnemonic_re) -> list:
    """Recover plausible control codes from instructions matching a mnemonic."""
    assembly = func_data.get("assembly", "").lower()
    if not assembly:
        return []
    codes = []
    seen = set()
    for line in assembly.split("\n"):
        if not mnemonic_re.match(line):
            continue
        for value in _immediates_in_line(line):
            if value in seen or not is_plausible_ioctl(value):
                continue
            seen.add(value)
            codes.append(value)
    return codes


def extract_ioctl_codes(func_data: dict) -> list:
    """Recover control codes a driver dispatch routine compares against."""
    return _extract_codes(func_data, DISPATCH_MNEMONIC_RE)


def extract_client_ioctl_codes(func_data: dict) -> list:
    """Recover control codes a user-mode client passes to DeviceIoControl."""
    return _extract_codes(func_data, CLIENT_MNEMONIC_RE)


def collect_client_ioctls(disassembled_functions: dict) -> list:
    """Collect vendor-range control codes issued by a user-mode client.

    Returns one entry per distinct code, with the function that references it.
    """
    if not disassembled_functions:
        return []
    results = []
    seen = set()
    for func_key, func_data in disassembled_functions.items():
        for code in extract_client_ioctl_codes(func_data):
            if code in seen:
                continue
            seen.add(code)
            entry = decode_ioctl(code)
            entry["function"] = func_data.get("name", func_key)
            entry["address"] = func_data.get("address")
            results.append(entry)
    results.sort(key=lambda entry: entry["code"])
    return results


def collect_driver_ioctls(disassembled_functions: dict) -> dict:
    """Summarise the device-control attack surface of a Windows driver.

    Returns an empty dict when nothing driver-like is found, so callers can skip
    attaching the section for ordinary user-mode binaries.
    """
    if not disassembled_functions:
        return {}

    dispatch_handlers = find_dispatch_handlers(disassembled_functions)
    dispatch_functions = {handler["function"] for handler in dispatch_handlers}

    # First pass: collect candidates so device-type clustering can inform
    # confidence before anything is reported.
    candidates = []
    device_type_counts = {}
    for func_key, func_data in disassembled_functions.items():
        function_name = func_data.get("name", func_key)
        for code in extract_ioctl_codes(func_data):
            device_type = (code >> 16) & 0xFFFF
            device_type_counts.setdefault(device_type, set()).add(code)
            candidates.append((code, function_name, func_data.get("address")))

    ioctls = []
    seen_codes = set()
    for code, function_name, address in candidates:
        if code in seen_codes:
            continue
        seen_codes.add(code)
        device_type = (code >> 16) & 0xFFFF
        in_dispatch = function_name in dispatch_functions
        clustered = len(device_type_counts.get(device_type, ())) > 1
        entry = decode_ioctl(code)
        entry["function"] = function_name
        entry["address"] = address
        entry["confidence"] = "high" if in_dispatch or clustered else "low"
        ioctls.append(entry)

    if not ioctls and not dispatch_handlers:
        return {}

    ioctls.sort(key=lambda entry: entry["code"])
    _flag_weak_access(ioctls)
    result = {
        "dispatch_handlers": dispatch_handlers,
        "ioctls": ioctls,
        "device_types": sorted(f"0x{dt:04X}" for dt in device_type_counts),
    }
    return result


def _flag_weak_access(ioctls: list) -> None:
    """Annotate control codes whose declared access is weaker than it should be.

    Two shapes are marked. FILE_ANY_ACCESS lets a handle opened without write
    permission reach the handler at all. Consecutive function codes that declare
    identical access are the read/write sibling pattern seen in ThrottleStop.sys
    (CVE-2025-7771), where the physical-memory *write* code 0x8000649C still
    declares FILE_READ_ACCESS and is therefore reachable from a read-only handle.
    """
    by_function = {}
    for entry in ioctls:
        if entry["access"] == "FILE_ANY_ACCESS":
            entry["weak_access"] = "FILE_ANY_ACCESS"
        key = (entry["device_type"], int(entry["function_code"], 16))
        by_function[key] = entry

    for (device_type, function_code), entry in by_function.items():
        sibling = by_function.get((device_type, function_code + 1))
        if sibling is None:
            continue
        # A read/write pair should declare different access rights; identical
        # read-only access on both means the sibling under-declares.
        if entry["access"] == sibling["access"] == "FILE_READ_ACCESS":
            sibling["weak_access"] = "read_write_pair_declares_read_only"
