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
import struct

# DRIVER_OBJECT.MajorFunction lives at offset 0x70 on x64 and each slot is a
# pointer, so the device-control dispatch slots are at fixed offsets. The
# structure is narrower on x86 (32-bit pointers throughout), putting the array
# at 0x38 with a 4-byte stride; a 32-bit driver installing its dispatch routine
# is invisible to the x64 offsets alone.
MAJOR_FUNCTION_OFFSET_X64 = 0x70
MAJOR_FUNCTION_OFFSET_X86 = 0x38
IRP_MJ_DEVICE_CONTROL = 0x0E
IRP_MJ_INTERNAL_DEVICE_CONTROL = 0x0F

DISPATCH_SLOTS = {
    MAJOR_FUNCTION_OFFSET_X64 + IRP_MJ_DEVICE_CONTROL * 8: "IRP_MJ_DEVICE_CONTROL",
    MAJOR_FUNCTION_OFFSET_X64
    + IRP_MJ_INTERNAL_DEVICE_CONTROL * 8: "IRP_MJ_INTERNAL_DEVICE_CONTROL",
}

DISPATCH_SLOTS_X86 = {
    MAJOR_FUNCTION_OFFSET_X86 + IRP_MJ_DEVICE_CONTROL * 4: "IRP_MJ_DEVICE_CONTROL",
    MAJOR_FUNCTION_OFFSET_X86
    + IRP_MJ_INTERNAL_DEVICE_CONTROL * 4: "IRP_MJ_INTERNAL_DEVICE_CONTROL",
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

# An immediate operand in any of the three rendering styles described above
# IMMEDIATE_RE, used by the switch-lowering patterns below.
_IMMEDIATE_TOKEN = r"#?(?:0x[0-9a-f]+|[0-9][0-9a-f]*h|[0-9]+)"

# A compare chain is only one of the two shapes a `switch (IoControlCode)` takes.
# Once a dispatch routine handles more than a handful of codes, MSVC stops
# emitting one compare per case and lowers the switch to a subtract-and-range
# check feeding a jump table:
#
#     sub  eax, 0x80006498     ; index = code - lowest case
#     cmp  eax, 0x24           ; how far the case range extends
#     ja   default_case        ; unsigned bounds check
#
# Only the base survives as an immediate, so a compare-only scan recovers a
# single control code and silently misses every other case in the table. The
# range check tells us how far the case span reaches, which is enough to
# enumerate the siblings.
SWITCH_BASE_RE = re.compile(
    rf"^\s*(?P<op>sub|add)\s+(?P<reg>[a-z][a-z0-9]*)\s*,\s*(?P<imm>{_IMMEDIATE_TOKEN})\s*$"
)
SWITCH_RANGE_RE = re.compile(
    rf"^\s*cmp\s+(?P<reg>[a-z][a-z0-9]*)\s*,\s*(?P<imm>{_IMMEDIATE_TOKEN})\s*$"
)
# The unsigned above-comparison branch to the default case. A signed form (jg)
# would mean the value is not being treated as an unsigned switch index.
SWITCH_BOUND_JUMP_RE = re.compile(r"^\s*(?:ja|jae|jnbe|jnb)\b")

# How far a recovered case span may reach before it is treated as noise rather
# than a switch. Function codes are 12 bits and a control code steps by 4 per
# function, so 0x400 covers a 256-case dispatch routine — far larger than any
# real driver — while rejecting a `sub`/`cmp` pair that merely happens to sit
# next to each other in arithmetic code.
SWITCH_MAX_CASE_SPAN = 0x400

# Cases in a control-code switch differ by whole function codes, so successive
# cases are 4 apart; the two low bits are the transfer method, which a driver
# does not vary across a contiguous case range. Enumerating every index in the
# span instead of every fourth one would invent three bogus codes per real one.
CONTROL_CODE_STRIDE = 4

# Runs of control codes in .rdata/.data are dispatch tables walked in a loop, so
# the entries are never compared against an immediate and cannot be recovered
# from disassembly. Three consecutive DWORDs sharing one vendor device type is
# short enough to catch small tables and long enough that a coincidental run of
# unrelated constants is unlikely.
IOCTL_TABLE_MIN_RUN = 3
IOCTL_TABLE_SECTIONS = (".rdata", ".data")

# Kernel object namespace prefixes, matched case-insensitively against the
# extracted strings to name the objects a driver's IOCTLs are reached through.
DRIVER_OBJECT_PATH_PREFIXES = {
    "device_names": ("\\device\\",),
    "symbolic_links": ("\\dosdevices\\", "\\??\\"),
    "client_device_paths": ("\\\\.\\",),
}

# A printf-style specifier, with `%%` (a literal percent) excluded.
FORMAT_SPECIFIER_RE = re.compile(r"%(?!%)[-+ #0-9.*]*[hlLwIq]*[diouxXeEfgGcCsSpn]")

# METHOD_NEITHER hands the driver the caller's raw user-mode pointers instead of
# a copied or mapped buffer, so the handler must validate them itself with
# ProbeForRead / ProbeForWrite. Importing neither means nothing in the image can
# be doing that validation.
USER_BUFFER_PROBE_IMPORTS = {
    "probeforread",
    "probeforwrite",
    "mmprobeandlockpages",
    "mmprobeandlockprocesspages",
    "mmprobeandlockselectedpages",
}

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


# The x86 form of the same store. A 32-bit dispatch slot holds a 32-bit function
# pointer, so here it is `dword ptr` that is allowed and `qword ptr` that is not.
_DISPATCH_STORE_TEMPLATE_X86 = (
    r"\bmov\s+(?:dword\s+ptr\s+)?"
    r"\[\s*(?!rsp|rbp|esp|ebp)([a-z][a-z0-9]*)\s*\+\s*"
    r"(?:{hex_off}|{dec_off}|{suffix_off})\s*\]\s*,"
)


def _dispatch_store_patterns(slots=None, template=None):
    """Build one assembly regex per device-control dispatch slot."""
    patterns = {}
    for offset, slot_name in (slots or DISPATCH_SLOTS).items():
        patterns[slot_name] = re.compile(
            (template or _DISPATCH_STORE_TEMPLATE).format(
                hex_off=f"0x{offset:x}",
                dec_off=str(offset),
                suffix_off=f"0*{offset:x}h",
            )
        )
    return patterns


DISPATCH_STORE_PATTERNS = _dispatch_store_patterns()
DISPATCH_STORE_PATTERNS_X86 = _dispatch_store_patterns(
    DISPATCH_SLOTS_X86, _DISPATCH_STORE_TEMPLATE_X86
)

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
    """Find functions that install an IRP_MJ_DEVICE_CONTROL dispatch routine.

    Both the x64 and the x86 DRIVER_OBJECT layouts are matched, since a driver
    built for 32-bit Windows stores through a different offset and stride and
    would otherwise look like it never installs a dispatch routine at all.
    """
    handlers = []
    for func_key, func_data in disassembled_functions.items():
        assembly = func_data.get("assembly", "").lower()
        if not assembly:
            continue
        for patterns, layout in (
            (DISPATCH_STORE_PATTERNS, "x64"),
            (DISPATCH_STORE_PATTERNS_X86, "x86"),
        ):
            for slot_name, pattern in patterns.items():
                if pattern.search(assembly):
                    handlers.append(
                        {
                            "slot": slot_name,
                            "layout": layout,
                            "function": func_data.get("name", func_key),
                            "address": func_data.get("address"),
                        }
                    )
    return handlers


def _parse_immediate(token: str):
    """Parse one immediate operand in any of the disassembler's integer bases."""
    if not token:
        return None
    token = token.lstrip("#")
    try:
        if token.startswith("0x"):
            return int(token, 16)
        if token.endswith("h"):
            return int(token[:-1], 16)
        return int(token, 10)
    except ValueError:
        return None


def extract_switch_ioctl_codes(func_data: dict) -> list:
    """Recover the case values of a jump-table `switch (IoControlCode)`.

    A compare chain names every case explicitly, but the subtract-and-range-check
    lowering names only the lowest one. The range check bounds the case span, so
    the remaining cases are recovered by stepping one function code at a time
    from the base. Holes in a sparse switch cannot be told from real cases
    without reading the jump table itself, so these are reported at low
    confidence: the span is an upper bound on the surface, not an exact set.
    """
    assembly = func_data.get("assembly", "").lower()
    if not assembly:
        return []
    lines = assembly.split("\n")
    codes = []
    seen = set()
    for index, line in enumerate(lines):
        base_match = SWITCH_BASE_RE.match(line)
        if not base_match:
            continue
        immediate = _parse_immediate(base_match.group("imm"))
        if immediate is None:
            continue
        # MSVC emits the subtraction either way round: `sub eax, BASE` or the
        # equivalent `add eax, -BASE` rendered as an unsigned 32-bit immediate.
        base = immediate if base_match.group("op") == "sub" else (-immediate) & 0xFFFFFFFF
        if not is_plausible_ioctl(base):
            continue
        span = _bounded_case_span(lines, index + 1, base_match.group("reg"))
        if span is None:
            continue
        for offset in range(0, span + 1, CONTROL_CODE_STRIDE):
            code = base + offset
            if code in seen or not is_plausible_ioctl(code):
                continue
            seen.add(code)
            codes.append(code)
    return codes


def _bounded_case_span(lines: list, start: int, register: str):
    """Return the case span of a switch range check, or None if there is none.

    The range check has to compare the same register the base was subtracted
    from and has to be followed by an unsigned above-branch to the default case.
    Without both, a `sub` and a `cmp` that merely sit near each other in
    arithmetic code would be read as a dispatch table.
    """
    for offset in range(start, min(start + 3, len(lines))):
        range_match = SWITCH_RANGE_RE.match(lines[offset])
        if not range_match:
            continue
        if range_match.group("reg") != register:
            return None
        span = _parse_immediate(range_match.group("imm"))
        if span is None or span <= 0 or span > SWITCH_MAX_CASE_SPAN:
            return None
        if offset + 1 < len(lines) and SWITCH_BOUND_JUMP_RE.match(lines[offset + 1]):
            return span
        return None
    return None


def collect_ioctl_tables(sections) -> list:
    """Recover control codes stored as a dispatch table in a data section.

    A driver that walks an array of ``{code, handler}`` entries never compares
    the code against an immediate, so disassembly cannot see the codes at all.
    Such a table shows up as consecutive DWORDs sharing one device type.

    ``sections`` is an iterable of ``(name, data)`` pairs. Requiring a shared
    vendor device type across the run is what keeps this off the two common
    lookalikes: tables of RVAs, whose high half is a low section-relative value,
    and UTF-16 text, whose high half is ASCII.
    """
    codes = []
    seen = set()
    for name, data in sections or ():
        if not data or str(name).lower() not in IOCTL_TABLE_SECTIONS:
            continue
        usable = len(data) - (len(data) % 4)
        if usable < IOCTL_TABLE_MIN_RUN * 4:
            continue
        words = struct.unpack_from(f"<{usable // 4}I", bytes(data), 0)
        run = []
        for word in words:
            device_type = (word >> 16) & 0xFFFF
            plausible = is_plausible_ioctl(word) and device_type >= VENDOR_DEVICE_TYPE_FLOOR
            if plausible and (not run or ((run[-1] >> 16) & 0xFFFF) == device_type):
                run.append(word)
                continue
            _flush_table_run(run, codes, seen)
            run = [word] if plausible else []
        _flush_table_run(run, codes, seen)
    return codes


def _flush_table_run(run: list, codes: list, seen: set) -> None:
    """Accept a run of DWORDs as a dispatch table once it is long enough."""
    if len(run) < IOCTL_TABLE_MIN_RUN:
        return
    for code in run:
        if code not in seen:
            seen.add(code)
            codes.append(code)


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


def _iter_metadata_strings(metadata: dict):
    """Yield every extracted string value in the metadata, original case kept."""
    for key in ("strings", "informative_strings"):
        for item in metadata.get(key, []) or []:
            value = item.get("value", "") if isinstance(item, dict) else item
            if value:
                yield str(value)


def _is_format_string(value: str) -> bool:
    """Return True for a printf-style template such as ``\\??\\%ls``.

    A driver builds its real name from these at runtime, so reporting the
    template as a concrete device name would name an object that never exists.
    """
    return bool(FORMAT_SPECIFIER_RE.search(value))


def classify_driver_strings(metadata: dict) -> dict:
    """Recover the device names and symbolic links a driver image references.

    The IOCTL surface only becomes actionable once the reviewer knows which
    object to open. Kernel object paths are unambiguous prefixes, so they can be
    picked out of the extracted strings without any disassembly: ``\\Device\\``
    names the device object, ``\\DosDevices\\`` and ``\\??\\`` name the symbolic
    link that makes it reachable from user mode, and ``\\\\.\\`` is the form a
    user-mode client opens. Returns an empty dict when nothing matches.
    """
    buckets = {"device_names": [], "symbolic_links": [], "client_device_paths": []}
    seen = set()
    for value in _iter_metadata_strings(metadata):
        trimmed = value.strip()
        lowered = trimmed.lower()
        if lowered in seen or _is_format_string(trimmed):
            continue
        for bucket, prefixes in DRIVER_OBJECT_PATH_PREFIXES.items():
            if lowered.startswith(prefixes):
                seen.add(lowered)
                buckets[bucket].append(trimmed)
                break
    result = {name: sorted(values) for name, values in buckets.items() if values}
    return result


def collect_driver_ioctls(disassembled_functions: dict, sections=None) -> dict:
    """Summarise the device-control attack surface of a Windows driver.

    Returns an empty dict when nothing driver-like is found, so callers can skip
    attaching the section for ordinary user-mode binaries.
    """
    if not disassembled_functions and not sections:
        return {}

    dispatch_handlers = find_dispatch_handlers(disassembled_functions or {})
    dispatch_functions = {handler["function"] for handler in dispatch_handlers}

    # First pass: collect candidates so device-type clustering can inform
    # confidence before anything is reported.
    candidates = []
    device_type_counts = {}

    def record(code, function_name, address, source):
        device_type_counts.setdefault((code >> 16) & 0xFFFF, set()).add(code)
        candidates.append((code, function_name, address, source))

    for func_key, func_data in (disassembled_functions or {}).items():
        function_name = func_data.get("name", func_key)
        address = func_data.get("address")
        for code in extract_ioctl_codes(func_data):
            record(code, function_name, address, "compare")
        for code in extract_switch_ioctl_codes(func_data):
            record(code, function_name, address, "switch")

    for code in collect_ioctl_tables(sections):
        record(code, None, None, "table")

    ioctls = []
    seen_codes = set()
    for code, function_name, address, source in candidates:
        if code in seen_codes:
            continue
        seen_codes.add(code)
        device_type = (code >> 16) & 0xFFFF
        in_dispatch = function_name in dispatch_functions
        clustered = len(device_type_counts.get(device_type, ())) > 1
        entry = decode_ioctl(code)
        entry["function"] = function_name
        entry["address"] = address
        entry["source"] = source
        # A code the disassembler never saw compared, or one inferred from a case
        # span rather than named outright, is a weaker signal than a literal
        # compare inside the dispatch routine and must not claim high confidence.
        corroborated = in_dispatch or clustered
        if source == "compare":
            entry["confidence"] = "high" if corroborated else "low"
        else:
            entry["confidence"] = "medium" if corroborated else "low"
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
    if unsafe := [entry["code"] for entry in ioctls if entry["method"] == "METHOD_NEITHER"]:
        result["method_neither_codes"] = unsafe
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
