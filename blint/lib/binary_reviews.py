"""Whole-binary review heuristics.

Some findings are only expressible over the entire image rather than a single
symbol or function, because the signal is the *absence* of something. A kernel
driver that exposes a hardware primitive is unremarkable on its own; a driver
that exposes one while importing no access-check API and creating its device
object without a security descriptor is the "no authorization check" flaw.
"""

import re
from collections import defaultdict
from typing import Any

from blint.lib.driver_ioctl import (
    USER_BUFFER_PROBE_IMPORTS,
    _normalized_callee,
    collect_client_ioctls,
    is_kernel_driver,
)
from blint.lib.implant_reviews import (
    COVERT_CHANNEL_DEVICES,
    IMPLANT_RULE_EVALUATORS,
    evaluate_implant_rule,
)

# Primitives that grant a caller direct hardware or physical-memory reach.
HARDWARE_PRIMITIVE_IMPORTS: set[str] = {
    "halgetbusdata",
    "halgetbusdatabyoffset",
    "halsetbusdata",
    "halsetbusdatabyoffset",
    "haltranslatebusaddress",
    "halassignslotresources",
    "mmmapiospace",
    "mmmapiospaceex",
    "zwmapviewofsection",
    "mmmaplockedpages",
    "mmmaplockedpagesspecifycache",
    "mmgetphysicaladdress",
    "iogetdmaadapter",
}

# Instructions that expose the same class of primitive without any import edge,
# because MSR and port I/O access are compiler intrinsics.
HARDWARE_PRIMITIVE_INSTRUCTIONS: tuple[str, ...] = (
    "rdmsr",
    "wrmsr",
    "rdpmc",
    "invd",
    "wbinvd",
)
HARDWARE_PRIMITIVE_INSTRUCTION_RE = re.compile(
    r"\b(" + "|".join(HARDWARE_PRIMITIVE_INSTRUCTIONS) + r")\b"
)

# Importing any of these means the driver at least attempts a caller check.
ACCESS_CHECK_IMPORTS: set[str] = {
    "sesingleprivilegecheck",
    "seaccesscheck",
    "seprivilegecheck",
    "seprivilegeobjectaudit",
    "sequeryauthenticationidtoken",
    "zwqueryinformationtoken",
    "ntqueryinformationtoken",
    "rtlvalidrelativesecuritydescriptor",
    "rtlvalidsecuritydescriptor",
    "iovalidatedeviceiocontrolaccess",
    "obreferenceobjectbyhandle",
    "iogetrequestorprocessid",
    "sesinglelegacyprivilegecheck",
}

# Creating the device object through these entry points attaches an SDDL-based
# security descriptor, which is the supported way to restrict access.
SECURE_DEVICE_CREATION_IMPORTS: set[str] = {
    "iocreatedevicesecure",
    "wdmlibiocreatedevicesecure",
    "wdfdeviceinitassignsddlstring",
}

DEVICE_CREATION_IMPORTS: set[str] = {
    "iocreatedevice",
    "iocreatesymboliclink",
    "wdfdevicecreate",
    "iocreatedevicesecure",
    "wdmlibiocreatedevicesecure",
}

# User-mode APIs needed to reach a driver's device object from a client.
DEVICE_OPEN_IMPORTS: set[str] = {
    "createfilea",
    "createfilew",
    "createfile2",
    "ntopenfile",
    "ntcreatefile",
}
DEVICE_IOCTL_IMPORTS: set[str] = {
    "deviceiocontrol",
    "ntdeviceiocontrolfile",
    "zwdeviceiocontrolfile",
}

# ---------------------------------------------------------------------------
# CALL_SITE_CONSTANT_ARGUMENTS: naming *what* reaches a resolved call.
#
# Linkage-level capability rules (CRYPTO_API and its siblings) can only say a
# binary is linked to an API. The call-site arguments block says what the
# binary actually passes: the tables below map the resolved callees whose
# named argument carries a security-relevant value, keyed by the normalized
# callee name, holding that argument's 0-based position (the block's own
# indexing). A callee missing from every table simply has no interpretable
# position; absence from a table proves nothing about the API.
# ---------------------------------------------------------------------------

# Callees whose named argument is the path being opened. Only an entry whose
# constant resolved to a string in the image reports — a path assembled at
# runtime is the stack-string recovery's evidence, not this rule's. The wide
# forms (CreateFileW, CreateFile2) reach this table through the pointer
# resolver's UTF-16LE reading; their literals must still clear the decoder's
# four-character minimum, so a three-character wide name stays out.
CALLSITE_PATH_ARGUMENTS: dict[str, int] = {
    # lpFileName is the first parameter of every CreateFile form.
    "createfilea": 0,
    "createfilew": 0,
    "createfile2": 0,
    "open": 0,
    "open64": 0,
    "fopen": 0,
    "fopen64": 0,
}

# CommonCrypto kCCAlgorithm* values (documented in CommonCrypto.h); the
# argument position they travel in differs per callee below.
CALLSITE_CRYPTO_ALGORITHM_VALUES: dict[int, str] = {
    0: "AES",
    1: "DES",
    2: "3DES",
    3: "CAST",
    4: "RC4",
    5: "RC2",
    6: "Blowfish",
}
CALLSITE_CRYPTO_ALGORITHM_INT_ARGUMENTS: dict[str, int] = {
    "cccrypt": 1,
    "cccryptorcreate": 1,
}
# Callees that take the algorithm as a *name*: only an entry whose constant
# resolved to a string reports, and the string is the algorithm name itself.
# BCryptOpenAlgorithmProvider's pszAlgId is a wide string; the pointer
# resolver reads it as UTF-16LE, subject to the same four-character minimum
# (so L"AES" and L"MD5" stay below the bar while L"SHA256" reports).
CALLSITE_CRYPTO_ALGORITHM_STRING_ARGUMENTS: dict[str, int] = {
    "bcryptopenalgorithmprovider": 1,
    "evp_get_cipherbyname": 0,
}

# Byte-order callees: a constant argument is the port in host byte order.
# Compilers inline these to a byte-swap more often than not, so a hit is
# real but the absence of one proves nothing.
CALLSITE_PORT_ARGUMENTS: dict[str, int] = {
    "htons": 0,
    "ntohs": 0,
}


def _reusable_call_site_block(metadata: dict) -> list[dict] | None:
    """The exported call-site block when it can stand in for the recovery.

    Returns the entries — an empty list included, which is an answer and not
    an absence — when the block was built and is complete, and None when the
    caller must run the per-function recovery itself. A block the parse never
    built has no coverage; a block that hit its entry bound is missing
    entries, and a control code dropped by that bound must not read as a
    control code the image does not issue.
    """
    coverage = metadata.get("call_site_arguments_coverage")
    if not isinstance(coverage, dict) or coverage.get("entries_truncated"):
        return None
    return metadata.get("call_site_arguments") or []


def _evaluate_callsite_constant_arguments(metadata: dict) -> list[dict]:
    """Surface the recovered constants that name what reaches a resolved call.

    Reads the exported ``call_site_arguments`` block and interprets
    only the argument positions the tables above name, so every emitted
    value is anchored to a documented ABI position: an integer is reported
    only where it matches a documented constant, a string only where the
    callee's argument is that string. This is what lets a capability finding
    say *which* paths are opened, *which* algorithm reaches a crypto call
    and *which* port a constant encodes, instead of only that the API is
    linked.
    """
    evidence: list[dict] = []
    seen: set[tuple] = set()
    for entry in metadata.get("call_site_arguments") or []:
        callee = _normalized_callee(entry.get("callee"))
        argument = entry.get("argument")
        value = entry.get("value")
        string = entry.get("string")
        base = {
            "callee": entry.get("callee"),
            "argument": argument,
            "function": (entry.get("functions") or [None])[0],
        }
        if callee in CALLSITE_PATH_ARGUMENTS:
            if argument != CALLSITE_PATH_ARGUMENTS[callee] or not string:
                continue
            item = {
                **base,
                "kind": "path",
                "path": string,
                "detail": (
                    f"The dataflow holds the path '{string}' in {entry.get('callee')}'s "
                    f"path argument at a resolved call site: the image opens it by name."
                ),
            }
        elif callee in CALLSITE_CRYPTO_ALGORITHM_INT_ARGUMENTS:
            if argument != CALLSITE_CRYPTO_ALGORITHM_INT_ARGUMENTS[callee]:
                continue
            algorithm = (
                CALLSITE_CRYPTO_ALGORITHM_VALUES.get(value) if isinstance(value, int) else None
            )
            if not algorithm:
                continue
            item = {
                **base,
                "kind": "crypto_algorithm",
                "algorithm": algorithm,
                "detail": (
                    f"The dataflow holds algorithm constant {algorithm} (argument {argument}) "
                    f"at a resolved {entry.get('callee')} call site."
                ),
            }
        elif callee in CALLSITE_CRYPTO_ALGORITHM_STRING_ARGUMENTS:
            if argument != CALLSITE_CRYPTO_ALGORITHM_STRING_ARGUMENTS[callee] or not string:
                continue
            item = {
                **base,
                "kind": "crypto_algorithm",
                "algorithm": string,
                "detail": (
                    f"The dataflow holds algorithm name '{string}' at a resolved "
                    f"{entry.get('callee')} call site."
                ),
            }
        elif callee in CALLSITE_PORT_ARGUMENTS:
            if argument != CALLSITE_PORT_ARGUMENTS[callee] or not isinstance(value, int):
                continue
            port = value & 0xFFFF
            item = {
                **base,
                "kind": "port",
                "port": port,
                "detail": (
                    f"The dataflow holds {port} as the port argument of a resolved "
                    f"{entry.get('callee')} call site."
                ),
            }
        else:
            continue
        key = (
            item["kind"],
            item["callee"],
            item.get("path") or item.get("algorithm") or item.get("port"),
        )
        if key in seen:
            continue
        seen.add(key)
        evidence.append(item)
    return evidence


# Installing and starting a kernel service is how a BYOVD chain loads its driver.
SERVICE_MANAGER_IMPORTS: set[str] = {
    "openscmanagera",
    "openscmanagerw",
}
SERVICE_CREATE_IMPORTS: set[str] = {
    "createservicea",
    "createservicew",
    "startservicea",
    "startservicew",
    "startserviceclla",
    "startservicectrldispatcher",
    "ntloaddriver",
    "zwloaddriver",
}

# Presence of an explicit SDDL string is equivalent evidence of restriction.
SDDL_MARKERS: tuple[str, ...] = (
    "d:p(a;;g",
    "d:p(a;;fa",
    "file_device_secure_open",
    "sddl",
)


def _normalize(name: Any) -> str:
    """Lowercase an import name and strip decoration for set membership tests.

    PE metadata qualifies imports with the originating library, for example
    ``ntoskrnl.exe::IoCreateDevice`` or ``KERNEL32.dll::DeviceIoControl``, so the
    library prefix has to be dropped before comparing against a bare API name.
    """
    if not name:
        return ""
    normalized = str(name).strip().lower()
    if "::" in normalized:
        normalized = normalized.rsplit("::", 1)[-1]
    return normalized.strip().lstrip("_")


def _collect_import_names(metadata: dict) -> set[str]:
    """Gather normalized import names from the metadata."""
    names: set[str] = set()
    for entry in metadata.get("imports", []) or []:
        if isinstance(entry, dict):
            normalized = _normalize(entry.get("name"))
        else:
            normalized = _normalize(entry)
        if normalized:
            names.add(normalized)
    return names


def _collect_string_values(metadata: dict) -> list[str]:
    """Gather informative and plain string values, lowercased."""
    values: list[str] = []
    for key in ("informative_strings", "strings"):
        for item in metadata.get(key, []) or []:
            if isinstance(item, dict):
                value = item.get("value", "")
            else:
                value = str(item)
            if value:
                values.append(value.lower())
    return values


def _has_hardware_primitive(import_names: set[str], metadata: dict) -> str:
    """Return the evidence for a hardware primitive, if any."""
    matched = sorted(import_names & HARDWARE_PRIMITIVE_IMPORTS)
    if matched:
        return matched[0]
    for func_data in (metadata.get("disassembled_functions") or {}).values():
        assembly = func_data.get("assembly", "").lower()
        if match := HARDWARE_PRIMITIVE_INSTRUCTION_RE.search(assembly):
            return match.group(1)
    return ""


def _device_object_names(metadata: dict) -> dict:
    """Return the device names and symbolic links recovered from the strings."""
    interface = metadata.get("driver_interface") or {}
    names = {}
    for key in ("device_names", "symbolic_links"):
        if values := interface.get(key):
            names[key] = values
    return names


def _client_device_paths(metadata: dict) -> list[str]:
    """Return the ``\\\\.\\`` device paths the image opens.

    Stack-built paths are included alongside the ones recovered from the strings,
    because an implant that assembles its device name at runtime leaves nothing
    in ``driver_interface`` to find.
    """
    paths = list((metadata.get("driver_interface") or {}).get("client_device_paths") or [])
    for entry in metadata.get("stack_strings") or []:
        value = str(entry.get("value", "")).strip()
        if value.startswith("\\\\.\\") and value not in paths:
            paths.append(value)
    return paths


def _is_covert_channel_path(path: str) -> bool:
    """Return True when a device path names a hypervisor or IPC channel."""
    leaf = str(path).strip()[4:].split("\\", 1)[0].strip().lower()
    return leaf in COVERT_CHANNEL_DEVICES


# ---------------------------------------------------------------------------
# W5.4: kernel-adjacent user-mode surface. Every rule here is a *review*
# signal, not a findings rule, by measurement: the benign populations
# (System32 slice + tiers 0/1) carry injection chains on debug and
# Sysinternals tooling, ETW/AMSI patch shapes on OS components and
# Microsoft clients, and persistence surfaces on the very tools that
# manage persistence. The rules give a reviewer the shape and name the
# primitives; they never render a verdict on their own.
# ---------------------------------------------------------------------------

# The three cross-process injection stages (plan 04/D). Each set holds the
# imports that realize the stage; the Ex/Nt forms take a target-process
# handle, which is what makes them cross-process by construction.
INJECTION_STAGES: dict[str, set[str]] = {
    "remote_allocation": {"virtualallocex", "ntallocatevirtualmemory"},
    "remote_write": {
        "writeprocessmemory",
        "ntwritevirtualmemory",
        "ntmapviewofsection",
        "zwmapviewofsection",
    },
    "remote_execution": {
        "createremotethread",
        "createremotethreadex",
        "ntcreatethreadex",
        "rtlcreateuserthread",
        "queueuserapc",
        "ntqueueapcthread",
        "setthreadcontext",
        "resumethread",
    },
}

# ETW trace routines and the primitives that make patching them possible.
ETW_TRACE_IMPORTS: set[str] = {"etweventwrite", "nttraceevent"}
MEMORY_PATCH_IMPORTS: set[str] = {
    "virtualprotect",
    "virtualprotectex",
    "ntprotectvirtualmemory",
    "zwprotectvirtualmemory",
    "writeprocessmemory",
    "ntwritevirtualmemory",
}

# The kernel transition instructions a *user-mode* image has no business
# executing outside ntdll: x86/x64 `syscall`/`sysenter`/`int 2e`, ARM64
# `svc #0`. blint renders immediates in decimal, so `int 2e` also appears
# as `int 46`.
_DIRECT_SYSCALL_RE = re.compile(
    r"\b(?:syscall|sysenter)\b|\bint\s+(?:0x2e|46|2eh)\b|\bsvc\s+#?0\b"
)

# The service-manager import set that can install a service.
SERVICE_MANAGER_IMPORTS_W54: set[str] = {
    "openscmanagera",
    "openscmanagerw",
    "createservicea",
    "createservicew",
}


def _is_ntdll(metadata: dict) -> bool:
    """True when the image is ntdll itself, which owns every syscall stub."""
    from blint.lib.driver_ioctl import _normalized_callee

    candidates = {str(metadata.get("name") or "")}
    version_info = metadata.get("version_info") or {}
    for table in (version_info.get("strings") or {}).values():
        entry = table.get("OriginalFilename") if isinstance(table, dict) else None
        if entry:
            candidates.add(str(entry))
    return any(_normalized_callee(name) == "ntdll.dll" for name in candidates if name)


def _evaluate_usermode_surface(rule_id: str, metadata: dict, import_names: set[str]) -> list[dict]:
    """The W5.4 review-rule evaluators."""

    if rule_id == "USERMODE_DIRECT_SYSCALL":
        # A kernel image never syscalls (it calls ntoskrnl exports), and
        # ntdll is where the transitions belong.
        if is_kernel_driver(metadata) or _is_ntdll(metadata):
            return []
        disassembled = metadata.get("disassembled_functions") or {}
        functions = []
        for func_data in disassembled.values():
            if not isinstance(func_data, dict):
                continue
            assembly = (func_data.get("assembly") or "").lower()
            if assembly and _DIRECT_SYSCALL_RE.search(assembly):
                functions.append(
                    {
                        "function": str(func_data.get("name") or ""),
                        "address": func_data.get("address"),
                    }
                )
                if len(functions) >= 5:
                    break
        if not functions:
            return []
        return [
            {
                "detail": (
                    "User-mode code executes kernel transitions directly "
                    "(syscall/int 2e/svc #0) instead of calling ntdll: the "
                    "shape of direct-syscall evasion, where user-mode API "
                    "hooks never fire."
                ),
                "functions": functions,
            }
        ]

    if rule_id == "PROCESS_INJECTION_PRIMITIVES":
        stages = {
            stage: sorted(import_names & members)
            for stage, members in INJECTION_STAGES.items()
            if import_names & members
        }
        if len(stages) < 2:
            return []
        code_signature = metadata.get("code_signature") or {}
        return [
            {
                "stages": stages,
                "stage_count": len(stages),
                "signing_class": code_signature.get("signing_class"),
                "detail": (
                    "Cross-process allocation/write/execution primitives present: "
                    "the injection chain shape. Debuggers, Sysinternals-style tools "
                    "and RPA software reach two or three stages legitimately - read "
                    "the chain with the image's purpose and signature."
                ),
            }
        ]

    if rule_id == "ETW_PATCH_EVIDENCE":
        trace = sorted(import_names & ETW_TRACE_IMPORTS)
        patch = sorted(import_names & MEMORY_PATCH_IMPORTS)
        if not trace or not patch:
            return []
        return [
            {
                "trace_routines": trace,
                "patch_primitives": patch,
                "detail": (
                    "References ETW trace routines alongside page-protection/"
                    "write primitives - the statically decidable half of ETW "
                    "tampering. Security tooling imports both legitimately."
                ),
            }
        ]

    if rule_id == "AMSI_PATCH_EVIDENCE":
        amsi = metadata.get("amsi_references") or {}
        patch = sorted(import_names & MEMORY_PATCH_IMPORTS)
        if not amsi or not patch:
            return []
        return [
            {
                "amsi_references": amsi.get("references"),
                "patch_primitives": patch,
                "detail": (
                    "References AmsiScanBuffer - the AMSI entry point - alongside "
                    "page-protection/write primitives. Only AMSI providers and AV "
                    "products belong in this shape."
                ),
            }
        ]

    if rule_id == "PERSISTENCE_SURFACE_REFERENCES":
        persistence = metadata.get("persistence_surfaces") or {}
        surfaces = sorted((persistence.get("surfaces") or {}).keys())
        service_apis = sorted(import_names & SERVICE_MANAGER_IMPORTS_W54)
        if len(surfaces) < 2 or not service_apis:
            return []
        return [
            {
                "surfaces": surfaces,
                "service_apis": service_apis,
                "detail": (
                    "Names multiple autostart/extension registry surfaces and "
                    "imports the service-manager APIs that write them - the "
                    "redundant-foothold shape. The tools that manage persistence "
                    "(Autoruns, Group Policy, security products) look the same."
                ),
            }
        ]

    return []


def _evaluate_binary_analysis(rule_id: str, metadata: dict) -> list[dict]:
    """Evaluate rule-specific whole-binary heuristics. Returns evidence list."""
    if rule_id in IMPLANT_RULE_EVALUATORS:
        return evaluate_implant_rule(rule_id, metadata)

    if rule_id in (
        "USERMODE_DIRECT_SYSCALL",
        "PROCESS_INJECTION_PRIMITIVES",
        "ETW_PATCH_EVIDENCE",
        "AMSI_PATCH_EVIDENCE",
        "PERSISTENCE_SURFACE_REFERENCES",
    ):
        return _evaluate_usermode_surface(rule_id, metadata, _collect_import_names(metadata))

    if rule_id == "CALL_SITE_CONSTANT_ARGUMENTS":
        return _evaluate_callsite_constant_arguments(metadata)

    import_names = _collect_import_names(metadata)

    if rule_id == "DRIVER_INSECURE_DEVICE_OBJECT":
        if not import_names & DEVICE_CREATION_IMPORTS:
            return []
        primitive = _has_hardware_primitive(import_names, metadata)
        if not primitive:
            return []
        if import_names & SECURE_DEVICE_CREATION_IMPORTS:
            return []
        if import_names & ACCESS_CHECK_IMPORTS:
            return []
        string_values = _collect_string_values(metadata)
        if any(marker in value for marker in SDDL_MARKERS for value in string_values):
            return []
        evidence = {
            "primitive": primitive,
            "detail": (
                "Device object is created without a security descriptor and the image "
                "imports no access-check API, so the primitive is reachable by any "
                "caller able to open the device."
            ),
        }
        # Naming the object turns the finding into something a reviewer can act
        # on directly, rather than knowing only that some device is exposed.
        evidence.update(_device_object_names(metadata))
        return [evidence]

    if rule_id == "BYOVD_EXPLOIT_CLIENT_DEVICE_ACCESS":
        # Only meaningful for user-mode images; a driver calling these is normal.
        if is_kernel_driver(metadata):
            return []
        if not (import_names & DEVICE_OPEN_IMPORTS and import_names & DEVICE_IOCTL_IMPORTS):
            return []
        client_codes = collect_client_ioctls(
            metadata.get("disassembled_functions") or {},
            arch_target=str(metadata.get("llvm_target_tuple") or ""),
            binary_format=str(metadata.get("binary_type") or "PE"),
            call_site_entries=_reusable_call_site_block(metadata),
        )
        if not client_codes:
            return []
        # The `\\.\` paths name the driver being driven, which is what decides
        # whether this is a vendor utility talking to its own driver or a client
        # reaching for someone else's.
        target_devices = _client_device_paths(metadata)
        # A hypervisor guest-communication device is reached with exactly this
        # import pair and a vendor-range control code, but it is a covert channel
        # rather than a vulnerable driver. Reporting it here would label the
        # capability wrongly; COVERT_CHANNEL_DEVICE_ACCESS names it correctly.
        if target_devices and all(_is_covert_channel_path(path) for path in target_devices):
            return []
        client_evidence: list[dict] = []
        for entry in client_codes:
            item = {
                "code": entry["code"],
                "device_type": entry["device_type"],
                "function_code": entry["function_code"],
                "method": entry["method"],
                "access": entry["access"],
                "function": entry["function"],
            }
            if target_devices:
                item["target_devices"] = target_devices
            client_evidence.append(item)
        return client_evidence

    if rule_id == "BYOVD_DRIVER_LOADER_SERVICE_INSTALL":
        if is_kernel_driver(metadata):
            return []
        loads_driver = bool(import_names & {"ntloaddriver", "zwloaddriver"})
        installs_service = bool(
            import_names & SERVICE_MANAGER_IMPORTS and import_names & SERVICE_CREATE_IMPORTS
        )
        if not (loads_driver or installs_service):
            return []
        return [
            {
                "detail": (
                    "Image installs or starts a kernel-mode service from user space, the "
                    "loading step of a bring-your-own-vulnerable-driver chain."
                ),
                "imports": sorted(
                    import_names
                    & (
                        SERVICE_MANAGER_IMPORTS
                        | SERVICE_CREATE_IMPORTS
                        | {"ntloaddriver", "zwloaddriver"}
                    )
                ),
            }
        ]

    if rule_id == "DRIVER_IOCTL_WEAK_DECLARED_ACCESS":
        driver_ioctls = metadata.get("driver_ioctls") or {}
        weak_evidence: list[dict] = []
        for entry in driver_ioctls.get("ioctls", []):
            if entry.get("weak_access"):
                weak_evidence.append(
                    {
                        "code": entry["code"],
                        "function": entry["function"],
                        "access": entry["access"],
                        "method": entry["method"],
                        "weak_access": entry["weak_access"],
                    }
                )
        return weak_evidence

    if rule_id == "DRIVER_IOCTL_METHOD_NEITHER":
        if not is_kernel_driver(metadata):
            return []
        driver_ioctls = metadata.get("driver_ioctls") or {}
        neither = [
            entry
            for entry in driver_ioctls.get("ioctls", [])
            if entry["method"] == "METHOD_NEITHER"
        ]
        if not neither:
            return []
        # A driver that probes the caller's buffers is doing the required work,
        # so only an image with no probe API anywhere is reported.
        if import_names & USER_BUFFER_PROBE_IMPORTS:
            return []
        return [
            {
                "code": entry["code"],
                "function": entry["function"],
                "access": entry["access"],
                "confidence": entry.get("confidence"),
                "detail": (
                    "Control code uses METHOD_NEITHER, so the handler receives raw "
                    "user-mode pointers, and the image imports no ProbeForRead / "
                    "ProbeForWrite to validate them."
                ),
            }
            for entry in neither
        ]

    return []


def review_binary_metadata(
    review_binary_list: list[dict[str, Any]] | None, metadata: dict, evidence_limit: int
) -> dict[str, list]:
    """Run all BINARY_REVIEWS rules against whole-binary metadata."""
    if not metadata:
        return {}
    results: defaultdict[str, list] = defaultdict(list)
    for review_group in review_binary_list or []:
        for rule_id, rule_obj in review_group.items():
            if rule_obj.get("check_type") != "binary_analysis":
                continue
            evidence = _evaluate_binary_analysis(rule_id, metadata)
            if evidence:
                results[rule_id] = evidence[:evidence_limit]
    return dict(results)
