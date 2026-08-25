"""Whole-binary heuristics for side-loaded and passively-triggered implants.

A capability list does not distinguish an implant from ordinary software. Both
open sockets, both allocate executable memory, both use cryptography. What
distinguishes them is *incoherence*: a claim in one part of the image that the
rest of the image contradicts, or a capability present with the infrastructure
that would justify it absent.

Each rule here is built on one such contradiction:

* A file whose version resource names one vendor while its export table
  implements another vendor's API (``PE_IMPERSONATES_SYSTEM_MODULE``).
* An export table that is a uniform array of stubs rather than real
  implementations (``PE_STUB_EXPORT_THUNK_TABLE``).
* A ``LoadLibrary`` of a module the import table never names
  (``PE_UNRESOLVED_SIBLING_MODULE_LOAD``).
* A library that gates its behaviour on which executable loaded it
  (``PE_HOST_PROCESS_NAME_GATE``).
* Several inbound transports with no outbound destination anywhere in the image
  (``PASSIVE_MULTI_TRANSPORT_LISTENER``).
* Security-relevant resource names that exist only as runtime arithmetic
  (``RUNTIME_CONSTRUCTED_SECURITY_STRINGS``).
* Registry values whose only purpose is to weaken authentication
  (``HOST_AUTHENTICATION_DOWNGRADE``).
* An encrypted region larger than any key, next to the primitives to decrypt it
  (``EMBEDDED_ENCRYPTED_PAYLOAD``).
* A table of code pointers indexed at runtime, with no dynamic-dispatch reason
  (``CUSTOM_COMMAND_DISPATCH_TABLE``).

Every rule states the contradiction it found in its evidence, so a reviewer can
check the claim rather than trust the label. None of them is a malware verdict on
its own; several together are.
"""

import re
from collections.abc import Iterable
from typing import Any

# --------------------------------------------------------------------------
# Vendor identity
# --------------------------------------------------------------------------

# Module names shipped by Microsoft as part of Windows. A file claiming one of
# these names while naming a different company in its version resource is
# impersonating a system component - the precondition for DLL side-loading and
# for search-order hijacking generally.
#
# The list is names only, not export sets, because the name is what the loader
# resolves and what a reviewer sees on disk. It covers the modules repeatedly
# abused for side-loading rather than attempting to enumerate System32.
MICROSOFT_SYSTEM_MODULES: frozenset[str] = frozenset(
    {
        "apphelp.dll",
        "atl.dll",
        "bcrypt.dll",
        "bcryptprimitives.dll",
        "cryptbase.dll",
        "cryptsp.dll",
        "crypt32.dll",
        "dbgcore.dll",
        "dbghelp.dll",
        "dnsapi.dll",
        "dpapi.dll",
        "dwmapi.dll",
        "dxgi.dll",
        "faultrep.dll",
        "iphlpapi.dll",
        "mpr.dll",
        "mscoree.dll",
        "msimg32.dll",
        "msvcp140.dll",
        "ncrypt.dll",
        "netapi32.dll",
        "netutils.dll",
        "ntmarta.dll",
        "profapi.dll",
        "propsys.dll",
        "riched20.dll",
        "rstrtmgr.dll",
        "samcli.dll",
        "secur32.dll",
        "sspicli.dll",
        "srvcli.dll",
        "textinputframework.dll",
        "textshaping.dll",
        "userenv.dll",
        "uxtheme.dll",
        "version.dll",
        "wer.dll",
        "windowscodecs.dll",
        "wininet.dll",
        "winhttp.dll",
        "winmm.dll",
        "wkscli.dll",
        "wldp.dll",
        "wtsapi32.dll",
    }
)

# Version-resource fields that name the publisher.
_VENDOR_FIELDS: tuple[str, ...] = ("CompanyName", "LegalCopyright", "ProductName")
_MICROSOFT_MARKERS: tuple[str, ...] = ("microsoft", "windows nt", "windows(r)")

# --------------------------------------------------------------------------
# Export table shape
# --------------------------------------------------------------------------

# Exports laid out at a uniform small stride are a generated thunk array, not
# separately compiled functions. SLEEPWALKER's seven DPAPI exports sit 10 bytes
# apart, each a jump through an empty pointer table. Real implementations of
# seven distinct API functions never have identical sizes.
#
# Three exports is the smallest run where a shared stride is meaningful, and 16
# bytes is generous for a thunk (a jump plus padding) while far below any real
# function.
MIN_STUB_EXPORTS = 3
MAX_STUB_EXPORT_STRIDE = 16

# --------------------------------------------------------------------------
# Transports
# --------------------------------------------------------------------------

# Inbound transports, grouped so the rule can count *distinct* ways the image can
# be reached rather than counting individual imports. A server implements one of
# these groups; occasionally two. An image implementing several is not serving a
# protocol, it is maximising the chance that one channel is reachable.
INBOUND_TRANSPORT_IMPORTS: dict[str, frozenset[str]] = {
    "tcp_listener": frozenset({"listen", "accept", "acceptex", "wsaaccept"}),
    "udp_datagram": frozenset({"recvfrom", "wsarecvfrom"}),
    "named_pipe_server": frozenset({"createnamedpipea", "createnamedpipew", "connectnamedpipe"}),
    "icmp": frozenset({"icmpsendecho", "icmpsendecho2", "icmpcreatefile", "icmp6sendecho2"}),
    "raw_socket": frozenset({"wsaioctl"}),
    "device_channel": frozenset({"deviceiocontrol"}),
}

# Outbound infrastructure. A remotely controlled implant with no hardcoded
# destination is waiting to be contacted; one of these means it initiates.
OUTBOUND_CONFIG_IMPORTS: frozenset[str] = frozenset(
    {
        "internetopena",
        "internetopenw",
        "internetopenurla",
        "internetopenurlw",
        "internetconnecta",
        "internetconnectw",
        "winhttpopen",
        "winhttpconnect",
        "winhttpopenrequest",
        "urldownloadtofilea",
        "urldownloadtofilew",
        "httpsendrequesta",
        "httpsendrequestw",
    }
)

# A hardcoded destination in the strings: a URL, a bare hostname, or a dotted
# quad. Any of these means the image knows where to call out to.
_URL_RE = re.compile(r"\b(?:https?|ftp|wss?)://", re.I)
_HOSTNAME_RE = re.compile(
    r"\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\.(?:com|net|org|io|ru|cn|info|biz|xyz|top|site|online|club|pw|cc|me|co|dev|app)\b",
    re.I,
)
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
# Addresses that are not a C2 destination: loopback, any-address, broadcast and
# the version-number-shaped quads that fill version resources.
_NON_ROUTABLE_ADDRESSES: frozenset[str] = frozenset(
    {"0.0.0.0", "127.0.0.1", "255.255.255.255", "1.1.1.1", "1.0.0.0"}
)

MIN_PASSIVE_TRANSPORTS = 3

# --------------------------------------------------------------------------
# Covert channels and host weakening
# --------------------------------------------------------------------------

# Device objects that cross the guest/host virtualisation boundary without
# touching the network stack, so no firewall, proxy or flow record observes the
# traffic.
#
# Named pipes are deliberately absent. `\\.\pipe\...` is ordinary Windows IPC -
# SQL Server client connections, code-coverage collectors, the .NET diagnostics
# channel and Rust's anonymous pipes all use it - and including it made this rule
# fire on 10 of 180 benign binaries while saying nothing about any of them. A
# pipe's contribution is counted as one inbound transport by
# PASSIVE_MULTI_TRANSPORT_LISTENER instead, which is the right weight for it.
COVERT_CHANNEL_DEVICES: dict[str, str] = {
    "vmci": "VMware Virtual Machine Communication Interface (guest-to-host channel)",
    "vmwarevmci": "VMware Virtual Machine Communication Interface (guest-to-host channel)",
    "vsock": "Virtio socket (guest-to-host channel)",
    "hvsocket": "Hyper-V socket (guest-to-partition channel)",
}

# Registry values whose only effect is to weaken authentication for remote
# access. Unlike a generic "writes to the registry" signal, each of these names
# an authentication boundary being lowered.
AUTHENTICATION_DOWNGRADE_VALUES: dict[str, str] = {
    "everyoneincludesanonymous": (
        "Grants anonymous logons the access rights of the Everyone group"
    ),
    "nullsessionpipes": "Permits unauthenticated named-pipe sessions to the listed pipes",
    "nullsessionshares": "Permits unauthenticated share access",
    "restrictanonymous": "Controls anonymous enumeration of accounts and shares",
    "restrictanonymoussam": "Controls anonymous enumeration of SAM accounts",
    "limitblankpassworduse": "Controls whether blank passwords may be used remotely",
    "requiresecuritysignature": "Controls whether SMB signing is required",
    "enablesecuritysignature": "Controls whether SMB signing is offered",
    "lmcompatibilitylevel": "Controls which LM/NTLM authentication levels are accepted",
    "disabledomaincreds": "Controls whether credentials may be cached for network use",
}

# Resource classes that a legitimate program has no reason to hide. A path or key
# assembled by arithmetic is being kept out of the strings deliberately.
_SENSITIVE_STRING_MARKERS: tuple[tuple[str, str], ...] = (
    ("\\\\.\\", "device object path"),
    ("\\device\\", "kernel device object"),
    ("\\??\\", "object manager symbolic link"),
    ("currentcontrolset", "system registry path"),
    ("\\lsa", "LSA registry path"),
    ("lanmanserver", "SMB server configuration path"),
    ("\\pipe\\", "named pipe path"),
    ("\\run", "autorun registry path"),
    ("services\\", "service registry path"),
)
# A loadable library name. Executables are deliberately excluded: LoadLibrary of
# an .exe is rare, whereas an .exe name in a DLL is usually the host process it
# checks for, which PE_HOST_PROCESS_NAME_GATE reports with the right meaning.
_LOADABLE_MODULE_RE = re.compile(r"^[\w.\-]{1,60}\.(?:dll|sys|cpl|ocx|drv)$", re.I)

# Windows modules that ordinary software resolves at runtime as a matter of
# course, either because the feature is optional or because the import is
# delay-loaded. Runtime loading of these is unremarkable and reporting it buries
# the case that matters. The api-set and extension-set contracts are matched by
# pattern rather than enumerated, since the loader resolves them by prefix.
_COMMON_RUNTIME_LOADED_MODULES: frozenset[str] = frozenset(
    {
        "advapi32.dll",
        "comctl32.dll",
        "comdlg32.dll",
        "gdi32.dll",
        "gdiplus.dll",
        "icmp.dll",
        "imagehlp.dll",
        "kernel32.dll",
        "kernelbase.dll",
        "ole32.dll",
        "ole32.dll",
        "oleaut32.dll",
        "opengl32.dll",
        "powrprof.dll",
        "psapi.dll",
        "rpcrt4.dll",
        "setupapi.dll",
        "shell32.dll",
        "shlwapi.dll",
        "user32.dll",
        "ws2_32.dll",
        "wsock32.dll",
        "ntdll.dll",
        "msvcrt.dll",
        "ucrtbase.dll",
        "vcruntime140.dll",
    }
)
_API_SET_PREFIXES: tuple[str, ...] = ("api-ms-win-", "ext-ms-win-", "api-ms-onecore")


def _is_documented_windows_module(name: str) -> bool:
    """Return True for a module whose runtime loading needs no explanation."""
    lowered = name.strip().lower()
    if lowered in _COMMON_RUNTIME_LOADED_MODULES or lowered in MICROSOFT_SYSTEM_MODULES:
        return True
    return lowered.startswith(_API_SET_PREFIXES)


def _module_stem(name: str) -> str:
    """Return a module name without its extension, lowercased."""
    return name.strip().lower().rsplit(".", 1)[0]


# The shortest stem allowed to anchor a near-miss comparison. Below this, common
# short names collide by accident.
_MIN_STEM_OVERLAP = 4


def _is_near_miss_of(candidate: str, reference: str) -> bool:
    """Return True when one module stem is an extension of the other.

    ``dpapisvc.dll`` beside ``dpapi.dll`` is the pattern: a name built to read as
    a companion of a module that really exists, so that finding it next to the
    real one on disk raises no question.
    """
    left, right = _module_stem(candidate), _module_stem(reference)
    if not left or not right or left == right:
        return False
    if min(len(left), len(right)) < _MIN_STEM_OVERLAP:
        return False
    return left.startswith(right) or right.startswith(left)


# --------------------------------------------------------------------------
# Dispatch tables
# --------------------------------------------------------------------------

# `lea reg, [rip + N]` takes the address of code or data; storing several of them
# into consecutive slots of one object builds a table of function pointers. Eight
# is well above the size of a C++ vtable a small utility would construct inline,
# and it is what a command interpreter's operation table looks like.
MIN_DISPATCH_TABLE_POINTERS = 8
_RIP_RELATIVE_LEA_RE = re.compile(
    r"^\s*lea\s+([a-z][a-z0-9]*)\s*,\s*\[\s*rip\s*[+-]\s*[^\]]+\]\s*$", re.I
)
_POINTER_STORE_RE = re.compile(
    r"^\s*mov\s+(?:qword|dword)\s+ptr\s+"
    r"\[\s*([a-z][a-z0-9]*)\s*(?:([+-])\s*(\d+|0x[0-9a-f]+)\s*)?\]\s*,\s*([a-z][a-z0-9]*)\s*$",
    re.I,
)

# Executable-memory primitives. A dispatch table is only a command interpreter if
# something in the image can also run what the commands deliver.
_CODE_EXECUTION_IMPORTS: frozenset[str] = frozenset(
    {"virtualprotect", "virtualprotectex", "virtualalloc", "virtualallocex", "createthread"}
)


def _normalize_import(name: Any) -> str:
    """Lowercase an import name, dropping the ``library::`` qualifier."""
    if not name:
        return ""
    normalized = str(name).strip().lower()
    if "::" in normalized:
        normalized = normalized.rsplit("::", 1)[-1]
    return normalized.strip().lstrip("_")


def collect_import_names(metadata: dict) -> set[str]:
    """Gather normalized import names from the metadata."""
    names: set[str] = set()
    for entry in metadata.get("imports", []) or []:
        name = entry.get("name") if isinstance(entry, dict) else entry
        if normalized := _normalize_import(name):
            names.add(normalized)
    return names


def _imported_libraries(metadata: dict) -> set[str]:
    """Gather the lowercased library names the import table declares."""
    libraries: set[str] = set()
    for entry in metadata.get("imports", []) or []:
        name = entry.get("name") if isinstance(entry, dict) else entry
        if not name or "::" not in str(name):
            continue
        libraries.add(str(name).split("::", 1)[0].strip().lower())
    for entry in metadata.get("dynamic_entries", []) or []:
        if isinstance(entry, dict) and (value := entry.get("name")):
            libraries.add(str(value).strip().lower())
    return libraries


def _iter_strings(metadata: dict) -> Iterable[str]:
    """Yield every recovered string value, from all three extraction channels.

    Stack-built strings are included because an implant that hides its resource
    names keeps them out of the other two entirely.
    """
    for key in ("strings", "informative_strings", "stack_strings"):
        for item in metadata.get(key, []) or []:
            value = item.get("value", "") if isinstance(item, dict) else item
            if value:
                yield str(value)


def _version_vendor(metadata: dict) -> str:
    """Return the publisher named by the version resource, lowercased."""
    version_metadata = ((metadata.get("resources") or {}).get("version_metadata")) or {}
    parts = [str(version_metadata.get(field, "")) for field in _VENDOR_FIELDS]
    return " ".join(part for part in parts if part).strip().lower()


def _claimed_filename(metadata: dict) -> str:
    """Return the module name the version resource claims, lowercased."""
    version_metadata = ((metadata.get("resources") or {}).get("version_metadata")) or {}
    return str(version_metadata.get("OriginalFilename", "")).strip().lower()


def _is_unsigned(metadata: dict) -> bool:
    """Return True when the image carries no valid Authenticode signature."""
    if metadata.get("is_signed"):
        return False
    flags = str((metadata.get("authenticode") or {}).get("verification_flags", "")).upper()
    return flags != "OK"


def _evaluate_impersonates_system_module(metadata: dict) -> list[dict]:
    """A file claiming a Microsoft module name under a different vendor's identity."""
    claimed = _claimed_filename(metadata)
    if claimed not in MICROSOFT_SYSTEM_MODULES:
        return []
    vendor = _version_vendor(metadata)
    if not vendor or any(marker in vendor for marker in _MICROSOFT_MARKERS):
        return []
    if not _is_unsigned(metadata):
        # A validly signed file stands behind the name with a verifiable
        # identity, which is the opposite of what this rule looks for.
        return []
    version_metadata = ((metadata.get("resources") or {}).get("version_metadata")) or {}
    return [
        {
            "claimed_module": claimed,
            "declared_company": version_metadata.get("CompanyName", ""),
            "declared_product": version_metadata.get("ProductName", ""),
            "signature": "unsigned",
            "detail": (
                f"The version resource names the Microsoft system module '{claimed}' while "
                f"attributing it to a different publisher, and the file is unsigned. A genuine "
                f"'{claimed}' is signed by Microsoft; a genuine third-party module does not "
                f"carry that filename."
            ),
        }
    ]


def _evaluate_stub_export_thunk_table(metadata: dict) -> list[dict]:
    """An export table that is a generated array of stubs, not implementations."""
    exports = metadata.get("exports") or []
    if len(exports) < MIN_STUB_EXPORTS:
        return []
    # A real forwarder is the supported way to re-export another module's API, so
    # a table of genuine forwarders is not a stub table.
    if any(entry.get("is_forwarded") for entry in exports if isinstance(entry, dict)):
        return []
    addresses = []
    for entry in exports:
        if not isinstance(entry, dict):
            return []
        address = entry.get("address")
        if not address:
            return []
        try:
            addresses.append(int(str(address), 16))
        except ValueError:
            return []
    addresses.sort()
    strides = {addresses[index + 1] - addresses[index] for index in range(len(addresses) - 1)}
    if len(strides) != 1:
        return []
    stride = strides.pop()
    if not 0 < stride <= MAX_STUB_EXPORT_STRIDE:
        return []
    return [
        {
            "export_count": len(exports),
            "stride_bytes": stride,
            "exports": sorted(
                str(entry.get("name", "")) for entry in exports if isinstance(entry, dict)
            ),
            "detail": (
                f"All {len(exports)} exports are spaced exactly {stride} bytes apart, so each is a "
                "fixed-size stub rather than a separately compiled function, and none is a real "
                "forwarded export. This is the shape of a proxy DLL that satisfies a loader's "
                "import resolution while implementing its behaviour elsewhere."
            ),
        }
    ]


def _evaluate_unresolved_sibling_module_load(metadata: dict) -> list[dict]:
    """A runtime-loaded module named to pass as a companion of a real one.

    Runtime loading on its own is far too common to report: every non-trivial
    program resolves some optional OS module through LoadLibrary. What is not
    ordinary is a runtime-loaded module that is *not* a documented Windows module
    and whose name is a near-miss of this image's own name or of a system module -
    a name chosen so the file reads as a legitimate companion on disk.
    """
    import_names = collect_import_names(metadata)
    if not import_names & {"loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw"}:
        return []
    declared = _imported_libraries(metadata)
    claimed = _claimed_filename(metadata)
    own_names = {name for name in (claimed, str(metadata.get("name", "")).strip().lower()) if name}
    evidence: list[dict] = []
    seen: set[str] = set()
    for value in _iter_strings(metadata):
        candidate = value.strip().lower()
        if candidate in seen or not _LOADABLE_MODULE_RE.match(candidate):
            continue
        if candidate in declared or candidate in own_names:
            continue
        if _is_documented_windows_module(candidate):
            continue
        # Only a near-miss of a *Microsoft system module* counts. Comparing
        # against the image's own name as well seemed natural - SLEEPWALKER's
        # dpapi.dll loads dpapisvc.dll, which is both - but it is the legitimate
        # pattern too: a product names its satellite and resource DLLs after
        # itself, and a per-architecture build names a variant of its own file.
        # That was all 5 false positives on a 400-binary benign corpus
        # (CodeCoverage.exe loading codecoveragemessages.dll, msalruntime_x86.dll
        # matching msalruntime.dll). Impersonating the OS is the part no ordinary
        # product does.
        resembles = next(
            (
                reference
                for reference in MICROSOFT_SYSTEM_MODULES
                if _is_near_miss_of(candidate, reference)
            ),
            "",
        )
        if not resembles:
            continue
        seen.add(candidate)
        evidence.append(
            {
                "module": value.strip(),
                "resembles": resembles,
                "detail": (
                    f"'{value.strip()}' is resolved at runtime through LoadLibrary - it is absent "
                    f"from the import table - and its name is a near-miss of '{resembles}'. A "
                    "module named to read as a companion of a real one is not recorded as a "
                    "dependency, need not exist at analysis time, and raises no question if found "
                    "beside the module it imitates."
                ),
            }
        )
    return evidence


def _evaluate_host_process_name_gate(metadata: dict) -> list[dict]:
    """A library whose behaviour depends on which executable loaded it."""
    if not metadata.get("is_shared_library"):
        return []
    import_names = collect_import_names(metadata)
    if not import_names & {
        "getmodulefilenamea",
        "getmodulefilenamew",
        "getcommandlinea",
        "getcommandlinew",
    }:
        return []
    evidence: list[dict] = []
    for entry in metadata.get("stack_strings") or []:
        value = str(entry.get("value", "")).strip()
        if not value.lower().endswith(".exe"):
            continue
        evidence.append(
            {
                "host_executable": value,
                "function": entry.get("function"),
                "detail": (
                    f"The library queries its own module or command line and compares it against "
                    f"'{value}', a name it assembles at runtime rather than storing. A library "
                    "that only acts inside one named host process is built to be side-loaded by "
                    "that process."
                ),
            }
        )
    return evidence


def _evaluate_passive_multi_transport_listener(metadata: dict) -> list[dict]:
    """Several inbound transports with no outbound destination in the image."""
    import_names = collect_import_names(metadata)
    transports = sorted(
        name for name, apis in INBOUND_TRANSPORT_IMPORTS.items() if import_names & apis
    )
    if len(transports) < MIN_PASSIVE_TRANSPORTS:
        return []
    if import_names & OUTBOUND_CONFIG_IMPORTS:
        return []
    if _hardcoded_destinations(metadata):
        return []
    return [
        {
            "transports": transports,
            "transport_count": len(transports),
            "detail": (
                f"The image can be reached over {len(transports)} independent inbound transports "
                f"({', '.join(transports)}) but contains no URL, hostname or address to call out "
                "to, and imports no client-side HTTP API. A remotely controlled component with no "
                "destination is waiting to be contacted rather than reporting in, which is why it "
                "produces no outbound traffic to detect."
            ),
        }
    ]


def _hardcoded_destinations(metadata: dict) -> list[str]:
    """Return the outbound destinations named in the image's strings."""
    found: list[str] = []
    for value in _iter_strings(metadata):
        if _URL_RE.search(value) or _HOSTNAME_RE.search(value):
            found.append(value)
            continue
        for match in _IPV4_RE.finditer(value):
            if match.group() not in _NON_ROUTABLE_ADDRESSES:
                found.append(match.group())
    return found


def _evaluate_covert_channel_device_access(metadata: dict) -> list[dict]:
    """Access to a device object that moves data without using the network stack."""
    import_names = collect_import_names(metadata)
    if not import_names & {"createfilea", "createfilew", "ntcreatefile"}:
        return []
    evidence: list[dict] = []
    seen: set[str] = set()
    for value in _iter_strings(metadata):
        text = value.strip()
        if not text.startswith("\\\\.\\"):
            continue
        leaf = text[4:].split("\\", 1)[0].strip().lower()
        for marker, description in COVERT_CHANNEL_DEVICES.items():
            if leaf != marker or marker in seen:
                continue
            seen.add(marker)
            evidence.append(
                {
                    "device": text,
                    "channel": description,
                    "detail": (
                        f"The image opens '{text}', a {description}. Data moved through it does "
                        "not traverse the network stack, so no firewall rule, proxy log or flow "
                        "record observes the transfer."
                    ),
                }
            )
    return evidence


def _evaluate_runtime_constructed_security_strings(metadata: dict) -> list[dict]:
    """Security-relevant resource names that exist only as runtime arithmetic."""
    evidence: list[dict] = []
    for entry in metadata.get("stack_strings") or []:
        value = str(entry.get("value", ""))
        lowered = value.lower()
        for marker, kind in _SENSITIVE_STRING_MARKERS:
            index = lowered.find(marker)
            if index < 0:
                continue
            # A reconstruction that does not begin at the start of the resource
            # name is missing the bytes a store through an unknown register left
            # out. Saying so keeps the evidence honest: the fragment is real, but
            # the full path is longer than what is shown.
            partial = index > 0
            item = {
                "value": value,
                "resource": kind,
                "function": entry.get("function"),
                "encoding": entry.get("encoding"),
                "partial": partial,
                "detail": (
                    f"The {kind} '{value}' is assembled from arithmetic at runtime instead of "
                    "being stored as a literal, so it does not appear in the image's strings. "
                    "Ordinary code has no reason to hide a resource name."
                ),
            }
            if partial:
                item["detail"] += (
                    " This is a partial reconstruction: the recovery pass follows no branches, so "
                    "the surrounding bytes of the real path were not resolved."
                )
            evidence.append(item)
            break
    return evidence


def _evaluate_host_authentication_downgrade(metadata: dict) -> list[dict]:
    """Registry values whose only purpose is to lower an authentication boundary."""
    import_names = collect_import_names(metadata)
    if not import_names & {
        "regsetvalueexa",
        "regsetvalueexw",
        "regcreatekeyexa",
        "regcreatekeyexw",
        "ntsetvaluekey",
        "regsetkeyvaluea",
        "regsetkeyvaluew",
    }:
        return []
    evidence: list[dict] = []
    seen: set[str] = set()
    for value in _iter_strings(metadata):
        lowered = value.strip().lower()
        for name, effect in AUTHENTICATION_DOWNGRADE_VALUES.items():
            if name not in lowered or name in seen:
                continue
            seen.add(name)
            evidence.append(
                {
                    "value_name": name,
                    "effect": effect,
                    "detail": (
                        f"The image can write the registry value '{name}'. {effect}. Modifying it "
                        "lowers an authentication boundary for every process on the host, not "
                        "only for this one."
                    ),
                }
            )
    return evidence


# The share of a section an opaque region must occupy before it is treated as an
# embedded payload rather than as ordinary opaque data. A large program's .rdata
# routinely holds certificates, compressed assets and unrecognised constant
# tables; each yields a high-entropy region, but a small fraction of a large
# section. Requiring a quarter of the section keeps those out while matching an
# implant whose data section exists mainly to carry its encrypted program -
# SLEEPWALKER's is 81% of .data.
MIN_PAYLOAD_SECTION_FRACTION = 0.25

# Only writable initialised data is considered. Read-only data is where a program
# legitimately keeps embedded assets: compressed resources, certificates, icon
# and font blobs, and the payload of a self-extracting installer. Python's
# distutils `wininst-*.exe` stubs are exactly that case, and they were 3 of 3
# false positives for this rule before the restriction.
#
# A large opaque blob in *writable* initialised data is a different claim: the
# program intends to modify it in place, which is what decrypting in place means.
# The trade is that an implant keeping its payload in .rdata is missed here; it
# still surfaces as an opaque_regions entry in the metadata.
PAYLOAD_SECTIONS: frozenset[str] = frozenset({".data"})


def _evaluate_embedded_encrypted_payload(metadata: dict) -> list[dict]:
    """An opaque region dominating a writable section, beside primitives to read it."""
    crypto = metadata.get("crypto_material") or {}
    regions = crypto.get("opaque_regions") or []
    if not regions:
        return []
    algorithms = crypto.get("algorithms") or []
    tables = crypto.get("permutation_tables") or []
    # Without any identified primitive the region could be compressed resources
    # or a certificate, so the correlation is what makes it a payload.
    if not algorithms and not tables:
        return []
    evidence: list[dict] = []
    for region in regions:
        if str(region.get("section", "")).lower() not in PAYLOAD_SECTIONS:
            continue
        fraction = region.get("section_fraction") or 0.0
        if fraction < MIN_PAYLOAD_SECTION_FRACTION:
            continue
        evidence.append(
            {
                "section": region["section"],
                "offset": region["offset"],
                "size": region["size"],
                "entropy": region["entropy"],
                "section_fraction": fraction,
                "algorithms": algorithms,
                "detail": (
                    f"{region['size']} contiguous bytes at {region['section']}+{region['offset']} "
                    f"have entropy {region['entropy']} and match no known constant table, and they "
                    f"occupy {fraction:.0%} of the section - which therefore exists mainly to carry "
                    f"them. The image also carries "
                    f"{', '.join(algorithms) or 'a substitution table'}. A region this size is not "
                    "a key; it is data the image can decrypt but a reviewer cannot read."
                ),
            }
        )
    return evidence


# Rules that establish an image is worth looking at in the first place. The
# dispatch-table heuristic is gated on at least one of them because a runtime
# pointer table is, on its own, indistinguishable from ordinary C++ interface
# construction: on a 180-binary benign corpus it matched ripgrep, coreclr,
# msdia140, sos.dll and the SQL Server client with counts up to 26, above the 18
# of the implant it was written for. No threshold separates those populations.
#
# Gated this way it stops being a detector and becomes a locator: once something
# else says the image is an implant, this names the function where its command
# handling is defined, which is the question a reviewer asks next.
_DISPATCH_CORROBORATING_RULES: tuple[str, ...] = (
    "PE_IMPERSONATES_SYSTEM_MODULE",
    "PE_STUB_EXPORT_THUNK_TABLE",
    "PE_HOST_PROCESS_NAME_GATE",
    "PASSIVE_MULTI_TRANSPORT_LISTENER",
    "COVERT_CHANNEL_DEVICE_ACCESS",
    "RUNTIME_CONSTRUCTED_SECURITY_STRINGS",
    "HOST_AUTHENTICATION_DOWNGRADE",
    "EMBEDDED_ENCRYPTED_PAYLOAD",
)


def _corroborating_rules(metadata: dict) -> list[str]:
    """Return the primary implant rules that also match this image.

    None of the listed evaluators consults the dispatch-table rule, so this
    cannot recurse.
    """
    return [
        rule_id
        for rule_id in _DISPATCH_CORROBORATING_RULES
        if IMPLANT_RULE_EVALUATORS[rule_id](metadata)
    ]


def _evaluate_custom_command_dispatch_table(metadata: dict) -> list[dict]:
    """A runtime-populated table of code pointers, the shape of an interpreter."""
    import_names = collect_import_names(metadata)
    if not import_names & _CODE_EXECUTION_IMPORTS:
        return []
    corroborating = _corroborating_rules(metadata)
    if not corroborating:
        return []
    evidence: list[dict] = []
    for func_key, func_data in (metadata.get("disassembled_functions") or {}).items():
        count, slots = _count_pointer_table_stores(func_data.get("assembly") or "")
        if count < MIN_DISPATCH_TABLE_POINTERS:
            continue
        evidence.append(
            {
                "function": func_data.get("name", func_key),
                "address": func_data.get("address"),
                "pointer_count": count,
                "slot_span_bytes": slots,
                "corroborated_by": corroborating,
                "detail": (
                    f"{count} distinct code addresses are stored into consecutive slots of one "
                    f"object spanning {slots} bytes. A table of function pointers built at runtime "
                    "and indexed by a value from outside the program is an interpreter dispatch "
                    "table, which is how an implant accepts commands without exposing their names "
                    "as strings or imports. Ordinary C++ interface construction produces the same "
                    "shape, so this is reported only because "
                    f"{', '.join(corroborating)} also matched; treat it as locating where the "
                    "command handling is defined rather than as independent evidence."
                ),
            }
        )
    evidence.sort(key=lambda entry: entry["pointer_count"], reverse=True)
    return evidence


def _count_pointer_table_stores(assembly: str) -> tuple[int, int]:
    """Count code pointers stored into one object, returning (count, slot span).

    A pointer is counted when a RIP-relative address is taken into a register and
    that same register is then stored into a base-plus-offset slot. Requiring the
    pair keeps ordinary address-taking (a single argument to a call) out of the
    count.
    """
    pointer_registers: set[str] = set()
    by_base: dict[str, set[int]] = {}
    for line in assembly.split("\n"):
        text = line.strip()
        if match := _RIP_RELATIVE_LEA_RE.match(text):
            pointer_registers.add(match.group(1).lower())
            continue
        if match := _POINTER_STORE_RE.match(text):
            base, sign, offset_token, source = match.groups()
            if source.lower() not in pointer_registers:
                continue
            offset = 0
            if offset_token:
                offset = (
                    int(offset_token, 16) if offset_token.startswith("0x") else int(offset_token)
                )
                if sign == "-":
                    offset = -offset
            by_base.setdefault(base.lower(), set()).add(offset)
            pointer_registers.discard(source.lower())
            continue
        # A call invalidates the tracked registers, since the pointer they held
        # has been consumed rather than stored.
        if text.startswith("call"):
            pointer_registers.clear()
    if not by_base:
        return 0, 0
    base = max(by_base, key=lambda key: len(by_base[key]))
    offsets = by_base[base]
    return len(offsets), (max(offsets) - min(offsets) + 8) if offsets else 0


# Rule id to evaluator. Kept as a table so the dispatcher in binary_reviews stays
# a lookup rather than a chain of comparisons.
IMPLANT_RULE_EVALUATORS: dict[str, Any] = {
    "PE_IMPERSONATES_SYSTEM_MODULE": _evaluate_impersonates_system_module,
    "PE_STUB_EXPORT_THUNK_TABLE": _evaluate_stub_export_thunk_table,
    "PE_UNRESOLVED_SIBLING_MODULE_LOAD": _evaluate_unresolved_sibling_module_load,
    "PE_HOST_PROCESS_NAME_GATE": _evaluate_host_process_name_gate,
    "PASSIVE_MULTI_TRANSPORT_LISTENER": _evaluate_passive_multi_transport_listener,
    "COVERT_CHANNEL_DEVICE_ACCESS": _evaluate_covert_channel_device_access,
    "RUNTIME_CONSTRUCTED_SECURITY_STRINGS": _evaluate_runtime_constructed_security_strings,
    "HOST_AUTHENTICATION_DOWNGRADE": _evaluate_host_authentication_downgrade,
    "EMBEDDED_ENCRYPTED_PAYLOAD": _evaluate_embedded_encrypted_payload,
    "CUSTOM_COMMAND_DISPATCH_TABLE": _evaluate_custom_command_dispatch_table,
}


def evaluate_implant_rule(rule_id: str, metadata: dict) -> list[dict]:
    """Evaluate one implant heuristic, returning its evidence list."""
    evaluator = IMPLANT_RULE_EVALUATORS.get(rule_id)
    return evaluator(metadata) if evaluator else []
