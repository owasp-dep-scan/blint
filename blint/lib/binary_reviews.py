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
    collect_client_ioctls,
    is_kernel_driver,
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


def _evaluate_binary_analysis(rule_id: str, metadata: dict) -> list[dict]:
    """Evaluate rule-specific whole-binary heuristics. Returns evidence list."""
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
        client_codes = collect_client_ioctls(metadata.get("disassembled_functions") or {})
        if not client_codes:
            return []
        # The `\\.\` paths name the driver being driven, which is what decides
        # whether this is a vendor utility talking to its own driver or a client
        # reaching for someone else's.
        target_devices = (metadata.get("driver_interface") or {}).get("client_device_paths")
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
