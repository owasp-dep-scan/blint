"""Reviews for the steps that follow SYSTEM code execution on Windows.

Plug and Play installs vendor services and co-installers as SYSTEM when a
matching device appears, and the published research on abusing it (Plug&Pwn)
relies on three binary shapes: a SYSTEM payload DLL that hands an interactive
process to the console user, a service that acts on a configuration file any
user can write, and tooling that registers a fake device under a pluggable
device's identity to drive the installation path. Each rule here names one
of those shapes from the import table, the section markers recorded at parse
time and, when ``--disassemble`` ran, the constants recovered at call sites.
"""

from __future__ import annotations

from typing import Any

from blint.lib.implant_reviews import collect_import_names

PROCESS_AS_USER_IMPORTS = frozenset({"createprocessasuserw", "createprocessasusera"})
CONSOLE_SESSION_IMPORTS = frozenset(
    {
        "wtsgetactiveconsolesessionid",
        "wtsenumeratesessionsw",
        "wtsenumeratesessionsa",
        "wtsenumeratesessionsexw",
        "wtsenumeratesessionsexa",
    }
)
SERVICE_IMPORTS = frozenset(
    {
        "startservicectrldispatcherw",
        "startservicectrldispatchera",
        "registerservicectrlhandlerexw",
        "registerservicectrlhandlerexa",
        "registerservicectrlhandlerw",
        "registerservicectrlhandlera",
    }
)
REGISTRY_WRITE_IMPORTS = frozenset(
    {
        "regsetvalueexw",
        "regsetvalueexa",
        "regsetvaluew",
        "regsetvaluea",
        "regsetkeyvaluew",
        "regsetkeyvaluea",
        "regcreatekeyexw",
        "regcreatekeyexa",
        "regdeletekeyw",
        "regdeletekeya",
        "regdeletekeyexw",
        "regdeletekeyexa",
        "regdeletevaluew",
        "regdeletevaluea",
        "regdeletetreew",
        "regdeletetreea",
    }
)
DEVICE_CREATE_IMPORTS = frozenset({"setupdicreatedeviceinfow", "setupdicreatedeviceinfoa"})
DEVICE_PROPERTY_IMPORTS = frozenset(
    {"setupdisetdeviceregistrypropertyw", "setupdisetdeviceregistrypropertya"}
)
DEVICE_INSTALL_IMPORTS = frozenset(
    {
        "cm_setup_devnode",
        "cm_setup_devnode_ex",
        "diinstalldevice",
        "updatedriverforplugandplaydevicesw",
        "updatedriverforplugandplaydevicesa",
    }
)

# Folder lookups and the argument that names the folder (CSIDL).
FOLDER_PATH_CSIDL_ARGUMENT = {
    "shgetfolderpathw": 1,
    "shgetfolderpatha": 1,
    "shgetfolderpathandsubdirw": 1,
    "shgetfolderpathandsubdira": 1,
    "shgetspecialfolderpathw": 2,
    "shgetspecialfolderpatha": 2,
}

# Documented constants the dataflow can recover at call sites.
TOKEN_SESSION_ID = 12  # TOKEN_INFORMATION_CLASS TokenSessionId
DIF_REGISTERDEVICE = 0x19
CSIDL_COMMON_APPDATA = 0x23  # ProgramData; the high byte carries CSIDL_FLAG_* bits


def _markers(metadata: dict) -> dict[str, Any]:
    block = metadata.get("privilege_markers")
    return block if isinstance(block, dict) else {}


def _marker_evidence(metadata: dict, name: str) -> list[str]:
    block = _markers(metadata)
    if not (block.get("markers") or {}).get(name):
        return []
    return list((block.get("evidence") or {}).get(name) or [])[:2] or [name]


def _export_names(metadata: dict) -> set[str]:
    return {
        str(entry.get("name"))
        for entry in metadata.get("exports") or []
        if isinstance(entry, dict) and entry.get("name")
    }


def _is_service_dll(metadata: dict) -> bool:
    """A svchost-hosted service: it exports ServiceMain or the svchost globals hook."""
    return any(
        "ServiceMain" in name or name == "SvchostPushServiceGlobals"
        for name in _export_names(metadata)
    )


def _interactive_desktop_evidence(metadata: dict) -> list[str]:
    """References to WinSta0\\Default, from the section scan or stack-built strings."""
    found = _marker_evidence(metadata, "interactive_desktop")
    for item in metadata.get("stack_strings") or []:
        value = str(item.get("value", "") if isinstance(item, dict) else item)
        if "winsta0\\default" in value.lower():
            found.append(value)
    return found[:2]


def _is_dll(metadata: dict) -> bool:
    characteristics = metadata.get("characteristics")
    if isinstance(characteristics, list):
        return "DLL" in characteristics
    return "DLL" in str(characteristics or "").replace(" ", "").split(",")


def _recovered_constants(metadata: dict, callees: frozenset, argument: int) -> list[dict] | None:
    """Constants the dataflow recovered for one argument of the named callees.

    None when no complete call-site recovery ran (default mode, or a block
    that hit its entry bound), so a caller can tell "not recovered" from
    "recovered and different".
    """
    coverage = metadata.get("call_site_arguments_coverage")
    if not isinstance(coverage, dict) or coverage.get("entries_truncated"):
        return None
    found = []
    for entry in metadata.get("call_site_arguments") or []:
        callee = str(entry.get("callee") or "").rsplit("::", 1)[-1].lower().lstrip("_")
        if callee not in callees or entry.get("argument") != argument:
            continue
        if isinstance(entry.get("value"), int):
            found.append(
                {"value": entry["value"], "function": (entry.get("functions") or [None])[0]}
            )
    return found


def _refine(
    metadata: dict, callees: frozenset, argument: int, wanted: int
) -> tuple[bool, dict | None]:
    """Whether call-site constants allow the finding, and the confirming call.

    A recovered call passing the wanted constant confirms the shape. Recovered
    calls that all pass something else rule it out. With nothing recovered the
    import-level evidence stands on its own.
    """
    recovered = _recovered_constants(metadata, callees, argument)
    if not recovered:
        return True, None
    for call in recovered:
        if call["value"] == wanted:
            return True, call
    return False, None


def _evaluate_dll_system_session_launch(metadata: dict) -> list[dict]:
    """A DLL that re-homes its own token to the console session and starts a process."""
    if not _is_dll(metadata) or _is_service_dll(metadata):
        # Service DLLs starting UI in a user's session are doing their job.
        return []
    imports = collect_import_names(metadata)
    launch = sorted(imports & PROCESS_AS_USER_IMPORTS)
    session_source = sorted(imports & CONSOLE_SESSION_IMPORTS)
    if not launch or not session_source:
        return []
    if not {"settokeninformation", "duplicatetokenex"} <= imports:
        return []
    # Without lpDesktop = WinSta0\\Default the process lands on the service
    # desktop, where nobody can use it; a payload must name the user's desktop.
    desktop = _interactive_desktop_evidence(metadata)
    if not desktop:
        return []
    allowed, confirming = _refine(
        metadata, frozenset({"settokeninformation"}), 1, TOKEN_SESSION_ID
    )
    if not allowed:
        return []
    evidence: dict[str, Any] = {
        "launch": launch,
        "session_source": session_source,
        "token_apis": ["DuplicateTokenEx", "SetTokenInformation"],
        "basis": "call_site_constant" if confirming else "imports",
    }
    if confirming:
        evidence["token_session_id_call"] = confirming.get("function")
    evidence["interactive_desktop"] = desktop
    if sid := _marker_evidence(metadata, "local_system_sid"):
        evidence["local_system_sid"] = sid
    if "wtsqueryusertoken" in imports:
        evidence["also_imports"] = ["WTSQueryUserToken"]
    evidence["detail"] = (
        "A library duplicates a token, moves it into the console user's session with "
        "SetTokenInformation(TokenSessionId) and starts a process with it. Run as SYSTEM, "
        "this puts a SYSTEM process on the logged-on user's desktop: the payload shape of "
        "DLLs loaded through print monitors, performance libraries or DLL planting."
    )
    return [evidence]


def _evaluate_service_user_writable_config(metadata: dict) -> list[dict]:
    """A service that reads INI settings and writes the registry, naming a user-writable path."""
    imports = collect_import_names(metadata)
    service = sorted(imports & SERVICE_IMPORTS)
    ini = sorted(name for name in imports if name.startswith("getprivateprofile"))
    registry = sorted(imports & REGISTRY_WRITE_IMPORTS)
    if not service or not ini or not registry:
        return []
    location = _user_writable_config_evidence(metadata)
    if not location:
        return []
    return [
        {
            "service_apis": service,
            "config_apis": ini,
            "registry_writes": registry,
            **location,
            "detail": (
                "A Windows service reads INI settings and can create, change or delete "
                "registry keys, and it names a location standard users can write to "
                "(ProgramData, Public). If the settings come from there, any user can "
                "steer the service's SYSTEM registry writes, which is CVE-2019-10617 "
                "(Atheros AtherosSvc) and the registry primitive used by Plug&Pwn."
            ),
        }
    ]


def _user_writable_config_evidence(metadata: dict) -> dict[str, Any]:
    """Where an INI file in a user-writable directory is named, or {}.

    Either the image carries the path itself (C:\\ProgramData\\...\\x.ini), or,
    with --disassemble, it looks up the ProgramData folder by CSIDL and
    carries an INI file name to put in it.
    """
    if paths := _marker_evidence(metadata, "user_writable_config"):
        return {"user_writable_configs": paths}
    names = _marker_evidence(metadata, "ini_file_name")
    if not names:
        return {}
    for callee, argument in FOLDER_PATH_CSIDL_ARGUMENT.items():
        for call in _recovered_constants(metadata, frozenset({callee}), argument) or []:
            if call["value"] & 0xFF == CSIDL_COMMON_APPDATA:
                return {
                    "programdata_lookup": {"callee": callee, "function": call.get("function")},
                    "ini_file_names": names,
                }
    return {}


def _evaluate_device_identity_spoofing(metadata: dict) -> list[dict]:
    """Code that registers a device under a pluggable bus identity and installs a driver for it."""
    imports = collect_import_names(metadata)
    create = sorted(imports & DEVICE_CREATE_IMPORTS)
    prop = sorted(imports & DEVICE_PROPERTY_IMPORTS)
    install = sorted(imports & DEVICE_INSTALL_IMPORTS)
    if not create or not prop or "setupdicallclassinstaller" not in imports or not install:
        return []
    templates = _marker_evidence(metadata, "device_id_template")
    if not templates:
        return []
    allowed, register_call = _refine(
        metadata, frozenset({"setupdicallclassinstaller"}), 0, DIF_REGISTERDEVICE
    )
    if not allowed:
        return []
    evidence: dict[str, Any] = {
        "device_creation": create + prop + ["setupdicallclassinstaller"],
        "driver_install": install,
        "device_id_templates": templates,
        "basis": "call_site_constant" if register_call else "imports",
        "detail": (
            "Creates a device node, sets its hardware ID to a USB, HID or Bluetooth "
            "identity and asks Windows to install a driver for it. That runs the "
            "Plug and Play install path for a device that is not attached, which is "
            "how Plug&Pwn's pnp_simulate finds Windows Update packages to attack. "
            "Device management tools do this too; check which identities it uses."
        ),
    }
    if register_call:
        evidence["register_device_call"] = register_call.get("function")
    return [evidence]


PRIVILEGE_RULE_EVALUATORS: dict[str, Any] = {
    "DLL_SYSTEM_SESSION_LAUNCH": _evaluate_dll_system_session_launch,
    "SERVICE_USER_WRITABLE_CONFIG": _evaluate_service_user_writable_config,
    "DEVICE_IDENTITY_SPOOFING": _evaluate_device_identity_spoofing,
}


def evaluate_privilege_rule(rule_id: str, metadata: dict) -> list[dict]:
    """Evaluate one rule from this module, returning its evidence list."""
    evaluator = PRIVILEGE_RULE_EVALUATORS.get(rule_id)
    return evaluator(metadata) if evaluator else []
