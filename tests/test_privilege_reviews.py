"""Tests for the SYSTEM-foothold reviews (privilege_reviews.py) and the
on-disk system-module-name implant rule.

The positives are real PE files compiled at test time from the C sources in
tests/data/pe/src with clang and lld-link (skipped where that toolchain is
absent), so the imports, section markers and call-site constants the rules
read are the ones blint recovers from a compiled binary. The metadata-only
tests pin the import and call-site shapes recovered from the Plug&Pwn payload
DLL (itm4n/Pentest-Windows PlugAndPwn/poc.cpp, built with
``zig c++ -target x86_64-windows-gnu -shared -O2``).
"""

import shutil
import subprocess
from pathlib import Path

import pytest

from blint.lib.binary_reviews import _evaluate_binary_analysis
from blint.lib.pe_usermode_surface import collect_privilege_markers

SRC = Path(__file__).resolve().parent / "data" / "pe" / "src"
_CLANG = shutil.which("clang") or "/opt/homebrew/opt/llvm/bin/clang"
_LLD_LINK = shutil.which("lld-link") or "/opt/homebrew/opt/llvm@18/bin/lld-link"
_LLVM_DLLTOOL = shutil.which("llvm-dlltool") or "/opt/homebrew/opt/llvm/bin/llvm-dlltool"

IMPORTS = {
    "session_launch.c": {
        "kernel32": ["GetCurrentProcess", "WTSGetActiveConsoleSessionId"],
        "advapi32": [
            "OpenProcessToken",
            "DuplicateTokenEx",
            "SetTokenInformation",
            "CreateProcessAsUserW",
        ],
    },
    "device_identity.c": {
        "setupapi": [
            "SetupDiCreateDeviceInfoList",
            "SetupDiCreateDeviceInfoW",
            "SetupDiSetDeviceRegistryPropertyW",
            "SetupDiCallClassInstaller",
        ],
        "cfgmgr32": ["CM_Setup_DevNode"],
    },
    "service_ini_registry.c": {
        "kernel32": ["GetPrivateProfileStringW"],
        "shell32": ["SHGetFolderPathW"],
        "advapi32": [
            "StartServiceCtrlDispatcherW",
            "RegisterServiceCtrlHandlerExW",
            "RegCreateKeyExW",
            "RegSetValueExW",
        ],
    },
}


def _build(work: Path, source: str, out_name: str, defines=()) -> Path | None:
    """Compile one fixture to an x64 PE; None when the toolchain is missing."""
    libs = []
    try:
        for library, names in IMPORTS[source].items():
            definition = work / f"{library}.def"
            definition.write_text(
                f"LIBRARY {library}.dll\nEXPORTS\n" + "".join(f"    {n}\n" for n in names)
            )
            lib = work / f"{library}.lib"
            subprocess.run(
                [_LLVM_DLLTOOL, "-d", str(definition), "-l", str(lib), "-m", "i386:x86-64"],
                check=True,
                capture_output=True,
            )
            libs.append(str(lib))
        obj = work / f"{out_name}.obj"
        subprocess.run(
            [_CLANG, "--target=x86_64-pc-windows-msvc", "-O2", "-c", str(SRC / source)]
            + [f"-D{define}" for define in defines]
            + ["-o", str(obj)],
            check=True,
            capture_output=True,
        )
        out = work / out_name
        link = [_LLD_LINK, "/nodefaultlib", f"/out:{out}", str(obj), *libs]
        if out_name.lower().endswith(".dll"):
            link[1:1] = ["/dll", "/entry:DllMain"]
        else:
            link[1:1] = ["/entry:start", "/subsystem:console"]
        subprocess.run(link, check=True, capture_output=True)
    except (OSError, subprocess.CalledProcessError):
        return None
    return out


@pytest.fixture(scope="module")
def build(tmp_path_factory):
    def _make(source, out_name, defines=()):
        work = tmp_path_factory.mktemp(out_name.replace(".", "_"))
        path = _build(work, source, out_name, defines)
        if path is None:
            pytest.skip("clang/lld-link/llvm-dlltool unavailable to build the fixture")
        return path

    return _make


def _parse(path, disassemble=False):
    from blint.lib.binary import parse

    metadata = parse(str(path), disassemble=disassemble)
    if disassemble and not metadata.get("disassembled_functions"):
        pytest.skip("disassembly unavailable (nyxstone/LLVM not installed)")
    return metadata


# ---------------------------------------------------------------------------
# DLL_SYSTEM_SESSION_LAUNCH
# ---------------------------------------------------------------------------


def test_session_launch_dll_fires_from_imports_and_markers(build):
    metadata = _parse(build("session_launch.c", "payload.dll"))
    markers = metadata["privilege_markers"]["markers"]
    assert markers["interactive_desktop"] == 1
    [evidence] = _evaluate_binary_analysis("DLL_SYSTEM_SESSION_LAUNCH", metadata)
    assert evidence["basis"] == "imports"
    assert evidence["launch"] == ["createprocessasuserw"]
    assert evidence["session_source"] == ["wtsgetactiveconsolesessionid"]
    assert evidence["interactive_desktop"]


def test_session_launch_confirmed_by_the_token_session_id_constant(build):
    metadata = _parse(build("session_launch.c", "payload_dis.dll"), disassemble=True)
    [evidence] = _evaluate_binary_analysis("DLL_SYSTEM_SESSION_LAUNCH", metadata)
    assert evidence["basis"] == "call_site_constant"
    assert evidence["token_session_id_call"]


def test_other_token_class_is_ruled_out_by_the_dataflow(build):
    # TokenIntegrityLevel (25): the same imports, a different operation.
    path = build("session_launch.c", "integrity_dis.dll", defines=["TOKEN_CLASS=25"])
    assert _evaluate_binary_analysis("DLL_SYSTEM_SESSION_LAUNCH", _parse(path))
    metadata = _parse(path, disassemble=True)
    assert _evaluate_binary_analysis("DLL_SYSTEM_SESSION_LAUNCH", metadata) == []


def test_session_launch_exe_is_out_of_scope(build):
    """Services and tools that start UI in a user's session are executables:
    on the measured corpus the import cluster appears only in Process
    Explorer and a virtualisation guest agent, never in a DLL."""
    metadata = _parse(build("session_launch.c", "payload.dll"))
    metadata["characteristics"] = "EXECUTABLE_IMAGE, LARGE_ADDRESS_AWARE"
    assert _evaluate_binary_analysis("DLL_SYSTEM_SESSION_LAUNCH", metadata) == []


def _plugpwn_payload_metadata():
    """The PlugAndPwn poc.cpp DLL as blint --disassemble recovered it."""
    imports = [
        "ADVAPI32.dll::ConvertSidToStringSidW",
        "ADVAPI32.dll::CreateProcessAsUserW",
        "ADVAPI32.dll::DuplicateTokenEx",
        "ADVAPI32.dll::GetTokenInformation",
        "ADVAPI32.dll::OpenProcessToken",
        "ADVAPI32.dll::SetTokenInformation",
        "KERNEL32.dll::IsProcessInJob",
        "KERNEL32.dll::WTSGetActiveConsoleSessionId",
    ]
    return {
        "characteristics": "EXECUTABLE_IMAGE, LARGE_ADDRESS_AWARE, DLL",
        "imports": [{"name": name} for name in imports],
        "privilege_markers": {
            "markers": {"interactive_desktop": 1, "local_system_sid": 1},
            "evidence": {
                "interactive_desktop": ["WinSta0\\Default"],
                "local_system_sid": ["S-1-5-18"],
            },
        },
        "call_site_arguments_coverage": {"entries": 22},
        "call_site_arguments": [
            {
                "callee": "ADVAPI32.dll::SetTokenInformation",
                "argument": 1,
                "value": 12,
                "functions": ["sub_1150"],
            },
            {
                "callee": "ADVAPI32.dll::SetTokenInformation",
                "argument": 3,
                "value": 4,
                "functions": ["sub_1150"],
            },
        ],
    }


def test_plugpwn_payload_shape():
    [evidence] = _evaluate_binary_analysis(
        "DLL_SYSTEM_SESSION_LAUNCH", _plugpwn_payload_metadata()
    )
    assert evidence["basis"] == "call_site_constant"
    assert evidence["token_session_id_call"] == "sub_1150"


def test_service_dlls_are_out_of_scope():
    """TabSvc.dll and gpsvc.dll on Windows 11 carry the whole cluster: the
    touch keyboard and Group Policy services start processes in the user's
    session as part of their job."""
    metadata = _plugpwn_payload_metadata()
    metadata["exports"] = [{"name": "ServiceMain"}, {"name": "SvchostPushServiceGlobals"}]
    assert _evaluate_binary_analysis("DLL_SYSTEM_SESSION_LAUNCH", metadata) == []
    metadata["exports"] = [{"name": "GroupPolicyClientServiceMain"}]
    assert _evaluate_binary_analysis("DLL_SYSTEM_SESSION_LAUNCH", metadata) == []


def test_session_launch_needs_the_interactive_desktop():
    """windiag.dll has the imports but never names WinSta0\\Default, so its
    process does not land on the user's desktop."""
    metadata = _plugpwn_payload_metadata()
    del metadata["privilege_markers"]
    assert _evaluate_binary_analysis("DLL_SYSTEM_SESSION_LAUNCH", metadata) == []
    metadata["stack_strings"] = [{"value": "WinSta0\\Default"}]
    [evidence] = _evaluate_binary_analysis("DLL_SYSTEM_SESSION_LAUNCH", metadata)
    assert evidence["interactive_desktop"] == ["WinSta0\\Default"]


def test_truncated_call_site_block_cannot_rule_out():
    metadata = _plugpwn_payload_metadata()
    metadata["call_site_arguments"][0]["value"] = 25
    assert _evaluate_binary_analysis("DLL_SYSTEM_SESSION_LAUNCH", metadata) == []
    metadata["call_site_arguments_coverage"]["entries_truncated"] = True
    [evidence] = _evaluate_binary_analysis("DLL_SYSTEM_SESSION_LAUNCH", metadata)
    assert evidence["basis"] == "imports"


# ---------------------------------------------------------------------------
# DEVICE_IDENTITY_SPOOFING
# ---------------------------------------------------------------------------


def test_device_identity_spoofing_fires_on_a_usb_identity(build):
    metadata = _parse(build("device_identity.c", "devsim.exe"))
    [evidence] = _evaluate_binary_analysis("DEVICE_IDENTITY_SPOOFING", metadata)
    assert evidence["driver_install"] == ["cm_setup_devnode"]
    assert any("usb\\vid_" in item.lower() for item in evidence["device_id_templates"])


def test_device_identity_spoofing_confirmed_by_dif_registerdevice(build):
    metadata = _parse(build("device_identity.c", "devsim_dis.exe"), disassemble=True)
    [evidence] = _evaluate_binary_analysis("DEVICE_IDENTITY_SPOOFING", metadata)
    assert evidence["basis"] == "call_site_constant"


def test_root_enumerated_device_is_not_spoofing(build):
    """Virtual device software (the inbox virtual smart card reader is the
    measured case) creates ROOT devices with the same APIs."""
    path = build("device_identity.c", "rootdev.exe", defines=['HARDWARE_ID=L"ROOT\\\\FIXTURE\\0"'])
    assert _evaluate_binary_analysis("DEVICE_IDENTITY_SPOOFING", _parse(path)) == []


# ---------------------------------------------------------------------------
# SERVICE_USER_WRITABLE_CONFIG
# ---------------------------------------------------------------------------


def test_service_reading_programdata_ini_fires(build):
    metadata = _parse(build("service_ini_registry.c", "vendorsvc.exe"))
    [evidence] = _evaluate_binary_analysis("SERVICE_USER_WRITABLE_CONFIG", metadata)
    assert evidence["config_apis"] == ["getprivateprofilestringw"]
    assert evidence["registry_writes"] == ["regcreatekeyexw", "regsetvalueexw"]
    assert evidence["user_writable_configs"] == ["ProgramData\\Vendor\\VendorService.ini"]


def test_service_finding_programdata_by_csidl_needs_the_dataflow(build):
    path = build("service_ini_registry.c", "foldersvc.exe", defines=["CONFIG_FROM_FOLDER"])
    # The image never spells out ProgramData; only the recovered CSIDL says so.
    assert _evaluate_binary_analysis("SERVICE_USER_WRITABLE_CONFIG", _parse(path)) == []
    metadata = _parse(path, disassemble=True)
    [evidence] = _evaluate_binary_analysis("SERVICE_USER_WRITABLE_CONFIG", metadata)
    assert evidence["programdata_lookup"]["callee"] == "shgetfolderpathw"
    assert evidence["ini_file_names"] == ["VendorService.ini"]


def test_programdata_log_text_is_not_a_config_path():
    """OneDriveSetup.exe names ProgramData only in log messages."""
    blob = b"Moving programdata '%ls' to new programdata '%ls'\x00"
    assert collect_privilege_markers(_Parsed(blob)) is None


def test_service_with_private_ini_is_silent(build):
    path = build(
        "service_ini_registry.c", "privatesvc.exe", defines=['CONFIG_PATH=L"VendorService.ini"']
    )
    assert _evaluate_binary_analysis("SERVICE_USER_WRITABLE_CONFIG", _parse(path)) == []


# ---------------------------------------------------------------------------
# Section markers
# ---------------------------------------------------------------------------


class _Section:
    def __init__(self, content):
        self.name = ".rdata"
        self.content = content


class _Parsed:
    def __init__(self, content):
        self.sections = [_Section(content)]


def test_privilege_markers_both_encodings_and_absence():
    blob = (
        "WinSta0\\Default".encode("utf-16-le")
        + b"\x00\x00S-1-5-18\x00%ALLUSERSPROFILE%\\Vendor\\agent.ini\x00"
    )
    block = collect_privilege_markers(_Parsed(blob))
    assert block["markers"] == {
        "ini_file_name": 1,
        "interactive_desktop": 1,
        "local_system_sid": 1,
        "user_writable_config": 1,
    }
    assert block["evidence"]["interactive_desktop"] == ["WinSta0\\Default"]
    assert collect_privilege_markers(_Parsed(b"nothing relevant here")) is None


# ---------------------------------------------------------------------------
# PE_SYSTEM_MODULE_NAME_WITHOUT_IDENTITY
# ---------------------------------------------------------------------------


def test_planted_system_module_name_fires(build, tmp_path):
    payload = build("session_launch.c", "payload.dll")
    planted = tmp_path / "CRYPTBASE.dll"
    planted.write_bytes(payload.read_bytes())
    [evidence] = _evaluate_binary_analysis(
        "PE_SYSTEM_MODULE_NAME_WITHOUT_IDENTITY", _parse(planted)
    )
    assert evidence["file_name"] == "cryptbase.dll"
    assert evidence["version_resource"] is False


@pytest.mark.parametrize(
    "path,version_info,fires",
    [
        (r"C:\Intel\RSDCM\CRYPTBASE.dll", {}, True),
        ("/opt/app/version.dll", {"CompanyName": "Some Game Mod"}, True),
        (r"C:\Windows\System32\cryptbase.dll", {"CompanyName": "Microsoft Corporation"}, False),
        (r"C:\Program Files\App\helper.dll", {}, False),
    ],
)
def test_system_module_name_rule_on_metadata(path, version_info, fires):
    metadata = {
        "file_path": path,
        "resources": {"version_metadata": version_info} if version_info else {},
        "code_signature": {"signature_count": 0},
    }
    evidence = _evaluate_binary_analysis("PE_SYSTEM_MODULE_NAME_WITHOUT_IDENTITY", metadata)
    assert bool(evidence) is fires


def test_full_versioninfo_decode_also_counts_as_microsoft_identity():
    metadata = {
        "file_path": r"C:\Windows\System32\cryptbase.dll",
        "resources": {},
        "version_info": {"strings": {"040904b0": {"CompanyName": "Microsoft Corporation"}}},
    }
    assert _evaluate_binary_analysis("PE_SYSTEM_MODULE_NAME_WITHOUT_IDENTITY", metadata) == []
