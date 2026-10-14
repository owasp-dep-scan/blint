r"""Tests for the driver package INF reader and the Plug and Play rules.

INF fixtures follow Microsoft's documented INF syntax and are written the way
Windows ships them (UTF-16LE with a BOM) unless a test is about encoding. The
reader was also run over a Windows 11 ARM64 DriverStore and C:\Windows\INF
(449 unique INFs); the Microsoft-provided shapes it found there are pinned
below as the negative cases.
"""

import os

import pytest

from blint.lib import inf as inf_mod
from blint.lib.checks import (
    check_pnp_autoload_registration,
    check_pnp_installer_software,
    check_pnp_privileged_component,
    check_pnp_system_service,
    check_pnp_vendor_coinstaller,
    check_pnp_writable_code_destination,
)
from blint.lib.inf import (
    driver_package_context,
    find_inf_files,
    inf_metadata,
    is_inf_file,
    parse_inf,
    privileged_roles,
)

ATHEROS_SHAPED = r"""; A vendor Bluetooth package shaped like the Plug&Pwn Atheros case
[Version]
Signature="$WINDOWS NT$"
Class=Bluetooth
ClassGuid={e0cbf06c-cd8b-4647-bb8a-263b43f0f974}
Provider=%VENDOR%
DriverVer=06/21/2019,10.0.0.1
CatalogFile=vendorbt.cat

[Manufacturer]
%VENDOR%=Vendor,NTamd64,NTarm64

[Vendor.NTamd64]
%Dev% = BT_Install, USB\VID_0489&PID_E078, USB\Class_E0&SubClass_01&Prot_01

[Vendor.NTarm64]
%Dev% = BT_Install, USB\VID_0489&PID_E078

[BT_Install.NT]
CopyFiles = Svc.Copy, Tools.Copy
DelReg = Old.DelReg

[BT_Install.NT.Services]
AddService = VendorBtSvc, 0, Svc_Inst
AddService = vendorbt, 0x2, Drv_Inst

[BT_Install.NT.CoInstallers]
AddReg = Co.AddReg

[Co.AddReg]
HKR,,CoInstallers32,0x00010000,"VendorCoInst.dll,VendorCoInstaller", \
    "WdfCoInstaller01011.dll,WdfCoInstaller"

[Old.DelReg]
HKR,,CoInstallers32

[Svc_Inst]
DisplayName = %SvcName%
ServiceType = 0x10
StartType = 2
ErrorControl = 1
ServiceBinary = %13%\VendorSvc.exe
AddReg = Perf.AddReg

[Drv_Inst]
ServiceType = 1
StartType = 3
ErrorControl = 1
ServiceBinary = %13%\vendorbt.sys

[Perf.AddReg]
HKR,Performance,Library,0x00020000,"%13%\vendorperf.dll"

[DestinationDirs]
Svc.Copy = 13
Tools.Copy = 24, Vendor\Tools

[Svc.Copy]
VendorSvc.exe
vendorbt.sys

[Tools.Copy]
VendorTool.exe
readme.txt

[Strings]
VENDOR = "Example Vendor"
Dev = "Example ; Bluetooth Adapter"
SvcName = "Example Service"
"""


def _write_inf(path, text, encoding="utf-16-le"):
    data = text.encode(encoding)
    if encoding == "utf-16-le":
        data = b"\xff\xfe" + data
    path.write_bytes(data)
    return str(path)


def _block(tmp_path, text, encoding="utf-16-le", name="pkg.inf"):
    return parse_inf(_write_inf(tmp_path / name, text, encoding))


def test_models_services_and_strings(tmp_path):
    block = _block(tmp_path, ATHEROS_SHAPED)
    assert block["encoding"] == "utf-16-le"
    assert block["version"]["provider"] == "Example Vendor"
    assert block["version"]["class"] == "Bluetooth"
    assert block["version"]["catalog_files"] == ["vendorbt.cat"]
    assert block["hardware_ids"] == ["USB\\VID_0489&PID_E078"]
    assert block["compatible_ids"] == ["USB\\Class_E0&SubClass_01&Prot_01"]
    assert block["buses"] == ["USB"]
    assert block["pnp_matchable"] and block["external_bus"]
    services = {s["name"]: s for s in block["services"]}
    user_service = services["VendorBtSvc"]
    assert user_service["kind"] == "win32_own_process"
    assert user_service["start"] == "auto"
    assert user_service["account"] == "LocalSystem"
    assert user_service["binary_name"] == "VendorSvc.exe"
    assert user_service["binary_dirid"] == "13"
    assert services["vendorbt"]["kind"] == "kernel_driver"
    assert "account" not in services["vendorbt"]


def test_co_installers_marks_framework_and_ignores_delreg(tmp_path):
    block = _block(tmp_path, ATHEROS_SHAPED)
    by_dll = {co["dll"]: co for co in block["co_installers"]}
    # The continuation line carries the second value; the DelReg section
    # names CoInstallers32 too but removes rather than adds it.
    assert set(by_dll) == {"VendorCoInst.dll", "WdfCoInstaller01011.dll"}
    assert by_dll["VendorCoInst.dll"]["framework"] is False
    assert by_dll["VendorCoInst.dll"]["entry_point"] == "VendorCoInstaller"
    assert by_dll["WdfCoInstaller01011.dll"]["framework"] is True


def test_registrations_copies_and_quoted_semicolons(tmp_path):
    block = _block(tmp_path, ATHEROS_SHAPED)
    surfaces = {(r["surface"], r["value_name"]) for r in block["registrations"]}
    assert surfaces == {("performance_library", "Library")}
    copies = {c["file"]: c for c in block["copies"]}
    assert copies["VendorTool.exe"]["writable"] == "system_drive_root"
    assert copies["VendorTool.exe"]["subdir"] == "Vendor\\Tools"
    assert copies["VendorTool.exe"]["executable"] is True
    assert "executable" not in copies["readme.txt"]
    assert "writable" not in copies["VendorSvc.exe"]


def test_ansi_inf_and_class_coinstaller(tmp_path):
    text = r"""[Version]
Signature="$Windows NT$"
Provider=Acme
[Manufacturer]
Acme=Acme
[Acme]
Widget=W_Install,HID\VID_1234&PID_5678
[W_Install]
AddReg=Class.AddReg
[Class.AddReg]
HKLM,System\CurrentControlSet\Control\CoDeviceInstallers,{745a17a0-74d3-11d0-b6fe-00a0c90f57da},0x00010008,"AcmeClassCo.dll,Entry"
HKLM,"System\CurrentControlSet\Control\Print\Monitors\Acme Port",Driver,,"acmemon.dll"
"""
    block = _block(tmp_path, text, encoding="latin-1")
    assert block["encoding"] == "utf-8"
    assert block["buses"] == ["HID"]
    [co] = block["co_installers"]
    assert co["scope"] == "class"
    assert co["dll"] == "AcmeClassCo.dll"
    assert co["class_guid"] == "{745a17a0-74d3-11d0-b6fe-00a0c90f57da}"
    assert [r["surface"] for r in block["registrations"]] == ["print_monitor"]


def test_add_software(tmp_path):
    text = r"""[Version]
Signature="$Windows NT$"
Provider=Acme
[Manufacturer]
Acme=Acme,NTamd64
[Acme.NTamd64]
Widget=W_Install,USB\VID_1234&PID_0001
[W_Install.NT.Software]
AddSoftware = AcmeApp,, App_Software
[App_Software]
SoftwareType = 1
SoftwareBinary = AcmeSetup.exe
SoftwareArguments = /quiet
SoftwareVersion = 1.0.0.0
"""
    block = _block(tmp_path, text)
    [software] = block["software"]
    assert software["software_type"] == 1
    assert software["binary_name"] == "AcmeSetup.exe"
    roles = privileged_roles(block)
    assert roles == [
        {"role": "installer_software", "name": "AcmeApp", "binary_name": "AcmeSetup.exe"}
    ]


def test_is_inf_file_needs_a_version_section(tmp_path):
    autorun = tmp_path / "autorun.inf"
    autorun.write_text("[autorun]\nopen=setup.exe\n")
    assert not is_inf_file(str(autorun))
    real = _write_inf(tmp_path / "real.INF", ATHEROS_SHAPED)
    assert is_inf_file(real)
    assert find_inf_files(str(tmp_path)) == [os.path.abspath(real)]
    assert find_inf_files(real) == [os.path.abspath(real)]


def test_oversized_inf_is_refused(tmp_path, monkeypatch):
    path = _write_inf(tmp_path / "big.inf", ATHEROS_SHAPED)
    monkeypatch.setattr(inf_mod, "MAX_INF_BYTES", 64)
    block = parse_inf(path)
    assert block["refused"] == "inf_too_large"
    metadata = inf_metadata(block, path)
    assert check_pnp_writable_code_destination(path, metadata, {}) is True


def test_listing_bound_keeps_the_count(tmp_path, monkeypatch):
    monkeypatch.setattr(inf_mod, "MAX_LISTED", 1)
    block = _block(tmp_path, ATHEROS_SHAPED)
    assert len(block["services"]) == 1
    assert block["services_count"] == 2


# ---------------------------------------------------------------------------
# Checks on the INF unit
# ---------------------------------------------------------------------------


def _metadata(tmp_path, text, name="pkg.inf"):
    path = _write_inf(tmp_path / name, text)
    return path, inf_metadata(parse_inf(path), path)


def test_vendor_package_fires_every_pnp_check(tmp_path):
    path, metadata = _metadata(tmp_path, ATHEROS_SHAPED)
    coinst = check_pnp_vendor_coinstaller(path, metadata, {})
    assert "VendorCoInst.dll" in coinst and "WdfCoInstaller" not in coinst
    assert "USB\\VID_0489&PID_E078" in coinst
    service = check_pnp_system_service(path, metadata, {})
    assert "VendorBtSvc (VendorSvc.exe, auto start)" in service
    assert "performance_library" in check_pnp_autoload_registration(path, metadata, {})
    writable = check_pnp_writable_code_destination(path, metadata, {})
    assert "VendorTool.exe -> system_drive_root\\Vendor\\Tools" in writable
    assert check_pnp_installer_software(path, metadata, {}) is True


def test_microsoft_provider_is_left_to_windows_servicing(tmp_path):
    """The DriverStore shapes: tsgenericusbdriver.inf ships a Microsoft
    co-installer for a USB ID, mptfcore.inf a LocalSystem service and ks.inf
    RunOnce entries. None of them is vendor code Plug and Play pulls in."""
    text = ATHEROS_SHAPED.replace('VENDOR = "Example Vendor"', 'VENDOR = "Microsoft"')
    path, metadata = _metadata(tmp_path, text)
    assert check_pnp_vendor_coinstaller(path, metadata, {}) is True
    assert check_pnp_system_service(path, metadata, {}) is True
    assert check_pnp_autoload_registration(path, metadata, {}) is True
    # Code in a user-writable directory is a defect whoever ships it.
    assert check_pnp_writable_code_destination(path, metadata, {}) is not True


def test_internal_bus_package_is_not_pluggable(tmp_path):
    text = ATHEROS_SHAPED.replace("USB\\VID_0489&PID_E078", "PCI\\VEN_8086&DEV_1234").replace(
        ", USB\\Class_E0&SubClass_01&Prot_01", ""
    )
    path, metadata = _metadata(tmp_path, text)
    assert metadata["inf"]["external_bus"] is False
    assert check_pnp_vendor_coinstaller(path, metadata, {}) is True
    assert check_pnp_system_service(path, metadata, {}) is True
    # Registration and copy findings do not depend on how the device arrives.
    assert check_pnp_autoload_registration(path, metadata, {}) is not True


def test_framework_coinstaller_alone_is_silent(tmp_path):
    text = ATHEROS_SHAPED.replace('"VendorCoInst.dll,VendorCoInstaller", \\\n    ', "")
    path, metadata = _metadata(tmp_path, text)
    assert [co["dll"] for co in metadata["inf"]["co_installers"]] == ["WdfCoInstaller01011.dll"]
    assert check_pnp_vendor_coinstaller(path, metadata, {}) is True


def test_service_with_its_own_account_is_not_system(tmp_path):
    text = ATHEROS_SHAPED.replace(
        "ServiceType = 0x10\n", "ServiceType = 0x10\nStartName = NT AUTHORITY\\LocalService\n"
    )
    path, metadata = _metadata(tmp_path, text)
    assert check_pnp_system_service(path, metadata, {}) is True


# ---------------------------------------------------------------------------
# Package context on the binaries an INF names
# ---------------------------------------------------------------------------


def test_driver_package_context_names_the_service_binary(tmp_path):
    _write_inf(tmp_path / "pkg.inf", ATHEROS_SHAPED)
    binary = tmp_path / "VendorSvc.exe"
    binary.write_bytes(b"MZ")
    context = driver_package_context(str(binary))
    [package] = context["packages"]
    assert package["inf"] == "pkg.inf"
    assert package["external_bus"] is True
    assert [role["role"] for role in package["roles"]] == ["system_service"]
    metadata = {"driver_package": context}
    finding = check_pnp_privileged_component(str(binary), metadata, {})
    assert "system_service of pkg.inf" in finding


def test_driver_package_context_reads_the_parent_directory(tmp_path):
    _write_inf(tmp_path / "pkg.inf", ATHEROS_SHAPED)
    (tmp_path / "amd64").mkdir()
    binary = tmp_path / "amd64" / "VendorCoInst.dll"
    binary.write_bytes(b"MZ")
    [package] = driver_package_context(str(binary))["packages"]
    assert package["inf"] == os.path.join("..", "pkg.inf")
    assert package["roles"][0]["role"] == "co_installer"


def test_unnamed_binary_gets_no_context(tmp_path):
    _write_inf(tmp_path / "pkg.inf", ATHEROS_SHAPED)
    other = tmp_path / "unrelated.dll"
    other.write_bytes(b"MZ")
    assert driver_package_context(str(other)) is None
    framework = tmp_path / "WdfCoInstaller01011.dll"
    framework.write_bytes(b"MZ")
    # Copied or not, a Microsoft framework co-installer has no privileged role.
    assert driver_package_context(str(framework)) is None


def test_copied_only_binary_gets_context_without_a_finding(tmp_path):
    _write_inf(tmp_path / "pkg.inf", ATHEROS_SHAPED)
    tool = tmp_path / "VendorTool.exe"
    tool.write_bytes(b"MZ")
    context = driver_package_context(str(tool))
    [package] = context["packages"]
    assert package["roles"] == []
    assert package["copied_to"] == [
        {"dirid": "24", "subdir": "Vendor\\Tools", "writable": "system_drive_root"}
    ]
    assert check_pnp_privileged_component(str(tool), {"driver_package": context}, {}) is True


def test_microsoft_package_context_is_not_reported(tmp_path):
    text = ATHEROS_SHAPED.replace('VENDOR = "Example Vendor"', 'VENDOR = "Microsoft"')
    _write_inf(tmp_path / "pkg.inf", text)
    binary = tmp_path / "VendorSvc.exe"
    binary.write_bytes(b"MZ")
    metadata = {"driver_package": driver_package_context(str(binary))}
    assert check_pnp_privileged_component(str(binary), metadata, {}) is True


@pytest.mark.parametrize("rule_id", ["CHECK_PNP_PRIVILEGED_COMPONENT"])
def test_pe_rule_scope_covers_the_toolchain_exe_types(rule_id):
    from blint.lib import analysis as analysis_mod

    exe_types = set(analysis_mod.rules_dict[rule_id].get("exe_types") or [])
    assert {"PE32", "PE64", "dotnetbinary", "gobinary", "genericbinary"} <= exe_types


def test_inf_rules_are_scoped_to_inf_units():
    from blint.lib import analysis as analysis_mod

    for rule_id in (
        "CHECK_PNP_VENDOR_COINSTALLER",
        "CHECK_PNP_SYSTEM_SERVICE",
        "CHECK_PNP_INSTALLER_SOFTWARE",
        "CHECK_PNP_AUTOLOAD_REGISTRATION",
        "CHECK_PNP_WRITABLE_CODE_DESTINATION",
    ):
        assert analysis_mod.rules_dict[rule_id]["exe_types"] == ["inf"], rule_id


DRIVERSTORE = os.path.expanduser("~/sandbox/pe-corpus/tier6-driverstore")


@pytest.mark.skipif(not os.path.isdir(DRIVERSTORE), reason="DriverStore corpus not present")
def test_inbox_driverstore_raises_no_pnp_findings():
    """Every INF in a Windows 11 DriverStore and C:\\Windows\\INF parses, and
    none of them fires a Plug and Play rule."""
    checks = (
        check_pnp_vendor_coinstaller,
        check_pnp_system_service,
        check_pnp_installer_software,
        check_pnp_autoload_registration,
        check_pnp_writable_code_destination,
    )
    paths = find_inf_files(DRIVERSTORE)
    assert len(paths) > 400
    for path in paths:
        metadata = inf_metadata(parse_inf(path), path)
        assert not metadata["inf"].get("refused"), path
        for check in checks:
            assert check(path, metadata, {}) is True, (path, check.__name__)


# ---------------------------------------------------------------------------
# Runner: INF units in a directory and inside a driver CAB
# ---------------------------------------------------------------------------

HELLO_PE = os.path.join(os.path.dirname(__file__), "data", "pe", "msvc-hello-x64.exe")


def _run(tmp_path, src):
    import json
    import logging

    logging.disable(logging.CRITICAL)
    from blint.config import BlintOptions
    from blint.lib.runners import run_default_mode

    reports = tmp_path / "reports"
    run_default_mode(
        BlintOptions(
            src_dir_image=[str(src)], reports_dir=str(reports), no_reviews=True, quiet_mode=True
        )
    )
    findings = json.loads((reports / "findings.json").read_text())
    if isinstance(findings, dict):
        findings = findings.get("findings", [])
    by_file = {}
    for finding in findings:
        by_file.setdefault(os.path.basename(finding["filename"]), set()).add(finding["id"])
    return reports, by_file


def test_runner_scans_inf_beside_its_service_binary(tmp_path):
    import json

    package = tmp_path / "package"
    package.mkdir()
    _write_inf(package / "vendorbt.inf", ATHEROS_SHAPED)
    with open(HELLO_PE, "rb") as handle:
        (package / "VendorSvc.exe").write_bytes(handle.read())
    reports, by_file = _run(tmp_path, package)
    assert {
        "CHECK_PNP_VENDOR_COINSTALLER",
        "CHECK_PNP_SYSTEM_SERVICE",
        "CHECK_PNP_AUTOLOAD_REGISTRATION",
        "CHECK_PNP_WRITABLE_CODE_DESTINATION",
    } <= by_file["vendorbt.inf"]
    assert "CHECK_PNP_PRIVILEGED_COMPONENT" in by_file["VendorSvc.exe"]
    metadata = json.loads((reports / "VendorSvc.exe-metadata.json").read_text())
    assert metadata["driver_package"]["packages"][0]["inf"] == "vendorbt.inf"
    inf_unit = json.loads((reports / "vendorbt.inf-metadata.json").read_text())
    assert inf_unit["exe_type"] == "inf"


def test_runner_reads_inf_members_of_a_driver_cab(tmp_path):
    import json

    from tests.test_cab import build_cab

    with open(HELLO_PE, "rb") as handle:
        pe_bytes = handle.read()
    inf_bytes = b"\xff\xfe" + ATHEROS_SHAPED.encode("utf-16-le")
    cab = tmp_path / "driver.cab"
    cab.write_bytes(build_cab({"vendorbt.inf": inf_bytes, "VendorSvc.exe": pe_bytes}))
    reports, by_file = _run(tmp_path, cab)
    assert "CHECK_PNP_SYSTEM_SERVICE" in by_file["vendorbt.inf"]
    assert "CHECK_PNP_PRIVILEGED_COMPONENT" in by_file["VendorSvc.exe"]
    metadata = json.loads((reports / "VendorSvc.exe-metadata.json").read_text())
    # Relative to the cabinet, never the extraction directory.
    assert metadata["driver_package"]["packages"][0]["inf"] == "vendorbt.inf"
    coverage = json.loads((reports / "analysis-coverage.json").read_text())
    assert coverage["units_by_role"]["cab-member"]["succeeded"] == 2
