"""Tests for Windows driver IOCTL surface recovery and driver review rules."""

import struct

from blint.lib.binary_reviews import review_binary_metadata
from blint.lib.driver_ioctl import (
    classify_driver_strings,
    collect_driver_ioctls,
    collect_ioctl_tables,
    decode_ioctl,
    extract_ioctl_codes,
    extract_switch_ioctl_codes,
    find_dispatch_handlers,
    is_plausible_ioctl,
)

# Control codes published for LnvMSRIO.sys (CVE-2025-8061 and the follow-up PCI
# configuration space research). These are used as ground truth for the decoder.
LNVMSRIO_PHYS_READ = 0x9C406104
LNVMSRIO_PHYS_WRITE = 0x9C40A108
LNVMSRIO_PCI_READ = 0x9C406144
LNVMSRIO_PCI_WRITE = 0x9C40A148

# ThrottleStop.sys (CVE-2025-7771): the write code declares FILE_READ_ACCESS.
THROTTLESTOP_PHYS_READ = 0x80006498
THROTTLESTOP_PHYS_WRITE = 0x8000649C


def test_decode_ioctl_matches_published_lnvmsrio_values():
    read_code = decode_ioctl(LNVMSRIO_PHYS_READ)
    assert read_code["device_type"] == "0x9C40"
    assert read_code["function_code"] == "0x841"
    assert read_code["method"] == "METHOD_BUFFERED"
    assert read_code["access"] == "FILE_READ_ACCESS"

    write_code = decode_ioctl(LNVMSRIO_PHYS_WRITE)
    assert write_code["function_code"] == "0x842"
    assert write_code["access"] == "FILE_WRITE_ACCESS"

    pci_read = decode_ioctl(LNVMSRIO_PCI_READ)
    assert pci_read["function_code"] == "0x851"
    assert pci_read["access"] == "FILE_READ_ACCESS"

    pci_write = decode_ioctl(LNVMSRIO_PCI_WRITE)
    assert pci_write["function_code"] == "0x852"
    assert pci_write["access"] == "FILE_WRITE_ACCESS"


def test_decode_ioctl_matches_published_throttlestop_values():
    read_code = decode_ioctl(THROTTLESTOP_PHYS_READ)
    write_code = decode_ioctl(THROTTLESTOP_PHYS_WRITE)
    assert read_code["device_type"] == "0x8000"
    assert read_code["function_code"] == "0x926"
    assert write_code["function_code"] == "0x927"
    # The documented flaw: the write code declares read access.
    assert write_code["access"] == "FILE_READ_ACCESS"


def test_is_plausible_ioctl_filters_unrelated_constants():
    assert is_plausible_ioctl(LNVMSRIO_PCI_READ)
    assert is_plausible_ioctl(0x00220000 | 0x2000)
    # Small immediates, and device types outside the custom ranges, are noise.
    assert not is_plausible_ioctl(0x1234)
    assert not is_plausible_ioctl(0x00010004)
    assert not is_plausible_ioctl(0xDEAD)


def test_find_dispatch_handlers_detects_device_control_slot_store():
    disassembled = {
        "0x140001000::DriverEntry": {
            "name": "DriverEntry",
            "address": "0x140001000",
            "assembly": (
                "lea rax, [rip+0x900]\n"
                "mov qword ptr [rcx+0xe0], rax\n"
                "mov qword ptr [rcx+0xe8], rax\n"
                "ret"
            ),
        },
        "0x140002000::unrelated": {
            "name": "unrelated",
            "address": "0x140002000",
            "assembly": "mov qword ptr [rcx+0x20], rax\nret",
        },
    }
    handlers = find_dispatch_handlers(disassembled)
    slots = {handler["slot"] for handler in handlers}
    assert slots == {"IRP_MJ_DEVICE_CONTROL", "IRP_MJ_INTERNAL_DEVICE_CONTROL"}
    assert all(handler["function"] == "DriverEntry" for handler in handlers)


def test_extract_ioctl_codes_reads_compare_chain():
    func_data = {
        "assembly": (
            "cmp eax, 0x9c406104\n"
            "je handler_read\n"
            "cmp eax, 0x9c40a108\n"
            "je handler_write\n"
            "cmp eax, 0x9c406144\n"
            "je handler_pci_read\n"
            "mov ecx, 0xdeadbeef\n"
            "cmp ebx, 8\n"
        ).lower()
    }
    codes = extract_ioctl_codes(func_data)
    assert LNVMSRIO_PHYS_READ in codes
    assert LNVMSRIO_PHYS_WRITE in codes
    assert LNVMSRIO_PCI_READ in codes
    # 0xdeadbeef is a `mov`, not a compare, so it must not be harvested.
    assert 0xDEADBEEF not in codes


def _lnvmsrio_like_disassembly():
    return {
        "0x140001000::DriverEntry": {
            "name": "DriverEntry",
            "address": "0x140001000",
            "assembly": "lea rax, [rip+0x900]\nmov qword ptr [rcx+0xe0], rax\nret",
        },
        "0x140001500::DispatchDeviceControl": {
            "name": "DispatchDeviceControl",
            "address": "0x140001500",
            "assembly": (
                "cmp eax, 0x9c406104\n"
                "je loc_read\n"
                "cmp eax, 0x9c40a108\n"
                "je loc_write\n"
                "cmp eax, 0x9c406144\n"
                "je loc_pci_read\n"
                "cmp eax, 0x9c40a148\n"
                "je loc_pci_write\n"
            ),
        },
    }


def test_collect_driver_ioctls_recovers_full_surface():
    result = collect_driver_ioctls(_lnvmsrio_like_disassembly())
    codes = {entry["code"] for entry in result["ioctls"]}
    assert codes == {"0x9C406104", "0x9C406144", "0x9C40A108", "0x9C40A148"}
    assert result["device_types"] == ["0x9C40"]
    assert [handler["slot"] for handler in result["dispatch_handlers"]] == [
        "IRP_MJ_DEVICE_CONTROL"
    ]
    # Codes recovered inside the dispatch routine are high confidence.
    assert all(entry["confidence"] == "high" for entry in result["ioctls"])
    functions = {entry["function"] for entry in result["ioctls"]}
    assert functions == {"DispatchDeviceControl"}


def test_collect_driver_ioctls_returns_empty_for_non_driver():
    disassembled = {
        "0x401000::main": {
            "name": "main",
            "address": "0x401000",
            "assembly": "mov eax, 1\ncmp eax, 2\nret",
        }
    }
    assert collect_driver_ioctls(disassembled) == {}
    assert collect_driver_ioctls({}) == {}


def test_weak_access_flags_read_only_write_sibling():
    disassembled = {
        "0x140001500::DispatchDeviceControl": {
            "name": "DispatchDeviceControl",
            "address": "0x140001500",
            "assembly": "cmp eax, 0x80006498\nje loc_read\ncmp eax, 0x8000649c\nje loc_write\n",
        }
    }
    result = collect_driver_ioctls(disassembled)
    by_code = {entry["code"]: entry for entry in result["ioctls"]}
    # The read half is correctly declared; the write sibling is under-declared.
    assert "weak_access" not in by_code["0x80006498"]
    assert by_code["0x8000649C"]["weak_access"] == "read_write_pair_declares_read_only"


def test_weak_access_flags_file_any_access():
    # Function 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS.
    any_access_code = (0x8000 << 16) | (0x900 << 2)
    disassembled = {
        "0x140001500::Dispatch": {
            "name": "Dispatch",
            "address": "0x140001500",
            "assembly": (
                f"cmp eax, {any_access_code:#x}\nje loc_a\n"
                f"cmp eax, {any_access_code + 4:#x}\n"
            ),
        }
    }
    result = collect_driver_ioctls(disassembled)
    assert all(entry["weak_access"] == "FILE_ANY_ACCESS" for entry in result["ioctls"])


DRIVER_REVIEW_RULES = [
    {
        "DRIVER_INSECURE_DEVICE_OBJECT": {"check_type": "binary_analysis"},
        "DRIVER_IOCTL_WEAK_DECLARED_ACCESS": {"check_type": "binary_analysis"},
    }
]

DRIVER_REVIEW_RULES_ALL = [
    {
        "DRIVER_INSECURE_DEVICE_OBJECT": {"check_type": "binary_analysis"},
        "DRIVER_IOCTL_WEAK_DECLARED_ACCESS": {"check_type": "binary_analysis"},
        "BYOVD_EXPLOIT_CLIENT_DEVICE_ACCESS": {"check_type": "binary_analysis"},
        "BYOVD_DRIVER_LOADER_SERVICE_INSTALL": {"check_type": "binary_analysis"},
    }
]


def test_insecure_device_object_fires_without_access_checks():
    metadata = {
        "exe_type": "PE64",
        "imports": [
            {"name": "IoCreateDevice"},
            {"name": "IoCreateSymbolicLink"},
            {"name": "HalGetBusDataByOffset"},
            {"name": "HalSetBusDataByOffset"},
        ],
    }
    results = review_binary_metadata(DRIVER_REVIEW_RULES, metadata, 5)
    assert "DRIVER_INSECURE_DEVICE_OBJECT" in results
    assert results["DRIVER_INSECURE_DEVICE_OBJECT"][0]["primitive"] == "halgetbusdatabyoffset"


def test_insecure_device_object_detects_msr_instruction_primitive():
    metadata = {
        "exe_type": "PE64",
        "imports": [{"name": "IoCreateDevice"}],
        "disassembled_functions": {
            "0x140001000::read_msr": {
                "name": "read_msr",
                "address": "0x140001000",
                "assembly": "mov ecx, edx\nrdmsr\nret",
            }
        },
    }
    results = review_binary_metadata(DRIVER_REVIEW_RULES, metadata, 5)
    assert results["DRIVER_INSECURE_DEVICE_OBJECT"][0]["primitive"] == "rdmsr"


def test_insecure_device_object_suppressed_by_access_check_import():
    metadata = {
        "exe_type": "PE64",
        "imports": [
            {"name": "IoCreateDevice"},
            {"name": "HalGetBusDataByOffset"},
            {"name": "SeSinglePrivilegeCheck"},
        ],
    }
    assert review_binary_metadata(DRIVER_REVIEW_RULES, metadata, 5) == {}


def test_insecure_device_object_suppressed_by_secure_device_creation():
    metadata = {
        "exe_type": "PE64",
        "imports": [
            {"name": "WdmlibIoCreateDeviceSecure"},
            {"name": "MmMapIoSpace"},
        ],
    }
    assert review_binary_metadata(DRIVER_REVIEW_RULES, metadata, 5) == {}


def test_insecure_device_object_suppressed_by_sddl_string():
    metadata = {
        "exe_type": "PE64",
        "imports": [{"name": "IoCreateDevice"}, {"name": "MmMapIoSpace"}],
        "informative_strings": [{"value": "D:P(A;;GA;;;SY)(A;;GA;;;BA)"}],
    }
    assert review_binary_metadata(DRIVER_REVIEW_RULES, metadata, 5) == {}


def test_insecure_device_object_ignores_user_mode_binary():
    metadata = {
        "exe_type": "PE64",
        "imports": [{"name": "CreateFileW"}, {"name": "DeviceIoControl"}],
    }
    assert review_binary_metadata(DRIVER_REVIEW_RULES, metadata, 5) == {}


def test_weak_declared_access_rule_reports_recovered_codes():
    metadata = {
        "exe_type": "PE64",
        "driver_ioctls": {
            "ioctls": [
                {
                    "code": "0x8000649C",
                    "function": "Dispatch",
                    "access": "FILE_READ_ACCESS",
                    "method": "METHOD_BUFFERED",
                    "weak_access": "read_write_pair_declares_read_only",
                },
                {
                    "code": "0x80006498",
                    "function": "Dispatch",
                    "access": "FILE_READ_ACCESS",
                    "method": "METHOD_BUFFERED",
                },
            ]
        },
    }
    results = review_binary_metadata(DRIVER_REVIEW_RULES, metadata, 5)
    evidence = results["DRIVER_IOCTL_WEAK_DECLARED_ACCESS"]
    assert len(evidence) == 1
    assert evidence[0]["code"] == "0x8000649C"


def test_lnvmsrio_shaped_driver_triggers_full_rule_set_end_to_end():
    """Simulate an LnvMSRIO.sys-shaped driver through the real rule pipeline."""
    from blint.config import BlintOptions
    from blint.lib.analysis import initialize_rules
    from blint.lib.review_runner import ReviewRunner

    initialize_rules(BlintOptions())

    disassembled = _lnvmsrio_like_disassembly()
    disassembled["0x140002790::read_pci_config"] = {
        "name": "read_pci_config",
        "address": "0x140002790",
        "assembly": (
            "mov eax, [rsp+0x50]\n"
            "shr eax, 8\n"
            "and eax, 0xff\n"
            "mov ecx, 4\n"
            "call HalGetBusDataByOffset\n"
            "ret"
        ),
        "direct_calls": ["HalGetBusDataByOffset"],
        "instruction_metrics": {},
        "instruction_count": 6,
    }
    disassembled["0x140002900::read_msr_handler"] = {
        "name": "read_msr_handler",
        "address": "0x140002900",
        "assembly": "mov ecx, [rdx]\nrdmsr\nmov [r8], eax\nret",
        "direct_calls": [],
        "instruction_metrics": {},
        "instruction_count": 4,
    }

    metadata = {
        "exe_type": "PE64",
        "magic": "PE32+",
        "imports": [
            {"name": "IoCreateDevice"},
            {"name": "IoCreateSymbolicLink"},
            {"name": "MmMapIoSpace"},
            {"name": "HalGetBusDataByOffset"},
            {"name": "HalSetBusDataByOffset"},
        ],
        "disassembled_functions": disassembled,
        "driver_ioctls": collect_driver_ioctls(disassembled),
    }

    reviewer = ReviewRunner()
    reviewer.run_review(metadata)
    rule_ids = {result["id"] for result in reviewer.process_review("LnvMSRIO.sys", "LnvMSRIO.sys")}

    assert "BYOVD_PCI_CONFIG_READ" in rule_ids
    assert "BYOVD_PCI_CONFIG_WRITE" in rule_ids
    assert "BYOVD_PHYS_MEM_MAPPING" in rule_ids
    assert "BYOVD_PORT_IO_MSR_INSTRUCTIONS" in rule_ids
    assert "BYOVD_PCI_CONFIG_UNVALIDATED_DISPATCH" in rule_ids
    assert "DRIVER_INSECURE_DEVICE_OBJECT" in rule_ids


def test_well_behaved_driver_does_not_trigger_driver_rules_end_to_end():
    """A driver with a secure device object and privilege checks stays quiet."""
    from blint.config import BlintOptions
    from blint.lib.analysis import initialize_rules
    from blint.lib.review_runner import ReviewRunner

    initialize_rules(BlintOptions())

    metadata = {
        "exe_type": "PE64",
        "magic": "PE32+",
        "imports": [
            {"name": "WdmlibIoCreateDeviceSecure"},
            {"name": "SeSinglePrivilegeCheck"},
            {"name": "HalGetBusDataByOffset"},
        ],
        "disassembled_functions": {
            "0x140002790::checked_read_pci": {
                "name": "checked_read_pci",
                "address": "0x140002790",
                "assembly": (
                    "call SeSinglePrivilegeCheck\ntest al, al\njz fail\n"
                    "call HalGetBusDataByOffset\nret"
                ),
                "direct_calls": ["SeSinglePrivilegeCheck", "HalGetBusDataByOffset"],
                "instruction_metrics": {},
                "instruction_count": 5,
            }
        },
    }

    reviewer = ReviewRunner()
    reviewer.run_review(metadata)
    rule_ids = {result["id"] for result in reviewer.process_review("good.sys", "good.sys")}

    assert "DRIVER_INSECURE_DEVICE_OBJECT" not in rule_ids
    assert "BYOVD_PCI_CONFIG_UNVALIDATED_DISPATCH" not in rule_ids
    # The capability itself is still reported, since the import is genuinely present.
    assert "BYOVD_PCI_CONFIG_READ" in rule_ids


def test_dispatch_detection_rejects_user_mode_false_positive_shapes():
    """Regression: shapes observed in a real user-mode PE (myLittleLpe.exe).

    Before the store/load distinction was enforced, these eleven instructions
    produced eight bogus dispatch handlers in a 491-function user-mode binary.
    """
    false_positive_shapes = [
        "mov rbx, qword ptr [rbp + 232]",  # load, not a store
        "mov rcx, qword ptr [rsp + 224]",  # load from a stack local
        "mov qword ptr [rsp + 224], rax",  # store to a stack local
        "mov qword ptr [rbp + 232], rax",  # store to a stack local
        "mov dword ptr [rcx + 232], eax",  # dword, not a pointer-sized slot
        "mov r13, qword ptr [rsp + 224]",
        "mov rax, qword ptr [rbx + 224]",
        "mov rax, qword ptr [rcx + 232]",
    ]
    for shape in false_positive_shapes:
        disassembled = {
            "0x140001000::f": {"name": "f", "address": "0x140001000", "assembly": shape}
        }
        assert find_dispatch_handlers(disassembled) == [], f"false positive on: {shape}"


def test_dispatch_detection_accepts_decimal_offset_store():
    """Real disassembly renders the slot offset in decimal, not hex."""
    disassembled = {
        "0x140001000::DriverEntry": {
            "name": "DriverEntry",
            "address": "0x140001000",
            "assembly": "lea rax, [rip + 0x900]\nmov qword ptr [rcx + 224], rax\nret",
        }
    }
    handlers = find_dispatch_handlers(disassembled)
    assert [handler["slot"] for handler in handlers] == ["IRP_MJ_DEVICE_CONTROL"]


def test_is_kernel_driver_gates_user_mode_binaries():
    from blint.lib.driver_ioctl import is_kernel_driver

    # A real user-mode exploit client: CUI subsystem, no kernel-only imports.
    assert not is_kernel_driver(
        {"subsystem": "WINDOWS_CUI", "imports": [{"name": "DeviceIoControl"}]}
    )
    assert not is_kernel_driver({})
    # Native subsystem, or kernel-only imports, identify a driver.
    assert is_kernel_driver({"subsystem": "NATIVE"})
    assert is_kernel_driver({"subsystem": "WINDOWS_GUI", "imports": [{"name": "IoCreateDevice"}]})


# Real nyxstone output for the same two instructions under each IntegerBase
# style, captured from `Nyxstone("x86_64", immediate_style=...)`. blint defaults
# to Dec, but immediate_style is a caller-settable parameter of
# disassemble_functions, so every style has to be understood.
NYXSTONE_RENDERINGS = {
    "Dec": "mov edx, 2147509400\nmov qword ptr [rcx + 224], rax",
    "HexPrefix": "mov edx, 0x80006498\nmov qword ptr [rcx + 0xe0], rax",
    "HexSuffix": "mov edx, 80006498h\nmov qword ptr [rcx + 0e0h], rax",
}


def test_immediate_recovery_handles_every_disassembler_integer_base():
    from blint.lib.driver_ioctl import extract_client_ioctl_codes

    for style, assembly in NYXSTONE_RENDERINGS.items():
        codes = extract_client_ioctl_codes({"assembly": assembly})
        assert THROTTLESTOP_PHYS_READ in codes, f"missed control code in {style} rendering"


def test_dispatch_slot_detection_handles_every_disassembler_integer_base():
    for style, assembly in NYXSTONE_RENDERINGS.items():
        disassembled = {"0x1000::f": {"name": "f", "address": "0x1000", "assembly": assembly}}
        handlers = find_dispatch_handlers(disassembled)
        assert [h["slot"] for h in handlers] == ["IRP_MJ_DEVICE_CONTROL"], (
            f"missed dispatch slot in {style} rendering"
        )


def test_aarch64_hash_prefixed_immediates_are_recovered():
    from blint.lib.driver_ioctl import extract_client_ioctl_codes

    # AArch64 renders immediates with a '#' prefix.
    codes = extract_client_ioctl_codes({"assembly": "mov w1, #0x80006498"})
    assert THROTTLESTOP_PHYS_READ in codes


def test_status_codes_and_compiler_magic_are_not_mistaken_for_ioctls():
    """Regression: values seen in a real user-mode PE that must not decode."""
    for noise in (
        0xC000000D,  # STATUS_INVALID_PARAMETER
        0xC0000409,  # STATUS_STACK_BUFFER_OVERRUN
        0xE06D7363,  # C++ exception magic
        0xCCCCCCCD,  # division reciprocal
        0xFFFFFFFF,  # -1 sentinel
        0xD0030000,
    ):
        assert not is_plausible_ioctl(noise), f"{noise:#x} should not decode as an IOCTL"
    # The genuine vendor-range codes still pass.
    assert is_plausible_ioctl(THROTTLESTOP_PHYS_READ)
    assert is_plausible_ioctl(LNVMSRIO_PCI_WRITE)


def test_vendor_function_code_floor_rejects_reserved_and_sign_bit_constants():
    """Regression: constants from the real exploit client that must not decode.

    All three fell in the vendor device-type range but used Microsoft-reserved
    function codes below 0x800.
    """
    for noise in (0x80000000, 0x80000026, 0x80000029):
        assert not is_plausible_ioctl(noise), f"{noise:#x} should not decode as an IOCTL"
    # Both documented CVE code sets use third-party function codes and survive.
    for real in (
        THROTTLESTOP_PHYS_READ,
        THROTTLESTOP_PHYS_WRITE,
        LNVMSRIO_PHYS_READ,
        LNVMSRIO_PCI_WRITE,
    ):
        assert is_plausible_ioctl(real)


def _exploit_client_metadata():
    """Metadata shaped like the CVE-2025-7771 proof-of-concept client."""
    return {
        "exe_type": "PE64",
        "magic": "PE32+",
        "subsystem": "WINDOWS_CUI",
        "imports": [
            {"name": "KERNEL32.dll::CreateFileW"},
            {"name": "KERNEL32.dll::DeviceIoControl"},
        ],
        "disassembled_functions": {
            "0x1400019f0::sub_19f0": {
                "name": "sub_19f0",
                "address": "0x1400019f0",
                "assembly": "mov edx, 2147509400\nmov rcx, rax\ncall qword ptr [rip + 0x1000]",
                "direct_calls": [],
                "instruction_metrics": {},
                "instruction_count": 3,
            },
            "0x140002030::sub_2030": {
                "name": "sub_2030",
                "address": "0x140002030",
                "assembly": "mov edx, 2147509404\nmov rcx, rax\ncall qword ptr [rip + 0x1000]",
                "direct_calls": [],
                "instruction_metrics": {},
                "instruction_count": 3,
            },
        },
    }


def test_exploit_client_rule_fires_on_device_plus_vendor_ioctl():
    results = review_binary_metadata(DRIVER_REVIEW_RULES_ALL, _exploit_client_metadata(), 10)
    evidence = results["BYOVD_EXPLOIT_CLIENT_DEVICE_ACCESS"]
    codes = {entry["code"] for entry in evidence}
    assert codes == {"0x80006498", "0x8000649C"}


def test_exploit_client_rule_requires_both_open_and_control_apis():
    metadata = _exploit_client_metadata()
    # DeviceIoControl alone, with no device-open API, is not the client shape.
    metadata["imports"] = [{"name": "KERNEL32.dll::DeviceIoControl"}]
    assert "BYOVD_EXPLOIT_CLIENT_DEVICE_ACCESS" not in review_binary_metadata(
        DRIVER_REVIEW_RULES_ALL, metadata, 10
    )


def test_exploit_client_rule_ignores_ordinary_file_io_binary():
    metadata = _exploit_client_metadata()
    metadata["disassembled_functions"] = {
        "0x401000::main": {
            "name": "main",
            "address": "0x401000",
            "assembly": "mov edx, 1024\nmov ecx, 66\ncall qword ptr [rip + 0x10]",
            "direct_calls": [],
            "instruction_metrics": {},
            "instruction_count": 3,
        }
    }
    assert "BYOVD_EXPLOIT_CLIENT_DEVICE_ACCESS" not in review_binary_metadata(
        DRIVER_REVIEW_RULES_ALL, metadata, 10
    )


def test_exploit_client_rule_does_not_fire_on_the_driver_itself():
    """A driver legitimately handles these codes; only clients are flagged."""
    metadata = _exploit_client_metadata()
    metadata["subsystem"] = "NATIVE"
    assert "BYOVD_EXPLOIT_CLIENT_DEVICE_ACCESS" not in review_binary_metadata(
        DRIVER_REVIEW_RULES_ALL, metadata, 10
    )


def test_driver_loader_rule_fires_on_service_install_and_ntloaddriver():
    service_install = {
        "exe_type": "PE64",
        "subsystem": "WINDOWS_CUI",
        "imports": [
            {"name": "ADVAPI32.dll::OpenSCManagerW"},
            {"name": "ADVAPI32.dll::CreateServiceW"},
            {"name": "ADVAPI32.dll::StartServiceW"},
        ],
    }
    results = review_binary_metadata(DRIVER_REVIEW_RULES_ALL, service_install, 10)
    assert "BYOVD_DRIVER_LOADER_SERVICE_INSTALL" in results

    direct_load = {
        "exe_type": "PE64",
        "subsystem": "WINDOWS_CUI",
        "imports": [{"name": "ntdll.dll::NtLoadDriver"}],
    }
    assert "BYOVD_DRIVER_LOADER_SERVICE_INSTALL" in review_binary_metadata(
        DRIVER_REVIEW_RULES_ALL, direct_load, 10
    )


def test_driver_loader_rule_ignores_service_query_only_binary():
    metadata = {
        "exe_type": "PE64",
        "subsystem": "WINDOWS_CUI",
        "imports": [
            {"name": "ADVAPI32.dll::OpenSCManagerW"},
            {"name": "ADVAPI32.dll::QueryServiceStatus"},
        ],
    }
    assert "BYOVD_DRIVER_LOADER_SERVICE_INSTALL" not in review_binary_metadata(
        DRIVER_REVIEW_RULES_ALL, metadata, 10
    )


def test_dll_qualified_imports_are_matched():
    """Real PE metadata qualifies imports as `library::function`."""
    metadata = {
        "exe_type": "PE64",
        "subsystem": "NATIVE",
        "imports": [
            {"name": "ntoskrnl.exe::IoCreateDevice"},
            {"name": "HAL.dll::HalGetBusDataByOffset"},
        ],
    }
    results = review_binary_metadata(DRIVER_REVIEW_RULES_ALL, metadata, 10)
    assert "DRIVER_INSECURE_DEVICE_OBJECT" in results
    assert results["DRIVER_INSECURE_DEVICE_OBJECT"][0]["primitive"] == "halgetbusdatabyoffset"


# --- Jump-table switch dispatch -------------------------------------------


def test_switch_lowering_recovers_sibling_case_codes():
    """A scaled index means each case is one function code, so the span enumerates.

    The `shr eax, 2` is the compiler dividing the code delta by four; without it
    the indices are raw deltas and the cases could sit anywhere in the span.
    """
    base = THROTTLESTOP_PHYS_READ
    func_data = {
        "assembly": (
            f"mov eax, [rbx+0x18]\nsub eax, {base:#x}\nshr eax, 2\ncmp eax, 0x2\nja default_case\n"
        )
    }
    codes = extract_switch_ioctl_codes(func_data)
    assert codes == [base, base + 4, base + 8]
    # 0x8000649C is the documented physical-memory write code, reachable only
    # through the case span and invisible to a compare-only scan.
    assert THROTTLESTOP_PHYS_WRITE in codes


def test_switch_lowering_recovers_a_clang_style_lea_base():
    """clang folds the subtraction into `lea reg, [reg + two's complement]`.

    Observed in a real clang-built driver: `lea eax, [rcx + 2147474432]` followed
    by `rol eax, 30`, which is the same division by four as `shr eax, 2`.
    """
    base = THROTTLESTOP_PHYS_READ
    complement = (-base) & 0xFFFFFFFF
    func_data = {
        "assembly": f"lea eax, [rcx + {complement}]\nrol eax, 30\ncmp eax, 1\nja default\n"
    }
    assert extract_switch_ioctl_codes(func_data) == [base, base + 4]


def test_switch_lowering_accepts_the_add_of_a_negative_base():
    base = THROTTLESTOP_PHYS_READ
    func_data = {
        "assembly": f"add eax, {(-base) & 0xFFFFFFFF:#x}\nror eax, 2\ncmp eax, 0x1\njae default\n"
    }
    assert extract_switch_ioctl_codes(func_data) == [base, base + 4]


def test_unscaled_switch_reports_only_the_base():
    """Without the divide-by-four the span cannot be enumerated safely.

    A real clang build lowered a four-case dispatch this way, with the cases at
    indices 0, 4, 8 and 15 - the last varying the method bits. Stepping the span
    by four would have missed that case and invented one at index 12.
    """
    base = THROTTLESTOP_PHYS_READ
    func_data = {"assembly": f"lea eax, [rcx + {(-base) & 0xFFFFFFFF}]\ncmp eax, 15\nja default\n"}
    assert extract_switch_ioctl_codes(func_data) == [base]


def test_switch_lowering_requires_the_full_range_check_shape():
    base = THROTTLESTOP_PHYS_READ
    # No bounds jump: ordinary arithmetic, not a switch.
    assert not extract_switch_ioctl_codes(
        {"assembly": f"sub eax, {base:#x}\ncmp eax, 0x8\nje loc\n"}
    )
    # Range check on a different register.
    assert not extract_switch_ioctl_codes(
        {"assembly": f"sub eax, {base:#x}\ncmp ecx, 0x8\nja loc\n"}
    )
    # An implausibly wide span is not a dispatch table.
    assert not extract_switch_ioctl_codes(
        {"assembly": f"sub eax, {base:#x}\ncmp eax, 0x9000\nja loc\n"}
    )
    # A base that is not a plausible control code is ignored.
    assert not extract_switch_ioctl_codes({"assembly": "sub eax, 0x1234\ncmp eax, 0x8\nja loc\n"})


def test_switch_recovered_codes_are_not_reported_as_high_confidence():
    """A case span is an upper bound, so it must not outrank a literal compare."""
    disassembled = {
        "0x140001000::DriverEntry": {
            "name": "DriverEntry",
            "address": "0x140001000",
            "assembly": "lea rax, [rip+0x900]\nmov qword ptr [rcx+0xe0], rax\nret",
        },
        "0x140001500::Dispatch": {
            "name": "Dispatch",
            "address": "0x140001500",
            "assembly": (
                f"sub eax, {THROTTLESTOP_PHYS_READ:#x}\nshr eax, 2\ncmp eax, 0x2\nja default\n"
            ),
        },
    }
    result = collect_driver_ioctls(disassembled)
    entries = {entry["code"]: entry for entry in result["ioctls"]}
    # The base appears as a literal immediate, so it keeps the confidence a
    # compare earns. The siblings exist only because the case span implies them.
    assert entries["0x80006498"]["source"] == "compare"
    assert entries["0x80006498"]["confidence"] == "high"
    assert entries["0x8000649C"]["source"] == "switch"
    assert entries["0x8000649C"]["confidence"] == "medium"


# --- Data-section dispatch tables -----------------------------------------


def _packed_table(codes):
    return struct.pack(f"<{len(codes)}I", *codes)


def test_data_section_table_scan_recovers_loop_driven_dispatch_tables():
    """A table walked in a loop is never compared, so disassembly cannot see it."""
    codes = [0x80006498, 0x8000649C, 0x800064A0, 0x800064A4]
    sections = [(".rdata", b"\x00" * 16 + _packed_table(codes) + b"\x00" * 16)]
    assert collect_ioctl_tables(sections) == codes


def test_data_section_table_scan_requires_a_run_and_a_shared_device_type():
    # Two entries is below the minimum run length.
    assert not collect_ioctl_tables([(".rdata", _packed_table([0x80006498, 0x8000649C]))])
    # Mixed device types are not one table.
    assert not collect_ioctl_tables(
        [(".rdata", _packed_table([0x80006498, 0x9C40A108, 0x800064A0]))]
    )
    # Only the data sections that hold tables are scanned.
    assert not collect_ioctl_tables(
        [(".text", _packed_table([0x80006498, 0x8000649C, 0x800064A0]))]
    )


def test_data_section_table_scan_ignores_rva_tables_and_utf16_text():
    """The two shapes that would otherwise flood the results with false codes."""
    rva_table = _packed_table([0x00011000, 0x00011080, 0x00011100, 0x00011180])
    utf16_text = "\\Device\\ThrottleStop".encode("utf-16-le")
    assert not collect_ioctl_tables([(".rdata", rva_table), (".data", utf16_text)])


def test_table_recovered_codes_never_claim_compare_confidence():
    """A table entry is corroborated by its run, but was never seen compared."""
    codes = [0x80006498, 0x8000649C, 0x800064A0]
    result = collect_driver_ioctls({}, sections=[(".rdata", _packed_table(codes))])
    assert {entry["code"] for entry in result["ioctls"]} == {
        "0x80006498",
        "0x8000649C",
        "0x800064A0",
    }
    assert all(entry["source"] == "table" for entry in result["ioctls"])
    assert all(entry["confidence"] == "medium" for entry in result["ioctls"])
    # No function owns a table entry, so the field is present but unset.
    assert all(entry["function"] is None for entry in result["ioctls"])


# --- 32-bit dispatch slot -------------------------------------------------


def test_dispatch_detection_handles_the_x86_driver_object_layout():
    """A 32-bit driver stores through 0x38 + slot*4, not 0x70 + slot*8."""
    handlers = find_dispatch_handlers(
        {
            "0x401000::DriverEntry": {
                "name": "DriverEntry",
                "address": "0x401000",
                "assembly": "mov dword ptr [ecx+0x70], eax\nret",
            }
        }
    )
    assert [(h["slot"], h["layout"]) for h in handlers] == [("IRP_MJ_DEVICE_CONTROL", "x86")]


def test_x86_dispatch_detection_rejects_stack_frame_stores():
    assert not find_dispatch_handlers(
        {
            "0x401000::f": {
                "name": "f",
                "address": "0x401000",
                "assembly": "mov dword ptr [ebp+0x70], eax\nmov eax, dword ptr [ecx+0x70]\nret",
            }
        }
    )


# --- Kernel object namespace strings --------------------------------------


def test_classify_driver_strings_buckets_kernel_object_paths():
    metadata = {
        "strings": [
            {"value": "\\Device\\ThrottleStop"},
            {"value": "\\DosDevices\\ThrottleStop"},
            {"value": "\\??\\GLOBALROOT"},
            {"value": "\\\\.\\ThrottleStop"},
            {"value": "just some text"},
        ]
    }
    result = classify_driver_strings(metadata)
    assert result["device_names"] == ["\\Device\\ThrottleStop"]
    assert result["symbolic_links"] == ["\\??\\GLOBALROOT", "\\DosDevices\\ThrottleStop"]
    assert result["client_device_paths"] == ["\\\\.\\ThrottleStop"]


def test_classify_driver_strings_drops_runtime_templates():
    """A format string names an object that never exists under that name."""
    metadata = {"strings": ["\\Device\\%ls", "\\DosDevices\\%s", "\\Device\\Real"]}
    assert classify_driver_strings(metadata) == {"device_names": ["\\Device\\Real"]}
    # A literal percent is not a template.
    assert classify_driver_strings({"strings": ["\\Device\\100%%Real"]})["device_names"]


def test_classify_driver_strings_returns_empty_when_nothing_matches():
    assert classify_driver_strings({"strings": ["hello", "C:\\Windows\\System32"]}) == {}
    assert classify_driver_strings({}) == {}


def test_insecure_device_object_evidence_names_the_device():
    metadata = {
        "exe_type": "PE64",
        "subsystem": "NATIVE",
        "imports": [{"name": "IoCreateDevice"}, {"name": "MmMapIoSpace"}],
        "driver_interface": {
            "device_names": ["\\Device\\ThrottleStop"],
            "symbolic_links": ["\\DosDevices\\ThrottleStop"],
        },
    }
    evidence = review_binary_metadata(DRIVER_REVIEW_RULES_ALL, metadata, 10)[
        "DRIVER_INSECURE_DEVICE_OBJECT"
    ][0]
    assert evidence["device_names"] == ["\\Device\\ThrottleStop"]
    assert evidence["symbolic_links"] == ["\\DosDevices\\ThrottleStop"]


# --- METHOD_NEITHER -------------------------------------------------------


METHOD_NEITHER_RULES = [{"DRIVER_IOCTL_METHOD_NEITHER": {"check_type": "binary_analysis"}}]

# Function 0x900, METHOD_NEITHER (low two bits set), FILE_ANY_ACCESS.
NEITHER_CODE = (0x8000 << 16) | (0x900 << 2) | 3


def _method_neither_metadata(imports):
    disassembled = {
        "0x140001500::Dispatch": {
            "name": "Dispatch",
            "address": "0x140001500",
            "assembly": f"cmp eax, {NEITHER_CODE:#x}\nje loc_a\n",
        }
    }
    return {
        "exe_type": "PE64",
        "subsystem": "NATIVE",
        "imports": [{"name": name} for name in imports],
        "disassembled_functions": disassembled,
        "driver_ioctls": collect_driver_ioctls(disassembled),
    }


def test_method_neither_rule_fires_without_a_probe_import():
    metadata = _method_neither_metadata(["IoCreateDevice", "MmMapIoSpace"])
    evidence = review_binary_metadata(METHOD_NEITHER_RULES, metadata, 10)[
        "DRIVER_IOCTL_METHOD_NEITHER"
    ]
    assert [entry["code"] for entry in evidence] == [f"0x{NEITHER_CODE:08X}"]


def test_method_neither_rule_suppressed_by_probe_import():
    metadata = _method_neither_metadata(["IoCreateDevice", "ntoskrnl.exe::ProbeForWrite"])
    assert "DRIVER_IOCTL_METHOD_NEITHER" not in review_binary_metadata(
        METHOD_NEITHER_RULES, metadata, 10
    )


def test_method_neither_rule_ignores_buffered_codes_and_user_mode_images():
    buffered = {
        "exe_type": "PE64",
        "subsystem": "NATIVE",
        "imports": [{"name": "IoCreateDevice"}],
        "driver_ioctls": collect_driver_ioctls(
            {
                "0x1500::Dispatch": {
                    "name": "Dispatch",
                    "address": "0x1500",
                    "assembly": f"cmp eax, {THROTTLESTOP_PHYS_READ:#x}\n",
                }
            }
        ),
    }
    assert "DRIVER_IOCTL_METHOD_NEITHER" not in review_binary_metadata(
        METHOD_NEITHER_RULES, buffered, 10
    )
    user_mode = dict(_method_neither_metadata(["MmMapIoSpace"]), subsystem="WINDOWS_GUI")
    user_mode["imports"] = [{"name": "CreateFileW"}]
    assert "DRIVER_IOCTL_METHOD_NEITHER" not in review_binary_metadata(
        METHOD_NEITHER_RULES, user_mode, 10
    )


def test_exploit_client_evidence_names_the_target_device():
    metadata = {
        "exe_type": "PE64",
        "imports": [{"name": "CreateFileW"}, {"name": "DeviceIoControl"}],
        "driver_interface": {"client_device_paths": ["\\\\.\\ThrottleStop"]},
        "disassembled_functions": {
            "0x401000::exploit": {
                "name": "exploit",
                "address": "0x401000",
                "assembly": f"mov edx, {THROTTLESTOP_PHYS_WRITE:#x}\ncall DeviceIoControl\n",
            }
        },
    }
    evidence = review_binary_metadata(DRIVER_REVIEW_RULES_ALL, metadata, 10)[
        "BYOVD_EXPLOIT_CLIENT_DEVICE_ACCESS"
    ]
    assert evidence[0]["target_devices"] == ["\\\\.\\ThrottleStop"]


def test_method_neither_rule_is_wired_into_the_real_rule_pipeline():
    """Locks the YAML definition and the BINARY_REVIEWS registration together."""
    from blint.config import BlintOptions
    from blint.lib.analysis import initialize_rules
    from blint.lib.review_runner import ReviewRunner

    initialize_rules(BlintOptions())

    metadata = _method_neither_metadata(["ntoskrnl.exe::IoCreateDevice", "MmMapIoSpace"])
    metadata["magic"] = "PE32+"
    metadata["driver_interface"] = {"device_names": ["\\Device\\Vulnerable"]}

    reviewer = ReviewRunner()
    reviewer.run_review(metadata)
    results = {result["id"]: result for result in reviewer.process_review("v.sys", "v.sys")}

    assert "DRIVER_IOCTL_METHOD_NEITHER" in results
    assert results["DRIVER_IOCTL_METHOD_NEITHER"]["evidence"][0]["code"] == f"0x{NEITHER_CODE:08X}"
    # The device the reviewer would have to open is carried on the finding.
    assert results["DRIVER_INSECURE_DEVICE_OBJECT"]["evidence"][0]["device_names"] == [
        "\\Device\\Vulnerable"
    ]


def test_binary_search_range_boundary_is_not_a_control_code():
    """Regression from a real clang build of contrib/win-driver-fixture.

    Dispatching on widely spaced codes lowers to a binary search, which compares
    against the boundary *below* a real code. Before the branch kind was taken
    into account, 0x80003443 was reported alongside the real 0x80003444.
    """
    disassembled = {
        "0x140001500::Dispatch": {
            "name": "Dispatch",
            "address": "0x140001500",
            "assembly": (
                "cmp eax, 0x80003443\nja higher_half\n"
                "cmp eax, 0x80003444\nje loc_handler\n"
                "cmp eax, 0x80002954\nje loc_other\n"
            ),
        }
    }
    codes = {entry["code"] for entry in collect_driver_ioctls(disassembled)["ioctls"]}
    assert codes == {"0x80003444", "0x80002954"}


def test_range_tested_code_is_kept_when_nothing_corroborates_the_off_by_one():
    """Only the shape `boundary, boundary+1` is dropped, not every range test."""
    disassembled = {
        "0x140001500::Dispatch": {
            "name": "Dispatch",
            "address": "0x140001500",
            "assembly": "cmp eax, 0x80003444\njbe loc_low\ncmp eax, 0x80002954\nje loc_other\n",
        }
    }
    codes = {entry["code"] for entry in collect_driver_ioctls(disassembled)["ioctls"]}
    assert "0x80003444" in codes


def test_msvc_style_span_in_code_units_is_enumerated():
    """MSVC leaves the index unscaled and bounds it in code units.

    Taken from a real MSVC build of contrib/win-driver-fixture: sixteen cases
    four apart give `cmp eax, 60`, not `cmp eax, 15`. A span that is a multiple
    of four puts the highest case a whole number of function codes above the
    base, so the range is function-code aligned and can be stepped out.
    """
    base = 0x80002440
    func_data = {
        "assembly": (
            f"lea eax, [rcx + {(-base) & 0xFFFFFFFF}]\nxor ebx, ebx\ncmp eax, 60\nja default\n"
        )
    }
    codes = extract_switch_ioctl_codes(func_data)
    assert codes == [base + step * 4 for step in range(16)]
