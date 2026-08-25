"""Tests for the side-loaded and passive-implant review heuristics.

Ground truth is the SLEEPWALKER sample described in
https://r136a1.dev/2026/08/24/sleepwalker-a-passive-backdoor-with-its-own-command-language/
(SHA-256 d347170752a28e2b8c4b8b9f3cab2e3a6541ba11682c94498d26eb9002779d60): a
59,904-byte x64 DLL posing as Microsoft's dpapi.dll with forged ESET version
resources, side-loaded into ERAAgent.exe.

Each rule is tested twice: once against the shape it is meant to catch, and once
against the legitimate shape that most resembles it. The negative cases matter
more than the positive ones, because a whole-binary rule that fires on ordinary
software makes every report less useful.
"""

from blint.lib.binary_reviews import review_binary_metadata
from blint.lib.implant_reviews import evaluate_implant_rule

# --------------------------------------------------------------------------
# Fixtures modelled on the real sample
# --------------------------------------------------------------------------

SLEEPWALKER_EXPORTS = [
    {"name": "CryptProtectDataNoUI", "ordinal": 1, "address": "0x1190", "is_forwarded": False},
    {"name": "CryptProtectMemory", "ordinal": 2, "address": "0x119a", "is_forwarded": False},
    {
        "name": "CryptResetMachineCredentials",
        "ordinal": 3,
        "address": "0x11a4",
        "is_forwarded": False,
    },
    {"name": "CryptUnprotectDataNoUI", "ordinal": 4, "address": "0x11ae", "is_forwarded": False},
    {"name": "CryptUnprotectMemory", "ordinal": 5, "address": "0x11b8", "is_forwarded": False},
    {
        "name": "CryptUpdateProtectedState",
        "ordinal": 6,
        "address": "0x11c2",
        "is_forwarded": False,
    },
    {"name": "iCryptIdentifyProtection", "ordinal": 7, "address": "0x11cc", "is_forwarded": False},
]

FORGED_RESOURCES = {
    "version_metadata": {
        "CompanyName": "ESET",
        "FileDescription": "ESET Management Agent Module",
        "InternalName": "ERAAgent",
        "OriginalFilename": "dpapi.dll",
        "ProductName": "ESET Management Agent",
    }
}


def sleepwalker_metadata(**overrides):
    """Build metadata resembling the real sample, with optional overrides."""
    metadata = {
        "exe_type": "PE64",
        "magic": "PE32+",
        "is_shared_library": True,
        "is_signed": False,
        "authenticode": {"verification_flags": "NO_SIGNATURE"},
        "resources": dict(FORGED_RESOURCES),
        "exports": list(SLEEPWALKER_EXPORTS),
        "imports": [
            {"name": "KERNEL32.dll::LoadLibraryW"},
            {"name": "KERNEL32.dll::GetModuleFileNameW"},
            {"name": "KERNEL32.dll::CreateNamedPipeW"},
            {"name": "KERNEL32.dll::ConnectNamedPipe"},
            {"name": "KERNEL32.dll::CreateFileW"},
            {"name": "KERNEL32.dll::DeviceIoControl"},
            {"name": "KERNEL32.dll::VirtualProtect"},
            {"name": "KERNEL32.dll::CreateThread"},
            {"name": "WS2_32.dll::WSAIoctl"},
            {"name": "WS2_32.dll::recvfrom"},
            {"name": "IPHLPAPI.DLL::IcmpSendEcho"},
            {"name": "ADVAPI32.dll::RegSetValueExW"},
        ],
        "stack_strings": [
            {"value": "\\\\.\\VMCI", "encoding": "utf-16le", "function": "sub_3be8"},
            {"value": "ERAAgent.exe", "encoding": "utf-16le", "function": "sub_10cc"},
            {"value": "everyoneincludesanonymous", "encoding": "ascii", "function": "sub_562c"},
            {"value": "NullSessionPipes", "encoding": "utf-16le", "function": "sub_57b0"},
            {
                "value": "YSTEM\\CurrentControlSet\\Serv",
                "encoding": "ascii",
                "function": "sub_57b0",
            },
        ],
        "strings": [{"value": "dpapisvc.dll"}],
        "crypto_material": {
            "algorithms": ["CRC-32", "SHA-256"],
            "opaque_regions": [
                {
                    "section": ".data",
                    "offset": "0x80",
                    "size": 2080,
                    "entropy": 7.908,
                    "section_size": 2560,
                    "section_fraction": 0.813,
                }
            ],
        },
    }
    metadata.update(overrides)
    return metadata


def benign_signed_library(**overrides):
    """A signed, honestly labelled DLL: the shape that must never match."""
    metadata = {
        "exe_type": "PE64",
        "magic": "PE32+",
        "is_shared_library": True,
        "is_signed": True,
        "authenticode": {"verification_flags": "OK"},
        "resources": {
            "version_metadata": {
                "CompanyName": "Example Corp",
                "OriginalFilename": "examplelib.dll",
                "ProductName": "Example Toolkit",
            }
        },
        "exports": [
            {"name": "ExampleInit", "ordinal": 1, "address": "0x1000", "is_forwarded": False},
            {"name": "ExampleRun", "ordinal": 2, "address": "0x1240", "is_forwarded": False},
            {"name": "ExampleStop", "ordinal": 3, "address": "0x1590", "is_forwarded": False},
        ],
        "imports": [
            {"name": "KERNEL32.dll::LoadLibraryW"},
            {"name": "KERNEL32.dll::GetModuleFileNameW"},
        ],
    }
    metadata.update(overrides)
    return metadata


# --------------------------------------------------------------------------
# PE_IMPERSONATES_SYSTEM_MODULE
# --------------------------------------------------------------------------


def test_impersonation_detected_on_forged_vendor_resources():
    evidence = evaluate_implant_rule("PE_IMPERSONATES_SYSTEM_MODULE", sleepwalker_metadata())
    assert len(evidence) == 1
    assert evidence[0]["claimed_module"] == "dpapi.dll"
    assert evidence[0]["declared_company"] == "ESET"


def test_impersonation_not_flagged_when_microsoft_is_the_declared_vendor():
    metadata = sleepwalker_metadata(
        resources={
            "version_metadata": {
                "CompanyName": "Microsoft Corporation",
                "OriginalFilename": "dpapi.dll",
            }
        }
    )
    assert evaluate_implant_rule("PE_IMPERSONATES_SYSTEM_MODULE", metadata) == []


def test_impersonation_not_flagged_when_validly_signed():
    """A signed file stands behind the name with a verifiable identity."""
    metadata = sleepwalker_metadata(is_signed=True, authenticode={"verification_flags": "OK"})
    assert evaluate_implant_rule("PE_IMPERSONATES_SYSTEM_MODULE", metadata) == []


def test_impersonation_not_flagged_for_a_non_system_filename():
    metadata = sleepwalker_metadata(
        resources={
            "version_metadata": {"CompanyName": "ESET", "OriginalFilename": "eset_module.dll"}
        }
    )
    assert evaluate_implant_rule("PE_IMPERSONATES_SYSTEM_MODULE", metadata) == []


# --------------------------------------------------------------------------
# PE_STUB_EXPORT_THUNK_TABLE
# --------------------------------------------------------------------------


def test_uniform_stride_exports_detected_as_stub_table():
    evidence = evaluate_implant_rule("PE_STUB_EXPORT_THUNK_TABLE", sleepwalker_metadata())
    assert len(evidence) == 1
    assert evidence[0]["stride_bytes"] == 10
    assert evidence[0]["export_count"] == 7


def test_real_functions_with_varying_sizes_are_not_a_stub_table():
    assert evaluate_implant_rule("PE_STUB_EXPORT_THUNK_TABLE", benign_signed_library()) == []


def test_genuine_forwarders_are_not_a_stub_table():
    """Re-exporting another module's API through real forwarders is supported."""
    exports = [
        {**entry, "is_forwarded": True, "fwd_library": "dpapi", "fwd_function": entry["name"]}
        for entry in SLEEPWALKER_EXPORTS
    ]
    metadata = sleepwalker_metadata(exports=exports)
    assert evaluate_implant_rule("PE_STUB_EXPORT_THUNK_TABLE", metadata) == []


def test_too_few_exports_is_not_a_stub_table():
    metadata = sleepwalker_metadata(exports=SLEEPWALKER_EXPORTS[:2])
    assert evaluate_implant_rule("PE_STUB_EXPORT_THUNK_TABLE", metadata) == []


# --------------------------------------------------------------------------
# PE_UNRESOLVED_SIBLING_MODULE_LOAD
# --------------------------------------------------------------------------


def test_near_miss_sibling_module_detected():
    evidence = evaluate_implant_rule("PE_UNRESOLVED_SIBLING_MODULE_LOAD", sleepwalker_metadata())
    assert [entry["module"] for entry in evidence] == ["dpapisvc.dll"]
    assert evidence[0]["resembles"] == "dpapi.dll"


def test_documented_windows_modules_are_not_reported():
    """Delay-loading OS modules is what ordinary software does.

    These are the exact names observed on legitimate binaries during development:
    reporting them made the rule useless.
    """
    metadata = sleepwalker_metadata(
        strings=[
            {"value": "OLEAUT32.dll"},
            {"value": "mscoree.dll"},
            {"value": "IpHlpApi.dll"},
            {"value": "icmp.dll"},
            {"value": "api-ms-win-core-synch-l1-2-0.dll"},
        ],
        stack_strings=[],
    )
    assert evaluate_implant_rule("PE_UNRESOLVED_SIBLING_MODULE_LOAD", metadata) == []


def test_unrelated_module_name_is_not_reported():
    """Only a name built to pass as a companion of a real module qualifies."""
    metadata = sleepwalker_metadata(strings=[{"value": "WUSER32.DLL"}], stack_strings=[])
    assert evaluate_implant_rule("PE_UNRESOLVED_SIBLING_MODULE_LOAD", metadata) == []


def test_products_satellite_dll_named_after_itself_is_not_reported():
    """A product naming its own resource DLL after itself is the normal case.

    These were all 5 false positives on a 400-binary benign corpus: comparing
    the runtime-loaded name against the image's *own* name rather than only
    against Microsoft module names.
    """
    metadata = sleepwalker_metadata(
        resources={
            "version_metadata": {
                "CompanyName": "Microsoft",
                "OriginalFilename": "CodeCoverage.exe",
            }
        },
        strings=[{"value": "codecoveragemessages.dll"}],
        stack_strings=[],
    )
    assert evaluate_implant_rule("PE_UNRESOLVED_SIBLING_MODULE_LOAD", metadata) == []


def test_per_architecture_variant_of_own_name_is_not_reported():
    metadata = sleepwalker_metadata(
        resources={
            "version_metadata": {
                "CompanyName": "Microsoft",
                "OriginalFilename": "msalruntime.dll",
            }
        },
        strings=[{"value": "msalruntime_x86.dll"}],
        stack_strings=[],
    )
    assert evaluate_implant_rule("PE_UNRESOLVED_SIBLING_MODULE_LOAD", metadata) == []


def test_declared_dependency_is_not_reported():
    metadata = sleepwalker_metadata(
        strings=[{"value": "KERNEL32.dll"}],
        stack_strings=[],
    )
    assert evaluate_implant_rule("PE_UNRESOLVED_SIBLING_MODULE_LOAD", metadata) == []


def test_executable_names_are_left_to_the_host_gate_rule():
    """An .exe name in a DLL is a host-process check, not a LoadLibrary target."""
    metadata = sleepwalker_metadata(strings=[{"value": "ERAAgent.exe"}], stack_strings=[])
    assert evaluate_implant_rule("PE_UNRESOLVED_SIBLING_MODULE_LOAD", metadata) == []


def test_no_loadlibrary_import_means_no_finding():
    metadata = sleepwalker_metadata(imports=[{"name": "KERNEL32.dll::CreateFileW"}])
    assert evaluate_implant_rule("PE_UNRESOLVED_SIBLING_MODULE_LOAD", metadata) == []


# --------------------------------------------------------------------------
# PE_HOST_PROCESS_NAME_GATE
# --------------------------------------------------------------------------


def test_host_process_gate_detected():
    evidence = evaluate_implant_rule("PE_HOST_PROCESS_NAME_GATE", sleepwalker_metadata())
    assert [entry["host_executable"] for entry in evidence] == ["ERAAgent.exe"]


def test_host_process_gate_requires_a_library():
    """An executable knowing its own name is not gating on a host."""
    metadata = sleepwalker_metadata(is_shared_library=False)
    assert evaluate_implant_rule("PE_HOST_PROCESS_NAME_GATE", metadata) == []


def test_host_process_gate_requires_a_runtime_built_name():
    """A stored host name is an ordinary configuration string."""
    metadata = sleepwalker_metadata(stack_strings=[])
    assert evaluate_implant_rule("PE_HOST_PROCESS_NAME_GATE", metadata) == []


# --------------------------------------------------------------------------
# PASSIVE_MULTI_TRANSPORT_LISTENER
# --------------------------------------------------------------------------


def test_multi_transport_listener_detected():
    evidence = evaluate_implant_rule("PASSIVE_MULTI_TRANSPORT_LISTENER", sleepwalker_metadata())
    assert len(evidence) == 1
    assert evidence[0]["transport_count"] >= 3
    assert "raw_socket" in evidence[0]["transports"]


def test_single_transport_server_is_not_flagged():
    """A server implementing one protocol is the common legitimate case."""
    metadata = sleepwalker_metadata(
        imports=[
            {"name": "WS2_32.dll::listen"},
            {"name": "WS2_32.dll::accept"},
        ]
    )
    assert evaluate_implant_rule("PASSIVE_MULTI_TRANSPORT_LISTENER", metadata) == []


def test_hardcoded_url_disqualifies_a_passive_listener():
    """An image that knows where to call out is not waiting to be contacted."""
    metadata = sleepwalker_metadata(strings=[{"value": "https://updates.example.com/v1"}])
    assert evaluate_implant_rule("PASSIVE_MULTI_TRANSPORT_LISTENER", metadata) == []


def test_hardcoded_routable_address_disqualifies_a_passive_listener():
    metadata = sleepwalker_metadata(strings=[{"value": "203.0.113.42"}])
    assert evaluate_implant_rule("PASSIVE_MULTI_TRANSPORT_LISTENER", metadata) == []


def test_loopback_address_does_not_count_as_a_destination():
    """Loopback and any-address are bind targets, not C2 destinations."""
    metadata = sleepwalker_metadata(
        strings=[{"value": "127.0.0.1"}, {"value": "0.0.0.0"}],
    )
    assert evaluate_implant_rule("PASSIVE_MULTI_TRANSPORT_LISTENER", metadata)


def test_http_client_import_disqualifies_a_passive_listener():
    metadata = sleepwalker_metadata(
        imports=[
            *sleepwalker_metadata()["imports"],
            {"name": "WINHTTP.dll::WinHttpConnect"},
        ]
    )
    assert evaluate_implant_rule("PASSIVE_MULTI_TRANSPORT_LISTENER", metadata) == []


# --------------------------------------------------------------------------
# COVERT_CHANNEL_DEVICE_ACCESS
# --------------------------------------------------------------------------


def test_vmci_covert_channel_detected():
    evidence = evaluate_implant_rule("COVERT_CHANNEL_DEVICE_ACCESS", sleepwalker_metadata())
    assert len(evidence) == 1
    assert evidence[0]["device"] == "\\\\.\\VMCI"


def test_named_pipe_is_not_a_covert_channel():
    """`\\\\.\\pipe\\...` is ordinary Windows IPC, not a monitoring bypass.

    These are the real paths that made this rule fire on 10 of 180 benign
    binaries: the SQL Server native client, the code-coverage collector, the
    .NET diagnostics channel and Rust's anonymous pipes.
    """
    for pipe_path in (
        "\\\\.\\pipe\\SQLLocal\\",
        "\\\\.\\pipe\\CodeCoverage.pipe.",
        "\\\\.\\pipe\\dotnet-diagnostic-%d",
        "\\\\.\\pipe\\__rust_anonymous_pipe1__.",
    ):
        metadata = sleepwalker_metadata(
            stack_strings=[{"value": pipe_path, "function": "sub_1"}], strings=[]
        )
        assert evaluate_implant_rule("COVERT_CHANNEL_DEVICE_ACCESS", metadata) == [], pipe_path


def test_ordinary_device_path_is_not_a_covert_channel():
    metadata = sleepwalker_metadata(
        stack_strings=[{"value": "\\\\.\\PhysicalDrive0", "function": "sub_1"}]
    )
    assert evaluate_implant_rule("COVERT_CHANNEL_DEVICE_ACCESS", metadata) == []


def test_covert_channel_requires_a_file_open_api():
    metadata = sleepwalker_metadata(imports=[{"name": "KERNEL32.dll::DeviceIoControl"}])
    assert evaluate_implant_rule("COVERT_CHANNEL_DEVICE_ACCESS", metadata) == []


def test_byovd_rule_defers_to_the_covert_channel_rule():
    """A hypervisor channel is not a vulnerable driver, so BYOVD must not claim it.

    Both rules are reached through the same import pair and a vendor-range control
    code; reporting VMCI as a BYOVD client names the capability wrongly.
    """
    metadata = sleepwalker_metadata(
        subsystem="Windows GUI",
        disassembled_functions={
            "0x1000::sub_1000": {
                "name": "sub_1000",
                "address": "0x1000",
                # 0x81032068: vendor device type, function code above 0x800.
                "assembly": "mov edx, 2164465768\ncall qword ptr [rip + 100]\nret",
            }
        },
        driver_interface={"client_device_paths": ["\\\\.\\VMCI"]},
    )
    review_binary_list = [
        {"BYOVD_EXPLOIT_CLIENT_DEVICE_ACCESS": {"check_type": "binary_analysis"}}
    ]
    results = review_binary_metadata(review_binary_list, metadata, 5)
    assert "BYOVD_EXPLOIT_CLIENT_DEVICE_ACCESS" not in results


def test_byovd_rule_still_fires_for_a_real_third_party_driver():
    metadata = sleepwalker_metadata(
        subsystem="Windows GUI",
        disassembled_functions={
            "0x1000::sub_1000": {
                "name": "sub_1000",
                "address": "0x1000",
                "assembly": "mov edx, 2147509400\ncall qword ptr [rip + 100]\nret",
            }
        },
        driver_interface={"client_device_paths": ["\\\\.\\ThrottleStop"]},
    )
    review_binary_list = [
        {"BYOVD_EXPLOIT_CLIENT_DEVICE_ACCESS": {"check_type": "binary_analysis"}}
    ]
    results = review_binary_metadata(review_binary_list, metadata, 5)
    assert "BYOVD_EXPLOIT_CLIENT_DEVICE_ACCESS" in results


# --------------------------------------------------------------------------
# RUNTIME_CONSTRUCTED_SECURITY_STRINGS
# --------------------------------------------------------------------------


def test_runtime_constructed_paths_reported():
    evidence = evaluate_implant_rule(
        "RUNTIME_CONSTRUCTED_SECURITY_STRINGS", sleepwalker_metadata()
    )
    values = {entry["value"] for entry in evidence}
    assert "\\\\.\\VMCI" in values


def test_partial_reconstruction_is_labelled_as_such():
    """A fragment is real evidence, but must not be presented as a whole path."""
    evidence = evaluate_implant_rule(
        "RUNTIME_CONSTRUCTED_SECURITY_STRINGS", sleepwalker_metadata()
    )
    complete = next(e for e in evidence if e["value"] == "\\\\.\\VMCI")
    partial = next(e for e in evidence if e["value"].startswith("YSTEM"))
    assert complete["partial"] is False
    assert partial["partial"] is True
    assert "partial reconstruction" in partial["detail"]


def test_innocuous_stack_strings_are_not_reported():
    metadata = sleepwalker_metadata(stack_strings=[{"value": "hello world", "function": "sub_1"}])
    assert evaluate_implant_rule("RUNTIME_CONSTRUCTED_SECURITY_STRINGS", metadata) == []


# --------------------------------------------------------------------------
# HOST_AUTHENTICATION_DOWNGRADE
# --------------------------------------------------------------------------


def test_authentication_downgrade_values_detected():
    evidence = evaluate_implant_rule("HOST_AUTHENTICATION_DOWNGRADE", sleepwalker_metadata())
    names = {entry["value_name"] for entry in evidence}
    assert "everyoneincludesanonymous" in names
    assert "nullsessionpipes" in names


def test_authentication_downgrade_requires_a_registry_write_api():
    """Naming a value without being able to write it is not the same finding."""
    metadata = sleepwalker_metadata(
        imports=[{"name": "ADVAPI32.dll::RegQueryValueExW"}],
    )
    assert evaluate_implant_rule("HOST_AUTHENTICATION_DOWNGRADE", metadata) == []


def test_unrelated_registry_writes_are_not_flagged():
    metadata = sleepwalker_metadata(
        stack_strings=[],
        strings=[{"value": "SOFTWARE\\Example\\Settings"}],
    )
    assert evaluate_implant_rule("HOST_AUTHENTICATION_DOWNGRADE", metadata) == []


# --------------------------------------------------------------------------
# EMBEDDED_ENCRYPTED_PAYLOAD
# --------------------------------------------------------------------------


def test_embedded_payload_detected():
    evidence = evaluate_implant_rule("EMBEDDED_ENCRYPTED_PAYLOAD", sleepwalker_metadata())
    assert len(evidence) == 1
    assert evidence[0]["size"] == 2080
    assert evidence[0]["section"] == ".data"


def test_small_share_of_a_large_section_is_not_a_payload():
    """A big program's .rdata holds certificates and compressed assets.

    Both benign binaries checked during development matched here before the
    section-share requirement was added.
    """
    metadata = sleepwalker_metadata(
        crypto_material={
            "algorithms": ["Base64", "MD5/SHA-1", "SHA-256"],
            "opaque_regions": [
                {
                    "section": ".rdata",
                    "offset": "0x10990",
                    "size": 7424,
                    "entropy": 7.942,
                    "section_size": 400000,
                    "section_fraction": 0.019,
                }
            ],
        }
    )
    assert evaluate_implant_rule("EMBEDDED_ENCRYPTED_PAYLOAD", metadata) == []


def test_read_only_data_payload_is_not_reported():
    """Read-only data legitimately holds self-extracting installer payloads.

    Python's distutils wininst-*.exe stubs were 3 of 3 false positives for this
    rule, with .rdata blobs at 37-48% of the section.
    """
    metadata = sleepwalker_metadata(
        crypto_material={
            "algorithms": ["MD5/SHA-1"],
            "opaque_regions": [
                {
                    "section": ".rdata",
                    "offset": "0x2000",
                    "size": 7424,
                    "entropy": 7.9,
                    "section_size": 15360,
                    "section_fraction": 0.484,
                }
            ],
        }
    )
    assert evaluate_implant_rule("EMBEDDED_ENCRYPTED_PAYLOAD", metadata) == []


def test_payload_without_any_identified_primitive_is_not_reported():
    """Opaque data alone could be compressed resources."""
    metadata = sleepwalker_metadata(
        crypto_material={
            "opaque_regions": [
                {
                    "section": ".data",
                    "offset": "0x80",
                    "size": 2080,
                    "entropy": 7.9,
                    "section_size": 2560,
                    "section_fraction": 0.81,
                }
            ]
        }
    )
    assert evaluate_implant_rule("EMBEDDED_ENCRYPTED_PAYLOAD", metadata) == []


# --------------------------------------------------------------------------
# CUSTOM_COMMAND_DISPATCH_TABLE
# --------------------------------------------------------------------------


def _pointer_table_assembly(count: int) -> str:
    lines = []
    for index in range(count):
        lines.append(f"lea rax, [rip + {1000 + index * 16}]")
        lines.append(f"mov qword ptr [rdi + {index * 8}], rax")
    lines.append("ret")
    return "\n".join(lines)


def test_dispatch_table_detected():
    metadata = sleepwalker_metadata(
        disassembled_functions={
            "0x3cd4::sub_3cd4": {
                "name": "sub_3cd4",
                "address": "0x180003cd4",
                "assembly": _pointer_table_assembly(18),
            }
        }
    )
    evidence = evaluate_implant_rule("CUSTOM_COMMAND_DISPATCH_TABLE", metadata)
    assert len(evidence) == 1
    assert evidence[0]["pointer_count"] == 18


def test_small_pointer_table_is_not_a_dispatch_table():
    """A handful of pointers is an ordinary struct or vtable initialisation."""
    metadata = sleepwalker_metadata(
        disassembled_functions={
            "0x1000::sub_1000": {
                "name": "sub_1000",
                "address": "0x1000",
                "assembly": _pointer_table_assembly(4),
            }
        }
    )
    assert evaluate_implant_rule("CUSTOM_COMMAND_DISPATCH_TABLE", metadata) == []


def test_dispatch_table_alone_is_not_reported():
    """A pointer table in an otherwise unremarkable image says nothing.

    ripgrep, coreclr, msdia140, sos.dll and the SQL Server native client all
    build tables of this shape, with counts up to 26 - above the 18 of the
    implant the heuristic was written for. Without corroboration it is C++.
    """
    metadata = {
        "exe_type": "PE64",
        "is_shared_library": True,
        "is_signed": True,
        "authenticode": {"verification_flags": "OK"},
        "imports": [
            {"name": "KERNEL32.dll::VirtualProtect"},
            {"name": "KERNEL32.dll::CreateThread"},
        ],
        "exports": [
            {"name": "Run", "ordinal": 1, "address": "0x1000", "is_forwarded": False},
        ],
        "disassembled_functions": {
            "0x1000::sub_1000": {
                "name": "sub_1000",
                "address": "0x1000",
                "assembly": _pointer_table_assembly(26),
            }
        },
    }
    assert evaluate_implant_rule("CUSTOM_COMMAND_DISPATCH_TABLE", metadata) == []


def test_dispatch_table_reports_what_corroborated_it():
    metadata = sleepwalker_metadata(
        disassembled_functions={
            "0x3cd4::sub_3cd4": {
                "name": "sub_3cd4",
                "address": "0x180003cd4",
                "assembly": _pointer_table_assembly(18),
            }
        }
    )
    evidence = evaluate_implant_rule("CUSTOM_COMMAND_DISPATCH_TABLE", metadata)
    assert evidence
    corroborating = evidence[0]["corroborated_by"]
    assert "PE_IMPERSONATES_SYSTEM_MODULE" in corroborating
    assert "EMBEDDED_ENCRYPTED_PAYLOAD" in corroborating


def test_dispatch_table_requires_an_execution_primitive():
    metadata = sleepwalker_metadata(
        imports=[{"name": "KERNEL32.dll::CreateFileW"}],
        disassembled_functions={
            "0x1000::sub_1000": {
                "name": "sub_1000",
                "address": "0x1000",
                "assembly": _pointer_table_assembly(18),
            }
        },
    )
    assert evaluate_implant_rule("CUSTOM_COMMAND_DISPATCH_TABLE", metadata) == []


def test_addresses_passed_to_calls_are_not_counted_as_a_table():
    """Taking an address and passing it to a call is not storing it in a table."""
    assembly = "\n".join(
        f"lea rax, [rip + {1000 + index * 16}]\ncall qword ptr [rip + 500]" for index in range(20)
    )
    metadata = sleepwalker_metadata(
        disassembled_functions={
            "0x1000::sub_1000": {"name": "sub_1000", "address": "0x1000", "assembly": assembly}
        }
    )
    assert evaluate_implant_rule("CUSTOM_COMMAND_DISPATCH_TABLE", metadata) == []


# --------------------------------------------------------------------------
# Whole-binary integration
# --------------------------------------------------------------------------


def test_all_implant_rules_fire_together_on_the_sample_shape():
    """The finding is the combination: each rule alone is far weaker."""
    rule_ids = [
        "PE_IMPERSONATES_SYSTEM_MODULE",
        "PE_STUB_EXPORT_THUNK_TABLE",
        "PE_UNRESOLVED_SIBLING_MODULE_LOAD",
        "PE_HOST_PROCESS_NAME_GATE",
        "PASSIVE_MULTI_TRANSPORT_LISTENER",
        "COVERT_CHANNEL_DEVICE_ACCESS",
        "RUNTIME_CONSTRUCTED_SECURITY_STRINGS",
        "HOST_AUTHENTICATION_DOWNGRADE",
        "EMBEDDED_ENCRYPTED_PAYLOAD",
        "CUSTOM_COMMAND_DISPATCH_TABLE",
    ]
    metadata = sleepwalker_metadata(
        disassembled_functions={
            "0x3cd4::sub_3cd4": {
                "name": "sub_3cd4",
                "address": "0x180003cd4",
                "assembly": _pointer_table_assembly(18),
            }
        }
    )
    review_binary_list = [{rule_id: {"check_type": "binary_analysis"} for rule_id in rule_ids}]
    results = review_binary_metadata(review_binary_list, metadata, 5)
    assert set(results) == set(rule_ids)


def test_no_implant_rules_fire_on_a_benign_signed_library():
    rule_ids = list(
        {
            "PE_IMPERSONATES_SYSTEM_MODULE",
            "PE_STUB_EXPORT_THUNK_TABLE",
            "PE_UNRESOLVED_SIBLING_MODULE_LOAD",
            "PE_HOST_PROCESS_NAME_GATE",
            "PASSIVE_MULTI_TRANSPORT_LISTENER",
            "COVERT_CHANNEL_DEVICE_ACCESS",
            "RUNTIME_CONSTRUCTED_SECURITY_STRINGS",
            "HOST_AUTHENTICATION_DOWNGRADE",
            "EMBEDDED_ENCRYPTED_PAYLOAD",
            "CUSTOM_COMMAND_DISPATCH_TABLE",
        }
    )
    review_binary_list = [{rule_id: {"check_type": "binary_analysis"} for rule_id in rule_ids}]
    assert review_binary_metadata(review_binary_list, benign_signed_library(), 5) == {}


def test_evidence_is_capped_at_the_evidence_limit():
    metadata = sleepwalker_metadata(
        stack_strings=[
            {"value": f"\\\\.\\Device{index}", "function": "sub_1"} for index in range(20)
        ]
        + [{"value": "\\\\.\\VMCI", "function": "sub_2"}],
    )
    review_binary_list = [
        {"RUNTIME_CONSTRUCTED_SECURITY_STRINGS": {"check_type": "binary_analysis"}}
    ]
    results = review_binary_metadata(review_binary_list, metadata, 5)
    assert len(results["RUNTIME_CONSTRUCTED_SECURITY_STRINGS"]) == 5


def test_unknown_rule_id_returns_no_evidence():
    assert evaluate_implant_rule("NOT_A_RULE", sleepwalker_metadata()) == []


def test_empty_metadata_is_handled():
    for rule_id in (
        "PE_IMPERSONATES_SYSTEM_MODULE",
        "PE_STUB_EXPORT_THUNK_TABLE",
        "PE_UNRESOLVED_SIBLING_MODULE_LOAD",
        "PE_HOST_PROCESS_NAME_GATE",
        "PASSIVE_MULTI_TRANSPORT_LISTENER",
        "COVERT_CHANNEL_DEVICE_ACCESS",
        "RUNTIME_CONSTRUCTED_SECURITY_STRINGS",
        "HOST_AUTHENTICATION_DOWNGRADE",
        "EMBEDDED_ENCRYPTED_PAYLOAD",
        "CUSTOM_COMMAND_DISPATCH_TABLE",
    ):
        assert evaluate_implant_rule(rule_id, {}) == []
