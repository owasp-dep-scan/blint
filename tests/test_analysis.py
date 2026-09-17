from pathlib import Path

import orjson

from blint.lib.analysis import (
    EVIDENCE_LIMIT,
    _build_mermaid_callgraph_text,
    _filter_callgraph_by_min_confidence,
    _safe_mermaid_label,
    load_default_rules,
    run_checks,
    run_wasm_findings,
)
from blint.lib.binary import parse
from blint.lib.runners import ReviewRunner

load_default_rules()


def test_gobinary():
    test_go_file = Path(__file__).parent / "data" / "ngrok-elf.json"
    with open(test_go_file) as fp:
        file_content = fp.read()
    metadata = orjson.loads(file_content)
    results = run_checks(test_go_file.name, metadata)
    assert results
    assert results[0]["id"] == "CHECK_PIE"
    reviewer = ReviewRunner()
    reviewer.run_review(metadata)
    results = reviewer.process_review(test_go_file, test_go_file.name)
    assert results


def test_genericbinary():
    test_gnu_file = Path(__file__).parent / "data" / "netstat-elf.json"
    with open(test_gnu_file) as fp:
        file_content = fp.read()
    metadata = orjson.loads(file_content)
    results = run_checks(test_gnu_file.name, metadata)
    assert not results
    reviewer = ReviewRunner()
    reviewer.run_review(metadata)
    results = reviewer.process_review("data/netstat-elf.json", test_gnu_file.name)
    assert not results


def test_process_review_returns_empty_list_when_no_results():
    reviewer = ReviewRunner()

    results = reviewer.process_review("no-results.bin", "no-results.bin")

    assert results == []


def test_pe_rpc_impersonation_reviews_trigger_on_imports_and_privilege_chains():
    metadata = {
        "exe_type": "PE64",
        "imports": [
            {"name": "Rpcrt4.dll::RpcImpersonateClient"},
            {"name": "Rpcrt4.dll::RpcRevertToSelf"},
            {"name": "Rpcrt4.dll::RpcServerRegisterIf"},
            {"name": "Rpcrt4.dll::RpcServerUseProtseqEp"},
            {"name": "Rpcrt4.dll::RpcServerListen"},
            {"name": "Rpcrt4.dll::RpcEpRegister"},
        ],
        "symtab_symbols": [
            {"name": "TermSrvApi"},
            {"name": "termsrv.dll"},
            {"name": "bde95fdf-eee0-45de-9e12-e5a61cd0d4fe"},
            {"name": "497d95a6-2d27-4bf5-9bbd-a6046957133c"},
            {"name": "RpcOpenListener"},
            {"name": "W32TIME_ALT"},
            {"name": "w32time.dll"},
            {"name": "8fb6d884-2388-11d0-8c35-00c04fda2795"},
            {"name": "\\PIPE\\W32TIME"},
            {"name": "DhcpClient"},
            {"name": "dhcpcore.dll"},
            {"name": "3c4728c5-f0ab-448b-bda1-6ce01eb0a6d5"},
            {"name": "dhcpcsvc"},
            {"name": "gpsvc.dll"},
            {"name": "2eb08e3e-639f-4fba-97b1-14f878961076"},
            {"name": "Server_ProcessRefresh"},
        ],
        "disassembled_functions": {
            "0x140001000::serve_rpc": {
                "name": "serve_rpc",
                "address": "0x140001000",
                "assembly": "call RpcServerRegisterIf",
                "direct_calls": [
                    "RpcServerRegisterIf",
                    "RpcServerUseProtseqEp",
                    "RpcServerListen",
                    "RpcImpersonateClient",
                ],
            },
            "0x140001100::steal_rpc_token": {
                "name": "steal_rpc_token",
                "address": "0x140001100",
                "assembly": "call RpcImpersonateClient",
                "direct_calls": [
                    "RpcImpersonateClient",
                    "OpenThreadToken",
                    "DuplicateTokenEx",
                ],
            },
            "0x140001200::launch_with_rpc_token": {
                "name": "launch_with_rpc_token",
                "address": "0x140001200",
                "assembly": "call RpcImpersonateClient",
                "direct_calls": [
                    "RpcImpersonateClient",
                    "DuplicateTokenEx",
                    "CreateProcessWithTokenW",
                ],
            },
            "0x140001300::launch_asuser_from_rpc_token": {
                "name": "launch_asuser_from_rpc_token",
                "address": "0x140001300",
                "assembly": "call RpcImpersonateClient",
                "direct_calls": [
                    "RpcImpersonateClient",
                    "DuplicateTokenEx",
                    "CreateProcessAsUserW",
                ],
            },
        },
    }

    reviewer = ReviewRunner()
    reviewer.run_review(metadata)
    results = reviewer.process_review("synthetic-pe.exe", "synthetic-pe.exe")

    rule_ids = {result["id"] for result in results}
    assert "RPC_IMPERSONATION_API" in rule_ids
    assert "RPC_SERVER_BOOTSTRAP_IMPORTS" in rule_ids
    assert "RPC_ENDPOINT_REGISTRATION_IMPORTS" in rule_ids
    assert "RPC_SERVER_IMPERSONATION_CHAIN" in rule_ids
    assert "RPC_TOKEN_IMPERSONATION_CHAIN" in rule_ids
    assert "RPC_IMPERSONATION_PROCESS_CHAIN" in rule_ids
    assert "RPC_IMPERSONATION_ASUSER_PROCESS_CHAIN" in rule_ids
    assert "RPC_TERMSERVICE_ARTIFACTS" in rule_ids
    assert "RPC_W32TIME_ARTIFACTS" in rule_ids
    assert "RPC_DHCP_SERVICE_ARTIFACTS" in rule_ids
    assert "RPC_GPSVC_ARTIFACTS" in rule_ids

    function_review = next(
        result for result in results if result["id"] == "RPC_SERVER_IMPERSONATION_CHAIN"
    )
    assert function_review["evidence"][0]["function"] == "serve_rpc"

    token_review = next(
        result for result in results if result["id"] == "RPC_TOKEN_IMPERSONATION_CHAIN"
    )
    assert token_review["evidence"][0]["function"] == "steal_rpc_token"

    process_review = next(
        result for result in results if result["id"] == "RPC_IMPERSONATION_PROCESS_CHAIN"
    )
    assert process_review["evidence"][0]["function"] == "launch_with_rpc_token"

    asuser_review = next(
        result for result in results if result["id"] == "RPC_IMPERSONATION_ASUSER_PROCESS_CHAIN"
    )
    assert asuser_review["evidence"][0]["function"] == "launch_asuser_from_rpc_token"


def test_multi_pattern_rpc_artifact_reviews_do_not_fire_on_single_token_match():
    metadata = {
        "exe_type": "PE64",
        "imports": [{"name": "Rpcrt4.dll::RpcImpersonateClient"}],
        "symtab_symbols": [{"name": "TermSrvApi"}],
        "functions": [{"name": "TermSrvApiHelper"}],
    }

    reviewer = ReviewRunner()
    reviewer.run_review(metadata)
    results = reviewer.process_review("single-artifact.exe", "single-artifact.exe")

    rule_ids = {result["id"] for result in results}
    assert "RPC_SERVER_BOOTSTRAP_IMPORTS" not in rule_ids
    assert "RPC_ENDPOINT_REGISTRATION_IMPORTS" not in rule_ids
    assert "RPC_TERMSERVICE_ARTIFACTS" not in rule_ids
    assert "RPC_GPSVC_ARTIFACTS" not in rule_ids


def test_miniplasma_cloudfilter_reviews_trigger_on_clustered_indicators():
    metadata = {
        "exe_type": "PE64",
        "imports": [
            {"name": "cldapi.dll::CfAbortOperation"},
            {"name": "kernel32.dll::GetNamedPipeServerSessionId"},
            {"name": "advapi32.dll::CreateProcessAsUserW"},
        ],
        "functions": [],
        "symtab_symbols": [],
        "informative_strings": [
            {"value": "CfAbortOperation"},
            {"value": "CfGetPlatformInfo"},
            {"value": "cldapi.dll"},
            {"value": "CloudFiles"},
            {"value": "BlockedApps"},
            {"value": "SetImpersonationToken"},
            {"value": "CreateSymbolicLink"},
            {"value": "SetSecurityDescriptor"},
            {"value": r"Registry\User\.DEFAULT"},
            {"value": "Volatile Environment"},
            {"value": "WriteDac"},
            {"value": "windir"},
            {"value": "System32"},
            {"value": "wermgr.exe"},
            {"value": "QueueReporting"},
            {"value": "MiniPlasmaWERPipe"},
            {"value": "GetNamedPipeServerSessionId"},
            {"value": "CreateProcessAsUser"},
        ],
        "disassembled_functions": {
            "0x140010000::trigger_cloudfilter_race": {
                "name": "trigger_cloudfilter_race",
                "address": "0x140010000",
                "assembly": "call NtThread.SetImpersonationToken\ncall CfAbortOperation\njmp trigger_cloudfilter_race",
                "direct_calls": ["NtThread.SetImpersonationToken", "CfAbortOperation"],
                "has_loop": True,
                "instruction_metrics": {"jump_count": 1},
                "instruction_count": 3,
            },
            "0x140010100::redirect_cloudfiles_policy": {
                "name": "redirect_cloudfiles_policy",
                "address": "0x140010100",
                "assembly": "CloudFiles BlockedApps Volatile Environment",
                "direct_calls": [
                    "NtKey.CreateSymbolicLink",
                    "SetSecurityDescriptor",
                    "NtOpenKey",
                ],
                "instruction_metrics": {},
                "instruction_count": 3,
            },
            "0x140010200::launch_from_wer_session": {
                "name": "launch_from_wer_session",
                "address": "0x140010200",
                "assembly": "MiniPlasmaWERPipe QueueReporting wermgr.exe",
                "direct_calls": [
                    "GetNamedPipeServerSessionId",
                    "CreateProcessAsUserW",
                ],
                "instruction_metrics": {},
                "instruction_count": 2,
            },
        },
    }

    reviewer = ReviewRunner()
    reviewer.run_review(metadata)
    results = reviewer.process_review("synthetic-miniplasma.exe", "synthetic-miniplasma.exe")

    rule_ids = {result["id"] for result in results}
    assert "CLOUDFILTER_ABORT_API" in rule_ids
    assert "WER_SESSION_PROCESS_LAUNCH_IMPORTS" in rule_ids
    assert "CLOUDFILTER_ABORT_HYDRATION_LPE_CLUSTER" in rule_ids
    assert "CLOUDFILTER_REGISTRY_POLICY_LINK_CLUSTER" in rule_ids
    assert "WER_QUEUE_REPORTING_ENV_HIJACK_CLUSTER" in rule_ids
    assert "CLOUDFILTER_ABORT_TOKEN_IMPERSONATION_CHAIN" in rule_ids
    assert "CLOUDFILTER_ABORT_LOOP" in rule_ids
    assert "CLOUDFILTER_REGISTRY_POLICY_LINK_CHAIN" in rule_ids
    assert "WER_ENVIRONMENT_PROCESS_CHAIN" in rule_ids

    abort_chain = next(
        result
        for result in results
        if result["id"] == "CLOUDFILTER_ABORT_TOKEN_IMPERSONATION_CHAIN"
    )
    assert abort_chain["evidence"][0]["function"] == "trigger_cloudfilter_race"


def test_miniplasma_reviews_require_clustered_or_behavioral_context():
    metadata = {
        "exe_type": "PE64",
        "imports": [{"name": "cldapi.dll::CfAbortOperation"}],
        "functions": [],
        "symtab_symbols": [],
        "informative_strings": [
            {"value": "CfAbortOperation"},
            {"value": "CloudFiles"},
        ],
        "disassembled_functions": {
            "0x140020000::ordinary_abort": {
                "name": "ordinary_abort",
                "address": "0x140020000",
                "assembly": "call CfAbortOperation\nret",
                "direct_calls": ["CfAbortOperation"],
                "has_loop": False,
                "instruction_metrics": {"jump_count": 0},
                "instruction_count": 2,
            }
        },
    }

    reviewer = ReviewRunner()
    reviewer.run_review(metadata)
    results = reviewer.process_review("ordinary-cloudfilter.exe", "ordinary-cloudfilter.exe")
    rule_ids = {result["id"] for result in results}

    assert "CLOUDFILTER_ABORT_API" in rule_ids
    assert "CLOUDFILTER_ABORT_HYDRATION_LPE_CLUSTER" not in rule_ids
    assert "CLOUDFILTER_REGISTRY_POLICY_LINK_CLUSTER" not in rule_ids
    assert "WER_QUEUE_REPORTING_ENV_HIJACK_CLUSTER" not in rule_ids
    assert "CLOUDFILTER_ABORT_TOKEN_IMPERSONATION_CHAIN" not in rule_ids
    assert "CLOUDFILTER_ABORT_LOOP" not in rule_ids


def test_review_runner_emits_pii_read_special_case_results():
    metadata = {
        "exe_type": "genericbinary",
        "pii_symbols": [
            {"name": "password"},
            {"name": "email"},
        ],
    }

    reviewer = ReviewRunner()
    reviewer.run_review(metadata)
    results = reviewer.process_review("pii.bin", "pii.bin")

    pii_review = next(result for result in results if result["id"] == "PII_READ")
    assert pii_review["evidence"] == [
        {"pattern": "password", "function": "password"},
        {"pattern": "email", "function": "email"},
    ]
    assert "patterns" not in pii_review


def test_review_runner_emits_loader_symbols_special_case_results_without_other_reviews():
    metadata = {
        "exe_type": "unknown-loader-type",
        "first_stage_symbols": [
            {"name": "download_and_exec"},
            {"name": "reflective_loader"},
        ],
    }

    reviewer = ReviewRunner()
    reviewer.run_review(metadata)
    results = reviewer.process_review("loader.bin", "loader.bin")

    loader_review = next(result for result in results if result["id"] == "LOADER_SYMBOLS")
    assert loader_review["evidence"] == [
        {"pattern": "download_and_exec", "function": "download_and_exec"},
        {"pattern": "reflective_loader", "function": "reflective_loader"},
    ]


def test_ntqsi_cve_2026_40369_review_clusters_trigger_on_informative_strings():
    metadata = {
        "exe_type": "PE64",
        "functions": [],
        "symtab_symbols": [],
        "informative_strings": [
            {"value": "NtQuerySystemInformation"},
            {"value": "NtQuerySystemInformationEx"},
            {"value": "[target+0] += num_processes  (DWORD increment)"},
            {"value": "[target+4] += total_threads  (DWORD add)"},
            {"value": "[target+8] += total_handles  (DWORD add)"},
            {"value": "PsInitialSystemProcess"},
            {"value": "System EPROCESS"},
            {"value": "OpenProcessToken"},
            {"value": "SeDebug"},
            {"value": "VirtualAllocEx"},
            {"value": "WriteProcessMemory"},
            {"value": "CreateRemoteThread"},
        ],
    }

    reviewer = ReviewRunner()
    reviewer.run_review(metadata)
    results = reviewer.process_review("synthetic-ntqsi.exe", "synthetic-ntqsi.exe")

    rule_ids = {result["id"] for result in results}
    assert "NTQSI_CLASS253_INCREMENT_CLUSTER" in rule_ids
    assert "NTQSI_KERNEL_TOKEN_THEFT_CLUSTER" in rule_ids


def test_ntqsi_cve_2026_40369_review_clusters_require_multiple_indicators():
    metadata = {
        "exe_type": "PE64",
        "functions": [],
        "symtab_symbols": [],
        "informative_strings": [
            {"value": "NtQuerySystemInformation"},
            {"value": "VirtualAllocEx"},
        ],
    }

    reviewer = ReviewRunner()
    reviewer.run_review(metadata)
    results = reviewer.process_review("single-ntqsi.exe", "single-ntqsi.exe")

    rule_ids = {result["id"] for result in results}
    assert "NTQSI_CLASS253_INCREMENT_CLUSTER" not in rule_ids
    assert "NTQSI_KERNEL_TOKEN_THEFT_CLUSTER" not in rule_ids


def test_ntqsi_disassembly_reviews_trigger_on_class253_and_buildinfo_patterns():
    metadata = {
        "exe_type": "PE64",
        "disassembled_functions": {
            "0x140001000::trigger_class253": {
                "name": "trigger_class253",
                "address": "0x140001000",
                "assembly": "mov ecx, 0xfd\nmov rdx, rbx\nxor r8d, r8d\nlea r9, [rsp+0x20]\ncall NtQuerySystemInformation",
                "direct_calls": ["NtQuerySystemInformation"],
                "instruction_metrics": {},
                "instruction_count": 5,
            },
            "0x140001100::query_build_info": {
                "name": "query_build_info",
                "address": "0x140001100",
                "assembly": "mov ecx, 0xde\nlea rdx, [rsp+0x20]\nmov r8d, 4\nlea r9, [rsp+0x40]\ncall NtQuerySystemInformationEx",
                "direct_calls": ["NtQuerySystemInformationEx"],
                "instruction_metrics": {},
                "instruction_count": 5,
            },
        },
    }

    reviewer = ReviewRunner()
    reviewer.run_review(metadata)
    results = reviewer.process_review("synthetic-ntqsi-disasm.exe", "synthetic-ntqsi-disasm.exe")

    rule_ids = {result["id"] for result in results}
    assert "NTQSI_CLASS253_ZERO_LENGTH_CALL" in rule_ids
    assert "NTQSIEX_SYSTEM_BUILD_VERSION_QUERY" in rule_ids

    class253_review = next(
        result for result in results if result["id"] == "NTQSI_CLASS253_ZERO_LENGTH_CALL"
    )
    assert class253_review["evidence"][0]["function"] == "trigger_class253"

    buildinfo_review = next(
        result for result in results if result["id"] == "NTQSIEX_SYSTEM_BUILD_VERSION_QUERY"
    )
    assert buildinfo_review["evidence"][0]["function"] == "query_build_info"


def test_ntqsi_disassembly_reviews_do_not_fire_on_generic_system_info_calls():
    metadata = {
        "exe_type": "PE64",
        "disassembled_functions": {
            "0x140002000::ordinary_query": {
                "name": "ordinary_query",
                "address": "0x140002000",
                "assembly": "mov ecx, 5\nmov r8d, 0x100\ncall NtQuerySystemInformation",
                "direct_calls": ["NtQuerySystemInformation"],
                "instruction_metrics": {},
                "instruction_count": 3,
            },
            "0x140002100::other_ex_query": {
                "name": "other_ex_query",
                "address": "0x140002100",
                "assembly": "mov ecx, 7\nmov r8d, 4\ncall NtQuerySystemInformationEx",
                "direct_calls": ["NtQuerySystemInformationEx"],
                "instruction_metrics": {},
                "instruction_count": 3,
            },
        },
    }

    reviewer = ReviewRunner()
    reviewer.run_review(metadata)
    results = reviewer.process_review("generic-ntqsi-disasm.exe", "generic-ntqsi-disasm.exe")

    rule_ids = {result["id"] for result in results}
    assert "NTQSI_CLASS253_ZERO_LENGTH_CALL" not in rule_ids
    assert "NTQSIEX_SYSTEM_BUILD_VERSION_QUERY" not in rule_ids


def test_apple_mie_annotation_pack_triggers_on_clustered_macho_indicators():
    metadata = {
        "exe_type": "MachO",
        "functions": [],
        "dynamic_symbols": [
            {"name": "_fork"},
            {"name": "_posix_spawn"},
            {"name": "_setuid"},
            {"name": "_csops"},
            {"name": "_csops_audittoken"},
            {"name": "_pthread_setname_np"},
            {"name": "_thread_get_state"},
        ],
        "symtab_symbols": [],
        "informative_strings": [
            {"value": "_zalloc_ro_mut"},
            {"value": "ro_zone"},
            {"value": "ucred"},
            {"value": "cr_uid"},
            {"value": "TPIDR_EL1"},
        ],
    }

    reviewer = ReviewRunner()
    reviewer.run_review(metadata)
    results = reviewer.process_review("synthetic-mie-tool", "synthetic-mie-tool")

    rule_ids = {result["id"] for result in results}
    assert "APPLE_DARWIN_PRIVESC_STAGING_API_CLUSTER" in rule_ids
    assert "APPLE_DARWIN_ROZONE_REACHABILITY_API_CLUSTER" in rule_ids
    assert "APPLE_DARWIN_THREAD_LEAK_SURFACE_CLUSTER" in rule_ids
    assert "APPLE_MIE_COPYCAT_STRING_CLUSTER" in rule_ids


def test_apple_mie_annotation_pack_requires_clustered_macho_indicators():
    metadata = {
        "exe_type": "MachO",
        "functions": [],
        "dynamic_symbols": [
            {"name": "_setuid"},
            {"name": "_csops"},
            {"name": "_pthread_setname_np"},
        ],
        "symtab_symbols": [],
        "informative_strings": [
            {"value": "_zalloc_ro_mut"},
        ],
    }

    reviewer = ReviewRunner()
    reviewer.run_review(metadata)
    results = reviewer.process_review("ordinary-macho", "ordinary-macho")

    rule_ids = {result["id"] for result in results}
    assert "APPLE_DARWIN_PRIVESC_STAGING_API_CLUSTER" not in rule_ids
    assert "APPLE_DARWIN_ROZONE_REACHABILITY_API_CLUSTER" not in rule_ids
    assert "APPLE_DARWIN_THREAD_LEAK_SURFACE_CLUSTER" not in rule_ids
    assert "APPLE_MIE_COPYCAT_STRING_CLUSTER" not in rule_ids


def test_apple_mie_zalloc_ro_mut_prepatch_disassembly_review():
    metadata = {
        "exe_type": "MachO",
        "disassembled_functions": {
            "0xfffffe000b4e3560::_zalloc_ro_mut": {
                "name": "_zalloc_ro_mut",
                "address": "0xfffffe000b4e3560",
                "assembly": "cmp x8, x29\nb.lo skip_stack_check\nand x9, x8, #0xffffffffffffc000\nadds x9, x8, x4\nb.hs range_check\ncmp x8, x10",
                "instruction_metrics": {},
                "instruction_count": 6,
            },
            "0xfffffe000b4e84d0::_zalloc_ro_mut_patched_copy": {
                "name": "_zalloc_ro_mut",
                "address": "0xfffffe000b4e84d0",
                "assembly": "mrs x10, TPIDR_EL1\nadds x9, x8, x4\nb.hs per_cpu_check\nldr x11, [x10, #0x158]\nldr x10, [x10, #0xe8]\ncmp x8, x11\nccmp x9, x11, #0x0, hs\nccmp x9, x10, #0x2, hs\nb.ls panic",
                "instruction_metrics": {},
                "instruction_count": 9,
            },
            "0xfffffe000b4e9000::_zalloc_ro_mut_atomic": {
                "name": "_zalloc_ro_mut_atomic",
                "address": "0xfffffe000b4e9000",
                "assembly": "adds x9, x8, x4\nb.hs range_check",
                "instruction_metrics": {},
                "instruction_count": 2,
            },
        },
    }

    reviewer = ReviewRunner()
    reviewer.run_review(metadata)
    results = reviewer.process_review("kernelcache-macho", "kernelcache-macho")

    zalloc_review = next(
        result for result in results if result["id"] == "APPLE_MIE_ZALLOC_RO_MUT_PREPATCH_BOUNDS"
    )
    assert zalloc_review["evidence"] == [
        {
            "function": "_zalloc_ro_mut",
            "address": "0xfffffe000b4e3560",
            "snippet": "cmp x8, x29",
        }
    ]


def test_ntqsi_indirect_dynamic_disassembly_reviews_trigger_on_getprocaddress_style_variants():
    metadata = {
        "exe_type": "PE64",
        "disassembled_functions": {
            "0x140003000::resolve_and_trigger_class253": {
                "name": "resolve_and_trigger_class253",
                "address": "0x140003000",
                "assembly": "call GetModuleHandleW\ncall GetProcAddress\nmov r11, rax\nmov ecx, 0xfd\nmov rdx, rbx\nxor r8d, r8d\nlea r9, [rsp+0x20]\ncall r11",
                "direct_calls": ["GetModuleHandleW", "GetProcAddress"],
                "direct_call_targets": [
                    {
                        "target_name": "",
                        "target_address": "",
                        "target_address_candidates": [],
                        "raw_operand": "r11",
                        "kind": "indirect_hint",
                    }
                ],
                "has_indirect_call": True,
                "instruction_metrics": {},
                "instruction_count": 8,
            },
            "0x140003100::hinted_build_version_indirect": {
                "name": "hinted_build_version_indirect",
                "address": "0x140003100",
                "assembly": "mov ecx, 0xde\nlea rdx, [rsp+0x20]\nmov r8d, 4\nlea r9, [rsp+0x40]\ncall qword ptr [rax]",
                "direct_calls": [],
                "direct_call_targets": [
                    {
                        "target_name": "NtQuerySystemInformationEx",
                        "target_address": "",
                        "target_address_candidates": [],
                        "raw_operand": "qword ptr [rax]",
                        "kind": "indirect_hint",
                    }
                ],
                "has_indirect_call": True,
                "instruction_metrics": {},
                "instruction_count": 5,
            },
        },
    }

    reviewer = ReviewRunner()
    reviewer.run_review(metadata)
    results = reviewer.process_review(
        "synthetic-ntqsi-indirect.exe", "synthetic-ntqsi-indirect.exe"
    )

    rule_ids = {result["id"] for result in results}
    assert "NTQSI_CLASS253_DYNAMIC_INDIRECT_CALL" in rule_ids
    assert "NTQSIEX_SYSTEM_BUILD_VERSION_DYNAMIC_INDIRECT_QUERY" in rule_ids


def test_ntqsi_indirect_dynamic_disassembly_reviews_require_selector_and_context():
    metadata = {
        "exe_type": "PE64",
        "disassembled_functions": {
            "0x140004000::generic_resolver_wrapper": {
                "name": "generic_resolver_wrapper",
                "address": "0x140004000",
                "assembly": "call GetModuleHandleW\ncall GetProcAddress\nmov r11, rax\nmov ecx, 5\nxor r8d, r8d\ncall r11",
                "direct_calls": ["GetModuleHandleW", "GetProcAddress"],
                "direct_call_targets": [
                    {
                        "target_name": "",
                        "target_address": "",
                        "target_address_candidates": [],
                        "raw_operand": "r11",
                        "kind": "indirect_hint",
                    }
                ],
                "has_indirect_call": True,
                "instruction_metrics": {},
                "instruction_count": 6,
            },
            "0x140004100::wrong_hint_no_zero_length": {
                "name": "wrong_hint_no_zero_length",
                "address": "0x140004100",
                "assembly": "mov ecx, 0xfd\nmov r8d, 4\ncall qword ptr [rax]",
                "direct_calls": [],
                "direct_call_targets": [
                    {
                        "target_name": "NtQuerySystemInformation",
                        "target_address": "",
                        "target_address_candidates": [],
                        "raw_operand": "qword ptr [rax]",
                        "kind": "indirect_hint",
                    }
                ],
                "has_indirect_call": True,
                "instruction_metrics": {},
                "instruction_count": 3,
            },
        },
    }

    reviewer = ReviewRunner()
    reviewer.run_review(metadata)
    results = reviewer.process_review(
        "synthetic-ntqsi-indirect-negative.exe",
        "synthetic-ntqsi-indirect-negative.exe",
    )

    rule_ids = {result["id"] for result in results}
    assert "NTQSI_CLASS253_DYNAMIC_INDIRECT_CALL" not in rule_ids
    assert "NTQSIEX_SYSTEM_BUILD_VERSION_DYNAMIC_INDIRECT_QUERY" not in rule_ids


def test_ntqsi_cross_function_resolver_chain_reviews_trigger_on_split_resolution_and_use():
    metadata = {
        "exe_type": "PE64",
        "disassembled_functions": {
            "0x140005000::resolve_ntqsi": {
                "name": "resolve_ntqsi",
                "address": "0x140005000",
                "assembly": "call GetModuleHandleW\ncall GetProcAddress\nret",
                "direct_calls": ["GetModuleHandleW", "GetProcAddress"],
                "direct_call_targets": [],
                "has_indirect_call": False,
                "instruction_metrics": {"ret_count": 1},
                "instruction_count": 3,
            },
            "0x140005100::use_resolved_ntqsi": {
                "name": "use_resolved_ntqsi",
                "address": "0x140005100",
                "assembly": "call resolve_ntqsi\nmov r11, rax\nmov ecx, 0xfd\nmov rdx, rbx\nxor r8d, r8d\nlea r9, [rsp+0x20]\ncall r11",
                "direct_calls": ["resolve_ntqsi"],
                "direct_call_targets": [
                    {
                        "target_name": "",
                        "target_address": "",
                        "target_address_candidates": [],
                        "raw_operand": "r11",
                        "kind": "indirect_hint",
                    }
                ],
                "has_indirect_call": True,
                "instruction_metrics": {},
                "instruction_count": 7,
            },
            "0x140005200::resolve_ntqsiex": {
                "name": "resolve_ntqsiex",
                "address": "0x140005200",
                "assembly": "call GetModuleHandleW\ncall GetProcAddress\nret",
                "direct_calls": ["GetModuleHandleW", "GetProcAddress"],
                "direct_call_targets": [],
                "has_indirect_call": False,
                "instruction_metrics": {"ret_count": 1},
                "instruction_count": 3,
            },
            "0x140005300::use_resolved_ntqsiex": {
                "name": "use_resolved_ntqsiex",
                "address": "0x140005300",
                "assembly": "call resolve_ntqsiex\nmov r10, rax\nmov ecx, 0xde\nlea rdx, [rsp+0x20]\nmov r8d, 4\nlea r9, [rsp+0x40]\ncall r10",
                "direct_calls": ["resolve_ntqsiex"],
                "direct_call_targets": [
                    {
                        "target_name": "",
                        "target_address": "",
                        "target_address_candidates": [],
                        "raw_operand": "r10",
                        "kind": "indirect_hint",
                    }
                ],
                "has_indirect_call": True,
                "instruction_metrics": {},
                "instruction_count": 7,
            },
        },
    }

    reviewer = ReviewRunner()
    reviewer.run_review(metadata)
    results = reviewer.process_review("synthetic-ntqsi-cross.exe", "synthetic-ntqsi-cross.exe")

    rule_ids = {result["id"] for result in results}
    assert "NTQSI_CLASS253_CROSS_FUNCTION_RESOLVER_CHAIN" in rule_ids
    assert "NTQSIEX_SYSTEM_BUILD_VERSION_CROSS_FUNCTION_RESOLVER_CHAIN" in rule_ids

    class253_review = next(
        result
        for result in results
        if result["id"] == "NTQSI_CLASS253_CROSS_FUNCTION_RESOLVER_CHAIN"
    )
    assert class253_review["evidence"][0]["function"] == "use_resolved_ntqsi"
    assert class253_review["evidence"][0]["related_function"] == "resolve_ntqsi"

    buildinfo_review = next(
        result
        for result in results
        if result["id"] == "NTQSIEX_SYSTEM_BUILD_VERSION_CROSS_FUNCTION_RESOLVER_CHAIN"
    )
    assert buildinfo_review["evidence"][0]["function"] == "use_resolved_ntqsiex"
    assert buildinfo_review["evidence"][0]["related_function"] == "resolve_ntqsiex"


def test_ntqsi_cross_function_resolver_chain_reviews_require_helper_call_relationship():
    metadata = {
        "exe_type": "PE64",
        "disassembled_functions": {
            "0x140006000::resolve_ntqsi": {
                "name": "resolve_ntqsi",
                "address": "0x140006000",
                "assembly": "call GetModuleHandleW\ncall GetProcAddress\nret",
                "direct_calls": ["GetModuleHandleW", "GetProcAddress"],
                "direct_call_targets": [],
                "has_indirect_call": False,
                "instruction_metrics": {"ret_count": 1},
                "instruction_count": 3,
            },
            "0x140006100::indirect_without_helper_link": {
                "name": "indirect_without_helper_link",
                "address": "0x140006100",
                "assembly": "mov r11, rax\nmov ecx, 0xfd\nmov rdx, rbx\nxor r8d, r8d\ncall r11",
                "direct_calls": [],
                "direct_call_targets": [
                    {
                        "target_name": "",
                        "target_address": "",
                        "target_address_candidates": [],
                        "raw_operand": "r11",
                        "kind": "indirect_hint",
                    }
                ],
                "has_indirect_call": True,
                "instruction_metrics": {},
                "instruction_count": 5,
            },
            "0x140006200::calls_helper_but_wrong_selector": {
                "name": "calls_helper_but_wrong_selector",
                "address": "0x140006200",
                "assembly": "call resolve_ntqsi\nmov r11, rax\nmov ecx, 5\nxor r8d, r8d\ncall r11",
                "direct_calls": ["resolve_ntqsi"],
                "direct_call_targets": [
                    {
                        "target_name": "",
                        "target_address": "",
                        "target_address_candidates": [],
                        "raw_operand": "r11",
                        "kind": "indirect_hint",
                    }
                ],
                "has_indirect_call": True,
                "instruction_metrics": {},
                "instruction_count": 5,
            },
        },
    }

    reviewer = ReviewRunner()
    reviewer.run_review(metadata)
    results = reviewer.process_review(
        "synthetic-ntqsi-cross-negative.exe",
        "synthetic-ntqsi-cross-negative.exe",
    )

    rule_ids = {result["id"] for result in results}
    assert "NTQSI_CLASS253_CROSS_FUNCTION_RESOLVER_CHAIN" not in rule_ids
    assert "NTQSIEX_SYSTEM_BUILD_VERSION_CROSS_FUNCTION_RESOLVER_CHAIN" not in rule_ids


def test_run_review_methods_symbols_caps_evidence_at_limit():
    patterns = [f"pattern{i}" for i in range(EVIDENCE_LIMIT + 2)]
    functions_list = [f"symbol_pattern{i}" for i in range(EVIDENCE_LIMIT + 2)]
    reviewer = ReviewRunner()

    reviewer.run_review_methods_symbols(
        [{"RULE_CAP": {"patterns": patterns, "min_patterns": 1}}], functions_list
    )

    assert len(reviewer.results["RULE_CAP"]) == EVIDENCE_LIMIT


def test_run_review_methods_symbols_parses_rule_options_defensively():
    functions_list = ["RpcServerListen"]

    reviewer = ReviewRunner()
    reviewer.run_review_methods_symbols(
        [
            {
                "RULE_FALSE_STRING": {
                    "patterns": ["RpcServerListen"],
                    "min_patterns": "not-a-number",
                    "allow_shared_matches": "false",
                }
            },
            {
                "RULE_SECOND": {
                    "patterns": ["RpcServerListen"],
                }
            },
        ],
        functions_list,
    )

    assert "RULE_FALSE_STRING" in reviewer.results
    assert "RULE_SECOND" not in reviewer.results

    reviewer = ReviewRunner()
    reviewer.run_review_methods_symbols(
        [
            {
                "RULE_TRUE_STRING": {
                    "patterns": ["RpcServerListen"],
                    "allow_shared_matches": "true",
                }
            },
            {
                "RULE_SHARED_SECOND": {
                    "patterns": ["RpcServerListen"],
                }
            },
        ],
        functions_list,
    )

    assert "RULE_TRUE_STRING" in reviewer.results
    assert "RULE_SHARED_SECOND" in reviewer.results

    reviewer = ReviewRunner()
    reviewer.run_review_methods_symbols(
        [
            {
                "RULE_TYPO_STRING": {
                    "patterns": ["RpcServerListen"],
                    "allow_shared_matches": "flase",
                }
            },
            {
                "RULE_TYPO_SECOND": {
                    "patterns": ["RpcServerListen"],
                }
            },
        ],
        functions_list,
    )

    assert "RULE_TYPO_STRING" in reviewer.results
    assert "RULE_TYPO_SECOND" not in reviewer.results


def test_run_review_methods_symbols_uses_informative_strings_per_rule_opt_in():
    functions_list = ["safe_function"]
    informative_values = ["bpf_sock_ops_active_established_cb"]

    reviewer = ReviewRunner()
    reviewer.run_review_methods_symbols(
        [
            {
                "RULE_NO_OPT_IN": {
                    "patterns": ["bpf_sock_ops_active_established_cb"],
                }
            },
            {
                "RULE_WITH_OPT_IN": {
                    "patterns": ["bpf_sock_ops_active_established_cb"],
                    "include_informative_strings": True,
                }
            },
        ],
        functions_list,
        informative_values=informative_values,
    )

    assert "RULE_NO_OPT_IN" not in reviewer.results
    assert "RULE_WITH_OPT_IN" in reviewer.results


def test_run_review_methods_symbols_matches_single_backslash_windows_paths():
    reviewer = ReviewRunner()

    reviewer.run_review_methods_symbols(
        [
            {
                "RULE_WINDOWS_PATH": {
                    "patterns": [r"Microsoft\Windows\Windows Error Reporting\QueueReporting"],
                    "include_informative_strings": True,
                }
            }
        ],
        [],
        informative_values=[r"Microsoft\Windows\Windows Error Reporting\QueueReporting"],
    )

    assert "RULE_WINDOWS_PATH" in reviewer.results


def test_safe_mermaid_label_sanitizes_parser_unsafe_chars():
    raw_label = ' unsafe extern "C" fn(*mut u8)\n\t\\windows\\path|core::fmt `tick` '
    normalized = _safe_mermaid_label(raw_label)
    assert normalized == "unsafe extern 'C' fn(*mut u8) /windows/path/core::fmt 'tick'"
    assert '"' not in normalized
    assert "\\" not in normalized
    assert "|" not in normalized


def test_build_mermaid_callgraph_text_with_unsafe_labels():
    callgraph = {
        "nodes": [
            {
                "id": 0,
                "name": 'unsafe extern "C" fn(*mut u8)',
                "address": "0x10",
            }
        ],
        "edges": [],
        "external": [
            {
                "src": 0,
                "target": 'std::ffi::CString::new|"quoted"',
                "reason": "unresolved",
                "count": 1,
            }
        ],
    }
    mermaid_text = _build_mermaid_callgraph_text(callgraph)
    assert "graph TD" in mermaid_text
    assert "unsafe extern 'C' fn(*mut u8) (0x10)" in mermaid_text
    assert "std::ffi::CString::new/'quoted'" in mermaid_text
    assert '\\"' not in mermaid_text


def test_filter_callgraph_by_min_confidence_filters_edges_and_externals():
    callgraph = {
        "nodes": [{"id": 0, "name": "a", "address": "0x10"}],
        "edges": [
            {"src": 0, "dst": 0, "count": 1, "kind": "direct", "confidence": "high"},
            {
                "src": 0,
                "dst": 0,
                "count": 1,
                "kind": "tailcall",
                "confidence": "medium",
            },
        ],
        "external": [
            {
                "src": 0,
                "target": "x",
                "reason": "unresolved",
                "count": 1,
                "confidence": "low",
            }
        ],
        "edge_count": 2,
    }

    filtered = _filter_callgraph_by_min_confidence(callgraph, "high")

    assert filtered["edge_count"] == 1
    assert len(filtered["edges"]) == 1
    assert filtered["edges"][0]["confidence"] == "high"
    assert filtered["external"] == []


def test_network_evasion_cluster_reviews_trigger_with_informative_strings():
    metadata = {
        "exe_type": "genericbinary",
        "functions": [],
        "symtab_symbols": [],
        "informative_strings": [
            {"value": "BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB"},
            {"value": "bpf_setsockopt"},
            {"value": "TCP_MAXSEG"},
            {"value": "/dev/net/tun"},
            {"value": "gvisor"},
            {"value": "wintun"},
            {"value": "IP_HDRINCL"},
            {"value": "SOCK_RAW"},
            {"value": "pcap_sendpacket"},
            {"value": "DNS-over-HTTPS"},
            {"value": "dns-query"},
            {"value": "127.0.0.1:53"},
        ],
    }

    reviewer = ReviewRunner()
    reviewer.run_review(metadata)
    results = reviewer.process_review("synthetic-net.bin", "synthetic-net.bin")
    rule_ids = {result["id"] for result in results}

    assert "EBPF_SOCK_OPS_CLUSTER" in rule_ids
    assert "TUN_INTERFACE_CLUSTER" in rule_ids
    assert "RAW_PACKET_SOCKET_CLUSTER" in rule_ids
    assert "DOH_BYPASS_CLUSTER" in rule_ids


def test_network_evasion_cluster_reviews_require_multiple_patterns():
    metadata = {
        "exe_type": "genericbinary",
        "functions": [],
        "symtab_symbols": [],
        "informative_strings": [{"value": "IP_HDRINCL"}],
    }

    reviewer = ReviewRunner()
    reviewer.run_review(metadata)
    results = reviewer.process_review("single-token.bin", "single-token.bin")
    rule_ids = {result["id"] for result in results}

    assert "RAW_PACKET_SOCKET_CLUSTER" not in rule_ids


def test_run_wasm_findings_pass_through():
    dos_file = Path(__file__).parent / "data" / "dos_growth_loop.wasm"
    metadata = parse(str(dos_file))

    results = run_wasm_findings(str(dos_file), metadata)

    assert results
    assert results[0]["id"] == "WASM-DOS-003"
    assert results[0]["severity"] == "high"
    assert results[0]["exe_type"] == "wasmbinary"
    assert results[0]["filename"] == str(dos_file)
    assert results[0]["exe_name"] == metadata["name"]
    assert results[0]["evidence"]


def test_run_wasm_findings_orders_by_severity_then_id():
    metadata = {
        "name": "synthetic.wasm",
        "exe_type": "wasmbinary",
        "wasm_analysis": {
            "findings": [
                {"id": "WASM-B-001", "title": "Medium finding", "severity": "medium"},
                {
                    "id": "WASM-A-002",
                    "title": "High finding",
                    "severity": "high",
                    "confidence": "high",
                    "evidence": {"ops": 3},
                    "remediation": "Do the safe thing.",
                },
            ]
        },
    }

    results = run_wasm_findings("synthetic.wasm", metadata)

    assert [item["id"] for item in results] == ["WASM-A-002", "WASM-B-001"]
    assert results[0]["description"] == "Do the safe thing."
    assert results[0]["evidence"] == {"ops": 3}
    assert results[0]["confidence"] == "high"


def test_run_wasm_findings_empty_inputs():
    clean_file = Path(__file__).parent / "data" / "complex_flow.wasm"
    clean_metadata = parse(str(clean_file))

    assert run_wasm_findings("clean.wasm", clean_metadata) == []
    assert run_wasm_findings("clean.wasm", {}) == []
    assert run_wasm_findings("clean.wasm", {"wasm_analysis": {}}) == []


def test_check_wx_segments_reports_offending_segment_names():
    metadata = {
        "exe_type": "genericbinary",
        "name": "wx.elf",
        "wx_segments": [
            {"name": "PT_LOAD[1]", "permissions": "rwx", "virtual_address": "0x401000"},
            {"name": "PT_LOAD[2]", "permissions": "rwx", "virtual_address": "0x402000"},
        ],
    }

    results = [
        result for result in run_checks("wx.elf", metadata) if result["id"] == "CHECK_WX_SEGMENTS"
    ]

    assert len(results) == 1
    assert results[0]["severity"] == "critical"
    assert "PT_LOAD[1]" in results[0]["title"]
    assert "PT_LOAD[2]" in results[0]["title"]


def test_check_wx_segments_reports_pe_sections_by_name():
    metadata = {
        "exe_type": "PE64",
        "name": "wx.exe",
        "wx_segments": [
            {"name": ".rwx", "permissions": "rwx", "virtual_address": "0x2000"},
        ],
    }

    results = [
        result for result in run_checks("wx.exe", metadata) if result["id"] == "CHECK_WX_SEGMENTS"
    ]

    assert len(results) == 1
    assert ".rwx" in results[0]["title"]


def test_check_wx_segments_ignores_malformed_or_unnamed_entries():
    metadata = {
        "exe_type": "MachO",
        "name": "wx.dylib",
        "wx_segments": ["__DATA", {"permissions": "rwx"}, {"name": ""}],
    }

    results = [
        result
        for result in run_checks("wx.dylib", metadata)
        if result["id"] == "CHECK_WX_SEGMENTS"
    ]

    assert results == []


def test_check_wx_segments_passes_without_offending_segments():
    clean_metadata = {
        "exe_type": "genericbinary",
        "name": "ok.elf",
        "wx_segments": [],
    }
    missing_key_metadata = {
        "exe_type": "PE32",
        "name": "ok.exe",
    }
    other_exe_type_metadata = {
        "exe_type": "wasmbinary",
        "name": "module.wasm",
        "wx_segments": [
            {"name": "PT_LOAD[1]", "permissions": "rwx", "virtual_address": "0x401000"},
        ],
    }

    assert not [r for r in run_checks("ok.elf", clean_metadata) if r["id"] == "CHECK_WX_SEGMENTS"]
    assert not [
        r for r in run_checks("ok.exe", missing_key_metadata) if r["id"] == "CHECK_WX_SEGMENTS"
    ]
    assert not [
        r
        for r in run_checks("module.wasm", other_exe_type_metadata)
        if r["id"] == "CHECK_WX_SEGMENTS"
    ]


def test_check_dll_characteristics_prefers_structured_flags():
    """V1: mandatory-value membership is exact against the decoded flag list.

    The substring path exists only for metadata exported before the
    structured block (parse cache); both must answer identically.
    """
    from blint.lib.checks import check_dll_characteristics

    rule = {
        "mandatory_values": [
            "HIGH_ENTROPY_VA",
            "NX_COMPAT",
            "GUARD_CF",
            "FORCE_INTEGRITY",
            "DYNAMIC_BASE",
        ]
    }
    structured_metadata = {
        "dll_characteristics_structured": {
            "value": 352,
            "flags": ["HIGH_ENTROPY_VA", "DYNAMIC_BASE", "NX_COMPAT"],
            "source": "optional_header",
        },
        "dll_characteristics": "HIGH_ENTROPY_VA, DYNAMIC_BASE, NX_COMPAT",
    }
    assert (
        check_dll_characteristics("t.exe", structured_metadata, rule_obj=rule)
        == "GUARD_CF, FORCE_INTEGRITY"
    )
    legacy_metadata = {
        "dll_characteristics": "HIGH_ENTROPY_VA, DYNAMIC_BASE, NX_COMPAT",
    }
    assert (
        check_dll_characteristics("t.exe", legacy_metadata, rule_obj=rule)
        == "GUARD_CF, FORCE_INTEGRITY"
    )
    complete_metadata = {
        "dll_characteristics_structured": {
            "value": 0x42F4,
            "flags": [
                "HIGH_ENTROPY_VA",
                "DYNAMIC_BASE",
                "FORCE_INTEGRITY",
                "NX_COMPAT",
                "GUARD_CF",
            ],
            "source": "optional_header",
        },
    }
    assert check_dll_characteristics("t.exe", complete_metadata, rule_obj=rule) is True


def test_check_dll_characteristics_reports_everything_on_a_zero_bitfield():
    """The least hardened PE of all must report every mandatory value.

    Its joined compat string is empty, so a truthiness test on that string
    skips the comparison entirely and the image passes — the false negative
    mirroring the false positive V1 describes.
    """
    from blint.lib.checks import check_dll_characteristics

    rule = {"mandatory_values": ["NX_COMPAT", "DYNAMIC_BASE", "GUARD_CF"]}
    metadata = {
        "dll_characteristics_structured": {
            "value": 0,
            "flags": [],
            "source": "optional_header",
        },
        "dll_characteristics": "",
    }
    assert (
        check_dll_characteristics("t.exe", metadata, rule_obj=rule)
        == "NX_COMPAT, DYNAMIC_BASE, GUARD_CF"
    )


def test_pac_rules_removed_with_their_false_recommendations():
    """W0.3: CHECK_PAC/CHECK_PAC_STRICT no longer exist.

    The findings they fired on every ARM64 PE were false recommendations:
    no PE source records PAC at all. The GuardFlags bit blint read as PAC
    (LIEF's RF_INSTRUMENTED) is Return Flow Guard per the Windows SDK's
    winnt.h, and MSVC 19.44 offers no /guard:signret option to even produce
    the advised artifact. A rule whose property can never truthfully be
    True fires guaranteed noise.
    """
    from blint.lib import analysis as analysis_module

    assert "CHECK_PAC" not in analysis_module.rules_dict
    assert "CHECK_PAC_STRICT" not in analysis_module.rules_dict
    arm64_metadata = {
        "exe_type": "PE64",
        "machine_type": "ARM64",
        "machine_type_value": 0xAA64,
        "security_properties": {},
    }
    ids = {r["id"] for r in run_checks("python-arm64.exe", arm64_metadata)}
    assert "CHECK_PAC" not in ids
    assert "CHECK_PAC_STRICT" not in ids


def test_optin_feature_rules_removed_from_the_registry():
    """W0.3: CHECK_XFG/CHECK_CET/CHECK_ENCLAVE no longer exist.

    Each fired "missing <feature>" on essentially every PE: the features are
    opt-in (66/66 stock Microsoft-signed tier-0 binaries lack an enclave
    configuration), and with an omitted property read as a failure they even
    fired on .cat and .zip files blint cannot parse as PE. The properties
    stay in security_properties, computed from their named sources.
    """
    from blint.lib import analysis as analysis_module

    for rule_id in ("CHECK_XFG", "CHECK_CET", "CHECK_ENCLAVE"):
        assert rule_id not in analysis_module.rules_dict


def test_check_security_property_omitted_key_is_not_a_failure():
    """The tristate discipline at the rule layer: a property absent from
    security_properties means its source was absent (P2.4), so there is
    nothing to claim. Reading omission as a failure is what made the
    property rules fire on unparseable files (V4)."""
    from blint.lib.checks import check_security_property

    rule = {"property_key": "cet_shadow_stack"}
    # Omitted property: no claim, rule silent.
    assert check_security_property("t.exe", {"security_properties": {}}, rule_obj=rule)
    assert check_security_property("t.exe", {}, rule_obj=rule)
    # Computed False: the finding fires — it is backed by a source.
    assert not check_security_property(
        "t.exe", {"security_properties": {"cet_shadow_stack": False}}, rule_obj=rule
    )
    # Computed True: clean.
    assert check_security_property(
        "t.exe", {"security_properties": {"cet_shadow_stack": True}}, rule_obj=rule
    )


def test_unknown_exe_type_never_fires_a_scoped_rule():
    """A rule's exe_types list is a scope declaration: a file whose exe_type
    could not be resolved is outside every declared scope. This is the
    .cat/.zip defect — those files carried no exe_type and still fired the
    PE-scoped property rules."""
    metadata = {
        "dll_characteristics_structured": {"value": 0, "flags": [], "source": "optional_header"},
        "dll_characteristics": "",
    }
    ids = {r["id"] for r in run_checks("python.cat", metadata)}
    assert "CHECK_DLL_CHARACTERISTICS" not in ids
    # The same file parsed as a PE does fire it — the gate is about scope,
    # not about softening the check.
    ids = {r["id"] for r in run_checks("python.exe", {**metadata, "exe_type": "PE64"})}
    assert "CHECK_DLL_CHARACTERISTICS" in ids


def test_rule_machine_type_gate_resolution_rules():
    from blint.lib.analysis import _rule_machine_type_allows

    arm64_rule = {"machine_types": ["ARM64", "ARM64EC", "ARM64X"]}
    # The numeric value resolves through blint's table, so a stale or renamed
    # rendered string cannot widen or shrink the gate.
    assert _rule_machine_type_allows(
        {"machine_type": "AARCH64", "machine_type_value": 0xAA64}, arm64_rule
    )
    assert not _rule_machine_type_allows(
        {"machine_type": "ARM64", "machine_type_value": 0x8664}, arm64_rule
    )
    # Rendered-string fallback for metadata without the numeric field.
    assert _rule_machine_type_allows({"machine_type": "arm64"}, arm64_rule)
    assert not _rule_machine_type_allows({"machine_type": "AMD64"}, arm64_rule)
    # An unresolvable machine never fires a machine-gated rule...
    assert not _rule_machine_type_allows({}, arm64_rule)
    # ...but an absent gate means "all", preserving existing rule behavior.
    assert _rule_machine_type_allows({}, {})
    assert _rule_machine_type_allows({"machine_type": "AMD64"}, {"machine_types": []})
