from pathlib import Path

import orjson

from blint.lib.analysis import (
    EVIDENCE_LIMIT,
    _filter_callgraph_by_min_confidence,
    _build_mermaid_callgraph_text,
    _safe_mermaid_label,
    load_default_rules,
    run_checks,
)
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
        result
        for result in results
        if result["id"] == "RPC_IMPERSONATION_PROCESS_CHAIN"
    )
    assert process_review["evidence"][0]["function"] == "launch_with_rpc_token"

    asuser_review = next(
        result
        for result in results
        if result["id"] == "RPC_IMPERSONATION_ASUSER_PROCESS_CHAIN"
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
