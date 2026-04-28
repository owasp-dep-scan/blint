import os
import sys
from pathlib import Path

import pytest

from blint.lib.binary import (
    build_disassembly_callgraph_metadata,
    demangle_symbolic_name,
    parse,
    parse_informative_strings,
    parse_macho_symbols,
)


TEST_DATA_DIR = Path(__file__).resolve().parent / "data"


def test_parse():
    if os.path.exists("/bin/ls"):
        metadata = parse("/bin/ls")
        assert metadata


@pytest.mark.parametrize(
    "wasm_name",
    [
        "adversarial_ops.wasm",
        "bulk_memory.wasm",
        "complex_flow.wasm",
        "dos_growth_loop.wasm",
    ],
)
def test_parse_wasm_metadata(wasm_name):
    wasm_file = TEST_DATA_DIR / wasm_name
    metadata = parse(str(wasm_file))

    assert wasm_file.exists(), f"Missing test fixture: {wasm_file}"
    assert metadata["binary_type"] == "WASM"
    assert metadata["machine_type"] == "WASM32"
    assert metadata["module_version"] == 1
    assert metadata["functions"]
    assert metadata["exports"]
    assert metadata["section_count"] > 0
    assert isinstance(metadata.get("wasm_imports"), list)
    assert metadata["imports"] == metadata["dynamic_entries"]
    assert (
        metadata["import_dependencies"]["libraries"][str(wasm_file)]["type"]
        == "main_binary"
    )
    assert metadata["llvm_target_tuple"] == "wasm32-unknown-unknown"
    assert metadata["hashes"]["sha256"]
    assert metadata["wasm_report"]["file"] == str(wasm_file)


def test_parse_wasm_parser_failure(tmp_path):
    wasm_file = tmp_path / "broken.wasm"
    wasm_file.write_bytes(b"\x00asm\x01\x00")
    metadata = parse(str(wasm_file))

    assert metadata["binary_type"] == "WASM"
    assert metadata["errors"]
    assert "WebAssembly" in metadata["errors"][0]


def test_parse_informative_strings_extracts_and_deduplicates_network_hints():
    class _FakeParsed:
        strings = [
            "BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB",
            "bpf_sock_ops_active_established_cb",
            "IP_HDRINCL",
            "harmless_string",
            "127.0.0.1:53",
            "shadow",
            "sniper",
        ]

    informative = parse_informative_strings(_FakeParsed())
    values = [entry["value"] for entry in informative]

    assert "BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB" in values
    assert "IP_HDRINCL" in values
    assert "127.0.0.1:53" in values
    assert "harmless_string" not in values
    assert "shadow" not in values
    assert "sniper" not in values
    assert len(values) == 3


def test_parse_informative_strings_matches_punctuated_indicators_once():
    class _FakeParsed:
        strings = [
            " DNS-over-HTTPS ",
            "dns-over-https",
            "/dev/net/tun0",
            "dns-query endpoint",
            "",
            None,
        ]

    informative = parse_informative_strings(_FakeParsed())
    values = [entry["value"] for entry in informative]

    assert values == ["DNS-over-HTTPS", "/dev/net/tun0", "dns-query endpoint"]
    assert all(entry["category"] == "network_evasion_hint" for entry in informative)


def test_parse_wasm_detects_dos_growth_loop_finding():
    wasm_file = TEST_DATA_DIR / "dos_growth_loop.wasm"
    metadata = parse(str(wasm_file))

    findings = (metadata.get("wasm_analysis") or {}).get("findings") or []
    finding_ids = {finding.get("id") for finding in findings}
    assert "WASM-DOS-003" in finding_ids


def test_parse_macho_symbols_export_info_symbol_is_json_safe():
    class _FakeExportInfo:
        symbol = object()
        kind = "regular"
        flags = "FLAG_A"
        node_offset = 0x10
        address = 0x20

    class _FakeSymbol:
        has_binding_info = False
        value = 0x1000
        demangled_name = "macho_symbol"
        name = "macho_symbol"
        has_export_info = True
        export_info = _FakeExportInfo()
        category = "N_SECT"
        type = "TYPE"
        numberof_sections = 1
        description = "desc"
        origin = "ORIGIN"

    symbols, _ = parse_macho_symbols([_FakeSymbol()])

    assert symbols
    export_info = symbols[0]["export_info"]
    assert export_info
    assert export_info["symbol"] == "macho_symbol"


def test_build_disassembly_callgraph_metadata_counts_and_external():
    metadata = {
        "disassembled_functions": {
            "0x20::beta": {
                "name": "beta",
                "address": "0x20",
                "direct_calls": [],
            },
            "0x10::alpha": {
                "name": "alpha",
                "address": "0x10",
                "direct_calls": ["beta", "beta", "ext::io", "dup"],
            },
            "0x30::dup": {
                "name": "dup",
                "address": "0x30",
                "direct_calls": [],
            },
            "0x40::dup": {
                "name": "dup",
                "address": "0x40",
                "direct_calls": [],
            },
        }
    }

    graph = build_disassembly_callgraph_metadata(metadata)

    assert graph["version"] == 2
    assert graph["node_count"] == 4
    assert graph["edge_count"] == 1
    assert graph["nodes"][0]["name"] == "alpha"
    assert graph["nodes"][1]["name"] == "beta"
    assert graph["edges"] == [
        {
            "src": 0,
            "dst": 1,
            "count": 2,
            "kind": "direct",
            "confidence": "high",
        }
    ]
    assert graph["external"] == [
        {
            "src": 0,
            "target": "dup",
            "count": 1,
            "reason": "ambiguous_name",
            "confidence": "low",
        },
        {
            "src": 0,
            "target": "ext::io",
            "count": 1,
            "reason": "symbol_only_miss",
            "confidence": "low",
        },
    ]


def test_build_disassembly_callgraph_metadata_deterministic_for_input_order():
    metadata_a = {
        "disassembled_functions": {
            "0x20::beta": {
                "name": "beta",
                "address": "0x20",
                "direct_calls": [],
            },
            "0x10::alpha": {
                "name": "alpha",
                "address": "0x10",
                "direct_calls": ["beta"],
            },
        }
    }
    metadata_b = {
        "disassembled_functions": {
            "0x10::alpha": {
                "name": "alpha",
                "address": "0x10",
                "direct_calls": ["beta"],
            },
            "0x20::beta": {
                "name": "beta",
                "address": "0x20",
                "direct_calls": [],
            },
        }
    }

    graph_a = build_disassembly_callgraph_metadata(metadata_a)
    graph_b = build_disassembly_callgraph_metadata(metadata_b)

    assert graph_a == graph_b


def test_build_disassembly_callgraph_metadata_prefers_address_targets():
    metadata = {
        "disassembled_functions": {
            "0x10::foo": {
                "name": "foo",
                "address": "0x10",
                "direct_calls": [],
                "direct_call_targets": [
                    {
                        "target_name": "dup",
                        "target_address": "0x30",
                        "raw_operand": "0x30",
                    },
                    {
                        "target_name": "",
                        "target_address": "",
                        "raw_operand": "std::rt::lang_start",
                    },
                ],
            },
            "0x20::dup": {
                "name": "dup",
                "address": "0x20",
                "direct_calls": [],
            },
            "0x30::dup": {
                "name": "dup",
                "address": "0x30",
                "direct_calls": [],
            },
        }
    }

    graph = build_disassembly_callgraph_metadata(metadata)

    assert graph["edge_count"] == 1
    assert graph["edges"] == [
        {
            "src": 0,
            "dst": 2,
            "count": 1,
            "kind": "direct",
            "confidence": "high",
        }
    ]
    assert graph["external"] == [
        {
            "src": 0,
            "target": "std::rt::lang_start",
            "count": 1,
            "reason": "unresolved",
            "confidence": "low",
        }
    ]


def test_build_disassembly_callgraph_metadata_handles_none_target_name_and_rva():
    metadata = {
        "image_base": 0x100000000,
        "disassembled_functions": {
            "0x100000010::foo": {
                "name": "foo",
                "address": "0x100000010",
                "direct_call_targets": [
                    {
                        "target_name": None,
                        "target_address": "0x30",
                        "raw_operand": "#48",
                    }
                ],
            },
            "0x100000030::bar": {
                "name": "bar",
                "address": "0x100000030",
                "direct_call_targets": [],
            },
        },
    }

    graph = build_disassembly_callgraph_metadata(metadata)

    assert graph["edge_count"] == 1
    assert graph["edges"] == [
        {
            "src": 0,
            "dst": 1,
            "count": 1,
            "kind": "direct",
            "confidence": "high",
        }
    ]
    assert graph["external"] == []


def test_build_disassembly_callgraph_metadata_preserves_edge_kind():
    metadata = {
        "disassembled_functions": {
            "0x10::foo": {
                "name": "foo",
                "address": "0x10",
                "direct_call_targets": [
                    {
                        "target_name": "bar",
                        "target_address": "0x20",
                        "raw_operand": "0x20",
                        "kind": "tailcall",
                    },
                    {
                        "target_name": "",
                        "target_address": "",
                        "raw_operand": "jmp_target",
                        "kind": "tailcall",
                    },
                ],
            },
            "0x20::bar": {
                "name": "bar",
                "address": "0x20",
                "direct_call_targets": [],
            },
        }
    }

    graph = build_disassembly_callgraph_metadata(metadata)

    assert graph["edges"] == [
        {
            "src": 0,
            "dst": 1,
            "count": 1,
            "kind": "tailcall",
            "confidence": "medium",
        }
    ]
    assert graph["external"] == [
        {
            "src": 0,
            "target": "jmp_target",
            "count": 1,
            "reason": "unresolved:tailcall",
            "confidence": "low",
        }
    ]


def test_build_disassembly_callgraph_metadata_indirect_hint_reason_and_edge():
    metadata = {
        "disassembled_functions": {
            "0x10::caller": {
                "name": "caller",
                "address": "0x10",
                "direct_call_targets": [
                    {
                        "target_name": "callee",
                        "target_address": "0x20",
                        "target_address_candidates": ["0x20"],
                        "raw_operand": "rax",
                        "kind": "indirect_hint",
                    },
                    {
                        "target_name": "",
                        "target_address": "",
                        "target_address_candidates": [],
                        "raw_operand": "unknown_reg",
                        "kind": "indirect_hint",
                    },
                ],
            },
            "0x20::callee": {
                "name": "callee",
                "address": "0x20",
                "direct_call_targets": [],
            },
        }
    }

    graph = build_disassembly_callgraph_metadata(metadata)

    assert graph["edges"] == [
        {
            "src": 0,
            "dst": 1,
            "count": 1,
            "kind": "indirect_hint",
            "confidence": "low",
        }
    ]
    assert graph["external"] == [
        {
            "src": 0,
            "target": "unknown_reg",
            "count": 1,
            "reason": "unresolved:indirect_hint",
            "confidence": "low",
        }
    ]


def test_build_disassembly_callgraph_metadata_indirect_hint_links_plt_alias_to_internal():
    metadata = {
        "disassembled_functions": {
            "0x10::caller": {
                "name": "caller",
                "address": "0x10",
                "direct_call_targets": [
                    {
                        "target_name": "callee@plt",
                        "target_address": "",
                        "target_address_candidates": [],
                        "raw_operand": "qword ptr [rip + 0x10]",
                        "kind": "indirect_hint",
                    }
                ],
            },
            "0x20::callee": {
                "name": "callee",
                "address": "0x20",
                "direct_call_targets": [],
            },
            "0x20::callee@plt": {
                "name": "callee@plt",
                "address": "0x20",
                "direct_call_targets": [],
            },
        }
    }

    graph = build_disassembly_callgraph_metadata(metadata)

    assert graph["edges"] == [
        {
            "src": 0,
            "dst": 1,
            "count": 1,
            "kind": "indirect_hint",
            "confidence": "low",
        }
    ]
    assert graph["external"] == []


def test_build_disassembly_callgraph_metadata_indirect_hint_plt_alias_ambiguity_is_external():
    metadata = {
        "disassembled_functions": {
            "0x10::caller": {
                "name": "caller",
                "address": "0x10",
                "direct_call_targets": [
                    {
                        "target_name": "puts@plt",
                        "target_address": "",
                        "target_address_candidates": [],
                        "raw_operand": "qword ptr [rip + 0x10]",
                        "kind": "indirect_hint",
                    }
                ],
            },
            "0x20::puts_one": {
                "name": "puts",
                "address": "0x20",
                "direct_call_targets": [],
            },
            "0x30::puts_two": {
                "name": "puts",
                "address": "0x30",
                "direct_call_targets": [],
            },
        }
    }

    graph = build_disassembly_callgraph_metadata(metadata)

    assert graph["edges"] == []
    assert graph["external"] == [
        {
            "src": 0,
            "target": "qword ptr [rip + 0x10]",
            "count": 1,
            "reason": "ambiguous_address:indirect_hint",
            "confidence": "low",
        }
    ]


def test_build_disassembly_callgraph_metadata_collapses_same_address_aliases():
    metadata = {
        "disassembled_functions": {
            "0x10::foo_alias": {
                "name": "foo_alias",
                "address": "0x10",
                "direct_call_targets": [
                    {
                        "target_name": "bar",
                        "target_address": "0x20",
                        "target_address_candidates": ["0x20"],
                        "raw_operand": "0x20",
                        "kind": "direct",
                    }
                ],
            },
            "0x10::foo_main": {
                "name": "foo_main",
                "address": "0x10",
                "direct_call_targets": [],
            },
            "0x20::bar": {
                "name": "bar",
                "address": "0x20",
                "direct_call_targets": [],
            },
        }
    }

    graph = build_disassembly_callgraph_metadata(metadata)

    assert graph["node_count"] == 2
    assert graph["edges"] == [
        {
            "src": 0,
            "dst": 1,
            "count": 1,
            "kind": "direct",
            "confidence": "high",
        }
    ]
    assert graph["nodes"][0]["aliases"] == ["foo_alias", "foo_main"]


def test_build_disassembly_callgraph_metadata_resolves_target_inside_function_range():
    metadata = {
        "disassembled_functions": {
            "0x10::caller": {
                "name": "caller",
                "address": "0x10",
                "direct_call_targets": [
                    {
                        "target_name": "",
                        "target_address": "0x25",
                        "target_address_candidates": ["0x25"],
                        "raw_operand": "0x25",
                        "kind": "direct",
                    }
                ],
            },
            "0x20::callee": {
                "name": "callee",
                "address": "0x20",
                "direct_call_targets": [],
            },
            "0x30::next_fn": {
                "name": "next_fn",
                "address": "0x30",
                "direct_call_targets": [],
            },
        }
    }

    graph = build_disassembly_callgraph_metadata(metadata)

    assert graph["edges"] == [
        {
            "src": 0,
            "dst": 1,
            "count": 1,
            "kind": "direct",
            "confidence": "high",
        }
    ]


def test_build_disassembly_callgraph_metadata_canonical_alias_is_deterministic():
    metadata_a = {
        "disassembled_functions": {
            "0x10::zzz": {"name": "zzz", "address": "0x10", "direct_call_targets": []},
            "0x10::aaa": {"name": "aaa", "address": "0x10", "direct_call_targets": []},
        }
    }
    metadata_b = {
        "disassembled_functions": {
            "0x10::aaa": {"name": "aaa", "address": "0x10", "direct_call_targets": []},
            "0x10::zzz": {"name": "zzz", "address": "0x10", "direct_call_targets": []},
        }
    }

    graph_a = build_disassembly_callgraph_metadata(metadata_a)
    graph_b = build_disassembly_callgraph_metadata(metadata_b)

    assert graph_a == graph_b
    assert graph_a["nodes"][0]["name"] == "aaa"
    assert graph_a["nodes"][0]["aliases"] == ["aaa", "zzz"]


def test_build_disassembly_callgraph_metadata_keeps_tied_address_candidates_ambiguous():
    metadata = {
        "disassembled_functions": {
            "0x10::caller": {
                "name": "caller",
                "address": "0x10",
                "direct_call_targets": [
                    {
                        "target_name": "",
                        "target_address": "",
                        "target_address_candidates": ["0x1000", "0x2000"],
                        "raw_operand": "0x1000",
                        "kind": "direct",
                    }
                ],
            },
            "0x1000::func_a": {
                "name": "func_a",
                "address": "0x1000",
                "direct_call_targets": [],
            },
            "0x2000::func_b": {
                "name": "func_b",
                "address": "0x2000",
                "direct_call_targets": [],
            },
        }
    }

    graph = build_disassembly_callgraph_metadata(metadata)

    assert graph["edges"] == []
    assert graph["external"] == [
        {
            "src": 0,
            "target": "0x1000",
            "count": 1,
            "reason": "ambiguous_address",
            "confidence": "low",
        }
    ]


def test_parse_adds_callgraph_when_disassembly_results_exist(monkeypatch):
    if not os.path.exists("/bin/ls"):
        pytest.skip("/bin/ls not available on this host")

    fake_disassembly = {
        "0x10::core::main": {
            "name": "core::main",
            "address": "0x10",
            "direct_calls": ["helper"],
        },
        "0x20::helper": {
            "name": "helper",
            "address": "0x20",
            "direct_calls": [],
        },
    }

    def _fake_disassemble_functions(_parsed_obj, _metadata):
        return fake_disassembly

    monkeypatch.setattr(
        "blint.lib.binary.disassemble_functions", _fake_disassemble_functions
    )

    metadata = parse("/bin/ls", disassemble=True)

    assert metadata.get("disassembled_functions") == fake_disassembly
    assert metadata.get("callgraph")
    assert metadata["callgraph"]["edge_count"] == 1


@pytest.mark.skipif(
    sys.platform == "win32", reason="symbolic is not available on windows"
)
def test_demangle():
    assert (
        demangle_symbolic_name(".rdata$.refptr.__mingw_initltsdrot_force")
        == "__declspec(dllimport) __mingw_initltsdrot_force"
    )
    assert (
        demangle_symbolic_name(
            "_ZN4core3ptr79drop_in_place$LT$alloc..vec..Vec$LT$wast..component..types..VariantCase$GT$$GT$17h41b828a7ca01b8c4E.llvm.12153207245666130899"
        )
        == "core::ptr::drop_in_place<alloc::vec::Vec<wast::component::types::VariantCase>>"
    )
    assert (
        demangle_symbolic_name(
            "_ZN5tokio7runtime4task7harness20Harness$LT$T$C$S$GT$8complete17h79b950493dfd179dE.llvm.3144946739014404372"
        )
        == "tokio::runtime::task::harness::Harness<T,S>::complete"
    )
    assert (
        demangle_symbolic_name(
            "_ZN4core3ptr252drop_in_place$LT$core..result..Result$LT$$LP$alloc..collections..vec_deque..VecDeque$LT$core..result..Result$LT$tokio..fs..read_dir..DirEntry$C$std..io..error..Error$GT$$GT$$C$std..fs..ReadDir$C$bool$RP$$C$tokio..runtime..task..error..JoinError$GT$$GT$17hb2a9b81fd7c41483E.llvm.17332334537075604262"
        )
        == "core::ptr::drop_in_place<core::result::Result<(alloc::collections::vec_deque::VecDeque<core::result::Result<tokio::fs::read_dir::DirEntry,std::io::error::Error>>,std::fs::ReadDir,bool),tokio::runtime::task::error::JoinError>>"
    )
    assert (
        demangle_symbolic_name(
            "_ZN6anyhow5error31_$LT$impl$u20$anyhow..Error$GT$9construct17h41b87edbd45e0d86E.llvm.16823983138386609681"
        )
        == "anyhow::error::<impl anyhow::Error>::construct"
    )
    assert (
        demangle_symbolic_name(".refptr._pcre2_ucd_records_8")
        == "__declspec(dllimport) _pcre2_ucd_records_8"
    )
    assert (
        demangle_symbolic_name(
            "_<alloc::string::String as core::ops::index::Index<core::ops::range::RangeFrom<usize>>>::index::h4be97e660083a1bb"
        )
        == "_<alloc::string::String as core::ops::index::Index<core::ops::range::RangeFrom<usize>>>::index"
    )
    assert (
        demangle_symbolic_name(
            "core::ptr::drop_in_place<&core::option::Option<usize>>::hb70d68c80e72fe43"
        )
        == "core::ptr::drop_in_place<&core::option::Option<usize>>"
    )
