import os
import sys
from pathlib import Path

import pytest

from blint.lib.binary import demangle_symbolic_name, parse, parse_macho_symbols


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
