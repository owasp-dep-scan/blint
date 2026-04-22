import os
import sys

import pytest

from blint.lib import binary as binary_lib
from blint.lib.binary import demangle_symbolic_name, parse


def test_parse():
    if os.path.exists("/bin/ls"):
        metadata = parse("/bin/ls")
        assert metadata


def test_parse_wasm_metadata(tmp_path, monkeypatch):
    wasm_file = tmp_path / "simple_add.wasm"
    wasm_file.write_bytes(b"\x00asm\x01\x00\x00\x00")

    report = {
        "module_version": 1,
        "section_count": 4,
        "sections": [{"index": 0, "id": 1, "name": "Type", "size": 8, "offset": 8}],
        "function_count": 1,
        "functions": [
            {
                "index": 0,
                "name": "add",
                "signature_index": 0,
                "offset": 40,
                "body_size": 12,
                "instruction_count": 4,
                "instructions": [
                    {"offset": 40, "opcode": "local.get", "immediates": [0]}
                ],
            }
        ],
        "imports": [
            {
                "index": 0,
                "module": "env",
                "name": "log",
                "kind": "func",
                "type_index": 0,
            }
        ],
        "exports": [{"index": 0, "name": "add", "kind": "func", "ref_index": 0}],
        "memories": [{"index": 0, "limits": {"min": 1, "max": 2, "is_64": False}}],
        "analysis": {
            "detections": {
                "wasi": {"detected": False, "variants": []},
                "js_interface": {"detected": False},
            }
        },
        "errors": [],
    }
    monkeypatch.setattr(binary_lib, "parse_wasm_file", lambda _: report)

    metadata = parse(str(wasm_file))

    assert metadata["binary_type"] == "WASM"
    assert metadata["machine_type"] == "WASM32"
    assert metadata["module_version"] == 1
    assert metadata["functions"][0]["name"] == "add"
    assert metadata["dynamic_entries"] == [{"name": "env", "tag": "NEEDED"}]
    assert metadata["import_dependencies"]["dependencies"]
    assert metadata["llvm_target_tuple"] == "wasm32-unknown-unknown"
    assert metadata["hashes"]["sha256"]


def test_parse_wasm_parser_failure(tmp_path, monkeypatch):
    wasm_file = tmp_path / "broken.wasm"
    wasm_file.write_bytes(b"\x00asm\x01\x00\x00\x00")

    def _raise_parse(_):
        raise ValueError("boom")

    monkeypatch.setattr(binary_lib, "parse_wasm_file", _raise_parse)
    metadata = parse(str(wasm_file))

    assert metadata["binary_type"] == "WASM"
    assert metadata["errors"]
    assert "Failed to parse wasm file" in metadata["errors"][0]


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
