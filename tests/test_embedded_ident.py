"""Embedded code that leaves no version banner: brotli, Node.js and .NET.

The fixtures under tests/data/embedded are tiny aarch64 ELF shared objects
built by tests/data/embedded/build.sh from the C sources beside them. They
reproduce only the strings and symbol names the detectors read: the brotli
decoder's error-name table in each shape (1.0.x bare names, 1.1+ prefixed
names, with and without the CVE-2026-111497 BLOCK_SWITCH fix), Node.js's
release URLs and inspector string, and the .NET runtime pack's export family
and build stamp. The real binaries they mirror (node 24.22.0/24.22.1,
Debian's patched libbrotli 1.0.9, the PyPI Brotli wheel, .NET 8.0.32's
libSystem.IO.Compression.Native.so) were measured with the same detectors.
"""

from pathlib import Path

import orjson
import pytest

from blint.config import BlintOptions
from blint.lib.banners import detect_vendored_banners
from blint.lib.binary import parse
from blint.lib.embedded_ident import (
    BROTLI_BOM_REF,
    BROTLI_DECODER_TABLES,
    BROTLI_PURL,
    _brotli_record,
    _dotnet_record,
    _has_c_string,
)
from blint.lib.runners import run_sbom_mode

_EMBEDDED = Path(__file__).resolve().parent / "data" / "embedded"


def _record(metadata: dict, library: str) -> dict | None:
    return next(
        (r for r in metadata.get("embedded_libraries") or [] if r["library"] == library), None
    )


def _cstrings(*values: str) -> list[bytes]:
    """One section's worth of NUL-separated C strings."""
    return [b"\x00" + b"\x00".join(v.encode() for v in values) + b"\x00"]


PREFIXED_TABLE = [
    "_ERROR_FORMAT_EXUBERANT_NIBBLE",
    "_ERROR_FORMAT_RESERVED",
    "_ERROR_FORMAT_EXUBERANT_META_NIBBLE",
    "_ERROR_FORMAT_SIMPLE_HUFFMAN_ALPHABET",
    "_ERROR_FORMAT_SIMPLE_HUFFMAN_SAME",
    "_ERROR_FORMAT_CONTEXT_MAP_REPEAT",
]
BARE_TABLE = [name.removeprefix("_ERROR_FORMAT_") for name in PREFIXED_TABLE]


@pytest.mark.parametrize(
    ("fixture", "fix_state", "table"),
    [
        ("brotli-1.2.0-unpatched.so", "absent", "prefixed"),
        ("brotli-1.2.1-patched.so", "present", "prefixed"),
        # Debian's 1.0.9-2+deb12u1 backport: bare names, BLOCK_SWITCH added.
        ("brotli-1.0.9-backport.so", "present", "bare"),
        ("node-24.22.0.so", "absent", "prefixed"),
        ("node-24.22.1.so", "present", "prefixed"),
        # .NET 8 bundles a 1.0.x copy without the fix.
        ("libSystem.IO.Compression.Native.so", "absent", "bare"),
    ],
)
def test_brotli_fix_state_from_fixtures(fixture, fix_state, table):
    metadata = parse(str(_EMBEDDED / fixture))
    record = _record(metadata, "brotli")
    assert record is not None
    assert record["purl"] == BROTLI_PURL
    assert "version" not in record
    assert record["properties"] == {
        "brotli_block_switch_fix": fix_state,
        "brotli_error_table": table,
    }
    assert any(item["where"] == "symbols" for item in record["evidence"])


def test_brotli_absent_when_the_api_is_only_imported():
    # A program that links libbrotlidec imports the API and owns no table.
    metadata = {
        "dynamic_symbols": [
            {"name": "BrotliDecoderCreateInstance", "is_imported": True},
            {"name": "BrotliDecoderDecompressStream", "is_imported": True},
        ]
    }
    assert _brotli_record(_cstrings("libbrotlidec.so.1"), set()) is None
    from blint.lib.embedded_ident import _defined_symbol_names

    assert _brotli_record([], _defined_symbol_names(metadata)) is None


def test_brotli_api_without_error_table_is_unknown():
    defined = {"_BrotliDecoderCreateInstance", "_BrotliDecoderDecompressStream"}
    record = _brotli_record([], defined)
    assert record["properties"] == {
        "brotli_block_switch_fix": "unknown",
        "brotli_error_table": "none",
    }


def test_brotli_one_api_name_is_not_a_decoder():
    assert _brotli_record([], {"BrotliDecoderDecompress"}) is None


def test_brotli_table_needs_three_distinctive_names():
    contents = _cstrings("_ERROR_FORMAT_EXUBERANT_NIBBLE", "_ERROR_FORMAT_CONTEXT_MAP_REPEAT")
    assert _brotli_record(contents, set()) is None


def test_brotli_node_constant_names_are_not_the_decoder_table():
    # Node's zlib binding lists BROTLI_DECODER_ERROR_* constant names; they
    # are not the decoder's error strings and must not count as its table.
    contents = _cstrings(
        *(f"BROTLI_DECODER_ERROR_FORMAT_{n}" for n in BARE_TABLE),
        "BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH",
    )
    assert _brotli_record(contents, set()) is None


def test_prefixed_names_are_not_read_as_bare_ones():
    contents = _cstrings(*PREFIXED_TABLE, "_ERROR_FORMAT_BLOCK_SWITCH")
    assert not _has_c_string(contents, "BLOCK_SWITCH")
    assert not _has_c_string(contents, "EXUBERANT_NIBBLE")
    record = _brotli_record(contents, set())
    assert record["properties"]["brotli_error_table"] == "prefixed"
    assert record["properties"]["brotli_block_switch_fix"] == "present"


def test_two_copies_report_the_unpatched_one():
    contents = _cstrings(*BARE_TABLE, "BLOCK_SWITCH", *PREFIXED_TABLE)
    record = _brotli_record(contents, set())
    assert record["properties"] == {
        "brotli_block_switch_fix": "absent",
        "brotli_error_table": "prefixed+bare",
    }


def test_two_copies_of_one_table_shape_report_the_unpatched_one():
    # Two copies a linker kept apart, only one of them fixed: the table's
    # names occur twice and the fix name once.
    contents = _cstrings(*PREFIXED_TABLE, "_ERROR_FORMAT_BLOCK_SWITCH") + _cstrings(
        *PREFIXED_TABLE
    )
    record = _brotli_record(contents, set())
    assert record["properties"]["brotli_block_switch_fix"] == "absent"
    both_fixed = _cstrings(*PREFIXED_TABLE, "_ERROR_FORMAT_BLOCK_SWITCH") * 2
    assert _brotli_record(both_fixed, set())["properties"]["brotli_block_switch_fix"] == "present"


@pytest.mark.parametrize(
    ("fixture", "fix_state"),
    [
        ("brotli-lld-tailmerged-unpatched.so", "absent"),
        ("brotli-lld-tailmerged-patched.so", "present"),
        # The decoder API hidden: only its tables mark the decoder.
        ("brotli-lld-tailmerged-hidden.so", "absent"),
    ],
)
def test_lld_tail_merged_names_are_read_from_the_node_constants(fixture, fix_state):
    """lld -O2 leaves the decoder's names only as tails of Node's constants."""
    metadata = parse(str(_EMBEDDED / fixture))
    assert _record(metadata, "brotli")["properties"] == {
        "brotli_block_switch_fix": fix_state,
        "brotli_error_table": "constant",
    }


def test_decoder_tables_alone_are_a_decoder_of_unknown_state():
    contents = [b"\x90" + BROTLI_DECODER_TABLES[0] + b"\x90" + BROTLI_DECODER_TABLES[1]]
    record = _brotli_record(contents, set())
    assert record["properties"] == {
        "brotli_block_switch_fix": "unknown",
        "brotli_error_table": "none",
    }
    # The encoder keeps only the first table, and the Go port has both.
    assert _brotli_record([BROTLI_DECODER_TABLES[0]], set()) is None
    assert _brotli_record(contents, set(), is_go=True) is None


def test_rust_port_is_not_the_c_decoder():
    """brotli-decompressor's FFI shim defines the C API and carries the tables."""
    assert _record(parse(str(_EMBEDDED / "brotli-rust-ffi.so")), "brotli") is None
    api = {"BrotliDecoderCreateInstance", "BrotliDecoderDecompressStream"}
    rust_names = api | {"_ZN19brotli_decompressor3ffi28BrotliDecoderCreateInstance17h0E"}
    assert _brotli_record([], api, rust_names) is None
    # The C decoder's own table still identifies a C copy beside the Rust port.
    contents = _cstrings(*PREFIXED_TABLE) + [b"brotli-decompressor-4.0.1/src/lib.rs"]
    assert _brotli_record(contents, api, rust_names)["properties"]["brotli_error_table"] == (
        "prefixed"
    )


def test_every_slice_of_a_universal_macho_is_read():
    """A universal dylib whose arm64 slice lacks the fix its x86_64 slice has."""
    metadata = parse(str(_EMBEDDED / "brotli-universal-x86_64-patched.dylib"))
    properties = _record(metadata, "brotli")["properties"]
    assert properties["brotli_block_switch_fix"] == "absent"
    assert properties["brotli_slice_fix_states"] == "x86_64=present, arm64=absent"


def test_dotnet_stamp_without_product_string_stays_versionless():
    metadata = parse(str(_EMBEDDED / "libSystem.IO.Compression.Native.so"))
    record = _record(metadata, "dotnet-runtime")
    assert record["purl"] == "pkg:github/dotnet/runtime"
    assert "version" not in record and "cpe" not in record
    assert record["properties"] == {
        "dotnet_file_version": "8.0.3226.50405",
        "dotnet_source_commit": "b9a49e4a6d3a444a3685e318c74a7892d01873f7",
    }


def test_dotnet_product_string_agreeing_with_the_stamp_versions_it():
    metadata = parse(str(_EMBEDDED / "libSystem.IO.Compression.Native-product.so"))
    record = _record(metadata, "dotnet-runtime")
    assert record["version"] == "8.0.32"
    assert record["cpe"] == "cpe:2.3:a:microsoft:.net:8.0.32:*:*:*:*:*:*:*"


def test_dotnet_release_candidate_is_not_read_as_ga():
    # An 8.0.0 RC carries file version 8.0.23.x, the same shape as 8.0.0 GA;
    # its product string is the prerelease one, so no version is claimed.
    contents = _cstrings(
        "8.0.0-rc.2.23479.6",
        "@(#)Version 8.0.23.47906 @Commit: 0b25e38ad32a69cd83ae246104b32449203cc71c",
    )
    record = _dotnet_record({}, contents, {"SystemNative_Read"})
    assert "version" not in record
    assert record["properties"]["dotnet_file_version"] == "8.0.23.47906"


def test_dotnet_pe_product_version_resource():
    metadata = {"resources": {"version_metadata": {"ProductVersion": "8.0.32+b9a49e4a6d3a"}}}
    record = _dotnet_record(metadata, [], {"CompressionNative_Crc32"})
    assert record["version"] == "8.0.32"


_STAMP = "@(#)Version 8.0.3226.50405 @Commit: b9a49e4a6d3a444a3685e318c74a7892d01873f7"


def test_dotnet_jit_is_identified():
    record = _dotnet_record({}, _cstrings(_STAMP), {"jitStartup", "getJit", "jitBuildString"})
    assert record["properties"]["dotnet_file_version"] == "8.0.3226.50405"
    assert "version" not in record


def test_dotnet_host_without_exports_is_identified():
    """The dotnet muxer and apphosts export nothing; their hostfxr strings mark them."""
    contents = _cstrings("hostfxr_main_startupinfo", "COREHOST_TRACE", "8.0.32", _STAMP)
    record = _dotnet_record({}, contents, set())
    assert record["version"] == "8.0.32"
    assert record["evidence"][0]["what"] == ".NET host (muxer or apphost) strings"
    assert _dotnet_record({}, _cstrings("COREHOST_TRACE", _STAMP), set()) is None


def test_dotnet_stamp_after_another_sccs_string():
    contents = _cstrings("@(#)Version 1.2 of something else", _STAMP)
    record = _dotnet_record({}, contents, {"SystemNative_Read"})
    assert record["properties"]["dotnet_file_version"] == "8.0.3226.50405"


def test_dotnet_product_version_resource_must_agree_with_the_stamp():
    metadata = {"resources": {"version_metadata": {"ProductVersion": "8.0.31+0123456789ab"}}}
    record = _dotnet_record(metadata, _cstrings(_STAMP), {"CompressionNative_Crc32"})
    assert "version" not in record
    assert record["properties"]["dotnet_file_version"] == "8.0.3226.50405"
    assert any("disagreeing" in item["what"] for item in record["evidence"])


def test_pe_resources_are_not_read_for_embedded_code():
    """An installer's .rsrc can be hundreds of MB and never holds the decoder."""
    from types import SimpleNamespace

    from blint.lib.embedded_ident import _section_contents

    binary = SimpleNamespace(
        sections=[
            SimpleNamespace(name=".rsrc", content=b"resource payload"),
            SimpleNamespace(name=".rdata", content=b"program strings"),
        ]
    )
    assert _section_contents(binary) == [b"program strings"]


def test_dotnet_export_family_alone_is_not_an_identification():
    assert _dotnet_record({}, [], {"SystemNative_Read"}) is None
    assert _dotnet_record({}, _cstrings("@(#)Version 8.0.3226.1 @Commit: abcdef1"), set()) is None


def test_node_banner_from_release_url_and_inspector_string():
    metadata = parse(str(_EMBEDDED / "node-24.22.1.so"))
    result = detect_vendored_banners(metadata)
    assert [(b["purl"], b["cpe"]) for b in result["banners"]] == [
        (
            "pkg:generic/node@24.22.1",
            "cpe:2.3:a:nodejs:node.js:24.22.1:*:*:*:*:*:*:*",
        )
    ]


def test_node_string_in_an_addon_is_a_mention():
    # An addon imports Node-API and owns no runtime: the string is a mention.
    metadata = {
        "strings": [{"value": "node.js/v24.22.1"}],
        "dynamic_symbols": [{"name": "napi_create_object", "is_imported": True}],
    }
    result = detect_vendored_banners(metadata)
    assert result["banners"] == []
    assert [m["purl"] for m in result["mentions"]] == ["pkg:generic/node@24.22.1"]


def test_bun_is_not_node():
    """Bun carries Node.js's headersUrl and implements Node-API itself."""
    metadata = parse(str(_EMBEDDED / "bun-1.4.3.so"))
    result = detect_vendored_banners(metadata)
    assert result["banners"] == []
    assert [(m["purl"], m["reason"]) for m in result["mentions"]] == [
        ("pkg:generic/node@26.3.0", "Bun runtime; implements the nodejs API")
    ]


def test_bun_sbom_has_no_node_component(tmp_path):
    bom = _sbom(tmp_path, "bun-1.4.3.so")
    components = _flatten([bom["metadata"]["component"], *bom.get("components", [])])
    assert not any("pkg:generic/node" in (c.get("purl") or "") for c in components)
    assert "Bun runtime" in _properties(bom["metadata"]["component"])[
        "internal:vendored_banner_mentions"
    ]


def test_node_identity_past_the_string_cap(monkeypatch):
    """A large Mach-O holds more strings than are extracted; the inspector
    string can sit past the cap, so the Node.js rules also read section bytes."""
    from blint.lib import binary_common

    monkeypatch.setattr(binary_common, "MAX_EXTRACTED_STRINGS", 0)
    metadata = parse(str(_EMBEDDED / "node-24.18.0-inspector-only.dylib"))
    assert metadata["identity_strings"] == ["node.js/v24.18.0"]
    result = detect_vendored_banners(metadata)
    assert [(b["purl"], b["cpe"]) for b in result["banners"]] == [
        ("pkg:generic/node@24.18.0", "cpe:2.3:a:nodejs:node.js:24.18.0:*:*:*:*:*:*:*")
    ]


def _sbom(tmp_path: Path, fixture: str) -> dict:
    output = tmp_path / f"{fixture}.cdx.json"
    options = BlintOptions(
        sbom_mode=True,
        src_dir_image=[str(_EMBEDDED / fixture)],
        sbom_output=str(output),
        quiet_mode=True,
    )
    assert run_sbom_mode(options)
    return orjson.loads(output.read_bytes())


def _sbom_components(tmp_path: Path, fixture: str) -> list[dict]:
    bom = _sbom(tmp_path, fixture)
    return bom["metadata"]["component"].get("components", []) + bom.get("components", [])


def _flatten(components: list[dict]) -> list[dict]:
    flat = []
    for component in components:
        flat.append(component)
        flat.extend(_flatten(component.get("components") or []))
    return flat


def _properties(component: dict) -> dict:
    return {p["name"]: p["value"] for p in component.get("properties") or []}


def test_patched_and_unpatched_node_produce_different_sboms(tmp_path):
    seen = {}
    for version in ("24.22.0", "24.22.1"):
        bom = _sbom(tmp_path, f"node-{version}.so")
        components = _flatten(bom["metadata"]["component"].get("components", []) + bom["components"])
        node = next(c for c in components if c.get("purl", "").startswith("pkg:generic/node"))
        brotli = next(c for c in components if c.get("bom-ref") == BROTLI_BOM_REF)
        assert node["purl"] == f"pkg:generic/node@{version}"
        assert node["cpe"] == f"cpe:2.3:a:nodejs:node.js:{version}:*:*:*:*:*:*:*"
        assert brotli["purl"] == BROTLI_PURL
        assert _properties(brotli)["internal:vendored_attribution"] == "embedded_identification"
        assert "internal:brotli_block_switch_fix" not in _properties(brotli)
        # The fix state belongs to the file that carries the copy.
        seen[version] = _properties(bom["metadata"]["component"])[
            "internal:brotli_block_switch_fix"
        ]
    assert seen == {"24.22.0": "absent", "24.22.1": "present"}


def _scan(tmp_path: Path, inputs: list[Path]) -> dict:
    output = tmp_path / "scan.cdx.json"
    options = BlintOptions(
        sbom_mode=True,
        src_dir_image=[str(i) for i in inputs],
        sbom_output=str(output),
        quiet_mode=True,
    )
    assert run_sbom_mode(options)
    return orjson.loads(output.read_bytes())


def _copy(source: str, target: Path) -> Path:
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes((_EMBEDDED / source).read_bytes())
    return target


def test_directory_scan_keeps_each_copy_fix_state_apart(tmp_path):
    """One shared brotli component; each file keeps its own copy's state.

    A file whose own name is brotli does not collide with the shared
    component, so the document has no duplicate bom-ref.
    """
    scan_dir = tmp_path / "rootfs"
    _copy("brotli-1.2.1-patched.so", scan_dir / "libpatched.so")
    _copy("brotli-1.2.0-unpatched.so", scan_dir / "libunpatched.so")
    _copy("brotli-1.2.0-unpatched.so", scan_dir / "brotli")
    bom = _scan(tmp_path, [scan_dir])
    components = _flatten(bom["metadata"]["component"].get("components", []) + bom["components"])
    refs = [c["bom-ref"] for c in components]
    assert len(refs) == len(set(refs))
    states = {
        c["name"]: _properties(c).get("internal:brotli_block_switch_fix")
        for c in components
        if "internal:brotli_block_switch_fix" in _properties(c)
    }
    assert states == {"libpatched.so": "present", "libunpatched.so": "absent", "brotli": "absent"}
    shared = [c for c in components if c["bom-ref"] == BROTLI_BOM_REF]
    assert len(shared) == 1
    depends = {d["ref"]: d.get("dependsOn", []) for d in bom["dependencies"]}
    for name in states:
        assert BROTLI_BOM_REF in depends[f"pkg:generic/{name}"]


def test_same_named_copies_keep_the_weakest_state(tmp_path):
    """Two files of one name are one component; the unpatched copy wins."""
    for order in (("a", "b"), ("b", "a")):
        scan_dir = tmp_path / "".join(order)
        _copy("brotli-1.2.1-patched.so", scan_dir / order[0] / "libbrotlidec.so.1")
        _copy("brotli-1.2.0-unpatched.so", scan_dir / order[1] / "libbrotlidec.so.1")
        bom = _scan(tmp_path, [scan_dir])
        # Merged into one file component, the document's own when it is the only one.
        components = _flatten([bom["metadata"]["component"], *bom["components"]])
        (copy,) = [c for c in components if c["name"] == "libbrotlidec.so.1"]
        assert _properties(copy)["internal:brotli_block_switch_fix"] == "absent"


def test_dotnet_sbom_component_carries_stamp_properties(tmp_path):
    bom = _sbom(tmp_path, "libSystem.IO.Compression.Native.so")
    components = _flatten(bom["metadata"]["component"].get("components", []) + bom["components"])
    runtime = next(c for c in components if c.get("purl") == "pkg:github/dotnet/runtime")
    # The stamp is this file's; the runtime component is shared by every file.
    assert "internal:dotnet_file_version" not in _properties(runtime)
    properties = _properties(bom["metadata"]["component"])
    assert properties["internal:dotnet_file_version"] == "8.0.3226.50405"
    assert "export family" in properties["internal:embedded_evidence"]


def test_macho_dylib_identity_is_not_a_dependency_of_itself(tmp_path):
    """LIEF lists a dylib's own LC_ID_DYLIB among its libraries.

    It is the artifact's identity: the install name and current_version
    ride the parent component, and no library component or declared
    dependency names the dylib itself.
    """
    from blint.lib.import_attribution import declared_libraries

    fixture = _EMBEDDED / "libbrotlidec.1.2.0.dylib"
    metadata = parse(str(fixture))
    identity = [e for e in metadata["libraries"] if e.get("command") == "ID_DYLIB"]
    assert [(e["name"], e["version"]) for e in identity] == [
        ("/opt/homebrew/opt/brotli/lib/libbrotlidec.1.dylib", "1.2.0")
    ]
    assert "libbrotlidec.1.dylib" not in declared_libraries(metadata)
    assert _record(metadata, "brotli")["properties"]["brotli_block_switch_fix"] == "absent"

    bom = _sbom(tmp_path, fixture.name)
    components = _flatten(bom["metadata"]["component"].get("components", []) + bom["components"])
    assert not any("libbrotlidec.1.dylib" in (c.get("purl") or "") for c in components)
    # A single input's parent is the document's own component.
    properties = _properties(bom["metadata"]["component"])
    assert properties["internal:dylib_install_name"] == (
        "/opt/homebrew/opt/brotli/lib/libbrotlidec.1.dylib"
    )
    assert properties["internal:dylib_current_version"] == "1.2.0"


# --- blintdb versions against the artifact's own evidence -----------------

_BROTLI_RECORD = {
    "library": "brotli",
    "purl": "pkg:generic/brotli",
    "evidence": [{"what": "error-name table", "where": "strings", "value": "..."}],
    "properties": {"brotli_block_switch_fix": "absent", "brotli_error_table": "prefixed"},
}


def _blintdb_brotli_components(tmp_path, monkeypatch, own_version=None):
    """process_exe_file with a database holding only brotli 1.1.0.

    The database's six zlib-named symbols are what the fixture builder
    stores; the project row is what the match reports.
    """
    from tests.test_sbom_blintdb import _run_process_exe_with_db

    metadata = {
        "name": "libbrotlidec.1.dylib",
        "binary_type": "MachO",
        "symtab_symbols": [
            {"name": name}
            for name in ("deflate", "inflate", "zlibVersion", "compress2", "uncompress", "crc32")
        ],
        "embedded_libraries": [_BROTLI_RECORD],
    }
    if own_version:
        metadata["libraries"] = [
            {
                "name": "/opt/homebrew/opt/brotli/lib/libbrotlidec.1.dylib",
                "version": own_version,
                "compatibility_version": "1.0.0",
                "command": "ID_DYLIB",
            }
        ]
    return _run_process_exe_with_db(
        tmp_path,
        monkeypatch,
        "pkg:generic/brotli@1.1.0",
        metadata,
        binary_name="libbrotlidec.1.dylib",
    )


def _component_properties(component) -> dict:
    return {p.name: p.value for p in component.properties or []}


def test_dylib_own_version_contradicting_the_database_drops_the_db_version(
    tmp_path, monkeypatch
):
    """The darwin meson blintdb holds only brotli 1.1.0 and named Homebrew's
    libbrotlidec.1.2.0.dylib 1.1.0, against the dylib's own current_version."""
    components = _blintdb_brotli_components(tmp_path, monkeypatch, own_version="1.2.0")
    brotli = [c for c in components if "brotli" in (c.purl or "")]
    assert [c.purl for c in brotli] == ["pkg:generic/brotli"]
    properties = _component_properties(brotli[0])
    assert properties["internal:blintdb_version_contradiction"] == (
        "database row 1.1.0; artifact evidence dylib_current_version=1.2.0"
    )
    # The fix state is the file's; the match stands for the library.
    assert "internal:brotli_block_switch_fix" not in properties


def test_database_only_version_is_marked_as_a_database_match(tmp_path, monkeypatch):
    components = _blintdb_brotli_components(tmp_path, monkeypatch)
    (brotli,) = [c for c in components if "brotli" in (c.purl or "")]
    assert brotli.purl == "pkg:generic/brotli@1.1.0"
    properties = _component_properties(brotli)
    assert properties["internal:blintdb_version_basis"] == "database_row"
    assert "internal:brotli_block_switch_fix" not in properties


def test_database_version_the_artifact_confirms(tmp_path, monkeypatch):
    components = _blintdb_brotli_components(tmp_path, monkeypatch, own_version="1.1.0")
    (brotli,) = [c for c in components if "brotli" in (c.purl or "")]
    assert brotli.purl == "pkg:generic/brotli@1.1.0"
    assert _component_properties(brotli)["internal:blintdb_version_basis"] == "artifact_evidence"
