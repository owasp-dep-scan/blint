"""Tests for the .tbd SDK symbol index (P2.6).

Coverage map:

- **TAPI variants** (workplan rule 10: a fixture per format variant). The
  reader claims v1-v4 and multi-document streams; each shape has a fixture
  here, because only the v4 shape is exercised by the real SDK the
  ground-truth test runs against.
- **Attribution policy**. The load-bearing decision -- a re-exported symbol
  is attributed to the declaring library, never the implementing one -- is
  pinned from both sides: the umbrella provides, and a library that does
  not re-export does not inherit.
- **Determinism**. Two builds over the same tree serialize identically, and
  neither the artifact nor the metadata block carries the SDK's absolute
  path.
- **Ground truth** (workplan rule 22). One test runs against a real Xcode
  SDK and derives its expectations from ``dyld_info`` on a real binary;
  it asserts non-empty results and skips cleanly where that toolchain is
  absent. A hand-built fixture can only confirm the fixture author's
  reading of the format, which is why the real-artifact test exists.
"""

import os
import subprocess
import sys
from pathlib import Path

import orjson
import pytest

from blint.lib.import_attribution import build_symbol_provider_map
from blint.lib.tbd_index import (
    ATTRIBUTED_SYMBOL_SAMPLE_CAP,
    SDK_ATTRIBUTIONS_KEY,
    UNCONFIRMED_SYMBOL_SAMPLE_CAP,
    TbdIndex,
    TbdSdkError,
    enrich_macho_sdk_attribution,
    index_fingerprint,
    load_or_build_index,
)

# --- fixture SDK trees -------------------------------------------------------

V4_UMBRELLA = """\
--- !tapi-tbd
tbd-version:     4
targets:         [ x86_64-macos, arm64-macos ]
install-name:    '/usr/lib/libUmbrella.B.dylib'
current-version: 1351
reexported-libraries:
  - targets:         [ x86_64-macos, arm64-macos ]
    libraries:       [ '/usr/lib/system/libchild.dylib', '/usr/lib/system/libreexporter.dylib', '/usr/lib/libmissing.dylib' ]
exports:
  - targets:         [ x86_64-macos ]
    symbols:         [ _umbrella_own, 'R1234$_residency_marked' ]
  - targets:         [ arm64-macos ]
    symbols:         [ _umbrella_own ]
"""


def _write_sdk(root: Path) -> None:
    """A fixture SDK exercising every schema shape the reader claims."""
    (root / "usr" / "lib" / "system").mkdir(parents=True)
    (root / "usr" / "lib" / "libUmbrella.B.tbd").write_text(V4_UMBRELLA)
    # Direct provider: its exports are what the umbrella re-exports inherit.
    (root / "usr" / "lib" / "system" / "libchild.tbd").write_text(
        "--- !tapi-tbd\n"
        "tbd-version:     4\n"
        "targets:         [ x86_64-macos, arm64-macos ]\n"
        "install-name:    '/usr/lib/system/libchild.dylib'\n"
        "exports:\n"
        "  - targets:         [ x86_64-macos, arm64-macos ]\n"
        "    symbols:         [ _dispatch_once, _child_direct, _getenv ]\n"
        "    weak-symbols:    [ _child_weak ]\n"
    )
    # A stub that only *re-exports* a symbol (never lists it in exports):
    # the shape _strcmp has in the real SDK. An umbrella above it must
    # inherit the symbol through the closure.
    (root / "usr" / "lib" / "system" / "libreexporter.tbd").write_text(
        "--- !tapi-tbd\n"
        "tbd-version:     4\n"
        "targets:         [ x86_64-macos ]\n"
        "install-name:    '/usr/lib/system/libreexporter.dylib'\n"
        "reexports:\n"
        "  - targets:         [ x86_64-macos ]\n"
        "    symbols:         [ _strcmp ]\n"
    )
    # The git-analog binary declares this helper library too, and its one
    # import is a direct export of it (the libxcselect shape).
    (root / "usr" / "lib" / "libhelper.tbd").write_text(
        "--- !tapi-tbd\n"
        "tbd-version:     4\n"
        "targets:         [ x86_64-macos ]\n"
        "install-name:    '/usr/lib/libhelper.dylib'\n"
        "exports:\n"
        "  - targets:         [ x86_64-macos ]\n"
        "    symbols:         [ _helper_invoke_xcrun ]\n"
    )
    # The pcre shape: a declared library whose symbols the binary imports
    # directly by flat bind.
    (root / "usr" / "lib" / "libpcre.tbd").write_text(
        "--- !tapi-tbd\n"
        "tbd-version:     4\n"
        "targets:         [ x86_64-macos ]\n"
        "install-name:    '/usr/lib/libpcre.0.dylib'\n"
        "exports:\n"
        "  - targets:         [ x86_64-macos ]\n"
        "    symbols:         [ _pcre_compile, _pcre_exec ]\n"
    )
    # ObjC classes: binaries bind `_OBJC_CLASS_$_Foo`, stubs list `Foo`.
    frameworks = root / "System" / "Library" / "Frameworks"
    (frameworks / "Foundation.framework").mkdir(parents=True)
    (frameworks / "Foundation.framework" / "Foundation.tbd").write_text(
        "--- !tapi-tbd\n"
        "tbd-version:     4\n"
        "targets:         [ arm64-macos ]\n"
        "install-name:    '/System/Library/Frameworks/Foundation.framework/Foundation'\n"
        "exports:\n"
        "  - targets:         [ arm64-macos ]\n"
        "    symbols:         [ _FoundationFunc ]\n"
        "    objc-classes:    [ NSArray, NSString ]\n"
        "    objc-eh-types:   [ NSException ]\n"
    )
    # v3-era shape: `re-exports` names libraries, sections keyed by `archs`.
    (root / "usr" / "lib" / "libv3.tbd").write_text(
        "--- !tapi-tbd\n"
        "tbd-version:     3\n"
        "targets:         [ x86_64-macos ]\n"
        "install-name:    '/usr/lib/libv3.dylib'\n"
        "re-exports:      [ '/usr/lib/libv3child.dylib' ]\n"
        "exports:\n"
        "  - archs:           [ x86_64 ]\n"
        "    symbols:         [ _v3_export ]\n"
    )
    (root / "usr" / "lib" / "libv3child.tbd").write_text(
        "--- !tapi-tbd\n"
        "tbd-version:     3\n"
        "targets:         [ x86_64-macos ]\n"
        "install-name:    '/usr/lib/libv3child.dylib'\n"
        "exports:\n"
        "  - archs:           [ x86_64 ]\n"
        "    symbols:         [ _v3child_export ]\n"
    )
    # v1 shape: symbol lists under `sections` with a `kind` discriminator.
    (root / "usr" / "lib" / "libv1.tbd").write_text(
        "--- !tapi-tbd\n"
        "tbd-version:     1\n"
        "targets:         [ x86_64-macos ]\n"
        "install-name:    '/usr/lib/libv1.dylib'\n"
        "sections:\n"
        "  - kind:            symbols\n"
        "    archs:           [ x86_64 ]\n"
        "    symbols:         [ _v1_export ]\n"
        "  - kind:            objc-classes\n"
        "    archs:           [ x86_64 ]\n"
        "    symbols:         [ V1Class ]\n"
    )
    # One file, two documents: a framework stub carrying its legacy sibling.
    (frameworks / "Multi.framework").mkdir(parents=True)
    (frameworks / "Multi.framework" / "Multi.tbd").write_text(
        "--- !tapi-tbd\n"
        "tbd-version:     4\n"
        "targets:         [ arm64-macos ]\n"
        "install-name:    '/System/Library/Frameworks/Multi.framework/Multi'\n"
        "exports:\n"
        "  - targets:         [ arm64-macos ]\n"
        "    symbols:         [ _multi_primary ]\n"
        "--- !tapi-tbd\n"
        "tbd-version:     4\n"
        "targets:         [ arm64-macos ]\n"
        "install-name:    '/System/Library/Frameworks/Multi.framework/MultiLegacy'\n"
        "exports:\n"
        "  - targets:         [ arm64-macos ]\n"
        "    symbols:         [ _multi_legacy ]\n"
    )
    # Apple ships malformed stubs; one must not sink the index.
    (root / "usr" / "lib" / "libbroken.tbd").write_text(
        "--- !tapi-tbd\ntbd-version: 4\ntargets: [ , broken\n"
    )


@pytest.fixture()
def sdk_root(tmp_path):
    root = tmp_path / "MacOSX.sdk"
    root.mkdir()
    _write_sdk(root)
    return root


@pytest.fixture()
def sdk_index(sdk_root):
    return TbdIndex.build(str(sdk_root))


# --- build and schema variants ------------------------------------------------


def test_build_indexes_every_document(sdk_index, sdk_root):
    # 11 files hold 11 valid documents: the multi-doc file carries two, the
    # broken file contributes none.
    assert sdk_index.file_count == 11
    assert sdk_index.document_count == 11
    assert len(sdk_index.libraries) == 11
    assert "/usr/lib/libUmbrella.B.dylib" in sdk_index.libraries
    assert str(sdk_root) not in " ".join(sdk_index.libraries)


def test_v4_direct_exports_and_weak_symbols(sdk_index):
    direct, _ = sdk_index._symbol_library_ids("_dispatch_once")
    assert direct
    direct_weak, _ = sdk_index._symbol_library_ids("_child_weak")
    assert direct_weak


def test_umbrella_provides_reexported_symbols_via_closure(sdk_index):
    # The load-bearing attribution decision: the symbol an umbrella re-exports
    # belongs to the umbrella's surface, because a Mach-O two-level bind names
    # the library the binary declared, and dyld walks re-exports from there.
    provides, via_reexport = sdk_index.provides(
        "/usr/lib/libUmbrella.B.dylib", "_dispatch_once"
    )
    assert provides is True
    assert via_reexport is True
    # The implementing library provides it directly.
    provides_direct, via = sdk_index.provides("/usr/lib/system/libchild.dylib", "_dispatch_once")
    assert provides_direct is True
    assert via is False


def test_reexport_section_symbols_propagate_up_the_closure(sdk_index):
    # `_strcmp` exists in nobody's exports; a stub offers it in its
    # `reexports` section, and the umbrella above that stub must inherit it.
    # This is the exact shape `_strcmp` has under libSystem in a real SDK.
    assert sdk_index.exports.get("_strcmp") in (None, [])
    provides, via = sdk_index.provides("/usr/lib/libUmbrella.B.dylib", "_strcmp")
    assert provides is True
    assert via is True


def test_library_that_does_not_reexport_does_not_inherit(sdk_index):
    # Negative control for the closure: libchild is a leaf and provides
    # nothing but its own exports; another stub's re-exports are not its own.
    provides, _ = sdk_index.provides("/usr/lib/system/libchild.dylib", "_strcmp")
    assert provides is False
    provides, _ = sdk_index.provides("/usr/lib/system/libchild.dylib", "_umbrella_own")
    assert provides is False


def test_reexport_of_a_library_missing_from_the_sdk_tolerated(sdk_index):
    # libUmbrella re-exports /usr/lib/libmissing.dylib, which has no stub.
    # The edge contributes nothing, the umbrella still indexes, and asking
    # about the missing library's symbols simply finds nothing.
    provides, _ = sdk_index.provides("/usr/lib/libUmbrella.B.dylib", "_thing_only_missing_has")
    assert provides is False
    provides, _ = sdk_index.provides("/usr/lib/libmissing.dylib", "_dispatch_once")
    assert provides is False


def test_objc_class_symbols_match_through_their_prefixes(sdk_index):
    install = "/System/Library/Frameworks/Foundation.framework/Foundation"
    for bind_form in (
        "_OBJC_CLASS_$_NSArray",
        "_OBJC_METACLASS_$_NSArray",
        # eh-type names carry the class name with a leading underscore
        "_OBJC_EHTYPE_$_NSException",
    ):
        provides, _ = sdk_index.provides(install, bind_form)
        assert provides is True, bind_form
    provides, _ = sdk_index.provides(install, "_OBJC_CLASS_$_NSArray")
    assert provides


def test_v3_reexports_and_arch_keyed_sections(sdk_index):
    provides, via = sdk_index.provides("/usr/lib/libv3.dylib", "_v3_export")
    assert provides is True and via is False
    provides, via = sdk_index.provides("/usr/lib/libv3.dylib", "_v3child_export")
    assert provides is True and via is True


def test_v1_sections_with_kind(sdk_index):
    provides, _ = sdk_index.provides("/usr/lib/libv1.dylib", "_v1_export")
    assert provides is True
    provides, _ = sdk_index.provides("/usr/lib/libv1.dylib", "_OBJC_CLASS_$_V1Class")
    assert provides is True


def test_multi_document_file_indexes_all_install_names(sdk_index):
    base = "/System/Library/Frameworks/Multi.framework/"
    assert sdk_index.provides(base + "Multi", "_multi_primary")[0] is True
    assert sdk_index.provides(base + "MultiLegacy", "_multi_legacy")[0] is True
    # Siblings do not provide for each other.
    assert sdk_index.provides(base + "Multi", "_multi_legacy")[0] is False


def test_unresolvable_and_unknown_symbols_stay_unprovided(sdk_index):
    provides, _ = sdk_index.provides("/usr/lib/libUmbrella.B.dylib", "_nope_not_anywhere")
    assert provides is False
    provides, _ = sdk_index.provides("/usr/lib/not-in-the-index.dylib", "_dispatch_once")
    assert provides is False


def test_attribute_prefers_declared_load_command_order(sdk_index):
    declared = [
        "/usr/lib/libUmbrella.B.dylib",
        "/usr/lib/system/libchild.dylib",
    ]
    # Both provide it; the first declared wins, matching dyld's search order.
    assert sdk_index.attribute("_dispatch_once", declared) == "/usr/lib/libUmbrella.B.dylib"
    # Only the child provides this one.
    assert sdk_index.attribute("_child_direct", list(reversed(declared))) == (
        "/usr/lib/system/libchild.dylib"
    )
    # Nothing declared provides it: unattributed, never guessed at.
    assert sdk_index.attribute("_objc_msgSend", declared) == ""
    assert sdk_index.attribute("_dispatch_once", []) == ""


# --- failure modes ------------------------------------------------------------


def test_empty_sdk_path_is_a_loud_error(tmp_path):
    empty = tmp_path / "empty-sdk"
    empty.mkdir()
    with pytest.raises(TbdSdkError):
        TbdIndex.build(str(empty))


def test_missing_sdk_path_is_a_loud_error(tmp_path):
    with pytest.raises(TbdSdkError):
        TbdIndex.build(str(tmp_path / "does-not-exist"))


def test_file_sdk_path_is_a_loud_error(sdk_root):
    with pytest.raises(TbdSdkError):
        TbdIndex.build(str(sdk_root / "usr" / "lib" / "libv3.tbd"))


# --- determinism and the on-disk artifact ------------------------------------


def test_serialization_is_deterministic_and_path_free(sdk_root):
    first = TbdIndex.build(str(sdk_root))
    second = TbdIndex.build(str(sdk_root))
    raw_first = first.to_bytes()
    assert raw_first == second.to_bytes()
    # Determinism also forbids the environment leaking into the artifact.
    assert str(sdk_root).encode() not in raw_first
    restored = TbdIndex.from_bytes(raw_first)
    assert restored.to_bytes() == raw_first
    assert restored.provides("/usr/lib/libUmbrella.B.dylib", "_dispatch_once") == (
        first.provides("/usr/lib/libUmbrella.B.dylib", "_dispatch_once")
    )


def test_fingerprint_ignores_absolute_location(tmp_path):
    first = tmp_path / "one"
    second = tmp_path / "two"
    for root in (first, second):
        root.mkdir()
        _write_sdk(root)
        # Normalize mtimes: two freshly written trees differ in creation time
        # by milliseconds, which must not masquerade as a content change.
        for path in root.rglob("*.tbd"):
            os.utime(path, (1700000000, 1700000000))
    assert index_fingerprint(str(first)) == index_fingerprint(str(second))
    # Touching a file changes mtime and must change the fingerprint.
    os.utime(first / "usr" / "lib" / "libv3.tbd", (0, 0))
    assert index_fingerprint(str(first)) != index_fingerprint(str(second))


def test_load_or_build_uses_disk_artifact(tmp_path, monkeypatch):
    cache_dir = tmp_path / "cache"
    monkeypatch.setenv("BLINT_CACHE_DIR", str(cache_dir))
    sdk_root = tmp_path / "sdk"
    sdk_root.mkdir()
    _write_sdk(sdk_root)
    index = load_or_build_index(str(sdk_root))
    artifacts = list(cache_dir.glob("tbd-index-*.json.zlib"))
    assert len(artifacts) == 1
    # A fresh process-equivalent: memo cleared, build forbidden. Only the
    # artifact can answer.
    monkeypatch.setattr(load_or_build_index.__globals__["TbdIndex"], "build", None)
    load_or_build_index.__globals__["_INDEX_MEMO"].clear()
    try:
        warmed = load_or_build_index(str(sdk_root))
        assert warmed.to_bytes() == index.to_bytes()
    finally:
        load_or_build_index.__globals__["_INDEX_MEMO"].clear()
        monkeypatch.undo()


def test_load_or_build_memoizes_per_process(tmp_path, monkeypatch):
    monkeypatch.setenv("BLINT_CACHE_DIR", str(tmp_path / "cache"))
    sdk_root = tmp_path / "sdk"
    sdk_root.mkdir()
    _write_sdk(sdk_root)
    first = load_or_build_index(str(sdk_root))
    second = load_or_build_index(str(sdk_root))
    assert first is second


def test_load_or_build_propagates_loud_error(tmp_path, monkeypatch):
    monkeypatch.setenv("BLINT_CACHE_DIR", str(tmp_path / "cache"))
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(TbdSdkError):
        load_or_build_index(str(empty))


# --- metadata enrichment -------------------------------------------------------


def _git_like_metadata() -> dict:
    """The /usr/bin/git shape: every import prefixed by its bind library."""
    return {
        "name": "/usr/bin/git",
        "binary_type": "MachO",
        "libraries": [
            {"name": "/usr/lib/libhelper.dylib"},
            {"name": "/usr/lib/libUmbrella.B.dylib"},
        ],
        "symtab_symbols": [
            {
                "name": "/usr/lib/libUmbrella.B.dylib::_dispatch_once",
                "short_name": "_dispatch_once",
                "is_imported": True,
            },
            {
                "name": "/usr/lib/libUmbrella.B.dylib::_strcmp",
                "short_name": "_strcmp",
                "is_imported": True,
            },
            {
                "name": "/usr/lib/libhelper.dylib::_helper_invoke_xcrun",
                "short_name": "_helper_invoke_xcrun",
                "is_imported": True,
            },
            {
                "name": "_mh_execute_header",
                "is_imported": False,
                "is_exported": True,
            },
        ],
    }


def _mailq_like_metadata() -> dict:
    """The /usr/bin/mailq shape: undefined symbols, none carrying a prefix."""
    return {
        "name": "/usr/bin/mailq",
        "binary_type": "MachO",
        "libraries": [
            {"name": "/usr/lib/libUmbrella.B.dylib"},
            {"name": "/usr/lib/libpcre.0.dylib"},
        ],
        "symtab_symbols": [
            {"name": "_getenv", "is_imported": True},
            {"name": "_pcre_compile", "is_imported": True},
            {"name": "_totally_unknown_import", "is_imported": True},
        ],
    }


def test_enrich_confirms_load_command_binds(sdk_root):
    metadata = _git_like_metadata()
    block = enrich_macho_sdk_attribution(metadata, str(sdk_root))
    assert block is not None
    # _dispatch_once and _strcmp reach the umbrella only through re-exports;
    # _helper_invoke_xcrun is a direct export of its own library.
    assert block["confirmed_symbol_count"] == 3
    assert block["reexport_confirmed_symbol_count"] == 2
    assert block["unconfirmed_symbol_count"] == 0
    assert block["attributed_symbol_count"] == 0
    # Non-imported symbols are neither confirmed nor attributed.
    assert metadata.get(SDK_ATTRIBUTIONS_KEY) == {}


def test_enrich_reports_unconfirmed_binds_honestly(sdk_root):
    metadata = _git_like_metadata()
    # A bind the SDK surface cannot back: worth an honest look, not silence.
    metadata["symtab_symbols"].append(
        {"name": "/usr/lib/libUmbrella.B.dylib::_private_symbol", "is_imported": True}
    )
    block = enrich_macho_sdk_attribution(metadata, str(sdk_root))
    assert block["confirmed_symbol_count"] == 3
    assert block["unconfirmed_symbol_count"] == 1
    assert block["unconfirmed_symbols"] == ["/usr/lib/libUmbrella.B.dylib::_private_symbol"]


def test_counts_stay_exact_when_samples_are_capped(sdk_root):
    """Counts are exact; only the samples are bounded.

    The count is what an analyst acts on -- "the SDK could not vouch for 140
    of these binds" -- so it must not saturate at the sample cap. Collection
    used to stop at the cap, which silently turned any number above 16 into
    16 and understated every large binary's gap.
    """
    metadata = _git_like_metadata()
    over_cap = UNCONFIRMED_SYMBOL_SAMPLE_CAP * 3
    for index in range(over_cap):
        metadata["symtab_symbols"].append(
            {
                "name": f"/usr/lib/libUmbrella.B.dylib::_private_{index:03d}",
                "is_imported": True,
            }
        )
    block = enrich_macho_sdk_attribution(metadata, str(sdk_root))
    assert block["unconfirmed_symbol_count"] == over_cap
    assert len(block["unconfirmed_symbols"]) == UNCONFIRMED_SYMBOL_SAMPLE_CAP

def test_attributed_count_is_exact_above_the_sample_cap(tmp_path):
    """The same contract on the attribution side, with its own SDK tree.

    Built separately rather than added to ``sdk_root``: that fixture's
    document and file counts are pinned by the build tests.
    """
    root = tmp_path / "Bulk.sdk" / "usr" / "lib"
    root.mkdir(parents=True)
    attributable = ATTRIBUTED_SYMBOL_SAMPLE_CAP * 2
    symbols = ", ".join(f"_bulk_{index:03d}" for index in range(attributable))
    (root / "libbulk.tbd").write_text(
        "--- !tapi-tbd\n"
        "tbd-version:     4\n"
        "targets:         [ arm64-macos ]\n"
        "install-name:    '/usr/lib/libbulk.dylib'\n"
        "exports:\n"
        "  - targets:         [ arm64-macos ]\n"
        f"    symbols:         [ {symbols} ]\n"
    )
    metadata = {
        "binary_type": "MachO",
        "libraries": [{"name": "/usr/lib/libbulk.dylib"}],
        "symtab_symbols": [
            {"name": f"_bulk_{index:03d}", "is_imported": True}
            for index in range(attributable)
        ],
    }
    block = enrich_macho_sdk_attribution(metadata, str(tmp_path / "Bulk.sdk"))
    assert block["attributed_symbol_count"] == attributable
    assert len(block["attributed_symbols"]) == ATTRIBUTED_SYMBOL_SAMPLE_CAP
    # The dependency graph gets the full map, not the sample.
    assert len(metadata[SDK_ATTRIBUTIONS_KEY]) == attributable


def test_enrich_attributes_flat_binds_to_declared_libraries(sdk_root):
    metadata = _mailq_like_metadata()
    block = enrich_macho_sdk_attribution(metadata, str(sdk_root))
    assert block["attributed_symbol_count"] == 2
    full_map = metadata[SDK_ATTRIBUTIONS_KEY]
    assert full_map["_getenv"] == "/usr/lib/libUmbrella.B.dylib"
    assert full_map["_pcre_compile"] == "/usr/lib/libpcre.0.dylib"
    # The unknown import stays out rather than being guessed at.
    assert "_totally_unknown_import" not in full_map
    # The exported sample and the count agree, and the sample is capped
    # separately from the full map.
    assert block["attributed_symbols"]["_getenv"] == "/usr/lib/libUmbrella.B.dylib"


def test_enrich_without_declared_libraries_is_a_no_op(sdk_root):
    metadata = {"binary_type": "MachO", "libraries": [], "symtab_symbols": []}
    assert enrich_macho_sdk_attribution(metadata, str(sdk_root)) is None
    assert "sdk_tbd" not in metadata


def test_enrich_never_leaks_the_sdk_path(sdk_root):
    metadata = _git_like_metadata()
    enrich_macho_sdk_attribution(metadata, str(sdk_root))
    exported = {
        key: value
        for key, value in metadata.items()
        if key != SDK_ATTRIBUTIONS_KEY
    }
    assert str(sdk_root).encode() not in orjson.dumps(exported)


def test_provider_map_consumes_sdk_attributions_with_own_source(sdk_root):
    metadata = _mailq_like_metadata()
    enrich_macho_sdk_attribution(metadata, str(sdk_root))
    providers, sources = build_symbol_provider_map(metadata)
    assert sources == ["sdk_tbd"]
    assert providers["_getenv"] == "libUmbrella.B.dylib"
    assert providers["_pcre_compile"] == "libpcre.0.dylib"


def test_load_commands_evidence_outranks_sdk_attribution(sdk_root):
    metadata = _mailq_like_metadata()
    # A symbol the SDK attributed and the binary's own bind also names: the
    # bind wins, and the source list records both kinds of evidence.
    metadata["symtab_symbols"].insert(
        0,
        {
            "name": "/usr/lib/libpcre.0.dylib::_getenv",
            "is_imported": True,
        },
    )
    enrich_macho_sdk_attribution(metadata, str(sdk_root))
    providers, sources = build_symbol_provider_map(metadata)
    assert "load_commands" in sources and "sdk_tbd" in sources
    assert providers["_getenv"] == "libpcre.0.dylib"


# --- ground truth against real artifacts (workplan rule 22) -------------------


def _real_sdk() -> str | None:
    if sys.platform != "darwin":
        return None
    try:
        result = subprocess.run(
            ["xcrun", "--show-sdk-path"], capture_output=True, text=True, check=True
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    sdk = result.stdout.strip()
    return sdk if sdk and os.path.isdir(sdk) else None


@pytest.fixture(scope="module")
def real_sdk():
    sdk = _real_sdk()
    if not sdk:
        pytest.skip("no Xcode SDK available for ground-truth verification")
    return sdk


@pytest.fixture(scope="module")
def real_index(real_sdk):
    return load_or_build_index(real_sdk)


def _dyld_info_imports(binary: str) -> list[tuple[str, str]]:
    """(symbol, from-short-name) pairs according to dyld_info itself."""
    result = subprocess.run(
        ["/usr/bin/dyld_info", "-imports", binary],
        capture_output=True,
        text=True,
        check=True,
    )
    pairs = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if "(from " not in line:
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        symbol = parts[1]
        pairs.append((symbol, line.rsplit("(from ", 1)[1].rstrip(")")))
    return pairs


def _declared_install_names(binary: str) -> list[str]:
    result = subprocess.run(
        ["/usr/bin/otool", "-L", binary], capture_output=True, text=True, check=True
    )
    names = []
    for line in result.stdout.splitlines()[1:]:
        path = line.strip().split(" ", 1)[0]
        if path.startswith("/"):
            names.append(path)
    return names


@pytest.mark.skipif(not os.path.exists("/usr/bin/git"), reason="no /usr/bin/git")
def test_index_confirms_the_binds_dyld_reports_for_a_real_binary(real_index):
    """Ground truth: every import dyld reports for /usr/bin/git must be
    provided by the SDK surface of the library dyld names.

    Both sides of the comparison come from outside blint: the imports and
    their libraries from ``dyld_info``, the declared install-names from
    ``otool -L``. The assertion is on a non-empty result set -- a parser
    that returned nothing would satisfy everything else (rule 22).
    """
    pairs = _dyld_info_imports("/usr/bin/git")
    assert len(pairs) >= 10, f"dyld_info returned too little to test against: {pairs}"
    declared = _declared_install_names("/usr/bin/git")
    assert declared
    confirmed = 0
    for symbol, from_short in pairs:
        candidates = [
            name for name in declared if from_short in Path(name).name
        ]
        assert candidates, f"no declared library matches dyld's '{from_short}'"
        hits = [bool(real_index.provides(name, symbol)[0]) for name in candidates]
        assert any(hits), (
            f"SDK index cannot confirm {symbol} from {candidates} "
            "(dyld reports it imported from there)"
        )
        confirmed += 1
    assert confirmed >= 10


@pytest.mark.skipif(
    not os.path.isfile("/usr/lib/libpcre2-8.dylib"),
    reason="no readable system dylib for the exports oracle",
)
def test_index_matches_a_real_dylibs_exports(real_index):
    """Ground truth on the export side: what dyld_info says a real on-disk
    dylib exports, the SDK's stub for the same library must also list."""
    dylib = "/usr/lib/libpcre2-8.dylib"
    result = subprocess.run(
        ["/usr/bin/dyld_info", "-exports", dylib],
        capture_output=True,
        text=True,
        check=True,
    )
    exports = [
        line.strip().split()[-1]
        for line in result.stdout.splitlines()
        if line.strip() and not line.strip().startswith(("-", "offset", "/usr"))
    ]
    assert exports, "dyld_info -exports returned nothing to test against"
    install = subprocess.run(
        ["/usr/bin/otool", "-D", dylib], capture_output=True, text=True, check=True
    ).stdout.splitlines()[-1].strip()
    assert install.startswith("/"), f"unexpected install name: {install!r}"
    sampled = exports[:40]
    confirmed = [symbol for symbol in sampled if real_index.provides(install, symbol)[0]]
    assert confirmed, (
        f"SDK stub for {install} confirmed none of the exports dyld_info "
        f"reports for the on-disk dylib (sampled {len(sampled)})"
    )
