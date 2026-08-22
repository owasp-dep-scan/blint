import copy
import json
import os
import pathlib
import shutil

import pytest

from blint.lib.binary import parse, parse_symbols
from blint.lib.checks import (
    check_abi_floor,
    check_libc_portability,
    check_runtime_loading,
    check_search_path,
)
from blint.lib.elf_abi import (
    analyze_elf_abi,
    compute_abi_requirements,
    parse_version_node,
    version_sort_key,
)
from blint.lib.elf_dlopen import (
    _normalize_candidate,
    recover_runtime_dependencies,
    summarize_runtime_loading,
)
from blint.lib.elf_linkmap import (
    _classify_search_path,
    _expand_tokens,
    _split_paths,
    resolve_link_closure,
)
from blint.lib.sbom import (
    components_from_abi_requirements,
    components_from_recovered_dependencies,
)

# Parsed metadata for the same Rust binary built for three targets, trimmed to
# the fields the ABI passes read. The binaries themselves live under the
# gitignored tests/fixtures tree, so anything driven from them runs only where
# that corpus has been fetched; these snapshots keep the assertions running
# everywhere. Real-binary behaviour is covered in CI by test_elf_abi_corpus.py,
# which analyses five distribution images in place.
METADATA_SNAPSHOTS = json.loads(
    (pathlib.Path(__file__).parent / "data" / "elf-abi-metadata.json").read_text()
)

FIXTURE_ROOT = os.path.join(
    os.path.dirname(__file__),
    "fixtures",
    "rust-binaries",
    "wasm-tools-1.247.0",
)


def elf_fixture(target: str) -> str:
    return os.path.join(FIXTURE_ROOT, f"wasm-tools-1.247.0-{target}", "wasm-tools")


def snapshot(target: str) -> dict:
    """Return the trimmed parsed metadata for one build target."""
    return copy.deepcopy(METADATA_SNAPSHOTS[target])


requires_binary_fixtures = pytest.mark.skipif(
    not os.path.isfile(elf_fixture("x86_64-linux")),
    reason="binary fixtures are not checked in; fetch the rust-binaries corpus to run these",
)


def test_parse_version_node():
    assert parse_version_node("GLIBC_2.34") == ("GLIBC", "2.34")
    assert parse_version_node("GLIBCXX_3.4.29") == ("GLIBCXX", "3.4.29")
    # The trailing index identifies the version table entry, not the version.
    assert parse_version_node("GLIBC_2.2.5(2)") == ("GLIBC", "2.2.5")
    # Underscore-separated tails normalize to the dotted form so that versions
    # written in either style compare against each other.
    assert parse_version_node("LIBSSH2_1_0") == ("LIBSSH2", "1.0")
    # Providers containing underscores are common in the wild and the version
    # is still the trailing numeric tail, not the first one found.
    assert parse_version_node("LIBPAM_EXTENSION_1.0") == ("LIBPAM_EXTENSION", "1.0")
    assert parse_version_node("NCURSES6_TINFO_5.7.20081102") == (
        "NCURSES6_TINFO",
        "5.7.20081102",
    )
    assert parse_version_node("OPENSSL_1_1_0") == ("OPENSSL", "1.1.0")
    # A version tail can end in a named component rather than a number.
    assert parse_version_node("NCURSES6_TINFO_6.6.current") == (
        "NCURSES6_TINFO",
        "6.6.current",
    )
    # MIT Kerberos appends a vendor tag after the version.
    assert parse_version_node("krb5_3_MIT") == ("krb5", "3")
    assert parse_version_node("gssapi_krb5_2_MIT") == ("gssapi_krb5", "2")
    # Plenty of real nodes carry no version at all and must not have one
    # invented for them.
    assert parse_version_node("SASL2") == ("SASL2", "")
    assert parse_version_node("SD_SHARED") == ("SD_SHARED", "")
    # A node named after a shared object names a library, not a version.
    assert parse_version_node("libjson-glib-1.0.so.0") == ("libjson-glib-1.0.so.0", "")
    # A private node carries no version at all.
    assert parse_version_node("GLIBC_PRIVATE") == ("GLIBC_PRIVATE", "")
    assert parse_version_node("Base") == ("Base", "")
    assert parse_version_node("* Global *") == ("* Global *", "")
    assert parse_version_node("") == ("", "")


def test_version_sort_key_orders_numerically():
    # A lexical comparison puts 2.9 above 2.34, which would understate the floor.
    assert version_sort_key("2.34") > version_sort_key("2.9")
    assert version_sort_key("2.2.5") < version_sort_key("2.3")
    assert version_sort_key("3.4.29") > version_sort_key("3.4.9")


def test_abi_floor_is_the_maximum_over_imports():
    metadata = {
        "dynamic_symbols": [
            {"name": "memcpy", "version": "GLIBC_2.14(3)", "is_imported": True},
            {"name": "statx", "version": "GLIBC_2.28(16)", "is_imported": True},
            {"name": "printf", "version": "GLIBC_2.2.5(2)", "is_imported": True},
            # A defined symbol describes what this object offers, not what it needs.
            {"name": "my_export", "version": "GLIBC_2.38(1)", "is_imported": False},
        ]
    }
    requirements = compute_abi_requirements(metadata)
    assert len(requirements) == 1
    assert requirements[0]["provider"] == "GLIBC"
    assert requirements[0]["min_version"] == "2.28"
    assert requirements[0]["determining_symbols"] == ["statx"]
    assert requirements[0]["symbol_count"] == 3
    assert requirements[0]["package_name"] == "libc"


def test_private_version_nodes_are_flagged():
    # A private node is an explicit statement that the symbol is internal, which
    # constrains portability more than any version floor does.
    metadata = {
        "interpreter": "/lib64/ld-linux-x86-64.so.2",
        "dynamic_symbols": [
            {"name": "__libc_early_init", "version": "GLIBC_PRIVATE", "is_imported": True},
            {"name": "memcpy", "version": "GLIBC_2.14", "is_imported": True},
        ],
    }
    abi = analyze_elf_abi(metadata)
    assert abi["uses_private_symbol_versions"] is True
    assert abi["private_version_providers"] == ["GLIBC_PRIVATE"]
    assert abi["min_glibc_version"] == "2.14"
    assert any("private version node" in note for note in abi["portability_notes"])


def test_unversioned_nodes_are_not_providers():
    metadata = {
        "dynamic_symbols": [
            {"name": "puts", "version": "* Global *", "is_imported": True},
            {"name": "gets", "version": "Base", "is_imported": True},
        ]
    }
    assert compute_abi_requirements(metadata) == []


def test_real_glibc_binary_reports_its_floor():
    abi = analyze_elf_abi(snapshot("x86_64-linux"))
    assert abi["libc"] == "glibc"
    # statx was added in glibc 2.28 and is the highest node this binary binds.
    assert abi["min_glibc_version"] == "2.28"
    determining = {
        symbol
        for req in abi["requirements"]
        if req["provider"] == "GLIBC"
        for symbol in req["determining_symbols"]
    }
    assert "statx" in determining
    assert abi["uses_implementation_specific_interfaces"] is True


def test_floor_differs_per_architecture():
    # The same source built for two architectures binds different version nodes,
    # so a single floor for the project would be wrong for one of them.
    x86 = analyze_elf_abi(snapshot("x86_64-linux"))["min_glibc_version"]
    arm = analyze_elf_abi(snapshot("aarch64-linux"))["min_glibc_version"]
    assert x86 == "2.28"
    assert arm == "2.18"


def test_musl_binary_is_identified_and_warned_about():
    abi = analyze_elf_abi(snapshot("x86_64-musl"))
    assert abi["libc"] == "musl"
    assert abi["min_glibc_version"] == ""
    assert any("musl" in note for note in abi["portability_notes"])


class FakeSymbol:
    """Mimics the parser's behaviour for an unmangled symbol.

    The real parser returns an empty string, not an error, when a symbol has no
    mangled form. Only the error branch was handled, so every plain C symbol in
    an ELF binary came through nameless.
    """

    def __init__(self, name, demangled):
        self.name = name
        self.demangled_name = demangled
        self.value = 0
        self.size = 0
        self.shndx = 0
        self.information = 0
        self.imported = True
        self.exported = False
        self.is_function = True
        self.is_static = False
        self.is_variable = False
        self.has_version = False
        self.type = "FUNC"
        self.binding = "GLOBAL"
        self.visibility = "DEFAULT"


def test_unmangled_symbols_keep_their_name():
    symbols, _ = parse_symbols(
        [
            FakeSymbol("__libc_start_main", ""),
            FakeSymbol("_ZN3Foo3barEv", "Foo::bar()"),
        ]
    )
    assert [s["name"] for s in symbols] == ["__libc_start_main", "Foo::bar()"]
    # The linkage name is kept only where demangling changed it.
    assert "raw_name" not in symbols[0]
    assert symbols[1]["raw_name"] == "_ZN3Foo3barEv"


def test_symbol_names_survive_parsing_on_a_real_binary():
    metadata = snapshot("x86_64-linux")
    imported = [s for s in metadata["dynamic_symbols"] if s.get("is_imported")]
    assert imported
    assert all(s["name"] for s in imported)
    assert "__libc_start_main" in {s["name"] for s in imported}


def test_analyze_elf_abi_on_empty_metadata():
    assert analyze_elf_abi({}) == {}


def test_normalize_library_candidate():
    assert _normalize_candidate("libvulkan.so.1") == ("libvulkan.so.1", "")
    assert _normalize_candidate("/usr/lib/libcuda.so") == ("libcuda.so", "/usr/lib/libcuda.so")
    assert _normalize_candidate("libfoo.dylib") == ("libfoo.dylib", "")
    # A format template is assembled at runtime and is not itself a name.
    assert _normalize_candidate("%s/libfoo.so") == ("", "")
    assert _normalize_candidate("failed to load libfoo.so") == ("", "")
    assert _normalize_candidate("") == ("", "")


def test_runtime_dependency_recovery_excludes_declared_names():
    metadata = {
        "dynamic_symbols": [{"name": "dlopen", "is_imported": True}],
        "dynamic_entries": [{"tag": "NEEDED", "name": "libc.so.6"}],
        "strings": [
            {"value": "libvulkan.so.1", "section": ".rodata"},
            # Already a static dependency, so not a gap in the dependency list.
            {"value": "libc.so.6", "section": ".rodata"},
        ],
    }
    recovered = recover_runtime_dependencies(metadata)
    assert [entry["name"] for entry in recovered] == ["libvulkan.so.1"]
    assert recovered[0]["confidence"] == "high"


def test_loader_and_self_references_are_not_dependencies():
    # Linkers and binary-manipulation libraries carry tables of loader names for
    # every target they support, and sanitizer runtimes name themselves. Neither
    # is a dlopen target.
    metadata = {
        "name": "/usr/lib/libasan.so.8.0.0",
        "dynamic_symbols": [{"name": "dlopen", "is_imported": True}],
        "dynamic_entries": [{"tag": "SONAME", "name": "libasan.so.8"}],
        "strings": [
            {"value": "ld64.so.1", "section": ".rodata"},
            {"value": "ld-linux-x86-64.so.2", "section": ".rodata"},
            {"value": "libasan.so", "section": ".rodata"},
            {"value": "libnuma.so.1", "section": ".rodata"},
        ],
    }
    assert [e["name"] for e in recover_runtime_dependencies(metadata)] == ["libnuma.so.1"]


def test_many_candidates_are_treated_as_a_name_table():
    # Five library names in one object is a lookup table of supported targets,
    # not five separate load sites, so none of them earns top confidence.
    metadata = {
        "dynamic_symbols": [{"name": "dlopen", "is_imported": True}],
        "strings": [
            {"value": f"libtarget{index}.so.1", "section": ".rodata"} for index in range(5)
        ],
    }
    recovered = recover_runtime_dependencies(metadata)
    assert len(recovered) == 5
    assert {entry["confidence"] for entry in recovered} == {"medium"}


def test_symbol_lookup_alone_is_not_library_loading():
    # dlsym operates on a handle the caller already has; on its own it does not
    # mean this binary loads anything.
    metadata = {
        "dynamic_symbols": [{"name": "dlsym", "is_imported": True}],
        "strings": [{"value": "libvulkan.so.1", "section": ".rodata"}],
    }
    assert recover_runtime_dependencies(metadata) == []
    assert summarize_runtime_loading(metadata)["loads_libraries"] is False


def test_runtime_loading_records_call_sites():
    metadata = {
        "dynamic_symbols": [{"name": "dlopen", "is_imported": True}],
        "disassembled_functions": {
            "0x1000::load_driver": {"name": "load_driver", "direct_calls": ["dlopen"]},
            "0x2000::main": {"name": "main", "direct_calls": ["load_driver"]},
        },
    }
    summary = summarize_runtime_loading(metadata)
    assert summary["call_sites"] == {"dlopen": ["load_driver"]}
    assert summary["loads_libraries"] is True


def test_loader_token_expansion():
    assert _expand_tokens("$ORIGIN/../lib", "/opt/app/bin", "lib64", "x86_64") == (
        "/opt/app/bin/../lib"
    )
    assert _expand_tokens("/usr/$LIB", "/x", "lib64", "x86_64") == "/usr/lib64"
    assert _expand_tokens("/usr/lib/$PLATFORM", "/x", "lib64", "x86_64") == "/usr/lib/x86_64"


def test_empty_search_path_entry_means_current_directory():
    # The loader reads an empty entry as the working directory, which is the
    # sharpest form of an untrusted search path.
    assert _split_paths("/a::/b") == ["/a", ".", "/b"]
    assert _classify_search_path(".") == "current-directory"
    assert _classify_search_path("/tmp/lib") == "world-writable"
    assert _classify_search_path("lib") == "relative"
    assert _classify_search_path("/usr/lib") == ""


@requires_binary_fixtures
def test_link_closure_reports_missing_and_unresolved(tmp_path):
    exe = elf_fixture("x86_64-linux")
    metadata = parse(exe)
    libdir = tmp_path / "lib" / "x86_64-linux-gnu"
    libdir.mkdir(parents=True)
    for soname in ("libgcc_s.so.1", "libm.so.6", "libc.so.6"):
        shutil.copy(exe, libdir / soname)

    closure = resolve_link_closure(metadata, exe, root=str(tmp_path))
    resolved = {entry["name"] for entry in closure["resolved"]}
    missing = {entry["name"] for entry in closure["missing"]}
    assert resolved == {"libgcc_s.so.1", "libm.so.6", "libc.so.6"}
    # Nothing on the search path supplies these, which is a load-time failure
    # the DT_NEEDED list alone cannot reveal.
    assert "libpthread.so.0" in missing
    assert closure["complete"] is False
    # The stand-in libraries export nothing, so every import stays unresolved.
    assert closure["unresolved_symbol_count"] > 0


def test_link_closure_is_empty_without_dependencies():
    assert resolve_link_closure({"dynamic_entries": []}, "/tmp/nothing") == {}


def test_abi_components_carry_the_derived_floor():
    abi = analyze_elf_abi(snapshot("x86_64-linux"))
    components = components_from_abi_requirements(abi)
    libc = next(c for c in components if c.name == "libc")
    assert str(libc.version.root) == "2.28"
    assert libc.group == "gnu"
    assert libc.purl == "pkg:generic/gnu/libc@2.28"
    property_names = {p.name for p in libc.properties}
    assert "internal:abi_determining_symbols" in property_names


def test_recovered_dependency_components_are_optional():
    components = components_from_recovered_dependencies(
        [{"name": "libvulkan.so.1", "confidence": "high", "evidence": ["imports dlopen"]}]
    )
    assert len(components) == 1
    assert components[0].name == "libvulkan"
    assert components[0].scope.value == "optional"
    assert {p.name for p in components[0].properties} >= {
        "internal:soname",
        "internal:load_kind",
    }


def test_abi_floor_check_compares_against_the_baseline():
    metadata = {"abi_analysis": {"min_glibc_version": "2.34"}}
    assert check_abi_floor("f", metadata, {"baseline_version": "2.34"}) is True
    assert check_abi_floor("f", metadata, {"baseline_version": "2.17"}) == (
        "requires glibc 2.34, baseline is 2.17"
    )
    # A binary with no derived floor cannot violate one.
    assert check_abi_floor("f", {}, {"baseline_version": "2.17"}) is True


def test_portability_and_loading_checks_name_their_evidence():
    metadata = {
        "abi_analysis": {"features": {"implementation_specific_imports": ["dl_iterate_phdr"]}},
        "recovered_dependencies": [{"name": "libcuda.so.1", "confidence": "high"}],
        "link_closure": {
            "risky_search_paths": [{"kind": "DT_RPATH", "path": ".", "issue": "current-directory"}]
        },
    }
    assert check_libc_portability("f", metadata, {}) == "dl_iterate_phdr"
    assert check_runtime_loading("f", metadata, {}) == "libcuda.so.1"
    assert "current-directory" in check_search_path("f", metadata, {})
    assert check_libc_portability("f", {}, {}) is True
    assert check_search_path("f", {}, {}) is True
