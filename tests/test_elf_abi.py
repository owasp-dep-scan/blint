import copy
import json
import os
import pathlib
import shutil

import pytest

from blint.lib.analysis import run_checks
from blint.lib.binary import parse, parse_symbols
from blint.lib.checks import (
    check_abi_floor,
    check_libc_portability,
    check_runtime_loading,
    check_search_path,
    check_virtual_size,
)
from blint.lib.elf_abi import (
    analyze_elf_abi,
    compute_abi_requirements,
    parse_version_node,
    version_sort_key,
)
from blint.lib.elf_dlopen import (
    _normalize_candidate,
    imported_loader_entry_points,
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


def test_abi_requirements_property_carries_the_derived_floor():
    """F2a.4: the floor is a property on the binary, not a component.

    The interface version an ABI node names is a requirement on the
    execution environment, so asserting it as a pkg:generic component
    (name@version) would publish an identity no artifact has.
    """
    from blint.lib.sbom import format_abi_requirements

    abi = analyze_elf_abi(snapshot("x86_64-linux"))
    line = format_abi_requirements(abi)
    assert "GLIBC>=2.28" in line
    # The imports that set the floor ride along so a reader can verify.
    assert "set by" in line


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


def test_abi_floor_check_compares_against_the_baseline(monkeypatch):
    monkeypatch.delenv("BLINT_GLIBC_BASELINE", raising=False)
    rule = {"baseline_version": "2.28"}
    # A floor at or below the baseline is not a finding, whoever set it.
    assert (
        check_abi_floor(
            "f", {"abi_analysis": {"min_glibc_version": "2.28", "libc": "glibc"}}, rule
        )
        is True
    )
    assert (
        check_abi_floor(
            "f", {"abi_analysis": {"min_glibc_version": "2.17", "libc": "glibc"}}, rule
        )
        is True
    )
    # A binary with no derived floor cannot violate one.
    assert check_abi_floor("f", {}, rule) is True


def test_abi_floor_default_baseline_reports_info_and_names_the_provider(monkeypatch):
    monkeypatch.delenv("BLINT_GLIBC_BASELINE", raising=False)
    result = check_abi_floor(
        "f", {"abi_analysis": {"min_glibc_version": "2.34", "libc": "glibc"}},
        {"baseline_version": "2.28"},
    )
    # A floor above a default nobody chose is a note, not a policy finding,
    # and the finding says both the provider and which baseline was used.
    assert result["severity"] == "info"
    assert result["evidence"].startswith("GLIBC floor 2.34")
    assert "built-in default baseline 2.28" in result["evidence"]
    assert "BLINT_GLIBC_BASELINE" in result["evidence"]


def test_abi_floor_user_baseline_keeps_medium_and_names_the_env(monkeypatch):
    metadata = {"abi_analysis": {"min_glibc_version": "2.34", "libc": "glibc"}}
    rule = {"baseline_version": "2.28"}
    monkeypatch.setenv("BLINT_GLIBC_BASELINE", "2.17")
    result = check_abi_floor("f", metadata, rule)
    # A floor above a baseline somebody chose is a deployment error.
    assert result["severity"] == "medium"
    assert "GLIBC floor 2.34" in result["evidence"]
    assert "configured baseline 2.17" in result["evidence"]
    assert "BLINT_GLIBC_BASELINE" in result["evidence"]
    # The user baseline is compared, not the YAML default: equal and below
    # never fire.
    at_baseline = {"abi_analysis": {"min_glibc_version": "2.17", "libc": "glibc"}}
    assert check_abi_floor("f", at_baseline, rule) is True
    monkeypatch.setenv("BLINT_GLIBC_BASELINE", "2.41")
    assert check_abi_floor("f", metadata, rule) is True
    monkeypatch.setenv("BLINT_GLIBC_BASELINE", "2.34")
    assert check_abi_floor("f", metadata, rule) is True


def test_abi_floor_never_fires_on_musl_or_bionic(monkeypatch):
    # Ground rule 35: a glibc baseline is meaningless against a binary that
    # carries no GLIBC version nodes, so even a synthetic floor on a musl or
    # bionic binary must not fire.
    monkeypatch.setenv("BLINT_GLIBC_BASELINE", "2.17")
    for libc in ("musl", "bionic"):
        metadata = {"abi_analysis": {"min_glibc_version": "2.34", "libc": libc}}
        assert check_abi_floor("f", metadata, {"baseline_version": "2.28"}) is True
    # The committed musl snapshot is the real shape: musl, no GLIBC floor.
    monkeypatch.delenv("BLINT_GLIBC_BASELINE", raising=False)
    assert check_abi_floor("f", snapshot("x86_64-musl"), {"baseline_version": "2.28"}) is True


def test_abi_floor_ignores_non_glibc_providers(monkeypatch):
    # A glibc baseline says nothing about a GLIBCXX floor: the C++ floor is
    # recorded in abi_analysis.requirements but never compared here.
    monkeypatch.delenv("BLINT_GLIBC_BASELINE", raising=False)
    metadata = {
        "abi_analysis": {
            "libc": "glibc",
            "min_glibc_version": "",
            "requirements": [{"provider": "GLIBCXX", "min_version": "3.4.30"}],
        }
    }
    assert check_abi_floor("f", metadata, {"baseline_version": "2.28"}) is True


def test_abi_floor_severity_flows_into_the_finding(monkeypatch):
    # run_rule honours the check's per-finding severity override, and the
    # override must not leak into the shared rule object.
    from blint.lib.analysis import rules_dict, run_rule

    rule = rules_dict["CHECK_ABI_FLOOR"]
    metadata = {"abi_analysis": {"min_glibc_version": "2.34", "libc": "glibc"}}
    monkeypatch.delenv("BLINT_GLIBC_BASELINE", raising=False)
    default_finding = run_rule("demo", metadata, rule, "genericbinary", "CHECK_ABI_FLOOR")
    assert default_finding["severity"] == "info"
    assert "GLIBC floor 2.34" in default_finding["title"]
    monkeypatch.setenv("BLINT_GLIBC_BASELINE", "2.17")
    user_finding = run_rule("demo", metadata, rule, "genericbinary", "CHECK_ABI_FLOOR")
    assert user_finding["severity"] == "medium"
    assert rules_dict["CHECK_ABI_FLOOR"]["severity"] == "medium"


def test_abi_floor_on_a_real_glibc_elf(monkeypatch):
    # plain-libc-demo.elf binds GLIBC_2.34 symbols (floor verified with
    # readelf --dyn-syms), so one real binary spans all three outcomes.
    metadata = parse(
        os.path.join(os.path.dirname(__file__), "data", "plain-libc-demo.elf")
    )
    assert metadata["abi_analysis"]["min_glibc_version"] == "2.34"
    monkeypatch.delenv("BLINT_GLIBC_BASELINE", raising=False)
    (default_finding,) = [
        f for f in run_checks("plain-libc-demo.elf", metadata) if f["id"] == "CHECK_ABI_FLOOR"
    ]
    assert default_finding["severity"] == "info"
    monkeypatch.setenv("BLINT_GLIBC_BASELINE", "2.17")
    (user_finding,) = [
        f for f in run_checks("plain-libc-demo.elf", metadata) if f["id"] == "CHECK_ABI_FLOOR"
    ]
    assert user_finding["severity"] == "medium"
    monkeypatch.setenv("BLINT_GLIBC_BASELINE", "2.34")
    assert not [
        f for f in run_checks("plain-libc-demo.elf", metadata) if f["id"] == "CHECK_ABI_FLOOR"
    ]


def test_portability_and_loading_checks_name_their_evidence():
    metadata = {
        "abi_analysis": {
            "libc": "glibc",
            "features": {
                "implementation_specific_imports": ["backtrace", "dl_iterate_phdr"],
                "glibc_specific_imports": ["backtrace"],
                "shared_libc_imports": ["dl_iterate_phdr"],
            },
        },
        "dynamic_symbols": [{"name": "dlopen", "is_imported": True}],
        "recovered_dependencies": [{"name": "libcuda.so.1", "confidence": "high"}],
        "link_closure": {
            "risky_search_paths": [{"kind": "DT_RPATH", "path": ".", "issue": "current-directory"}]
        },
    }
    result = check_libc_portability("f", metadata, {})
    assert result.startswith("glibc-specific")
    assert "backtrace" in result
    # dl_iterate_phdr is exported by both measured libcs, so it is not a
    # portability block and must not be listed.
    assert "dl_iterate_phdr" not in result
    loading = check_runtime_loading("f", metadata, {})
    assert "libcuda.so.1" in loading and "not observed loads" in loading
    assert "current-directory" in check_search_path("f", metadata, {})
    assert check_libc_portability("f", {}, {}) is True
    assert check_search_path("f", {}, {}) is True


def test_libc_portability_classification_from_measured_symbol_lists():
    # The per-symbol availability table must classify exactly the interfaces
    # the measured glibc 2.41 / musl 1.2.6 symbol lists say it does (see
    # INTERFACE_LIBC_AVAILABILITY's provenance comment for the measurement).
    from blint.lib.elf_abi import INTERFACE_LIBC_AVAILABILITY as table

    assert table["backtrace"] == "glibc"
    assert table["__freadahead"] == "musl"
    assert table["dl_iterate_phdr"] == "both"
    assert table["pthread_getattr_np"] == "both"
    assert table["__libc_start_main"] == "both"
    assert table["__register_frame_info"] == "neither"


def test_libc_portability_fires_only_on_the_libc_specific_subset():
    def features(**buckets):
        merged = {
            "implementation_specific_imports": sorted(
                name for names in buckets.values() for name in names
            )
        }
        merged.update(buckets)
        return merged

    glibc_binary = {
        "abi_analysis": {
            "libc": "glibc",
            "features": features(
                glibc_specific_imports=["_obstack_begin", "backtrace"],
                shared_libc_imports=["__ctype_b_loc", "__libc_start_main", "dl_iterate_phdr"],
            ),
        }
    }
    result = check_libc_portability("f", glibc_binary, {})
    assert result.startswith("glibc-specific")
    assert "_obstack_begin" in result and "backtrace" in result
    assert "__libc_start_main" not in result and "__ctype_b_loc" not in result

    # A glibc binary binding only shared interfaces is portable between the
    # two measured libcs: no finding.
    shared_only = {
        "abi_analysis": {
            "libc": "glibc",
            "features": features(shared_libc_imports=["__libc_start_main", "dladdr"]),
        }
    }
    assert check_libc_portability("f", shared_only, {}) is True

    # The F0 defect case: a musl binary importing dl_iterate_phdr and
    # pthread_getattr_np - musl's own interface - was called glibc-bound.
    musl_shared_only = {
        "abi_analysis": {
            "libc": "musl",
            "features": features(
                shared_libc_imports=[
                    "__libc_start_main",
                    "dl_iterate_phdr",
                    "pthread_getattr_np",
                    "pthread_setname_np",
                ]
            ),
        }
    }
    assert check_libc_portability("f", musl_shared_only, {}) is True

    # A musl binary binding musl's own extra interface is a finding, and the
    # evidence names musl - never glibc.
    musl_specific = {
        "abi_analysis": {
            "libc": "musl",
            "features": features(musl_specific_imports=["__freadahead"]),
        }
    }
    musl_result = check_libc_portability("f", musl_specific, {})
    assert musl_result.startswith("musl-specific")
    assert "__freadahead" in musl_result
    assert "glibc-specific" not in musl_result

    # No libc identified: each binding is named with its own provider rather
    # than guessed.
    unknown = {
        "abi_analysis": {
            "libc": "",
            "features": features(
                glibc_specific_imports=["backtrace"],
                musl_specific_imports=["__freadahead"],
            ),
        }
    }
    unknown_result = check_libc_portability("f", unknown, {})
    assert "glibc-specific: backtrace" in unknown_result
    assert "musl-specific: __freadahead" in unknown_result


def test_libc_portability_ignores_non_libc_runtime_interfaces():
    # __register_frame_info and friends are exported by libgcc_s, not by
    # either libc: recording them as C library internals was a misattribution
    # the measurement exposed, and the rule must not report them.
    metadata = {
        "abi_analysis": {
            "libc": "glibc",
            "features": {
                "implementation_specific_imports": ["__register_frame_info"],
                "non_libc_runtime_imports": ["__register_frame_info"],
            },
        }
    }
    assert check_libc_portability("f", metadata, {}) is True


def test_libc_portability_on_real_binaries():
    # Committed snapshots of one Rust project built for glibc and musl.
    glibc_abi = analyze_elf_abi(snapshot("x86_64-linux"))
    result = check_libc_portability("f", {"abi_analysis": glibc_abi}, {})
    assert result.startswith("glibc-specific")
    assert "__cxa_thread_atexit_impl" in result
    assert "gnu_get_libc_version" in result
    assert "dl_iterate_phdr" not in result

    musl_abi = analyze_elf_abi(snapshot("x86_64-musl"))
    # The musl build binds only interfaces both libcs export, so the rule
    # that F0 measured firing here 4 times is now silent on it.
    assert check_libc_portability("f", {"abi_analysis": musl_abi}, {}) is True

    # A real committed glibc ELF whose only non-standard import is
    # __libc_start_main (shared) also stays silent.
    real = parse(
        os.path.join(os.path.dirname(__file__), "data", "plain-libc-demo.elf")
    )
    assert check_libc_portability("f", real, {}) is True


class TestVirtualSizePerFormatLimit:
    """F1b.3: the 30MB cap came from PE practice; ELF gets its own, from the
    measured benign distribution. Both sides of every limit, plus the Mach-O
    and rule-without-format_limits shapes."""

    RULE = {"limit": "30MB", "format_limits": {"ELF": "128MB"}}

    def test_elf_limit_is_128mb_on_both_sides(self):
        below = {"binary_type": "ELF", "virtual_size": 128 * 1024 * 1024 - 1}
        at_limit = {"binary_type": "ELF", "virtual_size": 128 * 1024 * 1024}
        # A stock static Go net/http build maps 37.4 MB - the exact tier-0
        # file that the PE-derived 30MB limit fired on - and must pass now.
        benign_go = {"binary_type": "ELF", "virtual_size": int(37.4 * 1024 * 1024)}
        assert check_virtual_size("f", benign_go, self.RULE) is True
        assert check_virtual_size("f", below, self.RULE) is True
        assert check_virtual_size("f", at_limit, self.RULE) is False

    def test_pe_keeps_the_30mb_limit(self):
        below = {"binary_type": "PE", "virtual_size": 30 * 1024 * 1024 - 1}
        at_limit = {"binary_type": "PE", "virtual_size": 30 * 1024 * 1024}
        benign_max = {"binary_type": "PE", "virtual_size": int(6.5 * 1024 * 1024)}
        assert check_virtual_size("f", benign_max, self.RULE) is True
        assert check_virtual_size("f", below, self.RULE) is True
        assert check_virtual_size("f", at_limit, self.RULE) is False

    def test_unknown_format_falls_back_to_the_default_limit(self):
        other = {"binary_type": "WASM", "virtual_size": 31 * 1024 * 1024}
        assert check_virtual_size("f", other, self.RULE) is False
        no_type = {"virtual_size": 31 * 1024 * 1024}
        assert check_virtual_size("f", no_type, self.RULE) is False

    def test_rule_without_format_limits_keeps_the_single_limit(self):
        legacy = {"limit": "30MB"}
        elf_40mb = {"binary_type": "ELF", "virtual_size": 40 * 1024 * 1024}
        assert check_virtual_size("f", elf_40mb, legacy) is False

    def test_no_virtual_size_never_fires(self):
        # Mach-O metadata carries no virtual_size at all, so the check is
        # data-gated off there regardless of limits.
        assert check_virtual_size("f", {"binary_type": "MachO"}, self.RULE) is True

    def test_real_elf_fixture_passes(self):
        metadata = parse(
            os.path.join(os.path.dirname(__file__), "data", "plain-libc-demo.elf")
        )
        assert metadata["binary_type"] == "ELF"
        assert check_virtual_size("f", metadata, self.RULE) is True


class TestRuntimeLoadingStatesItsEvidence:
    """F1b.4: the finding's evidence is a string paired with imported loader
    entry points, and a binary that cannot open a library by name is never
    reported as loading one."""

    def test_name_with_loader_import_fires_naming_both(self):
        metadata = {
            "dynamic_symbols": [{"name": "dlopen", "is_imported": True}],
            "recovered_dependencies": [
                {"name": "libstdbuf.so", "confidence": "high"},
                {"name": "libfoo.so", "confidence": "low"},
            ],
        }
        result = check_runtime_loading("f", metadata, {})
        # The low-confidence candidate stays out; the evidence names the
        # string, the loader entry point, and its own nature.
        assert "libstdbuf.so" in result
        assert "libfoo.so" not in result
        assert "library-name strings" in result
        assert "dlopen" in result
        assert "not observed loads" in result

    def test_name_without_loader_import_is_suppressed(self):
        # However the names got into the metadata (a stale parse, another
        # producer), no imported loader entry point means the binary cannot
        # open a library by name: suppress rather than lower, because the
        # rule's title would be false at any severity.
        metadata = {
            "recovered_dependencies": [{"name": "libfoo.so", "confidence": "high"}],
            "dynamic_symbols": [{"name": "printf", "is_imported": True}],
        }
        assert check_runtime_loading("f", metadata, {}) is True

    def test_no_names_at_all_never_fires(self):
        metadata = {
            "dynamic_symbols": [{"name": "dlopen", "is_imported": True}],
            "recovered_dependencies": [],
        }
        assert check_runtime_loading("f", metadata, {}) is True
        assert check_runtime_loading("f", {}, {}) is True

    def test_real_elf_without_runtime_loading_stays_silent(self):
        metadata = parse(
            os.path.join(os.path.dirname(__file__), "data", "plain-libc-demo.elf")
        )
        assert check_runtime_loading("f", metadata, {}) is True

    def test_loader_defining_dlopen_is_not_a_loader_client(self):
        # The ld-musl shape that fired on tier-0: the dynamic loader defines
        # dlopen/dlsym (is_imported False) and carries libc.so as data.
        # Defining the entry point is the loader's job, not evidence it calls
        # one, so nothing is recovered and the rule cannot fire.
        loader_shape = {
            "dynamic_symbols": [
                {"name": "dlopen", "is_imported": False},
                {"name": "dlsym", "is_imported": False},
            ],
            "strings": [{"value": "libc.so", "section": ".rodata"}],
        }
        assert imported_loader_entry_points(loader_shape) == set()
        assert recover_runtime_dependencies(loader_shape) == []

    def test_importing_dlopen_with_a_string_recovers(self):
        client_shape = {
            "dynamic_symbols": [{"name": "dlopen", "is_imported": True}],
            "strings": [{"value": "libstdbuf.so", "section": ".rodata"}],
        }
        assert imported_loader_entry_points(client_shape) == {"dlopen"}
        recovered = recover_runtime_dependencies(client_shape)
        assert [entry["name"] for entry in recovered] == ["libstdbuf.so"]
