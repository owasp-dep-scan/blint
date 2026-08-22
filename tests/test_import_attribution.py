import copy
import json
import pathlib

from blint.lib.binary import analyze_import_deps, build_disassembly_callgraph_metadata
from blint.lib.checks import check_undeclared_dependencies, check_unused_dependencies
from blint.lib.import_attribution import (
    UNATTRIBUTED_LIBRARY,
    analyze_link_hygiene,
    attribute_call_target,
    build_symbol_provider_map,
    declared_libraries,
    is_library_name,
    normalize_call_target,
    symbol_lookup_names,
)

# Trimmed parsed metadata for a real binary. See tests/test_elf_abi.py for why
# these are snapshots rather than the binaries themselves.
METADATA_SNAPSHOTS = json.loads(
    (pathlib.Path(__file__).parent / "data" / "elf-abi-metadata.json").read_text()
)


def snapshot(target: str) -> dict:
    return copy.deepcopy(METADATA_SNAPSHOTS[target])


def elf_metadata(**overrides) -> dict:
    metadata = {
        "name": "/opt/app/bin/tool",
        "binary_type": "ELF",
        "dynamic_entries": [
            {"tag": "NEEDED", "name": "libc.so.6"},
            {"tag": "NEEDED", "name": "libz.so.1"},
        ],
        "dynamic_symbols": [
            {"name": "memcpy", "is_imported": True},
            {"name": "getenv", "is_imported": True},
        ],
    }
    metadata.update(overrides)
    return metadata


def test_elf_symbols_are_not_attributed_without_evidence():
    # ELF records imported symbols and needed libraries as two unrelated lists.
    # Picking one of the needed libraries invents a dependency edge, so with no
    # closure resolved every symbol has to stay unattributed.
    graph = analyze_import_deps(elf_metadata())
    assert graph["attribution_sources"] == []
    assert graph["unattributed_symbol_count"] == 2
    assert set(graph["libraries"]) == {"/opt/app/bin/tool", UNATTRIBUTED_LIBRARY}
    # Crucially, neither declared library was guessed at.
    assert "libz.so.1" not in graph["libraries"]
    assert "libc.so.6" not in graph["libraries"]


def test_elf_symbols_are_attributed_from_the_resolved_closure():
    metadata = elf_metadata(
        link_closure={"symbol_providers": {"memcpy": "libc.so.6", "getenv": "libc.so.6"}}
    )
    graph = analyze_import_deps(metadata)
    assert graph["attribution_sources"] == ["link_closure"]
    assert graph["unattributed_symbol_count"] == 0
    edge = next(dep for dep in graph["dependencies"] if dep["to"] == "libc.so.6")
    assert sorted(edge["symbols"]) == ["getenv", "memcpy"]


def test_real_elf_binary_attributes_nothing_without_a_closure():
    # Regression guard for the arbitrary attribution this replaced, which put
    # all 122 imports of this binary under whichever needed library the set
    # happened to yield first -- libgcc_s.so.1, including memcpy and
    # __libc_start_main, while libc.so.6 was absent from the graph entirely.
    metadata = snapshot("x86_64-linux")
    graph = analyze_import_deps(metadata)
    assert graph["unattributed_symbol_count"] == 122
    assert "libgcc_s.so.1" not in graph["libraries"]
    assert set(graph["libraries"]) == {metadata["name"], UNATTRIBUTED_LIBRARY}


def test_real_elf_binary_attributes_every_import_with_a_closure():
    # The same binary, once the closure supplies the missing evidence.
    metadata = snapshot("x86_64-linux")
    metadata["link_closure"] = {
        "symbol_providers": {entry["name"]: "libc.so.6" for entry in metadata["dynamic_symbols"]}
    }
    graph = analyze_import_deps(metadata)
    assert graph["attribution_sources"] == ["link_closure"]
    assert graph["unattributed_symbol_count"] == 0
    assert "libc.so.6" in graph["libraries"]


def test_cpp_namespaces_are_not_read_as_libraries():
    # `::` separates namespace components in C++ and Rust. Reading it as a
    # library prefix turns a namespaced method into a dependency on `APT`.
    metadata = elf_metadata(
        dynamic_symbols=[
            {
                "name": "APT::PackageContainer::begin()",
                "raw_name": "_ZN3APT16PackageContainer5beginEv",
                "is_imported": True,
            }
        ]
    )
    graph = analyze_import_deps(metadata)
    assert "APT" not in graph["libraries"]
    assert graph["unattributed_symbol_count"] == 1


def test_cpp_symbols_are_matched_on_their_linkage_name():
    # A provider's export table holds mangled names, so the demangled name alone
    # never matches and every C++ import would come through unattributed.
    metadata = elf_metadata(
        dynamic_entries=[{"tag": "NEEDED", "name": "libapt-pkg.so.7.0"}],
        dynamic_symbols=[
            {
                "name": "APT::PackageContainer::begin()",
                "raw_name": "_ZN3APT16PackageContainer5beginEv",
                "is_imported": True,
            }
        ],
        link_closure={
            "symbol_providers": {"_ZN3APT16PackageContainer5beginEv": "libapt-pkg.so.7.0"}
        },
    )
    graph = analyze_import_deps(metadata)
    assert graph["unattributed_symbol_count"] == 0
    assert "libapt-pkg.so.7.0" in graph["libraries"]


def test_macho_library_prefix_is_used_when_it_names_a_library():
    metadata = {
        "name": "/App.app/App",
        "binary_type": "MachO",
        "libraries": [{"name": "/usr/lib/libSystem.B.dylib"}],
        "symtab_symbols": [
            {"name": "/usr/lib/libSystem.B.dylib::printf", "is_imported": True},
            # Rust path syntax uses the same separator and must not be read as
            # a library named `wasm_tools`.
            {"name": "wasm_tools::wit_dylib::Opts::run", "is_imported": True},
        ],
    }
    graph = analyze_import_deps(metadata)
    assert "libSystem.B.dylib" in graph["libraries"]
    assert "wasm_tools" not in graph["libraries"]


def test_pe_imports_attribute_without_a_closure():
    # PE names every import as `library::function`, so attribution is free.
    metadata = {
        "name": "app.exe",
        "binary_type": "PE",
        "imports": [{"name": "KERNEL32.dll::CreateFileW"}],
    }
    providers, sources = build_symbol_provider_map(metadata)
    assert sources == ["import_table"]
    assert providers["CreateFileW"] == "KERNEL32.dll"


def test_is_library_name():
    assert is_library_name("/usr/lib/libSystem.B.dylib")
    assert is_library_name("libz.so.1")
    assert is_library_name("KERNEL32.dll")
    assert not is_library_name("wasm_tools")
    assert not is_library_name("APT")
    assert not is_library_name("")


def test_symbol_lookup_names_prefers_the_linkage_name():
    assert symbol_lookup_names({"raw_name": "_ZN3Foo3barEv", "name": "Foo::bar()"}) == [
        "_ZN3Foo3barEv",
        "Foo::bar()",
    ]
    assert symbol_lookup_names({"name": "memcpy"}) == ["memcpy"]
    assert symbol_lookup_names({}) == []


def test_normalize_call_target_strips_linkage_decoration():
    # A call routed through the procedure linkage table or a Windows import
    # thunk names the same symbol as the plain reference.
    assert normalize_call_target("memcpy@plt") == "memcpy"
    assert normalize_call_target("__imp_CreateFileW") == "CreateFileW"
    assert normalize_call_target("memcpy@GLIBC_2.14") == "memcpy"
    assert normalize_call_target("/usr/lib/libSystem.B.dylib::printf") == "printf"
    # A namespaced name is left intact; truncating it could match the wrong
    # symbol entirely.
    assert normalize_call_target("APT::Container::begin") == "APT::Container::begin"
    assert normalize_call_target("") == ""


def test_attribute_call_target():
    providers = {"memcpy": "libc.so.6"}
    assert attribute_call_target("memcpy", providers) == "libc.so.6"
    assert attribute_call_target("memcpy@plt", providers) == "libc.so.6"
    assert attribute_call_target("unknown_symbol", providers) == ""
    assert attribute_call_target("memcpy", {}) == ""
    # A Mach-O target carries its own dylib and needs no map.
    assert (
        attribute_call_target("/usr/lib/libSystem.B.dylib::printf", {}, is_macho=True)
        == "libSystem.B.dylib"
    )


def test_callgraph_external_edges_name_their_library():
    # The mechanism: an external edge whose recovered symbol name is a known
    # import is labelled with the library it lands in.
    metadata = {
        "name": "app",
        "binary_type": "PE",
        "imports": [{"name": "KERNEL32.dll::CreateFileW"}],
        "functions": [{"name": "main", "address": "0x1000"}],
        "disassembled_functions": {
            "0x1000::main": {
                "name": "main",
                "address": "0x1000",
                "direct_calls": ["CreateFileW"],
            }
        },
    }
    callgraph = build_disassembly_callgraph_metadata(metadata)
    external = [entry for entry in callgraph["external"] if entry.get("library")]
    assert external, callgraph["external"]
    assert external[0]["library"] == "KERNEL32.dll"
    # The target is still unresolved as an internal edge, but the library it
    # reaches is evidence rather than a guess.
    assert external[0]["confidence"] == "medium"
    assert callgraph["attributed_external_count"] == 1
    assert callgraph["external_attribution_sources"] == ["import_table"]


def test_declared_libraries_per_format():
    assert declared_libraries(elf_metadata()) == ["libc.so.6", "libz.so.1"]
    assert declared_libraries(
        {"binary_type": "MachO", "libraries": [{"name": "/usr/lib/libSystem.B.dylib"}]}
    ) == ["libSystem.B.dylib"]
    assert declared_libraries(
        {"binary_type": "PE", "imports": [{"name": "KERNEL32.dll::CreateFileW"}]}
    ) == ["KERNEL32.dll"]


def test_unused_dependency_is_reported():
    # libz is declared but nothing is imported from it, which is what
    # `--as-needed` would have removed at link time.
    metadata = elf_metadata(
        link_closure={"symbol_providers": {"memcpy": "libc.so.6", "getenv": "libc.so.6"}}
    )
    graph = analyze_import_deps(metadata)
    hygiene = analyze_link_hygiene(metadata, graph)
    assert [entry["name"] for entry in hygiene["unused_dependencies"]] == ["libz.so.1"]
    assert hygiene["undeclared_dependencies"] == []


def test_undeclared_dependency_is_reported():
    # libtinfo supplies a symbol but is reached only through another library's
    # dependency list, which is not a contract.
    metadata = elf_metadata(
        dynamic_entries=[{"tag": "NEEDED", "name": "libncurses.so.6"}],
        dynamic_symbols=[
            {"name": "initscr", "is_imported": True},
            {"name": "tigetnum", "is_imported": True},
        ],
        link_closure={
            "symbol_providers": {"initscr": "libncurses.so.6", "tigetnum": "libtinfo.so.6"}
        },
    )
    graph = analyze_import_deps(metadata)
    hygiene = analyze_link_hygiene(metadata, graph)
    assert [entry["name"] for entry in hygiene["undeclared_dependencies"]] == ["libtinfo.so.6"]
    assert hygiene["unused_dependencies"] == []


def test_startup_glue_still_counts_as_using_a_library():
    # A shared library that imports only `__cxa_finalize` genuinely depends on
    # libc for it. Discounting startup symbols reports that as unused.
    metadata = elf_metadata(
        dynamic_entries=[{"tag": "NEEDED", "name": "libc.so.6"}],
        dynamic_symbols=[{"name": "__cxa_finalize", "is_imported": True}],
        link_closure={"symbol_providers": {"__cxa_finalize": "libc.so.6"}},
    )
    hygiene = analyze_link_hygiene(metadata, analyze_import_deps(metadata))
    assert hygiene["unused_dependencies"] == []


def test_hygiene_is_withheld_without_attribution_evidence():
    # With nothing attributed every dependency looks unused, so reporting at all
    # would be worse than staying silent.
    assert analyze_link_hygiene(elf_metadata(), analyze_import_deps(elf_metadata())) == {}


def test_hygiene_checks_report_their_evidence():
    metadata = {
        "link_hygiene": {
            "unused_dependencies": [{"name": "libz.so.1", "reason": "no symbols imported"}],
            "undeclared_dependencies": [{"name": "libtinfo.so.6", "symbol_count": 2}],
        }
    }
    assert check_unused_dependencies("f", metadata, {}) == "libz.so.1"
    assert check_undeclared_dependencies("f", metadata, {}) == "libtinfo.so.6"
    assert check_unused_dependencies("f", {}, {}) is True
    assert check_undeclared_dependencies("f", {}, {}) is True
