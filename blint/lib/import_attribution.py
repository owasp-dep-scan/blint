"""Attribution of imported symbols to the libraries that supply them.

Knowing *that* a binary imports `memcpy` is much less useful than knowing which
library answers the call. PE records the answer directly, because its import
table is organised by DLL. ELF does not: the dynamic symbol table is a flat list
and the `DT_NEEDED` list is a separate flat list, with nothing connecting the
two. The connection only exists once the dependency closure has been resolved and
each library's exports are known.

This module centralises that lookup so the import graph, the callgraph's external
edges, and the link hygiene findings all attribute symbols the same way and
degrade the same way. Where no evidence exists, a symbol is reported as
unattributed rather than guessed at -- a wrong library is worse than an honest
gap, because it silently reassigns a dependency edge that downstream tools treat
as fact.
"""

from blint.logger import LOG

# Symbols that no evidence can tie to a library are collected here rather than
# dropped, so that the count of unexplained imports stays visible.
UNATTRIBUTED_LIBRARY = "unattributed"

# Symbols the linker resolves without any library providing them. Only these are
# discounted when judging whether a dependency is used.
#
# It is tempting to also discount startup glue such as `__libc_start_main` and
# `__cxa_finalize` on the grounds that every binary imports them. That is a
# mistake: they are ordinary symbols that libc really does supply, and a shared
# library importing only `__cxa_finalize` genuinely depends on libc for its
# destructor registration. Discounting them reports that dependency as unused.
UNPROVIDED_SYMBOLS = frozenset(
    {
        "__gmon_start__",
        "_ITM_registerTMCloneTable",
        "_ITM_deregisterTMCloneTable",
    }
)


def is_library_name(value: str) -> bool:
    """Return True when a string names a shared library rather than a namespace.

    Mach-O prefixes an imported symbol with the dylib that supplies it, using the
    same ``::`` separator that Rust and C++ use between namespace components. A
    Rust symbol such as ``wasm_tools::wit_dylib::Opts::run`` is otherwise
    indistinguishable from a library prefix, and reading it as one invents a
    dependency on a library called ``wasm_tools``.
    """
    return bool(value) and (
        "/" in value or value.endswith(".dylib") or ".so" in value or value.endswith(".dll")
    )


def build_symbol_provider_map(metadata: dict) -> tuple[dict[str, str], list[str]]:
    """Map each imported symbol to the library that supplies it.

    Args:
        metadata: Parsed binary metadata.

    Returns:
        tuple[dict[str, str], list[str]]: The symbol-to-library map, and the
        evidence sources it was built from. An empty map with no sources means
        the format offers no attribution evidence and none was resolved, which
        callers must treat as "unknown" rather than as "no dependencies".
    """
    providers: dict[str, str] = {}
    sources: list[str] = []

    # PE names every import as `library::function`, so attribution is free and
    # always available.
    pe_pairs = 0
    for entry in metadata.get("imports") or []:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name") or ""
        if "::" in name:
            library, _, symbol = name.partition("::")
            if library and symbol:
                providers.setdefault(symbol, library)
                pe_pairs += 1
    if pe_pairs:
        sources.append("import_table")

    # Mach-O binds each symbol to a dylib path, which the symbol parser records
    # in the same `library::symbol` form. This is only read for Mach-O: in every
    # other format `::` in a symbol name is a C++ namespace separator, and
    # reading it as a library turns `APT::PackageContainer::begin` into a
    # dependency on a library called `APT`.
    macho_pairs = 0
    if metadata.get("binary_type") == "MachO":
        for bucket in ("symtab_symbols", "dynamic_symbols"):
            for entry in metadata.get(bucket) or []:
                if not isinstance(entry, dict):
                    continue
                # The dylib path is the prefix, so the split is on the first
                # separator; anything after it may itself contain `::`, as Rust
                # and C++ names routinely do.
                library, separator, symbol = (entry.get("name") or "").partition("::")
                if not separator or not symbol or not is_library_name(library):
                    continue
                providers.setdefault(symbol, library.rsplit("/", 1)[-1])
                macho_pairs += 1
    if macho_pairs and "import_table" not in sources:
        sources.append("load_commands")

    # ELF only knows which library supplies a symbol once the closure has been
    # resolved against a filesystem and each library's exports read.
    closure_providers = (metadata.get("link_closure") or {}).get("symbol_providers") or {}
    if closure_providers:
        for symbol, library in closure_providers.items():
            providers.setdefault(symbol, library)
        sources.append("link_closure")

    if providers:
        LOG.debug(
            "Attributed %d imported symbols to libraries via %s",
            len(providers),
            ", ".join(sources),
        )
    return providers, sources


def symbol_lookup_names(entry: dict) -> list[str]:
    """Return the names a symbol may be known by, most specific first.

    A provider's export table holds linkage names, so a C++ symbol only matches
    on its mangled form. blint records the demangled name for readability and
    keeps the linkage name alongside it whenever the two differ.
    """
    names = []
    for key in ("raw_name", "name"):
        value = entry.get(key)
        if value and value not in names:
            names.append(value)
    return names


def normalize_call_target(target: str) -> str:
    """Reduce a call target as it appears in disassembly to a bare symbol name.

    Call targets carry linkage decoration that the symbol tables do not: a call
    routed through the procedure linkage table reads as ``memcpy@plt``, and the
    Windows import thunk reads as ``__imp_memcpy``. Both name the same symbol.
    """
    target = (target or "").strip()
    if not target:
        return ""
    # A Mach-O target is prefixed with its dylib path, so the symbol is
    # everything after the first separator. The prefix has to look like a
    # library, or a namespaced C++ name would be truncated into something that
    # could match the wrong symbol.
    prefix, separator, remainder = target.partition("::")
    if separator and ("/" in prefix or ".so" in prefix or prefix.endswith(".dylib")):
        target = remainder
    for suffix in ("@plt", "@PLT", "@got", "@GOT", "@gotpcrel", "@GOTPCREL"):
        if target.endswith(suffix):
            target = target[: -len(suffix)]
    for prefix in ("__imp_", "_imp_", "j_"):
        if target.startswith(prefix):
            target = target[len(prefix) :]
    # A versioned reference names the same symbol as its unversioned form.
    return target.partition("@")[0].strip()


def attribute_call_target(
    target: str, provider_map: dict[str, str], *, is_macho: bool = False
) -> str:
    """Return the library supplying a call target, or an empty string.

    Args:
        target: The call target as recorded on an external callgraph edge.
        provider_map: The map returned by :func:`build_symbol_provider_map`.
        is_macho: Whether ``::`` in the target separates a dylib path from a
            symbol. In every other format it is a C++ namespace separator.
    """
    if not target:
        return ""
    # A Mach-O target already names its dylib, so no lookup is needed.
    if is_macho and "::" in target:
        return target.partition("::")[0].rsplit("/", 1)[-1]
    if not provider_map:
        return ""
    if library := provider_map.get(target):
        return library
    normalized = normalize_call_target(target)
    return provider_map.get(normalized, "") if normalized != target else ""


def declared_libraries(metadata: dict) -> list[str]:
    """Return the libraries the binary declares a direct dependency on."""
    declared: list[str] = []
    seen = set()

    def add(name: str):
        name = (name or "").rsplit("/", 1)[-1]
        if name and name not in seen:
            seen.add(name)
            declared.append(name)

    if metadata.get("binary_type") == "MachO":
        for entry in metadata.get("libraries") or []:
            if isinstance(entry, dict):
                add(entry.get("name", ""))
        return declared
    for entry in metadata.get("dynamic_entries") or []:
        if isinstance(entry, dict) and entry.get("tag") == "NEEDED":
            add(entry.get("name", ""))
    if declared:
        return declared
    # PE has no DT_NEEDED; the set of libraries named in the import table is the
    # equivalent declaration.
    for entry in metadata.get("imports") or []:
        if isinstance(entry, dict) and "::" in (entry.get("name") or ""):
            add(entry["name"].partition("::")[0])
    return declared


def _meaningful_symbols(symbols: list) -> list[str]:
    """Drop the symbols that no library actually provides."""
    return [name for name in symbols or [] if name not in UNPROVIDED_SYMBOLS]


def analyze_link_hygiene(metadata: dict, dep_graph: dict) -> dict:
    """Report declared dependencies that are unused and used ones that are not declared.

    A `DT_NEEDED` entry from which nothing is imported still costs a mapped
    object, an entry in every dependency list built from the binary, and a
    vulnerability match against a library the program never calls. Linking with
    `--as-needed` removes it.

    The opposite case matters more for correctness: a library that supplies
    symbols without being declared is being reached through some other library's
    dependency list. That works until the intermediate library drops its own
    dependency, at which point the program stops linking for reasons that have
    nothing to do with any change made to it.

    Args:
        metadata: Parsed binary metadata.
        dep_graph: The import dependency graph, used for its per-library symbol
            attribution.

    Returns:
        dict: The findings, plus ``attribution_sources`` recording what the
        result is based on. Returns an empty dict when nothing can be attributed,
        because with no evidence every dependency looks unused.
    """
    _, sources = build_symbol_provider_map(metadata)
    if not sources:
        return {}

    declared = declared_libraries(metadata)
    if not declared:
        return {}

    used: dict[str, list[str]] = {}
    for library, entry in (dep_graph.get("libraries") or {}).items():
        if not isinstance(entry, dict) or entry.get("type") != "imported":
            continue
        if library == UNATTRIBUTED_LIBRARY:
            continue
        used[library.rsplit("/", 1)[-1]] = _meaningful_symbols(entry.get("imported_symbols") or [])

    unused = []
    for library in declared:
        symbols = used.get(library)
        if not symbols:
            unused.append(
                {
                    "name": library,
                    "reason": "no symbols imported"
                    if library not in used
                    else "only linker-resolved symbols imported",
                }
            )

    declared_set = set(declared)
    undeclared = [
        {"name": library, "symbol_count": len(symbols), "symbols": sorted(symbols)[:8]}
        for library, symbols in sorted(used.items())
        if library not in declared_set and symbols
    ]

    unattributed = (dep_graph.get("libraries") or {}).get(UNATTRIBUTED_LIBRARY) or {}
    return {
        "attribution_sources": sources,
        "unused_dependencies": unused,
        "undeclared_dependencies": undeclared,
        "unattributed_symbol_count": len(unattributed.get("imported_symbols") or []),
        "declared_count": len(declared),
    }
