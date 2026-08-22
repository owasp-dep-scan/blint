"""ELF ABI requirement and portability analysis.

An ELF binary that imports versioned symbols carries an implicit floor on the
runtime it can execute against: the highest version node it binds to. That floor
is the single most useful portability fact about a dynamically linked binary, and
it cannot be read off the version *definition* table alone -- the `.gnu.version_r`
section merely lists the version nodes the linker recorded, which routinely
includes nodes no imported symbol actually needs.

This module derives the floor the way the dynamic loader would: by looking at the
version attached to each imported symbol and taking the maximum per provider
library. It also collects the ABI features that make a binary hard to relocate to
a different libc or to load outside a stock loader -- indirect functions, thread
local storage models, unique symbols and interposable weak definitions.
"""

import re

from blint.logger import LOG

# Version nodes come in two shapes and the split between provider and version is
# genuinely ambiguous between them, so they are tried in a fixed order.
#
# The underscore form writes the version with underscores: `OPENSSL_1_1_0`,
# `LIBSSH2_1_0`. It is tried first, because the dotted pattern would otherwise
# read `LIBSSH2_1_0` as provider `LIBSSH2_1` at version `0`. Requiring at least
# two numeric components and a provider with no underscores keeps it from
# claiming nodes that belong to the dotted form.
UNDERSCORE_VERSION_RE = re.compile(
    r"^(?P<provider>[A-Za-z][A-Za-z0-9+]*?)_(?P<version>\d+(?:_\d+)+)$"
)

# The dotted form is by far the more common: `GLIBC_2.34`, `GLIBCXX_3.4.29`.
# The provider may itself contain underscores -- `LIBPAM_EXTENSION_1.0` and
# `NCURSES6_TINFO_5.7.20081102` are both real -- so the provider match is lazy
# and backtracks until the remainder is a numeric tail. The tail may end in a
# named component rather than a number, as in `NCURSES6_TINFO_6.6.current`.
DOTTED_VERSION_RE = re.compile(
    r"^(?P<provider>[A-Za-z][A-Za-z0-9_+]*?)[._]"
    r"(?P<version>\d[\d.]*(?:\.[A-Za-z][A-Za-z0-9]*)?)$"
)

# Some projects append a vendor tag after the version: MIT Kerberos ships
# `krb5_3_MIT`, `gssapi_krb5_2_MIT` and `k5crypto_3_MIT`. The provider here may
# contain underscores, which is why this is tried last -- by this point neither
# of the other two forms matched, so there is no ambiguity left to lose.
VENDOR_SUFFIX_VERSION_RE = re.compile(
    r"^(?P<provider>[A-Za-z][A-Za-z0-9_+]*?)_(?P<version>\d+)_(?P<vendor>[A-Za-z][A-Za-z0-9]*)$"
)

# A node named after a shared object names a library, not a version, so no
# version should be read out of it.
SONAME_NODE_RE = re.compile(r"\.so(\.\d+)*$")

# The parser renders a symbol's version as the node name followed by its index
# in the version table, as in `GLIBC_2.34(19)`. The index identifies the table
# entry, not the version, so it is dropped before the node is interpreted.
VERSION_INDEX_SUFFIX_RE = re.compile(r"\(\d+\)\s*$")

# Version nodes that carry no version information at all. `Base` is emitted by
# the GNU linker for the unversioned node of a versioned library.
# `* Global *` is how the parser renders the global version index, which every
# symbol in an object without version definitions carries.
UNVERSIONED_NODES = frozenset({"Base", "base", "* Global *", "* Local *", ""})

# Maps a version node provider to the package coordinates the symbol floor
# describes. Without this a floor of `GLIBC_2.34` would be attributed to a
# component literally named "glibc", which no package ecosystem uses.
PROVIDER_PACKAGES = {
    "GLIBC": {"name": "libc", "group": "gnu", "description": "GNU C Library"},
    "GLIBC_PRIVATE": {"name": "libc", "group": "gnu", "description": "GNU C Library (private)"},
    "GCC": {"name": "libgcc", "group": "gnu", "description": "GCC low-level runtime library"},
    "GLIBCXX": {"name": "libstdc++", "group": "gnu", "description": "GNU Standard C++ Library"},
    "CXXABI": {"name": "libstdc++", "group": "gnu", "description": "C++ ABI runtime"},
    "CXXABI_ARM": {"name": "libstdc++", "group": "gnu", "description": "C++ ABI runtime"},
    "LIBGCC": {"name": "libgcc", "group": "gnu", "description": "GCC low-level runtime library"},
    "GOMP": {"name": "libgomp", "group": "gnu", "description": "GNU OpenMP runtime"},
    "GFORTRAN": {"name": "libgfortran", "group": "gnu", "description": "GNU Fortran runtime"},
    "OPENSSL": {"name": "openssl", "group": "", "description": "OpenSSL"},
    "OPENSSL_1_1_0": {"name": "openssl", "group": "", "description": "OpenSSL"},
    "ZLIB": {"name": "zlib", "group": "", "description": "zlib compression library"},
    "LIBXML2": {"name": "libxml2", "group": "", "description": "libxml2"},
    "NSS": {"name": "nss", "group": "", "description": "Network Security Services"},
    "CURL_OPENSSL": {"name": "curl", "group": "", "description": "libcurl"},
    "LIBSSH2": {"name": "libssh2", "group": "", "description": "libssh2"},
}

# Symbol types that constrain how a binary can be loaded. LIEF renders these as
# the ELF `STT_` names with the prefix removed.
IFUNC_SYMBOL_TYPES = frozenset({"GNU_IFUNC", "IFUNC"})
TLS_SYMBOL_TYPES = frozenset({"TLS"})

# `STB_GNU_UNIQUE` forces the loader to keep one instance of the symbol process
# wide, which prevents the object from ever being unloaded.
UNIQUE_BINDINGS = frozenset({"GNU_UNIQUE", "UNIQUE"})

# Interfaces whose behaviour is tied to a specific C library implementation
# rather than to a standard. A binary that imports these cannot be re-pointed at
# a different libc without a compatibility layer, so they are worth surfacing
# even when every other portability signal is clean.
IMPLEMENTATION_SPECIFIC_INTERFACES = frozenset(
    {
        # Loader and link map introspection.
        "dl_iterate_phdr",
        "_dl_find_object",
        "dladdr",
        "dladdr1",
        "dlinfo",
        "dlvsym",
        "_dl_sym",
        # Backtrace support, which walks loader-private structures.
        "backtrace",
        "backtrace_symbols",
        "backtrace_symbols_fd",
        # Allocator internals.
        "malloc_usable_size",
        "malloc_trim",
        "malloc_stats",
        "malloc_info",
        "mallinfo",
        "mallinfo2",
        "mallopt",
        "__libc_malloc",
        "__libc_free",
        "__libc_calloc",
        "__libc_realloc",
        # stdio internals exposed as public symbols.
        "fopencookie",
        "__freadahead",
        "__fpurge",
        "_IO_getc",
        "_IO_putc",
        # Threading internals beyond the POSIX surface.
        "pthread_getattr_np",
        "pthread_setname_np",
        "pthread_getname_np",
        "pthread_attr_setaffinity_np",
        "pthread_attr_getaffinity_np",
        "pthread_timedjoin_np",
        "pthread_tryjoin_np",
        "__pthread_register_cancel",
        "__pthread_unregister_cancel",
        # Locale and iconv internals.
        "__ctype_b_loc",
        "__ctype_tolower_loc",
        "__ctype_toupper_loc",
        "gnu_get_libc_version",
        "gnu_get_libc_release",
        # Name service switch, which loads implementation modules at runtime.
        "__nss_configure_lookup",
        "getpwent_r",
        "getgrent_r",
        # Obstack and other GNU extensions with an exported ABI.
        "_obstack_begin",
        "_obstack_newchunk",
        "obstack_free",
        # Registration hooks used by the GNU runtime.
        "__register_atfork",
        "__cxa_thread_atexit_impl",
        "__libc_start_main",
        "__libc_current_sigrtmin",
        "__libc_current_sigrtmax",
        # Stack unwinder entry points, whose ABI differs between runtimes.
        "_Unwind_Find_FDE",
        "__register_frame_info",
        "__deregister_frame_info",
    }
)


def parse_version_node(node: str) -> tuple[str, str]:
    """Split a symbol version node into its provider and version.

    Args:
        node: A version node such as ``GLIBC_2.34`` or ``Base``.

    Returns:
        tuple[str, str]: ``(provider, version)``. The version is an empty string
        for nodes that carry no version, and the provider is the node itself in
        that case.
    """
    node = VERSION_INDEX_SUFFIX_RE.sub("", (node or "").strip()).strip()
    if not node or node in UNVERSIONED_NODES:
        return node, ""
    if SONAME_NODE_RE.search(node):
        return node, ""
    for pattern in (UNDERSCORE_VERSION_RE, DOTTED_VERSION_RE, VENDOR_SUFFIX_VERSION_RE):
        if match := pattern.match(node):
            # Normalize the underscore form to dotted so that versions written
            # in either style compare against each other.
            version = match.group("version").replace("_", ".").strip(".")
            return match.group("provider"), version
    return node, ""


def version_sort_key(version: str) -> tuple:
    """Return a tuple that orders dotted version strings numerically.

    ``2.34`` must sort above ``2.9``, which a lexical comparison gets wrong.
    Non-numeric components sort below any numeric component at the same
    position so that a malformed node never wins the maximum.
    """
    parts = []
    for component in (version or "").split("."):
        if component.isdigit():
            parts.append((1, int(component), ""))
        elif component:
            parts.append((0, 0, component))
    return tuple(parts)


def _iter_versioned_imports(metadata: dict):
    """Yield ``(symbol_name, version_node)`` for every imported versioned symbol.

    Only imported symbols matter for an ABI floor. A versioned symbol that the
    binary *defines* describes what it offers to others, which is a different
    question.
    """
    for bucket in ("dynamic_symbols", "symtab_symbols"):
        for symbol in metadata.get(bucket) or []:
            if not isinstance(symbol, dict):
                continue
            if not symbol.get("is_imported"):
                continue
            version = (symbol.get("version") or "").strip()
            if not version:
                continue
            provider, _ = parse_version_node(version)
            if not provider or provider in UNVERSIONED_NODES:
                continue
            name = symbol.get("name") or ""
            yield name, version


def compute_abi_requirements(metadata: dict) -> list[dict]:
    """Derive the minimum runtime version required by each version provider.

    The floor for a provider is the highest version node bound by any imported
    symbol. Recording the symbols that establish the floor makes the result
    auditable: a surprising floor can be traced to the one import that raised it.

    Args:
        metadata: Parsed binary metadata.

    Returns:
        list[dict]: One entry per provider, sorted by provider name. Each entry
        carries ``provider``, ``min_version``, ``symbol_count``,
        ``determining_symbols`` and the package coordinates when known.
    """
    by_provider: dict[str, dict] = {}
    for name, node in _iter_versioned_imports(metadata):
        provider, version = parse_version_node(node)
        if not provider:
            continue
        entry = by_provider.setdefault(
            provider,
            {
                "provider": provider,
                "min_version": "",
                "symbol_count": 0,
                "versions": set(),
                "_determining": [],
            },
        )
        entry["symbol_count"] += 1
        if not version:
            continue
        entry["versions"].add(version)
        current = entry["min_version"]
        if not current or version_sort_key(version) > version_sort_key(current):
            entry["min_version"] = version
            entry["_determining"] = [name]
        elif version == current and len(entry["_determining"]) < 8:
            entry["_determining"].append(name)

    requirements = []
    for provider, entry in sorted(by_provider.items()):
        package = PROVIDER_PACKAGES.get(provider, {})
        requirements.append(
            {
                "provider": provider,
                "min_version": entry["min_version"],
                "symbol_count": entry["symbol_count"],
                "version_count": len(entry["versions"]),
                "versions": sorted(entry["versions"], key=version_sort_key),
                "determining_symbols": sorted(entry["_determining"]),
                "package_name": package.get("name", ""),
                "package_group": package.get("group", ""),
                "description": package.get("description", ""),
            }
        )
    return requirements


def _detect_libc_flavour(metadata: dict, requirements: list[dict]) -> str:
    """Identify the C library the binary was linked against."""
    interpreter = (metadata.get("interpreter") or "").lower()
    if "musl" in interpreter:
        return "musl"
    if "ld-linux" in interpreter or "ld64.so" in interpreter or "ld.so" in interpreter:
        return "glibc"
    if metadata.get("is_targeting_android"):
        return "bionic"
    if any(req["provider"].startswith("GLIBC") for req in requirements):
        return "glibc"
    needed = {
        (entry.get("name") or "").lower()
        for entry in metadata.get("dynamic_entries") or []
        if entry.get("tag") == "NEEDED"
    }
    if any(name.startswith("libc.musl") or name.startswith("ld-musl") for name in needed):
        return "musl"
    if "libc.so.6" in needed:
        return "glibc"
    if "libc.so" in needed and metadata.get("is_targeting_android"):
        return "bionic"
    return ""


def _collect_symbol_features(metadata: dict) -> dict:
    """Count the ABI features that constrain how the binary can be loaded."""
    features = {
        "ifunc_symbols": [],
        "tls_symbols": [],
        "unique_symbols": [],
        "imported_ifunc_symbols": [],
        "implementation_specific_imports": [],
    }
    seen_impl = set()
    for bucket in ("dynamic_symbols", "symtab_symbols"):
        for symbol in metadata.get(bucket) or []:
            if not isinstance(symbol, dict):
                continue
            name = symbol.get("name") or ""
            sym_type = (symbol.get("type") or "").upper()
            binding = (symbol.get("binding") or "").upper()
            if sym_type in IFUNC_SYMBOL_TYPES:
                if symbol.get("is_imported"):
                    _append_capped(features["imported_ifunc_symbols"], name)
                else:
                    _append_capped(features["ifunc_symbols"], name)
            if sym_type in TLS_SYMBOL_TYPES:
                _append_capped(features["tls_symbols"], name)
            if binding in UNIQUE_BINDINGS:
                _append_capped(features["unique_symbols"], name)
            if (
                symbol.get("is_imported")
                and name in IMPLEMENTATION_SPECIFIC_INTERFACES
                and name not in seen_impl
            ):
                seen_impl.add(name)
                features["implementation_specific_imports"].append(name)
    features["implementation_specific_imports"].sort()
    return features


def _append_capped(target: list, value: str, limit: int = 32):
    """Append to an evidence list without letting it grow without bound.

    A binary can define thousands of TLS symbols; the report only needs enough
    names to make the finding actionable.
    """
    if value and len(target) < limit:
        target.append(value)


def analyze_elf_abi(metadata: dict) -> dict:
    """Build the ABI requirement and portability summary for an ELF binary.

    Args:
        metadata: Parsed binary metadata, after symbols have been populated.

    Returns:
        dict: A summary with ``requirements``, ``libc``, ``features`` and a set
        of boolean portability flags. Returns an empty dict when the binary has
        no dynamic symbol information to reason about.
    """
    requirements = compute_abi_requirements(metadata)
    features = _collect_symbol_features(metadata)
    libc = _detect_libc_flavour(metadata, requirements)
    if not requirements and not any(features.values()) and not libc:
        return {}

    glibc_floor = ""
    for req in requirements:
        if req["provider"] == "GLIBC" and req["min_version"]:
            glibc_floor = req["min_version"]
            break

    # A private version node is an explicit statement by the providing library
    # that the symbol is internal and carries no stability promise. Binding one
    # is a stronger portability constraint than any version floor, because the
    # symbol can change or disappear in a patch release.
    private_providers = [
        req["provider"] for req in requirements if req["provider"].endswith("_PRIVATE")
    ]

    summary = {
        "libc": libc,
        "private_version_providers": private_providers,
        "uses_private_symbol_versions": bool(private_providers),
        "requirements": requirements,
        "features": features,
        "min_glibc_version": glibc_floor,
        "uses_symbol_versioning": bool(requirements),
        "uses_ifunc": bool(features["ifunc_symbols"] or features["imported_ifunc_symbols"]),
        "uses_tls": bool(features["tls_symbols"]),
        "uses_unique_symbols": bool(features["unique_symbols"]),
        "uses_implementation_specific_interfaces": bool(
            features["implementation_specific_imports"]
        ),
    }
    # A statically linked image has no loader to satisfy, so the only portability
    # question left is whether it still reaches for a runtime it cannot have.
    summary["is_statically_linked"] = not metadata.get("has_interpreter") and not any(
        entry.get("tag") == "NEEDED" for entry in metadata.get("dynamic_entries") or []
    )
    summary["portability_notes"] = _build_portability_notes(summary)
    LOG.debug(
        "ABI analysis: libc=%s providers=%d ifunc=%s tls=%s",
        libc or "unknown",
        len(requirements),
        summary["uses_ifunc"],
        summary["uses_tls"],
    )
    return summary


def _build_portability_notes(summary: dict) -> list[str]:
    """Turn the raw ABI facts into short, human-readable portability notes."""
    notes = []
    if summary["min_glibc_version"]:
        notes.append(
            f"Requires glibc {summary['min_glibc_version']} or newer; "
            "it will not start on an older host."
        )
    for req in summary["requirements"]:
        if req["provider"] in ("GLIBC", "GLIBC_PRIVATE") or not req["min_version"]:
            continue
        label = req["package_name"] or req["provider"]
        notes.append(
            f"Requires {label} providing {req['provider']}_{req['min_version']} or newer."
        )
    if summary["requirements"] and summary["libc"] == "musl":
        notes.append(
            "Binds versioned symbols while linked against musl, which does not "
            "implement symbol versioning; the version nodes will be ignored at runtime."
        )
    if summary["uses_private_symbol_versions"]:
        providers = ", ".join(summary["private_version_providers"])
        notes.append(
            f"Binds symbols under a private version node ({providers}). These are "
            "internal interfaces with no stability promise and can change in a "
            "patch release of the providing library."
        )
    if summary["uses_ifunc"]:
        notes.append(
            "Uses indirect functions, which require a loader that runs IFUNC "
            "resolvers before relocation processing completes."
        )
    if summary["uses_unique_symbols"]:
        notes.append(
            "Defines process-unique symbols, which prevent the object from being unloaded."
        )
    if summary["uses_implementation_specific_interfaces"]:
        names = ", ".join(summary["features"]["implementation_specific_imports"][:5])
        notes.append(
            f"Imports C library implementation internals ({names}); these have no "
            "portable equivalent across libc implementations."
        )
    if summary["is_statically_linked"] and summary["uses_implementation_specific_interfaces"]:
        notes.append(
            "A statically linked image that also depends on loader internals cannot "
            "reliably introspect libraries it loads at runtime."
        )
    return notes
