"""Recovery of runtime-loaded library dependencies.

A library opened through `dlopen` never appears in `DT_NEEDED`, so a dependency
list built from the dynamic table alone silently omits it. This matters most for
exactly the dependencies people care about: hardware drivers, codec plugins,
authentication modules and cryptographic providers are almost always loaded on
demand rather than linked.

There is a declarative way to record these -- the packaging note that some
projects embed -- but it is opt-in and rare in practice. This module recovers the
rest from the image itself: it finds the runtime-loading entry points a binary
imports, then pairs them with the library-name strings the binary carries, and
grades each candidate by how much evidence supports it.
"""

import re

from blint.logger import LOG

# Entry points that map a shared object at runtime, across the platforms blint
# parses. Presence of any of these is what makes a library-shaped string in the
# data sections meaningful rather than incidental.
RUNTIME_LOAD_IMPORTS = frozenset(
    {
        "dlopen",
        "dlmopen",
        "__libc_dlopen_mode",
        "android_dlopen_ext",
        "dlsym",
        "dlvsym",
        "LoadLibraryA",
        "LoadLibraryW",
        "LoadLibraryExA",
        "LoadLibraryExW",
        "LdrLoadDll",
        "NSAddImage",
        "_dyld_get_image_name",
    }
)

# Imports that only resolve a symbol in an already-open handle. On their own they
# are weaker evidence than an actual open.
SYMBOL_LOOKUP_IMPORTS = frozenset({"dlsym", "dlvsym", "GetProcAddress"})

# Library-name shapes, in the order they are tried. Each must match the whole
# string so that a log message merely mentioning a library is not mistaken for a
# load target.
LIBRARY_NAME_PATTERNS = (
    # ELF shared objects, with or without a version suffix: libfoo.so, libz.so.1
    re.compile(r"^(?:[\w.+\-/]*/)?(lib[\w.+\-]+\.so(?:\.\d+)*)$"),
    # Bare versioned objects that do not use the lib prefix.
    re.compile(r"^(?:[\w.+\-/]*/)?([\w.+\-]+\.so(?:\.\d+)*)$"),
    # Mach-O dynamic libraries.
    re.compile(r"^(?:[\w.+\-/]*/)?([\w.+\-]+\.dylib)$"),
    # Windows modules.
    re.compile(r"^(?:[\w.+\-\\/]*[\\/])?([\w.+\-]+\.dll)$"),
)

# Strings that match the library shape but are format templates rather than
# names, usually assembled at runtime from a directory and a soname.
FORMAT_PLACEHOLDER_RE = re.compile(r"%[-#0-9. ]*[sdiuxXpc]|\{\}|\$\{")

# Data sections that hold string literals a load call could reference. Strings
# found outside these are far more likely to be incidental.
STRING_SECTIONS = frozenset({".rodata", ".rdata", ".data.rel.ro", "__cstring", ".data"})

# Guard against scanning a pathologically large data section.
MAX_SECTION_SCAN_BYTES = 64 * 1024 * 1024

# The dynamic loader itself is never a dlopen target. Names of this shape appear
# in the data of linkers and binary-manipulation libraries, which carry tables of
# the loader name for every target they support.
LOADER_NAME_RE = re.compile(r"^ld[\d\-._]|^ld\.so|^ld64\.so|^ldx?\d*\.so")

# Above this many candidates in one object, the names are almost certainly a
# lookup table of supported targets rather than that many distinct load sites.
NAME_TABLE_THRESHOLD = 3


def _normalize_candidate(value: str) -> tuple[str, str]:
    """Return ``(soname, full_path)`` for a string that names a library.

    Returns empty strings when the value does not look like a library name.
    """
    value = (value or "").strip().strip("\x00")
    if not value or len(value) > 256 or " " in value:
        return "", ""
    if FORMAT_PLACEHOLDER_RE.search(value):
        return "", ""
    for pattern in LIBRARY_NAME_PATTERNS:
        if match := pattern.match(value):
            return match.group(1), value if "/" in value or "\\" in value else ""
    return "", ""


def _loading_imports(metadata: dict) -> set[str]:
    """Collect the runtime-loading entry points the binary actually imports."""
    found = set()
    for bucket in ("dynamic_symbols", "symtab_symbols", "imports"):
        for entry in metadata.get(bucket) or []:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name") or ""
            # PE imports are recorded as `library::function`.
            if "::" in name:
                name = name.rsplit("::", 1)[-1]
            if name in RUNTIME_LOAD_IMPORTS:
                found.add(name)
    return found


def _loading_call_sites(metadata: dict) -> dict[str, list[str]]:
    """Map each runtime-loading entry point to the functions that call it.

    Only available when disassembly ran. Naming the call sites turns "this binary
    can load libraries" into "these functions load libraries", which is what a
    reviewer needs to judge whether the behaviour is expected.
    """
    call_sites: dict[str, list[str]] = {}
    for func in (metadata.get("disassembled_functions") or {}).values():
        if not isinstance(func, dict):
            continue
        caller = func.get("name") or func.get("address") or ""
        for callee in func.get("direct_calls") or []:
            target = callee.rsplit("::", 1)[-1] if "::" in callee else callee
            target = target.lstrip("_") if target.startswith("__imp_") else target
            if target in RUNTIME_LOAD_IMPORTS:
                sites = call_sites.setdefault(target, [])
                if caller and caller not in sites and len(sites) < 32:
                    sites.append(caller)
    return call_sites


def _candidate_strings(metadata: dict, parsed_obj=None) -> list[dict]:
    """Extract library-name candidates from the binary's string data.

    The section content is scanned directly rather than reusing the metadata
    ``strings`` list, because that list is filtered for secret-like entropy and
    length and drops short names such as ``libz.so.1``. Scanning here also keeps
    the section a candidate came from, which is the difference between a literal
    the code can reference and an incidental byte sequence.
    """
    candidates: dict[str, dict] = {}

    def record(value: str, section: str):
        soname, full_path = _normalize_candidate(value)
        if not soname:
            return
        existing = candidates.setdefault(soname, {"name": soname, "paths": [], "sections": set()})
        if full_path and full_path not in existing["paths"]:
            existing["paths"].append(full_path)
        if section:
            existing["sections"].add(section)

    if parsed_obj is not None:
        for section_name, values in _iter_section_strings(parsed_obj):
            for value in values:
                record(value, section_name)
    for entry in metadata.get("strings") or []:
        value = entry.get("value", "") if isinstance(entry, dict) else str(entry)
        record(value, entry.get("section", "") if isinstance(entry, dict) else "")
    return list(candidates.values())


def _iter_section_strings(parsed_obj):
    """Yield ``(section_name, values)`` of NUL-terminated strings per section.

    Library names are stored as C strings, so splitting on NUL recovers each one
    exactly. A regex over printable runs would instead merge adjacent names.
    """
    sections = getattr(parsed_obj, "sections", None)
    if not sections:
        return
    for section in sections:
        name = (getattr(section, "name", "") or "").lower()
        if name not in STRING_SECTIONS:
            continue
        try:
            content = bytes(section.content)
        except (AttributeError, TypeError, ValueError) as exc:
            LOG.debug("Unable to read content of section %s: %s", name, exc)
            continue
        if not content or len(content) > MAX_SECTION_SCAN_BYTES:
            continue
        values = []
        for chunk in content.split(b"\x00"):
            # A soname is short; anything longer is not one and skipping it
            # early keeps the decode cost proportional to real candidates.
            if 4 <= len(chunk) <= 256:
                values.append(chunk.decode("latin-1"))
        if values:
            yield name, values


def _declared_dependencies(metadata: dict) -> set[str]:
    """Names already accounted for by the static dependency table."""
    declared = set()
    for entry in metadata.get("dynamic_entries") or []:
        if entry.get("tag") in ("NEEDED", "SONAME") and entry.get("name"):
            declared.add(entry["name"])
    for entry in metadata.get("libraries") or []:
        if isinstance(entry, dict) and entry.get("name"):
            declared.add(entry["name"].rsplit("/", 1)[-1])
    for entry in metadata.get("dlopen_dependencies") or []:
        if isinstance(entry, dict) and entry.get("name"):
            declared.add(entry["name"])
    return declared


def _self_names(metadata: dict) -> set[str]:
    """Names that refer to the object being analysed.

    A library whose own soname appears in its data has not declared a dependency
    on itself; sanitizer runtimes and plugin hosts both do this.
    """
    names = set()
    for entry in metadata.get("dynamic_entries") or []:
        if entry.get("tag") == "SONAME" and entry.get("name"):
            names.add(entry["name"])
    if binary_name := (metadata.get("name") or ""):
        names.add(binary_name.rsplit("/", 1)[-1])
    # `libasan.so.8.0.0` should also match a reference to plain `libasan.so`.
    return {name.split(".so")[0] for name in names if name}


def recover_runtime_dependencies(metadata: dict, parsed_obj=None) -> list[dict]:
    """Recover libraries the binary loads at runtime rather than linking to.

    Args:
        metadata: Parsed binary metadata, after strings and symbols are populated.
        parsed_obj: The parsed binary, used to read string sections directly.

    Returns:
        list[dict]: One entry per recovered library, sorted by name. Each carries
        ``name``, ``confidence``, ``evidence`` and any absolute ``paths`` found.
        Libraries already listed as static dependencies or already declared
        through the packaging note are excluded, since they are not a gap.
    """
    loading_imports = _loading_imports(metadata)
    if not loading_imports:
        return []
    # An image that can only look up symbols in handles it was given is not
    # itself loading anything.
    if loading_imports <= SYMBOL_LOOKUP_IMPORTS:
        return []

    declared = _declared_dependencies(metadata)
    self_names = _self_names(metadata)
    call_sites = _loading_call_sites(metadata)
    recovered = []
    for candidate in _candidate_strings(metadata, parsed_obj):
        name = candidate["name"]
        if name in declared or LOADER_NAME_RE.match(name) or name.split(".so")[0] in self_names:
            continue
        sections = candidate["sections"]
        evidence = [f"imports {', '.join(sorted(loading_imports - SYMBOL_LOOKUP_IMPORTS))}"]
        # A name sitting in a read-only data section is a literal the code can
        # reference; the same name elsewhere is more likely to be incidental.
        in_string_section = bool(sections & STRING_SECTIONS)
        if in_string_section:
            evidence.append(f"string literal in {sorted(sections & STRING_SECTIONS)[0]}")
        if candidate["paths"]:
            evidence.append(f"absolute path {candidate['paths'][0]}")
        if in_string_section and (candidate["paths"] or name.startswith("lib")):
            confidence = "high"
        elif in_string_section or candidate["paths"]:
            confidence = "medium"
        else:
            confidence = "low"
        recovered.append(
            {
                "name": name,
                "confidence": confidence,
                "evidence": evidence,
                "paths": candidate["paths"],
                "sections": sorted(sections),
                "source": "recovered",
            }
        )

    recovered.sort(key=lambda entry: entry["name"])
    if len(recovered) > NAME_TABLE_THRESHOLD:
        # Many library names in one object is the signature of a table of
        # supported targets, not of that many separate load sites, so nothing
        # here earns the top confidence grade.
        for entry in recovered:
            if entry["confidence"] == "high":
                entry["confidence"] = "medium"
                entry["evidence"].append(
                    f"one of {len(recovered)} library names in this object, "
                    "which suggests a name table rather than a distinct load site"
                )
    if recovered:
        LOG.debug(
            "Recovered %d runtime-loaded dependency candidates via %s",
            len(recovered),
            ", ".join(sorted(loading_imports)),
        )
    # Attach the call sites once rather than per candidate; they describe the
    # binary's loading behaviour, not any single library.
    if call_sites and recovered:
        recovered[0]["call_sites"] = call_sites
    return recovered


def summarize_runtime_loading(metadata: dict) -> dict:
    """Describe how and where the binary loads libraries at runtime."""
    loading_imports = _loading_imports(metadata)
    if not loading_imports:
        return {}
    call_sites = _loading_call_sites(metadata)
    return {
        "entry_points": sorted(loading_imports),
        "call_sites": call_sites,
        "call_site_count": sum(len(v) for v in call_sites.values()),
        "loads_libraries": bool(loading_imports - SYMBOL_LOOKUP_IMPORTS),
    }
