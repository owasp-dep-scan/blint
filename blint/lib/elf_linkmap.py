"""Static resolution of the ELF dynamic link closure.

Recording the `DT_NEEDED` list tells you what a binary asks for. It does not tell
you whether those requests can be satisfied, which library actually supplies each
imported symbol, or whether a search path lets an attacker-controlled directory
answer first. Those questions need the resolution step the dynamic loader performs
at startup, reproduced statically.

The resolver here follows the documented loader search order and reports what it
finds: the transitive set of objects that would be mapped, the ones that are
missing, the symbols nothing in the closure defines, and the provider of every
symbol that does resolve. It never executes the binary and never loads code -- it
only parses the candidate files it locates on disk.
"""

import os
import re
from collections import OrderedDict, deque
from pathlib import Path

import lief

from blint.logger import LOG

# The loader expands these tokens inside RPATH, RUNPATH and DT_NEEDED entries.
ORIGIN_TOKEN_RE = re.compile(r"\$(?:ORIGIN|\{ORIGIN\})")
LIB_TOKEN_RE = re.compile(r"\$(?:LIB|\{LIB\})")
PLATFORM_TOKEN_RE = re.compile(r"\$(?:PLATFORM|\{PLATFORM\})")

# Fallback directories consulted after RPATH, LD_LIBRARY_PATH and RUNPATH.
DEFAULT_SEARCH_DIRS = (
    "/lib",
    "/usr/lib",
    "/usr/local/lib",
)

# Machine-specific directory names, keyed by the upper-cased machine type.
MACHINE_LIB_DIRS = {
    "X86_64": ("/lib64", "/usr/lib64", "/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu"),
    "AARCH64": ("/lib64", "/usr/lib64", "/lib/aarch64-linux-gnu", "/usr/lib/aarch64-linux-gnu"),
    "ARM": ("/lib/arm-linux-gnueabihf", "/usr/lib/arm-linux-gnueabihf"),
    "I386": ("/lib32", "/usr/lib32", "/lib/i386-linux-gnu", "/usr/lib/i386-linux-gnu"),
    "RISCV": ("/lib64", "/usr/lib64", "/lib/riscv64-linux-gnu", "/usr/lib/riscv64-linux-gnu"),
    "PPC64": ("/lib64", "/usr/lib64", "/lib/powerpc64le-linux-gnu"),
    "LOONGARCH": ("/lib64", "/usr/lib64", "/lib/loongarch64-linux-gnu"),
}

# `$PLATFORM` expands to the kernel's name for the processor.
MACHINE_PLATFORM = {
    "X86_64": "x86_64",
    "AARCH64": "aarch64",
    "ARM": "arm",
    "I386": "i686",
    "RISCV": "riscv64",
    "PPC64": "ppc64le",
    "LOONGARCH": "loongarch64",
}

# Directories that anyone on the system can write to. A search path entry under
# one of these lets an unprivileged user decide which library gets loaded.
WORLD_WRITABLE_PREFIXES = ("/tmp", "/var/tmp", "/dev/shm", "/var/spool")

# Cap the closure so a pathological dependency graph cannot stall an analysis run.
MAX_CLOSURE_OBJECTS = 256


def _expand_tokens(path: str, origin: str, lib_dir: str, platform: str) -> str:
    """Expand the loader's dynamic string tokens in a search path entry."""
    path = ORIGIN_TOKEN_RE.sub(origin, path)
    path = LIB_TOKEN_RE.sub(lib_dir, path)
    path = PLATFORM_TOKEN_RE.sub(platform, path)
    return path


def _split_paths(value: str) -> list[str]:
    """Split a colon-separated loader path list, dropping empty entries.

    An empty entry means the current directory to the loader, which is a finding
    in its own right, so it is preserved as ``"."`` rather than discarded.
    """
    if not value:
        return []
    return [part if part else "." for part in value.split(":")]


class LinkResolver:
    """Resolves the dynamic link closure of an ELF binary against a filesystem."""

    def __init__(self, root: str = "/", extra_search_paths: list[str] | None = None):
        """
        Args:
            root: Filesystem root to resolve against. Point this at an unpacked
                image or sysroot to analyse a binary in the context it ships in
                rather than the context it is being scanned from.
            extra_search_paths: Directories consulted as if they were in
                ``LD_LIBRARY_PATH``.
        """
        self.root = Path(root)
        self.extra_search_paths = list(extra_search_paths or [])
        self._parse_cache: dict[str, dict | None] = {}

    def _rooted(self, path: str) -> Path:
        """Map an absolute loader path into the configured root."""
        if self.root == Path("/"):
            return Path(path)
        return self.root / path.lstrip("/")

    def _default_dirs(self, machine_type: str) -> list[str]:
        """Return the loader's default directories for a machine type."""
        dirs = list(MACHINE_LIB_DIRS.get(machine_type.upper(), ()))
        dirs.extend(DEFAULT_SEARCH_DIRS)
        # `/etc/ld.so.conf` additions are part of the default set on glibc hosts.
        dirs.extend(self._ld_so_conf_dirs())
        seen = OrderedDict((d, None) for d in dirs)
        return list(seen)

    def _ld_so_conf_dirs(self) -> list[str]:
        """Read the directories configured through ``/etc/ld.so.conf``.

        Only one level of ``include`` is followed, which covers the layout every
        mainstream distribution ships and avoids unbounded traversal.
        """
        dirs: list[str] = []
        conf = self._rooted("/etc/ld.so.conf")
        if not conf.is_file():
            return dirs
        entries = [conf]
        try:
            for line in conf.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.split("#", 1)[0].strip()
                if line.startswith("include "):
                    pattern = line.removeprefix("include ").strip()
                    base = self._rooted("/etc") if not pattern.startswith("/") else self.root
                    entries.extend(sorted(Path(base).glob(pattern.lstrip("/"))))
        except OSError as exc:
            LOG.debug("Unable to read %s: %s", conf, exc)
            return dirs
        for entry in entries:
            try:
                for line in entry.read_text(encoding="utf-8", errors="ignore").splitlines():
                    line = line.split("#", 1)[0].strip()
                    if line and not line.startswith("include ") and line.startswith("/"):
                        dirs.append(line)
            except OSError as exc:
                LOG.debug("Unable to read %s: %s", entry, exc)
        return dirs

    def search_paths(self, obj: dict, machine_type: str) -> list[dict]:
        """Build the ordered search path for one object.

        The order is the one the loader documents: ``DT_RPATH`` (ignored when
        ``DT_RUNPATH`` is present), then ``LD_LIBRARY_PATH``, then ``DT_RUNPATH``,
        then the default directories. Each entry records its origin so that a
        library resolved from a writable RPATH can be reported as such.
        """
        origin = str(Path(obj["path"]).parent)
        lib_dir = "lib64" if machine_type.upper() in ("X86_64", "AARCH64") else "lib"
        platform = MACHINE_PLATFORM.get(machine_type.upper(), machine_type.lower())
        entries: list[dict] = []

        def add(paths, kind):
            for raw in paths:
                expanded = _expand_tokens(raw, origin, lib_dir, platform)
                entries.append({"path": expanded, "kind": kind, "raw": raw})

        if obj.get("runpath"):
            # DT_RUNPATH present means DT_RPATH is ignored entirely.
            add(_split_paths(os.environ.get("LD_LIBRARY_PATH", "")), "LD_LIBRARY_PATH")
            add(self.extra_search_paths, "extra")
            add(_split_paths(obj["runpath"]), "DT_RUNPATH")
        else:
            add(_split_paths(obj.get("rpath", "")), "DT_RPATH")
            add(_split_paths(os.environ.get("LD_LIBRARY_PATH", "")), "LD_LIBRARY_PATH")
            add(self.extra_search_paths, "extra")
        add(self._default_dirs(machine_type), "default")
        return entries

    def locate(self, soname: str, search_paths: list[dict]) -> dict | None:
        """Find the first file matching a ``DT_NEEDED`` name on the search path."""
        if "/" in soname:
            # A needed entry containing a slash is used verbatim, without search.
            candidate = self._rooted(soname)
            if candidate.is_file():
                return {"path": str(candidate), "kind": "direct", "search_entry": soname}
            return None
        for entry in search_paths:
            candidate = self._rooted(entry["path"]) / soname
            if candidate.is_file():
                return {
                    "path": str(candidate),
                    "kind": entry["kind"],
                    "search_entry": entry["path"],
                }
        return None

    def parse_object(self, path: str) -> dict | None:
        """Parse one ELF object into the minimal facts the resolver needs."""
        if path in self._parse_cache:
            return self._parse_cache[path]
        result = None
        try:
            parsed = lief.ELF.parse(path)
        except (RuntimeError, OSError) as exc:
            LOG.debug("Unable to parse dependency %s: %s", path, exc)
            parsed = None
        if parsed is not None and not isinstance(parsed, lief.lief_errors):
            result = {
                "path": path,
                "soname": "",
                "needed": [],
                "rpath": "",
                "runpath": "",
                "exports": set(),
                "imports": [],
            }
            for entry in parsed.dynamic_entries:
                tag = str(entry.tag).rsplit(".", maxsplit=1)[-1]
                if tag == "SONAME":
                    result["soname"] = entry.name
                elif tag == "NEEDED":
                    result["needed"].append(entry.name)
                elif tag == "RPATH":
                    result["rpath"] = getattr(entry, "rpath", "")
                elif tag == "RUNPATH":
                    result["runpath"] = getattr(entry, "runpath", "")
            for symbol in parsed.dynamic_symbols:
                try:
                    if symbol.exported and symbol.name:
                        result["exports"].add(symbol.name)
                    elif symbol.imported and symbol.name:
                        result["imports"].append(symbol)
                except (AttributeError, TypeError):
                    continue
        self._parse_cache[path] = result
        return result


def _binary_search_seed(metadata: dict, exe_path: str) -> dict:
    """Build the resolver's view of the binary under analysis from its metadata."""
    seed = {
        "path": os.path.abspath(exe_path),
        "soname": "",
        "needed": [],
        "rpath": "",
        "runpath": "",
    }
    for entry in metadata.get("dynamic_entries") or []:
        tag = entry.get("tag")
        if tag == "NEEDED":
            seed["needed"].append(entry.get("name", ""))
        elif tag == "SONAME":
            seed["soname"] = entry.get("name", "")
        elif tag == "RPATH":
            seed["rpath"] = entry.get("value", "")
        elif tag == "RUNPATH":
            seed["runpath"] = entry.get("value", "")
    seed["needed"] = [name for name in seed["needed"] if name]
    return seed


def _classify_search_path(path: str) -> str:
    """Flag search path entries that widen who can decide what gets loaded."""
    if path in (".", ""):
        return "current-directory"
    if path.startswith(WORLD_WRITABLE_PREFIXES):
        return "world-writable"
    if not path.startswith("/"):
        return "relative"
    return ""


def resolve_link_closure(
    metadata: dict,
    exe_path: str,
    *,
    root: str = "/",
    extra_search_paths: list[str] | None = None,
) -> dict:
    """Resolve the transitive dependency closure and symbol providers.

    Args:
        metadata: Parsed metadata for the binary under analysis.
        exe_path: Path to the binary on disk.
        root: Filesystem root to resolve library paths against.
        extra_search_paths: Extra directories treated as ``LD_LIBRARY_PATH``.

    Returns:
        dict: ``resolved`` maps each soname to where it was found and how,
        ``missing`` lists the sonames nothing on the search path satisfies,
        ``unresolved_symbols`` lists imports no object in the closure defines,
        ``symbol_providers`` maps a resolved import to the library that supplies
        it, and ``risky_search_paths`` records search entries that let an
        unexpected directory answer first. Returns an empty dict for binaries
        with no dynamic dependencies.
    """
    seed = _binary_search_seed(metadata, exe_path)
    if not seed["needed"]:
        return {}

    machine_type = metadata.get("machine_type") or ""
    resolver = LinkResolver(root=root, extra_search_paths=extra_search_paths)

    resolved: "OrderedDict[str, dict]" = OrderedDict()
    missing: list[dict] = []
    exports: set[str] = set()
    provider_by_symbol: dict[str, str] = {}
    risky: list[dict] = []
    visited_paths: set[str] = set()

    # Record the search paths the binary itself contributes, which is where a
    # writable or relative entry has the most impact.
    for entry in resolver.search_paths(seed, machine_type):
        if entry["kind"] in ("DT_RPATH", "DT_RUNPATH"):
            if issue := _classify_search_path(entry["path"]):
                risky.append(
                    {
                        "path": entry["path"],
                        "raw": entry["raw"],
                        "kind": entry["kind"],
                        "issue": issue,
                    }
                )

    queue = deque((name, seed, "direct") for name in seed["needed"])
    while queue:
        if len(resolved) >= MAX_CLOSURE_OBJECTS:
            LOG.debug("Dependency closure capped at %d objects", MAX_CLOSURE_OBJECTS)
            break
        soname, parent, relation = queue.popleft()
        if soname in resolved or any(m["name"] == soname for m in missing):
            continue
        search_paths = resolver.search_paths(parent, machine_type)
        location = resolver.locate(soname, search_paths)
        if not location:
            missing.append({"name": soname, "needed_by": parent.get("soname") or parent["path"]})
            continue
        obj = resolver.parse_object(location["path"])
        if obj is None:
            missing.append(
                {
                    "name": soname,
                    "needed_by": parent.get("soname") or parent["path"],
                    "reason": "not a parsable ELF object",
                }
            )
            continue
        resolved[soname] = {
            "name": soname,
            "path": location["path"],
            "found_via": location["kind"],
            "search_entry": location.get("search_entry", ""),
            "needed_by": parent.get("soname") or parent["path"],
            "relation": relation,
            "export_count": len(obj["exports"]),
        }
        if location["kind"] in ("DT_RPATH", "DT_RUNPATH", "LD_LIBRARY_PATH"):
            # Resolving outside the default directories means the effective
            # library differs from the one a package manager would install.
            resolved[soname]["overrides_default_path"] = True
        for name in obj["exports"]:
            if name not in provider_by_symbol:
                provider_by_symbol[name] = soname
        exports |= obj["exports"]
        if location["path"] not in visited_paths:
            visited_paths.add(location["path"])
            for child in obj["needed"]:
                queue.append((child, obj, "transitive"))

    unresolved = []
    for symbol in metadata.get("dynamic_symbols") or []:
        if not isinstance(symbol, dict) or not symbol.get("is_imported"):
            continue
        name = symbol.get("name") or ""
        if not name or name in exports:
            continue
        # A weak import that goes unresolved is intentional: the binary checks
        # the address for null before use.
        if (symbol.get("binding") or "").upper() == "WEAK":
            continue
        unresolved.append({"name": name, "version": symbol.get("version") or ""})

    return {
        "root": root,
        "resolved": list(resolved.values()),
        "missing": missing,
        "resolved_count": len(resolved),
        "missing_count": len(missing),
        "unresolved_symbols": unresolved[:64],
        "unresolved_symbol_count": len(unresolved),
        "symbol_providers": provider_by_symbol,
        "risky_search_paths": risky,
        "complete": not missing and not unresolved,
    }
