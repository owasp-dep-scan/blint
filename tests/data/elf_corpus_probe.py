"""Probe executed inside a corpus container by test_elf_abi_corpus.py.

Runs the ELF ABI analysis over every shared object and executable it can find in
the image, and checks each result against ground truth read out of ``readelf``.
The probe is deliberately distribution agnostic: it discovers objects rather than
hardcoding paths, and derives the expected values per provider rather than
assuming glibc, so the same code validates a musl image and a glibc one.

Results are printed as a single JSON line after a marker, which is the only
contract the calling test depends on.
"""

import glob
import json
import os
import pathlib
import re
import subprocess
import sys
import traceback

# Attribution and link hygiene both need the dependency closure resolved, and
# inside the image the filesystem being resolved against is the right one.
os.environ["BLINT_RESOLVE_LINK_CLOSURE"] = "1"

# Resolve the checkout from this file's location rather than a fixed path, so
# the probe works wherever the container copied the source to.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from blint.lib.binary import parse
from blint.lib.elf_abi import parse_version_node, version_sort_key

ELF_MAGIC = b"\x7fELF"

# Where distributions put shared objects. The glob covers Debian and Ubuntu's
# multiarch layout as well as the flat lib64 layout used elsewhere.
LIBRARY_DIRS = (
    "/lib",
    "/lib64",
    "/usr/lib",
    "/usr/lib64",
    "/usr/lib/*-linux-gnu*",
    "/usr/local/lib",
)
BINARY_DIRS = ("/bin", "/usr/bin", "/sbin", "/usr/sbin")

# A symbol reference in readelf output looks like `name@GLIBC_2.14` for an
# import and `name@@GLIBC_2.14` for the default version of a definition. The
# line ends with the symbol's index in the version table, as in ` (2)`, which is
# not part of the node name.
VERSIONED_SYMBOL_RE = re.compile(
    r"\s(?P<name>[^\s@]+)@(?P<default>@?)(?P<node>[^\s@()]+)(?:\s+\(\d+\))?\s*$"
)

# A provider that still contains a separator immediately followed by a digit had
# a version in it that the node grammar failed to split off. Nodes naming a
# library rather than a version, such as `libjson-glib-1.0.so.0`, are excluded:
# they carry no version by design.
UNSPLIT_VERSION_RE = re.compile(r"[._]\d")

MAX_OBJECTS = 260


def is_elf(path):
    try:
        with open(path, "rb") as handle:
            return handle.read(4) == ELF_MAGIC
    except OSError:
        return False


def discover_objects():
    """Find ELF objects in the image, preferring libraries over executables."""
    found, seen = [], set()

    def collect(patterns, limit):
        count = 0
        for pattern in patterns:
            for directory in sorted(glob.glob(pattern)):
                if not os.path.isdir(directory):
                    continue
                for name in sorted(os.listdir(directory)):
                    path = os.path.join(directory, name)
                    # Symlinks would analyse the same file repeatedly and skew
                    # every count in the report.
                    if os.path.islink(path) or not os.path.isfile(path):
                        continue
                    real = os.path.realpath(path)
                    if real in seen or not is_elf(path):
                        continue
                    seen.add(real)
                    found.append(path)
                    count += 1
                    if count >= limit:
                        return

    collect(LIBRARY_DIRS, MAX_OBJECTS - 40)
    collect(BINARY_DIRS, 40)
    return found


def readelf_requirements(path):
    """Return the highest version node per provider across imported symbols.

    This is the same quantity the ABI analysis computes, derived independently
    from the linker's own output, so a mismatch means one of the two is wrong.
    """
    try:
        completed = subprocess.run(
            ["readelf", "--dyn-syms", "-W", path],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None

    floors = {}
    for line in completed.stdout.splitlines():
        # Only undefined symbols are imports; a definition describes what this
        # object offers, which is a different question.
        if " UND " not in line:
            continue
        match = VERSIONED_SYMBOL_RE.search(line.rstrip())
        if not match:
            continue
        provider, version = parse_version_node(match.group("node"))
        if not provider or not version:
            continue
        current = floors.get(provider, "")
        if not current or version_sort_key(version) > version_sort_key(current):
            floors[provider] = version
    return floors


def blint_requirements(abi):
    return {
        requirement["provider"]: requirement["min_version"]
        for requirement in abi.get("requirements") or []
        if requirement.get("min_version")
    }


def ldd_unused(path):
    """Return the direct dependencies ``ldd -u`` considers unused.

    This is a second opinion on the same question, computed by the loader itself,
    but not an identical one. ``ldd -u`` relocates the whole closure and counts a
    dependency as used if anything in it binds to the library, so a library the
    binary never calls directly still counts as used when some other dependency
    calls it. blint reports direct use only, which is what `--as-needed` acts on.
    The comparison is therefore one-directional: everything ``ldd`` calls unused
    must also be unused directly.

    Returns ``None`` when ``ldd -u`` is unsupported, which is the case on musl.
    Treating that as "nothing unused" would silently compare against garbage.

    Only run inside the corpus container and only against distribution-owned
    files: ``ldd`` works by invoking the dynamic loader, which is not something
    to point at an untrusted binary.
    """
    try:
        completed = subprocess.run(
            ["ldd", "-u", path], capture_output=True, text=True, timeout=120
        )
    except (OSError, subprocess.SubprocessError):
        return None
    combined = completed.stdout + completed.stderr
    if "cannot load" in combined or "unrecognized option" in combined:
        return None
    if completed.returncode not in (0, 1):
        return None
    unused = []
    for line in completed.stdout.splitlines():
        line = line.strip()
        if line.startswith("/"):
            unused.append(line.rsplit("/", 1)[-1])
    return sorted(unused)


def direct_symbol_overlap(path, soname):
    """Return how many of a binary's undefined symbols a library exports.

    This is the precise definition of the link hygiene finding: zero overlap
    means the binary imports nothing from the library, so declaring it as a
    dependency achieves nothing. Returns ``None`` when it cannot be computed.
    """
    undefined = _undefined_symbols(path)
    exported = _library_exports(soname)
    if undefined is None or exported is None:
        return None
    return len(undefined & exported)


def _undefined_symbols(path):
    """Return the linkage names of a binary's undefined dynamic symbols."""
    try:
        completed = subprocess.run(
            ["nm", "-D", "--undefined-only", path],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    return {
        line.split()[-1].partition("@")[0]
        for line in completed.stdout.splitlines()
        if line.split()
    }


_EXPORT_CACHE: dict = {}


def _library_exports(soname):
    """Return the symbols a library on the search path exports, via ``nm``.

    Used to check that an attributed symbol really is supplied by the library it
    was attributed to. Returns ``None`` when the library cannot be located or
    read, which is not a failure -- only a positive mismatch is.
    """
    if soname in _EXPORT_CACHE:
        return _EXPORT_CACHE[soname]
    located = ""
    for directory in ("/lib64", "/usr/lib64", "/lib", "/usr/lib"):
        for candidate in glob.glob(f"{directory}/{soname}") + glob.glob(
            f"{directory}/*-linux-gnu*/{soname}"
        ):
            if os.path.exists(candidate):
                located = candidate
                break
        if located:
            break
    exports = None
    if located:
        try:
            completed = subprocess.run(
                ["nm", "-D", "--defined-only", located],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if completed.returncode == 0:
                exports = {
                    line.split()[-1].partition("@")[0]
                    for line in completed.stdout.splitlines()
                    if line.split()
                }
        except (OSError, subprocess.SubprocessError):
            exports = None
    _EXPORT_CACHE[soname] = exports
    return exports


def readelf_needed(path):
    """Return the DT_NEEDED names readelf reports, as an independent check."""
    try:
        completed = subprocess.run(
            ["readelf", "-d", "-W", path], capture_output=True, text=True, timeout=120
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    return sorted(re.findall(r"Shared library: \[([^\]]+)\]", completed.stdout))


def main():
    paths = discover_objects()
    report = {
        "objects": len(paths),
        "parsed": 0,
        "parse_failures": [],
        "floor_matched": 0,
        "floor_mismatched": [],
        "needed_matched": 0,
        "needed_mismatched": [],
        "libc_counts": {},
        "unparsed_nodes": {},
        "unversioned_nodes": {},
        "private_nodes": 0,
        "ifunc": 0,
        "tls": 0,
        "unique_symbols": 0,
        "implementation_specific": 0,
        "recovered": {},
        "nameless_symbol_objects": [],
        "hygiene_checked": 0,
        "verified_unused": 0,
        "false_unused": [],
        "missed_unused": [],
        "unused_dependency_objects": 0,
        "undeclared_dependency_objects": 0,
        "misattributed_symbols": [],
    }

    for path in paths:
        try:
            metadata = parse(path)
        except Exception as exc:  # noqa: BLE001 - one bad file must not end the sweep
            report["parse_failures"].append(
                {
                    "path": path,
                    "error": f"{type(exc).__name__}: {exc}",
                    "traceback": traceback.format_exc()[-1500:],
                }
            )
            continue
        report["parsed"] += 1
        abi = metadata.get("abi_analysis") or {}

        libc = abi.get("libc") or "unknown"
        report["libc_counts"][libc] = report["libc_counts"].get(libc, 0) + 1

        expected = readelf_requirements(path)
        if expected is not None:
            actual = blint_requirements(abi)
            if expected == actual:
                report["floor_matched"] += 1
            else:
                report["floor_mismatched"].append(
                    {"path": path, "expected": expected, "actual": actual}
                )

        expected_needed = readelf_needed(path)
        if expected_needed is not None:
            actual_needed = sorted(
                entry["name"]
                for entry in metadata.get("dynamic_entries") or []
                if entry.get("tag") == "NEEDED" and entry.get("name")
            )
            if expected_needed == actual_needed:
                report["needed_matched"] += 1
            else:
                report["needed_mismatched"].append(
                    {"path": path, "expected": expected_needed, "actual": actual_needed}
                )

        for requirement in abi.get("requirements") or []:
            provider = requirement["provider"]
            if requirement["min_version"]:
                continue
            # Plenty of real nodes carry no version at all -- `SASL2`,
            # `SD_SHARED`, `GLIBC_PRIVATE` -- so the absence of one is not by
            # itself a defect. Only a provider that still has a version buried
            # in it points at a grammar failure.
            report["unversioned_nodes"][provider] = (
                report["unversioned_nodes"].get(provider, 0) + 1
            )
            if UNSPLIT_VERSION_RE.search(provider) and ".so" not in provider:
                report["unparsed_nodes"][provider] = report["unparsed_nodes"].get(provider, 0) + 1
        if abi.get("uses_private_symbol_versions"):
            report["private_nodes"] += 1
        if abi.get("uses_ifunc"):
            report["ifunc"] += 1
        if abi.get("uses_tls"):
            report["tls"] += 1
        if abi.get("uses_unique_symbols"):
            report["unique_symbols"] += 1
        if abi.get("uses_implementation_specific_interfaces"):
            report["implementation_specific"] += 1

        # A symbol that parses to an empty name silently removes itself from
        # every symbol-derived result, so it is worth catching directly.
        symbols = metadata.get("dynamic_symbols") or []
        if symbols and not any(symbol.get("name") for symbol in symbols):
            report["nameless_symbol_objects"].append(path)

        # The link hygiene finding answers the same question as `ldd -u`, so it
        # is checked against that rather than against a recorded expectation.
        hygiene = metadata.get("link_hygiene")
        if hygiene:
            if hygiene["unused_dependencies"]:
                report["unused_dependency_objects"] += 1
            if hygiene["undeclared_dependencies"]:
                report["undeclared_dependency_objects"] += 1

            # The precise invariant: a library reported unused must export none
            # of the symbols this binary leaves undefined. A violation here is a
            # false positive, which is the only way this finding can mislead.
            for entry in hygiene["unused_dependencies"]:
                overlap = direct_symbol_overlap(path, entry["name"])
                if overlap:
                    report["false_unused"].append(
                        {"path": path, "library": entry["name"], "overlap": overlap}
                    )
                elif overlap == 0:
                    report["verified_unused"] += 1

            # The loader's own opinion, as a check for missed findings. It counts
            # transitive use as use, so it can call a library used that this
            # binary never calls directly -- but never the reverse.
            expected_unused = ldd_unused(path)
            if expected_unused is not None:
                report["hygiene_checked"] += 1
                actual_unused = {entry["name"] for entry in hygiene["unused_dependencies"]}
                missed = [name for name in expected_unused if name not in actual_unused]
                if missed:
                    report["missed_unused"].append({"path": path, "missed": missed})

        # A symbol attributed to a library that does not export it is worse than
        # no attribution, so verify a sample of the edges against the provider.
        for edge in (metadata.get("import_dependencies") or {}).get("dependencies") or []:
            library = edge.get("to") or ""
            if not library.endswith((".so", ".dylib")) and ".so." not in library:
                continue
            exported = _library_exports(library)
            if exported is None:
                continue
            for symbol in edge.get("symbols") or []:
                # blint records the demangled name while nm reports the linkage
                # name, so only plain C identifiers can be compared directly.
                if not symbol.replace("_", "").isalnum():
                    continue
                if symbol not in exported and len(report["misattributed_symbols"]) < 20:
                    report["misattributed_symbols"].append(
                        {"path": path, "library": library, "symbol": symbol}
                    )

        for entry in metadata.get("recovered_dependencies") or []:
            if entry.get("confidence") == "high":
                key = os.path.basename(path)
                report["recovered"].setdefault(key, []).append(entry["name"])

    print("BLINT_RESULT_START")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
