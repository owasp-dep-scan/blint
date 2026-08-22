#!/usr/bin/env python3
"""Sweep a filesystem of real shared objects through the ELF ABI analysis.

The fixture binaries checked into this repository cover a handful of targets
built by one toolchain. That is enough to test the parsing logic and nowhere near
enough to test the assumptions: symbol version node shapes, indirect functions,
thread local storage models, unusual search paths and unresolvable closures all
appear in the wild at rates a small fixture set never reproduces.

This script points the analysis at every shared object and executable under a
root -- most usefully a distribution container image, where a few thousand
objects from hundreds of packages are one `docker run` away -- and reports what
it found plus anything that failed. It is a corpus harness, not a test: it has no
expected output, and its value is the exceptions and the outliers it surfaces.

Usage:

    # Against a container image, which is where the interesting variety is.
    docker run --rm -v "$PWD:/blint" -w /blint python:3.12-slim \\
        sh -c "pip install -q -e . && python contrib/elf_abi_sweep.py /usr/lib"

    # Against the host, or an unpacked image root.
    python contrib/elf_abi_sweep.py /usr/lib --limit 500 --json sweep.json
"""

import argparse
import json
import os
import sys
import traceback
from collections import Counter, defaultdict

# Allow running straight from a checkout without installing.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from blint.lib.binary import parse  # noqa: E402
from blint.lib.elf_linkmap import resolve_link_closure  # noqa: E402

ELF_MAGIC = b"\x7fELF"


def is_elf(path: str) -> bool:
    """Return True when the file starts with the ELF magic."""
    try:
        with open(path, "rb") as handle:
            return handle.read(4) == ELF_MAGIC
    except OSError:
        return False


def find_objects(root: str, limit: int) -> list[str]:
    """Collect ELF files under a root, skipping symlinks to avoid duplicates."""
    found = []
    for dirpath, _, filenames in os.walk(root, followlinks=False):
        for filename in filenames:
            path = os.path.join(dirpath, filename)
            if os.path.islink(path) or not os.path.isfile(path):
                continue
            if is_elf(path):
                found.append(path)
                if limit and len(found) >= limit:
                    return found
    return found


def sweep(paths: list[str], resolve_closure: bool, root: str) -> dict:
    """Run the ABI analysis over every path and aggregate the outcome."""
    stats = {
        "analyzed": 0,
        "failed": 0,
        "with_requirements": 0,
        "with_recovered_dependencies": 0,
        "with_ifunc": 0,
        "with_tls": 0,
        "with_unique_symbols": 0,
        "with_implementation_specific_imports": 0,
        "with_missing_dependencies": 0,
        "with_risky_search_path": 0,
        "with_private_version_nodes": 0,
    }
    libc_counts = Counter()
    provider_counts = Counter()
    glibc_floors = Counter()
    # Version node shapes the parser did not split into a provider and version
    # are the most likely place for the node grammar to be wrong.
    unparsed_nodes = Counter()
    implementation_imports = Counter()
    recovered_names = Counter()
    failures = []
    highest_floor = defaultdict(list)

    for path in paths:
        try:
            metadata = parse(path)
        except Exception as exc:  # noqa: BLE001 - a corpus run must not stop at one file
            stats["failed"] += 1
            failures.append({"path": path, "error": f"{type(exc).__name__}: {exc}"})
            if os.getenv("SWEEP_TRACEBACK"):
                traceback.print_exc()
            continue

        stats["analyzed"] += 1
        abi = metadata.get("abi_analysis") or {}
        if not abi:
            continue
        libc_counts[abi.get("libc") or "unknown"] += 1
        if abi.get("requirements"):
            stats["with_requirements"] += 1
        for requirement in abi.get("requirements") or []:
            provider_counts[requirement["provider"]] += 1
            # A private node legitimately has no version, so it is not evidence
            # of a grammar problem.
            if not requirement["min_version"] and not requirement["provider"].endswith("_PRIVATE"):
                unparsed_nodes[requirement["provider"]] += 1
        if floor := abi.get("min_glibc_version"):
            glibc_floors[floor] += 1
            highest_floor[floor].append(os.path.basename(path))
        features = abi.get("features") or {}
        if abi.get("uses_private_symbol_versions"):
            stats["with_private_version_nodes"] += 1
        if abi.get("uses_ifunc"):
            stats["with_ifunc"] += 1
        if abi.get("uses_tls"):
            stats["with_tls"] += 1
        if abi.get("uses_unique_symbols"):
            stats["with_unique_symbols"] += 1
        for name in features.get("implementation_specific_imports") or []:
            implementation_imports[name] += 1
        if features.get("implementation_specific_imports"):
            stats["with_implementation_specific_imports"] += 1

        recovered = metadata.get("recovered_dependencies") or []
        if recovered:
            stats["with_recovered_dependencies"] += 1
        for entry in recovered:
            if entry.get("confidence") in ("high", "medium"):
                recovered_names[entry["name"]] += 1

        if resolve_closure:
            closure = resolve_link_closure(metadata, path, root=root)
            if closure.get("missing"):
                stats["with_missing_dependencies"] += 1
            if closure.get("risky_search_paths"):
                stats["with_risky_search_path"] += 1

    return {
        "stats": stats,
        "libc": dict(libc_counts.most_common()),
        "providers": dict(provider_counts.most_common(30)),
        "unparsed_version_nodes": dict(unparsed_nodes.most_common(20)),
        "glibc_floors": dict(sorted(glibc_floors.items())),
        "implementation_specific_imports": dict(implementation_imports.most_common(25)),
        "recovered_dependencies": dict(recovered_names.most_common(25)),
        "failures": failures[:50],
    }


def print_report(report: dict):
    """Print the sweep result in a form that is quick to scan."""
    stats = report["stats"]
    print(f"\nAnalyzed {stats['analyzed']} objects, {stats['failed']} failed to parse.\n")

    print("C library:")
    for name, count in report["libc"].items():
        print(f"  {name:<12} {count}")

    if report["glibc_floors"]:
        print("\nMinimum glibc version required:")
        for version, count in report["glibc_floors"].items():
            print(f"  {version:<12} {count}")

    print("\nABI features:")
    for key in (
        "with_requirements",
        "with_ifunc",
        "with_tls",
        "with_unique_symbols",
        "with_implementation_specific_imports",
        "with_private_version_nodes",
        "with_recovered_dependencies",
        "with_missing_dependencies",
        "with_risky_search_path",
    ):
        print(f"  {key:<40} {stats[key]}")

    if report["unparsed_version_nodes"]:
        # Every entry here is a node the grammar did not understand, which is
        # the signal this harness exists to produce.
        print("\nVersion nodes with no parsed version (check the node grammar):")
        for provider, count in report["unparsed_version_nodes"].items():
            print(f"  {provider:<30} {count}")

    if report["implementation_specific_imports"]:
        print("\nMost common C library implementation internals:")
        for name, count in report["implementation_specific_imports"].items():
            print(f"  {name:<40} {count}")

    if report["recovered_dependencies"]:
        print("\nMost common runtime-loaded libraries recovered:")
        for name, count in report["recovered_dependencies"].items():
            print(f"  {name:<40} {count}")

    if report["failures"]:
        print(f"\nFirst {len(report['failures'])} failures:")
        for failure in report["failures"]:
            print(f"  {failure['path']}: {failure['error']}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", help="Directory to sweep for ELF objects")
    parser.add_argument(
        "--limit", type=int, default=0, help="Stop after this many objects (0 for no limit)"
    )
    parser.add_argument(
        "--resolve-closure",
        action="store_true",
        help="Also resolve each object's dependency closure against the filesystem",
    )
    parser.add_argument("--json", dest="json_out", help="Write the full report to this file")
    args = parser.parse_args()

    paths = find_objects(args.root, args.limit)
    print(f"Found {len(paths)} ELF objects under {args.root}")
    if not paths:
        return 1
    report = sweep(paths, args.resolve_closure, "/")
    print_report(report)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
        print(f"\nFull report written to {args.json_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
