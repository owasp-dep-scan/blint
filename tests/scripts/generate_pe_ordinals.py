#!/usr/bin/env python3
"""Regenerate blint/data/pe_ordinals.yml from the ordinal-stable System32 DLLs.

Some Windows DLLs are imported by ordinal far too often to leave the numbers
unread: ``ws2_32`` (its first 23 ordinals are the classic WinSock calls),
``mpr``, ``oleaut32`` (the BSTR/VARIANT pair), ``shlwapi``, ``netapi32`` and
``wsock32``. blint resolves those imports through this generated snapshot and
marks the entries ``resolution: "ordinal_table"``; ordinals outside the
snapshot stay ordinals with ``resolution: "unresolved"`` (plan 01/A.6).

Ordinal assignments are per-build facts, so the snapshot records the Windows
build and the exact source files (sha256) it was generated from. Regenerate
against a newer build by copying that build's DLLs and re-running; every
positive in the data is then traceable to a file.

Usage:
    .venv/bin/python tests/scripts/generate_pe_ordinals.py \\
        <dir-with-the-six-dlls> --build "10.0.26100.9278" \\
        -o blint/data/pe_ordinals.yml
"""

import argparse
import hashlib
import sys
from pathlib import Path

import lief

# The DLLs the plan scopes: ordinals stable and common enough to resolve.
ORDINAL_DLLS = ("ws2_32.dll", "mpr.dll", "oleaut32.dll", "shlwapi.dll", "netapi32.dll", "wsock32.dll")


def parse_dll(path: Path) -> dict[int, str]:
    """One DLL's ordinal -> export-name map, forwarders included.

    Forwarder exports keep their own name (``wsock32`` ordinal 1 is named
    ``accept`` and forwards to ``ws2_32.accept``); the name is what an
    import of that ordinal binds to, so that is what the snapshot records.
    """
    parsed = lief.PE.parse(str(path))
    export = parsed.get_export()
    if not export:
        raise ValueError(f"{path.name} has no export table")
    ordinals: dict[int, str] = {}
    for entry in export.entries:
        if entry.name and entry.ordinal:
            ordinals[int(entry.ordinal)] = entry.name
    return ordinals


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("source_dir", type=Path, help="directory holding the source DLLs")
    parser.add_argument("--build", required=True, help="Windows build the DLLs came from")
    parser.add_argument(
        "-o", "--output", type=Path, default=Path("blint/data/pe_ordinals.yml")
    )
    args = parser.parse_args()

    lines = [
        "# blint's ordinal resolution table (PE lane W1.2, plan 01/A.6).",
        "#",
        f"# Source: System32 DLLs from a Windows build {args.build} installation.",
        "# Ordinal assignments are per-build facts; the sha256 values below pin",
        "# the exact files this table was generated from. Regenerate with",
        "# tests/scripts/generate_pe_ordinals.py against a newer build when the",
        "# covered DLLs change their assignments.",
        "#",
        "# DLL keys are lowercased module names; ordinals map to the export name",
        "# (forwarder exports record their own name). Ordinals absent here stay",
        "# unresolved at runtime - they are never guessed.",
        "",
        f"source_build: \"{args.build}\"",
        "source_files:",
    ]
    tables: dict[str, dict[int, str]] = {}
    for dll_name in ORDINAL_DLLS:
        path = args.source_dir / dll_name
        if not path.exists():
            print(f"missing source DLL: {path}", file=sys.stderr)
            sys.exit(1)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"  {dll_name}: {digest}")
        tables[dll_name] = parse_dll(path)
    lines.append("ordinals:")
    for dll_name in ORDINAL_DLLS:
        lines.append(f"  {dll_name}:")
        for ordinal in sorted(tables[dll_name]):
            lines.append(f"    {ordinal}: {tables[dll_name][ordinal]}")
    args.output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    total = sum(len(t) for t in tables.values())
    print(f"wrote {args.output}: {len(tables)} DLLs, {total} ordinals")


if __name__ == "__main__":
    main()
