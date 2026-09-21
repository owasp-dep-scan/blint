#!/usr/bin/env python3
"""Regenerate blint/data/pe_apisets.yml from an apisetschema.dll.

API sets (``api-ms-win-core-*``) are loader-virtual DLLs: the schema carried
in ``C:\\Windows\\System32\\apisetschema.dll`` binds each contract name to
the host DLL the loader actually maps. blint resolves imports through a
generated snapshot of that schema so dependency lists, dependency-graph
checks and SBOM ``dependsOn`` name real DLLs on modern Windows
(plan 01/A.6). The snapshot records the Windows build it came from; a
contract newer than the snapshot simply stays unresolved.

Schema layout (Windows 10+, documented by Geoff Chappell's API Set work and
the Quarkslab apiset studies; validated here against known resolutions such
as api-ms-win-crt-runtime-l1-1-0 -> ucrtbase.dll): a 28-byte
API_SET_NAMESPACE header, then API_SET_NAMESPACE_ENTRY records (24 bytes),
then per-entry API_SET_VALUE_ENTRY records (20 bytes). Offsets are from the
start of the schema blob, names are UTF-16LE without the ``.dll`` extension.
Each entry's first value is the host the loader substitutes; later values
carry alias bindings for importing modules and are not followed.

Recent builds drop old contract versions from the schema entirely (a
Windows 11 25H2-schema has no ``api-ms-win-core-synch-l1-1-0`` row) while
binaries importing those names still ship. The loader resolves them through
the physical stub DLLs in ``C:\\Windows\\System32\\downlevel\\`` — real DLLs
whose every export forwards to the host (``dumpbin /exports`` proves it).
Pass that directory via ``--downlevel-dir`` and the generator folds each
stub's forwarder target in as the binding for its name. Schema rows win:
they are the loader's own table.

Usage:
    .venv/bin/python tests/scripts/generate_pe_apisets.py \\
        <apisetschema.dll> --build "10.0.26100.9278" \\
        [--downlevel-dir <dir-with-downlevel-api-ms-dlls>] \\
        -o blint/data/pe_apisets.yml

The source file is copied out of a Windows installation (for this lane: the
Windows 11 ARM64 VM's System32, which is also the tier-5 corpus slice); the
generated YAML, not the DLL, ships with blint.
"""

import argparse
import hashlib
import struct
import sys
from pathlib import Path

import lief

NAMESPACE_HEADER = struct.Struct("<7I")
NAMESPACE_ENTRY = struct.Struct("<6I")
VALUE_ENTRY = struct.Struct("<5I")


def utf16(blob: bytes, offset: int, length: int) -> str:
    return blob[offset : offset + length].decode("utf-16-le", errors="replace")


def parse_schema(data: bytes) -> dict[str, str]:
    if len(data) < NAMESPACE_HEADER.size:
        raise ValueError("schema blob shorter than the namespace header")
    version, _size, _flags, count, entry_offset, _hash_offset, _factor = (
        NAMESPACE_HEADER.unpack_from(data, 0)
    )
    if version < 2 or count == 0 or count > 100_000:
        raise ValueError(f"implausible schema header: version={version} count={count}")
    api_sets: dict[str, str] = {}
    for index in range(count):
        entry_base = entry_offset + index * NAMESPACE_ENTRY.size
        if entry_base + NAMESPACE_ENTRY.size > len(data):
            raise ValueError(f"entry {index} past end of schema")
        _flags, name_off, name_len, _hashed_len, value_off, value_count = (
            NAMESPACE_ENTRY.unpack_from(data, entry_base)
        )
        name = utf16(data, name_off, name_len)
        if not name or not value_count:
            continue
        value_base = value_off
        if value_base + VALUE_ENTRY.size > len(data):
            continue
        _vflags, _alias_off, _alias_len, host_off, host_len = VALUE_ENTRY.unpack_from(
            data, value_base
        )
        # The first value is the primary host; later values bind aliases for
        # specific importing modules and are not dependency answers.
        host = utf16(data, host_off, host_len) if host_len else ""
        if not host:
            continue
        api_sets[name.lower()] = host.lower()
    return api_sets


def parse_downlevel_stubs(directory: Path) -> dict[str, str]:
    """Resolve api-ms names through the downlevel stub DLLs' forwarders.

    Every export of a downlevel stub forwards to the host DLL, so one
    forwarder is enough to bind the stub's name. Stub names keep the
    ``.dll`` extension; the schema's key convention (stem, lowercased) is
    applied here.
    """
    resolved: dict[str, str] = {}
    for path in sorted(directory.glob("*.dll")):
        try:
            parsed = lief.PE.parse(str(path))
            export = parsed.get_export()
            for entry in export.entries:
                if entry.is_forwarded and entry.forward_information:
                    library = entry.forward_information.library
                    if library:
                        host = library.strip().lower()
                        if not host.endswith(".dll"):
                            host = f"{host}.dll"
                        resolved[path.stem.lower()] = host
                        break
        except (AttributeError, TypeError, ValueError) as exc:
            print(f"skipping {path.name}: {exc}", file=sys.stderr)
    return resolved


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("schema_dll", type=Path, help="path to apisetschema.dll")
    parser.add_argument("--build", required=True, help="Windows build the DLL came from")
    parser.add_argument(
        "--downlevel-dir",
        type=Path,
        default=None,
        help="directory holding the downlevel api-ms stub DLLs (System32\\downlevel)",
    )
    parser.add_argument(
        "-o", "--output", type=Path, default=Path("blint/data/pe_apisets.yml")
    )
    args = parser.parse_args()

    data = args.schema_dll.read_bytes()
    # The schema blob lives in the .apiset section; find it via the section
    # table rather than assuming an offset.
    api_sets = {}
    if data[:2] == b"MZ":
        parsed = lief.PE.parse(str(args.schema_dll))
        sections = [
            (s.name, int(s.offset), int(s.size))
            for s in parsed.sections
        ]
        blobs = [data[off : off + size] for name, off, size in sections if name == ".apiset"]
        if not blobs:
            print("no .apiset section found", file=sys.stderr)
            sys.exit(1)
        api_sets = parse_schema(blobs[0])
    else:
        api_sets = parse_schema(data)

    downlevel_count = 0
    if args.downlevel_dir:
        downlevel = parse_downlevel_stubs(args.downlevel_dir)
        # Schema rows are the loader's own table and win; the downlevel
        # stubs cover the contract versions the schema dropped.
        for name, host in downlevel.items():
            if name not in api_sets:
                api_sets[name] = host
                downlevel_count += 1

    lines = [
        "# blint's API set resolution snapshot (PE lane W1.2, plan 01/A.6).",
        "#",
        f"# Source: apisetschema.dll from a Windows build {args.build} installation;",
        f"# schema sha256 {hashlib.sha256(data).hexdigest()}.",
    ]
    if downlevel_count:
        lines.append(
            f"# Plus {downlevel_count} contract versions resolved through the"
            " System32\\downlevel stub DLLs' forwarder exports (the schema"
            " dropped these rows; the loader maps the stubs)."
        )
    lines += [
        "# Regenerate with tests/scripts/generate_pe_apisets.py after replacing the",
        "# source DLL. Contract names are lowercased without the .dll extension;",
        "# values are the host DLL the loader maps, first schema value only.",
        "# A contract missing here (a newer Windows build's additions) stays",
        "# unresolved at runtime by design - it is never guessed.",
        "#",
        "# The loader reads this same schema at image load, so these bindings are",
        "# the ground truth for which DLL an api-ms-* import costs.",
        "",
        f"source_build: \"{args.build}\"",
        "schema_version: 6",
        "api_sets:",
    ]
    for name in sorted(api_sets):
        lines.append(f"  {name}: {api_sets[name]}")
    args.output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {args.output}: {len(api_sets)} api sets")


if __name__ == "__main__":
    main()
