# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT
"""Hand-built ELF64 and Mach-O64 fixtures that embed a GraalVM-style SBOM.

A native image built with SBOM embedding exports two global symbols: ``sbom``,
whose value is the address of a gzip-compressed CycloneDX JSON payload, and
``sbom_length``, whose address holds the payload's size as an 8-byte
little-endian unsigned integer. The builders below produce minimal but
genuinely well-formed binaries that carry exactly those symbols, so the reader
is exercised through the same LIEF lookups a real Quarkus or Oracle GraalVM
image presents. Variants drop a symbol, lie about the size, or corrupt the
payload, which is how the reader's refusals are tested.
"""

from __future__ import annotations

import gzip
import json
import struct

# ELF64 constants, spelled out so the fixture mirrors the format rather than
# the tables the code under test uses.
ET_EXEC = 2
EM_X86_64 = 62
EV_CURRENT = 1
PT_LOAD = 1
PF_R = 4
SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHF_ALLOC = 0x2
STB_GLOBAL = 1
STT_OBJECT = 1

EHDR_SIZE = 64
PHDR_SIZE = 56
SHDR_SIZE = 64
SYM_SIZE = 24

ELF_BASE = 0x400000
SYMBOLS_OFF = 0x200

# Mach-O 64 constants.
MH_MAGIC_64 = 0xFEEDFACF
MH_EXECUTE = 2
CPU_TYPE_X86_64 = 0x01000007
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
N_EXT = 0x01
N_SECT = 0x0E

MHDR_SIZE = 32
SEGMENT_CMD_SIZE = 72
SECTION_CMD_SIZE = 80
SYMTAB_CMD_SIZE = 24
NLIST_SIZE = 16

MACHO_VM_BASE = 0x100000000


def cyclonedx_document() -> dict:
    """A small, real-looking CycloneDX document like the ones Quarkus embeds."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": "urn:uuid:9a8b7c6d-5e4f-4a3b-2c1d-0e9f8a7b6c5d",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "getting-started",
                "version": "1.0.0-SNAPSHOT",
            },
        },
        "components": [
            {
                "type": "library",
                "bom-ref": "pkg:maven/io.quarkus/quarkus-core@4.0.1?type=jar",
                "group": "io.quarkus",
                "name": "quarkus-core",
                "version": "4.0.1",
                "purl": "pkg:maven/io.quarkus/quarkus-core@4.0.1?type=jar",
                "hashes": [{"alg": "SHA-256", "content": "a" * 64}],
                "licenses": [{"license": {"id": "Apache-2.0"}}],
            },
            {
                "type": "library",
                "bom-ref": "pkg:maven/io.smallrye.reactive/mutiny@3.2.0?type=jar",
                "group": "io.smallrye.reactive",
                "name": "mutiny",
                "version": "3.2.0",
                "purl": "pkg:maven/io.smallrye.reactive/mutiny@3.2.0?type=jar",
            },
        ],
        "dependencies": [
            {
                "ref": "pkg:maven/io.quarkus/quarkus-core@4.0.1?type=jar",
                "dependsOn": ["pkg:maven/io.smallrye.reactive/mutiny@3.2.0?type=jar"],
            },
        ],
    }


def _compact(document: dict) -> str:
    return json.dumps(document, separators=(",", ":"))


def gzip_document(document: dict) -> bytes:
    """The gzip wrapper the sbom symbol carries, not raw deflate."""
    return gzip.compress(_compact(document).encode(), mtime=0)


def bomb_document(pad_mib: int = 33) -> bytes:
    """A gzip bomb: a document that inflates past the decompressed cap."""
    filler = "x" * (pad_mib * 1024 * 1024)
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "components": [
            {"type": "library", "name": "pad", "purl": f"pkg:generic/pad?x={filler}"}
        ],
    }
    return gzip.compress(_compact(document).encode(), mtime=0)


def _elf_sym(name_offset: int, address: int, size: int) -> bytes:
    return struct.pack(
        "<IBBHQQ",
        name_offset,
        (STB_GLOBAL << 4) | STT_OBJECT,
        0,
        1,
        address,
        size,
    )


def build_elf(
    payload: bytes,
    include_sbom: bool = True,
    include_length: bool = True,
    declared_length: int | None = None,
    mapped_bytes: int | None = None,
) -> bytes:
    """An ELF64 whose ``sbom`` and ``sbom_length`` symbols describe ``payload``.

    ``declared_length`` replaces the length word, so a fixture can lie about
    the size. ``mapped_bytes`` shrinks the loadable segment, so a fixture can
    make the declared size read past the mapped memory. Either symbol can be
    omitted.
    """
    length = declared_length if declared_length is not None else len(payload)
    symbols_blob = payload + struct.pack("<Q", length)

    strtab = b"\0sbom\0sbom_length\0"
    symtab: bytes = struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)
    if include_sbom:
        symtab += _elf_sym(1, ELF_BASE + SYMBOLS_OFF, len(payload))
    if include_length:
        symtab += _elf_sym(
            6, ELF_BASE + SYMBOLS_OFF + len(payload), 8
        )
    strtab_off = SYMBOLS_OFF + len(symbols_blob)
    symtab_off = strtab_off + len(strtab)
    shstrtab = b"\0.load\0.symtab\0.strtab\0.shstrtab\0"
    shstrtab_off = symtab_off + len(symtab)
    shdr_off = shstrtab_off + len(shstrtab)
    total = shdr_off + 5 * SHDR_SIZE
    mapped_size = mapped_bytes if mapped_bytes is not None else total

    ident = struct.pack(
        "<16B",
        0x7F,
        ord("E"),
        ord("L"),
        ord("F"),
        2,
        1,
        EV_CURRENT,
        *([0] * 9),
    )
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident,
        ET_EXEC,
        EM_X86_64,
        EV_CURRENT,
        0,
        EHDR_SIZE,
        shdr_off,
        0,
        EHDR_SIZE,
        PHDR_SIZE,
        1,
        SHDR_SIZE,
        5,
        4,
    )
    phdr = struct.pack(
        "<IIQQQQQQ",
        PT_LOAD,
        PF_R,
        0,
        ELF_BASE,
        0,
        mapped_size,
        mapped_size,
        0x1000,
    )
    shdrs = b"".join(
        [
            struct.pack("<IIQQQQIIQQ", *([0] * 10)),
            struct.pack(
                "<IIQQQQIIQQ",
                1,
                SHT_PROGBITS,
                SHF_ALLOC,
                ELF_BASE + SYMBOLS_OFF,
                SYMBOLS_OFF,
                len(symbols_blob),
                0,
                0,
                1,
                0,
            ),
            struct.pack(
                "<IIQQQQIIQQ",
                7,
                SHT_SYMTAB,
                0,
                0,
                symtab_off,
                len(symtab),
                3,
                1,
                8,
                SYM_SIZE,
            ),
            struct.pack(
                "<IIQQQQIIQQ", 15, SHT_STRTAB, 0, 0, strtab_off, len(strtab), 0, 0, 1, 0
            ),
            struct.pack(
                "<IIQQQQIIQQ", 23, SHT_STRTAB, 0, 0, shstrtab_off, len(shstrtab), 0, 0, 1, 0
            ),
        ]
    )
    return (
        bytearray(ehdr)
        + bytearray(phdr)
        + bytearray(b"\0" * (SYMBOLS_OFF - EHDR_SIZE - PHDR_SIZE))
        + bytearray(symbols_blob)
        + bytearray(strtab)
        + bytearray(symtab)
        + bytearray(shstrtab)
        + bytearray(shdrs)
    )


def _macho_sym(name_offset: int, address: int) -> bytes:
    return struct.pack("<IBBHQ", name_offset, N_EXT | N_SECT, 1, 0, address)


def build_macho(
    payload: bytes,
    include_sbom: bool = True,
    include_length: bool = True,
    declared_length: int | None = None,
) -> bytes:
    """A single-arch Mach-O64 whose symbol table carries ``_sbom`` and
    ``_sbom_length``; Mach-O prefixes global C symbols with an underscore."""
    length = declared_length if declared_length is not None else len(payload)
    symbols_blob = payload + struct.pack("<Q", length)

    strtab = b"\0_sbom\0_sbom_length\0"
    header_size = MHDR_SIZE + SEGMENT_CMD_SIZE + SECTION_CMD_SIZE + SYMTAB_CMD_SIZE
    symtab_off = header_size + len(symbols_blob)
    strtab_off = symtab_off + 2 * NLIST_SIZE
    total = strtab_off + len(strtab)

    syms = b""
    if include_sbom:
        syms += _macho_sym(1, MACHO_VM_BASE + header_size)
    if include_length:
        syms += _macho_sym(7, MACHO_VM_BASE + header_size + len(payload))

    section = struct.pack(
        "<16s16sQQIIIIIIII",
        b"__sbom",
        b"__TEXT",
        MACHO_VM_BASE + header_size,
        len(symbols_blob),
        header_size,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    )
    segment = struct.pack(
        "<II16sQQQQiiII",
        LC_SEGMENT_64,
        SEGMENT_CMD_SIZE + SECTION_CMD_SIZE,
        b"__TEXT",
        MACHO_VM_BASE,
        total,
        0,
        total,
        5,
        5,
        1,
        0,
    ) + section
    nsyms = sum([include_sbom, include_length])
    symtab_cmd = struct.pack(
        "<IIIIII",
        LC_SYMTAB,
        SYMTAB_CMD_SIZE,
        symtab_off,
        nsyms,
        strtab_off,
        len(strtab),
    )
    mhdr = struct.pack(
        "<IIIiIIiI",
        MH_MAGIC_64,
        CPU_TYPE_X86_64,
        3,
        MH_EXECUTE,
        2,
        len(segment) + len(symtab_cmd),
        0,
        0x200000,
    )
    return (
        bytearray(mhdr + segment + symtab_cmd)
        + bytearray(symbols_blob)
        + bytearray(syms)
        + bytearray(strtab)
    )
