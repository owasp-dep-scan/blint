# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT
"""Hand-built ELF64 fixtures for the layout-coherence reviews.

The reviews under test exist because of a published attack that adds an
implant to a finished ELF without changing one original byte: append the
payload plus a fresh section header table at EOF, retype a spare ``PT_NOTE``
program header into an executable ``PT_LOAD`` covering the appended bytes,
and point ``e_entry`` and ``e_shoff`` at them (arXiv 2607.24888, carried
through GNU ``strip`` across the NixOS bootstrap).

Rather than ship a malicious binary, the builders below produce a minimal but
genuinely well-formed ELF that lief parses like any other, and then apply the
paper's three transformations to it. ``implanted_elf`` reproduces the paper's
layout exactly — including the section header table landing *after* the
payload, which is why the executable mapping does not reach end-of-file
there; ``appended_exec_segment_elf`` covers the simpler appender that pads
its mapping to EOF. Keeping the two apart is deliberate: a fixture shaped to
make a check fire proves nothing about the check.
"""

from __future__ import annotations

import struct

PAGE = 0x1000
IMAGE_BASE = 0x400000

# ELF constants used below; spelled out rather than imported so the fixture
# does not depend on the same enum tables the code under test uses.
ET_EXEC = 2
EM_X86_64 = 62
PT_LOAD = 1
PT_NOTE = 4
PF_X, PF_W, PF_R = 1, 2, 4
SHT_PROGBITS, SHT_NOTE, SHT_STRTAB = 1, 7, 3
SHF_ALLOC, SHF_EXECINSTR = 0x2, 0x4

EHDR_SIZE, PHDR_SIZE, SHDR_SIZE = 64, 56, 64

# Offsets inside the clean image.
PHDR_OFF = EHDR_SIZE
NOTE_OFF = 0x100
TEXT_OFF = 0x200
SHSTRTAB_OFF = 0x300
SHDR_OFF = 0x400
CLEAN_SIZE = SHDR_OFF + 4 * SHDR_SIZE

_TEXT = b"\x48\x31\xc0\xc3"  # xor rax, rax; ret
_NOTE = struct.pack("<III", 4, 16, 3) + b"GNU\x00" + bytes(range(16))
_SHSTRTAB = b"\x00.text\x00.note.gnu.build-id\x00.shstrtab\x00.payload\x00"


def _name_offset(name: str) -> int:
    return _SHSTRTAB.index(name.encode() + b"\x00")


def _shdr(name: str, sh_type: int, flags: int, addr: int, offset: int, size: int) -> bytes:
    return struct.pack(
        "<IIQQQQIIQQ",
        _name_offset(name) if name else 0,
        sh_type,
        flags,
        addr,
        offset,
        size,
        0,
        0,
        1,
        0,
    )


def _phdr(p_type: int, flags: int, offset: int, vaddr: int, size: int) -> bytes:
    return struct.pack("<IIQQQQQQ", p_type, flags, offset, vaddr, 0, size, size, PAGE)


def _ehdr(entry: int, shoff: int, phnum: int, shnum: int) -> bytes:
    return (
        b"\x7fELF\x02\x01\x01\x00" + bytes(8)
        + struct.pack(
            "<HHIQQQIHHHHHH",
            ET_EXEC,
            EM_X86_64,
            1,
            entry,
            PHDR_OFF,
            shoff,
            0,
            EHDR_SIZE,
            PHDR_SIZE,
            phnum,
            SHDR_SIZE,
            shnum,
            3,
        )
    )


def clean_elf() -> bytearray:
    """A minimal, coherent ELF64: entry in ``.text``, notes under ``PT_NOTE``."""
    image = bytearray(CLEAN_SIZE)
    entry = IMAGE_BASE + TEXT_OFF
    # Two load segments, as a linker emits them: a read-only one over the
    # headers and notes, and a separate executable one over .text that stops
    # well before the string table and the section header table. A single
    # LOAD spanning the whole file would make the clean fixture trip
    # executable_mapping_at_eof, which is a property of that shortcut and not
    # of a real image.
    phdrs = (
        _phdr(PT_LOAD, PF_R, 0, IMAGE_BASE, TEXT_OFF)
        + _phdr(PT_LOAD, PF_R | PF_X, TEXT_OFF, entry, len(_TEXT))
        + _phdr(PT_NOTE, PF_R, NOTE_OFF, IMAGE_BASE + NOTE_OFF, len(_NOTE))
    )
    shdrs = (
        _shdr("", 0, 0, 0, 0, 0)
        + _shdr(".text", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, entry, TEXT_OFF, len(_TEXT))
        + _shdr(
            ".note.gnu.build-id",
            SHT_NOTE,
            SHF_ALLOC,
            IMAGE_BASE + NOTE_OFF,
            NOTE_OFF,
            len(_NOTE),
        )
        + _shdr(".shstrtab", SHT_STRTAB, 0, 0, SHSTRTAB_OFF, len(_SHSTRTAB))
    )
    image[0:EHDR_SIZE] = _ehdr(entry, SHDR_OFF, 3, 4)
    image[PHDR_OFF : PHDR_OFF + len(phdrs)] = phdrs
    image[NOTE_OFF : NOTE_OFF + len(_NOTE)] = _NOTE
    image[TEXT_OFF : TEXT_OFF + len(_TEXT)] = _TEXT
    image[SHSTRTAB_OFF : SHSTRTAB_OFF + len(_SHSTRTAB)] = _SHSTRTAB
    image[SHDR_OFF : SHDR_OFF + len(shdrs)] = shdrs
    return image


_PAYLOAD = bytes(range(64))


def implanted_elf() -> bytearray:
    """The paper's three transformations applied to :func:`clean_elf`.

    Append the payload and a new section header table registering
    ``.payload``; retype the spare ``PT_NOTE`` header into an executable
    ``PT_LOAD`` covering the payload; redirect ``e_entry`` into ``.payload``
    and ``e_shoff`` at the new table. Every original byte survives, and the
    old section header table stays in the file, orphaned.
    """
    image = clean_elf()
    payload_off = len(image)
    payload_vaddr = IMAGE_BASE + 0x100000
    image += _PAYLOAD
    new_shoff = len(image)
    image += (
        _shdr("", 0, 0, 0, 0, 0)
        + _shdr(".text", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, IMAGE_BASE + TEXT_OFF, TEXT_OFF, len(_TEXT))
        + _shdr(".note.gnu.build-id", SHT_NOTE, SHF_ALLOC, IMAGE_BASE + NOTE_OFF, NOTE_OFF, len(_NOTE))
        + _shdr(".shstrtab", SHT_STRTAB, 0, 0, SHSTRTAB_OFF, len(_SHSTRTAB))
        + _shdr(
            ".payload",
            SHT_PROGBITS,
            SHF_ALLOC | SHF_EXECINSTR,
            payload_vaddr,
            payload_off,
            len(_PAYLOAD),
        )
    )
    # Repurpose: the PT_NOTE header becomes an executable PT_LOAD.
    note_phdr_off = PHDR_OFF + 2 * PHDR_SIZE
    image[note_phdr_off : note_phdr_off + PHDR_SIZE] = _phdr(
        PT_LOAD, PF_R | PF_X, payload_off, payload_vaddr, len(_PAYLOAD)
    )
    # Redirect: entry into the payload, section table to the appended one.
    image[0:EHDR_SIZE] = _ehdr(payload_vaddr, new_shoff, 3, 5)
    return image


def appended_exec_segment_elf() -> bytearray:
    """A simpler appender: executable mapping padded to end-of-file.

    Same repurposed ``PT_NOTE``, but no new section header table, so the
    executable mapping runs to the last byte of the file. This is the shape
    ``executable_mapping_at_eof`` describes; ``implanted_elf`` deliberately
    does not have it.
    """
    image = clean_elf()
    payload_off = len(image)
    payload_vaddr = IMAGE_BASE + 0x100000
    image += _PAYLOAD
    note_phdr_off = PHDR_OFF + 2 * PHDR_SIZE
    image[note_phdr_off : note_phdr_off + PHDR_SIZE] = _phdr(
        PT_LOAD, PF_R | PF_X, payload_off, payload_vaddr, len(_PAYLOAD)
    )
    return image
