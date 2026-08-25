"""Tests for embedded cryptographic constant and opaque payload detection."""

import random
import struct

from blint.lib.crypto_constants import (
    MIN_REGION_SIZE,
    analyze_crypto_material,
    find_crypto_constants,
    find_high_entropy_regions,
    find_permutation_tables,
)

SHA256_K_TABLE = struct.pack("<4I", 0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5)
AES_SBOX_HEAD = bytes.fromhex("637c777bf26b6fc53001672bfed7ab76")
CRC32_REFLECTED_POLY = struct.pack("<I", 0xEDB88320)


def _padded(payload: bytes, offset: int = 64, total: int = 1024) -> bytes:
    """Place a payload inside an otherwise structured, low-entropy section."""
    body = bytearray(b"\x00" * total)
    body[offset : offset + len(payload)] = payload
    return bytes(body)


def test_identifies_sha256_round_constants():
    findings = find_crypto_constants([(".rdata", _padded(SHA256_K_TABLE))])
    assert findings
    entry = findings[0]
    assert entry["algorithm"] == "SHA-256"
    assert entry["constant"] == "round constant table"
    assert entry["confidence"] == "high"
    assert entry["offset"] == "0x40"


def test_identifies_aes_substitution_box():
    findings = find_crypto_constants([(".rdata", _padded(AES_SBOX_HEAD))])
    assert [f["algorithm"] for f in findings] == ["AES"]


def test_four_byte_polynomial_is_medium_confidence():
    """A short constant can occur by chance, so it must not claim high confidence."""
    findings = find_crypto_constants([(".text", _padded(CRC32_REFLECTED_POLY))])
    assert findings[0]["algorithm"] == "CRC-32"
    assert findings[0]["confidence"] == "medium"


def test_only_scanned_sections_are_read():
    """A constant in .rsrc is a resource, not evidence about the program's code."""
    assert find_crypto_constants([(".rsrc", _padded(SHA256_K_TABLE))]) == []
    assert find_crypto_constants([(".reloc", _padded(SHA256_K_TABLE))]) == []


def test_base32_alphabet_is_identified():
    section = _padded(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    findings = find_crypto_constants([(".rdata", section)])
    assert ("Base32", "RFC 4648 alphabet") in [(f["algorithm"], f["constant"]) for f in findings]


def test_no_constants_yields_no_findings():
    assert find_crypto_constants([(".rdata", b"\x00" * 4096)]) == []
    assert find_crypto_constants(None) == []
    assert find_crypto_constants([]) == []


def test_permutation_table_detected():
    """A 256-byte table holding every byte value once is a substitution box."""
    table = bytes(range(256))
    tables = find_permutation_tables([(".rdata", b"\x00" * 64 + table + b"\x00" * 64)])
    assert tables
    assert tables[0]["size"] == 256
    assert tables[0]["offset"] == "0x40"


def test_structured_data_is_not_a_permutation_table():
    # A table of small little-endian RVAs: many repeated high bytes.
    rvas = b"".join(struct.pack("<I", 0x1000 + index * 16) for index in range(64))
    assert find_permutation_tables([(".rdata", rvas)]) == []


def test_opaque_region_is_reported_with_its_section_share():
    # A fixed seed rather than os.urandom, so the recovered geometry is stable
    # across runs. `bytes(range(256))` is unsuitable as a stand-in for
    # ciphertext: its 0x20-0x3F stretch is entirely printable and is correctly
    # rejected, which splits the region.
    blob = random.Random(1234).randbytes(1024)
    section = b"\x00" * 128 + blob + b"\x00" * 128
    regions = find_high_entropy_regions([(".data", section)])
    assert regions
    region = regions[0]
    assert region["size"] >= MIN_REGION_SIZE
    assert region["section_size"] == len(section)
    # The share of the section is what later distinguishes a payload from a table.
    assert region["section_fraction"] > 0.25
    # Nothing outside the blob may be claimed.
    assert int(region["offset"], 16) >= 128


def test_printable_text_is_not_an_opaque_region():
    """An alphabet table has maximum window entropy but is plainly not ciphertext.

    SLEEPWALKER's own .data contains a lowercase alphabet run that satisfies the
    distinct-byte test, so without the printable check it would be reported as
    key material.
    """
    alphabet = bytes(range(0x20, 0x7F)) * 8
    assert find_high_entropy_regions([(".data", alphabet)]) == []


def test_identified_tables_are_excluded_from_opaque_regions():
    """A named constant table must not also be reported as unknown ciphertext."""
    table = bytes(range(256))
    section = b"\x00" * 64 + table + b"\x00" * 64
    tables = find_permutation_tables([(".rdata", section)])
    with_exclusion = find_high_entropy_regions([(".rdata", section)], None, tables)
    assert with_exclusion == []
    # Without being told about the table, the same bytes do look opaque.
    assert find_high_entropy_regions([(".rdata", section)])


def test_small_regions_are_not_reported():
    """A single hash or GUID is unremarkable in ordinary binaries."""
    section = b"\x00" * 128 + random.Random(7).randbytes(32) + b"\x00" * 128
    assert find_high_entropy_regions([(".data", section)]) == []


def test_analyze_returns_empty_for_a_plain_binary():
    assert analyze_crypto_material([(".rdata", b"\x00" * 2048)]) == {}
    assert analyze_crypto_material(None) == {}


def test_analyze_combines_algorithms_and_regions():
    section = _padded(SHA256_K_TABLE, total=2048)
    data = b"\x00" * 64 + random.Random(99).randbytes(1024) + b"\x00" * 64
    result = analyze_crypto_material([(".rdata", section), (".data", data)])
    assert result["algorithms"] == ["SHA-256"]
    assert any(region["section"] == ".data" for region in result["opaque_regions"])
