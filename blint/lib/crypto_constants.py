"""Detection of embedded cryptographic primitives and encrypted payload regions.

blint infers cryptography behaviourally, from bitwise and SIMD instruction
density. That says a function looks like a cipher; it does not say which one, and
it says nothing at all about a statically linked crypto library whose work
happens inside a routine the disassembler never classified.

The constants are what identify the primitive. A software SHA-256 has to carry
its 64 round constants, a CRC-32 has to carry its polynomial, and a Base32 codec
has to carry its alphabet. These are fixed by the specification, so matching them
names the algorithm outright.

Two things this module deliberately does not assume. Absence of a table is not
absence of the algorithm: an AES built against AES-NI carries no tables at all,
and mbedTLS with runtime table generation leaves only zero-filled BSS - which is
why SLEEPWALKER shows SHA-256 and CRC-32 constants but no AES S-box, despite
being an AES-256-CCM implant. And a matched constant proves the primitive is
present, never that its use is malicious; every TLS stack matches several.

The second half of the module looks for what the primitive operates on. A
contiguous high-entropy region inside an otherwise structured data section is
either key material or an encrypted blob, and in a small binary with no packer
section layout it is the embedded payload. SLEEPWALKER's is ~2KB at ``.data``
offset 128, holding its AES-256-CCM key, nonce and encrypted bootstrap program.
"""

import math
import struct
from collections import Counter
from collections.abc import Iterable


def _le32(*words: int) -> bytes:
    """Pack 32-bit constants as they appear in a little-endian image."""
    return struct.pack(f"<{len(words)}I", *words)


def _le64(*words: int) -> bytes:
    """Pack 64-bit constants as they appear in a little-endian image."""
    return struct.pack(f"<{len(words)}Q", *words)


# (algorithm, what the bytes are, signature). Signatures are ordered longest
# first within an algorithm so the most specific match is the one reported.
#
# Every entry is a value fixed by the algorithm's specification, not a
# compiler-dependent artefact, so a match is a property of the primitive rather
# than of the build.
_SIGNATURES: tuple[tuple[str, str, bytes], ...] = (
    # SHA-2 round constants are the first cube roots of the primes; four of them
    # is already a 16-byte sequence no unrelated data reproduces.
    ("SHA-256", "round constant table", _le32(0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5)),
    ("SHA-256", "initialization vector", _le32(0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A)),
    ("SHA-224", "initialization vector", _le32(0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939)),
    ("SHA-512", "round constant table", _le64(0x428A2F98D728AE22, 0x7137449123EF65CD)),
    ("SHA-512", "initialization vector", _le64(0x6A09E667F3BCC908, 0xBB67AE8584CAA73B)),
    ("SHA-384", "initialization vector", _le64(0xCBBB9D5DC1059ED8, 0x629A292A367CD507)),
    ("SHA-1", "round constants", _le32(0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6)),
    # MD5 and SHA-1 share this IV, so it cannot attribute one over the other.
    ("MD5/SHA-1", "initialization vector", _le32(0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)),
    ("MD5", "sine round constant table", _le32(0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE)),
    # AES forward and inverse substitution boxes, in the byte order a ROM table
    # holds them.
    (
        "AES",
        "substitution box",
        bytes.fromhex("637c777bf26b6fc53001672bfed7ab76"),
    ),
    (
        "AES",
        "inverse substitution box",
        bytes.fromhex("52096ad53036a538bf40a39e81f3d7fb"),
    ),
    # The T-table variant precomputes the round transform instead, so a build
    # using it carries no plain S-box.
    ("AES", "encryption T-table", _le32(0xC66363A5, 0xF87C7C84, 0xEE777799, 0xF67B7B8D)),
    ("AES", "decryption T-table", _le32(0x51F4A750, 0x7E416553, 0x1A17A4C3, 0x3A275E96)),
    ("AES", "round constant table", _le32(0x00000001, 0x00000002, 0x00000004, 0x00000008)),
    # CRC polynomials. The reflected form is the one almost every implementation
    # uses, and it commonly appears as an immediate in code rather than a table.
    ("CRC-32", "table head", _le32(0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA)),
    ("CRC-32", "reflected polynomial", _le32(0xEDB88320)),
    ("CRC-32", "polynomial", _le32(0x04C11DB7)),
    ("CRC-32C", "reflected polynomial", _le32(0x82F63B78)),
    # Stream cipher setup constants, which are ASCII by specification.
    ("ChaCha20", "sigma constant", b"expand 32-byte k"),
    ("ChaCha20", "tau constant", b"expand 16-byte k"),
    ("Salsa20", "sigma constant", b"expand 32-byte k"),
    # Codec alphabets. A custom protocol that tunnels data through DNS labels or
    # text fields has to carry one of these.
    (
        "Base64",
        "standard alphabet",
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    ),
    (
        "Base64",
        "URL-safe alphabet",
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
    ),
    ("Base32", "RFC 4648 alphabet", b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"),
    ("Base32", "extended hex alphabet", b"0123456789ABCDEFGHIJKLMNOPQRSTUV"),
    # Blowfish seeds its P-array from the fractional digits of pi.
    ("Blowfish", "P-array initialisation", _le32(0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344)),
)

# A four-byte polynomial is a weaker match than a sixteen-byte table: it can in
# principle occur as an unrelated immediate, whereas a table cannot. The
# distinction is reported rather than resolved, so a reviewer can weigh it.
_HIGH_CONFIDENCE_SIGNATURE_LEN = 8

# Sections worth scanning. Tables live in read-only and initialised data;
# polynomials and initialisation vectors are frequently immediates in code.
CRYPTO_SCAN_SECTIONS: tuple[str, ...] = (".rdata", ".data", ".text", ".rodata")

# Window geometry for the entropy scan. Thirty-two bytes is the smallest unit
# worth reporting (an AES-256 key) and the step keeps the scan aligned to the
# 16-byte granularity crypto material is normally laid out on.
_ENTROPY_WINDOW = 32
_ENTROPY_STEP = 16
# Random bytes drawn from 256 values fill a 32-byte window with about 30 distinct
# values. Requiring 26 admits real key material while rejecting the structured
# data - pointer tables, RVAs, counters, UTF-16 text - that fills a data section.
_MIN_DISTINCT_BYTES = 26
# A window that is mostly printable ASCII is text or an alphabet table, not
# ciphertext, however many distinct values it holds. The lowercase alphabet in
# SLEEPWALKER's own .data is exactly this case: 32 distinct bytes, maximum
# window entropy, and plainly not key material.
_MAX_PRINTABLE_FRACTION = 0.75
# Smallest merged region reported. A single window is often a GUID, a hash or a
# public-key fingerprint, all of which are unremarkable in ordinary binaries.
MIN_REGION_SIZE = 64
# Sections whose contents are expected to be opaque. Compressed resources,
# certificates and embedded archives make a high-entropy region there
# uninformative, so they are not scanned.
ENTROPY_SCAN_SECTIONS: tuple[str, ...] = (".rdata", ".data", ".rodata")


def _shannon_entropy(data: bytes) -> float:
    """Return the Shannon entropy of a byte window in bits per byte."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def find_crypto_constants(sections: Iterable[tuple[str, bytes]] | None) -> list[dict]:
    """Identify cryptographic algorithms from the constants an image embeds.

    ``sections`` is an iterable of ``(name, data)`` pairs. Returns one entry per
    distinct (algorithm, constant) pair, naming the section and offset so the
    match can be confirmed by inspection.
    """
    findings: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for name, data in sections or ():
        if not data or str(name).lower() not in CRYPTO_SCAN_SECTIONS:
            continue
        payload = bytes(data)
        for algorithm, kind, signature in _SIGNATURES:
            if (algorithm, kind) in seen:
                continue
            offset = payload.find(signature)
            if offset < 0:
                continue
            seen.add((algorithm, kind))
            findings.append(
                {
                    "algorithm": algorithm,
                    "constant": kind,
                    "section": str(name),
                    "offset": f"0x{offset:X}",
                    "confidence": (
                        "high" if len(signature) >= _HIGH_CONFIDENCE_SIGNATURE_LEN else "medium"
                    ),
                }
            )
    findings.sort(key=lambda entry: (entry["algorithm"], entry["constant"]))
    return findings


# A table holding each of the 256 byte values exactly once is a permutation: a
# substitution box, or the byte-shuffle stage of a custom cipher or obfuscator.
# It has maximum entropy by construction, so without recognising it separately it
# would be reported as an unidentified encrypted region on every image that has
# one.
_PERMUTATION_TABLE_SIZE = 256


def find_permutation_tables(sections: Iterable[tuple[str, bytes]] | None) -> list[dict]:
    """Locate 256-byte tables that hold every byte value exactly once.

    A permutation of the full byte range is a substitution box. Recognising one
    without knowing which algorithm it belongs to is still worth reporting: a
    custom or modified S-box is precisely what a bespoke cipher carries, and it
    would not match any published constant.
    """
    tables: list[dict] = []
    for name, data in sections or ():
        if not data or str(name).lower() not in ENTROPY_SCAN_SECTIONS:
            continue
        payload = bytes(data)
        # A table is aligned in practice, and stepping by the alignment rather
        # than by one byte keeps the scan linear in the section size.
        for offset in range(0, len(payload) - _PERMUTATION_TABLE_SIZE + 1, 16):
            window = payload[offset : offset + _PERMUTATION_TABLE_SIZE]
            if len(set(window)) == _PERMUTATION_TABLE_SIZE:
                tables.append(
                    {
                        "section": str(name),
                        "offset": f"0x{offset:X}",
                        "size": _PERMUTATION_TABLE_SIZE,
                    }
                )
    return tables


def _is_opaque_window(window: bytes) -> bool:
    """Return True when a window looks like ciphertext or key material."""
    if len(set(window)) < _MIN_DISTINCT_BYTES:
        return False
    printable = sum(1 for byte in window if 0x20 <= byte <= 0x7E)
    return printable / len(window) <= _MAX_PRINTABLE_FRACTION


def _identified_spans(
    section: str, constants: list[dict] | None, tables: list[dict] | None
) -> list[tuple[int, int]]:
    """Return (start, end) byte spans in one section already accounted for.

    A round-constant table and a substitution box are high-entropy by
    construction. Once either has been identified by name, reporting the same
    bytes again as an unidentified encrypted region is a duplicate finding
    dressed as a second signal.
    """
    spans: list[tuple[int, int]] = []
    for entry in constants or ():
        if entry.get("section", "").lower() != section.lower():
            continue
        start = int(entry["offset"], 16)
        # A named table extends past its matched signature; the round-constant
        # tables this matters for are 256 bytes.
        spans.append((start, start + _PERMUTATION_TABLE_SIZE))
    for entry in tables or ():
        if entry.get("section", "").lower() != section.lower():
            continue
        start = int(entry["offset"], 16)
        spans.append((start, start + int(entry["size"])))
    return spans


def find_high_entropy_regions(
    sections: Iterable[tuple[str, bytes]] | None,
    known_constants: list[dict] | None = None,
    known_tables: list[dict] | None = None,
) -> list[dict]:
    """Locate contiguous opaque regions inside otherwise structured data sections.

    Adjacent qualifying windows are merged, because the size of the region is
    what distinguishes a single hash or GUID from an embedded encrypted payload.

    Passing the constants and permutation tables already identified suppresses
    the regions they account for, so what remains is the material this module
    could *not* name - which is the part worth a reviewer's attention.
    """
    regions: list[dict] = []
    for name, data in sections or ():
        if not data or str(name).lower() not in ENTROPY_SCAN_SECTIONS:
            continue
        payload = bytes(data)
        if len(payload) < _ENTROPY_WINDOW:
            continue
        excluded = _identified_spans(str(name), known_constants, known_tables)
        start: int | None = None
        end = 0
        for offset in range(0, len(payload) - _ENTROPY_WINDOW + 1, _ENTROPY_STEP):
            window_end = offset + _ENTROPY_WINDOW
            opaque = _is_opaque_window(payload[offset:window_end]) and not any(
                offset < span_end and window_end > span_start for span_start, span_end in excluded
            )
            if opaque:
                if start is None:
                    start = offset
                end = window_end
                continue
            if start is not None:
                _append_region(regions, str(name), payload, start, end)
                start = None
        if start is not None:
            _append_region(regions, str(name), payload, start, end)
    regions.sort(key=lambda entry: entry["size"], reverse=True)
    return regions


def _append_region(
    regions: list[dict], section: str, payload: bytes, start: int, end: int
) -> None:
    """Record a merged opaque region once it is large enough to be meaningful."""
    size = end - start
    if size < MIN_REGION_SIZE:
        return
    # The fraction of the section the region occupies is what separates an
    # embedded payload from ordinary opaque data. A large program's .rdata holds
    # certificates, compressed assets and unrecognised constant tables, and any
    # of them yields a multi-kilobyte high-entropy region - but only a small
    # fraction of a large section. A section that is *mostly* one opaque blob
    # exists to carry it.
    section_size = len(payload)
    regions.append(
        {
            "section": section,
            "offset": f"0x{start:X}",
            "size": size,
            "entropy": round(_shannon_entropy(payload[start:end]), 3),
            "section_size": section_size,
            "section_fraction": round(size / section_size, 3) if section_size else 0.0,
        }
    )


def analyze_crypto_material(sections: Iterable[tuple[str, bytes]] | None) -> dict:
    """Summarise the cryptographic constants and opaque data an image carries.

    Returns an empty dict when nothing is found, so callers can skip attaching
    the section for images with no embedded crypto.
    """
    section_list = list(sections or ())
    constants = find_crypto_constants(section_list)
    tables = find_permutation_tables(section_list)
    regions = find_high_entropy_regions(section_list, constants, tables)
    result: dict = {}
    if constants:
        result["constants"] = constants
        result["algorithms"] = sorted({entry["algorithm"] for entry in constants})
    if tables:
        result["permutation_tables"] = tables
    if regions:
        result["opaque_regions"] = regions
    return result
