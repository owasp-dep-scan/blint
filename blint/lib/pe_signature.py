# SPDX-License-Identifier: Apache-2.0
"""Structured Authenticode ``code_signature`` block for PE (W2.1, W2.2; 02/A-A.3).

The block replaces none of the existing keys and mirrors the Mach-O
``code_signature`` shape so both formats answer the same questions: who
signed this, with what digest, through which chain, at what time — and,
stated in band, what blint did *not* do (``trust_validation`` is
``"not_performed"``; blint names a chain, it never validates trust, so no
consumer can read "signed" as "trusted").

The PKCS#7/CMS structures are walked at the byte level from the certificate
table's DER (``WIN_CERTIFICATE`` entries of type ``PKCS_SIGNED_DATA``),
not through a dependency's object model: the fields a reader acts on
(digest algorithms, chain termination, exact counts) must not move when a
dependency changes how it renders its enums (ground rule 28). LIEF is used
for exactly one fact: the file's authentihash, which is the computed half
of ``structural_integrity.digest_match``.

W2.2 facts carried by the same walk:

- Timestamps, both forms — the RFC 3161 countersignature
  (``1.3.6.1.4.1.311.3.3.1``) and the legacy PKCS#9 countersignature
  (``1.2.840.113549.1.9.6``). The timestamp is the load-bearing field:
  signing certificates can be valid for days, so every validity statement
  is made relative to the timestamp, not to now. A signature with no
  timestamp at all states ``expires_hard: true`` — it really does stop
  being verifiable at certificate expiry. Nested signatures inherit the
  outer signature's timestamp for that statement (they cannot postdate the
  blob that carries them) and say so with ``inherited: true``.
- Nested signatures (``1.3.6.1.4.1.311.2.4.1``) become additional entries
  of the same ``signatures`` list, so a SHA-1 outer signature with a
  SHA-256 nested one is not reported as a SHA-1-signed binary; the
  block-level ``weak_digest_only`` is computed over every signature,
  including ones past the listing cap.
- Page hashes from ``SpcPeImageData``: presence, exact count, algorithm.
  Presence is reported; this packet does not recompute them, and nothing
  here claims verification.

Counts beside capped listings are exact and carry a truncation flag —
``signature_count``/``signatures_truncated``, ``chain_length``/
``chain_truncated`` — and page-hash counts are exact by division, with no
listing at all.

Everything returned is plain JSON types (str/int/bool/None/dict/list) so
the parse cache can serialize it. Hostile input — truncated, cyclic or
oversized DER — degrades to ``parse_status: "malformed"`` with a
``parse_error`` reason, never an exception through the parse.
"""

import contextlib
import datetime
import re

import lief

from blint.lib.pe_overlay import security_directory_range
from blint.logger import LOG

# --- OIDs the walk keys on. Numbers, never a dependency's enum names. -----
OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_SPC_INDIRECT_DATA = "1.3.6.1.4.1.311.2.1.4"
OID_SPC_PE_IMAGE_DATA = "1.3.6.1.4.1.311.2.1.15"
OID_SPC_OPUS_INFO = "1.3.6.1.4.1.311.2.1.12"
OID_SPC_STATEMENT_TYPE = "1.3.6.1.4.1.311.2.1.11"
OID_SIGNING_TIME = "1.2.840.113549.1.9.5"
OID_COUNTERSIGNATURE = "1.2.840.113549.1.9.6"
OID_RFC3161_COUNTERSIGNATURE = "1.3.6.1.4.1.311.3.3.1"
OID_NESTED_SIGNATURE = "1.3.6.1.4.1.311.2.4.1"
OID_COMMON_NAME = "2.5.4.3"
OID_ORGANIZATION = "2.5.4.10"
OID_BASIC_CONSTRAINTS = "2.5.29.19"
OID_EXT_KEY_USAGE = "2.5.29.37"

DIGEST_ALGORITHM_NAMES = {
    "1.2.840.113549.2.5": "MD5",
    "1.3.14.3.2.26": "SHA1",
    "2.16.840.1.101.3.4.2.1": "SHA256",
    "2.16.840.1.101.3.4.2.2": "SHA384",
    "2.16.840.1.101.3.4.2.3": "SHA512",
}
# The digests a signature should use today; CHECK_WEAK_SIGNATURE_DIGEST
# fires only when *no* signature in the file (nested included) uses one.
MODERN_DIGESTS = frozenset({"SHA256", "SHA384", "SHA512"})

# Page-hash list algorithms (measured on signtool /ph output); unknown OIDs
# pass through as dotted strings.
PAGE_HASH_ALGORITHM_NAMES = {
    "1.3.6.1.4.1.311.2.3.1": "SHA1",
    "1.3.6.1.4.1.311.2.3.2": "SHA256",
}
PAGE_HASH_WIDTHS = {"SHA1": 20, "SHA256": 32}
# classId of the SpcSerializedObject that carries page hashes: a 16-byte
# OCTET STRING GUID, measured on signtool /ph output.
PAGE_HASH_CLASS_ID = bytes.fromhex("a6b586d5b4a12466ae05a217da8e60d6")

EKU_NAMES = {
    "1.3.6.1.5.5.7.3.3": "codeSigning",
    "1.3.6.1.5.5.7.3.8": "timeStamping",
    "1.3.6.1.4.1.311.10.3.1": "microsoftTrustListSigning",
    "1.3.6.1.4.1.311.10.3.5": "whql",
    "1.3.6.1.4.1.311.10.3.5.1": "whqlDriverPublishing",
    "1.3.6.1.4.1.311.61.1.1": "kernelModeCodeSigning",
    "1.3.6.1.4.1.311.2.1.21": "individualCodeSigning",
    "1.3.6.1.4.1.311.2.1.22": "commercialCodeSigning",
}
STATEMENT_TYPE_NAMES = {
    "1.3.6.1.4.1.311.2.1.21": "individual_code_signing",
    "1.3.6.1.4.1.311.2.1.22": "commercial_code_signing",
}

# --- Limits (ground rule 30: this is an untrusted-input parser; every cap
# ships a fixture that exceeds it, and every count beside a capped listing
# is exact and flagged when the listing stops short). ----------------------
# A certificate table is a few hundred KiB in practice (page hashes add
# ~11 bytes per 4 KiB of file); beyond this the deep walk is refused and
# recorded, never chewed.
MAX_TABLE_BYTES = 32 * 1024 * 1024
# BER indefinite-length nesting depth; a hand-built blob can recurse.
MAX_BER_DEPTH = 64
# Signatures walked and listed (top-level plus nested). ``signature_count``
# is exact up to this window; beyond it the walk stops and
# ``signature_walk_truncated`` says the count is a floor, not a verdict.
MAX_SIGNATURES_WALKED = 64
# Chain certificates named; ``chain_length`` is exact beyond the window.
MAX_CHAIN_CERTIFICATES = 16
# A timestamp token is a few KiB; this only bounds hostile input.
MAX_TIMESTAMP_TOKEN_BYTES = 4 * 1024 * 1024

WIN_CERT_REVISION_2008 = 0x0200
WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002


class _SignatureFormatError(ValueError):
    """Raised when a DER/BER or Authenticode structure cannot be walked."""


# ---------------------------------------------------------------------------
# BER/DER primitives. The indefinite-length form is handled (some countersign
# tokens use it); the recursion that consumes it is depth-capped.
# ---------------------------------------------------------------------------
def _ber_read(data: bytes, pos: int, end: int, depth: int = 0) -> tuple[int, bytes, int]:
    """Read one TLV; returns (tag, content, next_pos)."""
    if depth > MAX_BER_DEPTH:
        raise _SignatureFormatError("ber_nesting_too_deep")
    if pos + 2 > end:
        raise _SignatureFormatError("truncated_tlv_header")
    tag = data[pos]
    length_byte = data[pos + 1]
    pos += 2
    if length_byte < 0x80:
        length = length_byte
        if pos + length > end:
            raise _SignatureFormatError("truncated_definite_length")
        return tag, data[pos : pos + length], pos + length
    if length_byte == 0x80:
        content_start = pos
        while True:
            if pos + 2 <= end and data[pos] == 0 and data[pos + 1] == 0:
                return tag, data[content_start:pos], pos + 2
            _, _, pos = _ber_read(data, pos, end, depth + 1)
    num_octets = length_byte & 0x7F
    if num_octets > 4 or pos + num_octets > end:
        raise _SignatureFormatError("unsupported_or_truncated_long_length")
    length = int.from_bytes(data[pos : pos + num_octets], "big")
    pos += num_octets
    if pos + length > end:
        raise _SignatureFormatError("truncated_long_form_content")
    return tag, data[pos : pos + length], pos + length


def _oid_decode(content: bytes) -> str:
    """Decode an OBJECT IDENTIFIER value into dotted-decimal form."""
    if not content:
        raise _SignatureFormatError("empty_oid")
    first = content[0]
    parts = [str(first // 40 if first < 80 else 2), str(first % 40 if first < 80 else first - 80)]
    value = 0
    for byte in content[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    if value:
        raise _SignatureFormatError("truncated_oid_component")
    return ".".join(parts)


def _decode_string(tag: int, content: bytes) -> str | None:
    """Decode one ASN.1 string value; None when the tag is not a string."""
    try:
        if tag in (0x0C, 0x13, 0x16):  # UTF8String, PrintableString, IA5String
            return content.decode("utf-8")
        if tag == 0x1E:  # BMPString
            return content.decode("utf-16-be")
        if tag == 0x14:  # TeletexString
            return content.decode("latin-1")
    except (UnicodeDecodeError, ValueError):
        return None
    return None


_UTC_TIME_RE = re.compile(r"^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(?:\.\d+)?Z$")
_GENERALIZED_TIME_RE = re.compile(r"^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(?:\.(\d{1,6}))?Z?$")
_UTC = datetime.timezone.utc


def _asn1_time(tag: int, content: bytes) -> tuple[str | None, datetime.datetime | None]:
    """Decode UTCTime/GeneralizedTime into (ISO-8601 Z string, aware UTC dt)."""
    try:
        text = content.decode("ascii")
    except UnicodeDecodeError:
        return None, None
    if tag == 0x17:  # UTCTime YYMMDDHHMM[SS]Z
        match = _UTC_TIME_RE.match(text)
        if not match:
            return None, None
        year = int(match.group(1))
        year += 2000 if year < 50 else 1900
        try:
            dt = datetime.datetime(
                year,
                int(match.group(2)),
                int(match.group(3)),
                int(match.group(4)),
                int(match.group(5)),
                int(match.group(6) or 0),
                tzinfo=_UTC,
            )
        except ValueError:
            return None, None
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ"), dt
    if tag == 0x18:  # GeneralizedTime YYYYMMDDHHMM[SS[.fff]]Z
        match = _GENERALIZED_TIME_RE.match(text)
        if not match:
            return None, None
        micro = int((match.group(7) or "0").ljust(6, "0"))
        try:
            dt = datetime.datetime(
                int(match.group(1)),
                int(match.group(2)),
                int(match.group(3)),
                int(match.group(4)),
                int(match.group(5)),
                int(match.group(6) or 0),
                micro,
                tzinfo=_UTC,
            )
        except ValueError:
            return None, None
        iso = dt.strftime("%Y-%m-%dT%H:%M:%S")
        if micro:
            iso += f".{micro:06d}".rstrip("0")
        return iso + "Z", dt
    return None, None


def _name_values(name: bytes) -> dict[str, list[str]]:
    """String values of an X.509 Name (RDNSequence), keyed by attribute OID."""
    out: dict[str, list[str]] = {}
    pos = 0
    end = len(name)
    while pos < end:
        _, rdn, pos = _ber_read(name, pos, end)
        rdn_pos = 0
        rdn_end = len(rdn)
        while rdn_pos < rdn_end:
            _, atv, rdn_pos = _ber_read(rdn, rdn_pos, rdn_end)
            atv_pos = 0
            atv_end = len(atv)
            oid = None
            value = None
            while atv_pos < atv_end:
                tag, content, atv_pos = _ber_read(atv, atv_pos, atv_end)
                if tag == 0x06:
                    oid = _oid_decode(content)
                elif value is None:
                    value = _decode_string(tag, content)
            if oid is not None and value is not None:
                out.setdefault(oid, []).append(value)
    return out


# ---------------------------------------------------------------------------
# X.509 certificates
# ---------------------------------------------------------------------------
def _parse_certificate(content: bytes) -> dict:
    """One certificate's facts from the Certificate SEQUENCE *content*.

    Inside TBSCertificate the field order after the optional [0] version is
    serialNumber, signature (AlgorithmIdentifier), issuer, validity, subject,
    subjectPublicKeyInfo — then optional extension blocks. The raw issuer and
    subject Name TLVs are kept for chain matching, which is a byte
    comparison, never a rendered-string comparison.
    """
    out: dict = {
        "subject_cn": None,
        "subject_o": None,
        "issuer_cn": None,
        "serial_hex": None,
        "not_before": None,
        "not_after": None,
        "not_before_dt": None,
        "not_after_dt": None,
        "is_ca": None,
        "eku": [],
        "raw_subject": b"",
        "raw_issuer": b"",
    }
    tbs_tag, tbs, _ = _ber_read(content, 0, len(content))
    if tbs_tag != 0x30:
        raise _SignatureFormatError("tbs_not_a_sequence")
    pos = 0
    end = len(tbs)
    sequence_index = 0
    while pos < end:
        tlv_start = pos
        tag, value, pos = _ber_read(tbs, pos, end)
        if tag == 0xA0:  # [0] EXPLICIT version
            continue
        if tag == 0xA3:  # [3] EXPLICIT extensions
            _certificate_extensions(value, out)
            continue
        if tag == 0x02 and out["serial_hex"] is None:
            out["serial_hex"] = value.hex()
            continue
        if tag != 0x30:
            continue
        sequence_index += 1
        if sequence_index == 2:  # issuer (1 is the signature AlgorithmIdentifier)
            out["raw_issuer"] = bytes(tbs[tlv_start:pos])
            names = _name_values(value)
            out["issuer_cn"] = (names.get(OID_COMMON_NAME) or [None])[0]
        elif sequence_index == 3:  # validity
            validity_pos = 0
            validity_end = len(value)
            times = []
            while validity_pos < validity_end:
                time_tag, time_value, validity_pos = _ber_read(value, validity_pos, validity_end)
                times.append(_asn1_time(time_tag, time_value))
            if len(times) == 2:
                out["not_before"], out["not_before_dt"] = times[0]
                out["not_after"], out["not_after_dt"] = times[1]
        elif sequence_index == 4:  # subject
            out["raw_subject"] = bytes(tbs[tlv_start:pos])
            names = _name_values(value)
            out["subject_cn"] = (names.get(OID_COMMON_NAME) or [None])[0]
            out["subject_o"] = (names.get(OID_ORGANIZATION) or [None])[0]
    return out


def _certificate_extensions(exts_field: bytes, out: dict) -> None:
    """Decode BasicConstraints (is_ca) and ExtKeyUsage (eku) extensions."""
    _, exts, _ = _ber_read(exts_field, 0, len(exts_field))
    pos = 0
    end = len(exts)
    while pos < end:
        _, ext, pos = _ber_read(exts, pos, end)
        ext_pos = 0
        ext_end = len(ext)
        ext_oid = None
        ext_value = None
        while ext_pos < ext_end:
            tag, value, ext_pos = _ber_read(ext, ext_pos, ext_end)
            if tag == 0x06:
                ext_oid = _oid_decode(value)
            elif tag == 0x04:
                ext_value = value
        if ext_oid == OID_BASIC_CONSTRAINTS and ext_value is not None:
            bc_tag, bc, _ = _ber_read(ext_value, 0, len(ext_value))
            if bc_tag == 0x30:
                # cA DEFAULT FALSE: an empty SEQUENCE is explicitly not a CA.
                out["is_ca"] = len(bc) >= 2 and bc[0] == 0x01 and bc[1] != 0
        elif ext_oid == OID_EXT_KEY_USAGE and ext_value is not None:
            # ExtKeyUsageSyntax ::= SEQUENCE OF KeyPurposeId — descend into
            # the outer SEQUENCE before reading the OIDs.
            ekus = []
            seq_tag, purposes, _ = _ber_read(ext_value, 0, len(ext_value))
            eku_content = purposes if seq_tag == 0x30 else ext_value
            eku_pos = 0
            eku_end = len(eku_content)
            while eku_pos < eku_end:
                eku_tag, eku_value, eku_pos = _ber_read(eku_content, eku_pos, eku_end)
                if eku_tag == 0x06:
                    oid = _oid_decode(eku_value)
                    ekus.append(EKU_NAMES.get(oid, oid))
            out["eku"] = ekus


def _parse_certificate_set(set_content: bytes, limit: int) -> tuple[list[dict], int]:
    """Certificates from a SignedData [0] IMPLICIT CertificateSet.

    Returns (parsed, total): at most ``limit`` parsed and the exact total
    present, so a saturated list is never mistaken for the count.
    """
    parsed = []
    pos = 0
    end = len(set_content)
    total = 0
    while pos < end:
        tag, certificate, pos = _ber_read(set_content, pos, end)
        if tag != 0x30:
            continue
        total += 1
        if len(parsed) < limit:
            parsed.append(_parse_certificate(certificate))
    return parsed, total


# ---------------------------------------------------------------------------
# SignedData / SignerInfo
# ---------------------------------------------------------------------------
def _parse_content_info(der: bytes) -> tuple[str | None, bytes | None]:
    """ContentInfo → (contentType OID, inner SEQUENCE content)."""
    tag, content, _ = _ber_read(der, 0, len(der))
    if tag != 0x30:
        raise _SignatureFormatError("content_info_not_a_sequence")
    pos = 0
    end = len(content)
    content_type = None
    payload = None
    while pos < end:
        tag, value, pos = _ber_read(content, pos, end)
        if tag == 0x06:
            content_type = _oid_decode(value)
        elif tag == 0xA0:
            inner_tag, payload, _ = _ber_read(value, 0, len(value))
            if inner_tag != 0x30:
                raise _SignatureFormatError("content_not_a_sequence")
    if content_type is None:
        raise _SignatureFormatError("content_info_without_content_type")
    return content_type, payload


def _parse_signed_data(signed_data: bytes) -> dict:
    """SignedData fields: inner content, certificates, raw SignerInfos.

    SignedData ::= SEQUENCE { version, digestAlgorithms SET, contentInfo,
    certificates [0] IMPLICIT OPTIONAL, crls [1] IMPLICIT OPTIONAL,
    signerInfos SET }. digestAlgorithms is a SET that precedes the
    contentInfo, so the content_type guard skips it; a [1] crls block is
    context-tagged (0xA1), not a SET, and never reaches the signerInfos arm.
    """
    out: dict = {
        "content_type": None,
        "content": None,
        "certificates": [],
        "certificate_count": 0,
        "signer_infos": [],
    }
    pos = 0
    end = len(signed_data)
    while pos < end:
        tag, value, pos = _ber_read(signed_data, pos, end)
        if tag == 0x30 and out["content_type"] is None:  # encapContentInfo
            inner_pos = 0
            inner_end = len(value)
            while inner_pos < inner_end:
                inner_tag, inner_value, inner_pos = _ber_read(value, inner_pos, inner_end)
                if inner_tag == 0x06:
                    out["content_type"] = _oid_decode(inner_value)
                elif inner_tag == 0xA0:
                    _, out["content"], _ = _ber_read(inner_value, 0, len(inner_value))
        elif tag == 0xA0:  # [0] IMPLICIT CertificateSet
            parsed, total = _parse_certificate_set(value, MAX_CHAIN_CERTIFICATES * 2)
            out["certificates"] = parsed
            out["certificate_count"] = total
        elif tag == 0x31 and out["content_type"] is not None:  # signerInfos
            signer_pos = 0
            signer_end = len(value)
            while signer_pos < signer_end:
                si_tag, si_value, signer_pos = _ber_read(value, signer_pos, signer_end)
                if si_tag == 0x30:
                    out["signer_infos"].append(si_value)
    return out


def _parse_signer_info(content: bytes) -> dict:
    """One SignerInfo: sid, digest algorithm, authenticated/unauthenticated
    attributes (keyed by OID, values the raw SET contents)."""
    out: dict = {
        "issuer_serial_hex": None,
        "raw_issuer": b"",
        "digest_algorithm": None,
        "authenticated_attributes": {},
        "unauthenticated_attributes": {},
        "encrypted_digest": None,
    }
    pos = 0
    end = len(content)
    state = 0  # 0=version, 1=sid seen, 2=digestAlgorithm seen
    while pos < end:
        tag, value, pos = _ber_read(content, pos, end)
        if state == 0 and tag == 0x02:  # version
            state = 1
            continue
        if state == 1 and tag == 0x30:  # sid: issuerAndSerialNumber
            sid_pos = 0
            sid_end = len(value)
            while sid_pos < sid_end:
                sid_tlv_start = sid_pos
                sid_tag, sid_value, sid_pos = _ber_read(value, sid_pos, sid_end)
                if sid_tag == 0x30:  # the issuer Name
                    # Kept as the full TLV so the match against a
                    # certificate's raw subject TLV is a byte comparison of
                    # the same shape.
                    out["raw_issuer"] = bytes(value[sid_tlv_start:sid_pos])
                elif sid_tag == 0x02:
                    out["issuer_serial_hex"] = sid_value.hex()
            state = 2
            continue
        if state == 1 and tag == 0xA0:  # sid: subjectKeyIdentifier
            out["subject_key_identifier_hex"] = value.hex()
            state = 2
            continue
        if state == 2 and tag == 0x30:  # digestAlgorithm
            alg_pos = 0
            alg_end = len(value)
            while alg_pos < alg_end:
                alg_tag, alg_value, alg_pos = _ber_read(value, alg_pos, alg_end)
                if alg_tag == 0x06:
                    oid = _oid_decode(alg_value)
                    out["digest_algorithm"] = DIGEST_ALGORITHM_NAMES.get(oid, oid)
            state = 3
            continue
        if tag == 0xA0:  # [0] IMPLICIT authenticatedAttributes
            out["authenticated_attributes"] = _parse_attribute_set(value)
            continue
        if tag == 0x04 and out["encrypted_digest"] is None:  # encryptedDigest
            out["encrypted_digest"] = value.hex()
            continue
        if tag == 0xA1:  # [1] IMPLICIT unauthenticatedAttributes
            out["unauthenticated_attributes"] = _parse_attribute_set(value)
            continue
    return out


def _parse_attribute_set(set_content: bytes) -> dict[str, list[bytes]]:
    """Attributes from a SET OF Attribute, values keyed by OID."""
    out: dict[str, list[bytes]] = {}
    pos = 0
    end = len(set_content)
    while pos < end:
        _, attribute, pos = _ber_read(set_content, pos, end)
        attr_pos = 0
        attr_end = len(attribute)
        oid = None
        values = []
        while attr_pos < attr_end:
            tag, value, attr_pos = _ber_read(attribute, attr_pos, attr_end)
            if tag == 0x06 and oid is None:
                oid = _oid_decode(value)
            elif tag == 0x31:
                values.append(value)
        if oid is not None:
            out.setdefault(oid, []).extend(values)
    return out


def _first_set_value(values: list[bytes]) -> bytes | None:
    """First SET's content of an attribute value list, or None."""
    for value in values:
        return value
    return None


# ---------------------------------------------------------------------------
# Authenticode content: SpcIndirectDataContent
# ---------------------------------------------------------------------------
def _parse_spc_indirect_data(content: bytes) -> dict:
    """SpcIndirectDataContent ::= SEQUENCE { data, messageDigest }.

    ``data`` is SpcAttributeTypeAndOptionalValue { OID SPC_PE_IMAGE_DATA,
    SpcPeImageData }; ``messageDigest`` is DigestInfo — the digest of the
    *file*, which ``structural_integrity`` compares against the
    authentihash blint computes.
    """
    out: dict = {
        "digest_algorithm": None,
        "digest_hex": None,
        "page_hashes": {"present": False},
        "pe_image_flags": None,
    }
    pos = 0
    end = len(content)
    child_index = 0
    while pos < end:
        tag, value, pos = _ber_read(content, pos, end)
        if tag != 0x30:
            continue
        child_index += 1
        if child_index == 1:
            _parse_attribute_type_and_value(value, out)
        elif child_index == 2:
            _parse_digest_info(value, out)
    return out


def _parse_attribute_type_and_value(content: bytes, out: dict) -> None:
    """{ type OID, value ANY } — the ANY is SpcPeImageData for SPC_PE."""
    attribute_type = None
    pos = 0
    end = len(content)
    while pos < end:
        tag, value, pos = _ber_read(content, pos, end)
        if tag == 0x06 and attribute_type is None:
            attribute_type = _oid_decode(value)
        elif tag == 0x30 and attribute_type == OID_SPC_PE_IMAGE_DATA:
            _parse_spc_pe_image_data(value, out)


def _parse_digest_info(content: bytes, out: dict) -> None:
    """DigestInfo { digestAlgorithm AlgorithmIdentifier, digest OCTET STRING }."""
    pos = 0
    end = len(content)
    while pos < end:
        tag, value, pos = _ber_read(content, pos, end)
        if tag == 0x30 and out["digest_algorithm"] is None:
            alg_pos = 0
            alg_end = len(value)
            while alg_pos < alg_end:
                alg_tag, alg_value, alg_pos = _ber_read(value, alg_pos, alg_end)
                if alg_tag == 0x06:
                    oid = _oid_decode(alg_value)
                    out["digest_algorithm"] = DIGEST_ALGORITHM_NAMES.get(oid, oid)
        elif tag == 0x04 and out["digest_hex"] is None:
            out["digest_hex"] = value.hex()


def _parse_spc_pe_image_data(content: bytes, out: dict) -> None:
    """SpcPeImageData { flags BIT STRING, file SpcLink } — page hashes."""
    pos = 0
    end = len(content)
    while pos < end:
        tag, value, pos = _ber_read(content, pos, end)
        if tag == 0x03 and out["pe_image_flags"] is None:
            out["pe_image_flags"] = value.hex()
        elif tag in (0xA0, 0xA1, 0xA2, 0x80, 0x16):
            _parse_spc_link(tag, value, out)


def _parse_spc_link(tag: int, content: bytes, out: dict) -> None:
    """SpcLink CHOICE — signtool wraps the selected alternative in an extra
    [0], so both the wrapped and the direct encodings are handled.

    moniker [1] { classId OCTET STRING, serializedData OCTET STRING }: the
    page-hash moniker's classId is a 16-byte GUID and its serializedData
    carries, per hash algorithm, one flat stream of (offset, hash) records.
    """
    if tag == 0xA0 and content:
        # Wrapped: look one level down for the chosen alternative.
        with contextlib.suppress(_SignatureFormatError):
            inner_tag, inner_value, _ = _ber_read(content, 0, len(content))
            _parse_spc_link(inner_tag, inner_value, out)
        return
    if tag != 0xA1:  # only the moniker alternative carries page hashes
        return
    pos = 0
    end = len(content)
    class_id = None
    serialized = None
    while pos < end:
        entry_tag, entry_value, pos = _ber_read(content, pos, end)
        if entry_tag == 0x04 and class_id is None:
            class_id = entry_value
        elif entry_tag == 0x04 and serialized is None:
            serialized = entry_value
    if class_id != PAGE_HASH_CLASS_ID or not serialized:
        return
    _parse_page_hashes(serialized, out, depth=0)


def _parse_page_hashes(serialized: bytes, out: dict, depth: int) -> None:
    """Page hashes: { algorithm OID, SET { OCTET STRING records } } pairs.

    Each records blob is a flat stream of 4-byte little-endian file offsets
    each followed by one digest; the digest width follows the algorithm
    (SHA-1 → 20, SHA-256 → 32) and the count is exact by division — there
    is no listing to cap.
    """
    if depth > 8 or out["page_hashes"].get("count") is not None:
        return
    pos = 0
    end = len(serialized)
    while pos < end:
        tag, value, pos = _ber_read(serialized, pos, end)
        if tag == 0x06 and "algorithm" not in out["page_hashes"]:
            oid = _oid_decode(value)
            out["page_hashes"]["algorithm"] = PAGE_HASH_ALGORITHM_NAMES.get(oid, oid)
            out["page_hashes"]["present"] = True
        elif tag == 0x04 and out["page_hashes"].get("algorithm") is not None:
            width = PAGE_HASH_WIDTHS.get(out["page_hashes"]["algorithm"], 0)
            if width:
                record_length = 4 + width
                total, leftover = divmod(len(value), record_length)
                out["page_hashes"]["count"] = total
                if leftover:
                    out["page_hashes"]["trailing_bytes"] = leftover
                return
        elif tag in (0x30, 0x31):
            _parse_page_hashes(value, out, depth + 1)


# ---------------------------------------------------------------------------
# Attribute decoders
# ---------------------------------------------------------------------------
def _parse_opus_info(content: bytes) -> dict:
    """SpcSpOpusInfo { programName SpcString?, moreInfo SpcLink? }."""
    out: dict = {}
    pos = 0
    end = len(content)
    while pos < end:
        tag, value, pos = _ber_read(content, pos, end)
        if tag == 0xA0 and "program_name" not in out:
            out["program_name"] = _decode_spc_string(value)
        elif tag == 0xA1 and "url" not in out:
            out["url"] = _decode_spc_string(value)
    return {k: v for k, v in out.items() if v}


def _decode_spc_string(content: bytes) -> str | None:
    """One SpcString/SpcLink string value; signtool uses primitive [0] (0x80)
    TLVs whose content is ASCII (URLs) or UCS-2BE (program names). There is
    no tag to tell the two apart, so printable-only bytes read as ASCII and
    anything else as UCS-2BE."""
    if len(content) >= 2 and content[0] in (0x80, 0x16, 0x0C, 0x1E):
        with contextlib.suppress(_SignatureFormatError):
            _, inner, _ = _ber_read(content, 0, len(content))
            if content[0] == 0x80:
                if all(0x20 <= byte <= 0x7E for byte in inner):
                    return inner.decode("ascii")
                return _decode_string(0x1E, inner)
            text = _decode_string(content[0], inner)
            if text is not None:
                return text
    return _decode_string(0x16, content) or _decode_string(0x1E, content)


def _parse_statement_type(content: bytes) -> list[str]:
    """spcStatementType: SEQUENCE of OIDs (individual/commercial signing)."""
    names = []
    pos = 0
    end = len(content)
    while pos < end:
        tag, value, pos = _ber_read(content, pos, end)
        if tag == 0x06:
            oid = _oid_decode(value)
            names.append(STATEMENT_TYPE_NAMES.get(oid, oid))
    return names


# ---------------------------------------------------------------------------
# Timestamps
# ---------------------------------------------------------------------------
def _parse_rfc3161_token(content: bytes) -> dict:
    """RFC 3161 TimeStampToken: a ContentInfo wrapping SignedData whose
    encapsulated content is TSTInfo (genTime, optional tsa name)."""
    out: dict = {"kind": "rfc3161", "time": None, "tsa_cn": None}
    if len(content) > MAX_TIMESTAMP_TOKEN_BYTES:
        out["error"] = f"token_too_large:{len(content)}"
        return out
    content_type, payload = _parse_content_info(content)
    if content_type != OID_SIGNED_DATA or payload is None:
        out["error"] = f"unexpected_token_content:{content_type}"
        return out
    token = _parse_signed_data(payload)
    tst_content = token["content"]
    if tst_content is None:
        out["error"] = "token_without_content"
        return out
    tst_tag, tst, _ = _ber_read(tst_content, 0, len(tst_content))
    if tst_tag != 0x30:
        out["error"] = "tst_info_not_a_sequence"
        return out
    pos = 0
    end = len(tst)
    while pos < end:
        tag, value, pos = _ber_read(tst, pos, end)
        if tag in (0x17, 0x18) and out["time"] is None:
            out["time"], out["_time_dt"] = _asn1_time(tag, value)
        elif tag == 0xA1 and out["tsa_cn"] is None:  # tsa [1] EXPLICIT GeneralName
            out["tsa_cn"] = _general_name_cn(value)
    if out["tsa_cn"] is None:
        # Fall back to the token's own signer certificate.
        for si in token["signer_infos"][:1]:
            info = _parse_signer_info(si)
            cert = _match_certificate(token["certificates"], info)
            if cert:
                out["tsa_cn"] = cert["subject_cn"]
    return out


def _general_name_cn(content: bytes) -> str | None:
    """CN from a [4] directoryName GeneralName."""
    tag, value, _ = _ber_read(content, 0, len(content))
    if tag == 0xA4:
        name_tag, name, _ = _ber_read(value, 0, len(value))
        if name_tag == 0x30:
            names = _name_values(name)
            return (names.get(OID_COMMON_NAME) or [None])[0]
    return None


def _parse_pkcs9_countersignature(content: bytes, outer_certs: list[dict]) -> dict:
    """PKCS#9 countersignature: a SignerInfo whose signed attributes carry
    signingTime; the countersigner is matched against the outer blob's
    certificate set. The attribute value is a SET containing the
    SignerInfo SEQUENCE, so the extra wrapper is stripped first."""
    out: dict = {"kind": "pkcs9", "time": None, "tsa_cn": None}
    info_content = content
    with contextlib.suppress(_SignatureFormatError):
        first_tag, first_value, _ = _ber_read(content, 0, len(content))
        if first_tag == 0x30:
            info_content = first_value
    info = _parse_signer_info(info_content)
    signing_time = _first_set_value(info["authenticated_attributes"].get(OID_SIGNING_TIME, []))
    if signing_time is not None:
        time_tag, time_value, _ = _ber_read(signing_time, 0, len(signing_time))
        out["time"], out["_time_dt"] = _asn1_time(time_tag, time_value)
    cert = _match_certificate(outer_certs, info)
    if cert:
        out["tsa_cn"] = cert["subject_cn"]
    return out


def _match_certificate(certificates: list[dict], info: dict) -> dict | None:
    """The certificate a SignerInfo names, by (issuer DER, serial) bytes.

    RFC 5652: the sid's issuerAndSerialNumber names the signer's certificate
    by its issuer and serial — so the match is against each certificate's
    issuer, and the chain walk (subject == issuer) is the separate step that
    follows it.
    """
    if not info.get("issuer_serial_hex"):
        return None
    for cert in certificates:
        if cert["serial_hex"] == info["issuer_serial_hex"] and cert["raw_issuer"] == info.get(
            "raw_issuer"
        ):
            return cert
    # Serial numbers are the same INTEGER DER in both places; the issuer Name
    # can differ in encoding, so the serial alone is the fallback match.
    for cert in certificates:
        if cert["serial_hex"] == info["issuer_serial_hex"]:
            return cert
    return None


def _build_chain(
    certificates: list[dict], signer: dict, certificates_truncated: bool = False
) -> tuple[list[dict], int, str | None, bool | None, bool]:
    """The chain the blob ships above the signer: intermediates then root.

    Structural only — the next link is the certificate whose subject DER
    equals the current link's issuer DER. Returns (listed chain, length,
    terminating CN, whether it terminates at a self-signed root, whether the
    length is exact).

    ``certificates_truncated`` says the blob carried more certificates than
    the parse window kept. A walk that then runs out of links has not found
    the end of the chain, it has found the end of what was parsed — so the
    length is a floor and both the terminating CN and ``chain_complete`` are
    withheld rather than named from the last link that happened to fit.
    """
    chain: list[dict] = []
    chain_length = 0
    complete = False
    current = signer
    if current["raw_subject"] == current["raw_issuer"]:
        # A self-signed signer is its own root: the chain terminates at the
        # leaf itself, which is what signing_class will call self_signed.
        return chain, 0, current["subject_cn"], True, True
    seen = {signer["serial_hex"]}
    ran_out = False
    while True:
        nxt = None
        for cert in certificates:
            if cert["serial_hex"] in seen:
                continue
            if cert["raw_subject"] == current["raw_issuer"]:
                nxt = cert
                break
        if nxt is None:
            ran_out = True
            break
        chain_length += 1
        seen.add(nxt["serial_hex"])
        if chain_length <= MAX_CHAIN_CERTIFICATES:
            chain.append(
                {
                    "cn": nxt["subject_cn"],
                    "o": nxt["subject_o"],
                    "serial": nxt["serial_hex"],
                    "is_ca": nxt["is_ca"],
                    "issuer_cn": nxt["issuer_cn"],
                }
            )
        current = nxt
        if current["raw_subject"] == current["raw_issuer"]:
            complete = True
            break
    if certificates_truncated and ran_out:
        return chain, chain_length, None, None, False
    terminates_at = current["subject_cn"] if chain_length else None
    return chain, chain_length, terminates_at, complete, True


def _timestamp_entry(countersignature: dict, cert: dict | None) -> dict:
    """The ``timestamp`` block for one signature, with the validity statement
    made relative to the timestamp (A.1): the question is whether the
    certificate was valid *when the timestamp says it signed*, never whether
    it is valid now."""
    entry = {
        "present": True,
        "kind": countersignature["kind"],
        "time": countersignature.get("time"),
        "tsa_cn": countersignature.get("tsa_cn"),
    }
    time_dt = countersignature.get("_time_dt")
    if cert and time_dt is not None and cert.get("not_before_dt") and cert.get("not_after_dt"):
        entry["signature_valid_at_timestamp"] = (
            cert["not_before_dt"] <= time_dt <= cert["not_after_dt"]
        )
    return entry


def _strip_counter(value: dict) -> dict:
    """Countersignature dict without the non-JSON datetime helper."""
    return {k: v for k, v in value.items() if not k.startswith("_")}


# ---------------------------------------------------------------------------
# One signature (top-level or nested)
# ---------------------------------------------------------------------------
def _parse_signature(
    der: bytes,
    authentihash_fn,
    nesting_level: int = 0,
    inherited_timestamp: dict | None = None,
) -> tuple[dict | None, list[bytes]]:
    """Parse one ContentInfo into a signature entry.

    Returns (entry, nested_ders): the entry for ``signatures[]`` and the
    nested-signature DER values to recurse into, so the caller owns the
    walk/list caps in one place.
    """
    content_type, payload = _parse_content_info(der)
    if content_type != OID_SIGNED_DATA or payload is None:
        return None, []
    signed = _parse_signed_data(payload)
    if not signed["signer_infos"]:
        return None, []
    info = _parse_signer_info(signed["signer_infos"][0])
    cert = _match_certificate(signed["certificates"], info)
    certificates_truncated = signed["certificate_count"] > len(signed["certificates"])

    entry: dict = {
        "digest_algorithm": info["digest_algorithm"],
        "nested": nesting_level > 0,
    }
    if nesting_level:
        entry["nesting_level"] = nesting_level
    if cert:
        entry["signer"] = {
            "cn": cert["subject_cn"],
            "o": cert["subject_o"],
            "serial": cert["serial_hex"],
            "not_before": cert["not_before"],
            "not_after": cert["not_after"],
            "issuer_cn": cert["issuer_cn"],
            "eku": cert["eku"],
        }
        chain, chain_length, terminates_at, complete, length_exact = _build_chain(
            signed["certificates"], cert, certificates_truncated
        )
        entry["chain"] = chain
        entry["chain_length"] = chain_length
        if chain_length > MAX_CHAIN_CERTIFICATES:
            entry["chain_truncated"] = True
        if not length_exact:
            # The chain ran past the certificate parse window, so the length
            # is a floor: say so rather than letting it read as the whole
            # chain (``chain_terminates_at`` and ``chain_complete`` are the
            # facts that window cost us, and they are withheld above).
            entry["chain_length_exact"] = False
        entry["chain_terminates_at"] = terminates_at
        entry["chain_complete"] = complete
    else:
        entry["signer"] = None
        entry["chain"] = []
        entry["chain_length"] = 0
        entry["chain_terminates_at"] = None
        entry["chain_complete"] = False
        if certificates_truncated:
            # The signer's own certificate may be one of the ones past the
            # parse window: "not found here" is not "not carried" (rule 14).
            entry["signer_certificate_not_parsed"] = True
            entry["chain_complete"] = None

    # Content: the file digest and the SpcPeImageData (page hashes).
    if signed["content_type"] == OID_SPC_INDIRECT_DATA and signed["content"] is not None:
        spc = _parse_spc_indirect_data(signed["content"])
        digest_algorithm = spc.get("digest_algorithm")
        digest_block: dict = {
            "algorithm": digest_algorithm,
            "embedded": spc.get("digest_hex"),
        }
        computed = authentihash_fn(digest_algorithm) if authentihash_fn and digest_algorithm else None
        digest_block["computed"] = computed
        if computed is None:
            # State the non-recompute rather than echoing the embedded value.
            digest_block["digest_match"] = None
            digest_block["recompute"] = "not_performed"
        else:
            digest_block["digest_match"] = computed == spc["digest_hex"]
        entry["digest"] = digest_block
        if spc["page_hashes"].get("present"):
            entry["page_hashes"] = spc["page_hashes"]

    # Signed attributes: opus info and statement types.
    opus_value = _first_set_value(info["authenticated_attributes"].get(OID_SPC_OPUS_INFO, []))
    if opus_value is not None:
        with contextlib.suppress(_SignatureFormatError):
            _, opus_content, _ = _ber_read(opus_value, 0, len(opus_value))
            opus = _parse_opus_info(opus_content)
            if opus:
                entry["opus_info"] = opus
    statement_value = _first_set_value(
        info["authenticated_attributes"].get(OID_SPC_STATEMENT_TYPE, [])
    )
    if statement_value is not None:
        with contextlib.suppress(_SignatureFormatError):
            _, statement_content, _ = _ber_read(statement_value, 0, len(statement_value))
            statements = _parse_statement_type(statement_content)
            if statements:
                entry["statements"] = statements

    # Timestamps: RFC 3161 preferred, PKCS#9 recorded alongside.
    countersignatures: list[dict] = []
    rfc3161_value = _first_set_value(
        info["unauthenticated_attributes"].get(OID_RFC3161_COUNTERSIGNATURE, [])
    )
    if rfc3161_value is not None:
        with contextlib.suppress(_SignatureFormatError):
            token = _parse_rfc3161_token(rfc3161_value)
            if not token.get("error"):
                countersignatures.append(token)
    pkcs9_value = _first_set_value(info["unauthenticated_attributes"].get(OID_COUNTERSIGNATURE, []))
    if pkcs9_value is not None:
        with contextlib.suppress(_SignatureFormatError):
            countersignatures.append(
                _parse_pkcs9_countersignature(pkcs9_value, signed["certificates"])
            )
    if countersignatures:
        entry["countersignatures"] = [_strip_counter(c) for c in countersignatures]
        preferred = next(
            (c for c in countersignatures if c["kind"] == "rfc3161"), countersignatures[0]
        )
        entry["timestamp"] = _timestamp_entry(preferred, cert)
    elif inherited_timestamp and inherited_timestamp.get("present"):
        # A nested signature cannot postdate the blob that carries it, so the
        # outer timestamp is its timestamp — stated, not silently reused.
        entry["timestamp"] = {
            "present": True,
            "kind": inherited_timestamp.get("kind"),
            "time": inherited_timestamp.get("time"),
            "tsa_cn": inherited_timestamp.get("tsa_cn"),
            "inherited": True,
        }
        time_dt = inherited_timestamp.get("_time_dt")
        if cert and time_dt is not None and cert.get("not_before_dt") and cert.get("not_after_dt"):
            entry["timestamp"]["signature_valid_at_timestamp"] = (
                cert["not_before_dt"] <= time_dt <= cert["not_after_dt"]
            )
    else:
        entry["timestamp"] = {"present": False}
    entry["expires_hard"] = not entry["timestamp"].get("present", False)

    nested_ders = list(info["unauthenticated_attributes"].get(OID_NESTED_SIGNATURE, []))
    return entry, nested_ders


# ---------------------------------------------------------------------------
# Certificate table and entry point
# ---------------------------------------------------------------------------
def _win_certificate_entries(table: bytes, block: dict) -> dict:
    """WIN_CERTIFICATE entries: exact count, the type-2 DER blobs kept.

    Entries are 8-byte aligned; a header that runs past the table is a
    recorded truncation, and the walk stops without raising.
    """
    out = {"count": 0, "signed_data_blobs": [], "other_type_count": 0, "revision": None}
    pos = 0
    end = len(table)
    while pos + 8 <= end:
        length = int.from_bytes(table[pos : pos + 4], "little")
        revision = int.from_bytes(table[pos + 4 : pos + 6], "little")
        cert_type = int.from_bytes(table[pos + 6 : pos + 8], "little")
        if length < 8 or pos + length > end:
            block["parse_error"] = f"entry_{out['count']}_truncated"
            break
        out["count"] += 1
        if out["revision"] is None:
            out["revision"] = revision
        if cert_type == WIN_CERT_TYPE_PKCS_SIGNED_DATA:
            out["signed_data_blobs"].append(table[pos + 8 : pos + length])
        else:
            out["other_type_count"] += 1
        pos += (length + 7) & ~7
    return out


_LIEF_ALGORITHMS = {
    "MD5": lambda: lief.PE.ALGORITHMS.MD5,
    "SHA1": lambda: lief.PE.ALGORITHMS.SHA_1,
    "SHA256": lambda: lief.PE.ALGORITHMS.SHA_256,
    "SHA384": lambda: lief.PE.ALGORITHMS.SHA_384,
    "SHA512": lambda: lief.PE.ALGORITHMS.SHA_512,
}


def _authentihash_factory(parsed_obj: lief.PE.Binary):
    """The file's authentihash in the named algorithm, or None when blint
    does not recompute it (unsupported algorithm) — the embedded value is
    never reported as if blint had computed it."""

    def compute(algorithm: str) -> str | None:
        factory = _LIEF_ALGORITHMS.get(algorithm)
        if factory is None:
            return None
        with contextlib.suppress(Exception):
            return parsed_obj.authentihash(factory()).hex()
        return None

    return compute


def parse_pe_code_signature(parsed_obj: lief.PE.Binary, exe_file: str) -> dict:
    """The structured ``code_signature`` block for one PE file (02/A).

    ``parse_status``: ``"absent"`` (no certificate table), ``"malformed"``
    (a table or signature blint could not walk — never folded into
    "unsigned"), or ``"parsed"``. ``scope``: ``"embedded"`` whenever a
    certificate table is present, ``"none"`` otherwise, with
    ``catalog_lookup: "not_performed"`` stating that a catalog-signed file
    cannot be distinguished from an unsigned one until W2.3 supplies a
    catalog directory.
    """
    block: dict = {
        "parse_status": "absent",
        "parse_error": None,
        "scope": "none",
        "trust_validation": "not_performed",
        "signatures": [],
        "signature_count": 0,
        "weak_digest_only": False,
    }

    cert_range = security_directory_range(parsed_obj)
    if cert_range is None:
        block["catalog_lookup"] = "not_performed"
        return block
    offset, size = cert_range
    block["scope"] = "embedded"
    if size > MAX_TABLE_BYTES:
        block["parse_status"] = "malformed"
        block["parse_error"] = f"table_too_large:{size}"
        return block
    try:
        with open(exe_file, "rb") as handle:
            handle.seek(offset)
            table = handle.read(size)
    except OSError as e:
        block["parse_status"] = "malformed"
        block["parse_error"] = f"table_unreadable:{e}"
        return block
    if len(table) < size:
        block["parse_status"] = "malformed"
        block["parse_error"] = f"table_truncated:{len(table)}_of_{size}"
        return block

    entries = _win_certificate_entries(table, block)
    block["certificate_entries"] = entries["count"]
    if entries["revision"] is not None:
        block["certificate_revision"] = entries["revision"]
    if entries["other_type_count"]:
        block["unparsed_certificate_entries"] = entries["other_type_count"]

    authentihash_fn = _authentihash_factory(parsed_obj)
    signature_count = 0
    modern_seen = False
    signature_errors: list[str] = []
    pending: list[tuple[bytes, int, dict | None]] = [
        (der, 0, None) for der in entries["signed_data_blobs"]
    ]
    while pending:
        der, level, inherited = pending.pop(0)
        if signature_count >= MAX_SIGNATURES_WALKED:
            block["signature_walk_truncated"] = True
            break
        try:
            entry, nested_ders = _parse_signature(der, authentihash_fn, level, inherited)
        except _SignatureFormatError as e:
            signature_errors.append(f"level_{level}:{e}")
            continue
        except (IndexError, KeyError, TypeError, ValueError) as e:
            signature_errors.append(f"level_{level}:{type(e).__name__}:{e}")
            continue
        if entry is None:
            continue
        signature_count += 1
        if entry.get("digest_algorithm") in MODERN_DIGESTS:
            modern_seen = True
        # One window bounds both the walk and the listing, so there is one
        # flag to read rather than two that can never disagree (rule 21).
        block["signatures"].append(entry)
        for nested_der in nested_ders:
            pending.append((nested_der, level + 1, entry.get("timestamp")))

    # weak_digest_only is computed over every signature walked, nested
    # included: reporting only the outer SHA-1 of a dual-signed binary would
    # make a modern binary look SHA-1-signed. A truncated walk has not seen
    # every signature, so a "no modern digest anywhere" verdict it could not
    # have reached is None (undecided) rather than a true the rule would fire
    # on -- the one modern signature may be the one past the window.
    block["signature_count"] = signature_count
    if modern_seen or signature_count == 0:
        block["weak_digest_only"] = False
    elif block.get("signature_walk_truncated"):
        block["weak_digest_only"] = None
    else:
        block["weak_digest_only"] = True
    if signature_errors:
        block["signature_errors"] = signature_errors

    if signature_count:
        block["parse_status"] = "parsed"
        for entry in block["signatures"]:
            digest = entry.get("digest") or {}
            if digest.get("digest_match") is not None:
                block["structural_integrity"] = {
                    "digest_match": digest["digest_match"],
                    "algorithm": digest["algorithm"],
                    "computed": digest["computed"],
                    "embedded": digest["embedded"],
                }
                break
        else:
            block["structural_integrity"] = {"recompute": "not_performed"}
    elif entries["count"] == 0 or block["parse_error"] or signature_errors:
        block["parse_status"] = "malformed"
        if not block["parse_error"]:
            block["parse_error"] = ";".join(signature_errors[:3]) or "no_certificate_entries"
        LOG.debug(f"PE code_signature malformed for {exe_file}: {block['parse_error']}")
    else:
        # A table of only non-PKCS#7 entries parsed cleanly but carries no
        # signature; that is a stated zero, not a malformed table.
        block["parse_status"] = "parsed"
        block["signature_count"] = 0
    return block
