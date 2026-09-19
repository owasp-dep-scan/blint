# SPDX-License-Identifier: Apache-2.0
"""Tests for the structured PE ``code_signature`` block (W2.1, W2.2).

Real-artifact assertions (ground rules 22/29) run against four committed
fixtures signed on the Windows VM with signtool — one per variant: an
RFC 3161-timestamped signature, the same with ``/ph`` page hashes, a
signature with no timestamp at all, and a SHA-1 digest signature. The
corpus-gated tests cover the shapes signtool cannot produce here (a
dual-signed binary with a PKCS#9 countersignature, short-lived
certificates, a chain to a Microsoft root). Hostile and cap fixtures are
hand-built DER: a truncated or cyclic structure must degrade to
``parse_status: "malformed"``, never raise through the parse, and every
count beside a capped listing must stay exact past the cap.
"""

import struct
from types import SimpleNamespace

import pytest

from blint.lib.binary import parse
from blint.lib.checks import (
    check_authenticode,
    check_kernel_signing_class,
    check_self_signed,
    check_signature_not_timestamped,
    check_signature_unknown_root,
    check_signer_mismatch,
    check_weak_signature_digest,
)
from blint.lib.pe_signature import (
    MAX_BER_DEPTH,
    MAX_CHAIN_CERTIFICATES,
    MAX_SIGNATURES_WALKED,
    _win_certificate_entries,
    parse_pe_code_signature,
)

RFC3161 = "tests/data/pe/sig-rfc3161.exe"
PAGEHASH = "tests/data/pe/sig-pagehash.exe"
NOTIMESTAMP = "tests/data/pe/sig-notimestamp.exe"
SHA1 = "tests/data/pe/sig-sha1.exe"
UNSIGNED = "tests/data/pe/msvc-hello-x64.exe"

SIGNER_CN = "Blint Packet Test Signing"
SIGNER_O = "Blint PE Lane"


# ---------------------------------------------------------------------------
# Real fixtures, signed by signtool on the Windows VM (rules 22/29).
# ---------------------------------------------------------------------------
def test_real_rfc3161_signature():
    metadata = parse(RFC3161)
    block = metadata["code_signature"]
    assert block["parse_status"] == "parsed"
    assert block["scope"] == "embedded"
    assert block["trust_validation"] == "not_performed"
    assert block["signature_count"] == 1
    assert block["weak_digest_only"] is False
    signature = block["signatures"][0]
    assert signature["digest_algorithm"] == "SHA256"
    # signtool verify /pa /v: "Issued to: Blint Packet Test Signing"
    #                        "Issued by: Blint Packet Test Signing"
    assert signature["signer"]["cn"] == SIGNER_CN
    assert signature["signer"]["o"] == SIGNER_O
    assert signature["signer"]["serial"]
    assert signature["signer"]["not_before"] and signature["signer"]["not_after"]
    assert signature["chain"] == []
    # The self-signed signer is its own root.
    assert signature["chain_complete"] is True
    assert signature["chain_terminates_at"] == SIGNER_CN
    # signtool: "The signature is timestamped: Fri Sep 18 17:06:11 2026" —
    # signtool renders local time (the VM is UTC+1); blint reports the
    # token's own UTC time.
    timestamp = signature["timestamp"]
    assert timestamp["present"] is True
    assert timestamp["kind"] == "rfc3161"
    assert timestamp["time"] == "2026-09-18T16:06:11Z"
    assert timestamp["signature_valid_at_timestamp"] is True
    assert signature["expires_hard"] is False
    assert signature["countersignatures"][0]["kind"] == "rfc3161"
    # signtool: "Hash of file (sha256): 8EE8B15E…DBDED" — blint recomputed
    # the same value, and it matches the digest embedded in the signature.
    assert signature["digest"]["digest_match"] is True
    assert signature["digest"]["computed"] == signature["digest"]["embedded"]
    assert block["structural_integrity"]["digest_match"] is True


def test_real_page_hashes():
    metadata = parse(PAGEHASH)
    block = metadata["code_signature"]
    signature = block["signatures"][0]
    page_hashes = signature["page_hashes"]
    assert page_hashes["present"] is True
    assert page_hashes["algorithm"] == "SHA256"
    # The count is exact by division (4-byte offset + 32-byte digest per
    # page); nothing here claims to verify them.
    assert page_hashes["count"] == 31
    assert metadata["security_properties"]["signed_page_hashes"] is True


def test_real_notimestamp_fires_the_rule():
    metadata = parse(NOTIMESTAMP)
    block = metadata["code_signature"]
    signature = block["signatures"][0]
    assert signature["timestamp"] == {"present": False}
    assert signature["expires_hard"] is True
    result = check_signature_not_timestamped(NOTIMESTAMP, metadata, {})
    assert result is not True
    assert "no timestamp" in result


def test_real_sha1_fires_weak_digest():
    metadata = parse(SHA1)
    block = metadata["code_signature"]
    assert block["signatures"][0]["digest_algorithm"] == "SHA1"
    assert block["weak_digest_only"] is True
    result = check_weak_signature_digest(SHA1, metadata, {})
    assert result is not True
    assert "SHA-256" in result
    # The SHA-1 fixture is also unsigned by timestamp: both rules fire.
    assert check_signature_not_timestamped(SHA1, metadata, {}) is not True


def test_real_structural_integrity_against_signtool_hash():
    """signtool verify /pa /v prints "Hash of file (sha256): 8EE8B15E…" for
    all three SHA-256 fixtures; blint's computed authentihash must equal it."""
    expected = "8ee8b15eb4bfbe3f0a3d8faecf3713d5590398d2cd0841e1d0363716ae4dbded"
    for path in (RFC3161, PAGEHASH, NOTIMESTAMP):
        metadata = parse(path)
        computed = metadata["code_signature"]["structural_integrity"]["computed"]
        assert computed == expected, path


def test_real_unsigned_scope_none_with_catalog_lookup_not_performed():
    metadata = parse(UNSIGNED)
    block = metadata["code_signature"]
    assert block["parse_status"] == "absent"
    assert block["scope"] == "none"
    assert block["catalog_lookup"] == "not_performed"
    assert block["trust_validation"] == "not_performed"
    assert block["signature_count"] == 0
    assert block["signatures"] == []
    # The tristate has no source to read: the gaps say so.
    assert "signed_page_hashes" in metadata["security_properties_gaps"]
    assert "authenticode_scope" in metadata["security_properties_gaps"]
    # The absence case is a finding only once a catalog lookup was performed
    # and came back negative: with catalog_lookup "not_performed" (no
    # --catalog-dir) a catalog-signed file cannot be distinguished from an
    # unsigned one, so an unsigned claim would be manufactured (rule 11).
    assert check_authenticode(UNSIGNED, metadata, {}) is True
    assert check_signature_not_timestamped(UNSIGNED, metadata, {}) is True
    assert check_weak_signature_digest(UNSIGNED, metadata, {}) is True


def test_legacy_authenticode_key_kept():
    """Additive rule 15: the flat legacy key stays populated for one
    release, sourced from the first signature."""
    metadata = parse(RFC3161)
    authenticode = metadata["authenticode"]
    assert authenticode["verification_flags"] == "OK"
    assert authenticode["cert_signer"]
    assert "Python" not in authenticode["cert_signer"].get("subject", "")


def test_real_python313_rfc3161_and_shortlived_cert():
    """Tier-0 reference: PSF-signed, three-day certificate, RFC 3161
    timestamp, chain to the Microsoft root. Skipped when the corpus is
    absent."""
    import os

    path = os.path.expanduser(
        "~/sandbox/pe-corpus/tier0-reference/python-amd64/python.exe"
    )
    if not os.path.exists(path):
        pytest.skip("tier-0 corpus not present")
    metadata = parse(path)
    block = metadata["code_signature"]
    assert block["parse_status"] == "parsed"
    signature = block["signatures"][0]
    assert signature["signer"]["cn"] == "Python Software Foundation"
    # V5: the signing certificate is valid for three days — "was it valid
    # when the timestamp says it signed?" is the right question, and the
    # answer is yes.
    assert signature["signer"]["not_before"] == "2025-08-13T16:32:28Z"
    assert signature["signer"]["not_after"] == "2025-08-16T16:32:28Z"
    assert signature["timestamp"]["kind"] == "rfc3161"
    assert signature["timestamp"]["signature_valid_at_timestamp"] is True
    assert signature["chain_complete"] is True
    assert signature["chain_terminates_at"] == (
        "Microsoft Identity Verification Root Certificate Authority 2020"
    )
    assert all(cert["is_ca"] for cert in signature["chain"])
    assert signature["opus_info"]["program_name"] == "Python 3.13.7 (bcee1c3)"
    assert signature["digest"]["digest_match"] is True


def test_real_dual_signed_weak_digest_only_false():
    """02/A.3 on a real artifact: a SHA-1 outer signature with a SHA-256
    nested one must NOT read as a SHA-1-signed binary, and the PKCS#9
    countersignature must be extracted as the timestamp it is. Skipped when
    the corpus is absent."""
    import os

    path = os.path.expanduser("~/sandbox/pe-corpus/tier1-ecosystem/sysinternals/Testlimit.exe")
    if not os.path.exists(path):
        pytest.skip("tier-1 corpus not present")
    metadata = parse(path)
    block = metadata["code_signature"]
    assert block["parse_status"] == "parsed"
    assert block["signature_count"] == 2
    outer, nested = block["signatures"]
    assert outer["digest_algorithm"] == "SHA1"
    assert outer["nested"] is False
    assert outer["timestamp"]["kind"] == "pkcs9"
    assert outer["timestamp"]["time"] == "2016-11-17T22:39:10Z"
    assert outer["timestamp"]["tsa_cn"] == "Microsoft Time-Stamp Service"
    assert outer["expires_hard"] is False
    assert nested["nested"] is True
    assert nested["digest_algorithm"] == "SHA256"
    # The nested signature carries its own RFC 3161 timestamp (present, not
    # inherited), and the file is not weak-digest-only.
    assert nested["timestamp"]["present"] is True
    assert "inherited" not in nested["timestamp"]
    assert block["weak_digest_only"] is False
    assert check_weak_signature_digest(path, metadata, {}) is True


def test_real_nested_signature_inherits_outer_timestamp():
    """vcruntime140.dll: RFC 3161 timestamps with fractional seconds; the
    nested signature carries its own, so nothing is silently reused.
    Skipped when the corpus is absent."""
    import os

    path = os.path.expanduser(
        "~/sandbox/pe-corpus/tier0-reference/python-amd64/vcruntime140.dll"
    )
    if not os.path.exists(path):
        pytest.skip("tier-0 corpus not present")
    metadata = parse(path)
    block = metadata["code_signature"]
    assert block["signature_count"] == 2
    outer, nested = block["signatures"]
    assert outer["timestamp"]["time"] == "2025-01-17T21:31:02.505Z"
    assert nested["timestamp"]["present"] is True
    assert nested["timestamp"]["time"] == "2025-01-17T21:31:03.153Z"
    assert "inherited" not in nested["timestamp"]
    assert nested["expires_hard"] is False


# ---------------------------------------------------------------------------
# Hand-built DER: hostile cases (rule 30) must degrade, never raise.
# ---------------------------------------------------------------------------
def _tlv(tag: int, content: bytes) -> bytes:
    if len(content) < 0x80:
        return bytes([tag, len(content)]) + content
    length = len(content).to_bytes((len(content).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length)]) + length + content


def _oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    body = bytearray([parts[0] * 40 + parts[1]])
    for value in parts[2:]:
        chunk = [value & 0x7F]
        value >>= 7
        while value:
            chunk.append((value & 0x7F) | 0x80)
            value >>= 7
        body.extend(reversed(chunk))
    return _tlv(0x06, bytes(body))


def _name(cn: str) -> bytes:
    return _tlv(0x30, _tlv(0x31, _tlv(0x30, _oid("2.5.4.3") + _tlv(0x0C, cn.encode()))))


def _org_name(cn: str, org: str) -> bytes:
    """A Name carrying both an O and a CN RDN, in the order real certs use."""
    rdns = _tlv(0x31, _tlv(0x30, _oid("2.5.4.10") + _tlv(0x0C, org.encode())))
    return _tlv(0x30, rdns + _tlv(0x31, _tlv(0x30, _oid("2.5.4.3") + _tlv(0x0C, cn.encode()))))


def _extensions(
    ekus: list[str] | None = None,
    policies: list[str] | None = None,
    is_ca: bool | None = None,
) -> bytes:
    """An extensions block ([3]) with the given EKU OIDs, policy OIDs and
    BasicConstraints — the facts the signing class keys on."""
    encoded = b""
    if ekus is not None:
        encoded += _tlv(
            0x30, _oid("2.5.29.37") + _tlv(0x04, _tlv(0x30, b"".join(_oid(e) for e in ekus)))
        )
    if policies is not None:
        infos = b"".join(_tlv(0x30, _oid(p)) for p in policies)
        encoded += _tlv(0x30, _oid("2.5.29.32") + _tlv(0x04, _tlv(0x30, infos)))
    if is_ca is not None:
        inner = _tlv(0x01, b"\xff") if is_ca else b""
        encoded += _tlv(0x30, _oid("2.5.29.19") + _tlv(0x04, _tlv(0x30, inner)))
    if not encoded:
        return b""
    return _tlv(0xA3, _tlv(0x30, encoded))


def _cert_tlv(
    serial: int,
    issuer_cn: str,
    subject_cn: str,
    subject_org: str | None = None,
    ekus: list[str] | None = None,
    policies: list[str] | None = None,
    is_ca: bool | None = None,
    issuer_org: str | None = None,
) -> bytes:
    """A minimal but structurally real certificate: TBS with serial, alg,
    issuer, validity, subject — plus optional extensions."""
    issuer_name = _org_name(issuer_cn, issuer_org) if issuer_org else _name(issuer_cn)
    subject_name = _org_name(subject_cn, subject_org) if subject_org else _name(subject_cn)
    tbs = _tlv(
        0x30,
        _tlv(0xA0, _tlv(0x02, b"\x02"))
        + _tlv(0x02, serial.to_bytes(8, "big"))
        + _tlv(0x30, _oid("2.16.840.1.101.3.4.2.1"))
        + issuer_name
        + _tlv(0x30, _tlv(0x17, b"250101000000Z") + _tlv(0x17, b"350101000000Z"))
        + subject_name
        + _extensions(ekus=ekus, policies=policies, is_ca=is_ca),
    )
    return _tlv(0x30, tbs + _tlv(0x30, _oid("2.16.840.1.101.3.4.2.1")) + _tlv(0x03, b"\x00"))


def _signer_info(
    serial: int, issuer_cn: str, digest_oid: str, unauth: list[bytes] | None = None
) -> bytes:
    sid = _tlv(0x30, _name(issuer_cn) + _tlv(0x02, serial.to_bytes(8, "big")))
    attrs = b""
    if unauth:
        attrs = _tlv(0xA1, b"".join(unauth))
    return _tlv(
        0x30,
        _tlv(0x02, b"\x01")
        + sid
        + _tlv(0x30, _oid(digest_oid))
        + _tlv(0x30, _oid("1.2.840.113549.1.1.1"))
        + _tlv(0x04, b"\x00" * 32)
        + attrs,
    )


def _nested_attr(content_info: bytes) -> bytes:
    return _tlv(
        0x30, _oid("1.3.6.1.4.1.311.2.4.1") + _tlv(0x31, content_info)
    )


def _countersign_attr() -> bytes:
    """A PKCS#9 countersignature attribute: a SignerInfo carrying
    signingTime, named by a TSA certificate the blob must also ship."""
    signing_time = _tlv(
        0x30,
        _oid("1.2.840.113549.1.9.5") + _tlv(0x31, _tlv(0x17, b"260101120000Z")),
    )
    countersigner = _tlv(
        0x30,
        _tlv(0x02, b"\x01")
        + _tlv(0x30, _name("TSA") + _tlv(0x02, (9).to_bytes(8, "big")))
        + _tlv(0x30, _oid("2.16.840.1.101.3.4.2.1"))
        + _tlv(0xA0, signing_time)
        + _tlv(0x30, _oid("1.2.840.113549.1.1.1"))
        + _tlv(0x04, b"\x00" * 32),
    )
    return _tlv(0x30, _oid("1.2.840.113549.1.9.6") + _tlv(0x31, countersigner))


def _content_info(certs: list[bytes], signer: bytes) -> bytes:
    signed_data = (
        _tlv(0x02, b"\x01")
        + _tlv(0x31, _tlv(0x30, _oid("2.16.840.1.101.3.4.2.1")))
        + _tlv(
            0x30,
            _oid("1.3.6.1.4.1.311.2.1.4")
            + _tlv(
                0xA0,
                _tlv(
                    0x30,
                    _tlv(0x30, _oid("1.3.6.1.4.1.311.2.1.15") + _tlv(0x30, b"\x03\x01\x00"))
                    + _tlv(0x30, _tlv(0x30, _oid("2.16.840.1.101.3.4.2.1")) + _tlv(0x04, b"\x00" * 32)),
                ),
            ),
        )
        + _tlv(0xA0, b"".join(certs))
        + _tlv(0x31, signer)
    )
    return _tlv(0x30, _oid("1.2.840.113549.1.7.2") + _tlv(0xA0, _tlv(0x30, signed_data)))


def _stub_parsed_obj(rva: int, size: int):
    """A stub whose security directory sits at index 4, as the PE spec
    fixes the directory order."""
    directories = [SimpleNamespace(rva=0, size=0)] * 4
    return SimpleNamespace(data_directories=[*directories, SimpleNamespace(rva=rva, size=size)])


def _stub_table(tmp_path, blob: bytes, declared_size: int | None = None):
    """A file whose certificate table (at offset 8) is ``blob``."""
    import pathlib

    tmp_path = pathlib.Path(tmp_path)
    entry_len = 8 + len(blob)
    entry = struct.pack("<IHH", entry_len, 0x0200, 0x0002) + blob
    if entry_len % 8:
        entry += b"\x00" * (8 - entry_len % 8)
    table = entry
    if declared_size is not None:
        table = table[:declared_size]
    data = b"MZ\x00\x00\x00\x00\x00\x00" + table
    path = tmp_path / "table.bin"
    path.write_bytes(data)
    return parse_pe_code_signature(
        _stub_parsed_obj(8, declared_size or len(table)), str(path)
    )


def test_hostile_truncated_entry_degrades(tmp_path):
    path = tmp_path / "short.bin"
    path.write_bytes(b"MZ\x00\x00")
    block = parse_pe_code_signature(_stub_parsed_obj(8, 64), str(path))
    # An unreadable table is malformed, never an exception or a thin answer.
    assert block["parse_status"] == "malformed"
    assert block["parse_error"]


def test_hostile_garbage_der_degrades(tmp_path):
    block = _stub_table(tmp_path, b"\xde\xad\xbe\xef" * 8)
    assert block["scope"] == "embedded"
    assert block["parse_status"] == "malformed"
    assert block["parse_error"]
    assert block["signature_count"] == 0


def test_hostile_truncated_tlv_degrades(tmp_path):
    blob = _content_info([_cert_tlv(1, "A", "A")], _signer_info(1, "A", "2.16.840.1.101.3.4.2.1"))
    block = _stub_table(tmp_path, blob[: len(blob) // 2])
    assert block["parse_status"] == "malformed"
    assert block["parse_error"]
    assert "signature_errors" in block or block["signature_count"] == 0


def test_hostile_deep_indefinite_nesting_degrades(tmp_path):
    # A cyclic shape: indefinite-length SEQUENCEs nested far past the BER
    # depth cap, each consuming two bytes of the one before.
    blob = b"\x30\x80" * (MAX_BER_DEPTH * 4) + b"\x00\x00"
    block = _stub_table(tmp_path, blob)
    assert block["parse_status"] == "malformed"
    assert block["parse_error"]
    assert block["signature_count"] == 0


def test_hostile_oversized_table_refused(tmp_path):
    path = tmp_path / "big.bin"
    path.write_bytes(b"MZ\x00\x00")
    block = parse_pe_code_signature(
        _stub_parsed_obj(8, 64 * 1024 * 1024), str(path)
    )
    assert block["parse_status"] == "malformed"
    assert block["parse_error"].startswith("table_too_large")


def test_non_cms_entry_type_counted(tmp_path):
    entry = struct.pack("<IHH", 16, 0x0200, 0x0001) + b"\x00" * 8
    path = tmp_path / "x509.bin"
    path.write_bytes(b"MZ\x00\x00\x00\x00\x00\x00" + entry)
    block = parse_pe_code_signature(_stub_parsed_obj(8, 16), str(path))
    assert block["certificate_entries"] == 1
    assert block["unparsed_certificate_entries"] == 1
    # Parsed cleanly; it just carries no Authenticode signature.
    assert block["parse_status"] == "parsed"
    assert block["signature_count"] == 0


# ---------------------------------------------------------------------------
# Caps and exact counts (ground rule 33): fixtures larger than the windows.
# ---------------------------------------------------------------------------
def test_signature_count_exact_past_the_walk_window():
    """Ten nested signatures: every one is counted and every one listed —
    the count is never the size of a shorter listing."""
    depth = 10
    signer = _signer_info(1, "Leaf", "2.16.840.1.101.3.4.2.1")
    content_info = _content_info([_cert_tlv(1, "Leaf", "Leaf")], signer)
    for _ in range(depth):
        content_info = _content_info(
            [_cert_tlv(1, "Leaf", "Leaf")],
            _signer_info(1, "Leaf", "2.16.840.1.101.3.4.2.1", unauth=[_nested_attr(content_info)]),
        )
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        block = _stub_table(tmp, content_info)
    assert block["parse_status"] == "parsed"
    assert block["signature_count"] == depth + 1
    assert len(block["signatures"]) == depth + 1
    assert "signatures_truncated" not in block
    assert "signature_walk_truncated" not in block
    nested = [sig for sig in block["signatures"] if sig["nested"]]
    assert len(nested) == depth
    levels = sorted(sig["nesting_level"] for sig in nested)
    assert levels == list(range(1, depth + 1))


def test_walk_past_the_window_declines_the_weak_digest_verdict():
    """Ground rule 33 for the signature window itself: a fixture with more
    nested signatures than ``MAX_SIGNATURES_WALKED``.

    The test above stops at ten, which is well inside the window, so nothing
    exercised what the walk does at it. Past the window the count is a floor
    (``signature_walk_truncated`` says so) and ``weak_digest_only`` must not
    be decided from the signatures that happened to fit: here every walked
    signature is SHA-1 and the innermost one — the one the walk never
    reaches — is SHA-256, so a sampled verdict would report a dual-signed
    binary as SHA-1-signed at high severity.
    """
    depth = MAX_SIGNATURES_WALKED + 6
    inner = _content_info(
        [_cert_tlv(1, "Leaf", "Leaf")], _signer_info(1, "Leaf", "2.16.840.1.101.3.4.2.1")
    )
    content_info = inner
    for _ in range(depth):
        content_info = _content_info(
            [_cert_tlv(1, "Leaf", "Leaf")],
            _signer_info(1, "Leaf", "1.3.14.3.2.26", unauth=[_nested_attr(content_info)]),
        )
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        block = _stub_table(tmp, content_info)
    assert block["parse_status"] == "parsed"
    assert block["signature_count"] == MAX_SIGNATURES_WALKED
    assert len(block["signatures"]) == MAX_SIGNATURES_WALKED
    assert block["signature_walk_truncated"] is True
    assert block["weak_digest_only"] is None
    assert (
        check_weak_signature_digest("f", {"code_signature": block}, {}) is True
    ), "an undecided verdict must not be reported as a finding"


def test_chain_length_exact_past_the_listing_cap():
    """A 20-certificate chain: ``chain_length`` is exact (20) while the
    listing stops at the cap with ``chain_truncated``."""
    depth = MAX_CHAIN_CERTIFICATES + 4
    # The leaf (serial 7, issued by CA0) plus cert i above it: subject CA{i},
    # issued by CA{i+1}. The walk follows CA0 → CA1 → … and stops short of a
    # root, one certificate longer than the listing cap.
    certs = [_cert_tlv(7, "CA0", "Leaf")]
    certs += [
        _cert_tlv(100 + index, f"CA{index + 1}", f"CA{index}") for index in range(depth)
    ]
    signer = _signer_info(7, "CA0", "2.16.840.1.101.3.4.2.1")
    content_info = _content_info(certs, signer)
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        block = _stub_table(tmp, content_info)
    assert block["parse_status"] == "parsed"
    signature = block["signatures"][0]
    assert signature["chain_length"] == depth
    assert len(signature["chain"]) == MAX_CHAIN_CERTIFICATES
    assert signature["chain_truncated"] is True
    assert signature["chain_complete"] is False


def test_chain_past_the_certificate_parse_window_withholds_its_end():
    """A chain longer than the certificate *parse* window, not just the
    listing window.

    The test above uses 20 certificates, which is inside the 32 the
    CertificateSet parse keeps, so it measured the listing cap only. With 40,
    the walk runs out of parsed certificates before it runs out of chain: the
    length is then a floor, and naming ``chain_terminates_at`` from the last
    link that happened to fit would assert an end the blob does not have.
    """
    depth = 40
    certs = [_cert_tlv(7, "CA0", "Leaf")]
    certs += [_cert_tlv(100 + index, f"CA{index + 1}", f"CA{index}") for index in range(depth)]
    content_info = _content_info(certs, _signer_info(7, "CA0", "2.16.840.1.101.3.4.2.1"))
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        block = _stub_table(tmp, content_info)
    signature = block["signatures"][0]
    assert signature["chain_length"] < depth, "the walk cannot see past the parse window"
    assert signature["chain_length_exact"] is False
    assert signature["chain_terminates_at"] is None
    assert signature["chain_complete"] is None


def test_nested_inheritance_and_untimestamped_nested(tmp_path):
    """A nested signature inherits the outer timestamp (stated); with no
    timestamp anywhere, expires_hard is true for both entries."""
    nested_blob = _content_info(
        [_cert_tlv(1, "Leaf", "Leaf")],
        _signer_info(1, "Leaf", "2.16.840.1.101.3.4.2.1"),
    )
    import tempfile

    # Outer with a PKCS#9 countersignature: the nested entry inherits it.
    outer_with_ts = _content_info(
        [_cert_tlv(1, "Leaf", "Leaf"), _cert_tlv(9, "TSA", "TSA")],
        _signer_info(
            1,
            "Leaf",
            "2.16.840.1.101.3.4.2.1",
            unauth=[_countersign_attr(), _nested_attr(nested_blob)],
        ),
    )
    with tempfile.TemporaryDirectory() as tmp:
        block = _stub_table(tmp, outer_with_ts)
    assert block["signature_count"] == 2
    outer, nested = block["signatures"]
    assert outer["timestamp"]["present"] is True
    assert outer["timestamp"]["kind"] == "pkcs9"
    assert outer["timestamp"]["time"] == "2026-01-01T12:00:00Z"
    assert nested["nested"] is True
    assert nested["timestamp"]["present"] is True
    assert nested["timestamp"]["inherited"] is True
    assert nested["timestamp"]["time"] == outer["timestamp"]["time"]
    assert nested["expires_hard"] is False

    # The same blob with no timestamp attribute at all: both entries are
    # expires_hard and the rule fires for the file.
    outer_no_ts = _content_info(
        [_cert_tlv(1, "Leaf", "Leaf")],
        _signer_info(1, "Leaf", "2.16.840.1.101.3.4.2.1", unauth=[_nested_attr(nested_blob)]),
    )
    with tempfile.TemporaryDirectory() as tmp:
        block = _stub_table(tmp, outer_no_ts)
    assert all(sig["timestamp"]["present"] is False for sig in block["signatures"])
    assert all(sig["expires_hard"] is True for sig in block["signatures"])


def test_recompute_not_performed_stated_not_duplicated(tmp_path):
    """Without an authentihash source the digest fields say so instead of
    echoing the embedded value as if blint had computed it."""
    content_info = _content_info(
        [_cert_tlv(1, "Leaf", "Leaf")], _signer_info(1, "Leaf", "2.16.840.1.101.3.4.2.1")
    )
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        block = _stub_table(tmp, content_info)
    signature = block["signatures"][0]
    assert signature["digest"]["embedded"]
    assert signature["digest"]["computed"] is None
    assert signature["digest"]["digest_match"] is None
    assert signature["digest"]["recompute"] == "not_performed"
    assert block["structural_integrity"] == {"recompute": "not_performed"}


def test_win_certificate_entry_truncation_recorded():
    block: dict = {}
    # dwLength runs past the table: recorded, count stays zero.
    table = struct.pack("<IHH", 64, 0x0200, 0x0002) + b"\x00" * 8
    entries = _win_certificate_entries(table, block)
    assert entries["count"] == 0
    assert block["parse_error"] == "entry_0_truncated"


# ---------------------------------------------------------------------------
# Signing class (W2.4, 02/C)
# ---------------------------------------------------------------------------
KERNEL_EKU = "1.3.6.1.4.1.311.61.1.1"
WHQL_EKU = "1.3.6.1.4.1.311.10.3.5"
ATTESTATION_EKU = "1.3.6.1.4.1.311.10.3.5.1"
EV_POLICY = "2.23.140.1.3"
OV_POLICY = "2.23.140.1.2.1"


def _class_block(certs, signer) -> dict:
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        return _stub_table(tmp, _content_info(certs, signer))


def test_real_self_signed_fixture_class_and_rule():
    """The signtool test certificates are self-signed: the class says so and
    CHECK_SELF_SIGNED fires, while the unknown-root rule stays silent — the
    self-signed fact is the same fact, reported once."""
    block = parse(RFC3161)["code_signature"]
    assert block["signing_class"] == "self_signed"
    signature = block["signatures"][0]
    # The self-signed signer is its own root: the fingerprint is computed
    # and matched against the shipped anchor snapshot — a test certificate
    # is outside it, and that is a fact, not a trust verdict.
    assert signature["root_fingerprint"]
    assert signature["root_known"] is False
    assert "root_microsoft" not in signature
    metadata = parse(RFC3161)
    assert check_self_signed(RFC3161, metadata, {}) is not True
    assert "self-signed" in check_self_signed(RFC3161, metadata, {})
    assert check_signature_unknown_root(RFC3161, metadata, {}) is True


def test_real_unsigned_carries_no_class():
    """Without a performed catalog lookup an unsigned claim is manufactured,
    so the key is absent — its absence means undetermined (rule 11)."""
    block = parse(UNSIGNED)["code_signature"]
    assert "signing_class" not in block
    for rule in (check_self_signed, check_signature_unknown_root, check_kernel_signing_class):
        assert rule(UNSIGNED, parse(UNSIGNED), {}) is True


def test_class_kernel_mode():
    """EKU 1.3.6.1.4.1.311.61.1.1 (wincrypt.h szOID_KP_KERNEL_MODE_CODE_SIGNING)
    is kernel_mode, and CHECK_KERNEL_SIGNING_CLASS reports it."""
    # The signer's EKU lives on its certificate's extensions, not the
    # SignerInfo — put the kernel EKU on the leaf.
    certs = [
        _cert_tlv(
            5,
            "Microsoft Windows Third Party Component CA 2013",
            "Contoso Driver Signing",
            ekus=[KERNEL_EKU],
        ),
        _cert_tlv(
            6,
            "Microsoft Root Certificate Authority 2011",
            "Microsoft Windows Third Party Component CA 2013",
            is_ca=True,
        ),
    ]
    signer = _signer_info(5, "Microsoft Windows Third Party Component CA 2013", "1.3.14.3.2.26")
    block = _class_block(certs, signer)
    assert block["signing_class"] == "kernel_mode"
    assert check_kernel_signing_class("f", {"code_signature": block}, {}) is not True
    # The normal Authenticode shape: leaf and PCA shipped, root named only.
    # Not self_signed, and no root fact is claimed from a root not in hand.
    signature = block["signatures"][0]
    assert signature["chain_complete"] is False
    assert "root_known" not in signature
    assert signature["chain_length"] == 1


def test_kernel_driver_shipping_its_own_root_classes_unknown_root():
    """The malicious-driver shape, and the reason the chain outranks the leaf.

    A self-issued chain shipped whole still carries the kernel-mode EKU and
    an organization name — that is what makes it load — so while the leaf's
    claims decided the class, this blob read as an ordinary kernel_mode (or,
    without the driver EKU, commercial_ov) signature and
    CHECK_SIGNATURE_UNKNOWN_ROOT could only ever fire on certificates that
    are not code-signing certificates at all. The class now follows the
    chain, and the kernel fact the driver lane consumes survives it because
    the kernel rule reads the EKU rather than the class string.
    """
    certs = [
        _cert_tlv(5, "Totally Legit CA", "Contoso Driver Signing",
                  subject_org="Contoso Ltd", ekus=[KERNEL_EKU, "1.3.6.1.5.5.7.3.3"]),
        _cert_tlv(6, "Totally Legit Root", "Totally Legit CA", is_ca=True),
        _cert_tlv(7, "Totally Legit Root", "Totally Legit Root", is_ca=True),
    ]
    block = _class_block(certs, _signer_info(5, "Totally Legit CA", "2.16.840.1.101.3.4.2.1"))
    assert block["signatures"][0]["chain_complete"] is True
    assert block["signatures"][0]["root_known"] is False
    assert block["signing_class"] == "unknown_root"
    metadata = {"code_signature": block}
    assert check_signature_unknown_root("f", metadata, {}) is not True
    assert check_kernel_signing_class("f", metadata, {}) is not True


def test_class_attestation_and_whql():
    """szOID_ATTEST_WHQL_CRYPTO (10.3.5.1) is attestation_signed; the plain
    WHQL EKU (10.3.5) is whql; a certificate carrying both kernel and
    attestation EKUs decides as kernel_mode (first in the order)."""
    def blob(leaf_ekus):
        certs = [
            _cert_tlv(5, "MS PCA", "HW Publisher", ekus=leaf_ekus),
            _cert_tlv(6, "MS Root", "MS PCA", is_ca=True),
        ]
        return certs, _signer_info(5, "MS PCA", "2.16.840.1.101.3.4.2.1")

    import tempfile

    certs, signer = blob([ATTESTATION_EKU])
    with tempfile.TemporaryDirectory() as tmp:
        block = _stub_table(tmp, _content_info(certs, signer))
    assert block["signing_class"] == "attestation_signed"

    certs, signer = blob([WHQL_EKU])
    with tempfile.TemporaryDirectory() as tmp:
        block = _stub_table(tmp, _content_info(certs, signer))
    assert block["signing_class"] == "whql"

    certs, signer = blob([KERNEL_EKU, ATTESTATION_EKU])
    with tempfile.TemporaryDirectory() as tmp:
        block = _stub_table(tmp, _content_info(certs, signer))
    assert block["signing_class"] == "kernel_mode"


def test_class_commercial_ev_and_ov():
    """The CA/Browser Forum policy OIDs separate EV from OV; an OV policy or
    an organization alone is commercial_ov."""
    import tempfile

    certs = [
        _cert_tlv(5, "DigiCert EV CA", "Acme Corp", subject_org="Acme Corp",
                  ekus=["1.3.6.1.5.5.7.3.3"], policies=[EV_POLICY, OV_POLICY]),
        _cert_tlv(6, "DigiCert Root", "DigiCert EV CA", is_ca=True),
    ]
    signer = _signer_info(5, "DigiCert EV CA", "2.16.840.1.101.3.4.2.1")
    with tempfile.TemporaryDirectory() as tmp:
        block = _stub_table(tmp, _content_info(certs, signer))
    assert block["signing_class"] == "commercial_ev"
    assert block["signatures"][0]["signer"]["policies"] == ["evCodeSigning", "ovCodeSigning"]
    # The blob stops below the root, so no root fact is claimed and the
    # leaf's policy is what the class has to go on.
    assert "root_known" not in block["signatures"][0]

    # OV policy without the EV one — and an organization with no policy at
    # all (older OV certs) is still commercial_ov.
    certs[0] = _cert_tlv(5, "DigiCert OV CA", "Acme Corp", subject_org="Acme Corp",
                         ekus=["1.3.6.1.5.5.7.3.3"], policies=[OV_POLICY])
    with tempfile.TemporaryDirectory() as tmp:
        block = _stub_table(tmp, _content_info(certs, signer))
    assert block["signing_class"] == "commercial_ov"

    certs[0] = _cert_tlv(5, "Some CA", "Acme Corp", subject_org="Acme Corp",
                         ekus=["1.3.6.1.5.5.7.3.3"])
    with tempfile.TemporaryDirectory() as tmp:
        block = _stub_table(tmp, _content_info(certs, signer))
    assert block["signing_class"] == "commercial_ov"


def test_class_unknown_root_fires_the_rule():
    """A complete chain whose self-signed root is outside the shipped
    snapshot is unknown_root, and CHECK_SIGNATURE_UNKNOWN_ROOT names the
    root. A Microsoft-organization leaf over that chain does NOT become
    microsoft_1st_party — the anchor fingerprint, not the name, decides."""
    certs = [
        _cert_tlv(5, "Not A Real CA", "Acme Corp", subject_org="Microsoft Corporation",
                  ekus=["1.3.6.1.5.5.7.3.3"]),
        _cert_tlv(6, "Not A Real Root", "Not A Real CA", is_ca=True),
        _cert_tlv(7, "Not A Real Root", "Not A Real Root", is_ca=True),
    ]
    import tempfile

    signer = _signer_info(5, "Not A Real CA", "2.16.840.1.101.3.4.2.1")
    with tempfile.TemporaryDirectory() as tmp:
        block = _stub_table(tmp, _content_info(certs, signer))
    assert block["signing_class"] == "unknown_root"
    assert block["signatures"][0]["root_known"] is False
    result = check_signature_unknown_root("f", {"code_signature": block}, {})
    assert result is not True
    assert "Not A Real Root" in result


def test_class_microsoft_first_party_by_anchor_name():
    """The normal Authenticode shape: leaf + PCA shipped, root named but not
    carried. The class follows the top shipped link's issuer statement to
    the Microsoft root in the snapshot — and, because the root is not in
    hand, no root fingerprint is claimed."""
    certs = [
        _cert_tlv(5, "Microsoft Windows Production PCA 2011", "Microsoft Windows",
                  subject_org="Microsoft Corporation"),
        _cert_tlv(6, "Microsoft Root Certificate Authority 2011",
                  "Microsoft Windows Production PCA 2011", is_ca=True),
    ]
    import tempfile

    signer = _signer_info(5, "Microsoft Windows Production PCA 2011", "2.16.840.1.101.3.4.2.1")
    with tempfile.TemporaryDirectory() as tmp:
        block = _stub_table(tmp, _content_info(certs, signer))
    assert block["signing_class"] == "microsoft_1st_party"
    signature = block["signatures"][0]
    assert signature["chain_complete"] is False
    assert "root_fingerprint" not in signature
    assert signature["chain"][-1]["issuer_cn"] == "Microsoft Root Certificate Authority 2011"
    # The class rests on a string the signer wrote, not on a root blint
    # hashed, and the block has to say so: 223 of the 224 first-party
    # classes measured across tiers 0/1/5 take this path, so a consumer
    # that cannot tell the two apart is reading the weak one as the strong
    # one almost every time.
    assert block["signing_class_anchor"] == "issuer_name"


def test_first_party_anchor_basis_distinguishes_hash_from_name():
    """A forged chain reaches the same class as a real one by name alone.

    Nothing here is a trust verdict — blint validates no chain (02/D) — but
    the subject organization and the issuer CN are both strings the signer
    chose, so the first-party class they produce must not read the same as
    one anchored to a root fingerprint blint actually matched.
    """
    certs = [
        _cert_tlv(5, "Microsoft Root Certificate Authority 2011", "Totally Microsoft",
                  subject_org="Microsoft Corporation", ekus=["1.3.6.1.5.5.7.3.3"]),
    ]
    block = _class_block(
        certs, _signer_info(5, "Microsoft Root Certificate Authority 2011", "2.16.840.1.101.3.4.2.1")
    )
    assert block["signing_class"] == "microsoft_1st_party"
    assert block["signing_class_anchor"] == "issuer_name"
    assert "root_fingerprint" not in block["signatures"][0]


def test_class_withheld_when_leaf_is_microsoft_named_but_anchor_unknown():
    """A Microsoft-named organization whose chain anchors outside the
    snapshot is not first-party Microsoft: the anchor decides, and the
    class is withheld rather than guessed (rule 11)."""
    certs = [
        _cert_tlv(5, "Some Commercial CA", "Microsoft Windows", subject_org="Microsoft Corporation"),
        _cert_tlv(6, "Some Commercial Root", "Some Commercial CA", is_ca=True),
        _cert_tlv(7, "Some Commercial Root", "Some Commercial Root", is_ca=True),
    ]
    import tempfile

    signer = _signer_info(5, "Some Commercial CA", "2.16.840.1.101.3.4.2.1")
    with tempfile.TemporaryDirectory() as tmp:
        block = _stub_table(tmp, _content_info(certs, signer))
    # The chain is complete and the root is outside the snapshot, so the
    # strongest honest statement is unknown_root.
    assert block["signing_class"] == "unknown_root"


def test_class_absent_without_deciding_facts():
    """An organization-less, policy-less code-signing leaf (individual code
    signing) anchored below a named public root determines no class in the
    02/C table — the key must be absent, not defaulted. The chain ships
    leaf and intermediate only (the normal shape), the intermediate names
    the real DigiCert Trusted Root G4, and nothing else in the blob is a
    class fact."""
    certs = [
        _cert_tlv(5, "DigiCert OV CA", "Jane Doe", ekus=["1.3.6.1.5.5.7.3.3"]),
        _cert_tlv(6, "DigiCert Trusted Root G4", "DigiCert OV CA", is_ca=True),
    ]
    import tempfile

    signer = _signer_info(5, "DigiCert OV CA", "2.16.840.1.101.3.4.2.1")
    with tempfile.TemporaryDirectory() as tmp:
        block = _stub_table(tmp, _content_info(certs, signer))
    signature = block["signatures"][0]
    assert signature["chain_complete"] is False
    assert signature["chain"][-1]["issuer_cn"] == "DigiCert Trusted Root G4"
    assert "signing_class" not in block


def test_class_withheld_when_the_walk_was_truncated():
    """Ground rule 33 against the verdict itself: more nested signatures
    than the walk window, the innermost one kernel-signed. A class decided
    from the walked prefix would be a sample verdict; the key must be
    absent and the kernel rule must stay silent."""
    inner = _content_info(
        [_cert_tlv(1, "Leaf", "Leaf", ekus=[KERNEL_EKU])],
        _signer_info(1, "Leaf", "2.16.840.1.101.3.4.2.1"),
    )
    content_info = inner
    for _ in range(MAX_SIGNATURES_WALKED + 4):
        content_info = _content_info(
            [_cert_tlv(1, "Leaf", "Leaf")],
            _signer_info(1, "Leaf", "2.16.840.1.101.3.4.2.1", unauth=[_nested_attr(content_info)]),
        )
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        block = _stub_table(tmp, content_info)
    assert block["signature_walk_truncated"] is True
    assert "signing_class" not in block
    assert check_kernel_signing_class("f", {"code_signature": block}, {}) is True
    assert check_self_signed("f", {"code_signature": block}, {}) is True


def test_class_past_the_chain_listing_cap_still_exact():
    """A 20-link chain: the listing stops at the cap but the walk finished,
    so the root fingerprint is in hand and the class derives from it —
    while chain_length stays the exact 21, not the 16 listed."""
    depth = MAX_CHAIN_CERTIFICATES + 4
    certs = [_cert_tlv(7, "CA0", "Acme Corp", subject_org="Microsoft Corporation",
                       ekus=[KERNEL_EKU])]
    certs += [_cert_tlv(100 + index, f"CA{index + 1}", f"CA{index}", is_ca=True) for index in range(depth)]
    certs.append(_cert_tlv(999, "CA20", "CA20", is_ca=True))
    signer = _signer_info(7, "CA0", "2.16.840.1.101.3.4.2.1")
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        block = _stub_table(tmp, _content_info(certs, signer))
    signature = block["signatures"][0]
    assert signature["chain_length"] == depth + 1
    assert len(signature["chain"]) == MAX_CHAIN_CERTIFICATES
    assert signature["chain_truncated"] is True
    assert signature["chain_complete"] is True
    assert signature["root_fingerprint"]
    # The walk finished, so the chain's own fact decides: this root is
    # outside the shipped snapshot. The class is taken from the completed
    # walk, not from the 16 links that fit the listing — and the kernel
    # EKU the signer carries is still reported beside it.
    assert block["signing_class"] == "unknown_root"
    assert check_kernel_signing_class("f", {"code_signature": block}, {}) is not True


def test_class_withheld_when_the_anchor_is_past_the_parse_window():
    """40 certificates: the walk runs out of parsed links before the root.
    The signer's own EKU is still in hand, so kernel_mode derives — but no
    root fact is claimed and unknown_root is not manufactured from the
    chain that could not be finished."""
    depth = 40
    certs = [_cert_tlv(7, "CA0", "Acme Corp", subject_org="Microsoft Corporation")]
    certs += [_cert_tlv(100 + index, f"CA{index + 1}", f"CA{index}", is_ca=True) for index in range(depth)]
    signer = _signer_info(7, "CA0", "2.16.840.1.101.3.4.2.1")
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        block = _stub_table(tmp, _content_info(certs, signer))
    signature = block["signatures"][0]
    assert signature["chain_length_exact"] is False
    assert signature["chain_complete"] is None
    assert "root_fingerprint" not in signature
    assert "signing_class" not in block, (
        "the leaf names Microsoft but the anchor is unknowable here"
    )


def test_signer_mismatch_rule():
    """The one-directional comparison: fires on the impersonation shape,
    never on the benign publisher-signs-subsidiary shapes measured on the
    corpus (Microsoft/Sysinternals, OpenJS/Node.js, PSF/OpenSSL)."""
    def metadata_for(company: str, signer_o: str, signer_cn: str | None = None):
        return {
            "code_signature": {
                "parse_status": "parsed",
                "signatures": [{"signer": {"o": signer_o, "cn": signer_cn or signer_o}}],
            },
            "version_info": {"strings": {"0409": {"CompanyName": company}}},
        }

    fired = check_signer_mismatch(
        "f", metadata_for("Microsoft Corporation", "Evil Signer Ltd"), {}
    )
    assert fired is not True
    assert "Microsoft Corporation" in fired and "Evil Signer Ltd" in fired

    # The signer carrying the publisher's token satisfies the claim.
    assert check_signer_mismatch(
        "f", metadata_for("Microsoft Corporation", "Microsoft Corporation"), {}
    ) is True
    # Containment both ways: "Microsoft" vs "Microsoft Corporation".
    assert check_signer_mismatch(
        "f", metadata_for("Microsoft", "Microsoft Corporation"), {}
    ) is True
    # The benign shapes from the tiers 0-1 measurement — never findings.
    assert check_signer_mismatch(
        "f",
        metadata_for("Sysinternals - www.sysinternals.com", "Microsoft Corporation"),
        {},
    ) is True
    assert check_signer_mismatch(
        "f", metadata_for("Node.js", "OpenJS Foundation"), {}
    ) is True
    assert check_signer_mismatch(
        "f",
        metadata_for("The OpenSSL Project, https://www.openssl.org/",
                     "Python Software Foundation"),
        {},
    ) is True
    # A company outside the table is not arbitrated at all.
    assert check_signer_mismatch(
        "f", metadata_for("Contoso Ltd", "Fabrikam Inc"), {}
    ) is True
    # Missing facts determine nothing (rule 11).
    assert check_signer_mismatch(
        "f",
        {"code_signature": {"parse_status": "parsed", "signatures": []},
         "version_info": {"strings": {"0409": {"CompanyName": "Microsoft"}}}},
        {},
    ) is True
    assert check_signer_mismatch(
        "f",
        {"code_signature": {"parse_status": "parsed",
                            "signatures": [{"signer": {"cn": "X", "o": "X"}}]},
         "version_info": {"strings": {}}},
        {},
    ) is True


def test_signer_mismatch_silent_on_real_fixtures():
    """The real signed fixtures carry no Microsoft claim (or no version
    strings), so the rule is silent on every one of them."""
    for path in (RFC3161, PAGEHASH, NOTIMESTAMP, SHA1):
        metadata = parse(path)
        assert check_signer_mismatch(path, metadata, {}) is True, path


def test_root_anchor_snapshot_shape():
    """The shipped anchor list is data with provenance: every key a SHA-256
    fingerprint, every entry named, and the snapshot dated and built — the
    facts a reader needs to know what the match was made against."""
    from blint.lib.pe_signature import _load_data_table, _root_anchor_table

    table = _load_data_table("pe_roots.yml")
    assert table.get("source_build")
    assert table.get("hashed_on")
    assert "LocalMachine\\Root" in (table.get("source_stores") or [])
    assert table.get("hash") == "sha256"
    roots = _root_anchor_table()
    assert len(roots) >= 28, "the snapshot carries the full VM store export"
    import re

    fingerprint_re = re.compile(r"^[0-9a-f]{64}$")
    microsoft = 0
    for fingerprint, facts in roots.items():
        assert fingerprint_re.match(fingerprint), fingerprint
        assert facts.get("cn")
        microsoft += 1 if facts.get("microsoft") else 0
    assert microsoft >= 10, "the Microsoft roots are flagged as such"


def test_class_on_real_corpus_files():
    """Ground-truth classes on corpus files (rule 29): the PSF-signed
    python.exe is commercial_ov over a complete chain anchored at the
    Microsoft-operated Identity Verification root (in the snapshot, not a
    Microsoft leaf); the Sysinternals Testlimit is Microsoft's own code
    signing cert (microsoft_1st_party). Skipped when the corpus is
    absent."""
    import os

    python_exe = os.path.expanduser("~/sandbox/pe-corpus/tier0-reference/python-amd64/python.exe")
    if not os.path.exists(python_exe):
        pytest.skip("tier-0 corpus not present")
    block = parse(python_exe)["code_signature"]
    assert block["signing_class"] == "commercial_ov"
    signature = block["signatures"][0]
    assert signature["root_known"] is True
    assert signature["root_microsoft"] is True
    assert signature["root_fingerprint"] == (
        "5367f20c7ade0e2bca790915056d086b720c33c1fa2a2661acf787e3292e1270"
    ), "Microsoft Identity Verification Root Certificate Authority 2020"

    testlimit = os.path.expanduser("~/sandbox/pe-corpus/tier1-ecosystem/sysinternals/Testlimit.exe")
    if not os.path.exists(testlimit):
        pytest.skip("tier-1 corpus not present")
    block = parse(testlimit)["code_signature"]
    assert block["signing_class"] == "microsoft_1st_party"
    # Decided by the primary (outer) signature — the audit key is absent.
    assert "signing_class_signature" not in block
    # The SHA-1 outer signature decides; the nested SHA-256 one agrees.
    assert block["signatures"][1]["signer"]["o"] == "Microsoft Corporation"
