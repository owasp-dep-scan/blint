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
    check_signature_not_timestamped,
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


def _cert_tlv(serial: int, issuer_cn: str, subject_cn: str) -> bytes:
    """A minimal but structurally real certificate: TBS with serial, alg,
    issuer, validity, subject — no key, no extensions."""
    tbs = _tlv(
        0x30,
        _tlv(0xA0, _tlv(0x02, b"\x02"))
        + _tlv(0x02, serial.to_bytes(8, "big"))
        + _tlv(0x30, _oid("2.16.840.1.101.3.4.2.1"))
        + _name(issuer_cn)
        + _tlv(0x30, _tlv(0x17, b"250101000000Z") + _tlv(0x17, b"350101000000Z"))
        + _name(subject_cn),
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
