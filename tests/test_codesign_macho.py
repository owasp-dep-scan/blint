"""Tests for the Mach-O code-signature SuperBlob parser (P2.4).

Every fixture is built inline from the format's own constants — no binary
blobs are committed. The builders double as the format documentation: a
SuperBlob (big-endian) indexes blobs by slot type; each blob is
``magic:u32 length:u32 payload``; a CodeDirectory carries its fields at fixed
offsets with version-gated extensions; entitlements ride in an XML-plist slot
and/or a DER slot; the CMS signature is a ``0xfade0b01`` wrapper around
PKCS#7 DER (codesign emits BER indefinite lengths in places, so both are
exercised — rule 10: a fixture per format variant).

The cdhash assertion is computed independently here (hashlib over the raw
CodeDirectory bytes), not by calling into the module under test.
"""

import hashlib
import plistlib
import struct

import orjson
import pytest

from blint.lib.codesign_macho import (
    CSMAGIC_BLOBWRAPPER,
    CSMAGIC_CODEDIRECTORY,
    CSMAGIC_DER_ENTITLEMENTS,
    CSMAGIC_ENTITLEMENTS,
    CSMAGIC_REQUIREMENTS,
    SUPERBLOB_MAGIC,
    parse_superblob,
    signature_summary,
)


# ---------------------------------------------------------------------------
# DER/BER builders (test-side, independent of the module under test)
# ---------------------------------------------------------------------------
def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _der(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content


def _der_utf8(text: str) -> bytes:
    return _der(0x0C, text.encode())


def _der_int(value: int) -> bytes:
    length = max(1, (value.bit_length() + 8) // 8)
    return _der(0x02, value.to_bytes(length, "big", signed=True))


def _der_oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    body = bytearray([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        chunk = [part & 0x7F]
        part >>= 7
        while part:
            chunk.append((part & 0x7F) | 0x80)
            part >>= 7
        body.extend(reversed(chunk))
    return _der(0x06, bytes(body))


def _der_name(cn: str) -> bytes:
    """An X.509 Name with a single commonName RDN."""
    atv = _der(0x30, _der_oid("2.5.4.3") + _der_utf8(cn))
    return _der(0x30, _der(0x31, atv))


def _der_certificate(subject_cn: str, serial: int) -> bytes:
    """A minimal (structurally valid, cryptographically fake) X.509 cert."""
    alg = _der(0x30, _der_oid("1.2.840.113549.1.1.11") + _der(0x05, b""))
    tbs = (
        _der(0xA0, _der(0x02, b"\x02"))
        + _der_int(serial)
        + alg
        + _der_name(f"Issuer-of-{subject_cn}")
        + _der(0x30, _der(0x17, b"240101000000Z") + _der(0x17, b"340101000000Z"))
        + _der_name(subject_cn)
        + _der(0x30, alg + _der(0x03, b"\x00\x03\x02\xff"))
    )
    return _der(0x30, _der(0x30, tbs) + alg + _der(0x03, b"\x00"))


def _der_cms(certificates: list[bytes], signer_serial: int, indefinite: bool = False) -> bytes:
    """PKCS#7 SignedData naming one signer by issuerAndSerialNumber.

    With ``indefinite`` the constructed elements use BER indefinite lengths
    (00 00 terminated), the shape codesign actually emits for the outer
    ContentInfo and SignedData.
    """
    signer_info = _der(
        0x30,
        _der_int(1)
        + _der(0x30, _der_name("ignored") + _der_int(signer_serial))
        + _der(0x30, _der_oid("2.16.840.1.101.3.4.2.1") + _der(0x05, b"")),
    )
    signed_data = _der(
        0x30,
        _der_int(1)
        + _der(0x31, _der(0x30, _der_oid("2.16.840.1.101.3.4.2.1") + _der(0x05, b"")))
        + _der(0x30, _der_oid("1.2.840.113549.1.7.1"))
        + _der(0xA0, b"".join(certificates))
        + _der(0x31, signer_info),
    )
    if indefinite:
        content_info = (
            b"\x30\x80"
            + _der_oid("1.2.840.113549.1.7.2")
            + b"\xa0\x80" + signed_data + b"\x00\x00"
            + b"\x00\x00"
        )
    else:
        content_info = _der(
            0x30,
            _der_oid("1.2.840.113549.1.7.2") + _der(0xA0, signed_data),
        )
    return content_info


# ---------------------------------------------------------------------------
# SuperBlob builders
# ---------------------------------------------------------------------------
def _blob(magic: int, payload: bytes) -> bytes:
    return struct.pack(">II", magic, 8 + len(payload)) + payload


def _code_directory(
    identifier: str = "com.example.app",
    team_id: str | None = None,
    flags: int = 0,
    version: int = 0x20400,
    hash_type: int = 2,
    platform: int = 0,
    code_slots: int = 1,
    exec_seg_flags: int = 0,
    runtime_version: int = 0,
) -> bytes:
    """A complete CodeDirectory blob (magic and length included).

    Field order mirrors real embedded directories: fixed header, identifier
    string at ``identOffset``, page hashes at ``hashOffset``, team identifier
    at ``teamOffset`` (v0x20200+), exec-segment fields (v0x20400+), runtime
    version (v0x20500+).
    """
    header_len = 0x5C if (version >= 0x20500 and runtime_version) else 0x58
    ident = identifier.encode() + b"\x00"
    ident_offset = header_len
    hash_offset = ident_offset + len(ident)
    hashes = b"\xaa" * (32 * code_slots)
    body = bytearray(header_len)
    struct.pack_into(">II", body, 0, CSMAGIC_CODEDIRECTORY, 0)
    struct.pack_into(">II", body, 8, version, flags)
    struct.pack_into(">IIIII", body, 0x10, hash_offset, ident_offset, 2, code_slots, 0x2000)
    body[0x24] = 32  # hash size
    body[0x25] = hash_type
    body[0x26] = platform
    body[0x27] = 12  # log2(page size) -> 4096
    body_out = bytearray(body + ident + hashes)
    if version >= 0x20200:
        team_offset = 0
        if team_id is not None:
            team_offset = len(body_out)
            body_out += team_id.encode() + b"\x00"
        struct.pack_into(">I", body_out, 0x30, team_offset)
    if version >= 0x20400:
        # execSegBase/execSegLimit/execSegFlags live inside the fixed header
        # at 0x40..0x57, before the identifier string.
        struct.pack_into(">QQQ", body_out, 0x40, 0, 0x1000, exec_seg_flags)
    if version >= 0x20500 and runtime_version:
        struct.pack_into(">I", body_out, 0x58, runtime_version)
    struct.pack_into(">I", body_out, 4, len(body_out))
    return bytes(body_out)


def _requirements_blob(types: list[int]) -> bytes:
    body = struct.pack(">I", len(types))
    offset = 8 + 4 + 8 * len(types)
    for slot_type in types:
        req = _blob(0xFADE0C00 + slot_type, b"\x00" * 8)
        body += struct.pack(">II", slot_type, offset)
        offset += len(req)
    for slot_type in types:
        body += _blob(0xFADE0C00 + slot_type, b"\x00" * 8)
    return _blob(CSMAGIC_REQUIREMENTS, body)


def _entitlements_blob(value: bytes, der: bool = False) -> bytes:
    return _blob(CSMAGIC_DER_ENTITLEMENTS if der else CSMAGIC_ENTITLEMENTS, value)


def _der_entitlements(entries: dict) -> bytes:
    """DER-encoded plist dict: APPLICATION-16 { INTEGER 1, [0xB0] { SEQ(k, v)* } }."""
    rendered = []
    for key, val in entries.items():
        if isinstance(val, bool):
            value = _der(0x01, b"\xff" if val else b"\x00")
        elif isinstance(val, int):
            value = _der_int(val)
        elif isinstance(val, list):
            inner = b""
            for item in val:
                inner += (
                    _der_utf8(item) if isinstance(item, str) else _der_int(item)
                )
            value = _der(0x30, inner)
        else:
            value = _der_utf8(val)
        rendered.append(_der(0x30, _der_utf8(key) + value))
    return _der(0x70, _der_int(1) + _der(0xB0, b"".join(rendered)))


def _superblob(entries: list[tuple[int, bytes]], declared_length: int | None = None) -> bytes:
    offset = 12 + 8 * len(entries)
    index = b""
    payloads = b""
    for slot_type, blob in entries:
        index += struct.pack(">II", slot_type, offset)
        payloads += blob
        offset += len(blob)
    length = offset if declared_length is None else declared_length
    header = struct.pack(">III", SUPERBLOB_MAGIC, length, len(entries))
    return header + index + payloads


# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------
def test_primary_code_directory_fields_and_cdhash():
    cd = _code_directory(
        identifier="com.example.tool",
        team_id="TEAM1234AB",
        flags=0x10000,  # CS_RUNTIME
        platform=16,
        code_slots=3,
    )
    detail = parse_superblob(_superblob([(0, cd)]))

    assert detail["parse_status"] == "parsed"
    assert detail["provenance"] == "unknown"
    directory = detail["code_directories"][0]
    assert directory["identifier"] == "com.example.tool"
    assert directory["team_id"] == "TEAM1234AB"
    assert directory["version"] == "0x20400"
    assert directory["hash_type"] == "sha256"
    assert directory["hash_size"] == 32
    assert directory["page_size"] == 4096
    assert directory["code_slots"] == 3
    assert directory["special_slots"] == 2
    assert directory["platform_id"] == 16
    assert directory["flags"]["runtime"] is True
    assert directory["flags"]["adhoc"] is False
    # The cdhash is sha256 over the CodeDirectory's own bytes; the 20-byte
    # truncation is what codesign displays as CDHash.
    expected = hashlib.sha256(cd).hexdigest()
    assert directory["cdhash"] == expected[:40]
    assert directory["cdhash_full"] == expected
    assert directory["cdhash_algorithm"] == "sha256"


def test_cdhash_sha1_variant():
    cd = _code_directory(hash_type=1)
    detail = parse_superblob(_superblob([(0, cd)]))
    directory = detail["code_directories"][0]
    assert directory["hash_type"] == "sha1"
    assert directory["cdhash"] == hashlib.sha1(cd).hexdigest()[:40]


def test_code_directory_v20100_has_no_team_or_execseg_fields():
    cd = _code_directory(version=0x20100, team_id="SHOULD_NOT_APPEAR")
    detail = parse_superblob(_superblob([(0, cd)]))
    directory = detail["code_directories"][0]
    assert "team_id" not in directory
    assert "exec_seg_flags" not in directory


def test_exec_seg_flags_reported_when_v20400():
    cd = _code_directory(exec_seg_flags=0x1)  # CS_EXECSEG_MAIN_BINARY
    detail = parse_superblob(_superblob([(0, cd)]))
    assert detail["code_directories"][0]["exec_seg_flags"]["main_binary"] is True
    assert detail["code_directories"][0]["exec_seg_flags"]["jit"] is False


def test_runtime_version_reported_when_v20500():
    # runtime 0x20600 → "2.6.0", the hardened-runtime ABI version field that
    # CodeDirectory v0x20500 added after the exec-segment fields.
    cd = _code_directory(version=0x20500, runtime_version=0x20600)
    detail = parse_superblob(_superblob([(0, cd)]))
    directory = detail["code_directories"][0]
    assert directory["version"] == "0x20500"
    assert directory["runtime_version"] == "2.6.0"
    assert directory["identifier"] == "com.example.app"


def test_unknown_hash_type_named_without_cdhash():
    # An unrecognized hash type must be named as unknown rather than guessed,
    # and no cdhash can be claimed for an algorithm blint cannot compute.
    cd = _code_directory(hash_type=4)
    detail = parse_superblob(_superblob([(0, cd)]))
    directory = detail["code_directories"][0]
    assert directory["hash_type"] == "unknown(4)"
    assert "cdhash" not in directory
    assert "cdhash_full" not in directory


def test_provenance_adhoc_and_linker_signed():
    adhoc = parse_superblob(
        _superblob([(0, _code_directory(flags=0x2))])
    )
    assert adhoc["provenance"] == "adhoc"
    linker = parse_superblob(
        _superblob(
            [(0, _code_directory(flags=0x20000 | 0x2))]
        )
    )
    assert linker["provenance"] == "linker_signed"


def test_entitlements_xml_and_der_slots():
    entitlements = {
        "get-task-allow": True,
        "com.apple.security.cs.allow-jit": True,
        "com.apple.developer.team-identifier": "TEAM1234AB",
        "com.apple.security.application-groups": ["group.one", "group.two"],
        "com.apple.private.count": 3,
    }
    xml_blob = _entitlements_blob(plistlib.dumps(entitlements))
    der_blob = _entitlements_blob(_der_entitlements(entitlements), der=True)
    detail = parse_superblob(
        _superblob(
            [
                (0, _code_directory()),
                (5, xml_blob),
                (7, der_blob),
            ]
        )
    )
    assert detail["parse_status"] == "parsed"
    assert detail["entitlements"] == entitlements
    assert detail["entitlements_der"] == entitlements


def test_entitlements_der_false_and_nested_array():
    entitlements = {
        "com.apple.security.cs.disable-library-validation": False,
        "keychain-access-groups": ["a.b", "c.d"],
    }
    detail = parse_superblob(
        _superblob(
            [
                (0, _code_directory()),
                (7, _entitlements_blob(_der_entitlements(entitlements), der=True)),
            ]
        )
    )
    assert detail["entitlements_der"]["com.apple.security.cs.disable-library-validation"] is False
    assert detail["entitlements_der"]["keychain-access-groups"] == ["a.b", "c.d"]


def test_entitlements_xml_only_and_der_only():
    xml_only = plistlib.dumps({"get-task-allow": True})
    detail = parse_superblob(
        _superblob(
            [
                (0, _code_directory()),
                (5, _entitlements_blob(xml_only)),
            ]
        )
    )
    assert detail["entitlements"] == {"get-task-allow": True}
    assert detail["entitlements_der"] is None
    der_only = parse_superblob(
        _superblob(
            [
                (0, _code_directory()),
                (7, _entitlements_blob(_der_entitlements({"a.b": True}), der=True)),
            ]
        )
    )
    assert der_only["entitlements"] is None
    assert der_only["entitlements_der"] == {"a.b": True}


def test_entitlements_undecodable_recorded_not_fatal():
    # Rule 14: an undecodable entitlements payload must never read as "no
    # entitlements"; the failure is recorded on the slot it belongs to.
    detail = parse_superblob(
        _superblob(
            [
                (0, _code_directory()),
                (5, _entitlements_blob(b"this is not a plist")),
            ]
        )
    )
    assert detail["parse_status"] == "parsed"
    assert "decode_error" in detail["entitlements"]


def test_alternate_code_directories_indexed():
    primary = _code_directory(identifier="com.example.primary")
    alternate = _code_directory(identifier="com.example.alt", hash_type=1)
    detail = parse_superblob(
        _superblob(
            [
                (0, primary),
                (0x1000, alternate),
            ]
        )
    )
    assert [d["slot_type"] for d in detail["code_directories"]] == [
        "code_directory",
        "alternate_code_directory_0x1000",
    ]
    assert detail["code_directories"][1]["identifier"] == "com.example.alt"


def test_requirements_inventory():
    detail = parse_superblob(
        _superblob(
            [
                (0, _code_directory()),
                (2, _requirements_blob([3])),
            ]
        )
    )
    assert detail["requirements"] == {"count": 1, "types": ["designated"]}


def test_cms_signer_named_by_serial_not_position():
    # The leaf is not first in the certificate set; the signer is the cert
    # whose serial matches SignerInfo's issuerAndSerialNumber.
    leaf = _der_certificate("Developer ID Application: Example Corp", serial=0x42)
    intermediate = _der_certificate("Example Certification Authority", serial=0x7)
    cms_der = _der_cms([intermediate, leaf], signer_serial=0x42)
    detail = parse_superblob(
        _superblob(
            [
                (0, _code_directory()),
                (0x10000, _blob(CSMAGIC_BLOBWRAPPER, cms_der)),
            ]
        )
    )
    cms = detail["cms"]
    assert cms["content_type"] == "signedData"
    assert cms["signer_cn"] == "Developer ID Application: Example Corp"
    assert [c["subject_cn"] for c in cms["certificates"]] == [
        "Example Certification Authority",
        "Developer ID Application: Example Corp",
    ]
    assert cms["trust_validation"] == "not_performed"
    # A CMS blob turns a non-adhoc signature into cms_signed provenance.
    assert detail["provenance"] == "cms_signed"


def test_cms_ber_indefinite_lengths():
    leaf = _der_certificate("Apple Software Signing", serial=0x9)
    cms_der = _der_cms([leaf], signer_serial=0x9, indefinite=True)
    detail = parse_superblob(
        _superblob(
            [
                (0, _code_directory()),
                (0x10000, _blob(CSMAGIC_BLOBWRAPPER, cms_der)),
            ]
        )
    )
    assert detail["cms"]["signer_cn"] == "Apple Software Signing"
    assert detail["cms"]["parse_error"] is None


def test_blob_index_offsets_and_sizes():
    cd_blob = _code_directory()
    der_blob = _entitlements_blob(_der_entitlements({"a": True}), der=True)
    detail = parse_superblob(_superblob([(0, cd_blob), (7, der_blob)]))
    assert detail["blobs"][0]["slot_type"] == "code_directory"
    assert detail["blobs"][0]["offset"] == 28  # header + two index entries
    assert detail["blobs"][0]["size"] == len(cd_blob)
    assert detail["blobs"][1]["offset"] == 28 + len(cd_blob)
    assert detail["length"] == 28 + len(cd_blob) + len(der_blob)


# Malformed inputs: recorded failures, never exceptions (gate 5).
def test_truncated_superblob_declared_length_beyond_input():
    blob = _superblob([(0, _code_directory())])
    detail = parse_superblob(blob[: len(blob) - 10])
    assert detail["parse_status"] == "parse_failed"
    assert detail["parse_error"]


def test_garbage_bytes_bad_magic():
    detail = parse_superblob(b"\xde\xad\xbe\xef" + b"\x00" * 40)
    assert detail["parse_status"] == "parse_failed"
    assert "bad_magic" in detail["parse_error"]


def test_truncated_index():
    # Header declares two entries but the input holds only one index slot:
    # the count pre-check must refuse the whole blob.
    header = struct.pack(">III", SUPERBLOB_MAGIC, 20, 2)
    detail = parse_superblob(header + struct.pack(">II", 0, 20))
    assert detail["parse_status"] == "parse_failed"
    assert "index_truncated" in detail["parse_error"]


def test_blob_offset_beyond_input():
    header = struct.pack(">III", SUPERBLOB_MAGIC, 64, 1)
    index = struct.pack(">II", 0, 0x10000)
    detail = parse_superblob(header + index)
    assert detail["parse_status"] == "parse_failed"
    assert "beyond_input" in detail["parse_error"]


def test_signature_summary_projects_lean_view():
    cd = _code_directory(identifier="com.example.app", team_id="TEAM", flags=0x2)
    detail = parse_superblob(
        _superblob(
            [
                (0, cd),
                (7, _entitlements_blob(_der_entitlements({"get-task-allow": True}), der=True)),
            ]
        )
    )
    summary = signature_summary(detail)
    assert summary["available"] is True
    assert summary["parse_status"] == "parsed"
    assert summary["provenance"] == "adhoc"
    assert summary["identifier"] == "com.example.app"
    assert summary["team_id"] == "TEAM"
    assert summary["cdhash"] == hashlib.sha256(cd).hexdigest()[:40]
    assert summary["entitlements_der"] == {"get-task-allow": True}
    assert orjson.dumps(summary)  # rule 20: plain JSON types only


def test_signature_summary_failed_parse():
    summary = signature_summary({"parse_status": "parse_failed", "parse_error": "bad_magic:0x0"})
    assert summary == {
        "available": True,
        "parse_status": "parse_failed",
        "parse_error": "bad_magic:0x0",
    }


def test_superblob_output_is_plain_json():
    # Rule 20: the parse cache refuses entries it cannot serialize, so a
    # bytes/memoryview leaking into the detail would silently make every
    # signed binary uncached. Assert at the source.
    entitlements = {"a.b": [True, 1, "x"]}
    detail = parse_superblob(
        _superblob(
            [
                (0, _code_directory()),
                (5, _entitlements_blob(plistlib.dumps(entitlements))),
                (7, _entitlements_blob(_der_entitlements(entitlements), der=True)),
                (2, _requirements_blob([3])),
                (0x10000, _blob(CSMAGIC_BLOBWRAPPER, _der_cms([_der_certificate("C", 1)], 1))),
            ]
        )
    )
    blob = orjson.dumps(detail)
    assert b'"cdhash"' in blob


@pytest.mark.parametrize(
    "flags, expected",
    [
        (0x2, "adhoc"),
        (0x20000, "linker_signed"),
        (0x0, "unknown"),
    ],
)
def test_provenance_matrix_without_cms(flags, expected):
    detail = parse_superblob(
        _superblob([(0, _code_directory(flags=flags))])
    )
    assert detail["provenance"] == expected
