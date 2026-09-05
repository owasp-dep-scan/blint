"""
Parser for the Mach-O embedded code signature (the SuperBlob that
``LC_CODE_SIGNATURE`` points at).

The blob format is defined in Apple's ``cs_blobs.h``. Every integer in it is
big-endian regardless of the hosting slice's byte order. A SuperBlob starts
with magic ``0xfade0cc0`` and indexes its member blobs by slot type:

- slot 0: the (primary) CodeDirectory
- slot 2: internal requirements
- slot 5: entitlements as an XML plist
- slot 7: entitlements as DER (the encoding modern Apple binaries carry)
- slots 0x1000-0x1fff: alternate CodeDirectories
- slot 0x10000: the CMS (PKCS#7) signature wrapped in a ``0xfade0b01`` blob

Scope: this parser reports what a binary *claims* about itself — who signed
it, under which flags, with which entitlements. It does **not** validate
trust: certificate chains are named, never verified, no revocation or
notarization state is consulted, and the output says so with an explicit
``trust_validation`` field so "signed" is never read as "trusted".

Everything returned is plain JSON types (str/int/bool/None/dict/list): the
values flow into metadata that the parse cache serializes, and the cache
refuses entries it cannot represent rather than guessing (rule 20). No bytes
or memoryviews ever escape this module.
"""

import hashlib
import plistlib
import struct

SUPERBLOB_MAGIC = 0xFADE0CC0
SUPERBLOB_HEADER_LEN = 12
BLOB_HEADER_LEN = 8

CSMAGIC_CODEDIRECTORY = 0xFADE0C02
CSMAGIC_REQUIREMENTS = 0xFADE0C01
CSMAGIC_ENTITLEMENTS = 0xFADE7171
CSMAGIC_DER_ENTITLEMENTS = 0xFADE7172
CSMAGIC_BLOBWRAPPER = 0xFADE0B01

CSSLOT_CODEDIRECTORY = 0
CSSLOT_REQUIREMENTS = 2
CSSLOT_ENTITLEMENTS = 5
CSSLOT_DER_ENTITLEMENTS = 7
CSSLOT_ALTERNATE_CODEDIRECTORY_MIN = 0x1000
CSSLOT_ALTERNATE_CODEDIRECTORY_MAX = 0x1FFF
CSSLOT_SIGNATURESLOT = 0x10000

# CodeDirectory flag bits (cs_blobs.h), keyed by the metadata name they are
# reported under. ``library_validation`` is a convenience computed from the
# forced (0x10) and required (0x2000) bits.
CD_FLAGS = {
    "adhoc": 0x00000002,
    "get_task_allow": 0x00000004,
    "installer": 0x00000008,
    "forced_library_validation": 0x00000010,
    "hard": 0x00000100,
    "kill": 0x00000200,
    "check_expiration": 0x00000400,
    "restrict": 0x00000800,
    "enforcement": 0x00001000,
    "require_library_validation": 0x00002000,
    "runtime": 0x00010000,
    "linker_signed": 0x00020000,
}

# exec segment flags (CodeDirectory v0x20400 and later)
EXEC_SEG_FLAGS = {
    "main_binary": 0x1,
    "allow_unsigned": 0x10,
    "debugger": 0x20,
    "jit": 0x40,
    "skip_library_validation": 0x80,
    "can_load_cd_hash": 0x100,
    "can_exec_cd_hash": 0x200,
}

CD_HASH_ALGORITHMS = {1: "sha1", 2: "sha256"}
CD_HASH_TYPE_NAMES = {0: "none", 1: "sha1", 2: "sha256"}

REQUIREMENT_TYPES = {
    1: "host",
    2: "guest",
    3: "designated",
    4: "library",
    5: "plugin",
}

CMS_OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
CMS_CONTENT_TYPES = {CMS_OID_SIGNED_DATA: "signedData"}
OID_COMMON_NAME = "2.5.4.3"
OID_ORGANIZATION = "2.5.4.10"

# Entitlements and CMS payloads are a few KiB in practice; these caps keep a
# pathologically large blob from turning into a plistlib/ASN.1 chew. The blob
# is still reported (size, slot presence) — only the deep parse is skipped.
MAX_PLIST_BYTES = 4 * 1024 * 1024
MAX_ASN1_BYTES = 8 * 1024 * 1024
MAX_CERTIFICATES = 16


class _Asn1Error(ValueError):
    """Raised when a DER/BER structure cannot be walked safely."""


def _ber_read(data: bytes, pos: int, end: int) -> tuple[int, bytes, int]:
    """Read one DER/BER TLV; returns (tag, content, next_pos).

    Handles the indefinite-length form (0x80, terminated by 00 00) that CMS
    blobs produced by codesign actually use, by recursively consuming
    children until the terminator. Raises :class:`_Asn1Error` on truncation.
    """
    if pos + 2 > end:
        raise _Asn1Error("truncated TLV header")
    tag = data[pos]
    length_byte = data[pos + 1]
    pos += 2
    if length_byte < 0x80:
        length = length_byte
        if pos + length > end:
            raise _Asn1Error("truncated definite-length content")
        return tag, data[pos : pos + length], pos + length
    if length_byte == 0x80:
        content_start = pos
        while True:
            if pos + 2 <= end and data[pos] == 0 and data[pos + 1] == 0:
                return tag, data[content_start:pos], pos + 2
            _, _, pos = _ber_read(data, pos, end)
    num_octets = length_byte & 0x7F
    if num_octets > 4 or pos + num_octets > end:
        raise _Asn1Error("unsupported or truncated long-form length")
    length = int.from_bytes(data[pos : pos + num_octets], "big")
    pos += num_octets
    if pos + length > end:
        raise _Asn1Error("truncated long-form content")
    return tag, data[pos : pos + length], pos + length


def _asn1_oid_decode(content: bytes) -> str:
    """Decode an OBJECT IDENTIFIER value into dotted-decimal form."""
    if not content:
        raise _Asn1Error("empty OID")
    first = content[0]
    parts = [str(first // 40 if first < 80 else 2), str(first % 40 if first < 80 else first - 80)]
    value = 0
    for byte in content[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    if value:
        raise _Asn1Error("truncated OID component")
    return ".".join(parts)


def _x509_name_values(name: bytes) -> dict[str, list[str]]:
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
                    oid = _asn1_oid_decode(content)
                elif value is None:
                    try:
                        value = content.decode("utf-8")
                    except UnicodeDecodeError:
                        value = None
            if oid is not None and value is not None:
                out.setdefault(oid, []).append(value)
    return out


def _tbs_content(certificate_content: bytes) -> bytes:
    """The TBSCertificate content inside one X.509 Certificate's content.

    ``Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm,
    signature }`` — the caller has consumed the Certificate TLV, so the
    fields the name and serial helpers want live one level deeper, inside
    the leading TBSCertificate SEQUENCE.
    """
    tag, content, _ = _ber_read(certificate_content, 0, len(certificate_content))
    if tag != 0x30:
        raise _Asn1Error(f"expected TBSCertificate SEQUENCE, got tag 0x{tag:02x}")
    return content


def _certificate_names(certificate_content: bytes) -> dict:
    """Subject/issuer names from one X.509 Certificate's SEQUENCE content.

    Inside TBSCertificate the field order after the optional [0] version is
    serialNumber, signature (algorithm), issuer, validity, subject — the
    second and fourth SEQUENCE are therefore the issuer and subject Names.
    """
    names = {"subject_cn": None, "subject_organization": None, "issuer_cn": None}
    try:
        tbs = _tbs_content(certificate_content)
        pos = 0
        end = len(tbs)
        sequence_count = 0
        while pos < end:
            tag, value, pos = _ber_read(tbs, pos, end)
            if tag == 0xA0:  # [0] EXPLICIT version
                continue
            if tag != 0x30:
                continue
            sequence_count += 1
            if sequence_count == 2:  # issuer
                issuer = _x509_name_values(value)
                names["issuer_cn"] = (issuer.get(OID_COMMON_NAME) or [None])[0]
            elif sequence_count == 4:  # subject
                subject = _x509_name_values(value)
                names["subject_cn"] = (subject.get(OID_COMMON_NAME) or [None])[0]
                names["subject_organization"] = (subject.get(OID_ORGANIZATION) or [None])[0]
                break
    except (_Asn1Error, IndexError):
        pass
    return names


def _parse_cms_signature(der: bytes) -> dict:
    """Name the signer chain inside a CMS blob without validating anything.

    Walks ContentInfo → SignedData → [0] certificates and records each
    certificate's subject/issuer common name and organization. The signing
    certificate is identified the way RFC 5652 says consumers must: by the
    issuerAndSerialNumber in SignerInfos, not by position — the blob stores
    intermediates in no guaranteed order. The result is provenance evidence
    only: nothing here checks signatures, validity windows, or trust anchors,
    and the returned ``trust_validation`` field says so in band.
    """
    out: dict = {
        "present": True,
        "content_type": None,
        "signer_cn": None,
        "certificates": [],
        "trust_validation": "not_performed",
        "parse_error": None,
    }
    if len(der) > MAX_ASN1_BYTES:
        out["parse_error"] = f"cms_blob_too_large:{len(der)}"
        return out
    try:
        tag, content, _ = _ber_read(der, 0, len(der))
        if tag != 0x30:
            raise _Asn1Error(f"expected ContentInfo SEQUENCE, got tag 0x{tag:02x}")
        pos = 0
        content_end = len(content)
        content_type_oid = None
        while pos < content_end:
            tag, value, pos = _ber_read(content, pos, content_end)
            if tag == 0x06:
                content_type_oid = _asn1_oid_decode(value)
                break
        if content_type_oid is None:
            raise _Asn1Error("ContentInfo without contentType")
        out["content_type"] = CMS_CONTENT_TYPES.get(content_type_oid, content_type_oid)
        if content_type_oid != CMS_OID_SIGNED_DATA:
            return out
        # [0] EXPLICIT content holds the SignedData SEQUENCE.
        signed_data = None
        while pos < content_end:
            tag, value, pos = _ber_read(content, pos, content_end)
            if tag == 0xA0:
                inner_tag, signed_data, _ = _ber_read(value, 0, len(value))
                if inner_tag != 0x30:
                    raise _Asn1Error("SignedData is not a SEQUENCE")
                break
        if signed_data is None:
            raise _Asn1Error("SignedData not found")
        # SignedData ::= SEQUENCE { version, digestAlgorithms, contentInfo,
        #                           [0] certificates, [1] crls, signerInfos }
        sd_pos = 0
        sd_end = len(signed_data)
        signer_serial = None
        while sd_pos < sd_end:
            tag, value, sd_pos = _ber_read(signed_data, sd_pos, sd_end)
            if tag == 0xA0:  # [0] certificates
                cert_pos = 0
                cert_end = len(value)
                while cert_pos < cert_end and len(out["certificates"]) < MAX_CERTIFICATES:
                    tag, certificate, cert_pos = _ber_read(value, cert_pos, cert_end)
                    if tag == 0x30:
                        entry = _certificate_names(certificate)
                        entry["serial"] = _certificate_serial(certificate)
                        out["certificates"].append(entry)
            elif tag == 0x31:  # SET: digestAlgorithms or signerInfos; only the
                # latter contains a SignerInfo SEQUENCE with a sid
                signer_serial = _signer_serial(value) or signer_serial
        if signer_serial is not None:
            for entry in out["certificates"]:
                if entry.get("serial") == signer_serial:
                    out["signer_cn"] = entry.get("subject_cn")
                    break
    except _Asn1Error as e:
        out["parse_error"] = f"asn1:{e}"
    except IndexError as e:
        out["parse_error"] = f"index:{e}"
    return out


def _certificate_serial(certificate_content: bytes) -> str | None:
    """Serial number of an X.509 certificate, hex-encoded for JSON safety.

    Like :func:`_certificate_names`, takes the Certificate SEQUENCE content
    with the outer TLV already consumed; the serial is the first untagged
    INTEGER of TBSCertificate, after the optional [0] version.
    """
    try:
        tbs = _tbs_content(certificate_content)
        pos = 0
        end = len(tbs)
        while pos < end:
            tag, value, pos = _ber_read(tbs, pos, end)
            if tag == 0xA0:  # [0] version
                continue
            if tag == 0x02:  # serialNumber: the first untagged INTEGER
                return value.hex()
            return None
    except (_Asn1Error, IndexError):
        pass
    return None


def _signer_serial(signer_infos_set: bytes) -> str | None:
    """issuerAndSerialNumber serial of the first SignerInfo, hex-encoded.

    SignerInfo ::= SEQUENCE { version INTEGER, sid, digestAlgorithm, ... };
    the version INTEGER is skipped, then the sid — a SEQUENCE
    (issuerAndSerialNumber) — yields its serial, while [0]
    subjectKeyIdentifier carries no serial and yields None.
    """
    try:
        pos = 0
        end = len(signer_infos_set)
        while pos < end:
            tag, signer_info, pos = _ber_read(signer_infos_set, pos, end)
            if tag != 0x30:
                continue
            si_pos = 0
            si_end = len(signer_info)
            sid = None
            while si_pos < si_end:
                tag, value, si_pos = _ber_read(signer_info, si_pos, si_end)
                if tag == 0x02:  # version
                    continue
                if tag == 0x30:
                    sid = value
                break
            if sid is None:
                return None
            sid_pos = 0
            sid_end = len(sid)
            while sid_pos < sid_end:
                tag, value, sid_pos = _ber_read(sid, sid_pos, sid_end)
                if tag == 0x02:
                    return value.hex()
            return None
    except (_Asn1Error, IndexError):
        return None
    return None


def _parse_der_entitlements(der: bytes) -> dict:
    """Decode Apple's DER-encoded entitlements plist into a plain dict.

    The encoding is the ASN.1 mapping of a CFPropertyList: an application-16
    wrapper holding a version INTEGER and a context-tag-16 SET; each dict
    entry is a SEQUENCE of (UTF8String key, value). Values map to JSON types:
    UTF8String → str, INTEGER → int, BOOLEAN → bool, NULL → true, SEQUENCE →
    list of values, OCTET STRING → hex string. Anything else is reported via
    an explicit ``__decode_errors__`` list rather than guessed at.
    """
    out: dict = {}
    errors: list[str] = []
    tag, content, _ = _ber_read(der, 0, len(der))
    if tag != 0x70:  # APPLICATION 16, constructed
        raise _Asn1Error(f"expected entitlements wrapper tag 0x70, got 0x{tag:02x}")
    pos = 0
    end = len(content)
    while pos < end:
        tag, value, pos = _ber_read(content, pos, end)
        if tag != 0xB0:  # the dictionary
            continue
        entry_pos = 0
        entry_end = len(value)
        while entry_pos < entry_end:
            tag, entry, entry_pos = _ber_read(value, entry_pos, entry_end)
            if tag != 0x30:
                errors.append(f"unexpected_entry_tag:0x{tag:02x}")
                continue
            key, val = _parse_der_entitlement_entry(entry, errors)
            if key is not None:
                out[key] = val
        break
    if errors:
        out["__decode_errors__"] = errors
    return out


def _parse_der_entitlement_entry(entry: bytes, errors: list[str]) -> tuple[str | None, object]:
    key = None
    value = None
    pos = 0
    end = len(entry)
    while pos < end:
        tag, content, pos = _ber_read(entry, pos, end)
        if key is None:
            if tag not in (0x0C, 0x13, 0x16):  # UTF8String, PrintableString, IA5String
                errors.append(f"unsupported_key_tag:0x{tag:02x}")
                return None, None
            key = content.decode("utf-8")
            continue
        value, decode_error = _parse_der_entitlement_value(tag, content)
        if decode_error:
            errors.append(decode_error)
            return None, None
    return key, value


def _parse_der_entitlement_value(tag: int, content: bytes) -> tuple[object, str | None]:
    """Map one DER value to a JSON type; (None, error-reason) when it cannot."""
    if tag in (0x0C, 0x13, 0x16):
        return content.decode("utf-8"), None
    if tag == 0x02:
        return int.from_bytes(content, "big", signed=True), None
    if tag == 0x01:
        return content == b"\xff", None
    if tag == 0x05:  # NULL, the legacy encoding of ``true``
        return True, None
    if tag == 0x04:
        return content.hex(), None
    if tag == 0x30:  # array
        items = []
        pos = 0
        end = len(content)
        while pos < end:
            item_tag, item_content, pos = _ber_read(content, pos, end)
            value, decode_error = _parse_der_entitlement_value(item_tag, item_content)
            if decode_error:
                return None, decode_error
            items.append(value)
        return items, None
    return None, f"unsupported_value_tag:0x{tag:02x}"


def _parse_requirements(blob: bytes) -> dict | None:
    """Slot-type inventory of the internal requirements superblob."""
    if len(blob) < BLOB_HEADER_LEN + 4:
        return None
    count = struct.unpack_from(">I", blob, BLOB_HEADER_LEN)[0]
    types = []
    pos = BLOB_HEADER_LEN + 4
    for _ in range(count):
        if pos + 8 > len(blob):
            break
        slot_type, _offset = struct.unpack_from(">II", blob, pos)
        pos += 8
        types.append(REQUIREMENT_TYPES.get(slot_type, f"0x{slot_type:x}"))
    return {"count": count, "types": types}


def _string_at(blob: bytes, offset: int) -> str | None:
    """NUL-terminated string at offset, bounded by the buffer."""
    if not 0 < offset < len(blob):
        return None
    end = blob.find(b"\x00", offset)
    if end == -1:
        end = len(blob)
    raw = blob[offset:end]
    if not raw:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _parse_code_directory(blob: bytes, slot_name: str) -> dict | None:
    """One CodeDirectory's fields, its flags, and its cdhash.

    The cdhash is the hash of the CodeDirectory's own bytes using the hash
    algorithm the directory declares. ``cdhash`` is truncated to 20 bytes —
    the form codesign displays and the identity the system keys on — and
    ``cdhash_full`` carries the whole digest, so either is comparable against
    ``codesign -dvvv`` output.
    """
    if len(blob) < 0x28 or struct.unpack_from(">I", blob, 0)[0] != CSMAGIC_CODEDIRECTORY:
        return None
    version = struct.unpack_from(">I", blob, 8)[0]
    flags_raw = struct.unpack_from(">I", blob, 12)[0]
    (
        _hash_offset,
        ident_offset,
        n_special_slots,
        n_code_slots,
        code_limit,
    ) = struct.unpack_from(">5I", blob, 16)
    hash_size = blob[0x24]
    hash_type = blob[0x25]
    platform_id = blob[0x26]
    page_size = 1 << blob[0x27] if blob[0x27] < 32 else 0
    flags = {name: bool(flags_raw & bit) for name, bit in CD_FLAGS.items()}
    if flags_raw & (CD_FLAGS["forced_library_validation"] | CD_FLAGS["require_library_validation"]):
        flags["library_validation"] = True
    out: dict = {
        "slot_type": slot_name,
        "version": f"0x{version:x}",
        "flags_raw": flags_raw,
        "flags": flags,
        "identifier": _string_at(blob, ident_offset),
        "hash_type": CD_HASH_TYPE_NAMES.get(hash_type, f"unknown({hash_type})"),
        "hash_size": hash_size,
        "page_size": page_size,
        "special_slots": n_special_slots,
        "code_slots": n_code_slots,
        "code_limit": code_limit,
    }
    if version >= 0x20200 and len(blob) >= 0x34:
        out["team_id"] = _string_at(blob, struct.unpack_from(">I", blob, 0x30)[0])
    if version >= 0x20400 and len(blob) >= 0x58:
        exec_seg_flags = struct.unpack_from(">Q", blob, 0x50)[0]
        out["exec_seg_flags"] = {
            name: bool(exec_seg_flags & bit) for name, bit in EXEC_SEG_FLAGS.items()
        }
    if platform_id:
        out["platform_id"] = platform_id
    if version >= 0x20500 and len(blob) >= 0x5C:
        runtime = struct.unpack_from(">I", blob, 0x58)[0]
        if runtime:
            out["runtime_version"] = (
                f"{(runtime >> 16) & 0xFFFF}.{(runtime >> 8) & 0xFF}.{runtime & 0xFF}"
            )
    algorithm = CD_HASH_ALGORITHMS.get(hash_type)
    if algorithm and hash_size:
        digest = hashlib.new(algorithm, blob).hexdigest()
        out["cdhash_algorithm"] = algorithm
        out["cdhash"] = digest[:40]
        out["cdhash_full"] = digest
    return out


def _slot_type_name(slot_type: int) -> str:
    if slot_type == CSSLOT_CODEDIRECTORY:
        return "code_directory"
    if slot_type == CSSLOT_REQUIREMENTS:
        return "requirements"
    if slot_type == CSSLOT_ENTITLEMENTS:
        return "entitlements"
    if slot_type == CSSLOT_DER_ENTITLEMENTS:
        return "entitlements_der"
    if CSSLOT_ALTERNATE_CODEDIRECTORY_MIN <= slot_type <= CSSLOT_ALTERNATE_CODEDIRECTORY_MAX:
        return f"alternate_code_directory_{slot_type:#x}"
    if slot_type == CSSLOT_SIGNATURESLOT:
        return "cms_signature"
    return f"0x{slot_type:x}"


def parse_superblob(blob: bytes) -> dict:
    """Parse an embedded code-signature SuperBlob into plain JSON types.

    Returns a dict with ``parse_status`` of ``"parsed"`` or
    ``"parse_failed"``; malformed input yields ``"parse_failed"`` with a
    ``parse_error`` reason instead of an exception, so a corrupt signature
    degrades into an explicit, machine-readable answer. On success the dict
    carries the blob index, every CodeDirectory (primary and alternates) with
    flags and cdhashes, entitlements from the XML and DER slots, the internal
    requirements inventory, and the CMS signer-chain names. A payload that is
    structurally fine but fails a deep decode (entitlements plist, CMS) is
    still ``"parsed"`` — the failure is recorded on the sub-block it belongs
    to, never silently.
    """
    detail: dict = {
        "parse_status": "parse_failed",
        "parse_error": None,
        "length": None,
        "blobs": [],
        "code_directories": [],
        "requirements": None,
        "entitlements": None,
        "entitlements_der": None,
        "cms": None,
        "provenance": "unknown",
    }
    if len(blob) < SUPERBLOB_HEADER_LEN:
        detail["parse_error"] = f"blob_too_small:{len(blob)}"
        return detail
    magic, length, count = struct.unpack_from(">III", blob, 0)
    if magic != SUPERBLOB_MAGIC:
        detail["parse_error"] = f"bad_magic:0x{magic:08x}"
        return detail
    if length > len(blob):
        detail["parse_error"] = f"declared_length:{length}_beyond_input:{len(blob)}"
        return detail
    if count > (len(blob) - SUPERBLOB_HEADER_LEN) // BLOB_HEADER_LEN:
        detail["parse_error"] = f"index_truncated:{count}_entries"
        return detail
    detail["length"] = length
    cms_der = None
    primary_flags_raw = None
    for index in range(count):
        slot_type, offset = struct.unpack_from(">II", blob, SUPERBLOB_HEADER_LEN + 8 * index)
        if offset + BLOB_HEADER_LEN > len(blob):
            detail["parse_error"] = f"blob_{index}_offset:{offset}_beyond_input"
            return detail
        blob_magic, blob_length = struct.unpack_from(">II", blob, offset)
        if blob_length > len(blob) - offset:
            detail["parse_error"] = f"blob_{index}_length:{blob_length}_beyond_input"
            return detail
        slot_name = _slot_type_name(slot_type)
        detail["blobs"].append(
            {
                "slot_type": slot_name,
                "offset": offset,
                "size": blob_length,
                "magic": f"0x{blob_magic:08x}",
            }
        )
        content = blob[offset : offset + blob_length]
        if blob_magic == CSMAGIC_CODEDIRECTORY:
            directory = _parse_code_directory(content, slot_name)
            if directory is None:
                detail["parse_error"] = f"blob_{index}_undecodable_code_directory"
                return detail
            if slot_type == CSSLOT_CODEDIRECTORY:
                primary_flags_raw = directory["flags_raw"]
            detail["code_directories"].append(directory)
        elif blob_magic == CSMAGIC_ENTITLEMENTS and detail["entitlements"] is None:
            detail["entitlements"] = _parse_entitlements_payload(
                content[BLOB_HEADER_LEN:], "xml"
            )
        elif blob_magic == CSMAGIC_DER_ENTITLEMENTS and detail["entitlements_der"] is None:
            detail["entitlements_der"] = _parse_entitlements_payload(
                content[BLOB_HEADER_LEN:], "der"
            )
        elif blob_magic == CSMAGIC_REQUIREMENTS:
            detail["requirements"] = _parse_requirements(content)
        elif blob_magic == CSMAGIC_BLOBWRAPPER and slot_type == CSSLOT_SIGNATURESLOT:
            cms_der = content[BLOB_HEADER_LEN:]
    if cms_der is not None:
        detail["cms"] = _parse_cms_signature(cms_der)
    detail["provenance"] = _provenance(primary_flags_raw, detail["cms"])
    detail["parse_status"] = "parsed"
    return detail


def _parse_entitlements_payload(payload: bytes, kind: str) -> dict:
    """Decode one entitlements payload; a decode failure is recorded in band.

    Returns either the parsed dict or ``{"decode_error": "<reason>"}`` so a
    consumer looking at the entitlements slot can tell "no entitlements"
    from "entitlements blint could not decode" (rule 14).
    """
    if len(payload) > MAX_PLIST_BYTES:
        return {"decode_error": f"{kind}_too_large:{len(payload)}"}
    try:
        if kind == "xml":
            parsed = plistlib.loads(bytes(payload))
        else:
            return _parse_der_entitlements(bytes(payload))
    except (plistlib.InvalidFileException, _Asn1Error, ValueError, IndexError) as e:
        return {"decode_error": f"{kind}_{type(e).__name__}"}
    result = _plist_to_plain(parsed)
    return result if isinstance(result, dict) else {"__root__": result}


def _plist_to_plain(value: object) -> object:
    """Normalize a plistlib result into pure JSON types."""
    if isinstance(value, dict):
        return {str(k): _plist_to_plain(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_plist_to_plain(v) for v in value]
    if isinstance(value, bool) or value is None or isinstance(value, (int, str)):
        return value
    if isinstance(value, bytes):
        return value.hex()
    return str(value)


def _provenance(primary_flags_raw: int | None, cms: dict | None) -> str:
    """Who produced the signature — a claim read off the blob, not a trust judgment."""
    if primary_flags_raw is not None and primary_flags_raw & CD_FLAGS["linker_signed"]:
        return "linker_signed"
    if primary_flags_raw is not None and primary_flags_raw & CD_FLAGS["adhoc"]:
        return "adhoc"
    if cms and cms.get("content_type") == "signedData":
        return "cms_signed"
    return "unknown"


def signature_summary(detail: dict) -> dict | None:
    """Lean per-slice view of a parsed signature for ``slices[]`` entries.

    Carries everything that can differ between slices and that rule 21 says
    must never be silently merged across them — identifier, team, cdhash,
    flags, entitlements, provenance — and drops blob-layout internals (the
    blob index, offsets, the CMS certificate chain) so universal-binary
    entries stay lean.
    """
    if detail.get("parse_status") != "parsed":
        return {
            "available": True,
            "parse_status": detail.get("parse_status", "parse_failed"),
            "parse_error": detail.get("parse_error"),
        }
    directories = detail.get("code_directories") or []
    primary = next(
        (d for d in directories if d.get("slot_type") == "code_directory"),
        directories[0] if directories else None,
    )
    return {
        "available": True,
        "parse_status": "parsed",
        "provenance": detail.get("provenance"),
        "identifier": primary.get("identifier") if primary else None,
        "team_id": primary.get("team_id") if primary else None,
        "cdhash": primary.get("cdhash") if primary else None,
        "hash_type": primary.get("hash_type") if primary else None,
        "flags": primary.get("flags") if primary else None,
        "entitlements": detail.get("entitlements"),
        "entitlements_der": detail.get("entitlements_der"),
    }
