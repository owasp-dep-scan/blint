"""Embedded provisioning profile parsing (``embedded.mobileprovision`` /
``embedded.provisionprofile``).

A provisioning profile is a CMS (PKCS#7) SignedData whose encapsulated
content is a property list: name, team, validity window, the entitlements
Apple signed (notably ``application-identifier`` and ``get-task-allow``),
and for development profiles the list of provisioned devices. The profile is
what ties a binary to a signing identity and an app ID, so it answers
questions the code signature cannot: when the signature stops being valid,
and whether the binary was provisioned for distribution or for a developer's
desk.

Decoding reuses the DER walker from the code-signature parser (same CMS
envelope). Two deliberate boundaries:

- Device UDIDs are sensitive and huge; only their count is reported, never
  the identifiers.
- Expiry is a property of *now*, not of the file, so the block records the
  profile's dates and the checks layer evaluates them at run time — parse
  output stays a pure function of the input bytes (the determinism gate).
"""

import os
import plistlib
from datetime import datetime, timezone

from blint.lib.codesign_macho import (
    _asn1_oid_decode,
    _Asn1Error,
    _ber_read,
    _parse_cms_signature,
)

# Caps mirroring the code-signature parser: a hostile payload must degrade
# into a parse failure, not a memory or CPU problem.
MAX_PROFILE_BYTES = 8 * 1024 * 1024
MAX_PLIST_BYTES = 4 * 1024 * 1024
CMS_OID_DATA = "1.2.840.113549.1.7.1"


CMS_OID_SIGNED_DATA = "1.2.840.113549.1.7.2"


def decode_provisioning_profile(data: bytes) -> dict:
    """Decode a DER CMS provisioning profile into plain JSON types.

    The envelope is ContentInfo (contentType ``signedData``) whose SignedData
    carries an encapsulated content of type ``pkcs7-data`` — the property
    list bytes. Returns a dict with ``parse_status`` of ``"parsed"`` or
    ``"parse_failed"`` (with ``parse_error``); a profile whose CMS parses but
    whose plist does not is still ``"parsed"``, with the plist failure
    recorded on the plist sub-block it belongs to. Dates are ISO-8601
    strings; the profile's validity is evaluated by the checks layer.
    """
    detail: dict = {
        "parse_status": "parse_failed",
        "parse_error": None,
        "name": None,
        "team_name": None,
        "team_identifiers": [],
        "application_identifier_prefixes": [],
        "created": None,
        "expires": None,
        "entitlements": None,
        "provisioned_device_count": None,
        "provisions_all_devices": None,
        "provisioned_device_count_available": False,
        "cms": None,
        "plist": None,
    }
    if len(data) > MAX_PROFILE_BYTES:
        detail["parse_error"] = f"profile_too_large:{len(data)}"
        return detail
    try:
        tag, content, _ = _ber_read(data, 0, len(data))
        if tag != 0x30:
            detail["parse_error"] = f"expected_ContentInfo_SEQUENCE_got_0x{tag:02x}"
            return detail
        content_type_oid = None
        plist_bytes = None
        pos = 0
        end = len(content)
        signed_data = None
        while pos < end:
            tag, value, pos = _ber_read(content, pos, end)
            if tag == 0x06 and content_type_oid is None:
                content_type_oid = _asn1_oid_decode(value)
            elif tag == 0xA0 and signed_data is None:
                # [0] EXPLICIT eContent of the ContentInfo holds the
                # SignedData SEQUENCE itself.
                inner_tag, signed, _ = _ber_read(value, 0, len(value))
                if inner_tag == 0x30:
                    signed_data = signed
        if content_type_oid != CMS_OID_SIGNED_DATA:
            detail["parse_error"] = f"unexpected_content_type:{content_type_oid}"
            return detail
        if signed_data is None:
            detail["parse_error"] = "signedData_not_found"
            return detail
        # SignedData ::= SEQUENCE { version, digestAlgorithms, encapContentInfo,
        # [0] certificates, [1] crls, signerInfos }. The plist lives in the
        # encapContentInfo: a SEQUENCE of contentType (pkcs7-data) and [0]
        # eContent (an OCTET STRING).
        sd_pos = 0
        sd_end = len(signed_data)
        while sd_pos < sd_end:
            tag, value, sd_pos = _ber_read(signed_data, sd_pos, sd_end)
            if tag != 0x30:
                continue
            encap_pos = 0
            encap_end = len(value)
            encap_oid = None
            while encap_pos < encap_end:
                tag, ev, encap_pos = _ber_read(value, encap_pos, encap_end)
                if tag == 0x06 and encap_oid is None:
                    encap_oid = _asn1_oid_decode(ev)
                elif tag == 0xA0 and plist_bytes is None:
                    inner_tag, octets, _ = _ber_read(ev, 0, len(ev))
                    if inner_tag == 0x04:
                        plist_bytes = octets
            break
        if encap_oid is not None and encap_oid != CMS_OID_DATA:
            detail["parse_error"] = f"unexpected_encap_content_type:{encap_oid}"
            return detail
    except (_Asn1Error, IndexError) as e:
        detail["parse_error"] = f"asn1:{e}"
        return detail
    detail["cms"] = _cms_summary(data)
    plist_block = {"parse_status": "parse_failed", "parse_error": None}
    if not plist_bytes:
        plist_block["parse_error"] = "no_encapsulated_content"
        detail["plist"] = plist_block
        detail["parse_status"] = "parsed"
        return detail
    if len(plist_bytes) > MAX_PLIST_BYTES:
        plist_block["parse_error"] = f"plist_too_large:{len(plist_bytes)}"
        detail["plist"] = plist_block
        detail["parse_status"] = "parsed"
        return detail
    try:
        plist = plistlib.loads(bytes(plist_bytes))
    except (plistlib.InvalidFileException, ValueError, IndexError) as e:
        plist_block["parse_error"] = f"{type(e).__name__}"
        detail["plist"] = plist_block
        detail["parse_status"] = "parsed"
        return detail
    if not isinstance(plist, dict):
        plist_block["parse_error"] = "non_dict_root"
        detail["plist"] = plist_block
        detail["parse_status"] = "parsed"
        return detail
    detail["plist"] = {"parse_status": "parsed", "parse_error": None}
    detail.update(_plist_fields(plist))
    detail["parse_status"] = "parsed"
    return detail


def _plist_fields(plist: dict) -> dict:
    """Extract the profile fields blint reports, normalizing to JSON types."""
    fields: dict = {
        "name": _clean_str(plist.get("Name")),
        "team_name": _clean_str(plist.get("TeamName")),
        "team_identifiers": [
            _clean_str(v) for v in plist.get("TeamIdentifier") or [] if _clean_str(v)
        ],
        "application_identifier_prefixes": [
            _clean_str(v) for v in plist.get("ApplicationIdentifierPrefix") or [] if _clean_str(v)
        ],
        "created": _iso(plist.get("CreationDate")),
        "expires": _iso(plist.get("ExpirationDate")),
        "provisions_all_devices": bool(plist.get("ProvisionsAllDevices")),
    }
    devices = plist.get("ProvisionedDevices")
    # Device UDIDs never leave this function; only their presence and count.
    fields["provisioned_device_count"] = len(devices) if isinstance(devices, list) else None
    fields["provisioned_device_count_available"] = isinstance(devices, list)
    entitlements = plist.get("Entitlements")
    if isinstance(entitlements, dict):
        keep = {}
        for key in (
            "application-identifier",
            "get-task-allow",
            "aps-environment",
            "beta-reports-active",
        ):
            if key in entitlements:
                keep[key] = entitlements[key]
        fields["entitlements"] = keep
    return fields


def _cms_summary(data: bytes) -> dict | None:
    """Signer-chain names from the profile's CMS, via the codesign parser.

    Reuses :func:`blint.lib.codesign_macho._parse_cms_signature` so one CMS
    reading serves both formats; a failure here degrades to None and the
    profile itself is still reported.
    """
    # _parse_cms_signature walks ContentInfo → SignedData itself, so the
    # whole DER payload goes in unchanged.
    summary = _parse_cms_signature(data)
    return {
        "signer_cn": summary.get("signer_cn"),
        "certificate_count": len(summary.get("certificates") or []),
        "trust_validation": summary.get("trust_validation"),
    }


def load_embedded_profile(app_dir: str) -> tuple[str, bytes] | None:
    """Read the embedded profile of a bundle, if it ships one.

    Checks the standard locations — ``embedded.mobileprovision`` at the
    bundle root (iOS shape) and ``Contents/embedded.provisionprofile``
    (macOS shape) — and returns ``(source_name, raw_bytes)`` or None.
    """
    for relative, name in (
        ("embedded.provisionprofile", "embedded.provisionprofile"),
        ("embedded.mobileprovision", "embedded.mobileprovision"),
        ("Contents/embedded.provisionprofile", "embedded.provisionprofile"),
        ("Contents/embedded.mobileprovision", "embedded.mobileprovision"),
    ):
        path = os.path.join(app_dir, *relative.split("/"))
        try:
            with open(path, "rb") as fp:
                return name, fp.read()
        except OSError:
            continue
    return None


def summarize_for_metadata(profile: dict) -> dict:
    """The subset of a decoded profile that belongs in binary metadata.

    Everything already is JSON types; this drops the CMS internals a
    consumer would not act on, keeping the exported block small (the
    metadata is a budget).
    """
    keep = {
        "parse_status": profile.get("parse_status"),
        "parse_error": profile.get("parse_error"),
        "name": profile.get("name"),
        "team_name": profile.get("team_name"),
        "team_identifiers": profile.get("team_identifiers"),
        "created": profile.get("created"),
        "expires": profile.get("expires"),
        "provisions_all_devices": profile.get("provisions_all_devices"),
        "provisioned_device_count": profile.get("provisioned_device_count"),
        "provisioned_device_count_available": profile.get("provisioned_device_count_available"),
        "entitlements": profile.get("entitlements"),
    }
    if cms := profile.get("cms"):
        keep["signer_cn"] = cms.get("signer_cn")
    return keep


def is_expired(profile: dict, now: datetime | None = None) -> bool:
    """True when the profile's expiry is in the past (or unparseable)."""
    expires = profile.get("expires")
    if not expires:
        return False
    try:
        expires_dt = datetime.fromisoformat(expires)
    except ValueError:
        return False
    now = now or datetime.now(timezone.utc)
    if expires_dt.tzinfo is None:
        expires_dt = expires_dt.replace(tzinfo=timezone.utc)
    return expires_dt < now


def application_identifier(profile: dict) -> str | None:
    """The signed ``<team-id>.<bundle-id>`` application identifier."""
    entitlements = profile.get("entitlements") or {}
    app_id = entitlements.get("application-identifier")
    if app_id:
        return str(app_id)
    # Older profiles carry it only as a prefix list.
    prefixes = profile.get("application_identifier_prefixes") or []
    return str(prefixes[0]) if prefixes else None


def is_wildcard(profile: dict) -> bool:
    """True when the signed application identifier ends in the ``*`` wildcard."""
    app_id = application_identifier(profile)
    return bool(app_id) and app_id.rstrip().endswith("*")


def is_development(profile: dict) -> bool:
    """True when the profile provisions a development build.

    ``get-task-allow`` is what a development profile signs: any debugger can
    attach to the shipping binary. Provisioned devices and the development
    APS environment corroborate, but the entitlement is the decision.
    """
    entitlements = profile.get("entitlements") or {}
    return entitlements.get("get-task-allow") is True


def _clean_str(value) -> str | None:
    return str(value).strip() if isinstance(value, (str, int)) and str(value).strip() else None


def _iso(value) -> str | None:
    if isinstance(value, datetime):
        if value.tzinfo is not None:
            value = value.astimezone(timezone.utc)
        return value.isoformat()
    return None
