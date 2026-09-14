"""Tests for provisioning profile parsing (P2.5).

Ground truth for the CMS decode comes from outside blint: the fixtures are
signed by ``openssl smime`` (an independent producer) and, where openssl is
available, the encapsulated plist is extracted again by
``openssl smime -verify`` and compared field for field with blint's decode.
Apple's own ``security cms -D`` is consulted when it can decode the
artifact; it refuses openssl-produced CMS on current macOS builds even with
an Apple-CA-shaped chain, so the openssl pair is the standing reference.

The plist payload fixtures cover the profile variants Apple issues:
development (get-task-allow, provisioned devices), distribution
(ad-hoc devices, no get-task-allow), enterprise (ProvisionsAllDevices) and
wildcard (``*`` application identifier).
"""

import plistlib
import shutil
import subprocess
from datetime import datetime, timezone

import pytest

from blint.lib.provisioning import (
    application_identifier,
    decode_provisioning_profile,
    is_development,
    is_expired,
    is_wildcard,
    load_embedded_profile,
)

OPENSSL = shutil.which("openssl")

_PLIST_DEVELOPMENT = {
    "Name": "iOS Team Provisioning Profile",
    "TeamName": "Example Incorporated",
    "TeamIdentifier": ["ABCDEF1234"],
    "ApplicationIdentifierPrefix": ["ABCDEF1234"],
    "CreationDate": datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
    "ExpirationDate": datetime(2027, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
    "Entitlements": {
        "application-identifier": "ABCDEF1234.com.example.myapp",
        "get-task-allow": True,
        "aps-environment": "development",
    },
    "ProvisionedDevices": ["udid-one", "udid-two", "udid-three"],
}

_PLIST_DISTRIBUTION = {
    "Name": "MyApp Distribution",
    "TeamName": "Example Incorporated",
    "TeamIdentifier": ["ABCDEF1234"],
    "Entitlements": {
        "application-identifier": "ABCDEF1234.com.example.myapp",
        "get-task-allow": False,
    },
    "ExpirationDate": datetime(2020, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
}

_PLIST_ENTERPRISE_WILDCARD = {
    "Name": "Enterprise Wildcard",
    "TeamName": "Example Incorporated",
    "TeamIdentifier": ["TEAMXYZ789"],
    "Entitlements": {
        "application-identifier": "TEAMXYZ789.*",
        "get-task-allow": False,
    },
    "ProvisionsAllDevices": True,
    "ExpirationDate": datetime(2035, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
}


def _openssl_sign(plist: dict, tmp_path) -> bytes:
    """Produce a real DER CMS embedding the plist, signed by openssl."""
    subject = "/CN=iPhone Distribution: Example Incorporated/O=Example Inc"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(tmp_path / "key.pem"),
            "-out",
            str(tmp_path / "cert.pem"),
            "-days",
            "365",
            "-nodes",
            "-subj",
            subject,
        ],
        check=True,
        capture_output=True,
    )
    plist_path = tmp_path / "profile.plist"
    plist_path.write_bytes(plistlib.dumps(plist))
    subprocess.run(
        [
            "openssl",
            "smime",
            "-sign",
            "-binary",
            "-nodetach",
            "-nosmimecap",
            "-in",
            str(plist_path),
            "-signer",
            str(tmp_path / "cert.pem"),
            "-inkey",
            str(tmp_path / "key.pem"),
            "-outform",
            "DER",
            "-out",
            str(tmp_path / "profile.mobileprovision"),
        ],
        check=True,
        capture_output=True,
    )
    return (tmp_path / "profile.mobileprovision").read_bytes()


def _openssl_payload(profile: bytes, tmp_path) -> dict:
    """Independent decode: extract the encapsulated plist with openssl."""
    raw_path = tmp_path / "input.mobileprovision"
    raw_path.write_bytes(profile)
    out = subprocess.run(
        [
            "openssl",
            "smime",
            "-verify",
            "-noverify",
            "-inform",
            "DER",
            "-in",
            str(raw_path),
            "-out",
            str(tmp_path / "decoded.plist"),
        ],
        check=True,
        capture_output=True,
    )
    assert out.returncode == 0
    return plistlib.loads((tmp_path / "decoded.plist").read_bytes())


def test_decode_development_profile_matches_openssl_payload(tmp_path):
    if not OPENSSL:
        pytest.skip("needs openssl to produce and decode the CMS fixture")
    profile = decode_provisioning_profile(_openssl_sign(_PLIST_DEVELOPMENT, tmp_path))
    assert profile["parse_status"] == "parsed"
    truth = _openssl_payload(_openssl_sign(_PLIST_DEVELOPMENT, tmp_path), tmp_path)
    assert profile["name"] == truth["Name"]
    assert profile["team_name"] == truth["TeamName"]
    assert profile["team_identifiers"] == truth["TeamIdentifier"]
    assert (
        profile["entitlements"]["application-identifier"]
        == truth["Entitlements"]["application-identifier"]
    )
    assert profile["entitlements"]["get-task-allow"] is True
    assert profile["entitlements"]["aps-environment"] == "development"
    # Device UDIDs are sensitive: the count is reported, never the values.
    assert profile["provisioned_device_count"] == 3
    assert profile["provisioned_device_count_available"] is True
    assert "udid-one" not in str(profile)
    assert profile["cms"]["certificate_count"] >= 1
    assert profile["cms"]["signer_cn"]


def test_development_profile_flags(tmp_path):
    if not OPENSSL:
        pytest.skip("needs openssl")
    profile = decode_provisioning_profile(_openssl_sign(_PLIST_DEVELOPMENT, tmp_path))
    assert is_development(profile) is True
    assert is_wildcard(profile) is False
    assert not is_expired(profile)
    assert application_identifier(profile) == "ABCDEF1234.com.example.myapp"


def test_expired_distribution_profile(tmp_path):
    if not OPENSSL:
        pytest.skip("needs openssl")
    profile = decode_provisioning_profile(_openssl_sign(_PLIST_DISTRIBUTION, tmp_path))
    assert is_expired(profile) is True
    assert is_development(profile) is False
    assert profile["provisions_all_devices"] is False


def test_enterprise_wildcard_profile(tmp_path):
    if not OPENSSL:
        pytest.skip("needs openssl")
    profile = decode_provisioning_profile(_openssl_sign(_PLIST_ENTERPRISE_WILDCARD, tmp_path))
    assert profile["provisions_all_devices"] is True
    assert is_wildcard(profile) is True
    assert application_identifier(profile) == "TEAMXYZ789.*"
    assert not is_expired(profile)


def test_garbage_input_degrades_to_parse_failed():
    for bad in (b"", b"\x00" * 16, b"not der at all" * 10):
        profile = decode_provisioning_profile(bad)
        assert profile["parse_status"] == "parse_failed"
        assert profile["parse_error"]
        # A failed parse must not carry half-decoded fields.
        assert profile["entitlements"] is None


def test_signed_data_without_encapsulated_content_does_not_raise():
    """A well-formed envelope around a SignedData carrying no SEQUENCE member.

    The profile bytes come out of an app bundle, so a malformed one must
    decode to a parse_error like any other garbage rather than raise out of
    the parser and abort the bundle's analysis.
    """

    def der(tag: int, payload: bytes) -> bytes:
        if len(payload) < 128:
            return bytes([tag, len(payload)]) + payload
        length = len(payload).to_bytes((len(payload).bit_length() + 7) // 8, "big")
        return bytes([tag, 0x80 | len(length)]) + length + payload

    signed_data = der(0x02, b"\x01") + der(0x31, b"")  # version, digestAlgorithms
    oid = bytes.fromhex("2a864886f70d010702")  # 1.2.840.113549.1.7.2
    envelope = der(0x30, der(0x06, oid) + der(0xA0, der(0x30, signed_data)))
    profile = decode_provisioning_profile(envelope)
    assert profile["parse_status"] == "parsed"
    assert profile["plist"]["parse_error"] == "no_encapsulated_content"


def test_plist_failure_is_recorded_on_its_own_block(tmp_path):
    """A CMS that parses but wraps a non-plist payload is 'parsed' with the
    failure recorded on the plist block, never silent (rule 14)."""
    if not OPENSSL:
        pytest.skip("needs openssl")
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(tmp_path / "key.pem"),
            "-out",
            str(tmp_path / "cert.pem"),
            "-days",
            "365",
            "-nodes",
            "-subj",
            "/CN=Test",
        ],
        check=True,
        capture_output=True,
    )
    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"this is not a plist at all")
    subprocess.run(
        [
            "openssl",
            "smime",
            "-sign",
            "-binary",
            "-nodetach",
            "-nosmimecap",
            "-in",
            str(payload),
            "-signer",
            str(tmp_path / "cert.pem"),
            "-inkey",
            str(tmp_path / "key.pem"),
            "-outform",
            "DER",
            "-out",
            str(tmp_path / "bad.mobileprovision"),
        ],
        check=True,
        capture_output=True,
    )
    profile = decode_provisioning_profile((tmp_path / "bad.mobileprovision").read_bytes())
    assert profile["parse_status"] == "parsed"
    assert profile["plist"]["parse_status"] == "parse_failed"
    assert profile["plist"]["parse_error"]


def test_expiry_evaluated_at_check_time():
    """The same stored dates must read expired or valid depending on now,
    so parse output stays deterministic and the clock lives in the checks."""
    stored = {"expires": "2020-01-01T00:00:00+00:00"}
    assert is_expired(stored, now=datetime(2021, 1, 1, tzinfo=timezone.utc)) is True
    assert is_expired(stored, now=datetime(2019, 1, 1, tzinfo=timezone.utc)) is False
    assert is_expired({"expires": None}) is False
    assert is_expired({"expires": "not a date"}) is False


def test_load_embedded_profile_finds_both_spellings(tmp_path):
    assert load_embedded_profile(str(tmp_path)) is None
    (tmp_path / "Contents").mkdir()
    (tmp_path / "Contents" / "embedded.provisionprofile").write_bytes(b"CMS")
    found = load_embedded_profile(str(tmp_path))
    assert found and found[0] == "embedded.provisionprofile" and found[1] == b"CMS"


def test_check_functions_on_metadata():
    """The rule-engine layer: clean without a profile, fires on the block."""
    from blint.lib.checks import (
        check_profile_development,
        check_profile_expired,
        check_profile_wildcard,
    )

    clean = {"provisioning_profile": {"parse_status": "parse_failed"}}
    assert check_profile_expired("f", {}, {}) is True
    assert check_profile_expired("f", clean, {}) is True
    expired_block = {
        "provisioning_profile": {
            "parse_status": "parsed",
            "name": "Old Profile",
            "expires": "2020-01-01T00:00:00+00:00",
            "entitlements": {"application-identifier": "TEAM.app", "get-task-allow": False},
        }
    }
    result = check_profile_expired("f", expired_block, {})
    assert isinstance(result, str) and "Old Profile" in result
    dev_block = {
        "provisioning_profile": {
            "parse_status": "parsed",
            "name": "Dev Profile",
            "expires": "2099-01-01T00:00:00+00:00",
            "entitlements": {
                "application-identifier": "TEAM.app",
                "get-task-allow": True,
                "aps-environment": "development",
            },
        }
    }
    result = check_profile_development("f", dev_block, {})
    assert isinstance(result, str) and "get-task-allow" in result
    assert check_profile_expired("f", dev_block, {}) is True
    wildcard_block = {
        "provisioning_profile": {
            "parse_status": "parsed",
            "name": "Ent",
            "expires": "2099-01-01T00:00:00+00:00",
            "entitlements": {"application-identifier": "TEAM.*"},
        }
    }
    result = check_profile_wildcard("f", wildcard_block, {})
    assert isinstance(result, str) and "TEAM.*" in result
    assert check_profile_development("f", wildcard_block, {}) is True


def test_rules_yml_declares_profile_rules():
    """The three profile rules ship with the repo's rule catalog."""
    from blint.lib.analysis import rules_dict

    for rule_id, severity in (
        ("CHECK_PROFILE_EXPIRED", "high"),
        ("CHECK_PROFILE_DEVELOPMENT", "medium"),
        ("CHECK_PROFILE_WILDCARD", "medium"),
    ):
        rule = rules_dict.get(rule_id)
        assert rule, f"{rule_id} missing from the rule catalog"
        assert rule["severity"] == severity
        assert "MachO" in rule["exe_types"]


def test_ipa_with_profile_yields_block_and_findings(tmp_path):
    """End to end: an .ipa whose app carries embedded.mobileprovision gets the
    decoded block on every member's metadata and fires the profile rules."""
    import zipfile

    from blint.lib.binary import parse
    from blint.lib.checks import check_profile_development
    from blint.lib.ios import collect_ios_app, enrich_with_bundle_context

    if not OPENSSL:
        pytest.skip("needs openssl")
    profile_bytes = _openssl_sign(_PLIST_DEVELOPMENT, tmp_path)
    app = "DemoApp.app"
    ipa_path = tmp_path / "demo.ipa"
    macho = b"\xcf\xfa\xed\xfe" + b"\x00" * 256
    with zipfile.ZipFile(ipa_path, "w") as zf:
        zf.writestr(
            f"Payload/{app}/Info.plist",
            plistlib.dumps(
                {"CFBundleExecutable": "DemoApp", "CFBundleIdentifier": "com.example.demo"}
            ),
        )
        zf.writestr(f"Payload/{app}/DemoApp", macho)
        zf.writestr(f"Payload/{app}/embedded.mobileprovision", profile_bytes)
    app_collected = collect_ios_app(str(ipa_path))
    assert app_collected
    profile_block = app_collected["bundle_info"]["provisioning_profile"]
    assert profile_block["parse_status"] == "parsed"
    assert profile_block["entitlements"]["get-task-allow"] is True
    metadata = parse(app_collected["binaries"][0]["path"])
    enriched = enrich_with_bundle_context(
        metadata, app_collected["bundle_info"], "main", "DemoApp.app/DemoApp"
    )
    assert enriched["provisioning_profile"]["name"] == "iOS Team Provisioning Profile"
    # The development check fires on the enriched metadata.
    assert isinstance(check_profile_development("f", enriched, {}), str)
