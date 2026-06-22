"""Integration tests for the iOS privacy / fingerprinting review rules.

These exercise the rule engine end to end: crafted Mach-O metadata is fed
through ``ReviewRunner`` and the resulting capability findings are asserted, so
the YAML rule definitions and their wiring are covered (not just ios.py).
"""

import pytest

from blint.lib.analysis import load_default_rules
from blint.lib.review_runner import ReviewRunner


@pytest.fixture(scope="module", autouse=True)
def _rules_loaded():
    load_default_rules()


def _run(metadata):
    metadata.setdefault("exe_type", "MachO")
    runner = ReviewRunner()
    runner.run_review(metadata)
    return {r["id"]: r for r in runner.process_review("bin", "bin")}


def test_privacy_capability_rules_fire():
    findings = _run(
        {
            "dynamic_symbols": [
                {"name": "_canOpenURL"},
                {"name": "_sysctlbyname"},
                {"name": "_getifaddrs"},
            ],
            "symtab_symbols": [{"name": "_gethostname"}, {"name": "kSecAttrAccessibleAlways"}],
            "objc_metadata": {
                "selectors": [
                    "nativeBounds",
                    "mainScreen",
                    "requestTrackingAuthorization",
                    "requestFullAccessToEvents",
                ],
                "external_classes": [
                    "MTLCreateSystemDefaultDevice",
                    "ATTrackingManager",
                    "EKEventStore",
                    "DCAppAttestService",
                ],
            },
        }
    )
    for rule_id in (
        "IOS_APP_PRESENCE_PROBE",
        "IOS_HARDWARE_FINGERPRINT",
        "IOS_NETWORK_INTERFACE_ENUM",
        "IOS_PLATFORM_IDENTIFIER",
        "IOS_DISPLAY_FINGERPRINT",
        "IOS_KEYCHAIN_PERSISTENCE",
        "IOS_USER_TRACKING_REQUEST",
        "IOS_CALENDAR_REMINDERS_ACCESS",
        "IOS_DEVICE_ATTESTATION",
    ):
        assert rule_id in findings, f"expected {rule_id} to fire"
    # Privacy rules carry a category for distinct reporting.
    assert findings["IOS_APP_PRESENCE_PROBE"]["category"] == "privacy-sidechannel"


def test_posture_rules_fire_from_informative_tokens():
    findings = _run(
        {
            "symtab_symbols": [],
            "informative_strings": [
                {"value": "PRIV_NSPrivacyTracking"},
                {"value": "PRIV_PrivacyManifestMissing"},
                {"value": "PRIV_ManyApplicationQueriesSchemes"},
                {"value": "PRIV_NSBonjourServices"},
                {"value": "PRIV_NSCameraUsageDescription"},
                {"value": "PRIV_UNDECLARED_NSPrivacyAccessedAPICategorySystemBootTime"},
            ],
        }
    )
    for rule_id in (
        "IOS_TRACKING_DECLARED",
        "IOS_PRIVACY_MANIFEST_MISSING",
        "IOS_MANY_QUERY_SCHEMES",
        "IOS_LOCAL_NETWORK_DECLARED",
        "IOS_SENSITIVE_PERMISSIONS_DECLARED",
        "IOS_UNDECLARED_REQUIRED_REASON_API",
    ):
        assert rule_id in findings, f"expected {rule_id} to fire"


def test_clean_binary_has_no_privacy_findings():
    findings = _run(
        {
            "symtab_symbols": [{"name": "_main"}, {"name": "_printf"}],
            "objc_metadata": {
                "selectors": ["viewDidLoad"],
                "external_classes": ["UIViewController"],
            },
        }
    )
    privacy = [fid for fid in findings if fid.startswith("IOS_")]
    assert privacy == [], f"unexpected privacy findings on clean binary: {privacy}"
