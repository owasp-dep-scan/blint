import plistlib
import zipfile

import os

from blint.lib.ios import (
    _ats_tokens,
    _collect_privacy_signals,
    _privacy_tokens,
    _read_privacy_manifest,
    _summarize_ats,
    _undeclared_required_reason_tokens,
    collect_ios_app,
    enrich_with_bundle_context,
    is_ios_app,
)

# Minimal Mach-O magic so is_exe() treats the fixture files as binaries.
_MACHO_BYTES = b"\xcf\xfa\xed\xfe" + b"\x00" * 256


def _make_ipa(tmp_path, *, with_framework=True, with_appex=True):
    app = "DemoApp.app"
    info = {
        "CFBundleExecutable": "DemoApp",
        "CFBundleIdentifier": "com.example.demo",
        "CFBundleShortVersionString": "1.2.3",
        "MinimumOSVersion": "15.0",
    }
    ipa_path = tmp_path / "demo.ipa"
    with zipfile.ZipFile(ipa_path, "w") as zf:
        zf.writestr(f"Payload/{app}/Info.plist", plistlib.dumps(info))
        zf.writestr(f"Payload/{app}/DemoApp", _MACHO_BYTES)
        if with_framework:
            zf.writestr(f"Payload/{app}/Frameworks/Demo.framework/Demo", _MACHO_BYTES)
            zf.writestr(f"Payload/{app}/Frameworks/libextra.dylib", _MACHO_BYTES)
        if with_appex:
            appex_info = {"CFBundleExecutable": "Widget"}
            zf.writestr(
                f"Payload/{app}/PlugIns/Widget.appex/Info.plist",
                plistlib.dumps(appex_info),
            )
            zf.writestr(f"Payload/{app}/PlugIns/Widget.appex/Widget", _MACHO_BYTES)
    return str(ipa_path)


def test_is_ios_app():
    assert is_ios_app("/tmp/foo.ipa")
    assert is_ios_app("/tmp/FOO.IPA")
    assert not is_ios_app("/tmp/foo.apk")
    assert not is_ios_app(None)


def test_collect_ios_app_enumerates_binaries(tmp_path):
    ipa = _make_ipa(tmp_path)
    app = collect_ios_app(ipa)
    assert app is not None
    roles = {b["role"] for b in app["binaries"]}
    assert {"main", "framework", "dylib", "plugin"} <= roles
    # Main executable leads the list.
    assert app["binaries"][0]["role"] == "main"
    assert app["bundle_info"]["bundle_identifier"] == "com.example.demo"
    assert app["bundle_info"]["bundle_version"] == "1.2.3"
    # Bundle-relative paths, not extraction temp paths.
    main = app["binaries"][0]
    assert main["bundle_path"] == os.path.join("DemoApp.app", "DemoApp")


def test_collect_ios_app_rejects_non_zip(tmp_path):
    bogus = tmp_path / "bad.ipa"
    bogus.write_bytes(b"not a zip")
    assert collect_ios_app(str(bogus)) is None


def test_collect_ios_app_requires_payload(tmp_path):
    ipa_path = tmp_path / "empty.ipa"
    with zipfile.ZipFile(ipa_path, "w") as zf:
        zf.writestr("NotPayload/readme.txt", "hello")
    assert collect_ios_app(str(ipa_path)) is None


def test_enrich_with_bundle_context_sets_path_and_ids():
    metadata = {"name": "/tmp/blint_ios_appXXXX/Payload/DemoApp.app/DemoApp"}
    bundle_info = {
        "bundle_identifier": "com.example.demo",
        "bundle_version": "1.2.3",
        "minimum_os_version": "15.0",
        "executable": "DemoApp",
    }
    enrich_with_bundle_context(metadata, bundle_info, "main", "DemoApp.app/DemoApp")
    assert metadata["name"] == "DemoApp.app/DemoApp"
    assert metadata["file_path"] == "DemoApp.app/DemoApp"
    assert metadata["bundle_identifier"] == "com.example.demo"
    assert metadata["ios_bundle"]["role"] == "main"
    # The raw executable key is not leaked into the context.
    assert "executable" not in metadata["ios_bundle"]


def test_summarize_ats_flags_arbitrary_loads():
    ats = _summarize_ats({"NSAllowsArbitraryLoads": True})
    assert ats["allows_arbitrary_loads"] is True


def test_summarize_ats_flags_insecure_exception_domains():
    ats = _summarize_ats(
        {
            "NSExceptionDomains": {
                "insecure.example.com": {"NSExceptionAllowsInsecureHTTPLoads": True},
                "secure.example.com": {"NSExceptionRequiresForwardSecrecy": True},
            }
        }
    )
    assert ats["insecure_exception_domains"] == ["insecure.example.com"]


def test_summarize_ats_returns_none_for_secure_default():
    assert _summarize_ats({"NSExceptionDomains": {}}) is None
    assert _summarize_ats(None) is None


def test_ats_tokens_emitted_for_weakened_policy():
    tokens = _ats_tokens({"allows_arbitrary_loads": True, "insecure_exception_domains": ["x.com"]})
    assert "ATS_NSAllowsArbitraryLoads" in tokens
    assert "ATS_NSExceptionAllowsInsecureHTTPLoads" in tokens
    assert _ats_tokens(None) == []


def test_collect_privacy_signals_extracts_declarations():
    plist = {
        "NSCameraUsageDescription": "needs camera",
        "NSLocationWhenInUseUsageDescription": "needs location",
        "LSApplicationQueriesSchemes": ["whatsapp", "tg", "whatsapp"],
        "NSBonjourServices": ["_airplay._tcp", "_homekit._tcp"],
        "CFBundleName": "ignored",
    }
    signals = _collect_privacy_signals(plist)
    assert signals["privacy_usage_descriptions"] == [
        "NSCameraUsageDescription",
        "NSLocationWhenInUseUsageDescription",
    ]
    # Duplicates removed and sorted.
    assert signals["query_schemes"] == ["tg", "whatsapp"]
    assert signals["bonjour_services"] == ["_airplay._tcp", "_homekit._tcp"]


def test_collect_privacy_signals_empty_when_absent():
    assert _collect_privacy_signals({"CFBundleName": "x"}) == {}


def test_read_privacy_manifest_aggregates(tmp_path):
    app = tmp_path / "DemoApp.app"
    (app / "Frameworks" / "Ads.framework").mkdir(parents=True)
    app_manifest = {
        "NSPrivacyTracking": False,
        "NSPrivacyAccessedAPITypes": [
            {"NSPrivacyAccessedAPIType": "NSPrivacyAccessedAPICategoryUserDefaults"}
        ],
    }
    fw_manifest = {
        "NSPrivacyTracking": True,
        "NSPrivacyTrackingDomains": ["ads.example.com"],
        "NSPrivacyCollectedDataTypes": [
            {"NSPrivacyCollectedDataType": "NSPrivacyCollectedDataTypeDeviceID"}
        ],
        "NSPrivacyAccessedAPITypes": [
            {"NSPrivacyAccessedAPIType": "NSPrivacyAccessedAPICategorySystemBootTime"}
        ],
    }
    (app / "PrivacyInfo.xcprivacy").write_bytes(plistlib.dumps(app_manifest))
    (app / "Frameworks" / "Ads.framework" / "PrivacyInfo.xcprivacy").write_bytes(
        plistlib.dumps(fw_manifest)
    )
    manifest = _read_privacy_manifest(str(app))
    assert manifest["present"] is True
    assert manifest["manifest_count"] == 2
    # Tracking is true if any component declares it.
    assert manifest["tracking"] is True
    assert manifest["tracking_domains"] == ["ads.example.com"]
    assert manifest["collected_data_types"] == ["NSPrivacyCollectedDataTypeDeviceID"]
    assert manifest["accessed_api_categories"] == [
        "NSPrivacyAccessedAPICategorySystemBootTime",
        "NSPrivacyAccessedAPICategoryUserDefaults",
    ]


def test_read_privacy_manifest_absent(tmp_path):
    app = tmp_path / "DemoApp.app"
    app.mkdir()
    assert _read_privacy_manifest(str(app)) is None


def test_privacy_tokens_for_posture():
    bundle_info = {
        "privacy_usage_descriptions": ["NSCameraUsageDescription"],
        "query_schemes": ["a", "b", "c", "d", "e", "f"],
        "bonjour_services": ["_airplay._tcp"],
        "privacy_manifest": {
            "tracking": True,
            "tracking_domains": ["t.example.com"],
            "accessed_api_categories": ["NSPrivacyAccessedAPICategoryUserDefaults"],
        },
    }
    tokens = _privacy_tokens(bundle_info)
    assert "PRIV_NSCameraUsageDescription" in tokens
    assert "PRIV_LSApplicationQueriesSchemes" in tokens
    assert "PRIV_ManyApplicationQueriesSchemes" in tokens
    assert "PRIV_NSBonjourServices" in tokens
    assert "PRIV_NSPrivacyTracking" in tokens
    assert "PRIV_NSPrivacyTrackingDomains" in tokens
    assert "PRIV_NSPrivacyAccessedAPICategoryUserDefaults" in tokens
    assert "PRIV_PrivacyManifestMissing" not in tokens


def test_privacy_tokens_flags_missing_manifest():
    assert "PRIV_PrivacyManifestMissing" in _privacy_tokens({})


def test_undeclared_required_reason_tokens():
    metadata = {
        "symtab_symbols": [{"name": "_systemUptime"}],
        "objc_metadata": {"selectors": ["standardUserDefaults"], "external_classes": []},
    }
    # UserDefaults declared, SystemBootTime not.
    bundle_info = {
        "privacy_manifest": {
            "accessed_api_categories": ["NSPrivacyAccessedAPICategoryUserDefaults"]
        }
    }
    tokens = _undeclared_required_reason_tokens(metadata, bundle_info)
    assert "PRIV_UNDECLARED_NSPrivacyAccessedAPICategorySystemBootTime" in tokens
    assert "PRIV_UNDECLARED_NSPrivacyAccessedAPICategoryUserDefaults" not in tokens


def test_undeclared_required_reason_tokens_no_manifest_flags_all_used():
    metadata = {"symtab_symbols": [{"name": "_systemUptime"}]}
    tokens = _undeclared_required_reason_tokens(metadata, {})
    assert tokens == ["PRIV_UNDECLARED_NSPrivacyAccessedAPICategorySystemBootTime"]


def test_enrich_injects_privacy_tokens_for_main_only():
    bundle_info = {
        "privacy_usage_descriptions": ["NSCameraUsageDescription"],
        "privacy_manifest": {"present": True, "tracking": True, "tracking_domains": []},
    }
    main = {"name": "x"}
    enrich_with_bundle_context(main, bundle_info, "main", "DemoApp.app/DemoApp")
    assert "PRIV_NSCameraUsageDescription" in main["informative_strings"]
    assert "PRIV_NSPrivacyTracking" in main["informative_strings"]
    framework = {"name": "y"}
    enrich_with_bundle_context(framework, bundle_info, "framework", "F")
    assert "PRIV_NSCameraUsageDescription" not in (framework.get("informative_strings") or [])


def test_enrich_injects_ats_tokens_into_informative_strings():
    metadata = {"name": "x", "informative_strings": []}
    bundle_info = {"app_transport_security": {"allows_arbitrary_loads": True}}
    enrich_with_bundle_context(metadata, bundle_info, "main", "DemoApp.app/DemoApp")
    assert "ATS_NSAllowsArbitraryLoads" in metadata["informative_strings"]
    # Non-main binaries do not get the bundle-level ATS tokens.
    other = {"name": "y"}
    enrich_with_bundle_context(other, bundle_info, "framework", "DemoApp.app/Frameworks/F")
    assert "ATS_NSAllowsArbitraryLoads" not in (other.get("informative_strings") or [])
