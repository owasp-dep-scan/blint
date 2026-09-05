import pytest
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


def test_collect_ios_app_detailed_reports_reasons(tmp_path):
    """Every collect failure mode yields its documented machine-readable token."""
    from blint.lib.ios import collect_ios_app_detailed

    bogus = tmp_path / "bogus.ipa"
    bogus.write_bytes(b"PK\x03\x04" + b"\x00" * 64)
    assert collect_ios_app_detailed(str(bogus)) == (None, "extract_failed")

    no_payload = tmp_path / "nopayload.ipa"
    with zipfile.ZipFile(no_payload, "w") as zf:
        zf.writestr("NotPayload/readme.txt", "hello")
    assert collect_ios_app_detailed(str(no_payload)) == (None, "no_payload_dir")

    no_app = tmp_path / "noapp.ipa"
    with zipfile.ZipFile(no_app, "w") as zf:
        zf.writestr("Payload/readme.txt", "hello")
    assert collect_ios_app_detailed(str(no_app)) == (None, "no_app_bundle")

    no_binaries = tmp_path / "nobinaries.ipa"
    info = {"CFBundleExecutable": "DemoApp"}
    with zipfile.ZipFile(no_binaries, "w") as zf:
        zf.writestr("Payload/DemoApp.app/Info.plist", plistlib.dumps(info))
    assert collect_ios_app_detailed(str(no_binaries)) == (None, "no_binaries")

    # Success returns the app dict and no reason.
    ipa = _make_ipa(tmp_path)
    app, reason = collect_ios_app_detailed(ipa)
    assert app is not None
    assert reason is None


def _blint_ios_app_dir_count() -> int:
    import glob
    import tempfile

    return len(glob.glob(os.path.join(tempfile.gettempdir(), "blint_ios_app*")))


def test_read_bundle_info_rejects_non_dict_plist_roots(tmp_path):
    """A legal plist with a non-dict root must not crash the bundle reader.

    plistlib returns None for an empty <plist/> and lists/strings for other
    root element types; all are treated like an unreadable plist (rule 10:
    one fixture per variant).
    """
    from blint.lib.ios import _read_bundle_info

    for plist_bytes in (
        b'<plist version="1.0"/>',
        b'<plist version="1.0"><array><string>x</string></array></plist>',
        b"<plist version=\"1.0\"><string>just a string</string></plist>",
    ):
        app_dir = tmp_path / "App.app"
        app_dir.mkdir(exist_ok=True)
        (app_dir / "Info.plist").write_bytes(plist_bytes)
        info = _read_bundle_info(str(app_dir))
        assert info == {"bundle_dir": "App.app"}


def test_collect_ios_app_non_dict_plist_root_no_crash_no_leak(tmp_path):
    """The reviewer's repro: <plist version="1.0"/> must collect, not crash.

    The binaries inside are still analyzable (bundle info is simply empty),
    and the extraction directory must be gone when collection fails or
    returns.
    """
    from blint.lib.ios import collect_ios_app_detailed
    import shutil

    ipa_path = tmp_path / "app1.ipa"
    with zipfile.ZipFile(ipa_path, "w") as zf:
        zf.writestr("Payload/App1.app/Info.plist", b'<plist version="1.0"/>')
        zf.writestr("Payload/App1.app/App1", _MACHO_BYTES)

    before = _blint_ios_app_dir_count()
    app, reason = collect_ios_app_detailed(str(ipa_path))
    assert app is not None
    assert reason is None
    assert len(app["binaries"]) == 1
    shutil.rmtree(app["temp_dir"], ignore_errors=True)
    assert _blint_ios_app_dir_count() == before


def test_collect_ios_app_detailed_cleans_up_on_unexpected_error(tmp_path, monkeypatch):
    """Any exception mid-collection removes the extraction dir before raising.

    Error isolation makes surviving a bad archive the normal outcome, so the
    cleanup cannot live only on the skip-return paths (review round 1,
    must-fix).
    """
    import blint.lib.ios as ios_mod

    ipa_path = tmp_path / "app2.ipa"
    with zipfile.ZipFile(ipa_path, "w") as zf:
        zf.writestr(
            "Payload/App2.app/Info.plist",
            plistlib.dumps({"CFBundleExecutable": "App2"}),
        )
        zf.writestr("Payload/App2.app/App2", _MACHO_BYTES)

    def boom(*_args):
        raise RuntimeError("boom")

    monkeypatch.setattr(ios_mod, "_read_privacy_manifest", boom)
    before = _blint_ios_app_dir_count()
    with pytest.raises(RuntimeError, match="boom"):
        ios_mod.collect_ios_app_detailed(str(ipa_path))
    assert _blint_ios_app_dir_count() == before
