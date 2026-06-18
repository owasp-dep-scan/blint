import plistlib
import zipfile

import os

from blint.lib.ios import (
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
