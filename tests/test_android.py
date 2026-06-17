from pathlib import Path
from xml.etree import ElementTree

from blint.lib.android import (
    build_manifest_properties,
    build_parent_component,
    find_main_activity,
    parse_apk_summary,
    select_base_apk,
)

SAMPLE_MANIFEST = """<manifest xmlns:android="http://schemas.android.com/apk/res/android" \
android:versionCode="2616021" android:versionName="1.2026.160" \
android:compileSdkVersion="37" package="com.example.app">
<uses-sdk android:minSdkVersion="29" android:targetSdkVersion="37"></uses-sdk>
<uses-permission android:name="android.permission.CAMERA"></uses-permission>
<uses-permission android:name="android.permission.INTERNET"></uses-permission>
<uses-feature android:name="android.hardware.camera"></uses-feature>
<application>
<activity android:name="com.example.app.MainActivity">
<intent-filter>
<action android:name="android.intent.action.MAIN"></action>
<category android:name="android.intent.category.LAUNCHER"></category>
</intent-filter>
</activity>
</application>
</manifest>"""


def _manifest_attributes():
    root = ElementTree.fromstring(SAMPLE_MANIFEST)
    ns = "{http://schemas.android.com/apk/res/android}"
    return {
        "package": root.get("package", ""),
        "versionName": root.get(f"{ns}versionName", ""),
        "versionCode": root.get(f"{ns}versionCode", ""),
        "compileSdkVersion": root.get(f"{ns}compileSdkVersion", ""),
        "minSdkVersion": root.find("uses-sdk").get(f"{ns}minSdkVersion", ""),
        "targetSdkVersion": root.find("uses-sdk").get(f"{ns}targetSdkVersion", ""),
        "permissions": sorted(p.get(f"{ns}name") for p in root.iter("uses-permission")),
        "features": sorted(f.get(f"{ns}name") for f in root.iter("uses-feature")),
        "mainActivity": find_main_activity(root),
    }


def test_parse_summary():
    test_summary_file = Path(__file__).parent / "data" / "apk-summary.txt"
    with open(test_summary_file) as fp:
        comp = parse_apk_summary(fp.read())
        assert comp


def test_find_main_activity():
    root = ElementTree.fromstring(SAMPLE_MANIFEST)
    assert find_main_activity(root) == "com.example.app.MainActivity"


def test_build_parent_component_from_manifest():
    manifest = _manifest_attributes()
    component = build_parent_component(manifest, "app.apk")
    assert component is not None
    assert component.name == "com.example.app"
    assert component.version.root == "1.2026.160"
    assert component.purl == "pkg:android/com.example.app@1.2026.160"


def test_build_manifest_properties_with_bundle_info():
    manifest = _manifest_attributes()
    bundle_info = {
        "app_name": "Example",
        "arches": ["arm64-v8a"],
        "languages": ["en", "de"],
        "dpis": ["480"],
    }
    props = {p.name: p.value for p in build_manifest_properties(manifest, bundle_info)}
    assert "android.permission.CAMERA" in props["internal.appPermissions"]
    assert props["internal:minSdkVersion"] == "29"
    assert props["internal:targetSdkVersion"] == "37"
    assert props["internal:mainActivity"] == "com.example.app.MainActivity"
    assert props["internal:appName"] == "Example"
    assert props["internal:architectures"] == "arm64-v8a"


def test_build_parent_component_requires_name():
    assert build_parent_component({}, "app.apk") is None


def test_select_base_apk():
    apks = ["/tmp/split_config.en.apk", "/tmp/base.apk", "/tmp/split_config.arm64.apk"]
    assert select_base_apk(apks) == "/tmp/base.apk"
    assert select_base_apk(["/tmp/split_config.en.apk"]) == "/tmp/split_config.en.apk"
    assert select_base_apk([]) is None


def test_create_dex_component_tolerates_missing_metadata():
    # parse_dex error path returns metadata without 'methods'/'classes' keys.
    from blint.lib.android import create_dex_component

    comp = create_dex_component(
        "app.apk", {"file_path": "x.dex"}, "", "classes", "classes.dex", None
    )
    props = {p.name: p.value for p in comp.properties}
    assert props["internal:functions"] == ""
    assert props["internal:classes"] == ""


def test_format_dex_method_handles_missing_prototype():
    from blint.lib.android import _format_dex_method

    class _NoProto:
        name = "doThing"

        @property
        def prototype(self):
            raise AttributeError("no prototype")

    assert _format_dex_method(_NoProto()) == "doThing"
