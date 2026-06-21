"""Tests for the iOS/macOS (``.ipa``) SBOM generation path."""

import json
import plistlib
import zipfile
from types import SimpleNamespace

from blint.cyclonedx.spec import Scope, Type
from blint.lib.sbom import (
    _callgraph_sidecar_slug,
    _ios_purl,
    ios_binary_component,
    ios_parent_component,
    is_apple_platform_library,
    process_ios_file,
    write_ios_callgraphs,
)

# Minimal Mach-O magic so is_exe() treats the fixture files as binaries.
_MACHO_BYTES = b"\xcf\xfa\xed\xfe" + b"\x00" * 256


def _make_ipa(tmp_path):
    app = "DemoApp.app"
    info = {
        "CFBundleExecutable": "DemoApp",
        "CFBundleIdentifier": "com.example.demo",
        "CFBundleName": "DemoApp",
        "CFBundleShortVersionString": "1.2.3",
        "MinimumOSVersion": "15.0",
    }
    ipa_path = tmp_path / "demo.ipa"
    with zipfile.ZipFile(ipa_path, "w") as zf:
        zf.writestr(f"Payload/{app}/Info.plist", plistlib.dumps(info))
        zf.writestr(f"Payload/{app}/DemoApp", _MACHO_BYTES)
        zf.writestr(f"Payload/{app}/Frameworks/Demo.framework/Demo", _MACHO_BYTES)
    return str(ipa_path)


def test_ios_purl_includes_path_qualifier():
    purl = _ios_purl("com.example.demo", "1.0", {"path": "DemoApp.app/DemoApp"})
    assert purl.startswith("pkg:ios/com.example.demo@1.0")
    assert "path=DemoApp.app/DemoApp" in purl


def test_ios_parent_component_from_bundle_identifier(tmp_path):
    bundle_info = {
        "bundle_identifier": "com.example.demo",
        "bundle_name": "DemoApp",
        "bundle_version": "1.2.3",
        "minimum_os_version": "15.0",
    }
    comp = ios_parent_component(bundle_info, str(tmp_path / "demo.ipa"))
    assert comp.type == Type.application
    assert comp.name == "com.example.demo"
    assert str(comp.version.root) == "1.2.3"
    assert comp.purl == "pkg:ios/com.example.demo@1.2.3"
    prop_names = {p.name for p in comp.properties}
    assert "internal:minimumOSVersion" in prop_names


def test_ios_binary_component_roles_and_hash(tmp_path):
    bin_path = tmp_path / "DemoApp"
    bin_path.write_bytes(_MACHO_BYTES)
    bundle_info = {"bundle_identifier": "com.example.demo", "bundle_version": "1.2.3"}

    main = ios_binary_component(
        {"path": str(bin_path), "role": "main", "bundle_path": "DemoApp.app/DemoApp"},
        bundle_info,
    )
    assert main.type == Type.application
    assert main.hashes and main.hashes[0].content
    assert "path=DemoApp.app/DemoApp" in main.purl

    framework = ios_binary_component(
        {
            "path": str(bin_path),
            "role": "framework",
            "bundle_path": "DemoApp.app/Frameworks/Demo.framework/Demo",
        },
        bundle_info,
    )
    assert framework.type == Type.library


def test_ios_binary_component_uses_own_bundle_identity():
    # An embedded framework carries its own Info.plist identity, which should
    # win over the host application's version.
    bundle_info = {"bundle_identifier": "com.example.demo", "bundle_version": "1.2.3"}
    comp = ios_binary_component(
        {
            "path": __file__,  # any readable file; only hashed
            "role": "framework",
            "bundle_path": "DemoApp.app/Frameworks/Realm.framework/Realm",
            "bundle_identifier": "io.realm.Realm",
            "bundle_version": "4.1.1",
        },
        bundle_info,
    )
    assert str(comp.version.root) == "4.1.1"
    assert comp.purl.startswith("pkg:ios/io.realm.Realm@4.1.1")
    prop_names = {p.name for p in comp.properties}
    assert "internal:bundleIdentifier" in prop_names


def test_is_apple_platform_library_classification():
    assert is_apple_platform_library("/System/Library/Frameworks/Foundation.framework/Foundation")
    assert is_apple_platform_library("/usr/lib/libSystem.B.dylib")
    assert not is_apple_platform_library("@rpath/Alamofire.framework/Alamofire")
    assert not is_apple_platform_library("@executable_path/Frameworks/Bolts.framework/Bolts")
    assert not is_apple_platform_library("")


def test_process_ios_file_builds_app_hierarchy(tmp_path):
    ipa = _make_ipa(tmp_path)
    sbom = SimpleNamespace(metadata=SimpleNamespace(component=SimpleNamespace(components=None)))
    deps: dict[str, set] = {}
    components = process_ios_file(deps, deep_mode=False, f=ipa, sbom=sbom)
    names = {c.name for c in components}
    assert "DemoApp" in names
    assert "Demo" in names
    # The app-bundle parent is registered and depends on the binaries.
    parent_refs = [c.name for c in sbom.metadata.component.components]
    assert "com.example.demo" in parent_refs
    assert deps  # dependency edges recorded


def test_callgraph_sidecar_slug_is_filesystem_safe():
    assert (
        _callgraph_sidecar_slug("DemoApp.app/Frameworks/Realm.framework/Realm")
        == "DemoApp.app_Frameworks_Realm.framework_Realm"
    )
    # Both POSIX and Windows separators are flattened on any host OS.
    assert (
        _callgraph_sidecar_slug("DemoApp.app\\Frameworks\\Realm.framework\\Realm")
        == "DemoApp.app_Frameworks_Realm.framework_Realm"
    )
    assert _callgraph_sidecar_slug("My App.app/My App") == "My_App.app_My_App"
    assert _callgraph_sidecar_slug("") == "binary"


def test_write_ios_callgraphs_emits_sidecars(tmp_path, monkeypatch):
    # Disassembling a real Mach-O is exercised elsewhere; here we mock the
    # unpack/parse boundary so the sidecar-writing logic is tested deterministically.
    callgraph = {"version": 1, "nodes": [{"id": "n0"}], "edges": [], "external": []}
    app_dir = tmp_path / "unpacked"
    app_dir.mkdir()
    app = {
        "temp_dir": str(app_dir),
        "bundle_info": {},
        "binaries": [
            {"path": str(app_dir / "Main"), "bundle_path": "Demo.app/Main"},
            {"path": str(app_dir / "Lib"), "bundle_path": "Demo.app/Frameworks/Lib.framework/Lib"},
            {"path": str(app_dir / "Encrypted"), "bundle_path": "Demo.app/Encrypted"},
        ],
    }
    monkeypatch.setattr("blint.lib.sbom.collect_ios_app", lambda _f: app)
    # FairPlay-encrypted binaries yield no callgraph and must be skipped.
    parsed = {
        str(app_dir / "Main"): {"callgraph": callgraph},
        str(app_dir / "Lib"): {"callgraph": callgraph},
        str(app_dir / "Encrypted"): {"disassembly_skipped": "fairplay_encrypted"},
    }
    monkeypatch.setattr("blint.lib.sbom.parse", lambda path, disassemble=False: parsed[path])

    write_ios_callgraphs(str(tmp_path / "demo.ipa"), str(tmp_path / "bom.json"))

    sidecars = sorted(p.name for p in tmp_path.glob("*.callgraph.json"))
    assert sidecars == [
        "bom-demo.ipa-Demo.app_Frameworks_Lib.framework_Lib.callgraph.json",
        "bom-demo.ipa-Demo.app_Main.callgraph.json",
    ]
    data = json.loads((tmp_path / sidecars[1]).read_text())
    # Same JSON shape as the native binary callgraph.
    assert {"version", "nodes", "edges", "external"} <= set(data)
    assert data["nodes"]


def test_write_ios_callgraphs_noop_without_output(tmp_path):
    # No sbom_output means no sidecars are written and nothing raises.
    write_ios_callgraphs(_make_ipa(tmp_path), "")
    assert not list(tmp_path.glob("*.callgraph.json"))
