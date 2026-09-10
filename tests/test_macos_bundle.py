"""Tests for the macOS bundle walker (``.app`` / ``.framework`` / ``.dSYM``).

The fixtures are synthetic directory trees built at runtime with minimal
Mach-O magic bytes (``is_exe`` only inspects content, not load commands) so
they run on every CI platform. The walker itself is a directory reader; its
plausible failure modes — wrong executable candidate, doubled members through
the ``Versions/Current`` symlink alias, nested-bundle double reporting — are
what these tests pin. Validation of the parsed *metadata* against real Apple
artifacts is the lane's external ground-truth gate, not this file's job.
"""

import plistlib

from blint.lib.ios import enrich_with_bundle_context
from blint.lib.macos_bundle import (
    MACOS_BUNDLE_SUFFIXES,
    bundle_kind,
    collect_macos_bundle_detailed,
    find_macos_bundles,
    is_macos_bundle,
    path_inside_any_bundle,
)
from blint.lib.sbom import process_macos_bundle_file

# Minimal Mach-O magic so is_exe() treats the fixture files as binaries.
_MACHO_BYTES = b"\xcf\xfa\xed\xfe" + b"\x00" * 256


def _write(path, data=_MACHO_BYTES):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def _write_plist(path, info):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(plistlib.dumps(info))


def _make_app(tmp_path):
    """A macOS .app with one of every embedded component kind."""
    app = tmp_path / "Demo.app"
    _write_plist(
        app / "Contents" / "Info.plist",
        {
            "CFBundleExecutable": "Demo",
            "CFBundleIdentifier": "com.example.demo",
            "CFBundleName": "Demo",
            "CFBundleShortVersionString": "2.0.0",
            "LSMinimumSystemVersion": "12.0",
        },
    )
    _write(app / "Contents" / "MacOS" / "Demo")
    # A framework embedding its own framework (two levels deep).
    _write_plist(
        app / "Contents" / "Frameworks" / "Core.framework" / "Resources" / "Info.plist",
        {"CFBundleIdentifier": "org.example.core", "CFBundleName": "Core"},
    )
    _write(app / "Contents" / "Frameworks" / "Core.framework" / "Versions" / "A" / "Core")
    (app / "Contents" / "Frameworks" / "Core.framework" / "Versions" / "Current").symlink_to("A")
    _write_plist(
        app
        / "Contents"
        / "Frameworks"
        / "Core.framework"
        / "Versions"
        / "A"
        / "Frameworks"
        / "Inner.framework"
        / "Resources"
        / "Info.plist",
        {"CFBundleIdentifier": "org.example.inner"},
    )
    _write(
        app
        / "Contents"
        / "Frameworks"
        / "Core.framework"
        / "Versions"
        / "A"
        / "Frameworks"
        / "Inner.framework"
        / "Inner"
    )
    # An app extension with its own identity.
    _write_plist(
        app / "Contents" / "PlugIns" / "Widget.appex" / "Contents" / "Info.plist",
        {"CFBundleExecutable": "Widget", "CFBundleIdentifier": "com.example.widget"},
    )
    _write(app / "Contents" / "PlugIns" / "Widget.appex" / "Contents" / "MacOS" / "Widget")
    # An XPC service and a loose dylib.
    _write_plist(
        app / "Contents" / "XPCServices" / "Helper.xpc" / "Contents" / "Info.plist",
        {"CFBundleExecutable": "Helper", "CFBundleIdentifier": "com.example.helper"},
    )
    _write(app / "Contents" / "XPCServices" / "Helper.xpc" / "Contents" / "MacOS" / "Helper")
    _write(app / "Contents" / "Frameworks" / "loose.dylib")
    return app


def test_is_macos_bundle_and_kind():
    assert not is_macos_bundle("/nonexistent/Foo.app")
    assert bundle_kind("Foo.app") == "app"
    assert bundle_kind("Foo.APP") == "app"
    assert bundle_kind("Foo.framework") == "framework"
    assert bundle_kind("Foo.dSYM") == "dsym"
    assert bundle_kind("Foo.appex") == "appex"
    assert bundle_kind("Foo.xpc") == "xpc"


def test_app_bundle_collects_every_component_kind(tmp_path):
    app = _make_app(tmp_path)
    collection, reason = collect_macos_bundle_detailed(str(app))
    assert reason is None
    by_bundled_path = {b["bundle_path"]: b for b in collection["binaries"]}
    assert set(by_bundled_path) == {
        "Contents/MacOS/Demo",
        "Contents/Frameworks/Core.framework/Versions/A/Core",
        "Contents/Frameworks/Core.framework/Versions/A/Frameworks/Inner.framework/Inner",
        "Contents/PlugIns/Widget.appex/Contents/MacOS/Widget",
        "Contents/XPCServices/Helper.xpc/Contents/MacOS/Helper",
        "Contents/Frameworks/loose.dylib",
    }
    assert by_bundled_path["Contents/MacOS/Demo"]["role"] == "main"
    assert (
        by_bundled_path["Contents/Frameworks/Core.framework/Versions/A/Core"]["role"]
        == "framework"
    )
    assert (
        by_bundled_path["Contents/PlugIns/Widget.appex/Contents/MacOS/Widget"]["role"] == "plugin"
    )
    assert (
        by_bundled_path["Contents/XPCServices/Helper.xpc/Contents/MacOS/Helper"]["role"] == "xpc"
    )
    assert by_bundled_path["Contents/Frameworks/loose.dylib"]["role"] == "dylib"
    # Embedded members carry their own Info.plist identity, not the host's.
    widget = by_bundled_path["Contents/PlugIns/Widget.appex/Contents/MacOS/Widget"]
    assert widget["bundle_identifier"] == "com.example.widget"
    # The bundle-info identity is the app's.
    assert collection["bundle_info"]["bundle_identifier"] == "com.example.demo"
    assert collection["kind"] == "app"


def test_framework_versions_aliasing_yields_one_binary(tmp_path):
    fw = tmp_path / "Core.framework"
    _write_plist(
        fw / "Resources" / "Info.plist",
        {"CFBundleExecutable": "Core", "CFBundleIdentifier": "org.example.core"},
    )
    _write(fw / "Versions" / "A" / "Core")
    (fw / "Versions" / "Current").symlink_to("A")
    (fw / "Core").symlink_to("Versions/A/Core")
    collection, reason = collect_macos_bundle_detailed(str(fw))
    assert reason is None
    # The root-level path is the canonical user-visible spelling; the
    # Versions/Current and Versions/A aliases must not produce extra entries.
    assert [b["bundle_path"] for b in collection["binaries"]] == ["Core"]
    assert collection["binaries"][0]["role"] == "main"


def test_framework_without_executable_key_finds_versions_binary(tmp_path):
    fw = tmp_path / "Core.framework"
    _write_plist(fw / "Versions" / "A" / "Resources" / "Info.plist", {"CFBundleName": "Core"})
    _write(fw / "Versions" / "A" / "Core")
    collection, _reason = collect_macos_bundle_detailed(str(fw))
    assert [b["role"] for b in collection["binaries"]] == ["main"]
    assert collection["binaries"][0]["bundle_path"] == "Versions/A/Core"


def test_dsym_collects_dwarf_binaries_with_fallback_identity(tmp_path):
    dsym = tmp_path / "Demo.dSYM"
    _write(dsym / "Contents" / "Resources" / "DWARF" / "Demo")
    _write(dsym / "Contents" / "Resources" / "DWARF" / "Demo-arm64")
    collection, reason = collect_macos_bundle_detailed(str(dsym))
    assert reason is None
    assert collection["kind"] == "dsym"
    assert {b["role"] for b in collection["binaries"]} == {"debug"}
    assert collection["binaries"][0]["bundle_name"] == "Demo"


def test_ios_style_root_layout_is_accepted(tmp_path):
    app = tmp_path / "Legacy.app"
    _write_plist(
        app / "Info.plist",
        {"CFBundleExecutable": "Legacy", "CFBundleIdentifier": "com.example.legacy"},
    )
    _write(app / "Legacy")
    _write_plist(
        app / "Frameworks" / "Dep.framework" / "Info.plist",
        {"CFBundleIdentifier": "org.example.dep"},
    )
    _write(app / "Frameworks" / "Dep.framework" / "Dep")
    collection, reason = collect_macos_bundle_detailed(str(app))
    assert reason is None
    roles = {b["role"] for b in collection["binaries"]}
    assert roles == {"main", "framework"}


def test_empty_bundle_is_skipped_with_reason(tmp_path):
    app = tmp_path / "Empty.app"
    _write_plist(app / "Contents" / "Info.plist", {"CFBundleName": "Empty"})
    collection, reason = collect_macos_bundle_detailed(str(app))
    assert collection is None
    assert reason == "no_binaries"


def test_find_macos_bundles_suppresses_nested_bundles(tmp_path):
    app = _make_app(tmp_path)
    stranger = tmp_path / "Tools" / "Standalone.framework"
    _write_plist(stranger / "Info.plist", {"CFBundleName": "Standalone"})
    _write(stranger / "Standalone")
    bundles = find_macos_bundles(str(tmp_path))
    names = {b for b in bundles}
    assert str(app) in names
    assert str(stranger) in names
    # Embedded bundles (Core.framework, Widget.appex, Helper.xpc, Inner.framework)
    # belong to the walker, not to the discovery list.
    assert len(bundles) == 2


def test_path_inside_any_bundle_filters_discovered_files(tmp_path):
    app = _make_app(tmp_path)
    inside = str(app / "Contents" / "MacOS" / "Demo")
    outside = str(tmp_path / "elsewhere.bin")
    assert path_inside_any_bundle(inside, [str(app)])
    assert not path_inside_any_bundle(outside, [str(app)])
    # Windows-style separators in the bundle path must still match when the
    # file path uses them (both are produced by os.walk on that platform).
    assert path_inside_any_bundle("C:\\apps\\Foo.app\\Contents\\MacOS\\Foo", ["C:\\apps\\Foo.app"])


def test_suffixes_tuple_shape():
    assert MACOS_BUNDLE_SUFFIXES == (".app", ".framework", ".dsym", ".xpc", ".appex")


def test_process_macos_bundle_file_builds_pkg_macos_hierarchy(tmp_path):
    from types import SimpleNamespace

    app = _make_app(tmp_path)
    sbom = SimpleNamespace(metadata=SimpleNamespace(component=SimpleNamespace(components=None)))
    deps: dict[str, set] = {}
    components = process_macos_bundle_file(deps, deep_mode=False, f=str(app), sbom=sbom)
    purls = {c.purl for c in components}
    assert any(p.startswith("pkg:macos/com.example.demo@2.0.0?") for p in purls)
    assert any(p.startswith("pkg:macos/com.example.widget@") for p in purls)
    # Every component purl is pkg:macos, never pkg:ios, and carries the
    # bundle-relative path qualifier that keeps members unique.
    assert all(p.startswith("pkg:macos/") for p in purls)
    parent_names = [c.name for c in sbom.metadata.component.components]
    assert "com.example.demo" in parent_names
    assert deps  # parent -> member dependency edges recorded


def test_enrich_with_bundle_context_writes_macos_block():
    metadata = {"name": "Demo", "file_path": "Demo", "informative_strings": []}
    enriched = enrich_with_bundle_context(
        metadata,
        {"bundle_identifier": "com.example.demo", "bundle_version": "2.0.0"},
        "main",
        "Contents/MacOS/Demo",
        context_key="macos_bundle",
    )
    assert enriched["macos_bundle"]["role"] == "main"
    assert enriched["macos_bundle"]["bundle_path"] == "Contents/MacOS/Demo"
    assert "executable" not in enriched["macos_bundle"]
