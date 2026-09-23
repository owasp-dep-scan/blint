"""Tests for purl construction from binary metadata.

Binary metadata is not all strings. LIEF reports an ELF symbol version auxiliary
``hash`` as an int, and PackageURL normalizes versions and qualifier values by
calling ``strip()`` on them, so unconverted values raise AttributeError. The
f-string purl construction these call sites used previously tolerated any type.
"""

from packageurl import PackageURL

from blint.lib.sbom import (
    create_library_component,
    default_parent,
    purl_field,
)


def test_purl_field_coerces_numbers_and_drops_empty_values():
    assert purl_field(3735928559) == "3735928559"
    assert purl_field("1.0.0") == "1.0.0"
    assert purl_field("  1.0.0  ") == "1.0.0"
    assert purl_field(None) is None
    assert purl_field("") is None
    assert purl_field("   ") is None
    # Booleans are never meaningful purl values.
    assert purl_field(True) is None


# F2a.4: the ELF symbol-version nodes are no longer emitted as components
# (an interface floor is a requirement on the execution environment, not an
# artifact identity); the raw node names ride the parent component as the
# internal:symbols_version property, so the purl-coercion concerns those
# tests covered apply to create_library_component and stay covered there.


def test_create_library_component_accepts_numeric_versions():
    """Regression: numeric dylib versions crashed purl construction."""
    component = create_library_component(
        {"name": "/usr/lib/libSystem.B.dylib", "version": 1356, "compatibility_version": 1},
        "/bin/ls",
    )
    assert "compatibility_version=1" in component.purl
    assert PackageURL.from_string(component.purl).version == "1356"


def test_create_library_component_tolerates_missing_versions():
    component = create_library_component({"name": "/usr/lib/libutil.dylib"}, "/bin/ls")
    assert component.purl.startswith("pkg:file/libutil.dylib")
    assert PackageURL.from_string(component.purl).version is None


def test_default_parent_still_finds_a_build_bom_identity_for_a_dll():
    """W3.5 stopped a `.dll` filename from producing a `pkg:nuget` purl,
    which is right — but the build-BOM overlay was keyed on that same purl.

    `populate_purl_lookup` stores unversioned `pkg:nuget/<name>` keys only,
    so once the computed purl became `pkg:generic/<name>` the lookup could
    never hit for any input, and a `--src-dir-boms` run silently stopped
    upgrading the parent component it used to upgrade. A BOM naming the
    package is evidence, unlike the filename, so the hit is still allowed
    to yield a NuGet purl.
    """
    overlay = {"pkg:nuget/Newtonsoft.Json": "pkg:nuget/Newtonsoft.Json@13.0.3"}
    component = default_parent(["/tmp/Newtonsoft.Json.dll"], overlay)
    assert component.purl == "pkg:nuget/Newtonsoft.Json@13.0.3"
    assert component.version.root == "13.0.3"

    # Without a BOM entry the filename proves nothing, which is the whole
    # point of the W3.5 correction: no `pkg:nuget` from a name alone.
    assert default_parent(["/tmp/python313.dll"]).purl == "pkg:generic/python313"


def test_nupkg_identity_purls_escape_reserved_characters(tmp_path):
    """A nuspec is untrusted XML inside an untrusted archive.

    The id and version go straight into the component purl and bom-ref, so
    they are built through PackageURL rather than an f-string — a space or
    a `?` in either would otherwise emit a purl that does not round-trip.
    """
    import zipfile

    from blint.lib.sbom import _scratch_sbom, process_nupkg_file

    nuspec = (
        b"<?xml version='1.0'?><package><metadata>"
        b"<id>Weird Id?</id><version>1.0 beta</version>"
        b"<dependencies><dependency id='Dep Name' version='[2.0 rc]' /></dependencies>"
        b"</metadata></package>"
    )
    target = tmp_path / "weird.nupkg"
    with zipfile.ZipFile(target, "w") as zf:
        zf.writestr("weird.nuspec", nuspec)

    scratch = _scratch_sbom()
    deps: dict = {}
    components = process_nupkg_file(deps, str(target), scratch)

    parent = scratch.metadata.component.components[0]
    assert parent.purl == "pkg:nuget/Weird%20Id%3F@1.0%20beta"
    assert parent.bom_ref.root == parent.purl
    assert components[0].purl == "pkg:nuget/Dep%20Name@2.0%20rc"
    assert components[0].bom_ref.root == components[0].purl


def test_original_filename_identity_upgrade():
    """W4.5: a PE whose VERSIONINFO states an OriginalFilename names the
    component from the resource, with the on-disk name carried as evidence
    when it differs (ground rule 32: the mismatch is visible)."""

    from blint.lib.sbom import (
        add_signer_evidence,
        upgrade_parent_to_original_filename,
    )

    metadata = {
        "file_path": "/scan/renamed-tool.exe",
        "name": "renamed-tool.exe",
        "version_info": {
            "strings": {
                "000004b0": {
                    "OriginalFilename": "actual-tool.exe",
                    "ProductName": "Actual Tool",
                }
            }
        },
        "code_signature": {
            "parse_status": "parsed",
            "signing_class": "commercial_ov",
            "signatures": [{"signer": {"cn": "Acme Corp"}}],
        },
    }
    parent = default_parent(["/scan/renamed-tool.exe"])
    upgrade_parent_to_original_filename(parent, metadata, None)
    add_signer_evidence(parent, metadata)
    assert parent.name == "actual-tool"
    names = {p.name: p.value for p in parent.properties}
    assert names["internal:filename_original"] == "actual-tool.exe"
    assert names["internal:filename_on_disk"] == "renamed-tool.exe"
    assert names["internal:version_source"] == "version_info"
    assert names["internal:signer_cn"] == "Acme Corp"
    assert names["internal:signing_class"] == "commercial_ov"
    # The purl stays generic: a resource name is not a package id.
    assert parent.purl == "pkg:generic/actual-tool"


def test_original_filename_overlay_reaches_both_names():
    """The W3.5 coupling lesson: the overlay lookup must be re-keyed under
    the resource stem, or renaming the component makes the build-BOM
    overlay unreachable."""

    from blint.lib.sbom import upgrade_parent_to_original_filename

    metadata = {
        "file_path": "/scan/vendor.dll",
        "name": "vendor.dll",
        "version_info": {"strings": {"0": {"OriginalFilename": "real.dll"}}},
    }
    overlay = {
        "pkg:nuget/real": "pkg:nuget/real@2.5.0",
        "pkg:generic/real": "pkg:generic/real@2.5.0",
    }
    parent = default_parent(["/scan/vendor.dll"], overlay)
    upgrade_parent_to_original_filename(parent, metadata, overlay)
    assert parent.purl == "pkg:nuget/real@2.5.0"
    assert parent.name == "real"
    assert parent.version.root == "2.5.0"


def test_original_filename_absent_keeps_filename():
    from blint.lib.sbom import upgrade_parent_to_original_filename

    metadata = {"file_path": "/scan/tool.exe", "name": "tool.exe"}
    parent = default_parent(["/scan/tool.exe"])
    upgrade_parent_to_original_filename(parent, metadata, None)
    assert parent.name == "tool.exe"
    assert not [p for p in (parent.properties or []) if p.name == "internal:filename_original"]
