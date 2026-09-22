"""Tests for purl construction from binary metadata.

Binary metadata is not all strings. LIEF reports an ELF symbol version auxiliary
``hash`` as an int, and PackageURL normalizes versions and qualifier values by
calling ``strip()`` on them, so unconverted values raise AttributeError. The
f-string purl construction these call sites used previously tolerated any type.
"""

from packageurl import PackageURL

from blint.lib.sbom import (
    components_from_symbols_version,
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


def test_components_from_symbols_version_accepts_integer_hash():
    """Regression: an int hash crashed SBOM generation for ELF binaries."""
    components = components_from_symbols_version(
        [{"name": "GLIBC_2.34", "hash": 157882997, "value": 0}]
    )
    assert len(components) == 1
    purl = components[0].purl
    assert "hash=157882997" in purl
    # The purl must remain parseable after coercion.
    assert PackageURL.from_string(purl).qualifiers["hash"] == "157882997"


def test_components_from_symbols_version_omits_absent_hash():
    components = components_from_symbols_version([{"name": "GLIBC_2.34", "value": 0}])
    assert "hash=" not in components[0].purl


def test_components_from_symbols_version_escapes_reserved_characters():
    """The behaviour the PackageURL switch was made for must still hold."""
    components = components_from_symbols_version(
        [{"name": "lib with space+plus", "hash": "abc", "value": 0}]
    )
    purl = components[0].purl
    assert " " not in purl
    assert PackageURL.from_string(purl).name == "lib with space+plus"


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
