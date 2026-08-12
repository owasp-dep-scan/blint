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
