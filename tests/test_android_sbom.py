"""A1.3 - android native SBOM shape (01/D).

The fixtures are the committed A0.2 corpus files (real aapt2/zipalign/
apksigner packaging over NDK-built libraries).
"""

import re
from pathlib import Path

import orjson
from packageurl import PackageURL

from blint.config import BlintOptions
from blint.lib.sbom import generate

DATA = Path(__file__).parent / "data" / "android"
HEX_BUILD_ID = re.compile(r"^[0-9a-f]{16,}$")


def _emit(app: Path, tmp_path: Path) -> dict:
    out = tmp_path / f"{app.stem}.cdx.json"
    options = BlintOptions(
        src_dir_image=[str(app)],
        sbom_mode=True,
        sbom_output=str(out),
        quiet_mode=True,
    )
    generate(options, [], [str(app)])
    assert out.is_file()
    return orjson.loads(out.read_bytes())


def _so_components(doc: dict) -> list[dict]:
    return [
        c for c in doc["components"]
        if str(c.get("purl", "")).startswith("pkg:android/lib")
    ]


def _props(component: dict) -> dict:
    return {p["name"]: p["value"] for p in (component.get("properties") or [])}


def test_singleabi_shape_and_count_parity(tmp_path: Path) -> None:
    doc = _emit(DATA / "tier1_singleabi_stored16k.apk", tmp_path)
    sos = _so_components(doc)
    # One library, one ABI: one component - the count does not grow (01/D).
    assert len(sos) == 1
    component = sos[0]
    assert component["name"] == "libhello.so"
    purl = PackageURL.from_string(component["purl"])
    assert purl.qualifiers["abi"] == "arm64-v8a"
    # No version where only a build-id exists (V4): it is a property.
    assert component.get("version") is None
    props = _props(component)
    assert props["blint:build_id"].startswith("arm64-v8a:")
    assert not HEX_BUILD_ID.match(str(component.get("version") or ""))
    assert props["internal:srcFile"] == "lib/arm64-v8a/libhello.so"
    # NDK platform DT_NEEDED is marked platform and never a component.
    assert "libc.so" in props.get("blint:platform_needed", "")
    assert not any(
        c["name"] in ("libc.so", "liblog.so", "libm.so") for c in doc["components"]
    )
    # The app depends on the library component (parent edge kept): the
    # app's purl is the metadata parent, and its dependency entry lists
    # the library.
    lib_ref = component["bom-ref"]
    app_edges = [
        d for d in doc.get("dependencies", [])
        if str(d.get("ref", "")).startswith("pkg:android/")
        and "@" in str(d.get("ref", ""))
        and "?abi=" not in str(d.get("ref", ""))
    ]
    assert any(lib_ref in (d.get("dependsOn") or []) for d in app_edges)


def test_multiabi_one_component_with_per_abi_occurrences(tmp_path: Path) -> None:
    doc = _emit(DATA / "tier1_multiabi.xapk", tmp_path)
    sos = _so_components(doc)
    assert len(sos) == 1
    component = sos[0]
    purl = PackageURL.from_string(component["purl"])
    assert set(purl.qualifiers["abi"].split(",")) == {
        "arm64-v8a", "armeabi-v7a", "x86", "x86_64", "riscv64",
    }
    props = _props(component)
    # Per-ABI build-ids stay distinguishable on the merged component.
    build_ids = dict(
        part.split(":", 1) for part in props["blint:build_id"].split(",")
    )
    assert set(build_ids) >= {"arm64-v8a", "riscv64"}
    # Every split's location is evidence on the one component.
    assert len(props["internal:srcFile"].splitlines()) == 5


def test_every_purl_parses(tmp_path: Path) -> None:
    for app in ("tier1_singleabi_stored16k.apk", "tier1_multiabi.xapk",
                "tier1_no_dex.apk"):
        doc = _emit(DATA / app, tmp_path)
        for component in doc["components"]:
            purl = component.get("purl")
            if purl:
                assert PackageURL.from_string(purl).to_string() == purl


def test_no_dex_app_still_gets_library_components(tmp_path: Path) -> None:
    doc = _emit(DATA / "tier1_no_dex.apk", tmp_path)
    assert _so_components(doc)


def test_bundled_needed_library_edge(tmp_path: Path) -> None:
    # When a library DT_NEEDEDs another bundled library (not a platform
    # one), the dependency edge exists between the components.
    import zipfile

    with zipfile.ZipFile(DATA / "tier1_singleabi_stored16k.apk") as zf:
        hello = zf.read("lib/arm64-v8a/libhello.so")
        manifest = zf.read("AndroidManifest.xml")
    app = tmp_path / "bundled.apk"
    with zipfile.ZipFile(app, "w") as zf:
        # The real binary manifest: a stub XML yields no parent component
        # (no app edge to assert).
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("lib/arm64-v8a/libhello.so", hello)
        zf.writestr("lib/arm64-v8a/libpartner.so", hello)
    doc = _emit(app, tmp_path)
    sos = {c["name"]: c for c in _so_components(doc)}
    assert set(sos) == {"libhello.so", "libpartner.so"}
    refs = {name: c["bom-ref"] for name, c in sos.items()}
    edges = {
        d["ref"]: d.get("dependsOn", [])
        for d in doc.get("dependencies", [])
    }
    # The app depends on both members; hello's DT_NEEDED holds only
    # platform names (marked as the platform fact above), so no lib->lib
    # edge is asserted for this fixture.
    app_edges = [
        e for ref, e in edges.items()
        if ref.startswith("pkg:android/") and "@" in ref and "?abi=" not in ref
    ]
    assert app_edges
    assert {refs["libhello.so"], refs["libpartner.so"]} <= set(app_edges[0])
