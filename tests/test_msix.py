"""Tests for the MSIX/Appx container reader (W4.1).

Ground rule 10: every format variant gets a fixture that reaches it —
plain package, bundle of nested packages, manifest-less archive, malformed
manifest, hostile member paths, oversized packages. Ground rule 18: the
temp-directory count delta is asserted across success and across every
failure path, not read from the code. The real-artifact tests (rules 22/29)
run against the Windows Terminal ``.msixbundle`` in the corpus and are
skipped where the corpus is absent.
"""

import glob
import json
import os
import shutil
import tempfile
import zipfile

import pytest

from blint.lib.msix import (
    collect_msix_detailed,
    container_metadata,
    enrich_member_metadata,
    is_msix_file,
    parse_signature_p7x,
)

_DATA = os.path.join(os.path.dirname(__file__), "data")
_PE_MEMBER = os.path.join(_DATA, "pe", "msvc-hello-x64.exe")
_CORPUS_BUNDLE = os.path.expanduser(
    "~/sandbox/pe-corpus/tier3-packaged/WindowsTerminal.msixbundle"
)

MANIFEST_TEMPLATE = """<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
         xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities">
  <Identity Name="Acme.Demo" Publisher="CN=Acme, O=Acme" Version="1.2.3.0" ProcessorArchitecture="x64" />
  <Properties>
    <DisplayName>Demo</DisplayName>
    <PublisherDisplayName>Acme</PublisherDisplayName>
  </Properties>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.19041.0" MaxVersionTested="10.0.22621.0" />
  </Dependencies>
  <Capabilities>
    <Capability Name="internetClient" />
    <rescap:Capability Name="runFullTrust" />
  </Capabilities>
  <Applications>
    <Application Id="App" Executable="demo.exe" EntryPoint="Acme.Demo.App" />
  </Applications>
</Package>
"""

BUNDLE_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<Bundle SchemaVersion="5.0" xmlns="http://schemas.microsoft.com/appx/2013/bundle">
  <Identity Name="Acme.Bundle" Publisher="CN=Acme, O=Acme" Version="1.2.3.0" />
  <Packages>
    <Package Type="application" Version="1.2.3.0" Architecture="x64" FileName="pkg-x64.msix" Offset="69" Size="0" />
    <Package Type="application" Version="1.2.3.0" Architecture="arm64" FileName="pkg-arm64.msix" Offset="70" Size="0" />
  </Packages>
</Bundle>
"""


def _live_msix_temp_dirs() -> set[str]:
    return set(glob.glob(os.path.join(tempfile.gettempdir(), "blint_msix_*")))


def _build_package(path, manifest=MANIFEST_TEMPLATE, extra_members=None, member_name="demo.exe"):
    with zipfile.ZipFile(path, "w") as zf:
        if manifest is not None:
            zf.writestr("AppxManifest.xml", manifest)
        if member_name:
            with open(_PE_MEMBER, "rb") as pe:
                zf.writestr(member_name, pe.read())
        for name, data in (extra_members or {}).items():
            zf.writestr(name, data)
    return str(path)


def _build_bundle(path, packages, bundle_manifest=BUNDLE_MANIFEST):
    """packages: list of (archive_name, {member_name: bytes_or_path_marker})."""
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AppxMetadata/AppxBundleManifest.xml", bundle_manifest)
        for archive_name, members in packages:
            with tempfile.NamedTemporaryFile(suffix=".msix", delete=False) as buf:
                buf_name = buf.name
            _build_package(buf_name, extra_members=members)
            zf.write(buf_name, arcname=archive_name)
            os.unlink(buf_name)
    return str(path)


def test_is_msix_file_extension_routing():
    assert is_msix_file("x.msix") and is_msix_file("X.APPX")
    assert is_msix_file("x.msixbundle") and is_msix_file("x.appxbundle")
    assert not is_msix_file("x.zip") and not is_msix_file("x.exe")


def test_plain_package_collects_facts_and_members(tmp_path):
    package = _build_package(tmp_path / "plain.msix")
    collection, reason = collect_msix_detailed(package)
    assert reason is None
    try:
        assert collection["kind"] == "msix"
        identity = collection["identity"]
        assert identity["identity"]["name"] == "Acme.Demo"
        assert identity["identity"]["version"] == "1.2.3.0"
        assert identity["identity"]["publisher"] == "CN=Acme, O=Acme"
        assert identity["capabilities"]["general"] == ["internetClient"]
        assert identity["capabilities"]["restricted"] == ["runFullTrust"]
        assert identity["target_device_families"][0]["name"] == "Windows.Desktop"
        assert identity["applications"][0]["executable"] == "demo.exe"
        assert len(collection["binaries"]) == 1
        member = collection["binaries"][0]
        assert member["member_path"] == "demo.exe"
        assert member["container_path"] == "demo.exe"
        assert os.path.isfile(member["path"])
    finally:
        shutil.rmtree(collection["temp_dir"], ignore_errors=True)


def test_bundle_collects_nested_packages_and_attributes_members(tmp_path):
    bundle = _build_bundle(
        tmp_path / "b.msixbundle",
        [
            ("pkg-x64.msix", {"readme.txt": b"hello"}),
            ("pkg-arm64.msix", {}),
        ],
    )
    collection, reason = collect_msix_detailed(bundle)
    assert reason is None
    try:
        assert collection["kind"] == "msixbundle"
        assert collection["identity"]["identity"]["name"] == "Acme.Bundle"
        assert len(collection["packages"]) == 2
        paths = {b["container_path"] for b in collection["binaries"]}
        assert paths == {"pkg-x64.msix/demo.exe", "pkg-arm64.msix/demo.exe"}
        # Each member carries its own package identity, not the bundle's.
        for entry in collection["binaries"]:
            context = enrich_member_metadata({}, collection, entry)
            assert context["container"]["package_identity"]["name"] == "Acme.Demo"
            assert context["container"]["member_path"] == entry["container_path"]
    finally:
        shutil.rmtree(collection["temp_dir"], ignore_errors=True)


def test_bundle_with_corrupt_package_isolates_the_failure(tmp_path):
    with zipfile.ZipFile(tmp_path / "b2.msixbundle", "w") as zf:
        zf.writestr("AppxMetadata/AppxBundleManifest.xml", BUNDLE_MANIFEST)
        zf.writestr("pkg-x64.msix", b"PK\x03\x04" + b"\x00" * 64)
        with tempfile.NamedTemporaryFile(suffix=".msix", delete=False) as buf:
            buf_name = buf.name
        _build_package(buf_name)
        zf.write(buf_name, arcname="pkg-arm64.msix")
        os.unlink(buf_name)
    collection, reason = collect_msix_detailed(str(tmp_path / "b2.msixbundle"))
    assert reason is None
    try:
        # The corrupt package refused by name; the healthy one still walked.
        assert "nested_package_unreadable" in collection["refusals"]
        assert len(collection["packages"]) == 1
        assert collection["packages"][0]["container_path"] == "pkg-arm64.msix"
    finally:
        shutil.rmtree(collection["temp_dir"], ignore_errors=True)


def test_package_without_manifest_refused_by_name(tmp_path):
    package = _build_package(tmp_path / "nomanifest.msix", manifest=None)
    collection, reason = collect_msix_detailed(package)
    assert reason is None
    shutil.rmtree(collection["temp_dir"], ignore_errors=True)
    assert "appx_manifest_missing" in collection["refusals"]
    # The container metadata still states the refusal (rule 32) rather than
    # reading as a package with no facts.
    metadata = container_metadata(collection, package)
    assert "appx_manifest_missing" in metadata["container"]["refusals"]


def test_malformed_manifest_refused_by_name(tmp_path):
    package = _build_package(tmp_path / "badxml.msix", manifest="<Package><Identity")
    collection, reason = collect_msix_detailed(package)
    assert reason is None
    shutil.rmtree(collection["temp_dir"], ignore_errors=True)
    assert "manifest_xml_malformed" in collection["refusals"]


def test_unsafe_member_path_in_package_refused(tmp_path):
    package = _build_package(
        tmp_path / "evil.msix",
        extra_members={"../evil.dll": b"MZ\x00\x00", "C:/abs/evil.dll": b"MZ\x00\x00"},
    )
    collection, reason = collect_msix_detailed(package)
    assert reason is None
    shutil.rmtree(collection["temp_dir"], ignore_errors=True)
    assert collection["refusals"].count("member_path_unsafe") == 2
    assert len(collection["binaries"]) == 1


def test_symlink_member_refused(tmp_path):
    package_path = tmp_path / "linky.msix"
    with zipfile.ZipFile(package_path, "w") as zf:
        zf.writestr("AppxManifest.xml", MANIFEST_TEMPLATE)
        info = zipfile.ZipInfo("sneaky.dll")
        info.external_attr = 0o120777 << 16
        zf.writestr(info, b"MZ\x00\x00")
    collection, reason = collect_msix_detailed(str(package_path))
    assert reason is None
    shutil.rmtree(collection["temp_dir"], ignore_errors=True)
    assert "member_is_symlink" in collection["refusals"]


def test_oversized_nested_package_refused(tmp_path):
    """Ground rule 33: the cap has a fixture that exceeds it. A nested
    package past the declared-size cap is refused by the walk before a byte
    is decompressed, and the manifest-listed package that never extracted is
    named too."""
    from blint.lib.msix import MAX_NESTED_PACKAGE_SIZE

    with zipfile.ZipFile(tmp_path / "huge.msixbundle", "w") as zf:
        zf.writestr("AppxMetadata/AppxBundleManifest.xml", BUNDLE_MANIFEST)
        # Stated size exceeds the cap without writing the bytes: the walk
        # bounds on the declared central-directory size.
        zf.writestr("pkg-x64.msix", b"PK\x03\x04" + b"\x00" * 16)
        for info in zf.infolist():
            if info.filename == "pkg-x64.msix":
                info.file_size = MAX_NESTED_PACKAGE_SIZE + 1
    collection, reason = collect_msix_detailed(str(tmp_path / "huge.msixbundle"))
    assert reason is None
    try:
        assert "member_size_exceeds_cap" in collection["refusals"]
        assert "nested_package_unreadable" in collection["refusals"]
        assert collection["packages"] == []
    finally:
        shutil.rmtree(collection["temp_dir"], ignore_errors=True)


def test_blockmap_mismatch_recorded(tmp_path):
    """A member whose bytes no longer match its block map is a recorded
    mismatch, never a silent pass."""
    blockmap = """<?xml version="1.0" encoding="utf-8"?>
<BlockMap HashMethod="http://www.w3.org/2000/09/xmldsig#sha256">
  <Block Size="65536">
    <File LfSize="100" LfHash="abc=" Name="demo.exe">
      <Block Hash="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" Size="100" />
    </File>
  </Block>
</BlockMap>
"""
    package = _build_package(tmp_path / "tampered.msix", extra_members={"AppxBlockMap.xml": blockmap})
    collection, reason = collect_msix_detailed(package)
    assert reason is None
    shutil.rmtree(collection["temp_dir"], ignore_errors=True)
    verification = collection["blockmap_verification"]
    assert verification["verified_files"] == 1
    # Two ways the file disagrees with its map: the declared block's hash
    # does not match, and the file has data beyond the declared blocks.
    assert verification["mismatches"] == [
        {"member": "demo.exe", "mismatched_blocks": 2}
    ]


def test_container_metadata_shape_and_exe_type(tmp_path):
    package = _build_package(tmp_path / "meta.msix")
    collection, reason = collect_msix_detailed(package)
    assert reason is None
    shutil.rmtree(collection["temp_dir"], ignore_errors=True)
    metadata = container_metadata(collection, "/tmp/meta.msix")
    assert metadata["exe_type"] == "msix"
    container = metadata["container"]
    assert container["kind"] == "msix"
    assert container["restricted_capability_count"] == 1
    assert container["member_binary_count"] == 1
    assert container["refusals"] == []
    assert container["identities"][0]["identity"]["name"] == "Acme.Demo"


def test_leak_delta_across_success_and_failures(tmp_path):
    """Ground rule 18 asserted, not read: zero live blint_msix_ directories
    beyond the one the caller still owns, after every path."""
    before = _live_msix_temp_dirs()

    # Success path: collection returned, caller cleans up.
    good = _build_package(tmp_path / "good.msix")
    collection, reason = collect_msix_detailed(good)
    assert reason is None
    shutil.rmtree(collection["temp_dir"], ignore_errors=True)

    # Failing-member path: a bundle with a corrupt nested package.
    bad_member = tmp_path / "badmember.msixbundle"
    with zipfile.ZipFile(bad_member, "w") as zf:
        zf.writestr("AppxMetadata/AppxBundleManifest.xml", BUNDLE_MANIFEST)
        zf.writestr("pkg-x64.msix", b"garbage-not-a-zip")
    collection, reason = collect_msix_detailed(str(bad_member))
    assert reason is None
    shutil.rmtree(collection["temp_dir"], ignore_errors=True)

    # Malformed-archive path.
    corrupt = tmp_path / "corrupt.msix"
    corrupt.write_bytes(b"PK\x03\x04" + b"\x00" * 64)
    assert collect_msix_detailed(str(corrupt))[1] == "archive_unreadable"

    # Cap-refusal path: the bundle whose nested package is past the cap.
    from blint.lib.msix import MAX_NESTED_PACKAGE_SIZE

    with zipfile.ZipFile(tmp_path / "cap.msixbundle", "w") as zf:
        zf.writestr("AppxMetadata/AppxBundleManifest.xml", BUNDLE_MANIFEST)
        zf.writestr("pkg-x64.msix", b"PK\x03\x04" + b"\x00" * 16)
        for info in zf.infolist():
            if info.filename == "pkg-x64.msix":
                info.file_size = MAX_NESTED_PACKAGE_SIZE + 1
    collection, reason = collect_msix_detailed(str(tmp_path / "cap.msixbundle"))
    assert reason is None
    assert collection["packages"] == []
    shutil.rmtree(collection["temp_dir"], ignore_errors=True)

    after = _live_msix_temp_dirs()
    assert after - before == set()


def test_parse_signature_p7x_rejects_non_p7x_bytes():
    assert parse_signature_p7x(b"NOTPKCX") is None


def test_sbom_process_msix_file(tmp_path):
    """The BOM carries the package as parent (manifest identity, not
    filename), members keyed by container path, and refusals as a property
    (rule 32)."""
    from blint.lib.sbom import _scratch_sbom, process_msix_file

    package = _build_package(tmp_path / "sbom.msix")
    scratch = _scratch_sbom()
    deps: dict = {}
    components = process_msix_file(deps, package, scratch)
    parent = scratch.metadata.component.components[0]
    assert parent.purl == "pkg:appx/Acme.Demo@1.2.3.0"
    assert parent.name == "Acme.Demo"
    assert any(p.name == "internal:version_source" for p in parent.properties)
    assert len(components) == 1
    member = components[0]
    assert member.purl == "pkg:file/demo.exe?path=demo.exe"
    assert member.name == "demo.exe"
    assert member.hashes and member.hashes[0].alg.value == "SHA-256"
    # parent depends on the member
    parent_ref = str(parent.bom_ref.root)
    assert deps[parent_ref]


def test_sbom_process_msix_file_refusal_reaches_the_bom(tmp_path):
    from blint.lib.sbom import _scratch_sbom, process_msix_file

    corrupt = tmp_path / "corrupt.msix"
    corrupt.write_bytes(b"PK\x03\x04" + b"\x00" * 64)
    scratch = _scratch_sbom()
    components = process_msix_file({}, str(corrupt), scratch)
    assert components == []
    parent = scratch.metadata.component.components[0]
    refusal = [p for p in parent.properties if p.name == "internal:container_refusal"]
    assert refusal and refusal[0].value == "archive_unreadable"


def _corpus_bundle():
    return _CORPUS_BUNDLE if os.path.isfile(_CORPUS_BUNDLE) else None


@pytest.mark.skipif(_corpus_bundle() is None, reason="corpus tier3 not present")
def test_real_windows_terminal_bundle_ground_truth():
    """Rules 22/29: the real Store bundle. The facts asserted here were
    cross-checked against the Windows 11 VM's MakeAppx unpack and
    Get-AppxPackage (see the packet's gate block)."""
    collection, reason = collect_msix_detailed(_corpus_bundle())
    assert reason is None
    try:
        assert collection["kind"] == "msixbundle"
        assert collection["identity"]["identity"]["name"] == "Microsoft.WindowsTerminal"
        assert len(collection["packages"]) == 3
        assert {p["container_path"].split("_")[-1] for p in collection["packages"]} == {
            "x64.msix",
            "x86.msix",
            "ARM64.msix",
        }
        assert len(collection["binaries"]) == 45
        assert collection["signature"]["signer_cn"] == "Microsoft Corporation"
        restricted = set()
        verified = 0
        for package in collection["packages"]:
            restricted |= set(package["identity"]["capabilities"]["restricted"])
            verified += package["blockmap_verification"]["verified_files"]
        assert restricted == {"runFullTrust", "unvirtualizedResources"}
        assert verified > 0
        assert all(
            package["blockmap_verification"]["mismatches"] == []
            for package in collection["packages"]
        )
    finally:
        shutil.rmtree(collection["temp_dir"], ignore_errors=True)


@pytest.mark.skipif(_corpus_bundle() is None, reason="corpus tier3 not present")
def test_real_bundle_metadata_exports_and_container_findings(tmp_path):
    from blint.config import BlintOptions
    from blint.lib.runners import run_default_mode

    reports = os.path.join(str(tmp_path), "reports")
    options = BlintOptions(
        src_dir_image=[_corpus_bundle()],
        reports_dir=reports,
        no_reviews=True,
        quiet_mode=True,
    )
    run_default_mode(options)
    with open(os.path.join(reports, "analysis-coverage.json")) as handle:
        coverage = json.load(handle)
    assert coverage["units"] == {
        "attempted": 49,
        "succeeded": 49,
        "failed": 0,
        "skipped": 0,
    }
    assert coverage["units_by_role"]["top-level"] == {
        "attempted": 1,
        "succeeded": 1,
        "failed": 0,
        "skipped": 0,
    }
    assert coverage["units_by_role"]["msix-package"] == {
        "attempted": 3,
        "succeeded": 3,
        "failed": 0,
        "skipped": 0,
    }
    assert coverage["units_by_role"]["msix-member"] == {
        "attempted": 45,
        "succeeded": 45,
        "failed": 0,
        "skipped": 0,
    }
    # Container metadata exported, and member findings attributed to the
    # member path inside the package.
    assert os.path.isfile(os.path.join(reports, "WindowsTerminal.msixbundle-metadata.json"))
    member_report = os.path.join(reports, "wt.exe-metadata.json")
    assert os.path.isfile(member_report)
    with open(member_report) as handle:
        member_metadata = json.load(handle)
    assert (
        member_metadata["container"]["member_path"]
        == "CascadiaPackage_1.22.12111.0_ARM64.msix/wt.exe"
    )
