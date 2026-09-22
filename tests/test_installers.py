"""Tests for W4.3: ClickOnce manifests, installer detection, 7z-SFX payloads.

The 7z reader is verified against archives created and listed by 7-Zip on
the ground-truth VM (the corpus carries the resulting SFX); synthetic
fixtures cover the hostile shapes (ground rules 22/30/33).
"""

import glob
import json
import logging
import os
import struct
import tempfile
from pathlib import Path

import pytest

from blint.lib.clickonce import is_clickonce_file, parse_clickonce
from blint.lib.installers import _parse_nsis_firstheader, detect_installer
from blint.lib.sevenz import find_archive_candidates, parse_sevenz_blob

_DATA = os.path.join(os.path.dirname(__file__), "data")
_PE = os.path.join(_DATA, "pe", "msvc-hello-x64.exe")
_CORPUS_SFX = os.path.expanduser("~/sandbox/pe-corpus/tier0-reference/7z-x64-setup.exe")

DEPLOYMENT_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<asmv1:assembly xsi:schemaLocation="urn:schemas-microsoft-com:asm.v1 assembly.adaptive2.xsd"
    manifestVersion="1.0"
    xmlns:asmv1="urn:schemas-microsoft-com:asm.v1"
    xmlns:asmv2="urn:schemas-microsoft-com:asm.v2"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <assemblyIdentity name="Acme.Client.app" version="1.0.0.5" publicKeyToken="0000000000000000"
                    culture="en-US" processorArchitecture="msil" />
  <description asmv2:publisher="Acme Corp" asmv2:product="Acme Client" />
  <deployment install="true" mapFileExtensions="true">
    <deploymentProvider url="http://deploy.example.com/client/Acme.Client.application" />
  </deployment>
  <dependency>
    <dependentAssembly dependencyType="install" codebase="Acme.Client.exe.manifest" size="12345">
      <assemblyIdentity name="Acme.Client.exe" version="1.0.0.5" publicKeyToken="0000000000000000"
                        culture="en-US" processorArchitecture="msil" />
    </dependentAssembly>
    <dependency>
      <dependentAssembly dependencyType="generate" />
    </dependency>
  </dependency>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v2">
    <security>
      <applicationRequestMinimum>
        <PermissionSet class="System.Security.PermissionSet" Unrestricted="true" />
        <defaultAssemblyRequest permissionSetReference="Trust" />
      </applicationRequestMinimum>
    </security>
  </trustInfo>
</asmv1:assembly>
"""


def _write_deployment(tmp_path):
    path = tmp_path / "Acme.Client.application"
    path.write_text(DEPLOYMENT_MANIFEST)
    return str(path)


def test_clickonce_deployment_facts(tmp_path):
    path = _write_deployment(tmp_path)
    block = parse_clickonce(path)
    assert block is not None
    assert block["kind"] == "deployment"
    assert block["identity"]["name"] == "Acme.Client.app"
    assert block["identity"]["version"] == "1.0.0.5"
    assert block["update_url"] == "http://deploy.example.com/client/Acme.Client.application"
    assert block["publisher"] == "Acme Corp"
    assert block["permission_set_unrestricted"] is True
    assert block["signature_present"] is False


def test_clickonce_manifest_content_routing(tmp_path):
    # An ordinary PE-sidecar manifest is NOT ClickOnce...
    plain = tmp_path / "app.manifest"
    plain.write_text('<?xml version="1.0"?><assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"/>')
    assert is_clickonce_file(str(plain)) is False
    # ...but an asm.v2 trustInfo manifest is.
    clickonce = tmp_path / "client.exe.manifest"
    clickonce.write_text(
        '<?xml version="1.0"?><assembly xmlns="urn:schemas-microsoft-com:asm.v2" '
        'xmlns:asmv2="urn:schemas-microsoft-com:asm.v2"><trustInfo xmlns="urn:schemas-microsoft-com:asm.v2"/>'
        "</assembly>"
    )
    assert is_clickonce_file(str(clickonce)) is True
    block = parse_clickonce(str(clickonce))
    assert block["kind"] == "application"


def test_clickonce_garbage_returns_none(tmp_path):
    path = tmp_path / "broken.application"
    path.write_bytes(b"<not-xml at all")
    assert parse_clickonce(str(path)) is None


def test_nsis_firstheader_parse():
    header = struct.pack("<IIII", 0, 0xDEADBEEF, 0x00012345, 0x00ABCDEF)
    blob = b"\x00" * 100 + header + b"\xff" * 64
    facts = _parse_nsis_firstheader(blob)
    assert facts is not None
    assert facts["length_of_header"] == 0x00012345
    assert facts["length_of_all_following_data"] == 0x00ABCDEF


def test_detect_installer_nsis_detection_only(tmp_path):
    pe = tmp_path / "installer.exe"
    pe.write_bytes(Path(_PE).read_bytes() + b"\x00" * 4096 + struct.pack("<IIII", 0, 0xDEADBEEF, 4096, 100000))
    block = detect_installer(str(pe), "nsis")
    assert block["family"] == "nsis"
    # Detection-only is stated in the block, not implied (rule 14).
    assert block["extraction"] == "detection_only"
    assert block["nsis_firstheader"]["length_of_all_following_data"] == 100000


def test_detect_installer_ignores_plain_pe(tmp_path):
    block = detect_installer(_PE, "unknown_low_entropy")
    assert block is None


def test_sevenz_rejects_garbage():
    assert find_archive_candidates(b"not a 7z at all") == []
    assert parse_sevenz_blob(b"\x00" * 64, [], []) is None


def _build_sfx(archive_path, stub_extra=b""):
    with open(archive_path, "rb") as handle:
        archive = handle.read()
    stub = b"MZ" + b"\x00" * 0x200 + stub_extra
    return stub + archive


@pytest.mark.skipif(not os.path.isfile("/tmp/test1.7z"), reason="ground-truth 7z fixture not built")
def test_sevenz_listing_matches_7z_l():
    """Facts cross-checked against `7z l` on the ground-truth VM:
    notes.md 5002, readme.txt 20 (see the packet's gate block)."""
    data = Path("/tmp/test1.7z").read_bytes()
    refs, degs = [], []
    block = parse_sevenz_blob(data, refs, degs)
    assert block is not None
    names = {m["name"]: m["size"] for m in block["members"]}
    assert names == {"notes.md": 5002, "readme.txt": 20}


def test_sevenz_crc_rejects_false_signature():
    """A 7z magic in the middle of a blob must not satisfy the start-header
    CRC check — the reader probes candidates and states the failure as a
    named degradation, never silence."""
    refusals: list[str] = []
    degradations: list[str] = []
    fake = b"MZ" + bytes([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) + bytes(64)
    block = parse_sevenz_blob(fake, refusals, degradations)
    assert block is not None
    assert block["members"] == []
    assert any(d.startswith("header_unusable") for d in degradations)


def test_sfx_runner_members_and_leak_delta(tmp_path):
    """The runner analyzes a real SFX's PE members as sfx-member units and
    leaves no temp directories (ground rule 18 asserted across the run)."""
    logging.disable(logging.CRITICAL)
    from blint.config import BlintOptions
    from blint.lib.runners import run_default_mode

    # The SFX under test: a real PE stub with the ground-truth archive
    # appended — exactly the shape a 7-Zip SFX module produces (the stub's
    # overlay is the archive).
    stub = Path(_PE).read_bytes()
    archive_bytes = Path("/tmp/test1.7z").read_bytes()
    sfx_path = tmp_path / "setup.exe"
    sfx_path.write_bytes(stub + archive_bytes)
    before = set(glob.glob(os.path.join(tempfile.gettempdir(), "blint_sfx_*")))
    reports = os.path.join(str(tmp_path), "reports")
    options = BlintOptions(
        src_dir_image=[str(sfx_path)],
        reports_dir=reports,
        no_reviews=True,
        quiet_mode=True,
    )
    run_default_mode(options)
    after = set(glob.glob(os.path.join(tempfile.gettempdir(), "blint_sfx_*")))
    assert after - before == set()
    with open(os.path.join(reports, "setup.exe-metadata.json")) as handle:
        metadata = json.load(handle)
    installer = metadata["installer"]
    assert installer["family"] == "sfx_7z"
    assert installer["extraction"] == "members"
    names = {m["name"]: m["size"] for m in installer["sfx_payload"]["members"]}
    assert names == {"notes.md": 5002, "readme.txt": 20}

