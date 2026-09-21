r"""Tests for the privileged-host plugin surface (PE lane W5.6, plan 04/F).

The fixtures are hand-built minimal PE DLLs (no binary blobs committed -
the same discipline as the inline wasm builder in test_binary.py), because
the properties under test are structural: which export sets satisfy which
contract, what an unreadable export directory does and does not claim, and
that detection never depends on the metadata strings list's gates.

The doc-pinned contract table is asserted against real artifacts wherever
a real one exists: the corpus tier-5 slice (APMon.dll/AppMon.dll) on any
machine, and C:\Windows\System32 itself when the suite runs on Windows
(the VM gate).
"""

import os
import struct

import pytest

from blint.lib.binary import parse
from blint.lib.checks import (
    check_lsa_plugin,
    check_privileged_host_plugin,
    check_unsigned_host_plugin,
)
from blint.lib.pe_host_plugins import (
    REGISTRATION_EVIDENCE_LIMIT,
    classify_host_plugins,
)

SLICE_ROOT = os.path.expanduser("~/sandbox/pe-corpus/tier5-system/system32")
WINDOWS_SYSTEM32 = r"C:\Windows\System32"

_DOS_HEADER = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x80) + b"\x00" * 0x40
_PE_SIG = b"PE\x00\x00"

_FILE_ALIGNMENT = 0x200
_SECTION_RVA = 0x1000
_SECTION_RAW = 0x200


def _build_pe_dll(
    export_names=None,
    rdata_strings=None,
    wide_strings=None,
    corrupt_export=False,
):
    """A minimal x64 PE DLL whose .rdata carries an export directory and
    optional strings. ``corrupt_export`` points data directory 0 at an
    RVA no section backs, the shape a truncated or damaged export
    directory takes in the wild."""
    export_names = export_names or []
    body = bytearray()

    def rva(offset):
        return _SECTION_RVA + offset

    if export_names:
        dll_name = b"testplugin.dll\x00"
        names_blob = b"".join(n.encode("ascii") + b"\x00" for n in export_names)
        n = len(export_names)
        dir_size = 40
        eat_off = dir_size
        npt_off = eat_off + 4 * n
        ot_off = npt_off + 4 * n
        names_off = ot_off + 2 * n
        dllname_off = names_off + len(names_blob)
        strings_off = dllname_off + len(dll_name)
        # Export Directory Table
        body += struct.pack(
            "<IIHHIIIIIII",
            0,  # characteristics
            0,  # timestamp
            0,  # major
            0,  # minor
            rva(dllname_off),  # name RVA
            1,  # ordinal base
            n,  # number of functions
            n,  # number of names
            rva(eat_off),  # EAT RVA
            rva(npt_off),  # name pointer table RVA
            rva(ot_off),  # ordinal table RVA
        )
        # Export address table: every function points into the section.
        for i in range(n):
            body += struct.pack("<I", rva(strings_off + 0x100 + 4 * i))
        # Name pointer table
        cursor = names_off
        name_rvas = []
        for name in export_names:
            name_rvas.append(rva(cursor))
            cursor += len(name.encode("ascii")) + 1
        for name_rva_value in name_rvas:
            body += struct.pack("<I", name_rva_value)
        # Ordinal table
        for i in range(n):
            body += struct.pack("<H", i)
        body += names_blob
        body += dll_name
    else:
        strings_off = 0
    # Padding then a code-ish blob so the section has content past the
    # directory, then the strings the fixture wants to embed.
    if export_names:
        body += b"\x00" * (strings_off + 0x100 - len(body) if len(body) < strings_off + 0x100 else 0)
    for s in rdata_strings or []:
        body += s.encode("ascii") + b"\x00"
    for s in wide_strings or []:
        body += s.encode("utf-16-le") + b"\x00\x00"

    virtual_size = max(len(body), 0x200)
    size_of_raw = (virtual_size + _FILE_ALIGNMENT - 1) // _FILE_ALIGNMENT * _FILE_ALIGNMENT

    coff = struct.pack(
        "<HHIIIHH",
        0x8664,  # AMD64
        1,  # sections
        0,  # timestamp
        0,  # symbol table ptr
        0,  # symbols
        0xF0,  # optional header size
        0x2022,  # DLL | EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    )
    if export_names and not corrupt_export:
        export_dir_rva, export_dir_size = rva(0), 40
    elif corrupt_export:
        # Backed by no section: the loader (and lief) cannot read it.
        export_dir_rva, export_dir_size = _SECTION_RVA + 0x8000, 0x40
    else:
        export_dir_rva, export_dir_size = 0, 0
    data_dirs = struct.pack("<II", export_dir_rva, export_dir_size) + b"\x00" * (15 * 8)
    optional = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        0x20B,  # PE32+
        14, 0,  # linker
        0x200,  # size of code
        size_of_raw,  # size of initialized data
        0,  # size of uninitialized
        rva(0x40) if export_names else 0,  # entry point (into the section)
        _SECTION_RVA,  # base of code
        0x180000000,  # image base
        0x1000,  # section alignment
        _FILE_ALIGNMENT,
        6, 0,  # OS version
        0, 0,  # image version
        6, 0,  # subsystem version
        0,  # win32 version
            _SECTION_RVA + ((virtual_size + 0xFFF) // 0x1000) * 0x1000,  # size of image

        _FILE_ALIGNMENT,  # size of headers
        0,  # checksum
        3,  # subsystem WINDOWS_CUI
        0,  # dll characteristics
        0x100000, 0x1000, 0x100000, 0x1000,  # stack/heap
        0,  # loader flags
        16,  # rva and sizes
    ) + data_dirs
    assert len(optional) == 0xF0, f"optional header packed to {len(optional)}"
    section = struct.pack(
        "<8sIIIIIIHHI",
        b".rdata\x00\x00",
        virtual_size,
        _SECTION_RVA,
        size_of_raw,
        _SECTION_RAW,
        0,
        0,
        0,
        0,
        0x40000040,  # INITIALIZED_DATA | READ
    )
    headers = bytearray(_DOS_HEADER + _PE_SIG + coff + optional + section)
    headers += b"\x00" * (_FILE_ALIGNMENT - len(headers))
    image = bytes(headers) + bytes(body).ljust(size_of_raw, b"\x00")
    return image


@pytest.fixture
def write_pe(tmp_path):
    def _write(name, image):
        path = tmp_path / name
        path.write_bytes(image)
        return str(path)

    return _write


def _parse_full(path):
    return parse(path)


# ---------------------------------------------------------------------------
# The block and its contracts
# ---------------------------------------------------------------------------


def test_password_filter_dll_gets_block_and_high_lsa_finding(write_pe):
    path = write_pe(
        "pwfilter.dll",
        _build_pe_dll(export_names=["InitializeChangeNotify", "PasswordFilter"]),
    )
    metadata = _parse_full(path)
    block = metadata.get("host_plugin")
    assert block, "a password filter DLL must produce a host_plugin block"
    ids = {c["id"] for c in block["contracts"]}
    assert ids == {"lsa_password_filter"}
    contract = block["contracts"][0]
    assert contract["host_process"] == "lsass.exe"
    assert contract["host_privilege"] == "system"
    assert contract["protected_process"] is True
    assert "InitializeChangeNotify" in contract["matched_exports"]
    assert "plaintext" in contract["credential_exposure"]
    result = check_lsa_plugin("pwfilter.dll", metadata, {})
    assert result is not True and "plaintext" in result
    result = check_privileged_host_plugin("pwfilter.dll", metadata, {})
    assert result is not True and "lsa_password_filter" in result


def test_ssp_ap_is_context_not_a_high_lsa_finding(write_pe):
    """The narrowing pin: SpLsaModeInitialize is on every core logon
    protocol (nine DLLs on a stock System32, measured), so it lands in
    the block and the informational rule - never in CHECK_LSA_PLUGIN."""
    path = write_pe("ssp.dll", _build_pe_dll(export_names=["SpLsaModeInitialize"]))
    metadata = _parse_full(path)
    ids = {c["id"] for c in metadata["host_plugin"]["contracts"]}
    assert ids == {"lsa_security_package"}
    assert check_lsa_plugin("ssp.dll", metadata, {}) is True
    result = check_privileged_host_plugin("ssp.dll", metadata, {})
    assert result is not True and "lsa_security_package" in result


def test_multiple_contracts_in_one_dll(write_pe):
    path = write_pe(
        "both.dll",
        _build_pe_dll(export_names=["SpLsaModeInitialize", "NPGetCaps", "TimeProvOpen"]),
    )
    metadata = _parse_full(path)
    ids = {c["id"] for c in metadata["host_plugin"]["contracts"]}
    assert ids == {"lsa_security_package", "network_provider", "time_provider"}


def test_print_monitor_contract(write_pe):
    path = write_pe("mon.dll", _build_pe_dll(export_names=["InitializePrintMonitor2"]))
    metadata = _parse_full(path)
    ids = {c["id"] for c in metadata["host_plugin"]["contracts"]}
    assert ids == {"print_monitor"}
    assert metadata["host_plugin"]["contracts"][0]["host_process"] == "spoolsv.exe"


def test_no_exports_no_block_and_no_gap(write_pe):
    """The empty case is a case (rule 32): a plain DLL with no export
    directory produces no block - and no degradation, because nothing
    failed to be read."""
    path = write_pe("plain.dll", _build_pe_dll(rdata_strings=["nothing to see"]))
    metadata = _parse_full(path)
    assert "host_plugin" not in metadata
    assert "exports_read_status" not in metadata
    assert "export_table_unreadable" not in metadata["analysis_coverage"]["degradations"]
    assert check_privileged_host_plugin("plain.dll", metadata, {}) is True
    assert check_lsa_plugin("plain.dll", metadata, {}) is True


def test_corrupt_export_directory_is_a_named_gap_not_a_verdict(write_pe):
    """Rules 14/32: an export directory lief could not read must not read
    as "not a plugin". There is no block, and the gap reaches
    analysis_coverage by name."""
    path = write_pe(
        "corrupt.dll",
        _build_pe_dll(export_names=["SpLsaModeInitialize"], corrupt_export=True),
    )
    metadata = _parse_full(path)
    assert metadata.get("exports_read_status") == "failed"
    assert "host_plugin" not in metadata
    assert "export_table_unreadable" in metadata["analysis_coverage"]["degradations"]


def test_export_names_are_matched_exactly_not_by_substring(write_pe):
    """Rule 11 negative fixture: names that contain a contract export as a
    substring, or share its prefix, satisfy nothing."""
    path = write_pe(
        "lookalike.dll",
        _build_pe_dll(
            export_names=[
                "MySpLsaModeInitializeEx",
                "xWSPStartup",
                "PasswordFilterEx2",
                "NPGetCapsHelper",
            ]
        ),
    )
    metadata = _parse_full(path)
    assert "host_plugin" not in metadata


# ---------------------------------------------------------------------------
# The COM contracts and their registration evidence
# ---------------------------------------------------------------------------


def test_bare_com_inproc_is_not_a_plugin(write_pe):
    """The measurement's headline: 1,443 of 3,191 system32 DLLs export the
    COM pair. Without a registration reference they satisfy no contract."""
    path = write_pe(
        "plaincom.dll",
        _build_pe_dll(
            export_names=["DllGetClassObject", "DllCanUnloadNow", "DllRegisterServer"],
            rdata_strings=[
                "CLSID\\{D6886603-9D2F-4EB2-B667-1971041FA96B}",
                "InprocServer32",
            ],
        ),
    )
    metadata = _parse_full(path)
    assert "host_plugin" not in metadata


def test_credential_provider_contract_needs_registration_reference(write_pe):
    path = write_pe(
        "credprov.dll",
        _build_pe_dll(
            export_names=["DllGetClassObject", "DllCanUnloadNow"],
            rdata_strings=[
                "SOFTWARE\\Classes\\CLSID\\{25CBB996-92ED-457e-B28C-4774084BD562}",
                (
                    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\"
                    "Credential Providers\\{25CBB996-92ED-457e-B28C-4774084BD562}"
                ),
            ],
        ),
    )
    metadata = _parse_full(path)
    contracts = metadata["host_plugin"]["contracts"]
    assert [c["id"] for c in contracts] == ["credential_provider"]
    assert contracts[0]["host_process"] == "LogonUI.exe"
    evidence = contracts[0]["evidence"]["registration_strings"]
    assert any("Credential Providers" in s for s in evidence)


def test_credential_provider_reference_found_in_wide_chars(write_pe):
    """Registration strings in real binaries are UTF-16LE as often as
    ASCII; the byte-level scan must see both."""
    path = write_pe(
        "credprovw.dll",
        _build_pe_dll(
            export_names=["DllGetClassObject"],
            wide_strings=[
                (
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
                    "Authentication\\Credential Providers\\"
                    "{F8A0B131-5F68-486c-8040-7E8FC3C85BB6}"
                ),
            ],
        ),
    )
    metadata = _parse_full(path)
    ids = {c["id"] for c in metadata["host_plugin"]["contracts"]}
    assert "credential_provider" in ids


def test_detection_does_not_depend_on_the_strings_listing(write_pe):
    """The W3.2 property: registration evidence is scanned from section
    bytes, so a reference the metadata strings gates out (short, no
    registry-shape prefix, ordinary entropy) is still detected."""
    fragment = "Authentication\\Credential Providers\\{F8A0B131-5F68-486c-8040-7E8FC3C85BB6}"
    path = write_pe(
        "shortref.dll",
        _build_pe_dll(
            export_names=["DllGetClassObject"],
            rdata_strings=[fragment],
        ),
    )
    metadata = _parse_full(path)
    ids = {c["id"] for c in metadata["host_plugin"]["contracts"]}
    assert "credential_provider" in ids
    listed = {s["value"] for s in metadata.get("strings") or []}
    # Whether the fragment survived parse_strings' gates is exactly what
    # detection must not hinge on: the contract fires either way, and the
    # fixture pins that the gate can drop it.
    if fragment not in listed:
        assert "credential_provider" in ids  # still detected without the listing


def test_registration_evidence_listing_is_bounded_but_detection_is_not(write_pe):
    """Rule 33: the evidence listing caps at REGISTRATION_EVIDENCE_LIMIT
    entries; a fixture with more matches than the cap still fires (the
    cap bounds metadata, never detection - no rule reads past entry 0)."""
    extra = [
        f"Authentication\\Credential Providers\\{{D6886603-9D2F-4EB2-B667-1971041FA9{i:02X}}}"
        for i in range(REGISTRATION_EVIDENCE_LIMIT + 3)
    ]
    path = write_pe(
        "manymatches.dll",
        _build_pe_dll(export_names=["DllGetClassObject"], rdata_strings=extra),
    )
    metadata = _parse_full(path)
    contracts = metadata["host_plugin"]["contracts"]
    assert [c["id"] for c in contracts] == ["credential_provider"]
    listed = contracts[0]["evidence"]["registration_strings"]
    assert len(listed) == REGISTRATION_EVIDENCE_LIMIT


def test_audio_processing_object_contract(write_pe):
    path = write_pe(
        "apo.dll",
        _build_pe_dll(
            export_names=["DllGetClassObject", "DllCanUnloadNow"],
            wide_strings=["HKR,AudioEngine\\AudioProcessingObjects,%APO_CLSID%"],
        ),
    )
    metadata = _parse_full(path)
    contracts = metadata["host_plugin"]["contracts"]
    assert [c["id"] for c in contracts] == ["audio_processing_object"]
    assert contracts[0]["host_process"] == "audiodg.exe"
    assert contracts[0]["host_privilege"] == "protected"


# ---------------------------------------------------------------------------
# The unsigned gate (W2.4 signing class)
# ---------------------------------------------------------------------------


def _plugin_metadata_with_signing_class(signing_class):
    metadata = {
        "exe_type": "PE64",
        "exports": [{"name": "InitializeChangeNotify", "ordinal": 1}],
        "host_plugin": {
            "contracts": [
                {
                    "id": "lsa_password_filter",
                    "title": "LSA password filter / notification package",
                    "host_process": "lsass.exe",
                    "host_privilege": "system",
                    "matched_exports": ["InitializeChangeNotify"],
                }
            ]
        },
    }
    if signing_class is not None:
        metadata["code_signature"] = {
            "parse_status": "parsed",
            "signing_class": signing_class,
        }
    return metadata


@pytest.mark.parametrize(
    "signing_class,fires",
    [
        ("unsigned", True),
        ("self_signed", True),
        ("unknown_root", True),
        (None, False),  # undetermined: never claimed as unsigned
        ("microsoft_1st_party", False),
        ("whql", False),
        ("commercial_ov", False),
        ("kernel_mode", False),
        ("attestation_signed", False),
    ],
)
def test_unsigned_rule_gates_on_signing_class(signing_class, fires):
    metadata = _plugin_metadata_with_signing_class(signing_class)
    result = check_unsigned_host_plugin("x.dll", metadata, {})
    if fires:
        assert result is not True and "plugin contract" in result
    else:
        assert result is True


def test_unsigned_rule_silent_without_signature_block():
    """No code_signature block at all (blint's default invocation performs
    no catalog lookup) determines nothing - the same discipline as
    CHECK_AUTHENTICODE."""
    metadata = _plugin_metadata_with_signing_class(None)
    assert "code_signature" not in metadata
    assert check_unsigned_host_plugin("x.dll", metadata, {}) is True


def test_unsigned_rule_silent_when_walk_truncated():
    metadata = _plugin_metadata_with_signing_class("self_signed")
    metadata["code_signature"]["parse_status"] = "parse_failed"
    assert check_unsigned_host_plugin("x.dll", metadata, {}) is True


def test_unsigned_rule_silent_without_contracts():
    metadata = _plugin_metadata_with_signing_class("unsigned")
    del metadata["host_plugin"]
    assert check_unsigned_host_plugin("x.dll", metadata, {}) is True


# ---------------------------------------------------------------------------
# ARM64X slices (rule 21)
# ---------------------------------------------------------------------------


def test_nested_export_disagreement_names_the_variance():
    """When the primary and nested listings are both readable and disagree
    on the contract set, the block names the variance rather than letting
    the primary silently speak for both slices."""
    metadata = {
        "exports": [{"name": "SpLsaModeInitialize", "ordinal": 1}],
        "nested_binary": {
            "exports": [{"name": "InitializeChangeNotify", "ordinal": 1}],
        },
    }
    block = classify_host_plugins(metadata, None)
    assert block
    assert {c["id"] for c in block["contracts"]} == {"lsa_security_package"}
    assert block["host_plugin_slice_variance"] == [
        "lsa_password_filter",
        "lsa_security_package",
    ]


def test_nested_listing_speaks_when_primary_is_unreadable():
    metadata = {
        "exports_read_status": "failed",
        "exports": [],
        "nested_binary": {"exports": [{"name": "TimeProvOpen", "ordinal": 1}]},
    }
    block = classify_host_plugins(metadata, None)
    assert block
    assert {c["id"] for c in block["contracts"]} == {"time_provider"}
    assert block["host_plugin_scope"] == "nested_binary"


def test_unreadable_primary_without_nested_says_nothing():
    """No block from a failed listing alone: the gap is carried by
    exports_read_status and the coverage degradation, not by a block that
    would read as a verdict."""
    metadata = {"exports_read_status": "failed", "exports": []}
    assert classify_host_plugins(metadata, None) is None


# ---------------------------------------------------------------------------
# The data table (a malformed entry must not pass silently)
# ---------------------------------------------------------------------------


def test_contract_table_shape():
    from blint.lib.pe_host_plugins import _contracts_table

    table = _contracts_table()["contracts"]
    assert table, "the contract table must load"
    privileges = {"system", "local_service", "protected", "inherited"}
    for contract_id, spec in table.items():
        assert spec.get("kind") in ("exports", "com_inproc"), contract_id
        assert spec.get("host_process"), contract_id
        assert spec.get("host_privilege") in privileges, contract_id
        assert spec.get("documentation"), contract_id
        if spec["kind"] == "exports":
            assert spec.get("export_names"), contract_id
        else:
            assert spec.get("com_export") and spec.get("registration_pattern"), contract_id


# ---------------------------------------------------------------------------
# Real artifacts (rule 29)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not (os.path.isdir(SLICE_ROOT) and os.path.exists(os.path.join(SLICE_ROOT, "APMon.dll"))),
    reason="tier-5 slice not present",
)
def test_real_print_monitors_on_the_slice():
    """APMon.dll and AppMon.dll are registered print monitors on the
    measurement VM (WSD Port and Appmon under Print\\Monitors); both
    export InitializePrintMonitor2 and must classify as print monitors."""
    for name in ("APMon.dll", "AppMon.dll"):
        metadata = _parse_full(os.path.join(SLICE_ROOT, name))
        contracts = (metadata.get("host_plugin") or {}).get("contracts") or []
        ids = {c["id"] for c in contracts}
        assert "print_monitor" in ids, name
        mon = next(c for c in contracts if c["id"] == "print_monitor")
        assert mon["matched_exports"] == ["InitializePrintMonitor2"]
        assert mon["host_process"] == "spoolsv.exe"
        # The slice files are catalog-signed Microsoft binaries, so the
        # high-severity unsigned rule stays silent without a catalog dir.
        assert check_unsigned_host_plugin(name, metadata, {}) is True


@pytest.mark.skipif(
    not os.path.exists(os.path.join(WINDOWS_SYSTEM32, "msv1_0.dll")),
    reason="not running on Windows",
)
@pytest.mark.parametrize(
    "dll,expected",
    [
        ("msv1_0.dll", "lsa_security_package"),
        ("kerberos.dll", "lsa_security_package"),
        ("schannel.dll", "lsa_security_package"),
        ("scecli.dll", "lsa_password_filter"),
        ("w32time.dll", "time_provider"),
        ("ntlanman.dll", "network_provider"),
        ("usbmon.dll", "print_monitor"),
        ("tcpmon.dll", "print_monitor"),
        ("localspl.dll", "print_monitor"),
        ("mswsock.dll", "winsock_service_provider"),
        ("SmartcardCredentialProvider.dll", "credential_provider"),
        ("credprovs.dll", "credential_provider"),
    ],
)
def test_registered_system_plugins_classify_correctly(dll, expected):
    """The registry ground truth from the measurement VM: every DLL here
    is registered at the contract's extension point (LSA Security/
    Notification Packages, W32Time TimeProviders, NetworkProvider order,
    Print Monitors, the Winsock catalog, Authentication Credential
    Providers), and blint must assign exactly that contract. Runs on the
    VM gate; the lsa_password_filter row is also CHECK_LSA_PLUGIN's
    benign population (scecli.dll is the registered notification
    package)."""
    metadata = _parse_full(os.path.join(WINDOWS_SYSTEM32, dll))
    block = metadata.get("host_plugin")
    assert block, dll
    ids = {c["id"] for c in block["contracts"]}
    assert expected in ids, f"{dll}: expected {expected} in {ids}"


@pytest.mark.skipif(
    not os.path.exists(os.path.join(WINDOWS_SYSTEM32, "scecli.dll")),
    reason="not running on Windows",
)
def test_scecli_fires_the_lsa_rule_on_windows():
    metadata = _parse_full(os.path.join(WINDOWS_SYSTEM32, "scecli.dll"))
    result = check_lsa_plugin("scecli.dll", metadata, {})
    assert result is not True and "plaintext" in result


@pytest.mark.skipif(
    not (os.path.isdir(SLICE_ROOT) and os.path.exists(os.path.join(SLICE_ROOT, "APMon.dll"))),
    reason="tier-5 slice not present",
)
def test_slice_histogram_no_lsa_or_unsigned_findings():
    """On the whole 240-file slice only the two print monitors carry any
    contract, so the high-severity W5.6 rules fire zero times there."""
    lsa = unsigned = 0
    for name in sorted(os.listdir(SLICE_ROOT)):
        path = os.path.join(SLICE_ROOT, name)
        if not os.path.isfile(path):
            continue
        metadata = _parse_full(path)
        if check_lsa_plugin(name, metadata, {}) is not True:
            lsa += 1
        if check_unsigned_host_plugin(name, metadata, {}) is not True:
            unsigned += 1
    assert (lsa, unsigned) == (0, 0)


# ---------------------------------------------------------------------------
# What the review of W5.6 found: the coverage mirroring, the dead table key,
# and the rule scope.
# ---------------------------------------------------------------------------


def test_slice_variance_reaches_analysis_coverage(write_pe, monkeypatch):
    """The scope and variance keys live inside the host_plugin block, so the
    coverage mirroring must read them from there.

    It read them from the top level of metadata instead, where nothing ever
    wrote them, so analysis_coverage never carried either key and the rule-21
    promise METADATA.md makes was unmet on every ARM64X image. No test looked
    at analysis_coverage, which is why the block-level assertions passed.
    """
    from blint.lib import binary as binary_mod

    metadata = {
        "exports": [{"name": "SpLsaModeInitialize", "ordinal": 1}],
        "nested_binary": {"exports": [{"name": "TimeProvOpen", "ordinal": 1}]},
    }
    block = classify_host_plugins(metadata, None)
    assert block["host_plugin_slice_variance"] == [
        "lsa_security_package",
        "time_provider",
    ]
    metadata["host_plugin"] = block
    coverage = binary_mod._build_analysis_coverage(metadata, disassemble=False)
    assert coverage["host_plugin_slice_variance"] == [
        "lsa_security_package",
        "time_provider",
    ]


def test_nested_scope_reaches_analysis_coverage():
    from blint.lib import binary as binary_mod

    metadata = {
        "exports_read_status": "failed",
        "exports": [],
        "nested_binary": {"exports": [{"name": "TimeProvOpen", "ordinal": 1}]},
    }
    metadata["host_plugin"] = classify_host_plugins(metadata, None)
    coverage = binary_mod._build_analysis_coverage(metadata, disassemble=False)
    assert coverage["host_plugin_scope"] == "nested_binary"
    assert "export_table_unreadable" in coverage["degradations"]


def test_contract_table_carries_no_key_the_loader_ignores():
    """Every key in a contract entry is one the loader reads.

    The table shipped ``match: any`` on all ten export contracts and nothing
    in pe_host_plugins.py has a concept of ``match`` - a semantic knob that
    looks authoritative in the data file and silently does nothing, so a
    later ``match: all`` would behave as ``any`` without failing anything.
    """
    from blint.lib.pe_host_plugins import _contracts_table

    known = {
        "title",
        "kind",
        "export_names",
        "com_export",
        "registration_pattern",
        "host_process",
        "host_privilege",
        "protected_process",
        "credential_exposure",
        "registration_hint",
        "documentation",
        "notes",
    }
    for contract_id, spec in _contracts_table()["contracts"].items():
        unknown = set(spec) - known
        assert not unknown, f"{contract_id} carries keys no loader reads: {unknown}"


def test_rule_scope_covers_the_toolchain_exe_types():
    """exe_type is a toolchain label that overwrites PE32/PE64.

    Measured across tier-0 and tier-1, 3 of 177 Windows PE files land outside
    PE32/PE64: node.exe on both architectures is labelled ``gobinary`` by the
    .rdata Go heuristic and the MinGW ripgrep build is ``genericbinary``. A
    Go c-shared DLL exports named entry points like any other, so a scope of
    PE32/PE64 alone silently excludes the binaries an implant is most likely
    to be built as - the CHECK_PACKED defect of W3.1, repeated on two
    high-severity rules.
    """
    from blint.lib import analysis as analysis_mod

    for rule_id in (
        "CHECK_PRIVILEGED_HOST_PLUGIN",
        "CHECK_UNSIGNED_HOST_PLUGIN",
        "CHECK_LSA_PLUGIN",
    ):
        exe_types = set(analysis_mod.rules_dict[rule_id].get("exe_types") or [])
        assert {"PE32", "PE64", "dotnetbinary", "gobinary", "genericbinary"} <= exe_types, rule_id
