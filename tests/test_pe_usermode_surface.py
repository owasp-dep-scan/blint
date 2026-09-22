r"""Tests for the kernel-adjacent user-mode surface (PE lane W5.4, plan 04/D).

Unit level: the COM/persistence/AMSI section scans on hand-built section
bytes, the RPC interface read through a fake address space, the four
review-rule evaluators (direct syscall, injection chain, ETW and AMSI
tampering, persistence references) on synthetic metadata, and the
ATT&CK/D3FEND tags reaching the capability catalog.

Real artifacts: the RPC registration fixture (contrib-style .c source in
tests/fixtures, built at test time with clang/lld-link and skipped where
the toolchain is absent) asserts the recovered UUID against the one
declared in its source, and doubles as the real user-mode negative for
the direct-syscall rule.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

from blint.lib.binary_reviews import _evaluate_binary_analysis
from blint.lib.capabilities import build_capability_index
from blint.lib.pe_usermode_surface import (
    COM_LISTING_LIMIT,
    collect_amsi_references,
    collect_com_registration,
    collect_persistence_surfaces,
    collect_rpc_interfaces,
)

CONTRIB_RPC_SRC = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "rpc_register_fixture.c"
SLICE_SYSTEM32 = Path.home() / "sandbox" / "pe-corpus" / "tier5-system" / "system32"
WINDOWS_SYSTEM32 = Path(r"C:\Windows\System32")

_LLD_LINK = shutil.which("lld-link") or "/opt/homebrew/opt/llvm@18/bin/lld-link"
_CLANG = shutil.which("clang") or "/opt/homebrew/opt/llvm/bin/clang"
_LLVM_DLLTOOL = shutil.which("llvm-dlltool") or "/opt/homebrew/opt/llvm/bin/llvm-dlltool"

DECLARED_UUID = "{F5A3B7C2-4E1D-8A4F-9B2C-3E5D6F7A8B9C}"


class _FakeSection:
    def __init__(self, name, content):
        self.name = name
        self.content = content


class _FakeParsed:
    def __init__(self, sections=None, memory=None):
        self.sections = sections or []
        self._memory = memory or {}

    def get_content_from_virtual_address(self, address, size):
        for start, blob in self._memory.items():
            if start <= address < start + len(blob):
                offset = address - start
                return blob[offset : offset + size]
        return b""


def _metadata(**overrides):
    metadata = {
        "exe_type": "PE64",
        "subsystem": "WINDOWS_CUI",
        "imports": [],
    }
    metadata.update(overrides)
    return metadata


def _imports(*names):
    return [{"name": f"kernel32.dll::{n}"} for n in names]


# ---------------------------------------------------------------------------
# Section scans: COM identity, persistence, AMSI
# ---------------------------------------------------------------------------


def test_com_clsid_and_appid_recovered_both_encodings():
    clsid = b"CLSID\\{1F2E3D4C-5B6A-7788-99AA-BBCCDDEEFF00}"
    appid = "AppID\\{ABBA1DDE-0000-1111-2222-333344445555}".encode("utf-16-le")
    parsed = _FakeParsed([_FakeSection(".rdata", clsid + b"\x00" + appid)])
    block = collect_com_registration(parsed)
    assert block is not None
    assert block["clsids"] == ["CLSID\\{1F2E3D4C-5B6A-7788-99AA-BBCCDDEEFF00}"]
    assert block["clsid_count"] == 1
    assert block["appids"] == ["AppID\\{ABBA1DDE-0000-1111-2222-333344445555}"]
    assert block["source"] == "registry_path_strings"


def test_com_listing_bound_is_named_not_silent():
    many = b"".join(
        b"CLSID\\{AAAAAAAA-0000-0000-0000-0000000000NN}".replace(b"NN", f"{i:02d}".encode())
        + b"\x00"
        for i in range(20)
    )
    block = collect_com_registration(_FakeParsed([_FakeSection(".rdata", many)]))
    assert block["clsid_count"] == 20
    assert block["listing_truncated"]["clsids"] == 4


def test_persistence_surfaces_counted_with_bounded_evidence():
    blob = (
        b"Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00"
        b"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\x00"
        b"Image File Execution Options\\calc.exe\x00"
    )
    block = collect_persistence_surfaces(_FakeParsed([_FakeSection(".rdata", blob)]))
    assert block is not None
    assert block["surfaces"]["run_key"] >= 1
    assert block["surfaces"]["ifeo"] == 1
    assert 0 < len(block["evidence"]["run_key"]) <= 4


def test_persistence_absent_when_nothing_matches():
    assert collect_persistence_surfaces(_FakeParsed([_FakeSection(".rdata", b"nothing here")])) is None


def test_amsi_reference_scan():
    blob = b"GetProcAddress(hAmsi, \"AmsiScanBuffer\")\x00"
    block = collect_amsi_references(_FakeParsed([_FakeSection(".rdata", blob)]))
    assert block is not None
    assert block["references"] == 1
    assert block["samples"]


def test_amsi_absent():
    assert collect_amsi_references(_FakeParsed([_FakeSection(".rdata", b"no amsi here")])) is None


# ---------------------------------------------------------------------------
# RPC interfaces: fake address space, then the real fixture
# ---------------------------------------------------------------------------

_GUID_BYTES = bytes.fromhex("c2b7a3f54e1d8a4f9b2c3e5d6f7a8b9c")


def test_rpc_interface_read_from_callsite_pointer():
    parsed = _FakeParsed(memory={0x180001000: b"\x00" * 4 + _GUID_BYTES})
    callsites = [
        {"callee": "RPCRT4.dll::RpcServerRegisterIf2", "argument": 0, "value": 0x180001000, "functions": ["Register"]}
    ]
    block = collect_rpc_interfaces(parsed, callsites)
    assert block is not None
    assert block["interfaces"][0]["uuid"] == DECLARED_UUID
    assert block["interfaces"][0]["registration_functions"] == ["Register"]


def test_rpc_implausible_guids_are_refused():
    for blob in (b"\x00" * 16, b"\xff" * 16, b"\x00\x00\x00\x00" + b"\x11" * 12):
        parsed = _FakeParsed(memory={0x180001000: b"\x00" * 4 + blob})
        callsites = [
            {"callee": "rpcrt4.dll::RpcServerRegisterIf2", "argument": 0, "value": 0x180001000}
        ]
        assert collect_rpc_interfaces(parsed, callsites) is None


def test_rpc_without_callsites_is_none():
    assert collect_rpc_interfaces(_FakeParsed(), []) is None
    assert collect_rpc_interfaces(_FakeParsed(), None) is None


# ---------------------------------------------------------------------------
# The review-rule evaluators
# ---------------------------------------------------------------------------


def test_direct_syscall_detected_and_gated():
    metadata = _metadata(
        disassembled_functions={
            "a": {"name": "sub_1", "assembly": "mov r10, rcx\nsyscall\nret"},
            "b": {"name": "sub_2", "assembly": "mov r10, rcx\nsvc #0\nret"},
        }
    )
    evidence = _evaluate_binary_analysis("USERMODE_DIRECT_SYSCALL", metadata)
    assert evidence
    functions = {f["function"] for f in evidence[0]["functions"]}
    assert functions == {"sub_1", "sub_2"}


def test_direct_syscall_excludes_ntdll_and_drivers():
    ntdll = _metadata(
        name="C:\\Windows\\System32\\ntdll.dll",
        version_info={
            "strings": {
                "040904b0": {"OriginalFilename": "ntdll.dll"},
            }
        },
        disassembled_functions={"a": {"name": "ZwOpenProcess", "assembly": "syscall"}},
    )
    assert _evaluate_binary_analysis("USERMODE_DIRECT_SYSCALL", ntdll) == []
    driver = _metadata(subsystem="NATIVE", disassembled_functions={"a": {"assembly": "syscall"}})
    assert _evaluate_binary_analysis("USERMODE_DIRECT_SYSCALL", driver) == []
    # No disassembly: nothing to say.
    assert _evaluate_binary_analysis("USERMODE_DIRECT_SYSCALL", _metadata()) == []


def test_injection_chain_scores_stages():
    two_stage = _metadata(
        imports=_imports("VirtualAllocEx", "WriteProcessMemory", "VirtualAlloc")
    )
    evidence = _evaluate_binary_analysis("PROCESS_INJECTION_PRIMITIVES", two_stage)
    assert evidence and evidence[0]["stage_count"] == 2
    assert set(evidence[0]["stages"]) == {"remote_allocation", "remote_write"}
    # A single stage never fires - a JIT or an allocator alone is ordinary.
    one_stage = _metadata(imports=_imports("VirtualAllocEx"))
    assert _evaluate_binary_analysis("PROCESS_INJECTION_PRIMITIVES", one_stage) == []


def test_etw_and_amsi_tampering_need_both_halves():
    both = _metadata(imports=_imports("EtwEventWrite", "VirtualProtect", "VirtualAlloc"))
    evidence = _evaluate_binary_analysis("ETW_PATCH_EVIDENCE", both)
    assert evidence and "etweventwrite" in evidence[0]["trace_routines"]
    trace_only = _metadata(imports=_imports("EtwEventWrite"))
    assert _evaluate_binary_analysis("ETW_PATCH_EVIDENCE", trace_only) == []
    amsi = _metadata(
        imports=_imports("VirtualProtect"),
        amsi_references={"references": 2, "samples": ["AmsiScanBuffer"]},
    )
    evidence = _evaluate_binary_analysis("AMSI_PATCH_EVIDENCE", amsi)
    assert evidence and evidence[0]["amsi_references"] == 2
    amsi_without_patch = _metadata(
        amsi_references={"references": 2, "samples": ["AmsiScanBuffer"]}
    )
    assert _evaluate_binary_analysis("AMSI_PATCH_EVIDENCE", amsi_without_patch) == []


def test_persistence_references_need_surfaces_and_service_apis():
    block = {
        "persistence_surfaces": {
            "surfaces": {"run_key": 1, "ifeo": 1},
            "evidence": {},
        }
    }
    with_service = _metadata(imports=_imports("OpenSCManagerW", "CreateServiceW"))
    with_service.update(block)
    evidence = _evaluate_binary_analysis("PERSISTENCE_SURFACE_REFERENCES", with_service)
    assert evidence and set(evidence[0]["surfaces"]) == {"run_key", "ifeo"}
    # Surfaces without the ability to install: not the chain shape.
    surfaces_only = _metadata()
    surfaces_only.update(block)
    assert _evaluate_binary_analysis("PERSISTENCE_SURFACE_REFERENCES", surfaces_only) == []
    # One surface with service APIs: every installer on Windows.
    one_surface = _metadata(imports=_imports("CreateServiceW"))
    one_surface.update({"persistence_surfaces": {"surfaces": {"run_key": 1}, "evidence": {}}})
    assert _evaluate_binary_analysis("PERSISTENCE_SURFACE_REFERENCES", one_surface) == []


# ---------------------------------------------------------------------------
# ATT&CK / D3FEND tags reach the capability catalog (issues #1, #126)
# ---------------------------------------------------------------------------


def test_capability_catalog_carries_attack_and_d3fend_tags():
    index = build_capability_index()
    by_id = {entry["id"]: entry for entry in index["capabilities"]}
    syscall_rule = by_id["USERMODE_DIRECT_SYSCALL"]
    assert any(tag.startswith("T1106") for tag in syscall_rule["attack"])
    assert syscall_rule["d3fend"] == ["D3-UPA (User Process Analysis)"]
    injection_rule = by_id["PROCESS_INJECTION_PRIMITIVES"]
    assert any(tag.startswith("T1055") for tag in injection_rule["attack"])
    # A rule that declares no D3FEND mapping has no d3fend key at all -
    # unmapped is a value, not an empty promise.
    assert "d3fend" not in by_id["CHECK_NX"]


# ---------------------------------------------------------------------------
# Real artifact: the RPC fixture (built at test time, never committed)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def rpc_fixture_metadata(tmp_path_factory):
    work = tmp_path_factory.mktemp("rpc_fixture")
    if not CONTRIB_RPC_SRC.exists():
        yield None
        return
    lib = work / "rpcrt4.lib"
    try:
        subprocess.run(
            [_LLVM_DLLTOOL, "-d", str(_rpc_def(work)), "-l", str(lib), "-m", "i386:x86-64"],
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError, FileNotFoundError):
        yield None
        return
    try:
        subprocess.run(
            [_CLANG, "--target=x86_64-pc-windows-msvc", "-O2", "-c", str(CONTRIB_RPC_SRC), "-o", str(work / "rpc.obj")],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [_LLD_LINK, "/dll", "/entry:DllMain", "/nodefaultlib", f"/out:{work / 'rpc_fixture.dll'}", str(work / "rpc.obj"), str(lib)],
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError):
        yield None
        return
    from blint.lib.binary import parse

    yield parse(str(work / "rpc_fixture.dll"), disassemble=True)


def _rpc_def(work: Path) -> Path:
    def_file = work / "rpcrt4.def"
    def_file.write_text("LIBRARY rpcrt4.dll\nEXPORTS\n    RpcServerRegisterIf2 @1\n")
    return def_file


def test_rpc_fixture_uuid_matches_source(rpc_fixture_metadata):
    if rpc_fixture_metadata is None:
        pytest.skip("clang/lld-link unavailable to build the RPC fixture")
    # The interface recovery anchors on call-site constants, which need
    # the disassembly path; without nyxstone/LLVM there is nothing to read.
    if not rpc_fixture_metadata.get("disassembled_functions"):
        pytest.skip("disassembly unavailable (nyxstone/LLVM not installed)")
    block = rpc_fixture_metadata.get("rpc_interfaces")
    assert block, "a registration call site was recovered, so the block must exist"
    uuids = {interface["uuid"] for interface in block["interfaces"]}
    assert DECLARED_UUID in uuids
    # The same real artifact is a clean negative for direct syscalls.
    assert _evaluate_binary_analysis("USERMODE_DIRECT_SYSCALL", rpc_fixture_metadata) == []


def test_com_counts_are_distinct_identities_not_occurrences():
    """clsid_count counts CLSIDs, not times a CLSID was seen.

    De-duplicating only at the listing bound counted occurrences past it:
    a class named three times in .rdata (its registration table and its
    call sites - the ordinary shape) added three. Twenty distinct CLSIDs
    reported twenty-eight.
    """
    guids = [f"{{{i:08d}-0000-0000-0000-000000000000}}" for i in range(20)]
    blob = b"".join((f"CLSID\\{guid}\x00" * 3).encode() for guid in guids)
    block = collect_com_registration(_FakeParsed([_FakeSection(".rdata", blob)]))
    assert block["clsid_count"] == 20
    assert len(block["clsids"]) == COM_LISTING_LIMIT
    assert block["listing_truncated"] == {"clsids": 20 - COM_LISTING_LIMIT}


def test_persistence_evidence_names_each_occurrence_not_the_first_one_repeatedly():
    """The evidence listing shows distinct references, one per occurrence.

    Re-reading `find(marker)` for every evidence slot re-reported the first
    hit, so the second Run key an image names was never shown and the
    listing bound could never be reached - the evidence said less than the
    count beside it.
    """
    blob = (
        b"software\\microsoft\\windows\\currentversion\\run\\Alpha\x00"
        b"software\\microsoft\\windows\\currentversion\\run\\Beta\x00"
    )
    block = collect_persistence_surfaces(_FakeParsed([_FakeSection(".rdata", blob)]))
    assert block["surfaces"]["run_key"] == 2
    assert block["evidence"]["run_key"] == [
        "currentversion\\run\\Alpha",
        "currentversion\\run\\Beta",
    ]
