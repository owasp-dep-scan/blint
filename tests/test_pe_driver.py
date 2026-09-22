r"""Tests for the driver identity block (PE lane W5.1, plan 04/A).

Two fixture levels, mirroring the lane's discipline:

- Metadata-level unit tests feed import/subsystem shapes straight into the
  classifier, so every kind signal and the gate have a fixture that reaches
  them without building a PE.
- Real-artifact tests run blint over the clang-built driver fixture
  (contrib/win-driver-fixture, built at test time - never committed, never
  loaded) and, when present, the corpus tier-5 benign driver sub-tier.

The hand-built assembly fixtures for the WDM callback recovery are written
in the three syntaxes nyxstone renders (Intel x86/x64, AArch64), including
the two refusal shapes: the explicit NULL store and the lone +0x68 store
with no MajorFunction slot (the cdrom.sys context-struct false positive
that decided the corroboration requirement).
"""

import shutil
import subprocess
from pathlib import Path

import pytest

from blint.lib.pe_driver import (
    ADD_DEVICE_OFFSETS,
    DRIVER_OBJECT_LAYOUTS,
    OBJECT_PATH_LIMIT,
    _driver_signing_view,
    _register_callbacks_for_layout,
    build_driver_block,
    classify_driver_kind,
    is_windows_driver,
    machine_layout_widths,
    recover_wdm_callbacks,
    refresh_driver_block_after_disassembly,
)

CONTRIB_FIXTURE = Path(__file__).resolve().parents[1] / "contrib" / "win-driver-fixture"
SLICE_DRIVERS = Path.home() / "sandbox" / "pe-corpus" / "tier5-system" / "drivers"
WINDOWS_DRIVERS = r"C:\Windows\System32\drivers"

_LLD_LINK = shutil.which("lld-link") or "/opt/homebrew/opt/llvm@18/bin/lld-link"
_CLANG = shutil.which("clang") or "/opt/homebrew/opt/llvm/bin/clang"
_LLVM_DLLTOOL = shutil.which("llvm-dlltool") or "/opt/homebrew/opt/llvm/bin/llvm-dlltool"


def _kernel_metadata(dlls=None, subsystem="NATIVE", functions=(), machine_type_value=0xAA64):
    """Driver-shaped metadata for one classifier call."""
    return {
        "subsystem": subsystem,
        "machine_type_value": machine_type_value,
        "imports": [
            {"name": f"{dll}::{fn}"} for dll, fns in (dlls or {}).items() for fn in fns
        ]
        + [{"name": fn} for fn in functions],
    }


# ---------------------------------------------------------------------------
# The gate (never a block for a non-driver, never a missed UMDF)
# ---------------------------------------------------------------------------


def test_native_subsystem_passes_gate():
    assert is_windows_driver(_kernel_metadata())


def test_windows_boot_application_passes_gate():
    assert is_windows_driver(_kernel_metadata(subsystem="WINDOWS_BOOT_APPLICATION"))


def test_ntoskrnl_import_passes_gate_without_native_subsystem():
    assert is_windows_driver(
        _kernel_metadata(subsystem="WINDOWS_CUI", dlls={"ntoskrnl.exe": ["IoCreateDevice"]})
    )


def test_umdf_dll_passes_gate_and_classifies_umdf():
    """The plan's own enum names umdf; a UMDF DLL is user-mode, so the
    framework import is what makes the kind reachable at all."""
    metadata = _kernel_metadata(
        subsystem="WINDOWS_CUI", dlls={"WUDFx02000.dll": ["WdfDriverCreate"]}
    )
    assert is_windows_driver(metadata)
    kind, evidence = classify_driver_kind(metadata)
    assert kind == "umdf"
    assert evidence and evidence[0]["kind"] == "umdf"


def test_user_mode_image_without_driver_imports_has_no_block():
    metadata = _kernel_metadata(
        subsystem="WINDOWS_GUI", dlls={"kernel32.dll": ["CreateFileW"]}
    )
    assert not is_windows_driver(metadata)
    # build_driver_block with a None parsed_obj is never reached through the
    # parse path for a non-driver; the gate alone is the contract here.


# ---------------------------------------------------------------------------
# Kind: determined, never defaulted (rule 32)
# ---------------------------------------------------------------------------


def test_wdm_is_a_determination_from_ntoskrnl_imports():
    kind, evidence = classify_driver_kind(
        _kernel_metadata(dlls={"ntoskrnl.exe": ["IoCreateDevice", "IofCompleteRequest"]})
    )
    assert kind == "wdm"
    assert evidence == [{"kind": "wdm", "evidence": "imports ntoskrnl.exe"}]


def test_kind_unknown_when_no_signal_matches():
    """A NATIVE image importing only side libraries carries kind unknown -
    a value, not a wdm guess."""
    kind, evidence = classify_driver_kind(
        _kernel_metadata(dlls={"ataport.sys": ["AtaPortInitialize"]})
    )
    assert kind is None
    assert evidence == []


def test_minifilter_beats_kmdf_in_precedence_and_evidence_shows_both():
    kind, evidence = classify_driver_kind(
        _kernel_metadata(
            dlls={
                "fltmgr.sys": ["FltRegisterFilter", "FltStartFilter"],
                "wdfldr.sys": ["WdfVersionBind"],
                "ntoskrnl.exe": ["IoCreateDevice"],
            }
        )
    )
    assert kind == "minifilter"
    kinds_in_evidence = [entry["kind"] for entry in evidence]
    assert kinds_in_evidence == ["minifilter", "kmdf", "wdm"]


def test_wfp_via_netio_import_prefixes():
    kind, _ = classify_driver_kind(
        _kernel_metadata(dlls={"netio.sys": ["FwpsCalloutRegister"]})
    )
    assert kind == "wfp"


def test_storport_and_ndis_kinds():
    assert classify_driver_kind(_kernel_metadata(dlls={"storport.sys": ["StorPortInitialize"]}))[
        0
    ] == "storport"
    assert classify_driver_kind(_kernel_metadata(dlls={"scsiport.sys": ["ScsiPortInitialize"]}))[
        0
    ] == "storport"
    assert classify_driver_kind(_kernel_metadata(dlls={"ndis.sys": ["NdisMRegisterMiniport"]}))[0] == (
        "ndis"
    )


def test_wdf_static_via_wdf01000_prefix():
    kind, evidence = classify_driver_kind(
        _kernel_metadata(dlls={"wdf01000.sys": ["WdfDriverCreate"]})
    )
    assert kind == "wdf_static"
    assert "wdf01000.sys" in evidence[0]["evidence"]


def test_machine_layout_widths():
    # ARM64 and x64 share the 64-bit layout; x86 alone gets the 32-bit one.
    assert machine_layout_widths({"machine_type_value": 0xAA64}) == ("64",)
    assert machine_layout_widths({"machine_type_value": 0x8664}) == ("64",)
    assert machine_layout_widths({"machine_type_value": 0x14C}) == ("32",)
    # An unknown machine falls back to both, stated rather than guessed.
    assert machine_layout_widths({}) == ("64", "32")


# ---------------------------------------------------------------------------
# WDM callbacks: registration stores, NULL refusal, corroboration
# ---------------------------------------------------------------------------

# x64 DriverEntry shape: stores a MajorFunction slot (corroboration) then
# DriverUnload and FastIoDispatch.
X64_DRIVERENTRY = """
mov [rcx+0x70], rax
mov qword ptr [rcx+0xe0], rdx
mov [rcx+0x68], rbx
mov [rcx+0x50], rdi
"""

# The same function writing NULL first: the driver stating "no unload".
X64_DRIVERENTRY_NULL_UNLOAD = """
xor ebx, ebx
mov [rcx+0x70], rax
mov [rcx+0x68], rbx
"""

# The cdrom.sys false positive: a context struct lazily allocated at
# runtime, with a non-NULL pointer stored at +0x68 and no MajorFunction
# store anywhere - not a DRIVER_OBJECT registration.
X64_CONTEXT_STRUCT_STORE = """
mov rbx, rcx
call ExAllocatePoolWithTag
mov [rbx+0x68], rax
"""

# ARM64 DriverEntry shape (nyxstone renders decimal immediates).
ARM64_DRIVERENTRY = """
str x8, [x0, #112]
str x9, [x0, #224]
str x10, [x0, #104]
"""

ARM64_NULL_UNLOAD = """
str xzr, [x0, #224]
str x9, [x0, #112]
"""

ARM64_ADDDEVICE = """
ldr x8, [x19, #48]
str x9, [x8, #32]
str x10, [x19, #224]
"""

# AddDevice store with no extension load in the window: an ordinary field.
ARM64_PLAIN_ADDDEVICE_OFFSET = """
str x9, [x8, #32]
str x10, [x19, #224]
"""


def test_x64_callbacks_registered_with_corroboration():
    result = recover_wdm_callbacks({"f": {"name": "DriverEntry", "assembly": X64_DRIVERENTRY}})
    assert result is not None
    assert set(result["callbacks"]) == {"DriverUnload"}
    assert result["fast_io_dispatch"] is True
    assert result["callback_evidence"]["DriverUnload"]["functions"] == ["DriverEntry"]


def test_x64_null_store_is_not_a_registration():
    result = recover_wdm_callbacks(
        {"f": {"name": "DriverEntry", "assembly": X64_DRIVERENTRY_NULL_UNLOAD}}
    )
    assert result is not None
    assert result["callbacks"] == []


def test_x64_lone_store_without_major_slot_is_not_claimed():
    """The corroboration requirement: without a MajorFunction-slot store the
    base register was never shown to be a DRIVER_OBJECT."""
    result = recover_wdm_callbacks(
        {"f": {"name": "sub_1000", "assembly": X64_CONTEXT_STRUCT_STORE}}
    )
    assert result == {"callbacks": [], "fast_io_dispatch": False}


def test_arm64_callbacks_registered():
    result = recover_wdm_callbacks(
        {"f": {"name": "DriverEntry", "assembly": ARM64_DRIVERENTRY}}
    )
    assert result is not None
    assert set(result["callbacks"]) == {"DriverUnload"}
    assert result["layouts"] == ["64"]


def test_arm64_xzr_store_is_not_a_registration():
    result = recover_wdm_callbacks({"f": {"name": "DriverEntry", "assembly": ARM64_NULL_UNLOAD}})
    assert result is not None
    assert result["callbacks"] == []


def test_arm64_adddevice_needs_extension_load_in_window():
    with_load = recover_wdm_callbacks(
        {"f": {"name": "DriverEntry", "assembly": ARM64_ADDDEVICE}}
    )
    assert with_load is not None
    assert "AddDevice" in with_load["callbacks"]
    without_load = recover_wdm_callbacks(
        {"f": {"name": "sub_1000", "assembly": ARM64_PLAIN_ADDDEVICE_OFFSET}}
    )
    assert without_load is not None
    assert "AddDevice" not in without_load["callbacks"]


def test_no_disassembly_yields_no_callbacks_block():
    assert recover_wdm_callbacks({}) is None


def test_refresh_skips_non_driver_metadata():
    metadata = {"disassembled_functions": {"f": {"name": "x", "assembly": X64_DRIVERENTRY}}}
    refresh_driver_block_after_disassembly(metadata)
    assert "driver" not in metadata


# ---------------------------------------------------------------------------
# The driver signing view: kernel-trust signatures outrank walk order
# ---------------------------------------------------------------------------


def test_dual_signed_driver_reads_whql_attestation():
    """The netkvm.sys/prl_* shape: an outer commercial EV signature and a
    nested WHQL attestation. The W2.4 block class stays commercial_ev (its
    documented walk-order contract); the driver view reads the signature
    that loads the kernel image."""
    block = {
        "parse_status": "parsed",
        "signing_class": "commercial_ev",
        "signatures": [
            {
                "signer": {
                    "cn": "Parallels International GmbH",
                    "o": "Parallels International GmbH",
                    "eku": ["codeSigning"],
                }
            },
            {
                "signer": {
                    "cn": "Microsoft Windows Hardware Compatibility Publisher",
                    "o": "Microsoft Corporation",
                    "eku": ["whql", "whqlAttestation", "codeSigning"],
                }
            },
        ],
    }
    view = _driver_signing_view(block)
    assert view["class"] == "attestation_signed"
    assert view["basis"] == "kernel_trust_signature"
    # The W2.4 block's own class is untouched - one derivation each, named.
    assert block["signing_class"] == "commercial_ev"


def test_kernel_mode_eku_outranks_whql_in_driver_view():
    block = {
        "parse_status": "parsed",
        "signatures": [
            {"signer": {"cn": "X", "eku": ["whql"]}},
            {"signer": {"cn": "Y", "eku": ["kernelModeCodeSigning"]}},
        ],
    }
    view = _driver_signing_view(block)
    assert view["class"] == "kernel_mode"


def test_driver_view_falls_back_to_block_class_with_basis_named():
    block = {
        "parse_status": "parsed",
        "signing_class": "microsoft_1st_party",
        "signing_class_anchor": "issuer_name",
        "signatures": [{"signer": {"cn": "Microsoft Windows", "eku": ["codeSigning"]}}],
    }
    view = _driver_signing_view(block)
    assert view["class"] == "microsoft_1st_party"
    assert view["basis"] == "block_signing_class"
    assert view["anchor"] == "issuer_name"


def test_driver_view_absent_when_nothing_determines():
    assert _driver_signing_view({"parse_status": "parsed", "signatures": []}) is None


def test_driver_block_signing_requires_parsed_block():
    """A signature block that failed to parse determines nothing - the
    signing key stays absent rather than claiming a class (rule 11)."""
    parsed = _FakeParsed([_FakeSection(".rdata", b"\\Device\\X\x00")])
    metadata = _kernel_metadata(dlls={"ntoskrnl.exe": ["IoCreateDevice"]})
    metadata["code_signature"] = {"parse_status": "parse_failed", "signing_class": "whql"}
    block = build_driver_block(metadata, parsed)
    assert block is not None
    assert "signing" not in block


# ---------------------------------------------------------------------------
# Real artifact: the clang-built fixture driver (never loaded, built at
# test time; skipped where the toolchain is absent)
# ---------------------------------------------------------------------------


def _build_fixture_driver(tmp_path: Path) -> str | None:
    out = tmp_path / "blint_test_driver.sys"
    if out.exists():
        return str(out)
    src = CONTRIB_FIXTURE / "ioctl_driver.c"
    def_file = CONTRIB_FIXTURE / "ntoskrnl.def"
    if not src.exists() or not def_file.exists():
        return None
    work = tmp_path
    lib = work / "ntoskrnl.lib"
    try:
        subprocess.run(
            [_LLVM_DLLTOOL, "-d", str(def_file), "-l", str(lib), "-m", "i386:x86-64"],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                _CLANG,
                "--target=x86_64-pc-windows-msvc",
                "-O2",
                "-fshort-wchar",
                "-c",
                str(src),
                "-o",
                str(work / "ioctl_driver.obj"),
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                _LLD_LINK,
                "/subsystem:native",
                "/driver",
                "/entry:DriverEntry",
                "/nodefaultlib",
                f"/out:{out}",
                str(work / "ioctl_driver.obj"),
                str(lib),
            ],
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return str(out)


@pytest.fixture(scope="module")
def fixture_driver(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("driver_fixture")
    path = _build_fixture_driver(tmp)
    if not path:
        yield None
        return
    from blint.lib.binary import parse

    yield parse(path, disassemble=True)


def test_fixture_driver_block(fixture_driver):
    if fixture_driver is None:
        pytest.skip("clang/lld-link unavailable to build the driver fixture")
    # The disassembly-derived keys need nyxstone; an environment without
    # it yields no disassembled functions and the test cannot run there.
    if not fixture_driver.get("disassembled_functions"):
        pytest.skip("disassembly unavailable (nyxstone/LLVM not installed)")
    block = fixture_driver.get("driver")
    assert block, "a NATIVE-subsystem .sys must produce a driver block"
    assert block["kind"] == "wdm"
    assert block["subsystem"] == "NATIVE"
    # The source names its device and symlink; the scan reads them from
    # the section bytes whether or not the strings list kept them.
    assert "\\Device\\BlintTestDriver" in block["device_names"]
    assert "\\DosDevices\\BlintTestDriver" in block["symbolic_links"]
    # The fixture registers no WDM callbacks but does install the dispatch
    # routine; the block names where the dispatch summary came from.
    assert block["wdm_callbacks"]["callbacks"] == []
    assert block["dispatch_routines"] == {"IRP_MJ_DEVICE_CONTROL": ["sub_1000"]}
    assert block["dispatch_routines_source"] == "driver_ioctls"


# ---------------------------------------------------------------------------
# Object path listing bound (rule 33): a fixture past the cap
# ---------------------------------------------------------------------------


class _FakeSection:
    def __init__(self, name, content):
        self.name = name
        self.content = content


class _FakeParsed:
    def __init__(self, sections):
        self.sections = sections


def test_object_path_listing_bound_names_truncation():
    from blint.lib.pe_driver import recover_object_paths

    # One more device path than the listing bound.
    names = [f"\\\\Device\\\\Path{i:03d}" for i in range(OBJECT_PATH_LIMIT + 3)]
    blob = "\n".join(names).encode("ascii")
    buckets, truncated = recover_object_paths(_FakeParsed([_FakeSection(".rdata", blob)]))
    assert len(buckets["device_names"]) == OBJECT_PATH_LIMIT
    assert truncated["device_names"] == 3


def test_object_path_empty_driver_is_stated_empty():
    """Rule 32: a driver naming no device object is stated as empty, not
    left to read as "not scanned"."""
    parsed = _FakeParsed([_FakeSection(".rdata", b"no paths here\x00")])
    metadata = _kernel_metadata(dlls={"ntoskrnl.exe": ["IoCreateDevice"]})
    block = build_driver_block(metadata, parsed)
    assert block is not None
    assert block["device_names"] == []
    assert block["symbolic_links"] == []


def test_block_absent_for_non_driver():
    parsed = _FakeParsed([_FakeSection(".rdata", b"\\Device\\Nope\x00")])
    metadata = _kernel_metadata(subsystem="WINDOWS_GUI", dlls={"kernel32.dll": ["CreateFileW"]})
    assert build_driver_block(metadata, parsed) is None


# ---------------------------------------------------------------------------
# Real artifacts: the benign driver sub-tier (corpus tier-5, mini) or the
# VM's own drivers directory
# ---------------------------------------------------------------------------


def _driver_metadata(path):
    import json

    metadata_path = Path(str(path) + "-metadata.json")
    if metadata_path.exists():
        with open(metadata_path) as handle:
            return json.load(handle)
    return None


@pytest.mark.skipif(
    not SLICE_DRIVERS.exists() and not Path(WINDOWS_DRIVERS).exists(),
    reason="no driver corpus on this machine",
)
def test_benign_subtier_kinds_are_established():
    """Every benign sub-tier driver gets a driver block whose kind is a
    determination: either a table kind with evidence, or the explicit
    ``unknown`` value."""
    root = SLICE_DRIVERS if SLICE_DRIVERS.exists() else Path(WINDOWS_DRIVERS)
    expected_kinds = {
        "acpi.sys": "wdm",
        "cdrom.sys": "kmdf",
        "bindflt.sys": "minifilter",
        "afd.sys": "ndis",
        "atapi.sys": "unknown",
    }
    checked = 0
    for sample in sorted(root.glob("*.sys")):
        metadata = _driver_metadata(sample)
        if metadata is None:
            from blint.lib.binary import parse

            metadata = parse(str(sample), {})
        block = metadata.get("driver")
        assert block, f"{sample.name} is a NATIVE image and must have a driver block"
        assert block["kind"] in (
            "wdm",
            "kmdf",
            "umdf",
            "wdf_static",
            "minifilter",
            "ndis",
            "storport",
            "wfp",
            "unknown",
        )
        if block["kind"] != "unknown":
            assert block["kind_evidence"], f"{sample.name} claims a kind with no evidence"
        if sample.name.lower() in expected_kinds:
            assert block["kind"] == expected_kinds[sample.name.lower()], sample.name
        checked += 1
    assert checked >= 10, f"sub-tier slice unexpectedly small: {checked}"


def test_x86_driver_registers_callbacks_through_absolute_immediates():
    """A 32-bit driver stores the address of its routine, not a register.

    `mov dword ptr [eax+0x34], 0x401000` is how MSVC emits
    `DriverObject->DriverUnload = DriverUnload` in non-PIC 32-bit code.
    Treating any operand beginning with `0` as NULL refused every one of
    them, so no 32-bit driver could report a callback or reach the
    MajorFunction corroboration at all - the x86 layout was unreachable,
    the same blind spot W5.3 fixed for ARM64.
    """
    lines = [
        "mov dword ptr [eax + 0x38], 0x401000",
        "mov dword ptr [eax + 0x34], 0x402000",
    ]
    callbacks, fast_io = _register_callbacks_for_layout(
        lines, DRIVER_OBJECT_LAYOUTS["32"], ADD_DEVICE_OFFSETS["32"]
    )
    assert callbacks == {"DriverUnload"}
    assert fast_io is False


def test_explicit_null_store_still_refuses_the_callback():
    """Only a literal zero is the driver saying "no callback here"."""
    lines = [
        "mov dword ptr [eax + 0x38], 0x401000",
        "mov dword ptr [eax + 0x34], 0x0",
    ]
    callbacks, _ = _register_callbacks_for_layout(
        lines, DRIVER_OBJECT_LAYOUTS["32"], ADD_DEVICE_OFFSETS["32"]
    )
    assert callbacks == set()
