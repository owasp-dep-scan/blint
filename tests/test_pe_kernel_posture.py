r"""Tests for the kernel hardening posture (PE lane W5.2, plan 04/B).

Unit level: every HVCI condition, the boot-start /INTEGRITYCHECK rule, the
scored dangerous-import families and their caps, fed with metadata dicts -
all four conditions read header facts blint already records, so no binary
is needed to reach them.

Real artifacts: the corpus tier-5 benign driver sub-tier asserts the
measurement the severities were decided from (ground rule 34) - every
sampled benign driver passes every HVCI condition, and the dangerous-import
block never fires a rule anywhere on it.
"""

from pathlib import Path

import pytest

from blint.config import BlintOptions
from blint.lib.analysis import initialize_rules, run_checks
from blint.lib.checks import check_boot_start_integritycheck, check_hvci_compatible
from blint.lib.pe_driver import build_driver_block
from blint.lib.pe_kernel_posture import (
    FAMILY_EVIDENCE_LIMIT,
    evaluate_dangerous_imports,
    evaluate_hvci_compatibility,
    evaluate_kernel_hardening,
    refresh_kernel_posture_after_disassembly,
)

SLICE_DRIVERS = Path.home() / "sandbox" / "pe-corpus" / "tier5-system" / "drivers"
WINDOWS_DRIVERS = Path(r"C:\Windows\System32\drivers")


def _driver_metadata(**overrides):
    metadata = {
        "exe_type": "PE64",
        "subsystem": "NATIVE",
        "machine_type_value": 0xAA64,
        "section_alignment": 0x1000,
        "wx_segments": [],
        "data_directories": [{"type": "BASE_RELOCATION_TABLE", "size": 764}],
        "imports": [{"name": "ntoskrnl.exe::IoCreateDevice"}],
    }
    metadata.update(overrides)
    return metadata


# ---------------------------------------------------------------------------
# HVCI conditions: each has a failing, a passing and an undetermined shape
# ---------------------------------------------------------------------------


def test_hvci_clean_driver_is_compatible():
    block = evaluate_hvci_compatibility(_driver_metadata())
    assert block["compatible"] is True
    assert block["failed_conditions"] == []
    assert block["undetermined_conditions"] == []


def test_hvci_x86_machine_fails_with_evidence():
    block = evaluate_hvci_compatibility(
        _driver_metadata(machine_type_value=0x14C, machine_type="I386")
    )
    assert block["compatible"] is False
    assert "machine_64_bit" in block["failed_conditions"]
    assert "I386" in block["failure_evidence"]["machine_64_bit"]


def test_hvci_wx_section_fails_and_names_the_section():
    block = evaluate_hvci_compatibility(
        _driver_metadata(wx_segments=[{"name": ".text", "permissions": "RWX"}])
    )
    assert "no_writable_executable_sections" in block["failed_conditions"]
    assert ".text" in block["failure_evidence"]["no_writable_executable_sections"]


def test_hvci_sub_page_alignment_fails():
    block = evaluate_hvci_compatibility(_driver_metadata(section_alignment=0x20))
    assert "section_alignment_page_sized" in block["failed_conditions"]
    assert "0x20" in block["failure_evidence"]["section_alignment_page_sized"]


def test_hvci_stripped_relocations_fail_both_shapes():
    declared_empty = evaluate_hvci_compatibility(
        _driver_metadata(data_directories=[{"type": "BASE_RELOCATION_TABLE", "size": 0}])
    )
    absent = evaluate_hvci_compatibility(_driver_metadata(data_directories=[]))
    for block in (declared_empty, absent):
        assert block["compatible"] is False
        assert "relocations_present" in block["failed_conditions"]
    # A missing data-directories block is undetermined, not failed.
    undetermined = evaluate_hvci_compatibility(
        _driver_metadata(data_directories=None)
    )
    assert "relocations_present" in undetermined["undetermined_conditions"]
    assert undetermined["compatible"] is None


def test_hvci_undetermined_is_not_failed():
    """Rule 32: a condition whose source is absent never reads as failed."""
    block = evaluate_hvci_compatibility(
        _driver_metadata(
            data_directories=None, wx_segments=None, section_alignment=None, machine_type_value=None
        )
    )
    assert block["compatible"] is None
    assert block["failed_conditions"] == []
    assert len(block["undetermined_conditions"]) == 4


# ---------------------------------------------------------------------------
# The rules: fired with evidence, and the silent shapes
# ---------------------------------------------------------------------------


def test_check_hvci_names_conditions():
    driver = build_driver_block(
        _driver_metadata(section_alignment=0x20, wx_segments=[{"name": "PAGE"}]), None
    )
    metadata = {"driver": driver}
    result = check_hvci_compatible("x.sys", metadata, {})
    assert result is not True
    assert "section_alignment_page_sized" in result
    assert "no_writable_executable_sections" in result
    assert "PAGE" in result


def test_check_hvci_silent_on_non_driver_and_clean_driver():
    assert check_hvci_compatible("x.exe", {}, {}) is True
    clean = {"driver": build_driver_block(_driver_metadata(), None)}
    assert check_hvci_compatible("x.sys", clean, {}) is True


def test_check_boot_start_integritycheck_fires_on_boot_domain():
    metadata = {
        "driver": {
            "kernel_hardening": {
                "boot_start": True,
                "boot_start_basis": "subsystem_windows_boot_application",
                "force_integrity": False,
            }
        }
    }
    result = check_boot_start_integritycheck("x.sys", metadata, {})
    assert result is not True
    assert "/INTEGRITYCHECK" in result


def test_check_boot_start_integritycheck_silent_shapes():
    # Not boot-start (the common NATIVE case): silent.
    assert check_boot_start_integritycheck(
        "x.sys",
        {"driver": {"kernel_hardening": {"boot_start": None, "force_integrity": False}}},
        {},
    ) is True
    # Boot-start but the flag could not be read: undetermined, not absent.
    assert check_boot_start_integritycheck(
        "x.sys", {"driver": {"kernel_hardening": {"boot_start": True}}}, {}
    ) is True
    # Boot-start with the flag: clean.
    assert check_boot_start_integritycheck(
        "x.sys",
        {"driver": {"kernel_hardening": {"boot_start": True, "force_integrity": True}}},
        {},
    ) is True


def test_kernel_hardening_sources_and_omissions():
    block = evaluate_kernel_hardening(
        _driver_metadata(
            load_configuration={"guard_flags": 0x00000200 | 0x00000100 | 0x00100000},
            security_properties={"force_integrity": True},
        )
    )
    assert block["kernel_cfg"] is True
    assert block["cfg_instrumented"] is True
    assert block["retpoline"] is True
    assert block["xfg"] is False
    assert block["force_integrity"] is True
    assert block["boot_start"] is None
    assert "registry" in block["boot_start_basis"]
    # No load config at all: the guard facts are omitted, not False.
    bare = evaluate_kernel_hardening(_driver_metadata(load_configuration={}))
    assert "kernel_cfg" not in bare
    assert "retpoline" not in bare


def test_boot_start_determined_only_for_boot_subsystem():
    boot = evaluate_kernel_hardening(
        _driver_metadata(subsystem="WINDOWS_BOOT_APPLICATION", load_configuration={})
    )
    assert boot["boot_start"] is True
    assert boot["boot_start_basis"] == "subsystem_windows_boot_application"


# ---------------------------------------------------------------------------
# Dangerous imports: scored families, caps, and the disassembly evidence
# ---------------------------------------------------------------------------


def test_dangerous_imports_families_and_score():
    block = evaluate_dangerous_imports(
        _driver_metadata(
            imports=[
                {"name": "ntoskrnl.exe::MmMapIoSpace"},
                {"name": "ntoskrnl.exe::ZwMapViewOfSection"},
                {"name": "ntoskrnl.exe::KeStackAttachProcess"},
            ]
        )
    )
    names = {family["name"] for family in block["families"]}
    assert names == {"physical_memory", "process_tampering"}
    assert block["capability_score"] == 6  # 3 + 3


def test_dangerous_imports_cap_is_a_listing_bound():
    """Rule 33: a fixture past the cap - the family still speaks, and the
    count states what the listing does not."""
    imports = [{"name": f"ntoskrnl.exe::MmMapIoSpace{i}"} for i in range(1, 4)]
    imports += [{"name": "ntoskrnl.exe::MmMapLockedPages"}] * 0
    # physical_memory has 7 members; add extras from other families only via
    # import_count, so construct one family with more matches than the cap by
    # repeating members under distinct names is impossible - use the whole
    # table plus two near-misses to exceed the cap within one family is not
    # possible either; the honest over-cap fixture uses import_count on the
    # process_tampering family, whose 6 members all match.
    all_members = [
        "KeStackAttachProcess",
        "PsLookupProcessByProcessId",
        "ZwOpenProcess",
        "NtOpenProcess",
        "ZwTerminateProcess",
        "ObOpenObjectByPointer",
    ]
    block = evaluate_dangerous_imports(
        _driver_metadata(imports=[{"name": f"ntoskrnl.exe::{m}"} for m in all_members])
    )
    family = next(f for f in block["families"] if f["name"] == "process_tampering")
    assert family["import_count"] == 6
    assert len(family["imports"]) <= FAMILY_EVIDENCE_LIMIT
    assert block["capability_score"] > 0


def test_dangerous_imports_absent_when_nothing_matches():
    assert evaluate_dangerous_imports(_driver_metadata()) is None


def test_msr_instructions_join_score_after_disassembly():
    metadata = _driver_metadata(
        imports=[{"name": "ntoskrnl.exe::MmMapIoSpace"}],
    )
    metadata["driver"] = {"dangerous_imports": evaluate_dangerous_imports(metadata)}
    base_score = metadata["driver"]["dangerous_imports"]["capability_score"]
    metadata["disassembled_functions"] = {
        "f": {"name": "sub_1", "assembly": "mov ecx, 0xCE\nrdmsr\nret"}
    }
    refresh_kernel_posture_after_disassembly(metadata)
    families = {family["name"] for family in metadata["driver"]["dangerous_imports"]["families"]}
    assert "msr_port_io" in families
    assert metadata["driver"]["dangerous_imports"]["capability_score"] == base_score + 2
    assert "rdmsr" in metadata["driver"]["dangerous_imports"]["families"][-1]["instructions"]


def test_msr_refresh_without_driver_block_is_noop():
    metadata = {"disassembled_functions": {"f": {"assembly": "rdmsr"}}}
    refresh_kernel_posture_after_disassembly(metadata)
    assert "driver" not in metadata


# ---------------------------------------------------------------------------
# End-to-end through the rule engine: fired findings, and the tier-0 shape
# ---------------------------------------------------------------------------


def test_rules_fire_through_engine_and_stay_silent_on_user_mode():
    initialize_rules(BlintOptions())
    hostile = _driver_metadata(section_alignment=0x20)
    hostile["driver"] = build_driver_block(hostile, None)
    findings = {finding["id"] for finding in run_checks("x.sys", hostile)}
    assert "CHECK_HVCI_COMPATIBLE" in findings
    # A non-driver never reaches either rule: no driver block.
    user_mode = {"exe_type": "PE64", "subsystem": "WINDOWS_GUI"}
    assert run_checks("x.exe", user_mode) == [] or all(
        finding["id"] not in {"CHECK_HVCI_COMPATIBLE", "CHECK_BOOT_START_INTEGRITYCHECK"}
        for finding in run_checks("x.exe", user_mode)
    )
    # Boot-start without /INTEGRITYCHECK fires through the engine.
    boot = _driver_metadata(
        subsystem="WINDOWS_BOOT_APPLICATION",
        load_configuration={},
        security_properties={"force_integrity": False},
    )
    boot["driver"] = build_driver_block(boot, None)
    findings = {finding["id"] for finding in run_checks("x.sys", boot)}
    assert "CHECK_BOOT_START_INTEGRITYCHECK" in findings


# ---------------------------------------------------------------------------
# Real artifacts: the benign sub-tier proves the measurement (rule 34)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not SLICE_DRIVERS.exists() and not WINDOWS_DRIVERS.exists(),
    reason="no driver corpus on this machine",
)
def test_benign_subtier_is_hvci_clean_and_never_fires():
    """Every benign driver passes every HVCI condition; no W5.2 rule fires
    anywhere on the sub-tier. This is the measurement the severities were
    chosen from, kept as a regression gate."""
    root = SLICE_DRIVERS if SLICE_DRIVERS.exists() else WINDOWS_DRIVERS
    initialize_rules(BlintOptions())
    from blint.lib.binary import parse

    checked = 0
    for sample in sorted(root.glob("*.sys"))[:12]:
        metadata = parse(str(sample), {})
        driver = metadata.get("driver")
        assert driver, f"{sample.name} must produce a driver block"
        hvci = driver.get("hvci_compatibility") or {}
        assert hvci.get("compatible") is True, (
            f"{sample.name} fails HVCI conditions {hvci.get('failed_conditions')} "
            "- re-measure before trusting this rule"
        )
        findings = {finding["id"] for finding in run_checks(str(sample), metadata)}
        assert "CHECK_HVCI_COMPATIBLE" not in findings, sample.name
        assert "CHECK_BOOT_START_INTEGRITYCHECK" not in findings, sample.name
        checked += 1
    assert checked >= 6
