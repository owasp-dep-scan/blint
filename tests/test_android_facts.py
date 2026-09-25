"""A2/B1 — bionic ELF fact tests (02/A) against real NDK-built fixtures.

Every fixture is a real NDK r28.2.13676358 build (commands next to the
sha256 in ``tests/data/android/a2-fixtures-manifest.json``; sources and
ndk-build modules in ``tests/scripts/android/jni_sources/``, the two
link variants ndk-build cannot express in ``build_a2_link_variants.sh``).
Structural tests run wherever blint's parser does; the probe test needs
the NDK llvm tools and skips where they are absent.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from blint.lib.binary import parse

DATA = Path(__file__).parent / "data" / "android"

CLEAN = DATA / "libhello.so"
TEXTRELS = DATA / "libhello_textrels.so"
RELR = DATA / "libhello_relr.so"
APS2 = DATA / "libhello_aps2.so"
NOSONAME = DATA / "libhello_nosoname.so"
ABSNEEDED = DATA / "libhello_absneeded.so"
MEMTAG = DATA / "libhello_memtag.so"
BTI = DATA / "libhello_bti.so"
# arm32 Android library from the A4a set: the rule-35 negative twin.
ARM32 = DATA / "liba4a_r1_arm.so"
# Non-Android ELF: the bionic facts block must not exist there.
NON_ANDROID = Path(__file__).parent / "data" / "plain-libc-demo.elf"

SCRIPT_PATH = Path(__file__).parent / "scripts" / "android" / "elf_facts_probe.py"
_spec = importlib.util.spec_from_file_location("elf_facts_probe", SCRIPT_PATH)
elf_facts_probe = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(elf_facts_probe)


def android_facts(path: Path) -> dict:
    metadata = parse(str(path))
    block = metadata.get("android")
    assert isinstance(block, dict), f"{path.name}: no android facts block"
    return block


def test_clean_twin_core_facts() -> None:
    facts = android_facts(CLEAN)
    assert facts["android_ident"]["min_api"] == 21
    assert isinstance(facts["android_ident"]["min_api"], int)
    assert facts["android_ident"]["ndk_version"] == "r28c"
    assert facts["soname"] == "libhello.so"
    assert facts["text_relocations"] is False
    assert facts["needed_absolute"] is False
    # Conditional facts absent on this build are absent keys, not Nones
    assert "packed_relocations" not in facts
    assert "memtag" not in facts


def test_text_relocations_planted() -> None:
    assert android_facts(TEXTRELS)["text_relocations"] is True
    assert android_facts(CLEAN)["text_relocations"] is False


def test_relr_kind_and_counts() -> None:
    packed = android_facts(RELR)["packed_relocations"]
    assert packed == [{"kind": "relr", "size_bytes": 16, "entry_count": 2}]


def test_aps2_presence_without_decode() -> None:
    packed = android_facts(APS2)["packed_relocations"]
    assert packed == [{"kind": "aps2", "size_bytes": 22}]


def test_no_soname_fact() -> None:
    facts = android_facts(NOSONAME)
    assert facts["soname"] is None
    assert android_facts(CLEAN)["soname"] == "libhello.so"


def test_needed_absolute_fact() -> None:
    facts = android_facts(ABSNEEDED)
    assert facts["needed_absolute"] is True
    assert facts["soname"] is None


def test_memtag_note_arm64() -> None:
    assert android_facts(MEMTAG)["memtag"] == {
        "level": "sync", "heap": False, "stack": True,
    }


def test_aarch64_features_arm64() -> None:
    assert android_facts(BTI)["aarch64_features"] == ["BTI", "PAC"]
    assert "aarch64_features" not in android_facts(CLEAN)


def test_page_alignment_fact() -> None:
    assert android_facts(CLEAN)["page_alignment"] == {
        "min_load_align": 16384, "mod_16384_incongruent": [],
    }
    fourk = android_facts(DATA / "libhello_page4k.so")["page_alignment"]
    assert fourk["min_load_align"] == 4096
    assert len(fourk["mod_16384_incongruent"]) == 2
    assert android_facts(DATA / "libhello_page16k.so")["page_alignment"] == {
        "min_load_align": 16384, "mod_16384_incongruent": [],
    }


def test_app_16k_verdict_stored_aligned() -> None:
    from blint.lib.android_native import scan_android_native

    verdict = scan_android_native(
        str(DATA / "tier1_singleabi_stored16k.apk")
    )["page_size_16k"]
    assert verdict["compatible"] is True
    assert verdict["summary"] == "16 KB page-size compatible on 1 of 1 64-bit ABIs"
    rec = verdict["per_abi"]["arm64-v8a"]["libraries"]["libhello.so"]
    assert rec["elf_16k"] is True
    assert rec["locations"][0]["zip_16k"] is True


def test_app_16k_verdict_multiabi_per_abi() -> None:
    from blint.lib.android_native import scan_android_native

    verdict = scan_android_native(str(DATA / "tier1_multiabi.xapk"))["page_size_16k"]
    # Rule 36: the aggregation names every 64-bit ABI, never first-or-best.
    assert verdict["incompatible_abis"] == ["riscv64"]
    assert verdict["compatible_abis"] == ["arm64-v8a", "x86_64"]
    assert "armeabi-v7a" in verdict["exempt_abis"]
    assert "x86" in verdict["exempt_abis"]
    assert verdict["summary"] == "16 KB page-size compatible on 2 of 3 64-bit ABIs"
    riscv = verdict["per_abi"]["riscv64"]["libraries"]["libhello.so"]
    assert riscv["elf_16k"] is False
    assert any("min_load_align=4096" in reason for reason in riscv["reasons"])


def test_deflated_locations_not_zip_judged() -> None:
    from blint.lib.android_native import scan_android_native

    verdict = scan_android_native(
        str(DATA / "tier1_singleabi_deflated.apk")
    )["page_size_16k"]
    rec = verdict["per_abi"]["arm64-v8a"]["libraries"]["libhello.so"]
    assert rec["locations"][0]["compression"] == "deflated"
    assert rec["locations"][0]["zip_16k"] is None
    assert rec["elf_16k"] is True


def test_sanitizer_fact() -> None:
    facts = android_facts(DATA / "libhello_hwasan.so")
    assert facts["sanitizers"] == {"sanitizers": ["hwasan"], "cfi": False}
    assert "sanitizers" not in android_facts(CLEAN)


def test_fortify_fact() -> None:
    fortified = android_facts(DATA / "libhello_fortify.so")["fortify"]["symbols"]
    assert "__memcpy_chk" in fortified and "__read_chk" in fortified
    assert "__stack_chk_fail" not in fortified  # canary, not FORTIFY
    # The -U_FORTIFY_SOURCE twin keeps the plain imports, no _chk set.
    assert "fortify" not in android_facts(DATA / "libhello_nofortify.so")


def test_unwind_fact() -> None:
    facts = android_facts(CLEAN)["unwind"]
    assert facts == {"eh_frame": True, "arm_exidx": False, "gnu_debugdata": False}
    # arm32 unwind tables live in .ARM.exidx (A4a fixture, real NDK build).
    exidx = android_facts(ARM32)["unwind"]
    assert exidx["arm_exidx"] is True and exidx["eh_frame"] is False


def test_shadow_call_stack_fact() -> None:
    metadata = parse(str(DATA / "libhello_scs.so"), disassemble=True)
    if not metadata.get("disassembled_functions"):
        pytest.skip("disassembly unavailable (no nyxstone)")
    scs = metadata["android"]["shadow_call_stack"]
    assert scs["function_count"] == 2
    assert "java_add_left" in scs["functions"]
    # The clean twin has no x18 store/load pair anywhere.
    clean = parse(str(CLEAN), disassemble=True)
    if not clean.get("disassembled_functions"):
        pytest.skip("disassembly unavailable (no nyxstone)")
    assert "shadow_call_stack" not in clean["android"]


def test_arm64_only_facts_absent_on_arm32() -> None:
    """Rule 35: MTE/BTI-PAC facts do not exist for a 32-bit Android ELF."""
    metadata = parse(str(ARM32))
    assert metadata["is_targeting_android"] is True
    block = metadata["android"]
    assert "memtag" not in block
    assert "aarch64_features" not in block


def test_no_android_block_on_non_android_elf() -> None:
    metadata = parse(str(NON_ANDROID))
    assert metadata.get("is_targeting_android") in (False, None)
    assert "android" not in metadata


@pytest.mark.skipif(
    not (Path(elf_facts_probe.default_readelf()).exists()),
    reason="needs the NDK's llvm-readelf",
)
def test_probe_agrees_with_readelf_on_fixtures(tmp_path: Path) -> None:
    """The B0 probe (oracle: llvm-readelf, same run) on every committed R1
    fixture: no disagreements. B2/B3 facts are not implemented yet, so the
    run is non-strict."""
    fixtures = [CLEAN, TEXTRELS, RELR, APS2, NOSONAME, ABSNEEDED, MEMTAG, BTI,
                DATA / "libhello_page4k.so", DATA / "libhello_page16k.so",
                DATA / "libhello_hwasan.so", DATA / "libhello_fortify.so",
                DATA / "libhello_nofortify.so"]
    out = tmp_path / "probe.json"
    code = elf_facts_probe.main(
        [str(f) for f in fixtures] + ["--json", str(out)]
    )
    assert code == 0, "probe reported disagreements; see its output"
    report = json.loads(out.read_text())
    assert len(report) == len(fixtures)
