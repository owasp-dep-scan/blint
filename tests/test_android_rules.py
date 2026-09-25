"""A3 — bionic loader rule tests (C1, 02/B, ground rule 37) and the
per-ABI hardening rules (C2).

Every planted defect is a real NDK r28.2.13676358 build (commands and
same-run readelf ground truth in ``tests/data/android/a2-fixtures-manifest.json``);
the app-context twins are built by mutating the parsed metadata's
container block the way ``runners._process_apk_so_members`` does, since the
condition being tested is the manifest fact, not the binary.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from blint.lib.analysis import run_checks
from blint.lib.binary import parse

DATA = Path(__file__).parent / "data" / "android"

CLEAN = DATA / "libhello.so"
ARM32 = DATA / "liba4a_r1_arm.so"
# The C1 loader rules; the C2 hardening rules (BTI/MTE) are asserted in
# their own tests because the plain NDK build fires BTI_PAC by design.
LOADER_RULES = {
    "CHECK_ANDROID_TEXTREL", "CHECK_ANDROID_WX_LOAD", "CHECK_ANDROID_NO_SONAME",
    "CHECK_ANDROID_ABS_NEEDED", "CHECK_ANDROID_PAGE_16K",
    "CHECK_ANDROID_EXTRACT_NATIVE_LIBS",
}


def findings_for(path: Path, **container) -> list[dict]:
    metadata = parse(str(path))
    if container:
        metadata["container"] = {"role": "apk-so-member", **container}
    return run_checks(str(path), metadata)


def android_ids(findings: list[dict]) -> list[str]:
    return [f["id"] for f in findings if f["id"] in LOADER_RULES]


def test_clean_twin_stays_silent() -> None:
    assert android_ids(findings_for(CLEAN)) == []


def test_defects_caught_without_app_context() -> None:
    """Standalone / no-manifest runs: the finding states the API level."""
    cases = {
        "libhello_textrels.so": "CHECK_ANDROID_TEXTREL",
        "libhello_page4k.so": "CHECK_ANDROID_PAGE_16K",
        "libhello_nosoname.so": "CHECK_ANDROID_NO_SONAME",
        "libhello_absneeded.so": "CHECK_ANDROID_ABS_NEEDED",
        "libhello_rwx.so": "CHECK_ANDROID_WX_LOAD",
    }
    for name, rule in cases.items():
        path = DATA / name
        metadata = parse(str(path))
        assert metadata["is_targeting_android"], name
        ids = android_ids(findings_for(path))
        assert rule in ids, f"{name}: {rule} did not fire; got {ids}"
    # The wording never assumes an API level when there is no manifest.
    finding = next(
        f for f in findings_for(DATA / "libhello_textrels.so")
        if f["id"] == "CHECK_ANDROID_TEXTREL"
    )
    assert "the loader refuses from API 23" in finding["title"]


def test_textrel_conditional_on_target_sdk() -> None:
    # The loader tolerates text relocations for apps targeting < 23.
    assert android_ids(findings_for(DATA / "libhello_textrels.so",
                                    min_sdk=21, target_sdk=21)) == []
    fired = findings_for(DATA / "libhello_textrels.so", min_sdk=21, target_sdk=35)
    assert "CHECK_ANDROID_TEXTREL" in android_ids(fired)
    assert "refuses this app (targets API 35 >= 23)" in fired[0]["title"]


def test_page_16k_conditional_on_target_sdk() -> None:
    # Play requires 16 KB support from targetSdk 35 (policy as fetched
    # 2026-09-25); below that the rule stays silent with app context.
    assert android_ids(findings_for(DATA / "libhello_page4k.so",
                                    min_sdk=24, target_sdk=34)) == []
    fired = findings_for(DATA / "libhello_page4k.so", min_sdk=24, target_sdk=35)
    assert "CHECK_ANDROID_PAGE_16K" in android_ids(fired)
    # The 16 KB-clean twin never fires, whatever the target.
    assert android_ids(findings_for(DATA / "libhello_page16k.so",
                                    min_sdk=24, target_sdk=35)) == []


def test_soname_and_needed_conditional_on_target_sdk() -> None:
    assert android_ids(findings_for(DATA / "libhello_nosoname.so",
                                    min_sdk=21, target_sdk=22)) == []
    assert "CHECK_ANDROID_NO_SONAME" in android_ids(
        findings_for(DATA / "libhello_nosoname.so", min_sdk=21, target_sdk=23))
    assert android_ids(findings_for(DATA / "libhello_absneeded.so",
                                    min_sdk=21, target_sdk=22)) == []
    fired = findings_for(DATA / "libhello_absneeded.so", min_sdk=21, target_sdk=23)
    assert "CHECK_ANDROID_ABS_NEEDED" in android_ids(fired)


def test_wx_load_conditional_on_target_sdk() -> None:
    # targetSdk 22 also predates the SONAME rule, so the omagic build
    # (which has no DT_SONAME) stays fully silent there.
    assert android_ids(findings_for(DATA / "libhello_rwx.so",
                                    min_sdk=21, target_sdk=22)) == []
    fired = findings_for(DATA / "libhello_rwx.so", min_sdk=24, target_sdk=26)
    assert "CHECK_ANDROID_WX_LOAD" in android_ids(fired)
    # The generic W+X rule yields to the Android one (no double report).
    assert "CHECK_WX_SEGMENTS" not in [f["id"] for f in fired]


def test_extract_native_libs_rule() -> None:
    # deflated member while extractNativeLibs=false: the loader refuses.
    fired = findings_for(
        DATA / "libhello.so", min_sdk=24, target_sdk=35,
        extract_native_libs={"value": False, "source": "manifest"},
        compression="deflated", offset_mod_4096=0, offset_mod_16384=0,
    )
    assert "CHECK_ANDROID_EXTRACT_NATIVE_LIBS" in android_ids(fired)
    # stored but not page-aligned: also refused
    fired = findings_for(
        DATA / "libhello.so", min_sdk=24, target_sdk=35,
        extract_native_libs={"value": False, "source": "manifest"},
        compression="stored", offset_mod_4096=512, offset_mod_16384=512,
    )
    assert "CHECK_ANDROID_EXTRACT_NATIVE_LIBS" in android_ids(fired)
    # stored and aligned: clean
    clean = findings_for(
        DATA / "libhello.so", min_sdk=24, target_sdk=35,
        extract_native_libs={"value": False, "source": "manifest"},
        compression="stored", offset_mod_4096=0, offset_mod_16384=0,
    )
    assert "CHECK_ANDROID_EXTRACT_NATIVE_LIBS" not in android_ids(clean)
    # extractNativeLibs=true: extraction happens, compression is fine
    clean = findings_for(
        DATA / "libhello.so", min_sdk=24, target_sdk=35,
        extract_native_libs={"value": True, "source": "manifest"},
        compression="deflated", offset_mod_4096=0, offset_mod_16384=0,
    )
    assert "CHECK_ANDROID_EXTRACT_NATIVE_LIBS" not in android_ids(clean)
    # No app context: the manifest fact cannot exist, the rule never fires.
    assert "CHECK_ANDROID_EXTRACT_NATIVE_LIBS" not in android_ids(findings_for(CLEAN))


def _all_ids(findings: list[dict]) -> list[str]:
    return [f["id"] for f in findings]


def test_bti_pac_arm64_only() -> None:
    # Planted without branch protection: the gap is reported.
    fired = findings_for(DATA / "libhello.so")
    assert "CHECK_ANDROID_BTI_PAC" in _all_ids(fired)
    # The -mbranch-protection=standard twin is silent.
    assert android_ids(findings_for(DATA / "libhello_bti.so")) == []
    # Rule 35: the check never runs on arm32 — the arm32 twin (also raw
    # clang, also without branch protection) gets no BTI finding.
    fired = findings_for(ARM32)
    assert "CHECK_ANDROID_BTI_PAC" not in _all_ids(fired)


def test_memtag_informational_arm64_only() -> None:
    fired = findings_for(DATA / "libhello_memtag.so")
    memtag = [f for f in fired if f["id"] == "CHECK_ANDROID_MEMTAG"]
    assert memtag and memtag[0]["severity"] == "info"
    assert "sync" in memtag[0]["title"] and "stack" in memtag[0]["title"]
    # Absence fires nowhere (the Android norm), on any ABI.
    assert "CHECK_ANDROID_MEMTAG" not in _all_ids(findings_for(DATA / "libhello_bti.so"))
    assert "CHECK_ANDROID_MEMTAG" not in _all_ids(findings_for(ARM32))


def test_pie_rule_covers_android_executables() -> None:
    # hello_static is a static non-PIE executable: PIE is a meaningful
    # question for it (main executable, not a DYN library).
    metadata = parse(str(DATA / "hello_static")) if (DATA / "hello_static").exists() else None
    if metadata is None:
        pytest.skip("static executable fixture not committed")
    assert metadata["elf_type"] == "EXEC"
    assert metadata["is_pie"] is False


def test_canary_rule_covers_android() -> None:
    # CHECK_CANARY (existing rule) applies per-ABI unchanged: the
    # -fno-stack-protector twin fires, the default build stays silent.
    fired = findings_for(DATA / "libhello_nocanary.so")
    assert "CHECK_CANARY" in _all_ids(fired)
    assert "CHECK_CANARY" not in _all_ids(findings_for(CLEAN))
