"""A1.2 - native code in the analysis path (01/C).

The no-dex and multi-ABI fixtures are the committed A0.2 corpus files
(real aapt2/zipalign/apksigner packaging over NDK-built libraries).
"""

import json
from pathlib import Path

import orjson

from blint.config import BlintOptions
from blint.lib.checks import check_libc_portability, check_rpath
from blint.lib.runners import run_default_mode

DATA = Path(__file__).parent / "data" / "android"
NO_DEX = DATA / "tier1_no_dex.apk"
MULTIABI = DATA / "tier1_multiabi.xapk"


def _run(src: Path, tmp_path: Path, **overrides) -> dict:
    options = BlintOptions(
        src_dir_image=[str(src)],
        reports_dir=str(tmp_path),
        no_reviews=True,
        quiet_mode=True,
        **overrides,
    )
    run_default_mode(options)
    return orjson.loads((tmp_path / "analysis-coverage.json").read_bytes())


def test_no_dex_apk_is_analyzed_not_skipped(tmp_path: Path) -> None:
    # V7: an APK with native code and no dex used to skip as
    # no_dex_bytecode; now the app is a container unit and the library is
    # an apk-so-member unit with its own exported metadata.
    coverage = _run(NO_DEX, tmp_path)
    assert coverage["skipped"] == []
    assert coverage["units_by_role"]["top-level"]["succeeded"] == 1
    member = coverage["units_by_role"]["apk-so-member"]
    assert member == {"attempted": 1, "succeeded": 1, "failed": 0, "skipped": 0}
    app_meta = orjson.loads((tmp_path / f"{NO_DEX.name}-metadata.json").read_bytes())
    native = app_meta["android_native"]
    assert native["abi_coverage"]["abis"] == ["arm64-v8a"]
    assert native["extract_native_libs"]["value"] is False
    assert native["counts"]["libraries"] == 1
    member_meta = orjson.loads(
        (tmp_path / f"{NO_DEX.name}!lib~arm64-v8a~libhello.so-metadata.json").read_bytes()
    )
    container = member_meta["container"]
    assert container["role"] == "apk-so-member"
    assert container["abi"] == "arm64-v8a"
    assert container["member_path"] == "lib/arm64-v8a/libhello.so"
    # The parse itself is a first-class ELF analysis (V3 reversed): the
    # hardening facts the SBOM path used to discard are on the unit.
    assert member_meta["binary_type"] == "ELF"
    assert member_meta["is_targeting_android"] is True
    assert member_meta["relro"] == "full"
    assert member_meta["has_canary"] is True


def test_android_abi_filter_limits_native_units(tmp_path: Path) -> None:
    coverage = _run(MULTIABI, tmp_path, android_abis=["arm64-v8a"])
    member = coverage["units_by_role"]["apk-so-member"]
    assert member["attempted"] == 1
    exports = [p.name for p in tmp_path.glob("*.json") if "!" in p.name]
    assert len(exports) == 1
    assert "arm64-v8a" in exports[0]


def test_all_abis_yield_per_abi_units(tmp_path: Path) -> None:
    coverage = _run(MULTIABI, tmp_path)
    member = coverage["units_by_role"]["apk-so-member"]
    assert member["attempted"] == 5
    assert member["failed"] == 0
    exports = [p.name for p in tmp_path.glob("*.json") if "!" in p.name]
    # One result per (app, abi, library): the five per-ABI builds are five
    # distinct units (ground rule 36).
    assert len(exports) == 5
    assert any("riscv64" in name for name in exports)


def test_dex_app_units_unchanged_plus_native(tmp_path: Path) -> None:
    # The stored16k apk ships a stub dex: the dex review path still runs
    # (dexbinary unit) and the native member rides beside it.
    coverage = _run(DATA / "tier1_singleabi_stored16k.apk", tmp_path)
    assert coverage["units_by_role"]["apk-so-member"]["succeeded"] == 1
    app_meta = orjson.loads(
        (tmp_path / "tier1_singleabi_stored16k.apk-metadata.json").read_bytes()
    )
    assert app_meta["exe_type"] == "dexbinary"
    assert app_meta["android_native"]["counts"]["libraries"] == 1


def test_libc_portability_bionic_out_of_scope() -> None:
    # Ground rule 35: the glibc-vs-musl measurement cannot judge bionic -
    # __register_atfork is bionic-exported (A0.3: 604 tier-0 FPs).
    metadata = {
        "abi_analysis": {
            "libc": "bionic",
            "features": {"glibc_specific_imports": ["__register_atfork"]},
        }
    }
    assert check_libc_portability("x.so", metadata, {}) is True
    # The glibc branch still fires on glibc binaries.
    glibc = {
        "abi_analysis": {
            "libc": "glibc",
            "features": {"glibc_specific_imports": ["backtrace"]},
        }
    }
    result = check_libc_portability("x.so", glibc, {})
    assert isinstance(result, str) and "backtrace" in result


def test_rpath_rule_bionic_out_of_scope() -> None:
    # Bionic ignores DT_RPATH and resolves DT_RUNPATH only within the
    # naming library's namespace - the rule's ld.so semantics do not
    # exist there, so it does not run (A0.3: the tier-0 hits included
    # bionic's own linker).
    bionic = {"has_rpath": True, "abi_analysis": {"libc": "bionic"}}
    assert check_rpath("x.so", bionic, {}) is True
    glibc = {"has_rpath": True, "abi_analysis": {"libc": "glibc"}}
    assert check_rpath("x.so", glibc, {}) is False


def test_bionic_runtime_not_tagged_glibc() -> None:
    # construct_binary_composition used to tag every bionic binary "glibc"
    # via the libc.so DT_NEEDED check (V12).
    from blint.lib.binary import construct_binary_composition

    metadata = {
        "dynamic_entries": [{"name": "libc.so", "tag": "NEEDED"}],
        "is_targeting_android": True,
    }
    composition = construct_binary_composition(metadata, None)
    assert "bionic" in composition["runtime_dependencies"]
    assert "glibc" not in composition["runtime_dependencies"]
    # Non-android binaries keep the glibc tag.
    metadata_linux = {"dynamic_entries": [{"name": "libc.so", "tag": "NEEDED"}]}
    composition_linux = construct_binary_composition(metadata_linux, None)
    assert "glibc" in composition_linux["runtime_dependencies"]


def test_native_member_findings_carry_qualified_names(tmp_path: Path) -> None:
    # Findings on a member attribute to app!member (never a temp path).
    options = BlintOptions(
        src_dir_image=[str(DATA / "abi_mismatch.apk")],
        reports_dir=str(tmp_path),
        no_reviews=True,
        quiet_mode=True,
    )
    run_default_mode(options)
    ffile = next(tmp_path.glob("*findings*.json"), None)
    if ffile:  # findings are optional; the attribution is the contract
        findings = json.loads(ffile.read_text())["findings"]
        for finding in findings:
            assert finding["filename"].startswith("abi_mismatch.apk!")
            assert "blint_android_so_" not in finding["filename"]
