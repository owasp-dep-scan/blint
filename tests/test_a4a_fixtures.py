"""A4a R1-R3 fixture tests.

The fixtures are real NDK r28 builds (commands and versions in
``tests/data/android/a4a-fixtures-manifest.json``, sources in
``tests/scripts/android/a4a_sources/``). Two test families:

- Structural facts that hold before and after the Thumb fix (symbol tables,
  Thumb bit, target tuple, stripped twins) — these run everywhere blint's
  parser does.
- Probe before-state measurements — these need the NDK llvm tools, skip
  where absent, and are the numbers the T2 commit flips to agreement.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from blint.lib.binary import parse

DATA = Path(__file__).parent / "data" / "android"
R1_THUMB = DATA / "liba4a_r1_thumb.so"
R1_ARM = DATA / "liba4a_r1_arm.so"
R1_ARM64 = DATA / "liba4a_r1_arm64-v8a.so"
R2 = DATA / "liba4a_r2.so"
R1_THUMB_STRIPPED = DATA / "liba4a_r1_thumb_stripped.so"
R2_STRIPPED = DATA / "liba4a_r2_stripped.so"

R1_HELPERS = (
    "add_mod",
    "mul_acc",
    "first_set",
    "byte_sum",
    "rotl32",
    "mix32",
    "stretch",
    "weighted",
    "smooth",
    "a4a_r1_run",
)

SCRIPT_PATH = Path(__file__).parent / "scripts" / "android" / "native_probe.py"
_spec = importlib.util.spec_from_file_location("native_probe", SCRIPT_PATH)
native_probe = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(native_probe)


def _tools_available() -> bool:
    try:
        native_probe.resolve_llvm_bin(None)
        return True
    except native_probe.ProbeError:
        return False


def _function_table(path: Path) -> dict[str, int]:
    metadata = parse(str(path))
    assert metadata.get("binary_type") == "ELF"
    return {f["name"]: int(f["address"], 16) for f in metadata.get("functions", []) if f["name"]}


def test_manifest_names_the_build_commands() -> None:
    manifest = json.loads((DATA / "a4a-fixtures-manifest.json").read_text(encoding="utf-8"))
    assert manifest["ndk"] == "28.2.13676358"
    builds = manifest["builds"]
    for name in (R1_THUMB.name, R1_ARM.name, R2.name, R1_THUMB_STRIPPED.name, R2_STRIPPED.name):
        assert name in builds, name
        assert builds[name]["command"].startswith("/")
    assert " -mthumb" in builds[R1_THUMB.name]["command"]
    assert " -marm" in builds[R1_ARM.name]["command"]
    assert "--strip-all" in builds[R1_THUMB_STRIPPED.name]["command"]


def test_r1_thumb_symbol_table_keeps_every_helper() -> None:
    table = _function_table(R1_THUMB)
    for name in R1_HELPERS:
        assert name in table, name


def test_r2_thumb_and_arm_symbols_carry_the_mode_bit() -> None:
    table = _function_table(R2)
    # st_value bit 0 is the ARM ELF Thumb marker: odd for Thumb functions
    # (default -mthumb codegen), even for the target("arm") ones.
    assert table["thumb_leaf"] & 1
    assert table["thumb_dispatcher"] & 1
    assert table["thumb_table_jump"] & 1
    assert table["wide_table_jump"] & 1
    assert table["arm_leaf"] & 1 == 0
    assert table["arm_state_step"] & 1 == 0
    assert table["pool_reader"] & 1 == 0
    # The interworking callers and the single export exist too.
    assert "a4a_r2_run" in table and table["a4a_r2_run"] & 1


def test_android_target_tuple_per_abi() -> None:
    assert parse(str(R1_THUMB))["llvm_target_tuple"] == "arm-unknown-linux-android"
    assert parse(str(R1_ARM))["llvm_target_tuple"] == "arm-unknown-linux-android"
    assert parse(str(R1_ARM64))["llvm_target_tuple"] == "aarch64-unknown-linux-android"
    for path in (R1_THUMB, R1_ARM, R2, R1_ARM64):
        assert parse(str(path)).get("is_targeting_android") is True


def test_stripped_twins_keep_only_the_export() -> None:
    table = _function_table(R1_THUMB_STRIPPED)
    assert "a4a_r1_run" in table
    for helper in R1_HELPERS[:-1]:
        assert helper not in table
    table = _function_table(R2_STRIPPED)
    assert "a4a_r2_run" in table
    assert "thumb_dispatcher" not in table and "arm_leaf" not in table


@pytest.mark.skipif(
    not _tools_available(), reason="needs NDK llvm tools (llvm-objdump/llvm-readelf)"
)
@pytest.mark.usefixtures("no_cover")
def test_probe_after_thumb_fix_r1_thumb() -> None:
    """After T2: every function matched, modes/boundaries/counts/mnemonics
    exact. Direct edges are T3's deliverable and still resolve to none."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        report_json = Path(td) / "r.json"
        code = native_probe.main([str(R1_THUMB), "--json", str(report_json)])
        summary = json.loads(report_json.read_text())["summary"]
    assert code == 0
    assert summary["agreement"] is True
    assert summary["matched"] == summary["blint_functions"] == summary["oracle_functions"]
    assert summary["edge_precision"] == 1.0 and summary["edge_recall"] == 1.0


@pytest.mark.skipif(
    not _tools_available(), reason="needs NDK llvm tools (llvm-objdump/llvm-readelf)"
)
@pytest.mark.usefixtures("no_cover")
def test_probe_after_thumb_fix_r2_interworking() -> None:
    """The interworking rung: all 46 functions matched exactly across
    ARM/Thumb modes, tbb/tbh tables and literal pools excluded on both
    sides; only the bl/blx edges are still missing (T3)."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        report_json = Path(td) / "r.json"
        code = native_probe.main([str(R2), "--json", str(report_json)])
        summary = json.loads(report_json.read_text())["summary"]
    # Full agreement: functions, modes, boundaries, counts, mnemonics and
    # every direct bl/blx edge - the R2 gate of the semantics packet.
    assert code == 0
    assert summary["agreement"] is True
    assert summary["edge_precision"] == 1.0 and summary["edge_recall"] == 1.0


@pytest.mark.skipif(
    not _tools_available(), reason="needs NDK llvm tools (llvm-objdump/llvm-readelf)"
)
@pytest.mark.usefixtures("no_cover")
def test_probe_r2_oracle_has_interworking_and_jump_tables() -> None:
    """The oracle side of the R2 rung: tbb/tbh tables, Thumb->ARM blx and
    mapping symbols all present in the real build, from the same run."""
    bin_dir, _ = native_probe.resolve_llvm_bin(None)
    functions, mapping = native_probe.parse_readelf_symbols(
        native_probe._run(bin_dir / "llvm-readelf", ["--symbols", "--wide"], R2)
    )
    sections = native_probe.parse_readelf_sections(
        native_probe._run(bin_dir / "llvm-readelf", ["--sections"], R2)
    )
    labels_by_shndx: dict[int, dict[int, str]] = {}
    for label_addr, (label_mode, shndx) in mapping.items():
        labels_by_shndx.setdefault(shndx, {})[label_addr] = label_mode
    modes = native_probe.function_modes(functions, labels_by_shndx, sections)
    assert any(mode == "thumb" for mode in modes.values())
    assert any(mode == "arm" for mode in modes.values())
    assert {mode for _addr, (mode, _shndx) in mapping.items()} >= {"arm", "thumb", "data"}
    timeline = native_probe.parse_objdump_timeline(
        native_probe._run(
            bin_dir / "llvm-objdump",
            ["-d", "--no-show-raw-insn", "--triple=thumbv7-linux-androideabi"],
            R2,
        )
    )
    mnemonics = {instr["mnemonic"] for instr in timeline}
    assert {"tbb", "tbh", "blx"} <= mnemonics


@pytest.mark.skipif(
    not _tools_available(), reason="needs NDK llvm tools (llvm-objdump/llvm-readelf)"
)
@pytest.mark.usefixtures("no_cover")
def test_probe_controls_agree_on_other_abis() -> None:
    assert native_probe.main([str(R1_ARM64)]) == 0
