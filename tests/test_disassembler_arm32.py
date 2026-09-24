"""ARM32 disassembly capability tests (A4a T2).

Every input is a real NDK r28 build committed under tests/data/android/
(build commands in tests/data/android/a4a-fixtures-manifest.json). The pure
span/mode helpers run everywhere; the decode-level tests need nyxstone.
"""

from __future__ import annotations

from pathlib import Path

import lief
import pytest

from blint.lib.binary import parse
from blint.lib.disassembler import (
    _arm32_code_spans,
    _arm32_function_mode,
    _arm32_mapping_symbol_modes,
    _arm32_mode_triples,
    _arm32_section_for_address,
    _arm32_skipped_regions,
    _disassemble_arm32_span,
    _is_arm32_target,
)

R2 = Path(__file__).parent / "data" / "android" / "liba4a_r2.so"


def _nyxstone_available() -> bool:
    try:
        from blint.lib.disassembler import NYXSTONE_AVAILABLE

        return NYXSTONE_AVAILABLE
    except ImportError:
        return False


def test_is_arm32_target_distinguishes_32bit_from_aarch64() -> None:
    assert _is_arm32_target("arm-unknown-linux-android")
    assert _is_arm32_target("armv7-none-linux-androideabi")
    assert _is_arm32_target("thumbv7-linux-androideabi")
    assert not _is_arm32_target("aarch64-unknown-linux-android")
    assert not _is_arm32_target("arm64-apple-macosx")
    assert not _is_arm32_target("x86_64-unknown-linux-gnu")
    assert not _is_arm32_target("")


def test_mode_triples_upgrade_arch_and_keep_the_rest() -> None:
    assert _arm32_mode_triples("arm-unknown-linux-android") == (
        "armv7-unknown-linux-android",
        "thumbv7-unknown-linux-android",
    )
    assert _arm32_mode_triples("arm") == ("armv7", "thumbv7")


def test_mapping_symbol_table_is_section_local() -> None:
    binary = lief.parse(str(R2))
    table = _arm32_mapping_symbol_modes(binary)
    assert table, "the R2 fixture carries $a/$t/$d labels"
    text_index = _arm32_section_for_address(binary, 0x1374)
    plt_index = _arm32_section_for_address(binary, 0x20B0)
    assert text_index != plt_index
    assert any(addr <= 0x1374 for addr, _mode in table[text_index])
    # The $a/$t/$d set is complete in the fixture's .text.
    assert {mode for _addr, mode in table[text_index]} >= {"arm", "thumb", "data"}


def test_function_mode_sources() -> None:
    # Mapping symbol wins over parity; parity wins when no label; no
    # evidence at all yields None for the caller's arbiter.
    labels = [(0x100, "arm"), (0x104, "data"), (0x108, "thumb")]
    assert _arm32_function_mode(0x102, labels, has_symbol=True) == "arm"
    assert _arm32_function_mode(0x105, labels, has_symbol=True) == "data"
    assert _arm32_function_mode(0x10A, labels, has_symbol=True) == "thumb"
    assert _arm32_function_mode(0x10C, [], has_symbol=True) == "arm"
    assert _arm32_function_mode(0x10D, [], has_symbol=True) == "thumb"
    assert _arm32_function_mode(0x200, [], has_symbol=False) is None


def test_code_spans_follow_labels_and_cover_the_start() -> None:
    labels = [(0x100, "arm"), (0x110, "data"), (0x120, "thumb")]
    # Extent beginning inside the $a region: the covering label claims the
    # head, the $d island is never a span, and the later $t region follows.
    assert _arm32_code_spans(0x104, 0x28, labels) == [(0x104, 0xC), (0x120, 0xC)]
    # An extent entirely inside one labeled region is one span.
    assert _arm32_code_spans(0x122, 0x4, labels) == [(0x122, 0x4)]
    # No labels at all: the whole extent, single span (stripped binaries).
    assert _arm32_code_spans(0x100, 0x10, []) == [(0x100, 0x10)]
    # A start inside a $d region: only later code labels become spans.
    assert _arm32_code_spans(0x112, 0x14, labels) == [(0x120, 0x6)]


def test_skipped_regions_are_the_complement_of_code_spans() -> None:
    labels = [(0x100, "arm"), (0x110, "data"), (0x120, "thumb")]
    spans = _arm32_code_spans(0x104, 0x28, labels)
    assert _arm32_skipped_regions(0x104, 0x28, spans) == [(0x110, 0x10)]
    assert _arm32_skipped_regions(0x100, 0x10, [(0x100, 0x10)]) == []


@pytest.mark.skipif(not _nyxstone_available(), reason="nyxstone not installed")
def test_span_decoder_resumes_past_undecodable_words() -> None:
    """Real bytes: atexit's extent in the -marm build ends with a literal
    pool whose first word (0xffffffe0) no LLVM 18 ARM decoder accepts; the
    span decoder must still recover the instructions behind it."""
    from nyxstone import Nyxstone

    r1_arm = R2.parent / "liba4a_r1_arm.so"
    binary = lief.parse(str(r1_arm))
    arm_instance = Nyxstone(target_triple="armv7-unknown-linux-android")
    atexit_bytes = list(binary.get_content_from_virtual_address(0x1380, 32))
    assert bytes(atexit_bytes[24:28]) == b"\xe0\xff\xff\xff"  # the pool word that raises
    instructions = _disassemble_arm32_span(arm_instance, atexit_bytes, 0x1380)
    addresses = [instr.address for instr in instructions]
    # The six code instructions before the pool all decode...
    assert addresses[:6] == [0x1380, 0x1384, 0x1388, 0x138C, 0x1390, 0x1394]
    # ...and decoding resumed after the word nyxstone refused.
    assert addresses[-1] >= 0x1398


@pytest.mark.skipif(not _nyxstone_available(), reason="nyxstone not installed")
def test_parse_records_mode_and_data_spans() -> None:
    metadata = parse(str(R2), disassemble=True)
    functions = metadata["disassembled_functions"]
    by_name = {entry.get("name"): entry for key, entry in functions.items() if entry.get("name")}
    assert by_name["thumb_leaf"]["instruction_mode"] == "thumb"
    assert by_name["arm_leaf"]["instruction_mode"] == "arm"
    assert by_name["arm_state_step"]["instruction_mode"] == "arm"
    assert by_name["thumb_dispatcher"]["instruction_mode"] == "thumb"
    # The tbb byte table inside thumb_table_jump is a skipped data span.
    spans = by_name["thumb_table_jump"]["data_spans"]
    assert spans and spans[0] == {"address": "0x1480", "size": 16}
    # ARM32 functions without islands omit data_spans entirely.
    assert "data_spans" not in by_name["thumb_leaf"]
    assert "data_spans" not in by_name["arm_leaf"]
    # Other architectures never carry either field (output stays
    # byte-compatible outside ARM32).
    arm64 = parse(str(R2.parent / "liba4a_r1_arm64-v8a.so"), disassemble=True)
    assert arm64["llvm_target_tuple"] == "aarch64-unknown-linux-android"
    for entry in arm64["disassembled_functions"].values():
        assert "instruction_mode" not in entry and "data_spans" not in entry
