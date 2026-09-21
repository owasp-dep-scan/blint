# SPDX-License-Identifier: Apache-2.0
"""Tests for PE layout forensics and the pre-main summary (W1.4, 01/B.5, B.1).

Every anomaly field ground rule 34 measures gets a fixture per variant: the
entry point outside ``.text`` / inside the last section, zero raw size with a
large virtual size, raw exceeding virtual, a ``SizeOfImage`` mismatch, a
truncated last section, timestamp sanity, and the section-name correlation
against the rich-header toolchain. The TLS fixtures place the directory and
the callback array in sections of chosen writability.
"""

import struct
import time

from blint.lib.binary import parse
from blint.lib.checks import check_tls_callbacks
from blint.lib.pe_layout import (
    MAX_LISTED_CALLBACKS,
    MAX_LISTED_CTORS,
    parse_pre_main_execution,
)

SECTION_RVA = 0x1000
HEADERS_END = 0x400


def _section_header(name: bytes, virtual_size: int, rva: int, raw_size: int, raw_ptr: int, chars: int) -> bytes:
    return struct.pack(
        "<8sIIIIIIHHI", name, virtual_size, rva, raw_size, raw_ptr, 0, 0, 0, 0, chars
    )


def _layout_image(
    sections: list[tuple[bytes, int, int, int, int]],
    entry_point_rva: int = 0x1000,
    sizeof_image: int | None = None,
    timestamp: int | None = 1700000000,
    with_section_bytes: bool = True,
) -> bytes:
    """A PE32+ image with the given (name, virtual_size, raw_size, chars)
    sections laid out back to back, and the given entry-point RVA."""
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    # COFF: machine, numberof_sections, time_date_stamp, ptr_symtab,
    # numberof_symbols, sizeof_optional, characteristics.
    coff = struct.pack(
        "<HHIIIHH", 0x8664, len(sections), timestamp or 0, 0, 0, 0xF0, 0x0022
    )
    optional = bytearray(0xF0)
    struct.pack_into("<H", optional, 0, 0x20B)
    struct.pack_into("<I", optional, 32, 0x1000)  # section alignment
    struct.pack_into("<I", optional, 36, 0x200)  # file alignment
    struct.pack_into("<H", optional, 68, 3)
    struct.pack_into("<I", optional, 60, HEADERS_END)  # size of headers
    struct.pack_into("<I", optional, 108, 16)  # numberof_rva_and_size
    rva = SECTION_RVA
    raw = HEADERS_END
    headers = b""
    total_raw = HEADERS_END
    for name, virtual_size, raw_size, chars, *_rest in sections:
        headers += _section_header(name, virtual_size, rva, raw_size, raw, chars)
        rva += 0x1000
        raw += raw_size
        total_raw += raw_size
    total_virtual = rva
    if sizeof_image is None:
        sizeof_image = total_virtual
    struct.pack_into("<I", optional, 56, sizeof_image)
    struct.pack_into("<I", optional, 16, entry_point_rva)
    image = b"".join([bytes(dos), b"PE\x00\x00", coff, bytes(optional), headers])
    if with_section_bytes:
        image = image.ljust(total_raw, b"\x00")
    else:
        image = image.ljust(HEADERS_END, b"\x00")
    return image


def _write(tmp_path, name: str, image: bytes) -> str:
    path = tmp_path / name
    path.write_bytes(image)
    return str(path)


def test_entry_point_placement_fields(tmp_path):
    # .text first, code second section named .rdata: the entry point sits
    # outside .text AND inside the last section.
    image = _layout_image(
        [
            (b".text\0\0\0", 0x1000, 0x400, 0x60000020),
            (b".rdata\0\0", 0x1000, 0x400, 0x40000040),
        ],
        entry_point_rva=0x2000 + 0x10,
    )
    md = parse(_write(tmp_path, "ep.exe", image), False)
    layout = md["layout"]
    assert layout["entry_point_section"] == ".rdata"
    assert layout["entry_point_outside_text"] is True
    assert layout["entry_point_in_last_section"] is True


def test_entry_point_inside_text_is_clean(tmp_path):
    image = _layout_image(
        [
            (b".text\0\0\0", 0x1000, 0x400, 0x60000020),
            (b".rdata\0\0", 0x1000, 0x400, 0x40000040),
        ],
        entry_point_rva=SECTION_RVA + 0x10,
    )
    md = parse(_write(tmp_path, "text.exe", image), False)
    layout = md["layout"]
    assert layout["entry_point_outside_text"] is False
    assert layout["entry_point_in_last_section"] is False


def test_single_section_image_omits_the_vacuous_field(tmp_path):
    """With one section, ``entry_point_in_last_section`` is vacuous — every
    section is the last — so the field is omitted, not defaulted (ground
    rule 32: the empty case stays visible as absence, not a thin False)."""
    image = _layout_image(
        [(b".text\0\0\0", 0x1000, 0x400, 0x60000020)], entry_point_rva=SECTION_RVA + 0x10
    )
    md = parse(_write(tmp_path, "single.exe", image), False)
    assert "entry_point_in_last_section" not in md["layout"]


def test_zero_entry_point_computes_nothing(tmp_path):
    """A resource-only DLL has no entry point; the placement fields say
    nothing rather than accusing (the empty case is a case)."""
    image = _layout_image(
        [(b".rsrc\0\0\0", 0x1000, 0x400, 0x40000040)], entry_point_rva=0
    )
    md = parse(_write(tmp_path, "noep.exe", image), False)
    layout = md["layout"]
    assert "entry_point_outside_text" not in layout
    assert "entry_point_outside_any_section" not in layout


def test_zero_raw_large_virtual_sections(tmp_path):
    """The unpacker-stub shape: no file bytes, a page or more of mapped
    space. A zero-raw section below the page threshold is not flagged."""
    image = _layout_image(
        [
            (b".text\0\0\0", 0x1000, 0x400, 0x60000020),
            (b"UPX0\0\0\0", 0x4000, 0, 0xE0000080),
        ],
        entry_point_rva=0x2000 + 0x10,
    )
    md = parse(_write(tmp_path, "packed.exe", image), False)
    layout = md["layout"]
    assert layout["zero_raw_size_sections"] == ["UPX0"]
    assert layout["large_virtual_zero_raw_sections"] == ["UPX0"]
    # No rich header, no go/dotnet markers: the correlation falls back to
    # the generic prefix set and names the toolchain as unknown.
    assert "section_naming_toolchain" not in layout
    assert layout["non_standard_sections"] == ["UPX0"]


def test_raw_exceeds_virtual_sections(tmp_path):
    image = _layout_image(
        [
            (b".text\0\0\0", 0x1000, 0x400, 0x60000020),
            # raw 0x800 bytes, virtual 0x100 (aligned to 0x200): raw wins.
            (b".data\0\0\0", 0x100, 0x800, 0xC0000040),
        ]
    )
    md = parse(_write(tmp_path, "rawbig.exe", image), False)
    assert md["layout"]["raw_exceeds_virtual_sections"] == [".data"]


def test_sizeof_image_mismatch(tmp_path):
    good = _layout_image([(b".text\0\0\0", 0x1000, 0x400, 0x60000020)])
    md = parse(_write(tmp_path, "ok.exe", good), False)
    assert md["layout"]["sizeof_image_mismatch"] is False
    bad = _layout_image(
        [(b".text\0\0\0", 0x1000, 0x400, 0x60000020)], sizeof_image=0x90000
    )
    md = parse(_write(tmp_path, "bad.exe", bad), False)
    assert md["layout"]["sizeof_image_mismatch"] is True
    assert md["layout"]["sizeof_image_expected"] == 0x2000


def test_timestamp_sanity(tmp_path):
    image = _layout_image([(b".text\0\0\0", 0x1000, 0x400, 0x60000020)], timestamp=0)
    md = parse(_write(tmp_path, "zero.exe", image), False)
    assert md["layout"]["timestamp_epoch_zero"] is True
    assert "timestamp_in_future" not in md["layout"]
    future = _layout_image(
        [(b".text\0\0\0", 0x1000, 0x400, 0x60000020)],
        timestamp=int(time.time()) + 10 * 365 * 86400,
    )
    md = parse(_write(tmp_path, "future.exe", future), False)
    assert md["layout"]["timestamp_in_future"] is True


def test_non_standard_sections_correlated_against_toolchain():
    """The correlation is keyed to the toolchain the rich header names: the
    same section name can be standard for one toolchain and not another."""
    from blint.lib.pe_layout import _detect_section_toolchain, _non_standard_sections

    assert _detect_section_toolchain({"rich_header": {"toolchain": {"linker_label": "VS2022"}}}) == "msvc"
    assert _detect_section_toolchain({"go_dependencies": {"x": "y"}}) == "go"
    assert _detect_section_toolchain({"is_dotnet": True}) == "dotnet"
    # .eh_frame is MinGW/GNU — non-standard for an MSVC image, standard for one.
    assert _non_standard_sections([".text", ".eh_frame"], "msvc") == [".eh_frame"]
    assert _non_standard_sections([".text", ".eh_frame"], "mingw") == []
    # COFF string-table long names ("/4") are the PE-spec encoding, not custom.
    assert _non_standard_sections(["/4", "/19"], "msvc") == []


def test_truncated_last_section(tmp_path):
    image = _layout_image(
        [
            (b".text\0\0\0", 0x1000, 0x1000, 0x60000020),
            (b".data\0\0\0", 0x1000, 0x400, 0xC0000040),
        ]
    )
    path = tmp_path / "trunc.exe"
    # Ship the file without the last section's raw bytes.
    path.write_bytes(image[: HEADERS_END + 0x1000])
    md = parse(str(path), False)
    assert md["layout"]["truncated_last_section"] is True
    whole = tmp_path / "whole.exe"
    whole.write_bytes(image)
    md = parse(str(whole), False)
    assert md["layout"]["truncated_last_section"] is False


def _tls_image(callback_rvas: list[int], array_read_only: bool = False) -> bytes:
    """A PE with a TLS directory. The directory struct lives in .rdata
    (read-only); the callback array lives in .data (writable), or in .rdata
    when ``array_read_only``. The callbacks point at ``callback_rvas`` RVAs."""
    imagebase = 0x140000000
    body = bytearray(0x1000)
    array = b"".join(
        struct.pack("<Q", imagebase + SECTION_RVA + rva) for rva in callback_rvas
    )
    array += struct.pack("<Q", 0)
    # .rdata is RVA 0x1000, .data is RVA 0x2000.
    array_va = imagebase + (0x1000 + 0x600 if array_read_only else 0x2000 + 0x200)
    body[0x280 : 0x280 + 40] = struct.pack(
        "<QQQQII",
        imagebase + 0x3000,  # StartAddressOfRawData
        imagebase + 0x3080,  # EndAddressOfRawData
        imagebase + 0x3100,  # AddressOfIndex
        array_va,  # AddressOfCallBacks
        0,  # SizeOfZeroFill
        0,  # Characteristics
    )
    data_body = bytearray(0x1000)
    if array_read_only:
        body[0x600 : 0x600 + len(array)] = array
    else:
        data_body[0x200 : 0x200 + len(array)] = array
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x8664, 2, 1700000000, 0, 0, 0xF0, 0x0022)
    optional = bytearray(0xF0)
    struct.pack_into("<H", optional, 0, 0x20B)
    struct.pack_into("<Q", optional, 24, imagebase)  # ImageBase
    struct.pack_into("<I", optional, 32, 0x1000)  # section alignment
    struct.pack_into("<I", optional, 36, 0x200)  # file alignment
    struct.pack_into("<H", optional, 68, 3)
    struct.pack_into("<I", optional, 56, 0x3000)  # size of image
    struct.pack_into("<I", optional, 60, HEADERS_END)
    struct.pack_into("<I", optional, 108, 16)  # numberof_rva_and_size
    struct.pack_into("<II", optional, 112 + 9 * 8, SECTION_RVA + 0x280, 40)
    headers = _section_header(
        b".rdata\0\0", 0x1000, SECTION_RVA, 0x1000, HEADERS_END, 0x40000040
    )
    headers += _section_header(
        b".data\0\0\0",
        0x1000,
        SECTION_RVA + 0x1000,
        0x1000,
        HEADERS_END + 0x1000,
        0xC0000040,
    )
    image = b"".join([bytes(dos), b"PE\x00\x00", coff, bytes(optional), headers]).ljust(
        HEADERS_END, b"\x00"
    )
    return image + bytes(body) + bytes(data_body)


def test_pre_main_execution_resolves_and_writability(tmp_path):
    """Callbacks resolved against discovered functions; directory read-only
    with the array writable is the runtime-patchable shape."""
    image = _tls_image([0x1230])
    path = tmp_path / "tls.exe"
    path.write_bytes(image)
    md = parse(str(path), False)
    # No discovered functions in this synthetic image: addresses stay raw.
    md["functions"] = [{"name": "my_tls_callback", "address": "0x140002230"}]
    block = parse_pre_main_execution(__import__("lief").PE.parse(str(path)), md)
    assert block["tls_callbacks"][0]["resolved"] is True
    assert block["tls_callbacks"][0]["function"] == "my_tls_callback"
    assert block["tls_directory_writable"] is False
    assert block["tls_callback_array_writable"] is True
    assert block["tls_callback_array_section"] == ".data"
    assert block["callback_count"] == 1


def test_pre_main_execution_states_a_read_only_callback_array(tmp_path):
    """A callback array in a read-only section says so.

    ``tls_directory_writable`` is stated either way, so an omitted
    ``tls_callback_array_writable`` reads as "could not be computed" — and on
    tiers 0-1 only 1 of the 14 files with callbacks has a writable array, so
    the silence would cover the other 13. The field is left out only when no
    section covers the array at all.
    """
    image = _tls_image([0x1230], array_read_only=True)
    path = tmp_path / "tls_ro.exe"
    path.write_bytes(image)
    block = parse_pre_main_execution(__import__("lief").PE.parse(str(path)), {})
    assert block["tls_callback_array_writable"] is False
    assert block["tls_callback_array_section"] == ".rdata"


def test_pre_main_counts_are_exact_past_the_listing_caps(tmp_path):
    """Ground rule 33 for this module's own windows: a fixture larger than
    MAX_LISTED_CALLBACKS and MAX_LISTED_CTORS.

    The listings are capped, but ``callback_count``/``initializer_count`` are
    the counts a reader acts on — an image registering 200 TLS callbacks must
    not report 64 — and the initializer/callback dedup must be decided over
    the whole array, not over the capped sample of it.
    """
    count = MAX_LISTED_CALLBACKS + 136
    image = _tls_image([0x1000 + 0x10 * i for i in range(count)])
    path = tmp_path / "many_tls.exe"
    path.write_bytes(image)
    parsed = __import__("lief").PE.parse(str(path))
    md = {
        "ctor_functions": [
            {"name": f"c{i}", "address": hex(0x140009000 + i)} for i in range(count)
        ]
    }
    block = parse_pre_main_execution(parsed, md)
    assert block["callback_count"] == count
    assert len(block["tls_callbacks"]) == MAX_LISTED_CALLBACKS
    assert block["tls_callbacks_truncated"] is True
    assert block["initializer_count"] == count
    assert len(block["ctor_functions"]) == MAX_LISTED_CTORS
    assert block["initializers_truncated"] is True
    # The ctors here are not the callbacks, and the dedup sees that even
    # though neither list is fully enumerated.
    assert "initializers_are_tls_callbacks" not in block


def test_pre_main_execution_deduplicates_lief_ctors(tmp_path):
    """LIEF derives PE ctor_functions from the TLS callback array; when the
    initializers are exactly the callbacks, one fact is stated instead of
    listing the functions twice (ground rule 21)."""
    image = _tls_image([0x1230])
    path = tmp_path / "tls_ctor.exe"
    path.write_bytes(image)
    parsed = __import__("lief").PE.parse(str(path))
    md = {
        "functions": [{"name": "cb", "address": "0x140002230"}],
        "ctor_functions": [{"name": "cb", "address": "0x140002230"}],
    }
    block = parse_pre_main_execution(parsed, md)
    assert block["initializers_are_tls_callbacks"] is True
    assert "ctor_functions" not in block
    assert block["initializer_count"] == 1
    # A distinct initializer list is still listed on its own.
    md["ctor_functions"] = [{"name": "real_init", "address": "0x140009000"}]
    block = parse_pre_main_execution(parsed, md)
    assert block["ctor_functions"] == ["real_init"]
    assert "initializers_are_tls_callbacks" not in block


def test_check_tls_callbacks_rule_fires_with_evidence_and_passes_clean():
    firing = {
        "pre_main_execution": {
            "tls_callbacks": [
                {"address": "0x140001000", "function": "tls_0", "resolved": True}
            ]
        }
    }
    evidence = check_tls_callbacks("f", firing, {})
    assert "tls_0" in evidence
    # Unresolved callbacks report the address, which is still evidence.
    evidence = check_tls_callbacks(
        "f",
        {"pre_main_execution": {"tls_callbacks": [{"address": "0x140001000", "resolved": False}]}},
        {},
    )
    assert "0x140001000" in evidence
    # The empty case passes: no callbacks is not a finding.
    assert check_tls_callbacks("f", {}, {}) is True
    assert check_tls_callbacks("f", {"pre_main_execution": {"callback_count": 0}}, {}) is True


def test_layout_block_absent_without_sections(tmp_path):
    """A file whose parse yields no layout block keeps working — the parse
    never raises through the caller."""
    md = parse("tests/data/pe/msvc-hello-x64.exe", False)
    layout = md.get("layout") or {}
    assert layout, "the real fixture must produce layout facts"
    assert "entry_point_section" in layout
    assert layout["entry_point_outside_text"] is False
    assert layout["section_naming_toolchain"] in ("msvc", "unknown")


def test_real_fixture_layout_and_pre_main():
    md = parse("tests/data/pe/msvc-hello-x64.exe", False)
    assert (md.get("layout") or {}).get("sizeof_image_mismatch") is False
    # The fixture has no TLS: the summary is absent, and the rule passes.
    assert "pre_main_execution" not in md or not md["pre_main_execution"].get(
        "tls_callbacks"
    )
