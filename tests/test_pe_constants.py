"""Tests for the blint-owned PE constant tables (ground rule 28)."""

import pytest

lief = pytest.importorskip("lief")

from blint.lib.pe_constants import (  # noqa: E402
    DLL_CHARACTERISTICS,
    decode_dll_characteristics,
    decode_flag_bits,
    machine_type_name,
    subsystem_name,
)


def test_decode_dll_characteristics_python313_value():
    # V1's exact bitfield: 352 = HIGH_ENTROPY_VA | DYNAMIC_BASE | NX_COMPAT,
    # the value on the tier-0 python313.dll reference binary. Names must come
    # from blint's PE-spec table in ascending bit order, never from a
    # dependency's enum rendering.
    assert decode_dll_characteristics(352) == [
        "HIGH_ENTROPY_VA",
        "DYNAMIC_BASE",
        "NX_COMPAT",
    ]


def test_decode_dll_characteristics_boundaries():
    assert decode_dll_characteristics(0) == []
    assert decode_dll_characteristics(0x4000) == ["GUARD_CF"]
    assert decode_dll_characteristics(0x2000) == ["WDM_DRIVER"]
    # 0xFFFF sets every bit: all eleven named flags in ascending bit order,
    # then the five untabled low bits surfaced as UNKNOWN.
    full = decode_dll_characteristics(0xFFFF)
    assert full[:11] == [
        "HIGH_ENTROPY_VA",
        "DYNAMIC_BASE",
        "FORCE_INTEGRITY",
        "NX_COMPAT",
        "NO_ISOLATION",
        "NO_SEH",
        "NO_BIND",
        "APPCONTAINER",
        "WDM_DRIVER",
        "GUARD_CF",
        "TERMINAL_SERVER_AWARE",
    ]
    assert full[11:] == ["UNKNOWN(1)", "UNKNOWN(2)", "UNKNOWN(4)", "UNKNOWN(8)", "UNKNOWN(16)"]
    # Every table name decodes back to exactly one flag, and no flag is a
    # substring of another, so the compat joined string cannot alias.
    names = list(DLL_CHARACTERISTICS.values())
    assert len(names) == len(set(names))
    for name in names:
        assert not any(name != other and name in other for other in names)


def test_decode_flag_bits_surfaces_unknown_bits():
    # Bits outside the table are rendered UNKNOWN(<bit>) like enum_to_str
    # does for out-of-enum values, ascending, after the named flags.
    assert decode_flag_bits(0x21, {0x20: "HIGH_ENTROPY_VA"}) == [
        "HIGH_ENTROPY_VA",
        "UNKNOWN(1)",
    ]
    # A multi-bit value with no table entry at all stays visible.
    assert decode_flag_bits(0x3, {}) == ["UNKNOWN(1)", "UNKNOWN(2)"]


def test_machine_type_and_subsystem_names():
    assert machine_type_name(0x8664) == "AMD64"
    assert machine_type_name(0xAA64) == "ARM64"
    assert machine_type_name(0xA641) == "ARM64EC"
    assert machine_type_name(0xA64E) == "ARM64X"
    # Values LIEF 1.0 does not enumerate still resolve (superset table).
    assert machine_type_name(0x5032) == "RISCV32"
    assert machine_type_name(0x1234) == "UNKNOWN(4660)"
    assert subsystem_name(2) == "WINDOWS_GUI"
    assert subsystem_name(3) == "WINDOWS_CUI"
    assert subsystem_name(1) == "NATIVE"
    assert subsystem_name(42) == "UNKNOWN(42)"


def test_decode_flag_bits_surfaces_bits_above_the_tables_range():
    # decode_flag_bits is generic over any bit table, so an unknown bit wider
    # than the widest named flag must still be visible rather than dropped.
    assert decode_flag_bits(1 << 20, DLL_CHARACTERISTICS) == ["UNKNOWN(1048576)"]
    assert decode_flag_bits(0x40 | (1 << 31), DLL_CHARACTERISTICS) == [
        "DYNAMIC_BASE",
        "UNKNOWN(2147483648)",
    ]


def test_lief_dll_characteristics_rendering_is_pinned():
    """Tripwire (ground rule 28, verification-log finding V1).

    LIEF 1.0 renders DLL_CHARACTERISTICS members as bare integers —
    ``str(DYNAMIC_BASE)`` is ``"64"``, not a name — which is what silently
    broke every PE hardening check that substring-matched the joined string.
    blint no longer consumes that rendering for dll_characteristics, so this
    test does not protect behavior directly; it exists so that a future LIEF
    release whose rendering changes is *noticed*: when this fails, re-run the
    V1 enum_to_str audit before trusting any rendered PE enum anywhere.
    """
    dll_characteristics = lief.PE.OptionalHeader.DLL_CHARACTERISTICS
    assert str(dll_characteristics.DYNAMIC_BASE) == "64"
