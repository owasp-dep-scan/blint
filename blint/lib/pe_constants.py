# SPDX-License-Identifier: Apache-2.0
"""Blint-owned PE constant tables.

Ground rule 28 (never match on a rendered enum) lives here: every bit-to-name
mapping a check or a rule needs is keyed by the numeric value fixed by the
PE specification, not by whatever string a dependency's enum ``__str__``
happens to render this release. LIEF 1.0 renders ``DLL_CHARACTERISTICS``
members as bare integers (verification-log finding V1), which silently broke
every PE hardening check that substring-matched the joined string; these
tables are the replacement source of truth.

The values are part of the on-disk format, so they cannot drift between
releases of any parsing library. Names follow the PE specification (and, where
the PE spec is silent, Microsoft's documented headers) so rendered names match
what Windows tools such as ``dumpbin /headers`` print.
"""

# IMAGE_DLLCHARACTERISTICS, PE spec "Optional Header Windows-Specific Fields
# (Image Only)". A 16-bit flag field; entries sorted by bit value.
DLL_CHARACTERISTICS: dict[int, str] = {
    0x0020: "HIGH_ENTROPY_VA",
    0x0040: "DYNAMIC_BASE",
    0x0080: "FORCE_INTEGRITY",
    0x0100: "NX_COMPAT",
    0x0200: "NO_ISOLATION",
    0x0400: "NO_SEH",
    0x0800: "NO_BIND",
    0x1000: "APPCONTAINER",
    0x2000: "WDM_DRIVER",
    0x4000: "GUARD_CF",
    0x8000: "TERMINAL_SERVER_AWARE",
}

# IMAGE_FILE_MACHINE_*, keyed by the 16-bit value. Base set is Microsoft's
# documented "Machine Types" table (PE spec + learn.microsoft.com), extended
# with the ARM64X/CHPE_X86 values Microsoft documents for Windows-on-ARM and
# long-standing winnt.h entries (ALPHA64, R3000, R10000, POWERPCBE, CEE,
# TRICORE) that real files still carry.
MACHINE_TYPES: dict[int, str] = {
    0x0000: "UNKNOWN",
    0x014C: "I386",
    0x0162: "R3000",
    0x0166: "R4000",
    0x0168: "R10000",
    0x0169: "WCEMIPSV2",
    0x0184: "ALPHA",
    0x01A2: "SH3",
    0x01A3: "SH3DSP",
    0x01A6: "SH4",
    0x01A8: "SH5",
    0x01C0: "ARM",
    0x01C2: "THUMB",
    0x01C4: "ARMNT",
    0x01D3: "AM33",
    0x01F0: "POWERPC",
    0x01F1: "POWERPCFP",
    0x01F2: "POWERPCBE",
    0x0200: "IA64",
    0x0266: "MIPS16",
    0x0268: "MIPS_STFPU16",
    0x0284: "ALPHA64",
    0x0366: "MIPSFPU",
    0x0466: "MIPSFPU16",
    0x0520: "TRICORE",
    0x0CEF: "CEE",
    0x0EBC: "EBC",
    0x3A64: "CHPE_X86",
    0x5032: "RISCV32",
    0x5064: "RISCV64",
    0x6232: "LOONGARCH32",
    0x6264: "LOONGARCH64",
    0x8664: "AMD64",
    0x9041: "M32R",
    0xA641: "ARM64EC",
    0xA64E: "ARM64X",
    0xAA64: "ARM64",
}

# IMAGE_SUBSYSTEM_*, PE spec "Subsystem Values". Value 1 (NATIVE) is what
# kernel-mode drivers carry; 8 (NATIVE_WINDOWS) is the historic Win9x driver
# subsystem, kept separate because the PE spec does.
SUBSYSTEMS: dict[int, str] = {
    0: "UNKNOWN",
    1: "NATIVE",
    2: "WINDOWS_GUI",
    3: "WINDOWS_CUI",
    5: "OS2_CUI",
    7: "POSIX_CUI",
    8: "NATIVE_WINDOWS",
    9: "WINDOWS_CE_GUI",
    10: "EFI_APPLICATION",
    11: "EFI_BOOT_SERVICE_DRIVER",
    12: "EFI_RUNTIME_DRIVER",
    13: "EFI_ROM",
    14: "XBOX",
    16: "WINDOWS_BOOT_APPLICATION",
    17: "XBOX_CODE_CATALOG",
}


def decode_flag_bits(value: int, table: dict[int, str]) -> list[str]:
    """Decode a numeric bitfield through a blint-owned bit-to-name table.

    Bits with no entry in the table are rendered ``UNKNOWN(<bit>)`` — the same
    convention :func:`blint.lib.utils.enum_to_str` uses for out-of-enum values —
    so an unknown bit stays visible instead of silently disappearing. Names
    come back in ascending bit order, which keeps the output deterministic
    regardless of enumeration order in any dependency.
    """
    flags: list[str] = []
    for bit in sorted(table):
        if value & bit:
            flags.append(table[bit])
    # Bits outside the table: surface them individually, lowest first.
    for pos in range(16):
        bit = 1 << pos
        if value & bit and bit not in table:
            flags.append(f"UNKNOWN({bit})")
    return flags


def decode_dll_characteristics(value: int) -> list[str]:
    """Decode the IMAGE_DLLCHARACTERISTICS bitfield into PE-spec flag names."""
    return decode_flag_bits(value, DLL_CHARACTERISTICS)


def machine_type_name(value: int) -> str:
    """Return the PE-spec name for an IMAGE_FILE_MACHINE value.

    Unknown values render ``UNKNOWN(<value>)`` so callers can tell a machine
    type these tables do not cover from a name match against a rendered enum.
    """
    return MACHINE_TYPES.get(value, f"UNKNOWN({value})")


def subsystem_name(value: int) -> str:
    """Return the PE-spec name for an IMAGE_SUBSYSTEM value."""
    return SUBSYSTEMS.get(value, f"UNKNOWN({value})")
