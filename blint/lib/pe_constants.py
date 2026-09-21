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

# IMAGE_GUARD (load configuration GuardFlags), "Load Configuration" section of
# the PE specification. Every bit is named; the table is pinned against the
# Windows SDK 10.0.26100 winnt.h IMAGE_GUARD_* defines and against
# `dumpbin /nologo /loadconfig` on real files (python313.dll GuardFlags
# 0x00000100 → "CF instrumented"; vcruntime140.dll 0x10417500 → CF instrumented
# / FID table present / Protect delayload IAT / Delayload IAT in its own
# section / Export suppression info present / Long jump target table present /
# EH Continuation table present). Note the top nibble 0xF0000000 is not a flag
# but the GuardCFFunctionTable entry-stride field, decoded separately.
GUARD_FLAGS: dict[int, str] = {
    0x00000100: "CF_INSTRUMENTED",
    0x00000200: "CFW_INSTRUMENTED",
    0x00000400: "CF_FUNCTION_TABLE_PRESENT",
    0x00000800: "SECURITY_COOKIE_UNUSED",
    0x00001000: "PROTECT_DELAYLOAD_IAT",
    0x00002000: "DELAYLOAD_IAT_IN_ITS_OWN_SECTION",
    0x00004000: "CF_EXPORT_SUPPRESSION_INFO_PRESENT",
    0x00008000: "CF_ENABLE_EXPORT_SUPPRESSION",
    0x00010000: "CF_LONGJUMP_TABLE_PRESENT",
    0x00020000: "RF_INSTRUMENTED",
    0x00040000: "RF_ENABLE",
    0x00080000: "RF_STRICT",
    0x00100000: "RETPOLINE_PRESENT",
    0x00400000: "EH_CONTINUATION_TABLE_PRESENT",
    0x00800000: "XFG_ENABLED",
    0x01000000: "CASTGUARD_PRESENT",
    0x02000000: "MEMCPY_PRESENT",
}

# Stride of GuardCFFunctionTable entries, encoded in the GuardFlags top nibble
# as (entry size / 4); 0 means the 8-byte default entry.
GUARD_FLAGS_FUNCTION_TABLE_SIZE_MASK = 0xF0000000
GUARD_FLAGS_FUNCTION_TABLE_SIZE_SHIFT = 28


def decode_guard_flags(value: int) -> list[str]:
    """Decode the load configuration GuardFlags bitfield into SDK flag names.

    The top nibble is the GuardCFFunctionTable entry-stride field, not a
    flag, so it is masked off here; read it through
    :func:`guard_cf_function_table_stride`.
    """
    return decode_flag_bits(value & ~GUARD_FLAGS_FUNCTION_TABLE_SIZE_MASK, GUARD_FLAGS)


def guard_cf_function_table_stride(value: int) -> int:
    """Entry stride (in 4-byte units) encoded in the GuardFlags top nibble."""
    return (value & GUARD_FLAGS_FUNCTION_TABLE_SIZE_MASK) >> GUARD_FLAGS_FUNCTION_TABLE_SIZE_SHIFT


# IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS payload bits (winnt.h
# IMAGE_DLLCHARACTERISTICS_EX_*). This is where a Windows image declares
# user-mode CET shadow-stack compatibility — a debug-directory claim, not a
# load configuration GuardFlags bit, so the entry must be read from the debug
# directory (type 20) rather than decoded from GuardFlags.
EX_DLL_CHARACTERISTICS: dict[int, str] = {
    0x01: "CET_COMPAT",
    0x02: "CET_COMPAT_STRICT_MODE",
    0x04: "CET_SET_CONTEXT_IP_VALIDATION_RELAXED_MODE",
    0x08: "CET_DYNAMIC_APIS_ALLOW_IN_PROC",
    0x10: "CET_RESERVED_1",
    0x20: "CET_RESERVED_2",
    0x40: "FORWARD_CFI_COMPAT",
    0x80: "HOTPATCH_COMPATIBLE",
}


def decode_ex_dll_characteristics(value: int) -> list[str]:
    """Decode the EX_DLLCHARACTERISTICS debug-entry payload into SDK names."""
    return decode_flag_bits(value, EX_DLL_CHARACTERISTICS)


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


# IMAGE_DEBUG_TYPE_* (winnt.h), keyed by the numeric value stored in the
# debug directory's IMAGE_DEBUG_DIRECTORY.Type field. Only the values the
# Windows SDK names are tabled; anything else renders UNKNOWN(<value>)
# through :func:`debug_type_name`. IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS
# (20) is pinned by dumpbin on real files: the SDK headers do not name it.
IMAGE_DEBUG_TYPES: dict[int, str] = {
    0x00: "UNKNOWN",
    0x01: "COFF",
    0x02: "CODEVIEW",
    0x03: "FPO",
    0x04: "MISC",
    0x05: "EXCEPTION",
    0x06: "FIXUP",
    0x07: "OMAP_TO_SRC",
    0x08: "OMAP_FROM_SRC",
    0x09: "BORLAND",
    0x0A: "RESERVED10",
    0x0B: "CLSID",
    0x0C: "VC_FEATURE",
    0x0D: "POGO",
    0x0E: "ILTCG",
    0x0F: "MPX",
    0x10: "REPRO",
    0x14: "EX_DLLCHARACTERISTICS",
}

IMAGE_DEBUG_TYPE_CODEVIEW = 0x02
IMAGE_DEBUG_TYPE_VC_FEATURE = 0x0C
IMAGE_DEBUG_TYPE_POGO = 0x0D
# /Brepro builds record a 16-byte image hash here; presence is the honest
# answer to "is this a reproducible build" (plan 01/A.5).
IMAGE_DEBUG_TYPE_REPRO = 0x10
IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS = 0x14


def debug_type_name(value: int) -> str:
    """Return the winnt.h name for an IMAGE_DEBUG_TYPE value."""
    return IMAGE_DEBUG_TYPES.get(value, f"UNKNOWN({value})")


# RESOURCE_TYPE ids (winuser.h RT_*), the first level of the resource tree.
# Custom types declared by string name never hit this table.
RESOURCE_TYPES: dict[int, str] = {
    0x01: "CURSOR",
    0x02: "BITMAP",
    0x03: "ICON",
    0x04: "MENU",
    0x05: "DIALOG",
    0x06: "STRING",
    0x07: "FONTDIR",
    0x08: "FONT",
    0x09: "ACCELERATOR",
    0x0A: "RCDATA",
    0x0B: "MESSAGETABLE",
    0x0C: "GROUP_CURSOR",
    0x0E: "GROUP_ICON",
    0x10: "VERSION",
    0x11: "DLGINCLUDE",
    0x13: "PLUGPLAY",
    0x14: "VXD",
    0x15: "ANICURSOR",
    0x16: "ANIICON",
    0x17: "HTML",
    0x18: "MANIFEST",
}


def resource_type_name(value: int) -> str:
    """Return the winuser.h name for a resource type id."""
    return RESOURCE_TYPES.get(value, f"UNKNOWN({value})")


# VS_FIXEDFILEINFO dwFileFlags (winver.h). A flag is only meaningful when
# the corresponding dwFileFlagsMask bit is set; the decode checks the mask.
VS_FILE_FLAGS_MASK = 0x0000003F
VS_FILE_FLAGS: dict[int, str] = {
    0x00000001: "DEBUG",
    0x00000002: "PRERELEASE",
    0x00000004: "PATCHED",
    0x00000008: "PRIVATEBUILD",
    0x00000010: "INFOINFERRED",
    0x00000020: "SPECIALBUILD",
}

# File OS constants that VERSIONINFO's fixed block actually uses (winver.h
# VOS_*), named for the metadata instead of a raw integer dump. The low word
# carries the Windows variant (1 = 16-bit, 4 = 32-bit); python313.dll
# declares the bare 0x00000004.
VS_FILE_OS: dict[int, str] = {
    0x00000000: "UNKNOWN",
    0x00000001: "WINDOWS_16BIT",
    0x00000004: "WINDOWS32",
    0x00010001: "DOS_WINDOWS16",
    0x00010004: "DOS_WINDOWS32",
    0x00020002: "OS2_PM16",
    0x00030003: "OS2_PM32",
    0x00040004: "NT_WINDOWS32",
}


def decode_file_flags(value: int, mask: int | None = None) -> list[str]:
    """Decode VS_FIXEDFILEINFO.dwFileFlags through its mask."""
    effective = value if mask is None else (value & mask)
    return decode_flag_bits(effective, VS_FILE_FLAGS)


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
    # Bits outside the table: surface them individually, lowest first. The
    # width comes from the value, not from the widest table entry, so a set
    # bit above the table's range stays visible instead of being dropped.
    for pos in range(value.bit_length()):
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
