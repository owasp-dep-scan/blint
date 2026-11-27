"""ELF parsing: headers, segments, dynamic entries and layout anomalies.

Split out of ``binary.py``; imports only ``binary_common`` (and, for the
rdata symbol reader the ELF path reuses, ``binary_pe``), never the
orchestrator that imports it.
"""

# pylint: disable=too-many-lines,consider-using-f-string
import contextlib
import os
import re
import struct
import warnings

import lief

from blint.lib.absint import _IMM, _parse_immediate
from blint.lib.binary_common import (
    ADDRESS_FMT,
    ELF_STACK_CHK_SYMBOLS,
    ENTRY_POINT_SECTIONS,
    LINK_CLOSURE_ROOT,
    LINK_CLOSURE_SEARCH_PATHS,
    RESOLVE_LINK_CLOSURE,
    SHF_EXECINSTR,
    _rwx_permissions_str,
    consolidate_dlopen_dependencies,
    detect_exe_type,
    parse_functions,
    parse_go_buildinfo,
    parse_graalvm_sbom,
    parse_notes,
    parse_overlay,
    parse_relro,
    parse_rust_buildinfo,
    parse_strings,
    parse_symbols,
)
from blint.lib.binary_macho import (  # noqa: F401
    _macho_address_to_virtual,
    _macho_arch_name,
    _macho_code_signature_block,
    _macho_content_segment_ranges,
    _macho_count,
    _macho_has_pac,
    _macho_imagebase_or_zero,
    _macho_is_signed,
    _macho_security_properties,
    _macho_signature_blob,
    _macho_signature_data_offset,
    _macho_signature_file_offset,
    _macho_slice_signature,
    _macho_slice_summary,
    _macho_symbol_signals,
    _macho_symtab_has_canary,
    _macho_symtab_has_names,
    _normalize_macho_function_list,
    _parse_macho,
    add_mach0_build_metadata,
    add_mach0_commands,
    add_mach0_functions,
    add_mach0_header_data,
    add_mach0_libraries,
    add_mach0_metadata,
    add_mach0_signature,
    add_mach0_versions,
    merge_macho_function_starts,
    merge_macho_objc_functions,
    parse_mach0_wx_segments,
    parse_macho_symbols,
)
from blint.lib.binary_pe import (  # noqa: F401
    _get_unwind_reg_name,
    _parse_unwind_flags,
    _parse_x64_opcode,
    _parse_x64_unwind_info,
    _pe_data_section_bytes,
    _pe_has_canary,
    _pe_section_bytes,
    _pointer_string_resolver,
    add_pe_header_data,
    add_pe_metadata,
    add_pe_optional_headers,
    add_rdata_symbols,
    parse_pe_authenticode,
    parse_pe_data,
    parse_pe_exceptions,
    parse_pe_exports,
    parse_pe_imports,
    parse_pe_load_config,
    parse_pe_symbols,
    parse_pe_wx_sections,
    process_pe_resources,
    process_pe_signature,
)
from blint.lib.binary_wasm import (  # noqa: F401
    build_wasm_callgraph,
    is_wasm_file,
    parse_wasm_metadata,
    trim_wasm_instruction_streams,
)
from blint.lib.elf_abi import analyze_elf_abi
from blint.lib.elf_dlopen import recover_runtime_dependencies, summarize_runtime_loading
from blint.lib.elf_linkmap import resolve_link_closure
from blint.lib.framework_ident import attach_frameworks
from blint.lib.jni import parse_static_jni_surface
from blint.lib.utils import (
    demangle_symbolic_name,
    enum_to_str,
)
from blint.logger import LOG

# Bionic ELF facts (02/A). Every constant is confirmed at a named tag, not
# copied: the DT_ANDROID_* tags from bionic's elf.h (NDK r28.2 sysroot
# usr/include/elf.h lines 235-253, identical in AOSP bionic
# libc/include/elf.h), the memtag note bits and the AArch64 GNU-property
# bits from LLVM llvm/include/llvm/BinaryFormat/ELF.h lines 1826-1873,
# which is what lld encodes from and llvm-readelf decodes with.
GNU_PROPERTY_AARCH64_FEATURE_1_AND = 0xC0000000
GNU_PROPERTY_AARCH64_FEATURE_1_BTI = 1 << 0
GNU_PROPERTY_AARCH64_FEATURE_1_PAC = 1 << 1
GNU_PROPERTY_AARCH64_FEATURE_1_GCS = 1 << 2
NT_MEMTAG_LEVEL_NONE = 0
NT_MEMTAG_LEVEL_ASYNC = 1
NT_MEMTAG_LEVEL_SYNC = 2
NT_MEMTAG_LEVEL_MASK = 3
NT_MEMTAG_HEAP = 4
NT_MEMTAG_STACK = 8
DF_TEXTREL = 0x4
PAGE_16K = 16384

# Sanitizer runtime evidence (02/A): the NDK links the sanitizer runtime
# statically into the shipped .so, so the markers appear both as imports
# (__hwasan_init) and defined exports (__asan_report_*); matching the
# dynamic symbol table either way is the fact. __cfi_check is the CFI
# instrumentation entry point a -fsanitize-cfi build defines.
SANITIZER_PREFIXES = {
    "hwasan": "__hwasan_",
    "asan": "__asan_",
    "ubsan": "__ubsan_",
    "tsan": "__tsan_",
    "msan": "__msan_",
}
CFI_SYMBOL = "__cfi_check"

# Clang's single-DSO CFI names its jump-table thunks ``<function>.cfi``;
# ``__cfi_check`` (the cross-DSO entry point the NDK emits) does not exist
# in a plain ``clang -fsanitize=cfi`` build, so the suffix is the other
# half of the CFI evidence.
CFI_JUMP_TABLE_SUFFIX = ".cfi"

# x86 CET evidence lives in the same .note.gnu.property the AArch64 reader
# decodes: GNU_PROPERTY_X86_FEATURE_1_AND (0xc0000002 in LLVM's ELF.h) with
# IBT at bit 0 and SHSTK at bit 1. lief decodes the note into
# NoteGnuProperty.X86Features features, so the bits are read through lief
# rather than re-parsed from the description bytes.
_X86_MACHINE_TYPES = {"X86_64", "I386", "AMD64"}

# glibc's stdio entry points that a C build at _FORTIFY_SOURCE=2 or higher
# routes through their ``__*_chk`` wrapper unconditionally (the wrapper
# takes a flag, not an object size). The size-checked calls (strcpy,
# snprintf, memcpy...) are not used: the compiler keeps the plain call
# whenever the destination size is unknown, so importing them says nothing
# about the build.
GLIBC_ALWAYS_FORTIFIED_IMPORTS = {
    "printf",
    "fprintf",
    "vprintf",
    "vfprintf",
    "dprintf",
    "vdprintf",
}

_AARCH64_FEATURE_NAMES = {
    GNU_PROPERTY_AARCH64_FEATURE_1_BTI: "BTI",
    GNU_PROPERTY_AARCH64_FEATURE_1_PAC: "PAC",
    GNU_PROPERTY_AARCH64_FEATURE_1_GCS: "GCS",
}


def parse_elf_wx_segments(parsed_obj: lief.ELF.Binary) -> list[dict]:
    """Collects the loadable ELF segments mapped both writable and executable.

    The GNU stack is deliberately excluded: an executable ``PT_GNU_STACK`` is
    already reported as a missing-NX finding, so covering it here would report
    the same defect twice.

    Args:
        parsed_obj: The parsed ELF binary.

    Returns:
        A list of segment descriptors with a name, normalized permissions and
        the load address, usable as evidence for the W^X check.
    """
    wx_segments: list[dict] = []
    segments = getattr(parsed_obj, "segments", None)
    if not segments or isinstance(segments, lief.lief_errors):
        return wx_segments
    with contextlib.suppress(AttributeError, TypeError):
        for index, segment in enumerate(segments):
            if segment.type != lief.ELF.Segment.TYPE.LOAD:
                continue
            writable = segment.has(lief.ELF.Segment.FLAGS.W)
            executable = segment.has(lief.ELF.Segment.FLAGS.X)
            if writable and executable:
                wx_segments.append(
                    {
                        "name": f"PT_LOAD[{index}]",
                        "permissions": _rwx_permissions_str(
                            segment.has(lief.ELF.Segment.FLAGS.R), writable, executable
                        ),
                        "virtual_address": ADDRESS_FMT.format(segment.virtual_address).strip(),
                    }
                )
    return wx_segments


def _elf_section_flags(section) -> int:
    """Return a section's raw ``sh_flags``, or 0 when lief cannot supply it."""
    with contextlib.suppress(AttributeError, TypeError, ValueError):
        return int(section.flags)
    return 0


def parse_elf_entry_point_section(parsed_obj: lief.ELF.Binary) -> str:
    """Return the name of the section containing ``e_entry``.

    PE metadata has carried ``entry_point_section`` for some time; this is the
    ELF counterpart, and the raw material for the entry-point coherence
    review. An empty string means the entry address falls in no section at
    all — which is itself the strongest form of the anomaly, so callers must
    distinguish "no section" from "not computed".
    """
    with contextlib.suppress(AttributeError, TypeError, ValueError):
        entrypoint = int(parsed_obj.header.entrypoint)
        if not entrypoint:
            return ""
        for section in parsed_obj.sections:
            start = int(section.virtual_address)
            size = int(section.size)
            if start and size and start <= entrypoint < start + size:
                return section.name
    return ""


def parse_elf_segments_summary(parsed_obj: lief.ELF.Binary) -> list[dict]:
    """Summarize every ELF program header, in program-header-table order.

    ELF metadata previously recorded only ``numberof_segments``, which is
    exactly the field an implant leaves untouched when it retypes a spare
    header in place. Exporting the table itself makes the change visible to a
    consumer diffing two builds of the same binary, and gives the layout
    reviews their evidence.
    """
    summary: list[dict] = []
    segments = getattr(parsed_obj, "segments", None)
    if not segments or isinstance(segments, lief.lief_errors):
        return summary
    with contextlib.suppress(AttributeError, TypeError, ValueError):
        for index, segment in enumerate(segments):
            summary.append(
                {
                    "index": index,
                    "type": enum_to_str(segment.type),
                    "permissions": _rwx_permissions_str(
                        segment.has(lief.ELF.Segment.FLAGS.R),
                        segment.has(lief.ELF.Segment.FLAGS.W),
                        segment.has(lief.ELF.Segment.FLAGS.X),
                    ),
                    "file_offset": int(segment.file_offset),
                    "file_size": int(segment.physical_size),
                    "virtual_address": ADDRESS_FMT.format(segment.virtual_address).strip(),
                    "virtual_size": int(segment.virtual_size),
                }
            )
    return summary


def _elf_notes_without_note_segment(parsed_obj: lief.ELF.Binary) -> list[dict]:
    """Allocated ``.note.*`` sections in a file that has no ``PT_NOTE`` at all.

    The loader reaches notes through ``PT_NOTE``; the section headers are for
    tools. Retyping the file's only ``PT_NOTE`` header into a ``PT_LOAD``
    therefore costs the attacker nothing at run time while leaving the note
    sections themselves in place, mapped, and unreachable as notes. A
    toolchain does not produce that state: it emits the segment and the
    sections together.

    The condition is deliberately "no ``PT_NOTE`` whatsoever", not "this
    section is uncovered". The Go linker legitimately emits a ``PT_NOTE``
    spanning only ``.note.go.buildid`` and leaves the adjacent
    ``.note.gnu.build-id`` outside it, so per-section coverage fires on every
    Go binary. The cost of the narrower rule is that a file with two
    ``PT_NOTE`` headers, one of them repurposed, is missed — worth paying,
    since the alternative is a rule nobody can leave enabled.

    Only ``SHF_ALLOC`` note sections count. Non-allocated notes are
    legitimately outside the load image and were never covered by a segment.
    """
    with contextlib.suppress(AttributeError, TypeError, ValueError):
        if any(segment.type == lief.ELF.Segment.TYPE.NOTE for segment in parsed_obj.segments):
            return []
        return [
            {
                "section": section.name,
                "file_offset": int(section.offset),
                "size": int(section.size),
            }
            for section in parsed_obj.sections
            if section.name.startswith(".note") and int(section.virtual_address)
        ]
    return []


def parse_elf_layout_anomalies(exe_file: str, parsed_obj: lief.ELF.Binary) -> list[dict]:
    """Collect structural contradictions in an ELF's layout.

    Each entry names the contradiction in ``kind`` and carries the addresses
    and names a reviewer needs to check it by hand. Emptiness is the normal
    result; nothing here is a verdict on its own.
    """
    anomalies: list[dict] = []
    header = getattr(parsed_obj, "header", None)
    if header is None:
        return anomalies
    with contextlib.suppress(AttributeError, TypeError, ValueError):
        entrypoint = int(header.entrypoint)
        # Relocatable objects and shared libraries without a start symbol
        # carry no meaningful entry point; there is nothing to be incoherent.
        if entrypoint and parsed_obj.header.file_type != lief.ELF.Header.FILE_TYPE.REL:
            anomalies += _elf_entry_point_anomalies(parsed_obj, entrypoint)
    for orphan in _elf_notes_without_note_segment(parsed_obj):
        anomalies.append(
            {
                "kind": "note_section_without_note_segment",
                **orphan,
                "detail": (
                    f"{orphan['section']} is part of the load image, but the file has no "
                    "PT_NOTE segment at all. A toolchain emits note sections and the PT_NOTE "
                    "that covers them together; sections outliving the segment is what "
                    "retyping that program header into something else leaves behind."
                ),
            }
        )
    anomalies += _elf_eof_executable_mapping(exe_file, parsed_obj)
    return anomalies


def _elf_entry_point_anomalies(parsed_obj: lief.ELF.Binary, entrypoint: int) -> list[dict]:
    """Entry-point coherence: where execution starts vs. where code lives."""
    containing = None
    for section in parsed_obj.sections:
        start = int(section.virtual_address)
        size = int(section.size)
        if start and size and start <= entrypoint < start + size:
            containing = section
            break
    address = ADDRESS_FMT.format(entrypoint).strip()
    if containing is None:
        return [
            {
                "kind": "entry_point_outside_any_section",
                "entrypoint": address,
                "detail": (
                    f"Execution starts at {address}, which no section header covers. Every "
                    "toolchain-produced entry point lies inside a section; an address outside "
                    "the section table is reachable through the program headers alone, which "
                    "is how code appended after the fact is mapped."
                ),
            }
        ]
    name = containing.name
    if not _elf_section_flags(containing) & SHF_EXECINSTR:
        return [
            {
                "kind": "entry_point_in_non_executable_section",
                "entrypoint": address,
                "section": name,
                "detail": (
                    f"Execution starts at {address}, inside section {name or '(unnamed)'}, "
                    "which is not marked SHF_EXECINSTR. The section table says this is not "
                    "code, and the entry point says it is; one of the two was edited."
                ),
            }
        ]
    if name not in ENTRY_POINT_SECTIONS:
        return [
            {
                "kind": "entry_point_in_unexpected_section",
                "entrypoint": address,
                "section": name,
                "detail": (
                    f"Execution starts at {address}, inside executable section {name}, which "
                    "is not one of the sections a toolchain starts a program in "
                    f"({', '.join(sorted(ENTRY_POINT_SECTIONS))}). Custom linker scripts do "
                    "reach this state legitimately, so read the section before concluding — "
                    "but relocating the entry point into a section of its own is also exactly "
                    "what an appended implant does."
                ),
            }
        ]
    return []


def _elf_eof_executable_mapping(exe_file: str, parsed_obj: lief.ELF.Binary) -> list[dict]:
    """Executable ``PT_LOAD`` segments whose file range ends at end-of-file.

    A linker lays the executable segment out before the read-only data,
    symbol table and section-header string table, so an executable mapping is
    followed by *something*. One that runs to the last byte of the file is the
    shape of code appended to a finished binary.

    The section header table sitting last is normal and deliberately not
    considered: the check is about the mapped, executable bytes.
    """
    findings: list[dict] = []
    with contextlib.suppress(AttributeError, TypeError, ValueError, OSError):
        file_size = os.path.getsize(exe_file)
        if not file_size:
            return findings
        for index, segment in enumerate(parsed_obj.segments):
            if segment.type != lief.ELF.Segment.TYPE.LOAD:
                continue
            if not segment.has(lief.ELF.Segment.FLAGS.X):
                continue
            end = int(segment.file_offset) + int(segment.physical_size)
            if end != file_size:
                continue
            findings.append(
                {
                    "kind": "executable_mapping_at_eof",
                    "segment": f"PT_LOAD[{index}]",
                    "file_offset": int(segment.file_offset),
                    "file_size": int(segment.physical_size),
                    "virtual_address": ADDRESS_FMT.format(segment.virtual_address).strip(),
                    "detail": (
                        f"PT_LOAD[{index}] is executable and its file range ends at byte "
                        f"{end}, the last byte of the file. A linker places read-only data "
                        "and the symbol tables after the code, so an executable mapping that "
                        "reaches end-of-file is code that arrived after the link."
                    ),
                }
            )
    return findings


def _elf_has_canary(parsed_obj: lief.ELF.Binary) -> bool | None:
    """Explicit canary verdict for an ELF, or None when there is no evidence.

    An ELF built with the stack protector references the runtime by name, so
    the symbol tables are the evidence. A binary stripped of every symbol
    leaves nothing to read and gets no verdict: unknown is reported as
    absent, not as clean. Symbols are read rather than
    ``get_symbol`` lookups so that "there were names to search" is itself
    observable — the verdict for a binary with symbols and no marker is
    ``False``, which is what makes CHECK_CANARY able to fire at all.
    """
    seen_named_symbol = False
    try:
        for symbol in parsed_obj.symbols:
            name = symbol.name
            if not isinstance(name, str) or not (name := name.strip()):
                continue
            seen_named_symbol = True
            if name in ELF_STACK_CHK_SYMBOLS:
                return True
    except (AttributeError, TypeError):
        return None
    return False if seen_named_symbol else None


def _is_aarch64(metadata: dict) -> bool:
    """Whether this ELF is arm64 — the only ABI with MTE and BTI/PAC.

    Arm64-only facts are emitted only for arm64 (ground rule 35): a rule
    or fact that cannot apply to an ABI must not be present for it, because
    a reader cannot tell "absent" from "not applicable" otherwise.
    """
    return str(metadata.get("machine_type") or "").upper() == "AARCH64"


def _decode_android_ident(note: dict) -> dict:
    sdk_version = note.get("sdk_version")
    with contextlib.suppress(TypeError, ValueError):
        sdk_version = int(sdk_version)
    return {
        "min_api": sdk_version,
        "ndk_version": note.get("ndk_version") or None,
        "ndk_build_number": note.get("ndk_build_number") or None,
    }


def _decode_memtag_note(note) -> dict:
    """Level and target bits of the ``.note.android.memtag`` payload.

    The note description is one u32 word: the low ``NT_MEMTAG_LEVEL_MASK``
    bits are the tag-check mode, ``NT_MEMTAG_HEAP``/``NT_MEMTAG_STACK``
    say which memory the loader must prepare for MTE (LLVM ELF.h,
    lld's ``--android-memtag-mode/heap/stack`` encoding).
    """
    description = bytes(note.description)
    value = int.from_bytes(description[:4], "little") if len(description) >= 4 else 0
    level = {
        NT_MEMTAG_LEVEL_ASYNC: "async",
        NT_MEMTAG_LEVEL_SYNC: "sync",
    }.get(value & NT_MEMTAG_LEVEL_MASK, "none")
    return {
        "level": level,
        "heap": bool(value & NT_MEMTAG_HEAP),
        "stack": bool(value & NT_MEMTAG_STACK),
    }


def _decode_aarch64_property_note(note) -> list[str]:
    """BTI/PAC/GCS names from a ``.note.gnu.property`` description.

    The note payload is a sequence of property entries
    ``(u32 type, u32 datasz, data, padding to 8 bytes)``; only
    ``GNU_PROPERTY_AARCH64_FEATURE_1_AND`` is decoded, and only the bits
    LLVM names (BTI, PAC, GCS). Unknown entries are skipped — the note
    carries other properties (stack size, no-copy-on-protected) that are
    not Android facts.
    """
    data = bytes(note.description)
    features: list[str] = []
    offset = 0
    with contextlib.suppress(struct.error):
        while offset + 8 <= len(data):
            prop_type, data_size = struct.unpack_from("<II", data, offset)
            offset += 8
            if prop_type == GNU_PROPERTY_AARCH64_FEATURE_1_AND and data_size >= 4:
                value = int.from_bytes(data[offset : offset + 4], "little")
                features = [name for bit, name in _AARCH64_FEATURE_NAMES.items() if value & bit]
                break
            offset += data_size + (8 - (data_size % 8)) % 8
    return features


def parse_android_sanitizers(symbol_names: set[str]) -> dict | None:
    """Sanitizer runtime markers in the dynamic symbol table (02/A)."""
    found = sorted(
        kind
        for kind, prefix in SANITIZER_PREFIXES.items()
        if any(name.startswith(prefix) for name in symbol_names)
    )
    result = {"sanitizers": found, "cfi": CFI_SYMBOL in symbol_names}
    return result if (found or result["cfi"]) else None


def parse_android_fortify(symbol_names: set[str]) -> dict | None:
    """bionic ``__*_chk`` imports (02/A).

    The FORTIFY annotation (FORTIFIED_LIBC_IN_USE) reviews the same
    evidence; the fact records the names. ``__stack_chk_*`` is the canary,
    deliberately excluded here as there.
    """
    fortified = _fortify_chk_names(symbol_names)
    return {"symbols": fortified} if fortified else None


def _elf_symbol_names(metadata: dict) -> set[str]:
    """Names from both metadata symbol buckets.

    The sanitizer, CFI and FORTIFY facts read symbol names, and a static
    build carries its evidence in ``.symtab`` while a dynamic one carries it
    in the dynamic table (as imports or, for a statically linked runtime,
    defined symbols), so the neutral facts read both buckets.
    """
    names: set[str] = set()
    for key in ("dynamic_symbols", "symtab_symbols"):
        for entry in metadata.get(key) or []:
            if isinstance(entry, dict) and entry.get("name"):
                names.add(str(entry["name"]))
    return names


def _fortify_chk_names(symbol_names: set[str]) -> list[str]:
    """The ``__*_chk`` fortify wrapper names, the Android list reused."""
    return sorted(
        name
        for name in symbol_names
        if name.startswith("__") and name.endswith("_chk") and not name.startswith("__stack_chk")
    )


def parse_elf_fortify(symbol_names: set[str], imported_names: set[str], libc: str) -> dict:
    """FORTIFY state from the wrapper symbols, for every ELF.

    ``fortified`` means a ``__*_chk`` wrapper exists in either symbol
    bucket. ``unfortified`` is claimed only for glibc builds: the binary
    imports a stdio call that glibc's headers route through its wrapper
    whenever ``_FORTIFY_SOURCE`` is 2 or higher (``printf`` and relatives),
    and no wrapper exists anywhere. Everything else is ``not determined``:
    a static binary or one with no such import shows neither shape; musl
    ships no ``__*_chk`` functions at all; and bionic only calls a wrapper
    when the destination size is known, so a bionic binary without
    wrappers may still have been built with fortify.

    Levels 2 and 3 are not told apart. Both call the same wrappers: level 3
    only changes how the object-size argument is computed, and a level 2
    build already imports ``__memcpy_chk`` and ``__memset_chk`` whenever the
    destination size is known and the length is not.
    """
    fortified = _fortify_chk_names(symbol_names)
    reason = None
    if fortified:
        status = "fortified"
    elif libc == "musl":
        status, reason = "not determined", "musl_has_no_chk_wrappers"
    elif libc == "bionic":
        status, reason = "not determined", "bionic_wrappers_need_known_sizes"
    elif imported_names & GLIBC_ALWAYS_FORTIFIED_IMPORTS:
        status = "unfortified"
    else:
        status, reason = "not determined", "no_fortifiable_imports"
    return {"status": status, "reason": reason, "symbols": fortified}


def _decode_x86_cet(parsed_obj: lief.ELF.Binary) -> dict:
    """IBT and SHSTK bits from the x86 GNU property note, via lief.

    ``-fcf-protection=full`` makes the linker record
    GNU_PROPERTY_X86_FEATURE_1_AND with both bits; ``=none`` leaves the
    note without them or drops it entirely, and either way the loader
    enables nothing, so "note absent" and "bits absent" both report false
    rather than unknown.
    """
    ibt = False
    shstk = False
    with contextlib.suppress(AttributeError, TypeError):
        for note in parsed_obj.notes:
            if "GNU_PROPERTY" not in str(getattr(note, "type", "")):
                continue
            for prop in note.properties:
                if "X86_FEATURE" not in str(getattr(prop, "type", "")):
                    continue
                for _flag, feature in prop.features:
                    token = str(feature).rsplit(".", 1)[-1].strip().upper()
                    if token == "IBT":
                        ibt = True
                    elif token == "SHSTK":
                        shstk = True
    return {"ibt": ibt, "shstk": shstk}


def parse_memory_safety(parsed_obj: lief.ELF.Binary, metadata: dict) -> dict:
    """Format-neutral memory-safety facts for every ELF.

    The Android facts keep their own sanitizer and fortify keys for
    compatibility; this block is the one every ELF carries, whatever libc
    or linkage it was built for. Sanitizer absence means "no runtime
    evidence", not "not instrumented": trap-mode UBSan and minimal runtimes
    link no marker symbols, so their absence cannot be told apart from
    their absence of evidence. The stack-clash fact joins this block only
    under ``--disassemble`` (see ``parse_stack_clash_protection``).
    """
    symbol_names = _elf_symbol_names(metadata)
    imported_names = {
        str(entry["name"])
        for entry in metadata.get("dynamic_symbols") or []
        if isinstance(entry, dict) and entry.get("name") and entry.get("is_imported")
    }
    libc = "glibc"
    if metadata.get("is_targeting_android") or isinstance(metadata.get("android"), dict):
        libc = "bionic"
    elif metadata.get("is_musl"):
        libc = "musl"
    else:
        with contextlib.suppress(AttributeError, TypeError):
            if any("musl" in str(lib) for lib in parsed_obj.libraries):
                libc = "musl"
    facts: dict = {
        "sanitizers": sorted(
            kind
            for kind, prefix in SANITIZER_PREFIXES.items()
            if any(name.startswith(prefix) for name in symbol_names)
        ),
        "cfi": CFI_SYMBOL in symbol_names
        or any(name.endswith(CFI_JUMP_TABLE_SUFFIX) for name in symbol_names),
        "fortify": parse_elf_fortify(symbol_names, imported_names, libc),
    }
    if str(metadata.get("machine_type") or "").upper() in _X86_MACHINE_TYPES:
        facts["cet"] = _decode_x86_cet(parsed_obj)
    return facts


def parse_android_unwind(parsed_obj: lief.ELF.Binary) -> dict | None:
    """Unwind-table presence (02/A): .eh_frame / .ARM.exidx / .gnu_debugdata.

    ``.eh_frame`` on every ABI, ``.ARM.exidx`` on arm32; ``.gnu_debugdata``
    is the mini-debuginfo a release build ships alongside a stripped
    symbol table. Only present sections are named.
    """
    with contextlib.suppress(AttributeError, TypeError):
        names = {section.name for section in parsed_obj.sections}
        result = {
            "eh_frame": ".eh_frame" in names,
            "arm_exidx": ".ARM.exidx" in names,
            "gnu_debugdata": ".gnu_debugdata" in names,
        }
        if any(result.values()):
            return result
    return None


def parse_shadow_call_stack(metadata: dict) -> dict | None:
    """arm64 shadow-call-stack prologue/epilogue evidence (02/A), text-based.

    A ``-fsanitize=shadow-call-stack`` function keeps its return address on
    a separate stack held in x18, so the disassembly shows a store through
    ``[x18`` in the prologue and a load through ``[x18`` before the return
    (measured on an NDK r28 build: ``str x30, [x18], #0x8`` /
    ``ldr x30, [x18, #-0x8]!``). Nyxstone provides no register metadata
    (AGENTS.md), so this is a match on the assembly text of each
    disassembled function, and it only runs when ``--disassemble`` did.
    """
    disassembled = metadata.get("disassembled_functions")
    if not isinstance(disassembled, dict) or not disassembled:
        return None
    functions = []
    for func_key, func_data in disassembled.items():
        assembly = func_data.get("assembly") if isinstance(func_data, dict) else None
        if not assembly:
            continue
        has_store = False
        has_load = False
        for line in str(assembly).splitlines():
            parts = line.split(maxsplit=1)
            if len(parts) != 2 or "[x18" not in parts[1]:
                continue
            mnemonic = parts[0].strip()
            if not parts[1].startswith("x30"):
                continue
            if mnemonic in ("str", "stur"):
                has_store = True
            elif mnemonic in ("ldr", "ldur"):
                has_load = True
        if has_store and has_load:
            functions.append(func_data.get("name") or func_key)
    if not functions:
        return None
    return {"functions": sorted(functions)[:64], "function_count": len(functions)}


# Stack-clash probing works in page-sized steps (GCC and Clang probe every
# 4 KiB on x86 and AArch64 alike), so a function whose frame grows by less
# than a page needs no probe and says nothing about the flag.
STACK_PROBE_PAGE = 4096
# A probe is the store that touches the new stack page after the stack
# pointer moves and before control leaves the straight-line code: next to
# the adjustment in the x86 loops, two instructions later in Clang's
# AArch64 loop (``sub sp, sp, #1, lsl #12``; ``cmp sp, x9``;
# ``str xzr, [sp]``), and up to ten later where GCC schedules other work
# first (glibc's aarch64 build).
_PROBE_WINDOW = 16
_BRANCH_MNEMONICS = ("b", "bl", "blr", "br", "ret", "call", "jmp", "cbz", "cbnz", "tbz", "tbnz")
# GCC schedules unrelated instructions before the register save that acts
# as its AArch64 probe, so that store is looked for further out. A wider
# window only leaves more frames unclassified; it never adds a verdict.
_IMPLICIT_PROBE_WINDOW = 8
# GCC on AArch64 probes at the caller-guard offset, Clang at the new top.
_AARCH64_PROBE_OFFSETS = {0, 1024}
# GCC's AArch64 guard size (64 KiB by default): below it, a register save
# at the new stack top is all the probing GCC emits; at or above it GCC
# always adds an explicit ``str xzr`` probe.
_AARCH64_GCC_GUARD = 65536

_X86_SUB_SP_RE = re.compile(rf"^(?:rsp|esp), ({_IMM})$")
_X86_OR_PROBE_RE = re.compile(rf"^(?:\w+ ptr )?\[(?:rsp|esp)(?: ?[+-] ?{_IMM})?\], ({_IMM})$")
_X86_MOV_PROBE_RE = re.compile(rf"^(?:\w+ ptr )?\[(?:rsp|esp)\], ({_IMM})$")
_AARCH64_SUB_SP_RE = re.compile(rf"^sp, sp, (?:({_IMM})(?:, lsl ({_IMM}))?|(x\d+))$")
_AARCH64_MOV_IMM_RE = re.compile(rf"^(x\d+), ({_IMM})$")
_AARCH64_PROBE_RE = re.compile(rf"^xzr, \[sp(?:, ({_IMM}))?\]$")
# Any register store this close to the new stack top: GCC on AArch64 counts
# the callee-saved register store after the allocation as the probe, and the
# same store appears in an unprotected build, so such a frame proves nothing.
_AARCH64_SP_STORE_RE = re.compile(rf"^(?:[xwqd]\d+|x29|x30)(?:, [xwqd]\d+)?, \[sp(?:, ({_IMM}))?\]$")


def _stack_probe_line(machine: str, mnemonic: str, operands: str) -> bool:
    """Whether one instruction stores zero to the top of the stack."""
    if machine == "AARCH64":
        match = _AARCH64_PROBE_RE.match(operands) if mnemonic == "str" else None
        return bool(match) and (_parse_immediate(match.group(1) or "0") in _AARCH64_PROBE_OFFSETS)
    if mnemonic == "or":
        # OR with zero changes nothing; compilers emit it only to probe.
        match = _X86_OR_PROBE_RE.match(operands)
    elif mnemonic == "mov":
        # A zeroing MOV is ordinary code too, so only the exact stack top
        # counts (Clang's probe shape).
        match = _X86_MOV_PROBE_RE.match(operands)
    else:
        return False
    return bool(match) and _parse_immediate(match.group(1)) == 0


def _stack_sub_amount(
    machine: str, mnemonic: str, operands: str, registers: dict[str, int]
) -> int | None:
    """Bytes one instruction subtracts from the stack pointer, if it does."""
    if mnemonic != "sub":
        return None
    if machine == "AARCH64":
        match = _AARCH64_SUB_SP_RE.match(operands)
        if not match:
            return None
        if match.group(3):
            # GCC loads frames that do not fit an immediate into a scratch
            # register first: ``mov x13, #20016``; ``sub sp, sp, x13``.
            return registers.get(match.group(3))
        amount = _parse_immediate(match.group(1))
        shift = _parse_immediate(match.group(2)) if match.group(2) else 0
        return None if amount is None or shift is None else amount << shift
    match = _X86_SUB_SP_RE.match(operands)
    return _parse_immediate(match.group(1)) if match else None


def _implicit_aarch64_probe(mnemonic: str, operands: str) -> bool:
    """Whether a register store lands where GCC's AArch64 probe would."""
    if mnemonic not in ("str", "stp", "stur"):
        return False
    match = _AARCH64_SP_STORE_RE.match(operands)
    if not match:
        return False
    offset = _parse_immediate(match.group(1) or "0")
    return offset is not None and 0 <= offset <= max(_AARCH64_PROBE_OFFSETS)


def _classify_frame(machine: str, assembly: str) -> str | None:
    """``probed``, ``unprobed`` or ``ambiguous`` for a function whose frame
    crosses a page, ``None`` for any other function."""
    lines = []
    for line in assembly.splitlines():
        parts = line.strip().split(maxsplit=1)
        if len(parts) == 2:
            lines.append((parts[0].lower(), parts[1].strip()))
    registers: dict[str, int] = {}
    large = probed = implicit = False
    for index, (mnemonic, operands) in enumerate(lines):
        if machine == "AARCH64" and mnemonic == "mov":
            if match := _AARCH64_MOV_IMM_RE.match(operands):
                value = _parse_immediate(match.group(2))
                if value is not None:
                    registers[match.group(1)] = value
            continue
        amount = _stack_sub_amount(machine, mnemonic, operands, registers)
        if amount is None:
            continue
        window = []
        for following in lines[index + 1 : index + 1 + _PROBE_WINDOW]:
            if following[0] in _BRANCH_MNEMONICS or following[0].startswith(("b.", "j")):
                break
            window.append(following)
        if any(_stack_probe_line(machine, m, o) for m, o in window):
            probed = True
        if amount >= STACK_PROBE_PAGE:
            large = True
            wide = lines[index + 1 : index + 1 + _IMPLICIT_PROBE_WINDOW]
            if (
                machine == "AARCH64"
                and amount < _AARCH64_GCC_GUARD
                and any(_implicit_aarch64_probe(m, o) for m, o in wide)
            ):
                implicit = True
    if not large:
        return None
    if probed:
        return "probed"
    return "ambiguous" if implicit else "unprobed"


def parse_stack_clash_protection(metadata: dict) -> dict:
    """Stack-clash protection verdict from disassembled functions.

    ``-fstack-clash-protection`` leaves no note and no symbol. Its evidence
    is the probe store the compilers place right after each page-sized
    stack adjustment in functions whose frame crosses a page: GCC
    ``or qword ptr [rsp], 0`` and Clang ``mov qword ptr [rsp], 0`` on x86,
    ``str xzr, [sp, #1024]`` and ``str xzr, [sp]`` on AArch64. Nyxstone
    gives text only, so the match is on the assembly text, and the whole
    fact exists only when ``--disassemble`` ran.

    Only functions with a page-crossing frame are classified, each as
    probed or unprobed: ``protected`` when all of them probe,
    ``unprotected`` when none does, ``partial`` when the binary mixes both
    (objects built with different flags). On AArch64 a frame smaller than
    GCC's 64 KiB guard whose allocation is followed by a register save at
    the new stack top is left out: GCC uses that store as the probe, and an
    unprotected build emits the same store. A binary with no classified function cannot show the
    flag either way and reports ``not determined``.
    """
    machine = str(metadata.get("machine_type") or "").upper()
    probed: list[str] = []
    unprobed: list[str] = []
    disassembled = metadata.get("disassembled_functions")
    if isinstance(disassembled, dict):
        for func_key, func_data in disassembled.items():
            if not isinstance(func_data, dict) or not func_data.get("assembly"):
                continue
            verdict = _classify_frame(machine, str(func_data["assembly"]))
            name = str(func_data.get("name") or func_key)
            if verdict == "probed":
                probed.append(name)
            elif verdict == "unprobed":
                unprobed.append(name)
    if probed and unprobed:
        status = "partial"
    elif probed:
        status = "protected"
    elif unprobed:
        status = "unprotected"
    else:
        status = "not determined"
    return {
        "status": status,
        "reason": "no_function_with_page_crossing_frame" if status == "not determined" else None,
        "probed_function_count": len(probed),
        "unprobed_function_count": len(unprobed),
        "probed_functions": sorted(probed)[:32],
        "unprobed_functions": sorted(unprobed)[:32],
    }


def parse_android_facts(parsed_obj: lief.ELF.Binary, metadata: dict) -> dict | None:
    """Collects the bionic-specific ELF facts (02/A) under one nested key.

    The block is emitted only for binaries that target Android
    (``.note.android.ident`` present), and the arm64-only facts (memtag,
    aarch64_features) only for AArch64 — a fact that cannot apply to an
    ABI is not present for it, so "absent" never means "not checked"
    (ground rule 35). Everything here is additive: the notes, dynamic
    entries and segments it reads are parsed once by the existing paths.

    The fact shapes mirror what ``llvm-readelf -a --notes`` reports for
    the same file (the ``elf_facts_probe.py`` oracle), so a disagreement
    is a bug by definition, not a formatting difference.
    """
    if not metadata.get("is_targeting_android"):
        return None
    facts: dict = {}
    for note in metadata.get("notes") or []:
        if note.get("type") == "ANDROID_IDENT" and "android_ident" not in facts:
            facts["android_ident"] = _decode_android_ident(note)
    # The memtag and GNU-property payloads are decoded from the LIEF note
    # objects directly: the metadata notes dict carries a truncated
    # description string, and these payloads must not depend on that cap.
    with contextlib.suppress(AttributeError, TypeError):
        for note in parsed_obj.notes:
            note_type = str(getattr(note, "type", ""))
            if "ANDROID_MEMTAG" in note_type and _is_aarch64(metadata):
                facts["memtag"] = _decode_memtag_note(note)
            elif "GNU_PROPERTY_TYPE_0" in note_type and _is_aarch64(metadata):
                if features := _decode_aarch64_property_note(note):
                    facts["aarch64_features"] = features
    packed: dict[str, dict] = {}
    text_relocations = False
    needed_absolute = False
    soname = None
    dynamic_entries = getattr(parsed_obj, "dynamic_entries", None)
    if dynamic_entries and not isinstance(dynamic_entries, lief.lief_errors):
        sizes: dict[str, int] = {}
        for entry in dynamic_entries:
            tag = entry.tag
            name = str(tag).removeprefix("TAG.")
            if name in (
                "ANDROID_REL",
                "ANDROID_RELA",
                "RELR",
                "ANDROID_RELR",
            ):
                packed.setdefault(name, {})
            elif name in ("ANDROID_RELSZ", "ANDROID_RELASZ", "RELRSZ", "ANDROID_RELRSZ"):
                sizes[name] = int(entry.value)
            elif name in ("RELRENT", "ANDROID_RELRENT"):
                sizes.setdefault("_entry_size", int(entry.value))
            elif tag == lief.ELF.DynamicEntry.TAG.TEXTREL:
                text_relocations = True
            elif tag == lief.ELF.DynamicEntry.TAG.FLAGS:
                text_relocations = text_relocations or bool(int(entry.value) & DF_TEXTREL)
            elif tag == lief.ELF.DynamicEntry.TAG.NEEDED:
                if "/" in (entry.name or ""):
                    needed_absolute = True
            elif tag == lief.ELF.DynamicEntry.TAG.SONAME and not soname:
                soname = entry.name or None
    if packed:
        # The APS2 table has no entry-size tag (bionic decodes the packed
        # stream itself), so the honest fact is the table size in bytes;
        # RELR carries DT_RELRENT and a count is derived from it.
        kind_names = {
            "ANDROID_REL": "aps2",
            "ANDROID_RELA": "aps2",
            "RELR": "relr",
            "ANDROID_RELR": "android_relr",
        }
        size_tags = {
            "aps2": ("ANDROID_RELSZ", "ANDROID_RELASZ"),
            "relr": ("RELRSZ",),
            "android_relr": ("ANDROID_RELRSZ",),
        }
        result: list[dict] = []
        for raw_kind, kind in kind_names.items():
            if raw_kind not in packed:
                continue
            kind_fact = {"kind": kind}
            for size_tag in size_tags[kind]:
                if size_tag in sizes:
                    kind_fact["size_bytes"] = sizes[size_tag]
                    break
            if kind_fact["kind"] != "aps2" and sizes.get("_entry_size"):
                kind_fact["entry_count"] = kind_fact.get("size_bytes", 0) // sizes["_entry_size"]
            result.append(kind_fact)
        facts["packed_relocations"] = result
    facts["text_relocations"] = text_relocations
    facts["soname"] = soname
    facts["needed_absolute"] = needed_absolute
    segments = getattr(parsed_obj, "segments", None)
    if segments and not isinstance(segments, lief.lief_errors):
        loads = [s for s in segments if s.type == lief.ELF.Segment.TYPE.LOAD]
        if loads:
            # 16 KB page-size fact (01/B): the minimum PT_LOAD p_align and
            # whether every LOAD's p_offset and p_vaddr are congruent
            # modulo 16384. The fact is emitted for every Android ELF; the
            # 16 KB *verdict* is 64-bit-only, and lives in the app summary.
            min_align = min(int(s.alignment) for s in loads)
            incongruent = [
                {"offset": int(s.file_offset), "vaddr": int(s.virtual_address)}
                for s in loads
                if (int(s.file_offset) - int(s.virtual_address)) % PAGE_16K
            ]
            facts["page_alignment"] = {
                "min_load_align": min_align,
                "mod_16384_incongruent": incongruent,
            }
        for segment in segments:
            if segment.type == lief.ELF.Segment.TYPE.TLS:
                facts["tls_segment"] = {
                    "align": int(segment.alignment),
                    "vaddr": int(segment.virtual_address),
                }
                break
    symbol_names = {
        entry.get("name")
        for entry in metadata.get("dynamic_symbols") or []
        if isinstance(entry, dict) and entry.get("name")
    }
    if sanitizers := parse_android_sanitizers(symbol_names):
        facts["sanitizers"] = sanitizers
    if fortify := parse_android_fortify(symbol_names):
        facts["fortify"] = fortify
    if unwind := parse_android_unwind(parsed_obj):
        facts["unwind"] = unwind
    # Static JNI surface (A5.1): Java_* exports and the lifecycle hooks,
    # decoded from the dynamic symbols both twins of a build carry.
    if jni_surface := parse_static_jni_surface(metadata.get("dynamic_symbols")):
        facts["jni"] = jni_surface
    return facts


def add_elf_metadata(exe_file: str, metadata: dict, parsed_obj: lief.ELF.Binary) -> dict:
    """Adds ELF metadata to the given metadata dictionary.

    Args:
        exe_file (str): The path of the executable file.
        metadata (dict): The dictionary to store the metadata.
        parsed_obj: The parsed object representing the ELF binary.

    Returns:
        dict: The updated metadata dictionary.
    """
    metadata["binary_type"] = "ELF"
    header = parsed_obj.header
    identity = header.identity
    metadata["magic"] = ("{:<02x} " * 8).format(*identity[:8]).strip()
    metadata = add_elf_header(header, metadata)
    metadata["name"] = exe_file
    metadata["imagebase"] = parsed_obj.imagebase
    if parsed_obj.interpreter:
        metadata["interpreter"] = parsed_obj.interpreter
        if "mipsel" in parsed_obj.interpreter:
            metadata["is_mips"] = True
        if "musl" in parsed_obj.interpreter:
            metadata["is_musl"] = True
    metadata["is_pie"] = parsed_obj.is_pie
    # ELF header type as a plain name (EXEC/DYN/REL). PIE and NX are
    # properties of loadable images: a REL object has no segments and a DYN
    # without an interpreter is a shared library, so rules keyed on those
    # facts need the type to ask whether they apply at all (F1a).
    metadata["elf_type"] = enum_to_str(parsed_obj.header.file_type)
    metadata["is_targeting_android"] = parsed_obj.is_targeting_android
    metadata["virtual_size"] = parsed_obj.virtual_size
    metadata["has_nx"] = parsed_obj.has_nx
    metadata["wx_segments"] = parse_elf_wx_segments(parsed_obj)
    # Layout coherence: the raw program-header table, where execution starts,
    # and the contradictions between them. Additive, and computed for every
    # ELF because they cost one pass over headers that are already parsed.
    metadata["entry_point_section"] = parse_elf_entry_point_section(parsed_obj)
    metadata["segments_summary"] = parse_elf_segments_summary(parsed_obj)
    metadata["layout_anomalies"] = parse_elf_layout_anomalies(exe_file, parsed_obj)
    metadata["has_interpreter"] = parsed_obj.has_interpreter
    metadata["has_notes"] = parsed_obj.has_notes
    metadata["has_overlay"] = parsed_obj.has_overlay
    metadata["use_gnu_hash"] = parsed_obj.use_gnu_hash
    metadata["use_sysv_hash"] = parsed_obj.use_sysv_hash
    metadata["eof_offset"] = parsed_obj.eof_offset
    metadata["relro"] = parse_relro(parsed_obj)
    metadata["exe_type"] = detect_exe_type(parsed_obj, metadata)
    # Stack-protector evidence, the same tristate the PE and Mach-O paths
    # use: an explicit verdict or no key at all, never a silently absent key
    # that CHECK_CANARY collapses into "protected".
    if (elf_canary := _elf_has_canary(parsed_obj)) is not None:
        metadata["has_canary"] = elf_canary
    # rpath check
    rpath = parsed_obj.get(lief.ELF.DynamicEntry.TAG.RPATH)
    if isinstance(rpath, lief.lief_errors):
        metadata["has_rpath"] = False
    elif rpath:
        metadata["has_rpath"] = True
    # runpath check
    runpath = parsed_obj.get(lief.ELF.DynamicEntry.TAG.RUNPATH)
    if isinstance(runpath, lief.lief_errors):
        metadata["has_runpath"] = False
    elif runpath:
        metadata["has_runpath"] = True
    symtab_symbols = parsed_obj.symtab_symbols
    metadata["static"] = bool(symtab_symbols and not isinstance(symtab_symbols, lief.lief_errors))
    dynamic_entries = parsed_obj.dynamic_entries
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", category=RuntimeWarning)
        metadata = add_elf_dynamic_entries(dynamic_entries, metadata)
    metadata = add_elf_symbols(metadata, parsed_obj)
    metadata["notes"] = parse_notes(parsed_obj)
    metadata["dlopen_dependencies"] = consolidate_dlopen_dependencies(metadata["notes"])
    metadata["strings"] = parse_strings(parsed_obj)
    metadata["symtab_symbols"], exe_type = parse_symbols(symtab_symbols)
    rdata_section = parsed_obj.get_section(".rodata")
    text_section = parsed_obj.get_section(".text")
    add_rdata_symbols(metadata, rdata_section, text_section, parsed_obj.sections)
    if exe_type:
        metadata["exe_type"] = exe_type
    metadata["dynamic_symbols"], exe_type = parse_symbols(parsed_obj.dynamic_symbols)
    if exe_type:
        metadata["exe_type"] = exe_type
    # Bionic-specific facts (02/A), one nested key, Android-targeting ELFs
    # only (arm64-only facts gated again inside); None on other binaries.
    # Runs after the dynamic symbol tables are in metadata because the
    # sanitizer and fortify facts read their names.
    android_facts = parse_android_facts(parsed_obj, metadata)
    if android_facts is not None:
        metadata["android"] = android_facts
    # Memory-safety facts for every ELF, the format-neutral
    # twin of the sanitizer/fortify facts above: same symbol evidence, both
    # buckets, any libc or linkage.
    metadata["memory_safety"] = parse_memory_safety(parsed_obj, metadata)
    # Framework/runtime identification (04/B, rule 38): evidence-keyed only,
    # stored under "frameworks" when anything matches. Runs after the android
    # facts (the NDK-note detector reads them) and the symbol tables.
    metadata = attach_frameworks(metadata, parsed_obj)
    metadata["functions"] = parse_functions(parsed_obj.functions)
    metadata["ctor_functions"] = parse_functions(parsed_obj.ctor_functions)
    metadata["dtor_functions"] = parse_functions(parsed_obj.dtor_functions)
    metadata["dotnet_dependencies"] = parse_overlay(parsed_obj)
    metadata["go_dependencies"], metadata["go_formulation"] = parse_go_buildinfo(parsed_obj)
    metadata["rust_dependencies"] = parse_rust_buildinfo(parsed_obj)
    metadata["graalvm_sbom"] = parse_graalvm_sbom(parsed_obj)
    # The ABI, runtime-loading and link-closure passes all read the symbol and
    # dynamic-entry buckets populated above, so they have to run last.
    metadata["abi_analysis"] = analyze_elf_abi(metadata)
    metadata["runtime_loading"] = summarize_runtime_loading(metadata)
    metadata["recovered_dependencies"] = recover_runtime_dependencies(metadata, parsed_obj)
    if RESOLVE_LINK_CLOSURE:
        # Resolution reads the filesystem the scan is running on, which is only
        # meaningful when that filesystem is the binary's intended runtime, so
        # it stays opt-in rather than firing on every parse.
        metadata["link_closure"] = resolve_link_closure(
            metadata,
            exe_file,
            root=LINK_CLOSURE_ROOT,
            extra_search_paths=LINK_CLOSURE_SEARCH_PATHS,
        )

    return metadata


def add_elf_header(header, metadata: dict) -> dict:
    """Adds ELF header data to the metadata dictionary.

    Args:
        header: The ELF header.
        metadata: The dictionary to store the metadata.

    Returns:
        The updated metadata dictionary.
    """
    if not header or isinstance(header, lief.lief_errors):
        return metadata
    try:
        eflags_str = determine_elf_flags(header)
        metadata["class"] = enum_to_str(header.identity_class)
        metadata["endianness"] = enum_to_str(header.identity_data)
        metadata["identity_version"] = enum_to_str(header.identity_version)
        metadata["identity_os_abi"] = enum_to_str(header.identity_os_abi)
        metadata["identity_abi_version"] = enum_to_str(header.identity_abi_version)
        metadata["file_type"] = enum_to_str(header.file_type)
        metadata["machine_type"] = enum_to_str(header.machine_type)
        metadata["object_file_version"] = enum_to_str(header.object_file_version)
        metadata["entrypoint"] = header.entrypoint
        for k in (
            "header_size",
            "identity_class",
            "numberof_sections",
            "numberof_segments",
            "program_header_offset",
            "program_header_size",
            "section_header_offset",
            "object_type",
            "section_header_size",
            "modes_list",
            "is_32",
            "is_64",
        ):
            if hasattr(header, k):
                metadata[k] = getattr(header, k)
        metadata["processor_flag"] = eflags_str
    except (AttributeError, TypeError, ValueError) as e:
        LOG.debug(f"Caught {type(e)}: {e} while parsing elf headers.")
    return metadata


def add_elf_symbols(metadata: dict, parsed_obj: lief.ELF.Binary) -> dict:
    """Extracts ELF symbols version information and adds it to the metadata dictionary.

    Args:
        metadata: The dictionary to store the metadata.
        parsed_obj: The parsed object representing the ELF binary.

    Returns:
        The updated metadata dictionary.
    """
    try:
        symbols_version = parsed_obj.symbols_version
        if symbols_version and not isinstance(symbols_version, lief.lief_errors):
            metadata["symbols_version"] = []
            symbol_version_auxiliary_cache: dict = {}
            for entry in symbols_version:
                symbol_version_auxiliary = entry.symbol_version_auxiliary
                if symbol_version_auxiliary and not symbol_version_auxiliary_cache.get(
                    symbol_version_auxiliary.name
                ):
                    symbol_version_auxiliary_cache[symbol_version_auxiliary.name] = True
                    metadata["symbols_version"].append(
                        {
                            "name": demangle_symbolic_name(symbol_version_auxiliary.name),
                            # Only the auxiliary entries of a version
                            # *requirement* carry a hash. The entries a library
                            # emits for the versions it defines do not, and
                            # reading the attribute unconditionally aborted the
                            # whole table for every versioned shared object.
                            "hash": getattr(symbol_version_auxiliary, "hash", None),
                            "value": entry.value,
                        }
                    )
    except (AttributeError, TypeError) as e:
        # Naming the attribute matters: this path goes silent when the parser
        # library renames a field, and an empty symbols_version block is
        # indistinguishable from a binary that genuinely has none.
        LOG.warning(
            "Symbol version table unavailable for %s (%s: %s). Version-derived "
            "components and the ABI floor will be missing from this result.",
            metadata.get("name", "binary"),
            type(e).__name__,
            e,
        )
        metadata["symbols_version"] = []
    return metadata


def add_elf_dynamic_entries(dynamic_entries, metadata: dict) -> dict:
    """Extracts ELF dynamic entries and adds them to the metadata dictionary.

    Args:
        dynamic_entries: The dynamic entries of the ELF binary.
        metadata: The dictionary to store the metadata.

    Returns:
        dict: The updated metadata dictionary.
    """
    metadata["dynamic_entries"] = []
    if isinstance(dynamic_entries, lief.lief_errors):
        return metadata
    for entry in dynamic_entries:
        if entry.tag == lief.ELF.DynamicEntry.TAG.NULL:
            continue
        if entry.tag in [
            lief.ELF.DynamicEntry.TAG.SONAME,
            lief.ELF.DynamicEntry.TAG.NEEDED,
        ]:
            metadata["dynamic_entries"].append(
                {
                    "name": demangle_symbolic_name(entry.name),
                    "tag": enum_to_str(entry.tag),
                    "value": entry.value,
                }
            )
            if "netcoredeps" in entry.name:
                metadata["exe_type"] = "dotnetbinary"
        if entry.tag in [
            lief.ELF.DynamicEntry.TAG.RUNPATH,
        ]:
            metadata["dynamic_entries"].append(
                {
                    "name": "runpath",
                    "tag": enum_to_str(entry.tag),
                    "value": entry.runpath,
                }
            )
        if entry.tag in [
            lief.ELF.DynamicEntry.TAG.RPATH,
        ]:
            metadata["dynamic_entries"].append(
                {
                    "name": "rpath",
                    "tag": enum_to_str(entry.tag),
                    "value": entry.rpath,
                }
            )
    return metadata


def determine_elf_flags(header) -> str:
    """Determines the ELF flags based on the given ELF header.
    Args:
        header: The ELF header.

    Returns:
        A string representing the ELF flags.
    """
    eflags_str = ""
    if header.machine_type == lief.ELF.ARCH.ARM and hasattr(header, "arm_flags_list"):
        eflags_str = ", ".join([enum_to_str(s) for s in header.arm_flags_list])
    if header.machine_type in [
        lief.ELF.ARCH.MIPS,
        lief.ELF.ARCH.MIPS_RS3_LE,
        lief.ELF.ARCH.MIPS_X,
    ]:
        eflags_str = ", ".join([enum_to_str(s) for s in header.flags_list])
    if header.machine_type == lief.ELF.ARCH.PPC64:
        eflags_str = ", ".join([enum_to_str(s) for s in header.ppc64_flags_list])
    if header.machine_type == lief.ELF.ARCH.HEXAGON:
        eflags_str = ", ".join([enum_to_str(s) for s in header.hexagon_flags_list])
    return eflags_str
