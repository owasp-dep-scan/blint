"""ELF parsing: headers, segments, dynamic entries and layout anomalies.

Split out of ``binary.py``; imports only ``binary_common`` (and, for the
rdata symbol reader the ELF path reuses, ``binary_pe``), never the
orchestrator that imports it.
"""

# pylint: disable=too-many-lines,consider-using-f-string
import contextlib
import os
import warnings

import lief

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
from blint.lib.utils import (
    demangle_symbolic_name,
    enum_to_str,
)
from blint.logger import LOG


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
    metadata["functions"] = parse_functions(parsed_obj.functions)
    metadata["ctor_functions"] = parse_functions(parsed_obj.ctor_functions)
    metadata["dtor_functions"] = parse_functions(parsed_obj.dtor_functions)
    metadata["dotnet_dependencies"] = parse_overlay(parsed_obj)
    metadata["go_dependencies"], metadata["go_formulation"] = parse_go_buildinfo(parsed_obj)
    metadata["rust_dependencies"] = parse_rust_buildinfo(parsed_obj)
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
