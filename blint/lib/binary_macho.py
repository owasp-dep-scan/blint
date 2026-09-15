"""Mach-O parsing: slices, symbols, functions and code signature.

Split out of ``binary.py``; imports only ``binary_common``, never the
orchestrator that imports it.
"""

# pylint: disable=too-many-lines,consider-using-f-string
import contextlib
import struct
import warnings

import lief

from blint.lib.binary_common import (
    ADDRESS_FMT,
    CPU_SUBTYPE_ARM64E,
    CPU_SUBTYPE_FLAG_MASK,
    LC_CODE_SIGNATURE_CMD,
    STACK_CHK_SYMBOLS,
    VM_PROT_EXECUTE,
    VM_PROT_READ,
    VM_PROT_WRITE,
    _batch_demangle_symbol_names,
    _codesign_security_flags,
    _entry_size,
    _is_synthetic_function_name,
    _is_weak_function_name,
    _lookup_demangled,
    _parse_address,
    _primary_code_directory,
    _rwx_permissions_str,
    guess_exe_type,
    integer_to_hex_str,
    parse_functions,
    parse_go_buildinfo,
    parse_rust_buildinfo,
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
from blint.lib.codesign_macho import SUPERBLOB_MAGIC, parse_superblob, signature_summary
from blint.lib.utils import (
    enum_to_str,
)
from blint.logger import LOG


def parse_mach0_wx_segments(parsed_obj: lief.MachO.Binary) -> list[dict]:
    """Collects the Mach-O segments initially mapped both writable and executable.

    Only ``init_protection`` counts as evidence: ``max_protection`` describes
    what a segment may later be remapped to, not what it is mapped with, so a
    permissive maximum alone does not mean writable code ever existed.

    Args:
        parsed_obj: The parsed MachO binary.

    Returns:
        A list of segment descriptors with a name, normalized permissions and
        the virtual address, usable as evidence for the W^X check.
    """
    wx_segments: list[dict] = []
    with contextlib.suppress(AttributeError, TypeError):
        for segment in parsed_obj.segments:
            protection = int(segment.init_protection)
            writable = bool(protection & VM_PROT_WRITE)
            executable = bool(protection & VM_PROT_EXECUTE)
            if writable and executable:
                wx_segments.append(
                    {
                        "name": segment.name,
                        "permissions": _rwx_permissions_str(
                            bool(protection & VM_PROT_READ), writable, executable
                        ),
                        "virtual_address": ADDRESS_FMT.format(segment.virtual_address).strip(),
                    }
                )
    return wx_segments


def parse_macho_symbols(symbols) -> tuple[list[dict], str]:
    """
    Parses the symbols and determines the executable type.

    Args:
        symbols (it_symbols): A list of symbol objects to parse.

    Returns:
        tuple: A tuple containing two elements:
            - symbols_list (list): A list of symbol dictionaries.
            - exe_type (str): The determined executable type.
    """
    symbols_list: list[dict] = []
    exe_type = ""
    if not symbols or isinstance(symbols, lief.lief_errors):
        return symbols_list, exe_type
    symbols = list(symbols)
    demangled = _batch_demangle_symbol_names(symbols)
    for symbol in symbols:
        try:
            # A symbol the binary does not define is an import; this is the
            # n_type-based category LIEF computes, the same signal the
            # import-hash path reads. The field has to be recorded explicitly:
            # analyze_import_deps gates on it, and a missing key read as False
            # silently dropped every Mach-O import from the dependency graph
            # while link hygiene went on to report every declared dylib as
            # unused (the false CHECK_UNUSED_DEPENDENCIES on /usr/bin/git).
            category = str(symbol.category or "")
            is_imported = category.upper().endswith("UNDEFINED")
            # Exports are what the export trie actually offers; EXTERNAL
            # symbols without export info (e.g. __mh_execute_header in some
            # link modes) stay non-exported here.
            is_exported = bool(symbol.has_export_info)
            libname = ""
            if symbol.has_binding_info and symbol.binding_info.has_library:
                libname = symbol.binding_info.library.name
            address = (
                symbol.value
                if symbol.value > 0 or not symbol.has_binding_info
                else symbol.binding_info.address
            )
            symbol_value = ADDRESS_FMT.format(address).strip()
            symbol_name = symbol.demangled_name
            if not symbol_name or isinstance(symbol_name, lief.lief_errors):
                symbol_name = symbol.name
            symbol_name = _lookup_demangled(demangled, symbol_name)
            if not exe_type:
                exe_type = guess_exe_type(symbol_name)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", category=RuntimeWarning)
                symbols_list.append(
                    {
                        "name": (f"{libname}::{symbol_name}" if libname else symbol_name),
                        "short_name": symbol_name,
                        "category": symbol.category,
                        "type": symbol.type,
                        "num_sections": symbol.numberof_sections,
                        "description": symbol.description,
                        "address": symbol_value,
                        "is_imported": is_imported,
                        "is_exported": is_exported,
                        "export_info": {
                            "symbol": symbol_name,
                            "kind": symbol.export_info.kind,
                            "flags": str(symbol.export_info.flags),
                            "offset": ADDRESS_FMT.format(symbol.export_info.node_offset),
                            "address": ADDRESS_FMT.format(symbol.export_info.address),
                        }
                        if symbol.has_export_info
                        else None,
                        "origin": symbol.origin,
                    }
                )
        except (AttributeError, TypeError):
            continue
    return symbols_list, exe_type


def _macho_symtab_has_names(symtab_symbols: list[dict] | None) -> bool:
    """True when a Mach-O symtab carries defined, named symbols worth reading.

    ``strip`` on a Mach-O executable keeps the symbol table itself — undefined
    imports stay because dyld needs them — but removes every defined local or
    external name. Runtime markers that survive a strip (``__mh_execute_header``,
    the ``radr://`` linker notes) are not name evidence. So "has names" is the
    honest signal for whether symbol-based analysis can see anything, and the
    inverse is what ``security_properties.stripped`` reports.
    """
    for symbol in symtab_symbols or []:
        if not isinstance(symbol, dict):
            continue
        if str(symbol.get("category", "")).upper().endswith("UNDEFINED"):
            continue
        name = symbol.get("short_name") or symbol.get("name") or ""
        if not isinstance(name, str):
            continue
        name = name.strip()
        if not name or name == "__mh_execute_header" or name.startswith("radr://"):
            continue
        return True
    return False


def _macho_symtab_has_canary(symtab_symbols: list[dict] | None) -> bool:
    """True when the Mach-O symtab references the stack-protector runtime."""
    for symbol in symtab_symbols or []:
        if not isinstance(symbol, dict):
            continue
        name = symbol.get("short_name") or symbol.get("name") or ""
        if isinstance(name, str) and name.strip() in STACK_CHK_SYMBOLS:
            return True
    return False


def _macho_is_signed(parsed_obj: lief.MachO.Binary) -> bool:
    """True when the slice carries an embedded code-signature blob.

    Presence of the blob is the file-level fact; who signed it and with what
    entitlements is the SuperBlob parser's job and is deliberately not
    attempted here.
    """
    try:
        if parsed_obj.has_code_signature and parsed_obj.code_signature.size > 0:
            return True
        if parsed_obj.has_code_signature_dir and parsed_obj.code_signature_dir.size > 0:
            return True
    except (AttributeError, TypeError):
        return False
    return False


def _macho_has_pac(parsed_obj: lief.MachO.Binary) -> bool:
    """True when the slice is built for arm64e-style pointer authentication."""
    try:
        return bool(parsed_obj.support_arm64_ptr_auth)
    except (AttributeError, TypeError):
        return False


def _macho_security_properties(metadata: dict, parsed_obj: lief.MachO.Binary) -> dict:
    """Security properties for Mach-O, computed rather than defaulted.

    Every property lands in one of three buckets: computed from the file
    (reported whatever the value), not applicable to the format (omitted —
    reporting ``relro: "no"`` for a format without RELRO reads as a finding
    when it is only a vocabulary mismatch), or not implemented yet (omitted,
    with the gap recorded in ``analysis_coverage``).

    - computed: ``nx``, ``w_xor_x``, ``pie``, ``canary`` (stack-protector
      symbols in the symtab), ``stripped`` (defined, named symbols in the
      symtab — see :func:`_macho_symtab_has_names`), ``is_signed`` (embedded
      signature blob, presence-only), ``pac`` when the slice is arm64e, and —
      when the SuperBlob parsed — ``hardened_runtime``,
      ``library_validation`` and ``get_task_allow`` from the primary
      CodeDirectory flags. These three are reported as explicit booleans
      whenever the signature parsed, because for hardening properties the
      ``False`` is the finding; when the signature did not parse they are
      omitted rather than guessed.
    - not applicable: ``relro``.
    - not implemented: granular ``has_nx_stack``/``has_nx_heap``.
    """
    properties = {
        "nx": metadata.get("has_nx", False),
        # True when no segment maps the same pages writable and executable.
        "w_xor_x": not metadata.get("wx_segments"),
        "pie": metadata.get("is_pie", False),
        "canary": metadata.get("has_canary", False),
        "stripped": not _macho_symtab_has_names(metadata.get("symtab_symbols")),
        "is_signed": _macho_is_signed(parsed_obj),
    }
    if _macho_has_pac(parsed_obj):
        properties["pac"] = True
    if code_directory := _primary_code_directory(metadata.get("code_signature")):
        properties.update(_codesign_security_flags(code_directory.get("flags")))
    # Bucket (c) bookkeeping: properties a Mach-O could carry but blint does
    # not compute yet. Stating them keeps "absent from security_properties"
    # from being read as "checked and clean", and analysis_coverage echoes it.
    gaps = ["has_nx_stack", "has_nx_heap"]
    code_signature = metadata.get("code_signature")
    if (
        isinstance(code_signature, dict)
        and code_signature.get("available")
        and code_signature.get("parse_status") == "parse_failed"
    ):
        # The blob is there and blint could not read it: the signature detail
        # is a declared blind spot, never a thin "no entitlements" answer.
        gaps.append("code_signature_detail")
    metadata["security_properties_gaps"] = gaps
    return properties


def _macho_arch_name(cpu_type: str, cpu_subtype: int) -> str:
    """Human-readable slice architecture; arm64 vs arm64e must stay distinct."""
    base = (cpu_type or "unknown").lower()
    if base == "arm64":
        subtype = int(cpu_subtype or 0) & CPU_SUBTYPE_FLAG_MASK
        return "arm64e" if subtype == CPU_SUBTYPE_ARM64E else "arm64"
    return base


def _macho_symbol_signals(parsed_slice: lief.MachO.Binary) -> dict:
    """Single pass over a slice's symtab for the symbol-derived signals.

    Mirrors the metadata-dict helpers used for the primary slice
    (:func:`_macho_symtab_has_names`, :func:`_macho_symtab_has_canary`) but
    reads LIEF objects directly so non-primary slices need no metadata dict.
    The primary-slice cross-check test pins the two against each other.
    """
    total = 0
    imports = 0
    canary = False
    has_defined_names = False
    with contextlib.suppress(AttributeError, TypeError):
        for symbol in parsed_slice.symbols:
            total += 1
            name = symbol.name
            if not isinstance(name, str):
                name = ""
            if name.strip() in STACK_CHK_SYMBOLS:
                canary = True
            if str(symbol.category).upper().endswith("UNDEFINED"):
                imports += 1
            elif name and name != "__mh_execute_header" and not name.startswith("radr://"):
                has_defined_names = True
    return {
        "total": total,
        "imports": imports,
        "canary": canary,
        "has_defined_names": has_defined_names,
    }


def _macho_count(entries) -> int:
    """Length of a LIEF object list that may be a lief_errors sentinel."""
    if not entries or isinstance(entries, lief.lief_errors):
        return 0
    with contextlib.suppress(TypeError):
        return len(list(entries))
    return 0


def _macho_slice_summary(
    exe_file: str, parsed_slice: lief.MachO.Binary, index: int, is_primary: bool
) -> dict:
    """Lean identity and hardening summary for one slice of a universal binary.

    The full metadata (functions, libraries, versions, strings) stays on the
    primary slice's top-level keys; each slice entry carries only what can
    genuinely differ between slices and therefore must never be merged across
    them: identity, the security properties, per-slice encryption state,
    counters that evidence the slice was really parsed, and the slice's own
    parsed code signature (``code_signature`` — every slice has its own
    CodeDirectory, cdhash and entitlements). Keeping the entries lean also
    keeps cache entries (which inherit metadata size) small.
    """
    header = parsed_slice.header
    cpu_type = enum_to_str(header.cpu_type)
    signals = _macho_symbol_signals(parsed_slice)
    summary = {
        "index": index,
        "cpu_type": cpu_type,
        "cpu_subtype": header.cpu_subtype,
        "arch": _macho_arch_name(cpu_type, header.cpu_subtype),
        "is_primary": is_primary,
        "security_properties": {
            "nx": bool(parsed_slice.has_nx),
            "w_xor_x": not parse_mach0_wx_segments(parsed_slice),
            "pie": bool(parsed_slice.is_pie),
            "canary": signals["canary"],
            "stripped": not signals["has_defined_names"],
            "is_signed": _macho_is_signed(parsed_slice),
        },
        "functions": _macho_count(parsed_slice.functions),
        "symbols": signals["total"],
        "imports": signals["imports"],
    }
    if _macho_has_pac(parsed_slice):
        summary["security_properties"]["pac"] = True
    slice_signature = _macho_slice_signature(exe_file, parsed_slice)
    summary["code_signature"] = slice_signature
    if slice_signature.get("parse_status") == "parsed":
        summary["security_properties"].update(
            _codesign_security_flags(slice_signature.get("flags"))
        )
    with contextlib.suppress(AttributeError, TypeError):
        encryption = parsed_slice.encryption_info
        if encryption is not None and not isinstance(encryption, lief.lief_errors):
            summary["is_encrypted"] = bool(getattr(encryption, "crypt_id", 0))
    return summary


def _macho_slice_signature(exe_file: str, parsed_slice: lief.MachO.Binary) -> dict:
    """Per-slice code-signature summary; never a merged cross-slice answer."""
    try:
        if not _macho_is_signed(parsed_slice):
            return {"available": False, "parse_status": "absent"}
        code_signature = None
        if parsed_slice.has_code_signature:
            code_signature = parsed_slice.code_signature
        elif parsed_slice.has_code_signature_dir:
            code_signature = parsed_slice.code_signature_dir
        if code_signature is None:
            return {"available": False, "parse_status": "absent"}
        blob, _blob_source = _macho_signature_blob(exe_file, parsed_slice, code_signature)
        if not blob:
            return {
                "available": True,
                "parse_status": "parse_failed",
                "parse_error": "blob_unreadable",
            }
        return signature_summary(parse_superblob(blob))
    except (AttributeError, TypeError, ValueError) as e:
        LOG.debug(f"Slice signature parse failed for {exe_file}: {type(e).__name__}: {e}")
        return {"available": True, "parse_status": "parse_failed", "parse_error": type(e).__name__}


def _parse_macho(exe_file: str, metadata: dict) -> lief.MachO.Binary | None:
    """Parse a Mach-O file, summarizing every slice of a universal binary.

    ``lief.parse`` auto-selects a single slice of a fat binary, so a universal
    input was analyzed as whichever slice came first — on an arm64e system
    binary that meant PAC was reported absent because the slice carrying it
    was never looked at. This uses ``lief.MachO.parse`` and returns the
    FatBinary's first slice as the primary: the existing top-level keys keep
    describing that slice exactly as before (additive rule — consumers read
    them today), while every slice gets a per-slice summary under ``slices``.
    Slice selection is by fat index, which is deterministic.

    A slice whose summary fails is recorded for ``analysis_coverage`` and the
    remaining slices are still summarized; the file is not aborted.
    """
    fat = lief.MachO.parse(exe_file)
    if not fat or isinstance(fat, lief.lief_errors):
        # Same failure behavior as before: parse() returns early with just
        # the file path and the run-level coverage records the unit.
        return lief.parse(exe_file)
    primary = fat.at(0)
    if not primary or isinstance(primary, lief.lief_errors):
        return None
    if len(fat) <= 1:
        return primary
    metadata["is_universal"] = True
    slice_summaries: list[dict] = []
    slice_errors: list[dict] = []
    for index in range(len(fat)):
        slice_obj = fat.at(index)
        if not slice_obj or isinstance(slice_obj, lief.lief_errors):
            slice_errors.append(
                {
                    "index": index,
                    "exception_type": "LiefParseError",
                    "message": "slice not parseable",
                }
            )
            continue
        try:
            slice_summaries.append(
                _macho_slice_summary(exe_file, slice_obj, index, slice_obj is primary)
            )
        except Exception as e:  # one slice must not abort the file
            LOG.error(f"Slice {index} summary failed for {exe_file}: {type(e).__name__}: {e}")
            slice_errors.append(
                {
                    "index": index,
                    "exception_type": type(e).__name__,
                    "message": str(e),
                }
            )
    metadata["slices"] = slice_summaries
    if slice_errors:
        metadata["slice_errors"] = slice_errors
    return primary


def add_mach0_metadata(exe_file: str, metadata: dict, parsed_obj: lief.MachO.Binary) -> dict:
    """Adds MachO metadata to the given metadata dictionary.

    Args:
        exe_file: The path of the executable file.
        metadata: The dictionary to store the metadata.
        parsed_obj: The parsed object representing the MachO binary.

    Returns:
        dict: The updated metadata dictionary.
    """
    metadata["binary_type"] = "MachO"
    metadata["name"] = exe_file
    metadata["imagebase"] = parsed_obj.imagebase
    metadata["is_pie"] = parsed_obj.is_pie
    metadata["has_nx"] = parsed_obj.has_nx
    metadata["wx_segments"] = parse_mach0_wx_segments(parsed_obj)
    metadata["exe_type"] = "MachO"
    metadata = add_mach0_versions(exe_file, metadata, parsed_obj)
    if parsed_obj.has_encryption_info and (encryption_info := parsed_obj.encryption_info):
        metadata["encryption_info"] = {
            "crypt_offset": encryption_info.crypt_offset,
            "crypt_size": encryption_info.crypt_size,
            "crypt_id": encryption_info.crypt_id,
        }
    if sinfo := parsed_obj.sub_framework:
        metadata["umbrella"] = sinfo.umbrella
    if cmd := parsed_obj.rpath:
        metadata["has_rpath"] = True
        metadata["rpath"] = cmd.path
    else:
        metadata["has_rpath"] = False
    try:
        if cmd := parsed_obj.uuid:
            uuid_str = " ".join(map(integer_to_hex_str, cmd.uuid))
            metadata["uuid"] = uuid_str
    except (AttributeError, TypeError, ValueError) as e:
        LOG.debug(f"Caught {type(e)}: {e} while parsing {exe_file} Mach0 UUID.")
    metadata = add_mach0_libraries(exe_file, metadata, parsed_obj)
    metadata = add_mach0_header_data(exe_file, metadata, parsed_obj)
    metadata = add_mach0_commands(metadata, parsed_obj)
    metadata = add_mach0_functions(metadata, parsed_obj)
    metadata = add_mach0_signature(exe_file, metadata, parsed_obj)
    metadata["go_dependencies"], metadata["go_formulation"] = parse_go_buildinfo(parsed_obj)
    metadata["rust_dependencies"] = parse_rust_buildinfo(parsed_obj)
    return metadata


def add_mach0_commands(metadata: dict, parsed_obj: lief.MachO.Binary) -> dict:
    """Extracts MachO commands metadata from the parsed object and adds it to the metadata.

    Args:
        metadata: The dictionary to store the metadata.
        parsed_obj: The parsed object representing the MachO binary.

    Returns:
        The updated metadata dictionary.
    """
    metadata["has_main"] = False
    metadata["has_thread_command"] = False
    if parsed_obj.main_command:
        metadata["has_main_command"] = not isinstance(parsed_obj.main_command, lief.lief_errors)
    if parsed_obj.thread_command:
        metadata["has_thread_command"] = not isinstance(
            parsed_obj.thread_command, lief.lief_errors
        )
    # FairPlay DRM: App Store binaries encrypt __TEXT (cryptid=1). Developer,
    # ad-hoc and enterprise builds are unencrypted (cryptid=0). An encrypted
    # binary cannot be meaningfully disassembled without on-device decryption.
    with contextlib.suppress(AttributeError, TypeError):
        enc = parsed_obj.encryption_info
        if enc is not None and not isinstance(enc, lief.lief_errors):
            crypt_id = getattr(enc, "crypt_id", 0)
            metadata["is_encrypted"] = bool(crypt_id)
            metadata["encryption_info"] = {
                "crypt_id": crypt_id,
                "crypt_offset": getattr(enc, "crypt_offset", 0),
                "crypt_size": getattr(enc, "crypt_size", 0),
            }
    return metadata


def add_mach0_versions(exe_file: str, metadata: dict, parsed_obj: lief.MachO.Binary) -> dict:
    """Extracts MachO version metadata from the parsed object and adds it to the metadata.

    Args:
        exe_file: The path of the executable file.
        metadata: The dictionary to store the metadata.
        parsed_obj: The parsed object representing the MachO binary.

    Returns:
        The updated metadata dictionary.
    """
    try:
        version = parsed_obj.version_min.version if parsed_obj.version_min else ""
        sdk = parsed_obj.version_min.sdk if parsed_obj.version_min else ""
        source_version = parsed_obj.source_version.version if parsed_obj.source_version else ""
        if source_version:
            metadata["source_version"] = "{:d}.{:d}.{:d}.{:d}.{:d}".format(*source_version)
        if version:
            metadata["version"] = "{:d}.{:d}.{:d}".format(*version)
        if sdk:
            metadata["sdk"] = "{:d}.{:d}.{:d}".format(*sdk)
    except (AttributeError, IndexError, TypeError) as e:
        LOG.debug(f"Caught {type(e)}: {e} while parsing {exe_file} Mach0 version metadata.")
    return add_mach0_build_metadata(exe_file, metadata, parsed_obj)


def add_mach0_build_metadata(exe_file: str, metadata: dict, parsed_obj: lief.MachO.Binary) -> dict:
    """Extracts MachO build version metadata from the parsed object and adds it to the metadata.

    Args:
        exe_file: The path of the executable file.
        metadata: The dictionary to store the metadata.
        parsed_obj: The parsed object representing the MachO binary.

    Returns:
        The updated metadata dictionary.
    """
    try:
        build_version = parsed_obj.build_version
        if not build_version:
            return metadata
        metadata["platform"] = enum_to_str(build_version.platform)
        metadata["minos"] = "{:d}.{:d}.{:d}".format(*build_version.minos)
        metadata["sdk"] = "{:d}.{:d}.{:d}".format(*build_version.sdk)
        if tools := build_version.tools:
            metadata["tools"] = []
            for tool in tools:
                tool_str = enum_to_str(tool.tool)
                metadata["tools"].append(
                    {
                        "tool": tool_str,
                        "version": "{}.{}.{}".format(*tool.version),
                    }
                )
    except (AttributeError, IndexError, TypeError) as e:
        LOG.debug(f"Caught {type(e)}: {e} while parsing {exe_file} Mach0 build version metadata.")
    return metadata


def add_mach0_libraries(exe_file: str, metadata: dict, parsed_obj: lief.MachO.Binary) -> dict:
    """Processes the libraries of a MachO binary and adds them to the metadata dictionary.

    Args:
        exe_file: The path of the executable file.
        metadata: The dictionary to store the metadata.
        parsed_obj: The parsed object representing the MachO binary.

    Returns:
        The updated metadata dictionary.
    """
    try:
        metadata["libraries"] = []
        if not parsed_obj.libraries:
            return metadata
        for library in parsed_obj.libraries:
            current_version_str = "{:d}.{:d}.{:d}".format(*library.current_version)
            compat_version_str = "{:d}.{:d}.{:d}".format(*library.compatibility_version)
            metadata["libraries"].append(
                {
                    "name": library.name,
                    "timestamp": library.timestamp,
                    "version": current_version_str,
                    "compatibility_version": compat_version_str,
                }
            )
    except (AttributeError, IndexError, ValueError) as e:
        LOG.debug(f"Caught {type(e)}: {e} while parsing {exe_file} Mach0 libraries.")
    return metadata


def add_mach0_header_data(exe_file: str, metadata: dict, parsed_obj: lief.MachO.Binary) -> dict:
    """Extracts MachO header data from the parsed object and adds it to the metadata dictionary.

    Args:
        exe_file: The path of the executable file.
        metadata: The dictionary to store the metadata.
        parsed_obj: The parsed object representing the MachO binary.

    Returns:
        The updated metadata dictionary.
    """
    try:
        header = parsed_obj.header
        flags_str = ", ".join([enum_to_str(s) for s in header.flags_list])
        metadata["magic"] = enum_to_str(header.magic)
        metadata["is_neural_model"] = header.magic == lief.MachO.MACHO_TYPES.NEURAL_MODEL
        metadata["cpu_type"] = enum_to_str(header.cpu_type)
        metadata["cpu_subtype"] = header.cpu_subtype
        metadata["file_type"] = enum_to_str(header.file_type)
        metadata["flags"] = flags_str
        metadata["number_commands"] = header.nb_cmds
        metadata["size_commands"] = header.sizeof_cmds
        metadata["reserved"] = header.reserved
    except (AttributeError, IndexError, TypeError) as e:
        LOG.debug(f"Caught {type(e)}: {e} while parsing {exe_file} Mach0 header.")
    return metadata


def _macho_content_segment_ranges(parsed_obj) -> tuple[list, list] | None:
    """Virtual and file ranges of the content-bearing segments, or ``None``.

    Only segments with file content may classify an address. ``__PAGEZERO``
    and other zero-file-size segments are excluded from the virtual side on
    purpose: ``__PAGEZERO`` maps the entire low half of the address space, so
    counting its virtual range would make every file-relative address
    classify as absolute.
    """
    virtual_ranges = []
    file_ranges = []
    try:
        segments = list(parsed_obj.segments)
    except (AttributeError, TypeError):
        return None
    for segment in segments:
        try:
            va = int(segment.virtual_address)
            vsz = int(segment.virtual_size)
            fo = int(segment.file_offset)
            fsz = int(segment.file_size)
        except (AttributeError, TypeError, ValueError):
            continue
        if fsz <= 0:
            continue
        file_ranges.append((fo, fo + fsz))
        virtual_ranges.append((va, va + (vsz if vsz > 0 else fsz)))
    if not virtual_ranges or not file_ranges:
        return None
    return virtual_ranges, file_ranges


def _macho_imagebase_or_zero(parsed_obj) -> int:
    """The image's base virtual address, or 0 when unavailable."""
    imagebase = getattr(parsed_obj, "imagebase", 0)
    return imagebase if isinstance(imagebase, int) and imagebase > 0 else 0


def _macho_address_to_virtual(addr, ranges, imagebase: int) -> int | None:
    """Rebase one address into the virtual space, decided by segment ranges.

    The address's space is determined from the image, never from the table it
    arrived in: inside a content segment's virtual range it is already a
    virtual address and is kept; inside a file range it is file-relative and
    is rebased by ``imagebase``. An address in *both* ranges is only
    unambiguous when ``imagebase`` is 0 (the two spaces hold the same number,
    so the rebase is the identity); with a non-zero imagebase the image does
    not say what the address means and it is returned unchanged for the
    caller to count rather than guess. Addresses in neither range are
    returned unchanged for the same reason.
    """
    if not isinstance(addr, int):
        return addr
    if ranges is None:
        return addr
    virtual_ranges, file_ranges = ranges
    in_virtual = any(lo <= addr < hi for lo, hi in virtual_ranges)
    in_file = any(lo <= addr < hi for lo, hi in file_ranges)
    if in_file and not in_virtual:
        return addr + imagebase
    return addr


def _normalize_macho_function_list(
    functions: list[dict] | None, ranges, imagebase: int
) -> tuple[list[dict], dict]:
    """Rebase a Mach-O function list into one address space (the virtual one).

    Each entry's space is classified against the image's segment ranges
    (:func:`_macho_address_to_virtual`) — not against the entry's origin —
    and file-relative entries are rebased by ``imagebase``. Entries whose
    synthetic ``sub_<addr>`` name encodes the pre-rebase address are renamed
    to the rebased address so name and address stay consistent. Entries that
    collapse onto one address after rebasing are merged: a real symbol name
    wins over a synthetic one (counted as a recovered name), the largest
    known size survives, and two *named* entries at one address are both
    kept as separate entries exactly as before. Indexes are re-assigned in
    list order.

    Returns the normalized list and counters: ``rebased``,
    ``duplicates_merged``, ``names_recovered``, ``ambiguous`` (address in
    both ranges with a non-zero imagebase — left unchanged) and
    ``unresolved`` (address in neither range — left unchanged).
    """
    stats = {
        "rebased": 0,
        "duplicates_merged": 0,
        "names_recovered": 0,
        "ambiguous": 0,
        "unresolved": 0,
    }
    if ranges is not None:
        virtual_ranges, file_ranges = ranges
    else:
        virtual_ranges, file_ranges = [], []
    grouped: dict[int, list[dict]] = {}
    order: list[int] = []
    unaddressed: list[dict] = []
    for fn in functions or []:
        entry = dict(fn)
        addr = _parse_address(entry.get("address"))
        if addr is None:
            unaddressed.append(entry)
            continue
        if ranges is not None:
            in_virtual = any(lo <= addr < hi for lo, hi in virtual_ranges)
            in_file = any(lo <= addr < hi for lo, hi in file_ranges)
            if in_file and in_virtual and imagebase != 0:
                stats["ambiguous"] += 1
            elif not in_file and not in_virtual:
                stats["unresolved"] += 1
            if in_file and not in_virtual:
                rebased_addr = addr + imagebase
                name = entry.get("name")
                if _is_synthetic_function_name(name) and int(str(name)[4:], 16) == addr:
                    entry["name"] = f"sub_{rebased_addr:x}"
                addr = rebased_addr
                entry["address"] = ADDRESS_FMT.format(addr).strip()
                stats["rebased"] += 1
        bucket = grouped.get(addr)
        if bucket is None:
            grouped[addr] = [entry]
            order.append(addr)
            continue
        bucket.append(entry)
    normalized: list[dict] = []
    for addr in order:
        bucket = grouped[addr]
        kept: list[dict] = []
        dropped: list[tuple[dict, dict]] = []
        by_name: dict[str, dict] = {}
        for entry in bucket:
            if _is_weak_function_name(entry.get("name")):
                continue
            survivor = by_name.get(str(entry["name"]))
            if survivor is None:
                by_name[str(entry["name"])] = entry
                kept.append(entry)
            else:
                # The same symbol reached this address from two tables; one
                # copy usually carries the size and the other does not.
                dropped.append((entry, survivor))
        weak = [e for e in bucket if _is_weak_function_name(e.get("name"))]
        if not kept:
            kept = weak[:1]
            weak = weak[1:]
        dropped.extend((entry, kept[0]) for entry in weak)
        if dropped:
            stats["duplicates_merged"] += len(dropped)
            if by_name and weak:
                # A function that used to appear unnamed or as sub_<addr> now
                # appears under its symbol name: count the recovered identity.
                stats["names_recovered"] += 1
            for dropped_entry, survivor in dropped:
                if _entry_size(dropped_entry) > _entry_size(survivor):
                    survivor["size"] = dropped_entry.get("size")
                if survivor.get("flags") is None and dropped_entry.get("flags") is not None:
                    survivor["flags"] = dropped_entry.get("flags")
        normalized.extend(kept)
    normalized.extend(unaddressed)
    for idx, entry in enumerate(normalized):
        entry["index"] = idx
    return normalized, stats


def merge_macho_function_starts(
    functions: list[dict], symtab_symbols: list[dict], parsed_obj: lief.MachO.Binary
) -> list[dict]:
    """Augment the function list with ``LC_FUNCTION_STARTS`` entry points.

    iOS/macOS release binaries are typically stripped, leaving lief's aggregated
    ``functions`` list with little more than ``__mh_execute_header``. The
    ``LC_FUNCTION_STARTS`` load command records the entry address of every
    function regardless of symbol stripping. We merge those addresses in,
    reusing any name already known for the address (from a surviving symbol) and
    synthesising a ``sub_<address>`` name otherwise, so the disassembler can
    recover and link the full set of functions.

    Every load-command entry and symtab address is classified against the
    image's segment ranges by :func:`_macho_address_to_virtual` and expressed
    as a virtual address before it is used, so the appended entries are in
    one space regardless of which space a source table used (P5.1: lief's
    aggregate mixes symtab virtual addresses with file-relative
    function-starts offsets without normalising). Entries lief left nameless
    adopt a surviving symbol's name for their address. The caller runs
    :func:`_normalize_macho_function_list` over the merged result, which
    rebases the incoming entries into the same space and collapses the
    duplicates that mixing created.
    """
    functions = list(functions or [])
    ranges = _macho_content_segment_ranges(parsed_obj)
    imagebase = _macho_imagebase_or_zero(parsed_obj)
    known_addresses = set()
    for fn in functions:
        addr = _parse_address(fn.get("address"))
        if addr is not None:
            known_addresses.add(addr)

    # Address -> best available symbol name, used to label recovered entries.
    # Symtab addresses are classified through the same segment-range rule as
    # everything else rather than assumed to already be virtual.
    address_names = {}
    for symbol in symtab_symbols or []:
        addr = _macho_address_to_virtual(_parse_address(symbol.get("address")), ranges, imagebase)
        name = symbol.get("short_name") or symbol.get("name")
        if addr and name and addr not in address_names:
            address_names[addr] = name

    # Pre-existing entries lief left nameless (its aggregate keeps the address
    # but not the symbol) adopt the surviving symbol's name here, before the
    # discovery merge would label them sub_<addr>: on an unstripped dylib the
    # symtab name is right there and dropping it reads as a stripped binary.
    for fn in functions:
        name = fn.get("name")
        addr = _macho_address_to_virtual(_parse_address(fn.get("address")), ranges, imagebase)
        if addr is None:
            continue
        if not name or _is_synthetic_function_name(name):
            symbol_name = address_names.get(addr)
            if symbol_name:
                fn["name"] = symbol_name

    start_addresses = []
    with contextlib.suppress(AttributeError, TypeError):
        fs = parsed_obj.function_starts
        if fs is not None and not isinstance(fs, lief.lief_errors):
            for entry in fs.functions:
                addr = entry.address if hasattr(entry, "address") else entry
                if isinstance(addr, int):
                    start_addresses.append(addr)

    next_index = len(functions)
    for addr in sorted({_macho_address_to_virtual(a, ranges, imagebase) for a in start_addresses}):
        if addr in known_addresses:
            continue
        known_addresses.add(addr)
        functions.append(
            {
                "index": next_index,
                "name": address_names.get(addr, f"sub_{addr:x}"),
                "address": ADDRESS_FMT.format(addr).strip(),
                "size": 0,
                "flags": None,
            }
        )
        next_index += 1
    return functions


def merge_macho_objc_functions(metadata: dict) -> dict:
    """Seed/label functions from recovered Objective-C method implementations.

    Each recovered implementation address is added as a function (when not
    already present) and, when an entry was only synthesised as ``sub_<addr>``
    from ``LC_FUNCTION_STARTS``, its name is upgraded to the readable
    ``-[Class selector]`` form.
    """
    objc_metadata = metadata.get("objc_metadata")
    if not objc_metadata:
        return metadata
    method_imps = objc_metadata.get("method_imps")
    if not method_imps:
        return metadata

    functions = list(metadata.get("functions") or [])
    by_address = {}
    for fn in functions:
        addr = _parse_address(fn.get("address"))
        if addr is not None:
            by_address[addr] = fn

    next_index = len(functions)
    for imp in method_imps:
        addr = imp.get("address")
        name = imp.get("name")
        if not isinstance(addr, int) or not name:
            continue
        existing = by_address.get(addr)
        if existing is None:
            entry = {
                "index": next_index,
                "name": name,
                "address": ADDRESS_FMT.format(addr).strip(),
                "size": 0,
                "flags": None,
            }
            functions.append(entry)
            by_address[addr] = entry
            next_index += 1
        elif str(existing.get("name", "")).startswith("sub_"):
            existing["name"] = name
    metadata["functions"] = functions
    return metadata


def add_mach0_functions(metadata: dict, parsed_obj: lief.MachO.Binary) -> dict:
    """Extracts MachO functions and symbols from the parsed object and adds them to the metadata.

    Args:
        metadata: The dictionary to store the metadata.
        parsed_obj: The parsed object representing the MachO binary.

    Returns:
        The updated metadata dictionary.
    """
    metadata["functions"] = parse_functions(parsed_obj.functions)
    metadata["ctor_functions"] = parse_functions(parsed_obj.ctor_functions)
    metadata["unwind_functions"] = parse_functions(parsed_obj.unwind_functions)
    metadata["symtab_symbols"], exe_type = parse_macho_symbols(parsed_obj.symbols)
    # Stack-protector evidence lives in the symtab, same as ELF's has_canary;
    # construct_security_properties reads it instead of defaulting Mach-O to
    # "no canary" (which is what the missing key used to collapse into).
    metadata["has_canary"] = _macho_symtab_has_canary(metadata["symtab_symbols"])

    # Populate function info based on local symbols for .o files or others where parsed_obj.functions is empty.
    if not metadata["functions"]:
        metadata["functions"] = [
            {"idx": idx, "name": symbol["name"], "address": symbol["address"]}
            for idx, symbol in enumerate(
                s
                for s in metadata["symtab_symbols"]
                if s["category"] == lief.MachO.Symbol.CATEGORY.LOCAL
            )
        ]

    # Stripped release builds (the common case for shipped iOS/macOS apps)
    # expose almost no local symbols, so lief's aggregated ``functions`` may
    # contain only ``__mh_execute_header``. Recover the real entry points from
    # the ``LC_FUNCTION_STARTS`` table so disassembly and callgraph
    # construction have a complete set of functions to work with.
    ranges = _macho_content_segment_ranges(parsed_obj)
    imagebase = _macho_imagebase_or_zero(parsed_obj)
    # Addresses that identified nothing before the merge. A name can be
    # recovered either by the merge (from a surviving symbol) or by the
    # normalization (a real name outranking a sub_<addr> twin), so the
    # recovery is counted once here, across both, rather than in either.
    unidentified_before = {
        _macho_address_to_virtual(_parse_address(fn.get("address")), ranges, imagebase)
        for fn in metadata["functions"]
        if _is_weak_function_name(fn.get("name"))
    }
    unidentified_before.discard(None)

    metadata["functions"] = merge_macho_function_starts(
        metadata["functions"], metadata["symtab_symbols"], parsed_obj
    )

    # One address space for the function lists (P5.1). lief's aggregate mixes
    # symtab virtual addresses with file-relative function-starts offsets, and
    # the merge above appends virtual ones; normalize every function-bearing
    # list into the virtual space here — at the point the lists are built —
    # so no consumer ever has to guess which space an address is in.
    space_stats = {}
    for list_key in ("functions", "ctor_functions", "unwind_functions"):
        metadata[list_key], space_stats[list_key] = _normalize_macho_function_list(
            metadata.get(list_key), ranges, imagebase
        )
    ambiguous = sum(s["ambiguous"] for s in space_stats.values())
    unresolved = sum(s["unresolved"] for s in space_stats.values())
    metadata["macho_function_address_space"] = {
        "normalized_to": "virtual",
        # The rebase anchor: a reader turns a virtual address back into a
        # file-relative offset by subtracting this (metadata["imagebase"]).
        "imagebase": metadata.get("imagebase", imagebase),
        "rebased_entries": sum(s["rebased"] for s in space_stats.values()),
        "duplicates_merged": sum(s["duplicates_merged"] for s in space_stats.values()),
        "names_recovered": sum(
            1
            for fn in metadata["functions"]
            if not _is_weak_function_name(fn.get("name"))
            and _parse_address(fn.get("address")) in unidentified_before
        ),
        "ambiguous_entries": ambiguous,
        "unresolved_entries": unresolved,
    }

    if exe_type:
        metadata["exe_type"] = exe_type
    if parsed_obj.dylinker:
        metadata["dylinker"] = parsed_obj.dylinker.name
    return metadata


def _macho_signature_data_offset(code_signature) -> int | None:
    """The ``dataoff`` of ``LC_CODE_SIGNATURE`` — an offset *within the slice*.

    LIEF exposes it as ``data_offset``. When that is unavailable the value is
    recovered from the 16 bytes the ``data`` property returns, which are the
    load command itself ``(cmd, cmdsize, dataoff, datasize)``, trying both
    byte orders.

    For a slice of a universal binary this is not a file offset: the fat
    header places the slice at ``fat_offset``, so the blob lives at
    ``fat_offset + dataoff``. Use :func:`_macho_signature_file_offset` for
    anything that seeks.
    """
    offset = getattr(code_signature, "data_offset", None)
    if isinstance(offset, int) and offset > 0:
        return offset
    data = getattr(code_signature, "data", None)
    if not data or len(data) < 16:
        return None
    raw = bytes(data)
    for fmt in ("<IIII", ">IIII"):
        cmd, _cmdsize, dataoff, _datasize = struct.unpack(fmt, raw[:16])
        if cmd == LC_CODE_SIGNATURE_CMD and 0 < dataoff < 1 << 32:
            return dataoff
    return None


def _macho_signature_file_offset(parsed_obj, code_signature) -> int | None:
    """Absolute file offset of the SuperBlob, fat header accounted for.

    ``dataoff`` is slice-relative, so for a universal binary every slice but
    a hypothetical one at offset zero would seek into the wrong bytes without
    adding ``fat_offset``. A thin binary reports ``fat_offset`` 0 and the two
    agree.
    """
    offset = _macho_signature_data_offset(code_signature)
    if offset is None:
        return None
    fat_offset = getattr(parsed_obj, "fat_offset", 0)
    return offset + (fat_offset if isinstance(fat_offset, int) and fat_offset > 0 else 0)


def _macho_signature_blob(exe_file: str, parsed_obj, code_signature) -> tuple[bytes | None, str]:
    """The raw SuperBlob bytes, and where they came from.

    Primary source is LIEF's ``content`` (it reads the range the load command
    names, relative to the right slice). When that is empty, the file range is
    read directly at :func:`_macho_signature_file_offset`, and the read is
    only accepted if the bytes actually start with the SuperBlob magic — a
    wrong offset must fail loudly rather than hand the parser garbage.
    """
    content = getattr(code_signature, "content", None)
    if content:
        blob = bytes(content)
        if blob:
            return blob, "lief_content"
    data_size = getattr(code_signature, "data_size", 0) or 0
    offset = _macho_signature_file_offset(parsed_obj, code_signature)
    if not data_size or offset is None:
        return None, "unavailable"
    try:
        with open(exe_file, "rb") as handle:
            handle.seek(offset)
            blob = handle.read(data_size)
    except OSError:
        return None, "unreadable"
    if len(blob) != data_size:
        return None, "short_read"
    if struct.unpack_from(">I", blob, 0)[0] != SUPERBLOB_MAGIC:
        return None, "wrong_offset"
    return blob, "file_range"


def _macho_code_signature_block(exe_file: str, parsed_obj, code_signature) -> dict:
    """The metadata ``code_signature`` block for one slice.

    ``parse_status`` is the honest tristate: ``"absent"``, ``"parsed"``, or
    ``"parse_failed"`` — a present-but-unreadable blob is never folded into a
    confident "unsigned" or an empty entitlements answer. ``data_offset`` is
    the load command's slice-relative ``dataoff``, ``file_offset`` the
    absolute position of the blob (they differ for a slice of a universal
    binary), and ``blob_source`` says which read path produced the bytes. The legacy ``size``/``data_size`` keys keep their
    original string values (load-command size and blob size respectively).

    Removed key, an explicit rule-15 exception: ``data`` used to hold the
    hex of those same 16 load-command bytes under a name claiming signature
    content — it has never held signature data. Its entire information
    content (cmd, cmdsize, dataoff, datasize) is preserved by ``size``,
    ``data_offset`` and ``data_size``, and the only consumer
    (``checks.check_codesign``) reads ``available``, which is unchanged.
    """
    block: dict = {
        "available": getattr(code_signature, "size", 0) > 0,
        "data_size": str(getattr(code_signature, "data_size", 0)),
        "size": str(getattr(code_signature, "size", 0)),
        "parse_status": "absent",
        "parse_error": None,
    }
    if not block["available"]:
        return block
    blob, blob_source = _macho_signature_blob(exe_file, parsed_obj, code_signature)
    block["blob_source"] = blob_source
    if not blob:
        block["parse_status"] = "parse_failed"
        block["parse_error"] = f"blob_source_{blob_source}"
        return block
    block["data_offset"] = _macho_signature_data_offset(code_signature)
    block["file_offset"] = _macho_signature_file_offset(parsed_obj, code_signature)
    detail = parse_superblob(blob)
    block["parse_status"] = detail.pop("parse_status")
    block["parse_error"] = detail.pop("parse_error")
    # The superblob detail is present exactly when the blob parsed: a failed
    # parse must leave nothing that reads as a thin partial answer.
    if block["parse_status"] == "parsed":
        block["superblob"] = detail
    return block


def add_mach0_signature(exe_file: str, metadata: dict, parsed_obj: lief.MachO.Binary) -> dict:
    """Extracts MachO code signature metadata from the parsed object and adds it to the metadata.

    The embedded SuperBlob (``LC_CODE_SIGNATURE`` → ``data_offset``/``data_size``)
    is parsed into semantic detail — blob index, CodeDirectory flags and
    cdhash, entitlements (XML and DER), requirements and the CMS signer
    chain — by :mod:`blint.lib.codesign_macho`. See
    :func:`_macho_code_signature_block` for the exact shape and the
    parse-status tristate.

    Args:
        exe_file: The path of the executable file.
        metadata: The dictionary to store the metadata.
        parsed_obj: The parsed object representing the MachO binary.

    Returns:
        The updated metadata dictionary.
    """
    try:
        code_signature = None
        if parsed_obj.has_code_signature:
            code_signature = parsed_obj.code_signature
        elif parsed_obj.has_code_signature_dir:
            code_signature = parsed_obj.code_signature_dir
        if code_signature is None:
            metadata["code_signature"] = {"available": False, "parse_status": "absent"}
        else:
            metadata["code_signature"] = _macho_code_signature_block(
                exe_file, parsed_obj, code_signature
            )
        if parsed_obj.has_data_in_code:
            data_in_code = parsed_obj.data_in_code
            metadata["data_in_code"] = {
                "data": str(data_in_code.data.hex()),
                "data_size": str(data_in_code.data_size),
                "size": str(data_in_code.size),
            }
    except (AttributeError, TypeError, ValueError) as e:
        LOG.debug(f"Caught {type(e)} while parsing {exe_file} Mach0 code signature.")
    return metadata
