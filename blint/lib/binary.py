# pylint: disable=too-many-lines,consider-using-f-string
import bisect
import contextlib
import os
import re

# Enable lief logging in debug mode
# Re-exported for backward compatibility: these were importable from
# blint.lib.binary before the per-format split.
import struct  # noqa: F401
import sys
from collections import Counter, defaultdict
from collections.abc import (  # noqa: F401
    Callable,
    Iterable,
)
from typing import (  # noqa: F401
    Any,
)

import lief
from wasm_tools.api import (  # noqa: F401
    parse_wasm_file,
)

from blint.config import (  # noqa: F401 - re-exported, see below  # noqa: F401
    BLINT_MAX_WASM_INSTRUCTIONS,
    FIRST_STAGE_WORDS,
    PII_WORDS,
    get_float_from_env,
    get_int_from_env,
)
from blint.lib.absint import (  # noqa: F401
    analyze_call_site_arguments,
    decode_pointer_string,
)

# Re-exported so ``from blint.lib.binary import X`` keeps working for every
# name this module used to define itself.
from blint.lib.binary_common import (  # noqa: F401  # noqa: F401
    ADDRESS_FMT,
    ASCII_STRING_RE,
    CPU_SUBTYPE_ARM64E,
    CPU_SUBTYPE_FLAG_MASK,
    DLOPEN_NOTE_TYPE,
    ELF_STACK_CHK_SYMBOLS,
    ENTRY_POINT_SECTIONS,
    LC_CODE_SIGNATURE_CMD,
    LINK_CLOSURE_ROOT,
    LINK_CLOSURE_SEARCH_PATHS,
    MACHO_SYNTHETIC_FUNCTION_NAME_RE,
    MAX_EXTRACTED_STRINGS,
    MIN_ENTROPY,
    MIN_EXTRACTED_STRING_LEN,
    MIN_LENGTH,
    PE_STACK_CHK_MARKERS,
    RESOLVE_LINK_CLOSURE,
    REVIEW_RELEVANT_STRING_RE,
    RUST_PANIC_REGEX_UNIX,
    RUST_PANIC_REGEX_WIN,
    SHF_EXECINSTR,
    STACK_CHK_SYMBOLS,
    STRING_BEARING_SECTION_PREFIXES,
    STRING_BEARING_SECTIONS,
    UTF16LE_STRING_RE,
    VM_PROT_EXECUTE,
    VM_PROT_READ,
    VM_PROT_WRITE,
    _batch_demangle_symbol_names,
    _codesign_security_flags,
    _default_confidence_for_kind,
    _entry_size,
    _is_synthetic_function_name,
    _is_weak_function_name,
    _lookup_demangled,
    _parse_address,
    _primary_code_directory,
    _rwx_permissions_str,
    binary_strings,
    calculate_entropy,
    check_secret,
    codecs,
    consolidate_dlopen_dependencies,
    decode_base64,
    demangle_symbolic_name,
    demangle_symbolic_names,
    detect_exe_type,
    enum_to_str,
    extract_note_data,
    extract_section_strings,
    format_symbol_section_index,
    guess_exe_type,
    integer_to_hex_str,
    is_probable_banner_string,
    is_review_relevant_string,
    is_string_bearing_section,
    orjson,
    parse_functions,
    parse_go_buildinfo,
    parse_notes,
    parse_overlay,
    parse_relro,
    parse_rust_buildinfo,
    parse_strings,
    parse_symbols,
    recover_rust_deps_from_panic,
    warnings,
    zlib,
)
from blint.lib.binary_elf import (  # noqa: F401
    _elf_entry_point_anomalies,
    _elf_eof_executable_mapping,
    _elf_has_canary,
    _elf_notes_without_note_segment,
    _elf_section_flags,
    add_elf_dynamic_entries,
    add_elf_header,
    add_elf_metadata,
    add_elf_symbols,
    determine_elf_flags,
    parse_elf_entry_point_section,
    parse_elf_layout_anomalies,
    parse_elf_segments_summary,
    parse_elf_wx_segments,
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
    construct_pe_security_properties,
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
from blint.lib.codesign_macho import (  # noqa: F401
    SUPERBLOB_MAGIC,
    parse_superblob,
    signature_summary,
)
from blint.lib.crypto_constants import CRYPTO_SCAN_SECTIONS, analyze_crypto_material
from blint.lib.disassembler import disassemble_functions
from blint.lib.driver_ioctl import (  # noqa: F401
    IOCTL_TABLE_SECTIONS,
    classify_driver_strings,
    collect_driver_ioctls,
    is_kernel_driver,
)
from blint.lib.elf_abi import (  # noqa: F401
    analyze_elf_abi,
)
from blint.lib.elf_dlopen import (  # noqa: F401
    recover_runtime_dependencies,
    summarize_runtime_loading,
)
from blint.lib.elf_linkmap import (  # noqa: F401
    resolve_link_closure,
)
from blint.lib.entropy import analyze_binary_entropy
from blint.lib.funcdisc.unwind import discover_functions, merge_discovered_functions
from blint.lib.import_attribution import (
    UNATTRIBUTED_LIBRARY,
    analyze_link_hygiene,
    attribute_call_target,
    build_symbol_provider_map,
    is_library_name,
    symbol_lookup_names,
)
from blint.lib.indicators import INFORMATIVE_STRING_CATALOGS
from blint.lib.macho_objc import parse_objc_metadata
from blint.lib.pe_host_plugins import classify_host_plugins
from blint.lib.pe_imports import (  # noqa: F401
    apiset_host,
    delay_import_hash,
    forwarder_target,
    ordinal_name,
    parse_pe_delay_imports,
    summarize_resolution,
)
from blint.lib.pe_layout import (  # noqa: F401
    parse_pe_layout,
    parse_pre_main_execution,
)
from blint.lib.similarity import attach_function_hashes, compute_import_hash
from blint.lib.stack_strings import analyze_stack_strings
from blint.lib.swift_metadata import merge_swift_functions, parse_swift_metadata
from blint.lib.tbd_index import SDK_ATTRIBUTIONS_KEY, enrich_macho_sdk_attribution
from blint.lib.toolchain import infer_toolchain
from blint.lib.utils import (  # noqa: F401
    calculate_hashes,
    camel_to_snake,
    cleanup_dict_lief_errors,
    coerce_to_text,
)
from blint.logger import DEBUG, LOG

if LOG.level != DEBUG:
    lief.logging.disable()


def is_shared_library(parsed_obj: lief.Binary | None) -> bool:
    """
    Checks if the given parsed binary object represents a shared library.

    Args:
        parsed_obj: The parsed binary object to be checked.

    Returns:
        bool: True if the parsed object represents a shared library.
    """
    if not parsed_obj:
        return False
    binary_format = getattr(parsed_obj, "format", None)
    if binary_format is None:
        if isinstance(parsed_obj, lief.ELF.Binary):
            binary_format = lief.Binary.FORMATS.ELF
        elif isinstance(parsed_obj, lief.PE.Binary):
            binary_format = lief.Binary.FORMATS.PE
        elif isinstance(parsed_obj, lief.MachO.Binary):
            binary_format = lief.Binary.FORMATS.MACHO
        else:
            return False
    if binary_format == lief.Binary.FORMATS.ELF:
        return parsed_obj.header.file_type == lief.ELF.Header.FILE_TYPE.DYN
    if binary_format == lief.Binary.FORMATS.PE:
        return parsed_obj.header.has_characteristic(lief.PE.Header.CHARACTERISTICS.DLL)
    if binary_format == lief.Binary.FORMATS.MACHO:
        return parsed_obj.header.file_type == lief.MachO.Header.FILE_TYPE.DYLIB
    return False


# --------------------------------------------------------------------------
# ELF layout coherence
# --------------------------------------------------------------------------
# An implant can be added to an ELF without changing a single original byte:
# append the payload plus a fresh section header table at EOF, retype a spare
# PT_NOTE program header into an executable PT_LOAD covering those bytes, and
# point e_entry and e_shoff at them. Nothing is packed, nothing becomes
# writable-and-executable, and readelf reports a self-consistent file, so
# neither CHECK_WX_SEGMENTS nor the entropy work sees it. What the result
# cannot hide is incoherence between the parts: the entry point lands in a
# section the toolchain would never start execution in, the note section the
# repurposed header used to cover is orphaned, and an executable mapping ends
# exactly at end-of-file. The helpers below compute those three observations
# as evidence; blint/lib/implant_reviews.py turns them into reviews.
#
# Reference: "Trusting-Trust Attack against an Entire Linux Distribution
# through Binary Manipulation" (arXiv 2607.24888), which carries the implant
# through GNU strip across the NixOS bootstrap.


def _prepare_informative_string_matchers(
    indicators: tuple[str, ...],
) -> tuple[tuple[re.Pattern[str], ...], tuple[str, ...]]:
    """Normalize informative string indicators into reusable matcher groups."""
    boundary_patterns = []
    substring_indicators = []
    for indicator in indicators:
        lowered_indicator = indicator.lower().strip()
        if not lowered_indicator:
            continue
        if all(ch.isalnum() or ch == "_" for ch in lowered_indicator):
            boundary_patterns.append(
                re.compile(rf"(?<![a-z0-9]){re.escape(lowered_indicator)}(?![a-z0-9])")
            )
            continue
        substring_indicators.append(lowered_indicator)
    return tuple(boundary_patterns), tuple(substring_indicators)


def _prepare_informative_string_catalogs(
    catalogs,
) -> tuple[tuple[str, tuple[re.Pattern[str], ...], tuple[str, ...]], ...]:
    """Compile informative-string catalogs into reusable matcher bundles."""

    prepared = []
    for category, indicators in catalogs:
        boundary_patterns, substring_indicators = _prepare_informative_string_matchers(indicators)
        prepared.append((category, boundary_patterns, substring_indicators))
    return tuple(prepared)


PREPARED_INFORMATIVE_STRING_CATALOGS = _prepare_informative_string_catalogs(
    INFORMATIVE_STRING_CATALOGS
)


def parse_informative_strings(parsed_obj: lief.Binary) -> list[dict]:
    """Extracts stable, non-secret string hints useful for capability clustering."""

    informative: list[dict] = []
    seen: set[str] = set()
    with contextlib.suppress(AttributeError):
        strings = binary_strings(parsed_obj)
        if isinstance(strings, lief.lief_errors):
            return informative
        for raw_value in strings:
            value = coerce_to_text(raw_value)
            if not value:
                continue
            text = value.strip()
            if not text:
                continue
            lowered = text.lower()
            if lowered in seen:
                continue
            for (
                category,
                boundary_patterns,
                substring_indicators,
            ) in PREPARED_INFORMATIVE_STRING_CATALOGS:
                if any(indicator in lowered for indicator in substring_indicators) or any(
                    pattern.search(lowered) for pattern in boundary_patterns
                ):
                    seen.add(lowered)
                    informative.append({"value": text, "category": category})
                    break
    return informative


def construct_llvm_target_tuple(metadata: dict) -> str:
    """
    Constructs an LLVM target tuple string from binary metadata.
    Format: arch-vendor-os-environment

    Args:
        metadata (dict): The dictionary of parsed binary metadata.

    Returns:
        str: A string representing the LLVM target tuple.
    """
    if metadata.get("is_dotnet"):
        # The architecture comes from the machine type, not from exe_type:
        # a managed image is dotnetbinary whatever its PE format width or
        # ISA is (W3.1 moved managed files out of PE32/PE64, which used to
        # decide this aggregate — the same tuple, now computed from the
        # fact that actually names the machine).
        machine_type = (metadata.get("machine_type") or "").upper()
        arch = {
            "I386": "i686",
            "AMD64": "x86_64",
            "ARM": "arm",
            "ARMNT": "arm",
            "AARCH64": "aarch64",
            "ARM64": "aarch64",
        }.get(machine_type, "x86_64")
        return f"{arch}-pc-windows-msvc"
    vendor = "unknown"
    os_str = "unknown"
    env = ""
    machine_type = (metadata.get("machine_type") or metadata.get("cpu_type") or "").upper()
    endianness = metadata.get("endianness", "LSB").upper()
    arch_map = {
        "I386": "i686",
        "X86_64": "x86_64",
        "AMD64": "x86_64",
        "ARM": "arm",
        "AARCH64": "aarch64",
        "ARM64": "aarch64",
        "ARM64EC": "aarch64",
        "ARM64X": "aarch64",
        "MIPS": "mips",
        "MIPS_RS3_LE": "mipsel",
        "PPC": "ppc",
        "POWERPC": "ppc",
        "PPC64": "ppc64",
        "POWERPC64": "ppc64",
        "RISCV": "riscv64",
        "SYSTEMZ": "systemz",
        "S390": "systemz",
        "SPARCV9": "sparcv9",
        "HEXAGON": "hexagon",
        "WASM32": "wasm32",
        "WASM64": "wasm64",
    }
    arch = arch_map.get(machine_type, "unknown")
    if "mips" in arch and endianness == "LSB":
        arch = arch.replace("mips", "mipsel")
    elif "ppc" in arch and endianness == "LSB":
        arch += "le"
    elif "aarch64" in arch and endianness == "MSB":
        arch = "aarch64_be"
    elif "arm" in arch and endianness == "MSB":
        arch = "armeb"
    binary_type = metadata.get("binary_type")
    if binary_type == "PE":
        os_str = "windows"
        vendor = "pc"
    elif binary_type == "MachO":
        vendor = "apple"
        platform = metadata.get("platform", "MACOS").upper()
        os_map = {
            "MACOS": "macosx",
            "IOS": "ios",
            "TVOS": "tvos",
            "WATCHOS": "watchos",
            "BRIDGEOS": "bridgeos",
            "DRIVERKIT": "driverkit",
        }
        os_str = os_map.get(platform, "darwin")
    elif binary_type == "ELF":
        vendor = "unknown"
        os_abi = metadata.get("identity_os_abi", "LINUX").upper()
        os_map = {
            "LINUX": "linux",
            "SYSTEMV": "linux",
            "FREEBSD": "freebsd",
            "NETBSD": "netbsd",
            "OPENBSD": "openbsd",
            "SOLARIS": "solaris",
        }
        os_str = os_map.get(os_abi, "linux")
    if metadata.get("is_targeting_android"):
        os_str = "linux"
        env = "android"
    elif os_str == "windows":
        env = "msvc"
    elif os_str == "linux":
        if metadata.get("is_musl"):
            env = "musl"
            interpreter = metadata.get("interpreter", "")
            if "-sf.so" in interpreter:
                env = "muslsf"
            elif arch == "arm":
                if "hard" in metadata.get("processor_flag", "").lower() or "-hf.so" in interpreter:
                    env = "musleabihf"
                else:
                    env = "musleabi"
            elif arch == "mips64" or arch == "mips64el":
                env = "muslabi64"
        else:
            env = "gnu"
            if arch.startswith("arm") and "hard" in metadata.get("processor_flag", "").lower():
                env = "gnueabihf"
    components = [arch, vendor, os_str]
    if env:
        components.append(env)
    return "-".join(components)


def _record_slice_variance(metadata: dict, properties: dict) -> None:
    """Name the properties whose value is not the same in every slice.

    The top-level ``security_properties`` block describes the primary slice —
    which keeps existing consumers correct, but leaves a fat binary's
    at-a-glance summary silently speaking for one architecture. /usr/bin/git
    is the case in point: PAC lives on its arm64e slice, so the top level
    carries no ``pac`` key and reads exactly like a binary that was checked
    and found to lack it. That was the original harm this block exists for, and analyzing the
    other slices does not fix it for anyone reading the summary.

    So the summary says so in band: ``security_properties_scope`` marks the
    answer as the primary slice's, and ``security_properties_slice_variance``
    names every property the slices disagree about. Nothing is merged — a
    merge would have to choose between an optimistic and a pessimistic lie —
    and the per-slice truth stays in ``slices``.
    """
    slices = metadata.get("slices") or []
    if not metadata.get("is_universal") or len(slices) < 2:
        return
    metadata["security_properties_scope"] = "primary_slice"
    # A property missing from one slice's set (pac, which is only reported
    # when true) is itself a disagreement, so compare over the union of keys.
    per_slice = [entry.get("security_properties") or {} for entry in slices]
    names = {name for entry in per_slice for name in entry}
    variance = sorted(name for name in names if len({entry.get(name) for entry in per_slice}) > 1)
    if variance:
        metadata["security_properties_slice_variance"] = variance
        LOG.debug(
            f"Universal binary slices disagree on {', '.join(variance)}; "
            f"security_properties describes the primary slice only"
        )


CODE_SIGNATURE_VARIANCE_ASPECTS = (
    "parse_status",
    "provenance",
    "identifier",
    "team_id",
    "cdhash",
    "hash_type",
    "flags",
    "entitlements",
    "entitlements_der",
)


def _record_code_signature_variance(metadata: dict) -> None:
    """Declare the scope of the top-level ``code_signature`` block.

    Signatures are per slice: every slice of a universal binary carries its
    own CodeDirectory, its own cdhash (they differ by construction — the
    directory hashes slice-specific code), and can carry different
    entitlements. The top-level block describes the primary slice, so for a
    fat binary it must say so (``code_signature_scope``) and name what the
    slices disagree about (``code_signature_slice_variance``) rather than
    presenting one slice's cdhash and entitlements as the binary's. Nothing
    is merged; per-slice truth stays in ``slices[][code_signature]``.
    """
    slices = metadata.get("slices") or []
    if not metadata.get("is_universal") or len(slices) < 2:
        return
    metadata["code_signature_scope"] = "primary_slice"
    variance = []
    for aspect in CODE_SIGNATURE_VARIANCE_ASPECTS:
        values = [(entry.get("code_signature") or {}).get(aspect) for entry in slices]
        first = values[0]
        if any(value != first for value in values[1:]):
            variance.append(aspect)
    if variance:
        metadata["code_signature_slice_variance"] = variance
        LOG.debug(
            f"Universal binary slices disagree on code signature "
            f"{', '.join(variance)}; code_signature describes the primary slice only"
        )


def construct_security_properties(metadata: dict, parsed_obj: lief.Binary) -> dict:
    """Constructs a summary of security mitigations."""
    if isinstance(parsed_obj, lief.MachO.Binary):
        properties = _macho_security_properties(metadata, parsed_obj)
    elif isinstance(parsed_obj, lief.PE.Binary):
        # PE: each property from its named source, omitted rather than
        # guessed when the source is absent (A.3/V4); the PE-specific body
        # lives with the rest of the PE parsing.
        properties, gaps = construct_pe_security_properties(
            metadata, parsed_obj, metadata["file_path"]
        )
        if gaps:
            metadata["security_properties_gaps"] = gaps
    else:
        properties = {
            "nx": metadata.get("has_nx", False),
            # True when no loadable segment maps the same pages writable and
            # executable, which trivially holds for formats without segments.
            "w_xor_x": not metadata.get("wx_segments"),
            "pie": metadata.get("is_pie", False),
            "relro": metadata.get("relro", "no"),
            "canary": metadata.get("has_canary", False),
            "stripped": not metadata.get("static", False),
            "is_signed": bool(metadata.get("signatures")),
        }
    return properties


def construct_binary_composition(metadata: dict, parsed_obj: lief.Binary) -> dict:
    """Summarizes the binary's composition."""
    composition: dict = {}
    dependencies = metadata.get("dynamic_entries", [])
    if isinstance(parsed_obj, lief.ELF.Binary):
        composition["linking_type"] = "dynamic" if metadata.get("has_interpreter") else "static"
    else:
        composition["linking_type"] = "dynamic" if dependencies else "static"
    composition["dependency_count"] = len(dependencies)
    runtimes = set()
    if metadata.get("is_musl"):
        runtimes.add("musl")
    elif "gnu" in metadata.get("llvm_target_tuple", ""):
        runtimes.add("glibc")
    if metadata.get("is_dotnet"):
        runtimes.add("dotnet_runtime")
    for dep in dependencies:
        dep_name = dep.get("name", "").lower()
        if "msvc" in dep_name:
            runtimes.add("msvcrt")
        if "libc.so" in dep_name:
            runtimes.add("glibc")
        for d in ("libstdc++", "openssl", "curl", "ffmpeg"):
            if d in dep_name:
                runtimes.add("libstdc++")
    composition["runtime_dependencies"] = sorted(runtimes)
    return composition


def standardize_keys(metadata: dict) -> dict:
    """Standardizes common keys across different binary formats."""
    if "entrypoint" in metadata:
        metadata["entry_point"] = metadata["entrypoint"]
    elif "addressof_entrypoint" in metadata:
        metadata["entry_point"] = int(metadata["addressof_entrypoint"].replace("0x", ""), 16)
    if "imagebase" in metadata:
        metadata["image_base"] = metadata["imagebase"]
    return metadata


def add_derived_attributes(metadata: dict, parsed_obj: lief.Binary | None) -> dict:
    """
    Adds various derived, high-level attributes to the metadata dictionary.
    """
    metadata["hashes"] = calculate_hashes(metadata["file_path"])
    metadata["security_properties"] = construct_security_properties(metadata, parsed_obj)
    _record_slice_variance(metadata, metadata["security_properties"])
    _record_code_signature_variance(metadata)
    metadata["binary_composition"] = construct_binary_composition(metadata, parsed_obj)
    build_info = {}
    if go_formulation := metadata.get("go_formulation"):
        build_info["language"] = "Go"
        # Absent, not null, when the toolchain version could not be recovered.
        if go_version := go_formulation.get("go_version"):
            build_info["go_version"] = go_version
    elif metadata.get("rust_dependencies"):
        build_info["language"] = "Rust"
    elif metadata.get("is_dotnet"):
        build_info["language"] = ".NET"
    if "major_linker_version" in metadata:
        build_info["linker_version"] = (
            f"{metadata['major_linker_version']}.{metadata['minor_linker_version']}"
        )
    if isinstance(parsed_obj, lief.ELF.Binary):
        build_info["linking_type"] = "dynamic" if parsed_obj.has_interpreter else "static"
        if parsed_obj.has_section(".comment"):
            comment_section = parsed_obj.get_section(".comment")
            build_info["compiler_version"] = (
                comment_section.content.tobytes().decode("ascii", "ignore").strip("\x00")
            )
    if build_info:
        metadata["build_info"] = build_info
    return metadata


def _address_sort_key(address: str) -> tuple[int, str]:
    """Build a stable sort key for hex-like addresses."""
    if not isinstance(address, str):
        return sys.maxsize, ""
    with contextlib.suppress(ValueError):
        return int(address, 16), address
    return sys.maxsize, address


def _name_lookup_keys(symbol_name: str) -> list[str]:
    """Generate deterministic name lookup keys, including lightweight PLT aliases."""
    if not isinstance(symbol_name, str):
        return []
    out = []

    def _add(name: str):
        if not isinstance(name, str):
            return
        normalized = name.strip()
        if normalized and normalized not in out:
            out.append(normalized)

    _add(symbol_name)
    if not out:
        return out

    primary = out[0]
    for suffix in ("@plt", ".plt"):
        if primary.endswith(suffix) and len(primary) > len(suffix):
            _add(primary[: -len(suffix)])
    if primary.startswith(".plt.") and len(primary) > len(".plt."):
        _add(primary[len(".plt.") :])

    return out


def _set_edge_confidence(
    edge_confidence: dict, confidence_rank: dict, edge_key: tuple, confidence: str
) -> None:
    existing = edge_confidence.get(edge_key)
    if not existing:
        edge_confidence[edge_key] = confidence
        return
    if confidence_rank.get(confidence, 0) < confidence_rank.get(existing, 0):
        edge_confidence[edge_key] = confidence


def _candidate_variants(addr_int: int, image_base_int: int | None) -> list[int]:
    """Address-space normalization helper with deterministic ordering."""
    variants = [addr_int]
    if image_base_int:
        variants.append(addr_int + image_base_int)
        if addr_int >= image_base_int:
            variants.append(addr_int - image_base_int)
    out = []
    for val in variants:
        if val >= 0 and val not in out:
            out.append(val)
    return out


def build_disassembly_callgraph_metadata(metadata: dict) -> dict:
    """Builds a compact deterministic callgraph from disassembled functions."""
    # We build the graph only from disassembly output so the result reflects executable
    # control-flow evidence, not just symbol tables.
    disassembled = metadata.get("disassembled_functions")
    if not isinstance(disassembled, dict) or not disassembled:
        return {}

    # We keep both user-facing identity (name/address) and call evidence
    # produced by the disassembler (`direct_call_targets`).
    nodes_raw = []
    for func_key, func_data in disassembled.items():
        if not isinstance(func_data, dict):
            continue
        name = func_data.get("name", "")
        address = func_data.get("address", "")
        if not name and "::" in func_key:
            name = func_key.split("::", 1)[1]
        if not address and "::" in func_key:
            address = func_key.split("::", 1)[0]
        canonical_key = f"{address}::{name}" if address and name else func_key
        nodes_raw.append(
            {
                "key": canonical_key,
                "name": name,
                "address": address,
                "rva_or_address": func_data.get("rvaOrAddress", ""),
                "direct_calls": func_data.get("direct_calls") or [],
                "direct_call_targets": func_data.get("direct_call_targets") or [],
            }
        )

    if not nodes_raw:
        return {}

    nodes_raw.sort(
        key=lambda node: (
            _address_sort_key(node.get("address", "")),
            node.get("name", ""),
            node.get("key", ""),
        )
    )

    # Mach-O and heavily symbolized Rust binaries often emit multiple names for
    # the same entrypoint. Without this collapse, a single target address can
    # appear ambiguous even though it is one concrete function location.
    by_address = defaultdict(list)
    no_address_nodes = []
    for node in nodes_raw:
        if node.get("address"):
            by_address[node["address"]].append(node)
        else:
            no_address_nodes.append(node)

    collapsed_nodes_raw = []
    for address, group in sorted(by_address.items(), key=lambda item: _address_sort_key(item[0])):
        group_sorted = sorted(group, key=lambda n: (n.get("name", ""), n.get("key", "")))
        canonical = dict(group_sorted[0])
        alias_names = sorted(
            {
                n.get("name", "")
                for n in group_sorted
                if isinstance(n.get("name"), str) and n.get("name")
            }
        )
        canonical["alias_names"] = alias_names
        merged_direct_calls: list = []
        merged_targets: list = []
        for item in group_sorted:
            merged_direct_calls.extend(item.get("direct_calls") or [])
            merged_targets.extend(item.get("direct_call_targets") or [])
        canonical["direct_calls"] = merged_direct_calls
        canonical["direct_call_targets"] = merged_targets
        collapsed_nodes_raw.append(canonical)

    collapsed_nodes_raw.extend(
        sorted(
            no_address_nodes,
            key=lambda node: (
                node.get("name", ""),
                node.get("key", ""),
            ),
        )
    )
    nodes_raw = collapsed_nodes_raw

    # These indexes are used by later matching passes in descending confidence:
    # exact VA -> normalized VA -> RVA space -> image-base transforms -> name.
    nodes = []
    name_to_ids = defaultdict(list)
    addr_to_ids = defaultdict(list)
    rva_to_ids = defaultdict(list)
    direct_calls_by_src = {}
    direct_call_targets_by_src = {}
    node_addr_ints = []
    for node_id, node in enumerate(nodes_raw):
        key = node["key"]
        nodes.append(
            {
                "id": node_id,
                "key": key,
                "name": node["name"],
                "address": node["address"],
                "aliases": node.get("alias_names", []),
            }
        )
        indexed_names = {node["name"], *(node.get("alias_names") or [])}
        node_lookup_keys = set()
        for indexed_name in indexed_names:
            node_lookup_keys.update(_name_lookup_keys(indexed_name))
        for lookup_key in sorted(node_lookup_keys):
            name_to_ids[lookup_key].append(node_id)
        direct_calls_by_src[node_id] = node.get("direct_calls", [])
        if node["address"]:
            with contextlib.suppress(ValueError):
                addr_int = int(node["address"], 16)
                addr_to_ids[addr_int].append(node_id)
                node_addr_ints.append((addr_int, node_id))
        if rva_or_address := node.get("rva_or_address"):
            with contextlib.suppress(ValueError):
                rva_to_ids[int(rva_or_address, 16)].append(node_id)

    for src_id, node in enumerate(nodes_raw):
        direct_call_targets_by_src[src_id] = node.get("direct_call_targets") or []

    # Build coarse function ranges from sorted entrypoints. This is a practical
    # fallback for targets landing on basic-block labels rather than exact
    # function starts (common in optimized code and jump-heavy dispatchers).
    node_ranges = {}
    range_starts = []
    range_ends = []
    range_node_ids = []
    if node_addr_ints:
        node_addr_ints.sort(key=lambda x: x[0])
        for idx, (start_addr, node_id) in enumerate(node_addr_ints):
            if idx + 1 < len(node_addr_ints):
                end_addr = node_addr_ints[idx + 1][0] - 1
            else:
                end_addr = start_addr
            node_ranges[node_id] = (start_addr, end_addr)
            range_starts.append(start_addr)
            range_ends.append(end_addr)
            range_node_ids.append(node_id)

    def _find_containing_node_id(addr_int):
        if not range_starts:
            return None
        idx = bisect.bisect_right(range_starts, addr_int) - 1
        if idx < 0:
            return None
        if addr_int <= range_ends[idx]:
            return range_node_ids[idx]
        return None

    image_base_int = None
    image_base = metadata.get("image_base", metadata.get("imagebase"))
    if isinstance(image_base, int):
        image_base_int = image_base
    elif isinstance(image_base, str):
        with contextlib.suppress(ValueError):
            image_base_int = int(image_base, 16)

    # MachO import slot/stub addresses resolved during disassembly. Calls whose
    # target lands on one of these are external imports (Foundation, libswiftCore,
    # libc, ...), not internal edges; classifying them here avoids the
    # range-containment fallback misattributing them to whichever function happens
    # to span the GOT/stub address.
    import_call_addresses = {}
    for addr_str, name in (metadata.get("import_call_addresses") or {}).items():
        with contextlib.suppress(ValueError, TypeError):
            import_call_addresses[int(addr_str, 16)] = name

    def _resolve_import_name(addr_int):
        for variant in (addr_int, addr_int & ~1):
            name = import_call_addresses.get(variant)
            if name:
                return name
        return None

    # We aggregate counts by (src, dst, kind) and track confidence separately
    # because the same edge can be observed through multiple heuristics.
    edge_counts: Counter[tuple[int, int, str]] = Counter()
    edge_confidence: dict[tuple, str] = {}
    external_counts: Counter[tuple[int, str, str]] = Counter()
    # The displayed target of an external edge is the raw operand when there is
    # one, which hides any symbol name the resolver did recover. Attribution
    # needs that name, so it is kept alongside rather than re-derived from the
    # display string.
    external_symbol_names = {}

    confidence_rank = {"low": 1, "medium": 2, "high": 3}

    for src_id, direct_targets in direct_call_targets_by_src.items():
        if not direct_targets:
            continue
        for target in direct_targets:
            if not isinstance(target, dict):
                continue
            target_addr = target.get("target_address", "")
            target_addr_candidates = target.get("target_address_candidates") or []
            target_name = target.get("target_name") or ""
            raw_operand = target.get("raw_operand", "")
            edge_kind = target.get("kind") or "direct"
            # Higher score means stronger matching evidence. Scores are designed
            # as a strict ladder so deterministic tie-breakers can resolve only
            # genuinely equivalent candidates.
            candidate_scores: defaultdict[int, int] = defaultdict(int)
            primary_addr_int = None
            with contextlib.suppress(ValueError):
                if target_addr:
                    primary_addr_int = int(target_addr, 16)

            def _score_candidates(id_list, score, scores=candidate_scores):
                for cid in id_list or []:
                    scores[cid] = max(scores[cid], score)

            numeric_candidates = []
            if target_addr:
                numeric_candidates.append(target_addr)
            if isinstance(target_addr_candidates, list):
                numeric_candidates.extend(target_addr_candidates)

            # External import calls take priority over internal heuristics: a
            # target on a known GOT/stub slot is a call out to a dynamic library,
            # never an internal edge.
            if import_call_addresses:
                import_name = None
                for candidate in numeric_candidates:
                    if not isinstance(candidate, str) or not candidate:
                        continue
                    with contextlib.suppress(ValueError):
                        import_name = _resolve_import_name(int(candidate, 16))
                    if import_name:
                        break
                if import_name:
                    reason = "import" if edge_kind == "direct" else f"import:{edge_kind}"
                    external_counts[(src_id, import_name, reason)] += 1
                    external_symbol_names[(src_id, import_name, reason)] = import_name
                    continue

            for candidate in numeric_candidates:
                if not isinstance(candidate, str) or not candidate:
                    continue
                with contextlib.suppress(ValueError):
                    addr_int = int(candidate, 16)
                    _score_candidates(addr_to_ids.get(addr_int, []), 100)
                    _score_candidates(addr_to_ids.get(addr_int & ~1, []), 95)
                    _score_candidates(rva_to_ids.get(addr_int, []), 90)
                    if image_base_int:
                        _score_candidates(addr_to_ids.get(addr_int + image_base_int, []), 85)
                        _score_candidates(
                            addr_to_ids.get((addr_int + image_base_int) & ~1, []), 80
                        )
                        if addr_int >= image_base_int:
                            _score_candidates(rva_to_ids.get(addr_int - image_base_int, []), 75)

                    # Range containment fallback: recover caller->callee edges
                    # when target points inside a function body.
                    containing_node_id = _find_containing_node_id(addr_int)
                    if containing_node_id is not None:
                        _score_candidates([containing_node_id], 70)
                    elif image_base_int:
                        containing_node_id = _find_containing_node_id(addr_int + image_base_int)
                        if containing_node_id is not None:
                            _score_candidates([containing_node_id], 65)

            if target_name:
                for idx, lookup_key in enumerate(_name_lookup_keys(target_name)):
                    _score_candidates(name_to_ids.get(lookup_key, []), 50 if idx == 0 else 45)

            if candidate_scores:
                max_score = max(candidate_scores.values())
                top_candidates = sorted(
                    [cid for cid, sc in candidate_scores.items() if sc == max_score]
                )
            else:
                top_candidates = []

            # Deterministic disambiguation chain:
            # 1) primary target narrowing
            # 2) smallest containing range
            # 3) nearest entrypoint distance
            # 4) lowest node id as final stable fallback
            selected_candidate = None
            selected_confidence = _default_confidence_for_kind(edge_kind)
            if len(top_candidates) == 1:
                selected_candidate = top_candidates[0]
            elif len(top_candidates) > 1:
                working = list(top_candidates)

                if primary_addr_int is not None:
                    primary_ids = set()
                    for variant in _candidate_variants(primary_addr_int, image_base_int):
                        primary_ids.update(addr_to_ids.get(variant, []))
                        primary_ids.update(addr_to_ids.get(variant & ~1, []))
                        primary_ids.update(rva_to_ids.get(variant, []))
                    narrowed = sorted(set(working).intersection(primary_ids))
                    if len(narrowed) == 1:
                        selected_candidate = narrowed[0]
                        selected_confidence = "medium"
                    elif narrowed:
                        working = narrowed

                if selected_candidate is None and primary_addr_int is not None:
                    containing = []
                    for cid in working:
                        rng = node_ranges.get(cid)
                        if not rng:
                            continue
                        start_addr, end_addr = rng
                        for variant in _candidate_variants(primary_addr_int, image_base_int):
                            if start_addr <= variant <= end_addr:
                                containing.append(cid)
                                break
                    if containing:
                        min_width = min(
                            (node_ranges[cid][1] - node_ranges[cid][0])
                            for cid in containing
                            if cid in node_ranges
                        )
                        narrowed = sorted(
                            [
                                cid
                                for cid in containing
                                if (node_ranges[cid][1] - node_ranges[cid][0]) == min_width
                            ]
                        )
                        if len(narrowed) == 1:
                            selected_candidate = narrowed[0]
                            selected_confidence = "medium"
                        else:
                            working = narrowed

                if selected_candidate is None and primary_addr_int is not None and working:
                    distance_map = {}
                    for cid in working:
                        rng = node_ranges.get(cid)
                        if not rng:
                            continue
                        start_addr = rng[0]
                        distance_map[cid] = min(
                            abs(start_addr - variant)
                            for variant in _candidate_variants(primary_addr_int, image_base_int)
                        )
                    if distance_map:
                        min_dist = min(distance_map.values())
                        narrowed = sorted(
                            [cid for cid, dist in distance_map.items() if dist == min_dist]
                        )
                        if len(narrowed) == 1:
                            selected_candidate = narrowed[0]
                            selected_confidence = "medium"
                        elif narrowed:
                            working = narrowed

            if selected_candidate is not None:
                edge_key = (src_id, selected_candidate, edge_kind)
                edge_counts[edge_key] += 1
                _set_edge_confidence(
                    edge_confidence, confidence_rank, edge_key, selected_confidence
                )
                continue

            # If no unique internal match exists, preserve evidence as an
            # external edge with a reason bucket. These buckets are useful KPI
            # signals and guide future resolver improvements.
            if raw_operand or target_name or target_addr:
                ext_target = raw_operand or target_name or target_addr
                if len(top_candidates) > 1:
                    reason = "ambiguous_address"
                else:
                    is_numeric_raw = isinstance(raw_operand, str) and raw_operand.startswith(
                        ("#", "0x")
                    )
                    if target_addr or target_addr_candidates:
                        reason = "address_space_miss"
                    elif target_name:
                        reason = "symbol_only_miss"
                    elif is_numeric_raw:
                        reason = "raw_imm"
                    else:
                        reason = "unresolved"
                if edge_kind != "direct":
                    reason = f"{reason}:{edge_kind}"
                external_counts[(src_id, ext_target, reason)] += 1
                if target_name:
                    external_symbol_names[(src_id, ext_target, reason)] = target_name

    for src_id, direct_calls in direct_calls_by_src.items():
        if direct_call_targets_by_src.get(src_id):
            continue
        for target_name in direct_calls:
            if not isinstance(target_name, str) or not target_name:
                continue
            candidate_ids = sorted(
                {
                    node_id
                    for lookup_key in _name_lookup_keys(target_name)
                    for node_id in name_to_ids.get(lookup_key, [])
                }
            )
            if len(candidate_ids) == 1:
                edge_key = (src_id, candidate_ids[0], "direct")
                edge_counts[edge_key] += 1
                _set_edge_confidence(edge_confidence, confidence_rank, edge_key, "high")
            else:
                reason = "ambiguous_name" if len(candidate_ids) > 1 else "symbol_only_miss"
                external_counts[(src_id, target_name, reason)] += 1
                external_symbol_names[(src_id, target_name, reason)] = target_name

    edges = [
        {
            "src": src,
            "dst": dst,
            "count": count,
            "kind": kind,
            "confidence": edge_confidence.get(
                (src, dst, kind), _default_confidence_for_kind(kind)
            ),
        }
        for (src, dst, kind), count in sorted(edge_counts.items(), key=lambda item: item[0])
    ]
    # An external edge says a call leaves the binary but not where it goes.
    # Naming the library turns the unresolved bucket into capability evidence:
    # "calls something we could not resolve" becomes "calls into libcrypto".
    external_provider_map, external_sources = build_symbol_provider_map(metadata)
    external = []
    attributed_external = 0
    for (src, target, reason), count in sorted(external_counts.items(), key=lambda item: item[0]):
        entry = {
            "src": src,
            "target": target,
            "count": count,
            "reason": reason,
            "confidence": "low",
        }
        symbol_name = external_symbol_names.get((src, target, reason), target)
        if library := attribute_call_target(
            symbol_name, external_provider_map, is_macho=metadata.get("binary_type") == "MachO"
        ):
            entry["library"] = library
            # The target is unresolved as an internal edge, but the library it
            # lands in is known from the import evidence rather than guessed.
            entry["confidence"] = "medium"
            attributed_external += 1
        external.append(entry)

    return {
        "version": 2,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": nodes,
        "edges": edges,
        "external": external,
        "external_attribution_sources": external_sources,
        "attributed_external_count": attributed_external,
    }


def parse(
    exe_file: str,
    disassemble: bool = False,
    wasm_strings: bool = True,
    wasm_call_graph: bool = True,
    sdk_path: str | None = None,
) -> dict:  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
    """
    Parse the executable using lief and capture the metadata

    :param: exe_file Binary file
    :param: disassemble Whether to disassemble functions (native formats only)
    :param: wasm_strings Whether to extract strings from wasm files
    :param: wasm_call_graph Whether to build the wasm_tools call graph for wasm files
    :param: sdk_path Optional Apple SDK root whose .tbd stubs are used to
        attribute and confirm Mach-O imports. Opt-in: reads an environment
        the user names, so it defaults to off and is recorded in metadata
        under the distinct `sdk_tbd` attribution source when given.
    :return Metadata dict
    """
    metadata: dict = {"file_path": exe_file}
    try:
        if is_wasm_file(exe_file):
            metadata = parse_wasm_metadata(
                exe_file,
                metadata,
                include_strings=wasm_strings,
                include_call_graph=wasm_call_graph,
            )
            metadata = standardize_keys(metadata)
            metadata["import_dependencies"] = analyze_import_deps(metadata)
            metadata["llvm_target_tuple"] = construct_llvm_target_tuple(metadata)
            metadata = add_derived_attributes(metadata, None)
            return cleanup_dict_lief_errors(metadata)
        if lief.is_oat(exe_file):
            parsed_obj = lief.OAT.parse(exe_file)
        elif lief.is_pe(exe_file):
            parser_config = lief.PE.ParserConfig.all
            parsed_obj = lief.PE.parse(exe_file, parser_config)
        elif lief.is_macho(exe_file):
            # lief.parse auto-selects one slice of a universal binary; go
            # through the FatBinary so every slice is seen.
            parsed_obj = _parse_macho(exe_file, metadata)
        else:
            parsed_obj = lief.parse(exe_file)
        if not parsed_obj:
            return metadata
        metadata["is_shared_library"] = is_shared_library(parsed_obj)
        # ELF Binary
        if isinstance(parsed_obj, lief.ELF.Binary):
            metadata = add_elf_metadata(exe_file, metadata, parsed_obj)
        elif isinstance(parsed_obj, lief.PE.Binary):
            # PE
            metadata = add_pe_metadata(exe_file, metadata, parsed_obj)
        elif isinstance(parsed_obj, lief.MachO.Binary):
            metadata = add_mach0_metadata(exe_file, metadata, parsed_obj)
            if objc_metadata := parse_objc_metadata(parsed_obj):
                metadata["objc_metadata"] = objc_metadata
                metadata = merge_macho_objc_functions(metadata)
        # Stripped binaries still carry runtime-mandated function tables
        # (compact unwind, eh_frame); recover the function starts they list so
        # disassembly and reviews are not blind on exactly these inputs.
        if isinstance(parsed_obj, (lief.ELF.Binary, lief.MachO.Binary)):
            # Swift reflection metadata (__swift5_* on Mach-O, .swift5_* on
            # ELF) names every Swift type, its fields and its metadata access
            # functions — evidence in its own right and a function oracle for
            # stripped Swift binaries (issue #109 for the ELF spelling).
            if swift_metadata := parse_swift_metadata(parsed_obj):
                metadata["swift_metadata"] = swift_metadata
                metadata = merge_swift_functions(metadata)
            metadata = discover_and_merge_functions(metadata, parsed_obj)
        metadata = standardize_keys(metadata)
        # SDK-assisted attribution has to precede the dependency graph: it
        # fills the provider evidence the graph and link hygiene read.
        if sdk_path and isinstance(parsed_obj, lief.MachO.Binary):
            enrich_macho_sdk_attribution(metadata, sdk_path)
        # ELF sets this in add_elf_metadata. PE and Mach-O previously produced no
        # strings at all, which silently disabled secret and string-based reviews
        # for those formats.
        # W3.2: a managed assembly's real string literals live in its #US
        # heap and are moved out of the dotnet block when it read them —
        # the byte-level scan finds only noise on a pure-IL image (two
        # strings in a 700 KB assembly). The scan is unioned in behind the
        # heap literals rather than dropped: on a mixed-mode C++/CLI image
        # the native code carries strings the heap knows nothing about,
        # and replacing would silently discard them. A heap blint could
        # not walk leaves the block without the key and the scan below
        # stays the fallback, so an unwalkable heap never reads as "this
        # assembly has no strings" (ground rule 14).
        dotnet_block = metadata.get("dotnet") or {}
        if "strings" in dotnet_block:
            heap_strings = dotnet_block.pop("strings")
            scanned = parse_strings(parsed_obj)
            if scanned:
                seen_values = {s["value"] for s in heap_strings}
                metadata["strings"] = heap_strings + [
                    s for s in scanned if s["value"] not in seen_values
                ]
                metadata["strings_source"] = "user_strings_heap+binary_scan"
            else:
                metadata["strings"] = heap_strings
                metadata["strings_source"] = "user_strings_heap"
        if "strings" not in metadata:
            metadata["strings"] = parse_strings(parsed_obj)
        # W5.6: the privileged-host plugin surface (04/F) - which plugin
        # contracts the export set satisfies and the host each loads into.
        # An interpretation of already-parsed facts (the export listings and
        # the section bytes for registration references), computed here
        # because the block reads the finalized metadata as a whole. Absent
        # when no contract matched - never an empty block that would read
        # as "not a plugin"; an unreadable export table is named through
        # exports_read_status in analysis_coverage instead.
        if isinstance(parsed_obj, lief.PE.Binary):
            if host_plugin_block := classify_host_plugins(metadata, parsed_obj):
                metadata["host_plugin"] = host_plugin_block
        if informative_strings := parse_informative_strings(parsed_obj):
            metadata["informative_strings"] = informative_strings
        metadata["import_dependencies"] = analyze_import_deps(metadata)
        # Judging a dependency unused requires knowing which library each symbol
        # came from, so this has to follow the attribution pass.
        if link_hygiene := analyze_link_hygiene(metadata, metadata["import_dependencies"]):
            metadata["link_hygiene"] = link_hygiene
        # The full SDK attribution map was for the passes above only; exported
        # and cached metadata carry the capped sample under `sdk_tbd`.
        metadata.pop(SDK_ATTRIBUTIONS_KEY, None)
        metadata["llvm_target_tuple"] = construct_llvm_target_tuple(metadata)
        metadata = add_derived_attributes(metadata, parsed_obj)
        # Section entropy and packing evidence are properties of the section
        # bytes, so they are collected for every native binary regardless of
        # whether disassembly is requested.
        if isinstance(parsed_obj, (lief.ELF.Binary, lief.PE.Binary, lief.MachO.Binary)):
            _file_size = None
            with contextlib.suppress(OSError):
                _file_size = os.path.getsize(exe_file)
            # For PE the overlay numbers come from the classified residue
            # (certificate table subtracted, pe_overlay), so the packing
            # analysis never counts a signature as overlay evidence (V3).
            pe_overlay = metadata.get("overlay_info") if isinstance(parsed_obj, lief.PE.Binary) else None
            metadata["entropy"] = analyze_binary_entropy(
                parsed_obj, _file_size, pe_overlay=pe_overlay
            )
            if packing := metadata["entropy"].get("packing"):
                metadata["security_properties"]["packed"] = packing.get("packed_likelihood") in (
                    "high",
                    "medium",
                )
        # Cross-version stable identifiers: import hash for every format and,
        # once disassembly ran, per-function fuzzy/CFG hashes. ELF carries its
        # imports as imported dynamic symbols, Mach-O as undefined symtab
        # entries whose names are prefixed `dylib::symbol`, and PE as the
        # imports list.
        import_names = [
            entry.get("name")
            for entry in metadata.get("imports", [])
            if isinstance(entry, dict) and entry.get("name")
        ]
        if not import_names:
            import_names = [
                entry.get("name")
                for entry in metadata.get("dynamic_symbols", [])
                if isinstance(entry, dict) and entry.get("name") and entry.get("is_imported")
            ]
        if not import_names and metadata.get("binary_type") == "MachO":
            import_names = []
            for entry in metadata.get("symtab_symbols", []):
                if not isinstance(entry, dict) or not entry.get("name"):
                    continue
                # Undefined symbols are the imports; blint records their
                # LIEF category, whose string form ends in "UNDEFINED".
                if str(entry.get("category", "")).upper().endswith("UNDEFINED"):
                    import_names.append(entry["name"])
        metadata["import_hash"] = compute_import_hash(import_names)
        if disassemble and metadata.get("is_encrypted"):
            # FairPlay-encrypted App Store binaries have an encrypted __TEXT
            # segment; disassembling it would yield meaningless instructions.
            # Report the reason clearly instead of producing noise.
            metadata["disassembly_skipped"] = "fairplay_encrypted"
            LOG.warning(
                f"Skipping disassembly of FairPlay-encrypted binary {exe_file}; "
                "decrypt on-device (e.g. with a dump tool) before analysis."
            )
        elif disassemble and isinstance(
            parsed_obj, (lief.ELF.Binary, lief.PE.Binary, lief.MachO.Binary)
        ):
            metadata["disassembled_functions"] = disassemble_functions(parsed_obj, metadata)
            attach_function_hashes(metadata.get("disassembled_functions"))
            if isinstance(parsed_obj, lief.PE.Binary) and metadata.get("pre_main_execution"):
                # W1.4: with disassembly available, the pre-main summary
                # refreshes so the anti-debug reachability fact can read the
                # callbacks' call targets.
                metadata["pre_main_execution"] = parse_pre_main_execution(
                    parsed_obj, metadata
                )
            if callgraph := build_disassembly_callgraph_metadata(metadata):
                metadata["callgraph"] = callgraph
            # String literals a binary assembles on its stack are invisible to
            # section scanning, so this is the only channel that sees the device
            # paths, registry keys and module names an obfuscated image hides.
            stack_strings, stack_strings_coverage = analyze_stack_strings(
                metadata["disassembled_functions"], metadata.get("llvm_target_tuple", "")
            )
            metadata["stack_strings_coverage"] = stack_strings_coverage
            if stack_strings:
                metadata["stack_strings"] = stack_strings
            # Call-site constant arguments: the recovered constants an
            # image passes to resolved callees, aggregated into one bounded
            # block. This is the only format-aware spot the recovery needs:
            # pointing a constant at the string section it names is a question
            # about this binary's memory, answered here and nowhere else.
            callsite_entries, callsite_coverage = analyze_call_site_arguments(
                metadata["disassembled_functions"],
                metadata.get("llvm_target_tuple", ""),
                metadata.get("binary_type", ""),
                resolve_string=_pointer_string_resolver(parsed_obj),
            )
            metadata["call_site_arguments_coverage"] = callsite_coverage
            if callsite_entries:
                metadata["call_site_arguments"] = callsite_entries
            if isinstance(parsed_obj, lief.PE.Binary) and is_kernel_driver(metadata):
                if driver_ioctls := collect_driver_ioctls(
                    metadata["disassembled_functions"],
                    sections=_pe_data_section_bytes(parsed_obj),
                ):
                    metadata["driver_ioctls"] = driver_ioctls
        # The kernel object namespace paths are recovered from strings, so unlike
        # the IOCTL surface they are available whether or not the image was
        # disassembled. They are collected for every PE, not just drivers: for a
        # driver they name the objects its IOCTLs are reached through, and for a
        # user-mode image the `\\.\` paths name the driver it talks to.
        if isinstance(parsed_obj, lief.PE.Binary):
            if driver_interface := classify_driver_strings(metadata):
                metadata["driver_interface"] = driver_interface
            # Embedded cryptographic constants and opaque data regions are
            # properties of the section bytes, so they are recovered whether or
            # not the image was disassembled.
            if crypto_material := analyze_crypto_material(
                _pe_section_bytes(parsed_obj, CRYPTO_SCAN_SECTIONS)
            ):
                metadata["crypto_material"] = crypto_material
    except (AttributeError, TypeError, ValueError) as e:
        LOG.exception(f"Caught {type(e)}: {e} while parsing {exe_file}.")
    # The in-parse pop above is on the success path only, and everything from
    # the dependency graph onward runs under the guard: a ValueError there
    # left the private full-attribution map in the metadata that gets exported
    # and cached, which is exactly what that key must never reach. Popping
    # again here covers the exception path.
    metadata.pop(SDK_ATTRIBUTIONS_KEY, None)
    # Toolchain provenance and coverage accounting run outside the guarded
    # block: they must summarize the run even when a parse step above failed,
    # and both are plain-metadata transforms that cannot raise.
    metadata["toolchain"] = infer_toolchain(metadata)
    metadata["analysis_coverage"] = _build_analysis_coverage(metadata, disassemble)
    return cleanup_dict_lief_errors(metadata)


def _build_analysis_coverage(metadata: dict, disassemble: bool) -> dict:
    """Account for what was analyzed versus what was discovered.

    A run that disassembled 3 of 400 functions must never be
    indistinguishable from a clean run of 400: automated consumers need the
    blind spots, not just the findings.
    """
    functions = metadata.get("functions") or []
    discovered = metadata.get("discovered_functions") or []
    disassembled = metadata.get("disassembled_functions") or {}
    symbolic_count = 0
    discovered_merged = 0
    for func_entry in functions:
        if not isinstance(func_entry, dict):
            continue
        if func_entry.get("discovered"):
            discovered_merged += 1
        else:
            symbolic_count += 1
    degradations = []
    if metadata.get("disassembly_skipped"):
        degradations.append(metadata["disassembly_skipped"])
    if disassemble and not disassembled and not metadata.get("disassembly_skipped"):
        degradations.append("disassembly_unavailable")
    if metadata.get("is_encrypted"):
        degradations.append("fairplay_encrypted")
    # W5.6: an export directory lief could not read is a named blind spot -
    # the host-plugin contracts are export-keyed, so the gap must reach the
    # coverage block rather than reading as "not a plugin" (rules 14/32).
    if metadata.get("exports_read_status") == "failed":
        degradations.append("export_table_unreadable")
    if (metadata.get("link_hygiene") or {}).get("attribution_status") == "unresolved":
        # Imports exist but none could be pinned to a library, so the
        # unused/undeclared dependency checks were skipped rather than clean.
        degradations.append("dependency_attribution_unresolved")
    # Pointer-materialisation blind spots, mirrored from the
    # call-site block's coverage so a consumer reading only this block
    # still sees them: a pc-relative materialisation that stayed symbolic
    # because the listing could not be located, and why.
    callsite_coverage = metadata.get("call_site_arguments_coverage") or {}
    if callsite_coverage.get("functions_extent_mismatch"):
        degradations.append("callsite_block_extent_mismatch")
    if callsite_coverage.get("functions_no_line_addresses"):
        degradations.append("callsite_no_line_addresses")
    if callsite_coverage.get("functions_unmodelled_pc_relative"):
        degradations.append("callsite_unmodelled_pc_relative")
    # Mach-O function addresses the segment ranges could not place in one
    # space: these entries are left in their raw space rather than
    # guessed at, which a consumer of the function lists must know about.
    macho_space = metadata.get("macho_function_address_space") or {}
    if macho_space.get("ambiguous_entries"):
        degradations.append("macho_function_space_ambiguous")
    if macho_space.get("unresolved_entries"):
        degradations.append("macho_function_space_unresolved")
    coverage = {
        "functions": {
            "symbolic": symbolic_count,
            "discovered": len(discovered),
            "discovered_merged_into_function_list": discovered_merged,
            "disassembled": len(disassembled),
        },
        "degradations": sorted(degradations),
    }
    if entropy := metadata.get("entropy"):
        sections_analyzed = len(entropy.get("sections") or [])
        coverage["sections_analyzed"] = sections_analyzed
    # Mach-O properties blint does not compute yet (stamped by
    # _macho_security_properties); mirrored here so a consumer of the coverage
    # block alone still sees the blind spots.
    if gaps := metadata.get("security_properties_gaps"):
        coverage["security_properties_gaps"] = list(gaps)
    # Same reason: a consumer reading only the coverage block must be able to
    # tell that the top-level security summary speaks for one slice and which
    # properties the other slices disagree about.
    if variance := metadata.get("security_properties_slice_variance"):
        coverage["security_properties_slice_variance"] = list(variance)
    # Same rule-21 reason for code_signature: the top-level block speaks for
    # the primary slice, and a consumer must be able to see that plus which
    # signature aspects the other slices disagree about.
    if scope := metadata.get("code_signature_scope"):
        coverage["code_signature_scope"] = scope
    if variance := metadata.get("code_signature_slice_variance"):
        coverage["code_signature_slice_variance"] = list(variance)
    # Same rule-21 reason for the host-plugin surface (W5.6): the block
    # speaks for one export listing whenever the ARM64X slices disagree,
    # and a consumer of the coverage block alone must see that. Unlike the
    # signature keys above, these two live inside the host_plugin block
    # rather than at the top level — one place to look for the fact — so
    # they are read from there.
    host_plugin = metadata.get("host_plugin") or {}
    if host_plugin_scope := host_plugin.get("host_plugin_scope"):
        coverage["host_plugin_scope"] = host_plugin_scope
    if host_plugin_variance := host_plugin.get("host_plugin_slice_variance"):
        coverage["host_plugin_slice_variance"] = list(host_plugin_variance)
    # A signature blob blint could not parse is a blind spot like any other:
    # declared in the gaps (stamped by _macho_security_properties), and here
    # as a degradation so a thin result can never read as "no entitlements".
    if (metadata.get("code_signature") or {}).get("parse_status") == "parse_failed":
        degradations.append("code_signature_parse_failed")
        coverage["degradations"] = sorted(degradations)
    # Same rule-32 reason for managed metadata (W3.1): a CLI header blint
    # found but could not fully read must not read as a clean native file,
    # and a partially-read table stream must not read as "no AssemblyRefs".
    dotnet_parse_status = (metadata.get("dotnet") or {}).get("parse_status")
    if dotnet_parse_status == "partial":
        degradations.append("dotnet_metadata_partial")
        coverage["degradations"] = sorted(degradations)
    elif dotnet_parse_status == "malformed":
        degradations.append("dotnet_metadata_malformed")
        coverage["degradations"] = sorted(degradations)
    # Per-slice accounting for universal binaries. A slice whose
    # summary failed is a unit like any other: isolated, counted, and named —
    # never silently dropped and never fatal for the file.
    slice_summaries = metadata.get("slices") or []
    slice_errors = metadata.pop("slice_errors", [])
    if metadata.get("is_universal"):
        coverage["slices"] = {
            "total": len(slice_summaries) + len(slice_errors),
            "summarized": len(slice_summaries),
            "failed": len(slice_errors),
        }
        if slice_errors:
            coverage["slices"]["errors"] = slice_errors
            degradations.append("slice_summary_failed")
            coverage["degradations"] = sorted(degradations)
    return coverage


def analyze_import_deps(metadata: dict) -> dict:
    """
    Analyzes the import dependencies from the metadata dictionary.

    Args:
        metadata (dict): The metadata dictionary containing parsed binary info.

    Returns:
        dict: A dictionary representing the import dependency graph.
              Structure:
              {
                "libraries": {
                  "lib_name": {
                    "type": "imported", // or "main_binary"
                    "imported_symbols": ["func1", "func2", ...],
                    "imported_from": ["other_lib1", "other_lib2", ...]
                  },
                  ...
                },
                "dependencies": [
                  {
                    "from": "main_binary",
                    "to": "lib_name",
                    "symbols": ["func1", "func2"]
                  },
                  ...
                ]
              }
    """
    LOG.debug("Analyzing import dependencies...")
    dep_graph: dict = {"libraries": {}, "dependencies": []}
    main_binary_name = metadata.get("name")
    if not main_binary_name:
        return {}
    dep_graph["libraries"][main_binary_name] = {
        "type": "main_binary",
        "imported_symbols": [],
        "imported_from": [],
    }
    binary_type = metadata.get("binary_type")
    if binary_type == "PE":
        def _add_pe_dependency(lib_name: str, func_name: str) -> None:
            """Record one import-table-shaped dependency edge."""
            if lib_name not in dep_graph["libraries"]:
                dep_graph["libraries"][lib_name] = {
                    "type": "imported",
                    "imported_symbols": [],
                    "imported_from": [],
                }
            if func_name not in dep_graph["libraries"][lib_name]["imported_symbols"]:
                dep_graph["libraries"][lib_name]["imported_symbols"].append(func_name)
            dep_exists = False
            for dep in dep_graph["dependencies"]:
                if dep["from"] == main_binary_name and dep["to"] == lib_name:
                    if func_name not in dep["symbols"]:
                        dep["symbols"].append(func_name)
                    dep_exists = True
                    break
            if not dep_exists:
                dep_graph["dependencies"].append(
                    {"from": main_binary_name, "to": lib_name, "symbols": [func_name]}
                )

            if lib_name not in dep_graph["libraries"][main_binary_name]["imported_from"]:
                dep_graph["libraries"][main_binary_name]["imported_from"].append(lib_name)

        for imp_entry in metadata.get("imports", []):
            full_name = imp_entry.get("name", "")
            if "::" in full_name:
                lib_name, func_name = full_name.split("::", 1)
            else:
                continue
            _add_pe_dependency(lib_name, func_name)
        # W3.2: a managed assembly's P/Invoke surface is a dependency edge
        # the import table never carries. The ModuleRef scope is the DLL,
        # the entry point the native export it must provide.
        for pinvoke_entry in (metadata.get("dotnet") or {}).get("pinvoke") or []:
            lib_name = pinvoke_entry.get("module") or ""
            func_name = pinvoke_entry.get("entry_point") or ""
            if not lib_name or not func_name:
                continue
            _add_pe_dependency(lib_name, func_name)
        # W1.2: export forwarders name DLLs the loader must map even though
        # no import-table entry does. They are dependencies of a distinct
        # kind — recorded so the graph is complete, and typed apart from
        # "imported" so link hygiene never reads them as symbol suppliers.
        for target in metadata.get("forwarder_targets") or []:
            if target == main_binary_name:
                continue
            if target not in dep_graph["libraries"]:
                dep_graph["libraries"][target] = {
                    "type": "forwarder_target",
                    "imported_symbols": [],
                    "imported_from": [],
                }
            dep_graph["dependencies"].append(
                {"from": main_binary_name, "to": target, "symbols": []}
            )
    else:
        all_potential_imports = metadata.get("symtab_symbols", []) + metadata.get(
            "dynamic_symbols", []
        )
        # ELF records imported symbols and needed libraries as two unrelated
        # lists, so attribution needs the resolved closure. Without it a symbol
        # stays unattributed: assigning it to an arbitrary needed library
        # invents a dependency edge that downstream tools treat as fact.
        provider_map, provider_sources = build_symbol_provider_map(metadata)
        unattributed_count = 0
        for sym_entry in all_potential_imports:
            if sym_entry.get("is_imported", False):
                full_name = sym_entry.get("name", "")
                if not full_name:
                    continue
                func_name = full_name
                # Only Mach-O prefixes a symbol with its library, and even
                # there the prefix must look like one: `::` is also the
                # namespace separator in C++ and Rust, so splitting blindly
                # turns `APT::PackageContainer::begin` into a dependency on a
                # library called `APT`.
                macho_library, separator, macho_symbol = full_name.partition("::")
                if binary_type == "MachO" and separator and is_library_name(macho_library):
                    lib_name = macho_library.rsplit("/", 1)[-1]
                    func_name = macho_symbol
                elif lib_name := next(
                    (
                        provider_map[key]
                        for key in symbol_lookup_names(sym_entry)
                        if key in provider_map
                    ),
                    "",
                ):
                    pass
                elif ".go" in full_name or ".s" in full_name or "internal" in full_name:
                    lib_name = full_name
                else:
                    lib_name = UNATTRIBUTED_LIBRARY
                    unattributed_count += 1
                if not lib_name:
                    continue

                if lib_name not in dep_graph["libraries"]:
                    dep_graph["libraries"][lib_name] = {
                        "type": "imported",
                        "imported_symbols": [],
                        "imported_from": [],
                    }

                if (
                    func_name not in dep_graph["libraries"][lib_name]["imported_symbols"]
                    and func_name != lib_name
                ):
                    dep_graph["libraries"][lib_name]["imported_symbols"].append(func_name)

                dep_exists = False
                for dep in dep_graph["dependencies"]:
                    if dep["from"] == main_binary_name and dep["to"] == lib_name:
                        if func_name not in dep["symbols"]:
                            dep["symbols"].append(func_name)
                        dep_exists = True
                        break
                if not dep_exists:
                    dep_graph["dependencies"].append(
                        {
                            "from": main_binary_name,
                            "to": lib_name,
                            "symbols": [func_name],
                        }
                    )

                if lib_name not in dep_graph["libraries"][main_binary_name]["imported_from"]:
                    dep_graph["libraries"][main_binary_name]["imported_from"].append(lib_name)
        dep_graph["attribution_sources"] = provider_sources
        dep_graph["unattributed_symbol_count"] = unattributed_count
        if unattributed_count and not provider_sources:
            # Worth stating plainly: the graph is a symbol list, not a
            # dependency graph, until the closure is resolved.
            LOG.debug(
                "%d imported symbols could not be attributed to a library. Set "
                "BLINT_RESOLVE_LINK_CLOSURE=1 to resolve the dependency closure "
                "and attribute them.",
                unattributed_count,
            )
    if len(dep_graph["dependencies"]):
        LOG.debug(
            f"Generated import dependency graph with {len(dep_graph['dependencies'])} dependencies."
        )
    return dep_graph


def discover_and_merge_functions(metadata: dict, parsed_obj) -> dict:
    """Thin wire-up for unwind-table function discovery (funcdisc.unwind).

    Recovery of stripped-binary function starts lives in a dedicated module;
    this only applies its merge contract: ``discovered_functions`` records the
    findings additively and ``functions`` gains ``sub_<address>`` entries only
    for addresses no symbol bucket already claims.
    """
    try:
        discovered = discover_functions(parsed_obj)
    except (AttributeError, TypeError, ValueError) as e:
        LOG.debug(f"Function discovery failed for {metadata.get('name')}: {type(e).__name__}: {e}")
        return metadata
    return merge_discovered_functions(metadata, discovered)


def parse_dex(dex_file: str) -> dict:
    """Parse dex files"""
    metadata: dict = {"file_path": dex_file}
    try:
        dexfile_obj = lief.DEX.parse(dex_file)
        if isinstance(dexfile_obj, lief.lief_errors):
            return metadata
        metadata["version"] = dexfile_obj.version
        metadata["header"] = dexfile_obj.header
        metadata["classes"] = list(dexfile_obj.classes)
        metadata["fields"] = list(dexfile_obj.fields)
        metadata["methods"] = list(dexfile_obj.methods)
        metadata["strings"] = list(dexfile_obj.strings)
        metadata["types"] = list(dexfile_obj.types)
        metadata["prototypes"] = list(dexfile_obj.prototypes)
        metadata["map"] = dexfile_obj.map
    except (AttributeError, TypeError) as e:
        LOG.exception(e)
    return cleanup_dict_lief_errors(metadata)
