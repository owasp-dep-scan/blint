"""Portable Executable (PE/COFF) parsing.

Split out of ``binary.py``; imports only ``binary_common``, never the
orchestrator that imports it.
"""

# pylint: disable=too-many-lines,consider-using-f-string
import codecs
import contextlib
import re
import warnings
from collections.abc import Callable, Iterable

import lief

from blint.config import (
    FIRST_STAGE_WORDS,
    PII_WORDS,
)
from blint.lib.absint import decode_pointer_string
from blint.lib.binary_common import (
    ADDRESS_FMT,
    PE_STACK_CHK_MARKERS,
    _rwx_permissions_str,
    format_symbol_section_index,
    guess_exe_type,
    parse_functions,
    parse_go_buildinfo,
    parse_overlay,
    parse_rust_buildinfo,
)
from blint.lib.binary_wasm import (  # noqa: F401
    build_wasm_callgraph,
    is_wasm_file,
    parse_wasm_metadata,
    trim_wasm_instruction_streams,
)
from blint.lib.driver_ioctl import (
    IOCTL_TABLE_SECTIONS,
)
from blint.lib.utils import (
    calculate_entropy,
    camel_to_snake,
    demangle_symbolic_name,
    enum_to_str,
)
from blint.logger import LOG

# A recovered call-site constant is only treated as a candidate pointer when
# it could name an address: below this it is a small integer (a flag, a size,
# a count) and resolving it would be reading a section it does not name.
_POINTER_STRING_MIN_VALUE = 0x10000
# How many bytes to read at a candidate pointer, and how long the run must be
# to count as the string it points at. The longer minimum (the stack-string
# decoder accepts three) keeps near-coincidental three-byte decodes out.
_POINTER_STRING_MAX_READ = 256
_POINTER_STRING_MIN_LEN = 4


def parse_pe_wx_sections(parsed_obj: lief.PE.Binary) -> list[dict]:
    """Collects the PE sections the loader maps both writable and executable.

    Args:
        parsed_obj: The parsed PE binary.

    Returns:
        A list of section descriptors with a name, normalized permissions and
        the relative virtual address, usable as evidence for the W^X check.
    """
    wx_sections: list[dict] = []
    with contextlib.suppress(AttributeError, TypeError):
        for section in parsed_obj.sections:
            characteristics = section.characteristics_lists
            writable = lief.PE.Section.CHARACTERISTICS.MEM_WRITE in characteristics
            executable = lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE in characteristics
            if writable and executable:
                wx_sections.append(
                    {
                        "name": section.name,
                        "permissions": _rwx_permissions_str(
                            lief.PE.Section.CHARACTERISTICS.MEM_READ in characteristics,
                            writable,
                            executable,
                        ),
                        "virtual_address": ADDRESS_FMT.format(section.virtual_address).strip(),
                    }
                )
    return wx_sections


def parse_pe_data(parsed_obj: lief.PE.Binary) -> list[dict]:
    """
    Parses the data directories from the given parsed PE binary object.

    Args:
        parsed_obj: The parsed PE binary object to extract from.

    Returns:
        list[dict]: A list of dictionaries, each representing a data directory.
    """
    data_list: list[dict] = []
    data_directories = parsed_obj.data_directories
    if not data_directories or isinstance(data_directories, lief.lief_errors):
        return data_list
    for directory in data_directories:
        section_name = ""
        section_chars = ""
        section_entropy = ""
        dir_type = enum_to_str(directory.type)
        if not dir_type.startswith("?") and directory.size:
            if directory.has_section:
                if directory.section.has_characteristic:
                    section_chars = ", ".join(
                        [enum_to_str(chara) for chara in directory.section.characteristics_lists]
                    )
                section_name = directory.section.name
                section_entropy = directory.section.entropy
            data_list.append(
                {
                    "name": section_name,
                    "type": dir_type,
                    "rva": directory.rva,
                    "size": directory.size,
                    "section_characteristics": section_chars,
                    "section_entropy": section_entropy,
                }
            )
    return data_list


def process_pe_resources(parsed_obj: lief.PE.Binary) -> dict:
    """
    Processes the resources of the parsed PE (Portable Executable) binary object
    and returns metadata about the resources.

    Args:
        parsed_obj: The parsed PE binary object to process the resources from.

    Returns:
        dict: A dictionary containing metadata about the resources
    """
    rm = parsed_obj.resources_manager
    if not rm or isinstance(rm, lief.lief_errors):
        return {}
    resources = {}
    version_metadata = {}
    version_info = rm.version if rm.has_version else None
    if isinstance(version_info, list) and len(version_info):
        if not isinstance(version_info[0], lief.lief_errors):
            version_info = version_info[0]
    if version_info and hasattr(version_info, "string_file_info"):
        string_file_info: lief.PE.ResourceStringFileInfo = version_info.string_file_info
        for lc_item in string_file_info.children:
            if lc_item.entries:
                for e in lc_item.entries:
                    version_metadata[e.key] = e.value
    try:
        version_info_dict = {}
        if version_info:
            for k in ("file_info", "key", "type"):
                if hasattr(version_info, k):
                    version_info_dict[k] = re.sub(
                        "\\s+", " ", str(getattr(version_info, k))
                    ).strip()
        resources = {
            "has_accelerator": rm.has_accelerator,
            "has_dialogs": rm.has_dialogs,
            "has_html": rm.has_html,
            "has_icons": rm.has_icons,
            "has_manifest": rm.has_manifest,
            "has_string_table": rm.has_string_table,
            "has_version": rm.has_version,
            "manifest": (
                rm.manifest.replace("\\xef\\xbb\\xbf", "").removeprefix("\ufeff")
                if rm.has_manifest
                else None
            ),
            "version_info": version_info_dict,
            "html": rm.html if rm.has_html else None,
        }
        if version_metadata:
            resources["version_metadata"] = version_metadata
    except (AttributeError, UnicodeError):
        return resources
    return resources


def process_pe_signature(parsed_obj: lief.PE.Binary) -> list[dict]:
    """
    Processes the signatures of the parsed PE (Portable Executable) binary
    object and returns information about the signatures.

    Args:
        parsed_obj: The parsed PE binary object to process the signatures from.

    Returns:
        list[dict]: A list of dictionaries containing signatures info.
    """
    signature_list = []
    with contextlib.suppress(AttributeError, TypeError, KeyError):
        for sig in parsed_obj.signatures:
            ci = sig.content_info
            signature_obj = {
                "version": sig.version,
                "digest_algorithm": enum_to_str(sig.digest_algorithm),
                "content_info": {
                    "content_type": lief.PE.oid_to_string(ci.content_type),
                    "digest_algorithm": enum_to_str(ci.digest_algorithm),
                    "digest": ci.digest.hex(),
                },
            }
            signers_list = []
            for signer in sig.signers:
                signer_obj = {
                    "version": signer.version,
                    "serial_number": signer.serial_number.hex(),
                    "issuer": str(signer.issuer),
                    "digest_algorithm": enum_to_str(signer.digest_algorithm),
                    "encryption_algorithm": str(signer.encryption_algorithm).rsplit(
                        ".", maxsplit=1
                    )[-1],
                    "encrypted_digest": signer.encrypted_digest.hex(),
                }
                signers_list.append(signer_obj)
            signature_obj["signers"] = signers_list
            signature_list.append(signature_obj)
    return signature_list


def parse_pe_authenticode(parsed_obj: lief.PE.Binary) -> dict:
    """
    Parses the Authenticode information from the given parsed PE.

    Args:
        parsed_obj: The parsed PE binary object to extract.

    Returns:
        dict: A dictionary containing the Authenticode information
    """
    try:
        sep = ":"  # blint requires Python 3.10+
        authenticode = {
            "md5_hash": parsed_obj.authentihash_md5.hex(*sep),
            "sha256_hash": parsed_obj.authentihash_sha256.hex(*sep),
            "sha512_hash": parsed_obj.authentihash_sha512.hex(*sep),
            "sha1_hash": parsed_obj.authentihash(lief.PE.ALGORITHMS.SHA_1).hex(*sep),
            "verification_flags": enum_to_str(parsed_obj.verify_signature()),
        }
        if signatures := parsed_obj.signatures:
            if not isinstance(signatures, lief.lief_errors) and signatures[0].signers:
                cert_signer_str = str(parsed_obj.signatures[0].signers[0].cert)
                cert_signer_obj = {}
                for p in cert_signer_str.split("\n"):
                    tmp_a = p.split(" : ")
                    if len(tmp_a) == 2:
                        tmp_key = tmp_a[0].strip().replace(" ", "_")
                        if "version" in tmp_key:
                            tmp_key = "version"
                        value = tmp_a[1].strip()
                        if value in (
                            "???",
                            "???, ???",
                        ):
                            value = "N/A"
                        cert_signer_obj[tmp_key] = value
                authenticode["cert_signer"] = cert_signer_obj
        return authenticode
    except (AttributeError, IndexError, KeyError, TypeError) as e:
        LOG.exception(f"Caught {type(e)} while parsing PE authentihash.")
        return {}


def parse_pe_symbols(symbols) -> tuple[list[dict], str]:
    """
    Parses the symbols and determines the executable type.

    Args:
        symbols (list): A list of symbol objects to parse.

    Returns:
        tuple: A tuple containing two elements:
            - symbols_list (list): A list of symbol dictionaries
            - exe_type (str): The determined executable type.
    """
    symbols_list = []
    exe_type = ""
    # Toolchains emit COFF storage classes that are absent from LIEF's enum (the
    # GNU toolchain uses 106, which the Microsoft PE/COFF spec leaves unassigned).
    # LIEF returns the raw int and warns once per symbol, so the warning is
    # suppressed around the loop rather than thousands of times inside it.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", category=RuntimeWarning)
        for symbol in symbols:
            if not symbol:
                continue
            try:
                if symbol.section and symbol.section.name:
                    section_nb_str = symbol.section.name
                else:
                    section_nb_str = format_symbol_section_index(symbol)
            except (AttributeError, TypeError) as e:
                LOG.debug(f"Caught {type(e)}: {e} while parsing {symbol} PE symbol.")
                section_nb_str = ""
            try:
                if not exe_type:
                    exe_type = guess_exe_type(symbol.name.lower())
                if symbol.name:
                    symbols_list.append(
                        {
                            "name": demangle_symbolic_name(symbol.name),
                            "value": symbol.value,
                            "size": symbol.size,
                            "id": section_nb_str,
                            "base_type": enum_to_str(symbol.base_type),
                            "complex_type": enum_to_str(symbol.complex_type),
                            "storage_class": enum_to_str(symbol.storage_class),
                        }
                    )
            except (IndexError, AttributeError, ValueError, RuntimeError):
                pass
    return symbols_list, exe_type


def parse_pe_imports(imports, imagebase: int) -> tuple[list[dict], list[dict]]:
    """
    Parses the imports and returns lists of imported symbols and DLLs.

    Args:
        imports (it_imports): A list of import objects to parse.

    Returns:
        tuple: A tuple containing two elements:
            - imports_list (list[dict])
            - dll_list (list[dict])
    """
    imports_list: list[dict] = []
    # Insertion-ordered rather than a set: this list is exported as
    # ``dynamic_entries`` and seeds the SBOM's dependency refs, so set
    # iteration order made both vary with PYTHONHASHSEED. First-seen order is
    # the import directory's own order, which is what ELF's DT_NEEDED list
    # already reports.
    dlls: dict[str, None] = {}
    if not imports or isinstance(imports, lief.lief_errors):
        return imports_list, []
    for import_ in imports:
        try:
            entries = import_.entries
        except AttributeError:
            break
        if isinstance(entries, lief.lief_errors):
            break
        for entry in entries:
            try:
                if entry.name:
                    dlls[import_.name] = None
                    imports_list.append(
                        {
                            "name": f"{import_.name}::{demangle_symbolic_name(entry.name)}",
                            "short_name": demangle_symbolic_name(entry.name),
                            "address": ADDRESS_FMT.format(entry.data).strip(),
                            "iat_value": entry.iat_value,
                            "hint": entry.hint,
                            "iat_address": (entry.iat_address + imagebase)
                            if hasattr(entry, "iat_address")
                            else None,
                        }
                    )
            except AttributeError:
                continue
    dll_list = [{"name": d, "tag": "NEEDED"} for d in dlls]
    return imports_list, dll_list


def parse_pe_exports(exports) -> list[dict]:
    """
    Parses the exports and returns a list of exported symbols.

    Args:
        exports: The exports object to parse.

    Returns:
        list[dict]: A list of exported symbol dictionaries.

    """
    exports_list: list[dict] = []
    if not exports or isinstance(exports, lief.lief_errors):
        return exports_list
    if not (entries := exports.entries) or isinstance(exports.entries, lief.lief_errors):
        return exports_list
    for entry in entries:
        metadata = {}
        extern = "[EXTERN]" if entry.is_extern else ""
        if entry.name:
            metadata = {
                "name": demangle_symbolic_name(entry.name),
                "ordinal": entry.ordinal,
                "address": ADDRESS_FMT.format(entry.address).strip(),
                "extern": extern,
            }
        fwd = entry.forward_information if entry.is_forwarded else None
        metadata["is_forwarded"] = entry.is_forwarded
        if fwd:
            metadata["fwd_library"] = fwd.library
            metadata["fwd_function"] = fwd.function
        if metadata:
            exports_list.append(metadata)
    return exports_list


def _parse_unwind_flags(flags_int: int) -> list[str]:
    """Decodes the integer flags into a list of readable names."""
    try:
        flag_obj = lief.PE.RuntimeFunctionX64.UNWIND_FLAGS(flags_int)
        return [f.name for f in lief.PE.RuntimeFunctionX64.UNWIND_FLAGS if f in flag_obj]
    except Exception:
        return [str(flags_int)]


def _get_unwind_reg_name(reg_int: int) -> str:
    """Maps the register integer to its name."""
    try:
        return lief.PE.RuntimeFunctionX64.UNWIND_REG(reg_int).name
    except Exception:
        return str(reg_int)


def _parse_x64_opcode(opcode) -> dict | None:
    if not opcode:
        return None

    data = {
        "name": opcode.opcode.name,
        "position": opcode.position,
    }

    if hasattr(opcode, "reg"):
        data["reg"] = enum_to_str(opcode.reg)
    if hasattr(opcode, "offset"):
        data["offset"] = opcode.offset
    if hasattr(opcode, "size"):
        data["size"] = opcode.size

    return data


def _parse_x64_unwind_info(ei) -> dict:
    f_reg = _get_unwind_reg_name(ei.frame_reg) if hasattr(ei, "frame_reg") else None
    info = {
        "version": ei.version,
        "flags_raw": ei.flags,
        "flags": _parse_unwind_flags(ei.flags),
        "sizeof_prologue": ei.sizeof_prologue,
        "count_opcodes": ei.count_opcodes,
        "frame_reg": f_reg,
        "frame_reg_offset": ei.frame_reg_offset,
        "handler_rva": ADDRESS_FMT.format(ei.handler).strip() if ei.handler else "0x0",
        "opcodes": [_parse_x64_opcode(o) for o in ei.opcodes],
    }
    return info


def parse_pe_exceptions(exceptions) -> list[dict]:
    exceptions_list = []
    for exc in exceptions:
        em = {
            "arch": exc.arch.name,
            "rva_start": ADDRESS_FMT.format(exc.rva_start).strip(),
            "section_offset": exc.offset,
            "raw_str": str(exc),
        }
        if isinstance(exc, lief.PE.RuntimeFunctionX64):
            em["rva_end"] = ADDRESS_FMT.format(exc.rva_end).strip()
            em["size"] = exc.size
            em["unwind_rva"] = ADDRESS_FMT.format(exc.unwind_rva).strip()
            ei = exc.unwind_info
            em.update(_parse_x64_unwind_info(ei))
            if hasattr(ei, "chained") and ei.chained:
                chained_obj = ei.chained
                chained_info = chained_obj.unwind_info
                em["chained"] = {
                    "arch": chained_obj.arch.name,
                    "rva_start": ADDRESS_FMT.format(chained_obj.rva_start).strip(),
                    "rva_end": ADDRESS_FMT.format(chained_obj.rva_end).strip(),
                    "size": chained_obj.size,
                    "unwind_rva": ADDRESS_FMT.format(chained_obj.unwind_rva).strip(),
                    **_parse_x64_unwind_info(chained_info),
                }
        elif isinstance(exc, lief.PE.RuntimeFunctionAArch64):
            em["rva_end"] = ADDRESS_FMT.format(exc.rva_end).strip()
            em["length"] = exc.length
            em["flags"] = exc.flag.name
        exceptions_list.append(em)
    return exceptions_list


def _pe_has_canary(parsed_obj: lief.PE.Binary, metadata: dict) -> bool | None:
    """Explicit canary verdict for a PE, or None when there is no evidence.

    Drives ``has_canary`` (and through it CHECK_CANARY) the same way the ELF
    and Mach-O paths do — the rule only fires on an explicit ``False``, so a
    PE that never set the key silently read as protected. Evidence order:
    the stack-protector runtime symbols the binary itself references win over
    the load-config guard flag, which is the same source
    ``construct_security_properties`` uses for ``security_properties.canary``.
    A PE with no load configuration and no marker symbol gets no verdict:
    unknown is reported as absent, not as clean (rule 14).
    """
    for source in ("symtab_symbols", "imports"):
        for symbol in metadata.get(source) or []:
            if not isinstance(symbol, dict):
                continue
            name = symbol.get("short_name") or symbol.get("name") or ""
            if isinstance(name, str) and any(
                marker in name.lower() for marker in PE_STACK_CHK_MARKERS
            ):
                return True
    try:
        if not parsed_obj.has_configuration:
            return None
        load_config = parsed_obj.load_configuration
        guard_flags = lief.PE.LoadConfiguration.IMAGE_GUARD
        return not load_config.has(guard_flags.SECURITY_COOKIE_UNUSED)
    except (AttributeError, TypeError, ValueError):
        return None


def parse_pe_load_config(parsed_obj: lief.PE.Binary) -> dict:
    """
    Parses the Load Configuration to extract Guard flags, Code Integrity,
    Enclaves, and Volatile Metadata.
    """
    lc_info: dict = {}
    if not parsed_obj.has_configuration:
        return lc_info
    try:
        load_config = parsed_obj.load_configuration
        lc_info["guard_flags"] = load_config.guard_flags
        lc_info["guard_cf_flags"] = [
            str(flag).split(".")[-1] for flag in load_config.guard_cf_flags_list
        ]
        if hasattr(load_config, "code_integrity"):
            ci = load_config.code_integrity
            if ci:
                lc_info["code_integrity"] = {
                    "flags": ci.flags,
                    "catalog": ci.catalog,
                    "catalog_offset": ci.catalog_offset,
                    "reserved": ci.reserved,
                }
        if hasattr(load_config, "enclave_config") and load_config.enclave_config:
            enclave = load_config.enclave_config
            lc_info["enclave_config"] = {
                "policy_flags": enclave.policy_flags,
                "profile_id": [hex(x) for x in enclave.family_id],
                "image_id": [hex(x) for x in enclave.image_id],
                "security_version": enclave.security_version,
                "enclave_size": enclave.enclave_size,
                "nb_threads": enclave.nb_threads,
                "imports": [
                    {"name": imp.import_name, "type": enum_to_str(imp.type)}
                    for imp in enclave.imports
                ],
            }
        if hasattr(load_config, "volatile_metadata") and load_config.volatile_metadata:
            vm = load_config.volatile_metadata
            lc_info["volatile_metadata"] = {
                "min_version": vm.min_version,
                "max_version": vm.max_version,
                "access_table_size": vm.access_table_size,
                "info_ranges_size": vm.info_ranges_size,
            }
        checks = {
            "guard_rf_verify_stackpointer": load_config.guard_rf_verify_stackpointer_function_pointer,
            "guard_xfg_check": load_config.guard_xfg_check_function_pointer,
            "guard_eh_continuation": load_config.guard_eh_continuation_count,
            "dynamic_value_reloc_table": load_config.dynamic_value_reloctable_offset,
        }
        lc_info["runtime_checks"] = {k: v for k, v in checks.items() if v}
    except (AttributeError, Exception) as e:
        LOG.debug(f"Error parsing Load Configuration: {e}")
    return lc_info


def _pe_section_bytes(parsed_obj: lief.PE.Binary, wanted: Iterable[str]) -> list:
    """Return the raw bytes of the named PE sections.

    Only the sections a scan looks at are read, so a large image does not pay to
    copy its resource and relocation sections into memory as well.

    Args:
        parsed_obj: The parsed PE binary.
        wanted: Lowercased section names to collect.

    Returns:
        list: (section name, bytes) pairs, empty if the content is unreadable.
    """
    sections = []
    wanted_names = {name.lower() for name in wanted}
    try:
        for section in parsed_obj.sections:
            name = (section.name or "").rstrip("\x00")
            if name.lower() not in wanted_names:
                continue
            if content := section.content:
                sections.append((name, bytes(content)))
    except (AttributeError, TypeError, ValueError) as e:
        LOG.debug(f"Unable to read PE section content: {e}")
    return sections


def _pe_data_section_bytes(parsed_obj: lief.PE.Binary) -> list:
    """Return the raw bytes of the PE data sections that can hold IOCTL tables."""
    return _pe_section_bytes(parsed_obj, IOCTL_TABLE_SECTIONS)


def _pointer_string_resolver(parsed_obj) -> Callable[[int], str | None]:
    """Build the constant→string resolver for the call-site arguments block.

    Returns a callable mapping one recovered integer constant to the string
    it points at in this image, or None. The constant is a candidate pointer
    only when it lands inside a mapped section of *this* binary — the one
    format-aware fact the format-agnostic recovery cannot know for itself.
    Results are memoized per constant because the same value is recovered at
    many call sites.

    PE sections carry RVAs while the disassembly and the constants it
    recovers live at absolute VAs — with the default image base a PE names
    every address ``0x140...``, above any RVA the sections report — so the
    image base is added to the ranges before the comparison. ELF and Mach-O
    sections already carry absolute addresses and contribute nothing.
    """
    ranges: list[tuple[int, int]] = []
    imagebase = 0
    with contextlib.suppress(AttributeError, TypeError, ValueError):
        imagebase = int(parsed_obj.optional_header.imagebase or 0)
    with contextlib.suppress(AttributeError, TypeError, ValueError):
        for section in parsed_obj.sections:
            va = int(section.virtual_address or 0)
            size = int(section.size or 0)
            if va and size:
                ranges.append((va + imagebase, va + imagebase + size))
    ranges.sort()
    resolved: dict[int, str | None] = {}

    def resolve(value: int) -> str | None:
        if value < _POINTER_STRING_MIN_VALUE:
            return None
        if value in resolved:
            return resolved[value]
        result = None
        if any(start <= value < end for start, end in ranges):
            data = b""
            with contextlib.suppress(Exception):
                data = bytes(
                    parsed_obj.get_content_from_virtual_address(value, _POINTER_STRING_MAX_READ)
                )
            result = decode_pointer_string(data, _POINTER_STRING_MIN_LEN)
        resolved[value] = result
        return result

    return resolve


def add_pe_metadata(exe_file: str, metadata: dict, parsed_obj: lief.PE.Binary) -> dict:
    """Adds PE metadata to the given metadata dictionary.

    Args:
        exe_file (str): The path of the executable file.
        metadata (dict): The dictionary to store the metadata.
        parsed_obj (lief.PE.Binary): The parsed object representing the PE binary.

    Returns:
        dict: The updated metadata dictionary.

    Raises:
        AttributeError: If the parsed object does not have the required attributes.
        IndexError: If there is an index error while accessing attributes.
        TypeError: If there is a type error while accessing attributes.
        ValueError: If there is a value error while accessing attributes.
    """
    try:
        metadata["binary_type"] = "PE"
        metadata["name"] = exe_file
        metadata["is_pie"] = parsed_obj.is_pie
        metadata["is_reproducible_build"] = parsed_obj.is_reproducible_build
        metadata["virtual_size"] = parsed_obj.virtual_size
        metadata["has_nx"] = parsed_obj.has_nx
        metadata["wx_segments"] = parse_pe_wx_sections(parsed_obj)
        metadata["imphash_pefile"] = lief.PE.get_imphash(parsed_obj, lief.PE.IMPHASH_MODE.PEFILE)
        metadata["imphash_lief"] = lief.PE.get_imphash(parsed_obj, lief.PE.IMPHASH_MODE.LIEF)
        metadata = add_pe_header_data(metadata, parsed_obj)
        metadata["load_configuration"] = parse_pe_load_config(parsed_obj)
        metadata["data_directories"] = parse_pe_data(parsed_obj)
        metadata["sections"] = []
        ep = parsed_obj.optional_header.addressof_entrypoint
        for sec in parsed_obj.sections:
            sec_size = max(getattr(sec, "virtual_size", 0), getattr(sec, "sizeof_raw_data", 0))
            if sec.virtual_address <= ep < (sec.virtual_address + sec_size):
                metadata["entry_point_section"] = sec.name
            sec_data = {
                "name": sec.name,
                "entropy": sec.entropy,
                "virtual_size": getattr(sec, "virtual_size", 0),
                "raw_size": getattr(sec, "sizeof_raw_data", 0),
            }
            if hasattr(sec, "characteristics_lists"):
                sec_data["characteristics"] = [enum_to_str(c) for c in sec.characteristics_lists]
            metadata["sections"].append(sec_data)
        if parsed_obj.has_rich_header:
            rich = parsed_obj.rich_header
            metadata["rich_header"] = {
                "key": hex(rich.key),
                "entries": [
                    {"id": e.id, "build_id": e.build_id, "count": e.count} for e in rich.entries
                ],
            }
        metadata["authenticode"] = parse_pe_authenticode(parsed_obj)
        metadata["signatures"] = process_pe_signature(parsed_obj)
        metadata["resources"] = process_pe_resources(parsed_obj)
        metadata["is_arm64ec"] = parsed_obj.is_arm64ec
        metadata["is_arm64x"] = parsed_obj.is_arm64x
        metadata["symtab_symbols"], exe_type = parse_pe_symbols(parsed_obj.symbols)
        if exe_type:
            metadata["exe_type"] = exe_type
        (
            metadata["imports"],
            metadata["dynamic_entries"],
        ) = parse_pe_imports(parsed_obj.imports, parsed_obj.optional_header.imagebase)
        # Stack-protector evidence, same as the ELF and Mach-O paths: an
        # explicit verdict (or none) rather than a silently absent key that
        # CHECK_CANARY collapses into "protected".
        if (pe_canary := _pe_has_canary(parsed_obj, metadata)) is not None:
            metadata["has_canary"] = pe_canary
        # Attempt to detect if this PE is a driver
        if metadata["dynamic_entries"]:
            for e in metadata["dynamic_entries"]:
                if e["name"] == "ntoskrnl.exe":
                    metadata["is_driver"] = True
                    break
        rdata_section = parsed_obj.get_section(".rdata")
        text_section = parsed_obj.get_section(".text")
        # If there are no .rdata and .text section, then attempt to look for two alphanumeric sections
        if not rdata_section and not text_section:
            for section in parsed_obj.sections:
                if str(section.name).removeprefix(".").isalnum():
                    if not rdata_section:
                        rdata_section = section
                    else:
                        text_section = section
        if rdata_section or text_section:
            add_rdata_symbols(metadata, rdata_section, text_section, parsed_obj.sections)
        metadata["exports"] = parse_pe_exports(parsed_obj.get_export())
        metadata["exceptions"] = parse_pe_exceptions(parsed_obj.exceptions)
        metadata["functions"] = parse_functions(parsed_obj.functions)
        metadata["ctor_functions"] = parse_functions(parsed_obj.ctor_functions)
        metadata["exception_functions"] = parse_functions(parsed_obj.exception_functions)
        # Detect if this PE might be dotnet
        for i, dd in enumerate(parsed_obj.data_directories):
            if (
                i == 14
                and dd.type.value == lief.PE.DataDirectory.TYPES.CLR_RUNTIME_HEADER.value
                and dd.size > 0
            ):
                metadata["is_dotnet"] = True
        metadata["dotnet_dependencies"] = parse_overlay(parsed_obj)
        metadata["go_dependencies"], metadata["go_formulation"] = parse_go_buildinfo(parsed_obj)
        metadata["rust_dependencies"] = parse_rust_buildinfo(parsed_obj)
        tls = parsed_obj.tls
        if tls:
            metadata["tls_callbacks"] = [
                ADDRESS_FMT.format(cb).strip() for cb in getattr(tls, "callbacks", [])
            ]
            if hasattr(tls, "sizeof_zero_fill"):
                metadata["tls_address_index"] = ADDRESS_FMT.format(tls.addressof_index).strip()
                metadata["tls_sizeof_zero_fill"] = tls.sizeof_zero_fill
                metadata["tls_data_template_len"] = len(tls.data_template)
                metadata["tls_characteristics"] = tls.characteristics
                if tls.has_section:
                    metadata["tls_section_name"] = tls.section.name
                if tls.has_data_directory:
                    metadata["tls_directory_type"] = str(tls.directory.type)
        nested_binary = parsed_obj.nested_pe_binary
        if nested_binary:
            LOG.debug("Binary has ARM64EC representation!")
            metadata["nested_binary"] = {
                "is_pie": nested_binary.is_pie,
                "is_reproducible_build": nested_binary.is_reproducible_build,
                "virtual_size": nested_binary.virtual_size,
                "has_nx": nested_binary.has_nx,
                "exports": parse_pe_exports(nested_binary.get_export()),
                "exceptions": parse_pe_exceptions(nested_binary.exceptions),
                "functions": parse_functions(nested_binary.functions),
                "ctor_functions": parse_functions(nested_binary.ctor_functions),
                "dotnet_dependencies": parse_overlay(nested_binary),
            }
    except (AttributeError, IndexError, TypeError, ValueError) as e:
        LOG.debug(f"Caught {type(e)}: {e} while parsing {exe_file} PE metadata.")
        raise
    try:
        if hasattr(parsed_obj, "overlay") and parsed_obj.overlay:
            if hasattr(parsed_obj.overlay, "tobytes"):
                overlay_bytes = parsed_obj.overlay.tobytes()
            else:
                overlay_bytes = bytes(parsed_obj.overlay)
            if len(overlay_bytes) > 0:
                metadata["overlay_info"] = {
                    "offset": getattr(parsed_obj, "overlay_offset", 0),
                    "size": len(overlay_bytes),
                    "entropy": calculate_entropy(overlay_bytes),
                }
    except (AttributeError, TypeError, ValueError) as e:
        LOG.debug(f"Failed to parse PE overlay for {exe_file}: {e}")
    return metadata


def add_pe_header_data(metadata: dict, parsed_obj: lief.PE.Binary) -> dict:
    """Adds PE header data to the metadata dictionary.

    Args:
        metadata: The dictionary to store the metadata.
        parsed_obj: The parsed object representing the PE binary.

    Returns:
        The updated metadata dictionary.
    """
    dos_header = parsed_obj.dos_header
    if dos_header and not isinstance(dos_header, lief.lief_errors):
        try:
            metadata["magic"] = str(dos_header.magic)
            header = parsed_obj.header
            metadata["machine_type"] = enum_to_str(header.machine)
            metadata["used_bytes_in_the_last_page"] = dos_header.used_bytes_in_last_page
            metadata["file_size_in_pages"] = dos_header.file_size_in_pages
            metadata["num_relocation"] = dos_header.numberof_relocation
            metadata["header_size_in_paragraphs"] = dos_header.header_size_in_paragraphs
            metadata["minimum_extra_paragraphs"] = dos_header.minimum_extra_paragraphs
            metadata["maximum_extra_paragraphs"] = dos_header.maximum_extra_paragraphs
            metadata["initial_relative_ss"] = dos_header.initial_relative_ss
            metadata["initial_sp"] = dos_header.initial_sp
            metadata["checksum"] = dos_header.checksum
            metadata["initial_ip"] = dos_header.initial_ip
            metadata["initial_relative_cs"] = dos_header.initial_relative_cs
            metadata["address_relocation_table"] = ADDRESS_FMT.format(
                dos_header.addressof_relocation_table
            ).strip()
            metadata["overlay_number"] = dos_header.overlay_number
            metadata["oem_id"] = dos_header.oem_id
            metadata["oem_info"] = dos_header.oem_info
            metadata["address_new_exeheader"] = ADDRESS_FMT.format(
                dos_header.addressof_new_exeheader
            ).strip()
            metadata["characteristics"] = ", ".join(
                [enum_to_str(chara) for chara in header.characteristics_list]
            )
            metadata["num_sections"] = header.numberof_sections
            metadata["time_date_stamps"] = header.time_date_stamps
            metadata["pointer_symbol_table"] = header.pointerto_symbol_table
            metadata["num_symbols"] = header.numberof_symbols
            metadata["size_optional_header"] = header.sizeof_optional_header
        except (IndexError, TypeError) as e:
            LOG.debug(f"Caught {type(e)}: {e} while parsing PE header metadata.")
    optional_header = parsed_obj.optional_header
    if optional_header and not isinstance(optional_header, lief.lief_errors):
        metadata = add_pe_optional_headers(metadata, optional_header)
    return metadata


def add_pe_optional_headers(metadata: dict, optional_header: lief.PE.OptionalHeader) -> dict:
    """Adds PE optional headers data to the metadata dictionary.

    Args:
        metadata: The dictionary to store the metadata.
        optional_header: The optional header of the PE binary.

    Returns:
        The updated metadata dictionary.
    """
    with contextlib.suppress(IndexError, TypeError):
        metadata["dll_characteristics"] = ", ".join(
            [enum_to_str(chara) for chara in optional_header.dll_characteristics_lists]
        )
        # Detect if this binary is a driver
        if "WDM_DRIVER" in metadata["dll_characteristics"]:
            metadata["is_driver"] = True
        metadata["subsystem"] = enum_to_str(optional_header.subsystem)
        metadata["is_gui"] = metadata["subsystem"] == "WINDOWS_GUI"
        metadata["exe_type"] = "PE32" if optional_header.magic == lief.PE.PE_TYPE.PE32 else "PE64"
        metadata["major_linker_version"] = optional_header.major_linker_version
        metadata["minor_linker_version"] = optional_header.minor_linker_version
        metadata["sizeof_code"] = optional_header.sizeof_code
        metadata["sizeof_initialized_data"] = optional_header.sizeof_initialized_data
        metadata["sizeof_uninitialized_data"] = optional_header.sizeof_uninitialized_data
        metadata["addressof_entrypoint"] = ADDRESS_FMT.format(
            optional_header.addressof_entrypoint
        ).strip()
        metadata["baseof_code"] = optional_header.baseof_code
        metadata["baseof_data"] = optional_header.baseof_data
        metadata["imagebase"] = optional_header.imagebase
        metadata["section_alignment"] = optional_header.section_alignment
        metadata["file_alignment"] = optional_header.file_alignment
        metadata["major_operating_system_version"] = optional_header.major_operating_system_version
        metadata["minor_operating_system_version"] = optional_header.minor_operating_system_version
        metadata["major_image_version"] = optional_header.major_image_version
        metadata["minor_image_version"] = optional_header.minor_image_version
        metadata["major_subsystem_version"] = optional_header.major_subsystem_version
        metadata["minor_subsystem_version"] = optional_header.minor_subsystem_version
        metadata["win32_version_value"] = optional_header.win32_version_value
        metadata["sizeof_image"] = optional_header.sizeof_image
        metadata["sizeof_headers"] = optional_header.sizeof_headers
        metadata["checksum"] = optional_header.checksum
        metadata["sizeof_stack_reserve"] = optional_header.sizeof_stack_reserve
        metadata["sizeof_stack_commit"] = optional_header.sizeof_stack_commit
        metadata["sizeof_heap_reserve"] = optional_header.sizeof_heap_reserve
        metadata["sizeof_heap_commit"] = optional_header.sizeof_heap_commit
        metadata["loader_flags"] = optional_header.loader_flags
        metadata["numberof_rva_and_size"] = optional_header.numberof_rva_and_size
    return metadata


def add_rdata_symbols(metadata: dict, rdata_section, text_section, sections) -> dict:
    """Adds rdata symbols to the metadata dictionary.

    Args:
        metadata: The dictionary to store the metadata.
        rdata_section: .rdata section of the binary.
        text_section: .text section of the binary.
        sections: All sections for advanced analysis

    Returns:
        The updated metadata dictionary.
    """
    file_extns_from_rdata = r".*\.(go|s|dll|exe|pdb)(\s|$)"
    rdata_symbols = set()
    pii_symbols = []
    first_stage_symbols = []
    for pii in PII_WORDS:
        for vari in (
            f"get{pii}",
            f"get_{pii}",
            f"get_{camel_to_snake(pii)}",
            f"Get{pii}",
        ):
            if (rdata_section and rdata_section.search_all(vari)) or (
                text_section and text_section.search_all(vari)
            ):
                pii_symbols.append(
                    {
                        "name": vari.lower(),
                        "type": "FUNCTION",
                        "is_function": True,
                        "is_imported": False,
                    }
                )
                continue
    for sw in FIRST_STAGE_WORDS:
        if (rdata_section and rdata_section.search_all(sw)) or (
            text_section and text_section.search_all(sw)
        ):
            first_stage_symbols.append(
                {
                    "name": sw,
                    "type": "FUNCTION",
                    "is_function": True,
                    "is_imported": True,
                }
            )
    # rdata and rodata can be technically anywhere
    # go binaries could have them under .gopclntab and .gosymtab for example
    # We attempt to search for symbols in every section.
    data_sections = []
    for section in sections:
        if str(section.name).removeprefix(".").isalnum():
            data_sections.append(section)
    for section in data_sections:
        str_content = (
            codecs.decode(section.content.tobytes("A"), encoding="utf-8", errors="ignore")
            if section and section.content
            else ""
        )
        for block in str_content.split(" "):
            if (
                "runtime." in block
                or "internal/" in block
                or re.match(file_extns_from_rdata, block)
            ):
                if ".go" in block:
                    metadata["exe_type"] = "gobinary"
                for asym in block.split("\x00"):
                    if re.match(file_extns_from_rdata + "$", asym):
                        rdata_symbols.add(asym)
    if not metadata["symtab_symbols"]:
        metadata["symtab_symbols"] = []
    metadata["symtab_symbols"] += [
        {"name": s, "type": "FILE", "is_function": False, "is_imported": True}
        for s in sorted(rdata_symbols)
    ]
    if pii_symbols:
        metadata["pii_symbols"] = pii_symbols
    if first_stage_symbols:
        metadata["first_stage_symbols"] = first_stage_symbols
    return metadata
