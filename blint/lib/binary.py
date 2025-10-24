# pylint: disable=too-many-lines,consider-using-f-string
import codecs
import contextlib
import os
import re
import sys
import warnings
from typing import Tuple
import zlib
import orjson

import lief

from blint.config import FIRST_STAGE_WORDS, PII_WORDS, get_float_from_env, get_int_from_env
from blint.logger import DEBUG, LOG
from blint.lib.utils import (
    camel_to_snake,
    calculate_entropy,
    calculate_hashes,
    check_secret,
    cleanup_dict_lief_errors,
    decode_base64,
    demangle_symbolic_name,
    enum_to_str,
)
from blint.lib.disassembler import disassemble_functions

MIN_ENTROPY = get_float_from_env("SECRET_MIN_ENTROPY", 0.39)
MIN_LENGTH = get_int_from_env("SECRET_MIN_LENGTH", 80)

# Enable lief logging in debug mode
if LOG.level != DEBUG:
    lief.logging.disable()

ADDRESS_FMT = "0x{:<10x}"


def is_shared_library(parsed_obj):
    """
    Checks if the given parsed binary object represents a shared library.

    Args:
        parsed_obj: The parsed binary object to be checked.

    Returns:
        bool: True if the parsed object represents a shared library.
    """
    if not parsed_obj:
        return False
    if parsed_obj.format == lief.Binary.FORMATS.ELF:
        return parsed_obj.header.file_type == lief.ELF.Header.FILE_TYPE.DYN
    if parsed_obj.format == lief.Binary.FORMATS.PE:
        return parsed_obj.header.has_characteristic(lief.PE.Header.CHARACTERISTICS.DLL)
    if parsed_obj.format == lief.Binary.FORMATS.MACHO:
        return parsed_obj.header.file_type == lief.MachO.Header.FILE_TYPE.DYLIB
    return False


def parse_notes(parsed_obj):
    """
    Parses the notes from the given parsed binary object.

    Args:
        parsed_obj: The parsed binary object containing the notes.

    Returns:
        list[dict]: A list of metadata dictionaries, each representing a note.

    Note:
        - The description is truncated to 16 words and appended with "..." if
            it exceeds 16 words.
    """
    data = []
    notes = parsed_obj.notes
    if isinstance(notes, lief.lief_errors):
        return data
    data += [extract_note_data(idx, note) for idx, note in enumerate(notes)]
    return data


def extract_note_data(idx, note):
    """
    Extracts metadata from a note object and returns a dictionary.

    Args:
        idx (int): The index of the note.
        note: The note object to extract data from.
    Returns:
        dict: A dictionary containing the extracted metadata
    """
    note_str = ""
    build_id = ""
    if note.type == lief.ELF.Note.TYPE.GNU_BUILD_ID:
        note_str = str(note)
    if "ID Hash" in note_str:
        build_id = note_str.rsplit("ID Hash:", maxsplit=1)[-1].strip()
    description = note.description
    description_str = " ".join(map(integer_to_hex_str, description[:64]))
    if len(description) > 64:
        description_str += " ..."
    if note.type == lief.ELF.Note.TYPE.GNU_BUILD_ID:
        build_id = description_str.replace(" ", "")
    type_str = note.type
    type_str = enum_to_str(type_str)
    note_details = ""
    sdk_version = ""
    ndk_version = ""
    ndk_build_number = ""
    abi = ""
    version_str = ""
    if type_str == "ANDROID_IDENT":
        sdk_version = note.sdk_version
        ndk_version = note.ndk_version
        ndk_build_number = note.ndk_build_number
    elif type_str.startswith("GNU_ABI_TAG"):
        version = [str(i) for i in note.version]
        version_str = ".".join(version)
    else:
        with contextlib.suppress(AttributeError):
            note_details = note.details
            version = note_details.version
            abi = str(note_details.abi)
            version_str = f"{version[0]}.{version[1]}.{version[2]}"
    if not version_str and build_id:
        version_str = build_id
    return {
        "index": idx,
        "description": description_str,
        "type": type_str,
        "details": note_details,
        "sdk_version": sdk_version,
        "ndk_version": ndk_version,
        "ndk_build_number": ndk_build_number,
        "abi": abi,
        "version": version_str,
        "build_id": build_id,
    }


def integer_to_hex_str(e):
    """
    Converts an integer to a hexadecimal string representation.

    Args:
        e: The integer to be converted.

    Returns:
        The hexadecimal string representation of the integer.
    """
    return "{:02x}".format(e)


def parse_relro(parsed_obj):
    """
    Determines the Relocation Read-Only (RELRO) protection level.

    Args:
        parsed_obj: The parsed binary object to analyze.

    Returns:
        str: The RELRO protection level of the binary object.
    """
    test_stmt = parsed_obj.get(lief.ELF.Segment.TYPE.GNU_RELRO)
    if isinstance(test_stmt, lief.lief_errors):
        return "no"
    dynamic_tags = parsed_obj.get(lief.ELF.DynamicEntry.TAG.FLAGS)
    bind_now, now = False, False
    if dynamic_tags and isinstance(dynamic_tags, lief.ELF.DynamicEntryFlags):
        bind_now = lief.ELF.DynamicEntryFlags.FLAG.BIND_NOW in dynamic_tags
    dynamic_tags = parsed_obj.get(lief.ELF.DynamicEntry.TAG.FLAGS_1)
    if dynamic_tags and isinstance(dynamic_tags, lief.ELF.DynamicEntryFlags):
        now = lief.ELF.DynamicEntryFlags.FLAG.NOW in dynamic_tags
    return "full" if bind_now or now else "partial"


def parse_functions(functions):
    """
    Parses a list of functions and returns a list of dictionaries.

    Args:
        functions (list): A list of function objects to parse.

    Returns:
        list[dict]: A list of function dictionaries
    """
    func_list = []
    with contextlib.suppress(AttributeError, TypeError):
        for idx, f in enumerate(functions):
            if f.name or f.address:
                cleaned_name = demangle_symbolic_name(f.name)
                func_list.append(
                    {
                        "index": idx,
                        "name": cleaned_name,
                        "address": ADDRESS_FMT.format(f.address).strip(),
                        "size": f.size,
                        "flags": str(f.flags_list) if f.flags_list else None,
                    }
                )
    return func_list


def parse_strings(parsed_obj):
    """
    Parse strings from a parsed object.

    Args:
        parsed_obj: The parsed object from which to extract strings.

    Returns:
        list: A list of dictionaries with keys: value, entropy, secret type
    """
    strings_list = []
    with contextlib.suppress(AttributeError):
        strings = parsed_obj.strings
        if isinstance(strings, lief.lief_errors):
            return strings_list
        for s in strings:
            try:
                if s and "[]" not in s and "{}" not in s:
                    entropy = calculate_entropy(s)
                    secret_type = check_secret(s)
                    if (entropy and (entropy > MIN_ENTROPY or len(s) > MIN_LENGTH)) or secret_type:
                        strings_list.append(
                            {
                                "value": decode_base64(s) if s.endswith("==") else s,
                                "entropy": entropy,
                                "secret_type": secret_type,
                            }
                        )
            except (AttributeError, TypeError):
                continue
    return strings_list


def parse_symbols(symbols):
    """
    Parse symbols from a list of symbols.

    Args:
        symbols (it_symbols): A list of symbols to parse.

    Returns:
        tuple[list[dict], str]: A tuple containing the symbols_list and exe_type
    """
    symbols_list = []
    exe_type = ""
    for symbol in symbols:
        try:
            symbol_version = symbol.symbol_version if symbol.has_version else ""
            is_imported = False
            is_exported = False
            if symbol.imported and not isinstance(symbol.imported, lief.lief_errors):
                is_imported = True
            if symbol.exported and not isinstance(symbol.exported, lief.lief_errors):
                is_exported = True
            symbol_name = symbol.demangled_name
            if isinstance(symbol_name, lief.lief_errors):
                symbol_name = demangle_symbolic_name(symbol.name)
            else:
                symbol_name = demangle_symbolic_name(symbol_name)
            exe_type = guess_exe_type(symbol_name)
            visibility = ""
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", category=RuntimeWarning)
                visibility = enum_to_str(symbol.visibility)
            symbols_list.append(
                {
                    "name": symbol_name,
                    "type": enum_to_str(symbol.type),
                    "value": ADDRESS_FMT.format(symbol.value).strip() if symbol.value > 0 else symbol.value,
                    "visibility": visibility,
                    "binding": enum_to_str(symbol.binding),
                    "is_imported": is_imported,
                    "is_exported": is_exported,
                    "information": symbol.information,
                    "is_function": symbol.is_function,
                    "is_static": symbol.is_static,
                    "is_variable": symbol.is_variable,
                    "version": str(symbol_version),
                    "shndx": symbol.shndx,
                    "size": symbol.size if symbol.size > 0 else None
                }
            )
        except (AttributeError, IndexError, TypeError):
            continue
    return symbols_list, exe_type


def detect_exe_type(parsed_obj, metadata):
    """
    Detects the type of the parsed binary object based on its characteristics
    and metadata.

    Args:
        parsed_obj: The parsed binary object to analyze.
        metadata (dict): The metadata dictionary containing binary information.

    Returns:
        str: The detected type of the binary.
    """
    with contextlib.suppress(AttributeError, TypeError):
        if parsed_obj.has_section(".note.go.buildid"):
            return "gobinary"
        if (
                parsed_obj.has_section(".note.gnu.build-id")
                or "musl" in metadata.get("interpreter")
                or "ld-linux" in metadata.get("interpreter")
        ):
            return "genericbinary"
        if metadata.get("machine_type") and metadata.get("file_type"):
            return f'{metadata.get("machine_type")}-{metadata.get("file_type")}'.lower()
        if metadata["relro"] in ("partial", "full"):
            return "genericbinary"
    return ""


def guess_exe_type(symbol_name):
    """
    Guess the executable type based on the symbol name.

    Args:
        symbol_name (str): The name of the symbol.

    Returns:
        str: The guessed executable type based on the symbol name.
    """
    exe_type = ""
    if "golang" in symbol_name or "_cgo_" in symbol_name:
        exe_type = "gobinary"
    if "_rust_" in symbol_name:
        exe_type = "genericbinary"
    if "DotNetRuntimeInfo" in symbol_name:
        exe_type = "dotnetbinary"
    return exe_type


def parse_pe_data(parsed_obj):
    """
    Parses the data directories from the given parsed PE binary object.

    Args:
        parsed_obj: The parsed PE binary object to extract from.

    Returns:
        list[dict]: A list of dictionaries, each representing a data directory.
    """
    data_list = []
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
                        [
                            enum_to_str(chara)
                            for chara in directory.section.characteristics_lists
                        ]
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


def process_pe_resources(parsed_obj):
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
                    version_info_dict[k] = re.sub('\\s+', ' ', str(getattr(version_info, k))).strip()
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


def process_pe_signature(parsed_obj):
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


def parse_pe_authenticode(parsed_obj):
    """
    Parses the Authenticode information from the given parsed PE.

    Args:
        parsed_obj: The parsed PE binary object to extract.

    Returns:
        dict: A dictionary containing the Authenticode information
    """
    try:
        sep = ":" if sys.version_info.minor > 7 else ()
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


def parse_pe_symbols(symbols):
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
    for symbol in symbols:
        if not symbol:
            continue
        try:
            if symbol.section and symbol.section.name:
                section_nb_str = symbol.section.name
            else:
                section_nb_str = "section<{:d}>".format(symbol.section_number)
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


def parse_pe_imports(imports):
    """
    Parses the imports and returns lists of imported symbols and DLLs.

    Args:
        imports (it_imports): A list of import objects to parse.

    Returns:
        tuple: A tuple containing two elements:
            - imports_list (list[dict])
            - dll_list (list[dict])
    """
    imports_list = []
    dlls = set()
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
                    dlls.add(import_.name)
                    imports_list.append(
                        {
                            "name": f"{import_.name}::{demangle_symbolic_name(entry.name)}",
                            "short_name": demangle_symbolic_name(entry.name),
                            "address": ADDRESS_FMT.format(entry.data).strip(),
                            "iat_value": entry.iat_value,
                            "hint": entry.hint,
                        }
                    )
            except AttributeError:
                continue
    dll_list = [{"name": d, "tag": "NEEDED"} for d in list(dlls)]
    return imports_list, dll_list


def parse_pe_exports(exports):
    """
    Parses the exports and returns a list of exported symbols.

    Args:
        exports: The exports object to parse.

    Returns:
        list[dict]: A list of exported symbol dictionaries.

    """
    exports_list = []
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


def parse_macho_symbols(symbols):
    """
    Parses the symbols and determines the executable type.

    Args:
        symbols (it_symbols): A list of symbol objects to parse.

    Returns:
        tuple: A tuple containing two elements:
            - symbols_list (list): A list of symbol dictionaries.
            - exe_type (str): The determined executable type.
    """
    symbols_list = []
    exe_type = ""
    if not symbols or isinstance(symbols, lief.lief_errors):
        return symbols_list, exe_type
    for symbol in symbols:
        try:
            libname = ""
            if symbol.has_binding_info and symbol.binding_info.has_library:
                libname = symbol.binding_info.library.name
            address = symbol.value if symbol.value > 0 or not symbol.has_binding_info else symbol.binding_info.address
            symbol_value = ADDRESS_FMT.format(address).strip()
            symbol_name = symbol.demangled_name
            if not symbol_name or isinstance(symbol_name, lief.lief_errors):
                symbol_name = demangle_symbolic_name(symbol.name)
            else:
                symbol_name = demangle_symbolic_name(symbol_name)
            if not exe_type:
                exe_type = guess_exe_type(symbol_name)
            with warnings.catch_warnings(action="ignore"):
                symbols_list.append(
                    {
                        "name": (f"{libname}::{symbol_name}" if libname else symbol_name),
                        "short_name": symbol_name,
                        "category": symbol.category,
                        "type": symbol.type,
                        "num_sections": symbol.numberof_sections,
                        "description": symbol.description,
                        "address": symbol_value,
                        "export_info": {
                            "symbol": symbol.export_info.symbol, "kind": symbol.export_info.kind,
                            "flags": str(symbol.export_info.flags),
                            "offset": ADDRESS_FMT.format(symbol.export_info.offset),
                            "address": ADDRESS_FMT.format(symbol.export_info.address)
                        } if symbol.has_export_info else None,
                        "origin": symbol.origin,
                    }
                )
        except (AttributeError, TypeError):
            continue
    return symbols_list, exe_type


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
        if metadata.get("exe_type") == "PE32":
            arch = "i686"
        else:
            arch = "x86_64"
        return f"{arch}-pc-windows-msvc"
    vendor = "unknown"
    os = "unknown"
    env = ""
    machine_type = (metadata.get("machine_type") or metadata.get("cpu_type") or "").upper()
    endianness = metadata.get("endianness", "LSB").upper()
    arch_map = {
        "I386": "x86",
        "X86_64": "x86_64",
        "AMD64": "x86_64",
        "ARM": "arm",
        "AARCH64": "aarch64",
        "ARM64": "aarch64",
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
        os = "win32"
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
        os = os_map.get(platform, "darwin")
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
        os = os_map.get(os_abi, "linux")
    if metadata.get("is_targeting_android"):
        os = "linux"
        env = "android"
    elif os == "win32":
        env = "msvc"
    elif os == "linux":
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
    components = [arch, vendor, os]
    if env:
        components.append(env)
    return "-".join(components)


def construct_security_properties(metadata: dict, parsed_obj: lief.Binary) -> dict:
    """Constructs a summary of security mitigations."""
    has_symtab = metadata.get("static", False)
    properties = {
        "nx": metadata.get("has_nx", False),
        "pie": metadata.get("is_pie", False),
        "relro": metadata.get("relro", "no"),
        "canary": metadata.get("has_canary", False),
        "stripped": not has_symtab,
        "is_signed": bool(metadata.get("signatures")),
    }
    if isinstance(parsed_obj, lief.PE.Binary):
        if dll_chars := metadata.get("dll_characteristics", ""):
            properties["control_flow_guard"] = "CONTROL_FLOW_GUARD" in dll_chars
            properties["aslr"] = "DYNAMIC_BASE" in dll_chars
    return properties


def construct_binary_composition(metadata: dict, parsed_obj: lief.Binary) -> dict:
    """Summarizes the binary's composition."""
    composition = {}
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
        if "msvc" in dep_name: runtimes.add("msvcrt")
        if "libc.so" in dep_name: runtimes.add("glibc")
        for d in ("libstdc++", "openssl", "curl", "ffmpeg"):
            if d  in dep_name:
                runtimes.add("libstdc++")
    composition["runtime_dependencies"] = sorted(list(runtimes))
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


def add_derived_attributes(metadata: dict, parsed_obj: lief.Binary):
    """
    Adds various derived, high-level attributes to the metadata dictionary.
    """
    metadata["hashes"] = calculate_hashes(metadata["file_path"])
    metadata["security_properties"] = construct_security_properties(metadata, parsed_obj)
    metadata["binary_composition"] = construct_binary_composition(metadata, parsed_obj)
    build_info = {}
    if go_formulation := metadata.get("go_formulation"):
        build_info["language"] = "Go"
        build_info["go_version"] = go_formulation.get("go_version")
    elif metadata.get("rust_dependencies"):
        build_info["language"] = "Rust"
    elif metadata.get("is_dotnet"):
        build_info["language"] = ".NET"
    if "major_linker_version" in metadata:
        build_info["linker_version"] = f'{metadata["major_linker_version"]}.{metadata["minor_linker_version"]}'
    if isinstance(parsed_obj, lief.ELF.Binary):
        build_info["linking_type"] = "dynamic" if parsed_obj.has_interpreter else "static"
        if parsed_obj.has_section(".comment"):
            comment_section = parsed_obj.get_section(".comment")
            build_info["compiler_version"] = comment_section.content.tobytes().decode('ascii', 'ignore').strip('\x00')
    if build_info:
        metadata["build_info"] = build_info
    return metadata


def parse(exe_file, disassemble=False):  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
    """
    Parse the executable using lief and capture the metadata

    :param: exe_file Binary file
    :return Metadata dict
    """
    metadata = {"file_path": exe_file}
    try:
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
        metadata = standardize_keys(metadata)
        metadata["import_dependencies"] = analyze_import_deps(metadata)
        metadata["llvm_target_tuple"] = construct_llvm_target_tuple(metadata)
        metadata = add_derived_attributes(metadata, parsed_obj)
        if disassemble:
            metadata["disassembled_functions"] = disassemble_functions(parsed_obj, metadata)
    except (AttributeError, TypeError, ValueError) as e:
        LOG.exception(f"Caught {type(e)}: {e} while parsing {exe_file}.")
    return cleanup_dict_lief_errors(metadata)


def add_elf_metadata(exe_file, metadata, parsed_obj):
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
    metadata["is_targeting_android"] = parsed_obj.is_targeting_android
    metadata["virtual_size"] = parsed_obj.virtual_size
    metadata["has_nx"] = parsed_obj.has_nx
    metadata["has_interpreter"] = parsed_obj.has_interpreter
    metadata["has_notes"] = parsed_obj.has_notes
    metadata["has_overlay"] = parsed_obj.has_overlay
    metadata["use_gnu_hash"] = parsed_obj.use_gnu_hash
    metadata["use_sysv_hash"] = parsed_obj.use_sysv_hash
    metadata["eof_offset"] = parsed_obj.eof_offset
    metadata["relro"] = parse_relro(parsed_obj)
    metadata["exe_type"] = detect_exe_type(parsed_obj, metadata)
    # Canary check
    canary_sections = ["__stack_chk_fail", "__intel_security_cookie"]
    for section in canary_sections:
        if parsed_obj.get_symbol(section):
            if isinstance(parsed_obj.get_symbol(section), lief.lief_errors):
                metadata["has_canary"] = False
            else:
                metadata["has_canary"] = True
                break
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

    return metadata


def add_elf_header(header, metadata):
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


def add_elf_symbols(metadata, parsed_obj):
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
            symbol_version_auxiliary_cache = {}
            for entry in symbols_version:
                symbol_version_auxiliary = entry.symbol_version_auxiliary
                if symbol_version_auxiliary and not symbol_version_auxiliary_cache.get(
                        symbol_version_auxiliary.name
                ):
                    symbol_version_auxiliary_cache[symbol_version_auxiliary.name] = True
                    metadata["symbols_version"].append(
                        {
                            "name": demangle_symbolic_name(symbol_version_auxiliary.name),
                            "hash": symbol_version_auxiliary.hash,
                            "value": entry.value,
                        }
                    )
    except (AttributeError, TypeError) as e:
        LOG.debug(f"Caught {type(e)}: {e} while parsing elf symbols.")
        metadata["symbols_version"] = []
    return metadata


def add_elf_dynamic_entries(dynamic_entries, metadata):
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


def determine_elf_flags(header):
    """Determines the ELF flags based on the given ELF header.
    Args:
        header: The ELF header.

    Returns:
        A string representing the ELF flags.
    """
    eflags_str = ""
    if header.machine_type == lief.ELF.ARCH.ARM and hasattr(header, "arm_flags_list"):
        eflags_str = ", ".join(
            [enum_to_str(s) for s in header.arm_flags_list]
        )
    if header.machine_type in [
        lief.ELF.ARCH.MIPS,
        lief.ELF.ARCH.MIPS_RS3_LE,
        lief.ELF.ARCH.MIPS_X,
    ]:
        eflags_str = ", ".join(
            [enum_to_str(s) for s in header.flags_list]
        )
    if header.machine_type == lief.ELF.ARCH.PPC64:
        eflags_str = ", ".join(
            [enum_to_str(s) for s in header.ppc64_flags_list]
        )
    if header.machine_type == lief.ELF.ARCH.HEXAGON:
        eflags_str = ", ".join(
            [enum_to_str(s) for s in header.hexagon_flags_list]
        )
    return eflags_str


def parse_overlay(parsed_obj: lief.Binary) -> dict[str, dict]:
    """
    Parse the overlay section to extract dotnet dependencies
    Args:
        parsed_obj (lief.Binary): The parsed object representing the PE binary.

    Returns:
        dict: Dict representing the deps.json if available.
    """
    deps = {}
    if hasattr(parsed_obj, "overlay"):
        overlay = parsed_obj.overlay
        overlay_str = (
            codecs.decode(overlay.tobytes(), encoding="utf-8", errors="backslashreplace")
            .replace("\0", "")
            .replace("\r\n", "")
            .replace("\n", "")
            .replace("  ", "")
        )
        if overlay_str.find('{"runtimeTarget') > -1:
            start_index = overlay_str.find('{"runtimeTarget')
            end_index = overlay_str.rfind("}}}")
            if end_index > -1:
                overlay_str = overlay_str[start_index: end_index + 3]
                try:
                    # deps should have runtimeTarget, compilationOptions, targets, and libraries
                    # Use libraries to construct BOM components and targets for the dependency tree
                    deps = orjson.loads(overlay_str)
                except orjson.JSONDecodeError:
                    pass
    return deps


def parse_go_buildinfo(
        parsed_obj: lief.Binary,
) -> Tuple[dict[str, dict[str, str]], dict[str, str]]:
    """
    Parse the go build info section to extract go dependencies
    Args:
        parsed_obj (lief.Binary): The parsed object representing the binary.

    Returns:
        tuple(dict[str, str], dict[str, str]): Tuple representing the dependencies and formulation.
    """
    formulation = {}
    deps = {}
    build_info_str: str = ""
    # Look for specific buildinfo sections for ELF and MachO binaries
    build_info: lief.Section | None = None
    if isinstance(parsed_obj, lief.ELF.Binary):
        build_info = parsed_obj.get_section(".go.buildinfo")
    elif isinstance(parsed_obj, lief.MachO.Binary):
        build_info = parsed_obj.get_section("__go_buildinfo")
    if build_info and build_info.size:
        build_info_str = (
            codecs.decode(build_info.content.tobytes(), encoding="utf-8", errors="replace")
            .replace("\0", "")
            .replace("\uFFFD", "")
            .replace("\t", " ")
        ).strip()
        build_info_str = build_info_str.encode("ascii", "ignore").decode("ascii")
    elif isinstance(parsed_obj, lief.PE.Binary):
        # For PE binaries look for .data section
        s: lief.PE.Section = parsed_obj.get_section(".data")
        if s and not isinstance(s, lief.lief_errors):
            build_info_str = (
                codecs.decode(
                    s.content.tobytes()[: int(s.size / 32)], encoding="ascii", errors="replace"
                )
                .replace("\0", "")
                .replace("\uFFFD", "")
                .replace("\t", " ")
            )
    lines = build_info_str.split("\n")
    for line in lines:
        if line.startswith("Go buildinf:"):
            tmp_a = line.split("Go buildinf:")
            formulation["go_version"] = tmp_a[-1].split("\x19")[0].split(" ")[-1]
        if "path " in line:
            tmp_a = line.split("path ")
            formulation["path"] = tmp_a[-1]
        if line.startswith("mod "):
            tmp_a = line.split("mod ")
            formulation["module"] = tmp_a[-1]
        if line.startswith("dep "):
            tmp_a = line.removeprefix("dep ").split(" ")
            deps[tmp_a[0]] = {
                "version": tmp_a[1],
                "hash": tmp_a[2] if len(tmp_a) == 3 and tmp_a[2].startswith("h1:") else None,
            }
        if line.startswith("build "):
            tmp_a = line.removeprefix("build ").split("=")
            formulation[tmp_a[0].replace("-", "")] = tmp_a[1]

    return deps, formulation


def parse_rust_buildinfo(parsed_obj: lief.Binary) -> list:
    """
    Parse the rust build info section that are cargo-auditable to extract rust dependencies
    Args:
        parsed_obj (lief.Binary): The parsed object representing the binary.

    Returns:
        list: List representing the dependencies.
    """
    deps = []

    try:
        audit_data_section = next(
            filter(lambda section: section.name == ".dep-v0", parsed_obj.sections), None
        )
        if audit_data_section is not None and audit_data_section.content:
            json_string = zlib.decompress(audit_data_section.content)
            audit_data = orjson.loads(json_string)

            if audit_data and audit_data["packages"]:
                packages = audit_data["packages"]
                deps = [x for x in packages if "root" not in x]
    except orjson.JSONDecodeError:
        pass

    return deps


def analyze_import_deps(metadata):
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
    dep_graph = {"libraries": {}, "dependencies": []}
    main_binary_name = metadata.get("name")
    if not main_binary_name:
        return {}
    dep_graph["libraries"][main_binary_name] = {
        "type": "main_binary",
        "imported_symbols": [],
        "imported_from": []
    }
    binary_type = metadata.get("binary_type")
    if binary_type == "PE":
        for imp_entry in metadata.get("imports", []):
            full_name = imp_entry.get("name", "")
            if "::" in full_name:
                lib_name, func_name = full_name.split("::", 1)
            else:
                continue
            if lib_name not in dep_graph["libraries"]:
                dep_graph["libraries"][lib_name] = {
                    "type": "imported",
                    "imported_symbols": [],
                    "imported_from": []
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
                dep_graph["dependencies"].append({
                    "from": main_binary_name,
                    "to": lib_name,
                    "symbols": [func_name]
                })

            if lib_name not in dep_graph["libraries"][main_binary_name]["imported_from"]:
                dep_graph["libraries"][main_binary_name]["imported_from"].append(lib_name)
    else:
        all_potential_imports = metadata.get("symtab_symbols", []) + metadata.get("dynamic_symbols", [])
        needed_libs = set()
        if binary_type == "MachO":
             needed_libs.update([lib.get("name") for lib in metadata.get("libraries", []) if lib.get("name")])
        else:
             needed_libs.update([entry["name"] for entry in metadata.get("imports", []) if entry.get("tag") == "NEEDED"])
        for sym_entry in all_potential_imports:
            if sym_entry.get("is_imported", False):
                full_name = sym_entry.get("name", "")
                if not full_name:
                    continue
                func_name = full_name
                if "::" in full_name:
                    lib_name, func_name = full_name.split("::", 1)
                else:
                    if binary_type == "MachO" and "::" in full_name:
                        last_colon_pos = full_name.rindex("::")
                        lib_part_with_path = full_name[:last_colon_pos]
                        func_name = full_name[last_colon_pos+2:]
                        lib_name_from_path = lib_part_with_path.split("/")[-1].split("::")[0] if "::" in lib_part_with_path.split("/")[-1] else lib_part_with_path.split("/")[-1]
                        if lib_name_from_path in needed_libs:
                             lib_name = lib_name_from_path
                        elif needed_libs:
                             lib_name = next(iter(needed_libs))
                        else:
                             LOG.debug(f"MachO Symbol {full_name} has no clear library in path or NEEDED list.")
                             continue
                    elif needed_libs:
                         lib_name = next(iter(needed_libs))
                    elif ".go" in full_name or ".s" in full_name or "internal" in full_name:
                         lib_name = full_name
                    else:
                         if main_binary_name not in full_name:
                            LOG.debug(f"Symbol {full_name} is imported but no library info found.")
                         continue
                if not lib_name:
                     continue

                if lib_name not in dep_graph["libraries"]:
                    dep_graph["libraries"][lib_name] = {
                        "type": "imported",
                        "imported_symbols": [],
                        "imported_from": []
                    }

                if func_name not in dep_graph["libraries"][lib_name]["imported_symbols"] and func_name != lib_name:
                    dep_graph["libraries"][lib_name]["imported_symbols"].append(func_name)

                dep_exists = False
                for dep in dep_graph["dependencies"]:
                    if dep["from"] == main_binary_name and dep["to"] == lib_name:
                        if func_name not in dep["symbols"]:
                            dep["symbols"].append(func_name)
                        dep_exists = True
                        break
                if not dep_exists:
                    dep_graph["dependencies"].append({
                        "from": main_binary_name,
                        "to": lib_name,
                        "symbols": [func_name]
                    })

                if lib_name not in dep_graph["libraries"][main_binary_name]["imported_from"]:
                    dep_graph["libraries"][main_binary_name]["imported_from"].append(lib_name)
    if len(dep_graph['dependencies']):
        LOG.debug(f"Generated import dependency graph with {len(dep_graph['dependencies'])} dependencies.")
    return dep_graph


def add_pe_metadata(exe_file: str, metadata: dict, parsed_obj: lief.PE.Binary):
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
        metadata["imphash_pefile"] = lief.PE.get_imphash(parsed_obj, lief.PE.IMPHASH_MODE.PEFILE)
        metadata["imphash_lief"] = lief.PE.get_imphash(parsed_obj, lief.PE.IMPHASH_MODE.LIEF)
        metadata = add_pe_header_data(metadata, parsed_obj)
        metadata["data_directories"] = parse_pe_data(parsed_obj)
        metadata["authenticode"] = parse_pe_authenticode(parsed_obj)
        metadata["signatures"] = process_pe_signature(parsed_obj)
        metadata["resources"] = process_pe_resources(parsed_obj)
        metadata["symtab_symbols"], exe_type = parse_pe_symbols(parsed_obj.symbols)
        if exe_type:
            metadata["exe_type"] = exe_type
        (
            metadata["imports"],
            metadata["dynamic_entries"],
        ) = parse_pe_imports(parsed_obj.imports)
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
        metadata["functions"] = parse_functions(parsed_obj.functions)
        metadata["ctor_functions"] = parse_functions(parsed_obj.ctor_functions)
        metadata["exception_functions"] = parse_functions(parsed_obj.exception_functions)
        # Detect if this PE might be dotnet
        for i, dd in enumerate(parsed_obj.data_directories):
            if i == 14 and dd.type.value == lief.PE.DataDirectory.TYPES.CLR_RUNTIME_HEADER.value:
                metadata["is_dotnet"] = True
        metadata["dotnet_dependencies"] = parse_overlay(parsed_obj)
        metadata["go_dependencies"], metadata["go_formulation"] = parse_go_buildinfo(parsed_obj)
        metadata["rust_dependencies"] = parse_rust_buildinfo(parsed_obj)
        tls = parsed_obj.tls
        if tls and tls.sizeof_zero_fill:
            metadata["tls_address_index"] = ADDRESS_FMT.format(tls.addressof_index).strip()
            metadata["tls_sizeof_zero_fill"] = tls.sizeof_zero_fill
            metadata["tls_data_template_len"] = len(tls.data_template)
            metadata["tls_characteristics"] = tls.characteristics
            metadata["tls_section_name"] = tls.section.name
            metadata["tls_directory_type"] = str(tls.directory.type)
    except (AttributeError, IndexError, TypeError, ValueError) as e:
        LOG.debug(f"Caught {type(e)}: {e} while parsing {exe_file} PE metadata.")
        raise
    return metadata


def add_pe_header_data(metadata, parsed_obj):
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


def add_pe_optional_headers(metadata, optional_header):
    """Adds PE optional headers data to the metadata dictionary.

    Args:
        metadata: The dictionary to store the metadata.
        optional_header: The optional header of the PE binary.

    Returns:
        The updated metadata dictionary.
    """
    with contextlib.suppress(IndexError, TypeError):
        metadata["dll_characteristics"] = ", ".join(
            [
                enum_to_str(chara)
                for chara in optional_header.dll_characteristics_lists
            ]
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


def add_rdata_symbols(metadata, rdata_section, text_section, sections):
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
        for vari in (f"get{pii}", f"get_{pii}", f"get_{camel_to_snake(pii)}", f"Get{pii}"):
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
                {"name": sw, "type": "FUNCTION", "is_function": True, "is_imported": True}
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
            if "runtime." in block or "internal/" in block or re.match(file_extns_from_rdata, block):
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


def add_mach0_metadata(exe_file, metadata, parsed_obj):
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


def add_mach0_commands(metadata, parsed_obj: lief.MachO.Binary):
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
    return metadata


def add_mach0_versions(exe_file, metadata, parsed_obj):
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


def add_mach0_build_metadata(exe_file, metadata, parsed_obj):
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


def add_mach0_libraries(exe_file, metadata, parsed_obj):
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


def add_mach0_header_data(exe_file, metadata, parsed_obj):
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


def add_mach0_functions(metadata, parsed_obj):
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

    # Populate function info based on local symbols for .o files or others where parsed_obj.functions is empty.
    if not metadata["functions"]:
        metadata["functions"] = [
            {
                "idx": idx,
                "name": symbol["name"],
                "address": symbol["address"]
            }
            for idx, symbol in enumerate(s for s in metadata["symtab_symbols"] if s["category"] == lief.MachO.Symbol.CATEGORY.LOCAL)
        ]

    if exe_type:
        metadata["exe_type"] = exe_type
    if parsed_obj.dylinker:
        metadata["dylinker"] = parsed_obj.dylinker.name
    return metadata


def add_mach0_signature(exe_file, metadata, parsed_obj):
    """Extracts MachO code signature metadata from the parsed object and adds it to the metadata.

    Args:
        exe_file: The path of the executable file.
        metadata: The dictionary to store the metadata.
        parsed_obj: The parsed object representing the MachO binary.

    Returns:
        The updated metadata dictionary.
    """
    try:
        if parsed_obj.has_code_signature:
            code_signature = parsed_obj.code_signature
            metadata["code_signature"] = {
                "available": code_signature.size > 0,
                "data": str(code_signature.data.hex()),
                "data_size": str(code_signature.data_size),
                "size": str(code_signature.size),
            }
        if not parsed_obj.has_code_signature and parsed_obj.has_code_signature_dir:
            code_signature = parsed_obj.code_signature_dir
            metadata["code_signature"] = {
                "available": code_signature.size > 0,
                "data": str(code_signature.data.hex()),
                "data_size": str(code_signature.data_size),
                "size": str(code_signature.size),
            }
        if not parsed_obj.has_code_signature and not parsed_obj.has_code_signature_dir:
            metadata["code_signature"] = {"available": False}
        if parsed_obj.has_data_in_code:
            data_in_code = parsed_obj.data_in_code
            metadata["data_in_code"] = {
                "data": str(data_in_code.data.hex()),
                "data_size": str(data_in_code.data_size),
                "size": str(data_in_code.size),
            }
    except (AttributeError, TypeError) as e:
        LOG.debug(f"Caught {type(e)} while parsing {exe_file} Mach0 code signature.")
    return metadata


def parse_dex(dex_file):
    """Parse dex files"""
    metadata = {"file_path": dex_file}
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
