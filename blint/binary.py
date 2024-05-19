# pylint: disable=too-many-lines,consider-using-f-string
import codecs
import contextlib
import sys
from typing import Tuple
import zlib
import orjson

import lief

from blint.logger import DEBUG, LOG
from blint.utils import calculate_entropy, check_secret, cleanup_dict_lief_errors, decode_base64

SYMBOLIC_FOUND = True
try:
    from symbolic._lowlevel import ffi, lib
    from symbolic.utils import encode_str, decode_str, rustcall
except OSError:
    SYMBOLIC_FOUND = False

MIN_ENTROPY = 0.39
MIN_LENGTH = 80

# Enable lief logging in debug mode
if LOG.level != DEBUG:
    lief.logging.disable()

ADDRESS_FMT = "0x{:<10x}"


def demangle_symbolic_name(symbol, lang=None, no_args=False):
    """Demangles symbol using llvm demangle falling back to some heuristics. Covers legacy rust."""
    if not SYMBOLIC_FOUND:
        return symbol
    try:
        func = lib.symbolic_demangle_no_args if no_args else lib.symbolic_demangle
        lang_str = encode_str(lang) if lang else ffi.NULL
        demangled = rustcall(func, encode_str(symbol), lang_str)
        demangled_symbol = decode_str(demangled, free=True).strip()
        # demangling didn't work
        if symbol and symbol == demangled_symbol:
            for ign in ("__imp_anon.", "anon.", ".L__unnamed"):
                if symbol.startswith(ign):
                    return "anonymous"
            if symbol.startswith("GCC_except_table"):
                return "GCC_except_table"
            if symbol.startswith("@feat.00"):
                return "SAFESEH"
            if (
                symbol.startswith("__imp_")
                or symbol.startswith(".rdata$")
                or symbol.startswith(".refptr.")
            ):
                symbol = f"__declspec(dllimport) {symbol.removeprefix('__imp_').removeprefix('.rdata$').removeprefix('.refptr.')}"
            demangled_symbol = (
                symbol.replace("..", "::")
                .replace("$SP$", "@")
                .replace("$BP$", "*")
                .replace("$LT$", "<")
                .replace("$u5b$", "[")
                .replace("$u7b$", "{")
                .replace("$u3b$", ";")
                .replace("$u20$", " ")
                .replace("$u5d$", "]")
                .replace("$u7d$", "}")
                .replace("$GT$", ">")
                .replace("$RF$", "&")
                .replace("$LP$", "(")
                .replace("$RP$", ")")
                .replace("$C$", ",")
                .replace("$u27$", "'")
            )
        # In case of rust symbols, try and trim the hash part from the end of the symbols
        if demangled_symbol.count("::") > 3:
            last_part = demangled_symbol.split("::")[-1]
            if len(last_part) == 17:
                demangled_symbol = demangled_symbol.removesuffix(f"::{last_part}")
        return demangled_symbol
    except AttributeError:
        return symbol


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
        return parsed_obj.header.file_type == lief.ELF.E_TYPE.DYNAMIC
    if parsed_obj.format == lief.Binary.FORMATS.PE:
        return parsed_obj.header.has_characteristic(lief.PE.Header.CHARACTERISTICS.DLL)
    if parsed_obj.format == lief.Binary.FORMATS.MACHO:
        return parsed_obj.header.file_type == lief.MachO.FILE_TYPES.DYLIB
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
    type_str = str(type_str).rsplit(".", maxsplit=1)[-1]
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
    test_stmt = parsed_obj.get(lief.ELF.SEGMENT_TYPES.GNU_RELRO)
    if isinstance(test_stmt, lief.lief_errors):
        return "no"
    dynamic_tags = parsed_obj.get(lief.ELF.DYNAMIC_TAGS.FLAGS)
    bind_now, now = False, False
    if dynamic_tags and not isinstance(dynamic_tags, lief.lief_errors):
        bind_now = lief.ELF.DYNAMIC_FLAGS.BIND_NOW in dynamic_tags
    dynamic_tags = parsed_obj.get(lief.ELF.DYNAMIC_TAGS.FLAGS_1)
    if dynamic_tags and not isinstance(dynamic_tags, lief.lief_errors):
        now = lief.ELF.DYNAMIC_FLAGS_1.NOW in dynamic_tags
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
        LOG.debug("Parsing functions")
        for idx, f in enumerate(functions):
            if f.name and f.address:
                cleaned_name = demangle_symbolic_name(f.name)
                func_list.append(
                    {
                        "index": idx,
                        "name": cleaned_name,
                        "address": ADDRESS_FMT.format(f.address).strip(),
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
        LOG.debug("Parsing strings")
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
                                "value": (decode_base64(s) if s.endswith("==") else s),
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
    LOG.debug("Parsing symbols")
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
            symbols_list.append(
                {
                    "name": symbol_name,
                    "type": str(symbol.type).rsplit(".", maxsplit=1)[-1],
                    "value": symbol.value,
                    "visibility": str(symbol.visibility).rsplit(".", maxsplit=1)[-1],
                    "binding": str(symbol.binding).rsplit(".", maxsplit=1)[-1],
                    "is_imported": is_imported,
                    "is_exported": is_exported,
                    "information": symbol.information,
                    "is_function": symbol.is_function,
                    "is_static": symbol.is_static,
                    "is_variable": symbol.is_variable,
                    "version": str(symbol_version),
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
    LOG.debug("Parsing data dictionaries")
    data_directories = parsed_obj.data_directories
    if not data_directories or isinstance(data_directories, lief.lief_errors):
        return data_list
    for directory in data_directories:
        section_name = ""
        section_chars = ""
        section_entropy = ""
        dir_type = str(directory.type).rsplit(".", maxsplit=1)[-1]
        if not dir_type.startswith("?") and directory.size:
            if directory.has_section:
                if directory.section.has_characteristic:
                    section_chars = ", ".join(
                        [
                            str(chara).rsplit(".", maxsplit=1)[-1]
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
    LOG.debug("Parsing PE resources")
    rm = parsed_obj.resources_manager
    if not rm or isinstance(rm, lief.lief_errors):
        return {}
    resources = {}
    version_metadata = {}
    version_info: lief.PE.ResourceVersion = rm.version if rm.has_version else None
    if version_info and version_info.has_string_file_info:
        string_file_info: lief.PE.ResourceStringFileInfo = version_info.string_file_info
        for lc_item in string_file_info.langcode_items:
            if lc_item.items:
                version_metadata.update(lc_item.items)
    try:
        resources = {
            "has_accelerator": rm.has_accelerator,
            "has_dialogs": rm.has_dialogs,
            "has_html": rm.has_html,
            "has_icons": rm.has_icons,
            "has_manifest": rm.has_manifest,
            "has_string_table": rm.has_string_table,
            "has_version": rm.has_version,
            "manifest": (rm.manifest.replace("\\xef\\xbb\\xbf", "") if rm.has_manifest else None),
            "version_info": str(rm.version) if rm.has_version else None,
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
                "digest_algorithm": str(sig.digest_algorithm),
                "content_info": {
                    "content_type": lief.PE.oid_to_string(ci.content_type),
                    "digest_algorithm": str(ci.digest_algorithm),
                    "digest": ci.digest.hex(),
                },
            }
            signers_list = []
            for signer in sig.signers:
                signer_obj = {
                    "version": signer.version,
                    "serial_number": signer.serial_number.hex(),
                    "issuer": str(signer.issuer),
                    "digest_algorithm": str(signer.digest_algorithm),
                    "encryption_algorithm": str(signer.encryption_algorithm),
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
        LOG.debug("Parsing authentihash")
        sep = ":" if sys.version_info.minor > 7 else ()
        authenticode = {
            "md5_hash": parsed_obj.authentihash_md5.hex(*sep),
            "sha256_hash": parsed_obj.authentihash_sha256.hex(*sep),
            "sha512_hash": parsed_obj.authentihash_sha512.hex(*sep),
            "sha1_hash": parsed_obj.authentihash(lief.PE.ALGORITHMS.SHA_1).hex(*sep),
            "verification_flags": str(parsed_obj.verify_signature()).replace(
                "VERIFICATION_FLAGS.", ""
            ),
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
                        cert_signer_obj[tmp_key] = tmp_a[1].strip()
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
    LOG.debug("Parsing symbols")
    symbols_list = []
    exe_type = ""
    for symbol in symbols:
        if not symbol:
            continue
        try:
            if symbol.section_number <= 0:
                section_nb_str = str(lief.PE.SYMBOL_SECTION_NUMBER(symbol.section_number)).rsplit(
                    ".", maxsplit=1
                )[-1]
            elif symbol.section and symbol.section.name:
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
                        "id": section_nb_str,
                        "base_type": str(symbol.base_type).rsplit(".", maxsplit=1)[-1],
                        "complex_type": str(symbol.complex_type).rsplit(".", maxsplit=1)[-1],
                        "storage_class": str(symbol.storage_class).rsplit(".", maxsplit=1)[-1],
                    }
                )
        except (IndexError, AttributeError, ValueError) as e:
            LOG.debug(f"Caught {type(e)}: {e} while parsing {symbol}.")
        except RuntimeError:
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
    LOG.debug("Parsing imports")
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
                            "data": entry.data,
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
    LOG.debug("Parsing exports")
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
                "address": ADDRESS_FMT.format(entry.address),
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
    LOG.debug("Parsing symbols")
    symbols_list = []
    exe_type = ""
    if not symbols or isinstance(symbols, lief.lief_errors):
        return symbols_list, exe_type
    for symbol in symbols:
        try:
            libname = ""
            if symbol.has_binding_info and symbol.binding_info.has_library:
                libname = symbol.binding_info.library.name
            symbol_value = (
                symbol.value
                if symbol.value > 0 or not symbol.has_binding_info
                else ADDRESS_FMT.format(symbol.binding_info.address)
            )
            symbol_name = symbol.demangled_name
            if not symbol_name or isinstance(symbol_name, lief.lief_errors):
                symbol_name = demangle_symbolic_name(symbol.name)
            else:
                symbol_name = demangle_symbolic_name(symbol_name)
            if not exe_type:
                exe_type = guess_exe_type(symbol_name)
            symbols_list.append(
                {
                    "name": (f"{libname}::{symbol_name}" if libname else symbol_name),
                    "short_name": symbol_name,
                    "type": symbol.type,
                    "num_sections": symbol.numberof_sections,
                    "description": symbol.description,
                    "value": symbol_value,
                }
            )
        except (AttributeError, TypeError):
            continue
    return symbols_list, exe_type


def parse(exe_file):  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
    """
    Parse the executable using lief and capture the metadata

    :param: exe_file Binary file
    :return Metadata dict
    """
    metadata = {"file_path": exe_file}
    try:
        parsed_obj = lief.parse(exe_file)
        metadata["is_shared_library"] = is_shared_library(parsed_obj)
        # ELF Binary
        if isinstance(parsed_obj, lief.ELF.Binary):
            metadata = add_elf_metadata(exe_file, metadata, parsed_obj)
        elif isinstance(parsed_obj, lief.PE.Binary):
            # PE
            metadata = add_pe_metadata(exe_file, metadata, parsed_obj)
        elif isinstance(parsed_obj, lief.MachO.Binary):
            metadata = add_mach0_metadata(exe_file, metadata, parsed_obj)
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
    metadata["interpreter"] = parsed_obj.interpreter
    metadata["is_pie"] = parsed_obj.is_pie
    metadata["virtual_size"] = parsed_obj.virtual_size
    metadata["has_nx"] = parsed_obj.has_nx
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
    rpath = parsed_obj.get(lief.ELF.DYNAMIC_TAGS.RPATH)
    if isinstance(rpath, lief.lief_errors):
        metadata["has_rpath"] = False
    elif rpath:
        metadata["has_rpath"] = True
    # runpath check
    runpath = parsed_obj.get(lief.ELF.DYNAMIC_TAGS.RUNPATH)
    if isinstance(runpath, lief.lief_errors):
        metadata["has_runpath"] = False
    elif runpath:
        metadata["has_runpath"] = True
    # This is getting renamed to symtab_symbols in lief 0.15.0
    static_symbols = parsed_obj.static_symbols
    metadata["static"] = bool(static_symbols and not isinstance(static_symbols, lief.lief_errors))
    dynamic_entries = parsed_obj.dynamic_entries
    metadata = add_elf_dynamic_entries(dynamic_entries, metadata)
    metadata = add_elf_symbols(metadata, parsed_obj)
    metadata["notes"] = parse_notes(parsed_obj)
    metadata["strings"] = parse_strings(parsed_obj)
    metadata["symtab_symbols"], exe_type = parse_symbols(static_symbols)
    if exe_type:
        metadata["exe_type"] = exe_type
    metadata["dynamic_symbols"], exe_type = parse_symbols(parsed_obj.dynamic_symbols)
    if exe_type:
        metadata["exe_type"] = exe_type
    metadata["functions"] = parse_functions(parsed_obj.functions)
    metadata["ctor_functions"] = parse_functions(parsed_obj.ctor_functions)
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
        metadata["class"] = str(header.identity_class).rsplit(".", maxsplit=1)[-1]
        metadata["endianness"] = str(header.identity_data).rsplit(".", maxsplit=1)[-1]
        metadata["identity_version"] = str(header.identity_version).rsplit(".", maxsplit=1)[-1]
        metadata["identity_os_abi"] = str(header.identity_os_abi).rsplit(".", maxsplit=1)[-1]
        metadata["identity_abi_version"] = header.identity_abi_version
        metadata["file_type"] = str(header.file_type).rsplit(".", maxsplit=1)[-1]
        metadata["machine_type"] = str(header.machine_type).rsplit(".", maxsplit=1)[-1]
        metadata["object_file_version"] = str(header.object_file_version).rsplit(".", maxsplit=1)[
            -1
        ]
        metadata["entrypoint"] = header.entrypoint
        metadata["processor_flag"] = str(header.processor_flag) + eflags_str
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
        if entry.tag == lief.ELF.DYNAMIC_TAGS.NULL:
            continue
        if entry.tag in [
            lief.ELF.DYNAMIC_TAGS.SONAME,
            lief.ELF.DYNAMIC_TAGS.NEEDED,
            lief.ELF.DYNAMIC_TAGS.RUNPATH,
            lief.ELF.DYNAMIC_TAGS.RPATH,
        ]:
            metadata["dynamic_entries"].append(
                {
                    "name": demangle_symbolic_name(entry.name),
                    "tag": str(entry.tag).rsplit(".", maxsplit=1)[-1],
                    "value": entry.value,
                }
            )
            # Detect dotnet binary
            if "netcoredeps" in entry.name:
                metadata["exe_type"] = "dotnetbinary"
    return metadata


def determine_elf_flags(header):
    """Determines the ELF flags based on the given ELF header.
    Args:
        header: The ELF header.

    Returns:
        A string representing the ELF flags.
    """
    eflags_str = ""
    if header.machine_type == lief.ELF.ARCH.ARM:
        eflags_str = " - ".join(
            [str(s).rsplit(".", maxsplit=1)[-1] for s in header.arm_flags_list]
        )
    if header.machine_type in [
        lief.ELF.ARCH.MIPS,
        lief.ELF.ARCH.MIPS_RS3_LE,
        lief.ELF.ARCH.MIPS_X,
    ]:
        eflags_str = " - ".join(
            [str(s).rsplit(".", maxsplit=1)[-1] for s in header.mips_flags_list]
        )
    if header.machine_type == lief.ELF.ARCH.PPC64:
        eflags_str = " - ".join(
            [str(s).rsplit(".", maxsplit=1)[-1] for s in header.ppc64_flags_list]
        )
    if header.machine_type == lief.ELF.ARCH.HEXAGON:
        eflags_str = " - ".join(
            [str(s).rsplit(".", maxsplit=1)[-1] for s in header.hexagon_flags_list]
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
                overlay_str = overlay_str[start_index : end_index + 3]
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
    build_info: lief.Section = None
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
    Parse the rust build info section of binaries that are cargo-auditable to extract rust dependencies
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
            metadata["tls_address_index"] = tls.addressof_index
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
            )
            metadata["overlay_number"] = dos_header.overlay_number
            metadata["oem_id"] = dos_header.oem_id
            metadata["oem_info"] = dos_header.oem_info
            metadata["address_new_exeheader"] = ADDRESS_FMT.format(
                dos_header.addressof_new_exeheader
            )
            metadata["characteristics"] = ", ".join(
                [str(chara).rsplit(".", maxsplit=1)[-1] for chara in header.characteristics_list]
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
                str(chara).rsplit(".", maxsplit=1)[-1]
                for chara in optional_header.dll_characteristics_lists
            ]
        )
        # Detect if this binary is a driver
        if "WDM_DRIVER" in metadata["dll_characteristics"]:
            metadata["is_driver"] = True
        metadata["subsystem"] = str(optional_header.subsystem).rsplit(".", maxsplit=1)[-1]
        metadata["is_gui"] = metadata["subsystem"] == "WINDOWS_GUI"
        metadata["exe_type"] = "PE32" if optional_header.magic == lief.PE.PE_TYPE.PE32 else "PE64"
        metadata["major_linker_version"] = optional_header.major_linker_version
        metadata["minor_linker_version"] = optional_header.minor_linker_version
        metadata["sizeof_code"] = optional_header.sizeof_code
        metadata["sizeof_initialized_data"] = optional_header.sizeof_initialized_data
        metadata["sizeof_uninitialized_data"] = optional_header.sizeof_uninitialized_data
        metadata["addressof_entrypoint"] = ADDRESS_FMT.format(optional_header.addressof_entrypoint)
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


def add_mach0_commands(metadata, parsed_obj):
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
        metadata["platform"] = str(build_version.platform).rsplit(".", maxsplit=1)[-1]
        metadata["minos"] = "{:d}.{:d}.{:d}".format(*build_version.minos)
        metadata["sdk"] = "{:d}.{:d}.{:d}".format(*build_version.sdk)
        if tools := build_version.tools:
            metadata["tools"] = []
            for tool in tools:
                tool_str = str(tool.tool).rsplit(".", maxsplit=1)[-1]
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
        flags_str = ", ".join([str(s).rsplit(".", maxsplit=1)[-1] for s in header.flags_list])
        metadata["magic"] = str(header.magic).rsplit(".", maxsplit=1)[-1]
        metadata["cpu_type"] = str(header.cpu_type).rsplit(".", maxsplit=1)[-1]
        metadata["cpu_subtype"] = header.cpu_subtype
        metadata["file_type"] = str(header.file_type).rsplit(".", maxsplit=1)[-1]
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
