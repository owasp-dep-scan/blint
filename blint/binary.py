import contextlib
import sys

import lief

from blint.logger import DEBUG, LOG
from blint.utils import calculate_entropy, check_secret, \
    cleanup_dict_lief_errors, cleanup_list_lief_errors, decode_base64

MIN_ENTROPY = 0.39
MIN_LENGTH = 80

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
        return parsed_obj.header.file_type == lief.ELF.E_TYPE.DYNAMIC
    if parsed_obj.format == lief.Binary.FORMATS.PE:
        return parsed_obj.header.has_characteristic(
            lief.PE.Header.CHARACTERISTICS.DLL
        )
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
    if not notes:
        return data
    data.extend(extract_note_data(idx, note) for idx, note in enumerate(notes))
    return cleanup_list_lief_errors(data)


def extract_note_data(idx, note):
    """
    Extracts metadata from a note object and returns a dictionary.

    Args:
        idx (int): The index of the note.
        note: The note object to extract data from.
    
    Returns:
        dict: A dictionary containing the extracted metadata
    """
    note_str = str(note)
    build_id = ""
    if "ID Hash" in note_str:
        build_id = note_str.rsplit("ID Hash:", maxsplit=1)[-1].strip()
    description = note.description
    description_str = " ".join(map(integer_to_hex_str, description[:16]))
    if len(description) > 16:
        description_str += " ..."
    type_str = note.type_core if note.is_core else note.type
    type_str = str(type_str).rsplit(".", maxsplit=1)[-1]
    note_details = note.details
    note_details_str = ""
    sdk_version = ""
    ndk_version = ""
    ndk_build_number = ""
    abi = ""
    version_str = ""
    if isinstance(note_details, lief.ELF.AndroidIdent):
        sdk_version = note_details.sdk_version
        ndk_version = note_details.ndk_version
        ndk_build_number = note_details.ndk_build_number
    if isinstance(note_details, lief.ELF.NoteAbi):
        version = note_details.version
        abi = str(note_details.abi)
        version_str = f"{version[0]}.{version[1]}.{version[2]}"
    if not version_str and type_str == "BUILD_ID" and build_id:
        version_str = build_id
    if note.is_core:
        note_details_str = note.details
    return cleanup_dict_lief_errors({
        "index": idx, "description": description_str, "type": type_str,
        "details": note_details_str, "sdk_version": sdk_version,
        "ndk_version": ndk_version, "ndk_build_number": ndk_build_number,
        "abi": abi, "version": version_str, "build_id": build_id,
    })


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
                cleaned_name = f.name.replace("..", "::")
                func_list.append(
                    {
                        "index": idx,
                        "name": cleaned_name,
                        "address": ADDRESS_FMT.format(f.address),
                    }
                )
    return cleanup_list_lief_errors(func_list)


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
                    if (
                        entropy and
                        (entropy > MIN_ENTROPY or len(s) > MIN_LENGTH)
                    ) or secret_type:
                        strings_list.append(
                            {
                                "value": (
                                    decode_base64(s) if s.endswith("==") else s
                                ),
                                "entropy": entropy,
                                "secret_type": secret_type,
                            }
                        )
            except (AttributeError, TypeError):
                continue
    return cleanup_list_lief_errors(strings_list)


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
            if symbol.imported and not isinstance(
                    symbol.imported, lief.lief_errors):
                is_imported = True
            if symbol.exported and not isinstance(
                    symbol.exported, lief.lief_errors):
                is_exported = True
            symbol_name = symbol.demangled_name
            if isinstance(symbol_name, lief.lief_errors):
                symbol_name = symbol.name
            exe_type = guess_exe_type(symbol_name)
            symbols_list.append(
                {
                    "name": symbol_name,
                    "type": str(symbol.type).rsplit(".", maxsplit=1)[-1],
                    "value": symbol.value,
                    "visibility": str(symbol.visibility).rsplit(
                        ".", maxsplit=1
                    )[-1],
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
    return cleanup_list_lief_errors(symbols_list), exe_type


def parse_interpreter(parsed_obj):
    """
    Parses the interpreter information from the given parsed binary object.

    Args:
        parsed_obj: The parsed binary object to extract the interpreter from.

    Returns:
        str: The interpreter information of the binary object.
    """
    try:
        interpreter =  parsed_obj.interpreter
        if isinstance(interpreter, lief.lief_errors):
            raise AttributeError
        return interpreter
    except AttributeError:
        return ""


def detect_exe_type(parsed_obj, metadata):
    """
    Detects the type of the parsed binary object based on its characteristics 
    and metadata.

    Args:
        parsed_obj: The parsed binary object to analyze.
        metadata (dict): The metadata dictionary containing binary information .

    Returns:
        str: The detected type of the binary.
    """
    try:
        if parsed_obj.has_section(".note.go.buildid"):
            return "gobinary"
        if (
            parsed_obj.has_section(".note.gnu.build-id")
            or "musl" in metadata.get("interpreter")
            or "ld-linux" in metadata.get("interpreter")
        ):
            return "genericbinary"
        if metadata.get("machine_type") and metadata.get("file_type"):
            return (f'{metadata.get("machine_type")}-'
                    f'{metadata.get("file_type")}').lower()
        if metadata["relro"] in ("partial", "full"):
            return "genericbinary"
    except (AttributeError, TypeError):
        return ""
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
    with contextlib.suppress(AttributeError, IndexError):
        LOG.debug("Parsing data dictionaries")
        data_directories = parsed_obj.data_directories
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
                                for chara
                                in directory.section.characteristics_lists
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
    return cleanup_list_lief_errors(data_list)


def process_pe_resources(parsed_obj):
    """
    Processes the resources of the parsed PE (Portable Executable) binary object
    and returns metadata about the resources.

    Args:
        parsed_obj: The parsed PE binary object to process the resources from.

    Returns:
        dict: A dictionary containing metadata about the resources
    """
    try:
        LOG.debug("Parsing PE resources")
        rm = parsed_obj.resources_manager
        return cleanup_dict_lief_errors({
            "has_accelerator": rm.has_accelerator, "has_dialogs": rm.has_dialogs,
            "has_html": rm.has_html, "has_icons": rm.has_icons,
            "has_manifest": rm.has_manifest,
            "has_string_table": rm.has_string_table,
            "has_version": rm.has_version,
            "html": rm.html if rm.has_html else None, "manifest": (
            rm.manifest.replace("\\xef\\xbb\\xbf",
                                "") if rm.has_manifest else None),
            "version_info": str(rm.version) if rm.has_version else None,
        })
    except AttributeError:
        return {}


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
    return cleanup_list_lief_errors(signature_list)


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
        authenticode = {}
        sep = ":" if sys.version_info.minor > 7 else ()
        authenticode["md5_hash"] = parsed_obj.authentihash_md5.hex(*sep)
        authenticode["sha256_hash"] = parsed_obj.authentihash_sha256.hex(*sep)
        authenticode["sha512_hash"] = parsed_obj.authentihash_sha512.hex(*sep)
        authenticode["sha1_hash"] = parsed_obj.authentihash(
            lief.PE.ALGORITHMS.SHA_1
        ).hex(*sep)
        authenticode["verification_flags"] = str(
            parsed_obj.verify_signature()
        ).replace("VERIFICATION_FLAGS.", "")
        if (
            parsed_obj.signatures
            and len(parsed_obj.signatures) > 0
            and parsed_obj.signatures[0].signers
        ):
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
        return cleanup_dict_lief_errors(authenticode)
    except (AttributeError, IndexError, KeyError, TypeError):
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
        try:
            if symbol.section_number <= 0:
                section_nb_str = str(
                    lief.PE.SYMBOL_SECTION_NUMBER(symbol.section_number)
                ).rsplit(".", maxsplit=1)[-1]
            else:
                try:
                    section_nb_str = symbol.section.name
                except AttributeError:
                    section_nb_str = "section<{:d}>".format(
                        symbol.section_number
                    )
        except (AttributeError, TypeError):
            section_nb_str = ""
        with contextlib.suppress(IndexError, AttributeError, ValueError):
            if not exe_type:
                try:
                    exe_type = guess_exe_type(symbol.name.lower())
                except AttributeError:
                    exe_type = ""
            if symbol.name:
                symbols_list.append(
                    {
                        "name": symbol.name.replace("..", "::"),
                        "value": symbol.value,
                        "id": section_nb_str,
                        "base_type": str(symbol.base_type).rsplit(
                            ".", maxsplit=1
                        )[-1],
                        "complex_type": str(symbol.complex_type).rsplit(
                            ".", maxsplit=1
                        )[-1],
                        "storage_class": str(symbol.storage_class).rsplit(
                            ".", maxsplit=1
                        )[-1],
                    }
                )
    return cleanup_list_lief_errors(symbols_list), exe_type


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
    for import_ in imports:
        try:
            entries = import_.entries
        except AttributeError:
            break
        for entry in entries:
            try:
                if entry.name:
                    dlls.add(import_.name)
                    imports_list.append(
                        {
                            "name": f"{import_.name}::{entry.name}",
                            "short_name": entry.name,
                            "data": entry.data,
                            "iat_value": entry.iat_value,
                            "hint": entry.hint,
                        }
                    )
            except AttributeError:
                continue
    dll_list = [{"name": d, "tag": "NEEDED"} for d in list(dlls)]
    return cleanup_list_lief_errors(imports_list), cleanup_list_lief_errors(dll_list)


def parse_pe_exports(exports):
    """
    Parses the exports and returns a list of exported symbols.

    Args:
        exports: The exports object to parse.

    Returns:
        list[dict]: A list of exported symbol dictionaries.

    """
    exports_list = []
    with contextlib.suppress(AttributeError):
        LOG.debug("Parsing exports")
        entries = exports.entries
        metadata = {}
        for entry in entries:
            extern = "[EXTERN]" if entry.is_extern else ""
            if entry.name:
                metadata = {
                    "name": entry.name,
                    "ordinal": entry.ordinal,
                    "address": ADDRESS_FMT.format(entry.address),
                    "extern": extern,
                }
            fwd = entry.forward_information if entry.is_forwarded else None
            metadata["is_forwarded"] = entry.is_forwarded
            if fwd:
                metadata["fwd_library"] = fwd.library
                metadata["fwd_function"] = fwd.function
            exports_list.append(metadata)
    return cleanup_list_lief_errors(exports_list)


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
    if not symbols:
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

            try:
                symbol_name = symbol.demangled_name
            except AttributeError:
                symbol_name = symbol.name
            symbol_name = symbol_name.replace("..", "::")
            if not exe_type:
                exe_type = guess_exe_type(symbol_name)
            symbols_list.append(
                {
                    "name": (
                        f"{libname}::{symbol_name}"
                        if libname
                        else symbol_name
                    ),
                    "short_name": symbol_name,
                    "type": symbol.type,
                    "num_sections": symbol.numberof_sections,
                    "description": symbol.description,
                    "value": symbol_value,
                }
            )
        except (AttributeError, TypeError):
            continue
    return cleanup_list_lief_errors(symbols_list), exe_type


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
            metadata["binary_type"] = "ELF"
            header = parsed_obj.header
            identity = header.identity
            eflags_str = ""
            if header.machine_type == lief.ELF.ARCH.ARM:
                eflags_str = " - ".join(
                    [
                        str(s).rsplit(".", maxsplit=1)[-1]
                        for s in header.arm_flags_list
                    ]
                )
            if header.machine_type in [
                lief.ELF.ARCH.MIPS,
                lief.ELF.ARCH.MIPS_RS3_LE,
                lief.ELF.ARCH.MIPS_X,
            ]:
                eflags_str = " - ".join(
                    [
                        str(s).rsplit(".", maxsplit=1)[-1]
                        for s in header.mips_flags_list
                    ]
                )
            if header.machine_type == lief.ELF.ARCH.PPC64:
                eflags_str = " - ".join(
                    [
                        str(s).rsplit(".", maxsplit=1)[-1]
                        for s in header.ppc64_flags_list
                    ]
                )
            if header.machine_type == lief.ELF.ARCH.HEXAGON:
                eflags_str = " - ".join(
                    [
                        str(s).rsplit(".", maxsplit=1)[-1]
                        for s in header.hexagon_flags_list
                    ]
                )
            metadata["magic"] = ("{:<02x} " * 8).format(*identity[:8]).strip()
            metadata["class"] = str(header.identity_class).rsplit(
                ".", maxsplit=1
            )[-1]
            metadata["endianness"] = str(header.identity_data).rsplit(
                ".", maxsplit=1
            )[-1]
            metadata["identity_version"] = str(header.identity_version).rsplit(
                ".", maxsplit=1
            )[-1]
            metadata["identity_os_abi"] = str(header.identity_os_abi).rsplit(
                ".", maxsplit=1
            )[-1]
            metadata["identity_abi_version"] = header.identity_abi_version
            metadata["file_type"] = str(header.file_type).rsplit(
                ".", maxsplit=1
            )[-1]
            metadata["machine_type"] = str(header.machine_type).rsplit(
                ".", maxsplit=1
            )[-1]
            metadata["object_file_version"] = str(
                header.object_file_version
            ).rsplit(".", maxsplit=1)[-1]
            metadata["entrypoint"] = header.entrypoint
            metadata["processor_flag"] = str(header.processor_flag) + eflags_str
            metadata["name"] = exe_file
            metadata["imagebase"] = parsed_obj.imagebase
            metadata["interpreter"] = parse_interpreter(parsed_obj)
            metadata["is_pie"] = parsed_obj.is_pie
            metadata["virtual_size"] = parsed_obj.virtual_size
            metadata["has_nx"] = parsed_obj.has_nx
            metadata["relro"] = parse_relro(parsed_obj)
            metadata["exe_type"] = detect_exe_type(parsed_obj, metadata)
            # Canary check
            canary_sections = ["__stack_chk_fail", "__intel_security_cookie"]
            for section in canary_sections:
                if parsed_obj.get_symbol(section):
                    if isinstance(
                            parsed_obj.get_symbol(section), lief.lief_errors):
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
            static_symbols = parsed_obj.static_symbols
            if static_symbols and not isinstance(
                    static_symbols, lief.lief_errors):
                metadata["static"] = True
            dynamic_entries = parsed_obj.dynamic_entries
            if dynamic_entries and not isinstance(
                dynamic_entries, lief.lief_errors
            ):
                metadata["dynamic_entries"] = []
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
                                "name": entry.name,
                                "tag": str(entry.tag).rsplit(".", maxsplit=1)[
                                    -1
                                ],
                                "value": entry.value,
                            }
                        )
                        # Detect dotnet binary
                        if "netcoredeps" in entry.name:
                            metadata["exe_type"] = "dotnetbinary"
            try:
                symbols_version = parsed_obj.symbols_version
                if len(symbols_version):
                    metadata["symbols_version"] = []
                    symbol_version_auxiliary_cache = {}
                    for entry in symbols_version:
                        symbol_version_auxiliary = (
                            entry.symbol_version_auxiliary
                        )
                        if (
                            symbol_version_auxiliary
                            and not symbol_version_auxiliary_cache.get(
                                symbol_version_auxiliary.name
                            )
                        ):
                            symbol_version_auxiliary_cache[
                                symbol_version_auxiliary.name
                            ] = True
                            metadata["symbols_version"].append(
                                {
                                    "name": symbol_version_auxiliary.name,
                                    "hash": symbol_version_auxiliary.hash,
                                    "value": entry.value,
                                }
                            )
            except (AttributeError, TypeError):
                metadata["symbols_version"] = []
            try:
                notes = parsed_obj.notes
                if notes:
                    metadata["notes"] = parse_notes(parsed_obj)
            except (AttributeError, TypeError):
                pass
            metadata["strings"] = parse_strings(parsed_obj)
            try:
                metadata["static_symbols"], exe_type = parse_symbols(
                    parsed_obj.static_symbols
                )
                if exe_type:
                    metadata["exe_type"] = exe_type
            except AttributeError:
                pass
            try:
                metadata["dynamic_symbols"], exe_type = parse_symbols(
                    parsed_obj.dynamic_symbols
                )
                if exe_type:
                    metadata["exe_type"] = exe_type
            except AttributeError:
                pass
            try:
                metadata["functions"] = parse_functions(parsed_obj.functions)
            except AttributeError:
                pass
            try:
                metadata["ctor_functions"] = parse_functions(
                    parsed_obj.ctor_functions
                )
            except AttributeError:
                pass
        elif isinstance(parsed_obj, lief.PE.Binary):
            # PE
            # Parse header
            try:
                metadata["binary_type"] = "PE"
                metadata["name"] = exe_file
                metadata["is_pie"] = parsed_obj.is_pie
                metadata["is_reproducible_build"] = (
                    parsed_obj.is_reproducible_build
                )
                metadata["virtual_size"] = parsed_obj.virtual_size
                metadata["has_nx"] = parsed_obj.has_nx
                dos_header = parsed_obj.dos_header
                metadata["magic"] = str(dos_header.magic)
                header = parsed_obj.header
                optional_header = parsed_obj.optional_header
                metadata["used_bytes_in_the_last_page"] = (
                    dos_header.used_bytes_in_last_page
                )
                metadata["file_size_in_pages"] = dos_header.file_size_in_pages
                metadata["num_relocation"] = dos_header.numberof_relocation
                metadata["header_size_in_paragraphs"] = (
                    dos_header.header_size_in_paragraphs
                )
                metadata["minimum_extra_paragraphs"] = (
                    dos_header.minimum_extra_paragraphs
                )
                metadata["maximum_extra_paragraphs"] = (
                    dos_header.maximum_extra_paragraphs
                )
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
                    [
                        str(chara).rsplit(".", maxsplit=1)[-1]
                        for chara in header.characteristics_list
                    ]
                )
                metadata["num_sections"] = header.numberof_sections
                metadata["time_date_stamps"] = header.time_date_stamps
                metadata["pointer_symbol_table"] = header.pointerto_symbol_table
                metadata["num_symbols"] = header.numberof_symbols
                metadata["size_optional_header"] = header.sizeof_optional_header
                metadata["dll_characteristics"] = ", ".join(
                    [
                        str(chara).rsplit(".", maxsplit=1)[-1]
                        for chara in optional_header.dll_characteristics_lists
                    ]
                )
                metadata["subsystem"] = str(optional_header.subsystem).rsplit(
                    ".", maxsplit=1
                )[-1]
                metadata["is_gui"] = metadata["subsystem"] == "WINDOWS_GUI"
                metadata["exe_type"] = (
                    "PE32"
                    if optional_header.magic == lief.PE.PE_TYPE.PE32
                    else "PE64"
                )
                metadata["major_linker_version"] = (
                    optional_header.major_linker_version
                )
                metadata["minor_linker_version"] = (
                    optional_header.minor_linker_version
                )
                metadata["sizeof_code"] = optional_header.sizeof_code
                metadata["sizeof_initialized_data"] = (
                    optional_header.sizeof_initialized_data
                )
                metadata["sizeof_uninitialized_data"] = (
                    optional_header.sizeof_uninitialized_data
                )
                metadata["addressof_entrypoint"] = ADDRESS_FMT.format(
                    optional_header.addressof_entrypoint
                )
                metadata["baseof_code"] = optional_header.baseof_code
                metadata["baseof_data"] = optional_header.baseof_data
                metadata["imagebase"] = optional_header.imagebase
                metadata["section_alignment"] = (
                    optional_header.section_alignment
                )
                metadata["file_alignment"] = optional_header.file_alignment
                metadata["major_operating_system_version"] = (
                    optional_header.major_operating_system_version
                )
                metadata["minor_operating_system_version"] = (
                    optional_header.minor_operating_system_version
                )
                metadata["major_image_version"] = (
                    optional_header.major_image_version
                )
                metadata["minor_image_version"] = (
                    optional_header.minor_image_version
                )
                metadata["major_subsystem_version"] = (
                    optional_header.major_subsystem_version
                )
                metadata["minor_subsystem_version"] = (
                    optional_header.minor_subsystem_version
                )
                metadata["win32_version_value"] = (
                    optional_header.win32_version_value
                )
                metadata["sizeof_image"] = optional_header.sizeof_image
                metadata["sizeof_headers"] = optional_header.sizeof_headers
                metadata["checksum"] = optional_header.checksum
                metadata["sizeof_stack_reserve"] = (
                    optional_header.sizeof_stack_reserve
                )
                metadata["sizeof_stack_commit"] = (
                    optional_header.sizeof_stack_commit
                )
                metadata["sizeof_heap_reserve"] = (
                    optional_header.sizeof_heap_reserve
                )
                metadata["sizeof_heap_commit"] = (
                    optional_header.sizeof_heap_commit
                )
                metadata["loader_flags"] = optional_header.loader_flags
                metadata["numberof_rva_and_size"] = (
                    optional_header.numberof_rva_and_size
                )
            except Exception:
                pass
                metadata["data_directories"] = parse_pe_data(parsed_obj)
                metadata["authenticode"] = parse_pe_authenticode(parsed_obj)
                metadata["signatures"] = process_pe_signature(parsed_obj)
                metadata["resources"] = process_pe_resources(parsed_obj)

            try:
                metadata["static_symbols"], exe_type = parse_pe_symbols(
                    parsed_obj.symbols
                )
                if exe_type:
                    metadata["exe_type"] = exe_type
            except AttributeError:
                pass
            try:
                (
                    metadata["imports"],
                    metadata["dynamic_entries"],
                ) = parse_pe_imports(parsed_obj.imports)
            except AttributeError:
                pass
            try:
                metadata["exports"] = parse_pe_exports(parsed_obj.get_export())
            except AttributeError:
                pass
            try:
                metadata["functions"] = parse_functions(parsed_obj.functions)
            except AttributeError:
                pass
            try:
                metadata["ctor_functions"] = parse_functions(
                    parsed_obj.ctor_functions
                )
            except AttributeError:
                pass
            try:
                metadata["exception_functions"] = parse_functions(
                    parsed_obj.exception_functions
                )
            except AttributeError:
                pass
            try:
                tls = parsed_obj.tls
                if tls and tls.sizeof_zero_fill:
                    metadata["tls_address_index"] = tls.addressof_index
                    metadata["tls_sizeof_zero_fill"] = tls.sizeof_zero_fill
                    metadata["tls_data_template_len"] = len(tls.data_template)
                    metadata["tls_characteristics"] = tls.characteristics
                    metadata["tls_section_name"] = tls.section.name
                    metadata["tls_directory_type"] = str(tls.directory.type)
            except (AttributeError, TypeError):
                pass
        elif isinstance(parsed_obj, lief.MachO.Binary):
            # MachO
            metadata["binary_type"] = "MachO"
            metadata["name"] = exe_file
            metadata["imagebase"] = parsed_obj.imagebase
            metadata["is_pie"] = parsed_obj.is_pie
            metadata["has_nx"] = parsed_obj.has_nx
            metadata["exe_type"] = "MachO"
            try:
                version = (
                    parsed_obj.version_min.version
                    if parsed_obj.version_min
                    else None
                )
                sdk = (
                    parsed_obj.version_min.sdk
                    if parsed_obj.version_min
                    else None
                )
                source_version = (
                    parsed_obj.source_version.version
                    if parsed_obj.source_version
                    else None
                )
                if source_version:
                    metadata["source_version"] = (
                        "{:d}.{:d}.{:d}.{:d}.{:d}".format(*source_version)
                    )
                if version:
                    metadata["version"] = "{:d}.{:d}.{:d}".format(*version)
                if sdk:
                    metadata["sdk"] = "{:d}.{:d}.{:d}".format(*sdk)
            except Exception:
                pass
            try:
                build_version = parsed_obj.build_version
                if build_version:
                    metadata["platform"] = str(build_version.platform).rsplit(
                        ".", maxsplit=1
                    )[-1]
                    metadata["minos"] = "{:d}.{:d}.{:d}".format(
                        *build_version.minos
                    )
                    metadata["sdk"] = "{:d}.{:d}.{:d}".format(
                        *build_version.sdk
                    )
                    tools = build_version.tools
                    if len(tools) > 0:
                        metadata["tools"] = []
                        for tool in tools:
                            tool_str = str(tool.tool).rsplit(".", maxsplit=1)[
                                -1
                            ]
                            metadata["tools"].append(
                                {
                                    "tool": tool_str,
                                    "version": "{}.{}.{}".format(*tool.version),
                                }
                            )
            except Exception:
                pass
            try:
                if parsed_obj.has_encryption_info:
                    encryption_info = parsed_obj.encryption_info
                    if encryption_info:
                        metadata["encryption_info"] = {
                            "crypt_offset": encryption_info.crypt_offset,
                            "crypt_size": encryption_info.crypt_size,
                            "crypt_id": encryption_info.crypt_id,
                        }
            except Exception:
                pass
            try:
                sinfo = parsed_obj.sub_framework
                if sinfo:
                    metadata["umbrella"] = sinfo.umbrella
            except Exception:
                pass
            try:
                cmd = parsed_obj.rpath
                if cmd:
                    metadata["has_rpath"] = True
                    metadata["rpath"] = cmd.path
            except Exception:
                metadata["has_rpath"] = False
            try:
                cmd = parsed_obj.uuid
                if cmd:
                    uuid_str = " ".join(map(integer_to_hex_str, cmd.uuid))
                    metadata["uuid"] = str(uuid_str)
            except Exception:
                pass
            try:
                if parsed_obj.libraries:
                    metadata["libraries"] = []
                    for library in parsed_obj.libraries:
                        current_version_str = "{:d}.{:d}.{:d}".format(
                            *library.current_version
                        )
                        compat_version_str = "{:d}.{:d}.{:d}".format(
                            *library.compatibility_version
                        )
                        metadata["libraries"].append(
                            {
                                "name": library.name,
                                "timestamp": library.timestamp,
                                "version": current_version_str,
                                "compatibility_version": compat_version_str,
                            }
                        )
            except Exception:
                pass
            try:
                header = parsed_obj.header
                flags_str = ", ".join(
                    [
                        str(s).rsplit(".", maxsplit=1)[-1]
                        for s in header.flags_list
                    ]
                )
                metadata["magic"] = str(header.magic).rsplit(".", maxsplit=1)[
                    -1
                ]
                metadata["cpu_type"] = str(header.cpu_type).rsplit(
                    ".", maxsplit=1
                )[-1]
                metadata["cpu_subtype"] = header.cpu_subtype
                metadata["file_type"] = str(header.file_type).rsplit(
                    ".", maxsplit=1
                )[-1]
                metadata["flags"] = flags_str
                metadata["number_commands"] = header.nb_cmds
                metadata["size_commands"] = header.sizeof_cmds
                metadata["reserved"] = header.reserved
            except Exception:
                pass
            try:
                if parsed_obj.main_command:
                    metadata["has_main_command"] = (
                        False if isinstance(
                            parsed_obj.main_command, lief.lief_errors)
                        else True
                    )
                if parsed_obj.thread_command:
                    metadata["has_thread_command"] = (
                        False if isinstance(
                            parsed_obj.thread_command, lief.lief_errors)
                        else True
                    )
            except AttributeError:
                metadata["has_main"] = False
                metadata["has_thread_command"] = False
            with contextlib.suppress(AttributeError):
                metadata["functions"] = parse_functions(parsed_obj.functions)
                metadata["ctor_functions"] = parse_functions(
                    parsed_obj.ctor_functions
                )
                metadata["unwind_functions"] = parse_functions(
                    parsed_obj.unwind_functions
                )
                metadata["static_symbols"], exe_type = parse_macho_symbols(
                    parsed_obj.symbols
                )
                if exe_type:
                    metadata["exe_type"] = exe_type
                if parsed_obj.dylinker:
                    metadata["dylinker"] = parsed_obj.dylinker.name
            with contextlib.suppress(AttributeError, TypeError):
                if parsed_obj.has_code_signature:
                    code_signature = parsed_obj.code_signature
                    metadata["code_signature"] = {
                        "available": code_signature.size > 0,
                        "data": str(code_signature.data.hex()),
                        "data_size": str(code_signature.data_size),
                        "size": str(code_signature.size),
                    }
                if (
                    not parsed_obj.has_code_signature
                    and parsed_obj.has_code_signature_dir
                ):
                    code_signature = parsed_obj.code_signature_dir
                    metadata["code_signature"] = {
                        "available": code_signature.size > 0,
                        "data": str(code_signature.data.hex()),
                        "data_size": str(code_signature.data_size),
                        "size": str(code_signature.size),
                    }
                if (
                    not parsed_obj.has_code_signature
                    and not parsed_obj.has_code_signature_dir
                ):
                    metadata["code_signature"] = {"available": False}
                if parsed_obj.has_data_in_code:
                    data_in_code = parsed_obj.data_in_code
                    metadata["data_in_code"] = {
                        "data": str(data_in_code.data.hex()),
                        "data_size": str(data_in_code.data_size),
                        "size": str(data_in_code.size),
                    }
    except (AttributeError, TypeError, ValueError) as e:
        LOG.exception(e)
    return cleanup_dict_lief_errors(metadata)


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



