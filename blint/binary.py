import sys

import lief
from lief import ELF, PE, MachO

from blint.logger import LOG
from blint.utils import calculate_entropy, check_secret, decode_base64

MIN_ENTROPY = 0.39
MIN_LENGTH = 80


def parse_desc(e):
    return "{:02x}".format(e)


def is_shared_library(parsed_obj):
    if not parsed_obj:
        return False
    if parsed_obj.format == lief.EXE_FORMATS.ELF:
        return parsed_obj.header.file_type == lief.ELF.E_TYPE.DYNAMIC
    elif parsed_obj.format == lief.EXE_FORMATS.PE:
        return parsed_obj.header.has_characteristic(lief.PE.HEADER_CHARACTERISTICS.DLL)
    elif parsed_obj.format == lief.EXE_FORMATS.MACHO:
        return parsed_obj.header.file_type == lief.MachO.FILE_TYPES.DYLIB
    return False


def parse_notes(parsed_obj):
    metadata = {"notes": []}
    notes = parsed_obj.notes
    if len(notes):
        for idx, note in enumerate(notes):
            description = note.description
            description_str = " ".join(map(parse_desc, description[:16]))
            if len(description) > 16:
                description_str += " ..."
            type_str = note.type_core if note.is_core else note.type
            type_str = str(type_str).split(".")[-1]
            note_details = note.details
            note_details_str = ""
            sdk_version = ""
            ndk_version = ""
            ndk_build_number = ""
            abi = ""
            version_str = ""
            if type(note_details) == lief.ELF.AndroidNote:
                sdk_version = note_details.sdk_version
                ndk_version = note_details.ndk_version
                ndk_build_number = note_details.ndk_build_number
            if type(note_details) == lief.ELF.NoteAbi:
                version = note_details.version
                abi = str(note_details.abi)
                version_str = "{:d}.{:d}.{:d}".format(
                    version[0], version[1], version[2]
                )
            if note.is_core:
                note_details_str = note.details
            metadata["notes"].append(
                {
                    "description": str(description_str),
                    "type": type_str,
                    "details": note_details_str,
                    "sdk_version": sdk_version,
                    "ndk_version": ndk_version,
                    "ndk_build_number": ndk_build_number,
                    "abi": abi,
                    "version": version_str,
                }
            )
    return metadata["notes"]


def parse_uuid(e):
    return "{:02x}".format(e)


def parse_relro(parsed_obj):
    bind_now = False
    now = False
    try:
        parsed_obj.get(lief.ELF.SEGMENT_TYPES.GNU_RELRO)
    except lief.not_found:
        return "no"
    try:
        bind_now = lief.ELF.DYNAMIC_FLAGS.BIND_NOW in parsed_obj.get(
            lief.ELF.DYNAMIC_TAGS.FLAGS
        )
    except lief.not_found:
        pass
    try:
        now = lief.ELF.DYNAMIC_FLAGS_1.NOW in parsed_obj.get(
            lief.ELF.DYNAMIC_TAGS.FLAGS_1
        )
    except lief.not_found:
        pass
    if bind_now or now:
        return "full"
    else:
        return "partial"


def parse_functions(functions):
    try:
        LOG.debug("Parsing functions")
        func_list = []
        for idx, f in enumerate(functions):
            if f.name and f.address:
                func_list.append(
                    {
                        "index": idx,
                        "name": f.name.replace("..", "::"),
                        "address": f.address,
                    }
                )
        return func_list
    except lief.exception:
        return []


def parse_strings(parsed_obj):
    try:
        LOG.debug("Parsing strings")
        strings_list = []
        strings = parsed_obj.strings
        for s in strings:
            if s and "[]" not in s and "{}" not in s:
                entropy = calculate_entropy(s)
                secret_type = check_secret(s)
                if (
                    entropy and (entropy > MIN_ENTROPY or len(s) > MIN_LENGTH)
                ) or secret_type:
                    strings_list.append(
                        {
                            "value": decode_base64(s) if s.endswith("==") else s,
                            "entropy": entropy,
                            "secret_type": secret_type,
                        }
                    )
        return strings_list
    except lief.exception:
        return []


def parse_symbols(symbols):
    try:
        LOG.debug("Parsing symbols")
        symbols_list = []
        for symbol in symbols:
            symbol_version = symbol.symbol_version if symbol.has_version else ""
            is_imported = False
            is_exported = False
            if symbol.imported:
                is_imported = True
            if symbol.exported:
                is_exported = True
            try:
                symbol_name = symbol.demangled_name
            except Exception:
                symbol_name = symbol.name
            symbols_list.append(
                {
                    "name": symbol_name,
                    "type": str(symbol.type).split(".")[-1],
                    "value": symbol.value,
                    "visibility": str(symbol.visibility).split(".")[-1],
                    "binding": str(symbol.binding).split(".")[-1],
                    "is_imported": is_imported,
                    "is_exported": is_exported,
                    "version": str(symbol_version),
                }
            )
        return symbols_list
    except lief.exception:
        return []


def parse_interpreter(parsed_obj):
    try:
        return parsed_obj.interpreter
    except lief.exception:
        return None


def detect_exe_type(parsed_obj):
    try:
        if parsed_obj.has_section(".note.go.buildid"):
            return "gobinary"
        elif parsed_obj.has_section(".note.gnu.build-id"):
            return "genericbinary"
    except lief.exception:
        return None


def guess_exe_type(symbol_name):
    exe_type = None
    if "golang" in symbol_name:
        exe_type = "gobinary"
    if "_rust_" in symbol_name:
        exe_type = "genericbinary"
    return exe_type


def parse_pe_data(parsed_obj):
    try:
        LOG.debug("Parsing data dictionaries")
        data_list = []
        data_directories = parsed_obj.data_directories
        for directory in data_directories:
            section_name = directory.section.name if directory.has_section else ""
            dir_type = str(directory.type).split(".")[-1]
            if not dir_type.startswith("?") and directory.size:
                data_list.append(
                    {
                        "name": section_name,
                        "type": dir_type,
                        "rva": directory.rva,
                        "size": directory.size,
                    }
                )
        return data_list
    except lief.exception:
        return None


def process_pe_resources(parsed_obj):
    try:
        rm = parsed_obj.resources_manager
        metadata = {
            "has_accelerator": rm.has_accelerator,
            "has_dialogs": rm.has_dialogs,
            "has_html": rm.has_html,
            "has_icons": rm.has_icons,
            "has_manifest": rm.has_manifest,
            "has_string_table": rm.has_string_table,
            "has_version": rm.has_version,
            "html": rm.html if rm.has_html else None,
            "manifest": rm.manifest if rm.has_manifest else None,
            "version_info": str(rm.version),
        }
        return metadata
    except lief.exception as e:
        print(e)
        return None


def process_pe_signature(parsed_obj):
    try:
        signature_list = []
        for idx, sig in enumerate(parsed_obj.signatures):
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
    except lief.exception:
        return None


def parse_pe_authenticode(parsed_obj):
    try:
        LOG.debug("Parsing authentihash")
        authenticode = {}
        sep = ":" if sys.version_info.minor > 7 else ()
        authenticode["md5_hash"] = parsed_obj.authentihash_md5.hex(*sep)
        authenticode["sha256_hash"] = parsed_obj.authentihash_sha256.hex(*sep)
        authenticode["sha1_hash"] = parsed_obj.authentihash(
            lief.PE.ALGORITHMS.SHA_1
        ).hex(*sep)
        authenticode["verification_flags"] = str(parsed_obj.verify_signature())
        cert_signer_str = str(parsed_obj.signatures[0].signers[0].cert)
        cert_signer_obj = {}
        for p in cert_signer_str.split("\n"):
            tmpA = p.split(" : ")
            if len(tmpA) == 2:
                tmpKey = tmpA[0].strip().replace(" ", "_")
                if "version" in tmpKey:
                    tmpKey = "version"
                cert_signer_obj[tmpKey] = tmpA[1].strip()
        authenticode["cert_signer"] = cert_signer_obj
        return authenticode
    except lief.exception:
        return None


def parse_pe_symbols(symbols):
    try:
        LOG.debug("Parsing symbols")
        symbols_list = []
        exe_type = None
        for symbol in symbols:
            section_nb_str = ""
            if symbol.section_number <= 0:
                section_nb_str = str(
                    PE.SYMBOL_SECTION_NUMBER(symbol.section_number)
                ).split(".")[-1]
            else:
                try:
                    section_nb_str = symbol.section.name
                except Exception:
                    section_nb_str = "section<{:d}>".format(symbol.section_number)
            if not exe_type:
                try:
                    exe_type = guess_exe_type(symbol.name.lower())
                    if symbol.name:
                        symbols_list.append(
                            {
                                "name": symbol.name.replace("..", "::"),
                                "value": symbol.value,
                                "id": section_nb_str,
                                "base_type": str(symbol.base_type).split(".")[-1],
                                "complex_type": str(symbol.complex_type).split(".")[-1],
                                "storage_class": str(symbol.storage_class).split(".")[
                                    -1
                                ],
                            }
                        )
                except Exception:
                    pass
        return symbols_list, exe_type
    except lief.exception:
        return [], None


def parse_pe_imports(imports):
    try:
        LOG.debug("Parsing imports")
        imports_list = []
        for import_ in imports:
            entries = import_.entries
            for entry in entries:
                if entry.name:
                    imports_list.append(
                        {
                            "name": entry.name,
                            "data": entry.data,
                            "iat_value": entry.iat_value,
                            "hint": entry.hint,
                        }
                    )
        return imports_list
    except lief.exception:
        return []


def parse_pe_exports(exports):
    try:
        LOG.debug("Parsing exports")
        exports_list = []
        entries = exports.entries
        for entry in entries:
            extern = "[EXTERN]" if entry.is_extern else ""
            if entry.name:
                exports_list.append(
                    {
                        "name": entry.name,
                        "ordinal": entry.ordinal,
                        "address": entry.address,
                        "extern": extern,
                    }
                )
        return exports_list
    except lief.exception:
        return []


def parse_macho_symbols(symbols):
    try:
        LOG.debug("Parsing symbols")
        symbols_list = []
        exe_type = None
        if len(symbols) == 0:
            return [], None
        for symbol in symbols:
            libname = ""
            if symbol.has_binding_info and symbol.binding_info.has_library:
                libname = symbol.binding_info.library.name

            symbol_value = (
                symbol.value
                if symbol.value > 0 or not symbol.has_binding_info
                else symbol.binding_info.address
            )

            try:
                symbol_name = symbol.demangled_name
            except Exception:
                symbol_name = symbol.name
            symbol_name = symbol_name.replace("..", "::")
            if not exe_type:
                exe_type = guess_exe_type(symbol_name)
            symbols_list.append(
                {
                    "name": symbol_name,
                    "type": symbol.type,
                    "num_sections": symbol.numberof_sections,
                    "description": symbol.description,
                    "value": symbol_value,
                    "libname": libname,
                }
            )
        return symbols_list, exe_type
    except lief.exception:
        return [], None


def parse(exe_file):
    """
    Parse the executable using lief and capture the metadata

    :param: exe_file Binary file
    :return Metadata dict
    """
    metadata = {}
    try:
        parsed_obj = lief.parse(exe_file)
        metadata["is_shared_library"] = is_shared_library(parsed_obj)
        # ELF Binary
        if isinstance(parsed_obj, ELF.Binary):
            header = parsed_obj.header
            identity = header.identity
            eflags_str = ""
            if header.machine_type == lief.ELF.ARCH.ARM:
                eflags_str = " - ".join(
                    [str(s).split(".")[-1] for s in header.arm_flags_list]
                )
            if header.machine_type in [
                lief.ELF.ARCH.MIPS,
                lief.ELF.ARCH.MIPS_RS3_LE,
                lief.ELF.ARCH.MIPS_X,
            ]:
                eflags_str = " - ".join(
                    [str(s).split(".")[-1] for s in header.mips_flags_list]
                )
            if header.machine_type == lief.ELF.ARCH.PPC64:
                eflags_str = " - ".join(
                    [str(s).split(".")[-1] for s in header.ppc64_flags_list]
                )
            if header.machine_type == lief.ELF.ARCH.HEXAGON:
                eflags_str = " - ".join(
                    [str(s).split(".")[-1] for s in header.hexagon_flags_list]
                )
            metadata["magic"] = "{:<02x} {:<02x} {:<02x} {:<02x}".format(
                identity[0], identity[1], identity[2], identity[3]
            )
            metadata["class"] = str(header.identity_class).split(".")[-1]
            metadata["endianness"] = str(header.identity_data).split(".")[-1]
            metadata["identity_version"] = str(header.identity_version).split(".")[-1]
            metadata["identity_os_abi"] = str(header.identity_os_abi).split(".")[-1]
            metadata["identity_abi_version"] = header.identity_abi_version
            metadata["file_type"] = str(header.file_type).split(".")[-1]
            metadata["machine_type"] = str(header.machine_type).split(".")[-1]
            metadata["object_file_version"] = str(header.object_file_version).split(
                "."
            )[-1]
            metadata["entrypoint"] = header.entrypoint
            metadata["processor_flag"] = str(header.processor_flag) + eflags_str
            metadata["name"] = parsed_obj.name
            metadata["imagebase"] = parsed_obj.imagebase
            metadata["interpreter"] = parse_interpreter(parsed_obj)
            metadata["is_pie"] = parsed_obj.is_pie
            metadata["virtual_size"] = parsed_obj.virtual_size
            metadata["has_nx"] = parsed_obj.has_nx
            metadata["relro"] = parse_relro(parsed_obj)
            metadata["exe_type"] = detect_exe_type(parsed_obj)
            # Canary check
            canary_sections = ["__stack_chk_fail", "__intel_security_cookie"]
            for section in canary_sections:
                try:
                    if parsed_obj.get_symbol(section):
                        metadata["has_canary"] = True
                        break
                except lief.not_found:
                    metadata["has_canary"] = False
            # rpath check
            try:
                if parsed_obj.get(lief.ELF.DYNAMIC_TAGS.RPATH):
                    metadata["has_rpath"] = True
            except lief.not_found:
                metadata["has_rpath"] = False
            # runpath check
            try:
                if parsed_obj.get(lief.ELF.DYNAMIC_TAGS.RUNPATH):
                    metadata["has_runpath"] = True
            except lief.not_found:
                metadata["has_runpath"] = False
            static_symbols = parsed_obj.static_symbols
            if len(static_symbols):
                metadata["static"] = True
            dynamic_entries = parsed_obj.dynamic_entries
            if len(dynamic_entries):
                metadata["dynamic_entries"] = []
                for entry in dynamic_entries:
                    if entry.tag == ELF.DYNAMIC_TAGS.NULL:
                        continue
                    if entry.tag in [
                        ELF.DYNAMIC_TAGS.SONAME,
                        ELF.DYNAMIC_TAGS.NEEDED,
                        ELF.DYNAMIC_TAGS.RUNPATH,
                        ELF.DYNAMIC_TAGS.RPATH,
                    ]:
                        metadata["dynamic_entries"].append(
                            {
                                "name": entry.name,
                                "tag": str(entry.tag).split(".")[-1],
                                "value": entry.value,
                            }
                        )
            try:
                symbols_version = parsed_obj.symbols_version
                if len(symbols_version):
                    metadata["symbols_version"] = []
                    for entry in symbols_version:
                        metadata["symbols_version"].append(
                            {
                                "name": entry.symbol_version_auxiliary,
                                "value": entry.value,
                            }
                        )
            except lief.exception:
                metadata["symbols_version"] = []
            try:
                notes = parsed_obj.notes
                if notes:
                    metadata["notes"] = parse_notes(parsed_obj)
            except lief.exception:
                pass
            metadata["strings"] = parse_strings(parsed_obj)
            try:
                metadata["static_symbols"] = parse_symbols(parsed_obj.static_symbols)
            except lief.exception:
                pass
            try:
                metadata["dynamic_symbols"] = parse_symbols(parsed_obj.dynamic_symbols)
            except lief.exception:
                pass
            try:
                metadata["functions"] = parse_functions(parsed_obj.functions)
            except lief.exception:
                pass
            try:
                metadata["ctor_functions"] = parse_functions(parsed_obj.ctor_functions)
            except lief.exception:
                pass
        elif isinstance(parsed_obj, PE.Binary):
            # PE
            # Parse header
            try:
                metadata["name"] = parsed_obj.name
                metadata["is_pie"] = parsed_obj.is_pie
                metadata["has_nx"] = parsed_obj.has_nx
                dos_header = parsed_obj.dos_header
                metadata["magic"] = str(dos_header.magic)
                header = parsed_obj.header
                optional_header = parsed_obj.optional_header
                metadata[
                    "used_bytes_in_the_last_page"
                ] = dos_header.used_bytes_in_the_last_page
                metadata["file_size_in_pages"] = dos_header.file_size_in_pages
                metadata["num_relocation"] = dos_header.numberof_relocation
                metadata[
                    "header_size_in_paragraphs"
                ] = dos_header.header_size_in_paragraphs
                metadata[
                    "minimum_extra_paragraphs"
                ] = dos_header.minimum_extra_paragraphs
                metadata[
                    "maximum_extra_paragraphs"
                ] = dos_header.maximum_extra_paragraphs
                metadata["initial_relative_ss"] = dos_header.initial_relative_ss
                metadata["initial_sp"] = dos_header.initial_sp
                metadata["checksum"] = dos_header.checksum
                metadata["initial_ip"] = dos_header.initial_ip
                metadata["initial_relative_cs"] = dos_header.initial_relative_cs
                metadata[
                    "address_relocation_table"
                ] = dos_header.addressof_relocation_table
                metadata["overlay_number"] = dos_header.overlay_number
                metadata["oem_id"] = dos_header.oem_id
                metadata["oem_info"] = dos_header.oem_info
                metadata["address_new_exeheader"] = dos_header.addressof_new_exeheader
                metadata["characteristics"] = ", ".join(
                    [str(chara).split(".")[-1] for chara in header.characteristics_list]
                )
                metadata["num_sections"] = header.numberof_sections
                metadata["time_date_stamps"] = header.time_date_stamps
                metadata["pointer_symbol_table"] = header.pointerto_symbol_table
                metadata["num_symbols"] = header.numberof_symbols
                metadata["size_optional_header"] = header.sizeof_optional_header
                metadata["dll_characteristics"] = ", ".join(
                    [
                        str(chara).split(".")[-1]
                        for chara in optional_header.dll_characteristics_lists
                    ]
                )
                metadata["subsystem"] = str(optional_header.subsystem).split(".")[-1]
                metadata["is_gui"] = (
                    True if metadata["subsystem"] == "WINDOWS_GUI" else False
                )
                metadata["exe_type"] = (
                    "PE32" if optional_header.magic == PE.PE_TYPE.PE32 else "PE64"
                )
                metadata["major_linker_version"] = optional_header.major_linker_version
                metadata["minor_linker_version"] = optional_header.minor_linker_version
                metadata["sizeof_code"] = optional_header.sizeof_code
                metadata[
                    "sizeof_initialized_data"
                ] = optional_header.sizeof_initialized_data
                metadata[
                    "sizeof_uninitialized_data"
                ] = optional_header.sizeof_uninitialized_data
                metadata["addressof_entrypoint"] = optional_header.addressof_entrypoint
                metadata["baseof_code"] = optional_header.baseof_code
                metadata["baseof_data"] = optional_header.baseof_data
                metadata["imagebase"] = optional_header.imagebase
                metadata["section_alignment"] = optional_header.section_alignment
                metadata["file_alignment"] = optional_header.file_alignment
                metadata[
                    "major_operating_system_version"
                ] = optional_header.major_operating_system_version
                metadata[
                    "minor_operating_system_version"
                ] = optional_header.minor_operating_system_version
                metadata["major_image_version"] = optional_header.major_image_version
                metadata["minor_image_version"] = optional_header.minor_image_version
                metadata[
                    "major_subsystem_version"
                ] = optional_header.major_subsystem_version
                metadata[
                    "minor_subsystem_version"
                ] = optional_header.minor_subsystem_version
                metadata["win32_version_value"] = optional_header.win32_version_value
                metadata["sizeof_image"] = optional_header.sizeof_image
                metadata["sizeof_headers"] = optional_header.sizeof_headers
                metadata["checksum"] = optional_header.checksum
                metadata["sizeof_stack_reserve"] = optional_header.sizeof_stack_reserve
                metadata["sizeof_stack_commit"] = optional_header.sizeof_stack_commit
                metadata["sizeof_heap_reserve"] = optional_header.sizeof_heap_reserve
                metadata["sizeof_heap_commit"] = optional_header.sizeof_heap_commit
                metadata["loader_flags"] = optional_header.loader_flags
                metadata[
                    "numberof_rva_and_size"
                ] = optional_header.numberof_rva_and_size
            except lief.exception:
                pass
            try:
                metadata["data_directories"] = parse_pe_data(parsed_obj)
            except lief.exception:
                pass
            try:
                metadata["authenticode"] = parse_pe_authenticode(parsed_obj)
            except lief.exception:
                pass
            try:
                metadata["signatures"] = process_pe_signature(parsed_obj)
            except lief.exception:
                pass
            try:
                metadata["resources"] = process_pe_resources(parsed_obj)
            except lief.exception:
                pass
            try:
                metadata["static_symbols"], exe_type = parse_pe_symbols(
                    parsed_obj.symbols
                )
                if exe_type:
                    metadata["exe_type"] = exe_type
            except lief.exception:
                pass
            try:
                metadata["imports"] = parse_pe_imports(parsed_obj.imports)
            except lief.exception:
                pass
            try:
                metadata["exports"] = parse_pe_exports(parsed_obj.get_export())
            except lief.exception:
                pass
            try:
                metadata["functions"] = parse_functions(parsed_obj.functions)
            except lief.exception:
                pass
            try:
                metadata["ctor_functions"] = parse_functions(parsed_obj.ctor_functions)
            except lief.exception:
                pass
            try:
                metadata["exception_functions"] = parse_functions(
                    parsed_obj.exception_functions
                )
            except lief.exception:
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
            except lief.exception:
                pass
        elif isinstance(parsed_obj, MachO.Binary):
            # MachO
            metadata["name"] = parsed_obj.name
            metadata["imagebase"] = parsed_obj.imagebase
            metadata["is_pie"] = parsed_obj.is_pie
            metadata["has_nx"] = parsed_obj.has_nx
            metadata["exe_type"] = "MachO"
            try:
                version = parsed_obj.version_min.version
                sdk = parsed_obj.version_min.sdk
                source_version = parsed_obj.source_version.version
                metadata["source_version"] = "{:d}.{:d}.{:d}.{:d}.{:d}".format(
                    *source_version
                )
                metadata["version"] = "{:d}.{:d}.{:d}".format(*version)
                metadata["sdk"] = "{:d}.{:d}.{:d}".format(*sdk)
            except lief.exception:
                pass
            try:
                build_version = parsed_obj.build_version
                metadata["platform"] = str(build_version.platform).split(".")[-1]
                metadata["minos"] = "{:d}.{:d}.{:d}".format(*build_version.minos)
                metadata["sdk"] = "{:d}.{:d}.{:d}".format(*build_version.sdk)
                tools = build_version.tools
                if len(tools) > 0:
                    metadata["tools"] = []
                    for tool in tools:
                        tool_str = str(tool.tool).split(".")[-1]
                        metadata["tools"].append(
                            {
                                "tool": tool_str,
                                "version": "{}.{}.{}".format(*tool.version),
                            }
                        )
            except lief.exception:
                pass
            try:
                encryption_info = parsed_obj.encryption_info
                if encryption_info:
                    metadata["encryption_info"] = {
                        "crypt_offset": encryption_info.crypt_offset,
                        "crypt_size": encryption_info.crypt_size,
                        "crypt_id": encryption_info.crypt_id,
                    }
            except lief.exception:
                pass
            try:
                sinfo = parsed_obj.sub_framework
                metadata["umbrella"] = sinfo.umbrella
            except lief.exception:
                pass
            try:
                cmd = parsed_obj.rpath
                metadata["has_rpath"] = True
                metadata["rpath"] = cmd.path
            except lief.exception:
                metadata["has_rpath"] = False
            try:
                cmd = parsed_obj.uuid
                uuid_str = " ".join(map(parse_uuid, cmd.uuid))
                metadata["uuid"] = str(uuid_str)
            except lief.exception:
                pass
            try:
                if parsed_obj.libraries:
                    metadata["libraries"] = []
                    for library in parsed_obj.libraries:
                        current_version_str = "{:d}.{:d}.{:d}".format(
                            *library.current_version
                        )
                        compatibility_version_str = "{:d}.{:d}.{:d}".format(
                            *library.compatibility_version
                        )
                        metadata["libraries"].append(
                            {
                                "name": library.name,
                                "timestamp": library.timestamp,
                                "version": current_version_str,
                                "compatibility_version": compatibility_version_str,
                            }
                        )
            except lief.exception:
                pass
            try:
                header = parsed_obj.header
                flags_str = ", ".join(
                    [str(s).split(".")[-1] for s in header.flags_list]
                )
                metadata["magic"] = str(header.magic).split(".")[-1]
                metadata["cpu_type"] = str(header.cpu_type).split(".")[-1]
                metadata["cpu_subtype"] = header.cpu_subtype
                metadata["file_type"] = str(header.file_type).split(".")[-1]
                metadata["flags"] = flags_str
                metadata["number_commands"] = header.nb_cmds
                metadata["size_commands"] = header.sizeof_cmds
                metadata["reserved"] = header.reserved
            except lief.exception:
                pass
            try:
                if parsed_obj.main_command:
                    metadata["has_main_command"] = True
                if parsed_obj.thread_command:
                    metadata["has_thread_command"] = True
            except lief.not_found:
                metadata["has_main"] = False
                metadata["has_thread_command"] = False
            try:
                metadata["functions"] = parse_functions(parsed_obj.functions)
            except lief.exception:
                pass
            try:
                metadata["ctor_functions"] = parse_functions(parsed_obj.ctor_functions)
            except lief.exception:
                pass
            try:
                metadata["unwind_functions"] = parse_functions(
                    parsed_obj.unwind_functions
                )
            except lief.exception:
                pass
            try:
                metadata["static_symbols"], exe_type = parse_macho_symbols(
                    parsed_obj.symbols
                )
                metadata["exe_type"] = exe_type
            except lief.exception:
                pass
            try:
                metadata["dylinker"] = parsed_obj.dylinker.name
            except lief.exception:
                pass
    except lief.exception as e:
        LOG.exception(e)
    return metadata
