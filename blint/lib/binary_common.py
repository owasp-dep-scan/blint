"""Format-agnostic binary parsing shared by the ELF, PE, Mach-O and WebAssembly
readers.

Split out of ``binary.py`` so the per-format modules can import it without
importing the orchestrator that imports them.
"""

# pylint: disable=too-many-lines,consider-using-f-string
import codecs
import contextlib
import os
import re
import warnings
import zlib
from collections import defaultdict

import lief
import orjson

from blint.config import (
    get_float_from_env,
    get_int_from_env,
)
from blint.lib.banners import is_probable_banner_string
from blint.lib.utils import (
    calculate_entropy,
    check_secret,
    coerce_to_text,
    decode_base64,
    demangle_symbolic_name,
    demangle_symbolic_names,
    enum_to_str,
)
from blint.logger import DEBUG, LOG

# Only lief.ELF.Binary exposes a `strings` property; PE and Mach-O do not, so
# those formats are scanned directly. Six characters is long enough to exclude
# instruction-encoding noise while keeping short but meaningful values such as
# device paths and SDDL fragments.
MIN_EXTRACTED_STRING_LEN = 6

MAX_EXTRACTED_STRINGS = 50000
# Sections that hold program string literals, by PE and Mach-O convention.
STRING_BEARING_SECTIONS: set[str] = {
    ".rdata",
    ".data",
    ".rsrc",
    ".idata",
    ".sdata",
    "__cstring",
    "__const",
    "__data",
    "__ustring",
    "__oslogstring",
    "__cfstring",
    "__literal4",
    "__literal8",
    "__literal16",
}
STRING_BEARING_SECTION_PREFIXES: tuple[str, ...] = ("__objc_", ".rodata")
ASCII_STRING_RE = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_EXTRACTED_STRING_LEN)
# Windows binaries hold most user-visible text as UTF-16LE.
UTF16LE_STRING_RE = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % MIN_EXTRACTED_STRING_LEN)
# Shapes that make a string worth keeping regardless of its entropy score.
#
# The entropy and length gates below were written to surface secrets, and they do
# that well. But the same list is what every string-based review reads, and for
# that purpose the gates reject almost everything of interest: `calculate_entropy`
# returns a coarse bucket, so `dpapisvc.dll` scores 0.2 and
# `EveryoneIncludesAnonymous` scores 0.2 against a 0.39 threshold, while
# `Microsoft Base Cryptographic Provider v1.0` scores 0. A PE whose indicators
# are all short structured strings therefore yielded two strings in total, and
# the SDDL and kernel-object-path reviews that read this list silently found
# nothing.
#
# Rather than lower the threshold - which would admit tens of thousands of
# `.rdata` fragments - a string is also kept when its *shape* says it names a
# resource: a namespaced path, a registry key, a module or device name, a URL, or
# an SDDL descriptor. These are the forms reviews match on, and they are bounded
# because each requires a specific delimiter or suffix.
REVIEW_RELEVANT_STRING_RE = re.compile(
    r"""(
        ^\\\\[.?]\\             # \\.\Device or \\?\Volume client paths
      | ^\\(?:device|dosdevices|\?\?|basenamedobjects|registry|rpc\ control)\\  # object manager
      | ^(?:hkey_|hklm\\|hkcu\\)  # registry roots
      | (?:system|software)\\(?:currentcontrolset|microsoft|policies)\\  # registry paths
      | ^[\w.\-]{1,60}\.(?:dll|exe|sys|cpl|ocx|drv)$  # a module name and nothing else
      | ^(?:https?|ftps?|wss?|ldaps?|smb)://  # a URL
      | ^[dosg]:(?:\(|p\()      # an SDDL security descriptor
      | ^/(?:dev|proc|sys|etc|var/run)/  # unix pseudo-file paths
    )""",
    re.IGNORECASE | re.VERBOSE,
)
MACHO_SYNTHETIC_FUNCTION_NAME_RE = re.compile(r"^sub_[0-9a-f]+$")

MIN_ENTROPY = get_float_from_env("SECRET_MIN_ENTROPY", 0.39)
MIN_LENGTH = get_int_from_env("SECRET_MIN_LENGTH", 80)

# Resolving the dynamic link closure walks the scanning host's filesystem, so it
# is only correct when that host is the binary's intended runtime. Enable it with
# BLINT_RESOLVE_LINK_CLOSURE=1, optionally against an unpacked image root.
RESOLVE_LINK_CLOSURE = os.getenv("BLINT_RESOLVE_LINK_CLOSURE", "").lower() in (
    "1",
    "true",
    "yes",
)
LINK_CLOSURE_ROOT = os.getenv("BLINT_LINK_ROOT", "/")
LINK_CLOSURE_SEARCH_PATHS = [
    p for p in os.getenv("BLINT_LINK_SEARCH_PATH", "").split(os.pathsep) if p
]


# Enable lief logging in debug mode
if LOG.level != DEBUG:
    lief.logging.disable()

ADDRESS_FMT = "0x{:<10x}"

# Regex to extract crate name and version from Rust panic messages
# Based on https://github.com/rustsec/rustsec/blob/main/quitters/src/lib.rs
RUST_PANIC_REGEX_UNIX = re.compile(
    rb"cargo/registry/src/[^/]+/(?P<crate>[0-9A-Za-z_-]+)-(?P<version>[0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z+.-]*)/"
)
RUST_PANIC_REGEX_WIN = re.compile(
    rb"cargo\\registry\\src\\[^\\]+\\(?P<crate>[0-9A-Za-z_-]+)-(?P<version>[0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z+.-]*)\\"
)

# ELF dlopen specification - https://github.com/uapi-group/specifications/blob/main/specs/elf_dlopen_metadata.md
DLOPEN_NOTE_TYPE = 0x407C0C0A


# Resolving the dynamic link closure walks the scanning host's filesystem, so it
# is only correct when that host is the binary's intended runtime. Enable it with
# BLINT_RESOLVE_LINK_CLOSURE=1, optionally against an unpacked image root.
RESOLVE_LINK_CLOSURE = os.getenv("BLINT_RESOLVE_LINK_CLOSURE", "").lower() in (
    "1",
    "true",
    "yes",
)
LINK_CLOSURE_ROOT = os.getenv("BLINT_LINK_ROOT", "/")
LINK_CLOSURE_SEARCH_PATHS = [
    p for p in os.getenv("BLINT_LINK_SEARCH_PATH", "").split(os.pathsep) if p
]
ADDRESS_FMT = "0x{:<10x}"


def parse_notes(parsed_obj: lief.Binary) -> list[dict]:
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
    data: list[dict] = []
    notes = parsed_obj.notes
    if isinstance(notes, lief.lief_errors):
        return data
    data += [extract_note_data(idx, note) for idx, note in enumerate(notes)]
    return data


def extract_note_data(idx: int, note) -> dict:
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
    dlopen_info = None

    # Check for GNU Build ID
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

    type_str = enum_to_str(note.type)
    raw_type = getattr(note, "original_type", -1)
    if raw_type <= 0:
        with contextlib.suppress(ValueError, TypeError):
            raw_type = int(note.type)
    # Check for FDO dlopen metadata (0x407c0c0a)
    # Logic adapted from: https://github.com/systemd/package-notes/blob/main/dlopen-notes.py
    if raw_type == DLOPEN_NOTE_TYPE:
        type_str = "DLOPEN_METADATA"
        note_name = note.name.strip("\x00") if note.name else ""
        if note_name == "FDO":
            try:
                raw_data = bytes(note.description)
                json_str = raw_data.decode("utf-8", errors="ignore").strip("\x00 \n\t")
                parsed_json = orjson.loads(json_str)
                if isinstance(parsed_json, list):
                    dlopen_info = parsed_json
                else:
                    LOG.debug(f"DLOPEN_METADATA payload is not a list: {type(parsed_json)}")
            except (orjson.JSONDecodeError, ValueError, TypeError) as e:
                LOG.debug(f"Failed to parse DLOPEN_METADATA JSON payload: {e}")

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
        # LIEF 1.0 dropped Note.details and instead returns concrete subclasses,
        # so ABI notes expose `abi` and `version` directly. Reading `details`
        # raised AttributeError for every note, making this branch dead code.
        with contextlib.suppress(AttributeError, IndexError, TypeError):
            note_version = getattr(note, "version", None)
            note_abi = getattr(note, "abi", None)
            if note_abi is not None:
                abi = str(note_abi)
            if note_version is not None:
                version = [str(i) for i in note_version]
                version_str = ".".join(version[:3])

    if not version_str and build_id:
        version_str = build_id

    result = {
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

    if dlopen_info:
        result["dlopen_info"] = dlopen_info

    return result


def consolidate_dlopen_dependencies(notes_data: list[dict]) -> list[dict]:
    """
    Aggregates DLOPEN_METADATA notes into a flat list of dependencies.
    Resolves priorities if the same library is mentioned multiple times.
    """
    prio_map = {"suggested": 1, "recommended": 2, "required": 3}

    deps_map: dict[str, dict] = {}

    for note in notes_data:
        if note.get("type") != "DLOPEN_METADATA" or not note.get("dlopen_info"):
            continue

        for entry in note["dlopen_info"]:
            feature = entry.get("feature", "unknown")
            desc = entry.get("description", "")
            priority_str = entry.get("priority", "recommended")
            priority_val = prio_map.get(priority_str, 2)

            sonames = entry.get("soname", [])
            if isinstance(sonames, str):
                sonames = [sonames]

            for soname in sonames:
                if soname not in deps_map:
                    deps_map[soname] = {
                        "priority_val": 0,
                        "priority": "suggested",
                        "features": set(),
                        "descriptions": set(),
                    }

                if priority_val > deps_map[soname]["priority_val"]:
                    deps_map[soname]["priority_val"] = priority_val
                    deps_map[soname]["priority"] = priority_str

                if feature:
                    deps_map[soname]["features"].add(feature)
                if desc:
                    deps_map[soname]["descriptions"].add(desc)

    results: list[dict] = []
    for soname, data in deps_map.items():
        results.append(
            {
                "name": soname,
                "priority": data["priority"],
                "features": sorted(data["features"]),
                "description": " | ".join(sorted(data["descriptions"])),
            }
        )

    return sorted(results, key=lambda x: x["name"])


def integer_to_hex_str(e: int) -> str:
    """
    Converts an integer to a hexadecimal string representation.

    Args:
        e: The integer to be converted.

    Returns:
        The hexadecimal string representation of the integer.
    """
    return f"{e:02x}"


def parse_relro(parsed_obj: lief.ELF.Binary) -> str:
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


def _rwx_permissions_str(readable: bool, writable: bool, executable: bool) -> str:
    """Renders segment permissions in the customary ``rwx`` notation."""
    return f"{'r' if readable else ''}{'w' if writable else ''}{'x' if executable else ''}"


# SHF_EXECINSTR: the section holds machine instructions.
SHF_EXECINSTR = 0x4
# Sections a toolchain legitimately places an entry point in. Entry stubs live
# in .text on every mainstream target; .init and the small startup-specific
# text sections cover linker scripts, -ffunction-sections builds and the
# hand-written entry stubs in libc and in freestanding images.
ENTRY_POINT_SECTIONS: frozenset[str] = frozenset(
    {
        ".text",
        ".text.startup",
        ".text.unlikely",
        ".text._start",
        ".init",
        ".init.text",
        ".start",
        ".startup",
        ".head.text",
        ".text.boot",
        ".plt",
        ".iplt",
    }
)
# Segment protections carried by mach-o load commands (mach/vm_protect.h).
VM_PROT_READ = 0x1
VM_PROT_WRITE = 0x2
VM_PROT_EXECUTE = 0x4


def parse_functions(functions) -> list[dict]:
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


def is_string_bearing_section(section) -> bool:
    """Return True for sections that carry program strings.

    An allow list is used rather than a deny list because scanning everything is
    actively harmful: executable sections yield printable fragments of
    instruction encodings, and DWARF debug sections are enormous. On ripgrep's
    Windows build those two sources produced 17k junk values, including
    ``33333333`` reported as an IP address, while the real strings live in
    ``.rdata``.
    """
    name = (getattr(section, "name", "") or "").lower()
    if not name:
        return False
    if name in STRING_BEARING_SECTIONS:
        return True
    return any(name.startswith(prefix) for prefix in STRING_BEARING_SECTION_PREFIXES)


def extract_section_strings(parsed_obj) -> list[str]:
    """Extract printable strings from section content.

    Used for formats LIEF has no ``strings`` property for. Without this, every
    string-based review silently finds nothing on PE and Mach-O binaries.
    """
    results: list[str] = []
    seen: set[str] = set()
    sections = getattr(parsed_obj, "sections", None)
    if not sections or isinstance(sections, lief.lief_errors):
        return results
    for section in sections:
        if len(results) >= MAX_EXTRACTED_STRINGS:
            break
        if not is_string_bearing_section(section):
            continue
        try:
            content = bytes(section.content)
        except (AttributeError, TypeError, ValueError):
            continue
        if not content:
            continue
        for pattern, is_wide in ((ASCII_STRING_RE, False), (UTF16LE_STRING_RE, True)):
            for match in pattern.finditer(content):
                if len(results) >= MAX_EXTRACTED_STRINGS:
                    break
                raw = match.group()
                value = raw.decode("utf-16-le", "ignore") if is_wide else raw.decode("latin-1")
                if value and value not in seen:
                    seen.add(value)
                    results.append(value)
    return results


def binary_strings(parsed_obj) -> list[str]:
    """Return the raw strings of a binary regardless of its format."""
    strings = getattr(parsed_obj, "strings", None)
    if strings and not isinstance(strings, lief.lief_errors):
        return list(strings)
    return extract_section_strings(parsed_obj)


def is_review_relevant_string(value: str) -> bool:
    """Return True when a string names a resource a review would match on."""
    return bool(REVIEW_RELEVANT_STRING_RE.search(value.strip()))


def parse_strings(parsed_obj: lief.Binary) -> list[dict]:
    """
    Parse strings from a parsed object.

    Args:
        parsed_obj: The parsed object from which to extract strings.

    Returns:
        list: A list of dictionaries with keys: value, entropy, secret type
    """
    strings_list: list[dict] = []
    with contextlib.suppress(AttributeError):
        strings = binary_strings(parsed_obj)
        if isinstance(strings, lief.lief_errors):
            return strings_list
        for raw_string in strings:
            try:
                # LIEF yields bytes for entries that are not valid UTF-8; the
                # majority of extracted strings are bytes in practice.
                s = coerce_to_text(raw_string)
                if s and "[]" not in s and "{}" not in s:
                    entropy = calculate_entropy(s)
                    secret_type = check_secret(s)
                    if (
                        (entropy and (entropy > MIN_ENTROPY or len(s) > MIN_LENGTH))
                        or secret_type
                        or is_review_relevant_string(s)
                        # Vendored-source version banners are short plain text
                        # that both entropy and length gates reject; the
                        # banner detection reads this list, so strings
                        # matching its library-anchored signatures are kept.
                        or is_probable_banner_string(s)
                    ):
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


def _batch_demangle_symbol_names(symbols) -> dict[str, str]:
    """Pre-demangle every distinct name in a symbol table in one batch.

    Symbol tables repeat the same name across dynsym, symtab, version tables,
    and GOT/PLT maps, so resolving each distinct name once and looking it up
    per entry is markedly cheaper than demangling per entry. This pass is
    best-effort: a name it cannot read is simply absent from the map, and the
    parse loop falls back to demangling that symbol on its own.
    """
    names: list[str] = []
    for symbol in symbols:
        try:
            name = symbol.demangled_name
            if not name or isinstance(name, lief.lief_errors):
                name = symbol.name
        except (AttributeError, IndexError, TypeError):
            continue
        if isinstance(name, str) and name:
            names.append(name)
    return demangle_symbolic_names(names)


def _lookup_demangled(demangled: dict[str, str], name) -> str:
    """Resolve ``name`` from the batch map, demangling it directly on a miss."""
    if isinstance(name, str):
        cached = demangled.get(name)
        if cached is not None:
            return cached
    return demangle_symbolic_name(name)


def parse_symbols(symbols) -> tuple[list[dict], str]:
    """
    Parse symbols from a list of symbols.

    Args:
        symbols (it_symbols): A list of symbols to parse.

    Returns:
        tuple[list[dict], str]: A tuple containing the symbols_list and exe_type
    """
    symbols_list: list[dict] = []
    exe_type = ""
    skipped: defaultdict[str, int] = defaultdict(int)
    symbols = list(symbols or [])
    demangled = _batch_demangle_symbol_names(symbols)
    for symbol in symbols:
        try:
            symbol_version = symbol.symbol_version if symbol.has_version else ""
            is_imported = False
            is_exported = False
            if symbol.imported and not isinstance(symbol.imported, lief.lief_errors):
                is_imported = True
            if symbol.exported and not isinstance(symbol.exported, lief.lief_errors):
                is_exported = True
            # A symbol with no mangling has no demangled form, and the parser
            # returns an empty string rather than an error for that case. Only
            # the error branch was handled, so every plain C symbol came through
            # nameless -- taking the raw name whenever the demangled one is
            # falsy covers both.
            symbol_name = symbol.demangled_name
            if isinstance(symbol_name, lief.lief_errors) or not symbol_name:
                symbol_name = symbol.name
            symbol_name = _lookup_demangled(demangled, symbol_name)
            # The linkage name is what appears in another object's export table,
            # so it is the only key that matches a C++ symbol across binaries.
            # It is recorded only when demangling actually changed the name.
            raw_name = symbol.name if isinstance(symbol.name, str) else ""
            exe_type = guess_exe_type(symbol_name)
            visibility = ""
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", category=RuntimeWarning)
                visibility = enum_to_str(symbol.visibility)
            symbol_entry = {
                "name": symbol_name,
                "type": enum_to_str(symbol.type),
                "value": ADDRESS_FMT.format(symbol.value).strip()
                if symbol.value > 0
                else symbol.value,
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
                "size": symbol.size if symbol.size > 0 else None,
            }
            if raw_name and raw_name != symbol_name:
                symbol_entry["raw_name"] = raw_name
            symbols_list.append(symbol_entry)
        except (AttributeError, IndexError, TypeError) as e:
            skipped[type(e).__name__] += 1
            continue
    if skipped:
        # Dropping symbols quietly understates every symbol-derived result, from
        # the SBOM component list to the ABI floor, so report the loss once with
        # the failure kinds that caused it rather than per symbol.
        detail = ", ".join(f"{count} {kind}" for kind, count in sorted(skipped.items()))
        LOG.warning("Skipped %d unreadable symbols (%s).", sum(skipped.values()), detail)
    return symbols_list, exe_type


def detect_exe_type(parsed_obj: lief.Binary, metadata: dict) -> str:
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
        # A statically linked ELF has no interpreter, and `"musl" in None`
        # raises TypeError — which the suppress() above swallowed, abandoning
        # the whole function and returning "" before the machine-type fallback
        # below could run. Every static ELF therefore had no exe_type at all,
        # and since review rules are selected by exact exe_type match, no
        # review rule of any group could ever fire on one. Coercing to "" here
        # is the whole fix.
        interpreter = metadata.get("interpreter") or ""
        if (
            parsed_obj.has_section(".note.gnu.build-id")
            or "musl" in interpreter
            or "ld-linux" in interpreter
        ):
            return "genericbinary"
        if metadata.get("machine_type") and metadata.get("file_type"):
            return f"{metadata.get('machine_type')}-{metadata.get('file_type')}".lower()
        if metadata["relro"] in ("partial", "full"):
            return "genericbinary"
    return ""


def guess_exe_type(symbol_name: str) -> str:
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


def format_symbol_section_index(symbol) -> str:
    """Render a COFF/PE symbol's section index for symbols with no named section.

    LIEF 1.0 moved PE symbols to the COFF module and renamed this field from
    ``section_number`` to ``section_idx``; ``lief.PE.Symbol`` no longer exists.
    Both names are read so the output is stable across LIEF versions. File
    records and absolute symbols legitimately have no section, which is why this
    returns an empty string rather than raising.
    """
    for attribute in ("section_idx", "section_number"):
        index = getattr(symbol, attribute, None)
        if isinstance(index, bool) or not isinstance(index, int):
            continue
        return f"section<{index:d}>"
    return ""


# C symbols whose import (or, for statically linked images, definition) proves
# the stack-protector was in play. Both the ELF (two leading underscores) and
# Mach-O (three) spellings are covered so one set serves both formats.
STACK_CHK_SYMBOLS = {
    "__stack_chk_fail",
    "__stack_chk_guard",
    "___stack_chk_fail",
    "___stack_chk_guard",
}
# ELF spellings of the stack-protector runtime: the glibc/musl entry points
# plus ICC's cookie object.
ELF_STACK_CHK_SYMBOLS = STACK_CHK_SYMBOLS | {"__intel_security_cookie"}
# PE spellings of the stack-protector runtime, matched as lowercase substrings
# so x86 decoration (`@__security_check_cookie@8`) still matches.
PE_STACK_CHK_MARKERS = (
    "security_check_cookie",
    "stack_chk_fail",
    "stack_chk_guard",
    "rtc_checkstackvars",
)


def _primary_code_directory(code_signature: dict | None) -> dict | None:
    """The primary (slot-0) CodeDirectory of a parsed code_signature block."""
    if not isinstance(code_signature, dict) or code_signature.get("parse_status") != "parsed":
        return None
    directories = (code_signature.get("superblob") or {}).get("code_directories") or []
    for directory in directories:
        if directory.get("slot_type") == "code_directory":
            return directory
    return directories[0] if directories else None


def _codesign_security_flags(flags: dict | None) -> dict:
    """The hardening-relevant CodeDirectory flags as security_properties keys.

    Computed only from a parsed CodeDirectory; an absent or unparseable
    signature yields {} so the keys stay out of security_properties instead
    of reporting confident negatives for an unknown.
    """
    if not isinstance(flags, dict):
        return {}
    return {
        "hardened_runtime": bool(flags.get("runtime")),
        "library_validation": bool(flags.get("library_validation")),
        "get_task_allow": bool(flags.get("get_task_allow")),
    }


def _default_confidence_for_kind(kind: str) -> str:
    return "high" if kind == "direct" else "medium" if kind == "tailcall" else "low"


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


GO_BUILDINFO_MAGIC = b"\xff Go buildinf:"
# go/src/debug/buildinfo: the blob opens with a 32-byte header — the magic, a
# pointer size and a flags byte. Flags bit 0x2 marks the inline layout
# (Go >= 1.18) where the toolchain version and the modinfo string follow the
# header as uvarint-length-prefixed contents. In the pre-1.18 layout the
# header instead holds pointers to strings that live outside the blob.
GO_BUILDINFO_FLAGS_INLINE = 0x2
GO_BUILDINFO_HEADER_LEN = 32
# Release strings ("go1.27.1") are ~10 bytes; devel strings carry a hash and
# a date. A longer length prefix means the header was misread, not that the
# version is big.
GO_BUILDINFO_MAX_VERSION_LEN = 128
# The modinfo string carries one line per dependency; release binaries hold
# 250-400 lines (~40 KB), so 1 MiB is a sanity bound against a misread length
# prefix, not a tight budget.
GO_BUILDINFO_MAX_MODINFO_LEN = 1 << 20
# go/src/debug/buildinfo: the inline modinfo string is framed by 16-byte
# sentinels (cmd/go/internal/modload infoStart/infoEnd) and is only usable
# when at least 33 bytes long with a newline immediately before the end
# sentinel — go's own framing check, which a random slice of the section
# does not pass.
GO_MODINFO_SENTINEL_LEN = 16
GO_MODINFO_MIN_FRAMED_LEN = 33
GO_VERSION_TEXT_RE = re.compile(r"^(?:go\d|devel)[\x20-\x7e]*$")


def _read_uvarint(data: bytes) -> tuple[int, int]:
    """Decode an unsigned LEB128 varint, returning (value, bytes_consumed).

    Returns (0, 0) when the buffer ends mid-value or the value exceeds 64
    bits, mirroring Go's binary.Uvarint n <= 0 error convention.
    """
    result = 0
    shift = 0
    for index, byte in enumerate(data):
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, index + 1
        shift += 7
        if shift >= 64:
            break
    return 0, 0


def _read_go_inline_blob(build_info_bytes: bytes) -> tuple[str | None, str | None]:
    """Read the (toolchain version, modinfo text) pair from raw buildinfo bytes.

    Mirrors go/src/debug/buildinfo's readRawBuildInfo for the >= 1.18 inline
    layout: a 32-byte header, then a uvarint-length-prefixed version string,
    then a uvarint-length-prefixed modinfo string. The modinfo string is
    framed by 16-byte sentinels on both ends; the framing is stripped only
    when go's own check passes (newline immediately before the end
    sentinel), so a misread length cannot smuggle in section noise. Each
    field fails independently and closed: a bad version returns
    ``(None, None)``, while an unusable modinfo still returns the version.
    The pre-1.18 pointer layout is not implemented — its strings live
    outside the blob, so it also yields ``(None, None)`` and callers leave
    the fields absent rather than guess.
    """
    offset = build_info_bytes.find(GO_BUILDINFO_MAGIC)
    if offset < 0:
        return None, None
    header_end = offset + GO_BUILDINFO_HEADER_LEN
    if header_end > len(build_info_bytes):
        return None, None
    if not build_info_bytes[offset + 15] & GO_BUILDINFO_FLAGS_INLINE:
        return None, None
    length, consumed = _read_uvarint(build_info_bytes[header_end : header_end + 10])
    if not 0 < length <= GO_BUILDINFO_MAX_VERSION_LEN:
        return None, None
    version_start = header_end + consumed
    version_end = version_start + length
    if version_end > len(build_info_bytes):
        return None, None
    try:
        version = build_info_bytes[version_start:version_end].decode("ascii")
    except UnicodeDecodeError:
        return None, None
    if not GO_VERSION_TEXT_RE.match(version):
        return None, None
    modinfo: str | None = None
    mod_length, mod_consumed = _read_uvarint(build_info_bytes[version_end : version_end + 10])
    if 0 < mod_length <= GO_BUILDINFO_MAX_MODINFO_LEN:
        mod_start = version_end + mod_consumed
        mod_end = mod_start + mod_length
        if mod_end <= len(build_info_bytes):
            framed = build_info_bytes[mod_start:mod_end]
            if (
                len(framed) >= GO_MODINFO_MIN_FRAMED_LEN
                and framed[len(framed) - GO_MODINFO_SENTINEL_LEN - 1] == 0x0A
            ):
                modinfo = (
                    framed[GO_MODINFO_SENTINEL_LEN:-GO_MODINFO_SENTINEL_LEN].decode(
                        "utf-8", errors="replace"
                    )
                    or None
                )
    return version, modinfo


def parse_go_toolchain_version(build_info_bytes: bytes) -> str | None:
    """Recover the Go toolchain version from the raw buildinfo bytes.

    The version string is uvarint-length-prefixed inside the blob (Go's own
    layout, go/src/debug/buildinfo), so it is read at the byte level rather
    than from the NUL-stripped text, where it glues onto the ``path`` entry
    and used to be read back as the module path. Every failure returns None
    so callers leave ``go_version`` absent instead of inventing a
    plausible-looking value: no buildinfo magic in the bytes, pre-1.18
    pointer layout, truncated or over-long length prefix, or content that is
    not a Go version shape.
    """
    version, _ = _read_go_inline_blob(build_info_bytes)
    return version


def _parse_go_modinfo(modinfo_text: str, deps: dict, formulation: dict) -> None:
    """Parse the framing-stripped modinfo text into deps and formulation.

    Follows go/src/runtime/debug ParseBuildInfo: lines are separated by
    ``\\n`` and fields by ``\\t``, and every line type is anchored on its
    ``keyword\\t`` prefix. ``path`` is the single field after the prefix;
    ``mod``/``dep`` carry up to three tab-separated columns (name, version,
    hash) and only the *name* becomes ``module``/a deps key — the version
    and hash are real data, not part of the identity. ``build`` settings are
    cut at the first ``=`` so values like ``a=b,c=d`` survive whole.
    Unrecognised or empty lines (including ``=>`` replacement lines) are
    ignored, as go's own printer-strictness is not blint's concern.
    """
    for line in modinfo_text.split("\n"):
        if line.startswith("path\t"):
            value = line[len("path\t") :]
            if value:
                formulation["path"] = value
        elif line.startswith("mod\t"):
            fields = line[len("mod\t") :].split("\t")
            if fields[0]:
                formulation["module"] = fields[0]
        elif line.startswith("dep\t"):
            fields = line[len("dep\t") :].split("\t")
            if fields[0]:
                deps[fields[0]] = {
                    "version": fields[1] if len(fields) > 1 else None,
                    "hash": fields[2]
                    if len(fields) == 3 and fields[2].startswith("h1:")
                    else None,
                }
        elif line.startswith("build\t"):
            key, sep, value = line[len("build\t") :].partition("=")
            if sep and key:
                formulation[key.replace("-", "")] = value


def _parse_go_buildinfo_text(build_info_str: str, deps: dict, formulation: dict) -> None:
    """Flattened-text fallback for deps and build settings only.

    Used only when the buildinfo blob cannot be read at the byte level (for
    example a pre-1.18 pointer layout): the NUL-stripped, tab-flattened
    section text still carries the ``dep`` and ``build`` lines, which are
    anchored on their keyword so a dependency named ``…/jsonpath`` cannot
    match. ``path`` and ``module`` are deliberately not recovered here — in
    flattened text their field boundaries are destroyed (the version glues
    onto the path, the version and hash glue onto the module name), so they
    stay absent rather than arrive wrong.
    """
    for line in build_info_str.split("\n"):
        if line.startswith("dep "):
            fields = line.removeprefix("dep ").split(" ")
            if fields[0]:
                deps[fields[0]] = {
                    "version": fields[1] if len(fields) > 1 else None,
                    "hash": fields[2]
                    if len(fields) == 3 and fields[2].startswith("h1:")
                    else None,
                }
        elif line.startswith("build "):
            key, sep, value = line.removeprefix("build ").partition("=")
            if sep and key:
                formulation[key.replace("-", "")] = value


def parse_go_buildinfo(
    parsed_obj: lief.Binary,
) -> tuple[dict[str, dict[str, str | None]], dict[str, str]]:
    """Parse the go build info blob to extract go dependencies and identity fields.

    The primary read is at the byte level, exactly as go/src/debug/buildinfo
    lays the blob out: the uvarint-length-prefixed toolchain version, then
    the framed modinfo string whose tab-separated ``path``/``mod``/``dep``/
    ``build`` lines are parsed with their field boundaries intact. On ELF
    and Mach-O the dedicated buildinfo section is read whole; on PE the
    magic is searched in the whole ``.data`` section because the modinfo
    string can be far larger than the text window the fallback uses. When
    the blob is unreadable (not a Go binary, truncated, or the pre-1.18
    pointer layout) the NUL-stripped flattened text is scanned for ``dep``
    and ``build`` lines only — ``path`` and ``module`` cannot be recovered
    from flattened text and stay absent rather than arrive concatenated.

    Args:
        parsed_obj (lief.Binary): The parsed object representing the binary.

    Returns:
        tuple(dict[str, str], dict[str, str]): Tuple representing the dependencies and formulation.
    """
    formulation = {}
    deps = {}
    build_info_str: str = ""
    build_info_bytes: bytes = b""
    # Look for specific buildinfo sections for ELF and MachO binaries
    build_info: lief.Section | None = None
    if isinstance(parsed_obj, lief.ELF.Binary):
        build_info = parsed_obj.get_section(".go.buildinfo")
    elif isinstance(parsed_obj, lief.MachO.Binary):
        build_info = parsed_obj.get_section("__go_buildinfo")
    if build_info and build_info.size:
        build_info_bytes = build_info.content.tobytes()
        build_info_str = (
            codecs.decode(build_info.content.tobytes(), encoding="utf-8", errors="replace")
            .replace("\0", "")
            .replace("\ufffd", "")
            .replace("\t", " ")
        ).strip()
        build_info_str = build_info_str.encode("ascii", "ignore").decode("ascii")
    elif isinstance(parsed_obj, lief.PE.Binary):
        # For PE binaries look for .data section
        s: lief.PE.Section = parsed_obj.get_section(".data")
        if s and not isinstance(s, lief.lief_errors):
            section_bytes = s.content.tobytes()
            # The blob is located in the full section: its uvarint length
            # prefixes describe a modinfo string that routinely exceeds the
            # text window, which is kept only for the flattened-text
            # fallback below.
            build_info_bytes = section_bytes
            build_info_str = (
                codecs.decode(
                    section_bytes[: int(s.size / 32)],
                    encoding="ascii",
                    errors="replace",
                )
                .replace("\0", "")
                .replace("\ufffd", "")
                .replace("\t", " ")
            )
    go_version, modinfo_text = _read_go_inline_blob(build_info_bytes)
    if go_version:
        formulation["go_version"] = go_version
    if modinfo_text is not None:
        _parse_go_modinfo(modinfo_text, deps, formulation)
    else:
        _parse_go_buildinfo_text(build_info_str, deps, formulation)

    return deps, formulation


def recover_rust_deps_from_panic(parsed_obj: lief.Binary) -> list[dict]:
    """
    Heuristically recover Rust dependencies by scanning for panic messages in the binary sections.
    This is useful when cargo-auditable data is stripped or missing.

    Args:
        parsed_obj (lief.Binary): The parsed binary object.

    Returns:
        list: A list of dictionaries containing 'name' and 'version'.
    """
    detected_deps = {}
    for section in parsed_obj.sections:
        if section.size == 0:
            continue
        try:
            content = section.content.tobytes()
        except Exception:
            continue
        for match in RUST_PANIC_REGEX_UNIX.finditer(content):
            try:
                crate = match.group("crate").decode("utf-8", errors="ignore")
                version = match.group("version").decode("utf-8", errors="ignore")
                detected_deps[(crate, version)] = True
            except (UnicodeDecodeError, AttributeError):
                continue
        for match in RUST_PANIC_REGEX_WIN.finditer(content):
            try:
                crate = match.group("crate").decode("utf-8", errors="ignore")
                version = match.group("version").decode("utf-8", errors="ignore")
                detected_deps[(crate, version)] = True
            except (UnicodeDecodeError, AttributeError):
                continue
    return [
        {
            "name": name,
            "version": version,
            "purl": f"pkg:cargo/{name}@{version}" if version else f"pkg:cargo/{name}",
        }
        for name, version in detected_deps
    ]


def parse_rust_buildinfo(parsed_obj: lief.Binary) -> list[dict]:
    """
    Parse the rust build info section that are cargo-auditable to extract rust dependencies.
    Falls back to panic message parsing if auditable data is not present.

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
                return deps
    except (orjson.JSONDecodeError, zlib.error, Exception) as e:
        LOG.debug(f"Failed to parse .dep-v0 section: {e}")
    if not deps:
        deps = recover_rust_deps_from_panic(parsed_obj)
    return deps


# Mach-O CPU subtype of arm64e (the low 24 bits; the high bits carry the
# ABI64 flag). The distinction matters because only arm64e slices get
# pointer authentication, so an aggregate "PAC: no" over a fat binary that
# contains an arm64e slice would be a confident wrong answer.
CPU_SUBTYPE_ARM64E = 0x2
CPU_SUBTYPE_FLAG_MASK = 0x00FFFFFF


def _parse_address(value) -> int | None:
    """Parse an address that may be an int or a hex/decimal string."""
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip():
        with contextlib.suppress(ValueError):
            return int(value.strip(), 0)
    return None


def _is_synthetic_function_name(name) -> bool:
    """True for the ``sub_<hex>`` names blint synthesises for unnamed code."""
    return bool(name) and bool(MACHO_SYNTHETIC_FUNCTION_NAME_RE.match(str(name)))


def _is_weak_function_name(name) -> bool:
    """True when a name identifies nothing: absent, empty, or ``sub_<hex>``.

    A weak name loses to a real symbol at the same address. lief leaves some
    aggregate entries nameless, so absence has to rank with ``sub_<hex>``
    rather than count as an identity of its own.
    """
    return not name or _is_synthetic_function_name(name)


def _entry_size(entry: dict) -> int:
    """A function entry's size as a non-negative int, 0 when absent."""
    size = entry.get("size")
    return size if isinstance(size, int) and size > 0 else 0


LC_CODE_SIGNATURE_CMD = 0x1D
