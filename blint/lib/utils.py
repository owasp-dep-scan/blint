import base64
import binascii
import math
import os
import re
import shutil
import string
import tempfile
import zipfile
from importlib.metadata import distribution
from pathlib import Path
from typing import Dict

import lief
from ar import Archive, ArchiveError
from custom_json_diff.lib.utils import file_write
from defusedxml.ElementTree import fromstring, ParseError
from orjson import orjson
from rich import box
from rich.table import Table

from blint.config import (
    ignore_directories,
    ignore_files,
    strings_allowlist,
    fuzzable_names,
    secrets_regex,
    BLINTDB_HOME, BLINTDB_LOC, BLINTDB_IMAGE_URL, BLINTDB_REFRESH
)
from blint.cyclonedx.spec import (
    ComponentEvidence,
    FieldModel,
    ComponentIdentityEvidence,
    Method,
    Technique,
)
from blint.logger import console, LOG

import oras.client
from oras.logger import setup_logger

setup_logger(quiet=True, debug=False)

CHARSET = string.digits + string.ascii_letters + r"""!&@"""

# Known files compressed with ar
KNOWN_AR_EXTNS = (".a", ".rlib", ".lib")


SYMBOLIC_FOUND = True
try:
    from symbolic._lowlevel import ffi, lib
    from symbolic.utils import encode_str, decode_str, rustcall
except OSError:
    SYMBOLIC_FOUND = False

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
        if demangled_symbol.count("::") > 2:
            last_part = demangled_symbol.split("::")[-1]
            if len(last_part) == 17:
                demangled_symbol = demangled_symbol.removesuffix(f"::{last_part}")
        return demangled_symbol
    except AttributeError:
        return symbol


def is_base64(s):
    """
    Checks if the given string is a valid Base64 encoded string.

    Args:
        s (str or bytes): The string to be checked.

    Returns:
        bool: True if the string is a valid Base64 encoded string.
    """
    try:
        decoded = base64.b64decode(s)
        return s.endswith("==") or base64.b64encode(decoded) == s.encode()
    except (binascii.Error, TypeError, UnicodeError) as e:
        LOG.debug(f"Caught {type(e)}: {e} while checking if {s} is base64")
        return False


def decode_base64(s):
    """
    This function decodes a Base64 encoded string. It first removes any newline
    characters from the input string. Then, it checks if the string is a valid
    Base64 encoded string using the `is_base64` function. If it is valid, the
    string is decoded using the Base64 decoding algorithm. If the decoded string
    can be successfully decoded as UTF-8, the decoded string is returned.
    Otherwise, the decoded string is returned as a byte string. If the input
    string is not a valid Base64 encoded string, it is returned as is.

    Args:
        s (str or bytes): The Base64 encoded string to be decoded.

    Returns:
      - str or bytes: Decoded string, either a UTF-8 string or a byte string.
    """
    s = s.replace("\n", "")
    if is_base64(s):
        decoded = base64.b64decode(s)
        try:
            return decoded.decode()
        except (binascii.Error, UnicodeError):
            return str(decoded)
    return s


def is_camel_case(s):
    """
    Checks if the given string follows the camel case naming convention.

    Args:
        s (str): The string to be checked.

    Returns:
        bool: True if the string follows the camel case naming convention.
    """
    s = re.sub(r"[*._#%&!\"]", "", s)
    for x in string.digits:
        if x in s:
            return False
    for x in string.punctuation:
        if x in s:
            return False
    return s != s.lower() and s != s.upper() and "_" not in s


def calculate_entropy(data):
    """
    This function calculates the entropy of the given data to measure its
    randomness or predictability. It first performs checks to handle special
    cases, such as empty data or data with a length less than 8. Then, it
    removes certain protocol prefixes from the data to reduce false positives.
    Next, it calculates the entropy based on the character frequencies in the
    data using the Shannon entropy formula. The entropy value represents the
    amount of uncertainty or randomness in the data. Finally, it applies
    additional conditions to adjust the entropy value based on the data's
    characteristics.

    Args:
        data: The data for which entropy needs to be calculated.

    Returns:
        float: The calculated entropy value.
    """
    if not data or len(data) < 8:
        return 0

    if any(text in data for text in strings_allowlist):
        return 0

    entropy = 0.0

    # Remove protocol prefixes which tend to increase false positives
    data = re.sub(r"(file|s3|http(s)?|email|ftp)://", "", data)

    if not data:
        return entropy

    char_count = {}
    for char in data:
        char_count[char] = char_count.get(char, 0) + 1

    total_chars = len(data)
    ascii_found = any(char in string.ascii_letters for char in char_count)
    digit_found = any(char in string.digits for char in char_count)
    punctuation_found = any(char in string.punctuation for char in char_count)

    for count in char_count.values():
        p_x = count / total_chars
        entropy += -p_x * math.log(p_x, 256)

    if is_camel_case(data) or data.lower() == data or data.upper() == data:
        return min(0.2, round(entropy, 2))

    if not ascii_found or (not digit_found and not punctuation_found):
        return min(0.4, round(entropy, 2))

    return round(entropy, 2) if punctuation_found else min(0.38, round(entropy, 2))


def check_secret(data):
    """
    This function checks if the given data contains any secrets. It first checks
    if any strings from the allowlist are present in the data. If so, it returns
    an empty string to indicate no secrets found. Then, it iterates over a set
    of regular expressions categorized by secrets and checks if any of the
    regular expressions match the data. If a match is found, it returns the
    corresponding category. If no secrets are found, it returns an empty string.

    Args:
      - data: The data to be checked for secrets.

    Returns:
        str: The category of the secret if found, otherwise an empty string.
    """
    if any(text in data for text in strings_allowlist):
        return ""

    for category, rlist in secrets_regex.items():
        for regex in rlist:
            if regex.search(data):
                return category

    return ""


def is_binary_string(content):
    """
    Method to check if the given content is a binary string
    """
    textchars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7F})
    return bool(content.translate(None, textchars))


def is_ignored_file(file_name):
    """
    Method to find if the given file can be ignored
    :param file_name: File to compare
    :return: Boolean True if file can be ignored. False otherwise
    """
    if not file_name:
        return False
    file_name = file_name.lower()
    extn = "".join(Path(file_name).suffixes)
    if extn in ignore_files or file_name in ignore_files:
        return True
    return any(file_name.endswith(ie) for ie in ignore_files)


def blintdb_setup(args):
    """
    This function downloads blint-db package from 'ghcr.io/appthreat/blintdb-vcpkg' using oras client
    and puts it into $BLINTDB_LOC path.
    If there is not path in $BLINTDB_LOC, it will add it to $HOME/blindb.
    $USE_BLINTDB is required to be set "true" or "1", in order to use blintdb
    """
    if not os.getenv("USE_BLINTDB") and not args.use_blintdb and not args.db_mode:
        LOG.debug(f"Skipping blintdb setup, USE_BLINTDB={os.getenv('USE_BLINTDB')}")
        return
    if not os.path.exists(BLINTDB_HOME):
        os.makedirs(BLINTDB_HOME)
    # Should we refresh the database
    if os.path.exists(BLINTDB_LOC) and not BLINTDB_REFRESH and (
            not args.image_url or args.image_url == BLINTDB_IMAGE_URL):
        LOG.debug(f"blintdb is present at {BLINTDB_LOC}. Skipping refresh.")
        return
    try:
        oras_client = oras.client.OrasClient()
        target_url = args.image_url if args.db_mode and args.image_url else BLINTDB_IMAGE_URL
        LOG.info(f"About to download the blintdb from {target_url} to {BLINTDB_HOME}")
        oras_client.pull(
            target=target_url,
            outdir=BLINTDB_HOME,
            allowed_media_type=[],
            overwrite=True,
        )
        os.environ["USE_BLINTDB"] = "true"
        LOG.debug(f"Blintdb stored at {BLINTDB_HOME}")
    except Exception as e:
        LOG.error(f"Blintdb Download failed: {e}")


def is_exe(src):
    """
    Detect if the source is a binary file

    Args:
        src: Source path

    Returns:
         bool: True if binary file. False otherwise.
    """
    if os.path.isfile(src):
        try:
            with open(src, "rb") as f:
                data = f.read(1024)
            return is_binary_string(data)
        except (TypeError, OverflowError, ValueError, OSError) as e:
            LOG.debug(f"Caught {type(e)} while reading file: {src}")
            return False
    return False


def filter_ignored_dirs(dirs):
    """
    Method to filter directory list to remove ignored directories

    Args:
        dirs: Directories

    Returns:
        list: Filtered list of directories
    """
    return [
        dirs.remove(d) for d in list(dirs) if d.lower() in ignore_directories
    ]


def find_exe_files(src):
    """
    Method to find files with given extension

    Args:
        src (str): Source path

    Returns:
        list: List of filtered files
    """
    result = []
    for root, dirs, files in os.walk(src):
        filter_ignored_dirs(dirs)
        for file in files:
            if is_ignored_file(file):
                continue
            full_path = os.path.join(root, file)
            for ar_extn in KNOWN_AR_EXTNS:
                if full_path.endswith(ar_extn):
                    result += extract_ar(full_path)
                    continue
            if is_exe(full_path):
                result.append(full_path)
    return result


def find_android_files(path):
    """
    Method to find android app files

    :param path: Project directory
    :return: List of android files
    """
    app_extns = [".apk", ".aab"]
    return find_files(path, app_extns)


def find_bom_files(path):
    """
    Method to find BOM files

    :param path: Project directory
    :return: List of bom files
    """
    app_extns = ["bom.json", ".cdx.json"]
    return find_files(path, app_extns)


def find_files(path, extns):
    """
    Method to find files matching an extension
    """
    result = []
    if os.path.isfile(path):
        result += [path for ext in extns if path.endswith(ext)]
    else:
        for root, dirs, files in os.walk(path):
            filter_ignored_dirs(dirs)
            for file in files:
                result += [os.path.join(root, file) for ext in extns if file.endswith(ext)]
    return result


def bom_strip(manifest):
    """
    Function to delete UTF-8 BOM character in "string"

    Args:
        manifest (str): Executable manifest

    Returns:
        str: Manifest without BOM character
    """
    utf8_bom = b"\xef\xbb\xbf"
    return manifest[3:] if manifest[:3] == utf8_bom else manifest


def parse_pe_manifest(manifest):
    """
    Method to parse xml pe manifest

    Args:
        manifest (str): Executable manifest

    Returns:
        dict: Parsed manifest with flattened keys and values
    """
    try:
        attribs_dict = {}
        root = fromstring(bom_strip(manifest))
        for child in root:
            for ele in child.iter():
                attribs_dict[ele.tag.rpartition("}")[-1]] = ele.attrib
        return attribs_dict
    except (TypeError, AttributeError, IndexError, ParseError) as e:
        LOG.debug(f"Caught {type(e)}: {e} while parsing PE manifest.")
        return {}


def is_fuzzable_name(name_str):
    """
    This function checks if a given name string is fuzzable.
    """
    return any(n.lower() in name_str for n in fuzzable_names) if name_str else False


def print_findings_table(findings, files):
    """
    Prints the findings in a formatted table.

    This function takes a list of findings and a list of files, and prints the
    findings in a table format. The table includes columns for ID, Binary (if
    multiple files), Title, and Severity.

    Args:
        findings (list[dict]): A list of dictionaries representing the findings
        files (list[str]): A list of files.
    """
    table = create_findings_table(files, "BLint Findings")
    table.add_column("Title")
    table.add_column("Severity")
    for f in findings:
        severity = f.get("severity").upper()
        severity_fmt = (
            f'{"[bright_red]" if severity in ("CRITICAL", "HIGH") else ""}' f"{severity}"
        )
        if len(files) > 1:
            table.add_row(
                f.get("id"),
                f.get("exe_name"),
                f.get("title"),
                severity_fmt,
            )
        else:
            table.add_row(
                f.get("id"),
                f.get("title"),
                severity_fmt,
            )
    console.print(table)


def create_findings_table(files: list[str], title: str) -> Table:
    """
    Creates a table for displaying findings.

    Args:
        files: The list of files.
        title: The title of the table.

    Returns:
        Table: The created table.
    """
    table = Table(
        title=title,
        box=box.DOUBLE_EDGE,
        header_style="bold magenta",
        show_lines=True,
    )
    table.add_column("ID")
    if len(files) > 1:
        table.add_column("Binary")
    return table


def gen_file_list(src: list[str]) -> list[str]:
    """Generates a list of files from the given source.

    This function generates a list of executable files from a source directory
    or identifies a file.

    Args:
        src (list[str]): A source file/directory

    Returns:
        list[str]: A list of files.
    """
    files = []
    for s in src:
        if os.path.isdir(s):
            files += find_exe_files(s)
        else:
            if is_ignored_file(s):
                continue
            full_path = os.path.abspath(s)
            for ar_extn in KNOWN_AR_EXTNS:
                if full_path.endswith(ar_extn):
                    files += extract_ar(full_path)
                    continue
            if is_exe(full_path):
                files.append(full_path)
    return files


def unzip_unsafe(zf, to_dir):
    """Method to unzip the file in an unsafe manne"""
    with zipfile.ZipFile(zf, "r") as zip_ref:
        zip_ref.extractall(to_dir)


def check_command(cmd):
    """
    Method to check if command is available
    :return True if command is available in PATH. False otherwise
    """
    cpath = shutil.which(cmd, mode=os.F_OK | os.X_OK)
    return cpath is not None


def get_version():
    """
    Returns the version of depscan
    """
    return distribution("blint").version


def cleanup_dict_lief_errors(old_dict):
    """
    Removes lief_errors from a dictionary recursively.

    Args:
        old_dict (dict): The dictionary to remove lief_errors from.

    Returns:
        dict: A new dictionary with lief_errors removed.

    """
    new_dict = {}
    for key, value in old_dict.items():
        if isinstance(value, lief.lief_errors):
            continue
        if isinstance(value, dict):
            entry = cleanup_dict_lief_errors(value)
        elif isinstance(value, list):
            entry = cleanup_list_lief_errors(value)
        else:
            entry = value
        new_dict[key] = entry
    return new_dict


def cleanup_list_lief_errors(d):
    """
    Cleans up a list by removing lief errors recursively.

    :param d: The list to be cleaned up.

    :return: The new list
    """
    new_lst = []
    for dl in d:
        if isinstance(dl, lief.lief_errors):
            continue
        if isinstance(dl, dict):
            entry = cleanup_dict_lief_errors(dl)
        elif isinstance(dl, list):
            entry = cleanup_list_lief_errors(dl)
        else:
            entry = dl
        new_lst.append(entry)
    return new_lst


def create_component_evidence(method_value: str, confidence: float,
                              evidence_metadata: dict = None) -> ComponentEvidence:
    """
    Creates component evidence based on the provided method value.

    Args:
        method_value: The value of the method used for analysis.
        confidence: The confidence interval.
        evidence_metadata: Extra metadata for evidence purposes.

    Returns:
        ComponentEvidence: The created component evidence.
    """
    return ComponentEvidence(
        identity=ComponentIdentityEvidence(
            field=FieldModel.purl,
            confidence=confidence,
            methods=[
                Method(
                    technique=Technique.binary_analysis,
                    value=method_value,
                    confidence=confidence,
                )
            ],
        )
    )


def camel_to_snake(name: str) -> str:
    """Convert camelCase to snake_case"""
    name = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub("([a-z0-9])([A-Z])", r"\1_\2", name).lower()


def extract_ar(ar_file: str, to_dir: str | None = None) -> list[str]:
    """
    Extract the given ar compressed files to the directory specified by to_dir.
    Returns the list of extracted files
    """
    if not to_dir:
        to_dir = tempfile.mkdtemp(prefix="ar-temp-", dir=os.getenv("BLINT_TEMP_DIR"))
    files_list = []
    with open(ar_file, "rb") as fp:
        try:
            with Archive(fp) as archive:
                for entry in archive:
                    # This workarounds a bug in ar that returns multiple names
                    file_name = entry.name.split("\n")[0].removesuffix("/")
                    afile = os.path.join(to_dir, file_name)
                    with open(afile, "wb") as output:
                        output.write(archive.open(entry, "rb").read())
                        files_list.append(afile)
        except (ArchiveError, ValueError) as e:
            LOG.warning(f"Failed to extract {ar_file}: {e}")
    return files_list


def export_metadata(directory: str, metadata: Dict, mtype: str):
    """
    Exports metadata to file.
    """
    if not os.path.exists(directory):
        os.makedirs(directory)
    outfile = str(Path(directory) / f"{mtype.lower()}.json")
    output = orjson.dumps(metadata, default=json_serializer).decode("utf-8", "ignore")
    file_write(outfile, output, success_msg="", log=LOG)


def json_serializer(obj):
    """JSON serializer to help serialize problematic types such as bytes"""
    if isinstance(obj, bytes):
        try:
            return obj.decode("utf-8")
        except UnicodeDecodeError:
            return ""

    return obj
