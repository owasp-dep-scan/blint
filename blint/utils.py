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

from ar import Archive
import lief
from defusedxml.ElementTree import fromstring
from rich import box
from rich.table import Table

from blint.config import (
    ignore_directories,
    ignore_files,
    strings_allowlist,
    fuzzable_names,
    secrets_regex
)
from blint.cyclonedx.spec import ComponentEvidence, FieldModel, Identity, Method, Technique
from blint.logger import console, LOG

CHARSET = string.digits + string.ascii_letters + r"""!&@"""

# Known files compressed with ar
KNOWN_AR_EXTNS = (".a", ".rlib", ".lib")


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
    # text_chars = bytearray(
    #     {7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7F})
    # return bool(
    #     content.translate(bytes.maketrans(b"", text_chars)))
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
        dirs.remove(d) for d in list(dirs) if d.lower() in ignore_directories or d.startswith(".")
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
    except (TypeError, AttributeError, IndexError) as e:
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


def create_component_evidence(method_value: str, confidence: float) -> ComponentEvidence:
    """
    Creates component evidence based on the provided method value.

    Args:
        method_value: The value of the method used for analysis.
        confidence: The confidence interval.

    Returns:
        ComponentEvidence: The created component evidence.
    """
    return ComponentEvidence(
        identity=Identity(
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
    name = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', name).lower()


def extract_ar(ar_file: str, to_dir: str | None = None) -> list[str]:
    """
    Extract the given ar compressed files to the directory specified by to_dir.
    Returns the list of extracted files
    """
    if not to_dir:
        to_dir = tempfile.mkdtemp(prefix="ar-temp-")
    files_list = []
    with open(ar_file, 'rb') as fp:
        with Archive(fp) as archive:
            for entry in archive:
                # This workarounds a bug in ar that returns multiple names
                file_name = entry.name.split("\n")[0].removesuffix("/")
                afile = os.path.join(to_dir, file_name)
                with open(afile, 'wb') as output:
                    output.write(archive.open(entry, 'rb').read())
                    files_list.append(afile)
    return files_list
