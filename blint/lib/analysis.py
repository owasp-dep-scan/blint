import contextlib
import importlib  # noqa
import os
import re
import sys
import uuid
from collections import defaultdict
from datetime import datetime
from itertools import islice
from pathlib import Path
from typing import Optional

import yaml
from rich.terminal_theme import MONOKAI

# pylint: disable-next=unused-import
from blint.lib.checks import (
    check_nx,
    check_pie,
    check_relro,
    check_canary,
    check_rpath,
    check_virtual_size,
    check_authenticode,
    check_dll_characteristics,
    check_codesign,
    check_trust_info,
)
from blint.config import FIRST_STAGE_WORDS, PII_WORDS, get_int_from_env, BlintOptions
from blint.logger import LOG, console
from blint.lib.utils import (
    create_findings_table,
    is_fuzzable_name,
    print_findings_table,
    export_metadata
)

try:
    import importlib.resources  # pylint: disable=ungrouped-imports

    HAVE_RESOURCE_READER = True
except ImportError:
    HAVE_RESOURCE_READER = False

review_files = []
if HAVE_RESOURCE_READER:
    with contextlib.suppress(NameError, FileNotFoundError):
        review_files = (
            resource.name
            for resource in importlib.resources.files("blint.data.annotations").iterdir()
            if resource.is_file() and resource.name.endswith(".yml")
        )
if not review_files:
    review_methods_dir = Path(__file__).parent / "data" / "annotations"
    review_files = [p.as_posix() for p in Path(review_methods_dir).rglob("*.yml")]

rules_dict = {}
review_exe_dict = defaultdict(list)
review_methods_dict = defaultdict(list)
review_symbols_dict = defaultdict(list)
review_imports_dict = defaultdict(list)
review_entries_dict = defaultdict(list)
review_functions_dict = defaultdict(list)

review_rules_cache = {
    "PII_READ": {
        "id": "PII_READ",
        "title": "Detect PII Read Operations",
        "summary": "Can Retrieve Sensitive PII data",
        "description": "Contains logic to retrieve sensitive data such as names, email, passwords etc.",
        "patterns": PII_WORDS,
    },
    "LOADER_SYMBOLS": {
        "id": "LOADER_SYMBOLS",
        "title": "Detect Initial Loader",
        "summary": "Behaves like a loader",
        "description": "The binary behaves like a loader by downloading and executing additional payloads.",
        "patterns": FIRST_STAGE_WORDS,
    },
}

# Debug mode
DEBUG_MODE = os.getenv("SCAN_DEBUG_MODE") == "debug"

# No of evidences per category
EVIDENCE_LIMIT = get_int_from_env("EVIDENCE_LIMIT", 5)


def get_resource(package, resource):
    """Return a file handle on a named resource in a Package."""

    # Prefer ResourceReader APIs, as they are newest.
    if HAVE_RESOURCE_READER:
        # If we're in the context of a module, we could also use
        # ``__loader__.get_resource_reader(__name__).open_resource(resource)``.
        # We use open_binary() because it is simple.
        return importlib.resources.files(package).joinpath(resource).open("r", encoding="utf-8")

    # Fall back to __file__.

    # We need to first import the package so we can find its location.
    # This could raise an exception!
    mod = importlib.import_module(package)

    # Undefined __file__ will raise NameError on variable access.
    try:
        package_path = os.path.abspath(os.path.dirname(mod.__file__))
    except NameError:
        package_path = None

    if package_path is not None:
        # Warning: there is a path traversal attack possible here if
        # resource contains values like ../../../../etc/password. Input
        # must be trusted or sanitized before blindly opening files or
        # you may have a security vulnerability!
        resource_path = os.path.join(package_path, resource)

        return open(resource_path, "r", encoding="utf-8")

    # Could not resolve package path from __file__.
    LOG.warning(f"Unable to load resource: {package}:{resource}")
    return None


# Load the rules
with get_resource("blint.data", "rules.yml") as fp:
    raw_rules = fp.read().split("---")
for tmp_data in raw_rules:
    if not tmp_data:
        continue
    rules_list = yaml.safe_load(tmp_data)
    for rule in rules_list:
        rules_dict[rule.get("id")] = rule

def load_default_rules():
    """Load default rules from package resources."""
    with get_resource("blint.data", "rules.yml") as fp:
        raw_rules = fp.read().split("---")
    for tmp_data in raw_rules:
        if not tmp_data:
            continue
        rules_list = yaml.safe_load(tmp_data)
        for rule in rules_list:
            rules_dict[rule.get("id")] = rule
    for review_methods_file in review_files:
        with get_resource("blint.data.annotations", review_methods_file) as fp:
            raw_annotations = fp.read().split("---")
            for tmp_data in raw_annotations:
                if not tmp_data:
                    continue
                methods_reviews_groups = yaml.safe_load(tmp_data)
                exe_type_list = methods_reviews_groups.get("exe_type")
                if isinstance(exe_type_list, str):
                    exe_type_list = [exe_type_list]
                all_rules = methods_reviews_groups.get("rules")
                method_rules_dict = {}
                for rule in all_rules:
                    rule_id = rule.get("id")
                    if rule_id:
                        method_rules_dict[rule_id] = rule
                        review_rules_cache[rule_id] = rule
                    else:
                        LOG.warning("Default rule has no 'id'. Skipping.")
                        continue
                for etype in exe_type_list:
                    if methods_reviews_groups.get("group") == "METHOD_REVIEWS":
                        review_methods_dict[etype].append(method_rules_dict)
                    elif methods_reviews_groups.get("group") == "EXE_REVIEWS":
                        review_exe_dict[etype].append(method_rules_dict)
                    elif methods_reviews_groups.get("group") == "SYMBOL_REVIEWS":
                        review_symbols_dict[etype].append(method_rules_dict)
                    elif methods_reviews_groups.get("group") == "IMPORT_REVIEWS":
                        review_imports_dict[etype].append(method_rules_dict)
                    elif methods_reviews_groups.get("group") == "ENTRIES_REVIEWS":
                        review_entries_dict[etype].append(method_rules_dict)
                    elif methods_reviews_groups.get("group") == "FUNCTION_REVIEWS":
                        review_functions_dict[etype].append(method_rules_dict)

def load_custom_rules(custom_dir_path: Optional[str], review_rules_cache, review_exe_dict, review_methods_dict, review_symbols_dict, review_imports_dict, review_entries_dict, review_functions_dict):
    """
    Loads custom review rules from a specified directory.
    """
    if not custom_dir_path:
        return
    if not os.path.isdir(custom_dir_path):
        LOG.debug(f"Custom rules directory '{custom_dir_path}' does not exist or is not a directory. Skipping custom rules.")
        return

    LOG.debug(f"Loading custom review rules from '{custom_dir_path}'")
    custom_path = Path(custom_dir_path)
    custom_rule_files = list(custom_path.glob("*.yml")) + list(custom_path.glob("*.yaml"))

    for rule_file_path in custom_rule_files:
        LOG.debug(f"Loading custom rules from {rule_file_path}")
        try:
            with open(rule_file_path, 'r', encoding='utf-8') as f:
                raw_annotations = f.read().split("---")
                for tmp_data in raw_annotations:
                    if not tmp_data:
                        continue
                    methods_reviews_groups = yaml.safe_load(tmp_data)
                    if not methods_reviews_groups:
                        continue
                    exe_type_list = methods_reviews_groups.get("exe_type")
                    if isinstance(exe_type_list, str):
                        exe_type_list = [exe_type_list]
                    all_rules = methods_reviews_groups.get("rules")
                    if not all_rules:
                        LOG.info(f"No 'rules' found in block of {rule_file_path}")
                        continue
                    method_rules_dict = {}
                    for rule in all_rules:
                        rule_id = rule.get("id")
                        if rule_id:
                            method_rules_dict[rule_id] = rule
                            review_rules_cache[rule_id] = rule
                        else:
                            LOG.warning(f"Rule in {rule_file_path} has no 'id'. Skipping.")
                            continue

                    for etype in exe_type_list:
                        if methods_reviews_groups.get("group") == "METHOD_REVIEWS":
                            review_methods_dict[etype].append(method_rules_dict)
                        elif methods_reviews_groups.get("group") == "EXE_REVIEWS":
                            review_exe_dict[etype].append(method_rules_dict)
                        elif methods_reviews_groups.get("group") == "SYMBOL_REVIEWS":
                            review_symbols_dict[etype].append(method_rules_dict)
                        elif methods_reviews_groups.get("group") == "IMPORT_REVIEWS":
                            review_imports_dict[etype].append(method_rules_dict)
                        elif methods_reviews_groups.get("group") == "ENTRIES_REVIEWS":
                            review_entries_dict[etype].append(method_rules_dict)
                        elif methods_reviews_groups.get("group") == "FUNCTION_REVIEWS":
                            review_functions_dict[etype].append(method_rules_dict)
                        else:
                            LOG.warning(f"Unknown group '{methods_reviews_groups.get('group')}' in {rule_file_path}. Skipping block.")
        except Exception as e:
            LOG.error(f"Error loading custom rules from {rule_file_path}: {e}")

def initialize_rules(blint_options: BlintOptions):
    """
    Loads default and custom rules based on blint_options.
    """
    rules_dict.clear()
    review_exe_dict.clear()
    review_methods_dict.clear()
    review_symbols_dict.clear()
    review_imports_dict.clear()
    review_entries_dict.clear()
    review_functions_dict.clear()
    review_rules_cache.clear()
    review_rules_cache.update({
        "PII_READ": {
            "id": "PII_READ",
            "title": "Detect PII Read Operations",
            "summary": "Can Retrieve Sensitive PII data",
            "description": "Contains logic to retrieve sensitive data such as names, email, passwords etc.",
            "patterns": PII_WORDS,
        },
        "LOADER_SYMBOLS": {
            "id": "LOADER_SYMBOLS",
            "title": "Detect Initial Loader",
            "summary": "Behaves like a loader",
            "description": "The binary behaves like a loader by downloading and executing additional payloads.",
            "patterns": FIRST_STAGE_WORDS,
        },
    })
    load_default_rules()
    load_custom_rules(blint_options.custom_rules_dir, review_rules_cache, review_exe_dict, review_methods_dict, review_symbols_dict, review_imports_dict, review_entries_dict, review_functions_dict)

def run_checks(f, metadata):
    """Runs the checks on the provided metadata using the loaded rules.

    Args:
        f: The metadata of the functions.
        metadata: The metadata containing information about the executable.

    Returns:
        A list of result dictionaries representing the outcomes of the checks.

    """
    results = []
    if not rules_dict:
        LOG.warning("No rules loaded!")
        return results
    if not metadata:
        return results
    exe_type = metadata.get("exe_type")
    for cid, rule_obj in rules_dict.items():
        rule_exe_types = rule_obj.get("exe_types")
        # Skip rules that are not valid for this exe type
        if exe_type and rule_exe_types and exe_type not in rule_exe_types:
            continue
        if result := run_rule(f, metadata, rule_obj, exe_type, cid):
            results.append(result)
    return results


def run_rule(f, metadata, rule_obj, exe_type, cid):
    """
    Runs a rule on a file with the provided metadata, rule object, executable
    type, and component ID.

    Args:
        f (str): The file path to run the rule on.
        metadata (dict): The metadata of the file.
        rule_obj (dict): The rule object to compare against.
        exe_type (str): The executable type of the file.
        cid (str): The component ID.

    Returns:
        str or dict: The result of running the rule on the file
    """
    if cfn := getattr(sys.modules[__name__], cid.lower(), None):
        result = cfn(f, metadata, rule_obj=rule_obj)
        if result is False or isinstance(result, str):
            aresult = {**rule_obj, "filename": f}
            return process_result(metadata, aresult, exe_type, result)
    return ""


def process_result(metadata, aresult, exe_type, result):
    """Processes the result by modifying the provided result dictionary.

    Args:
        metadata: The metadata containing information about the executable.
        aresult: The result dictionary to be modified.
        exe_type: The type of the executable.
        result: The result value to be processed.

    Returns:
        The modified result dictionary.

    """
    if isinstance(result, str):
        aresult["title"] = f"{aresult['title']} ({result})"
    if metadata.get("name"):
        aresult["exe_name"] = metadata.get("name")
    aresult["exe_type"] = exe_type
    return aresult


def run_prefuzz(metadata):
    """Runs the pre-fuzzing process on the given metadata.

    Generates a list of fuzzable methods from the provided metadata by
    extracting the function names and addresses.

    Args:
        metadata: The metadata containing the functions.

    Returns:
        A list of fuzzable methods with their names and addresses.

    """
    functions_list = [
        {
            "name": re.sub(r"[*&()]", "", f.get("name", "")),
            "address": f.get("address", ""),
        }
        for f in metadata.get("functions", [])
    ]
    functions_list += [
        {
            "name": re.sub(r"[*&()]", "", f.get("name", "")),
            "address": f.get("address", ""),
        }
        for f in metadata.get("ctor_functions", [])
    ]
    functions_list += [
        {
            "name": re.sub(r"[*&()]", "", f.get("name", "")),
            "address": f.get("address", ""),
        }
        for f in metadata.get("exception_functions", [])
    ]
    functions_list += [
        {
            "name": re.sub(r"[*&()]", "", f.get("name", "")),
            "address": f.get("address", ""),
        }
        for f in metadata.get("unwind_functions", [])
    ]
    functions_list += [
        {"name": f.get("name", ""), "address": f.get("address", "")}
        for f in metadata.get("exports", [])
    ]
    fuzzables = [
        {"name": f.get("name"), "address": f.get("address", "").strip()}
        for f in functions_list
        if is_fuzzable_name(f.get("name"))
    ]
    LOG.debug(f"Found {len(fuzzables)} fuzzable methods")
    return fuzzables


def print_reviews_table(reviews, files):
    """Prints the capability review table.

    Args:
        reviews: A list of dictionaries representing the capability reviews.
        files: A list of file names associated with the reviews.

    """
    table = create_findings_table(files, "BLint Capability Review")
    table.add_column("Capabilities")
    table.add_column("Evidence (Top 5)", overflow="fold")
    for r in reviews:
        evidences = [e.get("function") for e in r.get("evidence")]
        evidences = list(islice(evidences, EVIDENCE_LIMIT))
        if len(files) > 1:
            table.add_row(
                r.get("id"),
                r.get("exe_name"),
                r.get("summary"),
                "\n".join(evidences),
            )
        else:
            table.add_row(
                r.get("id"),
                r.get("summary"),
                "\n".join(evidences),
            )
    console.print(table)


def report(blint_options, exe_files, findings, reviews, fuzzables):
    """Generates a report based on the analysis results.

    Args:
        blint_options: A BlintOptions object containing settings.
        exe_files: A list of file names associated with the findings and reviews.
        findings: A list of dictionaries representing the findings.
        reviews: A list of dictionaries representing the reviews.
        fuzzables: A list of fuzzable methods.

    """
    if not findings and not reviews:
        LOG.info(f":white_heavy_check_mark: No issues found in {blint_options.src_dir_image}!")
        return
    if not os.path.exists(blint_options.reports_dir):
        os.makedirs(blint_options.reports_dir)
    run_uuid = os.environ.get("SCAN_ID", str(uuid.uuid4()))
    common_metadata = {
        "scan_id": run_uuid,
        "created": f"{datetime.now():%Y-%m-%d %H:%M:%S%z}",
    }
    if findings:
        print_findings_table(findings, exe_files)
        export_metadata(blint_options.reports_dir, {**common_metadata, "findings": findings}, "Findings")
    if reviews:
        print_reviews_table(reviews, exe_files)
        export_metadata(blint_options.reports_dir, {**common_metadata, "reviews": reviews}, "Reviews")
    if fuzzables:
        export_metadata(blint_options.reports_dir, {**common_metadata, "fuzzables": fuzzables}, "Fuzzables")
    else:
        LOG.debug("No suggestion available for fuzzing")
    # Try console output as html
    html_file = Path(blint_options.reports_dir) / "blint-output.html"
    console.save_html(html_file, theme=MONOKAI)
    LOG.debug(f"HTML report written to {html_file}")
