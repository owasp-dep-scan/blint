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

import orjson
import yaml
from rich.progress import Progress
from rich.terminal_theme import MONOKAI

from blint.binary import parse
# pylint: disable-next=unused-import
from blint.checks import (check_nx, check_pie,
                          check_relro, check_canary, check_rpath,
                          check_virtual_size, check_authenticode,
                          check_dll_characteristics, check_codesign,
                          check_trust_info)
from blint.logger import LOG, console
from blint.utils import (create_findings_table, is_fuzzable_name, print_findings_table)

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
            for resource in importlib.resources.files(
                "blint.data.annotations"
            ).iterdir()
            if resource.is_file() and resource.name.endswith(".yml")
        )
if not review_files:
    review_methods_dir = Path(__file__).parent / "data" / "annotations"
    review_files = [
        p.as_posix() for p in Path(review_methods_dir).rglob("*.yml")
    ]

rules_dict = {}
review_exe_dict = defaultdict(list)
review_methods_dict = defaultdict(list)
review_symbols_dict = defaultdict(list)
review_imports_dict = defaultdict(list)
review_entries_dict = defaultdict(list)
review_rules_cache = {}

# Debug mode
DEBUG_MODE = os.getenv("SCAN_DEBUG_MODE") == "debug"

# No of evidences per category
EVIDENCE_LIMIT = 5


def get_resource(package, resource):
    """Return a file handle on a named resource in a Package."""

    # Prefer ResourceReader APIs, as they are newest.
    if HAVE_RESOURCE_READER:
        # If we're in the context of a module, we could also use
        # ``__loader__.get_resource_reader(__name__).open_resource(resource)``.
        # We use open_binary() because it is simple.
        return (
            importlib.resources.files(package)
            .joinpath(resource)
            .open("r", encoding="utf-8")
        )

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

# Load the default review methods
for review_methods_file in review_files:
    raw_annotations = []
    if DEBUG_MODE:
        LOG.debug(f"Loading review file {review_methods_file}")
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
            method_rules_dict[rule.get("id")] = rule
            review_rules_cache[rule.get("id")] = rule
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


def json_serializer(obj):
    """JSON serializer to help serialize problematic types such as bytes"""
    if isinstance(obj, bytes):
        return obj.decode('utf-8')

    return obj


def report(src_dir, reports_dir, findings, reviews, files, fuzzables):
    """Generates a report based on the analysis results.

    Args:
        src_dir: The source directory.
        reports_dir: The directory to save the reports.
        findings: A list of dictionaries representing the findings.
        reviews: A list of dictionaries representing the reviews.
        files: A list of file names associated with the findings and reviews.
        fuzzables: A list of fuzzable methods.

    """
    run_uuid = os.environ.get("SCAN_ID", str(uuid.uuid4()))
    common_metadata = {
        "scan_id": run_uuid,
        "created": f"{datetime.now():%Y-%m-%d %H:%M:%S%z}",
    }
    if findings:
        print_findings_table(findings, files)
        findings_file = Path(reports_dir) / "findings.json"
        LOG.info(f"Findings written to {findings_file}")
        output = orjson.dumps({**common_metadata, "findings": findings}, default=json_serializer).decode("utf-8",
                                                                                                         "ignore")
        with open(findings_file, mode="w", encoding="utf-8") as ffp:
            ffp.write(output)
    if reviews:
        print_reviews_table(reviews, files)
        reviews_file = Path(reports_dir) / "reviews.json"
        LOG.info(f"Review written to {reviews_file}")
        output = orjson.dumps({**common_metadata, "reviews": reviews}, default=json_serializer).decode("utf-8",
                                                                                                       "ignore")
        with open(reviews_file, mode="w", encoding="utf-8") as rfp:
            rfp.write(output)
    if fuzzables:
        fuzzables_file = Path(reports_dir) / "fuzzables.json"
        LOG.info(f"Fuzzables data written to {fuzzables_file}")
        output = orjson.dumps({**common_metadata, "fuzzables": fuzzables}, default=json_serializer).decode("utf-8",
                                                                                                           "ignore")
        with open(fuzzables_file, mode="w", encoding="utf-8") as rfp:
            rfp.write(output)
    else:
        LOG.debug("No suggestion available for fuzzing")

    if not findings and not reviews:
        LOG.info(f":white_heavy_check_mark: No issues found in {src_dir}!")
    # Try console output as html
    else:
        html_file = Path(reports_dir) / "blint-output.html"
        console.save_html(html_file, theme=MONOKAI)
        LOG.info(f"HTML report written to {html_file}")


class AnalysisRunner:
    """Class to analyze binaries."""

    def __init__(self):
        self.findings = []
        self.reviews = []
        self.fuzzables = []
        self.progress = Progress(
            transient=True, redirect_stderr=True,
            redirect_stdout=True, refresh_per_second=1, )
        self.task = None
        self.reviewer = None

    def start(self, files, reports_dir, no_reviews=False, suggest_fuzzables=True):
        """Starts the analysis process for the given source files.

        This function takes the command-line arguments and the reports
        directory as input, and starts the analysis process. It iterates over
        the source files, parses the metadata, checks the security properties,
        performs symbol reviews, and suggests fuzzable targets if specified.

        Args:
            files (list): The list of source files to be analyzed.
            reports_dir (str): The directory where the reports will be stored.
            no_reviews (bool): Whether to perform reviews or not.
            suggest_fuzzables (bool): Whether to suggest fuzzable targets or not.

        Returns:
            tuple: A tuple of the findings, reviews, files, and fuzzables.
        """
        with self.progress:
            self.task = self.progress.add_task(
                f"[green] BLinting {len(files)} binaries",
                total=len(files), start=True, )
            for f in files:
                self._process_files(f, reports_dir, no_reviews, suggest_fuzzables)
        return self.findings, self.reviews, self.fuzzables

    def _process_files(self, f, reports_dir, no_reviews, suggest_fuzzables):
        """Processes the given file and generates findings.

        Args:
            f (str): The file to be processed.
            reports_dir (str): The directory where the reports will be stored.
            no_reviews (bool): Whether to perform reviews or not.
            suggest_fuzzables (bool): Whether to suggest fuzzable targets or not.

        """
        self.progress.update(
            self.task, description=f"Processing [bold]{f}[/bold]")
        metadata = parse(f)
        exe_name = metadata.get("name", "")
        # Store raw metadata
        metadata_file = (Path(reports_dir) / f"{os.path.basename(exe_name)}"
                                             f"-metadata.json")
        LOG.debug(f"Metadata written to {metadata_file}")
        output = orjson.dumps(metadata, default=json_serializer).decode("utf-8", "ignore")
        with open(metadata_file, mode="w", encoding="utf-8") as ffp:
            ffp.write(output)
        self.progress.update(
            self.task,
            description=f"Checking [bold]{f}[/bold] against rules")
        if finding := run_checks(f, metadata):
            self.findings += finding
        # Perform symbol reviews
        if no_reviews:
            self.do_review(exe_name, f, metadata)
        # Suggest fuzzable targets
        if suggest_fuzzables and (fuzzdata := run_prefuzz(metadata)):
            self.fuzzables.append(
                {
                    "filename": f,
                    "exe_name": exe_name,
                    "methods": fuzzdata,
                }
            )
        self.progress.advance(self.task)

    def do_review(self, exe_name, f, metadata):
        """Performs a review of the given file."""
        self.progress.update(
            self.task, description="Checking methods against review rules")
        self.reviewer = ReviewRunner()
        self.reviewer.run_review(metadata)
        if self.reviewer.results:
            review = self.reviewer.process_review(f, exe_name)
            self.reviews += review


class ReviewRunner:
    """Class for running reviews."""

    def __init__(self):
        self.results = {}
        self.review_methods_list = []
        self.review_exe_list = []
        self.review_symbols_list = []
        self.review_imports_list = []
        self.review_entries_list = []

    def run_review(self, metadata):
        """
        Runs a review of the given file and metadata.

        This function performs a review of the file and metadata based on the
        available review methods for the executable type. It collects the
        results from different review methods, including methods for functions,
        symbols, imports, and dynamic entries.

        Returns:
            dict[str, list]: Review results where the keys are the review
            method IDs and the values are lists of matching results.
        """
        if not review_methods_dict:
            LOG.warning("No review methods loaded!")
            return {}
        if not metadata or not (exe_type := metadata.get("exe_type")):
            return {}
        self._gen_review_lists(exe_type)
        # Check if reviews are available for this exe type
        if (
                self.review_methods_list
                or self.review_exe_list
                or self.review_symbols_list
                or self.review_imports_list
                or self.review_entries_list
        ):
            return self._review_lists(metadata)
        return {}

    def _review_lists(self, metadata):
        """
        Reviews lists in the metadata and performs specific actions based on the
        review type.

        Args:
            metadata (dict): The metadata to review.

        Returns:
            dict: The results of the review.
        """
        if self.review_methods_list or self.review_exe_list:
            self._methods_or_exe(metadata)
        if self.review_symbols_list or self.review_exe_list:
            self._review_symbols_exe(metadata)
        if self.review_imports_list:
            self._review_imports(metadata)
        if self.review_entries_list:
            self._review_entries(metadata)
        return self.results

    def _review_imports(self, metadata):
        """
        Reviews imports in the metadata.

        Args:
            metadata (dict): The metadata to review.
        """
        imports_list = [f.get("name", "") for f in metadata.get("imports", [])]
        LOG.debug(f"Reviewing {len(imports_list)} imports")
        self.run_review_methods_symbols(self.review_imports_list, imports_list)

    def _review_entries(self, metadata):
        """
        Reviews entries in the metadata and performs specific actions based on
        the review type.

        Args:
            metadata (dict): The metadata to review.

        Returns:
            dict: The results of the review.
        """
        entries_list = [f.get("name", "") for f in
                        metadata.get("dynamic_entries", []) if
                        f.get("tag") == "NEEDED"]
        LOG.debug(f"Reviewing {len(entries_list)} dynamic entries")
        self.run_review_methods_symbols(self.review_entries_list, entries_list)

    def _review_symbols_exe(self, metadata):
        """
        Reviews symbols in the metadata.

        Args:
            metadata (dict): The metadata to review.
        """
        symbols_list = [f.get("name", "") for f in
                        metadata.get("dynamic_symbols", [])]
        symbols_list += [f.get("name", "") for f in
                         metadata.get("symtab_symbols", [])]
        LOG.debug(f"Reviewing {len(symbols_list)} symbols")
        if self.review_symbols_list:
            self.run_review_methods_symbols(
                self.review_symbols_list, symbols_list)
        if self.review_exe_list:
            self.run_review_methods_symbols(self.review_exe_list, symbols_list)

    def _methods_or_exe(self, metadata):
        """
        Reviews lists in the metadata and performs specific actions based on the
        review type.

        Args:
            metadata (dict): The metadata to review.
        """
        functions_list = [re.sub(r"[*&()]", "", f.get("name", "")) for f in
                          metadata.get("functions", [])]
        if metadata.get("magic", "").startswith("PE"):
            functions_list += [f.get("name", "") for f in
                               metadata.get("symtab_symbols", [])]
        # If there are no function but static symbols use that instead
        if not functions_list and metadata.get("symtab_symbols"):
            functions_list = [f.get("name", "") for f in
                              metadata.get("symtab_symbols", [])]
        LOG.debug(f"Reviewing {len(functions_list)} functions")
        if self.review_methods_list:
            self.run_review_methods_symbols(
                self.review_methods_list, functions_list)
        if self.review_exe_list:
            self.run_review_methods_symbols(
                self.review_exe_list, functions_list)

    def _gen_review_lists(self, exe_type):
        """
        Generates the review lists based on the given executable type.

        This function takes the executable type as input and generates the
        review lists for the corresponding type. It retrieves the review lists
        from the review dictionaries based on the executable type.
        """
        self.review_methods_list = review_methods_dict.get(exe_type)
        self.review_exe_list = review_exe_dict.get(exe_type)
        self.review_symbols_list = review_symbols_dict.get(exe_type)
        self.review_imports_list = review_imports_dict.get(exe_type)
        self.review_entries_list = review_entries_dict.get(exe_type)

    def process_review(self, f, exe_name):
        """
        Processes the review results for the given executable and review.

        Returns:
            list[dict]: The processed review result.
        """
        reviews = []
        if not self.results:
            return {}
        for cid, evidence in self.results.items():
            aresult = {**review_rules_cache.get(cid), "evidence": evidence,
                       "filename": f, "exe_name": exe_name, }
            del aresult["patterns"]
            reviews.append(aresult)
        return reviews

    def run_review_methods_symbols(self, review_list, functions_list):
        """Runs a review of methods and symbols based on the provided lists.

        This function takes a list of review methods and a list of functions and
        performs a review to find matches between the patterns specified in the
        review methods and the functions. It returns a dictionary of results
        where the keys are the review method IDs and the values are lists of
        matching results.

        Args:
            review_list (list[dict]): The review methods or symbols.
            functions_list (list): A list of functions to be reviewed.

        Returns:
            dict[str, list]: Method/symbol IDs and their results.
        """
        results = defaultdict(list)
        found_cid = defaultdict(int)
        found_pattern = defaultdict(int)
        found_function = {}
        if not review_list:
            return
        for review_methods in review_list:
            for cid, rule_obj in review_methods.items():
                if found_cid[cid] > EVIDENCE_LIMIT:
                    continue
                patterns = rule_obj.get("patterns")
                for apattern in patterns:
                    if found_pattern[apattern] > EVIDENCE_LIMIT or found_cid[cid] > EVIDENCE_LIMIT:
                        continue
                    for afun in functions_list:
                        if apattern.lower() in afun.lower() and not found_function.get(afun.lower()):
                            result = {"pattern": apattern, "function": afun, }
                            results[cid].append(result)
                            found_cid[cid] += 1
                            found_pattern[apattern] += 1
                            found_function[afun.lower()] = True
        self.results |= results
