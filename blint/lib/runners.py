import logging
import os
import re
import sys
from collections import defaultdict

from rich.progress import Progress

from blint.config import BlintOptions
from blint.cyclonedx.spec import CycloneDX
from blint.lib.analysis import (
    EVIDENCE_LIMIT,
    report,
    review_entries_dict, review_exe_dict,
    review_imports_dict, review_methods_dict,
    review_rules_cache, review_symbols_dict, run_checks,
    run_prefuzz, review_functions_dict, initialize_rules
)
from blint.lib.binary import parse
from blint.logger import LOG
from blint.lib.sbom import generate
from blint.lib.utils import export_metadata, find_android_files, gen_file_list


def run_sbom_mode(blint_options: BlintOptions) -> CycloneDX:
    """
    Generates an SBOM for the given source directories. Binary files including android apk files are collected
    automatically.

    Args:
        blint_options (BlintOptions): A BlintOptions object containing the SBOM generation options.
    Returns:
        CycloneDX: Generated CycloneDX SBOM
    """
    if blint_options.stdout_mode:
        LOG.setLevel(logging.ERROR)
    else:
        if blint_options.sbom_output_dir and not os.path.exists(blint_options.sbom_output_dir):
            os.makedirs(blint_options.sbom_output_dir)
    exe_files = gen_file_list(blint_options.src_dir_image)
    android_files = []
    for src in blint_options.src_dir_image:
        if files := find_android_files(src):
            android_files += files
    return generate(blint_options, exe_files, android_files)


def run_default_mode(blint_options: BlintOptions) -> None:
    exe_files = gen_file_list(blint_options.src_dir_image)
    analyzer = AnalysisRunner()
    findings, reviews, fuzzables = analyzer.start(blint_options, exe_files)
    report(blint_options, exe_files, findings, reviews, fuzzables)

    if os.getenv("CI") and not blint_options.no_error:
        for f in findings:
            if f['severity'] == 'critical':
                sys.exit(1)


class AnalysisRunner:
    """Class to analyze binaries."""

    def __init__(self):
        self.findings = []
        self.reviews = []
        self.fuzzables = []
        self.progress = Progress(
            transient=True,
            redirect_stderr=True,
            redirect_stdout=True,
            refresh_per_second=1,
        )
        self.task = None
        self.reviewer = None

    def start(self, blint_options, exe_files):
        """Starts the analysis process for the given source files.

        This function takes the command-line arguments and the reports
        directory as input, and starts the analysis process. It iterates over
        the source files, parses the metadata, checks the security properties,
        performs symbol reviews, and suggests fuzzable targets if specified.

        Returns:
            tuple: A tuple of the findings, reviews, files, and fuzzables.
        """
        initialize_rules(blint_options)
        with self.progress:
            self.task = self.progress.add_task(
                f"[green] BLinting {len(exe_files)} binaries",
                total=len(exe_files),
                start=True,
            )
            for f in exe_files:
                self._process_files(f, blint_options)
        return self.findings, self.reviews, self.fuzzables

    def _process_files(self, f, blint_options):
        """
        Processes the given file and generates findings.
        """
        self.progress.update(self.task, description=f"Processing [bold]{f}[/bold]")
        metadata = parse(f, blint_options.disassemble)
        exe_name = metadata.get("name", "")
        # Store raw metadata
        export_metadata(blint_options.reports_dir, metadata, f"{os.path.basename(exe_name)}-metadata")
        self.progress.update(self.task, description=f"Checking [bold]{f}[/bold] against rules")
        if finding := run_checks(f, metadata):
            self.findings += finding
        # Perform symbol reviews
        if not blint_options.no_reviews:
            self.do_review(exe_name, f, metadata)
        # Suggest fuzzable targets
        if blint_options.fuzzy and (fuzzdata := run_prefuzz(metadata)):
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
        self.progress.update(self.task, description="Checking methods against review rules")
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
        self.review_functions_list = []

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
                or self.review_functions_list
        ):
            return self._review_lists(metadata)
        return self._review_loader_symbols(metadata)

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
        if self.review_functions_list:
            self._review_functions(metadata)
        self._review_pii(metadata)
        self._review_loader_symbols(metadata)
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
        entries_list = [
            f.get("name", "")
            for f in metadata.get("dynamic_entries", [])
            if f.get("tag") == "NEEDED"
        ]
        LOG.debug(f"Reviewing {len(entries_list)} dynamic entries")
        self.run_review_methods_symbols(self.review_entries_list, entries_list)

    def _review_pii(self, metadata):
        """
        Reviews pii symbols.

        Args:
            metadata (dict): The metadata to review.

        Returns:
            dict: The results of the review.
        """
        entries_list = [f.get("name", "") for f in metadata.get("pii_symbols", [])]
        results = defaultdict(list)
        for e in entries_list[0:EVIDENCE_LIMIT]:
            results["PII_READ"].append({"pattern": e, "function": e})
        self.results |= results

    def _review_loader_symbols(self, metadata):
        """
        Reviews loader symbols.

        Args:
            metadata (dict): The metadata to review.

        Returns:
            dict: The results of the review.
        """
        entries_list = [f.get("name", "") for f in metadata.get("first_stage_symbols", [])]
        results = defaultdict(list)
        for e in entries_list[0:EVIDENCE_LIMIT]:
            results["LOADER_SYMBOLS"].append({"pattern": e, "function": e})
        self.results |= results

    def _review_symbols_exe(self, metadata):
        """
        Reviews symbols in the metadata.

        Args:
            metadata (dict): The metadata to review.
        """
        symbols_list = [f.get("name", "") for f in metadata.get("dynamic_symbols", [])]
        symbols_list += [f.get("name", "") for f in metadata.get("symtab_symbols", [])]
        LOG.debug(f"Reviewing {len(symbols_list)} symbols")
        if self.review_symbols_list:
            self.run_review_methods_symbols(self.review_symbols_list, symbols_list)
        if self.review_exe_list:
            self.run_review_methods_symbols(self.review_exe_list, symbols_list)

    def _review_functions(self, metadata):
        """
        Reviews disassembled functions based on their behavioural metadata.
        """
        if not metadata.get("disassembled_functions"):
            return

        LOG.debug(f"Reviewing {len(metadata['disassembled_functions'])} disassembled functions")
        results = defaultdict(list)
        found_cid = defaultdict(int)
        for review_group in self.review_functions_list:
            for rule_id, rule_obj in review_group.items():
                for func_key, func_data in metadata["disassembled_functions"].items():
                    if found_cid[rule_id] >= EVIDENCE_LIMIT:
                        continue
                    check_type = rule_obj.get("check_type")
                    passed = False
                    if check_type == "function_flag":
                        check_field = rule_obj.get("check_field")
                        if func_data.get(check_field):
                            passed = True
                    elif check_type == "function_metric":
                        check_field = rule_obj.get("check_field")
                        operator_str = rule_obj.get("operator")
                        threshold = rule_obj.get("threshold")
                        if check_field and operator_str and threshold is not None:
                            value = func_data
                            for key in check_field.split('.'):
                                value = value.get(key)
                                if value is None:
                                    break
                            if value is not None:
                                if operator_str == ">":
                                    passed = value > threshold
                                elif operator_str == ">=":
                                    passed = value >= threshold
                                elif operator_str == "<":
                                    passed = value < threshold
                                elif operator_str == "<=":
                                    passed = value <= threshold
                                elif operator_str == "==":
                                    passed = value == threshold
                                elif operator_str == "!=":
                                    passed = value != threshold
                    elif check_type == "function_analysis":
                        if rule_id == "CRYPTO_BEHAVIOR":
                            metrics = func_data.get("instruction_metrics", {})
                            icount = func_data.get("instruction_count", 0)
                            if icount > 10:
                                shift_xor = metrics.get("shift_count", 0) + metrics.get("xor_count", 0)
                                if (shift_xor / icount > 0.2) and metrics.get("simd_fpu_count", 0) > 0:
                                    passed = True
                        elif rule_id == "ANTI_DISASSEMBLY_TRICKS":
                            metrics = func_data.get("instruction_metrics", {})
                            if func_data.get("instruction_count", 0) <= 5 and metrics.get("jump_count", 0) > 0:
                                passed = True
                    if passed:
                        evidence = {
                            "function": func_data.get("name", func_key),
                            "address": func_data.get("address"),
                            "snippet": func_data.get("assembly", "").split('\n')[0]
                        }
                        results[rule_id].append(evidence)
                        found_cid[rule_id] += 1
        self.results |= results

    def _methods_or_exe(self, metadata):
        """
        Reviews lists in the metadata and performs specific actions based on the
        review type.

        Args:
            metadata (dict): The metadata to review.
        """
        functions_list = [
            re.sub(r"[*&()]", "", f.get("name", "")) for f in metadata.get("functions", [])
        ]
        if metadata.get("magic", "").startswith("PE"):
            functions_list += [f.get("name", "") for f in metadata.get("symtab_symbols", [])]
        # If there are no function but static symbols use that instead
        if not functions_list and metadata.get("symtab_symbols"):
            functions_list = [f.get("name", "") for f in metadata.get("symtab_symbols", [])]
        LOG.debug(f"Reviewing {len(functions_list)} functions")
        if self.review_methods_list:
            self.run_review_methods_symbols(self.review_methods_list, functions_list)
        if self.review_exe_list:
            self.run_review_methods_symbols(self.review_exe_list, functions_list)

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
        self.review_functions_list = review_functions_dict.get(exe_type)

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
            aresult = {
                **review_rules_cache.get(cid),
                "evidence": evidence,
                "filename": f,
                "exe_name": exe_name,
            }
            if hasattr(aresult, "patterns"):
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
                        if apattern.lower() in afun.lower() and not found_function.get(
                                afun.lower()
                        ):
                            result = {
                                "pattern": apattern,
                                "function": afun,
                            }
                            results[cid].append(result)
                            found_cid[cid] += 1
                            found_pattern[apattern] += 1
                            found_function[afun.lower()] = True
        self.results |= results
