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
    initialize_rules,
    report,
    review_entries_dict,
    review_exe_dict,
    review_functions_dict,
    review_imports_dict,
    review_methods_dict,
    review_rules_cache,
    review_symbols_dict,
    run_checks,
    run_prefuzz,
)
from blint.lib.binary import is_wasm_file, parse
from blint.lib.function_reviews import review_disassembled_functions
from blint.lib.review_utils import run_pattern_reviews
from blint.lib.sbom import generate
from blint.lib.utils import (
    export_metadata,
    find_android_files,
    gen_file_list,
    get_hex_truncation_count,
    reset_hex_truncation_count,
)
from blint.logger import LOG


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
        if blint_options.sbom_output_dir and not os.path.exists(
            blint_options.sbom_output_dir
        ):
            os.makedirs(blint_options.sbom_output_dir)
    exe_files = gen_file_list(blint_options.src_dir_image)
    wasm_files = [f for f in exe_files if is_wasm_file(f)]
    if wasm_files:
        LOG.info(
            f"Found {len(wasm_files)} wasm file(s); these will be skipped in SBOM processing"
        )
    android_files = []
    for src in blint_options.src_dir_image:
        if files := find_android_files(src):
            android_files += files
    return generate(blint_options, exe_files, android_files)


def run_default_mode(blint_options: BlintOptions) -> None:
    reset_hex_truncation_count()
    wants_callgraph_outputs = (
        blint_options.render_mermaid_callgraph
        or blint_options.export_callgraph_graphml
        or blint_options.export_callgraph_gexf
    )
    if wants_callgraph_outputs and not blint_options.disassemble:
        LOG.info(
            "Callgraph export was requested without --disassemble; no callgraph artifacts will be generated."
        )
    exe_files = gen_file_list(blint_options.src_dir_image)
    analyzer = AnalysisRunner()
    findings, reviews, fuzzables, callgraphs = analyzer.start(blint_options, exe_files)
    report(blint_options, exe_files, findings, reviews, fuzzables, callgraphs)
    truncation_count = get_hex_truncation_count()
    if truncation_count:
        LOG.info(
            f"Metadata export hex-truncated {truncation_count} undecodable byte field(s). "
            "Tune BLINT_MAX_HEX_BYTES (or set to 0 to disable truncation)."
        )

    if os.getenv("CI") and not blint_options.no_error:
        for f in findings:
            if f["severity"] == "critical":
                sys.exit(1)


class AnalysisRunner:
    """Class to analyze binaries."""

    def __init__(self):
        self.findings = []
        self.reviews = []
        self.fuzzables = []
        self.callgraphs = []
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
        return self.findings, self.reviews, self.fuzzables, self.callgraphs

    def _process_files(self, f, blint_options):
        """
        Processes the given file and generates findings.
        """
        self.progress.update(
            self.task, description=f"Processing [bold]{os.path.basename(f)}[/bold]"
        )
        should_disassemble = blint_options.disassemble and not is_wasm_file(f)
        if blint_options.disassemble and not should_disassemble:
            LOG.debug(f"Skipping disassembly for wasm file {f}")
        metadata = parse(f, should_disassemble)
        exe_name = metadata.get("name", f)
        wasm_report = metadata.get("wasm_report")
        metadata_to_export = dict(metadata)
        if wasm_report:
            metadata_to_export.pop("wasm_report", None)
        # Store raw metadata
        export_metadata(
            blint_options.reports_dir,
            metadata_to_export,
            f"{os.path.basename(exe_name)}-metadata",
        )
        if wasm_report:
            export_metadata(
                blint_options.reports_dir,
                wasm_report,
                f"{os.path.basename(exe_name)}-wasm-report",
            )
        wants_callgraph_outputs = (
            blint_options.render_mermaid_callgraph
            or blint_options.export_callgraph_graphml
            or blint_options.export_callgraph_gexf
        )
        if wants_callgraph_outputs and metadata.get("callgraph"):
            self.callgraphs.append(
                {
                    "exe_name": os.path.basename(exe_name),
                    "callgraph": metadata.get("callgraph"),
                }
            )
        self.progress.update(
            self.task,
            description=f"Checking [bold]{os.path.basename(f)}[/bold] against rules",
        )
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
        self.progress.update(
            self.task, description="Checking methods against review rules"
        )
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
        entries_list = [
            f.get("name", "") for f in metadata.get("first_stage_symbols", [])
        ]
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
        disassembled_functions = metadata.get("disassembled_functions")
        if not disassembled_functions:
            return

        LOG.debug(f"Reviewing {len(disassembled_functions)} disassembled functions")
        results = review_disassembled_functions(
            self.review_functions_list,
            disassembled_functions,
            EVIDENCE_LIMIT,
        )
        self.results |= results

    def _methods_or_exe(self, metadata):
        """
        Reviews lists in the metadata and performs specific actions based on the
        review type.

        Args:
            metadata (dict): The metadata to review.
        """
        functions_list = [
            re.sub(r"[*&()]", "", f.get("name", ""))
            for f in metadata.get("functions", [])
        ]
        if metadata.get("magic", "").startswith("PE"):
            functions_list += [
                f.get("name", "") for f in metadata.get("symtab_symbols", [])
            ]
        # If there are no function but static symbols use that instead
        if not functions_list and metadata.get("symtab_symbols"):
            functions_list = [
                f.get("name", "") for f in metadata.get("symtab_symbols", [])
            ]
        informative_values = []
        for s in metadata.get("informative_strings", []):
            if isinstance(s, dict):
                value = s.get("value", "")
            else:
                value = str(s)
            if value:
                informative_values.append(value)
        LOG.debug(f"Reviewing {len(functions_list)} functions")
        if self.review_methods_list:
            self.run_review_methods_symbols(
                self.review_methods_list,
                functions_list,
                informative_values=informative_values,
            )
        if self.review_exe_list:
            self.run_review_methods_symbols(
                self.review_exe_list,
                functions_list,
                informative_values=informative_values,
            )

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

    def run_review_methods_symbols(
        self, review_list, functions_list, informative_values=None
    ):
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
        results = run_pattern_reviews(
            review_list,
            functions_list,
            EVIDENCE_LIMIT,
            informative_values=informative_values,
        )
        self.results |= results
