import logging
import os
import shutil
import sys

from rich.progress import Progress

from blint.config import BlintOptions
from blint.cyclonedx.spec import CycloneDX
from blint.lib.android import analyze_android_app
from blint.lib.analysis import initialize_rules, report, run_checks, run_prefuzz
from blint.lib.binary import is_wasm_file, parse
from blint.lib.ios import collect_ios_app, enrich_with_bundle_context, is_ios_app
from blint.lib.review_runner import ReviewRunner
from blint.lib.sbom import generate
from blint.lib.utils import (
    export_metadata,
    find_android_files,
    find_ios_files,
    gen_file_list,
    get_hex_truncation_count,
    is_android_app,
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
        if blint_options.sbom_output_dir and not os.path.exists(blint_options.sbom_output_dir):
            os.makedirs(blint_options.sbom_output_dir)
    exe_files = gen_file_list(blint_options.src_dir_image)
    wasm_files = [f for f in exe_files if is_wasm_file(f)]
    if wasm_files:
        LOG.info(f"Found {len(wasm_files)} wasm file(s); these will be skipped in SBOM processing")
    android_files = []
    ios_files = []
    for src in blint_options.src_dir_image:
        if files := find_android_files(src):
            android_files += files
        if files := find_ios_files(src):
            ios_files += files
    return generate(blint_options, exe_files, android_files, ios_files)


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
        wants_callgraph_outputs = (
            blint_options.render_mermaid_callgraph
            or blint_options.export_callgraph_graphml
            or blint_options.export_callgraph_gexf
        )
        if is_android_app(f):
            metadata = self._process_android_file(f)
            if metadata is None:
                LOG.warning(f"No dex bytecode could be read from android app {f}; skipping")
                self.progress.advance(self.task)
                return
        elif is_ios_app(f):
            self._process_ios_file(f, blint_options, wants_callgraph_outputs)
            self.progress.advance(self.task)
            return
        else:
            should_disassemble = blint_options.disassemble and not is_wasm_file(f)
            if blint_options.disassemble and not should_disassemble:
                LOG.debug(f"Skipping disassembly for wasm file {f}")
            metadata = parse(f, should_disassemble)
        self._finalize_metadata(f, metadata, blint_options, wants_callgraph_outputs)
        self.progress.advance(self.task)

    def _process_ios_file(self, f, blint_options, wants_callgraph_outputs):
        """Unpack an iOS/macOS app (.ipa) and analyse each contained Mach-O.

        One archive yields several binaries (the main executable plus embedded
        frameworks, dylibs and app extensions); each is parsed through the normal
        native path and enriched with the app-bundle context.
        """
        app = collect_ios_app(f)
        if app is None:
            return
        try:
            for entry in app["binaries"]:
                bin_path = entry["path"]
                role = entry["role"]
                self.progress.update(
                    self.task,
                    description=f"Processing [bold]{os.path.basename(bin_path)}[/bold] ({role})",
                )
                should_disassemble = blint_options.disassemble and not is_wasm_file(bin_path)
                metadata = parse(bin_path, should_disassemble)
                enrich_with_bundle_context(
                    metadata, app["bundle_info"], role, entry.get("bundle_path")
                )
                self._finalize_metadata(bin_path, metadata, blint_options, wants_callgraph_outputs)
        finally:
            shutil.rmtree(app["temp_dir"], ignore_errors=True)

    def _finalize_metadata(self, f, metadata, blint_options, wants_callgraph_outputs):
        """Export metadata and run checks/reviews/fuzzing for a parsed binary."""
        exe_name = metadata.get("name", f)
        wasm_report = metadata.get("wasm_report")
        metadata_to_export = dict(metadata)
        if wasm_report:
            metadata_to_export.pop("wasm_report", None)
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
        # Native security-property checks (PAC, CET, etc.) are meaningless for
        # Dalvik apps and would fire spuriously; the dex review supplies the
        # relevant behavioural findings instead.
        if metadata.get("exe_type") != "dexbinary" and (finding := run_checks(f, metadata)):
            self.findings += finding
        if not blint_options.no_reviews:
            self.do_review(exe_name, f, metadata)
        if blint_options.fuzzy and (fuzzdata := run_prefuzz(metadata)):
            self.fuzzables.append(
                {
                    "filename": f,
                    "exe_name": exe_name,
                    "methods": fuzzdata,
                }
            )

    def _process_android_file(self, f):
        """Disassemble an android app's dex bytecode into review metadata.

        The Dalvik disassembler always runs for android apps (it is the only way
        to get reviewable behaviour out of them) and the merged dex callgraph is
        always embedded in the metadata, mirroring the native disassembly path.
        Returns ``None`` when no dex could be read.
        """
        self.progress.update(
            self.task, description=f"Disassembling [bold]{os.path.basename(f)}[/bold]"
        )
        return analyze_android_app(f, build_cg=True)

    def do_review(self, exe_name, f, metadata):
        """Performs a review of the given file."""
        self.progress.update(self.task, description="Checking methods against review rules")
        self.reviewer = ReviewRunner()
        self.reviewer.run_review(metadata)
        if self.reviewer.results:
            review = self.reviewer.process_review(f, exe_name)
            self.reviews += review
