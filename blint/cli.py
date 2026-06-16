#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os

from blint.lib.runners import run_default_mode, run_sbom_mode
from blint.config import BlintOptions, BLINTDB_HOME, BLINTDB_IMAGE_URL, BLINTDB_LOC
from blint.lib.utils import blintdb_setup
from blint.logger import LOG

BLINT_LOGO = """
██████╗ ██╗     ██╗███╗   ██╗████████╗
██╔══██╗██║     ██║████╗  ██║╚══██╔══╝
██████╔╝██║     ██║██╔██╗ ██║   ██║
██╔══██╗██║     ██║██║╚██╗██║   ██║
██████╔╝███████╗██║██║ ╚████║   ██║
╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝
"""


def _callgraph_algorithms():
    """Return the registered callgraph match algorithm names."""
    from blint.lib.callgraph.algorithms import available_algorithms

    return available_algorithms()


def _callgraph_default_algorithm():
    """Return the default callgraph match algorithm name."""
    from blint.lib.callgraph.algorithms import DEFAULT_ALGORITHM

    return DEFAULT_ALGORITHM


def build_args():
    """
    Constructs command line arguments for the blint tool
    """
    parser = build_parser()
    return parser.parse_args()


def build_parser():
    parser = argparse.ArgumentParser(
        prog="blint",
        description="Binary linter and SBOM generator.",
    )
    parser.set_defaults(
        deep_mode=False,
        sbom_output="",
        stdout_mode=False,
        exports_prefix=[],
        src_dir_boms=[],
        sbom_mode=False,
        db_mode=False,
        callgraph_match_mode=False,
        quiet_mode=False,
    )
    parser.add_argument(
        "-i",
        "--src",
        dest="src_dir_image",
        action="extend",
        default=[],
        nargs="+",
        help="Source directories, container images or binary files. Defaults "
        "to current directory.",
    )
    parser.add_argument(
        "-o",
        "--reports",
        dest="reports_dir",
        default=os.path.join(os.getcwd(), "reports"),
        help="Reports directory. Defaults to reports.",
    )
    parser.add_argument(
        "--no-error",
        action="store_true",
        default=False,
        dest="noerror",
        help="Continue on error to prevent build from breaking.",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        default=False,
        dest="no_banner",
        help="Do not display banner.",
    )
    parser.add_argument(
        "--no-reviews",
        action="store_true",
        default=False,
        dest="no_reviews",
        help="Do not perform method reviews.",
    )
    parser.add_argument(
        "--suggest-fuzzable",
        action="store_true",
        default=False,
        dest="suggest_fuzzable",
        help="Suggest functions and symbols for fuzzing based on a dictionary.",
    )
    parser.add_argument(
        "--use-blintdb",
        action="store_true",
        default=os.path.exists(BLINTDB_LOC),
        dest="use_blintdb",
        help=f"Use blintdb v2 for symbol resolution where supported. Defaults to true if the file exists at {BLINTDB_LOC}. Use environment variables: BLINTDB_IMAGE_URL, BLINTDB_HOME, and BLINTDB_REFRESH for customization.",
    )
    parser.add_argument(
        "--disassemble",
        action="store_true",
        default=False,
        dest="disassemble",
        help="Disassemble functions and store the instructions in the metadata. Requires blint extended group to be installed.",
    )
    parser.add_argument(
        "--export-callgraph-mermaid",
        action="store_true",
        default=False,
        dest="render_mermaid_callgraph",
        help="Export callgraph as Mermaid (.mmd) files and embed diagrams into blint-output.html. Effective when --disassemble is enabled.",
    )
    parser.add_argument(
        "--export-callgraph-graphml",
        action="store_true",
        default=False,
        dest="export_callgraph_graphml",
        help="Export callgraph as GraphML for external graph analysis tools. Effective when --disassemble is enabled.",
    )
    parser.add_argument(
        "--export-callgraph-gexf",
        action="store_true",
        default=False,
        dest="export_callgraph_gexf",
        help="Export callgraph as GEXF for Gephi and other graph tooling. Effective when --disassemble is enabled.",
    )
    parser.add_argument(
        "--callgraph-min-confidence",
        choices=["low", "medium", "high"],
        default="low",
        dest="callgraph_min_confidence",
        help="Filter exported callgraph edges/external links by confidence. Defaults to low (no filtering).",
    )
    parser.add_argument(
        "--custom-rules-dir",
        dest="custom_rules_dir",
        type=str,
        help="Path to a directory containing custom YAML rule files (.yml or .yaml). These will be loaded in addition to default rules.",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        default=False,
        dest="quiet_mode",
        help="Disable logging and progress bars.",
    )
    # sbom commmand
    subparsers = parser.add_subparsers(
        title="sub-commands",
        description="Additional sub-commands",
        dest="subcommand_name",
    )
    sbom_parser = subparsers.add_parser(
        "sbom", help="Command to generate SBOM for supported binaries."
    )
    sbom_parser.set_defaults(sbom_mode=True)
    sbom_parser.add_argument(
        "-i",
        "--src",
        dest="src_dir_image",
        action="extend",
        default=[],
        nargs="+",
        help="Source directories, container images or binary files. Defaults to current directory.",
    )
    sbom_parser.add_argument(
        "-o",
        "--output-file",
        dest="sbom_output",
        help="SBOM output file. Defaults to sbom-binary-postbuild.cdx.json in current directory.",
    )
    sbom_parser.add_argument(
        "--deep",
        action="store_true",
        default=False,
        dest="deep_mode",
        help="Enable deep mode to collect more used symbols and modules "
        "aggressively. Slow operation. When combined with --use-blintdb, disassembly is enabled automatically to use function-hash lookup.",
    )
    sbom_parser.add_argument(
        "--stdout",
        action="store_true",
        default=False,
        dest="stdout_mode",
        help="Print the SBOM to stdout instead of a file.",
    )
    sbom_parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        default=False,
        dest="quiet_mode",
        help="Disable logging and progress bars.",
    )
    sbom_parser.add_argument(
        "--exports-prefix",
        default=[],
        action="extend",
        nargs="+",
        dest="exports_prefix",
        help="prefixes for the exports to be included in the SBOM.",
    )
    sbom_parser.add_argument(
        "--bom-src",
        dest="src_dir_boms",
        action="extend",
        nargs="+",
        help="Directories containing pre-build and build BOMs. Use to improve the precision.",
    )
    sbom_parser.add_argument(
        "--use-blintdb",
        action="store_true",
        default=os.path.exists(BLINTDB_LOC),
        dest="use_blintdb",
        help=f"Use blintdb v2 for symbol and disassembly-hash resolution. Defaults to true if the file exists at {BLINTDB_LOC}. Use environment variables: BLINTDB_IMAGE_URL, BLINTDB_HOME, and BLINTDB_REFRESH for customization.",
    )
    callgraph_match_parser = subparsers.add_parser(
        "callgraph-match",
        help="Match a source callgraph against a binary callgraph.",
    )
    callgraph_match_parser.set_defaults(callgraph_match_mode=True)
    callgraph_match_parser.add_argument(
        "--source",
        dest="source_callgraph",
        required=True,
        help="Path to a source-analysis callgraph JSON file.",
    )
    callgraph_match_parser.add_argument(
        "--binary",
        dest="match_binary",
        help="Path to a binary to parse with disassembly. Used when "
        "--binary-metadata is not supplied.",
    )
    callgraph_match_parser.add_argument(
        "--binary-metadata",
        dest="match_binary_metadata",
        help="Path to a pre-generated blint *-metadata.json file.",
    )
    callgraph_match_parser.add_argument(
        "-o",
        "--output",
        dest="match_output",
        help="Write the full JSON match report to this path.",
    )
    callgraph_match_parser.add_argument(
        "--min-confidence",
        choices=["low", "medium", "high"],
        default="low",
        dest="match_min_confidence",
        help="Minimum confidence for matches listed in the report. Defaults to low.",
    )
    callgraph_match_parser.add_argument(
        "--algorithm",
        choices=_callgraph_algorithms(),
        default=_callgraph_default_algorithm(),
        dest="match_algorithm",
        help="Matching algorithm to use. Defaults to " f"{_callgraph_default_algorithm()}.",
    )
    callgraph_match_parser.add_argument(
        "--no-propagation",
        action="store_true",
        default=False,
        dest="match_no_propagation",
        help="Disable structural propagation and report only name-based anchors.",
    )
    callgraph_match_parser.add_argument(
        "--with-fingerprint",
        action="store_true",
        default=False,
        dest="match_with_fingerprint",
        help="Enable experimental Layer 2 structural fingerprint matching. Best "
        "suited to densely resolved callgraphs; may reduce precision on sparse ones.",
    )
    callgraph_match_parser.add_argument(
        "--min-votes",
        type=int,
        default=2,
        dest="match_min_votes",
        help="Layer 1: minimum agreeing matched neighbors to accept a propagated "
        "match. Defaults to 2.",
    )
    callgraph_match_parser.add_argument(
        "--margin",
        type=int,
        default=1,
        dest="match_margin",
        help="Layer 1: minimum vote lead over the runner-up. Defaults to 1.",
    )
    callgraph_match_parser.add_argument(
        "--max-iterations",
        type=int,
        default=6,
        dest="match_max_iterations",
        help="Maximum propagation/fingerprint rounds. Defaults to 6.",
    )
    callgraph_match_parser.add_argument(
        "--khop",
        type=int,
        default=2,
        dest="match_khop",
        help="Layer 2: hop radius for fingerprint context. Defaults to 2.",
    )
    callgraph_match_parser.add_argument(
        "--fp-min-shared",
        type=int,
        default=2,
        dest="match_fp_min_shared",
        help="Layer 2: minimum shared anchored neighbor names. Defaults to 2.",
    )
    callgraph_match_parser.add_argument(
        "--fp-min-score",
        type=float,
        default=0.34,
        dest="match_fp_min_score",
        help="Layer 2: minimum combined Jaccard score to accept. Defaults to 0.34.",
    )
    callgraph_match_parser.add_argument(
        "--fp-margin",
        type=float,
        default=0.1,
        dest="match_fp_margin",
        help="Layer 2: minimum Jaccard lead over the runner-up. Defaults to 0.1.",
    )
    callgraph_match_parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        default=False,
        dest="quiet_mode",
        help="Disable logging and progress bars.",
    )
    db_parser = subparsers.add_parser("db", help="Command to manage the pre-compiled database.")
    db_parser.set_defaults(db_mode=True)
    db_parser.add_argument(
        "--download",
        action="store_true",
        default=True,
        dest="download_mode",
        help=f"Download the pre-compiled database to the {BLINTDB_HOME} directory. Use the environment variable `BLINTDB_HOME` to override.",
    )
    db_parser.add_argument(
        "--image-url",
        dest="image_url",
        choices=[
            "ghcr.io/appthreat/blintdb-vcpkg:v2",
            "ghcr.io/appthreat/blintdb-vcpkg-arm64:v2",
            "ghcr.io/appthreat/blintdb-vcpkg-darwin-arm64:v2",
            "ghcr.io/appthreat/blintdb-vcpkg-musl:v2",
            "ghcr.io/appthreat/blintdb-meson:v2",
            "ghcr.io/appthreat/blintdb-meson-arm64:v2",
            "ghcr.io/appthreat/blintdb-meson-darwin-arm64:v2",
            "ghcr.io/appthreat/blintdb-meson-musl:v2",
        ],
        default=BLINTDB_IMAGE_URL,
        help=f"Blintdb image url. Defaults to {BLINTDB_IMAGE_URL}. The environment variable `BLINTDB_IMAGE_URL` is an alternative way to set this value.",
    )
    return parser


def parse_input(src):
    """Parses the input source.

    This function takes the input source as a list and parses it to extract the
    path. It returns the parsed path as a list.

    Args:
        src: A list containing the input source.

    Returns:
        list: A list containing the parsed path.
    """
    if isinstance(src, list):
        path = src[0]
        result = path.split("\n")
        result = [res for res in result if os.path.exists(res)]
        return result
    return [src]


def handle_args(args=None):
    """Handles the command-line arguments.

    This function parses the command-line arguments and returns a BlintOptions object

    Args:
        args: Optional pre-parsed argument namespace. Parsed fresh when omitted.

    Returns:
        BlintOptions: A class containing the parsed command-line arguments
    """
    if args is None:
        args = build_args()
    if not args.no_banner and args.subcommand_name != "sbom":
        print(BLINT_LOGO)
    if not args.src_dir_image:
        args.src_dir_image = [os.getcwd()]
    blint_options = BlintOptions(
        deep_mode=args.deep_mode,
        exports_prefix=args.exports_prefix,
        fuzzy=args.suggest_fuzzable,
        no_error=args.noerror,
        no_reviews=args.no_reviews,
        reports_dir=args.reports_dir,
        sbom_mode=args.sbom_mode,
        quiet_mode=args.quiet_mode,
        db_mode=args.db_mode,
        image_url=args.image_url if args.db_mode else None,
        sbom_output=args.sbom_output,
        src_dir_boms=args.src_dir_boms,
        src_dir_image=args.src_dir_image,
        stdout_mode=args.stdout_mode,
        use_blintdb=args.use_blintdb,
        disassemble=args.disassemble,
        render_mermaid_callgraph=args.render_mermaid_callgraph,
        export_callgraph_graphml=args.export_callgraph_graphml,
        export_callgraph_gexf=args.export_callgraph_gexf,
        callgraph_min_confidence=args.callgraph_min_confidence,
        custom_rules_dir=args.custom_rules_dir,
    )
    return blint_options


def run_callgraph_match_command(args):
    """Run the callgraph-match subcommand from parsed CLI arguments."""
    from blint.lib.callgraph.command import run_callgraph_match
    from blint.lib.callgraph.match import MatchOptions

    if args.quiet_mode:
        LOG.disabled = True
    options = MatchOptions(
        enable_propagation=not args.match_no_propagation,
        enable_fingerprint=args.match_with_fingerprint,
        min_votes=args.match_min_votes,
        margin=args.match_margin,
        max_iterations=args.match_max_iterations,
        khop=args.match_khop,
        fp_min_shared=args.match_fp_min_shared,
        fp_min_score=args.match_fp_min_score,
        fp_margin=args.match_fp_margin,
    )
    run_callgraph_match(
        source_callgraph=args.source_callgraph,
        binary=args.match_binary,
        binary_metadata=args.match_binary_metadata,
        output=args.match_output,
        min_confidence=args.match_min_confidence,
        options=options,
        algorithm=args.match_algorithm,
        quiet=args.quiet_mode,
    )


def main():
    """Main function of the blint tool"""
    args = build_args()
    if args.subcommand_name == "callgraph-match":
        run_callgraph_match_command(args)
        return
    blint_options = handle_args(args)
    if blint_options.quiet_mode:
        LOG.disabled = True
    blintdb_setup(blint_options)

    # SBOM command
    if blint_options.sbom_mode:
        run_sbom_mode(blint_options)
    elif blint_options.db_mode:
        return
    # Default case
    else:
        run_default_mode(blint_options)


if __name__ == "__main__":
    main()
