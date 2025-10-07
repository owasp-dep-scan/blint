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
        help=f"Use blintdb for symbol resolution. Defaults to true if the file exists at {BLINTDB_LOC}. Use environment variables: BLINTDB_IMAGE_URL, BLINTDB_HOME, and BLINTDB_REFRESH for customization.",
    )
    parser.add_argument(
        "--disassemble",
        action="store_true",
        default=False,
        dest="disassemble",
        help="Disassemble functions and store the instructions in the metadata. Requires blint extended group to be installed.",
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
        default=[os.getcwd()],
        nargs="+",
        help="Source directories, container images or binary files. Defaults to current directory.",
    )
    sbom_parser.add_argument(
        "-o",
        "--output-file",
        dest="sbom_output",
        help="SBOM output file. Defaults to bom-post-build.cdx.json in current directory.",
    )
    sbom_parser.add_argument(
        "--deep",
        action="store_true",
        default=False,
        dest="deep_mode",
        help="Enable deep mode to collect more used symbols and modules "
             "aggressively. Slow operation.",
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
    db_parser = subparsers.add_parser(
        "db", help="Command to manage the pre-compiled database."
    )
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
        choices=["ghcr.io/appthreat/blintdb-vcpkg:v1",
                 "ghcr.io/appthreat/blintdb-vcpkg-arm64:v1",
                 "ghcr.io/appthreat/blintdb-vcpkg-darwin-arm64:v1",
                 "ghcr.io/appthreat/blintdb-vcpkg-musl:v1",
                 "ghcr.io/appthreat/blintdb-meson:v1",
                 "ghcr.io/appthreat/blintdb-meson-arm64:v1",
                 "ghcr.io/appthreat/blintdb-meson-darwin-arm64:v1",
                 "ghcr.io/appthreat/blintdb-meson-musl:v1",
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


def handle_args():
    """Handles the command-line arguments.

    This function parses the command-line arguments and returns a BlintOptions object

    Returns:
        BlintOptions: A class containing the parsed command-line arguments
    """
    args = build_args()
    if not args.no_banner and args.subcommand_name != "sbom":
        print(BLINT_LOGO)
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
        custom_rules_dir=args.custom_rules_dir,
    )
    return blint_options


def main():
    """Main function of the blint tool"""
    blint_options = handle_args()
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
