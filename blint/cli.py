#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import logging
import os
import sys

from blint.analysis import AnalysisRunner, report
from blint.logger import LOG
from blint.sbom import generate
from blint.utils import gen_file_list

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
    parser = argparse.ArgumentParser(
        prog="blint",
        description="Binary linter and SBOM generator.",
    )
    parser.add_argument(
        "-i",
        "--src",
        dest="src_dir_image",
        action="extend",
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
    # sbom commmand
    subparsers = parser.add_subparsers(
        title="sub-commands",
        description="Additional sub-commands",
        dest="subcommand_name",
    )
    sbom_parser = subparsers.add_parser(
        "sbom", help="Command to generate SBOM for supported binaries."
    )
    sbom_parser.add_argument(
        "-i",
        "--src",
        dest="src_dir_image",
        action="extend",
        nargs="+",
        help="Source directories, container images or binary files. Defaults "
             "to current directory.",
    )
    sbom_parser.add_argument(
        "-o",
        "--output-file",
        dest="sbom_output",
        help="SBOM output file. Defaults to bom.json in current directory.",
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
    return parser.parse_args()


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

    This function parses the command-line arguments and returns the parsed
    arguments, reports directory, and source directory.

    Returns:
        tuple: A tuple containing the parsed arguments, reports directory, and
               source directory.
    """
    args = build_args()
    if not args.no_banner and args.subcommand_name != "sbom":
        print(BLINT_LOGO)
    if not args.src_dir_image:
        args.src_dir_image = [os.getcwd()]
    if not os.getenv("CI"):
        src_dirs = args.src_dir_image
    else:
        src_dirs = parse_input(args.src_dir_image)

    # Create reports directory
    reports_dir = args.reports_dir

    for src in src_dirs:
        if not os.path.exists(src):
            LOG.error(f"{src} is an invalid file or directory!")
            sys.exit(1)
    return args, reports_dir, src_dirs


def main():
    """Main function of the blint tool"""
    args, reports_dir, src_dirs = handle_args()

    # SBOM command
    if args.subcommand_name == "sbom":
        if args.stdout_mode:
            sbom_output = sys.stdout
            LOG.setLevel(logging.ERROR)
        else:
            if args.sbom_output:
                sbom_output = args.sbom_output
            else:
                sbom_output = os.path.join(os.getcwd(), "bom.json")
            sbom_output_dir = os.path.dirname(sbom_output)
            if sbom_output_dir and not os.path.exists(sbom_output_dir):
                os.makedirs(sbom_output_dir)
        generate(src_dirs, sbom_output, args.deep_mode)
    # Default case
    else:
        if reports_dir and not os.path.exists(reports_dir):
            os.makedirs(reports_dir)
        files = gen_file_list(src_dirs)
        analyzer = AnalysisRunner()
        findings, reviews, fuzzables = analyzer.start(
            files, reports_dir, args.no_reviews, args.suggest_fuzzable
        )
        report(src_dirs, reports_dir, findings, reviews, files, fuzzables)

        if os.getenv("CI") and not args.noerror:
            for f in findings:
                if f['severity'] == 'critical':
                    sys.exit(1)


if __name__ == "__main__":
    main()
