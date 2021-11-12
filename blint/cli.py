#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os

from blint.analysis import report, start

blint_logo = """
██████╗ ██╗     ██╗███╗   ██╗████████╗
██╔══██╗██║     ██║████╗  ██║╚══██╔══╝
██████╔╝██║     ██║██╔██╗ ██║   ██║
██╔══██╗██║     ██║██║╚██╗██║   ██║
██████╔╝███████╗██║██║ ╚████║   ██║
╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝
"""


def build_args():
    """
    Constructs command line arguments for the vulndb tool
    """
    parser = argparse.ArgumentParser(
        prog="blint",
        description="Linting tool for binary files powered by lief.",
    )
    parser.add_argument(
        "-i",
        "--src",
        dest="src_dir_image",
        help="Source directory or container image or binary file. Defaults to current directory.",
    )
    parser.add_argument(
        "-o",
        "--reports",
        dest="reports_dir",
        help="Reports directory. Defaults to reports.",
    )
    parser.add_argument(
        "--no-error",
        action="store_true",
        default=False,
        dest="noerror",
        help="Continue on error to prevent build from breaking",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        default=False,
        dest="no_banner",
        help="Do not display banner",
    )
    parser.add_argument(
        "--no-reviews",
        action="store_true",
        default=False,
        dest="no_reviews",
        help="Do not perform method reviews",
    )
    return parser.parse_args()


def main():
    args = build_args()
    if not args.no_banner:
        print(blint_logo)
    src_dir = args.src_dir_image
    if not src_dir:
        src_dir = os.getcwd()
        reports_base_dir = src_dir
    else:
        reports_base_dir = os.path.dirname(src_dir)
    reports_dir = (
        args.reports_dir
        if args.reports_dir
        else os.path.join(reports_base_dir, "reports")
    )
    if not os.path.exists(src_dir):
        print(f"{src_dir} is an invalid file or directory!")
        return
    # Create reports directory
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
    findings, reviews = start(args, src_dir, reports_dir)
    report(args, src_dir, reports_dir, findings, reviews)


if __name__ == "__main__":
    main()
