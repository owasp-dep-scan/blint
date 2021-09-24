#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import sys

from rich.panel import Panel

from blint.analysis import start


def build_args():
    """
    Constructs command line arguments for the vulndb tool
    """
    parser = argparse.ArgumentParser(
        description="Linting tool for binary files powered by lief."
    )
    parser.add_argument(
        "-i",
        "--src",
        dest="src_dir_image",
        help="Source directory or container image or binary file",
    )
    parser.add_argument(
        "-o",
        "--report_file",
        dest="report_file",
        help="Report filename with directory",
    )
    parser.add_argument(
        "--no-error",
        action="store_true",
        default=False,
        dest="noerror",
        help="Continue on error to prevent build from breaking",
    )
    return parser.parse_args()


def main():
    args = build_args()
    src_dir = args.src_dir_image
    if not src_dir:
        src_dir = os.getcwd()
    reports_base_dir = os.path.dirname(src_dir)
    areport_file = (
        args.report_file
        if args.report_file
        else os.path.join(reports_base_dir, "reports", "blint.json")
    )
    reports_dir = os.path.dirname(areport_file)
    # Create reports directory
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
    findings = start(args, src_dir, areport_file)
    print(findings)


if __name__ == "__main__":
    main()
