#!/usr/bin/env python3
"""A2/B2 — R4 gate: blint's 16 KB verdict vs zipalign and check_elf_alignment.sh.

For every input APK/AAB/xapk this runs three tools over the same file in
the same run and compares them per (abi, library):

- blint: ``scan_android_native`` -> ``page_size_16k`` per-ABI verdict.
- ``check_elf_alignment.sh`` (Google's script, vendored under
  ~/sandbox/android-corpus/tools; needs NDK ``objdump``/``llvm-objdump``
  and the ``file`` utility on PATH): per-.so ELF verdict ALIGNED/UNALIGNED
  with the align value it read.
- ``zipalign -v -c -P 16 4`` (build-tools): per-entry zip-alignment
  verdict for stored ``lib/`` members.

Exempt 32-bit ABIs are never flagged by blint (rule 35) even when the
script reports them UNALIGNED — the script itself notes that "only
arm64-v8a/x86_64 libs need to be aligned"; those rows are reported as
exempt, not as disagreements. Every real disagreement is printed with
the words each tool emitted and fails the run.

Usage:
  poetry run python tests/scripts/android/verify_16k_verdict.py <app.apk>... \
      [--check-script PATH] [--zipalign PATH]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from blint.lib.android_native import scan_android_native

LINE_RE = re.compile(r"(ALIGNED|UNALIGNED)\s*\(?(\S*)\)?\s*$")
ZIPALIGN_ENTRY_RE = re.compile(
    r"^\s+\d+\s+(lib/[^ ]+\.so)\s+\((OK|BAD[^)]*)\)"
)


def run_script(app: str, script: str, env: dict) -> dict[str, tuple[str, str]]:
    """check_elf_alignment.sh -> {lib name: (verdict, words)}."""
    proc = subprocess.run([script, app], capture_output=True, text=True, env=env)
    results = {}
    for line in proc.stdout.splitlines():
        if match := LINE_RE.search(line):
            name = os.path.basename(line.split(":", 1)[0].strip())
            results[name] = (match.group(1), match.group(0))
    return results


def run_zipalign(app: str, zipalign: str) -> dict[str, tuple[bool, str]]:
    """zipalign -v -c -P 16 4 -> {entry: (16k_ok, words)} for lib/*.so."""
    proc = subprocess.run(
        [zipalign, "-v", "-c", "-P", "16", "4", app], capture_output=True, text=True
    )
    results = {}
    for line in proc.stdout.splitlines():
        if match := ZIPALIGN_ENTRY_RE.match(line):
            entry, words = match.group(1), match.group(2)
            ok = words.startswith("OK")
            if "- compressed" in words:
                # Deflated entries are not page-aligned in the zip and
                # zipalign does not require them to be.
                continue
            results[os.path.basename(entry)] = (ok, f"{entry} ({words})")
    return results


def verify(app: str, script: str, zipalign: str, env: dict) -> tuple[bool, dict]:
    model = scan_android_native(app)
    verdict = model["page_size_16k"]
    script_rows = run_script(app, script, env)
    zipalign_rows = run_zipalign(app, zipalign)
    report = {"app": os.path.basename(app), "summary": verdict["summary"],
              "comparisons": [], "disagreements": []}
    ok = True
    seen = set()
    for abi, abi_entry in verdict["per_abi"].items():
        for name, rec in abi_entry["libraries"].items():
            seen.add(name)
            script_verdict = script_rows.get(name, (None, "not reported by script"))
            script_aligned = script_verdict[0] == "ALIGNED"
            for loc in rec["locations"]:
                if loc["zip_16k"] is None:
                    continue
                zip_row = zipalign_rows.get(loc["entry"].split("/")[-1])
                if zip_row is None:
                    zip_ok, words = None, "no zipalign row"
                else:
                    zip_ok, words = zip_row
                entry_ok = (loc["zip_16k"] == zip_ok) or zip_ok is None
                if not entry_ok:
                    ok = False
                    report["disagreements"].append(
                        f"{loc['entry']}: blint zip_16k={loc['zip_16k']} vs zipalign '{words}'"
                    )
            blint_aligned = rec["elf_16k"] is not False
            if script_verdict[0] is not None and blint_aligned != script_aligned:
                ok = False
                report["disagreements"].append(
                    f"{abi}/{name}: blint elf_16k={rec['elf_16k']} vs script "
                    f"'{script_verdict[1]}'"
                )
            report["comparisons"].append(
                {"abi": abi, "lib": name, "blint_elf": rec["elf_16k"],
                 "script": script_verdict[0], "align_words": script_verdict[1],
                 "reasons": rec["reasons"]}
            )
    # Script verdicts on libs blint never judged (assets, 32-bit) are
    # reported, not compared: 32-bit ABIs are exempt by design.
    for name, (verdict_word, words) in script_rows.items():
        if name not in seen:
            report["comparisons"].append(
                {"abi": "(not judged: exempt or asset)", "lib": name,
                 "blint_elf": None, "script": verdict_word,
                 "align_words": words, "reasons": []}
            )
    return ok, report


def default_script() -> str:
    return os.path.expanduser(
        "~/sandbox/android-corpus/tools/check_elf_alignment.sh"
    )


def default_zipalign() -> str:
    sdk = os.path.expanduser("~/Android/sdk/build-tools")
    if os.path.isdir(sdk):
        latest = max(os.listdir(sdk))
        return os.path.join(sdk, latest, "zipalign")
    return "zipalign"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("apps", nargs="+", help="APK files")
    parser.add_argument("--check-script", default=default_script(),
                        help="path to check_elf_alignment.sh")
    parser.add_argument("--zipalign", default=default_zipalign())
    parser.add_argument("--json", dest="json_path")
    args = parser.parse_args(argv)
    env = dict(os.environ)
    ndk_root = Path.home() / "Android/sdk/ndk"
    if ndk_root.is_dir():
        for ndk in sorted(ndk_root.iterdir(), reverse=True):
            candidate = ndk / "toolchains/llvm/prebuilt/darwin-x86_64/bin"
            if candidate.is_dir():
                env["PATH"] = f"{candidate}:{env['PATH']}"
                break
    all_ok = True
    reports = []
    for app in args.apps:
        ok, report = verify(app, args.check_script, args.zipalign, env)
        reports.append(report)
        print(f"== {report['app']}: {report['summary']}")
        for disagreement in report["disagreements"]:
            print(f"  DISAGREE {disagreement}")
        if not ok:
            all_ok = False
    if args.json_path:
        Path(args.json_path).write_text(json.dumps(reports, indent=1))
    return 0 if all_ok else 2


if __name__ == "__main__":
    sys.exit(main())
