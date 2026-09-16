#!/usr/bin/env python3
"""Measure pointer materialisation (P4.9) on real binaries.

For each binary this parses with disassembly enabled and reports the
``call_site_arguments`` block's numbers plus the capability findings the
block's rule produces:

- ``entries``            recovered (callee, argument, value) triples
- ``strings_resolved``   entries whose value points at a real string
- ``capability_findings`` evidence items from the capability rule
- ``adrp_sites``         adrp / rip-relative lea occurrences in the listings
- ``distinct_strings``   the distinct strings, so a sample can be verified
                         against llvm-objdump (the precision gate)

Usage:
    python tests/scripts/measure_pointer_materialisation.py BIN [BIN ...]
        [--json OUT] [--sample N]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from blint.lib.binary import parse

DEFAULT_BINARIES = [
    "/bin/ls",
    "/usr/bin/curl",
    "/usr/bin/ssh",
    "/usr/bin/openssl",
    "/bin/zsh",
    "/opt/homebrew/bin/x264",
]


def run(path: str) -> dict:
    metadata = parse(path, disassemble=True)
    coverage = metadata.get("call_site_arguments_coverage") or {}
    entries = metadata.get("call_site_arguments") or []
    resolved = [e for e in entries if e.get("string")]
    from blint.lib.binary_reviews import _evaluate_callsite_constant_arguments

    evidence = _evaluate_callsite_constant_arguments({"call_site_arguments": entries})
    adrp_sites = 0
    lea_rip_sites = 0
    for func in (metadata.get("disassembled_functions") or {}).values():
        text = func.get("assembly") or ""
        adrp_sites += text.count("\nadrp ") + text.startswith("adrp ")
        lea_rip_sites += text.count("[rip ")
    return {
        "binary": path,
        "arch": (metadata.get("llvm_target_tuple") or "")[:40],
        "functions_disassembled": len(metadata.get("disassembled_functions") or {}),
        "adrp_sites": adrp_sites,
        "lea_rip_sites": lea_rip_sites,
        "callsite_entries": coverage.get("entries"),
        "strings_resolved": len(resolved),
        "capability_findings": len(evidence),
        "distinct_strings": sorted({e["string"] for e in resolved}),
        "string_examples": [
            {
                "string": e["string"],
                "value": e["value"],
                "callee": e["callee"],
                "argument": e["argument"],
                "function": e["functions"][0] if e.get("functions") else None,
                "instruction": (e.get("example") or {}).get("instruction"),
            }
            for e in resolved[:200]
        ],
        "coverage": coverage,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("binaries", nargs="*", default=DEFAULT_BINARIES)
    parser.add_argument("--json", dest="json_out", default=None)
    args = parser.parse_args()
    binaries = args.binaries or DEFAULT_BINARIES
    results = []
    for path in binaries:
        print(f"== {path}", flush=True)
        try:
            result = run(path)
        except Exception as exc:
            print(f"   FAILED: {exc}", flush=True)
            result = {"binary": path, "error": str(exc)}
        print(
            f"   arch={result.get('arch')} disassembled={result.get('functions_disassembled')}"
            f" adrp={result.get('adrp_sites')} lea_rip={result.get('lea_rip_sites')}"
            f" entries={result.get('callsite_entries')}"
            f" strings={result.get('strings_resolved')}"
            f" findings={result.get('capability_findings')}",
            flush=True,
        )
        results.append(result)
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(results, indent=2))
        print(f"wrote {args.json_out}")
    totals = {
        k: sum(r.get(k) or 0 for r in results)
        for k in (
            "adrp_sites",
            "lea_rip_sites",
            "callsite_entries",
            "strings_resolved",
            "capability_findings",
        )
    }
    print("TOTAL", json.dumps(totals))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
