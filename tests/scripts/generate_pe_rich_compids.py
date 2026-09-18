#!/usr/bin/env python3
"""Regenerate blint/data/pe_rich_compids.yml from the public comp.id table.

The rich header's comp.id records (product_id, build_number) identify the
exact Microsoft tool that produced each object group. The mapping is public
data that changes slowly; this script converts the community-maintained table
into blint's YAML so the runtime never needs the raw file:

  source: https://github.com/dishather/richprint/blob/master/comp_id.txt
  (originally compiled by M. H. from the @Comp.ID studies; the same table is
  adapted by mirar for the 010 Editor EXE.bt template and by the RichHeader
  Research group's RichPE tooling)

Usage:
    curl -sL https://raw.githubusercontent.com/dishather/richprint/master/comp_id.txt \\
        -o /tmp/comp_id.txt
    .venv/bin/python tests/scripts/generate_pe_rich_compids.py /tmp/comp_id.txt

Two tables are emitted:
- ``product_ids``: 16-bit product id -> tool token (C, C++, LNK, RES, ...),
  for a prodid-only fallback when the exact pair is unknown.
- ``comp_ids``: full 32-bit comp.id -> {tool, label}. The 32-bit key is the
  only safe join: ancient build numbers (50727 spans VS2005 and VS2012 rows)
  are reused across releases, and the source table keys on the full value.
"""

import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

BRACKET_RE = re.compile(r"^([0-9a-fA-F]{8})\s+\[([^\]]+)\]\s*(.*)$")
PRODID_RE = re.compile(r"^#?([0-9a-fA-F]{4})\s+\[([^\]]+)\]\s*(.*)$")
STAR_RE = re.compile(r"\(\*\)\s*$")

# Bracket marks that mean "no product recorded" rather than a tool.
NO_TOOL = {"---"}


def normalize_tool(mark: str) -> str:
    """``[ C ]`` -> ``C``; ``[C++]`` -> ``C++``."""
    return re.sub(r"\s+", "", mark.strip())


def main() -> None:
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    src, dst = Path(sys.argv[1]), Path(sys.argv[2])
    lines = src.read_text(encoding="utf-8", errors="replace").splitlines()

    prodid_tools: dict[int, Counter] = defaultdict(Counter)
    comp_id_rows: dict[int, tuple[str, str]] = {}
    skipped = []
    for line in lines:
        line = line.rstrip()
        if not line or line.startswith("# Format"):
            continue
        match = BRACKET_RE.match(line)
        if match:
            comp_id, mark, rest = match.groups()
            comp_id = int(comp_id, 16)
            tool = normalize_tool(mark)
            label = STAR_RE.sub("", rest).strip()
            prodid = comp_id >> 16
            if tool not in NO_TOOL:
                prodid_tools[prodid][tool] += 1
            if prodid and label:
                comp_id_rows[comp_id] = (tool if tool not in NO_TOOL else "---", label)
            continue
        match = PRODID_RE.match(line)
        if match and not BRACKET_RE.match(line):
            prodid, mark, _rest = match.groups()
            tool = normalize_tool(mark)
            if tool not in NO_TOOL:
                prodid_tools[int(prodid, 16)][tool] += 1
            continue
        if line.startswith("#"):
            continue
        skipped.append(line)

    out = ["# blint's rich header comp.id tables (PE lane W1.1, plan 01/A.4).",
           "#",
           "# Source: https://github.com/dishather/richprint/blob/master/comp_id.txt",
           "# (the community-maintained @Comp.ID table; the same data adapted by mirar's",
           "# EXE.bt 010 Editor template and by the RichHeaderResearch RichPE tooling).",
           "# Regenerate with tests/scripts/generate_pe_rich_compids.py after replacing",
           "# the source file.",
           "#",
           "# comp.id layout: (product_id << 16) | build_number. ``comp_ids`` is keyed",
           "# by the full 32-bit value because ancient build numbers are reused across",
           "# releases; ``product_ids`` names the tool when only the product id is",
           "# known. Values are fixed by the on-disk records, so they cannot drift",
           "# like a dependency's rendered enums.",
           "",
           "product_ids:"]
    for prodid in sorted(prodid_tools):
        tool, _count = prodid_tools[prodid].most_common(1)[0]
        out.append(f"  0x{prodid:04X}: \"{tool}\"")
    out += ["", "comp_ids:"]
    for comp_id in sorted(comp_id_rows):
        tool, label = comp_id_rows[comp_id]
        out.append(f"  0x{comp_id:08X}: \"{tool}|{label}\"")
    dst.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"wrote {dst}: {len(prodid_tools)} product ids, {len(comp_id_rows)} comp.id rows; "
          f"{len(skipped)} unparsed rows")


if __name__ == "__main__":
    main()
