# -*- coding: utf-8 -*-
"""Command orchestration and console rendering for ``blint callgraph-match``."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from rich.box import ROUNDED
from rich.panel import Panel
from rich.table import Table

from blint.lib.callgraph.algorithms import DEFAULT_ALGORITHM
from blint.lib.callgraph.api import match_files
from blint.lib.callgraph.match import MatchOptions
from blint.logger import LOG, console

_CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}

_LAYER_EXPLANATION = {
    "anchor": "matched by exact function name (demangled and canonicalized)",
    "propagation": "matched by call-neighbor agreement (structural)",
    "fingerprint": "matched by wider structural context (experimental)",
}


def _verdict(summary: dict) -> str:
    """Return a one-line plain-language interpretation of the match result."""
    anchors = summary["anchors"]
    matched = summary["binary_matched"]
    identified = summary["source_functions_identified"]
    if matched == 0:
        return (
            "No functions in this binary could be matched to the source. The "
            "binary is either unrelated to this source, fully stripped with no "
            "recoverable structure, or built very differently."
        )
    if anchors > 0:
        return (
            f"{anchors} functions matched the source by name with high "
            f"confidence, identifying {identified} distinct source functions. "
            "This binary is consistent with the provided source."
        )
    return (
        f"{matched} functions were matched by structure only (no surviving "
        "names). Treat these as candidate matches rather than proof."
    )


def _evidence_rows(matches: list, limit: int) -> list:
    """Return a representative, diverse set of matches to show as evidence.

    Each matching method (anchor, propagation, fingerprint) is sampled so the
    output illustrates every kind of evidence that was produced, rather than a
    long run of near-identical name anchors.
    """

    def _strength(match):
        return (_CONFIDENCE_RANK.get(match["confidence"], 0), match["score"])

    by_layer: dict[str, list] = {}
    for match in matches:
        by_layer.setdefault(match["layer"], []).append(match)
    for layer_matches in by_layer.values():
        layer_matches.sort(key=_strength, reverse=True)

    rows: list = []
    layers = [layer for layer in ("anchor", "propagation", "fingerprint") if layer in by_layer]
    if layers:
        per_layer = max(1, limit // len(layers))
        for layer in layers:
            rows.extend(by_layer[layer][:per_layer])
    # Fill any remaining slots with the next strongest matches overall.
    if len(rows) < limit:
        seen = {id(row) for row in rows}
        remainder = sorted((m for m in matches if id(m) not in seen), key=_strength, reverse=True)
        rows.extend(remainder[: limit - len(rows)])
    return sorted(rows, key=_strength, reverse=True)


def render_match_report(report: dict, *, evidence_limit: int = 12) -> None:
    """Print a human-readable summary of a callgraph match report to the console.

    The summary explains how many functions were matched, with what confidence
    and by which method, shows representative matches as evidence, and states the
    caveats that apply to the result.
    """
    summary = report["summary"]
    binary_file = report.get("binary", {}).get("file") or "unknown"

    console.print(
        Panel(
            f"Binary: [bold]{binary_file}[/bold]\n"
            f"Algorithm: [bold]{report.get('algorithm', 'layered')}[/bold]\n\n"
            f"{_verdict(summary)}",
            title="blint callgraph match",
            box=ROUNDED,
        )
    )

    overview = Table(box=ROUNDED, show_header=False, title="Overview")
    overview.add_column("Metric", style="cyan", no_wrap=True)
    overview.add_column("Value")
    overview.add_row("Binary functions", str(summary["binary_nodes"]))
    overview.add_row(
        "Source functions in callgraph", str(report.get("source", {}).get("nodes", 0))
    )
    overview.add_row(
        "Matched functions",
        f"{summary['binary_matched']} ({summary['coverage'] * 100:.1f}% of binary)",
    )
    overview.add_row(
        "Distinct source functions identified", str(summary["source_functions_identified"])
    )
    overview.add_row("Unmatched binary functions", str(summary["unmatched_binary"]))
    console.print(overview)

    breakdown = Table(box=ROUNDED, title="How functions were matched")
    breakdown.add_column("Method", style="cyan")
    breakdown.add_column("Count", justify="right")
    breakdown.add_column("Meaning")
    for layer in ("anchor", "propagation", "fingerprint"):
        count = summary["by_layer"].get(layer, 0)
        if count:
            breakdown.add_row(layer, str(count), _LAYER_EXPLANATION[layer])
    confidence = summary["by_confidence"]
    breakdown.add_row(
        "confidence",
        "",
        f"high={confidence.get('high', 0)} medium={confidence.get('medium', 0)} "
        f"low={confidence.get('low', 0)}",
    )
    console.print(breakdown)

    rows = _evidence_rows(report.get("matches", []), evidence_limit)
    if rows:
        evidence = Table(box=ROUNDED, title=f"Evidence (top {len(rows)} matches)")
        evidence.add_column("Address", style="magenta", no_wrap=True)
        evidence.add_column("Source function")
        evidence.add_column("Confidence", no_wrap=True)
        evidence.add_column("How", no_wrap=True)
        for match in rows:
            evidence.add_row(
                str(match.get("address") or "-"),
                match["source"],
                match["confidence"],
                match["layer"],
            )
        console.print(evidence)

    caveat = (
        "Unmatched functions are expected: they include C runtime startup code, "
        "statically linked standard library and dependency code not present in "
        "the source callgraph, compiler-generated helpers, and functions reached "
        "only through indirect or virtual calls that cannot be resolved "
        "statically. Structural (propagation and fingerprint) matches are lower "
        "confidence than name anchors and should be reviewed before being relied "
        "upon."
    )
    console.print(Panel(caveat, title="How to read this", box=ROUNDED))


def run_callgraph_match(
    source_callgraph: Optional[str],
    binary: Optional[str],
    binary_metadata: Optional[str],
    output: Optional[str],
    min_confidence: str = "low",
    options: Optional[MatchOptions] = None,
    algorithm: str = DEFAULT_ALGORITHM,
    quiet: bool = False,
    source_dir: Optional[str] = None,
    language: str = "rust",
    rusi_command: Optional[str] = None,
) -> dict:
    """Match a source callgraph against a binary and emit a report.

    Args:
        source_callgraph: Path to a source-analysis callgraph JSON file.
        binary: Path to a binary to parse with disassembly. Used when
            ``binary_metadata`` is not supplied.
        binary_metadata: Path to a pre-generated blint ``*-metadata.json``.
        output: Optional path to write the full JSON report to.
        min_confidence: Minimum confidence for matches listed in the report.
        options: Matching parameters.
        algorithm: Name of the matching algorithm to run.
        quiet: Suppress the human-readable console summary.
        source_dir: Path to a source tree to analyze instead of a precomputed
            callgraph. Analyzed only for languages with a registered analyzer.
        language: Source language; selects the source-directory analyzer (rusi
            runs only for ``"rust"``).
        rusi_command: Base rusi command used when ``source_dir`` is given.

    Returns:
        The match report as a ``dict``.
    """
    match_report = match_files(
        source_callgraph=source_callgraph,
        source_dir=source_dir,
        binary=binary,
        binary_metadata=binary_metadata,
        options=options,
        algorithm=algorithm,
        min_confidence=min_confidence,
        language=language,
        rusi_command=rusi_command,
    )
    report = match_report.to_dict()

    if not quiet:
        render_match_report(report)

    if output:
        out_path = Path(output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        LOG.info("Wrote callgraph match report to %s", out_path)

    return report
