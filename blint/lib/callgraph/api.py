# -*- coding: utf-8 -*-
"""
Library entry point for callgraph matching.

This is the stable, typed API for integrators who want to match a binary against
a source callgraph without driving the command line. It accepts either a
precomputed source callgraph JSON or a source directory (which it analyzes with
rusi), and either a binary to disassemble or a precomputed metadata file, and
returns a :class:`~blint.lib.callgraph.match.MatchReport`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional, Union

from blint.lib.binary import parse
from blint.lib.callgraph.algorithms import DEFAULT_ALGORITHM, get_algorithm
from blint.lib.callgraph.match import MatchOptions, MatchReport, build_report
from blint.lib.callgraph.model import load_binary_callgraph, load_source_callgraph
from blint.lib.callgraph.rusi import run_rusi_callgraph


# Source-directory analyzers keyed by language. rusi handles Rust. Other
# languages can register their own analyzer here without changing the matcher.
_SOURCE_ANALYZERS = {"rust": run_rusi_callgraph}


def _resolve_source_callgraph(
    source_callgraph: Optional[Union[str, Path, dict]],
    source_dir: Optional[Union[str, Path]],
    rusi_command: Optional[str],
    language: str,
) -> Union[str, Path, dict]:
    """Return a source callgraph payload from a file, a dict, or a source dir.

    A source directory is analyzed only for languages with a registered
    analyzer. rusi, the Rust analyzer, is invoked only when ``language`` is
    ``"rust"``.
    """
    if source_callgraph is not None:
        return source_callgraph
    if source_dir is not None:
        analyzer = _SOURCE_ANALYZERS.get((language or "").lower())
        if analyzer is None:
            supported = ", ".join(sorted(_SOURCE_ANALYZERS))
            raise ValueError(
                f"Source-directory analysis is not supported for language "
                f"'{language}'. Supported: {supported}. Pass a precomputed "
                "source callgraph with source_callgraph instead."
            )
        return analyzer(source_dir, rusi_command=rusi_command)
    raise ValueError("Pass one of source_callgraph or source_dir")


def _resolve_binary_metadata(
    binary: Optional[Union[str, Path]],
    binary_metadata: Optional[Union[str, Path, dict]],
) -> dict:
    """Return binary metadata from a metadata file/dict or by parsing a binary."""
    if binary_metadata is not None:
        if isinstance(binary_metadata, dict):
            return binary_metadata
        return json.loads(Path(binary_metadata).read_text(encoding="utf-8"))
    if binary is not None:
        return parse(str(binary), disassemble=True)
    raise ValueError("Pass one of binary or binary_metadata")


def match_files(
    *,
    source_callgraph: Optional[Union[str, Path, dict]] = None,
    source_dir: Optional[Union[str, Path]] = None,
    binary: Optional[Union[str, Path]] = None,
    binary_metadata: Optional[Union[str, Path, dict]] = None,
    options: Optional[MatchOptions] = None,
    algorithm: str = DEFAULT_ALGORITHM,
    min_confidence: str = "low",
    language: str = "rust",
    rusi_command: Optional[str] = None,
) -> MatchReport:
    """Match a binary against a source callgraph and return a typed report.

    Exactly one source input and one binary input must be supplied.

    Args:
        source_callgraph: Path to a source callgraph JSON file, or its parsed
            dict.
        source_dir: Path to a source tree to analyze. Used when
            ``source_callgraph`` is not given. Only analyzed for languages with
            a registered analyzer (rusi for Rust).
        binary: Path to a binary to parse with disassembly. Used when
            ``binary_metadata`` is not given.
        binary_metadata: Path to a blint ``*-metadata.json`` file, or its parsed
            dict.
        options: Matching parameters. Defaults to the balanced profile.
        algorithm: Matching algorithm name (for example ``"layered"`` or
            ``"anchors"``).
        min_confidence: Minimum confidence for matches listed in the report.
        language: Source language. Selects the source-directory analyzer; rusi
            runs only for ``"rust"``.
        rusi_command: Base rusi command used when ``source_dir`` is given and
            ``language`` is ``"rust"``.

    Returns:
        A :class:`MatchReport`.
    """
    source_payload = _resolve_source_callgraph(
        source_callgraph, source_dir, rusi_command, language
    )
    metadata = _resolve_binary_metadata(binary, binary_metadata)

    source_graph = load_source_callgraph(source_payload)
    binary_graph = load_binary_callgraph(metadata)

    matcher = get_algorithm(algorithm)
    result = matcher.match(source_graph, binary_graph, options)
    report = build_report(
        source_graph,
        binary_graph,
        result,
        min_confidence=min_confidence,
        binary_file=metadata.get("file_path")
        or (str(binary) if binary else None)
        or (str(binary_metadata) if isinstance(binary_metadata, (str, Path)) else None),
    )
    report["algorithm"] = matcher.name
    return MatchReport(algorithm=matcher.name, report=report, result=result)
