# -*- coding: utf-8 -*-
"""
Pluggable callgraph matching algorithms.

The matcher is intentionally split from the algorithm that drives it so that new
strategies can be added and selected by name without changing the loaders, the
report format, or the CLI. blint currently ships:

* ``layered`` - canonical-name anchors, structural propagation, and optional
  k-hop fingerprinting. The general-purpose default.
* ``anchors`` - canonical-name equality only. Fast and high precision; useful
  for unstripped identification and as a ground-truth baseline.

Algorithms operate on the language-agnostic :class:`CallGraph` model, so while
the first inputs are Rust binaries and rusi source graphs, the same algorithms
apply to any language whose names canonicalize and whose callgraphs load into
the shared model. New strategies (for example pure structural fingerprinting for
fully stripped binaries) register here and become available to the CLI
automatically.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Callable, Optional

from blint.lib.callgraph.match import MatchOptions, MatchResult, match_callgraphs
from blint.lib.callgraph.model import CallGraph


class CallgraphMatcher:
    """Base class for a named callgraph matching algorithm."""

    name: str = ""
    description: str = ""

    def match(
        self,
        source: CallGraph,
        binary: CallGraph,
        options: Optional[MatchOptions] = None,
    ) -> MatchResult:
        """Match ``binary`` against ``source`` and return the mapping."""
        raise NotImplementedError


class LayeredMatcher(CallgraphMatcher):
    """Anchors, structural propagation, and optional k-hop fingerprinting."""

    name = "layered"
    description = (
        "Canonical-name anchors plus structural propagation and optional "
        "fingerprinting. General-purpose default."
    )

    def match(self, source, binary, options=None):
        return match_callgraphs(source, binary, options)


class AnchorMatcher(CallgraphMatcher):
    """Canonical-name equality only (Layer 0)."""

    name = "anchors"
    description = (
        "Canonical-name equality only. Highest precision; recovers no stripped "
        "functions. Useful for unstripped identification and as a baseline."
    )

    def match(self, source, binary, options=None):
        options = options or MatchOptions()
        anchored = replace(options, enable_propagation=False, enable_fingerprint=False)
        return match_callgraphs(source, binary, anchored)


# Registry of available algorithms keyed by their stable CLI name.
_ALGORITHMS: dict[str, CallgraphMatcher] = {
    matcher.name: matcher for matcher in (LayeredMatcher(), AnchorMatcher())
}

#: The algorithm used when none is requested.
DEFAULT_ALGORITHM = LayeredMatcher.name


def available_algorithms() -> list[str]:
    """Return the registered algorithm names in stable order."""
    return sorted(_ALGORITHMS)


def algorithm_descriptions() -> dict[str, str]:
    """Return a mapping of algorithm name to human-readable description."""
    return {name: _ALGORITHMS[name].description for name in available_algorithms()}


def get_algorithm(name: Optional[str]) -> CallgraphMatcher:
    """Return the matcher registered under ``name`` (or the default).

    Raises:
        ValueError: If ``name`` is not a registered algorithm.
    """
    resolved = name or DEFAULT_ALGORITHM
    try:
        return _ALGORITHMS[resolved]
    except KeyError as exc:
        known = ", ".join(available_algorithms())
        raise ValueError(
            f"Unknown callgraph match algorithm '{resolved}'. Available: {known}"
        ) from exc


def register_algorithm(matcher: CallgraphMatcher) -> None:
    """Register a custom matcher, making it selectable by its ``name``."""
    if not matcher.name:
        raise ValueError("A callgraph matcher must define a non-empty name")
    _ALGORITHMS[matcher.name] = matcher
