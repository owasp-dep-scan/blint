# -*- coding: utf-8 -*-
"""
Callgraph analysis utilities for blint.

This package provides a canonical naming scheme for Rust (and Rust-like)
function identifiers and a matcher that aligns a source-level callgraph with a
binary callgraph. The matcher is the basis for binary-to-source identification,
runtime reachability evidence, dead-code detection, and tamper detection.

The stable library entry point is :func:`match_files`, which returns a typed
:class:`MatchReport`.
"""

from blint.lib.callgraph.api import match_files
from blint.lib.callgraph.canon import (
    CanonicalName,
    NameKind,
    canonicalize,
    demangle,
)
from blint.lib.callgraph.match import (
    DEFAULT_PROFILE,
    PROFILES,
    MatchOptions,
    MatchReport,
    options_for_profile,
)

__all__ = [
    "CanonicalName",
    "NameKind",
    "canonicalize",
    "demangle",
    "match_files",
    "MatchOptions",
    "MatchReport",
    "options_for_profile",
    "PROFILES",
    "DEFAULT_PROFILE",
]
