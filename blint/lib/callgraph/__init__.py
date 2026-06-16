# -*- coding: utf-8 -*-
"""
Callgraph analysis utilities for blint.

This package provides a canonical naming scheme for Rust (and Rust-like)
function identifiers and a matcher that aligns a source-level callgraph with a
binary callgraph. The matcher is the basis for binary-to-source identification,
runtime reachability evidence, dead-code detection, and tamper detection.
"""

from blint.lib.callgraph.canon import (
    CanonicalName,
    canonicalize,
    demangle,
)

__all__ = [
    "CanonicalName",
    "canonicalize",
    "demangle",
]
