# -*- coding: utf-8 -*-
"""
Structural fingerprints for matching functions without relying on their names.

When a binary is stripped, anchoring by name (Layer 0) and one-hop neighbor
voting (Layer 1) eventually run out of signal: many functions have an
out-degree of one in a recovered callgraph, so a single hop rarely sees enough
already-matched neighbors to cross a voting threshold.

This module widens the context. For an unmatched binary function it collects the
already-matched functions within ``k`` hops, weighting closer matches more
heavily, and turns them into votes for the source functions that occupy the
same structural position. Per-function disassembly features that survive
stripping (instruction count, presence of loops, system or crypto calls) are
used as a plausibility gate so that trivial stubs are not matched against
substantial source functions.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from blint.lib.callgraph.match import MatchResult
    from blint.lib.callgraph.model import CallGraph

# Functions smaller than this instruction count are treated as thunks/stubs and
# are not assigned a structural identity, which keeps low-information nodes from
# absorbing confident-looking but meaningless matches.
_MIN_INSTRUCTIONS_FOR_FINGERPRINT = 4


@dataclass(frozen=True)
class Voter:
    """An already-matched binary function contributing to a structural vote.

    Attributes:
        source_canon: The source function the matched binary node maps to.
        direction: ``"pred"`` if the voter calls the candidate's neighborhood,
            ``"succ"`` if it is called by it.
        weight: Distance-decayed weight (closer matched nodes weigh more).
    """

    source_canon: str
    direction: str
    weight: float


def is_fingerprintable(features: dict) -> bool:
    """Return ``True`` when a function is substantial enough to fingerprint.

    Functions with no recorded instruction count are allowed through (the
    feature may simply be unavailable), while functions known to be tiny stubs
    are rejected.
    """
    count = features.get("instruction_count")
    if count is None:
        return True
    try:
        return int(count) >= _MIN_INSTRUCTIONS_FOR_FINGERPRINT
    except (TypeError, ValueError):
        return True


def gather_khop_voters(
    binary: "CallGraph",
    result: "MatchResult",
    node_id: str,
    k: int,
) -> list[Voter]:
    """Collect distance-weighted voters within ``k`` hops of ``node_id``.

    A breadth-first walk follows predecessor and successor edges separately so
    that the direction of each matched neighbor is preserved. Each matched node
    contributes one :class:`Voter` weighted by ``1 / distance``; the nearest
    occurrence wins when a node is reachable by several paths.
    """
    voters: dict[tuple[str, str], float] = {}

    for direction, expand in (
        ("pred", binary.predecessors),
        ("succ", binary.successors),
    ):
        seen = {node_id}
        frontier: deque[tuple[str, int]] = deque((nb, 1) for nb in expand(node_id))
        for nb, _ in frontier:
            seen.add(nb)
        while frontier:
            current, distance = frontier.popleft()
            match = result.matches.get(current)
            if match is not None:
                weight = 1.0 / distance
                key = (match.source_canon, direction)
                if weight > voters.get(key, 0.0):
                    voters[key] = weight
            if distance >= k:
                continue
            for nb in expand(current):
                if nb not in seen:
                    seen.add(nb)
                    frontier.append((nb, distance + 1))

    return [
        Voter(source_canon=canon, direction=direction, weight=weight)
        for (canon, direction), weight in voters.items()
    ]
