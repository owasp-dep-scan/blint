# -*- coding: utf-8 -*-
"""
Align a binary callgraph with a source callgraph.

The matcher maps binary functions onto the source functions they were compiled
from. It works in layers of decreasing certainty:

* **Layer 0 - anchors.** Binary functions whose canonical name equals a source
  canonical name are matched directly. On an unstripped binary this recovers a
  large, high-confidence backbone and also serves as ground truth for evaluating
  the harder layers.
* **Layer 1 - structural propagation.** Starting from the anchors, unmatched
  binary functions are matched by agreement of their callers and callees: a
  binary function is mapped to the source function whose neighborhood best
  matches the already-mapped neighborhood of the binary function. This recovers
  names that are absent from the symbol table, which is the case for stripped or
  embedded binaries.

The result is a confidence-scored, many-to-one mapping (several monomorphized
binary functions may map to a single generic source definition).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

from blint.lib.callgraph.canon import NameKind
from blint.lib.callgraph.fingerprint import gather_khop_voters, is_fingerprintable
from blint.lib.callgraph.model import CallGraph

# Confidence labels ordered from least to most certain, matching the vocabulary
# already used by blint's callgraph export filters.
_CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}

# Node kinds that have no stable source-name counterpart and must not be matched
# by name alone in Layer 0.
_UNANCHORABLE_KINDS = frozenset({NameKind.CLOSURE, NameKind.GLUE, NameKind.INTRINSIC})


@dataclass(frozen=True)
class MatchOptions:
    """Tunable parameters for :func:`match_callgraphs`.

    Attributes:
        enable_propagation: Run Layer 1 structural propagation after anchoring.
        min_votes: Minimum number of agreeing mapped neighbors required to
            accept a propagated match.
        margin: Minimum lead in votes the best candidate must have over the
            runner-up to be accepted, which suppresses ambiguous matches.
        max_iterations: Maximum propagation rounds. Propagation stops early once
            a round produces no new matches.
        enable_fingerprint: Run Layer 2 k-hop structural fingerprint matching
            after propagation converges. Disabled by default: on edge-sparse
            graphs (for example Rust release binaries dominated by unresolved
            indirect calls) it trades precision for a small recall gain and is
            best enabled only when the binary callgraph is densely resolved.
        khop: Hop radius for Layer 2 anchored-context gathering.
        fp_min_shared: Minimum number of shared anchored neighbor names a Layer 2
            candidate must have before it can be accepted.
        fp_min_score: Minimum combined Jaccard score (predecessor + successor)
            required to accept a Layer 2 match.
        fp_margin: Minimum Jaccard lead the best Layer 2 candidate must have over
            the runner-up.
    """

    enable_propagation: bool = True
    min_votes: int = 2
    margin: int = 1
    max_iterations: int = 6
    enable_fingerprint: bool = False
    khop: int = 2
    fp_min_shared: int = 2
    fp_min_score: float = 0.34
    fp_margin: float = 0.1


# Named presets that bundle the individual knobs into intent-based choices.
# ``balanced`` mirrors the defaults. ``precision`` favors high-confidence matches
# by demanding stronger structural agreement and never running fingerprinting.
# ``recall`` accepts more uncertain matches and enables Layer 2 fingerprinting.
PROFILES = {
    "precision": {
        "enable_propagation": True,
        "min_votes": 3,
        "margin": 2,
        "enable_fingerprint": False,
    },
    "balanced": {},
    "recall": {
        "enable_propagation": True,
        "min_votes": 2,
        "margin": 1,
        "enable_fingerprint": True,
        "khop": 2,
        "fp_min_shared": 2,
        "fp_min_score": 0.3,
        "fp_margin": 0.05,
    },
}

#: The profile used when none is requested.
DEFAULT_PROFILE = "balanced"


def options_for_profile(profile: str = DEFAULT_PROFILE, **overrides) -> "MatchOptions":
    """Build :class:`MatchOptions` from a named profile plus explicit overrides.

    Args:
        profile: One of ``"precision"``, ``"balanced"``, or ``"recall"``.
        overrides: Individual option values that take precedence over the
            profile. Passing ``None`` for an override leaves the profile value
            in place, so callers can forward unset CLI flags directly.

    Returns:
        A :class:`MatchOptions` instance.

    Raises:
        ValueError: If ``profile`` is not a known profile.
    """
    if profile not in PROFILES:
        known = ", ".join(sorted(PROFILES))
        raise ValueError(f"Unknown match profile '{profile}'. Available: {known}")
    values = dict(PROFILES[profile])
    for key, value in overrides.items():
        if value is not None:
            values[key] = value
    return MatchOptions(**values)


@dataclass
class Match:
    """A single binary-to-source function mapping.

    Attributes:
        binary_id: The binary callgraph node id.
        source_canon: The canonical source name the binary function maps to.
        confidence: One of ``"low"``, ``"medium"``, ``"high"``.
        layer: ``"anchor"`` for a Layer 0 name match, ``"propagation"`` for a
            Layer 1 structural match.
        evidence: ``"symbol"`` or ``"structural"``.
        score: The supporting vote count for propagated matches, ``0`` for
            anchors.
    """

    binary_id: str
    source_canon: str
    confidence: str
    layer: str
    evidence: str
    score: int = 0


@dataclass
class MatchResult:
    """The full outcome of matching two callgraphs."""

    matches: dict[str, Match] = field(default_factory=dict)

    def add(self, match: Match) -> None:
        self.matches[match.binary_id] = match

    def __contains__(self, binary_id: str) -> bool:
        return binary_id in self.matches

    def __len__(self) -> int:
        return len(self.matches)


def _anchor(source: CallGraph, binary: CallGraph, result: MatchResult) -> None:
    """Populate Layer 0 anchors by canonical-name equality."""
    for node_id, node in binary.nodes.items():
        canon = node.canon
        if not canon.value or canon.kind in _UNANCHORABLE_KINDS:
            continue
        if source.ids_for_canon(canon.value):
            result.add(
                Match(
                    binary_id=node_id,
                    source_canon=canon.value,
                    confidence="high",
                    layer="anchor",
                    evidence="symbol",
                )
            )


def _vote(
    source: CallGraph,
    binary: CallGraph,
    result: MatchResult,
    node_id: str,
) -> Optional[tuple[str, int, int]]:
    """Score source candidates for an unmatched binary node by neighbor agreement.

    Each already-mapped predecessor of ``node_id`` votes for the source
    successors of its mapped source node; each mapped successor votes for the
    source predecessors of its mapped source node. The candidate accumulating
    the most votes is the structural best fit.

    Returns ``(best_canon, best_votes, runner_up_votes)`` or ``None`` when there
    are no mapped neighbors to vote.
    """
    votes: Counter[str] = Counter()

    for pred in binary.predecessors(node_id):
        mapped = result.matches.get(pred)
        if mapped is not None:
            votes.update(source.successors(mapped.source_canon))

    for succ in binary.successors(node_id):
        mapped = result.matches.get(succ)
        if mapped is not None:
            votes.update(source.predecessors(mapped.source_canon))

    if not votes:
        return None

    ranked = votes.most_common(2)
    best_canon, best_votes = ranked[0]
    runner_up = ranked[1][1] if len(ranked) > 1 else 0
    return best_canon, best_votes, runner_up


def _confidence_for_votes(votes: int) -> str:
    """Map a propagation vote count to a confidence label."""
    if votes >= 4:
        return "medium"
    return "low"


def _propagate(
    source: CallGraph,
    binary: CallGraph,
    result: MatchResult,
    options: MatchOptions,
) -> None:
    """Run Layer 1 structural propagation to a fixpoint."""
    for _ in range(options.max_iterations):
        pending: list[Match] = []
        for node_id in binary.nodes:
            if node_id in result:
                continue
            scored = _vote(source, binary, result, node_id)
            if scored is None:
                continue
            best_canon, best_votes, runner_up = scored
            if best_votes < options.min_votes:
                continue
            if best_votes - runner_up < options.margin:
                continue
            pending.append(
                Match(
                    binary_id=node_id,
                    source_canon=best_canon,
                    confidence=_confidence_for_votes(best_votes),
                    layer="propagation",
                    evidence="structural",
                    score=best_votes,
                )
            )
        if not pending:
            break
        for match in pending:
            # Re-check membership: a node is only assigned once per fixpoint run.
            if match.binary_id not in result:
                result.add(match)


def _fingerprint_vote(
    source: CallGraph,
    binary: CallGraph,
    result: MatchResult,
    node_id: str,
    options: MatchOptions,
) -> Optional[tuple[str, float, float, int]]:
    """Score source candidates for an unmatched node by anchored-neighbor overlap.

    Candidate source functions are generated cheaply from the k-hop matched
    context (Layer 1 voting widened by hop distance) and then rescored by the
    Jaccard overlap of their actual neighbor name sets against the binary
    function's already-matched neighbor names. Voting alone is non-discriminative
    because every neighbor of every matched node becomes a candidate; the Jaccard
    rescoring rewards candidates whose specific callers and callees line up and
    penalizes high-degree source hubs that overlap with everything.

    Returns ``(best_canon, best_jaccard, runner_up_jaccard, shared_count)`` or
    ``None`` when there is no usable context.
    """
    pred_names: set[str] = set()
    succ_names: set[str] = set()
    for voter in gather_khop_voters(binary, result, node_id, options.khop):
        if voter.direction == "pred":
            pred_names.add(voter.source_canon)
        else:
            succ_names.add(voter.source_canon)
    if not pred_names and not succ_names:
        return None

    # Candidate generation: source functions structurally adjacent to a matched
    # neighbor in the matching direction.
    candidates: set[str] = set()
    for canon in pred_names:
        candidates.update(source.successors(canon))
    for canon in succ_names:
        candidates.update(source.predecessors(canon))
    if not candidates:
        return None

    def _jaccard(left: set[str], right: set[str]) -> tuple[float, int]:
        if not left and not right:
            return 0.0, 0
        shared = left & right
        union = left | right
        return len(shared) / len(union), len(shared)

    scored: list[tuple[float, int, str]] = []
    for candidate in candidates:
        pred_j, pred_shared = _jaccard(pred_names, source.predecessors(candidate))
        succ_j, succ_shared = _jaccard(succ_names, source.successors(candidate))
        scored.append((pred_j + succ_j, pred_shared + succ_shared, candidate))

    scored.sort(reverse=True)
    best_score, best_shared, best_canon = scored[0]
    runner_up = scored[1][0] if len(scored) > 1 else 0.0
    return best_canon, best_score, runner_up, best_shared


def _fingerprint_match(
    source: CallGraph,
    binary: CallGraph,
    result: MatchResult,
    options: MatchOptions,
) -> None:
    """Run Layer 2 k-hop structural fingerprint matching to a fixpoint."""
    for _ in range(options.max_iterations):
        pending: list[Match] = []
        for node_id, node in binary.nodes.items():
            if node_id in result:
                continue
            if not is_fingerprintable(node.features):
                continue
            scored = _fingerprint_vote(source, binary, result, node_id, options)
            if scored is None:
                continue
            best_canon, best_score, runner_up, shared = scored
            if shared < options.fp_min_shared:
                continue
            if best_score < options.fp_min_score:
                continue
            if best_score - runner_up < options.fp_margin:
                continue
            pending.append(
                Match(
                    binary_id=node_id,
                    source_canon=best_canon,
                    confidence="low",
                    layer="fingerprint",
                    evidence="structural",
                    score=shared,
                )
            )
        if not pending:
            break
        for match in pending:
            if match.binary_id not in result:
                result.add(match)


def match_callgraphs(
    source: CallGraph,
    binary: CallGraph,
    options: Optional[MatchOptions] = None,
) -> MatchResult:
    """Match a binary callgraph against a source callgraph.

    Args:
        source: The source-derived callgraph (canonical-name keyed).
        binary: The binary-derived callgraph (address keyed).
        options: Matching parameters. Defaults to :class:`MatchOptions`.

    Returns:
        A :class:`MatchResult` mapping binary node ids to source functions.
    """
    options = options or MatchOptions()
    result = MatchResult()
    _anchor(source, binary, result)
    if options.enable_propagation:
        _propagate(source, binary, result, options)
    if options.enable_fingerprint:
        _fingerprint_match(source, binary, result, options)
    return result


def _meets_confidence(confidence: str, minimum: str) -> bool:
    return _CONFIDENCE_ORDER.get(confidence, 0) >= _CONFIDENCE_ORDER.get(minimum, 0)


def build_report(
    source: CallGraph,
    binary: CallGraph,
    result: MatchResult,
    *,
    min_confidence: str = "low",
    binary_file: Optional[str] = None,
) -> dict:
    """Build a serializable match report.

    Args:
        source: The source callgraph that was matched.
        binary: The binary callgraph that was matched.
        result: The :class:`MatchResult` to summarize.
        min_confidence: Drop individual matches below this confidence from the
            ``matches`` list. Summary counters always reflect all matches.
        binary_file: Optional path recorded in the report for provenance.

    Returns:
        A nested ``dict`` with a ``summary`` block and a ``matches`` list, ready
        to be serialized to JSON.
    """
    by_confidence: Counter[str] = Counter()
    by_layer: Counter[str] = Counter()
    matched_source: set[str] = set()
    emitted: list[dict] = []

    for match in result.matches.values():
        by_confidence[match.confidence] += 1
        by_layer[match.layer] += 1
        matched_source.add(match.source_canon)
        if not _meets_confidence(match.confidence, min_confidence):
            continue
        node = binary.nodes.get(match.binary_id)
        emitted.append(
            {
                "binary_id": match.binary_id,
                "address": node.address if node else None,
                "source": match.source_canon,
                "confidence": match.confidence,
                "layer": match.layer,
                "evidence": match.evidence,
                "score": match.score,
            }
        )

    emitted.sort(key=lambda item: (item["address"] or "", item["source"]))

    binary_total = len(binary)
    matched_total = len(result)
    coverage = round(matched_total / binary_total, 4) if binary_total else 0.0

    return {
        "schema_version": 1,
        "binary": {"file": binary_file, "nodes": binary_total},
        "source": {"nodes": len(source)},
        "summary": {
            "binary_nodes": binary_total,
            "binary_matched": matched_total,
            "coverage": coverage,
            "anchors": by_layer.get("anchor", 0),
            "propagated": by_layer.get("propagation", 0),
            "by_confidence": dict(by_confidence),
            "by_layer": dict(by_layer),
            "unmatched_binary": binary_total - matched_total,
            "source_functions_identified": len(matched_source),
        },
        "matches": emitted,
    }


@dataclass(frozen=True)
class MatchReport:
    """A typed, serializable result returned by the library match entry point.

    Wraps the report ``dict`` produced by :func:`build_report` with convenient
    typed accessors so integrators embedding blint do not have to index into raw
    dictionaries. Use :meth:`to_dict` to obtain the JSON-serializable form.
    """

    algorithm: str
    report: dict
    result: MatchResult = field(repr=False, default_factory=MatchResult)

    @property
    def summary(self) -> dict:
        return self.report.get("summary", {})

    @property
    def matches(self) -> list[dict]:
        return self.report.get("matches", [])

    @property
    def coverage(self) -> float:
        return float(self.summary.get("coverage", 0.0))

    @property
    def binary_matched(self) -> int:
        return int(self.summary.get("binary_matched", 0))

    @property
    def anchors(self) -> int:
        return int(self.summary.get("anchors", 0))

    @property
    def source_functions_identified(self) -> int:
        return int(self.summary.get("source_functions_identified", 0))

    def to_dict(self) -> dict:
        """Return the JSON-serializable report dictionary."""
        return self.report
