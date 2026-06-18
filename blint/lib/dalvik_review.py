"""
Behavioural review of Dalvik bytecode.

The :mod:`blint.lib.dalvik` disassembler decodes a method's bytecode and (with
the dex constant pools) resolves invoke / field / string operands to readable
descriptors. This module turns those resolved operands into the same metadata
shape that blint's native binary review consumes (a ``functions`` list and an
``informative_strings`` list), then runs the existing
:class:`~blint.lib.review_runner.ReviewRunner` against it.

Reusing the native review engine means the behavioural rules live in a standard
annotation file (``blint/data/annotations/review_methods_android.yml``, keyed by
the ``dexbinary`` exe type) and are matched by the shared ``run_pattern_reviews``
logic. There is no separate rule loader or matcher here.
"""

from dataclasses import dataclass, field
from typing import Iterable, List, Optional

from blint.lib.dalvik import DexPools, disassemble_method
from blint.lib.dalvik_dataflow import analyze
from blint.logger import LOG

# The exe type that ties the dex review metadata to the android annotation rules.
DEX_EXE_TYPE = "dexbinary"

# Opcodes for const-string / const-string/jumbo and fill-array-data.
_CONST_STRING_OPCODES = frozenset({0x1A, 0x1B})
_FILL_ARRAY_DATA_OPCODE = 0x26
# Cap the per-method instruction count for the (more expensive) data-flow pass so
# a pathological method cannot dominate review time.
_DATAFLOW_MAX_INSTRUCTIONS = 4000
# Minimum run length for an embedded byte sequence to be treated as a string.
_MIN_EMBEDDED_STRING_LEN = 4


def _embedded_strings(data: bytes) -> List[str]:
    """Extract printable ASCII runs from raw ``fill-array-data`` bytes.

    Obfuscated apps frequently stage URLs, class names and keys as ``byte[]`` /
    ``char[]`` array data rather than string constants, so these never appear in
    the dex string pool. Recovering them gives the review rules something to
    match on.
    """
    runs: List[str] = []
    current: List[str] = []
    for byte in data:
        if 0x20 <= byte < 0x7F:
            current.append(chr(byte))
        else:
            if len(current) >= _MIN_EMBEDDED_STRING_LEN:
                runs.append("".join(current))
            current = []
    if len(current) >= _MIN_EMBEDDED_STRING_LEN:
        runs.append("".join(current))
    return runs


@dataclass
class Finding:
    """A behavioural finding aggregated for presentation and the BOM."""

    id: str
    title: str
    severity: str
    count: int = 0
    evidence: List[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "count": self.count,
            "evidence": self.evidence,
        }


def build_review_metadata(metadata: dict, pools: Optional[DexPools] = None) -> dict:
    """
    Build review metadata from a parsed dex.

    The resolved invoke and field descriptors become the ``functions`` list and
    the resolved string constants become ``informative_strings``, which is what
    the METHOD review rules match against. Printable strings staged as
    ``fill-array-data`` are recovered via the data-flow pass and folded into
    ``informative_strings`` as well, so obfuscated payloads carried as byte/char
    arrays are still visible to the rules.

    Args:
        metadata: A ``parse_dex`` metadata dict (lief methods + constant pools).
        pools: Optional pre-built constant pools (defaults to building them).

    Returns:
        A metadata dict carrying ``exe_type``, ``functions`` and
        ``informative_strings`` for :class:`ReviewRunner`.
    """
    methods = metadata.get("methods") or []
    if not methods:
        return {"exe_type": DEX_EXE_TYPE, "functions": [], "informative_strings": []}
    if pools is None:
        pools = DexPools.from_metadata(metadata)
    targets: set = set()
    strings: set = set()
    for method in methods:
        if not getattr(method, "bytecode", None):
            continue
        try:
            instructions = disassemble_method(method, pools)
        except Exception as e:  # a malformed method must not abort the dex review
            LOG.debug(f"Failed to disassemble a dex method: {e}")
            continue
        has_array_data = False
        for inst in instructions:
            if inst.opcode == _FILL_ARRAY_DATA_OPCODE:
                has_array_data = True
            if inst.target is None:
                continue
            if inst.opcode in _CONST_STRING_OPCODES:
                strings.add(inst.target)
            else:
                targets.add(inst.target)
        # Recover embedded array data only for methods that carry it, bounding
        # the cost of the data-flow pass on large methods.
        if has_array_data and len(instructions) <= _DATAFLOW_MAX_INSTRUCTIONS:
            strings.update(_collect_embedded_strings(instructions))
    return {
        "exe_type": DEX_EXE_TYPE,
        "functions": [{"name": t} for t in sorted(targets)],
        "informative_strings": sorted(strings),
    }


def _collect_embedded_strings(instructions) -> set:
    """Printable strings recovered from a method's ``fill-array-data`` payloads."""
    found: set = set()
    try:
        df = analyze(instructions)
    except Exception as e:  # analysis is best-effort; never break the review
        LOG.debug(f"Data-flow analysis failed for a dex method: {e}")
        return found
    for fill in df.array_fills:
        found.update(_embedded_strings(fill.data))
    return found


def analyze_dex(metadata: dict, pools: Optional[DexPools] = None) -> List[Finding]:
    """
    Review a parsed dex for behavioural findings using the shared review engine.

    Args:
        metadata: A ``parse_dex`` metadata dict.
        pools: Optional pre-built constant pools (primarily for testing).

    Returns:
        The aggregated findings, one per triggered rule, sorted by severity.
    """
    # Imported lazily to avoid a heavy import chain at module load time and to
    # pick up rules loaded by the SBOM path.
    from blint.lib.analysis import (
        EVIDENCE_LIMIT,
        load_default_rules,
        review_methods_dict,
        review_rules_cache,
    )
    from blint.lib.review_runner import ReviewRunner

    if not review_methods_dict:
        # The SBOM path does not call initialize_rules, so ensure the bundled
        # annotation rules are loaded before reviewing.
        load_default_rules()

    review_metadata = build_review_metadata(metadata, pools)
    if not review_metadata["functions"] and not review_metadata["informative_strings"]:
        return []
    reviewer = ReviewRunner()
    results = reviewer.run_review(review_metadata)
    findings: List[Finding] = []
    for cid, evidence in results.items():
        rule = review_rules_cache.get(cid, {})
        samples = [e.get("function", "") for e in evidence][:EVIDENCE_LIMIT]
        findings.append(
            Finding(
                id=cid,
                title=rule.get("title", cid),
                severity=rule.get("severity", "info"),
                count=len(evidence),
                evidence=samples,
            )
        )
    return sorted(findings, key=lambda x: (_severity_rank(x.severity), -x.count))


def _severity_rank(severity: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(severity, 5)


def merge_findings(groups: Iterable[List[Finding]]) -> List[Finding]:
    """Merge findings produced for several dex files into one aggregated list."""
    merged: dict[str, Finding] = {}
    for group in groups:
        for finding in group:
            existing = merged.get(finding.id)
            if existing is None:
                merged[finding.id] = Finding(
                    id=finding.id,
                    title=finding.title,
                    severity=finding.severity,
                    count=finding.count,
                    evidence=list(finding.evidence[:5]),
                )
                continue
            existing.count += finding.count
            for ev in finding.evidence:
                if len(existing.evidence) >= 5:
                    break
                existing.evidence.append(ev)
    return sorted(merged.values(), key=lambda x: (_severity_rank(x.severity), -x.count))
