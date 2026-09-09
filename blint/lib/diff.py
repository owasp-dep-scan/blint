"""``blint diff`` — compare two versions of one binary (D1 / P4.4).

Each side is a binary or an exported ``*-metadata.json``. The report is a
structured delta over four layers:

1. **Metadata delta** — imported/exported symbol sets, linked dependencies,
   entitlements, section layout and entropy shifts, and format/identity
   fields (``exe_type``, architecture, toolchain, uuid).
2. **Hardening regressions** — ``security_properties`` compared through an
   explicit per-property polarity table (see ``HARDENING_POLARITY``). A
   regression is a move the table says is a weakening; values are never
   classified from truthiness alone, and properties blint has no polarity
   for are reported as unclassified changes.
3. **Finding delta** — security-check findings and capability reviews,
   paired across versions with ``compute_finding_pairing_key`` (rule id +
   evidence), never with ``finding_id`` (which is re-minted on every rebuild
   by design — see ``blint.lib.finding_ids``).
4. **Function-level delta** — available only when both sides carry
   ``disassembled_functions`` (i.e. were analyzed with ``--disassemble``).
   Functions pair by ``fuzzy_hash`` content first, then by name, so a
   recompile is not reported as everything-rewritten. When the layer's input
   is missing the report says so explicitly instead of claiming "no
   functions changed".

Findings and reviews are recomputed on both sides from their metadata with
the engine's own rule state (``initialize_rules``), which is what makes the
two input kinds (binary, metadata JSON) symmetric: the diff always compares
"what blint's current rules say about each side". Side effect to know about,
the same one ``blint.lib.capabilities`` documents: building a diff
re-initializes the module-global rule state to the built-in catalog.

Determinism contract: the same input pair produces the same report — every
list is sorted, no set iteration reaches the output, and ``diff(a, b)`` is
the mirror image of ``diff(b, a)`` (added/removed swap, old/new swap,
entropy deltas negate, regression becomes improvement).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any

import orjson

from blint.config import BlintOptions
from blint.lib.finding_ids import (
    attach_finding_ids,
    attach_pairing_keys,
    compute_finding_pairing_key,
    evidence_locator,
)

# Bounded lists in the report: a version bump of a large binary can add
# thousands of symbols, and a diff that dumps them all into one JSON blob is
# its own denial of service. Counts are always exact; only the listed names
# are capped.
LIST_LIMIT = 50

# Polarity of each ``security_properties`` key. This table is the whole
# definition of "hardening regression":
# - "hardening": presence is protective. Losing it is a regression, gaining
#   it an improvement.
# - "risk": presence is a weakness. Gaining it is a regression, losing it an
#   improvement.
# - "observe": reported as a change, never classified as a security
#   regression. (``stripped`` changes what analysis can see, not what an
#   attacker can break.)
# A key present in metadata but absent here is classified "unknown" and
# reported as an unclassified change — blint declines to call it a
# regression rather than guessing a polarity from its truthiness.
HARDENING_POLARITY: dict[str, str] = {
    "nx": "hardening",
    "w_xor_x": "hardening",
    "pie": "hardening",
    "canary": "hardening",
    "pac": "hardening",
    "is_signed": "hardening",
    "hardened_runtime": "hardening",
    "library_validation": "hardening",
    "get_task_allow": "risk",
    "packed": "risk",
    "stripped": "observe",
}

# ``relro`` is the one ordered security value: any step down the rank is a
# regression regardless of the endpoints.
RELRO_RANK = {"full": 2, "partial": 1, "no": 0}

# blint's own naming convention for functions discovered without a symbol
# name (disassembler.py synthesizes ``sub_<hex>`` from the address). Such
# names are rebuild-dependent, so the symbol-table layer counts them but
# never lists them as named-symbol changes — the code-level question is the
# function layer's job, answered by content hashes instead of names.
SYNTHETIC_NAME_RE = re.compile(r"^sub_[0-9a-f]+$")

# Identity fields compared verbatim. Hardening properties (is_pie, has_nx,
# relro, has_canary) are deliberately not here — the hardening layer owns
# them and classifies the change.
_IDENTITY_FIELDS = (
    "binary_type",
    "exe_type",
    "cpu_type",
    "cpu_subtype",
    "machine_type",
    "llvm_target_tuple",
    "uuid",
    "platform",
    "minos",
    "sdk",
    "source_version",
    "file_type",
    "interpreter",
    "dylinker",
    "entrypoint",
    "imagebase",
    "virtual_size",
)

_ENTROPY_SHIFT_THRESHOLD = 0.1

# Statuses that mean "this layer could not observe anything", not "no
# change"; they never satisfy the report-level ``unchanged`` claim on their
# own but are also never counted as differences.
_ABSENCE_STATUSES = (
    "unavailable",
    "no_import_evidence",
    "no_dependency_evidence",
    "no_symbol_names",
)


class DiffError(Exception):
    """The two inputs cannot be diffed; the message says why in one line."""


@dataclass
class DiffSide:
    """One input side: where it came from and the metadata/findings for it."""

    path: str
    kind: str  # "binary" | "metadata-json"
    metadata: dict[str, Any]
    findings: list[dict[str, Any]] = field(default_factory=list)
    reviews: list[dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Input loading


def load_side(path: str, disassemble: bool = False) -> DiffSide:
    """Load one diff input: a binary or a ``*-metadata.json`` export.

    A ``.json`` path is read as metadata when it parses to a dict carrying
    ``exe_type``; anything else is parsed as a binary. Both failure modes
    raise ``DiffError`` naming the path — a nonexistent path and an
    unparseable binary must fail loudly, not degrade to near-empty metadata
    that would read as a 100% diff.
    """
    if not path or not os.path.exists(path):
        raise DiffError(f"input does not exist: {path}")
    if os.path.isdir(path):
        raise DiffError(f"input is a directory, one file per side is required: {path}")
    if path.endswith(".json"):
        try:
            with open(path, "rb") as handle:
                metadata = orjson.loads(handle.read())
        except orjson.JSONDecodeError as exc:
            raise DiffError(f"{path} ends in .json but is not valid JSON: {exc}") from exc
        if isinstance(metadata, dict) and metadata.get("exe_type"):
            return DiffSide(path=path, kind="metadata-json", metadata=metadata)
        raise DiffError(
            f"{path} ends in .json but carries no exe_type, so it is not a "
            "blint *-metadata.json export"
        )
    from blint.lib.binary import parse

    metadata = parse(path, disassemble=disassemble)
    if not metadata or not metadata.get("exe_type"):
        raise DiffError(
            f"{path} is not a binary format blint understands (parsed without exe_type)"
        )
    return DiffSide(path=path, kind="binary", metadata=metadata)


def _recompute_findings_reviews(side: DiffSide) -> None:
    """Fill in the side's findings and reviews from its metadata.

    Mirrors the engine's per-binary pipeline (runners.py::_finalize_metadata):
    the same checks, the same wasm finding pass-through, the same stable-ID
    attachment — so a diff between two binaries agrees with two CLI runs.
    """
    from blint.lib.analysis import run_checks, run_wasm_findings
    from blint.lib.review_runner import ReviewRunner

    metadata = side.metadata
    exe_type = metadata.get("exe_type")
    # Native security-property checks are meaningless for Dalvik apps and
    # would fire spuriously; the dex review supplies behaviour findings
    # instead (the engine skips them the same way).
    if exe_type != "dexbinary":
        side.findings = run_checks(side.path, metadata)
        if exe_type == "wasmbinary":
            side.findings += run_wasm_findings(side.path, metadata)
    attach_finding_ids(side.path, metadata, side.findings)
    reviewer = ReviewRunner()
    reviewer.run_review(metadata)
    if reviewer.results:
        side.reviews = reviewer.process_review(
            side.path, os.path.basename(metadata.get("name") or side.path)
        )


def _ensure_comparable(old: DiffSide, new: DiffSide) -> None:
    """Refuse to diff inputs that are not two versions of one binary.

    Different ``exe_type`` (or architecture) means the sides answer different
    questions; reporting that as a large delta would be worse than refusing.
    Architecture is the LLVM target tuple when present, falling back to the
    format's cpu/machine type fields.
    """
    reasons = []
    if old.metadata.get("exe_type") != new.metadata.get("exe_type"):
        reasons.append(
            f"different exe_type: {old.metadata.get('exe_type')!r} vs {new.metadata.get('exe_type')!r}"
        )
    old_arch = old.metadata.get("llvm_target_tuple") or _cpu_signature(old.metadata)
    new_arch = new.metadata.get("llvm_target_tuple") or _cpu_signature(new.metadata)
    if old_arch != new_arch:
        reasons.append(f"different architecture: {old_arch!r} vs {new_arch!r}")
    if reasons:
        raise DiffError(
            f"inputs are not comparable ({'; '.join(reasons)}). "
            "blint diff compares two versions of one binary."
        )


def _cpu_signature(metadata: dict[str, Any]) -> tuple:
    return tuple(
        metadata.get(key) for key in ("binary_type", "cpu_type", "cpu_subtype", "machine_type")
    )


# ---------------------------------------------------------------------------
# Layer 1: metadata delta


def _identity_delta(old_meta: dict[str, Any], new_meta: dict[str, Any]) -> dict[str, Any]:
    changed = {}
    for field_name in _IDENTITY_FIELDS:
        old_value = old_meta.get(field_name)
        new_value = new_meta.get(field_name)
        if old_value != new_value and not (old_value is None and new_value is None):
            changed[field_name] = {"old": old_value, "new": new_value}
    old_sha = (old_meta.get("hashes") or {}).get("sha256")
    new_sha = (new_meta.get("hashes") or {}).get("sha256")
    identity: dict[str, Any] = {"changed_fields": changed}
    if old_sha != new_sha:
        identity["file_sha256"] = {"old": old_sha, "new": new_sha}
    toolchain = _toolchain_delta(old_meta.get("toolchain"), new_meta.get("toolchain"))
    if toolchain:
        identity["toolchain"] = toolchain
    return identity


def _toolchain_delta(old_tc: Any, new_tc: Any) -> dict[str, Any]:
    if not isinstance(old_tc, dict) and not isinstance(new_tc, dict):
        return {}
    old_tokens = _toolchain_tokens(old_tc)
    new_tokens = _toolchain_tokens(new_tc)
    if old_tokens == new_tokens:
        return {}
    return {
        "added": sorted(new_tokens - old_tokens),
        "removed": sorted(old_tokens - new_tokens),
    }


def _toolchain_tokens(toolchain: Any) -> set[str]:
    if not isinstance(toolchain, dict):
        return set()
    tokens = set()
    for group in ("compilers", "linkers", "runtimes"):
        for entry in toolchain.get(group) or []:
            if isinstance(entry, dict) and entry.get("name"):
                tokens.add(f"{group}:{entry['name']}@{entry.get('version') or ''}")
    if toolchain.get("libc"):
        tokens.add(f"libc:{toolchain['libc']}")
    return tokens


def _extract_dependencies(metadata: dict[str, Any]) -> tuple[list[str], str]:
    """Return the linked-library names and the metadata key they came from."""
    libraries = metadata.get("libraries")
    if isinstance(libraries, list) and libraries:
        names = []
        for entry in libraries:
            if isinstance(entry, dict) and entry.get("name"):
                names.append(str(entry["name"]))
            elif isinstance(entry, str) and entry:
                names.append(entry)
        if names:
            return names, "libraries"
    needed = [
        str(entry.get("name"))
        for entry in metadata.get("dynamic_entries") or []
        if isinstance(entry, dict) and entry.get("tag") == "NEEDED" and entry.get("name")
    ]
    if needed:
        return needed, "dynamic_entries"
    return [], "absent"


def _bounded(added: list[str], removed: list[str]) -> dict[str, Any]:
    """Counts exact, name lists capped — a diff nobody reads helps nobody."""
    return {
        "added": added[:LIST_LIMIT],
        "removed": removed[:LIST_LIMIT],
        "added_count": len(added),
        "removed_count": len(removed),
        "truncated": len(added) > LIST_LIMIT or len(removed) > LIST_LIMIT,
    }


def _set_delta(old_names: list[str], new_names: list[str]) -> dict[str, Any]:
    old_set, new_set = set(old_names), set(new_names)
    return _bounded(sorted(new_set - old_set), sorted(old_set - new_set))


def _extract_import_names(metadata: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    dependencies = metadata.get("import_dependencies")
    if isinstance(dependencies, dict):
        for library in (dependencies.get("libraries") or {}).values():
            if isinstance(library, dict):
                names.update(
                    str(symbol) for symbol in library.get("imported_symbols") or [] if symbol
                )
    if not names:
        for entry in metadata.get("imports") or []:
            if isinstance(entry, dict) and entry.get("name"):
                names.add(str(entry["name"]))
            elif isinstance(entry, str) and entry:
                names.add(entry)
    return names


def _imports_delta(old_meta: dict[str, Any], new_meta: dict[str, Any]) -> dict[str, Any]:
    """Import-set delta with the absent/empty distinction stated.

    An empty import set on a statically linked binary is "no import table",
    not "imports unchanged": two empty sets yield ``no_import_evidence``
    rather than an unchanged claim, and empty-vs-populated is reported as
    ``present_only_on_*`` — the import table appearing on one side — rather
    than a wholesale replacement of a common baseline.
    """
    old_names = _extract_import_names(old_meta)
    new_names = _extract_import_names(new_meta)
    if not old_names and not new_names:
        return {"status": "no_import_evidence"}
    delta: dict[str, Any] = {}
    if not old_names:
        delta["status"] = "present_only_on_new"
    elif not new_names:
        delta["status"] = "present_only_on_old"
    else:
        delta["status"] = "compared"
    delta.update(_bounded(sorted(new_names - old_names), sorted(old_names - new_names)))
    old_hash = old_meta.get("import_hash") or ""
    new_hash = new_meta.get("import_hash") or ""
    if old_hash and new_hash:
        delta["import_hash_changed"] = old_hash != new_hash
    else:
        # An empty import_hash means the side imports nothing (statically
        # linked); no claim about "the import hash" is possible then.
        delta["import_hash_changed"] = None
    return delta


def _exports_delta(old_meta: dict[str, Any], new_meta: dict[str, Any]) -> dict[str, Any]:
    def export_names(metadata: dict[str, Any]) -> list[str]:
        return [
            str(entry.get("name") if isinstance(entry, dict) else entry)
            for entry in metadata.get("exports") or []
            if (entry.get("name") if isinstance(entry, dict) else entry)
        ]

    old_names = export_names(old_meta)
    new_names = export_names(new_meta)
    if not old_names and not new_names:
        # Most executables export nothing; an all-empty layer is noise.
        return {}
    delta: dict[str, Any] = {"status": "compared"}
    delta.update(
        _bounded(sorted(set(new_names) - set(old_names)), sorted(set(old_names) - set(new_names)))
    )
    return delta


def _flatten_entitlements(metadata: dict[str, Any]) -> dict[str, Any] | None:
    code_signature = metadata.get("code_signature")
    if not isinstance(code_signature, dict):
        return None
    entitlements = code_signature.get("entitlements")
    if isinstance(entitlements, dict) and entitlements:
        return {str(key): entitlements[key] for key in entitlements}
    return None


def _entitlements_delta(old_meta: dict[str, Any], new_meta: dict[str, Any]) -> dict[str, Any]:
    old_ent = _flatten_entitlements(old_meta)
    new_ent = _flatten_entitlements(new_meta)
    if not old_ent and not new_ent:
        return {}
    old_keys, new_keys = set(old_ent or {}), set(new_ent or {})
    return {
        "added": {key: new_ent[key] for key in sorted(new_keys - old_keys)},
        "removed": {key: old_ent[key] for key in sorted(old_keys - new_keys)},
        "changed": {
            key: {"old": old_ent[key], "new": new_ent[key]}
            for key in sorted(old_keys & new_keys)
            if old_ent[key] != new_ent[key]
        },
    }


def _sections_delta(old_meta: dict[str, Any], new_meta: dict[str, Any]) -> dict[str, Any]:
    def sections_by_name(metadata: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
        by_name: dict[str, list[dict[str, Any]]] = {}
        for entry in (metadata.get("entropy") or {}).get("sections") or []:
            if isinstance(entry, dict) and entry.get("name"):
                by_name.setdefault(str(entry["name"]), []).append(entry)
        return by_name

    old_sections = sections_by_name(old_meta)
    new_sections = sections_by_name(new_meta)
    if not old_sections and not new_sections:
        return {}
    added = sorted(set(new_sections) - set(old_sections))
    removed = sorted(set(old_sections) - set(new_sections))
    shifted = []
    for name in sorted(set(old_sections) & set(new_sections)):
        old_list, new_list = old_sections[name], new_sections[name]
        # Duplicate section names are legal; pair them position-wise.
        for old_entry, new_entry in zip(old_list, new_list):
            old_entropy = old_entry.get("entropy") or 0.0
            new_entropy = new_entry.get("entropy") or 0.0
            entropy_delta = round(new_entropy - old_entropy, 4)
            size_old, size_new = old_entry.get("size"), new_entry.get("size")
            if abs(entropy_delta) >= _ENTROPY_SHIFT_THRESHOLD or size_old != size_new:
                shifted.append(
                    {
                        "name": name,
                        "entropy_old": old_entropy,
                        "entropy_new": new_entropy,
                        "entropy_delta": entropy_delta,
                        "size_old": size_old,
                        "size_new": size_new,
                    }
                )
    return {
        "added": added,
        "removed": removed,
        "shifted": shifted,
        "shifted_count": len(shifted),
    }


def _packing_delta(old_meta: dict[str, Any], new_meta: dict[str, Any]) -> dict[str, Any]:
    old_packing = (old_meta.get("entropy") or {}).get("packing") or {}
    new_packing = (new_meta.get("entropy") or {}).get("packing") or {}
    if not old_packing and not new_packing:
        return {}
    delta: dict[str, Any] = {}
    old_likelihood = old_packing.get("packed_likelihood")
    new_likelihood = new_packing.get("packed_likelihood")
    if old_likelihood != new_likelihood:
        delta["packed_likelihood"] = {"old": old_likelihood, "new": new_likelihood}
    old_packers = sorted(str(p) for p in old_packing.get("packers") or [])
    new_packers = sorted(str(p) for p in new_packing.get("packers") or [])
    if old_packers != new_packers:
        delta["packers"] = {
            "added": sorted(set(new_packers) - set(old_packers)),
            "removed": sorted(set(old_packers) - set(new_packers)),
        }
    return delta


def _symbol_table_delta(old_meta: dict[str, Any], new_meta: dict[str, Any]) -> dict[str, Any]:
    """Symbol-table surface: function/symbol counts plus real-name churn.

    Entries named with blint's synthetic ``sub_<hex>`` convention are
    address-derived and churn on every rebuild, so they move the counts but
    are never listed as named-symbol changes.
    """

    def real_names(metadata: dict[str, Any]) -> list[str]:
        return sorted(
            {
                str(entry.get("name"))
                for entry in metadata.get("functions") or []
                if isinstance(entry, dict)
                and entry.get("name")
                and not SYNTHETIC_NAME_RE.match(str(entry.get("name")))
            }
        )

    old_names = real_names(old_meta)
    new_names = real_names(new_meta)
    delta: dict[str, Any] = {
        "functions_old_count": len(old_meta.get("functions") or []),
        "functions_new_count": len(new_meta.get("functions") or []),
        "status": "compared",
    }
    for key, meta in (("symtab_old_count", old_meta), ("symtab_new_count", new_meta)):
        symtab = meta.get("symtab_symbols")
        if symtab is not None:
            delta[key] = len(symtab)
    if not old_names and not new_names:
        delta["status"] = "no_symbol_names"
        return delta
    delta.update(
        _bounded(sorted(set(new_names) - set(old_names)), sorted(set(old_names) - set(new_names)))
    )
    return delta


# ---------------------------------------------------------------------------
# Layer 2: hardening regressions


def _classify_hardening(property_name: str, old_value: Any, new_value: Any) -> tuple[str, str]:
    """Return (classification, polarity) for one changed security property.

    A value absent (``None``) on either side is an unclassified change: the
    property was not reported for that side, which is not evidence that it
    was gained or lost.
    """
    if property_name == "relro":
        old_rank = RELRO_RANK.get(str(old_value).lower(), -1) if old_value is not None else -1
        new_rank = RELRO_RANK.get(str(new_value).lower(), -1) if new_value is not None else -1
        if old_rank >= 0 and new_rank >= 0 and new_rank != old_rank:
            return ("regression" if new_rank < old_rank else "improvement"), "ordered"
        return "change", "ordered"
    polarity = HARDENING_POLARITY.get(property_name, "unknown")
    if polarity in ("hardening", "risk") and old_value is not None and new_value is not None:
        old_on, new_on = bool(old_value), bool(new_value)
        if old_on != new_on:
            hardened = new_on if polarity == "hardening" else not new_on
            return ("improvement" if hardened else "regression"), polarity
    return "change", polarity


def _hardening_delta(old_meta: dict[str, Any], new_meta: dict[str, Any]) -> dict[str, Any]:
    old_props = old_meta.get("security_properties") or {}
    new_props = new_meta.get("security_properties") or {}
    changes = []
    for property_name in sorted(set(old_props) | set(new_props)):
        old_value = old_props.get(property_name)
        new_value = new_props.get(property_name)
        if old_value == new_value:
            continue
        classification, polarity = _classify_hardening(property_name, old_value, new_value)
        changes.append(
            {
                "property": property_name,
                "old": old_value,
                "new": new_value,
                "polarity": polarity,
                "classification": classification,
            }
        )
    return {
        "changes": changes,
        "regression_count": sum(1 for c in changes if c["classification"] == "regression"),
        "improvement_count": sum(1 for c in changes if c["classification"] == "improvement"),
        "unclassified_count": sum(1 for c in changes if c["classification"] == "change"),
        # Rule 21: the summary block describes one slice of a universal
        # binary; the diff carries the scope through so a reader knows what
        # the compared values mean.
        "scope": new_meta.get("security_properties_scope"),
    }


# ---------------------------------------------------------------------------
# Layer 3: finding delta


def _finding_row(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "rule": str(finding.get("id") or ""),
        "title": str(finding.get("title") or ""),
        "severity": str(finding.get("severity") or ""),
        "pairing_key": finding.get("pairing_key"),
        "finding_id": finding.get("finding_id"),
    }


def _findings_delta(
    old_findings: list[dict[str, Any]], new_findings: list[dict[str, Any]]
) -> dict[str, Any]:
    """Findings paired across versions by ``pairing_key``, never by ID.

    ``finding_id`` folds in the whole-file sha256, so pairing on it would
    report every finding of every rebuild as removed-and-added. The pairing
    key is (rule id, evidence) — the same rule firing on the same evidence.
    A YAML check emits at most one finding per binary with empty evidence,
    so for checks the key reduces to the rule id: "CHECK_PIE" in the old
    build and "CHECK_PIE" in the new one are the same, still-open finding.
    """
    old_index = attach_pairing_keys(old_findings)
    new_index = attach_pairing_keys(new_findings)
    common = set(old_index) & set(new_index)
    severity_changed = [
        {
            "rule": str(old_index[key].get("id") or ""),
            "pairing_key": key,
            "severity_old": str(old_index[key].get("severity") or ""),
            "severity_new": str(new_index[key].get("severity") or ""),
        }
        for key in sorted(common)
        if (old_index[key].get("severity") or "") != (new_index[key].get("severity") or "")
    ]
    added_keys = sorted(set(new_index) - set(old_index))
    removed_keys = sorted(set(old_index) - set(new_index))
    return {
        "added": [_finding_row(new_index[key]) for key in added_keys],
        "removed": [_finding_row(old_index[key]) for key in removed_keys],
        "unchanged_count": len(common) - len(severity_changed),
        "severity_changed": severity_changed,
        "added_count": len(added_keys),
        "removed_count": len(removed_keys),
    }


def _reviews_delta(
    old_reviews: list[dict[str, Any]], new_reviews: list[dict[str, Any]]
) -> dict[str, Any]:
    """Capability-review delta, paired by rule id.

    Reviews carry no ``finding_id`` (P4.5 left review IDs out; adding them
    here would change the engine's review output, which stays byte-identical).
    One review entry exists per rule per binary — ``process_review`` merges
    each rule's matches into a single entry whose evidence list is an
    aggregate, not a locator — so the rule id pairs a review across versions,
    and a paired review whose aggregate evidence changed is reported with
    ``evidence_changed`` instead of as removed-and-added.
    """

    def by_rule(reviews: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        return {str(review.get("id") or ""): review for review in reviews if review.get("id")}

    old_by_rule = by_rule(old_reviews)
    new_by_rule = by_rule(new_reviews)
    common = set(old_by_rule) & set(new_by_rule)
    evidence_changed = [
        {"rule": rule_id, "pairing_key": compute_finding_pairing_key(rule_id, "")}
        for rule_id in sorted(common)
        if evidence_locator(old_by_rule[rule_id]) != evidence_locator(new_by_rule[rule_id])
    ]
    added = sorted(set(new_by_rule) - set(old_by_rule))
    removed = sorted(set(old_by_rule) - set(new_by_rule))

    def row(rule_id: str, source: dict[str, dict[str, Any]]) -> dict[str, Any]:
        review = source[rule_id]
        return {
            "rule": rule_id,
            "title": str(review.get("title") or ""),
            "summary": str(review.get("summary") or ""),
            "pairing_key": compute_finding_pairing_key(rule_id, ""),
        }

    return {
        "added": [row(rule_id, new_by_rule) for rule_id in added],
        "removed": [row(rule_id, old_by_rule) for rule_id in removed],
        "unchanged_count": len(common) - len(evidence_changed),
        "evidence_changed": evidence_changed,
        "added_count": len(added),
        "removed_count": len(removed),
    }


# ---------------------------------------------------------------------------
# Layer 4: function-level delta


def _function_delta(old_meta: dict[str, Any], new_meta: dict[str, Any]) -> dict[str, Any]:
    """Function-level delta keyed on ``fuzzy_hash`` content, then on name.

    ``disassembled_functions`` exists only under ``--disassemble``. A missing
    key on a side means the layer did not run and is reported as
    ``unavailable`` — an empty report here would read as "no functions
    changed", which is a claim the inputs cannot support. A key present but
    empty is a genuine zero (disassembly ran and recovered nothing) and is
    reported as a compared zero.

    Matching is content-first: entries whose ``fuzzy_hash`` appears on both
    sides are the same code (unchanged, whether or not they kept their name —
    a stripped rebuild renames everything, which is the symbol table's
    business, not the code's). The remainders pair by name, and a name-paired
    pair with divergent hashes is classified by one further deterministic
    test: when one side's mnemonic run is a strict prefix of the other's, the
    function *boundary* moved (discovery extended or truncated the run) but
    no instruction diverges — reported as ``scope_changed``, not ``changed``.
    Only a non-prefix divergence claims a code change. Name-paired entries
    whose hash is missing on a side cannot be judged and are ``unverifiable``.
    """
    if "disassembled_functions" not in old_meta or "disassembled_functions" not in new_meta:
        missing = [
            side
            for side, meta in (("old", old_meta), ("new", new_meta))
            if "disassembled_functions" not in meta
        ]
        return {
            "status": "unavailable",
            "reason": (
                "no disassembled functions on the "
                f"{' and '.join(missing)} side(s); regenerate with --disassemble"
            ),
        }

    def entries(metadata: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            entry
            for entry in (metadata.get("disassembled_functions") or {}).values()
            if isinstance(entry, dict) and entry.get("name")
        ]

    old_entries = entries(old_meta)
    new_entries = entries(new_meta)
    # Content pass. Both partitions match the same multiset minimum, so the
    # match counts are equal by construction (asserted by the mirror test).
    old_matched, old_rest = _content_partition(old_entries, _hash_counts(new_entries))
    new_matched, new_rest = _content_partition(new_entries, _hash_counts(old_entries))
    assert len(old_matched) == len(new_matched), "content pass must match symmetrically"
    unchanged_count = len(old_matched)

    # Name pass over the unmatched remainders.
    def by_name(rest: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        by_name: dict[str, list[dict[str, Any]]] = {}
        for entry in rest:
            by_name.setdefault(str(entry["name"]), []).append(entry)
        return by_name

    old_by_name = by_name(old_rest)
    new_by_name = by_name(new_rest)
    changed: list[dict[str, Any]] = []
    scope_changed: list[dict[str, Any]] = []
    unverifiable: list[str] = []
    added: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    for name in sorted(set(old_by_name) | set(new_by_name)):
        old_list = old_by_name.get(name) or []
        new_list = new_by_name.get(name) or []
        for index in range(max(len(old_list), len(new_list))):
            old_entry = old_list[index] if index < len(old_list) else None
            new_entry = new_list[index] if index < len(new_list) else None
            if old_entry and new_entry:
                old_hash = old_entry.get("fuzzy_hash") or ""
                new_hash = new_entry.get("fuzzy_hash") or ""
                if old_hash and new_hash and old_hash != new_hash:
                    row = {"name": name}
                    relation = _mnemonic_relation(old_entry, new_entry)
                    if relation == "prefix":
                        row["disassembly"] = (
                            f"boundary moved: {old_entry.get('instruction_count')} → "
                            f"{new_entry.get('instruction_count')} instructions"
                        )
                        scope_changed.append(row)
                    else:
                        changed.append(row)
                elif not old_hash or not new_hash:
                    unverifiable.append(name)
                # Equal hashes here would mean the content pass missed a
                # pair it should have caught; count them unchanged regardless.
                else:
                    unchanged_count += 1
            elif old_entry:
                removed.append(old_entry)
            else:
                added.append(new_entry)

    return {
        "status": "compared",
        "old_count": len(old_entries),
        "new_count": len(new_entries),
        "unchanged_count": unchanged_count,
        "changed": sorted(changed, key=lambda entry: entry["name"])[:LIST_LIMIT],
        "changed_count": len(changed),
        "scope_changed": sorted(scope_changed, key=lambda entry: entry["name"])[:LIST_LIMIT],
        "scope_changed_count": len(scope_changed),
        "unverifiable_names": sorted(set(unverifiable))[:LIST_LIMIT],
        "unverifiable_count": len(unverifiable),
        "added_names": sorted({str(e.get("name")) for e in added})[:LIST_LIMIT],
        "added_count": len(added),
        "removed_names": sorted({str(e.get("name")) for e in removed})[:LIST_LIMIT],
        "removed_count": len(removed),
        "truncated": len(changed) > LIST_LIMIT,
    }


def _mnemonic_relation(old_entry: dict[str, Any], new_entry: dict[str, Any]) -> str:
    """Classify two same-name disassembly runs of one function.

    Returns "prefix" when one side's mnemonic sequence is a strict prefix of
    the other's — the function boundary moved but no instruction position
    diverges — and "divergent" otherwise. Compares exactly the sequence the
    fuzzy hash covers (``similarity.function_mnemonics``), falling back to
    "divergent" when either side carries no assembly text.
    """
    from blint.lib.similarity import function_mnemonics

    old_asm = old_entry.get("assembly") or ""
    new_asm = new_entry.get("assembly") or ""
    if not old_asm or not new_asm:
        return "divergent"
    old_mn, new_mn = function_mnemonics(old_asm), function_mnemonics(new_asm)
    shorter, longer = (old_mn, new_mn) if len(old_mn) <= len(new_mn) else (new_mn, old_mn)
    if longer[: len(shorter)] == shorter and len(shorter) != len(longer):
        return "prefix"
    return "divergent"


def _hash_counts(entries: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for entry in entries:
        fuzzy = entry.get("fuzzy_hash") or ""
        if fuzzy:
            counts[fuzzy] = counts.get(fuzzy, 0) + 1
    return counts


def _content_partition(
    entries: list[dict[str, Any]], other_counts: dict[str, int]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split entries into content-matched and unmatchable, deterministically.

    An entry whose fuzzy hash exists in the other side's pool is
    content-matched (same code, whatever the name). Ties — several entries
    sharing one hash — are consumed in (hash, name) order so the partition,
    and therefore the report, does not depend on dict iteration order.
    """
    counts = dict(other_counts)
    matched: list[dict[str, Any]] = []
    unmatched: list[dict[str, Any]] = []
    for entry in sorted(
        entries, key=lambda e: (str(e.get("fuzzy_hash") or ""), str(e.get("name")))
    ):
        fuzzy = entry.get("fuzzy_hash") or ""
        if fuzzy and counts.get(fuzzy, 0) > 0:
            counts[fuzzy] -= 1
            matched.append(entry)
        else:
            unmatched.append(entry)
    return matched, unmatched


# ---------------------------------------------------------------------------
# Report assembly


def diff_binary_metadata(
    old_path: str, new_path: str, *, disassemble: bool = False, no_reviews: bool = False
) -> dict[str, Any]:
    """Diff two versions of one binary and return the report dict.

    Args:
        old_path: binary or ``*-metadata.json`` for the old version.
        new_path: same for the new version.
        disassemble: disassemble binary inputs (enables the function layer;
            metadata-JSON sides need the export to already carry
            ``disassembled_functions``).
        no_reviews: skip the capability-review layer.

    Returns:
        The report dict — plain JSON types, sorted lists, deterministic.

    Raises:
        DiffError: an input is missing/unreadable, or the sides are not two
            versions of one binary (different exe_type or architecture).
    """
    from blint.lib.analysis import initialize_rules

    # Both sides must be diffed under the same rule state; re-initializing
    # here is what guarantees the two sides of one report agree even when a
    # caller loaded custom rules earlier (see module docstring).
    initialize_rules(BlintOptions())

    old = load_side(old_path, disassemble=disassemble)
    new = load_side(new_path, disassemble=disassemble)
    _ensure_comparable(old, new)
    _recompute_findings_reviews(old)
    _recompute_findings_reviews(new)

    identity = _identity_delta(old.metadata, new.metadata)
    dependencies_old, dependencies_source = _extract_dependencies(old.metadata)
    dependencies_new, _ = _extract_dependencies(new.metadata)
    if dependencies_source == "absent" and not dependencies_new:
        dependencies: dict[str, Any] = {"status": "no_dependency_evidence"}
    else:
        dependencies = _set_delta(dependencies_old, dependencies_new)
    imports = _imports_delta(old.metadata, new.metadata)
    exports = _exports_delta(old.metadata, new.metadata)
    entitlements = _entitlements_delta(old.metadata, new.metadata)
    sections = _sections_delta(old.metadata, new.metadata)
    packing = _packing_delta(old.metadata, new.metadata)
    hardening = _hardening_delta(old.metadata, new.metadata)
    symbols = _symbol_table_delta(old.metadata, new.metadata)
    findings = _findings_delta(old.findings, new.findings)
    reviews = {} if no_reviews else _reviews_delta(old.reviews, new.reviews)
    functions = _function_delta(old.metadata, new.metadata)

    notes = []
    if functions.get("status") == "unavailable":
        notes.append(f"function layer unavailable: {functions['reason']}")
    if imports.get("status") == "no_import_evidence":
        notes.append(
            "no import evidence on either side (statically linked or no import table); "
            "imports are not claimed unchanged"
        )
    if symbols.get("status") == "no_symbol_names":
        notes.append("no symbol names on either side; symbol-table churn is not listed")

    report: dict[str, Any] = {
        "schema_version": 1,
        "old": _side_header(old),
        "new": _side_header(new),
        "unchanged": not any(
            delta
            for delta in (
                _has_delta(
                    identity, bool(identity.get("changed_fields") or identity.get("toolchain"))
                ),
                _count_delta(dependencies),
                _count_delta(imports),
                _count_delta(exports),
                _has_delta(entitlements, _entitlements_changed(entitlements)),
                _has_delta(sections, _sections_changed(sections)),
                _has_delta(packing, bool(packing)),
                _has_delta(hardening, bool(hardening.get("changes"))),
                _symbol_delta_changed(symbols),
                _has_delta(findings, _findings_changed(findings)),
                _has_delta(reviews, _reviews_changed(reviews)),
                _functions_changed(functions),
            )
        ),
        "identity": identity,
        "dependencies": dependencies,
        "imports": imports,
        "hardening": hardening,
        "symbols": symbols,
        "findings": findings,
        "functions": functions,
    }
    if exports:
        report["exports"] = exports
    if entitlements:
        report["entitlements"] = entitlements
    if sections:
        report["sections"] = sections
    if packing:
        report["packing"] = packing
    if reviews:
        report["reviews"] = reviews
    if notes:
        report["notes"] = notes
    report["summary"] = _summary(report)
    return report


def _has_delta(_layer: Any, changed: bool) -> bool:
    return bool(changed)


def _count_delta(layer: dict[str, Any]) -> bool:
    if layer.get("status") in _ABSENCE_STATUSES:
        return False
    return bool(layer.get("added_count") or layer.get("removed_count"))


def _entitlements_changed(entitlements: dict[str, Any]) -> bool:
    return bool(
        entitlements.get("added") or entitlements.get("removed") or entitlements.get("changed")
    )


def _sections_changed(sections: dict[str, Any]) -> bool:
    return bool(sections.get("added") or sections.get("removed") or sections.get("shifted"))


def _symbol_delta_changed(symbols: dict[str, Any]) -> bool:
    # Count deltas are observable even when no symbol names are available to
    # list; only the name listing degrades (flagged by the layer's status).
    if symbols.get("functions_old_count") != symbols.get("functions_new_count"):
        return True
    return bool(symbols.get("added_count") or symbols.get("removed_count"))


def _findings_changed(findings: dict[str, Any]) -> bool:
    return bool(
        findings.get("added_count")
        or findings.get("removed_count")
        or findings.get("severity_changed")
    )


def _reviews_changed(reviews: dict[str, Any]) -> bool:
    return bool(
        reviews.get("added_count")
        or reviews.get("removed_count")
        or reviews.get("evidence_changed")
    )


def _functions_changed(functions: dict[str, Any]) -> bool:
    if functions.get("status") in _ABSENCE_STATUSES:
        return False
    return bool(
        functions.get("changed_count")
        or functions.get("scope_changed_count")
        or functions.get("added_count")
        or functions.get("removed_count")
    )


def _side_header(side: DiffSide) -> dict[str, Any]:
    return {
        "path": side.path,
        "kind": side.kind,
        "name": os.path.basename(side.metadata.get("name") or side.path),
        "exe_type": side.metadata.get("exe_type"),
        "sha256": (side.metadata.get("hashes") or {}).get("sha256"),
    }


def _summary(report: dict[str, Any]) -> dict[str, Any]:
    hardening = report.get("hardening") or {}
    findings = report.get("findings") or {}
    reviews = report.get("reviews") or {}
    functions = report.get("functions") or {}
    imports = report.get("imports") or {}
    return {
        "hardening_regressions": hardening.get("regression_count", 0),
        "hardening_improvements": hardening.get("improvement_count", 0),
        "hardening_changes": hardening.get("unclassified_count", 0),
        "findings_added": findings.get("added_count", 0),
        "findings_removed": findings.get("removed_count", 0),
        "findings_severity_changed": len(findings.get("severity_changed") or []),
        "reviews_added": reviews.get("added_count", 0),
        "reviews_removed": reviews.get("removed_count", 0),
        "functions_unchanged": functions.get("unchanged_count", 0),
        "functions_changed": functions.get("changed_count", 0),
        "functions_scope_changed": functions.get("scope_changed_count", 0),
        "functions_added": functions.get("added_count", 0),
        "functions_removed": functions.get("removed_count", 0),
        "functions_unverifiable": functions.get("unverifiable_count", 0),
        "imports_added": imports.get("added_count", 0),
        "imports_removed": imports.get("removed_count", 0),
        "dependencies_added": (report.get("dependencies") or {}).get("added_count", 0),
        "dependencies_removed": (report.get("dependencies") or {}).get("removed_count", 0),
    }


# ---------------------------------------------------------------------------
# CLI rendering


def render_diff_table(report: dict[str, Any]) -> None:
    """Print the report as a rich table (the non---json CLI rendering)."""
    from rich.box import ROUNDED
    from rich.table import Table

    from blint.logger import console

    old_header, new_header = report.get("old") or {}, report.get("new") or {}
    summary = report.get("summary") or {}
    title = (
        f"blint diff — {old_header.get('name')} → {new_header.get('name')} "
        f"({old_header.get('exe_type')})"
    )
    if report.get("unchanged"):
        console.print(f"{title}: no differences found")
        return
    table = Table(box=ROUNDED, title=title, show_lines=False)
    table.add_column("Layer", style="cyan", no_wrap=True)
    table.add_column("Change", no_wrap=True)
    table.add_column("Detail", overflow="fold")

    for change in (report.get("hardening") or {}).get("changes") or []:
        classification = change["classification"]
        style = (
            "bold red"
            if classification == "regression"
            else "green"
            if classification == "improvement"
            else "yellow"
        )
        table.add_row(
            "hardening",
            f"[{style}]{classification.upper()}[/{style}]",
            f"{change['property']}: {change['old']} → {change['new']}",
        )

    for row in (report.get("findings") or {}).get("added") or []:
        table.add_row(
            "finding added", row.get("severity") or "-", f"{row.get('rule')}: {row.get('title')}"
        )
    for row in (report.get("findings") or {}).get("removed") or []:
        table.add_row(
            "finding removed", row.get("severity") or "-", f"{row.get('rule')}: {row.get('title')}"
        )
    for row in (report.get("findings") or {}).get("severity_changed") or []:
        table.add_row(
            "finding severity changed",
            "-",
            f"{row.get('rule')}: {row.get('severity_old')} → {row.get('severity_new')}",
        )

    for row in (report.get("reviews") or {}).get("added") or []:
        table.add_row(
            "review added", "-", f"{row.get('rule')}: {row.get('title') or row.get('summary')}"
        )
    for row in (report.get("reviews") or {}).get("removed") or []:
        table.add_row(
            "review removed", "-", f"{row.get('rule')}: {row.get('title') or row.get('summary')}"
        )

    dependencies = report.get("dependencies") or {}
    if dependencies.get("added_count") or dependencies.get("removed_count"):
        table.add_row(
            "dependencies",
            f"+{dependencies.get('added_count', 0)} / -{dependencies.get('removed_count', 0)}",
            ", ".join((dependencies.get("added") or []) + (dependencies.get("removed") or [])),
        )
    imports = report.get("imports") or {}
    if imports.get("status") in ("compared", "present_only_on_new", "present_only_on_old") and (
        imports.get("added_count") or imports.get("removed_count")
    ):
        table.add_row(
            "imports",
            f"+{imports.get('added_count', 0)} / -{imports.get('removed_count', 0)}",
            ", ".join((imports.get("added") or []) + (imports.get("removed") or [])),
        )
    elif imports.get("status") == "no_import_evidence":
        table.add_row("imports", "-", "no import evidence on either side")

    sections = report.get("sections") or {}
    section_details = []
    for name in sections.get("added") or []:
        section_details.append(f"+{name}")
    for name in sections.get("removed") or []:
        section_details.append(f"-{name}")
    for shift in sections.get("shifted") or []:
        section_details.append(
            f"{shift['name']}: entropy {shift['entropy_old']} → {shift['entropy_new']}"
        )
    if section_details:
        table.add_row("sections", f"{len(section_details)} change(s)", "; ".join(section_details))

    functions = report.get("functions") or {}
    if functions.get("status") == "unavailable":
        table.add_row("functions", "unavailable", functions.get("reason", ""))
    elif functions:
        detail = []
        for row in functions.get("changed") or []:
            detail.append(f"{row.get('name')} (code changed)")
        for row in functions.get("scope_changed") or []:
            detail.append(f"{row.get('name')} ({row.get('disassembly')})")
        table.add_row(
            "functions",
            f"{functions.get('unchanged_count', 0)} same code, "
            f"{functions.get('changed_count', 0)} changed, "
            f"{functions.get('scope_changed_count', 0)} boundary moved, "
            f"+{functions.get('added_count', 0)} / -{functions.get('removed_count', 0)}",
            "; ".join(detail),
        )

    identity = report.get("identity") or {}
    identity_rows = []
    file_sha = identity.get("file_sha256") or {}
    if file_sha:
        identity_rows.append("file bytes changed (sha256)")
    for field_name in sorted(identity.get("changed_fields") or {}):
        change = identity["changed_fields"][field_name]
        identity_rows.append(f"{field_name}: {change.get('old')} → {change.get('new')}")
    toolchain = identity.get("toolchain") or {}
    if toolchain:
        identity_rows.append(
            "toolchain: +"
            + ", ".join(toolchain.get("added") or [])
            + " -"
            + ", ".join(toolchain.get("removed") or [])
        )
    if identity_rows:
        table.add_row("identity", f"{len(identity_rows)} change(s)", "; ".join(identity_rows))

    symbols = report.get("symbols") or {}
    if symbols.get("status") == "compared" and (
        symbols.get("added_count") or symbols.get("removed_count")
    ):
        table.add_row(
            "symbol table",
            f"functions {symbols.get('functions_old_count')} → {symbols.get('functions_new_count')}",
            f"+{symbols.get('added_count', 0)} / -{symbols.get('removed_count', 0)} named symbols",
        )

    for note in report.get("notes") or []:
        table.add_row("note", "-", note)

    console.print(table)
    console.print(
        f"Summary: {summary.get('hardening_regressions', 0)} hardening regression(s), "
        f"{summary.get('hardening_improvements', 0)} improvement(s), "
        f"{summary.get('findings_added', 0)} finding(s) added, "
        f"{summary.get('findings_removed', 0)} removed"
    )


__all__ = [
    "DiffError",
    "DiffSide",
    "diff_binary_metadata",
    "load_side",
    "render_diff_table",
]
