"""Stable content-hash IDs for findings.

A finding is identified by three inputs and nothing else:

- ``rule_id`` — the finding's ``id`` field (``CHECK_NX``, ``WASM-STR-007``...).
- ``binary identity`` — the sha256 of the analyzed file's bytes. This is the
  same digest the parser records in ``metadata["hashes"]["sha256"]`` and the
  SBOM uses for component hashes, so the ID's notion of "which binary" is
  blint's existing one, not a new scheme.
- ``evidence locator`` — a canonical serialization of the finding's
  ``evidence`` field when it carries one (the wasm-tools findings do; the
  YAML-driven checks emit at most one finding per rule per binary, so for
  them the binary itself is the locator and the input is empty).

Deliberately NOT fed into the hash:

- Rendered prose (``title``, ``description``, ``summary``): fixing a typo in
  a rule's description must not make every finding look new.
- The file path and ``exe_name``: moving or renaming a binary must not
  re-track its findings.
- ``scan_id``, timestamps, the blint version and the analysis options: the
  ID describes the finding, not the run that produced it. A finding that
  only fires under ``--disassemble`` keeps the ID it would have without it.

Consequence of choosing whole-file bytes as the identity, stated plainly:
any byte change mints new IDs for every finding of that binary, including a
rebuild that changes nothing the finding depends on. The alternative — a
partial-content identity over "the bytes that matter" — cannot be computed
without duplicating the parser's knowledge of where loadable content lives
(the metadata carries no uniform layout list across formats), which is the
drift trap this packet exists to avoid. Exact-bytes identity is the honest
primitive; pairing findings across *rebuilt* binaries is similarity
matching, which is P4.2's fuzzy-hash domain, not the ID's.
"""

import hashlib
import json
from typing import Any

from blint.logger import LOG

# Bumped only when the ID scheme itself must change semantics; part of the
# hash input so two schemes can never collide.
_ID_SCHEME = "blint-finding-id-v1"

# 128 bits of the digest: collision-safe for any realistic suppression or
# diff corpus while staying a readable field.
_ID_LENGTH = 32


def binary_identity_digest(metadata: dict[str, Any], file_path: str) -> str:
    """Return the sha256 hex digest identifying the analyzed file's bytes.

    Prefers the digest the parser already recorded (so a cached parse and a
    fresh one agree by construction); streams the file only when the parser
    produced no ``hashes`` block (for example dex metadata).
    """
    sha256 = (metadata.get("hashes") or {}).get("sha256")
    if isinstance(sha256, str) and sha256:
        return sha256
    digest = hashlib.sha256()
    with open(file_path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _evidence_locator(finding: dict[str, Any]) -> str:
    """Canonical string for the finding's evidence, empty when it has none."""
    evidence = finding.get("evidence")
    if not evidence:
        return ""
    return json.dumps(evidence, sort_keys=True, separators=(",", ":"), default=str)


def compute_finding_id(rule_id: Any, identity: str, locator: str) -> str:
    """Compute the stable ID for one finding from its three inputs."""
    payload = "\x00".join((_ID_SCHEME, str(rule_id or ""), identity, locator))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:_ID_LENGTH]


def attach_finding_ids(
    file_path: str, metadata: dict[str, Any], findings: list[dict[str, Any]]
) -> int:
    """Attach a ``finding_id`` field to each finding, in place.

    IDs are unique within one binary: consumers key suppressions and diffs
    on them, so two findings sharing an ID would silently collapse into
    one. Rule and evidence separate them today, but nothing in the engine
    guarantees no rule will ever emit two findings with the same evidence,
    so a collision is broken here rather than trusted away — the later
    finding's ID takes an occurrence counter, and the collision is logged
    because it usually means the rule should be carrying a locator.

    Returns the number of findings that received an ID. The identity digest
    is computed once per binary, not once per finding.
    """
    if not findings:
        return 0
    identity = binary_identity_digest(metadata, file_path)
    occurrences: dict[str, int] = {}
    for finding in findings:
        rule_id = finding.get("id")
        locator = _evidence_locator(finding)
        finding_id = compute_finding_id(rule_id, identity, locator)
        seen_before = occurrences.get(finding_id, 0)
        occurrences[finding_id] = seen_before + 1
        if seen_before:
            LOG.warning(
                f"Finding {rule_id} in {file_path} repeats with identical evidence; "
                "disambiguating its stable id by occurrence."
            )
            finding_id = compute_finding_id(rule_id, identity, f"{locator}\x00#{seen_before}")
        finding["finding_id"] = finding_id
    return len(findings)
