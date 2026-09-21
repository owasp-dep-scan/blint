"""The privileged-host plugin surface (PE lane W5.6, plan 04/F).

A driver is not the only way a binary gets loaded into a privileged
process and kept there: Windows hosts a long list of *extension points*
where a DLL exporting a documented set of entry points is loaded
automatically into a host process - ``lsass.exe`` for LSA packages and
password filters, ``spoolsv.exe`` for print monitors, the W32Time
svchost for time providers, ``LogonUI.exe`` for credential providers -
usually running as SYSTEM, with no per-load prompt and no consent surface
after the one-time admin registration.

This module is the interpretation layer over facts blint already parses:
the export table (W1.2) and the section bytes. The contract table itself
is data (``blint/data/pe_host_plugin_contracts.yml``) pinned against
Microsoft's documentation with the tier-5/full-system32 measurement
recorded in its header - never transcribed from blint's own output, the
W3.1 lesson.

Design decisions the measurement forced:

- Bare COM in-proc exports are on 45% of a stock ``System32`` (1,443 of
  3,191 DLLs with named exports), so no contract keys on them alone. The
  two COM contracts (credential provider, Audio Processing Object)
  additionally require an in-binary reference to their registration path,
  scanned from section bytes rather than the ``strings`` list: the list
  is gate-filtered (entropy/length/shape) and its fallback path is
  capped, and a rule reading a capped or filtered listing turns that
  bound into a detection boundary - the W3.2 lesson.
- The export read status is a fact, not an implication. A binary whose
  export directory blint could not read gets no ``host_plugin`` block,
  ``exports_read_status: "failed"`` beside the empty export list, and a
  named ``analysis_coverage`` degradation - an unread gap must never read
  as "not a plugin" (ground rules 14 and 32).
- Ordinal-only exports are invisible here by construction, and that is
  sound: every host in the table resolves its contract entry points by
  name (``GetProcAddress``), so a name the binary does not export is a
  contract it cannot satisfy through this mechanism.
"""

from __future__ import annotations

import re
from typing import Any

import lief

from blint.lib.binary_common import is_string_bearing_section

# How many registration strings are listed per contract as evidence. The
# contract fires on the first hit and no rule reads past the first entry,
# so this bounds metadata size without bounding detection (rule 33: the
# cap is a listing bound, stated here, and pinned by a fixture that
# exceeds it).
REGISTRATION_EVIDENCE_LIMIT = 4

_TABLE_CACHE: dict | None = None


def _contracts_table() -> dict:
    """The contract table, loaded once (data file with provenance)."""
    global _TABLE_CACHE
    if _TABLE_CACHE is None:
        import importlib.resources

        import yaml

        try:
            with importlib.resources.files("blint.data").joinpath(
                "pe_host_plugin_contracts.yml"
            ).open("r", encoding="utf-8") as handle:
                _TABLE_CACHE = yaml.safe_load(handle) or {}
        except (OSError, yaml.YAMLError):
            # An unreadable table determines nothing (rule 11): the block
            # is absent rather than half-derived from a partial file.
            _TABLE_CACHE = {}
    return _TABLE_CACHE


def _export_names(metadata: dict[str, Any], key: str = "exports") -> set[str]:
    """Named exports of one export listing (ordinal-only entries carry no
    name and are excluded, which is the by-name-lookup soundness above)."""
    names: set[str] = set()
    for entry in metadata.get(key) or []:
        if isinstance(entry, dict) and entry.get("name"):
            names.add(str(entry["name"]))
    return names


def _registration_evidence(parsed_obj, pattern: str) -> list[str]:
    """In-binary references to a registration path, from section bytes.

    Scanned directly over the string-bearing sections in both ASCII and
    UTF-16LE rather than over ``metadata['strings']``: the strings list is
    entropy/length/shape gated and its extraction fallback is capped, and
    detection must not inherit those bounds (the W3.2 cap lesson). Forwarded
    strings, registry-script fragments and GUID-suffixed paths all match
    wherever they sit in the section.
    """
    hits: list[str] = []
    seen: set[bytes] = set()
    try:
        # Escape the *encoded* bytes, not the string: escaping the string
        # first doubles the backslashes, and once UTF-16-encoded each "\"
        # becomes 5C 00 where the 00 is read as a NUL escape by the bytes
        # regex engine, silently breaking the pattern.
        regex_ascii = re.compile(re.escape(pattern.encode("ascii")))
        regex_wide = re.compile(re.escape(pattern.encode("utf-16-le")))
    except UnicodeEncodeError:
        return hits
    sections = getattr(parsed_obj, "sections", None)
    if not sections or isinstance(sections, lief.lief_errors):
        return hits
    for section in sections:
        if not is_string_bearing_section(section):
            continue
        try:
            content = bytes(section.content)
        except (AttributeError, TypeError, ValueError):
            continue
        if not content:
            continue
        for regex in (regex_ascii, regex_wide):
            for match in regex.finditer(content):
                is_wide = regex is regex_wide
                # A short readable context around the hit (the surrounding
                # printable run) is the evidence string, not the bare key.
                start, end = match.start(), match.end()
                lo = start
                while lo > 0 and _printable_at(content, lo - (2 if is_wide else 1), is_wide):
                    lo -= 2 if is_wide else 1
                hi = end
                while hi < len(content) and _printable_at(content, hi, is_wide):
                    hi += 2 if is_wide else 1
                span = content[lo:hi]
                # Dedup on the context span, not the matched pattern: the
                # pattern bytes are identical at every occurrence, and the
                # evidence that distinguishes them is the GUID around it.
                if span in seen:
                    continue
                seen.add(span)
                try:
                    decoded = span.decode("utf-16-le" if is_wide else "latin-1")
                except (UnicodeDecodeError, ValueError):
                    decoded = pattern
                cleaned = decoded.strip()
                if cleaned:
                    hits.append(cleaned)
                if len(hits) >= REGISTRATION_EVIDENCE_LIMIT:
                    return hits
    return hits


def _printable_at(content: bytes, offset: int, is_wide: bool) -> bool:
    if offset < 0 or offset >= len(content):
        return False
    if not is_wide:
        return 0x20 <= content[offset] < 0x7F
    if offset + 1 >= len(content):
        return False
    return content[offset + 1] == 0 and 0x20 <= content[offset] < 0x7F


def _match_contracts(
    names: set[str], registration_lookup, table: dict
) -> list[dict[str, Any]]:
    """The contracts one export-name set satisfies, in table order.

    ``registration_lookup`` is a callable from registration pattern to
    evidence strings, invoked only for com_inproc contracts (whose pattern
    is not needed otherwise), so the section scan happens at most once per
    pattern and never for export-keyed contracts.
    """
    contracts: list[dict[str, Any]] = []
    if not names:
        return contracts
    for contract_id, spec in (table.get("contracts") or {}).items():
        if not isinstance(spec, dict):
            continue
        kind = spec.get("kind")
        if kind == "exports":
            wanted = [str(n) for n in spec.get("export_names") or []]
            matched = sorted(n for n in wanted if n in names)
            if not matched:
                continue
        elif kind == "com_inproc":
            com_export = str(spec.get("com_export") or "DllGetClassObject")
            if com_export not in names:
                continue
            evidence = registration_lookup(str(spec.get("registration_pattern") or ""))
            if not evidence:
                continue
            contracts.append(
                {
                    "id": contract_id,
                    "title": str(spec.get("title") or contract_id),
                    "host_process": str(spec.get("host_process") or ""),
                    "host_privilege": str(spec.get("host_privilege") or ""),
                    "matched_exports": [com_export],
                    "evidence": {"registration_strings": evidence},
                }
            )
            continue
        else:
            continue
        entry: dict[str, Any] = {
            "id": contract_id,
            "title": str(spec.get("title") or contract_id),
            "host_process": str(spec.get("host_process") or ""),
            "host_privilege": str(spec.get("host_privilege") or ""),
            "matched_exports": matched,
        }
        if spec.get("protected_process"):
            entry["protected_process"] = True
        if spec.get("credential_exposure"):
            entry["credential_exposure"] = str(spec["credential_exposure"])
        if spec.get("registration_hint"):
            entry["registration_hint"] = str(spec["registration_hint"])
        contracts.append(entry)
    return contracts


def classify_host_plugins(metadata: dict[str, Any], parsed_obj) -> dict | None:
    """The ``host_plugin`` block, or None when no evidence supports one.

    Present only when a contract matched - never an empty block that reads
    as "not a plugin". The export-keyed contracts come from the primary
    listing; for an ARM64X image whose primary slice could not be read but
    whose nested exports could, the block speaks for the nested listing
    and says so (``host_plugin_scope``), and when both are readable and
    disagree, ``host_plugin_slice_variance`` names the contracts they
    differ on (rule 21: adding a dimension must not silently let the
    summary speak for one slice).
    """
    table = _contracts_table()
    if not table.get("contracts"):
        return None
    primary_names = _export_names(metadata)
    # The com_inproc section scan is at most two regexes over the
    # string-bearing sections and only runs when a COM export is present.
    registration_lookup = (
        (lambda pattern: _registration_evidence(parsed_obj, pattern))
        if parsed_obj is not None
        else (lambda pattern: [])
    )
    primary_read_failed = metadata.get("exports_read_status") == "failed"
    contracts = _match_contracts(primary_names, registration_lookup, table)
    nested = metadata.get("nested_binary") or {}
    nested_names = _export_names(nested) if isinstance(nested, dict) else set()
    nested_contracts = (
        _match_contracts(nested_names, lambda pattern: [], table)
        if nested_names
        else []
    )
    block: dict[str, Any] = {}
    if contracts:
        block["contracts"] = contracts
    if primary_read_failed:
        # The primary export listing is unreadable: any contract set above
        # speaks only for what lief still surfaced, so a cleanly read
        # nested listing takes over and the scope says so. With neither,
        # there is no block - the gap is carried by exports_read_status
        # and the analysis_coverage degradation instead of by a silent
        # "not a plugin" (rules 14/32).
        if nested_contracts:
            block["contracts"] = nested_contracts
            block["host_plugin_scope"] = "nested_binary"
        elif contracts:
            block["host_plugin_scope"] = "partial_export_listing"
        else:
            return None
    elif contracts and nested_contracts:
        primary_ids = {c["id"] for c in contracts}
        nested_ids = {c["id"] for c in nested_contracts}
        variance = sorted(primary_ids ^ nested_ids)
        if variance:
            block["host_plugin_slice_variance"] = variance
    return block if block.get("contracts") else None
