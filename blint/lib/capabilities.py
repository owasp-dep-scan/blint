"""Machine-readable catalog of what blint can detect (D4).

The index is generated from the rule state the engine itself loads —
``initialize_rules`` plus the module globals in ``blint.lib.analysis`` —
and never opens a YAML file of its own. There is deliberately no second
YAML reader here: a catalog built from a parallel walk of the same files
would agree with the engine on the day it was written and drift silently
afterwards.

Side effect to know about: ``build_capability_index`` re-initializes the
module-global rule state to the built-in catalog (that is how it reads a
known-good load). In the CLI subcommand that is fine; in a long-running
process that loaded custom rules, call it knowing it resets them.
"""

from __future__ import annotations

from typing import Any

from blint.config import BlintOptions
from blint.lib.analysis import (
    _REVIEW_RULE_SOURCES,
    _review_group_targets,
    initialize_rules,
    review_rules_cache,
    rules_dict,
)
from blint.logger import LOG

# Evidence source per review group, named for the metadata the group's
# runner actually reads (see ReviewRunner): METHOD/EXE reviews match
# function and symbol names plus informative strings, SYMBOL reviews the
# symbol tables, and so on.
GROUP_EVIDENCE_SOURCES: dict[str, str] = {
    "METHOD_REVIEWS": "functions",
    "EXE_REVIEWS": "functions",
    "SYMBOL_REVIEWS": "symbols",
    "IMPORT_REVIEWS": "imports",
    "ENTRIES_REVIEWS": "dynamic_entries",
    "FUNCTION_REVIEWS": "disassembled_functions",
    "BINARY_REVIEWS": "binary_metadata",
}

# BINARY_REVIEWS rules whose evaluators can only produce evidence from
# disassembly-derived metadata, so an agent must pass --disassemble for the
# rule to be able to fire at all. This is the one catalog field derived
# from evaluator code rather than from the YAML; the code sites, as of the
# set being written:
# - BYOVD_EXPLOIT_CLIENT_DEVICE_ACCESS: collect_client_ioctls over
#   disassembled_functions (binary_reviews.py).
# - DRIVER_IOCTL_WEAK_DECLARED_ACCESS / DRIVER_IOCTL_METHOD_NEITHER:
#   metadata["driver_ioctls"] is only populated on the disassembly path
#   (binary.py).
# - CUSTOM_COMMAND_DISPATCH_TABLE: iterates disassembled_functions
#   (implant_reviews.py).
# - PE_HOST_PROCESS_NAME_GATE / RUNTIME_CONSTRUCTED_SECURITY_STRINGS:
#   evidence comes only from stack_strings, which the parser emits on the
#   disassembly path (implant_reviews.py, binary.py).
DISASSEMBLY_EVIDENCE_RULE_IDS: frozenset[str] = frozenset(
    {
        "BYOVD_EXPLOIT_CLIENT_DEVICE_ACCESS",
        "DRIVER_IOCTL_WEAK_DECLARED_ACCESS",
        "DRIVER_IOCTL_METHOD_NEITHER",
        "CUSTOM_COMMAND_DISPATCH_TABLE",
        "PE_HOST_PROCESS_NAME_GATE",
        "RUNTIME_CONSTRUCTED_SECURITY_STRINGS",
    }
)

CHECKS_SOURCE = "rules.yml"
CHECKS_EVIDENCE_SOURCE = "metadata"


def _entry(kind: str, rule: dict[str, Any]) -> dict[str, Any]:
    entry = {
        "kind": kind,
        "id": rule.get("id"),
        "title": rule.get("title"),
    }
    for optional in ("summary", "severity", "description"):
        if rule.get(optional) is not None:
            entry[optional] = rule.get(optional)
    return entry


def build_capability_index() -> dict[str, Any]:
    """Build the capability catalog from the engine's loaded rule state."""
    initialize_rules(BlintOptions())
    capabilities: list[dict[str, Any]] = []

    # Checks: dispatched per rule id from rules.yml against parsed metadata.
    for rule_id, rule_obj in rules_dict.items():
        entry = _entry("check", rule_obj)
        entry["evidence_source"] = [CHECKS_EVIDENCE_SOURCE]
        entry["groups"] = []
        entry["exe_types"] = sorted(rule_obj.get("exe_types") or [])
        entry["requires_disassemble"] = False
        entry["source_files"] = [CHECKS_SOURCE]
        capabilities.append(entry)

    # Reviews: aggregate per rule id across the group dicts. Ids reused in
    # several files (they exist today — see the catalog test) collapse to
    # one entry with the union of groups and exe_types; the display fields
    # come from review_rules_cache, the last-registered variant, which is
    # exactly what the engine's process_review emits for the id.
    aggregated: dict[str, dict[str, Any]] = {}
    for group, target_dict in sorted(_review_group_targets().items()):
        for exe_type, rule_maps in sorted(target_dict.items()):
            for rule_map in rule_maps:
                for rule_id in rule_map:
                    record = aggregated.setdefault(rule_id, {"groups": set(), "exe_types": set()})
                    record["groups"].add(group)
                    record["exe_types"].add(exe_type)
    for rule_id, record in aggregated.items():
        rule = review_rules_cache.get(rule_id) or {"id": rule_id}
        entry = _entry("review", rule)
        entry["evidence_source"] = sorted(
            {GROUP_EVIDENCE_SOURCES.get(g, g) for g in record["groups"]}
        )
        entry["groups"] = sorted(record["groups"])
        entry["exe_types"] = sorted(record["exe_types"])
        entry["requires_disassemble"] = "FUNCTION_REVIEWS" in record["groups"] or (
            rule_id in DISASSEMBLY_EVIDENCE_RULE_IDS
        )
        entry["source_files"] = sorted(_REVIEW_RULE_SOURCES.get(rule_id) or [])
        capabilities.append(entry)

    # Reviews seeded in code rather than YAML: ids present in the cache but
    # registered under no group. PII_READ and LOADER_SYMBOLS today; if a
    # YAML rule disappears from every group it would land here too, which
    # is the honest place for it.
    builtin_ids = sorted(set(review_rules_cache) - set(aggregated))
    for rule_id in builtin_ids:
        rule = review_rules_cache.get(rule_id) or {}
        entry = _entry("review", rule)
        entry["evidence_source"] = ["special_symbols"]
        entry["groups"] = []
        entry["exe_types"] = []
        entry["requires_disassemble"] = False
        entry["source_files"] = ["(builtin)"]
        capabilities.append(entry)

    capabilities.sort(key=lambda e: (e["kind"], e["id"] or ""))
    return {
        "schema_version": 1,
        "counts": {
            "checks": sum(1 for e in capabilities if e["kind"] == "check"),
            "reviews": sum(1 for e in capabilities if e["kind"] == "review"),
            "requires_disassemble": sum(1 for e in capabilities if e["requires_disassemble"]),
        },
        "capabilities": capabilities,
    }


def render_capabilities_table(index: dict[str, Any]) -> None:
    """Print the catalog as a rich table (the non---json CLI rendering)."""
    from rich.box import ROUNDED
    from rich.table import Table

    from blint.logger import console

    counts = index.get("counts") or {}
    table = Table(
        box=ROUNDED,
        title=(
            f"blint capabilities — {counts.get('checks', 0)} checks, "
            f"{counts.get('reviews', 0)} reviews, "
            f"{counts.get('requires_disassemble', 0)} need --disassemble"
        ),
    )
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Kind", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Evidence", no_wrap=True)
    table.add_column("Disasm", no_wrap=True)
    table.add_column("exe_types", overflow="fold")
    for entry in index.get("capabilities") or []:
        table.add_row(
            str(entry.get("id")),
            entry.get("kind", ""),
            str(entry.get("severity") or "-"),
            ", ".join(entry.get("evidence_source") or []),
            "yes" if entry.get("requires_disassemble") else "",
            ", ".join(entry.get("exe_types") or []),
        )
    console.print(table)
    duplicated = _duplicated_ids(index)
    if duplicated:
        LOG.warning(
            f"{len(duplicated)} rule ids are defined in more than one source file: "
            + ", ".join(duplicated)
        )


def _duplicated_ids(index: dict[str, Any]) -> list[str]:
    return sorted(
        entry.get("id")
        for entry in index.get("capabilities") or []
        if len(entry.get("source_files") or []) > 1
    )
