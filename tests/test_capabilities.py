"""Tests for the capability catalog (``blint capabilities``, D4).

The catalog is generated from the engine's own loaded rule state, so these
tests pin the invariants that keep it honest: uniqueness, dispatchability,
and the known duplicate-id set (recorded, not silently tolerated).
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from blint.lib import analysis as analysis_mod
from blint.lib.capabilities import (
    DISASSEMBLY_EVIDENCE_RULE_IDS,
    build_capability_index,
)

_REPO_ROOT = Path(__file__).resolve().parent.parent


def _cli_env():
    env = dict(os.environ)
    env["PYTHONPATH"] = str(_REPO_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    return env


# Rule ids defined in more than one annotation file today. Every entry is a
# deliberate capability reuse (the same id applied to different exe_types
# or evidence sources). The test exists so a new duplicate — or the removal
# of one — is a conscious, reviewed change rather than silent drift.
KNOWN_DUPLICATE_IDS = {
    "AUDIO_ACCESS_API",
    "BUNDLED_PYTHON",
    "CLIPBOARD_ACCESS_API",
    "C_C_LIB",
    "EXEC_METHODS",
    "FFMPEG_LIB",
    "FILE_IO_READ",
    "FILE_IO_WRITE",
    "GIT_METHODS",
    "HTTP_METHODS",
    "NET_METHODS",
    "RPC_METHODS",
    "SDL_LIB",
    "VIDEO_ACCESS_API",
    "WEAK_CRYPTO",
    "WEB_SOCKET_API",
}


@pytest.fixture(scope="module")
def index():
    return build_capability_index()


def _by_kind(index, kind):
    return [e for e in index["capabilities"] if e["kind"] == kind]


def test_index_counts_match_capabilities(index):
    assert index["counts"]["checks"] == len(_by_kind(index, "check"))
    assert index["counts"]["reviews"] == len(_by_kind(index, "review"))


def test_all_ids_unique(index):
    ids = [e["id"] for e in index["capabilities"]]
    assert len(ids) == len(set(ids))


def test_check_count_and_engine_parity(index):
    """The catalog's checks are exactly the rules the engine dispatches."""
    checks = _by_kind(index, "check")
    assert len(checks) == 28  # rules.yml today (24 + the four provisioning/objc-load rules)
    assert {e["id"] for e in checks} == set(analysis_mod.rules_dict)


def test_every_check_id_resolves_to_a_dispatchable_function(index):
    """run_rule looks the check up by id in the analysis module namespace;
    a rules.yml entry with no such function can never fire (dead rule)."""
    dead = [
        e["id"]
        for e in _by_kind(index, "check")
        if not getattr(analysis_mod, str(e["id"]).lower(), None)
    ]
    assert not dead


def test_every_engine_review_id_is_catalogued(index):
    """No review the engine can emit is missing from the catalog."""
    catalogued = {e["id"] for e in _by_kind(index, "review")}
    engine_ids = set(analysis_mod.review_rules_cache)
    for target in analysis_mod.REVIEW_GROUP_TARGETS.values():
        for rule_maps in target.values():
            for rule_map in rule_maps:
                engine_ids |= set(rule_map)
    assert catalogued == engine_ids
    # The two code-seeded reviews are catalogued and marked builtin.
    for builtin in ("PII_READ", "LOADER_SYMBOLS"):
        entry = next(e for e in _by_kind(index, "review") if e["id"] == builtin)
        assert entry["source_files"] == ["(builtin)"]
        assert entry["evidence_source"] == ["special_symbols"]


def test_duplicate_rule_ids_are_pinned(index):
    duplicated = {e["id"] for e in index["capabilities"] if len(e.get("source_files") or []) > 1}
    assert duplicated == KNOWN_DUPLICATE_IDS


def test_requires_disassemble_mapping(index):
    """requires_disassemble is True exactly for FUNCTION_REVIEWS rules and
    the BINARY_REVIEWS rules whose evaluators read disassembly-derived
    metadata; everything else runs on parse output alone."""
    flagged = {
        e["id"]
        for e in index["capabilities"]
        if e["requires_disassemble"] and "FUNCTION_REVIEWS" in (e.get("groups") or [])
    }
    all_function_reviews = {
        e["id"] for e in index["capabilities"] if "FUNCTION_REVIEWS" in (e.get("groups") or [])
    }
    assert flagged == all_function_reviews

    binary_review_ids = {
        e["id"] for e in index["capabilities"] if "BINARY_REVIEWS" in (e.get("groups") or [])
    }
    flagged_binary_reviews = {
        e["id"]
        for e in index["capabilities"]
        if e["requires_disassemble"] and "BINARY_REVIEWS" in (e.get("groups") or [])
    }
    assert flagged_binary_reviews == DISASSEMBLY_EVIDENCE_RULE_IDS & binary_review_ids
    assert flagged_binary_reviews  # the frozen set stays real

    for entry in _by_kind(index, "check"):
        assert entry["requires_disassemble"] is False


def test_index_is_deterministic():
    assert build_capability_index() == build_capability_index()


def test_entries_are_well_formed(index):
    for entry in index["capabilities"]:
        assert entry["id"] and entry["title"]
        assert isinstance(entry["evidence_source"], list) and entry["evidence_source"]
        assert isinstance(entry["exe_types"], list)
        assert isinstance(entry["requires_disassemble"], bool)
        assert entry["source_files"]


def test_capabilities_cli_json_matches_in_process_index(index):
    env = _cli_env()
    proc = subprocess.run(
        [sys.executable, "-m", "blint.cli", "capabilities", "--json"],
        capture_output=True,
        check=True,
        env=env,
        cwd=str(_REPO_ROOT),
    )
    payload = json.loads(proc.stdout)
    assert payload == index


def test_capabilities_cli_table_exits_zero():
    proc = subprocess.run(
        [sys.executable, "-m", "blint.cli", "capabilities"],
        capture_output=True,
        check=True,
        env=_cli_env(),
        cwd=str(_REPO_ROOT),
    )
    assert proc.stdout
