"""Tests for the F0 measurement instrument (tests/scripts/fp_gate.py).

These tests exercise the derived-file partition on plain dicts: no corpus,
no blint run and no filesystem semantics are involved, so they hold on every
platform.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve().parent / "scripts" / "fp_gate.py"

spec = importlib.util.spec_from_file_location("fp_gate", SCRIPT_PATH)
fp_gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fp_gate)


CLASSIFICATIONS = {
    "macho/dyld-arm64e/libA.dylib": ("Mach-O", "arm64e"),
    "macho/dyld-arm64e/libB.dylib": ("Mach-O", "arm64e"),
    "macho/apple-usr-lib/libC.dylib": ("Mach-O", "arm64"),
}


def build(entries, findings):
    by_path = {entry["path"]: entry for entry in entries}
    pairs = [(finding, by_path[finding["_entry"]]) for finding in findings]
    return fp_gate.build_report(entries, CLASSIFICATIONS, pairs, [], "file-test")


def test_codesign_on_derived_file_is_excluded_from_the_headline():
    entries = [
        {"path": "macho/dyld-arm64e/libA.dylib", "tier": "tier0", "derived": "dyld-cache-extraction"},
        {"path": "macho/apple-usr-lib/libC.dylib", "tier": "tier0"},
    ]
    findings = [
        {"id": "CHECK_CODESIGN", "severity": "high", "_entry": "macho/dyld-arm64e/libA.dylib"},
        {"id": "CHECK_CODESIGN", "severity": "high", "_entry": "macho/apple-usr-lib/libC.dylib"},
    ]
    report = build(entries, findings)
    # The derived codesign finding left the headline; the on-disk one stayed,
    # because it says something about the artifact and not the extraction.
    assert report["tool"]["findings"] == 1
    assert report["tool"]["excluded_derived_findings"] == 1
    assert report["derived"]["files"] == 1
    assert report["derived"]["kinds"] == {"dyld-cache-extraction": 1}
    assert report["derived"]["findings_per_rule"] == {"CHECK_CODESIGN": 1}
    assert report["derived"]["excluded_rules"] == ["CHECK_CODESIGN"]
    assert report["per_file"] == {"macho/apple-usr-lib/libC.dylib": 1}


def test_other_rules_on_derived_files_stay_in_the_headline():
    # Only extraction-sensitive rules are excluded; a rule whose answer
    # survives extraction (symbols, sections, header flags) stays even when
    # the file is derived.
    entries = [
        {"path": "macho/dyld-arm64e/libA.dylib", "tier": "tier0", "derived": "dyld-cache-extraction"},
        {"path": "macho/dyld-arm64e/libB.dylib", "tier": "tier0", "derived": "dyld-cache-extraction"},
    ]
    findings = [
        {"id": "CHECK_CODESIGN", "severity": "high", "_entry": "macho/dyld-arm64e/libA.dylib"},
        {"id": "CHECK_CANARY", "severity": "medium", "_entry": "macho/dyld-arm64e/libB.dylib"},
    ]
    report = build(entries, findings)
    assert report["tool"]["findings"] == 1
    assert report["findings_per_rule"] == {"CHECK_CANARY": 1}
    assert report["derived"]["findings_per_rule"] == {
        "CHECK_CODESIGN": 1,
        "CHECK_CANARY": 1,
    }
    assert report["per_file"] == {"macho/dyld-arm64e/libB.dylib": 1}


def test_manifest_without_derived_keys_is_unchanged():
    entries = [
        {"path": "macho/apple-usr-lib/libC.dylib", "tier": "tier0"},
    ]
    findings = [
        {"id": "CHECK_CODESIGN", "severity": "high", "_entry": "macho/apple-usr-lib/libC.dylib"},
    ]
    report = build(entries, findings)
    assert report["tool"]["findings"] == 1
    assert report["tool"]["excluded_derived_findings"] == 0
    assert report["derived"]["files"] == 0
    assert report["findings_per_rule"] == {"CHECK_CODESIGN": 1}
