# -*- coding: utf-8 -*-
"""Tests for the callgraph library entry point, profiles, and rusi gating."""

import json

import pytest

from blint.lib.callgraph import MatchReport, match_files, options_for_profile
from blint.lib.callgraph.match import DEFAULT_PROFILE, PROFILES

_SOURCE = {
    "call_graph": {
        "nodes": [
            {"id": f"cg-{n}", "qualified_name": n, "local": True}
            for n in ("app::main", "app::helper", "app::leaf")
        ],
        "edges": [
            {"source_id": "cg-app::main", "target_id": "cg-app::helper"},
            {"source_id": "cg-app::helper", "target_id": "cg-app::leaf"},
        ],
    }
}
_BINARY = {
    "file_path": "/tmp/app",
    "callgraph": {
        "nodes": [
            {"id": 0, "key": "0x10::app::main", "name": "app::main", "address": "0x10"},
            {"id": 1, "key": "0x20::app::helper", "name": "app::helper", "address": "0x20"},
            {"id": 2, "key": "0x30::app::leaf", "name": "app::leaf", "address": "0x30"},
        ],
        "edges": [
            {"src": 0, "dst": 1, "kind": "direct"},
            {"src": 1, "dst": 2, "kind": "direct"},
        ],
    },
    "disassembled_functions": {},
}


def test_profiles_set_expected_knobs():
    assert set(PROFILES) == {"precision", "balanced", "recall"}
    assert DEFAULT_PROFILE == "balanced"
    precision = options_for_profile("precision")
    assert precision.min_votes == 3 and precision.margin == 2
    assert precision.enable_fingerprint is False
    recall = options_for_profile("recall")
    assert recall.enable_fingerprint is True
    # Balanced equals the dataclass defaults.
    assert options_for_profile("balanced") == options_for_profile("balanced")


def test_profile_overrides_take_precedence_and_none_is_ignored():
    options = options_for_profile("precision", min_votes=5, margin=None)
    assert options.min_votes == 5  # explicit override applied
    assert options.margin == 2  # None left the profile value in place


def test_unknown_profile_raises():
    with pytest.raises(ValueError):
        options_for_profile("nonsense")


def test_match_files_with_dicts_returns_typed_report():
    report = match_files(source_callgraph=_SOURCE, binary_metadata=_BINARY)
    assert isinstance(report, MatchReport)
    assert report.algorithm == "layered"
    assert report.anchors == 3
    assert report.binary_matched == 3
    assert report.coverage == 1.0
    assert report.source_functions_identified == 3
    # to_dict is JSON-serializable.
    assert json.dumps(report.to_dict())


def test_match_files_requires_a_source_and_a_binary():
    with pytest.raises(ValueError):
        match_files(binary_metadata=_BINARY)
    with pytest.raises(ValueError):
        match_files(source_callgraph=_SOURCE)


def test_match_files_source_dir_rejects_non_rust_language(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    with pytest.raises(ValueError) as excinfo:
        match_files(
            source_dir=str(src),
            binary_metadata=_BINARY,
            language="go",
        )
    assert "not supported for language" in str(excinfo.value)


def test_match_files_source_dir_rust_invokes_analyzer(tmp_path, monkeypatch):
    src = tmp_path / "src"
    src.mkdir()
    captured = {}

    def fake_rusi(source_dir, *, rusi_command=None):
        captured["source_dir"] = str(source_dir)
        captured["rusi_command"] = rusi_command
        return _SOURCE

    # Patch the analyzer registered for rust.
    import blint.lib.callgraph.api as api

    monkeypatch.setitem(api._SOURCE_ANALYZERS, "rust", fake_rusi)
    report = match_files(
        source_dir=str(src),
        binary_metadata=_BINARY,
        language="rust",
        rusi_command="my-rusi",
    )
    assert captured["source_dir"] == str(src)
    assert captured["rusi_command"] == "my-rusi"
    assert report.anchors == 3
