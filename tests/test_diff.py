"""Tests for ``blint diff`` (D1 / P4.4): pairing semantics, hardening
polarity, layer deltas, mirror determinism, and the stripped/unstripped
ground truth."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from blint.lib.diff import (
    LIST_LIMIT,
    DiffError,
    _classify_hardening,
    _findings_delta,
    _function_delta,
    _imports_delta,
    _reviews_delta,
    _sections_delta,
    _symbol_table_delta,
    diff_binary_metadata,
    load_side,
)

_REPO_ROOT = Path(__file__).resolve().parent.parent
_CORPUS_DIR = _REPO_ROOT / "corpus-build"
GO_ELF = _CORPUS_DIR / "go-elf-unstripped"
GO_ELF_STRIPPED = _CORPUS_DIR / "go-elf-stripped"
STACKSTR_ARM64 = _CORPUS_DIR / "stackstr-arm64"
STACKSTR_ARM64_STRIPPED = _CORPUS_DIR / "stackstr-arm64-stripped"

needs_corpus = pytest.mark.skipif(
    not GO_ELF.exists() or not GO_ELF_STRIPPED.exists(),
    reason="corpus fixtures go-elf-unstripped / go-elf-stripped not built",
)
needs_stackstr = pytest.mark.skipif(
    not STACKSTR_ARM64.exists() or not STACKSTR_ARM64_STRIPPED.exists(),
    reason="corpus fixtures stackstr-arm64 / -stripped not built",
)


# ---------------------------------------------------------------------------
# Helpers to build synthetic sides


def _meta(**overrides) -> dict:
    """A minimal comparable metadata dict with every knob overridable."""
    metadata = {
        "exe_type": "genericbinary",
        "binary_type": "ELF",
        "machine_type": "X86_64",
        "name": "demo",
        "hashes": {"sha256": "a" * 64},
        "security_properties": {
            "nx": True,
            "pie": True,
            "canary": True,
            "relro": "full",
            "stripped": False,
            "packed": False,
            "is_signed": False,
        },
        "functions": [],
        "import_hash": "",
    }
    metadata.update(overrides)
    return metadata


def _write_meta(directory: Path, metadata: dict) -> str:
    target = directory / "side-metadata.json"
    target.write_text(json.dumps(metadata), encoding="utf-8")
    return str(target)


def _mkdir(tmp_path: Path, name: str) -> Path:
    target = tmp_path / name
    target.mkdir(exist_ok=True)
    return target


# ---------------------------------------------------------------------------
# The cross-version pairing decision


def test_pairing_key_ignores_what_finding_id_folds_in():
    """The pairing key must be invariant to the binary identity that the
    stable finding_id deliberately folds in: two rebuilds of one binary
    share no finding_id but pair their findings."""
    from blint.lib.finding_ids import compute_finding_id, compute_finding_pairing_key

    old_id = compute_finding_id("CHECK_PIE", "a" * 64, "")
    new_id = compute_finding_id("CHECK_PIE", "b" * 64, "")
    assert old_id != new_id, "finding_id must change across rebuilds by design"
    assert compute_finding_pairing_key("CHECK_PIE", "") == compute_finding_pairing_key(
        "CHECK_PIE", ""
    ), "pairing key must be the same across rebuilds"
    assert compute_finding_pairing_key("CHECK_PIE", "") != compute_finding_pairing_key(
        "CHECK_NX", ""
    )
    assert compute_finding_pairing_key("W", '{"f":1}') != compute_finding_pairing_key(
        "W", '{"f":2}'
    )
    # And the two schemes must never collide, even by accident.
    assert compute_finding_pairing_key("CHECK_PIE", "") != old_id


def test_pairing_keys_are_unique_within_a_side_and_pair_across_sides():
    from blint.lib.finding_ids import attach_pairing_keys

    findings = [
        {"id": "W", "evidence": {"f": 1}},
        {"id": "W", "evidence": {"f": 1}},  # repeat: occurrence-disambiguated
        {"id": "W", "evidence": {"f": 2}},
    ]
    index = attach_pairing_keys(findings)
    assert len(index) == 3, "repeats must not collapse"
    # The Nth repeat pairs with the Nth repeat, mirroring attach_finding_ids.
    same_evidence = [f for f in findings if f["evidence"] == {"f": 1}]
    assert same_evidence[0]["pairing_key"] != same_evidence[1]["pairing_key"]


def test_findings_pair_across_versions_instead_of_removed_and_added():
    """The headline consequence of the pairing decision: the same check
    firing on both versions is one unchanged finding, not a removal plus an
    addition, even though the two sides have different binary identities."""
    old = [{"id": "CHECK_PIE", "severity": "high"}, {"id": "CHECK_NX", "severity": "high"}]
    new = [{"id": "CHECK_PIE", "severity": "high"}]
    delta = _findings_delta(old, new)
    assert delta["removed"] == [d for d in delta["removed"] if d["rule"] != "CHECK_PIE"]
    assert [row["rule"] for row in delta["removed"]] == ["CHECK_NX"]
    assert delta["added"] == []
    assert delta["unchanged_count"] == 1


def test_findings_report_severity_change_on_a_paired_finding():
    delta = _findings_delta([{"id": "R", "severity": "medium"}], [{"id": "R", "severity": "high"}])
    assert delta["added"] == [] and delta["removed"] == []
    assert len(delta["severity_changed"]) == 1
    assert delta["severity_changed"][0]["severity_old"] == "medium"
    assert delta["severity_changed"][0]["severity_new"] == "high"


def test_repeated_findings_pair_positionally_across_versions():
    old = [{"id": "W", "evidence": {"f": 1}}, {"id": "W", "evidence": {"f": 1}}]
    new = [{"id": "W", "evidence": {"f": 1}}, {"id": "W", "evidence": {"f": 1}}]
    delta = _findings_delta(old, new)
    assert delta["unchanged_count"] == 2 and not delta["added"] and not delta["removed"]
    dropped_second = _findings_delta(old, new[:1])
    assert dropped_second["removed_count"] == 1


def test_reviews_pair_by_rule_and_flag_evidence_changes():
    old = [{"id": "ENV", "title": "t", "summary": "s", "evidence": [{"pattern": "getenv"}]}]
    same = [{**old[0], "evidence": [{"pattern": "getenv"}]}]
    changed_evidence = [
        {
            "id": "ENV",
            "title": "t",
            "summary": "s",
            "evidence": [{"pattern": "getenv"}, {"pattern": "setenv"}],
        }
    ]
    assert _reviews_delta(old, same)["unchanged_count"] == 1
    delta = _reviews_delta(old, changed_evidence)
    assert delta["unchanged_count"] == 0
    assert [row["rule"] for row in delta["evidence_changed"]] == ["ENV"]


# ---------------------------------------------------------------------------
# Input loading and comparability


def test_load_side_reads_metadata_json(tmp_path):
    side = load_side(str(_write_meta(tmp_path, _meta())))
    assert side.kind == "metadata-json"
    assert side.metadata["exe_type"] == "genericbinary"


def test_load_side_refuses_json_without_exe_type(tmp_path):
    bogus = tmp_path / "not-metadata.json"
    bogus.write_text('{"hello": "world"}', encoding="utf-8")
    with pytest.raises(DiffError, match="exe_type"):
        load_side(str(bogus))


def test_load_side_refuses_missing_path_and_directory(tmp_path):
    with pytest.raises(DiffError, match="does not exist"):
        load_side(str(tmp_path / "nope.bin"))
    with pytest.raises(DiffError, match="directory"):
        load_side(str(tmp_path))


def test_load_side_refuses_unparseable_binary(tmp_path):
    text = tmp_path / "plain.txt"
    text.write_text("definitely not a binary", encoding="utf-8")
    with pytest.raises(DiffError, match="not a binary format"):
        load_side(str(text))


def test_diff_refuses_different_exe_types(tmp_path):
    old_p = _write_meta(_mkdir(tmp_path, "old"), _meta(exe_type="gobinary"))
    new_p = _write_meta(_mkdir(tmp_path, "new"), _meta(exe_type="MachO"))
    with pytest.raises(DiffError, match="not comparable.*exe_type"):
        diff_binary_metadata(str(old_p), str(new_p))


def test_diff_refuses_different_architectures(tmp_path):
    old_p = _write_meta(_mkdir(tmp_path, "old"), _meta(machine_type="X86_64"))
    new_p = _write_meta(_mkdir(tmp_path, "new"), _meta(machine_type="AARCH64"))
    with pytest.raises(DiffError, match="not comparable.*architecture"):
        diff_binary_metadata(str(old_p), str(new_p))


# ---------------------------------------------------------------------------
# Hardening polarity (the explicit table)


def test_hardening_polarity_table():
    # Losing protection is a regression; gaining it an improvement.
    assert _classify_hardening("nx", True, False) == ("regression", "hardening")
    assert _classify_hardening("canary", True, False) == ("regression", "hardening")
    assert _classify_hardening("pie", False, True) == ("improvement", "hardening")
    # Risk properties flip: gaining packed or get-task-allow is a regression.
    assert _classify_hardening("packed", False, True) == ("regression", "risk")
    assert _classify_hardening("get_task_allow", False, True) == ("regression", "risk")
    # stripped is observable, never a security regression.
    assert _classify_hardening("stripped", False, True) == ("change", "observe")
    # relro is ordered: any step down is a regression.
    assert _classify_hardening("relro", "full", "partial") == ("regression", "ordered")
    assert _classify_hardening("relro", "partial", "no") == ("regression", "ordered")
    assert _classify_hardening("relro", "no", "full") == ("improvement", "ordered")
    # Unknown polarity is never classified from truthiness.
    assert _classify_hardening("some_future_property", False, True) == ("change", "unknown")
    # A side that did not report the property cannot claim gain or loss.
    assert _classify_hardening("pie", None, False) == ("change", "hardening")


def test_pie_loss_is_a_regression_end_to_end(tmp_path):
    old_p = _write_meta(_mkdir(tmp_path, "old"), _meta(is_pie=True))
    new_p = _write_meta(
        _mkdir(tmp_path, "new"),
        _meta(
            hashes={"sha256": "b" * 64},
            is_pie=False,
            security_properties={**_meta()["security_properties"], "pie": False},
        ),
    )
    report = diff_binary_metadata(str(old_p), str(new_p))
    hardening = report["hardening"]
    assert hardening["regression_count"] == 1
    change = hardening["changes"][0]
    assert (change["property"], change["old"], change["new"]) == ("pie", True, False)
    assert change["classification"] == "regression"
    assert report["summary"]["hardening_regressions"] == 1
    # And the findings layer agrees: the new side gains CHECK_PIE.
    assert [row["rule"] for row in report["findings"]["added"]] == ["CHECK_PIE"]
    assert [row["rule"] for row in report["findings"]["removed"]] == []


# ---------------------------------------------------------------------------
# Import-layer honesty (the empty-import_hash traps)


def test_empty_vs_empty_imports_is_not_claimed_unchanged():
    static = _meta(import_hash="")
    assert _imports_delta(static, {**static, "hashes": {"sha256": "b" * 64}})["status"] == (
        "no_import_evidence"
    )


def test_empty_vs_populated_imports_is_not_a_replacement():
    empty = _meta(import_hash="")
    populated = _meta(
        import_hash="deadbeefdeadbeef",
        import_dependencies={
            "libraries": {
                "libc.so": {"type": "imported", "imported_symbols": ["printf", "malloc"]}
            }
        },
    )
    delta = _imports_delta(empty, populated)
    assert delta["status"] == "present_only_on_new"
    assert delta["added_count"] == 2
    assert delta["import_hash_changed"] is None, "no claim when a side has no import hash"
    reverse = _imports_delta(populated, empty)
    assert reverse["status"] == "present_only_on_old"
    assert reverse["removed_count"] == 2


def test_import_delta_reports_symbol_changes_and_hash():
    a = _meta(
        import_hash="1" * 16,
        import_dependencies={"libraries": {"libc.so": {"imported_symbols": ["printf"]}}},
    )
    b = _meta(
        import_hash="2" * 16,
        import_dependencies={"libraries": {"libc.so": {"imported_symbols": ["printf", "read"]}}},
    )
    delta = _imports_delta(a, b)
    assert delta["status"] == "compared"
    assert delta["added"] == ["read"]
    assert delta["removed"] == []
    assert delta["import_hash_changed"] is True


# ---------------------------------------------------------------------------
# Other metadata layers


def test_dependencies_absent_on_both_sides_is_not_claimed_unchanged(tmp_path):
    old_p = _write_meta(_mkdir(tmp_path, "old"), _meta(libraries=None, dynamic_entries=[]))
    new_p = _write_meta(_mkdir(tmp_path, "new"), _meta(libraries=None, dynamic_entries=[]))
    report = diff_binary_metadata(str(old_p), str(new_p))
    assert report["dependencies"] == {"status": "no_dependency_evidence"}


def test_dependency_add_and_remove(tmp_path):
    old_p = _write_meta(_mkdir(tmp_path, "old"), _meta(libraries=[{"name": "liba.so"}]))
    new_p = _write_meta(
        _mkdir(tmp_path, "new"),
        _meta(libraries=[{"name": "libb.so"}, {"name": "liba.so"}], hashes={"sha256": "b" * 64}),
    )
    report = diff_binary_metadata(str(old_p), str(new_p))
    deps = report["dependencies"]
    assert deps["added"] == ["libb.so"] and deps["removed"] == []
    assert report["summary"]["dependencies_added"] == 1


def test_section_delta_reports_entropy_shift_and_size_change():
    old = _meta(
        entropy={
            "sections": [
                {"name": ".text", "size": 100, "entropy": 6.0},
                {"name": ".data", "size": 50, "entropy": 2.0},
                {"name": ".gone", "size": 10, "entropy": 1.0},
            ]
        }
    )
    new = _meta(
        entropy={
            "sections": [
                {"name": ".text", "size": 100, "entropy": 6.9},
                {"name": ".data", "size": 80, "entropy": 2.0},
                {"name": ".new", "size": 5, "entropy": 3.0},
            ]
        }
    )
    delta = _sections_delta(old, new)
    assert delta["added"] == [".new"] and delta["removed"] == [".gone"]
    shifted = {entry["name"]: entry for entry in delta["shifted"]}
    assert shifted[".text"]["entropy_delta"] == pytest.approx(0.9)
    assert shifted[".data"]["entropy_delta"] == 0.0, "size-only change still reports"
    assert shifted[".data"]["size_old"] == 50 and shifted[".data"]["size_new"] == 80


def test_section_delta_stays_quiet_below_threshold():
    old = _meta(entropy={"sections": [{"name": ".text", "size": 100, "entropy": 6.0}]})
    new = _meta(entropy={"sections": [{"name": ".text", "size": 100, "entropy": 6.05}]})
    delta = _sections_delta(old, new)
    assert delta["shifted"] == []


def test_symbol_table_layer_ignores_synthetic_names_but_counts_them():
    old = _meta(
        functions=[
            {"name": "main", "address": "0x1"},
            {"name": "sub_410", "address": "0x2"},
        ]
    )
    new = _meta(functions=[{"name": "sub_999", "address": "0x2"}], hashes={"sha256": "b" * 64})
    delta = _symbol_table_delta(old, new)
    assert delta["functions_old_count"] == 2 and delta["functions_new_count"] == 1
    assert delta["removed"] == ["main"], "synthetic sub_* names are never listed"
    assert delta["added"] == []


def test_symbol_list_truncates_with_exact_counts():
    old = _meta(functions=[{"name": f"sym{i}", "address": "0x1"} for i in range(LIST_LIMIT + 10)])
    delta = _symbol_table_delta(old, _meta(hashes={"sha256": "b" * 64}))
    assert delta["removed_count"] == LIST_LIMIT + 10, "count stays exact"
    assert len(delta["removed"]) == LIST_LIMIT
    assert delta["truncated"] is True


def test_entitlement_delta(tmp_path):
    old = _meta(code_signature={"entitlements": {"com.apple.get-task-allow": True, "gone": 1}})
    new = _meta(code_signature={"entitlements": {"com.apple.get-task-allow": False, "fresh": 1}})
    old_p = _write_meta(_mkdir(tmp_path, "old"), old)
    new_p = _write_meta(_mkdir(tmp_path, "new"), new)
    report = diff_binary_metadata(str(old_p), str(new_p))
    ent = report["entitlements"]
    assert ent["added"] == {"fresh": 1}
    assert ent["removed"] == {"gone": 1}
    assert ent["changed"] == {"com.apple.get-task-allow": {"old": True, "new": False}}


def test_identity_and_toolchain_delta(tmp_path):
    old = _meta(toolchain={"linkers": [{"name": "ld", "version": "1"}], "libc": "glibc"})
    new = _meta(
        hashes={"sha256": "b" * 64},
        machine_type="AARCH64",
        toolchain={"linkers": [{"name": "ld", "version": "2"}], "libc": "musl"},
    )
    new_p = _write_meta(_mkdir(tmp_path, "new"), new)
    old_p = _write_meta(_mkdir(tmp_path, "old"), old)
    with pytest.raises(DiffError):
        # Different machine_type must be refused before identity is compared.
        diff_binary_metadata(str(old_p), str(new_p))
    same_arch = _write_meta(
        _mkdir(tmp_path, "same"),
        {**new, "machine_type": "X86_64"},
    )
    report = diff_binary_metadata(str(old_p), str(same_arch))
    identity = report["identity"]
    assert identity["file_sha256"]["old"] == "a" * 64
    assert set(identity["toolchain"]["added"]) == {"linkers:ld@2", "libc:musl"}
    assert set(identity["toolchain"]["removed"]) == {"linkers:ld@1", "libc:glibc"}
    assert "machine_type" not in identity["changed_fields"]


# ---------------------------------------------------------------------------
# Function-level layer


def _fn(name, fuzzy, *, asm=None, cfg_hash=None, instructions=None):
    return {
        "name": name,
        "fuzzy_hash": fuzzy,
        "assembly": asm,
        "cfg_hash": cfg_hash,
        "instruction_count": instructions,
    }


def test_function_layer_unavailable_is_named_not_empty():
    delta = _function_delta(_meta(), _meta(hashes={"sha256": "b" * 64}))
    assert delta["status"] == "unavailable"
    assert "old and new" in delta["reason"]


def test_function_layer_present_but_empty_is_a_compared_zero():
    delta = _function_delta({"disassembled_functions": {}}, {"disassembled_functions": {}})
    assert delta["status"] == "compared"
    assert delta["unchanged_count"] == 0 and delta["changed_count"] == 0


def test_function_layer_content_matches_renames_and_classifies_changes():
    old = {
        "disassembled_functions": {
            "a::main": _fn("main", "h1"),
            "a::helper": _fn("helper", "h2"),
            "a::rewritten": _fn(
                "rewritten",
                "h3old",
                asm="push rbp\nmov rax, 1\nret",
            ),
            "a::truncated": _fn("truncated", "h4old", asm="push rbp\nmov rax, 1\nret"),
            "a::gone": _fn("gone", "h5"),
            "a::hashless": _fn("hashless", ""),
        }
    }
    new = {
        "disassembled_functions": {
            "b::main_renamed": _fn("main_renamed", "h1"),  # same code, new name
            "b::helper": _fn("helper", "h2"),
            "b::rewritten": _fn("rewritten", "h3new", asm="push rbp\nxor rbx, rbx\nret"),
            "b::truncated": _fn("truncated", "h4new", asm="push rbp"),  # prefix of old
            "b::fresh": _fn("fresh", "h6"),
            "b::hashless": _fn("hashless", ""),
        }
    }
    delta = _function_delta(old, new)
    assert delta["status"] == "compared"
    assert delta["unchanged_count"] == 2, "renamed same-code functions are unchanged"
    assert delta["changed_count"] == 1 and delta["changed"][0]["name"] == "rewritten"
    assert delta["scope_changed_count"] == 1 and delta["scope_changed"][0]["name"] == "truncated"
    assert delta["unverifiable_names"] == ["hashless"]
    assert delta["added_names"] == ["fresh"] and delta["added_count"] == 1
    assert delta["removed_names"] == ["gone"] and delta["removed_count"] == 1
    # Counts reconcile on both sides.
    assert delta["old_count"] == 6 and delta["new_count"] == 6
    assert (
        delta["unchanged_count"]
        + delta["changed_count"]
        + delta["scope_changed_count"]
        + delta["unverifiable_count"]
        + delta["removed_count"]
        == delta["old_count"]
    )
    assert (
        delta["unchanged_count"]
        + delta["changed_count"]
        + delta["scope_changed_count"]
        + delta["unverifiable_count"]
        + delta["added_count"]
        == delta["new_count"]
    )


def test_function_boundary_move_is_not_a_code_change():
    """The stripped/unstripped discovery artifact: the same bytes read as a
    longer instruction run must not be reported as rewritten code."""
    old = {"disassembled_functions": {"a::f": _fn("f", "x1", asm="push rbp\nmov rax, 1\nret")}}
    new = {"disassembled_functions": {"a::f": _fn("f", "x2", asm="push rbp\nmov rax, 1")}}
    delta = _function_delta(old, new)
    assert delta["changed_count"] == 0
    assert delta["scope_changed_count"] == 1


# ---------------------------------------------------------------------------
# Report-level contracts: unchanged, mirror, determinism


def _mirror(report: dict) -> dict:
    """The report diff(new, old) must produce, by construction."""
    mirrored = json.loads(json.dumps(report))
    for header in ("old", "new"):
        mirrored[header], report[header] = report[header], mirrored[header]
    sha = mirrored["identity"].get("file_sha256")
    if sha:
        sha["old"], sha["new"] = sha["new"], sha["old"]
    for field_change in (mirrored["identity"].get("changed_fields") or {}).values():
        field_change["old"], field_change["new"] = field_change["new"], field_change["old"]
    tc = mirrored["identity"].get("toolchain")
    if tc:
        tc["added"], tc["removed"] = tc["removed"], tc["added"]
    for layer in ("dependencies", "imports", "exports"):
        target = mirrored.get(layer) or {}
        target["added"], target["removed"] = target.get("removed", []), target.get("added", [])
        target["added_count"], target["removed_count"] = (
            target.get("removed_count", 0),
            target.get("added_count", 0),
        )
    hardening = mirrored["hardening"]
    for change in hardening["changes"]:
        change["old"], change["new"] = change["new"], change["old"]
        if change["classification"] == "regression":
            change["classification"] = "improvement"
        elif change["classification"] == "improvement":
            change["classification"] = "regression"
    hardening["regression_count"], hardening["improvement_count"] = (
        hardening["improvement_count"],
        hardening["regression_count"],
    )
    findings = mirrored["findings"]
    findings["added"], findings["removed"] = findings["removed"], findings["added"]
    findings["added_count"], findings["removed_count"] = (
        findings["removed_count"],
        findings["added_count"],
    )
    reviews = mirrored.get("reviews") or {}
    if reviews:
        reviews["added"], reviews["removed"] = reviews["removed"], reviews["added"]
        reviews["added_count"], reviews["removed_count"] = (
            reviews["removed_count"],
            reviews["added_count"],
        )
    functions = mirrored["functions"]
    if functions.get("status") == "compared":
        functions["added_count"], functions["removed_count"] = (
            functions["removed_count"],
            functions["added_count"],
        )
        functions["added_names"], functions["removed_names"] = (
            functions["removed_names"],
            functions["added_names"],
        )
        functions["old_count"], functions["new_count"] = (
            functions["new_count"],
            functions["old_count"],
        )
    symbols = mirrored["symbols"]
    if symbols.get("added_count") is not None:
        symbols["added"], symbols["removed"] = symbols.get("removed", []), symbols.get("added", [])
        symbols["added_count"], symbols["removed_count"] = (
            symbols.get("removed_count", 0),
            symbols.get("added_count", 0),
        )
        symbols["functions_old_count"], symbols["functions_new_count"] = (
            symbols["functions_new_count"],
            symbols["functions_old_count"],
        )
    return mirrored


@pytest.mark.parametrize("seed", [0, 1])
def test_mirror_property_on_a_synthetic_pair(tmp_path, seed):
    old = _meta(
        libraries=[{"name": "liba.so"}],
        functions=[{"name": "main", "address": "0x1"}],
    )
    new = _meta(
        hashes={"sha256": "b" * 64},
        security_properties={**_meta()["security_properties"], "pie": False},
        libraries=[{"name": "liba.so"}, {"name": "libb.so"}],
        functions=[
            {"name": "main", "address": "0x1"},
            {"name": "extra", "address": "0x2"},
        ],
    )
    old_p = _write_meta(_mkdir(tmp_path, "old"), old)
    new_p = _write_meta(_mkdir(tmp_path, "new"), new)
    forward = diff_binary_metadata(str(old_p), str(new_p))
    backward = diff_binary_metadata(str(new_p), str(old_p))
    mirrored = _mirror(forward)
    assert backward["unchanged"] == forward["unchanged"] == False
    # Compare the parts the mirror function reconstructs exactly.
    assert backward["hardening"]["changes"] == mirrored["hardening"]["changes"]
    assert backward["hardening"]["regression_count"] == mirrored["hardening"]["regression_count"]
    assert backward["dependencies"]["added"] == mirrored["dependencies"]["added"]
    assert backward["dependencies"]["removed"] == mirrored["dependencies"]["removed"]
    assert backward["symbols"]["removed"] == mirrored["symbols"]["removed"]
    assert backward["symbols"]["added"] == mirrored["symbols"]["added"]
    assert [r["rule"] for r in backward["findings"]["added"]] == [
        r["rule"] for r in mirrored["findings"]["added"]
    ]
    assert [r["rule"] for r in backward["findings"]["removed"]] == [
        r["rule"] for r in mirrored["findings"]["removed"]
    ]


def test_self_diff_is_empty_on_every_layer(tmp_path):
    metadata = _meta(libraries=[{"name": "liba.so"}])
    side = _write_meta(tmp_path, metadata)
    report = diff_binary_metadata(str(side), str(side))
    assert report["unchanged"] is True
    assert report["hardening"]["changes"] == []
    assert report["findings"]["added_count"] == report["findings"]["removed_count"] == 0
    assert report["identity"]["changed_fields"] == {}
    assert report["imports"].get("added_count", 0) == 0


def test_report_is_deterministic_across_processes(tmp_path):
    old = _meta(security_properties={**_meta()["security_properties"], "canary": False})
    old_p = _write_meta(_mkdir(tmp_path, "old"), old)
    new_p = _write_meta(_mkdir(tmp_path, "new"), _meta())
    script = (
        "import json, sys;"
        "from blint.lib.diff import diff_binary_metadata;"
        "print(json.dumps(diff_binary_metadata(sys.argv[1], sys.argv[2]), sort_keys=True))"
    )
    outputs = set()
    for seed in ("0", "12345"):
        result = subprocess.run(
            [sys.executable, "-c", script, str(old_p), str(new_p)],
            capture_output=True,
            text=True,
            cwd=str(_REPO_ROOT),
            env={**os.environ, "PYTHONHASHSEED": seed},
            check=True,
        )
        outputs.add(result.stdout)
    assert len(outputs) == 1, "cross-process output must be byte-identical"


# ---------------------------------------------------------------------------
# Real-binary ground truth (corpus fixtures)


@needs_corpus
def test_go_stripped_pair_reports_symbol_loss_not_code_rewrite():
    report = diff_binary_metadata(str(GO_ELF), str(GO_ELF_STRIPPED))
    # The symbol table change is the headline, with exact counts.
    assert report["symbols"]["functions_old_count"] == 1951
    assert report["symbols"]["functions_new_count"] == 0
    assert report["symbols"]["removed_count"] == 1951
    # Gaining "stripped" is a change, never a security regression.
    stripped_changes = [c for c in report["hardening"]["changes"] if c["property"] == "stripped"]
    assert stripped_changes and stripped_changes[0]["classification"] == "change"
    assert report["summary"]["hardening_regressions"] == 0
    # The static-Go import trap: no import table anywhere, claimed by name.
    assert report["imports"]["status"] == "no_import_evidence"
    # Without --disassemble the function layer says so honestly.
    assert report["functions"]["status"] == "unavailable"
    assert any("function layer unavailable" in note for note in report["notes"])


@needs_corpus
def test_go_pair_findings_are_unchanged_not_churned():
    """The finding-level reason the pairing key exists: finding_id changes on
    every rebuild, but the CHECK finding survives the rebuild unchanged."""
    report = diff_binary_metadata(str(GO_ELF), str(GO_ELF_STRIPPED))
    assert report["findings"]["added_count"] == 0
    assert report["findings"]["removed_count"] == 0
    assert report["findings"]["unchanged_count"] >= 1


@needs_stackstr
def test_stackstr_stripped_pair_code_is_not_reported_rewritten():
    report = diff_binary_metadata(
        str(STACKSTR_ARM64), str(STACKSTR_ARM64_STRIPPED), disassemble=True
    )
    functions = report["functions"]
    assert functions["status"] == "compared"
    assert functions["changed_count"] == 0, "same build: no code may be reported rewritten"
    assert functions["unchanged_count"] >= 3
    assert functions["added_count"] == 0
    assert functions["removed_count"] >= 1, "the stripped side disassembles fewer functions"
    # The symbol-table change is visible at the symbol layer with names.
    assert report["symbols"]["removed_count"] >= 1
    assert report["symbols"]["removed"] == ["_build_secret", "_leak", "_main"]
    # Mirror of the same pair agrees.
    backward = diff_binary_metadata(
        str(STACKSTR_ARM64_STRIPPED), str(STACKSTR_ARM64), disassemble=True
    )
    assert backward["functions"]["added_count"] == functions["removed_count"]
    assert backward["functions"]["removed_count"] == functions["added_count"]
    assert backward["functions"]["changed_count"] == 0


@pytest.mark.skipif(
    not (shutil.which("clang") or shutil.which("gcc")),
    reason="needs a C compiler for the hardening-flip pair",
)
def test_canary_flag_flip_is_reported_as_regression(tmp_path):
    """External ground truth: the compiler flag, not blint, decides. The same
    source compiled with and without stack protection must produce exactly a
    canary regression."""
    compiler = shutil.which("clang") or shutil.which("gcc")
    source = _REPO_ROOT / "tests" / "corpus" / "sources" / "stackstr.c"
    on_binary = tmp_path / "canary-on"
    off_binary = tmp_path / "canary-off"
    for target, flag in (
        (on_binary, "-fstack-protector-strong"),
        (off_binary, "-fno-stack-protector"),
    ):
        subprocess.run(
            [compiler, str(source), "-O2", flag, "-o", str(target)],
            check=True,
            capture_output=True,
        )
    from blint.lib.binary import parse

    on_props = parse(str(on_binary)).get("security_properties") or {}
    off_props = parse(str(off_binary)).get("security_properties") or {}
    if on_props.get("canary") is not True or off_props.get("canary") is not False:
        pytest.skip(
            f"toolchain did not flip canary: {on_props.get('canary')} -> {off_props.get('canary')}"
        )
    report = diff_binary_metadata(str(on_binary), str(off_binary))
    regressions = [
        (c["property"], c["old"], c["new"])
        for c in report["hardening"]["changes"]
        if c["classification"] == "regression"
    ]
    assert ("canary", True, False) in regressions
    # The compiler flag is ground truth; blint must not invent other regressions.
    assert report["summary"]["hardening_regressions"] == 1
    # The findings layer follows the rule catalog's own exe_type coverage:
    # CHECK_CANARY has no Mach-O entry today, so on Mach-O binaries the
    # hardening layer is the only layer that can report the regression.
    from blint.lib.analysis import rules_dict

    canary_rule = rules_dict.get("CHECK_CANARY") or {}
    report_new = report["new"]
    if not canary_rule.get("exe_types") or report_new["exe_type"] in canary_rule["exe_types"]:
        assert "CHECK_CANARY" in [row["rule"] for row in report["findings"]["added"]]
    else:
        assert report_new["exe_type"] not in canary_rule["exe_types"]
        assert "CHECK_CANARY" not in [row["rule"] for row in report["findings"]["added"]]


@pytest.mark.skipif(
    not (shutil.which("clang") or shutil.which("gcc")) or not sys.platform.startswith("linux"),
    reason="needs gcc/clang on x86-64 Linux for a -no-pie link",
)
def test_pie_flag_flip_is_reported_as_regression(tmp_path):
    compiler = shutil.which("clang") or shutil.which("gcc")
    source = _REPO_ROOT / "tests" / "corpus" / "sources" / "stackstr.c"
    on_binary = tmp_path / "pie-on"
    off_binary = tmp_path / "pie-off"
    for target, flags in (
        (on_binary, ["-fPIE", "-pie"]),
        (off_binary, ["-fno-pie", "-no-pie"]),
    ):
        subprocess.run(
            [compiler, str(source), "-O2", *flags, "-o", str(target)],
            check=True,
            capture_output=True,
        )
    from blint.lib.binary import parse

    on_props = parse(str(on_binary)).get("security_properties") or {}
    off_props = parse(str(off_binary)).get("security_properties") or {}
    if on_props.get("pie") is not True or off_props.get("pie") is not False:
        pytest.skip(f"toolchain did not flip pie: {on_props.get('pie')} -> {off_props.get('pie')}")
    report = diff_binary_metadata(str(on_binary), str(off_binary))
    regressions = [
        c["property"]
        for c in report["hardening"]["changes"]
        if c["classification"] == "regression"
    ]
    assert "pie" in regressions


@needs_corpus
def test_self_diff_of_a_real_binary_is_empty():
    report = diff_binary_metadata(str(GO_ELF), str(GO_ELF))
    assert report["unchanged"] is True
    assert report["summary"]["hardening_regressions"] == 0
    assert report["findings"]["added_count"] == 0 and report["findings"]["removed_count"] == 0


def test_hardening_layer_carries_the_security_properties_scope(tmp_path):
    """Rule 21: the summary block describes one slice of a universal binary,
    so the diff carries the scope through instead of comparing silently."""
    old_p = _write_meta(_mkdir(tmp_path, "old"), _meta())
    new_p = _write_meta(
        _mkdir(tmp_path, "new"),
        _meta(
            hashes={"sha256": "b" * 64},
            security_properties_scope="primary_slice",
            security_properties_slice_variance=["pac"],
        ),
    )
    report = diff_binary_metadata(str(old_p), str(new_p))
    assert report["hardening"]["scope"] == "primary_slice"
