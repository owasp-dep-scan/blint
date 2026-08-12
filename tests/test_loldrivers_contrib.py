"""Tests for the LOLDrivers coverage harness in contrib/."""

import importlib.util
import json
from pathlib import Path

import pytest

CONTRIB_SCRIPT = (
    Path(__file__).resolve().parents[1] / "contrib" / "loldrivers" / "sync_loldrivers.py"
)


@pytest.fixture(scope="module")
def sync_module():
    """Import the contrib script by path, since contrib is not a package."""
    spec = importlib.util.spec_from_file_location("sync_loldrivers", CONTRIB_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _dataset():
    """A miniature LOLDrivers-shaped dataset: one detected, one undetected."""
    return [
        {
            "Category": "vulnerable driver",
            "Tags": ["ThrottleStop.sys"],
            "KnownVulnerableSamples": [
                {
                    "SHA256": "a" * 64,
                    "Filename": "ThrottleStop.sys",
                    "ImportedFunctions": [
                        "IoCreateDevice",
                        "IoCreateSymbolicLink",
                        "MmMapIoSpace",
                        "HalSetBusDataByOffset",
                    ],
                }
            ],
        },
        {
            "Category": "vulnerable driver",
            "Tags": ["boring.sys"],
            "KnownVulnerableSamples": [
                {
                    "SHA256": "b" * 64,
                    "Filename": "boring.sys",
                    "ImportedFunctions": [
                        "DbgPrint",
                        "RtlInitUnicodeString",
                        "KeInitializeSpinLock",
                    ],
                },
                # No import list: must be skipped entirely.
                {"SHA256": "c" * 64, "Filename": "nodata.sys"},
            ],
        },
    ]


def test_iter_samples_skips_records_without_imports(sync_module):
    samples = list(sync_module.iter_samples(_dataset()))
    assert len(samples) == 2
    assert {s.get("Filename") for _, s in samples} == {"ThrottleStop.sys", "boring.sys"}


def test_build_metadata_qualifies_imports_like_real_pe_metadata(sync_module):
    metadata = sync_module.build_metadata({"ImportedFunctions": ["IoCreateDevice"]})
    assert metadata["imports"] == [{"name": "ntoskrnl.exe::IoCreateDevice"}]
    assert metadata["subsystem"] == "NATIVE"


def test_analyse_reports_hits_and_ranks_uncovered_imports(sync_module):
    report = sync_module.analyse(_dataset(), snapshot=set())

    assert report["samples_evaluated"] == 2
    assert report["samples_new_since_snapshot"] == 2

    fired = {hit["rule"] for hit in report["rule_hits"]}
    assert "BYOVD_PHYS_MEM_MAPPING" in fired
    assert "BYOVD_PCI_CONFIG_WRITE" in fired

    # The plumbing-only driver is undetected, and its ubiquitous imports are
    # filtered out of the candidate list rather than proposed as rule material.
    assert report["undetected_count"] == 1
    assert report["undetected_samples"][0]["filename"] == "boring.sys"
    candidates = {c["import"] for c in report["candidate_imports"]}
    assert "dbgprint" not in candidates
    assert "rtlinitunicodestring" not in candidates


def test_analyse_reports_only_new_samples_against_a_snapshot(sync_module):
    report = sync_module.analyse(_dataset(), snapshot={"a" * 64})
    assert report["samples_new_since_snapshot"] == 1
    assert report["new_sample_keys"] == ["b" * 64]


def test_load_snapshot_tolerates_missing_and_corrupt_files(sync_module, tmp_path):
    assert sync_module.load_snapshot(tmp_path / "absent.json") == set()
    corrupt = tmp_path / "corrupt.json"
    corrupt.write_text("{not json")
    assert sync_module.load_snapshot(corrupt) == set()
    valid = tmp_path / "valid.json"
    valid.write_text(json.dumps({"seen": ["x" * 64]}))
    assert sync_module.load_snapshot(valid) == {"x" * 64}


def test_process_tampering_rule_detects_the_cluster_it_was_added_for(sync_module):
    """The gap the harness surfaced: cross-process primitives with no phys mem."""
    metadata = sync_module.build_metadata(
        {
            "ImportedFunctions": [
                "PsLookupProcessByProcessId",
                "KeStackAttachProcess",
                "KeUnstackDetachProcess",
                "ObOpenObjectByPointer",
            ]
        }
    )
    assert "BYOVD_PROCESS_TAMPERING_PRIMITIVE" in sync_module.evaluate_sample(metadata)
