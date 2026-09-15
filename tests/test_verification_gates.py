# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT
"""Decision-path tests for the gate harnesses in tests/scripts/.

`tests/scripts/verify_pointer_precision.py` and
`tests/scripts/callgraph_kpi_baseline.py` decide whether the engine is
correct. Both spent two packets reporting unusable inputs as measurements
(the empty objdump sweep read as thousands of blint errors; an unparseable
path read as `platform: unknown` with advice to commit a zeroed baseline)
because nothing invoked them: no CI workflow runs any harness in
tests/scripts/ directly. Their full disassembly-backed runs are minutes
each and need llvm-objdump, LLVM 18 for nyxstone, and fixture binaries
that are not in git, so those stay manual — commands in
tests/scripts/README.md, and the /bin/ls run as a `slow` test below.

What runs here — in CI, on every push — is each gate's contract on
unusable and deliberately-wrong inputs: exit 2, a message naming the
real problem, and no baseline write. An unusable input must never read
as a pass, as a blint failure, or as a zero.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent / "scripts"


def _load_script(module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, SCRIPTS_DIR / f"{module_name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


kpi_gate = _load_script("callgraph_kpi_baseline")
precision_gate = _load_script("verify_pointer_precision")

LLVM_OBJDUMP = Path(precision_gate.LLVM_OBJDUMP)

NONEXISTENT = "/nonexistent-binary-for-gate-tests"


def _write_metadata(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


# ---- callgraph_kpi_baseline.py ----


def test_kpi_gate_names_unparseable_binary_as_unusable(tmp_path, capsys):
    rc = kpi_gate.main(["--binary", NONEXISTENT, "--baseline", str(tmp_path / "baseline.json")])

    assert rc == 2
    err = capsys.readouterr().err
    assert "llvm_target_tuple" in err
    assert NONEXISTENT in err


def test_kpi_gate_refuses_directory_input(tmp_path, capsys):
    rc = kpi_gate.main(["--binary", str(tmp_path), "--baseline", str(tmp_path / "b.json")])

    assert rc == 2
    assert "llvm_target_tuple" in capsys.readouterr().err


def test_kpi_gate_names_invalid_metadata_json(tmp_path, capsys):
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")

    rc = kpi_gate.main(["--metadata", str(broken)])

    assert rc == 2
    assert "not valid JSON" in capsys.readouterr().err


def test_kpi_gate_update_refuses_unparseable_input_without_writing(tmp_path, capsys):
    baseline = tmp_path / "baseline.json"

    rc = kpi_gate.main(["--binary", NONEXISTENT, "--baseline", str(baseline), "--update-baseline"])

    assert rc == 2
    assert "llvm_target_tuple" in capsys.readouterr().err
    assert not baseline.exists()


def test_kpi_gate_update_refuses_all_zero_kpi(tmp_path, capsys):
    metadata = _write_metadata(
        tmp_path / "zero-metadata.json",
        {
            "file_path": "/x/empty.bin",
            "llvm_target_tuple": "x86_64-unknown-zero-test",
            "disassembled_functions": {},
            "callgraph": {"edges": [], "external": []},
        },
    )
    baseline = tmp_path / "baseline.json"

    rc = kpi_gate.main(
        ["--metadata", str(metadata), "--baseline", str(baseline), "--update-baseline"]
    )

    assert rc == 2
    assert "no callgraph at all" in capsys.readouterr().err
    assert not baseline.exists()


def test_kpi_gate_update_bootstraps_a_real_platform(tmp_path):
    metadata = _write_metadata(
        tmp_path / "real-metadata.json",
        {
            "file_path": "/x/fake",
            "llvm_target_tuple": "aarch64-unknown-freebsd-test",
            "disassembled_functions": {"0x1000::f": {"direct_call_targets": ["0x2000"]}},
            "callgraph": {
                "edges": [{"src": 0, "dst": 0, "kind": "direct"}],
                "external": [{"src": 0, "target": "malloc", "reason": "import"}],
            },
        },
    )
    baseline = tmp_path / "baseline.json"

    rc = kpi_gate.main(
        ["--metadata", str(metadata), "--baseline", str(baseline), "--update-baseline"]
    )

    assert rc == 0
    entry = json.loads(baseline.read_text(encoding="utf-8"))["entries"][
        "aarch64-unknown-freebsd-test"
    ]
    assert entry["kpi"]["functions_total"] == 1
    assert entry["allowed_drop"]["functions_total"] == 0

    # The freshly bootstrapped baseline compares clean.
    assert kpi_gate.main(["--metadata", str(metadata), "--baseline", str(baseline)]) == 0


def test_kpi_gate_reports_regressions(tmp_path):
    metadata = _write_metadata(
        tmp_path / "real-metadata.json",
        {
            "file_path": "/x/fake",
            "llvm_target_tuple": "aarch64-unknown-freebsd-test",
            "disassembled_functions": {"0x1000::f": {"direct_call_targets": ["0x2000"]}},
            "callgraph": {
                "edges": [{"src": 0, "dst": 0, "kind": "direct"}],
                "external": [{"src": 0, "target": "malloc", "reason": "import"}],
            },
        },
    )
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "entries": {
                    "aarch64-unknown-freebsd-test": {
                        "kpi": {
                            "functions_total": 500,
                            "functions_with_direct_targets": 400,
                            "internal_edges": 900,
                            "external_edges": 100,
                            "internal_edge_kinds": {"direct": 900},
                            "external_reason_buckets": {"import": 100},
                        },
                        "allowed_drop": {
                            "functions_total": 0,
                            "functions_with_direct_targets": 0,
                            "internal_edges": 0,
                            "external_edges": 0,
                            "internal_edge_kinds": {"*": 0},
                            "external_reason_buckets": {"*": 0},
                        },
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    rc = kpi_gate.main(["--metadata", str(metadata), "--baseline", str(baseline)])

    assert rc == 1


def test_kpi_gate_explicit_platform_still_flows_through(tmp_path):
    """--platform names a platform for metadata carrying no target tuple."""
    metadata = _write_metadata(
        tmp_path / "plain-metadata.json",
        {
            "file_path": "/x/fake.exe",
            "disassembled_functions": {"0x1000::f": {"direct_call_targets": ["0x2000"]}},
            "callgraph": {"edges": [{"src": 0, "dst": 0, "kind": "direct"}], "external": []},
        },
    )

    rc = kpi_gate.main(
        [
            "--metadata",
            str(metadata),
            "--platform",
            "x86_64-pc-windows-msvc",
            "--baseline",
            str(tmp_path / "absent-baseline.json"),
        ]
    )

    assert rc == 1  # no baseline entry for the platform is a regression, not an error


def test_kpi_gate_refuses_to_compare_an_empty_callgraph(tmp_path, capsys):
    """An input that disassembled to nothing is an unknown on the compare path
    too, not a total regression of every counter in the baseline. Without this
    the gate reports the disassembler lost everything when what is missing is
    LLVM 18."""
    metadata = _write_metadata(
        tmp_path / "zero-metadata.json",
        {
            "file_path": "/x/empty.bin",
            "llvm_target_tuple": "x86_64-unknown-zero-test",
            "disassembled_functions": {},
            "callgraph": {"edges": [], "external": []},
        },
    )
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "entries": {
                    "x86_64-unknown-zero-test": {
                        "kpi": {"functions_total": 500, "internal_edges": 900},
                        "allowed_drop": {"functions_total": 0, "internal_edges": 0},
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    rc = kpi_gate.main(["--metadata", str(metadata), "--baseline", str(baseline)])

    err = capsys.readouterr().err
    assert rc == 2
    assert "no callgraph at all" in err
    assert "regressed" not in err


# ---- verify_pointer_precision.py ----


def test_precision_gate_names_missing_binary_as_unusable(capsys):
    rc = precision_gate.main([NONEXISTENT])

    assert rc == 2
    assert NONEXISTENT in capsys.readouterr().err


def test_precision_gate_classifies_landings_against_the_walked_entry():
    """A landing inside a sweep instruction that crossed the walked function's
    own entry is objdump's artifact; anything else is a real misplacement."""
    crossed_entry_span = 0x1000018FB  # objdump's drift instruction on /bin/ls
    entry = 0x100001900
    # The function's entry itself and its second instruction: sweep artifacts.
    assert precision_gate.classify_landing(entry, entry, crossed_entry_span, False) == "artifact"
    assert (
        precision_gate.classify_landing(entry + 1, entry, crossed_entry_span, False) == "artifact"
    )
    # A landing before the crossed entry, or inside a span that crosses no
    # entry of the walked function: a misplaced address, and the gate fails.
    assert (
        precision_gate.classify_landing(entry - 3, entry, crossed_entry_span, False) == "interior"
    )
    assert (
        precision_gate.classify_landing(entry + 1, 0x100002000, crossed_entry_span, False)
        == "interior"
    )


def test_precision_gate_treats_a_derailed_sweep_as_artifact_until_it_resyncs():
    """Once objdump's sweep has decoded across a function entry it stays wrong
    for several spans, not just the one that crossed. On /usr/bin/curl the
    sweep enters the padding before 0x100004304, and its *next* span starts at
    0x100004306 — after the entry — so the entry-crossing rule alone reports
    blint's correct `test rdi, rdi; je; push rbp` as two misplacements."""
    later_span = 0x100004306
    entry = 0x100004304
    assert precision_gate.classify_landing(0x100004307, entry, later_span, True) == "artifact"
    # The same landing without a prior derailment is still a misplacement:
    # desync is only ever entered by crossing a symbol-derived entry.
    assert precision_gate.classify_landing(0x100004307, entry, later_span, False) == "interior"


def test_precision_gate_labels_why_the_sweep_misdecoded():
    pad = precision_gate.span_start_label(b"\x00\x55\x48\x89")
    nop = precision_gate.span_start_label(b"\x0f\x1f\x44\x00\x00")
    drift = precision_gate.span_start_label(b"\xff\x55\x48\x89")

    assert "pad byte" in pad
    assert "nop" in nop
    assert "drifted" in drift


@pytest.mark.slow
@pytest.mark.skipif(sys.platform != "darwin", reason="/bin/ls only exists on macOS")
@pytest.mark.skipif(
    not Path("/bin/ls").exists() or not LLVM_OBJDUMP.exists(),
    reason="needs /bin/ls and llvm-objdump",
)
def test_precision_gate_bin_ls_passes(capsys):
    """The full /bin/ls gate: arch cross-check, objdump ground truth, verdict.

    Misuse — asking for a slice blint did not analyse — must exit 2, and the
    gate on the slice blint did analyse must PASS. The artifact count varies
    with the macOS build; what may not vary is that every landing objdump
    disagrees about is classified from the bytes, leaving no interior ones.
    """
    assert precision_gate.main(["/bin/ls", "--arch", "arm64"]) == 2
    err = capsys.readouterr().err
    assert "x86_64" in err and "--arch arm64" in err

    assert precision_gate.main(["/bin/ls", "--arch", "x86"]) == 0
    out = capsys.readouterr().out
    assert "PRECISION VERDICT: PASS" in out
