"""Parallel analysis tests (P3.2, ``--jobs N``).

Every gate here maps to a failure mode that cannot fire on a healthy
sequential run, so each one is forced explicitly (workplan rule 23):

- **Merge order**: results complete out of order; the caller merges by
  submission index. The end-to-end tests hold the parallel run to the
  determinism standard: exported metadata bytes, findings, reviews,
  fuzzables, callgraphs and the run-level coverage block must be identical
  to the sequential run.
- **Worker death**: a worker killed with SIGKILL mid-binary (not an
  exception — there is nothing to catch) must be recorded as a structured
  ``WorkerDied`` failure in ``analysis_coverage`` while every other file is
  still analyzed.
- **Sterile startup**: workers that die before finishing anything must
  surface as ``PoolStartupError``, and the caller must fall back to the
  sequential path rather than fail the scan.
- **SBOM parity**: the parallel SBOM must equal the sequential one (modulo
  the random serialNumber) and must abort like the sequential loop when a
  binary raises.

The poison fixtures below are module-level functions on purpose: spawn-started
workers import this module by name, so a worker sees the poison logic no
matter which platform start method is in play (parent-side monkeypatching
does not propagate under spawn — only the *spec* travels to the worker, so
the poison target rides in the picklable payload instead).
"""

import dataclasses
import logging
import multiprocessing
import os
import re
import shutil
import signal
import subprocess
from pathlib import Path

import pytest

import blint.lib.runners as runners_mod
import blint.lib.sbom as sbom_mod
from blint.config import BlintOptions
from blint.lib.parallel import (
    BufferedLogHandler,
    PoolStartupError,
    WorkerSpec,
    payload_as_state,
    resolve_jobs,
    run_pool,
)
from blint.lib.runners import AnalysisRunner, run_sbom_mode
from tests.test_determinism import _DEMO_C

# --------------------------------------------------------------------------
# resolve_jobs
# --------------------------------------------------------------------------


def test_resolve_jobs_defaults_and_auto():
    assert resolve_jobs(None) == 1
    assert resolve_jobs("") == 1
    assert resolve_jobs(1) == 1
    assert resolve_jobs("1") == 1
    assert resolve_jobs(" 8 ") == 8
    assert resolve_jobs(0) == (os.cpu_count() or 1)
    assert resolve_jobs("auto") == (os.cpu_count() or 1)
    assert resolve_jobs("AUTO") == (os.cpu_count() or 1)


@pytest.mark.parametrize("bad", ["4x", "-2", "two", "1.5"])
def test_resolve_jobs_rejects_garbage_loudly(bad):
    with pytest.raises(ValueError):
        resolve_jobs(bad)


# --------------------------------------------------------------------------
# Pool supervisor mechanics (generic WorkerSpec, no blint state)
# --------------------------------------------------------------------------


def _double_unit(payload, state):
    # Variable sleep so completions interleave and finish out of order.
    import time

    time.sleep(payload[1] % 3 * 0.01)
    return {"value": payload[0] * 2}


def test_run_pool_returns_all_results_with_out_of_order_completion():
    units = [(i, (i, i)) for i in range(12)]
    envelopes, hard = run_pool(units, 4, WorkerSpec(analyze=_double_unit, payload=None))
    assert not hard
    assert sorted(envelopes) == list(range(12))
    assert all(envelopes[i]["value"] == i * 2 for i in range(12))


def _suicide_unit(payload, state):
    if payload[0] in state["victims"]:
        os.kill(os.getpid(), signal.SIGKILL)
    return {"value": payload[0]}


def test_run_pool_worker_sigkill_recorded_and_run_completes():
    """A SIGKILLed worker's unit becomes a hard failure; the rest complete.

    The kill is a real SIGKILL — no exception is raised, nothing on the
    worker gets a chance to clean up — which is exactly the LIEF-segfault
    scenario the sequential path cannot have but a pool can.
    """
    units = [(i, (i, 0)) for i in range(8)]
    spec = WorkerSpec(
        analyze=_suicide_unit, setup=payload_as_state, payload={"victims": {2, 5}}
    )
    envelopes, hard = run_pool(units, 3, spec)
    assert sorted(envelopes) == [0, 1, 3, 4, 6, 7]
    assert sorted(hard) == [2, 5]
    assert "exited with code" in hard[2]


def test_run_pool_every_unit_kills_its_worker():
    """Worst case: every unit kills its worker; all become hard failures."""
    units = [(i, (i, 0)) for i in range(5)]
    spec = WorkerSpec(
        analyze=_suicide_unit,
        setup=payload_as_state,
        payload={"victims": set(range(5))},
    )
    envelopes, hard = run_pool(units, 2, spec)
    assert not envelopes
    assert sorted(hard) == list(range(5))


class _CountingContext:
    """Delegates to a real context while counting the queues it hands out."""

    def __init__(self):
        self._ctx = multiprocessing.get_context()
        self.queues_created = 0

    def Process(self, *args, **kwargs):
        return self._ctx.Process(*args, **kwargs)

    def Queue(self, *args, **kwargs):
        self.queues_created += 1
        return self._ctx.Queue(*args, **kwargs)


def test_run_pool_replaces_a_dead_worker_task_queue():
    """A replacement worker must never inherit the dead one's task queue.

    The parent can put a unit on a slot's queue and have the worker die
    before reading it. That unit is already accounted for as a hard failure,
    so a replacement reading the same queue would pick up stale work and
    desynchronize the slot's in-flight bookkeeping — after which a second
    death on that slot blames the wrong unit. Queues are therefore created
    per worker generation, which this counts: two workers plus at least one
    respawn means strictly more than three queues (two task + one result).
    """
    ctx = _CountingContext()
    units = [(i, (i, 0)) for i in range(6)]
    spec = WorkerSpec(analyze=_suicide_unit, setup=payload_as_state, payload={"victims": {1, 4}})
    envelopes, hard = run_pool(units, 2, spec, mp_context=ctx)
    assert sorted(hard) == [1, 4]
    assert sorted(envelopes) == [0, 2, 3, 5]
    # 2 task queues + 1 result queue for the first generation, plus one
    # fresh task queue for each of the two respawns.
    assert ctx.queues_created >= 5, (
        f"only {ctx.queues_created} queues created; a respawned worker reused a "
        "dead generation's task queue"
    )


def _setup_suicide(payload):
    os.kill(os.getpid(), signal.SIGKILL)


def test_run_pool_sterile_startup_raises():
    """Workers dying before finishing anything surface as PoolStartupError.

    The setup hook runs inside the worker before the loop; a SIGKILL there
    means no unit ever completes and none is ever assigned-and-lost, which
    is the unpicklable-payload/broken-start-method shape.
    """
    units = [(i, (i, 0)) for i in range(3)]
    spec = WorkerSpec(analyze=_double_unit, setup=_setup_suicide, payload=None)
    with pytest.raises(PoolStartupError):
        run_pool(units, 2, spec)


class _BrokenProcess:
    def start(self):
        raise OSError("no more processes")

    def is_alive(self):
        return False

    def exitcode(self):
        return None


class _BrokenContext:
    """Mimics a multiprocessing context whose Process.start always fails."""

    def Process(self, *args, **kwargs):
        return _BrokenProcess()

    def Queue(self, *args, **kwargs):
        from multiprocessing import Queue

        return Queue(*args, **kwargs)


def test_run_pool_bootstrap_failure_raises():
    with pytest.raises(PoolStartupError):
        run_pool(
            [(0, "x"), (1, "y")],
            2,
            WorkerSpec(analyze=_double_unit, payload=None),
            mp_context=_BrokenContext(),
        )


def test_buffered_log_handler_capacity_and_drop_summary():
    handler = BufferedLogHandler(capacity=3)
    root = logging.getLogger()
    old_level = root.level
    old_handlers = root.handlers
    root.setLevel(logging.DEBUG)
    root.handlers = [handler]
    try:
        for i in range(5):
            logging.getLogger("blint.test").warning("msg %d", i)
    finally:
        root.handlers = old_handlers
        root.setLevel(old_level)
    records = handler.take()
    assert [message for _, message in records[:3]] == ["msg 0", "msg 1", "msg 2"]
    assert "2 further worker log line(s) dropped" in records[-1][1]
    # take() resets: the next snapshot is empty, the drop notice is not repeated.
    assert handler.take() == []


# --------------------------------------------------------------------------
# Poison fixtures for the real default-mode/SBOM wiring. Module-level so
# spawn-started workers import them by name; the poison target travels in
# the (picklable) payload, never via parent-side monkeypatching.
# --------------------------------------------------------------------------


def _poison_setup_default(payload):
    state = runners_mod._worker_setup_default(payload)
    state["poison_path"] = payload["poison_path"]
    return state


def _poison_analyze_default(file_path, state):
    if file_path == state["poison_path"]:
        os.kill(os.getpid(), signal.SIGKILL)
    return runners_mod.analyze_unit_default(file_path, state)


def _logging_analyze_default(file_path, state):
    from blint.logger import LOG

    LOG.warning("worker processed %s", os.path.basename(file_path))
    return runners_mod.analyze_unit_default(file_path, state)


def _wrapped_run_pool_factory(poison_path=None, analyze=None, setup=None):
    """Wrap run_pool so the production call sites run a swapped-in spec.

    The parent's call site (blint.lib.runners.run_pool / blint.lib.sbom.run_pool)
    is monkeypatched; the swapped functions are module-level in this test
    module, so spawn workers import them by name and the poison rides in the
    picklable payload.
    """

    def wrapped_run_pool(units, num_workers, worker_spec, mp_context=None, on_done=None):
        payload = dict(worker_spec.payload or {})
        if poison_path is not None:
            payload["poison_path"] = poison_path
        spec = WorkerSpec(
            analyze=analyze or worker_spec.analyze,
            setup=setup or worker_spec.setup,
            teardown=worker_spec.teardown,
            payload=payload,
            unit_role=worker_spec.unit_role,
            record_errors=worker_spec.record_errors,
        )
        return run_pool(units, num_workers, spec, mp_context=mp_context, on_done=on_done)

    return wrapped_run_pool


# --------------------------------------------------------------------------
# End-to-end default mode
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def parallel_fixtures(tmp_path_factory):
    """A small mixed corpus: one freshly compiled native binary plus wasm."""
    compiler = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
    if not compiler:
        pytest.skip("no host C compiler available for the parallel fixtures")
    workdir = tmp_path_factory.mktemp("parallel-fixtures")
    source = workdir / "demo.c"
    source.write_text(_DEMO_C, encoding="utf-8")
    binary = workdir / "demo-bin"
    subprocess.run(
        [compiler, "-O1", "-o", str(binary), str(source)],
        check=True,
        capture_output=True,
    )
    data = Path(__file__).resolve().parent / "data"
    return [
        str(binary),
        str(data / "complex_flow.wasm"),
        str(data / "component_minimal.wasm"),
        str(data / "strings_secrets.wasm"),
    ]


def _run_analysis(exe_files, jobs, reports_dir, use_cache=False):
    options = BlintOptions(
        src_dir_image=list(exe_files),
        reports_dir=str(reports_dir),
        no_reviews=False,
        quiet_mode=True,
        jobs=jobs,
        disassemble=True,
        fuzzy=True,
        use_cache=use_cache,
    )
    runner = AnalysisRunner()
    results = runner.start(options, list(exe_files))
    return results, runner.analysis_coverage()


def test_parallel_default_mode_matches_sequential_bytes(parallel_fixtures, tmp_path):
    """The packet's central claim at unit scale: jobs=4 output == jobs=1.

    Reviews are ON (the default) so this also proves the workers load the
    rule state themselves: a worker without rules would produce a different
    review set, and the sets must be equal.
    """
    exe_files = parallel_fixtures
    out_seq = tmp_path / "seq"
    out_par = tmp_path / "par"
    (findings_seq, reviews_seq, fuzzables_seq, callgraphs_seq), _ = _run_analysis(
        exe_files, 1, out_seq
    )
    (findings_par, reviews_par, fuzzables_par, callgraphs_par), cov_par = _run_analysis(
        exe_files, 4, out_par
    )
    assert findings_par == findings_seq
    assert reviews_par == reviews_seq
    assert fuzzables_par == fuzzables_seq
    assert callgraphs_par == callgraphs_seq
    for name in sorted(p.name for p in out_seq.glob("*-metadata.json")):
        assert (out_par / name).read_bytes() == (out_seq / name).read_bytes(), name
    assert cov_par["units"] == {
        "attempted": len(exe_files),
        "succeeded": len(exe_files),
        "failed": 0,
        "skipped": 0,
    }
    assert cov_par["failures"] == []


def test_parallel_default_mode_jobs_exceeding_file_count(parallel_fixtures, tmp_path):
    _, cov = _run_analysis(parallel_fixtures, 32, tmp_path / "out")
    assert cov["units"]["attempted"] == len(parallel_fixtures)
    assert cov["units"]["succeeded"] == len(parallel_fixtures)
    assert cov["units"]["failed"] == 0


def test_parallel_default_mode_worker_sigkill_isolated(parallel_fixtures, tmp_path, monkeypatch):
    """Gate: a worker killed mid-binary is recorded; the run completes.

    The poisoned file's worker is SIGKILLed (no exception exists to catch);
    analysis_coverage must carry a WorkerDied record for exactly that file
    while every other file is analyzed and exported.
    """
    victim = parallel_fixtures[0]
    monkeypatch.setattr(
        runners_mod,
        "run_pool",
        _wrapped_run_pool_factory(
            poison_path=victim,
            analyze=_poison_analyze_default,
            setup=_poison_setup_default,
        ),
    )
    reports_dir = tmp_path / "out"
    options = BlintOptions(
        src_dir_image=list(parallel_fixtures),
        reports_dir=str(reports_dir),
        no_reviews=True,
        quiet_mode=True,
        jobs=4,
    )
    runner = AnalysisRunner()
    runner.start(options, list(parallel_fixtures))
    coverage = runner.analysis_coverage()
    assert coverage["units"]["attempted"] == len(parallel_fixtures)
    assert coverage["units"]["failed"] == 1
    assert coverage["units"]["succeeded"] == len(parallel_fixtures) - 1
    failure = coverage["failures"][0]
    assert failure["file_path"] == victim
    assert failure["stage"] == "worker"
    assert failure["exception_type"] == "WorkerDied"
    # Every other file was still analyzed and exported.
    exported = {p.name for p in reports_dir.glob("*-metadata.json")}
    assert len(exported) == len(parallel_fixtures) - 1


def test_parallel_default_mode_replays_worker_logs(parallel_fixtures, tmp_path, monkeypatch, caplog):
    """Worker log records are replayed by the parent, not printed by workers."""
    monkeypatch.setattr(
        runners_mod,
        "run_pool",
        _wrapped_run_pool_factory(analyze=_logging_analyze_default),
    )
    with caplog.at_level(logging.WARNING, logger="blint"):
        _run_analysis(parallel_fixtures, 3, tmp_path / "out")
    replayed = [r for r in caplog.records if "worker processed" in r.getMessage()]
    assert len(replayed) == len(parallel_fixtures)


def test_parallel_jobs_one_never_spawns_a_pool(parallel_fixtures, tmp_path, monkeypatch):
    """--jobs 1 is the sequential loop; the pool must not be touched."""

    def forbidden(*args, **kwargs):
        raise AssertionError("run_pool must not be called for --jobs 1")

    monkeypatch.setattr(runners_mod, "run_pool", forbidden)
    _, cov = _run_analysis(parallel_fixtures, 1, tmp_path / "out")
    assert cov["units"]["succeeded"] == len(parallel_fixtures)


def test_parallel_pool_startup_failure_falls_back_to_sequential(
    parallel_fixtures, tmp_path, monkeypatch
):
    """If the pool cannot start, the sequential path still runs the scan."""

    def broken_pool(*args, **kwargs):
        raise PoolStartupError("no workers could be started")

    monkeypatch.setattr(runners_mod, "run_pool", broken_pool)
    _, cov = _run_analysis(parallel_fixtures, 4, tmp_path / "out")
    assert cov["units"]["succeeded"] == len(parallel_fixtures)
    assert cov["units"]["failed"] == 0


# --------------------------------------------------------------------------
# End-to-end SBOM mode
# --------------------------------------------------------------------------


def _poison_analyze_sbom(file_path, state):
    if file_path == state["poison_path"]:
        os.kill(os.getpid(), signal.SIGKILL)
    return sbom_mod.analyze_unit_sbom(file_path, state)


def _raising_analyze_sbom(file_path, state):
    if file_path == state["poison_path"]:
        raise ValueError("poisoned binary")
    return sbom_mod.analyze_unit_sbom(file_path, state)


def _sbom_setup(payload):
    return payload


def test_sbom_parallel_matches_sequential(parallel_fixtures, tmp_path):
    """Parallel SBOM equals sequential (modulo the random serialNumber).

    Includes the wasm files with --wasm-sbom so both wasm paths (component
    interfaces and core-module skip) are part of the comparison.
    """
    outputs = {}
    for jobs, name in ((1, "seq.cdx.json"), (4, "par.cdx.json")):
        options = BlintOptions(
            sbom_mode=True,
            src_dir_image=list(parallel_fixtures),
            reports_dir=str(tmp_path),
            quiet_mode=True,
            jobs=jobs,
            sbom_output=str(tmp_path / name),
            wasm_sbom=True,
        )
        assert run_sbom_mode(options)
        outputs[jobs] = re.sub(
            rb'"serialNumber": "urn:uuid:[^"]*"',
            b'"serialNumber": ""',
            (tmp_path / name).read_bytes(),
        )
    assert outputs[4] == outputs[1]


def test_sbom_parallel_worker_sigkill_aborts_loudly(parallel_fixtures, tmp_path, monkeypatch):
    """A worker killed mid-binary must not silently drop a component.

    The sequential SBOM loop would have died on the same binary; parallel
    raises a RuntimeError naming the file instead of emitting an SBOM that
    quietly misses it.
    """
    victim = parallel_fixtures[0]

    def wrapped_run_pool(units, num_workers, worker_spec, mp_context=None, on_done=None):
        payload = dict(worker_spec.payload or {})
        payload["poison_path"] = victim
        spec = dataclasses.replace(
            worker_spec,
            analyze=_poison_analyze_sbom,
            setup=_sbom_setup,
            payload=payload,
        )
        return run_pool(units, num_workers, spec, mp_context=mp_context, on_done=on_done)

    monkeypatch.setattr(sbom_mod, "run_pool", wrapped_run_pool)
    options = BlintOptions(
        sbom_mode=True,
        src_dir_image=list(parallel_fixtures),
        reports_dir=str(tmp_path),
        quiet_mode=True,
        jobs=4,
        sbom_output=str(tmp_path / "sbom.json"),
    )
    with pytest.raises(RuntimeError, match="worker died"):
        run_sbom_mode(options)


def test_sbom_parallel_unit_exception_replayed_at_merge_position(
    parallel_fixtures, tmp_path, monkeypatch
):
    """The sequential SBOM loop aborts on a bad binary; so must parallel.

    The worker returns the exception in its envelope (record_errors=False)
    and the parent re-raises it at the unit's merge position — the parallel
    path must not be more tolerant than the sequential one.
    """

    def wrapped_run_pool(units, num_workers, worker_spec, mp_context=None, on_done=None):
        payload = dict(worker_spec.payload or {})
        payload["poison_path"] = parallel_fixtures[1]
        spec = dataclasses.replace(
            worker_spec,
            analyze=_raising_analyze_sbom,
            setup=_sbom_setup,
            payload=payload,
        )
        return run_pool(units, num_workers, spec, mp_context=mp_context, on_done=on_done)

    monkeypatch.setattr(sbom_mod, "run_pool", wrapped_run_pool)
    options = BlintOptions(
        sbom_mode=True,
        src_dir_image=list(parallel_fixtures),
        reports_dir=str(tmp_path),
        quiet_mode=True,
        jobs=4,
        sbom_output=str(tmp_path / "sbom.json"),
    )
    with pytest.raises(ValueError, match="poisoned binary"):
        run_sbom_mode(options)


# --------------------------------------------------------------------------
# Parse cache x jobs
# --------------------------------------------------------------------------


def test_cache_with_jobs_cold_warm_identity_and_counters(parallel_fixtures, tmp_path, monkeypatch):
    """--cache --jobs N: cold vs warm bytes identical; counters total right."""
    monkeypatch.setenv("BLINT_CACHE_DIR", str(tmp_path / "cache"))

    def run(jobs, reports_dir, use_cache=False):
        return _run_analysis(parallel_fixtures, jobs, reports_dir, use_cache=use_cache)

    out_seq, out_cold, out_warm = (
        tmp_path / "nocache",
        tmp_path / "cold",
        tmp_path / "warm",
    )
    (_, cov_seq) = run(1, out_seq)
    (_, cov_cold) = run(4, out_cold, use_cache=True)
    (_, cov_warm) = run(4, out_warm, use_cache=True)

    # Cold parallel == sequential (no cache), including metadata bytes.
    for name in sorted(p.name for p in out_seq.glob("*-metadata.json")):
        assert (out_cold / name).read_bytes() == (out_seq / name).read_bytes(), name
    # Warm parallel == cold parallel: replay is byte-identical.
    for name in sorted(p.name for p in out_cold.glob("*-metadata.json")):
        assert (out_warm / name).read_bytes() == (out_cold / name).read_bytes(), name

    total_files = len(parallel_fixtures)
    assert cov_cold["cache"]["enabled"] is True
    assert cov_cold["cache"]["misses"] == total_files
    assert cov_cold["cache"]["stored"] == total_files
    assert cov_cold["cache"]["hits"] == 0
    assert cov_warm["cache"]["hits"] == total_files
    assert cov_warm["cache"]["misses"] == 0
    assert cov_warm["cache"]["stored"] == 0
    assert cov_seq["cache"]["enabled"] is False
