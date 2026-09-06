# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT
"""Process-pool support for ``--jobs N`` (P3.2).

Runs one blint unit of work (one binary) per pool task across a fixed set of
worker processes. The unit of work stays the binary: there is deliberately no
parallelism within a binary (no threading of disassembly or slices).

Design notes that gate correctness, each with a test that forces it:

- **Determinism.** Workers complete out of order; every result envelope
  carries the submission index it belongs to, and the caller merges strictly
  in submission order (runners.py and sbom.py iterate ``range(len(units))``).
  Output is therefore byte-identical to the sequential run for any N.
- **Worker death.** Each worker owns a dedicated task queue and has at most
  one unit assigned at a time, so when a worker dies hard (segfault in LIEF,
  SIGKILL, OOM) the supervisor knows exactly which unit was assigned to it
  and reports it to the caller as a hard failure. The unit gets no second
  attempt: input that kills the interpreter would kill every retry, and the
  remaining files must not starve behind a crash loop. Workers that exit
  cleanly (sentinel after the last unit) are not replaced.
- **Sterile startup.** If workers keep dying without producing a single
  result (an unpicklable payload, a broken start method), the supervisor
  raises ``PoolStartupError`` after a bounded number of fruitless spawns
  instead of looping forever. Callers fall back to the sequential path, which
  records the real per-file failure through the normal isolation machinery.

Logging: workers swap their root logging handlers for an in-memory buffer
(:class:`BufferedLogHandler`) so nothing a worker prints can interleave with
the parent's rich ``Progress`` display. Buffered records travel back inside
the result envelope and the parent replays them through :data:`LOG` at merge
time — in submission order, which also keeps the captured
``blint-output.html`` deterministic across N.

Multiprocessing premises this module is built on (claims, checked in the
parallel tests and the gate scripts, not settled facts):

- The default start method is ``spawn`` on macOS and Windows and ``fork`` on
  Linux. Under spawn the worker re-imports every module, so all
  module-global rule state must be (re)initialized inside the worker —
  ``initialize_rules`` is idempotent and every default-mode worker calls it.
  Under fork the initialized globals are inherited read-only, which is safe
  because analysis only ever reads them.
- ``multiprocessing.Queue`` transfers arbitrary picklable payloads; worker
  payloads (``BlintOptions``, SBOM argument dicts, result envelopes) hold
  only primitives, lists, dicts and pydantic models — no locks, no open
  files, no module-level singletons.
- Daemon workers are used, so the pool dies with the parent on
  KeyboardInterrupt; each SQLite write in the parse cache is its own
  transaction, so an abruptly killed worker leaves no torn cache state.
"""

from __future__ import annotations

import contextlib
import logging
import multiprocessing
import os
import queue
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from blint.logger import LOG

# Poll interval while waiting for worker messages; also bounds how long a
# dead worker's exit can go unnoticed.
_POLL_SECONDS = 0.05
# A worker that dies without a unit assigned and without the run having
# produced anything is "sterile" — the pool cannot make progress.
_MIN_STERILE_DEATHS = 8
_STERILE_DEATHS_PER_WORKER = 3
# Hard ceiling on process spawns: generous (every unit could kill its worker
# plus every worker respawned a few times), but bounded.
_SPAWNS_PER_UNIT = 1
_EXTRA_SPAWNS = 32


class PoolStartupError(RuntimeError):
    """Raised when the worker pool cannot be started or cannot make progress.

    Callers must fall back to sequential processing: parallelism is a
    performance feature and must never be the reason a scan fails.
    """


def resolve_jobs(value: int | str | None) -> int:
    """Coerce a ``--jobs`` value to a positive worker count.

    Accepts an int, a decimal string, and the documented spellings for "one
    worker per CPU": ``auto`` (case-insensitive) or ``0``. Anything else
    raises ``ValueError`` — a typo like ``--jobs 4x`` must not silently mean
    1 or 4.
    """
    if value is None or value == "":
        return 1
    if isinstance(value, int):
        requested = value
    else:
        text = str(value).strip().lower()
        if text in ("auto", "cpu", "cpu_count"):
            requested = 0
        else:
            try:
                requested = int(text)
            except ValueError as exc:
                raise ValueError(
                    f"invalid --jobs value {value!r}: use a positive integer, "
                    "0 or 'auto' for the CPU count"
                ) from exc
    if requested < 0:
        raise ValueError(
            f"invalid --jobs value {value!r}: use a positive integer, "
            "0 or 'auto' for the CPU count"
        )
    if requested == 0:
        requested = os.cpu_count() or 1
    return max(1, requested)


class BufferedLogHandler(logging.Handler):
    """In-memory log sink for worker processes.

    Workers must not write to the terminal: their stderr would interleave
    with the parent's rich ``Progress`` display. This handler keeps
    ``(level, message)`` tuples up to ``capacity`` records per unit (the
    overflow is summarized rather than silently dropped) and ``take()``
    returns the buffer, resetting it for the next unit.
    """

    def __init__(self, capacity: int = 500) -> None:
        super().__init__(level=logging.NOTSET)
        self.capacity = capacity
        self._records: list[tuple[int, str]] = []
        self._dropped = 0

    def emit(self, record: logging.LogRecord) -> None:
        if len(self._records) >= self.capacity:
            self._dropped += 1
            return
        self._records.append((record.levelno, record.getMessage()))

    def take(self) -> list[tuple[int, str]]:
        """Return the buffered records and reset the buffer."""
        out = list(self._records)
        if self._dropped:
            out.append(
                (
                    logging.WARNING,
                    f"{self._dropped} further worker log line(s) dropped (buffer limit {self.capacity})",
                )
            )
        self._records = []
        self._dropped = 0
        return out


def install_log_buffer() -> BufferedLogHandler:
    """Replace this process's root log handlers with a buffer.

    Called only inside worker processes. The parent keeps its real handlers,
    replays buffered records at merge time, and therefore stays the only
    writer on the terminal.
    """
    root = logging.getLogger()
    handler = BufferedLogHandler()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    global _active_log_buffer
    _active_log_buffer = handler
    return handler


# Per-process handle on the installed buffer; workers read it back through
# take_worker_logs() when they build each unit's envelope.
_active_log_buffer: BufferedLogHandler | None = None


def take_worker_logs() -> list[tuple[int, str]]:
    """Return and clear this worker's buffered log records (empty in a parent)."""
    if _active_log_buffer is None:
        return []
    return _active_log_buffer.take()


@dataclass(frozen=True)
class WorkerSpec:
    """How a pool worker analyzes one unit.

    ``analyze(unit_payload, state) -> envelope`` does the actual work and is
    responsible for its own per-unit isolation where the sequential path has
    one (the default-mode runner catches per-file exceptions; the SBOM path
    does not). ``setup``/``teardown`` run once per worker and own any
    process-local resources — the default-mode worker creates and closes its
    parse-cache connection there. ``unit_role`` names the role used by the
    generic failure envelope when ``record_errors`` is set. With
    ``record_errors``, an exception from ``analyze`` becomes a failure-record
    envelope (mirroring the sequential runner's per-file ``except``); without
    it, the exception travels back in the envelope and the parent re-raises
    it at the unit's merge position (mirroring the sequential SBOM loop,
    which aborts the run).
    """

    analyze: Callable[[Any, Any], dict[str, Any]]
    setup: Callable[[Any], Any] | None = None
    teardown: Callable[[Any], None] | None = None
    payload: Any = None
    unit_role: str = "top-level"
    record_errors: bool = True


def payload_as_state(payload: Any) -> Any:
    """Setup hook for workers whose state *is* the payload (SBOM workers)."""
    return payload


def worker_main(
    spec: WorkerSpec,
    slot: int,
    task_queue: Any,
    result_queue: Any,
) -> None:
    """Pool worker loop: one unit assigned at a time, results indexed.

    Sends ``("idle", slot)`` before pulling each unit — this is what lets the
    parent attribute an in-flight unit to this slot when the worker dies —
    and ``("done", idx, envelope, slot)`` after it. The sentinel ``None``
    ends the loop. Exceptions escaping ``analyze`` are handled per
    ``WorkerSpec.record_errors``.
    """
    install_log_buffer()
    state = spec.setup(spec.payload) if spec.setup else None
    try:
        while True:
            result_queue.put(("idle", slot))
            unit = task_queue.get()
            if unit is None:
                break
            idx, unit_payload = unit
            try:
                envelope = spec.analyze(unit_payload, state)
            except Exception as exc:  # noqa: BLE001
                if spec.record_errors:
                    envelope = _recorded_failure_envelope(unit_payload, exc, spec.unit_role)
                else:
                    envelope = {"exception": exc, "logs": []}
            result_queue.put(("done", idx, envelope, slot))
    finally:
        if spec.teardown:
            with contextlib.suppress(Exception):
                spec.teardown(state)


def _recorded_failure_envelope(
    unit_payload: Any, exc: Exception, unit_role: str
) -> dict[str, Any]:
    """Envelope for a unit that raised under ``record_errors``.

    The events mirror what the sequential runner records for the same file —
    one attempted unit, one failure record — so the parent-side merge needs
    no special case.
    """
    return {
        "findings": [],
        "reviews": [],
        "fuzzables": [],
        "callgraphs": [],
        "events": [
            ("attempted", unit_role),
            (
                "failure",
                {
                    "file_path": str(unit_payload),
                    "unit_role": unit_role,
                    "stage": "process",
                    "exception_type": type(exc).__name__,
                    "message": str(exc),
                },
            ),
        ],
        "logs": [],
    }


def run_pool(
    units: list[tuple[int, Any]],
    num_workers: int,
    worker_spec: WorkerSpec,
    mp_context: multiprocessing.context.BaseContext | None = None,
    on_done: Callable[[int], None] | None = None,
) -> tuple[dict[int, Any], dict[int, str]]:
    """Run units across worker processes; return results keyed by unit index.

    Args:
        units: ``(index, payload)`` tuples, one per binary. The index is the
            submission position; the caller merges results in index order to
            reproduce the sequential run byte for byte.
        num_workers: Number of worker processes. Callers cap this at the unit
            count; the pool is only used with more than one unit.
        worker_spec: The :class:`WorkerSpec` every worker runs.
        mp_context: Optional multiprocessing context (tests inject ``fork``
            to unit-test worker death with patched state; production uses the
            platform default — spawn on macOS/Windows, fork on Linux).
        on_done: Parent-side callback invoked with the unit index as each
            result arrives (advances the progress bar in completion order —
            display only, never merge order).

    Returns:
        ``(envelopes, hard_failures)`` — result envelopes by index, and the
        indexes of units whose worker died hard mapped to a human-readable
        reason. Every index in ``units`` appears in exactly one of the two.

    Raises:
        PoolStartupError: workers could not be started, the respawn budget
            was exhausted, or workers kept dying without producing a result.
    """
    if not units:
        return {}, {}
    if num_workers < 1:
        raise PoolStartupError(f"num_workers must be >= 1, got {num_workers}")
    ctx = mp_context or multiprocessing.get_context()
    num_workers = min(num_workers, len(units))
    task_queues = {slot: ctx.Queue() for slot in range(num_workers)}
    result_queue = ctx.Queue()
    envelopes: dict[int, Any] = {}
    hard_failures: dict[int, str] = {}
    pending = {idx for idx, _ in units}
    unit_iter = iter(units)
    exhausted = False
    # slot -> the unit currently assigned to it (None when idle). A dead
    # worker's assignment is exactly the unit reported as hard-failed.
    in_flight: dict[int, int | None] = {}
    procs: dict[int, multiprocessing.process.BaseProcess] = {}
    sterile_deaths = 0
    spawns_allowed = len(units) * _SPAWNS_PER_UNIT + _EXTRA_SPAWNS
    sterile_threshold = max(_MIN_STERILE_DEATHS, num_workers * _STERILE_DEATHS_PER_WORKER)

    def spawn(slot: int) -> None:
        nonlocal spawns_allowed
        if spawns_allowed <= 0:
            raise PoolStartupError(
                "worker pool exceeded its respawn budget without completing the run"
            )
        spawns_allowed -= 1
        proc = ctx.Process(
            target=worker_main,
            args=(worker_spec, slot, task_queues[slot], result_queue),
            daemon=True,
        )
        proc.start()
        procs[slot] = proc
        in_flight[slot] = None

    def dispatch(slot: int) -> None:
        """Assign the next unit to an idle worker, or send the exit sentinel."""
        nonlocal exhausted
        if exhausted:
            task_queues[slot].put(None)
            return
        try:
            idx, payload = next(unit_iter)
        except StopIteration:
            exhausted = True
            task_queues[slot].put(None)
            return
        task_queues[slot].put((idx, payload))
        in_flight[slot] = idx

    try:
        for slot in range(num_workers):
            spawn(slot)
    except PoolStartupError:
        _shutdown(procs, task_queues, result_queue)
        raise
    except (OSError, ValueError, TypeError, AssertionError) as exc:
        _shutdown(procs, task_queues, result_queue)
        raise PoolStartupError(f"could not start worker processes: {exc}") from exc

    try:
        while pending:
            try:
                message = result_queue.get(timeout=_POLL_SECONDS)
            except queue.Empty:
                message = None
            if message is not None:
                kind = message[0]
                if kind == "idle":
                    slot = message[1]
                    # A stale "idle" from a dead generation is ignored; the
                    # replacement worker announces itself when it starts.
                    if slot in procs:
                        dispatch(slot)
                elif kind == "done":
                    _, idx, envelope, slot = message
                    if slot in in_flight:
                        in_flight[slot] = None
                    if idx in pending:
                        pending.discard(idx)
                        envelopes[idx] = envelope
                        sterile_deaths = 0
                        if on_done is not None:
                            on_done(idx)
            # Death scan: reap workers that exited since the last poll.
            for slot, proc in list(procs.items()):
                if proc.is_alive():
                    continue
                exitcode = proc.exitcode
                orphan = in_flight.pop(slot, None)
                del procs[slot]
                died_hard = exitcode is not None and exitcode != 0
                if died_hard and orphan is not None and orphan in pending:
                    pending.discard(orphan)
                    hard_failures[orphan] = (
                        f"worker process exited with code {exitcode} while this "
                        "unit was assigned to it (no retry: input that kills "
                        "the worker would kill every retry)"
                    )
                elif died_hard:
                    sterile_deaths += 1
                if died_hard:
                    LOG.debug(
                        "Pool worker slot %d exited with code %s (assigned unit: %s)",
                        slot, exitcode, orphan,
                    )
                    if (
                        sterile_deaths >= sterile_threshold
                        and not envelopes
                        and not hard_failures
                    ):
                        # Every worker so far died before finishing anything:
                        # the pool cannot make progress on this system.
                        raise PoolStartupError(
                            f"{sterile_deaths} worker(s) died without producing "
                            "any result; parallelism cannot make progress"
                        )
                    if pending:
                        spawn(slot)
    finally:
        _shutdown(procs, task_queues, result_queue)
    if pending:
        raise PoolStartupError(
            f"worker pool finished with {len(pending)} unit(s) unaccounted for"
        )
    return envelopes, hard_failures


def _shutdown(
    procs: dict[int, multiprocessing.process.BaseProcess],
    task_queues: dict[int, Any],
    result_queue: Any,
) -> None:
    """Terminate workers and release the queues; safe to call twice."""
    for proc in procs.values():
        if proc.is_alive():
            proc.terminate()
    for proc in procs.values():
        with contextlib.suppress(Exception):
            proc.join(timeout=5)
    for task_queue in task_queues.values():
        with contextlib.suppress(Exception):
            task_queue.close()
            task_queue.join_thread()
    with contextlib.suppress(Exception):
        result_queue.close()
        result_queue.join_thread()
