"""Stable Python API for analyzing binaries with blint (D4).

``blint.analyze()`` runs the same engine path the CLI runs —
``AnalysisRunner.start()`` over the parsed metadata, the same rule loading,
the same checks and reviews — and returns the results instead of writing
report files. It does not export artifacts and does not touch the terminal
unless asked to.

Re-entrancy contract, stated plainly: blint's rule state lives in module
globals that ``AnalysisRunner.start()`` re-initializes from the caller's
options on every run, so sequential ``analyze()`` calls each see exactly the
rules they asked for — the same results a fresh process would produce. The
globals cannot be shared by *concurrent* calls, so a module-level lock
serializes them: threads calling ``analyze()`` block on each other rather
than interleaving rule state. A full per-run rule-state refactor is P3.2's
``RuleCatalog`` concern, not this API's.
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field
from typing import Any

import orjson

from blint.config import BlintOptions
from blint.lib.runners import AnalysisRunner
from blint.lib.utils import json_serializer
from blint.logger import LOG

# Serializes analyze() calls: the engine's rule state is module-global and
# rebuilt per run, so concurrent calls must not interleave.
_ANALYSIS_LOCK = threading.Lock()


class BlintApiError(Exception):
    """Base class for input problems blint reports through the API."""


class NotABinaryError(BlintApiError):
    """The input exists but is not a binary format blint can analyze.

    Raised when the parse produced no ``exe_type`` (the same near-empty
    metadata a nonexistent path yields — the trap AGENTS.md documents) or
    when a recognized container was skipped (for example an apk with no dex
    bytecode). Distinct from ``AnalysisFailedError``: the file is the
    problem, not blint.
    """


class AnalysisFailedError(BlintApiError):
    """blint attempted the unit and failed; the failure record is attached.

    The engine isolates per-unit failures rather than aborting (P0.1); for a
    single-input API call the isolation record is turned back into an
    exception so a caller cannot mistake a failed analysis for a clean one.
    """

    def __init__(self, message: str, record: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.record = record


@dataclass
class AnalysisResult:
    """The outcome of one ``analyze()`` call.

    Attributes:
        metadata: the parsed metadata dict — the same content the CLI
            exports as ``*-metadata.json`` (the wasm report is split off,
            matching the export). ``None`` when the input was an archive
            (``.ipa``) that yielded several member binaries; their findings
            and reviews are in the lists and their accounting in
            ``coverage``.
        findings: security-check findings, each carrying a stable
            ``finding_id`` (see ``blint.lib.finding_ids``).
        reviews: capability reviews; these do not carry finding IDs yet.
        fuzzables: fuzzable-target suggestions (``suggest_fuzzable=True``).
        coverage: the run-level ``analysis_coverage`` block — attempted /
            succeeded / failed / skipped units and the failure records —
            the same shape the CLI exports as ``Analysis-Coverage.json``.
            The per-binary coverage block stays in
            ``metadata["analysis_coverage"]``; both are pre-existing
            shapes.

    Everything on this dataclass is plain JSON types: it serializes with
    ``json.dumps`` without a custom encoder.
    """

    metadata: dict[str, Any] | None = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    reviews: list[dict[str, Any]] = field(default_factory=list)
    fuzzables: list[dict[str, Any]] = field(default_factory=list)
    coverage: dict[str, Any] = field(default_factory=dict)


def _json_safe(metadata: dict[str, Any]) -> dict[str, Any]:
    """Return the metadata as plain JSON types, exactly as it is exported.

    The parse dict may hold ``bytes`` (for example Mach-O signature blobs),
    which the export path converts through ``json_serializer``. Running the
    same conversion here keeps ``result.metadata`` equal to the exported
    ``*-metadata.json`` content instead of a close cousin of it.
    """
    return orjson.loads(orjson.dumps(metadata, default=json_serializer))


def analyze(
    path: str | os.PathLike[str],
    *,
    disassemble: bool = False,
    no_reviews: bool = False,
    suggest_fuzzable: bool = False,
    custom_rules_dir: str | None = None,
    use_cache: bool = False,
    sdk_path: str | None = None,
    quiet: bool = True,
) -> AnalysisResult:
    """Analyze one binary file and return the findings for it.

    This is the API twin of the default CLI mode over a single file: the
    same ``AnalysisRunner`` engine path, so results agree field for field
    with ``blint -i <path>`` run with the matching flags. It analyzes the
    exact file given — no executable-bit gating, no directory scanning, no
    ``.ar`` extraction; point those at the CLI.

    Args:
        path: the binary to analyze.
        disassemble: disassemble functions first (the CLI's
            ``--disassemble``); enables the disassembly-derived reviews.
        no_reviews: skip capability reviews (``--no-reviews``).
        suggest_fuzzable: collect fuzzable-target suggestions
            (``--suggest-fuzzable``).
        custom_rules_dir: extra YAML rule directory (``--custom-rules-dir``).
            Applied for this call only; later calls are unaffected.
        use_cache: use the content-addressed parse cache (``--cache``).
        sdk_path: Apple SDK root for .tbd import attribution
            (``--sdk-path``).
        quiet: suppress blint's logging and progress output (default). Pass
            ``False`` to let log records through to the configured handler.

    Returns:
        AnalysisResult: see the dataclass.

    Raises:
        FileNotFoundError: ``path`` does not exist.
        ValueError: ``path`` is a directory.
        NotABinaryError: the file is not a binary blint understands (or a
            recognized container with nothing analyzable in it).
        AnalysisFailedError: the analysis of the input itself failed; the
            structured failure record is on ``.record``. Failures of
            members inside an archive do not raise — they are recorded in
            ``coverage["failures"]`` with the partial results returned.
    """
    file_path = os.fspath(path)
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"no such file: {file_path}")
    if os.path.isdir(file_path):
        raise ValueError(
            f"blint.analyze() analyzes one binary file, got directory: {file_path}. "
            "Directory scans are the CLI's job (blint -i <dir>)."
        )
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"not a regular file: {file_path}")
    options = BlintOptions(
        src_dir_image=[file_path],
        quiet_mode=bool(quiet),
        no_reviews=no_reviews,
        fuzzy=suggest_fuzzable,
        disassemble=disassemble,
        custom_rules_dir=custom_rules_dir,
        use_cache=use_cache,
        sdk_path=sdk_path,
    )
    with _ANALYSIS_LOCK:
        log_disabled_before = LOG.disabled
        if quiet:
            LOG.disabled = True
        try:
            runner = AnalysisRunner(
                export_artifacts=False,
                progress_disabled=bool(quiet),
                retain_metadata=True,
            )
            try:
                runner.start(options, [file_path])
            except SystemExit as exc:
                # Run-level configuration failures (a bad --sdk-path) exit
                # the CLI; through the API they become ordinary errors.
                raise BlintApiError(f"analysis aborted: {exc.code}") from exc
            coverage = runner.analysis_coverage()
            _raise_for_top_level_outcome(runner, coverage, file_path)
            records = runner.metadata_records
            if not records:
                raise NotABinaryError(
                    f"blint could not extract any analyzable binary from {file_path}"
                )
            metadata: dict[str, Any] | None
            if len(records) == 1:
                metadata = _json_safe(records[0]["metadata"])
                if not metadata.get("exe_type"):
                    raise NotABinaryError(f"{file_path} is not a binary format blint understands")
            else:
                # An archive (.ipa) yielded several member binaries; their
                # findings and reviews are in the lists, their metadata went
                # nowhere (exports are off by design).
                metadata = None
            return AnalysisResult(
                metadata=metadata,
                findings=runner.findings,
                reviews=runner.reviews,
                fuzzables=runner.fuzzables,
                coverage=coverage,
            )
        finally:
            LOG.disabled = log_disabled_before


def _raise_for_top_level_outcome(
    runner: AnalysisRunner, coverage: dict[str, Any], file_path: str
) -> None:
    """Turn a failed or skipped top-level unit into an exception.

    Member failures inside archives are deliberately left in the coverage
    block: the top-level unit succeeded there, and the partial results plus
    ``coverage["failures"]`` are the honest answer.
    """
    top_level = (coverage.get("units_by_role") or {}).get("top-level") or {}
    if top_level.get("failed"):
        record = next(
            (r for r in runner.unit_failures if r.get("unit_role") == "top-level"),
            None,
        )
        stage = (record or {}).get("stage", "process")
        exc_type = (record or {}).get("exception_type", "Exception")
        message = (record or {}).get("message", "")
        raise AnalysisFailedError(
            f"analysis of {file_path} failed at stage {stage}: {exc_type}: {message}",
            record=record,
        )
    if top_level.get("skipped"):
        record = next((r for r in runner.unit_skips if r.get("unit_role") == "top-level"), None)
        reason = (record or {}).get("reason", "skipped")
        raise NotABinaryError(f"{file_path} was not analyzed: {reason}")


__all__ = [
    "AnalysisFailedError",
    "AnalysisResult",
    "BlintApiError",
    "NotABinaryError",
    "analyze",
]
