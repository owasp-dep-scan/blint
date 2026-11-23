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
than interleaving rule state. A full per-run rule-state refactor is the
``RuleCatalog`` concern, not this API's.

Which entry points need that lock and which do not: ``analyze()``,
``analyze_many()`` and ``diff()`` re-initialize the rule-state globals
(``initialize_rules`` clears and refills ``rules_dict`` and the review
caches), so they hold ``_ANALYSIS_LOCK`` for the whole engine call: the
parse work inside a run cannot be split from the checks without engine
surgery, and over-holding a lock costs latency, never correctness.
``sbom()`` never touches the rule state (component mapping reads only the
parsed metadata), so concurrent ``sbom()`` calls do not serialise on each
other. The parse cache opens one SQLite connection per run (multi-connection
safe), and nyxstone disassembler instances are created per call, so neither
needs the lock.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

import orjson

from blint.config import BLINTDB_IMAGE_URL, BlintOptions
from blint.lib.diff import DiffError, diff_binary_metadata
from blint.lib.runners import AnalysisRunner
from blint.lib.utils import blintdb_setup, gen_file_list, json_serializer
from blint.logger import LOG

# Serializes the rule-state users (analyze/analyze_many/diff): the engine's
# rule state is module-global and rebuilt per run, so concurrent calls must
# not interleave. sbom() does not touch that state and runs lock-free.
_ANALYSIS_LOCK = threading.Lock()

# LOG.disabled is process-global, so a quiet call toggling it directly is a
# race between concurrent calls: the second caller captures the first's
# True and restores it after the first already restored False, leaving the
# logger disabled for the rest of the process. The toggle is therefore
# depth-counted under its own lock, and only the outermost caller restores
# the value it actually observed.
_LOG_STATE_LOCK = threading.Lock()
_log_disable_depth = 0
_log_disable_saved: bool = False


class _QuietLogs:
    """Suppress blint's logger for the duration, race-safe across threads."""

    def __init__(self, quiet: bool) -> None:
        self._quiet = quiet

    def __enter__(self) -> None:
        global _log_disable_depth, _log_disable_saved
        if not self._quiet:
            return
        with _LOG_STATE_LOCK:
            if _log_disable_depth == 0:
                _log_disable_saved = bool(LOG.disabled)
            _log_disable_depth += 1
            LOG.disabled = True

    def __exit__(self, *_exc: object) -> None:
        global _log_disable_depth
        if not self._quiet:
            return
        with _LOG_STATE_LOCK:
            _log_disable_depth -= 1
            if _log_disable_depth <= 0:
                _log_disable_depth = 0
                LOG.disabled = _log_disable_saved


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

    The engine isolates per-unit failures rather than aborting; for a
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
    with _ANALYSIS_LOCK, _QuietLogs(quiet):
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
    "BatchAnalysisResult",
    "BlintApiError",
    "BlintdbUnavailableError",
    "DiffInputError",
    "DiffResult",
    "NotABinaryError",
    "SbomResult",
    "analyze",
    "analyze_many",
    "diff",
    "sbom",
]


class BlintdbUnavailableError(BlintApiError):
    """A blintdb download was requested and did not produce a usable database.

    Raised by ``sbom(use_blintdb=True)`` so a missing or truncated database
    image can never degrade silently into a symbol-only SBOM that reads like
    a complete one.
    """


class DiffInputError(BlintApiError):
    """The two diff inputs cannot be compared; the message says why."""


@dataclass
class BatchAnalysisResult:
    """The outcome of one ``analyze_many()`` call over several inputs.

    Attributes:
        results: one :class:`AnalysisResult` per analyzed unit, in input
            order; the same shape ``analyze()`` returns for one file.
        coverage: the run-level ``analysis_coverage`` block, the shape the
            CLI exports as ``Analysis-Coverage.json`` (attempted, succeeded,
            failed, skipped units and the failure records).
        unmatched: findings, reviews and fuzzables whose ``filename``
            matched no analyzed unit. Normally empty; a non-empty list means
            the engine recorded work this API could not attribute, which is
            reported rather than dropped.
    """

    results: list[AnalysisResult] = field(default_factory=list)
    coverage: dict[str, Any] = field(default_factory=dict)
    unmatched: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class SbomResult:
    """The outcome of one ``sbom()`` call.

    Attributes:
        bom: the CycloneDX document as a JSON-ready dict, byte-for-byte the
            content ``blint sbom -o <file>`` writes. ``None`` when nothing
            analyzable was discovered, with the reason in ``coverage``.
        coverage: what was found and what was skipped: the inputs, the
            discovered unit counts (executables, android apps, ios apps,
            macOS bundles) and the skipped wasm files with the reason.
        output_file: the file the document was written to, or ``None`` when
            no ``output_file`` was requested (nothing is written unless
            asked for).
    """

    bom: dict[str, Any] | None = None
    coverage: dict[str, Any] = field(default_factory=dict)
    output_file: str | None = None


@dataclass
class DiffResult:
    """The outcome of one ``diff()`` call.

    Attributes:
        report: the diff report dict, the same document ``blint diff
            --json`` prints: metadata delta, hardening regressions,
            finding/review delta and (when both sides were disassembled)
            the function-level delta.
    """

    report: dict[str, Any] = field(default_factory=dict)


def _normalize_sources(
    path: str | os.PathLike[str] | Sequence[str],
) -> list[str]:
    """Accept one path or several, files or directories, as a list of strs."""
    if isinstance(path, (str, os.PathLike)):
        paths = [path]
    else:
        paths = list(path)
        if not paths:
            raise ValueError("no input paths were given")
        if any(isinstance(p, (list, tuple, set)) for p in paths):
            raise TypeError("expected file paths or directory paths, not nested sequences")
    return [os.fspath(p) for p in paths]


def analyze_many(
    path: str | os.PathLike[str] | Sequence[str],
    *,
    disassemble: bool = False,
    no_reviews: bool = False,
    suggest_fuzzable: bool = False,
    custom_rules_dir: str | None = None,
    use_cache: bool = False,
    sdk_path: str | None = None,
    quiet: bool = True,
) -> BatchAnalysisResult:
    """Analyze several binaries or directories and return per-file results.

    The batch twin of ``analyze()``: one engine run over every discovered
    file (one rule initialization, one lock acquisition) instead of one
    serialized call per file, with the results split back per unit.
    Discovery mirrors the CLI's default mode: directories are walked for
    executables, macOS bundles and ClickOnce manifests, archive files are
    extracted, and bundle members are attributed to their bundle. An
    explicit file path is used as given, executable bit and all (the same
    gating ``blint -i`` applies).

    Args:
        path: a file, a directory, or a list mixing both.
        disassemble: disassemble functions first (``--disassemble``).
        no_reviews: skip capability reviews (``--no-reviews``).
        suggest_fuzzable: collect fuzzable-target suggestions.
        custom_rules_dir: extra YAML rule directory, this call only.
        use_cache: use the content-addressed parse cache (``--cache``).
        sdk_path: Apple SDK root for .tbd import attribution.
        quiet: suppress blint's logging and progress output (default).

    Returns:
        BatchAnalysisResult: see the dataclass. A directory with no
        analyzable file yields empty ``results`` with the reason in
        ``coverage``, a stated outcome rather than a clean pass.

    Raises:
        FileNotFoundError: one of the given paths does not exist.
        ValueError: an empty input list.
    """
    sources = _normalize_sources(path)
    missing = [p for p in sources if not os.path.exists(p)]
    if missing:
        raise FileNotFoundError(f"no such file or directory: {missing[0]}")
    options = BlintOptions(
        src_dir_image=sources,
        quiet_mode=bool(quiet),
        no_reviews=no_reviews,
        fuzzy=suggest_fuzzable,
        disassemble=disassemble,
        custom_rules_dir=custom_rules_dir,
        use_cache=use_cache,
        sdk_path=sdk_path,
    )
    exe_files = gen_file_list(options.src_dir_image)
    macos_bundles: list[str] = []
    from blint.lib.inf import find_inf_files
    from blint.lib.macos_bundle import find_macos_bundles, path_inside_any_bundle
    from blint.lib.utils import find_clickonce_files

    for src in options.src_dir_image:
        macos_bundles += find_macos_bundles(src) or []
        for finder in (find_clickonce_files, find_inf_files):
            exe_files += [f for f in (finder(src) or []) if f not in exe_files]
    exe_files = [f for f in exe_files if not path_inside_any_bundle(f, macos_bundles)]
    exe_files += macos_bundles
    batch = BatchAnalysisResult()
    if not exe_files:
        batch.coverage = {
            "units": {"attempted": 0, "succeeded": 0, "failed": 0, "skipped": 0},
            "inputs": sources,
            "notes": ["no analyzable binaries were discovered in the given inputs"],
        }
        return batch
    with _ANALYSIS_LOCK, _QuietLogs(quiet):
        runner = AnalysisRunner(
            export_artifacts=False,
            progress_disabled=bool(quiet),
            retain_metadata=True,
        )
        try:
            runner.start(options, exe_files)
        except SystemExit as exc:
            raise BlintApiError(f"analysis aborted: {exc.code}") from exc
        batch.coverage = runner.analysis_coverage()
        records = runner.metadata_records
        by_unit: dict[str, AnalysisResult] = {}
        for record in records:
            unit_path = record.get("file_path") or ""
            by_unit[unit_path] = AnalysisResult(
                metadata=_json_safe(record.get("metadata") or {}),
            )
        for finding in runner.findings:
            unit = by_unit.get(finding.get("filename"))
            if unit is not None:
                unit.findings.append(finding)
            else:
                batch.unmatched.append(finding)
        for review in runner.reviews:
            unit = by_unit.get(review.get("filename"))
            if unit is not None:
                unit.reviews.append(review)
            else:
                batch.unmatched.append(review)
        for fuzzable in runner.fuzzables:
            unit = by_unit.get(fuzzable.get("filename"))
            if unit is not None:
                unit.fuzzables.append(fuzzable)
            else:
                batch.unmatched.append(fuzzable)
        batch.results = list(by_unit.values())
        return batch


def sbom(
    path: str | os.PathLike[str] | Sequence[str],
    *,
    deep: bool = False,
    use_blintdb: bool = False,
    blintdb_image_url: str | None = None,
    src_dir_boms: Sequence[str] = (),
    wasm_sbom: bool = False,
    android_abis: Sequence[str] = (),
    output_file: str | os.PathLike[str] | None = None,
    jobs: int = 1,
    quiet: bool = True,
) -> SbomResult:
    """Generate a CycloneDX SBOM for binaries, apps or directories.

    The API twin of ``blint sbom``: the same discovery and component
    mapping, returning the document instead of the CLI's exit code. Nothing
    is written unless ``output_file`` is given. This entry point holds no
    lock: component mapping reads no rule state, so concurrent ``sbom()``
    calls run in parallel.

    Args:
        path: a file, a directory, or a list mixing both (native binaries,
            ``.apk``/``.aab``, ``.ipa``, macOS bundle directories, wasm
            modules, Office/MSI/ClickOnce containers).
        deep: deep analysis (``--deep``; enables disassembly-backed
            matching and the dex callgraph export).
        use_blintdb: identify components against the blintdb database
            (``--use-blintdb``).
        blintdb_image_url: where to download the blintdb image from when
            the database is missing (defaults to blint's built-in URL).
        src_dir_boms: source BOMs whose purls enrich component matching
            (``--src-dir-boms``).
        wasm_sbom: emit components from wasm modules' Component Model
            interface imports (``--wasm-sbom``); wasm files are skipped
            otherwise, and the skipped paths are reported in the result.
        android_abis: analyze only these Android ABIs (``--android-abi``);
            empty means every ABI the app ships.
        output_file: write the document to this path (``-o``). ``None``
            (the default) writes nothing anywhere.
        jobs: parallel workers for large scans (``--jobs``).
        quiet: suppress blint's logging and progress output (default).

    Returns:
        SbomResult: see the dataclass. ``bom`` is ``None`` only when no
        analyzable input was discovered, and the coverage block says so.

    Raises:
        FileNotFoundError: one of the given paths does not exist.
        BlintdbUnavailableError: ``use_blintdb=True`` and the database
            could not be downloaded or verified. The SBOM is not returned
            in that case: a degraded SBOM must not read like a complete one.
    """
    sources = _normalize_sources(path)
    missing = [p for p in sources if not os.path.exists(p)]
    if missing:
        raise FileNotFoundError(f"no such file or directory: {missing[0]}")
    from blint.lib.binary_wasm import is_wasm_file
    from blint.lib.macos_bundle import find_macos_bundles, path_inside_any_bundle
    from blint.lib.sbom import generate
    from blint.lib.utils import find_android_files, find_clickonce_files, find_ios_files

    output_path = os.fspath(output_file) if output_file is not None else None
    options = BlintOptions(
        sbom_mode=True,
        deep_mode=bool(deep),
        no_error=True,
        no_reviews=True,
        quiet_mode=bool(quiet),
        src_dir_image=sources,
        stdout_mode=False,
        use_blintdb=bool(use_blintdb),
        image_url=blintdb_image_url or (BLINTDB_IMAGE_URL if use_blintdb else ""),
        sbom_output=output_path,
        src_dir_boms=list(src_dir_boms),
        wasm_sbom=bool(wasm_sbom),
        android_abis=list(android_abis),
        jobs=int(jobs),
    )
    coverage: dict[str, Any] = {"inputs": sources}
    if use_blintdb and not blintdb_setup(options):
        raise BlintdbUnavailableError(
            "the blintdb database could not be downloaded or verified; no SBOM was generated"
        )
    with _QuietLogs(quiet):
        exe_files = gen_file_list(options.src_dir_image)
        for src in options.src_dir_image:
            exe_files += [f for f in (find_clickonce_files(src) or []) if f not in exe_files]
        android_files: list[str] = []
        ios_files: list[str] = []
        macos_bundles: list[str] = []
        for src in options.src_dir_image:
            android_files += find_android_files(src) or []
            ios_files += find_ios_files(src) or []
            macos_bundles += find_macos_bundles(src) or []
        exe_files = [f for f in exe_files if not path_inside_any_bundle(f, macos_bundles)]
        skipped_wasm = [] if wasm_sbom else [f for f in exe_files if is_wasm_file(f)]
        coverage["units"] = {
            "executables": len(exe_files),
            "android_apps": len(android_files),
            "ios_apps": len(ios_files),
            "macos_bundles": len(macos_bundles),
        }
        coverage["skipped"] = {
            "wasm": skipped_wasm,
            "reason": (
                "wasm modules are skipped unless wasm_sbom=True "
                "(Component Model interface imports only)"
            ),
        }
        if not (exe_files or android_files or ios_files or macos_bundles):
            coverage["notes"] = ["no analyzable inputs were discovered"]
            return SbomResult(bom=None, coverage=coverage, output_file=None)
        sbom_obj = generate(options, exe_files, android_files, ios_files, macos_bundles)
        if sbom_obj is False:
            coverage["notes"] = ["no analyzable inputs were discovered"]
            return SbomResult(bom=None, coverage=coverage, output_file=None)
        document = orjson.loads(
            sbom_obj.model_dump_json(
                exclude_none=True,
                exclude_defaults=True,
                warnings=False,
                by_alias=True,
            )
        )
        return SbomResult(bom=document, coverage=coverage, output_file=output_path)


def diff(
    old: str | os.PathLike[str],
    new: str | os.PathLike[str],
    *,
    disassemble: bool = False,
    no_reviews: bool = False,
    quiet: bool = True,
) -> DiffResult:
    """Compare two versions of one binary and return the report.

    The API twin of ``blint diff``: the same four-layer report (metadata
    delta, hardening regressions, finding/review delta, function-level
    delta when both sides carry disassembly). Each side is a binary or an
    exported ``*-metadata.json``. Like ``analyze()`` this holds the
    analysis lock, because the diff recomputes findings and reviews under
    the module-global rule state.

    Args:
        old: binary or ``*-metadata.json`` for the old version.
        new: same for the new version.
        disassemble: disassemble binary inputs (enables the function layer).
        no_reviews: skip the capability-review layer.
        quiet: suppress blint's logging output (default).

    Returns:
        DiffResult: see the dataclass.

    Raises:
        DiffInputError: an input is missing or unreadable, is a directory,
            or the two sides are not two versions of one binary (different
            exe_type or architecture).
    """
    with _QuietLogs(quiet), _ANALYSIS_LOCK:
        try:
            report = diff_binary_metadata(
                os.fspath(old),
                os.fspath(new),
                disassemble=disassemble,
                no_reviews=no_reviews,
            )
        except DiffError as exc:
            raise DiffInputError(str(exc)) from exc
    return DiffResult(report=report)
