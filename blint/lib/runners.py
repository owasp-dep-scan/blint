import logging
import os
import shutil
import sys
from typing import Any, Literal

from rich.progress import Progress, TaskID

from blint.config import BlintOptions
from blint.cyclonedx.spec import CycloneDX
from blint.lib.analysis import (
    initialize_rules,
    report,
    run_checks,
    run_prefuzz,
    run_wasm_findings,
)
from blint.lib.android import analyze_android_app
from blint.lib.binary import build_wasm_callgraph, is_wasm_file, parse
from blint.lib.cache import CacheKeyError, ParseCache, compute_options_digest, sha256_file
from blint.lib.finding_ids import attach_finding_ids
from blint.lib.ios import (
    collect_ios_app_detailed,
    enrich_with_bundle_context,
    is_ios_app,
)
from blint.lib.parallel import (
    PoolStartupError,
    WorkerSpec,
    run_pool,
    take_worker_logs,
)
from blint.lib.review_runner import ReviewRunner
from blint.lib.sbom import generate
from blint.lib.tbd_index import TbdSdkError, load_or_build_index
from blint.lib.utils import (
    export_metadata,
    find_android_files,
    find_ios_files,
    gen_file_list,
    get_hex_truncation_count,
    is_android_app,
    reset_hex_truncation_count,
)
from blint.logger import LOG


def _validate_sdk_path(blint_options: BlintOptions) -> None:
    """Load the .tbd index once per run when --sdk-path was given.

    The failure is deliberately loud and run-level: a path with no .tbd
    files is a configuration error the analyst must see exactly once,
    before any analysis, not a per-binary degradation repeated for every
    Mach-O input. It also warms the on-disk index artifact so parallel
    workers each pay one load instead of one build.
    """
    sdk_path = getattr(blint_options, "sdk_path", None)
    if not sdk_path:
        return
    try:
        index = load_or_build_index(sdk_path)
    except TbdSdkError as exc:
        LOG.error(str(exc))
        raise SystemExit(2) from exc
    LOG.info(
        "SDK .tbd index ready: %d libraries from %d files",
        len(index.libraries),
        index.file_count,
    )


def run_sbom_mode(blint_options: BlintOptions) -> CycloneDX | Literal[False]:
    """
    Generates an SBOM for the given source directories. Binary files including android apk files are collected
    automatically.

    Args:
        blint_options (BlintOptions): A BlintOptions object containing the SBOM generation options.
    Returns:
        CycloneDX: Generated CycloneDX SBOM
    """
    _validate_sdk_path(blint_options)
    if blint_options.stdout_mode:
        LOG.setLevel(logging.ERROR)
    else:
        if blint_options.sbom_output_dir and not os.path.exists(blint_options.sbom_output_dir):
            os.makedirs(blint_options.sbom_output_dir)
    exe_files = gen_file_list(blint_options.src_dir_image)
    wasm_files = [f for f in exe_files if is_wasm_file(f)]
    if wasm_files:
        LOG.info(f"Found {len(wasm_files)} wasm file(s); these will be skipped in SBOM processing")
    android_files = []
    ios_files = []
    for src in blint_options.src_dir_image:
        if files := find_android_files(src):
            android_files += files
        if files := find_ios_files(src):
            ios_files += files
    return generate(blint_options, exe_files, android_files, ios_files)


def run_default_mode(blint_options: BlintOptions) -> None:
    reset_hex_truncation_count()
    wants_callgraph_outputs = (
        blint_options.render_mermaid_callgraph
        or blint_options.export_callgraph_graphml
        or blint_options.export_callgraph_gexf
    )
    if wants_callgraph_outputs and not blint_options.disassemble:
        LOG.info(
            "Callgraph export was requested without --disassemble; no callgraph artifacts will be generated."
        )
    exe_files = gen_file_list(blint_options.src_dir_image)
    analyzer = AnalysisRunner()
    findings, reviews, fuzzables, callgraphs = analyzer.start(blint_options, exe_files)
    report(
        blint_options,
        exe_files,
        findings,
        reviews,
        fuzzables,
        callgraphs,
        analysis_coverage=analyzer.analysis_coverage(),
    )
    truncation_count = get_hex_truncation_count()
    if truncation_count:
        LOG.info(
            f"Metadata export hex-truncated {truncation_count} undecodable byte field(s). "
            "Tune BLINT_MAX_HEX_BYTES (or set to 0 to disable truncation)."
        )

    if os.getenv("CI") and not blint_options.no_error:
        for f in findings:
            if f["severity"] == "critical":
                sys.exit(1)


class AnalysisRunner:
    """Class to analyze binaries."""

    def __init__(
        self,
        *,
        export_artifacts: bool = True,
        progress_disabled: bool = False,
        retain_metadata: bool = False,
    ) -> None:
        """Configure the runner for its caller.

        ``export_artifacts`` (CLI default) writes the per-binary
        ``*-metadata.json`` / wasm report files to ``reports_dir``; the
        Python API turns it off so ``blint.analyze()`` returns results
        without writing files. ``retain_metadata`` keeps each unit's
        exported metadata shape in ``metadata_records`` — used by the API
        for a single input; never enabled for multi-binary CLI runs, where
        retaining every parse would be an unbounded memory cost.
        ``progress_disabled`` mutes the transient progress bar for callers
        that must not touch the terminal.
        """
        self.findings: list[dict[str, Any]] = []
        self.reviews: list[dict[str, Any]] = []
        self.fuzzables: list[dict[str, Any]] = []
        self.callgraphs: list[dict[str, Any]] = []
        self.export_artifacts = export_artifacts
        self.retain_metadata = retain_metadata
        self.metadata_records: list[dict[str, Any]] = []
        self.progress: Progress = Progress(
            transient=True,
            redirect_stderr=True,
            redirect_stdout=True,
            refresh_per_second=1,
            disable=progress_disabled,
        )
        self.task: TaskID | None = None
        self.reviewer: ReviewRunner | None = None
        # Per-unit isolation bookkeeping. A "unit" is one analyzable input:
        # a top-level file, or one binary contained in an archive (.ipa).
        # Failures and skips are recorded structurally so callers can tell a
        # clean scan from a blind one (issues #122, #188).
        self.units_attempted = 0
        self.units_succeeded = 0
        self.unit_failures: list[dict[str, Any]] = []
        self.unit_skips: list[dict[str, Any]] = []
        # Attempted/succeeded are also kept per unit_role: the totals mix
        # granularities (an .ipa archive counts beside the members it
        # contains), and the breakdown is what lets a consumer compute a
        # rate over just the binaries.
        self.units_attempted_by_role: dict[str, int] = {}
        self.units_succeeded_by_role: dict[str, int] = {}
        # Parse cache (P2.2). The cache instance exists for the run only; a
        # disabled cache is None so the miss path costs nothing. Hit/miss
        # counters are kept per role for the same reason as units_by_role
        # (rule 19): a consumer must be able to decompose the totals.
        # In parallel mode (--jobs N) the parent owns no connection at all:
        # every worker opens its own (SQLite connections cannot be shared
        # across processes), and cache_enabled below is what the coverage
        # block reports.
        self.parse_cache: ParseCache | None = None
        self.cache_enabled = False
        self._parse_options_digest: str | None = None
        self.cache_hits = 0
        self.cache_misses = 0
        self.cache_stored = 0
        self.cache_by_role: dict[str, dict[str, int]] = {}
        # Ordered unit events, one tuple per attempted/succeeded/failed/
        # skipped/cache outcome in the order it happened. Sequential
        # processing accumulates state directly; parallel processing ships
        # this list back from each worker and replays it here in submission
        # order, which is what makes the merged run byte-identical to the
        # sequential one.
        self.events: list[tuple[str, ...]] = []

    def _mark_attempted(self, unit_role: str) -> None:
        self.units_attempted += 1
        self.units_attempted_by_role[unit_role] = self.units_attempted_by_role.get(unit_role, 0) + 1
        self.events.append(("attempted", unit_role))

    def _mark_success(self, unit_role: str) -> None:
        self.units_succeeded += 1
        self.units_succeeded_by_role[unit_role] = self.units_succeeded_by_role.get(unit_role, 0) + 1
        self.events.append(("succeeded", unit_role))

    def _record_failure(
        self, file_path: str, unit_role: str, stage: str, error: BaseException
    ) -> dict[str, Any]:
        """Record one isolated unit failure and keep the scan going.

        The caller owns the ``units_attempted`` accounting; this only files
        the structured failure record.
        """
        record = {
            "file_path": file_path,
            "unit_role": unit_role,
            "stage": stage,
            "exception_type": type(error).__name__,
            "message": str(error),
        }
        self.unit_failures.append(record)
        self.events.append(("failure", record))
        LOG.error(
            f"Analysis of {unit_role} unit {file_path} failed at stage {stage}: "
            f"{type(error).__name__}: {error}"
        )
        return record

    def _record_skip(self, file_path: str, unit_role: str, reason: str) -> dict[str, Any]:
        """Record one unit that was recognized but not analyzed, and why.

        As with ``_record_failure`` the caller owns the ``units_attempted``
        accounting; this only files the structured skip record.
        """
        record = {
            "file_path": file_path,
            "unit_role": unit_role,
            "reason": reason,
        }
        self.unit_skips.append(record)
        self.events.append(("skip", record))
        LOG.warning(f"Skipped {unit_role} unit {file_path}: {reason}")
        return record

    def analysis_coverage(self) -> dict[str, Any]:
        """Run-level counterpart of the per-binary ``analysis_coverage`` block.

        The per-binary block in ``blint/lib/binary.py`` counts what was
        analyzed inside one binary; this counts the units of the run itself.
        The two cannot live in the same place: each binary's metadata is
        exported before the later units run, so a run-level view can only be
        assembled by the runner once every unit has been attempted. Without
        it, a run that failed on half its inputs is indistinguishable from a
        run that never saw them.

        ``units`` totals mix granularities (an .ipa archive counts as a unit
        beside the member units it contains); ``units_by_role`` carries the
        same four counters per role so a consumer can compute a success rate
        over just the member binaries, or just the top-level inputs.
        """
        failed_by_role: dict[str, int] = {}
        for record in self.unit_failures:
            role = record["unit_role"]
            failed_by_role[role] = failed_by_role.get(role, 0) + 1
        skipped_by_role: dict[str, int] = {}
        for record in self.unit_skips:
            role = record["unit_role"]
            skipped_by_role[role] = skipped_by_role.get(role, 0) + 1
        units_by_role: dict[str, dict[str, int]] = {}
        for role in sorted(
            set(self.units_attempted_by_role) | set(failed_by_role) | set(skipped_by_role)
        ):
            units_by_role[role] = {
                "attempted": self.units_attempted_by_role.get(role, 0),
                "succeeded": self.units_succeeded_by_role.get(role, 0),
                "failed": failed_by_role.get(role, 0),
                "skipped": skipped_by_role.get(role, 0),
            }
        # Parse cache accounting (P2.2). ``enabled`` is what lets a consumer
        # tell a fast run from a cached one. Failures are never cached, so
        # every record in ``failures`` above is a fresh failure by
        # construction; ``caches_failures`` states that invariant in the
        # output itself. Per rule 19 the totals are broken down by role,
        # since only some roles (native/wasm parses) can hit the cache at
        # all — android app units never go through parse().
        by_role = {
            role: counts
            for role, counts in sorted(self.cache_by_role.items())
            if counts.get("hits") or counts.get("misses") or counts.get("stored")
        }
        return {
            "scope": "run",
            "units": {
                "attempted": self.units_attempted,
                "succeeded": self.units_succeeded,
                "failed": len(self.unit_failures),
                "skipped": len(self.unit_skips),
            },
            "units_by_role": units_by_role,
            "cache": {
                "enabled": self.cache_enabled,
                "hits": self.cache_hits,
                "misses": self.cache_misses,
                "stored": self.cache_stored,
                "caches_failures": False,
                "by_role": by_role,
            },
            "failures": list(self.unit_failures),
            "skipped": list(self.unit_skips),
        }

    def start(
        self, blint_options: BlintOptions, exe_files: list[str]
    ) -> tuple[
        list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]
    ]:
        """Starts the analysis process for the given source files.

        This function takes the command-line arguments and the reports
        directory as input, and starts the analysis process. It iterates over
        the source files, parses the metadata, checks the security properties,
        performs symbol reviews, and suggests fuzzable targets if specified.

        With ``--jobs N`` (N > 1 and more than one file) the same per-file
        work runs in a process pool and results are merged strictly in
        submission order, so the exported output is byte-identical to this
        sequential loop. ``--jobs 1`` is this loop, unchanged.

        Returns:
            tuple: A tuple of the findings, reviews, files, and fuzzables.
        """
        _validate_sdk_path(blint_options)
        initialize_rules(blint_options)
        jobs = max(1, int(getattr(blint_options, "jobs", 1) or 1))
        if jobs > 1 and len(exe_files) > 1:
            try:
                return self._start_parallel(blint_options, exe_files, jobs)
            except PoolStartupError as exc:
                # Parallelism is a performance feature and must never be the
                # reason a scan fails; the sequential path below records real
                # per-file failures through the normal isolation machinery.
                LOG.error(f"Parallel analysis unavailable ({exc}); falling back to sequential")
        self._setup_parse_cache(blint_options)
        try:
            with self.progress:
                self.task = self.progress.add_task(
                    f"[green] BLinting {len(exe_files)} binaries",
                    total=len(exe_files),
                    start=True,
                )
                for f in exe_files:
                    # One unparseable file must not abort a scan that is now much
                    # more expensive per binary (issues #122, #188): each unit is
                    # isolated and every failure is recorded in the run-level
                    # analysis coverage. Success is counted by _process_files,
                    # which knows whether the unit actually completed analysis.
                    self._mark_attempted("top-level")
                    try:
                        self._process_files(f, blint_options)
                    except Exception as e:  # noqa: BLE001
                        self._record_failure(f, "top-level", "process", e)
        finally:
            # Rule 18: the cache adds a SQLite connection to the run; it is
            # released structurally, on every path, successful or not.
            if self.parse_cache is not None:
                self.parse_cache.close()
        return self.findings, self.reviews, self.fuzzables, self.callgraphs

    def _setup_parse_cache(self, blint_options: BlintOptions, for_workers: bool = False) -> bool:
        """Prepare the run's parse cache when --cache was given.

        A cache key that cannot be derived (a new parse() option with no
        BlintOptions counterpart) disables caching for the run with a loud
        error instead of failing the scan: wrong-or-missing caching must
        never make blint unusable.

        With ``for_workers`` the parent only validates the key: SQLite
        connections cannot be shared across processes, so every pool worker
        opens its own connection in its setup hook and the parent never
        touches the cache. Returns whether caching is enabled for the run.
        """
        self.cache_enabled = False
        if not blint_options.use_cache:
            return False
        try:
            self._parse_options_digest = compute_options_digest(blint_options)
        except CacheKeyError as exc:
            LOG.error(f"Parse cache disabled for this run: {exc}")
            return False
        self.cache_enabled = True
        if for_workers:
            return True
        self.parse_cache = ParseCache()
        LOG.debug(
            "Parse cache enabled at %s", self.parse_cache.db_path
        )
        return True

    def _worker_spec(self, blint_options: BlintOptions, cache_enabled: bool) -> WorkerSpec:
        """The per-worker configuration for default-mode pool workers.

        The payload is ``BlintOptions`` plus the cache settings; it holds
        only primitives and lists, which is what makes it picklable to
        spawn-started workers.
        """
        return WorkerSpec(
            analyze=analyze_unit_default,
            setup=_worker_setup_default,
            teardown=_worker_teardown_default,
            payload={
                "blint_options": blint_options,
                "cache_enabled": cache_enabled,
                "options_digest": self._parse_options_digest,
            },
            unit_role="top-level",
            record_errors=True,
        )

    def _start_parallel(
        self, blint_options: BlintOptions, exe_files: list[str], jobs: int
    ) -> tuple[
        list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]
    ]:
        """Run one pool task per binary; merge results by submission index.

        The unit of work is the binary (no parallelism within a binary).
        Workers complete out of order; every envelope carries its submission
        index and the merge below iterates ``range(len(exe_files))``, which
        is what keeps findings/reviews/fuzzables/callgraphs and the
        run-level coverage block byte-identical to the sequential run for
        any N. A worker that dies hard (SIGKILL, segfault in LIEF, OOM) has
        its in-flight unit recorded here as a ``WorkerDied`` failure and
        every other file still gets analyzed.
        """
        cache_enabled = self._setup_parse_cache(blint_options, for_workers=True)
        spec = self._worker_spec(blint_options, cache_enabled)
        units = [(idx, f) for idx, f in enumerate(exe_files)]
        envelopes: dict[int, dict[str, Any]] = {}
        hard_failures: dict[int, str] = {}
        try:
            with self.progress:
                self.task = self.progress.add_task(
                    f"[green] BLinting {len(exe_files)} binaries ({jobs} workers)",
                    total=len(exe_files),
                    start=True,
                )
                envelopes, hard_failures = run_pool(
                    units,
                    min(jobs, len(units)),
                    spec,
                    on_done=self._advance_progress,
                )
                # Merge in submission order, never completion order.
                for idx in range(len(exe_files)):
                    if idx in envelopes:
                        self._merge_unit_envelope(envelopes[idx])
                    else:
                        self._merge_hard_failure(exe_files[idx], hard_failures[idx])
        finally:
            self.task = None
        return self.findings, self.reviews, self.fuzzables, self.callgraphs

    def _advance_progress(self, _idx: int) -> None:
        """Advance the run progress bar as worker results arrive."""
        if self.task is not None:
            self.progress.advance(self.task)

    def _merge_unit_envelope(self, envelope: dict[str, Any]) -> None:
        """Apply one worker's result to the run accumulators.

        Buffered worker log records are replayed first, then the envelope's
        ordered events, so the merged run's logs and coverage records appear
        in the same order the sequential run produced them.
        """
        for level, message in envelope.get("logs") or []:
            LOG.log(level, message)
        self.findings += envelope.get("findings") or []
        self.reviews += envelope.get("reviews") or []
        self.fuzzables += envelope.get("fuzzables") or []
        self.callgraphs += envelope.get("callgraphs") or []
        for event in envelope.get("events") or []:
            kind = event[0]
            if kind == "attempted":
                self._mark_attempted(event[1])
            elif kind == "succeeded":
                self._mark_success(event[1])
            elif kind == "failure":
                self.unit_failures.append(event[1])
                self.events.append(event)
            elif kind == "skip":
                self.unit_skips.append(event[1])
                self.events.append(event)
            elif kind == "cache":
                self._mark_cache(event[1], event[2])
            else:
                raise ValueError(f"unknown unit event kind {kind!r}")

    def _merge_hard_failure(self, file_path: str, reason: str) -> None:
        """Record a unit whose worker died hard (SIGKILL, segfault, OOM).

        Mirrors ``_record_failure`` but with a stage that names what actually
        happened: there is no exception to wrap, only an exit code.
        """
        record = {
            "file_path": file_path,
            "unit_role": "top-level",
            "stage": "worker",
            "exception_type": "WorkerDied",
            "message": reason,
        }
        self._mark_attempted("top-level")
        self.unit_failures.append(record)
        self.events.append(("failure", record))
        LOG.error(
            f"Analysis of top-level unit {file_path} failed at stage worker: "
            f"WorkerDied: {reason}"
        )
        self._advance_progress(0)

    def _mark_cache(self, outcome: str, unit_role: str) -> None:
        """Record one cache hit/miss/stored event, total and per role."""
        key = {"hit": "hits", "miss": "misses", "stored": "stored"}[outcome]
        if outcome == "hit":
            self.cache_hits += 1
        elif outcome == "miss":
            self.cache_misses += 1
        elif outcome == "stored":
            self.cache_stored += 1
        role_counts = self.cache_by_role.setdefault(
            unit_role, {"hits": 0, "misses": 0, "stored": 0}
        )
        role_counts[key] += 1
        self.events.append(("cache", outcome, unit_role))

    def _parse_with_cache(
        self, file_path: str, blint_options: BlintOptions, unit_role: str
    ) -> dict[str, Any]:
        """Parse a binary, serving the metadata from the content-addressed
        cache when the same bytes, blint version and options were parsed
        before. Only the parse is cached: checks, reviews and (for .ipa
        members) bundle enrichment always run on the returned metadata.
        Parse failures are never cached — see blint.lib.cache."""
        cache = self.parse_cache
        should_disassemble = blint_options.disassemble and not is_wasm_file(file_path)
        if cache is None:
            return parse(
                file_path,
                should_disassemble,
                wasm_strings=blint_options.wasm_strings,
                wasm_call_graph=blint_options.wasm_call_graph,
                sdk_path=blint_options.sdk_path,
            )
        file_sha = sha256_file(file_path)
        cached = cache.get(file_sha, file_path, self._parse_options_digest) if file_sha else None
        if cached is not None:
            self._mark_cache("hit", unit_role)
            return cached
        self._mark_cache("miss", unit_role)
        metadata = parse(
            file_path,
            should_disassemble,
            wasm_strings=blint_options.wasm_strings,
            wasm_call_graph=blint_options.wasm_call_graph,
            sdk_path=blint_options.sdk_path,
        )
        if file_sha and cache.put(file_sha, self._parse_options_digest, metadata):
            self._mark_cache("stored", unit_role)
        return metadata

    def _process_files(self, f: str, blint_options: BlintOptions) -> None:
        """
        Processes the given file and generates findings.
        """
        assert self.task is not None
        self.progress.update(
            self.task, description=f"Processing [bold]{os.path.basename(f)}[/bold]"
        )
        wants_callgraph_outputs = (
            blint_options.render_mermaid_callgraph
            or blint_options.export_callgraph_graphml
            or blint_options.export_callgraph_gexf
        )
        if is_android_app(f):
            metadata = self._process_android_file(f)
            if metadata is None:
                # _record_skip already logs the skip with its reason.
                self._record_skip(f, "top-level", "no_dex_bytecode")
                self.progress.advance(self.task)
                return
        elif is_ios_app(f):
            archive_processed = self._process_ios_file(f, blint_options, wants_callgraph_outputs)
            self.progress.advance(self.task)
            # The archive unit itself succeeded when collection and member
            # iteration completed; member outcomes are accounted separately.
            if archive_processed:
                self._mark_success("top-level")
            return
        else:
            should_disassemble = blint_options.disassemble and not is_wasm_file(f)
            if blint_options.disassemble and not should_disassemble:
                LOG.debug(f"Skipping disassembly for wasm file {f}")
            metadata = self._parse_with_cache(f, blint_options, "top-level")
        self._finalize_metadata(f, metadata, blint_options, wants_callgraph_outputs)
        self._mark_success("top-level")
        self.progress.advance(self.task)

    def _process_ios_file(
        self, f: str, blint_options: BlintOptions, wants_callgraph_outputs: bool
    ) -> bool:
        """Unpack an iOS/macOS app (.ipa) and analyse each contained Mach-O.

        One archive yields several binaries (the main executable plus embedded
        frameworks, dylibs and app extensions); each is parsed through the normal
        native path and enriched with the app-bundle context. Every member is
        isolated: one bad framework records a failure and the remaining members
        still get analysed.

        Returns ``True`` when the archive was collected and all members were
        attempted, ``False`` when the archive itself was skipped.
        """
        assert self.task is not None
        app, collect_reason = collect_ios_app_detailed(f)
        if app is None:
            self._record_skip(f, "top-level", collect_reason or "collect_failed")
            return False
        try:
            for entry in app["binaries"]:
                bin_path = entry["path"]
                role = entry["role"]
                self.progress.update(
                    self.task,
                    description=f"Processing [bold]{os.path.basename(bin_path)}[/bold] ({role})",
                )
                # Each contained binary is its own unit: a member that fails to
                # parse must not take the whole archive down with it.
                self._mark_attempted("ipa-member")
                try:
                    metadata = self._parse_with_cache(bin_path, blint_options, "ipa-member")
                    enrich_with_bundle_context(
                        metadata, app["bundle_info"], role, entry.get("bundle_path")
                    )
                    self._finalize_metadata(
                        bin_path, metadata, blint_options, wants_callgraph_outputs
                    )
                    self._mark_success("ipa-member")
                except Exception as e:  # noqa: BLE001
                    self._record_failure(bin_path, "ipa-member", "process", e)
            return True
        finally:
            shutil.rmtree(app["temp_dir"], ignore_errors=True)

    def _finalize_metadata(
        self,
        f: str,
        metadata: dict[str, Any],
        blint_options: BlintOptions,
        wants_callgraph_outputs: bool,
    ) -> None:
        """Export metadata and run checks/reviews/fuzzing for a parsed binary."""
        assert self.task is not None
        exe_name = metadata.get("name", f)
        wasm_report = metadata.get("wasm_report")
        # wasm needs no disassembly of its own: the wasm_tools call graph
        # converts directly into blint's callgraph payload. It is still gated on
        # --disassemble so the "no artifacts without --disassemble" message
        # stays truthful for every format.
        if (
            wasm_report
            and wants_callgraph_outputs
            and blint_options.disassemble
            and not metadata.get("callgraph")
            and (wasm_callgraph := build_wasm_callgraph(wasm_report))
        ):
            metadata["callgraph"] = wasm_callgraph
        metadata_to_export = dict(metadata)
        if wasm_report:
            metadata_to_export.pop("wasm_report", None)
        if self.retain_metadata:
            # The exported shape (wasm report split off), not the live parse
            # dict, so an API consumer sees exactly what the CLI exports.
            self.metadata_records.append({"file_path": f, "metadata": metadata_to_export})
        if self.export_artifacts:
            export_metadata(
                blint_options.reports_dir,
                metadata_to_export,
                f"{os.path.basename(exe_name)}-metadata",
            )
            if wasm_report:
                export_metadata(
                    blint_options.reports_dir,
                    wasm_report,
                    f"{os.path.basename(exe_name)}-wasm-report",
                )
        if wants_callgraph_outputs and metadata.get("callgraph"):
            self.callgraphs.append(
                {
                    "exe_name": os.path.basename(exe_name),
                    "callgraph": metadata.get("callgraph"),
                }
            )
        self.progress.update(
            self.task,
            description=f"Checking [bold]{os.path.basename(f)}[/bold] against rules",
        )
        unit_findings: list[dict[str, Any]] = []
        # Native security-property checks (PAC, CET, etc.) are meaningless for
        # Dalvik apps and would fire spuriously; the dex review supplies the
        # relevant behavioural findings instead.
        exe_type = metadata.get("exe_type")
        if exe_type != "dexbinary" and (finding := run_checks(f, metadata)):
            unit_findings += finding
        # wasm-tools findings are checks too: pass them through regardless of
        # --no-reviews so triage output stays consistent with other formats.
        if exe_type == "wasmbinary" and (finding := run_wasm_findings(f, metadata)):
            unit_findings += finding
        # Stable finding IDs (D4) are attached per binary, after the binary's
        # findings exist but before they join the run-wide list.
        attach_finding_ids(f, metadata, unit_findings)
        self.findings += unit_findings
        if not blint_options.no_reviews:
            self.do_review(exe_name, f, metadata)
        if blint_options.fuzzy and (fuzzdata := run_prefuzz(metadata)):
            self.fuzzables.append(
                {
                    "filename": f,
                    "exe_name": exe_name,
                    "methods": fuzzdata,
                }
            )

    def _process_android_file(self, f: str) -> dict[str, Any] | None:
        """Disassemble an android app's dex bytecode into review metadata.

        The Dalvik disassembler always runs for android apps (it is the only way
        to get reviewable behaviour out of them) and the merged dex callgraph is
        always embedded in the metadata, mirroring the native disassembly path.
        Returns ``None`` when no dex could be read.
        """
        assert self.task is not None
        self.progress.update(
            self.task, description=f"Disassembling [bold]{os.path.basename(f)}[/bold]"
        )
        return analyze_android_app(f, build_cg=True)

    def do_review(self, exe_name: str, f: str, metadata: dict[str, Any]) -> None:
        """Performs a review of the given file."""
        assert self.task is not None
        self.progress.update(self.task, description="Checking methods against review rules")
        self.reviewer = ReviewRunner()
        self.reviewer.run_review(metadata)
        if self.reviewer.results:
            review = self.reviewer.process_review(f, exe_name)
            self.reviews += review


def _worker_setup_default(payload: dict[str, Any]) -> dict[str, Any]:
    """Initialize one default-mode pool worker.

    Runs once per worker, before any unit. Under the spawn start method
    (macOS, Windows) the worker re-imported every module, so the module-
    global rule state is empty here and must be built; ``initialize_rules``
    clears and refills it, and is idempotent, so under fork (Linux), where
    the initialized globals were simply inherited, re-running it is a no-op
    in effect. The worker also opens its own parse-cache connection: SQLite
    connections cannot be shared across processes.
    """
    blint_options: BlintOptions = payload["blint_options"]
    initialize_rules(blint_options)
    cache = ParseCache() if payload["cache_enabled"] else None
    return {
        "blint_options": blint_options,
        "cache": cache,
        "options_digest": payload["options_digest"],
    }


def _worker_teardown_default(state: dict[str, Any]) -> None:
    """Close the worker's parse-cache connection on every exit path."""
    cache: ParseCache | None = state.get("cache")
    if cache is not None:
        cache.close()


def analyze_unit_default(file_path: str, state: dict[str, Any]) -> dict[str, Any]:
    """Analyze one top-level file inside a pool worker.

    This is the parallel twin of the sequential ``start()`` loop body: mark
    the unit attempted, run ``_process_files``, and turn any exception into
    a recorded failure exactly as the sequential path does. Everything the
    unit produces — findings, reviews, fuzzables, callgraphs, coverage
    events, buffered log records — travels back in one picklable envelope
    that the parent merges at the unit's submission index.
    """
    runner = AnalysisRunner()
    runner.task = runner.progress.add_task("unit", total=1, start=False)
    runner.parse_cache = state.get("cache")
    runner._parse_options_digest = state.get("options_digest")
    runner._mark_attempted("top-level")
    try:
        runner._process_files(file_path, state["blint_options"])
    except Exception as e:  # noqa: BLE001
        runner._record_failure(file_path, "top-level", "process", e)
    return {
        "findings": runner.findings,
        "reviews": runner.reviews,
        "fuzzables": runner.fuzzables,
        "callgraphs": runner.callgraphs,
        "events": runner.events,
        "logs": take_worker_logs(),
    }
