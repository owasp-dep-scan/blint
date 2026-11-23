# blint Python API reference

blint ships a stable Python API in `blint.api`: the same engine the CLI
runs, returning typed results instead of writing report files. Consumers
that want SBOMs, diffs, findings or reviews programmatically should use
these functions and nothing else.

## Semantic versioning scope

Everything in `blint.api.__all__` is covered by semantic versioning:
signatures, result-type fields and exception hierarchies change only in
major releases, and then only with a deprecation period where practical.
Everything else in the package, including every module under `blint.lib`,
`blint.config` and `blint.cli`, is internal: those names move without
notice, and code that imports them carries no compatibility promise. The
one documented exception outside `blint.api` is the CLI itself, whose flags
and JSON output shapes are also treated as an interface.

## Entry points

### `analyze(path, ...) -> AnalysisResult`

Analyze one binary file: the API twin of `blint -i <file>`.

Args: `path` (one file); keyword-only `disassemble`, `no_reviews`,
`suggest_fuzzable`, `custom_rules_dir`, `use_cache`, `sdk_path`, `quiet`
(defaults `False` except `quiet=True`); see the docstring for each.

Returns `AnalysisResult` with `metadata` (the exported
`*-metadata.json` content), `findings` (each with a stable `finding_id`),
`reviews` (each with a stable `review_id`), `fuzzables`, and `coverage`
(the run-level `analysis_coverage` block). All values are plain JSON
types.

Raises `FileNotFoundError` (missing path), `ValueError` (directory),
`NotABinaryError` (not a format blint understands, or a container with
nothing analyzable), `AnalysisFailedError` (the analysis itself failed;
the structured record is on `.record`), and `BlintApiError` (run-level
configuration failure such as a bad SDK path).

### `analyze_many(path, ...) -> BatchAnalysisResult`

The batch twin of `analyze()`: one engine run over a file, a directory or
a mix of both, with results split back per unit. Discovery mirrors the
CLI's default mode and shares its code (directory walk for executables,
macOS bundles, ClickOnce manifests, INF files, archive extraction). Same
keyword arguments as `analyze()`.

Returns `BatchAnalysisResult` with `results` (one `AnalysisResult` per
unit, input order), `coverage` (the run-level block) and `unmatched`
(findings or reviews whose file matched no unit; normally empty, reported
rather than dropped). Inputs where nothing analyzable is discovered
return empty `results` with the reason in `coverage["notes"]`, a stated
outcome rather than a clean pass.

Raises `FileNotFoundError` and `ValueError` as for `analyze()`.

### `sbom(path, ...) -> SbomResult`

Generate a CycloneDX SBOM: the API twin of `blint sbom`. Accepts a file, a
directory or a mix (native binaries, Android apps, iOS apps, macOS bundle
directories, wasm modules, Office/MSI/ClickOnce containers). Nothing is
written unless `output_file` is given.

Keyword arguments: `deep` (deep analysis, `--deep`), `use_blintdb`
(`--use-blintdb`), `blintdb_image_url` (download location for the blintdb
image; blint's built-in URL by default), `src_dir_boms` (source BOMs for
purl enrichment), `wasm_sbom` (emit wasm Component Model components;
wasm files are skipped otherwise and reported), `android_abis` (restrict
Android analysis to these ABIs), `output_file` (write the document here),
`jobs` (parallel workers), `quiet`.

Returns `SbomResult` with `bom` (the CycloneDX document as a JSON-ready
dict, exactly what the CLI writes to disk; `None` only when no analyzable
input was discovered, with the reason in `coverage`), `coverage`
(the inputs, the discovered unit counts, and the skipped wasm files with
the reason) and `output_file` (the path written, or `None`).

Raises `FileNotFoundError`, `BlintdbUnavailableError` (`use_blintdb`
was set and the database could not be downloaded or verified; no SBOM is
returned in that case, because a degraded SBOM must not read like a
complete one) and `AnalysisFailedError` (a unit could not be processed;
SBOM generation stops rather than leaving the component out, nothing is
written, and `.record` names the error).

This entry point holds no lock: component mapping reads no rule state,
so concurrent `sbom()` calls run in parallel with each other and with
`analyze()`.

### `diff(old, new, ...) -> DiffResult`

Compare two versions of one binary: the API twin of `blint diff
--diff-json`. Each side is a binary or an exported `*-metadata.json`.

Keyword arguments: `disassemble` (disassemble binary inputs, enabling the
function-level layer), `no_reviews` (skip the review layer), `quiet`.

Returns `DiffResult` with `report`, the same document the CLI prints:
metadata delta, hardening regressions, finding/review delta and (when both
sides carry disassembly) the function-level delta. Deterministic: the
same pair always produces the same report.

Raises `DiffInputError` (an input is missing or unreadable, is a
directory, or the sides are not two versions of one binary: different
`exe_type` or architecture).

## Stable ids

Findings carry `finding_id` and reviews carry `review_id`, both computed
by `blint.lib.finding_ids` and both 32 hex characters. A finding id hashes
the rule id, the sha256 of the analyzed file's bytes, and a canonical
serialization of the finding's evidence. A review id hashes only the rule
id and the file's sha256: blint reports one review per rule per binary, so
those two already name it, and its evidence (the matched symbols and
functions) is left out because it grows when a rule gains a pattern, when
`disassemble` adds function evidence, or when `EVIDENCE_LIMIT` changes.

Deliberately left out of both hashes, so none of these re-track an item:
rendered prose (titles and descriptions), the file path and `exe_name`,
`scan_id`, timestamps, the blint version and the analysis options. A rule
description typo therefore does not mint new ids, and moving a binary
keeps them; a rebuild changes the file bytes and therefore mints new ids
by design. Consumers diffing two *versions* of one binary must pair on
evidence, not on these ids; `blint diff` does that internally.

Review ids carry an extra marker in the hash input, so a rule id that
fires as both a check and a review can never make a finding id and a
review id collide.

## Exceptions

`BlintApiError` is the base class. Subclasses: `NotABinaryError`,
`AnalysisFailedError` (carries the engine's structured failure record on
`.record`), `DiffInputError`, `BlintdbUnavailableError`.

## Locking and concurrency

`analyze()`, `analyze_many()` and `diff()` share a module-level lock
because blint's rule state lives in module globals that each run
re-initializes from the caller's options; concurrent calls serialize
rather than interleaving that state. The parse work inside a run cannot
currently be split from the checks without engine surgery, so the lock is
held for the whole engine call. `sbom()` touches no rule state and runs
lock-free. The parse cache opens one SQLite connection per run, and
nyxstone disassembler instances are created per call, so neither needs
the lock.

## What the API never does

It writes no files unless an output path is an explicit argument, it does
not read the terminal, and it does not turn a failure into a clean
result: missing inputs raise, blintdb failures raise, and empty
discoveries come back with the reason in `coverage`, never as an empty
document that reads like a successful scan.
