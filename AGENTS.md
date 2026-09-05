# AGENTS.md

This guide helps AI coding agents work effectively in the `blint` repository.

## Mission

`OWASP blint` is a binary linter, disassembler, and SBOM generator for ELF, PE, Mach-O, WASM, and Android artifacts.

Primary workflows:

1. Security posture checks (PIE, NX, RELRO, canary, signing, PE hardening features).
2. Capability reviews from symbols/imports/functions using YAML rules.
3. Optional function disassembly (`--disassemble`) with nyxstone for advanced behavior detection.
4. CycloneDX SBOM generation (`blint sbom`) for binaries and Android apps.

## Repository map

- `blint/cli.py`: CLI parser, subcommands, and app entrypoint.
- `blint/config.py`: defaults, env vars, rule constants, disassembly indicator lists.
- `blint/lib/runners.py`: default analysis flow and SBOM flow orchestration.
- `blint/lib/analysis.py`: rule loading, checks execution, review engine, report writing.
- `blint/lib/review_runner.py`: `ReviewRunner` coordination for imports/symbols/entries/functions.
- `blint/lib/review_utils.py`: generic pattern-review matching and rule-option coercion.
- `blint/lib/function_reviews.py`: `FUNCTION_REVIEWS` heuristics and metric evaluation.
- `blint/lib/binary.py`: format parsing and metadata extraction (ELF/PE/Mach-O/WASM).
- `blint/lib/disassembler.py`: nyxstone-backed function disassembly and metrics.
- `blint/lib/sbom.py`: CycloneDX object construction and dependency modeling.
- `blint/lib/android.py`: APK/AAB metadata extraction and component mapping.
- `blint/db.py`: blintdb v2 SQLite-assisted component identification from symbols, binary-name hints, and disassembly hashes.
- `blint/data/rules.yml`: built-in hardening/security checks.
- `blint/data/annotations/*.yml`: built-in capability and behavior reviews.
- `docs/METADATA.md`, `docs/DISASSEMBLE.md`, `docs/RULES.md`: deep reference docs.
- `tests/`: unit tests and fixture metadata.

## Operational flow (default mode)

1. CLI builds `BlintOptions` (`blint/cli.py`).
2. `run_default_mode` gathers candidate binaries (`gen_file_list`).
3. Each binary is parsed (`blint/lib/binary.py::parse`).
4. Raw metadata is exported as `*-metadata.json`.
5. Security checks run from `rules.yml` (`run_checks`).
6. Capability reviews run from annotation rules (`blint/lib/review_runner.py::ReviewRunner`).
7. Optional fuzzable targets are generated (`run_prefuzz`).
8. Findings/reviews/fuzzables are exported as JSON plus HTML console output.

## Operational flow (SBOM mode)

1. `run_sbom_mode` discovers binary + Android inputs.
2. `generate` builds CycloneDX 1.6 model.
3. `process_exe_file` parses binaries and maps dependencies/components.
4. Optional `--use-blintdb` enriches component identification.
5. `--use-blintdb --deep` automatically enables disassembly and uses function-hash lookup before symbol fallback.
6. Wasm inputs are skipped unless `--wasm-sbom` is set, which emits components from the Component Model binary's imported WIT interface packages (exact evidence only; exports stay a parent property).
7. Output is written to the configured file (or stdout).

## Agent coding guidelines for this repo

- Preserve existing CLI compatibility and JSON schema shape.
- Prefer additive metadata fields over breaking renames/removals.
- Keep cross-format behavior consistent (ELF/PE/Mach-O/WASM field normalization).
- Rule engine behavior must remain deterministic and case-insensitive where expected.
- Keep heavy operations behind explicit flags (`--disassemble`, `--deep`, `--use-blintdb`).
- Avoid weakening error handling around malformed binaries.
- Always check for Windows path separators/characters (`\` vs `/`, drive letters, basename handling) when writing or updating filesystem logic, fixtures, and especially unit tests; avoid POSIX-only raw-string assertions when the behavior is path-based.
- Nyxstone currently provides disassembly text, but not structured operand/register metadata; register usage and call-target heuristics in `blint/lib/disassembler.py` must therefore remain text-based.
- For blintdb-backed SBOM matching, prefer exact project evidence over permissive fuzzy expansion. False positives in SBOM output are harder to review than missed low-confidence hints.
- Keep `blint/lib/indicators.py` high-signal and avoid turning it into a generic phrase dump. Prefer compact technical tokens over broad prose/CVE strings, and prefer high-quality disassembly-based detection or `FUNCTION_REVIEWS` heuristics when those can express the behavior reliably.

## Common task playbooks

### Add a new security/capability rule

1. Add or edit YAML in `blint/data/rules.yml` or `blint/data/annotations/*.yml`.
2. Ensure `id` is unique and includes required fields.
3. If using `FUNCTION_REVIEWS`, confirm `check_type` and fields align with
   `blint/lib/function_reviews.py` evaluation logic.
4. Add/adjust tests in `tests/test_analysis.py` with fixture metadata.

### Add metadata extraction for a format

1. Extend relevant parser section in `blint/lib/binary.py`.
2. Keep cleanup compatibility (`cleanup_dict_lief_errors`).
3. Update `docs/METADATA.md` for any new top-level or nested keys.
4. Add focused tests and fixtures under `tests/data/`.

### Extend SBOM mapping

1. Implement or refine component conversion in `blint/lib/sbom.py`.
2. Keep `bom_ref` stable and dependency refs consistent.
3. Preserve deep-mode behavior and avoid huge default output growth.
4. If the change touches `blint/db.py`, `blint/lib/sbom.py`, or blintdb evidence fields, validate both symbol-only and deep disassembly-assisted matching.

### WASM: wasm-tools upgrades

`blint/lib/binary.py::parse_wasm_metadata` normalizes the `wasm_tools` library's report into blint metadata. When bumping the `wasm-tools` floor in `pyproject.toml` (and `poetry.lock`):

1. Diff the library's release notes/changelog between the old and new pinned versions to find new `analysis` keys (capabilities, detections, findings) and new `types[]`/`sections[]`/`strings[]` fields.
2. Map new attributes additively into `parse_wasm_metadata` — never rename or drop existing keys. Prefer small summary fields (e.g. `wasm_isa_capabilities`, `wasm_types_summary`, `wasm_debug_info_present`) over re-exporting the full raw structure; the full payload always stays available in the companion `*-wasm-report.json`.
3. When summarizing counts by a category the library may extend later (e.g. type `kind`), don't hardcode the known kinds only — merge in any additional kind so per-key counts always sum to the reported `total`.
4. Add fixtures under `tests/data/*.wasm` exercising the new decode paths (small hand-built modules are fine — see `tests/test_binary.py::_debug_wasm_module` for a minimal DWARF-bearing module built inline without a binary blob) and cover them in `tests/test_binary.py`.
5. Update `docs/METADATA.md`'s WASM attribute table and the "wasm-tools X.Y attributes" prose section.
6. Run the full test suite and, since `blint/lib/binary.py` changed, sanity-check against the [callgraph regression validation policy](#callgraph-regression-validation-policy) below — wasm-only field mapping changes are exempt from re-running native-architecture KPI baselines, but say so explicitly rather than skipping silently.
7. Bump blint's own version (see below) — this is a feature addition, not a patch.

### Extend blintdb-backed matching

1. Treat `blint-db/` as the reference implementation for schema and corpus generation, but keep `blint` free of a runtime dependency on that package.
2. Prefer project-level lookups over per-binary fan-out when matching SBOM components.
3. Use `binary_type`, `llvm_target_tuple`, and binary-name hints to suppress false positives before lowering thresholds.
4. Ignore tiny low-information function hashes unless there is a strong reason to keep them.
5. When changing query shape, also consider indexes in `blint-db/blint_db/handlers/sqlite_handler.py`.

## Local validation commands

```bash
poetry install
poetry run pytest -q
poetry run blint --help
poetry run blint sbom --help
```

For blintdb-backed SBOM changes, also run a small real corpus validation against the linked `blint-db` workspace:

```bash
cd /path/to/blint
python tests/scripts/validate_blintdb_small_corpus.py --ecosystems meson
python tests/scripts/validate_blintdb_small_corpus.py --ecosystems vcpkg
python tests/scripts/validate_blintdb_small_corpus.py --ecosystems homebrew
```

The manifest for that workflow lives in `tests/data/blintdb-small-corpus.json` and currently covers 5 selectors each for Meson, vcpkg, and Homebrew.

The generated `summary.json` keeps per-ecosystem provenance in `ecosystems.<name>.provenance`, mirroring the linked `blint-db` run metadata. When build diagnostics matter, inspect `projects.build_failures`, which is exposed there as a flattened list of per-project failure records with keys such as `selector`, `project_name`, `ecosystem`, `build_system`, `status`, `stage`, and `message`, plus optional fields like `returncode` and `exception_type`.

### Callgraph regression validation policy

For any change that can affect disassembly or callgraph output (for example edits in
`blint/lib/disassembler.py`, `blint/lib/binary.py`, `blint/lib/callgraph_kpi.py`,
callgraph export/matching code, or callgraph fixture baselines/labels), agents must
validate KPI baseline + label accuracy for **all architecture entries** present in:

- `tests/data/callgraph-kpi/wasm-tools-1.247.0-baseline.json` (`entries` keys)
- `tests/data/callgraph-kpi/wasm-tools-1.247.0-labels.json` (`entries` keys)

Use `tests/scripts/callgraph_kpi_baseline.py` for each architecture fixture, passing
both `--baseline` and `--labels`. Do not update one architecture baseline in isolation
without checking the others for silent drift.

For fast iterative experiments (especially callgraph tuning), prefer quiet non-review runs:

```bash
poetry run blint -q --no-banner --no-reviews -i /path/to/binary -o /path/to/reports --disassemble
```

## Bumping blint's version

**Do not bump the version as part of an ordinary change.** The version is bumped
deliberately, once, when a release is cut — not once per feature, packet or
pull request. A branch that bumps it conflicts with every other branch in
flight, and a version that moves on every merge stops meaning anything to the
people reading it. If you think a change warrants a release, say so in the PR
and leave the version alone.

When a release *is* being cut, the version string is duplicated across several
files with no single source of truth — update all of them together, in the same
commit:

- `pyproject.toml` (`version = "..."`)
- `Info.plist` (`CFBundleVersion`)
- `file_version_info.txt` (`filevers`, `prodvers`, `FileVersion`, `ProductVersion` — note the four-part `x,y,z,0` tuple form alongside the dotted `x.y.z.0` strings)
- `Dockerfile` (`org.opencontainers.image.version` — uses a trailing `.x` wildcard, e.g. `"3.4.x"`, not the exact patch version)

Use `grep -rn "<old-version>"` across the repo (excluding `.git`, `.venv`, `node_modules`) before committing to make sure nothing was missed.

## Environment variables used often

- `BLINTDB_HOME`, `BLINTDB_IMAGE_URL`, `BLINTDB_REFRESH`, `USE_BLINTDB`
- `EVIDENCE_LIMIT`, `SYMBOLS_LOOKUP_BATCH_LEN`, `MIN_MATCH_SCORE`
- `BLINT_MAX_HEX_BYTES`
- `BLINT_MAX_WASM_INSTRUCTIONS` (total instruction-stream budget per wasm report, divided max-min fair across functions; 0 disables)
- `BLINT_CACHE_DIR` (parse-cache store location; defaults to the user cache directory)
- `BLINT_CACHE_MAX_BYTES` (parse-cache size bound; default 1 GiB, 0 disables eviction)
- `SCAN_DEBUG_MODE`, `SCAN_ID`
- `BLINT_DB_MESON_STRIP` when producing local Meson corpora in the linked `blint-db` repo

## Known sharp edges

- `config.py` is large and central; avoid broad edits unless necessary.
- Parsing code tolerates many malformed edge cases; keep exception handling intact.
- Disassembly depends on optional nyxstone install and LLVM target correctness.
- CI mode can fail builds on critical findings (`run_default_mode` + `CI` env).
- SBOM matching quality is sensitive to symbol noise. File names, tiny wrapper functions, and imported system symbols can skew scores if query filters are too loose.
