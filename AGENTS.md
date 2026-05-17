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
6. Output is written to the configured file (or stdout).

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

## Environment variables used often

- `BLINTDB_HOME`, `BLINTDB_IMAGE_URL`, `BLINTDB_REFRESH`, `USE_BLINTDB`
- `EVIDENCE_LIMIT`, `SYMBOLS_LOOKUP_BATCH_LEN`, `MIN_MATCH_SCORE`
- `BLINT_MAX_HEX_BYTES`
- `SCAN_DEBUG_MODE`, `SCAN_ID`
- `BLINT_DB_MESON_STRIP` when producing local Meson corpora in the linked `blint-db` repo

## Known sharp edges

- `config.py` is large and central; avoid broad edits unless necessary.
- Parsing code tolerates many malformed edge cases; keep exception handling intact.
- Disassembly depends on optional nyxstone install and LLVM target correctness.
- CI mode can fail builds on critical findings (`run_default_mode` + `CI` env).
- SBOM matching quality is sensitive to symbol noise. File names, tiny wrapper functions, and imported system symbols can skew scores if query filters are too loose.
