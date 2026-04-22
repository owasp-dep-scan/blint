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
- `blint/lib/binary.py`: format parsing and metadata extraction (ELF/PE/Mach-O/WASM).
- `blint/lib/disassembler.py`: nyxstone-backed function disassembly and metrics.
- `blint/lib/sbom.py`: CycloneDX object construction and dependency modeling.
- `blint/lib/android.py`: APK/AAB metadata extraction and component mapping.
- `blint/db.py`: blintdb SQLite-assisted component identification from symbols.
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
6. Capability reviews run from annotation rules (`ReviewRunner`).
7. Optional fuzzable targets are generated (`run_prefuzz`).
8. Findings/reviews/fuzzables are exported as JSON plus HTML console output.

## Operational flow (SBOM mode)

1. `run_sbom_mode` discovers binary + Android inputs.
2. `generate` builds CycloneDX 1.6 model.
3. `process_exe_file` parses binaries and maps dependencies/components.
4. Optional `--use-blintdb` enriches component identification.
5. Output is written to the configured file (or stdout).

## Agent coding guidelines for this repo

- Preserve existing CLI compatibility and JSON schema shape.
- Prefer additive metadata fields over breaking renames/removals.
- Keep cross-format behavior consistent (ELF/PE/Mach-O/WASM field normalization).
- Rule engine behavior must remain deterministic and case-insensitive where expected.
- Keep heavy operations behind explicit flags (`--disassemble`, `--deep`, `--use-blintdb`).
- Avoid weakening error handling around malformed binaries.

## Common task playbooks

### Add a new security/capability rule

1. Add or edit YAML in `blint/data/rules.yml` or `blint/data/annotations/*.yml`.
2. Ensure `id` is unique and includes required fields.
3. If using `FUNCTION_REVIEWS`, confirm `check_type` and fields align with
   `blint/lib/runners.py::_review_functions` logic.
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

## Local validation commands

```bash
poetry install
poetry run pytest -q
poetry run blint --help
poetry run blint sbom --help
```

## Environment variables used often

- `BLINTDB_HOME`, `BLINTDB_IMAGE_URL`, `BLINTDB_REFRESH`, `USE_BLINTDB`
- `EVIDENCE_LIMIT`, `SYMBOLS_LOOKUP_BATCH_LEN`, `MIN_MATCH_SCORE`
- `BLINT_MAX_HEX_BYTES`
- `SCAN_DEBUG_MODE`, `SCAN_ID`

## Known sharp edges

- `config.py` is large and central; avoid broad edits unless necessary.
- Parsing code tolerates many malformed edge cases; keep exception handling intact.
- Disassembly depends on optional nyxstone install and LLVM target correctness.
- CI mode can fail builds on critical findings (`run_default_mode` + `CI` env).
