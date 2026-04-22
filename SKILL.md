# SKILL.md

This file defines practical skills an AI agent should apply when working on `blint`.

## Skill: Navigate blint architecture quickly

- Start at `blint/cli.py` to identify mode (`default`, `sbom`, `db`).
- Follow orchestration in `blint/lib/runners.py`.
- For extraction logic, use `blint/lib/binary.py` and `blint/lib/android.py`.
- For rule behavior, use `blint/lib/analysis.py` and `blint/data/annotations/*.yml`.
- For SBOM behavior, use `blint/lib/sbom.py` and `blint/cyclonedx/spec.py`.

## Skill: Implement rule-driven behavior safely

- Understand rule types:
  - `rules.yml` -> hardening checks (`run_checks`).
  - annotations -> reviews (`METHOD_REVIEWS`, `SYMBOL_REVIEWS`, etc.).
  - `FUNCTION_REVIEWS` -> disassembly-derived behavior checks.
- Keep rule IDs stable and unique.
- Match field paths used in `function_metric` with actual metadata shape.
- Respect evidence limits (`EVIDENCE_LIMIT`) to avoid noisy output.

## Skill: Work with binary metadata extraction

- Preserve format-specific fields while maintaining normalized top-level fields.
- Do not break keys used downstream by checks/reviews/SBOM mappers.
- Keep defensive parsing style: suppress parser exceptions where already expected.
- Validate changes against representative fixtures in `tests/data/*.json` and `tests/data/*.wasm`.

## Skill: Extend disassembly analytics

- `--disassemble` is optional; do not force it into default flows.
- Avoid architecture-specific regressions:
  - x86/x64
  - AArch64/ARM64
  - MIPS/microMIPS/MIPS16 fallback paths
- Keep heuristics lightweight and deterministic.
- Ensure new indicators are configurable/constants-based when possible.

## Skill: Maintain SBOM correctness

- Preserve CycloneDX output validity (spec 1.6 model in this repo).
- Ensure each component has a stable `bom_ref`.
- Avoid dependency self-loops.
- Keep deep-mode details in properties, not default minimal output.
- Respect `--stdout` and output path behavior.

## Skill: Use blintdb integration properly

- Database usage is optional and should not block core execution.
- Keep behavior safe when DB is missing or download fails.
- Maintain current score-threshold semantics in `blint/db.py`.
- Avoid introducing non-read-only DB access in analysis paths.

## Skill: Testing and validation expectations

- Core tests:
  - `tests/test_analysis.py`
  - `tests/test_binary.py`
  - `tests/test_android.py`
  - `tests/test_disassembler.py`
- Add fixture-based tests for parser/rule changes.
- Prefer narrow tests for one behavior change at a time.

## Skill: Documentation updates with code changes

- Update `docs/RULES.md` when rule schema/usage changes.
- Update `docs/METADATA.md` when metadata keys/meaning change.
- Update `docs/DISASSEMBLE.md` when disassembly fields/heuristics change.
- Keep README examples aligned with actual CLI flags.

## Skill: High-confidence change checklist

- Confirm changed fields are consumed correctly by:
  - checks
  - reviews
  - report exporters
  - SBOM generation
- Run tests after editing Python logic.
- Ensure no accidental behavior change in non-targeted binary formats.
- For WASM parsing changes, verify both normalized fields (`imports`, `dynamic_entries`, `functions`) and raw passthrough fields (`wasm_report`, `wasm_analysis`).
