# tests/scripts — harness inventory

Two kinds of script live here, and they rot differently when nothing
invokes them (no CI workflow runs any of these directly; only
`validate_blintdb_small_corpus.py` is reached from the pytest suite).

**Gates** decide whether blint is correct: they exit non-zero on a
verdict. **Measurement tools** produce numbers for a human to read;
nobody should be expected to "pass" them, and nothing should gate on
their output.

## Gates

| Script | Verdict it produces |
| ------ | ------------------- |
| `verify_pointer_precision.py` | PASS/FAIL on pointer-materialisation precision vs llvm-objdump and the image bytes; exits 2 on an unusable input. Full arm64 run decodes ~2.4M instructions (~2.5 min). |
| `callgraph_kpi_baseline.py` | KPI regression gate vs `tests/data/callgraph-kpi/*-baseline.json` (+ label accuracy); exits 2 on an unusable input; refuses to write all-zero baseline entries. |
| `validate_funcdisc.py` | Runs the corpus assertions from `tests/corpus/manifest.json`; non-zero exit on any failure. |
| `determinism_jobs.py` | Byte-identity of CLI output across `--jobs 1/2/4/8` and two `PYTHONHASHSEED`s. |
| `ab_blintdb_v2_identity.py` | A/B byte-identity gate for the blintdb v2 path. |
| `callgraph_match_kpi.py` | Stripped-recovery matching experiment using the binary itself as ground truth. |
| `validate_blintdb_small_corpus.py` | blintdb component-identification validation over the small corpus manifest (also imported by `tests/test_blintdb_small_corpus_script.py`). |

## Measurement and fixture tools

| Script | What it measures or builds |
| ------ | -------------------------- |
| `bench.py` | Per-phase parse/analysis timings. |
| `jobs_bench.py` | Wall-clock / peak-RSS curves for `--jobs N`. |
| `benchmark_register_parsing.py` | Microbenchmark for disassembler register parsing. |
| `measure_pointer_materialisation.py` | Pointer-materialisation counts on real binaries. |
| `measure_static_linkage.py` | Member-level static-linkage attribution rates. |
| `measure_banner_precision.py` | Vendored-banner detection precision. |
| `measure_fuzzy_collisions.py` | Similarity-hash cross-project collision rates. |
| `build_corpus.py` | Materializes `tests/corpus/` fixtures from local toolchains. |
| `build_static_linkage_corpus.py` | Builds the static-linkage measurement corpus. |

## Running the gates

The KPI gate's decision paths run in CI via `tests/test_verification_gates.py`.
The disassembly-backed runs need llvm-objdump (`BLINT_LLVM_OBJDUMP` overrides
the path) and LLVM 18 for nyxstone (`NYXSTONE_LLVM_PREFIX=/opt/homebrew/opt/llvm@18`):

```bash
# precision gate — Mach-O x86_64 (fast, ~40s), the /bin/ls arm of the suite:
poetry run python tests/scripts/verify_pointer_precision.py /bin/ls --arch x86

# precision gate — arm64 Rust fixture (full sweep, ~2.5 min):
poetry run python tests/scripts/verify_pointer_precision.py \
  /path/to/wasm-tools-1.247.0-aarch64-macos/wasm-tools --arch arm64

# precision gate — PE (cross-validated on macOS/Linux hosts too):
poetry run python tests/scripts/verify_pointer_precision.py \
  /path/to/wasm-tools-1.247.0-x86_64-windows/wasm-tools.exe

# callgraph KPI + label accuracy (~2.5 min):
poetry run python tests/scripts/callgraph_kpi_baseline.py \
  --binary /path/to/wasm-tools-1.247.0-aarch64-macos/wasm-tools \
  --baseline tests/data/callgraph-kpi/wasm-tools-1.247.0-baseline.json \
  --labels tests/data/callgraph-kpi/wasm-tools-1.247.0-labels.json
```

Deliberately-wrong invocations must exit 2 naming the real problem —
point the precision gate at `--arch arm64` on `/bin/ls` (blint analyses
the x86_64 slice) or the KPI gate at a directory to see it.
