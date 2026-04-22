# Callgraph Analysis

This document describes how `blint` computes callgraph metadata and exports, including
current heuristics, confidence semantics, known limitations, and practical FP/FN triage.

## What the Callgraph Represents

`blint` builds a static callgraph from the `disassembled_functions` [attribute](./DISASSEMBLE.md).

- Internal edge: source and destination both map to known internal function nodes.
- External edge: source has call evidence but destination cannot be mapped uniquely.
- Edge kinds:
  - `direct`: direct call instruction (`call`, `bl`, `jal`, etc.)
  - `tailcall`: terminal unconditional jump treated as call transfer
  - `indirect_hint`: inferred indirect target (register/memory-chain heuristic)
- Confidence levels:
  - `high`: direct match to concrete internal destination
  - `medium`: deterministic but approximate recovery (for example tailcall recovery)
  - `low`: heuristic inference or unresolved external entry

### Implementation principles:

- **Determinism:** Node ordering and tie-breaking are explicitly stable.
- **Alias collapse:** Multiple symbols sharing one entry address are collapsed, reducing false ambiguity.
- **Architecture handling:** x86, AArch64, and MIPS operand normalization paths are implemented.
- **Heuristic transparency:** Unresolved targets are retained with reason buckets instead of dropped.
- **Operational export:** Confidence filtering is implemented for Mermaid, GraphML, and GEXF exports.

### Unique heuristics:

- Register-target tracking (`_update_register_target`) supports immediate and memory-chain recovery.
- Tailcall recovery emits terminal unconditional branch edges as `tailcall` targets.
- Windows x86_64 chain propagation is depth-limited (`chain_hop_limit=2`) to contain FP growth.
- Windows AArch64 excludes indexed memory chain propagation and non-canonical high candidates.
- Mach-O disassembly skips system-library symbol names that start with `/usr/lib/` or `/System/Library/`.

## End-to-End Algorithm

## Pass 1: Node Construction and Alias Collapse

Source: `disassembled_functions` entries.

Per function node fields:

- `id`, `key`, `name`, `address`, `aliases`

Determinism and normalization:

- Nodes are sorted by `(address, name, key)` before IDs are assigned.
- Multiple symbol names sharing one entrypoint are collapsed into one canonical node.

Why this matters:

- Reduces ambiguous-name false positives in symbol-rich binaries.
- Keeps output stable across runs and host environments.

## Pass 2: Call Target Extraction from Disassembly

Each disassembled call-like site emits a target record with:

- `target_name`
- `target_address`
- `target_address_candidates`
- `raw_operand`
- `kind`

Address candidate generation includes architecture-aware normalization:

- RIP-relative slot decoding on x86 (`[rip + off]`)
- decimal relative immediate handling (platform-aware)
- AArch64 signed/absolute immediate normalization
- ARM64 pointer-auth branch forms (`blraa`/`blrab`, `braa`/`brab`) with register-target parsing

## Pass 3: Tailcall Recovery

If a function ends with an unconditional branch and a concrete operand, `blint` emits a
`tailcall` target record.

Goal:

- Capture compiler/optimizer tail dispatch that otherwise fragments the graph.

## Pass 4: Indirect Hint Recovery (Register and Memory)

`blint` tracks lightweight register state to recover likely call targets before indirect
calls.

Supported patterns include:

- `mov reg, IMM|SYM` then `call reg`
- `add/sub reg, imm` propagation over tracked candidates
- `call [reg + off]` using tracked base candidates
- `call [rip + off]` slot lookup through symbol/address maps

### Windows-focused memory-chain passes

Current Windows x86_64 passes include:

1. `mov reg, [base + off]` chain propagation to inferred candidate slots.
2. `call [reg + off]` lookup using inferred candidates.
3. strict chain hop limit (default `2`), so deeper chains stop propagating.

### Windows ARM64-specific indirect-target filters

Current PE AArch64 handling adds two precision guardrails:

1. Do not propagate register-target chains through indexed memory operands
   (for example `ldr x8, [x9, x10, lsl #3]`) because target address depends on runtime index.
2. Drop non-canonical high virtual-address candidates in register chains, reducing
   sentinel-constant pollution (for example `0x7fff...ffff` arithmetic artifacts).

Example supported depth:

- `mov rcx, [rax+off] -> mov rdx, [rcx+off] -> call [rdx+off]` (resolved when map exists)

Example intentionally not propagated:

- `mov r8, [rdx+off] -> call [r8+off]` when this would exceed hop limit.

## Pass 5: Internal Destination Matching and Disambiguation

Call targets are matched to internal nodes using priority evidence, including:

1. exact address
2. normalized address (`& ~1`)
3. RVA/image-base transforms
4. range containment fallback
5. symbol-name fallback (with alias normalization such as PLT forms)

If multiple candidates tie, deterministic disambiguation is applied (primary address,
range width, distance, stable ID order).

## Pass 6: Unresolved Bucketing

When no unique internal destination is selected, evidence is emitted to `external` with
reason buckets such as:

- `ambiguous_address`
- `ambiguous_name`
- `address_space_miss`
- `symbol_only_miss`
- `raw_imm`
- `unresolved`

Kind suffixes are appended where applicable, for example
`unresolved:indirect_hint`.

## Export Tuning by Confidence

Callgraph metadata remains complete in `*-metadata.json`. Export renderers can filter by
confidence threshold:

```bash
blint --disassemble --export-callgraph-mermaid --callgraph-min-confidence low
blint --disassemble --export-callgraph-graphml --callgraph-min-confidence medium
blint --disassemble --export-callgraph-gexf --callgraph-min-confidence high
```

Notes:

- `low` keeps all edges/external entries.
- `medium` drops low-confidence entries (usually many `indirect_hint`/external links).
- `high` keeps only strongest internal evidence.

## Limitations and Trade-offs

- Indirect calls are heuristic; absence of edge is not proof of no control flow.
- Name recovery from pointer slots depends on available symbols/relocations.
- Aggressive propagation can inflate false positives; strict hop limiting reduces this.
- Indexed ARM64 address forms can look call-like but are frequently data-table lookups;
  Windows ARM64 now prefers precision over speculative propagation for these sites.
- External reason shifts can occur when one heuristic classifies evidence differently
  without semantic regression.

## Understanding False Positives and False Negatives

Recommended review order:

1. Validate `direct` internal edges first (highest precision).
2. Add `tailcall` edges to inspect dispatch behavior.
3. Triage `indirect_hint` as hints, not proof.
4. Inspect top external reason buckets to spot systemic misses.

Common FP signatures:

- Over-propagated register chains in heavily optimized dispatch code.
- Ambiguous-name fallback when aliases are dense.
- ARM64 constant-sentinel math (`max-int` style values) misread as call targets
  before candidate filtering.

Common FN signatures:

- Deep virtual dispatch beyond configured hop limit.
- Missing import/relocation symbol context.
- Non-canonical operand formatting not yet normalized.
- ARM64 indexed-memory dispatch (`[base, index, lsl #N]`) intentionally not
  propagated in Windows ARM64 mode to avoid high-FP explosions.

For regression control, use platform baselines and label assertions to track both KPI and
local FP/FN behavior across changes.

---

## Weaknesses in current implementation

- **No deep value-flow engine:** Indirect resolution is heuristic, not full points-to/dataflow analysis.
- **Symbol quality dependence:** Precision and recall depend on symbol/relocation availability, demangling performance, and formatting.
- **Static-only confidence model:** Confidence ranks are rule-based.

---

## Comparison with Other Approaches

### Rust/cargo callgraph workflows

Relevant facts from upstream docs:

- `rustc --emit` can produce `llvm-ir` and `mir` outputs.
- LLVM has callgraph printer passes such as `print-callgraph` and `dot-callgraph` (via `opt`).
- `cargo-call-stack` describes itself as a static whole-program stack-usage analyzer, warns about reliance
  on nightly/experimental behavior, and documents limited utility with heavy indirect calls/dynamic dispatch.

Relative to those workflows:

- **`blint` strengths:**
  - Works directly on released binaries (ELF/PE/Mach-O/WASM) without requiring source build pipelines.
  - Produces unresolved buckets and confidence-tagged edges for triage.
  - Integrates directly into security-review and metadata flows.
- **`blint` weaknesses:**
  - Lacks compiler-internal semantic context available in MIR/LLVM-IR pipelines.
  - Cannot provide source-level guarantees that compiler-IR workflows can sometimes provide in controlled builds.

### Capstone-centered approaches

Capstone positions itself as a lightweight multi-platform, multi-architecture disassembly framework.

Relative comparison:

- **`blint` strengths:**
  - Delivers end-to-end callgraph outputs, unresolved reason taxonomy, and export/report integration.
  - Includes platform-specific heuristics already packaged for security triage use.
- **`blint` weaknesses:**
  - A custom Capstone pipeline can be more customizable for niche instruction-level semantics.
  - `blint` currently favors deterministic heuristics over highly specialized per-target tuning.

### Ghidra decompiler-style approaches

Ghidra documents a full SRE framework with disassembly, decompilation, graphing, scripting, and both
interactive and automated modes.

Relative comparison:

- **`blint` strengths:**
  - Lightweight CLI-first automation and JSON-focused outputs fit CI/security scanning workflows.
  - Deterministic callgraph serialization and KPI regression flow are straightforward to automate.
- **`blint` weaknesses:**
  - Does not provide decompiler-level high-level recovery and analyst-driven interactive refinement.
  - Not designed to replace full interactive reverse-engineering sessions for complex indirect dispatch recovery.
