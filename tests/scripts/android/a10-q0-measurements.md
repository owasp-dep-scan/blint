# A10 Q0 — the 32-bit gap, measured (no production change)

Host: the reviewer Mac (macOS arm64, darwin 27.0.0). NDK r28c (`28.2.13676358`,
fixture builds; this packet builds none). nyxstone over Homebrew LLVM 18.1.8
(`/opt/homebrew/opt/llvm@18`, `NYXSTONE_LLVM_PREFIX`); the independent oracle is
`llvm-readelf`/`llvm-objdump` from the same prefix. blint @ `de1e8e7`
(`feat/an-a10`). Script: `a10_q0_measure.py`; raw JSON at `/tmp/a10-q0.json`.

The join ran with the FindClass confirmer (`--disassemble`) on RnHello and
organicmaps, all four ABIs. Counts (bound / bound_dynamic / ambiguous /
unbound):

| APK | ABI | bound_dynamic | ambiguous | unbound |
|---|---|---|---|---|
| RnHello | arm64-v8a | 305 | 1 | 26 |
| RnHello | x86_64 | 305 | 1 | 26 |
| RnHello | armeabi-v7a | 211 | 22 | 99 |
| RnHello | x86 | 265 | 22 | 45 |
| organicmaps | all four | 399 static `bound` each | 0 | 0 |

organicmaps has no gap: its join is 100% static exports, identical per ABI.
RnHello's gap rows (unbound on a 32-bit ABI, bound on arm64): 73 on v7a, 19 on
x86; the 19 x86 rows are a subset of v7a's 73 (54 are v7a-only).

## The REL-addend hypothesis is refuted

`armeabi-v7a` and `x86` do relocate with REL — `llvm-readelf -d` shows `REL`
and no `RELA` — so the hypothesis was that `defined_symbol_relocation_map`
reads a zero addend there. It does read zero, and it is already correct:
**0 of 92 gap rows** are off by an addend. On these libraries every
absolute-against-defined-symbol word stores 0 in the shipped bytes (the linker
leaves the addend — 0 for a plain `&symbol` — in the word, and the symbol's
value is the whole target), and every `R_ARM_RELATIVE`/`R_386_RELATIVE` word
carries the target VA in the word, which `relative_relocation_map` already
reads. LIEF's and readelf's relocation types and stored words agree on all 336
diagnosed words (cross-check in the script; the type spellings differ —
`TYPE.X86_32` vs `R_386_32` — and the hexdump words are byte-reversed on disk;
both are normalized before comparing).

## Cause table

| Cause | v7a | x86 | Libraries |
|---|---|---|---|
| A. fnPtr target is a function with no recoverable start | 54 | 0 | libreactnative (53, all yoga `jni_YG*`), libimagepipeline (1) |
| B. no static table: the 32-bit registrar materializes it at run time | 19 | 19 | libreactnative (13 + 2), libfbjni (3), libhermestooling (1) |

### A — the yoga wrappers (v7a only, 54 rows)

The triple's three words are all `R_ARM_RELATIVE` in `.data`, the join's map
reads them exactly (readelf-confirmed), the name and signature validate — and
the fnPtr lands 6–14 bytes inside `.text` at addresses like `0x42470e` that
are **not in any function-start source**: no dynsym/symtab symbol, no
`.ARM.exidx` entry. All 53 libreactnative targets sit strictly inside another
function's exidx extent (measured: 0 at a start, 53 inside). `llvm-objdump`
shows what they are: tiny Thumb tail-call wrappers (`ldr r1,[sp]; mov r0,r2;
b.w …`) that branch through 12-byte `movw/movt/add r12,pc; bx r12` PLT veneers
at the end of `.text`. The same declarations on arm64 bind to full-size
wrappers with `.eh_frame` coverage (e.g. `jni_YGConfigSetErrataJNI` →
`0x5b04b8`, a symtab function). Per the ladder's oracle (llvm-readelf symbols
plus eh_frame, or `.ARM.exidx` on v7a) the v7a targets are **not** verifiable
starts: binding them would fail the oracle. This is an honest refusal, not a
decode defect.

### B — runtime-materialized tables (both 32-bit ABIs, 19 rows)

No static `JNINativeMethod` triple exists in the 32-bit bytes for these
signatures. Measured on libfbjni v7a for `HybridData$Destructor.deleteNative
(J)V`: the name string sits in `.rodata` with **zero relocated words pointing
at it anywhere**; the descriptor string's only reference is a `.got` slot
(`R_ARM_GLOB_DAT` against `jmethod_traits<…>::kDescriptor`). The arm64 twin
keeps a static table (name word `R_AARCH64_RELATIVE` in `.data.rel.ro`, sig
word `R_AARCH64_ABS64` against `kDescriptor`) and binds. Same for the 13
libreactnative rows (`CxxCallbackImpl.nativeInvoke` et al., one-method classes)
and the three exact-signature `initHybrid` rows (the shared name string has 14
static triples on v7a — for other signatures; none carries
`(Lcom/facebook/react/bridge/JavaJSExecutor;)Lcom/facebook/jni/HybridData;`).
The one- and two-entry tables that stay static on 64-bit compile to three
immediate stores at run time on 32-bit (a 1-entry table is 12 bytes); only a
disassembly-layer walk of the registrar could see them — which is the
confirmer, and the confirmer models only arm64/x86_64.

## absint 32-bit inventory (Q2's input)

`blint.lib.absint` defines exactly two models: `Arm64Model` and `X86_64Model`
(`model_for_target` maps everything non-aarch64 to X86_64). `jni_findclass`
steps only these two; `confirm_table_ranges` returns `[]` for any other
machine, which is why the 22 ambiguous rows per 32-bit ABI stay ambiguous.
What a usable 32-bit layer would need, none of which exists:

- arm32/Thumb: `r0`–`r12` register families and 32-bit widths; 16/32-bit Thumb
  instruction text (`ldr rN, [pc, #imm]` literal pools, `movw`/`movt` pairs,
  `add rN, pc` — the veneer idiom, `push {…}` sequences); the RegisterNatives
  vtable offset at `215 * 4` and its `ldr`/`blx` spellings (the current
  `215 * 8`, `#1720`-style tokens are 64-bit-only); `_TABLE_ENTRY_STRIDE` is
  hard-coded 24 (64-bit).
- i386: `eax`-family widths would partially match, but the cdecl argument
  stack is the real gap — `(methods, count)` reach RegisterNatives through
  `push`/stack slots, which the model has no concept of (it models frame
  stores for strings, not argument slots at calls); `mov reg, [got]` GOT loads
  for preemptible symbols; the vtable offset is `215 * 4` here too.

Q2 is therefore dropped per its own condition: there is no model to step.

## The scope Q0 decides

- No relocation-map change: the maps are already exact on REL (readelf-verified).
- Q1 fixes nothing in the decode; it pins the two honest refusals with NDK
  fixtures on v7a and x86 (the wrapper-without-unwind-entry shape, and the
  runtime-materialized small table) plus one adjacent shape that must stay
  unbound, with the fn_addr oracle asserted per ABI.
- Q2: dropped (no 32-bit model; the inventory above is what one would cost).
- Q3 proceeds as planned (the "registered nowhere" mark, `--disassemble` only).
