# A9 P0 — the measurement (measure only)

Host: the reviewer Mac (macOS arm64). NDK r28c (`28.2.13676358`) built the
committed fixtures; this run used no NDK. nyxstone over Homebrew LLVM 18
(`18.1.8`, `/opt/homebrew/opt/llvm@18`, `NYXSTONE_LLVM_PREFIX` set, on
`PATH`). blint `e79572f` (#240 merged). `llvm-objdump` 18.1.8 read every
quoted instruction by hand. Script:
`tests/scripts/android/a9_p0_measure.py --corpus ~/sandbox/android-corpus`
(JSON beside this doc's numbers in the run log; the 27 APKs =
tier2-fdroid's 26 + RnHello).

## (a) The first-location effect

`bound_dynamic` (and static `bound`) rows whose `fn_addr` is not a function
start in that ABI's own copy of the library, per APK and ABI, on main:

| APK | ABI | bad `bound_dynamic` | bad `bound` (static) |
|---|---|---|---|
| com.blint.rnhello_1 | armeabi-v7a | **256** of 278 | 0 (no static rows) |
| com.blint.rnhello_1 | x86 | **251** of 278 | 0 |
| com.blint.rnhello_1 | x86_64 | **251** of 278 | 0 |
| app.organicmaps_26082718 | armeabi-v7a | 0 | **255** of 399 |
| app.organicmaps_26082718 | x86 | 0 | **254** of 399 |
| app.organicmaps_26082718 | x86_64 | 0 | **255** of 399 |
| com.adilhanney.saber_1360101 | armeabi-v7a | 0 | **8** of 8 |
| com.adilhanney.saber_1360103 | x86_64 | 0 | **4** of 8 |
| io.github.muntashirakon.AppManager_451 | armeabi-v7a / x86 / x86_64 | 4 each | 0 |
| net.osmand.plus_540402 | x86_64 | 7 | 0 |
| all other 20 APKs | all ABIs | 0 | 0 |

RnHello's join parses `libreactnative.so` from its arm64 location (first in
zip order) and applies those tables to every ABI: armeabi-v7a's 278
`bound_dynamic` rows carry arm64 addresses, 256 of which are not even
function starts in the v7a bytes (the rest land on coincidental starts —
same defect, luckier addresses). Every ABI reports identical counts
(294/8/30 with the confirmer), i.e. ground rule 36 is broken twice over:
wrong counts and foreign addresses. organicmaps shows the static side of
the same defect (255 of 399 `Java_*` bindings carry the first ABI's
addresses), and saber 1360101's v7a rows are 8-for-8 wrong (that build's
first location is another ABI's copy).

Scope decision (P1): tables, surfaces and FindClass confirmations become
per `(abi, library)`; a library missing from an ABI is named, never filled
in from another ABI. Oracle: every `fn_addr` is a function start in its
own ABI's bytes — including the static rows above.

## (b) The join's wall time on main

| APK | plain | `--disassemble` (confirmer) |
|---|---|---|
| com.blint.rnhello_1 | 1.15 s | 1.40 s |
| org.mozilla.fennec_fdroid_1560020 | 5.43 s | 8.62 s |
| org.videolan.vlc_13070108 | 3.27 s | 3.51 s |
| im.vector.app_40106624 (element) | 7.89 s | 7.74 s |
| slowest others: osmand 6.8-8.7 s, fennec 5.1-5.5 s, element 7.5-7.9 s | | |

P1's budget: the join must not grow past these by parsing each ABI's own
copy. Plan: parse only the libraries that own tables or a JNI surface in
the first pass (RnHello: 7 of 10, most a bare ``JNI_OnLoad`` at ~0.01 s;
``libreactnative.so`` is the expensive one at 0.10 s per copy), and
re-check the wall time per APK.

## (c) RnHello's nine unbound singles

Per single: where the name string is, what references it, why nothing
binds. All addresses arm64 `libreactnative.so` unless said otherwise;
`llvm-objdump -d` quotes verbatim.

**Four are one defect: the 256-byte cstring read limit truncates the
signature mid-descriptor, so `_valid_method_signature` refuses the entry.
The triples are complete and relocated — name word `R_AARCH64_RELATIVE`,
signature and fnPtr words `R_AARCH64_ABS64` against the defined
`jmethod_traits<...>::kDescriptor` / `MethodWrapper<...>::call` dynsym
symbols (the N2 shape):**

| single | signature length | triple |
|---|---|---|
| CatalystInstanceImpl.initializeBridge | 325 | slot `0x61edb0`, sig `0x29c9c8`, fn `0x50e7ac` (a start) |
| UIConstantsProviderBinding.install | 293 | slot `0x6227d8-8`, fn `0x5ac774` |
| TurboModuleManager.initHybrid | 277 | slot `0x6227d8`, fn `0x5a6d68` |
| ReactInstance.initHybrid | 446 | slot `0x620ab0`, fn `0x5435b8` |

The truncation also **splits runs and detaches registrars**: JReactInstance
(`ReactInstance`'s JNI class) registers a 14-entry table at `0x620ab0`, but
the refused first entry (the 446-byte `initHybrid`) makes the recovery
report the table from `0x620ac8` — and the registrar's materialization then
falls outside the recovered extent, so the chain never runs and
ReactInstance's five shared `CatalystInstanceImpl` names stay ambiguous.
`llvm-objdump`:

```
54346c: 106eb221   adr  x1, 0x620ab0 <_ZTVN8facebook5react14JReactInstanceE+0x20>
543474: 910023e0   add  x0, sp, #0x8
543478: 52802a02   mov  w2, #0x150              ; =336 = 14 * 24
543480: 9402c934   bl   0x5f5950 <memcpy@plt>
543484: 910023e0   add  x0, sp, #0x8
543488: 528001c1   mov  w1, #0xe                ; =14
54348c: 9402f5b5   bl   0x600b60 <HybridClass<JReactInstance...>::registerHybrid(...)@plt>
```

**Five cannot bind from these bytes (documented, no recovery added):**

- `WritableNativeArray.pushLong (J)V` / `WritableNativeMap.putLong
  (Ljava/lang/String;J)V` — the name strings do not exist in any shipped
  library (all four ABIs, every `.so`): `pushInt`, `pushDouble`,
  `putString`, ... are present as NUL-terminated strings with relocated
  triples; `pushLong`/`putLong` are absent entirely. No static carrier.
- `ReactInstance.installGlobals (Z)V` — no NUL-terminated
  "installGlobals" string anywhere (it appears only inside the mangled
  dynstr name `...14installGlobalsEv`); the two `(Z)V` triples belong to
  `pushBoolean` and `installJSIBindings`. No static carrier.
- `YogaNative.jni_YGNodeSetStyleInputsJNI (J[FI)V` — neither the name nor
  the descriptor exists in any library; `libyoga.so` is not shipped (the
  dex's `libyoga_so` accessor confirms the load attempt). Library absent.
- `JSCExecutor.initHybrid
  (Lcom/facebook/react/bridge/ReadableNativeMap;)Lcom/facebook/jni/HybridData;`
  — the descriptor exists nowhere; `libjscexecutor.so` is not shipped
  (the `libjscexecutor_so` accessor). Library absent.
- `JSCInstance`'s ambiguous `initHybrid ()Lcom/facebook/jni/HybridData;`
  (the residue's ninth): no registrar symbol, no
  "com/facebook/react/runtime/JSCInstance" class string in any library —
  the JSC glue is not linked into this Hermes build. Stays ambiguous.

## (d) The fbjni callee's (methods, count) across the direct call

Readable — answered from the absint model's state, with the caller's
argument registers carried into the callee's first `FrameState`
(`CatalystInstanceImpl`'s chain quoted; 13 chains walked):

- **count**: yes. The callee spills `w19 <- w1` and the RegisterNatives
  vtable call reads `w3 <- w19`, so the carried caller `w1` (17 for
  CatalystInstanceImpl, 14 for JReactInstance, 1 for the NativeArray and
  NativeMap registrars) is what the model holds at the call.
- **methods**: as a symbolic `("sp", k)` — the registrar memcpy'd the
  table to its frame (`mov x0, sp; bl memcpy@plt` with
  `x1 = adrp+add/adr -> the table`, `w2 = count * 24`) and passed the
  stack copy. The static-table tie-back is therefore the registrar's own
  copy, which the same walk reads: memcpy dst `("sp", k)`, src a
  materialised `("ptr", T)`, size `count * 24`. The 1-entry registrars
  inline the copy (`adr x8, 0x61fd98; ldr q0, [x8]; str q0, [sp]`) —
  there the single materialised table address is the tie-back.
- the class name is materialised inside the callee (registerHybrid), which
  the A8 chain walk already reads.

P3 is feasible with this shape: one table-address materialisation `T` per
registrar, the callee's `(methods == the carried stack marker, count)`
from carried registers, and the range `[T, T + count * 24)` per class. A
runtime-computed count reads as no constant and leaves the registration
without a range (stays ambiguous). This splits the merged two-class
`toString` run (`NativeArray` at `0x61fd98`, `NativeMap` at `0x61fdb0`,
each registered whole for its own class by its own registrar) and gives
JReactInstance its own range once P2 re-attaches its registrar.

## After P2 (same host, same run shape)

The fix: `_read_cstring` refuses a name or signature whose NUL sits beyond
`JNI_STRING_READ_LIMIT` (1024) instead of returning its truncated prefix —
the truncated signature silently failed validation and a truncated name
could have matched the identifier grammar and bound as a wrong string.

RnHello, plain: every ABI gains its copy's long-descriptor entries
(arm64/x86_64 278→282 bound_dynamic, unbound 30→26; v7a 208→211/102→99;
x86 262→265/48→45). With the confirmer, arm64 goes 294/8/30 → 303/3/26:
the four singles bind through the unique-pair rule, and the re-attached
JReactInstance registrar (its `adr 0x620ab0` lands inside the unsplit
14-entry table again) lets the whole-table rule bind ReactInstance's five
shared `CatalystInstanceImpl` names. The ambiguous residue is exactly the
P3 set: JSCInstance's `initHybrid` (no registrar anywhere) and
NativeArray/NativeMap `toString` (two registrars, one merged two-entry
run). x86_64's own confirmer still binds none of these: its chain hop is
broken (P3's first fix — nyxstone prints x86 direct-call operands as
pc-relative deltas, `_call_targets` read them as absolute), which P1's
per-ABI confirmations exposed now that arm64's ranges no longer stand in.

Corpus, plain, P1 → P2: element gains the same four RN descriptors
(+3/+4 bound_dynamic per version, in that version's own ABI), fennec
gains `GeckoSession$Window.open` (291 B), RnHello as above; the other 19
APKs unchanged. On the 32-bit ABIs `UIConstantsProviderBinding.install`
stays unbound: its v7a/x86 fnPtr words do not land on a discovered
function start (a per-ABI recovery fact, not the string bound).

Wall time: RnHello 1.42 s → 1.44 s plain (1.83 s → 1.86 s with the
confirmer) — the longer reads are bounded and rare.

## After P3 (same host, same run shape)

The registrar's argument registers are carried into the callee's first
state (`_seed_for_call` rewrites caller-frame `("sp", k)` / `("rbp", k)`
to `("caller_sp", k)` / `("caller_rbp", k)` markers); the callee's
RegisterNatives event then carries (methods marker, count, class) and
`_stack_copy_origin` ties the marker back: the registrar's memcpy
(dst == the stack slot, src a materialised table address, size) when the
copy is a call, else the registrar's entry-aligned materialised
addresses. Four x86_64 gaps fell out on the way: nyxstone prints x86
direct-call operands as rel32 (end-relative), which `_call_targets` read
as absolute — every x86_64 chain hop was lost; the x86 model keeps
rsp/rbp out of register values, so `mov rbx, rsp` is read beside the
model like `adr`; the class name in the x86_64 registerHybrid lives only
in rip-relative operands (overlapping SSE loads — mid-string artifacts
filtered by requiring a NUL or `L` before the address); and the x86_64
one-entry registrars address the table's words directly through
rip-relative loads, which the byte pre-scan now proposes.

RnHello with the confirmer: arm64 303/3 → **305/1** and x86_64
282/24 → **305/1** — NativeArray/NativeMap `toString` bind on both
call-site ABIs (each registrar's one-entry slice), and x86_64 reaches
arm64's counts for the first time. The residue on both is exactly
JSCInstance's `initHybrid` (no registrar, no class string anywhere).
Wall time: 1.86 s → 1.79 s with the confirmer, 1.43 s plain (the
confirmer stays behind `--disassemble`). The first cut cost 2.04 s on
RnHello and 11.6 s on fennec 1560010 (x86_64): the new pre-scan patterns
walked libxul's 118 MB .text byte-by-byte in Python (934k candidates,
5.5 s). Compiled-regex candidate location (0.7 s) put fennec 1560010 at
6.56 s - under P2's 8.29 s, because the regex also replaced the old
single-pattern loop.

The a9_split fixture (R1): SplitOne's and SplitTwo's `splitShared`
declarations bind through their own registrars' slices with their own
implementations on arm64 and x86_64; SplitRt's volatile count stays
ambiguous with all three candidates; the 32-bit twins keep all three
ambiguous.
