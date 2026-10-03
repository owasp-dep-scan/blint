# A14 W2 — the lane close-out

The close-out table (A0, W0, now), `docs/ANDROID.md` with the known
limits, and the behaviour-neutral sweep of the lane's code. Host: the
reviewer Mac (macOS arm64, darwin 27.0.0). NDK r28c (`28.2.13676358`).
nyxstone over Homebrew LLVM 18.1.8 (`/opt/homebrew/opt/llvm@18`); the
oracle tools from the same prefix. The JNA version each APK ships (read
from the APK): 5.18.1, jnidispatch native revision 7.0.4, in all seven
JNA APKs. Scripts: `tests/scripts/android/a14_w0_census.py` (the
baseline phases), `tests/scripts/android/a14_w2_closeout.py` (the
full-row oracle and the sweep's identity checks); raw data
`/tmp/a14-w2-baseline.json`, `/tmp/a14-w2-closeout.json`, the row dumps
`/tmp/a14-w2-rows-w1tree.json` and `/tmp/a14-w2-rows-now.json`.
Trees: A0 = the recorded A0.3 run (2026-09-24, `a93880e`); W0 = `3f17fee`
(main at A13); now = this tree (W0 + W1 + the W2 sweep).

## The close-out table

**Standalone findings per tier** (tier-0 emulator images, tier-1 planted
NDK builds; median per file, severity histogram):

| tier | A0 (a93880e) | W0 (3f17fee) | now |
|---|---|---|---|
| tier0/api34-arm64-v8a (1,541 files) | median 2, 353 findings | median 1; low 1,530, high 383, medium 237 | identical to W0 |
| tier0/api35-arm64-v8a (1,398) | median 1, 360 | median 1; low 1,365, medium 234 | identical to W0 |
| tier0/api36-arm64 (677) | median 1, 208 | median 1; low 670, medium 92 | identical to W0 |
| tier0/api36-arm64-v8a (1,679) | — | median 1; low 1,622, medium 234 | identical to W0 |
| tier1 r27/r28 × 5 ABIs | 8-16/group | median 2 (4 on r27/arm64) | identical to W0 |

Movement since A0: the medians fell (A0's LIBC_PORTABILITY bionic false
positives and the canary flood on system images were removed by the FP
lane's fixes and A3's per-ABI rule work — A0's V12), and the Android
rules themselves now account for the low/high mass (BTI_PAC's posture
fact, PAGE_16K's policy verdict). Every high on tier 0 is
`CHECK_ANDROID_PAGE_16K` on the API-34 image — 383 files that predate
Google's 16 KB rebuild, a true statement about those artifacts under
the quoted Play policy; the API 35/36 images fire zero of it. **Zero
critical findings on tier 0 at every point measured.** Nothing moved
between W0 and now: W1 touches only the join (behind `--disassemble`,
and the join feeds no finding on these inputs) and the W2 sweep is
comment-only (verified identical, below).

**SBOM components per tier-2 app** (`blint sbom`, 26 apps):

| | A0 | W0 | now |
|---|---|---|---|
| bare `.so` components | 242 | 171 | 171 |
| build-id-as-version | 203 of 242 (84%) | 0 | 0 |
| components per app | not recorded | 4-135 (framework nesting; termux.api 53 dex-only) | identical to W0 |

Movement since A0: A1.3's SBOM shape stopped emitting per-ABI duplicate
components, and A6's framework identification nests identified
frameworks as components (fdroid 111 components over one `.so`;
fennec 135 over 14). W0 → now: none.

**JNI join counts per ABI** (bound / bound_dynamic / ambiguous /
unbound, confirmers on; the join did not exist at A0 — it landed in A5
and reached its final shape here):

| APK | ABI | W0 | now |
|---|---|---|---|
| RnHello | arm64-v8a | 0/305/1/26 | 0/305/1/26 |
| RnHello | x86_64 | 0/305/1/26 | 0/305/1/26 |
| RnHello | armeabi-v7a | 0/251/1/80 | 0/251/1/80 |
| RnHello | x86 | 0/304/1/27 | 0/304/1/27 |
| organicmaps | all four | 399/0/0/0 | 399/0/0/0 |
| vlc 13070108 | x86_64 | 120/212/0/259 | 120/212/0/259 |
| element 40106624 | x86_64 | 854/303/1/1027 | 854/**768**/1/**562** (465 `jna_direct`) |
| element 40106621-23 | v7a/arm64/x86 | as A13 | +465 `jna_direct` each, unbound −465 |
| fennec 1560020 | arm64-v8a | 80/134/4/1410 | 80/**1529**/4/**15** (1,395 `jna_direct`) |
| fennec 1560000/010 | v7a/x86_64 | as A13 | +1,395 `jna_direct` each, unbound 1,431→36 / 1,410→15 |
| every other join-bearing APK | every ABI | as A13 | unchanged |

The whole movement since W0 is W1's `jna_direct` join: 6,045 rows over
seven builds (the fennec megazord/xul and element matrix uniffi
bindings, glean included). The plain (no-flag) join is unchanged on
every APK — the evidence walk is gated.

**Wall time and peak RSS** (default analysis / with `--disassemble`;
A0.3 recorded neither):

| app | W0 default → now | W0 disassemble → now |
|---|---|---|
| fennec 1560020 | 44.2s → 44.0s / 2.2 GB | 1,442.5s → 1,446.0s / 42.0 GB |
| element 40106624 | 53.9s → 54.5s / 2.3 GB | 410.6s → 414.2s / 8.7 GB |
| RnHello | 22.9s → 20.3s / 0.6 GB | 341.0s → 300.9s / 4.7 GB |
| organicmaps | 85.1s → 85.6s / 0.5 GB | 698.1s → 753.7s / 8.9 GB |

The join itself (not the whole analysis) pays for W1: fennec's
confirm-mode join 8.96 → 15.01s, element's 8.47 → 9.92s, RnHello's
5.12 → 5.41s — measured in W1's gate; inside the whole-analysis numbers
that delta is invisible. The full 27-app table (every run exiting 0) is
`/tmp/a14-w2-baseline.json`; W0's two multi-hour outliers reproduce
here at the same scale un-contended (saber 1360101: 7,508s contended →
7,760s alone; localsend 642: 9,719s → 9,753s; fennec 1560000 likewise
5,925s → 5,900s), so those two Flutter
builds are intrinsically slow disassemblies, not contention artifacts —
W0's measurements file attributed them to CPU sharing and this run
corrects that reading (their sibling builds stay at 140-300s).

## The jna_direct oracle (W2's own)

Over every bound row — `bound` and `bound_dynamic` alike — on RnHello,
organicmaps, vlc, element and fennec, per ABI: llvm-nm names each static
row's symbol address (equal to its `fn_addr`, arm32 Thumb bit masked);
llvm-readelf FUNC symbols plus eh_frame FDEs (`.ARM.exidx` on v7a) name
the function starts every dynamic row's `fn_addr` must be one of.
**6,324 rows checked (2,650 bound + 3,674 bound_dynamic), 0 failures.**
The two oracle fixes this needed are instructive and now pinned in the
script: arm32 FUNC st_values carry the Thumb bit (masked on comparison;
x86's legitimately odd addresses — uniffi's packed 5-6-byte checksum
stubs — compare unmasked).

## The sweep and its identity check

`jni.py`, `jni_findclass.py`, `android.py`, `android_native.py`,
`android_blintdb.py`: every packet, wave, plan-paragraph and measurement
citation removed from the comments (the module docstrings' `A1.1`,
`A5.2 E2`, `A9 P3`, `01/B`, "measured in N0(b)", "23 of 27 corpus APKs"
and their kin — 30 sites), two dead module-level constants deleted
(`jni._DESCRIPTOR_START`, unused since the oracle script grew its own
copy; `jni_findclass.REGISTER_NATIVES_VTABLE_OFFSET`, whose fact the
vtable-slot tokens already encode — both flagged by the
every-named-constant-needs-a-test rule, neither referenced anywhere).
No dead helper exists in the lane's modules (an AST scan over every
`def`, cross-referenced repository-wide: only context-manager dunders,
never dead). No docstring was found disagreeing with its code.

Identity evidence (a14_w2_closeout.py): the corpus join row sets of the
W1 tree and the swept tree — 30 join-bearing APKs, listing cap lifted —
**identical**; the default analysis's findings and review outputs over
RnHello, vlc, osmand, element and fennec on both trees — **identical**;
the tier-0/tier-1 standalone findings and the tier-2 SBOM re-run on the
swept tree — identical to W0's (above). `absint.py` and the disassembler
are untouched by W1 and the sweep, so the callgraph KPI suite is not
triggered (stated, not silently skipped); the join is exercised by the
full suite and the corpus oracle above.

## docs/ANDROID.md

The user-facing guide to what blint does with Android native code —
inputs (APK/AAB/splits/standalone `.so`), the default path vs
`--disassemble`, the per-ABI facts and rules, framework identification
and the SBOM shape, the JNI join (every list, every `confirmed_by`
label, what each proves), and the known-limits table with every group
left unbound, its count, its reason, and whether more code could reach
it. Linked from the README's Android bullet and from the top of the
JNI-join section in `docs/METADATA.md`.

## The gate block (W2)

- Host: the reviewer Mac (macOS arm64, darwin 27.0.0). NDK r28c
  (`28.2.13676358`). nyxstone over Homebrew LLVM 18.1.8
  (`/opt/homebrew/opt/llvm@18`). JNA shipped by each APK: 5.18.1
  (jnidispatch native revision 7.0.4). blint @ `b4c4957` (W1) for the
  before side of the sweep identity check; this tree is the after.
- Per APK and every ABI, bound/ambiguous/unbound before and after W1,
  with and without `--disassemble`, plus wall time: the W1 gate block
  (commit `b4c4957`) and `tests/scripts/android/a14-w1-measurements.md`
  carry the full table; without the flag every APK equals the before
  tree exactly.
- The jna_direct oracle: 6,045 rows, 0 failures (W1 gate); the
  independent full-row oracle over every bound row on RnHello,
  organicmaps, vlc, element and fennec: 6,324 rows, 0 failures.
- Precision: no `jna_direct` row without register evidence (empty
  list); no bound name exported by more than one library (empty list).
- The close-out table above; the sweep's identity check (rows and
  reviews identical).
- ruff check, ruff format and flake8 (CI selection) clean, and the full
  suite run once, serially, on the final tree.
