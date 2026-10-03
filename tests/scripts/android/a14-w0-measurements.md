# A14 W0 — the unbound census, the other groups, and the A0 baseline re-run

Measure only; no production change. Host: the reviewer Mac (macOS arm64,
darwin 27.0.0). NDK r28c (`28.2.13676358`, the fixture toolchain; no
fixture built in this packet). nyxstone over Homebrew LLVM 18.1.8
(`/opt/homebrew/opt/llvm@18`); oracle tools (`llvm-nm`, `llvm-readelf`,
`llvm-objdump`) from the same prefix; `dexdump` from build-tools 36.0.0.
The JNA version each APK ships is read from the APK itself (below).
Corpus: `~/sandbox/android-corpus` — 43 APK/XAPK entries over tiers 1-4
(26 tier-2, 1 tier-3, 10 tier-1 apps/splits, 6 tier-4 hostile zips), of
which 29 own a JNI join. (The A13 review's diff harness counted "42
APKs"; this census enumerates every APK/XAPK under the four tier
directories, which is 43 today — the tier-4 refusals are listed so the
hostile tier's behavior stays visible.) Script:
`tests/scripts/android/a14_w0_census.py`; raw data `/tmp/a14-w0-census.json`
(census), `/tmp/a14-w0-groups.json` (groups), `/tmp/a14-w0-baseline.json`
(baseline; reproducible from the script). blint @ `3f17fee` (main, the
A13 merge), run from a pristine worktree of that commit.

## (a) The unbound census

Every unbound row of every corpus APK, every ABI, with the confirmers on
(`--disassemble`'s join, listing cap lifted). Binned by whether the
method name equals an exported defined dynamic FUNC in exactly one
same-ABI library, in several, or in none:

| APK | ABI | unbound | unique export | several | none | register evidence on the matching rows | libjnidispatch.so |
|---|---|---|---|---|---|---|---|
| fennec 1560000 | armeabi-v7a | 1,431 | 1,395 | 0 | 36 | 1,395 of 1,395 | shipped |
| fennec 1560010 | x86_64 | 1,410 | 1,395 | 0 | 15 | 1,395 of 1,395 | shipped |
| fennec 1560020 | arm64-v8a | 1,410 | 1,395 | 0 | 15 | 1,395 of 1,395 | shipped |
| element 40106621 | armeabi-v7a | 1,084 | 465 | 0 | 619 | 465 of 465 | shipped |
| element 40106622 | arm64-v8a | 1,027 | 465 | 0 | 562 | 465 of 465 | shipped |
| element 40106623 | x86 | 1,028 | 465 | 0 | 563 | 465 of 465 | shipped |
| element 40106624 | x86_64 | 1,027 | 465 | 0 | 562 | 465 of 465 | shipped |
| every other join-bearing APK | each | 3-103 | 0 | **0** | all | — | absent |

Corpus totals: **6,045 unique-export rows, 0 several-exporter rows,
4,065 no-export rows.** No row anywhere has more than one exporter — the
ambiguity branch has no natural corpus case and the W1 fixture supplies
one. Every one of the 6,045 matching rows sits on a declaring class the
dex walk found `Native.register` evidence for; no matching row lacks it.

The JNA evidence, read from each APK's dex:

- **The version each APK ships**: JNA 5.18.1 (`Native.main`'s version
  constant) with jnidispatch native revision 7.0.4 (the
  `"Expected: 7.0.4"` check in `Native.<clinit>`) — identical in all
  seven JNA APKs (three fennec, four element).
- **The overload**: every app-declared site is
  `Native.register(Ljava/lang/Class;Ljava/lang/String;)void`; the
  `NativeLibrary` overloads appear only inside JNA's own `Native` class.
- **The constant library name**: fennec's 40 `mozilla.appservices.*`
  classes and its 2 `org.mozilla.experiments` (nimbus) classes register
  `"megazord"` (→ `libmegazord.so`); its 2 glean classes register
  `"xul"` (→ `libxul.so`); element's 6 `org.matrix.rustcomponents` /
  `uniffi.*` classes register `"matrix_sdk_crypto_ffi"`
  (→ `libmatrix_sdk_crypto_ffi.so`). In every case the name reaches the
  call through `findLibraryName` — the helper's constant fallback behind
  a Kotlin `access$` accessor, exactly the shape W1 must chase; no site
  carries the constant directly.
- **The callers**: every site sits in the class's own `<clinit>` (the
  prompt's "a method its `<clinit>` runs" is then only the helper that
  computes the name). `libjnidispatch.so` ships in each JNA APK's one
  ABI (the F-Droid builds are per-ABI).

Where the mass sits (corpus-wide, by declaring-class family):

| family | unique export | none | the exporter |
|---|---|---|---|
| org.matrix.rustcomponents.sdk.crypto | 1,412 | 0 | libmatrix_sdk_crypto_ffi.so |
| mozilla.telemetry.glean | 1,209 | 0 | **libxul.so** |
| mozilla.appservices.* (19 families) | 2,568 | 0 | libmegazord.so |
| uniffi.matrix_sdk_crypto / _common | 448 | 0 | libmatrix_sdk_crypto_ffi.so |
| org.mozilla.experiments (nimbus) | 408 | 0 | libmegazord.so |
| org.maplibre.android | 0 | 2,112 | none (runtime-built tables) |
| io.netty.channel + org.fusesource.jansi | 0 | 1,024 | none (no implementing library) |
| org.qtproject.qt5 | 0 | 292 | none for 73 rows/ABI (below) |
| androidx.graphics.path | 0 | 120 | none readable (below) |
| com.facebook.react / yoga / soloader residue | 0 | 313 | none (A13's documented residue) |
| everything else (realm 24, zstd-jni 12, gecko/geckoview 27, webrtc 11, flutter.embedding 10, osmand leftovers 88, vlc medialibrary 12, fennec components 12, RN gesturehandler 4, sub-3-row families) | 0 | 204 | none |

## (b) The other groups

**glean — 403 rows per fennec ABI, answered by libxul.so.** The
declaring classes are `mozilla.telemetry.glean.internal.UniffiLib` and
its `IntegrityCheckingUniffiLib` twin (uniffi bindings, JNA direct
mapping — `Native.register(..., "xul")` in the `<clinit>`; the census
shows all 403 method names, e.g. `ffi_glean_core_uniffi_contract_version`,
`uniffi_glean_core_checksum_constructor_countermetric_new`, exported as
defined FUNCs by **libxul.so** and by nothing else: glean-core is
compiled into Firefox's own libxul, not into the megazord (which exports
0 glean-named symbols; `llvm-nm -D --defined-only` on both, in
`/tmp/a14-w0-groups.json`). The A13 status note's "403 rows that match
no export" measured against libmegazord only; against the whole APK the
rows match uniquely. **Where glean's implementation lives: libxul.so.**
This group is reachable by W1's jna_direct join.

**androidx.graphics.path — 8 rows on every ABI of every Compose app**
(fdroid, newpipe, osmand, fennec; 120 corpus rows), declared
`PRIVATE FINAL NATIVE` on `androidx.graphics.path.PathIteratorPreApi34Impl`
(7 methods) and `ConicConverter` (1). `libandroidx.graphics.path.so`
ships everywhere and its `JNI_OnLoad` (arm64 copy, `llvm-objdump`)
performs two `RegisterNatives` calls through static tables: 7 entries at
0x5c48 (SDK≥26 table 0x5cf0 the twin) and 1 entry at 0x5d98 — the
relocated triples read cleanly (`createInternalPathIterator` /
`(Landroid/graphics/Path;IF)J` / fn 0x1888, …). The library is fully
stripped (one export: `JNI_OnLoad`) **and its `.eh_frame` carries only
5 FDEs (0xd2c-0xd74), none covering the JNI functions** — so the
fn-start oracle (defined FUNCs + unwind discovery) refuses every fnPtr
and F1 recovers no table. This is A10's "cause A" honest refusal
(yoga's symbol-less Thumb wrappers), on a table that would otherwise
bind all 8 rows. **Not reachable by the existing rules** without
weakening the function-start oracle; known limit.

**Qt5 — 73 rows per osmand ABI** over 6 `org.qtproject.qt5.android.*`
classes. OsmAnd ships libQt5Core/Network/Sql but **not** Qt's platform
plugin (`libqtforandroid.so`), which implements these natives.
`QtAndroidPrivate::initJNI` in libQt5Core registers its own static
`methods` local (`adr x2, 0x5b3938 …` `mov w3, #0x7`; `llvm-objdump`)
— 7 entries whose names/signatures read cleanly but whose fnPtrs are
hidden-visibility C++ statics; those ARE eh_frame-covered, the table
recovers, and the join already binds those 7 rows (`bound_dynamic 7`).
The remaining 73 rows have no implementing code in the APK at all. **Not
reachable; known limit** (nothing to bind to).

**netty and jansi — 256 rows per vlc ABI** (io.netty.channel.unix 91,
epoll 78, org.fusesource.jansi.internal 46, kqueue 41; x86_64 counts,
each vlc build's own ABI the same shape). The declaring classes are
static-native utility holders (`LimitsStaticallyReferencedJniMethods`:
`iovMax`, `sizeOfjlong` — `STATIC NATIVE`, no code, dexdump in
`/tmp/a14-w0-groups.json`); netty loads them through `NativeLoader`'s
optional `loadLibrary` (falling back silently when the transport
library is absent), jansi likewise. **No implementing library ships in
the APK** (vlc's whole native set is libc++_shared, libmla, libvlc,
libvlcjni) — correctly unbound, nothing to reach. **Known limit.**

The remaining no-export mass is the A13-documented residue (soloader's
21 rows per ABI — composition is out of reach by construction; yoga's
54 v7a wrappers; RnHello's four no-ABI rows and `nativeReadByte`; x86
`runStdFunctionImpl`) plus small optional-native families that ship no
implementation (realm 24, zstd-jni 12, webrtc 14, gecko/geckoview 43,
flutter.embedding 10, osmand leftovers 22).

## (c) What W1 can reach

**The jna_direct join**, exactly the 6,045 unique-export rows: the
declaring class (or a method its `<clinit>` runs) invokes
`Native.register`, `libjnidispatch.so` ships in the ABI, and exactly one
same-ABI library exports the name — with the register call's constant
library name (`megazord`/`xul`/`matrix_sdk_crypto_ffi`) picking the
candidate library, which is also the unique exporter everywhere in the
corpus. Expected arithmetic if it lands: fennec per ABI
1,395 more `bound_dynamic`, unbound 1,410→15 (v7a 1,431→36); element
per ABI 465 more, unbound 1,027→562. glean is inside this reach
(403 rows, `"xul"` → libxul.so).

**Everything else is out of reach of the existing rules** and goes to
W2's known-limits list with its reason: androidx.graphics.path (the
fn-start oracle's honest refusal — the table exists and is relocated,
but its functions carry no symbol and no unwind row), Qt5's 73 rows and
netty/jansi's 256 (no implementing library in the APK), maplibre's 2,112
(runtime-built tables, U2's dropped scope), soloader/yoga/no-ABI residue
(A13's documented closure).

## (d) The A0 baseline re-run

The three A0.3 phases re-run on this tree (blint @ `3f17fee`), plus the
JNI counts and wall/RSS the close-out table needs; raw data
`/tmp/a14-w0-baseline.json`.

**Standalone findings per tier** (`--no-reviews`, per group):

| group | scanned | median/file | severity histogram | top rules |
|---|---|---|---|---|
| tier0/api34-arm64-v8a | 1,541 | 1 | low 1,530, high 383, medium 237, info 73, warning 6 | BTI_PAC 1,530, PAGE_16K 383, CANARY 183 |
| tier0/api35-arm64-v8a | 1,398 | 1 | low 1,365, medium 234, info 71, warning 6 | BTI_PAC, CANARY |
| tier0/api36-arm64 | 677 | 1 | low 670, medium 92, info 30, warning 2 | BTI_PAC, CANARY |
| tier0/api36-arm64-v8a | 1,679 | 1 | low 1,622, medium 234, info 79, warning 3 | BTI_PAC, CANARY |
| tier1 r27/r28 × 5 ABIs | 19-27 each | 2 (4 on r27/arm64) | high = PAGE_16K on the planted non-16 KB variants (17-20 per ABI group, 3 on v7a/x86) | PAGE_16K, CANARY, NO_SONAME |

Tier-0 median is 1 everywhere. The tier-0 high findings are exactly
`CHECK_ANDROID_PAGE_16K` on the API-34 image (383 files: that system
image predates Google's 16 KB rebuild — the API 35 and 36 images fire
zero of it), each a true statement about the artifact under the Play
policy the rule quotes. **Zero critical findings anywhere on tier 0.**
(A0's V12 misfires — the bionic LIBC_PORTABILITY flood, the glibc
runtime tag — are gone; the FP lane's fixes and A3's rule work hold.)

**SBOM components per tier-2 app** (`blint sbom`, 26 apps): 171 bare
`.so` components (`pkg:android/<name>?arch=<abi>`) inside 4-135
components per app — the rest are the dex-derived application components
and the nested framework identifications (fdroid 111 and newpipe 102
components over 1 `.so` each; fennec 135 over 14; termux.api 53 with no
native code at all). **Zero build-id-as-version components** (A0's V4:
203 of 242; fixed by A1.3/A6's version evidence).

**JNI join counts per ABI** (`/tmp/a14-w0-baseline.json`
`join_counts`, both modes): with the confirmers off, `jna_direct` is 0
everywhere by construction (the W1 gate re-verifies); with them on, the
A13 counts hold — RnHello 305/1/26, 247/1/84, 289/2/41, 304/1/27 per
arm64/x86_64/v7a/x86; fennec 134/4/1,410 (arm64); element 303/1/1,027
(x86_64); organicmaps 399 bound / 0 dynamic / 0 unbound on every ABI; vlc
120 bound / 212 dynamic / 0 ambiguous.

**Wall time and peak RSS** (the default analysis, `blint -q --no-banner`,
and with `--disassemble`, per app; seconds / peak RSS):

| app | default | disassemble | peak RSS (disasm) |
|---|---|---|---|
| termux.api (dex-only control) | 2.8s | 2.7s | 0.2 GB |
| fdroid / newpipe | 13.1 / 8.5s | 13.5 / 8.5s | 0.8 / 0.5 GB |
| saber (Flutter) 1360101-03 | 6.2-8.0s | 142-7,508s | 2.0-4.6 GB |
| localsend (Flutter) 641-43 | 7.8-8.4s | 203-9,719s | 2.2-7.9 GB |
| termux / AppManager | 14.3 / 20.9s | 31.7 / 50.9s | 1.0 / 1.6 GB |
| vlc ×4 | 29.9-33.2s | 358-885s | 3.6-13.2 GB |
| osmand ×3 | 47.4-60.8s | 295-574s | 3.6-12.6 GB |
| element ×4 | 52.5-54.0s | 411-1,058s | 3.9-10.2 GB |
| fennec ×3 | 44.2-46.8s | 1,329-5,925s | 11.5-42.8 GB |
| organicmaps | 85.1s | 698.1s | 8.8 GB |
| RnHello | 22.9s | 341.0s | 4.7 GB |

Every run exits 0. The disassembly of the largest single libraries
(libxul in fennec, libflutter in the Flutter apps) dominates both
columns. The two multi-hour outliers (saber 1360101: 7,508s,
localsend 642: 9,719s) ran while the census and row-dump measurements
shared the machine — their sibling builds of nearly identical content
took 142-205s and 203-303s, which is that app's real disassembly cost.

## The gate block (W0)

- Host: the reviewer Mac (macOS arm64, darwin 27.0.0).
- NDK: r28c (`28.2.13676358`; no fixture built in this packet).
- nyxstone LLVM: Homebrew LLVM 18.1.8 (`/opt/homebrew/opt/llvm@18`).
- JNA shipped by each APK: 5.18.1 (jnidispatch native revision 7.0.4),
  read from each APK's dex — identical across the three fennec and four
  element builds.
- blint @ `3f17fee` (main), measured from a pristine worktree.
