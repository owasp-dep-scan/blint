# blint on Android native code

What blint does with the native code of an Android app — the inputs it
takes, what runs by default and what needs `--disassemble`, the per-ABI
facts and rules, framework identification, the SBOM shape, the dex↔native
JNI join, and the known limits of each. This is the user-facing guide;
`docs/METADATA.md` documents every emitted field, and the rule text in
`blint/data/rules.yml` and `blint/data/annotations/*.yml` is the
authoritative wording of each finding.

## Inputs

- **App archives**: `.apk`, `.aab` (with its config splits inside the
  bundle), `.apkm` / `.apks` / `.xapk` split bundles. Every `lib/<abi>/*.so`
  member is analyzed — in-place from the zip, whatever
  `android:extractNativeLibs` says, from every split that carries one.
  An app with native code but no dex is analyzed, not skipped.
- **Standalone ELF files**: a bare `.so` (or any ELF) is analyzed by
  itself; Android-specific facts are emitted when it carries
  `.note.android.ident`. The manifest-dependent rules (below) cannot fire
  there — a standalone run has no manifest.
- The ABI set is whatever the app ships (`arm64-v8a`, `armeabi-v7a`,
  `x86_64`, `x86`, `riscv64`); nothing is assumed about the missing ones.

## What runs by default, and what needs `--disassemble`

By default (`blint -i app.apk`):

- the native library model: every member, its ABI, its zip placement
  (stored/deflated, alignment), `extractNativeLibs`, and refusals
  (a zip-bomb or a library over the size cap is named, never parsed);
- one analysis unit per `(app, abi, library)` — each ABI's own copy is
  parsed for its own facts (hardening, bionic ELF facts, symbols,
  strings), never another ABI's bytes standing in for a missing one;
- the security checks and the capability reviews of `rules.yml` and the
  annotations over both the dex side and every native unit;
- the static half of the dex↔native JNI join (below): `Java_*` export
  decoding and `RegisterNatives` table recovery need no disassembly;
- `blint sbom` builds a CycloneDX 1.6 document (below).

With `--disassemble` (requires the nyxstone extension with LLVM 18 on
the path — see `docs/DISASSEMBLE.md`), additionally:

- every native function is disassembled, function metrics computed, and
  the native callgraph exported (with `--deep`: the dex callgraph too);
- the FindClass confirmer runs (`confirmed_by: "findclass"`), the
  runtime-built `RegisterNatives` tables recover on the 32-bit ABIs
  (`confirmed_by: "runtime_table"`), and the JNA direct-mapping evidence
  walk runs over the dex (`confirmed_by: "jna_direct"`) — see the join
  section;
- the app callgraph gains the native side and the JNI edges.

## Per-ABI facts and rules

Facts (mirroring `llvm-readelf -a --notes`, compared on every fixture by
`tests/scripts/android/elf_facts_probe.py`): the NDK note
(`min_api`, `ndk_version`), packed relocations (APS2 / RELR),
`.note.android.memtag` and the AArch64 GNU-property bits (arm64),
`DT_TEXTREL`, `DT_SONAME`, absolute `DT_NEEDED`, `PT_TLS`, and the
page-alignment facts behind the 16 KB verdict.

Rules (`blint/data/rules.yml`); a rule that cannot apply to an ABI never
runs on it:

| Rule | Scope |
|---|---|
| `CHECK_ANDROID_PAGE_16K` | app-level: a 64-bit ABI's ELF layout or zip placement breaks 16 KB mapping (Play requires it for targetSdk 35+; 32-bit ABIs exempt) |
| `CHECK_ANDROID_EXTRACT_NATIVE_LIBS` | app-level: `extractNativeLibs=false` but a member is compressed or unaligned (the loader refuses from API 23) |
| `CHECK_ANDROID_TEXTREL` | per library: text relocations (`DT_TEXTREL`/`DF_TEXTREL`) |
| `CHECK_ANDROID_WX_LOAD` | per library: a writable **and** executable segment |
| `CHECK_ANDROID_NO_SONAME` | per library: no `DT_SONAME` |
| `CHECK_ANDROID_ABS_NEEDED` | per library: a `DT_NEEDED` containing `/` |
| `CHECK_ANDROID_BTI_PAC` | arm64 only: no BTI/PAC GNU property (low: near-universal posture gap) |
| `CHECK_ANDROID_MEMTAG` | arm64 only: the MTE posture the `.note.android.memtag` declares (informational) |

Capability reviews add native-side behavior detections
(`blint/data/annotations/review_binary_android.yml` — e.g.
`ANDROID_PTRACE_TRACEME`, `ANDROID_INLINE_SYSCALLS` on the 32-bit ARM
`r7`-numbered `svc` sites, `ANDROID_WRITABLE_LOCATION_DLOPEN`) and
dex-side ones (`review_methods_android.yml`), some of which are
conjunctions across the join (a root-path probe needs both the dex
strings and a bound native).

## Framework identification and the SBOM shape

`blint sbom` emits:

- one application component for the app (`pkg:android/<package>`);
- one library component per shipped `.so`
  (`pkg:android/<name>?arch=<abi>`), with the binary's own version
  evidence where it exists;
- **nested** components for identified frameworks — emitted only from
  version-bearing evidence (a version string, a symbol set, or a blintdb
  hash named in the identifying commit; a file name alone is a hint
  property, never a component): NDK libc++, Flutter, React Native /
  Hermes / fbjni, BoringSSL / OpenSSL / NSS, VLC, Qt5 and more
  (`blint/lib/banners.py`, `blint/lib/android_blintdb.py`). `--use-blintdb`
  enriches identification from the blint-db corpus; `--use-blintdb
  --deep` adds disassembly-hash matching before the symbol fallback.
- the dependency graph: the app depends on every native component, and a
  nested framework attaches to the library that carries its evidence.

## The dex↔native JNI join

`android_jni` in the app's metadata joins every dex `ACC_NATIVE`
declaration to the shipped libraries, per ABI (the full field reference
is in `docs/METADATA.md`). Five lists, and what each row proves:

- **`bound`** — a decoded `Java_*` export implements the declaration:
  the JNI specification's name-mangling (Java SE 24, "Resolving Native
  Method Names") matches class, method and (when overloaded) parameter
  descriptors. `fn_addr` is the export's address in that ABI's copy.
- **`bound_dynamic`** — a recovered `JNINativeMethod` table entry answers
  the declaration (name and signature both equal; the table carries no
  class, so signature equality is required). With `--disassemble` a row
  carries one of:
  - `confirmed_by: "findclass"` — the FindClass confirmer read the
    registering function chain's constant class name (the absint
    call-site models over nyxstone text) and it named exactly one
    declaring class with exactly one candidate entry;
  - `confirmed_by: "runtime_table"` — the registrar built the table at
    run time (no static triple exists); only the i386 and arm32
    word-store shapes recover, every word is a store the walk saw and
    every fnPtr passes the function-start oracle;
  - `confirmed_by: "jna_direct"` — JNA direct mapping: the declaring
    class (or a method its `<clinit>` runs) invokes
    `com.sun.jna.Native.register` in the dex, `libjnidispatch.so` ships
    in that ABI, and exactly one same-ABI library exports the method
    name as a defined dynamic `FUNC` — the register call's constant
    library name (at the call, or the one constant the invoked helper
    returns) picks the candidate library, JNA mapping `foo` to
    `libfoo.so`. This is how uniffi bindings bind (Mozilla's
    applications-services megazord and glean-in-libxul, element's
    matrix-sdk-crypto): the VM never looks these names up, JNA's
    `Native.register` binds each static native to the exported symbol
    of the same name, so the join reads the same evidence JNA does.
- **`ambiguous_dynamic`** — the name and signature match recovered table
  entries, but the class-less evidence cannot say which declaration it
  implements (several declaring classes, or several entries); a row that
  a resolved registration provably does not implement may carry
  `candidates_registered_elsewhere: true`, and a JNA-registered name
  exported by several libraries with no register constant carries
  `jna_exporters` (every exporter listed, no arbitrary pick).
- **`unbound_dex_natives`** — nothing in that ABI answers the
  declaration. Not a defect by itself: see known limits.
- **`undeclared_exports`** — the ABI's `Java_*` exports no dex
  declaration claims (plus any that do not decode).

`System.loadLibrary` call sites are listed with the ABIs where the named
member actually ships. With `--disassemble` the app callgraph gains the
native side and `jni_static` / `jni_dynamic` edges for each bound row
(`jni_edge_count` states how many).

## Known limits

Every group the join leaves unbound, from the closing census over the
corpus (43 APK/XAPK entries; `--disassemble` on, listing cap lifted;
the counts are corpus-wide across every APK and ABI):

| Group | Rows | Why it stays unbound | Could more code reach it? |
|---|---|---|---|
| maplibre jni.hpp (`org.maplibre.android.*`, element) | 2,112 (528 × 4 per-ABI builds) | registrations built at run time: the entries pass as vararg references to stack temporaries (bulk copy) or through a builder storing via a stack-passed pointer | not without 64-bit stack-argument seeding plus builder modelling — deliberately out of scope (A13 U2) |
| netty + jansi (vlc) | 1,024 (256 × 4 per-ABI builds) | no implementing library ships in the APK (optional natives; the loader falls back silently) | no — there is nothing to bind to |
| Qt5 (`org.qtproject.qt5.android.*`, osmand) | 292 (73 × 4 per-ABI builds) | Qt's platform plugin (`libqtforandroid.so`) does not ship; libQt5Core's own `initJNI` table binds its 7 rows already | no — there is nothing to bind to |
| `androidx.graphics.path` (every Compose app) | 120 (8 × 15 app-ABIs) | the `RegisterNatives` tables are static and relocated, but every fnPtr lands on a function with no dynsym symbol and no eh_frame row (5 FDEs total, none on the JNI functions) — the function-start oracle refuses, honestly | only by weakening the fn-start oracle; refused (A10's "cause A" ruling) |
| soloader composition (`com.facebook.react.soloader.*`) | 21 per ABI | the composition happens at run time in Java (`SoLoader` merges libraries); no static table exists | no — out of reach by construction |
| yoga wrappers (RnHello, v7a) | 54 per app-ABI | the fnPtrs point at symbol-less, exidx-less Thumb tail-call wrappers | no — the refusal is the oracle working |
| RnHello no-ABI singles (`pushLong`, `putLong`, `installGlobals`, `JSCExecutor.initHybrid`), `nativeReadByte`, x86 `runStdFunctionImpl` | 7 per app | registered by registrars whose class materialization sits on a cold path the linear walk cannot pair (x86 epilogue crossing), or a static fn-start refusal | documented residue (A13) |
| realm / zstd-jni / webrtc / gecko / flutter-embedding / vlc-medialibrary optional natives | ~204 | optional natives whose implementing library is not shipped or registered from code the join does not model | no |

Everything else that was unbound at A13 on this corpus — the 6,045
JNA-direct rows of fennec, element and glean — binds with A14
(`confirmed_by: "jna_direct"`).
