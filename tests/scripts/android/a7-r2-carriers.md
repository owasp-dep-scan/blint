# A7 R2 — the rules on RootBeer 0.1.2 and the benign carriers

Host: the reviewer Mac (macOS 27.0 arm64), blint `feat/an-a7` after K2
(`d9f71a4`), NDK r28c `28.2.13676358` (its llvm-objdump is the oracle),
nyxstone LLVM 18 (`NYXSTONE_LLVM_PREFIX=/opt/homebrew/opt/llvm@18`).
Runner: `a7_r2_carriers.py`; raw JSON: `a7-r2-carriers.json`.

Scope: RootBeer's native library (the committed K1 build of
scottyab/rootbeer tag 0.1.2 `toolChecker.cpp`, arm64-v8a and x86_64) and
the reviewer's benign carriers that fit the sub-minute iteration budget.
The heavy carriers — libxul, libvlc, libart, libflutter,
libbluetooth_jni — are skipped here by wall time (K0 measured 88-1350 s
each) and covered by the R3 sweep at packet end. The whole R2 loop ran in
65.7 s wall for 15 libraries.

## Verdicts

| library | wall | block entries | rules fired |
|---|---|---|---|
| libc.so (bionic) | 9.0 s | 2,513 | none |
| libc_malloc_debug.so | 4.4 s | 433 | none |
| libchrome.so | 6.9 s | 183 | none |
| libclang_rt.asan / hwasan / ubsan | 8.1 / 2.6 / 1.6 s | 2452 / — / 820 | none |
| libdumpstateutil.so | 0.1 s | 97 | **ANDROID_SU_EXECUTION** (true positive) |
| libfdtrack.so | 4.2 s | 310 | none |
| libjnidispatch.so | 0.7 s | 205 | none |
| libmemunreachable.so | 2.0 s | 163 | none |
| libmozglue.so | 9.8 s | 1,109 | none |
| libsentry.so | 5.2 s | 979 | none |
| libunwindstack.so | 5.6 s | 490 | none |
| libtoolChecker 0.1.2 (arm64, x86_64) | 0.02 s | 4 | none |

For comparison, the same carriers under `main` recovered **zero**
rule-relevant constants (K0); the PLT naming, site-keyed resolution and
imagebase-aware pointer floor are what turned these libraries readable —
libunwindstack's block grew 165 -> 490 entries, libsentry's 511 -> 979,
libc's 1,400 -> 2,513.

## The hand-read oracle (llvm-objdump -d, NDK r28c)

- **libtoolChecker.so (RootBeer 0.1.2), the R2 centrepiece.** At
  `0x4874`: `adr x1, 0x66b` loads the mode literal; `mov x19, x0` keeps
  the *caller's* x0; `bl 0x4a90 <fopen@plt>`. At `0x49b8`: x0 is the
  return of a `blr x8` through the JNIEnv table (`GetStringUTFChars`).
  The path argument never holds a constant — the su paths live in the
  dex and cross JNI, exactly measurement 4. blint agrees: 0
  rule-relevant constants, no native rule fires; the app-level
  ANDROID_DEX_SU_PATHS_TO_NATIVE carries the case (fires on the a7 APK
  with `/system/xbin/` among the matched strings and 2 bound native
  declarations; the a5 APKs stay silent).
- **libdumpstateutil.so (the expected tier-0 true positive).** `.rodata`
  `0x25d4` holds `/system/xbin/su\0`; `RunCommandToFd`'s body does
  `adrp x22, 0x2000; add x22, x22, #…` into the char* argument of
  `basic_string::append` and later `mov x0, x22…; bl <execvp@plt>`
  where execvp's path arrives as a register. blint reports
  ANDROID_SU_EXECUTION with `via: string_append`, path
  `/system/xbin/su`, function `android::os::dumpstate::RunCommandToFd`
  — the append is what is proven, the consumer named, not proven.
- **libsentry.so (the anti-debug no-fire, real carrier).** Its ptrace
  call sites carry **no constant request** (arg0 unresolved at every
  site — the request travels in a variable, the crash-handler shape).
  ANDROID_PTRACE_TRACEME correctly stays silent: the rule needs the
  constant 0, not the import.
- **libjnidispatch.so (the unwinder no-fire, real carrier).** Its
  fopen/open sites have unresolved path arguments (the `/proc/self/maps`
  path is built at run time), and no rule fires. The census kept
  `/proc/self/maps` in the gated strings; no rule reads it.
- **libc.so (the property no-fire).** `__system_property_get` constants:
  `libc.debug.malloc.options`, `libc.debug.malloc.program`,
  `libc.debug.hooks.enable`, `heapprofd.enable`, `ro.build.version.sdk`
  — debug and version properties, none in the emulator-only family, so
  ANDROID_EMULATOR_PROPERTY_PROBE stays silent while proving the
  conjunction reads real names.
- **libunwindstack.so (the append form's no-fire).** Its
  `basic_string::append` constants are `/maps` and `  <unknown>` — the
  map-file suffix, not su — and its one dlopen constant is the bare
  SONAME `libdexfile.so`. Both rules correctly stay silent.
- **libmozglue.so.** dlopen constant `libc.so` (bare SONAME) — silent.

No false findings in R2; the one fire is the predicted true positive.
