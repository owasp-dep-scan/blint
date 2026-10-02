# A13 U0 — the 32-bit singles measured, and the 64-bit runtime tables censused

Measure only; no production change. Host: the reviewer Mac (macOS arm64,
darwin 27.0.0). NDK r28c (`28.2.13676358`, the fixture toolchain; no fixture
built in this packet). Oracle: `llvm-objdump` / `llvm-readelf` from Homebrew
LLVM 18.1.8 (`/opt/homebrew/opt/llvm@18`); nyxstone over the same prefix;
the x86 frame questions additionally settled by Unicorn 2.1.4 emulation of
the registrars themselves (the `ret 0x4` finding below). Corpus:
`~/sandbox/android-corpus` — `com.blint.rnhello_1.apk` (tier3-frameworks)
and `im.vector.app_40106624.apk` (tier2-fdroid, "element"). Script:
`tests/scripts/android/a13_u0_measure.py`; raw data: `/tmp/a13-u0.json`;
evidence windows: `/tmp/a13-u0-windows/*.asm`. blint @ `7b1a262` (main).

The join with the confirmers reproduces the A12 review's counts exactly:
arm64-v8a and x86_64 305/1/26, armeabi-v7a 247/1/84, x86 289/2/41
(bound_dynamic / ambiguous_dynamic / unbound); v7a's runtime_table rows 16,
x86's 4.

## (a) v7a's nine singles and x86's fifteen cause-B rows, by shape

v7a's 84 unbound = 54 yoga (closed) + 21 soloader (out of reach) + 9 singles.
x86's 41 = 21 soloader + 15 cause-B + 4 no-ABI rows (`pushLong`, `putLong`,
`JSCExecutor.initHybrid`, `installGlobals`) + the yoga
`jni_YGNodeSetStyleInputsJNI` (yoga cause A). Of x86's 15 cause-B rows, 11
are rows v7a recovers and x86 does not; the other 4 are the same rows that
fail on v7a (the S1 singles below). Four shapes cover everything:

| shape | rows | ABIs | the store sequence that defeats the walk |
|---|---|---|---|
| S1 class-after-vtable | `ThreadScopeSupport.runStdFunctionImpl`, `CxxCallbackImpl.nativeInvoke`, `ComponentNameResolverBinding.install`, `UIConstantsProviderBinding.install` | both | the registrar caches its jclass in a static and names the class only on the cold init path, which the compiler places at a **higher address** than the hot path holding the vtable call; the linear walk reaches the call with no class and drops the event (the words, the marker and the count all read) |
| S2 static fn-start refusal | `NativeMemoryChunk.nativeReadByte` | v7a | not a runtime shape: the registrar (libimagepipeline `JNI_OnLoad` → fbjni initialize chain) registers the **static** table at 0x3058 (6 entries). The static scan recovers the merged run 0x3040–0x3094 but refuses the last entry (slot 0x3094): its fnPtr 0xe44 is a 6-byte Thumb leaf (`ldrsb.w r0, [r2]; bx lr`) with no dynsym symbol and no `.ARM.exidx` row — yoga cause A's honest refusal. The runtime walk is not the reader that fails |
| X1 sret callee-pop | `TurboModulePerfLogger.jniEnableCppLogging`, `ProxyJavaScriptExecutor.initHybrid`, `HybridData$Destructor.deleteNative`, `BlobCollector.nativeInstall` — **and, through their `registerHybrid` callee, the seven rows below** | x86 | fbjni's `findClassLocal`/`findClassStatic` return `local_ref<jclass>` by sret and end in **`ret 0x4`** — the callee pops its hidden result pointer (verified: libfbjni-x86 0x1fa7f `ret 0x4`; Unicorn emulation of `TurboModulePerfLogger` and the `0x54b820` staging confirms the post-call esp is the pre-call esp **plus 4**). The model treats calls as stack-neutral, so the caller's compensating `sub esp, 4` leaves the frame baseline one word low; registrars that store the entry words **before** the call and compute the methods `lea` **after** it read the name word from the empty slot below the entry. The working control (`JReactMarker`) stores after the sub, so its stores and lea share the same wrong baseline and it binds |
| X2 the same pop, inside the chain callee | `NativeArray.toString`, `NativeMap.toString`, `CxxModuleWrapperBase.getName`, `ReadableMapBuffer.importByteBuffer`, `DefaultTurboModuleManagerDelegate.initHybrid`, `JSTimerExecutor.callTimers`, `HermesInstance.initHybrid` | x86 | the staging passes `{methods, count}` to `registerHybrid` as `initializer_list` — 8 raw bytes through `movsd`, which the model **already tracks** (`movsd` pairs since A11; the trace shows both words landing in the outgoing slots). The defeat is inside the seeded callee: every `registerHybrid` instantiation calls `findClassLocal` (the sret `ret 0x4` shape) *before* reading its incoming pair, so the un-compensated baseline shifts `lea edi, [esp + 0x30]` (registerHybrid<NativeArray> at 0x54a8b4) one word below the pair — it reads the return-address slot instead |

x86's S1 rows have the same init-path shape as v7a's (`JCxxCallbackImpl`
0x54ba50: hot-path vtable call at 0x54babd, init path at 0x54bae5+). One
complication is x86-only: in `ThreadScope::OnLoad` (0x17c70) the init path
sits **after the epilogue**, and the linear walk crosses the epilogue whose
pops restore junk into `ebx` (the GOT base), so the class-name `lea` at
0x17d3b yields a frame tuple and no class event fires at all — S1's fix
alone cannot recover x86's `runStdFunctionImpl`.

Verbatim representatives are committed beside this file in spirit — the
script's `--windows` output; the load-bearing lines:

**v7a S1 — `JCxxCallbackImpl::registerNatives` at 0x3c58c0 (Thumb):**

```asm
  3c58f8:  stm.w  sp, {r0, r1, r2}     # the entry words
  3c58fc:  blx    0x45f1a0             # getCurrentThreadEnv
  3c5902:  mov    r2, sp               # methods = sp (marker reads)
  3c5904:  movs   r3, #1               # count (reads)
  3c5906:  ldr.w  r5, [r1, #0x35c]     # RegisterNatives slot
  3c590c:  blx    r5                   # ← reached with last_class=None
  ...      (0x3c592e+ = the cold init path: findClassLocal names the class,
              branches back to 0x3c58e4 — after the call in address order)
```

**x86 X1 — `TurboModulePerfLogger`'s registrar at 0x5daab0:**

```asm
  5daad6:  lea    eax, [ebx - 0x458244]     # "jniEnableCppLogging"
  5daadc:  mov    [esp + 0x20], eax         # entry.name   ← stored HERE (esp = E)
  5daae6:  mov    [esp + 0x24], eax         # entry.signature (GOT slot)
  5daaf0:  mov    [esp + 0x28], eax         # entry.fnPtr      (GOT slot)
  5daafe:  lea    eax, [esp + 0x18]
  5dab02:  mov    [esp], eax                # arg1 = sret pointer (frame address)
  5dab05:  call   findClassLocal@plt        # callee ends `ret 0x4` → esp = E+4
  5dab0a:  sub    esp, 0x4                  # compensation → esp = E (truth)
  5dab12:  mov    ecx, [esp + 0x18]         # clazz ← the sret slot (aligns at E)
  5dab1e:  lea    esi, [esp + 0x20]         # methods = E+0x20 (the model says E-4+0x20)
  5dab35:  call   edx                       # ← the walk's marker is one word low
```

**x86 X2 — `NativeArray::registerNatives` staging at 0x54a7e0:**

```asm
  54a7fa:  lea    eax, [ebx - 0x455ef7]
  54a800:  mov    [esp + 0x18], eax     # entry words staged
  54a818:  lea    eax, [esp + 0x18]
  54a81c:  mov    [esp + 0x10], eax     # pair.methods
  54a820:  mov    dword ptr [esp + 0x14], 1   # pair.count
  54a828:  movsd  xmm0, qword ptr [esp + 0x10]
  54a82e:  movsd  qword ptr [esp], xmm0  # the 8-byte pass the model drops
  54a833:  call   registerHybrid<NativeArray>@plt
```

## (b) the 64-bit census: registrations built at run time, per shape

RnHello arm64 (86 vtable sites over 9 libraries; libreactnative 65,
libfbjni 4, libhermestooling 5, imagepipeline/jsi/hermes 3-1-3, the
filters/transcoders 2-2-1) and element x86_64 (88 sites over 8 libraries;
libmaplibre 31, libreactnative 40, the RN satellites the rest):

| APK, ABI | library | sites | shape | count | word-by-word readable? |
|---|---|---|---|---|---|
| element x86_64 | libmaplibre.so | 31 | jni.hpp bulk copy | 35 peer registrations (callers of the `jni::RegisterNatives` helpers) | **no** — the entries pass as vararg references to stack temporaries; the helper copies whole 24-byte entries (`movups` + the `[rdx+0x10]` word) into its own array; the names reach the temporaries through further stack objects (`mov r14, [r12]`), only the signature/fnPtr words come from `.data` pointer slots |
| element x86_64 | libmaplibre.so | (above) | single-entry builder | 40 builder callers (`MakeNativeMethod`/`RegisterNativePeer`), e.g. `MapRendererRunnable::registerNative` 0x4dad90: the name is a rip `lea`, but the signature/fnPtr pass in **argument registers** to a builder that stores them through a **stack-passed** `&entry` pointer — the 64-bit seed carries registers, not the stack-arg pointer, so the callee's stores cannot tie back | **no** (not without new stack-argument seeding plus builder modelling) |
| RnHello arm64 | all | 86 | fbjni single entry, 24-byte static copy | the fbjni singles (`JNativeRunnable` 0x19524: `adr x8, <object>; ldr q0, [x8]; ldr x8, [x8, #0x10]; str q0, [sp]; str x8, [sp, #0x10]; bl registerHybrid@plt`) — but the copied object **is** a static relocated triple (0x2cb88 `run/()V/0x196bc`, 0x2cbf0 `runStdFunctionImpl`, 0x2ccd8 `deleteNative` …) that the static scan already recovers; these rows are bound on arm64 **without** any runtime walk | no new rows exist to read |
| both | — | — | other | the counts/computed tables (hermes tooling, jsi) | out of scope |

element's 1027 unbound rows decompose as 883 `org.maplibre.*` (the jni.hpp
shapes above), 112 `uniffi.*` (Rust uniffi — a different family this wave
was not asked about), 26 `com.*`, 6 `io.*`. RnHello arm64's 26 unbound are
the 21 soloader rows, the 4 no-ABI rows and the yoga
`jni_YGNodeSetStyleInputsJNI` — none has a runtime table any ABI reads.

## (c) what U1 and U2 can reach

**U1 (the 32-bit singles) can reach, on the shapes above:**

- v7a: the four S1 rows (`runStdFunctionImpl`, `nativeInvoke`, both
  `install` bindings) — a runtime-shaped vtable call that no class
  materialization preceded can pair with the one class name the function
  does materialize (on the cold init path, below the call in address
  order); two class names or none leave it unrecorded.
  `nativeReadByte` (S2) stays: the refusal is the fn-start oracle's, and
  widening the walk cannot honestly read a symbol-less, exidx-less leaf.
- x86: the X1 four plus — through the same compensation inside the chain
  callee — the X2 seven (a call whose outgoing first argument is a pointer
  into the caller's frame returns through it and pops it; the caller's own
  `sub esp, K` immediately after the call states the pop size, so the
  baseline survives the pair. The failure mode of a wrong trigger is a
  shifted baseline that reads `None` words and refuses, never a wrong
  binding); the S1 rows except `runStdFunctionImpl` (x86's
  `ThreadScope::OnLoad` loses its init-path class materialization to the
  epilogue crossing — explained residue, not fixable by a linear walk
  without guessing register liveness).
- Expected arithmetic if every fix lands: v7a 247/1/84 → 247+4/1/80; x86
  289/2/41 → 289+15/1/27. The x86 install registrars and
  `JCxxCallbackImpl` do fire their init-path class events (the epilogue
  pops corrupt `ebx` only where the frame was realigned —
  `ThreadScope::OnLoad`'s `and esp, -16` is what makes its pops read the
  opaque-namespace slots). Nothing else moves: the 21 soloader rows per
  ABI, yoga, and the four no-ABI rows stay.

**U2 is dropped.** No readable shape exists on either 64-bit ABI: on
RnHello arm64 every runtime-built registration copies a static triple the
static scan already recovers (no new rows), and on element x86_64 the
jni.hpp shapes pass their entries through vararg stack temporaries (bulk
copy) or through a builder storing via a stack-passed pointer the 64-bit
seed does not carry (single entry). The prompt's own bar — a copy whose
source ties to a static object's words — is met by nothing the census
found. `absint` is untouched by U1, so the KPI suite is not triggered
(this is stated, not silently skipped); if U1's implementation does end up
touching `absint.py`, the full suite runs on all architectures.
