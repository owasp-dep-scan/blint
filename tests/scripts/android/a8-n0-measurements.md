# A8 N0 — the measurement, before any code changes

Host: the reviewer Mac (macOS 27.0 arm64), blint `feat/an-a8` at the N0
commit (branch point `5e121ed`, A7.2 merged), NDK r28b `28.2.13676358`
(`llvm-nm -D --defined-only`, `llvm-objdump`, `llvm-readelf -r` all from
`$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin`). Runner:
`a8_n0_measure.py --corpus ~/sandbox/android-corpus --llvm-bin <NDK bin>`
(full JSON not committed). Nothing in this packet changes blint/ code.

## (a) the J3 recall-gap hosts, exported API per ABI

`llvm-nm -D --defined-only`, family counts in the same run. gnutls_ counts
names *containing* the token, nettle_ the token minus gnutls-family
overlaps — the reviewer's A8-prompt table spellings (1,748 / 508 on vlc
13070105 v7a reproduce exactly).

| host (library) | abi | defined | port API families |
|---|---|---|---|
| fennec 1560000 `libgkcodecs.so` | armeabi-v7a | 153 | opus_ 27, vorbis_ 28, vpx_ 26 |
| fennec 1560010 | x86_64 | 153 | opus_ 27, vorbis_ 28, vpx_ 26 |
| fennec 1560020 | arm64-v8a | 153 | opus_ 27, vorbis_ 28, vpx_ 26 |
| saber 1360101 `libpdfium.so` | armeabi-v7a | 669 | FPDF*/PDFium* 421 |
| saber 1360102 | arm64-v8a | 670 | FPDF*/PDFium* 421 |
| saber 1360103 | x86_64 | 670 | FPDF*/PDFium* 421 |
| vlc 13070105 `libvlc.so` | armeabi-v7a | 32,851 | gnutls_ 1,748, nettle_ 508 |
| vlc 13070106 | arm64-v8a | 31,776 | gnutls_ 1,753, nettle_ 479 |
| vlc 13070107 | x86 | 31,440 | gnutls_ 1,762, nettle_ 480 |
| vlc 13070108 | x86_64 | 31,932 | gnutls_ 1,764, nettle_ 497 |
| osmand 540401 `libOsmAndCoreWithJNI.so` | armeabi-v7a | 10,578 | GDAL*/OGR*/CPL*/OSR* 0 |
| osmand 540402 | x86 + x86_64 | 10,576 / 10,570 | GDAL* 0 |
| osmand 540403 | arm64-v8a | 10,576 | GDAL* 0 |

vcpkg ports at the pinned revision 63bb8e44c1: `libgnutls` 3.8.12 (deps:
gmp, libidn2, libtasn1, libunistring, **nettle** 3.10, zlib), `gdal`,
`opus`, `libvorbis`, `libvpx` exist; **no `pdfium` port** (checked
`ports/`; J3's finding stands).

**The 30-name gate decides N1:**

- **kept: GnuTLS (vlc)** — 1,748-1,764 gnutls_ + 479-508 nettle_ on every
  ABI, port exists, one build brings nettle. The only kept host.
- **dropped: GDAL (osmand)** — 0 exported GDAL/OGR/CPL/OSR names on every
  ABI (hidden visibility; J3 gap entry 2, A6.4 deep hashes, out of scope).
- **dropped: pdfium (saber)** — 421 FPDF names is far above the gate, but
  no vcpkg port exists at the pinned revision, so A6.2's recipe cannot
  build it. Named, not built.
- **dropped: opus/libvorbis/libvpx (fennec libgkcodecs)** — 26-28 names
  each on every ABI, below the gate; lowering it re-opens J0's
  `sub_<hex>`/`$d.<n>` false-positive families.

## (b) where RnHello's 221 unbound declarations live

The join on `com.blint.rnhello_1.apk` at `5e121ed`: 0 bound, 111
bound_dynamic, 0 ambiguous, **221 unbound** — identical counts on all four
ABIs because `build_jni_join_summary` parses each library name once from
its first location (the arm64 bytes) and applies those tables to every
ABI. Per-ABI truth, measured from each ABI's own bytes:

| abi | F1 entries today (all libs) | extended-map entries |
|---|---|---|
| arm64-v8a | 111 (libreactnative 96, imagepipeline 8, native-filters 5, native-imagetranscoder 2) | 301 |
| armeabi-v7a | 55 (41 + 7 + 5 + 2) | 228 |
| x86 | 109 (94 + 8 + 5 + 2) | 282 |
| x86_64 | 111 (96 + 8 + 5 + 2) | 301 |

**The strings are in standard `JNINativeMethod` triples after all** —
stride 3 words (24 B on 64-bit ABIs, 12 B on 32-bit), in `.data.rel.ro`:
name at +0, signature at +1 word, fnPtr at +2 words. What differs from
F1's assumption is *which relocation carries each word*:

- the **name** word is `R_*_RELATIVE` (addend → `.rodata`);
- the **signature** word is an absolute relocation against the
  locally-defined weak OBJECT symbol
  `facebook::jni::jmethod_traits<F>::kDescriptor` (→ `.rodata`):
  `R_AARCH64_ABS64` / `R_ARM_ABS32` / `R_X86_64_64` / `R_386_32`;
- the **fnPtr** word is the same absolute form against the weak FUNC
  `facebook::jni::detail::MethodWrapper<M,&m>::call` (or
  `FunctionWrapperWithJniEntryPoint<F>::call`) — a defined dynamic FUNC,
  so it is already inside F1's `function_starts`.

fbjni's `registerNatives`/`makeNativeMethod` emits
`{name, kDescriptor, &MethodWrapper::call}`; the named template symbols
stay preemptible in `.dynsym` (weak, default visibility), so the linker
keeps symbol relocations instead of folding them to RELATIVE — which is
why F1's RELATIVE-only walk skips the whole triple. 169 of the unbound
names exist as strings in the arm64 libraries (libreactnative 162,
libhermestooling 5, libfbjni 4 - the generator on every group is fbjni:
ReactNativeFeatureFlagsCxxInterop 49 through `FunctionWrapperWithJniEntryPoint`
statics, HybridClass tables through `MethodWrapper`).

**Coverage if the walk also read absolute-against-defined-symbol words**
(the N2 candidate; F1's walk and validation unchanged, one map extended):

| abi | would bind (of 221) | pairs left ambiguous | pairs still unmatched |
|---|---|---|---|
| arm64-v8a | **167** | 8 | 30 |
| armeabi-v7a | 153 | 7 | 45 |
| x86 | 153 | 7 | 45 |
| x86_64 | 167 | 8 | 30 |

The arm64 unmatched residue (46 declarations): **21 soloader
`OpenSourceMergedSoMapping` `lib<name>_so ()I` accessors — the name
strings do not exist in any binary**; JNI_OnLoad composes them at runtime
from a `{const char* so_name, void* stub}` array (stride 16 B, the
`lib<name>.so` strings relocated RELATIVE) into a `calloc`'d
JNINativeMethod array (read in libjsctooling.so on element:
`adrp x1, <class name>; ... ldr x8,[x8,#0x30]; blr` = FindClass, then the
calloc loop). No static name carrier — dropped from N2's scope, named.
The rest are singles (initializeBridge, pushLong/putLong, three initHybrid
variants, JSCExecutor, YogaNative, UIConstantsProviderBinding,
TurboModuleManager).

## (c) ambiguous_dynamic over the 27 APKs, and the FindClass carrier

Census (the join as it stands on `5e121ed`): 4 of 27 APKs carry
`ambiguous_dynamic` — fennec 1560000/10/20 (11 each: 9 × `disposeNative
()V`, 2 × `onError (I)V`) and element 40106622/40106624 (5 each: all
`initHybrid ()Lcom/facebook/jni/HybridData;`, one recovered entry, five
declaring classes). Total 43 entries; 23 APKs carry none.

Carrier measurement (arm64; adrp+add materializations read as *strings at
the target address* — fbjni slices the class name out of the middle of the
`Lcom/...;` descriptor, so a precomputed string map misses it — plus
direct `bl` edges with PLT stubs resolved through the GOT, up to 2 hops to
a function loading the RegisterNatives vtable slot `ldr xN,[xM,#0x6b8]`):

- **fennec 1560020 (libxul): 7/7 candidate entries confirmed.** Each
  ambiguous table's registrar materializes exactly one declaring class:
  GeckoResult$GeckoCallback, EventDispatcher, AndroidVsync,
  XPCOMEventTarget, GeckoSession$Compositor; the shared `onError` table
  registers twice, once per class — the carrier resolves at site level.
- **RnHello post-N2 (the 8 pairs N2 would leave ambiguous): 6/6
  registering-table chains confirmed** — `X::registerNatives()` adrp+add's
  the table (stack memcpy) and `bl`s (PLT) into
  `HybridClass<T>::registerHybrid`, which materializes the class-name
  string, calls `findClassLocal`, then the RegisterNatives vtable slot.
  Confirmed classes: BindingImpl, ComponentFactory, EventBeatManager,
  EmptyReactNativeConfig, StateWrapperImpl, CatalystInstanceImpl. The
  remaining 17 candidate rows are mid-table artifacts of the measurement's
  run segmentation, inside these six confirmed tables.
- **element 40106622 (libjsctooling): 0/1 confirmed** — the one ambiguous
  entry's table is registered by the runtime-composed soloader shape
  above (the class name beside it is `OpenSourceMergedSoMapping`, which is
  not among the pair's declaring classes; the `initHybrid` declarations
  stay ambiguous). 40106624 recovers no candidate table on arm64.

**N3 verdict: carriers exist** (fennec 7/7, RnHello 6/6 chains) — kept,
with the measured rule: bind an ambiguous entry when the registering
function chain's constant class-name string names exactly one of the
pair's declaring dex classes.

## The scope N0 decides

- **N1: GnuTLS only** (libgnutls 3.8.12 + nettle, 4 Android triplets,
  dynamic linkage, the A6.2 recipe). GDAL, pdfium, opus/libvorbis/libvpx
  dropped with the measured reasons above.
- **N2: the fbjni merged-registration shape** — extend the F1
  relocation-slot map with absolute relocations against locally-defined
  symbols; the walk, validation and join stay as they are. Expected:
  167/221 bound on arm64/x86_64, 153 on v7a/x86; the soloader 21 have no
  static carrier and stay unbound (documented, not guessed).
- **N3: the FindClass confirmer** — kept; 8 post-N2 pairs on RnHello plus
  today's 43 corpus entries, 7/7 + 6/6 carriers measured on the two apps
  where the tables register statically.
