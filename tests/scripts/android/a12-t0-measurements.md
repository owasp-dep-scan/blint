# A12 T0 — armeabi-v7a's RnHello rows measured: the confirmer's 22 ambiguous and the 45 non-yoga unbound

Measure only; no production change. Host: the reviewer Mac (macOS arm64,
darwin 27.0.0). NDK r28c (`28.2.13676358`, the fixture toolchain; no fixture
built in this packet). Oracle: `llvm-objdump` / `llvm-readelf` from Homebrew
LLVM 18.1.8 (`/opt/homebrew/opt/llvm@18`); nyxstone over the same prefix.
Corpus: `~/sandbox/android-corpus` — `com.blint.rnhello_1.apk`
(tier3-frameworks). Script: `tests/scripts/android/a12_t0_measure.py`; raw
data: `/tmp/a12-t0.json` (summarized below). blint @ `deb4bcb` (A11 merged).

The join with the FindClass confirmer reproduces the A11 review's counts
exactly: arm64-v8a and x86_64 305/1/26, armeabi-v7a 211/22/99, x86 289/2/41
(bound_dynamic / ambiguous_dynamic / unbound).

## (a) v7a's 99 unbound rows, split by cause

| cause | rows | note |
|---|---|---|
| yoga wrappers (A, closed) | 54 | fnPtrs land on 6-14-byte Thumb tail-call wrappers with no symbol and no `.ARM.exidx` row; arm64 binds the same declarations through eh_frame-covered wrappers. One further yoga row (`jni_YGNodeSetStyleInputsJNI`) is *unbound on arm64* and bound_dynamic on v7a — the two ABIs' static-table recoveries disagree on it; it is inside arm64's 26, not v7a's 99-relevant sets. |
| non-yoga, arm64 answers (B) | 20 | the tables the 32-bit build constructs at run time; this wave's target |
| non-yoga, no ABI answers | 25 | the 21 `OpenSourceMergedSoMapping.lib*_so` rows, `WritableNativeArray.pushLong`/`WritableNativeMap.putLong`, `JSCExecutor.initHybrid`, `ReactInstance.installGlobals` — plus `JSCInstance.initHybrid`, which arm64 leaves ambiguous (its own residue) |

## (b) the 22 ambiguous rows: registrar and argument sequence

21 of the 22 map to a named registrar chain (the exception is
`JSCInstance.initHybrid`, no registrar in any shipped library names it —
arm64's ambiguous residue too). Three staging shapes cover them:

| shape | registrars (rows) | count |
|---|---|---|
| `memcpy_from_static` | `CatalystInstanceImpl::registerNatives` (5 rows), `Binding::registerNatives` (BindingImpl), `JReactInstance::registerNatives` (5 ReactInstance rows), `WritableNativeArray/Map::registerNatives` | immediate (0x11, 0xe, 0x9, 0x8) |
| `neon_copy_static` | `CompositeTurboModuleManagerDelegate::registerNatives`, `JEmptyReactNativeConfig`, `StateWrapperImpl`, `EventBeatManager`, both inspector targets (6 rows) | immediate (0x5, 0x4, 0x2) |
| `runtime_built` | `ComponentFactory::registerNatives` (1 row) | immediate (0x1) |

One representative per shape, verbatim `llvm-objdump`
(`--triple=thumbv7a-none-linux-androideabi`; the ARM-mode `.plt` is decoded
separately through `.rel.plt`). The pc idiom is a pc-relative literal-pool
load completed by `add rN, pc`: `ldr r1, [pc, #K]` loads a pool word W, and
`add r1, pc` computes `W + (site + 4)`, the data address.

**memcpy_from_static — `facebook::react::Binding::registerNatives()` at 0x27aec0:**

```asm
  27aec6:  ldr   r1, [pc, #0x34]         @ 0x27aefc  (pool: table offset)
  27aec8:  mov   r4, sp                  # the stack buffer
  27aeca:  ldr   r0, [pc, #0x34]         @ 0x27af00  (pool: GOT offset)
  27aecc:  movs  r2, #0xa8               # 168 = 14 entries x 12 bytes
  27aece:  add   r1, pc                  # r1 = static merged table (.data.rel.ro)
  27aed0:  add   r0, pc                  # r0 = GOT slot
  27aed2:  ldr   r0, [r0]                # JavaVM*
  27aed4:  ldr   r0, [r0]                # JNIEnv
  27aed6:  str   r0, [sp, #0xac]
  27aed8:  mov   r0, r4                  # memcpy dst = sp
  27aeda:  blx   0x45cc44                # memcpy(sp, static, 168)
  27aede:  mov   r0, r4                  # methods = sp
  27aee0:  movs  r1, #0xe                # count = 14
  27aee2:  blx   0x45f8a0                # HybridClass<Binding, JBinding>::registerHybrid@plt
```

**neon_copy_static — `facebook::react::EventBeatManager::registerNatives()` at 0x29c380:**

```asm
  29c386:  ldr      r0, [pc, #0x3c]      # pool: static 2-entry table
  29c388:  ldr      r1, [pc, #0x3c]      # pool: GOT slot
  29c38a:  add      r0, pc               # r0 = static table (24 bytes)
  29c38c:  add      r1, pc               # r1 = GOT slot
  29c38e:  vld1.64  {d16, d17}, [r0]!    # 16 of the 24 bytes
  29c392:  ldr      r1, [r1]             # JavaVM*
  29c394:  vldr     d18, [r0]            # the remaining 8
  29c398:  mov      r0, sp
  29c39a:  ldr      r1, [r1]             # JNIEnv
  29c39e:  mov      r1, r0
  29c3a0:  vst1.64  {d16, d17}, [r1]!    # into the stack buffer
  29c3a4:  vstr     d18, [r1]
  29c3a8:  movs     r1, #0x2             # count = 2
  29c3aa:  blx      0x460740             # registerHybrid(sp, 2)@plt
```

The static table exists in the file in both copy shapes; the join already
recovers its entries (that is why the rows are *ambiguous*, not unbound).

**runtime_built — `facebook::react::ComponentFactory::registerNatives()` at 0x27f7b8:**

```asm
  27f7be:  ldr   r0, [pc, #0x3c]         # pool: name GOT offset
  27f7c0:  ldr   r1, [pc, #0x3c]         # pool: signature GOT offset
  27f7c2:  ldr   r2, [pc, #0x40]         # pool: fnPtr offset
  27f7c4:  add   r0, pc
  27f7c6:  ldr   r3, [pc, #0x40]         # pool: GOT offset (env)
  27f7c8:  add   r1, pc
  27f7ca:  ldr   r0, [r0]                # name  = *(GOT slot)
  27f7cc:  add   r2, pc                  # fnPtr = pc-computed
  27f7ce:  add   r3, pc
  27f7d0:  ldr   r1, [r1]                # signature = *(GOT slot)
  27f7d6:  str   r3, [sp, #0xc]
  27f7d8:  str   r1, [sp, #0x8]          # entry.signature
  27f7da:  movs  r1, #0x1                # count = 1
  27f7dc:  strd  r2, r0, [sp]            # entry.fnPtr, entry.name
  27f7e0:  mov   r0, sp                  # methods = sp
  27f7e2:  blx   0x45fc00                # registerHybrid(sp, 1)@plt
```

No static triple exists for this entry in the v7a bytes (A10's cause B
measurement: the name/signature/fnPtr words are only ever stored).

**The fbjni callee every staging calls — `HybridClass<Binding, JBinding>::registerHybrid` at 0x27af08** (all 21
mapped rows go through a per-class weak instantiation of it; the call reaches
it through the PLT because the symbol is preemptible):

```asm
  27af08:  push  {r4, r5, r6, r7, lr}
  27af0a:  add   r7, sp, #0xc
  27af12:  mov   r5, r0                  # methods (incoming arg 0)
  27af14:  ldr   r0, [pc, #0xa4]         # pool: GOT offset
  27af16:  mov   r4, r1                  # count (incoming arg 1)
  27af18:  add   r0, pc
  27af1a:  ldr   r0, [r0]                # JavaVM*
  27af1c:  ldr   r0, [r0]                # JNIEnv
  27af28:  ldr   r0, [pc, #0x94]         # pool: class-name string offset
  27af2c:  add   r0, pc
  27af2e:  adds  r0, #0x1                # skip the byte before the name
  27af30:  vld1.8 {d16, d17}, [r0]!      # NEON copy of the class name
  ...      (findClassLocal(copy), then:)
  27af5e:  blx   0x45f1a0                # getCurrentThreadEnv
  27af62:  ldr   r2, [r0]                # vtable
  27af64:  ldr   r1, [sp]                # clazz
  27af66:  ldr.w r6, [r2, #0x35c]        # RegisterNatives slot (215*4)
  27af6a:  mov   r2, r5                  # methods <- incoming arg 0
  27af6c:  mov   r3, r4                  # count    <- incoming arg 1
  27af6e:  blx   r6                      # RegisterNatives(env, clazz, methods, count)
```

The vtable call reads its arguments from the caller-carried r0/r1 — the same
cross-function shape the A9 P3 argument carrying resolves on arm64 and i386.

## (c) the 45 non-yoga unbound rows

**The 20 cause-B rows** (arm64 answers, v7a does not) are all tables built at
run time; the readable shapes:

| shape | rows (registrar) |
|---|---|
| same-function, `str`/`strd` stores | `JReactMarker::registerNatives` (nativeLogMarker), `DefaultComponentsRegistry::registerNatives` (register), `JInspectorFlags::registerNatives` (getFuseboxEnabled), `ThreadScope::OnLoad` (runStdFunctionImpl) |
| same-function, `stm.w sp, {r0, r1, r2}` | `JCxxCallbackImpl::registerNatives` (nativeInvoke) |
| fbjni chain, staging stores + registerHybrid callee | `NativeArray.toString`, `NativeMap.toString`, `ReadableMapBuffer.importByteBuffer`, `JSTimerExecutor.callTimers` (JTurbomodulePerfLogger-family), `HermesInstance.initHybrid`, `DefaultTurboModuleManagerDelegate.initHybrid`, the anonymous libfbjni staging at 0x115f4 (NativeRunnable.run) |
| registrar not labeled in the dump | `NativeMemoryChunk.nativeReadByte` (libimagepipeline JNI_OnLoad -> fbjni initialize chain), `HybridData$Destructor.deleteNative` (libfbjni), `ProxyJavaScriptExecutor.initHybrid`, `TurboModulePerfLogger.jniEnableCppLogging`, `BlobCollector.nativeInstall`, `CxxModuleWrapperBase.getName` |

**same-function runtime_built — `JReactMarker::registerNatives()` at 0x3bd49c:**

```asm
  3bd4ea:  ldr   r0, [pc, #0x78]         # pool: name offset
  3bd4ec:  ldr   r1, [pc, #0x78]         # pool: signature GOT offset
  3bd4ee:  add   r0, pc
  3bd4f0:  ldr   r2, [pc, #0x78]         # pool: fnPtr offset
  3bd4f2:  add   r1, pc
  3bd4f4:  ldr   r0, [r0]                # name = *(GOT slot)
  3bd4f6:  add   r2, pc                  # fnPtr = pc-computed
  3bd4f8:  ldr   r1, [r1]                # signature = *(GOT slot)
  3bd4fa:  str   r1, [sp, #0x10]         # entry.signature
  3bd4fc:  strd  r2, r0, [sp, #8]        # entry.fnPtr, entry.name
  3bd500:  blx   0x45f1a0                # getCurrentThreadEnv
  3bd504:  ldr   r2, [r0]                # vtable
  3bd506:  ldr   r1, [sp, #4]            # clazz
  3bd508:  ldr.w r4, [r2, #0x35c]        # RegisterNatives slot
  3bd50c:  add   r2, sp, #0x8            # methods = sp+8
  3bd50e:  movs  r3, #0x1                # count = 1
  3bd510:  blx   r4                      # RegisterNatives(env, clazz, sp+8, 1)
```

**`stm.w` spelling — `JCxxCallbackImpl::registerNatives()` at 0x3c58c0** builds
the same one-entry table with `stm.w sp, {r0, r1, r2}` (a store-multiple:
r0 to [sp], r1 to [sp+4], r2 to [sp+8]) before the identical vtable tail.

**The 25 rows no ABI answers** stay out of reach on every ABI (the soloader
composition declares them but no library's registration names them inside this
app's bytes; `pushLong`/`putLong`/`installGlobals` are registered by code paths
no ABI's join recovers). They are the same 25 arm64 keeps (arm64's 26th is the
yoga `jni_YGNodeSetStyleInputsJNI`).

## (d) what T1-T3 can reach

**T1 (the model) needs, per A10 Q0's inventory plus what the bytes above add:**
- registers r0-r12 families (arguments in r0-r3, the rest on the stack;
  r4-r11 callee-saved, r7 the frame pointer beside sp, lr its own family);
- Thumb text, 16- and 32-bit: `movs/mov rN, #imm|rM`, `adds/add.w`,
  `subs/sub sp, #imm`, `ldr rN, [pc, #K]` (literal pool),
  `add rN, pc` (the pc completion), `movw/movt`, `ldr/str/strd/stm.w`
  (sp- and register-based, writeback forms), `push/pop` (including `push
  {r4-r7, lr}` low/high split), NEON `vld/vst` as no-ops for GPRs;
- the vtable access `ldr(.w) rN, [rM, #860]` + `blx rN`, and `bl`/`blx imm`
  as calls (the PLT is ARM-mode but the *call* is Thumb `blx imm`);
- entry stride 12; the Thumb bit at every function start and fnPtr.

**T2 (the confirmer on v7a) can reach the 20 copy-static ambiguous rows** —
the arm64 fbjni chain, through: an arm32 branch in `_elf_plt_stub_names`
(the PLT stubs are ARM-mode `add ip,pc,#A; add ip,ip,#B; ldr pc,[ip,#C]!`,
3863 of them in libreactnative.so alone — without it no staging call resolves
and the chain never reaches the callee), the seeded callee reading
(methods, count) from the carried r0/r1, and `_stack_copy_origin` tying the
methods marker to the staging's memcpy source or its single table
materialisation (the NEON variant's pc-pair names the same static address the
copies read). The residue: `ComponentFactory.initHybrid` (its own table is
runtime-built, so no static range can name it — T3's, not T2's) and
`JSCInstance.initHybrid` (no registrar names it; arm64's residue too).

**T3 (runtime-built tables on v7a) has readable shapes**: constant counts
(`movs r3, #N`/`movs r1, #N`), words from pc-pairs (locally-defined strings
and fnPtrs), GOT-slot loads resolvable through the join's relocation maps
(`ldr rN, [rM]` where rM is a completed pc-pair naming a `.got` slot), and
stores `str`/`strd`/`stm.w` into the sp buffer the methods argument names.
The fn-start oracle on v7a is dynsym FUNCs plus `.ARM.exidx`. On x86 the same
family recovered 4 of 19 rows; how many of v7a's 20 the walk reads is T3's
measurement, not assumed here.

**Out of reach on v7a regardless**: the 54 yoga rows (A10 closed them), the
25 no-ABI rows, `JSCInstance.initHybrid`, and any registration whose count is
computed at run time or whose registrar the walk cannot name.

## Cost note (A10 Q0's estimate, still the reference)

A10 Q0 estimated the arm32 model at the i386 model's scale (registers,
immediates, stores, one pc idiom). What the v7a bytes add over that estimate:
the literal-pool word read (the model cannot see pool bytes — the walk must
resolve `ldr rN, [pc, #K]` beside it, the way i386's GOT loads resolve), the
`stm.w`/`strd` multi-word stores, and the ARM-mode PLT decoder. All are
bounded, text-adjacent work; nothing needs a second disassembler.
