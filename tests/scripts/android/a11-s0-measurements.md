# A11 S0 — the i386 confirmer's inputs, and the tables built at run time

Measure only; no production change. Host: the reviewer Mac (macOS arm64,
darwin 27.0.0). Oracle: `llvm-objdump` / `llvm-readelf` from Homebrew LLVM
18.1.8 (`/opt/homebrew/opt/llvm@18`); nyxstone over the same prefix; the
32-bit registrar arithmetic cross-checked by executing the shipped bytes under
Unicorn 2.1.4 (installed ad hoc for this measurement, not a blint dependency).
Corpus: `~/sandbox/android-corpus` — the 27 APKs of the R3 ladder (26
tier2-fdroid + `com.blint.rnhello_1.apk`). Script:
`tests/scripts/android/a11_s0_measure.py`; raw data: `/tmp/a11/s0-report.json`
(summarized below).

The join with the FindClass confirmer reproduces the A10 counts exactly:
arm64-v8a and x86_64 305/1/26, armeabi-v7a 211/22/99, x86 265/22/45
(bound_dynamic / ambiguous_dynamic / unbound).

## (a) RnHello x86's 22 ambiguous rows: registrar and argument sequence

21 of the 22 rows map to a named registrar chain in `libreactnative.so` (the
exception is `JSCInstance.initHybrid`, which no registrar in any shipped
library names — its registration is the runtime-built table the A10 review
marked `candidates_registered_elsewhere`). Three staging shapes cover them:

| shape | registrars (rows) | count |
|---|---|---|
| `memcpy_from_static` | `CatalystInstanceImpl::registerNatives` (6 rows), `Binding::registerNatives` (BindingImpl), one more | immediate (0x11, 0xe, ...) |
| `sse_copy_static` | `JReactInstance` (5 ReactInstance rows), `WritableNativeArray/Map`, `JEmptyReactNativeConfig`, `StateWrapperImpl`, `EventBeatManager`, both inspector targets | immediate |
| `runtime_built` | `ComponentFactory::registerNatives` (2 rows), `CompositeTurboModuleManagerDelegate`-family | immediate |

One representative per shape, verbatim `llvm-objdump` (AT&T); the pc idiom is
`call .+0; pop %ebx; add %ebx, GOT` (ebx = 0x65dd10 in every
libreactnative.so function).

**memcpy_from_static — `CatalystInstanceImpl::registerNatives()` at 0x52b0b0:**

```asm
   52b0d1:  leal   -0x4b08(%ebx), %eax      # the static merged table (GOTOFF)
   52b0d7:  movl   %eax, 0x4(%esp)          # memcpy src
   52b0db:  leal   0x20(%esp), %esi         # the stack buffer
   52b0df:  movl   %esi, (%esp)             # memcpy dst
   52b0e2:  movl   $0xcc, 0x8(%esp)         # 204 = 17 entries x 12 bytes
   52b0ea:  calll  memcpy@plt
   52b0ef:  movl   %esi, 0x18(%esp)         # {begin = stack buffer}
   52b0f3:  movl   $0x11, 0x1c(%esp)        # {count = 17}
   52b0fb:  movsd  0x18(%esp), %xmm0
   52b101:  movsd  %xmm0, (%esp)            # the 8-byte pair -> outgoing args
   52b106:  calll  HybridClass<CatalystInstanceImpl,...>::registerHybrid@plt
```

**sse_copy_static — `WritableNativeMap::registerNatives()` at 0x5573e0:** the
whole 9-entry table is copied from `.data.rel.ro` by seven
`movups -0xN(%ebx), %xmm0` / `movaps %xmm0, 0xN(%esp)` pairs, then
`leal 0x10(%esp), %eax; movl %eax, 0x8(%esp); movl $0x9, 0xc(%esp); movsd
0x8(%esp),%xmm0; movsd %xmm0,(%esp); calll registerHybrid@plt`. The static
table exists; the join already recovers it.

**runtime_built — `ComponentFactory::registerNatives()` at 0x342520:**

```asm
   34253a:  leal   -0x4619c5(%ebx), %eax    # name string (GOTOFF -> .rodata)
   342540:  movl   %eax, 0x18(%esp)         # entry.name
   342544:  movl   -0x1ef4(%ebx), %eax      # signature (GOT slot -> relocated
   34254a:  movl   %eax, 0x1c(%esp)         #   exported kDescriptor)
   34254e:  movl   -0x1ee4(%ebx), %eax      # fnPtr (GOT slot -> weak fn symbol)
   342554:  movl   %eax, 0x20(%esp)         # entry.fnPtr
   342558:  leal   0x18(%esp), %eax         # methods = &entry
   34255c:  movl   %eax, 0x10(%esp)
   342560:  movl   $0x1, 0x14(%esp)         # count = 1
   342568:  movsd  0x10(%esp), %xmm0 ; movsd %xmm0, (%esp)
   342573:  calll  HybridClass<ComponentFactory,...>::registerHybrid@plt
```

`facebook::jni::ThreadScope::OnLoad()` in `libfbjni.so` (0x17c70) is the
same-function variant: `andl $-0x10, %esp` (realign), `subl $0x30, %esp`,
three `movl %eax, 0x18/0x1c/0x20(%esp)` word stores, then the vtable call
with stored arguments — `movl %edx, 0x8(%esp)` (methods = `leal
0x18(%esp)`), `movl $0x1, 0xc(%esp)` (count), `calll *0x35c(%ecx)`.

**volatile count — the generic `JNI_OnLoad_Weak` at 0x382240:** pushes all
four arguments (`pushl %esi` count, `pushl %edi` methods, `pushl 0x18(%esp)`
clazz, `pushl %eax` env; `calll *0x35c(%ecx)`), with the count computed at
run time (`imull $0xaaaaaaab` — a divide-by-3 over a byte size) — the shape
that must stay ambiguous (a9_split's rt registration).

**The chain callee reads the pair one slot below the cdecl argument area.**
All 37 libreactnative `X::registerNatives()` staging calls pass the 8-byte
{begin, count} pair at the outgoing argument area (`movsd %xmm0, (%esp)` —
callee slots [E+4]/[E+8]). The libreactnative `registerHybrid` copies,
however, read the pair at [E+0]/[E+4] (`call findClassLocal@plt; sub $4,
%esp; leal 0x30(%esp), %edi; movl (%edi),%esi; movl 0x4(%edi),%edi`), which
Executing the shipped bytes under Unicorn confirms: [E+0] holds the return
address and [E+4] the staged begin. `libfbjni.so`'s own
`HybridClass<JNativeRunnable,...>::registerHybrid` (0x163c0) instead reads
`0x8(%ebp)` = [E+4] — the cdecl slot. So the i386 walker must read whatever
slot each callee's own bytes read (no assumed slot); for the libreactnative
copies the methods read yields no constant, and those rows' confirmations
ride the single-class whole-table rule (their registrars memcpy from static
tables the join already recovers), not the precise-range carry.

## (b) Tables built at run time, per ABI and library

Per-ABI totals over the 27 APKs (mechanical classification of every
RegisterNatives vtable call site — last writer of the methods argument —
plus, for the fbjni/reactnative chains, every `registerHybrid@plt` staging
call; the counts below add both):

| ABI | runtime-built registrations | where |
|---|---|---|
| x86 | 28 | libreactnative (21: 6 same-function + 15 staging), libfbjni (4), libhermestooling (2), libjnidispatch (1) |
| x86_64 | 31 | libmaplibre (jni.hpp) — see the caveat below |
| arm64-v8a | >=23 stack-array sites | libmaplibre 23 (`ldr q0,[xN]` bulk entry copies), plus reactnative staging not counted mechanically (its arm64 staging calls carry no @plt annotation) |
| armeabi-v7a | >=55 stack-array sites | libmaplibre 23, libvlc 9, libxul 8, libflutter 6, libreactnative 6, libfbjni 2, libOsmCore 1, others |

Store sequences, per family:

- **fbjni 32-bit / reactnative single-entry (word-materialised, immediate
  count)** — `movl %eax, K(%esp|%ebp)` per word, the value from a GOTOFF
  `leal ±K(%ebx)` (local strings, local fns) or a GOT slot load `movl
  ±K(%ebx)` (exported kDescriptor, weak fn symbols); methods `leal K(%esp)`;
  count `movl $N, 0xc(%esp)` or `pushl $N`. This is the S0 cause-B shape and
  the only one whose every entry word is stored from an address the walk can
  see. 28 registrations on x86; counts are immediates in all of them.
- **jni.hpp (maplibre, every ABI)** — the `jni::RegisterNatives<N>` template
  bulk-copies whole 24-byte entries from referenced entry objects into a
  stack array and passes `mov %rsp/%esp, methods` with an immediate count.
  On i386 the copies ride SSE lanes (`movss/unpcklps/movlhps/shufps` +
  `movaps %xmm0, K(%esp)`; args by `push`), on x86_64 `movups (%r10),%xmm0`
  + `movq` pairs, on arm64 `ldr q0,[x11]`/`str q0,[sp,#K]`. The mechanical
  buckets differ per ABI because the argument formation differs; the shape
  is one. Note: my classifier's x86_64 `runtime_built` bucket for these 31
  sites names the stack stores it saw — hand-reading the windows (above)
  shows bulk copies, not per-word materialisation.
- **reactnative chains (static tables)** — memcpy or SSE copies of a static
  merged table into a stack buffer (6 memcpy + 31 SSE staging sites on x86);
  the static table exists and the join recovers it, so these are not
  cause-B rows.

Counts computed at run time (no immediate beside the methods pointer):
43 sites in libreactnative@x86, 4 in libfbjni@x86, 38 in libmaplibre@arm64,
9 in libmaplibre@v7a — the volatile-count registrations that must stay
ambiguous.

## (c) What S1 and S3 can reach

- **S1 (the i386 model) can carry**: `push`/`pop`, `mov [esp+K]` dword
  stores and loads (including through a register holding a frame symbolic —
  how a callee reads its incoming arguments at the slot its own bytes name),
  `sub/add esp`, the `and esp, -16` realignment (rebased frame, earlier
  esp-keyed slots dropped), `mov esp, ebp` / `mov ebp, esp`, the inline pc
  thunk (`call 0` pushes the next instruction's address; the following `pop`
  yields the GOT base after `add ebx, imm`), GOTOFF `lea` on that base, the
  `movsd` pair staging copies, and pointer words in slots (a pushed/stored
  stack-address marker keeps its identity into a callee's walk). Verified on
  the shipped bytes: `Binding::registerNatives` yields arg slots
  `{("esp",-180), 14}` at the registerHybrid call; `ThreadScope::OnLoad`
  yields methods `("esp",-24)` and count 1 at the vtable call.
- **S3 can recover** the word-materialised runtime tables: the 28 x86
  registrations above (immediate counts, per-word materialised addresses —
  GOT loads resolved beside the model through the ELF relocation maps, the
  same way rip-relative operands resolve on x86_64). Every recovered fnPtr
  still passes the function-start oracle.
- **Out of reach this wave**: jni.hpp's bulk-copied entries (SSE lanes on
  i386/x86_64, q-registers on arm64 — nyxstone text carries no operand
  structure to follow lanes through shuffles); every volatile-count
  registration; all of armeabi-v7a (no arm32 model); the registerHybrid
  precise-range carry for the libreactnative i386 copies (the one-slot-low
  read above) — those rows confirm through the whole-table rule instead.
