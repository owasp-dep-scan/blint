# A14 W1 — the JNI close-out: the jna_direct join

One join path added, behind `--disassemble`, plus the fixtures that pin
its boundaries. Host: the reviewer Mac (macOS arm64, darwin 27.0). NDK
r28c (`28.2.13676358`, built the fixtures). nyxstone over Homebrew LLVM
18.1.8 (`/opt/homebrew/opt/llvm@18`); `llvm-readelf`/`llvm-nm` from the
same prefix as the oracles. The fixtures compile against
`net.java.dev.jna:jna` **5.18.1** from Maven Central (sha256
`260c4b1e22b1db9e110ee441c4f13ce115f841fa48c41d78750986214b395557`,
downloaded by `tests/scripts/android/build_a14_jni_fixtures.sh`, never
committed) — the version the corpus apps ship. Gate script
`tests/scripts/android/a14_w1_gate.py`; raw data
`/tmp/a14-w1-gate.json` and the before-tree row dump
`/tmp/a14-w1-before.json` (reproducible: `--dump-rows` from a
`3f17fee` worktree, then the gate on this tree with `--before-rows`).

## What W1 does

A dex declaration no static export and no recovered table answers can
still bind by name through JNA direct mapping, `confirmed_by:
"jna_direct"`, when all of these hold:

1. the declaring class (or a method its `<clinit>` runs) invokes
   `com.sun.jna.Native.register` in the dex — a `Class`-taking overload
   only when its class argument is the caller's own class literal
   (JNA's self-registration idiom; a site registering another class, or
   a class parameter, is evidence for no class);
2. `libjnidispatch.so` ships in that ABI (JNA's dispatch library — no
   dispatch library, no loadable binding);
3. exactly one same-ABI library exports the method name as a defined
   dynamic `FUNC` — the register call's constant library name (at the
   call, or the one constant the invoked helper returns, uniffi's
   `findLibraryName` fallback, followed through `access$` accessors)
   picks the candidate library, JNA mapping `foo` → `libfoo.so`.

Two exporters of the name with no constant to pick one: the row stays
`ambiguous_dynamic` carrying `jna_exporters` (every exporter listed).
The evidence is a dex bytecode walk the default join does not run (it
decodes only `loadLibrary` sites), so it is gated on `--disassemble`
alongside the confirmers; without the flag the join is byte-for-byte
the A13 join. The walk runs only when a dex carries `Native.register`
method-pool entries, and the per-ABI plain-export parse only when the
walk found evidence — every non-JNA app pays one method-pool name scan
and nothing else. `fn_addr` is the symbol's dynsym value in that ABI's
own copy (arm32 values carry the Thumb bit, as the static `bound` rows
always have). W0's census found no other group reachable by the
existing rules — every other unbound mass needs either a weakened
function-start oracle (androidx.graphics.path), an implementation that
is not in the APK (Qt5, netty/jansi), or 64-bit runtime-table modelling
deliberately out of scope (maplibre) — all carried to W2's known-limits
list.

## The corpus, before (3f17fee) and after (this tree)

Full row sets, listing cap lifted, confirmers on, every APK of the
corpus (43 APK/XAPK, 29 with a join; the gate diffed all of them):

| APK | ABI | bound_dynamic before → after | unbound before → after |
|---|---|---|---|
| fennec 1560000 | armeabi-v7a | 112 → 1,507 | 1,431 → 36 |
| fennec 1560010 | x86_64 | 134 → 1,529 | 1,410 → 15 |
| fennec 1560020 | arm64-v8a | 134 → 1,529 | 1,410 → 15 |
| element 40106621 | armeabi-v7a | 245 → 710 | 1,084 → 619 |
| element 40106622 | arm64-v8a | 303 → 768 | 1,027 → 562 |
| element 40106623 | x86 | 302 → 767 | 1,028 → 563 |
| element 40106624 | x86_64 | 303 → 768 | 1,027 → 562 |
| the other 22 join-bearing APKs | every ABI | unchanged | unchanged |

Exactly 6,045 rows moved, all `unbound → bound_dynamic`, every one
labelled `confirmed_by: "jna_direct"` (the gate's `gained_not_jna` list
is empty for every APK); no bound, bound_dynamic or ambiguous row was
lost or changed anywhere. The `plain` (no-flag) join is structurally
identical to A13's — the walk and the export parse never run — and the
gate's plain counts equal the before-tree's on every APK (the only
additive difference is the new `jna_direct: 0` counter). `ambiguous_dynamic`
never moved on any APK or ABI (fennec 1560000's v7a 5 — the A13
review's held-pairing residue — and element's 1-2 per ABI are the
pre-existing rows); no row became ambiguous through jna.

Join wall time (confirm mode, before → after): fennec 8.96 → 15.01s
(the JNA dex walk over three dex files plus the per-ABI plain-export
parse of every library, libxul included), element 8.47 → 9.92s,
RnHello (no JNA anywhere) 5.12 → 5.41s; plain mode unchanged within
noise (fennec 5.49 → 7.41s, element 7.81 → 7.46s, RnHello 1.71 →
1.50s).

## The jna_direct oracle

For every one of the 6,045 `jna_direct` rows: `fn_addr` equals the
`llvm-nm` address of that name in that ABI's library, and that address
is a function start per `llvm-readelf --dyn-syms`/`--syms` FUNCs plus
eh_frame FDEs (`.ARM.exidx` on v7a; arm32 st_values mask the Thumb bit,
x86's odd addresses — the packed 5-6-byte uniffi checksum stubs — are
compared unmasked). **6,045 checked, 0 failures.**

Precision lists: every `jna_direct` row whose declaring class the
independent evidence re-walk found no `Native.register` site for —
**empty**; every bound name exported by more than one library —
**empty** (the register constant names the exporter; the fixture's
decoy twin pins this).

## The fixtures

`tests/scripts/android/build_a14_jni_fixtures.sh` builds, from
`jni_sources/a14_jna` (real javac/d8 against the JNA jar, real NDK r28c
C libraries, no hand-assembled bytes):

- **liba14jna\<abi\>.so** (4 ABIs) exporting the seven plain names;
  **liba14other\<abi\>.so** exporting the decoy pair
  (`a14_ambiguous` — a genuine two-exporter ambiguity — and
  `a14_helper_mul`);
- **a14-jna.apk**: the dex (A14Direct: the constant at the call;
  A14Helper: the helper-fallback constant with the decoy exporter
  beside it; A14ViaInit: the call inside a method the `<clinit>` runs;
  A14Ambiguous: process-library registration, no constant; A14Twin: the
  negative twin, `System.loadLibrary` only; A14Bootstrap +
  A14RegisteredByBootstrap: a cross-class registration) plus both
  libraries and a name-presence `libjnidispatch.so` stub in all four
  ABIs;
- **a14-jna-nodispatch.apk**: the arm64 copies without the stub.

Fifteen new tests in `tests/test_jni.py`: the three register shapes
bind in every ABI with the right library; the constant picks between
the two exporters of `a14_helper_mul`; the two-exporter name stays
ambiguous with both listed; the negative twin and both bootstrap rows
stay unbound; no row binds without the flag; no row binds without
`libjnidispatch.so` in the ABI; the dex walk's evidence shapes; and
every fixture `fn_addr` passes the `llvm-readelf` symbol oracle in its
own ABI.

## The gate block (W1)

- Host: the reviewer Mac (macOS arm64, darwin 27.0.0).
- NDK: r28c (`28.2.13676358`) — the fixture builds.
- nyxstone LLVM: Homebrew LLVM 18.1.8 (`/opt/homebrew/opt/llvm@18`).
- JNA shipped by each APK: 5.18.1 (jnidispatch native revision 7.0.4),
  read from the APK; the fixtures compile against the same version.
- blint @ `cb4f41f` (W0).
- Oracle: 6,045 `jna_direct` rows checked against `llvm-nm` addresses
  and the readelf/objdump function-start sets — 0 failures. Both
  precision lists empty. The corpus row diff (before `3f17fee` vs
  after): 6,045 gained `jna_direct` rows over 7 APKs, 0 rows of any
  other kind moved.
- ruff check, ruff format (the files this packet touches), and flake8
  (CI selection) clean; the full suite green.
