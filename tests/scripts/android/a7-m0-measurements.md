# A7.2 M0 — the measurement, before any code changes

Host: the reviewer Mac (macOS 27.0 arm64), blint `feat/an-a7-2` at the M0
commit (branch point `cee6203`), NDK r28c `28.2.13676358`, nyxstone LLVM 18
(`NYXSTONE_LLVM_PREFIX=/opt/homebrew/opt/llvm@18`). Runners:
`a7_2_m0_measure.py` (counts a-c over the corpus, per-file JSON not
committed), `a7_2_m0_arm32_extent.py` (count d against the NDK
llvm-objdump, `--triple=thumbv7a-none-linux-androideabi`). Nothing in this
packet changes blint/ code.

## Inputs

- apps: every `lib/*/ *.so` member of the 27 tier-2/3 APKs (282 libraries,
  1.58 GB), extracted;
- tier1-ndk r27 + r28 (arm64-v8a, x86_64, x86, armeabi-v7a);
- the committed A7 fixtures at -O2 plus the new -Os/-Oz twins (same build
  script, same NDK; the -O2 rebuild is byte-identical to the committed
  binaries);
- the wasm-tools-1.247.0 x86_64/i686 ELF binaries (linux-gnu, linux-android)
  and the x86_64 Mach-O one, for the M1 scope question;
- count (d): the five stripped v7a carriers of the R3 hand-check
  (libflutter saber_1360101, libhermes rnhello, libvlc 13070105,
  libxul fennec_1560000, libjnidispatch vector_40106621).

## (a) last-line `jmp imm` on x86/x86_64

Instrument: for every disassembled function whose last instruction is a
`jmp` with an immediate operand (no register, no `[..]` slot), compute the
end-relative reading (`instr.address + len + imm`, M1's rule) and the
absolute reading (today's ELF behavior), and look each up in the PLT stub
map and the function symbol map. A site the disassembler already resolved
(tailcall entry with a real name — not the operand echoed back, which is
its placeholder for an unresolved numeric target) is counted separately.
Measured with the wave's working tree (M1 applied): the delta-only count
below is therefore a floor for M1's recovery, and the categories
absolute-only / neither are tree-independent.

| population | last-line `jmp imm` | delta names (only) | absolute only | already resolved | neither |
|---|---|---|---|---|---|
| apps + tier1-ndk + fixtures (all x86/x86_64 inputs, 192 files) | 193,538 | 106,399 | **0** | 3,573 | 83,566 |
| liba7_fire_x86_64_Oz.so | 5 | 5 | 0 | 0 | 0 |
| liba7_fire_x86_64_Os.so | 5 | 5 | 0 | 0 | 0 |
| wasm-tools x86_64-linux-gnu | 5,044 | 1,684 | 0 | 3 | 3,357 |
| wasm-tools x86_64-apple-macosx (Mach-O) | 5,974 | 0 | 0 | 0 | 5,974 |

Readings: no input anywhere names a callee through the absolute reading
that the end-relative reading does not — **0 absolute-only sites**, so M1
drops the absolute fallback for ELF tail jumps entirely (the same treatment
Windows jmps already had). The neither bucket holds backward jumps (loop
tails, not calls) and targets no table names (stripped images), neither of
which M1 claims. The Mach-O binary resolves nothing under either reading
(it is stripped; no PLT map), so leaving Mach-O out of M1's scope costs
nothing on the one Mach-O input measured.

## (b) pure thunks

Definition (M2's): a local function of at most 4 register-move /
constant-load instructions (arm64 `mov`/`movz`/`movk`/`fmov`/`nop` plus the
`adrp+add` address-constant pair; x86 `mov`/`nop`) followed by one
unconditional tail branch to a named callee whose target lies outside the
function. The shape has a single path by construction. Counted under M1's
resolution (that is what names an x86 thunk's PLT callee).

| population | files with thunks | thunks | named OUTLINED_FUNCTION_* | sites into thunks (arg-writing) |
|---|---|---|---|---|
| apps + tier1-ndk + fixtures | 121 | 30,413 | 1,490 | 90,444 (77,409) |
| liba7_fire_arm64-v8a_Oz.so | 1 | 1 | 1 | 3 (3) |
| libQt5Core.so (arm64, net.osmand.plus_540403) | 1 | 1,870 | 1,463 | — |
| wasm-tools aarch64-linux-gnu | 1 | 347 | 25 | 695 (695) |
| liba7_fire_arm64-v8a_Os.so / -O2 | 0 | 0 | 0 | 0 |

The arm64 -Oz outliner thunk is `OUTLINED_FUNCTION_0: mov w1, #2; b #408`
(to dlopen@plt); its three caller sites are a7_writable_dlopen's `bl #228`
/ `bl #208` / `bl #188`. `-O2 must not change` (M2's gate) holds by
construction: no -O2 build produces a thunk. The named outlined population
is one library — the Qt app's libQt5Core (unstripped symtab keeps the
outliner's names); everywhere else thunks live behind stripped sub_ names,
which the address-keyed map treats identically.

## (c) path-probe calls loading from a `.data.rel.ro` table

Instrument: for every resolved direct call to access/stat/lstat/fopen/open,
trace the path register backwards (arm64 x0 through `ldr xN, [base, ..]`
from an `adr`/`adrp+add` materialisation; x86-64 rdi through
`mov rdi, [base + idx]` from a `lea rip` materialisation); the site counts
when the table base lands in `.data.rel.ro`. The table's strings are read
through the RELATIVE-relocation addends (the in-file words are zero).

| input | sites | table strings |
|---|---|---|
| liba7_fire_arm64-v8a_Os.so | 3 (access, stat, fopen) | the 6 su paths |
| liba7_fire_arm64-v8a_Oz.so | 3 (access, stat, fopen) | the 6 su paths |
| liba7_fire_x86_64_Os.so | 3 (access, stat, fopen) | the 6 su paths |
| liba7_fire_x86_64_Oz.so | 3 (access, stat, fopen) | the 6 su paths |
| liba7_fire_*_-O2 (all) | 0 | — (paths inlined as constants) |
| **the whole corpus beside the fixtures** | **0** | — |

This is the out-of-scope `-Os`/`-Oz` root-probe shape: no constant reaches
the call, so ANDROID_ROOT_PATH_PROBE cannot fire on it at any optimization
the compiler does not unroll. The corpus count is zero outside the fixtures
— no app or tier-1 library loads a probe path from a `.data.rel.ro` table
at all — which ranks the su-table structural rule behind every candidate
that has corpus carriers (M3's ranked proposal carries the number).

Tier-0 (arm64 system images, 3,540 libraries, all four images deduped by
sha256) was measured after M3's code landed, on the same instrument:
34,362 pure thunks across 1,945 libraries (69,575 resolved call sites enter
one, 68,291 through an argument-writing thunk; none is named
OUTLINED_FUNCTION_* — the system images are stripped), zero
`.data.rel.ro`-loaded probe paths, and by architecture zero x86 tail jumps
(the images are arm64-only). The corpus-wide conclusions above hold: M2's
thunk population is real everywhere, and the su-table rule has no carrier
in any measured population.

## (d) the ARM32 extent overrun, per library

Oracle: `llvm-objdump -d --triple=thumbv7a-none-linux-androideabi` (the
default linear decode of these stripped libraries reads the Thumb code in
ARM state — condition-coded `svclt`/`stmdals` garbage and 4-byte spacing —
so the triple is forced; NDK r28c). Per svc site objdump reports: the
exidx interval [F, N) that contains it (F = blint's function start from
`.ARM.exidx` PREL31, N = the next row = where blint's extent ends today),
the first function-leaving terminator in [F, N) (`pop {…, pc}`, `bx lr`,
`bx rN`, `ldr pc, …`, or a `b`/`b.w` whose target leaves the interval), and
the pool gap N − terminator end.

| library | exidx functions | objdump svc sites | imm-0 | terminator-preceding | overrun intervals | pool gap median / max (B) |
|---|---|---|---|---|---|---|
| libjnidispatch | 172 | 1 | 1 | 0 | 97 / 172 | 44 / 11,960 |
| libhermes | 5,318 | 759 | 0 | 214 | 1,590 / 5,318 | 52 / 23,276 |
| libflutter | 23,429 | 6,806 | 0 | 2,852 | 5,814 / 23,429 | 68 / 46,252 |
| libvlc | 45,221 | 38,034 | 0 | 27,037 | 18,300 / 45,221 | 84 / 196,780 |
| libxul | 210,640 | 110,284 | 1 | 89,675 | 70,633 / 210,640 | 136 / 249,632 |

Readings:

- The immediate-0 filter reproduces the R3 hand-check's oracle exactly:
  the only plain `svc #0` sites are libjnidispatch's one genuine site
  (`0x160e8`, real code mid-function, no terminator before it) and
  libxul's one genuine site. Every other svc decode carries a nonzero
  immediate — literal-pool bytes. 2 true, 0 false is the target M3 must
  reach.
- A quarter to half of every library's exidx intervals carry bytes after
  their first terminator (the pools), with median gaps of 44-136 bytes —
  pool-sized. The large maxima are the intervals where the first
  terminator is an early return inside a real function, which is why M3's
  cut must be "stop where the pool starts" (no branch of the function's
  own code targets the region past the cut), never "cut at the first
  terminator".

## The flag-variant fixtures (R1)

`build_a7_fixtures.sh` now also builds `liba7_{fire,nofire}_{arm64-v8a,
x86_64}_{Os,Oz}.so` plus stripped twins (same compilers, `-Os`/`-Oz` for
`-O2`). Measured on the M0 tree (no M1/M2 fixes): arm64 -Os fires 5 rules
(root probe silent), arm64 -Oz fires 4 (root probe and writable-dlopen
silent — `OUTLINED_FUNCTION_0` carries the dlopen flags), x86_64 -Os fires
5, x86_64 -Oz fires 4 (ptrace silent — `a7_anti_debug` is a tail
`jmp 917` into the PLT that the ELF resolver reads absolute). Every
nofire variant stays silent. The manifest's `expected.flag_variants` table
records these rows; M1 and M2 flip the two cells their fixes recover.

## Review addendum

Measured on the reviewer Mac with the same NDK and nyxstone LLVM, against
`49c7ea8` and the review tree.

- **(a), Mach-O.** The claim above that the Mach-O binary resolves nothing
  under either reading was wrong. With the end-relative reading, wasm-tools
  x86_64-apple-macosx resolves 4,010 more tail calls: tailcall internal
  edges go from 2,066 to 6,076, `symbol_only_miss:tailcall` from 4,032 to 1,
  and 21 tail jumps into imports appear. Three sampled edges match
  `llvm-objdump`. The reading now applies to every format, and that
  baseline entry is refreshed.
- **(b), the replay.** M2's textual replay of a thunk's prep lines is
  replaced by the absint model's own `step` over a copy of the caller's
  state. The replay overwrote a `movk` or shifted `movz` with its bare
  immediate, and left the caller's register standing under a lone `adrp`
  (libQt5Core's `QAnimationDriver::started()`: `adrp x1, #2555904;
  mov w2, wzr; b OUTLINED_FUNCTION_43`).
- **(d), the pool filter.** M3's filter is removed. On NDK r28c builds of
  `a7_sources/a7_guarded_svc.c` (a real `svc #0` behind a conditional
  `bxeq lr`), it dropped both genuine sites at every flag in ARM state and
  at `-O2` in Thumb, stripped or not: its fallthrough walk treated a
  conditional return as a terminator. The r7 syscall-number requirement
  gives the verdicts instead: an immediate or `ldr r7, [pc, ...]` load
  within eight instructions of the svc, with no zero decode
  (`movs r0, r0`, `andeq r0, r0, r0`) or unconditional transfer between
  them.

  | population | raw `svc #0` decodes, filter / none | r7 sites, no filter |
  |---|---|---|
  | 70 v7a libraries of the tier-2/3 apps | 6 / 19 | 3, all `__clear_cache` (libjnidispatch x2, libQt5Core) |
  | fennec v7a libxul | not run / 21 | 1, `sub_52e6dac` (`__ARM_NR_cacheflush`) |

  Without the zero-decode break, libxul's `sub_60799f0` (a table of small
  words decoding as `ldr r7, [pc, #512]; movs r0, r0; svc #0`) was a false
  site. Disassembly time over the 70 is 4,436 s with the filter and 4,086 s
  without it, so the filter did not speed up ARM32 disassembly; libxul takes
  3,173 s without it.
