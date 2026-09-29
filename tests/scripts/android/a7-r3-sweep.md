# A7 K3 — the R3 sweep report

Host: the reviewer Mac (macOS 27.0 arm64), blint `feat/an-a7` at the K3
commit, NDK r28c `28.2.13676358` (its `llvm-objdump`/`llvm-nm` are the
oracle), nyxstone LLVM 18 (`NYXSTONE_LLVM_PREFIX=/opt/homebrew/opt/llvm@18`).
Runner: `a7_r3_sweep.py` (tier 0 sharded 4 ways, merged by
`a7_r3_merge.py`); the raw `a7-r3-sweep.json` they write is not committed.

Sets: tier 0 = all four system images (api34-arm64-v8a, api35-arm64-v8a,
api36-arm64, api36-arm64-v8a) deduped by sha256 → 3,540 unique `.so`,
each disassembled and credited to every image carrying it. Apps = the 27
tier-2/3 APKs through the production member-review path
(`run_default_mode` with `--disassemble`, reading the exported
`Reviews.json` back). The tier-0 shards ran under the K2 code; the only
rule change since (the arm32 gate) is a no-op on tier 0, which is
arm64-only. The apps sweep ran under the final tree.

## The defect the sweep found, and the fix it forced

The first apps pass reported 15 ANDROID_INLINE_SYSCALLS fires, 14 of them
on armeabi-v7a members — where the reviewer's arm64 census had seen one
site in one library. Hand-reading the members with `llvm-objdump`:

| library (v7a) | plain `svc #0` in llvm-objdump | blint reported |
|---|---|---|
| libflutter (saber 1360101) | 0 | 2 |
| libhermes (rnhello) | 0 | 1 |
| libvlc (VLC 13070105) | 0 | 2 |
| libxul (fennec 1560000) | 1 | 21 |
| libjnidispatch (vector) | 1 | 1 (genuine) |

25 false sites against 2 true. The decoded contexts show why: the `svc
#0` sits *after* the function's terminating instruction (`pop {r7, pc}`,
a tail `b.w`), amid `movs r0, r0` — blint's ARM32 function extents
overrun into the literal pools ARM32 linkers place between functions, and
pool bytes (Thumb `0xDF00` for svc, `0x0000` for `movs r0, r0`) decode as
code. This is an A4-lane disassembler defect, not a rule defect; the rule
now reports `not_evaluated` (`arm32_recovery_unreliable`) on armeabi-v7a
with these numbers in its description, keeping the ABIs whose counts
match the oracle (arm64: bionic libc 228/228, libxul 1/1; x86_64: the
fixture's `syscall`/`int 128`). The measured cost: libjnidispatch's one
genuine v7a site stays unreported.

## R3 table — tier 0 (3,540 libraries, all images, `--disassemble`)

| rule | fires | notes (not evaluated) |
|---|---|---|
| ANDROID_PTRACE_TRACEME | 1 | 34× callsite_block_truncated |
| ANDROID_ROOT_PATH_PROBE | 0 | 34× callsite_block_truncated |
| ANDROID_SU_EXECUTION | 4 | 34× callsite_block_truncated |
| ANDROID_EMULATOR_PROPERTY_PROBE | 0 | 34× callsite_block_truncated |
| ANDROID_WRITABLE_LOCATION_DLOPEN | 0 | 34× callsite_block_truncated |
| ANDROID_INLINE_SYSCALLS | 0 | — |

Median rules fired per library: **0** (3,535 of 3,540 fire nothing). The
34 truncated-block libraries (libart, libbluetooth_jni and the other
>4096-entry images, across the four images) are reported as coverage
facts, not findings.

Every finding, hand-checked:

1. **`_system_lib64/system_lib64_libnix.dylib.so` (api34) —
   ANDROID_PTRACE_TRACEME, TRUE.** The function is
   `nix::sys::ptrace::linux::traceme` at `0x4a2a8` (`llvm-nm -D` names
   the export; this file's section table defeats `llvm-objdump -d`
   outright — `invalid section index: 37` — so the verification is at the
   encoding level: word[1] at the function start is `0x2a1f03e0`, `mov
   w0, wzr` i.e. request register zeroed, and the `bl` at word[5]
   (`0x94004d59`) targets `0x5d820`, which the PLT decoder resolves to
   `ptrace` through the JUMP_SLOT relocations). The library is the Rust
   `nix` crate's Android build, which *provides* a traceme wrapper as
   part of its ptrace API; whether any app calls it for anti-debug is
   the reviewer's call. The shape is exactly what the rule claims.
2. **4× `libdumpstateutil.so` — ANDROID_SU_EXECUTION, TRUE, expected.**
   The same library in four carriers (api36-arm64, api36-arm64-v8a,
   api34 apex, api34 vndk.v34): `/system/xbin/su` reaches
   `std::string::append(char const*)` argument 1 inside
   `android::os::dumpstate::RunCommandToFd`, hand-verified in R2 with
   `llvm-objdump` (the `.rodata` literal at `0x25d4`, the `adrp/add`
   into the append, `execvp@plt` receiving a register). Platform code is
   reported like any other, at the documented weight — the prompt's
   decision point, answered in the rule file.

Zero false findings on tier 0.

## R3 table — tiers 2+3 (the tier-2/3 APKs through the member review path)

25 of the 27 APKs ran to completion under the final tree (sharded 5 ways;
wall 6,210 s for the longest shard). The two stragglers —
`com.adilhanney.saber_1360101.apk` and `org.localsend.localsend_app_642.apk`
— are armeabi-v7a-only Flutter builds whose 18 MB stripped ARM32 Dart
snapshots take ~2 h each to disassemble; the pre-gate pass completed
saber_1360101 (7,512 s) and its only new-rule findings were the 2
libflutter v7a inline-syscall sites the arm32 gate now reclassifies to
`not_evaluated` notes — and under the final code no v7a member can fire
any of the six rules, since the five call-site rules cannot evaluate on
that ABI and the inline-syscall rule is gated on it. Their verdicts are
therefore determined by construction; they are the one hole in the
re-run, recorded here rather than papered over.

| rule | fires | notes (not evaluated, member-units) |
|---|---|---|
| ANDROID_PTRACE_TRACEME | 0 | 116× abi_not_modelled, 34× callsite_block_truncated |
| ANDROID_ROOT_PATH_PROBE | 0 | 116× abi_not_modelled, 34× callsite_block_truncated |
| ANDROID_SU_EXECUTION | 0 | 116× abi_not_modelled, 34× callsite_block_truncated |
| ANDROID_EMULATOR_PROPERTY_PROBE | 0 | 116× abi_not_modelled, 34× callsite_block_truncated |
| ANDROID_WRITABLE_LOCATION_DLOPEN | 0 | 116× abi_not_modelled, 34× callsite_block_truncated |
| ANDROID_INLINE_SYSCALLS | **1** | 66× arm32_recovery_unreliable |
| ANDROID_DEX_SU_PATHS_TO_NATIVE | 0 | — |

Every new-rule finding (the one fire), hand-checked:

- **`org.mozilla.fennec_fdroid_1560020.apk!lib/arm64-v8a/libxul.so` —
  ANDROID_INLINE_SYSCALLS, TRUE.** One site, `sub_6635430` at
  `0x6635430`: syscall 135 (`rt_sigprocmask`) with `how=SIG_BLOCK` and an
  empty set — the signal-safety stub, hand-read in K0 and named in the
  rule description as the benign shape. Reported at low severity with
  the function named, as designed.

The pre-existing dex rules (ANDROID_REFLECTION, ANDROID_WEAK_CRYPTO, …)
fired as they always do; they are not this packet's and are excluded
from the table above.

The R1 fixtures fired through the same production path on every ABI they
evaluate (arm64-v8a and x86_64: all six fire on `liba7fire.so`,
`liba7nofire.so` and `libtoolChecker.so` silent; armeabi-v7a: six
not_evaluated notes — five `abi_not_modelled`, one
`arm32_recovery_unreliable` — and the dex rule still fires; recorded in
the K3 commit).

## Gates

- **Zero false findings**: tier 0 5/5 true; apps 1/1 true (the 14 v7a
  misdecode fires were removed by the gate, not shipped).
- **Tier-0 median findings per library**: 0 at K0 (no disassembly), 0 at
  K3 with `--disassemble` (3,535/3,540 silent; the 5 fires are the
  justified true positives). The K3 no-disassembly baseline re-run
  (`a7-k3-baseline.json`) is identical to K0's per-rule table — the rules
  add no noise to default runs.
- **R1 fire/no-fire on every ABI the rules evaluate**: green — arm64-v8a
  and x86_64 fire all six on the fire fixture with the benign twin and
  RootBeer silent; armeabi-v7a reports six not_evaluated notes and no
  fires.
- **Full suite, serially**: 2039 passed, 101 skipped, 0 failed
  (44:08 on this host, LLVM 18 for nyxstone); flake8
  `E9,F63,F7,F82` count 0 and ruff clean on the final tree.

## Review update

The "notes (not evaluated)" columns above describe the K3 tree, where a rule
that could not evaluate returned a placeholder row. Those rows reached the
capability review table under the rule's own summary (19 on the armeabi-v7a
fixture APK), so the review moved the facts to the library's
`analysis_coverage.degradations` (`callsite_abi_not_modelled`,
`callsite_entries_truncated`) and the rules now return nothing there. The
fires listed above are unchanged: libdumpstateutil and libnix were re-run
under the review tree with the same findings.
