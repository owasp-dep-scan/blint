# A7 K0 — the native capability-signal census (measure only)

Host: the reviewer Mac (macOS 27.0 arm64), blint `main` @ `f633396` (branch
`feat/an-a7`, K0 commit), NDK r28c `28.2.13676358`, LLVM 18 for nyxstone at
`/opt/homebrew/opt/llvm@18` (`NYXSTONE_LLVM_PREFIX`).
Script: `a7_k0_census.py` (same directory); raw JSON: `a7-k0-census.json`,
`a7-k0-carriers.json`, `a7-k0-baseline.json`, `a7-k0-svc.json`.
Sets: tier-0 = the api36-arm64-v8a system image deduped by sha256 (1,157 —
the reviewer's own file count), apps = every unique arm64 `.so` extracted
from the tier-2/3 APKs (73).

Nothing under `blint/` changed in this packet. Every number below came out
of `parse()` metadata — the reviewer's `llvm-nm` numbers ride beside them.

## 1. The census through blint's metadata

Import signals reproduce the reviewer exactly; string signals do not,
because the extractor's gates drop them (section 2).

| signal | app (blint) | app (reviewer) | tier-0 (blint) | tier-0 (reviewer) |
|---|---|---|---|---|
| `ptrace` import | 1 | 1 | 6 | 6 |
| `__system_property_*` import | 44 | 44 | 475 | 475 |
| `dlopen`/`android_dlopen_ext` import | 20 | 20 | 82 | 82 |
| `/proc/…/maps` string (gated) | 7 | 7 (raw) | 24 | 25 (raw) |
| `/proc/self/status` + `TracerPid` (gated) | 0 | 0 (raw) | 0 | 2 (raw) |
| su path string (gated) | 0 | 0 (raw) | 0 | 2 (raw) |
| `/data/local/tmp` string (gated) | 0 | 9 (raw) | 2 | 22 (raw) |
| emulator token (gated) | 0 | 2 (raw) | 11* | 0 (raw) |
| "frida" substring (gated) | 0 | 13 (raw) | 0 | 6 (raw) |

\* all inside kept strings that name emulator *system components*
(`init.goldfish.rc`, `…-impl.ranchu.so`, `libcodec2_goldfish_*`) — the
census's raw scan of standalone tokens found none; the blint side sees the
tokens only as filename fragments. Neither form is a fingerprint signal.

**Which import names reach the review lists:** an Android `.so` has an
empty `metadata["imports"]` — its imports ride `dynamic_symbols` with
`is_imported`, which `_review_symbols_exe` feeds to SYMBOL_REVIEWS and
EXE_REVIEWS. IMPORT_REVIEWS never sees an ELF's imports. `ptrace`,
`__system_property_get` and `dlopen` therefore do reach the pattern-review
machinery (via the symbols list), which is why the single-signal form of
these families is measurable at all — and why measurement 1 rules it out.

## 2. The strings the extractor drops

Raw side = blint's own pre-gate extractor (`binary_strings`); kept side =
`metadata["strings"]`, the list every string-based review reads.

| probe | tier-0 raw / kept | app raw / kept | verdict |
|---|---|---|---|
| `/proc/self/maps`, `/proc/%d/maps` | 25 / 24 | 8 / 7 | kept (review-relevant `^/proc/` shape) |
| `/proc/self/status` | 3 / 3 | 0 / 0 | kept |
| `TracerPid` | present raw beside the status opens | — | **lost** (short plain word) |
| su paths (`/system/xbin/su` …) | 2 / 0 | 0 / 0 | **lost** |
| `/data/local/tmp` | 24 / 2 | 9 / 0 | **lost** (the 2 kept tier-0 hits sit inside a >80-char Rust mega-string) |
| `ro.kernel.qemu`, `ro.hardware`, `ro.build.version.sdk` | 90 / 0 | 6 / 0 | **lost** |
| `goldfish` / `ranchu` tokens | 18 / (filenames only) | 2 / 0 | **lost** as standalone strings |
| `/system/bin/sh` | 2 / 0 | — | **lost** |
| "frida" substrings | 5 / 0 | 10 / 0 | dropped — and all false anyway ("Friday", "gMainThread", "Maintenance") |

So a string-side rule for su paths, writable-path loads, emulator
properties or shell execution sees nothing at all on this corpus; the
call-site constant layer (which resolves pointers straight out of the
image, never through the gated strings list) is the only view, exactly as
the ladder assumed.

## 3. What `CALL_SITE_CONSTANT_ARGUMENTS` recovers on the benign carriers (before K2)

Measured on `main` behavior (the runs predate the K2 working-tree changes;
the process had imported the modules before any edit landed):

| carrier | wall time (`--disassemble`) | functions | block entries | strings resolved | rule-relevant callees recovered |
|---|---|---|---|---|---|
| libc.so | 8.3 s | 2,467 | 1,400 | 495 | **none** |
| libunwindstack.so | 5.8 s | 1,361 | 165 | 20 | **none** |
| libmemunreachable.so | 1.7 s | 491 | 163 | 0 | **none** |
| libc_malloc_debug.so | 4.0 s | 1,215 | 433 | 0 | **none** |
| libfdtrack.so | 4.3 s | 920 | 310 | 0 | **none** |
| libart.so | 89.4 s | 16,066 | 4,096 (truncated) | 2,583 | **none** |
| libbluetooth_jni.so | 115.8 s | 21,776 | 4,096 (truncated) | 1,543 | **none** |
| libchrome.so | 5.9 s | 3,197 | 183 | 62 | **none** |
| libdumpstateutil.so | 0.3 s | 45 | 15 | 0 | **none** |
| libclang_rt.asan.so | 7.8 s | 2,510 | 2,452 | 1,048 | **none** |
| libclang_rt.hwasan.so | (svc run) | — | — | — | **none** |
| libclang_rt.ubsan.so | 1.2 s | 542 | 820 | 0 | **none** |
| libsentry.so | 4.8 s | 1,767 | 511 | 211 | **none** |
| libjnidispatch.so | 0.8 s | 174 | 97 | 69 | **none** |
| libmozglue.so | 8.5 s | 2,857 | 568 | 136 | **none** |
| libxul.so | 1,349.9 s | 270,662 | 4,096 (truncated) | 1,214 | **none** |
| libvlc.so | 312.6 s | 56,668 | 4,096 (truncated) | 2,388 | **none** |
| libflutter.so | 88.0 s | 44,921 | 4,096 (truncated) | 1,038 | **none** |

"Rule-relevant callees" = `ptrace`, `open`/`fopen`, `access`/`stat`,
`execve`/`execl*`/`popen`/`system`, `__system_property_get`,
`dlopen`/`android_dlopen_ext`. **Zero recovered constants at any of them,
on any carrier** — the entries these libraries do have are internal
(statically linked) callees. Two causes, both fixed in K2 and both
measured here first:

1. **PLT stubs are unnamed.** An arm64 `.so` calls its imports through
   `.plt` stubs; the address→name map carried only GOT-slot addresses
   from the JUMP_SLOT relocations, so `bl <plt>` resolved to no callee
   and the site contributed `records_unresolved_callee` (21 in the fire
   fixture built in K1) instead of an entry. The x86_64 direct
   `call <plt>` form has the same gap.
2. **Resolved strings were floored at 0x10000.** The pointer→string
   resolver rejected constants below 64 KiB — a PE-shaped floor (a PE's
   constants live above its image base). An Android `.so` keeps `.rodata`
   near 0x9b0, so even a resolved pointer never decoded as a string.

A third, subtler one surfaced while building the K1 fixtures: nyxstone
renders ARM branch targets pc-relative (`bl #1280`), and the call-site
recovery keyed callee resolution by operand text, so two sites sharing an
offset text (access and stat in the same loop) were refused as ambiguous.
K2 records the emitting instruction's site index and resolves by site.

The 4,096-entry cap truncates the block on libart, libbluetooth_jni,
libflutter, libvlc and libxul (`entries_truncated`): on those libraries
an absence in the block does not prove absence in the binary, so the K2
rules report `not_evaluated` (`callsite_block_truncated`) rather than a
silent no-fire.

## 4. The baseline: what the existing review rules report today

ReviewRunner over every tier-0 library and every app library (no
disassembly — the review path's default state):

- tier-0: 1,157 libraries, **median 0 rules fired**, mean 0.347, 822
  libraries with zero findings.
- apps: 73 libraries, median 1, mean 0.781, 34 with zero findings.

Per rule id (libraries firing):

| rule | tier-0 | apps |
|---|---|---|
| FORTIFIED_LIBC_IN_USE | 293 | 30 |
| LOADER_SYMBOLS | 38 | 15 |
| PII_READ | 14 | 7 |
| FILE_IO_WRITE | 24 | 0 |
| FILE_IO_READ | 11 | 0 |
| FFI_METHODS | 8 | 0 |
| NET_METHODS | 5 | 0 |
| EBPF_SOCK_OPS_CLUSTER | 2 | 1 |
| DOH_BYPASS_CLUSTER | 2 | 1 |
| HTTP_METHODS | 2 | 1 |
| WEB_SOCKET_API | 1 | 2 |
| WEAK_CRYPTO | 1 | 0 |
| RAW_NET_ACCESS | 0 | 1 |

`--disassemble` wall-time sample (the K3 gate's comparison point):
libunwindstack 5.1 s, libc 8.4 s, libflutter 86.5 s (plain parses:
0.08 s / 0.22 s / 1.5 s).

## 5. The `svc` carriers

Site counts and holder functions, from the disassembly text:

- **bionic libc.so: 228 sites in 225 functions** — the syscall wrappers
  themselves (`syscall`, `vfork`, `__bionic_clone`, `abort`,
  `fdsan_error`, …). Excluded from the K2 rule by SONAME.
- **libclang_rt.asan: 43 / hwasan: 42 / ubsan_standalone: 25 sites** —
  the sanitizers' `internal_*` raw-syscall layer
  (`internal_mmap`, `internal_mprotect`, `internal_sigprocmask`, …).
  Excluded by name.
- **libxul.so: the one app-library site** — `sub_6635430` at `0x6635430`
  (stripped; `a7-k0-svc.json` carries the context). The site issues
  syscall 135 (`rt_sigprocmask`) with `how=SIG_BLOCK`, an empty input
  set and an 8-byte output buffer — a signal-mask query, the
  async-signal-safe shape a signal/crash subsystem uses to inspect or
  block mask state without entering libc. The reviewer's guess was
  "linux_syscall_support-style crash-handler code"; the syscall number
  *corrects* the detail — it is a sigmask call, not an LSS-style
  `/proc/self/maps` read, though it is the same benign family: a single
  signal-safety syscall, no memory protection or file activity. The K2
  rule's exclusion list does not cover it (libxul is none of libc, a
  sanitizer runtime or Go), so it is the rule's one expected tier-2/3
  review hit — by design, at low severity, functions named.

Numbers match the reviewer's census exactly (228; 25–43 across the three
runtimes; one libxul site).
