# ELF memory-safety fixtures

Every binary here is built from `probe.c` (`small.c` for the small-frame
variant) by `build.sh`, so each pair differs only in the flag its name
names. `tests/test_elf_memory_safety.py` reads exactly these files.

## Rebuilding

`build.sh` runs inside an Ubuntu 24.04 container and detects its platform.
On an Apple Silicon Mac with Docker (OrbStack runs amd64 through Rosetta):

```sh
docker run --rm --platform linux/amd64 -v "$PWD:/work" -w /work ubuntu:24.04 \
    sh -c "apt-get update -qq && apt-get install -y -qq gcc gcc-multilib clang binutils && ./build.sh"
docker run --rm --platform linux/arm64 -v "$PWD:/work" -w /work ubuntu:24.04 \
    sh -c "apt-get update -qq && apt-get install -y -qq gcc clang binutils && ./build.sh"
```

The `musl/` pair is cross-built on the host (any platform) with zig:

```sh
zig cc -target x86_64-linux-musl -O2 -o musl/x86_64-musl-plain probe.c
zig cc -target aarch64-linux-musl -O2 -o musl/aarch64-musl-plain probe.c
```

(zig cannot link ASan for these musl targets, so musl stays un-sanitized.)

Before committing, the large builds are trimmed with
`llvm-strip --strip-debug`, which removes debug sections and keeps the
symbol tables the facts read; rerun it on anything over ~100 KB.

## What the variants show

Ubuntu 24.04's gcc enables several hardening flags by default, which is why
`gcc-plain` passes the `-fno-`/`-U` forms explicitly and the "on" builds
pass the enabling form: both sides of every pair are pinned regardless of
distro defaults.

| fixture | expected facts |
| --- | --- |
| `gcc-plain` | no sanitizers, no CET, no fortify, stack clash unprotected (disassembly) |
| `gcc-asan` / `gcc-tsan` / `gcc-ubsan` | the matching sanitizer in `memory_safety.sanitizers` |
| `clang-msan` (x86_64) | msan; `clang-hwasan` (aarch64) hwasan |
| `gcc-static-asan` | asan via `.symtab` (runtime linked into the image) |
| `clang-ubsan-trap` | no sanitizer symbols at all: the documented "cannot tell" case |
| `clang-cfi` vs `clang-cfi-none` | `cfi: true` via the `.cfi` jump-table symbols (`__cfi_check` is cross-DSO only) |
| `gcc-cet-full` vs `gcc-cet-none` | x86 IBT+SHSTK present vs absent (the note itself stays in the `none` build, without the feature bits) |
| `gcc-cet-full-32` | ELF32 with no property note at all: Ubuntu's i386 toolchain emits none, so CET is genuinely unmarked |
| `gcc-stack-clash-on` vs `gcc-stack-clash-off` | probes found vs page-crossing frames with no probes |
| `gcc-small-only` | no page-crossing frame: stack clash "not determined" even though the flag was on |
| `gcc-fortify0/2/3` | fortify level 0 / 2 / 3 (level 3 via `__memcpy_chk`, which needs the runtime object sizes) |
| `gcc-static-fortify3` | level 3 read from `.symtab`, no dynamic imports |
| `musl/*-plain` | nothing fortified (musl has no `_FORTIFY_SOURCE`), fortify level not determined (static, no imports to check) |
