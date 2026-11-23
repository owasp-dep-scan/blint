#!/bin/sh
# Builds the ELF memory-safety fixtures from probe.c. Run inside the matching
# Ubuntu 24.04 container (see README.md for the docker invocations); the
# script detects its platform and writes into the arch directory it belongs to.
#
# Ubuntu's gcc enables several hardening flags by default, so every variant
# pins its option explicitly on or off: the "off" builds pass the -fno-/-U
# forms and the "on" builds pass the enabling form, which keeps the pair
# comparable on any distro that changes its defaults.
set -eu

case "$(uname -m)" in
    x86_64) arch=x86_64 ;;
    aarch64) arch=aarch64 ;;
    *) echo "unexpected platform $(uname -m)"; exit 1 ;;
esac
outdir="$(dirname "$0")/$arch"
src="$(dirname "$0")/probe.c"
small_src="$(dirname "$0")/small.c"
mkdir -p "$outdir"

CC_GCC="${CC_GCC:-gcc}"
CC_CLANG="${CC_CLANG:-clang}"
have_clang=0
command -v "$CC_CLANG" >/dev/null 2>&1 && have_clang=1

build() {
    tag=$1; shift
    out="$outdir/$tag"
    "$@" -o "$out" "$src"
    echo "built $out"
}

# Baseline: every hardening flag the toolchain defaults to are turned off so
# the memory-safety facts read empty and the "on" builds differ from this.
build gcc-plain $CC_GCC -O2 -fno-stack-protector -fno-stack-clash-protection \
    -fcf-protection=none -U_FORTIFY_SOURCE

# Sanitizer variants (gcc links asan/ubsan/tsan runtimes dynamically; clang
# links them statically, which exercises the .symtab evidence path).
build gcc-asan $CC_GCC -O2 -fsanitize=address
build gcc-ubsan $CC_GCC -O2 -fsanitize=undefined
build gcc-tsan $CC_GCC -O2 -fsanitize=thread

# CET: the GNU_PROPERTY_X86_FEATURE_1_AND note with IBT and SHSTK.
if [ "$arch" = x86_64 ]; then
    build gcc-cet-full $CC_GCC -O2 -fcf-protection=full
    build gcc-cet-none $CC_GCC -O2 -fcf-protection=none
fi

# Stack-clash protection: identical sources, opposite flags, both compilers
# (their probing loops differ enough that both belong in the matrix).
build gcc-stack-clash-on $CC_GCC -O2 -fstack-clash-protection
build gcc-stack-clash-off $CC_GCC -O2 -fno-stack-clash-protection

# No page-crossing frame anywhere: the one build where stack-clash
# protection cannot be told from its absence (small.c has no large_frame).
$CC_GCC -O2 -fstack-clash-protection -o "$outdir/gcc-small-only" "$small_src" \
    && echo "built $outdir/gcc-small-only"

# frame.c: a frame that is not a multiple of the page (GCC on AArch64 loads
# it into a register before the sub) and zero stores at the stack top that
# are not probes.
frame_src="$(dirname "$0")/frame.c"
$CC_GCC -O2 -fstack-clash-protection -o "$outdir/gcc-frame-on" "$frame_src" && echo "built $outdir/gcc-frame-on"
$CC_GCC -O2 -fno-stack-clash-protection -o "$outdir/gcc-frame-off" "$frame_src" && echo "built $outdir/gcc-frame-off"
if [ "$have_clang" = 1 ]; then
    $CC_CLANG -O2 -fstack-clash-protection -o "$outdir/clang-frame-on" "$frame_src" && echo "built $outdir/clang-frame-on"
    $CC_CLANG -O2 -fno-stack-clash-protection -o "$outdir/clang-frame-off" "$frame_src" && echo "built $outdir/clang-frame-off"
fi

# sized.c at level 2 imports __memcpy_chk and __memset_chk, which is why
# the wrapper names cannot tell level 2 from level 3.
if [ "$arch" = x86_64 ]; then
    $CC_GCC -O2 -D_FORTIFY_SOURCE=2 -o "$outdir/gcc-fortify2-sized" "$(dirname "$0")/sized.c" \
        && echo "built $outdir/gcc-fortify2-sized"
fi

# FORTIFY levels (levels 2 and 3 need an optimizing compiler to fire).
build gcc-fortify0 $CC_GCC -O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0
build gcc-fortify2 $CC_GCC -O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
build gcc-fortify3 $CC_GCC -O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3

# Static runtime: gcc links the asan runtime into the image when asked
# explicitly (-static with -fsanitize is refused), so its markers land in
# .symtab instead of the dynamic import table.
build gcc-static-asan $CC_GCC -O2 -fsanitize=address -static-libasan

# Full static build: fortified libc symbols are defined locally, so the
# FORTIFY evidence is the static symbol table rather than the imports.
build gcc-static-fortify3 $CC_GCC -O2 -static -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3

# 32-bit x86 CET exercises the ELFCLASS32 note layout (needs gcc-multilib;
# skipped quietly when the 32-bit headers are not installed).
if [ "$arch" = x86_64 ]; then
    $CC_GCC -O2 -m32 -fcf-protection=full -o "$outdir/gcc-cet-full-32" "$src" \
        && echo "built $outdir/gcc-cet-full-32" || echo "skipped gcc-cet-full-32 (no 32-bit headers)"
fi

if [ "$have_clang" = 1 ]; then
    # MSan and HWASan exist only in clang; trap-mode UBSan links no runtime
    # symbols at all, the documented "cannot tell" case.
    if [ "$arch" = x86_64 ]; then
        build clang-msan $CC_CLANG -O2 -fsanitize=memory
    fi
    if [ "$arch" = aarch64 ]; then
        build clang-hwasan $CC_CLANG -O2 -fsanitize=hwaddress
    fi
    build clang-ubsan-trap $CC_CLANG -O2 -fsanitize=undefined -fsanitize-trap=undefined
    build clang-stack-clash-on $CC_CLANG -O2 -fstack-clash-protection
    build clang-stack-clash-off $CC_CLANG -O2 -fno-stack-clash-protection
    # Clang CFI needs LTO and hidden visibility; __cfi_check is the marker.
    build clang-cfi $CC_CLANG -O2 -flto -fvisibility=hidden -fsanitize=cfi
    build clang-cfi-none $CC_CLANG -O2 -flto -fvisibility=hidden
fi
