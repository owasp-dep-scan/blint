#!/usr/bin/env bash
# A2 (feat/an-a2-a3) — tier-1 link variants that ndk-build cannot express.
#
# ndk-build always passes -Wl,-soname, so the two SONAME facts need a raw
# NDK clang invocation (a real build; the command is this script):
#
#   hello_nosoname   -shared with no -soname flag     -> no DT_SONAME
#   hello_absneeded  linked against a soname-less helper by absolute
#                    path                              -> DT_NEEDED carries /
#
# The helper (libhelper_nosoname.so) is kept out of the corpus; only the
# two facts land in tier1-ndk. Everything is built and stripped with the
# named NDK's own toolchain; ground truth is captured by the tier-1
# manifest writer (llvm-readelf from the same NDK) in the same run.
#
# Usage: build_a2_link_variants.sh [corpus_root]
set -euo pipefail

corpus="${1:-$HOME/sandbox/android-corpus}"
here="$(cd "$(dirname "$0")" && pwd)"

ABIS="arm64-v8a armeabi-v7a x86_64 x86 riscv64"

triple_for() {
  case "$1" in
    arm64-v8a) echo "aarch64-linux-android21" ;;
    armeabi-v7a) echo "armv7a-linux-androideabi21" ;;
    x86_64) echo "x86_64-linux-android21" ;;
    x86) echo "i686-linux-android21" ;;
    riscv64) echo "riscv64-linux-android35" ;;  # riscv64 ships from API 35 only
  esac
}

for tag in r27 r28; do
  case "$tag" in
    r27) ndk="$HOME/Android/sdk/ndk/27.3.13750724" ;;
    r28) ndk="$HOME/Android/sdk/ndk/28.2.13676358" ;;
  esac
  toolchain="$ndk/toolchains/llvm/prebuilt/darwin-x86_64/bin"
  for abi in $ABIS; do
    cc="$toolchain/$(triple_for "$abi")-clang"
    out="$corpus/tier1-ndk/$tag/$abi"
    mkdir -p "$out"
    echo "== $tag/$abi"

    # hello_nosoname: -shared, no -soname flag, so lld records no SONAME.
    "$cc" -O2 -fPIC -fstack-protector-strong -shared \
      "$here/jni_sources/hello.c" "$here/jni_sources/blint_sink.c" \
      -o "$out/libhello_nosoname.so.unstripped"
    "$toolchain/llvm-strip" -o "$out/libhello_nosoname.so" \
      "$out/libhello_nosoname.so.unstripped"

    # hello_absneeded: link against a soname-less helper by a path (which
    # lld records verbatim as DT_NEEDED). The helper is linked in a fixed
    # work dir and named with a leading ./ so the recorded NEEDED is
    # deterministic ("./libhelper_nosoname.so") across machines.
    work="/tmp/blint_a2_absneeded"
    rm -rf "$work" && mkdir -p "$work"
    "$cc" -O2 -fPIC -shared "$here/jni_sources/blint_sink.c" \
      -o "$work/libhelper_nosoname.so"
    # The link runs with cwd=$work and names the helper "./libhelper_nosoname.so",
    # so lld records that literal string (a '/'-bearing path) as DT_NEEDED.
    (cd "$work" && "$cc" -O2 -fPIC -fstack-protector-strong -shared \
      "$here/jni_sources/hello.c" "$here/jni_sources/blint_sink.c" \
      ./libhelper_nosoname.so \
      -o "$out/libhello_absneeded.so.unstripped")
    "$toolchain/llvm-strip" -o "$out/libhello_absneeded.so" \
      "$out/libhello_absneeded.so.unstripped"
  done
done
echo "built nosoname/absneeded variants under $corpus/tier1-ndk"
