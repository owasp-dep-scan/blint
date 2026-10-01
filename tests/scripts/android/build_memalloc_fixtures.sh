#!/usr/bin/env bash
# SUSPICIOUS_MEMORY_ALLOC fire/no-fire fixtures, real NDK builds:
#
#   libmemalloc_<abi>.so   memalloc_sources/memalloc.c at -O2, for
#                          arm64-v8a, armeabi-v7a and x86_64
#
# Usage: build_memalloc_fixtures.sh [output_dir]
set -euo pipefail

out="${1:-$(cd "$(dirname "$0")/../../.." && pwd)/tests/data/android}"
here="$(cd "$(dirname "$0")" && pwd)"
src="$here/memalloc_sources/memalloc.c"

ndk="$HOME/Android/sdk/ndk/28.2.13676358"
toolchain="$ndk/toolchains/llvm/prebuilt/darwin-x86_64/bin"

mkdir -p "$out"
for pair in arm64-v8a:aarch64-linux-android24 armeabi-v7a:armv7a-linux-androideabi24 \
  x86_64:x86_64-linux-android24; do
  abi="${pair%%:*}"
  target="${pair#*:}"
  "$toolchain/clang" --target="$target" -O2 -fPIC -shared \
    -Wl,-soname,libmemalloc.so -Wl,--build-id=none \
    -o "$out/libmemalloc_${abi}.so" "$src"
done
