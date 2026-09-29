#!/usr/bin/env bash
# A7 K1 (feat/an-a7) — the native capability-review R1 fixtures, every one
# a real NDK build:
#
#   liba7_fire_<abi>{,_stripped}.so     the six fire shapes, one exported
#                                       function per family: ptrace
#                                       PTRACE_TRACEME, constant su paths
#                                       to access/stat/fopen, su-path
#                                       execl/system/popen, emulator
#                                       property names to
#                                       __system_property_get, dlopen of
#                                       /data//sdcard constant paths, and
#                                       the per-ABI inline syscall
#   liba7_nofire_<abi>{,_stripped}.so   the measured benign shapes: an
#                                       unwinder reading /proc/self/maps,
#                                       a crash handler's PTRACE_ATTACH/
#                                       SEIZE on a child, an
#                                       ro.build.version.sdk read,
#                                       execve of /system/bin/sh, dlopen
#                                       of a bare SONAME
#   libtoolChecker_<abi>{,_stripped}.so scottyab/rootbeer tag 0.1.2
#                                       rootbeerlib/src/main/cpp/
#                                       toolChecker.{cpp,h} built verbatim
#                                       (the R2 real-world case: its su
#                                       paths arrive from Java, so it
#                                       carries no constant)
#   a7-classes.dex                      the RootBeer 0.1.2 java half
#                                       (Const.suPaths, RootBeerNative
#                                       native declarations), javac
#                                       --release 11 + d8
#   a7-jni-<abi>.apk                    aapt2 link + zip + zipalign:
#                                       the dex plus liba7fire.so,
#                                       liba7nofire.so and libtoolChecker.so
#                                       under lib/<abi>, for arm64-v8a,
#                                       armeabi-v7a (the absint
#                                       cannot-evaluate ABI) and x86_64
#
# Usage: build_a7_fixtures.sh [output_dir]
set -euo pipefail

out="${1:-$(cd "$(dirname "$0")/../../.." && pwd)/tests/data/android}"
here="$(cd "$(dirname "$0")" && pwd)"
src="$here/a7_sources"

ndk="$HOME/Android/sdk/ndk/28.2.13676358"
toolchain="$ndk/toolchains/llvm/prebuilt/darwin-x86_64/bin"
build_tools="$HOME/Android/sdk/build-tools/36.0.0"
platform_jar="$HOME/Android/sdk/platforms/android-34/android.jar"

mkdir -p "$out"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# ---------------------------------------------------------------- dex
javac --release 11 -d "$work/classes" \
  $(find "$src/java" -name '*.java' | sort)
"$build_tools/d8" --release --min-api 24 --lib "$platform_jar" \
  --output "$work" $(find "$work/classes" -name '*.class' | sort)
cp "$work/classes.dex" "$out/a7-classes.dex"

# ---------------------------------------------------------------- libs
# -funwind-tables mirrors the A5 choice: real RegisterNatives libraries are
# C++ with unwind tables, and the arm32 stripped twin needs .ARM.exidx rows
# for function discovery. toolChecker links -llog for __android_log_print.
for abi in arm64-v8a armeabi-v7a x86_64; do
  case "$abi" in
    arm64-v8a) cc="$toolchain/aarch64-linux-android24-clang" ;;
    armeabi-v7a) cc="$toolchain/armv7a-linux-androideabi24-clang" ;;
    x86_64) cc="$toolchain/x86_64-linux-android24-clang" ;;
  esac
  for pair in "fire a7_fire.c" "nofire a7_nofire.c"; do
    set -- $pair
    lib="$1"; csrc="$2"
    "$cc" -O2 -fPIC -funwind-tables -shared -o "$work/liba7_${lib}_${abi}.so" \
      "$src/$csrc"
    cp "$work/liba7_${lib}_${abi}.so" "$out/liba7_${lib}_${abi}.so"
    "$toolchain/llvm-strip" --strip-all \
      -o "$out/liba7_${lib}_${abi}_stripped.so" "$work/liba7_${lib}_${abi}.so"
  done
  "$cc" -O2 -fPIC -funwind-tables -shared -o "$work/libtoolChecker_${abi}.so" \
    "$src/rootbeer/toolChecker.cpp" -llog
  cp "$work/libtoolChecker_${abi}.so" "$out/libtoolChecker_${abi}.so"
  "$toolchain/llvm-strip" --strip-all \
    -o "$out/libtoolChecker_${abi}_stripped.so" "$work/libtoolChecker_${abi}.so"
done

# ---------------------------------------------------------------- apks
# Members carry their loadable names: loadLibrary("toolChecker") in the dex
# resolves to the real zip member, and the fire/nofire libraries ride the
# same APK so the member review path sees them in place.
for abi in arm64-v8a armeabi-v7a x86_64; do
  apkroot="$work/apk-$abi"
  mkdir -p "$apkroot/lib/$abi"
  cp "$out/a7-classes.dex" "$apkroot/classes.dex"
  cp "$work/liba7_fire_${abi}.so" "$apkroot/lib/$abi/liba7fire.so"
  cp "$work/liba7_nofire_${abi}.so" "$apkroot/lib/$abi/liba7nofire.so"
  cp "$work/libtoolChecker_${abi}.so" "$apkroot/lib/$abi/libtoolChecker.so"
  "$build_tools/aapt2" link --manifest "$src/AndroidManifest.xml" \
    -I "$platform_jar" -o "$work/a7-$abi.apk" \
    --min-sdk-version 24 --target-sdk-version 34
  (cd "$apkroot" && zip -q -r "$work/a7-$abi.apk" .)
  "$build_tools/zipalign" -f 4 "$work/a7-$abi.apk" "$out/a7-jni-$abi.apk"
done

echo "built:"
ls -l "$out" | grep -E "a7-" || true
