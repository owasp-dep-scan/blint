#!/usr/bin/env bash
# The JNI registration fixtures, every one a real build:
#
#   liba8_hybrid_<abi>{,_stripped}.so    fbjni's merged registration
#                                        shape: JNINativeMethod tables in
#                                        .data.rel.ro whose NAME words are
#                                        R_*_RELATIVE (plain literals) but
#                                        whose signature + fnPtr words are
#                                        absolute relocations against the
#                                        preemptible dynsym symbols defined
#                                        in a8_hybrid_defs.cpp (the
#                                        jmethod_traits<F>::kDescriptor /
#                                        MethodWrapper<>::call shape
#                                        measured in libreactnative.so).
#                                        Includes the refused neighbour: a
#                                        decoy triple whose fnPtr word
#                                        targets a .rodata OBJECT.
#   liba8_ambig_<abi>{,_stripped}.so     three classes registering the
#                                        SAME name + signature through
#                                        FindClass: two with constant class
#                                        names beside RegisterNatives
#                                        (bind through the FindClass confirmer),
#                                        one with a runtime-composed name
#                                        (stays ambiguous).
#   a8-classes.dex                       both fixtures' dex (javac
#                                        --release 11 + d8)
#   a8-jni-<abi>.apk                     aapt2 link + zip + zipalign, both
#                                        libraries + the dex
#
# Stripped twins come from the NDK's llvm-strip; the preemptible symbols
# live in .dynsym, so both twins keep the same relocation shape.
#
# Usage: build_a8_jni_fixtures.sh [output_dir]
set -euo pipefail

out="${1:-$(cd "$(dirname "$0")/../../.." && pwd)/tests/data/android}"
here="$(cd "$(dirname "$0")" && pwd)"

ndk="$HOME/Android/sdk/ndk/28.2.13676358"
toolchain="$ndk/toolchains/llvm/prebuilt/darwin-x86_64/bin"
build_tools="$HOME/Android/sdk/build-tools/36.0.0"
platform_jar="$HOME/Android/sdk/platforms/android-34/android.jar"

mkdir -p "$out"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# ---------------------------------------------------------------- dex
javac --release 11 -d "$work/classes" \
  $(find "$here/jni_sources/a8_hybrid/java" "$here/jni_sources/a8_ambig/java" \
      -name '*.java' | sort)
"$build_tools/d8" --release --min-api 24 --lib "$platform_jar" \
  --output "$work" $(find "$work/classes" -name '*.class' | sort)
cp "$work/classes.dex" "$out/a8-classes.dex"

# ---------------------------------------------------------------- libs
# -funwind-tables: same rationale as build_a5_jni_fixtures.sh (the arm32 stripped
# twin needs .ARM.exidx rows for the table scan's fnPtr validation).
for abi in arm64-v8a armeabi-v7a x86_64 x86; do
  case "$abi" in
    arm64-v8a) cc="$toolchain/aarch64-linux-android24-clang" ;;
    armeabi-v7a) cc="$toolchain/armv7a-linux-androideabi24-clang" ;;
    x86_64) cc="$toolchain/x86_64-linux-android24-clang" ;;
    x86) cc="$toolchain/i686-linux-android24-clang" ;;
  esac
  for pair in hybrid:a8_hybrid ambig:a8_ambig; do
    lib="${pair%%:*}"
    src="${pair##*:}"
    "$cc" -g -O2 -fPIC -funwind-tables -shared \
      -o "$work/liba8_${lib}_${abi}.so" \
      "$here/jni_sources/$src/${src}_defs.cpp" \
      "$here/jni_sources/$src/${src}_tables.cpp"
    cp "$work/liba8_${lib}_${abi}.so" "$out/liba8_${lib}_${abi}.so"
    "$toolchain/llvm-strip" --strip-all \
      -o "$out/liba8_${lib}_${abi}_stripped.so" "$work/liba8_${lib}_${abi}.so"
  done
done

# ---------------------------------------------------------------- apks
for abi in arm64-v8a armeabi-v7a x86_64 x86; do
  apkroot="$work/apk-$abi"
  mkdir -p "$apkroot/lib/$abi"
  cp "$out/a8-classes.dex" "$apkroot/classes.dex"
  cp "$work/liba8_hybrid_${abi}.so" "$apkroot/lib/$abi/liba8hyb.so"
  cp "$work/liba8_ambig_${abi}.so" "$apkroot/lib/$abi/liba8amb.so"
  "$build_tools/aapt2" link --manifest "$here/jni_sources/a8_hybrid/AndroidManifest.xml" \
    -I "$platform_jar" -o "$work/a8-$abi.apk" \
    --min-sdk-version 24 --target-sdk-version 34
  (cd "$apkroot" && zip -q -r "$work/a8-$abi.apk" .)
  "$build_tools/zipalign" -f 4 "$work/a8-$abi.apk" "$out/a8-jni-$abi.apk"
done

echo "built:"
ls -l "$out" | grep -E "a8-" || true
