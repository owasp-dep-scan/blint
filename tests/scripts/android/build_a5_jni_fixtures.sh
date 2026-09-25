#!/usr/bin/env bash
# A5 E0 (feat/an-a4b-a5) — the JNI R1 fixtures, every one a real build:
#
#   liba5_static_<abi>{,_stripped}.so    static natives, one export per
#                                        mangling escape (_1, _2, _3,
#                                        _0xxxx via the nested class '$',
#                                        package '_'), the overloaded
#                                        __<sig> forms, JNI_OnLoad /
#                                        JNI_OnUnload, and one export with
#                                        no dex declaration (orphan)
#   liba5_dynamic_<abi>{,_stripped}.so   RegisterNatives from JNI_OnLoad:
#                                        5 methods across 2 classes, the
#                                        JNINativeMethod tables in
#                                        .data.rel.ro behind RELATIVE
#                                        relocations
#   a5-classes.dex                       the matching dex (javac --release
#                                        11 + d8), declaring all natives
#                                        plus missingNative (unbound)
#   a5-jni-<abi>.apk                     aapt2 link + zip + zipalign, both
#                                        libraries + the dex, for arm64-v8a
#                                        and armeabi-v7a
#
# Stripped twins come from the NDK's llvm-strip; the exports are dynamic
# symbols, so both twins carry the same Java_* surface.
#
# Usage: build_a5_jni_fixtures.sh [output_dir]
set -euo pipefail

out="${1:-$(cd "$(dirname "$0")/../../.." && pwd)/tests/data/android}"
here="$(cd "$(dirname "$0")" && pwd)"
src="$here/jni_sources/a5_jni"

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
cp "$work/classes.dex" "$out/a5-classes.dex"

# ---------------------------------------------------------------- libs
for abi in arm64-v8a armeabi-v7a; do
  case "$abi" in
    arm64-v8a) cc="$toolchain/aarch64-linux-android24-clang" ;;
    armeabi-v7a) cc="$toolchain/armv7a-linux-androideabi24-clang" ;;
  esac
  for lib in static dynamic; do
    "$cc" -g -O2 -fPIC -shared -o "$work/liba5_${lib}_${abi}.so" \
      "$src/jni_${lib}.c"
    cp "$work/liba5_${lib}_${abi}.so" "$out/liba5_${lib}_${abi}.so"
    "$toolchain/llvm-strip" --strip-all \
      -o "$out/liba5_${lib}_${abi}_stripped.so" "$work/liba5_${lib}_${abi}.so"
  done
done

# ---------------------------------------------------------------- apks
# Inside the APK the libraries carry their loadable names, so
# System.loadLibrary("jnistat")/"jnidyn" in the dex resolve to real zip
# members (the E2 mapping fact). The committed standalone twins keep the
# liba5_* names documented in the manifest.
for abi in arm64-v8a armeabi-v7a; do
  apkroot="$work/apk-$abi"
  mkdir -p "$apkroot/lib/$abi"
  cp "$out/a5-classes.dex" "$apkroot/classes.dex"
  cp "$work/liba5_static_${abi}.so" "$apkroot/lib/$abi/libjnistat.so"
  cp "$work/liba5_dynamic_${abi}.so" "$apkroot/lib/$abi/libjnidyn.so"
  "$build_tools/aapt2" link --manifest "$src/AndroidManifest.xml" \
    -I "$platform_jar" -o "$work/a5-$abi.apk" \
    --min-sdk-version 24 --target-sdk-version 34
  (cd "$apkroot" && zip -q -r "$work/a5-$abi.apk" .)
  "$build_tools/zipalign" -f 4 "$work/a5-$abi.apk" "$out/a5-jni-$abi.apk"
done

echo "built:"
ls -l "$out" | grep -E "a5-" || true
