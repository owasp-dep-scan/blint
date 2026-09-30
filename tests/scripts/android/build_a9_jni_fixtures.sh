#!/usr/bin/env bash
# A9 P2 + P1 fixtures.
#
# P2: liba9_long_<abi>.so - three JNINativeMethod entries whose name and
# signature strings cross the recovery's read bounds (an 802-byte descriptor
# that must bind, a 1037-byte descriptor and a 1120-char name that must stay
# refused). Compiled with the same NDK r28c toolchain and flags as the a5/a8
# fixtures (-funwind-tables so the stripped twin keeps .ARM.exidx rows).
#
# P1: a9-jni-multiabi.apk - repackages the committed A8 builds and
# a8-classes.dex into ONE apk that carries several ABIs' own bytes, so the
# per-(abi, library) join can be tested against copies whose addresses
# differ per ABI. liba8amb.so ships in arm64-v8a and x86_64 only: a library
# missing from an ABI answers nothing there (ground rule 36), which the join
# must report as unbound - never filled in from another ABI's tables.
set -euo pipefail

out="${1:-$(cd "$(dirname "$0")/../../.." && pwd)/tests/data/android}"
here="$(cd "$(dirname "$0")" && pwd)"

ndk="$HOME/Android/sdk/ndk/28.2.13676358"
toolchain="$ndk/toolchains/llvm/prebuilt/darwin-x86_64/bin"
build_tools="$HOME/Android/sdk/build-tools/36.0.0"
platform_jar="$HOME/Android/sdk/platforms/android-34/android.jar"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# ---------------------------------------------------------------- P2 dex
javac --release 11 -d "$work/classes" \
  $(find "$here/jni_sources/a9_long/java" -name '*.java' | sort)
"$build_tools/d8" --release --min-api 24 --lib "$platform_jar" \
  --output "$work" $(find "$work/classes" -name '*.class' | sort)
cp "$work/classes.dex" "$out/a9-classes.dex"

# ---------------------------------------------------------------- P2 libs
for abi in arm64-v8a armeabi-v7a x86_64 x86; do
  case "$abi" in
    arm64-v8a) cc="$toolchain/aarch64-linux-android24-clang" ;;
    armeabi-v7a) cc="$toolchain/armv7a-linux-androideabi24-clang" ;;
    x86_64) cc="$toolchain/x86_64-linux-android24-clang" ;;
    x86) cc="$toolchain/i686-linux-android24-clang" ;;
  esac
  "$cc" -g -O2 -fPIC -funwind-tables -shared \
    -o "$work/liba9_long_${abi}.so" \
    "$here/jni_sources/a9_long/a9_long_tables.cpp"
  cp "$work/liba9_long_${abi}.so" "$out/liba9_long_${abi}.so"
  "$toolchain/llvm-strip" --strip-all \
    -o "$out/liba9_long_${abi}_stripped.so" "$work/liba9_long_${abi}.so"
done

# ---------------------------------------------------------------- apks
# P1: the multi-ABI join fixture (committed a8 bytes).
apkroot="$work/apk"
mkdir -p "$apkroot/lib/arm64-v8a" "$apkroot/lib/armeabi-v7a" \
  "$apkroot/lib/x86_64" "$apkroot/lib/x86"
cp "$out/a8-classes.dex" "$apkroot/classes.dex"
for abi in arm64-v8a armeabi-v7a x86_64 x86; do
  cp "$out/liba8_hybrid_${abi}.so" "$apkroot/lib/$abi/liba8hyb.so"
done
cp "$out/liba8_ambig_arm64-v8a.so" "$apkroot/lib/arm64-v8a/liba8amb.so"
cp "$out/liba8_ambig_x86_64.so" "$apkroot/lib/x86_64/liba8amb.so"

"$build_tools/aapt2" link --manifest "$here/jni_sources/a9_long/AndroidManifest.xml" \
  -I "$platform_jar" -o "$work/a9-multiabi.apk" \
  --min-sdk-version 24 --target-sdk-version 34
(cd "$apkroot" && zip -q -r "$work/a9-multiabi.apk" .)
"$build_tools/zipalign" -f 4 "$work/a9-multiabi.apk" "$out/a9-jni-multiabi.apk"

# P2: the string-bound fixture, one copy per ABI.
longroot="$work/long"
mkdir -p "$longroot/lib/arm64-v8a" "$longroot/lib/armeabi-v7a" \
  "$longroot/lib/x86_64" "$longroot/lib/x86"
cp "$work/classes.dex" "$longroot/classes.dex"
for abi in arm64-v8a armeabi-v7a x86_64 x86; do
  cp "$work/liba9_long_${abi}.so" "$longroot/lib/$abi/liba9long.so"
done
"$build_tools/aapt2" link --manifest "$here/jni_sources/a9_long/AndroidManifest.xml" \
  -I "$platform_jar" -o "$work/a9-long.apk" \
  --min-sdk-version 24 --target-sdk-version 34
(cd "$longroot" && zip -q -r "$work/a9-long.apk" .)
"$build_tools/zipalign" -f 4 "$work/a9-long.apk" "$out/a9-jni-long.apk"

echo "built:"
ls -l "$out" | grep -E "a9-|liba9_" || true
