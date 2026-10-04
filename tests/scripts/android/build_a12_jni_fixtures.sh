#!/usr/bin/env bash
# The a8/a9/a11 fixtures' registrar shapes built for Thumb.
#
# liba12rt_armeabi-v7a.so    - the a11_rt registrar sources (constant-count
#                              word stores, the volatile-count twin, the
#                              realigned registrar, the pair-passing chain)
#                              compiled with -mthumb, because the a8-a11 v7a
#                              fixtures all came out ARM-mode and every
#                              shipped app library on armeabi-v7a is Thumb.
# liba12split_armeabi-v7a.so - the a9_split merged-table sources, -mthumb:
#                              the confirmer's whole chain (the staging's
#                              pool-pair + NEON slice copy, the per-class
#                              helper's vtable call) in the Thumb dialect.
# a12-jni-classes.dex        - the same a11 Rt* declarations.
# a12-jni-thumb.apk          - the dex plus the v7a Thumb registrar library.
# a12-jni-split-thumb.apk    - the a9 split dex plus its Thumb twin.
set -euo pipefail

out="${1:-$(cd "$(dirname "$0")/../../.." && pwd)/tests/data/android}"
here="$(cd "$(dirname "$0")" && pwd)"

ndk="$HOME/Android/sdk/ndk/28.2.13676358"
toolchain="$ndk/toolchains/llvm/prebuilt/darwin-x86_64/bin"
build_tools="$HOME/Android/sdk/build-tools/36.0.0"
platform_jar="$HOME/Android/sdk/platforms/android-34/android.jar"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# ----------------------------------------------------------------- dex
javac --release 11 -d "$work/classes" \
  $(find "$here/jni_sources/a11_rt/java" -name '*.java' | sort)
"$build_tools/d8" --release --min-api 24 --lib "$platform_jar" \
  --output "$work" $(find "$work/classes" -name '*.class' | sort)
cp "$work/classes.dex" "$out/a12-jni-classes.dex"
javac --release 11 -d "$work/split-classes" \
  $(find "$here/jni_sources/a9_split/java" -name '*.java' | sort)
mkdir -p "$work/split-dex"
"$build_tools/d8" --release --min-api 24 --lib "$platform_jar" \
  --output "$work/split-dex" $(find "$work/split-classes" -name '*.class' | sort)
cp "$work/split-dex/classes.dex" "$out/a12-jni-split-classes.dex"

# ----------------------------------------------------------------- libs
cc="$toolchain/armv7a-linux-androideabi24-clang"
"$cc" -g -O2 -fPIC -funwind-tables -mthumb -c \
  -o "$work/rt_thumb.o" "$here/jni_sources/a11_rt/a11_rt_tables.cpp"
"$cc" -g -O2 -fPIC -funwind-tables -mthumb -mstackrealign -c \
  -o "$work/rt_thumb_aligned.o" "$here/jni_sources/a11_rt/a11_rt_aligned.cpp"
"$cc" -shared -o "$work/liba12rt_armeabi-v7a.so" \
  "$work/rt_thumb.o" "$work/rt_thumb_aligned.o"
cp "$work/liba12rt_armeabi-v7a.so" "$out/liba12rt_armeabi-v7a.so"
"$toolchain/llvm-strip" --strip-all \
  -o "$out/liba12rt_armeabi-v7a_stripped.so" "$work/liba12rt_armeabi-v7a.so"
"$cc" -g -O2 -fPIC -funwind-tables -mthumb -shared \
  -o "$out/liba12split_armeabi-v7a.so" \
  "$here/jni_sources/a9_split/a9_split_tables.cpp"
"$toolchain/llvm-strip" --strip-all \
  -o "$out/liba12split_armeabi-v7a_stripped.so" "$out/liba12split_armeabi-v7a.so"

# ----------------------------------------------------------------- apks
apkroot="$work/apk"
mkdir -p "$apkroot/lib/armeabi-v7a"
cp "$out/liba12rt_armeabi-v7a.so" "$apkroot/lib/armeabi-v7a/liba12rt.so"
cp "$out/a12-jni-classes.dex" "$apkroot/classes.dex"
"$build_tools/aapt2" link --manifest "$here/jni_sources/a11_rt/AndroidManifest.xml" \
  -I "$platform_jar" -o "$work/a12-jni-thumb.apk"
(cd "$apkroot" && zip -q -r "$work/a12-jni-thumb.apk" .)
"$build_tools/zipalign" -f 4 "$work/a12-jni-thumb.apk" "$out/a12-jni-thumb.apk"

splitroot="$work/split-apk"
mkdir -p "$splitroot/lib/armeabi-v7a"
cp "$out/liba12split_armeabi-v7a.so" "$splitroot/lib/armeabi-v7a/liba12split.so"
cp "$out/a12-jni-split-classes.dex" "$splitroot/classes.dex"
"$build_tools/aapt2" link --manifest "$here/jni_sources/a9_split/AndroidManifest.xml" \
  -I "$platform_jar" -o "$work/a12-jni-split-thumb.apk"
(cd "$splitroot" && zip -q -r "$work/a12-jni-split-thumb.apk" .)
"$build_tools/zipalign" -f 4 "$work/a12-jni-split-thumb.apk" "$out/a12-jni-split-thumb.apk"
echo "built: liba12rt_armeabi-v7a.so and liba12split_armeabi-v7a.so (Thumb, stripped twins), dexes, a12-jni-thumb.apk, a12-jni-split-thumb.apk"
