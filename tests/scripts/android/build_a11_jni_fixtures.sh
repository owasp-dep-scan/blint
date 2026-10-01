#!/usr/bin/env bash
# A11 fixtures (S1/S2/S3).
#
# liba11rt_<abi>.so - registrars for the tables built at run time, one shape
# per registrar (see RtNative.java for each declaration's fate):
#   a11_rt_register_imm      two entries built per field (name/signature from
#                            PIC string objects, fnPtr through a noinline
#                            identity), constant count 2 - the shape an i386
#                            registrar walk can read.
#   a11_rt_register_volatile identical stores, count from a volatile - the
#                            adjacent shape that must stay unrecovered.
#   a11_rt_register_aligned  one entry staged into a realigned frame (the TU
#                            is compiled with -mstackrealign, so 32-bit
#                            prologues carry `and esp, -16`) - the rebase the
#                            i386 model must survive.
#   rtStaticAdd              static-table control beside them; binds everywhere.
#
# a11-classes.dex - RtNative/RtVolatile/RtAligned/RtStatic declarations.
# a11-jni-rt.apk  - the dex plus one copy of the library per ABI.
set -euo pipefail

out="${1:-$(cd "$(dirname "$0")/../../.." && pwd)/tests/data/android}"
here="$(cd "$(dirname "$0")" && pwd)"

ndk="$HOME/Android/sdk/ndk/28.2.13676358"
toolchain="$ndk/toolchains/llvm/prebuilt/darwin-x86_64/bin"
build_tools="$HOME/Android/sdk/build-tools/36.0.0"
platform_jar="$HOME/Android/sdk/platforms/android-34/android.jar"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# ------------------------------------------------------------------ dex
javac --release 11 -d "$work/classes" \
  $(find "$here/jni_sources/a11_rt/java" -name '*.java' | sort)
"$build_tools/d8" --release --min-api 24 --lib "$platform_jar" \
  --output "$work" $(find "$work/classes" -name '*.class' | sort)
cp "$work/classes.dex" "$out/a11-classes.dex"

# ----------------------------------------------------------------- libs
for abi in arm64-v8a armeabi-v7a x86_64 x86; do
  case "$abi" in
    arm64-v8a) cc="$toolchain/aarch64-linux-android24-clang" ;;
    armeabi-v7a) cc="$toolchain/armv7a-linux-androideabi24-clang" ;;
    x86_64) cc="$toolchain/x86_64-linux-android24-clang" ;;
    x86) cc="$toolchain/i686-linux-android24-clang" ;;
  esac
  "$cc" -g -O2 -fPIC -funwind-tables -c \
    -o "$work/rt_${abi}.o" "$here/jni_sources/a11_rt/a11_rt_tables.cpp"
  "$cc" -g -O2 -fPIC -funwind-tables -mstackrealign -c \
    -o "$work/rt_aligned_${abi}.o" "$here/jni_sources/a11_rt/a11_rt_aligned.cpp"
  "$cc" -shared -o "$work/liba11rt_${abi}.so" \
    "$work/rt_${abi}.o" "$work/rt_aligned_${abi}.o"
  cp "$work/liba11rt_${abi}.so" "$out/liba11rt_${abi}.so"
  "$toolchain/llvm-strip" --strip-all \
    -o "$out/liba11rt_${abi}_stripped.so" "$work/liba11rt_${abi}.so"
done

# ------------------------------------------------------------------ apk
apkroot="$work/apk"
mkdir -p "$apkroot/lib/arm64-v8a" "$apkroot/lib/armeabi-v7a" \
  "$apkroot/lib/x86_64" "$apkroot/lib/x86"
cp "$out/liba11rt_arm64-v8a.so" "$apkroot/lib/arm64-v8a/liba11rt.so"
cp "$out/liba11rt_armeabi-v7a.so" "$apkroot/lib/armeabi-v7a/liba11rt.so"
cp "$out/liba11rt_x86_64.so" "$apkroot/lib/x86_64/liba11rt.so"
cp "$out/liba11rt_x86.so" "$apkroot/lib/x86/liba11rt.so"
cp "$out/a11-classes.dex" "$apkroot/classes.dex"
"$build_tools/aapt2" link --manifest "$here/jni_sources/a11_rt/AndroidManifest.xml" \
  -I "$platform_jar" -o "$work/a11-jni-rt.apk"
(cd "$apkroot" && zip -q -r "$work/a11-jni-rt.apk" .)
"$build_tools/zipalign" -f 4 "$work/a11-jni-rt.apk" "$out/a11-jni-rt.apk"
echo "built: liba11rt_<abi>.so (4 ABIs, stripped twins), a11-classes.dex, a11-jni-rt.apk"
