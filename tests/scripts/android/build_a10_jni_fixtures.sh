#!/usr/bin/env bash
# A10 Q1 fixtures.
#
# liba10_gap_<abi>.so - the two honest 32-bit refusals A10 Q0 named, each
# beside a control that must keep binding:
#   plainAdd    control (constant-initialized table) - binds everywhere.
#   weakOnly    the fbjni kDescriptor shape (signature word against a weak
#               preemptible OBJECT dynsym) - binds everywhere, REL ABIs too.
#   nounwindAdd a real wrapper compiled with -fno-unwind-tables
#               -fno-asynchronous-unwind-tables and hidden: its triple's
#               words relocate onto a genuine function no start source can
#               verify (the RnHello v7a yoga wrappers) - refused everywhere.
#   smallOnly   the registrar builds the entry at run time through a
#               noinline constructor (makeNativeMethod shape) - no static
#               triple, refused everywhere.
#   decoyDataFn fnPtr word against a defined OBJECT - refused.
#
# a10-classes.dex - GapNative's five declarations (the join oracle).
# a10-jni-gap.apk - the dex plus one copy of the library per ABI, each ABI's
#               own bytes (ground rule 36).
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
  $(find "$here/jni_sources/a10_gap/java" -name '*.java' | sort)
"$build_tools/d8" --release --min-api 24 --lib "$platform_jar" \
  --output "$work" $(find "$work/classes" -name '*.class' | sort)
cp "$work/classes.dex" "$out/a10-classes.dex"

# ----------------------------------------------------------------- libs
for abi in arm64-v8a armeabi-v7a x86_64 x86; do
  case "$abi" in
    arm64-v8a) cc="$toolchain/aarch64-linux-android24-clang" ;;
    armeabi-v7a) cc="$toolchain/armv7a-linux-androideabi24-clang" ;;
    x86_64) cc="$toolchain/x86_64-linux-android24-clang" ;;
    x86) cc="$toolchain/i686-linux-android24-clang" ;;
  esac
  # The main TU keeps -funwind-tables like the a5/a8/a9 fixtures; the
  # wrapper TU drops unwind and async-unwind tables so no .ARM.exidx /
  # .eh_frame entry covers it, and its hidden visibility keeps it out of
  # .dynsym.
  "$cc" -g -O2 -fPIC -funwind-tables -c \
    -o "$work/tables_${abi}.o" "$here/jni_sources/a10_gap/a10_gap_tables.cpp"
  "$cc" -g -O2 -fPIC -fno-unwind-tables -fno-asynchronous-unwind-tables -c \
    -o "$work/nounwind_${abi}.o" "$here/jni_sources/a10_gap/a10_gap_nounwind.cpp"
  "$cc" -shared -o "$work/liba10_gap_${abi}.so" \
    "$work/tables_${abi}.o" "$work/nounwind_${abi}.o"
  cp "$work/liba10_gap_${abi}.so" "$out/liba10_gap_${abi}.so"
  "$toolchain/llvm-strip" --strip-all \
    -o "$out/liba10_gap_${abi}_stripped.so" "$work/liba10_gap_${abi}.so"
done

# ------------------------------------------------------------------ apk
apkroot="$work/apk"
mkdir -p "$apkroot/lib/arm64-v8a" "$apkroot/lib/armeabi-v7a" \
  "$apkroot/lib/x86_64" "$apkroot/lib/x86"
cp "$out/a10-classes.dex" "$apkroot/classes.dex"
for abi in arm64-v8a armeabi-v7a x86_64 x86; do
  cp "$work/liba10_gap_${abi}.so" "$apkroot/lib/$abi/liba10gap.so"
done

"$build_tools/aapt2" link --manifest "$here/jni_sources/a10_gap/AndroidManifest.xml" \
  -I "$platform_jar" -o "$work/a10-gap.apk" \
  --min-sdk-version 24 --target-sdk-version 34
(cd "$apkroot" && zip -q -r "$work/a10-gap.apk" .)
"$build_tools/zipalign" -f 4 "$work/a10-gap.apk" "$out/a10-jni-gap.apk"

echo "built:"
ls -l "$out" | grep -E "a10-|liba10_" || true
