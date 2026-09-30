#!/usr/bin/env bash
# A9 P1 - the multi-ABI JNI join fixture. No compilation: it repackages the
# committed A8 builds (liba8_hybrid/liba8_ambig, NDK r28c) and a8-classes.dex
# into ONE apk that carries several ABIs' own bytes, so the per-(abi, library)
# join can be tested against copies whose addresses differ per ABI.
#
# liba8amb.so ships in arm64-v8a and x86_64 only: a library missing from an
# ABI answers nothing there (ground rule 36), which the join must report as
# unbound - never filled in from another ABI's tables.
set -euo pipefail

out="${1:-$(cd "$(dirname "$0")/../../.." && pwd)/tests/data/android}"
here="$(cd "$(dirname "$0")" && pwd)"

build_tools="$HOME/Android/sdk/build-tools/36.0.0"
platform_jar="$HOME/Android/sdk/platforms/android-34/android.jar"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

apkroot="$work/apk"
mkdir -p "$apkroot/lib/arm64-v8a" "$apkroot/lib/armeabi-v7a" \
  "$apkroot/lib/x86_64" "$apkroot/lib/x86"
cp "$out/a8-classes.dex" "$apkroot/classes.dex"
for abi in arm64-v8a armeabi-v7a x86_64 x86; do
  cp "$out/liba8_hybrid_${abi}.so" "$apkroot/lib/$abi/liba8hyb.so"
done
cp "$out/liba8_ambig_arm64-v8a.so" "$apkroot/lib/arm64-v8a/liba8amb.so"
cp "$out/liba8_ambig_x86_64.so" "$apkroot/lib/x86_64/liba8amb.so"

"$build_tools/aapt2" link --manifest "$here/jni_sources/a8_hybrid/AndroidManifest.xml" \
  -I "$platform_jar" -o "$work/a9-multiabi.apk" \
  --min-sdk-version 24 --target-sdk-version 34
(cd "$apkroot" && zip -q -r "$work/a9-multiabi.apk" .)
"$build_tools/zipalign" -f 4 "$work/a9-multiabi.apk" "$out/a9-jni-multiabi.apk"

echo "built:"
ls -l "$out/a9-jni-multiabi.apk"
