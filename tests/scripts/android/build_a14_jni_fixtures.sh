#!/usr/bin/env bash
# A14 W1 fixtures (the JNA direct-mapping join).
#
# The dex side is a real JNA direct-mapped build: javac/d8 compile the
# classes against the JNA jar from Maven Central (net.java.dev.jna:jna,
# 5.18.1, the version the corpus apps ship; sha256 below). The jar is
# never committed - the script downloads it when missing and refuses a
# checksum mismatch.
#
#   A14Direct       Native.register(Class, "a14jna") - the constant at the
#                   call; binds to liba14jna.so.
#   A14Helper       the register name comes from findLibraryName()'s
#                   constant fallback (uniffi's shape); liba14other.so
#                   also exports the method name, so only the constant
#                   picks the right exporter.
#   A14ViaInit      the register call sits in a method the <clinit> runs.
#   A14Twin         the negative twin: same natives, same exports, but
#                   only System.loadLibrary - no register call anywhere;
#                   must stay unbound.
#   A14Ambiguous    registered against the process library (no
#                   constant); the name is exported by both libraries in
#                   every ABI, so the row must stay ambiguous with both
#                   exporters listed.
#   A14Bootstrap    registers A14RegisteredByBootstrap by its literal:
#                   that class binds, the bootstrap's own decoy does not.
#   A14Caller       its <clinit> runs A14SelfRegistrar's registrar, which
#                   registers A14SelfRegistrar: that class binds, the
#                   caller's own decoy does not.
#   A14Stale        the name argument is a field read in a register that
#                   held "a14jna" earlier; A14Branch passes "a14other" or
#                   "a14jna" by branch. Both names are exported by both
#                   libraries: no constant holds on every path, so both
#                   rows stay ambiguous.
#   A14Outer        Native.register(String) from the nested Init class,
#                   which declares no natives: JNA registers A14Outer.
#
# liba14jna_<abi>.so exports every plain C name; liba14other_<abi>.so
# exports the decoys (a14_ambiguous, a14_stale, a14_branch, a14_helper_mul).
# The JNA dispatch
# library is a name-presence stub (libjnidispatch.so, an empty library) -
# the join reads the name, and JNA's real dispatch artifact is LGPL and
# stays out of the repository.
#
# a14-jna.apk             the dex plus all three libraries in all four ABIs.
# a14-jna-nodispatch.apk  the arm64 copies without the dispatch stub: the
#                         gate that no binding happens where JNA cannot
#                         load.
set -euo pipefail

out="${1:-$(cd "$(dirname "$0")/../../.." && pwd)/tests/data/android}"
here="$(cd "$(dirname "$0")" && pwd)"

ndk="$HOME/Android/sdk/ndk/28.2.13676358"
toolchain="$ndk/toolchains/llvm/prebuilt/darwin-x86_64/bin"
build_tools="$HOME/Android/sdk/build-tools/36.0.0"
platform_jar="$HOME/Android/sdk/platforms/android-34/android.jar"

JNA_VERSION=5.18.1
JNA_SHA256=260c4b1e22b1db9e110ee441c4f13ce115f841fa48c41d78750986214b395557
JNA_URL="https://repo1.maven.org/maven2/net/java/dev/jna/jna/${JNA_VERSION}/jna-${JNA_VERSION}.jar"
jna_jar="$HOME/.cache/blint-fixtures/jna-${JNA_VERSION}.jar"
mkdir -p "$(dirname "$jna_jar")"
if [ ! -f "$jna_jar" ]; then
  curl -sfSL -o "$jna_jar" "$JNA_URL"
fi
echo "$JNA_SHA256  $jna_jar" | shasum -a 256 -c -

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# ------------------------------------------------------------------ dex
javac --release 11 -cp "$jna_jar" -d "$work/classes" \
  $(find "$here/jni_sources/a14_jna/java" -name '*.java' | sort)
"$build_tools/d8" --release --min-api 24 --lib "$platform_jar" \
  --classpath "$jna_jar" --output "$work" \
  $(find "$work/classes" -name '*.class' | sort)
cp "$work/classes.dex" "$out/a14-jna-classes.dex"

# ----------------------------------------------------------------- libs
for abi in arm64-v8a armeabi-v7a x86_64 x86; do
  case "$abi" in
    arm64-v8a) cc="$toolchain/aarch64-linux-android24-clang" ;;
    armeabi-v7a) cc="$toolchain/armv7a-linux-androideabi24-clang" ;;
    x86_64) cc="$toolchain/x86_64-linux-android24-clang" ;;
    x86) cc="$toolchain/i686-linux-android24-clang" ;;
  esac
  "$cc" -g -O2 -fPIC -c -o "$work/a14_${abi}.o" "$here/jni_sources/a14_jna/c/a14_jna.c"
  "$cc" -shared -o "$out/liba14jna_${abi}.so" "$work/a14_${abi}.o"
  "$cc" -g -O2 -fPIC -c -o "$work/other_${abi}.o" "$here/jni_sources/a14_jna/c/a14_other.c"
  "$cc" -shared -o "$out/liba14other_${abi}.so" "$work/other_${abi}.o"
  "$cc" -g -O2 -fPIC -c -o "$work/stub_${abi}.o" "$here/jni_sources/a14_jna/c/a14_jnidispatch_stub.c"
  "$cc" -shared -o "$work/libjnidispatch_${abi}.so" "$work/stub_${abi}.o"
done

# ----------------------------------------------------------------- apks
apkroot="$work/apk"
mkdir -p "$apkroot/lib/arm64-v8a" "$apkroot/lib/armeabi-v7a" \
  "$apkroot/lib/x86_64" "$apkroot/lib/x86"
for abi in arm64-v8a armeabi-v7a x86_64 x86; do
  cp "$out/liba14jna_${abi}.so" "$apkroot/lib/$abi/liba14jna.so"
  cp "$out/liba14other_${abi}.so" "$apkroot/lib/$abi/liba14other.so"
  cp "$work/libjnidispatch_${abi}.so" "$apkroot/lib/$abi/libjnidispatch.so"
done
cp "$out/a14-jna-classes.dex" "$apkroot/classes.dex"
"$build_tools/aapt2" link --manifest "$here/jni_sources/a14_jna/AndroidManifest.xml" \
  -I "$platform_jar" -o "$work/a14-jna.apk"
(cd "$apkroot" && zip -q -r "$work/a14-jna.apk" .)
"$build_tools/zipalign" -f 4 "$work/a14-jna.apk" "$out/a14-jna.apk"

nogate="$work/nogate"
mkdir -p "$nogate/lib/arm64-v8a"
cp "$out/liba14jna_arm64-v8a.so" "$nogate/lib/arm64-v8a/liba14jna.so"
cp "$out/liba14other_arm64-v8a.so" "$nogate/lib/arm64-v8a/liba14other.so"
cp "$out/a14-jna-classes.dex" "$nogate/classes.dex"
"$build_tools/aapt2" link --manifest "$here/jni_sources/a14_jna/AndroidManifest.xml" \
  -I "$platform_jar" -o "$work/a14-jna-nodispatch.apk"
(cd "$nogate" && zip -q -r "$work/a14-jna-nodispatch.apk" .)
"$build_tools/zipalign" -f 4 "$work/a14-jna-nodispatch.apk" "$out/a14-jna-nodispatch.apk"

echo "built: liba14jna_<abi>.so + liba14other_<abi>.so (4 ABIs), a14-jna-classes.dex, a14-jna.apk, a14-jna-nodispatch.apk (against jna-${JNA_VERSION}, sha256 ${JNA_SHA256})"
