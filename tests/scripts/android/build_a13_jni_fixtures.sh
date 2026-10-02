#!/usr/bin/env bash
# A13 U1 fixtures (the 32-bit singles' registrar shapes).
#
# liba13rt_<abi>.so - one registrar per shape (see the java declarations'
# expected fates):
#   a13_rt_register_lazy      the class is found only on the cold init path
#                            the compiler places below the RegisterNatives
#                            call (the RN ThreadScope / CxxCallbackImpl /
#                            install-binding shape).
#   a13_rt_register_sret      the entry words are stored before a call that
#                            returns through a caller-frame pointer the
#                            callee pops (the i386 sret form; fbjni's
#                            findClassLocal), with the caller's `sub esp, 4`
#                            re-alignment between the stores and the methods
#                            lea.
#   a13_rt_register_via_pair  the pair-passing chain whose callee makes its
#                            own sret call before reading the incoming pair
#                            (the registerHybrid shape).
#   a13_rt_register_two       the refusal twin: the cold init path names two
#                            classes, so the call that no class material-
#                            ization precedes stays unread.
#   rtStaticAdd               static-table control beside them; binds
#                            everywhere.
#
# liba13ctl_x86.so + liba13ctlfb_x86.so - the sret trigger's false-fire
# controls (added by the A13 review): registrars that hand a frame pointer
# to a plain-`ret` local callee, an external libc call, and the sibling's
# plain-`ret` helper between their entry stores and their methods lea,
# beside the sibling-defined genuine sret finder (`ret 4`, the libfbjni
# findClassLocal shape). The first three bound before A13 and must keep
# binding: the trigger must not fire without the callee's own pop proof.
#
# liba13held_x86.so + liba13held_thumb_armeabi-v7a.so - the held
# registration's consumed-name control (added by the A13 review): a
# registrar whose first table goes into the jclass Java passed in, and
# whose one class name, found below that call, a second RegisterNatives
# consumes. The first table must not be attributed to that class.
#
# a13-jni-classes.dex - RtLazy/RtSret/RtPairSret/RtTwo/RtControl
# declarations.
# a13-jni-singles.apk  - the dex plus one copy of the library per ABI
#                        (armeabi-v7a in ARM state).
# a13-jni-singles-thumb.apk - the v7a copy rebuilt with -mthumb (the
#                        dialect the measured registrars ship in).
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
  $(find "$here/jni_sources/a13_rt/java" -name '*.java' | sort)
"$build_tools/d8" --release --min-api 24 --lib "$platform_jar" \
  --output "$work" $(find "$work/classes" -name '*.class' | sort)
cp "$work/classes.dex" "$out/a13-jni-classes.dex"

# ----------------------------------------------------------------- libs
# -fomit-frame-pointer matches the shipped RN libraries: their i386
# registrars address the frame through esp (the walk's slot keys), not
# through an ebp frame the baseline cannot shift.
for abi in arm64-v8a armeabi-v7a x86_64 x86; do
  case "$abi" in
    arm64-v8a) cc="$toolchain/aarch64-linux-android24-clang" ;;
    armeabi-v7a) cc="$toolchain/armv7a-linux-androideabi24-clang" ;;
    x86_64) cc="$toolchain/x86_64-linux-android24-clang" ;;
    x86) cc="$toolchain/i686-linux-android24-clang" ;;
  esac
  "$cc" -g -O2 -fPIC -funwind-tables -fomit-frame-pointer -c \
    -o "$work/singles_${abi}.o" "$here/jni_sources/a13_rt/a13_rt_singles.cpp"
  "$cc" -g -O2 -fPIC -funwind-tables -fomit-frame-pointer -c \
    -o "$work/pair_${abi}.o" "$here/jni_sources/a13_rt/a13_rt_pair.cpp"
  "$cc" -shared -o "$work/liba13rt_${abi}.so" \
    "$work/singles_${abi}.o" "$work/pair_${abi}.o"
  cp "$work/liba13rt_${abi}.so" "$out/liba13rt_${abi}.so"
  "$toolchain/llvm-strip" --strip-all \
    -o "$out/liba13rt_${abi}_stripped.so" "$work/liba13rt_${abi}.so"
done

# the Thumb twin of the v7a copy
cc="$toolchain/armv7a-linux-androideabi24-clang"
"$cc" -g -O2 -fPIC -funwind-tables -mthumb -fomit-frame-pointer -c \
  -o "$work/singles_thumb.o" "$here/jni_sources/a13_rt/a13_rt_singles.cpp"
"$cc" -g -O2 -fPIC -funwind-tables -mthumb -fomit-frame-pointer -c \
  -o "$work/pair_thumb.o" "$here/jni_sources/a13_rt/a13_rt_pair.cpp"
"$cc" -shared -o "$out/liba13rt_thumb_armeabi-v7a.so" \
  "$work/singles_thumb.o" "$work/pair_thumb.o"
"$toolchain/llvm-strip" --strip-all \
  -o "$out/liba13rt_thumb_armeabi-v7a_stripped.so" "$out/liba13rt_thumb_armeabi-v7a.so"

# ------------------------------------------------- sret false-fire controls
# x86-only: the callee-pop verification's regression pair. liba13ctlfb is
# the libfbjni stand-in defining the external sret finder (`ret 4`) and a
# plain-`ret` helper; liba13ctl's registrars hand a frame pointer as arg1
# to a local plain-`ret` callee, an external libc call (snprintf), the
# sibling's plain-`ret` helper, and the sibling's genuine sret finder,
# each between the entry stores and the methods lea. -fomit-frame-pointer
# matches the shipped RN libraries.
cc="$toolchain/i686-linux-android24-clang"
"$cc" -g -O2 -fPIC -funwind-tables -fomit-frame-pointer -c \
  -o "$work/popctl_find.o" "$here/jni_sources/a13_rt/a13_rt_popctl_find.cpp"
"$cc" -shared -o "$out/liba13ctlfb_x86.so" "$work/popctl_find.o"
"$cc" -g -O2 -fPIC -funwind-tables -fomit-frame-pointer -c \
  -o "$work/popctl.o" "$here/jni_sources/a13_rt/a13_rt_popctl.cpp"
"$cc" -shared -o "$out/liba13ctl_x86.so" "$work/popctl.o" \
  -L"$out" -l:liba13ctlfb_x86.so
"$toolchain/llvm-strip" --strip-all -o "$out/liba13ctlfb_x86_stripped.so" "$out/liba13ctlfb_x86.so"
"$toolchain/llvm-strip" --strip-all -o "$out/liba13ctl_x86_stripped.so" "$out/liba13ctl_x86.so"

# --------------------------------------------- held consumed-name control
cc="$toolchain/i686-linux-android24-clang"
"$cc" -g -O2 -fPIC -funwind-tables -fomit-frame-pointer -c \
  -o "$work/held_x86.o" "$here/jni_sources/a13_rt/a13_rt_held.cpp"
"$cc" -shared -o "$out/liba13held_x86.so" "$work/held_x86.o"
cc="$toolchain/armv7a-linux-androideabi24-clang"
"$cc" -g -O2 -fPIC -funwind-tables -mthumb -fomit-frame-pointer -c \
  -o "$work/held_thumb.o" "$here/jni_sources/a13_rt/a13_rt_held.cpp"
"$cc" -shared -o "$out/liba13held_thumb_armeabi-v7a.so" "$work/held_thumb.o"

# ----------------------------------------------------------------- apks
apkroot="$work/apk"
mkdir -p "$apkroot/lib/arm64-v8a" "$apkroot/lib/armeabi-v7a" \
  "$apkroot/lib/x86_64" "$apkroot/lib/x86"
cp "$out/liba13rt_arm64-v8a.so" "$apkroot/lib/arm64-v8a/liba13rt.so"
cp "$out/liba13rt_armeabi-v7a.so" "$apkroot/lib/armeabi-v7a/liba13rt.so"
cp "$out/liba13rt_x86_64.so" "$apkroot/lib/x86_64/liba13rt.so"
cp "$out/liba13rt_x86.so" "$apkroot/lib/x86/liba13rt.so"
cp "$out/a13-jni-classes.dex" "$apkroot/classes.dex"
"$build_tools/aapt2" link --manifest "$here/jni_sources/a13_rt/AndroidManifest.xml" \
  -I "$platform_jar" -o "$work/a13-jni-singles.apk"
(cd "$apkroot" && zip -q -r "$work/a13-jni-singles.apk" .)
"$build_tools/zipalign" -f 4 "$work/a13-jni-singles.apk" "$out/a13-jni-singles.apk"

thumbroot="$work/thumb-apk"
mkdir -p "$thumbroot/lib/armeabi-v7a"
cp "$out/liba13rt_thumb_armeabi-v7a.so" "$thumbroot/lib/armeabi-v7a/liba13rt.so"
cp "$out/a13-jni-classes.dex" "$thumbroot/classes.dex"
"$build_tools/aapt2" link --manifest "$here/jni_sources/a13_rt/AndroidManifest.xml" \
  -I "$platform_jar" -o "$work/a13-jni-singles-thumb.apk"
(cd "$thumbroot" && zip -q -r "$work/a13-jni-singles-thumb.apk" .)
"$build_tools/zipalign" -f 4 "$work/a13-jni-singles-thumb.apk" "$out/a13-jni-singles-thumb.apk"
echo "built: liba13rt_<abi>.so (4 ABIs + thumb twin, stripped twins), liba13ctl_x86.so + liba13ctlfb_x86.so (+ stripped), liba13held (x86, thumb v7a), a13-jni-classes.dex, a13-jni-singles.apk, a13-jni-singles-thumb.apk"
