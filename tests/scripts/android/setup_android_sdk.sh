#!/usr/bin/env bash
# A0.1 — install a self-contained Android SDK in user space for the Android
# native lane. No sudo, no Homebrew casks; everything lands under
# $ANDROID_SDK_ROOT (default ~/Android/sdk), leaving any pre-existing
# ~/Library/Android/sdk untouched.
#
# Components (A0.1 contract):
#   - command-line tools (sdkmanager/avdmanager)
#   - platform-tools (adb), build-tools 36.0.0, emulator
#   - platforms android-34/35/36 (android.jar for tier-1 builds)
#   - NDK r27 line (27.3.13750724) and r28 line (28.2.13676358)
#   - google_apis (non-Play, rootable) system images, API 34-36,
#     arm64-v8a + x86_64
#
# Versions were taken from https://dl.google.com/android/repository/repository2-3.xml
# on 2026-09-24; the NDK picks are the newest r27.x and r28.x in that index.

set -euo pipefail

SDK_ROOT="${ANDROID_SDK_ROOT:-$HOME/Android/sdk}"
CMDLINE_TOOLS_BUILD="15641748"
NDK_R27="27.3.13750724"
NDK_R28="28.2.13676358"
BUILD_TOOLS="36.0.0"
API_LEVELS="34 35 36"
ABIS="arm64-v8a x86_64"

log() { printf '[setup_android_sdk] %s\n' "$*" >&2; }

mkdir -p "$SDK_ROOT"
cd "$SDK_ROOT"

if [ ! -x cmdline-tools/latest/bin/sdkmanager ]; then
  log "downloading command-line tools build $CMDLINE_TOOLS_BUILD"
  curl -fL --retry 3 -o /tmp/commandlinetools-mac.zip \
    "https://dl.google.com/android/repository/commandlinetools-mac-${CMDLINE_TOOLS_BUILD}_latest.zip"
  rm -rf cmdline-tools
  mkdir -p cmdline-tools
  unzip -q /tmp/commandlinetools-mac.zip -d cmdline-tools
  mv cmdline-tools/cmdline-tools cmdline-tools/latest
  rm /tmp/commandlinetools-mac.zip
fi

SDKMANAGER="$SDK_ROOT/cmdline-tools/latest/bin/sdkmanager"
AVDMANAGER="$SDK_ROOT/cmdline-tools/latest/bin/avdmanager"

log "accepting licenses"
"$SDKMANAGER" --sdk_root="$SDK_ROOT" --licenses >/dev/null < <(yes)

PKGS=(
  "platform-tools"
  "build-tools;${BUILD_TOOLS}"
  "emulator"
)
for api in $API_LEVELS; do
  PKGS+=("platforms;android-${api}")
done
PKGS+=("ndk;${NDK_R27}" "ndk;${NDK_R28}")
for api in $API_LEVELS; do
  for abi in $ABIS; do
    PKGS+=("system-images;android-${api};google_apis;${abi}")
  done
done

log "installing: ${PKGS[*]}"
"$SDKMANAGER" --sdk_root="$SDK_ROOT" "${PKGS[@]}" >/dev/null < <(yes)

log "creating AVDs"
# cmdline-tools 15641748 dropped --sdk_root from avdmanager; ANDROID_SDK_ROOT
# (exported here) is how it finds the SDK.
export ANDROID_SDK_ROOT="$SDK_ROOT"
for api in $API_LEVELS; do
  for abi in $ABIS; do
    if ! "$AVDMANAGER" list avd 2>/dev/null | grep -q "Name: a0-api${api}-${abi}"; then
      echo no | "$AVDMANAGER" create avd \
        --name "a0-api${api}-${abi}" \
        --package "system-images;android-${api};google_apis;${abi}" \
        --device pixel_6 >/dev/null
    fi
  done
done

log "installed versions:"
"$SDKMANAGER" --sdk_root="$SDK_ROOT" --list_installed
log "done. SDK root: $SDK_ROOT"
