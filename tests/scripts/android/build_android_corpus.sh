#!/usr/bin/env bash
# A0.2 — Android native corpus builder (bash entrypoint).
#
# Working copy of the reviewer-owned scripts/build_android_corpus.sh lane in
# ~/blint-android-native-plans; the heavy lifting lives in the python
# helpers next to this script. Tiers are run separately because tier 0 boots
# one emulator per (api, abi) system image:
#
#   build_android_corpus.sh tier1
#   build_android_corpus.sh tier4 --base-so <real ndk libhello.so>
#   for api in 34 35 36; do for abi in arm64-v8a x86_64; do
#     build_android_corpus.sh tier0 --api $api --abi $abi
#   done; done

set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"

export ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$HOME/Android/sdk}"
export ANDROID_CORPUS_ROOT="${ANDROID_CORPUS_ROOT:-$HOME/sandbox/android-corpus}"

# The python helper takes the bare tier number.
tier="${1#tier}"
shift || true
exec python3 "$here/build_android_corpus.py" "$tier" "$@"
