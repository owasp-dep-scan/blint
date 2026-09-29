#!/usr/bin/env bash
# A7.2 — the callgraph KPI suite over all 11 wasm-tools-1.247.0
# architectures (AGENTS.md policy: every architecture entry in
# tests/data/callgraph-kpi/wasm-tools-1.247.0-baseline.json, both
# --baseline and --labels).
#
# Usage: bash tests/scripts/android/a7_2_kpi_suite.sh [report-dir]
set -uo pipefail

export PATH="/opt/homebrew/opt/llvm@18/bin:$PATH"
export NYXSTONE_LLVM_PREFIX=/opt/homebrew/opt/llvm@18
cd "$(dirname "$0")/../../.."

reports="${1:-/tmp/a7m0/kpi}"
mkdir -p "$reports"
native="$HOME/sandbox/rust-binaries/wasm-tools-1.247.0"
android="$HOME/sandbox/rust-binaries"

status=0
run() {  # run <platform> <binary>
  local platform="$1" binary="$2"
  local out
  out=$(poetry run python tests/scripts/callgraph_kpi_baseline.py \
    --binary "$binary" --baseline tests/data/callgraph-kpi/wasm-tools-1.247.0-baseline.json \
    --labels tests/data/callgraph-kpi/wasm-tools-1.247.0-labels.json \
    --output "$reports/${platform}.json" 2>&1)
  local rc=$?
  echo "== $platform (rc=$rc)"
  if [ $rc -ne 0 ] || echo "$out" | grep -q "regressions:"; then
    echo "$out" | tail -25
    status=1
  else
    echo "$out" | grep -E "functions_total|internal_edges|external_edges|recall|precision" | head -6
  fi
}

run aarch64-apple-macosx        "$native/wasm-tools-1.247.0-aarch64-macos/wasm-tools"
run aarch64-pc-windows-msvc     "$native/wasm-tools-1.247.0-aarch64-windows/wasm-tools.exe"
run aarch64-unknown-linux-android "$android/wasm-tools-1.247.0-android-aarch64-linux-android"
run aarch64-unknown-linux-gnu   "$native/wasm-tools-1.247.0-aarch64-linux/wasm-tools"
run arm-unknown-linux-android   "$android/wasm-tools-1.247.0-android-armv7-linux-androideabi"
run i686-unknown-linux-android  "$android/wasm-tools-1.247.0-android-i686-linux-android"
run riscv64-unknown-linux-gnu   "$native/wasm-tools-1.247.0-riscv64-linux/wasm-tools"
run x86_64-apple-macosx         "$native/wasm-tools-1.247.0-x86_64-macos/wasm-tools"
run x86_64-pc-windows-msvc      "$native/wasm-tools-1.247.0-x86_64-windows/wasm-tools.exe"
run x86_64-unknown-linux-android "$android/wasm-tools-1.247.0-android-x86_64-linux-android"
run x86_64-unknown-linux-gnu    "$native/wasm-tools-1.247.0-x86_64-linux/wasm-tools"

exit $status
