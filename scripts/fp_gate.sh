#!/usr/bin/env bash
# False-positive gate for blint findings (PE-lane ground rule 27).
#
# Runs blint over a corpus tier directory and reports findings per binary:
# the per-binary counts, the median, and the full per-rule histogram. This is
# the metric the tier-0 "findings count may not rise" rule is enforced with,
# so it is deliberately stable and cheap:
#   - capability reviews are skipped (--no-reviews); the metric counts rule
#     findings only
#   - no disassembly, no callgraph, no blintdb
#   - the reports directory is a throwaway temp dir unless --keep is passed
#
# Usage:
#   scripts/fp_gate.sh <tier-dir> [options]
#     --blint <path>     blint executable (default: .venv/bin/blint, then $PATH)
#     --jobs <n>         pass through to blint --jobs (default 1)
#     --keep             keep the reports dir (printed at the end)
#     --max-median <n>   exit 1 when the median exceeds n (reporting-only
#                        unless given)
#
# A binary with no findings contributes a zero to the per-binary list and to
# the median; the denominator is the number of *-metadata.json files blint
# exported, which includes binaries that produced no findings.
set -euo pipefail

TIER_DIR=""
BLINT_BIN="${BLINT_BIN:-}"
JOBS=1
KEEP=0
MAX_MEDIAN=""

while [ $# -gt 0 ]; do
  case "$1" in
    --blint) BLINT_BIN="$2"; shift ;;
    --jobs) JOBS="$2"; shift ;;
    --keep) KEEP=1 ;;
    --max-median) MAX_MEDIAN="$2"; shift ;;
    -h|--help) sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) TIER_DIR="$1" ;;
  esac
  shift
done

[ -n "$TIER_DIR" ] || { echo "usage: fp_gate.sh <tier-dir> [--blint path] [--jobs n] [--keep] [--max-median n]" >&2; exit 2; }
[ -d "$TIER_DIR" ] || { echo "not a directory: $TIER_DIR" >&2; exit 2; }

# Resolve the blint executable without assuming a poetry-managed checkout.
if [ -z "$BLINT_BIN" ]; then
  for candidate in ".venv/bin/blint" "$(pwd)/.venv/bin/blint"; do
    if [ -x "$candidate" ]; then BLINT_BIN="$candidate"; break; fi
  done
fi
if [ -z "$BLINT_BIN" ]; then
  BLINT_BIN="$(command -v blint || true)"
fi
[ -n "$BLINT_BIN" ] || { echo "blint executable not found; pass --blint <path>" >&2; exit 2; }

REPORTS_DIR="$(mktemp -d "${TMPDIR:-/tmp}/fp-gate.XXXXXX")"

cleanup() {
  if [ "$KEEP" = 1 ]; then
    echo "reports kept in: $REPORTS_DIR"
  else
    rm -rf "$REPORTS_DIR"
  fi
}
trap cleanup EXIT

# -q/--no-banner keep the run deterministic; stderr is dropped so the only
# output is the gate report itself.
"$BLINT_BIN" -q --no-banner --no-reviews --jobs "$JOBS" \
  -i "$TIER_DIR" -o "$REPORTS_DIR" >/dev/null 2>&1

TIER_LABEL="$TIER_DIR" REPORTS_DIR="$REPORTS_DIR" MAX_MEDIAN="$MAX_MEDIAN" python3 - <<'PY'
import json
import os
import statistics
import sys

tier = os.environ["TIER_LABEL"]
reports = os.environ["REPORTS_DIR"]
max_median = os.environ.get("MAX_MEDIAN") or ""

# The denominator is the run's own coverage record, not the number of
# findings.json entries: a tier is only honest when binaries that produced
# zero findings are counted too. Per-binary *-metadata.json files cannot be
# used for this — same-named binaries in different subdirectories overwrite
# each other's exports, which silently shrinks the denominator.
units = {}
coverage_path = os.path.join(reports, "analysis-coverage.json")
if os.path.exists(coverage_path):
    with open(coverage_path, "rb") as fp:
        units = (json.load(fp) or {}).get("units") or {}
total_binaries = int(units.get("succeeded") or 0)
failed_binaries = int(units.get("failed") or 0)

findings_path = os.path.join(reports, "findings.json")
findings = []
if os.path.exists(findings_path):
    with open(findings_path, "rb") as fp:
        findings = (json.load(fp) or {}).get("findings") or []

per_binary: dict[str, int] = {}
per_rule: dict[str, int] = {}
per_rule_severity: dict[str, str] = {}
for f in findings:
    name = f.get("filename") or f.get("exe_name") or "<unknown>"
    per_binary[name] = per_binary.get(name, 0) + 1
    rid = f.get("id") or "<no-id>"
    per_rule[rid] = per_rule.get(rid, 0) + 1
    per_rule_severity[rid] = str(f.get("severity") or "?")

# Binaries with zero findings enter the median as zeros, so the median is
# over the whole tier and not just the binaries that fired.
counts = list(per_binary.values()) + [0] * max(0, total_binaries - len(per_binary))
median = statistics.median(counts) if counts else 0.0

print(f"== fp_gate: {tier}")
print(
    f"binaries analyzed: {total_binaries} succeeded, {failed_binaries} failed; "
    f"total findings: {len(findings)}"
)
print(f"median findings/binary: {median}")
print(f"binaries with findings: {len(per_binary)}; with zero findings: {max(0, total_binaries - len(per_binary))}")
print("per-binary findings (only binaries that fired):")
for name, count in sorted(per_binary.items(), key=lambda kv: (-kv[1], kv[0])):
    print(f"  {count:4d}  {name}")
if per_rule:
    print("per-rule histogram:")
    for rid, count in sorted(per_rule.items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"  {count:4d}  {rid} ({per_rule_severity.get(rid, '?')})")
else:
    print("per-rule histogram: (none)")

if max_median and median > float(max_median):
    print(f"GATE FAIL: median {median} > {max_median}", file=sys.stderr)
    sys.exit(1)
PY
