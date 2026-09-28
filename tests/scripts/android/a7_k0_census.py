#!/usr/bin/env python3
"""A7 K0 — the native capability-signal census, through blint's own metadata.

The reviewer measured the corpus with ``llvm-nm`` / raw printable-run reads /
``llvm-objdump`` (numbers in GLM-PROMPT.md, table 1). This script reproduces
the census the only way the coming rules can see it: through ``parse()``
metadata — ``dynamic_symbols`` (which is where an ELF's imports ride; the
``imports`` key is empty for Android ``.so`` files) and the gated ``strings``
list — and, for the benign carriers, through the exported
``call_site_arguments`` block behind ``--disassemble``.

Subcommands (each writes one JSON part beside this script):

- ``census``    — signal counts over the deduped tier-0 api36 set and the
                  tier-2/3 app libraries, plus the raw-vs-gated string
                  survival table (which probe strings the extractor drops).
- ``carriers``  — per benign carrier, what ``call_site_arguments`` recovers
                  today at the rule-relevant callees, with wall time.
- ``baseline``  — what the existing review rules report today per rule id on
                  the tier-0 and app-library sets, and the median findings
                  per library (the K3 gate's comparison point).
- ``svc``       — for every ``svc`` carrier, the functions holding the sites.

Measurement only: this packet changes nothing under ``blint/``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tempfile
import time
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from blint.config import BlintOptions
from blint.lib.analysis import initialize_rules
from blint.lib.binary import parse
from blint.lib.review_runner import ReviewRunner

CORPUS = Path.home() / "sandbox" / "android-corpus"
TIER0_API36 = CORPUS / "tier0-system" / "api36-arm64-v8a"
APP_DIRS = ("tier2-fdroid", "tier3-frameworks", "tier3-builds")

# The reviewer's table 1, for the side-by-side in the results file.
REVIEWER_NUMBERS = {
    "tier0_files": 1157,
    "app_files": 73,
    "ptrace_import": {"app": 1, "tier0": 6},
    "proc_maps_string": {"app": 7, "tier0": 25},
    "proc_status_tracerpid": {"app": 0, "tier0": 2},
    "su_path_string": {"app": 0, "tier0": 2},
    "system_property_import": {"app": 44, "tier0": 475},
    "emulator_tokens": {"app": 2, "tier0": 0},
    "dlopen_import": {"app": 20, "tier0": 82},
    "data_local_tmp_string": {"app": 9, "tier0": 22},
    "frida_substring": {"app": 13, "tier0": 6},
}

SU_PATH_RE = re.compile(
    r"/(?:system/(?:x)?bin|sbin|su/bin|vendor/bin|system/sd/(?:x)?bin|magisk)/su\b"
)
PROC_MAPS_RE = re.compile(r"/proc/(?:self|%[ds]|%u|\d+)/maps")
FRIDA_RE = re.compile(r"frida", re.IGNORECASE)

# The benign carriers, named in the reviewer's table. Tier-0 paths are the
# api36 copies; app carriers name the APK + member. Anything absent is
# skipped and reported as skipped, never guessed.
TIER0_CARRIERS = {
    "libunwindstack.so": "_system_lib64/system_lib64_libunwindstack.so",
    "libmemunreachable.so": "_system_lib64/system_lib64_libmemunreachable.so",
    "libc_malloc_debug.so": "_apex/com.android.runtime/lib64/libc_malloc_debug.so",
    "libfdtrack.so": "_system_lib64/system_lib64_libfdtrack.so",
    "libart.so": "_apex/com.android.art/lib64/libart.so",
    "libc.so": "_apex/com.android.runtime/lib64/libc.so",
    "libbluetooth_jni.so": "_apex/com.android.bt/lib64/libbluetooth_jni.so",
    "libchrome.so": "_system_lib64/system_lib64_libchrome.so",
    "libdumpstateutil.so": "_system_lib64/system_lib64_libdumpstateutil.so",
    "libclang_rt.asan.so": "_system_lib64/system_lib64_libclang_rt.asan-aarch64-android.so",
    "libclang_rt.hwasan.so": "_apex/com.android.runtime/lib64/libclang_rt.hwasan-aarch64-android.so",
    "libclang_rt.ubsan.so": (
        "_system_lib64/system_lib64_libclang_rt.ubsan_standalone-aarch64-android.so"
    ),
}
APP_CARRIERS = {
    "libsentry.so": ("tier2-fdroid/im.vector.app_40106622.apk", "lib/arm64-v8a/libsentry.so"),
    "libjnidispatch.so": (
        "tier2-fdroid/im.vector.app_40106622.apk",
        "lib/arm64-v8a/libjnidispatch.so",
    ),
    "libmozglue.so": (
        "tier2-fdroid/org.mozilla.fennec_fdroid_1560020.apk",
        "lib/arm64-v8a/libmozglue.so",
    ),
    "libxul.so": ("tier2-fdroid/org.mozilla.fennec_fdroid_1560020.apk", "lib/arm64-v8a/libxul.so"),
    "libvlc.so": ("tier2-fdroid/org.videolan.vlc_13070106.apk", "lib/arm64-v8a/libvlc.so"),
    "libflutter.so": (
        "tier2-fdroid/com.adilhanney.saber_1360102.apk",
        "lib/arm64-v8a/libflutter.so",
    ),
}

# Callees whose recovered constants the K2 candidates would read.
RULE_CALLEES = {
    "ptrace": {"ptrace"},
    "open_family": {"open", "open64", "fopen", "fopen64", "openat"},
    "access_stat": {"access", "stat", "stat64", "lstat", "fstat", "__xstat"},
    "exec_family": {"execve", "execv", "execl", "execlp", "execvp", "popen", "system"},
    "system_property": {"__system_property_get", "__system_property_find"},
    "dlopen_family": {"dlopen", "dlvsym", "android_dlopen_ext", "android_load_sphal"},
}

SVC_CONTEXT_LINES = 6


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tier0_unique_files(tier0_dir: Path) -> list[dict]:
    """The deduped .so set of one system image, per its MANIFEST.json."""
    manifest = json.loads((tier0_dir / "MANIFEST.json").read_text(encoding="utf-8"))
    seen: dict[str, dict] = {}
    for entry in manifest.get("entries", []):
        name = entry.get("file", "")
        if not name.endswith(".so"):
            continue
        if entry["sha256"] in seen:
            continue
        seen[entry["sha256"]] = {
            "path": str(tier0_dir / name),
            "sha256": entry["sha256"],
            "member": name,
        }
    return sorted(seen.values(), key=lambda item: item["member"])


def extract_app_libs(out_dir: Path) -> list[dict]:
    """Every unique arm64 .so member of the tier-2/3 APKs, extracted once."""
    seen: dict[str, dict] = {}
    for rel in APP_DIRS:
        app_dir = CORPUS / rel
        if not app_dir.is_dir():
            continue
        for apk in sorted(app_dir.glob("*.apk")):
            try:
                with zipfile.ZipFile(apk) as zf:
                    for info in zf.infolist():
                        name = info.filename
                        if not (name.startswith("lib/arm64-v8a/") and name.endswith(".so")):
                            continue
                        data = zf.read(info)
                        digest = hashlib.sha256(data).hexdigest()
                        if digest in seen:
                            continue
                        target = out_dir / f"{digest[:16]}-{Path(name).name}"
                        target.write_bytes(data)
                        seen[digest] = {
                            "path": str(target),
                            "sha256": digest,
                            "member": f"{apk.name}!{name}",
                        }
            except zipfile.BadZipFile:
                print(f"skip unreadable apk {apk}", file=sys.stderr)
    return sorted(seen.values(), key=lambda item: item["member"])


def materialize_carriers(out_dir: Path) -> dict[str, str]:
    """Copy the named carriers into out_dir; missing ones are skipped loudly."""
    carriers: dict[str, str] = {}
    for name, rel in TIER0_CARRIERS.items():
        path = TIER0_API36 / rel
        if path.is_file():
            carriers[name] = str(path)
        else:
            print(f"carrier absent (skipped): {name} at {path}", file=sys.stderr)
    for name, (apk_rel, member) in APP_CARRIERS.items():
        apk = CORPUS / apk_rel
        try:
            with zipfile.ZipFile(apk) as zf:
                data = zf.read(member)
        except (KeyError, OSError, zipfile.BadZipFile):
            print(f"carrier absent (skipped): {name} in {apk_rel}", file=sys.stderr)
            continue
        target = out_dir / f"carrier-{name}"
        target.write_bytes(data)
        carriers[name] = str(target)
    return carriers


def metadata_import_names(metadata: dict) -> set[str]:
    """Import names the metadata exposes (ELF keeps them in dynamic_symbols)."""
    names = set()
    for entry in metadata.get("imports") or []:
        if isinstance(entry, dict) and entry.get("name"):
            names.add(str(entry["name"]))
    for entry in metadata.get("dynamic_symbols") or []:
        if isinstance(entry, dict) and entry.get("name") and entry.get("is_imported"):
            names.add(str(entry["name"]))
    return names


def metadata_string_values(metadata: dict) -> list[str]:
    values = []
    for item in metadata.get("strings") or []:
        value = item.get("value", "") if isinstance(item, dict) else str(item)
        if value:
            values.append(value)
    return values


def census_signals(metadata: dict) -> dict:
    imports = metadata_import_names(metadata)
    strings = metadata_string_values(metadata)
    blob = "\n".join(strings)
    return {
        "ptrace_import": "ptrace" in imports,
        "proc_maps_string": bool(PROC_MAPS_RE.search(blob)),
        "proc_status_and_tracerpid": "/proc/self/status" in blob and "TracerPid" in blob,
        "su_path_string": bool(SU_PATH_RE.search(blob)),
        "system_property_import": any(
            name.startswith("__system_property") for name in imports
        ),
        "emulator_token_string": "goldfish" in blob.lower() or "ranchu" in blob.lower(),
        "dlopen_import": bool(
            imports & {"dlopen", "android_dlopen_ext", "android_load_sphal"}
        ),
        "data_local_tmp_string": "/data/local/tmp" in blob,
        "frida_substring": bool(FRIDA_RE.search(blob)),
    }


RAW_PROBES = {
    "proc_maps": PROC_MAPS_RE,
    "proc_status": re.compile(r"/proc/self/status"),
    "tracerpid": re.compile(r"TracerPid"),
    "su_path": SU_PATH_RE,
    "data_local_tmp": re.compile(r"/data/local/tmp"),
    "emulator_token": re.compile(r"goldfish|ranchu", re.IGNORECASE),
    "property_name": re.compile(r"ro\.kernel\.qemu|ro\.hardware\b|ro\.build\.version\.sdk"),
    "system_bin_sh": re.compile(r"/system/bin/sh"),
    "frida": FRIDA_RE,
}


def raw_string_survival(path: str, metadata: dict) -> dict:
    """For each probe family: present in the raw strings vs kept by the gates.

    The raw side is blint's own extractor before the gates
    (``binary_strings``); the kept side is the metadata ``strings`` list the
    reviews read. A family present raw in N files and kept in M < N names the
    strings the review path cannot see.
    """
    import lief

    parsed = lief.ELF.parse(path)
    if parsed is None or isinstance(parsed, lief.lief_errors):
        return {}
    from blint.lib.binary_common import binary_strings, coerce_to_text

    raw_values = [coerce_to_text(s) for s in binary_strings(parsed)]
    kept = set(metadata_string_values(metadata))
    result = {}
    for family, pattern in RAW_PROBES.items():
        raw_hits = {v for v in raw_values if v and pattern.search(v)}
        if not raw_hits:
            continue
        kept_hits = {v for v in raw_hits if v in kept}
        result[family] = {
            "files_raw": 1,
            "examples_raw": sorted(raw_hits)[:4],
            "examples_kept": sorted(kept_hits)[:4],
            "kept": bool(kept_hits),
        }
    return result


def load_metadata(path: str) -> dict:
    return parse(path)


def cmd_census(args: argparse.Namespace) -> dict:
    with tempfile.TemporaryDirectory(prefix="a7_k0_census_") as tmp:
        app_files = extract_app_libs(Path(tmp)) if not args.no_apps else []
        tier0_files = tier0_unique_files(Path(args.tier0)) if not args.no_tier0 else []
        sets = {"tier0": tier0_files, "app": app_files}
        result = {"reviewer_numbers": REVIEWER_NUMBERS, "sets": {}}
        for label, files in sets.items():
            counts: dict[str, int] = {}
            carriers: dict[str, list[str]] = {}
            survival: dict[str, dict] = {}
            frida_words: set[str] = set()
            for index, item in enumerate(files):
                if args.limit and index >= args.limit:
                    break
                metadata = load_metadata(item["path"])
                if metadata.get("binary_type") != "ELF":
                    continue
                signals = census_signals(metadata)
                if args.frida_words:
                    for value in metadata_string_values(metadata):
                        if match := FRIDA_RE.search(value):
                            start = max(0, match.start() - 12)
                            frida_words.add(value[start : match.end() + 12])
                for key, fired in signals.items():
                    counts[key] = counts.get(key, 0) + (1 if fired else 0)
                    if fired:
                        carriers.setdefault(key, []).append(Path(item["member"]).name)
                if args.survival:
                    for family, info in raw_string_survival(item["path"], metadata).items():
                        bucket = survival.setdefault(family, {"files_raw": 0, "files_kept": 0})
                        bucket["files_raw"] += 1
                        bucket["files_kept"] += 1 if info["kept"] else 0
                        if not info["kept"] and bucket["files_raw"] <= 200:
                            bucket.setdefault("lost_examples", [])
                            if info["examples_raw"] and len(bucket["lost_examples"]) < 8:
                                bucket["lost_examples"].extend(info["examples_raw"][:2])
            result["sets"][label] = {
                "files_measured": min(len(files), args.limit or len(files)),
                "signal_counts": counts,
                "carriers": {key: sorted(set(names)) for key, names in carriers.items()},
                "string_survival": survival,
            }
            if frida_words:
                result["sets"][label]["frida_substring_contexts"] = sorted(frida_words)[:40]
    return result


def cmd_carriers(args: argparse.Namespace) -> dict:
    with tempfile.TemporaryDirectory(prefix="a7_k0_carriers_") as tmp:
        carriers = materialize_carriers(Path(tmp))
        result = {}
        for name, path in sorted(carriers.items()):
            start = time.monotonic()
            metadata = parse(path, True)
            elapsed = round(time.monotonic() - start, 2)
            entries = metadata.get("call_site_arguments") or []
            coverage = metadata.get("call_site_arguments_coverage") or {}
            recovered = {}
            for entry in entries:
                callee = str(entry.get("callee") or "")
                for family, members in RULE_CALLEES.items():
                    if callee.lower() in members:
                        bucket = recovered.setdefault(
                            family,
                            {
                                "entries": [],
                                "resolved_strings": [],
                                "unresolved_constants": 0,
                            },
                        )
                        record = {
                            "callee": callee,
                            "argument": entry.get("argument"),
                            "value": entry.get("value"),
                            "string": entry.get("string"),
                            "site_count": entry.get("site_count"),
                            "functions": entry.get("functions"),
                        }
                        bucket["entries"].append(record)
                        if entry.get("string"):
                            bucket["resolved_strings"].append(entry["string"])
                        elif isinstance(entry.get("value"), int):
                            bucket["unresolved_constants"] += 1
            result[name] = {
                "wall_time_disassemble_s": elapsed,
                "functions": len(metadata.get("functions") or []),
                "disassembled_functions": len(metadata.get("disassembled_functions") or {}),
                "callsite_entries": len(entries),
                "callsite_coverage": {
                    key: coverage.get(key)
                    for key in (
                        "functions_total",
                        "functions_dataflow",
                        "functions_no_abi",
                        "entries",
                        "entries_truncated",
                        "strings_resolved",
                    )
                },
                "recovered": recovered,
            }
            print(f"{name}: {elapsed}s, {len(entries)} callsite entries")
    return result


def cmd_baseline(args: argparse.Namespace) -> dict:
    initialize_rules(BlintOptions())
    with tempfile.TemporaryDirectory(prefix="a7_k0_baseline_") as tmp:
        app_files = extract_app_libs(Path(tmp)) if not args.no_apps else []
        tier0_files = tier0_unique_files(Path(args.tier0)) if not args.no_tier0 else []
        result = {"per_rule": {}, "per_library_findings": {}}
        for label, files in (("tier0", tier0_files), ("app", app_files)):
            per_rule: dict[str, int] = {}
            findings_per_library: list[int] = []
            fired_files = 0
            for index, item in enumerate(files):
                if args.limit and index >= args.limit:
                    break
                metadata = load_metadata(item["path"])
                if metadata.get("binary_type") != "ELF":
                    continue
                runner = ReviewRunner()
                runner.run_review(metadata)
                rule_count = 0
                for rule_id in runner.results:
                    per_rule[rule_id] = per_rule.get(rule_id, 0) + 1
                    rule_count += 1
                findings_per_library.append(rule_count)
                fired_files += 1
            findings_per_library.sort()
            median = (
                findings_per_library[len(findings_per_library) // 2]
                if findings_per_library
                else 0
            )
            result["per_rule"][label] = dict(sorted(per_rule.items()))
            result["per_library_findings"][label] = {
                "libraries": fired_files,
                "median_rules_fired_per_library": median,
                "mean_rules_fired_per_library": round(
                    sum(findings_per_library) / fired_files, 3
                )
                if fired_files
                else 0,
                "libraries_with_zero_findings": findings_per_library.count(0),
            }
            print(f"{label}: {fired_files} libraries, median {median}")
        if args.sample_timing:
            sample = {}
            with tempfile.TemporaryDirectory(prefix="a7_k0_timing_") as tmp2:
                carriers = materialize_carriers(Path(tmp2))
                for name in args.sample_timing:
                    if name not in carriers:
                        continue
                    start = time.monotonic()
                    parse(carriers[name], False)
                    plain = round(time.monotonic() - start, 2)
                    start = time.monotonic()
                    parse(carriers[name], True)
                    disasm = round(time.monotonic() - start, 2)
                    sample[name] = {"parse_s": plain, "parse_disassemble_s": disasm}
                    print(f"{name}: plain {plain}s, --disassemble {disasm}s")
            result["sample_timing"] = sample
    return result


def cmd_svc(args: argparse.Namespace) -> dict:

    svc_re = re.compile(r"\bsvc\s+#?0\b")
    with tempfile.TemporaryDirectory(prefix="a7_k0_svc_") as tmp:
        carriers = materialize_carriers(Path(tmp))
        result = {}
        for name, path in sorted(carriers.items()):
            if args.only and name not in args.only:
                continue
            metadata = parse(path, True)
            disassembled = metadata.get("disassembled_functions") or {}
            if not disassembled:
                continue
            holders = []
            for key, func_data in disassembled.items():
                assembly = str(func_data.get("assembly") or "")
                lines = assembly.split("\n")
                hits = [i for i, line in enumerate(lines) if svc_re.search(line)]
                if not hits:
                    continue
                holder = {
                    "function": str(func_data.get("name") or key),
                    "address": func_data.get("address"),
                    "sites": len(hits),
                    "example_lines": [],
                }
                if name == "libxul.so" or args.context:
                    line = hits[0]
                    holder["example_lines"] = lines[max(0, line - SVC_CONTEXT_LINES) : line + 2]
                holders.append(holder)
            if holders:
                result[name] = {
                    "site_total": sum(holder["sites"] for holder in holders),
                    "functions_holding_sites": holders[: args.max_functions or 40],
                    "functions_holding_sites_count": len(holders),
                }
                print(f"{name}: {sum(h['sites'] for h in holders)} sites in {len(holders)} functions")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--tier0", default=str(TIER0_API36), help="tier-0 system image directory"
    )
    parser.add_argument("--limit", type=int, default=0, help="cap files per set (0 = all)")
    parser.add_argument("--no-apps", action="store_true")
    parser.add_argument("--no-tier0", action="store_true")
    parser.add_argument(
        "--survival", action="store_true", help="census: measure raw-vs-gated string survival"
    )
    parser.add_argument(
        "--frida-words", action="store_true", help="census: collect frida substring contexts"
    )
    parser.add_argument(
        "--sample-timing",
        nargs="*",
        default=None,
        help="baseline: time parse ± disassembly on these carriers",
    )
    parser.add_argument("--context", action="store_true", help="svc: context for every carrier")
    parser.add_argument("--only", nargs="*", help="svc: only these carriers")
    parser.add_argument("--max-functions", type=int, default=40)
    parser.add_argument("command", choices=["census", "carriers", "baseline", "svc"])
    args = parser.parse_args()
    handlers = {
        "census": cmd_census,
        "carriers": cmd_carriers,
        "baseline": cmd_baseline,
        "svc": cmd_svc,
    }
    result = handlers[args.command](args)
    out = Path(__file__).parent / f"a7-k0-{args.command}.json"
    # ``svc`` runs are per-carrier in practice (the heavy ones take tens of
    # minutes each), so a result file that already exists is merged into
    # rather than replaced - a rerun with --only keeps the other carriers.
    if args.command == "svc" and out.is_file():
        try:
            existing = json.loads(out.read_text(encoding="utf-8"))
            if isinstance(existing, dict):
                existing.update(result)
                result = existing
        except ValueError:
            pass
    out.write_text(json.dumps(result, indent=1, sort_keys=True), encoding="utf-8")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
