#!/usr/bin/env python3
"""F0.2 classification: verdict per tier-0 finding, from tools that are not blint.

For every finding in a corpus reports directory this script derives the
ground-truth fact with a named external tool and records a verdict:
``true`` (the finding states a real fact about the artifact), ``false``
(the finding is wrong or the concept cannot apply), or ``unverifiable``
(the external evidence cannot decide; the reason is recorded).

Ground-truth tools, named per corpus file in the output:
- Mach-O (host): ``otool -hv`` (filetype + PIE flag), ``otool -l``
  (LC_CODE_SIGNATURE, __objc_nlclslist section), ``otool -L`` (declared
  dependencies), ``codesign -dv`` (signature presence),
  ``dyld_info -undefined`` (undefined symbols), ``nm -gU`` (a dependency's
  exported symbols, used to test unused-dependency claims). Tool versions
  come from the host's Xcode and are recorded in the output.
- ELF (one debian:stable container with binutils): ``readelf -h`` (type),
  ``readelf -l`` (GNU_STACK flags, PT_LOAD memsz sum), ``readelf --dyn-syms``
  (__stack_chk_fail, per-symbol GLIBC_ versions, implementation-internal
  symbols). Version recorded (GNU Binutils for Debian 2.44).

Verdict rules (each stated so a reader can disagree with one):
- CHECK_PIE: applies only to main executables — a Mach-O dylib/bundle and an
  ET_REL relocatable are position-independent or loaded-by-others by
  construction, so a PIE finding there is ``false`` (rule cannot apply). An
  MH_EXECUTE without the PIE flag, or an ET_EXEC, is ``true``.
- CHECK_NX: an ET_REL object has no stack segment at all, so NX cannot apply
  (``false``); GNU_STACK with RWE is ``true``.
- CHECK_CODESIGN: no LC_CODE_SIGNATURE and ``codesign`` refusing the file is
  ``true`` of the artifact (dyld-cache extractions land here and the reason
  string says so); a signature load command present but blint firing would be
  ``false`` (blint bug).
- CHECK_CANARY: no __stack_chk_* symbol in the binary's symbol table is
  ``true``; otherwise ``false``.
- CHECK_ABI_FLOOR: readelf's highest GLIBC_ symbol version decides; agreeing
  with (or exceeding) the finding's claimed floor is ``true``, a version
  readelf cannot confirm is ``false``.
- CHECK_LIBC_PORTABILITY: every symbol the finding lists must exist in the
  binary's dynamic symbols (``true`` then); on a musl binary any listed
  glibc-internal symbol is checked against readelf the same way, and the
  libc identified by the interpreter (ld-musl vs ld-linux) is recorded with
  the verdict so the glibc-assumption question is decidable downstream.
- CHECK_UNUSED_DEPENDENCIES: a declared dependency is called unused; the
  claim is ``true`` when none of the binary's undefined symbols matches any
  of that dependency's exported symbols (resolved from the dyld extraction
  tree or the host), ``false`` when a match exists, ``unverifiable`` when
  the dependency binary cannot be located.
- CHECK_OBJC_LOAD_METHODS: a non-empty __objc_nlclslist section is ``true``.
- CHECK_RUNTIME_LOADING: ``true`` when the named library string exists in
  the file bytes (grep) — the rule reports embedded names, not verified
  dlopen behaviour — and that limitation is stated in the reason.
- CHECK_VIRTUAL_SIZE: the sum of PT_LOAD memsz from readelf; at or above the
  rule's limit is ``true``.

Where a rule fires hundreds of times the output also carries a seeded random
sample of 30 findings per rule (seed recorded), but every finding is
classified mechanically regardless.

Usage:
    python tests/scripts/fp_classify.py --corpus ~/sandbox/fp-corpus
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

DEFAULT_CORPUS = Path.home() / "sandbox" / "fp-corpus"
DEFAULT_SEED = 20260923
SAMPLE_SIZE = 30
DYLD_EXTRACT_ROOT = Path.home() / "sandbox" / "fp-corpus-work"
VERDICT_ORDER = ("true", "false", "unverifiable")


def sh(command: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True)


# --- Mach-O facts -----------------------------------------------------------


def macho_facts(path: Path) -> dict:
    facts: dict = {"kind": "macho"}
    hv = sh(["otool", "-hv", str(path)])
    facts["otool_hv"] = hv.stdout
    # Last line of `otool -hv`: magic cputype cpusubtype caps filetype ncmds
    # sizeofcmds flags... - filetype is the 5th token; the PIE flag is a word
    # in the trailing flags region.
    last_line = hv.stdout.strip().splitlines()[-1] if hv.stdout.strip() else ""
    tokens = last_line.split()
    facts["filetype"] = tokens[4] if len(tokens) >= 5 else "unknown"
    facts["pie_flag"] = bool(re.search(r"\bPIE\b", last_line))
    load = sh(["otool", "-l", str(path)]).stdout
    facts["has_code_signature"] = "LC_CODE_SIGNATURE" in load
    nl = re.search(
        r"sectname __objc_nlclslist.*?size 0x([0-9a-f]+)", load, re.DOTALL
    )
    facts["objc_nlclslist_size"] = int(nl.group(1), 16) if nl else 0
    facts["declared_dylibs"] = [
        line.strip()
        for line in sh(["otool", "-L", str(path)]).stdout.splitlines()
        if line.strip().endswith(".dylib") or "/System/" in line or "/usr/lib/" in line
    ][1:]
    codesign = sh(["codesign", "-dv", str(path)])
    facts["codesign_rc"] = codesign.returncode
    facts["codesign_not_signed"] = "not signed at all" in codesign.stderr
    return facts


def macho_undefined_symbols(path: Path) -> set[str]:
    result = sh(["dyld_info", "-undefined", str(path)])
    symbols = set()
    for line in result.stdout.splitlines():
        # rows: "0x0000_0000  flat  _symbol_name  (from libX)"
        for token in line.split():
            if token.startswith("_") and len(token) > 1:
                symbols.add(token.lstrip("_"))
    return symbols


def macho_exported_symbols(dep_path: Path) -> set[str]:
    result = sh(["nm", "-gU", str(dep_path)])
    symbols = set()
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            symbols.add(parts[-1].lstrip("_"))
    return symbols


def resolve_dependency(name: str) -> Path | None:
    base = os.path.basename(name.split(" (")[0])
    for root in (
        DYLD_EXTRACT_ROOT / "dyld-extract-arm64e",
        DYLD_EXTRACT_ROOT / "dyld-extract-x86_64",
    ):
        if not root.is_dir():
            continue
        candidates = list(root.rglob(base))
        if candidates:
            return candidates[0]
    for direct in (Path("/usr/lib"), Path("/usr/bin"), Path("/bin")):
        candidate = direct / base
        if candidate.exists():
            return candidate
    return None


# --- ELF facts (one container run) ------------------------------------------


def elf_facts_via_docker(corpus_root: Path, paths: list[str]) -> dict[str, dict]:
    script = (
        "import json, re, subprocess\n"
        f"paths = {json.dumps(paths)}\n"
        r"""
facts = {}
for path in paths:
    entry = {}
    header = subprocess.run(["readelf", "-h", path], capture_output=True, text=True).stdout
    m = re.search(r"Type:\s+(\w+)", header)
    entry["type"] = m.group(1) if m else "unknown"
    m = re.search(r"Machine:\s+(.+)", header)
    entry["machine"] = m.group(1).strip() if m else "unknown"
    load = subprocess.run(["readelf", "-l", "-W", path], capture_output=True, text=True).stdout
    gnu_stack = re.search(r"GNU_STACK\s+\S+\s+\S+\s+\S+\s+\S+\s+0x[0-9a-f]+\s+([RWE ]+)", load)
    entry["gnu_stack"] = gnu_stack.group(1).strip() if gnu_stack else None
    memsz = 0
    for m in re.finditer(r"LOAD\s+0x[0-9a-f]+\s+0x[0-9a-f]+\s+0x[0-9a-f]+\s+0x[0-9a-f]+\s+0x([0-9a-f]+)", load):
        memsz += int(m.group(1), 16)
    entry["pt_load_memsum"] = memsz
    interp = re.search(r"Requesting program interpreter: (.*?)\]", load)
    entry["interpreter"] = interp.group(1) if interp else None
    dynsyms = subprocess.run(["readelf", "--dyn-syms", "-W", path], capture_output=True, text=True).stdout
    allsyms = subprocess.run(["readelf", "--syms", "-W", path], capture_output=True, text=True).stdout
    entry["stack_chk"] = "__stack_chk" in (dynsyms if entry["type"] != "REL" else allsyms)
    entry["stack_chk_source"] = "readelf --syms (ET_REL has no .dynsym)" if entry["type"] == "REL" else "readelf --dyn-syms"
    versions = [float(v[6:].rsplit(".", 1)[0] if v[6:].count(".") > 1 else v[6:])
                for v in re.findall(r"GLIBC_[0-9.]+", dynsyms)]
    entry["max_glibc"] = max(versions) if versions else None
    internals = sorted(set(re.findall(r"(__(?:libc|isoc|stack_chk|glibc|mempcpy|strfmon)[A-Za-z0-9_]*)", dynsyms)))
    entry["internal_symbols"] = internals
    entry["dlopen_import"] = "dlopen" in dynsyms
    # readelf -W lines end with an optional "(N)" version-code column after
    # the symbol name; strip it before extracting names.
    names = set()
    for sym_source in (dynsyms, allsyms):
        for line in sym_source.splitlines():
            line = re.sub(r"\s+\(\d+\)\s*$", "", line)
            m = re.search(r"\s([_A-Za-z][A-Za-z0-9_]*)(?:@\S+)?\s*$", line)
            if m:
                names.add(m.group(1))
    entry["all_dynsym_names"] = sorted(names)
    facts[path] = entry
print(json.dumps(facts))
"""
    )
    import base64

    encoded = base64.b64encode(script.encode()).decode()
    completed = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--platform",
            "linux/arm64",
            "-v",
            f"{corpus_root}:/corpus:ro",
            "debian:stable",
            "sh",
            "-c",
            ("apt-get update >/dev/null 2>&1; apt-get install -y --no-install-recommends binutils python3 >/dev/null 2>&1; "
            "readelf --version | head -1 >&2; "
            f"echo {encoded} | base64 -d | python3 -"),
        ],
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        sys.stderr.write(completed.stderr[-2000:])
        raise SystemExit("ELF facts container run failed")
    return json.loads(completed.stdout)


# --- Verdicts ----------------------------------------------------------------


def classify_finding(
    finding: dict, rel_path: str, facts: dict, corpus_root: Path
) -> tuple[str, str]:
    """Return (verdict, reason) for one finding."""
    kind = facts.get("kind")
    if kind == "macho":
        return classify_macho_finding(finding, rel_path, facts, corpus_root)
    return classify_elf_finding(finding, rel_path, facts, corpus_root)


def classify_macho_finding(
    finding: dict, rel_path: str, facts: dict, corpus_root: Path
) -> tuple[str, str]:
    rule = finding.get("id")
    binary_path = corpus_root / rel_path
    if rule == "CHECK_PIE":
        if facts["filetype"] != "MH_EXECUTE":
            return (
                "false",
                (f"otool -hv filetype {facts['filetype']}: PIE is a property of "
                "main executables, not of dylibs/bundles/objects"),
            )
        if not facts["pie_flag"]:
            return "true", "otool -hv: MH_EXECUTE without PIE flag"
        return "false", "otool -hv: MH_EXECUTE carries the PIE flag"
    if rule == "CHECK_CODESIGN":
        if not facts["has_code_signature"] and facts["codesign_not_signed"]:
            reason = "otool -l: no LC_CODE_SIGNATURE; codesign -dv: not signed at all"
            if rel_path.startswith("macho/dyld-"):
                reason += " (dyld-cache extraction carries no signature copy)"
            return "true", reason
        if facts["has_code_signature"]:
            return "false", "otool -l shows LC_CODE_SIGNATURE but blint fired"
        return "unverifiable", f"codesign rc={facts['codesign_rc']}"
    if rule == "CHECK_OBJC_LOAD_METHODS":
        if facts["objc_nlclslist_size"] > 0:
            return "true", f"otool -l: __objc_nlclslist size 0x{facts['objc_nlclslist_size']:x}"
        return "false", "otool -l: no __objc_nlclslist section"
    if rule == "CHECK_UNUSED_DEPENDENCIES":
        undefined = macho_undefined_symbols(binary_path)
        title = str(finding.get("title") or "")
        # The finding title carries the unused dependency names.
        unused_names = [n.strip() for n in title.split("(")[-1].rstrip(")").split(",") if n.strip()]
        verdicts = []
        for name in unused_names:
            dep = resolve_dependency(name)
            if dep is None:
                verdicts.append((name, "unverifiable", "dependency binary not locatable"))
                continue
            exports = macho_exported_symbols(dep)
            overlap = undefined & exports
            if overlap:
                sample = sorted(overlap)[:3]
                verdicts.append(
                    (name, "false", f"nm -gU: {dep.name} exports {sample} which the binary imports")
                )
            else:
                verdicts.append(
                    (name, "true", f"dyld_info -undefined vs nm -gU of {dep.name}: no shared symbol")
                )
        if any(v == "false" for _, v, _ in verdicts):
            return (
                "false",
                "; ".join(f"{n}: {why}" for n, v, why in verdicts if v == "false"),
            )
        if all(v == "unverifiable" for _, v, _ in verdicts):
            return "unverifiable", "; ".join(f"{n}: {why}" for n, v, why in verdicts)
        return (
            "true",
            "; ".join(f"{n}: {why}" for n, v, why in verdicts if v == "true"),
        )
    if rule == "CHECK_CANARY":
        symbols = macho_exported_symbols(binary_path) | macho_undefined_symbols(binary_path)
        if any("stack_chk" in s for s in symbols):
            return "false", f"nm/dyld_info: stack_chk symbols present ({[s for s in symbols if 'stack_chk' in s][:2]})"
        return "true", "nm/dyld_info: no __stack_chk symbol in symtab or undefineds"
    return "unverifiable", f"no Mach-O ground truth rule for {rule}"


def classify_elf_finding(finding: dict, rel_path: str, facts: dict, corpus_root: Path) -> tuple[str, str]:
    rule = finding.get("id")
    if rule == "CHECK_PIE":
        if facts["type"] == "EXEC":
            return "true", "readelf -h: ET_EXEC (non-PIE executable)"
        if facts["type"] == "REL":
            return (
                "false",
                "readelf -h: ET_REL relocatable — PIE cannot apply to an object file",
            )
        return "false", f"readelf -h: type {facts['type']} is position-independent"
    if rule == "CHECK_NX":
        if facts["type"] == "REL":
            return (
                "false",
                "readelf -h/-l: ET_REL with no PT_GNU_STACK — no stack exists, NX cannot apply",
            )
        if facts["gnu_stack"] and "E" in facts["gnu_stack"]:
            return "true", f"readelf -l: GNU_STACK {facts['gnu_stack']} (executable)"
        if facts["gnu_stack"] is None:
            return (
                "false",
                "readelf -l: no GNU_STACK header (NX assumed by loader policy)",
            )
        return "false", f"readelf -l: GNU_STACK {facts['gnu_stack']} (not executable)"
    if rule == "CHECK_CANARY":
        if not facts["stack_chk"]:
            source = facts.get("stack_chk_source") or "readelf --dyn-syms"
            return "true", f"{source}: no __stack_chk import"
        source = facts.get("stack_chk_source") or "readelf --dyn-syms"
        return "false", f"{source}: __stack_chk present"
    if rule == "CHECK_ABI_FLOOR":
        if facts["max_glibc"] is None:
            return (
                "false",
                ("readelf --dyn-syms: no GLIBC_ version references at all "
                f"(interpreter: {facts.get('interpreter')})"),
            )
        m = re.search(r"GLIBC floor ([0-9.]+)", str(finding.get("title") or ""))
        claimed = float(m.group(1)) if m else None
        if claimed is not None and claimed > facts["max_glibc"] + 1e-9:
            return (
                "false",
                f"readelf max GLIBC_ is {facts['max_glibc']}, finding claims {claimed}",
            )
        baseline = re.search(r"baseline ([0-9.]+)", str(finding.get("title") or ""))
        baseline = baseline.group(1) if baseline else "?"
        return (
            "true",
            (f"readelf --dyn-syms: max GLIBC_{facts['max_glibc']} exceeds the "
             f"{baseline} baseline; medium when that baseline was user-set, info "
             "when it is the built-in default"),
        )
    if rule == "CHECK_LIBC_PORTABILITY":
        title = str(finding.get("title") or "")
        # F1b.2 title shape: "<kind>-specific (measured against ...): names"
        kind_match = re.search(r"\b(glibc|musl)-specific[^:]*:\s*(.*)$", title)
        if not kind_match:
            return "unverifiable", f"unrecognised title shape: {title[:80]}"
        kind = kind_match.group(1)
        listed = [s.strip() for s in kind_match.group(2).rstrip(")").split(",") if s.strip()]
        names = set(facts.get("all_dynsym_names") or [])
        missing = [s for s in listed if s.lstrip("_") not in names and s not in names]
        libc = "musl" if (facts.get("interpreter") or "").startswith("/lib/ld-musl") else (
            "glibc" if facts.get("interpreter") else "static/none"
        )
        if missing:
            return (
                "false",
                f"readelf --dyn-syms: listed symbols absent from the binary: {missing[:5]}",
            )
        if libc not in (kind, "static/none"):
            return (
                "false",
                (f"interpreter says {libc} but the finding labels the interfaces "
                 f"{kind}-specific"),
            )
        return (
            "true",
            (f"readelf --dyn-syms confirms the listed symbols; the {kind}-only claim was "
             "measured against the exported symbol lists of glibc 2.41 (debian libc6 "
             "2.41-12+deb13u4) and musl 1.2.6 (alpine musl-1.2.6-r2), readelf --dyn-syms "
             f"on each (libc: {libc})"),
        )
    if rule == "CHECK_VIRTUAL_SIZE":
        mib = facts["pt_load_memsum"] / 1024 / 1024
        # F1b.3: per-format limits - 128MB ELF (benign corpus max 37.4 MiB, a
        # stock static Go build), 30MB default otherwise.
        limit = 128 if facts.get("type") in ("EXEC", "DYN", "REL") else 30
        if mib >= limit:
            return (
                "true",
                (f"readelf -l: PT_LOAD memsz sum {mib:.0f} MiB at or above the "
                 f"{limit}MB ELF limit"),
            )
        return (
            "false",
            f"readelf -l: PT_LOAD memsz sum {mib:.0f} MiB below the {limit}MB limit",
        )
    if rule == "CHECK_RUNTIME_LOADING":
        title = str(finding.get("title") or "")
        # F1b.4 title shape: "library-name strings (a, b) paired with imported
        # loader entry points (dlopen); the strings are evidence, not observed loads"
        m = re.search(r"library-name strings \(([^)]*)\).*entry points \(([^)]*)\)", title)
        if not m:
            return "unverifiable", f"unrecognised title shape: {title[:80]}"
        listed = [s.strip() for s in m.group(1).split(",") if s.strip()]
        entry_points = [s.strip() for s in m.group(2).split(",") if s.strip()]
        if not listed:
            return "unverifiable", "finding lists no library names"
        verdicts = []
        for name in listed:
            grep = sh(["grep", "-c", name, str(corpus_root / rel_path)])
            verdicts.append((name, grep.returncode == 0))
        missing = [n for n, found in verdicts if not found]
        if missing:
            return "false", f"named library strings absent from the file: {missing}"
        imported = [ep for ep in entry_points if ep in set(facts.get("all_dynsym_names") or [])]
        if not imported:
            return (
                "false",
                (f"readelf --dyn-syms: none of the claimed entry points {entry_points} "
                 "is imported"),
            )
        return (
            "true",
            (f"the named library strings exist in the file bytes (grep) and readelf "
             f"--dyn-syms confirms {imported} is imported; the finding states string "
             "evidence, not an observed load"),
        )
    return "unverifiable", f"no ELF ground truth rule for {rule}"


# --- Driver ------------------------------------------------------------------


def tool_versions() -> dict[str, str]:
    versions = {}
    xcodebuild = sh(["xcodebuild", "-version"])
    versions["xcode"] = " ".join(xcodebuild.stdout.split("\n")[:1])
    versions["otool_dyld_info_nm_codesign"] = (
        f"Xcode toolchain ({versions['xcode'] or 'unknown'})"
    )
    versions["file"] = sh(["file", "--version"]).stdout.splitlines()[0]
    return versions


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--reports", default=None)
    args = parser.parse_args()

    corpus_root = Path(args.corpus).expanduser().resolve()
    reports_dir = Path(args.reports).expanduser() if args.reports else corpus_root / "reports"
    findings = json.loads((reports_dir / "findings.json").read_text())["findings"]
    manifest = json.loads((corpus_root / "MANIFEST.json").read_text())
    by_realpath = {os.path.realpath(corpus_root / e["path"]): e for e in manifest}

    macho_paths, elf_paths = [], []
    for finding in findings:
        entry = by_realpath.get(os.path.realpath(finding["filename"]))
        if not entry:
            continue
        rel = entry["path"]
        if rel.startswith("macho/") and rel not in macho_paths:
            macho_paths.append(rel)
        elif rel.startswith("elf/") and rel not in elf_paths:
            elf_paths.append(rel)

    print(f"[facts] Mach-O files: {len(macho_paths)}, ELF files: {len(elf_paths)}")
    facts_cache_path = reports_dir / "fp-classify-facts.json"
    facts: dict[str, dict] = {}
    if facts_cache_path.exists():
        facts = json.loads(facts_cache_path.read_text())
    missing_macho = [p for p in macho_paths if p not in facts]
    missing_elf = [p for p in elf_paths if p not in facts]
    if missing_macho:
        for i, rel in enumerate(missing_macho):
            facts[rel] = macho_facts(corpus_root / rel)
            if (i + 1) % 50 == 0:
                print(f"[facts] macho {i + 1}/{len(missing_macho)}")
    if missing_elf:
        elf_facts = elf_facts_via_docker(
            corpus_root, [f"/corpus/{p}" for p in missing_elf]
        )
        for container_path, entry in elf_facts.items():
            facts[container_path.removeprefix("/corpus/")] = entry
    facts_cache_path.write_text(json.dumps(facts, indent=1, sort_keys=True))

    records = []
    for finding in findings:
        entry = by_realpath.get(os.path.realpath(finding["filename"]))
        if not entry:
            records.append(
                {"rule": finding.get("id"), "path": None, "verdict": "unverifiable",
                 "reason": "finding does not map to a manifest entry"}
            )
            continue
        rel = entry["path"]
        verdict, reason = classify_finding(finding, rel, facts.get(rel, {}), corpus_root)
        records.append(
            {
                "rule": finding.get("id"),
                "severity": finding.get("severity"),
                "path": rel,
                "title": finding.get("title"),
                "verdict": verdict,
                "reason": reason,
            }
        )

    summary: dict = {"seed": args.seed, "tools": tool_versions(), "rules": {}}
    by_rule: dict[str, list] = defaultdict(list)
    for record in records:
        by_rule[record["rule"]].append(record)
    rng = random.Random(args.seed)
    for rule in sorted(by_rule):
        rule_records = by_rule[rule]
        verdicts = Counter(r["verdict"] for r in rule_records)
        false_reasons = Counter(
            r["reason"] for r in rule_records if r["verdict"] == "false"
        )
        sample = (
            rng.sample(rule_records, SAMPLE_SIZE)
            if len(rule_records) > SAMPLE_SIZE
            else rule_records
        )
        summary["rules"][rule] = {
            "total": len(rule_records),
            "true": verdicts.get("true", 0),
            "false": verdicts.get("false", 0),
            "unverifiable": verdicts.get("unverifiable", 0),
            "distinct_false_reasons": dict(false_reasons),
            "sample": [
                {"path": r["path"], "verdict": r["verdict"], "reason": r["reason"]}
                for r in sample
            ],
        }
    out_path = reports_dir / "fp-classify.json"
    out_path.write_text(json.dumps(summary, indent=1, sort_keys=True) + "\n")
    (reports_dir / "fp-classify-records.json").write_text(
        json.dumps(records, indent=1) + "\n"
    )
    print(f"\n{'rule':<32}{'total':>7}{'true':>7}{'false':>7}{'unver':>7}")
    for rule, data in summary["rules"].items():
        print(
            f"{rule:<32}{data['total']:>7}{data['true']:>7}{data['false']:>7}"
            f"{data['unverifiable']:>7}"
        )
    print(f"\nwrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
