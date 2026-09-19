"""Reproduces the W3.1 ground-truth comparison (ground rule 29).

The oracle is `gt.csproj`/`gtdotnet.cs` in this directory: a spec-based
System.Reflection.Metadata dumper built and run on the Windows 11 ARM64 VM
(.NET SDK 10). `gt-output.jsonl` holds the 63 records it produced (62
corpus managed files + helloexe.dll, a managed EXE built on the VM because
the corpus ships no managed executable).

This script re-parses the corpus side with blint and diffs the agreement
fields the packet commits to: assembly identity, public key token, the
full AssemblyRef list, ModuleRefs, the P/Invoke surface, entry-point
token, CLI flags and counts. Every skipped file (corpus absent) is named.

Usage: python tests/scripts/verify_dotnet_ground_truth.py
"""

import json
import sys
from pathlib import Path

import lief

from blint.lib.pe_dotnet import parse_pe_dotnet

GT_FILE = Path(__file__).parent.parent / "data" / "pe" / "dotnet-gt" / "gt-output.jsonl"
CORPUS = Path("~/sandbox/pe-corpus").expanduser()
# helloexe.dll was built on the VM, not in the corpus; the packet commit
# pastes its blint block verbatim.
INDEPENDENT = {"helloexe.dll"}


def main() -> int:
    records = [json.loads(line) for line in GT_FILE.read_text().splitlines()]
    agree = differ = skipped = 0
    for rec in records:
        rel = rec["corpus_path"]
        path = CORPUS / rel
        if not path.exists():
            print(f"SKIP {rel}: corpus file absent")
            skipped += 1
            continue
        block = parse_pe_dotnet(lief.PE.parse(str(path)), str(path))
        issues = []
        if block is None:
            issues.append("blint: no CLI header, oracle: managed")
        else:
            issues = compare(rec, block)
        if issues:
            differ += 1
            print(f"DIFF {rel}")
            for issue in issues:
                print(f"     {issue}")
        else:
            agree += 1
    print(f"agree: {agree}, differ: {differ}, skipped: {skipped}")
    return 1 if differ else 0


def compare(rec: dict, block: dict) -> list[str]:
    issues: list[str] = []
    asm = block.get("assembly", {})
    if asm.get("name") != rec.get("name"):
        issues.append(f"name {asm.get('name')!r} != {rec.get('name')!r}")
    if asm.get("version") != rec.get("version"):
        issues.append(f"version {asm.get('version')} != {rec.get('version')}")
    if asm.get("culture") != rec.get("culture"):
        issues.append(f"culture {asm.get('culture')!r} != {rec.get('culture')!r}")
    if asm.get("mvid") != rec.get("mvid"):
        issues.append(f"mvid {asm.get('mvid')} != {rec.get('mvid')}")
    # Oracle: an empty token string means no public key; blint omits it.
    oracle_pkt = rec.get("public_key_token") or None
    if asm.get("public_key_token") != oracle_pkt:
        issues.append(
            f"pkt {asm.get('public_key_token')!r} != {oracle_pkt!r}"
        )
    if block.get("cli_flags_value") != rec.get("cli_flags_value"):
        issues.append("cli_flags_value")
    if sorted(block.get("cli_flags", [])) != sorted(rec.get("cli_flags", [])):
        issues.append("cli_flags")
    if block.get("target_framework") != (rec.get("target_framework") or [None])[0]:
        issues.append(
            f"target_framework {block.get('target_framework')} != {rec.get('target_framework')}"
        )
    mine = sorted(
        (r["name"], r["version"], r.get("public_key_token", ""))
        for r in block.get("assembly_refs", [])
    )
    theirs = sorted(
        (r["name"], r["version"], r["public_key_token"])
        for r in rec.get("assembly_refs", [])
    )
    if mine != theirs:
        issues.append("assembly_refs")
    if sorted(block.get("module_refs", [])) != sorted(rec.get("module_refs", [])):
        issues.append("module_refs")
    mp = sorted(
        (e.get("module", ""), e.get("entry_point", ""), e.get("method", ""))
        for e in block.get("pinvoke", [])
    )
    gp = sorted(
        (e["module"], e["entry_point"], e["method"]) for e in rec.get("pinvoke", [])
    )
    if mp != gp:
        issues.append("pinvoke")
    counts = block.get("counts", {})
    for key in ("typedef", "methoddef", "field", "typeref", "memberref",
                "assembly_ref", "module_ref", "implmap"):
        if counts.get(key, 0) != rec["counts"].get(key):
            issues.append(f"count {key}: {counts.get(key, 0)} != {rec['counts'].get(key)}")
    if rec.get("entry_point_token", "0x00000000") != "0x00000000":
        ep = block.get("entry_point", {})
        if ep.get("token") != rec["entry_point_token"]:
            issues.append(f"entry token {ep.get('token')} != {rec['entry_point_token']}")
    return issues


if __name__ == "__main__":
    sys.exit(main())
