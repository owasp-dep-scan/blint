"""Reproduces the W3.1/W3.2 ground-truth comparison (ground rule 29).

The oracle is `gt.csproj`/`gtdotnet.cs` in this directory: a spec-based
System.Reflection.Metadata dumper built and run on the Windows 11 ARM64 VM
(.NET SDK 10) and, since it is plain .NET, anywhere else an SDK exists.
`gt-output.jsonl` holds the 63 records it produced (62 corpus managed files
+ helloexe.dll, a managed EXE built on the VM because the corpus ships no
managed executable).

This script re-parses the corpus side with blint and diffs the agreement
fields the packet commits to: assembly identity, public key token, the
full AssemblyRef list, ModuleRefs, the P/Invoke surface, entry-point
token, CLI flags and counts. Every skipped file (corpus absent) is named.

W3.2 adds three more compared groups whenever the records carry them —
resolved TypeRefs (``typerefs``), rendered MemberRefs (``memberrefs``) and
the #US walk (``user_strings_count``/``user_strings_sha256``). The shipped
63-record file predates those fields, so the extended comparison needs a
fresh record set, which the oracle now also produces on this machine:

    dotnet run -c Release --project tests/data/pe/dotnet-gt/gt.csproj -- \\
        ~/sandbox/pe-corpus/tier0-reference ~/sandbox/pe-corpus/tier1-ecosystem \\
        ~/sandbox/pe-corpus/tier2-managed ~/sandbox/pe-corpus/tier5-system \\
        > /tmp/gt-corpus-w32.jsonl
    dotnet run -c Release --project tests/data/pe/dotnet-gt/gt.csproj -- \\
        /usr/local/share/dotnet/shared > /tmp/gt-framework-w32.jsonl
    python tests/scripts/verify_dotnet_ground_truth.py /tmp/gt-corpus-w32.jsonl
    python tests/scripts/verify_dotnet_ground_truth.py /tmp/gt-framework-w32.jsonl

Usage: python tests/scripts/verify_dotnet_ground_truth.py [records.jsonl]

The default record set is the 63 corpus files, and W3.1's review showed
that set is too narrow to be a gate on its own: every one of its
assemblies happened to sit on the same side of a coded-index column-width
threshold, so it agreed 63/63 while two real framework assemblies parsed
to a fabricated identity. Pass a jsonl produced by pointing the oracle at
a larger tree to widen it — records may name their subject as
``corpus_path`` (relative to the corpus root) or as ``file`` (absolute),
which is what the oracle emits when run over an arbitrary directory.
"""

import json
import sys
from pathlib import Path

import lief

from blint.lib.pe_dotnet import (
    MAX_LISTED_MEMBERREFS,
    MAX_LISTED_PINVOKE,
    MAX_LISTED_TYPEREFS,
    parse_pe_dotnet,
)

GT_FILE = Path(__file__).parent.parent / "data" / "pe" / "dotnet-gt" / "gt-output.jsonl"
CORPUS = Path("~/sandbox/pe-corpus").expanduser()
# helloexe.dll was built on the VM, not in the corpus; the packet commit
# pastes its blint block verbatim.
INDEPENDENT = {"helloexe.dll"}
# Listing caps: the oracle dumps whole tables, blint lists a capped prefix,
# so the comparison slices the oracle's rows through the same window. These
# are imported rather than restated — they were literals here, and a cap
# changed in the parser left the oracle comparing against the old window
# while still reporting agreement (ground rule 21).


def main() -> int:
    source = Path(sys.argv[1]) if len(sys.argv) > 1 else GT_FILE
    records = [json.loads(line) for line in source.read_text().splitlines()]
    agree = differ = skipped = 0
    for rec in records:
        if "corpus_path" in rec:
            rel = rec["corpus_path"]
            path = CORPUS / rel
        else:
            rel = rec["file"]
            path = Path(rel)
        if not path.exists():
            print(f"SKIP {rel}: file absent")
            skipped += 1
            continue
        if rec.get("status") not in (None, "managed"):
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
    if len(gp) > MAX_LISTED_PINVOKE:
        # Above the listing cap blint's window is the ImplMap-table prefix,
        # which the oracle cannot reconstruct (it walks MethodDefinitions,
        # so its list has no window to slice). The agreement claim degrades
        # honestly: every listed row is real, and the listing is exactly
        # the cap wide.
        extra = set(mp) - set(gp)
        if extra:
            issues.append(f"pinvoke rows outside oracle: {sorted(extra)[:3]}")
        if len(mp) != MAX_LISTED_PINVOKE:
            issues.append(f"pinvoke listing {len(mp)} != cap {MAX_LISTED_PINVOKE}")
    elif mp != gp:
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
    # W3.2 fields: compared only when the records carry them, so the
    # shipped W3.1 record set keeps validating the W3.1 fields.
    if "typerefs" in rec:
        listed = min(int(rec["counts"].get("typeref", 0)), MAX_LISTED_TYPEREFS)
        # blint walks the first `listed` rows and omits the ones whose
        # scope it cannot resolve (named as a degradation there); the
        # oracle tags those rows instead.
        expected = sorted(
            (t["name"], t["scope"])
            for t in rec["typerefs"][:listed]
            if t["scope_kind"] not in ("nil", "unresolved")
        )
        mine = sorted(
            (t["name"], t["scope"]) for t in block.get("typerefs", [])
        )
        if mine != expected:
            issues.append(
                f"typerefs: {len(mine)} rows vs {len(expected)} expected"
            )
    if "memberrefs" in rec:
        listed = min(int(rec["counts"].get("memberref", 0)), MAX_LISTED_MEMBERREFS)
        expected = sorted(
            (m["name"], m["parent"])
            for m in rec["memberrefs"][:listed]
            if m["parent_kind"] not in ("type_spec", "nil")
        )
        mine = sorted(
            (m["name"], m["parent"]) for m in block.get("memberrefs", [])
        )
        if mine != expected:
            issues.append(
                f"memberrefs: {len(mine)} rows vs {len(expected)} expected"
            )
    if "user_strings_count" in rec:
        # The oracle writes count 0 with an empty digest when it finds no
        # #US stream at all; blint omits both fields and names
        # us_heap_missing. Facade assemblies legitimately ship none, so
        # the oracle's empty digest normalizes to blint's absent field.
        oracle_count = rec.get("user_strings_count") or 0
        oracle_sha = rec.get("user_strings_sha256") or None
        if block.get("user_strings_count", 0) != oracle_count:
            issues.append(
                f"user_strings_count {block.get('user_strings_count', 0)} "
                f"!= {oracle_count}"
            )
        if block.get("user_strings_sha256") != oracle_sha:
            issues.append("user_strings_sha256")
    return issues


if __name__ == "__main__":
    sys.exit(main())
