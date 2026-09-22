#!/usr/bin/env python3
"""Generate the vulnerable-driver snapshot shipped as blint data (W5.3).

Combines two sources into ``blint/data/pe_vulnerable_drivers.json``:

- The loldrivers.io dataset (every sample's SHA256/MD5, keyed to the
  driver entry's name, category and CVEs).
- The Microsoft recommended driver block rules (the SiPolicy XML behind
  https://aka.ms/VulnerableDriverBlockList), whose Deny rules carry
  SHA1/SHA256 file hashes and filename rules per blocked driver.

The snapshot is *data with provenance*: refreshing it is a data PR that
re-runs this script with fresh downloads and commits the result - there is
no network call at scan time, ever (plan 04/C.4). Matching is by exact
hash only; a filename alone never fires the rule, because driver filenames
collide across vendors and a false accusation here is worse than a miss.

Usage:
    python tests/scripts/generate_pe_vulnerable_drivers.py \
        --loldrivers ~/loldrivers.json \
        --blocklist ~/msblocklist/VulnerableDriverBlockList/DriverPolicy_Enforced_LegacyFormat.xml
"""

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

LOLDRIVERS_URL = "https://www.loldrivers.io/api/drivers.json"
BLOCKLIST_URL = "https://aka.ms/VulnerableDriverBlockList"


def _norm_hash(value: str) -> str | None:
    value = (value or "").strip().lower()
    if not value:
        return None
    # The SiPolicy hashes are hex; normalize width and charset strictly so a
    # parse slip cannot poison the snapshot.
    if not re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", value):
        return None
    return value


def build_snapshot(loldrivers_path: Path, blocklist_path: Path, loldrivers_url: str) -> dict:
    dataset = json.loads(loldrivers_path.read_text())
    fetched = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    entries: dict[str, dict] = {}
    lold_sha: dict[str, str] = {}
    lold_md5: dict[str, str] = {}
    for entry in dataset:
        name = (entry.get("Tags") or [None])[0] or entry.get("Filename") or "unknown"
        key = hashlib.md5(name.encode()).hexdigest()[:12]
        cves = sorted({m.group(0) for m in re.finditer(r"CVE-\d{4}-\d+", name + " " + str(entry.get("Description") or ""))})
        entries.setdefault(key, {"name": name, "category": entry.get("Category"), "cves": cves})
        for sample in entry.get("KnownVulnerableSamples") or []:
            sha = _norm_hash(sample.get("SHA256") or "")
            md5 = _norm_hash(sample.get("MD5") or "")
            if sha:
                lold_sha[sha] = key
            if md5:
                lold_md5[md5] = key

    # Microsoft recommended driver block rules (SiPolicy XML).
    xml = blocklist_path.read_text(encoding="utf-8-sig")
    version = (re.search(r"<VersionEx>([^<]+)</VersionEx>", xml) or [None, ""])[1]
    ms_sha256: dict[str, str] = {}
    ms_sha1: dict[str, str] = {}
    deny_re = re.compile(
        r'<Deny\b[^>]*FriendlyName="([^"]*)"[^>]*Hash="([0-9A-Fa-f/]+)"[^>]*/>'
    )
    for friendly, hash_value in deny_re.findall(xml):
        digest = _norm_hash(hash_value)
        if not digest:
            continue
        # The FriendlyName names the driver (its backslash-separated path or
        # filename) and the hash kind; page hashes are excluded because they
        # match page-aligned regions of a file, not the file's own digest.
        if "Page" in friendly:
            continue
        name = friendly.split("\\")[0].strip()
        if len(digest) == 64:
            ms_sha256[digest] = name
        elif len(digest) == 40:
            ms_sha1[digest] = name

    return {
        "snapshot_version": 1,
        "loldrivers": {
            "source_url": loldrivers_url,
            "fetched": fetched,
            "sample_count": len(lold_sha),
            "sha256": lold_sha,
            "md5": lold_md5,
        },
        "microsoft_blocklist": {
            "source_url": BLOCKLIST_URL,
            "policy_version": version,
            "fetched": fetched,
            "sha256": ms_sha256,
            "sha1": ms_sha1,
        },
        "entries": entries,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--loldrivers", type=Path, required=True)
    parser.add_argument("--blocklist", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("blint/data/pe_vulnerable_drivers.json"))
    parser.add_argument("--loldrivers-url", default=LOLDRIVERS_URL)
    args = parser.parse_args()

    snapshot = build_snapshot(args.loldrivers, args.blocklist, args.loldrivers_url)
    args.output.write_text(json.dumps(snapshot, separators=(",", ":"), sort_keys=True))
    size_kb = args.output.stat().st_size // 1024
    print(
        f"snapshot written to {args.output} ({size_kb} KB): "
        f"loldrivers {len(snapshot['loldrivers']['sha256'])} sha256 / "
        f"{len(snapshot['loldrivers']['md5'])} md5; "
        f"blocklist {len(snapshot['microsoft_blocklist']['sha256'])} sha256 / "
        f"{len(snapshot['microsoft_blocklist']['sha1'])} sha1"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
