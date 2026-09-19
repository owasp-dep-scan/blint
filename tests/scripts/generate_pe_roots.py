#!/usr/bin/env python3
"""Regenerate blint/data/pe_roots.yml, the shipped root-anchor fingerprints.

The table maps the SHA-256 fingerprint of every certificate in a Windows
machine's trusted root stores to its subject facts, and flags the roots
Microsoft operates. The signing-class derivation (plan 02/C) uses it to
name the root a signature chain terminates at — a statement about the
file, never a trust verdict: blint does not consult a live store, fetch
CRL/OCSP data or build chains beyond what the signature blob itself ships
(section D's non-goals).

The export is produced ON the Windows VM by
``C:\\Users\\appthreat\\blint\\export_root_store.ps1`` (itself checked in
beside this script's notes in the VM's blint directory):

    ssh win11-vm 'powershell -ExecutionPolicy Bypass -File C:\\Users\\appthreat\\blint\\export_root_store.ps1'
    scp win11-vm:C:/Users/appthreat/blint-corpus/root_store.json /tmp/
    .venv/bin/python tests/scripts/generate_pe_roots.py /tmp/root_store.json \\
        -o blint/data/pe_roots.yml

The export records the store names, the host build and the export date;
this script only hashes the DER and rewrites the YAML, so every positive
in the data is traceable to a store snapshot.
"""

import argparse
import base64
import hashlib
import json
import sys


def subject_value(subject: str, attr: str) -> str | None:
    """One RDN value out of an X.500 subject string (attr=value pairs)."""
    for part in subject.split(","):
        part = part.strip()
        if part.lower().startswith(f"{attr.lower()}="):
            return part.split("=", 1)[1]
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", help="root_store.json written by export_root_store.ps1")
    parser.add_argument("-o", "--output", default="blint/data/pe_roots.yml")
    args = parser.parse_args()

    with open(args.export, encoding="utf-8-sig") as handle:
        export = json.load(handle)
    stores = sorted({record["store"] for record in export["certs"]})
    roots: dict[str, dict] = {}
    der_by_fingerprint: dict[str, list[str]] = {}
    for record in export["certs"]:
        fingerprint = hashlib.sha256(base64.b64decode(record["der_b64"])).hexdigest()
        der_by_fingerprint.setdefault(fingerprint, []).append(record["store"])
        subject = record["subject"]
        cn = subject_value(subject, "CN")
        org = subject_value(subject, "O")
        roots[fingerprint] = {
            "cn": cn or subject,
            "o": org,
            "microsoft": "microsoft" in subject.lower(),
            "stores": sorted(der_by_fingerprint[fingerprint]),
        }
    store_labels = ", ".join("LocalMachine\\" + s for s in stores)
    # Single-quoted YAML style: backslashes are literal there, and the
    # store names are Windows paths.
    store_list = "\n".join(f"  - 'LocalMachine\\{s}'" for s in stores)
    header = f"""\
# blint's shipped root-anchor fingerprints (PE lane W2.4, plan 02/C).
#
# What was hashed: the DER of every certificate in the machine trusted
# root stores of the Windows ARM64 VM ({export['host_build']}),
# exported on {export['exported'][:10]}. The stores:
# {store_labels}.
# Regenerate with tests/scripts/generate_pe_roots.py against a newer store
# export; roots added after the export date are outside this snapshot.
#
# blint matches the SHA-256 of the self-signed certificate a signature
# chain terminates at against these fingerprints, and reads the microsoft
# flag to separate first-party Microsoft roots from public ones. This is
# a statement about the file's shipped chain, not about the world: blint
# performs no trust validation, consults no live store and fetches no
# revocation data (plan 02/D), so a root outside this snapshot reads as
# "outside the shipped snapshot", never as "untrusted" in the CryptoAPI
# sense.

source_build: "{export['host_build']}"
source_stores:
{store_list}
hashed_on: "{export['exported'][:10]}"
hash: sha256
roots:
"""
    lines = []
    for fingerprint in sorted(roots):
        entry = roots[fingerprint]
        lines.append(f"  {fingerprint}:")
        lines.append(f"    cn: {json.dumps(entry['cn'])}")
        if entry["o"]:
            lines.append(f"    o: {json.dumps(entry['o'])}")
        lines.append(f"    microsoft: {str(bool(entry['microsoft'])).lower()}")
        lines.append("    stores:")
        lines.extend(f"      - {store}" for store in entry["stores"])
    out = header + "\n".join(lines) + "\n"
    with open(args.output, "w", encoding="utf-8") as handle:
        handle.write(out)
    microsoft_count = sum(1 for e in roots.values() if e["microsoft"])
    print(f"{args.output}: {len(roots)} roots ({microsoft_count} Microsoft), "
          f"build {export['host_build']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
