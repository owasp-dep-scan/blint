"""Known-vulnerable-driver matching against the shipped snapshot (W5.3).

``CHECK_KNOWN_VULNERABLE_DRIVER`` is the single most operationally useful
Windows rule blint could ship (plan 04/C.4), and it ships as *data*: a
snapshot of the loldrivers.io dataset plus the Microsoft recommended
driver block rules (``blint/data/pe_vulnerable_drivers.json``, generated
by ``tests/scripts/generate_pe_vulnerable_drivers.py``, carrying both
sources' URLs and fetch dates). Refreshing the snapshot is a data PR.

There is no network call at scan time, ever. Matching is by exact file
hash only - SHA-256 and MD5, the two digests the snapshot carries for
every sample. A filename or signer match never fires the rule: driver
filenames collide across vendors, and accusing a file whose bytes blint
has not pinned is the false-positive shape this lane rejects (the gate
is zero hits on the 330-driver benign sub-tier, every one of them a
legitimately signed driver).
"""

from __future__ import annotations

import json
import logging
from typing import Any

DATA_FILE = "pe_vulnerable_drivers.json"
SNAPSHOT_CACHE: dict[str, Any] | None = None
LOG = logging.getLogger("blint.pe_vulnerable_drivers")


def _snapshot() -> dict[str, Any]:
    """The shipped snapshot, loaded once.

    An unreadable snapshot is a named blind spot, not an empty answer:
    ``lookup_status`` reports it and the rule stays silent (rule 11 - a
    lookup that could not happen never claims "not vulnerable").
    """
    global SNAPSHOT_CACHE
    if SNAPSHOT_CACHE is None:
        import importlib.resources

        try:
            with importlib.resources.files("blint.data").joinpath(DATA_FILE).open(
                "r", encoding="utf-8"
            ) as handle:
                SNAPSHOT_CACHE = json.load(handle)
        except (OSError, ValueError) as e:
            LOG.warning(f"Unable to load the vulnerable-driver snapshot: {e}")
            SNAPSHOT_CACHE = {}
    return SNAPSHOT_CACHE


def match_vulnerable_driver(metadata: dict[str, Any]) -> dict[str, Any]:
    """Match one binary's digests against the shipped snapshot.

    Returns a block with an explicit ``lookup_status``:

    - ``"matched"``: at least one digest pins this exact file in the
      snapshot; ``matches`` names each (field, digest, source, driver).
    - ``"no_match"``: hashes were available and none is in the snapshot -
      the only state in which "not in the snapshot" may be read.
    - ``"no_hash"``: blint has no digest to match, so nothing was checked.
    - ``"snapshot_unavailable"``: the data file could not be read.
    """
    snapshot = _snapshot()
    if not snapshot or not snapshot.get("loldrivers"):
        return {"lookup_status": "snapshot_unavailable"}
    hashes = metadata.get("hashes") or {}
    sha256 = str(hashes.get("sha256") or "").lower()
    md5 = str(hashes.get("md5") or "").lower()
    if not sha256 and not md5:
        return {"lookup_status": "no_hash"}
    matches: list[dict[str, Any]] = []
    lold = snapshot.get("loldrivers") or {}
    ms = snapshot.get("microsoft_blocklist") or {}
    entries = snapshot.get("entries") or {}
    if sha256:
        key = lold.get("sha256", {}).get(sha256)
        if key:
            matches.append(
                {
                    "field": "sha256",
                    "source": "loldrivers",
                    "driver": (entries.get(key) or {}).get("name", key),
                    "category": (entries.get(key) or {}).get("category"),
                }
            )
        name = ms.get("sha256", {}).get(sha256)
        if name:
            matches.append({"field": "sha256", "source": "microsoft_blocklist", "driver": name})
    if md5:
        key = lold.get("md5", {}).get(md5)
        if key:
            matches.append(
                {
                    "field": "md5",
                    "source": "loldrivers",
                    "driver": (entries.get(key) or {}).get("name", key),
                    "category": (entries.get(key) or {}).get("category"),
                }
            )
    block: dict[str, Any] = {
        "lookup_status": "matched" if matches else "no_match",
        "snapshot": {
            "loldrivers_url": lold.get("source_url"),
            "loldrivers_fetched": lold.get("fetched"),
            "blocklist_version": ms.get("policy_version"),
            "blocklist_fetched": ms.get("fetched"),
        },
    }
    if matches:
        block["matches"] = matches
    return block
