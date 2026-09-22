"""Installer detection for PE overlays (W4.3), extending the W0.2 classifier.

The overlay classifier labels an installer-shaped residue (``nsis``,
``inno``, ``installshield``, ``sfx_7z``); this module turns those labels
into documented header facts and states, per family, what blint did and did
not open:

- **nsis** — detection plus first-header facts (the documented
  ``firstheader_`` structure: flags, the 0xDEADBEEF magic, header and data
  sizes). Member extraction is *not* performed: the NSIS data block is a
  compiled install-script database whose file entries are resolved by
  emulating the script VM, which is a decompiler, not a container format —
  detection-only, stated here and in docs/METADATA.md.
- **sfx_7z** — detection plus the appended 7z archive's directory through
  ``sevenz.py``: member listing (exact names and sizes for LZMA/LZMA2/copy
  folders) and bounded member extraction at the runner level. BCJ2-encoded
  folders refuse by name.
- **inno / installshield** — detection-only, no structure facts beyond the
  overlay classification and the marker that matched.

The block rides parse() output, so CACHE_SCHEMA_VERSION moves in this
packet (10 → 11) — the first stored-shape change of the wave.
"""

# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
# SPDX-License-Identifier: Apache-2.0

import os
import struct

from blint.lib.sevenz import parse_sevenz_blob

NSIS_FIRSTHEADER_MAGIC = 0xDEADBEEF

# Bounds (ground rule 30): a NSIS data block is never decompressed here, so
# the caps only bound how much of the file is *scanned* and how large a 7z
# directory may be (sevenz.py carries its own measured caps).
MAX_INSTALLER_SCAN_BYTES = 8 * 1024 * 1024
MAX_NSIS_HEADER_OFFSET = 4 * 1024 * 1024


def detect_installer(path: str, overlay_classification: str | None) -> dict | None:
    """Build the ``installer`` block for one PE, or None when not an installer.

    ``overlay_classification`` is the W0.2 residue label; only installer
    families get a block. Facts never read as verdicts: the block states
    which container shape the executable carries, not what it might do.
    """
    if overlay_classification not in ("nsis", "inno", "installshield", "sfx_7z"):
        return None
    block: dict = {
        "family": overlay_classification,
        "extraction": "detection_only",
        "refusals": [],
        "degradations": [],
    }
    try:
        with open(path, "rb") as handle:
            head = handle.read(MAX_INSTALLER_SCAN_BYTES)
    except OSError:
        block["degradations"].append("installer_file_unreadable")
        return block
    if overlay_classification == "nsis":
        first = _parse_nsis_firstheader(head)
        if first:
            block["nsis_firstheader"] = first
            block["extraction"] = "detection_only"
        else:
            block["degradations"].append("nsis_firstheader_not_found")
    elif overlay_classification == "sfx_7z":
        block["extraction"] = "members"
        payload = parse_sevenz_blob(head, block["refusals"], block["degradations"])
        if payload is None:
            block["degradations"].append("sevenz_signature_not_found")
        else:
            block["sfx_payload"] = {
                "offset": payload.get("payload_offset"),
                "version": payload.get("version"),
                "member_count": payload.get("member_count"),
                "members": payload.get("members") or [],
                "total_unpacked": payload.get("total_unpacked"),
            }
    return block


def _parse_nsis_firstheader(head: bytes) -> dict | None:
    """The documented NSIS firstheader, if present near the overlay start.

    firstheader: flags(4), magic(4, 0xDEADBEEF LE), length_of_header(4),
    length_of_all_following_data(4). No data block is decompressed. The
    0xDEADBEEF magic also occurs inside installer data, so candidates are
    ranked by plausibility (a data length that fits the scan window); when
    none is plausible the first candidate is reported beside a
    ``firstheader_implausible`` degradation rather than guessed away.
    """
    limit = min(len(head), MAX_NSIS_HEADER_OFFSET)
    needle = struct.pack("<I", NSIS_FIRSTHEADER_MAGIC)
    candidates: list[dict] = []
    position = head.find(needle)
    while 0 <= position <= limit and position >= 4:
        flags, _magic, length_of_header, length_of_all = struct.unpack(
            "<IIII", head[position - 4 : position + 12]
        )
        facts = {
            "flags": flags,
            "offset": position - 4,
            "length_of_header": length_of_header,
            "length_of_all_following_data": length_of_all,
        }
        if length_of_all <= len(head):
            return facts
        candidates.append(facts)
        position = head.find(needle, position + 1)
    if candidates:
        candidates[0]["implausible"] = True
        return candidates[0]
    return None


def sfx_member_collection(path: str) -> dict | None:
    """The 7z payload of an SFX for the runner's member analysis.

    Returns None when the file is not an SFX. Members are listed from the
    (LZMA-compressed) directory; the runner extracts individual members it
    can decode through :meth:`SevenZipArchive.extract`.
    """
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_INSTALLER_SCAN_BYTES)
    except OSError:
        return None
    from blint.lib.sevenz import find_archive_candidates

    if not find_archive_candidates(data):
        return None
    refusals: list[str] = []
    degradations: list[str] = []
    return parse_sevenz_blob(data, refusals, degradations)
