# SPDX-License-Identifier: Apache-2.0
"""PE overlay classification (PE-lane packet W0.2, verification finding V3).

The bytes a PE appends after its last section — the overlay — are where
installers stash their payload, single-file bundles their embedded files, and
Authenticode its certificate table. blint historically reported that region as
one undifferentiated ``overlay_size``, which made every signed binary in
existence read as packing evidence: the certificate table lives at the overlay
start by construction, so ``python.exe`` carried 14 KB of "overlay" that was
entirely its signature (V3) and ``CHECK_PACKED`` fired on all 62 tier-0
Microsoft-signed binaries.

This module fixes the input side and adds the classifier the installer work
(W4.3) consumes:

1. :func:`security_directory_range` locates the ``IMAGE_DIRECTORY_ENTRY_SECURITY``
   region, which the PE specification defines in file-offset terms.
2. :func:`classify_pe_overlay` subtracts that region from the overlay and
   classifies the *residue* by magic — ``zip``, ``cab``, ``msi``, ``nsis``,
   ``inno``, ``installshield``, ``sfx_7z``, ``dotnet_single_file_bundle``,
   ``go_buildinfo`` — falling back to an entropy verdict over the residue
   (``unknown_high_entropy``/``unknown_low_entropy``).

The residue, not the raw region, is what ``overlay_info`` and the packing
analysis report, so a signature-only overlay is no overlay at all.
"""

# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>

import contextlib
import os
from collections import Counter
from math import log2

# Entropy of the residue decides between the two unknown labels; the threshold
# is the same one the section-entropy analysis uses for packed payloads.
UNKNOWN_HIGH_ENTROPY = "unknown_high_entropy"
UNKNOWN_LOW_ENTROPY = "unknown_low_entropy"

# Windows-head bytes scanned for embedded-format magic. Archive formats
# (zip/cab/msi/7z) are only claimed when they start the residue — an archive
# in the middle of unknown bytes is not an archive overlay. Everything else is
# matched by signature inside these windows, and the .NET single-file bundle
# marker is matched near the end of the file, where the bundle spec places it.
HEAD_WINDOW = 64 * 1024
TAIL_WINDOW = 64 * 1024

# The .NET single-file bundle marker, verified against a real `dotnet publish
# -p:PublishSingleFile=true` artifact (.NET 10, win-arm64) on the Windows VM.
DOTNET_BUNDLE_MARKER = bytes(
    [
        0x8B, 0x12, 0x02, 0xB9, 0x6A, 0x61, 0x20, 0x38,
        0x72, 0x7B, 0x93, 0x02, 0x14, 0xD7, 0xA0, 0x32,
        0x13, 0xF5, 0xB9, 0xE6, 0xEF, 0xAE, 0x33, 0x18,
        0xEE, 0x3B, 0x2D, 0xCE, 0x24, 0xB3, 0x6A, 0xAE,
    ]
)

# (label, head-magic predicate) pairs, checked in order. Start-of-residue
# magics first so a zip appended behind an unknown blob stays unknown.
_ZIP_MAGIC = (b"PK\x03\x04", b"PK\x05\x06")
_CAB_MAGIC = b"MSCF"
_MSI_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"  # OLE/CFBF — what .msi is
_SFX_7Z_MAGIC = b"7z\xbc\xaf'\x1c"
_SFX_7Z_CONFIG = b";!@Install@!UTF-8!"
_NSIS_MAGIC = b"\xef\xbe\xad\xde"  # firstheader magic, little-endian DEADBEEF
_GO_BUILDINFO_MAGIC = b"\xff Go buildinf:"


def _shannon(data: bytes) -> float:
    total = len(data)
    if not total:
        return 0.0
    entropy = 0.0
    for count in Counter(data).values():
        probability = count / total
        entropy -= probability * log2(probability)
    return entropy


def security_directory_range(parsed_obj) -> tuple[int, int] | None:
    """Return the Authenticode certificate table's (file offset, size).

    The PE specification defines the certificate table's "RVA" field as a
    file offset, so no section mapping is applied. Absent, empty or out-of-
    range tables return None; a size that would run past the end of file is
    clipped by the caller.
    """
    try:
        for index, directory in enumerate(parsed_obj.data_directories):
            if index != 4:  # IMAGE_DIRECTORY_ENTRY_SECURITY
                continue
            rva = int(getattr(directory, "rva", 0) or 0)
            size = int(getattr(directory, "size", 0) or 0)
            if rva <= 0 or size <= 0:
                return None
            return rva, size
    except (AttributeError, TypeError, ValueError):
        return None
    return None


def _end_of_sections(parsed_obj) -> int:
    """Largest raw end offset across the section table (0 when unreadable)."""
    ends = []
    with contextlib.suppress(AttributeError, TypeError, ValueError):
        for section in parsed_obj.sections:
            offset = int(getattr(section, "offset", 0) or 0)
            raw_size = int(getattr(section, "sizeof_raw_data", 0) or 0)
            if offset > 0 and raw_size > 0:
                ends.append(offset + raw_size)
    return max(ends) if ends else 0


def classify_overlay(
    data: bytes,
    *,
    tail: bytes | None = None,
    high_entropy_threshold: float = 7.2,
) -> str:
    """Label one residue byte string. Pure and shared with tests.

    The label vocabulary is the A.2 contract: ``zip``, ``cab``, ``msi``,
    ``nsis``, ``inno``, ``installshield``, ``sfx_7z``,
    ``dotnet_single_file_bundle``, ``go_buildinfo``, then the entropy
    verdicts. ``authenticode`` is deliberately absent — the certificate table
    is subtracted before this function is called, so it never appears as a
    residue label.

    ``tail`` carries the last bytes of the residue when the caller read the
    two ends of a large overlay separately. It must be given whenever ``data``
    is a window rather than the whole residue, because anything recognisable
    can sit at either end of a multi-megabyte residue.

    **Measured correction (W3.3).** This function used to say the .NET bundle
    marker sits at the end of the file. It does not. On a single-file publish
    built with the .NET 11 SDK the 32-byte signature is at offset 9,718,712,
    inside the *sections* (which end at 11,757,568) — the host template
    embeds it, and the bundler writes only the manifest offset into the eight
    bytes before it. So ``dotnet_single_file_bundle`` is not reachable for a
    real .NET 11 bundle here, and the residue of the measured one classifies
    ``unknown_low_entropy``: it is uncompressed assemblies, so it does not
    trip the packing heuristic either. The label is kept for the layouts that
    do put the marker in the residue, and the authoritative single-file
    signal is now ``dotnet.shape`` (``blint/lib/pe_dotnet_shape.py``), which
    reads the manifest rather than guessing from a residue.
    """
    if not data and not tail:
        return UNKNOWN_LOW_ENTROPY
    head = data[:HEAD_WINDOW]
    if head.startswith(_ZIP_MAGIC):
        return "zip"
    if head.startswith(_CAB_MAGIC):
        return "cab"
    if head.startswith(_MSI_MAGIC):
        return "msi"
    if head.startswith(_SFX_7Z_MAGIC) or _SFX_7Z_CONFIG in head:
        return "sfx_7z"
    if head[4:8] == _NSIS_MAGIC or b"Nullsoft" in head[:64]:
        return "nsis"
    if head.startswith((b"zlb\x1a", b"id\x1a")) or b"Inno Setup" in head:
        return "inno"
    if b"InstallShield" in head:
        return "installshield"
    # Entropy is measured over everything the caller handed us, which is the
    # whole residue for a small overlay and the two sampled ends for a large
    # one — never the tail twice.
    sample = data + tail if tail else data
    # The marker is looked for in the last window of whatever we hold: the end
    # of ``data`` when it is the whole residue, and ``tail`` when the caller
    # read the two ends separately (``tail`` is then empty only because the
    # head window already reached the end).
    if DOTNET_BUNDLE_MARKER in data[-TAIL_WINDOW:] + (tail or b""):
        return "dotnet_single_file_bundle"
    if _GO_BUILDINFO_MAGIC in head:
        return "go_buildinfo"
    if _shannon(sample) >= high_entropy_threshold:
        return UNKNOWN_HIGH_ENTROPY
    return UNKNOWN_LOW_ENTROPY


def classify_pe_overlay(parsed_obj, exe_file: str, file_size: int | None = None) -> dict | None:
    """Subtract the certificate table from a PE's overlay and classify the rest.

    Returns the ``overlay_info`` metadata block: the security directory as its
    own named region, and ``offset``/``size``/``entropy``/``classification``
    describing the residue. ``size`` is 0 with classification
    ``unknown_low_entropy`` when nothing is left — the ordinary case for a
    stock signed binary, whose entire overlay was the certificate table.
    """
    if file_size is None:
        with contextlib.suppress(OSError):
            file_size = os.path.getsize(exe_file)
    if not file_size:
        return None
    start = _end_of_sections(parsed_obj)
    if start <= 0 or start >= file_size:
        return None
    overlay = {"offset": start, "size": file_size - start}
    segments: list[tuple[int, int]] = [(start, file_size)]
    security = {}
    if cert_range := security_directory_range(parsed_obj):
        cert_offset, cert_size = cert_range
        cert_size = max(0, min(cert_size, file_size - cert_offset))
        security = {"offset": cert_offset, "size": cert_size}
        clipped: list[tuple[int, int]] = []
        for seg_start, seg_end in segments:
            if cert_size <= 0 or cert_offset >= seg_end or cert_offset + cert_size <= seg_start:
                clipped.append((seg_start, seg_end))
                continue
            if cert_offset > seg_start:
                clipped.append((seg_start, min(cert_offset, seg_end)))
            if cert_offset + cert_size < seg_end:
                clipped.append((max(cert_offset + cert_size, seg_start), seg_end))
        segments = clipped
    residue_size = sum(end - seg_start for seg_start, end in segments)
    residue_head = b""
    residue_tail = b""
    if residue_size:
        # Two bounded windows — the start of the residue, where archive and
        # installer magic lives, and its end, where the .NET bundle marker
        # lives — so a multi-GB installer overlay is never read in full on
        # the default scan path. Both ends must be read: reading only the
        # head labels every real single-file bundle unknown_high_entropy.
        with contextlib.suppress(OSError, ValueError), open(exe_file, "rb") as handle:
            head_start, head_end = segments[0]
            handle.seek(head_start)
            residue_head = handle.read(min(head_end - head_start, HEAD_WINDOW))
            tail_end = segments[-1][1]
            tail_start = max(segments[-1][0], tail_end - TAIL_WINDOW, head_start + len(residue_head))
            if tail_end > tail_start:
                handle.seek(tail_start)
                residue_tail = handle.read(tail_end - tail_start)
    overlay["security_directory"] = security or None
    overlay["size"] = residue_size
    if residue_size == 0:
        overlay["offset"] = file_size
        overlay["entropy"] = 0.0
        overlay["classification"] = UNKNOWN_LOW_ENTROPY
    else:
        overlay["offset"] = segments[0][0]
        overlay["entropy"] = round(_shannon(residue_head + residue_tail), 4)
        overlay["classification"] = classify_overlay(residue_head, tail=residue_tail)
    return overlay
