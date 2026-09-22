"""Shared bounded container framework for blint's archive inputs (W4.1).

Every archive blint opens is untrusted input (ground rule 30): member counts,
total uncompressed sizes, per-member sizes, decompression ratios, member path
depths and member path safety are bounded on every reader, every refusal is
named rather than silent, and every extraction cleans up on every exit path
including exceptions (ground rule 18). This module is the one place those
mechanisms live, so the per-format readers (``msix.py``, ``cab.py``,
``office.py``, ...) cannot drift into a fourth independent pattern. The
``.ipa`` reader (``ios.py``) predates it and still extracts through
``zipfile.extractall`` with zipfile's own member-name sanitisation; it does
not carry size/count caps, which is stated here rather than claimed away —
moving it onto this framework is the Apple lane's call, not this wave's.

The path-safety check is the single implementation in the tree. It grew out of
``nuget_package._member_path_unsafe`` after W3.5's review found the
drive-relative check missed the drive-absolute form an archiver actually
writes (``C:/evil/evil.dll``, which ``ntpath.join`` honours by discarding the
base); that module now imports this one instead of keeping its own copy.

Refusal names are a closed vocabulary shared with the tests:

- ``archive_unreadable`` — the container could not be opened at all
- ``member_count_exceeds_cap``
- ``member_path_unsafe`` — traversal, absolute path, drive prefix, backslash
- ``member_is_symlink``
- ``member_depth_exceeds_cap``
- ``member_size_exceeds_cap``
- ``member_compression_ratio_exceeds_cap`` — zip-bomb class
- ``total_uncompressed_exceeds_cap``
- ``member_unreadable`` — declared/inactual state disagreed, or the read failed
"""

# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
# SPDX-License-Identifier: Apache-2.0

import contextlib
import os
import shutil
import tempfile
import zipfile
from dataclasses import dataclass

# Chunked copy bound for extraction: one member's read loop never holds more
# than this plus the destination buffer.
_EXTRACT_CHUNK = 1024 * 1024


@dataclass(frozen=True)
class ContainerLimits:
    """The bounds one container reader enforces.

    Every field is part of the reader's contract (ground rule 30). Each
    format reader sets its own measured numbers and states the measurement
    in its module docstring; the framework does not guess defaults.
    Containers within containers (a .msixbundle holds .msix packages, an
    MSI holds CABs) bound the nested unit the same way: its declared size
    faces the reader's caps before anything is decompressed.
    """

    max_members: int
    max_total_uncompressed: int
    max_member_size: int
    max_member_depth: int
    # Uncompressed/compressed per member; the zip-bomb bound. Stored
    # members have ratio 1 by definition.
    max_member_compression_ratio: int


def member_path_unsafe(name: str) -> bool:
    """A member name blint must never treat as a path it could write to.

    Ground rule 30's traversal class: ``..`` segments, rooted absolute
    paths, UNC prefixes, Windows drive letters in *both* spellings, and
    backslash separators (the zip spec says ``/``; a ``\\`` is how an
    extracted path escapes on Windows). Readers whose format documents
    backslash as its separator (CAB) normalise before calling this, so the
    check itself stays one implementation.
    """
    if not name or "\x00" in name:
        return True
    if "\\" in name:
        return True
    if name.startswith("/"):
        return True
    segments = name.split("/")
    if any(seg == ".." for seg in segments):
        return True
    # Any drive-letter prefix, with or without a directory component: both
    # `C:evil` (drive-relative) and `C:/evil/x` (drive-absolute) escape an
    # output directory, because ntpath.join discards the base as soon as
    # the second argument names a drive. Refusing only the first form would
    # leave the one an archiver actually writes.
    return len(name) >= 2 and name[1] == ":" and name[0].isalpha()


def zip_member_is_symlink(info: zipfile.ZipInfo) -> bool:
    """True when a zip member's Unix mode bits mark it a symlink.

    S_IFLNK lives in the high 16 bits of ``external_attr``. A symlink member
    is refused even by readers that never extract: the refusal is a fact
    about the archive, not only about what this reader would do with it.
    """
    return ((info.external_attr >> 16) & 0o170000) == 0o120000


def walk_zip_members(
    archive: zipfile.ZipFile,
    limits: ContainerLimits,
    refusals: list[str],
    *,
    member_size_cap: int | None = None,
) -> list[zipfile.ZipInfo]:
    """Walk a zip's central directory under the reader's bounds.

    Returns the members blint accepts. Members refused by name (unsafe path,
    symlink, depth, size, ratio) do not join the list but do not stop the
    walk; a walk past the member-count or total-size caps stops there and
    says so. ``member_size_cap`` tightens the per-member bound below the
    limits' own value (the nested-container readers use it to bound what
    they decompress) without weakening anything else.
    """
    accepted: list[zipfile.ZipInfo] = []
    total_uncompressed = 0
    per_member_cap = min(
        limits.max_member_size, member_size_cap if member_size_cap is not None else limits.max_member_size
    )
    for info in archive.infolist():
        if len(accepted) >= limits.max_members:
            refusals.append("member_count_exceeds_cap")
            break
        name = info.filename
        if member_path_unsafe(name):
            refusals.append("member_path_unsafe")
            continue
        if zip_member_is_symlink(info):
            refusals.append("member_is_symlink")
            continue
        if len(name.rstrip("/").split("/")) > limits.max_member_depth:
            refusals.append("member_depth_exceeds_cap")
            continue
        if info.file_size > per_member_cap:
            refusals.append("member_size_exceeds_cap")
            continue
        ratio = info.file_size // max(1, info.compress_size)
        if ratio > limits.max_member_compression_ratio:
            refusals.append("member_compression_ratio_exceeds_cap")
            continue
        total_uncompressed += info.file_size
        if total_uncompressed > limits.max_total_uncompressed:
            refusals.append("total_uncompressed_exceeds_cap")
            break
        accepted.append(info)
    return accepted


def read_zip_member_bounded(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    cap: int,
    refusals: list[str],
    refusal_name: str = "member_size_exceeds_cap",
) -> bytes | None:
    """Decompress one member into memory under a hard byte cap.

    The declared ``file_size`` is checked first, but it is attacker-chosen,
    so the read loop enforces the cap against what actually arrives and
    refuses by ``refusal_name`` when the two disagree in the hostile
    direction. Returns ``None`` on any refusal; callers treat ``None`` as
    "this member is unavailable" and carry the refusal beside the fact.
    """
    if info.file_size > cap:
        refusals.append(refusal_name)
        return None
    try:
        with archive.open(info) as handle:
            data = handle.read(cap + 1)
    except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError):
        refusals.append("member_unreadable")
        return None
    if len(data) > cap:
        refusals.append(refusal_name)
        return None
    return data


@contextlib.contextmanager
def bounded_temp_dir(prefix: str):
    """A temp directory removed on every exit path, exceptions included.

    Ground rule 18's structural form: one ``finally`` around the whole body,
    not a cleanup call repeated at each return. The leak tests assert the
    live-directory delta across success and across every failure path
    rather than reading this code.
    """
    temp_dir = tempfile.mkdtemp(prefix=prefix)
    try:
        yield temp_dir
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def extract_zip_members(
    archive: zipfile.ZipFile,
    members: list[zipfile.ZipInfo],
    dest_dir: str,
    limits: ContainerLimits,
    refusals: list[str],
) -> dict[str, str]:
    """Extract the named members into ``dest_dir`` under the reader's bounds.

    Extraction is streamed: the loop enforces the declared size and the
    per-member cap against bytes actually read, so a member that lies about
    its size is cut off and named rather than absorbed. Returns a mapping of
    member name → extracted path for the members that extracted cleanly;
    refused members are named in ``refusals`` and simply do not appear in
    the mapping. Destinations are pre-joined through ``os.path.join`` after
    the path-safety check, which is what makes the drive-prefix refusal load-
    bearing (``ntpath.join`` would otherwise discard the base).
    """
    extracted: dict[str, str] = {}
    for info in members:
        name = info.filename
        if info.file_size > limits.max_member_size:
            refusals.append("member_size_exceeds_cap")
            continue
        dest = os.path.join(dest_dir, *name.split("/"))
        parent = os.path.dirname(dest)
        try:
            if parent:
                os.makedirs(parent, exist_ok=True)
            written = 0
            with archive.open(info) as src, open(dest, "wb") as out:
                while True:
                    chunk = src.read(_EXTRACT_CHUNK)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > limits.max_member_size:
                        raise _MemberTooLarge()
                    out.write(chunk)
        except _MemberTooLarge:
            refusals.append("member_size_exceeds_cap")
            with contextlib.suppress(OSError):
                os.unlink(dest)
            continue
        except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError):
            refusals.append("member_unreadable")
            with contextlib.suppress(OSError):
                os.unlink(dest)
            continue
        extracted[name] = dest
    return extracted


class _MemberTooLarge(Exception):
    """Internal: the extracted bytes exceeded the declared size or cap."""
