"""Android native-code container model (A1.1).

Reads the ``.so`` entries of an APK (or split bundle) from the zip itself
instead of unzipping the archive to a directory: stored entries are recorded
at their data offset and deflated entries are decompressed into bounded
buffers. Every fact recorded per library — zip entry name, compression
method, data offset and its alignment modulo 4 KiB / 16 KiB, CRC, sha256 —
comes from the zip central directory plus the local file header, which is
where ``zipalign -c -P 16`` reads the same facts from.

The ABI model follows ``01-native-in-apk.md``: only ``lib/<abi>/`` at an
APK root (and ``<module>/lib/<abi>/`` in an AAB) is an ABI directory; the
ELF header must agree with the directory it sits in, and disagreement is
the fact ``abi_mismatch``. Splits and bundles are one logical app:
libraries are deduplicated by sha256 with every location kept.

Every budget here has a hostile fixture (tests/scripts/android/
make_hostile_fixtures.py) and a unit test that crosses it; a limit without
its fixture is written down, not implemented (standing requirement 2).
Zip-slip style names are recorded, never written to disk.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import struct
import tempfile
import zipfile
from dataclasses import asdict, dataclass, field
from typing import IO, Any

from blint.logger import LOG

# --- ABI model ---------------------------------------------------------------
#
# e_machine values are the EM_* constants of the System V ABI ELF enum;
# elf_class is EI_CLASS (1 = 32-bit, 2 = 64-bit).
ANDROID_ABIS: dict[str, dict[str, int]] = {
    "arm64-v8a": {"e_machine": 183, "elf_class": 2},
    "armeabi-v7a": {"e_machine": 40, "elf_class": 1},
    "x86_64": {"e_machine": 62, "elf_class": 2},
    "x86": {"e_machine": 3, "elf_class": 1},
    "riscv64": {"e_machine": 243, "elf_class": 2},
}
# Directories an app may still ship for compat with pre-2019 devices; the
# NDK cannot build them any more, so their presence is recorded via
# ``abi_retired`` rather than treated as a supported ABI.
RETIRED_ABIS: dict[str, dict[str, int]] = {
    "armeabi": {"e_machine": 3, "elf_class": 1},
    "mips": {"e_machine": 8, "elf_class": 1},
    "mips64": {"e_machine": 8, "elf_class": 2},
}

# --- budgets (ground rules 30/33; each has a hostile fixture) -----------------
# Values measured over the A0.2 corpus (tier-0 trees, tier-1 planted builds
# and tier-2 F-Droid apps): the largest app ships ~150 .so entries and well
# under 1 GiB of native code, so these budgets refuse nothing benign while
# bounding hostile inputs. See the module docstring for the crossing
# fixtures; a budget approached but never crossed by a test is not
# implemented.
MAX_NATIVE_LIBS = 512  # .so entries per logical app
MAX_TOTAL_LIB_BYTES = 4 * 1024 * 1024 * 1024  # 4 GiB uncompressed .so budget
MAX_LIB_ENTRY_BYTES = 1024 * 1024 * 1024  # 1 GiB for a single .so entry
MAX_BUNDLE_DEPTH = 2  # bundle -> inner apk; nested bundles refuse beyond
# Whole-zip walk window so a hostile central directory cannot pin the scan.
MAX_ZIP_ENTRIES = 65536

BUNDLE_EXTENSIONS = (".apks", ".xapk", ".apkm")
ELF_MAGIC = b"\x7fELF"


@dataclass
class LibLocation:
    """One zip location a library's bytes were found at."""

    container: str  # outermost input file (the bundle, when bundled)
    entry_name: str  # zip entry name inside its apk
    split: str  # "" for a plain apk, else the inner apk's name
    abi: str  # ABI directory the entry sits in ("" for assets)
    location_kind: str  # "lib_dir" | "asset"
    compression: str  # "stored" | "deflated" | other method names
    data_offset: int  # offset of the entry's data in its apk file/bytes
    offset_mod_4096: int
    offset_mod_16384: int
    compressed_size: int
    uncompressed_size: int
    crc32: int


@dataclass
class NativeLibrary:
    """A deduplicated native library of one logical app."""

    sha256: str
    name: str  # entry basename, e.g. libfoo.so
    size: int
    elf_class: int = 0
    e_machine: int = 0
    e_flags: int = 0
    e_type: int = 0
    abi_mismatch: list[str] = field(default_factory=list)
    not_elf: bool = False
    locations: list[LibLocation] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["abis"] = sorted({loc.abi for loc in self.locations if loc.abi})
        return data


def elf_header_facts(data: bytes) -> dict[str, int]:
    """Read e_ident class, e_type, e_machine and e_flags.

    Layout per the System V ABI: the 16-byte e_ident, then (32-bit) halfword
    e_type/e_machine; e_flags sits at offset 36 in ELF32 and 48 in ELF64.
    """
    if len(data) < 20 or data[:4] != ELF_MAGIC:
        return {}
    elf_class = data[4]
    facts: dict[str, int] = {"elf_class": elf_class, "e_type": 0, "e_machine": 0, "e_flags": 0}
    try:
        facts["e_type"], facts["e_machine"] = struct.unpack_from("<HH", data, 16)
        if elf_class == 2 and len(data) >= 52:
            facts["e_flags"] = struct.unpack_from("<I", data, 48)[0]
        elif elf_class == 1 and len(data) >= 40:
            facts["e_flags"] = struct.unpack_from("<I", data, 36)[0]
    except struct.error:
        pass
    return facts


def safe_name_problems(entry_name: str) -> list[str]:
    """Zip-slip classes for a member name. Recorded, never written."""
    problems = []
    if any(part == ".." for part in entry_name.split("/")):
        problems.append("parent_traversal")
    if entry_name.startswith("/"):
        problems.append("absolute_path")
    if len(entry_name) >= 2 and entry_name[1] == ":":
        problems.append("drive_letter")
    if "\\" in entry_name:
        problems.append("backslash_separator")
    return problems


def classify_entry(entry_name: str, *, aab: bool = False) -> tuple[str, str]:
    """Map a zip entry name to ``(abi, location_kind)``.

    Only ``lib/<abi>/`` at the APK root is an ABI directory - plus
    ``<module>/lib/<abi>/`` inside an AAB (``aab=True``), where module
    directories are the bundle's own layout. Everything else (assets/,
    ``res/lib/<abi>/``, payloads anywhere else) is an asset location that
    never feeds ABI coverage: the loose ``"lib" in rel_path`` test this
    replaces counted ``assets/arm64-v8a/x.so`` as arm64 coverage (V2).
    """
    parts = entry_name.split("/")
    if len(parts) >= 3 and parts[-3] == "lib" and parts[-1].endswith(".so"):
        abi = parts[-2]
        if abi in ANDROID_ABIS or abi in RETIRED_ABIS:
            prefix = parts[:-3]
            if not prefix or (aab and len(prefix) == 1):
                return abi, "lib_dir"
    if entry_name.endswith(".so"):
        return "", "asset"
    return "", "other"


def abi_mismatch_reasons(abi: str, facts: dict[str, int]) -> list[str]:
    """Compare an ELF header against the ABI directory it sits in."""
    if not facts or not abi:
        return []
    expected = ANDROID_ABIS.get(abi) or RETIRED_ABIS.get(abi)
    if not expected:
        return []
    problems = []
    if facts.get("e_machine") != expected["e_machine"]:
        problems.append(
            f"e_machine {facts.get('e_machine')} in a {abi} directory "
            f"(expected {expected['e_machine']})"
        )
    if facts.get("elf_class") != expected["elf_class"]:
        problems.append(
            f"ELF class {facts.get('elf_class')} in a {abi} directory "
            f"(expected {expected['elf_class']})"
        )
    return problems


def _compression_name(method: int) -> str:
    names = {0: "stored", 8: "deflated", 9: "deflate64", 12: "bzip2", 14: "lzma"}
    return names.get(method, f"method-{method}")


def local_data_offset(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> int:
    """Data offset of an entry: local header (30 bytes) + name + local extra.

    The local extra field can be longer than the central-directory extra —
    zipalign stores alignment padding there — so the local header is read
    rather than trusting the central record.
    """
    fp = zf.fp
    if fp is None:
        return info.header_offset
    saved = fp.tell()
    try:
        fp.seek(info.header_offset)
        header = fp.read(30)
        if len(header) == 30 and header[:4] == b"PK\x03\x04":
            name_len, extra_len = struct.unpack_from("<HH", header, 26)
            return info.header_offset + 30 + name_len + extra_len
    except (OSError, struct.error):
        pass
    finally:
        fp.seek(saved)
    return info.header_offset


class _Budget:
    """Per-logical-app budgets; every crossing refuses by name."""

    def __init__(self) -> None:
        self.refusals: list[str] = []
        self.lib_count = 0
        self.total_bytes = 0
        self.entries_walked = 0

    def note_entry(self) -> bool:
        self.entries_walked += 1
        if self.entries_walked > MAX_ZIP_ENTRIES:
            self._refuse_once("zip_entry_count_exceeds_cap")
            return False
        return True

    def admit_lib(self, uncompressed_size: int, name: str) -> bool:
        if self.lib_count >= MAX_NATIVE_LIBS:
            self._refuse_once("native_lib_count_exceeds_cap")
            return False
        if uncompressed_size > MAX_LIB_ENTRY_BYTES:
            self._refuse_once(f"lib_entry_exceeds_cap:{os.path.basename(name)}")
            return False
        if self.total_bytes + uncompressed_size > MAX_TOTAL_LIB_BYTES:
            self._refuse_once("native_lib_total_bytes_exceeds_cap")
            return False
        self.lib_count += 1
        self.total_bytes += uncompressed_size
        return True

    def _refuse_once(self, refusal: str) -> None:
        if refusal not in self.refusals:
            self.refusals.append(refusal)
            LOG.warning("Android native scan refused: %s", refusal)


def _open_zip(source: str | IO[bytes]) -> zipfile.ZipFile | None:
    try:
        return zipfile.ZipFile(source)
    except (zipfile.BadZipFile, OSError, ValueError) as e:
        LOG.warning("Android container %s could not be read: %s", source, e)
        return None


def _scan_one_apk(
    zf: zipfile.ZipFile,
    *,
    container: str,
    split: str,
    budget: _Budget,
    out: list[NativeLibrary],
    unsafe: list[dict[str, str]],
    aab: bool = False,
) -> None:
    for info in zf.infolist():
        if not budget.note_entry():
            break
        name = info.filename
        # orig_filename is the stored name; on Windows zipfile rewrites
        # backslashes in .filename to "/".
        problems = safe_name_problems(info.orig_filename)
        if problems:
            unsafe.append({"entry": info.orig_filename, "problems": sorted(problems)})
            continue
        abi, kind = classify_entry(name, aab=aab)
        if kind == "other":
            continue
        if not budget.admit_lib(info.file_size, name):
            continue
        sha256 = hashlib.sha256()
        head = b""
        with zf.open(info) as fh:
            # Bounded read: the entry cap bounds the loop; head is kept for
            # the ELF facts, the digest runs over the whole member.
            while chunk := fh.read(1 << 20):
                if not head:
                    head = chunk[:64]
                sha256.update(chunk)
        facts = elf_header_facts(head)
        data_offset = local_data_offset(zf, info)
        out.append(
            NativeLibrary(
                sha256=sha256.hexdigest(),
                name=os.path.basename(name),
                size=info.file_size,
                elf_class=facts.get("elf_class", 0),
                e_machine=facts.get("e_machine", 0),
                e_flags=facts.get("e_flags", 0),
                e_type=facts.get("e_type", 0),
                abi_mismatch=abi_mismatch_reasons(abi, facts),
                not_elf=bool(head) and not facts,
                locations=[
                    LibLocation(
                        container=container,
                        entry_name=name,
                        split=split,
                        abi=abi,
                        location_kind=kind,
                        compression=_compression_name(info.compress_type),
                        data_offset=data_offset,
                        offset_mod_4096=data_offset % 4096,
                        offset_mod_16384=data_offset % 16384,
                        compressed_size=info.compress_size,
                        uncompressed_size=info.file_size,
                        crc32=info.CRC,
                    )
                ],
            )
        )


def _dedupe(libraries: list[NativeLibrary]) -> list[NativeLibrary]:
    """Merge same-name same-bytes libraries across splits, keeping every
    location.

    Identity is (name, sha256), not sha256 alone: the same library
    shipped in several splits is one logical library, but a byte-identical
    copy under a different file name is a second entry point the app can
    load, and it keeps its own identity.
    """
    by_key: dict[tuple[str, str], NativeLibrary] = {}
    for lib in libraries:
        key = (lib.name, lib.sha256)
        existing = by_key.get(key)
        if existing is None:
            by_key[key] = lib
        else:
            existing.locations.extend(lib.locations)
    return list(by_key.values())


def abi_coverage(libraries: list[NativeLibrary]) -> dict[str, Any]:
    """App-level ABI coverage summary (01/A.5)."""
    per_abi: dict[str, set[str]] = {}
    retired: set[str] = set()
    for lib in libraries:
        for loc in lib.locations:
            if loc.location_kind != "lib_dir":
                continue
            if loc.abi in RETIRED_ABIS:
                retired.add(loc.abi)
                continue
            per_abi.setdefault(loc.abi, set()).add(lib.name)
    abis = sorted(per_abi)
    names_by_abi = {abi: sorted(names) for abi, names in sorted(per_abi.items())}
    # A library missing from some shipped ABI is a real crash cause; the
    # per-name gap is stated explicitly, never silently first-or-best.
    missing: dict[str, list[str]] = {}
    union: set[str] = set()
    for names in per_abi.values():
        union |= names
    for name in sorted(union):
        absent = [abi for abi in abis if name not in names_by_abi[abi]]
        if absent:
            missing[name] = absent
    has_32 = any(a in ("armeabi-v7a", "x86") for a in abis)
    has_64 = any(a in ("arm64-v8a", "x86_64", "riscv64") for a in abis)
    return {
        "abis": abis,
        "libraries_per_abi": {abi: len(names) for abi, names in names_by_abi.items()},
        "missing_from_abi": missing,
        "ships_32_bit": has_32,
        "ships_64_bit": has_64,
        # Play requires 64-bit wherever 32-bit ships; the fact is stated,
        # not judged (rule 34: the policy date belongs to a rule, A3).
        "requires_64_bit_coverage": has_32 and not has_64,
        "abi_retired": sorted(retired),
    }


def extract_native_libs_fact(manifest_attrs: dict[str, Any]) -> dict[str, Any]:
    """The ``extractNativeLibs`` fact with its provenance (01/A.2).

    ``manifest`` when the attribute was decoded from AndroidManifest.xml;
    ``agp_default`` when it is absent and minSdk >= 23 (the AGP default,
    which the loader then enforces: a compressed or unaligned ``.so``
    fails to load).
    """
    declared = manifest_attrs.get("extractNativeLibs")
    if declared is not None:
        return {"value": declared, "source": "manifest"}
    min_sdk = manifest_attrs.get("minSdkVersion") or ""
    if str(min_sdk).isdigit() and int(min_sdk) >= 23:
        return {"value": False, "source": "agp_default"}
    return {"value": None, "source": "unset"}


def scan_android_native(app_file: str, manifest_attrs: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build the native-code model for one logical app.

    Handles a plain apk, an AAB (module/lib/<abi> layout), and split
    bundles (.apks/.xapk/.apkm — one level of nesting); bundle nesting
    beyond MAX_BUNDLE_DEPTH refuses by name. ``manifest_attrs`` overrides
    the manifest decode; by default the app's manifest is decoded here
    (the same apkInspector path the SBOM uses) so the
    ``extract_native_libs`` fact is always grounded in the manifest.
    """
    if manifest_attrs is None:
        # Local import: blint.lib.android imports this module for its own
        # container work, and the manifest decoder lives there.
        from blint.lib.android import read_manifest_attributes

        manifest_attrs = read_manifest_attributes(app_file)
    budget = _Budget()
    libraries: list[NativeLibrary] = []
    unsafe: list[dict[str, str]] = []
    containers: list[dict[str, Any]] = []
    refusals: list[str] = []

    is_aab = str(app_file).lower().endswith(".aab")

    def scan_zip(source: str | IO[bytes], container: str, split: str, depth: int) -> None:
        record = {"container": container, "split": split, "depth": depth}
        zf = _open_zip(source)
        if zf is None:
            refusals.append(f"container_unreadable:{os.path.basename(container)}")
            return
        with zf:
            _scan_one_apk(
                zf, container=container, split=split, budget=budget,
                out=libraries, unsafe=unsafe, aab=is_aab,
            )
            record["entry_count"] = budget.entries_walked
        containers.append(record)

    if str(app_file).lower().endswith(BUNDLE_EXTENSIONS):
        # One logical app: the bundle's own entries are apks, not libs.
        zf = _open_zip(app_file)
        nested_refused = False
        if zf is not None:
            with zf:
                containers.append(
                    {"container": app_file, "split": "", "depth": 0, "bundle": True}
                )
                for info in zf.infolist():
                    if not budget.note_entry():
                        refusals.append("zip_entry_count_exceeds_cap")
                        break
                    if not info.filename.lower().endswith(".apk"):
                        if info.filename.lower().endswith(BUNDLE_EXTENSIONS):
                            nested_refused = True
                        continue
                    if info.file_size > MAX_TOTAL_LIB_BYTES:
                        refusals.append("bundle_member_exceeds_cap")
                        continue
                    with _spool_member(zf, info) as inner:
                        scan_zip(inner, app_file, info.filename, 1)
        else:
            refusals.append("container_unreadable")
        if nested_refused:
            refusals.append("bundle_depth_exceeds_cap")
    else:
        scan_zip(app_file, app_file, "", 0)

    deduped = _dedupe(libraries)
    model = {
        "app_file": app_file,
        "containers": containers,
        "libraries": [lib.to_dict() for lib in deduped],
        "abi_coverage": abi_coverage(deduped),
        "extract_native_libs": extract_native_libs_fact(manifest_attrs or {}),
        "unsafe_names": unsafe,
        "refusals": sorted(set(refusals) | set(budget.refusals)),
        "counts": {
            "containers": len(containers),
            "libraries": len(deduped),
            "locations": sum(len(lib.locations) for lib in deduped),
            "bytes": budget.total_bytes,
        },
    }
    return model


def read_library_bytes(container: str, entry_name: str, limit: int = MAX_LIB_ENTRY_BYTES) -> bytes | None:
    """Bounded read of one library member from its apk.

    For a plain apk the container is the file on disk; for bundle members
    use :func:`read_bundle_member_bytes`.
    """
    zf = _open_zip(container)
    if zf is None:
        return None
    try:
        with zf:
            info = zf.getinfo(entry_name)
            with zf.open(info) as fh:
                return fh.read(limit + 1)[:limit]
    except (KeyError, zipfile.BadZipFile, OSError, ValueError):
        return None


def _spool_member(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> IO[bytes]:
    """Copy one inner apk out of a bundle into an anonymous temp file."""
    # The caller owns and closes the spool. Not SpooledTemporaryFile:
    # before Python 3.11 it lacks seekable(), which zipfile needs.
    spool = tempfile.TemporaryFile()  # noqa: SIM115
    with zf.open(info) as fh:
        shutil.copyfileobj(fh, spool, 1 << 20)
    spool.seek(0)
    return spool


class LibraryReader:
    """Reads library bytes from their zip locations, opening each split once.

    Used as a context manager; bundle splits are copied to a temp file on first use and
    kept open until exit, so a bundle with many libraries is not re-read
    per library.
    """

    def __init__(self, app_file: str, limit: int = MAX_LIB_ENTRY_BYTES) -> None:
        self.app_file = app_file
        self.limit = limit
        self._zips: dict[str, zipfile.ZipFile | None] = {}
        self._spools: list[Any] = []

    def __enter__(self) -> LibraryReader:  # noqa: PYI034
        return self

    def __exit__(self, *exc: object) -> None:
        for zf in self._zips.values():
            if zf is not None:
                zf.close()
        for spool in self._spools:
            spool.close()

    def _zip_for(self, split: str) -> zipfile.ZipFile | None:
        if split in self._zips:
            return self._zips[split]
        zf = None
        if not split:
            zf = _open_zip(self.app_file)
        else:
            outer = self._zip_for("")
            if outer is not None:
                try:
                    spool = _spool_member(outer, outer.getinfo(split))
                    self._spools.append(spool)
                    zf = _open_zip(spool)
                except (KeyError, zipfile.BadZipFile, OSError, ValueError):
                    zf = None
        self._zips[split] = zf
        return zf

    def read(self, location: dict[str, Any]) -> bytes | None:
        """Bounded read of the library at one model location."""
        zf = self._zip_for(location.get("split") or "")
        if zf is None:
            return None
        try:
            with zf.open(location["entry_name"]) as fh:
                return fh.read(self.limit + 1)[: self.limit]
        except (KeyError, zipfile.BadZipFile, OSError, ValueError):
            return None
