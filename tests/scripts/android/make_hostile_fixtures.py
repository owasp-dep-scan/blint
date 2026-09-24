#!/usr/bin/env python3
"""Tier-4 hostile fixtures for the Android native lane (A0.2 / A1.1).

Every input here is deliberately malformed; none of it can come from a real
tool, so each fixture is built to the format spec and names it:

  - zip structure per the .ZIP Application Note (PK\\x03\\x04 local file
    header, central directory, EOCD) - written through Python's zipfile with
    byte-patching where the stdlib write path would normalise a name;
  - ELF structure per the System V ABI / Android ELF extension documents
    (``DT_ANDROID_REL`` is tag ``0x6fffe000`` in the Android ELF doc,
    ``bionic-linker-namespace`` / ``android-changes-for-ndk-developers.md``
    state the loader's contract for packed relocations).

ELF-based fixtures are derived from a real NDK-built ``libhello.so`` passed
with ``--base-so`` so the bytes under test come from a real toolchain; only
the malformation is synthetic.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import zipfile
from pathlib import Path

# Zip-slip member-name classes. The "\\" form is planted by byte-patching
# because Python's zipfile rewrites backslashes to "/" in member names on
# some platforms at write time (AGENTS.md separator edge, in fixture form).
UNSAFE_NAMES = [
    "../evil.so",
    "lib/../../evil.so",
    "/data/local/tmp/evil.so",
]

DRIVE_NAME = "C:/evil/evil.so"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _minimal_elf64_aarch64() -> bytes:
    """A 64-bit little-endian ELF header for EM_AACH64, laid out to the
    System V ABI ELF header (e_ident magic/class/data/version, e_type ET_DYN,
    e_machine). Used only when no real NDK library was supplied."""
    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0, 0]) + b"\x00" * 7
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        e_ident,
        3,   # e_type ET_DYN
        183,  # e_machine EM_AARCH64
        1,   # e_version
        0,   # e_entry
        64,  # e_phoff
        0,   # e_shoff
        0,   # e_flags
        64,  # e_ehsize
        56,  # e_phentsize
        0,   # e_phnum
        0,   # e_shentsize
        0,   # e_shnum
        0,   # e_shstrndx
    )
    return header


def _real_or_stub_elf(base_so: Path | None) -> bytes:
    if base_so and base_so.exists():
        return base_so.read_bytes()
    return _minimal_elf64_aarch64()


def build_all(out_dir: Path, base_so: Path | None = None) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    made = []
    elf = _real_or_stub_elf(base_so)
    build_zip_slip(out_dir, elf)
    made.append(out_dir / "zip_slip.apk")
    made.append(out_dir / "zip_slip_backslash.apk")
    made.append(build_many_entries(out_dir, elf, count=600))
    made.append(build_zip_bomb(out_dir))
    made.append(build_deep_bundle(out_dir, elf, depth=4))
    made.append(build_abi_mismatch(out_dir, elf))
    made.extend(build_elf_malformations(out_dir, elf))
    made.append(build_not_elf(out_dir))
    return [m for m in made if m]


def build_zip_slip(out_dir: Path, elf: bytes) -> Path:
    """Two fixtures: the plain traversal-name archive, and a backslash-name
    archive planted by byte-patching (Python's zipfile normalises "\\" to
    "/" in member names on some platforms at write time, so no write path
    can produce the patched form)."""
    target = out_dir / "zip_slip.apk"
    with zipfile.ZipFile(target, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"stub")
        for name in UNSAFE_NAMES:
            zf.writestr(name, elf)
        # Drive-absolute name: zipfile stores it verbatim on posix.
        zf.writestr(DRIVE_NAME, elf)
    placeholder = "lib/placeholderXX"
    evil = "lib\\..\\..\\evil.so"
    assert len(placeholder) == len(evil)
    staging = out_dir / "_slip_staging.apk"
    with zipfile.ZipFile(staging, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"stub")
        zf.writestr(placeholder, elf)
    patched = staging.read_bytes().replace(placeholder.encode(), evil.encode())
    assert patched != staging.read_bytes(), "placeholder not found to patch"
    backslash = out_dir / "zip_slip_backslash.apk"
    backslash.write_bytes(patched)
    staging.unlink()
    return target


def build_many_entries(out_dir: Path, elf: bytes, count: int) -> Path:
    target = out_dir / "many_so_entries.apk"
    with zipfile.ZipFile(target, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("AndroidManifest.xml", b"stub")
        for i in range(count):
            zf.writestr(f"lib/arm64-v8a/lib{i:04d}.so", elf)
    return target


def build_zip_bomb(out_dir: Path) -> Path:
    """One deflated member claiming ~1 GiB of zeros; tiny on disk."""
    target = out_dir / "zip_bomb.apk"
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        zf.writestr("AndroidManifest.xml", b"stub")
        zf.writestr("lib/arm64-v8a/libbomb.so", b"\x00" * (64 * 1024 * 1024))
    return target


def build_deep_bundle(out_dir: Path, elf: bytes, depth: int) -> Path:
    """Nested .apks bundles: bundle-in-bundle past any sane recursion cap."""
    leaf = out_dir / "_leaf.apk"
    with zipfile.ZipFile(leaf, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"stub")
        zf.writestr("lib/arm64-v8a/libleaf.so", elf)
    current = leaf
    for i in range(depth):
        nxt = out_dir / f"_deep{i}.xapk"
        with zipfile.ZipFile(nxt, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(current, current.name)
        if current != leaf:
            current.unlink()
        current = nxt
    target = out_dir / "deep_bundle.xapk"
    target.write_bytes(current.read_bytes())
    current.unlink()
    leaf.unlink()
    return target


def build_abi_mismatch(out_dir: Path, elf: bytes) -> Path:
    """The base .so is aarch64; every directory says x86_64."""
    target = out_dir / "abi_mismatch.apk"
    with zipfile.ZipFile(target, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"stub")
        zf.writestr("lib/x86_64/libwrongarch.so", elf)
    return target


def build_elf_malformations(out_dir: Path, elf: bytes) -> list[Path]:
    made = []
    # Truncated: cut at 60% so program headers exist but sections do not.
    trunc = out_dir / "truncated.so"
    trunc.write_bytes(elf[: int(len(elf) * 0.6)])
    made.append(trunc)
    bogus = _bogus_aps2(elf)
    if bogus:
        target = out_dir / "bogus_aps2.so"
        target.write_bytes(bogus)
        made.append(target)
    return made


def _bogus_aps2(elf: bytes) -> bytes | None:
    """Retag one dynamic entry as DT_ANDROID_REL (0x6fffe000, Android ELF
    doc) pointing at a library-name string, so anything that trusts the tag
    parses packed relocations out of garbage.

    Walks the 64-bit ELF program headers to PT_DYNAMIC per the System V ABI
    (struct layout: e_phoff/e_phentsize/e_phnum in the header; each program
    header is p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz,
    p_memsz, p_align), then the 16-byte dynamic entries until DT_NULL.
    """
    data = bytearray(elf)
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        return None  # not a 64-bit little-endian ELF
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags, p_offset = struct.unpack_from("<IIQ", data, off)
        if p_type != 2:  # PT_DYNAMIC
            continue
        for j in range(0, len(data) - off, 16):
            dyn_off = p_offset + j
            if dyn_off + 16 > len(data):
                break
            d_tag, d_val = struct.unpack_from("<QQ", data, dyn_off)
            if d_tag == 0:  # DT_NULL: rest is padding, patch the first pad
                struct.pack_into("<QQ", data, dyn_off, 0x6FFFE000, d_val or 0x40)
                return bytes(data)
    return None


def build_not_elf(out_dir: Path) -> Path:
    target = out_dir / "not_elf.so"
    target.write_text("this is not an elf, it just lives in lib/arm64-v8a\n")
    return target


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("out_dir", type=Path)
    parser.add_argument("--base-so", type=Path, default=None,
                        help="a real NDK-built .so to malform (preferred)")
    args = parser.parse_args()
    made = build_all(args.out_dir, args.base_so)
    manifest = {
        "tier": 4,
        "note": "hostile fixtures; see module docstring for the specs each "
                "shape is built to",
        "entries": [
            {"file": p.name, "size": p.stat().st_size, "sha256": _sha256(p)}
            for p in sorted(made)
        ],
    }
    (args.out_dir / "MANIFEST.json").write_text(json.dumps(manifest, indent=1))
    for p in made:
        print(p)


if __name__ == "__main__":
    main()
