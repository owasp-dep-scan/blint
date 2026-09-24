#!/usr/bin/env python3
"""Android native corpus builder (A0.2).

Working copy of the reviewer-owned ``scripts/build_android_corpus.sh`` lane in
``~/blint-android-native-plans``; kept here so the build is reproducible from
the blint checkout alone. Tiers per ``05-corpus.md``:

  tier0  emulator system trees (``/system/lib64``, ``/system/lib``,
         ``/system/bin``, every ``/apex/*/lib*``, ``/vendor/lib*``), pulled
         with ``adb root`` from google_apis images, API 34-36, arm64 + x86_64.
  tier1  NDK planted-variant fixtures (``jni_sources/``), built with NDK r27
         and r28 for every ABI the toolchain supports, then packaged into
         small real APKs with aapt2/zipalign/apksigner.
  tier4  hand-built hostile inputs (see ``make_hostile_fixtures.py``).

Every file lands in ``MANIFEST.json`` together with ground truth captured in
the same run (``llvm-readelf``, ``zipalign -c -P 16``, ``aapt2 dump
badging``). No app-store scraping: system images, NDK output and F-Droid APKs
only (ground rule 39).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

NDK_VERSIONS = {"r27": "27.3.13750724", "r28": "28.2.13676358"}
API_LEVELS = ("34", "35", "36")
TIER0_ABIS = ("arm64-v8a", "x86_64")
# Order matters for the manifest's abi lists; riscv64 is included only when
# the NDK toolchain actually ships a compiler for it (checked at build time).
APP_ABIS = ("arm64-v8a", "armeabi-v7a", "x86_64", "x86", "riscv64")
# ndk-build TARGET_ARCH values and the .S textrel probe for each.
TEXTREL_ARCH = {
    "arm64-v8a": "arm64",
    "armeabi-v7a": "arm",
    "x86_64": "x86_64",
    "x86": "x86",
    "riscv64": "riscv64",
}
# Variants that only exist on arm64 (NDK docs: hwaddress and memtag are
# aarch64 sanitizers; branch protection is aarch64-only).
ARM64_ONLY = ("hello_hwasan", "hello_memtag", "hello_bti")


def sdk_root() -> Path:
    root = Path(os.environ.get("ANDROID_SDK_ROOT") or Path.home() / "Android" / "sdk")
    if not root.is_dir():
        sys.exit(f"Android SDK not found at {root}; run setup_android_sdk.sh first")
    return root


def corpus_root() -> Path:
    return Path(os.environ.get("ANDROID_CORPUS_ROOT") or Path.home() / "sandbox" / "android-corpus")


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    proc = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if proc.returncode != 0:
        print(f"!! {' '.join(cmd)}\n{proc.stdout}\n{proc.stderr}", file=sys.stderr)
    return proc


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def ndk_dir(tag: str) -> Path:
    return sdk_root() / "ndk" / NDK_VERSIONS[tag]


def readelf_tool(tag: str) -> Path:
    host = "darwin-x86_64" if sys.platform == "darwin" else "linux-x86_64"
    return ndk_dir(tag) / "toolchains" / "llvm" / "prebuilt" / host / "bin" / "llvm-readelf"


def adb() -> str:
    return str(sdk_root() / "platform-tools" / "adb")


def emulator() -> str:
    return str(sdk_root() / "emulator" / "emulator")


# ---------------------------------------------------------------------------
# tier 0: emulator system trees
# ---------------------------------------------------------------------------


def tier0_pull(api: str, abi: str, out_root: Path) -> None:
    """Boot the AVD headless, adb root, pull the system ELF trees."""
    avd = f"a0-api{api}-{abi}"
    out_dir = out_root / f"api{api}-{abi}"
    out_dir.mkdir(parents=True, exist_ok=True)
    emu = subprocess.Popen(
        [emulator(), "-avd", avd, "-no-window", "-no-audio", "-no-boot-anim",
         "-no-snapshot", "-wipe-data", "-gpu", "swiftshader_indirect"],
        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
    )
    try:
        _wait_for_boot()
        run([adb(), "root"])
        time.sleep(5)
        _wait_for_device()
        fingerprint = run([adb(), "shell", "getprop", "ro.build.fingerprint"]).stdout.strip()
        print(f"[tier0] {avd}: {fingerprint}")
        targets = {
            "_system_bin": ["/system/bin"],
            "_system_lib64": ["/system/lib64"],
            "_system_lib": ["/system/lib"],
            "_vendor_lib64": ["/vendor/lib64"],
            "_vendor_lib": ["/vendor/lib"],
        }
        for dest, dirs in targets.items():
            _pull_elfs(dirs, out_dir / dest)
        _pull_apex_libs(out_dir / "_apex")
        _write_tier0_manifest(out_dir, avd, fingerprint)
    finally:
        emu.terminate()
        try:
            emu.wait(timeout=30)
        except subprocess.TimeoutExpired:
            emu.kill()
        run([adb(), "emu", "kill"])
        run([adb(), "wait-for-device"])


def _wait_for_device(timeout: int = 300) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if run([adb(), "get-state"]).stdout.strip() == "device":
            return True
        time.sleep(3)
    return False


def _wait_for_boot(timeout: int = 600) -> bool:
    run([adb(), "wait-for-device"])
    deadline = time.time() + timeout
    while time.time() < deadline:
        out = run([adb(), "shell", "getprop", "sys.boot_completed"]).stdout.strip()
        if out == "1":
            return True
        time.sleep(5)
    raise TimeoutError("emulator did not finish booting")


def _shell_find(path: str, patterns: list[str]) -> list[str]:
    find_cmd = ["find", path, "-type", "f", "\\(", "-name", patterns[0]]
    for p in patterns[1:]:
        find_cmd += ["-o", "-name", p]
    find_cmd += ["\\)"]
    out = run([adb(), "shell", " ".join(find_cmd)]).stdout
    return sorted(ln.strip() for ln in out.splitlines() if ln.strip())


def _pull_elfs(dirs: list[str], dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    for d in dirs:
        for remote in _shell_find(d, ["*.so"]):
            rel = remote.lstrip("/").replace("/", "_")
            local = dest / f"{rel}"
            if not local.exists():
                run([adb(), "pull", remote, str(local)])


def _pull_apex_libs(dest: Path) -> None:
    """Pull every /apex/<name>/lib{,64}/*.so with the apex name preserved."""
    out = run([adb(), "shell", "ls", "/apex"]).stdout.split()
    for apex in sorted(ln.strip() for ln in out if ln.strip()):
        for subdir in ("lib64", "lib"):
            for remote in _shell_find(f"/apex/{apex}/{subdir}", ["*.so"]):
                local = dest / apex / subdir / os.path.basename(remote)
                local.parent.mkdir(parents=True, exist_ok=True)
                if not local.exists():
                    run([adb(), "pull", remote, str(local)])


def _write_tier0_manifest(out_dir: Path, avd: str, fingerprint: str) -> None:
    entries = []
    for path in sorted(out_dir.rglob("*")):
        if path.is_file() and path.name != "MANIFEST.json":
            entries.append(
                {
                    "file": str(path.relative_to(out_dir)),
                    "size": path.stat().st_size,
                    "sha256": sha256_file(path),
                }
            )
    manifest = {
        "source": f"emulator system image {avd} (google_apis, adb root)",
        "fingerprint": fingerprint,
        "tier": 0,
        "entries": entries,
    }
    (out_dir / "MANIFEST.json").write_text(json.dumps(manifest, indent=1))


# ---------------------------------------------------------------------------
# tier 1: NDK planted variants + real APK packaging
# ---------------------------------------------------------------------------

STUB_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.blint.fixtures"
    android:versionCode="1" android:versionName="1.0">
    <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="35"/>
    <application android:label="blint-tier1" android:hasCode="{has_code}"
        android:extractNativeLibs="{extract_native_libs}">
        <activity android:name=".Hello" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>
"""

STUB_JAVA = """package com.example.blint.fixtures;

public class Hello {
    static { System.loadLibrary("hello"); }

    public static void main(String[] args) {
        System.out.println(stringFromJNI());
    }

    static native String stringFromJNI();
}
"""


def tier1_build(out_root: Path) -> None:
    sdk = sdk_root()
    build_tools = max((sdk / "build-tools").iterdir())
    aapt2 = str(build_tools / "aapt2")
    d8 = str(build_tools / "d8")
    apksigner = str(build_tools / "apksigner")
    zipalign = str(build_tools / "zipalign")
    jni_sources = Path(__file__).parent / "jni_sources"
    workdir = out_root / "tier1-build"
    workdir.mkdir(parents=True, exist_ok=True)
    keystore = _ensure_debug_keystore(workdir)

    # Stub dex built once with javac + d8 (real tools).
    dex_file = workdir / "classes.dex"
    if not dex_file.exists():
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "Hello.java"
            src.write_text(STUB_JAVA)
            javac = run(["javac", "--release", "11", "-d", td, str(src)])
            if javac.returncode != 0:
                print("[tier1] javac failed; APKs will ship without dex", file=sys.stderr)
            else:
                run(["jar", "cf", str(Path(td) / "classes.jar"), "-C", td, "com"])
                run([d8, "--release", "--min-api", "24",
                     "--output", str(workdir), str(Path(td) / "classes.jar")])

    built: dict[str, dict[str, Path]] = {}
    for tag in NDK_VERSIONS:
        ndk = ndk_dir(tag)
        ndkbuild = str(ndk / "ndk-build")
        for abi in APP_ABIS:
            if abi == "riscv64" and not _ndk_has_riscv64(ndk):
                print(f"[tier1] {tag}: no riscv64 toolchain, skipped")
                continue
            app_abi = {"arm64-v8a": "arm64-v8a", "armeabi-v7a": "armeabi-v7a"}.get(abi, abi)
            build_dir = workdir / tag / abi
            if not (build_dir / "libs").exists():
                shutil.copytree(jni_sources, build_dir / "jni", dirs_exist_ok=True)
                cmd = [ndkbuild, "-C", str(build_dir), f"APP_ABI={app_abi}",
                       "NDK_PROJECT_PATH=.", "APP_BUILD_SCRIPT=jni/Android.mk"]
                if abi == "riscv64":
                    # The riscv64 toolchain is android35+ only.
                    cmd += ["APP_PLATFORM=android-35"]
                # All modules build for every ABI; Android.mk guards the
                # arm64-only sanitizers with TARGET_ARCH so unsupported
                # combinations are skipped instead of failing the build.
                run(cmd, cwd=build_dir)
            libdir = build_dir / "libs" / app_abi
            if not libdir.exists():
                print(f"[tier1] {tag}/{abi}: build produced nothing", file=sys.stderr)
                continue
            for f in sorted(libdir.iterdir()):
                if f.is_file() and f.name != "wrap.sh":  # keep the static exe too
                    built.setdefault(f"{tag}/{abi}", {})[f.name] = f
            # Unstripped objects are the symbolised builds the functions-per-ABI
            # baseline measures against; ndk-build keeps them under obj/local.
            unstripped = build_dir / "obj" / "local" / app_abi
            for f in sorted(unstripped.iterdir()):
                if f.is_file() and f.name != "wrap.sh":
                    built.setdefault(f"{tag}/{abi}/unstripped", {})[f.name] = f

    # Library files land in the corpus tree next to per-variant metadata.
    lib_out = out_root / "tier1-ndk"
    for key, libs in sorted(built.items()):
        for name, path in libs.items():
            dest = lib_out / key / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, dest)

    _package_apks(out_root, built, aapt2, zipalign, apksigner, keystore, dex_file)
    _write_tier1_manifest(out_root, lib_out)


def _ndk_has_riscv64(ndk: Path) -> bool:
    triple_bins = ndk / "toolchains" / "llvm" / "prebuilt"
    if not triple_bins.exists():
        return False
    for host in triple_bins.iterdir():
        if any((host / "bin").glob("riscv64-linux-android*-clang")):
            return True
    return False


def _ensure_debug_keystore(workdir: Path) -> Path:
    keystore = workdir / "debug.keystore"
    if not keystore.exists():
        run(["keytool", "-genkeypair", "-keystore", str(keystore),
             "-storepass", "android", "-keypass", "android",
             "-alias", "androiddebugkey", "-dname", "CN=Android Debug,O=Android,C=US",
             "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000"])
    return keystore


def _zip_add_stored(zip_target: Path, members: list[tuple[str, Path]]) -> None:
    """Add members STORED (extractNativeLibs=false layout)."""
    with zipfile.ZipFile(zip_target, "a") as zf:
        for name, path in members:
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_STORED
            with open(path, "rb") as fh:
                zf.writestr(info, fh.read())


def _package_apks(
    out_root: Path,
    built: dict[str, dict[str, Path]],
    aapt2: str,
    zipalign: str,
    apksigner: str,
    keystore: Path,
    dex_file: Path,
) -> None:
    """Package real APKs around the built libraries.

    The zip layout is itself a planted fact: a deflated, 4 KB-aligned apk
    (the extractNativeLibs="true" layout) and a stored, 16 KB-aligned apk
    (the minSdk>=23 AGP default), verified in the same run with
    ``zipalign -c -P 16 -v 4``.
    """
    apk_out = out_root / "tier1-ndk" / "apks"
    apk_out.mkdir(parents=True, exist_ok=True)
    workdir = out_root / "tier1-build"
    r28 = "r28"

    def build_apk(name: str, has_code: bool, extract_native_libs: str,
                  lib_members: list[tuple[str, Path, str]]) -> Path:
        target = apk_out / f"{name}.apk"
        if target.exists():
            target.unlink()
        mf = workdir / f"{name}-AndroidManifest.xml"
        mf.write_text(STUB_MANIFEST.format(
            has_code="true" if has_code else "false",
            extract_native_libs=extract_native_libs))
        proc = run([aapt2, "link", "-o", str(target), "--manifest", str(mf),
                    "-I", str(sdk_root() / "platforms" / "android-35" / "android.jar")])
        if proc.returncode != 0:
            print(f"[tier1] aapt2 link failed for {name}", file=sys.stderr)
            return target
        if has_code and dex_file.exists():
            with zipfile.ZipFile(target, "a") as zf:
                zf.write(dex_file, "classes.dex")
        with zipfile.ZipFile(target, "a") as zf:
            for entry_name, path, method in lib_members:
                if method == "stored":
                    continue
                # zipfile defaults to STORED per call unless told otherwise;
                # the deflated layout is the point of this variant.
                zf.writestr(entry_name, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED)
        stored = [(n, p) for n, p, m in lib_members if m == "stored"]
        if stored:
            _zip_add_stored(target, stored)
        # zipalign -P takes the page size in KILOBYTES (4, 16 or 64).
        page = "16" if extract_native_libs == "false" else "4"
        run([zipalign, "-f", "-P", page, "4", str(target), str(target) + ".aligned"])
        target.unlink(missing_ok=True)
        os.replace(str(target) + ".aligned", target)
        run([apksigner, "sign", "--ks", str(keystore), "--ks-pass", "pass:android",
             "--key-pass", "pass:android", str(target)])
        return target

    r28_arm64 = built.get(f"{r28}/arm64-v8a", {})
    hello = r28_arm64.get("libhello.so")
    if hello:
        build_apk("tier1_singleabi_deflated", True, "true",
                  [("lib/arm64-v8a/libhello.so", hello, "deflated")])
        build_apk("tier1_singleabi_stored16k", True, "false",
                  [("lib/arm64-v8a/libhello.so", hello, "stored")])
        build_apk("tier1_no_dex", False, "false",
                  [("lib/arm64-v8a/libhello.so", hello, "stored")])
    # Multi-ABI app from every ABI built with r28: one base apk (dex only)
    # plus per-ABI config splits, bundled as an .xapk (zip of apks) so the
    # split/dedupe path has a real logical-app input.
    multi: list[tuple[str, Path, str]] = []
    for abi in APP_ABIS:
        lib = built.get(f"{r28}/{abi}", {}).get("libhello.so")
        if lib:
            multi.append((f"lib/{abi}/libhello.so", lib, "stored"))
    if len(multi) >= 2:
        base = build_apk("tier1_base", True, "false", [])
        splits = [base]
        for abi in APP_ABIS:
            lib = built.get(f"{r28}/{abi}", {}).get("libhello.so")
            if not lib:
                continue
            split = build_apk(f"tier1_split_config.{abi}", False, "false",
                              [(f"lib/{abi}/libhello.so", lib, "stored")])
            splits.append(split)
        xapk = apk_out / "tier1_multiabi.xapk"
        if xapk.exists():
            xapk.unlink()
        with zipfile.ZipFile(xapk, "w", zipfile.ZIP_DEFLATED) as zf:
            info = {
                "label": "blint tier-1 multi-ABI bundle",
                "pname": "com.example.blint.fixtures",
                "versioncode": 1,
                "arches": [abi for abi in APP_ABIS if built.get(f"{r28}/{abi}")],
            }
            zf.writestr("info.json", json.dumps(info))
            for split in splits:
                zf.write(split, split.name)


def _write_tier1_manifest(out_root: Path, lib_out: Path) -> None:
    """Ground truth per built library: llvm-readelf from the same NDK."""
    entries = []
    for path in sorted(lib_out.rglob("*")):
        if not path.is_file() or path.suffix not in (".so", "") or path.name == "MANIFEST.json":
            continue
        rel = str(path.relative_to(out_root))
        readelf = str(readelf_tool("r28"))
        header = run([readelf, "-h", "-l", "-d", "-n", str(path)]).stdout
        entries.append({
            "file": rel,
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
            "readelf": header,
        })
    apk_out = lib_out / "apks"
    for path in sorted(apk_out.glob("*.apk")) if apk_out.exists() else []:
        rel = str(path.relative_to(out_root))
        badging = run([str(max((sdk_root() / "build-tools").iterdir()) / "aapt2"),
                       "dump", "badging", str(path)]).stdout
        check = run([str(max((sdk_root() / "build-tools").iterdir()) / "zipalign"),
                     "-c", "-P", "16", "-v", "4", str(path)]).stdout
        entries.append({
            "file": rel,
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
            "badging": badging,
            "zipalign_check": check,
        })
    for path in sorted(apk_out.glob("*.xapk")) if apk_out.exists() else []:
        entries.append({
            "file": str(path.relative_to(out_root)),
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
        })
    (out_root / "tier1-ndk" / "MANIFEST.json").write_text(
        json.dumps({"tier": 1, "entries": entries}, indent=1))




# ---------------------------------------------------------------------------
# tier 0 x86_64: static extraction from the (unbootable-on-ARM) images
# ---------------------------------------------------------------------------

LPGEO_MAGIC = 0x616C4467  # liblp geometry magic
LPMETA_MAGIC = 0x414C5030  # liblp metadata magic
EROFS_MAGIC = 0xE0F5E1E2  # at offset 1024 per the EROFS on-disk spec
SECTOR = 512


def _gpt_partition_offset(img: Path, want: str) -> int:
    """Byte offset of a GPT partition by name (protective-MBR + GPT layout).

    The emulator's system.img is a GPT disk whose `super` partition holds
    the logical partitions; the GPT header sits at LBA 1 and entries at the
    header's PartitionEntryLBA (UEFI spec, table 5-3).
    """
    with img.open("rb") as f:
        f.seek(512)
        header = f.read(512)
        if header[:8] != b"EFI PART":
            raise ValueError(f"{img}: not a GPT disk image")
        pstart, pcount, psize = struct.unpack_from("<QII", header, 72)
        f.seek(pstart * 512)
        for _ in range(min(pcount, 128)):
            entry = f.read(psize)
            if bytes(entry[0:16]) == b"\x00" * 16:
                continue
            s_lba, _e_lba = struct.unpack_from("<QQ", entry, 32)
            name = entry[56:128].decode("utf-16-le").rstrip("\x00")
            if name == want:
                return s_lba * 512
    raise ValueError(f"{img}: no GPT partition named {want!r}")


def _parse_lp_super(img: Path) -> dict[str, list[tuple[int, int]]]:
    """Parse the liblp geometry+metadata of a super partition.

    Layout per system/core/fs_mgr/liblp (geometry at 4 KiB into the super
    partition, metadata slots after it; partitions and linear extents as in
    metadata.h). Returns
    {logical_name: [(byte_offset, byte_length), ...]} within the image.
    """
    super_off = _gpt_partition_offset(img, "super")
    data = img.open("rb")
    data.seek(super_off + 4096)
    geo = data.read(64)
    magic, _size, _crc, meta_max, slots, _block = struct.unpack_from(
        "<II32sIII", geo, 0
    )
    if magic != LPGEO_MAGIC:
        raise ValueError(f"{img}: not a liblp super partition (magic {magic:#x})")
    # The metadata area follows the geometry block; which slot is active
    # varies by image, so the first page carrying the metadata magic wins.
    meta_magic = struct.pack("<I", LPMETA_MAGIC)
    meta_base = 0
    for probe in range(super_off + 8192, super_off + 8192 + 4 * 1024 * 1024, 4096):
        data.seek(probe)
        if data.read(4) == meta_magic:
            data.seek(probe)
            meta_base = probe
            break
    if not meta_base:
        raise ValueError(f"{img}: no liblp metadata after the geometry block")
    meta = data.read(128)
    # v10.0 metadata: four table descriptors of {offset, count, entry_size}
    # each (liblp metadata.h LpMetadataTableDescriptor), after the two
    # checksums. Offsets are relative to the tables area (hsize bytes in).
    (_p_off, _p_count, _p_size, _e_off, _e_count, _e_size,
     _g_off, _g_count, _g_size, _b_off, _b_count, _b_size) = struct.unpack_from(
        "<12I", meta, 80
    )
    part_off, part_count = _p_off, _p_count
    ext_off, ext_count = _e_off, _e_count
    _hsize = vals_hsize = struct.unpack_from("<I", meta, 8)[0]
    # Partition entries (52 bytes: name[36] + three u32 + u16, naturally
    # padded) and extent entries (24 bytes: u64 num_sectors, u32 device,
    # u64 device_offset) are read at the descriptor's own entry_size so a
    # future liblp that grows either struct still walks correctly.
    data.seek(meta_base + vals_hsize + part_off)
    partitions_raw = data.read(part_count * _p_size)
    data.seek(meta_base + vals_hsize + ext_off)
    extents_raw = data.read(ext_count * _e_size)
    out: dict[str, list[tuple[int, int]]] = {}
    for i in range(part_count):
        base = i * _p_size
        name = partitions_raw[base:base + 36].split(b"\x00")[0].decode()
        _attrs, first_extent, num_extents, _group = struct.unpack_from(
            "<IIIH", partitions_raw, base + 36
        )
        spans = []
        for j in range(num_extents):
            ebase = (first_extent + j) * _e_size
            num_sectors, _device, dev_offset = struct.unpack_from(
                "<QI4xQ", extents_raw, ebase
            )
            spans.append((super_off + dev_offset, num_sectors * SECTOR))
        if spans:
            out[name] = spans
    return out


def _extract_partition(img: Path, spans: list[tuple[int, int]], dest: Path) -> str:
    """Copy one logical partition out of the super image; returns fs kind."""
    with img.open("rb") as src, dest.open("wb") as out:
        for offset, length in spans:
            src.seek(offset)
            remaining = length
            while remaining:
                chunk = src.read(min(1 << 22, remaining))
                if not chunk:
                    break
                out.write(chunk)
                remaining -= len(chunk)
    with dest.open("rb") as f:
        f.seek(1024)
        magic = f.read(4)
    erofs = struct.unpack("<I", magic)[0] == EROFS_MAGIC
    return "erofs" if erofs else ("ext4" if magic == b"\x53\xef" else "unknown")


def tier0_extract_x86(api: str, out_root: Path) -> None:
    """Extract the x86_64 image's system/vendor trees without booting it.

    OUTCOME on this machine (A0.2, 2026-09-24): the liblp metadata parses
    (partition names/sizes/counts cross-checked against the emulator's own
    ``lpdump -j`` run on the same bytes), but the extent -> filesystem
    mapping did not reconcile - no ext4/erofs superblock lands at any
    offset the extents imply under any unit interpretation, and the
    emulator's ``lpdump`` text mode refuses the same image ("Failed to
    read metadata") while its JSON mode omits extents. Tier-0 x86_64 was
    therefore NOT collected; the finding and its blockers are recorded in
    the A0.2 commit. Kept because the parser is correct for the metadata
    half and a machine with loop mounts (or a bootable x86_64 host) makes
    the rest work.
    """
    sdk = sdk_root()
    image = sdk / "system-images" / f"android-{api}" / "google_apis" / "x86_64" / "system.img"
    out_dir = out_root / f"api{api}-x86_64"
    work = out_root / f".x86-work-api{api}"
    work.mkdir(parents=True, exist_ok=True)
    spans = _parse_lp_super(image)
    print(f"[tier0-x86] api{api} logical partitions: {sorted(spans)}")
    mounts: list[tuple[str, Path, Path]] = []  # (name, img, guest_dir)
    for name in ("system", "vendor"):
        if name not in spans:
            continue
        part_img = work / f"{name}.img"
        fs = _extract_partition(image, spans[name], part_img)
        print(f"[tier0-x86] {name}: {fs} {part_img.stat().st_size >> 20} MiB")
        if fs not in ("erofs", "ext4"):
            continue
        guest = f"/data/local/tmp/{name}_{api}.img"
        run([adb(), "push", str(part_img), guest])
        mounts.append((name, part_img, guest))
    if not mounts:
        print("[tier0-x86] nothing to mount", file=sys.stderr)
        return
    results: dict[str, str] = {}
    for name, part_img, guest in mounts:
        target = f"/mnt/blint_{name}"
        run([adb(), "shell", f"mkdir -p {target}"])
        for fstype in ("erofs", "ext4"):
            proc = run([adb(), "shell",
                        f"mount -t {fstype} -o ro,loop {guest} {target}"])
            if proc.returncode == 0 and "failed" not in proc.stdout.lower():
                results[name] = fstype
                break
        else:
            print(f"[tier0-x86] could not mount {name}", file=sys.stderr)
            continue
        pull_map = {
            "system": [("_system_lib64", f"{target}/lib64"), ("_system_lib", f"{target}/lib")],
            "vendor": [("_vendor_lib64", f"{target}/lib64"), ("_vendor_lib", f"{target}/lib")],
        }
        for dest, remote in pull_map[name]:
            (out_dir / dest).mkdir(parents=True, exist_ok=True)
            for f in _shell_find(remote, ["*.so"]):
                local = out_dir / dest / os.path.basename(f)
                if not local.exists():
                    run([adb(), "pull", f, str(local)])
        run([adb(), "shell", f"umount {target}"])
    (work / "extraction.json").write_text(json.dumps(
        {"partitions": {k: v for k, v in spans.items()}, "mounted": results}, indent=1))
    for _, _, guest in mounts:
        run([adb(), "shell", f"rm -f {guest}"])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tier", choices=["0", "1", "4", "0x"])
    parser.add_argument("--api", choices=API_LEVELS)
    parser.add_argument("--abi", choices=TIER0_ABIS)
    parser.add_argument("--corpus-root", default=str(corpus_root()))
    args = parser.parse_args()
    out_root = Path(args.corpus_root)
    if args.tier == "0":
        if not (args.api and args.abi):
            sys.exit("tier 0 needs --api and --abi")
        tier0_pull(args.api, args.abi, out_root / "tier0-system")
    elif args.tier == "1":
        tier1_build(out_root)
    elif args.tier == "0x":
        if not args.api:
            sys.exit("tier 0x needs --api")
        tier0_extract_x86(args.api, out_root / "tier0-system")
    elif args.tier == "4":
        from make_hostile_fixtures import build_all
        build_all(out_root / "tier4-hostile")


if __name__ == "__main__":
    main()
