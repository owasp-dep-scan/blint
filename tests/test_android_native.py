"""A1.1 - Android native container model tests.

Fixtures are the A0.2 corpus files committed under tests/data/android/
(built by the real Android toolchain: aapt2/zipalign/apksigner from
build-tools 36.0.0 over NDK r28-built libraries) plus hostile inputs
generated inline per the .ZIP Application Note layout the way
tests/scripts/android/make_hostile_fixtures.py builds them.
"""

import json
import zipfile
from pathlib import Path

from blint.lib.android_native import (
    MAX_BUNDLE_DEPTH,
    MAX_NATIVE_LIBS,
    abi_coverage,
    classify_entry,
    extract_native_libs_fact,
    read_library_bytes,
    safe_name_problems,
    scan_android_native,
)

DATA = Path(__file__).parent / "data" / "android"
STORED16K = DATA / "tier1_singleabi_stored16k.apk"
DEFLATED = DATA / "tier1_singleabi_deflated.apk"
NO_DEX = DATA / "tier1_no_dex.apk"
MULTIABI = DATA / "tier1_multiabi.xapk"


def _lib(model: dict, name: str) -> dict:
    return next(lib for lib in model["libraries"] if lib["name"] == name)


def test_stored16k_layout_facts(tmp_path: Path) -> None:
    # zipalign -c -P 16 -v 4 on this apk passes for the stored entry; the
    # model must read the same fact from the zip itself (A0.2 manifest).
    model = scan_android_native(str(STORED16K))
    lib = _lib(model, "libhello.so")
    assert lib["e_machine"] == 183 and lib["elf_class"] == 2
    (location,) = lib["locations"]
    assert location["abi"] == "arm64-v8a"
    assert location["location_kind"] == "lib_dir"
    assert location["compression"] == "stored"
    assert location["offset_mod_16384"] == 0
    assert location["crc32"] != 0
    assert lib["abi_mismatch"] == []
    assert model["refusals"] == []


def test_deflated_layout_and_extract_native_libs() -> None:
    model = scan_android_native(str(DEFLATED))
    (location,) = _lib(model, "libhello.so")["locations"]
    assert location["compression"] == "deflated"
    # The manifest declares extractNativeLibs="true" (A0.2 packaging).
    assert model["extract_native_libs"] == {"value": True, "source": "manifest"}


def test_extract_native_libs_agp_default_matrix() -> None:
    # Every branch of the boolean, including the unset case (rule 3).
    assert extract_native_libs_fact({"extractNativeLibs": False}) == {
        "value": False, "source": "manifest",
    }
    assert extract_native_libs_fact({"minSdkVersion": "24"}) == {
        "value": False, "source": "agp_default",
    }
    assert extract_native_libs_fact({"minSdkVersion": "22"}) == {
        "value": None, "source": "unset",
    }
    assert extract_native_libs_fact({}) == {"value": None, "source": "unset"}


def test_stored16k_extract_native_libs_declared_false() -> None:
    # Both tier-1 manifests declare the attribute (the A0.2 packaging
    # writes it); the stored+16 KiB-aligned apk declares false, which is
    # the layout the loader enforces for minSdk >= 23. The agp_default
    # branch - attribute absent, minSdk >= 23 - is covered by the unit
    # matrix above and exercised on real apps in A1.2.
    model = scan_android_native(str(STORED16K))
    assert model["extract_native_libs"] == {"value": False, "source": "manifest"}


def test_no_dex_apk_has_native_libraries() -> None:
    model = scan_android_native(str(NO_DEX))
    assert model["counts"]["libraries"] == 1
    assert model["abi_coverage"]["abis"] == ["arm64-v8a"]


def test_multiabi_bundle_is_one_logical_app() -> None:
    # The xapk holds a base apk plus per-ABI config splits; one logical
    # app, every split walked, all five ABIs covered (01/A.4). The five
    # per-ABI libhello.so builds differ by architecture, so they are five
    # distinct libraries - dedupe applies to identical bytes, which the
    # next test exercises.
    model = scan_android_native(str(MULTIABI))
    hellos = [lib for lib in model["libraries"] if lib["name"] == "libhello.so"]
    splits = {loc["split"] for lib in hellos for loc in lib["locations"]}
    assert any("riscv64" in split for split in splits)
    abis = model["abi_coverage"]["abis"]
    assert {"arm64-v8a", "armeabi-v7a", "x86_64", "x86", "riscv64"} <= set(abis)
    # Provenance lists every inner apk of the bundle.
    assert model["counts"]["containers"] >= 6


def test_same_bytes_dedupe_keeps_every_location(tmp_path: Path) -> None:
    # Same .so bytes in base and in a split: one library, two locations
    # (sha256 dedupe with all locations kept, 01/A.4).
    with zipfile.ZipFile(STORED16K) as zf:
        lib_bytes = zf.read("lib/arm64-v8a/libhello.so")
    base = tmp_path / "base.apk"
    with zipfile.ZipFile(base, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"stub")
        zf.writestr("lib/arm64-v8a/libhello.so", lib_bytes)
    split = tmp_path / "split_config.arm64-v8a.apk"
    with zipfile.ZipFile(split, "w") as zf:
        zf.writestr("lib/arm64-v8a/libhello.so", lib_bytes)
    bundle = tmp_path / "bundle.xapk"
    with zipfile.ZipFile(bundle, "w") as zf:
        zf.writestr("info.json", json.dumps({"pname": "x"}))
        zf.write(base, base.name)
        zf.write(split, split.name)
    model = scan_android_native(str(bundle))
    assert model["counts"]["libraries"] == 1
    assert model["counts"]["locations"] == 2
    locs = _lib(model, "libhello.so")["locations"]
    assert {loc["split"] for loc in locs} == {base.name, split.name}


def test_abi_mismatch_recorded_not_fatal() -> None:
    # abi_mismatch.apk stores an aarch64 ELF under lib/x86_64/ (A0.2).
    model = scan_android_native(str(DATA / "abi_mismatch.apk"))
    lib = _lib(model, "libwrongarch.so")
    assert any("e_machine 183 in a x86_64 directory" in reason for reason in lib["abi_mismatch"])


def test_classify_entry_dir_matrix() -> None:
    assert classify_entry("lib/arm64-v8a/x.so") == ("arm64-v8a", "lib_dir")
    assert classify_entry("lib/riscv64/x.so") == ("riscv64", "lib_dir")
    # AAB module layout is an ABI directory only for actual bundles.
    assert classify_entry("base/lib/arm64-v8a/x.so") == ("", "asset")
    assert classify_entry("base/lib/arm64-v8a/x.so", aab=True) == ("arm64-v8a", "lib_dir")
    # The loose-path defects this model replaces (V2): assets and nested
    # lib dirs are never ABI coverage.
    assert classify_entry("assets/arm64-v8a/x.so") == ("", "asset")
    assert classify_entry("res/lib/x86_64/x.so") == ("", "asset")
    assert classify_entry("assets/payload.so") == ("", "asset")
    assert classify_entry("res/raw/xml") == ("", "other")
    # Retired ABIs are recognized so they can be recorded as retired.
    assert classify_entry("lib/armeabi/x.so") == ("armeabi", "lib_dir")


def test_retired_abis_recorded(tmp_path: Path) -> None:
    apk = tmp_path / "retired.apk"
    # ELF header of a real NDK build (the committed stored16k fixture).
    elf = read_library_bytes(str(STORED16K), "lib/arm64-v8a/libhello.so", 64)
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("lib/armeabi/libold.so", elf)
        zf.writestr("lib/mips/liboldmips.so", elf)
    model = scan_android_native(str(apk))
    assert model["abi_coverage"]["abi_retired"] == ["armeabi", "mips"]
    assert model["abi_coverage"]["abis"] == []


def test_unsafe_names_recorded_never_written(tmp_path: Path) -> None:
    model = scan_android_native(str(DATA / "zip_slip.apk"))
    entries = {u["entry"]: u["problems"] for u in model["unsafe_names"]}
    assert entries["../evil.so"] == ["parent_traversal"]
    assert entries["/data/local/tmp/evil.so"] == ["absolute_path"]
    assert entries["C:/evil/evil.so"] == ["drive_letter"]
    # No library was collected from the traversal names.
    assert all(not lib["name"].startswith("evil") for lib in model["libraries"])


def test_backslash_name_refused_by_name(tmp_path: Path) -> None:
    # Byte-patched fixture (A0.2): the backslash separator survived every
    # write path, and the reader records it even though it never extracts.
    model = scan_android_native(str(DATA / "zip_slip_backslash.apk"))
    assert any(
        u["problems"] == ["backslash_separator"] for u in model["unsafe_names"]
    )


def test_deep_bundle_refuses_by_name() -> None:
    model = scan_android_native(str(DATA / "deep_bundle.xapk"))
    assert "bundle_depth_exceeds_cap" in model["refusals"]
    assert MAX_BUNDLE_DEPTH == 2


def test_not_elf_library_flagged(tmp_path: Path) -> None:
    apk = tmp_path / "textso.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"stub")
        zf.writestr("lib/arm64-v8a/libtext.so", b"definitely not an elf\n")
    model = scan_android_native(str(apk))
    lib = _lib(model, "libtext.so")
    assert lib["not_elf"] is True
    # No header facts to disagree with the directory about.
    assert lib["abi_mismatch"] == []


def test_lib_count_cap_refuses_by_name(tmp_path: Path) -> None:
    # 600 stored entries over the 512 cap; generated inline per the same
    # .ZIP layout as make_hostile_fixtures.py (small stub ELFs).
    apk = tmp_path / "many.apk"
    stub = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 60
    with zipfile.ZipFile(apk, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("AndroidManifest.xml", b"stub")
        for i in range(MAX_NATIVE_LIBS + 88):
            zf.writestr(f"lib/arm64-v8a/lib{i:04d}.so", stub)
    model = scan_android_native(str(apk))
    assert "native_lib_count_exceeds_cap" in model["refusals"]
    # The cap bounds the collected set, and the refusal is visible beside
    # it (rule 32: never reads as an empty app).
    assert model["counts"]["libraries"] >= 1


def test_per_entry_size_cap_refuses_by_name(tmp_path: Path) -> None:
    from blint.lib.android_native import MAX_LIB_ENTRY_BYTES

    apk = tmp_path / "huge.apk"
    with zipfile.ZipFile(apk, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", b"stub")
        # ~1 GiB of zeros, deflated small; the read is streaming so the
        # fixture costs seconds, not memory.
        zf.writestr("lib/arm64-v8a/libhuge.so", b"\x00" * (MAX_LIB_ENTRY_BYTES + 1))
    model = scan_android_native(str(apk))
    assert any(r.startswith("lib_entry_exceeds_cap") for r in model["refusals"])


def test_read_library_bytes_is_bounded(tmp_path: Path) -> None:
    limit = 4096
    data = read_library_bytes(str(STORED16K), "lib/arm64-v8a/libhello.so", limit)
    assert data is not None and len(data) == limit
    assert data[:4] == b"\x7fELF"
    assert read_library_bytes(str(STORED16K), "no/such/entry.so", limit) is None


def test_abi_coverage_missing_library_matrix() -> None:
    from blint.lib.android_native import LibLocation, NativeLibrary

    def loc(abi: str) -> LibLocation:
        return LibLocation(
            container="a.apk", entry_name=f"lib/{abi}/libx.so", split="", abi=abi,
            location_kind="lib_dir", compression="stored", data_offset=4096,
            offset_mod_4096=0, offset_mod_16384=0, compressed_size=10,
            uncompressed_size=10, crc32=1,
        )

    libs = [
        NativeLibrary(sha256="a", name="libx.so", size=1, locations=[loc("arm64-v8a")]),
        NativeLibrary(
            sha256="b", name="libboth.so", size=1,
            locations=[loc("arm64-v8a"), loc("x86_64")],
        ),
    ]
    coverage = abi_coverage(libs)
    # libx is missing from x86_64 while libboth ships everywhere: the gap
    # is stated per name, never silently first-or-best (rule 36).
    assert coverage["missing_from_abi"] == {"libx.so": ["x86_64"]}
    assert coverage["requires_64_bit_coverage"] is False


def test_safe_name_problem_matrix() -> None:
    assert safe_name_problems("lib/ok.so") == []
    assert "parent_traversal" in safe_name_problems("a/../../x.so")
    assert "absolute_path" in safe_name_problems("/etc/x.so")
    assert "drive_letter" in safe_name_problems("C:/evil.so")
    assert "drive_letter" in safe_name_problems("c:evil.so")
    assert "backslash_separator" in safe_name_problems("lib\\evil.so")
