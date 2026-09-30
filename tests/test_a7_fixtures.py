"""The native capability-review fixtures.

The fixtures are real NDK r28c builds (commands and versions in
``tests/data/android/a7-fixtures-manifest.json``, sources in
``tests/scripts/android/a7_sources/``). This file pins the fixtures
themselves, independent of the rules:

- the committed binaries match the manifest's build description;
- every fixture parses as an Android-targeting ELF with the expected
  import/symbol surface;
- the inline-syscall family's fire/no-fire is already decidable from the
  disassembly text (``svc #0`` / ``syscall`` / ``int 128``), per ABI;
- the RootBeer library keeps the 0.1.2 JNI exports and holds no constant
  su path of its own, while the a7 APKs carry the dex half plus all three
  libraries.

The rules' fire/no-fire table (the manifest's ``expected`` block) is
asserted in ``test_android_capability_rules.py``.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from blint.lib.binary import parse

DATA = Path(__file__).parent / "data" / "android"
ABIS = ("arm64-v8a", "armeabi-v7a", "x86_64")
FIRE = {abi: DATA / f"liba7_fire_{abi}.so" for abi in ABIS}
NOFIRE = {abi: DATA / f"liba7_nofire_{abi}.so" for abi in ABIS}
TOOLCHECKER = {abi: DATA / f"libtoolChecker_{abi}.so" for abi in ABIS}
APKS = {abi: DATA / f"a7-jni-{abi}.apk" for abi in ABIS}

# The exported function each fire family lives behind.
FIRE_FUNCTIONS = (
    "a7_anti_debug",
    "a7_root_check",
    "a7_su_exec",
    "a7_emulator_fingerprint",
    "a7_writable_dlopen",
    "a7_inline_syscall",
    "a7_run_all",
)
NOFIRE_FUNCTIONS = (
    "a7_unwinder",
    "a7_crash_handler",
    "a7_sdk_probe",
    "a7_shell_exec",
    "a7_soname_dlopen",
    "a7_nofire_run",
)

ROOTBEER_JNI_EXPORTS = (
    "Java_com_scottyab_rootbeer_RootBeerNative_checkForRoot",
    "Java_com_scottyab_rootbeer_RootBeerNative_setLogDebugMessages",
)

INLINE_SYSCALL_MARKERS = {
    "arm64-v8a": ("svc #0",),
    "armeabi-v7a": ("svc #0",),
    "x86_64": ("syscall", "int 128"),
}


def _nyxstone_available() -> bool:
    try:
        from blint.lib.disassembler import NYXSTONE_AVAILABLE

        return NYXSTONE_AVAILABLE
    except Exception:
        return False


def _metadata(path: Path, disassemble: bool = False) -> dict:
    metadata = parse(str(path), disassemble)
    assert metadata.get("binary_type") == "ELF"
    return metadata


def _imported_names(metadata: dict) -> set[str]:
    return {
        entry.get("name", "")
        for entry in metadata.get("dynamic_symbols", [])
        if isinstance(entry, dict) and entry.get("is_imported")
    }


def _function_names(metadata: dict) -> set[str]:
    return {entry.get("name", "") for entry in metadata.get("functions", []) if entry.get("name")}


def test_manifest_names_the_build_commands() -> None:
    manifest = json.loads((DATA / "a7-fixtures-manifest.json").read_text(encoding="utf-8"))
    assert manifest["tools"]["ndk"].startswith("28.2.13676358")
    builds = manifest["builds"]
    for fixture in (
        "liba7_fire_<abi>.so",
        "liba7_nofire_<abi>.so",
        "libtoolChecker_<abi>.so",
        "a7-classes.dex",
        "a7-jni-<abi>.apk",
    ):
        assert fixture in builds, fixture
    assert "rootbeer/toolChecker.cpp" in manifest["sources"]
    assert "verbatim" in manifest["sources"]["rootbeer/toolChecker.cpp"]
    expected = manifest["expected"]
    # Every family has a fire and a no-fire case, and each armeabi-v7a
    # column says the rule does not evaluate there.
    for rule in (
        "ANDROID_PTRACE_TRACEME",
        "ANDROID_ROOT_PATH_PROBE",
        "ANDROID_SU_EXECUTION",
        "ANDROID_EMULATOR_PROPERTY_PROBE",
        "ANDROID_WRITABLE_LOCATION_DLOPEN",
        "ANDROID_INLINE_SYSCALLS",
    ):
        assert rule in expected, rule
    for rule in expected:
        if rule == "ANDROID_DEX_SU_PATHS_TO_NATIVE" or not isinstance(expected[rule], dict):
            continue
        for lib, table in expected[rule].items():
            if not (isinstance(table, dict) and "armeabi-v7a" in table):
                continue
            if rule == "ANDROID_INLINE_SYSCALLS":
                # The instruction-text rule evaluates everywhere; since
                # A7.2 M3 stopped 32-bit ARM extents at the literal pools,
                # its armeabi-v7a cells state a fire/silent verdict.
                assert "not evaluated" not in table["armeabi-v7a"], (rule, lib)
            else:
                # The call-site rules still need the modelled ABIs.
                assert "not evaluated" in table["armeabi-v7a"], (rule, lib)


@pytest.mark.parametrize("abi", ABIS)
def test_fire_fixture_surface(abi: str) -> None:
    metadata = _metadata(FIRE[abi])
    assert metadata.get("is_targeting_android") is True
    assert isinstance(metadata.get("android"), dict)
    names = _function_names(metadata)
    for name in FIRE_FUNCTIONS:
        assert name in names, name
    imports = _imported_names(metadata)
    for expected_import in ("ptrace", "access", "stat", "fopen", "execl", "system", "popen"):
        assert expected_import in imports, expected_import
    assert "__system_property_get" in imports
    assert "dlopen" in imports


@pytest.mark.parametrize("abi", ABIS)
def test_nofire_fixture_surface(abi: str) -> None:
    metadata = _metadata(NOFIRE[abi])
    assert metadata.get("is_targeting_android") is True
    names = _function_names(metadata)
    for name in NOFIRE_FUNCTIONS:
        assert name in names, name
    imports = _imported_names(metadata)
    # Every benign single signal is present — that is the point of the
    # fixture: ptrace, properties, execve and dlopen all appear, and the
    # rules still stay silent because no call-site constant matches.
    for expected_import in ("ptrace", "__system_property_get", "execve", "dlopen"):
        assert expected_import in imports, expected_import


@pytest.mark.parametrize("abi", ABIS)
def test_rootbeer_library_keeps_jni_exports_and_no_constant_su_path(abi: str) -> None:
    metadata = _metadata(TOOLCHECKER[abi])
    names = _function_names(metadata)
    for export in ROOTBEER_JNI_EXPORTS:
        assert export in names, export
    # Measurement 4: the su paths arrive through JNI, so the gated strings
    # list of the native library carries none of them.
    values = [
        item.get("value", "") if isinstance(item, dict) else str(item)
        for item in metadata.get("strings") or []
    ]
    assert not any("su" in value.rsplit("/", 1)[-1] for value in values if "/" in value)


@pytest.mark.parametrize("abi", ABIS)
def test_inline_syscall_sites_decode_on_every_abi(abi: str) -> None:
    # A disassembler-level fact, independent of the rule (which does not
    # evaluate 32-bit ARM): the encodings decode as svc #0 / syscall /
    # int 128 in the fire fixture and nowhere in the no-fire twin.
    if not _nyxstone_available():
        pytest.skip("nyxstone is not available")
    fire = _metadata(FIRE[abi], disassemble=True)
    holders = _functions_holding_inline_syscalls(fire)
    assert holders, f"expected inline syscall sites in the {abi} fire fixture"
    assert {"a7_inline_syscall", "a7_run_all"} <= holders
    nofire = _metadata(NOFIRE[abi], disassemble=True)
    assert _functions_holding_inline_syscalls(nofire) == set()


def _functions_holding_inline_syscalls(metadata: dict) -> set[str]:
    import re

    # blint renders x86's int 0x80 in decimal (int 128); arm64 and Thumb
    # render svc #0 (the A4a disassembly).
    pattern = re.compile(r"\bsvc\s+#?0\b|\bsyscall\b|\bint\s+(?:0x80|128)\b")
    holders: set[str] = set()
    for key, func_data in (metadata.get("disassembled_functions") or {}).items():
        assembly = str((func_data or {}).get("assembly") or "")
        if assembly and pattern.search(assembly):
            holders.add(str(func_data.get("name") or key))
    return holders


@pytest.mark.parametrize("abi", ABIS)
def test_a7_apk_carries_dex_and_all_three_libraries(abi: str) -> None:
    with zipfile.ZipFile(APKS[abi]) as zf:
        names = set(zf.namelist())
    assert "classes.dex" in names
    for member in (
        f"lib/{abi}/liba7fire.so",
        f"lib/{abi}/liba7nofire.so",
        f"lib/{abi}/libtoolChecker.so",
    ):
        assert member in names, member


def test_a7_dex_declares_the_native_methods_and_su_paths() -> None:
    # The dex half of the join: parse it with blint's own dex reader and
    # check the const-string surface plus the native declarations.
    import tempfile

    from blint.lib.binary import parse_dex
    from blint.lib.dalvik_review import build_review_metadata
    from blint.lib.jni import collect_dex_native_facts

    with tempfile.TemporaryDirectory() as tmp:
        with zipfile.ZipFile(APKS["arm64-v8a"]) as zf:
            target = str(Path(tmp) / "classes.dex")
            with open(target, "wb") as handle:
                handle.write(zf.read("classes.dex"))
        dex = parse_dex(target)
        strings = set(build_review_metadata(dex).get("informative_strings") or [])
        natives = collect_dex_native_facts(dex).get("natives") or []
    # RootBeer's directory list rides the dex (the specific entries; the
    # generic ones like /data/ alone do not identify a root probe).
    for su_directory in ("/system/xbin/", "/su/bin/", "/system/usr/we-need-root/"):
        assert su_directory in strings, su_directory
    native_names = {entry.get("name") for entry in natives}
    assert "checkForRoot" in native_names
    assert "setLogDebugMessages" in native_names
