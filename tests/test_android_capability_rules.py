"""A7 K2 — the native Android capability rules against the R1 fixtures.

The oracle is ``tests/data/android/a7-fixtures-manifest.json``'s
``expected`` table: every rule fires on its fire fixture and stays silent
on its no-fire fixture, on every ABI the rule evaluates; on armeabi-v7a
the call-site rules report ``not_evaluated`` as a fact (ground rule 35)
while the instruction-text rule still evaluates. The fixtures are real
NDK builds — see the manifest for commands and versions.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from blint.config import BlintOptions
from blint.lib.analysis import initialize_rules

DATA = Path(__file__).parent / "data" / "android"
ABIS = ("arm64-v8a", "armeabi-v7a", "x86_64")

MODELLED_ABIS = ("arm64-v8a", "x86_64")

CALL_SITE_RULES = (
    "ANDROID_PTRACE_TRACEME",
    "ANDROID_ROOT_PATH_PROBE",
    "ANDROID_SU_EXECUTION",
    "ANDROID_EMULATOR_PROPERTY_PROBE",
    "ANDROID_WRITABLE_LOCATION_DLOPEN",
)
def _nyxstone_available() -> bool:
    try:
        from blint.lib.disassembler import NYXSTONE_AVAILABLE

        return NYXSTONE_AVAILABLE
    except Exception:
        return False


def _android_results(metadata: dict) -> dict[str, list[dict]]:
    from blint.lib.review_runner import ReviewRunner

    runner = ReviewRunner()
    runner.run_review(metadata)
    return {key: value for key, value in runner.results.items() if key.startswith("ANDROID_")}


def _parse_fixture(name: str) -> dict:
    from blint.lib.binary import parse

    metadata = parse(str(DATA / name), True)
    assert metadata.get("binary_type") == "ELF"
    return metadata


def test_rules_are_registered_for_elf_and_dex() -> None:
    initialize_rules(BlintOptions())
    from blint.lib.analysis import review_binary_dict

    elf_rules = set()
    for block in review_binary_dict.get("ELF") or []:
        elf_rules.update(block)
    for rule in CALL_SITE_RULES:
        assert rule in elf_rules, rule
    assert "ANDROID_INLINE_SYSCALLS" in elf_rules
    dex_rules = set()
    for block in review_binary_dict.get("dexbinary") or []:
        dex_rules.update(block)
    assert "ANDROID_DEX_SU_PATHS_TO_NATIVE" in dex_rules


@pytest.mark.parametrize("abi", ABIS)
def test_fire_fixture_fires_every_rule(abi: str) -> None:
    if not _nyxstone_available():
        pytest.skip("nyxstone is not available")
    results = _android_results(_parse_fixture(f"liba7_fire_{abi}.so"))
    if abi in MODELLED_ABIS:
        for rule in CALL_SITE_RULES:
            assert rule in results, (rule, abi)
        # The call-site evidence names the constant, never just the import.
        for entry in results["ANDROID_PTRACE_TRACEME"]:
            assert entry["request"] == 0
            assert entry["request_name"] == "PTRACE_TRACEME"
        root_paths = {entry["path"] for entry in results["ANDROID_ROOT_PATH_PROBE"]}
        assert "/system/xbin/su" in root_paths
        exec_constants = {entry["path"] for entry in results["ANDROID_SU_EXECUTION"]}
        # The command form: system()/popen() constants carry the whole line.
        assert any(path.endswith("su -c id") for path in exec_constants)
        properties = {entry["property"] for entry in results["ANDROID_EMULATOR_PROPERTY_PROBE"]}
        assert "ro.kernel.qemu" in properties
        load_paths = {entry["path"] for entry in results["ANDROID_WRITABLE_LOCATION_DLOPEN"]}
        assert "/data/local/tmp/plugin.so" in load_paths
    # The instruction-text rule fires on the modelled ABIs; on v7a it
    # reports not_evaluated (the arm32 extent-overrun measurement).
    inline = results["ANDROID_INLINE_SYSCALLS"]
    if abi in MODELLED_ABIS:
        assert inline and inline[0]["site_total"] >= 1
        assert {"a7_inline_syscall", "a7_run_all"} <= {
            holder["function"] for holder in inline[0]["functions"]
        }
    else:
        assert inline and inline[0]["status"] == "not_evaluated"
        assert inline[0]["reason"] == "arm32_recovery_unreliable"
        assert "llvm-objdump" in inline[0]["detail"]


@pytest.mark.parametrize("abi", ABIS)
def test_nofire_fixture_stays_silent(abi: str) -> None:
    if not _nyxstone_available():
        pytest.skip("nyxstone is not available")
    results = _android_results(_parse_fixture(f"liba7_nofire_{abi}.so"))
    real = {key: value for key, value in results.items() if key != "ANDROID_INLINE_SYSCALLS"}
    if abi in MODELLED_ABIS:
        # The crash handler's ptrace(PTRACE_ATTACH), the /proc/self/maps
        # read, the SDK probe, the shell execve and the bare-SONAME dlopen
        # are all present in this binary and all stay silent.
        assert real == {}, real
        assert "ANDROID_INLINE_SYSCALLS" not in results
    else:
        # Unmodelled ABI: all six rules each say so as a fact.
        assert set(real) == set(CALL_SITE_RULES)
        for entries in real.values():
            assert entries[0]["status"] == "not_evaluated"
            assert entries[0]["reason"] == "abi_not_modelled"
        inline = results["ANDROID_INLINE_SYSCALLS"]
        assert inline and inline[0]["reason"] == "arm32_recovery_unreliable"


@pytest.mark.parametrize("abi", ABIS)
def test_unmodelled_abi_reports_not_evaluated(abi: str) -> None:
    if not _nyxstone_available():
        pytest.skip("nyxstone is not available")
    if abi in MODELLED_ABIS:
        pytest.skip("absint models this ABI")
    results = _android_results(_parse_fixture(f"liba7_fire_{abi}.so"))
    for rule in CALL_SITE_RULES:
        assert rule in results, rule
        entries = results[rule]
        assert entries[0]["status"] == "not_evaluated"
        assert entries[0]["reason"] == "abi_not_modelled"
        assert "arm64 and x86_64" in entries[0]["detail"]


def test_without_disassembly_the_rules_stay_silent_like_every_disassembly_layer() -> None:
    # A plain parse (no --disassemble) of an Android library: the call-site
    # rules are silent, exactly as the stack-string and function-review
    # layers are — the run's analysis coverage already names the missing
    # disassembly globally, and per-rule notes would be boilerplate on
    # every library. The not_evaluated fact is reserved for the cases a
    # disassembled report could mistake for absence (unmodelled ABI,
    # truncated block) — asserted in the v7a tests above.
    from blint.lib.binary import parse

    metadata = parse(str(DATA / "liba7_fire_arm64-v8a.so"))
    results = _android_results(metadata)
    assert results == {}, results


def test_non_android_elf_never_reports() -> None:
    # A desktop ELF carries no android facts block; every rule is silent
    # rather than guessing (the fixture is blint's own committed ELF test
    # binary territory, so a synthetic metadata shape is the honest unit).
    from blint.lib.review_runner import ReviewRunner

    initialize_rules(BlintOptions())
    metadata = {
        "exe_type": "genericbinary",
        "binary_type": "ELF",
        "name": "libdesktop.so",
        "magic": "7f 45 4c 46",
        "strings": [{"value": "/system/xbin/su"}, {"value": "ro.kernel.qemu"}],
    }
    runner = ReviewRunner()
    runner.run_review(metadata)
    android_rules = {key for key in runner.results if key.startswith("ANDROID_")}
    assert android_rules == set()


def test_rootbeer_native_library_holds_no_fire_evidence() -> None:
    # Measurement 4: toolChecker at 0.1.2 receives its paths from Java, so
    # the native side fires nothing — the dex rule carries that case.
    if not _nyxstone_available():
        pytest.skip("nyxstone is not available")
    results = _android_results(_parse_fixture("libtoolChecker_arm64-v8a.so"))
    real = {key: value for key, value in results.items() if key != "ANDROID_INLINE_SYSCALLS"}
    assert real == {}, real
    assert "ANDROID_INLINE_SYSCALLS" not in results


def test_dex_rule_fires_on_a7_apk_and_not_on_a5(tmp_path: Path) -> None:
    # The app-level conjunction: analyze_android_app's merged dex metadata
    # plus the A5 JNI join summary, exactly the two blocks
    # _process_android_app attaches before the review runs.
    from blint.lib.android import analyze_android_app
    from blint.lib.android_native import scan_android_native
    from blint.lib.jni import build_jni_join_summary

    initialize_rules(BlintOptions())
    for apk, expect_fire in (
        ("a7-jni-arm64-v8a.apk", True),
        ("a5-jni-arm64-v8a.apk", False),
    ):
        metadata = analyze_android_app(str(DATA / apk), build_cg=False)
        assert metadata is not None
        native = scan_android_native(str(DATA / apk))
        join = build_jni_join_summary(str(DATA / apk), native)
        assert join, apk
        metadata["android_jni"] = join
        results = _android_results(metadata)
        rule = results.get("ANDROID_DEX_SU_PATHS_TO_NATIVE")
        if expect_fire:
            assert rule, apk
            entry = rule[0]
            assert "/system/xbin/" in entry["su_path_strings"]
            assert "/su/bin/" in entry["su_path_strings"]
            # The generic directories alone never match.
            assert "/data/" not in entry["su_path_strings"]
            assert entry["bound_native_declarations"] >= 2
        else:
            assert rule is None, apk


def test_su_path_matcher_forms() -> None:
    from blint.lib.android_reviews import _SU_COMMAND_RE, _SU_PATH_SUFFIX_RE

    for path in ("/system/bin/su", "/system/xbin/su", "/su/bin/su", "su"):
        assert _SU_PATH_SUFFIX_RE.search(path), path
    for path in ("/system/bin/sum", "/system/bin/sudo", "/sudo", "/su.bin/su2"):
        assert not _SU_PATH_SUFFIX_RE.search(path), path
    for command in ("/system/bin/su -c id", "/system/xbin/su -c id", "su -c id"):
        assert _SU_COMMAND_RE.search(command), command
    for command in ("/system/bin/sum -c id", "/system/bin/sudo -c id"):
        assert not _SU_COMMAND_RE.search(command), command


def test_plt_stub_names_decode_the_fixture_table() -> None:
    import lief

    from blint.lib.disassembler import _elf_plt_stub_names

    for name, machine_marker in (
        ("liba7_fire_arm64-v8a.so", "ptrace"),
        ("liba7_fire_x86_64.so", "ptrace"),
    ):
        parsed = lief.ELF.parse(str(DATA / name))
        stubs = _elf_plt_stub_names(parsed)
        assert stubs, name
        assert machine_marker in stubs.values(), name
        # The arm32 PLT shape is not decoded (documented): a v7a library
        # returns no stubs rather than wrong ones.
        parsed_v7a = lief.ELF.parse(str(DATA / "liba7_fire_armeabi-v7a.so"))
        assert _elf_plt_stub_names(parsed_v7a) == {}


def test_su_execution_covers_the_dumpstate_string_append_form() -> None:
    # llvm-objdump of the api36 libdumpstateutil: RunCommandToFd appends
    # "/system/xbin/su" through basic_string::append(char const*) and the
    # later execvp receives a register - the recoverable half is the append.
    from blint.lib.android_reviews import evaluate_android_rule

    metadata = {
        "binary_type": "ELF",
        "llvm_target_tuple": "aarch64-unknown-linux-android",
        "android": {"soname": "libdumpstateutil.so"},
        "call_site_arguments_coverage": {"entries": 1},
        "call_site_arguments": [
            {
                "callee": "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEPKc",
                "argument": 1,
                "value": 0x25D4,
                "string": "/system/xbin/su",
                "site_count": 1,
                "functions": ["android::os::dumpstate::RunCommandToFd(...)"],
            }
        ],
    }
    evidence = evaluate_android_rule("ANDROID_SU_EXECUTION", metadata)
    assert len(evidence) == 1
    assert evidence[0]["via"] == "string_append"
    assert evidence[0]["path"] == "/system/xbin/su"
    # The benign counterpart: appending an unrelated path stays silent.
    metadata["call_site_arguments"][0]["string"] = "/system/bin/dumpstate"
    assert evaluate_android_rule("ANDROID_SU_EXECUTION", metadata) == []


def test_inline_syscall_exclusions_by_name_and_buildinfo() -> None:
    from blint.lib.android_reviews import evaluate_android_rule

    base = {
        "binary_type": "ELF",
        "llvm_target_tuple": "aarch64-unknown-linux-android",
        "call_site_arguments_coverage": {"entries": 0},
        "android": {"soname": None},
        "disassembled_functions": {
            "f::do_raw": {
                "name": "do_raw",
                "address": "0x1000",
                "assembly": "mov x8, #64\nsvc #0\nret",
            }
        },
    }
    fires = evaluate_android_rule("ANDROID_INLINE_SYSCALLS", dict(base, name="libmine.so"))
    assert fires and fires[0]["site_total"] == 1
    # bionic libc and the sanitizer runtimes are excluded by name.
    bionic = dict(base, name="libc.so", android={"soname": "libc.so"})
    assert evaluate_android_rule("ANDROID_INLINE_SYSCALLS", bionic) == []
    runtime = dict(base, name="libclang_rt.asan-aarch64-android.so")
    assert evaluate_android_rule("ANDROID_INLINE_SYSCALLS", runtime) == []
    # Go-built libraries are excluded by buildinfo.
    go = dict(base, name="libgo.so", build_info={"go_version": "go1.24.0"})
    assert evaluate_android_rule("ANDROID_INLINE_SYSCALLS", go) == []
    # ARM32: even a decoded svc site does not carry a finding - the R3
    # hand-check measured extent-overrun false sites on stripped v7a
    # libraries (llvm-objdump oracle: 25 false vs 2 true), so the ABI
    # reports not_evaluated with that reason instead.
    arm32 = dict(
        base,
        name="libflutter.so",
        llvm_target_tuple="armv7a-unknown-linux-androideabi24",
        disassembled_functions={
            "f::stub": {
                "name": "stub",
                "address": "0x1000",
                "assembly": "movs r0, r0\nsvc #0\nmovs r0, r0",
            }
        },
    )
    verdict = evaluate_android_rule("ANDROID_INLINE_SYSCALLS", arm32)
    assert verdict and verdict[0]["status"] == "not_evaluated"
    assert verdict[0]["reason"] == "arm32_recovery_unreliable"


def test_writable_prefix_boundaries() -> None:
    from blint.lib.android_reviews import _is_writable_load_path

    for path in (
        "/data/local/tmp/plugin.so",
        "/sdcard/Android/data/plugin.so",
        "/storage/emulated/0/plugin.so",
        "/data/data/com.example/files/libextra.so",
        "/data/local/tmp",
    ):
        assert _is_writable_load_path(path), path
    for path in (
        "/system/lib64/libmine.so",
        "/data/local/tmpx/plugin.so",
        "/sdcardX/plugin.so",
        "/datadata/plugin.so",
        "libc++_shared.so",
    ):
        assert not _is_writable_load_path(path), path
