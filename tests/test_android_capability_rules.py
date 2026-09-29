"""The native Android capability rules against NDK-built fixtures.

The oracle is ``tests/data/android/a7-fixtures-manifest.json``'s
``expected`` table: every rule fires on its fire fixture and stays silent
on its no-fire fixture, on every ABI the rule evaluates. On armeabi-v7a no
rule reports, and the call-site gap is named in the coverage block. The
manifest records the build commands and toolchain versions.
"""

from __future__ import annotations

import json
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
    if abi in MODELLED_ABIS:
        inline = results["ANDROID_INLINE_SYSCALLS"]
        assert inline and inline[0]["site_total"] >= 1
        assert {"a7_inline_syscall", "a7_run_all"} <= {
            holder["function"] for holder in inline[0]["functions"]
        }
    else:
        # 32-bit ARM: nothing reports, not even a placeholder row.
        assert results == {}, results


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
        assert results == {}, results


@pytest.mark.parametrize("abi_flag", ["arm64-v8a_Os", "arm64-v8a_Oz", "x86_64_Os", "x86_64_Oz"])
def test_flag_variant_fixture_matches_the_manifest_table(abi_flag: str) -> None:
    # The -Os/-Oz twins (A7.2 R1) are pinned to the manifest's expected
    # table, which records what each flag does to each rule: the loop-held
    # su-path table silences the root probe everywhere, the arm64 -Oz
    # outliner hides dlopen until a pure thunk is followed, and the x86_64
    # -Oz tail jmp hides ptrace until the ELF resolver reads it pc-relative.
    if not _nyxstone_available():
        pytest.skip("nyxstone is not available")
    initialize_rules(BlintOptions())
    manifest = json.loads((DATA / "a7-fixtures-manifest.json").read_text(encoding="utf-8"))
    expected = manifest["expected"]["flag_variants"][abi_flag]
    for lib, rows in expected.items():
        results = _android_results(_parse_fixture(f"{lib}_{abi_flag}.so"))
        if isinstance(rows, str):
            assert results == {}, (lib, abi_flag, results)
            continue
        for rule, verdict in rows.items():
            fires = verdict.startswith("fire")
            assert bool(results.get(rule)) is fires, (lib, abi_flag, rule, verdict)


@pytest.mark.parametrize("abi_flag", ["arm64-v8a_Oz"])
def test_outlined_thunk_is_followed_and_its_moves_applied(abi_flag: str) -> None:
    # The arm64 -Oz machine outliner carries dlopen's RTLD_NOW in
    # OUTLINED_FUNCTION_0 (mov w1, #2; b dlopen): the call-site block names
    # dlopen through the thunk and the thunk's constant reaches argument 1.
    if not _nyxstone_available():
        pytest.skip("nyxstone is not available")
    from blint.lib.binary import parse

    metadata = parse(str(DATA / f"liba7_fire_{abi_flag}.so"), True)
    entries = metadata.get("call_site_arguments") or []
    via_thunk = [
        entry
        for entry in entries
        if entry.get("callee") == "dlopen" and entry.get("callee_via_thunk")
    ]
    assert via_thunk, entries
    paths = {entry.get("string") for entry in via_thunk if entry.get("argument") == 0}
    assert "/data/local/tmp/plugin.so" in paths
    flags = [entry for entry in via_thunk if entry.get("argument") == 1]
    assert flags and {entry.get("value") for entry in flags} == {2}
    # The -O2 build has no outlined thunk, so nothing there resolves via one.
    plain = parse(str(DATA / "liba7_fire_arm64-v8a.so"), True)
    assert not [
        entry
        for entry in plain.get("call_site_arguments") or []
        if entry.get("callee_via_thunk")
    ]


@pytest.mark.parametrize("abi", ABIS)
def test_unmodelled_abi_is_named_in_coverage_not_in_reviews(abi: str) -> None:
    # An ABI the call-site dataflow does not model is a coverage fact on the
    # library, never a review row carrying the rule's summary.
    if not _nyxstone_available():
        pytest.skip("nyxstone is not available")
    metadata = _parse_fixture(f"liba7_fire_{abi}.so")
    degradations = metadata["analysis_coverage"]["degradations"]
    if abi in MODELLED_ABIS:
        assert "callsite_abi_not_modelled" not in degradations
    else:
        assert "callsite_abi_not_modelled" in degradations
        assert _android_results(metadata) == {}


def test_truncated_call_site_block_is_a_coverage_degradation() -> None:
    from blint.lib.binary import _build_analysis_coverage

    coverage = _build_analysis_coverage(
        {"call_site_arguments_coverage": {"entries_truncated": True, "functions_no_abi": 0}},
        True,
    )
    assert "callsite_entries_truncated" in coverage["degradations"]
    assert "callsite_abi_not_modelled" not in coverage["degradations"]


def test_without_disassembly_the_rules_stay_silent() -> None:
    from blint.lib.binary import parse

    metadata = parse(str(DATA / "liba7_fire_arm64-v8a.so"))
    results = _android_results(metadata)
    assert results == {}, results


def test_non_android_elf_never_reports() -> None:
    # A desktop ELF carries no android facts block, so every rule is silent.
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
    # RootBeer 0.1.2's toolChecker receives its paths from Java, so its
    # library holds no constant; the dex rule covers that case.
    if not _nyxstone_available():
        pytest.skip("nyxstone is not available")
    results = _android_results(_parse_fixture("libtoolChecker_arm64-v8a.so"))
    real = {key: value for key, value in results.items() if key != "ANDROID_INLINE_SYSCALLS"}
    assert real == {}, real
    assert "ANDROID_INLINE_SYSCALLS" not in results


def test_dex_rule_fires_on_a7_apk_and_not_on_a5(tmp_path: Path) -> None:
    # The app-level conjunction: the merged dex metadata plus the JNI join
    # summary, the two blocks _process_android_app attaches before review.
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


def test_dex_rule_needs_a_list_of_su_directories() -> None:
    from blint.lib.android_reviews import evaluate_android_rule

    join = {"per_abi": {"arm64-v8a": {"bound": [{"method": "a"}], "bound_dynamic": []}}}
    one = {"android_jni": join, "informative_strings": ["/system/xbin/", "/data/"]}
    assert evaluate_android_rule("ANDROID_DEX_SU_PATHS_TO_NATIVE", one) == []
    two = {"android_jni": join, "informative_strings": [{"value": "/system/xbin/"}, "/su/bin/"]}
    evidence = evaluate_android_rule("ANDROID_DEX_SU_PATHS_TO_NATIVE", two)
    assert evidence and evidence[0]["su_path_strings"] == ["/su/bin/", "/system/xbin/"]
    unbound = {
        "android_jni": {"per_abi": {}},
        "informative_strings": ["/system/xbin/", "/su/bin/"],
    }
    assert evaluate_android_rule("ANDROID_DEX_SU_PATHS_TO_NATIVE", unbound) == []


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
        # The arm32 PLT shape is not decoded: no stubs rather than wrong ones.
        parsed_v7a = lief.ELF.parse(str(DATA / "liba7_fire_armeabi-v7a.so"))
        assert _elf_plt_stub_names(parsed_v7a) == {}


def test_su_execution_covers_the_dumpstate_string_append_form() -> None:
    # dumpstate's RunCommandToFd appends "/system/xbin/su" through
    # basic_string::append(char const*); the later execvp receives a register.
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
    # 32-bit ARM is not evaluated, even with a decoded svc site.
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
    assert evaluate_android_rule("ANDROID_INLINE_SYSCALLS", arm32) == []


# nyxstone's rendering of svc #0, syscall and int 0x80 in each IntegerBase
# (NYXSTONE_LLVM_PREFIX=llvm@18; aarch64 prints "#0" in every style).
SYSCALL_RENDERINGS = {
    "Dec": ("svc #0", "syscall\nint 128"),
    "HexPrefix": ("svc #0x0", "syscall\nint 0x80"),
    "HexSuffix": ("svc #0h", "syscall\nint 80h"),
}


def test_inline_syscall_sites_match_every_integer_base() -> None:
    from blint.lib.android_reviews import _INLINE_SYSCALL_RE

    for style, (arm, x86) in SYSCALL_RENDERINGS.items():
        assert len(_INLINE_SYSCALL_RE.findall(arm)) == 1, style
        assert len(_INLINE_SYSCALL_RE.findall(x86)) == 2, style
    for other in ("svc #1", "svc #0x80", "int 3", "int3", "syscalls"):
        assert not _INLINE_SYSCALL_RE.findall(other), other


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
