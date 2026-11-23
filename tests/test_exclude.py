"""Exclusion globs for the directory walks (``--exclude``)."""

import os
import shutil
import sys
from pathlib import Path

import pytest

from blint.api import analyze_many, sbom
from blint.cli import build_parser
from blint.lib.exclude import ExcludeMatcher, compile_excludes, relative_posix
from blint.lib.runners import discover_default_mode_inputs, discover_sbom_inputs
from blint.lib.utils import gen_file_list

PLAIN_ELF = Path(__file__).resolve().parent / "data" / "plain-libc-demo.elf"


@pytest.mark.parametrize(
    ("pattern", "path", "expected"),
    [
        # The shapes cdxgen's --exclude was measured to accept.
        ("test/**", "test", True),
        ("test/**", "test/a/b.dll", True),
        ("test/**", "sub/test/a.dll", False),
        ("**/test/**", "sub/test/a.dll", True),
        ("**/test/**", "contrib/deep/test", True),
        ("**/test/**", "sub/docs/a.dll", False),
        ("*/test/**", "sub/test/a.dll", True),
        ("*/test/**", "test/a.dll", False),
        ("*/test/**", "a/b/test/a.dll", False),
        ("*.nupkg", "a.nupkg", True),
        ("*.nupkg", "d/a.nupkg", False),
        ("**/*.nupkg", "d/e/a.nupkg", True),
        ("./ci/**", "ci/x", True),
        ("ci/", "ci/x", True),
        ("**/*.{nupkg,dll}", "x/a.dll", True),
        ("**/*.{nupkg,dll}", "x/a.exe", False),
        ("build-?/**", "build-1/a", True),
        ("build-?/**", "build-12/a", False),
        ("lib[ab]/**", "libb/x", True),
        ("lib[!ab]/**", "libb/x", False),
        ("probe/test/**", "test/x", False),
        ("**", "anything/at/all", True),
    ],
)
def test_matcher_follows_cdxgen_semantics(pattern, path, expected):
    assert ExcludeMatcher([pattern]).matches(path) is expected


def test_matcher_ignores_empty_input():
    assert not ExcludeMatcher(None)
    assert not ExcludeMatcher(["", "  "])
    assert not ExcludeMatcher(["test/**"]).matches("")
    assert compile_excludes(["a"]).patterns == ["a"]
    matcher = ExcludeMatcher(["a"])
    assert compile_excludes(matcher) is matcher


@pytest.mark.parametrize(
    ("path", "root", "expected"),
    [
        ("/scan/test/a.dll", "/scan", "test/a.dll"),
        ("/scan/test/a.dll", "/scan/", "test/a.dll"),
        ("C:\\scan\\test\\a.dll", "C:\\scan", "test/a.dll"),
        ("c:\\Scan\\test\\a.dll", "C:\\Scan\\", "test/a.dll"),
        ("C:\\scan\\test", "C:\\scan", "test"),
        ("C:\\scanner\\a.dll", "C:\\scan", None),
        ("/other/a.dll", "/scan", None),
        ("/scan", "/scan", ""),
    ],
)
def test_relative_posix_handles_windows_and_posix_paths(path, root, expected):
    assert relative_posix(path, root) == expected


def test_windows_paths_match_forward_slash_globs():
    matcher = ExcludeMatcher(["test/**", "**/obj/**"])
    assert matcher.is_excluded("C:\\scan\\test\\data\\a.nupkg", "C:\\scan")
    assert matcher.is_excluded("C:\\scan\\src\\obj\\a.dll", "C:\\scan")
    assert not matcher.is_excluded("C:\\scan\\src\\a.dll", "C:\\scan")
    assert not matcher.is_excluded("D:\\elsewhere\\test\\a.dll", "C:\\scan")


def _tree(tmp_path: Path) -> Path:
    """A scan root with the same binary at the top, in test/ and in sub/test/."""
    root = tmp_path / "scan"
    for rel in ("app.bin", "test/t.bin", "sub/test/s.bin", "sub/keep.bin", "ci/c.bin"):
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(PLAIN_ELF, target)
        target.chmod(0o755)
    return root


def _relative(root: Path, files) -> set[str]:
    return {Path(f).relative_to(root).as_posix() for f in files}


def test_gen_file_list_anchors_globs_at_the_scanned_directory(tmp_path):
    root = _tree(tmp_path)
    everything = _relative(root, gen_file_list([str(root)]))
    assert everything == {"app.bin", "test/t.bin", "sub/test/s.bin", "sub/keep.bin", "ci/c.bin"}
    anchored = _relative(root, gen_file_list([str(root)], ["test/**"]))
    assert anchored == everything - {"test/t.bin"}
    deep = _relative(root, gen_file_list([str(root)], ["**/test/**", "ci/**"]))
    assert deep == {"app.bin", "sub/keep.bin"}
    single = _relative(root, gen_file_list([str(root)], ["*/test/**"]))
    assert single == everything - {"sub/test/s.bin"}


def test_a_pattern_spelled_with_the_working_directory_matches_nothing(tmp_path):
    root = _tree(tmp_path)
    files = gen_file_list([str(root)], [f"{root.name}/test/**"])
    assert len(files) == 5


def test_an_explicit_file_is_never_excluded(tmp_path):
    root = _tree(tmp_path)
    named = str(root / "test" / "t.bin")
    assert gen_file_list([named], ["**"]) == [named]


def test_discovery_helpers_apply_the_exclusion(tmp_path):
    root = _tree(tmp_path)
    shutil.copy(PLAIN_ELF, root / "test" / "x.application")
    default_inputs = discover_default_mode_inputs([str(root)], ["test/**"])
    assert not any("test" + os.sep + "t.bin" in f for f in default_inputs)
    inputs = discover_sbom_inputs([str(root)], ["test/**"])
    assert _relative(root, inputs.exe_files) == {
        "app.bin",
        "sub/test/s.bin",
        "sub/keep.bin",
        "ci/c.bin",
    }


def test_android_ios_and_clickonce_files_are_excluded(tmp_path):
    root = tmp_path / "scan"
    for rel in ("test/a.apk", "test/b.ipa", "keep/a.apk", "keep/b.ipa", "test/c.application"):
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(b"x")
    inputs = discover_sbom_inputs([str(root)], ["test/**"])
    assert _relative(root, inputs.android_files) == {"keep/a.apk"}
    assert _relative(root, inputs.ios_files) == {"keep/b.ipa"}


@pytest.mark.skipif(sys.platform == "win32", reason="bundle directory names")
def test_macos_bundles_are_excluded(tmp_path):
    from blint.lib.macos_bundle import find_macos_bundles

    root = tmp_path / "scan"
    for rel in ("test/A.app", "keep/B.app"):
        (root / rel).mkdir(parents=True)
    found = find_macos_bundles(str(root), ["test/**"])
    assert [Path(f).name for f in found] == ["B.app"]


def test_inf_files_are_excluded(tmp_path):
    from blint.lib.inf import find_inf_files

    root = tmp_path / "scan"
    for rel in ("test/a.inf", "keep/b.inf"):
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text('[Version]\nSignature="$WINDOWS NT$"\n')
    assert [Path(f).name for f in find_inf_files(str(root), ["test/**"])] == ["b.inf"]


def test_cli_exposes_a_repeatable_exclude_option():
    for argv in (
        ["--exclude", "test/**", "--exclude", "ci/**"],
        ["sbom", "--exclude", "test/**", "--exclude", "ci/**"],
    ):
        assert build_parser().parse_args(argv).exclude == ["test/**", "ci/**"]
    assert build_parser().parse_args([]).exclude == []


def test_api_entry_points_take_exclude(tmp_path):
    root = _tree(tmp_path)
    result = sbom(str(root), exclude=["test/**", "sub/**", "ci/**"])
    assert result.coverage["units"]["executables"] == 1
    batch = analyze_many(str(root), exclude=["**"])
    assert batch.coverage["units"]["attempted"] == 0
