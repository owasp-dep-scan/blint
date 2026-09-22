"""Tests for the shared bounded container framework (W4.1).

Ground rule 30: every cap the framework enforces gets a hostile fixture that
*exceeds* it — a cap approached is a cap untested — and asserts the refusal
by name. Ground rule 18: extraction cleanup is asserted as a live
temp-directory delta, never read from the code.
"""

import glob
import os
import tempfile
import zipfile

import pytest

from blint.lib.container import (
    ContainerLimits,
    bounded_temp_dir,
    extract_zip_members,
    member_path_unsafe,
    read_zip_member_bounded,
    walk_zip_members,
    zip_member_is_symlink,
)

LIMITS = ContainerLimits(
    max_members=8,
    max_total_uncompressed=1024 * 1024,
    max_member_size=64 * 1024,
    max_member_depth=4,
    max_member_compression_ratio=128,
)


def _live_framework_temp_dirs() -> set[str]:
    return set(glob.glob(os.path.join(tempfile.gettempdir(), "blint_container_test_*")))


@pytest.mark.parametrize(
    "name",
    [
        "../evil.txt",
        "lib/../../evil.txt",
        "/etc/passwd",
        "//server/share/x",
        "C:evil.dll",
        # The drive-absolute form, which is what an archiver actually
        # writes and what ntpath.join actually honours (the W3.5 review
        # finding): joining an output directory with it discards the base.
        "C:/evil/evil.dll",
        "c:/evil.dll",
        r"back\slash.dll",
        "",
        "with\x00nul",
    ],
)
def test_unsafe_member_paths(name):
    assert member_path_unsafe(name) is True


@pytest.mark.parametrize(
    "name",
    [
        "Payload/App.exe",
        "AppxManifest.xml",
        "a/b/c/d.dll",
        "weird name with spaces.txt",
        "dot.name.dll",
    ],
)
def test_safe_member_paths(name):
    assert member_path_unsafe(name) is False


def test_zip_member_is_symlink_detected_from_mode_bits():
    info = zipfile.ZipInfo("link")
    info.external_attr = (0o120777 << 16) | 0o777
    assert zip_member_is_symlink(info) is True
    plain = zipfile.ZipInfo("file")
    plain.external_attr = (0o100644 << 16) | 0o644
    assert zip_member_is_symlink(plain) is False


def _zip_with_members(path, names, sizes=None):
    with zipfile.ZipFile(path, "w") as zf:
        for index, name in enumerate(names):
            size = sizes[index] if sizes else 16
            zf.writestr(name, b"A" * size)


def test_member_count_cap_refused_by_name(tmp_path):
    archive_path = tmp_path / "many.zip"
    _zip_with_members(archive_path, [f"f{i}" for i in range(20)])
    refusals: list[str] = []
    with zipfile.ZipFile(archive_path) as archive:
        accepted = walk_zip_members(archive, LIMITS, refusals)
    assert len(accepted) == LIMITS.max_members
    assert "member_count_exceeds_cap" in refusals


def test_total_uncompressed_cap_refused_by_name(tmp_path):
    archive_path = tmp_path / "big.zip"
    # Members stay under the per-member cap (64 KB) so the sum is what
    # trips: 6 x 190 KB > the 1 MB total.
    limits = ContainerLimits(
        max_members=LIMITS.max_members,
        max_total_uncompressed=1024 * 1024,
        max_member_size=256 * 1024,
        max_member_depth=LIMITS.max_member_depth,
        max_member_compression_ratio=LIMITS.max_member_compression_ratio,
    )
    _zip_with_members(archive_path, [f"f{i}" for i in range(6)], sizes=[190 * 1024] * 6)
    refusals: list[str] = []
    with zipfile.ZipFile(archive_path) as archive:
        accepted = walk_zip_members(archive, limits, refusals)
    assert len(accepted) < 6
    assert "total_uncompressed_exceeds_cap" in refusals


def test_member_size_cap_refused_by_name(tmp_path):
    archive_path = tmp_path / "member.zip"
    _zip_with_members(archive_path, ["small", "huge"], sizes=[16, 300 * 1024])
    refusals: list[str] = []
    with zipfile.ZipFile(archive_path) as archive:
        accepted = walk_zip_members(archive, LIMITS, refusals)
    assert [info.filename for info in accepted] == ["small"]
    assert "member_size_exceeds_cap" in refusals


def test_member_depth_cap_refused_by_name(tmp_path):
    archive_path = tmp_path / "deep.zip"
    _zip_with_members(archive_path, ["a/b/c/d/e/too_deep.dll", "shallow.dll"])
    refusals: list[str] = []
    with zipfile.ZipFile(archive_path) as archive:
        accepted = walk_zip_members(archive, LIMITS, refusals)
    assert [info.filename for info in accepted] == ["shallow.dll"]
    assert "member_depth_exceeds_cap" in refusals


def test_compression_ratio_cap_refused_by_name(tmp_path):
    """The zip-bomb bound: a member that decompresses past the ratio cap
    while staying under the per-member size cap — the ratio is the only
    bound that sees it."""
    archive_path = tmp_path / "bomb.zip"
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("bomb", b"\x00" * (60 * 1024))
    refusals: list[str] = []
    with zipfile.ZipFile(archive_path) as archive:
        accepted = walk_zip_members(archive, LIMITS, refusals)
    assert accepted == []
    assert "member_compression_ratio_exceeds_cap" in refusals


def test_read_member_bounded_refuses_declared_oversize_by_name(tmp_path):
    archive_path = tmp_path / "big_member.zip"
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("liar", b"B" * (256 * 1024))
    refusals: list[str] = []
    with zipfile.ZipFile(archive_path) as archive:
        info = archive.infolist()[0]
        data = read_zip_member_bounded(archive, info, 64 * 1024, refusals)
    assert data is None
    assert "member_size_exceeds_cap" in refusals


def test_extract_refuses_inconsistent_member_without_absorbing(tmp_path):
    """A member whose declared size was tampered with does not open at all —
    zipfile validates the entry against its central-directory record and
    raises — so the extraction refuses it by name and carries on with the
    healthy members. Nothing inconsistent is written."""
    dest = tmp_path / "out"
    dest.mkdir()
    archive_path = tmp_path / "liar2.zip"
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("fine.txt", b"ok")
        zf.writestr("liar", b"C" * 4096)
    refusals: list[str] = []
    with zipfile.ZipFile(archive_path) as archive:
        infos = archive.infolist()
        infos[1].file_size = 16
        extracted = extract_zip_members(archive, infos, str(dest), LIMITS, refusals)
    assert set(extracted) == {"fine.txt"}
    assert "member_unreadable" in refusals
    assert not (dest / "liar").exists()
    assert (dest / "fine.txt").read_bytes() == b"ok"


def test_bounded_temp_dir_cleans_up_on_exception():
    before = _live_framework_temp_dirs()
    with pytest.raises(RuntimeError), bounded_temp_dir(prefix="blint_container_test_") as temp_dir:
        assert os.path.isdir(temp_dir)
        raise RuntimeError("boom")
    after = _live_framework_temp_dirs()
    assert after - before == set()


def test_bounded_temp_dir_cleans_up_on_success():
    before = _live_framework_temp_dirs()
    with bounded_temp_dir(prefix="blint_container_test_") as temp_dir:
        assert os.path.isdir(temp_dir)
    after = _live_framework_temp_dirs()
    assert after - before == set()
    assert not os.path.isdir(temp_dir)
