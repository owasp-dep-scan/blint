"""Regression tests for the v4 security-hardening pass.

Each test pins one fix from the adversarial review so a later change cannot
silently reopen it. Every "hostile fixture exceeds the cap / escapes the dir"
case asserts the refusal or the containment by name, not merely the absence of
a crash.
"""

import os
import struct
import zlib

import pytest

from blint.lib.container import (
    ContainerLimits,
    extract_zip_to_dir,
)

# ---------------------------------------------------------------------------
# F1 — 7z-SFX member-name path traversal (arbitrary file write)
# ---------------------------------------------------------------------------


def _canonical_number(value: int) -> bytes:
    if value < 0x80:
        return bytes([value])
    for k in range(1, 8):
        if value < (1 << (8 * k)) and (value >> (8 * k)) < (1 << (7 - k)):
            first = ((0xFF << (8 - k)) & 0xFF) | (value >> (8 * k))
            out = bytes([first])
            for i in range(k):
                out += bytes([(value >> (8 * i)) & 0xFF])
            return out
    raise ValueError("value too large")


def _build_sevenz(member_name: str, content: bytes) -> bytes:
    """A minimal single-member 7z archive (plain kHeader, copy coder)."""
    magic = b"7z\xbc\xaf\x27\x1c"
    pack = content
    unpack_size = len(pack)
    pack_info = bytearray()
    pack_info += _canonical_number(0)
    pack_info += _canonical_number(1)
    pack_info.append(0x09)  # kSize
    pack_info += _canonical_number(unpack_size)
    pack_info.append(0x00)  # kEnd
    folder = bytearray()
    folder += _canonical_number(1)  # numCoders
    folder.append(0x01)  # flags: id_size 1
    folder.append(0x00)  # copy coder
    unpack_info = bytearray()
    unpack_info.append(0x0B)  # kFolder
    unpack_info += _canonical_number(1)
    unpack_info.append(0)  # external
    unpack_info += folder
    unpack_info.append(0x0C)  # kCodersUnpackSize
    unpack_info += _canonical_number(unpack_size)
    unpack_info.append(0x00)
    streams = bytearray()
    streams.append(0x06)  # kPackInfo
    streams += pack_info
    streams.append(0x07)  # kUnpackInfo
    streams += unpack_info
    streams.append(0x00)
    name_bytes = member_name.encode("utf-16-le") + b"\x00\x00"
    name_prop = bytearray([0]) + name_bytes
    files_info = bytearray()
    files_info += _canonical_number(1)
    files_info.append(0x11)  # kName
    files_info += _canonical_number(len(name_prop))
    files_info += name_prop
    files_info.append(0x00)
    next_header = bytearray()
    next_header.append(0x01)  # kHeader
    next_header.append(0x04)  # kMainStreamsInfo
    next_header += streams
    next_header.append(0x05)  # kFilesInfo
    next_header += files_info
    next_header.append(0x00)
    sig = bytearray()
    sig += magic
    sig += bytes([0x00, 0x04])
    sig += struct.pack("<I", 0)
    sig += struct.pack("<Q", len(pack))
    sig += struct.pack("<Q", len(next_header))
    sig += struct.pack("<I", zlib.crc32(bytes(next_header)) & 0xFFFFFFFF)
    return bytes(sig) + pack + bytes(next_header)


def test_sevenz_extract_refuses_traversal_member(tmp_path):
    from blint.lib.sevenz import extract_sevenz_members

    escaped = tmp_path / "ESCAPED.txt"
    member = "/".join([".."] * 6) + "/" + str(escaped)
    archive = _build_sevenz(member, b"pwned")
    dest = tmp_path / "out"
    dest.mkdir()
    refusals: list[str] = []
    extracted = extract_sevenz_members(archive, str(dest), refusals)
    assert not escaped.exists(), "traversal member escaped the destination directory"
    assert "member_path_unsafe" in refusals
    assert extracted == {}


def test_sevenz_extract_allows_safe_member(tmp_path):
    from blint.lib.sevenz import extract_sevenz_members

    archive = _build_sevenz("inner/payload.bin", b"hello-world")
    dest = tmp_path / "out"
    dest.mkdir()
    refusals: list[str] = []
    extracted = extract_sevenz_members(archive, str(dest), refusals)
    assert "member_path_unsafe" not in refusals
    assert (dest / "inner" / "payload.bin").read_bytes() == b"hello-world"
    assert extracted == {"inner/payload.bin": str(dest / "inner" / "payload.bin")}


def test_sevenz_parse_flags_unsafe_member():
    from blint.lib.sevenz import parse_sevenz_blob

    archive = _build_sevenz("../../../../etc/evil", b"x")
    refusals: list[str] = []
    block = parse_sevenz_blob(archive, refusals, [])
    assert block is not None
    assert "member_path_unsafe" in refusals


# ---------------------------------------------------------------------------
# F2 — bounded zip extraction (decompression bomb + traversal)
# ---------------------------------------------------------------------------

_BOMB_LIMITS = ContainerLimits(
    max_members=1024,
    max_total_uncompressed=256 * 1024 * 1024,
    max_member_size=64 * 1024 * 1024,
    max_member_depth=32,
    max_member_compression_ratio=100,
)


def _zip(path, members):
    import zipfile

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for name, data in members:
            z.writestr(name, data)


def test_extract_zip_refuses_compression_bomb(tmp_path):
    bomb = tmp_path / "bomb.zip"
    _zip(bomb, [(f"m{i}.bin", b"\0" * (4 * 1024 * 1024)) for i in range(8)])
    dest = tmp_path / "out"
    dest.mkdir()
    refusals: list[str] = []
    extracted = extract_zip_to_dir(str(bomb), str(dest), _BOMB_LIMITS, refusals)
    assert "member_compression_ratio_exceeds_cap" in refusals
    assert extracted == {}
    # Nothing high-amplification landed on disk.
    total = sum(f.stat().st_size for f in dest.rglob("*") if f.is_file())
    assert total == 0


def test_extract_zip_refuses_archive_unreadable(tmp_path):
    notzip = tmp_path / "x.zip"
    notzip.write_bytes(b"PK\x03\x04not a real zip")
    dest = tmp_path / "out"
    dest.mkdir()
    refusals: list[str] = []
    extracted = extract_zip_to_dir(str(notzip), str(dest), _BOMB_LIMITS, refusals)
    assert "archive_unreadable" in refusals
    assert extracted == {}


def test_extract_zip_allows_benign(tmp_path):
    ok = tmp_path / "ok.zip"
    _zip(ok, [("classes.dex", b"dex-bytes"), ("lib/x.so", b"so-bytes")])
    dest = tmp_path / "out"
    dest.mkdir()
    refusals: list[str] = []
    extract_zip_to_dir(str(ok), str(dest), _BOMB_LIMITS, refusals)
    assert not refusals
    assert (dest / "classes.dex").read_bytes() == b"dex-bytes"
    assert (dest / "lib" / "x.so").read_bytes() == b"so-bytes"


# ---------------------------------------------------------------------------
# F5 — rich markup injection must not abort the report tables
# ---------------------------------------------------------------------------


def test_findings_table_survives_markup_payload():
    from blint.lib.utils import print_findings_table

    findings = [
        {
            "id": "A[/bold]",
            "exe_name": "x[/red]y.exe",
            "title": "t[link=x]z",
            "severity": "critical",
        }
    ]
    # Two files => the exe_name column renders; a MarkupError here would abort
    # the whole report before findings/reviews/HTML are written.
    print_findings_table(findings, ["f1", "f2"])


def test_reviews_table_survives_markup_payload():
    from blint.lib.analysis import print_reviews_table

    reviews = [{"id": "R", "exe_name": "x[/bold].so", "summary": "s[/x]", "evidence": ["sym[/y]"]}]
    print_reviews_table(reviews, ["f1", "f2"])


# ---------------------------------------------------------------------------
# F7 — blintdb image reference validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ref,expected_host",
    [
        ("ghcr.io/appthreat/blintdb-vcpkg:v2", "ghcr.io"),
        ("ghcr.io/x@sha256:" + "a" * 64, "ghcr.io"),
        ("registry.example.com:5000/x:1", "registry.example.com:5000"),
        ("localhost:5000/x", "localhost:5000"),
    ],
)
def test_blintdb_ref_accepts_valid(ref, expected_host):
    from blint.lib.utils import _validate_blintdb_ref

    assert _validate_blintdb_ref(ref) == expected_host


@pytest.mark.parametrize(
    "ref",
    ["http://evil/x", "evil/../x", "ubuntu", "a b/c", "", "has\tctrl/x"],
)
def test_blintdb_ref_rejects_invalid(ref):
    from blint.lib.utils import _validate_blintdb_ref

    assert _validate_blintdb_ref(ref) is None


# ---------------------------------------------------------------------------
# F9 — untrusted XML parses with entity expansion forbidden
# ---------------------------------------------------------------------------


def test_safe_xml_blocks_entity_bomb():
    from blint.lib.safe_xml import DefusedXmlException, safe_fromstring

    bomb = (
        '<?xml version="1.0"?><!DOCTYPE lolz ['
        '<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;">]>'
        "<lolz>&lol2;</lolz>"
    )
    with pytest.raises(DefusedXmlException):
        safe_fromstring(bomb)


def test_safe_xml_parses_benign():
    from blint.lib.safe_xml import safe_fromstring

    root = safe_fromstring("<a><b>x</b></a>")
    assert root.tag == "a"


# ---------------------------------------------------------------------------
# NEW — binary_common cargo-auditable zlib bomb is capped
# ---------------------------------------------------------------------------


def test_audit_decompress_capped():
    from blint.lib.binary_common import MAX_AUDIT_DECOMPRESSED, _decompress_capped

    bomb = zlib.compress(b"\0" * (MAX_AUDIT_DECOMPRESSED + 8 * 1024 * 1024))
    with pytest.raises(zlib.error):
        _decompress_capped(bomb, MAX_AUDIT_DECOMPRESSED)
    assert _decompress_capped(zlib.compress(b"ok"), MAX_AUDIT_DECOMPRESSED) == b"ok"


# ---------------------------------------------------------------------------
# NEW — CFBundleExecutable path traversal (host-file read) is contained
# ---------------------------------------------------------------------------


def test_ios_bundle_executable_cannot_escape(tmp_path):
    from blint.lib import ios

    # A host file outside the app bundle that a crafted CFBundleExecutable
    # would otherwise point blint at.
    secret = tmp_path / "secret.bin"
    secret.write_bytes(b"\x7fELF" + b"\0" * 64)  # looks like a binary

    payload = tmp_path / "Payload"
    app = payload / "A.app"
    app.mkdir(parents=True)

    bundle_info = {"executable": "../../secret.bin"}
    binaries = ios._collect_bundle_binaries(str(app), bundle_info)
    real_secret = os.path.realpath(secret)
    assert all(os.path.realpath(b["path"]) != real_secret for b in binaries)
