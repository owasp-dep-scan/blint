# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT
"""Overlay classification tests (W0.2, V3).

Ground rule 10: the classifier claims a label vocabulary, so each label gets
its own fixture. Ground rule 22: the magics are pinned against real
artifacts — the certificate-table values against the tier-0 python313.dll
measurements recorded in the verification log, the 7z SFX signature against
the tier-0 installers, and the .NET bundle marker against a real
`dotnet publish -p:PublishSingleFile=true` artifact (see
scripts/windows/build_sfx.ps1).
"""



from blint.lib.pe_overlay import (
    DOTNET_BUNDLE_MARKER,
    UNKNOWN_HIGH_ENTROPY,
    UNKNOWN_LOW_ENTROPY,
    classify_overlay,
    classify_pe_overlay,
    security_directory_range,
)


class _Directory:
    def __init__(self, rva, size):
        self.rva = rva
        self.size = size


class _FakePE:
    """Just the surface security_directory_range and classify_pe_overlay read."""

    def __init__(self, cert=None, section_end=0):
        self._cert = cert
        self._section_end = section_end

    @property
    def data_directories(self):
        # Index 4 is IMAGE_DIRECTORY_ENTRY_SECURITY; earlier indices are
        # filler so the enumerate-based lookup exercises the real path.
        dirs = [_Directory(0, 0)] * 4
        if self._cert:
            dirs.append(_Directory(*self._cert))
        return dirs

    @property
    def sections(self):
        if not self._section_end:
            return []

        class _Section:
            offset = self._section_end - 0x200
            sizeof_raw_data = 0x200

        return [_Section()]


ZIP_LOCAL_HEADER = b"PK\x03\x04" + b"\x00" * 26 + b"hello.txt-Helloworld"

LABEL_PAYLOADS = {
    "zip": ZIP_LOCAL_HEADER,
    "cab": b"MSCF\x00\x00\x00\x00" + b"\x00" * 24,
    "msi": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 56,
    "nsis": b"\x00\x00\x00\x00\xef\xbe\xad\xde" + b"\x00" * 20 + b"NullsoftInst\x00",
    "inno": b"zlb\x1a" + b"\x00" * 60,
    "installshield": b"\x00" * 16 + b"InstallShield Packaging" + b"\x00" * 32,
    "sfx_7z": b"7z\xbc\xaf'\x1c" + b"\x00" * 58,
    "dotnet_single_file_bundle": b"\x00" * 64 + DOTNET_BUNDLE_MARKER + b"\x00" * 8,
    "go_buildinfo": b"\xff Go buildinf:" + b"\x00" * 48,
}


def test_classifier_labels_each_documented_magic():
    """One fixture per A.2 label (ground rule 10); authenticode is not a
    residue label — the certificate table is subtracted before this runs."""
    for label, payload in LABEL_PAYLOADS.items():
        assert classify_overlay(payload) == label, label
    assert "authenticode" not in LABEL_PAYLOADS


def test_classifier_falls_back_to_entropy_verdict():
    # Compressed-looking bytes that match no magic: high entropy.
    high = bytes(range(256)) * 64
    assert classify_overlay(high) == UNKNOWN_HIGH_ENTROPY
    # Repetitive bytes that match no magic: low entropy.
    assert classify_overlay(b"\x00" * 4096) == UNKNOWN_LOW_ENTROPY
    # The empty residue is a case, and it is the ordinary signed binary.
    assert classify_overlay(b"") == UNKNOWN_LOW_ENTROPY


def test_classifier_rejects_archive_magic_buried_in_noise():
    """A zip header in the middle of unknown bytes is not a zip overlay;
    only start-of-residue magics claim the archive labels."""
    payload = b"\xab\xcd\xef\x01" + ZIP_LOCAL_HEADER + b"\x00" * 64
    assert classify_overlay(payload) in (UNKNOWN_LOW_ENTROPY, UNKNOWN_HIGH_ENTROPY)


def test_security_directory_range_reads_directory_four():
    assert security_directory_range(_FakePE(cert=(0x5D2B00, 14168))) == (0x5D2B00, 14168)
    # Absent, zeroed or sizeless directories are no certificate table.
    assert security_directory_range(_FakePE()) is None
    assert security_directory_range(_FakePE(cert=(0, 0))) is None


def test_classify_pe_overlay_subtracts_certificate_table(tmp_path):
    """V3: python313.dll's whole 14168-byte overlay *was* its certificate
    table. The same shape — section end, certificate, nothing after — must
    classify as no overlay at all, with the cert region named in band."""
    section_end = 0x600
    cert = b"CERT" * 128  # 512 bytes of certificate-table stand-in
    data = bytearray(b"\x00" * section_end)
    data += cert
    exe = tmp_path / "signed.exe"
    exe.write_bytes(bytes(data))
    parsed = _FakePE(cert=(section_end, len(cert)), section_end=section_end)

    info = classify_pe_overlay(parsed, str(exe), file_size=section_end + len(cert))
    assert info["security_directory"] == {"offset": section_end, "size": len(cert)}
    assert info["size"] == 0
    assert info["classification"] == UNKNOWN_LOW_ENTROPY


def test_classify_pe_overlay_classifies_residue_behind_the_certificate(tmp_path):
    """An installer that is signed *and* carries an appended payload: the
    certificate table is subtracted and the residue is classified."""
    section_end = 0x600
    cert = b"CERT" * 128
    zip_payload = ZIP_LOCAL_HEADER + b"\x00" * 128
    data = bytearray(b"\x00" * section_end)
    data += cert + zip_payload
    exe = tmp_path / "signed-installer.exe"
    exe.write_bytes(bytes(data))
    parsed = _FakePE(cert=(section_end, len(cert)), section_end=section_end)

    info = classify_pe_overlay(parsed, str(exe), file_size=len(data))
    assert info["security_directory"] == {"offset": section_end, "size": len(cert)}
    assert info["offset"] == section_end + len(cert)
    assert info["size"] == len(zip_payload)
    assert info["classification"] == "zip"


def test_classify_pe_overlay_without_certificate(tmp_path):
    section_end = 0x400
    payload = b"MSCF" + b"\x00" * 252
    data = bytearray(b"\x00" * section_end) + payload
    exe = tmp_path / "cab-sfx.exe"
    exe.write_bytes(bytes(data))
    parsed = _FakePE(section_end=section_end)

    info = classify_pe_overlay(parsed, str(exe), file_size=len(data))
    assert info["security_directory"] is None
    assert info["size"] == len(payload)
    assert info["classification"] == "cab"


def test_classify_pe_overlay_no_overlay_region(tmp_path):
    exe = tmp_path / "flat.exe"
    exe.write_bytes(b"\x00" * 0x400)
    parsed = _FakePE(section_end=0x400)
    assert classify_pe_overlay(parsed, str(exe), file_size=0x400) is None
