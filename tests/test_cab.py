"""Tests for the cabinet (MSCF) reader (W4.2).

Hand-built stored- and MSZIP-folder cabinets exercise the happy paths and
the hostile ones (truncation, unsupported method, unsafe member names,
oversized members) — every refusal named (ground rule 30), every cap
exceeded by a fixture (ground rule 33).
"""

import os
import struct
import tempfile
import zlib

from blint.lib.cab import extract_cab_members, parse_cab

CAB_MAGIC = b"MSCF"


def build_cab(files: dict[str, bytes], *, method: int = 0, truncate: int | None = None) -> bytes:
    """One folder; stored (0) or mszip (1); every file in that folder."""
    # CFDATA blocks cap at 32 KB uncompressed each; the folder payload is
    # the concatenation of every file's bytes (stored) or per-chunk MSZIP
    # streams, and each chunk becomes one CFDATA block.
    payload = b"".join(files.values())
    offsets = {}
    position = 0
    for name, content in files.items():
        offsets[name] = position
        position += len(content)
    folder_payload_chunks = [
        payload[i : i + 32768] for i in range(0, len(payload), 32768)
    ] or [b""]
    folder_data = b""
    for chunk in folder_payload_chunks:
        if method == 1:
            compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
            comp = b"CK" + compressor.compress(chunk) + compressor.flush()
            folder_data += struct.pack("<IHH", 0, len(comp), len(chunk)) + comp
        else:
            folder_data += struct.pack("<IHH", 0, len(chunk), len(chunk)) + chunk
    num_blocks = len(folder_payload_chunks)
    num_files = len(files)
    cffile_size = sum(16 + len(n.encode()) + 1 for n in files)
    header_size = 36 + 8
    coff_files = header_size
    cb_cabinet = coff_files + cffile_size + len(folder_data)
    header = CAB_MAGIC
    header += struct.pack("<III", 0, cb_cabinet, 0)  # reserved1, size, reserved2
    header += struct.pack("<I", coff_files)
    header += struct.pack("<I", 0)  # reserved3
    header += struct.pack("<BB", 3, 1)  # version 1.3
    header += struct.pack("<HHHHH", 1, num_files, 0, 0x1234, 0)
    assert len(header) == 36
    folders = struct.pack("<IHH", header_size + cffile_size, num_blocks, method)
    entries = b""
    for name, payload in files.items():
        encoded = name.encode()
        entries += struct.pack("<IIHHHH", len(payload), offsets[name], 0, 0, 0, 0)
        entries += encoded + b"\x00"
    image = bytearray(header + folders + entries + folder_data)
    if truncate is not None:
        image = image[:truncate]
    return bytes(image)


def test_parse_lists_stored_members(tmp_path):
    path = tmp_path / "stored.cab"
    path.write_bytes(build_cab({"a.dll": b"A" * 300, "sub/b.sys": b"B" * 70000}))
    block = parse_cab(str(path))
    assert block["parse_status"] == "parsed"
    assert block["member_count"] == 2
    assert block["methods"] == ["none"]
    names = {m["name"] for m in block["members"]}
    assert names == {"a.dll", "sub/b.sys"}
    assert block["total_uncompressed"] == 70300


def test_extract_stored_members_round_trip():
    dest = tempfile.mkdtemp(prefix="blint_cab_test_")
    try:
        path = os.path.join(dest, "s.cab")
        with open(path, "wb") as handle:
            handle.write(build_cab({"a.dll": b"A" * 300}))
        refusals: list[str] = []
        extracted = extract_cab_members(path, dest, refusals)
        assert refusals == []
        assert extracted["a.dll"].endswith("a.dll")
        with open(extracted["a.dll"], "rb") as handle:
            assert handle.read() == b"A" * 300
    finally:
        import shutil

        shutil.rmtree(dest, ignore_errors=True)


def test_mszip_folder_extracts_through_stdlib(tmp_path):
    path = tmp_path / "zip.cab"
    path.write_bytes(build_cab({"z.dll": b"Z" * 4096}, method=1))
    block = parse_cab(str(path))
    assert block["methods"] == ["mszip"]
    dest = tempfile.mkdtemp(prefix="blint_cab_test_")
    try:
        refusals: list[str] = []
        extracted = extract_cab_members(str(path), dest, refusals)
        assert extracted.get("z.dll"), refusals
        with open(extracted["z.dll"], "rb") as handle:
            assert handle.read() == b"Z" * 4096
    finally:
        import shutil

        shutil.rmtree(dest, ignore_errors=True)


def test_lzx_folder_refuses_extraction_by_name(tmp_path):
    path = tmp_path / "lzx.cab"
    path.write_bytes(build_cab({"l.dll": b"L" * 100}, method=3))
    dest = tempfile.mkdtemp(prefix="blint_cab_test_")
    try:
        refusals: list[str] = []
        extracted = extract_cab_members(str(path), dest, refusals)
        assert extracted == {}
        assert "member_compression_unsupported" in refusals
        # ...while the listing still works (a refusal is not emptiness).
        block = parse_cab(str(path))
        assert block["member_count"] == 1
    finally:
        import shutil

        shutil.rmtree(dest, ignore_errors=True)


def test_truncated_cab_refuses_by_name(tmp_path):
    path = tmp_path / "cut.cab"
    path.write_bytes(build_cab({"a.dll": b"A" * 300}, truncate=20))
    block = parse_cab(str(path))
    assert block["parse_status"] in ("partial", "failed")
    # Header-level truncation reads as unreadable; body-level as truncated.
    assert "archive_truncated" in block["refusals"] or "archive_unreadable" in block["refusals"]


def test_unsafe_member_name_refused_on_extract(tmp_path):
    path = tmp_path / "evil.cab"
    path.write_bytes(build_cab({r"..\\evil.dll".replace("\\\\", "\\x5c\\x5c"): b"E" * 10}))
    dest = tempfile.mkdtemp(prefix="blint_cab_test_")
    try:
        refusals: list[str] = []
        extracted = extract_cab_members(str(path), dest, refusals)
        assert extracted == {}
        assert "member_path_unsafe" in refusals
        assert not os.path.exists(os.path.join(dest, "evil.dll"))
    finally:
        import shutil

        shutil.rmtree(dest, ignore_errors=True)


def test_not_a_cab_fails_cleanly(tmp_path):
    path = tmp_path / "nope.cab"
    path.write_bytes(b"PK\x03\x04" + b"\x00" * 40)
    block = parse_cab(str(path))
    assert block["parse_status"] == "failed"
    assert "not_a_cab" in block["refusals"]


def test_member_count_cap_refused(tmp_path):
    files = {f"f{i}.dll": b"x" for i in range(5)}
    path = tmp_path / "many.cab"
    path.write_bytes(build_cab(files))
    # Shrink the cap by monkeypatching the module constant: the cap must
    # refuse, whatever its value (the hostile fixture exceeds it).
    from blint.lib import cab as cab_module

    original = cab_module.MAX_CAB_MEMBERS
    cab_module.MAX_CAB_MEMBERS = 2
    try:
        block = parse_cab(str(path))
        assert "member_count_exceeds_cap" in block["refusals"]
        assert len(block["members"]) == 2
    finally:
        cab_module.MAX_CAB_MEMBERS = original


def test_runner_cab_route_units_and_leak_delta(tmp_path):
    """The runner routes a .cab as a container unit; PE members analyze as
    cab-member units attributed to their member path; no temp dir leaks
    (ground rule 18 asserted across the whole run)."""
    import glob
    import json
    import logging

    logging.disable(logging.CRITICAL)
    from blint.config import BlintOptions
    from blint.lib.runners import run_default_mode

    data_dir = os.path.join(os.path.dirname(__file__), "data")
    pe_member = os.path.join(data_dir, "pe", "msvc-hello-x64.exe")
    with open(pe_member, "rb") as handle:
        pe_bytes = handle.read()
    cab_path = tmp_path / "payload.cab"
    cab_path.write_bytes(build_cab({"inner/hello.exe": pe_bytes}))
    before = set(glob.glob(os.path.join(tempfile.gettempdir(), "blint_cab_*")))
    reports = os.path.join(str(tmp_path), "reports")
    options = BlintOptions(
        src_dir_image=[str(cab_path)],
        reports_dir=reports,
        no_reviews=True,
        quiet_mode=True,
    )
    run_default_mode(options)
    after = set(glob.glob(os.path.join(tempfile.gettempdir(), "blint_cab_*")))
    assert after - before == set()
    with open(os.path.join(reports, "analysis-coverage.json")) as handle:
        coverage = json.load(handle)
    assert coverage["units_by_role"]["top-level"] == {
        "attempted": 1,
        "succeeded": 1,
        "failed": 0,
        "skipped": 0,
    }
    assert coverage["units_by_role"]["cab-member"] == {
        "attempted": 1,
        "succeeded": 1,
        "failed": 0,
        "skipped": 0,
    }
    with open(os.path.join(reports, "hello.exe-metadata.json")) as handle:
        member_metadata = json.load(handle)
    assert member_metadata["container"]["member_path"] == "inner/hello.exe"
    with open(os.path.join(reports, "payload.cab-metadata.json")) as handle:
        cab_metadata = json.load(handle)
    assert cab_metadata["cab"]["extracted_member_count"] == 1


def test_runner_msi_route_metadata_export(tmp_path):
    """A routed .msi exports msi facts with exe_type msi (unit-level)."""
    import json
    import logging

    logging.disable(logging.CRITICAL)
    from blint.config import BlintOptions
    from blint.lib.runners import run_default_mode
    from tests.test_msi import build_msi, build_table

    strings = [
        "",
        "Property", "Value", "Name", "Table", "Number", "Type",
        "ProductName", "Cab Installer", "ProductVersion", "2.0",
        "ProductCode", "{CAB-GUID}", "_Tables", "_Columns",
    ]

    def sid(name):
        return strings.index(name)

    schemas = {
        "Property": [("Property", 0x2940, 2), ("Value", 0x2940, 2)],
        "_Tables": [("Name", 0x2940, 2)],
        "_Columns": [
            ("Table", 0x2940, 2),
            ("Number", 0x0102, 2),
            ("Name", 0x2940, 2),
            ("Type", 0x0102, 2),
        ],
    }
    tables = {
        "Property": build_table(
            [
                [sid("ProductName"), sid("Cab Installer")],
                [sid("ProductVersion"), sid("2.0")],
                [sid("ProductCode"), sid("{CAB-GUID}")],
            ],
            schemas["Property"],
        )
    }
    image = build_msi(strings, tables, schemas)
    msi_path = tmp_path / "installer.msi"
    msi_path.write_bytes(image)
    reports = os.path.join(str(tmp_path), "reports")
    options = BlintOptions(
        src_dir_image=[str(msi_path)],
        reports_dir=reports,
        no_reviews=True,
        quiet_mode=True,
    )
    run_default_mode(options)
    with open(os.path.join(reports, "installer.msi-metadata.json")) as handle:
        metadata = json.load(handle)
    assert metadata["exe_type"] == "msi"
    assert metadata["msi"]["identity"]["product_name"] == "Cab Installer"
    assert metadata["msi"]["identity"]["product_code"] == "{CAB-GUID}"
