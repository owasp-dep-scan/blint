r"""Tests for the .NET publish shape (PE lane W3.3, plan 03/A.3).

The properties under test are structural, so most fixtures are built here
rather than committed: a bundle manifest is a byte layout, and a synthetic
one can be made to exceed a cap or stop mid-entry in a way no real publish
does.

The real artifacts are the six publish shapes built with the .NET 11 SDK on
the Windows ARM64 VM (``dotnet publish`` with the framework-dependent,
self-contained, single-file, ReadyToRun, trimmed and NativeAOT options).
Those tests are the ground truth for this packet - the publish command is
the oracle, blint's answer is what is being checked - and they skip where
the tree is absent.
"""

import os
import struct

import pytest

from blint.lib.pe_dotnet_shape import (
    BUNDLE_SIGNATURE,
    MAX_LISTED_BUNDLE_MEMBERS,
    classify_dotnet_shape,
    read_bundle_manifest,
)

SHAPES_ROOT = os.environ.get("BLINT_DOTNET_SHAPES", r"C:\Users\appthreat\shapes")


def _shape_path(publish, name):
    return os.path.join(SHAPES_ROOT, f"out-{publish}", name)


def _have(publish, name):
    return os.path.exists(_shape_path(publish, name))


needs_shapes = pytest.mark.skipif(
    not _have("nativeaot", "ShapeProbe.exe"),
    reason="the .NET publish shape tree is not present (built on the VM)",
)


# ---------------------------------------------------------------------------
# The bundle manifest, as a byte layout
# ---------------------------------------------------------------------------


def _7bit(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _string(text: str) -> bytes:
    raw = text.encode("utf-8")
    return _7bit(len(raw)) + raw


def _manifest(members, major=6, minor=0, bundle_id="TESTBUNDLE", declared=None):
    """A bundle manifest exactly as Microsoft.NET.HostModel writes one."""
    body = struct.pack(
        "<IIi", major, minor, len(members) if declared is None else declared
    )
    body += _string(bundle_id)
    if major >= 2:
        body += struct.pack("<qqqqQ", 0, 0, 0, 0, 0)
    for path, offset, size, file_type in members:
        body += struct.pack("<qq", offset, size)
        if major >= 6:
            body += struct.pack("<q", 0)
        body += bytes([file_type])
        body += _string(path)
    return body


def test_manifest_round_trip():
    members = [
        ("App.dll", 4096, 1024, 1),
        ("App.runtimeconfig.json", 8192, 300, 4),
        ("native.dll", 16384, 2048, 2),
    ]
    data = b"\x00" * 64 + _manifest(members)
    parsed = read_bundle_manifest(data, 64)
    assert parsed["version"] == "6.0"
    assert parsed["bundle_id"] == "TESTBUNDLE"
    assert parsed["member_count"] == 3
    assert [m["path"] for m in parsed["members"]] == [m[0] for m in members]
    assert [m["type"] for m in parsed["members"]] == [
        "assembly",
        "runtime_config_json",
        "native_binary",
    ]


def test_member_listing_cap_is_exceeded_by_the_fixture():
    """Rule 33: the cap has a fixture that goes past it, and the entries
    beyond it are declared rather than dropped in silence.

    No rule reads this list - it is metadata for a reader and for the SBOM -
    so the cap bounds metadata size and not detection. That distinction is
    the W3.2 lesson and it is why the number may be round.
    """
    over = MAX_LISTED_BUNDLE_MEMBERS + 50
    members = [(f"Member{i}.dll", 4096 * (i + 1), 16, 1) for i in range(over)]
    data = b"\x00" * 64 + _manifest(members)
    parsed = read_bundle_manifest(data, 64)
    assert parsed["member_count"] == over
    assert len(parsed["members"]) == MAX_LISTED_BUNDLE_MEMBERS
    assert parsed["members_listing_capped"] is True
    assert "members_truncated" not in parsed


def test_manifest_cut_mid_entry_is_named_not_silent():
    """A manifest that stops inside an entry is a truncated file, which is
    a different fact from blint's own listing bound (ground rule 14)."""
    members = [(f"Member{i}.dll", 4096, 16, 1) for i in range(20)]
    data = b"\x00" * 64 + _manifest(members)
    parsed = read_bundle_manifest(data[: len(data) - 60], 64)
    assert parsed["members_truncated"] is True
    assert "members_listing_capped" not in parsed
    assert 0 < len(parsed["members"]) < 20


def test_absurd_declared_count_is_refused():
    """The count comes out of the file, so it is bounded before it is
    trusted (ground rule 30)."""
    data = b"\x00" * 64 + _manifest([], declared=10_000_000)
    assert read_bundle_manifest(data, 64) is None


def test_offset_outside_the_buffer_is_refused():
    assert read_bundle_manifest(b"\x00" * 32, 4096) is None
    assert read_bundle_manifest(b"\x00" * 32, -1) is None
    # Offset 0 is the DOS header of the image itself, never a manifest.
    assert read_bundle_manifest(b"\x00" * 64 + _manifest([]), 0) is None


def test_bundle_signature_matches_the_overlay_classifier():
    """One constant, two readers. The overlay classifier labels a residue
    and this module decodes the manifest; they must agree on what they are
    looking for (ground rule 21)."""
    from blint.lib.pe_overlay import DOTNET_BUNDLE_MARKER

    assert BUNDLE_SIGNATURE == DOTNET_BUNDLE_MARKER


# ---------------------------------------------------------------------------
# The managed branch: order of the tests is the finding
# ---------------------------------------------------------------------------


class _FakeSection:
    def __init__(self, name, vaddr, size, offset, characteristics=0x40000040):
        self.name = name
        self.virtual_address = vaddr
        self.virtual_size = size
        self.sizeof_raw_data = size
        self.offset = offset
        self.characteristics = characteristics


class _FakeBinary:
    def __init__(self, sections):
        self.sections = sections


def _write(tmp_path, name, payload):
    path = tmp_path / name
    path.write_bytes(payload)
    return str(path)


def test_ready_to_run_is_decided_before_the_ilonly_flag(tmp_path):
    """The measured R2R assembly has cli_flags_value 0x4 - ILONLY clear.

    A mixed-mode test that ran before the ReadyToRun one would therefore
    label every ordinary ReadyToRun build as C++/CLI. The order is the
    behaviour, so it is pinned here.
    """
    payload = bytearray(b"\x00" * 0x400)
    payload[0x200:0x204] = b"RTR\x00"
    path = _write(tmp_path, "r2r.dll", bytes(payload))
    obj = _FakeBinary([_FakeSection(".text", 0x1000, 0x200, 0x200)])
    dotnet = {
        "cli_flags_value": 0x4,
        "managed_native_header_rva": 0x1000,
        "managed_native_header_size": 148,
    }
    shape = classify_dotnet_shape(obj, path, {}, dotnet)
    assert shape["kind"] == "ready_to_run"
    assert "managed_native_header_readytorun" in shape["evidence"]


def test_mixed_mode_only_without_a_native_header(tmp_path):
    path = _write(tmp_path, "mixed.dll", b"\x00" * 0x400)
    obj = _FakeBinary([_FakeSection(".text", 0x1000, 0x200, 0x200)])
    shape = classify_dotnet_shape(
        obj,
        path,
        {},
        {"cli_flags_value": 0x0, "managed_native_header_rva": 0},
    )
    assert shape["kind"] == "mixed_mode"


def test_il_only_when_the_flag_is_set(tmp_path):
    path = _write(tmp_path, "il.dll", b"\x00" * 0x400)
    obj = _FakeBinary([_FakeSection(".text", 0x1000, 0x200, 0x200)])
    shape = classify_dotnet_shape(
        obj,
        path,
        {},
        {"cli_flags_value": 0x1, "managed_native_header_rva": 0},
    )
    assert shape["kind"] == "il_only"


def test_native_header_blint_cannot_identify_is_named(tmp_path):
    """Rule 14: a header that is present but not a ReadyToRun one is
    reported as unrecognised, not folded into il_only, which would claim
    there is no native code when blint does not know that."""
    path = _write(tmp_path, "odd.dll", b"\x00" * 0x400)
    obj = _FakeBinary([_FakeSection(".text", 0x1000, 0x200, 0x200)])
    shape = classify_dotnet_shape(
        obj,
        path,
        {"exports": []},
        {"cli_flags_value": 0x1, "managed_native_header_rva": 0x1000,
         "managed_native_header_size": 16},
    )
    assert shape["kind"] == "native_image_unknown"


# ---------------------------------------------------------------------------
# The native branch
# ---------------------------------------------------------------------------


def test_unwritten_placeholder_is_an_apphost_not_a_bundle(tmp_path):
    """Every .NET apphost carries the bundle signature whether it was
    bundled or not - the host template embeds it so the bundler knows
    where to write the header offset. Measured: the framework-dependent,
    self-contained and trimmed apphosts all carry it at offset 71,856 with
    the preceding int64 still zero. Keying on the signature alone would
    call every one of them a single-file bundle.
    """
    payload = b"\x00" * 64 + struct.pack("<q", 0) + BUNDLE_SIGNATURE + b"\x00" * 64
    path = _write(tmp_path, "apphost.exe", payload)
    shape = classify_dotnet_shape(_FakeBinary([]), path, {}, None)
    assert shape["kind"] == "apphost"


def test_written_offset_makes_it_a_bundle(tmp_path):
    members = [("App.dll", 128, 16, 1)]
    manifest = _manifest(members)
    prefix = b"\x00" * 64 + struct.pack("<q", 0) + BUNDLE_SIGNATURE
    header_offset = len(prefix)
    payload = bytearray(prefix + manifest)
    payload[64 : 64 + 8] = struct.pack("<q", header_offset)
    path = _write(tmp_path, "bundle.exe", bytes(payload))
    shape = classify_dotnet_shape(_FakeBinary([]), path, {}, None)
    assert shape["kind"] == "single_file_bundle"
    assert shape["bundle"]["members"][0]["path"] == "App.dll"


def test_bundle_offset_that_decodes_to_nothing_still_says_bundle(tmp_path):
    """Rule 14 again: a written offset whose manifest blint cannot read is
    a bundle it could not decode, not an apphost with no payload."""
    prefix = b"\x00" * 64 + struct.pack("<q", 0) + BUNDLE_SIGNATURE
    payload = bytearray(prefix + b"\xff" * 64)
    payload[64 : 64 + 8] = struct.pack("<q", len(prefix))
    path = _write(tmp_path, "brokenbundle.exe", bytes(payload))
    shape = classify_dotnet_shape(_FakeBinary([]), path, {}, None)
    assert shape["kind"] == "single_file_bundle"
    assert "bundle_header_unreadable" in shape["evidence"]
    assert "bundle" not in shape


def _aot_image(tmp_path, name, *, with_rtr=True, section_flags=0x40000040):
    payload = bytearray(b"\x00" * 0x800)
    if with_rtr:
        payload[0x400:0x404] = b"RTR\x00"
        payload[0x404:0x406] = struct.pack("<H", 26)
    return _write(tmp_path, name, bytes(payload)), _FakeBinary(
        [_FakeSection(".rdata", 0x2000, 0x400, 0x400, section_flags)]
    )


def test_native_aot_requires_both_conditions(tmp_path):
    """coreclr.dll exports DotNetRuntimeContractDescriptor too, and it is
    an ordinary native runtime DLL - so the export alone cannot be the
    test. Measured: coreclr.dll has no ReadyToRun header at all, and the
    NativeAOT image has both."""
    exports = {"exports": [{"name": "DotNetRuntimeContractDescriptor"}]}

    path, obj = _aot_image(tmp_path, "aot.exe")
    assert classify_dotnet_shape(obj, path, exports, None)["kind"] == "native_aot"

    # The export without the header: coreclr.dll's shape.
    path, obj = _aot_image(tmp_path, "runtime.dll", with_rtr=False)
    assert classify_dotnet_shape(obj, path, exports, None) is None

    # The header without the export.
    path, obj = _aot_image(tmp_path, "nameless.exe")
    assert classify_dotnet_shape(obj, path, {"exports": []}, None) is None


def test_rtr_bytes_in_executable_code_are_not_a_header(tmp_path):
    """The measured NativeAOT image contains the four signature bytes
    inside .text as instruction encoding. Restricting the search to
    initialized non-executable data is what keeps that from counting."""
    exports = {"exports": [{"name": "DotNetRuntimeContractDescriptor"}]}
    path, _obj = _aot_image(tmp_path, "codehit.exe")
    executable = _FakeBinary(
        [_FakeSection(".text", 0x2000, 0x400, 0x400, 0x60000020)]
    )
    assert classify_dotnet_shape(executable, path, exports, None) is None


def test_a_plain_native_pe_says_nothing(tmp_path):
    path = _write(tmp_path, "native.dll", b"MZ" + b"\x00" * 0x400)
    assert classify_dotnet_shape(_FakeBinary([]), path, {"exports": []}, None) is None


# ---------------------------------------------------------------------------
# Real artifacts (ground rule 29): the publish command is the oracle
# ---------------------------------------------------------------------------


@needs_shapes
@pytest.mark.parametrize(
    ("publish", "name", "expected"),
    [
        ("framework-dependent", "ShapeProbe.dll", "il_only"),
        ("framework-dependent", "ShapeProbe.exe", "apphost"),
        ("self-contained", "ShapeProbe.dll", "il_only"),
        ("self-contained", "ShapeProbe.exe", "apphost"),
        ("readytorun", "ShapeProbe.dll", "ready_to_run"),
        ("trimmed", "ShapeProbe.dll", "il_only"),
        ("trimmed", "ShapeProbe.exe", "apphost"),
        ("single-file", "ShapeProbe.exe", "single_file_bundle"),
        ("nativeaot", "ShapeProbe.exe", "native_aot"),
    ],
)
def test_every_publish_shape_classifies(publish, name, expected):
    from blint.lib.binary import parse

    path = _shape_path(publish, name)
    if not os.path.exists(path):
        pytest.skip(f"{publish}/{name} not built")
    metadata = parse(path)
    shape = (metadata.get("dotnet") or {}).get("shape")
    assert shape, f"{publish}/{name} produced no shape block"
    assert shape["kind"] == expected


@needs_shapes
def test_the_bundle_members_are_the_self_contained_publish():
    """Ground truth for the member list: the assemblies the bundler embedded
    must be the assemblies the equivalent non-bundled self-contained publish
    wrote to disk, at the same sizes.

    The comparison is restricted to the carried files - assemblies and
    native binaries - because the *generated* ones legitimately differ.
    Measured: ShapeProbe.deps.json is 29,177 bytes beside the
    self-contained publish and 27,856 inside the bundle, because the
    single-file publish rewrites it for the bundled layout. Asserting over
    those too would be asserting that two different files are the same
    file.
    """
    from blint.lib.binary import parse

    sf = _shape_path("single-file", "ShapeProbe.exe")
    sc_dir = os.path.join(SHAPES_ROOT, "out-self-contained")
    if not (os.path.exists(sf) and os.path.isdir(sc_dir)):
        pytest.skip("both publishes are needed")
    shape = (parse(sf).get("dotnet") or {}).get("shape")
    members = {m["path"]: m for m in shape["bundle"]["members"]}
    assert len(members) == shape["bundle"]["member_count"]
    carried = {"assembly", "native_binary"}
    matched = generated = 0
    for name, member in members.items():
        disk = os.path.join(sc_dir, name)
        if not os.path.exists(disk):
            continue
        if member["type"] not in carried:
            generated += 1
            continue
        assert os.path.getsize(disk) == member["size"], name
        matched += 1
    assert matched >= 100, f"only {matched} carried members matched the publish"
    # The generated files are present in both and are expected to differ;
    # the count is asserted so their exclusion stays a stated fact rather
    # than a silent hole in the comparison.
    assert generated >= 1


@needs_shapes
def test_the_runtime_host_is_not_called_a_plugin_of_itself():
    """coreclr.dll is the hard negative: a native runtime DLL full of the
    same .NET strings and exporting the same runtime descriptor as a
    NativeAOT image. It must produce no shape at all."""
    from blint.lib.binary import parse

    path = os.path.join(SHAPES_ROOT, "out-self-contained", "coreclr.dll")
    if not os.path.exists(path):
        pytest.skip("coreclr.dll not present")
    assert "dotnet" not in parse(path)
