r"""Tests for IOCTL depth (PE lane W5.3, plan 04/C).

Unit level: the input-length constraint recovery (x64 and ARM64 shapes),
the SDDL device-ACL scan (ASCII and UTF-16LE via the wide view), the
ARM64 dispatch-store patterns, and the vulnerable-driver snapshot matcher,
fed with synthetic metadata and hand-built section bytes.

Real artifacts: the corpus benign sub-tier (zero snapshot hits - the rule
34 measurement the severity was chosen from, kept as a regression gate),
the clang-built fixture driver for the x64 dispatch path, and - when the
opt-in hostile sample is present - the CVE-2025-7771 driver whose
published control codes must reproduce.
"""

import json
from pathlib import Path

import pytest

from blint.lib.checks import check_known_vulnerable_driver
from blint.lib.driver_ioctl import find_dispatch_handlers
from blint.lib.pe_ioctl_depth import (
    _LENGTH_WINDOW,
    _wide_view,
    annotate_input_length_checks,
    collect_input_length_constraints,
    recover_device_acl,
)
from blint.lib.pe_vulnerable_drivers import match_vulnerable_driver

SLICE_DRIVERS = Path.home() / "sandbox" / "pe-corpus" / "tier5-system" / "drivers"
WINDOWS_DRIVERS = Path(r"C:\Windows\System32\drivers")
HOSTILE_SAMPLE = Path.home() / "sandbox" / "pe-corpus" / "tier6-drivers-hostile" / "ThrottleStop.sys"

X64_LENGTH_CHECK = """
mov rbp, qword ptr [rdx + 184]
cmp dword ptr [rbp + 12], 40
jne 42
"""
X64_NO_LENGTH_CHECK = """
mov rbp, qword ptr [rdx + 184]
mov eax, dword ptr [rbp + 24]
"""
ARM64_LENGTH_CHECK = """
ldr x8, [x19, #184]
ldr w9, [x8, #12]
cmp w9, #40
b.ne #42
"""
ARM64_LENGTH_REG_HELD = """
mov rcx, qword ptr [rbx + 184]
mov edx, dword ptr [rcx + 12]
cmp edx, 92
je 20
"""


def _functions(*bodies):
    return {
        f"sub_{index}": {"name": f"sub_{index}", "assembly": body}
        for index, body in enumerate(bodies)
    }


# ---------------------------------------------------------------------------
# Input-length constraints
# ---------------------------------------------------------------------------


def test_x64_length_compare_recovered():
    constraints = collect_input_length_constraints(_functions(X64_LENGTH_CHECK))
    assert len(constraints) == 1
    entry = next(iter(constraints.values()))
    assert entry["input_length_constants"] == [40]
    assert entry["comparison_kinds"] == ["equality"]


def test_arm64_length_load_and_compare_recovered():
    constraints = collect_input_length_constraints(_functions(ARM64_LENGTH_CHECK))
    entry = next(iter(constraints.values()))
    assert entry["input_length_constants"] == [40]
    assert "equality" in entry["comparison_kinds"]


def test_intel_length_load_into_register_recovered():
    constraints = collect_input_length_constraints(_functions(ARM64_LENGTH_REG_HELD))
    entry = next(iter(constraints.values()))
    assert 92 in entry["input_length_constants"]


def test_stack_location_without_length_access_is_not_a_constraint():
    assert collect_input_length_constraints(_functions(X64_NO_LENGTH_CHECK)) == {}


def test_length_check_annotation_is_function_level():
    constraints = collect_input_length_constraints(_functions(X64_LENGTH_CHECK))
    ioctls = [
        {"code": "0x80002400", "function": "sub_0"},
        {"code": "0x80002954", "function": "sub_1"},  # unknown handler
    ]
    annotate_input_length_checks(ioctls, constraints)
    assert ioctls[0]["input_length_checked"] is True
    assert ioctls[0]["input_length_constants"] == [40]
    assert "input_length_checked" not in ioctls[1]


# ---------------------------------------------------------------------------
# ARM64 dispatch stores
# ---------------------------------------------------------------------------


def test_arm64_dispatch_store_detected_and_null_refused():
    functions = _functions(
        "str x0, [x19, #224]",  # IRP_MJ_DEVICE_CONTROL slot
        "str xzr, [x19, #224]",  # NULL: no handler
        "str x1, [x20, #232]",  # internal device control slot
    )
    handlers = find_dispatch_handlers(functions)
    by_function = {handler["function"]: handler["slot"] for handler in handlers}
    assert by_function["sub_0"] == "IRP_MJ_DEVICE_CONTROL"
    assert "sub_1" not in by_function
    assert by_function["sub_2"] == "IRP_MJ_INTERNAL_DEVICE_CONTROL"


def test_arm64_frame_pointer_base_is_refused():
    handlers = find_dispatch_handlers(_functions("str x0, [x29, #224]"))
    assert handlers == []


# ---------------------------------------------------------------------------
# Device DACL (SDDL)
# ---------------------------------------------------------------------------


class _FakeSection:
    def __init__(self, name, content):
        self.name = name
        self.content = content


class _FakeParsed:
    def __init__(self, sections):
        self.sections = sections


def test_sddl_ascii_restricted_descriptor():
    parsed = _FakeParsed([_FakeSection(".rdata", b"D:P(A;;GA;;;SY)(A;;GA;;;BA)\x00")])
    acl = recover_device_acl(parsed)
    assert acl is not None
    assert acl["sddl_strings"] == ["D:P(A;;GA;;;SY)(A;;GA;;;BA)"]
    assert acl["world_accessible"] is False


def test_sddl_world_grant_is_flagged():
    parsed = _FakeParsed([_FakeSection(".rdata", b"X:D:P(A;;GA;;;SY)(A;;GR;;;WD)Y\x00")])
    acl = recover_device_acl(parsed)
    assert acl is not None
    assert acl["world_accessible"] is True


def test_sddl_utf16le_recovered_via_wide_view():
    blob = "D:P(A;;GA;;;SY)(A;;GA;;;BA)".encode("utf-16-le")
    parsed = _FakeParsed([_FakeSection(".rdata", blob)])
    acl = recover_device_acl(parsed)
    assert acl is not None
    assert acl["sddl_strings"] == ["D:P(A;;GA;;;SY)(A;;GA;;;BA)"]


def test_wide_view_never_matches_corrupted_pairs():
    # The wide view renders non-text pairs as NUL, so the ASCII pattern
    # cannot span them.
    content = b"D\x00P\x00\xAB\xCD(A;;GA;;;SY)"
    view = _wide_view(content)
    from blint.lib.pe_ioctl_depth import SDDL_DEVICE_RE_ASCII

    assert SDDL_DEVICE_RE_ASCII.search(view) is None


def test_no_sddl_strings_is_no_block():
    parsed = _FakeParsed([_FakeSection(".rdata", b"no descriptors here\x00")])
    assert recover_device_acl(parsed) is None


# ---------------------------------------------------------------------------
# The vulnerable-driver snapshot
# ---------------------------------------------------------------------------


def _snapshot():
    data = Path(__file__).resolve().parents[1] / "blint" / "data" / "pe_vulnerable_drivers.json"
    return json.loads(data.read_text())


def test_snapshot_data_integrity():
    """The shipped snapshot is complete, or the rule's recall is a lie.
    Failing this is a data problem, not a code problem."""
    snapshot = _snapshot()
    assert len(snapshot["loldrivers"]["sha256"]) >= 1000
    assert len(snapshot["loldrivers"]["md5"]) >= 1000
    assert len(snapshot["microsoft_blocklist"]["sha256"]) >= 300
    assert snapshot["loldrivers"]["source_url"]
    assert snapshot["loldrivers"]["fetched"]


def test_match_by_sha256_from_snapshot():
    snapshot = _snapshot()
    digest, key = next(iter(snapshot["loldrivers"]["sha256"].items()))
    metadata = {"hashes": {"sha256": digest}}
    block = match_vulnerable_driver(metadata)
    assert block["lookup_status"] == "matched"
    match = block["matches"][0]
    assert match["field"] == "sha256"
    assert match["source"] == "loldrivers"
    assert match["driver"]


def test_no_match_and_no_hash_are_distinct():
    block = match_vulnerable_driver({"hashes": {"sha256": "0" * 64, "md5": "0" * 32}})
    assert block["lookup_status"] == "no_match"
    assert match_vulnerable_driver({})["lookup_status"] == "no_hash"


def test_check_fires_with_named_driver_and_stays_silent_otherwise():
    snapshot = _snapshot()
    digest, key = next(iter(snapshot["loldrivers"]["sha256"].items()))
    name = snapshot["entries"][key]["name"]
    metadata = {
        "vulnerable_driver": match_vulnerable_driver({"hashes": {"sha256": digest}})
    }
    result = check_known_vulnerable_driver("x.sys", metadata, {})
    assert result is not True
    assert name in result
    assert "loldrivers" in result
    # no_match is silent - and it is the only state from which silence
    # reads as "not in the snapshot".
    clean = {"vulnerable_driver": {"lookup_status": "no_match"}}
    assert check_known_vulnerable_driver("x.sys", clean, {}) is True
    assert check_known_vulnerable_driver("x.sys", {}, {}) is True


def test_filename_alone_never_matches():
    """The false-positive guard: a digest blint does not carry never
    matches, no matter what name the file claims - the snapshot has no
    name-keyed path for the matcher to reach."""
    block = match_vulnerable_driver(
        {"hashes": {"sha256": "a" * 64}, "name": "throttlestop.sys"}
    )
    assert block["lookup_status"] == "no_match"
    assert "matches" not in block


# ---------------------------------------------------------------------------
# Real artifacts
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not SLICE_DRIVERS.exists() and not WINDOWS_DRIVERS.exists(),
    reason="no driver corpus on this machine",
)
def test_benign_subtier_never_matches_snapshot():
    """Ground rule 34 / gate P5: zero snapshot hits across the benign
    driver sub-tier."""
    root = SLICE_DRIVERS if SLICE_DRIVERS.exists() else WINDOWS_DRIVERS
    from blint.lib.binary import parse

    checked = 0
    for sample in sorted(root.glob("*.sys"))[:12]:
        metadata = parse(str(sample), {})
        block = metadata.get("vulnerable_driver") or {}
        assert block.get("lookup_status") == "no_match", sample.name
        checked += 1
    assert checked >= 6


@pytest.mark.skipif(not HOSTILE_SAMPLE.exists(), reason="hostile driver sample not fetched")
def test_published_control_codes_reproduce_and_snapshot_matches():
    """The CVE-2025-7771 gate: the recovered IOCTL surface of the real
    ThrottleStop.sys includes the published control codes (0x80006498 read,
    0x8000649C write - SentinelOne's writeup and the PoC), and the snapshot
    matches the file by digest. Read-only, static, never loaded."""
    from blint.lib.binary import parse

    metadata = parse(str(HOSTILE_SAMPLE), disassemble=True)
    if not metadata.get("disassembled_functions"):
        # The IOCTL recovery is disassembly-derived; without nyxstone/LLVM
        # this gate cannot run on this machine.
        pytest.skip("disassembly unavailable (nyxstone/LLVM not installed)")
    ioctls = (metadata.get("driver_ioctls") or {}).get("ioctls") or []
    codes = {entry["code"] for entry in ioctls}
    assert "0x80006498" in codes
    assert "0x8000649C" in codes
    block = metadata.get("vulnerable_driver") or {}
    assert block.get("lookup_status") == "matched"
    sources = {match["source"] for match in block.get("matches") or []}
    assert "loldrivers" in sources


def test_deny_everyone_is_not_world_accessible():
    """A deny ACE naming Everyone locks it out; it must not read as a grant.

    Matching the trustee alone (`;;;WD)`) made the most restricted
    descriptor there is - one that explicitly denies Everyone - report
    world_accessible, inverting the fact that decides whether the recovered
    IOCTL list is unprivileged attack surface.
    """
    sddl = b"D:P(D;;GA;;;WD)(A;;GA;;;SY)(A;;GA;;;BA)\x00"
    block = recover_device_acl(_FakeParsed([_FakeSection(".rdata", sddl)]))
    assert block["sddl_strings"]
    assert block["world_accessible"] is False
    granted = b"D:P(A;;GA;;;WD)(A;;GA;;;SY)\x00"
    assert recover_device_acl(_FakeParsed([_FakeSection(".rdata", granted)]))[
        "world_accessible"
    ] is True


def test_length_access_far_from_the_stack_location_load_is_not_a_length_check():
    """+0x0C is only InputBufferLength near the stack-location load.

    _LENGTH_WINDOW was defined and never applied, so one stack-location
    load licensed every `[reg+0xc]` access to the end of the function -
    and +0x0C is an offset every other structure in a dispatch routine
    uses too.
    """
    far = "\n".join(
        ["mov rbx, qword ptr [rdx + 0xb8]"]
        + ["nop"] * (_LENGTH_WINDOW + 4)
        + ["cmp dword ptr [rbx + 0xc], 0x28", "je 0x1000"]
    )
    assert collect_input_length_constraints({"f": {"name": "f", "assembly": far}}) == {}
    near = "mov rbx, qword ptr [rdx + 0xb8]\ncmp dword ptr [rbx + 0xc], 0x28\nje 0x1000"
    assert collect_input_length_constraints({"g": {"name": "g", "assembly": near}}) == {
        "g": {"input_length_constants": [0x28], "comparison_kinds": ["equality"]}
    }
