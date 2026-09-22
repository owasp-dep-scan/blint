"""IOCTL depth (PE lane W5.3, plan 04/C).

Two facts turn the recovered control-code list into a severity:

- **Per-IOCTL input-length validation.** A dispatch routine that never
  compares ``Parameters.DeviceIoControl.InputBufferLength`` against a
  constant accepts any buffer size - the unchecked-length shape behind a
  large share of driver pool-overflow CVEs. The recovery finds the IRP
  stack-location load (``[reg+0xB8]`` on x64/ARM64, ``+0x60`` on x86)
  followed within a few instructions by an access of the length field at
  ``+0x0C`` - both offsets validated against real drivers' disassembly
  before the patterns were written (acpi.sys carries 24 such sites,
  ataport.sys 32). The verdict is function-level: an IOCTL whose handler
  function contains at least one length comparison is marked
  ``input_length_checked``, which is a correlation across the function,
  not a proof the check guards that specific code - the confidence
  statement is part of the block.

- **The device DACL.** A device object reachable by ``Everyone`` makes
  every recovered IOCTL unprivileged attack surface; without the DACL the
  list has no severity. ``IoCreateDeviceSecure`` receives its security
  descriptor as an SDDL string literal, which lives in ``.rdata`` - the
  scan reads the section bytes in both encodings (ASCII and UTF-16LE, the
  forms the compiler emits) and decodes the grant ACEs. The common
  restricted shape ``D:P(A;;GA;;;SY)(A;;GA;;;BA)`` (system and
  administrators only) passes silently; a grant to ``WD`` (Everyone),
  ``AN`` (Anonymous) or ``BU`` (Builtin Users) is named. The block is
  absent when no SDDL string exists - "no descriptor found" is stated by
  the W5.1 device-creation facts (``IoCreateDevice`` vs
  ``IoCreateDeviceSecure``), not by an empty block here (rules 14/32).
"""

from __future__ import annotations

import re
from typing import Any

import lief

from blint.lib.binary_common import is_string_bearing_section
from blint.lib.driver_ioctl import _parse_immediate

# IRP -> Tail.Overlay.CurrentStackLocation offsets. The x64/ARM64 (8-byte
# pointer) layout and the x86 one. Probed against real drivers before use:
# see the module docstring.
STACK_LOCATION_OFFSETS: dict[str, str] = {
    "64": "0xb8",
    "32": "0x60",
}
# IO_STACK_LOCATION.Parameters.DeviceIoControl.InputBufferLength, the same
# field offset on both widths (two ULONGs before it).
INPUT_BUFFER_LENGTH_OFFSET_64 = 0x0C
INPUT_BUFFER_LENGTH_OFFSET_32 = 0x0C

# The stack-location load, Intel syntax, both widths.
_INTEL_STACK_LOCATION_RE = re.compile(
    r"^\s*mov\s+(?P<dst>[a-z][a-z0-9]*)\s*,\s*"
    r"(?:qword\s+ptr\s+|dword\s+ptr\s+)?\[\s*(?P<src>[a-z][a-z0-9]*)\s*\+\s*"
    r"(?P<off>0x[0-9a-f]+|[0-9]+)\s*\]"
)
# The ARM64 form (decimal immediates, the # prefix).
_ARM64_STACK_LOCATION_RE = re.compile(
    r"^\s*ldr\s+(?P<dst>x[0-9]+)\s*,\s*\[\s*(?P<src>x[0-9]+)\s*,\s*#(?P<off>[0-9]+)\s*\]"
)
# The length access: a direct memory compare (Intel) or a load feeding a
# register compare (ARM64 renders `ldr w8, [x19, #12]` then `cmp w8, #0x28`).
_INTEL_LENGTH_CMP_RE = re.compile(
    r"^\s*cmp\s+(?:dword\s+ptr\s+)?\[\s*(?P<base>[a-z][a-z0-9]*)\s*\+\s*"
    r"(?P<off>0x[0-9a-f]+|[0-9]+)\s*\]\s*,\s*(?P<imm>[^,\s]+)"
)
_INTEL_LENGTH_LOAD_RE = re.compile(
    r"^\s*mov\s+(?P<dst>[a-z][a-z0-9]*)\s*,\s*(?:dword\s+ptr\s+)?\[\s*"
    r"(?P<base>[a-z][a-z0-9]*)\s*\+\s*(?P<off>0x[0-9a-f]+|[0-9]+)\s*\]"
)
_ARM64_LENGTH_LOAD_RE = re.compile(
    r"^\s*ldr\s+(?P<dst>w[0-9]+)\s*,\s*\[\s*(?P<base>x[0-9]+)\s*,\s*#(?P<off>[0-9]+)\s*\]"
)
_ARM64_REG_CMP_RE = re.compile(
    r"^\s*cmp\s+(?P<reg>w[0-9]+)\s*,\s*#?(?P<imm>[0-9a-fx]+)"
)
_EQUALITY_BRANCH_RE = re.compile(r"^\s*(?:je|jz|jne|jnz|b\.eq|b\.ne)\b")
_RANGE_BRANCH_RE = re.compile(
    r"^\s*(?:ja|jae|jb|jbe|jna|jnae|jnb|jnbe|jg|jge|jl|jle|b\.hs|b\.hi|b\.lo|b\.ls)\b"
)
# How far past the stack-location load the length access may sit. This is
# the whole basis for reading a `[reg+0xc]` access as InputBufferLength:
# +0x0C is an ordinary offset that every other structure in the function
# also uses, and without the window a single stack-location load licensed
# every such access to the end of the function.
_LENGTH_WINDOW = 12

# Listing bound on the constraints reported per driver. A listing bound
# only: the per-IOCTL annotation reads the per-function map, which is
# complete regardless of what the listing shows (rule 33).
CONSTRAINT_LISTING_LIMIT = 16


STACK_LOCATION_OFFSET_VALUES: frozenset[int] = frozenset(
    _parse_immediate(token) for token in STACK_LOCATION_OFFSETS.values()
)


_INTEL_REG_CMP_RE = re.compile(
    r"^\s*cmp\s+(?P<reg>[a-z][a-z0-9]*)\s*,\s*(?P<imm>[^,\s]+)"
)


def _comparison_kind(lines: list[str], index: int) -> str:
    """How the branch after a compare uses it: equality, range, or neither."""
    branch = lines[index + 1] if index + 1 < len(lines) else ""
    if _EQUALITY_BRANCH_RE.match(branch):
        return "equality"
    if _RANGE_BRANCH_RE.match(branch):
        return "range"
    return "compare"


def _consume_register_compare(
    line: str,
    index: int,
    lines: list[str],
    pending_lengths: list[tuple[int, str]],
    constants: list[int],
    kinds: set[str],
) -> bool:
    """Answer a pending length load with a register compare, if this is one.

    Returns True when the line was a compare against a register holding a
    recognized InputBufferLength, so the caller stops processing it.
    """
    cmp_match = _ARM64_REG_CMP_RE.match(line) or _INTEL_REG_CMP_RE.match(line)
    if not cmp_match:
        return False
    # Answer the most recent length load still in flight.
    for pending in reversed(pending_lengths):
        if pending[1] != cmp_match.group("reg"):
            continue
        value = _parse_immediate(cmp_match.group("imm"))
        if value is not None:
            constants.append(value)
            kinds.add(_comparison_kind(lines, index))
        pending_lengths.remove(pending)
        return True
    return False


def collect_input_length_constraints(
    disassembled_functions: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Per-function input-length validation facts, keyed by function name.

    A function counts as length-checking when it loads the IRP stack
    location and then reads or compares the InputBufferLength field within
    a few instructions. The recovered constants are the sizes the driver
    compares against (the expected request shapes) - evidence for a
    reviewer, not a validation the block claims the driver performs
    correctly.
    """
    constraints: dict[str, dict[str, Any]] = {}
    if not disassembled_functions:
        return constraints
    length_offsets = {
        INPUT_BUFFER_LENGTH_OFFSET_64,
        INPUT_BUFFER_LENGTH_OFFSET_32,
    }
    for func_key, func_data in disassembled_functions.items():
        if not isinstance(func_data, dict):
            continue
        assembly = (func_data.get("assembly") or "").lower()
        if not assembly:
            continue
        lines = assembly.split("\n")
        function_name = str(func_data.get("name") or func_key)
        constants: list[int] = []
        kinds: set[str] = set()
        stack_location_at: int | None = None
        pending_lengths: list[tuple[int, str]] = []
        for index, line in enumerate(lines):
            intel = _INTEL_STACK_LOCATION_RE.match(line)
            arm64 = None if intel else _ARM64_STACK_LOCATION_RE.match(line)
            if intel or arm64:
                off_token = intel.group("off") if intel else arm64.group("off")
                off = _parse_immediate(off_token)
                if off in STACK_LOCATION_OFFSET_VALUES:
                    stack_location_at = index
                    continue
            # The register compare answers a load that already passed the
            # window, so it is handled before the window gate - the window
            # bounds which accesses are *recognized* as the length field,
            # not how far the comparison of a recognized one may sit.
            if pending_lengths and _consume_register_compare(
                line, index, lines, pending_lengths, constants, kinds
            ):
                continue
            # _LENGTH_WINDOW is the claim the docstring makes and now the
            # one the scan enforces: only a length access inside the window
            # that follows a stack-location load is InputBufferLength. +0x0C
            # is an offset every other structure in the function uses too,
            # so without the window one stack-location load licensed every
            # `[reg+0xc]` access to the end of the function (rule 9).
            if stack_location_at is None or index - stack_location_at > _LENGTH_WINDOW:
                continue
            # Intel: a compare straight against the memory operand.
            intel_cmp = _INTEL_LENGTH_CMP_RE.match(line)
            if intel_cmp and _parse_immediate(intel_cmp.group("off")) in length_offsets:
                value = _parse_immediate(intel_cmp.group("imm"))
                if value is not None:
                    constants.append(value)
                    kinds.add(_comparison_kind(lines, index))
                continue
            # ARM64 (and register-held Intel lengths): load then compare.
            load = _ARM64_LENGTH_LOAD_RE.match(line) or _INTEL_LENGTH_LOAD_RE.match(line)
            if load and _parse_immediate(load.group("off")) in length_offsets:
                pending_lengths.append((index, load.group("dst")))
                continue
        if stack_location_at is not None and constants:
            constraints[function_name] = {
                "input_length_constants": sorted(set(constants))[:16],
                "comparison_kinds": sorted(kinds),
            }
    return constraints


def annotate_input_length_checks(
    ioctls: list[dict[str, Any]], constraints: dict[str, dict[str, Any]]
) -> None:
    """Mark recovered control codes whose handler checks the input length.

    The correlation is function-level and says so: ``input_length_checked``
    is true when the function the code was recovered from contains an
    InputBufferLength comparison, not when a proven check guards that
    code's branch specifically.
    """
    for entry in ioctls:
        function = entry.get("function")
        if function and function in constraints:
            entry["input_length_checked"] = True
            entry["input_length_constants"] = constraints[function][
                "input_length_constants"
            ]


# SDDL device-descriptor strings: `D:` plus optional protection flag and
# ACE list, the shape IoCreateDeviceSecure's DefaultSDDLString argument
# takes. Bounded so a coincidental byte run cannot read as a descriptor.
_SDDL_ACE = rb"\([AD];;[A-Za-z0-9;-]+;;;[A-Za-z-]{2,}\)"
SDDL_DEVICE_RE_ASCII = re.compile(rb"D:P?[NRX]?" + _SDDL_ACE + rb"(?:" + _SDDL_ACE + rb"){0,8}")
# Grant ACEs whose trustee reaches beyond admins/system. WD=Everyone,
# AN=Anonymous, BU=Builtin Users, AU=Authenticated Users. The leading `A`
# is load-bearing: matching the trustee alone made a *deny* ACE read as a
# grant, so `D:P(D;;GA;;;WD)(A;;GA;;;SY)` - a descriptor that explicitly
# locks Everyone out, the most restricted shape there is - reported
# world_accessible and turned the IOCTL list into "unprivileged attack
# surface" backwards (rule 14).
_WORLD_SID_RE = re.compile(rb"\(A;;[A-Za-z0-9;-]+;;;(?:WD|AN|BU|AU)\)")

# How many SDDL strings are listed as evidence (a listing bound only; the
# world_accessible verdict scans every match, uncapped).
SDDL_LISTING_LIMIT = 8


def _wide_view(content: bytes) -> bytes:
    """The UTF-16LE interpretation of a section, as a byte string.

    Every 2-byte pair renders its low byte when the high byte is zero and
    NUL otherwise, so an ASCII regex run over the view can only match a
    span whose pairs were genuinely UTF-16LE text: the classes never
    contain NUL, and a corrupted pair emits NUL and breaks the match.
    This is how the SDDL scan sees wide strings without maintaining a
    second, interleaved regex.
    """
    out = bytearray(len(content) // 2)
    for index in range(len(out)):
        out[index] = content[index * 2] if content[index * 2 + 1] == 0 else 0
    return bytes(out)


def recover_device_acl(parsed_obj: lief.PE.Binary) -> dict[str, Any] | None:
    """The device-object security descriptor the image installs, or None.

    Reads SDDL strings from the string-bearing section bytes in both
    encodings (never the metadata strings list, whose gates must not bound
    this evidence). ``world_accessible`` is true when any grant ACE names
    a world-readable SID group - the property that turns the IOCTL list
    into unprivileged attack surface.
    """
    sections = getattr(parsed_obj, "sections", None)
    if not sections or isinstance(sections, lief.lief_errors):
        return None
    sddl_strings: list[str] = []
    seen: set[bytes] = set()
    world_accessible = False
    for section in sections:
        if not is_string_bearing_section(section):
            continue
        try:
            content = bytes(section.content)
        except (AttributeError, TypeError, ValueError):
            continue
        if not content:
            continue
        for raw in (
            *(match.group(0) for match in SDDL_DEVICE_RE_ASCII.finditer(content)),
            *(
                match.group(0)
                for match in SDDL_DEVICE_RE_ASCII.finditer(_wide_view(content))
            ),
        ):
            if raw in seen:
                continue
            seen.add(raw)
            if _WORLD_SID_RE.search(raw):
                world_accessible = True
            if len(sddl_strings) < SDDL_LISTING_LIMIT:
                try:
                    decoded = raw.decode("latin-1")
                except (UnicodeDecodeError, ValueError):
                    continue
                sddl_strings.append(decoded)
    if not sddl_strings:
        return None
    return {
        "sddl_strings": sddl_strings,
        "world_accessible": world_accessible,
        "source": "rdata_sddl_string",
    }
