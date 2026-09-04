"""Call-site and prologue completion for function discovery.

Unwind tables (see ``funcdisc.unwind``) miss two classes of functions:

- Formats without unwind tables at all. Stripped Go ELF binaries carry no
  ``.eh_frame``, and 32-bit PEs have no ``.pdata``, so symbol-free inputs
  still start from zero.
- Functions the tables legitimately omit: PLT-excluded cold code, hand-written
  assembly, and entries stripped alongside the binary.

Two completion passes close the gap:

- **Call-site promotion.** A resolved direct-call target inside an executable
  range but inside no known function span is a function start; the called
  code has to exist somewhere. The disassembler feeds these back into its
  worklist until a fixpoint (bounded), which is recursive-descent discovery
  built on machinery that already resolves the targets.
- **Prologue scan.** When a binary yields fewer functions than a prologue,
  scan executable bytes for compiler-generated frame setups (``push rbp;
  mov rbp, rsp`` / ``endbr64`` on x86-64, ``paciasp`` and the ``stp x29, x30,
  [sp, #-N]!`` frame on ARM64) aligned the way the ABI aligns functions. This
  is the lowest-confidence source, so it is tagged ``prologue`` and gated to
  sparse binaries only.

Both passes emit the same ``{address, size, source}`` shape as unwind
discovery so the merge contract is shared.
"""

import bisect
import struct

import lief

# Discovery must never dominate runtime, so both passes are bounded.
MAX_PROMOTED_FUNCTIONS = 1024
MAX_PROLOGUE_CANDIDATES = 8192
# The disassembler bounds a function with no known successor by this many
# bytes; the span check reuses it so both passes agree on function extent.
DEFAULT_FUNCTION_SPAN = 4096
# Prologue scanning runs only when symbol + unwind discovery produced fewer
# than this many functions; on denser binaries its precision is unneeded and
# its residue would only add noise.
PROLOGUE_SCAN_MIN_FUNCTIONS = 32

# x86-64: `push rbp; mov rbp, rsp` is the classic frame setup and endbr64
# starts every CET-protected function.
X86_PROLOGUE = b"\x55\x48\x89\xe5"
X86_ENDBR64 = b"\xf3\x0f\x1e\xfa"
# A function aligned to 16 bytes that starts with endbr64 and sets up a frame
# within the next two instructions is a compiler-emitted function start.
X86_ENDBR_WINDOW = 12
# Go's stack-split prologue: `cmp rsp, [r14+0x10]` (the g stack-guard) must
# be followed by a `jbe` to morestack, and large frames start by allocating
# `lea r12, [rsp-x]` before the same comparison. The r14-based guard exists
# only in Go code, which keeps both patterns high-precision.
X86_GO_STACK_CHECK = b"\x49\x3b\x66\x10"
X86_GO_LARGE_FRAME = b"\x4c\x8d\x64\x24"

# ARM64: paciasp (pointer-authenticated functions) and the frame-pointer push.
# `stp x29, x30, [sp, #<-N]>!` fixes bits 31-22 (store pair, pre-index,
# 64-bit), Rt2=x30, Rn=sp, Rt=x29; only the 7-bit immediate varies.
ARM64_PACIASP = 0xD503233F
ARM64_STP_FP_MASK = 0xFFC07FFF
ARM64_STP_FP_VALUE = 0xA9807BFD
# `mov x29, sp` is the canonical alias `add x29, sp, #0`.
ARM64_MOV_FP_SP = 0x910003FD
# Go's arm64 stack guard: `ldr x16, [x28+16]` loads g.stackguard0; x28 holds
# the g pointer only in Go code, so this single fixed word is high-precision.
ARM64_GO_STACK_CHECK = 0xF9400B90


def executable_ranges(parsed_obj) -> list[tuple[int, int]]:
    """Executable virtual-address ranges as ``[(start, end_exclusive), ...]``.

    Ranges are absolute virtual addresses, matching the call targets the
    disassembler resolves from instruction operands. Non-function executable
    areas (PLT thunks, Mach-O stubs) are subtracted so their trampolines are
    never promoted into fake ``sub_`` functions.
    """
    ranges: list[tuple[int, int]] = []
    excluded: list[tuple[int, int]] = []
    try:
        if isinstance(parsed_obj, lief.ELF.Binary):
            for section in parsed_obj.sections:
                if not section.size or section.size > (1 << 32):
                    continue
                if section.flags & 0x4:  # SHF_EXECINSTR
                    start = int(section.virtual_address)
                    ranges.append((start, start + int(section.size)))
                    if section.name.startswith(".plt"):
                        excluded.append((start, start + int(section.size)))
        elif isinstance(parsed_obj, lief.MachO.Binary):
            for section in parsed_obj.sections:
                if getattr(section.segment, "name", "") != "__TEXT":
                    continue
                size = int(section.size)
                if not size:
                    continue
                start = int(section.virtual_address)
                ranges.append((start, start + size))
                if section.name in ("__stubs", "__stub_helper"):
                    excluded.append((start, start + size))
        elif isinstance(parsed_obj, lief.PE.Binary):
            for section in parsed_obj.sections:
                if not section.size:
                    continue
                if section.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE):
                    start = int(section.virtual_address) + int(parsed_obj.optional_header.imagebase)
                    ranges.append((start, start + int(section.size)))
    except (AttributeError, TypeError, ValueError):
        return ranges
    merged: list[tuple[int, int]] = []
    for start, end in sorted(set(ranges) - set(excluded)):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _in_ranges(address: int, ranges: list[tuple[int, int]]) -> bool:
    for start, end in ranges:
        if start <= address < end:
            return True
        if address < start:
            break
    return False


def promotable_call_target(
    target_addr: int,
    known_starts: list[int],
    disassembled_spans: list[tuple[int, int]],
    exec_ranges: list[tuple[int, int]],
) -> int | None:
    """Return the address to promote, or None.

    The disassembly itself is the ground truth for what is a function body:
    a call target inside an already-disassembled extent is an intra-function
    or mid-code label and is declined, while a target in executable memory
    outside every disassembled extent (and not already a known start) proves
    called code the discovery tables missed. Extent intervals are sorted and
    non-overlapping, so a bisect lookup decides containment.
    """
    if not _in_ranges(target_addr, exec_ranges):
        return None
    idx = bisect.bisect_right(known_starts, target_addr) - 1
    if idx >= 0 and known_starts[idx] == target_addr:
        return None
    idx = bisect.bisect_right(disassembled_spans, (target_addr,)) - 1
    if idx >= 0:
        start, end = disassembled_spans[idx]
        if target_addr < end:
            return None
    return target_addr


def find_prologue_candidates(
    parsed_obj, arch_target: str, exec_ranges: list[tuple[int, int]]
) -> list[int]:
    """Scan executable bytes for frame-setup prologues.

    Returns absolute virtual addresses, sorted and deduplicated. Only patterns
    that compilers emit at function boundaries are recognized; anything weaker
    (bare ``sub rsp``, arbitrary ``stp``) has too many false positives to be
    worth its noise.
    """
    lower_arch = (arch_target or "").lower()
    is_arm64 = "aarch64" in lower_arch or "arm64" in lower_arch
    candidates: set[int] = set()
    try:
        if isinstance(parsed_obj, lief.ELF.Binary):
            sections = [
                (int(s.virtual_address), bytes(s.content))
                for s in parsed_obj.sections
                if s.size and (s.flags & 0x4) and not s.name.startswith(".plt")
            ]
        elif isinstance(parsed_obj, lief.MachO.Binary):
            sections = [
                (int(s.virtual_address), bytes(s.content))
                for s in parsed_obj.sections
                if getattr(s.segment, "name", "") == "__TEXT"
                and int(s.size)
                and s.name not in ("__stubs", "__stub_helper")
            ]
        elif isinstance(parsed_obj, lief.PE.Binary):
            imagebase = int(parsed_obj.optional_header.imagebase)
            sections = [
                (imagebase + int(s.virtual_address), bytes(s.content))
                for s in parsed_obj.sections
                if s.size and s.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE)
            ]
        else:
            return []
    except (AttributeError, TypeError, ValueError):
        return []
    for start, content in sections:
        if len(candidates) >= MAX_PROLOGUE_CANDIDATES:
            break
        if is_arm64:
            candidates.update(_scan_arm64_prologues(start, content))
        else:
            candidates.update(_scan_x86_prologues(start, content))
    return sorted(
        addr for addr in candidates if _in_ranges(addr, exec_ranges)
    )[:MAX_PROLOGUE_CANDIDATES]


def _scan_x86_prologues(start: int, content: bytes) -> set[int]:
    """Find x86-64 prologues at 16-byte-aligned addresses."""
    found: set[int] = set()
    # `push rbp; mov rbp, rsp` is 4 bytes; anything it mid-decodes into is
    # vanishingly rare at 16-byte alignment.
    cursor = content.find(X86_PROLOGUE)
    while cursor >= 0 and len(found) < MAX_PROLOGUE_CANDIDATES:
        if (start + cursor) % 16 == 0:
            found.add(start + cursor)
        cursor = content.find(X86_PROLOGUE, cursor + 1)
    # endbr64-protected functions: the branch target label sits before the
    # frame setup, so the function start is the endbr64 itself.
    cursor = content.find(X86_ENDBR64)
    while cursor >= 0 and len(found) < MAX_PROLOGUE_CANDIDATES:
        if (start + cursor) % 16 == 0:
            window = content[cursor + 4 : cursor + 4 + X86_ENDBR_WINDOW]
            if X86_PROLOGUE in window or b"\x48\x8b\xe4" in window or b"\x48\x83\xec" in window:
                found.add(start + cursor)
        cursor = content.find(X86_ENDBR64, cursor + 1)
    # Go stack-split prologues: guard comparison at the function start with
    # the conditional morestack branch right behind it, and the large-frame
    # allocation that precedes the same comparison.
    for pattern, needs_branch in ((X86_GO_STACK_CHECK, True), (X86_GO_LARGE_FRAME, False)):
        cursor = content.find(pattern)
        while cursor >= 0 and len(found) < MAX_PROLOGUE_CANDIDATES:
            if (start + cursor) % 16 == 0:
                if not needs_branch or content[cursor + 4 : cursor + 6] in (
                    b"\x0f\x86",
                    b"\x0f\xbe",
                    b"\x76",
                ):
                    found.add(start + cursor)
            cursor = content.find(pattern, cursor + 1)
    return found


def _scan_arm64_prologues(start: int, content: bytes) -> set[int]:
    """Find ARM64 prologues at 4-byte-aligned word boundaries."""
    found: set[int] = set()
    usable = len(content) - (len(content) % 4)
    for offset in range(0, usable, 4):
        if len(found) >= MAX_PROLOGUE_CANDIDATES:
            break
        word = struct.unpack_from("<I", content, offset)[0]
        if word == ARM64_PACIASP or word == ARM64_GO_STACK_CHECK:
            found.add(start + offset)
        elif word & ARM64_STP_FP_MASK == ARM64_STP_FP_VALUE:
            # The frame-pointer push alone is common inside functions; paired
            # with the `mov x29, sp` that always follows it in a prologue, it
            # is a reliable start marker.
            if offset + 8 <= usable:
                next_word = struct.unpack_from("<I", content, offset + 4)[0]
                if next_word == ARM64_MOV_FP_SP:
                    found.add(start + offset)
    return found
