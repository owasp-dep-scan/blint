"""The driver identity block (PE lane W5.1, plan 04/A).

A ``driver`` block is attached to every Windows image whose subsystem is
NATIVE or WINDOWS_BOOT_APPLICATION, that imports ``ntoskrnl.exe``, or that
imports the UMDF framework (the one addition to the plan's gate sentence,
argued in the data table: a UMDF driver is a user-mode DLL and would never
reach the block otherwise, yet ``umdf`` is a kind the plan's own enum
names). The block is identity, not verdicts: kind, the WDF binding facts
blint can actually see, the kernel objects the image names, the WDM
callbacks its code registers, and the W2.4 signing class carried in from
``code_signature``.

Determination discipline (this is the packet's load-bearing rule):

- ``kind`` is established by the signal table in
  ``blint/data/pe_driver_kinds.yml`` and never defaulted. A gate-passing
  image for which no signal matches carries ``kind: "unknown"`` - that is a
  value the block carries, not a wdm guess. Every matched signal is listed
  in ``kind_evidence`` even when precedence picked a different kind, so a
  KMDF minifilter shows both.
- Absence is not negation. Keys that need disassembly (``wdm_callbacks``,
  ``dispatch_routines``) are present only when the disassembly path ran;
  without it they are omitted rather than reported empty, and the
  ``analysis_coverage`` block already says whether disassembly ran.
- The WDF *version* is deliberately not recovered. The version lives in the
  WDF_BIND_INFO structure behind a pointer argument of WdfVersionBind;
  decoding it statically would mean guessing a non-public struct layout,
  and a plausible-looking wrong version is fabricated metadata (the W3.1
  lesson). ``wdf.library`` and ``wdf.static`` are facts blint can see;
  ``wdf.version`` is omitted until it can be read honestly.
"""

from __future__ import annotations

import re
from typing import Any

import lief

from blint.lib.binary_common import is_string_bearing_section
from blint.lib.pe_kernel_posture import apply_kernel_posture

# Kernel object namespace prefixes. Kernel object paths are unambiguous, so
# a match is a fact about the object the image names (the same prefixes
# driver_ioctl.classify_driver_strings reads from the metadata strings list;
# this scan reads the section bytes directly so the strings list's
# entropy/length/shape gates never become an identity boundary).
DRIVER_OBJECT_PATH_PREFIXES: tuple[tuple[str, str], ...] = (
    ("device_names", "\\device\\"),
    ("symbolic_links", "\\dosdevices\\"),
    ("symbolic_links", "\\??\\"),
    ("client_device_paths", "\\\\.\\"),
    ("registry_paths", "\\registry\\machine\\"),
)

# A path longer than this is not a device object name; a matched prefix
# followed by 200 bytes of binary garbage is a coincidental byte sequence.
_OBJECT_PATH_MAX_LEN = 120

# Listing bound per bucket. This is a listing bound only - consumers key on
# membership, never on the tail, and the fixtures include one past the bound
# pinning that the bucket still speaks (the rule-33 discipline).
OBJECT_PATH_LIMIT = 16

# WDF binding: the loader DLL (dynamic) and the framework runtime
# (statically linked). Wdf01100.sys and later minor-version runtimes share
# the Wdf01 prefix; the data table carries the same signals.
WDF_DYNAMIC_DLLS: set[str] = {"wdfldr.sys"}
WDF_STATIC_DLL_PREFIXES: tuple[str, ...] = ("wdf01",)

# The normalized import DLL set of a driver decides the gate and the kind.
_KERNEL_GATE_DLLS: set[str] = {"ntoskrnl.exe"}
_UMDF_DLL_PREFIXES: tuple[str, ...] = ("wudfx",)

_TABLE_CACHE: dict | None = None


def _kinds_table() -> dict:
    """The kind signal table, loaded once (data file with provenance)."""
    global _TABLE_CACHE
    if _TABLE_CACHE is None:
        import importlib.resources

        import yaml

        try:
            with importlib.resources.files("blint.data").joinpath(
                "pe_driver_kinds.yml"
            ).open("r", encoding="utf-8") as handle:
                _TABLE_CACHE = yaml.safe_load(handle) or {}
        except (OSError, yaml.YAMLError):
            # An unreadable table determines nothing (rule 11): kinds stay
            # unknown rather than half-derived from a partial file.
            _TABLE_CACHE = {}
    return _TABLE_CACHE


def imported_dll_names(metadata: dict[str, Any]) -> set[str]:
    """The lowercased DLL names this image imports.

    PE import entries are qualified ``library::function``; the DLL name is
    the part before the qualifier. Delay imports are deliberately excluded:
    the kind table is about what the loader binds, and a delay-loaded
    framework DLL is a different fact.
    """
    names: set[str] = set()
    for entry in metadata.get("imports") or []:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or "")
        if "::" in name:
            names.add(name.split("::", 1)[0].lower())
        # Unqualified names (some symbol paths) carry no DLL; ignore them
        # for gate purposes rather than guess a library.
    return names


def imported_function_names(metadata: dict[str, Any]) -> set[str]:
    """The lowercased, unqualified import function names (no leading _)."""
    names: set[str] = set()
    for entry in metadata.get("imports") or []:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or "")
        if "::" in name:
            name = name.rsplit("::", 1)[1]
        names.add(name.strip().lower().lstrip("_"))
    return names


def is_windows_driver(metadata: dict[str, Any]) -> bool:
    """True when the metadata describes a Windows driver image.

    The plan's gate: subsystem NATIVE or WINDOWS_BOOT_APPLICATION, or an
    ntoskrnl.exe import. The one addition (recorded in the data table
    header) is the UMDF framework import, which is how the plan's own
    ``umdf`` kind becomes reachable.
    """
    if not metadata:
        return False
    subsystem = str(metadata.get("subsystem", "")).upper()
    if subsystem in ("NATIVE", "WINDOWS_BOOT_APPLICATION"):
        return True
    dlls = imported_dll_names(metadata)
    if dlls & _KERNEL_GATE_DLLS:
        return True
    return any(dll.startswith(_UMDF_DLL_PREFIXES) for dll in dlls)


def classify_driver_kind(metadata: dict[str, Any]) -> tuple[str | None, list[dict[str, Any]]]:
    """The driver kind and the evidence that establishes it.

    Returns ``(kind, evidence)`` where ``kind`` is one of the table's kinds
    or ``None`` when nothing establishes a kind (the caller renders that as
    ``"unknown"`` - a carried value, never a guess). ``evidence`` lists
    every matched signal with the kind it speaks for, so a driver matching
    several shows its full classification basis and the precedence that
    picked the reported one.
    """
    table = _kinds_table()
    kinds = table.get("kinds") or {}
    precedence = table.get("precedence") or list(kinds)
    if not kinds:
        return None, []
    dlls = imported_dll_names(metadata)
    functions = imported_function_names(metadata)
    matched: list[tuple[int, str, str]] = []
    for position, kind in enumerate(precedence):
        spec = kinds.get(kind)
        if not isinstance(spec, dict):
            continue
        for dll in spec.get("dlls") or []:
            if str(dll).lower() in dlls:
                matched.append((position, kind, f"imports {dll}"))
                break
        else:
            for prefix in spec.get("dll_prefixes") or []:
                hit = next((d for d in sorted(dlls) if d.startswith(str(prefix).lower())), None)
                if hit:
                    matched.append((position, kind, f"imports {hit}"))
                    break
            else:
                for prefix in spec.get("import_prefixes") or []:
                    hit = sorted(f for f in functions if f.startswith(str(prefix).lower()))
                    if hit:
                        matched.append((position, kind, f"imports {hit[0]}"))
                        break
    matched.sort(key=lambda item: item[0])
    evidence = [{"kind": kind, "evidence": why} for _, kind, why in matched]
    if not matched:
        return None, evidence
    return matched[0][1], evidence


def recover_object_paths(
    parsed_obj: lief.PE.Binary,
) -> tuple[dict[str, list[str]], dict[str, int]]:
    """The kernel object paths the image names, from section bytes.

    Scanned over the string-bearing sections in both ASCII and UTF-16LE so
    the metadata strings list's gates never bound identity evidence. Each
    bucket is sorted, de-duplicated case-insensitively, and bounded by
    OBJECT_PATH_LIMIT; the second value counts the per-bucket matches past
    that bound so the block can name the truncation instead of silently
    cutting.
    """
    buckets: dict[str, list[str]] = {
        "device_names": [],
        "symbolic_links": [],
        "client_device_paths": [],
        "registry_paths": [],
    }
    seen: set[str] = set()
    truncated: dict[str, int] = {}
    sections = getattr(parsed_obj, "sections", None)
    if not sections or isinstance(sections, lief.lief_errors):
        return buckets, truncated
    for section in sections:
        if not is_string_bearing_section(section):
            continue
        try:
            content = bytes(section.content)
        except (AttributeError, TypeError, ValueError):
            continue
        if not content:
            continue
        lowered = content.lower()
        for encoding in ("ascii", "utf-16-le"):
            stride = 2 if encoding == "utf-16-le" else 1
            for bucket, prefix in DRIVER_OBJECT_PATH_PREFIXES:
                prefix_bytes = prefix.encode(encoding)
                start = 0
                while start < len(lowered):
                    at = lowered.find(prefix_bytes, start)
                    if at < 0:
                        break
                    # Walk the readable tail of the match: the path ends
                    # where the (UTF-16 or ASCII) printable run does.
                    end = at
                    while (
                        end + stride <= len(content)
                        and 0x20 <= content[end] < 0x7F
                        and (stride == 1 or content[end + 1] == 0)
                    ):
                        end += stride
                    value = content[at:end].decode(encoding, errors="replace").rstrip()
                    start = end if end > at else at + len(prefix_bytes)
                    if not value or len(value) > _OBJECT_PATH_MAX_LEN:
                        continue
                    key = (bucket, value.lower())
                    if key in seen:
                        continue
                    seen.add(key)
                    if len(buckets[bucket]) >= OBJECT_PATH_LIMIT:
                        truncated[bucket] = truncated.get(bucket, 0) + 1
                        continue
                    buckets[bucket].append(value)
    for bucket, values in buckets.items():
        values.sort()
    return buckets, truncated


# DRIVER_OBJECT field offsets, by layout width. x64 and ARM64 share the
# 64-bit layout (8-byte pointers throughout); x86 is the 32-bit one. The
# MajorFunction array and its IRP_MJ_DEVICE_CONTROL slot live at the same
# offsets driver_ioctl already keys on (0x70/0x38), so the callback stores
# and the dispatch stores describe one structure, not two guesses.
DRIVER_OBJECT_LAYOUTS: dict[str, dict[str, int]] = {
    "64": {
        "driver_extension": 0x30,
        "fast_io": 0x50,
        "start_io": 0x60,
        "unload": 0x68,
        "major_base": 0x70,
        "major_stride": 8,
    },
    "32": {
        "driver_extension": 0x18,
        "fast_io": 0x28,
        "start_io": 0x30,
        "unload": 0x34,
        "major_base": 0x38,
        "major_stride": 4,
    },
}
MAJOR_FUNCTION_SLOTS = 28

# DRIVER_EXTENSION.AddDevice offset within the extension structure.
ADD_DEVICE_OFFSETS: dict[str, int] = {"64": 0x20, "32": 0x10}

# Store instructions that register a callback: Intel syntax (x86 and x64 as
# nyxstone renders both) and ARM64 syntax (`str xN, [xM, #<dec>]` - blint
# renders immediates in decimal by default, and the # prefix is AArch64's).
# Only a 64-bit `str x` store counts on ARM64: a callback slot holds a
# pointer, and `str w`/`strb` at the same offset is a different object.
# Base registers that address the stack frame are excluded: a DRIVER_OBJECT
# pointer is a parameter, not a local at the same offset.
_INTEL_STORE_RE = re.compile(
    r"^\s*mov\s+(?:qword\s+ptr\s+)?\[\s*"
    r"(?!rsp|rbp|esp|ebp)(?P<base>[a-z][a-z0-9]*)\s*\+\s*"
    r"(?P<off>0x[0-9a-f]+|[0-9]+)\s*\]\s*,"
)
_ARM64_STORE_RE = re.compile(
    r"^\s*str\s+x(?P<src>[0-9]+)\s*,\s*\[\s*"
    r"(?!x29\b|xzr\b)(?P<base>x[0-9]+)\s*,\s*#(?P<off>[0-9]+)\s*\]"
)
# AddDevice is registered through the extension pointer: a load from
# DRIVER_OBJECT.DriverExtension followed, within a few instructions, by a
# store through the loaded register at the AddDevice offset.
_INTEL_EXT_LOAD_RE = re.compile(
    r"^\s*mov\s+(?P<dst>[a-z][a-z0-9]*)\s*,\s*"
    r"(?:qword\s+ptr\s+)?\[\s*(?P<src>[a-z][a-z0-9]*)\s*\+\s*"
    r"(?P<off>0x[0-9a-f]+|[0-9]+)\s*\]"
)
_ARM64_EXT_LOAD_RE = re.compile(
    r"^\s*ldr\s+(?P<dst>x[0-9]+)\s*,\s*\[\s*(?P<src>x[0-9]+)\s*,\s*#(?P<off>[0-9]+)\s*\]"
)
# An explicit "no callback" is the same store at the same offset: WDM drivers
# routinely write NULL to DriverUnload to state that there is none, and that
# must not read as registering one. Intel source registers are checked for a
# zeroing instruction in the preceding few lines (the ARM64 rendering names
# its zero register xzr, which the store pattern already refuses).
_INTEL_ZERO_RE = re.compile(r"^\s*(?:xor|sub)\s+(?P<reg>[a-z][a-z0-9]*)\s*,\s*(?P=reg)")
_INTEL_ZERO_WINDOW = 4
_ADDDEVICE_WINDOW = 6


def _parse_offset(token: str) -> int | None:
    try:
        if token.startswith("0x"):
            return int(token, 16)
        return int(token, 10)
    except ValueError:
        return None


def _register_alias(reg: str) -> str:
    """The canonical 64-bit spelling of an x86/x64 register name."""
    if len(reg) >= 3 and reg.startswith("e") and reg[1] != "x":
        return f"r{reg[1:]}"
    return reg


def _register_was_zeroed(lines: list[str], index: int, stored: str) -> bool:
    """True when the stored register was zeroed within the preceding lines.

    Comparing through the alias so `xor ebx, ebx` zeroes `rbx` - the 32-bit
    zeroing is the same value.
    """
    stored = _register_alias(stored)
    for prior in lines[max(0, index - _INTEL_ZERO_WINDOW) : index]:
        match = _INTEL_ZERO_RE.match(prior)
        if match and _register_alias(match.group("reg")) == stored:
            return True
    return False


def _register_callbacks_for_layout(
    lines: list[str], offsets: dict[str, int], add_device_offset: int
) -> tuple[set[str], bool]:
    """One function's WDM callback registrations in one layout width.

    Returns (callback names registered, fast-io pointer present). A store
    counts only when its offset is the field's offset exactly; loads never
    count (reading DriverUnload is not registering one).

    Corroboration requirement: the same function must also store at least
    one MajorFunction slot. Offsets collide - a runtime-allocated context
    struct has pointer fields too, and cdrom.sys (a KMDF driver whose
    DriverEntry never touches a DRIVER_OBJECT field directly) stores
    non-NULL values at +0x60/+0x68 into exactly such a struct. A store at a
    MajorFunction slot is the shared context that says the base register
    actually holds a DRIVER_OBJECT; without it, a lone store at +0x68 is an
    ordinary struct write and is not claimed. The stated blind spot: a
    driver registering only DriverUnload and no dispatch routine at all is
    reported with no callbacks (a driver that handles no IRP is not a
    working driver).
    """
    callbacks: set[str] = set()
    fast_io = False
    major_stores = 0
    major_lo = offsets["major_base"]
    major_hi = major_lo + (MAJOR_FUNCTION_SLOTS - 1) * offsets["major_stride"]
    for index, line in enumerate(lines):
        intel = _INTEL_STORE_RE.match(line)
        arm64 = None if intel else _ARM64_STORE_RE.match(line)
        if not intel and not arm64:
            # The AddDevice window walk needs the load lines too, but they
            # are re-scanned when the store is found; nothing to do here.
            continue
        off = _parse_offset(intel.group("off") if intel else arm64.group("off"))
        if off is None:
            continue
        if intel:
            # A NULL store is the driver stating "no callback here", not a
            # registration; refuse it rather than claim the callback.
            stored = line.rsplit(",", 1)[-1].strip()
            if stored.startswith("0"):
                continue
            if _register_was_zeroed(lines, index, stored):
                continue
        if major_lo <= off <= major_hi:
            major_stores += 1
        elif off == offsets["unload"]:
            callbacks.add("DriverUnload")
        elif off == offsets["start_io"]:
            callbacks.add("DriverStartIo")
        elif off == offsets["fast_io"]:
            fast_io = True
        elif off == add_device_offset:
            # A store at the AddDevice offset only registers AddDevice when
            # the base register was loaded from DRIVER_OBJECT.DriverExtension
            # within the preceding few instructions; otherwise it is an
            # ordinary struct field write that happens to share the offset.
            load_re = _INTEL_EXT_LOAD_RE if intel else _ARM64_EXT_LOAD_RE
            for prior in lines[max(0, index - _ADDDEVICE_WINDOW) : index]:
                prior_match = load_re.match(prior)
                if prior_match and _parse_offset(prior_match.group("off")) == offsets[
                    "driver_extension"
                ]:
                    callbacks.add("AddDevice")
                    break
    if not major_stores:
        # No dispatch-slot store in this function: the base register was
        # never shown to be a DRIVER_OBJECT, so nothing here is claimed.
        return set(), False
    return callbacks, fast_io


def machine_layout_widths(metadata: dict[str, Any]) -> tuple[str, ...]:
    """The plausible DRIVER_OBJECT layout widths for this image's machine.

    Matching only the plausible width keeps a 64-bit image's ordinary
    struct stores (an x64 driver writes plenty of fields at 0x18-0x34) from
    registering callbacks through the 32-bit table. An unknown machine
    falls back to both widths, stated in the block.
    """
    value = metadata.get("machine_type_value")
    if isinstance(value, int) and not isinstance(value, bool):
        from blint.lib import pe_constants

        name = pe_constants.machine_type_name(value).upper()
        if "X86" in name or "I386" in name or "I486" in name:
            return ("32",)
        if name.startswith("ARMNT"):
            return ("32",)
        return ("64",)
    machine = str(metadata.get("machine_type") or "").upper()
    if "X86" in machine and "X64" not in machine and "86" in machine:
        return ("32",)
    if machine:
        return ("64",)
    return ("64", "32")


def recover_wdm_callbacks(
    disassembled_functions: dict[str, Any], widths: tuple[str, ...] = ("64",)
) -> dict[str, Any] | None:
    """The WDM callbacks the driver's code registers, from disassembly.

    Returns None when there is no disassembly to read (the key is omitted
    rather than reported empty - absence of a run is not absence of
    callbacks). ``widths`` selects the DRIVER_OBJECT layout widths matched,
    from the image's machine type where it is known.
    """
    if not disassembled_functions:
        return None
    registered: dict[str, dict[str, Any]] = {}
    fast_io_functions: list[str] = []
    layouts_seen: set[str] = set()
    for func_key, func_data in disassembled_functions.items():
        if not isinstance(func_data, dict):
            continue
        assembly = (func_data.get("assembly") or "").lower()
        if not assembly:
            continue
        lines = assembly.split("\n")
        function_name = str(func_data.get("name") or func_key)
        for width in widths:
            offsets = DRIVER_OBJECT_LAYOUTS[width]
            add_device_offset = ADD_DEVICE_OFFSETS[width]
            callbacks, func_fast_io = _register_callbacks_for_layout(
                lines, offsets, add_device_offset
            )
            if not callbacks and not func_fast_io:
                continue
            layouts_seen.add(width)
            for callback in sorted(callbacks):
                entry = registered.setdefault(callback, {"functions": []})
                if len(entry["functions"]) < 5 and function_name not in entry["functions"]:
                    entry["functions"].append(function_name)
            if func_fast_io and function_name not in fast_io_functions:
                if len(fast_io_functions) < 5:
                    fast_io_functions.append(function_name)
    if not registered and not fast_io_functions:
        return {"callbacks": [], "fast_io_dispatch": False}
    return {
        "callbacks": sorted(registered),
        "callback_evidence": {
            name: {"functions": entry["functions"]} for name, entry in sorted(registered.items())
        },
        "fast_io_dispatch": bool(fast_io_functions),
        "fast_io_evidence": {"functions": fast_io_functions},
        # Which structure widths the stores matched - a 64-bit-only driver
        # and an x86 one read differently in a report.
        "layouts": sorted(layouts_seen),
    }


def _driver_signing_view(code_signature: dict) -> dict[str, Any] | None:
    """The signing view the driver lane reads, from the W2.4 block.

    Dual-signed drivers are the normal case for vendor hardware: the file
    carries the vendor's own commercial signature *and* Microsoft's WHQL
    attestation, and it loads into the kernel because of the second one.
    The W2.4 ``signing_class`` derives from the first signature whose facts
    determine one, in walk order - the outer signature first, exactly the
    order Windows evaluates them - so a Parallels EV + WHQL-attestation
    driver classes as ``commercial_ev`` there, which is correct about its
    outer signature and understates what vouches for the kernel image.

    This view therefore scans every parsed signature for the kernel-trust
    programs first (kernelModeCodeSigning, then the WHQL pair, the same
    EKU-to-class vocabulary as W2.4), and falls back to the block's class.
    ``basis`` names which path decided, so the two blocks can be reconciled
    by a reader without either re-deriving the other.
    """
    signatures = code_signature.get("signatures") or []
    for wanted, klass in (
        ({"kernelModeCodeSigning"}, "kernel_mode"),
        ({"whqlAttestation"}, "attestation_signed"),
        ({"whql"}, "whql"),
    ):
        for signature in signatures:
            if not isinstance(signature, dict):
                continue
            ekus = set((signature.get("signer") or {}).get("eku") or [])
            if ekus & wanted:
                return {"class": klass, "basis": "kernel_trust_signature"}
    if code_signature.get("signing_class"):
        view = {
            "class": code_signature.get("signing_class"),
            "basis": "block_signing_class",
        }
        if code_signature.get("signing_class_anchor"):
            view["anchor"] = code_signature.get("signing_class_anchor")
        return view
    return None


def build_driver_block(metadata: dict[str, Any], parsed_obj: lief.PE.Binary) -> dict[str, Any] | None:
    """The ``driver`` identity block, or None when this is not a driver.

    Everything here is available without disassembly; binary.parse refreshes
    the block with the disassembly-derived facts (WDM callbacks, dispatch
    routines) once that path has run.
    """
    if not is_windows_driver(metadata):
        return None
    kind, kind_evidence = classify_driver_kind(metadata)
    block: dict[str, Any] = {
        # Rule 32: "unknown" is a value the block carries - a kind blint
        # could not establish is stated as such, never silently read as wdm.
        "kind": kind or "unknown",
        "kind_evidence": kind_evidence,
        "subsystem": metadata.get("subsystem"),
    }
    if metadata.get("major_subsystem_version") is not None:
        block["subsystem_version"] = (
            f"{metadata.get('major_subsystem_version')}."
            f"{metadata.get('minor_subsystem_version')}"
        )
    dlls = imported_dll_names(metadata)
    wdf_block: dict[str, Any] = {}
    if dlls & WDF_DYNAMIC_DLLS:
        wdf_block["library"] = "WdfLdr.sys"
        wdf_block["static"] = False
    elif any(dll.startswith(WDF_STATIC_DLL_PREFIXES) for dll in dlls):
        wdf_block["library"] = min(
            dll for dll in dlls if dll.startswith(WDF_STATIC_DLL_PREFIXES)
        )
        wdf_block["static"] = True
    if wdf_block:
        # The version is deliberately absent (module docstring); the block
        # says so once rather than implying the facts are complete.
        wdf_block["version"] = None
        wdf_block["version_note"] = "not_decoded_statically"
        block["wdf"] = wdf_block
    paths, truncated = recover_object_paths(parsed_obj)
    for bucket, values in paths.items():
        if values:
            block[bucket] = values
        elif bucket in ("device_names", "symbolic_links"):
            # The empty case is a case (rule 32): a driver that names no
            # device object and no symlink is stated as empty, not left
            # ambiguous with "not scanned".
            block[bucket] = []
    if truncated:
        block["object_paths_truncated"] = {
            bucket: count for bucket, count in sorted(truncated.items())
        }
    if any(paths.values()):
        block["object_paths_source"] = "section_scan"
    code_signature = metadata.get("code_signature") or {}
    if isinstance(code_signature, dict) and code_signature.get("parse_status") == "parsed":
        # Carried in from W2.4 with the basis named: the block summarises the
        # signature block (it does not re-derive it) and, for dual-signed
        # drivers, names the kernel-trust signature that loads the image.
        signing_view = _driver_signing_view(code_signature)
        if signing_view:
            signing_view["source"] = "code_signature"
            block["signing"] = signing_view
    # W5.2: the kernel hardening posture (HVCI conditions, kernel CFG /
    # retpoline facts, scored BYOVD primitive families) attaches here so the
    # block stays the one-stop driver identity+posture summary.
    apply_kernel_posture(block, metadata)
    return block


def refresh_driver_block_after_disassembly(metadata: dict[str, Any]) -> None:
    """Add the disassembly-derived facts to an existing ``driver`` block.

    Called by binary.parse once ``disassembled_functions`` exists. Facts
    recovered by other blocks are summarised with their source named rather
    than recomputed (rule 21: one place computes, the summary says where).
    """
    block = metadata.get("driver")
    if not isinstance(block, dict):
        return
    callbacks_block = recover_wdm_callbacks(
        metadata.get("disassembled_functions") or {},
        widths=machine_layout_widths(metadata),
    )
    if callbacks_block is not None:
        block["wdm_callbacks"] = callbacks_block
    driver_ioctls = metadata.get("driver_ioctls") or {}
    handlers = driver_ioctls.get("dispatch_handlers") or []
    if handlers:
        routines: dict[str, list[str]] = {}
        for handler in handlers:
            if not isinstance(handler, dict):
                continue
            slot = str(handler.get("slot") or "")
            function = str(handler.get("function") or "")
            if slot and function:
                routines.setdefault(slot, [])
                if function not in routines[slot]:
                    routines[slot].append(function)
        block["dispatch_routines"] = routines
        block["dispatch_routines_source"] = "driver_ioctls"
