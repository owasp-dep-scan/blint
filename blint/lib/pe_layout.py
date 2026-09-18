# SPDX-License-Identifier: Apache-2.0
"""PE layout forensics and the pre-main execution summary (W1.4, 01/B.5, B.1).

The layout block turns the section-table and header facts a reverse engineer
checks by hand into named fields: raw-vs-virtual size anomalies, zero raw
size with a large virtual size (the unpacker-stub shape), section names that
do not fit the toolchain the rich header names, the entry point outside
``.text`` or inside the last section, a ``SizeOfImage`` that disagrees with
the section table, a truncated last section, and header-timestamp sanity.
The fields are facts — every anomaly a reader could act on is measured over
the benign corpus tiers and defended in the packet commit (ground rule 34);
the rule layer, not the field, decides guilt.

``pre_main_execution`` is the one answer to "what runs before ``main``": TLS
callbacks resolved to discovered functions, the writability of the TLS
directory and callback array, and the static initializers LIEF recovers,
under one summary per format (ground rule 21 — no second place to look).
"""

import contextlib
import os
import time
from collections.abc import Iterable

import lief

from blint.lib.binary_common import ADDRESS_FMT
from blint.lib.import_attribution import normalize_call_target
from blint.logger import LOG

# SECTION_CHARACTERISTICS bit for MEM_WRITE, used for the TLS writability
# facts. Keyed by number so writability never depends on a rendered enum.
SECTION_MEM_WRITE = 0x80000000

# One 4 KiB page: a section with no file bytes at all mapping at least this
# much virtual space is the zero-raw/large-virtual shape (unpacker stubs,
# but also the ordinary .bss).
LARGE_VIRTUAL_THRESHOLD = 0x1000

# Timestamps more than a day into the future are treated as impossible; a
# one-day skew absorbs clock drift across build farms.
TIMESTAMP_FUTURE_SKEW = 86400

# A section table longer than this is a hostile image; the extra sections
# are counted, not listed.
MAX_LISTED_SECTIONS = 64

# Bound the pre-main lists the same way.
MAX_LISTED_CALLBACKS = 64
MAX_LISTED_CTORS = 64

# Pre-main call targets that name debugger awareness, checked only against
# the image's own imports when the callback's function was disassembled.
# Four names, deliberately: the classic pair plus the two syscall wrappers.
ANTI_DEBUG_IMPORTS = frozenset(
    {
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtSetInformationThread",
        "NtQueryInformationProcess",
    }
)

# Section-name prefixes the named toolchains emit, lowercased. A section is
# standard when its lowercase name starts with one of the toolchain's
# prefixes, which folds the ``$``-suffixed merged names (``.text$mn``) and
# numbered variants (``.textbss``) in without enumerating them. The MSVC set
# includes the sections Microsoft documents for CFG (``.00cfg``) and for the
# ARM64X/ARM64EC hybrid images (``.a64xrm`` relocations, ``.hexpthk`` and
# ``fothk`` hotpatch thunks) — measured on tier 0-1, where the only
# non-standard names left are genuinely third-party.
MSVC_SECTION_PREFIXES = (
    ".text",
    ".rdata",
    ".data",
    ".pdata",
    ".xdata",
    ".bss",
    ".edata",
    ".idata",
    ".tls",
    ".reloc",
    ".rsrc",
    ".debug",
    ".didat",
    ".gfids",
    ".giats",
    ".glue",
    ".gehcont",
    ".00cfg",
    ".hexpthk",
    ".a64xrm",
    "fothk",
)
GNU_SECTION_PREFIXES = MSVC_SECTION_PREFIXES + (
    ".eh_frame",
    ".gcc",
    ".ctors",
    ".dtors",
    ".crt",
    ".gnu",
    ".rodata",
    ".init",
    ".fini",
    ".note",
    ".comment",
    ".stab",
    ".drectve",
    ".tm_clone",
    ".got",
    ".zig",
    "_rdata",
)
GO_SECTION_PREFIXES = (
    ".text",
    ".rdata",
    ".data",
    ".pdata",
    ".xdata",
    ".idata",
    ".reloc",
    ".rsrc",
    ".gopclntab",
    ".gosymtab",
    ".symtab",
)
DOTNET_SECTION_PREFIXES = (
    ".text",
    ".rdata",
    ".data",
    ".pdata",
    ".rsrc",
    ".reloc",
    ".idata",
    ".tls",
    ".bss",
    ".clr_uef",
)
# A image whose toolchain is unknown gets the union, so only names outside
# every common toolchain are listed — the honest best effort.
GENERIC_SECTION_PREFIXES = tuple(sorted(set(GNU_SECTION_PREFIXES + GO_SECTION_PREFIXES)))

SECTION_TOOLCHAINS = {
    "msvc": MSVC_SECTION_PREFIXES,
    "mingw": GNU_SECTION_PREFIXES,
    "go": GO_SECTION_PREFIXES,
    "dotnet": DOTNET_SECTION_PREFIXES,
    "unknown": GENERIC_SECTION_PREFIXES,
}


def _section_name(section) -> str:
    name = getattr(section, "name", "") or ""
    return name.rstrip("\x00")


def _detect_section_toolchain(metadata: dict) -> str:
    """The toolchain the section-name expectation is keyed to.

    Reads the provenance the other packets established: the .NET and Go
    markers, then the rich header's linker record (W1.1). A MinGW build
    carries no rich header, so a ``.eh_frame``/``.gcc_*`` section names it —
    the one case where the sections themselves pick the expectation.
    """
    if metadata.get("is_dotnet"):
        return "dotnet"
    if metadata.get("go_dependencies"):
        return "go"
    rich_toolchain = (metadata.get("rich_header") or {}).get("toolchain") or {}
    if rich_toolchain.get("linker_label") or rich_toolchain.get("linker_build_id"):
        return "msvc"
    if metadata.get("rust_dependencies"):
        return "msvc"
    return "unknown"


def _non_standard_sections(names: list[str], toolchain: str) -> list[str]:
    prefixes = SECTION_TOOLCHAINS.get(toolchain, GENERIC_SECTION_PREFIXES)
    listed = []
    for name in names:
        lowered = name.lower()
        # "/nnnn" is the COFF string-table encoding for long section names
        # (the PE spec's standard form), not a custom name.
        if lowered.startswith("/"):
            continue
        if not lowered.startswith(prefixes):
            listed.append(name)
            if len(listed) >= MAX_LISTED_SECTIONS:
                break
    return listed


def _align_up(value: int, alignment: int) -> int:
    if alignment <= 1:
        return value
    return (value + alignment - 1) // alignment * alignment


def parse_pe_layout(parsed_obj: lief.PE.Binary, exe_file: str, metadata: dict) -> dict:
    """The layout-forensics block for one PE image (01/B.5).

    Every field is computed from the section table, the optional header and
    the file size — never from another field's verdict. Fields that would be
    vacuous (no entry point, no sections) are omitted rather than defaulted,
    so absence reads as "could not be computed", not "computed clean".
    """
    block: dict = {}
    try:
        sections = list(parsed_obj.sections)
    except (AttributeError, TypeError, ValueError) as exc:
        LOG.debug(f"Unable to enumerate PE sections for layout forensics: {exc}")
        return block
    try:
        optional_header = parsed_obj.optional_header
        entry_point_rva = int(optional_header.addressof_entrypoint or 0)
        sizeof_image = int(optional_header.sizeof_image or 0)
        section_alignment = int(optional_header.section_alignment or 0)
        file_alignment = int(optional_header.file_alignment or 0x200)
    except (AttributeError, TypeError, ValueError) as exc:
        LOG.debug(f"Unable to read PE optional header for layout forensics: {exc}")
        return block

    rows = []
    for section in sections:
        rows.append(
            {
                "name": _section_name(section),
                "virtual_address": int(getattr(section, "virtual_address", 0) or 0),
                "virtual_size": int(getattr(section, "virtual_size", 0) or 0),
                "raw_size": int(getattr(section, "sizeof_raw_data", 0) or 0),
                "raw_pointer": int(getattr(section, "pointerto_raw_data", 0) or 0),
            }
        )

    # Entry-point placement. A zero entry point (every resource-only DLL)
    # computes nothing: there is nothing to place. "Outside .text" is only
    # computed when a .text exists to be outside of — a packed image that
    # renamed its code section is described by the non-standard-sections
    # field, not by this one.
    if entry_point_rva:
        entry_section = None
        for row in rows:
            span = max(row["virtual_size"], row["raw_size"])
            if row["virtual_address"] <= entry_point_rva < row["virtual_address"] + span:
                entry_section = row
                break
        text_present = any(row["name"].lower() == ".text" for row in rows)
        block["entry_point_section"] = entry_section["name"] if entry_section else None
        if entry_section is not None and text_present:
            block["entry_point_outside_text"] = (
                entry_section["name"].lower() != ".text"
            )
        # With a single section the answer is vacuous — every section is
        # the last — so the field is stated only where it can differ.
        if len(rows) > 1:
            block["entry_point_in_last_section"] = entry_section is rows[-1]
        if entry_section is None:
            block["entry_point_outside_any_section"] = True

    # SizeOfImage: what the section table adds up to versus what the
    # optional header claims the loader should reserve.
    if rows and section_alignment:
        expected = max(
            _align_up(row["virtual_address"] + max(row["virtual_size"], 1), section_alignment)
            for row in rows
        )
        block["sizeof_image_expected"] = expected
        if sizeof_image:
            block["sizeof_image_mismatch"] = expected != sizeof_image

    # Size anomalies, one named list per shape. A zero raw size is only an
    # anomaly at scale: a page or more of virtual space with no file bytes.
    zero_raw = [row["name"] for row in rows if row["raw_size"] == 0]
    if zero_raw:
        block["zero_raw_size_sections"] = zero_raw[:MAX_LISTED_SECTIONS]
    large_virtual_zero_raw = [
        row["name"]
        for row in rows
        if row["raw_size"] == 0 and row["virtual_size"] >= LARGE_VIRTUAL_THRESHOLD
    ]
    if large_virtual_zero_raw:
        block["large_virtual_zero_raw_sections"] = large_virtual_zero_raw[:MAX_LISTED_SECTIONS]
    raw_exceeds_virtual = [
        row["name"]
        for row in rows
        if row["raw_size"] > 0 and row["raw_size"] > _align_up(row["virtual_size"], file_alignment)
    ]
    if raw_exceeds_virtual:
        block["raw_exceeds_virtual_sections"] = raw_exceeds_virtual[:MAX_LISTED_SECTIONS]

    # Section naming versus the toolchain the rich header names.
    if rows:
        names = [row["name"] for row in rows if row["name"]]
        toolchain = _detect_section_toolchain(metadata)
        non_standard = _non_standard_sections(names, toolchain)
        if non_standard:
            block["non_standard_sections"] = non_standard
        if toolchain != "unknown":
            block["section_naming_toolchain"] = toolchain

    # A last section whose raw bytes run past end of file means the image
    # was truncated after the fact (an appended certificate is outside the
    # section table, so it never explains this).
    if rows:
        try:
            file_size = int(os.path.getsize(exe_file))
        except OSError:
            file_size = 0
        if file_size:
            last = rows[-1]
            if last["raw_size"] and last["raw_pointer"]:
                block["truncated_last_section"] = (
                    last["raw_pointer"] + last["raw_size"] > file_size
                )

    # Header timestamp sanity: zero is the /Brepro (or intentional) shape,
    # a future stamp is impossible to have recorded honestly.
    stamp = int(metadata.get("time_date_stamps") or 0)
    if stamp:
        block["timestamp"] = stamp
        block["timestamp_in_future"] = stamp > int(time.time()) + TIMESTAMP_FUTURE_SKEW
    else:
        block["timestamp_epoch_zero"] = True
    return block


def _writable_section_for_rva(parsed_obj: lief.PE.Binary, rva: int) -> str | None:
    """The name of the writable section covering an RVA, else None."""
    try:
        for section in parsed_obj.sections:
            start = int(section.virtual_address or 0)
            span = max(int(getattr(section, "virtual_size", 0) or 0), 1)
            characteristics = getattr(section, "characteristics_lists", []) or []
            writable = SECTION_MEM_WRITE in _characteristic_values(characteristics)
            if writable and start <= rva < start + span:
                return _section_name(section)
    except (AttributeError, TypeError, ValueError):
        return None
    return None


def _characteristic_values(characteristics: Iterable) -> set[int]:
    """Numeric section characteristic values, tolerant of enum renderings."""
    values = set()
    for item in characteristics:
        with contextlib.suppress(AttributeError, TypeError, ValueError):
            values.add(int(getattr(item, "value", item)))
    return values


def _section_writability(parsed_obj: lief.PE.Binary, section) -> bool | None:
    """Whether the TLS directory's own section maps writable."""
    try:
        characteristics = section.characteristics_lists or []
    except (AttributeError, TypeError, ValueError):
        return None
    return SECTION_MEM_WRITE in _characteristic_values(characteristics)


def parse_pre_main_execution(parsed_obj: lief.PE.Binary, metadata: dict) -> dict:
    """The one pre-``main`` summary for a PE image (01/B.1).

    Unifies what the format offers: TLS callbacks (resolved to discovered
    functions when the address matches), the writability of the TLS
    directory and of the callback array, and LIEF's ``ctor_functions`` static
    initializers. The legacy top-level ``tls_callbacks`` address list keeps
    its shape; this block is the consumer-facing summary.
    """
    block: dict = {}
    functions_by_address: dict[str, dict] = {}
    for func in metadata.get("functions") or []:
        if isinstance(func, dict) and func.get("address"):
            functions_by_address.setdefault(func["address"], func)

    try:
        tls = parsed_obj.tls
    except (AttributeError, TypeError, ValueError):
        tls = None
    callback_rows: list[dict] = []
    if tls:
        try:
            raw_callbacks = list(tls.callbacks or [])
        except (AttributeError, TypeError, ValueError):
            raw_callbacks = []
        imagebase = 0
        with contextlib.suppress(AttributeError, TypeError, ValueError):
            imagebase = int(parsed_obj.optional_header.imagebase or 0)
        for callback in raw_callbacks[:MAX_LISTED_CALLBACKS]:
            with contextlib.suppress(AttributeError, TypeError, ValueError):
                address = ADDRESS_FMT.format(callback).strip()
                row: dict = {"address": address}
                func = functions_by_address.get(address)
                if func is None and imagebase:
                    func = functions_by_address.get(
                        ADDRESS_FMT.format(callback - imagebase).strip()
                    )
                if func is not None:
                    row["function"] = func.get("name")
                    row["resolved"] = True
                else:
                    row["resolved"] = False
                callback_rows.append(row)
        if len(raw_callbacks) > MAX_LISTED_CALLBACKS:
            block["tls_callbacks_truncated"] = True
        if callback_rows:
            block["tls_callbacks"] = callback_rows
        if tls.has_section:
            writable = _section_writability(parsed_obj, tls.section)
            if writable is not None:
                block["tls_directory_writable"] = writable
                if writable:
                    block["tls_directory_section"] = _section_name(tls.section)
        # The callback array the loader walks lives at AddressOfCallBacks;
        # a writable array is the runtime-patchable shape.
        array_rva = None
        with contextlib.suppress(AttributeError, TypeError, ValueError):
            array_rva = int(tls.addressof_callbacks) - imagebase
        if array_rva is not None and array_rva > 0:
            writable_section = _writable_section_for_rva(parsed_obj, array_rva)
            if writable_section:
                block["tls_callback_array_writable"] = True
                block["tls_callback_array_section"] = writable_section

    anti_debug_reachable: list[str] = []
    disassembled_functions = metadata.get("disassembled_functions") or {}
    if disassembled_functions:
        # The disassembly dict is keyed ``address::name``; index the name
        # part too so a resolved callback can find its own call targets.
        by_name: dict[str, dict] = {}
        for func_key, func_data in disassembled_functions.items():
            if isinstance(func_data, dict) and "::" in str(func_key):
                by_name.setdefault(str(func_key).split("::", 1)[1], func_data)
        for row in callback_rows:
            if not row.get("resolved"):
                continue
            func_name = row.get("function")
            disassembled = disassembled_functions.get(func_name) or by_name.get(func_name) or {}
            targets = disassembled.get("direct_call_targets") or []
            for target in targets:
                normalized = normalize_call_target(str(target))
                if normalized in ANTI_DEBUG_IMPORTS:
                    anti_debug_reachable.append(func_name)
                    break
    if anti_debug_reachable:
        block["anti_debug_reachable_functions"] = sorted(set(anti_debug_reachable))[:16]

    ctors: list[dict] = []
    for func in metadata.get("ctor_functions") or []:
        if isinstance(func, dict) and (func.get("name") or func.get("address")):
            ctors.append(func)
            if len(ctors) >= MAX_LISTED_CTORS:
                break
    if ctors:
        # LIEF derives a PE image's ctor_functions from the TLS callback
        # array, so when the initializers are exactly the callbacks they
        # are one fact, not two: state the relationship instead of listing
        # the same functions twice (ground rule 21).
        callback_addresses = {row.get("address") for row in callback_rows}
        ctors_are_callbacks = bool(callback_rows) and all(
            func.get("address") in callback_addresses for func in ctors
        )
        if ctors_are_callbacks:
            block["initializers_are_tls_callbacks"] = True
        else:
            block["ctor_functions"] = [
                func.get("name") or func.get("address") for func in ctors
            ]

    if callback_rows or ctors:
        block["callback_count"] = len(callback_rows)
        block["initializer_count"] = len(ctors)
    return block
