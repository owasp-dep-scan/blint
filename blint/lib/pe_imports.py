# SPDX-License-Identifier: Apache-2.0
"""PE import depth: delay-load, ordinal resolution, apiset resolution (W1.2).

The import table answers "which DLLs does this image need and which functions
does it call". Three facts make that answer wrong or blind on modern Windows:

- **Delay-load imports** live in a second table the loader resolves on first
  use. They are real dependencies and a classic evasion surface precisely
  because the common tools read only the first table, so they are parsed into
  ``delay_imports[]`` in the same shape as ``imports`` and never merged with
  it — the distinction is the signal (plan 01/A.6).
- **Ordinal-only imports** carry a number instead of a name. For the DLLs
  where ordinals are stable and common (``ws2_32``, ``mpr``, ``oleaut32``,
  ``shlwapi``, ``netapi32``, ``wsock32``) the number is resolved through the
  generated ``blint/data/pe_ordinals.yml`` snapshot; entries resolved this way
  carry ``resolution: "ordinal_table"`` and the ones that are not stay
  ordinals with ``resolution: "unresolved"`` — never conflated (rule 14).
- **API sets** (``api-ms-win-core-*``) are loader-virtual DLLs: the schema in
  ``apisetschema.dll`` binds each one to the host DLL that is actually mapped.
  Every dependency list, dependency-graph check and SBOM ``dependsOn`` is
  wrong on modern Windows without that resolution, so imports record the host
  through the generated ``blint/data/pe_apisets.yml`` snapshot and keep the
  original name in ``apiset`` — the snapshot records the Windows build it was
  generated from.

Both tables are generated data with a provenance header and a regenerator in
``tests/scripts/``; nothing is fetched at runtime. Ground rule 28 applies:
table keys are the on-disk names and numbers, never a dependency's rendering.
"""

import contextlib
import importlib.resources

import lief
import yaml

from blint.lib.binary_common import ADDRESS_FMT
from blint.lib.similarity import compute_import_hash
from blint.lib.utils import demangle_symbolic_name
from blint.logger import LOG


def _dll_key(name: str) -> str:
    """Data-directory DLL names are case-insensitive on Windows; both cases
    occur in real images ("WS2_32.dll", "wsock32.dll"), so every table lookup
    goes through one lowercasing helper."""
    return (name or "").strip().lower()


# IMAGE_ORDINAL_FLAG for a 64-bit import; 32-bit images use 0x80000000. The
# flag marks an import-by-ordinal slot; the ordinal is the low 16 bits.
ORDINAL_FLAG_PE64 = 0x8000000000000000
ORDINAL_FLAG_PE32 = 0x80000000

# Tag distinguishing how a dependency list entry was learned. A DLL whose
# entries are all ordinal or which is reached only through a delay-load
# directory was previously invisible to blint's dependency list; these tags
# keep the evidence source explicit beside the plain ``NEEDED`` entry.
TAG_DELAYLOAD = "DELAYLOAD"
TAG_FORWARDER = "FORWARDER"
# W3.2: a managed assembly's P/Invoke scopes (DllImport / ImplMap). Unlike a
# delay-load entry a P/Invoke module is mapped at first call, not at image
# load — which is exactly why it never appears in the import table — so it
# is a declared dependency of its own kind, not a loader-level NEEDED one.
TAG_PINVOKE = "PINVOKE"

# Resolution vocabulary for an entry's function name (plan 01/A.6: resolved
# ordinal-table entries and unresolved ordinals are distinct outcomes).
RESOLUTION_ORDINAL_TABLE = "ordinal_table"
RESOLUTION_UNRESOLVED = "unresolved"

# Samples recorded in the resolution summary stay bounded; the counts remain
# exact so a summary can never understate what fell back.
_RESOLUTION_SAMPLE_CAP = 16

_ORDINAL_TABLES_CACHE: dict | None = None
_APISET_CACHE: dict | None = None


def _load_yaml_table(filename: str) -> dict:
    """Load one generated data table from ``blint/data``."""
    try:
        with importlib.resources.files("blint.data").joinpath(filename).open(
            "r", encoding="utf-8"
        ) as handle:
            return yaml.safe_load(handle) or {}
    except (OSError, yaml.YAMLError) as exc:
        LOG.debug(f"Unable to load {filename}: {exc}")
        return {}


def _ordinal_tables() -> dict:
    """Load (once) the generated ordinal map."""
    global _ORDINAL_TABLES_CACHE
    if _ORDINAL_TABLES_CACHE is None:
        _ORDINAL_TABLES_CACHE = _load_yaml_table("pe_ordinals.yml")
    return _ORDINAL_TABLES_CACHE


def _apiset_table() -> dict:
    """Load (once) the generated apiset snapshot."""
    global _APISET_CACHE
    if _APISET_CACHE is None:
        _APISET_CACHE = _load_yaml_table("pe_apisets.yml")
    return _APISET_CACHE


def ordinal_table_build() -> str | None:
    """The Windows build the ordinal snapshot was generated from, if known."""
    build = _ordinal_tables().get("source_build")
    return str(build) if build else None


def apiset_schema_build() -> str | None:
    """The Windows build the apiset snapshot came from, if known."""
    build = _apiset_table().get("source_build")
    return str(build) if build else None


def is_apiset(dll_name: str) -> bool:
    """True when the DLL name is an API set or ext-ms contract name.

    The contract namespaces are fixed by the loader (``api-ms-*``,
    ``ext-ms-*``), not by the snapshot, so a name newer than the snapshot
    still reads as an apiset — it resolves through :func:`apiset_host` only
    when the snapshot covers it.
    """
    lowered = _dll_key(dll_name)
    return lowered.startswith(("api-ms-", "ext-ms-"))


def apiset_host(dll_name: str) -> str | None:
    """The host DLL an API set name maps to, or None when unresolved.

    The snapshot keys are stored without the ``.dll`` extension and
    lowercased, mirroring how the loader folds contract names.
    """
    if not is_apiset(dll_name):
        return None
    table = _apiset_table().get("api_sets") or {}
    stem = _dll_key(dll_name).removesuffix(".dll")
    host = table.get(stem)
    if not host:
        return None
    host = str(host)
    # Hosts are recorded with their extension; tolerate a bare module name
    # in case a future schema source stops including it.
    return host if host.endswith(".dll") else f"{host}.dll"


def ordinal_name(dll_name: str, ordinal: int) -> str | None:
    """The export name for an ordinal of a covered DLL, or None.

    Only the DLLs the snapshot covers answer here: ordinal assignments are
    per-build facts, so guessing beyond the snapshot would manufacture names
    the loader never promised.
    """
    tables = _ordinal_tables().get("ordinals") or {}
    dll_table = tables.get(_dll_key(dll_name))
    if not dll_table:
        return None
    name = dll_table.get(int(ordinal))
    return str(name) if name else None


def _ordinal_flag(pe32: bool) -> int:
    return ORDINAL_FLAG_PE32 if pe32 else ORDINAL_FLAG_PE64


def _is_ordinal_entry(entry, pe32: bool) -> bool:
    """True when the entry imports by ordinal.

    LIEF 1.0 exposes ``is_ordinal`` directly; the flag check is kept as the
    source of truth because it is the format fact (IMAGE_ORDINAL_FLAG) and
    works even if a future entry object stops mirroring it.
    """
    with contextlib.suppress(AttributeError, TypeError, ValueError):
        if entry.is_ordinal:
            return True
    try:
        return bool(int(entry.data) & _ordinal_flag(pe32))
    except (AttributeError, TypeError, ValueError):
        return False


def _entry_ordinal(entry, pe32: bool) -> int | None:
    """The import ordinal for an ordinal entry, from the format fact.

    The ordinal is the low 16 bits of the import slot value, which is how
    ``dumpbin /imports`` prints it (``Ordinal 54`` for a slot holding
    ``0x8000...0036``). LIEF's own ``ordinal`` attribute agrees; the mask
    stays the fallback so the number remains the spec's, not a library's.
    """
    with contextlib.suppress(AttributeError, TypeError, ValueError):
        ordinal = int(entry.ordinal)
        if ordinal:
            return ordinal
    try:
        return int(entry.data) & 0xFFFF
    except (AttributeError, TypeError, ValueError):
        return None


def _resolve_function_name(raw_dll: str, entry, pe32: bool) -> dict:
    """Resolve one import's function name, recording how it was resolved.

    Named imports demangle and stay as they are. Ordinal imports resolve
    through the snapshot when the DLL is covered — ``resolution:
    "ordinal_table"`` — and stay ordinals otherwise, ``resolution:
    "unresolved"``; both carry the ordinal itself.
    """
    info: dict = {}
    if not _is_ordinal_entry(entry, pe32):
        name = entry.name
        if name:
            info["short_name"] = demangle_symbolic_name(name)
        return info
    ordinal = _entry_ordinal(entry, pe32)
    if ordinal is None:
        return {}
    info["ordinal"] = ordinal
    resolved = ordinal_name(raw_dll, ordinal)
    if resolved:
        info["short_name"] = demangle_symbolic_name(resolved)
        info["resolution"] = RESOLUTION_ORDINAL_TABLE
    else:
        info["short_name"] = f"#{ordinal}"
        info["resolution"] = RESOLUTION_UNRESOLVED
    return info


def _resolve_dll(dll_name: str) -> tuple[str, str | None]:
    """Resolve one DLL name through the apiset snapshot.

    Returns the name the dependency graph should carry — the host DLL when
    the snapshot covers the contract, the original name otherwise — plus the
    original contract name when a resolution happened.
    """
    host = apiset_host(dll_name)
    if host and host != _dll_key(dll_name):
        return host, dll_name
    return dll_name, None


def _parse_import_table(imports, imagebase: int, pe32: bool) -> tuple[list[dict], list[dict]]:
    """Parse one import directory (regular or delay-load) into blint's shape.

    Per-entry shape matches the historical ``imports`` entry (name, short_name,
    address, iat_value, hint, iat_address) with the additive resolution fields.
    The DLL list merges per DLL name, first-seen order preserved (this list
    seeds the SBOM's dependency refs, so iteration order must not vary with
    PYTHONHASHSEED), and records the api sets a host stands in for.
    """
    entries_list: list[dict] = []
    dlls: dict[str, dict] = {}
    if not imports:
        return entries_list, []
    for import_ in imports:
        try:
            entries = import_.entries
        except AttributeError:
            break
        if not entries or isinstance(entries, lief.lief_errors):
            continue
        raw_dll = import_.name
        dll_for_graph, resolved_from = _resolve_dll(raw_dll)
        for entry in entries:
            try:
                resolved = _resolve_function_name(raw_dll, entry, pe32)
                if not resolved.get("short_name") and not resolved.get("ordinal"):
                    # Neither a name nor an ordinal slot: nothing to record.
                    continue
                row = {
                    "name": f"{dll_for_graph}::{resolved['short_name']}",
                    "short_name": resolved["short_name"],
                    "address": ADDRESS_FMT.format(entry.data).strip(),
                    "iat_value": entry.iat_value,
                    "hint": getattr(entry, "hint", 0) or 0,
                }
                if hasattr(entry, "iat_address"):
                    row["iat_address"] = entry.iat_address + imagebase
                if resolved_from:
                    row["apiset"] = resolved_from
                if "ordinal" in resolved:
                    row["ordinal"] = resolved["ordinal"]
                if "resolution" in resolved:
                    row["resolution"] = resolved["resolution"]
                entries_list.append(row)
                dll_row = dlls.setdefault(dll_for_graph, {"apisets": []})
                if resolved_from and resolved_from not in dll_row["apisets"]:
                    dll_row["apisets"].append(resolved_from)
            except (AttributeError, TypeError, ValueError):
                continue
    dll_list = []
    for name, row in dlls.items():
        entry = {"name": name, "tag": "NEEDED"}
        if row["apisets"]:
            entry["apisets"] = row["apisets"]
        dll_list.append(entry)
    return entries_list, dll_list


def parse_pe_imports(imports, imagebase: int, pe32: bool = False) -> tuple[list[dict], list[dict]]:
    """
    Parses the regular import table into imported symbols and a DLL list.

    Args:
        imports: The import objects to parse.
        imagebase: The image base, added to entry IAT addresses.
        pe32: True for a PE32 image, whose ordinal flag is the 32-bit one.

    Returns:
        tuple: (imports_list, dll_list) — the DLL list carries the apiset
        hosts the snapshot resolved, with the original contract names under
        ``apisets``.
    """
    if not imports or isinstance(imports, lief.lief_errors):
        return [], []
    return _parse_import_table(imports, imagebase, pe32)


def parse_pe_delay_imports(
    delay_imports, imagebase: int, pe32: bool = False
) -> tuple[list[dict], list[dict]]:
    """
    Parses the delay-load import table (01/A.6).

    Same shape as :func:`parse_pe_imports`' result, tagged ``DELAYLOAD`` in
    its DLL list so the SBOM and dependency consumers can keep the two tables
    apart — the distinction between the tables is the signal, so they are
    never merged.

    Returns:
        tuple: (delay_imports_list, delay_dll_list)
    """
    if not delay_imports:
        return [], []
    entries_list, dll_list = _parse_import_table(delay_imports, imagebase, pe32)
    for row in dll_list:
        row["tag"] = TAG_DELAYLOAD
    return entries_list, dll_list


def summarize_resolution(
    imports_list: list[dict], delay_list: list[dict], dll_lists: list[list[dict]]
) -> dict:
    """Summarize how completely this image's imports resolved (01/A.6).

    Facts only: how many ordinal imports the snapshot named and how many
    stayed ordinals, and per-DLL apiset coverage — a DLL entry whose name is
    the host it resolved to counts resolved (the original contract names ride
    in its ``apisets`` list), an apiset name that fell back to itself counts
    unresolved. The counts are exact; samples are capped and say so.
    """
    summary: dict = {
        "ordinals_resolved": 0,
        "ordinals_unresolved": 0,
        "apisets_resolved": 0,
        "apisets_unresolved": 0,
    }
    unresolved_samples: list[str] = []
    for row in imports_list + delay_list:
        resolution = row.get("resolution")
        if resolution == RESOLUTION_ORDINAL_TABLE:
            summary["ordinals_resolved"] += 1
        elif resolution == RESOLUTION_UNRESOLVED:
            summary["ordinals_unresolved"] += 1
            if len(unresolved_samples) < _RESOLUTION_SAMPLE_CAP:
                unresolved_samples.append(row.get("name") or "")
    unresolved_apisets: list[str] = []
    for dll_list in dll_lists:
        for entry in dll_list:
            name = entry.get("name") or ""
            for apiset in entry.get("apisets") or []:
                summary["apisets_resolved"] += 1
            if is_apiset(name) and "apisets" not in entry:
                summary["apisets_unresolved"] += 1
                if len(unresolved_apisets) < _RESOLUTION_SAMPLE_CAP:
                    unresolved_apisets.append(name)
    if unresolved_samples:
        summary["ordinals_unresolved_samples"] = unresolved_samples
        if len(unresolved_samples) == _RESOLUTION_SAMPLE_CAP:
            summary["ordinals_unresolved_capped"] = True
    if unresolved_apisets:
        summary["apisets_unresolved_samples"] = unresolved_apisets
    return summary


def delay_import_hash(delay_imports_list: list[dict]) -> str:
    """Import hash over the delay-load table only.

    Same normalization as the cross-format ``import_hash`` so the two hashes
    are comparable; evasive loading hides in delay tables precisely because
    the common imphash implementations never see them (verification log V6).
    """
    names = [
        row.get("name")
        for row in delay_imports_list or []
        if isinstance(row, dict) and row.get("name")
    ]
    return compute_import_hash(names)


def forwarder_target(library: str, function: str) -> str:
    """Render an export forwarder target the way dumpbin prints it.

    ``NTDLL`` + ``RtlAllocHeap`` becomes ``NTDLL.RtlAllocHeap`` — the raw
    strings from the export table, not a normalization, so the target reads
    exactly as the image states it.
    """
    return f"{library}.{function}" if library and function else ""


def normalize_forwarder_library(library: str) -> str:
    """The DLL name a forwarder target names, in dependency-list form.

    Forwarder strings use the target module's export name (``NTDLL``,
    ``WS2_32``), which may lack the extension a dependency list carries.
    """
    lowered = _dll_key(library)
    if not lowered:
        return ""
    return lowered if lowered.endswith(".dll") else f"{lowered}.dll"
