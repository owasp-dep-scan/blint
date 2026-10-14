"""Kernel-adjacent user-mode surface (PE lane W5.4, plan 04/D).

The same reviewer question the driver lane answers, asked of a user-mode
image: how does this reach the kernel, another process, or a permanent
foothold? The blocks here are *facts* blint recovers; the judgements live
in the review rules (``review_usermode_win.yml``) and are tagged with the
ATT&CK and D3FEND techniques they evidence as the rules are written
(issues #1, #126), not in a later pass.

- ``com_registration``: CLSIDs and AppIDs the image references, from
  ``CLSID\\{...}`` / ``AppID\\{...}`` registry-path strings in the section
  bytes (both encodings). COM CLSIDs are a genuine identity signal and
  nothing in the checksec family had them. This is also the registry-
  string recovery the W5.6 host-plugin note points at: a later packet may
  re-point ``pe_host_plugins``' registration evidence at it (its own
  measured behaviour is pinned, so that re-point is not done here).
- ``rpc_interfaces`` (requires ``--disassemble``): interface UUIDs from
  the ``RPC_SERVER_INTERFACE`` structures an ``RpcServerRegisterIf*``
  call site receives (the GUID at offset +0x04, per rpcdce.h's
  ``Length``-then-``InterfaceId`` layout, plausibility-gated). A
  call-site-anchored read only: a UUID blint cannot tie to a registration
  call is not reported, and the recall limit is stated rather than
  widened by an unanchored .rdata GUID scan (GUIDs are everywhere).
- ``persistence_surfaces``: the documented autostart/extension registry
  and file surfaces the image names - Run keys, IFEO, AppInit/AppCert,
  WMI event consumers, scheduled-task XML, the Services control set -
  from section bytes, never the gated strings list (the W3.2 cap
  lesson). Presence of a string is a *reference*, not a behaviour; every
  rule consuming this block says so.
"""

from __future__ import annotations

import re
from typing import Any

import lief

from blint.lib.binary_common import is_string_bearing_section

# Listing bounds. Listing bounds only: every rule consuming these blocks
# fires on membership/counts, never on the tail, and the fixtures pin
# that the counts survive past the listing (rule 33).
COM_LISTING_LIMIT = 16
PERSISTENCE_LISTING_LIMIT = 4

_GUID_RE = rb"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}"

# Persistence markers (case-insensitive), each naming its surface.
PERSISTENCE_MARKERS: tuple[tuple[str, bytes], ...] = (
    ("run_key", b"currentversion\\run"),
    ("ifeo", b"image file execution options"),
    ("appinit", b"appinit_dlls"),
    ("appcert", b"appcertdlls"),
    ("wmi_event_consumer", b"activescripteventconsumer"),
    ("wmi_event_consumer", b"commandlinetemplate"),
    ("scheduled_task", b"<task xmlns="),
    ("services_control_set", b"system\\currentcontrolset\\services"),
)

# Strings the privilege reviews weigh (privilege_reviews.py), each naming
# what it evidences: the interactive desktop a SYSTEM payload targets, the
# LocalSystem SID, an INI file inside a directory standard users can write
# to, any INI file name, and hardware-ID templates of pluggable buses.
# Regular expressions match within one string (no NUL in between).
PRIVILEGE_MARKERS: tuple[tuple[str, bytes | re.Pattern], ...] = (
    ("interactive_desktop", b"winsta0\\default"),
    ("local_system_sid", b"s-1-5-18"),
    (
        "user_writable_config",
        re.compile(
            rb"(?:programdata|\\users\\public|%public%|%allusersprofile%)[^\x00]{0,160}?\.ini(?![a-z0-9])"
        ),
    ),
    ("ini_file_name", re.compile(rb"[a-z0-9_\-]{1,64}\.ini(?![a-z0-9])")),
    ("device_id_template", b"usb\\vid_"),
    ("device_id_template", b"hid\\vid_"),
    ("device_id_template", b"bthenum\\"),
)

# RPC: the MIDL-generated RPC_SERVER_INTERFACE carries Length (4 bytes)
# then the InterfaceId RPC_SYNTAX_IDENTIFIER (GUID at +0x04, version at
# +0x14). The call site's IfSpec argument points at it.
RPC_REGISTER_CALLEES: set[str] = {
    "rpcserverregisterif",
    "rpcserverregisterifex",
    "rpcserverregisterif2",
    "rpcserverregisterif3",
}
_RPC_GUID_OFFSET = 0x04


def _wide_view(content: bytes) -> bytes:
    """The UTF-16LE interpretation of a section (see pe_ioctl_depth)."""
    out = bytearray(len(content) // 2)
    for index in range(len(out)):
        out[index] = content[index * 2] if content[index * 2 + 1] == 0 else 0
    return bytes(out)


def _iter_section_views(parsed_obj: lief.PE.Binary):
    """Yield the ASCII and UTF-16LE views of every string-bearing section.

    The wide view is emitted at both parities: real UTF-16 strings are
    2-aligned in .rdata, but a fixture (or a packed section) may place one
    at an odd offset, and the pair-wise view would otherwise split it.
    """
    sections = getattr(parsed_obj, "sections", None)
    if not sections or isinstance(sections, lief.lief_errors):
        return
    for section in sections:
        if not is_string_bearing_section(section):
            continue
        try:
            content = bytes(section.content)
        except (AttributeError, TypeError, ValueError):
            continue
        if not content:
            continue
        yield content
        yield _wide_view(content)
        if len(content) > 1:
            yield _wide_view(content[1:])


def collect_com_registration(parsed_obj: lief.PE.Binary) -> dict[str, Any] | None:
    """The COM identity the image registers or references, or None.

    A CLSID reference means the image names a COM class - its own (an
    in-proc server ships its CLSID for the installer or for DllRegister)
    or someone else's (a consumer launching one). The block says which
    strings were seen; only the registry knows what is actually
    registered.
    """
    guid_re = re.compile(b"(?:CLSID|APPID)\\\\" + _GUID_RE, re.IGNORECASE)
    # De-duplicated *before* the listing bound, not after it. Counting at
    # the bound counted occurrences, not identities: a CLSID string past
    # the cap that appears three times in .rdata (the ordinary case - a
    # class is named by its registration table and by its call sites) added
    # three to the count, so 20 distinct CLSIDs reported clsid_count 28.
    # A count that is not a count of anything is worse than no count
    # (rule 11).
    seen: dict[bytes, set[str]] = {b"CLSID": set(), b"APPID": set()}
    for view in _iter_section_views(parsed_obj):
        for match in guid_re.finditer(view):
            raw = match.group(0)
            kind = raw.split(b"\\")[0].upper()
            if kind not in seen:
                continue
            try:
                seen[kind].add(raw.decode("latin-1"))
            except (UnicodeDecodeError, ValueError):
                continue
    clsids, appids = sorted(seen[b"CLSID"]), sorted(seen[b"APPID"])
    if not clsids and not appids:
        return None
    block: dict[str, Any] = {"source": "registry_path_strings"}
    truncated: dict[str, int] = {}
    for key, values in (("clsid", clsids), ("appid", appids)):
        if not values:
            continue
        block[f"{key}s"] = values[:COM_LISTING_LIMIT]
        block[f"{key}_count"] = len(values)
        if len(values) > COM_LISTING_LIMIT:
            truncated[f"{key}s"] = len(values) - COM_LISTING_LIMIT
    if truncated:
        block["listing_truncated"] = truncated
    return block


def collect_persistence_surfaces(parsed_obj: lief.PE.Binary) -> dict[str, Any] | None:
    """The autostart and extension surfaces the image references, or None.

    Counts are exact (every match, both encodings); the evidence listing
    is bounded. A reference is not a write: services.exe names the
    Services key in every image that manages a service, and a security
    product legitimately references IFEO - the rules consuming this block
    weigh the surface against the rest of the image.
    """
    counts, evidence = _scan_markers(parsed_obj, PERSISTENCE_MARKERS)
    if not counts:
        return None
    return {
        "surfaces": counts,
        "evidence": evidence,
        "source": "section_scan",
        "note": "a reference is not a write; weigh with the rest of the image",
    }


def collect_privilege_markers(parsed_obj: lief.PE.Binary) -> dict[str, Any] | None:
    """The privilege-relevant strings the image names, or None.

    Like the persistence surfaces, these are references read from section
    bytes in both encodings, not behaviour; the reviews that read them
    always pair a marker with imports that could act on it.
    """
    counts, evidence = _scan_markers(parsed_obj, PRIVILEGE_MARKERS)
    if not counts:
        return None
    return {"markers": counts, "evidence": evidence, "source": "section_scan"}


def _scan_markers(
    parsed_obj: lief.PE.Binary, markers: tuple[tuple[str, bytes | re.Pattern], ...]
) -> tuple[dict[str, int], dict[str, list[str]]]:
    """Exact per-name match counts and bounded evidence snippets."""
    counts: dict[str, int] = {}
    evidence: dict[str, list[str]] = {}
    for view in _iter_section_views(parsed_obj):
        lowered = view.lower()
        for surface, marker in markers:
            for start in _marker_offsets(lowered, marker):
                counts[surface] = counts.get(surface, 0) + 1
                seen = evidence.setdefault(surface, [])
                if len(seen) < PERSISTENCE_LISTING_LIMIT:
                    try:
                        snippet = view[start : start + 64].split(b"\x00")[0].decode("latin-1")
                    except (UnicodeDecodeError, ValueError):
                        snippet = surface
                    if snippet not in seen:
                        seen.append(snippet)
    return dict(sorted(counts.items())), {name: evidence[name] for name in sorted(counts)}


def _marker_offsets(lowered: bytes, marker: bytes | re.Pattern):
    """Start offsets of every occurrence of a substring or pattern marker.

    Each occurrence is walked, not just the first, so the evidence listing
    holds distinct snippets up to its bound and the count beside it is exact.
    """
    if isinstance(marker, re.Pattern):
        for match in marker.finditer(lowered):
            yield match.start()
        return
    start = lowered.find(marker)
    while start >= 0:
        yield start
        start = lowered.find(marker, start + len(marker))


def collect_amsi_references(parsed_obj: lief.PE.Binary) -> dict[str, Any] | None:
    """References to the AMSI entry point in the section bytes, or None.

    ``AmsiScanBuffer`` is not an export anything imports; it is resolved by
    name (GetProcAddress) or reached by hardcoded offset, so the string is
    the statically visible half. AMSI providers and AV products
    legitimately carry it - which is why this is a fact block for the
    review rule to weigh, not a finding.
    """
    marker = b"amsiscanbuffer"
    references = 0
    samples: list[str] = []
    seen: set[bytes] = set()
    for view in _iter_section_views(parsed_obj):
        lowered = view.lower()
        occurrences = lowered.count(marker)
        if not occurrences:
            continue
        references += occurrences
        start = lowered.find(marker)
        raw = view[start : start + 48]
        if raw not in seen and len(samples) < 4:
            seen.add(raw)
            try:
                samples.append(raw.split(b"\x00")[0].decode("latin-1"))
            except (UnicodeDecodeError, ValueError):
                samples.append(marker.decode())
    if not references:
        return None
    return {
        "references": references,
        "samples": samples,
        "source": "section_scan",
    }


def _guid_from_bytes(blob: bytes) -> str | None:
    """Format an RFC 4122 GUID from 16 raw bytes, or None if implausible.

    Implausible: all-zero, all-FF, or a Data1 of zero - every one of those
    is a coincidence of ordinary data far more often than an interface.
    """
    if blob == b"\x00" * 16 or blob == b"\xff" * 16 or blob[:4] == b"\x00\x00\x00\x00":
        return None
    d1, d2, d3 = int.from_bytes(blob[0:4], "little"), blob[4:6], blob[6:8]
    d4, d5 = blob[8:10], blob[10:16]
    return f"{{{d1:08X}-{d2.hex().upper()}-{d3.hex().upper()}-{d4.hex().upper()}-{d5.hex().upper()}}}"


def collect_rpc_interfaces(
    parsed_obj: lief.PE.Binary,
    call_site_entries: list[dict[str, Any]] | None,
) -> dict[str, Any] | None:
    """Interface UUIDs anchored to RpcServerRegisterIf* call sites, or None.

    Reads the GUID the registration call actually received: the IfSpec
    argument (position 0) points at an RPC_SERVER_INTERFACE whose
    InterfaceId GUID sits at +0x04. Every read is plausibility-gated; a
    pointer that cannot be read in this image contributes nothing. Recall
    is deliberately partial and the block says so - MIDL servers that
    register through other mechanisms are not seen.
    """
    if not call_site_entries:
        return None
    interfaces: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in call_site_entries or []:
        callee = str(entry.get("callee") or "").strip().lower()
        if "::" in callee:
            callee = callee.rsplit("::", 1)[1]
        callee = callee.lstrip("_")
        if callee not in RPC_REGISTER_CALLEES:
            continue
        if entry.get("argument") != 0:
            continue
        pointer = entry.get("value")
        if not isinstance(pointer, int) or pointer <= 0:
            continue
        try:
            blob = bytes(
                parsed_obj.get_content_from_virtual_address(pointer + _RPC_GUID_OFFSET, 16)
            )
        except (AttributeError, TypeError, ValueError, OverflowError):
            continue
        guid = _guid_from_bytes(blob)
        if not guid or guid in seen:
            continue
        seen.add(guid)
        item: dict[str, Any] = {"uuid": guid}
        functions = entry.get("functions") or []
        if functions:
            item["registration_functions"] = functions[:3]
        item["callee"] = str(entry.get("callee"))
        interfaces.append(item)
    if not interfaces:
        return None
    return {
        "interfaces": interfaces,
        "source": "rpc_register_call_sites",
        "note": "call-site anchored and plausibility gated; servers registering "
        "through other mechanisms are not seen (stated recall limit)",
    }
