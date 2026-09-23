"""The macOS host-plugin surface (lane M1.1, plan ``07``).

A binary a user runs and a binary macOS loads automatically into someone
else's process are different security objects, and the second kind is
described by the *bundle*, not the Mach-O: a ``.driver`` in
``/Library/Audio/Plug-Ins/HAL`` is loaded on every boot into a child of the
Core Audio driver service with no per-load prompt, and what it may do is
declared in its ``Info.plist`` — not observed in its code. This module is
the interpretation layer over facts the bundle walker already collects:
the bundle suffix, the ``Info.plist`` and the bundle's location. The kind
table is data (``blint/data/macos_host_plugin_kinds.yml``) with the
per-key declaration measurements this packet was scoped by recorded in its
header.

Design decisions the measurement forced:

- The documented network key is the unused one. Across the 12 Apple HAL
  plugins measured on this machine (macOS 15.8), ``AudioServerPlugIn_Network``
  appears zero times — including Apple's own network-audio plugins, which
  hand off to companion processes over Mach IPC — while
  ``AudioServerPlugIn_MachServices`` is on 7 of 12. So the network key is
  reported when declared and no rule fires on ``_MachServices``: the service
  names are recorded in the block, and that is the honest shipping form
  (the CHECK_SIGNER_MISMATCH shape from W2.4 — 152 hits on 178 benign
  files before re-scoping).
- A ``.plugin`` bundle names a host only under a ``CoreMediaIO/Plug-Ins/DAL``
  path. The suffix alone is ambiguous (UserEventPlugins, Internet plug-ins
  and others use it), so a ``.plugin`` anywhere else gets no ``host_plugin``
  block at all — the honest answer to "which host?" is "not determinable
  from this evidence", not a guess.
- Every declaration field is worded as a request the bundle made, never as
  behaviour blint observed: blint read a plist, it did not watch the plugin
  use anything. And nothing in a ``.dext``/``.systemextension`` block may be
  read as "this software cannot reach the network": the DriverKit process
  restriction does not bind the containing application, which keeps ordinary
  network access. The block either names the containing application or says
  nothing about network reach — there is no network field here at all.
- ``install_scope`` is derived from where the bundle was found and is
  absent when blint is looking at a bundle out of context: a ``.driver`` in
  a downloads folder has no install scope yet, and inventing one would be
  a verdict blint did not determine. For the same reason a
  ``.systemextension``/``.dext`` found inside an application gets no
  install scope — the copy that runs is the activated one under
  ``/Library/SystemExtensions``, which blint is not looking at.
"""

from __future__ import annotations

import os
import plistlib
import re

from blint.logger import LOG

# How many Mach-service / IOKit user-client names are listed per key. A
# listing bound, not a detection bound: no rule reads past the presence of
# the key (the one rule on declarations fires on the boolean network key),
# and the largest real list measured on this system is 16
# (AppleAVBAudio.driver's _IOKitUserClients), so 64 is 4x the largest
# measured. Pinned by a fixture that exceeds it (rule 33).
NAME_LIST_LIMIT = 64

# The Info.plist keys reported as declarations, with the block key each
# maps to. AudioServerPlugIn_LoadingConditions (5 of 12 measured) and
# AudioServerPlugIn_Create (0 of 12) govern when a plugin loads, not what
# it may do, and are deliberately not reported.
_AUDIO_DECLARATION_KEYS = {
    "AudioServerPlugIn_Network": "network",
    "AudioServerPlugIn_MachServices": "mach_services",
    "AudioServerPlugIn_IOKitUserClients": "iokit_user_clients",
}

_TABLE_CACHE: dict | None = None


def _kinds_table() -> dict:
    """The kind table, loaded once (data file with provenance)."""
    global _TABLE_CACHE
    if _TABLE_CACHE is None:
        import importlib.resources

        import yaml

        try:
            with importlib.resources.files("blint.data").joinpath(
                "macos_host_plugin_kinds.yml"
            ).open("r", encoding="utf-8") as handle:
                _TABLE_CACHE = yaml.safe_load(handle) or {}
        except (OSError, yaml.YAMLError):
            # An unreadable table determines nothing (rule 11): the block
            # is absent rather than half-derived from a partial file.
            _TABLE_CACHE = {}
    return _TABLE_CACHE


def install_scope(bundle_dir: str) -> str | None:
    """Where the bundle was found: ``system``, ``machine``, ``user`` or None.

    ``/System/...`` is Apple's own sealed volume, ``/Library/...`` an
    administrator install loaded for every user, ``~/Library/...`` a
    per-user install. Anywhere else — a downloads folder, an application
    bundle, a build tree — returns None: blint is looking at the bundle out
    of context and an install scope would be a verdict it did not
    determine. Comparisons are case-insensitive, as macOS volumes commonly
    are.
    """
    # A rooted spelling is used verbatim (separators normalized): on
    # Windows, os.path.abspath("/Library/...") would prepend a drive letter
    # and silently turn a macOS install location into an out-of-context one
    # (and since Python 3.13, ntpath.isabs() itself returns False for
    # drive-less rooted paths, so isabs cannot be the test). Rootedness is
    # therefore spelled out: a leading slash, or a Windows drive prefix. A
    # Windows drive path ("C:/Library/...") is verbatim too and matches no
    # macOS scope - honestly, because a location on a Windows volume is not
    # where macOS loads plugins from.
    replaced = bundle_dir.replace("\\", "/")
    if replaced.startswith("/") or re.match(r"^[A-Za-z]:", replaced):
        normalized = replaced.lower()
    else:
        normalized = os.path.abspath(bundle_dir).replace("\\", "/").lower()
    home = os.path.expanduser("~").replace("\\", "/").rstrip("/").lower()
    if normalized.startswith("/system/"):
        return "system"
    if normalized.startswith("/library/"):
        return "machine"
    if home and normalized.startswith(home + "/library/"):
        return "user"
    return None


def _plugin_install_scope(kind: str, bundle_dir: str) -> str | None:
    """The install scope a *plugin block* may carry, which is not always the
    scope of the directory it sits in.

    A ``.systemextension`` / ``.dext`` shipped inside an application is not
    installed anywhere: the copy macOS runs is the activated one staged under
    ``/Library/SystemExtensions/<UUID>/``, and this one is inert payload. The
    module docstring has said so since the packet was written, but the code
    asked :func:`install_scope` about the path alone — so a vendor extension
    under ``/Library/Application Support/Acme/Acme.app/...`` came back
    ``machine``, which is how ``CHECK_UNSIGNED_HOST_PLUGIN`` (high) reaches an
    ad-hoc-signed extension that is not installed at all and calls it
    "installed machine-wide, vouched for by nobody". The test is the
    structural one - is there an ``.app`` ancestor - not whether that app's
    identity could be read: an extension inside an application whose
    ``Info.plist`` blint cannot parse is still inert payload, and tying the
    scope to plist readability would make a high finding appear or vanish
    with an unrelated parse failure.
    """
    if kind in ("systemextension", "dext") and _application_ancestor(bundle_dir) is not None:
        return None
    return install_scope(bundle_dir)


def _application_ancestor(bundle_dir: str) -> str | None:
    """The nearest ``.app`` directory this bundle sits inside, or None."""
    current = os.path.abspath(bundle_dir)
    while True:
        parent = os.path.dirname(current)
        if parent == current:
            return None
        current = parent
        if current.endswith(".app"):
            return current


def _table_entry(kind: str, bundle_dir: str) -> tuple[str, dict] | None:
    """The ``(table_key, entry)`` for a bundle kind, or None.

    ``plugin`` bundles are DAL camera plugins only when found under a
    ``CoreMediaIO/Plug-Ins/DAL`` path; the marker check runs on the
    normalized bundle path so a scan of an extracted disk image or an
    unusual mount still classifies by location rather than by prefix.

    The marker itself comes from the entry's ``require_path_marker`` field.
    It was hardcoded here while the table also declared it, so the data file
    documented a rule the code did not read and editing the table would have
    changed nothing (rule 21: one place for a fact). An entry that declares
    a marker and does not match it names no host.
    """
    table = _kinds_table().get("kinds") or {}
    key = "dal_plugin" if kind == "plugin" else kind
    entry = table.get(key)
    if not isinstance(entry, dict):
        return None
    marker = entry.get("require_path_marker")
    if isinstance(marker, str) and marker:
        normalized = os.path.abspath(bundle_dir).replace("\\", "/").lower()
        if marker.lower() not in normalized:
            return None
    return key, entry


def containing_app(bundle_dir: str) -> str | None:
    """The bundle identifier of the ``.app`` this bundle ships inside, if any.

    DriverKit and system extensions are activated by their containing
    application, so that application's identity is the honest anchor for
    "who installed this and vouches for it". The activated copies under
    ``/Library/SystemExtensions/<UUID>/`` have no ``.app`` ancestor, and the
    function says nothing there — exactly the "name the containing app or
    say nothing" rule. The ancestor's ``Info.plist`` is read for its
    ``CFBundleIdentifier``; when that is missing the bundle *name* is used
    rather than a path, which would move whenever the app is reinstalled.
    """
    app = _application_ancestor(bundle_dir)
    if app is None:
        return None
    plist = _read_bundle_plist(app)
    if not isinstance(plist, dict):
        return None
    for key in ("CFBundleIdentifier", "CFBundleName"):
        value = plist.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _read_bundle_plist(bundle_dir: str) -> dict | None:
    """Read ``Contents/Info.plist`` of a bundle directory; None when absent."""
    plist_path = os.path.join(bundle_dir, "Contents", "Info.plist")
    if not os.path.isfile(plist_path):
        return None
    try:
        with open(plist_path, "rb") as fp:
            return plistlib.load(fp)
    except (OSError, ValueError, plistlib.InvalidFileException) as e:
        LOG.debug(f"Could not read Info.plist at {plist_path}: {e}")
        return None


def _declarations(plist: object, status: str) -> dict | None:
    """The ``declarations`` sub-block, or None when nothing was declared.

    Only keys present in the plist are reported — an absent key is no
    declaration, and the block never asserts a negative it did not read.
    A plist blint could not read yields no ``declarations`` key plus a
    ``declarations_status`` naming why, so "declared nothing" and "could
    not be read" stay distinguishable (rule 14). A non-dict plist root is
    legal XML that carries no declarations at all.
    """
    if status != "read":
        return None
    if not isinstance(plist, dict):
        return None
    declarations: dict = {}
    for plist_key, block_key in _AUDIO_DECLARATION_KEYS.items():
        if plist_key not in plist:
            continue
        value = plist[plist_key]
        if block_key == "network":
            # Reported exactly as declared; the rule fires only on a real
            # boolean true, so a forged non-boolean value cannot trip it.
            declarations[block_key] = value
            continue
        names, capped = _coerce_name_list(value)
        declarations[block_key] = names
        if capped:
            declarations[f"{block_key}_listing_capped"] = True
    return declarations or None


def _coerce_name_list(value: object) -> tuple[list[str], bool]:
    """Coerce a plist value into the bounded list of names the block lists.

    A real declaration is an array of strings; a scalar is kept as a
    one-element list (a plist a vendor hand-edited into a bare string still
    names the thing), and anything else is stringified element-wise rather
    than dropped — the listing must not silently lose a name a reader of
    the plist can see.
    """
    raw = value if isinstance(value, list) else [value]
    names = [item if isinstance(item, str) else str(item) for item in raw]
    capped = len(names) > NAME_LIST_LIMIT
    return names[:NAME_LIST_LIMIT], capped


def classify_host_plugin(
    bundle_dir: str, kind: str, plist: object, plist_status: str
) -> dict | None:
    """The ``host_plugin`` block for a bundle, or None when none is supported.

    Present only when the kind names a host — never an empty block that
    reads as "not a plugin". ``plist_status`` is one of ``read``,
    ``info_plist_absent``, ``info_plist_unreadable`` or
    ``info_plist_not_a_dict``; only ``read`` produces declarations, every
    other status is carried verbatim so the gap is visible beside the
    block instead of reading as "declared nothing".
    """
    matched = _table_entry(kind, bundle_dir)
    if matched is None:
        return None
    table_key, entry = matched
    block: dict = {"kind": table_key}
    for source_key, block_key in (
        ("title", "title"),
        ("host", "host"),
        ("host_privilege", "host_privilege"),
        ("activation", "activation"),
    ):
        if isinstance(entry.get(source_key), str) and entry[source_key]:
            block[block_key] = entry[source_key]
    if scope := _plugin_install_scope(kind, bundle_dir):
        block["install_scope"] = scope
    if entry.get("reads_audio_declarations"):
        declarations = _declarations(plist, plist_status)
        if declarations:
            block["declarations"] = declarations
        if plist_status != "read":
            block["declarations_status"] = plist_status
    if kind in ("systemextension", "dext"):
        if app := containing_app(bundle_dir):
            block["containing_app"] = app
    return block
