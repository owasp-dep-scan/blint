"""macOS bundle (``.app`` / ``.framework`` / ``.dSYM``) handling for blint.

A macOS bundle is a directory, not an archive: the main Mach-O lives under
``Contents/MacOS`` (named by ``CFBundleExecutable``), embedded frameworks
under ``Contents/Frameworks``, app extensions under ``Contents/PlugIns`` and
XPC services under ``Contents/XPCServices``. ``.framework`` bundles carry the
executable at their root (or under ``Versions/``), and a ``.dSYM`` wraps the
DWARF slice(s) under ``Contents/Resources/DWARF``. This module enumerates the
Mach-O binaries to analyse and exposes the bundle context so each binary's
report can be enriched.

The plist reading, privacy-manifest aggregation and report enrichment are
shared with the ``.ipa`` path in :mod:`blint.lib.ios` — two bundle walkers
reading the same vocabulary would drift.
"""

import os
import plistlib

from blint.lib.ios import bundle_info_from_plist, read_privacy_manifest
from blint.lib.utils import is_exe
from blint.logger import LOG

# Bundle directory suffixes, matched case-insensitively (macOS volumes are
# commonly case-insensitive, so ``Foo.app`` and ``Foo.APP`` are the same shape).
MACOS_BUNDLE_SUFFIXES: tuple[str, ...] = (".app", ".framework", ".dsym", ".xpc", ".appex")

_KIND_BY_SUFFIX = {
    ".app": "app",
    ".appex": "appex",
    ".xpc": "xpc",
    ".framework": "framework",
    ".dsym": "dsym",
}

# Per-bundle-kind locations of Info.plist, tried in order. The root-level
# entries accept the iOS layout (no Contents/), which extracted .ipa payloads
# and some cross-platform tools produce, so one walker reads both.
_INFO_PLIST_LOCATIONS: dict[str, tuple[str, ...]] = {
    "app": ("Contents/Info.plist", "Info.plist"),
    "appex": ("Contents/Info.plist", "Info.plist"),
    "xpc": ("Contents/Info.plist", "Info.plist"),
    "framework": (
        "Resources/Info.plist",
        "Versions/A/Resources/Info.plist",
        "Versions/Current/Resources/Info.plist",
        "Info.plist",
    ),
    "dsym": ("Contents/Info.plist",),
}

# Directories that may hold embedded components, per kind. Missing directories
# are skipped, so the union of both layouts is listed rather than probed.
# ``Versions/Current/...`` and ``Versions/A/...`` resolve to the same files on
# every modern framework; ``_add_binary`` deduplicates by real path, so the
# aliasing costs one stat per entry, not a duplicate binary.
_EMBEDDED_DIRS: dict[str, tuple[str, ...]] = {
    "app": (
        "Contents/Frameworks",
        "Contents/PlugIns",
        "Contents/XPCServices",
        "Contents/Library",
        "Frameworks",
        "PlugIns",
        "XPCServices",
    ),
    "appex": ("Contents/Frameworks", "Frameworks"),
    "xpc": ("Contents/Frameworks", "Frameworks"),
    "framework": ("Frameworks", "Versions/A/Frameworks", "Versions/Current/Frameworks"),
    "dsym": (),
}

# The role an embedded bundle's executable plays, by the bundle's kind. The
# role names what the component is for; ``main`` is reserved for the
# top-level bundle's own executable.
_SUB_BUNDLE_ROLES = {
    "framework": "framework",
    "app": "plugin",
    "appex": "plugin",
    "xpc": "xpc",
}

# Directories inside a bundle's code tree that hold no executables by
# Apple's conventions and are pruned from the tool sweep.
_NON_CODE_DIRS = frozenset({"Resources", "Headers", "Modules", "_CodeSignature", "Documentation"})

# Bounds the walk so pointing blint at /Applications or an .xcarchive cannot
# turn one bundle into an unbounded scan. When the cap trips, the result says
# so (``binary_walk_truncated``) instead of silently omitting the rest.
_MAX_BINARIES = 2000


def is_macos_bundle(path) -> bool:
    """Return True when the path is a macOS bundle directory."""
    return (
        isinstance(path, str)
        and os.path.isdir(path)
        and os.path.basename(path.rstrip(os.sep)).lower().endswith(MACOS_BUNDLE_SUFFIXES)
    )


def bundle_kind(path: str) -> str:
    """Classify a bundle directory: app, appex, xpc, framework or dsym."""
    name = os.path.basename(path.rstrip(os.sep)).lower()
    for suffix, kind in _KIND_BY_SUFFIX.items():
        if name.endswith(suffix):
            return kind
    return "app"


def collect_macos_bundle_detailed(bundle_dir: str) -> tuple[dict | None, str | None]:
    """Collect the Mach-O binaries of a macOS bundle directory.

    Returns ``(collection, None)`` where ``collection`` carries
    ``bundle_info``, ``binaries`` (each with ``path``/``role``/``bundle_path``
    and, when known, the member's own bundle identity), ``kind`` and the
    ``bundle_dir``; or ``(None, reason)`` with a short machine-readable skip
    reason (``not_a_bundle``, ``no_binaries``). There is no extraction, so
    unlike the ``.ipa`` collector the caller cleans nothing up.

    Nested bundles are walked recursively — an embedded framework's
    frameworks, and a PlugIns app extension's XPC services, all belong to the
    scan. Every member entry is relative to the top-level bundle so reports
    and SBOM components identify binaries by their place in the bundle.
    """
    if not is_macos_bundle(bundle_dir):
        return None, "not_a_bundle"
    kind = bundle_kind(bundle_dir)
    binaries: list[dict] = []
    bundle_info = _bundle_info(bundle_dir, kind)
    _walk_bundle(bundle_dir, kind, bundle_info, binaries, root=True)
    # Members of the top-level bundle (its own executable, a dSYM's DWARF
    # binaries) inherit the bundle identity; embedded sub-bundles have already
    # stamped their own, which setdefault leaves alone.
    for entry in binaries:
        for key in ("bundle_identifier", "bundle_version", "bundle_name"):
            if bundle_info.get(key):
                entry.setdefault(key, bundle_info[key])
    if len(binaries) >= _MAX_BINARIES:
        bundle_info["binary_walk_truncated"] = True
        LOG.warning(
            f"Bundle walk hit the {_MAX_BINARIES}-binary cap in {bundle_dir}; "
            "remaining embedded binaries were not collected"
        )
    if not binaries:
        LOG.warning(f"No Mach-O binaries found in macOS bundle {bundle_dir}; skipping")
        return None, "no_binaries"
    return {
        "bundle_dir": bundle_dir,
        "kind": kind,
        "bundle_info": bundle_info,
        "binaries": binaries,
    }, None


def collect_macos_bundle(bundle_dir: str) -> dict | None:
    """Like :func:`collect_macos_bundle_detailed`, but only the collection."""
    return collect_macos_bundle_detailed(bundle_dir)[0]


def _bundle_info(bundle_dir: str, kind: str) -> dict:
    """Read the bundle's Info.plist from whichever layout it uses."""
    info: dict = {"bundle_dir": os.path.basename(bundle_dir.rstrip(os.sep))}
    for relative in _INFO_PLIST_LOCATIONS.get(kind, ()):
        plist_path = os.path.join(bundle_dir, *relative.split("/"))
        if not os.path.isfile(plist_path):
            continue
        try:
            with open(plist_path, "rb") as fp:
                plist = plistlib.load(fp)
        except (OSError, ValueError, plistlib.InvalidFileException) as e:
            LOG.debug(f"Could not read Info.plist at {plist_path}: {e}")
            break
        info.update(bundle_info_from_plist(plist))
        break
    # Frameworks, XPC services and dSYMs often ship no CFBundleIdentifier;
    # the bundle name is the identity both Apple tooling and users know them
    # by, and the SBOM needs one either way.
    if kind == "dsym":
        info.setdefault(
            "bundle_name", os.path.basename(bundle_dir.rstrip(os.sep)).removesuffix(".dSYM")
        )
    else:
        info.setdefault("bundle_name", os.path.basename(bundle_dir.rstrip(os.sep)))
    if manifest := read_privacy_manifest(bundle_dir, _EMBEDDED_DIRS.get(kind, ())):
        info["privacy_manifest"] = manifest
    return info


def _add_binary(binaries: list[dict], path: str, role: str, bundle_dir: str) -> bool:
    """Append one binary unless the walk is capped or it was already collected.

    Deduplication is by real path: a framework's ``Versions/Current`` symlink
    chain and its ``Versions/A`` real directory reach the same Mach-O through
    two names, and both would otherwise be analysed (and reported) twice.
    """
    if len(binaries) >= _MAX_BINARIES:
        return False
    if not (os.path.isfile(path) and is_exe(path)):
        return False
    real = os.path.realpath(path)
    if any(os.path.realpath(existing["path"]) == real for existing in binaries):
        return False
    binaries.append(
        {
            "path": path,
            "role": role,
            "bundle_path": os.path.relpath(path, bundle_dir).replace(os.sep, "/"),
        }
    )
    return True


def _walk_bundle(
    bundle_dir: str, kind: str, bundle_info: dict, binaries: list[dict], root: bool = False
) -> None:
    """Append the binaries of one bundle (and its embedded bundles).

    The top-level bundle's executable gets the ``main`` role; embedded
    components are named by what they are (framework, plugin, xpc, dylib,
    helper, debug). Loose Mach-O files that are neither a recognised bundle
    nor a ``.dylib`` (a helper tool, say) are not collected — adding them
    would turn every stray file in ``PlugIns`` into a unit.
    """
    if kind == "dsym":
        dwarf_dir = os.path.join(bundle_dir, "Contents", "Resources", "DWARF")
        if os.path.isdir(dwarf_dir):
            for entry in sorted(os.listdir(dwarf_dir)):
                _add_binary(binaries, os.path.join(dwarf_dir, entry), "debug", bundle_dir)
        return

    executable_name = bundle_info.get("executable") or os.path.basename(bundle_dir.rstrip(os.sep))
    if kind == "framework":
        stem = executable_name.removesuffix(".framework")
        candidates = (
            # The root-level spelling is the user-visible one on a real
            # framework (a symlink into Versions); ``Versions/A`` before
            # ``Versions/Current`` so an aliased spelling wins over an alias
            # of an alias.
            os.path.join(bundle_dir, stem),
            os.path.join(bundle_dir, "Versions", "A", stem),
            os.path.join(bundle_dir, "Versions", "Current", stem),
        )
        for candidate in candidates:
            role = "main" if root else _SUB_BUNDLE_ROLES.get(kind, "plugin")
            if _add_binary(binaries, candidate, role, bundle_dir):
                break
    else:
        macos_dir = os.path.join(bundle_dir, "Contents", "MacOS")
        candidates = [
            os.path.join(bundle_dir, "Contents", "MacOS", executable_name),
            # iOS-style layout: the executable sits at the bundle root.
            os.path.join(bundle_dir, executable_name),
        ]
        if os.path.isdir(macos_dir) and not any(os.path.isfile(c) for c in candidates):
            # No CFBundleExecutable match: try every Mach-O in MacOS/,
            # deterministically by name.
            candidates += [
                os.path.join(macos_dir, entry) for entry in sorted(os.listdir(macos_dir))
            ]
        for candidate in candidates:
            role = "main" if root else _SUB_BUNDLE_ROLES.get(kind, "plugin")
            if _add_binary(binaries, candidate, role, bundle_dir):
                break

    for relative in _EMBEDDED_DIRS.get(kind, ()):
        embedded_dir = os.path.join(bundle_dir, *relative.split("/"))
        if not os.path.isdir(embedded_dir):
            continue
        for entry in sorted(os.listdir(embedded_dir)):
            full = os.path.join(embedded_dir, entry)
            if os.path.isdir(full) and is_macos_bundle(full):
                _walk_embedded_bundle(full, binaries, bundle_dir)
            elif entry.endswith(".dylib") and os.path.isfile(full):
                _add_binary(binaries, full, "dylib", bundle_dir)
            elif (
                os.path.isfile(full)
                and relative.endswith("Library")
                # Privileged helpers and login items live under
                # Contents/Library (SMJobBless, SMAppService): the loose
                # executables there run with elevated or persistent
                # rights, which makes them audit surface.
                and is_exe(full)
            ):
                _add_binary(binaries, full, "helper", bundle_dir)

    # Auxiliary executables shipped beside the main binary (a privileged
    # helper is not one of these; those live under Contents/Library above) —
    # OrbStack, for instance, keeps pstramp, sparkle-cli and an xbin/
    # directory of CLI tools in Contents/MacOS, and Sparkle ships its
    # Autoupdate binary inside the framework's Versions directory. They are
    # real Mach-O files that a plain directory scan would have analysed, so
    # a bundle scan must not lose them; anything already collected (the
    # main executable, sub-bundle members) is skipped by real-path dedup.
    # Walked after the sub-bundles so a nested bundle's executable keeps
    # its bundle role and identity rather than being claimed as a tool.
    _sweep_tool_binaries(bundle_dir, kind, binaries, bundle_dir)


def _sweep_tool_binaries(start_dir: str, kind: str, binaries: list[dict], top_dir: str) -> None:
    """Collect remaining Mach-O executables under a bundle's code directories.

    Recursive for ``Contents/MacOS`` (tools live in subdirectories there) and
    for a framework's ``Versions``; the top-level directory itself is scanned
    one level deep only — ``Resources`` and friends are deliberately out of
    scope, since a bundle's resource tree is not code and walking it would
    pull VM images and asset blobs into every scan.
    """
    sweep_roots = []
    if kind == "framework":
        versions_dir = os.path.join(start_dir, "Versions")
        if os.path.isdir(versions_dir):
            sweep_roots.append((versions_dir, True))
    else:
        sweep_roots.append((os.path.join(start_dir, "Contents", "MacOS"), True))
        # iOS-style layout keeps the code at the bundle root.
        sweep_roots.append((start_dir, False))
    for sweep_root, recurse in sweep_roots:
        if not os.path.isdir(sweep_root):
            continue

        def _walk(walk_root: str, recursive: bool) -> None:
            for root, dirs, files in os.walk(walk_root):
                # Deterministic traversal. A nested bundle is walked as a
                # bundle (roles, identity) rather than swept as loose tools,
                # so it is removed from the descent here.
                dirs[:] = sorted(dirs)
                for d in list(dirs):
                    full = os.path.join(root, d)
                    if is_macos_bundle(full):
                        dirs.remove(d)
                        _walk_embedded_bundle(full, binaries, top_dir)
                    elif d in _NON_CODE_DIRS:
                        # A framework's Versions tree carries its resource
                        # bundle, headers and module maps beside its code;
                        # .nib/.strings archive files are binary content and
                        # would pass the executable sniff, so they are pruned
                        # by name rather than collected as tools.
                        dirs.remove(d)
                for entry in sorted(files):
                    _add_binary(binaries, os.path.join(root, entry), "tool", top_dir)
                if not recursive:
                    break

        _walk(sweep_root, recurse)


def _walk_embedded_bundle(bundle_dir: str, binaries: list[dict], top_dir: str) -> None:
    """Walk one embedded bundle, attributing its binaries to the top bundle."""
    kind = bundle_kind(bundle_dir)
    embedded_info = _bundle_info(bundle_dir, kind)
    before = len(binaries)
    _walk_bundle(bundle_dir, kind, embedded_info, binaries, root=False)
    # Entries produced by this sub-bundle carry its identity (real product
    # name and version, not the host app's) and a bundle_path relative to the
    # top-level bundle.
    for entry in binaries[before:]:
        for key in ("bundle_identifier", "bundle_version", "bundle_name"):
            if embedded_info.get(key):
                entry.setdefault(key, embedded_info[key])
        entry["bundle_path"] = os.path.relpath(entry["path"], top_dir).replace(os.sep, "/")


def find_macos_bundles(src: str) -> list[str]:
    """Discover top-level macOS bundle directories under ``src``.

    A bundle found inside another bundle is not reported — the walker above
    descends into embedded bundles itself, so reporting both would analyse
    every member twice. ``src`` itself may be a bundle.
    """
    if is_macos_bundle(src):
        return [os.path.abspath(src)]
    bundles: list[str] = []
    for root, dirs, _files in os.walk(src):
        kept = []
        for d in sorted(dirs):
            full = os.path.join(root, d)
            if full.lower().endswith(MACOS_BUNDLE_SUFFIXES):
                bundles.append(os.path.abspath(full))
            else:
                kept.append(d)
        # Do not descend into bundles; anything inside belongs to the bundle.
        dirs[:] = kept
    return bundles


def path_inside_any_bundle(file_path: str, bundle_dirs: list[str]) -> bool:
    """True when ``file_path`` lives inside one of the discovered bundles.

    Used to keep loose executables that directory discovery finds inside a
    bundle from also being analysed as top-level units beside the bundle
    unit that already covers them. Both sides are normalized to ``/``
    separators so the check holds when a real Windows walk produced ``\\``
    paths (or a report consumer compares against POSIX-spelled bundle paths).
    """
    normalized = file_path.replace("\\", "/")
    for bundle_dir in bundle_dirs:
        prefix = bundle_dir.replace("\\", "/").rstrip("/") + "/"
        if normalized.startswith(prefix):
            return True
    return False
