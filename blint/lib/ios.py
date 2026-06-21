"""iOS/macOS application (``.ipa``) handling for blint.

An ``.ipa`` is a zip archive whose ``Payload/<App>.app/`` bundle contains the
main Mach-O executable (named by ``CFBundleExecutable`` in ``Info.plist``),
embedded frameworks/dylibs under ``Frameworks/`` and app extensions under
``PlugIns/`` (each its own Mach-O). This module unpacks the archive, locates the
Mach-O binaries to analyse, and exposes the bundle context (identifier, version,
minimum OS, FairPlay encryption status) so each binary's report can be enriched.
"""

import os
import plistlib
import tempfile
import zipfile

from blint.lib.utils import is_exe
from blint.logger import LOG

IOS_APP_EXTNS = (".ipa",)

# Keys lifted from the app bundle's Info.plist into binary metadata.
_INFO_PLIST_KEYS = {
    "CFBundleIdentifier": "bundle_identifier",
    "CFBundleName": "bundle_name",
    "CFBundleDisplayName": "bundle_display_name",
    "CFBundleShortVersionString": "bundle_version",
    "CFBundleVersion": "bundle_build",
    "MinimumOSVersion": "minimum_os_version",
    "DTPlatformName": "platform_name",
    "DTPlatformVersion": "platform_version",
    "LSApplicationCategoryType": "application_category",
}


def is_ios_app(path) -> bool:
    """Return True when the path points to an iOS/macOS app archive (.ipa)."""
    return isinstance(path, str) and path.lower().endswith(IOS_APP_EXTNS)


def _read_bundle_info(app_dir: str) -> dict:
    """Read the relevant keys from a ``.app`` bundle's Info.plist."""
    info = {"bundle_dir": os.path.basename(app_dir)}
    plist_path = os.path.join(app_dir, "Info.plist")
    if not os.path.isfile(plist_path):
        return info
    try:
        with open(plist_path, "rb") as fp:
            plist = plistlib.load(fp)
    except (OSError, ValueError, plistlib.InvalidFileException) as e:
        LOG.debug(f"Could not read Info.plist at {plist_path}: {e}")
        return info
    for plist_key, meta_key in _INFO_PLIST_KEYS.items():
        if plist_key in plist:
            info[meta_key] = plist[plist_key]
    if executable := plist.get("CFBundleExecutable"):
        info["executable"] = executable
    if ats := _summarize_ats(plist.get("NSAppTransportSecurity")):
        info["app_transport_security"] = ats
    # URL schemes the app registers to handle (deep links / inter-app entry
    # points worth surfacing for analysis).
    schemes = []
    for url_type in plist.get("CFBundleURLTypes") or []:
        if isinstance(url_type, dict):
            schemes += url_type.get("CFBundleURLSchemes") or []
    if schemes:
        info["url_schemes"] = sorted(set(schemes))
    return info


def _summarize_ats(ats) -> dict | None:
    """Summarise the ``NSAppTransportSecurity`` policy from an Info.plist.

    App Transport Security enforces secure (HTTPS, TLS 1.2+) connections by
    default. Apps can weaken it globally with ``NSAllowsArbitraryLoads`` or per
    host via exception domains that disable forward secrecy, downgrade TLS, or
    permit insecure HTTP loads. We capture the weakening flags so they can be
    reported.
    """
    if not isinstance(ats, dict):
        return None
    summary = {
        "allows_arbitrary_loads": bool(ats.get("NSAllowsArbitraryLoads")),
        "allows_arbitrary_loads_media": bool(ats.get("NSAllowsArbitraryLoadsForMedia")),
        "allows_arbitrary_loads_web": bool(ats.get("NSAllowsArbitraryLoadsInWebContent")),
    }
    insecure_domains = []
    for domain, policy in (ats.get("NSExceptionDomains") or {}).items():
        if not isinstance(policy, dict):
            continue
        if policy.get("NSExceptionAllowsInsecureHTTPLoads") or policy.get(
            "NSThirdPartyExceptionAllowsInsecureHTTPLoads"
        ):
            insecure_domains.append(domain)
    if insecure_domains:
        summary["insecure_exception_domains"] = sorted(insecure_domains)
    # Only report when something actually weakens the default secure posture.
    if any(summary.values()):
        return summary
    return None


def _collect_bundle_binaries(app_dir: str, bundle_info: dict) -> list[dict]:
    """Locate the Mach-O binaries inside a ``.app`` bundle.

    Returns entries with ``path``/``role``, ordered with the main executable
    first so it leads the generated reports.
    """
    binaries: list[dict] = []
    seen: set[str] = set()

    payload_dir = os.path.dirname(app_dir)

    def _add(path: str, role: str, component_info: dict | None = None):
        if not path or path in seen:
            return
        if os.path.isfile(path) and is_exe(path):
            seen.add(path)
            entry = {
                "path": path,
                "role": role,
                "bundle_path": os.path.relpath(path, payload_dir),
            }
            # Each embedded framework / extension carries its own Info.plist
            # with the real product identifier and version; surfacing it lets
            # the SBOM identify the dependency precisely rather than inheriting
            # the host app's version.
            if component_info:
                for key in ("bundle_identifier", "bundle_version", "bundle_name"):
                    if component_info.get(key):
                        entry[key] = component_info[key]
            binaries.append(entry)

    # Main executable from CFBundleExecutable (fall back to the .app basename).
    executable = bundle_info.get("executable") or os.path.splitext(os.path.basename(app_dir))[0]
    _add(os.path.join(app_dir, executable), "main")

    # Embedded frameworks and dylibs.
    frameworks_dir = os.path.join(app_dir, "Frameworks")
    if os.path.isdir(frameworks_dir):
        for entry in sorted(os.listdir(frameworks_dir)):
            full = os.path.join(frameworks_dir, entry)
            if entry.endswith(".framework") and os.path.isdir(full):
                fw_exe = os.path.splitext(entry)[0]
                _add(os.path.join(full, fw_exe), "framework", _read_bundle_info(full))
            elif entry.endswith(".dylib"):
                _add(full, "dylib")

    # App extensions (each .appex is a nested bundle with its own executable).
    plugins_dir = os.path.join(app_dir, "PlugIns")
    if os.path.isdir(plugins_dir):
        for entry in sorted(os.listdir(plugins_dir)):
            appex = os.path.join(plugins_dir, entry)
            if entry.endswith(".appex") and os.path.isdir(appex):
                appex_info = _read_bundle_info(appex)
                appex_exe = appex_info.get("executable") or os.path.splitext(entry)[0]
                _add(os.path.join(appex, appex_exe), "plugin", appex_info)

    return binaries


def collect_ios_app(app_file: str) -> dict | None:
    """Unpack an ``.ipa`` and enumerate its Mach-O binaries.

    Returns a dict with ``temp_dir`` (caller is responsible for cleanup),
    ``bundle_info`` and ``binaries``; or ``None`` when no app bundle/binary is
    found.
    """
    temp_dir = tempfile.mkdtemp(prefix="blint_ios_app")
    try:
        with zipfile.ZipFile(app_file) as zf:
            zf.extractall(temp_dir)
    except (zipfile.BadZipFile, OSError) as e:
        LOG.warning(f"Could not extract iOS app {app_file}: {e}")
        return None

    payload_dir = os.path.join(temp_dir, "Payload")
    if not os.path.isdir(payload_dir):
        LOG.warning(f"iOS app {app_file} has no Payload/ directory; skipping")
        return None
    app_dirs = sorted(
        os.path.join(payload_dir, d)
        for d in os.listdir(payload_dir)
        if d.endswith(".app") and os.path.isdir(os.path.join(payload_dir, d))
    )
    if not app_dirs:
        LOG.warning(f"iOS app {app_file} has no .app bundle in Payload/; skipping")
        return None

    app_dir = app_dirs[0]
    bundle_info = _read_bundle_info(app_dir)
    binaries = _collect_bundle_binaries(app_dir, bundle_info)
    if not binaries:
        LOG.warning(f"No Mach-O binaries found in iOS app {app_file}; skipping")
        return None
    return {"temp_dir": temp_dir, "bundle_info": bundle_info, "binaries": binaries}


def enrich_with_bundle_context(
    metadata: dict, bundle_info: dict, role: str, bundle_path: str | None = None
) -> dict:
    """Attach app-bundle context to a binary's parsed metadata."""
    if not isinstance(metadata, dict):
        return metadata
    context = {k: v for k, v in bundle_info.items() if k != "executable"}
    context["role"] = role
    if bundle_path:
        context["bundle_path"] = bundle_path
    metadata["ios_bundle"] = context
    # Replace the extraction temp path with a stable bundle-relative path so
    # reports identify the binary by its location inside the app.
    if bundle_path:
        metadata["name"] = bundle_path
        metadata["file_path"] = bundle_path
    # Surface the most useful identifiers at the top level for reporting.
    for key in ("bundle_identifier", "bundle_version", "minimum_os_version"):
        if key in bundle_info:
            metadata.setdefault(key, bundle_info[key])
    # The App Transport Security policy lives in the Info.plist rather than the
    # Mach-O, so inject stable tokens into the binary's informative strings to
    # let the rule engine flag a weakened secure-transport posture.
    if role == "main":
        for token in _ats_tokens(bundle_info.get("app_transport_security")):
            metadata.setdefault("informative_strings", []).append(token)
    return metadata


def _ats_tokens(ats: dict | None) -> list[str]:
    """Translate an ATS summary into match tokens for the rule engine."""
    if not ats:
        return []
    tokens = []
    if ats.get("allows_arbitrary_loads"):
        tokens.append("ATS_NSAllowsArbitraryLoads")
    if ats.get("allows_arbitrary_loads_media"):
        tokens.append("ATS_NSAllowsArbitraryLoadsForMedia")
    if ats.get("allows_arbitrary_loads_web"):
        tokens.append("ATS_NSAllowsArbitraryLoadsInWebContent")
    if ats.get("insecure_exception_domains"):
        tokens.append("ATS_NSExceptionAllowsInsecureHTTPLoads")
    return tokens
