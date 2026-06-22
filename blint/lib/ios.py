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

# Filename of the app privacy manifest (iOS 17+ / required since May 2024). It is
# a binary/XML plist declaring tracking, tracking domains, the categories of data
# the app collects, and the "required reason" APIs the app (or an embedded SDK)
# uses. See Apple's "Describing use of required reason API" documentation.
_PRIVACY_MANIFEST_NAME = "PrivacyInfo.xcprivacy"

# Required-reason API categories mapped to lowercase symbol/selector markers that
# indicate the API is referenced by the binary. Apple requires each category in
# use to be declared in the privacy manifest; undeclared use is reportable
# (App Store warning ITMS-91053). Markers are kept high-signal to limit noise.
_REQUIRED_REASON_API_MARKERS = {
    "NSPrivacyAccessedAPICategoryUserDefaults": (
        "nsuserdefaults",
        "standarduserdefaults",
    ),
    "NSPrivacyAccessedAPICategoryFileTimestamp": (
        "getattrlistbulk",
        "nsfilemodificationdate",
        "nsfilecreationdate",
        "contentmodificationdatekey",
        "creationdatekey",
    ),
    "NSPrivacyAccessedAPICategorySystemBootTime": (
        "systemuptime",
        "mach_absolute_time",
        "kern.boottime",
    ),
    "NSPrivacyAccessedAPICategoryDiskSpace": (
        "nsfilesystemfreesize",
        "nsfilesystemsize",
        "volumeavailablecapacitykey",
        "volumetotalcapacitykey",
    ),
    "NSPrivacyAccessedAPICategoryActiveKeyboards": ("activeinputmodes",),
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
    info.update(_collect_privacy_signals(plist))
    return info


def _collect_privacy_signals(plist: dict) -> dict:
    """Extract privacy-relevant declarations from an Info.plist.

    These declarations describe the app's data-access posture independently of
    its code: the sensitive resources it is provisioned to access (the
    ``NS...UsageDescription`` consent strings), the other apps it can probe for
    via ``canOpenURL`` (``LSApplicationQueriesSchemes``) and the local-network
    services it discovers (``NSBonjourServices``).
    """
    signals: dict = {}
    usage = sorted(
        key for key in plist if isinstance(key, str) and key.endswith("UsageDescription")
    )
    if usage:
        signals["privacy_usage_descriptions"] = usage
    query_schemes = [
        str(s) for s in (plist.get("LSApplicationQueriesSchemes") or []) if isinstance(s, str)
    ]
    if query_schemes:
        signals["query_schemes"] = sorted(set(query_schemes))
    bonjour = [str(s) for s in (plist.get("NSBonjourServices") or []) if isinstance(s, str)]
    if bonjour:
        signals["bonjour_services"] = sorted(set(bonjour))
    return signals


def _read_privacy_manifest(app_dir: str) -> dict | None:
    """Read and aggregate the app privacy manifest(s) for a ``.app`` bundle.

    The main bundle, each embedded framework and each app extension may ship its
    own ``PrivacyInfo.xcprivacy``. We union their declarations so the reported
    posture reflects the whole app (third-party SDKs included): whether any
    component declares tracking, the set of tracking domains, the collected data
    types and the required-reason API categories declared in use.
    """
    paths: list[str] = []
    root_manifest = os.path.join(app_dir, _PRIVACY_MANIFEST_NAME)
    if os.path.isfile(root_manifest):
        paths.append(root_manifest)
    for sub in ("Frameworks", "PlugIns"):
        sub_dir = os.path.join(app_dir, sub)
        if not os.path.isdir(sub_dir):
            continue
        for root, _dirs, files in os.walk(sub_dir):
            if _PRIVACY_MANIFEST_NAME in files:
                paths.append(os.path.join(root, _PRIVACY_MANIFEST_NAME))
    if not paths:
        return None

    tracking = False
    tracking_domains: set[str] = set()
    data_types: set[str] = set()
    api_categories: set[str] = set()
    for path in paths:
        try:
            with open(path, "rb") as fp:
                manifest = plistlib.load(fp)
        except (OSError, ValueError, plistlib.InvalidFileException) as e:
            LOG.debug(f"Could not read privacy manifest at {path}: {e}")
            continue
        if not isinstance(manifest, dict):
            continue
        tracking = tracking or bool(manifest.get("NSPrivacyTracking"))
        tracking_domains.update(
            str(d) for d in (manifest.get("NSPrivacyTrackingDomains") or []) if isinstance(d, str)
        )
        for entry in manifest.get("NSPrivacyCollectedDataTypes") or []:
            if isinstance(entry, dict) and entry.get("NSPrivacyCollectedDataType"):
                data_types.add(str(entry["NSPrivacyCollectedDataType"]))
        for entry in manifest.get("NSPrivacyAccessedAPITypes") or []:
            if isinstance(entry, dict) and entry.get("NSPrivacyAccessedAPIType"):
                api_categories.add(str(entry["NSPrivacyAccessedAPIType"]))

    return {
        "present": True,
        "manifest_count": len(paths),
        "tracking": tracking,
        "tracking_domains": sorted(tracking_domains),
        "collected_data_types": sorted(data_types),
        "accessed_api_categories": sorted(api_categories),
    }


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
    if manifest := _read_privacy_manifest(app_dir):
        bundle_info["privacy_manifest"] = manifest
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
    # Likewise, the privacy posture (consent strings, app-probing schemes,
    # Bonjour services, the privacy manifest) lives outside the Mach-O. Inject
    # stable tokens so the rule engine can flag the app's data-access surface and
    # any required-reason APIs used without a matching manifest declaration.
    if role == "main":
        for token in _ats_tokens(bundle_info.get("app_transport_security")):
            metadata.setdefault("informative_strings", []).append(token)
        privacy_tokens = _privacy_tokens(bundle_info)
        privacy_tokens += _undeclared_required_reason_tokens(metadata, bundle_info)
        for token in privacy_tokens:
            metadata.setdefault("informative_strings", []).append(token)
    return metadata


def _privacy_tokens(bundle_info: dict) -> list[str]:
    """Translate the Info.plist / privacy-manifest posture into match tokens."""
    tokens: list[str] = []
    for key in bundle_info.get("privacy_usage_descriptions") or []:
        tokens.append(f"PRIV_{key}")
    if bundle_info.get("query_schemes"):
        tokens.append("PRIV_LSApplicationQueriesSchemes")
        # A large query list is a strong app-presence-probing signal on its own.
        if len(bundle_info["query_schemes"]) >= 5:
            tokens.append("PRIV_ManyApplicationQueriesSchemes")
    if bundle_info.get("bonjour_services"):
        tokens.append("PRIV_NSBonjourServices")
    manifest = bundle_info.get("privacy_manifest")
    if manifest:
        if manifest.get("tracking"):
            tokens.append("PRIV_NSPrivacyTracking")
        if manifest.get("tracking_domains"):
            tokens.append("PRIV_NSPrivacyTrackingDomains")
        for category in manifest.get("accessed_api_categories") or []:
            tokens.append(f"PRIV_{category}")
    else:
        tokens.append("PRIV_PrivacyManifestMissing")
    return tokens


def _undeclared_required_reason_tokens(metadata: dict, bundle_info: dict) -> list[str]:
    """Emit tokens for required-reason APIs used without a manifest declaration.

    Scans the binary's symbols and Objective-C runtime references for markers of
    Apple's required-reason API categories and compares them against the
    categories declared in the (aggregated) privacy manifest. Each category used
    but not declared yields a ``PRIV_UNDECLARED_<category>`` token.
    """
    haystack = _symbol_haystack(metadata)
    if not haystack:
        return []
    manifest = bundle_info.get("privacy_manifest") or {}
    declared = set(manifest.get("accessed_api_categories") or [])
    tokens: list[str] = []
    for category, markers in _REQUIRED_REASON_API_MARKERS.items():
        if category in declared:
            continue
        if any(marker in haystack for marker in markers):
            tokens.append(f"PRIV_UNDECLARED_{category}")
    return tokens


def _symbol_haystack(metadata: dict) -> str:
    """Build a lowercase blob of symbol and ObjC-runtime names for matching."""
    names: list[str] = []
    for key in ("dynamic_symbols", "symtab_symbols"):
        names += [sym.get("name", "") for sym in metadata.get(key) or []]
    if objc := metadata.get("objc_metadata"):
        names += objc.get("selectors") or []
        names += objc.get("external_classes") or []
    return "\n".join(name for name in names if name).lower()


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
