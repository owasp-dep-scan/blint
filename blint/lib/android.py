import json
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from collections.abc import Iterator
from typing import Any
from xml.etree import ElementTree

from custom_json_diff.lib.utils import file_read
from defusedxml.common import DefusedXmlException
from defusedxml.ElementTree import fromstring as defused_fromstring
from packageurl import PackageURL

from blint.config import SYMBOL_DELIMITER
from blint.cyclonedx.spec import Component, Property, RefType, Scope, Type
from blint.db import build_function_hash_index, build_symbol_source_map, detect_binaries_utilized
from blint.lib.android_blintdb import (
    blintdb_records,
    dynamic_symbol_names,
    refuses_openssl_match,
    superseded_by_framework,
)
from blint.lib.android_native import LibraryReader, scan_android_native
from blint.lib.binary import parse, parse_dex
from blint.lib.container import (
    ContainerLimits,
    CumulativeExtractionBudget,
    extract_zip_to_dir,
)
from blint.lib.dalvik_review import DEX_EXE_TYPE, Finding, analyze_dex, build_review_metadata
from blint.lib.framework_ident import framework_identity
from blint.lib.utils import (
    create_component_evidence,
    find_files,
)
from blint.logger import LOG

# Bounded caps for unpacking an Android app or bundle (ground rule 30). An
# ``.apk``/``.aab``/``.xapk`` is a zip of untrusted input, so extraction goes
# through the shared container framework instead of a bare extractall: member
# counts, total and per-member uncompressed sizes, path depth, path safety and
# the per-member compression ratio (the zip-bomb bound) are all enforced and
# every refusal is named. The numbers are generous for real apps (Play caps a
# base APK at 200 MB, and large games unpack to a few hundred MB) while the
# ratio cap kills the decompression bomb: a 20 MiB zero member deflates to
# ~20 KiB (ratio ~1000), far above the cap, so it is refused before a byte is
# written — in place of the previous unbounded ~1000x amplification.
ANDROID_LIMITS = ContainerLimits(
    max_members=131072,
    max_total_uncompressed=4 * 1024 * 1024 * 1024,
    max_member_size=2 * 1024 * 1024 * 1024,
    max_member_depth=64,
    max_member_compression_ratio=200,
)

# One budget for everything a single app/bundle scan unit may extract,
# across every nesting level (bundle -> inner apks -> their contents).
# Per-archive caps alone multiply across levels — a bundle of N inner apks
# gets a fresh cap each, so a modest upload under the ratio cap could still
# unpack N x 4 GiB (measured: 0.68 MiB -> 254 MiB over two levels). A shared
# budget turns that product into a sum. Generous for real apps — the largest
# Play titles unpack to ~4 GiB — while capping a hostile nested bundle at
# one 6 GiB write budget per scanned app.
MAX_APP_EXTRACTION_BUDGET = 6 * 1024 * 1024 * 1024


def _extract_app_zip(
    zip_path: str, to_dir: str, budget: CumulativeExtractionBudget | None = None
) -> list[str]:
    """Bounded extraction of an app/bundle zip into ``to_dir``.

    Replaces the former ``unzip_unsafe``: the same on-disk result for benign
    apps, but hostile archives (zip bombs, traversal names) are refused by
    name instead of exhausting the disk or escaping the directory. Refusals
    are logged so a truncated extraction never reads as a clean one.

    ``budget`` bounds the total this scan unit may extract across nested
    archives; a caller that passes none gets a fresh one for this archive.
    """
    if budget is None:
        budget = CumulativeExtractionBudget(MAX_APP_EXTRACTION_BUDGET)
    refusals: list[str] = []
    extract_zip_to_dir(zip_path, to_dir, ANDROID_LIMITS, refusals, budget=budget)
    if "archive_unreadable" in refusals:
        # The file is not a readable zip at all (as opposed to a zip with
        # individual members refused). Raise so the unit is isolated and
        # recorded as a failure, matching the former unzip_unsafe contract;
        # callers already handle zipfile.BadZipFile.
        raise zipfile.BadZipFile(f"{zip_path} is not a readable zip archive")
    if refusals:
        LOG.warning(
            "Bounded extraction of %s refused %d member(s): %s",
            os.path.basename(zip_path),
            len(refusals),
            ", ".join(sorted(set(refusals))),
        )
    return refusals

try:
    from apkInspector.axml import parse_apk_for_manifest
except ImportError:  # pragma: no cover - apkInspector is an optional dependency
    parse_apk_for_manifest = None

# Namespace used for android specific attributes in a decoded manifest.
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
# Split bundle archives. APKMirror bundles (.apkm) and split bundles
# (.apks/.xapk) are zip archives that contain a base apk along with
# configuration splits.
BUNDLE_EXTENSIONS: tuple[str, ...] = (".apkm", ".apks", ".xapk")

ANDROID_HOME = os.getenv("ANDROID_HOME")
APKANALYZER_CMD = os.getenv("APKANALYZER_CMD")
if (
    not APKANALYZER_CMD
    and ANDROID_HOME
    and os.path.exists(os.path.join(ANDROID_HOME, "cmdline-tools", "latest", "bin", "apkanalyzer"))
):
    APKANALYZER_CMD = os.path.join(ANDROID_HOME, "cmdline-tools", "latest", "bin", "apkanalyzer")
elif resolved_apkanalyzer := shutil.which("apkanalyzer"):
    # Resolve to a full path so exec_tool can run it with shell=False: on
    # Windows that is apkanalyzer.bat, which subprocess runs safely (the
    # stdlib applies batch-specific argument quoting), and on Unix it is the
    # executable launcher script.
    APKANALYZER_CMD = resolved_apkanalyzer


# Characters cmd.exe treats as operators/escapes. On Windows, executing a
# .bat/.cmd launcher routes the command line through cmd.exe even with
# ``shell=False``; Pythons carrying the BatBadBut fix (>=3.11.9, >=3.12.2)
# quote these away, but blint also supports 3.10, so an argument carrying
# them is refused outright rather than trusted to the interpreter's quoting.
_BAT_UNSAFE_CHARS = re.compile(r'[&|<>^"%]')


def _bat_unsafe_args(args: list[str]) -> list[str]:
    """Arguments a cmd.exe-routed batch launcher must not receive verbatim."""
    if not args or not str(args[0]).lower().endswith((".bat", ".cmd")):
        return []
    return [a for a in args[1:] if _BAT_UNSAFE_CHARS.search(a)]


def exec_tool(
    args: list[str], cwd: str | None = None, stdout: int = subprocess.PIPE
) -> subprocess.CompletedProcess | None:
    """
    Convenience method to invoke cli tools

    :param args: Command line arguments
    :param cwd: Working directory
    :param stdout: Specifies stdout of command

    The command is always invoked with ``shell=False``. ``args`` can carry
    attacker-controlled values (an apk path derived from an archive member
    name), and a shell would let a crafted name such as ``x&calc.exe&base.apk``
    inject commands on Windows (CWE-78); passing an argument vector to the
    program directly removes the shell from the chain entirely. Batch
    launchers on Windows are the one residual shell in that chain, so their
    arguments are additionally screened (see ``_bat_unsafe_args``).
    """
    if os.name == "nt" and (unsafe := _bat_unsafe_args(args)):
        LOG.warning(
            "Refusing to run %s with shell metacharacter(s) in %d argument(s): "
            "a crafted archive member name must not reach cmd.exe",
            args[0],
            len(unsafe),
        )
        return None
    try:
        LOG.debug(f'⚡︎ Executing "{" ".join(args)}"')
        return subprocess.run(
            args,
            stdout=stdout,
            stderr=subprocess.STDOUT,
            cwd=cwd,
            env=os.environ.copy(),
            shell=False,
            encoding="utf-8",
            check=False,
        )
    except (subprocess.SubprocessError, OSError) as e:
        LOG.exception(e)
        return None


def collect_app_metadata(
    app_file: str, deep_mode: bool, use_blintdb: bool = False
) -> tuple[Component | None, list[Component]]:
    """
    Collect various metadata about an android app.

    Both single apk files and split bundles (``.apkm``, ``.apks``, ``.xapk``)
    are supported.
    """
    if app_file.endswith(BUNDLE_EXTENSIONS):
        return collect_bundle_metadata(app_file, deep_mode, use_blintdb=use_blintdb)
    parent_component = apk_parent_component(app_file)
    app_facts: dict = {"hermes_bundles": scan_hermes_bundles(app_file)}
    components = collect_files_metadata(
        app_file, parent_component, deep_mode, app_facts=app_facts, use_blintdb=use_blintdb
    )
    attach_app_framework_facts(parent_component, app_facts)
    return parent_component, components


# Hermes bytecode container magic (facebook/hermes
# include/hermes/BCGen/HBC/BytecodeFileFormat.h: MAGIC = 0x1F1903C103BC1FC6,
# "Hermes" in ancient Greek, UTF-16BE, truncated to 8 bytes), little-endian
# on disk, followed by the u32 BYTECODE_VERSION
# (BytecodeVersion.h: 96 as of the constant's last update).
HERMES_HBC_MAGIC = bytes.fromhex("c61fbc03c103191f")
HERMES_BUNDLE_SUFFIXES = (".bundle", ".hbc")


def scan_hermes_bundles(app_file: str) -> list[dict]:
    """Read the Hermes bytecode header of the app's JS bundles, in place.

    The hbc header is the version-bearing evidence the Hermes source
    defines (magic + BYTECODE_VERSION), so the app-level fact states the
    bytecode format version the app ships. Reads 12 bytes per bundle-named
    member - nothing is extracted or fully read.
    """
    bundles: list[dict] = []
    try:
        with zipfile.ZipFile(app_file) as z:
            for name in z.namelist():
                if not name.endswith(HERMES_BUNDLE_SUFFIXES):
                    continue
                try:
                    with z.open(name) as fh:
                        header = fh.read(12)
                except (OSError, zipfile.BadZipFile):
                    continue
                if len(header) < 12 or header[:8] != HERMES_HBC_MAGIC:
                    continue
                bundles.append(
                    {
                        "member": name,
                        "bytecode_version": int.from_bytes(header[8:12], "little"),
                    }
                )
    except (OSError, zipfile.BadZipFile) as e:
        LOG.debug(f"Hermes bundle scan failed for {app_file}: {e}")
    return bundles


def attach_app_framework_facts(parent_component: Component | None, app_facts: dict) -> None:
    """Record app-level identification facts on the parent component.

    The NDK version dates every NDK-built library of an ABI, so the
    distinct ``.note.android.ident`` NDK versions are recorded per ABI as
    one property (ground rule 36: per-ABI facts, never the first or the
    best).
    """
    if parent_component is None:
        return
    ndk_versions = app_facts.get("ndk_versions") or {}
    if ndk_versions:
        value = ";".join(
            f"{abi}:{','.join(sorted(versions))}"
            for abi, versions in sorted(ndk_versions.items())
        )
        parent_component.properties = (parent_component.properties or []) + [
            Property(name="blint:ndk_versions", value=value)
        ]
    bundles = app_facts.get("hermes_bundles") or []
    if bundles:
        value = ",".join(
            f"{b['member']}:{b['bytecode_version']}" for b in bundles
        )
        parent_component.properties = (parent_component.properties or []) + [
            Property(name="blint:hermes_bytecode_version", value=value)
        ]


def collect_bundle_metadata(
    app_file: str, deep_mode: bool, use_blintdb: bool = False
) -> tuple[Component | None, list[Component]]:
    """
    Collect metadata for a split bundle (``.apkm``, ``.apks``, ``.xapk``).

    The bundle is unpacked and every contained apk is analysed. The base apk
    provides the manifest used to build the parent application component, and
    the bundle ``info.json`` (when present) supplies additional metadata.

    Args:
        app_file (str): The path to the bundle file.
        deep_mode (bool): Flag indicating whether to parse dex files.

    Returns:
        tuple: The parent component and the list of contained components.
    """
    bundle_temp_dir = tempfile.mkdtemp(prefix="blint_android_bundle")
    # One extraction budget for the bundle and every apk unpacked from it:
    # per-archive caps alone would face each inner apk afresh and multiply
    # across the nesting levels (see MAX_APP_EXTRACTION_BUDGET).
    budget = CumulativeExtractionBudget(MAX_APP_EXTRACTION_BUDGET)
    file_components = []
    parent_component: Component | None = None
    app_facts: dict = {"hermes_bundles": scan_hermes_bundles(app_file)}
    try:
        _extract_app_zip(app_file, bundle_temp_dir, budget=budget)
        bundle_info = read_bundle_info(bundle_temp_dir)
        apk_files = sorted(find_files(bundle_temp_dir, [".apk"]))
        if not apk_files:
            LOG.warning("No apk files were found in the bundle %s", app_file)
        base_apk = select_base_apk(apk_files)
        if base_apk:
            parent_component = apk_parent_component(app_file, base_apk, bundle_info)
        for apk in apk_files:
            file_components += collect_files_metadata(
                app_file, parent_component, deep_mode, unpack_target=apk,
                app_facts=app_facts, use_blintdb=use_blintdb, budget=budget,
            )
    finally:
        shutil.rmtree(bundle_temp_dir, ignore_errors=True)
    attach_app_framework_facts(parent_component, app_facts)
    return parent_component, file_components


def read_bundle_info(bundle_temp_dir: str) -> dict:
    """
    Read the ``info.json`` metadata bundled inside an apkm file.

    Args:
        bundle_temp_dir (str): The directory the bundle was unpacked to.

    Returns:
        dict: The parsed metadata or an empty dict when unavailable.
    """
    info_file = os.path.join(bundle_temp_dir, "info.json")
    if not os.path.exists(info_file):
        return {}
    try:
        return json.loads(file_read(info_file, False, log=LOG))
    except (ValueError, OSError) as e:
        LOG.debug(f"Unable to read the bundle info.json: {e}")
        return {}


def select_base_apk(apk_files: list[str]) -> str | None:
    """
    Pick the base apk from the list of apks contained within a bundle.

    Args:
        apk_files (list): The apk files discovered in the bundle.

    Returns:
        str | None: The base apk path or None when the list is empty.
    """
    for apk in apk_files:
        if os.path.basename(apk) == "base.apk":
            return apk
    # Otherwise prefer an apk that is not a configuration split.
    for apk in apk_files:
        if not os.path.basename(apk).startswith("split_"):
            return apk
    return apk_files[0] if apk_files else None


def apk_parent_component(
    app_file: str, manifest_apk: str | None = None, bundle_info: dict | None = None
) -> Component | None:
    """
    Build the parent application component for an apk.

    The component is derived by decoding the ``AndroidManifest.xml`` of the
    apk. When the manifest cannot be decoded, the ``apkanalyzer`` command line
    tool is used as a fallback.

    Args:
        app_file (str): Path reported as the originating application file.
        manifest_apk (str): The apk to read the manifest from. Defaults to
            ``app_file``.
        bundle_info (dict): Optional bundle metadata from ``info.json``.

    Returns:
        Component | None: The parent application component.
    """
    manifest_apk = manifest_apk or app_file
    manifest = read_manifest_attributes(manifest_apk)
    if manifest:
        return build_parent_component(manifest, app_file, bundle_info)
    return apk_summary_fallback(manifest_apk)


def read_manifest_attributes(apk_file: str) -> dict:
    """
    Decode the ``AndroidManifest.xml`` of an apk and return key attributes.

    Args:
        apk_file (str): The apk to decode.

    Returns:
        dict: The manifest attributes or an empty dict when decoding fails.
    """
    if parse_apk_for_manifest is None:
        LOG.debug("apkInspector is unavailable. Unable to decode the manifest.")
        return {}
    try:
        raw_xml = parse_apk_for_manifest(apk_file, raw=False)
    except Exception as e:  # apkInspector raises a variety of parsing errors
        LOG.debug(f"Unable to decode the manifest for {apk_file}: {e}")
        return {}
    if not raw_xml:
        return {}
    try:
        # Manifests come from untrusted archives, so entity expansion is blocked
        # the same way the PE manifest path already does.
        root = defused_fromstring(raw_xml)
    except (ElementTree.ParseError, DefusedXmlException) as e:
        LOG.debug(f"Unable to parse the decoded manifest for {apk_file}: {e}")
        return {}
    attributes: dict = {
        "package": root.get("package", ""),
        "versionName": root.get(f"{ANDROID_NS}versionName", ""),
        "versionCode": root.get(f"{ANDROID_NS}versionCode", ""),
        "compileSdkVersion": root.get(f"{ANDROID_NS}compileSdkVersion", ""),
    }
    uses_sdk = root.find("uses-sdk")
    if uses_sdk is not None:
        attributes["minSdkVersion"] = uses_sdk.get(f"{ANDROID_NS}minSdkVersion", "")
        attributes["targetSdkVersion"] = uses_sdk.get(f"{ANDROID_NS}targetSdkVersion", "")
    attributes["permissions"] = sorted(
        {
            perm.get(f"{ANDROID_NS}name")
            for perm in root.iter("uses-permission")
            if perm.get(f"{ANDROID_NS}name")
        }
    )
    attributes["features"] = sorted(
        {
            feat.get(f"{ANDROID_NS}name")
            for feat in root.iter("uses-feature")
            if feat.get(f"{ANDROID_NS}name")
        }
    )
    attributes["mainActivity"] = find_main_activity(root)
    # The loader-enforced native-lib layout (01/A.2): declared on
    # <application>; AGP's default when unset is minSdk >= 23, which
    # android_native.extract_native_libs_fact derives from minSdkVersion.
    application = root.find("application")
    if application is not None:
        declared = application.get(f"{ANDROID_NS}extractNativeLibs")
        if declared is not None:
            attributes["extractNativeLibs"] = declared.lower() == "true"
    return attributes


def find_main_activity(root: ElementTree.Element) -> str:
    """
    Locate the launcher activity declared in the manifest.

    Args:
        root (Element): The decoded manifest root element.

    Returns:
        str: The launcher activity name or an empty string.
    """
    for activity in root.iter("activity"):
        for intent_filter in activity.findall("intent-filter"):
            actions = {a.get(f"{ANDROID_NS}name") for a in intent_filter.findall("action")}
            categories = {c.get(f"{ANDROID_NS}name") for c in intent_filter.findall("category")}
            if (
                "android.intent.action.MAIN" in actions
                and "android.intent.category.LAUNCHER" in categories
            ):
                return activity.get(f"{ANDROID_NS}name", "") or ""
    return ""


def build_parent_component(
    manifest: dict, app_file: str, bundle_info: dict | None = None
) -> Component | None:
    """
    Build the parent application component from decoded manifest attributes.

    Args:
        manifest (dict): The decoded manifest attributes.
        app_file (str): The originating application file.
        bundle_info (dict): Optional bundle metadata from ``info.json``.

    Returns:
        Component | None: The parent application component.
    """
    bundle_info = bundle_info or {}
    name = manifest.get("package") or bundle_info.get("pname")
    version = manifest.get("versionName") or bundle_info.get("release_version") or ""
    if not name:
        return None
    purl = f"pkg:android/{name}@{version}" if version else f"pkg:android/{name}"
    component = Component(type=Type.application, name=name, version=version, purl=purl)
    component.bom_ref = RefType(purl)
    component.properties = build_manifest_properties(manifest, bundle_info)
    return component


def build_manifest_properties(manifest: dict, bundle_info: dict | None = None) -> list[Property]:
    """
    Build the component properties from decoded manifest and bundle metadata.

    Args:
        manifest (dict): The decoded manifest attributes.
        bundle_info (dict): Optional bundle metadata from ``info.json``.

    Returns:
        list: A list of Property objects.
    """
    bundle_info = bundle_info or {}
    properties = []
    if features := manifest.get("features"):
        properties.append(Property(name="internal.appFeatures", value="\n".join(features)))
    if permissions := manifest.get("permissions"):
        properties.append(Property(name="internal.appPermissions", value="\n".join(permissions)))
    scalar_props = {
        "internal:versionCode": manifest.get("versionCode") or bundle_info.get("versioncode"),
        "internal:minSdkVersion": manifest.get("minSdkVersion") or bundle_info.get("min_api"),
        "internal:targetSdkVersion": manifest.get("targetSdkVersion"),
        "internal:compileSdkVersion": manifest.get("compileSdkVersion"),
        "internal:mainActivity": manifest.get("mainActivity"),
    }
    # Additional metadata gleaned from the bundle's info.json (apkm specific).
    if bundle_info:
        scalar_props["internal:appName"] = bundle_info.get("app_name")
        scalar_props["internal:architectures"] = ",".join(bundle_info.get("arches") or [])
        scalar_props["internal:locales"] = ",".join(bundle_info.get("languages") or [])
        scalar_props["internal:densities"] = ",".join(bundle_info.get("dpis") or [])
    for prop_name, value in scalar_props.items():
        if value:
            properties.append(Property(name=prop_name, value=str(value)))
    return properties


def apk_summary_fallback(app_file: str) -> Component | None:
    """
    Build the parent component using the ``apkanalyzer`` command line tool.

    This is used only when the manifest cannot be decoded with apkInspector.

    Args:
        app_file (str): The apk to summarise.

    Returns:
        Component | None: The parent application component.
    """
    parent_component = apk_summary(app_file)
    if parent_component:
        parent_component.properties = []
        if features := apk_features(app_file):
            parent_component.properties.append(
                Property(name="internal.appFeatures", value=features)
            )
        if permissions := apk_permissions(app_file):
            parent_component.properties.append(
                Property(name="internal.appPermissions", value=permissions)
            )
    return parent_component


def apk_summary(app_file: str) -> Component | None:
    """
    Retrieve the parent component using apk summary
    """
    if not app_file.endswith(".apk") or not APKANALYZER_CMD:
        return None
    cp = exec_tool([APKANALYZER_CMD, "apk", "summary", app_file])
    return parse_apk_summary(cp.stdout) if cp and cp.returncode == 0 else None


def apk_features(app_file: str) -> str | None:
    """
    Retrieve the app features
    """
    if not app_file.endswith(".apk") or not APKANALYZER_CMD:
        return None
    cp = exec_tool([APKANALYZER_CMD, "apk", "features", app_file])
    return strip_apk_data(cp.stdout.strip()) if cp and cp.returncode == 0 else ""


def apk_permissions(app_file: str) -> str | None:
    """
    Retrieve the app permissions
    """
    if not app_file.endswith(".apk") or not APKANALYZER_CMD:
        return None
    cp = exec_tool([APKANALYZER_CMD, "manifest", "permissions", app_file])
    return strip_apk_data(cp.stdout.strip()) if cp and cp.returncode == 0 else ""


def strip_apk_data(data: str) -> str:
    """Strips the APK data by removing the first line if it contains "JAVA_TOOL_OPTIONS".
    Args:
        data (str): The input data to be stripped.

    Returns:
        str: The stripped data.
    """
    parts = data.split("\n")
    if "JAVA_TOOL_OPTIONS" in data and parts and len(parts) > 0:
        parts.pop(0)
    return "\n".join(parts)


def collect_version_files_metadata(app_file: str, app_temp_dir: str) -> list[Component]:
    """
    Collects metadata for version files in the given app temporary directory.

    Args:
        app_file (str): The path to the app file.
        app_temp_dir (str): The path to the app temporary directory.

    Returns:
        list: A list of Component objects, each representing a version file.
    """
    file_components = []
    # Find and read all .version files
    version_files = find_files(app_temp_dir, [".version"])
    for vf in version_files:
        file_name = os.path.basename(vf).removesuffix(".version")
        rel_path = os.path.relpath(vf, app_temp_dir)
        group = ""
        name = ""
        if "_" in file_name:
            group, name = parse_file_name(file_name, group)
        # Sometimes the version data could be dynamic. Eg:
        #   task ':lifecycle:lifecycle-viewmodel:writeVersionFile' property 'version'"
        # These can be treated as dynamic
        if version_data := file_read(vf, False, log=LOG).strip():
            if version_data.startswith("task"):
                version_data = "dynamic"
            if name:
                component = create_version_component(app_file, group, name, rel_path, version_data)
                file_components.append(component)
    return file_components


def create_version_component(
    app_file: str, group: str, name: str, rel_path: str, version_data: str
) -> Component:
    """
    Creates a Component object with the provided metadata.

    Args:
        app_file (str): The path to the app file.
        group (str): The group of the component.
        name (str): The name of the component.
        rel_path (str): The relative path of the component.
        version_data (str): The version data of the component.

    Returns:
        Component: A Component object with the provided metadata.
    """
    confidence = 1.0
    if group:
        purl = f"pkg:maven/{group}/{name}@{version_data}?type=jar"
    else:
        purl = f"pkg:maven/{name}@{version_data}?type=jar"
        confidence = 0.2
    # Adjust the confidence based on the version data
    if not version_data or version_data in ("latest", "dynamic"):
        confidence = 0.2
    component = Component(
        type=Type.library,
        group=group,
        name=name,
        version=version_data,
        purl=purl,
        scope=Scope.required,
        evidence=create_component_evidence(rel_path, confidence),
        properties=[
            Property(name="internal:srcFile", value=rel_path),
            Property(name="internal:appFile", value=app_file),
        ],
    )
    component.bom_ref = RefType(purl)
    return component


def parse_file_name(file_name: str, group: str) -> tuple[str, str]:
    """
    Parses the file name and returns the group and name components.

    Args:
        file_name (LiteralString | bytes): The file name to parse.
        group (str): The default group value.

    Returns:
        tuple: A tuple containing two elements:
            - group (str): The parsed group component.
            - name (str): The parsed name component.
    """
    parts = str(file_name).split("_")
    name = file_name
    if parts and len(parts) == 2:
        group = parts[0]
        name = parts[-1]
    else:
        name = str(name).replace("_", "-")
        # Patch the group name
        if name.startswith("kotlinx-"):
            group = "org.jetbrains.kotlinx"
    return group, name


# NDK stable-API runtime libraries (NDK docs apis.html, "Stable APIs" table,
# cross-checked against NDK r27.3/r28.2) plus the bionic runtime pair the
# linker itself provides. A DT_NEEDED on one of these is satisfied by the
# platform at load time, so it is a platform fact, never a component.
NDK_PLATFORM_LIBRARIES = frozenset({
    "libaaudio.so", "libamidi.so", "libandroid.so", "libbinder_ndk.so",
    "libc.so", "libcamera2ndk.so", "libdl.so", "libEGL.so", "libGLESv1_CM.so",
    "libGLESv2.so", "libGLESv3.so", "libjnigraphics.so", "liblog.so",
    "libm.so", "libmediandk.so", "libnativewindow.so", "libneuralnetworks.so",
    "libopenmax.so", "libOpenMAXAL.so", "libOpenSLES.so", "libstdc++.so",
    "libvulkan.so", "libz.so",
})


def _so_version_and_build_id(so_metadata: dict) -> tuple[str | None, str | None]:
    """Split the notes into a real version and a build-id.

    The build-id is a content hash; reporting it as a version was V4 (84%
    of tier-2 components carried one). A note version counts only when it
    is not a bare hex digest.
    """
    version = None
    build_id = None
    for anote in so_metadata.get("notes", []):
        if anote.get("build_id") and not build_id:
            build_id = str(anote["build_id"])
        note_version = anote.get("version")
        if note_version and not version:
            text = str(note_version).strip()
            is_hex = all(c in "0123456789abcdefABCDEF" for c in text)
            if text and not (is_hex and len(text) >= 16):
                version = text
    return version, build_id


def collect_so_files_metadata(
    app_file: str,
    app_temp_dir: str | None = None,
    app_facts: dict | None = None,
    use_blintdb: bool = False,
) -> list[Component]:
    """Collect SBOM components for the app's native libraries (A1.3, 01/D).

    Reads the libraries through the A1.1 container model (zip in place,
    ABI directories, split/bundle provenance) and emits ONE component per
    ``(name, version)`` with per-ABI occurrences - a five-ABI app is five
    evidence lines on one component, not five near-duplicates, and a
    single-ABI app's count does not grow. The build-id never masquerades
    as the version (V4): it rides the ``blint:build_id`` property keyed
    by ABI. purls are built with PackageURL (V5: ``c++_shared`` encodes,
    names keep their ``lib`` prefix so libapp/libdata stop colliding as
    "app"/"data"), and the ABI is a qualifier. DT_NEEDED platform
    libraries are recorded as the ``blint:platform_needed`` fact on the
    needing component, never emitted as components.

    With ``use_blintdb`` (A6.3 J1) every unique sha256 is matched against
    the local blintdb once - the same ``detect_binaries_utilized`` the
    standalone binary path uses. A match is symbol evidence: it nests as
    a child component of the host, and replaces the host's identity only
    when the host's declared DT_SONAME is one of the project's own library
    names in the database. Component versions come from the artifact, never
    from the database row.
    """
    model = scan_android_native(app_file)
    parsed: dict[str, dict] = {}
    with (
        tempfile.TemporaryDirectory(prefix="blint_android_so") as temp_dir,
        LibraryReader(app_file) as reader,
    ):
        for lib in model["libraries"]:
            if lib["sha256"] in parsed:
                continue
            data = reader.read(lib["locations"][0])
            if not data:
                continue
            member = os.path.join(temp_dir, lib["name"])
            with open(member, "wb") as fh:
                fh.write(data)
            try:
                so_metadata = parse(member)
            except Exception as e:  # one unreadable library must not sink the app
                LOG.debug(f"Failed to parse {lib['name']} from {app_file}: {e}")
                continue
            parsed[lib["sha256"]] = so_metadata
            if use_blintdb:
                _attach_blintdb_records(so_metadata, member)
    # Group by (name, version): per-ABI builds of the same library merge.
    groups: dict[tuple[str, str], list[tuple[dict, dict]]] = {}
    for lib in model["libraries"]:
        so_metadata = parsed.get(lib["sha256"])
        if so_metadata is None:
            continue
        if app_facts is not None:
            # App-level per-ABI NDK facts (rule 36): every NDK-built library
            # of the ABI dates it, so collect the distinct note versions.
            ident = (so_metadata.get("android") or {}).get("android_ident") or {}
            if ident.get("ndk_version"):
                for loc in lib.get("locations") or []:
                    if loc.get("abi"):
                        app_facts.setdefault("ndk_versions", {}).setdefault(
                            loc["abi"], set()
                        ).add(str(ident["ndk_version"]))
        version, _build = _so_version_and_build_id(so_metadata)
        groups.setdefault((lib["name"], version or ""), []).append((lib, so_metadata))
    components: list[Component] = []
    for (name, version), members in sorted(groups.items()):
        abis = sorted({
            loc.get("abi")
            for lib, _meta in members
            for loc in lib.get("locations") or []
            if loc.get("abi")
        })
        src_files = sorted({
            loc["entry_name"]
            for lib, _meta in members
            for loc in lib.get("locations") or []
        })
        build_ids = sorted({
            f"{loc['abi']}:{build}"
            for lib, meta in members
            if (build := _so_version_and_build_id(meta)[1])
            for loc in lib.get("locations") or []
            if loc.get("abi")
        })
        functions = sorted({
            f.get("name")
            for _lib, meta in members
            for f in meta.get("functions", [])
            if f.get("name") and not f.get("name").startswith("_")
        })
        needed = sorted({
            entry.get("name")
            for _lib, meta in members
            for entry in meta.get("dynamic_entries", [])
            if entry.get("tag") == "NEEDED" and entry.get("name")
        })
        platform_needed = sorted(
            n for n in needed if n in NDK_PLATFORM_LIBRARIES
        )
        purl = PackageURL(
            type="android",
            name=name,
            version=version or None,
            qualifiers={"abi": ",".join(abis)} if abis else {},
        ).to_string()
        properties = [
            Property(name="internal:srcFile", value="\n".join(src_files)),
            Property(name="internal:appFile", value=app_file),
            Property(name="internal:abis", value=",".join(abis)),
            Property(name="internal:functions", value=SYMBOL_DELIMITER.join(functions)),
        ]
        # Framework identification (04/B, rule 38): when every member of
        # this group carries the same replace-grade identification, the
        # framework component takes the file component's slot - the file is
        # the distribution unit of the project, and emitting both would
        # double-count the same bytes. The identity comes only from the
        # named evidence in the records; the file name becomes a hint.
        framework_record = _replacing_framework_record(members)
        identity = framework_identity(framework_record, abis) if framework_record else None
        component_name, component_version = name, version or None
        static_records: list[dict] = []
        if identity:
            component_name, component_version, purl = identity
            properties.append(Property(name="blint:hint:file_name", value=name))
            properties += _evidence_properties(framework_record)
            for hint in framework_record.get("hints") or []:
                properties.append(Property(name="blint:identification:hint", value=hint))
            static_records = framework_record.get("nested") or []
        else:
            # The file keeps its own identity. A static copy with exact
            # evidence (a re-exported BORINGSSL_* surface) nests as a child;
            # anything weaker is a property on the file component.
            for record in _group_hint_records(members):
                if record.get("static") and not record.get("hint_only"):
                    static_records.append(record)
                    continue
                values = [
                    f"{e.get('what')} ({e.get('where')}): {e.get('value')}"
                    for e in record.get("evidence") or []
                ]
                if values:
                    properties.append(
                        Property(
                            name=f"blint:identification:{record['framework']}",
                            value="; ".join(values),
                        )
                    )
        db_replace, db_records, db_properties = _group_blintdb_identity(
            members, framework_record, can_replace=identity is None
        )
        properties += db_properties
        if db_replace is not None:
            component_name = db_replace["project"]
            component_version = db_replace.get("version")
            purl = _blintdb_component_purl(db_replace, abis)
            properties.append(Property(name="blint:hint:file_name", value=name))
            properties += _blintdb_evidence_properties(db_replace)
        if build_ids:
            properties.append(
                Property(name="blint:build_id", value=",".join(build_ids))
            )
        if platform_needed:
            properties.append(
                Property(
                    name="blint:platform_needed",
                    value=",".join(platform_needed),
                )
            )
        component = Component(
            type=Type.library,
            name=component_name,
            version=component_version,
            purl=purl,
            scope=Scope.required,
            evidence=create_component_evidence(src_files[0] if src_files else app_file, 0.6),
            properties=properties,
        )
        component.bom_ref = RefType(purl)
        if children := _nested_framework_components(static_records, abis, purl):
            # Statically linked frameworks ride as child components of the
            # host - never as second copies of the host at top level.
            component.components = children
        if nested_db := _nested_blintdb_components(db_records, abis, purl):
            component.components = (component.components or []) + nested_db
        components.append(component)
    return components


def _evidence_properties(record: dict) -> list[Property]:
    """One ``blint:identification:evidence`` property per evidence entry."""
    return [
        Property(
            name="blint:identification:evidence",
            value=f"{record['framework']}: {e.get('what')} ({e.get('where')}): {e.get('value')}",
        )
        for e in record.get("evidence") or []
    ]


def _group_blintdb_identity(
    members: list[tuple[dict, dict]], framework_record: dict | None, *, can_replace: bool
) -> tuple[dict | None, list[dict], list[Property]]:
    """The group's blintdb replace record, nested records and drop counts.

    A framework record for the same bytes wins, a SONAME agreement may
    replace the host's identity when no framework identity holds the slot,
    and every other match nests.
    """
    framework_keys = {
        record.get("framework")
        for record in ([framework_record] if framework_record else [])
        + _group_hint_records(members)
    }
    records, superseded = _collect_group_blintdb_records(members, framework_keys)
    properties: list[Property] = []
    if superseded:
        properties.append(
            Property(
                name="blint:blintdb:superseded_by_framework",
                value="; ".join(sorted(set(superseded))),
            )
        )
    group_names = [n for _lib, meta in members for n in dynamic_symbol_names(meta)]
    refused = {
        record["soname"]
        for record in records
        if record["project"] == "openssl"
        and refuses_openssl_match(record["soname"], group_names, framework_keys)
    }
    if refused:
        records = [
            r for r in records if not (r["project"] == "openssl" and r["soname"] in refused)
        ]
        properties.append(
            Property(name="blint:blintdb:refused_provider_shape", value="; ".join(sorted(refused)))
        )
    replace = _blintdb_replace_record(members, records) if can_replace else None
    if replace is not None:
        records = [r for r in records if r is not replace]
    return replace, records, properties


def _attach_blintdb_records(so_metadata: dict, member_path: str) -> None:
    """Match one parsed .so against blintdb and attach identification records.

    The member path is needed for the version rules, which read the file's
    own strings.
    """
    try:
        detected, evidence = detect_binaries_utilized(
            symbol_source_map=build_symbol_source_map(so_metadata),
            function_hash_index=build_function_hash_index(so_metadata),
            binary_metadata=so_metadata,
        )
        if detected:
            so_metadata["blintdb_records"] = blintdb_records(
                so_metadata, detected, evidence, _version_bearing_strings(member_path)
            )
    except Exception as e:  # a database problem must not sink the app's SBOM
        LOG.debug(f"blintdb matching failed for {member_path}: {type(e).__name__}: {e}")


# A whole printable run (``strings -a``), short enough to be a version
# string, and the digit-dot-digit or date shape every version rule needs.
_PRINTABLE_RUN_RE = re.compile(rb"(?<![\x20-\x7e])[\x20-\x7e]{4,200}(?![\x20-\x7e])")
_VERSION_SHAPE_RE = re.compile(rb"\d[.-]\d")


def _version_bearing_strings(member_path: str) -> list[bytes]:
    """The file's printable runs that could carry a version.

    Read from the raw bytes: LIEF's string iterator skips sections, and
    libvlc's ``libpng version 1.6.50`` banner is invisible to it.
    """
    try:
        with open(member_path, "rb") as fh:
            data = fh.read()
    except OSError as e:
        LOG.debug(f"string read failed for {member_path}: {e}")
        return []
    return [
        run.group()
        for run in _PRINTABLE_RUN_RE.finditer(data)
        if _VERSION_SHAPE_RE.search(run.group())
    ]


def _collect_group_blintdb_records(
    members: list[tuple[dict, dict]], framework_keys: set[str]
) -> tuple[list[dict], list[str]]:
    """One record per project for the group, minus framework-claimed ones.

    The strongest member's record stands for the project, and ``abis``
    lists the ABIs whose copy matched: a child is a fact per ABI (rule 36).
    """
    merged: dict[str, dict] = {}
    abis: dict[str, set[str]] = {}
    superseded: list[str] = []
    for lib, meta in members:
        records, dropped = superseded_by_framework(
            meta.get("blintdb_records") or [], framework_keys
        )
        superseded += dropped
        for record in records:
            project = record["project"]
            current = merged.get(project)
            if current is None or (record.get("score") or 0) > (current.get("score") or 0):
                merged[project] = record
            abis.setdefault(project, set()).update(
                loc["abi"] for loc in lib.get("locations") or [] if loc.get("abi")
            )
    return [
        {**record, "abis": sorted(abis[project])} for project, record in merged.items()
    ], superseded


def _blintdb_replace_record(members: list[tuple[dict, dict]], records: list[dict]) -> dict | None:
    """The record that may replace the group's identity, or None.

    Structural rule: every member of the group carries the record AND every
    member's declared DT_SONAME is one of the project's own library names in
    the database - the host *is* the project's library. A file name alone is
    a hint; a partial (single-ABI) agreement keeps the file's identity and
    nests instead.
    """
    for record in records:
        project = record["project"]
        if not record.get("soname_match"):
            continue
        agreed = all(
            any(
                r.get("project") == project and r.get("soname_match")
                for r in (meta.get("blintdb_records") or [])
            )
            for _lib, meta in members
        )
        if agreed:
            return record
    return None


def _blintdb_component_purl(record: dict, abis: list[str]) -> str:
    """The database purl's identity with the artifact's version."""
    base = PackageURL.from_string(record["project_purl"])
    return PackageURL(
        type=base.type,
        namespace=base.namespace,
        name=base.name,
        version=record.get("version"),
        qualifiers={"abi": ",".join(sorted(abis))} if abis else {},
    ).to_string()


def _blintdb_evidence_properties(record: dict) -> list[Property]:
    properties = [
        Property(
            name="blint:identification:evidence",
            value=f"{record['project']}: {e.get('what')} ({e.get('where')}): {e.get('value')}",
        )
        for e in record.get("evidence") or []
    ]
    properties.append(Property(name="blint:blintdb:project_purl", value=record["project_purl"]))
    if record.get("score") is not None:
        properties.append(Property(name="blint:blintdb:score", value=str(record["score"])))
    if record.get("soname_match"):
        properties.append(
            Property(
                name="blint:blintdb:soname_match",
                value=f"{record['soname']} = {', '.join(record['matched_binary_names'])}",
            )
        )
    return properties


def _nested_blintdb_components(
    records: list[dict], abis: list[str], host_purl: str
) -> list[Component]:
    """Child components for the static copies blintdb found in a host.

    Bom-refs are scoped by the host, like the framework children.
    """
    children: list[Component] = []
    for record in records:
        purl = _blintdb_component_purl(record, record.get("abis") or abis)
        child = Component(
            type=Type.library,
            name=record["project"],
            version=record.get("version"),
            purl=purl,
            properties=_blintdb_evidence_properties(record),
        )
        child.bom_ref = RefType(f"{host_purl}|{purl}")
        children.append(child)
    return children


def _nested_framework_components(
    records: list[dict], abis: list[str], host_purl: str
) -> list[Component]:
    """Child components for static identifications inside a host library.

    The bom-ref is scoped by the host's, so two hosts carrying the same
    static copy in one ABI never share a ref.
    """
    from blint.lib.framework_ident import NESTED_COMPONENTS

    children: list[Component] = []
    for nested in records:
        entry = NESTED_COMPONENTS.get(nested.get("framework") or "")
        if not entry:
            continue
        purl_type, namespace, name = entry["purl"]
        qualifiers = {"abi": ",".join(sorted(abis))} if abis else {}
        purl = PackageURL(
            type=purl_type,
            namespace=namespace,
            name=name,
            version=nested.get("version") or None,
            qualifiers=qualifiers,
        ).to_string()
        child = Component(
            type=Type.library,
            name=entry["name"],
            version=nested.get("version") or None,
            purl=purl,
            properties=_evidence_properties(nested),
        )
        child.bom_ref = RefType(f"{host_purl}|{purl}")
        children.append(child)
    return children


def _group_hint_records(members: list[tuple[dict, dict]]) -> list[dict]:
    """Non-replacing framework records common to every member of a group."""
    seen: dict[tuple, dict] = {}
    common: list[tuple] | None = None
    for _lib, meta in members:
        records = meta.get("frameworks") or []
        keys = []
        for record in records:
            key = (record.get("framework"), record.get("version"))
            keys.append(key)
            seen.setdefault(key, record)
        if common is None:
            common = keys
        else:
            common = [k for k in common if k in keys]
    if not common:
        return []
    return [seen[k] for k in common]


def _replacing_framework_record(members: list[tuple[dict, dict]]) -> dict | None:
    """One replace-grade identification for a (name, version) group, or None.

    Every parsed member must carry the same framework record (same
    framework key and version) and that framework must be in the component
    table, so a half-identified multi-ABI build never rewrites the group's
    identity. Static identifications (a framework inside a host library)
    and hint-only records never replace.
    """
    from blint.lib.framework_ident import FRAMEWORK_COMPONENTS

    seen: tuple | None = None
    for _lib, meta in members:
        records = meta.get("frameworks") or []
        replacing = [
            r for r in records
            if not r.get("static")
            and not r.get("hint_only")
            and (r.get("framework") or "") in FRAMEWORK_COMPONENTS
        ]
        if len(replacing) != 1:
            return None
        record = replacing[0]
        key = (record.get("framework"), record.get("version"))
        if seen is None:
            seen = key
        elif seen != key:
            return None
    if seen is None:
        return None
    for _lib, meta in members:
        for r in meta.get("frameworks") or []:
            if not r.get("static") and (r.get("framework"), r.get("version")) == seen:
                return r
    return None


def parse_so_file(app_file: str, app_temp_dir: str, sof: str) -> Component:
    """Parses the given shared object (SO) file and generates metadata for it.

    Args:
        app_file: The path of the application file.
        app_temp_dir: The temporary directory of the application.
        sof: The path of the shared object file.

    Returns:
        Component: A Component object representing the parsed SO file.
    """
    so_metadata = parse(sof)
    name = os.path.basename(sof).removesuffix(".so").removeprefix("lib")
    rel_path = os.path.relpath(sof, app_temp_dir)
    group = ""
    arch = ""
    # Extract architecture from file
    # apk: lib/arm64-v8a/libsentry-android.so
    # aab: base/lib/armeabi-v7a/libsqlite3x.so
    if "lib" in rel_path:
        arch = rel_path.split(f"lib{os.sep}")[-1].split(os.sep)[0]
    # Retrieve the version number from notes
    version = get_so_version(so_metadata.get("notes", []))
    functions = [
        f.get("name")
        for f in so_metadata.get("functions", [])
        if f.get("name") and not f.get("name").startswith("_")
    ]
    purl = f"pkg:android/{name}"
    if version:
        purl = f"{purl}@{version}"
    if arch:
        purl = f"{purl}?arch={arch}"
    component = Component(
        type=Type.library,
        group=group,
        name=name,
        version=version,
        purl=purl,
        scope=Scope.required,
        evidence=create_component_evidence(str(rel_path), 0.5),
        properties=[
            Property(name="internal:srcFile", value=rel_path),
            Property(name="internal:appFile", value=app_file),
            Property(name="internal:functions", value=SYMBOL_DELIMITER.join(set(functions))),
        ],
    )
    component.bom_ref = RefType(purl)
    return component


def get_so_version(so_metadata_notes: list[dict]) -> str | None:
    """Returns the version of the shared object (SO) file.

    Args:
        so_metadata_notes: The metadata notes of the SO file.

    Returns:
        str | None: The version of the SO file or None.
    """
    version = None
    for anote in so_metadata_notes:
        if anote.get("version"):
            version = anote.get("version")
            break
        if anote.get("build_id"):
            version = anote.get("build_id")
            break
    return version


def collect_dex_files_metadata(
    app_file: str, parent_component: Component | None, app_temp_dir: str
) -> list[Component]:
    """
    Collects metadata for DEX files in the given app temporary directory.

    Args:
        app_file (str): The path to the app file
        parent_component (Component or None): The parent component, if available
        app_temp_dir (str): The path to the app temporary directory

    Returns:
        list: A list of Component objects, each representing a DEX file.
    """
    file_components = []
    # Parse all .dex files
    dex_files = find_files(app_temp_dir, [".dex"])
    for adex in dex_files:
        dex_metadata = parse_dex(adex)
        name = os.path.basename(adex).removesuffix(".dex")
        rel_path = os.path.relpath(adex, app_temp_dir)
        group = parent_component.group if parent_component and parent_component.group else ""
        version = (
            parent_component.version if parent_component and parent_component.version else None
        )
        findings = analyze_dex_behaviours(dex_metadata)
        component = create_dex_component(
            app_file, dex_metadata, group, name, rel_path, version, findings
        )
        file_components.append(component)
    return file_components


def _iter_app_dex_files(app_file: str) -> Iterator[tuple[str, str]]:
    """
    Yield ``(dex_path, app_temp_dir)`` for every dex inside an app or bundle.

    Bundles (.apkm/.apks/.xapk) are unzipped to locate their inner apks; each
    apk (or the app itself) is then unzipped to a temp dir whose dex files are
    yielded. The caller is responsible for nothing - all temp dirs are cleaned
    up once iteration completes.
    """
    bundle_temp_dir = None
    app_temp_dirs = []
    budget = CumulativeExtractionBudget(MAX_APP_EXTRACTION_BUDGET)
    try:
        if app_file.endswith(BUNDLE_EXTENSIONS):
            bundle_temp_dir = tempfile.mkdtemp(prefix="blint_android_bundle")
            _extract_app_zip(app_file, bundle_temp_dir, budget=budget)
            targets = sorted(find_files(bundle_temp_dir, [".apk"]))
        else:
            targets = [app_file]
        for apk in targets:
            app_temp_dir = tempfile.mkdtemp(prefix="blint_android_dex")
            app_temp_dirs.append(app_temp_dir)
            _extract_app_zip(apk, app_temp_dir, budget=budget)
            for adex in sorted(find_files(app_temp_dir, [".dex"])):
                yield adex, app_temp_dir
    finally:
        for d in app_temp_dirs:
            shutil.rmtree(d, ignore_errors=True)
        if bundle_temp_dir:
            shutil.rmtree(bundle_temp_dir, ignore_errors=True)


def analyze_android_app(app_file: str, build_cg: bool = False) -> dict | None:
    """
    Build review-ready metadata for an android app in the default analysis mode.

    Extracts every dex from the app (or bundle), disassembles their methods and
    aggregates the resolved invoke/field descriptors and string constants into a
    single ``dexbinary`` metadata dict that the shared :class:`ReviewRunner`
    consumes. When ``build_cg`` is set, a merged Dalvik callgraph is attached.

    Returns:
        A metadata dict with ``exe_type``/``functions``/``informative_strings``
        (and optionally ``callgraph``), or ``None`` when no dex could be read.
    """
    functions: set = set()
    strings: set = set()
    dex_count = 0
    for adex, _ in _iter_app_dex_files(app_file):
        try:
            review_metadata = build_review_metadata(parse_dex(adex))
        except Exception as e:  # a malformed dex must not abort the whole app
            LOG.debug(f"Failed to build review metadata for {adex}: {e}")
            continue
        dex_count += 1
        functions.update(fn.get("name", "") for fn in review_metadata.get("functions", []))
        strings.update(review_metadata.get("informative_strings", []))
    if not dex_count:
        return None
    metadata: dict = {
        "name": os.path.basename(app_file),
        "exe_type": DEX_EXE_TYPE,
        "functions": [{"name": fn} for fn in sorted(f for f in functions if f)],
        "informative_strings": sorted(s for s in strings if s),
    }
    if build_cg:
        try:
            metadata["callgraph"] = build_app_dex_callgraph(app_file)
        except Exception as e:  # callgraph is best-effort
            LOG.debug(f"Failed to build dex callgraph for {app_file}: {e}")
    return metadata


def build_app_dex_callgraph(app_file: str) -> dict:
    """
    Build a merged Dalvik callgraph for every dex in an app (or bundle).

    This re-reads the app and disassembles each dex, so it is intentionally
    only invoked on demand (it is not part of the default SBOM path). Returns a
    callgraph dict ``{"nodes": [...], "edges": [...]}``.
    """
    from blint.lib.dalvik_callgraph import build_callgraph, merge_callgraphs

    targets = []
    bundle_temp_dir = None
    budget = CumulativeExtractionBudget(MAX_APP_EXTRACTION_BUDGET)
    try:
        if app_file.endswith(BUNDLE_EXTENSIONS):
            bundle_temp_dir = tempfile.mkdtemp(prefix="blint_android_bundle")
            _extract_app_zip(app_file, bundle_temp_dir, budget=budget)
            targets = sorted(find_files(bundle_temp_dir, [".apk"]))
        else:
            targets = [app_file]
        per_dex = []
        for apk in targets:
            app_temp_dir = tempfile.mkdtemp(prefix="blint_android_cg")
            try:
                _extract_app_zip(apk, app_temp_dir, budget=budget)
                for adex in find_files(app_temp_dir, [".dex"]):
                    per_dex.append(build_callgraph(parse_dex(adex)))
            finally:
                shutil.rmtree(app_temp_dir, ignore_errors=True)
        return merge_callgraphs(per_dex)
    finally:
        if bundle_temp_dir:
            shutil.rmtree(bundle_temp_dir, ignore_errors=True)


def analyze_dex_behaviours(dex_metadata: dict) -> list[Finding]:
    """
    Run the Dalvik behavioural review over a parsed dex.

    The review disassembles the dex methods and flags risky behaviours
    (dynamic code loading, reflection, native exec, weak crypto, etc.).
    Failures are non-fatal: dex metadata collection proceeds without findings.
    """
    try:
        return analyze_dex(dex_metadata)
    except Exception as e:  # behavioural review must never break SBOM generation
        LOG.debug(f"Dalvik behavioural review failed: {e}")
        return []


def create_dex_component(
    app_file: str,
    dex_metadata: dict,
    group: str,
    name: str,
    rel_path: str,
    version: Any,
    findings: list[Finding] | None = None,
) -> Component:
    """
    Creates a Component object with the provided metadata for a DEX file.

    Args:
        app_file (str): The path to the app file.
        dex_metadata (dict): The metadata of the DEX file.
        group (str): The group of the component.
        name (LiteralString | bytes): The name of the component.
        rel_path (str | LiteralString |bytes): The relative path.
        version (str | None): The version of the component.

    Returns:
        Component: A Component object representing the DEX file with metadata.
    """
    purl = f"pkg:android/{name}"
    if version:
        purl = f"{purl}@{version}"
    functions = sorted(
        {
            _format_dex_method(m)
            for m in (dex_metadata.get("methods") or [])
            if _format_dex_method(m)
        }
    )
    classes = sorted(
        {_clean_type(c.fullname) for c in (dex_metadata.get("classes") or []) if c.fullname}
    )
    properties = [
        Property(name="internal:srcFile", value=rel_path),
        Property(name="internal:appFile", value=app_file),
        Property(name="internal:functions", value=SYMBOL_DELIMITER.join(functions)),
        Property(name="internal:classes", value=SYMBOL_DELIMITER.join(classes)),
    ]
    properties += build_behaviour_properties(findings)
    comp = Component(
        type=Type.file,
        group=group,
        name=name,
        version=version,
        purl=purl,
        scope=Scope.required,
        evidence=create_component_evidence(rel_path, 0.2),
        properties=properties,
    )
    comp.bom_ref = RefType(purl)
    return comp


def build_behaviour_properties(findings: list[Finding] | None) -> list[Property]:
    """
    Render Dalvik behavioural findings as component properties.

    Each finding becomes ``internal:behaviour:<ID>`` = ``<severity>|<count>|<sample>``
    and a single ``internal:behaviours`` property lists the triggered rule ids, so
    downstream consumers (atom-tools) can read them straight off the BOM.
    """
    if not findings:
        return []
    properties = [
        Property(
            name="internal:behaviours",
            value=",".join(f.id for f in findings),
        )
    ]
    for f in findings:
        sample = f.evidence[0] if f.evidence else ""
        properties.append(
            Property(name=f"internal:behaviour:{f.id}", value=f"{f.severity}|{f.count}|{sample}")
        )
    return properties


def _format_dex_method(method) -> str:
    """
    Format a single dex method as ``name(paramTypes):returnType``.

    DEX methods produced by LIEF may lack a prototype (e.g. abstract or synthetic
    members) so the prototype access is guarded; an unparseable method is skipped
    rather than aborting metadata collection for the whole dex file.
    """
    try:
        prototype = method.prototype
        params = ",".join(_clean_type(p.underlying_array_type) for p in prototype.parameters_type)
        return_type = _clean_type(prototype.return_type.underlying_array_type)
        return f"{method.name}({params}):{return_type}"
    except (AttributeError, TypeError):
        return method.name or ""


def _clean_type(t: Any) -> str:
    """
    Cleans the type string by replacing "/", removing the leading "L" and
    trailing ";".

    Args:
        t (str): The type string to clean.

    Returns:
        str: The cleaned type string.
    """
    return str(t).replace("/", ".").removeprefix("L").removesuffix(";")


def collect_files_metadata(
    app_file: str,
    parent_component: Component | None,
    deep_mode: bool,
    unpack_target: str | None = None,
    app_facts: dict | None = None,
    use_blintdb: bool = False,
    budget: CumulativeExtractionBudget | None = None,
) -> list[Component]:
    """
    Unzip the app (or a specific apk within a bundle) and collect metadata.

    Args:
        app_file (str): Path reported as the originating application file.
        parent_component (Component or None): The parent component, if available.
        deep_mode (bool): Flag indicating whether to parse dex files.
        unpack_target (str): Specific apk to unpack. Defaults to ``app_file``.
        use_blintdb (bool): Match native libraries against the local blintdb.
        budget (CumulativeExtractionBudget or None): Shared extraction budget
            for the whole bundle when unpacking inner apks; a fresh one is
            used when the app stands alone.

    Returns:
        list: A list of Component objects.
    """
    file_components = []
    app_temp_dir = tempfile.mkdtemp(prefix="blint_android_app")
    # finally, not a trailing call: SBOM mode has no per-unit isolation, so an
    # exception anywhere below would otherwise leave the whole extracted APK on
    # disk (ground rule 18).
    try:
        _extract_app_zip(unpack_target or app_file, app_temp_dir, budget=budget)
        file_components += collect_version_files_metadata(app_file, app_temp_dir)
        # Native libraries come from the zip in place (A1.1 model), not from
        # the unzip tree.
        file_components += collect_so_files_metadata(
            app_file, app_facts=app_facts, use_blintdb=use_blintdb
        )
        if deep_mode:
            file_components += collect_dex_files_metadata(app_file, parent_component, app_temp_dir)
    finally:
        shutil.rmtree(app_temp_dir, ignore_errors=True)
    return file_components


def parse_apk_summary(data: str | None) -> Component | None:
    """
    Parse output from apk summary
    """
    if data and (parts := data.strip().split("\n")[-1].split("\t")):
        name = parts[0]
        version = parts[-1]
        purl = f"pkg:android/{name}@{version}"
        component = Component(type=Type.application, name=name, version=version, purl=purl)
        component.bom_ref = RefType(purl)
        return component
    return None
