import json
import os
import shutil
import subprocess
import sys
import tempfile
from xml.etree import ElementTree

from custom_json_diff.lib.utils import file_read

from blint.config import SYMBOL_DELIMITER
from blint.cyclonedx.spec import Component, Property, RefType, Scope, Type
from blint.lib.binary import parse, parse_dex
from blint.lib.dalvik_review import analyze_dex
from blint.lib.utils import (
    check_command,
    create_component_evidence,
    find_files,
    unzip_unsafe,
)
from blint.logger import LOG

try:
    from apkInspector.axml import parse_apk_for_manifest
except ImportError:  # pragma: no cover - apkInspector is an optional dependency
    parse_apk_for_manifest = None

# Namespace used for android specific attributes in a decoded manifest.
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
# Split bundle archives. APKMirror bundles (.apkm) and split bundles
# (.apks/.xapk) are zip archives that contain a base apk along with
# configuration splits.
BUNDLE_EXTENSIONS = (".apkm", ".apks", ".xapk")

ANDROID_HOME = os.getenv("ANDROID_HOME")
APKANALYZER_CMD = os.getenv("APKANALYZER_CMD")
if (
    not APKANALYZER_CMD
    and ANDROID_HOME
    and os.path.exists(os.path.join(ANDROID_HOME, "cmdline-tools", "latest", "bin", "apkanalyzer"))
):
    APKANALYZER_CMD = os.path.join(ANDROID_HOME, "cmdline-tools", "latest", "bin", "apkanalyzer")
elif check_command("apkanalyzer"):
    APKANALYZER_CMD = "apkanalyzer"


def exec_tool(args, cwd=None, stdout=subprocess.PIPE):
    """
    Convenience method to invoke cli tools

    :param args: Command line arguments
    :param cwd: Working directory
    :param stdout: Specifies stdout of command
    """
    try:
        LOG.debug(f'⚡︎ Executing "{" ".join(args)}"')
        return subprocess.run(
            args,
            stdout=stdout,
            stderr=subprocess.STDOUT,
            cwd=cwd,
            env=os.environ.copy(),
            shell=sys.platform == "win32",
            encoding="utf-8",
            check=False,
        )
    except subprocess.SubprocessError as e:
        LOG.exception(e)
        return None


def collect_app_metadata(app_file, deep_mode):
    """
    Collect various metadata about an android app.

    Both single apk files and split bundles (``.apkm``, ``.apks``, ``.xapk``)
    are supported.
    """
    if app_file.endswith(BUNDLE_EXTENSIONS):
        return collect_bundle_metadata(app_file, deep_mode)
    parent_component = apk_parent_component(app_file)
    components = collect_files_metadata(app_file, parent_component, deep_mode)
    return parent_component, components


def collect_bundle_metadata(app_file, deep_mode):
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
    file_components = []
    parent_component = None
    try:
        unzip_unsafe(app_file, bundle_temp_dir)
        bundle_info = read_bundle_info(bundle_temp_dir)
        apk_files = sorted(find_files(bundle_temp_dir, [".apk"]))
        if not apk_files:
            LOG.warning("No apk files were found in the bundle %s", app_file)
        base_apk = select_base_apk(apk_files)
        if base_apk:
            parent_component = apk_parent_component(app_file, base_apk, bundle_info)
        for apk in apk_files:
            file_components += collect_files_metadata(
                app_file, parent_component, deep_mode, unpack_target=apk
            )
    finally:
        shutil.rmtree(bundle_temp_dir, ignore_errors=True)
    return parent_component, file_components


def read_bundle_info(bundle_temp_dir):
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


def select_base_apk(apk_files):
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


def apk_parent_component(app_file, manifest_apk=None, bundle_info=None):
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


def read_manifest_attributes(apk_file):
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
        root = ElementTree.fromstring(raw_xml)
    except ElementTree.ParseError as e:
        LOG.debug(f"Unable to parse the decoded manifest for {apk_file}: {e}")
        return {}
    attributes = {
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
    return attributes


def find_main_activity(root):
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
                return activity.get(f"{ANDROID_NS}name", "")
    return ""


def build_parent_component(manifest, app_file, bundle_info=None):
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


def build_manifest_properties(manifest, bundle_info=None):
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


def apk_summary_fallback(app_file):
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


def apk_summary(app_file):
    """
    Retrieve the parent component using apk summary
    """
    if not app_file.endswith(".apk") or not APKANALYZER_CMD:
        return None
    cp = exec_tool([APKANALYZER_CMD, "apk", "summary", app_file])
    return parse_apk_summary(cp.stdout) if cp and cp.returncode == 0 else None


def apk_features(app_file):
    """
    Retrieve the app features
    """
    if not app_file.endswith(".apk") or not APKANALYZER_CMD:
        return None
    cp = exec_tool([APKANALYZER_CMD, "apk", "features", app_file])
    return strip_apk_data(cp.stdout.strip()) if cp and cp.returncode == 0 else ""


def apk_permissions(app_file):
    """
    Retrieve the app permissions
    """
    if not app_file.endswith(".apk") or not APKANALYZER_CMD:
        return None
    cp = exec_tool([APKANALYZER_CMD, "manifest", "permissions", app_file])
    return strip_apk_data(cp.stdout.strip()) if cp and cp.returncode == 0 else ""


def strip_apk_data(data):
    """Strips the APK data by removing the first line if it contains "JAVA_TOOL_OPTIONS".
    Args:
        data (str): The input data to be stripped.

    Returns:
        str: The stripped data.
    """
    parts = data.split("\n")
    if "JAVA_TOOL_OPTIONS" in data:
        if parts and len(parts) > 0:
            parts.pop(0)
    return "\n".join(parts)


def collect_version_files_metadata(app_file, app_temp_dir):
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


def create_version_component(app_file, group, name, rel_path, version_data):
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


def parse_file_name(file_name, group):
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


def collect_so_files_metadata(app_file, app_temp_dir):
    """
    Collects metadata for shared object (`.so`) files.

    Args:
        app_file (str): The path to the app file.
        app_temp_dir (str): The path to the app temporary directory.

    Returns:
        list: A list of Component objects.
    """
    file_components = []
    # Parse all .so files
    so_files = find_files(app_temp_dir, [".so"])
    for sof in so_files:
        component = parse_so_file(app_file, app_temp_dir, sof)
        file_components.append(component)
    return file_components


def parse_so_file(app_file, app_temp_dir, sof):
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


def get_so_version(so_metadata_notes) -> str | None:
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


def collect_dex_files_metadata(app_file, parent_component, app_temp_dir):
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


def build_app_dex_callgraph(app_file):
    """
    Build a merged Dalvik callgraph for every dex in an app (or bundle).

    This re-reads the app and disassembles each dex, so it is intentionally
    only invoked on demand (it is not part of the default SBOM path). Returns a
    callgraph dict ``{"nodes": [...], "edges": [...]}``.
    """
    from blint.lib.dalvik_callgraph import build_callgraph, merge_callgraphs

    targets = []
    bundle_temp_dir = None
    try:
        if app_file.endswith(BUNDLE_EXTENSIONS):
            bundle_temp_dir = tempfile.mkdtemp(prefix="blint_android_bundle")
            unzip_unsafe(app_file, bundle_temp_dir)
            targets = sorted(find_files(bundle_temp_dir, [".apk"]))
        else:
            targets = [app_file]
        per_dex = []
        for apk in targets:
            app_temp_dir = tempfile.mkdtemp(prefix="blint_android_cg")
            try:
                unzip_unsafe(apk, app_temp_dir)
                for adex in find_files(app_temp_dir, [".dex"]):
                    per_dex.append(build_callgraph(parse_dex(adex)))
            finally:
                shutil.rmtree(app_temp_dir, ignore_errors=True)
        return merge_callgraphs(per_dex)
    finally:
        if bundle_temp_dir:
            shutil.rmtree(bundle_temp_dir, ignore_errors=True)


def analyze_dex_behaviours(dex_metadata):
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


def create_dex_component(app_file, dex_metadata, group, name, rel_path, version, findings=None):
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


def build_behaviour_properties(findings):
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


def _format_dex_method(method):
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


def _clean_type(t):
    """
    Cleans the type string by replacing "/", removing the leading "L" and
    trailing ";".

    Args:
        t (str): The type string to clean.

    Returns:
        str: The cleaned type string.
    """
    return str(t).replace("/", ".").removeprefix("L").removesuffix(";")


def collect_files_metadata(app_file, parent_component, deep_mode, unpack_target=None):
    """
    Unzip the app (or a specific apk within a bundle) and collect metadata.

    Args:
        app_file (str): Path reported as the originating application file.
        parent_component (Component or None): The parent component, if available.
        deep_mode (bool): Flag indicating whether to parse dex files.
        unpack_target (str): Specific apk to unpack. Defaults to ``app_file``.

    Returns:
        list: A list of Component objects.
    """
    file_components = []
    app_temp_dir = tempfile.mkdtemp(prefix="blint_android_app")
    unzip_unsafe(unpack_target or app_file, app_temp_dir)
    file_components += collect_version_files_metadata(app_file, app_temp_dir)
    file_components += collect_so_files_metadata(app_file, app_temp_dir)
    if deep_mode:
        file_components += collect_dex_files_metadata(app_file, parent_component, app_temp_dir)
    shutil.rmtree(app_temp_dir, ignore_errors=True)
    return file_components


def parse_apk_summary(data):
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
