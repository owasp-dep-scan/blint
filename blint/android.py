import os
import shutil
import subprocess
import sys
import tempfile

from blint.binary import parse, parse_dex
from blint.config import SYMBOL_DELIMITER
from blint.cyclonedx.spec import (
    Component,
    Property,
    RefType,
    Scope,
    Type,
)
from blint.logger import LOG
from blint.utils import check_command, create_component_evidence, find_files, unzip_unsafe

ANDROID_HOME = os.getenv("ANDROID_HOME")
APKANALYZER_CMD = os.getenv("APKANALYZER_CMD")
if not APKANALYZER_CMD and ANDROID_HOME and os.path.exists(os.path.join(ANDROID_HOME, "cmdline-tools", "latest", "bin", "apkanalyzer")):
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
    Collect various metadata about an android app
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
    components = collect_files_metadata(app_file, parent_component, deep_mode)
    return parent_component, components


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
    if "JAVA_TOOL_OPTIONS" in data:
        parts = data.split("\n")
        if parts and len(parts) > 0:
            parts.pop(0)
        return "\n".join(parts)
    return ""


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
        with open(vf, encoding="utf-8") as fp:
            version_data = fp.read().strip()
            # Sometimes the version data could be dynamic. Eg:
            #   task ':lifecycle:lifecycle-viewmodel:writeVersionFile' property 'version'"
            # These can be treated as dynamic
            if version_data and version_data.startswith("task"):
                version_data = "dynamic"
        if name and version_data:
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
    if group:
        purl = f"pkg:maven/{group}/{name}@{version_data}"
    else:
        purl = f"pkg:maven/{name}@{version_data}"
    confidence = 1.0
    # Adjust the confidence based on the version data
    if version_data in ("latest", "dynamic"):
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
    purl = f"pkg:generic/{name}@{version}"
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


def get_so_version(so_metadata_notes):
    """Returns the version of the shared object (SO) file.

    Args:
        so_metadata_notes: The metadata notes of the SO file.

    Returns:
        str: The version of the SO file.
    """
    version = "latest"
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
            parent_component.version if parent_component and parent_component.version else "latest"
        )
        component = create_dex_component(app_file, dex_metadata, group, name, rel_path, version)
        file_components.append(component)
    return file_components


def create_dex_component(app_file, dex_metadata, group, name, rel_path, version):
    """
    Creates a Component object with the provided metadata for a DEX file.

    Args:
        app_file (str): The path to the app file.
        dex_metadata (dict): The metadata of the DEX file.
        group (str): The group of the component.
        name (LiteralString | bytes): The name of the component.
        rel_path (str | LiteralString |bytes): The relative path.
        version (str): The version of the component.

    Returns:
        Component: A Component object representing the DEX file with metadata.
    """
    purl = f"pkg:generic/{name}@{version}"
    comp = Component(
        type=Type.file,
        group=group,
        name=name,
        version=version,
        purl=purl,
        scope=Scope.required,
        evidence=create_component_evidence(rel_path, 0.2),
        properties=[
            Property(name="internal:srcFile", value=rel_path),
            Property(name="internal:appFile", value=app_file),
            Property(
                name="internal:functions",
                value=SYMBOL_DELIMITER.join(
                    {
                        f"""{m.name}({','.join([_clean_type(p.underlying_array_type) for p in m.prototype.parameters_type])}):{_clean_type(m.prototype.return_type.underlying_array_type)}"""
                        for m in dex_metadata.get("methods")
                    }
                ),
            ),
            Property(
                name="internal:classes",
                value=SYMBOL_DELIMITER.join(
                    set(sorted([_clean_type(c.fullname) for c in dex_metadata.get("classes")]))
                ),
            ),
        ],
    )
    comp.bom_ref = RefType(purl)
    return comp


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


def collect_files_metadata(app_file, parent_component, deep_mode):
    """
    Unzip the app and collect metadata
    """
    file_components = []
    app_temp_dir = tempfile.mkdtemp(prefix="blint_android_app")
    unzip_unsafe(app_file, app_temp_dir)
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
        purl = f"pkg:apk/{name}@{version}"
        component = Component(type=Type.application, name=name, version=version, purl=purl)
        component.bom_ref = RefType(purl)
        return component
    return None
