import os
import shutil
import subprocess
import sys
import tempfile

from blint.binary import parse
from blint.cyclonedx.spec import (
    Component,
    ComponentEvidence,
    FieldModel,
    Identity,
    Method,
    Property,
    RefType,
    Scope,
    Technique,
    Type,
)
from blint.logger import LOG
from blint.utils import check_command, find_files, unzip_unsafe

ANDROID_HOME = os.getenv("ANDROID_HOME")
APKANALYZER_CMD = os.getenv("APKANALYZER_CMD")
if (
    not APKANALYZER_CMD
    and ANDROID_HOME
    and os.path.exists(
        os.path.join(
            ANDROID_HOME, "cmdline-tools", "latest", "bin", "apkanalyzer"
        )
    )
):
    APKANALYZER_CMD = os.path.join(
        ANDROID_HOME, "cmdline-tools", "latest", "bin", "apkanalyzer"
    )
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
        LOG.debug('⚡︎ Executing "%s"', " ".join(args))
        cp = subprocess.run(
            args,
            stdout=stdout,
            stderr=subprocess.STDOUT,
            cwd=cwd,
            env=os.environ.copy(),
            shell=sys.platform == "win32",
            encoding="utf-8",
            check=False,
        )
        return cp
    except Exception as e:
        LOG.exception(e)
        return None


def collect_app_metadata(app_file):
    """
    Collect various metadata about an android app
    """
    parent_component = apk_summary(app_file)
    if parent_component:
        parent_component.properties = []
        features = apk_features(app_file)
        if features:
            parent_component.properties.append(
                Property(name="internal.appFeatures", value=features)
            )
        permissions = apk_permissions(app_file)
        if permissions:
            parent_component.properties.append(
                Property(name="internal.appPermissions", value=permissions)
            )
    components = collect_files_metadata(app_file)
    return parent_component, components


def apk_summary(app_file):
    """
    Retrieve the parent component using apk summary
    """
    if not app_file.endswith(".apk") or not APKANALYZER_CMD:
        return None
    cp = exec_tool([APKANALYZER_CMD, "apk", "summary", app_file])
    if cp and cp.returncode == 0:
        return parse_apk_summary(cp.stdout)
    return None


def apk_features(app_file):
    """
    Retrieve the app features
    """
    if not app_file.endswith(".apk") or not APKANALYZER_CMD:
        return None
    cp = exec_tool([APKANALYZER_CMD, "apk", "features", app_file])
    if cp and cp.returncode == 0:
        data = cp.stdout.strip()
        if "JAVA_TOOL_OPTIONS" in data:
            parts = data.split(os.linesep)
            if parts and len(parts) > 1:
                parts.pop(0)
            return "\n".join(parts)
    return None


def apk_permissions(app_file):
    """
    Retrieve the app permissions
    """
    if not app_file.endswith(".apk") or not APKANALYZER_CMD:
        return None
    cp = exec_tool([APKANALYZER_CMD, "manifest", "permissions", app_file])
    if cp and cp.returncode == 0:
        data = cp.stdout.strip()
        if "JAVA_TOOL_OPTIONS" in data:
            parts = data.split(os.linesep)
            if parts and len(parts) > 1:
                parts.pop(0)
            return "\n".join(parts)
    return None


def collect_files_metadata(app_file):
    """
    Unzip the app and collect metadata
    """
    file_components = []
    app_temp_dir = tempfile.mkdtemp(prefix="blint_android_app")
    unzip_unsafe(app_file, app_temp_dir)
    # Find and read all .version files
    version_files = find_files(app_temp_dir, [".version"])
    if version_files:
        for vf in version_files:
            file_name = os.path.basename(vf).removesuffix(".version")
            rel_path = os.path.relpath(vf, app_temp_dir)
            group = ""
            name = ""
            if "_" in file_name:
                parts = file_name.split("_")
                name = file_name
                if parts and len(parts) == 2:
                    group = parts[0]
                    name = parts[-1]
                else:
                    name = name.replace("_", "-")
                    # Patch the group name
                    if name.startswith("kotlinx-"):
                        group = "org.jetbrains.kotlinx"
            with open(vf, encoding="utf-8") as fp:
                version_data = fp.read().strip()
                if name and version_data:
                    if group:
                        purl = f"pkg:maven/{group}/{name}@{version_data}"
                    else:
                        purl = f"pkg:maven/{name}@{version_data}"
                    component = Component(
                        type=Type.library,
                        group=group,
                        name=name,
                        version=version_data,
                        purl=purl,
                        scope=Scope.required,
                        evidence=ComponentEvidence(
                            identity=Identity(
                                field=FieldModel.purl,
                                confidence=1,
                                methods=[
                                    Method(
                                        technique=Technique.manifest_analysis,
                                        value=rel_path,
                                        confidence=1,
                                    )
                                ],
                            )
                        ),
                        properties=[
                            Property(name="internal:srcFile", value=rel_path),
                            Property(name="internal:appFile", value=app_file),
                        ],
                    )
                    component.bom_ref = RefType(purl)
                    file_components.append(component)
    # Parse all .so files
    so_files = find_files(app_temp_dir, [".so"])
    if so_files:
        for sof in so_files:
            so_metadata = parse(sof)
            name = os.path.basename(sof).removesuffix(".so").removeprefix("lib")
            rel_path = os.path.relpath(sof, app_temp_dir)
            group = ""
            version = "latest"
            arch = ""
            functions = []
            # Extract architecture from file
            # apk: lib/arm64-v8a/libsentry-android.so
            # aab: base/lib/armeabi-v7a/libsqlite3x.so
            if "lib" in rel_path:
                arch = rel_path.split(f"lib{os.sep}")[-1].split(os.sep)[0]
            # Retrieve the version number from notes
            for anote in so_metadata.get("notes", []):
                if anote.get("version"):
                    version = anote.get("version")
                    break
                elif anote.get("build_id"):
                    version = anote.get("build_id")
                    break
            if so_metadata.get("functions"):
                functions = [
                    f.get("name")
                    for f in so_metadata.get("functions")
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
                evidence=ComponentEvidence(
                    identity=Identity(
                        field=FieldModel.purl,
                        confidence=0.5,
                        methods=[
                            Method(
                                technique=Technique.binary_analysis,
                                value=rel_path,
                                confidence=0.5,
                            )
                        ],
                    )
                ),
                properties=[
                    Property(name="internal:srcFile", value=rel_path),
                    Property(name="internal:appFile", value=app_file),
                    Property(
                        name="internal:functions",
                        value=", ".join(set(functions)),
                    ),
                ],
            )
            component.bom_ref = RefType(purl)
            file_components.append(component)
    shutil.rmtree(app_temp_dir, ignore_errors=True)
    return file_components


def parse_apk_summary(data):
    """
    Parse output from apk summary
    """
    if data:
        parts = data.strip().split(os.linesep)[-1].split("\t")
        if parts:
            name = parts[0]
            version = parts[-1]
            purl = f"pkg:apk/{name}@{version}"
            component = Component(
                type=Type.application, name=name, version=version, purl=purl
            )
            component.bom_ref = RefType(purl)
            return component
    return None
