import os
import uuid
from datetime import datetime

from rich.progress import Progress

from blint.android import collect_app_metadata
from blint.cyclonedx.spec import (
    BomFormat,
    Component,
    CycloneDX,
    Lifecycles,
    Metadata,
    Phase,
    Tools,
    Type,
    RefType,
)
from blint.logger import LOG
from blint.utils import find_android_files, get_version


def default_parent(src_dirs):
    name = os.path.basename(src_dirs[0])
    purl = f"pkg:generic/{name}@latest"
    component = Component(
        type=Type.application, name=name, version="latest", purl=purl
    )
    component.bom_ref = RefType(purl)
    return component


def default_metadata(src_dirs):
    metadata = Metadata()
    metadata.timestamp = datetime.now()
    metadata.component = default_parent(src_dirs)
    metadata.tools = [
        Tools(
            components=[
                Component(
                    type=Type.application,
                    author="OWASP Foundation",
                    publisher="OWASP Foundation",
                    group="owasp-dep-scan",
                    name="blint",
                    version=get_version(),
                    purl=f"pkg:pypi/blint@{get_version()}",
                )
            ]
        )
    ]
    metadata.lifecycles = [Lifecycles(phase=Phase.post_build)]
    return metadata


def generate(src_dirs, output_file, deep_mode):
    android_files = []
    components = []
    dependencies = []
    sbom = CycloneDX(
        bomFormat=BomFormat.CycloneDX,
        specVersion="1.5",
        version=1,
        serialNumber=f"urn:uuid:{uuid.uuid4()}",
    )
    sbom.metadata = default_metadata(src_dirs)
    for src in src_dirs:
        files = find_android_files(src)
        if files:
            android_files += files
    if not android_files:
        return False
    with Progress(
        transient=True,
        redirect_stderr=True,
        redirect_stdout=True,
        refresh_per_second=1,
    ) as progress:
        task = progress.add_task(
            f"[green] Parsing {len(android_files)} android apps",
            total=len(android_files),
            start=True,
        )
        for f in android_files:
            dependencies_dict = {}
            progress.update(task, description=f"Processing [bold]{f}[/bold]")
            parent_component, app_components = collect_app_metadata(
                f, deep_mode
            )
            if parent_component:
                if not sbom.metadata.component.components:
                    sbom.metadata.component.components = []
                sbom.metadata.component.components.append(parent_component)
            if app_components:
                components += app_components
            track_dependency(
                dependencies_dict, parent_component, app_components
            )
            # Update the dependencies list
            if dependencies_dict:
                for k, v in dependencies_dict.items():
                    dependencies.append({"ref": k, "dependsOn": list(v)})
    # Populate the components
    sbom.components = trim_components(components)
    # If we have only one parent component then promote it to metadata.component
    if sbom.metadata.component.components:
        if len(sbom.metadata.component.components) == 1:
            sbom.metadata.component = sbom.metadata.component.components[0]
        else:
            # Fix the dangling tree
            root_depends_on = []
            for ac in sbom.metadata.component.components:
                root_depends_on.append(ac.bom_ref.model_dump(mode="python"))
            dependencies.append(
                {
                    "ref": sbom.metadata.component.bom_ref.model_dump(
                        mode="python"
                    ),
                    "dependsOn": root_depends_on,
                }
            )
    # Populate the dependencies
    sbom.dependencies = dependencies
    LOG.debug(
        "SBOM includes %d components and %d dependencies",
        len(components),
        len(dependencies),
    )
    with open(output_file, mode="w", encoding="utf-8") as fp:
        fp.write(
            sbom.model_dump_json(
                indent=2,
                exclude_none=True,
                exclude_defaults=True,
                warnings=False,
            )
        )
        LOG.debug("SBOM file generated successfully at %s", output_file)
    return True


def track_dependency(dependencies_dict, parent_component, app_components):
    if parent_component:
        if not dependencies_dict.get(
            parent_component.bom_ref.model_dump(mode="python")
        ):
            dependencies_dict[
                parent_component.bom_ref.model_dump(mode="python")
            ] = set()
        for acomp in app_components:
            if not dependencies_dict.get(
                acomp.bom_ref.model_dump(mode="python")
            ):
                dependencies_dict[acomp.bom_ref.model_dump(mode="python")] = (
                    set()
                )
            dependencies_dict[
                parent_component.bom_ref.model_dump(mode="python")
            ].add(acomp.bom_ref.model_dump(mode="python"))
    else:
        for acomp in app_components:
            if not dependencies_dict.get(
                acomp.bom_ref.model_dump(mode="python")
            ):
                dependencies_dict[acomp.bom_ref.model_dump(mode="python")] = (
                    set()
                )


def trim_components(components):
    added_dict = {}
    ret = []
    for comp in components:
        if not added_dict.get(comp.bom_ref.model_dump(mode="python")):
            added_dict[comp.bom_ref.model_dump(mode="python")] = comp
    for k in sorted(added_dict.keys()):
        ret.append(added_dict[k])
    return ret
