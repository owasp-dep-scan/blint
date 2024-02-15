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
    """
    Creates a default parent Component object for the given source directories.

    Args:
        src_dirs (list): A list of source directories.

    Returns:
        Component: A Component object representing the default parent.
    """
    name = os.path.basename(src_dirs[0])
    purl = f"pkg:generic/{name}@latest"
    component = Component(
        type=Type.application, name=name, version="latest", purl=purl
    )
    component.bom_ref = RefType(purl)
    return component


def default_metadata(src_dirs):
    """
    Creates default metadata for SBOM generation.

    Args:
        src_dirs (list): A list of source directories.

    Returns:
        Metadata: A Metadata object for SBOM generation.
    """
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
    """
    Generates an SBOM for the given source directories.

    Args:
        src_dirs (list): A list of source directories.
        output_file (str): The path to the output file.
        deep_mode (bool): Flag indicating whether to perform deep analysis.

    Returns:
        bool: True if the SBOM generation is successful, False otherwise.
    """
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
        if files := find_android_files(src):
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
            progress.update(task, description=f"Processing [bold]{f}[/bold]")
            components.extend(
                process_android_file(
                    components, deep_mode, dependencies, f, sbom)
            )
    return create_sbom(components, dependencies, output_file, sbom)


def create_sbom(components, dependencies, output_file, sbom):
    """
    Creates a Software Bill of Materials (SBOM) with the provided components,
    dependencies, output file, and SBOM object.

    Args:
        components (list): A list of Component objects.
        dependencies (list): A list of dependencies.
        output_file (str): The path to the output file.
        sbom: The SBOM object representing the SBOM.

    Returns:
        bool: True if the SBOM generation is successful, False otherwise.
    """
    # Populate the components
    sbom.components = trim_components(components)
    # If we have only one parent component then promote it to metadata.component
    if sbom.metadata.component.components:
        if len(sbom.metadata.component.components) == 1:
            sbom.metadata.component = sbom.metadata.component.components[0]
        else:
            root_depends_on = [
                ac.bom_ref.model_dump(mode="python")
                for ac in
                sbom.metadata.component.components
            ]
            dependencies.append({
                "ref": sbom.metadata.component.bom_ref.model_dump(
                    mode="python"), "dependsOn": root_depends_on, })
    # Populate the dependencies
    sbom.dependencies = dependencies
    LOG.debug(
        f"SBOM includes {len(components)} components and {len(dependencies)} "
        f"dependencies", )
    with open(output_file, mode="w", encoding="utf-8") as fp:
        fp.write(
            sbom.model_dump_json(
                indent=2, exclude_none=True, exclude_defaults=True,
                warnings=False, )
        )
        LOG.debug(f"SBOM file generated successfully at {output_file}")
    return True


def process_android_file(components, deep_mode, dependencies, f, sbom):
    """
    Process an Android file and update the dependencies and components.

    Args:
        components (list): List of components to be processed.
        deep_mode (bool): Flag indicating whether to process in deep mode.
        dependencies (list): List of dependencies to be updated.
        f (str): File to be processed.
        sbom (obj): Software Bill of Materials object to be updated.

    Returns:
        list: Updated components list after processing.
    """
    dependencies_dict = {}
    parent_component, app_components = collect_app_metadata(f, deep_mode)
    if parent_component:
        if not sbom.metadata.component.components:
            sbom.metadata.component.components = []
        sbom.metadata.component.components.append(parent_component)
    if app_components:
        components += app_components
    track_dependency(dependencies_dict, parent_component, app_components)
    # Update the dependencies list
    if dependencies_dict:
        dependencies.extend({"ref": k, "dependsOn": list(v)} for k, v in
                            dependencies_dict.items())
    return components


def track_dependency(dependencies_dict, parent_component, app_components):
    """
    Track dependencies between components and update the dependencies dict.

    Args:
        dependencies_dict (dict): The dictionary to store the dependencies.
        parent_component (Component): The parent component.
        app_components (list): The list of application components.

    Returns:
        None
    """
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
    """
    Trims duplicate components from the input list and returns the result.

    Args:
        components (list): A list of components to be trimmed.

    Returns:
        list: A list of unique components after trimming duplicates.
    """
    added_dict = {}
    for comp in components:
        if not added_dict.get(comp.bom_ref.model_dump(mode="python")):
            added_dict[comp.bom_ref.model_dump(mode="python")] = comp
    return [added_dict[k] for k in sorted(added_dict.keys())]
