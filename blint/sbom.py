import os
import uuid
from datetime import datetime
from typing import Any, Dict

from rich.progress import Progress

from blint.android import collect_app_metadata
from blint.binary import parse
from blint.config import SYMBOL_DELIMITER
from blint.cyclonedx.spec import (
    BomFormat,
    Component,
    CycloneDX,
    Lifecycles,
    Metadata,
    Phase,
    Property,
    RefType,
    Scope,
    Tools,
    Type,
)
from blint.logger import LOG
from blint.utils import create_component_evidence, find_android_files, gen_file_list, get_version


def default_parent(src_dirs: list[str]) -> Component:
    """
    Creates a default parent Component object for the given source directories.

    Args:
        src_dirs (list[str]): A list of source directories.

    Returns:
        Component: A Component object representing the default parent.
    """
    if not src_dirs:
        raise ValueError("No source directories provided")
    name = os.path.basename(src_dirs[0])
    purl = f"pkg:generic/{name}@latest"
    component = Component(type=Type.application, name=name, version="latest", purl=purl)
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


def generate(src_dirs: list[str], output_file: str, deep_mode: bool) -> bool:
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
    exe_files = gen_file_list(src_dirs)
    for src in src_dirs:
        if files := find_android_files(src):
            android_files += files
    if not android_files and not exe_files:
        return False
    with Progress(
            transient=True,
            redirect_stderr=True,
            redirect_stdout=True,
            refresh_per_second=1,
    ) as progress:
        if exe_files:
            task = progress.add_task(
                f"[green] Parsing {len(exe_files)} binaries",
                total=len(exe_files),
                start=True,
            )
        for exe in exe_files:
            progress.update(task, description=f"Processing [bold]{exe}[/bold]", advance=1)
            components.extend(process_exe_file(components, deep_mode, dependencies, exe, sbom))
        if android_files:
            task = progress.add_task(
                f"[green] Parsing {len(android_files)} android apps",
                total=len(android_files),
                start=True,
            )
        for f in android_files:
            progress.update(task, description=f"Processing [bold]{f}[/bold]", advance=1)
            components.extend(process_android_file(components, deep_mode, dependencies, f, sbom))
    return create_sbom(components, dependencies, output_file, sbom, deep_mode)


def create_sbom(
        components: list[Component], dependencies: list[dict], output_file: str, sbom: CycloneDX, deep_mode: bool
) -> bool:
    """
    Creates a Software Bill of Materials (SBOM) with the provided components,
    dependencies, output file, and SBOM object.

    Args:
        components (list): A list of Component objects.
        dependencies (list): A list of dependencies.
        output_file (str): The path to the output file.
        sbom: The SBOM object representing the SBOM.
        deep_mode (bool): Flag indicating whether to perform deep analysis.

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
                ac.bom_ref.model_dump(mode="python") for ac in sbom.metadata.component.components
            ]
            dependencies.append(
                {
                    "ref": sbom.metadata.component.bom_ref.model_dump(mode="python"),
                    "dependsOn": root_depends_on,
                }
            )
    # Populate the dependencies
    sbom.dependencies = dependencies
    LOG.debug(
        f"SBOM includes {len(components)} components and {len(dependencies)} dependencies",
    )
    with open(output_file, mode="w", encoding="utf-8") as fp:
        fp.write(
            sbom.model_dump_json(
                indent=None if deep_mode else 2,
                exclude_none=True,
                exclude_defaults=True,
                warnings=False,
            )
        )
        LOG.debug(f"SBOM file generated successfully at {output_file}")
    return True


def components_from_symbols_version(symbols_version: list[dict]) -> list[Component]:
    """
    Creates a list of Component objects from symbols version.
    This style of detection is quite imprecise since the version is just a min specifier.

    Args:
        symbols_version (list[dict]): A list of symbols version.

    Returns:
        list[Component]: list of components
    """
    lib_components: list[Component] = []
    for symbol in symbols_version:
        group = ""
        name = symbol["name"]
        version = "latest"
        if "_" in name:
            tmp_a = name.split("_")
            if len(tmp_a) == 2:
                version = tmp_a[-1]
                name = tmp_a[0].lower()
                if name.startswith("glib"):
                    name = name.removeprefix("g")
                    group = "gnu"
        purl = f"pkg:generic/{group}/{name}@{version}" if group else f"pkg:generic/{name}@{version}"
        if symbol.get("hash"):
            purl = f"{purl}?hash={symbol.get('hash')}"
        comp = Component(
            type=Type.library,
            group=group,
            name=name,
            version=version,
            purl=purl,
            evidence=create_component_evidence(symbol["name"], 0.5),
            properties=[
                Property(name="internal:symbol_version", value=symbol["name"])
            ]
        )
        comp.bom_ref = RefType(purl)
        lib_components.append(comp)
    return lib_components


def process_exe_file(
        components: list[Component],
        deep_mode: bool,
        dependencies: list[dict],
        exe: str,
        sbom: CycloneDX,
) -> list[Component]:
    """
    Processes an executable file, extracts metadata, and generates a Software Bill of Materials.

    Args:
        components: The list of existing components.
        deep_mode: A flag indicating whether to include deep analysis of the executable.
        dependencies: The list of dependencies.
        exe: The path to the executable file.
        sbom: The CycloneDX SBOM object.

    Returns:
        list[Component]: The updated list of components.

    """
    dependencies_dict = {}
    parent_component: Component = default_parent([exe])
    metadata: Dict[str, Any] = parse(exe)
    parent_component.properties = []
    lib_components: list[Component] = []
    for prop in (
            "binary_type",
            "magic",
            "class",
            "platform",
            "minos",
            "interpreter",
            "dylinker",
            "machine_type",
            "sdk",
            "uuid",
            "cpu_type",
            "flags",
            "relro",
            "is_pie",
            "has_nx",
            "static",
            "characteristics",
            "dll_characteristics",
            "subsystem",
            "is_gui",
            "major_linker_version",
            "minor_linker_version",
            "major_operating_system_version",
            "minor_operating_system_version",
    ):
        if metadata.get(prop):
            value = str(metadata.get(prop))
            if isinstance(metadata.get(prop), bool):
                value = value.lower()
            if value:
                parent_component.properties.append(Property(name=f"internal:{prop}", value=value))
    if metadata.get("notes"):
        for note in metadata.get("notes"):
            if note.get("version"):
                parent_component.properties.append(
                    Property(name=f"internal:{note.get('type')}", value=note.get('version')))
    if deep_mode:
        symbols_version: list[dict] = metadata.get("symbols_version", [])
        # Attempt to detect library components from the symbols version block
        # If this is unsuccessful then store the information as a property
        lib_components += components_from_symbols_version(symbols_version)
        if not lib_components:
            parent_component.properties += [
                Property(
                    name="internal:symbols_version",
                    value=", ".join([f["name"] for f in symbols_version]),
                )
            ]
        parent_component.properties += [
            Property(
                name="internal:functions",
                value=SYMBOL_DELIMITER.join(
                    [f["name"] for f in metadata.get("functions", []) if not f["name"].startswith("__")]),
            ),
            Property(
                name="internal:symtab_symbols",
                value=SYMBOL_DELIMITER.join([f["name"] for f in metadata.get("symtab_symbols", [])]),
            ),
            Property(
                name="internal:imports",
                value=SYMBOL_DELIMITER.join([f["name"] for f in metadata.get("imports", [])]),
            ),
            Property(
                name="internal:dynamic_symbols",
                value=SYMBOL_DELIMITER.join([f["name"] for f in metadata.get("dynamic_symbols", [])]),
            ),
        ]
    if not sbom.metadata.component.components:
        sbom.metadata.component.components = []
    sbom.metadata.component.components.append(parent_component)
    if metadata.get("libraries"):
        for entry in metadata.get("libraries"):
            comp = create_library_component(entry, exe)
            lib_components.append(comp)
    if metadata.get("dynamic_entries"):
        for entry in metadata["dynamic_entries"]:
            comp = create_dynamic_component(entry, exe)
            lib_components.append(comp)
    if lib_components:
        components += lib_components
        track_dependency(dependencies_dict, parent_component, lib_components)
    if dependencies_dict:
        dependencies.extend({"ref": k, "dependsOn": list(v)} for k, v in dependencies_dict.items())
    return components


def create_library_component(entry: Dict, exe: str) -> Component:
    """
    Processes a library entry and creates a component object.

    Args:
        entry: The entry containing the library information.
        exe: The executable associated with the library.

    Returns:
        Component: The created component object.
    """
    name = os.path.basename(entry["name"])
    purl = f"pkg:file/{name}@{entry['version']}"
    if entry.get("compatibility_version"):
        purl = f"{purl}?compatibility_version={entry['compatibility_version']}"
    comp = Component(
        type=Type.library,
        name=name,
        version=entry["version"],
        purl=purl,
        evidence=create_component_evidence(exe, 0.8),
        properties=[
            Property(name="internal:srcFile", value=exe),
            Property(name="internal:libPath", value=entry["name"]),
        ],
    )
    if entry.get("tag") == "NEEDED":
        comp.scope = Scope.required
    comp.bom_ref = RefType(purl)
    return comp


def create_dynamic_component(entry: Dict, exe: str) -> Component:
    """
    Creates a dynamic component object based on the entry information.

    Args:
        entry: The entry containing the component information.
        exe: The executable associated with the component.

    Returns:
        Component: The created dynamic component object.
    """
    purl = f"pkg:file/{entry['name']}"
    comp = Component(
        type=Type.library,
        name=entry["name"],
        purl=purl,
        evidence=create_component_evidence(exe, 0.5),
        properties=[
            Property(name="internal:srcFile", value=exe),
        ],
    )
    if entry.get("tag") == "NEEDED":
        comp.scope = Scope.required
    comp.bom_ref = RefType(purl)
    return comp


def process_android_file(
        components: list[Component], deep_mode: bool, dependencies: list[dict], f: str, sbom: CycloneDX
) -> list[Component]:
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
        dependencies.extend({"ref": k, "dependsOn": list(v)} for k, v in dependencies_dict.items())
    return components


def track_dependency(
        dependencies_dict: dict, parent_component: Component, app_components: list[Component]
) -> None:
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
        if not dependencies_dict.get(parent_component.bom_ref.model_dump(mode="python")):
            dependencies_dict[parent_component.bom_ref.model_dump(mode="python")] = set()
        for acomp in app_components:
            if not dependencies_dict.get(acomp.bom_ref.model_dump(mode="python")):
                dependencies_dict[acomp.bom_ref.model_dump(mode="python")] = set()
            dependencies_dict[parent_component.bom_ref.model_dump(mode="python")].add(
                acomp.bom_ref.model_dump(mode="python")
            )
    else:
        for acomp in app_components:
            if not dependencies_dict.get(acomp.bom_ref.model_dump(mode="python")):
                dependencies_dict[acomp.bom_ref.model_dump(mode="python")] = set()


def trim_components(components: list[Component]) -> list[Component]:
    """
    Trims duplicate components from the input list and returns the result.

    Args:
        components (list): A list of components to be trimmed.

    Returns:
        list: A list of unique components after trimming duplicates.
    """
    added_dict: dict[str, Component] = {}
    for comp in components:
        if not added_dict.get(comp.bom_ref.model_dump(mode="python")):
            added_dict[comp.bom_ref.model_dump(mode="python")] = comp
    return [added_dict[k] for k in sorted(added_dict.keys())]
