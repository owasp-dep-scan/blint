import base64
import binascii
import codecs
import os
import sys
import uuid
from datetime import datetime
from typing import Any, Dict

import orjson
from custom_json_diff.lib.utils import file_read, file_write
from rich.progress import Progress

from blint.lib.android import collect_app_metadata
from blint.lib.binary import parse
from blint.config import SYMBOL_DELIMITER, BlintOptions
from blint.cyclonedx.spec import (
    BomFormat,
    Component,
    CycloneDX,
    Hash,
    HashAlg,
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
from blint.lib.utils import (
    camel_to_snake,
    create_component_evidence,
    find_bom_files,
    get_version,
)
from blint.db import detect_binaries_utilized

from packageurl import PackageURL


def default_parent(src_dirs: list[str], symbols_purl_map: dict = None) -> Component:
    """
    Creates a default parent Component object for the given source directories.

    Args:
        src_dirs (list[str]): A list of source directories.
        symbols_purl_map (dict): containing symbol name as the key and purl as the value

    Returns:
        Component: A Component object representing the default parent.
    """
    if not src_dirs:
        raise ValueError("No source directories provided")
    name = os.path.basename(src_dirs[0]) or os.path.dirname(src_dirs[0])
    version = None
    # Extract the name from the .rlib files
    if name.endswith(".rlib"):
        name = name.split("-")[0].removeprefix("lib")
    purl_type = "nuget" if name.endswith(".dll") else "generic"
    if purl_type == "nuget":
        name = name.replace(".dll", "")
    purl = f"pkg:{purl_type}/{name}"
    pkg_type = Type.library if purl_type not in ("generic",) else Type.application
    if symbols_purl_map and symbols_purl_map.get(purl):
        purl = symbols_purl_map[purl]
        pkg_type = Type.library
        if "@" in purl:
            version = purl.split("@")[-1]
    component = Component(type=pkg_type, name=name, version=version, purl=purl)
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
    metadata.timestamp = f"{datetime.now().isoformat(timespec='seconds')}Z"
    metadata.component = default_parent(src_dirs)
    metadata.tools = Tools(
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
    metadata.lifecycles = [Lifecycles(phase=Phase.post_build)]
    return metadata


def generate(blint_options: BlintOptions, exe_files, android_files) -> CycloneDX:
    """
    Generates an SBOM for the given source directories.

    Args:
        blint_options (BlintOptions): A BlintOptions object containing the SBOM generation options.
    Returns:
        CycloneDX: Generated CycloneDX SBOM
    """
    if not android_files and not exe_files:
        return False
    symbols_purl_map = {}
    if blint_options.src_dir_boms:
        symbols_purl_map = populate_purl_lookup(blint_options.src_dir_boms)
    components = []
    dependencies = []
    dependencies_dict = {}
    sbom = CycloneDX(
        bomFormat=BomFormat.CycloneDX,
        specVersion="1.6",
        version=1,
        serialNumber=f"urn:uuid:{uuid.uuid4()}",
    )
    sbom.metadata = default_metadata(blint_options.src_dir_image)
    with Progress(
        transient=True,
        redirect_stderr=True,
        redirect_stdout=True,
        refresh_per_second=1,
        disable=blint_options.quiet_mode,
    ) as progress:
        if exe_files:
            task = progress.add_task(
                f"[green] Parsing {len(exe_files)} binaries",
                total=len(exe_files),
                start=True,
            )
        for exe in exe_files:
            progress.update(
                task, description=f"Processing [bold]{exe}[/bold]", advance=1
            )
            components += process_exe_file(
                dependencies_dict,
                blint_options.deep_mode,
                exe,
                sbom,
                blint_options.exports_prefix,
                symbols_purl_map,
                blint_options.use_blintdb,
            )
        if android_files:
            task = progress.add_task(
                f"[green] Parsing {len(android_files)} android apps",
                total=len(android_files),
                start=True,
            )
        for f in android_files:
            progress.update(task, description=f"Processing [bold]{f}[/bold]", advance=1)
            components += process_android_file(
                dependencies_dict, blint_options.deep_mode, f, sbom
            )
    if dependencies_dict:
        dependencies += [
            {"ref": k, "dependsOn": list(v)} for k, v in dependencies_dict.items()
        ]
    # Create the BOM file `blint_options.sbom_output` as well as return the generated BOM object
    return create_sbom(
        components,
        dependencies,
        blint_options.sbom_output,
        sbom,
        blint_options.deep_mode,
        symbols_purl_map,
    )


def create_sbom(
    components: list[Component],
    dependencies: list[dict],
    output_file: str,
    sbom: CycloneDX,
    deep_mode: bool,
    symbols_purl_map: dict,
) -> CycloneDX:
    """
    Creates a Software Bill of Materials (SBOM) with the provided components,
    dependencies, output file, and SBOM object.

    Args:
        components (list): A list of Component objects.
        dependencies (list): A list of dependencies.
        output_file (str): The path to the output BOM file.
        sbom (CycloneDX): The SBOM object representing the SBOM.
        deep_mode (bool): Flag indicating whether to perform deep analysis.
        symbols_purl_map (dict): containing symbol name as the key and purl as the value

    Returns:
        CycloneDX: CycloneDX object with trimmed components and dependencies
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
                for ac in sbom.metadata.component.components
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
        f"SBOM includes {len(sbom.components)} components and {len(sbom.dependencies)} dependencies"
    )
    if output_file is sys.stdout:
        print(sbom.model_dump_json(indent=2, exclude_none=True, exclude_defaults=True, warnings=False, by_alias=True))
    else:
        output_dir = os.path.dirname(output_file)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
    
        file_write(
            os.path.join(output_dir, output_file),
            sbom.model_dump_json(
                indent=None if deep_mode else 2,
                exclude_none=True,
                exclude_defaults=True,
                warnings=False,
                by_alias=True,
            ),
            log=LOG,
        )
    return sbom


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
        version = None
        pkg_type = "nuget" if name.endswith(".dll") else "generic"
        if "_" in name:
            tmp_a = name.split("_")
            if len(tmp_a) == 2:
                version = tmp_a[-1]
                name = tmp_a[0].lower()
                if name.startswith("glib"):
                    name = name.removeprefix("g")
                    group = "gnu"
        if pkg_type == "nuget":
            name = name.replace(".dll", "")
        purl = f"pkg:{pkg_type}/{group}/{name}" if group else f"pkg:{pkg_type}/{name}"
        if version:
            purl = f"{purl}@{version}"
        if symbol.get("hash"):
            purl = f"{purl}?hash={symbol.get('hash')}"
        comp = Component(
            type=Type.library,
            group=group,
            name=name,
            version=version,
            purl=purl,
            evidence=create_component_evidence(symbol["name"], 0.5),
            properties=[Property(name="internal:symbol_version", value=symbol["name"])],
        )
        comp.bom_ref = RefType(purl)
        lib_components.append(comp)
    return lib_components


def _add_to_parent_component(
    metadata_components: list[Component], parent_component: Component
):
    for mc in metadata_components:
        if mc.bom_ref.model_dump(mode="python") == parent_component.bom_ref.model_dump(
            mode="python"
        ):
            return
    metadata_components.append(parent_component)


def process_exe_file(
    dependencies_dict: dict[str, set],
    deep_mode: bool,
    exe: str,
    sbom: CycloneDX,
    export_prefixes: list[str] = None,
    symbols_purl_map: dict = None,
    use_blintdb: bool = False,
) -> list[Component]:
    """
    Processes an executable file, extracts metadata, and generates a Software Bill of Materials.

    Args:
        dependencies_dict (dict[str, set]): A dictionary of dependencies.
        deep_mode: A flag indicating whether to include deep analysis of the executable.
        exe: The path to the executable file.
        sbom: The CycloneDX SBOM object.
        export_prefixes (list): Prefixes to determine exported symbols.
        symbols_purl_map (dict): containing symbol name as the key and purl as the value
        use_blintdb (bool): should blintdb be used to improve component identification

    Returns:
        list[Component]: The updated list of components.

    """
    metadata: Dict[str, Any] = parse(exe)
    parent_component: Component = default_parent([exe], symbols_purl_map)
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
        "is_reproducible_build",
        "has_nx",
        "static",
        "characteristics",
        "dll_characteristics",
        "subsystem",
        "is_gui",
        "is_driver",
        "is_dotnet",
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
                parent_component.properties.append(
                    Property(name=f"internal:{prop}", value=value)
                )
    if metadata.get("notes"):
        for note in metadata.get("notes"):
            if note.get("version"):
                parent_component.properties.append(
                    Property(
                        name=f"internal:{note.get('type')}", value=note.get("version")
                    )
                )
    # For PE, resources could have a dict called version_metadata with interesting properties
    if metadata.get("resources"):
        version_metadata = metadata.get("resources").get("version_metadata")
        if version_metadata and isinstance(version_metadata, dict):
            for vk, vv in version_metadata.items():
                parent_component.properties.append(
                    Property(name=f"internal:{camel_to_snake(vk)}", value=vv)
                )
    if deep_mode:
        symbols_version: list[dict] = metadata.get("symbols_version", [])
        # Attempt to detect library components from the symbols version block
        # If this is unsuccessful then store the information as a property
        lib_components += components_from_symbols_version(symbols_version)
        if not lib_components and symbols_version:
            parent_component.properties.append(
                Property(
                    name="internal:symbols_version",
                    value=", ".join([f["name"] for f in symbols_version]),
                )
            )

        internal_functions = sorted(
            {
                f["name"]
                for f in metadata.get("functions", [])
                if not any(f["name"].startswith(p) for p in export_prefixes)
            }
        )
        if internal_functions:
            parent_component.properties.append(
                Property(
                    name="internal:functions",
                    value=SYMBOL_DELIMITER.join(internal_functions),
                )
            )
        export_functions = sorted(
            {
                f["name"]
                for f in metadata.get("functions", [])
                if any(f["name"].startswith(p) for p in export_prefixes)
            }
        )
        if export_functions:
            parent_component.properties.append(
                Property(
                    name="internal:export_functions",
                    value=SYMBOL_DELIMITER.join(export_functions),
                )
            )
        symtab_symbols = sorted(
            {
                f["name"]
                for f in metadata.get("symtab_symbols", [])
                if f and not any(f["name"].startswith(p) for p in export_prefixes)
            }
        )
        if symtab_symbols:
            parent_component.properties.append(
                Property(
                    name="internal:symtab_symbols",
                    value=SYMBOL_DELIMITER.join(symtab_symbols),
                )
            )
        exported_symtab_symbols = sorted(
            {
                f["name"]
                for f in metadata.get("symtab_symbols", [])
                if f and any(f["name"].startswith(p) for p in export_prefixes)
            }
        )
        if exported_symtab_symbols:
            parent_component.properties.append(
                Property(
                    name="internal:exported_symtab_symbols",
                    value=SYMBOL_DELIMITER.join(exported_symtab_symbols),
                )
            )
        all_imports = sorted(
            {
                f["name"]
                for f in metadata.get("imports", [])
                if f and not any(f["name"].startswith(p) for p in export_prefixes)
            }
        )
        if all_imports:
            parent_component.properties.append(
                Property(
                    name="internal:imports",
                    value=SYMBOL_DELIMITER.join(all_imports),
                )
            )
        all_exports = sorted(
            {
                f["name"]
                for f in metadata.get("imports", [])
                if any(f["name"].startswith(p) for p in export_prefixes)
            }
        )
        if all_imports:
            parent_component.properties.append(
                Property(
                    name="internal:exports",
                    value=SYMBOL_DELIMITER.join(all_exports),
                )
            )
        dynamic_symbols = sorted(
            {
                f["name"]
                for f in metadata.get("dynamic_symbols", [])
                if f and not any(f["name"].startswith(p) for p in export_prefixes)
            }
        )
        if dynamic_symbols:
            parent_component.properties.append(
                Property(
                    name="internal:dynamic_symbols",
                    value=SYMBOL_DELIMITER.join(dynamic_symbols),
                )
            )

        exported_dynamic_symbols = sorted(
            {
                f["name"]
                for f in metadata.get("dynamic_symbols", [])
                if f and any(f["name"].startswith(p) for p in export_prefixes)
            }
        )
        if exported_dynamic_symbols:
            parent_component.properties.append(
                Property(
                    name="internal:exported_dynamic_symbols",
                    value=SYMBOL_DELIMITER.join(exported_dynamic_symbols),
                )
            )

        # Should we use the blintdb to improve precision
        if use_blintdb:
            # utilize voting logic along with blitndb
            # we iterate through each symbol and try to find a match in the database

            LOG.debug("Utilizing blint_db")
            symtab_symbols_list = metadata.get("symtab_symbols", [])
            dynamic_symbols_list = metadata.get("dynamic_symbols", [])
            if symtab_symbols_list or dynamic_symbols_list:
                symtab_binaries_detected, binary_evidence_eids = (
                    detect_binaries_utilized(symtab_symbols_list)
                )
                binaries_detected, dynamic_binary_evidence_eids = (
                    detect_binaries_utilized(dynamic_symbols_list)
                )
                binaries_detected = binaries_detected.union(symtab_binaries_detected)
                binary_evidence_eids.update(dynamic_binary_evidence_eids)
                if binaries_detected:
                    LOG.debug(
                        f"Found {len(binaries_detected)} possible binary matches for {exe}."
                    )
                else:
                    LOG.debug(f"Unable to identify a match for {exe}.")
                # adds the components in a similar way to dynamic entries
                for binary_purl in binaries_detected:
                    entry = {
                        "purl": binary_purl,
                        "tag": "NEEDED",
                    }
                    comp = create_dynamic_component(
                        entry,
                        exe,
                        {"export_ids": binary_evidence_eids.get(binary_purl)},
                    )
                    lib_components.append(comp)

    if not sbom.metadata.component.components:
        sbom.metadata.component.components = []
    # Automatically promote application dependencies to the parent. Filter out any components with empty properties, as these are unparseable blobs.
    if parent_component.type == Type.application and len(parent_component.properties):
        _add_to_parent_component(sbom.metadata.component.components, parent_component)
    # Library dependencies such as .dll could be moved to lib_components
    elif parent_component.type == Type.library:
        lib_components.append(parent_component)
    if metadata.get("libraries"):
        for entry in metadata.get("libraries"):
            comp = create_library_component(entry, exe)
            lib_components.append(comp)
    if metadata.get("dynamic_entries"):
        for entry in metadata["dynamic_entries"]:
            comp = create_dynamic_component(entry, exe)
            lib_components.append(comp)
    # Convert libraries and targets from dotnet binaries
    if metadata.get("dotnet_dependencies"):
        pe_components = process_dotnet_dependencies(
            metadata.get("dotnet_dependencies"), dependencies_dict
        )
        lib_components += pe_components
    # Convert go dependencies
    if metadata.get("go_dependencies"):
        go_components = process_go_dependencies(metadata.get("go_dependencies"))
        lib_components += go_components
    # Convert go formulation section
    for k, v in metadata.get("go_formulation", {}).items():
        parent_component.properties.append(
            Property(
                name=f"internal:{camel_to_snake(k)}",
                value=str(v).strip(),
            )
        )
    # Convert rust dependencies
    if metadata.get("rust_dependencies"):
        rust_components = process_rust_dependencies(
            metadata.get("rust_dependencies"), dependencies_dict
        )
        lib_components += rust_components
    if lib_components:
        track_dependency(dependencies_dict, parent_component, lib_components)
    return lib_components


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


def create_dynamic_component(
    entry: Dict, exe: str, evidence_metadata: dict = None
) -> Component:
    """
    Creates a dynamic component object based on the entry information.

    Args:
        entry: The entry containing the component information.
        exe: The executable associated with the component.
        evidence_metadata: Extra metadata for evidence purposes.

    Returns:
        Component: The created dynamic component object.
    """
    group = None
    version = None
    name = entry.get("name", "").removeprefix("$ORIGIN/") if entry.get("name") else None
    purl = entry.get("purl", f"pkg:file/{name}")
    if not name and purl:
        try:
            purl_obj = PackageURL.from_string(purl)
            name = purl_obj.name
            group = purl_obj.namespace
            version = purl_obj.version
        except Exception:
            pass
    properties = [
        Property(name="internal:srcFile", value=exe),
    ]
    comp = Component(
        type=Type.library,
        group=group,
        name=name,
        version=version,
        purl=purl,
        evidence=create_component_evidence(exe, 0.5, evidence_metadata),
    )
    if evidence_metadata:
        for k, v in evidence_metadata.items():
            properties.append(
                Property(
                    name=f"internal:{k}",
                    value=", ".join(str(v)) if isinstance(v, list) else str(v),
                )
            )
    comp.properties = properties
    if entry.get("tag") == "NEEDED":
        comp.scope = Scope.required
    comp.bom_ref = RefType(purl)
    return comp


def process_android_file(
    dependencies_dict: dict[str, set],
    deep_mode: bool,
    f: str,
    sbom: CycloneDX,
) -> list[Component]:
    """
    Process an Android file and update the dependencies and components.

    Args:
        dependencies_dict (dict[str, set]): Existing dependencies dictionary.
        deep_mode (bool): Flag indicating whether to process in deep mode.
        f (str): File to be processed.
        sbom (obj): Software Bill of Materials object to be updated.

    Returns:
        list: Updated components list after processing.
    """
    parent_component, app_components = collect_app_metadata(f, deep_mode)
    if parent_component:
        if not sbom.metadata.component.components:
            sbom.metadata.component.components = []
        _add_to_parent_component(sbom.metadata.component.components, parent_component)
    if app_components:
        track_dependency(dependencies_dict, parent_component, app_components)
    return app_components


def process_dotnet_dependencies(
    dotnet_deps: dict[str, dict], dependencies_dict: dict[str, set]
) -> list[Component]:
    """
    Process the dotnet dependencies metadata extracted for binary overlays

    Args:
        dotnet_deps (dict[str, dict]): PE dependencies metadata
        dependencies_dict (dict[str, set]): Existing dependencies dictionary

    Returns:
        list: New component list
    """
    components = []
    libraries = dotnet_deps.get("libraries", {})
    # k: 'Microsoft.CodeAnalysis.Analyzers/3.3.4'
    # v: {'type': 'package', 'serviceable': True,
    #      'sha512': 'sha512-AxkxcPR+rheX0SmvpLVIGLhOUXAKG5vuc+aqo5r68g==',
    #      'path': 'microsoft.codeanalysis.analyzers/3.3.4',
    #      'hashPath': 'microsoft.codeanalysis.analyzers.3.3.4.nupkg.sha512'
    #    }
    for k, v in libraries.items():
        tmp_a = k.split("/")
        purl = f"pkg:nuget/{tmp_a[0]}@{tmp_a[1]}"
        hash_content = ""
        try:
            hash_content = codecs.encode(
                base64.b64decode(
                    v.get("sha512").removeprefix("sha512-"), validate=True
                ),
                encoding="hex",
            )
        except binascii.Error:
            hash_content = str(v.get("hash").removeprefix("sha512-"))
        comp = Component(
            type=Type.application if v.get("type") == "project" else Type.library,
            name=tmp_a[0],
            version=tmp_a[1],
            purl=purl,
            scope=Scope.required,
            evidence=create_component_evidence(v.get("path"), 1.0)
            if v.get("path")
            else {},
            properties=[
                Property(
                    name="internal:serviceable", value=str(v.get("serviceable")).lower()
                ),
                Property(name="internal:hash_path", value=v.get("hashPath")),
            ],
        )
        if hash_content:
            comp.hashes = [Hash(alg=HashAlg.SHA_512, content=hash_content)]
        comp.bom_ref = RefType(purl)
        components.append(comp)
    targets: dict[str, dict[str, dict]] = dotnet_deps.get("targets", {})
    for _, tv in targets.items():
        for k, v in tv.items():
            tmp_a = k.split("/")
            purl = f"pkg:nuget/{tmp_a[0]}@{tmp_a[1]}"
            depends_on = []
            for adep_name, adep_version in v.get("dependencies", {}).items():
                depends_on.append(f"pkg:nuget/{adep_name}@{adep_version}")
            if not dependencies_dict.get(purl):
                dependencies_dict[purl] = set()
            dependencies_dict[purl].update(depends_on)
    return components


def process_go_dependencies(go_deps: dict[str, str]) -> list[Component]:
    """
    Process the go dependencies metadata extracted for binary overlays

    Args:
        go_deps (dict[str, str]): dependencies metadata

    Returns:
        list: New component list
    """
    components = []
    # Key is the name and value is the version
    # We need to construct a purl by pretending the module name is the name with no namespace
    # This would make this compatible with cdxgen and depscan
    # See https://github.com/CycloneDX/cdxgen/issues/897
    for k, v in go_deps.items():
        # See #83
        # purl specification uses namespace hack for go to make this identifier use slash
        purl = f"""pkg:golang/{k.lower()}@{v.get("version")}"""
        comp = Component(
            type=Type.library,
            name=k,
            version=v.get("version"),
            purl=purl,
            scope=Scope.required,
            evidence=create_component_evidence(k, 1.0),
        )
        hash_content = ""
        if v.get("hash"):
            try:
                hash_content = codecs.encode(
                    base64.b64decode(v.get("hash").removeprefix("h1:"), validate=True),
                    encoding="hex",
                )
            except binascii.Error:
                hash_content = str(v.get("hash").removeprefix("h1:"))
        if hash_content:
            comp.hashes = [Hash(alg=HashAlg.SHA_256, content=hash_content)]
        comp.bom_ref = RefType(f"""pkg:golang/{k}@{v.get("version")}""")
        components.append(comp)
    return components


def process_rust_dependencies(
    rust_deps: list, dependencies_dict: dict[str, set]
) -> list[Component]:
    """
    Process the rust dependencies metadata extracted for binary overlays

    Args:
        rust_deps (list): dependencies metadata

    Returns:
        list: New component list
    """
    components = []
    idx_to_purl = {}
    for idx, dep in enumerate(rust_deps):
        idx_to_purl[idx] = f"""pkg:cargo/{dep["name"]}@{dep["version"]}"""
    for dependency in rust_deps:
        purl = f"""pkg:cargo/{dependency["name"]}@{dependency["version"]}"""
        purl_qualifer = (
            f"""?repository={dependency.get("source")}"""
            if dependency.get("source", "") != "crates.io"
            else ""
        )
        comp = Component(
            type=Type.library,
            name=dependency["name"],
            version=dependency["version"],
            purl=f"{purl}{purl_qualifer}",
            scope=Scope.required,
            evidence=create_component_evidence(dependency["name"], 0.8),
        )
        comp.bom_ref = RefType(purl)
        components.append(comp)
        if not dependencies_dict.get(purl):
            dependencies_dict[purl] = set()
        # Recover the dependency tree
        if dependency.get("dependencies"):
            for adep in dependency.get("dependencies"):
                dependencies_dict[purl].add(idx_to_purl[adep])
    return components


def track_dependency(
    dependencies_dict: dict[str, set],
    parent_component: Component,
    app_components: list[Component],
) -> None:
    """
    Track dependencies between components and update the dependencies dict.

    Args:
        dependencies_dict (dict[str, set]): The dictionary to store the dependencies.
        parent_component (Component): The parent component.
        app_components (list): The list of application components.

    Returns:
        None
    """
    if parent_component:
        if not dependencies_dict.get(
            parent_component.bom_ref.model_dump(mode="python")
        ):
            dependencies_dict[parent_component.bom_ref.model_dump(mode="python")] = (
                set()
            )
        for acomp in app_components:
            if not dependencies_dict.get(acomp.bom_ref.model_dump(mode="python")):
                dependencies_dict[acomp.bom_ref.model_dump(mode="python")] = set()
            # Prevent self loops
            if parent_component.bom_ref.model_dump(
                mode="python"
            ) != acomp.bom_ref.model_dump(mode="python"):
                dependencies_dict[
                    parent_component.bom_ref.model_dump(mode="python")
                ].add(acomp.bom_ref.model_dump(mode="python"))
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


def populate_purl_lookup(src_dir_boms: list[str]):
    """
    Create a purl lookup cache by parsing the various BOMs in the given source directory.

    Args:
        src_dir_boms (list): Directory containing pre-build and build sboms.

    Returns:
        dict: containing symbol name as the key and purl as the value
    """
    symbols_purl_map = {}
    for adir in src_dir_boms:
        if files := find_bom_files(adir):
            for f in files:
                fdata = file_read(f)
                try:
                    bom_obj = orjson.loads(fdata)
                    # Ignore non-compatible bom files
                    if (
                        not bom_obj
                        or not bom_obj.get("metadata", {}).get("lifecycles")
                        or not bom_obj.get("components")
                    ):
                        continue
                    for comp in bom_obj["components"]:
                        # For nuget, store the unversioned purl as a lookup key
                        if (
                            comp
                            and comp.get("purl")
                            and comp["purl"].startswith("pkg:nuget")
                            and "@" in comp["purl"]
                        ):
                            symbols_purl_map[comp["purl"].split("@")[0]] = comp["purl"]
                except orjson.JSONDecodeError:
                    LOG.debug(f"Unable to parse {f}")
    return symbols_purl_map
