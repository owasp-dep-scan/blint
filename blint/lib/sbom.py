import base64
import binascii
import codecs
import os
import shutil
import sys
import uuid
from datetime import datetime
from typing import Any, Dict

import orjson
from custom_json_diff.lib.utils import file_read, file_write
from packageurl import PackageURL
from rich.progress import Progress

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
from blint.db import (
    build_callgraph_canon_names,
    build_function_hash_index,
    build_symbol_source_map,
    detect_binaries_utilized,
)
from blint.lib.android import build_app_dex_callgraph, collect_app_metadata
from blint.lib.android_services import detect_services
from blint.lib.binary import is_wasm_file, parse
from blint.lib.ios import collect_ios_app
from blint.lib.utils import (
    calculate_hashes,
    camel_to_snake,
    create_component_evidence,
    find_bom_files,
    get_version,
)
from blint.logger import LOG


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


def generate(blint_options: BlintOptions, exe_files, android_files, ios_files=None) -> CycloneDX:
    """
    Generates an SBOM for the given source directories.

    Args:
        blint_options (BlintOptions): A BlintOptions object containing the SBOM generation options.
        exe_files (list): Native binaries to analyse.
        android_files (list): Android app archives to analyse.
        ios_files (list): iOS/macOS app archives (``.ipa``) to analyse.
    Returns:
        CycloneDX: Generated CycloneDX SBOM
    """
    ios_files = ios_files or []
    if not android_files and not exe_files and not ios_files:
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
        skipped_wasm = 0
        for exe in exe_files:
            if is_wasm_file(exe):
                skipped_wasm += 1
                continue
            progress.update(
                task,
                description=f"Processing [bold]{os.path.basename(exe)}[/bold]",
                advance=1,
            )
            components += process_exe_file(
                dependencies_dict,
                blint_options.deep_mode,
                exe,
                sbom,
                blint_options.exports_prefix,
                symbols_purl_map,
                blint_options.use_blintdb,
                blint_options.disassemble,
            )
        if skipped_wasm:
            LOG.info(f"Skipped {skipped_wasm} wasm file(s) during SBOM generation")
        if android_files:
            task = progress.add_task(
                f"[green] Parsing {len(android_files)} android apps",
                total=len(android_files),
                start=True,
            )
        for f in android_files:
            progress.update(task, description=f"Processing [bold]{f}[/bold]", advance=1)
            components += process_android_file(dependencies_dict, blint_options.deep_mode, f, sbom)
            if blint_options.disassemble:
                write_dex_callgraph(f, blint_options.sbom_output)
        if ios_files:
            task = progress.add_task(
                f"[green] Parsing {len(ios_files)} iOS apps",
                total=len(ios_files),
                start=True,
            )
        for f in ios_files:
            progress.update(task, description=f"Processing [bold]{f}[/bold]", advance=1)
            components += process_ios_file(dependencies_dict, blint_options.deep_mode, f, sbom)
            if blint_options.disassemble:
                write_ios_callgraphs(f, blint_options.sbom_output)
    if dependencies_dict:
        dependencies += [{"ref": k, "dependsOn": list(v)} for k, v in dependencies_dict.items()]
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
    Creates a Software Bill-of-Materials (SBOM) with the provided components,
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
        f"SBOM includes {len(sbom.components)} components and {len(sbom.dependencies)} dependencies"
    )
    if output_file is sys.stdout:
        print(
            sbom.model_dump_json(
                indent=2,
                exclude_none=True,
                exclude_defaults=True,
                warnings=False,
                by_alias=True,
            )
        )
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


def _add_to_parent_component(metadata_components: list[Component], parent_component: Component):
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
    disassemble: bool = False,
) -> list[Component]:
    """
    Processes an executable file, extracts metadata, and generates a Software Bill-of-Materials.

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
    if is_wasm_file(exe):
        return []
    metadata: Dict[str, Any] = parse(exe, disassemble=disassemble)
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
                parent_component.properties.append(Property(name=f"internal:{prop}", value=value))
    if metadata.get("notes"):
        for note in metadata.get("notes"):
            if note.get("version"):
                parent_component.properties.append(
                    Property(name=f"internal:{note.get('type')}", value=note.get("version"))
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

    if use_blintdb:
        LOG.debug("Utilizing blintdb v2 for SBOM component matching")
        symbol_source_map = build_symbol_source_map(metadata)
        function_hash_index = build_function_hash_index(metadata)
        callgraph_canon_names = build_callgraph_canon_names(metadata)
        binaries_detected, binary_evidence = detect_binaries_utilized(
            symbol_source_map=symbol_source_map,
            function_hash_index=function_hash_index,
            callgraph_canon_names=callgraph_canon_names,
            binary_metadata=metadata,
        )
        if binaries_detected:
            LOG.debug(f"Found {len(binaries_detected)} possible component matches for {exe}.")
        else:
            LOG.debug(f"Unable to identify a blintdb match for {exe}.")
        for binary_purl in sorted(binaries_detected):
            evidence = binary_evidence.get(binary_purl, {})
            evidence_metadata = {
                "blintdb_project_name": evidence.get("project_name"),
                "blintdb_score": evidence.get("score"),
                "blintdb_matched_binary_count": evidence.get("matched_binary_count"),
                "blintdb_matched_binary_name_count": evidence.get("matched_binary_name_count"),
                "blintdb_matched_binary_names": evidence.get("matched_binary_names", []),
                "blintdb_binary_name_match": evidence.get("binary_name_match"),
                "blintdb_matched_symbol_count": evidence.get("matched_symbol_count"),
                "blintdb_matched_symbol_sources": evidence.get("matched_symbol_sources", []),
                "blintdb_matched_symbols": evidence.get("matched_symbols", []),
                "blintdb_matched_instruction_hash_count": evidence.get(
                    "matched_instruction_hash_count"
                ),
                "blintdb_matched_instruction_hashes": evidence.get(
                    "matched_instruction_hashes", []
                ),
                "blintdb_matched_assembly_hash_count": evidence.get("matched_assembly_hash_count"),
                "blintdb_matched_assembly_hashes": evidence.get("matched_assembly_hashes", []),
                "blintdb_matched_callgraph_count": evidence.get("matched_callgraph_count"),
                "blintdb_matched_callgraph_functions": evidence.get(
                    "matched_callgraph_functions", []
                ),
            }
            comp = create_dynamic_component(
                {"purl": binary_purl, "tag": "NEEDED"},
                exe,
                {
                    key: value
                    for key, value in evidence_metadata.items()
                    if value not in (None, [], "")
                },
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


def create_dynamic_component(entry: Dict, exe: str, evidence_metadata: dict = None) -> Component:
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
            if isinstance(v, (list, tuple, set)):
                value = ", ".join(str(item) for item in v)
            else:
                value = str(v)
            properties.append(
                Property(
                    name=f"internal:{k}",
                    value=value,
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
        sbom (obj): Software Bill-of-Materials object to be updated.

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
        # Promote any known service / tracker SDKs bundled in the app into the
        # CycloneDX services list.
        services = detect_services(app_components)
        if services:
            existing = {s.bom_ref.root for s in (sbom.services or []) if s.bom_ref}
            sbom.services = (sbom.services or []) + [
                s for s in services if not s.bom_ref or s.bom_ref.root not in existing
            ]
    return app_components


def _ios_purl(bundle_identifier: str, version: str, qualifiers: dict | None = None) -> str:
    """Build a ``pkg:ios`` PackageURL string for an app bundle component."""
    return PackageURL(
        type="ios",
        name=bundle_identifier,
        version=version or None,
        qualifiers=qualifiers or {},
    ).to_string()


def ios_parent_component(bundle_info: dict, app_file: str) -> Component | None:
    """Build the parent application component for an iOS/macOS app bundle.

    The component is identified by the bundle's ``CFBundleIdentifier`` and
    version, mirroring how the android path derives the parent from the
    manifest package name.
    """
    identifier = bundle_info.get("bundle_identifier")
    name = identifier or bundle_info.get("bundle_name") or os.path.basename(app_file)
    version = str(bundle_info.get("bundle_version") or "")
    if not name:
        return None
    purl = _ios_purl(name, version)
    component = Component(type=Type.application, name=name, version=version, purl=purl)
    component.bom_ref = RefType(purl)
    manifest = bundle_info.get("privacy_manifest") or {}
    scalar_props = {
        "internal:bundleName": bundle_info.get("bundle_name"),
        "internal:bundleDisplayName": bundle_info.get("bundle_display_name"),
        "internal:bundleBuild": bundle_info.get("bundle_build"),
        "internal:minimumOSVersion": bundle_info.get("minimum_os_version"),
        "internal:platformName": bundle_info.get("platform_name"),
        "internal:platformVersion": bundle_info.get("platform_version"),
        "internal:applicationCategory": bundle_info.get("application_category"),
        # Privacy posture surfaced for at-a-glance triage.
        "internal:privacyManifestPresent": "true" if manifest.get("present") else "false",
        "internal:privacyTracking": "true" if manifest.get("tracking") else None,
    }
    list_props = {
        "internal:privacyUsageDescriptions": bundle_info.get("privacy_usage_descriptions"),
        "internal:appQuerySchemes": bundle_info.get("query_schemes"),
        "internal:bonjourServices": bundle_info.get("bonjour_services"),
        "internal:privacyTrackingDomains": manifest.get("tracking_domains"),
        "internal:privacyCollectedDataTypes": manifest.get("collected_data_types"),
        "internal:privacyAccessedAPICategories": manifest.get("accessed_api_categories"),
    }
    component.properties = [
        Property(name=key, value=str(value)) for key, value in scalar_props.items() if value
    ]
    component.properties += [
        Property(name=key, value=", ".join(values)) for key, values in list_props.items() if values
    ]
    return component


def ios_binary_component(entry: dict, bundle_info: dict) -> Component:
    """Build a component for a single Mach-O binary inside an app bundle.

    The main executable is reported as an application sub-component while
    embedded frameworks, dylibs and app-extension binaries are reported as
    libraries. Embedded frameworks and extensions are identified by their own
    ``Info.plist`` (real product identifier and version) when available, falling
    back to the host app's identity; components are keyed by their
    bundle-relative path so they remain unique within the bundle.
    """
    bundle_path = entry.get("bundle_path") or os.path.basename(entry["path"])
    role = entry.get("role", "framework")
    name = os.path.basename(bundle_path)
    # purls are canonical and must not embed Windows separators; the bundle path
    # is logically POSIX-style regardless of the extraction host.
    purl_path = bundle_path.replace("\\", "/")
    # Prefer the binary's own bundle identity (set for frameworks / appex);
    # fall back to the host application's identity and version.
    identifier = entry.get("bundle_identifier") or bundle_info.get("bundle_identifier") or name
    version = str(entry.get("bundle_version") or bundle_info.get("bundle_version") or "")
    comp_type = Type.application if role == "main" else Type.library
    purl = _ios_purl(identifier, version, {"path": purl_path})
    properties = [
        Property(name="internal:srcFile", value=bundle_path),
        Property(name="internal:role", value=role),
    ]
    if entry.get("bundle_identifier"):
        properties.append(Property(name="internal:bundleIdentifier", value=identifier))
    component = Component(
        type=comp_type,
        name=name,
        version=version,
        purl=purl,
        scope=Scope.required,
        evidence=create_component_evidence(bundle_path, 0.8),
        properties=properties,
    )
    component.bom_ref = RefType(purl)
    hashes = calculate_hashes(entry["path"])
    if hashes.get("sha256"):
        component.hashes = [Hash(alg=HashAlg.SHA_256, content=hashes["sha256"])]
    return component


# Install-path prefixes of dylibs provided by the iOS/macOS platform (the OS or
# the toolchain). These are not third-party supply-chain dependencies.
_APPLE_PLATFORM_DYLIB_PREFIXES = (
    "/System/",
    "/usr/lib/",
    "/Library/Apple/",
)


def is_apple_platform_library(install_name: str) -> bool:
    """Return True for a dylib install name provided by the Apple platform.

    Apps link many Apple frameworks (Foundation, UIKit, libSystem, ...) by
    absolute install path. These ship with the OS rather than being bundled in
    the ``.ipa``, so they are platform-provided rather than supply-chain
    dependencies and are tagged accordingly in the SBOM.
    """
    if not install_name:
        return False
    return install_name.startswith(_APPLE_PLATFORM_DYLIB_PREFIXES)


def ios_binary_libraries(bin_path: str) -> list[Component]:
    """Build linked-dylib components for one Mach-O, tagging their provenance.

    Each ``LC_LOAD_DYLIB`` becomes a library component. Apple platform
    frameworks are tagged ``internal:provenance=apple-platform`` and scoped
    ``excluded`` so SBOM consumers can filter the OS-provided noise from the
    bundled (``@rpath`` / ``@executable_path``) third-party dependencies, which
    are tagged ``internal:provenance=bundled``.
    """
    lib_components: list[Component] = []
    metadata = parse(bin_path)
    for lib_entry in metadata.get("libraries", []) or []:
        comp = create_library_component(lib_entry, bin_path)
        install_name = lib_entry.get("name", "")
        if is_apple_platform_library(install_name):
            comp.scope = Scope.excluded
            provenance = "apple-platform"
        else:
            provenance = "bundled"
        if comp.properties is None:
            comp.properties = []
        comp.properties.append(Property(name="internal:provenance", value=provenance))
        lib_components.append(comp)
    return lib_components


def process_ios_file(
    dependencies_dict: dict[str, set],
    deep_mode: bool,
    f: str,
    sbom: CycloneDX,
) -> list[Component]:
    """Process an iOS/macOS app (``.ipa``) and update the SBOM.

    The archive is unpacked and each embedded Mach-O binary (the main
    executable, frameworks, dylibs and app extensions) becomes a component
    depending on the app-bundle parent, mirroring the android app path.

    Args:
        dependencies_dict (dict[str, set]): Existing dependencies dictionary.
        deep_mode (bool): Flag indicating whether to include per-binary library
            components extracted from the Mach-O load commands.
        f (str): The ``.ipa`` file to process.
        sbom (CycloneDX): Software Bill-of-Materials object to be updated.

    Returns:
        list: The components discovered in the app.
    """
    app = collect_ios_app(f)
    if app is None:
        return []
    components: list[Component] = []
    try:
        parent_component = ios_parent_component(app["bundle_info"], f)
        if parent_component:
            if not sbom.metadata.component.components:
                sbom.metadata.component.components = []
            _add_to_parent_component(sbom.metadata.component.components, parent_component)
        binary_components: list[Component] = []
        for entry in app["binaries"]:
            comp = ios_binary_component(entry, app["bundle_info"])
            binary_components.append(comp)
            components.append(comp)
            if deep_mode:
                lib_components = ios_binary_libraries(entry["path"])
                components += lib_components
                if lib_components:
                    track_dependency(dependencies_dict, comp, lib_components)
        if parent_component and binary_components:
            track_dependency(dependencies_dict, parent_component, binary_components)
    finally:
        shutil.rmtree(app["temp_dir"], ignore_errors=True)
    return components


def write_dex_callgraph(app_file: str, sbom_output: str) -> None:
    """
    Write a Dalvik callgraph sidecar next to the BOM.

    Emitted when disassembly is requested (``--disassembly``), matching how
    native binary callgraphs are produced. The callgraph is written as
    ``<bom-stem>-<app>.dex-callgraph.json`` in the same JSON shape as blint's
    native binary callgraph, so it can be loaded by the callgraph tooling and
    exported to DOT / GraphML.
    """
    if not sbom_output:
        return
    try:
        callgraph = build_app_dex_callgraph(app_file)
    except Exception as e:  # callgraph emission must never fail SBOM generation
        LOG.debug(f"Unable to build the dex callgraph for {app_file}: {e}")
        return
    if not callgraph.get("nodes"):
        return
    stem = os.path.splitext(sbom_output)[0]
    app_name = os.path.basename(app_file)
    out_file = f"{stem}-{app_name}.dex-callgraph.json"
    try:
        file_write(out_file, orjson.dumps(callgraph).decode(), log=LOG)
        LOG.info(
            f"Wrote dex callgraph ({len(callgraph['nodes'])} nodes, "
            f"{len(callgraph['edges'])} edges) to {out_file}"
        )
    except OSError as e:
        LOG.debug(f"Unable to write the dex callgraph to {out_file}: {e}")


def _callgraph_sidecar_slug(bundle_path: str) -> str:
    """Turn a bundle-relative path into a filesystem-safe sidecar name segment.

    Both POSIX (``/``) and Windows (``\\``) separators are flattened regardless
    of the host OS so the emitted file name is deterministic everywhere.
    """
    slug = bundle_path.replace("\\", "_").replace("/", "_").replace(" ", "_")
    return slug or "binary"


def write_ios_callgraphs(app_file: str, sbom_output: str) -> None:
    """
    Write native Mach-O callgraph sidecars for an iOS/macOS app next to the BOM.

    Emitted when disassembly is requested (``--disassemble``), mirroring the
    Dalvik sidecar produced for android apps. One file is written per embedded
    Mach-O that yields a callgraph, named
    ``<bom-stem>-<app>-<bundle-path>.callgraph.json`` in the same JSON shape as
    blint's native binary callgraph, so it can be loaded by the callgraph
    tooling and exported to DOT / GraphML / GEXF. FairPlay-encrypted binaries
    (whose ``__TEXT`` cannot be disassembled) are skipped.
    """
    if not sbom_output:
        return
    app = collect_ios_app(app_file)
    if app is None:
        return
    stem = os.path.splitext(sbom_output)[0]
    app_name = os.path.basename(app_file)
    try:
        for entry in app["binaries"]:
            bin_path = entry["path"]
            bundle_path = entry.get("bundle_path") or os.path.basename(bin_path)
            try:
                metadata = parse(bin_path, disassemble=True)
            except Exception as e:  # callgraph emission must never fail SBOM generation
                LOG.debug(f"Unable to disassemble {bundle_path} in {app_file}: {e}")
                continue
            callgraph = metadata.get("callgraph")
            if not isinstance(callgraph, dict) or not callgraph.get("nodes"):
                continue
            out_file = f"{stem}-{app_name}-{_callgraph_sidecar_slug(bundle_path)}.callgraph.json"
            try:
                file_write(out_file, orjson.dumps(callgraph).decode(), log=LOG)
                LOG.info(
                    f"Wrote callgraph for {bundle_path} ({len(callgraph['nodes'])} nodes, "
                    f"{len(callgraph['edges'])} edges) to {out_file}"
                )
            except OSError as e:
                LOG.debug(f"Unable to write the callgraph to {out_file}: {e}")
    finally:
        shutil.rmtree(app["temp_dir"], ignore_errors=True)


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
                base64.b64decode(v.get("sha512").removeprefix("sha512-"), validate=True),
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
            evidence=create_component_evidence(v.get("path"), 1.0) if v.get("path") else {},
            properties=[
                Property(name="internal:serviceable", value=str(v.get("serviceable")).lower()),
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
        purl_qualifer = ""
        if dependency.get("source"):
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
        if not dependencies_dict.get(parent_component.bom_ref.model_dump(mode="python")):
            dependencies_dict[parent_component.bom_ref.model_dump(mode="python")] = set()
        for acomp in app_components:
            if not dependencies_dict.get(acomp.bom_ref.model_dump(mode="python")):
                dependencies_dict[acomp.bom_ref.model_dump(mode="python")] = set()
            # Prevent self loops
            if parent_component.bom_ref.model_dump(mode="python") != acomp.bom_ref.model_dump(
                mode="python"
            ):
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
