import base64
import binascii
import codecs
import os
import re
import shutil
import sys
import uuid
from datetime import datetime
from typing import Any, Literal, TextIO, cast

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
from blint.lib.parallel import (
    PoolStartupError,
    WorkerSpec,
    payload_as_state,
    run_pool,
    take_worker_logs,
)
from blint.lib.utils import (
    calculate_hashes,
    camel_to_snake,
    create_component_evidence,
    find_bom_files,
    get_version,
)
from blint.logger import LOG


def default_parent(src_dirs: list[str], symbols_purl_map: dict | None = None) -> Component:
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
    purl = PackageURL(type=purl_type, name=name).to_string()
    pkg_type = Type.library if purl_type not in ("generic",) else Type.application
    if symbols_purl_map and symbols_purl_map.get(purl):
        purl = symbols_purl_map[purl]
        pkg_type = Type.library
        if "@" in purl:
            version = purl.split("@")[-1]
    component = Component(type=pkg_type, name=name, version=version, purl=purl)
    component.bom_ref = RefType(purl)
    return component


def default_metadata(src_dirs: list[str]) -> Metadata:
    """
    Creates default metadata for SBOM generation.

    Args:
        src_dirs (list): A list of source directories.

    Returns:
        Metadata: A Metadata object for SBOM generation.
    """
    metadata = Metadata()
    metadata.timestamp = f"{datetime.now().isoformat(timespec='seconds')}Z"  # type: ignore[assignment]
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


def generate(
    blint_options: BlintOptions,
    exe_files: list[str],
    android_files: list[str],
    ios_files: list[str] | None = None,
) -> CycloneDX | Literal[False]:
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
    symbols_purl_map: dict = {}
    if blint_options.src_dir_boms:
        symbols_purl_map = populate_purl_lookup(blint_options.src_dir_boms)
    components = []
    dependencies = []
    dependencies_dict: dict[str, set] = {}
    sbom = CycloneDX(
        bomFormat=BomFormat.CycloneDX,
        specVersion="1.6",
        version=1,
        serialNumber=f"urn:uuid:{uuid.uuid4()}",
    )
    sbom.metadata = default_metadata(blint_options.src_dir_image)
    jobs = max(1, int(getattr(blint_options, "jobs", 1) or 1))
    with Progress(
        transient=True,
        redirect_stderr=True,
        redirect_stdout=True,
        refresh_per_second=1,
        disable=blint_options.quiet_mode,
    ) as progress:
        skipped_wasm = 0
        ran_parallel = False
        if exe_files and jobs > 1 and len(exe_files) > 1:
            try:
                skipped_wasm = _generate_exes_parallel(
                    blint_options,
                    exe_files,
                    sbom,
                    components,
                    dependencies_dict,
                    symbols_purl_map,
                    progress,
                )
                ran_parallel = True
            except PoolStartupError as exc:
                # Parallelism must never be the reason an SBOM fails; the
                # merge happens only after the pool succeeds, so nothing has
                # been accumulated and the sequential loop below processes
                # every file.
                LOG.error(
                    f"Parallel SBOM generation unavailable ({exc}); falling back to sequential"
                )
        if not ran_parallel:
            task = progress.add_task(
                f"[green] Parsing {len(exe_files)} binaries",
                total=len(exe_files),
                start=True,
            )
            for exe in exe_files:
                if is_wasm_file(exe):
                    if blint_options.wasm_sbom:
                        components += process_wasm_file(dependencies_dict, exe, sbom)
                    else:
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
            LOG.info(
                f"Skipped {skipped_wasm} wasm file(s) during SBOM generation; "
                "use --wasm-sbom to include Component Model interface dependencies"
            )
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
                write_dex_callgraph(f, cast(str, blint_options.sbom_output))
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
                write_ios_callgraphs(f, cast(str, blint_options.sbom_output))
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
    output_file: str | TextIO,
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
        output_file_str = cast(str, output_file)
        output_dir = os.path.dirname(output_file_str)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)

        file_write(
            os.path.join(output_dir, output_file_str),
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


def purl_field(value: Any) -> str | None:
    """Coerce a purl version or qualifier value to a non-empty string.

    PackageURL normalizes versions and qualifier values by calling ``strip()`` on
    them, so a non-string raises AttributeError. Binary metadata routinely holds
    numbers here: LIEF reports an ELF symbol version auxiliary ``hash`` as an int.
    Returns None for values that should be omitted from the purl entirely.
    """
    if value is None or isinstance(value, bool):
        return None
    if not isinstance(value, str):
        value = str(value)
    value = value.strip()
    return value or None


def components_from_abi_requirements(abi_analysis: dict) -> list[Component]:
    """Create components from the ABI floor each version provider imposes.

    The version recorded here is the highest version node any *imported* symbol
    binds to, which is the actual minimum the binary needs at runtime. Deriving
    it from the imports rather than from the version definition table avoids two
    errors that table alone produces: attributing a version to a provider no
    symbol uses, and reporting a version lower than the one really required.

    Args:
        abi_analysis (dict): The ``abi_analysis`` block from parsed metadata.

    Returns:
        list[Component]: list of components
    """
    lib_components: list[Component] = []
    for requirement in abi_analysis.get("requirements") or []:
        provider = requirement.get("provider") or ""
        version = requirement.get("min_version") or None
        name = requirement.get("package_name") or provider.lower()
        group = requirement.get("package_group") or ""
        if not name:
            continue
        purl = PackageURL(
            type="generic",
            namespace=group or None,
            name=name,
            version=purl_field(version),
        ).to_string()
        properties = [
            Property(name="internal:abi_provider", value=provider),
            Property(
                name="internal:abi_symbol_count",
                value=str(requirement.get("symbol_count", 0)),
            ),
        ]
        if determining := requirement.get("determining_symbols"):
            # Recording which imports set the floor lets a reader verify a
            # surprising version requirement instead of taking it on trust.
            properties.append(
                Property(
                    name="internal:abi_determining_symbols",
                    value=", ".join(determining[:8]),
                )
            )
        comp = Component(
            type=Type.library,
            group=group,
            name=name,
            version=version,
            purl=purl,
            # A floor derived from the imports is much stronger evidence than a
            # name split, but it is still a floor rather than the exact version
            # installed, so it stays short of full confidence.
            evidence=create_component_evidence(
                f"{provider}_{version}" if version else provider, 0.8
            ),
            properties=properties,
        )
        comp.bom_ref = RefType(purl)
        lib_components.append(comp)
    return lib_components


def components_from_recovered_dependencies(recovered: list[dict]) -> list[Component]:
    """Create components for libraries the binary loads at runtime.

    These never appear in the dynamic dependency table, so without them a plugin
    host or a driver loader produces an SBOM that omits precisely the components
    that determine what it can do. They are marked optional because the binary
    runs without them, in a reduced form.

    Args:
        recovered (list[dict]): The ``recovered_dependencies`` metadata block.

    Returns:
        list[Component]: list of components
    """
    confidence_scores = {"high": 0.6, "medium": 0.4, "low": 0.2}
    lib_components: list[Component] = []
    for entry in recovered or []:
        name = entry.get("name") or ""
        if not name:
            continue
        # Strip the extension and version suffix so the component name matches
        # what a package ecosystem calls the library.
        base = name.split(".so")[0].removesuffix(".dylib").removesuffix(".dll")
        pkg_type = "nuget" if name.endswith(".dll") else "generic"
        purl = PackageURL(type=pkg_type, name=base).to_string()
        comp = Component(
            type=Type.library,
            name=base,
            purl=purl,
            scope=Scope.optional,
            evidence=create_component_evidence(
                name, confidence_scores.get(entry.get("confidence"), 0.2)
            ),
            properties=[
                Property(name="internal:soname", value=name),
                Property(name="internal:load_kind", value="runtime"),
                Property(
                    name="internal:evidence",
                    value="; ".join(entry.get("evidence") or []),
                ),
            ],
        )
        comp.bom_ref = RefType(purl)
        lib_components.append(comp)
    return lib_components


def components_from_symbols_version(symbols_version: list[dict]) -> list[Component]:
    """
    Creates a list of Component objects from symbols version.
    This style of detection is quite imprecise since the version is just a min
    specifier. It is a fallback for binaries where the per-symbol version
    information needed by ``components_from_abi_requirements`` is unavailable.

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
        purl = PackageURL(
            type=pkg_type,
            namespace=group or None,
            name=name,
            version=purl_field(version),
            qualifiers=(
                {"hash": hash_value} if (hash_value := purl_field(symbol.get("hash"))) else {}
            ),
        ).to_string()
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
) -> None:
    for mc in metadata_components:
        if mc.bom_ref.model_dump(mode="python") == parent_component.bom_ref.model_dump(
            mode="python"
        ):
            return
    metadata_components.append(parent_component)


class _OrderedDeps:
    """Insertion-ordered set emulation for one dependency entry.

    Records the order refs were added in, which plain sets destroy; see
    :class:`_DepCapture` for why that order matters.
    """

    __slots__ = ("order", "_seen")

    def __init__(self) -> None:
        self.order: list[str] = []
        self._seen: set[str] = set()

    def add(self, value: str) -> None:
        if value not in self._seen:
            self._seen.add(value)
            self.order.append(value)

    def update(self, values) -> None:
        for value in values:
            self.add(value)

    def __bool__(self) -> bool:
        return True


class _DepCapture(dict):
    """Worker-side ``dependencies_dict`` that records insertion order.

    The SBOM builders grow their ``dependencies_dict`` through ``.get`` or
    ``[]`` followed by ``.add``/``.update``, replacing an entry only when it
    looks empty. Auto-creating a truthy ordered shim on first access keeps
    those replacements from happening, so the worker sees the exact per-file
    insertion sequence the sequential run would have produced. The parent
    replays that sequence into its accumulated sets in submission order;
    identical insertion sequence means identical set layout, which is what
    keeps the serialized ``dependsOn`` order byte-identical to the
    sequential run.
    """

    def get(self, key, default=None):
        if key not in self:
            self[key] = _OrderedDeps()
        return dict.__getitem__(self, key)

    def __missing__(self, key):
        self[key] = _OrderedDeps()
        return self[key]


def _scratch_sbom() -> CycloneDX:
    """A throwaway CycloneDX scaffold for one unit of SBOM work.

    ``process_exe_file`` and ``process_wasm_file`` record the binary's parent
    component by appending to ``sbom.metadata.component.components``; pool
    workers hand each unit a private scaffold so the parent-side append (and
    its dedupe against the accumulated list) happens exactly once, at the
    unit's merge position, in submission order.
    """
    scratch = CycloneDX(
        bomFormat=BomFormat.CycloneDX,
        specVersion="1.6",
        version=1,
        serialNumber=f"urn:uuid:{uuid.uuid4()}",
    )
    scratch.metadata = Metadata()
    scratch.metadata.component = Component(type=Type.application, name="blint-scratch")
    return scratch


def _drain_parent_components(scratch: CycloneDX) -> list[Component]:
    """Return (and clear) the parent components a unit appended to its scratch."""
    components_list = scratch.metadata.component.components if scratch.metadata else None
    if not components_list:
        return []
    scratch.metadata.component.components = []
    return list(components_list)


def analyze_unit_sbom(file_path: str, state: dict[str, Any]) -> dict[str, Any]:
    """Process one file for the SBOM inside a pool worker.

    Parallel twin of the sequential ``generate()`` loop body: wasm inputs
    keep their skip/``--wasm-sbom`` handling, native inputs run the full
    ``process_exe_file``. The unit's components, its parent components and
    its dependency-graph updates travel back as one envelope; the parent
    merges them at the unit's submission index, which keeps the component
    list, the metadata parent dedupe and the dependency dict insertion
    order identical to the sequential run. Exceptions are deliberately not
    caught here (``record_errors=False``): the sequential SBOM loop aborts
    the run on a bad binary, and so does the parent when it replays the
    exception at this unit's merge position.
    """
    if is_wasm_file(file_path):
        if not state["wasm_sbom"]:
            return {
                "wasm": True,
                "skipped": True,
                "components": [],
                "parent_components": [],
                "deps_updates": {},
                "logs": take_worker_logs(),
            }
        scratch = _scratch_sbom()
        deps_updates = _DepCapture()
        components = process_wasm_file(deps_updates, file_path, scratch)
        return {
            "wasm": True,
            "skipped": False,
            "components": components,
            "parent_components": _drain_parent_components(scratch),
            "deps_updates": {ref: ordered.order for ref, ordered in deps_updates.items()},
            "logs": take_worker_logs(),
        }
    scratch = _scratch_sbom()
    deps_updates = _DepCapture()
    components = process_exe_file(
        deps_updates,
        state["deep_mode"],
        file_path,
        scratch,
        state["exports_prefix"],
        state["symbols_purl_map"],
        state["use_blintdb"],
        state["disassemble"],
    )
    return {
        "wasm": False,
        "skipped": False,
        "components": components,
        "parent_components": _drain_parent_components(scratch),
        "deps_updates": {ref: ordered.order for ref, ordered in deps_updates.items()},
        "logs": take_worker_logs(),
    }


def _merge_dependency_updates(
    dependencies_dict: dict[str, set], updates: dict[str, list]
) -> None:
    """Fold one unit's dependency-graph updates into the run's dict.

    The updates carry per-ref refs in the order the worker added them;
    replaying that order (instead of batch-inserting a set) gives the
    accumulated sets exactly the insertion sequence of the sequential run,
    which is what keeps ``dependsOn`` serialization byte-identical.
    """
    for ref, deps in updates.items():
        dependencies_dict.setdefault(ref, set()).update(deps)


def _generate_exes_parallel(
    blint_options: BlintOptions,
    exe_files: list[str],
    sbom: CycloneDX,
    components: list[Component],
    dependencies_dict: dict[str, set],
    symbols_purl_map: dict,
    progress: Progress,
) -> int:
    """Run the per-binary SBOM work in a process pool; returns the count of
    wasm files skipped for lack of ``--wasm-sbom``.

    Results merge in submission order. A worker that dies hard while a
    binary was assigned to it raises here rather than dropping the binary
    silently: an SBOM missing a component is a wrong answer, and the
    sequential path would have died on the same binary too.
    """
    jobs = max(1, int(getattr(blint_options, "jobs", 1) or 1))
    spec = WorkerSpec(
        analyze=analyze_unit_sbom,
        setup=payload_as_state,
        payload={
            "deep_mode": blint_options.deep_mode,
            "exports_prefix": blint_options.exports_prefix,
            "symbols_purl_map": symbols_purl_map,
            "use_blintdb": blint_options.use_blintdb,
            "disassemble": blint_options.disassemble,
            "wasm_sbom": blint_options.wasm_sbom,
        },
        unit_role="sbom",
        record_errors=False,
    )
    units = [(idx, f) for idx, f in enumerate(exe_files)]
    task = progress.add_task(
        f"[green] Parsing {len(exe_files)} binaries ({jobs} workers)",
        total=len(exe_files),
        start=True,
    )
    envelopes, hard_failures = run_pool(
        units,
        min(jobs, len(units)),
        spec,
        on_done=lambda _idx: progress.advance(task),
    )
    # process_exe_file initializes this list lazily on first append; the
    # merge does the same so parent components land identically.
    if not sbom.metadata.component.components:
        sbom.metadata.component.components = []
    skipped_wasm = 0
    for idx in range(len(exe_files)):
        if idx in hard_failures:
            raise RuntimeError(
                f"worker died while processing {exe_files[idx]}: {hard_failures[idx]}"
            )
        envelope = envelopes[idx]
        for level, message in envelope.get("logs") or []:
            LOG.log(level, message)
        if "exception" in envelope:
            # analyze_unit_sbom runs without its own per-unit isolation on
            # purpose: the sequential loop aborts the run on a bad binary,
            # and replaying the exception at this unit's merge position
            # reproduces exactly that.
            raise envelope["exception"]
        if envelope["wasm"]:
            if envelope["skipped"]:
                skipped_wasm += 1
            else:
                components += envelope["components"]
                for parent_component in envelope["parent_components"]:
                    _add_to_parent_component(sbom.metadata.component.components, parent_component)
                _merge_dependency_updates(dependencies_dict, envelope["deps_updates"])
        else:
            components += envelope["components"]
            for parent_component in envelope["parent_components"]:
                _add_to_parent_component(sbom.metadata.component.components, parent_component)
            _merge_dependency_updates(dependencies_dict, envelope["deps_updates"])
            progress.update(
                task,
                description=f"Processed [bold]{os.path.basename(exe_files[idx])}[/bold]",
                advance=1,
            )
    return skipped_wasm


def process_exe_file(
    dependencies_dict: dict[str, set],
    deep_mode: bool,
    exe: str,
    sbom: CycloneDX,
    export_prefixes: list[str] | None = None,
    symbols_purl_map: dict | None = None,
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
    export_prefixes = export_prefixes or []
    metadata: dict[str, Any] = parse(exe, disassemble=disassemble)
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
    # A driver's control codes and the device object they are reached through are
    # the part of its attack surface a consumer of the SBOM most needs, and they
    # are lost entirely if only the `is_driver` flag is carried across.
    if driver_ioctls := metadata.get("driver_ioctls"):
        if codes := [entry["code"] for entry in driver_ioctls.get("ioctls", [])]:
            parent_component.properties.append(
                Property(name="internal:driver_ioctl_codes", value=", ".join(codes))
            )
    for key, values in (metadata.get("driver_interface") or {}).items():
        parent_component.properties.append(
            Property(name=f"internal:{key}", value=", ".join(values))
        )
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
        abi_analysis: dict = metadata.get("abi_analysis") or {}
        # The ABI floor computed from the imported symbols supersedes the
        # version-node heuristic, which cannot tell which nodes are actually
        # bound. Fall back to it only when no floor could be derived.
        abi_components = components_from_abi_requirements(abi_analysis)
        if abi_components:
            lib_components += abi_components
        else:
            lib_components += components_from_symbols_version(symbols_version)
        lib_components += components_from_recovered_dependencies(
            metadata.get("recovered_dependencies")
        )
        for prop_name, prop_value in (
            ("abi_libc", abi_analysis.get("libc")),
            ("abi_min_glibc_version", abi_analysis.get("min_glibc_version")),
            (
                "abi_portability_notes",
                " ".join(abi_analysis.get("portability_notes") or []),
            ),
        ):
            if prop_value:
                parent_component.properties.append(
                    Property(name=f"internal:{prop_name}", value=str(prop_value))
                )
        if link_hygiene := metadata.get("link_hygiene"):
            # A declared dependency nothing imports from still lands in every
            # downstream inventory and vulnerability match, so the SBOM is the
            # right place to say which ones they are.
            if unused := link_hygiene.get("unused_dependencies"):
                parent_component.properties.append(
                    Property(
                        name="internal:unused_dependencies",
                        value=", ".join(entry["name"] for entry in unused),
                    )
                )
            if undeclared := link_hygiene.get("undeclared_dependencies"):
                parent_component.properties.append(
                    Property(
                        name="internal:undeclared_dependencies",
                        value=", ".join(entry["name"] for entry in undeclared),
                    )
                )
        if link_closure := metadata.get("link_closure"):
            # A closure that does not resolve is a deployment fact the SBOM
            # consumer cannot recover from the component list alone.
            if missing := link_closure.get("missing"):
                parent_component.properties.append(
                    Property(
                        name="internal:missing_dependencies",
                        value=", ".join(entry["name"] for entry in missing),
                    )
                )
            if link_closure.get("unresolved_symbol_count"):
                parent_component.properties.append(
                    Property(
                        name="internal:unresolved_symbol_count",
                        value=str(link_closure["unresolved_symbol_count"]),
                    )
                )
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
        go_components = process_go_dependencies(metadata.get("go_dependencies") or {})
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


# WIT package identifier embedded in Component Model import names, e.g.
# "wasi:cli/run@0.2.0". Names outside this grammar carry no package identity
# and are skipped rather than guessed.
WASM_INTERFACE_RE = re.compile(
    r"^(?P<namespace>[a-z0-9][a-z0-9_-]*):(?P<package>[a-z0-9][a-z0-9_-]*)"
    r"/(?P<interface>[a-z0-9][a-z0-9_-]*)(@(?P<version>.+))?$"
)


def group_wasm_interface_imports(
    imports: list[dict],
) -> dict[tuple[str, str, str | None], set[str]]:
    """
    Groups Component Model import names into their WIT packages.

    Args:
        imports (list[dict]): Component import entries, each with a ``name``.

    Returns:
        dict[tuple[str, str, str | None], set[str]]: A mapping of
        ``(namespace, package, version)`` to the full import names from that
        package. Imports without a parsable package identifier are dropped.
    """
    grouped: dict[tuple[str, str, str | None], set[str]] = {}
    for entry in imports:
        match = WASM_INTERFACE_RE.match(str(entry.get("name", "")))
        if not match:
            continue
        key = (match.group("namespace"), match.group("package"), match.group("version"))
        grouped.setdefault(key, set()).add(match.group(0))
    return grouped


def process_wasm_file(
    dependencies_dict: dict[str, set],
    exe: str,
    sbom: CycloneDX,
) -> list[Component]:
    """
    Processes a WebAssembly binary for SBOM generation.

    Core modules are skipped: their imports are low-information symbols with
    no version evidence. Component Model binaries carry exact dependency
    evidence in their imported WIT interface packages (e.g. ``wasi:cli`` at
    ``0.2.0``), which are emitted as required library components when the
    ``--wasm-sbom`` opt-in is enabled. Exported interfaces are capabilities
    the binary provides, not dependencies, so they stay a parent property.

    Args:
        dependencies_dict (dict[str, set]): A dictionary of dependencies.
        exe: The path to the WebAssembly binary.
        sbom: The CycloneDX SBOM object.

    Returns:
        list[Component]: The created library components.
    """
    # Interface extraction only needs the component block and build info;
    # strings and the call graph would be dead weight for large components.
    metadata: dict[str, Any] = parse(exe, wasm_strings=False, wasm_call_graph=False)
    if not metadata.get("is_component"):
        return []
    component_info = (metadata.get("wasm_report") or {}).get("component") or {}
    parent_component: Component = default_parent([exe])
    parent_component.properties = []
    build_info = metadata.get("build_info") or {}
    for prop_name, prop_value in (
        ("binary_type", metadata.get("binary_type")),
        ("is_component", metadata.get("is_component")),
        ("runtime", build_info.get("runtime")),
        ("wasi_variants", build_info.get("wasi_variants")),
        ("component_version", build_info.get("component_version")),
        ("layer_version", build_info.get("layer_version")),
    ):
        if prop_value:
            if isinstance(prop_value, (list, tuple, set)):
                value = ", ".join(str(item) for item in prop_value)
            elif isinstance(prop_value, bool):
                value = str(prop_value).lower()
            else:
                value = str(prop_value)
            if value:
                parent_component.properties.append(
                    Property(name=f"internal:{prop_name}", value=value)
                )
    # The same WIT grammar decides what counts as an interface on both sides;
    # an unversioned export is as real as an unversioned import.
    exported_interfaces = sorted(
        name
        for entry in component_info.get("exports") or []
        if WASM_INTERFACE_RE.match(name := str(entry.get("name", "")))
    )
    if exported_interfaces:
        parent_component.properties.append(
            Property(
                name="internal:exported_interfaces",
                value=", ".join(exported_interfaces),
            )
        )
    lib_components: list[Component] = []
    grouped = group_wasm_interface_imports(component_info.get("imports") or [])
    for (namespace, package, version), interfaces in sorted(
        grouped.items(), key=lambda item: (item[0][:2], item[0][2] or "")
    ):
        purl = PackageURL(
            type="generic",
            namespace=namespace,
            name=package,
            version=purl_field(version),
            qualifiers={"type": "wasm"},
        ).to_string()
        comp = Component(
            type=Type.library,
            group=namespace,
            name=package,
            version=version,
            purl=purl,
            scope=Scope.required,
            evidence=create_component_evidence(exe, 0.7),
            properties=[
                Property(name="internal:srcFile", value=exe),
                # The WIT id, kept verbatim so a reader can grep the component
                # back to the import names in the binary.
                Property(name="internal:wit_package", value=f"{namespace}:{package}"),
                Property(name="internal:interfaces", value=", ".join(sorted(interfaces))),
            ],
        )
        comp.bom_ref = RefType(purl)
        lib_components.append(comp)
    if parent_component.type == Type.application and len(parent_component.properties):
        if not sbom.metadata.component.components:
            sbom.metadata.component.components = []
        _add_to_parent_component(sbom.metadata.component.components, parent_component)
    if lib_components:
        track_dependency(dependencies_dict, parent_component, lib_components)
    return lib_components


def create_library_component(entry: dict, exe: str) -> Component:
    """
    Processes a library entry and creates a component object.

    Args:
        entry: The entry containing the library information.
        exe: The executable associated with the library.

    Returns:
        Component: The created component object.
    """
    name = os.path.basename(entry["name"])
    version = purl_field(entry.get("version"))
    qualifiers = {}
    if compatibility_version := purl_field(entry.get("compatibility_version")):
        qualifiers["compatibility_version"] = compatibility_version
    purl = PackageURL(type="file", name=name, version=version, qualifiers=qualifiers).to_string()
    comp = Component(
        type=Type.library,
        name=name,
        version=version,
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
    entry: dict, exe: str, evidence_metadata: dict | None = None
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
    raw_name = entry.get("name")
    name = raw_name.removeprefix("$ORIGIN/") if raw_name else None
    purl = entry.get("purl")
    if not purl and name:
        purl = PackageURL(type="file", name=name).to_string()
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
    if purl:
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


def process_go_dependencies(go_deps: dict[str, dict]) -> list[Component]:
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
        if v_hash := v.get("hash"):
            try:
                hash_content = codecs.encode(
                    base64.b64decode(v_hash.removeprefix("h1:"), validate=True),
                    encoding="hex",
                )
            except binascii.Error:
                hash_content = str(v_hash.removeprefix("h1:"))
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
    parent_component: Component | None,
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


def populate_purl_lookup(src_dir_boms: list[str]) -> dict[str, str]:
    """
    Create a purl lookup cache by parsing the various BOMs in the given source directory.

    Args:
        src_dir_boms (list): Directory containing pre-build and build sboms.

    Returns:
        dict: containing symbol name as the key and purl as the value
    """
    symbols_purl_map: dict[str, str] = {}
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
