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
)
from blint.logger import LOG
from blint.utils import find_android_files, get_version


def default_parent(src_dirs):
    return Component(
        type=Type.application,
        name=os.path.basename(src_dirs[0]),
        version="latest",
    )


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


def generate(src_dirs, output_file):
    android_files = []
    components = []
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
            progress.update(task, description=f"Processing [bold]{f}[/bold]")
            parent_component, app_components = collect_app_metadata(f)
            if parent_component:
                if not sbom.metadata.component.components:
                    sbom.metadata.component.components = []
                sbom.metadata.component.components.append(parent_component)
            if app_components:
                components += app_components
    sbom.components = components
    # If we have only one parent component then promote it to metadata.component
    if (
        sbom.metadata.component.components
        and len(sbom.metadata.component.components) == 1
    ):
        sbom.metadata.component = sbom.metadata.component.components[0]
    LOG.debug("SBOM includes %d components", len(components))
    with open(output_file, mode="w") as fp:
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
