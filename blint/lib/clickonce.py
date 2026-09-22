"""ClickOnce deployment/application manifest reader (W4.3).

A ClickOnce app ships two XML manifests: ``.application`` (the deployment
manifest — identity, update URL, requested trust) and an application
``.manifest`` (the files that make up the app plus its requested execution
level). blint parses both as untrusted XML through defusedxml (no entity
expansion), reporting the declared facts — identity, publisher, the
``<trustInfo>`` requested permission set, the deployment provider URL and
the XML-DSig signature presence — and never treating a plain PE-sidecar
``.manifest`` as ClickOnce unless its namespace actually is one.

Cross-platform: pure XML parsing; a Linux run and a Windows run produce the
same facts (ground rule 31).
"""

# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
# SPDX-License-Identifier: Apache-2.0

import os

from blint.logger import LOG

DEPLOYMENT_EXT = ".application"

# Namespaces that make a ``.manifest`` a ClickOnce *application* manifest
# rather than an ordinary assembly manifest.
_ASM_V2_NS = "urn:schemas-microsoft-com:asm.v2"
_ASM_V1_NS = "urn:schemas-microsoft-com:asm.v1"


def is_clickonce_file(path) -> bool:
    """True for ``.application`` manifests and ClickOnce-shaped ``.manifest``s."""
    if not isinstance(path, str) or not os.path.isfile(path):
        return False
    if path.lower().endswith(DEPLOYMENT_EXT):
        return True
    if not path.lower().endswith(".manifest"):
        return False
    try:
        with open(path, "rb") as handle:
            head = handle.read(4096)
    except OSError:
        return False
    return b"asm.v2" in head and b"trustInfo" in head


def _localname(tag: str) -> str:
    return tag.rpartition("}")[2]


def _find_local(parent, name):
    for child in parent:
        if _localname(child.tag) == name:
            return child
    return None


def _iter_local(parent, name):
    for element in parent.iter():
        if _localname(element.tag) == name:
            yield element


def _attr(element, local: str) -> str | None:
    """Namespace-agnostic attribute read (asmv2:publisher etc.)."""
    for key, value in element.attrib.items():
        if _localname(key) == local:
            return value
    return None


def _identity_facts(element) -> dict:
    if element is None:
        return {}
    return {
        key: element.get(key)
        for key in ("name", "version", "publicKeyToken", "culture", "processorArchitecture")
        if element.get(key)
    }


def parse_clickonce(path: str) -> dict | None:
    """Parse one ClickOnce manifest into blint's facts block.

    Returns None when the file is not a ClickOnce manifest at all (not a
    refusal — the caller simply routes it elsewhere).
    """
    import defusedxml.ElementTree as ET

    try:
        with open(path, "rb") as handle:
            data = handle.read(2 * 1024 * 1024)  # 2 MiB manifest bound
    except OSError:
        return None
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return None
    root_local = _localname(root.tag)
    if root_local not in ("application", "assembly"):
        return None
    # Deployment manifests are <assembly> roots carrying a <deployment>
    # element (or <deploymentIdentity>); application manifests carry
    # <dependency>/<file> entries instead.
    kind = "application"
    if _find_local(root, "deployment") is not None or _find_local(root, "deploymentIdentity") is not None:
        kind = "deployment"
    block: dict = {
        "kind": kind,
        "identity": {},
        "publisher": None,
        "product": None,
        "update_url": None,
        "requested_execution_level": None,
        "permission_set_unrestricted": None,
        "compatible_frameworks": [],
        "files": [],
        "signature_present": False,
        "refusals": [],
    }
    description = _find_local(root, "description")
    if description is not None:
        block["publisher"] = _attr(description, "publisher")
        block["product"] = _attr(description, "product")
    identity = None
    if kind == "deployment":
        deployment_identity = _find_local(root, "deploymentIdentity")
        identity = deployment_identity or _find_local(root, "assemblyIdentity")
        for element in _iter_local(root, "deploymentProvider"):
            block["update_url"] = element.get("url")
            break
        for framework in _iter_local(root, "compatibleFrameworks"):
            for target in _iter_local(framework, "targetFramework"):
                name = target.get("version")
                if name:
                    block["compatible_frameworks"].append(name)
    else:
        assembly_identity = None
        for element in _iter_local(root, "assemblyIdentity"):
            assembly_identity = element
            break
        identity = assembly_identity
        for file_element in _iter_local(root, "file"):
            name = file_element.get("name")
            if name:
                block["files"].append(name)
    block["identity"] = _identity_facts(identity)
    for trust in _iter_local(root, "trustInfo"):
        security = _find_local(trust, "security")
        if security is None:
            continue
        request = _find_local(security, "applicationRequestMinimum")
        if request is not None:
            permission_set = _find_local(request, "PermissionSet")
            if permission_set is not None:
                block["permission_set_unrestricted"] = (
                    permission_set.get("Unrestricted", "false").lower() == "true"
                )
            default_set = _find_local(request, "defaultAssemblyRequest")
            _ = default_set
        execution = None
        for element in _iter_local(trust, "requestedExecutionLevel"):
            execution = element.get("level")
            break
        block["requested_execution_level"] = execution
    for signature in _iter_local(root, "Signature"):
        block["signature_present"] = True
        break
    if kind == "deployment" and not block["identity"]:
        block["refusals"].append("deployment_identity_missing")
    LOG.debug("ClickOnce %s manifest parsed: %s", kind, block["identity"].get("name"))
    return block


def clickonce_metadata(block: dict, file_path: str) -> dict:
    """The analyzed metadata dict for one ClickOnce manifest unit."""
    name = block["identity"].get("name") or os.path.basename(file_path)
    metadata: dict = {
        "name": name,
        "file_path": file_path,
        "exe_type": "clickonce",
        "clickonce": block,
    }
    return metadata
