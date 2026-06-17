"""
Static detection of remote services and third-party trackers in Android apps.

blint extracts the class names contained in an app's dex files. This module
matches those class names against bundled dictionaries of known service SDKs
(``android-services.json``) and trackers (``trackers.json``) and emits CycloneDX
``service`` entries for the ones present in the app.

Detection here is presence-based: it records that the SDK is bundled in the app,
not whether it is reachable at runtime. The data-flow direction is therefore
reported as ``unknown``; reachability-aware tooling (atom) can refine this.
"""

import importlib.resources
import json
from typing import List, Optional

from blint.config import SYMBOL_DELIMITER
from blint.cyclonedx.spec import (
    Component,
    DataClassification,
    DataFlowDirection,
    Property,
    RefType,
    Service,
    ServiceData,
)
from blint.logger import LOG


def _load_dictionary(resource: str, key: str) -> list:
    """Load a bundled JSON dictionary from the blint.data package."""
    try:
        with (
            importlib.resources.files("blint.data").joinpath(resource).open("r", encoding="utf-8")
        ) as f:
            return json.load(f).get(key, [])
    except (OSError, ValueError) as e:
        LOG.debug("Unable to load %s: %s", resource, e)
        return []


def _collect_class_names(app_components: List[Component]) -> List[str]:
    """Gather the dot-separated class names recorded on dex components."""
    classes: List[str] = []
    for component in app_components or []:
        for prop in component.properties or []:
            if prop.name == "internal:classes" and prop.value:
                classes.extend(c for c in prop.value.split(SYMBOL_DELIMITER) if c)
    return classes


def _matches(namespaces: List[str], class_names: List[str]) -> bool:
    """
    Check whether any class name matches one of the namespaces.

    Dotted package prefixes match as an anchored prefix; namespaces beginning
    with ``.`` are Exodus class-name fragments and match anywhere.
    """
    for ns in namespaces:
        if not ns:
            continue
        if ns.startswith("."):
            if any(ns in name for name in class_names):
                return True
        elif any(name.startswith(ns) for name in class_names):
            return True
    return False


def _build_service(
    name: str,
    category: str,
    local: bool,
    is_tracker: bool,
    hosts: Optional[List[str]] = None,
) -> Service:
    """Build a CycloneDX service entry for a detected SDK."""
    service = Service(
        name=name,
        group=category,
        data=[
            ServiceData(
                flow=DataFlowDirection.unknown,
                classification=DataClassification(category),
            )
        ],
        properties=[
            Property(name="internal:detection", value="static"),
            Property(
                name="internal:serviceKind",
                value="tracker" if is_tracker else "service",
            ),
        ],
    )
    # bom-ref is aliased and assigned post-construction, mirroring Component handling.
    service.bom_ref = RefType(f"service:{name}")
    # On-device runtimes stay within the trust boundary; everything else crosses it.
    service.x_trust_boundary = not local
    if hosts:
        service.endpoints = [f"https://{h}" for h in hosts if h]
    return service


def detect_services(app_components: List[Component]) -> List[Service]:
    """
    Detect remote services and trackers bundled in an Android app.

    Args:
        app_components: The components produced for the app (dex components carry
            an ``internal:classes`` property listing their class names).

    Returns:
        A list of CycloneDX service entries, one per detected SDK, sorted by name.
    """
    class_names = _collect_class_names(app_components)
    if not class_names:
        return []

    detected: dict[str, Service] = {}
    for entry in _load_dictionary("android-services.json", "services"):
        namespaces = entry.get("namespaces") or []
        if _matches(namespaces, class_names):
            name = entry.get("name", "")
            if name and name not in detected:
                detected[name] = _build_service(
                    name,
                    entry.get("category", ""),
                    bool(entry.get("local", False)),
                    is_tracker=False,
                    hosts=entry.get("hosts"),
                )
    for entry in _load_dictionary("trackers.json", "trackers"):
        namespaces = entry.get("namespaces") or []
        if _matches(namespaces, class_names):
            name = entry.get("name", "")
            if name and name not in detected:
                categories = entry.get("categories") or []
                detected[name] = _build_service(
                    name,
                    categories[0] if categories else "tracker",
                    local=False,
                    is_tracker=True,
                )
    return [detected[name] for name in sorted(detected)]
