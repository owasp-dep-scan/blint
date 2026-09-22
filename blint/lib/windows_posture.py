"""The Windows posture summary (PE lane W5.5, plan 04/E).

One block that answers "what am I looking at" before the findings list:
the signing class, the hardening properties split into present / absent /
unknown, the driver kind, the container origin and the managed shape.

Two rules this block exists to obey, both the reviewer's:

- **It summarises, it never recomputes.** Every value is read from the
  block of record (``code_signature``, ``security_properties``,
  ``driver``, ``dotnet``, the container blocks) in the same parse, and
  ``sources`` names where each fact came from. Nothing here re-derives a
  fact a second block already states, so the two cannot drift (rule 21).
- **Absent and unknown are different values** (rule 32). A hardening
  property the source computed and found off is ``absent``; a property
  whose source was unreadable - the ``security_properties_gaps`` - is
  ``unknown``. A reader must never see "this driver lacks
  /INTEGRITYCHECK" when blint means "blint could not read the flag".

Present on every Windows PE; on non-PE inputs there is no Windows
question to answer.
"""

from __future__ import annotations

from typing import Any

# The hardening properties the posture reports, with the cross-format
# name each renders under. Order is the report order.
_HARDENING_PROPERTIES: tuple[str, ...] = (
    "aslr",
    "high_entropy_va",
    "dep",
    "cfg",
    "xfg",
    "rfg",
    "retpoline",
    "cast_guard",
    "safe_delay_load",
    "cfg_export_suppression",
    "cet_shadow_stack",
    "gs_canary",
    "safe_seh",
    "force_integrity",
    "enclave",
    "nx",
    "w_xor_x",
    "pie",
)

# The exe_types a Windows container/package reports (W4 lane) - the
# "container origin" the posture names.
_CONTAINER_EXE_TYPES: set[str] = {
    "msi",
    "cab",
    "msix",
    "msixbundle",
    "appx",
    "appxbundle",
    "nupkg",
}


def _hardening_split(metadata: dict[str, Any]) -> dict[str, list[str]]:
    """The hardening properties, split by what the source actually said.

    Reads ``security_properties`` (the computed facts) and
    ``security_properties_gaps`` (the properties whose source was absent).
    A property in neither list was never computed and never gapped - it is
    not a property of this format, and the posture does not mention it.
    """
    security = metadata.get("security_properties") or {}
    gaps = set(metadata.get("security_properties_gaps") or [])
    present: list[str] = []
    absent: list[str] = []
    unknown: list[str] = []
    for name in _HARDENING_PROPERTIES:
        if name in gaps:
            unknown.append(name)
        elif name in security:
            if security[name] is True:
                present.append(name)
            else:
                absent.append(name)
    return {"present": present, "absent": absent, "unknown": unknown}


def build_windows_posture(metadata: dict[str, Any]) -> dict[str, Any] | None:
    """The ``windows_posture`` block, or None for non-Windows inputs."""
    if metadata.get("binary_type") != "PE":
        return None
    block: dict[str, Any] = {}

    # Signing: the W2.4 class, verbatim, only when it was determined. The
    # driver block's kernel-trust view is named as the second source when
    # it exists (W5.1) so a reader sees both derivations and where each
    # came from.
    code_signature = metadata.get("code_signature") or {}
    if code_signature.get("signing_class"):
        block["signing_class"] = code_signature.get("signing_class")
    block["sources"] = {
        "signing": "code_signature",
        "hardening": "security_properties",
        "driver": "driver",
        "managed_shape": "dotnet.shape",
    }

    hardening = _hardening_split(metadata)
    block["hardening"] = hardening
    # Rule 21: the security summary speaks for one slice of an ARM64X
    # image; the posture carries the scope through rather than restating
    # the values without it.
    if metadata.get("security_properties_scope"):
        block["security_properties_scope"] = metadata.get("security_properties_scope")
    if metadata.get("security_properties_slice_variance"):
        block["security_properties_slice_variance"] = list(
            metadata.get("security_properties_slice_variance") or []
        )

    driver = metadata.get("driver") or {}
    if driver.get("kind"):
        block["driver_kind"] = driver.get("kind")

    # Container origin: the W4 packaging lane stamps exe_type with the
    # package kind; the container block's kind is the same fact one level
    # down and is named as the source when it is the one speaking.
    exe_type = str(metadata.get("exe_type") or "")
    if exe_type in _CONTAINER_EXE_TYPES:
        block["container_origin"] = exe_type

    # Managed shape: the W3.3 shape kind when evidence produced one. A PE
    # with no CLI header and no shape evidence is NOT stamped "native" -
    # that was W3.3's discipline and the posture keeps it (silence, not a
    # native verdict).
    dotnet = metadata.get("dotnet") or {}
    shape = dotnet.get("shape") or {}
    if shape.get("kind"):
        block["managed_shape"] = shape.get("kind")
    elif metadata.get("is_dotnet"):
        block["managed_shape"] = "il_assembly"

    # No emptiness guard: `hardening` and `sources` are set unconditionally
    # above, so every PE carries a block - which is what the module
    # docstring says and what rule 32 wants (a PE with nothing notable is
    # still a PE blint looked at). The guard this replaced tested
    # `len(block) <= 1` and could never be true.
    return block
