r"""Tests for the Windows posture summary and diff deltas (W5.5, 04/E).

The posture block's whole contract is that it *summarises* - so the
load-bearing tests are the ones that would catch a drift or a swap: absent
vs unknown never merge (rule 32), the values equal their source blocks
(rule 21: one place computes), and the diff layer's windows changes are
mirror-symmetric.
"""

from blint.lib.diff import _windows_delta
from blint.lib.windows_posture import build_windows_posture


def _metadata(**overrides):
    metadata = {
        "binary_type": "PE",
        "exe_type": "PE64",
        "security_properties": {
            "aslr": True,
            "dep": True,
            "cfg": False,
            "force_integrity": False,
            "nx": True,
        },
        "security_properties_gaps": ["cet_shadow_stack"],
    }
    metadata.update(overrides)
    return metadata


# ---------------------------------------------------------------------------
# The posture block
# ---------------------------------------------------------------------------


def test_posture_splits_hardening_into_present_absent_unknown():
    block = build_windows_posture(_metadata())
    assert block["hardening"]["present"] == ["aslr", "dep", "nx"]
    # Computed-and-off: absent. This is a claim the source made.
    assert sorted(block["hardening"]["absent"]) == ["cfg", "force_integrity"]
    # Source unreadable: unknown. Rule 32 - never merged into absent.
    assert block["hardening"]["unknown"] == ["cet_shadow_stack"]


def test_posture_absent_and_unknown_are_different_values():
    metadata = _metadata(
        security_properties={"aslr": False, "cfg": True},
        security_properties_gaps=["xfg", "rfg", "cet_shadow_stack"],
    )
    block = build_windows_posture(metadata)
    assert "aslr" in block["hardening"]["absent"]
    assert "cfg" in block["hardening"]["present"]
    assert sorted(block["hardening"]["unknown"]) == ["cet_shadow_stack", "rfg", "xfg"]
    assert not set(block["hardening"]["absent"]) & set(block["hardening"]["unknown"])
    assert not set(block["hardening"]["present"]) & set(block["hardening"]["unknown"])


def test_posture_carries_signing_class_only_when_determined():
    block = build_windows_posture(
        _metadata(code_signature={"signing_class": "microsoft_1st_party"})
    )
    assert block["signing_class"] == "microsoft_1st_party"
    # Undetermined class: no key - never "unsigned" by omission.
    block = build_windows_posture(_metadata(code_signature={"signing_class": None}))
    assert "signing_class" not in block


def test_posture_driver_kind_container_origin_managed_shape():
    block = build_windows_posture(
        _metadata(
            driver={"kind": "minifilter"},
            dotnet={"shape": {"kind": "single_file_bundle"}},
        )
    )
    assert block["driver_kind"] == "minifilter"
    assert block["managed_shape"] == "single_file_bundle"
    assert "container_origin" not in block
    packaged = build_windows_posture(_metadata(exe_type="msix"))
    assert packaged["container_origin"] == "msix"


def test_posture_il_assembly_and_scope_passthrough():
    block = build_windows_posture(_metadata(is_dotnet=True))
    assert block["managed_shape"] == "il_assembly"
    scoped = build_windows_posture(
        _metadata(
            security_properties_scope="primary_slice",
            security_properties_slice_variance=["pac"],
        )
    )
    assert scoped["security_properties_scope"] == "primary_slice"
    assert scoped["security_properties_slice_variance"] == ["pac"]


def test_posture_names_its_sources():
    block = build_windows_posture(_metadata())
    assert block["sources"]["signing"] == "code_signature"
    assert block["sources"]["hardening"] == "security_properties"
    assert block["sources"]["driver"] == "driver"


def test_posture_absent_for_non_pe():
    assert build_windows_posture({"binary_type": "ELF"}) is None
    assert build_windows_posture({}) is None


def test_posture_values_equal_their_sources():
    """The drift guard: posture values are the source blocks' values, read
    in the same parse. If a source block changes shape, this fails before
    a silent mismatch ships."""
    metadata = _metadata(
        code_signature={"signing_class": "whql"},
        driver={"kind": "kmdf"},
        dotnet={"shape": {"kind": "native_aot"}},
    )
    block = build_windows_posture(metadata)
    assert block["signing_class"] == metadata["code_signature"]["signing_class"]
    assert block["driver_kind"] == metadata["driver"]["kind"]
    assert block["managed_shape"] == metadata["dotnet"]["shape"]["kind"]
    assert block["hardening"]["present"] == [
        name
        for name, value in sorted(metadata["security_properties"].items())
        if value is True
    ]


# ---------------------------------------------------------------------------
# The diff layer
# ---------------------------------------------------------------------------


def test_diff_windows_signer_and_class_changes():
    old = _metadata(
        code_signature={
            "signing_class": "commercial_ov",
            "signing_class_signature": 0,
            "signatures": [{"signer": {"cn": "Old Corp", "serial": "AA"}}],
        }
    )
    new = _metadata(
        code_signature={
            "signing_class": "commercial_ov",
            "signing_class_signature": 0,
            "signatures": [{"signer": {"cn": "New Corp", "serial": "BB"}}],
        }
    )
    delta = _windows_delta(old, new)
    assert delta["signer_changed"] == {"old": {"cn": "Old Corp", "serial": "AA"}, "new": {"cn": "New Corp", "serial": "BB"}}
    # The mirror image swaps old and new (the diff determinism contract).
    mirror = _windows_delta(new, old)
    assert mirror["signer_changed"]["old"] == delta["signer_changed"]["new"]


def test_diff_windows_ioctl_surface_delta():
    old = _metadata(
        driver={"kind": "wdm"},
        driver_ioctls={"ioctls": [{"code": "0x80002000"}, {"code": "0x80002004"}]},
    )
    new = _metadata(
        driver={"kind": "wdm"},
        driver_ioctls={"ioctls": [{"code": "0x80002000"}, {"code": "0x80002008"}]},
    )
    delta = _windows_delta(old, new)
    assert delta["ioctl_surface_changed"]["added"] == ["0x80002008"]
    assert delta["ioctl_surface_changed"]["removed"] == ["0x80002004"]


def test_diff_windows_pinvoke_manifest_vulnerable_driver():
    old = _metadata(
        resources={"manifest_parsed": {"requestedExecutionLevel": "asInvoker"}},
        dotnet={"pinvoke": [{"module": "kernel32.dll"}]},
        vulnerable_driver={"lookup_status": "no_match"},
    )
    new = _metadata(
        resources={"manifest_parsed": {"requestedExecutionLevel": "requireAdministrator"}},
        dotnet={"pinvoke": [{"module": "kernel32.dll"}, {"module": "ntdll.dll"}]},
        vulnerable_driver={"lookup_status": "matched"},
    )
    delta = _windows_delta(old, new)
    assert delta["manifest_execution_level_changed"] == {
        "old": "asInvoker",
        "new": "requireAdministrator",
    }
    assert delta["pinvoke_changed"]["added"] == ["ntdll.dll"]
    assert delta["vulnerable_driver_status_changed"] == {
        "old": "no_match",
        "new": "matched",
    }


def test_diff_windows_silent_without_windows_facts():
    assert _windows_delta(_metadata(), _metadata()) == {}
    # Unrelated metadata changes do not fabricate windows deltas.
    assert _windows_delta(_metadata(), _metadata(functions=[{"name": "x"}])) == {}
    # A lookup-status change between two non-matched states is not a finding.
    old = _metadata(vulnerable_driver={"lookup_status": "no_hash"})
    new = _metadata(vulnerable_driver={"lookup_status": "no_match"})
    assert _windows_delta(old, new) == {}
