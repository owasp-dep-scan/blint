r"""Tests for the macOS host-plugin surface (lane M1.1, plan 07).

Cross-platform coverage is synthetic: plugin bundles built to the real
layout measured on this system (``Contents/Info.plist`` +
``Contents/MacOS/<CFBundleExecutable>``, the shape every plugin kind on a
stock macOS ships), driven through the real bundle walker and the real
rule engine — including one full ``run_default_mode`` scan, because a rule
whose check function is absent from the dispatch import list fires
nowhere, and only an end-to-end run sees that (the P5 lesson: a capability
the suite does not reach is not a capability).

The positive cases that do not exist on any stock system — a ``.driver``
declaring ``AudioServerPlugIn_Network``, an unsigned machine-wide plugin —
are synthetic for that reason and that reason is measured: 0 of the 12
Apple HAL plugins on this machine declare the network key.

Real-artifact ground truth (rule 29) runs where the artifacts exist and is
skip-guarded otherwise. These tests run ``codesign`` on the same file in
the same run and compare blint's answer to its output, rather than to
values recorded on one machine: both did the latter first, and both failed
on the reviewer's Mac. ``Platform identifier`` is the macOS major version
(16 on macOS 15.8, 26 on macOS 26.6.2), and the activated system extension
a Mac happens to have is whichever one its owner installed — neither is a
constant, while "carries a platform identifier" and "is Developer-ID
signed" are the properties the rules actually read.

Originally recorded 2026-09-22 on macOS 15.8 (build 24H23):
``codesign -dv --entitlements -`` on AirPlay.driver printed
``Platform identifier=16``, ``Identifier=com.apple.audio.Halogen`` and
origin ``Software Signing``; ``codesign -dv`` on that machine's activated
Tailscale extension printed ``TeamIdentifier=W5364U7YZB`` with
``spctl -a -vv`` origin ``Developer ID Application: Tailscale Inc.
(W5364U7YZB)``. blint agreed with all of it. Re-measured on the reviewer's
macOS 26.6.2: ``Platform identifier=26``, blint's ``platform_id`` 26.
"""

import os
import plistlib
import re
import subprocess

import orjson
import pytest

from blint.config import BlintOptions
from blint.lib.analysis import load_default_rules, run_checks
from blint.lib.binary import parse
from blint.lib.checks import (
    check_audio_plugin_network,
    check_unsigned_host_plugin,
)
from blint.lib.macos_bundle import bundle_kind, collect_macos_bundle_detailed, is_macos_bundle
from blint.lib.macos_host_plugins import (
    NAME_LIST_LIMIT,
    classify_host_plugin,
    containing_app,
    install_scope,
)
from blint.lib.runners import run_default_mode

load_default_rules()

# Minimal Mach-O magic so is_exe() treats the fixture files as binaries —
# the same convention as test_macos_bundle.py; parse() reads them as thin
# Mach-O files, which is enough for the bundle-member pipeline.
_MACHO_BYTES = b"\xcf\xfa\xed\xfe" + b"\x00" * 256

AIRPLAY_DRIVER = "/System/Library/Audio/Plug-Ins/HAL/AirPlay.driver"
TAILSCALE_SYSEXT_DIR = "/Library/SystemExtensions"
_QUICKLOOK_GENERATOR = "/System/Library/QuickLook/Audio.qlgenerator"
_SPOTLIGHT_IMPORTER = "/System/Library/Spotlight/Application.mdimporter"
_AUDIO_UNIT = "/System/Library/Components/CoreAudio.component"


def _write(path, data=_MACHO_BYTES):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def _write_plist(path, info):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(plistlib.dumps(info))
    return path


def _driver_bundle(tmp_path, name="Fake.driver", plist_extra=None):
    """A .driver bundle in the measured real layout."""
    info = {
        "CFBundleExecutable": name.removesuffix(".driver"),
        "CFBundleIdentifier": f"com.example.{name.removesuffix('.driver').lower()}",
    }
    info.update(plist_extra or {})
    bundle = tmp_path / name
    _write_plist(bundle / "Contents" / "Info.plist", info)
    _write(bundle / "Contents" / "MacOS" / name.removesuffix(".driver"))
    return bundle


def _fired(results, cid):
    return [r for r in results if r["id"] == cid]


# --------------------------------------------------------------------------
# install scope: every branch, including the out-of-context one (rule 32).


def test_install_scope_branches():
    assert install_scope("/System/Library/Audio/Plug-Ins/HAL/AirPlay.driver") == "system"
    assert install_scope("/Library/Audio/Plug-Ins/HAL/Vendor.driver") == "machine"
    home = os.path.expanduser("~")
    assert install_scope(os.path.join(home, "Library", "Audio", "Plug-Ins", "HAL", "U.driver")) == "user"
    # Out of context: a downloads folder, an app bundle, a build tree. No
    # scope is invented for any of them.
    assert install_scope("/Users/me/Downloads/Vendor.driver") is None
    assert install_scope("/Applications/Vendor.app/Contents/Library/SystemExtensions/v.dext") is None
    assert install_scope("/tmp/scratch/Vendor.driver") is None
    # macOS volumes are commonly case-insensitive; the scope check is too.
    assert install_scope("/LIBRARY/Audio/Plug-Ins/HAL/Vendor.driver") == "machine"
    assert install_scope("/System/Library/QuickLook/Audio.qlgenerator") == "system"
    # A Windows drive path is not a macOS install location, ever (holds on
    # every platform: verbatim on Windows, cwd-mangled elsewhere).
    assert install_scope("C:\\Library\\Audio\\Plug-Ins\\HAL\\Vendor.driver") is None
    if os.name == "nt":
        # The backslash-rooted spelling a real Windows walk produces:
        # os.path.abspath there prepends a drive letter, which would
        # silently turn a macOS install location into an out-of-context one
        # (the suite runs on the VM; this branch is why).
        assert install_scope("\\Library\\Audio\\Plug-Ins\\HAL\\Vendor.driver") == "machine"
        assert install_scope("\\System\\Library\\Audio\\Plug-Ins\\HAL\\AirPlay.driver") == "system"


# --------------------------------------------------------------------------
# classification: a block per kind, and no block where none is supported.


@pytest.mark.parametrize(
    ("kind", "expected_kind_id"),
    [
        ("driver", "driver"),
        ("component", "component"),
        ("qlgenerator", "qlgenerator"),
        ("mdimporter", "mdimporter"),
        ("systemextension", "systemextension"),
        ("dext", "dext"),
    ],
)
def test_every_table_kind_produces_a_block(kind, expected_kind_id):
    block = classify_host_plugin(f"/Library/x/Foo.{kind}", kind, {}, "read")
    assert block, f"{kind} must produce a host_plugin block"
    assert block["kind"] == expected_kind_id
    # Every docstring/docs claim about the block: kind, title, host, that
    # host's privilege, and the activation path (the .driver vs .dext
    # approval difference is the point of the block).
    for key in ("title", "host", "host_privilege", "activation"):
        assert isinstance(block[key], str) and block[key], f"{kind} block missing {key}"


def test_plugin_bundle_is_dal_camera_only_under_dal_path():
    dal = classify_host_plugin(
        "/Library/CoreMediaIO/Plug-Ins/DAL/Vendor.plugin", "plugin", {}, "read"
    )
    assert dal and dal["kind"] == "dal_plugin"
    assert "camera" in dal["host"]
    # The negative fixture (rule 11): the same suffix anywhere else names no
    # host, and the honest answer is no block at all, not a guess.
    other = classify_host_plugin("/System/Library/UserEventPlugins/x.plugin", "plugin", {}, "read")
    assert other is None


def test_activation_difference_between_admin_and_dialog_kinds():
    driver = classify_host_plugin("/Library/Audio/Plug-Ins/HAL/V.driver", "driver", {}, "read")
    dext = classify_host_plugin("/tmp/V.dext", "dext", {}, "read")
    assert "administrator" in driver["activation"]
    assert "no per-load prompt" in driver["activation"]
    assert "user-approval dialog" in dext["activation"]


# --------------------------------------------------------------------------
# declarations: what is reported, how it is worded, and the listing cap.


def test_driver_network_declaration_reported_exactly_as_declared():
    block = classify_host_plugin(
        "/Library/Audio/Plug-Ins/HAL/V.driver",
        "driver",
        {"AudioServerPlugIn_Network": True},
        "read",
    )
    assert block["declarations"]["network"] is True


def test_driver_name_lists_recorded():
    block = classify_host_plugin(
        "/Library/Audio/Plug-Ins/HAL/V.driver",
        "driver",
        {
            "AudioServerPlugIn_MachServices": ["com.example.svc", "com.example.other"],
            "AudioServerPlugIn_IOKitUserClients": ["IOExampleUserClient"],
        },
        "read",
    )
    assert block["declarations"]["mach_services"] == ["com.example.svc", "com.example.other"]
    assert block["declarations"]["iokit_user_clients"] == ["IOExampleUserClient"]


def test_driver_name_list_cap_is_a_listing_bound_not_detection_bound():
    # Rule 33: a fixture larger than the window, with the signal spread
    # past it, asserting the cap by name.
    services = [f"com.example.service{i}" for i in range(NAME_LIST_LIMIT + 9)]
    block = classify_host_plugin(
        "/Library/Audio/Plug-Ins/HAL/V.driver",
        "driver",
        {"AudioServerPlugIn_MachServices": services},
        "read",
    )
    declarations = block["declarations"]
    assert len(declarations["mach_services"]) == NAME_LIST_LIMIT
    assert declarations["mach_services_listing_capped"] is True
    assert declarations["mach_services"] == services[:NAME_LIST_LIMIT]


def test_declarations_absent_when_key_absent():
    # The empty case (rule 32): no declaration keys, no declarations block,
    # and no field claiming a negative that was not read.
    block = classify_host_plugin(
        "/Library/Audio/Plug-Ins/HAL/V.driver", "driver", {"CFBundleExecutable": "V"}, "read"
    )
    assert "declarations" not in block
    assert "declarations_status" not in block


@pytest.mark.parametrize(
    "status", ["info_plist_absent", "info_plist_unreadable", "info_plist_not_a_dict"]
)
def test_declarations_status_names_why_the_plist_was_not_read(status):
    # Rule 14: "declared nothing" and "could not be read" stay
    # distinguishable.
    block = classify_host_plugin("/Library/Audio/Plug-Ins/HAL/V.driver", "driver", None, status)
    assert block, "the host is known from the suffix even without a plist"
    assert "declarations" not in block
    assert block["declarations_status"] == status


def test_forged_non_boolean_network_value_does_not_trip_the_rule():
    block = classify_host_plugin(
        "/Library/Audio/Plug-Ins/HAL/V.driver",
        "driver",
        {"AudioServerPlugIn_Network": "true"},
        "read",
    )
    # Reported exactly as declared, but the rule fires only on a real
    # boolean true, so a string cannot trip it.
    assert block["declarations"]["network"] == "true"
    metadata = {"exe_type": "MachO", "host_plugin": block}
    assert check_audio_plugin_network("V", metadata, {}) is True


# --------------------------------------------------------------------------
# the .dext honesty requirement (rule 11 through and through).


def _app_with_dext(tmp_path):
    app = tmp_path / "HostApp.app"
    _write_plist(
        app / "Contents" / "Info.plist",
        {"CFBundleExecutable": "HostApp", "CFBundleIdentifier": "com.example.hostapp"},
    )
    _write(app / "Contents" / "MacOS" / "HostApp")
    dext = app / "Contents" / "Library" / "SystemExtensions" / "com.example.drv.dext"
    _write_plist(
        dext / "Contents" / "Info.plist",
        {"CFBundleExecutable": "com.example.drv", "CFBundleIdentifier": "com.example.drv"},
    )
    _write(dext / "Contents" / "MacOS" / "com.example.drv")
    return app, dext


def test_dext_names_containing_app_and_never_claims_network_isolation(tmp_path):
    _app, dext = _app_with_dext(tmp_path)
    block = classify_host_plugin(str(dext), "dext", {}, "read")
    assert block["containing_app"] == "com.example.hostapp"
    # The honesty requirement, stated as a property: no field in the block
    # reads as "this software cannot reach the network" — the containing
    # application keeps ordinary network access, and the block either
    # names it or says nothing.
    assert not any("network" in key for key in block), sorted(block)


def test_activated_sysext_copy_has_no_containing_app(tmp_path):
    staged = tmp_path / "com.example.ext.systemextension"
    _write_plist(
        staged / "Contents" / "Info.plist", {"CFBundleExecutable": "com.example.ext"}
    )
    _write(staged / "Contents" / "MacOS" / "com.example.ext")
    # No .app ancestor above the on-disk fixture: say nothing rather than
    # name one. The scope check is a path-string classifier, so the real
    # activated location is exercised by its absolute spelling - /Library
    # cannot exist under a tmp_path.
    assert containing_app(str(staged)) is None
    activated = "/Library/SystemExtensions/UUID/com.example.ext.systemextension"
    block = classify_host_plugin(activated, "systemextension", {}, "read")
    assert "containing_app" not in block
    # The activated copy under /Library is genuinely machine-wide, unlike
    # the app-embedded copy which has no scope at all.
    assert block["install_scope"] == "machine"


def test_app_embedded_dext_has_no_install_scope(tmp_path):
    _app, dext = _app_with_dext(tmp_path)
    block = classify_host_plugin(str(dext), "dext", {}, "read")
    assert "install_scope" not in block
    assert containing_app(str(dext)) == "com.example.hostapp"


# --------------------------------------------------------------------------
# the bundle walker: recognition, stamping, and the walk.


def test_plugin_bundle_kinds_recognized_and_walked(tmp_path):
    driver = _driver_bundle(tmp_path, plist_extra={"AudioServerPlugIn_MachServices": ["com.x.svc"]})
    assert is_macos_bundle(str(driver))
    assert bundle_kind(str(driver)) == "driver"
    collection, reason = collect_macos_bundle_detailed(str(driver))
    assert reason is None
    assert collection["kind"] == "driver"
    (entry,) = collection["binaries"]
    assert entry["role"] == "main"
    assert entry["host_plugin"]["kind"] == "driver"
    assert entry["host_plugin"]["declarations"]["mach_services"] == ["com.x.svc"]
    # Out of context (tmp_path is not a Library): no install scope invented.
    assert "install_scope" not in entry["host_plugin"]


def test_app_members_and_embedded_dext_get_their_own_blocks(tmp_path):
    app, _dext = _app_with_dext(tmp_path)
    collection, reason = collect_macos_bundle_detailed(str(app))
    assert reason is None
    by_role = {entry["role"]: entry for entry in collection["binaries"]}
    # The app's own executable is not a plugin: no block reads as "not a
    # plugin" (absence is the honest answer for an app).
    assert "host_plugin" not in by_role["main"]
    dext_entry = next(
        e for e in collection["binaries"] if e["bundle_path"].endswith(".dext/Contents/MacOS/com.example.drv")
    )
    assert dext_entry["host_plugin"]["kind"] == "dext"
    assert dext_entry["host_plugin"]["containing_app"] == "com.example.hostapp"


def test_generic_plugin_bundle_walked_without_host_claim(tmp_path):
    plugin = tmp_path / "Handler.plugin"
    _write_plist(
        plugin / "Contents" / "Info.plist", {"CFBundleExecutable": "Handler"}
    )
    _write(plugin / "Contents" / "MacOS" / "Handler")
    collection, reason = collect_macos_bundle_detailed(str(plugin))
    assert reason is None
    assert collection["kind"] == "plugin"
    (entry,) = collection["binaries"]
    assert "host_plugin" not in entry


# --------------------------------------------------------------------------
# the rules, through the real dispatch.


def _plugin_metadata(block, exe_type="MachO", signature=None):
    metadata = {"exe_type": exe_type, "host_plugin": block}
    if signature is not None:
        metadata["code_signature"] = signature
    return metadata


def test_check_macos_host_plugin_fires_and_scopes_by_exe_type():
    block = classify_host_plugin("/Library/Audio/Plug-Ins/HAL/V.driver", "driver", {}, "read")
    results = run_checks("V", _plugin_metadata(block))
    fired = _fired(results, "CHECK_MACOS_HOST_PLUGIN")
    assert fired and fired[0]["severity"] == "info"
    # The check's text lands in the finding title as "Title (result)".
    assert "_coreaudiod" in fired[0]["title"]
    # The same metadata on a non-Mach-O exe_type fires nothing: rules must
    # not run out of their declared scope.
    assert not _fired(run_checks("V", _plugin_metadata(block, exe_type="ELF")), "CHECK_MACOS_HOST_PLUGIN")
    # Absent block = no finding (never "verified not a plugin").
    assert not _fired(run_checks("V", {"exe_type": "MachO"}), "CHECK_MACOS_HOST_PLUGIN")


def test_check_audio_plugin_network_positive_and_negative():
    fired_block = classify_host_plugin(
        "/Library/Audio/Plug-Ins/HAL/V.driver",
        "driver",
        {"AudioServerPlugIn_Network": True},
        "read",
    )
    results = run_checks("V", _plugin_metadata(fired_block))
    fired = _fired(results, "CHECK_AUDIO_PLUGIN_NETWORK")
    assert fired and fired[0]["severity"] == "medium"
    # Rule 11, pinned: the finding is worded as a declaration blint read,
    # never as behaviour it observed.
    assert "declaration" in fired[0]["title"]
    assert "did not watch" in fired[0]["title"]
    # Negative fixture: the common Apple shape (mach services, no network).
    quiet_block = classify_host_plugin(
        "/System/Library/Audio/Plug-Ins/HAL/AirPlay.driver",
        "driver",
        {"AudioServerPlugIn_MachServices": ["com.apple.x"]},
        "read",
    )
    assert not _fired(run_checks("V", _plugin_metadata(quiet_block)), "CHECK_AUDIO_PLUGIN_NETWORK")


def test_mach_services_declaration_fires_no_rule():
    # The measured no-rule decision, pinned as a property: a Mach-services
    # declaration changes the findings not at all (7 of 12 Apple plugins
    # declare it, so a rule on it would be noise on the OS's own plugins).
    with_decl = classify_host_plugin(
        "/System/Library/Audio/Plug-Ins/HAL/V.driver",
        "driver",
        {"AudioServerPlugIn_MachServices": ["com.example.svc"]},
        "read",
    )
    without_decl = classify_host_plugin(
        "/System/Library/Audio/Plug-Ins/HAL/V.driver", "driver", {}, "read"
    )
    ids_with = {r["id"] for r in run_checks("V", _plugin_metadata(with_decl))}
    ids_without = {r["id"] for r in run_checks("V", _plugin_metadata(without_decl))}
    assert ids_with == ids_without
    assert "CHECK_AUDIO_PLUGIN_MACH_SERVICES" not in ids_with


def _parsed_signature(platform_id=None, provenance=None, signer_cn=None, status="parsed"):
    superblob = {"code_directories": [], "provenance": provenance}
    if platform_id is not None:
        superblob["code_directories"].append({"slot_type": "code_directory", "platform_id": platform_id})
    if provenance == "cms_signed":
        superblob["cms"] = {"signer_cn": signer_cn}
    return {"available": True, "parse_status": status, "superblob": superblob}


def test_check_unsigned_host_plugin_macos_branches():
    block = classify_host_plugin("/Library/Audio/Plug-Ins/HAL/V.driver", "driver", {}, "read")
    assert block["install_scope"] == "machine"

    def fires(signature, blk=block):
        return isinstance(check_unsigned_host_plugin("V", _plugin_metadata(blk, signature=signature), {}), str)

    # Fires: nothing vouches for the plugin.
    assert fires({"available": False, "parse_status": "absent"})
    assert fires(_parsed_signature(provenance="adhoc"))
    assert fires(_parsed_signature(provenance="linker_signed"))
    assert fires(_parsed_signature(provenance="cms_signed", signer_cn="Apple Development: X"))
    # Silent: an identity vouches, or the answer is undetermined, or the
    # bundle is not installed anywhere blint can see.
    assert not fires(_parsed_signature(platform_id=16, provenance="cms_signed", signer_cn="Software Signing"))
    assert not fires(_parsed_signature(provenance="cms_signed", signer_cn="Developer ID Application: Example Inc (TEAM123)"))
    assert not fires(_parsed_signature(status="parse_failed"))
    assert not fires({"available": True, "parse_status": "parse_failed", "parse_error": "blob_unreadable"})
    out_of_context = classify_host_plugin("/tmp/V.driver", "driver", {}, "read")
    assert "install_scope" not in out_of_context
    assert not fires(_parsed_signature(provenance="adhoc"), blk=out_of_context)


def test_check_unsigned_host_plugin_run_checks_integration():
    block = classify_host_plugin("/Library/Audio/Plug-Ins/HAL/V.driver", "driver", {}, "read")
    metadata = _plugin_metadata(
        block, signature={"available": False, "parse_status": "absent"}
    )
    fired = _fired(run_checks("V", metadata), "CHECK_UNSIGNED_HOST_PLUGIN")
    assert fired and fired[0]["severity"] == "high"
    platform_block = classify_host_plugin(
        "/System/Library/Audio/Plug-Ins/HAL/AirPlay.driver", "driver", {}, "read"
    )
    assert not _fired(
        run_checks(
            "AirPlay",
            _plugin_metadata(
                platform_block,
                signature=_parsed_signature(platform_id=16, provenance="cms_signed", signer_cn="Software Signing"),
            ),
        ),
        "CHECK_UNSIGNED_HOST_PLUGIN",
    )


def test_pe_host_plugin_shape_still_routes_to_the_pe_branch():
    # The PE block (contracts list) must keep taking the signing_class
    # branch, not the macOS one.
    metadata = {
        "exe_type": "PE32",
        "host_plugin": {"contracts": [{"id": "lsa_password_filter", "host_process": "lsass.exe"}]},
        # _parsed_signature_block only reads blocks whose facts were parsed.
        "code_signature": {
            "parse_status": "parsed",
            "signing_class": "unsigned",
            "signatures": [],
        },
    }
    result = check_unsigned_host_plugin("pwfilter.dll", metadata, {})
    assert isinstance(result, str) and "signing class unsigned" in result


# --------------------------------------------------------------------------
# end to end: the only test shape that can see a dispatch gap.


def test_run_default_mode_exports_host_plugin_and_fires_the_info_rule(tmp_path):
    driver = _driver_bundle(
        tmp_path, plist_extra={"AudioServerPlugIn_MachServices": ["com.example.svc"]}
    )
    reports = tmp_path / "reports"
    options = BlintOptions(
        src_dir_image=[str(driver)],
        reports_dir=str(reports),
        no_reviews=True,
        quiet_mode=True,
    )
    run_default_mode(options)
    metadata_files = list(reports.glob("*-metadata.json"))
    assert metadata_files, "the driver bundle must be scanned as one unit"
    metadata = orjson.loads(metadata_files[0].read_bytes())
    block = metadata.get("host_plugin")
    assert block and block["kind"] == "driver"
    # One shape, no duplication: the block is top-level and not also nested
    # inside the bundle context.
    assert "host_plugin" not in (metadata.get("macos_bundle") or {})
    findings = orjson.loads((reports / "findings.json").read_bytes())["findings"]
    assert [f["id"] for f in findings if f["id"] == "CHECK_MACOS_HOST_PLUGIN"]
    # Mach services alone fire no rule (the measured decision).
    assert not [f for f in findings if f["id"] == "CHECK_AUDIO_PLUGIN_NETWORK"]


# --------------------------------------------------------------------------
# real-artifact ground truth (rule 29) — this Mac only, skip-guarded.


@pytest.mark.skipif(
    not os.path.isfile(os.path.join(AIRPLAY_DRIVER, "Contents", "Info.plist")),
    reason="Apple HAL plugins exist only on macOS",
)
def test_real_airplay_driver_is_a_platform_binary_system_plugin():
    collection, reason = collect_macos_bundle_detailed(AIRPLAY_DRIVER)
    assert reason is None
    (entry,) = [e for e in collection["binaries"] if e["role"] == "main"]
    block = entry["host_plugin"]
    assert block["kind"] == "driver"
    assert block["install_scope"] == "system"
    # Measured per-key table entry for this bundle: MachServices only.
    assert block["declarations"]["mach_services"] == [
        "com.apple.coremedia.endpointmanager.xpc",
        "com.apple.coremedia.endpoint.xpc",
        "com.apple.coremedia.endpointstream.xpc",
        "com.apple.coremedia.endpointstreamaudioengine.xpc",
        "com.apple.coremedia.samplebufferconsumer.xpc",
        "com.apple.coremedia.bufferedairplayglobalroutingregistry.xpc",
    ]
    assert "network" not in block["declarations"]
    # codesign -dv on this bundle prints `Platform identifier=<n>` and
    # `Identifier=com.apple.audio.Halogen`. The *number* is the macOS major
    # version (16 on macOS 15.8, 26 on macOS 26.6.2), so asserting a literal
    # pins the suite to one OS release — it failed on the reviewer's Mac for
    # exactly that reason. What the rule actually reads is the presence of a
    # platform identifier, which is what makes this an Apple platform binary,
    # so that is what is asserted; the value is cross-checked against
    # codesign itself below rather than against a constant.
    metadata = parse(entry["path"])
    directories = metadata["code_signature"]["superblob"]["code_directories"]
    platform_ids = [d.get("platform_id") for d in directories if d.get("platform_id")]
    assert platform_ids, "an Apple platform binary carries a platform identifier"
    assert any(d.get("identifier") == "com.apple.audio.Halogen" for d in directories)
    printed = subprocess.run(
        ["codesign", "-dv", AIRPLAY_DRIVER], capture_output=True, text=True
    )
    match = re.search(r"Platform identifier=(\d+)", printed.stderr)
    assert match, "codesign must print a platform identifier for this bundle"
    assert int(match.group(1)) in platform_ids, (
        "blint's platform_id must be the one codesign reports on this machine"
    )
    metadata["host_plugin"] = block
    assert check_unsigned_host_plugin("AirPlay", metadata, {}) is True


def _tailscale_sysext():
    if not os.path.isdir(TAILSCALE_SYSEXT_DIR):
        return None
    for root, dirs, _files in os.walk(TAILSCALE_SYSEXT_DIR):
        for d in dirs:
            if d.endswith(".systemextension"):
                return os.path.join(root, d)
    return None


@pytest.mark.skipif(
    _tailscale_sysext() is None,
    reason="no activated system extension on this machine",
)
def test_real_activated_sysext_is_developer_id_signed_machine_scope():
    sysext = _tailscale_sysext()
    collection, reason = collect_macos_bundle_detailed(sysext)
    assert reason is None
    (entry,) = [e for e in collection["binaries"] if e["role"] == "main"]
    block = entry["host_plugin"]
    assert block["kind"] == "systemextension"
    assert block["install_scope"] == "machine"
    # The activated copy has no containing app in its ancestry.
    assert "containing_app" not in block
    # Ground truth from codesign itself, on whatever extension this machine
    # has activated. The original form asserted one vendor's team identifier
    # and common name (Tailscale's), which the skipif did not guarantee was
    # present: any Mac with a different activated extension failed, and the
    # reviewer's did. What is machine-independent is the property the rule
    # reads — an activated extension is Developer-ID signed — so blint's
    # answer is compared against codesign's on the same file instead of
    # against a constant from another machine.
    metadata = parse(entry["path"])
    superblob = metadata["code_signature"]["superblob"]
    primary = next(d for d in superblob["code_directories"] if d.get("slot_type") == "code_directory")
    printed = subprocess.run(["codesign", "-dv", sysext], capture_output=True, text=True)
    team = re.search(r"TeamIdentifier=(\S+)", printed.stderr)
    assert team and team.group(1) != "not set", "an activated extension is team-signed"
    assert primary.get("team_id") == team.group(1)
    signer_cn = (superblob["cms"] or {}).get("signer_cn", "")
    assert signer_cn.startswith("Developer ID Application:"), (
        f"an activated system extension is Developer-ID signed; got {signer_cn!r}"
    )
    assert team.group(1) in signer_cn, "the Developer ID CN carries its own team identifier"
    metadata["host_plugin"] = block
    assert check_unsigned_host_plugin("sysext", metadata, {}) is True


@pytest.mark.parametrize(
    "bundle_path",
    [_QUICKLOOK_GENERATOR, _SPOTLIGHT_IMPORTER, _AUDIO_UNIT],
)
def test_real_system_plugin_kinds_get_blocks(bundle_path):
    if not os.path.isdir(bundle_path):
        pytest.skip("Apple system plugin bundles exist only on macOS")
    collection, reason = collect_macos_bundle_detailed(bundle_path)
    assert reason is None
    entry = collection["binaries"][0]
    block = entry.get("host_plugin")
    assert block, f"{bundle_path} must carry a host_plugin block"
    assert block["install_scope"] == "system"
    assert block["host"]


def test_extension_shipped_inside_an_application_has_no_install_scope(tmp_path):
    """Payload inside an app is not installed anywhere — not even under /Library.

    The module docstring has always said a `.systemextension`/`.dext` found
    inside an application gets no install scope: the copy macOS runs is the
    activated one staged under /Library/SystemExtensions. The code asked
    only about the path, so a vendor extension under
    /Library/Application Support/<Vendor>/<App>.app/... came back `machine`
    — and `CHECK_UNSIGNED_HOST_PLUGIN` is high on machine scope, so an
    ad-hoc-signed extension that is not installed at all was reported as
    "installed machine-wide, vouched for by nobody".

    The existing coverage used an app under /Applications, which returns
    None for an unrelated reason (it is in neither scope root), so it passed
    against the defect.
    """
    # A real /Library path, not tmp_path: under tmp_path the scope is None
    # for an unrelated reason (it is in neither scope root), which is why
    # the existing /Applications coverage passed against the defect. The
    # path need not exist — the ancestor test is structural.
    ext_path = (
        "/Library/Application Support/Acme/Acme.app"
        "/Contents/Library/SystemExtensions/com.acme.net.systemextension"
    )
    block = classify_host_plugin(ext_path, "systemextension", {}, "read")
    assert "install_scope" not in block
    # And the rule that reads the scope stays silent on this payload, even
    # with no signature at all.
    metadata = {"host_plugin": block, "code_signature": {"parse_status": "absent"}}
    assert check_unsigned_host_plugin("net", metadata, {}) is True
    # The containing app is still named when it can be read — that fact is
    # unchanged, and it is what a reviewer follows to find who vouches.
    app = tmp_path / "Acme.app"
    _write_plist(app / "Contents" / "Info.plist", {"CFBundleIdentifier": "com.acme.app"})
    ext = app / "Contents" / "Library" / "SystemExtensions" / "com.acme.net.systemextension"
    _write_plist(ext / "Contents" / "Info.plist", {"CFBundleExecutable": "net"})
    _write(ext / "Contents" / "MacOS" / "net")
    assert classify_host_plugin(str(ext), "systemextension", {}, "read")[
        "containing_app"
    ] == "com.acme.app"
    # The exemption is about extensions activated from an app, not about the
    # directory: a .driver inside an app under /Library keeps machine scope,
    # and so does an extension staged where macOS actually activates it.
    driver = classify_host_plugin(
        "/Library/Application Support/Acme/Acme.app/Contents/X.driver", "driver", {}, "read"
    )
    assert driver["install_scope"] == "machine"
    staged = classify_host_plugin(
        "/Library/SystemExtensions/ABC-123/com.acme.net.systemextension",
        "systemextension",
        {},
        "read",
    )
    assert staged["install_scope"] == "machine"
    assert "containing_app" not in staged


def test_a_plugin_kind_declaring_a_path_marker_reads_it_from_the_table(monkeypatch):
    """The marker is data, not a literal in the classifier.

    `require_path_marker` sat in macos_host_plugin_kinds.yml while the DAL
    check compared against a hardcoded copy of the same string, so editing
    the table changed nothing (rule 21).
    """
    import blint.lib.macos_host_plugins as mod

    monkeypatch.setattr(
        mod,
        "_kinds_table",
        lambda: {
            "kinds": {
                "dal_plugin": {
                    "title": "Test DAL",
                    "host": "a camera client",
                    "require_path_marker": "vendor/camera-plugins",
                }
            }
        },
    )
    assert mod.classify_host_plugin("/opt/vendor/camera-plugins/X.plugin", "plugin", {}, "read")
    assert mod.classify_host_plugin("/opt/elsewhere/X.plugin", "plugin", {}, "read") is None
