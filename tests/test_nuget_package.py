"""W3.5 — NuGet identity in the SBOM: the .nupkg reader and its bounds.

Tests here hold the rule-30 duty for the ``.nupkg`` container (every limit
with a hostile fixture that exceeds it and is refused by name, and a leak
assertion across success and failure — the reader extracts nothing, so the
assertion is the stronger "no temp entry is ever created"), the rule-11
negative fixtures for the retired ``.dll``-to-``pkg:nuget`` heuristic, the
version-slot honesty contract (``internal:version_source`` on every nuget
component that carries a version), and the token-qualifier move.

Real-artifact assertions against the corpus ``.nupkg`` files skip when the
corpus is absent; their ground truth is the NuGet client's own resolution
(``dotnet list package``) and ``GetAssemblyName`` on the Windows VM, pasted
in the packet commit.
"""

import os
import tempfile
import zipfile

import pytest

from blint.lib.nuget_package import (
    MAX_LISTED_NUSPEC_DEPENDENCIES,
    MAX_NUPKG_MEMBERS,
    MAX_NUSPEC_MEMBER_SIZE,
    _exact_pin,
    read_nupkg_nuspec,
)

NUSPEC_2013 = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">'
    "<metadata>"
    "<id>{id}</id><version>{version}</version>"
    "{extra}"
    "</metadata></package>"
)

GROUPED_DEPS = (
    "<dependencies>"
    '<group targetFramework="net8.0">'
    '<dependency id="System.IO.Pipelines" version="9.0.0" />'
    '<dependency id="Serilog" version="[4.2.0]" />'
    "</group>"
    '<group targetFramework=".NETFramework4.6.2">'
    '<dependency id="System.IO.Pipelines" version="9.0.0" />'
    '<dependency id="System.ValueTuple" version="[4.5.0,)" />'
    "</group>"
    "</dependencies>"
)

FLAT_DEPS = (
    "<dependencies>"
    '<dependency id="Serilog" version="4.2.0" />'
    "</dependencies>"
)


def _write_nupkg(path, nuspec: bytes, extra_members=None):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        if nuspec is not None:
            zf.writestr("Example.Package.nuspec", nuspec)
        for name, data in extra_members or []:
            zf.writestr(name, data)


def _nuspec(id_="Example.Package", version="1.2.3", extra="", template=NUSPEC_2013):
    return template.format(id=id_, version=version, extra=extra).encode()


# ---------------------------------------------------------------------------
# Identity: namespace variants (rule 10) and both dependency shapes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "namespace",
    [
        "http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd",
        "http://schemas.microsoft.com/packaging/2013/01/nuspec.xsd",
        "http://schemas.microsoft.com/packaging/2012/06/nuspec.xsd",
        "http://schemas.microsoft.com/packaging/2011/10/nuspec.xsd",
        "http://schemas.microsoft.com/packaging/2011/08/nuspec.xsd",
        "",
    ],
)
def test_identity_across_nuspec_namespace_variants(tmp_path, namespace):
    # All five namespaces were counted in real packages on the VM (100x
    # 2013/05, plus 2011/08, 2011/10, 2012/06, 2013/01); hand-built
    # packages ship none.
    package_open = f'<package xmlns="{namespace}">' if namespace else "<package>"
    doc = (
        '<?xml version="1.0" encoding="utf-8"?>'
        + package_open
        + "<metadata><id>Example.Package</id><version>1.2.3</version></metadata>"
        + "</package>"
    )
    target = tmp_path / "p.nupkg"
    _write_nupkg(target, doc.encode())
    result = read_nupkg_nuspec(str(target))
    assert result["package_id"] == "Example.Package"
    assert result["package_version"] == "1.2.3"
    assert result["refusals"] == []


def test_grouped_and_flat_dependency_shapes(tmp_path):
    target = tmp_path / "p.nupkg"
    _write_nupkg(target, _nuspec(extra=GROUPED_DEPS))
    result = read_nupkg_nuspec(str(target))
    deps = {(d["id"], d["group"]): d for d in result["dependencies"]}
    # The same id in two groups is two nuspec rows (the SBOM layer dedupes
    # by purl); an exact pin is the only row that yields a version.
    assert deps[("System.IO.Pipelines", "net8.0")]["exact_version"] is None
    assert deps[("Serilog", "net8.0")]["exact_version"] == "4.2.0"
    assert deps[("System.ValueTuple", ".NETFramework4.6.2")]["exact_version"] is None
    assert deps[("System.IO.Pipelines", ".NETFramework4.6.2")]["version_range"] == "9.0.0"

    flat = tmp_path / "flat.nupkg"
    _write_nupkg(flat, _nuspec(extra=FLAT_DEPS))
    result = read_nupkg_nuspec(str(flat))
    assert [d["id"] for d in result["dependencies"]] == ["Serilog"]
    # A bare version in nuspec grammar is a floor (">="), not a pin — the
    # restored version is the client's decision, never stated here.
    assert result["dependencies"][0]["exact_version"] is None


def test_exact_pin_grammar():
    assert _exact_pin("[1.2.3]") == "1.2.3"
    assert _exact_pin("1.2.3") is None  # minimum-version floor, not a pin
    assert _exact_pin("[1.0, 2.0)") is None
    assert _exact_pin("1.2.*") is None
    assert _exact_pin("") is None
    assert _exact_pin("[]") is None


# ---------------------------------------------------------------------------
# Rule 30: every limit refuses by name, with a fixture that exceeds it
# ---------------------------------------------------------------------------


def test_member_count_cap_refuses_by_name(tmp_path):
    # Fixture larger than the walk window (rule 33): the nuspec sits past
    # the cap, so the walk stops before finding it.
    target = tmp_path / "many.nupkg"
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zf:
        for i in range(MAX_NUPKG_MEMBERS + 5):
            zf.writestr(f"lib/m{i}.txt", b"x")
        zf.writestr("Example.Package.nuspec", _nuspec())
    result = read_nupkg_nuspec(str(target))
    assert "member_count_exceeds_cap" in result["refusals"]
    assert result["member_count"] == MAX_NUPKG_MEMBERS
    assert result["package_id"] is None
    # The other side of the boundary: the same archive with the nuspec
    # inside the walked prefix still reports identity, with the cap named
    # beside it rather than refusing the whole package.
    target2 = tmp_path / "many2.nupkg"
    with zipfile.ZipFile(target2, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Example.Package.nuspec", _nuspec())
        for i in range(MAX_NUPKG_MEMBERS + 5):
            zf.writestr(f"lib/m{i}.txt", b"x")
    result2 = read_nupkg_nuspec(str(target2))
    assert "member_count_exceeds_cap" in result2["refusals"]
    assert result2["package_id"] == "Example.Package"


def test_total_uncompressed_cap_refuses_by_name(tmp_path):
    target = tmp_path / "big.nupkg"
    # 500 members x 1.2 MiB of zeros: under the member cap, over the total
    # budget, and ~1 KB/member on disk so the fixture stays small.
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Example.Package.nuspec", _nuspec())
        for i in range(500):
            zf.writestr(f"lib/m{i}.bin", b"\x00" * (int(1.2 * 1024 * 1024)))
    result = read_nupkg_nuspec(str(target))
    assert "total_uncompressed_exceeds_cap" in result["refusals"]


def test_nuspec_size_cap_refuses_by_name(tmp_path):
    target = tmp_path / "bignuspec.nupkg"
    _write_nupkg(target, b"<package>" + b"x" * (MAX_NUSPEC_MEMBER_SIZE + 1) + b"</package>")
    result = read_nupkg_nuspec(str(target))
    assert "nuspec_member_exceeds_cap" in result["refusals"]
    assert result["package_id"] is None


@pytest.mark.parametrize(
    "member_name",
    [
        "../evil.txt",
        "lib/../../evil.txt",
        "/etc/passwd",
        "C:evil.dll",
        # The drive-absolute form, which is what an archiver actually
        # writes and what ntpath.join actually honours: joining an output
        # directory with "C:/evil/x" yields "C:/evil/x". Testing only the
        # drive-relative "C:evil.dll" above tested the shape the code
        # happened to check rather than the shape that escapes.
        "C:/evil/evil.dll",
        "c:/evil.dll",
    ],
)
def test_unsafe_member_paths_refuse_by_name(tmp_path, member_name):
    # Ground rule 30's traversal class. A "\" in a member name is refused
    # even though this reader never extracts, because a later extractor
    # could. (The "\" case has its own test below: on Windows,
    # ZipInfo.__init__ rewrites "\" to "/" at write time, so writestr can
    # never store one there — the AGENTS.md separator edge, in test form.)
    target = tmp_path / "evil.nupkg"
    with zipfile.ZipFile(target, "w") as zf:
        zf.writestr(member_name, b"x")
        zf.writestr("Example.Package.nuspec", _nuspec())
    result = read_nupkg_nuspec(str(target))
    assert "member_path_unsafe" in result["refusals"]
    assert result["package_id"] == "Example.Package"


def test_backslash_member_name_refuses_by_name(tmp_path):
    # Python's zipfile rewrites "\" to "/" in member names on Windows — on
    # every write path and, on CPython >= 3.14 there, on the read path
    # too — so a backslash member name cannot survive into blint's reader
    # on that platform: the stdlib sanitises it upstream. The name is
    # planted by byte-patching a same-length placeholder into the finished
    # archive (offsets stay valid; no write path can normalise it), and
    # the test then asserts whichever truth the platform actually offers:
    # the refusal where the name survives (macOS/Linux/older Windows
    # Pythons), and the documented stdlib layering where it does not.
    placeholder, evil = "lib/evil_dll", "lib\\evil.dll"
    assert len(placeholder) == len(evil)
    target = tmp_path / "backslash.nupkg"
    with zipfile.ZipFile(target, "w") as zf:
        zf.writestr(placeholder, b"x")
        zf.writestr("Example.Package.nuspec", _nuspec())
    patched = target.read_bytes().replace(
        placeholder.encode(), evil.encode()
    )
    assert patched != target.read_bytes(), "placeholder not found to patch"
    target.write_bytes(patched)
    with zipfile.ZipFile(target) as zf:
        stored = zf.namelist()
    result = read_nupkg_nuspec(str(target))
    if evil in stored:
        # the separator reached the reader; the reader refuses it even
        # though it never extracts, because a later extractor could
        assert "member_path_unsafe" in result["refusals"]
        assert result["package_id"] == "Example.Package"
    else:
        # CPython >= 3.14 on Windows normalised the name to "/" before
        # blint saw it. That is stdlib behaviour upstream of the reader,
        # not a blint refusal: the member reads as a safe name and the
        # identity is reported normally, with no refusal claimed.
        assert "lib/evil.dll" in stored
        assert "member_path_unsafe" not in result["refusals"]
        assert result["package_id"] == "Example.Package"


def test_symlink_member_refuses_by_name(tmp_path):
    target = tmp_path / "link.nupkg"
    with zipfile.ZipFile(target, "w") as zf:
        info = zipfile.ZipInfo("link-to-nuspec")
        # Unix S_IFLNK in the high 16 bits of external_attr.
        info.external_attr = (0o120777 << 16)
        zf.writestr(info, "Example.Package.nuspec")
        zf.writestr("Example.Package.nuspec", _nuspec())
    result = read_nupkg_nuspec(str(target))
    assert "member_is_symlink" in result["refusals"]
    assert result["package_id"] == "Example.Package"


def test_member_depth_cap_refuses_by_name(tmp_path):
    target = tmp_path / "deep.nupkg"
    _write_nupkg(target, _nuspec(), extra_members=[("a/" * 20 + "deep.txt", b"x")])
    result = read_nupkg_nuspec(str(target))
    assert "member_depth_exceeds_cap" in result["refusals"]
    assert result["package_id"] == "Example.Package"


def test_missing_and_multiple_nuspec_refuse_by_name(tmp_path):
    none_target = tmp_path / "none.nupkg"
    _write_nupkg(none_target, None, extra_members=[("[Content_Types].xml", b"<Types/>")])
    result = read_nupkg_nuspec(str(none_target))
    assert "no_nuspec_member" in result["refusals"]
    assert result["package_id"] is None

    two_target = tmp_path / "two.nupkg"
    with zipfile.ZipFile(two_target, "w") as zf:
        zf.writestr("A.nuspec", _nuspec(id_="A", version="1.0.0"))
        zf.writestr("B.nuspec", _nuspec(id_="B", version="2.0.0"))
    result2 = read_nupkg_nuspec(str(two_target))
    assert "multiple_nuspec_members" in result2["refusals"]
    assert result2["package_id"] is None


def test_not_a_zip_refuses_by_name(tmp_path):
    target = tmp_path / "fake.nupkg"
    target.write_bytes(b"MZ not a zip at all")
    result = read_nupkg_nuspec(str(target))
    assert "archive_unreadable" in result["refusals"]
    assert result["package_id"] is None


def test_dependency_listing_cap_refuses_by_name(tmp_path):
    # One <dependency> per group: the cap counts dependency rows across
    # groups, and the hostile archive exceeds it by three.
    nuspec = _nuspec(
        extra="<dependencies>"
        + "".join(
            f'<group targetFramework="net8.0"><dependency id="Dep{i}" version="[1.0.0]" /></group>'
            for i in range(MAX_LISTED_NUSPEC_DEPENDENCIES + 3)
        )
        + "</dependencies>"
    )
    target = tmp_path / "manydeps.nupkg"
    _write_nupkg(target, nuspec)
    result = read_nupkg_nuspec(str(target))
    assert "dependencies_listed_capped" in result["refusals"]
    assert len(result["dependencies"]) == MAX_LISTED_NUSPEC_DEPENDENCIES


# ---------------------------------------------------------------------------
# Rule 18: the cleanup claim is asserted, not read — and the reader's
# stronger claim is that no temp entry ever exists, on any path
# ---------------------------------------------------------------------------


def _temp_snapshot():
    return set(os.listdir(tempfile.gettempdir()))


@pytest.mark.parametrize(
    "archive",
    [
        "ok.nupkg",
        "evil.nupkg",
        "big.nupkg",
        "many.nupkg",
        "none.nupkg",
    ],
)
def test_no_temp_entries_across_success_and_every_refusal(tmp_path, archive):
    """The reader extracts nothing, so cleanup-on-failure holds by not
    creating anything: the delta across each parse is empty, asserted
    against the live temp directory (ground rule 18's checklist wants the
    delta, and this is its strongest form)."""
    targets = {
        "ok.nupkg": lambda p: _write_nupkg(p, _nuspec(extra=GROUPED_DEPS)),
        "evil.nupkg": lambda p: _write_nupkg(
            p, _nuspec(), extra_members=[("../evil.txt", b"x"), ("..\\evil2.txt", b"x")]
        ),
        "big.nupkg": lambda p: _write_nupkg(
            p, b"<package>" + b"x" * (MAX_NUSPEC_MEMBER_SIZE + 1) + b"</package>"
        ),
        "many.nupkg": lambda p: _write_nupkg(
            p, None, extra_members=[(f"lib/m{i}.txt", b"x") for i in range(MAX_NUPKG_MEMBERS + 3)]
        ),
        "none.nupkg": lambda p: _write_nupkg(p, None),
    }
    target = tmp_path / archive
    targets[archive](target)
    before = _temp_snapshot()
    read_nupkg_nuspec(str(target))
    after = _temp_snapshot()
    # No extraction anywhere, so no cleanup duty on any path — asserted as
    # an empty live delta across success and across every refusal above.
    assert after - before == set()


# ---------------------------------------------------------------------------
# SBOM wiring: identity, honesty properties, refusal visibility
# ---------------------------------------------------------------------------


def test_nupkg_components_carry_package_identity_and_ranges(tmp_path):
    from blint.lib.sbom import _scratch_sbom, process_nupkg_file

    target = tmp_path / "p.nupkg"
    _write_nupkg(target, _nuspec(extra=GROUPED_DEPS))
    scratch = _scratch_sbom()
    deps: dict = {}
    components = process_nupkg_file(deps, str(target), scratch)
    parent = scratch.metadata.component.components[0]
    assert parent.purl == "pkg:nuget/Example.Package@1.2.3"
    props = {p.name: p.value for p in parent.properties}
    assert props["internal:version_source"] == "package_version"
    by_purl = {str(c.purl): c for c in components}
    # Exact pin -> a versioned purl; floor/range -> an unversioned purl
    # plus the range as a property. Same id across groups -> one component.
    assert "pkg:nuget/Serilog@4.2.0" in by_purl
    assert "pkg:nuget/System.IO.Pipelines" in by_purl
    assert "pkg:nuget/System.ValueTuple" in by_purl
    assert "pkg:nuget/System.IO.Pipelines@9.0.0" not in by_purl
    range_props = {p.name: p.value for p in by_purl["pkg:nuget/System.ValueTuple"].properties}
    assert range_props["internal:version_range"] == "[4.5.0,)"
    assert "internal:version_source" not in range_props
    pin_props = {p.name: p.value for p in by_purl["pkg:nuget/Serilog@4.2.0"].properties}
    assert pin_props["internal:version_source"] == "package_version"
    # The dependency graph knows the parent -> dependency edges.
    parent_ref = str(parent.bom_ref.model_dump(mode="python"))
    assert parent_ref in deps
    assert str(by_purl["pkg:nuget/Serilog@4.2.0"].bom_ref.model_dump(mode="python")) in deps[parent_ref]


def test_refused_nupkg_still_emits_a_component_naming_the_refusal(tmp_path):
    # Rule 32: a .nupkg that produced no package identity must not vanish
    # or read as an ordinary generic binary — the refusals travel on the
    # component.
    from blint.lib.sbom import _scratch_sbom, process_nupkg_file

    target = tmp_path / "hostile.nupkg"
    _write_nupkg(target, None, extra_members=[("../evil.txt", b"x")])
    scratch = _scratch_sbom()
    process_nupkg_file({}, str(target), scratch)
    parent = scratch.metadata.component.components[0]
    assert str(parent.purl).startswith("pkg:generic/")
    props = {p.name: p.value for p in parent.properties}
    assert "no_nuspec_member" in props["internal:nupkg_refusals"]
    assert "member_path_unsafe" in props["internal:nupkg_refusals"]


# ---------------------------------------------------------------------------
# Rule 11: negative fixtures for the retired filename heuristic
# ---------------------------------------------------------------------------


# The .dll-named symbol-version case is covered end to end by
# tests/test_sbom_blintdb.py::test_deep_elf_abi_floor_is_a_parent_property_not_a_component.


def test_dll_named_recovered_dependency_is_generic_not_nuget():
    from blint.lib.sbom import components_from_recovered_dependencies

    comps = components_from_recovered_dependencies(
        [{"name": "plugin.dll", "confidence": "high", "evidence": ["dlopen"]}]
    )
    assert [str(c.purl) for c in comps] == ["pkg:generic/plugin"]


def test_native_dll_parent_is_generic(tmp_path):
    from blint.lib.sbom import default_parent

    parent = default_parent([str(tmp_path / "python313.dll")])
    assert str(parent.purl) == "pkg:generic/python313"
    assert parent.type.value == "library"


def test_default_parent_exe_is_unchanged(tmp_path):
    from blint.lib.sbom import default_parent

    parent = default_parent([str(tmp_path / "app.exe")])
    assert str(parent.purl) == "pkg:generic/app.exe"
    assert parent.type.value == "application"


# ---------------------------------------------------------------------------
# Managed parent identity: token qualifier and version honesty
# ---------------------------------------------------------------------------


def test_managed_parent_identity_from_assembly_metadata():
    from blint.cyclonedx.spec import Component, Type
    from blint.lib.sbom import upgrade_parent_to_assembly_identity

    parent = Component(type=Type.application, name="Newtonsoft.Json.dll")
    parent.properties = []
    assembly = {
        "name": "Newtonsoft.Json",
        "version": "13.0.0.0",
        "public_key_token": "30ad4fe6b2a6aeed",
    }
    upgrade_parent_to_assembly_identity(parent, assembly)
    assert str(parent.purl) == "pkg:nuget/Newtonsoft.Json@13.0.0.0?token=30ad4fe6b2a6aeed"
    assert parent.version.root == "13.0.0.0"
    props = {p.name: p.value for p in parent.properties}
    assert props["internal:version_source"] == "assembly_version"
    assert parent.type.value == "library"


def test_unsigned_assembly_parent_has_no_token_qualifier():
    # The required unsigned case: no token in the metadata, no qualifier in
    # the purl — an empty qualifier would be a token blint does not have.
    from blint.cyclonedx.spec import Component, Type
    from blint.lib.sbom import upgrade_parent_to_assembly_identity

    parent = Component(type=Type.library, name="unsigned.dll")
    parent.properties = []
    upgrade_parent_to_assembly_identity(
        parent, {"name": "unsigned", "version": "1.0.0.0"}
    )
    assert str(parent.purl) == "pkg:nuget/unsigned@1.0.0.0"


def test_build_bom_overlay_wins_over_assembly_version():
    from blint.cyclonedx.spec import Component, Type
    from blint.lib.sbom import upgrade_parent_to_assembly_identity

    parent = Component(type=Type.library, name="Newtonsoft.Json.dll")
    parent.properties = []
    overlay = {"pkg:nuget/Newtonsoft.Json": "pkg:nuget/Newtonsoft.Json@13.0.3"}
    upgrade_parent_to_assembly_identity(
        parent,
        {"name": "Newtonsoft.Json", "version": "13.0.0.0",
         "public_key_token": "30ad4fe6b2a6aeed"},
        overlay,
    )
    assert str(parent.purl) == "pkg:nuget/Newtonsoft.Json@13.0.3"
    assert parent.version.root == "13.0.3"
    props = {p.name: p.value for p in parent.properties}
    assert props["internal:version_source"] == "package_version"


# ---------------------------------------------------------------------------
# Rule 32: the AssemblyRef coverage state
# ---------------------------------------------------------------------------


def test_assemblyref_state_matrix():
    from blint.lib.sbom import dotnet_assemblyref_state

    assert dotnet_assemblyref_state({}) is None
    assert dotnet_assemblyref_state(None) is None
    assert dotnet_assemblyref_state({"parse_status": "parsed"}) == "read"
    # A genuine zero-row table is a determined negative (the netmodule
    # shape) — "read", not a gap.
    assert dotnet_assemblyref_state({"parse_status": "parsed", "counts": {"assemblyref": 0}}) == "read"
    assert dotnet_assemblyref_state({"parse_status": "partial"}) == "partial"
    assert dotnet_assemblyref_state({"parse_status": "malformed"}) == "malformed"
    assert dotnet_assemblyref_state({"parse_status": "no_cli_metadata"}) == "no_cli_metadata"
    assert (
        dotnet_assemblyref_state(
            {"parse_status": "parsed", "degradations": ["assembly_refs_listed_capped"]}
        )
        == "capped"
    )


# ---------------------------------------------------------------------------
# Real artifacts (ground rules 22/29) — skip when the corpus is absent
# ---------------------------------------------------------------------------


def _corpus_path(relative: str):
    path = os.path.expanduser(f"~/sandbox/pe-corpus/{relative}")
    if not os.path.exists(path):
        pytest.skip("pe-corpus not present")
    return path


def test_real_corpus_nupkg_identities_match_the_nuget_client():
    # Ground truth: `dotnet list package` (the NuGet client's own
    # resolution) and the .nuspec agree on id and version for every
    # package in the 21-package VM oracle set (21/21); these are three of
    # them. blint's reader states the same identity from the archive.
    expected = {
        "newtonsoft.json.13.0.3.nupkg": ("Newtonsoft.Json", "13.0.3"),
        "serilog.4.2.0.nupkg": ("Serilog", "4.2.0"),
        "system.text.json.9.0.0.nupkg": ("System.Text.Json", "9.0.0"),
    }
    for name, (pid, ver) in expected.items():
        result = read_nupkg_nuspec(_corpus_path(f"raw/nuget/{name}"))
        assert result["package_id"] == pid, name
        assert result["package_version"] == ver, name
        assert result["refusals"] == [], name


def test_real_newtonsoft_nupkg_dependency_groups_are_floors():
    # The nuspec of the most-downloaded NuGet package: dependency rows
    # grouped per target framework, every version a floor (bare "4.3.0"
    # means >= 4.3.0), so no exact_version anywhere.
    result = read_nupkg_nuspec(_corpus_path("raw/nuget/newtonsoft.json.13.0.3.nupkg"))
    deps = {(d["id"], d["group"]): d for d in result["dependencies"]}
    assert ("Microsoft.CSharp", ".NETStandard1.0") in deps
    assert ("NETStandard.Library", ".NETStandard1.1") in deps or (
        "NETStandard.Library",
        ".NETStandard1.3",
    ) in deps
    assert all(d["exact_version"] is None for d in result["dependencies"])


def test_real_stj_nupkg_dependencies_are_floors_not_versions():
    result = read_nupkg_nuspec(_corpus_path("raw/nuget/system.text.json.9.0.0.nupkg"))
    rows = [d for d in result["dependencies"] if d["id"] == "Microsoft.Bcl.AsyncInterfaces"]
    assert rows, "Microsoft.Bcl.AsyncInterfaces missing from STJ nuspec deps"
    groups = {d["group"] for d in rows}
    assert ".NETFramework4.6.2" in groups
    # Bare "9.0.0" in the nuspec means >= 9.0.0 — a floor. The version
    # slot stays empty rather than claiming the client's resolution.
    assert all(d["exact_version"] is None for d in rows)
    assert all(d["version_range"] == "9.0.0" for d in rows)


def test_real_managed_assembly_parent_purl(tmp_path):
    # Ground truth: GetAssemblyName on the VM reads Newtonsoft.Json
    # 13.0.0.0 token 30ad4fe6b2a6aeed; the nuspec states package version
    # 13.0.3. The component carries the assembly identity and names its
    # version source — it must not synthesise 13.0.3-from-13.0.0.0 or the
    # reverse.
    from blint.lib.sbom import _scratch_sbom, process_exe_file

    dll = _corpus_path(
        "tier2-managed/newtonsoft.json-13.0.3/lib/net6.0/Newtonsoft.Json.dll"
    )
    scratch = _scratch_sbom()
    components = process_exe_file({}, False, dll, scratch, [], None, False, False, None)
    parent = components[0]
    assert str(parent.purl) == "pkg:nuget/Newtonsoft.Json@13.0.0.0?token=30ad4fe6b2a6aeed"
    props = {p.name: p.value for p in parent.properties}
    assert props["internal:version_source"] == "assembly_version"
    assert props["internal:dotnet_assemblyref_state"] == "read"
    # Every strong-named AssemblyRef component carries its token as a purl
    # qualifier and no longer as a property.
    ref = next(c for c in components if str(c.purl).startswith("pkg:nuget/System.Runtime@"))
    assert str(ref.purl) == "pkg:nuget/System.Runtime@6.0.0.0?token=b03f5f7f11d50a3a"
    ref_props = {p.name for p in ref.properties}
    assert "internal:public_key_token" not in ref_props


def test_real_native_dll_parent_is_not_a_nuget_package(tmp_path):
    # The packet's reason to exist, on a real artifact: python313.dll is
    # CPython's native DLL — no CLI header, no NuGet package. The
    # component says generic, not pkg:nuget/python313.
    from blint.lib.sbom import _scratch_sbom, process_exe_file

    dll = _corpus_path("tier0-reference/python-amd64/python313.dll")
    scratch = _scratch_sbom()
    components = process_exe_file({}, False, dll, scratch, [], None, False, False, None)
    parent = components[0]
    assert str(parent.purl) == "pkg:generic/python313"
    assert not any(
        str(getattr(c, "purl", "")).startswith("pkg:nuget/") for c in components
    )
