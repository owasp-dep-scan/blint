"""Bounded NuGet package (``.nupkg``) reader for SBOM identity (W3.5).

A ``.nupkg`` is a zip archive whose ``.nuspec`` member is the one place the
real NuGet package id and package version are stated. Assembly metadata
cannot give those facts: the assembly name inside a package may differ from
the package id (measured: 45 of 60 tier-2 DLLs sit in a package whose id
differs from the assembly name), and the assembly version is not the package
version (measured over the tier-2 corpus and a 21-package VM oracle set:
zero of 50 identities are string-equal, and 31 differ semantically —
Newtonsoft.Json 13.0.3 ships assembly version 13.0.0.0).

An untrusted-input container parser (ground rule 30): member count, total
uncompressed size, member path depth and member path safety (``..``
segments, absolute paths, drive letters, backslash separators, symlink
entries) are bounded while walking the central directory, and the one
member whose bytes are decompressed — the ``.nuspec`` — has its own
per-member size cap. No other member is ever decompressed, so no other
member has a per-member read bound to need. Every refusal is named in the
returned ``refusals`` list — never a silent skip.

No extraction happens anywhere: the single ``.nuspec`` member is read into
memory, so there is no temp directory to clean up on any path. The leak test
asserts the stronger form of that claim: no temp entry is ever created,
across success and across every refusal.

Caps are set at >= 2x the maximum measured over 136 real ``.nupkg`` archives
on the Windows 11 ground-truth VM plus the corpus packages: 695 members max
(cap 2048), 125 MB total uncompressed max (cap 512 MiB), depth 7 max
(cap 16), largest ``.nuspec`` 6,564 bytes (cap 1 MiB).
"""

import xml.etree.ElementTree as ET
import zipfile

# Measured maxima in the module docstring; every cap has a hostile fixture
# in tests/test_nuget_package.py that exceeds it and is refused by name.
MAX_NUPKG_MEMBERS = 2048
MAX_NUPKG_TOTAL_UNCOMPRESSED = 512 * 1024 * 1024
MAX_NUSPEC_MEMBER_SIZE = 1024 * 1024
MAX_NUPKG_MEMBER_DEPTH = 16
MAX_LISTED_NUSPEC_DEPENDENCIES = 512

# The .nuspec lives at the archive root in every real package measured; one
# directory down is accepted for hand-built archives, deeper than that is
# not a shape NuGet produces.
MAX_NUSPEC_MEMBER_DEPTH = 2


def _localname(tag: str) -> str:
    """Strip an XML namespace from a tag: nuspec files ship five namespace
    variants in the wild (2013/05, 2013/01, 2012/06, 2011/10, 2011/08),
    and hand-built ones ship none."""
    return tag.rpartition("}")[2]


def _member_depth(name: str) -> int:
    # Zip member names use "/" per the spec; a "\" inside a member name is a
    # Windows-separator attack, refused before it reaches this count.
    return len(name.split("/"))


def _member_path_unsafe(name: str) -> bool:
    """A member name blint must never treat as a path it could extract.

    Ground rule 30's traversal class: ``..`` segments, rooted absolute
    paths, Windows drive letters, and backslash separators (the zip spec
    says ``/``; a ``\\`` is how an extracted path escapes on Windows).
    """
    if not name or "\x00" in name:
        return True
    if "\\" in name:
        return True
    if name.startswith("/"):
        return True
    segments = name.split("/")
    if any(seg == ".." for seg in segments):
        return True
    # Any drive-letter prefix, with or without a directory component: both
    # `C:evil` (drive-relative) and `C:/evil/x` (drive-absolute) escape an
    # output directory, because ntpath.join discards the base as soon as
    # the second argument names a drive. Refusing only the first form would
    # leave the one an archiver actually writes.
    return len(name) >= 2 and name[1] == ":" and name[0].isalpha()


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    # Unix mode bits live in the high 16 bits of external_attr; 0o120000 is
    # S_IFLNK. A symlink member is refused even though this reader never
    # extracts: a later extractor could, and the refusal is a fact about
    # the archive.
    return ((info.external_attr >> 16) & 0o170000) == 0o120000


def read_nupkg_nuspec(path: str) -> dict:
    """Read the ``.nuspec`` statement of one ``.nupkg`` without extracting.

    Returns a dict:

    - ``package_id`` / ``package_version`` — the NuGet identity, or None
      when the nuspec was absent, refused or did not state them.
    - ``dependencies`` — ``{id, version_range, group, exact_version}``
      rows; ``exact_version`` is set only when the range is an exact pin
      (``[1.2.3]``), because only a pin is a version a purl version slot
      may hold — a range is carried as a property, never synthesised into
      a version.
    - ``member_count`` — members walked before any cap stopped the walk.
    - ``refusals`` — every limit and hostile shape encountered, by name
      (ground rule 30). Refusals do not abort the identity: a package whose
      member listing was capped still reports the nuspec it was found in,
      with the cap named beside it.
    """
    result: dict = {
        "package_id": None,
        "package_version": None,
        "dependencies": [],
        "member_count": 0,
        "refusals": [],
    }
    nuspec_bytes = None
    try:
        with zipfile.ZipFile(path) as archive:
            nuspec_entry = None
            total_uncompressed = 0
            for info in archive.infolist():
                if result["member_count"] >= MAX_NUPKG_MEMBERS:
                    result["refusals"].append("member_count_exceeds_cap")
                    break
                result["member_count"] += 1
                name = info.filename
                if _member_path_unsafe(name):
                    result["refusals"].append("member_path_unsafe")
                    continue
                if _is_symlink(info):
                    result["refusals"].append("member_is_symlink")
                    continue
                if _member_depth(name) > MAX_NUPKG_MEMBER_DEPTH:
                    result["refusals"].append("member_depth_exceeds_cap")
                    continue
                total_uncompressed += info.file_size
                if total_uncompressed > MAX_NUPKG_TOTAL_UNCOMPRESSED:
                    result["refusals"].append("total_uncompressed_exceeds_cap")
                    break
                if name.lower().endswith(".nuspec"):
                    if _member_depth(name) <= MAX_NUSPEC_MEMBER_DEPTH:
                        if nuspec_entry is not None:
                            result["refusals"].append("multiple_nuspec_members")
                            nuspec_entry = None
                            break
                        nuspec_entry = info
            if nuspec_entry is None:
                if "multiple_nuspec_members" not in result["refusals"]:
                    result["refusals"].append("no_nuspec_member")
            elif nuspec_entry.file_size > MAX_NUSPEC_MEMBER_SIZE:
                result["refusals"].append("nuspec_member_exceeds_cap")
            else:
                nuspec_bytes = archive.read(nuspec_entry)
    except (zipfile.BadZipFile, OSError, RuntimeError):
        # A zip that cannot even be listed refuses everything: no identity
        # is claimed from an archive blint could not walk.
        result["refusals"].append("archive_unreadable")
        return result

    if nuspec_bytes is not None:
        _apply_nuspec(result, nuspec_bytes)
    return result


def _apply_nuspec(result: dict, data: bytes) -> None:
    """Parse the nuspec XML into the result dict, namespace-agnostically.

    ElementTree does not resolve external entities, so a hostile DTD in an
    untrusted nuspec cannot fetch anything; the parse either succeeds on
    the literal bytes or the refusal names it.
    """
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        result["refusals"].append("nuspec_xml_malformed")
        return
    metadata = None
    for child in root:
        if _localname(child.tag) == "metadata":
            metadata = child
            break
    if metadata is None:
        result["refusals"].append("nuspec_metadata_missing")
        return
    dependencies: list[dict] = []
    seen_deps: set[tuple[str, str, str]] = set()

    def add_dependency(dep: ET.Element, group: str) -> bool:
        """Record one <dependency>; False when the listing cap is reached."""
        if _localname(dep.tag) != "dependency":
            return True
        dep_id = (dep.get("id") or "").strip()
        if not dep_id:
            return True
        if len(dependencies) >= MAX_LISTED_NUSPEC_DEPENDENCIES:
            result["refusals"].append("dependencies_listed_capped")
            return False
        version_range = (dep.get("version") or "").strip()
        key = (dep_id, version_range, group)
        if key in seen_deps:
            return True
        seen_deps.add(key)
        dependencies.append(
            {
                "id": dep_id,
                "version_range": version_range,
                "group": group or None,
                "exact_version": _exact_pin(version_range),
            }
        )
        return True

    for child in metadata:
        tag = _localname(child.tag)
        if tag in ("id", "version") and child.text and child.text.strip():
            key = "package_id" if tag == "id" else "package_version"
            if result[key] is None:
                result[key] = child.text.strip()
        elif tag == "dependencies":
            # Two shapes in the wild: grouped (<group targetFramework>
            # wrapping <dependency> rows, the modern form) and flat
            # (<dependency> rows directly under <dependencies>, the legacy
            # form; its group, if any, is the targetFramework attribute on
            # <dependencies> itself).
            for sub in child:
                subtag = _localname(sub.tag)
                if subtag == "group":
                    group = sub.get("targetFramework") or ""
                    for dep in sub:
                        if not add_dependency(dep, group):
                            break
                elif subtag == "dependency":
                    if not add_dependency(sub, child.get("targetFramework") or ""):
                        break
    result["dependencies"] = dependencies


def _exact_pin(version_range: str) -> str | None:
    """The exact version a range pins, or None when it is a real range.

    In nuspec dependency grammar only ``[1.2.3]`` is an exact pin: a bare
    ``1.2.3`` means ">= 1.2.3" (a floor, not a resolution — the restored
    version is decided by the client, not stated here) and ``[1.0, 2.0)``
    is an interval. A floor or interval in a purl version slot would be a
    version blint does not have (ground rule 11), so it stays a property.
    """
    text = version_range.strip()
    if (
        text.startswith("[")
        and text.endswith("]")
        and "," not in text
        and len(text) > 2
    ):
        return text[1:-1].strip() or None
    return None
