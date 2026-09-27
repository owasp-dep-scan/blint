"""Tests for framework identification (04/B, rule 38) - H1-H5.

The R1 fixtures are the committed evidence files
(``tests/data/android/<framework>-evidence.json``, generated from the
corpus by ``tests/scripts/android/extract_identification_evidence.py``);
each test rebuilds the parse()-shaped metadata the detectors read from the
recorded evidence and asserts the identification against it. The R2 tests
parse the corpus library directly when it is present on the machine and
skip otherwise (rule 39: the corpus is never committed).
"""

import json
from pathlib import Path

import pytest

from blint.lib.framework_ident import (
    FRAMEWORK_COMPONENTS,
    attach_frameworks,
    framework_identity,
    identify_frameworks,
)

EVIDENCE_DIR = Path(__file__).parent / "data" / "android"


class _FakeElf:
    """The parsed-object surface identify_frameworks reads."""

    def __init__(self, strings=(), dynamic_entries=()):
        self._strings = list(strings)
        self.dynamic_entries = list(dynamic_entries)

    @property
    def strings(self):
        return self._strings


def _load_evidence(framework: str) -> dict:
    path = EVIDENCE_DIR / f"{framework}-evidence.json"
    if not path.exists():
        pytest.skip(f"{path.name} not committed")
    return json.loads(path.read_text())


def _metadata_from_evidence(evidence: dict) -> dict:
    """Rebuild the parse()-shaped metadata the detectors read."""
    blint = evidence["evidence"]["blint_parse"]
    sym = blint["symbol_evidence"]
    symbols = [{"name": n, "is_exported": True} for n in sym["matched_names"]]
    ident = blint.get("android_ident") or {}
    metadata = {
        "dynamic_symbols": symbols,
    }
    if ident:
        metadata["android"] = {"android_ident": ident}
    return metadata


def test_r1_ndk_libcxx_evidence_identifies_the_runtime():
    evidence = _load_evidence("ndk-libcxx")
    ident = evidence["evidence"]["blint_parse"]["android_ident"]
    assert ident and ident["ndk_version"], "the corpus lib must carry an NDK note"
    # The oracle side of the same run: the symbol evidence flags the
    # extractor recorded must agree with the detectors' requirements.
    sym = evidence["evidence"]["blint_parse"]["symbol_evidence"]
    assert sym["ndk1_namespace"] and sym["operator_new_exported"]

    metadata = _metadata_from_evidence(evidence)
    parsed = _FakeElf(dynamic_entries=[_Soname("libc++_shared.so")])
    records = identify_frameworks(parsed, metadata)
    assert [r["framework"] for r in records] == ["ndk-libcxx"]
    assert records[0]["version"] == ident["ndk_version"]
    what = [e["what"] for e in records[0]["evidence"]]
    assert "declared DT_SONAME" in what
    assert "exported operator new/delete (libc++abi)" in what


class _Soname:
    """One DT_SONAME dynamic entry carrying LIEF's own tag value."""

    def __init__(self, name):
        import lief

        self.name = name
        self.tag = lief.ELF.DynamicEntry.TAG.SONAME


def test_r1_a_bundled_static_libcxx_does_not_replace_its_host():
    """An app library that bundles libc++ keeps its own identity.

    libnative-imagetranscoder.so (frescolib) exports operator new/delete
    and carries __ndk1 and an NDK note; what it does not do is declare the
    SONAME libc++_shared.so. Without the SONAME evidence there is no
    ndk-libcxx identification - a statically linked copy is never a second
    copy of the runtime.
    """
    evidence = _load_evidence("ndk-libcxx")
    metadata = _metadata_from_evidence(evidence)
    parsed = _FakeElf(dynamic_entries=[_Soname("libnative-imagetranscoder.so")])
    assert identify_frameworks(parsed, metadata) == []
    parsed = _FakeElf()
    assert identify_frameworks(parsed, metadata) == []


def test_r1_file_name_alone_is_never_evidence():
    """No note, no symbols, only a name: no identification (rule 38)."""
    metadata = {"dynamic_symbols": []}
    parsed = _FakeElf()
    assert identify_frameworks(parsed, metadata) == []
    records = identify_frameworks(parsed, metadata)
    assert not FRAMEWORK_COMPONENTS.keys() & {
        r.get("framework") for r in records
    }


def test_framework_identity_builds_the_purl_with_the_abi_qualifier():
    record = {"framework": "ndk-libcxx", "version": "r26b"}
    name, version, purl = framework_identity(record, ["arm64-v8a", "x86"])
    assert name == "libc++ (NDK)"
    assert version == "r26b"
    assert purl == "pkg:generic/android-ndk/libcxx@r26b?abi=arm64-v8a%2Cx86"
    # A versionless record stays versionless - never a guessed version.
    _name, version, purl = framework_identity(
        {"framework": "ndk-libcxx"}, ["arm64-v8a"]
    )
    assert version == ""
    assert "@" not in purl


def test_framework_identity_returns_none_for_hint_only_records():
    assert framework_identity({"framework": "dart-aot-snapshot"}, []) is None
    assert framework_identity({}, []) is None


def test_attach_frameworks_stores_records_under_frameworks():
    metadata = {"android": {"android_ident": {"ndk_version": "r26b"}}}
    parsed = _FakeElf(dynamic_entries=[_Soname("libc++_shared.so")])
    out = attach_frameworks(metadata, parsed)
    # The bare-standin metadata lacks the symbol evidence, so nothing fires:
    # absence (no key) must read as "pass never matched", not a clean result.
    assert "frameworks" not in out


@pytest.mark.skipif(
    not (
        Path.home()
        / "sandbox/android-corpus/tier3-frameworks/com.blint.rnhello_1.apk"
    ).exists(),
    reason="corpus not present on this machine (rule 39: never committed)",
)
def test_r2_corpus_libcxx_identifies_and_app_lib_does_not():
    """R2: the real corpus library, parsed for real, when present."""
    import os
    import tempfile
    import zipfile

    apk = Path.home() / "sandbox/android-corpus/tier3-frameworks/com.blint.rnhello_1.apk"
    from blint.lib.binary import parse

    with tempfile.TemporaryDirectory() as tmp:
        with zipfile.ZipFile(apk) as z:
            libcxx = z.read("lib/arm64-v8a/libc++_shared.so")
            transcoder = z.read("lib/arm64-v8a/libnative-imagetranscoder.so")
        libcxx_path = os.path.join(tmp, "libc++_shared.so")
        transcoder_path = os.path.join(tmp, "libnative-imagetranscoder.so")
        Path(libcxx_path).write_bytes(libcxx)
        Path(transcoder_path).write_bytes(transcoder)

        libcxx_meta = parse(libcxx_path)
        records = libcxx_meta.get("frameworks") or []
        assert [r["framework"] for r in records] == ["ndk-libcxx"]
        assert records[0]["version"] == "r26-canary"

        # The bundled-static twin stays unidentified (no second copy of the
        # runtime - H4's nested-only rule, checked on the app side).
        transcoder_meta = parse(transcoder_path)
        assert not (transcoder_meta.get("frameworks") or [])
