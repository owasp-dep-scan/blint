"""Tests for framework identification.

The fixture tests use the committed evidence files
(``tests/data/android/<framework>-evidence.json``, generated from the
corpus by ``tests/scripts/android/extract_identification_evidence.py``);
each test rebuilds the parse()-shaped metadata the detectors read from the
recorded evidence and asserts the identification against it. The corpus tests
parse the corpus library directly when it is present on the machine and
skip otherwise (the corpus is never committed).
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
    """No note, no symbols, only a name: no identification."""
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
    reason="corpus not present on this machine (the corpus is never committed)",
)
def test_r2_corpus_libcxx_identifies_and_app_lib_does_not():
    """The real corpus library, parsed for real, when present."""
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
        # runtime - the nested-only rule, checked on the app side).
        transcoder_meta = parse(transcoder_path)
        assert not (transcoder_meta.get("frameworks") or [])


def test_r1_flutter_engine_identifies_with_nested_dart_and_hashes_only():
    """The engine record: symbols + Dart string; hashes stay hashes."""
    evidence = _load_evidence("flutter-engine")
    blint = evidence["evidence"]["blint_parse"]
    strings = blint["string_evidence"]
    assert strings["dart_vm_version"], "the engine embeds the Dart VM string"
    sym = blint["symbol_evidence"]
    assert sym["flutter_gpu_symbols"]

    symbols = [{"name": n, "is_exported": True} for n in sym["matched_names"]]
    metadata = {"dynamic_symbols": symbols}
    parsed = _FakeElf(strings=strings["dart_vm_version"] + strings["hex40_bare"])
    records = identify_frameworks(parsed, metadata)
    assert [r["framework"] for r in records] == ["flutter-engine"]
    record = records[0]
    # No version on the engine: the bare hashes map to no published release.
    assert "version" not in record
    # The nested Dart VM carries the version from its own string.
    nested = record.get("nested") or []
    assert [n["framework"] for n in nested] == ["dart-sdk"]
    assert nested[0]["version"] == strings["dart_vm_version"][0].split(" ")[0]
    assert nested[0]["static"] is True
    # The hashes ride as evidence values, never as the component version.
    hash_evidence = [e for e in record["evidence"] if "40-hex" in e["what"]]
    assert hash_evidence and "42d3d75a" in hash_evidence[0]["value"]


def test_r1_flutter_app_is_hint_only_with_the_snapshot_hash():
    """libapp.so: snapshot symbols + hash recorded; never a component."""
    evidence = _load_evidence("flutter-app")
    blint = evidence["evidence"]["blint_parse"]
    sym = blint["symbol_evidence"]
    assert sym["dart_snapshot_symbols"]

    symbols = [{"name": n, "is_exported": True} for n in sym["matched_names"]]
    metadata = {"dynamic_symbols": symbols}
    parsed = _FakeElf()
    records = identify_frameworks(parsed, metadata)
    assert [r["framework"] for r in records] == ["dart-aot-snapshot"]
    assert records[0]["framework"] not in FRAMEWORK_COMPONENTS
    assert framework_identity(records[0], []) is None


@pytest.mark.skipif(
    not (
        Path.home()
        / "sandbox/android-corpus/tier2-fdroid/org.localsend.localsend_app_643.apk"
    ).exists(),
    reason="corpus not present on this machine (the corpus is never committed)",
)
def test_r2_corpus_libflutter_nests_dart_and_libapp_stays_hint_only():
    """The real Flutter libraries, parsed for real, when present."""
    import os
    import tempfile
    import zipfile

    apk = (
        Path.home()
        / "sandbox/android-corpus/tier2-fdroid/org.localsend.localsend_app_643.apk"
    )
    from blint.lib.binary import parse

    with tempfile.TemporaryDirectory() as tmp:
        with zipfile.ZipFile(apk) as z:
            flutter = z.read("lib/arm64-v8a/libflutter.so")
            libapp = z.read("lib/arm64-v8a/libapp.so")
        flutter_path = os.path.join(tmp, "libflutter.so")
        libapp_path = os.path.join(tmp, "libapp.so")
        Path(flutter_path).write_bytes(flutter)
        Path(libapp_path).write_bytes(libapp)

        flutter_meta = parse(flutter_path)
        records = flutter_meta.get("frameworks") or []
        assert [r["framework"] for r in records] == ["flutter-engine"]
        name, version, purl = framework_identity(records[0], ["arm64-v8a"])
        assert name == "flutter_engine"
        assert version == ""
        assert purl == "pkg:github/flutter/flutter?abi=arm64-v8a"
        assert records[0]["nested"][0]["version"] == "3.11.5"

        libapp_meta = parse(libapp_path)
        app_records = libapp_meta.get("frameworks") or []
        assert [r["framework"] for r in app_records] == ["dart-aot-snapshot"]
        # The snapshot hash is in the evidence, hash-only.
        hash_evidence = [
            e for e in app_records[0]["evidence"] if "snapshot version hash" in e["what"]
        ]
        assert hash_evidence and len(hash_evidence[0]["value"]) == 32


def test_r1_hermes_android_identifies_from_the_rn_build_stamp():
    """libhermes.so is hermes-android, versioned by the "for RN x.y.z" stamp."""
    evidence = _load_evidence("react-native")
    blint = evidence["evidence"]["blint_parse"]
    strings = blint["string_evidence"]
    assert strings["rn_release"] == ["for RN 0.76.9"]
    metadata = _metadata_from_evidence(evidence)
    parsed = _FakeElf(strings=strings["rn_release"])
    records = identify_frameworks(parsed, metadata)
    assert [r["framework"] for r in records] == ["hermes-android"]
    assert records[0]["version"] == "0.76.9"
    name, version, purl = framework_identity(records[0], ["arm64-v8a"])
    assert (name, version) == ("hermes-android", "0.76.9")
    # RnHello's android/app/build.gradle pulls com.facebook.react:hermes-android.
    assert purl == "pkg:maven/com.facebook.react/hermes-android@0.76.9?abi=arm64-v8a"


def test_r1_fbjni_needs_both_the_string_and_the_symbol_namespace():
    """Templates alone (libreactnative) must never read as fbjni."""
    evidence = _load_evidence("fbjni")
    blint = evidence["evidence"]["blint_parse"]
    sym = blint["symbol_evidence"]
    assert sym["facebook_jni_namespace"] and blint["string_evidence"]["fbjni_uninitialized"]

    symbols = [{"name": n, "is_exported": True} for n in sym["matched_names"]]
    strings = blint["string_evidence"]["fbjni_uninitialized"]
    parsed = _FakeElf(strings=strings)
    records = identify_frameworks(parsed, {"dynamic_symbols": symbols})
    assert [r["framework"] for r in records] == ["fbjni"]

    # Symbols without the runtime string: a header-using library - no hit.
    records = identify_frameworks(
        _FakeElf(), {"dynamic_symbols": symbols}
    )
    assert records == []

    # The runtime string without the namespace: no hit either.
    records = identify_frameworks(parsed, {"dynamic_symbols": []})
    assert records == []


def test_r1_hermes_hbc_header_fact():
    """The bundle header: magic then the u32 BYTECODE_VERSION."""
    evidence = _load_evidence("react-native")
    hbc = evidence.get("hbc_header")
    assert hbc, "the R1 fixture records the bundle header bytes"
    # BytecodeFileFormat.h MAGIC, little-endian on disk.
    assert hbc["magic_hex"] == "c61fbc03c103191f"
    # BytecodeVersion.h: BYTECODE_VERSION = 96.
    assert hbc["bytecode_version"] == 96


@pytest.mark.skipif(
    not (
        Path.home()
        / "sandbox/android-corpus/tier3-frameworks/com.blint.rnhello_1.apk"
    ).exists(),
    reason="corpus not present on this machine (the corpus is never committed)",
)
def test_r2_corpus_rnhello_identifies_hermes_android_and_fbjni():
    """The real libraries and the bundle, parsed for real."""
    import os
    import tempfile
    import zipfile

    apk = Path.home() / "sandbox/android-corpus/tier3-frameworks/com.blint.rnhello_1.apk"
    from blint.lib.android import scan_hermes_bundles
    from blint.lib.binary import parse

    bundles = scan_hermes_bundles(str(apk))
    assert bundles == [{"member": "assets/index.android.bundle", "bytecode_version": 96}]

    with tempfile.TemporaryDirectory() as tmp:
        with zipfile.ZipFile(apk) as z:
            hermes = z.read("lib/arm64-v8a/libhermes.so")
            fbjni = z.read("lib/arm64-v8a/libfbjni.so")
        hermes_path = os.path.join(tmp, "libhermes.so")
        fbjni_path = os.path.join(tmp, "libfbjni.so")
        Path(hermes_path).write_bytes(hermes)
        Path(fbjni_path).write_bytes(fbjni)

        hermes_meta = parse(hermes_path)
        assert [(r["framework"], r.get("version"))
                for r in hermes_meta.get("frameworks") or []] == [("hermes-android", "0.76.9")]
        fbjni_meta = parse(fbjni_path)
        assert [r["framework"] for r in fbjni_meta.get("frameworks") or []] == ["fbjni"]


def test_r1_nss_identifies_from_versioncheck_plus_the_version_string():
    """Both halves required: the export and the version banner."""
    evidence = _load_evidence("nss")
    blint = evidence["evidence"]["blint_parse"]
    sym = blint["symbol_evidence"]
    assert sym["nss_version_check"]
    strings = blint["string_evidence"]["nss_version"]
    assert strings == ["Version: NSS 3.128"]

    symbols = [{"name": n, "is_exported": True} for n in sym["matched_names"]]
    parsed = _FakeElf(strings=strings)
    records = identify_frameworks(parsed, {"dynamic_symbols": symbols})
    assert [r["framework"] for r in records] == ["nss"]
    assert records[0]["version"] == "3.128"
    name, version, purl = framework_identity(records[0], ["arm64-v8a"])
    assert (name, version) == ("NSS", "3.128")
    assert purl == "pkg:github/nss-dev/nss@3.128?abi=arm64-v8a"

    # The string without the export: no identification.
    records = identify_frameworks(parsed, {"dynamic_symbols": []})
    assert records == []


def test_r1_boringssl_needs_boringssl_only_evidence_and_no_openssl_banner():
    """The platform libcrypto: BORINGSSL_* prefix, no banner - BoringSSL."""
    evidence = _load_evidence("boringssl")
    blint = evidence["evidence"]["blint_parse"]
    sym = blint["symbol_evidence"]
    assert sym["boringssl_prefix"]
    assert not blint["string_evidence"]["openssl_banner"]

    symbols = [{"name": n, "is_exported": True} for n in sym["matched_names"]]
    # llvm-readelf -d on the same api36 libcrypto.so: SONAME libcrypto.so.
    provider = _FakeElf(dynamic_entries=[_Soname("libcrypto.so")])
    records = identify_frameworks(provider, {"dynamic_symbols": symbols})
    assert [r["framework"] for r in records] == ["boringssl"]
    assert "version" not in records[0]
    assert not records[0]["static"] and not records[0]["hint_only"]
    name, version, purl = framework_identity(records[0], ["arm64-v8a"])
    assert (name, version) == ("BoringSSL", "")
    assert purl == "pkg:github/google/boringssl?abi=arm64-v8a"

    # An OpenSSL banner in the same file would rule BoringSSL out.
    parsed = _FakeElf(
        strings=["OpenSSL 3.0.2 15 Mar 2022"], dynamic_entries=[_Soname("libcrypto.so")]
    )
    records = identify_frameworks(parsed, {"dynamic_symbols": symbols})
    assert [r["framework"] for r in records] == ["openssl"]
    assert records[0]["version"] == "3.0.2"


def test_openssl_banner_outside_libcrypto_is_a_static_copy():
    """A library linking OpenSSL carries its banner without being OpenSSL.

    The banner is the one in vcpkg's arm64-android OpenSSL 3.6.2
    libcrypto.so (strings -a; SONAME libcrypto.so from llvm-readelf -d).
    Under that SONAME it replaces; under any other (libcurl linking OpenSSL
    statically) it nests with its version, like a re-exported BoringSSL.
    """
    banner = ["OpenSSL 3.6.2 7 Apr 2026"]
    provider = _FakeElf(strings=banner, dynamic_entries=[_Soname("libcrypto.so")])
    records = identify_frameworks(provider, {"dynamic_symbols": []})
    assert [(r["framework"], r["version"], r["static"]) for r in records] == [
        ("openssl", "3.6.2", False)
    ]
    versioned = _FakeElf(strings=banner, dynamic_entries=[_Soname("libcrypto.so.3")])
    assert not identify_frameworks(versioned, {"dynamic_symbols": []})[0]["static"]
    host = _FakeElf(strings=banner, dynamic_entries=[_Soname("libcurl.so")])
    records = identify_frameworks(host, {"dynamic_symbols": []})
    assert [(r["framework"], r["version"], r["static"]) for r in records] == [
        ("openssl", "3.6.2", True)
    ]


def test_r1_boringssl_inside_the_flutter_engine_nests():
    """A statically linked copy is an identification inside the host."""
    evidence = _load_evidence("flutter-engine")
    blint = evidence["evidence"]["blint_parse"]
    strings = blint["string_evidence"]
    symbols = [
        {"name": n, "is_exported": True} for n in blint["symbol_evidence"]["matched_names"]
    ]
    parsed = _FakeElf(
        strings=strings["dart_vm_version"] + strings["hex40_bare"]
        + ["../../../flutter/third_party/boringssl/src/crypto/mem_internal.c"]
    )
    records = identify_frameworks(parsed, {"dynamic_symbols": symbols})
    assert [r["framework"] for r in records] == ["flutter-engine"]
    nested = records[0].get("nested") or []
    assert [n["framework"] for n in nested] == ["dart-sdk", "boringssl"]
    # The nested copy never becomes a second top-level component.
    assert not any(r["framework"] == "boringssl" for r in records)
    # And the nested table builds its child identity.
    from blint.lib.framework_ident import NESTED_COMPONENTS

    assert "boringssl" in NESTED_COMPONENTS


def test_r1_vlc_identifies_from_the_release_string():
    evidence = _load_evidence("vlc")
    blint = evidence["evidence"]["blint_parse"]
    strings = blint["string_evidence"]
    assert strings["vlc_version"] == ["VLC 3.0.23"]
    parsed = _FakeElf(strings=strings["vlc_version"])
    records = identify_frameworks(parsed, {"dynamic_symbols": []})
    assert [r["framework"] for r in records] == ["vlc"]
    assert records[0]["version"] == "3.0.23"
    name, version, purl = framework_identity(records[0], ["x86_64"])
    assert (name, version) == ("libvlc", "3.0.23")
    assert purl == "pkg:github/videolan/vlc@3.0.23?abi=x86_64"


def test_r1_qt_identifies_from_qt_version_str():
    evidence = _load_evidence("qt")
    blint = evidence["evidence"]["blint_parse"]
    strings = blint["string_evidence"]
    assert strings["qt_version"], "the QT_VERSION_STR string must be recorded"
    parsed = _FakeElf(strings=strings["qt_version"])
    records = identify_frameworks(parsed, {"dynamic_symbols": []})
    assert [r["framework"] for r in records] == ["qt"]
    assert records[0]["version"] == "5.15.15"
    name, version, purl = framework_identity(records[0], ["arm64-v8a"])
    assert (name, version) == ("Qt", "5.15.15")
    assert purl == "pkg:github/qt/qtbase@5.15.15?abi=arm64-v8a"


@pytest.mark.skipif(
    not (Path.home() / "sandbox/android-corpus/tier2-fdroid").exists(),
    reason="corpus not present on this machine (the corpus is never committed)",
)
def test_r2_corpus_vlc_and_qt_identify_with_versions():
    """The real VLC and Qt5 libraries, parsed for real."""
    import os
    import tempfile
    import zipfile

    from blint.lib.binary import parse

    with tempfile.TemporaryDirectory() as tmp:
        with zipfile.ZipFile(
            Path.home()
            / "sandbox/android-corpus/tier2-fdroid/org.videolan.vlc_13070108.apk"
        ) as z:
            libvlc_path = os.path.join(tmp, "libvlc.so")
            Path(libvlc_path).write_bytes(z.read("lib/x86_64/libvlc.so"))
        with zipfile.ZipFile(
            Path.home()
            / "sandbox/android-corpus/tier2-fdroid/net.osmand.plus_540403.apk"
        ) as z:
            qt_path = os.path.join(tmp, "libQt5Core.so")
            Path(qt_path).write_bytes(z.read("lib/arm64-v8a/libQt5Core.so"))

        vlc_meta = parse(libvlc_path)
        assert [(r["framework"], r.get("version"))
                for r in vlc_meta.get("frameworks") or []] == [("vlc", "3.0.23")]
        qt_meta = parse(qt_path)
        assert [(r["framework"], r.get("version"))
                for r in qt_meta.get("frameworks") or []] == [("qt", "5.15.15")]


def test_r3_regression_string_only_boringssl_never_replaces_its_host():
    """A corpus sweep caught this: element v7a's libjingle (WebRTC) bundles BoringSSL.

    The vendored-path strings leaked from the static copy, and the first
    cut of the detector replaced the host's identity - WebRTC labelled as
    BoringSSL. Replace-grade requires the BORINGSSL_* exported prefix; a
    string-only hit is hint_only and keeps the host's identity.
    """
    metadata = {
        "dynamic_symbols": [
            {"name": "Java_org_webrtc_PeerConnectionFactory_nativeFoo",
             "is_exported": True},
        ],
    }
    parsed = _FakeElf(
        strings=["../../third_party/boringssl/src/ssl/internal.h"]
    )
    records = identify_frameworks(parsed, metadata)
    assert [r["framework"] for r in records] == ["boringssl"]
    assert records[0]["hint_only"] is True
    # hint-only records never reach the component table.
    assert framework_identity(records[0], ["armeabi-v7a"]) is None

    # The platform provider shape: exports the BORINGSSL_* prefix under a
    # libcrypto SONAME and so replace-grades.
    metadata["dynamic_symbols"].append({"name": "BORINGSSL_keccak", "is_exported": True})
    parsed.dynamic_entries = [_Soname("libcrypto.so")]
    records = identify_frameworks(parsed, metadata)
    assert records[0].get("hint_only") is not True
    assert framework_identity(records[0], ["arm64-v8a"])[0] == "BoringSSL"


def test_boringssl_exports_under_another_soname_are_a_static_copy():
    """AOSP's NNAPI sample SL driver re-exports BORINGSSL_self_test.

    llvm-nm -D --defined-only on the api35 neuralnetworks APEX's
    neuralnetworks_sample_sl_driver_prebuilt.so lists BORINGSSL_self_test;
    llvm-readelf -d gives SONAME neuralnetworks_sample_sl_driver_prebuilt.so.
    The driver links BoringSSL but is not BoringSSL: the record nests,
    never replacing the driver's identity.
    """
    from blint.lib.android import _nested_framework_components

    metadata = {"dynamic_symbols": [{"name": "BORINGSSL_self_test", "is_exported": True}]}
    parsed = _FakeElf(
        dynamic_entries=[_Soname("neuralnetworks_sample_sl_driver_prebuilt.so")]
    )
    records = identify_frameworks(parsed, metadata)
    assert [(r["framework"], r["static"], r["hint_only"]) for r in records] == [
        ("boringssl", True, False)
    ]
    host = "pkg:android/neuralnetworks_sample_sl_driver_prebuilt.so?abi=arm64-v8a"
    children = _nested_framework_components(records, ["arm64-v8a"], host)
    assert [c.purl for c in children] == ["pkg:github/google/boringssl?abi=arm64-v8a"]
    # Scoped by the host, so two hosts with the same static copy never share a ref.
    assert children[0].bom_ref.root == f"{host}|pkg:github/google/boringssl?abi=arm64-v8a"


def test_nss_needs_the_export_not_an_import():
    """A library importing NSS_VersionCheck is a consumer, not NSS."""
    parsed = _FakeElf(strings=["Version: NSS 3.128"])
    imported = {"name": "NSS_VersionCheck", "is_exported": False, "is_imported": True}
    assert identify_frameworks(parsed, {"dynamic_symbols": [imported]}) == []


def test_ossl_namespace_names_a_bannerless_openssl3_static_copy():
    """realm-core's OpenSSL 3 inside librealm-jni.so, by ossl_*.

    The names are llvm-nm's, from the committed openssl3 evidence:
    librealm-jni.so exports 1,618 ossl_* names and no OPENSSL_VERSION_TEXT
    banner (banner-based identification left it unidentified for exactly that reason). The record
    nests in the host, versionless.
    """
    from blint.lib.android import _nested_framework_components

    evidence = json.loads(
        (EVIDENCE_DIR / "openssl3-evidence.json").read_text(encoding="utf-8")
    )
    assert evidence["boringssl_libcrypto_ossl_count"] == 0
    names = evidence["realm_ossl_sample"]
    assert len(names) >= 10 and all(n.startswith("ossl_") for n in names)
    symbols = [{"name": n, "is_exported": True} for n in names]
    parsed = _FakeElf(dynamic_entries=[_Soname("librealm-jni.so")])
    records = identify_frameworks(parsed, {"dynamic_symbols": symbols})
    assert [(r["framework"], r["static"]) for r in records] == [("openssl", True)]
    assert "version" not in records[0]
    assert any("ossl_*" in e["what"] for e in records[0]["evidence"])
    host = "pkg:android/librealm-jni.so?abi=arm64-v8a"
    children = _nested_framework_components(records, ["arm64-v8a"], host)
    assert [c.purl for c in children] == ["pkg:github/openssl/openssl?abi=arm64-v8a"]
    assert children[0].bom_ref.root == f"{host}|pkg:github/openssl/openssl?abi=arm64-v8a"


def test_ossl_namespace_never_fires_on_boringssl_builds():
    """The tier-0 BoringSSL libcrypto.so exports zero ossl_* names.

    The names are llvm-nm's from the api36 system image's libcrypto.so
    (committed openssl3 evidence): the BORINGSSL_* provider surface and no
    OpenSSL 3 namespace, so the file stays BoringSSL and never becomes an
    OpenSSL match.
    """
    evidence = json.loads(
        (EVIDENCE_DIR / "openssl3-evidence.json").read_text(encoding="utf-8")
    )
    boring = evidence["boringssl_libcrypto_boringssl_exports"]
    assert boring and all(n.startswith("BORINGSSL_") for n in boring)
    symbols = [{"name": n, "is_exported": True} for n in boring]
    provider = _FakeElf(dynamic_entries=[_Soname("libcrypto.so")])
    records = identify_frameworks(provider, {"dynamic_symbols": symbols})
    assert [r["framework"] for r in records] == ["boringssl"]
    assert not any(r["framework"] == "openssl" for r in records)


def test_blintdb_openssl_match_is_dropped_when_boringssl_is_identified():
    """The BoringSSL framework record wins for the same bytes.

    A blintdb openssl port match on a library whose framework record says
    BoringSSL (any grade) is dropped and counted, so the platform's
    libcrypto.so never becomes an OpenSSL component.
    """
    from blint.lib.android_blintdb import superseded_by_framework

    records = [{"project": "openssl", "project_purl": "pkg:generic/openssl@3.6.2"}]
    for grade in ({"framework": "boringssl", "static": False, "hint_only": False},
                  {"framework": "boringssl", "static": True, "hint_only": False},
                  {"framework": "boringssl", "static": False, "hint_only": True}):
        kept, dropped = superseded_by_framework(records, {grade["framework"]})
        assert not kept and dropped == ["boringssl:openssl"]
