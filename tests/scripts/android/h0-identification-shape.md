# H0 — how an `apk-so-member` becomes an SBOM component today, and the
# proposed shape for identified frameworks (04/B, ground rule 38)

Status: inventory + proposal. **No detector ships in this packet** — the
H1-H5 packets implement the table below one framework at a time.

## 1. Today's shape (recorded against `main` @ c0fe93e)

An APK's native libraries reach the SBOM through
`blint/lib/android.py::collect_so_files_metadata`:

1. `scan_android_native` (the A1.1 in-place zip reader) yields every
   `lib/<abi>/*.so` as a library record with its locations.
2. Each library is `parse()`d once (deduped by content sha256).
3. `so_metadata["notes"]` are split by `_so_version_and_build_id`: a note
   version counts only when it is not a bare hex digest; the build-id never
   masquerades as a version (V4).
4. Libraries are grouped by `(file name, version)` — one component per pair
   with the ABIs folded into the purl qualifier, so a five-ABI app is one
   component with five evidence lines.
5. The component: `type=library`, `name=<file name>`, `version=<note
   version or None>`, `purl=pkg:android/<name>@<version>?abi=<abis>`
   (built with PackageURL; V5 keeps the `lib` prefix so `libapp` and
   `libdata` stop colliding), `scope=required`, `evidence=identity` on the
   first srcFile at confidence 0.6, `bom_ref = RefType(purl)`.
6. Properties: `internal:srcFile`, `internal:appFile`, `internal:abis`,
   `internal:functions` (delimiter-joined exported names),
   `blint:build_id` (per ABI), `blint:platform_needed` (DT_NEEDED platform
   libraries — recorded on the needing component, never emitted as
   components).
7. `bom_ref` stability: derived from the purl, which is derived from
   `(name, version, abis)` — deterministic for the same input.

Consequence for identification: today **every** framework library ships as
`pkg:android/lib<name>.so` with either no version (V4's 84%) or a note
version that says nothing about the project (an NDK r26b note says nothing
about React Native). Nothing in the SBOM names Flutter, React Native,
BoringSSL, NSS, VLC or Qt.

## 2. Proposed shape for an identified framework

Rule 38: a component is emitted only from a version-bearing string, symbol
set or header that is named in the implementing commit; a file name alone
is a hint property, never a component. The proposal, per framework record
produced by `parse()` under `metadata["frameworks"]`:

    {
      "framework": "react-native",
      "version": "0.76.9",
      "static": false,
      "evidence": [
        {"what": "HERMES_RELEASE_VERSION string", "where": "strings",
         "value": "for RN 0.76.9"}
      ],
      "hints": [],
      "nested": [ ... static identifications inside this host ... ]
    }

SBOM mapping:

- **Replace vs nest.** When the whole `.so` file *is* the framework
  artifact (libc++_shared.so, libflutter.so, libhermes.so, libfbjni.so,
  libnss3.so, libcrypto.so, libvlc.so, libQt5Core.so), the framework
  component **replaces** the generic `pkg:android/lib<name>.so` component:
  the file is the distribution unit of the project, and emitting both would
  double-count the same bytes. The component-count gate (A1.3: never larger
  than today for a single-ABI app) is preserved because it is 1:1. The
  file's provenance properties (`internal:srcFile`, `internal:abis`,
  `blint:build_id`) ride on the framework component unchanged, and the file
  name becomes a `blint:hint:file_name` property. When the framework is
  statically linked *inside* a host library (the Dart VM and BoringSSL
  inside libflutter.so), the identification **nests**: it becomes a child
  component of the host (`component.components`), never a second copy of
  the host.
- **purl type per framework** (justifications below): `pkg:generic` where
  no ecosystem type exists, `pkg:github` where the project's published
  repository is the identity, `pkg:npm` where the project's release
  versions live on npm.
- **Version**: only from the named evidence. A detector that cannot map
  its evidence to a published version emits a versionless component with
  the hashes as properties (never a guessed version).
- **Evidence**: one `cdx:blint:identification:evidence` property per
  evidence entry, value `<what> (<where>): <value>` — auditable against
  the bytes without re-parsing.
- **bom_ref stability**: derived from the framework purl + abi qualifier,
  deterministic for the same input, exactly as today.

App-level facts (per ABI, on the parent application component as
properties): `blint:ndk_versions` — the distinct `.note.android.ident` NDK
versions observed per ABI (the NDK version dates every NDK-built library in
that ABI); `blint:hermes_bytecode_version` — the Hermes bytecode header
version of the app's bundles.

## 3. The framework table (confirmed on the corpus — H1-H5 implement these)

| framework | component purl | replaces/nests | version evidence (named in the implementing commit) | corpus confirmation |
|---|---|---|---|---|
| ndk-libcxx | `pkg:generic/android-ndk/libcxx@<ndk version>` | replaces libc++_shared.so | `.note.android.ident` NDK version + build number, `std::__ndk1` namespace, and the exported `operator new`/`operator delete` only the shared C++ runtime defines | RnHello arm64 libc++_shared.so: r26-canary / 9891494; see `tests/data/android/ndk-libcxx-evidence.json` |
| flutter-engine | `pkg:github/flutter/flutter` (no version) | replaces libflutter.so; nests dart-sdk and boringssl | `InternalFlutterGpu_*` exports + embedded Dart VM; bare 40-hex revision strings reported as hashes only (the engine's `shell/version/BUILD.gn` names the four slots: FLUTTER_ENGINE_VERSION, FLUTTER_CONTENT_HASH, SKIA_VERSION, DART_VERSION — no published table maps them to releases at scan time) | localsend arm64 libflutter.so: Dart 3.11.5 string + 2 bare hashes; saber (a second Flutter build) carries no hashes — absence handled; see `flutter-engine-evidence.json` |
| dart-sdk (nested) | `pkg:github/dart-lang/sdk@<version>` | nests inside flutter-engine | Dart VM version string `X.Y.Z (channel) (date) on "target"` (dart-lang/sdk `runtime/vm/version_in.cc` str_ template) | localsend libflutter.so: `3.11.5 (stable) (Wed Apr 15 00:36:32 2026 -0700) on "android_arm64"` |
| dart-aot-snapshot | **no component** — hint property only | — | `_kDart*Snapshot*` exports + the 32-hex snapshot version hash (dart-lang/sdk `tools/make_version.py` `MakeSnapshotHashString`); no published hash→version table, so the hash is reported only | localsend libapp.so: hash `78da37fe...`, see `flutter-app-evidence.json` |
| react-native | `pkg:npm/react-native@<version>` | replaces the .so whose strings carry the evidence (libhermes.so) | `for RN X.Y.Z` string — RN's own build stamp: `ReactAndroid/hermes-engine/build.gradle.kts` sets `-DHERMES_RELEASE_VERSION=for RN ${version}`, compiled in by hermes' CMakeLists | RnHello (4 ABIs) and element (4 ABIs) libhermes.so: `for RN 0.76.9` |
| hermes (bytecode) | **no component** — app-level fact | — | the hbc header: magic `0x1F1903C103BC1FC6` then u32 `BYTECODE_VERSION` (`include/hermes/BCGen/HBC/BytecodeVersion.h`, `BytecodeFileFormat.h`) | RnHello `assets/index.android.bundle`: magic ok, version 96 |
| fbjni | `pkg:github/facebook/fbjni` (no version) | replaces libfbjni.so | the `fbjni is uninitialized; no thread can be attached.` runtime string (only fbjni's own TUs define it) + the `facebook::jni::` symbol namespace | RnHello arm64 libfbjni.so; see `fbjni-evidence.json` |
| boringssl | `pkg:github/google/boringssl` (no version) | replaces platform libcrypto.so; nests inside flutter-engine; HINT on hosts that merely bundle it (element's libjingle/WebRTC) | absence of the OpenSSL banner + BoringSSL-only evidence named in the implementing commit: replace-grade needs the `BORINGSSL_*` EXPORTED prefix (the provider's own surface); vendored-path strings alone (`third_party/boringssl/`) are hint-only - a library that bundles BoringSSL statically keeps hidden visibility and its own identity (the R3 sweep caught the first cut mislabelling WebRTC as BoringSSL) | api36 platform libcrypto.so (`BORINGSSL_*` exports, no banner); vendored paths inside localsend libflutter.so (nested) and element's libjingle (hint); see `boringssl-evidence.json` |
| openssl | `pkg:github/openssl/openssl@<version>` | replaces the .so | `OPENSSL_VERSION_TEXT` banner `OpenSSL X.Y.Z <date>` + `OPENSSL_x.y.z` symbol versions (elf_abi.py reads the latter) | **no OpenSSL-bearing library in the corpus** — expected identifications: zero; the detector still ships so the absence is a verified negative |
| nss | `pkg:github/nss-dev/nss@<version>` | replaces libnss3.so | `NSS_VersionCheck` export + `Version: NSS X.Y.Z` string | fennec arm64 libnss3.so: 3.128; see `nss-evidence.json` |
| vlc | `pkg:github/videolan/vlc@<version>` | replaces libvlc.so | `VLC X.Y.Z` release string | vlc x86_64 libvlc.so: 3.0.23 (`3.0.23 Vetinari` codename form also present); see `vlc-evidence.json` |
| qt | `pkg:github/qt/qtbase@<version>` | replaces libQt5Core.so | `QT_VERSION_STR` string `Qt X.Y.Z (build info)` | osmand arm64 libQt5Core.so: 5.15.15; see `qt-evidence.json` |

purl justifications: the purl spec has no NDK/Qt/VLC type; `generic` is its
documented fallback (namespace `android-ndk` groups the NDK components).
`github` names the project's published repository — for flutter-engine the
engine source and the embedded revision strings both live in flutter/flutter
since the 2025 monorepo merge; dart-lang/sdk, facebook/fbjni, nss-dev/nss
(the project's public mirror), openssl/openssl, videolan/vlc (mirror of the
release tags) and qt/qtbase (mirror of code.qt.io) are the upstream
identities of each artifact. `npm` is where react-native's release versions
are published and consumed.

Out of scope, with the corpus they need (04/B): Unity/IL2CPP
(`libunity.so` + `libil2cpp.so` + `global-metadata.dat`) and Mono/.NET
(`libmonosgen-2.0.so`, `libmonodroid.so`, assembly stores) — the corpus has
neither; a tier-2/tier-3 Unity app and a Xamarin/MAUI app are the missing
selectors.

## 4. The R1 evidence fixtures (committed, rule 39)

`tests/data/android/<framework>-evidence.json`, one per framework, each
holding the detector inputs in the shape `parse()` produces them plus the
llvm oracle read of the same file, the extracting command, the tool
versions and the source member's sha256 (the binaries themselves are never
committed). Regenerate with
`tests/scripts/android/extract_identification_evidence.py`.
