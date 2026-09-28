# H5 — R3 identification sweep results (2026-09-27)

Instrument: `tests/scripts/android/r3_identification_sweep.py` (the same
`parse()` the detectors run inside; APK members read in place). Host:
reviewer Mac, darwin arm64; lief 1.0.0-d05b3499b. Full JSON output
reproducible with the same command; the tables below are the hand-checked
condensation.

## Tier 0 — platform (all four images, 5,295 `.so` files)

**68 identifications, every one BoringSSL, every one hand-checked:**
44 `libcrypto.so` + 4 `libssl.so` (bionic/conscrypt/APEX crypto+TLS) +
3 `libcurl.so` + 3 `system_lib64_libcurl.so` (Android's curl is built
against BoringSSL) + 3 `system_lib64_libcrypto.so` + 2
`vendor_lib64_libcrypto.so` (renames of the same files in the flattened
corpus layout) + 2 `stable_cronet_libcrypto.so` + 2
`stable_cronet_libssl.so` (Chromium's network stack, statically
BoringSSL) + 4 `neuralnetworks_sample_sl_driver_prebuilt.so` + 1
`vendor_lib64_...` twin (AOSP's NNAPI sample SL driver, links
BoringSSL). Spot oracle (same run):
`BORINGSSL_*` exported prefix present, `llvm-readelf -n` shows no
OpenSSL banner. AOSP's platform TLS/crypto is BoringSSL - 68/68 correct,
**zero false identifications**, and the other ~5,227 platform libraries
(no framework evidence) stay unidentified - e.g. `libc.so`, `libutils.so`,
`libhwui.so` produce nothing.

## Tier 2 — F-Droid apps (27 APKs)

| app | identifications | hand check |
|---|---|---|
| saber 1360101-03 (3 ABIs) | flutter-engine (versionless) | plausible: Flutter app; saber has no engine-revision hash strings, identified via symbols + Dart string |
| localsend 641-43 (3 ABIs) | flutter-engine + nested dart-sdk 3.11.5 + nested boringssl; libapp.so hint-only with snapshot hash | plausible: Flutter app; engine hash 42d3d75a resolves to a flutter/flutter commit; Dart 3.11.5 string timestamp matches the published SDK tag time |
| element (im.vector.app) 40106621-24 (4 ABIs) | ndk-libcxx r27-beta1, fbjni, react-native 0.77.2; boringssl as a HINT on libjingle_peerconnection_so.so (WebRTC statically bundles BoringSSL) | plausible: RN-based Element; RN version from the "for RN 0.77.2" build stamp; the r27-beta1 libc++ matches its note |
| osmand 540401-03 (per-ABI) | qt 5.15.15, ndk-libcxx r27-beta1/r25c | plausible: Osmand is Qt-based; QT_VERSION_STR in libQt5Core |
| fennec 1560000/10/20 | nss 3.128 | plausible: NSS_VersionCheck + the version banner in libnss3 |
| vlc 13070105-08 | vlc 3.0.23, ndk-libcxx r21e (v7a/x86) and r27-beta1 (arm64/x86_64) | plausible: VLC 3.0.23 "Vetinari"; the per-ABI NDK split matches VLC's release engineering |
| termux 1022, newpipe 1015, fdroid 2000050, AppManager 451, organicmaps 26082718 | none (only `blint:ndk_versions` app facts) | correct: no framework evidence in their libraries - staying unidentified is the required behaviour |

**zero false identifications.** One defect was caught and fixed by this
gate: the first cut identified element's `libjingle_peerconnection_so.so`
(WebRTC, which statically links BoringSSL and leaks vendored-path strings)
as a BoringSSL *component* - a statically linked copy is a hint on the
host's identity, never a replacement. Replace-grade BoringSSL now requires
the `BORINGSSL_*` exported prefix; the regression test
(`test_r3_regression_string_only_boringssl_never_replaces_its_host`) pins
it.

App facts (25): `blint:ndk_versions` per ABI on every app (e.g. element
carries eight distinct NDK builds across its libraries: r23b, r26b, r27,
r27-beta1, r27b, r28b, r28c, r29); `blint:hermes_bytecode_version=96` on
RnHello.

## Tier 3 — RnHello (`com.blint.rnhello_1.apk`)

| identification | version | evidence |
|---|---|---|
| ndk-libcxx | r26-canary | note + build 9891494 + `std::__ndk1` + operator new exports + SONAME |
| react-native | 0.76.9 | "for RN 0.76.9" in libhermes.so (matches the corpus build record: `npx react-native init` logged "Welcome to React Native 0.76.9!") |
| fbjni | (none) | runtime string + `facebook::jni::` namespace |
| hermes bytecode (app fact) | 96 | hbc magic + version header |

**zero false identifications**: libreactnative.so, libjsi.so,
libappmodules.so, libimagepipeline.so, libnative-*.so all stay
unidentified (they carry an NDK note but not the runtime's own evidence).
