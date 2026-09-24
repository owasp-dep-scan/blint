# Android native lane — SDK setup and corpus tooling (A0)

Working copies of the reviewer-owned scripts in `~/blint-android-native-plans/scripts/`;
the proposal form of each script is in its A0 commit body.

## A0.1 tool record (2026-09-24, this machine)

Everything installed under `~/Android/sdk` in user space by
`setup_android_sdk.sh` — no sudo, no Homebrew casks. The pre-existing
`~/Library/Android/sdk` was left untouched.

| Component | Version |
|---|---|
| command-line tools | build `15641748` (`sdkmanager`/`avdmanager`) |
| platform-tools (adb) | 37.0.1-15733141 |
| build-tools | 36.0.0 (aapt2 2.20-13193326) |
| emulator | 37.1.11.0 (build 15917651) |
| platforms | android-34 (rev 3), android-35 (rev 2), android-36 (rev 2) |
| NDK r27 line | 27.3.13750724 |
| NDK r28 line | 28.2.13676358 |
| system images | google_apis (non-Play, rootable), rev 7-14: API 34/35/36 × arm64-v8a + x86_64 |
| Java (already present) | Temurin 26.0.2+10 |

Both NDK toolchains are `darwin-x86_64` builds (the NDK does not ship
`darwin-arm64` binaries); they run under Rosetta on this Apple Silicon host,
verified: `ndk-build --version` (GNU Make 4.3) and `llvm-readelf --version`
both execute. Both NDKs ship riscv64 compilers
(`riscv64-linux-android*-clang` present).

AVDs (created by the script): `a0-api{34,35,36}-{arm64-v8a,x86_64}`, device
`pixel_6`.

### Boot proof

`a0-api36-arm64-v8a`, headless
(`emulator -avd a0-api36-arm64-v8a -no-window -no-audio -no-boot-anim
-no-snapshot -wipe-data -gpu swiftshader_indirect`):

- `sys.boot_completed` = 1 after ~20 s.
- `adb root` → `id` = `uid=0(root) ... context=u:r:su:s0`.
- `getprop ro.build.version.sdk` = 36; fingerprint
  `google/sdk_gphone64_arm64/emu64a:16/BE2A.250530.026.F3/13894323:userdebug/dev-keys`
  (google_apis images are `userdebug`, which is what makes `adb root` work).
- `/apex` and `/vendor/lib64` are readable as root — the tier-0 gaps in the
  seed corpus.

### x86_64 images cannot boot on this machine

`a0-api36-x86_64` fails immediately:

```
FATAL | Avd's CPU Architecture 'x86_64' is not supported by the QEMU2
emulator on aarch64 host. System image must match the host architecture.
```

(emulator 37.1.11 does not emulate x86_64 guests on ARM hosts, accelerated
or otherwise.) The x86_64 images are installed and their contents are
reached statically instead: `system.img` is a GPT disk with an Android
`super` partition holding EROFS logical partitions, so tier-0 x86_64 files
are extracted by parsing the liblp metadata and loop-mounting the logical
partitions inside the running arm64 emulator (see
`build_android_corpus.py tier0-x86`), with `adb root` there. This is stated
in the A0.2 commit with the extraction log.

## Scripts

| File | Purpose |
|---|---|
| `setup_android_sdk.sh` | idempotent SDK/NDK/AVD install under `~/Android/sdk` |
| `build_android_corpus.sh` / `build_android_corpus.py` | tier 0 (emulator pulls), tier 1 (NDK planted variants + real APK packaging), tier 4 (hostile) |
| `jni_sources/` | tier-1 planted-variant sources; built by the real NDK, every flag is the expected fact |
| `make_hostile_fixtures.py` | tier-4 hostile inputs; each shape names the spec it is built to |
| `baseline_android.py` | A0.3 baseline: SBOM components/build-id versions, standalone .so findings per rule/ABI, `--disassemble` functions per ABI |

## A0.2 corpus results (2026-09-24)

| Tier | Collected | Notes |
|---|---|---|
| 0 arm64 | API 34/35/36 × {`/apex` (~280 MB), `/system/lib64` (~200 MB), `/vendor/lib64` (~80 MB)} via `adb root` | 1398-1541 ELF files per image; `_system_lib`/`_vendor_lib` are empty because the arm64-only images ship no 32-bit libs |
| 0 x86_64 | **not collected** | images cannot boot on ARM64 hosts (A0.1) and static extraction is blocked — see the `tier0_extract_x86` docstring and the A0.2 commit |
| 1 NDK | 122 files: 5 ABIs (incl. riscv64) × r27/r28 × {hello, page4k, page16k, textrels, static, + hwasan/memtag/bti on arm64}, stripped + unstripped, 9 APKs + 1 multi-ABI xapk | every planted fact verified with `llvm-readelf` from the same NDK in the same run; r27 defaults to 4 KiB LOAD alignment, r28 to 16 KiB |
| 2 F-Droid | seed (26 APKs) unchanged, per the prompt | — |
| 3 frameworks | React Native 0.76.9 hello app built locally (`com.blint.rnhello_1.apk`, 4 ABIs, Hermes) | Unity: no Unity editor/licence on this machine — not collected. .NET: `dotnet workload install` needs elevation on this machine (root-owned SDK manifest at /usr/local/share/dotnet, and `--to-path` still requires it) — not collected, no sudo available |
| 4 hostile | 9 fixtures, generated from a real NDK `libhello.so` base | the ≤100 KB subset is committed under `tests/data/android/` |

