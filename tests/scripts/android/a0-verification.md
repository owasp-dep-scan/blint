# A0.3 — V1-V15 re-verification and baseline (blint @ a93880e, 2026-09-24)

Every item re-verified on this machine against `a93880e` (the FP lane's
merge commit). "Confirmed" means the command reproduced the finding;
"corrected" entries note what the FP lane already changed.

| # | Verdict | Evidence (command → output, abridged) |
|---|---|---|
| V1 | confirmed | `blint sbom -i /tmp/v12-loose.apk` (apk with `libroot.so`, `assets/arm64-v8a/libfake.so`, `res/raw/libweird.so`, `res/lib/x86_64/libmisplaced.so`) → components emitted for **all five** placements (`internal:srcFile` shows each); the apk is fully unzipped to a temp dir by `collect_files_metadata` (`android.py:884-885`, `unzip_unsafe` = `extractall`). |
| V2 | confirmed | same run: `assets/arm64-v8a/libfake.so` → `?arch=arm64-v8a`; `libroot.so` (root) → an `arch` qualifier too (the loose `"lib" in rel_path` split); `res/lib/x86_64/libmisplaced.so` → **no** arch (nested lib/ missed). |
| V3 | confirmed | `parse()` on tier-1 `libhello.so` yields relro=full/has_canary/is_pie/has_nx/elf_type=DYN; the SBOM component keeps only name/version(functions)/srcFile/appFile/functions — every hardening fact is discarded in `parse_so_file`. |
| V4 | confirmed | SBOM over 26 seed tier-2 APKs: **242 .so components, 203 carry a hex build-id as `version`** (84%); e.g. `pkg:android/organicmaps@459d0badf12c80ad55828c3f24b227c1f9de768a?arch=`. |
| V5 | confirmed | `pkg:android/c++_shared@...` (unencoded `+`), no namespace, near-duplicate components per ABI/split (saber: 6 components × 3 per-ABI APKs). |
| V6 | confirmed | seed sbom `dependencies` carries app→each-.so edges (e.g. organicmaps: app dependsOn all 4 lib purls); in the stub-manifest run the dependency list degenerates to per-component entries. |
| V7 | confirmed | `blint -i tier1_no_dex.apk` (real apksigned apk, stored `lib/arm64-v8a/libhello.so`, no dex) → `analysis-coverage.json`: `skipped [{"reason": "no_dex_bytecode"}]`. |
| V8 | confirmed | tier-1 `libhello.so` metadata: `is_targeting_android=True`, notes `ANDROID_IDENT` + `GNU_BUILD_ID`, `relro=full`, `has_canary=True`, `has_nx=True`, `llvm_target_tuple=aarch64-unknown-linux-android`. |
| V9 | confirmed | On the *planted* variants: `libhello_bti.so` (readelf: `aarch64 feature: BTI, PAC`), `libhello_memtag.so` (readelf: `NT_ANDROID_TYPE_MEMTAG Stack: Enabled`), `libhello_page16k.so` (readelf: LOAD `Align 0x4000`) — none of these decoded facts appear in metadata (the strings that do appear come from disassembled `bti c` instructions, not from a property parse; `16384`/align facts absent everywhere). Also absent: DT_ANDROID_REL[A], DT_RELR, SHT_ANDROID_*, shadow-call-stack, HWASan, FORTIFY. |
| V10 | confirmed | Functions list carries `JNI_OnLoad`, `Java_com_example_..._stringFromJNI` as plain names; no JNI decoding/linkage; dex side has only `ANDROID_NATIVE_EXEC` (`review_methods_android.yml`). |
| V11 | confirmed | `_to_nyxstone_triple('aarch64-unknown-linux-android')` → unchanged; no Thumb handling — on unstripped v7a `libhello.so`, 10 FUNC symbols (llvm-readelf) → 12 "functions" (mis-split at Thumb symbol addresses), vs 8/10 on arm64 (see functions table below). |
| V12 | confirmed, two already fixed by the FP lane | Standalone tier-0 scans today fire: CHECK_CANARY (92-183/image), CHECK_LIBC_PORTABILITY (84-126/image, driven by `__register_atfork` which bionic also exports), CHECK_RUNTIME_LOADING (30-73/image, real dlopen imports per llvm-readelf), CHECK_PACKED (2-6), CHECK_RPATH (1). **CHECK_ABI_FLOOR no longer fires on bionic** (`check_abi_floor` returns True for libc=bionic — FP lane fix, confirmed by its absence from every tier-0 histogram); **CHECK_RUNTIME_LOADING now requires an imported loader** (confirmed: every tier-0 hit imports `dlopen@LIBC`). The glibc runtime tag (`construct_binary_composition`: `"libc.so" in needed → glibc`) still misfires on bionic — `runtimes: ["glibc"]` on tier-1 libs. |
| V13 | confirmed | RN hello app sbom: all 40 libs are generic `pkg:android/<stripped-name>` components; no framework identification. |
| V14 | corrected | `tests/test_android.py` is manifest/dex-only (10 tests, no .so/APK fixture) — confirmed. But the callgraph KPI baseline has **seven** entries today (`wasm-tools-1.247.0-baseline.json`: aarch64-{apple-macosx,pc-windows-msvc,unknown-linux-gnu}, x86_64-{apple-macosx,pc-windows-msvc,unknown-linux-gnu}, riscv64-unknown-linux-gnu) while the **labels file has five** (riscv64 and x86_64-apple-macosx labels are missing) — the plan's "6 entries" is stale and the two files disagree; noted for the gate block. |
| V15 | confirmed | `docs/CUSTOM_PROPERTIES.md` covers app/dex properties only; `docs/METADATA.md` has no android-native section. |

## Baseline (final corpus, this machine)

### SBOM per tier-2 app (26 seed APKs, `blint sbom`)

- 242 `.so` components total; **203 use a build-id as the version** (V4).
- 0 components for `com.termux.api` (dex-only control).
- Largest app (termux, 12 libs): 12 components, 12 build-id versions.

### Standalone .so findings per group (`blint --no-reviews`)

See `/tmp/a0-baseline-final.json` for the full table; abridged medians:

| group | scanned | files with findings | total | median/file | top rules |
|---|---|---|---|---|---|
| tier0/api34-arm64 | 1541 | 276 | 353 | 2 | CANARY 183, LIBC_PORTABILITY 90, RUNTIME_LOADING 73 |
| tier0/api35-arm64 | 1398 | 297 | 360 | 1 | CANARY 156, LIBC_PORTABILITY 126, RUNTIME_LOADING 71 |
| tier0/api36-arm64 | 677+ | 173 | 208 | 1 | CANARY 92, LIBC_PORTABILITY 84, RUNTIME_LOADING 30 |
| tier1 r27/r28 × 5 ABIs | 8-14 each | all | 8-16 | 2-4 | CANARY (all), LIBC_PORTABILITY (riscv64: `__register_atfork`) |

Classification against `llvm-readelf --dyn-syms` (named tool, same run):
- CHECK_CANARY: **true findings** — every sampled file genuinely lacks
  `__stack_chk_fail` (bugreport, cpu-target-features, ...); Google builds
  parts of the system without the stack protector. Medium severity.
- CHECK_LIBC_PORTABILITY: **false positives** — bionic binaries judged by
  the glibc-vs-musl table (`__register_atfork` is bionic-exported too).
- CHECK_RUNTIME_LOADING: **true findings** — real `dlopen@LIBC` imports
  paired with library-name strings (libRS, angle loader, ...).
- CHECK_PACKED (2-6/image): high-entropy sections in media libs —
  plausible-true, needs A2 review before any rule change.
- CHECK_RPATH (1/image): the linker itself; bionic ignores DT_RPATH —
  an A1.2/A3 classification candidate.

### `--disassemble` functions per ABI (unstripped tier-1 libhello.so)

| ABI | disassembled | symtab FUNC (llvm-readelf) |
|---|---|---|
| arm64-v8a | 8 | 10 |
| armeabi-v7a | 12 | 10 (mis-split; no Thumb st_value&1 handling) |
| x86_64 | 8 | 10 |
| x86 | 8 | 10 |
| riscv64 | 9 | 12 |

armeabi-v7a's shortfall takes the opposite sign at this fixture size
(over-split rather than under-cover) — the Thumb defect is real (V11);
its cost on large symbolised libraries is A4's measurement.
