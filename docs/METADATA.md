# Understanding blint's Binary Metadata

## Introduction

blint is a binary analysis tool that examines executable files to extract a wide range of metadata. This document serves as a technical guide for security analysts and reverse engineers who want to understand the JSON output produced by blint.

The primary goal of blint's metadata generation is to act as a "Rosetta Stone" for binary formats. It parses different and often complex structures from ELF, PE, and Mach-O files and presents them in a single, standardized JSON format. This allows for consistent analysis, scripting, and threat hunting across different operating systems and architectures.

This guide details the attributes found in the metadata, their purpose, and the methods blint uses to obtain them, including notable strengths and limitations.

## Core Concepts and Top-Level Attributes

At the highest level, the JSON output contains attributes that identify the binary and provide universally applicable information.

| Attribute             | Description                                                                                                                                                                                                                                                                      | Use Case                                                                                                                           |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `file_path`           | The absolute path to the analyzed binary file on the filesystem.                                                                                                                                                                                                                 | Basic file identification and tracking.                                                                                            |
| `binary_type`         | The format of the binary, such as `ELF`, `PE`, `MachO`, or `WASM`. This is the primary key for interpreting format-specific sections.                                                                                                                                            | Directing further analysis; knowing which format-specific tools to use next.                                                       |
| `hashes`              | A collection of cryptographic hashes for the file, including MD5, SHA1, SHA256, and SHA512.                                                                                                                                                                                      | File identification, malware signature matching, and searching in threat intelligence platforms like VirusTotal.                   |
| `llvm_target_tuple`   | A string constructed to represent the binary's target environment in a format recognized by LLVM. The format is `arch-vendor-os-environment`. For example: `x86_64-pc-win32-msvc` or `mipsel-unknown-linux-muslsf`. This is crucial for accurate disassembly.                    | Configuring disassemblers and decompilers; understanding the intended operating system and ABI.                                    |
| `callgraph`           | Optional compact function-call graph derived from `disassembled_functions` when `--disassemble` is enabled, or converted from the `wasm_tools` call graph for WASM inputs. Includes `nodes`, internal `edges` (with call counts), and unresolved/ambiguous external targets.     | Control-flow triage, function reachability analysis, and quick hotspot detection without parsing full assembly text.               |
| `strings`             | A list of strings extracted from the binary that exhibit high entropy or match patterns for secrets (API keys, private keys, etc.). Non-secret strings are filtered out to reduce noise. Base64-encoded strings are automatically decoded.                                       | Triage for hardcoded credentials, sensitive URLs, or cryptographic material. A primary step in vulnerability and malware analysis. |
| `informative_strings` | Optional list of selected non-secret strings that match stable operational or exploit-triage indicators (for example network stack hooks, raw socket constants, DNS redirection hints, or Windows local-elevation technique markers). Each item includes `value` and `category`. | Capability clustering for behaviors that may be visible in constants or embedded paths rather than symbol tables alone.            |

### Serialization Notes

- Some parser fields can include raw bytes that are not valid UTF-8.
- blint serializes undecodable bytes as hex strings for compatibility with JSON reports.
- To avoid oversized report fields, hex output is capped by `BLINT_MAX_HEX_BYTES` (default: `4096`).
- If capped, the value is emitted as `<hex>...<truncated:N_bytes>` where `N` is the original byte length.
- Set `BLINT_MAX_HEX_BYTES=0` to disable truncation.

---

## Format-Specific Attributes

blint provides detailed information specific to each binary format, normalized where possible.

### For ELF Binaries

ELF (Executable and Linkable Format) files are the standard for Linux, BSD, and many embedded systems.

- **Header Information (`header`):** Contains fundamental properties of the ELF file.
  - `class`: `ELF32` or `ELF64`, indicating a 32-bit or 64-bit binary.
  - `endianness`: `LSB` (Little-Endian) or `MSB` (Big-Endian). Crucial for MIPS and ARM analysis.
  - `identity_os_abi`: The target OS Application Binary Interface (e.g., `LINUX`, `FREEBSD`).
  - `machine_type`: The target CPU architecture (e.g., `AARCH64`, `MIPS`, `X86_64`).

- **Dynamic Entries (`dynamic_entries`):** Lists entries from the `.dynamic` section, which are essential for the dynamic linker.
  - `NEEDED`: Specifies a required shared library (e.g., `libc.so.6`). This is the basis for dependency analysis.
  - `SONAME`: The "shared object name" this binary provides if it's a library.
  - `RPATH`/`RUNPATH`: Library search paths hardcoded into the binary. A common focus for security review, as they can be used for library hijacking.

- **Notes (`notes`):** Contains metadata from `.note` sections.
  - `GNU_BUILD_ID`: A unique hash identifying the specific build, useful for matching the binary with its corresponding debug symbols.
  - `ANDROID_IDENT`: If present, provides Android-specific information like `sdk_version` and `ndk_version`.
  - **`dlopen_dependencies`**: Metadata extracted from the [FDO ELF Note](https://uapi-group.org/specifications/specs/elf_dlopen_metadata/) designed to declare dependencies loaded dynamically at runtime via `dlopen()`.
    - **Context**: Standard binary analysis usually only detects libraries linked at build time (found in `NEEDED` entries). However, many modern applications load plugins, codecs, or optional modules programmatically during execution.
    - **Content**: This attribute parses the embedded JSON note to list these "hidden" dependencies, including the library name (`soname`), its necessity (`required`, `recommended`, or `suggested`), and the specific application feature it enables.
    - **Use Case**: Critical for discovering the full dependency tree of modular applications (like media players or system daemons) that would otherwise appear to have very few dependencies during static analysis.

- **ABI Requirements (`abi_analysis`):** The runtime the binary requires and the ABI features that constrain where it can run. See [`abi_analysis`](#abi_analysis) below.

- **Runtime Loading (`runtime_loading`, `recovered_dependencies`):** Libraries the binary opens at runtime rather than linking against, recovered from the image itself rather than from a declarative note. See [`runtime_loading` and `recovered_dependencies`](#runtime_loading-and-recovered_dependencies) below.

- **Link Closure (`link_closure`, optional):** The result of resolving the dependency graph the way the dynamic loader would. See [`link_closure`](#link_closure) below.

### For PE Binaries

PE (Portable Executable) files are the standard for Windows.

- **Headers (`dos_header`, `header`, `optional_header`):**
  - `machine_type`: The target architecture (e.g., `AMD64`, `I386`).
  - `subsystem`: Indicates whether the application is `WINDOWS_GUI` or `WINDOWS_CUI` (console).
  - `dll_characteristics`: A set of flags indicating security features like `DYNAMIC_BASE` (ASLR) and `CONTROL_FLOW_GUARD`.

- **Load Configuration (`load_configuration`):** This structure is the bridge between the static binary and the OS Loader/Hypervisor security features.
  - `guard_flags`: The raw integer flags indicating various security settings processed by the OS loader.
  - `guard_cf_flags`: List of active Guard features, such as `CF_INSTRUMENTED` (Control Flow Guard) and `RF_INSTRUMENTED` (Return Flow Guard/PAC).
  - `code_integrity`: Configuration for **Hypervisor-Protected Code Integrity (HVCI)**.
    - `flags`: Settings determining how the kernel verifies the digital signature of this binary at runtime.
    - `catalog`: Indicates if the signature is stored in an external catalog file rather than embedded in the binary.
  - `enclave_config`: Metadata for running inside a **Trusted Execution Environment (TEE)**, such as Intel SGX or Windows VBS (Virtualization-based Security) Enclaves.
    - `policy_flags`: Security policies enforced by the enclave (e.g., debugging allowed).
    - `imports`: Specific functions imported by the enclave code from the host process.
  - `volatile_metadata`: Information used by **Virtual Secure Mode (VSM)**.
    - Defines memory ranges that are mutable vs. executable, allowing the Hypervisor to enforce W^X (Write XOR Execute) policies more granularly than standard page tables.
  - `runtime_checks`: A dictionary of specific function pointers present in the binary that correspond to hardware-backed security checks.
    - `guard_rf_verify_stackpointer`: Indicates the binary expects the OS to verify the Stack Pointer using ARM64 PAC keys (Key B).
    - `guard_xfg_check`: Indicates support for Extended Flow Guard (Type-based CFI).
    - `guard_eh_continuation`: Indicates support for Intel CET (Shadow Stack) during exception handling.

- **Authenticode (`authenticode`, `signatures`):** Detailed information about the binary's digital signature.
  - Provides hashes (`authentihash_*`) of the signed content.
  - Extracts information about the signer, including the issuer (`cert_signer`) and serial number. This is vital for trust verification and threat intelligence.

- **Resources (`resources`):** Metadata extracted from the `.rsrc` section.
  - `version_metadata`: Contains key-value pairs like `ProductName`, `CompanyName`, and `FileVersion`. Useful for identifying the software and its origin.
  - `manifest`: The embedded XML application manifest, which controls privileges, dependencies, and UI settings.
- **data_directories, sections, and rich_header**
  - See the official LIEF documentation to learn about these [attributes](https://lief.re/doc/latest/formats/pe/python.html#data-directory).
- **Imports and Exports (`imports`, `exports`):**
  - `imports`: A list of all functions imported from external DLLs, grouped by library. Forms the basis of the `imphash`.
  - `exports`: A list of all functions this binary provides to other executables.
- **Thread Local Storage (TLS) Callbacks:**
  - `tls_callbacks`: List of the callbacks associated with the current TLS. These functions are called before any other functions.
  - `tls_address_index`: The location to receive the TLS index assigned by the loader. This location should be located in a writable section like .data.
  - `tls_sizeof_zero_fill`: Size in bytes of the zeros to be padded after the data specified by data_template.
  - `tls_data_template_len`: Length of the initial content used to initialize TLS data.
  - `tls_characteristics`: The four bits [23:20] describe alignment info. Possible values are those defined as LIEF.IMAGE*SCN_ALIGN*\*, which are also used to describe alignment of section in object files. The other 28 bits are reserved for future use.
  - `tls_section_name`: Section associated with the TLS object (or absent if not linked)
  - `tls_directory_type`: Name of the DataDirectory associated with the TLS object (or absent if not linked)
- **Exceptions (exceptions):** For x86-64 and ARM64 PE binaries, this section provides detailed stack unwinding information extracted from the IMAGE_DIRECTORY_ENTRY_EXCEPTION.
  - Attributes:
    - `rva_start` and `rva_end`: The memory boundaries of the function code.
    - `unwind_info`: metadata including sizeof_prologue, frame_reg (frame pointer register), and flags.
    - `opcodes`: The specific machine instructions (e.g., PUSH_NONVOL, ALLOC_SMALL) used to set up the stack frame.
    - `handler_rva`: The address of the language-specific exception handler (e.g., \_\_C_specific_handler).
  - Use Cases:
    - _Function Discovery in Stripped Binaries_: Even if the symbol table is removed, the Exception Directory must remain valid for the OS to handle crashes. This makes rva_start and rva_end the most reliable way to discover function boundaries in stripped malware or commercial software.
    - _Stack Frame Reconstruction_: By analyzing the opcodes and prologue_size, analysts can reconstruct exactly how the stack is manipulated. This is vital for understanding where local variables are stored and identifying potential buffer overflow conditions.
    - _Anti-Analysis Detection_: Malware sometimes employs custom exception handlers (handler_rva) to obscure control flow or detect debuggers. Identifying non-standard handlers is a key indicator of obfuscation.

- **Embedded cryptography (`crypto_material`):** Recovered from the raw bytes of `.rdata`, `.data`, `.text` and `.rodata`, so it is available without `--disassemble`. Complements the behavioural `CRYPTO_BEHAVIOR` function review, which can say a routine looks like a cipher but not which one.
  - `algorithms`: Sorted list of algorithm names identified from specification-fixed constants.
  - `constants`: One entry per matched constant, with `algorithm`, `constant` (what the bytes are), `section`, `offset` and `confidence`. A 16-byte round-constant table is `high` confidence; a 4-byte polynomial that could occur as an unrelated immediate is `medium`.
  - `permutation_tables`: 256-byte tables holding every byte value exactly once — a substitution box, including a custom or modified one that matches no published constant.
  - `opaque_regions`: Contiguous high-entropy regions that match no known table, with `size`, `entropy`, `section_size` and `section_fraction`. The fraction is what separates an embedded encrypted payload from the certificates and compressed assets that fill a large program's `.rdata`.
  - Note that absence of a constant is not absence of the algorithm: an AES built against AES-NI carries no tables, and mbedTLS with runtime table generation leaves only zero-filled BSS.

- **Stack-built strings (`stack_strings`, requires `--disassemble`):** String literals the binary assembles on its stack from arithmetic rather than storing in a data section. These appear in no other string channel, so without this they are invisible to string scanning, to YARA rules written against literals, and to a reviewer reading the file.
  - Each entry carries `value`, `encoding` (`utf-16le` or `ascii`), the `function` and `address` it was built in, and the `frame` slot.
  - Recovery is a linear forward pass with no control-flow awareness, so a value assembled across a branch or loop may be partial. Treat entries as evidence to confirm against the reconstruction rather than as ground truth.

In the case of ARM64X, a single PE file encapsulates ARM64 and ARM64EC architectures. For `ARM64EC` nested PE binaries, an additional attribute `nested_binary` would contain the information such as `exports`, `exceptions`, `functions`, `ctor_functions`, and `dotnet_dependencies`.

### For Mach-O Binaries

Mach-O files are the standard for macOS, iOS, and other Apple operating systems.

- **Header (`header`):**
  - `cpu_type`: The target architecture (e.g., `ARM64`).
  - `file_type`: Identifies the binary as an `EXECUTABLE`, `DYLIB` (shared library), etc.

- **Load Commands:** Mach-O uses load commands instead of a dynamic section.
  - `libraries`: A list of required dylibs, equivalent to `NEEDED` entries in ELF.
  - `uuid`: A unique identifier for the binary, used by debuggers and crash report symbolication tools.
  - `rpath`: A runtime search path for libraries.
  - `code_signature`: Information about the binary's digital signature, crucial for Apple's security model.

- **Encryption (`is_encrypted`, `encryption_info`):** Derived from `LC_ENCRYPTION_INFO(_64)`. `is_encrypted` is `true` when `crypt_id` is non-zero (FairPlay-protected App Store binaries); developer, ad-hoc, and enterprise builds report `false`. `encryption_info` carries `crypt_id`, `crypt_offset`, and `crypt_size`. An encrypted `__TEXT` segment cannot be meaningfully disassembled without on-device decryption.

- **Objective-C metadata (`objc_metadata`):** Recovered by walking the raw `__objc_*` sections (LIEF's community build does not expose this). Internal pointers are resolved via relocation targets, with a chained-fixup fallback that decodes raw `dyld` chained pointers (validated against mapped section ranges) when no relocation map is present; external class pointers are resolved via the dyld binding table. Present only when the binary contains 64-bit Objective-C metadata (32-bit armv7/i386 layouts are skipped).
  - `class_count`, `protocol_count`, `selector_count`: summary counters.
  - `classes`: each entry has `name`, `superclass` (internal class name or external framework class), `method_count`, `methods` (selector names), and optional `protocols`.
  - `protocols`: declared protocols with their `name` and `methods`.
  - `selectors`: distinct selectors referenced at message-send sites (`__objc_selrefs`).
  - `external_classes`: framework/runtime classes the binary links against (e.g. `CLLocationManager`, `CTTelephonyNetworkInfo`). Selectors and external classes feed the capability review, surfacing iOS privacy capabilities.
  - `method_imps`: recovered method implementations as `{name, address}`, where `name` is the readable `-[Class selector]` form and `address` is the implementation's virtual address. These seed and label the `functions` list (see below) so message handlers are disassembled and named even in stripped binaries.

- **Function recovery (`functions`):** For stripped release builds (the common case for shipped iOS/macOS apps) the symbol table exposes little beyond `__mh_execute_header`. blint augments the function list from the `LC_FUNCTION_STARTS` table — every entry point is recovered, reusing a surviving symbol name when one exists and synthesising a `sub_<address>` name otherwise. Recovered Objective-C implementations then upgrade matching `sub_<address>` entries to their `-[Class selector]` names. This is what allows disassembly and callgraph construction to work on stripped apps.

- **Skipped disassembly (`disassembly_skipped`):** When `--disassemble` is requested for a FairPlay-encrypted binary (`is_encrypted` is `true`), disassembly is skipped and this field is set to `fairplay_encrypted` rather than producing meaningless instructions from the encrypted `__TEXT`.

- **Universal binaries (`is_universal`, `slices`):** A fat (universal) Mach-O contains one image per architecture. blint summarizes _every_ slice, not just the one the generic parser auto-selects. The existing top-level keys (`cpu_type`, `functions`, `security_properties`, …) keep describing the **primary slice** (the first fat entry — the same slice that was analyzed before this field existed, so consumers of those keys see no change); `is_universal` is `true` only for fat inputs, and `slices` carries one lean entry per slice in fat order:
  - `index`, `cpu_type`, `cpu_subtype`, `arch`, `is_primary`: slice identity. `arch` distinguishes `arm64` from `arm64e`, which matters because only arm64e slices get pointer authentication.
  - `security_properties`: the same property set as the top-level block, computed from _this slice's_ bytes. Hardening that differs between slices — a signature present on one slice but not another, PAC only on the arm64e slice — is reported per slice and is never merged into a single optimistic or pessimistic answer.
  - `functions`, `symbols`, `imports`: counters evidencing the slice was really parsed.
  - `is_encrypted`: per-slice FairPlay state (set when the slice's `crypt_id` is non-zero).
    Because the top-level block speaks for the primary slice, a fat input also carries `security_properties_scope: "primary_slice"` and, when the slices do not agree, `security_properties_slice_variance` naming every property they differ on (both mirrored into `analysis_coverage`). `/usr/bin/git` is the case in point: PAC is on its arm64e slice, so the top level has no `pac` key and would otherwise read exactly like a binary checked and found to lack it. Nothing is merged across slices — a merge would have to pick between an optimistic and a pessimistic lie — so the per-slice truth stays in `slices` and the summary states its own scope.

  Disassembly, entropy and string-based reviews run on the primary slice only; slice summaries are metadata-level. A slice whose summary fails is isolated and recorded in [`analysis_coverage`](#analysis_coverage) under `slices` — the file is not aborted.

> **Swift symbols** are demangled automatically (e.g. `Foundation.URL.appendingPathComponent(...)`), including the Mach-O underscore-prefixed manglings (`_$s…`/`_$S…`/`_T0…`) which the bundled demangler recognises directly. When `--disassemble` is enabled, Mach-O imported calls made through `__stubs` and the GOT are resolved to their demangled symbol names, so call sites reference real Foundation/libswiftCore/libc APIs rather than anonymous stubs.

### For iOS/macOS Apps (`.ipa`)

An `.ipa` is a zip archive containing a `Payload/<App>.app/` bundle. blint unpacks it and analyzes every Mach-O it contains — the main executable, embedded frameworks and dylibs (`Frameworks/`), and app extensions (`PlugIns/*.appex`) — each producing its own `*-metadata.json`. The application context from the bundle's `Info.plist` is attached to each binary's metadata.

| Attribute            | Description                                                                                                                                                                                                                                                                                                   |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ios_bundle`         | Bundle context: `bundle_identifier`, `bundle_name`, `bundle_version`, `bundle_build`, `minimum_os_version`, `platform_name`, `application_category`, `role` (`main`/`framework`/`dylib`/`plugin`), `bundle_path`, and the optional `app_transport_security`, `url_schemes`, and privacy keys described below. |
| `bundle_identifier`  | Convenience top-level copy of the app's `CFBundleIdentifier`.                                                                                                                                                                                                                                                 |
| `bundle_version`     | Convenience top-level copy of `CFBundleShortVersionString`.                                                                                                                                                                                                                                                   |
| `minimum_os_version` | Minimum supported OS version from the bundle.                                                                                                                                                                                                                                                                 |

The bundle context can also carry two security-relevant keys parsed from the `Info.plist`:

- `app_transport_security`: present only when the App Transport Security policy weakens the secure default. Carries `allows_arbitrary_loads`, `allows_arbitrary_loads_media`, `allows_arbitrary_loads_web`, and an `insecure_exception_domains` list. For the main executable these are also projected into `informative_strings` as `ATS_*` tokens so the rule engine can flag a weakened transport posture (rule `IOS_INSECURE_TRANSPORT_ATS`).
- `url_schemes`: the custom URL schemes the app registers (`CFBundleURLTypes`), useful as deep-link / inter-app entry points.

The bundle context also carries the app's privacy posture, parsed from the `Info.plist` and the `PrivacyInfo.xcprivacy` privacy manifest(s):

- `privacy_usage_descriptions`: the `NS...UsageDescription` consent-string keys the app declares (e.g. `NSCameraUsageDescription`), indicating the sensitive resources it is provisioned to access.
- `query_schemes`: the `LSApplicationQueriesSchemes` the app can probe via `canOpenURL` to detect other installed apps.
- `bonjour_services`: the `NSBonjourServices` the app browses for on the local network.
- `privacy_manifest`: present when any component ships a `PrivacyInfo.xcprivacy`. Aggregated across the app, embedded frameworks and extensions, it carries `present`, `manifest_count`, `tracking`, `tracking_domains`, `collected_data_types`, and `accessed_api_categories` (the declared "required reason" API categories).

For the main executable these are projected into `informative_strings` as `PRIV_*` tokens (mirroring the `ATS_*` tokens above) so the rule engine can flag the privacy surface — for example `PRIV_NSCameraUsageDescription`, `PRIV_LSApplicationQueriesSchemes`, `PRIV_NSPrivacyTracking`, `PRIV_PrivacyManifestMissing`, and `PRIV_UNDECLARED_<category>` for a required-reason API referenced by the binary without a matching manifest declaration.

Embedded framework and app-extension binaries are additionally enriched with their _own_ `Info.plist` identity (`bundle_identifier`, `bundle_version`) so the SBOM can report the real product version of a bundled dependency rather than inheriting the host app's version.

### For WASM Binaries

WASM (WebAssembly) binaries are parsed via `wasm_tools` and then normalized into blint's common metadata model.

- **Detection:** blint treats a file as WASM when the extension is `.wasm` or the magic bytes are `00 61 73 6d`.
- **Normalization:** blint preserves common cross-format keys (`imports`, `dynamic_entries`, `functions`, `symtab_symbols`, `dynamic_symbols`) so dependency and review workflows continue to work.
- **Raw passthrough export:** the complete parser output is written as a separate report artifact (`*-wasm-report.json`) in the reports directory.

| Attribute                 | Description                                                                                       | Notes                                                                                                                       |
| ------------------------- | ------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `binary_type`             | Set to `WASM`.                                                                                    | Distinguishes the format in downstream logic.                                                                               |
| `exe_type`                | Set to `wasmbinary`.                                                                              | Format hint used by review logic.                                                                                           |
| `machine_type`            | WASM architecture class: `WASM32` or `WASM64`.                                                    | Derived from memory limits (`memories[].limits.is_64`) or the `isa.memory64` capability when the 64-bit memory is imported. |
| `module_version`          | WebAssembly module version from header.                                                           | Usually `1` for core wasm modules.                                                                                          |
| `section_count`           | Number of parsed sections.                                                                        | Mirrors parser report.                                                                                                      |
| `sections`                | Parsed section records (`id`, `name`, `size`, `offset`, etc.).                                    | Format-specific detail for structural analysis.                                                                             |
| `wasm_imports`            | Detailed WASM imports with `module`, `name`, `kind`, `type_index`.                                | Use this for function-level import analysis.                                                                                |
| `imports`                 | Compatibility dependency list.                                                                    | For WASM this is normalized to module-level `{name, tag:"NEEDED"}` entries.                                                 |
| `dynamic_entries`         | Same dependency-style list as `imports`.                                                          | Keeps dependency processing consistent with ELF/PE/Mach-O.                                                                  |
| `exports`                 | WASM exports with `name`, `kind`, `ref_index`.                                                    | Export-level capability and surface analysis.                                                                               |
| `functions`               | Parsed functions mapped to blint shape (`index`, `name`, `address`, `size`, `instruction_count`). | `address` reflects instruction/body offset in wasm bytes.                                                                   |
| `dynamic_symbols`         | Synthetic imported symbol list used by dependency graph logic.                                    | Built from WASM imports; includes `is_imported` markers.                                                                    |
| `symtab_symbols`          | Synthetic exported symbol list used by review logic.                                              | Built from WASM exports; includes `is_exported` markers.                                                                    |
| `wasm_analysis`           | Structured analysis from `wasm_tools` (detections, capabilities, profiles, findings).             | Preserved as provided by parser API.                                                                                        |
| `wasm_errors`             | Parser-reported errors, if any.                                                                   | Non-fatal parse warnings/errors can appear here.                                                                            |
| `is_component`            | `true` when the binary is a Component Model artifact.                                             | Added by blint from the wasm-tools 2.0 report.                                                                              |
| `wasm_toolchain`          | Toolchain fingerprint (`languages`, `processed_by`, `sdks`, `target_features`).                   | Decoded from `producers` / `target_features` custom sections.                                                               |
| `wasm_strings_summary`    | Strings/IoC digest: `detected`, `string_count`, `signals`, `counts`, masked `samples`.            | Summary only; the full string list stays in `*-wasm-report.json`.                                                           |
| `wasm_call_graph_summary` | Call graph digest: `node_count`, `edge_count`, `truncated`, `edge_kinds`.                         | Edge kinds: `direct`, `indirect-approx`, `typed-approx`. Full graph stays in `*-wasm-report.json`.                          |
| `wasm_unknown_opcodes`    | Distinct unknown instruction mnemonics from the analysis summary.                                 | Empty when the decoder recognizes every instruction.                                                                        |
| `wasm_isa_capabilities`   | Sorted `isa.*` instruction-set capability tokens (e.g. `isa.simd`, `isa.gc`, `isa.memory64`).     | Added with wasm-tools 2.1; derived from decoded opcodes, type definitions, and memory limits.                               |
| `wasm_types_summary`      | Type-section digest: `total` plus per-kind counts (`func`, `struct`, `array`).                    | Added with wasm-tools 2.1; GC composite types decoded from plain and rec-group entries.                                     |
| `wasm_debug_info_present` | `true` when the module still carries DWARF (`.debug_*`) custom sections.                          | Added with wasm-tools 2.1; mirrors the `debug_info_present` format signal.                                                  |
| `build_info`              | WASI runtime/variant and JS-interface hints (see below), plus toolchain and component version.    | `wasi_variants` use `preview1`/`preview2`/`preview3`/`legacy`.                                                              |
| `errors`                  | blint-level error list for WASM parsing.                                                          | Set when parser reports issues or parse operation fails.                                                                    |

The `build_info` block for WASM binaries is assembled from the parser detections and report blocks:

- `runtime: "WASI"` and `wasi_variants` when WASI imports are detected. Variant naming follows wasm-tools 2.0: `preview1`, `preview2` (renamed from `preview2-like`), `preview3` (WASI 0.3 / async components), and `legacy`.
- `host_interface: "JavaScript"` when JS-interface modules are detected.
- `languages` and `processed_by` when a toolchain fingerprint was decoded from `producers` custom sections.
- `component_version` and `layer_version` for Component Model binaries.

For Component Model binaries, `module_version` carries the raw 32-bit header value (for example `65549` = component version 13, layer 1) rather than the core-module version `1`, and the section lists in both the metadata and `*-wasm-report.json` are aggregations across all nested core modules, with each entry carrying a `core_module` index.

The findings computed by the `wasm_tools` analysis layer (`WASM-CAP-001` through `WASM-STR-007`, plus `WASM-ISA-008`) are passed through into blint's findings output (`findings.json` and the console/HTML report). Each finding keeps its stable `WASM-*` id and severity (they top out at `high`, so CI builds that fail only on `critical` findings are unaffected), maps the upstream `remediation` text to `description`, and carries `confidence` plus the parser `evidence` dict. These findings are checks, not reviews: they appear even when runs are invoked with `--no-reviews`.

With wasm-tools 2.1, `WASM-DOS-003` fires only when a `memory.grow` executes inside a loop body (allocator startup growth alone no longer triggers it) and its evidence reports `loop_memory_grow_ops` plus the responsible functions. The new `WASM-ISA-008` advisory (severity `low`) reports relaxed-SIMD instructions, the principal source of cross-engine numeric non-determinism.

#### wasm-tools 2.1 attributes

blint requires wasm-tools 2.1 and surfaces its new report attributes as follows:

- **Instruction-set capability tokens.** The analysis `capabilities` list gains `isa.*` tokens derived from decoded opcodes, type definitions, and memory limits: `isa.simd`, `isa.relaxed-simd`, `isa.atomics`, `isa.gc`, `isa.function-references`, `isa.tail-call`, `isa.memory64`, `isa.wide-arithmetic`, `isa.legacy-exceptions`, and `isa.exceptions`. blint re-exports the `isa.*` subset as `wasm_isa_capabilities` and also uses `isa.memory64` to classify `machine_type` when a module imports its 64-bit memory (Emscripten-style) instead of defining it in the memory section.
- **GC type decoding.** Type-section entries now decode GC composite types, including rec groups that expand one entry per member of the group's type-index slots. Each `types[]` entry in `*-wasm-report.json` carries a `kind` (`func`, `struct`, or `array`); `struct`/`array` entries carry no signature. blint summarizes this as `wasm_types_summary` (`total`, `func`, `struct`, `array`, plus a key for any further kind a newer wasm-tools decodes, so the per-kind counts always sum to `total`), and the mere presence of composite types raises the `isa.gc` capability.
- **Legacy exception handling.** The pre-renumbering `try`/`catch`/`catch_all`/`rethrow`/`delegate` opcodes still emitted by older toolchains now decode (raising `isa.legacy-exceptions`) instead of surfacing as unknown opcodes; the current `try_table`/`throw`/`throw_ref` form raises `isa.exceptions`.
- **DWARF awareness.** `.debug_*` custom sections are detected and raise a `debug_info_present` signal in `analysis.detections.format.signals`; printable strings from a `.debug_str` section are appended to the report `strings` with a `source: "custom:.debug_str"` label and a separate 250-entry budget. Secret/IoC detection (and therefore `WASM-STR-007` and `wasm_strings_summary`) still considers data-segment strings only. blint surfaces the signal as the `wasm_debug_info_present` boolean.

WASM binaries also receive common derived fields like `hashes`, `import_dependencies`, `llvm_target_tuple` (for example `wasm32-unknown-unknown`), `security_properties`, and `binary_composition`.

blint writes the raw parser payload to a companion file named `*-wasm-report.json` alongside `*-metadata.json`. With wasm-tools 2.0 this payload additionally includes `is_component`, the extracted `strings` with linear-memory provenance (capped), the labeled `call_graph`, the `toolchain` fingerprint, and — for components — the `component` block with interfaces, interface packages, and nested core modules. With wasm-tools 2.1, `types[]` entries carry a `kind` attribute, the `strings` list may include `.debug_str` entries labeled with a `source` field, and the analysis block carries the `isa.*` capabilities and the `loop_memory_grow_ops` memory profile metric.

#### Report-size guards

Two CLI opt-outs and one default guard bound the wasm report size:

- `--no-wasm-strings` skips string extraction. `strings` becomes empty in the report, `wasm_strings_summary` reports `detected: false`, and the string-derived findings (e.g. `WASM-STR-007`) disappear along with their evidence source.
- `--no-wasm-call-graph` skips call-graph construction. `call_graph` becomes empty, `wasm_call_graph_summary` zeroes out, and wasm callgraph exports (`--export-callgraph-*`) produce no artifacts even with `--disassemble`.
- Function instruction streams are capped at `BLINT_MAX_WASM_INSTRUCTIONS` instructions per report (default `50000`, `0` disables). This is the only unbounded part of the parser output — strings and graph edges are already capped by wasm-tools — and for large modules it dominates the report size (a 1 MB module produced a 33 MB report, 98% instructions).

  The budget covers every function in the report, including those inside core modules and nested components. It is divided max-min fair rather than first-come: each function is offered an equal share, and a function needing less than its share releases the remainder to the longer ones. This keeps a trimmed report a sample of the whole module instead of the first few functions in section order — at the default budget a 3000-function module leaves every function with at least some of its body, where a greedy split would empty all but the first few dozen.

  Trimmed functions keep a truthful `instruction_count` and gain an `instructions_truncated` count. When anything was dropped the report gains a top-level `blint_truncation` block (`instruction_budget`, `instructions_dropped`, `functions_truncated`), so the artifact is self-describing and a consumer can distinguish a small module from a trimmed large one without the log line. A log hint also names the environment variable.

#### Callgraphs and SBOM components

The wasm callgraph is converted from the `wasm_tools` static call graph rather than from disassembly; see [Callgraph Analysis](./CALLGRAPH.md#webassembly-callgraphs) for the edge kinds and confidence semantics. For SBOM generation, `blint sbom --wasm-sbom` turns a Component Model binary's imported WIT interface packages into components; see [Custom Properties](./CUSTOM_PROPERTIES.md#webassembly-component-model-properties) for the properties involved.

Representative WASM fixtures used by tests are available under `tests/data/*.wasm`.

---

## Symbol and Function Information

This collection of attributes describes the functions and data within the binary, providing insight into its structure and capabilities.

### Symbol Tables: `symtab_symbols` and `dynamic_symbols`

Symbols are names for locations in memory, typically corresponding to functions or global variables. BLint extracts symbols from two primary sources, which serve different purposes.

```
+------------------------------------+
|        Your Executable File        |
|                                    |
| +-----------------+  (for static   |
| | .symtab         |   linking &    |
| | (symtab_symbols)|   debugging)   |
| +-----------------+                |
|         ^                          |
|         | (often stripped)         |
|                                    |
| +-----------------+  (for dynamic  |
| | .dynsym         |   linking at   |
| |(dynamic_symbols)|   runtime)     |
| +-----------------+                |
|                                    |
+------------------------------------+
```

- **`symtab_symbols`**: This is the full symbol table (`.symtab` in ELF), containing names for _all_ functions and global variables, including internal, non-exported ones.
  - **Purpose**: Provides a comprehensive map of the binary's internal structure.
  - **Use Case**: Invaluable for reverse engineering, as it gives names to internal functions.
  - **Limitation**: This table is often stripped from production binaries to reduce size and hinder reverse engineering. Its absence is a key indicator (`"stripped": true` in `security_properties`).

- **`dynamic_symbols`**: This is the smaller symbol table (`.dynsym` in ELF) used by the dynamic linker at runtime. It only contains symbols that are imported from or exported to other shared libraries.
  - **Purpose**: To resolve dependencies between shared libraries.
  - **Use Case**: Understanding the binary's public API (what it exports) and its direct dependencies on functions from other libraries (what it imports).
  - **Strength**: This table is almost never stripped from dynamically linked executables, as it is essential for the program to run.

Each symbol entry contains details like its `name`, `type` (`FUNC` or `OBJECT`), `binding` (`GLOBAL`, `LOCAL`, `WEAK`), and whether it is `is_imported` or `is_exported`.

- **`name`** is the demangled form where one exists, which is what a reader wants to see.
- **`raw_name`** is the linkage name, present only when demangling changed it. This is the name that appears in another object's export table, so it is the only key that matches a C++ or Rust symbol across binaries. It is what [symbol attribution](#symbol-attribution) and version-aware database lookups match on.
- **`version`** is the symbol version node the symbol binds to, such as `GLIBC_2.28`. See [`abi_analysis`](#abi_analysis).

### Function Lists: `functions`, `ctor_functions`, `dtor_functions`

While symbol tables provide the names, these lists represent a curated set of functions that LIEF identifies as code entry points.

- **`functions`**: A list of general functions identified by the parser, often corresponding to exported symbols or entries in specific sections.

- **`ctor_functions`**: A list of **constructors**. These are special functions that are executed _before_ the program's main entry point (`main` or `WinMain`).
  - **Purpose**: To initialize the program's state or set up runtime environments.
  - **Use Case for Analysts**: Malware and legitimate programs alike use constructors for early initialization. Examining these functions can reveal anti-debugging checks, environment setup, or other critical startup logic that occurs before the main code path.

- **`dtor_functions`**: A list of **destructors**. These are special functions that are executed when the program exits cleanly.
  - **Purpose**: To perform cleanup tasks like flushing files or releasing resources.
  - **Use Case for Analysts**: Malware may use destructors to cover its tracks, delete files, or send a final beacon upon exit. These are important to check for cleanup or anti-forensic activities.

### `discovered_functions` and `function_discovery`

Recovered function starts for binaries whose symbol tables are stripped or incomplete. Two structures are additive to the symbol-driven lists:

- **`discovered_functions`**: every function start recovered from the structures the runtime itself depends on, which survive `strip`:
  - **Mach-O `__TEXT,__unwind_info`** (compact unwind): `source: "unwind"`, with exact function sizes derived from the sorted offset table and its sentinel entry.
  - **ELF `.eh_frame_hdr` / `.eh_frame`**: `source: "eh_frame"`. Starts come from the binary-search table when present; sizes come from the exact FDE `pc_range` values. A CIE/FDE walk covers binaries whose header table is missing or malformed.
  - Each entry carries `name` (the real symbol name when one exists, `sub_<address>` otherwise), `address`, `size` and `source`. Addresses already claimed by a symbol bucket enrich the existing entry with the exact unwind size when its size was unknown.
- **`function_discovery`**: summary of the merge — `sources` (per-source counts) and `merged_count` (addresses that were genuinely new, i.e. not claimed by any symbol bucket).

Entries whose addresses already appear in the symbol-driven buckets never replace or duplicate them; only genuinely new addresses are appended to `functions` (with `"discovered": true`, `size` 0). Call-site promotion (see the disassembly docs) records its additions in `discovered_functions` with `source: "callsite"`.

---

## Build and Dependency Information

These attributes provide insight into the toolchain, programming language, and third-party libraries used to create the binary. This is critical for Supply Chain Security and vulnerability analysis.

### `build_info`

This object summarizes key information about the toolchain and primary language used to compile the binary.

| Property           | Description                                                                                                                                         | Use Case                                                                                                                       |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `language`         | The primary programming language detected (e.g., `Go`, `Rust`, `.NET`). This is inferred from language-specific sections or symbols.                | Guides the reverse engineering process by setting expectations for runtime behavior, calling conventions, and data structures. |
| `go_version`       | If the language is Go, this specifies the exact version of the Go compiler toolchain used (e.g., `go1.18.3`).                                       | Allows for checking against known vulnerabilities in specific versions of the Go compiler or standard library.                 |
| `linker_version`   | The version of the linker program (e.g., from `ld` or `link.exe`) that produced the final executable, if this information is present in the binary. | Can help fingerprint the build environment (e.g., a specific Linux distribution or version of Visual Studio).                  |
| `compiler_version` | The compiler identification string, often extracted from the `.comment` section in ELF files (e.g., `GCC: (Ubuntu 11.2.0-19ubuntu1) 11.2.0`).       | Precisely identifies the compiler and its version, which is useful for tracking toolchain vulnerabilities.                     |

### `*_dependencies`

These attributes provide detailed lists of third-party libraries and packages compiled into the binary.

| Attribute             | Description                                                                                                                                                                                                                                                         | Use Case                                                                                                                                                                                                                                       |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `go_dependencies`     | A list of Go packages used to build the binary, extracted from the embedded `.go.buildinfo` section. Includes package names, exact versions, and checksums (`h1:` hashes).                                                                                          | **Gold Standard for SCA.** Allows for precise identification of Go libraries and their versions, enabling direct mapping to known vulnerabilities (CVEs) in those packages.                                                                    |
| `rust_dependencies`   | A list of Rust crates used to build the binary, extracted from the `.dep-v0` section created by the `cargo-auditable` feature. Includes crate name, version, and kind.                                                                                              | Similar to Go, this enables precise SCA for Rust applications, mapping crates to known CVEs. **Limitation**: This section is only present if the developer explicitly enables the `cargo-auditable` feature during compilation.                |
| `dotnet_dependencies` | A structured list of NuGet packages and their versions, extracted from the `deps.json` file embedded in the PE overlay of self-contained .NET applications.                                                                                                         | Provides precise SCA for .NET applications, allowing for vulnerability mapping. **Limitation**: This is only available for .NET Core/5+ applications published in "self-contained" mode and is not present in framework-dependent deployments. |
| `import_dependencies` | A structured graph detailing which shared libraries (`.dll`, `.so`, `.dylib`) are imported by the main binary and which specific symbols are used from each library. See [Symbol attribution](#symbol-attribution) for what the attribution is based on per format. | Provides a clear, high-level view of runtime dependencies. Helps identify the use of sensitive APIs (e.g., crypto, networking) and from which library they originate. This is a foundational element for behavior analysis.                    |

---

## Derived and Analytical Attributes

This is where blint provides the most value, by interpreting low-level data and presenting high-level security and compositional insights.

### `callgraph` (optional, requires `--disassemble`)

When disassembly output is available, blint derives a deterministic top-level callgraph:

- `version`: Schema version for downstream compatibility.
- `node_count` / `edge_count`: Number of internal nodes and internal edges.
- `nodes`: Stable list of functions with `{id, key, name, address, aliases}` where `aliases` includes other names sharing the same entry address.
- `edges`: Internal call edges as `{src, dst, count, kind, confidence}` where `kind` is one of `direct`, `tailcall`, `indirect_hint`.
- `external`: Unresolved or ambiguous call targets as `{src, target, count, reason, confidence}`, plus `library` when the target can be attributed to the library that supplies it.
- `external_attribution_sources` / `attributed_external_count`: What the library attribution was based on, and how many external edges carry one.

Notes:

- The graph includes direct edges, tail-call approximations, and register-tracked indirect hints.
- `confidence` indicates edge trust level (`high`, `medium`, `low`) for analyst triage.
- Duplicate call instructions are preserved via edge `count`.
- Address/name collisions and misses are surfaced in `external` with reason buckets such as `ambiguous_address`, `ambiguous_name`, and `address_space_miss`.
- An external edge carries a `library` only when the resolver recovered a symbol name for the target and that name is a known import. Edges whose target is a register-indirect operand cannot be attributed, so `library` is absent on most of them. Where it is present, `confidence` is raised from `low` to `medium`: the target is still unresolved as an internal edge, but the library it reaches is evidence rather than a guess.
- Same-address symbol aliases are collapsed into a canonical node to reduce false ambiguity while preserving alias visibility.

For WASM binaries the same payload is produced by converting the `wasm_tools` static call graph instead of disassembly, so the callgraph export flags work for `.wasm` inputs under `--disassemble` too. Differences from the native graph:

- Imported host functions become `external` targets with reason `import` (e.g. `wasi_snapshot_preview1.fd_write`) rather than nodes; the nodes are the locally defined functions.
- Edge `kind` keeps the upstream semantics: `direct` edges are exact, `indirect-approx` (element-segment over-approximation for `call_indirect`) and `typed-approx` (signature-based approximation for `call_ref`) are candidates, and only `direct` edges carry `high` confidence.
- Call sites to the same target collapse into edge `count`; node `key` uses the function body offset as its address.

### `abi_analysis`

ELF only. Describes the runtime the binary requires and the ABI features that constrain where it can be deployed. Every value is derived from the _imported_ symbols, not from the version definition table, because a version node appearing in `.gnu.version_r` does not mean any symbol binds to it.

| Property                                  | Description                                                                                                                                                                                         |
| :---------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `libc`                                    | The C library the binary is linked against: `glibc`, `musl`, `bionic`, or empty when it cannot be determined. Inferred from the interpreter first, then from the version providers and `DT_NEEDED`. |
| `min_glibc_version`                       | The minimum glibc the binary can run on, as a dotted version. Empty when no glibc version node is bound.                                                                                            |
| `requirements`                            | One entry per version provider. See the table below.                                                                                                                                                |
| `features`                                | Symbol-level ABI features: `ifunc_symbols`, `imported_ifunc_symbols`, `tls_symbols`, `unique_symbols`, and `implementation_specific_imports`. Each is a capped list of symbol names.                |
| `uses_symbol_versioning`                  | True when any imported symbol carries a version node.                                                                                                                                               |
| `uses_ifunc`                              | True when the binary defines or imports an indirect function, which requires a loader that runs IFUNC resolvers.                                                                                    |
| `uses_tls`                                | True when thread-local storage symbols are present.                                                                                                                                                 |
| `uses_unique_symbols`                     | True when the binary defines `STB_GNU_UNIQUE` symbols, which prevent the object from being unloaded.                                                                                                |
| `uses_private_symbol_versions`            | True when a symbol binds to a private version node such as `GLIBC_PRIVATE`. These are internal interfaces with no stability promise.                                                                |
| `private_version_providers`               | The private providers bound, e.g. `["GLIBC_PRIVATE"]`.                                                                                                                                              |
| `uses_implementation_specific_interfaces` | True when the binary imports C library internals that have no portable equivalent (loader introspection, allocator internals, backtrace support, non-portable pthread extensions).                  |
| `is_statically_linked`                    | True when there is no interpreter and no `DT_NEEDED` entry.                                                                                                                                         |
| `portability_notes`                       | Human-readable sentences summarizing the above, suitable for direct display.                                                                                                                        |

Each entry in `requirements` describes one version provider:

| Property                         | Description                                                                                                                                                 |
| :------------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `provider`                       | The version node provider, e.g. `GLIBC`, `GLIBCXX`, `LIBPAM_EXTENSION`, `GLIBC_PRIVATE`.                                                                    |
| `min_version`                    | The **highest** version node any imported symbol binds to — that is, the minimum the runtime must supply. Empty for providers whose nodes carry no version. |
| `determining_symbols`            | The imported symbols that set `min_version`. Use these to trace an unexpectedly high floor back to the single import responsible.                           |
| `symbol_count`                   | How many imported symbols bind to this provider.                                                                                                            |
| `versions`                       | Every distinct version bound for this provider, sorted numerically.                                                                                         |
| `package_name` / `package_group` | Package coordinates for the provider where known, e.g. `libc` / `gnu` for `GLIBC`. Used to build the SBOM component.                                        |

### `runtime_loading` and `recovered_dependencies`

Libraries opened through `dlopen` never appear in `DT_NEEDED`, so a dependency list built from the dynamic table alone omits them. `dlopen_dependencies` covers the case where the project embeds a declarative note; these two attributes cover everything else by recovering the information from the image.

`runtime_loading` describes the behaviour:

| Property          | Description                                                                                                                                |
| :---------------- | :----------------------------------------------------------------------------------------------------------------------------------------- |
| `entry_points`    | The runtime-loading functions the binary imports (`dlopen`, `dlmopen`, `android_dlopen_ext`, `LoadLibraryW`, `dlsym`, …).                  |
| `loads_libraries` | True when at least one entry point actually opens a library. `dlsym` alone operates on a handle the caller already has and does not count. |
| `call_sites`      | Maps each entry point to the functions that call it. Populated only with `--disassemble`.                                                  |
| `call_site_count` | Total number of call sites across all entry points.                                                                                        |

`recovered_dependencies` lists the libraries themselves. Names already present in `DT_NEEDED`, `libraries`, or `dlopen_dependencies` are excluded, since those are not gaps.

| Property     | Description                                                                                                                             |
| :----------- | :-------------------------------------------------------------------------------------------------------------------------------------- |
| `name`       | The soname as it appears in the binary, e.g. `libgpm.so.2`.                                                                             |
| `confidence` | `high` when the name is a literal in a read-only data section and looks like a library, `medium` for weaker placement, `low` otherwise. |
| `evidence`   | Why the candidate was accepted: which loading entry point is imported, which section the literal is in, and any absolute path found.    |
| `paths`      | Absolute paths found for the library, when the binary hardcodes one.                                                                    |
| `sections`   | The sections the name was found in.                                                                                                     |

Format templates such as `%s/libfoo.so` are excluded: they are assembled at runtime and are not themselves names. This keeps the pass conservative — it under-reports rather than inventing dependencies.

### `link_closure`

**Opt-in.** Resolving the closure reads the filesystem the scan runs on, which is only meaningful when that filesystem is the binary's intended runtime. Enable it with:

| Environment variable         | Description                                                                                                   |
| :--------------------------- | :------------------------------------------------------------------------------------------------------------ |
| `BLINT_RESOLVE_LINK_CLOSURE` | Set to `1`, `true`, or `yes` to run the resolution.                                                           |
| `BLINT_LINK_ROOT`            | Filesystem root to resolve against. Point this at an unpacked image or sysroot rather than the scanning host. |
| `BLINT_LINK_SEARCH_PATH`     | Extra directories treated as if they were in `LD_LIBRARY_PATH`, separated by the platform path separator.     |

Resolution follows the loader's documented search order: `DT_RPATH` (ignored when `DT_RUNPATH` is present), then `LD_LIBRARY_PATH`, then `DT_RUNPATH`, then the default directories for the machine type plus anything configured in `/etc/ld.so.conf`. The `$ORIGIN`, `$LIB` and `$PLATFORM` tokens are expanded as the loader expands them.

| Property                  | Description                                                                                                                                                                                  |
| :------------------------ | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `resolved`                | Each object that would be mapped, with `path`, `found_via` (which kind of search path answered), `needed_by`, `relation` (`direct` or `transitive`), and `export_count`.                     |
| `missing`                 | Sonames nothing on the search path supplies. Each is a load-time failure and usually indicates an undeclared packaging dependency.                                                           |
| `unresolved_symbols`      | Imported symbols no object in the closure defines, capped at 64 entries. Weak imports are excluded, since going unresolved is their intended behaviour.                                      |
| `unresolved_symbol_count` | The full count, before the cap.                                                                                                                                                              |
| `symbol_providers`        | Maps each resolved symbol name to the soname that supplies it. This is the edge-level dependency data `dynamic_entries` cannot give you.                                                     |
| `risky_search_paths`      | `DT_RPATH` / `DT_RUNPATH` entries that are relative, empty (which the loader reads as the working directory), or under a world-writable directory. Each carries `path`, `kind`, and `issue`. |
| `complete`                | True only when nothing is missing and no symbol is unresolved.                                                                                                                               |
| `root`                    | The filesystem root the result describes.                                                                                                                                                    |

The closure is capped at 256 objects so a pathological dependency graph cannot stall a run.

### Symbol attribution

`import_dependencies` maps each imported symbol to the library that supplies it. How much evidence exists for that depends entirely on the format:

| Format | Evidence                                                                                                                                                                            | Available                                         |
| :----- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------------------------------------------------ |
| PE     | The import table is organised by DLL, so every import names its library.                                                                                                            | Always                                            |
| Mach-O | Each symbol is bound to a dylib, recorded as `library::symbol`.                                                                                                                     | Always                                            |
| ELF    | The dynamic symbol table and the `DT_NEEDED` list are unrelated flat lists. The connection only exists once the dependency closure is resolved and each library's exports are read. | Only with [`link_closure`](#link_closure) enabled |

Two fields record what the result rests on:

| Property                    | Description                                                                                                                          |
| :-------------------------- | :----------------------------------------------------------------------------------------------------------------------------------- |
| `attribution_sources`       | Which evidence was used: `import_table`, `load_commands`, `link_closure`. Empty means none was available.                            |
| `unattributed_symbol_count` | How many imported symbols could not be tied to a library. These are collected under a synthetic `unattributed` entry in `libraries`. |

**An ELF binary analysed without closure resolution attributes nothing.** That is deliberate. Assigning a symbol to an arbitrary declared library produces a dependency edge that is indistinguishable downstream from a correct one, and a wrong edge is worse than an honest gap.

C++ and Rust symbols are matched on their linkage name, which blint records as `raw_name` on the symbol whenever demangling changed it. A provider's export table holds mangled names, so the demangled name alone never matches.

Note that `::` is a library separator only in Mach-O, and only when the prefix looks like a library. Everywhere else it separates namespace components, and `APT::PackageContainer::begin` is one symbol rather than a dependency on `APT`.

### `link_hygiene`

Reports declared dependencies that are never used and used libraries that are never declared. Requires symbol attribution, so for ELF it needs closure resolution; the whole block is absent when nothing could be attributed, because with no evidence every dependency looks unused.

| Property                    | Description                                                                                                                                                                |
| :-------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `unused_dependencies`       | Declared libraries from which no symbol is imported, each with a `name` and a `reason`. Linking with `--as-needed` removes them.                                           |
| `undeclared_dependencies`   | Libraries supplying symbols without being declared, with `symbol_count` and a sample of `symbols`. These work only for as long as some other dependency keeps them mapped. |
| `attribution_sources`       | The evidence the result is based on, as above.                                                                                                                             |
| `unattributed_symbol_count` | Imports not tied to any library. A high count means the findings are based on partial evidence.                                                                            |
| `declared_count`            | How many direct dependencies were declared.                                                                                                                                |

`unused_dependencies` answers a similar question to `ldd -u`, but not an identical one. `ldd -u` relocates the whole closure and counts a library as used if anything in it binds to the library, so a library this binary never calls still counts as used when some other dependency calls it. blint reports **direct** use, which is what `--as-needed` acts on. Everything `ldd -u` reports unused will also be reported here; the reverse does not hold.

Over-linking is largely a property of the distribution rather than the project: builds that pass `--as-needed` are almost free of it, while those that do not accumulate it as link lines are inherited between libraries.

### `wx_segments`

Present for every ELF, PE and Mach-O image. Lists the loadable segments or sections the loader maps both writable and executable, each with its `name`, normalized `permissions` (for example `rwx`) and `virtual_address`. An empty list means the image maintains Write XOR Execute: no code mapping is writable and no data mapping is executable.

What counts as a mapping follows what each platform loader actually enforces:

- **ELF:** `PT_LOAD` program headers carrying both `PF_W` and `PF_X`, named `PT_LOAD[<index>]` by program-header position. An executable `PT_GNU_STACK` is deliberately not listed here; it is a stack-executability defect and is reported by the NX signal (`has_nx`) instead.
- **PE:** Sections whose characteristics include both `MEM_WRITE` and `MEM_EXECUTE`.
- **Mach-O:** Segments whose `init_protection` includes both write and execute. `max_protection` is ignored: it describes what a segment may later be remapped to, not what it is mapped with, so a permissive maximum alone does not mean writable code ever existed.

The `CHECK_WX_SEGMENTS` security check turns each entry into a finding naming the segment.

### `entropy`

Per-section Shannon entropy plus packing evidence, collected for every ELF, PE and Mach-O image whether or not disassembly is requested.

- **`sections`**: one entry per non-empty section with `name`, `size`, `entropy` (bits per byte, 0-8), `executable`, `writable`, and `sampled` (true when entropy was computed over the first 8 MB of a larger section — the sample is always the section head, so results stay deterministic).
- **`packing`**: the derived signals:
  - `packed_likelihood`: `high` / `medium` / `low` summary of the evidence below.
  - `packers`: packer section-name signatures found (UPX, Themida, VMProtect, ASPack, MPRESS and others).
  - `writable_executable_sections`: section-level W+X evidence; the loadable-segment view lives in [`wx_segments`](#wx_segments).
  - `executable_section_entropy` / `max_executable_section_entropy`: per-executable-section entropy values.
  - `overlay_size`: bytes past the last section's file content (ELF/PE only; the Mach-O file tail is the code-signature SuperBlob and is excluded).
  - `findings`: the individual evidence strings (`packer_section:`, `writable_executable_section:`, `high_entropy_exec_with_few_imports`, `entrypoint_outside_executable_sections`, `virtual_size_mismatch:`, `file_overlay`).

The `CHECK_PACKED` security check turns `high`/`medium` likelihood into a finding naming the evidence.

### `toolchain`

Compiler and runtime attribution built from binary evidence rather than declared metadata. Every signal carries `source` and `confidence`:

- **`compilers`**: from ELF `.comment` sections (gcc, clang, rustc, lld with versions), Mach-O `LC_BUILD_VERSION` tool entries, and the PE linker version fields.
- **`runtimes`**: Go (buildinfo or `runtime.*` symbols), Rust (buildinfo or `_ZN`/`_R` mangling), Swift (`swift_` stdlib symbols), Objective-C (`objc_*` trampolines), MSVC/MinGW CRT fingerprints, .NET.
- **`libc`**: `glibc` or `musl` from symbol-version requirements and the ELF interpreter.

Empty lists mean the format carries no such evidence — attribution is never padded with guesses.

### `import_hash`

A stable digest over the normalized import-name set (ELF dynamic symbols marked as imports, or the `imports` list for PE/Mach-O). Normalization strips ELF `@@VERSION` suffixes, PE `__imp_`/`_imp_` thunks and common leading-underscore decoration, so the same dependency set hashes identically across formats and minor version bumps. Empty for binaries that import nothing (fully static images).

### `analysis_coverage`

Accounting for what was analyzed versus what was discovered, so a run that disassembled 3 of 400 functions is never indistinguishable from a clean run of 400:

- **`functions`**: `symbolic` (from symbol buckets), `discovered` (recovered from unwind tables, prologues and call sites), `discovered_merged_into_function_list`, `disassembled`.
- **`degradations`**: reasons parts of the binary were not analyzed, e.g. `fairplay_encrypted`, `disassembly_unavailable`, `slice_summary_failed`.
- **`sections_analyzed`**: sections the entropy pass examined.
- **`slices`** (universal Mach-O binaries only): `total`, `summarized` and `failed` slice counts. A slice whose summary failed is isolated — the remaining slices are still reported, and `errors` carries one record per failed slice (`index`, `exception_type`, `message`).
- **`security_properties_gaps`**: properties the format could carry but blint does not compute yet (currently Mach-O's granular `has_nx_stack` / `has_nx_heap`). Their absence from `security_properties` means "not implemented", never "checked and clean".

#### Run-level `analysis-coverage.json`

Alongside `findings.json`/`reviews.json`, default-mode runs write an `analysis-coverage.json` summarizing the run's _units_ (a top-level file, or one binary contained in an `.ipa`). A binary that fails to parse no longer aborts the scan (issues #122, #188); the failure lands here instead:

- **`units`**: `attempted` / `succeeded` / `failed` / `skipped`. Totals mix granularities: an `.ipa` archive counts as a unit beside the member units it contains.
- **`units_by_role`**: the same four counters per unit role (`top-level`, `ipa-member`), so a consumer can compute a success rate over just the member binaries or just the top-level inputs.
- **`failures`**: one record per failed unit with `file_path`, `unit_role` (`top-level` or `ipa-member`), `stage`, `exception_type` and `message`.
- **`skipped`**: one record per recognized-but-unanalyzed unit with `file_path`, `unit_role` and a machine-readable `reason` (e.g. `extract_failed`, `no_dex_bytecode`).
- **`cache`**: parse-cache accounting. `enabled` tells a fast run from a cached one; `hits` / `misses` / `stored` count what was served from the content-addressed parse cache; `caches_failures` is always `false` — parse failures are never cached, so every record in `failures` is a fresh failure; `by_role` carries the same three counters per unit role, since not every role can hit the cache (android app units never go through `parse()`).

This file is exported even when the scan produced no findings, so a caller can always tell "clean" from "blind" without reading stderr.

### Parse cache

Default-mode runs can cache parse metadata in a content-addressed SQLite store keyed on `(sha256(file bytes), blint version, options digest)`, separate from blintdb (which is a shipped read-only artifact). A warm run replays byte-identical metadata — including the cross-path case, where the stored path is rewritten to the current one exactly where `parse()` embeds it. The cache is **off by default** — `--cache` opts a run into it, since caching writes to the user's disk and is a caller's choice; `blint cache stats` reports entry count and actual size on disk, and `blint cache clear` deletes the store. Entries are zlib-compressed and bounded by `BLINT_CACHE_MAX_BYTES` (default 1 GiB; `0` disables the bound) with least-recently-used eviction; the store lives at `BLINT_CACHE_DIR` (default: the user cache directory, e.g. `~/.cache/blint` on Linux), in `parse-cache.db`.

### `security_properties`

This object provides a quick, at-a-glance summary of the most important security mitigations compiled into the binary.

Properties are format-aware: a property the format has no concept of is _omitted_ rather than reported as a negative finding (`relro` never appears for Mach-O, for example), and a property blint does not compute for the format is omitted and listed in [`analysis_coverage`](#analysis_coverage) under `security_properties_gaps`.

| Property                 | Description                                                                                                             | Security Implication                                                                                       |
| :----------------------- | :---------------------------------------------------------------------------------------------------------------------- | :--------------------------------------------------------------------------------------------------------- |
| `nx`                     | **Non-eXecutable.** True if data regions (stack/heap) are not executable.                                               | Mitigates code injection attacks.                                                                          |
| `w_xor_x`                | **Write XOR Execute.** True when no loadable segment is mapped both writable and executable.                            | Keeps code pages unmodifiable at runtime; violations are listed in [`wx_segments`](#wx_segments).          |
| `pie` / `aslr`           | **Address Space Layout Randomization.**                                                                                 | Makes memory corruption exploits harder by randomizing locations.                                          |
| `canary`                 | **Stack Cookie.** Confirmed via Load Config or symbols.                                                                 | Mitigates stack-based buffer overflows.                                                                    |
| `control_flow_guard`     | **CFG (Forward-Edge).** Validates indirect call targets.                                                                | Mitigates function pointer corruption (e.g., vtable hijacking).                                            |
| `xfg`                    | **Extended Flow Guard.** A stricter version of CFG that validates function signatures (types) at indirect call sites.   | significantly reduces the number of valid targets for an attacker compared to standard CFG.                |
| `cfg_export_suppression` | **CFG Export Suppression.** Prevents valid exported functions from being called indirectly unless explicitly permitted. | Reduces the attack surface by limiting available gadgets in exported APIs.                                 |
| `pac`                    | **Pointer Authentication (ARM64).** Signs return addresses.                                                             | Hardware-enforced protection against ROP.                                                                  |
| `pac_strict`             | **Strict PAC.** Fails to load if hardware support is missing.                                                           | Enforces a fail-closed security policy for PAC.                                                            |
| `cet_shadow_stack`       | **Intel CET / Shadow Stack.** Indicated by EH Continuation Tables.                                                      | Hardware-enforced protection against ROP by maintaining a secondary, immutable stack for return addresses. |
| `retpoline`              | **Retpoline.** Use of return trampolines.                                                                               | Mitigates Spectre Variant 2 (Branch Target Injection) side-channel attacks.                                |
| `cast_guard`             | **CastGuard.** Validates virtual function calls.                                                                        | Mitigates C++ type confusion and vtable hijacking attacks.                                                 |
| `safe_seh`               | **Safe SEH.** (x86) Registers exception handlers at compile time.                                                       | Prevents attackers from overwriting SEH chains on the stack to gain execution.                             |
| `safe_delay_load`        | **Protected Delay-Load IAT.** Marks delay-load tables read-only after initialization.                                   | Prevents hooking of APIs that are loaded lazily during execution.                                          |
| `enclave`                | **Enclave Support.** Binary contains configuration for SGX/VBS.                                                         | Indicates the application uses TEE (Trusted Execution Environment) features for high-security operations.  |
| `packed`                 | **Packing evidence present.** Derived from the [`entropy`](#entropy) block.                                             | Strings, symbols and disassembly-derived findings may be incomplete until the binary is unpacked.          |
