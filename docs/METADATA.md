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
| `strings`             | A list of strings extracted from the binary that exhibit high entropy or match patterns for secrets (API keys, private keys, etc.). Non-secret strings are filtered out to reduce noise. Base64-encoded strings are automatically decoded. On a managed (W3.2) assembly the list is the `#US` heap's actual string literals — the compiler's own store, not a byte scan — led by the heap values with the byte scan unioned in behind them (`strings_source: user_strings_heap` / `user_strings_heap+binary_scan` names the provenance; absent means the byte scan, as before).                                      | Triage for hardcoded credentials, sensitive URLs, or cryptographic material. A primary step in vulnerability and malware analysis. |
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

- **Layout Coherence (`entry_point_section`, `segments_summary`, `layout_anomalies`):** Where execution starts, the full program-header table, and the contradictions between them. See [`layout_anomalies`](#layout_anomalies) below.

### For PE Binaries

PE (Portable Executable) files are the standard for Windows.

- **Headers (`dos_header`, `header`, `optional_header`):**
  - `machine_type`: The target architecture (e.g., `AMD64`, `I386`), rendered from the COFF `Machine` field.
  - `machine_type_value`: The raw numeric `IMAGE_FILE_MACHINE_*` value (e.g., `0x8664`). Rule `machine_types:` gates and the arch mapping resolve names through blint's own PE-spec table (`blint/lib/pe_constants.py`), never through a dependency's enum rendering.
  - `subsystem`: The subsystem (e.g., `WINDOWS_GUI`, `WINDOWS_CUI`).
  - `subsystem_value`: The raw numeric `IMAGE_SUBSYSTEM_*` value (e.g., `2`).
  - `dll_characteristics_structured`: The DLL characteristics bitfield decoded by blint, not by the parsing library: `{"value": 352, "flags": ["HIGH_ENTROPY_VA", "DYNAMIC_BASE", "NX_COMPAT"], "source": "optional_header"}`. Unknown bits surface as `UNKNOWN(<bit>)`; names follow the PE specification.
  - `dll_characteristics`: Compat alias for one release — the joined form of `dll_characteristics_structured.flags` (`"HIGH_ENTROPY_VA, DYNAMIC_BASE, NX_COMPAT"`). Consumers should move to the structured block; the string is scheduled for removal.

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
  - Kept for one release after the structured `code_signature` block below landed (additive rule); `verification_flags` is LIEF's *structural* verdict, not trust.

- **Code signature (`code_signature`):** the structured Authenticode block, parsed by `blint/lib/pe_signature.py` from the certificate table's DER (`WIN_CERTIFICATE` entries of type `PKCS_SIGNED_DATA`), mirroring the Mach-O `code_signature` block so both formats answer the same questions (W2.1/W2.2). `trust_validation` is `not_performed` in band — blint names chains, it never validates trust (no root-store anchoring, no revocation), so "signed" is never readable as "trusted".
  - `parse_status`: `parsed`, `malformed`, or `absent`. A present-but-unwalkable table or signature is `malformed` with a `parse_error` reason and per-signature `signature_errors` — never folded into a confident "unsigned".
  - `scope`: `embedded` when a certificate table exists, `catalog` when a `--catalog-dir` lookup matched the file's authentihash against a catalog member (W2.3; `blint/lib/pe_catalog.py`), `none` otherwise. Embedded wins: a table present is `embedded` even when a catalog would also match, because Windows uses the embedded blob first.
  - `catalog_lookup` — the three states, and the honesty each requires: `not_performed` (no `--catalog-dir` supplied; a catalog-signed file cannot be distinguished from an unsigned one, so nothing may read `is_signed: false`), `positive` (the authentihash matched a catalog member), `negative` (the lookup was performed against a **complete** index and the file is in none of its catalogs — the only state from which "genuinely unsigned" follows; `CHECK_AUTHENTICODE` fires only here), and `index_incomplete` (a directory was supplied, the hash was **not found**, and the index refused or truncated catalogs, or found none — "not found in the part of the index we built" is not "not signed"). Only the negative needs a complete index: a hash the index did store is proof regardless, so a positive match still resolves against an incomplete index and carries `catalog_index_incomplete: true` beside it. `catalog_lookup_error: "authentihash_unavailable"` names the rare case where the file's reference hashes could not be computed at all.
  - `catalog` (on a `positive` match): `path` (the matching `.cat` file), `member_hash` (the hex that matched) and `member_hash_algorithm` (`SHA256` preferred, `SHA1` fallback — catalogs store one entry per width and do not name the algorithm in band; it is implied by the digest width). `catalog_directory` states the `--catalog-dir` the index was built from whenever one was supplied. On a positive match `signatures[]` is repopulated from the catalog's own signer through the same walk, so a consumer reads one block for both scopes (rule 21), and `structural_integrity` states the byte equality between blint's computed authentihash and the catalog's stored member hash. `catalog_signature_errors` marks a member match whose catalog signer could not be read — a structural match, not a readable one.
  - Catalog files as input (W2.3): a `.cat` is PKCS#7 `SignedData` whose encapsulated content is a CTL (`1.3.6.1.4.1.311.10.1`). Both layouts parse by member-entry shape — simplified package catalogs (entries in a plain SEQUENCE, every member as a SHA-1 + SHA-256 entry pair) and the classic RFC 5283-style CTL (version INTEGER first, entries under `[1] IMPLICIT`, `CatalogNameValue`/`CatalogMemberInfo` attributes naming member and indirect-catalog files). Index limits (ground rule 30): 32 MiB per catalog file, 65,536 members per catalog, 8,192 catalogs and 1,000,000 entries per index, 65,536 files walked — tripping any of them is a recorded degradation that marks the index incomplete, and counts beside capped stores stay exact.
  - `certificate_entries` (exact), `certificate_revision`, and `unparsed_certificate_entries` for non-PKCS#7 table entries.
  - `signatures`: a **list** — dual signing is the normal case, not an exception. `signature_count` is exact unless `signature_walk_truncated` is present, which says the hostile-input walk window (64 signatures, nested included) stopped short — the count is then a floor, and so is the listing beside it. Each entry:
    - `digest_algorithm` — the SignerInfo digest (`SHA256`, `SHA1`, dotted OID when unmapped).
    - `signer`: `cn`, `o`, `serial` (hex), `not_before`/`not_after` (ISO 8601 Z), `issuer_cn`, `eku` (named: `codeSigning`, `whql`, `kernelModeCodeSigning`, …; dotted OIDs when unmapped).
    - `chain`: the certificates the blob ships above the signer (leaf's issuer upward) — `cn`, `o`, `serial`, `is_ca`, `issuer_cn`. `chain_length` is exact and `chain_truncated` marks a listing past the 16-entry window — unless `chain_length_exact: false` says the chain ran past the certificate parse window (32), in which case the length is a floor and `chain_terminates_at`/`chain_complete` are `null`: a walk that ran out of parsed certificates found the end of the window, not the end of the chain. Otherwise `chain_terminates_at` names the last link's CN and `chain_complete` says whether that link is self-signed (a root) — a chain the blob leaves incomplete says so rather than implying a root it never carried. `signer_certificate_not_parsed` marks the case where the signer's own certificate was past that window, so a `null` signer is not read as one the blob never carried.
    - `timestamp`: `{"present": true, "kind": "rfc3161"|"pkcs9", "time": "<ISO>", "tsa_cn": "<CN>", "signature_valid_at_timestamp": true|false}` — both countersignature forms are extracted (`countersignatures` lists every one) and validity is stated **relative to the timestamp**, because short-lived certificates make "is the cert expired?" the wrong question. Nested signatures state `inherited: true` when they reuse the outer signature's timestamp. With no timestamp at all: `{"present": false}` and `expires_hard: true` — such a signature really does stop being verifiable at certificate expiry (`CHECK_SIGNATURE_NOT_TIMESTAMPED`).
    - `page_hashes`: `{"present": true, "count": <exact>, "algorithm": "SHA256"}` from the `SpcPeImageData` moniker. Presence is a hardening property; blint does not recompute them and claims no verification.
    - `opus_info` (`program_name`, `url` when present), `statements` (individual/commercial code signing), and `digest` — the per-signature `structural_integrity`: `algorithm`, `embedded`, `computed` (the authentihash blint recomputed) and `digest_match`. When blint does not recompute (unsupported algorithm), the block says `recompute: "not_performed"` instead of echoing the embedded value.
  - `structural_integrity`: the same facts for the first signature whose digest blint recomputed.
  - `weak_digest_only`: true only when **no** signature, nested ones included, uses a modern digest — the outer SHA-1 of a dual-signed binary is not a SHA-1-signed binary (`CHECK_WEAK_SIGNATURE_DIGEST`). `null` when `signature_walk_truncated` cut the walk short before a modern digest was seen: the verdict needs every signature, so a walk that saw only some of them declines it rather than guessing true.
  - `signing_class` (W2.4, plan 02/C): what *kind* of signed this file is, derived from facts the walk already carries — `self_signed` (the signer certificate is its own root), `kernel_mode` (EKU `1.3.6.1.4.1.311.61.1.1`), `attestation_signed` (EKU `1.3.6.1.4.1.311.10.3.5.1`, `szOID_ATTEST_WHQL_CRYPTO`: attested rather than HLK-tested; a signer certificate carrying both this and the WHQL EKU — the Hardware Compatibility Publisher cert does — decides as `attestation_signed`, the stricter child OID), `whql` (EKU `1.3.6.1.4.1.311.10.3.5`), `microsoft_1st_party` (a Microsoft leaf — the exact subject organization from `blint/data/pe_publisher_identities.yml` — whose chain anchors at a Microsoft root, either by fingerprint when the blob ships the root or by the top shipped link's issuer naming a Microsoft root in the anchor snapshot — `signing_class_anchor` says which of the two, and it is worth reading: 223 of the 224 first-party classes measured across tiers 0/1/5 are `issuer_name`, an issuer CN the signer wrote rather than a root blint hashed), `commercial_ev` / `commercial_ov` (code-signing EKU plus, respectively, the CA/Browser Forum EV policy OID `2.23.140.1.3`, or an OV policy / an organization on the signer), `unknown_root` (a complete chain whose self-signed root's SHA-256 fingerprint is outside the shipped snapshot), and `unsigned` — which follows **only** from `catalog_lookup: "negative"`, a performed lookup against a complete index. When the inputs do not determine a class the key is **absent, and its absence means undetermined — never `unsigned`**: no catalog directory was supplied, the index was incomplete, the signature walk was truncated, or the signer's facts (no EKU, no policy, no organization, no anchor) name nothing in the class table. A truncated walk never yields a class — a verdict is not decided from a sample, the same discipline `weak_digest_only` follows. Within one signature the chain decides before the leaf: `self_signed` and `unknown_root` outrank the leaf-stated classes, because a self-issued chain shipped whole still carries a code-signing EKU and an organization name and would otherwise read as `commercial_ov`. The class is decided by the first signature in walk order whose facts determine one (the primary signature first, the order Windows evaluates them); `signing_class_signature` names the deciding index when it is not the first. Catalog-scope blocks derive the class from the catalog's own signer, the same way.
  - Root-anchor facts, per signature: `root_fingerprint` (SHA-256 of the self-signed certificate the chain terminates at), `root_known` (whether that fingerprint is in the shipped snapshot) and `root_microsoft` (whether the snapshot flags it as a Microsoft-operated root) — stated only when the walk actually reached a self-signed certificate. Where the blob ships leaf and intermediates but no root — the normal Authenticode shape — nothing is claimed about the root; the top shipped link's `issuer_cn` is still the anchor name a consumer can read.
  - The shipped root snapshot (`blint/data/pe_roots.yml`) is **data with provenance**: what was hashed (the DER of every trusted root certificate), from which stores (`LocalMachine\Root`, `LocalMachine\AuthRoot`), on which date, at which Windows build — regenerate with `tests/scripts/generate_pe_roots.py` against a newer store export. Matching a chain's terminating root against it is a statement about the file, not about the world: blint performs no trust validation, consults no live store, fetches no CRL/OCSP data and builds no chain beyond what the signature blob itself ships (`trust_validation` stays `not_performed`), so a root outside the snapshot reads as "outside the shipped snapshot", never as untrusted in the CryptoAPI sense — blint does not claim parity with `signtool verify`, which resolves live trust; blint states structure.
  - `signer.policies` (when the signer carries certificatePolicies): the CA/Browser Forum code-signing policy OIDs, named (`evCodeSigning` `2.23.140.1.3`, `ovCodeSigning` `2.23.140.1.2.1`, `individualCodeSigning` `2.23.140.1.2.2`; dotted OIDs when unmapped).
  - Rules that consume the block: `CHECK_SIGNATURE_NOT_TIMESTAMPED` and `CHECK_WEAK_SIGNATURE_DIGEST` (W2.2), and the W2.4 additions — `CHECK_SELF_SIGNED` (the signer vouches only for itself), `CHECK_SIGNATURE_UNKNOWN_ROOT` (complete chain to a root outside the shipped snapshot; a chain that stops below the root is never reported, because the blob not carrying a root says nothing about the root), `CHECK_KERNEL_SIGNING_CLASS` (informational; the kernel-signing class, consumed by the driver lane), and `CHECK_SIGNER_MISMATCH` (the VERSIONINFO `CompanyName` claims a publisher from `blint/data/pe_publisher_identities.yml` whose identity tokens the signature's signer does not carry — the one-directional impersonation check; the reverse, a publisher signing software whose CompanyName names an acquired brand or an upstream project, is normal and never a finding). All four follow the class verdict and stay silent when it is withheld.

- **Managed metadata (`dotnet`):** the ECMA-335 CLI block, parsed by `blint/lib/pe_dotnet.py` from the `#~`/`#-` table stream and the `#Strings`, `#Blob`, `#GUID` and `#US` heaps (W3.1, plan 03/A.1). Present only for binaries carrying a CLI header (data directory 14) — those binaries are also `exe_type: "dotnetbinary"`, decoupled from bitness (the other half of #114), with `is_dotnet` keeping its old meaning for existing consumers.
  - `parse_status`: `parsed` (clean), `partial` (read with named degradations), `malformed` (structure unusable). Partial and malformed both land in `analysis_coverage.degradations` (`dotnet_metadata_partial`, `dotnet_metadata_malformed`) so a thin result never reads as clean. Absence of the whole block means "no CLI header", never "assembly without dependencies".
  - `runtime_version`: the metadata root's version string (`v4.0.30319`, `v2.0.50727`).
  - `cli_flags` / `cli_flags_value`: the `COMIMAGE_FLAGS` decoded through blint's own name table (`ILONLY`, `32BITREQUIRED`, `IL_LIBRARY`, `STRONGNAMESIGNED`, `NATIVE_ENTRYPOINT`, `TRACKDEBUGDATA`, `32BITPREFERRED`) plus the raw bitfield.
  - `assembly`: identity from the Assembly table — `name`, `version` (four-part), `culture` (`neutral` when the string index is 0), `public_key_token` (the eight-byte token; for full-key blobs the low eight bytes of SHA-1 reversed, for eight-byte blobs the blob itself, absent when there is no key), `hash_algorithm` (+ `hash_algorithm_id`), `mvid` (the module GUID, dumpbin canonical form).
  - `target_framework`: the `System.Runtime.Versioning.TargetFrameworkAttribute` value (`.NETFramework,Version=v4.5`, `.NETCoreApp,Version=v8.0`), decoded from the custom-attribute blob (prolog + SerString). Absent when the attribute is absent — .NET Framework 2.0-4.0 assemblies legitimately carry none.
  - `assembly_refs`: the AssemblyRef table as `{name, version, culture, public_key_token}` rows, in table order. These become `pkg:nuget/<name>@<version>` SBOM components whose purl carries the public key token as a `token` qualifier (`pkg:nuget/Newtonsoft.Json@13.0.0.0?token=30ad4fe6b2a6aeed` — W3.5; a non-neutral culture rides as an `internal:culture` property). The version is the four-part *assembly* version, which is not the NuGet package version — Newtonsoft.Json 13.0.3 ships assembly version 13.0.0.0 — so every such component carries `internal:version_source: assembly_version`, and where a `.deps.json` overlay already named the package the overlay's component wins: one package, one component, never the same library twice at two kinds of version. Listing capped at 1,024 with `assembly_refs_listed_capped`; `counts.assembly_ref` stays exact. The SBOM parent of a managed file mirrors how complete this table's evidence is as `internal:dotnet_assemblyref_state` (see `docs/CUSTOM_PROPERTIES.md`).
  - `module_refs`: the ModuleRef table — the native DLLs named as P/Invoke scopes. Capped at 256 with `module_refs_listed_capped`.
  - `pinvoke`: the ImplMap surface — `{module, entry_point, method}` rows, the managed analogue of the import table. Capped at 512 with `pinvoke_listed_capped`. Mixed-mode C++/CLI images ship ImplMap rows for native IJW methods with an empty `ImportName`; the Windows oracle treats an empty import name as no P/Invoke entry (SRM skips `Name.IsNil` rows), blint matches, and the rows still count in `counts.implmap`. Each distinct module also joins `dynamic_entries` under the `PINVOKE` tag: a DllImport maps at first call, not at image load, so it is a declared dependency the import table never carries — the declaration set, the dependency graph and `CHECK_UNDECLARED_DEPENDENCIES` (whose scope includes `dotnetbinary` since W3.2) read it.
  - `typerefs` (W3.2): the TypeRef table as `{name, scope}` rows in table order — the referenced types with the assembly (or module of this assembly) each comes from. An AssemblyRef scope renders as the assembly's bare name (`mscorlib`); a ModuleRef or the Module row renders as `module:<name>` — a type provided by a module of this assembly is a different fact from one provided by another assembly, and the two never collapse. A nested TypeRef (scope naming an enclosing type) follows its enclosing row to the scope that names a provider. Rows whose scope cannot be resolved are omitted and named (`typeref_scope_unresolved`) rather than read as module-provided; listing capped at 1,024 with `typerefs_listed_capped`.
  - `memberrefs` (W3.2): the MemberRef table as `{name, parent}` rows in table order — the referenced members with the type, module or method that defines them (`Type::member`, `module:<name>`, `method:<name>`). A TypeSpec parent is a generic instantiation — a signature blob, not a name — so those rows are not rendered; `memberrefs_typespec_parents` carries their count as a fact (it is not a degradation and does not flip `parse_status`). Unresolvable parents are omitted and named (`memberref_parent_unresolved`); listing capped at 16,384 with `memberrefs_listed_capped`. The cap is deliberately far above the largest table measured (8,126 rows across 790 assemblies) because it is a *detection* boundary and not only a listing one — `review_managed_dotnet` matches on this list, so a row past the cap is a capability blint never looks for.
  - `user_strings_count` / `user_strings_sha256` (W3.2): facts about the `#US` heap walk — the exact number of entries decoded, and a SHA-256 over each value's UTF-8 bytes plus a 0x00 separator in heap order (the digest the ground-truth oracle computes, so the two walks compare byte for byte). Absent entirely when the assembly ships no `#US` heap (`us_heap_missing` — legitimate for facade assemblies, and never read as "zero strings"); a clean empty heap reports a zero count and the empty-input digest.
  - `strings` (block-level, W3.2): the walked #US literals promoted to the top-level `strings` key by `binary.parse` (which also sets `strings_source` to `user_strings_heap`, or `user_strings_heap+binary_scan` where the native byte scan contributed values the heap cannot know — mixed-mode native strings). Admission is by length only (4–4,096 characters; the native scan needs an entropy gate because a byte scan cannot tell a literal from noise, but a #US entry *is* the literal — the dex path ships raw strings the same way). Capped at 4,096 entries with `user_strings_listed_capped`; walk-level bounds: 262,144 entries, 64 MiB decoded, 1 MiB per entry (a longer entry is skipped and named, not fatal); a walk that stops early reports the prefix's count and digest and names `user_strings_heap_truncated`.
  - `counts`: declared row counts for the tables the block consumes (`typedef`, `methoddef`, `field`, `typeref`, `memberref`, `assembly_ref`, `module_ref`, `implmap`, `assembly`). Real streams leave zero-row tables out of the Valid mask, so an unset bit means zero rows (the reader looked); only a table the overrun logic dropped stays absent.
  - `entry_point`: from the CLI header token — `{token, method, type}` when the token resolves through MethodDef (or through MethodSpec to one), with `type` the declaring TypeDef's namespace-qualified name; `{token, kind: "native"}` when `NATIVE_ENTRYPOINT` is set (the token is an RVA, not a metadata token — mixed-mode images); token-only plus `entry_point_unresolved` when the token names no readable row. Absent for DLLs without an entry point.
  - `shape` (W3.3, plan 03/A.3): how the application was **published**, as `{kind, evidence}` and — for a single-file publish — the decoded `bundle` manifest. `kind` is one of `il_only`, `ready_to_run`, `mixed_mode`, `native_image_unknown`, `single_file_bundle`, `native_aot` or `apphost`, and `evidence` names the facts that decided it. Unlike the rest of this block, `shape` is also emitted for PEs with **no** CLI header: a single-file bundle and a NativeAOT image are .NET applications whose managed origin is invisible to a metadata reader, and reporting them as ordinary native binaries would be exactly the "absence reads as clean" that ground rule 32 forbids. Those two carry `parse_status: "no_cli_metadata"` — `is_dotnet` stays false and `exe_type` is unchanged, because there is no CLI metadata for the managed rules to read.
    - `ready_to_run` is decided from the CLI header's ManagedNativeHeader pointing at an `RTR\0` signature, and is decided *before* the `ILONLY` flag is consulted: the ReadyToRun assemblies the .NET 11 SDK produces have `cli_flags_value` `0x4`, so ILONLY is clear on an ordinary R2R build and a mixed-mode test that ran first would call every one of them C++/CLI. A ManagedNativeHeader that is present but is not an R2R one is `native_image_unknown`, never folded into `il_only`.
    - `single_file_bundle` vs `apphost` turns on the `int64` immediately *before* the 32-byte bundle signature, not on the signature itself: every .NET apphost embeds the signature as a placeholder whether it was bundled or not (measured at offset 71,856 in the framework-dependent, self-contained and trimmed apphosts), and what the bundler writes is the manifest's file offset. Zero means unbundled. A written offset whose manifest cannot be decoded still reports `single_file_bundle` with `bundle_header_unreadable` — a bundle blint could not read, not a host with no payload.
    - `bundle` carries `version`, `bundle_id`, `member_count`, the `deps.json`/`runtimeconfig.json` sizes and `members`: one `{path, offset, size, type}` entry per embedded file (`type` is `assembly`, `native_binary`, `deps_json`, `runtime_config_json`, `symbols` or `unknown`), listed up to 4,096 with `members_listing_capped`. No rule reads that list, so the cap bounds metadata size and not detection. A manifest that stops mid-entry is `members_truncated` instead — blint's own bound and a damaged file are different facts (ground rule 14).
    - `native_aot` requires **two** conditions, because neither alone is specific: a `DotNetRuntimeContractDescriptor`/`DotNetRuntimeDebugHeader` export *and* an `RTR\0` header in an initialized, non-executable section. `coreclr.dll` exports the same descriptor and is an ordinary native runtime DLL; the measured NativeAOT image also contains the four signature bytes inside `.text` as instruction encoding, which is why the section restriction is part of the test.
    - Measured false positives before it shipped: over a full `C:\Windows\System32` (3,984 PEs, 0 parse errors) the classifier emits a shape for 15 files and stays silent on 3,969 — 7 `il_only` and 8 `mixed_mode`, the latter all real C++/CLI images (the MFC managed-interop DLLs, `dnscmmc`, `NAPCRYPT`), and not one `native_aot`, `single_file_bundle` or `apphost` among the native PEs.
    - A self-contained single-file publish embeds the managed assemblies but not the native runtime: the measured bundle lists 182 assemblies plus `deps.json` and `runtimeconfig.json`, and the 15 native runtime files beside the equivalent self-contained publish (`coreclr.dll`, `clrjit.dll`, `hostfxr.dll` and the rest) are not members — the runtime is linked into the host image itself, whose sections total 11.7 MB against the plain apphost's 76 KB. So the member list is the shipped *managed* set, which is what it says and all it says.
    - What `shape` deliberately does **not** claim: whether a publish was framework-dependent, self-contained or trimmed. Those differ only in the contents of the output *directory* (5, 200 and 27 files in the measurement), not in any byte of the binary blint is handed.
  - `strong_name` (W3.4, plan 03/A.4): the strong-name facts as **separate presence facts, never one verdict**. Strong names are distinct from Authenticode and are never merged with the `code_signature` block: a strong name says the assembly's identity is bound to a key, Authenticode says a publisher vouched for the file, and an assembly can have either, both or neither. The block carries no verification result anywhere — blint does not hash the assembly with the signature region excluded, so no field here may be read as "the signature verifies".
    - `declares_public_key` / `public_key_size` / `public_key_token`: whether the Assembly row's `PublicKey` blob is present, its size in bytes (160 for the 1024-bit RSA keys every assembly measured ships; 8 when the column holds a bare token), and the token **computed** from the key (the same `public_key_token()` the identity block flows from — the two tokens can never disagree). Absent rather than false when the Assembly table itself could not be read.
    - `strongnamesigned_flag`: the CLI header's `COMIMAGE_FLAGS_STRONGNAMESIGNED` bit, restated beside the facts it belongs with. It is a header bit, not a verdict: a `/publicsign` build sets it over an all-zero signature region.
    - `signature_present` / `signature_size` (and `signature_all_zero`): the CLI header's `StrongNameSignature` directory (RVA/size at offset 32 — the field W3.3 did not read, two fields before the `ManagedNativeHeader` it did). `signature_all_zero` states whether the region's bytes are all zero, **the fact a delay-signed assembly ships** — and a public-signed one too (measured: 215 of 1,186 .NET 10 shared-framework assemblies carry a null signature with the flag set; a delay-signed build carries one with the flag clear). It is emitted only over bytes blint read in full: an unmapped RVA (`strong_name_signature_unmapped`), a declared size past the 4 KiB read bound (`strong_name_signature_exceeds_cap`) a region running past end of file (`strong_name_signature_short_read`) or a directory whose two halves contradict each other — a size with no RVA, or an RVA with no size (`strong_name_signature_directory_half_declared`, reported as `signature_present: false` because no region exists, with the contradiction in the degradation rather than in a number) — withholds the field and names the reason — an absent region reports `signature_present: false` and **omits** `signature_all_zero` rather than vacuously calling it true.
    - `delay_sign`: an `AssemblyDelaySignAttribute(true)` row exists. This is the one metadata location that names DelaySign, and it is rarely written: Roslyn consumes the pseudo-attribute and emits no row (measured with and without `/delaysign`, attribute in source or not), so a Roslyn delay-signed assembly reports `delay_sign: false` and shows its shape in `signature_all_zero` instead. Rows survive from toolchains that write them — the MSVC-managed MFC pair (`mfcm140.dll`) carries one **over a fully-written signature**, which is exactly why this is a fact and not a verdict.
    - `internals_visible_to` / `internals_visible_to_count`: the friend assembly names the `InternalsVisibleToAttribute` rows name — an attack-surface fact, because a friend name is a name anyone can build an assembly under when the key does not constrain it. Each entry is `{name, public_key?, public_key_token?}`: the name byte-exactly as stored, any `PublicKey=` the string names, byte-exactly as the string writes it (a value that is not parseable hex is still reported, with `internals_visible_to_public_key_invalid` named and no token emitted), and the token computed from that key. Only rows parented on the Assembly row are listed — the scope the runtime honours and the ground-truth oracle walks. A strong-named parent must key its friends (CS1726); a keyless friend under an unsigned parent is legal and reports `name` alone. Listing capped at 128 with `internals_visible_to_listed_capped` and the exact count in `internals_visible_to_count`; **no rule reads this list**, so the cap bounds metadata size and not detection. The largest count measured across 1,248 assemblies is 55 (`System.Private.Windows.Core.dll`).
  - Bounds (ground rule 30): stream count ≤ 16, version area ≤ 1 KiB, string reads ≤ 4 KiB (a longer entry is `strings_entry_truncated_by_cap` when a NUL exists beyond the window, `strings_entry_unterminated` when one does not), blob reads ≤ 64 KiB, declared rows must fit the stream (`tables_exceed_stream` drops the tables from the first overrun on, and their counts stay absent rather than being reported as facts), unknown tables (`0x30+`, portable-PDB space) stop the layout instead of guessing row widths. Every refusal is a named degradation in the block; a table blint could not read never reads as "this assembly has no X".
  - `table_stream_heapsizes_unhandled:<byte>`: the table stream's HeapSizes byte carries a bit beyond the three heap-index widths. Those bits mark delta-only and extra-data metadata and move where the rows begin; no assembly measured sets one, so blint names the shape rather than laying rows out on an assumption.
  - Layout cross-check: a correct row layout accounts for the whole table stream bar an alignment tail (measured at 0, 2 or 4 bytes over 375 real assemblies). A larger shortfall means the computed column widths are not the writer's, so every row read under them is some other table's bytes — `tables_layout_short:<bytes>` is named and every row-derived fact (`assembly`, `assembly_refs`, `module_refs`, `pinvoke`, `entry_point`, `target_framework`, the strong-name block's key/attribute facts) is withheld rather than reported. `counts` survives, because the row-count array is header data independent of the widths. The CLI-header half of `strong_name` (`signature_present`, `signature_size`, `signature_all_zero`, `strongnamesigned_flag`) survives too — those are header facts, not row-derived.

- **Resources (`resources`):** Metadata extracted from the `.rsrc` section.
  - `version_metadata`: Contains key-value pairs like `ProductName`, `CompanyName`, and `FileVersion`. Useful for identifying the software and its origin.
  - `manifest`: The embedded XML application manifest, which controls privileges, dependencies, and UI settings.
- **Debug directory (`debug`):** one block per image, decoded in `blint/lib/pe_debug.py`. Added with the W1.1 packet (plan 01/A.4-A.5); an image with no debug directory reports nothing, and the security-properties gaps carry the absence.
  - `entries`: one row per `IMAGE_DEBUG_DIRECTORY` entry — `type` (named from blint's winnt.h table in `pe_constants`, `UNKNOWN(<value>)` for untabled values), `type_value`, `timestamp`, `size`, plus the raw addresses. More than 64 entries are counted under `entries_truncated` rather than decoded.
  - `codeview`: the PDB lookup key — `signature` (`RSDS` or the legacy `NB10`), `guid` (canonical dumpbin form for RSDS), `age`, `pdb_path` and `pdb_filename` (split on both `\` and `/`). This block is the single source feeding `security_properties.debug_info` / `debug_info_pdb_path`.
  - `repro`: `{"present": true, "hash": "<hex>"}` (the length-prefixed image hash, 32 bytes on current `/Brepro` builds) when the image carries an `IMAGE_DEBUG_TYPE_REPRO` entry, `{"present": false}` when a directory exists without one. This is the authoritative reproducibility answer; `is_reproducible_build` (LIEF, timestamp-based) stays alongside as the legacy heuristic — when they disagree, `repro` wins.
  - `vc_feature`: the `IMAGE_DEBUG_TYPE_VC_FEATURE` counters (`c_cpp`, `gs`, `guards`, `sdl`, `pre_vcpp`).
  - `pogo`: the PGO section list (`sections`, capped at 256 with `sections_truncated`/`sections_total`) and the `signature` (`PGO`/`PGU`).
  - `ex_dllcharacteristics`: the `IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS` payload decoded through blint's `EX_DLL_CHARACTERISTICS` bit table (`CET_COMPAT`, ...).
- **Rich header (`rich_header`):** decoded and validated at the byte level in `pe_debug.py`; replaces the raw LIEF entry dump when the header can be read (the LIEF shape stays as the fallback). Entries are in file order.
  - `key`: the XOR key, rendered as `0x...`.
  - `checksum_valid`: the stored key is the checksum of the DOS region plus the header itself (algorithm per the RichHeaderResearch RichPE tooling, validated on real MSVC images); a `false` here is a repacking/tampering signal, never a parse error.
  - `entries`: the raw records, `{id, build_id, count}` in file order.
  - `decoded`: each record named through the generated comp.id tables in `blint/data/pe_rich_compids.yml` (provenance in the file header; regenerate with `tests/scripts/generate_pe_rich_compids.py`): `{product_id, tool, label, build_id, count}` — the label names the exact Visual Studio drop, e.g. python313.dll's `LNK VS2022 v17.14.9 build 35213`. Unknown pairs still name the tool from the 16-bit product id; wholly unknown products render `UNKNOWN(<id>)`.
  - `toolchain`: `linker_build_id` and `linker_label` from the linker record, `comp_id_builds`, and `mixed_toolchain` (objects built by more than one drop — vendored static libraries are the benign case, a rewritten header the interesting one). This also feeds the `toolchain` block's `msvc` compiler entry.
- **VERSIONINFO (`version_info`, top level):** the full VERSIONINFO decode, added with W1.3 (plan 01/A.7); the string tables are parsed from the raw resource by blint because LIEF 1.0 drops valid tables and merges adjacent language tables. This block is the input for the Windows SBOM identity work (03/D) and the tier 0-1 presence gate.
  - `present`, `languages`: sorted language keys (`040904b0`, ...).
  - `strings`: `{language: {KeyName: value}}` — every key of every language table.
  - `fixed`: the `VS_FIXEDFILEINFO` block decoded from the raw resource (LIEF 1.0 does not expose it): `file_version`/`product_version` in `MS.LS` dotted form, `file_flags` through the mask (`DEBUG`, `PRERELEASE`, `PATCHED`, `PRIVATEBUILD`, `INFOINFERRED`, `SPECIALBUILD`), `file_os`, `file_type`, `file_subtype`. Absent when the resource carries strings only.
  - `mismatches`: which of `FileVersion`/`ProductVersion` disagree between the fixed block and the string table — the classic tampering tell. The comparison is semantic (first two numeric components), so a fixed `3.13.7150.1013` beside a marketing string `3.13.7` is agreement, not a finding.
- **Resources depth (`resources` extensions):** the legacy `has_*` booleans, the raw `manifest` XML and the flattened `version_metadata` are unchanged; W1.3 adds:
  - `manifest_parsed`: the manifest decoded — `requestedExecutionLevel`, `uiAccess`, `dpiAware`/`dpiAwareness`, `longPathAware`, `activeCodePage`, `supportedOS` GUIDs mapped to Windows names, and `assembly_identities` (side-by-side dependencies). A present-but-unparseable manifest records `parse_status: failed` rather than reading as "no elevation requested".
  - `tree_summary`: resource type → `{count, bytes, entropy}`. Type names come from blint's RT_* table; entropy samples two 64 KiB windows (start and end) per resource so a multi-MB blob is summarized without being read in full.
  - `hashes`: per-resource SHA-256 (`type`, `id`, `lang`, `size`, `sha256`), truncated at 1 MiB per resource with `hash_truncated` and a recorded degradation beyond a 32 MiB total budget.
  - `icon_hash`: deterministic SHA-256 over the sorted per-icon digests — the cluster key for "same icon" identity.
  - `embedded_pe`: resources whose data starts with a structurally valid PE image (MZ, e_lfanew inside the data, `PE\0\0` there), each with its `type`, `id`, `file_offset` and `size` — a dropper indicator reported as a fact, not a finding.
  - `degradations`: every limit the tree hit (node count, depth, hash budgets, embedded-PE report cap) is recorded here, never silently skipped (ground rule 30: the resource tree is attacker-controlled input).
- **Imports and Exports (`imports`, `exports`):**
  - `imports`: A list of all functions imported from external DLLs, grouped by library. Forms the basis of the `imphash`.
  - `exports`: A list of all functions this binary provides to other executables.
  - W1.2 import depth (`blint/lib/pe_imports.py`):
    - Ordinal-only imports are resolved through the generated ordinal snapshot (`blint/data/pe_ordinals.yml`, sourced from the six DLLs whose ordinals are stable and common: `ws2_32`, `mpr`, `oleaut32`, `shlwapi`, `netapi32`, `wsock32`; the snapshot records the Windows build and the source files' sha256). A resolved entry carries `ordinal` plus `resolution: "ordinal_table"`; an ordinal outside the snapshot stays an ordinal — its `short_name` renders `#<ordinal>` and `resolution: "unresolved"`. The two outcomes are never conflated.
    - API set contracts (`api-ms-win-*`, `ext-ms-*`) resolve through the generated snapshot of `apisetschema.dll` (`blint/data/pe_apisets.yml`, which records the Windows build it came from; contract versions the schema dropped are restored from the `System32\downlevel` stub DLLs' forwarder exports). A resolved entry's dependency identity is the host DLL, with the original contract name kept in `apiset` (per entry) and `apisets` (per dependency-list entry); a contract missing from the snapshot keeps its own name. Regenerators live in `tests/scripts/`.
    - `delay_imports[]`: the delay-load import table in the same shape as `imports` — never merged with it, the distinction is the signal — plus `delay_import_hash`, the same normalization as `import_hash` over the delay table only.
    - `import_resolution`: exact counts for the image — `ordinals_resolved`, `ordinals_unresolved`, `apisets_resolved`, `apisets_unresolved` — with capped (`ordinals_unresolved_capped`, `apisets_unresolved_samples`) samples naming what fell back.
    - `dynamic_entries` gains a `tag` vocabulary beside `NEEDED`: `DELAYLOAD` for a DLL reached only through the delay-load table and `FORWARDER` for an export-forwarder target (see below), so the SBOM sees the dependency without conflating the tables. An apiset-resolved NEEDED entry carries `apisets: [...]` listing the contract names it stands in for.
  - Export forwarders: an export whose target lives in another DLL records `forwarded_to` in dumpbin's form (`"NTDLL.RtlAllocHeap"`) beside the existing `fwd_library`/`fwd_function`, and the target DLL joins `dynamic_entries` (tag `FORWARDER`) and the `import_dependencies` graph (library type `forwarder_target`) — the loader maps it even though no import-table entry names it.
- **Layout forensics (`layout`):** the section-table and header facts of B.5, each a named field, computed from the section table, optional header and file size. Fields that would be vacuous are omitted, not defaulted (a zero entry point computes no placement fields; a single-section image omits `entry_point_in_last_section`, which is vacuous there):
  - `entry_point_section`, `entry_point_outside_text` (computed only when a `.text` exists to be outside of), `entry_point_in_last_section`, `entry_point_outside_any_section`.
  - `sizeof_image_expected` and `sizeof_image_mismatch`: what the section table adds up to versus what the optional header claims.
  - `zero_raw_size_sections`, `large_virtual_zero_raw_sections` (no file bytes, a page or more of mapped space — the unpacker-stub shape; the ordinary `.bss` appears here too, it is a fact list, not a verdict), `raw_exceeds_virtual_sections`.
  - `non_standard_sections` and `section_naming_toolchain`: names outside the named toolchain's section set (MSVC's documented `.00cfg`, `.hexpthk`, `.a64xrm`/`fothk` ARM64X/EC sections count as standard; `/nnn` COFF string-table long names are the spec's encoding, not custom names). The toolchain comes from the rich header (W1.1), the Go and .NET markers, else `unknown` (key omitted; the generic prefix set applies).
  - `truncated_last_section`: the last section's raw bytes run past end of file.
  - `timestamp` (header `TimeDateStamp`), `timestamp_epoch_zero` (the `/Brepro` shape), `timestamp_in_future`. A future stamp on a `/Brepro` build is expected — correlate with `debug.repro.present`.
- **Pre-main execution (`pre_main_execution`):** the one summary of what runs before `main` (B.1); the legacy top-level `tls_callbacks` address list keeps its shape.
  - `tls_callbacks`: one row per callback — `address`, and `function`/`resolved: true` when the address matched a discovered function.
  - `tls_directory_writable` and `tls_callback_array_writable` (with `tls_callback_array_section`): the writability of the TLS directory struct and of the callback array the loader walks — a writable array is the runtime-patchable shape. Both are stated either way; the array pair is omitted only when no section covers the array.
  - `ctor_functions` (static initializers) or, when LIEF's PE initializers are exactly the TLS callbacks (it derives them from the callback array), `initializers_are_tls_callbacks: true` — one fact, not a duplicate list.
  - `callback_count`, `initializer_count`: exact counts, never the size of the capped listing; `tls_callbacks_truncated` and `initializers_truncated` say when the listings stop short of them.
  - `anti_debug_reachable_functions`: only when disassembly ran and a resolved callback's call targets reach one of a fixed set of debugger-awareness imports (`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtSetInformationThread`, `NtQueryInformationProcess`).
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
  - Recovery is a fixed-point dataflow over the function's CFG: a register or frame byte survives a control-flow merge only when every incoming path agrees on its value, and blocks unreachable from the entry contribute nothing. A value assembled on one branch of a conditional is therefore not reported — treat entries as paths that certainly execute, and confirm the reconstruction before acting on it.
  - `stack_strings_coverage` records how the pass covered the binary: `functions_total`, `functions_dataflow` (CFG fixed point), `functions_fallback` (no usable CFG — straight-line pass), and `functions_iteration_cap_hit` (the loop iteration cap was reached; those functions contribute no entries, because a half-converged state is residue rather than evidence).

- **Call-site constant arguments (`call_site_arguments`, requires `--disassemble`):** The integer constants an image holds in the ABI's argument registers at calls the disassembler resolved to a named callee. A capability review can only say an image is _linked_ to an API; this block says _what_ it passes to it — which control code reaches `DeviceIoControl`, which algorithm constant reaches `CCCrypt`, which path string reaches `CreateFile` when the constant points into a string section.
  - One entry per distinct `(callee, argument, value)` triple, sorted, each with `argument` (0-based position in the callee's integer argument list), `site_count` (how many call sites were collapsed), up to three citing `functions`, and an `example` citation (`function`, `line`, `instruction`) so every value can be checked against the disassembly. When a constant points at a mapped section and decodes as text, the string rides along as `string`. Both encodings a pointed-at literal uses are read: ASCII and UTF-16LE little-endian (the wide form the `W` Windows APIs take), under the stack-string decoder's character filter and a four-character minimum that counts decoded characters, not bytes.
  - A constant is reported only where every CFG path reaching the call agrees on it; unresolved call sites contribute a coverage counter, never an entry — an integer with no resolved destination stays out of the block.
  - The block is bounded: `BLINT_MAX_CALLSITE_ARGUMENTS` (default 4096, `0` disables the block) caps entries per binary, one function contributes at most 256 distinct entries, and every tripped bound is named in `call_site_arguments_coverage` (`entries_truncated`, `functions_entries_capped`, `functions_entries_capped_names`).
  - `call_site_arguments_coverage` also records the per-function analysis method counts (`functions_total`, `functions_dataflow`, `functions_no_cfg`, `functions_cfg_mismatch`, `functions_cap_hit`, `functions_no_abi`, `functions_skipped`) and `records_unresolved_callee`, so what the block cannot say is a number, not a silence.
  - Position-independent code materialises string addresses in two instructions (ARM64 `adrp` + `add`, x86-64 rip-relative `lea`). When the disassembly can locate each instruction, those pairs are folded into the absolute address they compute and reported as the constant — so a `string` in this block is the text actually living at the address a call received. Each disassembled function therefore also carries `instruction_lengths` (per-line instruction sizes aligned with `assembly`; reconstruct a line's address by prefix-summing lengths from its CFG block's start VA). Materialisation failures are named, never silent: `functions_no_line_addresses` (blocks without usable VAs or without exported lengths), `functions_extent_mismatch` (a block's extent contradicts the strides its lines claim), `functions_unmodelled_pc_relative` (an `adr` the model deliberately does not fold), `arguments_materialised` / `pointer_values_page_only` (how many argument values were folded pointers, and how many of those are bare uncompleted pages), and `strings_resolved` (entries whose constant resolved to text). The same reasons surface in `analysis_coverage.degradations` as `callsite_*`.

- **Privileged-host plugin surface (`host_plugin`, PE only):** Present only when the binary's export set (plus, for the two COM contracts, an in-binary registration reference) satisfies a documented Windows extension-point contract; absent otherwise — and absence reads as "no plugin contract evidenced", never as "verified not a plugin". A binary whose export directory is declared but unreadable carries `exports_read_status: "failed"` beside the empty `exports` list and an `export_table_unreadable` degradation in `analysis_coverage`, so a detection gap is never mistaken for a clean result.
  - `contracts`: one entry per satisfied contract, in table order, each with `id`, `title`, `host_process` (the process the contract loads the DLL into — `lsass.exe`, `spoolsv.exe`, the W32Time `svchost.exe`, `winlogon.exe` and WNet callers, `LogonUI.exe`, `audiodg.exe`, or the set of calling processes for the Winsock/AppCert contracts), `host_privilege` (`system`, `local_service`, `protected` or `inherited`), and `matched_exports` (the exact names that satisfied the contract).
  - `protected_process: true` appears on contracts whose host runs protected (LSA under PPL, `audiodg.exe` for protected content); `credential_exposure` names what a contract sees in the clear (`lsa_password_filter`: account passwords on every change; `network_provider`: logon credentials via `NPLogonNotify` under winlogon); `registration_hint` names the registry key the host registers the DLL under.
  - The export-keyed contracts are exact-name matches against the table in `blint/data/pe_host_plugin_contracts.yml`, which is pinned against Microsoft's documentation with each contract's full-System32 hit count recorded in its header. The two COM contracts (`credential_provider`, `audio_processing_object`) additionally require an in-binary reference to their registration path (`Authentication\Credential Providers`, `AudioEngine\AudioProcessingObjects`), scanned from section bytes in ASCII and UTF-16LE — not from the `strings` list, whose gates and fallback cap must not bound detection. Their entries carry `evidence.registration_strings` (the readable spans around each reference, listed up to 4 — a listing bound no rule reads past the first entry of). Recall on these two is partial by construction: only the registry knows which CLSID is registered, so the finding text qualifies with "when registered".
  - For ARM64X images whose primary and nested export listings disagree on the contract set, `host_plugin_slice_variance` names the differing contracts; when the primary listing is unreadable but the nested one read cleanly, `host_plugin_scope: "nested_binary"` says which listing speaks. Both are mirrored in `analysis_coverage`.
  - Ordinal-only exports cannot satisfy any contract here, which is sound rather than a gap: every host in the table resolves its entry points by name.

In the case of ARM64X, a single PE file encapsulates ARM64 and ARM64EC architectures. For `ARM64EC` nested PE binaries, an additional attribute `nested_binary` would contain the information such as `exports`, `exceptions`, `functions`, `ctor_functions`, and `dotnet_dependencies`.

### For Mach-O Binaries

Mach-O files are the standard for macOS, iOS, and other Apple operating systems.

- **Header (`header`):**
  - `cpu_type`: The target architecture (e.g., `ARM64`).
  - `file_type`: Identifies the binary as an `EXECUTABLE`, `DYLIB` (shared library), etc.
  - `magic`: The Mach-O magic as a name (observed `"MAGIC_64"` on an arm64 macOS executable). A top-level key, like the other header fields here.
  - `is_neural_model`: `true` only when the header magic is Apple's neural-model file magic (`0xbeefface`, LIEF's `MACHO_TYPES.NEURAL_MODEL`); `false` on ordinary Mach-O images (observed `false` on `/bin/ls`, `gh`, and Go toolchain binaries). Present on every Mach-O metadata — it names the file type the header declares, not an analysis verdict, so `false` is the expected value for binaries and libraries.

- **Load Commands:** Mach-O uses load commands instead of a dynamic section.
  - `libraries`: A list of required dylibs, equivalent to `NEEDED` entries in ELF.
  - `uuid`: A unique identifier for the binary, used by debuggers and crash report symbolication tools.
  - `rpath`: A runtime search path for libraries.
  - `code_signature`: The embedded code-signature SuperBlob, parsed into semantic detail (see below).

- **Code signature (`code_signature`):** The SuperBlob that `LC_CODE_SIGNATURE` points at, parsed by `blint/lib/codesign_macho.py` — what the binary _claims_ about itself, never a trust judgment. `trust_validation` fields say `not_performed` in band, so "signed" is never read as "trusted"; blint does not validate certificate chains, revocation, or notarization.
  - `available`: `true` when the slice carries an embedded signature blob.
  - `parse_status`: `parsed`, `parse_failed`, or `absent`. A present-but-corrupt blob is `parse_failed` — never folded into a confident "unsigned" or an empty entitlements answer; it lands in `analysis_coverage` (`security_properties_gaps` gains `code_signature_detail`, and `degradations` gains `code_signature_parse_failed`).
  - `size`, `data_size`: legacy keys (strings) — the load-command size and the blob size in the file. `data_offset`: the load command's `dataoff`, which is **slice-relative**; `file_offset`: the absolute position of the SuperBlob in the file (`fat_offset + dataoff` — the two differ for every slice of a universal binary). `blob_source`: `lief_content` or `file_range`, i.e. which read path produced the bytes.
    The former `data` key (removed, an explicit additive-only exception) held the hex of the 16-byte load command itself under a name claiming signature content — it had never held signature data. Its entire information content (cmd, cmdsize, dataoff, datasize) is preserved by `size`, `data_offset`/`file_offset` and `data_size`.
  - `superblob.blobs`: the blob index — `slot_type`, `offset`, `size`, `magic` per member.
  - `superblob.code_directories[]`: every CodeDirectory (primary and alternates) with `version`, `identifier`, `team_id`, `flags` (named booleans: `adhoc`, `hard`, `kill`, `restrict`, `runtime` (hardened runtime), `library_validation`, `get_task_allow`, `linker_signed`, …), `flags_raw`, `hash_type`/`hash_size`, `page_size`, `code_slots`/`special_slots`, `code_limit`, `platform_id`, `runtime_version` (v0x20500+), `exec_seg_flags` (v0x20400+), and the **cdhash** — `cdhash` (20-byte truncated, the form `codesign -dvvv` displays and the identity the system keys on) plus `cdhash_full` and `cdhash_algorithm`.
  - `superblob.entitlements`: parsed key/value pairs from the XML-plist slot; `superblob.entitlements_der`: the same from the DER slot (modern Apple binaries). A payload that fails to decode yields `{"decode_error": ...}` rather than an empty dict, so "no entitlements" and "undecodable entitlements" stay distinct.
  - `superblob.requirements`: internal-requirements inventory (`count`, `types`).
  - `superblob.cms`: the CMS (PKCS#7) signature — `content_type`, `signer_cn` (the signing certificate, identified by SignerInfo issuerAndSerialNumber, not blob position), `certificates[]` with `subject_cn`/`subject_organization`/`issuer_cn`/`serial`, and `trust_validation: "not_performed"`.
  - `superblob.provenance`: `adhoc`, `linker_signed`, `cms_signed`, or `unknown` — a claim read off the blob's flags and CMS presence.
- **Signature-derived security properties:** when the SuperBlob parsed, `security_properties` gains explicit `hardened_runtime`, `library_validation` and `get_task_allow` booleans from the primary CodeDirectory flags (`False` is reported too — for hardening properties the negative is the finding). `is_signed` remains presence-only (the blob exists), so a corrupt blob still reads `is_signed: true` with the failure recorded as a gap.

- **Encryption (`is_encrypted`, `encryption_info`):** Derived from `LC_ENCRYPTION_INFO(_64)`. `is_encrypted` is `true` when `crypt_id` is non-zero (FairPlay-protected App Store binaries); developer, ad-hoc, and enterprise builds report `false`. `encryption_info` carries `crypt_id`, `crypt_offset`, and `crypt_size`. An encrypted `__TEXT` segment cannot be meaningfully disassembled without on-device decryption.

- **Objective-C metadata (`objc_metadata`):** Recovered by walking the raw `__objc_*` sections (LIEF's community build does not expose this). Internal pointers are resolved via relocation targets, with a chained-fixup fallback that decodes raw `dyld` chained pointers (validated against mapped section ranges) when no relocation map is present; external class pointers are resolved via the dyld binding table. Present only when the binary contains 64-bit Objective-C metadata (32-bit armv7/i386 layouts are skipped).
  - `class_count`, `protocol_count`, `selector_count`: summary counters.
  - `classes`: each entry has `name`, `superclass` (internal class name or external framework class), `method_count`, `methods` (selector names), and optional `protocols`.
  - `protocols`: declared protocols with their `name` and `methods`.
  - `selectors`: distinct selectors referenced at message-send sites (`__objc_selrefs`).
  - `external_classes`: framework/runtime classes the binary links against (e.g. `CLLocationManager`, `CTTelephonyNetworkInfo`). Selectors and external classes feed the capability review, surfacing iOS privacy capabilities.
  - `method_imps`: recovered method implementations as `{name, address}`, where `name` is the readable `-[Class selector]` form and `address` is the implementation's virtual address. These seed and label the `functions` list (see below) so message handlers are disassembled and named even in stripped binaries.
  - `category_count`, `categories`: categories from `__objc_catlist` — named extensions that patch existing (usually framework) classes. Each carries `name`, `class_name` (from the dyld binding table for external classes, otherwise the internal `class_ro_t` name), instance/class `methods`, `protocols` and `properties`. Category methods are seeded like class methods, spelled `-[Class(Category) selector]`.
  - `nonlazy_class_count`, `nonlazy_classes`: classes in `__objc_nlclslist` — the runtime runs their `+load` before `main`. Each entry names the class (`runs_before_main: true`) and, when recovered, the `+load` implementation address; these seed `+[Name load]` functions. `nonlazy_category_count`/`nonlazy_categories` cover `__objc_nlcatlist`. Rule `CHECK_OBJC_LOAD_METHODS` (info) names the classes.
  - `classes[].ivars` / `classes[].properties`: declared ivars (`name`, `type`) and properties (`name`, type-encoding `attributes` such as `T@"NSString",R,N`) from the class's read-only data, in both the legacy pointer and relative small encodings.
  - `parse_degradations`, `parse_degradation_count`: counted tokens for every unresolvable pointer or unparsable list — partial reads are reported, never silent.

- **Function recovery (`functions`):** For stripped release builds (the common case for shipped iOS/macOS apps) the symbol table exposes little beyond `__mh_execute_header`. blint augments the function list from the `LC_FUNCTION_STARTS` table — every entry point is recovered, reusing a surviving symbol name when one exists and synthesising a `sub_<address>` name otherwise. Recovered Objective-C implementations then upgrade matching `sub_<address>` entries to their `-[Class selector]` names. This is what allows disassembly and callgraph construction to work on stripped apps.

- **One address space for Mach-O functions:** every address in `functions`, `ctor_functions`, `unwind_functions`, `discovered_functions` and the `disassembled_functions` keys is a **virtual address** (executables are typically `0x100000000`-based; dylibs are typically `0x0`-based, where the virtual and file-relative spaces coincide). LIEF's aggregate mixes symtab virtual addresses with file-relative `LC_FUNCTION_STARTS` offsets; blint classifies each entry against the image's segment ranges — an address inside a content-bearing segment's virtual range is virtual, one inside its file range is file-relative and is rebased by `imagebase` — so a reader never has to guess which space an address is in. Subtract `imagebase` to recover the file-relative offset. Entries that collapsed onto one address after rebasing are merged (a real symbol name wins over the synthetic `sub_<addr>` twin, the largest known size survives). The `macho_function_address_space` block records what happened: `normalized_to` (`"virtual"`), the `imagebase` anchor, `rebased_entries`, `duplicates_merged`, `names_recovered`, and `ambiguous_entries`/`unresolved_entries` for addresses the segment ranges could not place (left in their raw space, never guessed; also mirrored into `analysis_coverage.degradations`). Zero-file-size segments such as `__PAGEZERO` are excluded from classification — their virtual range covers the whole low half of the address space and would swallow every file-relative address.

- **Skipped disassembly (`disassembly_skipped`):** When `--disassemble` is requested for a FairPlay-encrypted binary (`is_encrypted` is `true`), disassembly is skipped and this field is set to `fairplay_encrypted` rather than producing meaningless instructions from the encrypted `__TEXT`.

- **Universal binaries (`is_universal`, `slices`):** A fat (universal) Mach-O contains one image per architecture. blint summarizes _every_ slice, not just the one the generic parser auto-selects. The existing top-level keys (`cpu_type`, `functions`, `security_properties`, …) keep describing the **primary slice** (the first fat entry — the same slice that was analyzed before this field existed, so consumers of those keys see no change); `is_universal` is `true` only for fat inputs, and `slices` carries one lean entry per slice in fat order:
  - `index`, `cpu_type`, `cpu_subtype`, `arch`, `is_primary`: slice identity. `arch` distinguishes `arm64` from `arm64e`, which matters because only arm64e slices get pointer authentication.
  - `security_properties`: the same property set as the top-level block, computed from _this slice's_ bytes. Hardening that differs between slices — a signature present on one slice but not another, PAC only on the arm64e slice — is reported per slice and is never merged into a single optimistic or pessimistic answer.
  - `code_signature`: the slice's own parsed signature summary (`parse_status`, `provenance`, `identifier`, `team_id`, `cdhash`, `hash_type`, `flags`, `entitlements`, `entitlements_der`). Signatures are per slice — every slice has its own CodeDirectory and its own cdhash, and entitlements can differ between slices — so a single top-level cdhash for a fat binary would be a wrong answer.
  - `functions`, `symbols`, `imports`: counters evidencing the slice was really parsed.
  - `is_encrypted`: per-slice FairPlay state (set when the slice's `crypt_id` is non-zero).
    Because the top-level block speaks for the primary slice, a fat input also carries `security_properties_scope: "primary_slice"` and, when the slices do not agree, `security_properties_slice_variance` naming every property they differ on (both mirrored into `analysis_coverage`). `/usr/bin/git` is the case in point: PAC is on its arm64e slice, so the top level has no `pac` key and would otherwise read exactly like a binary checked and found to lack it. Nothing is merged across slices — a merge would have to pick between an optimistic and a pessimistic lie — so the per-slice truth stays in `slices` and the summary states its own scope.
    The same rule applies to signatures: the top-level `code_signature` block declares `code_signature_scope: "primary_slice"` and, when slices disagree, `code_signature_slice_variance` names the aspects (`cdhash`, `entitlements`, `flags`, …) — also mirrored into `analysis_coverage`. cdhash differs by construction across slices; differing entitlements are the signal to look for.

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

### macOS Bundle Directories (`.app` / `.framework` / `.dSYM`)

A macOS bundle is a directory (unlike an `.ipa`, there is nothing to unpack). blint walks it — the main executable under `Contents/MacOS` (named by `CFBundleExecutable`), embedded frameworks (`Contents/Frameworks`), app extensions (`Contents/PlugIns/*.appex`), XPC services (`Contents/XPCServices/*.xpc`), login-item and LaunchServices helper apps under `Contents/Library`, a framework's own `Versions/` tree, and a `.dSYM`'s DWARF slices — and analyzes every Mach-O it finds. Auxiliary executables beside the main binary (installer tools, privileged helpers) are collected with role `tool`/`helper` so a bundle scan never loses them relative to a plain directory scan. Members are deduplicated through `Versions/Current` symlink aliasing, and a 2000-binary walk cap records `binary_walk_truncated` instead of stopping silently. In SBOM output the bundle is the parent application component and each binary a component with `pkg:macos` purls keyed by bundle-relative path.

| Attribute      | Description                                                                                                                                                              |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `macos_bundle` | The same bundle-context shape as `ios_bundle` below (identity, role, `bundle_path`, ATS/URL-scheme/privacy keys) for binaries analyzed through a macOS bundle directory. |

### Windows Containers: MSIX / Appx (`.msix` / `.appx` / `.msixbundle` / `.appxbundle`)

An MSIX/Appx package is a zip whose `AppxManifest.xml` states identity and capabilities; a bundle is a zip of packages. blint walks the container (`blint/lib/msix.py` through the shared bounded framework in `blint/lib/container.py`), analyzes every `exe`/`dll` member through the normal PE path, and attributes each member to its place in the package (`container_path`, e.g. `CascadiaPackage_1.22.12111.0_ARM64.msix/wt.exe`). The container itself is an analyzed unit whose metadata carries:

| Attribute                 | Description                                                                                                                                                                                            |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `container.kind`          | `msix`, `appx`, `msixbundle` or `appxbundle` — also the metadata `exe_type`, so container-scoped rules gate on it.                                                                                     |
| `container.identities`    | Bundle identity plus each package's `AppxManifest` facts: `identity` (`name`, `version`, `publisher`, `architecture`), `display_name`, `publisher_display_name`, `target_device_families`, `package_dependencies`, `applications` (entry executables). |
| `container.capabilities`  | `{general, restricted, device}` capability names from the manifest. Restricted capabilities are recognised by their `rescap` namespace, not a name list, so capabilities Microsoft adds later still class correctly. Listed per class up to 128; `restricted_capability_count` is the counted total the rule reads, so a past-the-cap manifest still fires. |
| `container.signature`     | Facts from `AppxSignature.p7x` (a `PKCX`-prefixed PKCS#7) parsed through the same signature walker the PE certificate table uses: `signer_cn`, `signer_o`, `digest_algorithm`, `signature_count`. No trust validation is performed. |
| `container.blockmap`      | The `AppxBlockMap.xml` declaration: `hash_method` (SHA-256 only; anything else records `blockmap_hash_method_unsupported`), `file_count`, `total_size`.                                                |
| `container.blockmap_verification` | Block hashes recomputed for every extracted member: `verified_files`, `verified_blocks`, and `mismatches` (member + mismatched-block count). Unextracted files are declared, not verified — the scope is stated by the counts, never implied. |
| `container.package_count` / `member_binary_count` | How many nested packages were walked and how many member binaries were analyzed.                                                                                               |
| `container.refusals`      | Every named refusal (ground rule 30): `member_path_unsafe`, `member_is_symlink`, `member_size_exceeds_cap`, `member_count_exceeds_cap`, `total_uncompressed_exceeds_cap`, `member_compression_ratio_exceeds_cap`, `appx_manifest_missing`, `manifest_xml_malformed`, `nested_package_unreadable`, `archive_unreadable` and friends. Sorted, deliberately not de-duplicated: a package with ten unsafe members reports ten. |

Caps are measured (module docstring, `blint/lib/msix.py`): ≥2x the Windows Terminal 1.22 reference bundle — 2048 members, 512 MiB total, 64 MiB per member, depth 16, compression ratio 128, 64 nested packages. `CHECK_MSIX_RESTRICTED_CAPABILITY` (info, by measurement — 17 of 56 ordinary Store packages declare a restricted capability) names the declared surface. In SBOM output the package is the parent component (`pkg:appx/<name>@<version>` from the manifest identity) and each member a component keyed by container path with a SHA-256 hash; container refusals reach the BOM as `internal:container_refusals`.

### Provisioning Profiles (`provisioning_profile`)

Bundles signed for direct distribution carry a provisioning profile — `embedded.mobileprovision` (iOS shape) or `embedded.provisionprofile` (macOS, under `Contents/`). The profile is a CMS envelope around a plist; blint decodes it (`blint/lib/provisioning.py`) into:

| Attribute                               | Description                                                                                                                                                                                                                                                                                                                                                                      |
| --------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `parse_status`                          | `parsed` or `parse_failed` (with `parse_error`). A failed CMS or plist decode is reported, never guessed.                                                                                                                                                                                                                                                                        |
| `name`, `team_name`, `team_identifiers` | The profile's identity and signing team.                                                                                                                                                                                                                                                                                                                                         |
| `created`, `expires`                    | ISO-8601 validity window. Validity is evaluated by the checks at scan time, keeping parse output deterministic.                                                                                                                                                                                                                                                                  |
| `entitlements`                          | Every entitlement key the profile grants, with its value, spelled exactly as signed — no allow-list, the same policy as the code-signature `superblob.entitlements` block. iOS profiles sign `application-identifier`; macOS profiles sign `com.apple.application-identifier`; both spellings are the same entitlement and are reported verbatim (consumers should read either). |
| `provisioned_device_count`              | Count only — device UDIDs never enter metadata.                                                                                                                                                                                                                                                                                                                                  |
| `provisions_all_devices`                | Enterprise (in-house) distribution marker.                                                                                                                                                                                                                                                                                                                                       |
| `signer_cn`                             | Common name of the CMS signer chain (names only; no trust validation).                                                                                                                                                                                                                                                                                                           |

Three rules consume the block: `CHECK_PROFILE_EXPIRED` (high), `CHECK_PROFILE_DEVELOPMENT` (medium — a `get-task-allow` profile in a shipping bundle) and `CHECK_PROFILE_WILDCARD` (medium — a `team-id.*` application identifier).

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

| Property           | Description                                                                                                                                                                                                                                                                                                     | Use Case                                                                                                                       |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `language`         | The primary programming language detected (e.g., `Go`, `Rust`, `.NET`). This is inferred from language-specific sections or symbols.                                                                                                                                                                            | Guides the reverse engineering process by setting expectations for runtime behavior, calling conventions, and data structures. |
| `go_version`       | If the language is Go, the Go toolchain version copied from `go_formulation.go_version` (e.g. `go1.27.1`), read length-prefixed from the raw buildinfo blob. **Absent** when the version cannot be recovered — e.g. a pre-1.18 pointer-layout buildinfo or a truncated blob — rather than set to a placeholder. | Checking against known vulnerabilities in specific versions of the Go compiler or standard library.                            |
| `linker_version`   | The version of the linker program (e.g., from `ld` or `link.exe`) that produced the final executable, if this information is present in the binary.                                                                                                                                                             | Can help fingerprint the build environment (e.g., a specific Linux distribution or version of Visual Studio).                  |
| `compiler_version` | The compiler identification string, often extracted from the `.comment` section in ELF files (e.g., `GCC: (Ubuntu 11.2.0-19ubuntu1) 11.2.0`).                                                                                                                                                                   | Precisely identifies the compiler and its version, which is useful for tracking toolchain vulnerabilities.                     |

### `*_dependencies`

These attributes provide detailed lists of third-party libraries and packages compiled into the binary.

| Attribute             | Description                                                                                                                                                                                                                                                         | Use Case                                                                                                                                                                                                                                       |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `go_dependencies`     | A list of Go packages used to build the binary, extracted from the embedded `.go.buildinfo` section. Includes package names, exact versions, and checksums (`h1:` hashes).                                                                                          | **Gold Standard for SCA.** Allows for precise identification of Go libraries and their versions, enabling direct mapping to known vulnerabilities (CVEs) in those packages.                                                                    |
| `rust_dependencies`   | A list of Rust crates used to build the binary, extracted from the `.dep-v0` section created by the `cargo-auditable` feature. Includes crate name, version, and kind.                                                                                              | Similar to Go, this enables precise SCA for Rust applications, mapping crates to known CVEs. **Limitation**: This section is only present if the developer explicitly enables the `cargo-auditable` feature during compilation.                |
| `dotnet_dependencies` | A structured list of NuGet packages and their versions, extracted from the `deps.json` file embedded in the PE overlay of self-contained .NET applications.                                                                                                         | Provides precise SCA for .NET applications, allowing for vulnerability mapping. **Limitation**: This is only available for .NET Core/5+ applications published in "self-contained" mode and is not present in framework-dependent deployments. |
| `import_dependencies` | A structured graph detailing which shared libraries (`.dll`, `.so`, `.dylib`) are imported by the main binary and which specific symbols are used from each library. See [Symbol attribution](#symbol-attribution) for what the attribution is based on per format. | Provides a clear, high-level view of runtime dependencies. Helps identify the use of sensitive APIs (e.g., crypto, networking) and from which library they originate. This is a foundational element for behavior analysis.                    |

### `go_formulation`

Companion to `go_dependencies`: the Go build's own description of itself, parsed from the embedded buildinfo (`.go.buildinfo` on ELF, `__go_buildinfo` on Mach-O, a `.data` section scan on PE). A flat object:

- `go_version` is the Go toolchain version (e.g. `"go1.27.1"`, `devel …` strings keep their full shape, e.g. `"go1.26.4-X:jsonv2"`). It is read at the byte level from the raw buildinfo blob — the 32-byte `\xff Go buildinf:` header, then the uvarint-length-prefixed version string exactly as laid out by `go/src/debug/buildinfo` (inline since Go 1.18; observed on go1.26.4/1.26.5/1.27.0/1.27.1 builds, on ELF, Mach-O and PE alike) — so it cannot be confused with module paths that merely contain a `go` token. On pre-1.18 pointer-layout buildinfo the version lives outside the blob and `go_version` stays **absent**; absent, not a placeholder, is the contract for "not determined".
- `path` and `module` come from the same byte-level blob read, not from the NUL-stripped text: after the version, the blob carries the modinfo string framed by 16-byte sentinels (`cmd/go/internal/modload`'s `infoStart`/`infoEnd`), and inside that frame the lines are tab-separated exactly as `go/src/runtime/debug.ParseBuildInfo` expects. `path` is the single field of the `path` line; `module` is the **name column only** of the `mod` line — the version and `h1:` hash columns are real data, not part of the module identity, and never appear in the value. A dependency whose name ends in `path` (e.g. `…/jsonpath`) cannot leak into `path`, because lines are anchored on their `keyword\t` prefix rather than matched as substrings. When the blob cannot be read (pre-1.18 layout, truncation, failed sentinel check), both keys are **absent** — never a partial or concatenated string. A module-less build (`go build main.go`) reports `"path": "command-line-arguments"` and no `module` key at all.
- One entry per `build KEY=VALUE` setting with `-` stripped from the key (e.g. `-buildmode=exe` → `"buildmode": "exe"`, `-compiler=gc` → `"compiler": "gc"`, while environment-style keys keep their spelling: `"CGO_ENABLED": "1"`, `"GOARCH": "arm64"`). The value is cut at the **first** `=`, so values that themselves contain `=` survive whole — `DefaultGODEBUG=tracebacklabels=0,x509sslcertoverrideplatform=0` is stored in full (observed on `gh` 2.100.0).
- The key is present on every binary parsed by the ELF/PE/Mach-O readers — `{}` for non-Go binaries (observed `{}` on `/bin/ls`) — so an empty object means "not a Go binary or no readable buildinfo", not "Go with no build settings". On PE the blob (magic, version, framed modinfo) is located by searching the whole `.data` section, since the modinfo string can be larger than the text window used by the fallback; `go_dependencies` and `build` settings are also recovered from that full-section blob read.

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

### `import_call_addresses` (Mach-O, requires `--disassemble`)

A top-level dict mapping Mach-O import landing addresses to the imported symbol's name, built once when disassembly starts (`blint/lib/disassembler.py::build_macho_import_address_map`). Mach-O has no ELF-style PLT/GOT relocations, so imported calls would otherwise land on anonymous `sub_*` stub nodes; this table is what lets the callgraph builder classify such calls as external import edges instead of misattributing them to whichever internal function happens to span the slot address (the mechanism the Swift-symbols note above refers to).

- Two address families are covered: dyld binding-table slots (`__got` and the lazy/non-lazy symbol-pointer sections) and `__stubs` entries (indexed through the indirect symbol table via the section's `reserved1`/`reserved2`).
- Keys are hex virtual-address strings; values are demangled symbol names. Observed on `/bin/ls` (175 entries), e.g. `"0x100005000": "__DefaultRuneLocale"`, and on `/usr/bin/log` (793 entries), where the C++ mangled binding `__ZNSt3__112__next_primeEm` appears as `"0x100037340": "std::__1::__next_prime(unsigned long)"`.
- The key appears only for Mach-O inputs and only when disassembly runs; without `--disassemble` it is absent (not empty). An empty dict would mean a Mach-O with no bindings and no stubs — distinct from the key never having been built. ELF needs no such table: imported names are resolved from GOT/PLT relocations directly.
- The callgraph's `external` edges consume it: a call target that lands on a known slot is a call out to a dynamic library, never an internal edge, and the recovered name is what makes the edge's `library` attribution (and its confidence raise from `low` to `medium`) possible.

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
| Mach-O | Each symbol is bound to a dylib, recorded as `library::symbol`. The `is_imported` flag on each symtab entry marks the undefined symbols that are the imports.                       | Always                                            |
| ELF    | The dynamic symbol table and the `DT_NEEDED` list are unrelated flat lists. The connection only exists once the dependency closure is resolved and each library's exports are read. | Only with [`link_closure`](#link_closure) enabled |

Two fields record what the result rests on:

| Property                    | Description                                                                                                                          |
| :-------------------------- | :----------------------------------------------------------------------------------------------------------------------------------- |
| `attribution_sources`       | Which evidence was used: `import_table`, `load_commands`, `sdk_tbd`, `link_closure`. Empty means none was available.                 |
| `unattributed_symbol_count` | How many imported symbols could not be tied to a library. These are collected under a synthetic `unattributed` entry in `libraries`. |

**An ELF binary analysed without closure resolution attributes nothing.** That is deliberate. Assigning a symbol to an arbitrary declared library produces a dependency edge that is indistinguishable downstream from a correct one, and a wrong edge is worse than an honest gap.

C++ and Rust symbols are matched on their linkage name, which blint records as `raw_name` on the symbol whenever demangling changed it. A provider's export table holds mangled names, so the demangled name alone never matches.

Note that `::` is a library separator only in Mach-O, and only when the prefix looks like a library. Everywhere else it separates namespace components, and `APT::PackageContainer::begin` is one symbol rather than a dependency on `APT`.

#### The `.tbd` SDK index (`--sdk-path`)

On a running macOS install the system libraries a binary links against are absent from disk — they live only in the dyld shared cache. `--sdk-path <dir>` (off by default) points blint at an Apple SDK whose `.tbd` text stubs describe what every system library exports, and is the only static oracle for confirming Mach-O dependency questions. The path must contain `.tbd` files; a run given a path with none aborts with an error rather than serving an empty index.

When the option is on, Mach-O imports the binary's own evidence could not pin to a library (flat binds, missing binding info) are attributed to the first declared library — in load-command order, matching dyld's search order — whose export surface provides the symbol. A symbol's surface is the library's own `exports`/`reexports` sections plus, transitively, the exports of everything it names under `reexported-libraries` (v4) or `re-exports` (v2/v3).

A re-exported symbol is attributed to the **declaring** library, never the implementing one. A Mach-O two-level bind records the ordinal of the library in the binary's own load-command list; dyld resolves through that library's re-export edges at runtime, but the bind still names the declared library — `dyld_info -imports /usr/bin/git` reports `_dispatch_once (from libSystem)` although the implementation lives in libdispatch.dylib. Substituting the implementing library would contradict the binary's own bind and re-flag declared umbrellas as unused.

The evidence is marked `sdk_tbd` in `attribution_sources`, always distinct from `load_commands`: **a `.tbd` describes what the SDK ships, not what the machine under the binary ships.** The block records no SDK identity — no paths, versions, or totals of the analyst's environment — only these binary-relative facts:

| Property                          | Description                                                                           |
| :-------------------------------- | :------------------------------------------------------------------------------------ |
| `attributed_symbol_count`         | Imports without a `dylib::symbol` prefix that the index pinned to a declared library. |
| `attributed_symbols`              | Capped, sorted sample of the same, as `symbol: install-name`.                         |
| `confirmed_symbol_count`          | Load-command binds the SDK surface confirms.                                          |
| `reexport_confirmed_symbol_count` | How many of those confirmations needed the re-export closure.                         |
| `unconfirmed_symbol_count`        | Load-command binds the SDK surface cannot back — private or otherwise noteworthy.     |
| `unconfirmed_symbols`             | Capped, sorted sample of the same.                                                    |

Every `_count` above is exact; only the `_symbols` samples are capped, so a large binary's metadata does not grow with its import table. A count that saturated at the sample cap would understate exactly the binaries whose gaps matter most.

The index is built once per run and cached on disk (under the parse-cache directory, keyed by a fingerprint of the SDK's `.tbd` tree), so `--jobs N` workers each pay one load rather than one build.

### `link_hygiene`

Reports declared dependencies that are never used and used libraries that are never declared. Requires symbol attribution, so for ELF it needs closure resolution; the whole block is absent when no attribution evidence was collected at all, because with no evidence every dependency looks unused. A separate shape covers the case where the binary imports symbols but none of them could be pinned to any library:

| Property             | Description                                                                                                                                                                                                                                                                                                             |
| :------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `attribution_status` | `"unresolved"` — the binary imports symbols, but none were attributed, so unused/undeclared answers would be manufactured rather than observed. No `unused_dependencies` or `undeclared_dependencies` keys are present in this state, and `analysis_coverage.degradations` carries `dependency_attribution_unresolved`. |

| Property                    | Description                                                                                                                                                                |
| :-------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `unused_dependencies`       | Declared libraries from which no symbol is imported, each with a `name` and a `reason`. Linking with `--as-needed` removes them.                                           |
| `undeclared_dependencies`   | Libraries supplying symbols without being declared, with `symbol_count` and a sample of `symbols`. These work only for as long as some other dependency keeps them mapped. |
| `attribution_sources`       | The evidence the result is based on, as above.                                                                                                                             |
| `unattributed_symbol_count` | Imports not tied to any library. A high count means the findings are based on partial evidence.                                                                            |
| `imported_symbol_count`     | Present only in the `unresolved` state: how many imports existed for the (failed) attribution to consider.                                                                 |
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

### `layout_anomalies`

ELF only. Three related additions record how an ELF is laid out and where that layout contradicts itself:

- `entry_point_section`: the name of the section containing `e_entry`, the ELF counterpart of the field PE metadata has always carried. An empty string means the entry address falls in no section at all — which is the strongest form of the anomaly below, not a missing computation.
- `segments_summary`: every program header in table order, each with `index`, `type`, normalized `permissions`, `file_offset`, `file_size`, `virtual_address` and `virtual_size`. ELF metadata previously recorded only `numberof_segments`, which is exactly the field that stays constant when a spare program header is retyped in place; exporting the table makes that change visible to anything diffing two builds of the same binary.
- `layout_anomalies`: a list of structural contradictions, each with a `kind`, the addresses and names needed to check it by hand, and a `detail` sentence. An empty list is the normal result.

The anomaly kinds:

| `kind`                                  | What it means                                                                                                              |
| --------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `entry_point_outside_any_section`       | `e_entry` is covered by no section header. Toolchain-produced entry points always lie inside a section.                    |
| `entry_point_in_non_executable_section` | `e_entry` is inside a section not marked `SHF_EXECINSTR`. The section table says this is not code; the header says it is.  |
| `entry_point_in_unexpected_section`     | `e_entry` is inside an executable section whose name is outside the small set toolchains emit entry stubs into.            |
| `note_section_without_note_segment`     | The image maps `.note.*` sections but carries no `PT_NOTE` at all, so nothing at run time can reach them.                  |
| `executable_mapping_at_eof`             | An executable `PT_LOAD`'s file range ends on the last byte of the file, where a linker would have placed data and symbols. |

These exist because an implant can be added to a finished ELF without changing one original byte: append the payload at EOF, retype a spare `PT_NOTE` program header into an executable `PT_LOAD` covering it, and redirect `e_entry` and `e_shoff` (arXiv 2607.24888, which carries exactly this through GNU `strip` across the NixOS bootstrap). Nothing is packed, nothing becomes writable-and-executable, and the result is internally consistent enough that `readelf` reports no problem — so neither `wx_segments` nor `entropy` sees it. What the result cannot hide is the disagreement between its parts.

The `ELF_ENTRY_POINT_OUTSIDE_CODE`, `ELF_NOTE_SECTION_WITHOUT_SEGMENT`, `ELF_APPENDED_EXECUTABLE_MAPPING` and `ELF_BUILD_SANDBOX_EVASION_GATE` reviews turn these into findings. Note that `note_section_without_note_segment` requires the _absence_ of any `PT_NOTE` rather than per-section coverage: the Go linker legitimately emits a `PT_NOTE` spanning only `.note.go.buildid` and leaves the adjacent `.note.gnu.build-id` outside it, so per-section coverage fires on every Go binary.

### `entropy`

Per-section Shannon entropy plus packing evidence, collected for every ELF, PE and Mach-O image whether or not disassembly is requested.

- **`sections`**: one entry per non-empty section with `name`, `size`, `entropy` (bits per byte, 0-8), `executable`, `writable`, and `sampled` (true when entropy was computed over the first 8 MB of a larger section — the sample is always the section head, so results stay deterministic).
- **`packing`**: the derived signals:
  - `packed_likelihood`: `high` / `medium` / `low` summary of the evidence below. On PE, an overlay counts as evidence only when its residue is `unknown_high_entropy` and an independent packing signal agrees; a lone overlay — installer payload, appended archive, bundle — is reported without raising the likelihood.
  - `packers`: packer section-name signatures found (UPX, Themida, VMProtect, ASPack, MPRESS and others).
  - `writable_executable_sections`: section-level W+X evidence; the loadable-segment view lives in [`wx_segments`](#wx_segments).
  - `executable_section_entropy` / `max_executable_section_entropy`: per-executable-section entropy values.
  - `overlay_size`: bytes past the last section's file content (ELF/PE only; the Mach-O file tail is the code-signature SuperBlob and is excluded). On PE this is the overlay **residue** — the Authenticode certificate table (`IMAGE_DIRECTORY_ENTRY_SECURITY`) is subtracted first, so a signed stock binary reports `overlay_size: 0` rather than counting its signature as packing evidence.
  - `overlay_classification`: PE only — the magic-based label of the overlay residue (`zip`, `cab`, `msi`, `nsis`, `inno`, `installshield`, `sfx_7z`, `dotnet_single_file_bundle`, `go_buildinfo`, `unknown_high_entropy`, `unknown_low_entropy`; see [`overlay_info`](#overlay_info)).
  - `findings`: the individual evidence strings (`packer_section:`, `writable_executable_section:`, `high_entropy_exec_with_few_imports`, `entrypoint_outside_executable_sections`, `virtual_size_mismatch:`, `file_overlay`).

The `CHECK_PACKED` security check turns `high`/`medium` likelihood into a finding naming the evidence.

### `overlay_info`

PE only. The classified overlay: the region past the last section's raw bytes, minus the Authenticode certificate table.

| Attribute           | Description                                                                                                                                                        |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `offset`, `size`    | File offset and size of the residue — the overlay that is left once the certificate table is subtracted. `size` is 0 for a stock signed binary, whose entire overlay was the signature. |
| `security_directory`| `{offset, size}` of the `IMAGE_DIRECTORY_ENTRY_SECURITY` region (the PE specification defines the certificate table's "RVA" as a file offset), or `null` when absent. |
| `entropy`           | Shannon entropy of the residue, sampled from its head/tail windows.                                                                                             |
| `classification`    | Magic-based label: `zip`, `cab`, `msi`, `nsis`, `inno`, `installshield`, `sfx_7z`, `dotnet_single_file_bundle`, `go_buildinfo`, `unknown_high_entropy`, `unknown_low_entropy`. The classifier (`blint/lib/pe_overlay.py`) is shared with the installer/container work. |

### `toolchain`

Compiler and runtime attribution built from binary evidence rather than declared metadata. Every signal carries `source` and `confidence`:

- **`compilers`**: from ELF `.comment` sections (gcc, clang, rustc, lld with versions), Mach-O `LC_BUILD_VERSION` tool entries, and the PE linker version fields.
- **`runtimes`**: Go (buildinfo or `runtime.*` symbols), Rust (buildinfo or `_ZN`/`_R` mangling), Swift (`swift_` stdlib symbols), Objective-C (`objc_*` trampolines), MSVC/MinGW CRT fingerprints, .NET.
- **`libc`**: `glibc` or `musl` from symbol-version requirements and the ELF interpreter.

Empty lists mean the format carries no such evidence — attribution is never padded with guesses.

### `import_hash`

A stable digest over the normalized import-name set (ELF dynamic symbols marked as imports, or the `imports` list for PE/Mach-O). Normalization strips ELF `@@VERSION` suffixes, PE `__imp_`/`_imp_` thunks and common leading-underscore decoration, so the same dependency set hashes identically across formats and minor version bumps. Empty for binaries that import nothing (fully static images).

### `swift_metadata`

Swift reflection metadata, parsed by `blint/lib/swift_metadata.py` from `__swift5_*` (Mach-O) or `.swift5_*` (ELF) sections — the same parser serves both formats (issue #109). The sections survive stripping and carry every Swift type's name, fields and metadata access functions.

| Attribute                                   | Description                                                                                                                                                             |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `type_count`, `types`                       | Every Swift type: `name`, `kind` (`class`/`struct`/`enum`), the metadata `access_function` address, and the declared `fields` (property names).                         |
| `kind_counts`                               | Per-kind totals.                                                                                                                                                        |
| `protocol_count`, `protocols`               | Protocol names from `__swift5_protos`.                                                                                                                                  |
| `access_function_count`, `access_functions` | Named code addresses (`metadata_access_function_for_<Type>`) seeded into `functions` so disassembly and callgraph work reaches Swift entry points on stripped binaries. |

Swift type and field names also join the ObjC selectors and symbols in the privacy-marker haystack (`_symbol_haystack`), so a Swift property `creationDate` matches the required-reason API categories like the C symbol spellings do.

### `analysis_coverage`

Accounting for what was analyzed versus what was discovered, so a run that disassembled 3 of 400 functions is never indistinguishable from a clean run of 400:

- **`functions`**: `symbolic` (from symbol buckets), `discovered` (recovered from unwind tables, prologues and call sites), `discovered_merged_into_function_list`, `disassembled`.
- **`degradations`**: reasons parts of the binary were not analyzed, e.g. `fairplay_encrypted`, `disassembly_unavailable`, `slice_summary_failed`.
- **`sections_analyzed`**: sections the entropy pass examined.
- **`slices`** (universal Mach-O binaries only): `total`, `summarized` and `failed` slice counts. A slice whose summary failed is isolated — the remaining slices are still reported, and `errors` carries one record per failed slice (`index`, `exception_type`, `message`).
- **`security_properties_gaps`**: properties the format could carry but blint does not compute yet, or whose source could not be read. Their absence from `security_properties` means "not implemented" or "source unreadable", never "checked and clean". Mach-O records its granular `has_nx_stack` / `has_nx_heap` and unreadable signature blobs here; PE records an unreadable load configuration, an absent debug directory, an unresolved Authenticode scope (catalog signing, W2.3) and unparsed page hashes (no `code_signature` block was parsed).

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

### Parallel analysis

`--jobs N` analyzes up to N binaries in parallel worker processes (default `1`, which is the unchanged sequential loop; `0` or `auto` means one worker per CPU). Both the default mode and `blint sbom` accept the flag; the unit of work is one binary, and there is no parallelism within a binary. Output is byte-identical to the sequential run for any N: every worker result carries its input position and the parent merges strictly in that order, which also holds for `analysis-coverage.json` and the cache counters. A worker that dies hard (e.g. a segfault inside LIEF) is recorded in `analysis-coverage.json` as a failure with `stage: "worker"` and `exception_type: "WorkerDied"` naming the file it was analyzing; the remaining files are still analyzed. If the pool cannot start at all, the run falls back to the sequential path with an error logged. With `--cache --jobs N`, every worker opens its own SQLite connection to the same store (WAL mode); hit/miss/stored totals match the equivalent sequential run.

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
| `cet_shadow_stack`       | **Intel CET / Shadow Stack.** PE: the `CET_COMPAT` bit of the debug directory's EX_DLLCHARACTERISTICS entry.            | Hardware-enforced protection against ROP by maintaining a secondary, immutable stack for return addresses. |
| `retpoline`              | **Retpoline.** Use of return trampolines.                                                                               | Mitigates Spectre Variant 2 (Branch Target Injection) side-channel attacks.                                |
| `cast_guard`             | **CastGuard.** Validates virtual function calls.                                                                        | Mitigates C++ type confusion and vtable hijacking attacks.                                                 |
| `safe_seh`               | **Safe SEH.** (x86) Registers exception handlers at compile time.                                                       | Prevents attackers from overwriting SEH chains on the stack to gain execution.                             |
| `safe_delay_load`        | **Protected Delay-Load IAT.** Marks delay-load tables read-only after initialization.                                   | Prevents hooking of APIs that are loaded lazily during execution.                                          |
| `enclave`                | **Enclave Support.** Binary contains configuration for SGX/VBS.                                                         | Indicates the application uses TEE (Trusted Execution Environment) features for high-security operations.  |
| `packed`                 | **Packing evidence present.** Derived from the [`entropy`](#entropy) block.                                             | Strings, symbols and disassembly-derived findings may be incomplete until the binary is unpacked.          |

For PE, the block is computed from named sources (PE-lane packet W0.3): every property answers from the specific header field that defines it, and is **omitted rather than guessed** when that source is absent — the omission is recorded in [`security_properties_gaps`](#analysis_coverage), never reported as a thin `false`. A load configuration that failed to read is a gap; a load configuration that read and lacks a bit is a computed `false`.

PE-specific properties and their sources:

| Property          | Source | Notes |
| ----------------- | ------ | ----- |
| `aslr` / `high_entropy_va` / `dep` / `force_integrity` | optional header `DLLCharacteristics` bitfield, decoded through blint's PE-spec table (`pe_constants`) | `seh` on x86 from the same field's `NO_SEH` bit. |
| `cfg` / `control_flow_guard` / `xfg` / `rfg` / `retpoline` / `cast_guard` / `safe_delay_load` / `cfg_export_suppression` | load configuration `GuardFlags`, decoded bit by bit through the winnt.h-derived table | `cfg`/`control_flow_guard` are the `CF_INSTRUMENTED` bit. The `EH_CONTINUATION_TABLE_PRESENT` bit is `/guard:ehcont` metadata in [`load_configuration`](#load_configuration), deliberately **not** read as CET. |
| `gs_canary` / `canary` | load configuration `SecurityCookie` != 0 and not `SECURITY_COOKIE_UNUSED` | one value under the PE name and the cross-format name. |
| `safe_seh` | load configuration `SEHandlerCount` (x86 machines) | |
| `cet_shadow_stack` / `cet_shadow_stack_strict` | debug directory `IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS` entry (winnt.h type 20), `CET_COMPAT` bits | user-mode CET is a debug-directory claim, not a GuardFlags one. |
| `debug_info` | debug directory: `full` when a CodeView entry carries a PDB path, `codeview_only` when entries exist without one, `none` for an empty directory | replaces the COFF-symbol-table `stripped` guess, which modern MSVC images made meaningless; `debug_info_pdb_path` carries the path when present. |
| `arm64ec` / `arm64x` | PE header machine type | |
| `authenticode_scope` | `embedded` when a signature table exists | catalog signing is not resolved yet (W2.3), so a non-embedded scope is recorded as a gap rather than guessed as `none`. |
| `signed_page_hashes` | `code_signature.signatures[].page_hashes` | stated either way when a signature was parsed (`true` when any signature carries `SpcPeImageData` page hashes); the gaps list carries it when no block was parsed. |
| `enclave` | load configuration `EnclaveConfigurationPointer` | presence-only: `true` when an enclave configuration exists, omitted otherwise — absence is the Windows norm, not a computed negative. |

`pac`/`pac_strict` are deliberately absent for PE: no PE field records ARM64 pointer authentication (the GuardFlags `RF_*` bits are Return Flow Guard per the Windows SDK headers), so there is no honest source to compute from.

### Windows Containers: MSI databases and CAB archives (`.msi` / `.msp` / `.cab`)

An `.msi` is a CFBF storage whose streams are database tables; a `.cab` is the payload container MSI, drivers and update packages ship. Both parse with pure struct code (`blint/lib/msi.py`, `blint/lib/cab.py`) over the shared CFBF reader (`blint/lib/cfbf.py`) — no OLE library, no Windows API.

| Attribute | Description |
| --- | --- |
| `msi` (exe_type `msi`) | `parse_status`, `table_count`/`tables` (decoded names), `identity` (`product_code`, `upgrade_code`, `package_code`, `product_name`, `product_version`, `manufacturer`), `summary` (the `\x05SummaryInformation` property set: title, author, template, revision number — the PackageCode —, timestamps, application name), `file_count`, `component_count`, `custom_action_count`/`custom_actions` (each with the Type field decoded: `kind` dll/exe/jscript/vbscript, `source`, `deferred_in_script`, `no_impersonate`, `rollback`, `async`, `continue_on_error`, `terminal_server_aware`), `binaries` (Binary-table stream names and sizes — stream bytes are never read), `embedded_cabinets` (Media table's Cabinet column: name, `embedded`, `size`), `digital_signature_present`, `refusals`, `degradations`. |
| `cab` / `cab_members` (exe_type `cab`) | `parse_status`, `version`, `folder_count`, `methods` (`none`/`mszip`/`lzx`/`quantum`), `member_count`, `total_uncompressed`, `extracted_member_count`, `extraction_refusals`, plus the member listing (`name`, `size`, `unsafe_path`). Members in stored/MSZIP folders extract and their PE members (`.exe`/`.dll`/`.sys`) analyze as `cab-member` units attributed to the member path; LZX/Quantum folders refuse by name (`member_compression_unsupported`) — a stdlib-only constraint, stated rather than worked around. |

CFBF chain sanity is a first-class fact (a malformed chain is a finding, not a swallowed error): `fat_chain_loop`, `minifat_chain_loop`, `sector_out_of_range`, `chain_terminated_early`, `directory_tree_loop`, `stream_chain_broken` are named degradations beside whatever was read. Caps are measured (module docstrings): CFBF 4,096 directory entries / 256 MiB per stream / 512 MiB total read budget; CAB 16,384 members / 512 MiB total / 256 MiB per member. In SBOM output the `.msi` parent carries the product identity and codes (`internal:msiProductCode` etc.) and a `.cab` lists its members as components keyed by member path; refusals and degradations reach the BOM as `internal:msi_refusals` / `internal:cab_refusals` (rule 32).

### Installers and ClickOnce manifests (W4.3)

A PE whose overlay residue classifies as an installer family (the W0.2 overlay classifier) carries an `installer` block in its metadata; ClickOnce manifests (`.application`, and `.manifest` files whose namespace is ClickOnce's `asm.v2`) parse as their own units.

| Attribute | Description |
| --- | --- |
| `installer.family` | `nsis`, `sfx_7z`, `inno` or `installshield` — what the overlay classifier matched. |
| `installer.extraction` | States the honesty of the block: `detection_only` (NSIS, Inno, InstallShield — no member extraction) or `members` (7z-SFX — member listing and bounded extraction). **Detection-only is stated in the block, never implied.** |
| `installer.nsis_firstheader` | The documented NSIS `firstheader`: `flags`, `offset`, `length_of_header`, `length_of_all_following_data`. NSIS member extraction is deliberately not implemented — the data block is a compiled install-script database resolved by emulating the script VM, which is a decompiler, not a container reader. Detection-only, stated. |
| `installer.sfx_payload` | The appended 7z archive (signature-header CRC verified before use): `offset`, `version`, `member_count`, `members` (name, size — exact for LZMA/LZMA2/copy folders), `total_unpacked`. BCJ2-encoded folders (x86-filtered SFX modules) refuse by name (`member_compression_unsupported`, `folder_unpack_sizes_unresolved`) rather than listing as analyzable. |
| `clickonce` (exe_type `clickonce`) | `kind` (`deployment`/`application`), `identity` (name, version, publicKeyToken, culture, architecture), `publisher`, `product`, `update_url` (the `<deploymentProvider>`), `requested_execution_level`, `permission_set_unrestricted`, `compatible_frameworks`, `files` (application manifests), `signature_present` (XML-DSig), `refusals`. |

The runner analyzes a 7z-SFX's decodable members (`.exe`/`.dll`/`.sys`) as `sfx-member` units attributed to their member path, beside the stub executable's own top-level unit. `CACHE_SCHEMA_VERSION` moved 10 → 11 in this packet: the `installer` block rides parse() output. No rule consumes the installer block yet — a "packed installer" rule needs a measured benign population (software installers are overwhelmingly legitimate), which is not yet measured.
