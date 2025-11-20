# Understanding blint's Binary Metadata

## Introduction

blint is a binary analysis tool that examines executable files to extract a wide range of metadata. This document serves as a technical guide for security analysts and reverse engineers who want to understand the JSON output produced by blint.

The primary goal of blint's metadata generation is to act as a "Rosetta Stone" for binary formats. It parses different and often complex structures from ELF, PE, and Mach-O files and presents them in a single, standardized JSON format. This allows for consistent analysis, scripting, and threat hunting across different operating systems and architectures.

This guide details the attributes found in the metadata, their purpose, and the methods blint uses to obtain them, including notable strengths and limitations.

## Core Concepts and Top-Level Attributes

At the highest level, the JSON output contains attributes that identify the binary and provide universally applicable information.

| Attribute           | Description                                                                                                                                                                                                                                                   | Use Case                                                                                                                           |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `file_path`         | The absolute path to the analyzed binary file on the filesystem.                                                                                                                                                                                              | Basic file identification and tracking.                                                                                            |
| `binary_type`       | The format of the binary, such as `ELF`, `PE`, or `MachO`. This is the primary key for interpreting format-specific sections.                                                                                                                                 | Directing further analysis; knowing which format-specific tools to use next.                                                       |
| `hashes`            | A collection of cryptographic hashes for the file, including MD5, SHA1, SHA256, and SHA512.                                                                                                                                                                   | File identification, malware signature matching, and searching in threat intelligence platforms like VirusTotal.                   |
| `llvm_target_tuple` | A string constructed to represent the binary's target environment in a format recognized by LLVM. The format is `arch-vendor-os-environment`. For example: `x86_64-pc-win32-msvc` or `mipsel-unknown-linux-muslsf`. This is crucial for accurate disassembly. | Configuring disassemblers and decompilers; understanding the intended operating system and ABI.                                    |
| `strings`           | A list of strings extracted from the binary that exhibit high entropy or match patterns for secrets (API keys, private keys, etc.). Non-secret strings are filtered out to reduce noise. Base64-encoded strings are automatically decoded.                    | Triage for hardcoded credentials, sensitive URLs, or cryptographic material. A primary step in vulnerability and malware analysis. |

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

### For PE Binaries

PE (Portable Executable) files are the standard for Windows.

- **Headers (`dos_header`, `header`, `optional_header`):**
  - `machine_type`: The target architecture (e.g., `AMD64`, `I386`).
  - `subsystem`: Indicates whether the application is `WINDOWS_GUI` or `WINDOWS_CUI` (console).
  - `dll_characteristics`: A set of flags indicating security features like `DYNAMIC_BASE` (ASLR) and `CONTROL_FLOW_GUARD`.

- **Authenticode (`authenticode`, `signatures`):** Detailed information about the binary's digital signature.
  - Provides hashes (`authentihash_*`) of the signed content.
  - Extracts information about the signer, including the issuer (`cert_signer`) and serial number. This is vital for trust verification and threat intelligence.

- **Resources (`resources`):** Metadata extracted from the `.rsrc` section.
  - `version_metadata`: Contains key-value pairs like `ProductName`, `CompanyName`, and `FileVersion`. Useful for identifying the software and its origin.
  - `manifest`: The embedded XML application manifest, which controls privileges, dependencies, and UI settings.

- **Imports and Exports (`imports`, `exports`):**
  - `imports`: A list of all functions imported from external DLLs, grouped by library. Forms the basis of the `imphash`.
  - `exports`: A list of all functions this binary provides to other executables.

- **Exceptions (exceptions):**

For x86-64 and ARM64 PE binaries, this section provides detailed stack unwinding information extracted from the IMAGE_DIRECTORY_ENTRY_EXCEPTION.

    Attributes:
        - rva_start and rva_end: The memory boundaries of the function code.
        - unwind_info: metadata including sizeof_prologue, frame_reg (frame pointer register), and flags.
        - opcodes: The specific machine instructions (e.g., PUSH_NONVOL, ALLOC_SMALL) used to set up the stack frame.
        - handler_rva: The address of the language-specific exception handler (e.g., __C_specific_handler).

    - Use Cases for Analysts:
        - Function Discovery in Stripped Binaries: Even if the symbol table is removed, the Exception Directory must remain valid for the OS to handle crashes. This makes rva_start and rva_end the most reliable way to discover function boundaries in stripped malware or commercial software.
        - Stack Frame Reconstruction: By analyzing the opcodes and prologue_size, analysts can reconstruct exactly how the stack is manipulated. This is vital for understanding where local variables are stored and identifying potential buffer overflow conditions.
        - Anti-Analysis Detection: Malware sometimes employs custom exception handlers (handler_rva) to obscure control flow or detect debuggers. Identifying non-standard handlers is a key indicator of obfuscation.

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

### Function Lists: `functions`, `ctor_functions`, `dtor_functions`

While symbol tables provide the names, these lists represent a curated set of functions that LIEF identifies as code entry points.

- **`functions`**: A list of general functions identified by the parser, often corresponding to exported symbols or entries in specific sections.

- **`ctor_functions`**: A list of **constructors**. These are special functions that are executed _before_ the program's main entry point (`main` or `WinMain`).
  - **Purpose**: To initialize the program's state or set up runtime environments.
  - **Use Case for Analysts**: Malware and legitimate programs alike use constructors for early initialization. Examining these functions can reveal anti-debugging checks, environment setup, or other critical startup logic that occurs before the main code path.

- **`dtor_functions`**: A list of **destructors**. These are special functions that are executed when the program exits cleanly.
  - **Purpose**: To perform cleanup tasks like flushing files or releasing resources.
  - **Use Case for Analysts**: Malware may use destructors to cover its tracks, delete files, or send a final beacon upon exit. These are important to check for cleanup or anti-forensic activities.

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

| Attribute             | Description                                                                                                                                                                | Use Case                                                                                                                                                                                                                                       |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `go_dependencies`     | A list of Go packages used to build the binary, extracted from the embedded `.go.buildinfo` section. Includes package names, exact versions, and checksums (`h1:` hashes). | **Gold Standard for SCA.** Allows for precise identification of Go libraries and their versions, enabling direct mapping to known vulnerabilities (CVEs) in those packages.                                                                    |
| `rust_dependencies`   | A list of Rust crates used to build the binary, extracted from the `.dep-v0` section created by the `cargo-auditable` feature. Includes crate name, version, and kind.     | Similar to Go, this enables precise SCA for Rust applications, mapping crates to known CVEs. **Limitation**: This section is only present if the developer explicitly enables the `cargo-auditable` feature during compilation.                |
| `dotnet_dependencies` | A structured list of NuGet packages and their versions, extracted from the `deps.json` file embedded in the PE overlay of self-contained .NET applications.                | Provides precise SCA for .NET applications, allowing for vulnerability mapping. **Limitation**: This is only available for .NET Core/5+ applications published in "self-contained" mode and is not present in framework-dependent deployments. |
| `import_dependencies` | A structured graph detailing which shared libraries (`.dll`, `.so`, `.dylib`) are imported by the main binary and which specific symbols are used from each library.       | Provides a clear, high-level view of runtime dependencies. Helps identify the use of sensitive APIs (e.g., crypto, networking) and from which library they originate. This is a foundational element for behavior analysis.                    |

---

## Derived and Analytical Attributes

This is where blint provides the most value, by interpreting low-level data and presenting high-level security and compositional insights.

### `security_properties`

This object provides a quick, at-a-glance summary of the most important security mitigations compiled into the binary.

| Property             | Description                                                                                                                                                                               | Security Implication                                                                                                  |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `nx`                 | **Non-eXecutable Stack/Heap.** True if memory regions intended for data (like the stack and heap) are marked as non-executable.                                                           | Mitigates entire classes of exploits that rely on injecting and executing shellcode from the stack or heap.           |
| `pie`                | **Position-Independent Executable.** True if the binary is compiled to be loaded at a random memory address each time it runs.                                                            | A prerequisite for effective ASLR (Address Space Layout Randomization). Makes ROP/JOP attacks significantly harder.   |
| `relro`              | **Relocation Read-Only.** Describes the protection level of ELF global data sections (`.got`, `.dtors`). Can be `"no"`, `"partial"`, or `"full"`.                                         | `"full"` RELRO makes the Global Offset Table (GOT) read-only after linking, preventing GOT overwrite exploits.        |
| `canary`             | **Stack Canary.** True if the binary was compiled with stack canaries, which are secret values placed on the stack to detect buffer overflows before they can overwrite return addresses. | A primary defense against classic stack-based buffer overflow attacks.                                                |
| `stripped`           | **Stripped Symbols.** True if the symbol table (`.symtab`), which contains names for internal, non-exported functions, has been removed.                                                  | Makes reverse engineering more difficult as function names are lost. Most production binaries are stripped.           |
| `is_signed`          | True if the binary has a digital signature (Authenticode for PE, Code Signature for Mach-O).                                                                                              | Indicates the binary's integrity and origin can be potentially verified. An unsigned binary is often more suspicious. |
| `control_flow_guard` | **(PE Only)** True if the binary is compiled with Microsoft's Control Flow Guard, which validates indirect call targets.                                                                  | Mitigates exploits that rely on corrupting function pointers to hijack control flow.                                  |
