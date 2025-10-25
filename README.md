# blint

<img src="./blint.png" width="200" height="auto" />

`blint` is a Binary Linter that checks the security properties and capabilities of your executables. It is powered by [lief](https://github.com/lief-project/LIEF) and can generate a Software Bill-of-Materials (SBOM) for supported binaries.

## What is blint?

blint is a tool for reverse engineers, security analysts, and developers to quickly assess the security posture and composition of a binary file. In an age of statically-linked Golang, Rust, and .NET applications, understanding what's inside a binary is more important than ever. blint automates this initial triage process.

**Supported Binary Formats:**

- ELF (for GNU and musl libc)
- PE (Windows executables and DLLs)
- Mach-O (macOS and iOS, x64 and arm64)
- Android (APK, AAB, including DEX files in deep mode)

## Key Features & Use Cases

- **Comprehensive Security Audits:** Automatically checks for common security mitigations like PIE, ASLR, NX, Stack Canaries, and RELRO. Ideal for ensuring your CI/CD pipeline produces hardened binaries.
- **Software Bill-of-Materials (SBOM) Generation:** Creates CycloneDX SBOMs for binaries built with Go, Rust, .NET, and Android toolchains, providing a clear inventory of third-party components for vulnerability management.
- **Deep Binary Inspection:** Disassembles, extracts, and analyzes a wealth of information including symbols, functions, dependencies, and build toolchains. This raw data is saved as a detailed JSON file.
  - For a complete guide to all attributes in this file, see the [Technical Metadata Documentation](./docs/METADATA.md).
  - Navigate to the [disassembly guide](./docs/DISASSEMBLE.md).
- **Capability Analysis:** Identifies potentially sensitive capabilities by reviewing imported functions and symbols, such as network access, filesystem operations, or cryptographic API usage.
- **CI/CD Integration:** Can be added to build pipelines to enforce security policies, such as requiring code signing on all release artifacts.
- **Fuzzing Target Identification:** Suggests interesting functions to target for fuzzing based on common patterns in function names (e.g., `parse`, `decode`, `copy`).
- **Extensible with Custom Rules:** Define your own capabilities and checks using simple [YAML rule files](./docs/RULES.md).

## Installation

`blint` requires Python >= 3.10.

```bash
pip install blint
```

For **disassembly support**, which enables instruction-level analysis of functions, install the `extended` version. This includes the [nyxstone](https://github.com/emproof-com/nyxstone) disassembler.

```bash
pip install blint[extended]
```

## Quick Start

Analyze a binary and save the reports to the `/tmp/blint` directory:

```bash
blint -i /bin/netstat -o /tmp/blint
```

Analyze a Go or Rust binary and get suggestions for fuzzing targets:

```bash
blint -i /path/to/my-binary --suggest-fuzzable
```

Generate a CycloneDX SBOM for an Android application:

```shell
blint sbom -i /path/to/app.apk -o sbom.cdx.json
```

## Understanding the Output

blint produces several JSON artifacts in the specified reports directory.

| Filename                | Purpose                                                                                         | Details                                                                                                                                                                            |
|-------------------------|-------------------------------------------------------------------------------------------------| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `exename-metadata.json` | **Raw, detailed metadata** extracted from the binary. This is the source for all other reports. | Contains everything: headers, symbols, functions, dependencies, signature info, and more. See the **[Technical Metadata Documentation](./docs/METADATA.md)** for a full breakdown. |
| `findings.json`         | A summary of the **security properties audit**. Designed for CI/CD integration.                 | Lists security mitigations like PIE, NX, and Stack Canaries and whether they are present.                                                                                          |
| `reviews.json`          | A summary of the **capability review**.                                                         | Lists detected capabilities (e.g., "networking", "file-read", "crypto") based on the symbols and functions found.                                                                  |
| `fuzzables.json`        | A list of **suggested functions to fuzz**, generated when using the `--suggest-fuzzable` flag.  | Identifies functions with names that suggest data parsing or manipulation, which are often good candidates for fuzzing.                                                            |
| `sbom-*.cdx.json`       | The **Software Bill-of-Materials (SBOM)**, generated by the `sbom` sub-command.                 | A CycloneDX-formatted JSON file detailing the binary's components and dependencies.                                                                                                |

## Advanced Usage: SBOM Generation with blintdb

For C/C++ binaries, identifying components from symbols alone can be imprecise. `blint` can use **blintdb**, a pre-compiled database of symbols from popular open-source libraries (like those from vcpkg), to dramatically improve component identification.

The workflow is a two-step process:

1.  **Download the blintdb database:**

    ```shell
    blint db --download
    ```

    This downloads the database to the directory specified by the `BLINTDB_HOME` environment variable.

2.  **Generate the SBOM with blintdb enabled:**
    ```shell
    blint sbom -i /path/to/binary -o sbom.cdx.json --use-blintdb
    ```

This will cross-reference symbols found in your binary against the database to identify components like OpenSSL, zlib, and others.

## Command-Line Reference

<details>
<summary><strong>Main Command Help</strong></summary>

```shell
usage: blint [-h] [-i SRC_DIR_IMAGE [SRC_DIR_IMAGE ...]] [-o REPORTS_DIR] [--no-error] [--no-banner] [--no-reviews] [--suggest-fuzzable] [--use-blintdb] {sbom} ...

Binary linter and SBOM generator.

options:
  -h, --help            show this help message and exit
  -i, --src SRC_DIR_IMAGE [SRC_DIR_IMAGE ...]
                        Source directories, container images or binary files. Defaults to current directory.
  -o, --reports REPORTS_DIR
                        Reports directory. Defaults to reports.
  --no-error            Continue on error to prevent build from breaking.
  --no-banner           Do not display banner.
  --no-reviews          Do not perform method reviews.
  --suggest-fuzzable    Suggest functions and symbols for fuzzing based on a dictionary.
  --use-blintdb         Use blintdb for symbol resolution. Use environment variables: BLINTDB_IMAGE_URL, BLINTDB_HOME, and BLINTDB_REFRESH for customization.
  --disassemble         Disassemble functions and store the instructions in the metadata. Requires blint extended group to be installed.
  --custom-rules-dir CUSTOM_RULES_DIR
                        Path to a directory containing custom YAML rule files (.yml or .yaml). These will be loaded in addition to default rules.
  -q, --quiet           Disable logging and progress bars.

sub-commands:
  Additional sub-commands

  {sbom}
    sbom                Command to generate SBOM for supported binaries.
    db                  Command to manage the pre-compiled database.
```

</details>

<details>
<summary><strong>SBOM Sub-command Help</strong></summary>

```shell
usage: blint sbom [-h] [-i SRC_DIR_IMAGE [SRC_DIR_IMAGE ...]] [-o SBOM_OUTPUT] [--deep] [--stdout] [--exports-prefix EXPORTS_PREFIX [EXPORTS_PREFIX ...]]
                  [--bom-src SRC_DIR_BOMS [SRC_DIR_BOMS ...]]

options:
  -h, --help            show this help message and exit
  -i SRC_DIR_IMAGE [SRC_DIR_IMAGE ...], --src SRC_DIR_IMAGE [SRC_DIR_IMAGE ...]
                        Source directories, container images or binary files. Defaults to current directory.
  -o SBOM_OUTPUT, --output-file SBOM_OUTPUT
                        SBOM output file. Defaults to sbom-binary-postbuild.cdx.json in current directory.
  --deep                Enable deep mode to collect more used symbols and modules aggressively. Slow operation.
  --stdout              Print the SBOM to stdout instead of a file.
  --exports-prefix EXPORTS_PREFIX [EXPORTS_PREFIX ...]
                        prefixes for the exports to be included in the SBOM.
  --bom-src SRC_DIR_BOMS [SRC_DIR_BOMS ...]
                        Directories containing pre-build and build BOMs. Use to improve the precision.
```

</details>

<details>
<summary><strong>DB Sub-command Help</strong></summary>

```shell
usage: blint db [-h] [--download] [--image-url IMAGE_URL]

options:
  -h, --help            show this help message and exit
  --download            Download the pre-compiled database to the /Volumes/Work/blintdb/ directory. Use the environment variable `BLINTDB_HOME` to override.
  --image-url IMAGE_URL
                        blintdb image url. Defaults to ghcr.io/appthreat/blintdb-vcpkg-arm64:v1. The environment variable `BLINTDB_IMAGE_URL` is an alternative way to set this value.
```

</details>

## References

- [lief examples](https://github.com/lief-project/LIEF/tree/master/examples)
- [checksec.py](https://github.com/slimm609/checksec.py)

## Sponsorship

If you love `blint`, please consider [donating to our project](https://owasp.org/donate?reponame=www-project-dep-scan&title=OWASP+dep-scan). In addition, `blint` is made possible by the incredible work of the LIEF project. Please consider sponsoring them as well.

- [LIEF Project](https://github.com/sponsors/lief-project/)
