# BLint

<img src="./blint.png" width="200" height="auto" />

BLint is a Binary Linter that checks the security properties and capabilities of your executables. It is powered by [lief](https://github.com/lief-project/LIEF). Since version 2, blint can also generate Software Bill-of-Materials (SBOM) for supported binaries.

[![BLint Demo](https://asciinema.org/a/438138.png)](https://asciinema.org/a/438138)

Supported binary formats:

- Android (apk, aab)
- ELF (GNU, musl)
- PE (exe, dll)
- Mach-O (x64, arm64)

You can run blint on Linux and Mac against any of these binary formats.

## Motivation

Nowadays, vendors distribute statically linked binaries produced by Golang, Rust, or Dotnet tooling. Users are used to running antivirus and anti-malware scans while using these binaries in their local devices. Blint augments these scans by listing the technical capabilities of a binary. For example, whether the binary could use network connections or can perform file system operations and so on.
The binary is first parsed using the lief framework to identify the various properties, such as functions and the presence of symtab and dynamic symbols. Thanks to YAML-based annotation data, this information can be matched against capabilities and presented visually using a rich table.
NOTE: The presence of capabilities doesn't imply that the binary always performs the operations. Use the output of this tool to get an idea about a binary. Also, this tool is not suitable for reviewing malware and other heavily obfuscated binaries for obvious reasons.

## Use cases

- Quickly identify malicious binaries by looking at their capabilities (Ability to manipulate networks or drivers or kernels etc)
- Add blint to CI/CD to inspect the final binaries to ensure code signing or authenticode is applied correctly
- Identify interesting functions and symbols for fuzzing

## Installation

- Install python 3.10, 3.11, or 3.12

```bash
pip install blint
```

For [disassembly](./docs/DISASSEMBLE.md) support, install the extended group which includes [nyxstone](https://github.com/emproof-com/nyxstone).

```bash
pip install blint[extended]
```

### Single binary releases

You can download single binary builds from the [blint-bin releases](https://github.com/OWASP-dep-scan/blint/releases). These executables should work without requiring python to be installed. The macOS .pkg file is signed with a valid developer account.

## Usage

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

### SBOM sub-command

```shell
usage: blint sbom [-h] [-i SRC_DIR_IMAGE [SRC_DIR_IMAGE ...]] [-o SBOM_OUTPUT] [--deep] [--stdout] [--exports-prefix EXPORTS_PREFIX [EXPORTS_PREFIX ...]]
                  [--bom-src SRC_DIR_BOMS [SRC_DIR_BOMS ...]]

options:
  -h, --help            show this help message and exit
  -i SRC_DIR_IMAGE [SRC_DIR_IMAGE ...], --src SRC_DIR_IMAGE [SRC_DIR_IMAGE ...]
                        Source directories, container images or binary files. Defaults to current directory.
  -o SBOM_OUTPUT, --output-file SBOM_OUTPUT
                        SBOM output file. Defaults to bom-post-build.cdx.json in current directory.
  --deep                Enable deep mode to collect more used symbols and modules aggressively. Slow operation.
  --stdout              Print the SBOM to stdout instead of a file.
  --exports-prefix EXPORTS_PREFIX [EXPORTS_PREFIX ...]
                        prefixes for the exports to be included in the SBOM.
  --bom-src SRC_DIR_BOMS [SRC_DIR_BOMS ...]
                        Directories containing pre-build and build BOMs. Use to improve the precision.
```

### DB sub-command

```shell
usage: blint db [-h] [--download] [--image-url IMAGE_URL]

options:
  -h, --help            show this help message and exit
  --download            Download the pre-compiled database to the /Volumes/Work/blintdb/ directory. Use the environment variable `BLINTDB_HOME` to override.
  --image-url IMAGE_URL
                        Blintdb image url. Defaults to ghcr.io/appthreat/blintdb-vcpkg-arm64:v1. The environment variable `BLINTDB_IMAGE_URL` is an alternative way to set this value.
```

To test any binary, including default commands

```bash
blint -i /bin/netstat -o /tmp/blint
```

Use -i to check any other binary. For eg: to check ngrok

```bash
blint -i ~/ngrok -o /tmp/blint
```

Pass `--suggest-fuzzable` to get suggestions for fuzzing. A dictionary containing "common verbs" is used to identify these functions.

```bash
blint -i ~/ngrok -o /tmp/blint --suggest-fuzzable
```

To use [custom rules](./docs/RULES.md), use the `--custom-rules-dir` argument.

```
blint --custom-rules-dir /path/to/my_custom_rules ...
```

To generate SBOM in [CycloneDX format](https://cyclonedx.org/) for supported binaries, use the sbom sub-command.

```shell
blint sbom -i /path/to/apk -o bom.json
```

```shell
blint sbom -i /directory/with/apk/aab -o bom.json
```

To parse all files, including `.dex` files, pass `--deep` argument.

```shell
blint sbom -i /path/to/apk -o bom.json --deep
```

Component identification for C/C++ binaries could be improved with [blintdb](https://github.com/AppThreat/blint-db). To download the pre-compiled database (SQLite format), first run the `db` command followed by the `sbom` command.

```shell
blint db
blint sbom -i /path/to/binary -o bom.json --deep
```

The following binaries are supported:

- Android (apk/aab)
- Dotnet executable binaries
- Go binaries
- Rust binaries
- c/c++ binaries (WIP)

```shell
blint sbom -i /path/to/go-binaries -o bom.json --deep
```

For all other binaries, the symbols will be collected and represented as properties with `internal` prefixes for the parent component. Child components and dependencies would be missing.

PowerShell example

![PowerShell](./docs/blint-powershell.jpg)

## Reports

Blint produces the following json artifacts in the reports directory:

- blint-output.html - HTML output from the console logs
- exename-metadata.json - Raw metadata about the parsed binary. Includes symbols, functions, and signature information
- findings.json - Contains information from the security properties audit. Useful for CI/CD integrations
- reviews.json - Contains information from the capability reviews. Useful for further analysis
- fuzzables.json - Contains a suggested list of methods for fuzzing

sbom command generates CycloneDX json.

## References

- [lief examples](https://github.com/lief-project/LIEF/tree/master/examples)
- [checksec](https://github.com/Wenzel/checksec.py)

## Sponsorship wishlist

If you love blint, you should consider [donating](https://owasp.org/donate?reponame=www-project-dep-scan&title=OWASP+dep-scan) to our project. In addition, consider donating to the below projects, which make blint possible.

- [LIEF](https://github.com/sponsors/lief-project/)
