# Authoring Custom Rules

`blint` allows users to define custom rules to extend its analysis capabilities, particularly for identifying specific behaviors or characteristics within binaries. These rules are defined using YAML files.

## Rule File Structure

A custom rules file is a YAML document with the following top-level keys:

- `text` (Optional): A human-readable description of the review group.
- `group`: Specifies the category of the rules. Valid groups are:
  - `METHOD_REVIEWS`: Reviews symbols found in the main symbol table or function lists.
  - `EXE_REVIEWS`: Reviews symbols (often used for general executable characteristics).
  - `SYMBOL_REVIEWS`: Reviews dynamic symbols (e.g., imported symbols in PE, ELF, MachO).
  - `IMPORT_REVIEWS`: Reviews imported library names or function names (e.g., from PE imports, ELF NEEDED entries).
  - `ENTRIES_REVIEWS`: Reviews dynamic entries (e.g., ELF NEEDED entries).
  - `FUNCTION_REVIEWS`: Reviews the `disassembled_functions` metadata generated when using `--disassemble`.
- `exe_type`: A list of executable types this group applies to. Common types include `PE32`, `PE64`, `ELF`, `MachO`, `dotnetbinary`, `genericbinary`. You can use a single string if it applies to only one type.
- `binary_type` (Optional): An additional filter based on the binary format (e.g., `MachO`, `ELF`, `PE`).
- `rules`: A list of individual rule definitions.

## Rule Definition Structure

Each rule within the `rules` list is a dictionary containing the following keys:

- `id` (Required): A unique identifier string for the rule. This ID is used in the output report.
- `title` (Required): A short, descriptive title for the rule.
- `summary` (Required): A brief summary of what the rule detects.
- `description` (Required): A detailed description of the rule, explaining its purpose and the logic behind it.
- `patterns` (Required for `METHOD_REVIEWS`, `SYMBOL_REVIEWS`, `IMPORT_REVIEWS`, `ENTRIES_REVIEWS`): A list of strings (case-insensitive) to search for within the target symbol/function/entry names. If any pattern matches, the rule triggers.
- `check_type` (Required for `FUNCTION_REVIEWS`): Specifies how the rule evaluates the `disassembled_functions` data. Valid types are:
  - `function_flag`: Checks if a specific boolean field within the function's metadata is `true`.
  - `function_metric`: Compares a numerical field within the function's metadata (e.g., `instruction_metrics`) against a threshold using an operator.
  - `function_analysis`: Requires custom logic within the `blint` codebase to evaluate the function's metadata (e.g., `assembly`, `instruction_metrics`, `regs_read`, etc.) based on complex criteria.
- `check_field` (Required for `function_flag` and `function_metric`): The path to the field within the `disassembled_functions` dictionary for the function being analyzed (e.g., `has_system_call`, `instruction_metrics.xor_count`).
- `operator` (Required for `function_metric`): The comparison operator to use (e.g., `>`, `>=`, `<`, `<=`, `==`, `!=`).
- `threshold` (Required for `function_metric`): The numerical value to compare the `check_field` against using the `operator`.
- `severity` (Optional): Can be used to categorize the rule's output (e.g., `critical`, `high`, `medium`, `low`). This might influence reporting or filtering.

## Sample Rules

Here are examples demonstrating different rule types:

### Example 1: `ENTRIES_REVIEWS` (Dynamic Library Dependencies)

This rule checks for common FFmpeg and SDL libraries in the dynamic entries (`.so` files on Linux/macOS).

```yaml
---
text: Review for dynamic entries (.so files) identified in a binary produced by GNU build
group: ENTRIES_REVIEWS
exe_type: genericbinary
rules:
  - id: FFMPEG_LIB
    title: FFMPEG library used
    summary: Can Manipulate Multimedia files
    description: |
      FFmpeg is the leading multimedia framework, able to decode, encode, transcode, mux, demux, stream, filter and play pretty much anything that humans and machines have created. It supports the most obscure ancient formats up to the cutting edge. No matter if they were designed by some standards committee, the community or a corporation. It is also highly portable: FFmpeg compiles, runs, and passes our testing infrastructure FATE across Linux, Mac OS X, Microsoft Windows, the BSDs, Solaris, etc. under a wide variety of build environments, machine architectures, and configurations.
    patterns:
      - libavutil
      - libswscale
      - libswresample
      - libavcodec
      - libavformat
      - libavdevice
      - libavfilter

  - id: SDL_LIB
    title: Simple DirectMedia layer library used
    summary: Can Access Graphics & Input Devices
    description: |
      Simple DirectMedia Layer is a cross-platform development library designed to provide low level access to audio, keyboard, mouse, joystick, and graphics hardware via OpenGL and Direct3D. It is used by video playback software, emulators, and popular games including Valve's award winning catalog and many Humble Bundle games.
    patterns:
      - libsdl2
```

### Example 2: `SYMBOL_REVIEWS` (MachO Symbols)

This rule checks for specific API function calls in a MachO binary.

```yaml
---
text: Review for symbols identified in a MachO binary
group: SYMBOL_REVIEWS
exe_type: MachO
binary_type: MachO
rules:
  - id: FS_API
    title: File System API functions used
    summary: Can Manipulate Files
    description: |
      A convenient interface to the contents of the file system, and the primary means of interacting with it. A file manager object lets you examine the contents of the file system and make changes to it. The FileManager class provides convenient access to a shared file manager object that is suitable for most types of file-related manipulations. A file manager object is typically your primary mode of interaction with the file system. You use it to locate, create, copy, and move files and directories. You also use it to get information about a file or directory or change some of its attributes.
    patterns:
      - NSHomeDirectory
      - NSUserName
      - NSFullUserName
      - homeDirectory
      - NSHomeDirectoryForUser
      - NSTemporaryDirectory
      - NSSearchPathForDirectoriesInDomains
      - NSOpenStepRootDirectory
      - containerURL
      - contentsOfDirectory
      - mountedVolumeURLs
      - subpathsOfDirectory
      - subpaths
      - createDirectory
      - createDirectory
      - createFile
      - removeItem
      - removeItem
      - trashItem
      - replaceItem
      - copyItem
      - moveItem
      - isUbiquitousItem
      - startDownloadingUbiquitousItem
      - evictUbiquitousItem
      - createSymbolicLink
      - linkItem
      - destinationOfSymbolicLink
      - fileExists
      - isReadableFile
      - isWritableFile
      - isExecutableFile
      - isDeletableFile
      - attributesOfFileSystem
      - changeCurrentDirectoryPath
      - NSFileTypeForHFSTypeCode
      - changeFileAttributes
      - fileSystemAttributes
      - directoryContents
      - pathContentOfSymbolicLink
```

### Example 3: `FUNCTION_REVIEWS` (Malware Analysis Indicators)

These rules analyze the disassembled function metadata for signs of potentially malicious behavior.

```yaml
---
group: FUNCTION_REVIEWS
exe_type: [PE32, PE64, genericbinary, ELF, MachO]
rules:
  - id: INDIRECT_EXECUTION
    title: Function with Indirect Execution
    summary: Function uses indirect calls or jumps (e.g., call rax), a common technique in malware.
    description: Indirect control flow can be used to hide malicious functionality or implement complex logic like virtual function calls.
    check_type: function_flag
    check_field: has_indirect_call
  - id: HIGH_XOR_USAGE
    title: Function with High XOR Instruction Count
    summary: Function contains a disproportionately high number of XOR instructions.
    description: XOR instructions are common in obfuscation techniques and cryptographic routines. Checks `xor_count` in `instruction_metrics`.
    check_type: function_metric
    check_field: instruction_metrics.xor_count
    operator: ">"
    threshold: 50
  - id: CRYPTO_BEHAVIOR
    title: Function with Cryptographic Behavior
    summary: Function exhibits behavior commonly found in cryptographic routines.
    description: This function contains a high number of bitwise/shift/rotate instructions and uses SIMD registers, which is a strong indicator of cryptographic operations.
    check_type: function_analysis
  - id: HIGH_REGISTER_USAGE
    title: Function with High Register Usage
    summary: Function reads or writes a very high number of unique registers.
    description: Functions performing cryptographic operations or heavy obfuscation often manipulate many registers simultaneously. Checks `unique_regs_read_count` or `unique_regs_written_count` in `instruction_metrics`.
    check_type: function_metric
    check_field: instruction_metrics.unique_regs_read_count
    operator: ">"
    threshold: 25
  - id: POTENTIAL_ANTI_DEBUG
    title: Function Contains Potential Anti-Debugging Checks
    summary: Function contains patterns commonly used for anti-debugging.
    description: This could involve checking specific registers, calling specific APIs (if resolved later), or using instructions like rdtsc for timing.
    check_type: function_analysis
  - id: HIGH_ARITHMETIC_USAGE
    title: Function with High Arithmetic Instruction Count
    summary: Function contains a disproportionately high number of arithmetic/logical instructions (e.g., add, sub, imul, and, or).
    description: High usage of arithmetic instructions can be a sign of cryptographic algorithms or complex mathematical computations often found in malware. Checks `arith_count` in `instruction_metrics`.
    check_type: function_metric
    check_field: instruction_metrics.arith_count
    operator: ">"
    threshold: 50
  - id: COMPLEX_CONTROL_FLOW
    title: Function with Complex Control Flow
    summary: Function contains a high number of conditional jumps, indicating complex logic or obfuscation.
    description: A high `conditional_jump_count` in `instruction_metrics` can suggest complex control flow, often used for obfuscation.
    check_type: function_metric
    check_field: instruction_metrics.conditional_jump_count
    operator: ">"
    threshold: 50
  - id: POTENTIAL_SHELLCODE_CHARS
    title: Function Exhibits Potential Shellcode Characteristics
    summary: Function combines several indicators common in shellcode (e.g., syscalls, indirect calls, high register usage).
    description: A meta-rule combining flags like `has_system_call`, `has_indirect_call`, high `instruction_metrics.conditional_jump_count`, and low `instruction_count` might indicate shellcode-like behavior.
    check_type: function_analysis
  - id: HIGH_JUMP_USAGE
    title: Function with High Unconditional Jump Count
    summary: Function contains a disproportionately high number of unconditional jump instructions.
    description: High `jump_count` in `instruction_metrics` might indicate obfuscation techniques or the implementation of jump tables, common in packed or obfuscated code.
    check_type: function_metric
    check_field: instruction_metrics.jump_count
    operator: ">"
    threshold: 50
  - id: POTENTIAL_ROP_GADGET
    title: Function Resembles a Potential ROP Gadget
    summary: Function is very small, performs minimal operations, and ends with a return.
    description: Short functions (e.g., < 10 instructions) that read registers/stack, perform simple operations, and end with `ret` might be ROP gadgets used in exploits.
    check_type: function_analysis
```

## Using Custom Rules

To use your custom rules:

1.  **Create a Directory:** Place your YAML rule files (e.g., `my_custom_rules.yml`) in a dedicated directory (e.g., `./my_rules/`).
2.  **Run `blint`:** Use the `--custom-rules-dir` command-line argument when running `blint`, pointing it to your directory containing the YAML files.

    ```bash
    blint --disassemble --custom-rules-dir ./my_rules/ /path/to/binary
    ```

`blint` will load the rules from the specified directory and apply them during the analysis, reporting matches alongside its default checks. Rules in the custom directory are loaded _after_ the default rules, so they will be applied to the analysis process.
