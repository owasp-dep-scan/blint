# `disassembled_functions` Attribute Documentation

## Overview

The `disassembled_functions` attribute is an optional output of the `blint` binary analysis tool. It provides disassembled machine code and related analysis for functions identified in the binary's metadata (e.g., from symbol tables). This feature requires the `nyxstone` library for disassembly.

## Prerequisites

*   LLVM 18 and g++ must be installed. Alternatively, use the blint container image.
*   blint extended with `nyxstone` library must be installed (`pip install blint[extended]`).
*   Invoke blint cli with `--disassemble`

## Structure

The `disassembled_functions` attribute is a dictionary where keys are function names (as determined by the initial `lief` parsing and symbol resolution). The value for each key is another dictionary containing the following fields:

| Field Name | Type | Description |
| :--- | :--- | :--- |
| `name` | String | The name of the function. |
| `address` | String | The virtual address of the function entry point (hexadecimal string, e.g., "0x12345"). |
| `assembly` | String | The full disassembled code of the function, with instructions separated by newlines. |
| `assembly_hash` | String | A SHA-256 hash of the entire `assembly` string. |
| `instruction_hash` | String | A SHA-256 hash of the newline-separated list of instruction *mnemonics* (e.g., "push", "mov", "call"). |
| `instruction_count` | Integer | The total number of instructions disassembled. |
| `instruction_metrics` | Dictionary | A map of specific instruction types to their counts. |
| `direct_calls` | List of Strings | A list of function names identified as targets of *direct* calls (e.g., `call 0x123456` where `0x123456` resolves to a known function name) within this function. |
| `has_indirect_call` | Boolean | True if the function contains instructions like `call rax` or `call [rax+0x10]`. |
| `has_system_call` | Boolean | True if the function contains system call instructions (e.g., `syscall`, `int 0x80`). |
| `has_security_feature` | Boolean | True if the function contains instructions related to security features (e.g., `endbr64`, `endbr32`). |
| `has_crypto_call` | Boolean | True if the function's disassembly text contains patterns indicating cryptographic operations (based on `blint.config.CRYPTO_INDICATORS`). |
| `has_gpu_call` | Boolean | True if the function's disassembly text contains patterns indicating GPU-related operations (based on `blint.config.GPU_INDICATORS`). |
| `has_loop` | Boolean | True if the function contains conditional jumps that target addresses earlier within the disassembled range (indicating a potential loop). |
| `function_type` | String | A classification of the function based on heuristics (e.g., "PLT_Thunk", "Simple_Return", "Has_Indirect_Calls", "Has_Conditional_Jumps", "Complex"). |

### `instruction_metrics` Sub-structure

The `instruction_metrics` dictionary contains counts for specific categories of instructions found during disassembly:

| Field Name | Type | Description |
| :--- | :--- | :--- |
| `call_count` | Integer | Number of `call` instructions. |
| `conditional_jump_count` | Integer | Number of conditional jump instructions (e.g., `je`, `jne`, `jg`, `jle`). |
| `xor_count` | Integer | Number of `xor` instructions. |
| `shift_count` | Integer | Number of shift/rotate instructions (e.g., `shl`, `shr`, `rol`, `ror`). |
| `arith_count` | Integer | Number of arithmetic/logical instructions (e.g., `add`, `sub`, `imul`, `and`, `or`). |
| `ret_count` | Integer | Number of `ret` instructions. |
| `jump_count` | Integer | Number of `jmp` instructions. |

## Use Cases

1.  **Binary Fingerprinting and Diffing:** Compare binaries by matching functions based on their `assembly_hash` or `instruction_hash`. This helps identify identical or modified functions between different versions or variants of a binary.
2.  **Vulnerability Detection:** Identify functions containing specific instruction patterns or sequences associated with known vulnerabilities or insecure coding practices. The `instruction_metrics` can highlight functions with unusual numbers of certain instructions.
3.  **Malware Analysis:** Analyze the disassembled code for suspicious patterns, such as indirect calls (`has_indirect_call`), system calls (`has_system_call`), or cryptographic operations (`has_crypto_call`). The `assembly` field allows for manual inspection.
4.  **Code Similarity Analysis:** Group functions based on their `assembly_hash` or `instruction_hash` to find duplicated or similar code blocks within a binary.
5.  **Function Characterization:** Quickly assess the nature of a function using the `function_type` field and boolean flags (`has_loop`, `has_security_feature`, etc.). This can help prioritize analysis or identify specific types of functions (e.g., PLT thunks).
6.  **Call Graph Approximation:** Use the `direct_calls` field to build a partial call graph based on statically resolvable direct calls. Note that this will not include calls resolved via PLT/GOT or indirect calls.
7.  **Security Feature Verification:** Confirm the presence of control-flow integrity features (like CET) by checking the `has_security_feature` flag and examining the `assembly` for relevant instructions.

