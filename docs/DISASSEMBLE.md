# `disassembled_functions` Attribute Documentation

## Overview

The `disassembled_functions` attribute is an optional output of the `blint` binary analysis tool. It provides disassembled machine code and related analysis for functions identified in the binary's metadata (e.g., from symbol tables). This feature requires the `nyxstone` library for disassembly.

## Prerequisites

- LLVM 18 and g++ must be installed. Alternatively, use the blint container image.
- blint extended with `nyxstone` library must be installed (`pip install blint[extended]`).
- Invoke blint cli with `--disassemble`

## Structure

The `disassembled_functions` attribute is a dictionary where each key is a unique string identifying the function by its virtual address and name, in the format "0xADDRESS::FUNCTION_NAME" (e.g., "0x140012345::simple_add"). Using both address and name prevents collisions in cases where multiple functions might share the same name (e.g., in different modules or due to symbol stripping). The value for each key is another dictionary containing the following fields:

| Field Name                    | Type               | Description                                                                                                                                                                                                                                                                                        |
|:------------------------------|:-------------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `name`                        | String             | The name of the function.                                                                                                                                                                                                                                                                          |
| `address`                     | String             | The virtual address of the function entry point (hexadecimal string, e.g., "0x12345").                                                                                                                                                                                                             |
| `assembly`                    | String             | The full disassembled code of the function, with instructions separated by newlines.                                                                                                                                                                                                               |
| `assembly_hash`               | String             | A SHA-256 hash of the entire `assembly` string.                                                                                                                                                                                                                                                    |
| `instruction_hash`            | String             | A SHA-256 hash of the newline-separated list of instruction _mnemonics_ (e.g., "push", "mov", "call").                                                                                                                                                                                             |
| `instruction_count`           | Integer            | The total number of instructions disassembled.                                                                                                                                                                                                                                                     |
| `instruction_metrics`         | Dictionary         | A map of specific instruction types to their counts.                                                                                                                                                                                                                                               |
| `direct_calls`                | List of Strings    | A list of function names identified as targets of _direct_ calls (e.g., `call 0x123456` where `0x123456` resolves to a known function name) within this function.                                                                                                                                  |
| `has_indirect_call`           | Boolean            | True if the function contains instructions like `call rax` or `call [rax+0x10]`.                                                                                                                                                                                                                   |
| `has_system_call`             | Boolean            | True if the function contains system call instructions (e.g., `syscall`, `int 0x80`).                                                                                                                                                                                                              |
| `has_security_feature`        | Boolean            | True if the function contains instructions related to security features (e.g., `endbr64`, `endbr32`).                                                                                                                                                                                              |
| `has_crypto_call`             | Boolean            | True if the function's disassembly text contains patterns indicating cryptographic operations (based on `blint.config.CRYPTO_INDICATORS`).                                                                                                                                                         |
| `has_gpu_call`                | Boolean            | True if the function's disassembly text contains patterns indicating GPU-related operations (based on `blint.config.GPU_INDICATORS`).                                                                                                                                                              |
| `has_loop`                    | Boolean            | True if the function contains conditional jumps that target addresses earlier within the disassembled range (indicating a potential loop).                                                                                                                                                         |
| `regs_read`                   | List of Strings    | A list of unique register names that are _read_ within the disassembled function code. This provides a high-level view of all registers whose values influence the function's execution.                                                                                                           |
| `regs_written`                | List of Strings    | A list of unique register names that are _written to_ within the disassembled function code. This indicates registers whose values are modified by the function.                                                                                                                                   |
| `used_simd_reg_types`         | List of Strings    | A list of SIMD register types such as FPU, MMX, SSE/AVX etc.                                                                                                                                                                                                                                       |
| `instructions_with_registers` | List of Dictionary | A detailed list providing register usage information for _each individual instruction_ within the function.                                                                                                                                                                                        |
| `function_type`               | String             | A classification of the function based on heuristics. Possible values include: "PLT_Thunk", "Simple_Return", "Has_Syscalls", "Has_Indirect_Calls", or "Has_Conditional_Jumps". If a function doesn't fit these specific categories but is not a simple return, this field will be an empty string. |
| `proprietary_instructions`    | List of Strings    | (Apple Silicon Only) A list of categories for proprietary instructions found (e.g., "GuardedMode", "AMX"). This indicates the use of non-standard hardware features.                                                                                                                                                                                                                   |
| `sreg_interactions`           | List of Strings    | (Apple Silicon Only) A list of categories for interactions with proprietary System Registers (e.g., "SPRR_CONTROL", "PAC_KEYS"). This signals manipulation of low-level security and hardware configuration.                                                                                                                                                                                                                |                                                                                                                                                                                                                              |

### `instruction_metrics` Sub-structure

The `instruction_metrics` dictionary contains counts for specific categories of instructions found during disassembly:

| Field Name                  | Type    | Description                                                                                   |
| :-------------------------- | :------ | :-------------------------------------------------------------------------------------------- |
| `call_count`                | Integer | Number of `call` instructions.                                                                |
| `conditional_jump_count`    | Integer | Number of conditional jump instructions (e.g., `je`, `jne`, `jg`, `jle`).                     |
| `xor_count`                 | Integer | Number of `xor` instructions.                                                                 |
| `shift_count`               | Integer | Number of shift/rotate instructions (e.g., `shl`, `shr`, `rol`, `ror`).                       |
| `arith_count`               | Integer | Number of arithmetic/logical instructions (e.g., `add`, `sub`, `imul`, `and`, `or`).          |
| `ret_count`                 | Integer | Number of `ret` instructions.                                                                 |
| `jump_count`                | Integer | Number of `jmp` instructions.                                                                 |
| `simd_fpu_count`            | Integer | Number of `simd` instructions.                                                                |
| `unique_regs_read_count`    | Integer | Number of unique registers read within the function (aggregated from all instructions).       |
| `unique_regs_written_count` | Integer | Number of unique registers written to within the function (aggregated from all instructions). |

### `instructions_with_registers` Sub-structure

Each element in the `instructions_with_registers` list is a dictionary corresponding to a single disassembled instruction. It contains:

| Field Name     | Type            | Description                                                                                      |
| :------------- | :-------------- | :----------------------------------------------------------------------------------------------- |
| `regs_read`    | List of Strings | A list of register names that are _read_ as part of this specific instruction's operation.       |
| `regs_written` | List of Strings | A list of register names that are _written to_ as part of this specific instruction's operation. |

#### Understanding Register Usage

The `regs_read` and `regs_written` fields (both globally for the function and per-instruction) provide a first-pass approximation of register usage. They analyze the textual representation of the assembly instruction.

- **`regs_read`**: Indicates registers whose current value is used by the instruction.
  - Example: `add rax, rbx`
    - `regs_read`: `["rax", "rbx"]` (The values in `rax` and `rbx` are inputs to the addition).
- **`regs_written`**: Indicates registers whose value is modified or set by the instruction.
  - Example: `add rax, rbx`
    - `regs_written`: `["rax"]` (The result of `rax + rbx` is stored back into `rax`).
- **Implicit Operands**: Some instructions implicitly read or write specific registers (e.g., `push`/`pop` use `rsp`; `call`/`ret` affect `rsp` and `rip`). The analysis attempts to account for common implicit behaviors for certain instruction types, but coverage might not be exhaustive.
- **Memory Operands**: Instructions accessing memory via addresses calculated from registers (e.g., `mov rax, [rbx + rcx*2]`) indicate that `rbx` and `rcx` are read (used for address calculation). The destination `rax` is written.
- **Limitations**: This analysis is based on parsing the assembly text string. It provides a good approximation for common instructions but might be inaccurate for highly complex or obfuscated code, or for instructions not explicitly handled in the parsing logic.

-----

## Use Cases

1.  **Binary Fingerprinting and Diffing:** Compare binaries by matching functions based on their `assembly_hash` or `instruction_hash`. This helps identify identical or modified functions between different versions or variants of a binary.
2.  **Vulnerability Detection:** Identify functions containing specific instruction patterns or sequences associated with known vulnerabilities or insecure coding practices. The `instruction_metrics` can highlight functions with unusual numbers of certain instructions.
3.  **Malware Analysis:** Analyze the disassembled code for suspicious patterns, such as indirect calls (`has_indirect_call`), system calls (`has_system_call`), or cryptographic operations (`has_crypto_call`). The `assembly` field allows for manual inspection.
4.  **Code Similarity Analysis:** Group functions based on their `assembly_hash` or `instruction_hash` to find duplicated or similar code blocks within a binary.
5.  **Function Characterization:** Quickly assess the nature of a function using the `function_type` field and boolean flags (`has_loop`, `has_security_feature`, etc.). This can help prioritize analysis or identify specific types of functions (e.g., PLT thunks).
6.  **Call Graph Approximation:** Use the `direct_calls` field to build a partial call graph based on statically resolvable direct calls. Note that this will not include calls resolved via PLT/GOT or indirect calls.
7.  **Security Feature Verification:** Confirm the presence of control-flow integrity features (like CET) by checking the `has_security_feature` flag and examining the `assembly` for relevant instructions.
8.  **Register Usage Analysis:**
    - **Identify Potential Arguments:** Functions that read specific registers (especially those used for argument passing conventions like `rcx`, `rdx`, `r8`, `r9` on Windows x64 or `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9` on System V AMD64 ABI) at the beginning might be taking arguments via those registers.
    - **Track Data Flow:** By examining `instructions_with_registers`, you can trace how data moves through registers within a function. For example, seeing `rax` written by one instruction and then read by a subsequent one.
    - **Detect Register Preservation:** Check if a function modifies callee-saved registers (like `rbx`, `rbp`, `r12-r15` on x64) without restoring them, which might violate calling conventions or indicate specific behavior.
    - **Spot Unusual Register Patterns:** Functions that read or write an unusually large number of registers might be complex, perform context switching, or manipulate state extensively.
9. Analyzing Proprietary Hardware Features (Apple Silicon)

The proprietary_instructions and sreg_interactions fields provide powerful insights into how software leverages Apple's custom silicon features. This is critical for security research, anti-tampering analysis, and performance tuning on macOS and iOS.
    - **Detecting Advanced Security Hardening:**
        - Use Case: A kernel extension or system daemon uses hardware-enforced memory permissions that are stronger than standard ARM features.
        - blint Findings: The sreg_interactions list contains "SPRR_CONTROL" or "GXF_CONTROL".
        - Analysis: This indicates the function is setting up or entering a "Guarded Execution" mode (GXF) or manipulating the Secure Page Table (SPRR). This code is highly security-sensitive and is likely part of Apple's core operating system defenses, such as protecting kernel memory or DRM components.
    - **Identifying Anti-Debugging and Anti-Emulation:**
        - Use Case: A protected application wants to detect if it's being run under a debugger or in an emulator. It does this by reading hardware performance counters, which behave differently in virtualized environments.
        - blint Findings: The sreg_interactions list contains "PERF_COUNTERS".
        - Analysis: This is a strong indicator of an anti-analysis technique. The function is likely measuring execution time or specific hardware events to detect anomalies caused by debuggers or emulators.
    - **Finding Performance-Critical Code:**
        - Use Case: A high-performance application uses Apple's custom matrix co-processor for machine learning or signal processing tasks.
        - blint Findings: The proprietary_instructions list contains "AMX" (Apple Matrix Coprocessor).
        - Analysis: This function is a candidate for performance analysis. It directly leverages specialized hardware, and any changes to it could have significant performance implications.
    - **Locating Kernel-Level Pointer Authentication Logic:**
        - Use Case: The kernel is configuring Pointer Authentication (PAC) keys to protect its own function pointers from being overwritten in an attack.
        - blint Findings: The sreg_interactions list contains "PAC_KEYS".
        - Analysis: This function is manipulating the hardware keys used for pointer signing and authentication. It is a critical part of the system's control-flow integrity and a high-value target for security researchers.

------

## Examples

Consider a simple function that adds two numbers passed in `rcx` and `rdx`, stores the result in `rax`, and returns.

**Disassembly Snippet:**

```assembly
simple_add:
   push rbp
   mov rbp, rsp
   mov rax, rcx  ; Move first argument (rcx) to rax
   add rax, rdx  ; Add second argument (rdx) to rax
   pop rbp
   ret
```

**Corresponding `disassembled_functions` Entry (Simplified):**

```json
{
  "0x140012345::simple_add": {
    "name": "simple_add",
    "address": "0x140012345",
    "assembly": "push rbp\nmov rbp, rsp\nmov rax, rcx\nadd rax, rdx\npop rbp\nret",
    "instruction_count": 6,
    "instruction_metrics": {
      "arith_count": 1,
      "call_count": 0,
      ...
      "unique_regs_read_count": 4,
      "unique_regs_written_count": 3
    },
    "regs_read": ["rbp", "rsp", "rcx", "rdx"],
    "regs_written": ["rbp", "rsp", "rax"],
    "instructions_with_registers": [
      {
        "regs_read": ["rbp", "rsp"],
        "regs_written": ["rsp"]
      },
      {
        "regs_read": ["rsp"],
        "regs_written": ["rbp"]
      },
      {
        "regs_read": ["rcx"],
        "regs_written": ["rax"]
      },
      {
        "regs_read": ["rax", "rdx"],
        "regs_written": ["rax"]
      },
      {
        "regs_read": ["rsp"],
        "regs_written": ["rbp", "rsp"]
      },
      {
        "regs_read": ["rax", "rsp"],
        "regs_written": ["rsp"]
      }
    ]
    ...
  }
}
```

**Explanation:**

1.  **Global `regs_read`**: `["rbp", "rsp", "rcx", "rdx"]` - These are all the unique registers read anywhere in the function. `rbp` and `rsp` are used for stack frame management. `rcx` and `rdx` are the input arguments.
2.  **Global `regs_written`**: `["rbp", "rsp", "rax"]` - These are all the unique registers modified. `rbp` and `rsp` are modified during stack frame setup/teardown. `rax` holds the result.
3.  **`instructions_with_registers`**:
    - `push rbp`: Reads `rbp`, Writes `rsp` (stack pointer decremented).
    - `mov rbp, rsp`: Reads `rsp`, Writes `rbp` (base pointer set to current stack top).
    - `mov rax, rcx`: Reads `rcx`, Writes `rax` (first argument moved to result register).
    - `add rax, rdx`: Reads `rax` and `rdx`, Writes `rax` (adds second argument to result).
    - `pop rbp`: Reads `rbp` (from stack, implicitly using `rsp`), Writes `rsp` (stack pointer incremented).
    - `ret`: Typically doesn't directly read/write general-purpose registers listed here (though it implicitly uses `rsp` to get the return address and `rip` to set the next instruction).


Example 2: Analyzing an Apple Silicon Security Function

Consider a hypothetical function on macOS that configures memory permissions.

```
_configure_secure_memory:
   stp    x29, x30, [sp, #-16]!
   mov    x29, sp
   mrs    x0, s3_6_c15_c1_0  // Read SPRR_CONFIG_EL1
   orr    x0, x0, #1         // Set the SPRR_CONFIG_EN bit
   msr    s3_6_c15_c1_0, x0  // Write back to enable SPRR
   ldp    x29, x30, [sp], #16
   ret
```

Corresponding `disassembled_functions` attribute:

```json
{
  "0x1000abcde::_configure_secure_memory": {
    "name": "_configure_secure_memory",
    "address": "0x1000abcde",
    "assembly": "stp x29, x30, [sp, #-16]!\nmov x29, sp\nmrs x0, s3_6_c15_c1_0\norr x0, x0, #1\nmsr s3_6_c15_c1_0, x0\nldp x29, x30, [sp], #16\nret",
    "proprietary_instructions": [],
    "sreg_interactions": [
      "SPRR_CONTROL"
    ],
    "regs_read": ["x29", "x30", "sp", "x0"],
    "regs_written": ["x29", "x30", "sp", "x0"],
    "instructions_with_registers": [
      // ...
      {
        "regs_read": [],
        "regs_written": ["x0"]
      },
      // ...
    ]
    ...
  }
}
```

**Explanation:**

1. sreg_interactions: The analysis detects that the code reads (mrs) and writes (msr) to the s3_6_c15_c1_0 system register. It looks this up in its internal map and correctly identifies it as a control register for the SPRR hardware feature, adding "SPRR_CONTROL" to the list.
2. Analyst Conclusion: An analyst can immediately conclude that this function is not a typical application function but is instead part of a low-level system component responsible for configuring hardware memory security. This allows them to prioritize it for further investigation.

------

## Function Boundary Detection

The disassembler determines the end of a function using a "linear sweep" heuristic. Disassembly begins at the function's entry point and stops when it encounters a terminating instruction (like ret or an unconditional jmp) or when it reaches the address of the next known function in the same section.

### Implications:

- For most compiler-generated functions, this approach is highly accurate.
- In functions with multiple ret paths (e.g., an early error-checking exit), the disassembly may be truncated at the first ret it finds.
- This method may not correctly handle hand-crafted assembly with unusual control flow, such as functions that fall through into one another without an explicit jmp or ret.
