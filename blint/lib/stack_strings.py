"""Recovery of string literals a binary builds at runtime instead of storing.

An implant that never stores its device paths, registry keys or module names as
literals defeats every string-based review, because there is nothing in
``.rdata`` to match. The strings still exist - they are just assembled into a
stack buffer one word at a time, from immediates the compiler folded into
arithmetic. SLEEPWALKER builds ``\\\\.\\VMCI`` this way:

    mov  ecx, 92                    ; '\\'
    mov  dword ptr [rbp - 28], 6029358
    lea  eax, [rcx - 15]            ; 'M'
    mov  word ptr [rbp - 32], cx
    mov  word ptr [rbp - 22], ax
    ...

Recovering it needs no emulation of the whole function, only value tracking
over integer registers and the frame stores they feed. That interpreter lives
in ``blint.lib.absint`` as one architecture-parameterized model shared by
x86-64 and ARM64: functions whose metadata carries a CFG are analyzed as a
fixed-point dataflow over its blocks (a value assembled on a not-taken branch
path cannot leak into the result), and the rest by a straight-line pass.

The limits follow from the deliberately small model. A string assembled
through memory this pass cannot locate or across a call is not recovered,
and a frame slot overwritten later yields whatever the last store put
there. Recovered strings are therefore evidence to confirm, not ground
truth - but a false positive is expensive here, so the decoder only accepts
runs that actually look like text.
"""

from blint.lib.absint import (
    MAX_RUNS_PER_FUNCTION,
    MIN_RECOVERED_LEN,
    recover_function_stack_strings,
    recover_function_stack_strings_with_method,
)

__all__ = [
    "MAX_RUNS_PER_FUNCTION",
    "MIN_RECOVERED_LEN",
    "analyze_stack_strings",
    "recover_function_stack_strings",
    "recover_stack_strings",
]


def analyze_stack_strings(
    disassembled_functions: dict | None, arch_target: str = ""
) -> tuple[list[dict], dict]:
    """Recover stack-built literals across every function, with coverage counters.

    Returns one entry per distinct value, naming the function it was built in
    so a reviewer can go straight to the reconstruction and confirm it, plus
    counters stating how many functions the CFG dataflow covered, how many
    fell back to the straight-line pass, and how many hit the iteration cap
    (those contribute no entries — an unconverged state is residue, not
    evidence).
    """
    counters = {
        "functions_total": 0,
        "functions_dataflow": 0,
        "functions_fallback": 0,
        "functions_iteration_cap_hit": 0,
    }
    recovered: list[dict] = []
    if not disassembled_functions:
        return recovered, counters
    seen: set[str] = set()
    for func_key, func_data in disassembled_functions.items():
        counters["functions_total"] += 1
        entries, method = recover_function_stack_strings_with_method(func_data, arch_target)
        if method == "dataflow":
            counters["functions_dataflow"] += 1
        elif method == "cap_hit":
            counters["functions_iteration_cap_hit"] += 1
            continue
        elif method == "skipped":
            continue
        else:
            counters["functions_fallback"] += 1
        for entry in entries:
            lowered = entry["value"].lower()
            if lowered in seen:
                continue
            seen.add(lowered)
            recovered.append(
                {
                    **entry,
                    "function": func_data.get("name", func_key),
                    "address": func_data.get("address"),
                }
            )
    recovered.sort(key=lambda entry: entry["value"].lower())
    return recovered, counters


def recover_stack_strings(
    disassembled_functions: dict | None, arch_target: str = ""
) -> list[dict]:
    """Recover stack-built string literals across every disassembled function."""
    return analyze_stack_strings(disassembled_functions, arch_target)[0]
