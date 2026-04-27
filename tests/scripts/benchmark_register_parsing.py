#!/usr/bin/env python3
"""Microbenchmark for disassembler register parsing hot paths."""

from __future__ import annotations

import argparse
import statistics
import time
from types import SimpleNamespace

from blint.lib.binary import parse
from blint.lib.disassembler import _analyze_instructions, _extract_register_usage

CORPUS = [
    ("mov rax, rbx", "x86_64"),
    ("add rax, rcx", "x86_64"),
    ("lea r8, [rbx + r9 * 2 + 10]", "x86_64"),
    ("call 0x123456", "x86_64"),
    ("call rcx", "x86_64"),
    ("jmp qword ptr [rip + 0x10]", "x86_64"),
    ("MOV %RAX, %RBX", "x86_64"),
    ("ldr x0, [x1, #0x20]", "aarch64"),
    ("stp x29, x30, [sp, #-16]!", "aarch64"),
    ("orr x1, xzr, x2", "aarch64"),
    ("blr x12", "aarch64"),
    ("addiu $sp, $sp, -32", "mipsel"),
    ("sw $ra, 28($sp)", "mipsel"),
    ("lw $gp, 24($sp)", "mipsel"),
    ("move $t9, $ra", "mipsel"),
    ("addu $v0, $t0, $t1", "mipsel"),
]


def _timeit(func, repeat: int) -> list[float]:
    samples = []
    for _ in range(repeat):
        start = time.perf_counter()
        func()
        samples.append(time.perf_counter() - start)
    return samples


def _summarize(label: str, samples: list[float]) -> None:
    print(
        f"{label}: min={min(samples):.6f}s avg={statistics.mean(samples):.6f}s "
        f"median={statistics.median(samples):.6f}s max={max(samples):.6f}s"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repeat", type=int, default=5)
    parser.add_argument("--batch-multiplier", type=int, default=4000)
    parser.add_argument("--binary", default="")
    args = parser.parse_args()

    corpus = CORPUS * args.batch_multiplier

    def run_extract_usage() -> None:
        for asm, arch in corpus:
            _extract_register_usage(asm, None, arch)

    x86_corpus = [asm for asm, arch in corpus if arch == "x86_64"]
    mock_instrs = []
    addr = 0x1000
    for asm in x86_corpus[:12000]:
        mock_instrs.append(
            SimpleNamespace(assembly=asm, address=addr, bytes=b"\x90\x90\x90\x90")
        )
        addr += 4
    instr_addrs = [instr.address for instr in mock_instrs]

    def run_analyze() -> None:
        _analyze_instructions(mock_instrs, 0x1000, addr + 4, instr_addrs, {}, "x86_64")

    _summarize("extract_register_usage", _timeit(run_extract_usage, args.repeat))
    _summarize("analyze_instructions", _timeit(run_analyze, args.repeat))

    if args.binary:
        parse_samples = _timeit(
            lambda: parse(args.binary, disassemble=True), args.repeat
        )
        _summarize("parse_disassemble", parse_samples)


if __name__ == "__main__":
    main()
