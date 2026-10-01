"""Tests for the SUSPICIOUS_MEMORY_ALLOC function review.

The rule describes a loader: memory that can be made executable is obtained and
control then passes into it. The fixtures are real NDK builds of
``tests/scripts/android/memalloc_sources/memalloc.c`` (rebuild with
``tests/scripts/android/build_memalloc_fixtures.sh``), one function per shape,
on three ABIs. The no-fire shapes are the ordinary code the rule used to flag:
a heap allocation next to a callback, a read-only file mapping, and a mapping
next to a switch's jump table.
"""

from pathlib import Path

import pytest

from blint.lib.function_reviews import _evaluate_function_analysis

FIXTURES = Path(__file__).parent / "data" / "android"

FIRES = {"run_from_exec_mapping", "flip_page_and_call"}
SILENT = {"heap_callback", "map_file_readonly", "map_and_dispatch"}
# A read-write mapping next to a callback: the protection argument clears it
# where the call-site layer models the ABI; armeabi-v7a has no model, so the
# protection is unknown and the call counts as executable.
READ_WRITE = "map_rw_then_callback"
PROTECTION_UNREAD = {"armeabi-v7a"}


def _nyxstone_available() -> bool:
    try:
        from blint.lib.disassembler import NYXSTONE_AVAILABLE

        return NYXSTONE_AVAILABLE
    except ImportError:
        return False


@pytest.mark.skipif(not _nyxstone_available(), reason="the review reads nyxstone disassembly")
@pytest.mark.parametrize("abi", ["arm64-v8a", "armeabi-v7a", "x86_64"])
def test_fires_only_on_the_loader_shapes(abi: str) -> None:
    """Platform-independent: reads a committed ELF fixture by path."""
    from blint.lib.binary import parse

    metadata = parse(str(FIXTURES / f"libmemalloc_{abi}.so"), disassemble=True)
    context = (metadata.get("llvm_target_tuple") or "", metadata.get("binary_type") or "")
    shapes = FIRES | SILENT | {READ_WRITE}
    verdicts = {}
    for func_data in (metadata.get("disassembled_functions") or {}).values():
        name = func_data.get("name", "")
        if name in shapes:
            fired, _ = _evaluate_function_analysis(
                "SUSPICIOUS_MEMORY_ALLOC", func_data, {}, *context
            )
            verdicts[name] = fired
    assert set(verdicts) == shapes, abi
    expected = FIRES | ({READ_WRITE} if abi in PROTECTION_UNREAD else set())
    assert {name for name, fired in verdicts.items() if fired} == expected, abi


def test_remote_injection_triad_fires_without_a_local_indirect_call() -> None:
    func_data = {
        "name": "inject",
        "assembly": "",
        "direct_calls": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
    }
    assert _evaluate_function_analysis("SUSPICIOUS_MEMORY_ALLOC", func_data, {})[0]


def test_remote_allocation_alone_does_not_fire() -> None:
    func_data = {
        "name": "reserve",
        "assembly": "",
        "direct_calls": ["VirtualAllocEx", "CloseHandle"],
    }
    assert not _evaluate_function_analysis("SUSPICIOUS_MEMORY_ALLOC", func_data, {})[0]


def test_allocator_names_are_matched_exactly() -> None:
    """A name that merely contains an API (folly's usingJEMalloc) is not that API."""
    func_data = {
        "name": "probe",
        "assembly": "",
        "direct_calls": ["folly::usingJEMalloc", "mallocx", "mmap_helper"],
    }
    assert not _evaluate_function_analysis("SUSPICIOUS_MEMORY_ALLOC", func_data, {})[0]
