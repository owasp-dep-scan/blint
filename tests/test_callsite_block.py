"""Tests for the call-site constant-argument metadata block (P4.7).

Three layers:

- Unit tests over synthetic function metadata pin the block builder's
  aggregation contract: one entry per distinct (callee, argument, value)
  triple, unresolved callees counted but never exported, every cap named in
  the coverage counters when it trips, and a resolver seam for pointing a
  constant at the string it names.
- The driver_ioctl block path: codes read from the block match the codes the
  per-function recovery produces for the same sites, so the two sources
  cannot drift.
- The capability rule reads the block and names *what* reaches a resolved
  call: which path, which algorithm, which port.
"""

from blint.lib.absint import (
    MAX_CALLSITE_ARGUMENT_ENTRIES,
    MAX_CALLSITE_ENTRIES_PER_FUNCTION,
    analyze_call_site_arguments,
)
from blint.lib.driver_ioctl import collect_client_ioctls


def _deviceioctl_func(assembly: str, name: str = "sub_1400") -> dict:
    lines = assembly.split("\n")
    return {
        "name": name,
        "address": "0x1400",
        "assembly": assembly,
        "instruction_count": len(lines),
        "cfg": {"blocks": [{"instructions": len(lines)}], "edges": []},
        "direct_call_targets": [
            {
                "target_name": "KERNEL32.dll::DeviceIoControl",
                "raw_operand": "qword ptr [rip + 4096]",
                "kind": "indirect_hint",
            }
        ],
    }


# ---------------------------------------------------------------------------
# The block builder.
# ---------------------------------------------------------------------------


def test_block_aggregates_distinct_triples_with_citations():
    functions = {
        "0x1400::a": _deviceioctl_func(
            "mov edx, 2201297921\ncall qword ptr [rip + 4096]", name="a"  # 0x83352401
        ),
        "0x1500::b": _deviceioctl_func(
            "mov edx, 2201297921\ncall qword ptr [rip + 4096]", name="b"  # same code
        ),
        "0x1600::c": _deviceioctl_func(
            "mov edx, 2201297937\ncall qword ptr [rip + 4096]", name="c"  # 0x83352411
        ),
    }
    entries, coverage = analyze_call_site_arguments(functions, "", "PE")
    assert coverage["functions_dataflow"] == 3
    assert coverage["entries"] == len(entries) == 2
    by_value = {entry["value"]: entry for entry in entries}
    assert set(by_value) == {0x83352401, 0x83352411}
    # The repeated code cites both functions and counts both sites.
    assert by_value[0x83352401]["functions"] == ["a", "b"]
    assert by_value[0x83352401]["site_count"] == 2
    # Every entry can be checked against the disassembly it came from.
    assert by_value[0x83352401]["example"]["function"] == "a"
    assert by_value[0x83352401]["example"]["instruction"].startswith("call")
    # Win64 argument position 1 is edx.
    assert by_value[0x83352401]["argument"] == 1
    assert by_value[0x83352401]["callee"] == "KERNEL32.dll::DeviceIoControl"


def test_unresolved_callees_are_counted_never_exported():
    functions = {
        "0x1400::a": _deviceioctl_func("mov edx, 2201297921\ncall qword ptr [rip + 4096]"),
    }
    functions["0x1400::a"]["direct_call_targets"] = []
    entries, coverage = analyze_call_site_arguments(functions, "", "PE")
    assert entries == []
    # The constants existed and the recovery saw them: named, not hidden.
    assert coverage["records_unresolved_callee"] == 1


def test_degradation_methods_are_named_in_coverage():
    functions = {
        "0x1400::no_cfg": {"name": "no_cfg", "assembly": "nop"},
        "0x1500::skipped": {"name": "skipped"},
    }
    _, coverage = analyze_call_site_arguments(functions, "", "PE")
    assert coverage["functions_no_cfg"] == 1
    assert coverage["functions_skipped"] == 1
    assert coverage["functions_dataflow"] == 0


def test_per_function_cap_is_named(monkeypatch):
    monkeypatch.setattr("blint.lib.absint.MAX_CALLSITE_ENTRIES_PER_FUNCTION", 2)
    # One function carrying five distinct constants at five call sites
    # contributes only the first two, and the cap is named with it in it.
    assembly = "\n".join(
        f"mov edx, {2201297921 + index}\ncall qword ptr [rip + 4096]" for index in range(5)
    )
    one_function = {"0x1400::bloated": _deviceioctl_func(assembly, name="bloated")}
    entries, coverage = analyze_call_site_arguments(one_function, "", "PE")
    assert len(entries) == 2
    assert coverage["functions_entries_capped"] == 1
    assert coverage["functions_entries_capped_names"] == ["bloated"]

    # The same constants spread across five functions never hit the cap.
    spread = {
        f"0x{1400 + index:x}::f{index}": _deviceioctl_func(
            f"mov edx, {2201297921 + index}\ncall qword ptr [rip + 4096]",
            name=f"f{index}",
        )
        for index in range(5)
    }
    entries, coverage = analyze_call_site_arguments(spread, "", "PE")
    assert len(entries) == 5
    assert coverage["functions_entries_capped"] == 0


def test_binary_cap_trips_and_is_named(monkeypatch):
    functions = {
        f"0x{1400 + index:x}::f{index}": _deviceioctl_func(
            f"mov edx, {2201297921 + index}\ncall qword ptr [rip + 4096]",
            name=f"f{index}",
        )
        for index in range(5)
    }
    entries, coverage = analyze_call_site_arguments(functions, "", "PE", max_entries=3)
    assert len(entries) == 3
    assert coverage["entries_truncated"] is True
    assert coverage["max_entries"] == 3


def test_zero_max_entries_disables_the_block():
    functions = {"0x1400::a": _deviceioctl_func("mov edx, 2201297921\ncall qword ptr [rip + 4096]")}
    entries, coverage = analyze_call_site_arguments(functions, "", "PE", max_entries=0)
    assert entries == []
    assert coverage["max_entries"] == 0


def test_resolver_seams_strings_into_entries():
    functions = {"0x1400::a": _deviceioctl_func("mov edx, 2201297921\ncall qword ptr [rip + 4096]")}
    entries, _ = analyze_call_site_arguments(
        functions, "", "PE", resolve_string=lambda value: "0x83352401" if value == 0x83352401 else None
    )
    assert entries[0]["string"] == "0x83352401"


def test_default_entry_bound_is_exported_and_overridable(monkeypatch):
    monkeypatch.setenv("BLINT_MAX_CALLSITE_ARGUMENTS", "7")
    functions = {"0x1400::a": _deviceioctl_func("mov edx, 2201297921\ncall qword ptr [rip + 4096]")}
    _, coverage = analyze_call_site_arguments(functions, "", "PE")
    assert coverage["max_entries"] == 7
    monkeypatch.delenv("BLINT_MAX_CALLSITE_ARGUMENTS")
    _, coverage = analyze_call_site_arguments(functions, "", "PE")
    assert coverage["max_entries"] == MAX_CALLSITE_ARGUMENT_ENTRIES


# ---------------------------------------------------------------------------
# The driver_ioctl block path: one source of truth, no drift.
# ---------------------------------------------------------------------------


def test_collect_client_ioctls_reads_the_block():
    block = [
        {
            "callee": "KERNEL32.dll::DeviceIoControl",
            "argument": 1,
            "value": 0x83352401,
            "site_count": 2,
            "functions": ["IoDispatch", "second_site"],
        },
        # An entry at the wrong argument position, and one with a
        # non-ioctl-looking constant, contribute nothing.
        {
            "callee": "KERNEL32.dll::DeviceIoControl",
            "argument": 0,
            "value": 0x83352405,
            "site_count": 1,
            "functions": ["IoDispatch"],
        },
        {
            "callee": "KERNEL32.dll::DeviceIoControl",
            "argument": 1,
            "value": 4096,
            "site_count": 1,
            "functions": ["IoDispatch"],
        },
    ]
    functions = {
        "0x1400::IoDispatch": {"name": "IoDispatch", "address": "0x1400"},
        "0x1500::second_site": {"name": "second_site", "address": "0x1500"},
    }
    entries = collect_client_ioctls(functions, binary_format="PE", call_site_entries=block)
    codes = {entry["code"]: entry for entry in entries}
    assert set(codes) == {"0x83352401"}
    # Each citing function names a real site; the sorted result keeps the first.
    assert codes["0x83352401"]["function"] in {"IoDispatch", "second_site"}


def test_collect_client_ioctls_block_matches_per_function_recovery():
    """Block-driven and recovery-driven results agree for the same sites."""
    assembly = (
        "mov ecx, 409\n"
        "mov edx, 2201297921\n"  # 0x83352401
        "xor r8d, r8d\n"
        "xor r9d, r9d\n"
        "call qword ptr [rip + 4096]"
    )
    functions = {"0x1400::sub_1400": _deviceioctl_func(assembly)}
    from_block = collect_client_ioctls(
        functions,
        binary_format="PE",
        call_site_entries=analyze_call_site_arguments(functions, "", "PE")[0],
    )
    from_recovery = collect_client_ioctls(functions, binary_format="PE")
    assert [entry["code"] for entry in from_block] == [entry["code"] for entry in from_recovery]


# ---------------------------------------------------------------------------
# The capability rule.
# ---------------------------------------------------------------------------


def _rule_metadata(entries: list[dict]) -> dict:
    return {"call_site_arguments": entries}


def test_capability_rule_names_path_algorithm_and_port():
    from blint.lib.binary_reviews import _evaluate_callsite_constant_arguments

    metadata = _rule_metadata(
        [
            {
                "callee": "KERNEL32.dll::CreateFileW",
                "argument": 2,
                "value": 4198412,
                "string": "\\\\.\\PhysicalDrive0",
                "functions": ["open_device"],
            },
            {"callee": "CCCrypt", "argument": 1, "value": 4, "functions": ["crypt"], "string": None},
            {
                "callee": "bcrypt.dll::BCryptOpenAlgorithmProvider",
                "argument": 1,
                "value": 4200,
                "string": "SHA1",
                "functions": ["digest"],
            },
            {"callee": "htons", "argument": 0, "value": 8080, "functions": ["bind_port"]},
        ]
    )
    evidence = _evaluate_callsite_constant_arguments(metadata)
    kinds = {item["kind"] for item in evidence}
    assert kinds == {"path", "crypto_algorithm", "port"}
    by_kind = {item["kind"]: item for item in evidence}
    assert by_kind["path"]["path"] == "\\\\.\\PhysicalDrive0"
    assert by_kind["crypto_algorithm"]["algorithm"] in {"RC4", "SHA1"}
    assert by_kind["port"]["port"] == 8080
    # Every item cites where the constant was recovered.
    assert all(item["function"] for item in evidence)


def test_capability_rule_stays_quiet_on_uninterpretable_positions():
    from blint.lib.binary_reviews import _evaluate_callsite_constant_arguments

    metadata = _rule_metadata(
        [
            # Right callee, wrong position.
            {"callee": "CreateFileW", "argument": 0, "value": 1, "string": "x", "functions": ["f"]},
            # Path callee whose constant resolved to no string.
            {"callee": "CreateFileW", "argument": 2, "value": 42, "functions": ["f"]},
            # Crypto callee whose constant is no documented algorithm.
            {"callee": "CCCrypt", "argument": 1, "value": 12345, "functions": ["f"]},
            # No block at all.
        ][:3]
    )
    assert _evaluate_callsite_constant_arguments(metadata) == []
    assert _evaluate_callsite_constant_arguments({}) == []


def test_capability_rule_is_registered_and_loads():
    """The YAML rule loads with the built-in annotations and dispatches."""
    from blint.config import BlintOptions
    from blint.lib.analysis import initialize_rules, review_rule_sources

    initialize_rules(BlintOptions())
    sources = review_rule_sources.get("CALL_SITE_CONSTANT_ARGUMENTS")
    assert sources and any("review_callsites_generic" in str(source) for source in sources), (
        "the rule's annotation file was not loaded"
    )
