"""Kernel hardening posture (PE lane W5.2, plan 04/B).

Three facts attach to the ``driver`` block (W5.1) and one finding family
leaves with them:

- ``hvci_compatibility``: Microsoft's documented HVCI (memory integrity)
  driver ruleset, encoded as individually evidenced conditions. A failure
  names *which* condition failed - "this driver is not compatible" says
  nothing a reviewer can act on. Measured before the rule shipped (ground
  rule 34): all 330 drivers on the VM's full System32\\drivers pass every
  condition, so a failure is a real signal, not noise.
- ``kernel_hardening``: the kernel-relevant load-configuration and
  DLL-characteristics facts (kernel CFG, retpoline, XFG, RFG,
  /INTEGRITYCHECK, enclave configuration), each with its source named -
  this block summarises, it never recomputes what ``security_properties``
  and ``load_configuration`` already state. One deliberate finding: the
  plan's "import optimization" has no GuardFlags bit of its own in the
  Windows SDK table - retpoline presence is the flag that carries it - so
  no separate key exists to invent.
- ``dangerous_imports``: the BYOVD primitive families, *scored*, not
  listed. The measurement that decided what this block may claim (rule
  34), over the 330-driver benign sub-tier: MmMapLockedPagesSpecifyCache
  is imported by 138 benign drivers (42%), MmMapIoSpace by only 3, and 72
  drivers (22%) carry two or more primitive families. No rule may fire on
  a family count alone at any severity. The block is context for a
  reviewer (and for W5.3, where exposure joins capability); the findings
  that fire on combinations with exposure already exist as review rules
  (DRIVER_INSECURE_DEVICE_OBJECT and siblings), which this block does not
  replace.

Boot-start discipline: ``/INTEGRITYCHECK`` absence is a finding only on a
boot-start driver. Boot-start-ness is determined statically exactly once -
subsystem WINDOWS_BOOT_APPLICATION, the images winload itself loads. For
every other driver the StartType lives in the registry blint cannot read,
so the fact stays ``undetermined`` and no rule fires (rule 11).
"""

from __future__ import annotations

from typing import Any

from blint.lib.function_reviews import PRIVILEGED_HW_INSTRUCTION_PATTERNS

# The HVCI conditions, in report order. Each entry: (id, statement, eval).
# The eval receives the metadata and returns (verdict, evidence) where
# verdict is True (condition holds), False (fails), or None (the source
# the condition reads was absent - undetermined, never "failed").
PAGE_SIZE = 0x1000

_MSR_INSTRUCTION_RE = PRIVILEGED_HW_INSTRUCTION_PATTERNS

# The BYOVD primitive families (plan 04/B), with the weight each family
# contributes to capability_score. Weights reflect how directly the
# primitive yields kernel read/write: physical-memory mapping and cross-
# process access are the coin of the BYOVD realm; PCI config space is
# narrower; callback registration is a monitoring surface any EDR also
# carries. The benign-population counts in the module docstring are the
# reason these are context, not findings.
DANGEROUS_FAMILIES: tuple[dict[str, Any], ...] = (
    {
        "name": "physical_memory",
        "title": "Physical memory access",
        "weight": 3,
        "imports": (
            "mmmapiospace",
            "mmmapiospaceex",
            "mmmaplockedpages",
            "mmmaplockedpagesspecifycache",
            "mmgetphysicaladdress",
            "zwmapviewofsection",
            "mmcopyvirtualmemory",
        ),
        "benign_hit_count": 162,
    },
    {
        "name": "process_tampering",
        "title": "Cross-process access",
        "weight": 3,
        "imports": (
            "kestackattachprocess",
            "pslookupprocessbyprocessid",
            "zwopenprocess",
            "ntopenprocess",
            "zwterminateprocess",
            "obopenobjectbypointer",
        ),
        "benign_hit_count": 103,
    },
    {
        "name": "pci_config",
        "title": "PCI configuration space",
        "weight": 2,
        "imports": (
            "halgetbusdatabyoffset",
            "halsetbusdatabyoffset",
            "halgetbusdata",
            "halsetbusdata",
            "halassignslotresources",
        ),
        "benign_hit_count": 5,
    },
    {
        "name": "callback_registration",
        "title": "System-wide callback registration",
        "weight": 1,
        "imports": (
            "obregistercallbacks",
            "pssetcreateprocessnotifyroutine",
            "pssetcreateprocessnotifyroutineex",
            "pssetcreatethreadnotifyroutine",
            "pssetloadimagenotifyroutine",
            "cmregistercallback",
            "cmregistercallbackex",
        ),
        "benign_hit_count": 17,
    },
)

# MSR/port instructions are the disassembly-level form of the hardware
# primitive family; they are evidence in the same block, weight 2.
MSR_FAMILY_WEIGHT = 2

# Listing bound per family: a listing bound only, no consumer reads past
# the first entries (rule 33 fixture pins the block still speaks past it).
FAMILY_EVIDENCE_LIMIT = 8


def _condition_machine_64_bit(metadata: dict[str, Any]) -> tuple[bool | None, str]:
    from blint.lib import pe_constants

    value = metadata.get("machine_type_value")
    if isinstance(value, int) and not isinstance(value, bool):
        name = pe_constants.machine_type_name(value).upper()
        if name in ("I386", "I486", "X86") or name.startswith("ARMNT"):
            return False, f"machine type {name}"
        return True, name
    rendered = str(metadata.get("machine_type") or "").upper()
    if rendered:
        if "X86" in rendered and "X64" not in rendered:
            return False, f"machine type {rendered}"
        return True, rendered
    return None, "machine type not recorded"


def _condition_no_wx_sections(metadata: dict[str, Any]) -> tuple[bool | None, str]:
    wx = metadata.get("wx_segments")
    if wx is None:
        return None, "section characteristics not recorded"
    if wx:
        names = ", ".join(
            str(entry.get("name")) for entry in wx[:5] if isinstance(entry, dict)
        )
        return False, f"writable+executable section(s): {names}"
    return True, "no section is writable and executable"


def _condition_section_alignment(metadata: dict[str, Any]) -> tuple[bool | None, str]:
    alignment = metadata.get("section_alignment")
    if alignment is None:
        return None, "section alignment not recorded"
    if alignment < PAGE_SIZE:
        return False, f"SectionAlignment {alignment:#x} < {PAGE_SIZE:#x}"
    return True, f"SectionAlignment {alignment:#x}"


def _condition_relocations_present(metadata: dict[str, Any]) -> tuple[bool | None, str]:
    directories = metadata.get("data_directories")
    if directories is None:
        return None, "data directories not recorded"
    for entry in directories:
        if (
            isinstance(entry, dict)
            and entry.get("type") == "BASE_RELOCATION_TABLE"
        ):
            size = int(entry.get("size") or 0)
            if size:
                return True, f"base relocation directory present ({size} bytes)"
            return False, "base relocation directory declared with size 0 (relocations stripped)"
    # The shape blint's own parser produces for a stripped image: parse_pe_data
    # emits only directories with a non-zero size, so the entry is absent
    # rather than present-and-empty. The size-0 branch above holds for
    # metadata from any other producer.
    return False, "no base relocation directory"


HVCI_CONDITIONS: tuple[tuple[str, str, Any], ...] = (
    (
        "machine_64_bit",
        "the image targets a 64-bit machine (x86/ARM32 kernels are never HVCI-compatible)",
        _condition_machine_64_bit,
    ),
    (
        "no_writable_executable_sections",
        "no section is both writable and executable (HVCI forbids W+X kernel pages)",
        _condition_no_wx_sections,
    ),
    (
        "section_alignment_page_sized",
        f"section alignment is at least one page ({PAGE_SIZE:#x})",
        _condition_section_alignment,
    ),
    (
        "relocations_present",
        "base relocations are present (a driver without them cannot load at randomized addresses)",
        _condition_relocations_present,
    ),
)


def evaluate_hvci_compatibility(metadata: dict[str, Any]) -> dict[str, Any]:
    """The ``hvci_compatibility`` block: per-condition evidence.

    ``compatible`` is True only when every condition holds, False when at
    least one fails with its evidence in ``failed_conditions``, and the
    conditions whose source was absent are listed in
    ``undetermined_conditions`` rather than folded into either verdict
    (rules 11/32: absence of a source is not a failed condition).
    """
    conditions: list[dict[str, Any]] = []
    failed: list[str] = []
    undetermined: list[str] = []
    for condition_id, statement, evaluate in HVCI_CONDITIONS:
        verdict, evidence = evaluate(metadata)
        entry: dict[str, Any] = {"id": condition_id, "statement": statement}
        if verdict is None:
            entry["verdict"] = "undetermined"
            entry["evidence"] = evidence
            undetermined.append(condition_id)
        elif verdict:
            entry["verdict"] = "pass"
            entry["evidence"] = evidence
        else:
            entry["verdict"] = "fail"
            entry["evidence"] = evidence
            failed.append(condition_id)
        conditions.append(entry)
    block: dict[str, Any] = {
        "conditions": conditions,
        "compatible": False if failed else None if undetermined else True,
        "failed_conditions": failed,
        "undetermined_conditions": undetermined,
    }
    if failed:
        block["failure_evidence"] = {
            entry["id"]: entry["evidence"]
            for entry in conditions
            if entry["verdict"] == "fail"
        }
    return block


# GuardFlags bits, from blint's winnt.h-derived table (pe_constants) - the
# numeric values are the contract (ground rule 28), restated here as named
# keys the kernel posture block reports.
_KERNEL_HARDENING_GUARD_BITS: tuple[tuple[str, int], ...] = (
    ("cfg_instrumented", 0x00000100),
    ("kernel_cfg", 0x00000200),  # IMAGE_GUARD_CFW_INSTRUMENTED
    ("rfg", 0x00020000),
    ("retpoline", 0x00100000),
    ("xfg", 0x00800000),
)


def evaluate_kernel_hardening(metadata: dict[str, Any]) -> dict[str, Any]:
    """The ``kernel_hardening`` block, with each fact's source named.

    Summarises ``load_configuration`` and the DLL characteristics; it does
    not recompute what ``security_properties`` states (rule 21). Keys are
    omitted when their source is absent - absence is "not determined",
    never False.
    """
    block: dict[str, Any] = {}
    load_config = metadata.get("load_configuration") or {}
    guard_flags = load_config.get("guard_flags")
    if isinstance(guard_flags, int):
        for name, bit in _KERNEL_HARDENING_GUARD_BITS:
            block[name] = bool(guard_flags & bit)
        block["source"] = "load_configuration.guard_flags"
    security = metadata.get("security_properties") or {}
    if "force_integrity" in security:
        block["force_integrity"] = security["force_integrity"] is True
        block.setdefault("source", "security_properties")
    if load_config.get("enclave_config"):
        block["enclave_config"] = True
    # Boot-start-ness is determined statically exactly once: the
    # WINDOWS_BOOT_APPLICATION subsystem is the set winload itself loads.
    # Everything else is registry state blint cannot see (module docstring).
    subsystem = str(metadata.get("subsystem") or "").upper()
    if subsystem == "WINDOWS_BOOT_APPLICATION":
        block["boot_start"] = True
        block["boot_start_basis"] = "subsystem_windows_boot_application"
    elif subsystem:
        block["boot_start"] = None
        block["boot_start_basis"] = "undetermined_registry_state_not_readable"
    return block


def evaluate_dangerous_imports(metadata: dict[str, Any]) -> dict[str, Any] | None:
    """The scored BYOVD primitive families, or None when nothing matches.

    ``capability_score`` sums the weights of the families present (an MSR
    instruction on the disassembly path adds MSR_FAMILY_WEIGHT via
    refresh_kernel_posture_after_disassembly). This block is context: the
    benign-population measurement in the module docstring is why no rule
    fires on it alone.
    """
    imports: set[str] = set()
    for entry in metadata.get("imports") or []:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or "")
        if "::" in name:
            name = name.rsplit("::", 1)[1]
        imports.add(name.strip().lower().lstrip("_"))
    if not imports:
        return None
    families: list[dict[str, Any]] = []
    score = 0
    for family in DANGEROUS_FAMILIES:
        matched = sorted(imports & set(family["imports"]))
        if not matched:
            continue
        families.append(
            {
                "name": family["name"],
                "title": family["title"],
                "weight": family["weight"],
                "imports": matched[:FAMILY_EVIDENCE_LIMIT],
                "import_count": len(matched),
            }
        )
        score += family["weight"]
    if not families:
        return None
    return {
        "families": families,
        "capability_score": score,
        "score_note": "context only - benign sub-tier prevalence makes this block "
        "informational by measurement (mmmaplockedpagesspecifycache: 138 of 330 benign drivers)",
    }


def apply_kernel_posture(block: dict[str, Any], metadata: dict[str, Any]) -> None:
    """Attach the posture facts to the W5.1 ``driver`` block, in place."""
    block["hvci_compatibility"] = evaluate_hvci_compatibility(metadata)
    kernel_hardening = evaluate_kernel_hardening(metadata)
    if kernel_hardening:
        block["kernel_hardening"] = kernel_hardening
    dangerous = evaluate_dangerous_imports(metadata)
    if dangerous:
        block["dangerous_imports"] = dangerous


def refresh_kernel_posture_after_disassembly(metadata: dict[str, Any]) -> None:
    """Add the disassembly-level MSR/port-instruction evidence.

    Called from binary.parse next to the driver-block refresh. The
    instruction patterns are the same ones the BYOVD_FUNCTION analysis
    rules use (one source for the fact, rule 21); the finding text names
    the instruction so the claim is checkable against the disassembly.
    """
    block = metadata.get("driver")
    if not isinstance(block, dict):
        return
    dangerous = block.get("dangerous_imports")
    if dangerous is None:
        dangerous = {
            "families": [],
            "capability_score": 0,
        }
        block["dangerous_imports"] = dangerous
    instructions: set[str] = set()
    disassembled = metadata.get("disassembled_functions") or {}
    for func_data in disassembled.values():
        if not isinstance(func_data, dict):
            continue
        assembly = (func_data.get("assembly") or "").lower()
        if not assembly:
            continue
        for pattern in _MSR_INSTRUCTION_RE:
            match = pattern.search(assembly)
            if match:
                instructions.add(match.group(0).split()[0].strip(","))
        if len(instructions) >= 4:
            break
    if not instructions:
        return
    named = sorted(instructions)[:FAMILY_EVIDENCE_LIMIT]
    for family in dangerous["families"]:
        if family["name"] == "msr_port_io":
            family["instructions"] = named
            return
    dangerous["families"].append(
        {
            "name": "msr_port_io",
            "title": "Privileged hardware instructions",
            "weight": MSR_FAMILY_WEIGHT,
            "instructions": named,
        }
    )
    dangerous["capability_score"] = dangerous.get("capability_score", 0) + MSR_FAMILY_WEIGHT
    # No score_note default: the block created here has no import families
    # to be prevalent, and an empty note reads as a note that says nothing.
