"""Section entropy, packing signals, and section anomalies.

Every peer tool computes these; blint historically computed none of them. A
packed implant ships with an executable section full of high-entropy data, a
tiny import table, and an entrypoint pointing at a decryption stub — and
blint would report the section names and nothing more.

The analysis is section-by-section Shannon entropy plus a handful of cheap
structural checks whose evidence is unambiguous:

- writable+executable sections (classic self-modifying code habitat)
- known packer section-name signatures (UPX, Themida, VMProtect, ASPack...)
- an entrypoint outside the main executable section (a stub in its own
  section is how packers hand control to the unpacked payload)
- virtual vs raw size mismatches and file overlays (appended data)
- executable sections carrying no symbols at all

``packed_likelihood`` summarizes the evidence as ``high``/``medium``/``low``.
It is a likelihood, not a verdict: high-entropy resources legitimately ship
inside many binaries, so the per-signal evidence is reported alongside and
rules can weigh it.
"""

import contextlib
import math

import lief

# Sections are entropy-sampled above this size: entropy over the first
# ENTROPY_SAMPLE_BYTES is representative for packed-data detection and keeps
# the /usr/bin-scale scans fast. The sample is always the section head, so
# results are deterministic.
ENTROPY_SAMPLE_BYTES = 8 * 1024 * 1024

# Shannon entropy of 8-bit bytes ranges to 8.0; packed payloads cluster above
# ~7.2 while ordinary compiled code sits between 5 and 6.5.
HIGH_ENTROPY_THRESHOLD = 7.2
ELEVATED_ENTROPY_THRESHOLD = 6.8

# Section names that identify well-known packers. Compact and exact: every
# entry here has a specific tool behind it, per the indicators discipline.
PACKER_SECTION_SIGNATURES = {
    "upx0": "UPX",
    "upx1": "UPX",
    "upx2": "UPX",
    "upx!": "UPX",
    ".upx": "UPX",
    "aspack": "ASPack",
    "adata": "ASPack",
    ".aspack": "ASPack",
    "themida": "Themida",
    ".themida": "Themida",
    "vmp0": "VMProtect",
    "vmp1": "VMProtect",
    ".vmp0": "VMProtect",
    ".vmp1": "VMProtect",
    "mpress1": "MPRESS",
    "mpress2": "MPRESS",
    ".nsp0": "NsPack",
    ".nsp1": "NsPack",
    "nsp1": "NsPack",
    "petite": "Petite",
    ".petite": "Petite",
    ".y0da": "Y0da",
    ".enigma1": "Enigma",
    ".enigma2": "Enigma",
    ".rlpack": "RLPack",
    ".packed": "generic packed",
}

# Executable-section flags per format, kept as plain booleans by the adapters.
PE_MEM_EXECUTE = 0x20000000
PE_MEM_WRITE = 0x80000000
ELF_SHF_WRITE = 0x1
ELF_SHF_EXECINSTR = 0x4


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte over the given data."""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    entropy = 0.0
    for count in counts:
        if not count:
            continue
        probability = count / total
        entropy -= probability * math.log2(probability)
    return entropy


def _entropy_sample(data: bytes) -> bytes:
    if len(data) <= ENTROPY_SAMPLE_BYTES:
        return data
    return data[:ENTROPY_SAMPLE_BYTES]


def collect_sections(parsed_obj) -> list[dict]:
    """Collect format-agnostic section facts for the analyses below.

    Each entry carries name, virtual address/size, raw size, executable and
    writable flags and the section's raw bytes when cheaply available.
    """
    sections: list[dict] = []
    try:
        if isinstance(parsed_obj, lief.ELF.Binary):
            for section in parsed_obj.sections:
                flags = int(getattr(section, "flags", 0) or 0)
                size = int(section.size or 0)
                if size <= 0 or size > (1 << 32):
                    continue
                sections.append(
                    {
                        "name": section.name,
                        "virtual_address": int(section.virtual_address or 0),
                        "virtual_size": size,
                        "raw_size": size,
                        "file_offset": int(getattr(section, "offset", 0) or 0),
                        "executable": bool(flags & ELF_SHF_EXECINSTR),
                        "writable": bool(flags & ELF_SHF_WRITE),
                        "bytes": bytes(section.content) if section.content else b"",
                    }
                )
        elif isinstance(parsed_obj, lief.PE.Binary):
            imagebase = int(parsed_obj.optional_header.imagebase or 0)
            for section in parsed_obj.sections:
                virtual_size = int(getattr(section, "virtual_size", 0) or 0)
                raw_size = int(getattr(section, "size", 0) or 0)
                if max(virtual_size, raw_size) <= 0:
                    continue
                characteristics = int(getattr(section, "characteristics", 0) or 0)
                sections.append(
                    {
                        "name": section.name,
                        "virtual_address": imagebase + int(section.virtual_address or 0),
                        "virtual_size": virtual_size or raw_size,
                        "raw_size": raw_size,
                        "file_offset": int(getattr(section, "offset", 0) or 0),
                        "executable": bool(characteristics & PE_MEM_EXECUTE),
                        "writable": bool(characteristics & PE_MEM_WRITE),
                        "bytes": bytes(section.content) if section.content else b"",
                    }
                )
        elif isinstance(parsed_obj, lief.MachO.Binary):
            for segment in parsed_obj.segments:
                for section in segment.sections:
                    size = int(section.size or 0)
                    if size <= 0 or size > (1 << 32):
                        continue
                    # Mach-O has no per-section W/X flags; the segment's
                    # protection applies to everything inside it.
                    init_prot = int(getattr(segment, "init_protection", 0) or 0)
                    sections.append(
                        {
                            "name": section.name,
                            "virtual_address": int(section.virtual_address or 0),
                            "virtual_size": size,
                            "raw_size": int(getattr(section, "file_size", size) or size),
                            "file_offset": int(getattr(section, "offset", 0) or 0),
                            "executable": bool(init_prot & 0x4),  # VM_PROT X bit
                            "writable": bool(init_prot & 0x2),  # VM_PROT_WRITE bit
                            "bytes": bytes(section.content) if section.content else b"",
                        }
                    )
    except (AttributeError, TypeError, ValueError):
        return sections
    return sections


def analyze_section_entropy(sections: list[dict]) -> list[dict]:
    """Compute per-section entropy entries for the metadata block."""
    entries = []
    for section in sections:
        data = section.get("bytes") or b""
        if not data:
            continue
        entropy = shannon_entropy(_entropy_sample(data))
        entries.append(
            {
                "name": section["name"],
                "size": section["virtual_size"],
                "entropy": round(entropy, 4),
                "executable": section["executable"],
                "writable": section["writable"],
                "sampled": len(data) > ENTROPY_SAMPLE_BYTES,
            }
        )
    entries.sort(key=lambda item: (-item["entropy"], item["name"]))
    return entries


def analyze_packing(
    sections: list[dict],
    entrypoint: int | None,
    import_count: int | None,
    file_size: int | None = None,
    is_macho: bool = False,
) -> dict:
    """Derive packing likelihood and section anomalies from section facts.

    Every parameter is plain data so callers (and tests) can exercise the
    heuristics without constructing a parsed binary.
    """
    findings: list[str] = []
    packers = set()
    writable_executable = []
    exec_sections = [s for s in sections if s["executable"]]
    max_exec_entropy = 0.0
    exec_entropy_by_name: dict[str, float] = {}
    for section in sections:
        data = section.get("bytes") or b""
        name = (section["name"] or "").lower()
        if name in PACKER_SECTION_SIGNATURES:
            packers.add(PACKER_SECTION_SIGNATURES[name])
            findings.append(f"packer_section:{section['name']}")
        if not data:
            continue
        entropy = shannon_entropy(_entropy_sample(data))
        if section["executable"]:
            max_exec_entropy = max(max_exec_entropy, entropy)
            exec_entropy_by_name[section["name"]] = round(entropy, 4)
        if section["executable"] and section["writable"]:
            writable_executable.append(section["name"])

    for name in writable_executable:
        findings.append(f"writable_executable_section:{name}")
    if exec_sections and import_count is not None and exec_sections[0]:
        if max_exec_entropy >= HIGH_ENTROPY_THRESHOLD and import_count < 20:
            findings.append("high_entropy_exec_with_few_imports")
        elif max_exec_entropy >= ELEVATED_ENTROPY_THRESHOLD and import_count < 10:
            findings.append("elevated_entropy_exec_with_minimal_imports")

    # Entrypoint outside every executable section is how a stub section hands
    # off to unpacked code. Only meaningful when an entrypoint is known and
    # executable sections exist to compare against.
    if entrypoint is not None and exec_sections:
        inside = any(
            s["virtual_address"] <= entrypoint < s["virtual_address"] + s["virtual_size"]
            for s in exec_sections
        )
        if not inside:
            findings.append("entrypoint_outside_executable_sections")

    # Raw-vs-virtual size mismatch on executable sections: virtual memory
    # that has no file backing is where unpacked code gets written.
    for section in exec_sections:
        if section["raw_size"] and section["virtual_size"] > section["raw_size"] * 4:
            findings.append(f"virtual_size_mismatch:{section['name']}")

    overlay_size = 0
    if file_size is not None and sections and not is_macho:
        # Overlay: bytes past the end of the last section's raw file content.
        # Sections without a file offset (bss-like) contribute nothing. Mach-O
        # is excluded: its file tail is the code-signature SuperBlob, which is
        # legitimate on every signed binary and would fire the finding on all
        # of them.
        ends = [
            s["file_offset"] + s["raw_size"]
            for s in sections
            if s.get("file_offset") and s.get("raw_size")
        ]
        end_of_sections = max(ends) if ends else 0
        if file_size > end_of_sections > 0:
            overlay_size = file_size - end_of_sections
            if overlay_size > 0x1000:
                findings.append("file_overlay")

    if packers:
        likelihood = "high"
    elif "high_entropy_exec_with_few_imports" in findings or (
        writable_executable and max_exec_entropy >= HIGH_ENTROPY_THRESHOLD
    ):
        likelihood = "high"
    elif findings:
        likelihood = "medium"
    else:
        likelihood = "low"

    return {
        "packed_likelihood": likelihood,
        "packers": sorted(packers),
        "writable_executable_sections": sorted(writable_executable),
        "executable_section_entropy": dict(sorted(exec_entropy_by_name.items())),
        "max_executable_section_entropy": round(max_exec_entropy, 4),
        "overlay_size": overlay_size,
        "findings": sorted(findings),
    }


def analyze_binary_entropy(parsed_obj, file_size: int | None = None) -> dict:
    """LIEF adapter: run entropy + packing analysis on a parsed binary."""
    sections = collect_sections(parsed_obj)
    entropy_entries = analyze_section_entropy(sections)
    entrypoint = None
    import_count = None
    with contextlib.suppress(AttributeError, TypeError, ValueError):
        entrypoint = int(parsed_obj.entrypoint) if parsed_obj.entrypoint else None
    with contextlib.suppress(AttributeError, TypeError, ValueError):
        import_count = len(list(parsed_obj.imported_functions))
    packing = analyze_packing(
        sections, entrypoint, import_count, file_size, is_macho=isinstance(parsed_obj, lief.MachO.Binary)
    )
    return {
        "sections": entropy_entries,
        "packing": packing,
    }
