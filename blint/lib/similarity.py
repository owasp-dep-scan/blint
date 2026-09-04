"""Similarity and provenance hashing.

blintdb matches functions by exact disassembly hash, which is precise but
shatters under compiler drift: a recompile reorders blocks, swaps registers
and shifts immediates, and every hash changes. This module adds the missing
degradation path — hashes that survive drift — plus the binary-level import
hash blint only had for PE:

- **Function fuzzy hash**: the normalized mnemonic sequence (operands
  dropped), hashed. Register allocation and immediate changes vanish;
  reordering survives as long as the mnemonic run does.
- **Function CFG hash**: the block/edge *shape* of a function from the
  ``cfg`` metrics, canonicalized so block numbering does not matter.
- **Import hash**: a stable digest over the sorted, normalized import-name
  set. Normalization strips the decoration that varies between linkers and
  versions (leading underscores, PE ``__imp_`` thunks, ELF ``@@`` version
  suffixes) so the same dependency set hashes the same across formats.

These are computed from metadata only — no new dependencies, no extra
parsing — and are additive metadata keys intended to become blintdb index
columns.
"""

import hashlib
import re

_ELF_VERSION_SUFFIX = re.compile(r"@@?([A-Za-z0-9._]+)$")
_IMPORT_DECORATIONS = (
    "__imp_",
    "_imp_",
    "__hilt_",
    "real@",
)


_ORIGIN_PREFIX = re.compile(r"^[\w.\-/]+(?:\.dll|\.dylib|\.so|\.tbd|[A-Za-z]\w*\.[A-Za-z])::")


def _normalize_import_name(name: str) -> str:
    """Strip decoration that varies across toolchains for one import name."""
    name = (name or "").strip()
    if not name:
        return ""
    name = _ORIGIN_PREFIX.sub("", name)
    name = _ELF_VERSION_SUFFIX.sub("", name)
    for decoration in _IMPORT_DECORATIONS:
        if name.startswith(decoration):
            name = name[len(decoration):]
            break
    # Both PE (leading underscore for cdecl) and Mach-O (leading underscore
    # for everything) prepend underscores that ELF symbols do not carry.
    name = name.lstrip("_")
    return name.lower()


def _stable_digest(payload: str) -> str:
    """Truncated sha256 hex digest; stability across runs is the contract."""
    return hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()[:16]


def compute_import_hash(import_names: list[str] | None) -> str:
    """Hash the normalized import set; empty when a binary imports nothing."""
    normalized = sorted({_normalize_import_name(name) for name in import_names or [] if name})
    normalized = [name for name in normalized if name]
    if not normalized:
        return ""
    return _stable_digest("\n".join(normalized))


def function_fuzzy_hash(assembly: str) -> str:
    """Hash the mnemonic sequence of one disassembled function.

    Operands are dropped entirely: registers are allocation artifacts,
    immediates shift with constants, and both change under compiler versions
    that preserve behavior. The mnemonic *sequence* is what survives.
    """
    if not assembly:
        return ""
    mnemonics = []
    for line in assembly.split("\n"):
        token = line.strip().split(None, 1)
        if token and token[0]:
            mnemonics.append(token[0].lower())
    if not mnemonics:
        return ""
    return _stable_digest("\n".join(mnemonics))


def function_cfg_hash(cfg: dict | None) -> str:
    """Hash the canonical shape of one function's block graph.

    Uses the emitted ``blocks``/``edges`` listings when present. Block
    identities are canonicalized with a Weisfeiler-Lehman refinement: blocks
    start colored by instruction count, then are repeatedly re-colored by the
    multiset of their successors' colors until the partition stops changing,
    which gives the same numbering to structurally identical graphs
    regardless of where the blocks sit in memory. The hash covers the refined
    colors and the sorted edge set, so two functions match only when their
    shapes genuinely coincide — a count-only summary would match any two
    functions with the same aggregate numbers. Falls back to the aggregate
    metrics when the detailed listings are unavailable.

    Each round's signature is digested back to a fixed-width token before the
    next round consumes it. Carrying the raw nested tuples forward instead
    would grow every color by a factor of its out-degree per round, which on
    a few-hundred-block function reaches tens of kilobytes per block and
    costs more than the disassembly that produced the graph.
    """
    if not cfg:
        return ""
    blocks = cfg.get("blocks")
    edges = cfg.get("edges")
    if blocks and edges is not None:
        block_count = len(blocks)
        successors: list[list[int]] = [[] for _ in range(block_count)]
        valid_edges = [
            edge
            for edge in edges
            if isinstance(edge.get("src"), int)
            and isinstance(edge.get("dst"), int)
            and 0 <= edge["src"] < block_count
            and 0 <= edge["dst"] < block_count
        ]
        for edge in valid_edges:
            successors[edge["src"]].append(edge["dst"])
        # Weisfeiler-Lehman refinement over fixed-width colors. Refinement
        # can only ever split the partition, so once the number of distinct
        # colors stops growing the partition is stable and further rounds are
        # wasted work.
        colors = [f"n{block.get('instructions', 0)}" for block in blocks]
        distinct = len(set(colors))
        for _ in range(min(block_count, 8)):
            colors = [
                _stable_digest(
                    colors[index] + "|" + ",".join(sorted(colors[succ] for succ in successors[index]))
                )
                for index in range(block_count)
            ]
            refined = len(set(colors))
            if refined == distinct:
                break
            distinct = refined
        # Position-independent payload: the multiset of refined block colors
        # plus the edges keyed by those colors rather than by block index, so
        # the same shape at different addresses hashes identically.
        edge_pairs = sorted(
            (edge.get("kind", "jump"), colors[edge["src"]], colors[edge["dst"]])
            for edge in valid_edges
        )
        payload = "\n".join(
            [
                *(f"c={color}" for color in sorted(colors)),
                *(f"e={kind}:{src}->{dst}" for kind, src, dst in edge_pairs),
            ]
        )
        return _stable_digest(payload)
    parts = [
        f"blocks={cfg.get('block_count', 0)}",
        f"edges={cfg.get('edge_count', 0)}",
        f"cc={cfg.get('cyclomatic_complexity', 0)}",
        f"loops={cfg.get('loop_count', 0)}",
        f"unreachable={cfg.get('unreachable_block_count', 0)}",
        f"indirect={cfg.get('indirect_branch_count', 0)}",
        f"maxblock={cfg.get('max_block_instructions', 0)}",
        f"tailcalls={cfg.get('tail_call_count', 0)}",
    ]
    return _stable_digest("\n".join(parts))


def attach_function_hashes(disassembled_functions: dict | None) -> None:
    """Add fuzzy/cfg hashes to each disassembled function dict, in place."""
    if not isinstance(disassembled_functions, dict):
        return
    for func_data in disassembled_functions.values():
        if not isinstance(func_data, dict):
            continue
        if func_data.get("fuzzy_hash") or not func_data.get("assembly"):
            continue
        func_data["fuzzy_hash"] = function_fuzzy_hash(func_data["assembly"])
        if cfg := func_data.get("cfg"):
            func_data["cfg_hash"] = function_cfg_hash(cfg)
