# -*- coding: utf-8 -*-
"""
Canonical naming for Rust function identifiers.

Source analysis tools and binary disassemblers describe the same function with
slightly different spellings. A source callgraph might name a method
``wasmparser::validator::operators::OperatorValidatorTemp<R>::label_types``
while the binary reports the monomorphized, trait-qualified form
``<wasmparser::...::OperatorValidatorTemp<R> as ...>::label_types`` together
with a compiler hash suffix.

To compare the two graphs, both sides are reduced to a *canonical name*: a
stable, generic-free, hash-free path of the form ``crate::module::Type::method``.
Canonicalization is deliberately lossy. Generic arguments, lifetimes, reference
and mutability markers, and compiler-generated disambiguation hashes are all
removed so that every monomorphized instance of a generic function collapses
onto the single source definition it was generated from.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional

try:  # pragma: no cover - exercised indirectly; import guarded for safety
    import multi_demangle
except ImportError:  # pragma: no cover - multi_demangle is a hard dependency
    multi_demangle = None


# Trailing Rust symbol-hash suffix, e.g. ``::h41b828a7ca01b8c4``.
_HASH_SUFFIX = re.compile(r"::h[0-9a-f]{8,}\b")
# Trailing LLVM thunk suffix, e.g. ``.llvm.12153207245666130899``.
_LLVM_SUFFIX = re.compile(r"\.llvm\.\d+$")
# Compiler-generated closure markers in either source or binary spelling.
_CLOSURE_MARKER = re.compile(r"\{\{closure\}\}|(?:^|::)closure(?:_\d+)*\b")
# Lifetimes such as ``'a`` and the anonymous lifetime ``'_``.
_LIFETIME = re.compile(r"'[a-z_][a-z0-9_]*")
# Collapsed runs of path separators.
_MULTI_SEP = re.compile(r":{3,}")

# C runtime / linker glue that has no Rust source counterpart. These are kept as
# their own canonical names but tagged so that callers can exclude them from
# source matching when desired.
_CRT_GLUE = frozenset(
    {
        "_start",
        "_init",
        "_fini",
        "deregister_tm_clones",
        "register_tm_clones",
        "__do_global_dtors_aux",
        "frame_dummy",
        "__libc_csu_init",
        "__libc_csu_fini",
        "_dl_relocate_static_pie",
        "__rust_alloc",
        "__rust_dealloc",
        "__rust_realloc",
        "__rust_alloc_zeroed",
    }
)


class NameKind(str, Enum):
    """A best-effort classification of a canonical name.

    The kind is a hint used to weight matches and to keep compiler-generated
    artefacts (closures, drop glue, runtime stubs) from being matched against
    ordinary source functions by name alone.
    """

    FUNCTION = "function"
    METHOD = "method"
    CLOSURE = "closure"
    GLUE = "glue"
    INTRINSIC = "intrinsic"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class CanonicalName:
    """The canonical form of a function identifier.

    Attributes:
        value: The canonical ``crate::module::Type::method`` path with all
            generics, lifetimes, and hash suffixes removed. Empty when the input
            could not be reduced to a meaningful identifier.
        kind: A :class:`NameKind` hint describing the symbol category.
        raw: The original (pre-canonicalization) name, preserved for reporting.
        is_generic: ``True`` when the original name carried generic arguments,
            which is a strong signal that a single source definition may map to
            several monomorphized binary functions.
    """

    value: str
    kind: NameKind
    raw: str
    is_generic: bool

    def __bool__(self) -> bool:
        return bool(self.value)


def _looks_mangled(symbol: str) -> bool:
    """Return ``True`` when ``symbol`` appears to be a raw mangled name."""
    return symbol.startswith(("_ZN", "_RN", "_R", "__Z", "?")) or "$LT$" in symbol


def demangle(symbol: str) -> str:
    """Best-effort demangle of a raw, mangled symbol name.

    Rust ``v0`` and ``legacy`` symbols as well as Itanium/MSVC C++ symbols are
    demangled via :mod:`multi_demangle`. Inputs that are already demangled, or
    that cannot be demangled, are returned unchanged so the function is safe to
    apply uniformly to a symbol table of mixed provenance.

    Args:
        symbol: A possibly-mangled symbol name.

    Returns:
        The demangled name, or ``symbol`` unchanged on any failure.
    """
    if not symbol or multi_demangle is None or not _looks_mangled(symbol):
        return symbol
    try:
        demangled = multi_demangle.demangle_symbol(symbol)
    except Exception:  # pragma: no cover - defensive; demangler must not raise
        return symbol
    return demangled or symbol


def _strip_generics(name: str) -> str:
    """Remove balanced ``<...>`` generic argument groups from ``name``."""
    out: list[str] = []
    depth = 0
    for ch in name:
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth = max(0, depth - 1)
        elif depth == 0:
            out.append(ch)
    return "".join(out)


def _split_balanced_angle(name: str) -> Optional[tuple[str, str]]:
    """Split a leading balanced ``<...>`` group from the remainder.

    Returns a ``(inner, rest)`` tuple when ``name`` begins with ``<`` and the
    group closes, otherwise ``None``. ``inner`` excludes the outer brackets and
    ``rest`` is whatever follows the closing ``>`` (typically ``::method``).
    """
    if not name.startswith("<"):
        return None
    depth = 0
    for idx, ch in enumerate(name):
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth -= 1
            if depth == 0:
                return name[1:idx], name[idx + 1 :]
    return None


def _reduce_qualified_self(name: str) -> str:
    """Reduce trait/impl qualified prefixes to the implementing type.

    ``<Type as Trait>::method`` becomes ``Type::method`` and
    ``<impl Trait for Type>::method`` (or ``<impl Type>::method``) becomes
    ``Type::method``. The implementing type is what a source callgraph records,
    so collapsing the trait qualifier aligns the two naming schemes.
    """
    split = _split_balanced_angle(name)
    if split is None:
        return name
    inner, rest = split

    # ``impl`` blocks: ``impl Trait for Type`` -> ``Type``; ``impl Type`` -> ``Type``.
    if inner.startswith("impl "):
        body = inner[len("impl ") :]
        for_idx = _find_top_level(body, " for ")
        inner = body[for_idx + len(" for ") :] if for_idx != -1 else body
    else:
        # ``Type as Trait`` -> ``Type``.
        as_idx = _find_top_level(inner, " as ")
        if as_idx != -1:
            inner = inner[:as_idx]

    return _reduce_qualified_self(inner.strip()) + rest


def _find_top_level(name: str, needle: str) -> int:
    """Find ``needle`` in ``name`` outside any ``<...>`` group, else ``-1``."""
    depth = 0
    nlen = len(needle)
    for idx in range(len(name) - nlen + 1):
        ch = name[idx]
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth = max(0, depth - 1)
        elif depth == 0 and name[idx : idx + nlen] == needle:
            return idx
    return -1


def _classify(canonical: str, raw: str) -> NameKind:
    """Classify a canonical name into a :class:`NameKind` hint."""
    if _CLOSURE_MARKER.search(raw) or _CLOSURE_MARKER.search(canonical):
        return NameKind.CLOSURE
    if "drop_in_place" in canonical:
        return NameKind.GLUE
    leaf = canonical.rsplit("::", 1)[-1]
    if not canonical:
        return NameKind.UNKNOWN
    if leaf in _CRT_GLUE or canonical in _CRT_GLUE:
        return NameKind.GLUE
    if leaf.startswith("__") or "::" not in canonical and canonical.startswith("_"):
        return NameKind.INTRINSIC
    # A CamelCase penultimate segment indicates a method on a type.
    segments = canonical.split("::")
    if len(segments) >= 2:
        owner = segments[-2]
        if owner[:1].isupper():
            return NameKind.METHOD
    return NameKind.FUNCTION


def canonicalize(name: str, *, demangle_first: bool = False) -> CanonicalName:
    """Reduce a function identifier to its :class:`CanonicalName`.

    Args:
        name: A demangled Rust path, a raw mangled symbol (set
            ``demangle_first`` or rely on auto-detection), or a plain symbol.
        demangle_first: Force a demangle pass before canonicalization. When
            ``False`` the input is demangled only if it looks mangled.

    Returns:
        A :class:`CanonicalName`. ``value`` is empty for inputs that do not
        reduce to a usable identifier (for example an empty or whitespace name).
    """
    raw = name or ""
    work = raw.strip()
    if not work:
        return CanonicalName("", NameKind.UNKNOWN, raw, False)

    if demangle_first or _looks_mangled(work):
        work = demangle(work).strip()

    is_generic = "<" in work

    # Order matters: strip trailing hashes first so they cannot interfere with
    # the trait/impl reduction, then resolve qualified-self prefixes before the
    # remaining generic groups are discarded.
    work = _HASH_SUFFIX.sub("", work)
    work = _LLVM_SUFFIX.sub("", work)
    work = _reduce_qualified_self(work)
    work = _strip_generics(work)
    work = _LIFETIME.sub("", work)
    work = work.replace("&mut ", "").replace("&", "").replace("(", "").replace(")", "")
    work = work.replace(" ", "")
    work = _MULTI_SEP.sub("::", work).strip(":")

    kind = _classify(work, raw)
    return CanonicalName(work, kind, raw, is_generic)
