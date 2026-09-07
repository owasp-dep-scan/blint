# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT
"""Symbol index built from an Apple SDK's `.tbd` (TAPI) files.

On a running macOS install the system libraries a binary links against are
absent from disk (`/usr/lib` holds a handful of trampolines and broken
symlinks; `libSystem.B.dylib` itself lives only in the dyld shared cache).
The SDK ships the counterpart of every one of those libraries as a `.tbd`
text stub: a YAML document (TAPI v1-v4) listing the symbols a library
promises to export, the libraries it re-exports, and its umbrella parent.
An index over those stubs is the only static oracle for "which declared
library actually supplies this import" on macOS.

Attribution policy -- which install-name a symbol is attributed to
-----------------------------------------------------------------

A symbol is attributed to the library whose *export surface* contains it:
its own `exports`/`reexports` symbol sections, plus -- transitively -- the
exports of every library it names under `reexported-libraries` (v4) or
`re-exports` (v2/v3). The implementing sub-library is deliberately *not*
substituted for the declaring one. A Mach-O two-level bind records the
ordinal of the library in the *binary's own* load-command list; dyld then
walks that library's export trie, following re-export edges into the
implementing image, but the bind still names the declared library.
`dyld_info -imports /usr/bin/git` reports `_dispatch_once (from libSystem)`
even though the implementation lives in libdispatch.dylib, and blint's
own `libname::symbol` symtab prefixes come from the same bind evidence.
Attributing re-exported symbols to the implementing library would
contradict the binary's bind, and every declared umbrella would read as
unused again -- the exact failure this module exists to prevent. The
implementing library is genuinely unnamed in a v4 `reexports` symbol
section anyway.

Source honesty -- the SDK is not the runtime
--------------------------------------------

A `.tbd` describes what the SDK's stub promises, not what the machine
under the binary ships. Everything this module writes into metadata is
therefore marked with the `sdk_tbd` attribution source (see
``build_symbol_provider_map``), never with `load_commands`, so a consumer
can always tell a bind the binary itself made from an export the SDK
implies. Attribution produced here targets the libraries the binary
declares; it never invents dependencies on libraries the binary did not
name.

Determinism
-----------

The index is derived from the analyst's filesystem, but none of that
environment may reach metadata: no absolute SDK paths, no SDK versions,
no build timestamps. The ``sdk_tbd`` metadata block carries only counts
and capped, sorted samples of binary-relative facts. The on-disk index
artifact lives under the parse-cache directory, keyed by a fingerprint of
the SDK's `.tbd` tree (paths, sizes, mtimes), so an SDK update rebuilds
it; the artifact itself is internal and its bytes never reach output.

TAPI schema notes (verified against a real Xcode SDK, not assumed)
-----------------------------------------------------------------

- v4 files carry `install-name`, `exports` sections keyed by `targets`
  with symbol lists under `symbols`, `weak-symbols`, `objc-classes`,
  `objc-eh-types`, `thread-local-symbols`; re-exported *libraries* under
  `reexported-libraries`.
- v3-era files use `re-exports` for the library list and may carry a
  `reexports` *symbol* section parallel to `exports` (symbols offered via
  re-export whose implementing library the stub does not name).
- One file may hold several documents (a framework stub commonly carries
  its legacy sibling), so the reader consumes every document in the
  stream.
- The `!tapi-tbd` YAML tag is unknown to ``yaml.SafeLoader`` and raises;
  the loader here ignores unknown tags instead.
- v1 documents (per TAPI docs) organize symbols under `sections` with a
  `kind` field; that layout is covered by fixtures, not by the real SDK
  used for verification, which ships v4 only.
"""

import hashlib
import os
import zlib

import orjson
import yaml

from blint.lib.import_attribution import is_library_name
from blint.logger import LOG

# Metadata sample caps: counts are exact, samples are bounded so a large
# binary's metadata does not grow with its import table (metadata size is
# a budget, not a free variable).
ATTRIBUTED_SYMBOL_SAMPLE_CAP = 32
UNCONFIRMED_SYMBOL_SAMPLE_CAP = 16

# ObjC class symbols a binary binds under, versus the plain class names a
# .tbd lists under objc-classes.
_OBJC_CLASS_PREFIXES = ("_OBJC_CLASS_$", "_OBJC_METACLASS_$", "_OBJC_EHTYPE_$")

# Private metadata key carrying the *full* symbol -> install-name map from
# one parse run, so the dependency graph attributes every symbol while the
# exported `sdk_tbd` block keeps only a capped sample. Deleted by parse()
# before export/cache; never present in stored metadata.
SDK_ATTRIBUTIONS_KEY = "sdk_tbd_attributions"

# Symbol-list fields a TAPI section may carry. Entries are either plain
# symbols (export surface) or class names: objc-classes and objc-eh-types
# both list bare class names (a real SDK lists `NSException`, while the
# binary binds `_OBJC_EHTYPE_$_NSException`), so both are class lookups.
_SECTION_SYMBOL_FIELDS = {
    "symbols": "symbol",
    "weak-symbols": "symbol",
    "thread-local-symbols": "symbol",
    "objc-classes": "objc_class",
    "objc-eh-types": "objc_class",
}


class TbdSdkError(RuntimeError):
    """Raised when an SDK path cannot yield a usable .tbd index.

    Deliberately a RuntimeError, not a ValueError: parse() catches ValueError
    as part of malformed-binary tolerance, and a bad --sdk-path is a
    configuration error that must be reported, never absorbed into a
    per-binary degradation.
    """


class _TbdLoader(yaml.SafeLoader):
    """A SafeLoader that tolerates the ``!tapi-tbd`` tag and its kin."""


def _construct_unknown(loader, suffix, node):
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_mapping(node)


_TbdLoader.add_multi_constructor("!", _construct_unknown)

# The C-backed loader is an order of magnitude faster, which on thousands of
# stubs is the difference between a snappy first run and a small wait; fall
# back to the pure-Python loader where PyYAML was built without libyaml.
try:
    class _TbdCLoader(yaml.CSafeLoader):  # type: ignore[name-defined]
        """The libyaml equivalent of :class:`_TbdLoader`."""

    _TbdCLoader.add_multi_constructor("!", _construct_unknown)
    _PREFERRED_LOADER = _TbdCLoader
except AttributeError:  # pragma: no cover - depends on PyYAML build flags
    _PREFERRED_LOADER = _TbdLoader


class TbdIndex:
    """A symbol -> install-name index over one SDK's .tbd files.

    The in-memory shape is three symbol-keyed dicts mapping to library ids
    (positions in the sorted ``libraries`` list) plus the transitive
    re-export closure. Membership queries are dict lookups; the closure is
    precomputed at build time so ``provides`` never walks the graph.
    """

    def __init__(
        self,
        libraries: list[str],
        exports: dict[str, list[int]],
        reexport_symbols: dict[str, list[int]],
        objc_classes: dict[str, list[int]],
        reexports_closure: dict[int, list[int]],
        file_count: int,
        document_count: int,
    ):
        self.libraries = libraries
        self.exports = exports
        self.reexport_symbols = reexport_symbols
        self.objc_classes = objc_classes
        self.reexports_closure = reexports_closure
        # Inverse of the closure: which libraries transitively re-export a
        # given provider. Lookups then cost union-over-providers, not a walk
        # over every library in the SDK.
        self.reexport_consumers: dict[int, list[int]] = {}
        for lib_id, closure in reexports_closure.items():
            for provider_id in closure:
                self.reexport_consumers.setdefault(provider_id, []).append(lib_id)
        self.file_count = file_count
        self.document_count = document_count
        self._lib_id = {name: i for i, name in enumerate(libraries)}
        self._by_basename: dict[str, list[int]] = {}
        for i, name in enumerate(libraries):
            self._by_basename.setdefault(name.rsplit("/", 1)[-1], []).append(i)

    # -- construction ---------------------------------------------------------

    @classmethod
    def build(cls, sdk_path: str) -> "TbdIndex":
        """Walk ``sdk_path`` and index every .tbd document found.

        Raises:
            TbdSdkError: When the path is missing, unreadable, or contains
                no .tbd files at all. A user who names an SDK path gets an
                error, never a silently empty index.
        """
        if not os.path.isdir(sdk_path):
            raise TbdSdkError(f"SDK path is not a directory: {sdk_path}")
        tbd_files = _find_tbd_files(sdk_path)
        if not tbd_files:
            raise TbdSdkError(
                f"No .tbd files found under {sdk_path}; an SDK root was "
                "expected (for example the path printed by "
                "`xcrun --show-sdk-path`). Nothing was indexed."
            )
        libraries: set[str] = set()
        exports: dict[str, set[int]] = {}
        reexport_symbols: dict[str, set[int]] = {}
        objc_classes: dict[str, set[int]] = {}
        reexport_edges: dict[str, set[str]] = {}
        document_count = 0
        for file_path in tbd_files:
            for document in _iter_tbd_documents(file_path):
                install_name = (document.get("install-name") or "").strip()
                if not install_name:
                    continue
                libraries.add(install_name)
                document_count += 1
        lib_ids = {name: i for i, name in enumerate(sorted(libraries))}
        for file_path in tbd_files:
            for document in _iter_tbd_documents(file_path):
                install_name = (document.get("install-name") or "").strip()
                if not install_name:
                    continue
                lib_id = lib_ids[install_name]
                own_exports, own_reexports, own_classes = _extract_symbols(document)
                for symbol in own_exports:
                    exports.setdefault(symbol, set()).add(lib_id)
                for symbol in own_reexports:
                    reexport_symbols.setdefault(symbol, set()).add(lib_id)
                for klass in own_classes:
                    objc_classes.setdefault(klass, set()).add(lib_id)
                for target in _extract_reexported_libraries(document):
                    reexport_edges.setdefault(install_name, set()).add(target)
        sorted_libs = sorted(libraries)
        closure = _build_reexports_closure(sorted_libs, reexport_edges)
        return cls(
            libraries=sorted_libs,
            exports={k: sorted(v) for k, v in exports.items()},
            reexport_symbols={k: sorted(v) for k, v in reexport_symbols.items()},
            objc_classes={k: sorted(v) for k, v in objc_classes.items()},
            reexports_closure=closure,
            file_count=len(tbd_files),
            document_count=document_count,
        )

    # -- queries --------------------------------------------------------------

    def _resolve_library(self, install_name: str) -> list[int]:
        """Library ids a declared name may refer to, exact match first.

        Binaries declare full install-names, so exact matching is the norm;
        a basename fallback covers declarations that use a suffix. An
        ambiguous basename resolves to every candidate: for the unused-
        dependency judgment, any provider wins, which errs toward *used*
        and away from flagging a dependency unused on a naming technicality.
        """
        lib_id = self._lib_id.get(install_name)
        if lib_id is not None:
            return [lib_id]
        return self._by_basename.get(install_name.rsplit("/", 1)[-1], [])

    def _symbol_library_ids(self, symbol: str) -> tuple[set[int], set[int]]:
        """Libraries providing ``symbol``, split by direct vs re-export only.

        Direct providers list the symbol in their own exports or ObjC class
        tables. Re-export-only providers are the libraries that transitively
        re-export a provider, plus any library listing the symbol in its own
        ``reexports`` sections. That last kind matters: a stub can offer a
        symbol purely through a re-export -- ``_strcmp`` appears only in
        libsystem_c's ``reexports`` section, never in anyone's ``exports`` --
        and an umbrella above it must inherit the symbol through the
        closure, which is what makes libSystem provide ``_strcmp``.
        """
        direct: set[int] = set(self.exports.get(symbol, ()))
        if not direct and symbol.startswith(_OBJC_CLASS_PREFIXES):
            # `_OBJC_CLASS_$_NSView` binds class `NSView`, listed plain under
            # objc-classes; the eh-type spelling carries a leading underscore
            # on the class name, so both bare forms are tried, against the
            # class tables and the plain export surface both.
            tail = symbol.split("$_", 1)[-1] if "$_" in symbol else ""
            for klass in {tail, tail.lstrip("_")}:
                if not klass:
                    continue
                direct.update(self.objc_classes.get(klass, ()))
                direct.update(self.exports.get(klass, ()))
        declared = self.reexport_symbols.get(symbol)
        reexport_only: set[int] = set(declared) if declared else set()
        # The consumers map is the inverse of the *transitive* closure, so a
        # single hop reaches every umbrella above any provider.
        for provider_id in direct | reexport_only:
            reexport_only.update(self.reexport_consumers.get(provider_id, ()))
        reexport_only -= direct
        return direct, reexport_only

    def provides(self, install_name: str, symbol: str) -> tuple[bool, bool]:
        """Whether the library's export surface contains the symbol.

        Returns ``(provides, via_reexport)``. ``via_reexport`` is True when
        confirmation needed the re-export closure -- recorded so consumers
        can tell a direct export from an SDK-implied one.
        """
        candidates = self._resolve_library(install_name)
        if not candidates:
            return False, False
        direct, reexported = self._symbol_library_ids(symbol)
        candidate_set = set(candidates)
        if candidate_set & set(direct):
            return True, False
        if candidate_set & set(reexported):
            return True, True
        return False, False

    def attribute(self, symbol: str, declared_install_names: list[str]) -> str:
        """The first declared library whose surface provides the symbol.

        Declared libraries arrive in load-command order, which is also the
        order dyld searches for flat references, so first match is the
        faithful answer. Returns an empty string when nothing declared
        provides the symbol: the symbol stays unattributed rather than
        pinned to a library the binary does not name.
        """
        direct, reexported = self._symbol_library_ids(symbol)
        if not direct and not reexported:
            return ""
        providers = set(direct) | set(reexported)
        for name in declared_install_names:
            if any(lib_id in providers for lib_id in self._resolve_library(name)):
                return name
        return ""

    # -- persistence ------------------------------------------------------------

    def to_bytes(self) -> bytes:
        """zlib-compressed orjson bytes of the index for the on-disk cache.

        Sorted structures in, so the same SDK always yields the same bytes;
        nothing environment-derived (paths, timestamps) is stored beyond the
        library install-names and symbol names themselves.
        """
        payload = {
            "libraries": self.libraries,
            "exports": self.exports,
            "reexport_symbols": self.reexport_symbols,
            "objc_classes": self.objc_classes,
            "reexports_closure": {str(k): v for k, v in self.reexports_closure.items()},
            "file_count": self.file_count,
            "document_count": self.document_count,
        }
        return zlib.compress(orjson.dumps(payload, option=orjson.OPT_SORT_KEYS), 6)

    @classmethod
    def from_bytes(cls, raw: bytes) -> "TbdIndex":
        payload = orjson.loads(zlib.decompress(raw))
        return cls(
            libraries=payload["libraries"],
            exports=payload["exports"],
            reexport_symbols=payload["reexport_symbols"],
            objc_classes=payload["objc_classes"],
            reexports_closure={int(k): v for k, v in payload["reexports_closure"].items()},
            file_count=payload["file_count"],
            document_count=payload["document_count"],
        )


def _find_tbd_files(sdk_path: str) -> list[str]:
    """Every .tbd file under ``sdk_path``, in sorted (deterministic) order."""
    found: list[str] = []
    for root, dirs, files in os.walk(sdk_path):
        # Symlinked framework VersionCurrent-style aliases would double-count
        # documents; walking links tends toward the same files repeatedly, and
        # os.walk already visits the real paths.
        dirs.sort()
        for name in sorted(files):
            if name.lower().endswith(".tbd"):
                found.append(os.path.join(root, name))
    return found


def _iter_tbd_documents(file_path: str):
    """Yield every TAPI document in a .tbd file.

    A file is a YAML stream and may hold several documents (a framework's
    stub commonly carries its legacy sibling). Files that fail to parse are
    skipped with a debug log: one malformed stub must not decide whether the
    whole SDK is usable, and a partial index is still evidence -- the gap is
    visible as an unconfirmed symbol rather than as a missing index.
    """
    try:
        with open(file_path, encoding="utf-8", errors="replace") as handle:
            for document in yaml.load_all(handle, Loader=_PREFERRED_LOADER):
                if isinstance(document, dict):
                    yield document
    except (yaml.YAMLError, OSError, ValueError) as exc:
        # Debug, not warning: a real SDK ships a handful of malformed stubs,
        # and one skipped file is a gap the consumer sees as an unconfirmed
        # symbol, not an operational problem in the run.
        LOG.debug("Skipping unreadable .tbd file %s: %s", file_path, exc)


def _extract_symbols(document: dict) -> tuple[set[str], set[str], set[str]]:
    """Pull (exports, reexport-symbols, objc-classes) out of one document.

    Every section list is treated the same regardless of the target key
    naming it (`targets` on v4, `archs` on older files): what matters is
    whether it carries symbols, and the field it carried them in.
    """
    exports: set[str] = set()
    reexports: set[str] = set()
    classes: set[str] = set()
    for section_key, target in (("exports", exports), ("reexports", reexports)):
        sections = document.get(section_key)
        if not isinstance(sections, list):
            continue
        for section in sections:
            if not isinstance(section, dict):
                # v1-style plain string entries in exports lists
                if isinstance(section, str):
                    target.add(section)
                continue
            for field, kind in _SECTION_SYMBOL_FIELDS.items():
                entries = section.get(field)
                if not isinstance(entries, list):
                    continue
                sink = classes if kind == "objc_class" else target
                sink.update(entry for entry in entries if isinstance(entry, str))
    # v1 organizes the same lists under `sections` with a `kind` discriminator
    # (covered by fixture; the SDKs verified in the field ship v4).
    for section in document.get("sections") or []:
        if not isinstance(section, dict):
            continue
        kind = str(section.get("kind") or "")
        entries = section.get("symbols")
        if not isinstance(entries, list):
            continue
        strings = {entry for entry in entries if isinstance(entry, str)}
        if kind == "objc-classes":
            classes.update(strings)
        else:
            exports.update(strings)
    return exports, reexports, classes


def _extract_reexported_libraries(document: dict) -> list[str]:
    """Install-names a document re-exports, across the v2/v3 and v4 spellings.

    v4 names them under `reexported-libraries` (a list of target-grouped
    entries or plain strings); v2/v3 use `re-exports`. Entries that are not
    library-shaped (dicts without usable names, non-strings) are ignored.
    """
    names: list[str] = []
    for key in ("reexported-libraries", "re-exports"):
        entries = document.get(key)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if isinstance(entry, str):
                names.append(entry.strip())
            elif isinstance(entry, dict):
                for sub in entry.get("libraries") or []:
                    if isinstance(sub, str):
                        names.append(sub.strip())
    return [name for name in names if name]


def _build_reexports_closure(
    libraries: list[str], edges: dict[str, set[str]]
) -> dict[int, list[int]]:
    """Transitive re-export closure over library ids.

    Edges name install-names that may themselves be absent from the SDK
    (a stub can re-export a library the SDK does not stub); those edges
    contribute nothing. Cycles are tolerated by the visited set.
    """
    lib_ids = {name: i for i, name in enumerate(libraries)}
    id_edges: dict[int, list[int]] = {}
    for source, targets in edges.items():
        source_id = lib_ids.get(source)
        if source_id is None:
            continue
        resolved = sorted(
            {lib_ids[target] for target in targets if target in lib_ids}
        )
        if resolved:
            id_edges[source_id] = resolved
    closure: dict[int, list[int]] = {}
    for start in id_edges:
        visited: set[int] = set()
        stack = list(id_edges.get(start, []))
        while stack:
            current = stack.pop()
            if current in visited or current == start:
                continue
            visited.add(current)
            stack.extend(id_edges.get(current, []))
        if visited:
            closure[start] = sorted(visited)
    return closure


def index_fingerprint(sdk_path: str) -> str:
    """A stable fingerprint of the SDK's .tbd tree, for the on-disk cache key.

    Relative paths, sizes and mtimes are enough to notice an SDK swap
    (different content lands at different paths or with different sizes)
    without reading 8k files' contents on every start. Absolute paths of the
    host never enter the value: only the relative layout of the tree does.
    """
    digest = hashlib.sha256()
    for file_path in _find_tbd_files(sdk_path):
        rel = os.path.relpath(file_path, sdk_path).replace(os.sep, "/")
        try:
            stat = os.stat(file_path)
        except OSError:
            continue
        digest.update(rel.encode("utf-8", "replace"))
        digest.update(f"\0{stat.st_size}\0{stat.st_mtime_ns}\n".encode())
    return digest.hexdigest()


def _cache_dir() -> str:
    from blint.lib.cache import _user_cache_dir

    return os.environ.get("BLINT_CACHE_DIR") or _user_cache_dir()


# Per-process memo. Workers are separate processes, so each pays one index
# load per run; the on-disk artifact makes that a decompress-and-parse, not
# a re-read of thousands of YAML files.
_INDEX_MEMO: dict[str, TbdIndex] = {}


def load_or_build_index(sdk_path: str, use_disk_cache: bool = True) -> TbdIndex:
    """Return the index for ``sdk_path``, building it at most once per process.

    Raises:
        TbdSdkError: When the SDK path yields no usable .tbd files. Loud by
            design: an analyst who names a path without stubs must be told,
            not served an empty confirmation.
    """
    resolved = os.path.abspath(sdk_path)
    cached = _INDEX_MEMO.get(resolved)
    if cached is not None:
        return cached
    artifact_path = ""
    if use_disk_cache:
        try:
            fingerprint = index_fingerprint(resolved)
            artifact_path = os.path.join(
                _cache_dir(), f"tbd-index-{fingerprint[:32]}.json.zlib"
            )
            if os.path.exists(artifact_path) and os.path.getsize(artifact_path) > 0:
                with open(artifact_path, "rb") as handle:
                    index = TbdIndex.from_bytes(handle.read())
                _INDEX_MEMO[resolved] = index
                LOG.debug(
                    "Loaded .tbd index for %s from %s (%d libraries)",
                    resolved,
                    artifact_path,
                    len(index.libraries),
                )
                return index
        except (OSError, ValueError, orjson.JSONDecodeError) as exc:
            LOG.debug("Could not load cached .tbd index: %s", exc)
    index = TbdIndex.build(resolved)
    _INDEX_MEMO[resolved] = index
    if use_disk_cache and artifact_path:
        try:
            os.makedirs(os.path.dirname(artifact_path), exist_ok=True)
            tmp_path = artifact_path + ".tmp"
            with open(tmp_path, "wb") as handle:
                handle.write(index.to_bytes())
            os.replace(tmp_path, artifact_path)
        except OSError as exc:
            LOG.debug("Could not store .tbd index artifact: %s", exc)
    LOG.debug(
        "Built .tbd index for %s: %d libraries from %d files / %d documents",
        resolved,
        len(index.libraries),
        index.file_count,
        index.document_count,
    )
    return index


def enrich_macho_sdk_attribution(metadata: dict, sdk_path: str) -> dict | None:
    """Attribute and confirm Mach-O imports against the SDK's .tbd stubs.

    Three binary-relative facts are recorded under ``metadata["sdk_tbd"]``,
    all additive and all free of SDK identity (no paths, versions, totals
    of the analyst's environment):

    - imports without a ``dylib::symbol`` prefix (flat binds, missing
      binding info) attributed to a declared library via the index;
    - load-command attributions confirmed by the SDK surface, split by
      whether the re-export closure was needed;
    - load-command attributions the SDK surface could *not* confirm --
      private or exported-elsewhere symbols worth an honest look.

    Returns the block, or None when the binary declares no libraries for
    the index to speak about (nothing can be attributed or confirmed
    against a library set that does not exist). Raises TbdSdkError upward
    when the SDK path is unusable: the caller decides loudness, this
    function never downgrades it.
    """
    index = load_or_build_index(sdk_path)
    declared = [
        (entry.get("name") or "")
        for entry in metadata.get("libraries") or []
        if isinstance(entry, dict) and (entry.get("name") or "")
    ]
    if not declared:
        return None
    attributed: dict[str, str] = {}
    confirmed_count = 0
    reexport_confirmed_count = 0
    unconfirmed: list[str] = []
    seen: set[str] = set()
    for bucket in ("symtab_symbols", "dynamic_symbols"):
        for entry in metadata.get(bucket) or []:
            if not isinstance(entry, dict) or not entry.get("is_imported"):
                continue
            name = entry.get("name") or ""
            if not name or name in seen:
                continue
            seen.add(name)
            library, separator, symbol = name.partition("::")
            if separator and is_library_name(library):
                # The bind itself names the library; the SDK can confirm or
                # question it, never replace it.
                provides, via_reexport = index.provides(
                    library.rsplit("/", 1)[-1], symbol
                )
                if provides:
                    confirmed_count += 1
                    if via_reexport:
                        reexport_confirmed_count += 1
                elif len(unconfirmed) < UNCONFIRMED_SYMBOL_SAMPLE_CAP:
                    unconfirmed.append(name)
            else:
                owner = index.attribute(name, declared)
                if owner:
                    attributed[name] = owner
    block = {
        "attributed_symbol_count": len(attributed),
        "attributed_symbols": dict(
            sorted(attributed.items())[:ATTRIBUTED_SYMBOL_SAMPLE_CAP]
        ),
        "confirmed_symbol_count": confirmed_count,
        "reexport_confirmed_symbol_count": reexport_confirmed_count,
        "unconfirmed_symbol_count": len(unconfirmed),
        "unconfirmed_symbols": sorted(unconfirmed)[:UNCONFIRMED_SYMBOL_SAMPLE_CAP],
    }
    metadata["sdk_tbd"] = block
    # The dependency graph must attribute every symbol, not the capped
    # sample metadata carries, so the full map rides along under a private
    # key that parse() deletes before the metadata is exported or cached.
    # Consumers reading exported metadata (reviews, callgraphs) fall back
    # to the sample.
    metadata[SDK_ATTRIBUTIONS_KEY] = dict(sorted(attributed.items()))
    return block
