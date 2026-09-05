# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT
"""Content-addressed cache for parse metadata (P2.2).

Caches the output of ``blint.lib.binary.parse`` keyed on
``(sha256(file bytes), blint version, options digest)`` in a SQLite database
maintained with the apsw machinery from ``blint.db``. The cache database lives
under the user cache directory (``appdirs.user_cache_dir("blint")``), never
inside blintdb: blintdb is a shipped read-only artifact and must not be
written to.

The options digest is *derived*, not hand-listed: ``compute_options_digest``
walks ``parse()``'s own signature and resolves every parameter except the
input path against the ``BlintOptions`` attribute of the same name. A new
``parse()`` parameter therefore enters the key automatically; one without a
``BlintOptions`` counterpart raises ``CacheKeyError`` at startup rather than
silently serving stale results, because a missed option serving wrong results
is worse than any slowdown. ``BLINT_MAX_WASM_INSTRUCTIONS`` (the one
environment constant that reaches ``parse()``) is folded into the digest;
``BLINT_MAX_HEX_BYTES`` is export-time only and deliberately excluded.

Replay path rewriting: ``parse()`` embeds the input path in its output in a
handful of places — the top-level ``file_path`` and ``name`` fields, and
inside ``import_dependencies`` where the binary's own path is the
``libraries`` key and the ``from`` of its dependency edges. Entries are
content-addressed, so a hit is rewritten by replacing every *exact*
occurrence of the stored path (string values and dict keys, at any depth)
with the current path, preserving key order. Exact match matters: a binary
can embed its own build-time path inside strings extracted from the bytes,
and those are binary content that must not be touched. The cold-versus-warm
byte-identity tests include a cross-path case that fails loudly if a future
change leaks the path anywhere else (the one known exception is the error
message recorded when a wasm file fails to parse, which embeds the path as a
substring inside a longer sentence and therefore stays as first parsed).

Failure policy: parse results are cached only when ``parse()`` returns
normally *and* produced a recognized binary (a ``binary_type``). Exceptions
escaping ``parse()`` are never cached — they can have transient causes (fd or
memory exhaustion), and replaying one would turn a temporary outage into a
permanent failure for that file. Deterministically malformed input that
``parse()`` survives is cached like any other result, because replaying it is
byte-identical to reparse. Run-level coverage therefore never carries a
replayed failure.

Entries are zlib-compressed and the store is bounded: when the compressed
total exceeds ``BLINT_CACHE_MAX_BYTES`` (default 1 GiB, 0 disables the bound),
least-recently-used entries are evicted until it fits. The store lives at
``BLINT_CACHE_DIR`` (default: the per-user cache directory) in a file named
``parse-cache.db``; ``blint cache stats`` reports its actual size on disk and
``blint cache clear`` deletes it.
"""

from __future__ import annotations

import contextlib
import hashlib
import inspect
import os
import time
import zlib
from typing import Any

import apsw
import orjson

from blint.config import get_int_from_env
from blint.db import _apply_runtime_pragmas, _execute
from blint.lib.binary import parse as binary_parse
from blint.logger import LOG

CACHE_SCHEMA_VERSION = 1
DEFAULT_MAX_CACHE_BYTES = 1024 * 1024 * 1024
# Parse results without a recognized binary_type are not stored: an
# unrecognized file parses to near-nothing in microseconds, and caching that
# near-nothing pollutes the store without saving anything.
_STORE_MIN_KEYS = ("binary_type",)
_ZLIB_LEVEL = 6


class CacheKeyError(RuntimeError):
    """Raised when a parse() input that affects output cannot be keyed."""


def _blint_version() -> str:
    """The running blint version; part of the cache key."""
    from importlib.metadata import version

    try:
        return version("blint")
    except Exception:  # noqa: BLE001
        return "unknown"


def sha256_file(file_path: str) -> str | None:
    """sha256 hex digest of the file's bytes, or None when unreadable."""
    digest = hashlib.sha256()
    try:
        with open(file_path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def compute_options_digest(
    blint_options: Any,
    parse_fn=None,
    wasm_instruction_budget: int | None = None,
) -> str:
    """Derive a digest of every option that can affect ``parse()`` output.

    The parameter list comes from ``parse()``'s signature itself, so adding a
    parameter to ``parse()`` changes the digest without touching this module.
    Each parameter (except the input path) must resolve to a ``BlintOptions``
    attribute of the same name; anything else raises ``CacheKeyError`` so the
    gap is loud instead of a silently wrong cache. The wasm instruction
    budget constant that ``binary.py`` consumes is folded in explicitly.
    """
    parse_fn = parse_fn or binary_parse
    if wasm_instruction_budget is None:
        wasm_instruction_budget = binary_parse.__globals__.get(
            "BLINT_MAX_WASM_INSTRUCTIONS", 0
        )
    payload: dict[str, Any] = {
        "cache_schema": CACHE_SCHEMA_VERSION,
        "BLINT_MAX_WASM_INSTRUCTIONS": wasm_instruction_budget,
    }
    for name, param in inspect.signature(parse_fn).parameters.items():
        if name == "exe_file":
            continue
        if param.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
            raise CacheKeyError(
                f"parse() parameter {name!r} is variadic; the cache cannot key it. "
                "Refactor parse() to take explicit options before caching it."
            )
        if hasattr(blint_options, name):
            payload[name] = getattr(blint_options, name)
        else:
            raise CacheKeyError(
                f"parse() parameter {name!r} has no BlintOptions counterpart, so "
                "the parse cache cannot key it. Add the attribute to BlintOptions "
                "(or exclude it here with a comment proving it cannot affect "
                "parse output); serving cached results for an unkeyed option "
                "would silently be wrong."
            )
    canonical = orjson.dumps(payload, option=orjson.OPT_SORT_KEYS)
    return hashlib.sha256(canonical).hexdigest()


class ParseCache:
    """SQLite-backed content-addressed store of parse metadata.

    One connection, opened lazily and reused for the whole run; ``close`` is
    idempotent and must be called by the owner when the run ends (the
    AnalysisRunner closes it in a ``finally``). Every SQLite failure is
    swallowed into a cache miss or a skipped store with a debug log: the cache
    is best-effort and must never fail a scan.
    """

    def __init__(
        self,
        *,
        enabled: bool = True,
        cache_dir: str | None = None,
        max_bytes: int | None = None,
    ) -> None:
        self.enabled = enabled
        # user_cache_dir("blint") already ends in the app name on every
        # platform (~/Library/Caches/blint, ~/.cache/blint); do not append
        # another one.
        self.cache_dir = cache_dir or os.environ.get("BLINT_CACHE_DIR") or _user_cache_dir()
        self.db_path = os.path.join(self.cache_dir, "parse-cache.db")
        if max_bytes is None:
            max_bytes = get_int_from_env("BLINT_CACHE_MAX_BYTES", DEFAULT_MAX_CACHE_BYTES)
        self.max_bytes = max(0, int(max_bytes))
        self._conn: apsw.Connection | None = None

    # -- connection handling -------------------------------------------------

    def _connection(self, create: bool = False) -> apsw.Connection | None:
        if self._conn is not None:
            return self._conn
        if not create and not os.path.exists(self.db_path):
            return None
        try:
            # Refuse a symlinked cache file explicitly. blintdb opens its own
            # database with SQLITE_OPEN_NOFOLLOW; that flag cannot be used
            # here because SQLite rejects paths with a symlinked parent
            # directory outright (CantOpenError), which on macOS means every
            # location under /var/folders — i.e. all temp dirs.
            if os.path.islink(self.db_path):
                LOG.warning(
                    "Parse cache at %s is a symlink; refusing to use it", self.db_path
                )
                return None
            if create:
                os.makedirs(self.cache_dir, exist_ok=True)
            flags = apsw.SQLITE_OPEN_READWRITE
            if create:
                flags |= apsw.SQLITE_OPEN_CREATE
            self._conn = apsw.Connection(os.path.abspath(self.db_path), flags=flags)
            _apply_runtime_pragmas(self._conn, read_only=False)
            if create:
                self._create_schema(self._conn)
        except (apsw.Error, OSError) as exc:
            LOG.debug("Parse cache unavailable at %s: %s", self.db_path, exc)
            self.close()
            return None
        return self._conn

    @staticmethod
    def _create_schema(connection: apsw.Connection) -> None:
        # incremental auto_vacuum must be set before the first table exists to
        # take effect, so pages freed by eviction are returned to the OS on
        # incremental_vacuum instead of lingering in the file
        with contextlib.suppress(apsw.Error):
            connection.execute("PRAGMA auto_vacuum = INCREMENTAL")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS ParseCache (
                cache_key TEXT PRIMARY KEY,
                file_sha256 TEXT NOT NULL,
                blint_version TEXT NOT NULL,
                options_digest TEXT NOT NULL,
                byte_size INTEGER NOT NULL,
                stored_size INTEGER NOT NULL,
                created_at REAL NOT NULL,
                last_used REAL NOT NULL,
                hits INTEGER NOT NULL DEFAULT 0,
                data BLOB NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS ParseCacheLru ON ParseCache (last_used)"
        )

    def close(self) -> None:
        """Close the SQLite connection; idempotent."""
        if self._conn is not None:
            with contextlib.suppress(Exception):
                self._conn.close()
            self._conn = None

    # -- core operations -----------------------------------------------------

    def cache_key(self, file_sha256: str, options_digest: str) -> str:
        material = orjson.dumps(
            [CACHE_SCHEMA_VERSION, file_sha256, _blint_version(), options_digest],
            option=orjson.OPT_SORT_KEYS,
        )
        return hashlib.sha256(material).hexdigest()

    def get(self, file_sha256: str, current_path: str, options_digest: str) -> dict | None:
        """Return cached metadata for the file content, rewritten for
        ``current_path``. Returns None on any miss or error."""
        if not self.enabled or not file_sha256:
            return None
        connection = self._connection(create=False)
        if connection is None:
            return None
        cache_key = self.cache_key(file_sha256, options_digest)
        try:
            rows = _execute(
                connection,
                "SELECT data FROM ParseCache WHERE cache_key = ?",
                [cache_key],
            )
            if not rows:
                return None
            metadata = orjson.loads(zlib.decompress(rows[0]["data"]))
            connection.execute(
                "UPDATE ParseCache SET last_used = ?, "
                "hits = COALESCE(hits, 0) + 1 WHERE cache_key = ?",
                [time.time(), cache_key],
            )
        except (apsw.Error, zlib.error, ValueError) as exc:
            LOG.debug("Parse cache read failed for %s: %s", current_path, exc)
            return None
        if not isinstance(metadata, dict):
            return None
        # parse() embeds the input path in its output (file_path, name, and
        # the binary's own entry in import_dependencies); rewrite every exact
        # occurrence of the stored path so the replay mirrors a fresh parse
        # at the current location.
        stored_path = metadata.get("file_path")
        metadata = self._rewrite_stored_path(metadata, stored_path, current_path)
        metadata["file_path"] = current_path
        if "name" in metadata:
            metadata["name"] = current_path
        return metadata

    @staticmethod
    def _rewrite_stored_path(value: Any, stored_path: str | None, current_path: str) -> Any:
        """Replace exact occurrences of the stored path with the current one.

        Only whole-string equality is rewritten, in both dict keys and string
        values, at any depth; dict insertion order is preserved (a plain
        ``d[new] = d.pop(old)`` would move the key and break byte identity).
        Strings that merely *contain* the path as a substring — binary-embedded
        build paths, wasm parse-error sentences — are content and stay as
        stored.
        """
        if not stored_path or stored_path == current_path:
            return value
        if isinstance(value, str):
            return current_path if value == stored_path else value
        if isinstance(value, dict):
            return {
                (current_path if key == stored_path else key): (
                    ParseCache._rewrite_stored_path(item, stored_path, current_path)
                )
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [ParseCache._rewrite_stored_path(item, stored_path, current_path) for item in value]
        return value

    def put(self, file_sha256: str, options_digest: str, metadata: dict) -> bool:
        """Store parse metadata. Only results with a recognized ``binary_type``
        are stored; exceptions never reach here because the caller only calls
        ``put`` after ``parse()`` returned normally."""
        if not self.enabled or not file_sha256 or not isinstance(metadata, dict):
            return False
        if not all(key in metadata for key in _STORE_MIN_KEYS):
            LOG.debug(
                "Not caching parse result without %s for %s",
                _STORE_MIN_KEYS,
                metadata.get("file_path"),
            )
            return False
        try:
            raw = orjson.dumps(metadata, default=str)
            data = zlib.compress(raw, _ZLIB_LEVEL)
        except (TypeError, ValueError) as exc:
            LOG.debug("Parse cache serialization failed: %s", exc)
            return False
        connection = self._connection(create=True)
        if connection is None:
            return False
        cache_key = self.cache_key(file_sha256, options_digest)
        now = time.time()
        try:
            connection.execute(
                "INSERT OR REPLACE INTO ParseCache "
                "(cache_key, file_sha256, blint_version, options_digest, "
                " byte_size, stored_size, created_at, last_used, data) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    cache_key,
                    file_sha256,
                    _blint_version(),
                    options_digest,
                    len(raw),
                    len(data),
                    now,
                    now,
                    data,
                ],
            )
            self._evict(connection)
        except (apsw.Error, MemoryError) as exc:
            LOG.debug("Parse cache write failed: %s", exc)
            return False
        return True

    def _evict(self, connection: apsw.Connection) -> None:
        """Evict least-recently-used entries until the store fits the bound."""
        if not self.max_bytes:
            return
        rows = _execute(
            connection,
            "SELECT cache_key, stored_size FROM ParseCache "
            "ORDER BY last_used ASC, created_at ASC",
            [],
        )
        total = sum(int(row["stored_size"]) for row in rows)
        evicted = 0
        for row in rows:
            if total <= self.max_bytes:
                break
            connection.execute(
                "DELETE FROM ParseCache WHERE cache_key = ?", [row["cache_key"]]
            )
            total -= int(row["stored_size"])
            evicted += 1
        if evicted:
            LOG.debug("Parse cache evicted %d entry(s) to honor the size bound", evicted)
            with contextlib.suppress(apsw.Error):
                connection.execute("PRAGMA incremental_vacuum")

    # -- management surface (blint cache stats/clear) --------------------------

    def stats(self) -> dict:
        """On-disk facts about the cache, actual sizes included."""
        result: dict[str, Any] = {
            "db_path": self.db_path,
            "exists": os.path.exists(self.db_path),
            "enabled": self.enabled,
            "max_bytes": self.max_bytes,
            "entries": 0,
            "logical_bytes": 0,
            "compressed_bytes": 0,
            "total_hits": 0,
            "db_file_bytes": 0,
            "by_blint_version": {},
        }
        if not result["exists"]:
            return result
        result["db_file_bytes"] = os.path.getsize(self.db_path)
        connection = self._connection(create=False)
        if connection is None:
            return result
        try:
            rows = _execute(
                connection,
                "SELECT COUNT(*) AS entries, "
                "COALESCE(SUM(byte_size), 0) AS logical_bytes, "
                "COALESCE(SUM(stored_size), 0) AS compressed_bytes, "
                "COALESCE(SUM(hits), 0) AS total_hits "
                "FROM ParseCache",
                [],
            )
            if rows:
                result.update(rows[0])
            for row in _execute(
                connection,
                "SELECT blint_version, COUNT(*) AS entries, "
                "COALESCE(SUM(stored_size), 0) AS compressed_bytes "
                "FROM ParseCache GROUP BY blint_version",
                [],
            ):
                result["by_blint_version"][row["blint_version"]] = {
                    "entries": row["entries"],
                    "compressed_bytes": row["compressed_bytes"],
                }
        except apsw.Error as exc:
            LOG.debug("Parse cache stats failed: %s", exc)
        return result

    def clear(self) -> int:
        """Delete the cache database; returns bytes freed (0 when absent)."""
        self.close()
        if not os.path.exists(self.db_path):
            return 0
        freed = os.path.getsize(self.db_path)
        os.remove(self.db_path)
        return freed


def _user_cache_dir() -> str:
    from appdirs import user_cache_dir

    return user_cache_dir("blint")
