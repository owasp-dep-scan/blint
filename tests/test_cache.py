"""Parse cache tests (P2.2).

The cache's contract has four load-bearing parts, and each has a test that
would fail loudly if the part broke:

- **Byte identity**: a warm (cached) run must produce metadata byte-identical
  to a cold run. The comparison helper is imported from ``test_determinism``
  rather than re-implemented, so the cache is held to exactly the standard
  the determinism gate sets — including the cross-path case, which pins the
  replay rewrite: every *exact* occurrence of the stored path (``file_path``,
  ``name``, and the binary's own ``import_dependencies`` entry) becomes the
  current path, and the test fails if any other field still carries path A.
- **Invalidation**: the key is (sha256 bytes, blint version, options digest).
  A changed file byte, a changed version, or a changed output-affecting
  option must each force a miss — a cache that never misses is
  indistinguishable from one that is silently wrong.
- **Failure policy**: exceptions escaping ``parse()`` are never cached, so
  every recorded failure is fresh; deterministically malformed input that
  ``parse()`` survives (a truncated wasm, which yields ``binary_type`` plus
  an ``errors`` list) *is* cached, and replays byte-identically.
- **Resources** (workplan rule 18): the cache adds a SQLite connection and a
  file hash to every run, on the hit path and the miss path. The failure test
  asserts the live-resource delta across failing parses, not merely that the
  cleanup code looks right.
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

import orjson
import pytest

import blint.lib.cache as cache_mod
from blint.config import BlintOptions
from blint.lib import runners as runners_mod
from blint.lib.binary import parse
from blint.lib.cache import (
    CacheKeyError,
    ParseCache,
    compute_options_digest,
)
from blint.lib.runners import AnalysisRunner
from blint.lib.utils import gen_file_list
from tests.test_determinism import (
    _DEMO_C,
    _assert_identical_metadata,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def _assert_replay_equals_cold(warm: dict, cold: dict) -> None:
    """Hold a cached replay to the determinism standard, in the export domain.

    A cache serves the serialized domain: orjson turns live LIEF enum objects
    (symtab ``category``/``type``/``kind``/``origin``, ELF ``identity_class``)
    into their integer values, so a replayed dict necessarily carries ints
    where a cold parse holds enum objects. Exported bytes are identical
    either way, and no consumer outside ``binary.py`` reads those fields
    after parse (reviews, SBOM and blintdb read symbol *names*; the one
    string-coercion of ``category`` happens inside parse(), before caching).
    The cold side is therefore normalized through the same serializer the
    export and the cache use, and then both legs of the determinism helper
    — insertion-ordered orjson bytes *and* canonical JSON — run strictly.
    """
    cold_export_domain = orjson.loads(orjson.dumps(cold, default=str))
    _assert_identical_metadata(warm, cold_export_domain)


@pytest.fixture(scope="module")
def native_binary(tmp_path_factory):
    """A freshly compiled native binary so the disassembly path is exercised."""
    compiler = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
    if not compiler:
        pytest.skip("no host C compiler available for the parse-cache fixtures")
    workdir = tmp_path_factory.mktemp("cache-fixtures")
    source = workdir / "demo.c"
    source.write_text(_DEMO_C, encoding="utf-8")
    binary = workdir / "demo-bin"
    subprocess.run(
        [compiler, "-O1", "-o", str(binary), str(source)],
        check=True,
        capture_output=True,
    )
    return binary


@pytest.fixture()
def cache_options(tmp_path):
    """BlintOptions pointed at an isolated reports dir, cache on."""
    return BlintOptions(
        src_dir_image=[],
        reports_dir=str(tmp_path / "reports"),
        no_reviews=True,
    )


def _cached_parse_then_cold_parse(options: BlintOptions, file_path: str):
    """Prime the cache (miss + store), then return a real hit and a cold parse.

    Returns (warm_hit, cold_metadata): ``warm_hit`` comes from a second
    runner consulting the primed cache — the actual replay path consumers
    get; ``cold_metadata`` is a plain parse() call. Comparing them is the
    cache's byte-identity contract.
    """
    options.src_dir_image = [file_path]
    primer = AnalysisRunner()
    primer._setup_parse_cache(options)
    primer._parse_with_cache(file_path, options, "top-level")
    primer.parse_cache.close()

    warm_runner = AnalysisRunner()
    warm_runner._setup_parse_cache(options)
    warm = warm_runner._parse_with_cache(file_path, options, "top-level")
    assert warm_runner.cache_hits == 1, f"expected a cache hit for {file_path}"
    warm_runner.parse_cache.close()

    cold = parse(
        file_path,
        options.disassemble,
        wasm_strings=options.wasm_strings,
        wasm_call_graph=options.wasm_call_graph,
    )
    return warm, cold


def _runner_run(options: BlintOptions, file_path: str) -> AnalysisRunner:
    """A full AnalysisRunner.start() over one file, using the env cache dir."""
    options.src_dir_image = [file_path]
    runner = AnalysisRunner()
    runner._setup_parse_cache(options)
    runner.start(options, gen_file_list([file_path]))
    return runner


def _open_fd_count() -> int:
    if os.path.exists("/dev/fd"):
        return len(os.listdir("/dev/fd"))
    if os.path.exists("/proc/self/fd"):
        return len(os.listdir("/proc/self/fd"))
    pytest.skip("no /dev/fd or /proc/self/fd on this platform")


# ---------------------------------------------------------------------------
# Options digest derivation
# ---------------------------------------------------------------------------


def test_digest_derived_from_parse_signature(cache_options):
    """Changing an output-affecting option changes the digest; changing an
    option that cannot affect parse() output does not."""
    base = compute_options_digest(cache_options)
    cache_options.disassemble = not cache_options.disassemble
    assert compute_options_digest(cache_options) != base
    cache_options.disassemble = not cache_options.disassemble
    cache_options.wasm_strings = not cache_options.wasm_strings
    assert compute_options_digest(cache_options) != base
    cache_options.wasm_strings = not cache_options.wasm_strings
    # Non-parse options must not cause misses: same digest.
    cache_options.no_reviews = not cache_options.no_reviews
    cache_options.reports_dir = "/somewhere/else"
    cache_options.no_cache = not cache_options.no_cache
    assert compute_options_digest(cache_options) == base


def test_digest_raises_on_unkeyed_parse_parameter(cache_options):
    """A parse() parameter with no BlintOptions counterpart must be loud.

    The digest walks parse()'s signature; a future parameter that is not
    wired into BlintOptions raises instead of silently leaving itself out of
    the key, which would serve stale results for that option.
    """

    def future_parse(exe_file, disassemble=False, wasm_strings=True, new_thing=False):
        return {}

    with pytest.raises(CacheKeyError, match="new_thing"):
        compute_options_digest(cache_options, parse_fn=future_parse)

    # Once the parameter is mirrored on BlintOptions it keys automatically.
    cache_options.new_thing = "set"
    digest_with = compute_options_digest(cache_options, parse_fn=future_parse)
    cache_options.new_thing = "other"
    digest_other = compute_options_digest(cache_options, parse_fn=future_parse)
    assert digest_with != digest_other


def test_digest_covers_wasm_instruction_budget(cache_options):
    """BLINT_MAX_WASM_INSTRUCTIONS reaches parse() (wasm report trimming), so
    it is folded into the digest."""
    base = compute_options_digest(cache_options)
    tuned = compute_options_digest(cache_options, wasm_instruction_budget=123456)
    assert tuned != base


def test_parse_cache_disabled_by_no_cache_flag(cache_options):
    """--no-cache means no cache instance and a disabled coverage block."""
    cache_options.no_cache = True
    runner = AnalysisRunner()
    runner._setup_parse_cache(cache_options)
    assert runner.parse_cache is None
    coverage = runner.analysis_coverage()
    assert coverage["cache"] == {
        "enabled": False,
        "hits": 0,
        "misses": 0,
        "stored": 0,
        "caches_failures": False,
        "by_role": {},
    }


# ---------------------------------------------------------------------------
# Byte identity: cold vs warm
# ---------------------------------------------------------------------------


def test_cold_vs_warm_byte_identical_native(native_binary, cache_options):
    """A cached replay is byte-identical to a fresh parse, both as
    insertion-ordered orjson bytes and as canonical JSON."""
    cache_options.disassemble = True
    warm, cold = _cached_parse_then_cold_parse(cache_options, str(native_binary))
    if not warm.get("disassembled_functions"):
        pytest.skip("disassembly unavailable (nyxstone cannot handle this host target)")
    _assert_replay_equals_cold(warm, cold)


def test_cold_vs_warm_byte_identical_wasm(cache_options):
    warm, cold = _cached_parse_then_cold_parse(
        cache_options, str(REPO_ROOT / "tests" / "data" / "complex_flow.wasm")
    )
    _assert_replay_equals_cold(warm, cold)


def _corpus_files():
    corpus = REPO_ROOT / "corpus-build"
    if not corpus.is_dir():
        return []
    return sorted(
        p.name for p in corpus.iterdir() if p.is_file() and not p.name.startswith(".")
    )


@pytest.mark.parametrize(
    "fixture_name",
    _corpus_files(),
)
def test_cold_vs_warm_byte_identical_corpus(fixture_name, cache_options):
    """Every materialized corpus fixture: warm replay == cold parse.

    Skipped cleanly when corpus-build/ has not been materialized; when it
    has, this is the full-corpus form of the byte-identity gate (not just a
    couple of fixtures).
    """
    fixture = REPO_ROOT / "corpus-build" / fixture_name
    cache_options.disassemble = True
    warm, cold = _cached_parse_then_cold_parse(cache_options, str(fixture))
    _assert_replay_equals_cold(warm, cold)


def test_cold_vs_warm_byte_identical_across_paths(native_binary, cache_options, tmp_path):
    """Content-addressed means the entry is shared across paths.

    Parse and cache at path A, replay at path B: the replay must equal a
    cold parse at path B — pinning that the stored path is rewritten exactly
    where parse() embeds it (file_path, name, the import_dependencies
    self-entry) and nowhere else.
    """
    path_a = tmp_path / "first-location-bin"
    path_b = tmp_path / "second_location" / "renamed-bin"
    shutil.copy(native_binary, path_a)
    path_b.parent.mkdir()
    shutil.copy(native_binary, path_b)
    cache_options.disassemble = True

    primer = AnalysisRunner()
    primer._setup_parse_cache(cache_options)
    primer._parse_with_cache(str(path_a), cache_options, "top-level")
    primer.parse_cache.close()

    replayer = AnalysisRunner()
    replayer._setup_parse_cache(cache_options)
    warm = replayer._parse_with_cache(str(path_b), cache_options, "top-level")
    assert replayer.cache_hits == 1, "same bytes at a new path must be a cache hit"
    replayer.parse_cache.close()

    cold = parse(str(path_b), disassemble=True)
    _assert_replay_equals_cold(warm, cold)


# ---------------------------------------------------------------------------
# Invalidation
# ---------------------------------------------------------------------------


def test_invalidation_changed_file_bytes(native_binary, cache_options):
    """Modifying the file's bytes at the same path forces a miss."""
    cache_options.disassemble = False
    work = cache_options.reports_dir + "-bin"
    shutil.copy(native_binary, work)
    first = _runner_run(cache_options, work)
    assert first.cache_stored == 1

    with open(work, "r+b") as handle:
        handle.seek(-1, os.SEEK_END)
        tail = handle.read(1)
        handle.seek(-1, os.SEEK_END)
        handle.write(bytes([tail[0] ^ 0xFF]))

    second = _runner_run(cache_options, work)
    assert second.cache_hits == 0, "changed bytes must not be served from cache"
    assert second.cache_misses == 1
    assert second.cache_stored == 1


def test_invalidation_changed_blint_version(native_binary, cache_options, monkeypatch):
    """A different blint version is a different key."""
    cache_options.disassemble = False
    first = _runner_run(cache_options, str(native_binary))
    assert first.cache_stored == 1

    monkeypatch.setattr(cache_mod, "_blint_version", lambda: "99.0.0-test")
    second = _runner_run(cache_options, str(native_binary))
    assert second.cache_hits == 0, "a version change must invalidate entries"
    assert second.cache_misses == 1


def test_invalidation_changed_option(native_binary, cache_options):
    """A changed output-affecting option is a different key, and the replayed
    metadata matches the new options rather than the cached ones."""
    cache_options.disassemble = True
    first = _runner_run(cache_options, str(native_binary))
    assert first.cache_stored == 1

    cache_options.disassemble = False
    second = _runner_run(cache_options, str(native_binary))
    assert second.cache_hits == 0, "changed disassemble option must invalidate"
    metadata = json.loads(
        (Path(cache_options.reports_dir) / f"{Path(native_binary).name}-metadata.json").read_text()
    )
    assert not metadata.get("disassembled_functions")


# ---------------------------------------------------------------------------
# Failure policy
# ---------------------------------------------------------------------------


def test_failure_never_cached_and_resources_stable(native_binary, cache_options, monkeypatch):
    """A parse that raises is recorded as a fresh failure every time, nothing
    is stored, and the run leaks no file descriptors (rule 18).

    The cache adds a SQLite connection and a file hash to the run on both
    the hit and the miss path; this asserts the live-resource delta across
    failing parses instead of trusting the cleanup code by reading it.
    """
    cache_options.disassemble = True
    calls = {"n": 0}

    def exploding_parse(*args, **kwargs):
        calls["n"] += 1
        raise RuntimeError(f"synthetic parse failure #{calls['n']}")

    monkeypatch.setattr(runners_mod, "parse", exploding_parse)

    baseline_fds = _open_fd_count()
    for attempt in (1, 2, 3):
        runner = AnalysisRunner()
        runner._setup_parse_cache(cache_options)
        runner.start(cache_options, [str(native_binary)])
        coverage = runner.analysis_coverage()
        assert coverage["units"]["failed"] == 1
        assert coverage["units"]["succeeded"] == 0
        assert coverage["failures"][0]["message"] == f"synthetic parse failure #{attempt}"
        assert coverage["cache"]["stored"] == 0
        assert coverage["cache"]["caches_failures"] is False
        # The cache connection is closed structurally in start()'s finally.
        assert runner.parse_cache._conn is None
        # Three runs in, the fd count must be back at baseline: no connection
        # or file handle may survive a run.
        assert _open_fd_count() == baseline_fds, f"fd leak on failing run {attempt}"
    assert calls["n"] == 3, "every run must actually parse; failures are not replayed"

    store = ParseCache()
    assert store.stats()["entries"] == 0


def test_deterministic_corrupt_input_is_cached_and_replayed_identically(cache_options):
    """A truncated wasm parses to binary_type + errors deterministically, so
    it is cached — and the replay carries the same errors, byte-identical."""
    data = (REPO_ROOT / "tests" / "data" / "complex_flow.wasm").read_bytes()
    bin_dir = Path(cache_options.reports_dir + "-bin")
    bin_dir.mkdir(parents=True, exist_ok=True)
    corrupt_file = bin_dir / "truncated.wasm"
    corrupt_file.write_bytes(data[: int(len(data) * 0.6)])

    cache_options.disassemble = False
    warm, cold = _cached_parse_then_cold_parse(cache_options, str(corrupt_file))
    assert cold.get("errors"), "fixture must be a deterministic parse failure"
    _assert_replay_equals_cold(warm, cold)


def test_hit_run_coverage_distinguishes_cached_units(cache_options):
    """The run-level coverage must let a consumer tell a cached run from a
    cold one, including which roles were served from cache (rule 19)."""
    wasm = str(REPO_ROOT / "tests" / "data" / "complex_flow.wasm")
    first = _runner_run(cache_options, wasm)
    cold_block = first.analysis_coverage()["cache"]
    assert cold_block["enabled"] is True
    assert cold_block["hits"] == 0 and cold_block["misses"] == 1 and cold_block["stored"] == 1
    assert cold_block["by_role"] == {"top-level": {"hits": 0, "misses": 1, "stored": 1}}

    second = _runner_run(cache_options, wasm)
    warm_block = second.analysis_coverage()["cache"]
    assert warm_block["hits"] == 1 and warm_block["misses"] == 0 and warm_block["stored"] == 0
    assert warm_block["by_role"] == {"top-level": {"hits": 1, "misses": 0, "stored": 0}}


# ---------------------------------------------------------------------------
# Management surface: stats, clear, eviction, symlink refusal
# ---------------------------------------------------------------------------


def test_stats_and_clear(tmp_path):
    cache = ParseCache(cache_dir=str(tmp_path / "c"))
    stats = cache.stats()
    assert stats["exists"] is False and stats["entries"] == 0

    big = {"binary_type": "ELF", "blob": [{"k": i} for i in range(500)]}
    assert cache.put("aa" * 32, "digest", big) is True
    assert cache.get("aa" * 32, "/x", "digest") is not None

    stats = cache.stats()
    assert stats["exists"] is True
    assert stats["entries"] == 1
    assert stats["logical_bytes"] > stats["compressed_bytes"] > 0
    assert stats["db_file_bytes"] == os.path.getsize(cache.db_path)
    assert stats["total_hits"] == 1

    freed = cache.clear()
    assert freed > 0
    assert cache.stats()["exists"] is False
    cache.close()


def _incompressible_blob(seed: int, size: int = 4000) -> list[str]:
    """Random-ish strings so zlib cannot shrink the entry: eviction is sized
    on stored (compressed) bytes, and repetitive blobs would compress to
    almost nothing and make the bound untestable."""
    import hashlib

    blob = []
    counter = seed
    while sum(len(s) for s in blob) < size:
        counter += 1
        blob.append(hashlib.sha256(f"{seed}:{counter}".encode()).hexdigest())
    return blob


def test_lru_eviction_honors_size_bound(tmp_path):
    cache = ParseCache(cache_dir=str(tmp_path / "c"))
    entries = {
        "aa" * 32: _incompressible_blob(1),
        "bb" * 32: _incompressible_blob(2),
    }
    for sha, blob in entries.items():
        assert cache.put(sha, "d", {"binary_type": "ELF", "blob": blob})
    # Touch bb so aa becomes the least-recently-used entry.
    assert cache.get("bb" * 32, "/x", "d") is not None

    two_entries_total = cache.stats()["compressed_bytes"]
    # A bound just below both entries forces an eviction on the next store.
    cache.max_bytes = two_entries_total - 1
    assert cache.put("cc" * 32, "d", {"binary_type": "ELF", "blob": _incompressible_blob(3)})

    survivors = {
        row[0]
        for row in cache._connection().execute("SELECT file_sha256 FROM ParseCache")
    }
    # The least-recently-used entry (aa, never touched) must be evicted
    # first, and the just-stored entry must survive the pass.
    assert "aa" * 32 not in survivors, "LRU order must decide who is evicted first"
    assert "cc" * 32 in survivors
    cache.close()


def test_symlinked_cache_db_is_refused(tmp_path):
    """A symlinked cache file is never written through."""
    cache_dir = tmp_path / "c"
    cache_dir.mkdir()
    target = tmp_path / "elsewhere.db"
    target.write_bytes(b"")
    link = cache_dir / "parse-cache.db"
    link.symlink_to(target)
    cache = ParseCache(cache_dir=str(cache_dir))
    assert cache.put("aa" * 32, "d", {"binary_type": "ELF"}) is False
    assert cache.get("aa" * 32, "/x", "d") is None
    assert target.stat().st_size == 0
    cache.close()


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


def test_cli_no_cache_flag_default_off():
    from blint.cli import build_parser

    args = build_parser().parse_args(["--no-cache", "-i", "/tmp"])
    assert args.no_cache is True
    args = build_parser().parse_args(["-i", "/tmp"])
    assert args.no_cache is False


def test_cli_cache_subcommand_parsing():
    from blint.cli import build_parser

    args = build_parser().parse_args(["cache", "stats", "--json"])
    assert args.subcommand_name == "cache"
    assert args.cache_action == "stats"
    assert args.cache_stats_json is True
    args = build_parser().parse_args(["cache", "clear"])
    assert args.cache_action == "clear"


def test_cli_cache_stats_and_clear_roundtrip(tmp_path, capsys):
    """The `blint cache stats/clear` handlers against a real store.

    ParseCache() inside run_cache_command resolves BLINT_CACHE_DIR, which the
    suite's conftest pins to this test's tmp_path.
    """
    from blint.cli import build_parser, run_cache_command

    seeded = ParseCache()  # same env-resolved location the CLI will use
    seeded.put("aa" * 32, "d", {"binary_type": "ELF", "blob": ["x" * 100]})
    seeded.close()

    parser = build_parser()
    run_cache_command(parser.parse_args(["cache", "stats", "--json"]))
    payload = json.loads(capsys.readouterr().out)
    assert payload["exists"] is True
    assert payload["entries"] == 1

    run_cache_command(parser.parse_args(["cache", "clear"]))
    out = capsys.readouterr().out
    assert "Deleted parse cache" in out

    run_cache_command(parser.parse_args(["cache", "stats", "--json"]))
    payload = json.loads(capsys.readouterr().out)
    assert payload["exists"] is False and payload["entries"] == 0
