"""Shared test isolation for the whole suite.

The parse cache is enabled by default in default-mode runs; without
this fixture every analysis test would read and write the developer's real
user cache directory and second runs would silently replay cached metadata
instead of exercising the parse path. Each test gets a throwaway cache
directory via BLINT_CACHE_DIR, which ParseCache reads at construction time.
"""

import pytest


@pytest.fixture(autouse=True)
def _isolated_parse_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("BLINT_CACHE_DIR", str(tmp_path / "parse-cache"))
    yield


@pytest.fixture(autouse=True)
def _no_blintdb_env_leak(monkeypatch):
    """Every test starts and ends without USE_BLINTDB.

    blintdb_setup sets USE_BLINTDB=true after a pull, for the rest of the
    process. Leaked into a later test, a `blint sbom` subprocess that test
    spawns inherits it and pulls the real multi-GB blintdb. Recording the
    variable through monkeypatch restores it after the test whatever the
    test, or the code under test, did to it.
    """
    monkeypatch.setenv("USE_BLINTDB", "")
    monkeypatch.delenv("USE_BLINTDB")
    yield
