"""Shared test isolation for the whole suite.

The parse cache (P2.2) is enabled by default in default-mode runs; without
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
