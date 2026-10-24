"""Resumable, verified blob pulls for blintdb (blint.lib.oci_pull).

blintdb layers are 15 to 74 GB. blint 4.0.1's pull died with
``IncompleteRead`` a few GB in, exited 0, and left a truncated blint.db that
later runs treated as present. These tests drive ``download_layer_verified``
against a fake registry: a dropped stream resumes with a Range request, a
server that ignores the range restarts the layer, an interrupted run's
``.part`` is resumed by the next one, and nothing unverified ever lands at
the destination.
"""

import hashlib
from pathlib import Path

import pytest
import requests

from blint.lib import oci_pull
from blint.lib.oci_pull import PullFailedError, RegistryPullClient

BLOB = bytes(range(256)) * 64  # 16 KiB
DIGEST = f"sha256:{hashlib.sha256(BLOB).hexdigest()}"


class FakeResponse:
    def __init__(self, status_code, body=b"", headers=None, fail_after=None):
        self.status_code = status_code
        self.headers = headers or {}
        self._body = body
        self._fail_after = fail_after
        self.closed = False

    def iter_content(self, chunk_size=1):
        sent = 0
        for start in range(0, len(self._body), 1024):
            if self._fail_after is not None and sent >= self._fail_after:
                raise requests.exceptions.ChunkedEncodingError("IncompleteRead")
            chunk = self._body[start : start + 1024]
            sent += len(chunk)
            yield chunk

    def close(self):
        self.closed = True


class FakeRegistry(RegistryPullClient):
    """Serves BLOB, honouring Range unless told not to, with scripted drops."""

    def __init__(self, drops=(), honour_range=True, statuses=()):
        super().__init__("ghcr.io", "appthreat/blintdb-test")
        self.drops = list(drops)
        self.statuses = list(statuses)
        self.honour_range = honour_range
        self.ranges = []

    def request(self, method, path, **kwargs):
        range_header = (kwargs.get("headers") or {}).get("Range")
        self.ranges.append(range_header)
        if self.statuses:
            status = self.statuses.pop(0)
            if isinstance(status, tuple):
                return FakeResponse(status[0], headers=status[1])
            return FakeResponse(status)
        fail_after = self.drops.pop(0) if self.drops else None
        if range_header and self.honour_range:
            offset = int(range_header.removeprefix("bytes=").rstrip("-"))
            if offset >= len(BLOB):
                return FakeResponse(416)
            return FakeResponse(
                206,
                BLOB[offset:],
                {"Content-Range": f"bytes {offset}-{len(BLOB) - 1}/{len(BLOB)}"},
                fail_after,
            )
        return FakeResponse(200, BLOB, fail_after=fail_after)


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch):
    monkeypatch.setattr(oci_pull.time, "sleep", lambda _seconds: None)


def _part_files(directory: Path) -> list[Path]:
    return sorted(directory.glob(".*.part"))


def test_dropped_stream_resumes_with_a_range_request(tmp_path):
    registry = FakeRegistry(drops=[4096, 8192])
    dest = tmp_path / "blint.db"
    registry.download_layer_verified(DIGEST, len(BLOB), dest, "blint.db")
    assert dest.read_bytes() == BLOB
    assert registry.ranges == [None, "bytes=4096-", "bytes=12288-"]
    assert _part_files(tmp_path) == []


def test_server_ignoring_the_range_restarts_the_layer(tmp_path):
    registry = FakeRegistry(drops=[4096], honour_range=False)
    dest = tmp_path / "blint.db"
    registry.download_layer_verified(DIGEST, len(BLOB), dest, "blint.db")
    # The full body came back on the retry and replaced the partial bytes
    # rather than being appended to them.
    assert dest.read_bytes() == BLOB


def test_exhausted_resumes_fail_and_keep_the_part_for_the_next_run(tmp_path):
    drops = [1024] * (oci_pull.MAX_RESUME_ATTEMPTS + 1)
    registry = FakeRegistry(drops=drops)
    dest = tmp_path / "blint.db"
    with pytest.raises(PullFailedError, match="kept at"):
        registry.download_layer_verified(DIGEST, len(BLOB), dest, "blint.db")
    assert not dest.exists()
    parts = _part_files(tmp_path)
    assert len(parts) == 1
    kept = parts[0].read_bytes()
    assert kept == BLOB[: len(kept)] and 0 < len(kept) < len(BLOB)

    # The next run re-hashes what is there and asks only for the rest.
    retry = FakeRegistry()
    retry.download_layer_verified(DIGEST, len(BLOB), dest, "blint.db")
    assert dest.read_bytes() == BLOB
    assert retry.ranges == [f"bytes={len(kept)}-"]
    assert _part_files(tmp_path) == []


def test_part_of_another_digest_is_not_resumed_and_is_removed(tmp_path):
    """A part left for an older image digest would otherwise sit there, GBs
    large, for good."""
    stale = tmp_path / ".blint.db.0000000000000000.part"
    stale.write_bytes(b"x" * 100)
    registry = FakeRegistry()
    registry.download_layer_verified(DIGEST, len(BLOB), tmp_path / "blint.db", "blint.db")
    assert registry.ranges == [None]
    assert _part_files(tmp_path) == []


def test_a_second_pull_is_refused_while_one_holds_the_destination(tmp_path):
    """Two runs sharing BLINTDB_HOME used to append to the same .part."""
    dest = tmp_path / "blint.db"
    with (
        oci_pull._exclusive_lock(tmp_path / ".blint.db.lock", "blint.db"),
        pytest.raises(PullFailedError, match="another pull is writing"),
    ):
        FakeRegistry().download_layer_verified(DIGEST, len(BLOB), dest, "blint.db")
    assert not dest.exists()
    FakeRegistry().download_layer_verified(DIGEST, len(BLOB), dest, "blint.db")
    assert dest.read_bytes() == BLOB


def test_the_file_itself_is_verified_before_it_lands(tmp_path, monkeypatch):
    """The digest of the stream is not the digest of the file when anything
    else wrote to it."""
    dest = tmp_path / "blint.db"

    def fetch_with_extra_bytes(self, digest, size, part_file, written, label):
        part_file.write_bytes(BLOB + b"appended by someone else")

    monkeypatch.setattr(RegistryPullClient, "_fetch_into", fetch_with_extra_bytes)
    with pytest.raises(PullFailedError, match="Size mismatch"):
        FakeRegistry().download_layer_verified(DIGEST, len(BLOB), dest, "blint.db")
    assert not dest.exists()
    assert _part_files(tmp_path) == []


class MisreadRangeRegistry(FakeRegistry):
    """A proxy that answers a Range request with a 206 the part cannot take."""

    def __init__(self, mode):
        super().__init__(drops=[4096])
        self.mode = mode

    def request(self, method, path, **kwargs):
        range_header = (kwargs.get("headers") or {}).get("Range")
        if not range_header:
            return super().request(method, path, **kwargs)
        self.ranges.append(range_header)
        offset = int(range_header.removeprefix("bytes=").rstrip("-"))
        end = f"{len(BLOB) - 1}/{len(BLOB)}"
        if self.mode == "early-start":
            start = offset - 1000
            return FakeResponse(206, BLOB[start:], {"Content-Range": f"bytes {start}-{end}"})
        if self.mode == "no-content-range":
            return FakeResponse(206, BLOB[offset:], {})
        return FakeResponse(206, BLOB[offset:], {"Content-Range": f"Bytes {offset}-{end}"})


@pytest.mark.parametrize(
    ("mode", "ranges"),
    [
        # A 206 that does not start where the part ends is never appended.
        ("early-start", [None, "bytes=4096-", None]),
        ("no-content-range", [None, "bytes=4096-", None]),
        # Range units are case-insensitive (RFC 9110).
        ("unit-case", [None, "bytes=4096-"]),
    ],
)
def test_a_partial_response_is_appended_only_where_the_part_ends(tmp_path, mode, ranges):
    registry = MisreadRangeRegistry(mode)
    dest = tmp_path / "blint.db"
    registry.download_layer_verified(DIGEST, len(BLOB), dest, "blint.db")
    assert dest.read_bytes() == BLOB
    assert registry.ranges == ranges


def test_rate_limiting_is_retried_after_the_delay_the_registry_asks(tmp_path, monkeypatch):
    delays = []
    monkeypatch.setattr(oci_pull.time, "sleep", delays.append)
    registry = FakeRegistry(statuses=[(429, {"Retry-After": "7"}), (429, {"Retry-After": "9999"})])
    dest = tmp_path / "blint.db"
    registry.download_layer_verified(DIGEST, len(BLOB), dest, "blint.db")
    assert dest.read_bytes() == BLOB
    assert delays == [7.0, oci_pull.RETRY_AFTER_CAP_SECONDS]


def test_manifest_fetch_is_retried(monkeypatch):
    manifest = {"layers": []}
    replies = [
        FakeResponse(503),
        FakeResponse(429, headers={"Retry-After": "1"}),
        requests.exceptions.ConnectionError("reset"),
    ]

    class Manifest(FakeResponse):
        def json(self):
            return manifest

    def request(self, method, path, **kwargs):
        reply = replies.pop(0) if replies else Manifest(200)
        if isinstance(reply, Exception):
            raise reply
        return reply

    monkeypatch.setattr(RegistryPullClient, "request", request)
    client = RegistryPullClient("ghcr.io", "appthreat/blintdb-test")
    assert client.get_manifest("v1") == manifest
    assert replies == []


def test_digest_mismatch_never_lands_and_drops_the_part(tmp_path):
    registry = FakeRegistry()
    wrong = f"sha256:{'0' * 64}"
    dest = tmp_path / "blint.db"
    with pytest.raises(PullFailedError, match="Digest mismatch"):
        registry.download_layer_verified(wrong, len(BLOB), dest, "blint.db")
    assert not dest.exists()
    assert _part_files(tmp_path) == []


def test_missing_blob_fails_without_retrying(tmp_path):
    registry = FakeRegistry(statuses=[404])
    with pytest.raises(PullFailedError, match="404"):
        registry.download_layer_verified(DIGEST, len(BLOB), tmp_path / "blint.db", "blint.db")
    assert registry.ranges == [None]


def test_server_errors_are_retried(tmp_path):
    registry = FakeRegistry(statuses=[503, 502])
    dest = tmp_path / "blint.db"
    registry.download_layer_verified(DIGEST, len(BLOB), dest, "blint.db")
    assert dest.read_bytes() == BLOB
    assert len(registry.ranges) == 3
