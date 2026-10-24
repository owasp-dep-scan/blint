# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT
"""
Streaming OCI registry pull for blintdb artifacts.

The Python oras client streams downloads in 8 KiB chunks without
verifying anything, and an interrupted pull leaves a truncated blint.db
that later runs treat as present. This module pulls blintdb artifacts
with constant memory and end-to-end integrity instead:

- bearer auth negotiated from the registry's own challenge, using
  credentials from the docker config when the registry demands them
- layers stream to a ``.part`` sibling in 8 MiB chunks; the file's size
  and the layer digest from the manifest are verified on the file itself
  before it is atomically renamed into place
- a dropped connection resumes with an HTTP ``Range`` request instead of
  starting a multi-GB layer again, and a ``.part`` an interrupted run left
  behind for the same digest is resumed by the next run; a response that
  does not start where the ``.part`` ends restarts the layer
- one pull at a time per destination, under an exclusive lock, so two runs
  sharing ``BLINTDB_HOME`` never write the same ``.part``
- rate limiting (429) and server errors are retried, honouring
  ``Retry-After``, for manifests as well as blobs
- periodic progress logs, because a multi-GB download is otherwise
  silent long enough to look hung
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import re
import time
from collections.abc import Iterator
from pathlib import Path

import requests

CHUNK_SIZE = 8 * 1024 * 1024
PROGRESS_LOG_INTERVAL = 1024 * 1024 * 1024
# Resumes allowed per layer before giving up. Each resume asks only for the
# bytes not yet written, so the budget bounds retries, not bytes.
MAX_RESUME_ATTEMPTS = 8
RESUME_BACKOFF_SECONDS = 2.0
RESUME_BACKOFF_CAP_SECONDS = 60.0
# The longest Retry-After honoured; a registry asking for more gets retried
# at this interval until the attempts run out.
RETRY_AFTER_CAP_SECONDS = 300.0
# Statuses worth retrying: rate limiting and server errors.
RETRYABLE_STATUSES = frozenset({429, *range(500, 600)})


class RetryableStatusError(requests.exceptions.RequestException):
    """A registry answered with a status worth retrying (429 or 5xx)."""

    def __init__(self, status_code: int, retry_after: float | None = None):
        super().__init__(f"registry returned {status_code}")
        self.status_code = status_code
        self.retry_after = retry_after


# Failures a retry (with a Range request, for a blob) can recover from. Any
# other HTTP status is final.
RESUMABLE_ERRORS = (
    requests.exceptions.ChunkedEncodingError,
    requests.exceptions.ConnectionError,
    requests.exceptions.Timeout,
    RetryableStatusError,
)

MANIFEST_ACCEPT_TYPES = (
    "application/vnd.oci.image.manifest.v1+json, "
    "application/vnd.docker.distribution.manifest.v2+json, "
    "application/vnd.oci.image.index.v1+json, "
    "application/vnd.docker.distribution.manifest.list.v2+json"
)

_CHALLENGE_PATTERN = re.compile(
    r'Bearer realm="(?P<realm>[^"]+)"(?:,service="(?P<service>[^"]+)")?'
)


class PullFailedError(RuntimeError):
    """Raised when an artifact cannot be pulled intact."""


def _retry_after(response: requests.Response) -> float | None:
    """The Retry-After delay in seconds, when given as a number."""
    value = (response.headers or {}).get("Retry-After", "")
    try:
        return max(0.0, float(value))
    except (TypeError, ValueError):
        return None


def _raise_for_retryable(response: requests.Response) -> None:
    if response.status_code in RETRYABLE_STATUSES:
        retry_after = _retry_after(response)
        response.close()
        raise RetryableStatusError(response.status_code, retry_after)


def _backoff(attempt: int, exc: Exception) -> float:
    """Seconds to wait before retry ``attempt`` (1-based) after ``exc``."""
    retry_after = getattr(exc, "retry_after", None)
    if retry_after is not None:
        return min(retry_after, RETRY_AFTER_CAP_SECONDS)
    return min(RESUME_BACKOFF_SECONDS * (2 ** (attempt - 1)), RESUME_BACKOFF_CAP_SECONDS)


@contextlib.contextmanager
def _exclusive_lock(lock_file: Path, label: str) -> Iterator[None]:
    """Hold an exclusive lock on ``lock_file``, or fail at once.

    The lock is the operating system's, so it is released when the holder
    exits however it exits; the file itself stays, since removing it would
    let two runs lock two different files of one name.
    """
    handle = open(lock_file, "a+b")  # noqa: SIM115 - closed in finally
    try:
        try:
            if os.name == "nt":
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise PullFailedError(
                f"{label}: another pull is writing {lock_file.parent}; wait for it to "
                "finish, then run the pull again."
            ) from exc
        yield
    finally:
        with contextlib.suppress(OSError):
            if os.name == "nt":
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


def _docker_config_basic_auth(registry: str) -> tuple[str, str] | None:
    """Fetch basic-auth credentials for a registry from the docker config."""
    for config_path in (
        Path(os.environ.get("DOCKER_CONFIG") or Path.home() / ".docker")
        / "config.json",
    ):
        try:
            config = json.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        entry = (config.get("auths") or {}).get(registry) or {}
        token = entry.get("auth")
        if token:
            decoded = base64.b64decode(token).decode("utf-8", errors="replace")
            if ":" in decoded:
                username, password = decoded.split(":", 1)
                return username, password
    return None


class RegistryPullClient:
    """Minimal read-only OCI distribution client."""

    def __init__(self, registry: str, repository: str):
        self.registry = registry
        self.repository = repository
        self._token: str | None = None
        self._basic_auth: tuple[str, str] | None = None
        self._session = requests.Session()
        self._session.headers["User-Agent"] = "blint-oci-pull/1.0 (+https://github.com/owasp-dep-scan/blint)"
        # Blob GETs redirect to CDN hosts; requests only forwards
        # Authorization to the original host on redirects.
        self._session.max_redirects = 10

    def _api_url(self, path: str) -> str:
        return f"https://{self.registry}{path}"

    def _fetch_token(self, scope: str) -> None:
        probe = self._session.get(self._api_url("/v2/"), timeout=(15, 60))
        header = probe.headers.get("WWW-Authenticate", "")
        match = _CHALLENGE_PATTERN.search(header)
        if not match:
            if probe.status_code == 200:
                # Registry allows unauthenticated access; nothing to do.
                return
            raise PullFailedError(
                f"Registry did not offer a bearer challenge (status {probe.status_code})"
            )
        if self._basic_auth is None:
            self._basic_auth = _docker_config_basic_auth(self.registry)
        params = {"scope": scope}
        if service := match.group("service"):
            params["service"] = service
        response = self._session.get(
            match.group("realm"),
            params=params,
            auth=self._basic_auth,
            timeout=(15, 60),
        )
        response.raise_for_status()
        payload = response.json()
        self._token = payload.get("token") or payload.get("access_token")

    def request(self, method: str, path: str, **kwargs) -> requests.Response:
        headers = dict(kwargs.pop("headers", None) or {})
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        response = self._session.request(
            method, self._api_url(path), headers=headers, timeout=(15, 300), **kwargs
        )
        if response.status_code == 401:
            # No token yet, or a stale one: (re)negotiate and retry once.
            self._fetch_token(f"repository:{self.repository}:pull")
            if self._token:
                headers["Authorization"] = f"Bearer {self._token}"
                response = self._session.request(
                    method,
                    self._api_url(path),
                    headers=headers,
                    timeout=(15, 300),
                    **kwargs,
                )
        return response

    def get_manifest(self, reference: str) -> dict:
        attempts = 0
        while True:
            try:
                response = self.request(
                    "GET",
                    f"/v2/{self.repository}/manifests/{reference}",
                    headers={"Accept": MANIFEST_ACCEPT_TYPES},
                )
                _raise_for_retryable(response)
                break
            except RESUMABLE_ERRORS as exc:
                attempts += 1
                if attempts > MAX_RESUME_ATTEMPTS:
                    raise PullFailedError(
                        f"Manifest fetch failed after {MAX_RESUME_ATTEMPTS} retries: {exc}"
                    ) from exc
                delay = _backoff(attempts, exc)
                print(
                    f"manifest {reference}: {exc}; retrying in {delay:.0f}s "
                    f"(attempt {attempts} of {MAX_RESUME_ATTEMPTS})",
                    flush=True,
                )
                time.sleep(delay)
        if response.status_code != 200:
            raise PullFailedError(
                f"Manifest fetch failed ({response.status_code}): {response.text[:200]}"
            )
        manifest = response.json()
        if "layers" not in manifest:
            raise PullFailedError("Reference resolved to a non-image manifest")
        return manifest

    def _blob_response(
        self, digest: str, offset: int, label: str
    ) -> tuple[requests.Response | None, int]:
        """A streaming response for the blob and the offset its body starts at.

        Asks for the bytes from ``offset`` when there are some already. A
        registry that ignores the range answers 200 with the whole blob, so
        the body starts at 0. A 206 that does not start at ``offset`` (a proxy
        that rounds the start, or drops Content-Range) cannot be appended to
        the part, so the whole blob is asked for instead. Returns
        ``(None, offset)`` when the registry says nothing is left (416).
        """
        path = f"/v2/{self.repository}/blobs/{digest}"
        headers = {"Range": f"bytes={offset}-"} if offset else {}
        response = self.request("GET", path, stream=True, headers=headers)
        if offset and response.status_code == 416:
            response.close()
            return None, offset
        _raise_for_retryable(response)
        if response.status_code == 200:
            return response, 0
        if offset and response.status_code == 206:
            if _resumes_at(response, offset):
                return response, offset
            response.close()
            response = self.request("GET", path, stream=True)
            _raise_for_retryable(response)
            if response.status_code == 200:
                return response, 0
        status = response.status_code
        response.close()
        raise PullFailedError(f"Blob fetch for {label} failed ({status})")

    def download_layer_verified(
        self, digest: str, size: int, dest: Path, label: str
    ) -> None:
        """Stream one blob to dest, verifying its digest before renaming.

        The bytes land in a ``.part`` file named after the digest, written by
        one pull at a time under a lock beside the destination; parts of
        other digests are removed. A dropped connection resumes from the
        bytes already written with a ``Range`` request; a response that does
        not continue the part restarts the layer from zero rather than
        appending to it. The size and the digest are checked on the finished
        file itself, so resumed bytes are verified the same way as fresh
        ones. When the retry budget runs out the ``.part`` is kept for the
        next run and the pull fails; a digest or size mismatch deletes it.
        """
        part_file = dest.with_name(f".{dest.name}.{digest.rsplit(':', 1)[-1][:16]}.part")
        with _exclusive_lock(dest.with_name(f".{dest.name}.lock"), label):
            for stale in dest.parent.glob(f".{dest.name}.*.part"):
                if stale != part_file:
                    stale.unlink(missing_ok=True)
            written = _resumable_length(part_file, size)
            if written:
                print(
                    f"{label}: resuming from {written / (1024 ** 3):.1f} GiB left by an "
                    "interrupted pull",
                    flush=True,
                )
            started = time.monotonic()
            self._fetch_into(digest, size, part_file, written, label)
            _verify_part(part_file, digest, size, label)
            os.replace(part_file, dest)
        total = dest.stat().st_size
        elapsed = max(time.monotonic() - started, 1)
        print(
            f"{label}: downloaded and verified {total / (1024 ** 2):.0f} MiB in "
            f"{elapsed / 60:.1f} min ({total / elapsed / (1024 ** 2):.0f} MiB/s)",
            flush=True,
        )

    def _fetch_into(
        self, digest: str, size: int | None, part_file: Path, written: int, label: str
    ) -> None:
        """Write the blob into ``part_file`` from ``written`` on, retrying."""
        next_mark = (written // PROGRESS_LOG_INTERVAL + 1) * PROGRESS_LOG_INTERVAL
        attempts = 0
        while size is None or written < size:
            try:
                response, start = self._blob_response(digest, written, label)
                if response is None:
                    # Nothing past what is already on disk: the checks on the
                    # file decide whether that is the whole blob.
                    break
                try:
                    if start != written:
                        written = start
                        next_mark = PROGRESS_LOG_INTERVAL
                    with open(part_file, "ab" if written else "wb") as handle:
                        for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
                            if not chunk:
                                continue
                            handle.write(chunk)
                            written += len(chunk)
                            if written >= next_mark:
                                print(
                                    f"downloaded {written / (1024 ** 3):.1f} GiB of {label}",
                                    flush=True,
                                )
                                while next_mark <= written:
                                    next_mark += PROGRESS_LOG_INTERVAL
                finally:
                    response.close()
                if size is None:
                    break
                if written < size:
                    # The body ended early without a connection error.
                    raise requests.exceptions.ChunkedEncodingError(
                        f"stream ended at {written} of {size} bytes"
                    )
            except RESUMABLE_ERRORS as exc:
                attempts += 1
                if attempts > MAX_RESUME_ATTEMPTS:
                    raise PullFailedError(
                        f"{label}: gave up after {MAX_RESUME_ATTEMPTS} resumed attempts "
                        f"({written} of {size} bytes; {exc}). The partial download is "
                        f"kept at {part_file} and the next pull resumes from it."
                    ) from exc
                delay = _backoff(attempts, exc)
                print(
                    f"{label}: {exc} at {written} bytes; resuming in {delay:.0f}s "
                    f"(attempt {attempts} of {MAX_RESUME_ATTEMPTS})",
                    flush=True,
                )
                time.sleep(delay)


def _resumes_at(response: requests.Response, offset: int) -> bool:
    """Whether a ranged response really starts at ``offset``.

    Range units are case-insensitive (RFC 9110 section 14.1).
    """
    if response.status_code != 206:
        return False
    content_range = (response.headers or {}).get("Content-Range", "")
    unit, _, spec = content_range.strip().partition(" ")
    first = spec.strip().split("-", 1)[0]
    return unit.lower() == "bytes" and first.isdigit() and int(first) == offset


def _resumable_length(part_file: Path, size: int | None) -> int:
    """How much of an earlier run's partial layer can be resumed.

    A part longer than the layer cannot be a prefix of it and is discarded.
    """
    try:
        length = part_file.stat().st_size
    except FileNotFoundError:
        return 0
    if size is not None and length > size:
        part_file.unlink(missing_ok=True)
        return 0
    return length


def _verify_part(part_file: Path, digest: str, size: int | None, label: str) -> None:
    """Check the finished part's size and digest on the file itself."""
    try:
        actual_size = part_file.stat().st_size
    except FileNotFoundError as exc:
        raise PullFailedError(f"{label}: the download left no file to verify") from exc
    if size is not None and actual_size != size:
        part_file.unlink(missing_ok=True)
        raise PullFailedError(
            f"Size mismatch for {label}: manifest says {size}, wrote {actual_size}"
        )
    hasher = hashlib.sha256()
    with open(part_file, "rb") as handle:
        while chunk := handle.read(CHUNK_SIZE):
            hasher.update(chunk)
    actual = f"sha256:{hasher.hexdigest()}"
    if actual != digest:
        part_file.unlink(missing_ok=True)
        raise PullFailedError(f"Digest mismatch for {label}: manifest says {digest}, got {actual}")


def stream_pull(target: str, outdir: str) -> list[Path]:
    """
    Pull every layer of ``target`` (``registry/repo[:tag|@digest]``) into
    ``outdir``, named by each layer's title annotation and verified against
    the manifest digests. Returns the written paths.
    """
    if "@" in target:
        registry_repo, reference = target.rsplit("@", 1)
    elif ":" in target.rsplit("/", 1)[-1]:
        registry_repo, reference = target.rsplit(":", 1)
    else:
        reference = "latest"
        registry_repo = target
    registry, repository = registry_repo.split("/", 1)

    client = RegistryPullClient(registry, repository)
    manifest = client.get_manifest(reference)

    written: list[Path] = []
    outdir_path = Path(outdir)
    outdir_path.mkdir(parents=True, exist_ok=True)
    for layer in manifest.get("layers", []):
        title = (layer.get("annotations") or {}).get("org.opencontainers.image.title")
        if not title:
            # blintdb images always title their layers; an untitled layer
            # has no defined filename to land at.
            continue
        # Defense in depth against a hostile manifest writing outside outdir.
        dest = (outdir_path / title).resolve()
        if outdir_path.resolve() not in dest.parents:
            raise PullFailedError(f"Layer title escapes output directory: {title!r}")
        client.download_layer_verified(
            layer["digest"], layer.get("size"), dest, title
        )
        written.append(dest)
    if not written:
        raise PullFailedError(f"No titled layers in {target}")
    return written
