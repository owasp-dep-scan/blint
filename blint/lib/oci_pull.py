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
- layers stream to a ``.part`` sibling in 8 MiB chunks, hashing as they
  land; the layer digest from the manifest is verified before the file
  is atomically renamed into place
- a dropped connection resumes with an HTTP ``Range`` request instead of
  starting a multi-GB layer again, and a ``.part`` an interrupted run left
  behind for the same digest is re-hashed and resumed by the next run
- periodic progress logs, because a multi-GB download is otherwise
  silent long enough to look hung
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import time
from pathlib import Path

import requests

CHUNK_SIZE = 8 * 1024 * 1024
PROGRESS_LOG_INTERVAL = 1024 * 1024 * 1024
# Resumes allowed per layer before giving up. Each resume asks only for the
# bytes not yet written, so the budget bounds retries, not bytes.
MAX_RESUME_ATTEMPTS = 8
RESUME_BACKOFF_SECONDS = 2.0
RESUME_BACKOFF_CAP_SECONDS = 60.0
# Connection-level failures a Range request can recover from. An HTTP error
# status is handled separately: 5xx is retried, anything else is final.
RESUMABLE_ERRORS = (
    requests.exceptions.ChunkedEncodingError,
    requests.exceptions.ConnectionError,
    requests.exceptions.Timeout,
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
        response = self.request(
            "GET",
            f"/v2/{self.repository}/manifests/{reference}",
            headers={"Accept": MANIFEST_ACCEPT_TYPES},
        )
        if response.status_code != 200:
            raise PullFailedError(
                f"Manifest fetch failed ({response.status_code}): {response.text[:200]}"
            )
        manifest = response.json()
        if "layers" not in manifest:
            raise PullFailedError("Reference resolved to a non-image manifest")
        return manifest

    def download_layer_verified(
        self, digest: str, size: int, dest: Path, label: str
    ) -> None:
        """Stream one blob to dest, verifying its digest before renaming.

        The bytes land in a ``.part`` file named after the digest. A dropped
        connection resumes from the bytes already written with a ``Range``
        request; a registry or CDN that ignores the range restarts the layer
        from zero rather than appending a second copy. The hash covers every
        byte of the final file, resumed or not, so the digest check is the
        same either way. When the resume budget runs out the ``.part`` is
        kept for the next run and the pull fails; a digest or size mismatch
        deletes it.
        """
        part_file = dest.with_name(f".{dest.name}.{digest.rsplit(':', 1)[-1][:16]}.part")
        hasher = hashlib.sha256()
        written = 0
        if part_file.exists():
            written = _rehash_part(part_file, hasher, size)
            if written:
                print(
                    f"{label}: resuming from {written / (1024 ** 3):.1f} GiB left by an "
                    "interrupted pull",
                    flush=True,
                )
            else:
                hasher = hashlib.sha256()
        next_mark = (written // PROGRESS_LOG_INTERVAL + 1) * PROGRESS_LOG_INTERVAL
        started = time.monotonic()
        attempts = 0
        while size is None or written < size:
            headers = {"Range": f"bytes={written}-"} if written else {}
            try:
                response = self.request(
                    "GET",
                    f"/v2/{self.repository}/blobs/{digest}",
                    stream=True,
                    headers=headers,
                )
                try:
                    if written and response.status_code == 416:
                        # Nothing past what is already on disk: the digest
                        # check below decides whether that is the whole blob.
                        break
                    if response.status_code >= 500:
                        raise requests.exceptions.ConnectionError(
                            f"registry returned {response.status_code}"
                        )
                    if response.status_code not in (200, 206):
                        raise PullFailedError(
                            f"Blob fetch for {label} failed ({response.status_code})"
                        )
                    if written and not _resumes_at(response, written):
                        # The server ignored or misread the range: start over.
                        written = 0
                        hasher = hashlib.sha256()
                        next_mark = PROGRESS_LOG_INTERVAL
                    with open(part_file, "ab" if written else "wb") as handle:
                        for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
                            if not chunk:
                                continue
                            handle.write(chunk)
                            hasher.update(chunk)
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
                delay = min(
                    RESUME_BACKOFF_SECONDS * (2 ** (attempts - 1)), RESUME_BACKOFF_CAP_SECONDS
                )
                print(
                    f"{label}: connection dropped at {written} bytes ({exc}); "
                    f"resuming in {delay:.0f}s (attempt {attempts} of {MAX_RESUME_ATTEMPTS})",
                    flush=True,
                )
                time.sleep(delay)
        actual = f"sha256:{hasher.hexdigest()}"
        if actual != digest or (size is not None and written != size):
            part_file.unlink(missing_ok=True)
            if actual != digest:
                raise PullFailedError(
                    f"Digest mismatch for {label}: manifest says {digest}, got {actual}"
                )
            raise PullFailedError(
                f"Size mismatch for {label}: manifest says {size}, wrote {written}"
            )
        os.replace(part_file, dest)
        elapsed = max(time.monotonic() - started, 1)
        print(
            f"{label}: downloaded and verified {written / (1024 ** 2):.0f} MiB in "
            f"{elapsed / 60:.1f} min ({written / elapsed / (1024 ** 2):.0f} MiB/s)",
            flush=True,
        )


def _resumes_at(response: requests.Response, offset: int) -> bool:
    """Whether a ranged response really starts at ``offset``."""
    if response.status_code != 206:
        return False
    content_range = response.headers.get("Content-Range", "")
    unit, _, spec = content_range.partition(" ")
    first = spec.split("-", 1)[0]
    return unit == "bytes" and first.isdigit() and int(first) == offset


def _rehash_part(part_file: Path, hasher, size: int | None) -> int:
    """Feed an earlier run's partial layer into ``hasher``; return its length.

    A part longer than the layer cannot be a prefix of it and is discarded.
    """
    length = part_file.stat().st_size
    if size is not None and length > size:
        part_file.unlink(missing_ok=True)
        return 0
    with open(part_file, "rb") as handle:
        while chunk := handle.read(CHUNK_SIZE):
            hasher.update(chunk)
    return length


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
