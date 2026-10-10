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
        """Stream one blob to dest, verifying its digest before renaming."""
        part_file = dest.with_name(f".{dest.name}.part")
        response = self.request(
            "GET", f"/v2/{self.repository}/blobs/{digest}", stream=True
        )
        if response.status_code != 200:
            raise PullFailedError(
                f"Blob fetch for {label} failed ({response.status_code})"
            )
        hasher = hashlib.sha256()
        written = 0
        next_mark = PROGRESS_LOG_INTERVAL
        started = time.monotonic()
        try:
            with open(part_file, "wb") as handle:
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
            actual = f"sha256:{hasher.hexdigest()}"
            if actual != digest:
                raise PullFailedError(
                    f"Digest mismatch for {label}: manifest says {digest}, got {actual}"
                )
            if size is not None and written != size:
                raise PullFailedError(
                    f"Size mismatch for {label}: manifest says {size}, wrote {written}"
                )
            os.replace(part_file, dest)
        finally:
            response.close()
            if part_file.exists():
                part_file.unlink(missing_ok=True)
        elapsed = max(time.monotonic() - started, 1)
        print(
            f"{label}: downloaded and verified {written / (1024 ** 2):.0f} MiB in "
            f"{elapsed / 60:.1f} min ({written / elapsed / (1024 ** 2):.0f} MiB/s)",
            flush=True,
        )


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
