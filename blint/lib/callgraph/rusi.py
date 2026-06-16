# -*- coding: utf-8 -*-
"""
Run the rusi source analyzer to produce a source callgraph.

rusi is an external Rust source analysis tool. Its location and invocation vary
between environments, so the base command is supplied by the caller, either as a
CLI argument or through the ``RUSI_CMD`` (or ``BLINT_RUSI_CMD``) environment
variable. Examples of a base command are ``cargo run -p rusi-cli --`` when run
from a rusi checkout, or the path to a prebuilt ``rusi`` binary.

This lets ``blint callgraph-match`` accept a source directory directly and
analyze it for the user, instead of requiring a precomputed callgraph JSON.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
from pathlib import Path
from typing import Optional, Union

from blint.logger import LOG

# Maximum seconds to allow a rusi analysis to run before giving up.
_DEFAULT_RUSI_TIMEOUT = int(os.getenv("BLINT_RUSI_TIMEOUT", "1800"))


def resolve_rusi_command(explicit_command: Optional[str] = None) -> list[str]:
    """Return the rusi base command as an argument list, or an empty list.

    The explicit command takes precedence over the ``RUSI_CMD`` and
    ``BLINT_RUSI_CMD`` environment variables. An empty list means rusi is not
    configured.
    """
    raw = explicit_command or os.getenv("RUSI_CMD") or os.getenv("BLINT_RUSI_CMD") or ""
    if not raw.strip():
        return []
    return shlex.split(raw)


def run_rusi_callgraph(
    source_dir: Union[str, Path],
    *,
    rusi_command: Optional[str] = None,
    work_dir: Optional[Union[str, Path]] = None,
    timeout: int = _DEFAULT_RUSI_TIMEOUT,
) -> dict:
    """Run rusi over a source tree and return the parsed callgraph as a dict.

    Args:
        source_dir: Path to the crate or workspace source to analyze.
        rusi_command: Base rusi command. Falls back to the environment.
        work_dir: Directory for the temporary callgraph output. Defaults to
            ``source_dir``.
        timeout: Maximum seconds to allow the analysis to run.

    Returns:
        The parsed callgraph JSON as a dict.

    Raises:
        ValueError: If no rusi command is configured.
        FileNotFoundError: If ``source_dir`` does not exist.
        RuntimeError: If rusi fails, times out, or produces no output.
    """
    base_command = resolve_rusi_command(rusi_command)
    if not base_command:
        raise ValueError(
            "No rusi command configured. Pass --rusi-cmd or set the RUSI_CMD "
            "environment variable (for example 'cargo run -p rusi-cli --' or a "
            "path to a rusi binary)."
        )
    source_path = Path(source_dir)
    if not source_path.exists():
        raise FileNotFoundError(f"Source directory does not exist: {source_path}")

    out_dir = Path(work_dir) if work_dir else source_path
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "rusi-callgraph.json"
    command = [
        *base_command,
        "analyze",
        "--dir",
        str(source_path),
        "--callgraph",
        "static",
        "--out",
        str(out_path),
    ]
    LOG.info("Running rusi to analyze %s", source_path)
    LOG.debug("rusi command: %s", " ".join(command))
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            check=False,
            encoding="utf-8",
            timeout=timeout,
        )
    except (FileNotFoundError, OSError) as exc:
        raise RuntimeError(f"rusi could not be executed ({base_command[0]}): {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"rusi timed out after {timeout}s on {source_path}") from exc

    if result.returncode != 0:
        raise RuntimeError(
            f"rusi exited with status {result.returncode} on {source_path}. "
            f"{(result.stderr or '').strip()[:500]}"
        )
    if not out_path.exists():
        raise RuntimeError(f"rusi produced no callgraph output for {source_path}")
    return json.loads(out_path.read_text(encoding="utf-8"))
