# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT
"""blint.db.get() open-path behaviour (F2a.1).

A blintdb that cannot be opened must degrade the run to no-blintdb with a
warning, never crash the SBOM (ground rule: a false positive is a defect of
the same severity as a crash — and so is a crash). The macOS reproducer from
D0 is BLINTDB_HOME=/tmp/...: SQLITE_OPEN_NOFOLLOW refuses any symlinked path
component, and /tmp is one. The fix resolves the path with realpath first and
keeps NOFOLLOW on the resolved path.
"""

import os
import shutil
from pathlib import Path

import pytest

from blint import db as db_module
from blint.db import detect_binaries_utilized, get, is_supported_blintdb
from tests.test_sbom_blintdb import _create_v2_blintdb


@pytest.fixture()
def real_v2_db(tmp_path: Path) -> Path:
    db_file = tmp_path / "real-home" / "blint.db"
    db_file.parent.mkdir()
    _create_v2_blintdb(str(db_file))
    return db_file


def test_get_opens_through_symlinked_directory_component(real_v2_db: Path, tmp_path: Path):
    """The D0 reproducer shape: a symlinked BLINTDB_HOME component opens."""
    linked_home = tmp_path / "linked-home"
    os.symlink(real_v2_db.parent, linked_home)
    connection = get(str(linked_home / "blint.db"))
    assert connection is not None
    try:
        rows = connection.execute("SELECT key FROM SchemaMeta").fetchall()
        assert {row[0] for row in rows} == {"schema_family", "schema_version"}
    finally:
        connection.close()
    # The whole lookup path degrades cleanly through the same symlinked home
    # rather than raising apsw.CantOpenError out of the SBOM run.
    detected, evidence = detect_binaries_utilized(
        symbol_source_map={"symtab_symbols": ["demo_symbol"]},
        db_file=str(linked_home / "blint.db"),
    )
    assert detected == set()
    assert evidence == {}


def test_get_degrades_on_unreadable_database(real_v2_db: Path, tmp_path: Path, caplog):
    """An unreadable database logs a warning and returns None, never raises."""
    unreadable = tmp_path / "unreadable-home" / "blint.db"
    unreadable.parent.mkdir()
    shutil.copy(real_v2_db, unreadable)
    os.chmod(unreadable, 0)
    try:
        with caplog.at_level("WARNING", logger="blint.logger"):
            connection = get(str(unreadable))
        assert connection is None
        assert "continuing without blintdb" in caplog.text
        assert is_supported_blintdb(str(unreadable)) is False
    finally:
        # restore permissions so pytest's tmp_path cleanup can unlink the file
        os.chmod(unreadable, 0o644)


def test_get_refuses_a_symlinked_database_file(real_v2_db: Path, tmp_path: Path, caplog):
    """Only directory components are resolved; a database file that is
    itself a symlink is still refused by NOFOLLOW, and the run degrades."""
    link_home = tmp_path / "file-link-home"
    link_home.mkdir()
    os.symlink(real_v2_db, link_home / "blint.db")
    with caplog.at_level("WARNING", logger="blint.logger"):
        connection = get(str(link_home / "blint.db"))
    assert connection is None
    assert "continuing without blintdb" in caplog.text


def test_get_returns_none_for_missing_database(tmp_path: Path):
    assert get(str(tmp_path / "absent-home" / "blint.db")) is None


def test_symlinked_home_end_to_end_sbom_degrades(real_v2_db: Path, tmp_path: Path):
    """detect_binaries_utilized over a /tmp-shaped home never raises.

    Uses a home whose path contains an actual symlinked component (tmp_path
    on macOS is already under /var -> /private/var; the explicit symlink
    makes the shape hold on any host).
    """
    linked_home = tmp_path / "e2e-linked-home"
    os.symlink(real_v2_db.parent, linked_home)
    db_module._blintdb_capability_cache.clear()
    detected, evidence = detect_binaries_utilized(
        symbol_source_map={"symtab_symbols": ["demo_symbol"]},
        binary_metadata={"binary_type": "MachO", "name": "demo"},
        db_file=str(linked_home / "blint.db"),
    )
    assert detected == set()
    assert evidence == {}
