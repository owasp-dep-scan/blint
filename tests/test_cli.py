from pathlib import Path

import pytest

from blint.cli import build_parser, handle_args


def test_export_callgraph_mermaid_flag_sets_option():
    parser = build_parser()
    args = parser.parse_args(["--export-callgraph-mermaid"])
    assert args.render_mermaid_callgraph is True


def test_callgraph_min_confidence_flag_sets_option():
    parser = build_parser()
    args = parser.parse_args(["--callgraph-min-confidence", "high"])
    assert args.callgraph_min_confidence == "high"


def test_help_shows_primary_mermaid_export_flag_only():
    parser = build_parser()
    help_text = parser.format_help()
    assert "--export-callgraph-mermaid" in help_text
    assert "--callgraph-min-confidence" in help_text


def test_diff_subcommand_parses_positional_inputs_and_flags():
    parser = build_parser()
    args = parser.parse_args(["diff", "old.bin", "new.bin"])
    assert args.old_input == "old.bin"
    assert args.new_input == "new.bin"
    assert args.diff_json is False
    assert args.diff_disassemble is False
    assert args.diff_no_reviews is False


def test_diff_subcommand_json_flag():
    parser = build_parser()
    args = parser.parse_args(["diff", "old.bin", "new.bin", "--json", "--disassemble"])
    assert args.diff_json is True
    assert args.diff_disassemble is True


def test_diff_subcommand_in_help():
    parser = build_parser()
    assert "diff" in parser.format_help()


def test_banner_survives_legacy_codepage_console(tmp_path):
    """The startup banner must not crash a legacy-codepage stdout (#80).

    A Windows console with cp1252/IBM437 cannot encode the block-art logo,
    and blint crashed at ``print(BLINT_LOGO)`` before scanning anything -
    found by the #80 stress run against a real System32. Reproduced here
    portably by forcing ``PYTHONIOENCODING=cp1252`` on any platform: the
    scan must complete (exit 0) with the plain-text fallback banner.
    """
    import os
    import subprocess
    import sys

    env = dict(os.environ, PYTHONIOENCODING="cp1252", BLINT_CACHE_DIR=str(tmp_path / "cache"))
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "blint.cli",
            "-q",
            "--no-reviews",
            "-i",
            str(Path(__file__).resolve().parent / "data" / "complex_flow.wasm"),
            "-o",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 0, result.stderr[-400:]


def test_glibc_baseline_flag_sets_the_env_var(monkeypatch, tmp_path):
    """--glibc-baseline is the CLI spelling of BLINT_GLIBC_BASELINE."""
    monkeypatch.delenv("BLINT_GLIBC_BASELINE", raising=False)
    args = build_parser().parse_args(
        ["--no-banner", "--glibc-baseline", "2.17", "-i", str(tmp_path)]
    )
    handle_args(args)
    import os

    assert os.environ["BLINT_GLIBC_BASELINE"] == "2.17"
    monkeypatch.delenv("BLINT_GLIBC_BASELINE", raising=False)


def test_glibc_baseline_flag_rejects_malformed_versions():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--glibc-baseline", "two-point-two-eight"])


def _point_blintdb_at(monkeypatch, tmp_path):
    from blint.lib import utils
    from blint.logger import LOG

    # main() -q disables the shared logger for the rest of the process;
    # restore it so later caplog-based tests still see records.
    monkeypatch.setattr(LOG, "disabled", LOG.disabled)
    home = tmp_path / "blintdb"
    monkeypatch.setattr(utils, "BLINTDB_HOME", str(home))
    monkeypatch.setattr(utils, "BLINTDB_LOC", str(home / "blint.db"))
    return home


def test_db_download_failure_exits_non_zero(monkeypatch, tmp_path):
    """4.0.1 logged "Blintdb Download failed" and exited 0."""
    import sys

    from blint import cli
    from blint.lib import oci_pull

    _point_blintdb_at(monkeypatch, tmp_path)

    def failing_pull(target, outdir):
        raise oci_pull.PullFailedError("Manifest fetch failed (404)")

    monkeypatch.setattr(oci_pull, "stream_pull", failing_pull)
    monkeypatch.setattr(sys, "argv", ["blint", "--no-banner", "-q", "db", "--download"])
    with pytest.raises(SystemExit) as excinfo:
        cli.main()
    assert excinfo.value.code == 1


def test_db_download_success_exits_zero(monkeypatch, tmp_path):
    import sys

    from blint import cli
    from blint.lib import oci_pull

    home = _point_blintdb_at(monkeypatch, tmp_path)

    def pull(target, outdir):
        home.mkdir(parents=True, exist_ok=True)
        (home / "blint.db").write_bytes(b"")
        return [home / "blint.db"]

    monkeypatch.setattr(oci_pull, "stream_pull", pull)
    monkeypatch.setattr(sys, "argv", ["blint", "--no-banner", "-q", "db", "--download"])
    assert cli.main() is None


def test_truncated_blintdb_is_downloaded_again(monkeypatch, tmp_path):
    import sqlite3

    from blint.config import BlintOptions
    from blint.lib import oci_pull, utils

    home = _point_blintdb_at(monkeypatch, tmp_path)
    home.mkdir()
    db_file = home / "blint.db"
    with sqlite3.connect(db_file) as connection:
        connection.execute("create table t (x blob)")
        connection.executemany("insert into t values (?)", [(b"x" * 4096,)] * 8)
    db_file.write_bytes(db_file.read_bytes()[:-4096])
    pulled = []

    def pull(target, outdir):
        pulled.append(target)
        return [db_file]

    monkeypatch.setattr(oci_pull, "stream_pull", pull)
    assert utils.blintdb_setup(BlintOptions(use_blintdb=True))
    assert len(pulled) == 1


def test_sbom_mode_exits_non_zero_for_a_missing_input(tmp_path, caplog):
    """An image reference or a mistyped path used to write nothing and exit 0."""
    from blint.config import BlintOptions
    from blint.lib.runners import run_sbom_mode

    options = BlintOptions(
        sbom_mode=True,
        src_dir_image=["node:24.22.0-bookworm-slim"],
        sbom_output=str(tmp_path / "bom.json"),
    )
    with caplog.at_level("ERROR"), pytest.raises(SystemExit) as excinfo:
        run_sbom_mode(options)
    assert excinfo.value.code == 1
    assert "does not pull container images" in caplog.text


def test_missing_input_with_no_error_continues(tmp_path):
    from blint.config import BlintOptions
    from blint.lib.runners import run_sbom_mode

    options = BlintOptions(
        sbom_mode=True,
        no_error=True,
        quiet_mode=True,
        src_dir_image=[str(tmp_path / "missing")],
        sbom_output=str(tmp_path / "bom.json"),
    )
    # Logged, not fatal: the run carries on and simply has nothing to scan.
    assert run_sbom_mode(options) is False


def test_tar_archive_input_warns(tmp_path, caplog):
    import tarfile

    from blint.config import BlintOptions
    from blint.lib.runners import check_inputs

    archive = tmp_path / "image.tar"
    with tarfile.open(archive, "w") as handle:
        member = tmp_path / "manifest.json"
        member.write_text("[]")
        handle.add(member, arcname="manifest.json")
    with caplog.at_level("WARNING"):
        check_inputs(BlintOptions(src_dir_image=[str(archive)]))
    assert "tar archive" in caplog.text
