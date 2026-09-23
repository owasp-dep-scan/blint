from pathlib import Path

from blint.cli import build_parser


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
