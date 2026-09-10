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
