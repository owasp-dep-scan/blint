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
