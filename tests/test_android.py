from pathlib import Path

from blint.android import parse_apk_summary


def test_parse_summary():
    test_summary_file = Path(__file__).parent / "data" / "apk-summary.txt"
    with open(test_summary_file) as fp:
        comp = parse_apk_summary(fp.read())
        assert comp
