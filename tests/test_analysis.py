import json
from pathlib import Path

from blint.analysis import run_checks, run_review


def test_gobinary():
    test_go_file = Path(__file__).parent / "data" / "ngrok-elf.json"
    with open(test_go_file) as fp:
        metadata = json.load(fp)
        results = run_checks(test_go_file.name, metadata)
        assert results
        assert results[0]["id"] == "CHECK_PIE"
        results = run_review(test_go_file.name, metadata)
        assert results


def test_genericbinary():
    test_gnu_file = Path(__file__).parent / "data" / "netstat-elf.json"
    with open(test_gnu_file) as fp:
        metadata = json.load(fp)
        results = run_checks(test_gnu_file.name, metadata)
        assert not results
        results = run_review(test_gnu_file.name, metadata)
        assert not results
