import orjson
from pathlib import Path

from blint.lib.analysis import ReviewRunner, run_checks


def test_gobinary():
    test_go_file = Path(__file__).parent / "data" / "ngrok-elf.json"
    with open(test_go_file) as fp:
        file_content = fp.read()
    metadata = orjson.loads(file_content)
    results = run_checks(test_go_file.name, metadata)
    assert results
    assert results[0]["id"] == "CHECK_PIE"
    reviewer = ReviewRunner()
    reviewer.run_review(metadata)
    results = reviewer.process_review(test_go_file, test_go_file.name)
    assert results


def test_genericbinary():
    test_gnu_file = Path(__file__).parent / "data" / "netstat-elf.json"
    with open(test_gnu_file) as fp:
        file_content = fp.read()
    metadata = orjson.loads(file_content)
    results = run_checks(test_gnu_file.name, metadata)
    assert not results
    reviewer = ReviewRunner()
    reviewer.run_review(metadata)
    results = reviewer.process_review('data/netstat-elf.json', test_gnu_file.name)
    assert not results
