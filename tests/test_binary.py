import os

from blint.binary import parse


def test_parse():
    if os.path.exists("/bin/ls"):
        metadata = parse("/bin/ls")
        assert metadata
