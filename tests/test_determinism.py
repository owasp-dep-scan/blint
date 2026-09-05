"""Determinism gate (P0.3): two runs over the same input must agree byte for byte.

Two shipped v4 features derive output from set iteration and dict merges
(discovery ordering, CFG hashes), which is exactly the input this test exists
to pin. It checks agreement at two levels:

- in-process: ``parse()`` run twice against the same file must produce the
  same metadata, catching dependence on process state;
- cross-process: two subprocess parses with *different* ``PYTHONHASHSEED``
  values must produce identical bytes. Set iteration order varies with the
  hash seed, so this is the only level that can catch a stray ``for x in
  some_set`` leaking into output order.

Both levels compare raw insertion-ordered ``orjson`` bytes (the export
format a cache or diff consumer sees) and canonical sorted-key JSON (the
content). Metadata fields that legitimately vary between runs would have to
be listed in ``VARIABLE_FIELDS`` with a justification; the list is empty
because ``parse()`` derives every field from the input file's bytes and
never emits timestamps, and both runs use the same input path.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import orjson
import pytest

from blint.lib.binary import parse

REPO_ROOT = Path(__file__).resolve().parents[1]

# Fields of the metadata that may legitimately differ between two runs over
# the same input. Deliberately empty: parse() output is a pure function of
# the input bytes plus the input path, and both runs see the same path. If a
# future feature adds a genuinely variable field (a timestamp, an environment
# probe), add its top-level key here with a comment saying why it varies —
# and a test proving the two runs really do differ on exactly that field.
VARIABLE_FIELDS: list[str] = []

_DEMO_C = """\
#include <string.h>
static int helper(int x) { return x * 3 + 1; }
static int accumulate(int n) {
    int acc = 0;
    for (int i = 0; i < n; i++) {
        acc += helper(i);
    }
    return acc;
}
const char *wave0_label(void) { return "wave0-determinism-demo"; }
int main(void) { return accumulate(7) + (int)strlen(wave0_label()); }
"""


def _first_diff_path(first, second, path="$"):
    """Locate the first differing position in two JSON-like structures."""
    if type(first) is not type(second):
        return f"{path}: {type(first).__name__} vs {type(second).__name__}"
    if isinstance(first, dict):
        for key in sorted(set(first) | set(second)):
            if key not in first:
                return f"{path}.{key}: missing from first run"
            if key not in second:
                return f"{path}.{key}: missing from second run"
            deeper = _first_diff_path(first[key], second[key], f"{path}.{key}")
            if deeper:
                return deeper
        return ""
    if isinstance(first, list):
        if len(first) != len(second):
            return f"{path}: list length {len(first)} vs {len(second)}"
        for index, (a, b) in enumerate(zip(first, second)):
            deeper = _first_diff_path(a, b, f"{path}[{index}]")
            if deeper:
                return deeper
        return ""
    if first != second:
        return f"{path}: {first!r} vs {second!r}"
    return ""


def _assert_identical_metadata(first: dict, second: dict) -> None:
    """Compare two metadata dicts byte- and content-wise, modulo listed fields."""
    for field in VARIABLE_FIELDS:
        first.pop(field, None)
        second.pop(field, None)
    first_bytes = orjson.dumps(first, default=str)
    second_bytes = orjson.dumps(second, default=str)
    assert first_bytes == second_bytes, (
        "insertion-ordered bytes differ: "
        f"{_first_diff_path(json.loads(first_bytes), json.loads(second_bytes))}"
    )
    first_canonical = json.dumps(first, sort_keys=True, default=str)
    second_canonical = json.dumps(second, sort_keys=True, default=str)
    assert first_canonical == second_canonical, (
        "canonical JSON differs: "
        f"{_first_diff_path(json.loads(first_canonical), json.loads(second_canonical))}"
    )


@pytest.fixture(scope="module")
def native_binary(tmp_path_factory):
    """A freshly compiled native binary so the disassembly path is exercised.

    Built at test time from committed source (no binary blobs in git); skipped
    cleanly on machines without a host C compiler.
    """
    compiler = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
    if not compiler:
        pytest.skip("no host C compiler available for the determinism fixture")
    workdir = tmp_path_factory.mktemp("determinism")
    source = workdir / "demo.c"
    source.write_text(_DEMO_C, encoding="utf-8")
    binary = workdir / "demo-bin"
    subprocess.run(
        [compiler, "-O1", "-o", str(binary), str(source)],
        check=True,
        capture_output=True,
    )
    return binary


def _parsed_metadata(binary: Path) -> dict:
    metadata = parse(str(binary), disassemble=True)
    return metadata


def _disassembly_really_ran(metadata: dict) -> bool:
    if not metadata.get("disassembled_functions"):
        return False
    return "disassembly_unavailable" not in (
        metadata.get("analysis_coverage", {}).get("degradations") or []
    )


def test_determinism_two_runs_in_one_process(native_binary):
    """The same input parsed twice in one process yields identical metadata."""
    first = _parsed_metadata(native_binary)
    second = _parsed_metadata(native_binary)
    if not _disassembly_really_ran(first):
        pytest.skip("disassembly unavailable (nyxstone cannot handle this host target)")
    _assert_identical_metadata(first, second)


def test_determinism_across_hash_seeds(native_binary):
    """Two subprocess parses under different hash seeds agree byte for byte.

    Set iteration order depends on PYTHONHASHSEED, so in-process repetition
    cannot see set-order nondeterminism; different seeds in fresh processes
    can. The comparison is on raw orjson bytes, i.e. the exact bytes a
    metadata export (and therefore a future cache) would carry.
    """
    probe = (
        "import sys;"
        "import orjson;"
        "sys.path.insert(0, sys.argv[1]);"
        "from blint.lib.binary import parse;"
        "md = parse(sys.argv[2], disassemble=True);"
        "print(orjson.dumps(md, default=str).decode('utf-8', 'ignore'))"
    )
    outputs = {}
    for seed in ("0", "4242"):
        env = dict(os.environ)
        env["PYTHONHASHSEED"] = seed
        env["PYTHONPATH"] = str(REPO_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
        result = subprocess.run(
            [sys.executable, "-c", probe, str(REPO_ROOT), str(native_binary)],
            check=True,
            capture_output=True,
            env=env,
        )
        outputs[seed] = result.stdout
    if b'"disassembled_functions":{}' in outputs["0"] or (
        b"disassembled_functions" not in outputs["0"]
    ):
        pytest.skip("disassembly unavailable (nyxstone cannot handle this host target)")
    assert outputs["0"] == outputs["4242"], (
        "metadata bytes differ across PYTHONHASHSEED values; some output "
        "ordering derives from set iteration: "
        f"{_first_diff_path(json.loads(outputs['0']), json.loads(outputs['4242']))}"
    )


def test_determinism_wasm_fixture_across_hash_seeds():
    """The wasm path (wasm-tools report normalization) is likewise pinned."""
    wasm_file = REPO_ROOT / "tests" / "data" / "complex_flow.wasm"
    probe = (
        "import sys;"
        "import orjson;"
        "sys.path.insert(0, sys.argv[1]);"
        "from blint.lib.binary import parse;"
        "md = parse(sys.argv[2], disassemble=False);"
        "print(orjson.dumps(md, default=str).decode('utf-8', 'ignore'))"
    )
    outputs = {}
    for seed in ("0", "4242"):
        env = dict(os.environ)
        env["PYTHONHASHSEED"] = seed
        env["PYTHONPATH"] = str(REPO_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
        result = subprocess.run(
            [sys.executable, "-c", probe, str(REPO_ROOT), str(wasm_file)],
            check=True,
            capture_output=True,
            env=env,
        )
        outputs[seed] = result.stdout
    assert outputs["0"] == outputs["4242"]


def test_determinism_corpus_fixture_if_present(tmp_path):
    """If the local corpus is built, the harshest fixture is pinned too.

    go-elf-stripped drives prologue scanning and call-site promotion over
    ~1600 discovered functions — the largest set-iteration surface in the
    engine. Skipped cleanly when tests/corpus has not been materialized.
    """
    go_stripped = REPO_ROOT / "corpus-build" / "go-elf-stripped"
    if not go_stripped.exists():
        pytest.skip("corpus-build/ not materialized (run tests/scripts/build_corpus.py)")
    first = _parsed_metadata(go_stripped)
    second = _parsed_metadata(go_stripped)
    _assert_identical_metadata(first, second)
    assert _disassembly_really_ran(first)
