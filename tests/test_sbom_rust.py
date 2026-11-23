"""cargo-auditable dependency positions must resolve to the right crates."""

import types
import zlib

import orjson

from blint.lib.binary_common import parse_rust_buildinfo
from blint.lib.sbom import process_rust_dependencies


def _binary(packages):
    payload = zlib.compress(orjson.dumps({"packages": packages}))
    section = types.SimpleNamespace(name=".dep-v0", content=list(payload))
    return types.SimpleNamespace(sections=[section])


def _pkg(name, deps=(), root=False):
    pkg = {"name": name, "version": "1.0.0", "source": "crates.io", "dependencies": list(deps)}
    if root:
        pkg["root"] = True
    return pkg


def _edges(packages):
    deps = parse_rust_buildinfo(_binary(packages))
    dependencies_dict = {}
    process_rust_dependencies(deps, dependencies_dict)
    return {
        k.split("/")[-1].split("@")[0]: {v.split("/")[-1].split("@")[0] for v in vs}
        for k, vs in dependencies_dict.items()
    }


def test_root_in_the_middle_remaps_positions():
    # Sorted by name: a, app (root), b, c. app -> a, b; b -> c; a -> c.
    packages = [
        _pkg("a", [3]),
        _pkg("app", [0, 2], root=True),
        _pkg("b", [3]),
        _pkg("c"),
    ]
    parsed = parse_rust_buildinfo(_binary(packages))
    assert [p["name"] for p in parsed] == ["a", "b", "c"]
    assert parsed[0]["dependencies"] == [2]
    assert parsed[1]["dependencies"] == [2]
    assert _edges(packages) == {"a": {"c"}, "b": {"c"}, "c": set()}


def test_dependency_on_last_entry_does_not_raise():
    packages = [_pkg("a"), _pkg("app", [0, 2], root=True), _pkg("z")]
    packages[0]["dependencies"] = [2]
    assert _edges(packages) == {"a": {"z"}, "z": set()}


def test_root_last_keeps_positions():
    packages = [_pkg("a", [1]), _pkg("b"), _pkg("zapp", [0], root=True)]
    parsed = parse_rust_buildinfo(_binary(packages))
    assert [p["dependencies"] for p in parsed] == [[1], []]
    assert _edges(packages) == {"a": {"b"}, "b": set()}


def test_root_first_and_references_to_root_dropped():
    packages = [_pkg("app", [1], root=True), _pkg("a", [0, 2]), _pkg("b")]
    assert _edges(packages) == {"a": {"b"}, "b": set()}


def test_out_of_range_index_is_skipped():
    deps = [
        {"name": "a", "version": "1.0.0", "source": "crates.io", "dependencies": [1, 7]},
        {"name": "b", "version": "1.0.0", "source": "crates.io"},
    ]
    dependencies_dict = {}
    process_rust_dependencies(deps, dependencies_dict)
    assert dependencies_dict["pkg:cargo/a@1.0.0"] == {"pkg:cargo/b@1.0.0"}
