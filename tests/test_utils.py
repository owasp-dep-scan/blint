from importlib.metadata import PackageNotFoundError
from pathlib import Path

import orjson
import pytest

from blint.lib import utils
from blint.lib.utils import (
    calculate_entropy,
    demangle_symbolic_name,
    enum_to_str,
    export_metadata,
    get_hex_truncation_count,
    get_version,
    reset_hex_truncation_count,
)


def test_demangle_swift_symbol():
    # The demangler recognises both the bare Swift mangling and the Mach-O
    # underscore-prefixed form (`_$s…`) directly.
    assert demangle_symbolic_name("$s4main3fooyyF") == "main.foo() -> ()"
    assert demangle_symbolic_name("_$s4main3fooyyF") == "main.foo() -> ()"


def test_demangle_leaves_plain_symbols_unchanged():
    assert demangle_symbolic_name("CCCryptorCreate") == "CCCryptorCreate"


class _UnserializableThing:
    def __str__(self):
        return "unserializable-thing"


class _StrExplodesThing:
    def __str__(self):
        raise RuntimeError("boom")


class _NamePropertyExplodesThing:
    @property
    def name(self):
        raise RuntimeError("name boom")


def test_export_metadata_handles_unserializable_objects(tmp_path):
    metadata = {
        "value": _UnserializableThing(),
        "danger": _StrExplodesThing(),
        "name_danger": _NamePropertyExplodesThing(),
        "path": Path(tmp_path),
        "set_value": {"b", "a", _StrExplodesThing()},
        "raw_bytes": b"\xff\x00",
    }

    export_metadata(str(tmp_path), metadata, "serializer-regression")

    out_file = tmp_path / "serializer-regression.json"
    assert out_file.exists()
    saved = orjson.loads(out_file.read_bytes())

    assert saved["value"].startswith("<unsupported:")
    assert saved["danger"].startswith("<unsupported:")
    assert saved["name_danger"].startswith("<unsupported:")
    assert saved["path"] == str(tmp_path)
    assert len(saved["set_value"]) == 3
    assert "a" in saved["set_value"]
    assert "b" in saved["set_value"]
    assert any(str(v).startswith("<unsupported:") for v in saved["set_value"])
    assert saved["raw_bytes"] == "ff00"


def test_export_metadata_caps_hex_bytes_with_env_setting(tmp_path, monkeypatch):
    reset_hex_truncation_count()
    monkeypatch.setattr(utils, "BLINT_MAX_HEX_BYTES", 1)
    metadata = {"raw_bytes": b"\xff\x00"}

    export_metadata(str(tmp_path), metadata, "serializer-hex-cap")

    out_file = tmp_path / "serializer-hex-cap.json"
    assert out_file.exists()
    saved = orjson.loads(out_file.read_bytes())
    assert saved["raw_bytes"] == "ff...<truncated:2_bytes>"
    assert get_hex_truncation_count() == 1


def test_hex_truncation_counter_reset(tmp_path, monkeypatch):
    reset_hex_truncation_count()
    monkeypatch.setattr(utils, "BLINT_MAX_HEX_BYTES", 1)
    export_metadata(str(tmp_path), {"raw_bytes": b"\xff\x00"}, "serializer-counter")
    assert get_hex_truncation_count() == 1
    reset_hex_truncation_count()
    assert get_hex_truncation_count() == 0


def test_calculate_entropy_accepts_bytes_like_payloads():
    entropy = calculate_entropy(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09")
    assert isinstance(entropy, float)
    assert entropy >= 0


def test_get_version_returns_string_when_installed():
    version = get_version()
    assert isinstance(version, str)
    assert version


def test_get_version_falls_back_when_metadata_missing(monkeypatch):
    def _raise(_name):
        raise PackageNotFoundError("blint")

    monkeypatch.setattr(utils, "distribution", _raise)
    assert get_version() == "dev"


def test_enum_to_str_returns_the_name_on_every_lief_enum_flavour():
    """LIEF has two enum flavours and the interpreter renders them differently.

    ``OptionalHeader.DLL_CHARACTERISTICS`` members are *arithmetic* - they
    pass ``isinstance(x, int)`` - while ``MACHINE_TYPES`` members are not.
    Testing for int first therefore reported every known member of every
    flag enum as ``UNKNOWN(64)``. And ``str()`` on a LIEF enum is a property
    of the interpreter rather than of LIEF: measured with one and the same
    wheel (lief 1.0.0-d05b3499b), Python 3.10.17 renders
    ``DLL_CHARACTERISTICS.DYNAMIC_BASE`` and 3.11.14 renders ``64``, the
    enum ``__str__`` change that landed in 3.11 - so taking the last dotted
    component yielded a name on one supported interpreter and a number
    string on the other.

    Reading ``name`` first answers both. Only a value LIEF really could not
    place - one with no ``name`` at all - still renders ``UNKNOWN(<value>)``.
    """
    lief = pytest.importorskip("lief")

    dll_characteristics = lief.PE.OptionalHeader.DLL_CHARACTERISTICS
    assert isinstance(dll_characteristics.DYNAMIC_BASE, int)  # the arithmetic flavour
    assert not isinstance(lief.PE.Header.MACHINE_TYPES.AMD64, int)

    assert enum_to_str(dll_characteristics.DYNAMIC_BASE) == "DYNAMIC_BASE"
    assert enum_to_str(dll_characteristics.NX_COMPAT) == "NX_COMPAT"
    assert enum_to_str(lief.PE.Header.MACHINE_TYPES.AMD64) == "AMD64"
    assert enum_to_str(lief.PE.OptionalHeader.SUBSYSTEM.WINDOWS_CUI) == "WINDOWS_CUI"

    # A raw integer is what LIEF hands back for a value absent from the
    # enum, and it stays distinguishable from a real name.
    assert enum_to_str(999) == "UNKNOWN(999)"
    assert enum_to_str(0) == "UNKNOWN(0)"
