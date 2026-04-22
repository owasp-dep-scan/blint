from pathlib import Path

import orjson

import blint.lib.utils as utils
from blint.lib.utils import (
    calculate_entropy,
    export_metadata,
    get_hex_truncation_count,
    reset_hex_truncation_count,
)


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
