from pathlib import Path

from blint.lib.ml.analysis import analyze_safetensors


def test_safetensors():
    test_sf = Path(__file__).parent.parent / "data" / "test-model.safetensors"
    result = analyze_safetensors(test_sf)
    assert result
