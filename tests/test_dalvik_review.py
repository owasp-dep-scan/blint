from types import SimpleNamespace

from blint.lib.dalvik import DexPools
from blint.lib.dalvik_review import (
    Finding,
    analyze_dex,
    build_review_metadata,
    merge_findings,
)


def _method(index, bytecode):
    return SimpleNamespace(index=index, bytecode=bytecode, name=f"m{index}")


def _pools(methods, strings=None):
    return DexPools(strings=strings or [], types=[], fields=[], methods=methods)


def test_build_review_metadata_splits_targets_and_strings():
    # invoke-static {v0}, method@0 ; const-string v1, string@0
    bytecode = bytes([0x71, 0x10, 0x00, 0x00, 0x00, 0x00, 0x1A, 0x01, 0x00, 0x00])
    pools = _pools(["Lp/Q;->run()V"], strings=["http://x"])
    md = build_review_metadata({"methods": [_method(0, bytecode)]}, pools=pools)
    assert md["exe_type"] == "dexbinary"
    assert {f["name"] for f in md["functions"]} == {"Lp/Q;->run()V"}
    assert md["informative_strings"] == ["http://x"]


def test_detects_reflection_invoke():
    bytecode = bytes([0x71, 0x10, 0x00, 0x00, 0x00, 0x00])
    pools = _pools(["Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;"])
    findings = analyze_dex({"methods": [_method(0, bytecode)]}, pools=pools)
    assert "ANDROID_REFLECTION" in {f.id for f in findings}


def test_native_exec_detected():
    bytecode = bytes([0x71, 0x10, 0x00, 0x00, 0x00, 0x00])
    pools = _pools(["Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V"])
    findings = analyze_dex({"methods": [_method(0, bytecode)]}, pools=pools)
    assert "ANDROID_NATIVE_EXEC" in {f.id for f in findings}


def test_weak_crypto_flags_weak_algorithm_string():
    bytecode = bytes([0x1A, 0x00, 0x00, 0x00])
    pools = _pools([], strings=["DES/ECB/PKCS5Padding"])
    findings = analyze_dex({"methods": [_method(0, bytecode)]}, pools=pools)
    assert "ANDROID_WEAK_CRYPTO" in {f.id for f in findings}


def test_strong_cipher_not_flagged_weak():
    bytecode = bytes([0x1A, 0x00, 0x00, 0x00])
    pools = _pools([], strings=["AES/GCM/NoPadding"])
    findings = analyze_dex({"methods": [_method(0, bytecode)]}, pools=pools)
    assert "ANDROID_WEAK_CRYPTO" not in {f.id for f in findings}


def test_remote_ai_service_by_endpoint():
    bytecode = bytes([0x1A, 0x00, 0x00, 0x00])
    pools = _pools([], strings=["https://api.openai.com/v1/chat/completions"])
    findings = analyze_dex({"methods": [_method(0, bytecode)]}, pools=pools)
    assert "ANDROID_REMOTE_AI_SERVICE" in {f.id for f in findings}


def test_tracker_sdk_by_package():
    bytecode = bytes([0x71, 0x10, 0x00, 0x00, 0x00, 0x00])
    pools = _pools(["Lcom/appsflyer/AppsFlyerLib;->start(Landroid/content/Context;)V"])
    findings = analyze_dex({"methods": [_method(0, bytecode)]}, pools=pools)
    assert "ANDROID_TRACKER_SDK" in {f.id for f in findings}


def test_empty_metadata_returns_no_findings():
    assert analyze_dex({"methods": []}) == []


def test_merge_findings_aggregates_counts_and_caps_evidence():
    g1 = [Finding("X", "t", "high", count=2, evidence=["a", "b"])]
    g2 = [Finding("X", "t", "high", count=3, evidence=["c", "d", "e", "f", "g", "h"])]
    merged = merge_findings([g1, g2])
    assert len(merged) == 1
    assert merged[0].count == 5
    assert len(merged[0].evidence) == 5
