from blint.lib.callgraph_kpi import compare_kpi, evaluate_accuracy, extract_kpi


def _sample_metadata():
    return {
        "disassembled_functions": {
            "0x10::alpha": {
                "name": "alpha",
                "address": "0x10",
                "direct_call_targets": [
                    {"target_name": "beta", "target_address": "0x20"}
                ],
            },
            "0x20::beta": {
                "name": "beta",
                "address": "0x20",
                "direct_call_targets": [],
            },
        },
        "callgraph": {
            "nodes": [
                {"id": 0, "name": "alpha", "address": "0x10"},
                {"id": 1, "name": "beta", "address": "0x20"},
            ],
            "edges": [
                {
                    "src": 0,
                    "dst": 1,
                    "kind": "direct",
                    "count": 1,
                    "confidence": "high",
                }
            ],
            "external": [
                {
                    "src": 0,
                    "target": "puts",
                    "reason": "symbol_only_miss",
                    "count": 1,
                    "confidence": "low",
                }
            ],
        },
    }


def test_extract_kpi_counts_fields():
    kpi = extract_kpi(_sample_metadata())

    assert kpi["functions_total"] == 2
    assert kpi["functions_with_direct_targets"] == 1
    assert kpi["internal_edges"] == 1
    assert kpi["external_edges"] == 1
    assert kpi["internal_edge_kinds"] == {"direct": 1}
    assert kpi["external_reason_buckets"] == {"symbol_only_miss": 1}


def test_compare_kpi_reports_drop_regressions():
    baseline = {
        "functions_total": 10,
        "functions_with_direct_targets": 8,
        "internal_edges": 30,
        "external_edges": 20,
        "internal_edge_kinds": {"direct": 25},
        "external_reason_buckets": {"address_space_miss": 20},
    }
    actual = {
        "functions_total": 10,
        "functions_with_direct_targets": 7,
        "internal_edges": 20,
        "external_edges": 19,
        "internal_edge_kinds": {"direct": 20},
        "external_reason_buckets": {"address_space_miss": 1},
    }
    allowed_drop = {
        "functions_with_direct_targets": 0,
        "internal_edges": 5,
        "external_edges": 100,
        "internal_edge_kinds": {"*": 2},
        "external_reason_buckets": {"*": 100},
    }

    failures = compare_kpi(actual, baseline, allowed_drop)

    assert any("functions_with_direct_targets" in failure for failure in failures)
    assert any("internal_edges" in failure for failure in failures)
    assert any("internal_edge_kinds.direct" in failure for failure in failures)
    assert all("external_reason_buckets" not in failure for failure in failures)


def test_evaluate_accuracy_tracks_fp_and_fn():
    labels = [
        {
            "type": "internal",
            "src": "alpha@0x10",
            "dst": "beta@0x20",
            "kind": "direct",
            "expect_present": True,
        },
        {
            "type": "internal",
            "src": "alpha@0x10",
            "dst": "ghost@0x99",
            "kind": "direct",
            "expect_present": True,
        },
        {
            "type": "external",
            "src": "alpha@0x10",
            "target": "puts",
            "reason": "symbol_only_miss",
            "expect_present": False,
        },
        {
            "type": "external",
            "src": "alpha@0x10",
            "target": "missing",
            "reason": "symbol_only_miss",
            "expect_present": False,
        },
    ]

    accuracy = evaluate_accuracy(_sample_metadata(), labels)

    assert accuracy["assertions"] == 4
    assert accuracy["true_positives"] == 1
    assert accuracy["false_negatives"] == 1
    assert accuracy["false_positives"] == 1
    assert accuracy["true_negatives"] == 1
