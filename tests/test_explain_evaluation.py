from queryguard.evaluation import evaluate
from queryguard.explain import analyze_explain


def test_json_and_text_explain():
    findings = analyze_explain({"Plan": {"Node Type": "Seq Scan", "Plan Rows": 20_000_000, "Total Cost": 200_000}})
    assert {"plan_sequential_scan", "plan_large_rows", "plan_high_cost"} <= {f.code for f in findings}
    assert "plan_nested_loop" in {f.code for f in analyze_explain("Nested Loop (cost=0..200000)") }


def test_adversarial_corpus_has_at_least_100_cases():
    report = evaluate()
    assert report["total"] >= 100
    assert report["passed"] == report["total"]
