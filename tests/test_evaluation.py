import json
from pathlib import Path

from evaluation.run_evaluation import evaluate

EVALUATION_DIR = Path(__file__).parents[1] / "evaluation"


def test_expected_results_cover_all_documented_scenarios() -> None:
    scenarios = json.loads((EVALUATION_DIR / "scenarios.json").read_text("utf-8"))
    expected = json.loads(
        (EVALUATION_DIR / "expected_results.json").read_text("utf-8")
    )

    assert expected["review_status"] == "Independent review complete"
    assert len(scenarios["scenarios"]) >= 8
    assert {
        scenario["id"] for scenario in scenarios["scenarios"]
    } == set(expected["scenarios"])
    assert all(scenario.get("description") for scenario in scenarios["scenarios"])


def test_synthetic_evaluation_reports_finding_and_app_metrics() -> None:
    result = evaluate()

    assert result["scenario_count"] >= 8
    assert result["finding_level"] == {
        "tp": 9,
        "fp": 0,
        "fn": 0,
        "precision": 1.0,
        "recall": 1.0,
        "f1": 1.0,
    }
    assert result["application_level"] == {
        "tp": 6,
        "fp": 0,
        "fn": 0,
        "precision": 1.0,
        "recall": 1.0,
        "f1": 1.0,
    }
