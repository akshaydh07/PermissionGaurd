import json
from pathlib import Path
from typing import Any

from permission_guard.analyzer import analyze_report, load_policy
from permission_guard.models import PermissionReport

EVALUATION_DIR = Path(__file__).resolve().parent
ACTIONABLE_CATEGORIES = {
    "purpose_mismatch",
    "policy_violation",
    "suspicious_combination",
}


def _finding_key(category: str, permissions: tuple[str, ...]) -> str:
    return f"{category}|{'+'.join(sorted(permissions))}"


def evaluate() -> dict[str, Any]:
    scenarios = json.loads((EVALUATION_DIR / "scenarios.json").read_text("utf-8"))
    expected = json.loads(
        (EVALUATION_DIR / "expected_results.json").read_text("utf-8")
    )
    default_policy = load_policy()
    finding_counts = {"tp": 0, "fp": 0, "fn": 0}
    application_counts = {"tp": 0, "fp": 0, "fn": 0}
    results: list[dict[str, Any]] = []

    for scenario in scenarios["scenarios"]:
        report = PermissionReport(
            app_name=scenario["app_name"],
            package_name=scenario["package_name"],
            purpose=scenario["purpose"],
            permissions=tuple(scenario["permissions"]),
            source_format="json",
        )
        policy = dict(default_policy)
        override_name = scenario.get("policy_override")
        if override_name:
            override = expected["policy_overrides"][override_name]
            policy["denied_permissions"] = override["denied_permissions"]

        result = analyze_report(report, policy)
        detected = {
            _finding_key(finding.category, finding.permissions)
            for finding in result.findings
            if finding.category in ACTIONABLE_CATEGORIES
        }
        scenario_expected = set(
            expected["scenarios"][scenario["id"]]["expected_actionable_findings"]
        )
        finding_counts["tp"] += len(detected & scenario_expected)
        finding_counts["fp"] += len(detected - scenario_expected)
        finding_counts["fn"] += len(scenario_expected - detected)

        expected_positive = bool(scenario_expected)
        detected_positive = bool(detected)
        if expected_positive and detected_positive:
            application_counts["tp"] += 1
        elif detected_positive:
            application_counts["fp"] += 1
        elif expected_positive:
            application_counts["fn"] += 1

        actual_uncertainty = {
            finding.category
            for finding in result.findings
            if finding.category in {"unknown_permission", "unknown_purpose"}
        }
        expected_uncertainty = set(
            expected["scenarios"][scenario["id"]]["expected_uncertainty_categories"]
        )
        if actual_uncertainty != expected_uncertainty:
            raise AssertionError(
                f"{scenario['id']}: uncertainty categories differ; "
                f"expected {sorted(expected_uncertainty)}, "
                f"got {sorted(actual_uncertainty)}"
            )
        results.append(
            {
                "id": scenario["id"],
                "score": result.score,
                "risk_band": result.risk_band,
                "expected_findings": sorted(scenario_expected),
                "detected_findings": sorted(detected),
            }
        )

    return {
        "scenario_count": len(results),
        "finding_level": _metrics(finding_counts),
        "application_level": _metrics(application_counts),
        "results": results,
    }


def _metrics(counts: dict[str, int]) -> dict[str, int | float | None]:
    tp, fp, fn = counts["tp"], counts["fp"], counts["fn"]
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None
        and recall is not None
        and precision + recall
        else None
    )
    return {
        **counts,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def main() -> None:
    report = evaluate()
    print(f"Synthetic scenarios: {report['scenario_count']}")
    for scope in ("finding_level", "application_level"):
        metrics = report[scope]
        print(
            f"{scope}: TP={metrics['tp']} FP={metrics['fp']} FN={metrics['fn']} "
            f"precision={_display(metrics['precision'])} "
            f"recall={_display(metrics['recall'])} F1={_display(metrics['f1'])}"
        )
    for scenario in report["results"]:
        print(
            f"{scenario['id']}: score={scenario['score']} "
            f"risk={scenario['risk_band']} detected={len(scenario['detected_findings'])}"
        )


def _display(value: float | None) -> str:
    return "N/A" if value is None else f"{value:.3f}"


if __name__ == "__main__":
    main()
