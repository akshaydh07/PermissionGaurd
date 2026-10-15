from copy import deepcopy
from pathlib import Path

import pytest

from permission_guard.analysis_models import AnalysisResult
from permission_guard.analyzer import analyze_report, load_policy
from permission_guard.errors import ReportInputError
from permission_guard.models import PermissionReport


POLICY_PATH = Path(__file__).parents[1] / "policies" / "security_policy.json"


def _report(
    purpose: str | None,
    *permissions: str,
) -> PermissionReport:
    return PermissionReport(
        app_name="Test application",
        package_name="org.example.test",
        purpose=purpose,
        permissions=tuple(permissions),
        source_format="json",
    )


def _policy() -> dict:
    return load_policy(POLICY_PATH)


@pytest.mark.parametrize(
    ("purpose", "permission"),
    [
        ("audio recording", "android.permission.RECORD_AUDIO"),
        ("photography", "android.permission.CAMERA"),
        ("navigation", "android.permission.ACCESS_FINE_LOCATION"),
        ("weather", "android.permission.INTERNET"),
    ],
)
def test_justified_sensitive_permissions_do_not_get_purpose_mismatch(
    purpose: str,
    permission: str,
) -> None:
    result = analyze_report(_report(purpose, permission), POLICY_PATH)

    assert not any(finding.category == "purpose_mismatch" for finding in result.findings)
    permission_finding = next(
        finding
        for finding in result.findings
        if finding.category == "permission_sensitivity"
    )
    assert permission_finding.permissions == (permission,)
    assert permission_finding.explanation
    assert permission_finding.recommended_action


def test_unknown_purpose_does_not_invent_permission_mismatch() -> None:
    result = analyze_report(
        _report("an unrecognized purpose", "android.permission.CAMERA"),
        POLICY_PATH,
    )

    assert not any(finding.category == "purpose_mismatch" for finding in result.findings)
    assert result.scoring_breakdown["sensitivity"] == 6


def test_unknown_permission_is_reported_as_uncertain_without_points() -> None:
    permission = "org.example.permission.UNKNOWN"
    result = analyze_report(_report("calculator", permission), POLICY_PATH)
    finding = next(f for f in result.findings if f.category == "unknown_permission")

    assert finding.permissions == (permission,)
    assert finding.confidence < 0.5
    assert finding.uncertainty
    assert finding.score_contribution == 0
    assert "Verify" in finding.recommended_action


@pytest.mark.parametrize(
    ("permissions", "rule_id"),
    [
        (
            (
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.READ_CONTACTS",
            ),
            "location-and-contacts",
        ),
        (
            (
                "android.permission.RECORD_AUDIO",
                "android.permission.RECEIVE_BOOT_COMPLETED",
            ),
            "microphone-and-background-execution",
        ),
        (
            (
                "android.permission.READ_MEDIA_IMAGES",
                "android.permission.INTERNET",
            ),
            "storage-and-network",
        ),
    ],
)
def test_suspicious_combinations_are_review_indicators(
    permissions: tuple[str, str],
    rule_id: str,
) -> None:
    result = analyze_report(_report(None, *permissions), POLICY_PATH)
    finding = next(
        item for item in result.findings if item.finding_id == f"combination:{rule_id}"
    )

    assert finding.category == "suspicious_combination"
    assert finding.score_contribution > 0
    assert finding.uncertainty
    assert "not evidence" in finding.uncertainty
    assert finding.recommended_action


def test_overlapping_combination_findings_are_not_double_counted() -> None:
    policy = _policy()
    policy["combinations"].append(
        {
            "id": "microphone-and-network",
            "groups": ["microphone", "network"],
            "severity": "medium",
            "score": 10,
            "confidence": 0.6,
            "explanation": "Synthetic overlapping rule for regression coverage.",
            "recommended_action": "Review microphone and network use.",
        }
    )
    result = analyze_report(
        _report(
            None,
            "android.permission.RECORD_AUDIO",
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.INTERNET",
        ),
        policy,
    )
    findings = [
        finding
        for finding in result.findings
        if finding.category == "suspicious_combination"
    ]

    assert len(findings) == 2
    assert sum(f.score_contribution for f in findings) == 22


def test_score_is_deterministic_and_capped_at_100() -> None:
    report = _report(
        "calculator",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.MANAGE_EXTERNAL_STORAGE",
        "android.permission.SEND_SMS",
        "android.permission.READ_CONTACTS",
        "android.permission.INTERNET",
    )

    first = analyze_report(report, POLICY_PATH)
    second = analyze_report(report, POLICY_PATH)

    assert first == second
    assert first.score == 100
    assert first.risk_band == "High"
    assert sum(first.scoring_breakdown.values()) >= first.score


def test_overprivileged_calculator_gets_actionable_findings() -> None:
    result = analyze_report(
        _report(
            "calculator",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.READ_CONTACTS",
            "android.permission.INTERNET",
        ),
        POLICY_PATH,
    )

    assert result.risk_band == "High"
    mismatches = [
        finding
        for finding in result.findings
        if finding.category == "purpose_mismatch"
    ]
    assert {permission for item in mismatches for permission in item.permissions} == {
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.READ_CONTACTS",
        "android.permission.INTERNET",
    }
    assert all(item.score_contribution > 0 for item in mismatches)
    assert all(item.recommended_action for item in mismatches)
    assert any(
        finding.finding_id == "combination:location-and-contacts"
        for finding in result.findings
    )


@pytest.mark.parametrize(
    ("score", "expected_band"),
    [
        (0, "Low"),
        (29, "Low"),
        (30, "Medium"),
        (59, "Medium"),
        (60, "High"),
        (100, "High"),
    ],
)
def test_risk_band_boundaries(score: int, expected_band: str) -> None:
    policy = _policy()
    policy["permissions"] = {
        "android.permission.TEST": {
            "sensitivity": "low",
            "impact": "Synthetic impact for boundary testing.",
            "justified_purposes": ["test"],
            "recommended_action": "Synthetic remediation.",
        }
    }
    policy["purpose_aliases"] = {"test": "test"}
    policy["scoring"]["sensitivity_points"]["low"] = score
    report = _report("test", "android.permission.TEST")

    result = analyze_report(report, policy)

    assert result.score == score
    assert result.risk_band == expected_band


def test_policy_violation_and_mismatch_share_one_incremental_penalty() -> None:
    policy = _policy()
    policy["purpose_aliases"]["calculator"] = "calculator"
    policy["denied_permissions"] = ["android.permission.CAMERA"]
    result = analyze_report(
        _report("calculator", "android.permission.CAMERA"),
        policy,
    )
    mismatch = next(f for f in result.findings if f.category == "purpose_mismatch")
    violation = next(f for f in result.findings if f.category == "policy_violation")

    assert mismatch.score_contribution == 0
    assert violation.score_contribution == policy["scoring"]["policy_violation_points"]
    assert result.scoring_breakdown["purpose_mismatch"] == 0
    assert result.scoring_breakdown["policy_violations"] == 25


def test_policy_can_be_loaded_from_json_and_version_is_returned() -> None:
    result = analyze_report(_report("calculator"), POLICY_PATH)

    assert result.policy_version == "1.0"


def test_invalid_policy_is_reported() -> None:
    invalid_policy = _policy()
    invalid_policy["scoring"]["purpose_mismatch_points"] = -1

    with pytest.raises(ReportInputError, match="non-negative integers"):
        analyze_report(_report("calculator"), invalid_policy)


def test_policy_violation_finding_has_relevant_recommendation() -> None:
    policy = _policy()
    policy["denied_permissions"] = ["android.permission.SEND_SMS"]

    result: AnalysisResult = analyze_report(
        _report("messaging", "android.permission.SEND_SMS"),
        policy,
    )
    finding = next(f for f in result.findings if f.category == "policy_violation")

    assert finding.permissions == ("android.permission.SEND_SMS",)
    assert "exception" in finding.recommended_action


def test_report_model_is_not_modified_by_analysis() -> None:
    report = _report("calculator", "android.permission.CAMERA")
    original = deepcopy(report)

    analyze_report(report, POLICY_PATH)

    assert report == original
