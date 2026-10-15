import json
import re
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any

from permission_guard.analysis_models import (
    AnalysisResult,
    Finding,
    FindingSeverity,
)
from permission_guard.errors import ReportInputError
from permission_guard.models import PermissionReport

DEFAULT_POLICY_PATH = (
    Path(__file__).resolve().parent.parent / "policies" / "security_policy.json"
)
_VALID_SENSITIVITY = {"low", "medium", "high", "critical"}
_VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
_BACKGROUND_PERMISSIONS = {
    "android.permission.FOREGROUND_SERVICE",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.WAKE_LOCK",
    "android.permission.SCHEDULE_EXACT_ALARM",
}
_STORAGE_PERMISSIONS = {
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_VISUAL_USER_SELECTED",
}
_NETWORK_PERMISSIONS = {
    "android.permission.INTERNET",
}


def load_policy(path: str | Path = DEFAULT_POLICY_PATH) -> dict[str, Any]:
    """Load and validate a JSON policy file."""
    try:
        with Path(path).open(encoding="utf-8") as policy_file:
            policy = json.load(policy_file)
    except OSError as error:
        raise ReportInputError(f"Unable to read analysis policy: {error}.") from error
    except json.JSONDecodeError as error:
        raise ReportInputError(f"Invalid analysis policy JSON: {error.msg}.") from error

    validate_policy(policy)
    return policy


def validate_policy(policy: Any) -> None:
    """Validate a parsed organizational policy, raising ReportInputError on invalid input."""
    _validate_policy(policy)


def analyze_report(
    report: PermissionReport,
    policy: Mapping[str, Any] | str | Path | None = None,
) -> AnalysisResult:
    """Analyze a normalized report using deterministic local policy rules."""
    active_policy = (
        load_policy(policy)
        if isinstance(policy, (str, Path))
        else dict(policy) if policy is not None else load_policy()
    )
    validate_policy(active_policy)

    permission_config: Mapping[str, Any] = active_policy["permissions"]
    scoring: Mapping[str, Any] = active_policy["scoring"]
    aliases: Mapping[str, str] = active_policy["purpose_aliases"]
    normalized_purpose = _normalize_purpose(report.purpose)
    canonical_purpose = aliases.get(normalized_purpose) if normalized_purpose else None

    findings: list[Finding] = []
    if canonical_purpose is None:
        findings.append(
            Finding(
                finding_id="unknown-purpose",
                category="unknown_purpose",
                severity="info",
                permissions=(),
                evidence=(
                    (
                        f"Purpose '{report.purpose}' is not in the configured aliases."
                        if normalized_purpose
                        else "No application purpose was provided."
                    ),
                ),
                explanation=(
                    "The configured policy cannot map this application purpose "
                    "to a known category, so no purpose-mismatch conclusion is made."
                ),
                score_contribution=0,
                confidence=0.2,
                uncertainty=(
                    "Purpose matching is unavailable until the purpose is clarified "
                    "or added to the local policy aliases."
                ),
                recommended_action=(
                    "Confirm the application's purpose and add a reviewed purpose "
                    "alias if the current catalog does not cover it."
                ),
            )
        )
    permission_findings: dict[str, dict[str, int]] = {}
    for permission in report.permissions:
        definition = permission_config.get(permission)
        if definition is None:
            findings.append(
                Finding(
                    finding_id=f"unknown-permission:{permission}",
                    category="unknown_permission",
                    severity="low",
                    permissions=(permission,),
                    evidence=(f"{permission} is declared in the permission report.",),
                    explanation=(
                        "This permission is not in the configured permission "
                        "catalog, so its impact and purpose fit are unknown."
                    ),
                    score_contribution=0,
                    confidence=0.2,
                    uncertainty="No catalog entry is available for this permission.",
                    recommended_action=(
                        "Verify this permission against authoritative Android "
                        "documentation and add a reviewed policy entry if needed."
                    ),
                )
            )
            continue

        sensitivity = definition["sensitivity"]
        sensitivity_points = scoring["sensitivity_points"][sensitivity]
        permission_findings[permission] = {
            "sensitivity": sensitivity_points,
            "mismatch": 0,
            "policy": 0,
        }
        findings.append(
            Finding(
                finding_id=f"permission:{permission}",
                category="permission_sensitivity",
                severity=_finding_severity(sensitivity),
                permissions=(permission,),
                evidence=(f"{permission} is declared in the permission report.",),
                explanation=definition["impact"],
                score_contribution=sensitivity_points,
                confidence=0.95,
                uncertainty=None,
                recommended_action=definition["recommended_action"],
            )
        )

        if canonical_purpose is not None and canonical_purpose not in definition[
            "justified_purposes"
        ]:
            mismatch_points = scoring["purpose_mismatch_points"]
            permission_findings[permission]["mismatch"] = mismatch_points
            findings.append(
                Finding(
                    finding_id=f"purpose-mismatch:{permission}",
                    category="purpose_mismatch",
                    severity="medium",
                    permissions=(permission,),
                    evidence=(
                        f"Declared purpose '{report.purpose}' maps to "
                        f"'{canonical_purpose}'.",
                        f"'{canonical_purpose}' is not listed as a justification "
                        f"for {permission}.",
                    ),
                    explanation=(
                        "The configured catalog does not list this permission "
                        "as justified for the declared app purpose. This is a "
                        "review prompt, not proof of misuse."
                    ),
                    score_contribution=0,
                    confidence=0.75,
                    uncertainty=(
                        "Purpose-to-permission mappings are coarse and may not "
                        "cover every legitimate app feature."
                    ),
                    recommended_action=(
                        "Confirm the app's features and document a valid reason "
                        "for this permission, or remove it if unnecessary."
                    ),
                )
            )

    denied_permissions = set(active_policy["denied_permissions"])
    for permission in report.permissions:
        if permission not in denied_permissions:
            continue
        if permission not in permission_findings:
            permission_findings[permission] = {
                "sensitivity": 0,
                "mismatch": 0,
                "policy": 0,
            }
        permission_findings[permission]["policy"] = scoring[
            "policy_violation_points"
        ]
        findings.append(
            Finding(
                finding_id=f"policy-deny:{permission}",
                category="policy_violation",
                severity="high",
                permissions=(permission,),
                evidence=(
                    f"{permission} appears in the configured organizational "
                    "denylist.",
                ),
                explanation=(
                    "This permission violates the configured organizational "
                    "policy. The finding describes a policy breach, not malicious "
                    "behavior."
                ),
                score_contribution=0,
                confidence=1.0,
                uncertainty=None,
                recommended_action=(
                    "Remove the permission or request a documented policy "
                    "exception from the organization."
                ),
            )
        )

    combination_findings = _combination_findings(
        report.permissions,
        active_policy["combinations"],
    )
    findings.extend(combination_findings)

    sensitivity_total = sum(
        values["sensitivity"] for values in permission_findings.values()
    )
    mismatch_total = 0
    policy_total = 0
    for permission, values in permission_findings.items():
        mismatch_value = values["mismatch"]
        policy_value = values["policy"]
        selected = max(mismatch_value, policy_value)
        target_category = None
        if policy_value >= mismatch_value and policy_value:
            target_category = "policy_violation"
            policy_total += selected
        elif mismatch_value:
            target_category = "purpose_mismatch"
            mismatch_total += selected
        if target_category is not None:
            target = next(
                finding
                for finding in findings
                if finding.category == target_category
                and finding.permissions == (permission,)
            )
            findings[findings.index(target)] = replace(
                target,
                score_contribution=selected,
            )

    combination_total = sum(
        finding.score_contribution for finding in combination_findings
    )
    breakdown = {
        "sensitivity": sensitivity_total,
        "purpose_mismatch": mismatch_total,
        "policy_violations": policy_total,
        "combinations": combination_total,
    }
    score = min(100, sum(breakdown.values()))
    risk_band = (
        "Low" if score < 30 else "Medium" if score < 60 else "High"
    )

    return AnalysisResult(
        app_name=report.app_name,
        package_name=report.package_name,
        purpose=report.purpose,
        score=score,
        risk_band=risk_band,
        findings=tuple(findings),
        scoring_breakdown=breakdown,
        policy_version=active_policy["version"],
    )


def _combination_findings(
    permissions: tuple[str, ...],
    configured_rules: list[dict[str, Any]],
) -> list[Finding]:
    permission_set = set(permissions)
    matches: list[tuple[dict[str, Any], tuple[str, ...]]] = []
    for rule in configured_rules:
        left = _group_permissions(rule["groups"][0], permission_set)
        right = _group_permissions(rule["groups"][1], permission_set)
        if left and right:
            matches.append((rule, tuple(sorted(left | right))))

    components: list[list[int]] = []
    for current, (_, current_permissions) in enumerate(matches):
        overlapping = [
            index
            for index, component in enumerate(components)
            if any(
                set(matches[member][1]) & set(current_permissions)
                for member in component
            )
        ]
        if not overlapping:
            components.append([current])
            continue
        first_component = overlapping[0]
        components[first_component].append(current)
        for index in reversed(overlapping[1:]):
            components[first_component].extend(components.pop(index))

    findings: list[Finding] = []
    for component in components:
        selected_index = max(
            component,
            key=lambda index: (
                matches[index][0]["score"],
                matches[index][0]["id"],
            ),
        )
        for index in component:
            rule, evidence_permissions = matches[index]
            contribution = rule["score"] if index == selected_index else 0
            findings.append(
                Finding(
                    finding_id=f"combination:{rule['id']}",
                    category="suspicious_combination",
                    severity=rule["severity"],
                    permissions=evidence_permissions,
                    evidence=(
                        f"Declared permissions matched rule '{rule['id']}'.",
                    ),
                    explanation=rule["explanation"],
                    score_contribution=contribution,
                    confidence=rule["confidence"],
                    uncertainty=(
                        "Permission co-occurrence is an indicator for review, "
                        "not evidence of malicious behavior."
                    ),
                    recommended_action=rule["recommended_action"],
                )
            )
    return findings


def _group_permissions(group: str, permissions: set[str]) -> set[str]:
    if group == "location":
        return permissions & {
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
        }
    if group == "contacts":
        return permissions & {
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.GET_ACCOUNTS",
        }
    if group == "microphone":
        return permissions & {
            "android.permission.RECORD_AUDIO",
        }
    if group == "background_execution":
        return permissions & _BACKGROUND_PERMISSIONS
    if group == "storage":
        return permissions & _STORAGE_PERMISSIONS
    if group == "network":
        return permissions & _NETWORK_PERMISSIONS
    return set()


def _normalize_purpose(purpose: str | None) -> str:
    if purpose is None:
        return ""
    return re.sub(r"\s+", " ", purpose.strip().casefold())


def _finding_severity(sensitivity: str) -> FindingSeverity:
    if sensitivity == "low":
        return "low"
    if sensitivity == "medium":
        return "medium"
    if sensitivity == "high":
        return "high"
    if sensitivity == "critical":
        return "critical"
    raise ReportInputError(f"Unsupported sensitivity level: {sensitivity}.")


def _validate_policy(policy: Any) -> None:
    if not isinstance(policy, Mapping):
        raise ReportInputError("Analysis policy must be a JSON object.")
    required = {
        "version",
        "scoring",
        "purpose_aliases",
        "permissions",
        "denied_permissions",
        "combinations",
    }
    if set(policy) != required:
        raise ReportInputError(
            "Analysis policy must contain exactly: "
            + ", ".join(sorted(required))
            + "."
        )
    if not isinstance(policy["version"], str) or not policy["version"].strip():
        raise ReportInputError("Policy version must be a non-empty string.")

    scoring = policy["scoring"]
    if not isinstance(scoring, Mapping) or set(scoring) != {
        "sensitivity_points",
        "purpose_mismatch_points",
        "policy_violation_points",
    }:
        raise ReportInputError("Policy scoring configuration is incomplete.")
    sensitivity_points = scoring["sensitivity_points"]
    if (
        not isinstance(sensitivity_points, Mapping)
        or set(sensitivity_points) != _VALID_SENSITIVITY
        or any(not _nonnegative_int(value) for value in sensitivity_points.values())
        or not _nonnegative_int(scoring["purpose_mismatch_points"])
        or not _nonnegative_int(scoring["policy_violation_points"])
    ):
        raise ReportInputError("Policy scoring points must be non-negative integers.")

    aliases = policy["purpose_aliases"]
    if not isinstance(aliases, Mapping) or any(
        not isinstance(alias, str)
        or not alias.strip()
        or _normalize_purpose(alias) != alias
        or not isinstance(canonical, str)
        or not canonical.strip()
        for alias, canonical in aliases.items()
    ):
        raise ReportInputError("Purpose aliases must map non-empty strings.")

    permissions = policy["permissions"]
    if not isinstance(permissions, Mapping):
        raise ReportInputError("Policy permissions must be an object.")
    for permission, definition in permissions.items():
        if (
            not isinstance(permission, str)
            or not permission.strip()
            or not isinstance(definition, Mapping)
            or set(definition)
            != {"sensitivity", "impact", "justified_purposes", "recommended_action"}
            or not isinstance(definition["sensitivity"], str)
            or definition["sensitivity"] not in _VALID_SENSITIVITY
            or not isinstance(definition["impact"], str)
            or not definition["impact"].strip()
            or not isinstance(definition["recommended_action"], str)
            or not definition["recommended_action"].strip()
            or not isinstance(definition["justified_purposes"], list)
            or any(
                not isinstance(value, str) or not value.strip()
                for value in definition["justified_purposes"]
            )
        ):
            raise ReportInputError(f"Invalid permission policy entry: {permission}.")

    denied = policy["denied_permissions"]
    if not isinstance(denied, list) or any(
        not isinstance(permission, str) or not permission.strip()
        for permission in denied
    ):
        raise ReportInputError("denied_permissions must be a list of permission names.")

    combinations = policy["combinations"]
    if not isinstance(combinations, list):
        raise ReportInputError("Policy combinations must be a list.")
    identifiers: set[str] = set()
    valid_groups = {
        "location",
        "contacts",
        "microphone",
        "background_execution",
        "storage",
        "network",
    }
    for rule in combinations:
        if (
            not isinstance(rule, dict)
            or set(rule)
            != {
                "id",
                "groups",
                "severity",
                "score",
                "confidence",
                "explanation",
                "recommended_action",
            }
            or not isinstance(rule["id"], str)
            or not rule["id"].strip()
            or rule["id"] in identifiers
            or not isinstance(rule["groups"], list)
            or len(rule["groups"]) != 2
            or any(
                not isinstance(group, str) or group not in valid_groups
                for group in rule["groups"]
            )
            or not isinstance(rule["severity"], str)
            or rule["severity"] not in _VALID_SEVERITIES
            or not _nonnegative_int(rule["score"])
            or isinstance(rule["confidence"], bool)
            or not isinstance(rule["confidence"], (int, float))
            or not 0 <= rule["confidence"] <= 1
            or not isinstance(rule["explanation"], str)
            or not rule["explanation"].strip()
            or not isinstance(rule["recommended_action"], str)
            or not rule["recommended_action"].strip()
        ):
            raise ReportInputError("Invalid or duplicate policy combination rule.")
        identifiers.add(rule["id"])


def _nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0
