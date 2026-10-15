from dataclasses import dataclass
from typing import Literal


RiskBand = Literal["Low", "Medium", "High"]
FindingSeverity = Literal["info", "low", "medium", "high", "critical"]


@dataclass(frozen=True, slots=True)
class Finding:
    finding_id: str
    category: str
    severity: FindingSeverity
    permissions: tuple[str, ...]
    evidence: tuple[str, ...]
    explanation: str
    score_contribution: int
    confidence: float
    uncertainty: str | None
    recommended_action: str


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    app_name: str | None
    package_name: str | None
    purpose: str | None
    score: int
    risk_band: RiskBand
    findings: tuple[Finding, ...]
    scoring_breakdown: dict[str, int]
    policy_version: str
