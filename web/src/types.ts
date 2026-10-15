export type RiskLevel = "Low" | "Medium" | "High";

export type AppPermission = {
  name: string;
  group: string;
  severity: RiskLevel;
  confidence: number;
  explanation: string;
  purposeFit: "Expected" | "Review";
  recommendation: string;
};

export type ProtectedApp = {
  id: string;
  name: string;
  publisher: string;
  category: string;
  initials: string;
  tint: string;
  score: number;
  risk: RiskLevel;
  permissions: AppPermission[];
  lastScanned: string;
};

export type AnalysisReport = {
  app_name: string | null;
  package_name: string | null;
  purpose: string | null;
  permissions: string[];
  source_format: "json" | "csv" | "apk";
  permission_source: "report" | "android_manifest";
};

export type AnalysisFinding = {
  finding_id: string;
  category: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  permissions: string[];
  evidence: string[];
  explanation: string;
  score_contribution: number;
  confidence: number;
  uncertainty: string | null;
  recommended_action: string;
};

export type AnalysisResponse = {
  analysis_id: number;
  report: AnalysisReport;
  result: {
    app_name: string | null;
    package_name: string | null;
    purpose: string | null;
    score: number;
    risk_band: RiskLevel;
    findings: AnalysisFinding[];
    scoring_breakdown: Record<string, number>;
    policy_version: string;
  };
};

export type Page =
  | "Overview"
  | "Installed apps"
  | "App details"
  | "Alerts"
  | "Scan history"
  | "Manual analysis"
  | "Privacy settings";

export type AuthView = "landing" | "sign-in" | "create-account" | "app";
