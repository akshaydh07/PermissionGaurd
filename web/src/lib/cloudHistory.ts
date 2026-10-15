import type { SupabaseClient } from "@supabase/supabase-js";
import type { AnalysisResponse } from "../types";
import { getVerifiedUser } from "./auth";

export type CloudHistoryItem = {
  id: string;
  created_at: string;
  app_name: string | null;
  package_name: string | null;
  purpose: string | null;
  source_format: "json" | "csv" | "apk";
  score: number;
  risk_band: "Low" | "Medium" | "High";
  policy_version: string;
  findings_count: number;
};

export type CloudSaveOutcome = "saved" | "not_configured" | "consent_required";

export async function saveAnalysisSummary(
  client: SupabaseClient | null,
  consented: boolean,
  analysis: AnalysisResponse,
): Promise<CloudSaveOutcome> {
  if (!client) return "not_configured";
  if (!consented) return "consent_required";

  const user = await getVerifiedUser(client);
  if (!user) {
    throw new Error("Sign in again before saving to cloud history.");
  }

  const { error } = await client.from("scan_history").insert({
    user_id: user.id,
    app_name: analysis.report.app_name,
    package_name: analysis.report.package_name,
    purpose: analysis.report.purpose,
    source_format: analysis.report.source_format,
    score: analysis.result.score,
    risk_band: analysis.result.risk_band,
    policy_version: analysis.result.policy_version,
    findings_count: analysis.result.findings.length,
  });
  if (error) {
    throw new Error(`Unable to save cloud history: ${error.message}`);
  }
  return "saved";
}

export async function loadCloudHistory(
  client: SupabaseClient | null,
  consented: boolean,
): Promise<CloudHistoryItem[]> {
  if (!client) return [];
  if (!consented) return [];

  const user = await getVerifiedUser(client);
  if (!user) {
    throw new Error("Sign in again before viewing cloud history.");
  }

  const { data, error } = await client
    .from("scan_history")
    .select(
      "id, created_at, app_name, package_name, purpose, source_format, score, risk_band, policy_version, findings_count",
    )
    .order("created_at", { ascending: false });
  if (error) {
    throw new Error(`Unable to load cloud history: ${error.message}`);
  }
  return (data ?? []) as CloudHistoryItem[];
}
