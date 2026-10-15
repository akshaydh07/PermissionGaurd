import type { SupabaseClient } from "@supabase/supabase-js";
import { describe, expect, it, vi } from "vitest";
import { loadCloudHistory, saveAnalysisSummary } from "./cloudHistory";
import type { AnalysisResponse } from "../types";

const analysis: AnalysisResponse = {
  analysis_id: 12,
  report: {
    app_name: "Sample",
    package_name: "org.example.sample",
    purpose: "photo editing",
    permissions: ["android.permission.CAMERA"],
    source_format: "json",
    permission_source: "report",
  },
  result: {
    app_name: "Sample",
    package_name: "org.example.sample",
    purpose: "photo editing",
    score: 21,
    risk_band: "Low",
    findings: [
      {
        finding_id: "permission:camera",
        category: "permission_sensitivity",
        severity: "medium",
        permissions: ["android.permission.CAMERA"],
        evidence: ["fixture"],
        explanation: "fixture",
        score_contribution: 6,
        confidence: 0.9,
        uncertainty: null,
        recommended_action: "fixture",
      },
    ],
    scoring_breakdown: { sensitivity: 6 },
    policy_version: "1.0",
  },
};

function fakeClient(options?: {
  userId?: string | null;
  authError?: { message: string } | null;
  insertError?: { message: string } | null;
  rows?: unknown[];
}) {
  const insert = vi.fn().mockResolvedValue({ error: options?.insertError ?? null });
  const order = vi.fn().mockResolvedValue({ data: options?.rows ?? [], error: null });
  const select = vi.fn(() => ({ order }));
  const from = vi.fn(() => ({ insert, select }));
  const getUser = vi.fn().mockResolvedValue({
    data: { user: options?.userId ? { id: options.userId } : null },
    error: options?.authError ?? null,
  });
  const getSession = vi.fn().mockResolvedValue({
    data: {
      session: options?.userId || options?.authError
        ? { access_token: "test-token" }
        : null,
    },
    error: null,
  });
  const client = {
    auth: { getUser, getSession },
    from,
  } as unknown as SupabaseClient;
  return { client, getUser, from, insert, select, order };
}

describe("optional cloud history", () => {
  it("keeps signed-out local use independent of cloud storage", async () => {
    const { client, from } = fakeClient();

    await expect(saveAnalysisSummary(client, false, analysis)).resolves.toBe(
      "consent_required",
    );
    await expect(loadCloudHistory(client, false)).resolves.toEqual([]);
    expect(from).not.toHaveBeenCalled();
  });

  it("does not attempt cloud access when no account is signed in", async () => {
    const { client, from } = fakeClient();

    await expect(saveAnalysisSummary(client, true, analysis)).rejects.toThrow(
      "Sign in again",
    );
    await expect(loadCloudHistory(client, true)).rejects.toThrow(
      "Sign in again",
    );
    expect(from).not.toHaveBeenCalled();
  });

  it("saves only an explicit, minimized summary after consent", async () => {
    const { client, from, insert, getUser } = fakeClient({ userId: "user-a" });

    await expect(saveAnalysisSummary(client, true, analysis)).resolves.toBe(
      "saved",
    );

    expect(getUser).toHaveBeenCalledOnce();
    expect(from).toHaveBeenCalledWith("scan_history");
    expect(insert).toHaveBeenCalledWith({
      user_id: "user-a",
      app_name: "Sample",
      package_name: "org.example.sample",
      purpose: "photo editing",
      source_format: "json",
      score: 21,
      risk_band: "Low",
      policy_version: "1.0",
      findings_count: 1,
    });
    const savedFields = Object.keys(insert.mock.calls[0][0] as object);
    expect(savedFields).not.toContain("permissions");
    expect(savedFields).not.toContain("evidence");
    expect(savedFields).not.toContain("report");
  });

  it("does not contact Supabase when cloud sync is opted out", async () => {
    const { client, from } = fakeClient({ userId: "user-a" });

    await expect(saveAnalysisSummary(client, false, analysis)).resolves.toBe(
      "consent_required",
    );
    await expect(loadCloudHistory(client, false)).resolves.toEqual([]);
    expect(from).not.toHaveBeenCalled();
  });

  it("rejects expired or invalid sessions before reading or writing history", async () => {
    const { client, from } = fakeClient({
      userId: "expired-user",
      authError: { message: "JWT expired" },
    });

    await expect(saveAnalysisSummary(client, true, analysis)).rejects.toThrow(
      "session could not be verified",
    );
    await expect(loadCloudHistory(client, true)).rejects.toThrow(
      "session could not be verified",
    );
    expect(from).not.toHaveBeenCalled();
  });

  it("returns only the authenticated user's RLS-filtered cloud records", async () => {
    const rows = [
      {
        id: "history-1",
        created_at: "2026-10-14T00:00:00Z",
        app_name: "Sample",
        package_name: "org.example.sample",
        purpose: "photo editing",
        source_format: "json",
        score: 21,
        risk_band: "Low",
        policy_version: "1.0",
        findings_count: 1,
      },
    ];
    const { client, getUser, from, select } = fakeClient({
      userId: "user-a",
      rows,
    });

    await expect(loadCloudHistory(client, true)).resolves.toEqual(rows);
    expect(getUser).toHaveBeenCalledOnce();
    expect(from).toHaveBeenCalledWith("scan_history");
    expect(select).toHaveBeenCalledWith(
      "id, created_at, app_name, package_name, purpose, source_format, score, risk_band, policy_version, findings_count",
    );
  });
});
