import type { SupabaseClient } from "@supabase/supabase-js";
import { describe, expect, it, vi } from "vitest";
import { getVerifiedUser, signOut } from "./auth";

describe("account session handling", () => {
  it("treats a valid signed-out state as no account", async () => {
    const client = {
      auth: {
        getSession: vi.fn().mockResolvedValue({
          data: { session: null },
          error: null,
        }),
        getUser: vi.fn().mockResolvedValue({
          data: { user: null },
          error: null,
        }),
      },
    } as unknown as SupabaseClient;

    await expect(getVerifiedUser(client)).resolves.toBeNull();
  });

  it("does not accept an expired or invalid access session", async () => {
    const client = {
      auth: {
        getSession: vi.fn().mockResolvedValue({
          data: { session: { access_token: "expired-token" } },
          error: null,
        }),
        getUser: vi.fn().mockResolvedValue({
          data: { user: null },
          error: { message: "JWT expired" },
        }),
      },
    } as unknown as SupabaseClient;

    await expect(getVerifiedUser(client)).rejects.toThrow(
      "session could not be verified",
    );
  });

  it("signs the account out through Supabase and surfaces failures", async () => {
    const authSignOut = vi.fn().mockResolvedValue({ error: null });
    const client = {
      auth: { signOut: authSignOut },
    } as unknown as SupabaseClient;

    await expect(signOut(client)).resolves.toBeUndefined();
    expect(authSignOut).toHaveBeenCalledOnce();

    authSignOut.mockResolvedValueOnce({ error: { message: "network error" } });
    await expect(signOut(client)).rejects.toThrow("Unable to sign out");
  });
});
