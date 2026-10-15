import type { SupabaseClient, User } from "@supabase/supabase-js";

export async function getVerifiedUser(
  client: SupabaseClient,
): Promise<User | null> {
  const { data: sessionData, error: sessionError } =
    await client.auth.getSession();
  if (sessionError) {
    throw new Error(
      "Your saved session could not be read. Sign in again before using cloud history.",
    );
  }
  if (!sessionData.session) return null;

  const { data, error } = await client.auth.getUser();
  if (error) {
    throw new Error(
      "Your session could not be verified. Sign in again before using cloud history.",
    );
  }
  return data.user;
}

export async function signOut(client: SupabaseClient): Promise<void> {
  const { error } = await client.auth.signOut();
  if (error) {
    throw new Error(`Unable to sign out: ${error.message}`);
  }
}
