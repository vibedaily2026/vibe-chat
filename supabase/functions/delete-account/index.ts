import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "https://achi-three.vercel.app",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Vary": "Origin",
};

function response(body: Record<string, unknown>, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

async function listAllFiles(admin: ReturnType<typeof createClient>, bucket: string, folder = ""): Promise<string[]> {
  const files: string[] = [];
  let offset = 0;
  while (true) {
    const { data, error } = await admin.storage.from(bucket).list(folder, {
      limit: 1000,
      offset,
      sortBy: { column: "name", order: "asc" },
    });
    if (error) throw new Error(`Could not list ${bucket}/${folder}: ${error.message}`);
    const entries = data ?? [];
    for (const entry of entries) {
      const path = folder ? `${folder}/${entry.name}` : entry.name;
      if (entry.id === null) {
        files.push(...await listAllFiles(admin, bucket, path));
      } else {
        files.push(path);
      }
    }
    if (entries.length < 1000) break;
    offset += entries.length;
  }
  return files;
}

async function removeUserStorage(admin: ReturnType<typeof createClient>, userId: string) {
  // Profile photos are stored under the member's user ID.
  const { data: profileEntries, error: profileListError } = await admin.storage
    .from("profile-photos")
    .list(userId, { limit: 1000 });
  if (profileListError) throw new Error(`Could not list profile photos: ${profileListError.message}`);
  const profilePaths = (profileEntries ?? [])
    .filter((entry) => entry.id !== null)
    .map((entry) => `${userId}/${entry.name}`);
  if (profilePaths.length) {
    const { error } = await admin.storage.from("profile-photos").remove(profilePaths);
    if (error) throw new Error(`Could not remove profile photos: ${error.message}`);
  }

  // Private media paths are conversation-or-ticket ID / user ID / file.
  for (const bucket of ["private-chat-media", "private-support-media"]) {
    const rootEntries = await admin.storage.from(bucket).list("", { limit: 1000 });
    if (rootEntries.error) throw new Error(`Could not list ${bucket}: ${rootEntries.error.message}`);
    for (const root of rootEntries.data ?? []) {
      if (root.id !== null) continue;
      const memberFolder = `${root.name}/${userId}`;
      const { data: memberEntries, error } = await admin.storage.from(bucket).list(memberFolder, { limit: 1000 });
      if (error) throw new Error(`Could not list ${bucket}/${memberFolder}: ${error.message}`);
      const paths = (memberEntries ?? [])
        .filter((entry) => entry.id !== null)
        .map((entry) => `${memberFolder}/${entry.name}`);
      if (paths.length) {
        const { error: removeError } = await admin.storage.from(bucket).remove(paths);
        if (removeError) throw new Error(`Could not remove files from ${bucket}: ${removeError.message}`);
      }
    }
  }
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return response({ error: "Method not allowed" }, 405);

  const origin = req.headers.get("Origin");
  if (origin && origin !== "https://achi-three.vercel.app" && !origin.startsWith("http://localhost:")) {
    return response({ error: "Origin not allowed" }, 403);
  }

  const authorization = req.headers.get("Authorization");
  if (!authorization?.startsWith("Bearer ")) return response({ error: "Authentication required" }, 401);

  const supabaseUrl = Deno.env.get("SUPABASE_URL");
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
  const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!supabaseUrl || !anonKey || !serviceRoleKey) {
    return response({ error: "Account deletion service is not configured" }, 500);
  }

  const token = authorization.slice("Bearer ".length);
  const authClient = createClient(supabaseUrl, anonKey, {
    global: { headers: { Authorization: authorization } },
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const { data: { user }, error: userError } = await authClient.auth.getUser(token);
  if (userError || !user) return response({ error: "Invalid or expired session" }, 401);

  const admin = createClient(supabaseUrl, serviceRoleKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  try {
    // Remove the member's public community posts because messages.user_id is a text
    // column and may not be covered by an auth.users foreign-key cascade.
    const { error: messagesError } = await admin.from("messages").delete().eq("user_id", user.id);
    if (messagesError) throw new Error(`Could not remove community messages: ${messagesError.message}`);

    // Remove uploaded media before deleting the Auth user.
    await removeUserStorage(admin, user.id);

    // Auth deletion cascades through account-owned rows with ON DELETE CASCADE
    // foreign keys (profile, blocks, conversations, direct/support messages, etc.).
    const { error: deleteError } = await admin.auth.admin.deleteUser(user.id);
    if (deleteError) throw new Error(`Could not delete authentication account: ${deleteError.message}`);

    return response({ success: true });
  } catch (error) {
    console.error("ACHI account deletion failed", error);
    return response({ error: error instanceof Error ? error.message : "Account deletion failed" }, 500);
  }
});
