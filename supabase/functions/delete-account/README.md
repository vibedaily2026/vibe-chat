# ACHI account deletion Edge Function

This function permanently deletes the currently authenticated ACHI member. It verifies the caller's JWT, removes the member's community posts and uploaded files, then deletes the Supabase Auth user. Database rows with `ON DELETE CASCADE` foreign keys are removed by PostgreSQL.

## Deploy

From the repository root, with the Supabase CLI linked to the ACHI project:

```bash
supabase functions deploy delete-account
```

Confirm the function has the following Supabase project secrets configured (the first two are normally available to Edge Functions automatically):

- `SUPABASE_URL`
- `SUPABASE_ANON_KEY`
- `SUPABASE_SERVICE_ROLE_KEY` (must be kept secret; never put it in browser code)

The function must be deployed before the Delete Account button can complete deletion.

## Important

Before production launch, verify the foreign-key cascade behavior for all account-owned tables and the retention rules for reports or records that ACHI is legally required to retain. The function intentionally does not delete reports submitted by or about a member explicitly; those records need a documented safety/legal retention policy.
