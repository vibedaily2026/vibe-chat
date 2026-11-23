-- ACHI launch-readiness diagnostic (READ ONLY)
-- Run once in Supabase SQL Editor. This does not change any data or settings.
-- Returns the live definitions of security-sensitive RPCs, Storage configuration,
-- and the exact permissions relevant to launch.

with function_rows as (
  select
    'FUNCTION'::text as section,
    p.proname::text as object_name,
    case when p.prosecdef then 'SECURITY DEFINER' else 'INVOKER' end as status,
    pg_get_functiondef(p.oid) as details
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  where n.nspname = 'public'
    and p.proname in (
      'my_location_enabled',
      'set_my_location',
      'find_nearby_friends',
      'users_are_blocked',
      'open_direct_conversation',
      'get_my_blocked_profiles',
      'achi_is_admin'
    )
),
bucket_rows as (
  select
    'STORAGE BUCKET'::text as section,
    b.id::text as object_name,
    case when b.public then 'PUBLIC' else 'PRIVATE' end as status,
    'size_limit=' || coalesce(b.file_size_limit::text, 'NULL')
      || '; allowed_mime_types=' || coalesce(b.allowed_mime_types::text, 'NULL') as details
  from storage.buckets b
  where b.id in ('profile-photos','private-chat-media','private-support-media')
),
policy_rows as (
  select
    'STORAGE POLICY'::text as section,
    policyname::text as object_name,
    cmd::text || '; roles=' || roles::text as status,
    'USING=' || coalesce(qual, 'NULL') || '; CHECK=' || coalesce(with_check, 'NULL') as details
  from pg_policies
  where schemaname = 'storage'
    and tablename = 'objects'
    and (
      coalesce(qual, '') ilike '%profile-photos%'
      or coalesce(with_check, '') ilike '%profile-photos%'
      or coalesce(qual, '') ilike '%private-chat-media%'
      or coalesce(with_check, '') ilike '%private-chat-media%'
      or coalesce(qual, '') ilike '%private-support-media%'
      or coalesce(with_check, '') ilike '%private-support-media%'
      or policyname ilike '%profile%'
      or policyname ilike '%private_chat%'
      or policyname ilike '%support%'
    )
),
privilege_rows as (
  select
    'PERMISSION'::text as section,
    'authenticated on public.direct_messages'::text as object_name,
    'DELETE=' || has_table_privilege('authenticated', 'public.direct_messages', 'DELETE')::text
      || '; SELECT=' || has_table_privilege('authenticated', 'public.direct_messages', 'SELECT')::text
      || '; INSERT=' || has_table_privilege('authenticated', 'public.direct_messages', 'INSERT')::text as status,
    'Unsend requires DELETE privilege plus a matching DELETE RLS policy.'::text as details
)
select * from function_rows
union all select * from bucket_rows
union all select * from policy_rows
union all select * from privilege_rows
order by section, object_name;
