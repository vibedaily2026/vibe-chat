-- Allow each authenticated member to see only the profiles they personally blocked.
-- This narrowly scoped SECURITY DEFINER function avoids weakening profiles RLS policies.
create or replace function public.get_my_blocked_profiles()
returns table (
  id uuid,
  display_name text,
  username text,
  avatar_url text
)
language sql
stable
security definer
set search_path = ''
as $$
  select
    p.id,
    coalesce(to_jsonb(p)->>'display_name', to_jsonb(p)->>'displayname') as display_name,
    to_jsonb(p)->>'username' as username,
    coalesce(
      to_jsonb(p)->>'avatar_url',
      to_jsonb(p)->>'avatarurl',
      to_jsonb(p)->>'avartar'
    ) as avatar_url
  from public.user_blocks b
  join public.profiles p on p.id = b.blocked_id
  where b.blocker_id = (select auth.uid())
  order by b.created_at desc;
$$;

revoke all on function public.get_my_blocked_profiles() from public, anon;
grant execute on function public.get_my_blocked_profiles() to authenticated;
