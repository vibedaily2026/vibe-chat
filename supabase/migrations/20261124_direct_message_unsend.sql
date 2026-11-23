-- ACHI: allow members to unsend only their own private messages.
-- Safe to run more than once. Apply in Supabase SQL Editor before testing unsend.

create or replace function public.users_are_blocked(p_user_a uuid, p_user_b uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.user_blocks b
    where (b.blocker_id = p_user_a and b.blocked_id = p_user_b)
       or (b.blocker_id = p_user_b and b.blocked_id = p_user_a)
  );
$$;

revoke all on function public.users_are_blocked(uuid, uuid) from public, anon;
grant execute on function public.users_are_blocked(uuid, uuid) to authenticated;

grant delete on public.direct_messages to authenticated;

drop policy if exists direct_messages_delete_own on public.direct_messages;
create policy direct_messages_delete_own
on public.direct_messages
for delete
to authenticated
using (
  sender_id = (select auth.uid())
  and exists (
    select 1
    from public.conversation_participants cp
    join public.conversations c on c.id = cp.conversation_id
    where cp.conversation_id = direct_messages.conversation_id
      and cp.user_id = (select auth.uid())
      and (c.user_a = (select auth.uid()) or c.user_b = (select auth.uid()))
      and not public.users_are_blocked(c.user_a, c.user_b)
  )
);
