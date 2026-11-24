-- Scope helper RPCs to a conversation participant.
-- Prevent authenticated callers from probing whether two unrelated users have blocked each other.
create or replace function public.users_are_blocked(p_user_a uuid, p_user_b uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select
    (select auth.uid()) is not null
    and (select auth.uid()) in (p_user_a, p_user_b)
    and exists (
      select 1
      from public.user_blocks b
      where (b.blocker_id = p_user_a and b.blocked_id = p_user_b)
         or (b.blocker_id = p_user_b and b.blocked_id = p_user_a)
    );
$$;

-- A reply target must belong to a conversation in which the caller is an actual participant.
create or replace function public.achi_can_reply_to_direct_message(
  p_reply_id uuid,
  p_conversation_id uuid,
  p_user_id uuid
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select
    p_user_id = (select auth.uid())
    and exists (
      select 1
      from public.direct_messages parent
      join public.conversations c on c.id = parent.conversation_id
      join public.conversation_participants cp
        on cp.conversation_id = c.id
       and cp.user_id = (select auth.uid())
      where parent.id = p_reply_id
        and parent.conversation_id = p_conversation_id
        and (
          (c.user_a = (select auth.uid()) and c.user_b <> (select auth.uid()))
          or (c.user_b = (select auth.uid()) and c.user_a <> (select auth.uid()))
        )
        and not exists (
          select 1
          from public.user_blocks b
          where (b.blocker_id = c.user_a and b.blocked_id = c.user_b)
             or (b.blocker_id = c.user_b and b.blocked_id = c.user_a)
        )
    );
$$;

revoke all on function public.users_are_blocked(uuid, uuid) from public, anon;
grant execute on function public.users_are_blocked(uuid, uuid) to authenticated;
revoke all on function public.achi_can_reply_to_direct_message(uuid, uuid, uuid) from public, anon;
grant execute on function public.achi_can_reply_to_direct_message(uuid, uuid, uuid) to authenticated;
