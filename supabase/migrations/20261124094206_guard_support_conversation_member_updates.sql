-- Restrict member edits to their own support conversation settings and read state.
-- Admin-only read markers and system-maintained metadata are protected by a trigger.
create or replace function public.achi_guard_support_conversation_updates()
returns trigger
language plpgsql
security invoker
set search_path = ''
as $$
begin
  if (select auth.uid()) is not null and not public.achi_is_admin() then
    if new.id is distinct from old.id
       or new.member_id is distinct from old.member_id
       or new.created_at is distinct from old.created_at
       or new.admin_last_read_at is distinct from old.admin_last_read_at
       or new.last_message_at is distinct from old.last_message_at
       or new.updated_at is distinct from old.updated_at then
      raise exception 'Members may only update their support conversation settings and read state'
        using errcode = '42501';
    end if;
  end if;
  return new;
end;
$$;

drop trigger if exists achi_guard_support_conversation_updates on public.support_conversations;
create trigger achi_guard_support_conversation_updates
before update on public.support_conversations
for each row execute function public.achi_guard_support_conversation_updates();

revoke all on function public.achi_guard_support_conversation_updates() from public, anon, authenticated;

revoke update on table public.support_conversations from authenticated;
grant update (subject, status, member_last_read_at, admin_last_read_at)
  on table public.support_conversations to authenticated;
