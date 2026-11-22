-- ACHI: track when each member last read a private conversation.
-- Run this migration in the Supabase SQL Editor.

alter table public.conversation_participants
  add column if not exists last_read_at timestamptz not null default now();

drop policy if exists conversation_participants_update_own_read_at
  on public.conversation_participants;

create policy conversation_participants_update_own_read_at
on public.conversation_participants
for update to authenticated
using (user_id = (select auth.uid()))
with check (user_id = (select auth.uid()));

grant update (last_read_at)
on public.conversation_participants
to authenticated;
