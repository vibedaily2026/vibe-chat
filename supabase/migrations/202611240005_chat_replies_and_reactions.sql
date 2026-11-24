-- ACHI: add reply threads and emoji reactions to private and community messages.
-- Safe to apply more than once in Supabase SQL Editor.

-- Community messages use bigint IDs; private direct_messages use UUID IDs.
-- Repair an earlier partially-applied version that may have created this column as UUID.
do $$
declare
  v_type text;
begin
  select data_type into v_type
  from information_schema.columns
  where table_schema='public' and table_name='messages' and column_name='reply_to_id';

  if v_type='uuid' then
    if exists (select 1 from public.messages where reply_to_id is not null) then
      raise exception 'public.messages.reply_to_id is UUID and contains values; manual review is required before converting it to bigint';
    end if;
    alter table public.messages drop column reply_to_id;
  end if;
end $$;

alter table public.messages
  add column if not exists reply_to_id bigint
  references public.messages(id) on delete set null;

alter table public.direct_messages
  add column if not exists reply_to_id uuid
  references public.direct_messages(id) on delete set null;

create index if not exists messages_reply_to_id_idx
  on public.messages(reply_to_id);
create index if not exists direct_messages_reply_to_id_idx
  on public.direct_messages(reply_to_id);

create table if not exists public.community_message_reactions (
  id uuid primary key default gen_random_uuid(),
  message_id bigint not null references public.messages(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  emoji text not null check (emoji in ('❤️','😂','😍','👍','😢','😮','🔥','👏')),
  created_at timestamptz not null default now(),
  unique (message_id,user_id)
);

create table if not exists public.direct_message_reactions (
  id uuid primary key default gen_random_uuid(),
  message_id uuid not null references public.direct_messages(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  emoji text not null check (emoji in ('❤️','😂','😍','👍','😢','😮','🔥','👏')),
  created_at timestamptz not null default now(),
  unique (message_id,user_id)
);

create index if not exists community_message_reactions_message_idx
  on public.community_message_reactions(message_id);
create index if not exists direct_message_reactions_message_idx
  on public.direct_message_reactions(message_id);

alter table public.community_message_reactions enable row level security;
alter table public.direct_message_reactions enable row level security;
alter table public.community_message_reactions replica identity full;
alter table public.direct_message_reactions replica identity full;

drop policy if exists community_reactions_read_visible_messages on public.community_message_reactions;
create policy community_reactions_read_visible_messages
on public.community_message_reactions for select to authenticated
using (
  exists (
    select 1
    from public.messages m
    join public.community_room_members crm on crm.room_id=m.room_id
    where m.id=community_message_reactions.message_id
      and crm.user_id=(select auth.uid())
      and m.created_at >= crm.joined_at
  )
);

drop policy if exists community_reactions_insert_own on public.community_message_reactions;
create policy community_reactions_insert_own
on public.community_message_reactions for insert to authenticated
with check (
  user_id=(select auth.uid())
  and exists (
    select 1
    from public.messages m
    join public.community_room_members crm on crm.room_id=m.room_id
    where m.id=community_message_reactions.message_id
      and crm.user_id=(select auth.uid())
      and m.created_at >= crm.joined_at
  )
);

drop policy if exists community_reactions_update_own on public.community_message_reactions;
create policy community_reactions_update_own
on public.community_message_reactions for update to authenticated
using (user_id=(select auth.uid()))
with check (
  user_id=(select auth.uid())
  and exists (
    select 1
    from public.messages m
    join public.community_room_members crm on crm.room_id=m.room_id
    where m.id=community_message_reactions.message_id
      and crm.user_id=(select auth.uid())
      and m.created_at >= crm.joined_at
  )
);

drop policy if exists community_reactions_delete_own on public.community_message_reactions;
create policy community_reactions_delete_own
on public.community_message_reactions for delete to authenticated
using (user_id=(select auth.uid()));

drop policy if exists direct_reactions_read_participants on public.direct_message_reactions;
create policy direct_reactions_read_participants
on public.direct_message_reactions for select to authenticated
using (
  exists (
    select 1
    from public.direct_messages dm
    join public.conversation_participants cp on cp.conversation_id=dm.conversation_id
    join public.conversations c on c.id=dm.conversation_id
    where dm.id=direct_message_reactions.message_id
      and cp.user_id=(select auth.uid())
      and (c.user_a=(select auth.uid()) or c.user_b=(select auth.uid()))
      and not public.users_are_blocked(c.user_a,c.user_b)
  )
);

drop policy if exists direct_reactions_insert_own on public.direct_message_reactions;
create policy direct_reactions_insert_own
on public.direct_message_reactions for insert to authenticated
with check (
  user_id=(select auth.uid())
  and exists (
    select 1
    from public.direct_messages dm
    join public.conversation_participants cp on cp.conversation_id=dm.conversation_id
    join public.conversations c on c.id=dm.conversation_id
    where dm.id=direct_message_reactions.message_id
      and cp.user_id=(select auth.uid())
      and (c.user_a=(select auth.uid()) or c.user_b=(select auth.uid()))
      and not public.users_are_blocked(c.user_a,c.user_b)
  )
);

drop policy if exists direct_reactions_update_own on public.direct_message_reactions;
create policy direct_reactions_update_own
on public.direct_message_reactions for update to authenticated
using (user_id=(select auth.uid()))
with check (user_id=(select auth.uid()));

drop policy if exists direct_reactions_delete_own on public.direct_message_reactions;
create policy direct_reactions_delete_own
on public.direct_message_reactions for delete to authenticated
using (user_id=(select auth.uid()));


-- Validate community reply targets in a SECURITY DEFINER helper to avoid recursive RLS on messages.
create or replace function public.achi_can_reply_to_community_message(p_reply_id bigint,p_room_id uuid,p_user_id uuid)
returns boolean
language sql
stable
security definer
set search_path=''
as $$
  select p_user_id=(select auth.uid()) and exists (
    select 1
    from public.messages parent
    join public.community_room_members crm on crm.room_id=parent.room_id
    where parent.id=p_reply_id
      and parent.room_id=p_room_id
      and crm.user_id=p_user_id
      and parent.created_at>=crm.joined_at
  );
$$;
revoke all on function public.achi_can_reply_to_community_message(bigint,uuid,uuid) from public,anon;
grant execute on function public.achi_can_reply_to_community_message(bigint,uuid,uuid) to authenticated;

drop policy if exists "ACHI members can send community room messages" on public.messages;
create policy "ACHI members can send community room messages"
on public.messages for insert to authenticated
with check (
  user_id=auth.uid()::text
  and exists (
    select 1 from public.community_room_members crm
    where crm.room_id=messages.room_id and crm.user_id=auth.uid()
  )
  and (
    reply_to_id is null
    or public.achi_can_reply_to_community_message(reply_to_id,room_id,auth.uid())
  )
);

-- Validate direct-message reply targets without recursively invoking direct_messages RLS.
create or replace function public.achi_can_reply_to_direct_message(p_reply_id uuid,p_conversation_id uuid,p_user_id uuid)
returns boolean
language sql
stable
security definer
set search_path=''
as $
  select p_user_id=(select auth.uid()) and exists (
    select 1
    from public.direct_messages parent
    where parent.id=p_reply_id
      and parent.conversation_id=p_conversation_id
  );
$;
revoke all on function public.achi_can_reply_to_direct_message(uuid,uuid,uuid) from public,anon;
grant execute on function public.achi_can_reply_to_direct_message(uuid,uuid,uuid) to authenticated;

drop policy if exists direct_messages_insert_sender on public.direct_messages;
create policy direct_messages_insert_sender on public.direct_messages
for insert to authenticated
with check (
  sender_id=(select auth.uid())
  and exists (
    select 1 from public.conversation_participants cp
    join public.conversations c on c.id=cp.conversation_id
    where cp.conversation_id=direct_messages.conversation_id
      and cp.user_id=(select auth.uid())
      and (c.user_a=(select auth.uid()) or c.user_b=(select auth.uid()))
      and not public.users_are_blocked(c.user_a,c.user_b)
  )
  and (
    reply_to_id is null
    or public.achi_can_reply_to_direct_message(reply_to_id,conversation_id,auth.uid())
  )
);

-- Ensure reaction updates/deletes remain limited to messages visible to the member.
drop policy if exists community_reactions_update_own on public.community_message_reactions;
create policy community_reactions_update_own
on public.community_message_reactions for update to authenticated
using (
  user_id=(select auth.uid())
  and exists (
    select 1 from public.messages m
    join public.community_room_members crm on crm.room_id=m.room_id
    where m.id=community_message_reactions.message_id
      and crm.user_id=(select auth.uid()) and m.created_at>=crm.joined_at
  )
)
with check (
  user_id=(select auth.uid())
  and exists (
    select 1 from public.messages m
    join public.community_room_members crm on crm.room_id=m.room_id
    where m.id=community_message_reactions.message_id
      and crm.user_id=(select auth.uid()) and m.created_at>=crm.joined_at
  )
);
drop policy if exists community_reactions_delete_own on public.community_message_reactions;
create policy community_reactions_delete_own
on public.community_message_reactions for delete to authenticated
using (
  user_id=(select auth.uid())
  and exists (
    select 1 from public.messages m
    join public.community_room_members crm on crm.room_id=m.room_id
    where m.id=community_message_reactions.message_id
      and crm.user_id=(select auth.uid()) and m.created_at>=crm.joined_at
  )
);

drop policy if exists direct_reactions_update_own on public.direct_message_reactions;
create policy direct_reactions_update_own
on public.direct_message_reactions for update to authenticated
using (
  user_id=(select auth.uid())
  and exists (
    select 1 from public.direct_messages dm
    join public.conversation_participants cp on cp.conversation_id=dm.conversation_id
    join public.conversations c on c.id=dm.conversation_id
    where dm.id=direct_message_reactions.message_id
      and cp.user_id=(select auth.uid())
      and not public.users_are_blocked(c.user_a,c.user_b)
  )
)
with check (
  user_id=(select auth.uid())
  and exists (
    select 1 from public.direct_messages dm
    join public.conversation_participants cp on cp.conversation_id=dm.conversation_id
    join public.conversations c on c.id=dm.conversation_id
    where dm.id=direct_message_reactions.message_id
      and cp.user_id=(select auth.uid())
      and not public.users_are_blocked(c.user_a,c.user_b)
  )
);
drop policy if exists direct_reactions_delete_own on public.direct_message_reactions;
create policy direct_reactions_delete_own
on public.direct_message_reactions for delete to authenticated
using (
  user_id=(select auth.uid())
  and exists (
    select 1 from public.direct_messages dm
    join public.conversation_participants cp on cp.conversation_id=dm.conversation_id
    join public.conversations c on c.id=dm.conversation_id
    where dm.id=direct_message_reactions.message_id
      and cp.user_id=(select auth.uid())
      and not public.users_are_blocked(c.user_a,c.user_b)
  )
);

grant select,insert,update,delete on public.community_message_reactions to authenticated;
grant select,insert,update,delete on public.direct_message_reactions to authenticated;

-- Keep reaction updates live for clients subscribed to Supabase Realtime.
do $$
begin
  if exists (select 1 from pg_publication where pubname='supabase_realtime') then
    if not exists (select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename='community_message_reactions') then
      alter publication supabase_realtime add table public.community_message_reactions;
    end if;
    if not exists (select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename='direct_message_reactions') then
      alter publication supabase_realtime add table public.direct_message_reactions;
    end if;
  end if;
end $$;
