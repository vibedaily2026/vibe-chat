-- Vibe Chat: secure one-to-one messaging foundation
-- Run this migration in the Supabase SQL Editor.

create extension if not exists pgcrypto;

create table if not exists public.conversations (
  id uuid primary key default gen_random_uuid(),
  user_a uuid not null references auth.users(id) on delete cascade,
  user_b uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint conversations_distinct_users check (user_a <> user_b),
  constraint conversations_sorted_users check (user_a < user_b),
  constraint conversations_unique_pair unique (user_a, user_b)
);

create table if not exists public.conversation_participants (
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  joined_at timestamptz not null default now(),
  primary key (conversation_id, user_id)
);

create table if not exists public.direct_messages (
  id uuid primary key default gen_random_uuid(),
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  sender_id uuid not null references auth.users(id) on delete cascade,
  message_type text not null default 'text'
    check (message_type in ('text','image','location','audio')),
  body text,
  media_path text,
  latitude double precision,
  longitude double precision,
  created_at timestamptz not null default now(),
  constraint direct_messages_payload_check check (
    (message_type = 'text' and nullif(btrim(body), '') is not null
      and media_path is null and latitude is null and longitude is null)
    or
    (message_type = 'image' and media_path is not null
      and body is null and latitude is null and longitude is null)
    or
    (message_type = 'audio' and media_path is not null
      and body is null and latitude is null and longitude is null)
    or
    (message_type = 'location' and latitude is not null and longitude is not null
      and latitude between -90 and 90 and longitude between -180 and 180
      and body is null and media_path is null)
  )
);

create index if not exists direct_messages_conversation_created_idx
  on public.direct_messages (conversation_id, created_at);

create table if not exists public.call_sessions (
  id uuid primary key default gen_random_uuid(),
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  caller_id uuid not null references auth.users(id) on delete cascade,
  callee_id uuid not null references auth.users(id) on delete cascade,
  status text not null default 'ringing'
    check (status in ('ringing','accepted','rejected','ended','missed')),
  created_at timestamptz not null default now(),
  ended_at timestamptz,
  constraint call_sessions_distinct_users check (caller_id <> callee_id)
);

create index if not exists call_sessions_conversation_created_idx
  on public.call_sessions (conversation_id, created_at desc);

create table if not exists public.call_signals (
  id bigint generated always as identity primary key,
  call_id uuid not null references public.call_sessions(id) on delete cascade,
  sender_id uuid not null references auth.users(id) on delete cascade,
  signal jsonb not null,
  created_at timestamptz not null default now()
);

create index if not exists call_signals_call_created_idx
  on public.call_signals (call_id, created_at);

create or replace function public.users_are_blocked(p_user_a uuid, p_user_b uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $
  select exists (
    select 1 from public.user_blocks b
    where (b.blocker_id = p_user_a and b.blocked_id = p_user_b)
       or (b.blocker_id = p_user_b and b.blocked_id = p_user_a)
  );
$;

revoke all on function public.users_are_blocked(uuid, uuid) from public, anon;
grant execute on function public.users_are_blocked(uuid, uuid) to authenticated;

alter table public.conversations enable row level security;
alter table public.conversation_participants enable row level security;
alter table public.direct_messages enable row level security;
alter table public.call_sessions enable row level security;
alter table public.call_signals enable row level security;

drop policy if exists conversations_read_participants on public.conversations;
create policy conversations_read_participants on public.conversations
for select to authenticated
using (
  exists (
    select 1 from public.conversation_participants cp
    where cp.conversation_id = conversations.id and cp.user_id = (select auth.uid())
  )
);

drop policy if exists conversation_participants_read_self on public.conversation_participants;
create policy conversation_participants_read_self on public.conversation_participants
for select to authenticated
using (user_id = (select auth.uid()));

drop policy if exists direct_messages_read_participants on public.direct_messages;
create policy direct_messages_read_participants on public.direct_messages
for select to authenticated
using (
  exists (
    select 1
    from public.conversation_participants cp
    join public.conversations c on c.id = cp.conversation_id
    where cp.conversation_id = direct_messages.conversation_id
      and cp.user_id = (select auth.uid())
      and (
        (c.user_a = (select auth.uid()) and c.user_b = direct_messages.sender_id)
        or (c.user_b = (select auth.uid()) and c.user_a = direct_messages.sender_id)
        or direct_messages.sender_id = (select auth.uid())
      )
      and not public.users_are_blocked(c.user_a, c.user_b)
  )
);

drop policy if exists direct_messages_insert_sender on public.direct_messages;
create policy direct_messages_insert_sender on public.direct_messages
for insert to authenticated
with check (
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

drop policy if exists call_sessions_read_participants on public.call_sessions;
create policy call_sessions_read_participants on public.call_sessions
for select to authenticated
using (
  caller_id = (select auth.uid()) or callee_id = (select auth.uid())
);

drop policy if exists call_sessions_insert_caller on public.call_sessions;
create policy call_sessions_insert_caller on public.call_sessions
for insert to authenticated
with check (
  caller_id = (select auth.uid())
  and exists (
    select 1 from public.conversations c
    where c.id = call_sessions.conversation_id
      and (
        (c.user_a = caller_id and c.user_b = callee_id)
        or (c.user_b = caller_id and c.user_a = callee_id)
      )
      and not public.users_are_blocked(c.user_a, c.user_b)
  )
);

drop policy if exists call_sessions_update_participants on public.call_sessions;
create policy call_sessions_update_participants on public.call_sessions
for update to authenticated
using (caller_id = (select auth.uid()) or callee_id = (select auth.uid()))
with check (caller_id = (select auth.uid()) or callee_id = (select auth.uid()));

drop policy if exists call_signals_read_call_participants on public.call_signals;
create policy call_signals_read_call_participants on public.call_signals
for select to authenticated
using (
  exists (
    select 1 from public.call_sessions cs
    where cs.id = call_signals.call_id
      and (cs.caller_id = (select auth.uid()) or cs.callee_id = (select auth.uid()))
  )
);

drop policy if exists call_signals_insert_sender on public.call_signals;
create policy call_signals_insert_sender on public.call_signals
for insert to authenticated
with check (
  sender_id = (select auth.uid())
  and exists (
    select 1 from public.call_sessions cs
    where cs.id = call_signals.call_id
      and (cs.caller_id = (select auth.uid()) or cs.callee_id = (select auth.uid()))
      and cs.status in ('ringing','accepted')
  )
);

create or replace function public.open_direct_conversation(p_other_user_id uuid)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_me uuid := (select auth.uid());
  v_a uuid;
  v_b uuid;
  v_conversation_id uuid;
begin
  if v_me is null then
    raise exception 'Authentication required';
  end if;
  if p_other_user_id is null or p_other_user_id = v_me then
    raise exception 'Choose another member';
  end if;
  if not exists (select 1 from auth.users u where u.id = p_other_user_id) then
    raise exception 'Member not found';
  end if;
  if exists (
    select 1 from public.user_blocks b
    where (b.blocker_id = v_me and b.blocked_id = p_other_user_id)
       or (b.blocker_id = p_other_user_id and b.blocked_id = v_me)
  ) then
    raise exception 'Messaging is unavailable for this member';
  end if;

  v_a := least(v_me, p_other_user_id);
  v_b := greatest(v_me, p_other_user_id);

  insert into public.conversations(user_a, user_b)
  values (v_a, v_b)
  on conflict (user_a, user_b) do nothing;

  select c.id into v_conversation_id
  from public.conversations c
  where c.user_a = v_a and c.user_b = v_b;

  insert into public.conversation_participants(conversation_id, user_id)
  values (v_conversation_id, v_a), (v_conversation_id, v_b)
  on conflict do nothing;

  return v_conversation_id;
end;
$$;

revoke all on function public.open_direct_conversation(uuid) from public, anon;
grant execute on function public.open_direct_conversation(uuid) to authenticated;

grant select on public.conversations, public.conversation_participants,
  public.direct_messages, public.call_sessions, public.call_signals to authenticated;
grant insert on public.direct_messages, public.call_sessions, public.call_signals to authenticated;
grant update (status, ended_at) on public.call_sessions to authenticated;
grant usage, select on sequence public.call_signals_id_seq to authenticated;

-- Private media bucket. File path format: <conversation UUID>/<sender UUID>/<random filename>
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'private-chat-media',
  'private-chat-media',
  false,
  20971520,
  array['image/jpeg','image/png','image/webp','image/gif','audio/webm','audio/ogg','audio/mp4','audio/mpeg']
)
on conflict (id) do update set
  public = false,
  file_size_limit = 20971520,
  allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists private_chat_media_read on storage.objects;
create policy private_chat_media_read on storage.objects
for select to authenticated
using (
  bucket_id = 'private-chat-media'
  and exists (
    select 1 from public.conversations c
    where c.id::text = (storage.foldername(name))[1]
      and (c.user_a = (select auth.uid()) or c.user_b = (select auth.uid()))
      and not public.users_are_blocked(c.user_a, c.user_b)
  )
);

drop policy if exists private_chat_media_insert on storage.objects;
create policy private_chat_media_insert on storage.objects
for insert to authenticated
with check (
  bucket_id = 'private-chat-media'
  and (storage.foldername(name))[2] = (select auth.uid())::text
  and exists (
    select 1 from public.conversations c
    where c.id::text = (storage.foldername(name))[1]
      and (c.user_a = (select auth.uid()) or c.user_b = (select auth.uid()))
      and not public.users_are_blocked(c.user_a, c.user_b)
  )
);

drop policy if exists private_chat_media_delete_own on storage.objects;
create policy private_chat_media_delete_own on storage.objects
for delete to authenticated
using (
  bucket_id = 'private-chat-media'
  and (storage.foldername(name))[2] = (select auth.uid())::text
);


-- Enable Supabase Realtime for private message and call signaling events.
do $$
declare
  v_table text;
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    foreach v_table in array array['direct_messages','call_sessions','call_signals'] loop
      if not exists (
        select 1 from pg_publication_tables
        where pubname = 'supabase_realtime'
          and schemaname = 'public'
          and tablename = v_table
      ) then
        execute format('alter publication supabase_realtime add table public.%I', v_table);
      end if;
    end loop;
  end if;
end $$;
