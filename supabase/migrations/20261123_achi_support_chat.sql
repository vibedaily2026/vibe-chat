-- ACHI private support chat: member conversations and admin inbox
-- Corrected migration: adds a protected member/admin role to ACHI profiles.
-- Run this updated file in Supabase SQL Editor.

alter table public.profiles
  add column if not exists role text not null default 'member';

do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conrelid = 'public.profiles'::regclass
      and conname = 'profiles_role_check'
  ) then
    alter table public.profiles
      add constraint profiles_role_check check (role in ('admin','member'));
  end if;
end $$;

create or replace function public.achi_is_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.profiles p
    where p.id = auth.uid()
      and p.role = 'admin'
  );
$$;

revoke all on function public.achi_is_admin() from public;
grant execute on function public.achi_is_admin() to authenticated;

-- Prevent members from assigning themselves (or anyone else) the admin role.
create or replace function public.achi_protect_profile_role()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if auth.uid() is not null and not public.achi_is_admin() then
    if tg_op = 'INSERT' and new.role <> 'member' then
      raise exception 'Only an ACHI admin can assign admin roles';
    elsif tg_op = 'UPDATE' and new.role is distinct from old.role then
      raise exception 'Only an ACHI admin can change profile roles';
    end if;
  end if;
  return new;
end;
$$;

drop trigger if exists achi_protect_profile_role on public.profiles;
create trigger achi_protect_profile_role
before insert or update of role on public.profiles
for each row execute function public.achi_protect_profile_role();

create table if not exists public.support_conversations (
  id uuid primary key default gen_random_uuid(),
  member_id uuid not null unique references auth.users(id) on delete cascade,
  subject text not null default 'general'
    check (subject in ('general','technical','account','suggestion')),
  status text not null default 'open'
    check (status in ('open','closed')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  last_message_at timestamptz not null default now(),
  member_last_read_at timestamptz not null default now(),
  admin_last_read_at timestamptz not null default now()
);

create table if not exists public.support_messages (
  id uuid primary key default gen_random_uuid(),
  conversation_id uuid not null references public.support_conversations(id) on delete cascade,
  sender_id uuid not null references auth.users(id) on delete cascade,
  message_type text not null default 'text'
    check (message_type in ('text','image')),
  body text,
  media_path text,
  created_at timestamptz not null default now(),
  constraint support_messages_content_check check (
    (message_type = 'text' and body is not null and length(trim(body)) > 0)
    or (message_type = 'image' and media_path is not null)
  )
);

create index if not exists support_messages_conversation_created_idx
  on public.support_messages (conversation_id, created_at);

create index if not exists support_conversations_updated_idx
  on public.support_conversations (updated_at desc);

alter table public.support_conversations enable row level security;
alter table public.support_messages enable row level security;

drop policy if exists "ACHI members and admins can view support conversations" on public.support_conversations;
create policy "ACHI members and admins can view support conversations"
on public.support_conversations for select to authenticated
using (member_id = auth.uid() or public.achi_is_admin());

drop policy if exists "ACHI members can create own support conversation" on public.support_conversations;
create policy "ACHI members can create own support conversation"
on public.support_conversations for insert to authenticated
with check (member_id = auth.uid());

drop policy if exists "ACHI members and admins can update support conversation" on public.support_conversations;
create policy "ACHI members and admins can update support conversation"
on public.support_conversations for update to authenticated
using (member_id = auth.uid() or public.achi_is_admin())
with check (member_id = auth.uid() or public.achi_is_admin());

drop policy if exists "ACHI members and admins can read support messages" on public.support_messages;
create policy "ACHI members and admins can read support messages"
on public.support_messages for select to authenticated
using (
  exists (
    select 1 from public.support_conversations c
    where c.id = support_messages.conversation_id
      and (c.member_id = auth.uid() or public.achi_is_admin())
  )
);

drop policy if exists "ACHI members and admins can send support messages" on public.support_messages;
create policy "ACHI members and admins can send support messages"
on public.support_messages for insert to authenticated
with check (
  sender_id = auth.uid()
  and exists (
    select 1 from public.support_conversations c
    where c.id = support_messages.conversation_id
      and (c.member_id = auth.uid() or public.achi_is_admin())
  )
);

grant select, insert, update on public.support_conversations to authenticated;
grant select, insert on public.support_messages to authenticated;

create or replace function public.achi_touch_support_conversation()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  update public.support_conversations
  set updated_at = now(),
      last_message_at = new.created_at
  where id = new.conversation_id;
  return new;
end;
$$;

drop trigger if exists achi_touch_support_conversation on public.support_messages;
create trigger achi_touch_support_conversation
after insert on public.support_messages
for each row execute function public.achi_touch_support_conversation();

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'private-support-media',
  'private-support-media',
  false,
  8388608,
  array['image/jpeg','image/png','image/webp','image/gif']
)
on conflict (id) do update set
  public = false,
  file_size_limit = 8388608,
  allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists "ACHI participants and admins can view support media" on storage.objects;
create policy "ACHI participants and admins can view support media"
on storage.objects for select to authenticated
using (
  bucket_id = 'private-support-media'
  and exists (
    select 1 from public.support_conversations c
    where c.id::text = (storage.foldername(name))[1]
      and (c.member_id = auth.uid() or public.achi_is_admin())
  )
);

drop policy if exists "ACHI participants can upload support media" on storage.objects;
create policy "ACHI participants can upload support media"
on storage.objects for insert to authenticated
with check (
  bucket_id = 'private-support-media'
  and (storage.foldername(name))[2] = auth.uid()::text
  and exists (
    select 1 from public.support_conversations c
    where c.id::text = (storage.foldername(name))[1]
      and (c.member_id = auth.uid() or public.achi_is_admin())
  )
);

drop policy if exists "ACHI users can delete own support media" on storage.objects;
create policy "ACHI users can delete own support media"
on storage.objects for delete to authenticated
using (
  bucket_id = 'private-support-media'
  and (storage.foldername(name))[2] = auth.uid()::text
);

do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (
       select 1 from pg_publication_tables
       where pubname = 'supabase_realtime'
         and schemaname = 'public'
         and tablename = 'support_messages'
     ) then
    alter publication supabase_realtime add table public.support_messages;
  end if;
end $$;
