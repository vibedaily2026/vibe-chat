-- Restore ACHI community rooms and their membership/read-state tables.
-- Safe to run more than once in Supabase SQL Editor.

create table if not exists public.community_rooms (
  id uuid primary key default gen_random_uuid(),
  slug text not null unique,
  name_th text not null,
  name_en text not null,
  description_th text not null default '',
  description_en text not null default '',
  emoji text not null default '💬',
  created_at timestamptz not null default now()
);

alter table public.community_rooms enable row level security;
drop policy if exists "ACHI members can view community rooms" on public.community_rooms;
create policy "ACHI members can view community rooms"
on public.community_rooms for select to authenticated
using (true);
grant select on public.community_rooms to authenticated;

insert into public.community_rooms
  (slug, name_th, name_en, description_th, description_en, emoji)
values
  ('general', 'ห้องพูดคุยทั่วไป', 'General Chat', 'พูดคุยทั่วไป พบปะสมาชิกใหม่ และแบ่งปันเรื่องราว', 'Meet members, say hello, and share everyday conversations', '🌏'),
  ('gaming', 'ห้องเกม', 'Gaming', 'พูดคุยเรื่องเกม หาเพื่อนเล่นเกม และแลกเปลี่ยนประสบการณ์', 'Talk games, find gaming buddies, and share your experiences', '🎮'),
  ('music', 'ห้องดนตรี', 'Music', 'พูดคุยเรื่องเพลง ศิลปิน และแบ่งปันเพลงที่ชอบ', 'Talk about music and artists, and share songs you love', '🎵'),
  ('friends', 'ห้องหาเพื่อน', 'Meet New Friends', 'ทำความรู้จักสมาชิกใหม่และหาเพื่อนคุย', 'Meet new members and make friends', '💬')
on conflict (slug) do update set
  name_th = excluded.name_th,
  name_en = excluded.name_en,
  description_th = excluded.description_th,
  description_en = excluded.description_en,
  emoji = excluded.emoji;

create table if not exists public.community_room_members (
  room_id uuid not null references public.community_rooms(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  joined_at timestamptz not null default now(),
  primary key (room_id, user_id)
);

alter table public.community_room_members enable row level security;
drop policy if exists "Members can view own community room memberships" on public.community_room_members;
create policy "Members can view own community room memberships"
on public.community_room_members for select to authenticated
using (user_id = auth.uid());
drop policy if exists "Members can join community rooms" on public.community_room_members;
create policy "Members can join community rooms"
on public.community_room_members for insert to authenticated
with check (user_id = auth.uid());
grant select, insert on public.community_room_members to authenticated;

create table if not exists public.community_room_reads (
  user_id uuid not null references auth.users(id) on delete cascade,
  room_id uuid not null references public.community_rooms(id) on delete cascade,
  last_read_at timestamptz not null default now(),
  primary key (user_id, room_id)
);

alter table public.community_room_reads enable row level security;
drop policy if exists "ACHI members can read own community room read state" on public.community_room_reads;
create policy "ACHI members can read own community room read state"
on public.community_room_reads for select to authenticated
using (user_id = auth.uid());
drop policy if exists "ACHI members can create own community room read state" on public.community_room_reads;
create policy "ACHI members can create own community room read state"
on public.community_room_reads for insert to authenticated
with check (user_id = auth.uid());
drop policy if exists "ACHI members can update own community room read state" on public.community_room_reads;
create policy "ACHI members can update own community room read state"
on public.community_room_reads for update to authenticated
using (user_id = auth.uid())
with check (user_id = auth.uid());
grant select, insert, update on public.community_room_reads to authenticated;

alter table public.messages add column if not exists room_id uuid;
update public.messages
set room_id = (select id from public.community_rooms where slug = 'general')
where room_id is null;

do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'messages_room_id_fkey'
      and conrelid = 'public.messages'::regclass
  ) then
    alter table public.messages
      add constraint messages_room_id_fkey
      foreign key (room_id) references public.community_rooms(id)
      on delete restrict;
  end if;
end $$;

alter table public.messages alter column room_id set not null;
create index if not exists messages_room_created_at_idx
  on public.messages (room_id, created_at);

alter table public.messages enable row level security;
drop policy if exists "ACHI members can read community room messages" on public.messages;
create policy "ACHI members can read community room messages"
on public.messages for select to authenticated
using (
  exists (
    select 1 from public.community_room_members m
    where m.room_id = messages.room_id
      and m.user_id = auth.uid()
      and messages.created_at >= m.joined_at
  )
);
drop policy if exists "ACHI members can send community room messages" on public.messages;
create policy "ACHI members can send community room messages"
on public.messages for insert to authenticated
with check (
  user_id = auth.uid()::text
  and exists (
    select 1 from public.community_room_members m
    where m.room_id = messages.room_id
      and m.user_id = auth.uid()
  )
);
grant select, insert on public.messages to authenticated;
