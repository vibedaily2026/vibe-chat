-- ACHI: members can only read community messages posted after they joined each room.
-- Apply this migration in Supabase SQL Editor.

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
