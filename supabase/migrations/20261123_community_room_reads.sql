-- ACHI community room read receipts
-- Run once in Supabase SQL Editor. Safe to run again.

create table if not exists public.community_room_reads (
  user_id uuid not null references auth.users(id) on delete cascade,
  room_id uuid not null references public.community_rooms(id) on delete cascade,
  last_read_at timestamptz not null default now(),
  primary key (user_id, room_id)
);

alter table public.community_room_reads enable row level security;

drop policy if exists "ACHI members can read own community room read state"
on public.community_room_reads;
create policy "ACHI members can read own community room read state"
on public.community_room_reads
for select
to authenticated
using (user_id = auth.uid());

drop policy if exists "ACHI members can create own community room read state"
on public.community_room_reads;
create policy "ACHI members can create own community room read state"
on public.community_room_reads
for insert
to authenticated
with check (user_id = auth.uid());

drop policy if exists "ACHI members can update own community room read state"
on public.community_room_reads;
create policy "ACHI members can update own community room read state"
on public.community_room_reads
for update
to authenticated
using (user_id = auth.uid())
with check (user_id = auth.uid());

grant select, insert, update on public.community_room_reads to authenticated;
