-- ACHI public member status and profile comments
alter table public.profiles add column if not exists status text not null default '';
do $$ begin if not exists (select 1 from pg_constraint where conname='profiles_status_length_check') then alter table public.profiles add constraint profiles_status_length_check check(char_length(status)<=160); end if; end $$;
create table if not exists public.profile_comments(id uuid primary key default gen_random_uuid(),profile_id uuid not null references public.profiles(id) on delete cascade,user_id uuid not null references auth.users(id) on delete cascade,content text not null check(char_length(btrim(content)) between 1 and 500),created_at timestamptz not null default now());
create index if not exists profile_comments_profile_created_idx on public.profile_comments(profile_id,created_at desc);
alter table public.profile_comments enable row level security;
drop policy if exists "Authenticated members can read profile comments" on public.profile_comments;
create policy "Authenticated members can read profile comments" on public.profile_comments for select to authenticated using(true);
drop policy if exists "Members can post profile comments as themselves" on public.profile_comments;
create policy "Members can post profile comments as themselves" on public.profile_comments for insert to authenticated with check(user_id=auth.uid());
drop policy if exists "Authors or profile owners can delete comments" on public.profile_comments;
create policy "Authors or profile owners can delete comments" on public.profile_comments for delete to authenticated using(user_id=auth.uid() or profile_id=auth.uid());
