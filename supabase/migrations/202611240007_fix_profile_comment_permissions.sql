-- Ensure authenticated members can use profile comments through Supabase REST.
-- RLS policies still restrict rows to the signed-in member and public profile comments.
grant usage on schema public to authenticated;
grant select, insert, delete on table public.profile_comments to authenticated;

drop policy if exists "Authenticated members can read profile comments" on public.profile_comments;
create policy "Authenticated members can read profile comments"
on public.profile_comments for select to authenticated using (true);

drop policy if exists "Members can post profile comments as themselves" on public.profile_comments;
create policy "Members can post profile comments as themselves"
on public.profile_comments for insert to authenticated
with check (user_id = (select auth.uid()));

drop policy if exists "Authors or profile owners can delete comments" on public.profile_comments;
create policy "Authors or profile owners can delete comments"
on public.profile_comments for delete to authenticated
using (user_id = (select auth.uid()) or profile_id = (select auth.uid()));

notify pgrst, 'reload schema';
