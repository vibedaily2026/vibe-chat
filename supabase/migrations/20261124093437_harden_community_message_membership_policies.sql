-- Remove legacy permissive policies that bypass community-room membership.
-- Keep the ACHI membership-scoped SELECT and INSERT policies intact.
drop policy if exists "Members can read messages" on public.messages;
drop policy if exists "Members can send their own messages" on public.messages;
