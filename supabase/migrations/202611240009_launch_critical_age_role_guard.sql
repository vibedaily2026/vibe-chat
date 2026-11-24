-- ACHI launch-critical safeguards: adult-only signup and profile role protection.
-- Apply this migration in the Supabase SQL Editor before enabling public registration.
-- Existing accounts are not deleted or modified by this migration.

create or replace function public.achi_enforce_minimum_age_on_signup()
returns trigger
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_dob_text text;
  v_dob date;
begin
  v_dob_text := new.raw_user_meta_data ->> 'date_of_birth';

  if v_dob_text is null or v_dob_text !~ '^\d{4}-\d{2}-\d{2}$' then
    raise exception 'ACHI requires a valid date of birth for age verification'
      using errcode = '23514';
  end if;

  begin
    v_dob := v_dob_text::date;
  exception when others then
    raise exception 'ACHI requires a valid date of birth for age verification'
      using errcode = '23514';
  end;

  if v_dob > current_date - interval '18 years' then
    raise exception 'ACHI is only available to people who are at least 18 years old'
      using errcode = '23514';
  end if;

  if v_dob < date '1900-01-01' then
    raise exception 'Please enter a valid date of birth'
      using errcode = '23514';
  end if;

  return new;
end;
$$;

drop trigger if exists achi_minimum_age_on_signup on auth.users;
create trigger achi_minimum_age_on_signup
before insert on auth.users
for each row execute function public.achi_enforce_minimum_age_on_signup();

create or replace function public.achi_guard_profile_sensitive_fields()
returns trigger
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_claim_role text := coalesce(auth.role(), '');
begin
  -- Never allow a browser-authenticated member to create or promote an admin profile.
  if v_claim_role <> 'service_role'
     and current_user not in ('postgres', 'supabase_admin')
     and not public.achi_is_admin() then
    if tg_op = 'INSERT' then
      if new.role is not null and new.role <> 'member' then
        raise exception 'Only a trusted administrator can assign an elevated profile role'
          using errcode = '42501';
      end if;
    elsif new.role is distinct from old.role then
      raise exception 'Profile roles can only be changed by a trusted administrator'
        using errcode = '42501';
    end if;
  end if;

  -- Legacy profile ages remain untouched; only new or changed values are checked.
  if tg_op = 'INSERT' then
    if new.age is not null and new.age < 18 then
      raise exception 'ACHI is only available to people who are at least 18 years old'
        using errcode = '23514';
    end if;
  elsif new.age is distinct from old.age and new.age is not null and new.age < 18 then
    raise exception 'ACHI is only available to people who are at least 18 years old'
      using errcode = '23514';
  end if;

  return new;
end;
$$;

drop trigger if exists achi_guard_profile_sensitive_fields on public.profiles;
create trigger achi_guard_profile_sensitive_fields
before insert or update on public.profiles
for each row execute function public.achi_guard_profile_sensitive_fields();

revoke all on function public.achi_enforce_minimum_age_on_signup() from public, anon, authenticated;
revoke all on function public.achi_guard_profile_sensitive_fields() from public, anon, authenticated;

-- Remove broad row-level UPDATE permission and grant only member-editable fields.
-- SELECT remains available (including existing profile reads); role is never client-editable.
revoke update on table public.profiles from authenticated;
revoke update (role) on table public.profiles from authenticated;
grant update (username, display_name, age, gender, avatar_url, bio, interests, status)
  on table public.profiles to authenticated;

notify pgrst, 'reload schema';
