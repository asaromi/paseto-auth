-- Creates the `public.profile` table used by `saveProfileMetadata` (src/services.ts)
-- to store register-time `metadata` (e.g. `full_name`) for each Supabase auth user.

create table if not exists public.profile (
  id uuid primary key references auth.users (id) on delete cascade,
  full_name varchar(64),
  created_at timestamptz not null default now(),
  updated_at timestamptz
);

-- Keep `updated_at` current on every update, since Postgres does not do this automatically.
create or replace function public.set_profile_updated_at()
returns trigger as $$
begin
  new.updated_at = now();
  return new;
end;
$$ language plpgsql;

drop trigger if exists set_profile_updated_at on public.profile;

create trigger set_profile_updated_at
  before update on public.profile
  for each row
  execute function public.set_profile_updated_at();

-- Restrict access so a user can only read/write their own profile row.
alter table public.profile enable row level security;

drop policy if exists "Users can view own profile" on public.profile;
create policy "Users can view own profile"
  on public.profile for select
  using (id = auth.uid());

drop policy if exists "Users can insert own profile" on public.profile;
create policy "Users can insert own profile"
  on public.profile for insert
  with check (id = auth.uid());

drop policy if exists "Users can update own profile" on public.profile;
create policy "Users can update own profile"
  on public.profile for update
  using (id = auth.uid())
  with check (id = auth.uid());
