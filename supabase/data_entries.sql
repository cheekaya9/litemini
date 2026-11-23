-- Data Entry page: table, per-user permissions, row level security.
-- Safe to re-run.

-- 1) permissions on profiles (admin always has all three; set only by the admin-users function / admin)
alter table public.profiles add column if not exists can_add    boolean not null default false;
alter table public.profiles add column if not exists can_edit   boolean not null default false;
alter table public.profiles add column if not exists can_delete boolean not null default false;

-- 2) helpers (SECURITY DEFINER so policies can read profiles without recursion)
create or replace function public.my_can(p text)
returns boolean language sql stable security definer set search_path = public as $$
  select coalesce((
    select case
      when role = 'admin' then true
      when p = 'add'    then can_add
      when p = 'edit'   then can_edit
      when p = 'delete' then can_delete
      else false end
    from public.profiles where id = auth.uid() and approved
  ), false)
$$;

create or replace function public.can_view_entries()
returns boolean language sql stable security definer set search_path = public as $$
  select coalesce((
    select (role in ('admin','user')) or can_add or can_edit or can_delete
    from public.profiles where id = auth.uid() and approved
  ), false)
$$;

revoke all on function public.my_can(text) from public, anon;
revoke all on function public.can_view_entries() from public, anon;
grant execute on function public.my_can(text) to authenticated;
grant execute on function public.can_view_entries() to authenticated;

-- 3) table
create table if not exists public.data_entries (
  id            uuid primary key default gen_random_uuid(),
  daily         text not null,                -- the day / sheet name, same idea as invoices."اليومية"
  customer_name text,
  address       text,
  zone          text,
  product       text,
  phone         text,
  alt_phone     text,
  amount        numeric,
  sender        text,
  code          text,
  notes         text,
  archived      boolean not null default false,
  created_at    timestamptz not null default now(),
  created_by    uuid,
  updated_at    timestamptz not null default now(),
  updated_by    uuid
);
create index if not exists data_entries_daily_idx on public.data_entries (daily, created_at);

create or replace function public.data_entries_stamp()
returns trigger language plpgsql set search_path = public as $$
begin
  if tg_op = 'INSERT' then
    new.created_by := auth.uid(); new.created_at := now();
  end if;
  new.updated_by := auth.uid(); new.updated_at := now();
  return new;
end $$;

drop trigger if exists data_entries_stamp on public.data_entries;
create trigger data_entries_stamp before insert or update on public.data_entries
  for each row execute function public.data_entries_stamp();

-- 4) security: only logged-in users; every action checked on the server
alter table public.data_entries enable row level security;
revoke all on public.data_entries from anon;
grant select, insert, update, delete on public.data_entries to authenticated;

drop policy if exists "de read"   on public.data_entries;
drop policy if exists "de insert" on public.data_entries;
drop policy if exists "de update" on public.data_entries;
drop policy if exists "de delete" on public.data_entries;
create policy "de read"   on public.data_entries for select to authenticated using (public.can_view_entries());
create policy "de insert" on public.data_entries for insert to authenticated with check (public.my_can('add'));
create policy "de update" on public.data_entries for update to authenticated using (public.my_can('edit')) with check (public.my_can('edit'));
create policy "de delete" on public.data_entries for delete to authenticated using (public.my_can('delete'));

-- 5) list of days (daily) that have entries; runs with the caller's rights, so RLS applies
create or replace function public.data_entry_days()
returns table(daily text, n bigint, last_at timestamptz)
language sql stable security invoker set search_path = public as $$
  select daily, count(*), max(created_at) from public.data_entries group by daily order by max(created_at) desc
$$;
revoke all on function public.data_entry_days() from public, anon;
grant execute on function public.data_entry_days() to authenticated;
