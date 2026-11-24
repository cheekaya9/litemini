-- داتا انتري (zone) inside minilite: tables + permissions (re-runnable).
-- Uses the same permission model as the accounts page: profiles.can_add / can_edit / can_delete (admin = all).

-- helper: anyone who may write at least something (needed for the shared settings table)
create or replace function public.can_write_entries()
returns boolean language sql stable security definer set search_path = public as $$
  select coalesce((
    select (role = 'admin') or can_add or can_edit or can_delete
    from public.profiles where id = auth.uid() and approved
  ), false)
$$;
revoke all on function public.can_write_entries() from public, anon;
grant execute on function public.can_write_entries() to authenticated;

create table if not exists public.zone_shipments (
  id          uuid primary key default gen_random_uuid(),
  day         text not null,
  tab         text not null check (tab in ('w','t','b','g','q','k','h')),
  pos         integer not null default 0,
  data        jsonb not null default '{}'::jsonb,
  version     integer not null default 1,
  updated_at  timestamptz not null default now(),
  updated_by  uuid default auth.uid()
);
create index if not exists zone_shipments_day_tab_pos_idx on public.zone_shipments (day, tab, pos);
create index if not exists zone_shipments_updated_idx on public.zone_shipments (updated_at, id);

create table if not exists public.zone_settings (
  key         text primary key,
  value       jsonb not null default '{}'::jsonb,
  version     integer not null default 1,
  updated_at  timestamptz not null default now(),
  updated_by  uuid default auth.uid()
);

create or replace function public.zone_bump_row()
returns trigger language plpgsql set search_path = public as $$
begin
  new.version    := old.version + 1;
  new.updated_at := now();
  new.updated_by := auth.uid();
  return new;
end $$;

create or replace trigger zone_shipments_bump before update on public.zone_shipments
  for each row execute function public.zone_bump_row();
create or replace trigger zone_settings_bump before update on public.zone_settings
  for each row execute function public.zone_bump_row();

alter table public.zone_shipments enable row level security;
alter table public.zone_settings  enable row level security;
revoke all on public.zone_shipments from anon;
revoke all on public.zone_settings  from anon;
grant select, insert, update, delete on public.zone_shipments to authenticated;
grant select, insert, update on public.zone_settings to authenticated;

drop policy if exists "zs read"   on public.zone_shipments;
drop policy if exists "zs insert" on public.zone_shipments;
drop policy if exists "zs update" on public.zone_shipments;
drop policy if exists "zs delete" on public.zone_shipments;
create policy "zs read"   on public.zone_shipments for select to authenticated using (public.can_view_entries());
create policy "zs insert" on public.zone_shipments for insert to authenticated with check (public.my_can('add'));
create policy "zs update" on public.zone_shipments for update to authenticated using (public.my_can('edit')) with check (public.my_can('edit'));
create policy "zs delete" on public.zone_shipments for delete to authenticated using (public.my_can('delete'));

drop policy if exists "zt read"   on public.zone_settings;
drop policy if exists "zt insert" on public.zone_settings;
drop policy if exists "zt update" on public.zone_settings;
create policy "zt read"   on public.zone_settings for select to authenticated using (public.can_view_entries());
create policy "zt insert" on public.zone_settings for insert to authenticated with check (public.can_write_entries());
create policy "zt update" on public.zone_settings for update to authenticated using (public.can_write_entries()) with check (public.can_write_entries());
