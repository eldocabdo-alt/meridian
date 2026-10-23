-- Meridian sync schema. Paste into Supabase -> SQL Editor -> Run. Safe to run again.
--
-- One generic table: every block, task, session, category, the settings and the live focus
-- session is a row (kind, id) holding its JSON. Row-level security: a row is visible only to
-- the account that owns it. Conflicts resolve last-write-wins on the device clock (client_ts).

create table if not exists public.items (
  user_id    uuid        not null default auth.uid() references auth.users (id) on delete cascade,
  kind       text        not null,
  id         text        not null,
  data       jsonb,
  deleted    boolean     not null default false,
  client_ts  bigint      not null,
  updated_at timestamptz not null default now(),
  primary key (user_id, kind, id)
);

create index if not exists items_user_updated on public.items (user_id, updated_at);

alter table public.items enable row level security;
drop policy if exists "own rows" on public.items;
create policy "own rows" on public.items
  for all using (user_id = auth.uid()) with check (user_id = auth.uid());

-- Server clock for the pull cursor, whatever the device clock says.
create or replace function public.items_touch() returns trigger
language plpgsql as $$
begin
  new.updated_at := now();
  return new;
end $$;

drop trigger if exists items_touch on public.items;
create trigger items_touch before insert or update on public.items
  for each row execute function public.items_touch();

-- Batched upsert that never lets an older change overwrite a newer one.
create or replace function public.push_items(rows jsonb) returns void
language sql security invoker as $$
  insert into public.items (user_id, kind, id, data, deleted, client_ts)
  select auth.uid(), r ->> 'kind', r ->> 'id', r -> 'data',
         coalesce((r ->> 'deleted')::boolean, false), (r ->> 'client_ts')::bigint
  from jsonb_array_elements(rows) as r
  on conflict (user_id, kind, id) do update
    set data = excluded.data, deleted = excluded.deleted, client_ts = excluded.client_ts
    where public.items.client_ts <= excluded.client_ts;
$$;

-- Live updates between devices.
do $$
begin
  alter publication supabase_realtime add table public.items;
exception when duplicate_object then null;
end $$;
