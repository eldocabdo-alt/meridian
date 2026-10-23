-- Meridian push notifications. Paste into Supabase -> SQL Editor -> Run (after schema.sql). Safe to run again.

-- One row per device that turned notifications on.
create table if not exists public.push_subscriptions (
  endpoint   text primary key,
  user_id    uuid not null default auth.uid() references auth.users (id) on delete cascade,
  p256dh     text not null,
  auth       text not null,
  device     text,
  created_at timestamptz not null default now(),
  last_ok    timestamptz
);
alter table public.push_subscriptions enable row level security;
drop policy if exists "own rows" on public.push_subscriptions;
create policy "own rows" on public.push_subscriptions
  for all using (user_id = auth.uid()) with check (user_id = auth.uid());

-- What has been sent (once-only keys). Server-only: RLS on, no policies.
create table if not exists public.push_log (
  user_id uuid not null,
  key     text not null,
  sent_at timestamptz not null default now(),
  primary key (user_id, key)
);
alter table public.push_log enable row level security;

-- Server-only secrets (the VAPID key pair the push function generates for itself). RLS on, no policies.
create table if not exists public.app_secrets (
  name  text primary key,
  value text not null
);
alter table public.app_secrets enable row level security;

-- Every 30 seconds, ask the push function to send whatever is due.
create extension if not exists pg_net;
create extension if not exists pg_cron;
select cron.unschedule(jobid) from cron.job where jobname = 'meridian-push';
select cron.schedule(
  'meridian-push',
  '30 seconds',
  $$ select net.http_post(
       url := 'https://kndoevpebpjvgzqvurpg.supabase.co/functions/v1/push',
       headers := '{"Content-Type": "application/json"}'::jsonb,
       body := '{"action": "tick"}'::jsonb
     ) $$
);
