create table public.scan_history (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references auth.users (id) on delete cascade,
    created_at timestamptz not null default now(),
    app_name text check (app_name is null or char_length(app_name) <= 200),
    package_name text check (package_name is null or char_length(package_name) <= 255),
    purpose text check (purpose is null or char_length(purpose) <= 500),
    source_format text not null check (source_format in ('json', 'csv', 'apk')),
    score integer not null check (score between 0 and 100),
    risk_band text not null check (risk_band in ('Low', 'Medium', 'High')),
    policy_version text not null check (char_length(policy_version) <= 40),
    findings_count integer not null check (findings_count between 0 and 10000)
);

alter table public.scan_history enable row level security;
alter table public.scan_history force row level security;

revoke all on table public.scan_history from public, anon, authenticated;
grant select, insert, delete on table public.scan_history to authenticated;

create policy "Users read their own scan history"
    on public.scan_history for select to authenticated
    using (auth.uid() = user_id);

create policy "Users insert their own scan history"
    on public.scan_history for insert to authenticated
    with check (auth.uid() = user_id);

create policy "Users delete their own scan history"
    on public.scan_history for delete to authenticated
    using (auth.uid() = user_id);
