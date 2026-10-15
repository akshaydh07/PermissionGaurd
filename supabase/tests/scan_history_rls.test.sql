begin;

select plan(9);

insert into auth.users (
    instance_id,
    id,
    aud,
    role,
    email,
    encrypted_password,
    email_confirmed_at,
    raw_app_meta_data,
    raw_user_meta_data,
    created_at,
    updated_at
)
values
    (
        '00000000-0000-0000-0000-000000000000',
        'd0000000-0000-4000-8000-000000000001',
        'authenticated',
        'authenticated',
        'stage-d-user-a@example.invalid',
        '',
        now(),
        '{}'::jsonb,
        '{}'::jsonb,
        now(),
        now()
    ),
    (
        '00000000-0000-0000-0000-000000000000',
        'd0000000-0000-4000-8000-000000000002',
        'authenticated',
        'authenticated',
        'stage-d-user-b@example.invalid',
        '',
        now(),
        '{}'::jsonb,
        '{}'::jsonb,
        now(),
        now()
    )
on conflict (id) do nothing;

set local role authenticated;
select set_config(
    'request.jwt.claim.sub',
    'd0000000-0000-4000-8000-000000000001',
    true
);

select lives_ok(
    $$insert into public.scan_history (
        user_id, app_name, source_format, score, risk_band, policy_version, findings_count
    ) values (
        'd0000000-0000-4000-8000-000000000001',
        'User A record', 'json', 12, 'Low', '1.0', 1
    )$$,
    'an authenticated user can insert their own summary'
);

select results_eq(
    $$select app_name from public.scan_history$$,
    $$values ('User A record'::text)$$,
    'a user can read their own history'
);

select set_config(
    'request.jwt.claim.sub',
    'd0000000-0000-4000-8000-000000000002',
    true
);

select is(
    (select count(*)::integer from public.scan_history),
    0,
    'another user cannot read the first user history'
);

select is(
    (
        with deleted as (
            delete from public.scan_history
            where user_id = 'd0000000-0000-4000-8000-000000000001'
            returning id
        )
        select count(*)::integer from deleted
    ),
    0,
    'another user cannot delete the first user history'
);

select throws_ok(
    $$update public.scan_history
      set app_name = 'Modified by user B'
      where user_id = 'd0000000-0000-4000-8000-000000000001'$$,
    '42501',
    'permission denied for table scan_history',
    'another user cannot modify the first user history'
);

select lives_ok(
    $$insert into public.scan_history (
        user_id, app_name, source_format, score, risk_band, policy_version, findings_count
    ) values (
        'd0000000-0000-4000-8000-000000000002',
        'User B record', 'csv', 20, 'Low', '1.0', 0
    )$$,
    'the second authenticated user can insert their own summary'
);

select results_eq(
    $$select app_name from public.scan_history$$,
    $$values ('User B record'::text)$$,
    'the second user sees only their own history'
);

select set_config(
    'request.jwt.claim.sub',
    'd0000000-0000-4000-8000-000000000001',
    true
);

select results_eq(
    $$select app_name from public.scan_history$$,
    $$values ('User A record'::text)$$,
    'the first user record remains unchanged after another user attempts modification'
);

select set_config(
    'request.jwt.claim.sub',
    'd0000000-0000-4000-8000-000000000002',
    true
);

select throws_ok(
    $$insert into public.scan_history (
        user_id, app_name, source_format, score, risk_band, policy_version, findings_count
    ) values (
        'd0000000-0000-4000-8000-000000000001',
        'Forged owner', 'json', 12, 'Low', '1.0', 0
    )$$,
    '42501',
    'new row violates row-level security policy for table "scan_history"',
    'a user cannot insert history owned by another user'
);

select * from finish();
rollback;
