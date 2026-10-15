# PermissionGuard

PermissionGuard is a local-first prototype for identifying excessive Android
application permissions. It analyzes declarations and report data; it does not
execute APKs or transmit uploaded data to external services.

## Current stage

Stage 4 provides shared permission-report data structures, JSON/CSV
normalization, static APK manifest extraction, deterministic policy-based
analysis, a Streamlit dashboard, and local SQLite scan history.

## Development setup

Use Python 3.10 or newer. Create and activate a virtual environment, then run:

```powershell
python -m pip install -r requirements.txt
python -m pytest
```

Start the dashboard from the project directory:

```powershell
python -m streamlit run app.py
```

By default, scan history is stored in `data/permission_guard.db` and customized
policy settings in `data/user_policy.json`. Both are local-only files; the
database and custom policy are excluded from version control.

## Permission report formats

### Android APK files

Install the dependencies, then pass the uploaded APK bytes and filename to the
same ingestion entry point used for JSON and CSV:

```python
from pathlib import Path

from permission_guard.ingestion import parse_permission_report

apk_bytes = Path("example.apk").read_bytes()
report = parse_permission_report(apk_bytes, "example.apk")
print(report.package_name, report.app_name, report.permissions)
```

APK parsing uses Androguard's static manifest reader. The permission list
contains declarations from AndroidManifest.xml only; it does not identify
permissions granted by a device or permissions used at runtime. APK bytes are
parsed locally in memory; PermissionGuard does not install or execute APKs,
and it does not transmit uploaded files or extracted data to external services.
Uploads are limited to 100 MB; the manifest, optional resources table, and
archive entry count also have parser safety limits. Missing package or label
metadata is represented as `None`. Unsupported, malformed, or over-limit files
raise `ReportInputError` with a user-facing explanation.

JSON reports use an object with a required `permissions` array and optional
metadata:

```json
{
  "app_name": "Example",
  "package_name": "org.example.app",
  "purpose": "photo editing",
  "permissions": ["android.permission.CAMERA"]
}
```

CSV reports contain one permission per row. They must include a `permission`
column (or `permissions`); `app_name`, `package_name`, and `purpose` are
optional columns and must not conflict across rows.

The parser accepts UTF-8 JSON or CSV files, trims values, and removes duplicate
permission names while preserving their original order. It rejects malformed
or ambiguous reports instead of guessing.

Synthetic app examples and small parser fixtures are under `tests/fixtures/`.

## Deterministic permission analysis

Analyze any normalized APK, JSON, or CSV report with the same API:

```python
from permission_guard.analyzer import analyze_report
from permission_guard.ingestion import parse_permission_report

report = parse_permission_report(
    '{"app_name":"Memo","purpose":"audio recording",'
    '"permissions":["android.permission.RECORD_AUDIO"]}',
    "memo.json",
)
result = analyze_report(report)
print(result.score, result.risk_band)
for finding in result.findings:
    print(finding.severity, finding.explanation, finding.recommended_action)
```

The default local policy is `policies/security_policy.json`; pass a JSON policy
path or an equivalent validated mapping to `analyze_report` to customize
permission sensitivity, purpose mappings, organizational denied permissions,
combination rules, and scoring weights. Scores are reproducible, additive by
configured categories, capped at 100, and classified as Low (0–29), Medium
(30–59), or High (60–100). For each permission, the engine applies its
sensitivity contribution once and uses the larger of a purpose mismatch or
organizational violation increment. Overlapping combination rules share only
the largest contribution in their connected group. Unknown permissions have
zero score until cataloged; unknown purposes do not trigger mismatch findings.

Purpose mappings and permission catalogs are reviewable policy inputs, not
ground truth. Combination matches are indicators for human review, never proof
of malicious behavior. APK analysis concerns manifest declarations only; it
cannot establish device grants or runtime permission use.
PermissionGuard provides recommendations only; it does not revoke permissions
or make changes to Android devices.

## Stage 5 evaluation

Run the curated synthetic evaluation with:

```powershell
python -m evaluation.run_evaluation
```

The ten documented scenarios and their independently reviewed expected
policy-triage findings are in `evaluation/scenarios.json` and
`evaluation/expected_results.json`. A separate read-only review checked the
scenario labels against the scenario descriptions and configured policy before
metrics were recorded.

The latest executed run produced **finding-level** TP=9, FP=0, FN=0,
precision=1.000, recall=1.000, and F1=1.000. A finding is an exact
`(scenario, category, sorted permission tuple)` match, limited to
purpose-mismatch, policy-violation, and suspicious-combination review findings.
The **application-level** presence metric produced TP=6, FP=0, FN=0, and
precision/recall/F1=1.000; this asks only whether an application has any
actionable finding and does not check that the finding identity is correct.

These results describe agreement with a small, curated set of synthetic
policy-review expectations—not real-world malware detection, permission use,
or general detection accuracy. The scenarios intentionally encode behavior
represented in the current policy, so results should not be generalized beyond
them.

## React frontend (Stage C)

The separate `web/` directory contains a React, TypeScript, Vite, Tailwind CSS,
and Lucide-based interface. It does not replace the Streamlit app. Dashboard
inventory, alerts, and history remain clearly labeled synthetic demonstration
data; the **Manual analysis** workflow uses the local FastAPI API and displays
results from the existing Python ingestion and deterministic scoring engine.
Selected input files are sent only to the local backend, not to an external
service. APK analysis parses static manifest declarations only.

Install Python 3.10 or newer and Node.js 20 or newer. In Terminal 1, from the
project root, create/activate the Python environment if needed, install
dependencies, and start the API bound to loopback:

```powershell
python -m pip install -r requirements.txt
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

In Terminal 2, start the React frontend:

```powershell
cd web
npm ci
npm run dev
```

Open the Vite loopback URL (normally `http://127.0.0.1:5173`). The backend
health check is `http://127.0.0.1:8000/api/health`; interactive API
documentation is available locally at `http://127.0.0.1:8000/docs`. Build the
frontend from `web/` with `npm run build`. In PowerShell installations that
block the `npm.ps1` script, use `npm.cmd` instead of `npm`.

The API accepts `.json` and `.csv` reports at `POST /api/analyze/report`, APK
files at `POST /api/analyze/apk`, retrieves persisted local results from
`GET /api/reports/{analysis_id}`, and returns the active local policy from
`GET /api/policies/active`. Uploads are limited to 100 MB and purpose input to
500 characters. Analysis records use the existing local SQLite database.
There is no authentication, cloud storage, or device scanning in this stage.
The Streamlit dashboard remains available with its existing command:

```powershell
python -m streamlit run app.py
```

## Stage D: optional accounts and cloud history

Local analysis remains available from **Explore local demo** without a
Supabase account. Cloud authentication and history require configuring a
Supabase project; without configuration, the account forms remain disabled and
local analysis continues to work.

1. Create a Supabase project and enable the Email provider under
   **Authentication → Providers**. Configure the site URL and redirect URLs
   for `http://127.0.0.1:5173` (and `http://localhost:5173` if you use that
   host). Email confirmation behavior follows the project's Auth settings.
2. Apply the checked-in migration to the linked project. From the repository
   root in PowerShell, after installing the Supabase CLI:

   ```powershell
   supabase login
   supabase link --project-ref YOUR_PROJECT_REF
   supabase db push
   ```

   This creates `public.scan_history` with row-level security enabled and
   forced. Authenticated users can select, insert, and delete only rows whose
   `user_id` equals `auth.uid()`. The database tests are in
   `supabase/tests/scan_history_rls.test.sql`; run them against a local Supabase
   stack with Docker and the Supabase CLI:

   ```powershell
   supabase start
   supabase test db
   ```

3. In `web/`, copy `.env.example` to `.env.local` and fill in the Supabase
   project URL and **public anon/publishable key**:

   ```powershell
   Copy-Item .env.example .env.local
   ```

   `VITE_SUPABASE_URL` and `VITE_SUPABASE_ANON_KEY` are intentionally
   browser-visible configuration. **Never place a service-role key in the
   frontend, a `VITE_` variable, or `.env.local`.** RLS—not secrecy of the
   public anon key—protects database rows. Restart Vite after changing
   environment values.
4. Start the local API and frontend in separate terminals using the Stage C
   commands above. Run frontend tests and the production build from `web/`:

   ```powershell
   npm.cmd test
   npm.cmd run build
   ```

Cloud history is off until an authenticated user explicitly enables it in
Privacy settings. Each scan summary then still requires a separate **Save
summary to cloud history** action. Only app/package metadata, optional purpose,
source format, score, risk band, policy version, and finding count are stored;
APK bytes, original JSON/CSV, permission lists, evidence, and full findings are
not sent to Supabase. Turning sync off prevents future reads and writes but
does not delete summaries already stored; those rows remain subject to the
account's RLS policies.

Local analysis continues to use the Python engine and local SQLite. Supabase
is used by the frontend only for email authentication and the opt-in,
summary-only history table; no service-role key or server database password is
used. Cloud behavior depends on the project's Auth settings and successful
application of the migration. The browser/client tests mock Supabase, while
the pgTAP isolation tests require a runnable Supabase/PostgreSQL environment.
This stage does not add device scanning, permission changes, or automatic
cloud upload of input files.

## Stage 5 evaluation and verification

Run all tests, including the local API integration tests, with
`python -m pytest -q`. The suite covers JSON,
CSV, and generated binary-XML APK uploads through the dashboard; purpose
selection; analysis and report rendering; comparison; history reopen/delete;
and policy save/restore. Security regression tests cover malformed and
over-limit reports, malformed APKs, a ZIP path-traversal entry that must not be
extracted, a malicious JSON field rejected by the schema, and SQL-injection
payloads passed as bound scan identifiers.

A separate read-only security review found no confirmed vulnerabilities in
upload handling, archive parsing, deserialization, SQL, secret exposure,
external network transmission, or APK execution. A source scan for
`pickle`, process launch, outbound HTTP/socket libraries, `eval`/`exec`, and
ZIP extraction calls found no matches in the app or application package.
The evaluation and security checks are synthetic/static checks; they do not
constitute a formal penetration test or analysis of real Android runtime
behavior.
