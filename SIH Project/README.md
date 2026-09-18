# VIGIL

VIGIL is a detection-only security assessment dashboard for authorized
application testing. It combines lightweight SAST, passive DAST, and Python
dependency scanning through a single Flask API and web interface.

## Run locally

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m flask --app main:create_app run --host 127.0.0.1 --port 5056
```

Open `http://127.0.0.1:5056/`.

## Run an assessment from the CLI

```powershell
.\.venv\Scripts\python.exe main.py --config config/config.yaml --output reports/security-assessment.html
```

The CLI runs SAST, passive DAST, SCA, and any explicitly enabled authenticated
checks. DAST never sends exploit payloads or mutates application data.

## API

- `GET /healthz` - liveness check
- `GET /api/scans` - scan history retained by the current process
- `POST /api/scans` - run an authorized scan

Example:

```json
{
  "mode": "all",
  "target_url": "https://www.worldmonitor.app"
}
```

Supported modes are `sast`, `dast`, `sca`, `rbac`, `idor`, `password-policy`, `rate-limit`, `sqli`, `session-management`, `api-security`, `data-privacy`, `xss`, `both`, and `all`.

### Authenticated RBAC checks

RBAC checks are opt-in. Set `rbac.enabled: true`, set `rbac.scope` to an
explicit list containing the exact authorized target URL (or hostname),
provide dedicated test accounts, and list every permitted GET endpoint with
its `required_role`.
VIGIL only tests endpoints that are both configured and discovered from the
target root page. Credentials and response cookies are never included in
finding evidence. All active modules enforce the same scope gate, log a
redacted request/response artifact under `reports/artifacts/`, and link the
latest artifact from the finding. Keep credentials and generated artifacts out
of source control.

### IDOR checks

IDOR checks are also opt-in and require at least two dedicated accounts with
the same role. Configure only safe GET request templates, such as
`/api/orders/{id}` or `/api/orders?order_id={order_id}`. VIGIL collects numeric
IDs and UUIDs from each account's authenticated JSON/URL responses, substitutes
one account's identifier into the other account's configured request, and
reports unexpected access. It does not send mutation requests or scan outside
the explicit endpoint allowlist.

### Active XSS checks

Active XSS checks are opt-in and require Playwright with a Chromium browser
installed. The Docker image installs both automatically; for local execution,
install the Python requirements and run `playwright install chromium`.
Configure reflected or stored endpoints explicitly. VIGIL uses a uniquely
tagged DOM-marker payload, verifies execution in a headless browser, and saves
execution screenshots under the configured evidence directory. Stored checks
submit with one configured account and verify the view with each configured
account. If Playwright or Chromium is unavailable, the scanner skips safely and
does not report reflection-only false positives.

### Password-policy checks

Password-policy checks are opt-in and should use disposable authorized test
accounts. Configure registration and/or password-change endpoints explicitly,
then define rules for minimum length, complexity, and common-password
rejection. The scanner reports each weak test input that the endpoint accepts.
Separate login-protection checks can send a bounded number of failed attempts
to verify configured rate limiting or lockout responses. Keep this
configuration private and never use production credentials.

### SQL injection checks

SQLi checks are opt-in and require explicit same-origin endpoint and input
configuration. VIGIL uses only a small proof-of-concept payload set: quote
error detection and boolean true/false comparison. Payloads are sanitized in
reports, destructive statements are not sent, and time-based/deep scanning is
not supported by default. The scanner reports the affected parameter, input
location, response signal, and redacted evidence.

### Session-management checks

Session-management checks are opt-in and require explicit authorized login
configuration plus dedicated test accounts. VIGIL validates session-cookie
security flags, token entropy/predictability, session fixation behavior
(pre-login vs post-login token rotation), configured idle-timeout enforcement,
and logout invalidation against allowlisted protected endpoints. Timeout and
logout probes are intentionally conservative and configuration-bound so scans
stay proof-of-concept and non-destructive.

### API security checks

API checks are opt-in and allowlist-bound. Configure REST or GraphQL routes
explicitly. The scanner classifies discovered `/api/*` and `/graphql` paths,
checks unauthenticated access to routes marked `requires_auth`, detects
stack-trace/internal-path leakage from configured malformed requests, and can
perform a mass-assignment canary check only when both `mass_assignment: true`
and an explicit `verify_path` are provided. API object-level authorization
continues to use the existing IDOR module; keep those endpoint definitions
aligned when testing BOLA behavior.

#### Local API security demo

Run the intentionally insecure localhost fixture:

```powershell
.\.venv\Scripts\python.exe demo\mock_api_target.py
```

Then scan it from another terminal:

```powershell
.\.venv\Scripts\python.exe main.py `
  --config demo\api-demo.yaml `
  --output reports\api-demo.html
```

The fixture demonstrates unauthenticated API access, verbose GraphQL errors,
and mass-assignment persistence. It binds only to `127.0.0.1`.

### Data storage and privacy checks

Data privacy checks are passive and opt-in. They inspect configured or
discovered same-origin responses for PII, tokens, keys, private-key markers,
and other sensitive data; flag sensitive query-string values; and can inspect
`localStorage`/`sessionStorage` with a headless browser when
`browser_storage: true` is explicitly enabled. Values are redacted in
evidence. No payloads are submitted and no application state is changed.

#### Local data-privacy demo

```powershell
.\.venv\Scripts\python.exe demo\mock_privacy_target.py
```

Then, from another terminal:

```powershell
.\.venv\Scripts\python.exe main.py `
  --config demo\privacy-demo.yaml `
  --output reports\privacy-demo.html
```

The fixture demonstrates PII, token-like data, and a sensitive URL query
parameter on localhost only.

#### Local session-check demo

VIGIL includes an intentionally insecure localhost-only fixture so the session
checks can be demonstrated safely:

```powershell
.\.venv\Scripts\python.exe demo\mock_session_target.py
```

In another terminal, run the scanner with its demo configuration:

```powershell
$env:ASSESSMENT_CONFIG = (Resolve-Path demo\session-demo.yaml).Path
.\.venv\Scripts\python.exe main.py --config demo\session-demo.yaml --output reports\session-demo.html
```

The fixture is designed to demonstrate weak token entropy, missing cookie
flags, session fixation, logout invalidation, and missing idle-timeout
enforcement. It binds only to `127.0.0.1` and must not be exposed publicly.

### Rate-limit checks

Rate-limit checks are opt-in and endpoint allowlist-based. Configure a
conservative request count, interval, cooldown, and expected throttle statuses.
The scanner enforces a hard maximum of 10 requests per endpoint, a minimum
inter-request delay, and a maximum cooldown even if a configuration requests
more. It reports the request count and observed response codes when no
throttling signal or `Retry-After` header is observed. Use only disposable
authorized accounts and non-production targets.

## Deploy with Docker

```powershell
docker build -t vigil .
docker run --rm -p 8080:8080 vigil
```

The image uses a non-root user, a bounded Gunicorn configuration, a Docker
health check, and the `/healthz` endpoint. Render deployment is configured in
[`render.yaml`](render.yaml).

## Scope and authorization

Only scan systems and repositories for which you have explicit permission.
Credentialed RBAC, IDOR, rate-limit, and active injection testing are not
enabled by default. Configure and review those workflows separately before
adding them to an authorized test environment.
