# Sprint 7B dashboard operation

The opt-in read-only shell is approved local implementation, not yet accepted or deployed.
It supports provider login, exact scan selection, historical scope/lifecycle and report
availability. Assessment/evidence/finding/NIST views, mutations and scan execution are excluded.
[ROADMAP.md](../../ROADMAP.md) owns status and the [active plan](../exec-plans/active/sprint-7.md)
records authority and exact validation. Never reuse development/test identities in production.

## Configuration and startup

Defaults are unchanged: `DASHBOARD_ENABLED=false` adds no dashboard routes or session handling.
When enabled, set these through trusted operator configuration, never browser input:

| Setting | Requirement |
| --- | --- |
| AUTH_MODE and APP_ENV | oidc; production requires HTTPS; no development-marker fallback |
| OIDC_ISSUER and OIDC_JWKS_URL | Exact trusted user-pool issuer and advertised JWKS; discovery issuer/JWKS must agree |
| OIDC_AUDIENCE | Exact URL-formatted API resource identifier, distinct from client ID |
| OIDC_ALGORITHMS | Explicit asymmetric allowlist; Cognito uses RS256 |
| OIDC_ROLES_CLAIM | cognito:groups for the initial dedicated Cognito pool |
| DASHBOARD_ENABLED | Explicit true |
| DASHBOARD_ORIGIN | Exact HTTPS scheme/host/port with no path, credentials, query or trailing slash |
| DASHBOARD_CLIENT_ID | Confidential app client's non-secret identifier |
| DASHBOARD_CLIENT_SECRET | Server-only credential supplied securely; never put it in Git, chat or frontend build variables |
| DASHBOARD_SCOPES | openid, plus explicitly registered required scopes; offline_access is rejected |
| DASHBOARD_STATIC_DIR | Built index.html and assets directory; defaults to frontend/dist |

Run `pnpm --dir frontend install --frozen-lockfile` then `pnpm --dir frontend build` before local
Python startup. The multi-stage Dockerfile builds those same assets into the non-root image.
No runtime Node process or external asset CDN is used. Compose passes opt-in configuration and
still binds loopback; production ingress, TLS, secret delivery and deployment are separate work.

The backend supports HTTP only with `OIDC_ALLOW_INSECURE_HTTP=true`, loopback endpoints and an
explicit local/test APP_ENV. This is for controlled protocol tests, not production authentication.
For Vite editing, use loopback port 5173 and DASHBOARD_ORIGIN=http://127.0.0.1:5173 with the same
local-only gate; its narrow proxy preserves that origin through the backend on port 8000.
Never expose the controlled issuer or development proxy publicly.

## Cognito registration requirements

The selected production target is Cognito User Pools Essentials with managed login. Live pool,
app-client, group, MFA, secret and IAM changes require separate human authorization. None is
created by code implementation or validation. Use a dedicated invite-only pool, required MFA,
one confidential BFF client and exactly VIEWER, ANALYST, APPROVER and ADMIN application groups.
These are not IAM roles; do not attach an identity pool or give browser users AWS credentials.

Register the exact callback DASHBOARD_ORIGIN/dashboard/auth/callback and enable authorization
code flow with S256 PKCE. The server requests `resource=OIDC_AUDIENCE`; Cognito access-token
`aud` is present only with resource binding. Never substitute client_id or an ID token for API
audience verification. Allow only required scopes and administratively assigned application roles.
Additional/unrecognized groups fail closed; Cognito federation can add groups automatically, so
federation requires a separate reviewed claims contract, not an implicit production-ready feature.
[Authorization endpoint](https://docs.aws.amazon.com/cognito/latest/developerguide/authorization-endpoint.html),
[access-token claims](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-access-token.html),
[groups](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-user-groups.html).

Do not log callback query strings at an external ingress either. The application removes them
from its ASGI access-log scope and returns a clean fixed redirect with no-referrer/no-store.
Malformed state/CSRF is safely rejected. Unexpected dashboard errors return a fixed 500 with
the same security headers and callback-query redaction; server programming errors remain observable.
Provider tokens never enter browser JavaScript, cookies, URLs, Web Storage, IndexedDB or test traces.
No refresh token is kept. Cognito may retain its own login session after dashboard expiry/logout;
local logout does not claim global revocation or mandatory IdP reauthentication.

## Session and READ behavior

Login/session requests use a random browser-bound one-time state, library-validated nonce/PKCE,
opaque HttpOnly cookies, exact Origin and CSRF checks. Sessions expire at 15 idle minutes,
60 absolute minutes or token expiry. The process-local store has 100 login/1,000 session caps,
rejects exhaustion rather than evicting other users and is cleared on process exit/restart.
Operate one process; shared or durable sessions are deliberately not implemented.

Only scan list/detail/technical-posture GETs are forwarded, through the real bearer API and READ
dependencies. Each requires `X-Dashboard-Context` matching the public `session_context` returned
by the authenticated session bootstrap. The value is correlation, not authority; it cannot
replace the opaque cookie, bearer verification or READ. A stale tab gets 401 before forwarding
under another session. Supported Chromium/Firefox use ephemeral same-origin BroadcastChannel
invalidation to clear old identity/data and abort pending reads across tabs before logout
completes, then rebootstrap when the session changes. Notifications contain only a public
context and event type, never tokens, CSRF, identity or report data; no Web Storage is introduced.
Cookie-only `/api/v1` calls remain unauthorized. The shell never selects latest
implicitly, claims account isolation, infers PASS from missing evidence, or displays a compliance
score. Pending/no-bundle reports have unavailable counts, not zero. Partial/failed retained facts
remain visible with explicit coverage limitations. Client guards require exact lifecycle enums
and all four finite nonnegative integer counts for available reports (including legitimate zero),
while unavailable counts remain null. No counts or score view is added. Offset pages are not frozen snapshots.

## Reproducible validation

Node 24.19.0 and pnpm 11.19.0 are pinned; frontend dependencies use exact versions and a lockfile.
Run typecheck, lint, test and build scripts in frontend. Install the pinned Playwright browsers
with `pnpm --dir frontend exec playwright install chromium firefox`.
Then run `python scripts/validate.py --dashboard --focused tests/api/test_dashboard_api.py
tests/unit/security tests/unit/test_config.py tests/api/test_technical_posture_api.py tests/unit/contracts`
as one command. The harness creates its own disposable PostgreSQL container on loopback, supplies
its generated TEST_DATABASE_URL, tests real signed OIDC/READ/browser/database boundaries,
then runs full regression and container gates and removes only that created database container.
It never reuses an operator database. The browser fixture is test-only and excluded from the image.
Browser traces/videos/screenshots are disabled for automated authenticated journeys to avoid
retaining credentials/evidence. A separately requested local visual check must use synthetic data.

Independent review and publication/merge approvals remain mandatory. Controlled-issuer acceptance
does not prove a live Cognito tenant, MFA enrollment, ingress/TLS or production operational setup.
