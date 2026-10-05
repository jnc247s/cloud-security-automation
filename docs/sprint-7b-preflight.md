# Sprint 7B authenticated shell preflight

Prepared 2026-10-03. The original analysis below is preserved. Subsequent user confirmations
approve React/TypeScript/Vite, the BFF/session design, 7B implementation, Cognito Essentials
and a controlled local test issuer. The [completed plan](exec-plans/completed/sprint-7.md) records
that superseding authority, including one read-only reviewer and scoped commit/push/PR approval.
Review passed and [PR #43](https://github.com/jnc247s/cloud-security-automation/pull/43) merged
under the subsequent user confirmation after green final-head CI. Merged-main CI passed and
7B is accepted. The completed plan records the subsequent scoped closeout and remaining-Sprint-7
approval; auto-merge, live operations and later-sprint work remain excluded. The original
analysis and its earlier approval/status limits below are historical, not the current 7B status.
7A--7E and Sprint 7 are now COMPLETE through PR #50 with exact-head review and green main CI;
Sprint 8 is NEXT only and remains unstarted.

Original checkpoint: analysis only; the user approved continuing the existing 7A/7B goal through
7A documentary closeout and the 7B prerequisites. **No browser architecture or 7B implementation
is approved yet.** This document recommends a same-origin React/TypeScript client with a small
backend-for-frontend (BFF) authentication layer in the existing FastAPI process. It needs explicit
approval because cookie sessions and server-held provider tokens are a new security boundary.

[ROADMAP.md](../ROADMAP.md) owns status and the [completed plan](exec-plans/completed/sprint-7.md)
owns approved scope. 7A is accepted through [PR #42](https://github.com/jnc247s/cloud-security-automation/pull/42)
at main `bd639f48095ef63e658abd284ce25c927998c0fb`; exact-head review and merged-main CI passed.
7B remains PLANNED. Stop after 7B acceptance; no 7C, 7D, 7E or later-sprint implementation.

## Inspected contracts and constraints

The preserved worktree is on local `codex/sprint-7b-preflight`, from verified clean main.
The parent checkout's unrelated skill files, original 6E.3 checkout and reviewed 7A branch remain
untouched. No frontend package, dependency, browser runtime or IdP registration was created.

Inspected sources include [architecture](../ARCHITECTURE.md), [security](../SECURITY.md),
[threat model](../THREAT_MODEL.md), [product requirements](../PRODUCT_REQUIREMENTS.md),
[API](api.md), the [original Sprint 7 preflight](sprint-7-preflight.md), application settings,
startup/router/authentication/authorization, scan/report schemas/routes and their API/security
tests. The accepted integration points are:

| Need | Accepted contract | Constraint on 7B |
| --- | --- | --- |
| List scans | GET /api/v1/scans, limit 1..100, offset >= 0 | Load bounded pages. Offset results are not a frozen snapshot; no new account/Region filtering or pagination contract. |
| Select historical context | GET /api/v1/scans/{scan_id} | Use an explicit UUID and exact retained profile/catalog/scope. Never silently switch to latest. |
| Explain report availability | GET /api/v1/scans/{scan_id}/technical-posture, schema 1.0.0 | IN_PROGRESS, AVAILABLE and UNAVAILABLE are not assessment states. Null counts are not zeros or PASS. |
| Enforce identity and READ | Existing signature/JWKS/issuer/audience/expiry/subject/roles verifier and capability dependencies | The BFF must carry the user's provider access token through the existing API boundary, not trust client roles or introduce a shared privileged token. |
| Preserve accepted startup | create_app, settings validation, executor lifespan, health/readiness and Docker | Dashboard support should be explicit opt-in, with default startup unchanged. No new workers, scan execution or live AWS calls. |

All four recognized roles currently hold READ. Scan creation still requires EXECUTE; the dashboard
will neither expose nor proxy that operation, even for ADMIN. The API has no browser login,
session middleware, token issuance, wildcard CORS or account/tenant isolation. A UI filter would
not create authorization. The current single-process deployment and its limitations remain.

The local Node executable reports 24.19.0; a pnpm command wrapper is present. Package-manager
version, dependencies, browsers and reproducible builds have not been installed or validated.
No exact frontend or Python OAuth-client release is selected by this preflight.

## Proposed user interface and toolchain

Recommend a small React/TypeScript client built with Vite, plain accessible HTML/CSS and no
external fonts, analytics, CDN widgets or offline caches. React's official guidance describes
Vite as an option for an existing-API client, while noting the additional responsibility for
routing and data fetching; this is a project-specific choice, not a universal framework claim.
[React guidance](https://react.dev/learn/build-a-react-app-from-scratch),
[Vite guide](https://vite.dev/guide/).

Keep frontend source separate from Python, for example in `frontend/`. Pin a supported Node and
package-manager version, reviewed dependency releases and a lockfile during authorized
implementation. Use a frozen-lockfile install, TypeScript checking, frontend lint/unit tests
and a production build. Propose Vitest for units and Playwright for real browser journeys;
verify browser/platform requirements before installing them.
[Vitest guide](https://vitest.dev/guide/), [Playwright guide](https://playwright.dev/docs/intro).

Build static assets into the existing non-root API image and serve a dedicated dashboard path;
do not replace /api/v1, health/readiness, docs or OpenAPI routing. Local frontend development
uses loopback and same-origin browser requests through a restricted development proxy.
Production HTTPS/ingress configuration and deployment remain external, separately authorized work.

7B's visible scope is login/session status, bounded scan selection, exact selected-scan identity,
scope/lifecycle/failure context and report availability, with loading/empty/error/partial states.
Do not add assessment/evidence/finding investigation pages, NIST hierarchy views, compliance
charts or scan-start/remediation controls; those exceed this shell slice. Handle back, refresh,
missing/deleted selection and scan changes explicitly. Abort superseded reads and guard response
generation so a late response cannot restore an old scan or signed-out user's data.

## Authentication choice for approval

| Option | Token handling and user experience | Added boundary |
| --- | --- | --- |
| Recommended BFF in FastAPI | Authorization Code with S256 PKCE; tokens and transaction state remain server-side. Browser receives only an opaque session cookie. Normal same-tab login and session restoration on reload. | New bounded session store, cookie/CSRF protections and tightly restricted READ adapter; requires explicit design approval and independent security review. |
| Direct browser client | Public-client Code with S256 PKCE, tokens and transaction state held only in memory. A popup keeps the initiating page alive; reload requires sign-in again. | Browser OAuth, callback/message correlation, popup/COOP/provider compatibility and token-endpoint CORS. No server session, but JavaScript can access bearer tokens. |

The BFF recommendation is a project inference for this sensitive security console. The inspected
IETF browser-apps draft discusses BFF protection against direct token theft and recommends the
pattern for sensitive applications; it remains **work in progress, not an adopted RFC**.
[Draft 27, section 6.1](https://www.ietf.org/archive/id/draft-ietf-oauth-browser-based-apps-27.html#name-backend-for-frontend-bff).
Use RFC 9700's code-flow, redirect/issuer and PKCE security guidance; no implicit/password grant,
client secret in a browser or disabled API verifier.
[RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1).

A direct-client alternative is not implicitly approved. Ordinary same-tab redirects lose an
in-memory PKCE verifier; do not quietly persist it in sessionStorage. Candidate oidc-client-ts
defaults use persistent browser stores for interaction state and user data, so both would need
explicit memory-only configuration. Its popup callback must relay to the original page without
depending on that popup's missing in-memory state. Pin and audit the chosen release, origin/state
and message-source checks, opener isolation and adverse browser tests before selecting it.
[Library settings](https://authts.github.io/oidc-client-ts/interfaces/UserManagerSettings.html),
[popup callback source](https://github.com/authts/oidc-client-ts/blob/main/src/UserManager.ts).
These mutable source references inform analysis only; they do not approve an unpinned dependency.

## Proposed BFF security contract

The following is proposed behavior, not an existing interface or implemented mitigation:

- The external IdP issues all tokens. A reviewed OAuth/OIDC library handles Code + S256 PKCE,
  state/nonce/issuer correlation, confidential-client authentication and ID-token verification.
  The API access token must be a signed JWT for the exact existing API audience/roles contract;
  an ID token is not a substitute. Do not implement custom OAuth cryptography.
- Require explicit dashboard enablement and complete trusted operator configuration: exact
  public origin, issuer/discovery/JWKS, client ID, API audience/scopes and callback. Production
  uses HTTPS and a separately supplied server-side client credential. Never derive redirect or
  provider URLs from untrusted Host/query values. Missing configuration fails closed, not into
  development access. IdP client registration and secret provisioning are separate human actions.
- Use cryptographically random opaque session IDs, an HttpOnly/Secure host-only cookie and no
  Domain attribute. Propose SameSite=Strict for authenticated sessions, with a separate short-lived
  Lax correlation cookie only for the top-level code callback. Rotate identity on login and
  destroy it on logout; no provider tokens or verifier/nonce payload in signed/encrypted cookies.
  Starlette's standard SessionMiddleware stores readable signed session information, so it is
  not a server-only token store. [Starlette documentation](https://starlette.dev/middleware/#sessionmiddleware).
- Keep provider tokens and pending login state in a bounded, thread-safe, process-local store,
  without cloud evidence or database persistence. Proposed initial caps: 1,000 sessions and
  100 pending logins; expire pending transactions after five minutes. Reject capacity exhaustion
  safely and clear consumed/replayed/expired states. A restart ends sessions and requires login;
  this deliberately shares the accepted one-process limitation, not an HA/session guarantee.
- Proposed session limits: 15-minute idle and 60-minute absolute lifetime, never beyond the
  access token's validity. Revalidate the real bearer/READ boundary for every forwarded read.
  No offline_access, refresh-token retention or silent renewal initially; expiry requires login.
  Local logout invalidates the dashboard session and clears data, not every IdP session or an
  already issued external token. Global IdP logout/revocation is not claimed by this slice.
- Use a session-bound CSRF token and exact trusted Origin checks for login/logout; bind callback
  state and PKCE to the initiating browser and enforce one-time use. Define same-origin read
  checks and adverse cross-site tests; SameSite alone is not the CSRF design.
- The READ adapter allows only scan list/detail/posture operations and bounded accepted query
  parameters. Preserve server IDs, fields, error codes and authorization. Forward the user's
  token internally through the existing API, never directly query the database, override its
  dependencies, accept arbitrary upstream URLs/headers, follow external redirects or proxy
  mutation methods. /api/v1 itself remains bearer-only; a dashboard cookie cannot authenticate it.
- Keep tokens, cookies, codes, client credentials and cloud data out of logs, errors, URLs,
  telemetry and test artifacts. Authorization codes exist only on the protocol callback; consume
  them once, sanitize callback access logs, omit third-party assets and immediately redirect to
  a fixed clean dashboard URL with no-referrer/no-store. No token-bearing logout URL.
- Escape untrusted metadata as text; require scoped CSP/security headers and no-store for all
  dashboard session/data/error responses. No localStorage, sessionStorage, IndexedDB or service
  worker evidence/credential cache. Clear data and invalidate pending responses on logout, expiry,
  identity change and authentication failure. HttpOnly does not prevent same-origin malicious
  scripts from making authorized reads; CSP, safe rendering and dependency review remain required.
- Any explicit local/test development access remains visibly labeled and loopback-only, gated by
  both backend and dashboard configuration. Never auto-select it on an OIDC error, and never
  allow it with production settings. Do not change the existing development-marker/API contract.

No distributed store, new migration, password system, identity provider, capability or tenant
policy is proposed. The new session boundary needs SECURITY.md, THREAT_MODEL.md, architecture
and browser-interface documentation during approved implementation, not an accepted-design edit now.

## Proposed implementation and acceptance gates

1. Approve UI/toolchain, BFF versus direct-client boundary and session policy. Identify the IdP
   or explicitly approve a controlled local test issuer plus provider-neutral production
   configuration. Record exact non-secret registration requirements and implementation authority.
2. Implement the approved authentication/static-serving boundary as a small scoped slice,
   preserving existing startup, bearer API, generic services and runtime defaults. Add allowed
   and denied session/callback/CSRF/proxy tests before the shell depends on it.
3. Implement the bounded read-only shell and authenticated client lifecycle, with API-derived
   types and response checks. Invalid/missing/null report data never becomes a safe result.
4. Run browser-to-real-API-to-disposable-database journeys with controlled issuer/JWKS and real
   production-style JWT/READ verification; no dependency bypass. Exercise login/code exchange,
   nonce/state/PKCE mismatch and replay, wrong issuer/audience/key/roles, expiry, logout/fixation,
   CSRF/cross-origin attacks, session limits/restart and cookie-only denial at /api/v1.
5. Verify all recognized READ roles and no scanner/executor/AWS/writer calls. Test attempted
   proxy mutation/traversal/redirect/header injection, bounded pagination, every scan/report
   lifecycle, late-response races, refresh/back/selection and null-versus-zero handling.
   Run keyboard/accessibility, responsive layouts, hostile text and cache/artifact-leak checks
   on supported browsers. Do not substitute canned UI fixtures for full acceptance journeys.
6. Run frontend frozen-lockfile install, type/lint/unit/build/browser checks; then targeted
   backend tests, Ruff, format, complete regression with disposable PostgreSQL, Compose and
   image/runtime checks. Accepted 7A ten-SELECT/historical invariants remain regression gates.
7. Update corresponding owner documents; obtain separately authorized independent review,
   resolve findings, then obtain separate publication and required merge approval. Verify exact
   final-head and merged-main CI. Only then mark 7B COMPLETE and stop; Sprint 7 remains incomplete.

## Decisions needed before coding

Approve or revise the React/TypeScript/Vite and BFF recommendation, including the stated session
lifetimes/caps and re-login-on-expiry behavior. A direct browser client is an explicit alternative,
not a fallback. Then request 7B implementation separately.

Which OIDC provider will supply the API-compatible tokens? If one exists, provide its name and
non-secret issuer/client ID/API audience or say that registration is not ready. **Do not paste
client secrets, tokens, private keys or production configuration.** If no provider exists yet,
approve a controlled local test issuer and configurable production integration; live provider
registration, credentials and deployment stay outside implementation authority. Without live
configuration, tests prove the protocol/integration contracts, not a validated production tenant.

No reviewer was launched and no new commit, push, PR, merge, browser session, IdP/AWS or production
operation occurred for this preparation. Exact documentary validation belongs in the active plan;
the new proposal is not 7B implementation or acceptance.
