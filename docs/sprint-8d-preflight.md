# Sprint 8D authenticated dashboard workflow preflight

Analysis-only checkpoint on 2026-10-14 UTC. 8A, 8B and 8C are COMPLETE as offline-accepted
code/tests; Sprint 8 remains IN PROGRESS, and 8D/8E remain PLANNED. Browser mutation and recovery
contracts below require a user design decision. This is a proposal, not an approved execution
plan or authorization to implement those contracts, launch a worker or operate live AWS.

## Entry evidence and authority

Accepted main is `599e155090b654f09987f3d48e8c431b116ba7c4`, tree
`6cc196972e4d236a93bcf58d9b081bbff01c8854`, through
[PR #69](https://github.com/jnc247s/cloud-security-automation/pull/69). Exact-head REVIEW_PASS at
`d7d421e`, both complete first-attempt candidate primary audits, ordinary expected-head guarded
merge and complete [exact-main CI 38523209002](https://github.com/jnc247s/cloud-security-automation/actions/runs/38523209002)
passed. Every CI run covered 3,755 backend cases/163 files, all 696 PostgreSQL cases/33 files
without skips, 139 frontend cases/eight files, all 76 browser journeys (38 per project, one
worker/zero retries), all 18 quality/image/cleanup steps and 19 existing SQLite warnings.
These are accepted predecessor receipts, not tests of a new dashboard mutation workflow.

Migration head is `20261013_0010`; operator databases are not migrated automatically. Clean
local main was normally fast-forwarded to the verified merge before creating
`codex/sprint-8d-preflight` in the existing worktree. The 8C acceptance-owner/status-contract
refresh is task-owned and uncommitted. All 77 existing branches, three worktrees and three
unrelated parent skills were preserved; only the approved main fast-forward and new scoped
branch changed the branch inventory. No reset, clean, replacement or deletion occurred.

[AGENTS](../AGENTS.md), [ROADMAP](../ROADMAP.md), the
[active plan](exec-plans/active/sprint-8.md), [product requirements](../PRODUCT_REQUIREMENTS.md),
[architecture](../ARCHITECTURE.md), [security](../SECURITY.md), [threat model](../THREAT_MODEL.md),
[completed Sprint 7 plan](exec-plans/completed/sprint-7.md), [API](api.md),
[dashboard operations](operations/dashboard.md), [remediation operations](operations/remediation.md),
[persistence](persistence.md) and [inventory operations](operations/aws-inventory.md) govern this
analysis. Standing Sprint 8 authority permits routine accepted-design delivery after its gates;
it explicitly does not decide new browser mutation contracts. No new reviewer was launched.

## Intended story and current boundaries

A signed engineer selects an exact retained EC2-004 FAIL occurrence and proposes the fixed
enable-default action. A different verified approver reviews and decides; a third distinct
EXECUTE principal requests execution admission. The separately operated isolated worker
remains outside the browser/API process. After normal acknowledgment, a current EXECUTE
principal explicitly requests linked read-only verification and inspects its sealed historical
receipt. Approval, execution, verification, technical results and finding handling remain distinct.

| Boundary | Current implementation | 8D implication |
| --- | --- | --- |
| Browser and assets | React/TypeScript/Vite, built into the existing FastAPI image; [App](../frontend/src/App.tsx), [ScanShell](../frontend/src/ScanShell.tsx) | Reuse this stack; no platform, IdP, dependency or deployment migration |
| Session and proxy | [Dashboard](../app/dashboard/routes.py) authenticates an opaque cookie, exact origin and expected public context, then re-enters the real bearer API through ASGI; [store](../app/dashboard/store.py) is bounded and process-local | New writes cannot bypass the API, use direct SQL/services or expose tokens |
| Existing browser methods | Explicit scan/investigation GET allowlists; only login/logout currently use POST | Remediation GETs and a new mutation boundary need typed additive contracts; arbitrary forwarding stays denied |
| Human identity | API [ActorContext](../app/remediation/contracts.py) retains full issuer/subject/roles; browser session bootstrap exposes subject/roles, not issuer | Add a verified non-secret issuer hint if the UI compares identity pairs; never use a display name as authority |
| Proposal and decisions | [RemediationService](../app/services/remediation_service.py) revalidates retained provenance/governance, owns short transactions and atomically writes audit/idempotency history | Forward only fixed typed inputs; preserve current capability, digest, expiry and separation checks |
| Execution admission | [service](../app/services/remediation_execution_service.py) records a five-minute third-human grant, one request/proposal and protected reservations | Label this as requesting admission, not launching AWS; no public worker-launch endpoint |
| Verification | [service](../app/services/remediation_verification_service.py) commits linked intent before submission; full retained-policy scanner and immutable receipt are already accepted | Reuse manual EXECUTE requests, three attempts/one active, actor/key replay and separate historical verdict |
| Assessment to finding | [assessment detail](../frontend/src/investigation-api.ts) already carries finding and exact occurrence UUIDs | Start from these bound IDs; never substitute a latest occurrence or infer IDs from prose |

Source searches found 208 remediation-contract/service references across 34 files and 87
browser-session/client references. Relevant callers include the three bearer route modules,
worker/verification services, signed HTTP helpers, PostgreSQL/history tests, current App/API
validators and investigation components. No service constructor, ORM relationship, API enum,
catalog/profile or migration change is proposed.

## Scan selection and scan-start report

Current-source evidence, not a diagnosis of the original operator instance:

- ScanShell always renders Scan history and Open scan by UUID beside the selected report. Its
  `popstate` listener supports browser Back. Clearing the UUID and submitting already clears
  selection, but there is no explicit Back to scan selection button or focus-return affordance.
- Below 760px, [styles](../frontend/src/style.css) stack the sections. The UUID form follows the
  variable-height history list, so controls can move while pages load. The previously demonstrated
  pointer/layout race remains unfixed; later passing tests did not diagnose the older CI failure.
- An empty successful page renders No scans on this page. That alone cannot establish whether
  the operator database is empty, the offset is beyond current rows, or the user ran another build.
  Do not fabricate seed records or select latest implicitly to conceal the issue.
- There is no scan-start control. Existing signed browser acceptance explicitly requires
  `POST /dashboard/api/scans` to return 405, even for ADMIN. Ordinary scanning remains the
  existing EXECUTE-only bearer API, not a browser feature.
- [ScanService.start_scan](../app/services/scan_service.py) persists a UUID before submission
  but has no caller idempotency key; scan audit attribution still retains only subject.
  Adding a browser Start scan button therefore needs a separate scope/retry decision. It must
  not inherit remediation replay guarantees or retry an ambiguous scan POST automatically.

Recommend an explicit clear-selection/focus-return control, stable placement of selection
controls, preserved history offset/deep links/Back behavior and an informative empty state.
Retain a native-pointer race regression without weakening headers, retries, timeouts or existing
navigation assertions. Original operator build/data and native Firefox failure causes remain
unconfirmed. No new browser or live scan was run to attribute those causes.

## Decisions requiring approval

### D1 Narrow opt-in browser authority

Recommend independent default-off `DASHBOARD_REMEDIATION_ENABLED` for the new write workflow;
enabled configuration requires the existing enabled OIDC dashboard. Existing dashboard defaults,
GET routes and direct bearer API remain unchanged. Admission and verification retain their own
independent backend flags and explicit account/Region scopes.

Add six typed remediation history GETs through the existing READ adapter: proposal,
execution and verification list/detail. Lists use current supported filters and default 25,
maximum 100 rows; reject duplicate/unknown queries and invalid IDs. Add verified issuer and
non-authorizing feature hints to authenticated bootstrap only as explicitly documented additive
metadata. Current API authentication/capabilities remain authoritative.

For mutations, recommend a closed browser prepare/submit interface, not a generic POST proxy.
The only upstream operations are CREATE proposal, APPROVE/REJECT decision, REVOKE, execution
admission and linked verification, mapped to the five existing fixed bearer POST routes.
Require exact Origin/fetch-site, safely bounded session CSRF and matching session context,
fresh verified identity/current capability, strict closed typed JSON and a bounded body (12 KiB
supports the existing 2,000-character Unicode reason plus IDs). Reject duplicate JSON/security
headers and browser-selected URLs, methods, role/credential/endpoint/account/desired-state inputs.
Forward only the session's bearer identity, a fixed path/body and the prepared UUID key.
Keep no-store/CSP/security headers and sanitized errors on every path. The API checks authority
again; UI role/identity hints never authorize anything.

No role changes, ADMIN override, AWS calls, credential provisioning, worker launch, direct
database access, automatic approval, rollback, quarantine clearing or finding mutation is added.
The scanner remains read-only and the worker retains its separate ECS-only write identity.

### D2 Confirmation and uncertain-outcome recovery

Recommend a bounded, non-authorizing, process-local prepared-operation store associated with
the current opaque session. It holds a server-generated UUID and frozen normalized operation,
target/body, verified actor pair and result references—not provider tokens, raw response caches
or another execution grant. Proposed limits are 16 entries/session and 256 globally, with
exhaustion rejected rather than evicting uncertain work. Preparation is limited to five minutes
and the existing session deadline; its expiry never releases a database/worker reservation.

The user reviews the prepared target/action/digests/risk and explicitly confirms submission.
Proposed browser paths are `POST /dashboard/api/remediation-operations` to prepare,
`POST /dashboard/api/remediation-operations/{operation_id}/submit` to confirm, and session-bound
GET list/detail on that same resource to recover coordination state. The operation discriminator
and typed target/input are closed; clients never supply an upstream URL. These paths fit the
existing development proxy prefix. Preparation is ephemeral coordination, not a proposal,
approval or execution grant; only the normal upstream service creates authoritative history.
Store in-flight state before the fixed bearer call; concurrent submit cannot dispatch twice.
An explicit retry reuses the identical actor/operation/key/body and existing API replay semantics.
No automatic retry, key regeneration, background execution or renewed authority follows an error.
Same-session reload can recover prepared/in-flight/unconfirmed entries without Web Storage.

After forwarding, a lost/malformed response, timeout, logout or expiry is not proof of no effect.
Even a later denied retry cannot prove an earlier commit did not occur. The BFF must not label
these as canceled/no-write or pretend that aborting fetch rolls back the API. Confirm trusted
result IDs through existing READ history; submission-failure verification IDs may already name
an accepted terminal attempt. Stop with an explicit unconfirmed state when reconciliation is
insufficient. Process/session loss still ends ephemeral browser coordination: sign in and review
immutable API history, never silently issue a replacement intent. No durable BFF database,
distributed store or modification of accepted domain ledgers is proposed.

This is a new browser recovery contract, not already approved by backend idempotency or the
standing workflow. A memory-only browser UUID alternative has weaker page-reload recovery;
durable cross-process browser-intent recovery would require a separate API/schema design.

### D3 Dashboard scope and labels

Recommend remediation workflow plus the bounded selection/navigation repair. Keep ordinary
Start scan excluded unless the user explicitly chooses its additional contract. The default
five-control catalog remains unchanged: a retained completed EC2-004 FAIL with complete KMS
context and an eligible finding is required; the UI must explain unsupported/disabled evidence,
not enable controls or rewrite history.

Label request execution admission accurately; the isolated worker is operated separately.
Display historical approval plus server-derived blockers, execution phase/reservation, immutable
verification verdict and technical/finding state separately. Normal ACKNOWLEDGED can be verified
even when original write authority later expires/revokes; QUARANTINED cannot, including late ACK.
VERIFIED is a complete later historical observation, not causation, KMS usability, existing-volume
encryption or lasting state. New verification attempts are explicit and bounded, never write retries.

## Bounded implementation slices

After D1--D3 approval, recommend sequential slices, each with its own complete acceptance gates:

1. **8D1 Read-only foundation and navigation — recommended first.** Typed six-GET adapter and
   runtime-validated proposal/decision, v1/v2 execution and verification views; exact finding/
   occurrence links; separate status/validity display; explicit selection clearing/focus return
   and stable controls. No mutation, AWS dispatch, policy/default or persistence change.
2. **8D2 Approved manual workflow.** Default-off browser prepare/submit boundary, bounded
   same-session recovery, additive verified identity hints and explicit proposal/decision/revoke/
   admission/verification forms. Complete one signed three-human vertical path through existing
   APIs and read history; no public worker launcher or generic scan POST.
3. **8D3 Integrated UI acceptance.** Full adverse authority/replay/expiry/logout/cross-tab/
   response-loss/reload/capacity/race matrix, genuine offline installed worker plus managed
   read-only verification and PostgreSQL proof, all retained status/history compatibility and
   current-source two-browser/keyboard/mobile acceptance. No partial work unit completes 8D.

8E still requires whole-sprint security/compatibility acceptance and documentation closeout.
Do not mark Sprint 8 or the goal complete at 8D1, 8D2 or preflight. No Sprint 9+ work starts.

## Risks, compatibility and required validation

Principal risks are confused-deputy escalation, stale session/role/target state, duplicate
submission after uncertainty, misleading admission/ACK/verification labels, private history
leakage, unsupported version fallbacks, page relayout and growing detail payloads. Browser
display truncation and list limits are not network-payload bounds or tenant isolation. Keep
the accepted one-trust-domain/single-process and live-provider/physical-isolation limits.

Before changing interfaces, search all callers and atomically update frontend session/API
guards, BFF routes/store/config, development proxy, tests and API/security/threat/operations
owners. Preserve old GET/default-off behavior, all `/api/v1` bodies/enums/statuses, current
constructors/transactions, migration 0010, immutable history and worker/scanner separation.
Do not add speculative services, framework/provider changes or deployment infrastructure.

Required tests include default-off/no-development fallback; all four roles and full issuer/
subject separation; no ADMIN bypass; Origin/CSRF/context/header/body/URL injection; unknown
versions/coercive scalars/cross-ID bindings; caller-owned history and exact paired audits;
same key/input/current authority and conflicting replay; uncertain response/commit, expired or
changed session and post-logout effects; same-session reload and process-loss reconciliation;
no duplicate SDK write; three verification attempts/one active; stale/equal evidence, KMS drift,
partial/failed scans and quarantine; capacity and no unsafe eviction; native pointer/Back/focus/
mobile/keyboard/XSS and late-response clearing. Tests must cross genuine signed OIDC, BFF,
bearer API, disposable PostgreSQL, installed offline worker/closed SDK and managed reader.
Lower-layer fixtures/mock-fetch tests alone are not the complete story.

Each implementation slice runs targeted tests first, then Ruff lint/format and complete pytest
with an explicitly disposable TEST_DATABASE_URL, all PostgreSQL cases without skips, frontend
type/lint/unit/build, current-source Chromium/Firefox acceptance, Compose/image/startup/default
smokes, exact-commit independent review, complete candidate CI audits, ordinary guarded merge
and complete exact-main audit. Reuse the existing authorized reviewer; no new agent is needed.
Never weaken assertions/security headers, add retries/skips or reduce scope to obtain green.

## Analysis validation and limits

Fresh existing targeted checks passed **219 backend cases in 70.14s**, without warnings/skips,
covering dashboard/investigation APIs, the three signed remediation API wrappers, security and
owner contracts. Fresh pinned frontend unit checks passed **139 cases/eight files in 26.63s**.
These validate existing boundaries, not the proposed mutation or prepared-operation workflow.

The first frontend setup rejected global fallback pnpm 11.25.0 before tests; the existing
task-local pnpm 11.19.0 and Node 24.19.0 passed, without dependency updates. The first restricted
backend run yielded no complete-result evidence. An isolated asyncio startup stalled there
and completed in 0.276s outside the restricted environment. Only the exactly revalidated owned
test/probe children were stopped; their receipts remain. The unchanged authorized-local
selection then passed above. No application defect or underlying platform mechanism is claimed.

Documentation-only reconciliation corrected stale linked-verification, backend/browser scope,
global migration-head and API-index statements. Original predictions, failed runs and residuals
remain. Post-preflight checks passed **103 owner/link/status contracts in 0.43s**, Ruff lint,
454-file formatting and whitespace checks. No new full regression, PostgreSQL/browser journey, review, commit, push, PR, merge,
live AWS/IdP/IAM/secret, operator database, deployment or production operation is claimed here.

Stop for the D1--D3 design decision before implementing browser mutations or this execution
plan. Standing approval resumes routine gated work only after those new choices are resolved.

## Design approval and implementation entry

After reviewing the D1--D3 summary and this preflight, the user requested “Continue and implement”
on 2026-10-14. D1--D3 and the sequential 8D1--8D3 plan are approved. The original predictions
above remain the analysis record; current approved detail belongs in the active Sprint 8 plan
and current status in ROADMAP. Start with read-only 8D1. No live AWS, worker operation, operator
database migration, deployment, credential/IAM change or later sprint is authorized.
