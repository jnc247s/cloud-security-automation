# Sprint 8D2 manual remediation workflow preflight

## Entry and authority

Analysis checkpoint on 2026-10-15. ROADMAP and the active Sprint 8 plan agree: 8D1 is COMPLETE,
8D is IN PROGRESS, and 8D2, 8D3 and 8E remain required. Accepted main is
`d6a37658f2d34f94d26a475d91b95ef7a511d940`, tree
`f7c399635740c0e39f7cf0bd4488c6ff1c8be806`, through
[PR #70](https://github.com/jnc247s/cloud-security-automation/pull/70) and complete
[exact-main CI 38794113567](https://github.com/jnc247s/cloud-security-automation/actions/runs/38794113567).
Migration head remains `20261013_0010`.

The user approved D1--D3 and their sequential implementation on 2026-10-14. The
[8D preflight](sprint-8d-preflight.md) and
[approved predictions](exec-plans/active/sprint-8.md#approved-8d-predictions) govern this slice.
Standing workflow approval covers implementation and gated delivery within those choices; new
architecture or design choices still require the user. No new such choice was identified in
this analysis. Live AWS, worker operation, deployment, IAM/secrets, operator databases and
Sprint 9+ remain excluded.

The existing task checkout was reused. Clean, audited main was normally fast-forwarded before
creating `codex/sprint-8d2-preflight`. Thirteen pending owner-document/status-contract edits
reconcile accepted 8D1; they are task-owned and preserved. All 78 predecessor branches, three
worktrees and three unrelated parent skill files remain; the scoped branch is the sole branch
addition. No reset, clean, replacement, branch deletion or unrelated staging occurred.

## Contracts and integration findings

The inspected interfaces include dashboard routes/store/config, authentication and capability
mapping, all five bearer mutation routes and their request/view models, domain error handlers,
verification submission/replay, immutable history readers, frontend bootstrap/API/session
clearing and investigation/history callers, signed HTTP helpers, security/config/owner tests,
and the existing two-project browser fixture. Permanent owner documents, product requirements
and completed Sprint 7 constraints remain applicable.

| Boundary | Existing behavior | Required 8D2 treatment |
| --- | --- | --- |
| Dashboard session | Opaque cookie; cached identity metadata; fresh token validation on each lookup | Use the newly verified principal for preparation/submission capabilities and issuer/subject binding, not cached roles. Keep existing READ/session callers compatible. |
| Bearer API | Five fixed typed POST operations with UUID idempotency keys and fresh capabilities | Re-enter these APIs, not services or SQL. Server selects the operation, path, normalized body and key; no browser-selected URL, credentials, scope or desired state. |
| Proposal | Exact finding/occurrence, fixed action/version, reason | Review exact IDs and fixed risk. Preparation does not yet have a sealed proposal digest and must not imply a durable proposal exists. |
| Decision and admission | Proposal digest plus referenced approval where required; domain revalidation and three distinct identity pairs | UI hints cannot authorize. Preserve stale/equal-evidence, governance, expiry and no-ADMIN-bypass checks in the services. |
| Revocation | Any current APPROVE principal, including a proposer with that capability | Do not reuse the stricter initial-approval UI identity exclusion for revocation. |
| Verification | Linked request commits before executor submission; same actor/key replays without resubmission | A submission-failure 503 can already name durable verification/scan IDs. Confirm those IDs through READ history; never turn 503 into a replacement intent. |
| History | Immutable content plus changing operational phase/blockers/receipt | Reconciliation compares immutable IDs, digests, reason and actor pair, plus request key where exposed. Do not require mutable state or historical role lists to remain identical. |
| Frontend bootstrap | Existing runtime guard tolerates additive fields; old clients have no issuer/feature hints | Add verified non-secret hints. Missing hints keep the new client READ-only; malformed hints never enable writes. Keep existing login/logout client closed. |
| Session loss | Logout/expiry/cross-tab transitions immediately clear private UI; no Web Storage | Preserve immediate clearing and late-response rejection. Aborting a forwarded request does not cancel its effects. |

The only upstream mutation mappings are:

| Prepared operation | Fixed bearer route | Capability |
| --- | --- | --- |
| Proposal | `POST /api/v1/remediations` | PROPOSE |
| Decision | `POST /api/v1/remediations/{proposal_id}/decisions` | APPROVE |
| Revocation | `POST /api/v1/remediations/{proposal_id}/revocations` | APPROVE |
| Execution admission | `POST /api/v1/remediations/{proposal_id}/executions` | EXECUTE |
| Linked verification | `POST /api/v1/remediation-executions/{execution_id}/verifications` | EXECUTE |

Existing request/response models, enums, status codes, service constructors, transactions,
idempotency ledgers, role maps, ORM and migrations are unchanged. Proposal/decision READ views
do not expose their request key: the BFF must not invent a key-lookup API or claim that history
provides a key proof it does not contain. A trusted response reference and exact immutable
history binding are required; insufficient evidence remains unconfirmed.

## Preparation and recovery

Add the independently default-off `DASHBOARD_REMEDIATION_ENABLED` setting. True requires an
enabled OIDC dashboard. Backend admission/verification flags and explicit scopes remain
independent and default-off. No setting derives write scope from scanner configuration.

Use the approved closed preparation and submission namespace:

- `POST /dashboard/api/remediation-operations` prepares one typed operation.
- `POST /dashboard/api/remediation-operations/{operation_id}/submit` explicitly confirms or
  retries that operation, without a replacement body/key.
- Session-bound GET list/detail on the same resource recovers coordination after reload.

The server creates a UUID and freezes the normalized operation/target/body and verified
issuer/subject pair. Memory holds no access token, raw upstream response cache or domain grant.
Limits remain 16 operations/session and 256 globally; reject exhaustion rather than evict
uncertain work. Preparation expires at five minutes or the existing session deadline, whichever
comes first. It never renews the session, proposal, execution grant or database reservation.

Use the existing session-store synchronization boundary for atomic coordination, with no lock
held over authentication, HTTP or database work. Session expiry/revocation/clear also discards
its coordination; opaque operation IDs are not capabilities and another session cannot use them.
Record in-flight state before dispatch, so concurrent confirmations cannot make a second call.
Only an explicit same-actor retry can reuse the identical key and normalized body while the
preparation remains valid. No automatic retry, background submit or key regeneration is added.

Coordination distinguishes prepared, in-flight, unconfirmed, confirmed and unused-expired
operations. Expired forwarded work remains unconfirmed rather than becoming canceled/no-effect.
Retain its references until session loss; expiry does not erase uncertainty or free capacity
through unsafe eviction. A confirmed request is not proof of worker execution or verification.

All new boundary paths require current identity/capability and matching session context.
Mutation paths additionally require exact Origin and same-origin fetch-site, bounded CSRF and
closed typed JSON within 12 KiB. Reject duplicate security headers/JSON keys, extra fields,
coercive values, invalid UTF-8, non-finite values and browser-selected upstream inputs. Parse
errors are fixed and sanitized, not FastAPI validation echoes containing user input.

After dispatch, timeout, response loss, malformed data, logout or expiry cannot prove no effect.
A later denied retry cannot settle an earlier uncertain commit. Confirm trusted result IDs
with the existing fixed READ APIs. Recognize only the existing sanitized
`verification_submission_failed` shape, then validate its verification/scan/execution/actor/key
bindings against history. Its accepted attempt may have a failed scan/receipt; it is never
displayed as VERIFIED merely because the request exists. No sufficient reference means an
explicit unconfirmed result and manual immutable-history reconciliation, not a fresh request.

Session/process loss ends this ephemeral recovery mechanism. Signing in again and observing an
empty operation list does not establish that previous work had no effect. Explain the manual
history check before preparing any replacement. Do not add durable BFF persistence or mutate
accepted domain recovery, reservation or audit policy.

## Implementation work units

These are work units within one complete 8D2 slice, not independently completed slices:

1. Add frozen coordination types, bounded session-store transitions, the independent flag and
   targeted expiry/actor/capacity/concurrency/default-off tests. This is the recommended first
   work unit because all later routes and UI recovery depend on its invariants.
2. Add fixed typed preparation/submission/history-confirmation adapters and signed API tests.
   Preserve the existing Dashboard session/READ interfaces. Check fresh authority before
   claiming an operation and again through the normal bearer route; never cache authorization.
3. Add guarded typed client calls, authenticated issuer/feature hints, same-session recovery
   and all five manual forms. Keep existing READ props/routes compatible. Review/confirm/retry
   are explicit; no automatic chaining, Web Storage, worker launch or ordinary Start scan.
4. Prove the signed three-human path through the real BFF, bearer APIs and disposable
   PostgreSQL, including reload/replay and durable verification submission-failure recovery.
   Keep the flag-enabled browser fixture/data isolated from the accepted default-off fixture:
   new proposals must not reorder global histories used by retained browser assertions.
5. Update owner documents, run all slice gates, obtain exact-commit independent review from
   the existing reviewer, and complete candidate/merge/exact-main audits before 8D3.

Forms retain separate historical approval/current blockers, execution phase/reservation,
verification verdict, technical status and finding handling. Admission requests do not start
the separate worker. Normal acknowledgment remains eligible for verification after write
authority expires/revokes; quarantine and late acknowledgment are not. VERIFIED remains an
exact later historical observation, not causation, lasting state, KMS usability or encryption
of existing volumes.

## Risks and validation

Primary risks are confused-deputy authority, cached roles, cross-session operation access,
double dispatch, unsafe replacement after uncertainty, incorrect mutable-history comparisons,
mislabeling accepted requests as execution success, private data retained across logout, and
flag-enabled test data interfering with retained default-off journeys. Closed typed mappings,
fresh authority, atomic claims, conservative recovery, immutable READ confirmation and isolated
fixtures address these without changing domain policy. Single-process memory and the existing
one-trust-domain deployment limit remain; no cross-process durability or tenant isolation is
introduced.

Targeted coverage must include all roles and issuer/subject pairs; self-approval/admission
separation and no ADMIN override; Origin/CSRF/context/header/body injection; strict versions and
cross-ID history bindings; same key/input/current authority; denied replay after uncertain
commit; simultaneous submit; exact expiry, capacity without eviction, session/process loss and
logout during dispatch; normal and submission-failed verification references; no duplicate
worker write; default-off/legacy-client and retained history compatibility. Keep accepted
assertions and existing browser retries, timeouts, security headers and two-project coverage.

The complete 8D2 gates remain targeted tests, Ruff lint/format, full backend regression with
all PostgreSQL cases against an explicitly disposable TEST_DATABASE_URL, frontend
type/lint/unit/build, both browser projects, Compose/image/startup/default-off proof,
exact-commit independent review, both complete current-scope candidate CI primary audits,
ordinary expected-head guarded merge and complete exact-main audit. 8D3 still owns expanded
adverse UI/installed-worker/managed-reader acceptance; 8E still owns whole-sprint closeout.

Fresh preflight checks passed 295 existing backend cases in 122.77 seconds, without warnings
or skips. The primary log records removal of only that run's labeled temporary tmpfs database.
All 539 frozen source paths and hashes were independently rechecked unchanged after terminal
output. Native observation state was unavailable after context continuation; the saved complete
pytest/cleanup primary, not a restarted run or an inferred process exit, establishes this result.
These are existing-contract checks, not tests of new 8D2 functionality or a new full regression.
Accepted 8D1 CI receipts are predecessor evidence, not fresh frontend/browser runs for 8D2.

At this checkpoint application implementation is unstarted. No reviewer, commit, push, PR,
merge, operator migration, live provider, credential or production operation occurred. The
approved plan permits proceeding with the first bounded work unit; full Sprint 8 remains active.

## Implementation continuation

Under the existing D1--D3 approval, local implementation began with the store/configuration
and fixed server adapters described above. The active plan records exact work-unit receipts,
preserved failures and pending UI/full-slice gates. The API owner now specifies the
[local preparation contract](api.md#sprint-8d2-preparation-boundary-local-candidate).
This continuation does not change the analysis predictions or constitute accepted 8D2.
