# Sprint 8B3.2 combined fault and recovery acceptance preflight

Prepared: 2026-10-11. Analysis complete; test implementation has not started at this checkpoint.

The recommended next slice is test-only composition of signed human authority, migrated persistence,
the accepted worker and closed AWS adapter, deterministic faults, and authorized history. No new
architecture or design decision is identified. Standing Sprint 8 authority covers implementation
within the accepted design; it does not authorize live operations. [ROADMAP](../ROADMAP.md) owns
status and the [active plan](exec-plans/active/sprint-8.md) owns approved task detail.

## Accepted entry and preservation

The clean scoped branch `codex/sprint-8b32-preflight` starts at accepted main
`01db441ddeee8466e068b30f0547f29a3906f4e7`, tree
`1d713ea298359373f5ff20c851b2b89198d7ba45`. [PR #62](https://github.com/jnc247s/cloud-security-automation/pull/62)
closed the owning 8B3.1 documentation reconciliation. Exact-main
[CI 38194672821](https://github.com/jnc247s/cloud-security-automation/actions/runs/38194672821)
passed after exact-head independent review, both first-attempt candidate CI runs and a guarded
ordinary merge. Those are accepted baseline results, not validation of future fault tests.

Sprints 0--7, 8A, 8B1, 8B2 and 8B3.1 are COMPLETE. Sprint 8/8B/8B3 remain IN PROGRESS;
8B3.2/8B3.3 and 8C--8E remain PLANNED at this analysis checkpoint. Sprint 9+ is unstarted.
Runtime remains `7a36ddde20aafc60712b38165acd25460418ab92`, migration `20261008_0009`, opt-in
catalog `0.13.0`, five-control default catalog `0.2.1` and profile version `1.0.0`.

The ordinary main fast-forward and one new scoped branch preserve the other 70 local branches,
all three worktrees and the parent's three unrelated untracked `.agents/` skill files. Those
files are excluded from task edits and commits. No reset, clean, checkout replacement, branch
deletion, operator database mutation or live AWS operation belongs to this slice.

## Contracts and callers

The whole [8B3 preflight](sprint-8b3-preflight.md) and [approved 8B design](sprint-8b-preflight.md)
remain governing scope. The source inspection covers the following integration boundaries.

| Boundary | Existing contract and proposed test seam |
| --- | --- |
| Human authority | `app/api/routes/remediations.py` directly constructs `RemediationService` and `RemediationExecutionService`. Create proposal, approval, execution and revocation through production-mode signed HTTP, never inserted authority or authentication overrides. Test-only shared domain time can use the existing service clock constructor; JWT signature, issuer, audience, subject, roles and expiry remain real. |
| Admission and READ | `app/services/remediation_execution_service.py` validates immutable proposal/approval/request bindings, v1/v2 event digests and paired audit. Replay requires current EXECUTE and returns the original grant without renewal. Global admission limit is 32; only eligible queued authority can be reaped before intent. |
| Worker driver | `app/remediation/worker_driver.py` uses fresh sessions for each SQL operation, then closes them before factory, STS/EC2 and shutdown. Existing clock, monotonic, pause and factory seams suffice; no production test hook is needed. |
| Worker persistence | `app/services/remediation_worker_service.py` locks admission guard, Resource, Finding, proposal, target and claim in that order. Time is refreshed after lock waits. New pre-intent owners receive new nonces without resetting the three-read budget. WRITE_INTENT and its service audit commit before dispatch. |
| Adapter and transport | `app/remediation/worker_aws.py` uses the real ECS-relative-only temporary source, built-in models, fixed regional STS/EC2, two/five-second connect/read timeouts and total attempt count one. Intercept synthetic metadata and SDK transport before any network; count both SDK invocations and transport sends for ambiguous-write cases. |
| Signed baseline | `tests/worker_http.py` plus its API/PostgreSQL wrappers cover seven acknowledged/no-write journeys. Its strict transaction/row-lock probes, two-authority-audit expectation, Stubber queues, private-field checks and protected-state comparison must remain intact. Stubber-only write counts are not wire-attempt proof. |
| Existing faults | `tests/unit/services/test_remediation_worker.py`, `tests/integration/test_remediation_worker_postgres.py` and `tests/unit/test_remediation_worker_aws.py` already exercise seeded service faults, locks and transport errors. Retain them; combine their boundaries with signed authority rather than presenting disconnected suites as the integrated result. |
| Evidence and findings | `tests/remediation_fixtures.py`, `tests/execution_fixtures.py`, offline EC2 evidence and `persist_scan_result` supply trusted test evidence. Normal scan persistence alone reconciles findings. Worker receipts/readback must not create scans, change technical results, resolve findings or assert verification. |

Caller searches include the application worker entry point, route constructors, service/unit
harnesses, existing shared HTTP helper and both thin wrappers. No public worker route, scanner
writer dependency or control-specific service is added. Existing constructor defaults and all
accepted callers remain compatible.

## Bounded test matrix

One 8B3.2 delivery slice covers all families below. Individual passing families do not complete
8B3.2; the source, independent review, full regression and delivery gates remain required.

| Family | Combined journey and required assertion |
| --- | --- |
| Pre-intent authority and evidence | Signed grant followed by expiry at equality, revocation, governance change or newer assessment. Blocked authority performs no write; a block before claim constructs no AWS factory. Permanent reads and exhausted transient reads produce NO_WRITE with global budget at most three. Strict encryption/KMS changes never weaken expected-false/exact-key checks. |
| Ownership and reclaim | Competing workers have one owner. At the 30-second pre-intent lease boundary, reclaim uses a new nonce and retains the accumulated read budget. The old nonce cannot persist intent or a receipt. PostgreSQL barriers establish actual concurrent lock behavior; SQLite is not evidence of PostgreSQL serialization. |
| Lock waits and cutoff | On PostgreSQL, hold the real Resource lock while expiry, governance round-trip or signed revocation completes. The waiting intent operation rechecks fresh time/state and refuses stale authority. Revocation after durable intent is recorded but does not promise cancellation of a possibly dispatched call. |
| Ambiguous dispatch | Real adapter write transport timeout, retryable 503 and malformed success receipt each have at most one SDK enable invocation and one wire send. Durable intent/audit must precede that send. Uncertainty becomes sticky QUARANTINED with held target/capacity and sanitized history, never attributed success. |
| Death and uncertain result persistence | Simulated death before/inside dispatch and acknowledgment transaction failure leave possible-effect intent. Restart after grant expiry observes only; no resend or post-intent reclaim occurs. A late original-owner receipt or true observation cannot clear prior quarantine. Final-deadline expiry after intent dispatches zero writes and retains quarantine. |
| Readback and retention | At most three persisted polls in the original 30-second window across restarts, with no renewed window or duplicated ordinal. A response received after the deadline is not accepted as an observation. Held quarantine survives late receipts, expiry and new signed admission; exercise the actual 32-slot limit without lowering the production constant. Ordinary conclusive durable ACK may release the target but remains unverified. |
| Signed history and denial | At relevant fault phases, signed list/detail and authorized replay agree on unchanged v1 grant, linked v2 service journal and exact paired human/service audit. Missing bearer, cookie-only access, lost capability and conflicting replay deny without DB/AWS effects. READ/replay never append, renew, expose nonce/lease/intent coordinates, dispatch, verify or mutate findings/technical evidence. |

## Test isolation and implementation order

Recommend a new `tests/worker_fault_http.py` helper and thin API/PostgreSQL fault wrappers, with
PostgreSQL-only barrier tests in the integration wrapper. Reuse existing signed headers,
database projections and offline evidence. Factor an existing helper only if necessary and
preserve strict baseline defaults and every existing caller atomically. No application,
migration, dependency, CI, frontend or credential-policy change is predicted.

Start with signed grant setup and history checks, then pre-intent/no-write faults, real transport
uncertainty, restart/retention budgets and PostgreSQL races. Every completed family retains its
negative assertions; do not omit difficult families or rename a partial subset as completion.

Keep domain time shared across API and worker while leaving JWT authentication untouched.
Revocation adds a third human authority audit: assert it explicitly rather than relaxing the
baseline helper's exact two-audit check. Compare all protected tables before/after; deliberate
test governance/evidence mutations must be separately declared and checked. Never normalize
away unexpected finding, scan, assessment, evidence, exception or audit changes.

Use operation-specific strict response queues. Unused Stubber responses and unexpected transport
destinations are failures, not ignored tails. Existing no-active-worker-transaction probes must
not be weakened to accommodate an independently held PostgreSQL test transaction; use a separate
holder engine/session and bounded synchronization. External row-lock probes test committed intent
and release, not a stronger SQL-to-AWS lock guarantee. Fault injection must target an actual
boundary, including rollback/uncertain-commit outcomes, without replacing the accepted driver.

## Security and recovery decisions

Only EC2-004 action `aws.ec2.enable-ebs-encryption-by-default` version `1.0.0`, false to true,
is in scope. PROPOSE, APPROVE and EXECUTE require three distinct verified issuer/subject pairs;
ADMIN cannot bypass separation. Worker service identity is not a fourth human authority.
Scanner credentials remain read-only. The separate writer ceiling remains enable-default and
the two regional settings reads, with STS identity verification; no disable, key change, KMS,
volume conversion, IAM or caller-selected scope/endpoints are introduced.

Proposal expiry is 24 hours; grant expiry is the earlier of proposal expiry and admission plus
five minutes. Neither replay nor reclaim renews it. Intent is the revocation cutoff. After it,
uncertainty/death does not permit resend, TTL release or compensating disable. Readback observes
only and cannot establish causation, PASS or verification. Incident release remains separately
authorized, with proof of old-worker quiescence/effect, not a new force-clear API.

AWS provides no accepted compare-and-swap guarantee. A worker paused after its final deadline
check can resume and dispatch; tests must not imply hard cancellation, fencing of AWS, or certainty
that the request had no effect. Physical-human, IdP, task/network/IAM isolation and workload/key
usability remain unproved by offline tests. Code acceptance is not deployment or operator migration.

Stop for design approval if a discovered defect requires changed authority, credential channel,
topology, public API, event schema, success meaning, retry/release behavior or stronger cancellation.
Reproduce and explain an actual defect before proposing a narrowly scoped accepted-design repair;
do not alter assertions to fit a different intent.

## Compatibility and acceptance gates

The first frozen test candidate's review found three validation gaps. The bounded repair keeps
equal-time ambiguity as a separate case and proves strictly greater persisted observation time
plus STALE_TARGET for newer evidence. Governance expectations allow only the two exact fixture
audit rows captured before worker completion. Capacity checks compare full state immediately
before/after admission; denial permits no change. Trusted evidence fixture deltas are kept
separate from signed API effects, and every existing row remains protected. Negative regressions
inject the reviewer's weakened detector/unrelated audit/finding effects and require the helpers
to reject them. Passing ordinary cases cannot substitute for these guards or exact repair review.

Preserve routes, status codes, enums, constructors, history schemas, canonical IDs, profile/catalog
versions, fail-closed authentication, no-store/private projections and scanner startup. Migration
0009 remains schema-before-code even with the worker disabled; no new migration is predicted.
Rescan attribution remains 8C, dashboard mutation/navigation remains 8D and enabled image/process
security acceptance remains 8B3.3. Native Firefox launch and the local scan-picker/back-navigation
report remain limitations; Linux browser regression does not repair them.

Run new targeted journeys and affected old signed API/worker/auth/history tests first, then Ruff
check, Ruff format check and complete pytest. Use the existing validator's freshly owned disposable
PostgreSQL 16 and explicit TEST_DATABASE_URL; no operator database or skipped integration acceptance.
Cover actual PostgreSQL claim/lock/migration integrity, Compose and packaged-image compatibility.
Retain all frontend and 74 Chromium/Firefox regression journeys in final-head CI.

Record fresh actual counts and failure receipts, not inherited baseline totals. Freeze the exact
candidate for the existing reviewer, resolve every actionable finding, require both final-head
CI runs, ordinary expected-head guarded merge and successful exact-main CI. No branch/worktree
deletion, optional public-comment retry, live operation or later-sprint work is authorized here.
Whole Sprint 8 remains active and incomplete after 8B3.2 acceptance.
