# Sprint 8B3 integrated offline acceptance preflight

Prepared: 2026-10-11. Analysis only; 8B3 implementation remains PLANNED.
ROADMAP owns status; the [active plan](exec-plans/active/sprint-8.md) owns approved detail.

## Verified entry and authority

Clean local/remote main was verified at `04803adbb8baf825ec62f19c5b2bea015f907277`, the ordinary
PR #60 documentary merge. Exact first-attempt [main CI 38171117595](https://github.com/jnc247s/cloud-security-automation/actions/runs/38171117595)
completed successfully. Its reviewed tree is `5320218b39707d353fe96f91413ab1dc7f9b4099`, with
parents accepted implementation `7a36ddde20aafc60712b38165acd25460418ab92` and documentary head
`c17d47dc2f57b8e38f5c2faf363ca0561b58d79d`. PR #60's review, final-head push/PR CI, guarded merge
and exact-main gates passed; preparation-time pending receipts remain historical, not blockers.

Sprints 0--7, 8A, 8B1 and 8B2 are COMPLETE; Sprint 8/8B remain IN PROGRESS. 8B3 and 8C--8E are
PLANNED; Sprint 9+ is unstarted. Migration head remains `20261008_0009`, catalog `0.13.0`, default
catalog `0.2.1`, profile version `1.0.0`. Code acceptance is not deployment or operator migration.

The [approved 8B design](sprint-8b-preflight.md) already bounds 8B3 to integrated signed HTTP,
database, offline AWS, faults/security/container acceptance and delivery. Standing Sprint 8
authorization covers routine implementation within that design, validation, the existing reviewer
and guarded delivery. It does not decide a new architecture or authorize live operations.
This preflight records recommendations, not implemented tests or a completed acceptance result.

Scope is only EC2-004, action `aws.ec2.enable-ebs-encryption-by-default` version `1.0.0`, fixed
false-to-true. No additional handler, credential source, public worker endpoint, force-clear,
automatic rollback, rescan, dashboard mutation or general scan-start UI belongs in 8B3.

## Contracts, callers and existing coverage

| Boundary | Implemented evidence and integration implication |
| --- | --- |
| Human authority and admission | `app/api/routes/remediations.py` calls `RemediationService` for proposal/decision/revocation and `RemediationExecutionService.admit` for third-human EXECUTE admission. Production-mode OIDC checks signature, issuer, audience, expiry, subject and roles; capability checks remain in routes and mutation services. Three distinct verified issuer/subject pairs are required, including ADMIN. |
| Signed HTTP fixture | `tests/execution_http.py` completes signed proposal/approval/admission/READ on SQLite and `test_signed_execution_admission_http_postgres` repeats it on real PostgreSQL. It deliberately forbids AWS and stops at QUEUED. `tests/dashboard_fixtures.py` supplies a controlled issuer and real authorization without dependency overrides. |
| Worker orchestration | `RemediationWorker` accepts existing session, clock/pause and internal AWS-factory seams; `_db` closes each worker session before provider construction, STS/EC2 and close. Only `app/remediation/worker.py` launches it. API/scanner startup and Compose do not launch remediation. |
| Worker persistence | `RemediationWorkerService` takes admission guard first, then Resource/Finding/proposal/target/claim locks, rechecks time after waits, appends paired audit/journal, and commits WRITE_INTENT before dispatch. Claims and durable read budgets are private; no SQL lock fences AWS. |
| Closed AWS adapter | `EbsDefaultWriter.from_ecs` accepts only the fixed relative ECS task source, built-in SDK models and fixed regional STS/EC2 clients. `tests/unit/test_remediation_worker_aws.py` exercises real factory with synthetic metadata/Stubber, malformed/source/scope negatives and actual one-attempt transport errors. These tests do not start the signed HTTP journey. |
| Faults and races | `tests/unit/services/test_remediation_worker.py` covers service-seeded driver success, no-write, fencing, expiry/revocation, unknown write, simulated death, acknowledgment rollback, sticky quarantine and readback limits. `tests/integration/test_remediation_worker_postgres.py` repeats selected rules and real claim/resource-lock/revocation/downgrade races. Authority is seeded through services, not signed HTTP. |
| Public history | `app/api/routes/remediation_executions.py` uses READ-protected list/detail. `RemediationExecutionService._content/_events/_view` validates immutable bindings, digest links, paired human/service audit, versioned events and coordination. Authorized EXECUTE replay projects this history without renewing or dispatching. Current signed tests inspect only v1 QUEUED history. |
| Process/image | Process tests call `worker.main` in-process for default-off, invalid configuration and sanitized output. Existing accepted image probes verify installed SDK/default-off only. Neither is enabled separate-process HTTP-to-worker acceptance. Production image contains application/migrations, not tests or pytest; do not change production packaging to install a harness. |
| Scan/findings | `ScanService._create_pending_scan` selects current settings policy; `InProcessScanExecutor` subsequently honors persisted exact profile/catalog/services using the scanner's read-only provider. `persist_scan_result` owns explicit sufficient-PASS finding reconciliation. Worker acknowledgment/readback does neither and creates no scan. |

The gap is combined coverage, not evidence that accepted authentication/worker behavior is broken.
Do not claim separate passing suites or SDK/default-off probes prove the complete journey.

## Bounded implementation slices

Accept each delivery slice before advancing. Keep 8B3 incomplete until all three are accepted.

| Slice | Scope and acceptance boundary |
| --- | --- |
| 8B3.1 recommended first | Test-only signed proposal/approval/EXECUTE admission -> migrated disposable PostgreSQL -> real worker driver and closed adapter with entirely intercepted synthetic credential/AWS I/O -> signed READ list/detail and authorized replay. Include acknowledged-unverified and changed-precondition/no-write journeys, service/human audit distinction, no finding/assessment/scan mutation and no factory construction from API startup/admission. |
| 8B3.2 | Extend that journey with deterministic pre/post-intent faults, revocation/governance/expiry lock races, competing/reclaimed owners, ambiguous write/result commit, late receipt, post-intent read-only restart, target/capacity retention, global read budgets and signed denied/replay paths. Assert actual transport ceiling as well as SDK invocation ceiling where dispatch uncertainty is injected. |
| 8B3.3 | Installed-image and separate-process offline acceptance, forbidden source/scope/configuration/leakage negatives, default-off/no-start behavior and Compose compatibility; independently review/deliver the final 8B acceptance and reconcile limits. A mounted test-only harness may intercept transport before invoking the unchanged module entry point; never add a production test mode or endpoint override. |

Proposed first-slice paths are a focused shared helper such as `tests/worker_http.py`,
`tests/api/test_remediation_worker_acceptance.py`,
`tests/integration/test_remediation_worker_http_postgres.py`, and matching owner/plan receipts.
Reuse accepted fixtures and constructor seams; factor test helpers only where integration needs it.
No application, migration, dependency, IAM, CI or frontend edit is predicted for 8B3.1.
An actual application defect must be reproduced, explained and scoped before any repair; changes
to accepted intent require human approval, not silently different assertions.

### First-slice acceptance assertions

- Persist source evidence through existing offline EC2 fixtures and `persist_scan_result`, with
  complete exact EC2-004 FAIL/KMS provenance. Create proposal, approval and execution only through
  signed bearer requests; do not construct Principal objects or insert authority to bypass HTTP.
- Assert 201 proposal/decision, 202 first admission, 200 identical authorized replay, closed input,
  three distinct human identities, fixed derived scope and original request/digest/expiry. Admission
  and API lifespan do not construct the writer or submit a scan.
- Use the existing real ECS-only factory and adapter with synthetic temporary credential metadata,
  intercepted transport and Stubber/typed deterministic responses. Unexpected network destinations
  fail the test. No ambient credentials, profile/config file, metadata service or AWS is consulted.
  Keep one explicit synthetic account/Region/expected role; strict present and expected-absence KMS
  contexts both remain supported, including exact legacy non-ARN strings.
- At provider construction, STS, both settings reads, enable and shutdown, prove worker transactions
  are closed. Probe committed WRITE_INTENT and paired audit using a separate database session before
  the single enable invocation. Track relevant API/worker sessions and, where appropriate, use a
  separate PostgreSQL lock probe; assertions about only one test session are not complete evidence.
- READ must project unchanged immutable v1 admission plus correctly linked v2 service history,
  valid digests/audit IDs and private-coordinate exclusion. Success is ACKNOWLEDGED with observed
  desired state, never VERIFIED/PASS; changed precondition is NO_WRITE with zero enable calls.
- Compare retained scan/assessment/snapshot/evidence/finding/occurrence/governance state before and
  after. No new scan, assessment, finding lifecycle update or verification link is allowed. Only
  approved remediation coordination/journal/audit changes. List, detail and authorized replay agree;
  repeated READ/replay does not append history or renew grant. Missing bearer/cookie-only and lost
  capability still deny rather than reaching the worker.

## Decisions and recovery boundaries

No new architectural/design decision is identified for 8B3.1: the single action, distinct humans,
ECS-only isolated writer, default-off controls, stale-state checks and conservative recovery are
already approved. Test-only composition is routine work under standing authorization.

Keep the approved ceiling: EC2 enable-default and the two regional settings reads only; STS verifies
identity. Do not give scanner/API a writer role or broaden the writer with KMS, disable, key-change,
volume conversion, generic EC2 or IAM permissions. Separate code/configuration cannot prove deployed
task/host/network/IAM isolation, physical-human separation or safe default-key/workload usability.

Pre-intent reclaim uses a new fenced nonce and the same three-read budget; authority checks and
grant expiry never renew. Intent is the revocation cutoff, followed by at most one SDK attempt and
the final deadline check. After intent, process death/timeout/malformed receipt/uncertain commit
means possible effect. Recovery observes only, with the durable three-poll/thirty-second window;
true readback or late receipt cannot erase prior quarantine or free its reservation/capacity.
There is no TTL-based release, resend or compensating disable. AWS has no accepted CAS guarantee;
a paused worker after its final deadline check remains an external race.

Stop for explicit design approval if acceptance would require another credential channel, automatic
post-intent release/retry, stronger cancellation/CAS promises, caller-selected scope/endpoints,
new public worker routes, changed authority or success definitions, migration/runtime topology,
or production enablement. Incident release requires separate authorization and proof of old-worker
quiescence/effect, not a test waiver. Any required physical infrastructure is outside this slice.

Rescan remains 8C: exact approved account/Region/target, profile/catalog versions/checksums/services,
later COMPLETED scan, explicit EC2-004 PASS and complete proof. Public start_scan's current-policy
selection cannot substitute for that future linked seam. Bare acknowledgment, readback, partial or
failed scan, omitted control/target or insufficient evidence does not verify or resolve remediation.
Normal scan persistence remains the only finding reconciliation owner. 8C needs its own preflight;
8B3 only protects this boundary. Dashboard design remains 8D, including the user's earlier scan
selection/back-navigation report; no general scan-start UI is silently added.

## Risks, compatibility and validation

Principal risks are false confidence from disconnected tests, ambient credential/network leakage,
fault injection that hides real transaction/transport behavior, nondeterministic race timing,
incorrect v1/v2 READ projection or replay after worker events, and conflating ACK/observation with
technical repair. Use real migrated PostgreSQL, explicit barriers/bounded clocks, strict transport
interception, negative assertions and immutable before/after comparisons. Do not replace protected
tests, suppress genuine errors, waive failures or increase retries to obtain green results.

No existing interface change is predicted. Preserve constructor defaults, routes, status codes,
enums, event schemas, OIDC/capabilities, source/control/profile/catalog IDs, scanner credentials,
finding/exception history and startup. 0009 schema-before-code and strict v1/v2-event/expanded-phase
client coordination remain prerequisites even when the worker is disabled; no new migration or
operator database mutation is authorized. Broad SDK dependency ranges make fresh installed-image
checks necessary; report actual runtime versions rather than inheriting local ones.

Each implementation slice runs targeted new journeys and affected old API/worker/security/history
tests first, then `python -m ruff check .`, `python -m ruff format --check .` and complete
`python -m pytest`. Use the existing validator's freshly owned disposable PostgreSQL 16 and explicit
TEST_DATABASE_URL; integration skips are not acceptance. Never reuse an operator DATABASE_URL.
Run affected migration/integrity/claim/race regressions, Compose/image checks, and final installed
process acceptance. Preserve full dashboard type/lint/unit/build and 74 Chromium/Firefox regression
journeys in CI; native Firefox-launch and local picker/navigation limits remain unwaived.

Freeze the exact candidate for the existing independent reviewer, resolve findings, then require
both first-attempt final-head CI runs, ordinary expected-head guarded merge and green exact-main CI.
No new reviewer, forced merge, branch/worktree deletion, live AWS/IdP/IAM/secret/deployment or
production operation is authorized. Update owners for actual material changes, preserving original
predictions, failed receipts and anchors. 8E/whole Sprint 8 remains incomplete after 8B3.

## Analysis checkpoint

The scoped `codex/sprint-8b3-preflight` branch starts at accepted `04803ad`; three existing worktrees,
all prior branches and the parent's three unrelated untracked `.agents/` skill files are preserved
and excluded. This preflight and owner progress records are the only planned edits in this step.
No runtime/test/schema implementation, application launch, new reviewer, commit, push, PR or merge
is performed by this analysis. Validation results are recorded in the active plan when completed;
PR #60's passing checks are baseline evidence, not fresh acceptance of proposed 8B3 tests.
