# Remediation authority operations

This describes accepted Sprint 8A proposal/decision authority through PR #53 and 8B1 database
admission through PR #55, with exact-commit independent review, both final-head CI and green exact
main CI 37726113041. It is not a deployment or live-operation authorization. ROADMAP and the active
[Sprint 8 plan](../exec-plans/active/sprint-8.md) own status and approved scope. See the
[API contract](../api.md), [persistence](../persistence.md), SECURITY and THREAT_MODEL.

The 8B2 section below describes accepted code through PR #59 and exact main CI 37864100728,
not deployment behavior or live authorization. The 8B2 migration was `20261008_0009`;
execution-history readers still require it even while the worker is disabled. Current accepted
head is `20261013_0010` for 8C verification history. Apply schema before
updated code only under separately authorized maintenance; no operator database is auto-migrated.

## Implemented boundary

8A stores immutable intent, initial approval/rejection, approval revocation, idempotency results
and paired audit. It cannot execute an AWS change, acquire a write identity, submit a remediation
job, rescan, change a finding/exception or use the dashboard as a mutation proxy. Scanner
permissions remain exactly the read-only inventory policy. Do not grant scanner write access.

The sole action/version is `aws.ec2.enable-ebs-encryption-by-default` / `1.0.0`, for EC2-004,
fixed false-to-true in the finding's account/Region. Its future effect is encryption of future
EBS volumes and snapshot copies; it does not encrypt existing volumes, change the default KMS
key or support automatic rollback. Review workload/default-key compatibility before proposing;
a technical FAIL is not approval of an operational change.

## Local/test workflow prerequisites

Use an explicitly isolated, migrated development/test database. The accepted default catalog
`0.2.1` remains unchanged: a reviewed opt-in EC2-004-enabled exact profile/catalog and completed
scan are required. Proposal creation needs a retained explicit FAIL occurrence, false default,
complete encryption and default-KMS/expected-absence evidence, and OPEN/ACKNOWLEDGED disposition
without an active unexpired exception. Missing KMS evidence blocks remediation eligibility but
does not rewrite the technical assessment or remove its finding.

Use the normal bearer API with controlled signed test identities or a separately approved
properly configured IdP. Missing/malformed identity is never replaced by a test override in
production. Development auth represents one fixed identity and cannot complete self-approval.
Do not expose it publicly, invent role headers or bypass authentication to test the workflow.

1. A PROPOSE human principal selects the exact finding/occurrence and submits a bounded reason
   and supported action/version with a new UUID Idempotency-Key.
2. A different APPROVE human principal reviews the whole immutable content, risk, exact baseline
   and digest, then submits APPROVE or REJECT with that digest and a separate request key.
   ADMIN has no separation bypass. APPROVE revalidates stored eligibility under locks.
3. If authority must be removed, any APPROVE principal submits the exact proposal digest and
   approval decision ID plus reason to the revocations route. Revocation is terminal and remains
   possible after expiry/staleness. There is no proposer withdrawal or reapproval.
4. Use READ list/detail to inspect immutable decisions and current derived blocking reasons.
   An APPROVED record can be expired/stale without losing its historical approval. These checks
   use retained database evidence only, not a fresh AWS observation. 8A has no execution step;
   accepted 8B1 admission below still cannot dispatch AWS work.

All identities are compared as full verified issuer/subject pairs. IdP policy must prevent one
person controlling several approval identities and grant human workflow roles only to suitable
human accounts; cryptographic token validation cannot prove distinct physical people. Accepted
8B1 enforces a third distinct execution requester. Accepted 8B2 adds separate worker service
attribution; that identity is not a fourth human or part of 8A/database admission.

## Retry, staleness and recovery

Keep a request's key and normalized input together in the trusted caller. After an ambiguous
HTTP/database timeout, retry the identical request with the same identity/operation/key. Current
capability is still required. A successful prior commit returns the original record (200 rather
than first-create 201), without duplicate audit or renewed authority. Different content under
the same key returns 409; keys are scoped across all proposals within each operation. A sanitized
503 is a failed/unavailable persistence operation, never proof of success. Read/retry to establish
the stored outcome; do not manufacture a new key to hide an ambiguous result.

Approval expires 24 hours after proposal creation. Any other assessment for the same stable
target/control observed later or at an ambiguous equal time invalidates it, irrespective of
result. Relevant finding/exception history changes also invalidate the bound governance digest.
An omitted control is not an assessment or evidence of a fix. Submit a new proposal against a
reviewed current occurrence rather than refreshing/reusing stale intent. REJECT or REVOKE can
remove authority when positive approval is blocked. GET never writes expiry or lifecycle rows.
Finding governance is bound to append-only event IDs, so returning to the prior status cannot
revive an old proposal or approval, even when both changes have the same timestamp. Pre-repair
local proposals fail the tightened governance digest; create new reviewed intent, never rewrite
or delete the original authority history.

Programmatic service READ callers must use a session without pending inserts/updates/deletes.
The service rejects pending work before querying rather than flushing or refreshing it away.
Clean caller-owned transactions remain usable and open; only mutations require an idle session.
HTTP request sessions already satisfy this boundary. READ traversal suppresses autoflush.

8A has no durable execution attempt/recovery state, live precondition call or rescan link. Later
slices must distinguish a committed pre-call execution intent, successful/unknown AWS effect,
bounded retries and exact-policy verification; they cannot infer success from an API return,
absence, partial PASS or an approved proposal. Findings retain their existing completed-scan
explicit-PASS-only resolution policy. Do not manually change finding results to mimic execution.

## Migration, data and acceptance gates

Accepted repository migration head is `20261008_0009`; no deployed database migration is claimed
or authorized by code acceptance. Apply through Alembic only and validate against an explicitly
disposable TEST_DATABASE_URL. New authority/audit history is sensitive. Restrict DB access and protect
backups; append-only guards do not protect against privileged schema modification/direct INSERTs.
Human authority/admission audit actor IDs are canonical issuer/subject identity digests; full
human identity/roles/capability are retained in metadata. Worker events instead use
`actor_type="service"` and the canonical JSON SHA-256 of `WorkerActor`
(`service_id`, `expected_role_arn`), without human roles or capability. Service history is not a
fourth human approval. Legacy audit limitations remain unchanged.

Before any separately authorized downgrade, quiesce writers, verify a restorable backup and use
the current online migration environment. Any 8A authority row or new remediation audit event
blocks the entire downgrade path across 0007 before DDL; offline crossing is blocked. Do not
purge immutable records or disable constraints to force rollback. Prefer reviewed forward repair
or a separately authorized backup restoration.

No deployment, writer-role policy, IAM/secret change or live AWS operation is authorized by code
implementation or tests. 8A and its documentary closeout cleared exact-commit independent review,
accepted publication, guarded ordinary merge and green exact merged-main CI. PR #54 closes the
documentary prerequisite with exact merged-main CI 37706030374 at
`24dbda32a0babcffff9698ece4a46c406690ef8e`. The
[8B analysis preflight](../sprint-8b-preflight.md) records the design bundle approved on 2026-10-07.
8B1 admission/journal and 8B2 isolated-worker code are accepted; neither is live-operation
permission. Remaining slices need their own required
review/delivery/acceptance. The active plan records
standing approval for routine Sprint 8 workflow; architectural/design decisions and live operations are
not pre-approved. Integrated 8B offline acceptance is recorded below; rescan, UI and whole-Sprint-8
acceptance remain later bounded slices. No later sprint is started here.

<a name="approved-local-8b1-admission--pending-acceptance"></a>

## Accepted 8B1 admission

Accepted 8B1 adds a third-human execution request/history, not an AWS worker. It introduced
`20261007_0008`; current code requires accepted `20261008_0009` even with the worker disabled.
Use only an explicitly isolated, authorized local/test database with the matching current schema.
No existing database/demo or live provider is assumed or migrated by code acceptance.

New requests default off. An authorized local/test operator may explicitly configure
`REMEDIATION_ADMISSION_ENABLED=true`, `REMEDIATION_ACCOUNT_ID` (12 ASCII digits), and
`REMEDIATION_REGION` (exact reviewed Region). Enabled-but-missing/invalid scope fails startup.
Scanner `AWS_PROFILE`/`AWS_REGION` is not reused or changed; there are no writer credentials or
worker flags in this slice. Never enable a production operation under test/implementation approval.

After proposal and independent approval, a third verified human with EXECUTE supplies exact
`proposal_sha256`, `approval_decision_id`, nonblank bounded `reason`, and UUID Idempotency-Key to
`POST /api/v1/remediations/{proposal_id}/executions`. Full issuer/subject pairs must be distinct,
including ADMIN. Admission rechecks retained eligibility and configured scope. It returns 202 with
QUEUED history and a grant expiring at the earlier of proposal expiry or request time plus five
minutes. There is no dispatch; API success does not mean the EBS setting changed or a finding passed.
The dashboard still cannot submit this request, and one fixed development identity cannot complete
the three-person flow. IdP governance is required to establish suitable human accounts.

Read `/api/v1/remediation-executions` (optional proposal_id, bounded pagination) and detail by UUID
with READ. Review `phase`, `blocking_reasons`, `reservation_held` separately: reads may report
QUEUED with expiry/revocation blockers, and never mutate/release it. Identical EXECUTE retries use
the original key/body, return 200 without renewed authority or events even when new admission is
off, and still require current capability. Changed input/key reuse is 409; do not create a new key
to hide an ambiguous result. One request per proposal; one outstanding per target; 32 globally.

A successful new admission can journal EXPIRED/BLOCKED and release only validated QUEUED/no-write
history; failed admission rolls cleanup back. 8B1 itself supplies no periodic reaper, worker recovery
or WRITE_INTENT phase. 8B2 unknown-effect reservations stay quarantined, never released by
this grant's elapsed time. A new proposal/approval is required for a new request after termination.

Revision 0008 preserves old ledgers and adds protected request/journal/coordination records. Any
execution, event, reservation coordinate or new execution audit blocks downgrade across 0008
before DDL; offline crossing is blocked. Empty seed alone permits empty round-trip. Quiesce writers,
verify a backup and obtain separate operational authorization; never delete history/disable guards.
The subsequent test-only repair/documentary reconciliation completed through PR #57/#58 with
exact merged-main CI; ROADMAP retains the original failures and final receipts. No live AWS or
production work is authorized.

<a name="8b2-isolated-worker-candidate--not-authorized-for-live-operation"></a>

## Accepted 8B2 isolated worker — not authorized for live operation

The disabled-by-default one-job entry point is `python -m app.remediation.worker UUID`. It is
never started by API, scanner or Compose startup. A default-off invocation exits with
`WORKER_DISABLED` before database/credential lookup. Offline tests use synthetic metadata and
SDK responses; installed-process tests intercept all transport before the real entrypoint. Do not enable
the process or run a live job under implementation, test, CI or merge approval.

After separate operational approval, the isolated process requires environment-only
`REMEDIATION_WORKER_ENABLED`, `REMEDIATION_WORKER_ACCOUNT_ID`, `REMEDIATION_WORKER_REGION`,
`REMEDIATION_WORKER_ROLE_ARN`, `REMEDIATION_WORKER_DATABASE_URL`; enabled mode requires all four
scope/database values and PostgreSQL migrated to accepted 0009. `.env` and scanner/application
settings are not loaded. Do not copy scanner keys/profiles or put credentials/URLs in CLI arguments.
No worker values are added to shared `.env.example` or automatically injected into Compose.
Runtime receives only ECS task-role temporary credentials through the fixed relative metadata
source. Static keys, profiles/shared host roles, web identity, custom credential/service endpoints
and fallback are rejected. Factory/code flags cannot prove physical credential isolation.

Deployment must independently prove an isolated writer task not shared with API/scanner, expected
STS account/role and reviewed account/Region-limited IAM ceiling: enable-default and only the two
regional settings reads. No policy/role/network/credential/deployment change is supplied here.
EC2 settings reads do not prove key usability or future workload compatibility. Operators retain
the approved compatibility review; no additional KMS permission or key change is inferred.

Only original immutable three-human admission permits claim/intent. Pre-intent attempts are
fenced, short-lived and capped at three across owners; expiry/revocation/changed settings terminate
without dispatch. Committed WRITE_INTENT is the cancellation cutoff, followed by one SDK write
with bounded timeouts and no retry. A conclusive completed call/durable receipt may release normal
ownership; it is ACKNOWLEDGED_UNVERIFIED, not a repair verdict. Worker dependency logs are disabled
and output is fixed classifications only; use authenticated sensitive READ journal/audit to inspect
history, not raw provider logs or credentials. READ errors/absence must not be interpreted as success.

Crash/timeout/malformed result/ambiguous receipt commit leaves possible effect and sticky
quarantine. Restart is read-only after intent, even after grant expiry; the global three-poll/
thirty-second observation window never renews on restart. True readback or a late original receipt
does not clear quarantine. No repeat enable, lease/TTL release, force-clear API, automatic rollback,
manual finding resolution or rescan is provided. Separately authorized incident recovery must prove
the old worker cannot resume and reconcile effect before any forward repair/release is designed.
Preserve history and obtain approval; do not create another proposal to bypass a held target.
8B3 offline installed-worker acceptance is recorded below; 8C exact-policy read-only verification,
8D UI and 8E remain later gates.

<a name="integrated-offline-acceptance-candidate-8b31"></a>

## Accepted integrated offline tests 8B3.1

The test-only first slice of the [8B3 preflight](../sprint-8b3-preflight.md) joins production-mode
signed human authority/admission, real migrated database history, the existing isolated-worker
driver/closed ECS-only adapter and authenticated execution READ/replay. Tests intercept synthetic
credential metadata and SDK responses; they do not access an ECS metadata service or AWS.
The PostgreSQL version uses only an explicitly configured disposable TEST_DATABASE_URL and
separate NOWAIT lock probes. Expected-absence, ARN and exact legacy key contexts are retained;
already-enabled or changed key/absence preconditions produce NO_WRITE without enable dispatch.

The accepted tests verify durable intent/audit before one offline write and acknowledged-unverified
history without changing scans, technical results, findings, exceptions or governance. Local
focused/full backend and PostgreSQL, quality, Compose/image and cleanup gates passed, followed by
exact tested-source and final-head REVIEW_PASS. [PR #61](https://github.com/jnc247s/cloud-security-automation/pull/61)
merged at `eea2f0c` with the reviewed tree unchanged after both first-attempt candidate CI runs;
exact merged-main [CI 38185057377](https://github.com/jnc247s/cloud-security-automation/actions/runs/38185057377)
passed. Each run passed all 3,274 backend tests, 448 PostgreSQL cases without skips, 133 frontend
tests, 74 Chromium/Firefox journeys and all quality/image/cleanup steps. Signed fault/race/recovery
is accepted below; enabled installed-image/separate-process acceptance remains a later 8B3 gate. This is not
deployment, physical credential isolation, attributed verification, automatic incident recovery,
operator migration or live execution proof. The API/dashboard/scanner behavior and all operator
authorization boundaries above remain unchanged. ROADMAP owns current status.

<a name="local-fault-and-recovery-test-candidate-8b32"></a>

## Accepted combined fault and recovery tests 8B3.2

The [8B3.2 preflight](../sprint-8b32-preflight.md) bounds the accepted test-only slice to combined
signed authority, unchanged database/worker/adapter behavior, deterministic faults and authorized
history. The tests intercept metadata and every real STS/EC2 transport, count actual
enable sends as well as SDK invocations, and exercises PostgreSQL ownership/lock races. No AWS,
ECS metadata service, operator database, credential issuance or production system is contacted.

Tests preserve the intent cutoff and uncertain-effect quarantine after crashes, late receipts,
true observations and grant expiry. Read-only recovery retains global budgets/window and target/
capacity ownership; a conclusive acknowledgment durably committed before a lost return remains
ACKNOWLEDGED and unverified. Neither result verifies the control or resolves a finding. These
are offline fault/recovery tests, not enabled-process, physical-isolation or deployment evidence.
The corrected fault suite and cleanup repair received independent exact-head REVIEW_PASS.
[PR #64](https://github.com/jnc247s/cloud-security-automation/pull/64) ordinarily merged at
`9c3df32` with the reviewed tree unchanged after both first-attempt candidate CI runs;
exact merged-main [CI 38294459508](https://github.com/jnc247s/cloud-security-automation/actions/runs/38294459508)
passed. Each final run passed 3,330 backend tests (all 478 PostgreSQL cases without skips),
139 frontend cases, all 76 browser journeys and quality/image/cleanup gates. The original failed
main Firefox cause remains unconfirmed; application layout is unchanged and its demonstrated
pointer-interaction race remains for 8D. The active plan retains failures, exact acceptance and
the preceding documentary closeout's separate gates before 8B3.3, now accepted below. ROADMAP owns status.
No operator procedure, authorization boundary, scanner privilege or runtime behavior above changes.

## Accepted installed process and security tests 8B3.3

[PR #66](https://github.com/jnc247s/cloud-security-automation/pull/66) merged at
`d338040260de3954065a46041118504134bc320c`, preserving reviewed tree `08bcaae8`, after exact-head
REVIEW_PASS and both first-attempt candidate CI audits. Complete first-attempt
[exact-main CI 38346013358](https://github.com/jnc247s/cloud-security-automation/actions/runs/38346013358)
passed. Each run passed all 3,567 backend cases/152 files (597 PostgreSQL cases/26 files, no skips),
139 frontend cases/eight files, all 76 browser journeys and all 18 quality/image/cleanup steps.

Fresh restricted test containers run the unchanged installed worker and real SDK with synthetic
temporary credentials and intercepted metadata/STS/EC2 transport. Tests bind signed three-human
authority and public history to independent database/lock/commit probes, exact source fingerprints,
actual installed versions, non-root/read-only/no-new-privileges runtime and narrow mounts.
Configuration/credential-source, identity, transport and proof negatives fail closed; fresh-process
crash/uncertain-effect recovery never resends enable or renews global read budgets/window.
Packaged API startup preserves queued history and cannot construct/dispatch the writer.
The 119-case integration file includes eight parent-only snapshot negatives and API startup;
it is not 119 enabled-worker journeys. All retained signed fault/race/recovery tests also ran.

This completes offline 8B acceptance, not deployment or live authorization. The owning-document
closeout passed its review/candidate/guarded-merge/exact-main gates through
[PR #67](https://github.com/jnc247s/cloud-security-automation/pull/67) at `771d630c`, exact-main
CI 38423060289. The [8C preflight](../sprint-8c-preflight.md) R1--R3 recommendations were approved
on 2026-10-13; linked verification is now accepted in default-off 8C1 below. Worker/admission stay
default off; scanner permissions are unchanged. Migration 0010 is now the accepted head;
existing execution-history compatibility remains as documented for 0009. Test-container
restrictions do not establish physical ECS/task/host/network/IAM separation or distinct physical
humans. Key/workload compatibility, live providers, operator maintenance and production remain
separately gated. Acknowledgment/readback is not causation, attributed verification, technical PASS
or finding resolution. 8B supplies no incident force-clear, TTL release, rollback or rescan;
8C1 now supplies the separate read-only verification scan, not browser mutation.
Historical failures and unfixed dashboard interaction limits remain in the active plan
and [limitation register](known-limitations.md); passing Linux/installed-process tests do not fix them.

<a name="linked-verification-8c1-candidate"></a>
## Linked verification 8C1

Use the generic bearer [verification API](../api.md#linked-remediation-verification-8c1-candidate)
for a new read-only full-original-scope scan after normal ACKNOWLEDGED history. Accepted through
PR #68 and complete exact-main CI 38483896952, with integrated 8C2 acceptance/coherent receipt
reads accepted through PR #69 and exact-main CI 38523209002, it remains default off and undeployed. It requires
migration `20261013_0010`; operator database maintenance is separately
authorized and never automatic from code acceptance. `/ready` remains connectivity-only.

`REMEDIATION_VERIFICATION_ENABLED` defaults false. Enabling requires explicit
`REMEDIATION_VERIFICATION_ACCOUNT_ID` and `REMEDIATION_VERIFICATION_REGION`, not scanner/writer
scope fallback. The same scope guard applies before collection on RUNNING recovery. Compose
defaults, scanner permissions and writer isolation are unchanged; no live scope is enabled here.
The caller sends only a bounded reason and UUID Idempotency-Key, never credentials/policy/scan ID.
Persisted requested services must match one of the executor's four retained complete-scope
generations; unsupported/ad-hoc scopes fail closed before provider construction.

Poll READ detail for a sealed receipt. VERIFIED requires complete strictly later EC2-004 PASS
and unchanged complete present/absent KMS context. NOT_VERIFIED requires equally proven FAIL;
partial/failed/unavailable evidence or context drift is INCONCLUSIVE. Technical results and
finding status stay independent; full-scope normal scans may change other findings. This is
historical observation, not worker causation, key usability or existing-volume assurance.

Three explicit accepted attempts and one active scan per execution are allowed. Replay requires
current EXECUTE, returns the same attempt including failure and never submits again. Accepted
submission failures count. After a terminal attempt, use a new explicit request/key only within
the bound. On uncertain response/commit, replay the original key. Startup recovery reuses the
same durable RUNNING scan ID/policy; read-only collection may repeat, never the remediation write.
No automatic post-terminal scan or quarantine release exists. Corrupt history/linkage fails
closed; when it cannot support a trusted failure receipt, RUNNING/active state remains for
separately reviewed maintenance. Never delete/rewrite history, force-clear or fabricate a receipt.

8C2's signed full-path, real managed reader, installed reader-only SDK chain, all four retained
policy generations, terminal commit faults and fresh-process recovery passed offline acceptance.
The receipt reader refreshes cached RUNNING scan state when a terminal receipt becomes visible;
it does not write, lock, commit/roll back caller work or relax proof/audit validation. This
acceptance does not enable a scope, create credentials, migrate an operator database or prove
deployed ECS/IAM/network isolation. Accepted 8D1 exposes READ history and bounded scan navigation
through PR #70 and complete exact-main CI 38794113567; see [dashboard operation](dashboard.md).
It introduces no browser mutations, worker launcher, schema/default/credential change or live
scope. Accepted 8D2 adds the separate manual workflow below; 8D3 integrated UI acceptance and
8E whole-sprint acceptance remain required.

Accepted 8D2 prepares and explicitly submits only the five existing bearer
operations, behind its own default-off dashboard flag. It does not enable backend scopes or
start the isolated worker. Session-bound coordination is non-authorizing and temporary; request
confirmation requires bound immutable READ references, including durable verification
submission failures. Timeout/logout/expiry and later denied retry do not cancel prior effects.
Session/process loss requires manual history reconciliation before any replacement. Typed
forms/recovery are implemented with no automatic mutation. All 90 signed browser journeys passed;
the new manual verification workflow confirms request history only, not a rescan verdict.
Complete review/delivery gates passed through PR #71 and exact-main CI 38833846226. Every CI
run covered 4,007 backend cases (714 PostgreSQL), 289 frontend cases, all 90 browser journeys
and all 18 quality/image/cleanup steps without skips/retries. See the
[dashboard contract](dashboard.md).
