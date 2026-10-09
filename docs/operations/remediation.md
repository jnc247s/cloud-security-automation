# Remediation authority operations

This describes accepted Sprint 8A proposal/decision authority through PR #53 and 8B1 database
admission through PR #55, with exact-commit independent review, both final-head CI and green exact
main CI 37726113041. It is not a deployment or live-operation authorization. ROADMAP and the active
[Sprint 8 plan](../exec-plans/active/sprint-8.md) own status and approved scope. See the
[API contract](../api.md), [persistence](../persistence.md), SECURITY and THREAT_MODEL.

The 8B2 section below describes a local worker candidate, not accepted deployment behavior.
Accepted head remains 0008 until the active plan records its own complete gates.

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
8B1 enforces a third distinct execution requester. A dedicated worker service identity is a later
unimplemented boundary, not part of 8A or database admission.

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

Accepted repository migration head is `20261007_0008`; no deployed database migration is claimed
or authorized by code acceptance. Apply through Alembic only and validate against an explicitly
disposable TEST_DATABASE_URL. New authority/audit history is sensitive. Restrict DB access and protect
backups; append-only guards do not protect against privileged schema modification/direct INSERTs.
New audit actor IDs are canonical issuer/subject identity digests; full identity/roles/capability
are retained in metadata. Legacy audit limitations remain unchanged.

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
Only 8B1 admission/journal implementation was started; the rest is not implemented behavior or
live-operation permission. Later slices need their own required
review/delivery/acceptance. The active plan records
standing approval for routine Sprint 8 workflow; architectural/design decisions and live operations are
not pre-approved. Execution, rescan, UI and whole-Sprint-8 acceptance remain later bounded slices;
no later sprint is started here.

<a name="approved-local-8b1-admission--pending-acceptance"></a>

## Accepted 8B1 admission

Accepted 8B1 adds a third-human execution request/history, not an AWS worker. Use only an
explicitly isolated, authorized local/test database migrated to accepted `20261007_0008`.
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
history; failed admission rolls cleanup back. There is no periodic reaper, worker recovery or
WRITE_INTENT phase. Later unknown-effect reservations must stay quarantined, never released by
this grant's elapsed time. A new proposal/approval is required for a new request after termination.

Revision 0008 preserves old ledgers and adds protected request/journal/coordination records. Any
execution, event, reservation coordinate or new execution audit blocks downgrade across 0008
before DDL; offline crossing is blocked. Empty seed alone permits empty round-trip. Quiesce writers,
verify a backup and obtain separate operational authorization; never delete history/disable guards.
The subsequent test-only repair/documentary reconciliation completed through PR #57/#58 with
exact merged-main CI; ROADMAP retains the original failures and final receipts. No live AWS or
production work is authorized.

## 8B2 isolated worker candidate — not authorized for live operation

The disabled-by-default one-job entry point is `python -m app.remediation.worker UUID`. It is
never started by API, scanner or Compose startup. A default-off invocation exits with
`WORKER_DISABLED` before database/credential lookup. Tests use fakes/Stubber only. Do not enable
the process or run a live job under implementation, test, CI or merge approval.

After separate operational approval, the isolated process requires environment-only
`REMEDIATION_WORKER_ENABLED`, `REMEDIATION_WORKER_ACCOUNT_ID`, `REMEDIATION_WORKER_REGION`,
`REMEDIATION_WORKER_ROLE_ARN`, `REMEDIATION_WORKER_DATABASE_URL`; enabled mode requires all four
scope/database values and PostgreSQL migrated to candidate 0009. `.env` and scanner/application
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
8B3 whole-worker acceptance, 8C exact-policy read-only verification, 8D UI and 8E remain later gates.
