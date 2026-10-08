# Sprint 8B remediation execution preflight

Current approval: on 2026-10-07 the user approved decisions 1--5 and the API/persistence/sequence
bundle and requested 8B1 only. Its implementation plan is in the [active Sprint 8 plan](exec-plans/active/sprint-8.md).
8B1 is accepted through PR #55 at `0c6005827ae765fe2b2669e4f503af6ca58cdc15`, with exact-commit
REVIEW_PASS, both final-head CI and exact main CI 37726113041; head is `20261007_0008`.
The original analysis baseline and pending-gate predictions below are preserved as historical text,
not current authorization status. ROADMAP and the active plan own current progress. No live
operation is authorized and no worker/rescan/UI begins in 8B1.

Analysis only, prepared 2026-10-07. The recommendations below need design approval before
implementation. Sprint 8 is IN PROGRESS; 8A is COMPLETE and 8B--8E remain PLANNED.

Recommend starting with **8B1: durable third-human execution requests and a separate execution
journal**, without an AWS worker or write credentials. Follow with the isolated single-action
worker and then its integrated fault/recovery acceptance. An ambiguous AWS outcome must never
cause an automatic repeat write or silently release the target to another request.

## Accepted baseline and scope

Accepted main is `24dbda32a0babcffff9698ece4a46c406690ef8e`, reviewed tree
`46e71bdb21cc5be0c9758b68b1866c417876f54c`. PR #54 closed 8A documentation and passed
[exact merged-main CI 37706030374](https://github.com/jnc247s/cloud-security-automation/actions/runs/37706030374).
Migration head remains `20261006_0007`; catalog `0.13.0` and the five-control default are unchanged.
Analysis uses branch `codex/sprint-8b-preflight` in the existing scoped checkout. Other branches,
worktrees and unrelated parent `.agents/` files remain preserved and excluded.

Retain the approved action `aws.ec2.enable-ebs-encryption-by-default`, version `1.0.0`, for
EC2-004, false to true only. No disable, default-key change, existing-volume conversion, arbitrary
AWS operation or shell execution. Enabling is regional and affects future EBS volumes/snapshot
copies, not existing volumes; workload and KMS compatibility require human review.
[AWS EBS guidance](https://docs.aws.amazon.com/ebs/latest/userguide/encryption-by-default.html).

Keep three distinct verified `(issuer, subject)` identities for PROPOSE, APPROVE and execution
admission. ADMIN has no separation override. The AWS worker is an independent service identity,
not a fourth human approval or an impersonated EXECUTE principal. Accepted proposal lifetime is
24 hours. Approval/revocation, finding disposition, technical assessment and execution history
stay separate. Any APPROVE principal retains the accepted terminal revocation operation, including
after expiry/staleness. Scanner credentials, collectors and assessment rules remain unchanged.

## Contracts and callers inspected

The authority sources are [AGENTS](../AGENTS.md), [roadmap](../ROADMAP.md),
[product requirements](../PRODUCT_REQUIREMENTS.md), [architecture](../ARCHITECTURE.md),
[security](../SECURITY.md), [threat model](../THREAT_MODEL.md),
[active Sprint 8 plan](exec-plans/active/sprint-8.md), the original
[Sprint 8 preflight](sprint-8-preflight.md), and the completed
[Sprint 7 design and acceptance record](exec-plans/completed/sprint-7.md).
Domain references are [API](api.md), [persistence](persistence.md),
[remediation operations](operations/remediation.md), [inventory operations](operations/aws-inventory.md),
[dashboard operations](operations/dashboard.md) and [known limitations](operations/known-limitations.md).

| Integration | Implemented evidence and consequence for 8B |
| --- | --- |
| Authority API/service | `app/api/routes/remediations.py`, `app/remediation/contracts.py`, `app/services/remediation_service.py`: closed inputs, bearer capabilities, full identities, digest/idempotency checks and service-owned mutation transactions. Add separate execution contracts; do not expand ProposalView or reinterpret decisions. |
| Authorization | `app/security/authentication.py`, `authorization.py`: verified issuer/subject and READ/PROPOSE/APPROVE/EXECUTE mapping. Current capabilities must be checked at admission/replay. No claim proves distinct physical humans or immediate later role revocation. |
| Provenance/governance | `app/remediation/provenance.py`, `app/database/governance.py`, `persistence.py`: completed explicit FAIL, false setting, complete KMS context, immutable source/policy bindings and finding-event IDs. Newer/equal target-control assessments and governance round trips block old authority. |
| Persistence | `app/models/remediation.py`, migration 0007 and `alembic/env.py`: immutable proposals/decisions and CREATE/DECIDE/REVOKE request ledger, populated fail-before-DDL downgrade guards. Execution needs additive tables and an additive reviewed migration. |
| AWS and startup | `app/aws/client.py`, `sessions.py`, EC2 collector and `app/main.py`: scanner credential chain, cached identity and scanner retries; API lifespan starts the scan executor only. Never reuse that provider or start a writer in API startup. |
| Scan execution | `app/services/scan_service.py`, `scan_executor.py`: public scan creation chooses today's deployment policy, while persisted execution reloads checksum-bound historical policy/services. 8C needs a separate exact-policy creation/linking seam. |
| Callers and tests | Router/service callers, signed HTTP helper, SQLite authority/migration tests, PostgreSQL concurrency/downgrade tests and scanner tests. `tests/remediation_http.py` explicitly expects absent execution routes; update only the newly approved route expectation with positive and fail-closed tests. |
| Browser | Accepted dashboard proxy is GET-only and cookies do not authorize bearer mutations. No remediation caller exists in the frontend; 8D requires its own mutation/security preflight. Scan-picker/back-navigation report remains untriaged, not fixed by this analysis. |

Resource then Finding then Proposal is the accepted PostgreSQL lock order; SQLite uses its
writer reservation. New execution coordination must follow those locks consistently and never
take a Scan lock afterward. READ methods reject pending caller changes before SQL and suppress
autoflush; mutation methods reject an already-active caller transaction. Preserve these contracts.

## Design decisions requiring approval

### 1 Isolated worker and constrained credentials

Recommend a separately launched worker process, disabled by default, for one configured account
and Region initially. New execution admission is also disabled by default. Production enablement,
role creation and deployment remain separately authorized, not implied by code acceptance.

Use an isolated temporary workload-role credential source. Reject static keys, shared profiles,
scanner fallback, caller-selected role/Region/endpoint and configured endpoint overrides. Validate
fresh AWS account and expected workload role before any precondition or write. Fail closed on
missing/mismatched identity or scope. Do not mount writer credentials into the API/scanner; code
factories and flags alone cannot prove deployment-level identity isolation.
STS returns account and role identity and does not require an IAM allow for GetCallerIdentity.
[AWS STS contract](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html).

The writer permission ceiling is `ec2:EnableEbsEncryptionByDefault` plus only
`ec2:GetEbsEncryptionByDefault` and `ec2:GetEbsDefaultKmsKeyId` for preconditions/readback.
The enable action has no resource-level permission and supports `ec2:Region`; its allow therefore
uses `Resource: "*"`, constrained by account-specific role and allowed Region, not a fictitious
volume ARN. Do not grant `ec2:*`, disable/reset/modify-key, KMS write/decrypt or IAM permissions.
[EC2 action table](https://docs.aws.amazon.com/service-authorization/latest/reference/list_ec2.html),
[resource-column rules](https://docs.aws.amazon.com/service-authorization/latest/reference/reference_policies_actions-resources-contextkeys.html).
Region-deny policy examples require careful global-service handling and are not ready-made role
policies to copy wholesale.
[AWS Region policy guidance](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_examples_aws_deny-requested-region.html).

### 2 Short durable execution authorization

Recommend a new immutable execution request from a currently authenticated EXECUTE human distinct
from both proposer and approver. Bind proposal digest, exact approval decision, action/version,
target, complete provenance/governance, reason, identity/capability and UUID idempotency key.
One execution request per proposal; reserve the account/Region/action target across proposals.
Initial admission capacity is 32 outstanding requests, enforced transactionally, not an
unbounded in-memory queue. Quarantined requests retain their capacity/reservation.

Authorize the dispatch cutoff until the earlier of proposal expiry or request time plus five
minutes. No stored JWT, credential material, automatic reapproval, extended lifetime or actor
impersonation. The worker rechecks stored authority, current approval/revocation, expiry, binding
and governance; it cannot continuously query the issuer for role changes. This bounded durable
authorization, with explicit revocation, is the proposed policy for later role loss. Physical-human
separation and trusted direct database INSERTs remain deployment/governance trust boundaries.

### 3 Fresh checks and an explicit dispatch cutoff

Outside database transactions, verify writer identity and read both regional EBS settings afresh.
Require the setting to be exactly boolean false and the complete KMS context to match approved
intent. Preserve the accepted present-key and expected-absence cases: only a successful response
with absent/null key is expected absence; an error, blank/malformed value or partial response is
not. Do not silently tighten 8A proposal eligibility to only a present ARN. AWS documents a key ARN
response; the existing collector accepts a nonblank string, so mismatch is conservatively blocking,
not normalization that rewrites approved intent.
[AWS default-key contract](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_GetEbsDefaultKmsKeyId.html).

Two EC2 reads do not prove KMS key usability, permission or workload compatibility. Recommend
retaining the approved human compatibility review, with no new DescribeKey/decrypt permission or
change to EC2-004. Already true before dispatch is a no-write/precondition-changed outcome, never
an attributed repair or a technical PASS.

Then take short ordered locks, revalidate immutable history, current eligibility, expiry,
revocation, target reservation and worker claim, and atomically commit WRITE_INTENT plus audit.
Only that claim owner may make one write invocation. No open SQL transaction/row lock spans AWS.
Concurrent pre-intent workers must lose their claim before dispatch; owner/claim checks are fenced
in the database, with no expired-lease reuse of a post-intent owner.

Recommend WRITE_INTENT commit as the revocation/expiry cutoff. Revocation committed first blocks
dispatch. Later revocation is still accepted and retained, but cannot promise to cancel an
in-flight/admitted write or undo it; expiry likewise cannot prove cancellation after the cutoff.
The original worker rechecks its deadline immediately before calling and abandons a late call,
but pauses after the final check remain an external race. Governance or AWS changes after the
cutoff cannot be serialized by SQL. AWS accepts only DryRun, not an expected-state CAS or client
idempotency token: the no-CAS conclusion follows from the documented input contract.
[AWS enable contract](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_EnableEbsEncryptionByDefault.html).

### 4 No repeat write after uncertain dispatch

Recommend at most one SDK write invocation per execution request, with
`retries={"mode": "standard", "total_max_attempts": 1}` and bounded connection/read timeouts.
Botocore's total_max_attempts includes the initial call; max_attempts instead counts retries.
The scanner's existing retry configuration is not a safe writer configuration.
[Botocore retry contract](https://docs.aws.amazon.com/botocore/latest/reference/config.html).
Offline local SDK inspection confirms the installed 1.43.87 model has only DryRun and supports
total_max_attempts and ignoring configured endpoint URLs; no AWS client or credential lookup was
needed. Future image/runtime acceptance must independently validate its installed SDK.

| Durable phase | Recovery and target reservation |
| --- | --- |
| Queued or claimed, no WRITE_INTENT | Bounded read-only retries/reclaim are permitted only with a new fenced claim and fresh authority/deadline checks; expired/revoked/changed intent terminates without a write and releases the reservation. |
| WRITE_INTENT, no conclusive committed outcome | Never resend the write, even if a crash may have preceded the call. Read-only reconciliation may record observations; retain sticky quarantine and the target reservation. |
| Conclusive completed call and durable receipt | Record sanitized request ID, response classification and readback separately. Acknowledgment is not verification. Release normal dispatch ownership only when that caller is known finished; failed/malformed/uncertain outcomes remain conservative. |
| Unknown or potentially live old worker | Lease expiry, TTL or a true readback cannot prove quiescence. No automatic unlock or force-clear API. Release requires separately authorized incident recovery proving the old worker cannot resume and reconciling AWS effect. |

Use a finite pre-intent read retry budget, initially three attempts within the five-minute
authorization, and at most three readback polls within 30 seconds. Stop on expiry, scope mismatch,
revocation or changed evidence; do not retry those as transient errors. Post-intent recovery reads
are observation-only even after authority expiry. A timeout, process death or response parsing
failure may have changed AWS and must not be labeled failure-with-no-effect. Desired-state
readback alone does not establish causation. No automatic rollback or compensating disable.

This intentionally sacrifices automatic recovery of some safe-but-unprovable requests. Database
leases and application tokens do not fence a paused worker at AWS; a repeatable-write or automatic
quarantine-release policy would be a different architecture requiring separate approval.

### 5 Verification remains a separate read only stage

Recommend an execution outcome such as acknowledged/observed-desired but **unverified** until 8C
links a read-only scan for the exact approved account/Region/target, source profile/version/digest,
catalog/version/digest and requested services. Do not call public start_scan unchanged: it selects
today's policy. Reuse persisted scan execution after adding an explicit internal creation/link seam.

Verification requires a later COMPLETED scan with explicit EC2-004 PASS and complete relevant
evidence/provenance. FAILED/PARTIAL scan, omitted control/target, insufficient evidence, bare API
return or readback never verifies remediation or manually resolves a finding. Normal scan
persistence owns finding reconciliation. A verification assessment itself makes the original
proposal stale and may resolve its finding; do not reinterpret that as erasing the historical
execution grant or automatically rejecting an otherwise valid verification result.

Approve only this verification boundary/dependency now. 8C still gets its own preflight and
implementation gate; no rescan implementation or new public scan parameters belong in 8B1.

## Proposed API and persistence additions

Use generic execution interfaces, not one route/service per control:

- `POST /api/v1/remediations/{proposal_id}/executions`, EXECUTE, UUID Idempotency-Key; body only
  proposal_sha256, approval_decision_id and a bounded nonblank reason. New acceptance returns 202;
  identical actor/key/body replay returns 200 with the same historical request. Replay requires
  current EXECUTE but never extends, requeues or redispatches authority. Reject extra fields with
  422; preserve 401/403 enforcement and sanitized 409 conflicts. Disabled new admission returns a
  sanitized 503 after authentication/authorization. No role, credential, endpoint or AWS parameter.
- Separate paginated READ `GET /api/v1/remediation-executions` and `/{execution_id}`; closed
  execution projections, bounded filters, sanitized phase/observation/error classifications and
  historical IDs. Retained human reasons are sensitive READ-protected metadata, never log output.
  No worker claim, secret, raw AWS error or sensitive credential-bearing output.

Add an immutable execution-request table and append-only execution-event journal, plus mutable
target/claim coordination. Bind request and event digests and approval references; atomically
append corresponding audit events. Enforce one execution per proposal, actor/key uniqueness,
event sequence uniqueness and target reservation across proposals with database constraints, not
only service checks. Index foreign keys, target/phase lookups and paginated history; validate
SQLite/PostgreSQL semantics. Use short, consistent transactions. Any capacity coordination lock
precedes Resource locks on every new path; existing 8A lock paths do not acquire it afterward.

Do not expand 8A RemediationRequest operation values, rewrite immutable authority, add execution
fields to ProposalView, or change finding/technical enums. Add a reviewed Alembic revision after
0007; update full-path populated/offline downgrade guards before any DDL, including new execution
history. Preserve 8A guards, legacy rows, audit constraints/triggers and caller transaction ownership.
No schema head is advanced by this preflight. Direct privileged INSERT/schema control remains
trusted; append-only storage is not a substitute for database access isolation.

After design approval, corresponding owner updates belong in API, persistence, architecture,
security/threat model, operations and changelog as each implementation actually lands. Proposals
here do not silently amend accepted design or operational deployment policy.

## Bounded implementation sequence

| Slice | Scope and acceptance boundary |
| --- | --- |
| 8B1 recommended first | Immutable EXECUTE admission, journal/target coordination, generic execution READ API, additive migration, capability/separation/idempotency/rollback/staleness/concurrency/upgrade/downgrade tests. Admission disabled by default; tests enable offline only. No worker/factory, AWS client, writer credential or scan creation. |
| 8B2 | Separately launched disabled-by-default single-action worker, fixed account/Region/role scope, fresh checks, atomic WRITE_INTENT, one SDK write, bounded readback and conservative recovery, with fakes/Stubber and no live credentials. |
| 8B3 | Whole-worker signed-HTTP to database to offline AWS acceptance, crash/race/recovery fault injection, credential-negative/image/Compose tests, independent review and delivery closeout. No rescan/UI implementation or later sprint. |

Finish and accept each bounded slice before the next: targeted tests, full regression, disposable
PostgreSQL, relevant security/container acceptance, documentation, exact-head independent review,
green final-head CI, ordinary guarded merge and green exact merged-main CI. Standing approval
covers routine workflow within accepted design, never live operations or unresolved design.
8C verification, 8D browser mutations and 8E whole-Sprint-8 acceptance remain subsequent work.

## Required validation and compatibility

- Signed three-identity separation, ADMIN no bypass, cross-issuer identity correctness, missing/
  expired/invalid bearer rejection, cookie-only denial, current EXECUTE required for replay,
  disabled admission, sensitive READ trust-domain behavior and sanitized errors/logs.
- Digest/provenance/policy/action/version/approval tampering; expiry equality; newer/equal FAIL,
  PASS and insufficient assessment; omitted control; exception and equal-time governance round
  trips; exact strict booleans and present/expected-absence/malformed/unavailable KMS context.
- Atomic audit/history/request/reservation rollback, same/changed-key replay, one request per
  proposal, cross-proposal same-target races, capacity limit, competing workers and lock order.
  Assert no SQL transaction or lock is held during AWS reads/writes.
- Revocation and governance commits on either side of WRITE_INTENT; crashes before/after intent,
  during/after call and before result commit; stale claims, paused zombie workers and sticky
  quarantine. No post-intent write replay, TTL release, attributed success or automatic rollback.
- SDK write invocation and actual transport-retry limits; bounded read retries/deadlines; account,
  role, Region, endpoint override and forbidden credential-source negatives. API/scanner startup
  never constructs a writer; existing collector/rule/no-AWS service boundaries stay intact.
- Migration metadata parity, populated upgrade/history/foreign-key/trigger fidelity, immutable
  update/delete/TRUNCATE guards, full-path downgrade blocked before DDL and concurrency on an
  explicitly disposable TEST_DATABASE_URL. Preserve old 8A request enum and all unaffected HTTP
  expectations while adding rigorous tests for the newly approved execution route.
- Exact-policy scan regression and explicit-PASS-only finding reconciliation; existing READ
  dashboard/session/Chromium/Firefox journeys remain unchanged. No general Run Scan UI is added.
- Every implementation slice runs `python -m ruff check .`, `python -m ruff format --check .`
  and complete `python -m pytest` after targeted tests. Runtime slices validate Compose/image and
  offline startup; frontend changes later require full type/lint/build/unit/browser checks.

Major limits are the AWS no-CAS race, post-cutoff cancellation limits, conservative stuck-target
recovery, KMS/workload usability not proved by EC2 reads, noncontinuous human-role freshness,
physical-human and privileged-database trust, and deployment-level credential isolation. None is
resolved by a green test alone. Keep existing local Firefox-launch limitation and the untriaged
scan navigation report visible; passing Linux CI is not proof those user observations are fixed.

## Analysis validation and Git state

Existing baseline checks ran with Python 3.14.5:

```text
python -m pytest tests/unit/contracts tests/unit/security tests/unit/database/test_remediation.py tests/unit/database/test_remediation_migrations.py tests/api/test_remediations.py
python -m ruff check .
python -m ruff format --check .
git diff --check
```

The first test run had 212 passed and one setup error in 47.69s: sandbox access to the shared
pytest temp directory was denied before the signed API test ran. A fresh isolated workspace
temp directory/local test issuer rerun passed all 213 tests in 48.97s with no skips or weakened
assertions; owned temp fixtures were removed. Ruff and whitespace checks passed; Ruff reported
390 files already formatted. These are baseline/analysis checks, not acceptance of future 8B code.
No fresh full regression, PostgreSQL, container or browser run is claimed; the unchanged accepted
baseline has exact-main CI above and each future implementation slice must repeat its own gates.

HEAD remains `24dbda32a0babcffff9698ece4a46c406690ef8e` on `codex/sprint-8b-preflight`.
Only four owned Markdown files change: this preflight, ROADMAP, active Sprint 8 plan and remediation
operations. Application/tests/migrations and accepted architecture/security contracts are unchanged.
No new reviewer, commit, push, PR, merge, live AWS/production operation or later sprint is started.

## Approval gate

Approve decisions 1--5 and the proposed API/persistence/sequence as a bundle, or identify a
specific change. Then implement **8B1 only** and apply its full acceptance gates before 8B2.
Approval does not authorize AWS execution, IAM/secret/deployment operations, automatic release
of uncertain targets, new browser mutations or Sprint 9+. This analysis does not complete Sprint 8.
