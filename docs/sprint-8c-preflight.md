# Sprint 8C linked verification preflight

Approval update, 2026-10-13: the user approved the recommended R1--R3 package and requested
continuation. The [approved 8C predictions](exec-plans/active/sprint-8.md#approved-8c-predictions)
now govern implementation. The analysis checkpoint and its proposed wording below are retained
as original predictions, not the current approval state.

Analysis-only checkpoint on 2026-10-13. Sprint 8 is IN PROGRESS; 8A and 8B are COMPLETE as
offline-accepted code/tests; 8C--8E remain PLANNED. The three decisions below need approval
before implementation. Standing workflow approval does not make architectural/design choices.

## Verified entry baseline

Clean local and remote main match `771d630c9385c1155f981bd47e18d43e87fb2290`,
[PR #67](https://github.com/jnc247s/cloud-security-automation/pull/67), reviewed tree
`87080be23d635b926191965874b3a3d45fbd50e2`. Exact corrected-head REVIEW_PASS covers
`098111b701827f10b062a06a6a57042a59408a59`; the earlier LOW receipt-attribution finding is
independently closed and its failed verdict retained. Both first-attempt candidate CI audits
and complete [exact-main CI 38423060289](https://github.com/jnc247s/cloud-security-automation/actions/runs/38423060289)
passed. Each proves 3,567 backend cases/152 files, all 597 PostgreSQL cases/26 files without skips,
139 frontend cases/eight files, 76 unique browser journeys (38 per project, one worker/zero retries)
and all 18 quality/image/cleanup steps. Main backend took 2820.45s with 19 existing SQLite warnings.
The merge has exactly the expected predecessor and reviewed-feature parents; no bypass or deletion.

Installed-process test implementation remains `d3380402` (PR #66); runtime remains `7a36ddde`
(PR #59). Migration head is `20261008_0009`, opt-in catalog `0.13.0`, default catalog `0.2.1`,
default profile `1.0.0`. Local main advanced normally, then clean `codex/sprint-8c-preflight`
was created. All 76 local branches, three worktrees and three unrelated parent skills are preserved.
A frozen snapshot covers 506 tracked files, including 498 outside the eight allowed receipt/owner
documents. No 8C implementation or approved execution plan exists.

Authority: [AGENTS](../AGENTS.md), [ROADMAP](../ROADMAP.md),
[active Sprint 8 plan](exec-plans/active/sprint-8.md), [product](../PRODUCT_REQUIREMENTS.md),
[architecture](../ARCHITECTURE.md), [security](../SECURITY.md), [threats](../THREAT_MODEL.md),
[API](api.md), [persistence](persistence.md), [assessment foundation](assessment-foundation.md),
[remediation operations](operations/remediation.md), [inventory policy](operations/aws-inventory.md)
and the original [Sprint 8 preflight](sprint-8-preflight.md). The latter establishes exact-policy
rescan intent, not the undecided request, outcome or retry contracts below.

## Existing contracts and integration gaps

| Boundary | Implemented behavior | 8C implication |
| --- | --- | --- |
| [ScanService](../app/services/scan_service.py) | Creation selects deployment policy/current services, commits RUNNING/SCAN_STARTED, then submits | Add an internal exact-retained-intent path; preserve old callers and public scan inputs |
| [ScanExecutor](../app/services/scan_executor.py) | Verifies stored profile/artifacts, exact catalog/registry and one of four retained service tuples before provider construction; one process, two workers, 32 outstanding | Reuse its protocol/read-only identity; add expected-account/link/verification-contract checks before collection, not a new queue or writer |
| [Execution history](../app/services/remediation_execution_service.py) | Validates immutable proposal/approval/request, SHA-linked v1/v2 journal, paired audit and private claim consistency | Bind a normal acknowledgment; never reinterpret true readback or a late receipt as normal dispatch success |
| Authority | READ/PROPOSE/APPROVE/EXECUTE and three distinct verified human identity pairs remain separate | Define explicit verification-request authority; it grants no new AWS write |
| [Persistence](../app/database/persistence.py) | Complete later explicit PASS can resolve findings; later FAIL can reopen | Do not edit results/findings directly; full scans may legitimately affect other findings |
| [baseline_for](../app/remediation/provenance.py) | Validates completed EC2-004 FAIL and strict source/KMS bindings | Add a separate postcondition reader; do not weaken this FAIL-only proposal validator |

Callers inspected include the scan route, technical-posture projection, dashboard fixture,
scan-service tests, populated PostgreSQL persistence/restart tests and signed IAM/EC2/network/S3/
CloudTrail/governance acceptance helpers. Preserve request fields, service constructors,
ScanExecutor methods, historical service tuples and worker event/phase schemas.

A normal pending scan has no expected remediation account before STS. Checking only after
collection is too late: wrong-account facts could be collected and ordinary persistence could
affect unrelated findings. For linked scans, compare the scanner provider's authoritative account
and Region to immutable intent before facts are collected, and validate that binding again before
result persistence.

## Recommended design pending approval

### Initiation and authority

Use explicit current EXECUTE requests after a normal ACKNOWLEDGED execution, not automatic worker
scan dispatch. Any EXECUTE principal may request the read-only check; original three-human
separation still governs the AWS write. Retain full verified issuer/subject/roles/capability and
a bounded reason.

Verification defaults off, with explicit account/Region scope and no scanner-setting fallback.
Derive target/action/policy from validated history; callers cannot choose credentials, endpoints,
profile/catalog, scan ID or desired state. Approval expiry, later revocation or a now-stale
proposal does not grant another write, but should not prevent checking an acknowledged operation.

Initial attributed verification rejects QUEUED, CLAIMED, WRITE_INTENT, NO_WRITE, EXPIRED, BLOCKED
and QUARANTINED histories. A late receipt retaining quarantine is not a normal acknowledgment.
Ordinary scans remain diagnostic tools; verification never clears worker quarantine, ownership
or target reservations.

### Exact scope and outcome

Create a new scan with the baseline's complete persisted profile/artifacts, catalog/control
definitions and exact requested service/collector scope. No deployment-default/latest fallback
or retroactive attachment of caller-selected scans. Validate retained scope support before AWS.
Use unchanged read-only collectors, deterministic rules and normal evidence-based finding
reconciliation. EC2-only scope needs a different scope/finding-resolution contract.

A versioned terminal receipt belongs to the verification attempt, not ExecutionPhase,
FindingStatus or AssessmentResult. Seal exact scan/result, target snapshot/assessment,
policy/control and encryption/KMS source bindings.

Recommend:

- VERIFIED: complete collection, exact account/Region/target/policy/control, observation strictly
  later than the acknowledgment and original baseline, explicit EC2-004 PASS, and complete
  encryption/default-KMS evidence matching approved present/absent KMS context.
- NOT_VERIFIED: equally valid complete later evidence with explicit EC2-004 FAIL.
- INCONCLUSIVE: partial/failed collection, missing/ambiguous provenance/target, nondecisive result,
  unsupported retained contract, or changed/unavailable KMS context.

Other controls need not PASS, but collection must be complete. Technical PASS with changed KMS
context may resolve a finding under unchanged technical policy while the attempt is INCONCLUSIVE.
Neither result is rewritten. A historical receipt proves the setting under that policy at its
observation time, not worker causation, lasting state, existing-volume encryption or key/workload
usability.

### Persistence, replay and recovery

Recommend immutable requests/attempts, new-scan links and versioned terminal receipts with
restrictive indexed foreign keys, protected history and paired audit. A new additive Alembic
revision follows 0009; old migrations/events remain unchanged. Mutable coordination, if required,
is private and separate from audit/history and worker reservations.

UUID Idempotency-Key is scoped to verified actor and verification operation across executions.
Identical authorized replay returns the same attempt/scan/receipt, including failure. Changed
input conflicts. Replay checks current capability and never starts a new scan or renews write
authority.

Recommend at most three explicit attempts per execution, one active. A terminal inconclusive/
not-verified attempt stays immutable; another authorized request/key creates the next within
the bound. No automatic post-terminal rescan, approval or write resend. Rejected admission
does not consume an attempt; accepted attempts count even when submission fails.

Commit request, link, exact-policy pending scan and full request/start audit together before
submission. Atomically persist scan terminalization with receipt/audit, including sanitized
failure. A receipt cannot precede or contradict its retained bundle. Unknown commits require
reading/replaying the same identity, not a fresh key.

Reuse one-process startup recovery of the same durable RUNNING scan ID and exact policy/contract.
Re-executing interrupted read-only collection is not resending the AWS write. Missing/tampered
links, policy/artifacts/catalog/contract or expected identity fail closed. Define coordination
order before implementation; never acquire execution/authority locks after Scan/Resource/Finding
locks during terminalization. No transaction spans provider construction, STS, collection,
submission or shutdown. READ rejects pending caller writes before SQL and never finalizes history.

## Proposed implementation slices

1. 8C1 complete single-action vertical path, recommended first: approved contracts/new migration,
   immutable binding/audit, authorized/default-off idempotent request, exact-policy pending scan,
   read-only identity guard, atomic terminal receipt and READ list/detail. Include focused real
   signed-API/disposable-PostgreSQL success/denial/failure/recovery tests. Do not release admission
   without its required identity and terminalization safeguards.
2. 8C2 integrated fault/race/restart and compatibility acceptance: changed deployment policy,
   retained service generations, competing requests, commit/response crashes, submission failure,
   caller ownership, incomplete/forged evidence and mixed historical/current findings. Verify
   installed-image/API startup, whole-flow/full regression and all review/delivery gates before
   accepting 8C.

Proposed routes are generic: EXECUTE POST beneath an execution's verification collection and
separate READ verification list/detail. Exact paths/DTO/error names belong in an approved plan/API
owner, not an assumed implementation. Old scan/remediation/worker responses remain unchanged.
BFF/browser mutations, general scan-start UI and scan-picker/back-navigation repairs remain 8D.

## Required validation

- Signed authentication/capability 401/403/typed-input denial before effects; full attribution,
  changed-capability replay, explicit scope/default-off and no writer construction.
- Exact old policy/catalog/artifacts/control/scope after deployment roll-forward; malformed,
  unsupported/rehashed bindings reject before AWS and unrelated result/finding writes.
- Wrong STS account/Region, execution/scan/target/control substitution, old/equal observation,
  omitted/disabled control, strict boolean types, graph/source/checksum tampering and
  present/expected-absence/unavailable/changed KMS.
- Complete PASS/FAIL versus partial/failed/nondecisive scans; other-control failures; normal
  finding resolution/reopen separate from historical verification outcomes.
- Actor/key replay/conflict, concurrent admissions, three-attempt/one-active bounds, caller
  transaction preservation, paired audit rollback, receipt/bundle atomicity and recovery at
  every commit/submission boundary.
- Populated upgrade from 0009, ORM/schema comparison, immutable/cross-reference guards and
  whole-path pre-DDL incompatible/offline downgrade refusal on SQLite/disposable PostgreSQL.
- Targeted tests, Ruff lint/format, complete pytest with disposable TEST_DATABASE_URL, unchanged
  legacy scan/service/profile/worker regressions, Compose/image/startup/OpenAPI and relevant full
  browser gates. Exact independent review, both final-head CI, ordinary guarded merge and complete
  exact-main CI remain required. No skips, retries or assertion waivers.

## Approval decisions

| Decision | Recommendation | Alternatives needing a different plan |
| --- | --- | --- |
| R1 initiation/eligibility | Explicit current EXECUTE by any EXECUTE principal; normal ACKNOWLEDGED only; default-off scoped enablement | Automatic delegation, original-requester-only authority, or quarantine diagnostic verification |
| R2 scope/verdict | Full original scope/exact policy; complete later EC2-004 PASS plus unchanged complete KMS context; independent historical verdict | EC2-only scope or PASS-only verdict without KMS condition |
| R3 durability/retries | Immutable requests/links/versioned terminal receipts/audit; three explicit attempts, one active; replay and same-ID RUNNING recovery | One attempt, another explicit bound, or read-derived outcomes instead of sealed receipts |

Approve or amend R1--R3 before approved 8C predictions or implementation. Future schema, routes,
enablement and verdict semantics above are proposed, not accepted contracts.

Residual risks: observation races/eventual consistency, noncausal attribution, full-scope read
cost and effects on other findings, retained-policy support, single-process recovery, lock/
transaction ordering and privileged database access. Scanner credentials remain read-only;
writer/execution/quarantine semantics are unchanged.

No live AWS/IdP/IAM/secret operation, operator database mutation, deployment, production action,
new reviewer, commit/publication or Sprint 9+ work occurs in this preflight. No current runtime,
API, enum, schema, policy or test body changes.
