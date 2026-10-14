# Sprint 8C2 integrated verification acceptance preflight

Analysis-only checkpoint on 2026-10-14 UTC. 8C1 is COMPLETE as default-off offline code; 8C
and Sprint 8 remain IN PROGRESS. This preflight recommends one complete test-only acceptance
slice under the already approved R1--R3 design. No new architecture or product decision is
identified. Standing routine workflow applies after this analysis; any newly required change
to authority, scope, verdict, recovery, credentials or browser contracts needs a user decision.

## Entry baseline and authority

Accepted main is `76e0f7866dddb41d3ccd61913fbbeb36d594808e`, reviewed tree
`6d263beaa6b0d8533c002e8a11050110cb89d624`, through [PR #68](https://github.com/jnc247s/cloud-security-automation/pull/68).
Exact corrected-head REVIEW_PASS at `bbb0f6a`, both first-attempt candidate primary audits,
ordinary expected-head guarded merge and complete [exact-main CI 38483896952](https://github.com/jnc247s/cloud-security-automation/actions/runs/38483896952)
passed. Each primary proves 3,646 backend cases/156 files, 628 PostgreSQL cases/27 files without
skips, 139 frontend cases/eight files, all 76 configured browser journeys (38 per project,
one worker/zero retries), and all 18 quality/image/cleanup steps. These are baseline receipts,
not proof that every combined verification fault/restart story is already covered.

Migration head is `20261013_0010`; no operator database is automatically migrated. The clean
existing worktree was fast-forwarded normally to accepted main, then scoped branch
`codex/sprint-8c2-preflight` was created. Existing branches, all three worktrees and unrelated
parent skills are preserved. The uncommitted C1 acceptance-owner refresh and its strict status
contract remain task-owned and must not be discarded or represented as published.

Read authority: [AGENTS](../AGENTS.md), [ROADMAP](../ROADMAP.md),
[active Sprint 8 plan](exec-plans/active/sprint-8.md), [product](../PRODUCT_REQUIREMENTS.md),
[architecture](../ARCHITECTURE.md), [security](../SECURITY.md), [threat model](../THREAT_MODEL.md),
[approved 8C design](sprint-8c-preflight.md), [API](api.md), [persistence](persistence.md),
[assessment foundation](assessment-foundation.md), [remediation operations](operations/remediation.md),
[inventory policy](operations/aws-inventory.md) and [limitations](operations/known-limitations.md).
The limitation register's stale global rescan deferral was reconciled at analysis entry; ordinary
scan idempotency limits, unverified worker readback and physical deployment risks remain.

## User story and existing integration contracts

A signed proposer, distinct approver and distinct executor create human write authority;
the separately launched offline worker acknowledges the one approved action. A current EXECUTE
principal explicitly requests a new read-only scan of the complete retained policy and scope.
Normal collectors, rules and persistence produce a separate immutable verification receipt,
available through READ history. No browser mutation is part of this story; that remains 8D.

| Boundary | Existing evidence and integration point | New acceptance needed |
| --- | --- | --- |
| Signed authority and write | [ProcessJourney](../tests/worker_process_http.py) uses real proposal/decision/admission routes; [installed worker cases](../tests/integration/test_remediation_worker_process_postgres.py) use a closed synthetic SDK transport | Continue the same genuine signed three-human journey into verification, proving the scan never adds another write |
| Verification admission | [service](../app/services/remediation_verification_service.py) commits request/link/RUNNING scan and paired request/start audit before `submit`; actor/key replay precedes enablement/executor checks | Independent committed-state and lock probes at submission; concurrent API requests and response/commit-loss boundaries |
| Managed scan and recovery | [executor](../app/services/scan_executor.py) supports injected provider/session factories, bounded real `submit`, and same-ID startup recovery via [create_app](../app/main.py) | Actual threaded submission and fresh application/executor recovery, not a recording submitter followed by private `_run` |
| Policy and identity | Retained profile/artifacts/catalog/control and one of four exact service generations load before provider construction; linked scope flag/account/Region and provider identity are checked | Explicit deployment-policy roll-forward, all four linked historical scopes, mismatched/unsupported/rehashed intent and identity denial before facts |
| Result and receipt | [persistence](../app/database/persistence.py) validates bundle identity/scope again and seals receipt/audit in the same transaction; [proof reader](../app/remediation/verification_evidence.py) separates verdict from technical results | Complete, partial, failed and forged-proof cases with independent visible row/audit/finding assertions and terminal commit faults |
| READ and replay | Views revalidate retained request/receipt/audit; dirty caller work is rejected before SQL and GET cannot seal history | GET/list/replay across pending, terminal, failed and corrupt history; clean/pending caller ownership and no provider/submission effects |
| Installed application | Existing [runtime](../tests/worker_process_runtime.py) and [shim](../tests/worker_process_harness.py) prove installed worker source/SDK and packaged API startup | Verification-capable installed API/scanner path, source identity and recovery under a closed reader-only test environment |

The baseline [signed verification helper](../tests/verification_http.py) uses a recording executor,
manually calls the fixture's scan runner, and starts from [VerificationHarness](../tests/verification_fixtures.py)
service-generated acknowledgment rather than the separate worker process. Its real signatures,
collectors, rules and persistence are useful boundary evidence, not the complete combined story.

The older worker seed in [remediation_fixtures](../tests/remediation_fixtures.py) delegates to
[ec2_bundle](../tests/ec2_fixtures.py), whose requested services are only `("ec2",)`. That ad-hoc
scope is deliberately rejected by verification's retained-scope loader. Build a new full-scope
baseline with existing collector/rule contracts; do not weaken the loader or existing worker tests.
Old ProcessJourney final guards also require OPEN findings and no scan submissions. Keep those
accepted guards intact; use new verification-specific guards after the worker boundary, allowing
only the exact normal finding changes earned by the read-only scan.

Existing packaged API startup is a no-work probe, not a reader-credential isolation demonstration:
its test environment includes worker configuration/ECS metadata variables while asserting no
provider activity. A verification-capable API/scanner test must use a separate closed reader
environment and prohibit writer construction; do not extend the no-work probe into a scan while
retaining writer identity. No production credential mode or endpoint override is proposed.

## Bounded implementation and recommended first work unit

Recommend one complete 8C2 test-only slice, with four internal work units before delivery:

1. Signed full-path PostgreSQL journey. Create a complete-scope baseline, drive distinct signed
   PROPOSE/APPROVE/EXECUTE routes, launch the existing restricted installed worker using synthetic
   transport, request verification through the real route and managed executor, and poll READ
   for the sealed receipt. Prove committed intent/audit before external work, exact identities,
   one worker write total, reader-only scan calls, unchanged execution journal, and normal
   findings/evidence versus separate historical verdict. This is the recommended first work unit.
2. Outcome, authority and replay matrix. Cover complete PASS and FAIL with present/expected-absent
   unchanged KMS; changed/unavailable context; partial/failed/nondecisive evidence; wrong/equal/old
   observation; target/control/source substitution; other-control FAIL and mixed historical/current
   findings. Add signed denial and actor/operation/key cross-execution conflicts, current-capability
   loss, disabled/unavailable replay, one-active/three-attempt bounds and quarantine/late receipt.
3. Fault, race and restart matrix. Cover before/after admission commit, lost response/commit
   acknowledgment, submission/capacity rejection, before/after terminal result/receipt/audit commit,
   and fresh startup during RUNNING collection. Use independent sessions and bounded barriers;
   prove original IDs/audits, atomic visibility and no write resend. Trusted failures can seal
   INCONCLUSIVE; corrupt bindings must retain conservative RUNNING/active state for maintenance.
   Preserve READ caller inserts/updates/deletes and clean transactions, no autoflush or repair,
   guard-first ordering, and whole-path downgrade exclusion/refusal.
4. Retained-policy and installed-process closure. Exercise current, pre-5F, pre-5E and pre-5D
   full-scope generations with deployment profile/catalog/artifact changes. Unsupported or forged
   history fails before provider/result writes, never falls back to latest. Verify installed
   verification/API/executor/proof source paths and real bearer routes, default-off startup,
   separate reader environment, bounded same-ID restart, no writer construction/credential sharing,
   and closed synthetic transport. Retain the existing packaging/worker guard suites unchanged.

No partial work unit completes 8C2. Preserve the complete matrix and required delivery gates.
New test helpers can use accepted `executor_factory`, `provider_factory`, session factory and
clock boundaries. Cloud I/O, trusted local issuer transport and targeted fault points may be
replaced; do not mock away authentication, authorization, services, rules, persistence, immutable
receipt proof, or parent/child identity boundaries. Test-only shims stay outside production images,
with exact source hashes and existing non-root/read-only/capability/mount/network/ownership checks.

No runtime/API/role/enum/control/profile/schema/collector/worker changes are planned. If a test
reveals an accepted-contract defect, stop at that boundary, report concrete evidence and plan a
bounded repair. New semantics or a new public testability hook are not silently approved by this
test-only plan. Old migrations and every existing valid assertion remain intact.

## Risks and compatibility

- A real asynchronous response can already contain a terminal receipt; tests must not assume
  every new 202 is still RUNNING. Use explicit gates to observe the durable pending boundary.
- Distinguish request-owned SQL transactions from unrelated concurrent READ sessions. Probe the
  relevant guard/target locks from an independent connection instead of asserting every session
  in the process is idle. No transaction may span its provider construction, STS, collection,
  submission or shutdown.
- Receipt-audit fault duration matters: a persistent failure can prevent trusted failure sealing;
  a one-shot fault may terminalize FAILED/INCONCLUSIVE. Neither permits an automatic post-terminal
  attempt, writer resend, fabricated receipt or READ repair. Replay the original UUID on uncertainty.
- The executor remains one-process/two-worker/32-outstanding, without distributed lease, periodic
  recovery, cancellation or quota. Do not add speculative orchestration or fleet-scale claims.
- Original expiry/revocation/staleness does not renew a write or deny a normal acknowledged
  observation. Current verification scope/enablement is still checked before recovery collection;
  disabled/mismatched recovery must make no provider call under the accepted contract.
- Eventual consistency, noncausal attribution, key/workload usability, other-finding effects,
  privileged schema/INSERT access and distinct physical humans remain explicit limits. Synthetic
  process isolation does not establish deployed ECS/IAM/network separation or live compatibility.
- Old API/worker bodies, roles, audit versions, technical/finding enums, ordinary scans and all
  four retained scopes remain compatible. Strict clients still need the accepted additive audit
  vocabulary and 0010 verification schema; no operator migration is performed by these tests.

## Validation and completion evidence

Use only explicitly disposable local/test PostgreSQL and owned temporary data. Preserve operator
configuration, stopped/user containers, existing worktrees/branches and untracked parent skills.
Keep the local Docker endpoint validated and cleanup ownership-checked; cleanup errors must not
mask the primary failure. No actual AWS/IdP/IAM/secret/operator-database/production operation.

Run targeted signed full-path/fault/compatibility/installed tests first, then:

```text
python -m ruff check .
python -m ruff format --check .
python -m pytest
```

The full suite must execute all collected PostgreSQL cases without skips; collect and freeze the
new per-file/per-case scope rather than reuse C1's counts as a new acceptance result. Validate
Compose/image, installed source/startup/OpenAPI/security and unchanged pinned frontend/browser
regression as relevant. Required exact-commit independent review (reuse the existing authorized
reviewer), bounded repairs, both complete candidate CI primary audits, ordinary expected-head
guarded merge and complete exact-main primary audit remain mandatory. No retry/skip/header/pin/
assertion waiver is permitted to obtain green results. Update owners and record actual differences
without rewriting original predictions; 8C is COMPLETE only after the full 8C2 acceptance succeeds.

The prior local headed-browser pass still has only 57 retained case rows; native Firefox and four
Linux headless causes remain unproven despite later complete configured CI passes. The user's
scan-picker/back-navigation report stays untriaged for 8D. No browser mutation/general scan-start,
live enablement, deployment, Sprint 9+ work, new reviewer launch, commit, publication or merge
occurs in this analysis checkpoint. Existing C1 owner/contract reconciliation is preserved.

## Implementation coverage after approval

This section records the local candidate after standing workflow approval; the original
analysis predictions above are preserved. One bounded runtime repair became necessary:
`RemediationVerificationService._receipt` refreshes cached RUNNING scan state when a committed
receipt becomes visible. The deterministic COMPLETED/FAILED interleaving tests reproduce the
accepted-contract defect and guard the repair. No write, row lock, caller commit/rollback,
new API field, role, migration, credential mode or verdict semantics is introduced.

The complete candidate matrix uses the following evidence. Counts describe collected cases,
not acceptance; the combined targeted run, full regression and delivery gates remain required.

| Test module | Cases | Approved boundary |
| --- | ---: | --- |
| [Signed acceptance](../tests/integration/test_remediation_verification_acceptance_postgres.py) | 14 | Installed acknowledged write followed by real managed PASS/FAIL; absent/present or changed KMS; partial/nondecisive/failed identity evidence; current authority, replay, one active and three explicit attempts |
| [Signed authority](../tests/integration/test_remediation_verification_authority_postgres.py) | 5 | Actor/operation/key and cross-execution namespace; current role and token expiry; original grant expiry/revocation do not renew write authority or forbid observation; installed quarantine/true readback and genuine late-ACK callback remain ineligible |
| [SQL faults and proof](../tests/integration/test_remediation_verification_faults_postgres.py) | 17 | Submission rejection; root SQL commit before/after loss; equal/older collection; source/time/control/target/version substitution; rehashed corrupt intent with no READ/replay/startup repair; other-control FAIL and mixed historical/current findings |
| [Retained policy](../tests/integration/test_remediation_verification_policy_postgres.py) | 16 | Four exact retained scope generations, original profile/catalog/artifacts after real deployment-policy change, same-ID startup recovery and current-scope/unsupported-catalog denial before provider |
| [Installed reader](../tests/integration/test_remediation_verification_process_postgres.py) | 6 | Real Uvicorn/bearer routes and installed SDK read-only credential chain; default-off and wrong account; fresh process recovery before provider and during fact collection |
| [Recovery and ownership](../tests/integration/test_remediation_verification_recovery_postgres.py) | 10 | Admission commit uncertainty; atomic receipt/audit rollback; real concurrent signed requests; independent guard-lock negative; coherent READ during terminal commit; caller insert/update/delete and clean transaction preservation |
| [Independent reader guards](../tests/unit/services/test_verification_process_guards.py) | 40 | Malformed installed proof/container cases, including six collection-interruption negatives |

The existing 31 verification unit and 31 PostgreSQL cases remain intact. They provide additional
request/default/capability, persistence/history guard, populated upgrade and downgrade exclusion,
whole-path guard-first ordering and caller ownership evidence. Existing signed API, ordinary
scan/executor capacity, packaging and worker suites remain regression requirements; new cases
do not replace them or weaken their assertions.

Test faults replace only controlled clock, synthetic cloud response or transaction/INSERT
boundaries. Services, bearer authentication, rules, proof classification and persistence run
normally. Incoming forged assessment INSERT values retain database history/FK guards: source,
time or schema substitution yields INCONCLUSIVE; target/version FK rejection rolls back the
result and seals trusted FAILED/INCONCLUSIVE. Rehashed request corruption is detected before
provider construction and prevents failure sealing, retaining conservative RUNNING history.
These are test-only privileged-input models, not a claim that arbitrary schema owners are
prevented from destroying data. The late-ACK authority case uses genuine owned-claim callbacks,
not an installed SDK write; installed quarantine has separate genuine process evidence.

Capacity rejection is injected at the accepted submit boundary; the unchanged ordinary executor
tests separately exercise actual bounded load. Root-transaction fault injection distinguishes
SQLAlchemy flush child transactions from the SQL commit, and independent sessions establish
atomic visibility. A committed complete scan also retains its normal FINDING_RESOLVED audit;
verification history never suppresses or rewrites that event.

The installed collection interruption occurs after real SDK STS and the first synthetic
read-only fact response, before the collector returns or result persistence starts. Owned child
exit 90 leaves the original RUNNING request, scan and paired audits; a fresh installed API/scanner
must resume those same IDs using a fresh reader-only credential chain. All source, mount,
network, non-root, privilege, closed-transport and independent committed-state probes still apply.
This remains offline acceptance, not physical deployment/IAM or live-provider evidence.
