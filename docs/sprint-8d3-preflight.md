# Sprint 8D3 integrated dashboard acceptance preflight

## Entry and authority

Analysis checkpoint on 2026-10-16. Accepted 8D2 is `main` at
`f97cf7bb44a3695e514ef9aaf64dedb70a463cdc`, tree
`07822310fe13673ff7e3dc0f20c0851adcb06c55`, through
[PR #71](https://github.com/jnc247s/cloud-security-automation/pull/71) and complete
[exact-main CI 38833846226](https://github.com/jnc247s/cloud-security-automation/actions/runs/38833846226).
Corrected-head REVIEW_PASS, both complete first-attempt candidate audits and ordinary guarded
merge passed. Each CI run covered 4,007 backend cases/169 files, all 714 PostgreSQL cases/34
files, 289 frontend cases/13 files, 90 browser journeys (45 per project, one worker, zero
retries/skips), all 18 quality/image/cleanup steps and 19 existing SQLite warnings.

The user approved D1--D3 and sequential implementation on 2026-10-14. The
[8D preflight](sprint-8d-preflight.md), [approved predictions](exec-plans/active/sprint-8.md#approved-8d-predictions)
and standing routine workflow govern this test-only slice. No new product/security design
choice is identified. New authority, credentials, public interfaces or recovery semantics still
require approval. 8E and the full Sprint 8 goal remain required; Sprint 9+ is excluded.

Clean local main was normally fast-forwarded before creating `codex/sprint-8d3-preflight` in
the existing checkout. Thirteen task-owned owner/status-contract edits reconcile accepted
8D2, preserving historical predictions, failures and links. All 79 predecessor branches,
three worktrees and unrelated parent skills remain; only the scoped branch was added.
Migration head remains `20261013_0010`. No operator database is migrated.

## Story and integration contracts

A signed proposer selects an exact retained EC2-004 FAIL. A distinct approver decides and a
third verified issuer/subject pair requests admission. A separately launched installed offline
worker uses that committed authority exactly once. A current EXECUTE principal manually requests
linked verification; the genuine managed reader collects the retained policy, assesses and
persists a sealed receipt. The browser renders approval, execution, verification, old technical
results and current finding handling separately. Normal sufficient later scan evidence may
resolve a finding; admission, acknowledgment and browser confirmation never rewrite history.

| Boundary | Existing evidence | Remaining 8D3 proof |
| --- | --- | --- |
| Manual UI and clients | [Actions](../frontend/src/RemediationActions.tsx), [workflow](../frontend/src/RemediationWorkflow.tsx), [typed operations](../frontend/src/remediation-operations.ts) | Native full/adverse stories, not mocked-fetch tests alone |
| BFF and bearer API | [Fixed operation routes](../app/dashboard/operation_routes.py), [store](../app/dashboard/store.py), [API tests](../tests/api/test_dashboard_operations.py) | Preserve fresh capability/actor checks, explicit same-key submission, no generic proxy or SQL shortcut |
| Browser fixture | [8D2 native journey](../frontend/e2e/remediation-workflow.spec.ts), [isolated server](../tests/dashboard_operation_browser_server.py) | Its recording executor and separately seeded ACK prove request admission only; do not relabel them installed execution or VERIFIED |
| Installed worker | [Owned runtime](../tests/worker_process_runtime.py), [signed process guards](../tests/worker_process_http.py) | Run the installed child against the actual UI-created grant, with source/identity/intent/audit/write-count evidence |
| Managed verification | [Full-scope source and ManagedReader](../tests/verification_acceptance.py), [integrated cases](../tests/integration/test_remediation_verification_acceptance_postgres.py) | Reuse real submit/thread/collect/rule/persist/receipt boundaries after browser-created authority, not private `_run` or precreated receipts |
| Installed reader isolation | [Reader runtime](../tests/verification_process_runtime.py), [installed cases](../tests/integration/test_remediation_verification_process_postgres.py) | Preserve reader-only configuration, no writer construction, source identity and same-ID recovery evidence |
| Existing browser compatibility | [Playwright configuration](../frontend/playwright.config.ts), [validation runner](../scripts/validate.py) | Retain all 90 accepted journeys, both projects, keyboard/mobile/history/default-off behavior and existing pins/security/timeouts |

The inspected callers include App/session unmounting, history/actions, all five preparation
operations and fixed bearer routes, operation claim/settlement, executor lifecycle injection,
the signed HTTP/process helpers, ownership-guarded schema helpers and browser/container runners.
[Product requirements](../PRODUCT_REQUIREMENTS.md), [architecture](../ARCHITECTURE.md),
[security](../SECURITY.md), [threats](../THREAT_MODEL.md), [API](api.md),
[dashboard operations](operations/dashboard.md), [remediation operations](operations/remediation.md),
[persistence](persistence.md) and the [completed Sprint 7 plan](exec-plans/completed/sprint-7.md)
retain their accepted boundaries. Ordinary browser Start scan remains excluded.

## Bounded implementation and first work unit

Implement one complete 8D3 slice with the following internal work units. None independently
completes 8D3, 8D or Sprint 8.

1. **Owned coordinator and genuine native path.** Use a test-parent coordinator with the existing
   owned runtime/schema, a full retained-scope source and real managed scanner. Drive new
   proposal/decision/admission through native signed UI; do not reuse ProcessJourney's constructor
   to create authority behind the browser. Independently validate the committed grant before the
   separate installed worker. Request verification from normal ACK and render the sealed receipt
   in Chromium and Firefox. Begin with closed control-message/ownership guards, then prove this
   complete path before considering the work unit done.
2. **Adverse authority and recovery.** Exercise all four roles, full actor pairs and no ADMIN
   bypass; stale/newer/equal evidence, governance, expiry/revocation and fresh capability loss;
   explicit reviewed original-key retry, conflicts and commit/response loss; same-session reload,
   superseded/missing recovery, session/process loss and manual history reconciliation. Cover
   double-click/concurrent in-flight submission, no automatic POST, 16/session and 256/global
   rejection without eviction, cross-tab/logout/401 clearing and late responses.
3. **Verdicts, history and interaction.** Cover pending, normal ACK, quarantine/late ACK and the
   three-attempt/one-active bounds. Produce VERIFIED, NOT_VERIFIED and INCONCLUSIVE through real
   scanner outcomes, including technical PASS with incompatible KMS/provenance or incomplete
   evidence. Preserve v1/v2 histories, immutable original results and legitimate normal finding
   lifecycle. Exercise exact retained IDs, disabled/missing hints, no ordinary scan POST,
   keyboard-only review/confirmation, focus return, mobile layout, hostile text and native races.
4. **Whole-slice validation and delivery.** Freeze fresh complete collections and source hashes;
   run targeted, full backend/all PostgreSQL, frontend, both-browser, Compose/image/startup and
   security/ownership gates. Reuse the existing independent reviewer, repair findings, publish
   only after local gates, audit both exact-head CI primaries, ordinarily merge with an expected-
   head guard and audit exact-main CI. Then accept 8D and proceed to 8E, not Sprint 9.

## Test orchestration and credential boundaries

Keep Docker ownership in the test parent, outside browser/API/scanner processes. Do not mount
a Docker socket, start a nested daemon, expose a generic command broker or add a public worker
launcher. Native CI and the local Linux-browser adapter must retain the same complete story;
neither may skip the installed step because its host differs.

The parent owns the fresh labelled image/network/tmpfs PostgreSQL handle and its schema.
Existing worker URL validation accepts only schemas registered on that live handle. The 8D2
browser helper's differently owned schema must not be adopted or accepted by weakening that
guard. Use a separate integrated fixture, retaining accepted 8D2 fixtures and assertions.

A bounded private parent-control channel may name only fixed test operations and canonical
owned instance/request/execution UUIDs. No arbitrary argv, URL, environment or credentials are
accepted. Independently bind the execution to the fixture source and durable human audit before
launch; parser validation alone grants no authority. Claims/results must be fenced against
duplicate, mismatched and late messages. The local container adapter must preserve those same
ownership checks and restricted mounts; any inability to do so is a failed harness boundary,
not permission to expose Docker or weaken isolation.

Only the installed worker receives its existing synthetic ECS-only write configuration. The
API/managed reader must reject worker construction and must not receive that identity or role.
The closed synthetic transport can replace cloud I/O, not authentication, API authorization,
services, collectors, rules, persistence, source identity or immutable receipt validation. Real
managed `submit` must run; independent SQL connections prove committed intent/short transactions
before provider work. Use fixed test account/Region values from existing worker helpers, never
browser-selected scope or production credentials. Do not print connection strings or tokens.

## Risks and compatibility

- Build/setup timing, native CI versus Linux-container coordination and owned cleanup are
  integration risks. Preserve testcase/assertion timeouts, zero retries, source freezes and
  primary-error-preserving cleanup. Only exact owned children/resources may be removed.
- A confirmed request is not a worker run; ACK/readback is not attributed verification. A
  sealed observation is not causation, existing-volume encryption, KMS usability or lasting state.
- Scanner evidence can normally update current findings; it cannot rewrite immutable original
  assessments. Keep that change separate from the historical remediation verdict.
- Lost responses, cancellation of a fetch, logout, expiry or later denied retry do not prove
  no prior effect. No replacement key, renewed grant, automatic retry or quarantine release.
- Test-only seams and closed fault gates may use accepted factories/clock/transports. Do not add
  public production test hooks or weaken caller ownership, row-lock order, proof or audit checks.
- Existing `/api/v1` schemas/statuses/enums, constructors, ORM/migration 0010, control/profile
  defaults, scanner credentials and installed worker code remain unchanged. A reproduced runtime
  defect requires a bounded repair analysis; new semantics/design still require the user.

## Validation and entry

The [acceptance evidence matrix](sprint-8d3-acceptance-matrix.md) tracks each named requirement
below its actual unit, API, PostgreSQL or native boundary. It records remaining scope without
replacing these original predictions or the active plan's required gates.

Owner reconciliation passed 287 targeted cases, Ruff lint/467-file formatting and whitespace.
Its two failed new-documentation runs and corrected historical references remain in the active
plan. Those checks are not a new D3 full regression, browser or installed-worker acceptance.

Run targeted guards and the genuine integrated story first. Then run `python -m ruff check .`,
`python -m ruff format --check .` and complete `python -m pytest` with an explicitly disposable
TEST_DATABASE_URL and every PostgreSQL case enabled. Run pinned frontend type/lint/unit/build,
all retained plus new Chromium/Firefox journeys, Compose/image/source/startup/default-off checks
and exact owned cleanup. Count current cases and identities; do not reuse 4,007/714/289/90 as
new acceptance totals after adding tests. All review/CI/merge/main gates above remain mandatory.

Standing approval and the approved D1--D3 sequence authorize this bounded test-only implementation
after this analysis. No new product/security architecture decision is required. If a safe test
adapter needs broader Docker/network/credential authority or changed product semantics, stop
at that boundary and ask. No live AWS/IdP/IAM/secret/operator-database/deployment/production or
later-sprint operation is authorized. Current progress remains owned by ROADMAP and the active plan.
