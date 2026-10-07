# Sprint 8 — Human-Approved Remediation

## Authority and baseline

ROADMAP alone owns sprint status. Starting baseline: clean main
`20c04665f89ae8c8cf9348603fd54e0e100b6076`, accepted PR #52 and successful merged-main
CI 37354537175, migration `20261001_0006`, Sprints 0--7 COMPLETE.
Read [preflight](../../sprint-8-preflight.md), [API](../../api.md),
[persistence](../../persistence.md), [AWS inventory](../../operations/aws-inventory.md),
[known limitations](../../operations/known-limitations.md), and the permanent root documents.

On 2026-10-06 the user selected the security/cancellation decisions below, received the 8A plan,
then requested `Continue` after leaving Plan mode. This authorizes local 8A implementation only.
Reviewer agents, commits, pushes, PRs, merge, live AWS/IAM/secret/production changes and Sprint 9+
remain unauthorized. Preserve unrelated parent skill files and existing branches/worktrees.
Subsequent review/repair and standing workflow authorizations are recorded below. The original
checkpoints retain their historical approval boundaries; the latest authorization governs routine
workflow, but never implicitly approves architecture/design decisions or live operations.

| Slice | Outcome | Status |
| --- | --- | --- |
| 8A | Durable proposals, approvals/rejections/revocation and authenticated API | IN PROGRESS |
| 8B | Isolated single-action worker, fresh preconditions, recovery | PLANNED |
| 8C | Linked exact-policy read-only verification scan | PLANNED |
| 8D | Authenticated dashboard workflow | PLANNED |
| 8E | Whole-sprint security/compatibility acceptance and closeout | PLANNED |

Only one slice advances at a time after required review/publication/merge and green exact
merged-main CI. Later slices need their own analysis preflight. Standing routine approval below
applies only within accepted design; unresolved architectural/design decisions need explicit
approval before implementation.

## Approved 8A predictions

- Register proposal-only action `aws.ec2.enable-ebs-encryption-by-default` version `1.0.0`,
  EC2-004 only, fixed desired true. No handler, AWS calls, credential acquisition or executor.
- Three distinct verified issuer/subject pairs are required across proposer, approver and later
  execution requester. APPROVE/REJECT actors differ from proposer; ADMIN cannot bypass.
  Any APPROVE principal may revoke an approval. No proposer withdrawal.
- Immutable proposal content binds occurrence/assessment/snapshot, exact profile/catalog/control
  versions and checksums, source evidence and default KMS context, action, reason and 24-hour
  expiry. Completed explicit FAIL, false EBS default, complete KMS/expected absence and
  OPEN/ACKNOWLEDGED finding without an active unexpired exception are required.
- Revalidate evidence and governance at approval. Any newer assessment for stable target/control,
  regardless of result, invalidates; ambiguous equal observation time fails closed.
  Bind relevant governance state. No stale proposal refresh or automatic approval.
- Add append-only proposal/decision/idempotency rows and restrictive/indexed relationships in
  migration `20261006_0007`. Preserve old migrations, audit/history guards and caller ownership.
  Populated downgrade preflight must fail before any DDL on the complete downgrade path.
- Mutations own a short transaction, lock Resource then Finding then proposal, and atomically
  append full verified issuer/subject/roles/capability audit context. Do not lock Scan afterward.
- Generic GET list/detail require READ; POST proposals require PROPOSE; decision/revocation
  endpoints require APPROVE. Strict typed input, UUID Idempotency-Key and nonblank reasons
  bounded to 2,000 characters. Initial APPROVE/REJECT is unique; optional REVOKE is terminal.
- Identical authorized retries return the original record without effects. Different normalized
  input with the same actor/operation/key conflicts. Separate approval status from derived
  expiry/stale/ineligibility reasons. Reads never mutate history.
- Preserve finding and assessment lifecycles, defaults, stable IDs, scanner permissions,
  authentication, roles and all existing API bodies. No UI changes in 8A.

## Validation and delivery gates

Targeted tests: capability/signed identity and self-approval denial; digest/provenance tampering;
cross-scope references; unsupported actions; missing KMS context; exact expiry; newer and equal-
time assessment staleness; governance/exception eligibility; terminal transitions; retries and
concurrent decisions; rollback and full audit context; immutable history and no technical
mutation; no AWS/executor/credential paths. Validate populated upgrades from 0006, schema
comparison and pre-DDL downgrade refusal on SQLite and disposable PostgreSQL.

Then run `python -m ruff check .`, `python -m ruff format --check .` and `python -m pytest`.
Run PostgreSQL integration with an explicitly disposable TEST_DATABASE_URL. Verify application
startup, health/readiness, OpenAPI and relevant container/image behavior. Record exact outcomes;
never weaken tests or accepted history to obtain green results.

Update API/persistence/architecture/security/threat/operations owner documents. Independent
review, publication, required merge approval and successful exact merged-main CI remain gates.
8A is not COMPLETE until accepted. Do not archive this plan or mark Sprint 8 COMPLETE early.

## Implementation checkpoints

2026-10-06: verified local and remote main match the expected baseline, clean checkout and no
existing scoped branch. Created `codex/sprint-8a-remediation-foundation`. Recorded the preflight,
plan and authorization; reconciled two stale documentation claims. No code, migration application,
tests, review, commit, remote publication or later slice has yet been completed at this checkpoint.
Original predictions above must remain intact; append material implemented differences here.

### Local 8A implementation checkpoint — 2026-10-06, not accepted

Implemented the closed proposal/decision contracts, read-only retained provenance validator,
generic transaction-owning service and bearer API. Revision `20261006_0007` adds immutable
proposals, decisions and request results, restrictive/indexed references, insertion guards,
four additive audit types and whole-path pre-DDL downgrade refusal. Existing migrations,
catalogs/profiles, findings/technical results, scanner and dashboard behavior are unchanged.
The PostgreSQL best-practices skill guided indexed foreign keys, constraints, short transactions
and consistent Resource → Finding → proposal locks; no network/AWS call occurs in them.

Implemented clarifications/differences from the original predictions:

- New remediation audit actor IDs are canonical issuer/subject SHA-256 digests, with untruncated
  verified issuer/subject/roles/capability metadata. Existing audit attribution is not rewritten.
- Expiry/staleness remains derived alongside historical approval status. REJECT/REVOKE can
  remove stale/expired authority, including revocation by a proposer who has APPROVE. No
  withdrawal, refresh, execution request or third-principal execution path is implemented.
- EC2-004 cannot legitimately evaluate N/A: a disabled control is omitted. Tests use real
  FAIL/PASS/INSUFFICIENT_EVIDENCE/equal-time histories, an omitted-control story and a strict
  no-result-filter query assertion rather than fabricate an invalid technical N/A fixture.
- Legacy migration tests remain pinned to their exact historical transitions and compare all
  pre-existing rows/checks/triggers. Current-head assertions move to 0007; ORM drift checking
  follows upgrade to head, and new empty tables are explicitly enumerated. Whole-path writer
  tests observe the new earliest guard, with a separate direct 0007 concurrent-writer test.

Updated README, architecture, security/threat, API/persistence and operations owners, including
the [remediation runbook](../../operations/remediation.md). Documentation distinguishes accepted
main/0006 from pending local 8A/0007. No standalone execution deployment or credential policy
has been added. IdP governance must establish appropriate human accounts; distinct verified
identity pairs alone cannot prove distinct physical people.

Validation progression (failed runs are not waived): the first local targeted set passed 184
checks; disposable PostgreSQL expanded that to 200, then stopped on one formatting discrepancy.
After additional edge checks, a new fault-injection test failed before reaching its intended retry
recovery branch (216 other checks passed). Moving the injected integrity failure to audit insertion
preserved its assertions and passed the isolated test. The subsequent 217 focused checks and
Ruff/format passed. Full regression then passed 2,813 and failed nine legacy migration assumptions
in 756.86s, with 19 existing SQLite datetime-adapter warnings. These were former-head, earliest-
lock, intermediate-head drift and additive-empty-table expectations, not waived data-integrity
assertions. The corrected local subset passed seven checks. A fresh complete run, including all
nine affected cases and direct 0007 writer exclusion, is still required at this checkpoint.

Validation uses the existing project virtual environment, not the incomplete system interpreter,
and `scripts/validate.py` provisions an isolated tmpfs PostgreSQL container with disposable
TEST_DATABASE_URL. Every completed harness run removed its owned database; user databases,
unrelated skill files and worktrees were preserved. No live AWS/IdP/production operations,
reviewer agents, commits, staging, publication, PRs, merge or 8B+ implementation occurred.

The corrected expanded focused set passed 233 checks in 92.33s, including all nine previously
failing cases, rehashed baseline substitution, current capability on retries, generated OpenAPI
and a directly committing 0007 authority writer. Ruff/format passed. That subsequent full run
was deliberately stopped, without a success claim, after inspection identified a caller-ownership
gap in the new service: a flushed caller write can look clean to ORM pending-change checks.
Only the uniquely identified owned pytest process was stopped; the harness removed its disposable
database. The correction requires an idle session and rejects explicit/read/flushed-write caller
transactions without committing or rolling them back. Dedicated SQLite/PostgreSQL tests retain
the caller transaction and prove its rollback remains effective. The complete corrected tree
must receive a fresh focused/full/quality/container run before review handoff.

### Final local validation receipt — 2026-10-06

The corrected 8A implementation is locally validated and ready for separately authorized
independent review, not accepted or COMPLETE. Original predictions and unsuccessful/stopped
run history above remain intact. The final harness exited 0 and removed its owned disposable
PostgreSQL container; user databases and existing containers/worktrees were not removed.

| Gate | Exact outcome |
| --- | --- |
| Expanded focused acceptance | 239 passed in 95.97s; no skips; 19 existing SQLite adapter warnings |
| `python -m ruff check .` | Passed |
| `python -m ruff format --check .` | Passed; 389 files already formatted |
| `python -m pytest` with harness-owned TEST_DATABASE_URL | 2,833 passed in 738.23s; no skips; 19 existing SQLite adapter warnings |
| PostgreSQL integration coverage | 318 cases in that full run; marker collection confirms 318/2,833 |
| `git diff --check` | Passed |
| `docker compose config --quiet` | Passed; no Compose services started |
| `docker build -t cloud-security-automation:validation .` | Passed |
| Built-image smoke | Passed: Python 3.12 import, remediation/decision/revocation and health/readiness OpenAPI registration; network disabled, test/development settings, in-memory SQLite, no mounts/credentials |

Runtime image identity is
`sha256:a26773f523858d2df22e7ba7f71e3df877bba7bcc0f5dc2809512da4d8da510a`.
The existing project interpreter used for local gates is
`C:\Users\jncoh\OneDrive\Documents\ChatGPT\ResProject1 2\.venv\Scripts\python.exe`
(Python 3.14.5). All commands run in the scoped checkout, not the parent. No dependencies,
container definitions, authentication/role configuration or frontend source were changed.

The exact focused selection passed to `scripts/validate.py --focused` was:

```text
tests/unit/database/test_remediation.py
tests/unit/database/test_remediation_migrations.py
tests/api/test_remediations.py
tests/integration/test_remediation_postgres.py
tests/unit/database/test_migrations.py
tests/unit/security
tests/unit/contracts
tests/integration/test_assessment_foundation_postgres.py::test_postgres_failed_transition_rolls_back_ddl
tests/integration/test_governance_category_migration_postgres.py::test_populated_round_trip
tests/integration/test_governance_category_migration_postgres.py::test_writer_is_excluded_before_category_preflight
tests/integration/test_persistence_postgres.py::test_postgres_evidence_graph_writer_completes_before_downgrade_preflight
tests/integration/test_unresolved_region_migration_postgres.py::test_failed_transition_is_atomic_and_retryable
tests/integration/test_unresolved_region_migration_postgres.py::test_writer_is_serialized_before_downgrade_preflight
tests/unit/database/test_assessment_foundation.py::test_failed_sqlite_transition_rolls_back_ddl
tests/unit/database/test_governance_category_migration.py::test_populated_round_trip
tests/unit/database/test_unresolved_region_migration.py::test_failed_transition_is_atomic_and_retryable
```

Coverage includes real signed production-mode bearer authentication on SQLite/PostgreSQL,
capability and ADMIN self-decision denial, scope/digest/rehashed-baseline protection, KMS
presence/absence/unavailability, expiry and stale/governance checks, retries and competing
actors/targets, terminal decisions and revocation, caller-ownership/audit rollback, immutability,
populated upgrades and pre-DDL downgrade/writer exclusion. Existing startup, health/readiness,
scan execution and all accepted control/report/dashboard backend checks pass. Frontend-unit/
browser suites were not rerun for this backend-only slice; frontend source is
unchanged and the existing image's frontend build succeeded from cache. No live IdP, AWS or
production environment was exercised; local tests are not deployment or physical-human proof.

Delivery state: branch `codex/sprint-8a-remediation-foundation`, HEAD unchanged at
`20c04665f89ae8c8cf9348603fd54e0e100b6076`; changes are uncommitted and unstaged. Parent untracked
`.agents/` files and all three original worktrees/branches remain preserved. No reviewer agent,
commit, push, PR, merge, writer credential, live operation, 8B--8E or Sprint 9+ implementation.
Review/publication/merge approval and green exact merged-main CI remain open gates. Stop here
until the user separately authorizes the next workflow action.

### Independent review and approved repair — 2026-10-07

The user separately authorized one read-only independent reviewer. The reviewed input was the
41-file unstaged/uncommitted 8A tree against HEAD `20c04665f89ae8c8cf9348603fd54e0e100b6076`;
SHA-256 comparisons verified no file changed during review. Verdict REVIEW_FAIL, with two MEDIUM
findings and no identified CRITICAL/HIGH findings:

1. Governance hashed reversible current finding status, not immutable finding history. Existing
   governed OPEN → ACKNOWLEDGED → OPEN transitions removed STALE_GOVERNANCE and let an old
   proposal be approved, or automatically unblocked already-approved authority.
2. List/detail reads could silently discard a pending Finding edit with autoflush disabled, or
   flush pending writes with autoflush enabled. Normal HTTP uses fresh autoflush-disabled sessions;
   this was a service caller-ownership defect, not a demonstrated HTTP authorization bypass.

Independent checks passed 57 SQLite authority/migration cases and one signed production-mode
HTTP case. The HTTP setup first met the known sandbox temporary-directory denial, then passed
unchanged with approved escalation. In-memory probes reproduced both issues. Root also passed
Ruff/format/diff checks; PostgreSQL/full/container gates were inspected through prior receipts
and tests, not rerun during review. No repo file was edited by the reviewer.

The user approved only these fixes, regression tests, review-receipt updates and required
validation. No second reviewer is authorized. The PostgreSQL skill guided use of the existing
target/time audit index and preservation of short Resource → Finding → proposal transactions.
Governance now includes sorted append-only finding audit-event IDs, scoped to the finding and
independent of timestamp. Thus equal-time status round trips cannot restore a previous digest;
unrelated findings and remediation audit events do not invalidate it. Existing exception-state
bindings remain. READ entry points reject pending inserts/updates/deletes before any SQL, without
flush, refresh, commit or rollback; complete read traversal suppresses autoflush. Clean explicit,
read and flushed-write caller transactions remain usable and caller-owned.

No schema, migration head, API fields, roles, scanner permissions, finding/technical lifecycles
or action version change. This tightens the unaccepted 8A governance digest: pre-repair local
proposals remain immutable but derive STALE_GOVERNANCE and need new intent, not data rewriting.
There is no accepted-main remediation data to migrate. Existing migrations remain unchanged.

Test-first receipt: all 20 new defect-focused SQLite cases failed on the reviewed implementation
in 12.46s; no failure was waived. After repair, 33 new SQLite cases passed in 19.32s, covering
proposed/approved authority, ACKNOWLEDGED/FALSE_POSITIVE round trips, equal/distinct event times,
unrelated finding scope, list/detail pending insert/update/delete protection under both autoflush
settings, and clean explicit/read/flushed transaction preservation. Equivalent PostgreSQL cases
and a lock-waited same-time disposition round trip are added. Expanded focused/full/quality/
container validation remains required at this checkpoint; no corrected-tree REVIEW_PASS claimed.
8A and Sprint 8 stay IN PROGRESS. No commit/staging, publication, merge, live operation or 8B+ work.

### Repaired-tree local validation receipt — 2026-10-07

The same focused selection listed in the 2026-10-06 receipt now includes the new regression
cases. `scripts/validate.py --focused` ran with the existing project interpreter and its own
disposable TEST_DATABASE_URL, exited 0, and removed only its uniquely owned PostgreSQL container.
The 41-file uncommitted input remained byte-identical throughout the harness, verified by SHA-256.
Final receipt-only documentation edits follow that run; application/test/migration files are
unchanged and owner-document checks are rerun afterward.

| Gate | Exact outcome |
| --- | --- |
| Expanded focused acceptance | 306 passed in 187.71s; no skips; 19 existing SQLite adapter warnings |
| `python -m ruff check .` | Passed |
| `python -m ruff format --check .` | Passed; 389 files already formatted |
| `python -m pytest` with harness-owned TEST_DATABASE_URL | 2,900 passed in 883.18s; no skips; 19 existing SQLite adapter warnings |
| PostgreSQL integration coverage | 352 cases in that full run; collection confirms 352/2,900 |
| `git diff --check` | Passed |
| `docker compose config --quiet` | Passed; no Compose services started |
| `docker build -t cloud-security-automation:validation .` | Passed |
| Equal-baseline-time in-memory probe | Passed for proposed and approved authority: new governed status round trips at the original maximum finding-event timestamp never remove STALE_GOVERNANCE; old undecided approval remains denied |

The added tests cover 33 SQLite and 34 PostgreSQL cases, including lock-waited same-time
disposition changes and clean/pending caller transaction ownership. Existing migration guards,
history, controls, startup, health, authentication, scan execution, reporting and dashboard backend
contracts pass. All original predictions and pre-repair failed/validation/review receipts remain.
No schema or established migration changed; head remains local `20261006_0007`, accepted 0006.

Frontend source is unchanged; separate frontend-unit/browser suites were not rerun. The image's
frontend build reused accepted cached inputs. The backend image resolves the existing allowed
dependency ranges; no dependency specification/lockfile changed. This is not a full regression
under the image's dependency/runtime combination, nor live IdP/AWS/production validation.
Final image smoke/identity and post-receipt owner-document checks remain pending at this checkpoint.

The two review findings are locally repaired and validated, not independently closed. The prior
REVIEW_FAIL is not replaced by these self-checks; a separately authorized corrected-tree review
is still required. Branch `codex/sprint-8a-remediation-foundation`, HEAD remains
`20c04665f89ae8c8cf9348603fd54e0e100b6076`; changes remain unstaged/uncommitted. No second reviewer,
commit, push, PR, merge, live operation, writer credentials, execution, 8B--8E or Sprint 9+ work.

Final documentation/image handoff: 63 owner-document link/status checks passed in 1.28s after
receipt edits. The image was rebuilt once more after the final README update and passed a
network-disabled Python 3.12 import/OpenAPI smoke check, explicitly confirming both repaired
source paths plus remediation/decision/revocation and health/readiness registration, with no
execution route. Settings were explicit test/development with in-memory SQLite, no mounts or
credentials; no API process, live cloud call or Compose service was launched. Final image ID is
`sha256:1f10995598dea23b0118dc86a115e1a5165fed63daeafa4cbbd3d65b2b2c4267`.
Only receipt documentation changed after the full run; SHA-256 comparisons verify application,
tests and migrations stayed identical. Final owner-document/quality/diff checks are repeated
after this handoff note. Parent untracked `.agents/` files and all original worktrees/branches
remain preserved. Stop for separately approved read-only follow-up review; no REVIEW_PASS,
acceptance, publication, later slice or live authority is inferred.

### Repaired-tree independent follow-up review — 2026-10-07

The user authorized one read-only follow-up on the corrected 41-file unstaged/uncommitted tree
against HEAD `20c04665f89ae8c8cf9348603fd54e0e100b6076`. The same independent reviewer returned
REVIEW_PASS: both prior MEDIUM findings CLOSED and no new CRITICAL/HIGH/MEDIUM/LOW findings.
Root SHA-256 comparisons before and after review confirm every input file remained unchanged.

Independent command, using the existing project interpreter:

```text
python -m pytest tests/unit/database/test_remediation.py tests/unit/database/test_remediation_migrations.py tests/api/test_remediations.py tests/integration/test_remediation_postgres.py -q
```

156 passed in 167.42s, no skips, including all 65 current remediation PostgreSQL cases and the
lock-waited equal-time governance round trip. The uniquely owned loopback/tmpfs database was
removed. Independent in-memory probes confirmed old proposed/approved authority cannot revive
even when MAX(timestamp) stays unchanged, new proposals approve, unrelated finding/remediation
events do not invalidate intent, and dirty detail/list reads reject before SQL while preserving
caller transactions under both autoflush settings. Clean transactions remain caller-owned.
Capability, provenance/KMS, idempotency, expiry, audit atomicity, lock order and downgrade paths
remain intact. The PostgreSQL skill guided index/short-transaction review.

Ruff/full regression/remaining PostgreSQL/container gates were not independently repeated;
their recorded results remain separate evidence. This closes the repaired-tree review, not
exact-commit delivery, acceptance or Sprint 8 completion. Original failed receipts remain intact.

### Local application smoke and reported UI limitations — 2026-10-07

At the user's request, the existing controlled-issuer browser fixture ran against a newly owned
loopback/tmpfs PostgreSQL database. Existing assets were rebuilt with pinned tooling; source,
dependencies and all 41 review-input files remained unchanged. Real HTTP health/readiness/docs/
OpenAPI and unauthenticated remediation denial passed. Chromium passed signed local login,
retained assessment/snapshot display, NIST technical counts/release selection, cookie-only API
denial, mutation-proxy denial and logout, with no page errors or external browser requests.
The fixture forbids AWS calls and contains synthetic data only.

The two-browser smoke did not pass: local Firefox launch failed with `spawn UNKNOWN` before
reaching the application; an isolated blank-page launch reproduced it. No Firefox coverage is
claimed or failure waived. The run stopped and removed only its owned database/processes; ports
9011/9012 were confirmed closed. This is distinct from the prior backend acceptance run.
The user subsequently reported missing selectable scans/back-to-picker navigation in their own
demo. That report remains untriaged, not independently reproduced or repaired here. Revisit it
at 8D preflight; no frontend change or general scan-start workflow is silently added to 8A.

### Standing Sprint 8 workflow authorization — 2026-10-07

The user requested: complete Sprint 8 and automatically approve its workflow unless an
architectural or design decision is required. This supersedes the earlier routine approval
gates, not safety boundaries or original historical predictions. Routine implementation within
accepted design, validation, documentation, independent review/repairs, scoped feature commits,
pushes/PRs and ordinary guarded merges are pre-approved when required gates pass. Reuse the
existing reviewer where suitable; this is not authorization for unnecessary parallel agents.

Preserve one bounded slice at a time, exact-commit review, targeted/full/integration/security/
container/browser gates where relevant, no unresolved acceptance defects, and green exact
merged-main CI. Do not force-push, bypass protections, delete branches/worktrees/user data or
silently add scope. Scanner credentials stay read-only. Live AWS/remediation, IAM/secret changes,
production operations, deployment and Sprint 9+ remain separately authorized, never inferred
from the goal. No live execution or production setup is needed to claim offline/scoped acceptance.

Immediate sequence: record the corrected-tree review and authorization, validate receipt changes,
commit 8A, obtain exact-commit independent review, publish a scoped PR, require green final-head
CI and ordinary guarded merge, then require exact merged-main CI and documentary closeout.
Only then advance to 8B analysis preflight. Present unresolved architecture/design choices and
stop before implementing them; automatic workflow approval cannot decide credential/process
isolation, stale-state/recovery semantics, verification policy or new browser mutation contracts.
8A/Sprint 8 remain IN PROGRESS and 8B--8E PLANNED at this checkpoint.

Delivery preparation: 91 documentation/contract checks passed in 0.39s after the receipt and
authorization updates; Ruff check, 389-file formatting and whitespace checks passed. SHA-256
comparison with the independently reviewed input confirms only nine owner/receipt Markdown files
changed; application code, tests and migrations remain identical to the reviewed/full-validated
tree. Repeat these lightweight gates after this receipt before the first scoped commit. Final
exact-head CI still must run the complete backend/PostgreSQL/frontend/browser/image pipeline;
the local Firefox launch failure is not a passing browser acceptance result.
