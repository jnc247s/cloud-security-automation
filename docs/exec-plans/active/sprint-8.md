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
| 8A | Durable proposals, approvals/rejections/revocation and authenticated API | COMPLETE |
| 8B | Isolated single-action worker, fresh preconditions, recovery | COMPLETE |
| 8C | Linked exact-policy read-only verification scan | COMPLETE |
| 8C1 | Complete linked-verification vertical path | COMPLETE |
| 8C2 | Integrated fault/restart, policy and historical-scope acceptance | COMPLETE |
| 8D | Authenticated dashboard workflow | IN PROGRESS |
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

### Accepted 8A implementation — 2026-10-07

8A code is COMPLETE through [PR #53](https://github.com/jnc247s/cloud-security-automation/pull/53),
ordinarily merged at `691d8814c785feafc0d9d3b3b43d7d1af89542a0`. The initial baseline and all
original predictions, unsuccessful runs and historical authorization boundaries above remain intact.
This receipt supersedes their current-state pending claims, not their historical evidence.
Sprint 8 stays IN PROGRESS, this plan stays active and 8B--8E remain PLANNED.

The final 41-file commit `df5e8576a6621e6bcdb1d6efc4e460dc239f0c16` received independent
exact-commit REVIEW_PASS with no actionable findings. Both original MEDIUM findings remain closed;
all 28 source/test/migration fingerprints matched the independently reviewed repaired tree.
Independent exact-commit checks passed 91 contract tests plus Ruff/389-file format/diff checks.
The user specifically approved publishing this commit to the public repository and opening its PR
after the publication permission gate stopped the first attempt. Standing routine approval covered
the guarded ordinary merge. Neither operation bypassed protection, force-pushed or deleted a branch.
Remote commit/tree/file-list verification matched the reviewed input. The merge has exactly the
expected `20c04665f89ae8c8cf9348603fd54e0e100b6076` and feature parents and the same reviewed tree.

Fresh exact-commit local acceptance passed 306 focused checks in 171.43s and 2,900 regression
tests in 827.74s, including 352 PostgreSQL cases, no skips and 19 existing SQLite warnings.
Ruff, 389-file formatting, diff, Compose configuration and image build passed; the uniquely owned
disposable database was removed. Frontend typecheck/lint, 130 tests in seven files and build passed.
The initial sandbox frontend helper-process EPERM occurred before tests; the identical approved
local-permission rerun passed. The inspected image
`sha256:09fcef39e7fdec048915252caef1b6c3f6bb20e6b78aa1afd484fd10196e0665` passed network-disabled
Python 3.12.15 import/OpenAPI/repaired-source smoke, no mounts or credentials. A first smoke attempt
addressed the non-runnable build configuration digest and did not start a container; the inspected
image retry passed. All 41 file fingerprints and the clean commit stayed unchanged throughout.
Pre-publication contract/quality checks repeated successfully: 91 tests in 0.38s, Ruff/format/diff.

| Exact CI gate | Backend outcome | Remaining outcome |
| --- | --- | --- |
| [Push 37690504169](https://github.com/jnc247s/cloud-security-automation/actions/runs/37690504169), feature `df5e857` | 2,900 passed in 778.15s | 130 frontend units, 74 browser checks, quality/image/cleanup passed |
| [PR 37690509162](https://github.com/jnc247s/cloud-security-automation/actions/runs/37690509162), same feature head | 2,900 passed in 942.77s | 130 frontend units, 74 browser checks, quality/image/cleanup passed |
| [Main 37693245169](https://github.com/jnc247s/cloud-security-automation/actions/runs/37693245169), exact merge `691d881` | 2,900 passed in 928.72s | 130 frontend units, 74 browser checks, quality/image/cleanup passed |

Each run includes all 352 PostgreSQL cases, no skips and 19 existing SQLite adapter warnings;
browser logs prove 37 Chromium and 37 Firefox checks with zero retries. CI uses Linux/Python 3.12;
local regression uses Python 3.14.5. No full image-runtime regression, live IdP/AWS/production or
physical-human separation proof is claimed. Successful Linux browser CI does not waive the earlier
local Firefox launch failure or reproduce/repair the user's navigation report. Existing CI action-
runtime and upcoming Ubuntu-label warnings were non-blocking; no workflow/dependency change or
Sprint 9 hardening was introduced. Source, tests, migrations, scanners and dashboard are unchanged.

### 8A documentary closeout — in progress, 2026-10-07

After green exact merged-main CI, the clean local main was normally fast-forwarded without reset
and `codex/sprint-8a-closeout` created. This documentation/progress-contract slice reconciles
accepted 8A status, repository migration head 0007, current owner documents and these receipts.
It does not change
architecture, interfaces, security policy, control/catalog/profile versions or implemented behavior.
The original feature branch, all worktrees and unrelated parent `.agents/` files are preserved.

Targeted owner/contract checks, Ruff/format/full regression with a disposable PostgreSQL database,
independent exact-commit review, publication, final-head CI, guarded ordinary merge and exact new
main CI remain required for this documentary closeout. Do not infer that these new document edits
are already validated or merged. Only after that closeout may 8B analysis preflight start; unresolved
architecture/design choices still need approval before implementation. No 8B--8E, Sprint 9+, live
AWS/remediation, writer credentials, IAM/secret or production operation is started here.

The first owner/contract check passed 90 and failed one stage-specific assertion in 0.78s:
the progress contract still expected the former 8A IN PROGRESS row. No failure is waived.
The assertion now requires the accepted COMPLETE row and matching ROADMAP claim, with explicit
8B--8E and Sprint 9/10 PLANNED checks; all historical predictions and existing runtime/security
assertions remain. This is the sole test-source change, not a relaxation or new application behavior.
Required targeted/quality/full validation remains pending at this checkpoint.

Renamed current-owner headings retain their six former fragment IDs as explicit compatibility
anchors. File-link contract tests do not validate fragments; a separate old-ID/uniqueness check
is required. The completed Sprint 7 summary is dated to its original closeout, not changed into
a new current-state Sprint 8 claim. Historical predictions and receipt bodies remain intact.

### 8A closeout local validation and review correction — 2026-10-07

The bounded delta contains 13 Markdown owners/receipts and one strict stage-status contract.
The first corrected contract run passed all 91 in 0.40s, then Ruff caught a 102-character new
assertion line. Wrapping that assertion without changing it passed a fresh 91 in 0.38s,
Ruff, 389-file format and diff checks. No failure or assertion was waived.
The separate baseline-heading/anchor check confirms all six former fragments exactly once;
the file-link contracts do not provide fragment validation.

The unchanged provided harness ran `python -m scripts.validate --focused tests/unit/contracts`
with the project interpreter and its uniquely owned loopback/tmpfs PostgreSQL database:

| Gate | Exact outcome |
| --- | --- |
| Focused owner/contract checks | 91 passed in 0.36s |
| Ruff / format / diff | Passed; 389 files already formatted |
| Full regression | 2,900 passed in 781.70s; no skips; 19 existing SQLite adapter warnings |
| PostgreSQL integration coverage | All 352 cases included; separate collection confirms 352/2,900 |
| Compose configuration / image build | Passed; no Compose service started |
| Harness completion / database cleanup | Exit 0; removed only its owned disposable database |

All 14 input fingerprints remained identical throughout this validation. The 27 other accepted
source/test/migration fingerprints match the reviewed feature commit; application, migrations,
frontend, scripts, workflow, dependencies and product requirements are unchanged. The sole test
delta is the stage-status contract, whose corrected full-run input remains unchanged.
The inspected runnable image
`sha256:dc097c344c0fb765e9bce65806a0059c30a223226b05fe875cba688beab51d7e` passed Python 3.12.15
import/OpenAPI smoke with read-only filesystem, no network/mounts/credentials or server startup.
Local regression used Python 3.14.5; this is not full image-runtime regression or live-provider
validation. Frontend/browser suites were not rerun locally for this owner/contract-only delta;
the unchanged frontend image build used cached accepted inputs. Fresh exact-head CI must still
run the full frontend and both-browser gates; prior local Firefox/navigation limits are retained.

The existing authorized reviewer independently passed 91 contracts in 0.35s, Ruff/389-file format,
diff, six anchors and collection, with all 14 input fingerprints unchanged. Direct read-only PR/CI
checks verified the exact PR #53 receipts. Preliminary verdict REVIEW_FAIL contained one LOW:
the accepted 7C architecture subsection still called its historical 0006 head current. After the
full run, only that sentence is qualified as 7C's acceptance-time head/no migration, plus this
receipt added. No architecture/schema change is introduced; the original finding is not waived.
The same reviewer's correction verification and exact-commit review, publication/final-head CI,
ordinary guarded merge and exact main CI remain required before 8B preflight.

The same reviewer subsequently returned corrected-tree preliminary REVIEW_PASS: original LOW
CLOSED, no new actionable findings. Fresh independent 91 contracts passed in 0.34s, with Ruff,
389-file format and diff checks. All 14 inputs stayed unchanged during verification; only the
architecture qualifier and receipt differ from the preceding input, and the sole test-source
hash is unchanged. This closes working-input review, not the required exact-commit/delivery gates.

### 8A closeout first-head CI and test-only boundary repair — 2026-10-07

The 14-file closeout commit `1df1aef5ac394ce3217f22c093321a5d9139b39f` received independent
exact-commit REVIEW_PASS with the original LOW closed and no new actionable findings, then
was normally published in [PR #54](https://github.com/jnc247s/cloud-security-automation/pull/54).
The worktree remained clean; branches, worktrees and unrelated parent skill files were preserved.

| First-head CI | Exact outcome |
| --- | --- |
| [Push 37698569530](https://github.com/jnc247s/cloud-security-automation/actions/runs/37698569530) | FAILURE: 2,900 backend passed in 1,028.18s; 130 frontend passed; 73 browser passed and one Chromium expiry assertion failed; image build skipped; cleanup passed |
| [PR 37698577228](https://github.com/jnc247s/cloud-security-automation/actions/runs/37698577228) | SUCCESS: 2,900 backend passed in 988.80s; 130 frontend and all 74 browser checks passed; quality/image/cleanup passed |

Both runs include 352 PostgreSQL cases, no test skips, 19 existing SQLite warnings and zero
browser retries. The push failure is not waived by the PR success. No merge, CI rerun or 8B
preflight occurred. An initial local watcher TLS handshake timeout was a monitoring failure,
not a CI result; read-only metadata and a replacement watcher recovered the actual final outcome.

The failing assertion was the existing combined-panel expiry journey's missing Sign in button
after a real 401. Refresh itself clears retained panels, and the former waiter accepted any API
401, including obsolete reads. Neither observation proves completion of session recovery.
CI retained no screenshot/trace/video or uploaded artifact, so the failed run's bootstrap status
and final DOM are unavailable. The original failure's precise cause remains unestablished;
no deterministic application/authentication defect or authorization bypass was reproduced.

The existing reviewer independently confirmed that actual current concurrent/single 401s reach
Sign in, while an obsolete read is correctly ignored. Root ran two instrumented Chromium expiry
journeys with unchanged assertions against a uniquely owned loopback/tmpfs database: both passed
in 12.7s, observing current history 401, session 200 with authenticated=false and Sign in. Only
that database was removed; no operator database/server or AWS operation was used.

The bounded repair extends this closeout with two frontend test files only. The browser journey
now correlates 401 to requests initiated by the current refresh, permits a sibling read to trigger
recovery and abort history, explicitly requires session 200/authenticated=false, and retains
all panel/storage/Sign in assertions and existing timeouts/zero-retry policy. Sanitized diagnostic
events contain only boundary labels, response codes, authenticated boolean and sign-in button
counts, never cookies, headers, URLs, identities or evidence payloads. Three new deterministic
App cases hold the bootstrap unresolved and verify immediate clearing, then valid signed-out,
503 and malformed-response behavior. No application, session policy, API, schema, dependency,
workflow, security header or credential change is justified or made.

The first focused unit run passed eight tests, but typecheck caught four uses of Playwright's
`exact` option in Testing Library calls. Anchored role-name matches corrected the test API usage
without weakening assertions. Fresh eight focused tests, typecheck, lint and diff checks passed.
Complete regression/PostgreSQL/frontend/controlled-browser gates and fresh independent new-head
review/CI/guarded merge/main CI remain required. The earlier 1df1aef review does not cover this
repair. This is synchronization/observability improvement, not a proven application fix.
8A code remains COMPLETE; documentary closeout and Sprint 8 remain IN PROGRESS, 8B--8E PLANNED.

### 8A closeout repair local acceptance and review — 2026-10-07

Fresh local acceptance of the bounded test-only repair passed:

| Gate | Exact outcome |
| --- | --- |
| Provided harness `python -m scripts.validate --focused tests/unit/contracts` | 91 focused checks in 0.34s; 2,900 regression tests in 784.10s, including all 352 PostgreSQL cases; no skips; 19 existing SQLite warnings |
| Backend quality/container gates | Ruff, 389-file format, diff, Compose configuration and image build passed; harness exit 0 and only its owned disposable database removed |
| Frontend | Typecheck/lint/build passed; all 133 units in seven files passed in 3.44s |
| Full controlled Chromium project | All 37 journeys passed in 44.5s, no retries; owned issuer/server stopped and only its fresh database removed |
| Optional diagnostic guard correction | Typecheck/lint/diff and one fresh real expiry journey passed in 11.1s; its separately owned database removed |

The full Chromium expiry journey exercised two current parallel 401s and two session 200/false
responses before Sign in. This is successful controlled acceptance, not reproduction of the
original CI failure or proof of a runtime fix. Local Firefox was not rerun or claimed passed;
fresh complete Linux Chromium/Firefox CI on the new commit remains mandatory.

The independent preliminary repair review returned REVIEW_FAIL with one LOW: optional locator
counts in the diagnostic finally block could replace the primary assertion/page-crash error.
A guard catches only these diagnostic counts and emits a fixed unavailable marker, with no raw
exception; all actual body assertions/errors still propagate. Corrected-input REVIEW_PASS closes
that LOW with no new findings. Four independent source-based scenarios verify primary errors
survive both failed/successful counts and successful bodies retain their original result.
Independent typecheck/lint/diff passed with all five inputs frozen. Prior independent eight-unit,
91-contract/quality results were carried forward, not falsely claimed rerun.

Only this optional frontend diagnostic block changed after the fresh full harness started;
the other 15 aggregate inputs, application/backend tests/migrations and primary browser assertions
were unchanged. The corrected block has separate independent review and targeted real-browser/
type/lint validation. No test/runtime/security assertion was waived. This receipt is added after
the completed run; repeat the owner/contract and quality checks before committing it.

The freshly inspected runnable image
`sha256:076d145bf0074237e471fd9f7cbb652c4ed2fa798ed7f089cf8a5806f4296e86` passed network-disabled
Python 3.12.15 import/OpenAPI smoke with read-only filesystem, no mounts/credentials, database
connection or server startup. Local regression used Python 3.14.5, not full image-runtime tests.
The original three worktrees/branches and unrelated parent `.agents/` remain preserved, and
migration head stays `20261006_0007`. Exact new-commit review, both new-head CI gates, guarded
ordinary merge and exact main CI are still outstanding; no 8B preflight or live operation starts.

### 8A closeout acceptance and 8B analysis entry — 2026-10-07

The repaired head `8ab285322bfbcc636c2e64103ae761ba6dfe7797`, parent `1df1aef`, received
independent exact-commit REVIEW_PASS with no actionable findings. The diagnostic LOW is closed;
all 16 committed inputs match the frozen reviewed files. Original failed attempts and preliminary
reviews above remain intact. The final receipt was the sole change after corrected-input review;
fresh independent 91 contract tests in 0.41s, Ruff/389-file formatting, typecheck/lint and commit/
aggregate whitespace checks passed. Earlier unit/source probes were carried forward, not rerun.

Normal publication updated existing PR #54 without force-push or branch deletion. Final-head
and exact merged-main gates all passed:

| Exact CI gate | Backend outcome | Remaining outcome |
| --- | --- | --- |
| [Push 37703707008](https://github.com/jnc247s/cloud-security-automation/actions/runs/37703707008), repaired `8ab2853` | 2,900 passed in 702.39s | 133 frontend units in seven files, 74 browser journeys, quality/image/cleanup passed |
| [PR 37703709625](https://github.com/jnc247s/cloud-security-automation/actions/runs/37703709625), same head | 2,900 passed in 1,076.07s | 133 frontend units in seven files, 74 browser journeys, quality/image/cleanup passed |
| [Main 37706030374](https://github.com/jnc247s/cloud-security-automation/actions/runs/37706030374), exact merge `24dbda3` | 2,900 passed in 990.62s | 133 frontend units in seven files, 74 browser journeys, quality/image/cleanup passed |

Each run includes all 352 PostgreSQL cases, no skips, 19 existing SQLite warnings and 37 Chromium/
37 Firefox journeys with zero retries. Expiry diagnostics show a current 401, session 200 with
authenticated=false and Sign in. Firefox also proves a current sibling 401 may abort history and
still recover correctly; a history-only waiter would reject that valid flow. The original failure's
precise cause remains unestablished. No application/authentication defect is claimed fixed.
Passing Linux CI does not waive the local Firefox launcher limitation or resolve the user's
untriaged scan-picker/back-navigation report. Existing non-blocking CI action/runner warnings
remain; no dependency/workflow or Sprint 9 hardening change is introduced.

[PR #54](https://github.com/jnc247s/cloud-security-automation/pull/54) merged under standing
routine approval on 2026-10-08T00:07:07Z (local 2026-10-07), using an ordinary exact-head guarded
merge with no bypass or deletion. Merge `24dbda32a0babcffff9698ece4a46c406690ef8e` has exactly
parents `691d8814c785feafc0d9d3b3b43d7d1af89542a0` and the repaired head, retaining reviewed tree
`46e71bdb21cc5be0c9758b68b1866c417876f54c`. Remote refs and clean local fast-forward were verified;
the feature/closeout branches, all worktrees and unrelated parent `.agents/` files are preserved.

This closes the 8A documentary prerequisite and supersedes earlier pending delivery statements,
not historical predictions, failures or limits. 8A remains COMPLETE and Sprint 8 IN PROGRESS;
8B--8E remain PLANNED. Branch `codex/sprint-8b-preflight` starts analysis only from that accepted
clean main. No worker/API/schema implementation, AWS calls, writer credentials, rescan or browser
mutation begins. Credential/process isolation, dispatch/revocation cutoff, uncertain recovery and
verification policy remain design decisions to present for approval before implementation.

### 8B analysis preflight and design approval gate — 2026-10-07

The [8B preflight](../../sprint-8b-preflight.md) inspects accepted authority/callers, capabilities,
immutable persistence/audit and downgrade guards, finding/governance ordering, scanner credentials,
scan policy/execution, signed HTTP and SQLite/PostgreSQL concurrency tests, and READ-only browser
boundaries. Current primary AWS contracts and offline installed SDK model/config inspection inform
the recommendations; no AWS client, credential lookup, live operation or worker is introduced.

Pending design bundle: isolated disabled-by-default writer and admission for one account/Region;
third-human durable EXECUTE request expiring at min(proposal expiry, request time plus five minutes);
fresh strict EBS/KMS context and revalidation before durable WRITE_INTENT; explicit revocation/expiry
cutoff with residual external races; one SDK write and no automatic post-intent resend/TTL release;
sticky uncertain-target quarantine and separately authorized recovery; readback unverified until a
later exact-policy COMPLETED explicit-PASS scan through unchanged read-only scanner credentials.
The proposed generic execution API/journal/coordination and additive migration preserve 8A contracts.

Recommend 8B1: durable execution admission, immutable journal/target reservation, generic READ API
and migration/tests only, no worker/AWS client/write credentials or rescan. Then 8B2 isolated worker
and 8B3 fault/security/container acceptance, sequentially after each slice's exact acceptance gates.
All choices remain proposals. 8B--8E stay PLANNED and Sprint 8 IN PROGRESS. No implementation,
new reviewer, commit/publication/merge or live operation is authorized by this analysis receipt.
Standing routine workflow approval remains applicable only after the unresolved design is approved.

Analysis validation: the existing contract/security/SQLite authority/migration/signed-HTTP selection
first had 212 passed and one sandbox shared-temp setup error in 47.69s. A new isolated workspace
temp/local-issuer rerun passed all 213 in 48.97s, no skips/assertion changes; owned fixtures cleaned
up. Ruff check, format (390 files) and whitespace checks passed. No fresh full regression/PG/browser/
image acceptance is claimed for this Markdown-only analysis. Only four owned Markdown files change;
HEAD remains accepted main `24dbda3` on the preflight branch. The writing skill separates proposals
from accepted history; PostgreSQL guidance informs short ordered transactions and indexed durable
coordination, without adding a database service or holding locks across AWS. Stop for design approval.

### Approved 8B design and 8B1 execution authority plan — 2026-10-07

The user's "yes" answers the explicit pending question: approve preflight decisions 1--5 and its
API/persistence/sequence bundle, then begin 8B1 only. The design gate is resolved, not waived.
Standing routine implementation/review/publication/guarded-merge workflow remains approved within
that scope. No AWS worker, AWS execution, IAM/secret/deployment operation, browser mutation, rescan,
additional reviewer or later sprint is authorized. Reuse the previously authorized reviewer for
independent review when the completed 8B1 candidate is ready; no delegation is started here.

| Bounded implementation | State | Scope |
| --- | --- | --- |
| 8B1 | COMPLETE | Durable EXECUTE admission, immutable event journal, target/capacity coordination, READ APIs, additive migration, security/concurrency/history tests |
| 8B2 | COMPLETE | Isolated disabled single-action AWS worker and fresh checks/dispatch/recovery, after accepted 8B1 |
| 8B3 | COMPLETE | Integrated offline fault/security/container acceptance and 8B closeout, after accepted 8B2 |

8B1 starts on `codex/sprint-8b1-execution-authority` at accepted `24dbda3`, with remote main
reverified exact and the four owned analysis Markdown changes retained. The analysis branch,
original worktrees/branches and parent `.agents/` are preserved. No development occurs on main.

Predictions: add closed execution request/content/event/READ contracts; a disabled-by-default
admission gate with explicit account/Region scope; third verified EXECUTE human separate from both
proposer and approver; min(proposal expiry, admission plus five minutes); current-capability
actor/key/content replay returning the same historical request without renewing/requeueing it.
Persist one execution per proposal, immutable request/event digests with paired full-identity audit,
a singleton capacity guard and unique mutable target reservation. Serialize admission on that
guard before Resource/Finding/Proposal locks; maximum 32 outstanding requests. Expired queued
requests may terminate/release within the same owned transaction; READ never mutates them.
Conflicting/stale/revoked/invalid authority fails closed and no partial admission survives rollback.

Add migration `20261007_0008` after immutable 0007, with indexed restrictive references, immutable
history/insert guards and populated/offline fail-before-DDL guards on the entire downgrade path.
Do not expand 8A ledger operations, ProposalView, finding/technical enums, scanner credentials or
execution behavior. The journal admits only queued/no-write terminal states in this slice, not
WRITE_INTENT, actual AWS outcomes or verification claims. Subsequent worker states require their
own atomic implementation/validation within the approved design.

Validate signed HTTP separation, extra/caller-controlled input rejection, default-off and scope
gates, idempotency and dirty/active-session ownership, staleness/governance/provenance, expiration,
target/capacity races, atomic audit rollback, immutable history, populated upgrades/downgrades and
PostgreSQL lock revalidation. Then the complete repository regression, disposable PostgreSQL,
runtime/Compose/image, required independent exact-head review and normal delivery/main-CI gates.
Update owning API/persistence/architecture/security/threat/operations/changelog documents as the
implementation actually lands. 8B and Sprint 8 remain IN PROGRESS until their complete gates pass.

### Local 8B1 implementation/validation checkpoint — 2026-10-07, not accepted

Implemented admission-only contracts, scoped default-off settings, current EXECUTE/three-human
authorization, retained eligibility, five-minute capped authority, actor/key replay, immutable
request/linked journal and paired audit, protected singleton/target coordination, generic READ
APIs and candidate migration 0008. Old authority ledgers/ProposalView, technical/finding lifecycle,
scanner permissions, catalogs/profiles and dashboard remain unchanged. No AWS, credential, worker,
WRITE_INTENT, quarantine/recovery, verification scan or 8B2+ implementation occurs.

Implemented clarification: target coordinates cannot be deleted/truncated, the singleton is
protected against ordinary mutation, and a held reference cannot clear without terminal history.
Only validated QUEUED/no-dispatch history may be reaped EXPIRED or replaced BLOCKED, atomically
with successful new admission; failed admission rolls cleanup back and reads/replays never reap.
Whole-path downgrade blocks retained coordinates as well as authority/journal/audit. Future worker
phases must participate in guard-first locking and must not inherit time-based no-write release.
PostgreSQL skill guidance informed short ordered transactions, indexed restrictive references,
constraints and concurrency validation. The writing skill distinguishes accepted baseline 0007
and historical 8A receipts from candidate 0008 and pending review/delivery; original predictions
above remain intact. Updated all corresponding owner documents without granting live authority.

Validation progression: the first SQLite selection passed 30 and failed one new test's positional
call to an existing keyword-only governance helper (18.54s). Correcting the test call preserved
its equal-time round-trip assertions; 38 passed in 21.36s. The expanded configuration/admission/
migration set passed 71 in 44.13s; signed production-mode bearer HTTP on SQLite passed with the
existing authority API (2 in 3.25s), using controlled issuer/AWS-forbidden fixtures. A standalone
legacy migration/progress selection passed 19 in 4.92s, and contracts/config/security 140 in 0.88s.

Disposable PostgreSQL focused acceptance passed 291 in 349.85s, no skips and 19 existing SQLite
datetime-adapter warnings; Ruff and 402-file format passed. Full regression collected 3,018,
then reported an existing assessment-foundation rollback assertion still expecting former head
0007. Only the verified owned pytest leaf was stopped; the parent harness removed its disposable
database and exited 1. This stopped/failing run is not accepted. The head assertion is updated to
0008 without weakening rollback/schema/data checks; a fresh focused/full run remains required.
Other historical migration tests retain exact predecessor assertions; new head-only expectations,
earliest writer exclusion and the protected singleton seed are updated atomically.

Unchanged dashboard compatibility passed typecheck, lint, 133 units in seven files and production
build. No browser pass is claimed here; required exact-head Linux Chromium/Firefox CI remains a
delivery gate, and the previously recorded local Firefox limitation is not waived. No staging,
commit, new reviewer, publication, merge, user database/branch/worktree deletion or live operation
has occurred at this checkpoint. 8B1/8B and Sprint 8 remain IN PROGRESS.

The corrected legacy migration/contracts subset passed 114 in 9.57s with quality checks. A fresh
expanded disposable PostgreSQL selection then passed 330 and failed one old unresolved-region
concurrency observer in 387.45s, before the full regression started. Its observer still matched
the prior 0007-first lock statement and timed out before seeing the now-first 0008 guard. Updated
only that statement/comment; writer exclusion, blocked-before-DDL error, complete schema/data
preservation and existing timeout assertions remain. The harness exited 1 and removed its owned
database. No gate is waived; another fresh focused/full/container run is required.

### Final local 8B1 validation receipt — 2026-10-07, review/delivery pending

The observer edit briefly had an indentation/parse error, caught and corrected by Ruff before
any new test run. Fresh expanded acceptance then passed **331 in 374.36s**, zero skips and 19
existing SQLite adapter warnings; Ruff and all 402-file formatting checks passed. The complete
regression subsequently exited 0 for **3,018 tests**, including all **397 PostgreSQL cases**.
The full pytest terminal summary fell inside a truncated console chunk, so no full-run elapsed
time or warning total is claimed. All integration cases were observed passing; source inspection
confirmed the sole skip condition is an absent TEST_DATABASE_URL, which this disposable run set.
Current collection remains 3,018. Stale cache entries for no-longer-collected historical tests
were preserved, not treated as current failures or removed to obtain green validation.

The existing validation harness also passed whitespace, Compose configuration and API image
build, exited 0, and removed only its uniquely owned disposable PostgreSQL container and test
directory. A separate uniquely named, self-removing image container passed imports, OpenAPI bearer
contracts, actual default-off/null scope and production development-auth refusal with networking
disabled and an in-memory test URL. It did not run a server, worker, scan or AWS operation.
Dashboard typecheck/lint, 133 units/seven files and build remain passing; no local browser run/pass
is claimed. Fresh exact-head CI must still pass the complete Linux backend/PostgreSQL/client/both-
browser/image pipeline, then ordinary guarded merge and exact merged-main CI.

SHA-256 comparisons confirm all 40 candidate files stayed unchanged throughout the final focused/
full/quality/image run. This final Markdown-only receipt is appended afterward; recheck contracts/
quality/whitespace and preserve all other fingerprints before a scoped commit and independent
exact-commit review by the existing authorized reviewer. No staging, commit, publication, merge,
live operation or 8B2+ work has occurred at this receipt. Local validation is not acceptance;
8B1/8B and Sprint 8 remain IN PROGRESS.

Compatibility: existing bodies, roles, caller ownership, authority ledger operations, assessments,
finding state and scanner behavior are unchanged. Four additive tables require Alembic before the
new endpoints can be used. Internal exhaustive AuditEventType consumers must accept three additive
execution journal types. Future worker phases require atomic model/migration/API updates and
validation; this admission-only version fails closed on unsupported history rather than releasing
a possible-effect reservation. Database operators/direct INSERT and physical-human governance,
shared READ trust domain, no fleet-scale/rate-limit guarantee and no live provider validation remain.

### 8B1 independent review and delivery acceptance — 2026-10-07

The existing authorized read-only reviewer returned REVIEW_PASS with no findings for exact commit
`7c3633557cc3d15ccedf3635297f22c58172e000`, parent `24dbda32a0babcffff9698ece4a46c406690ef8e` and
tree `1a01c9198220cc7d7efc054efe6826c70685a8f5`. All 40 committed/working-file fingerprints stayed
unchanged; worktree/index remained clean. Independent checks passed 195 focused SQLite/config/
migration/signed-HTTP/security/contracts in 51.14s, 47 disposable PostgreSQL admission/predecessor-
writer checks in 143.26s, 18 caller-ownership probes and four database-guard negatives, plus
Ruff/402-file format/whitespace. The first native focused run failed temporary-folder permissions
and is not a passing receipt; its unchanged fresh selection subsequently passed. Full regression,
image, frontend and browsers were inspected root receipts, not independently rerun. The reviewer
removed only its disposable container and three owned directories, without repo edits.

[PR #55](https://github.com/jnc247s/cloud-security-automation/pull/55) published the exact reviewed
commit under standing routine approval. The integration lacked PR-creation permission; the
already connected authorized GitHub CLI created the same scoped PR instead. No protection was
bypassed. A first merge guard stopped before mutation because an overly broad frontend-receipt
match also found a timestamp; exact normalized Tests summaries confirmed 133 in each run.

| Exact CI input | Backend receipt | Other required gates |
| --- | --- | --- |
| [Push 37724540662](https://github.com/jnc247s/cloud-security-automation/actions/runs/37724540662), reviewed `7c36335` | 3,018 passed in 801.81s | 133 frontend/seven files, 74 browser journeys, quality/image/cleanup passed |
| [PR 37724587400](https://github.com/jnc247s/cloud-security-automation/actions/runs/37724587400), reviewed `7c36335` | 3,018 passed in 772.66s | 133 frontend/seven files, 74 browser journeys, quality/image/cleanup passed |
| [Main 37726113041](https://github.com/jnc247s/cloud-security-automation/actions/runs/37726113041), merge `0c60058` | 3,018 passed in 1171.85s | 133 frontend/seven files, 74 browser journeys, quality/image/cleanup passed |

Each run includes all 397 PostgreSQL cases, no skips, 19 existing SQLite warnings, 37 Chromium/
37 Firefox journeys and zero retries. Linux CI is not live IdP/AWS/production coverage and does not
waive the local Firefox or scan-picker/navigation limitations. Existing CI warnings remain.

The ordinary expected-head guarded merge completed at 2026-10-08T04:09:19Z, retaining exactly
parents `[24dbda3, 7c36335]` and the reviewed tree at
`0c6005827ae765fe2b2669e4f503af6ca58cdc15`. Exact-main CI finished 2026-10-08T04:33:38Z.
Remote refs preserve the feature branch; all existing worktrees/branches and parent `.agents/`
files remain. 8B1 admission is accepted, not AWS execution or whole-sprint completion.

The separate `codex/sprint-8b1-closeout` reconciliation updates current owner status and its
progress-contract assertion only. Original predictions, implementation differences and all
failed/limited receipts remain intact. This closeout's validation/exact-review/publication/CI/
ordinary merge/exact-main gates are pending at entry, before any later slice advances.
Sprint 8/8B remain IN PROGRESS; 8B2/8B3 and 8C--8E PLANNED; Sprint 9+ unstarted. No new worker,
credentials, AWS calls, rescan, dashboard mutation, schema/runtime or live-operation change.

### 8B1 documentary closeout local validation — 2026-10-08

The bounded candidate changes twelve owner documents and one progress-contract test, not app,
Alembic, frontend, scripts or dependency sources. The assertion now requires accepted B1 COMPLETE
in the active plan and ROADMAP, while retaining all protected/later-slice checks. Eight renamed
8B1 headings retain their former fragment IDs exactly once; explicit anchors have no duplicates.
Current T20 distinguishes absent per-actor quotas from the implemented global capacity limit.

| Local gate | Observed outcome |
| --- | --- |
| Focused contracts/configuration | 109 passed in 0.52s |
| Ruff check and format check | Passed; 402 files already formatted |
| Full regression with harness-owned TEST_DATABASE_URL | 3,018 passed in 1159.83s, including all 397 PostgreSQL cases; no skips, 19 existing SQLite warnings |
| Whitespace and Compose configuration | Passed; no Compose services started |
| API image build | Passed |
| Owner readback and fragment compatibility | Passed for the bounded changes and eight renamed fragments |

The validation script completed every source/quality/container gate and removed its owned
disposable database. The outer PowerShell wrapper nevertheless exited 1: its final temp guard
rejected every reparse-point attribute, including OneDrive Cloud E metadata. This wrapper failure
is retained, not reported as exit 0 or a failed test assertion. Read-only checks identified the
exact generated UUID folder and creation time, Cloud E tag 0x9000E01A without name surrogacy,
and no real descendant links. The Windows handle-resolved final path matched that exact workspace
folder. Separate narrowly scoped cleanup then exited 0 and removed only those generated fixtures.
[Microsoft's tag definition](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/c8e77b37-3909-4fe6-a4ea-2b9d423b1ee4)
identifies this tag as Cloud Files metadata, not a symlink/junction. No OneDrive configuration
was changed or filesystem tag stripped to force cleanup. No user data, existing database,
branch or worktree was modified or deleted.

All thirteen source fingerprints were identical throughout the targeted/full/quality/image run
and cleanup. Only this Markdown receipt, verification dates and the per-actor quota clarification
are edited afterward; no runtime, schema or test code changes after full regression. Recheck
contracts/configuration, quality/whitespace and unchanged remaining fingerprints before the
scoped commit and exact review by the existing authorized reviewer. Original predictions,
unsuccessful/limited receipts and existing warnings remain preserved. This is local validation,
not documentary acceptance; publication and exact-head/main CI remain gates. No local browser
pass or live provider coverage is claimed; frontend source is unchanged and Linux CI is required.

Git at this receipt: codex/sprint-8b1-closeout, HEAD remains accepted 0c60058; thirteen files are
unstaged/uncommitted. 8A/B1 are COMPLETE; Sprint 8/8B IN PROGRESS; 8B2/8B3/8C--8E PLANNED.
No new reviewer, AWS worker, write credentials, live operation or Sprint 9+ work was started.

### 8B1 documentary closeout review corrections — 2026-10-08

The existing read-only reviewer returned REVIEW_FAIL for frozen closeout commit
`c933a1924cc0204a10678cafe40aab6a0c84aa05`, tree
`2247c506d8db4444a5d2fb5fdb869ffd3690f6ef`, with two LOW owner inconsistencies and no
CRITICAL/HIGH/MEDIUM findings. The current architecture migration chain omitted accepted 0008;
the runbook still named 0007 and unqualifiedly described accepted 8B1 delivery gates as pending.
These findings are retained, not treated as approval. The bounded repair extends the current
chain through 0008, updates the runbook head and scopes its remaining gates to this documentary
closeout. Earlier revisions, predictions, receipts and compatibility anchors remain unchanged.

Independent checks before repair passed 109 contracts/configuration tests in 0.38s, Ruff,
402-file formatting and commit whitespace. All eight renamed fragments and six earlier anchors
were preserved without duplicate explicit anchors; all thirteen fingerprints remained unchanged
and committed blobs matched working files. Read-only metadata verified PR #55 and its three
successful exact-input CI runs. Full regression, PostgreSQL, image and browser totals were
inspected root receipts, not independent reruns. No reviewer edits, database use, publication
or live operations occurred.

Only these three Markdown files change after the first review. Recheck contracts/configuration,
quality/whitespace and the remaining ten fingerprints, commit the bounded correction without
rewriting the failed-review commit, and obtain a fresh exact-commit review from the same reviewer.
Both exact-head CI runs and guarded merge/exact-main CI remain mandatory before this closeout
is accepted or any later slice advances. No runtime, migration, test or security-design change.

### 8B1 documentary closeout failed main gate and approved test repair — 2026-10-08

The corrected frozen closeout `99f46c8e1750b161fdf65324da5f3fc0b35de273` received independent
REVIEW_PASS from the existing reviewer. Its focused contracts/configuration passed 109 tests
in 0.38s, Ruff/402-file formatting/whitespace and fragment compatibility passed. Final-head
[push CI 37731581293](https://github.com/jnc247s/cloud-security-automation/actions/runs/37731581293)
passed 3,018 backend tests in 1413.60s; final-head
[PR CI 37731646385](https://github.com/jnc247s/cloud-security-automation/actions/runs/37731646385)
passed the same 3,018 in 849.44s. Each included 397 PostgreSQL cases, no skips, 19 existing SQLite
warnings, 133 frontend tests/seven files and 74 browser journeys (37 Chromium/37 Firefox,
zero retries), with quality, image and cleanup gates passing.

[PR #56](https://github.com/jnc247s/cloud-security-automation/pull/56) merged ordinarily at
2026-10-08T05:47:15Z into `1478361d395c66e8bb5a6c7454f1c791ce8acdcd`, with exact parents
`[0c60058, 99f46c8]` and reviewed tree `eac65f647209ed0c18b2a39feb65ea714a7f0d15`.
Exact merged-main [CI 37734136435 attempt 1](https://github.com/jnc247s/cloud-security-automation/actions/runs/37734136435)
FAILED: 1 failed, 3,017 passed, 19 existing SQLite warnings in 1181.41s. The failed case was
`tests/integration/test_unresolved_region_migration_postgres.py::test_writer_is_serialized_before_downgrade_preflight`.
PostgreSQL reported `DeadlockDetected`: the downgrade waited for an exclusive graph-table lock
while the coordinator's third-connection snapshot waited for a shared scan-table lock.
Frontend/browser/image stages were dependency-skipped, not passing; owned database cleanup passed.
The [public failure receipt](https://github.com/jnc247s/cloud-security-automation/pull/56#issuecomment-6053631113)
retains this gate. No rerun or passing sister run replaces it. B1 feature acceptance remains valid;
documentary closeout acceptance and advancement remain pending.

The user explicitly approved the proposed test-only repair and routine validation/review/delivery
workflow on 2026-10-08. The clean latest-main checkout at `1478361` was fast-forwarded normally
before creating `codex/sprint-8b1-test-synchronization`. The scoped repair preserves `state(engine)`
and its complete snapshot, factors a caller-owned connection helper, and captures the pre-DDL
baseline on the already serialized downgrade connection. It retains the exact CommandError,
writer serialization and full revision/row/CHECK comparison, adds observed PostgreSQL blocker and
no-DDL assertions, exercises the race five times in fresh schemas, and tests caller transaction
ownership on both SQLite and PostgreSQL. Only the two test files and these two sprint owners may
change. App, Alembic, migrations, locks, credentials, runtime, API, findings and scanner behavior
remain unchanged; no skip, retry or error suppression is authorized.

Required gates are focused caller/SQLite/PostgreSQL checks, complete regression with an explicitly
harness-owned disposable TEST_DATABASE_URL, Ruff/format/whitespace, Compose/image checks,
independent exact-commit review by the existing reviewer, both exact-head CI runs, ordinary
expected-head guarded merge and fresh exact merged-main CI. Preserve all failed receipts and
existing worktrees, branches and unrelated parent `.agents/` files. No new reviewer or live
AWS/production operation is authorized. Sprint 8/8B remain IN PROGRESS, 8A/B1 COMPLETE,
8B2/8B3/8C--8E PLANNED and Sprint 9+ unstarted.

### 8B1 test synchronization repair local validation — 2026-10-08

The four-file candidate preserves every snapshot field and the `state(engine)` caller interface.
The racing coordinator no longer reads application tables during downgrade; its catalog-only
observation proves the writer blocks that downgrade. The serialized downgrade connection captures
the committed writer's full baseline before DDL, then the test requires the exact protected
CommandError, zero DDL and unchanged revision/rows/CHECKs after rollback. Five independent schema
cases passed. SQLite and PostgreSQL helper tests verify uncommitted caller data, no new connection,
no helper commit/rollback/close and continued ownership of the original active transaction.

| Local gate | Observed outcome |
| --- | --- |
| Initial SQLite/caller/progress selection | 27 passed in 9.51s |
| Focused migrations, PostgreSQL, contracts and configuration | 177 passed in 32.90s |
| Complete regression with harness-owned disposable TEST_DATABASE_URL | 3,024 passed in 1099.25s, including all 402 PostgreSQL cases; no skips, 19 existing SQLite warnings |
| Ruff check and format check | Passed; 402 files already formatted |
| Whitespace and Compose configuration | Passed; no Compose services started |
| API image build | Passed using existing cached source/build layers |
| Owned disposable database and temporary fixtures cleanup | Passed; harness and outer wrapper exited 0 |

Initial lint/format checks reported two overlong test lines; the formatter corrected only those
two test files before the passing runs. No assertion was weakened, skipped, retried or suppressed.
All four source fingerprints stayed identical throughout full validation. Only this Markdown
receipt changes afterward; recheck focused contracts and quality, and verify unchanged other
fingerprints before the scoped commit and existing reviewer's exact-commit review.

Local validation used Windows/Python 3.14.5 and PostgreSQL 16; fresh Linux/Python 3.12 exact-head
and merged-main CI remain mandatory. The unchanged frontend was not separately exercised in a
local browser run; CI must run its frontend and both browser gates. No local Firefox or live
IdP/AWS/production pass is claimed. The failed PR #56 exact-main receipt remains retained.
App, Alembic, frontend, scripts, CI and dependencies are unchanged. No production migration,
application behavior, findings, scanner credentials or security boundary changes occur.

Git at this receipt: `codex/sprint-8b1-test-synchronization`, HEAD `1478361`, four unstaged files.
Review/publication/exact-head CI/guarded merge/exact-main CI remain pending. Sprint 8/8B remain
IN PROGRESS, 8A/B1 COMPLETE, later slices PLANNED, and no Sprint 9+ work or live operation started.

### 8B1 browser gate failure and approved diagnosis — 2026-10-08

Frozen migration-test repair `c2ef20e03f19220016e255e63f4de07a73da4e23`, tree
`e286fcffd156646be43f729f006f2146aa8822af`, received independent REVIEW_PASS with zero findings.
The existing reviewer independently passed 158 tests in 32.56s, including 16 PostgreSQL cases
and all five fresh-schema races, no skips, Ruff/402-file formatting/whitespace, AST snapshot
equivalence and unchanged fingerprints. Owned database/temp cleanup passed. Root full/image
receipts were inspected evidence, not independently rerun. [PR #57](https://github.com/jnc247s/cloud-security-automation/pull/57)
published that exact candidate by an ordinary non-force push and remains OPEN/unmerged.

| Exact final-head run, attempt 1 | Backend and frontend | Browser and remaining gates |
| --- | --- | --- |
| [Push 37802803710](https://github.com/jnc247s/cloud-security-automation/actions/runs/37802803710) FAILED | 3,024 passed in 1036.11s; 133 frontend/seven files; quality passed | 1 failed, 73 passed: 36 Chromium/37 Firefox, zero retries; image dependency-skipped; owned database cleanup passed |
| [PR 37802814292](https://github.com/jnc247s/cloud-security-automation/actions/runs/37802814292) PASSED | 3,024 passed in 1221.79s; 133 frontend/seven files; quality passed | 74 passed: 37 Chromium/37 Firefox, zero retries; image and cleanup passed |

Both backend runs include all 402 PostgreSQL cases, no skips and 19 existing SQLite warnings.
The push failed `frontend/e2e/nist.spec.ts:170:1`, real session expiry: line 187 did not find the
exact Sign in button within 5,000ms after test-triggered expiry and an API 401 observation.
Passing companion CI does not erase that failure. The [public receipt](https://github.com/jnc247s/cloud-security-automation/pull/57#issuecomment-6064047504)
retains both results, the unresolved response-to-UI recovery boundary and the next approval gate.
No CI rerun or merge occurred; main remains `1478361` with the earlier PR #56 failure retained.

The user explicitly answered Yes to the proposed narrow browser-test diagnosis and a
synchronization-only fix if justified on 2026-10-08. This resolves that scope gate, not an
authentication-design gate. Continue on the clean existing repair branch at `c2ef20e`; preserve
the two reviewed Python tests unchanged. The only new test source permitted is
`frontend/e2e/nist.spec.ts`, alongside ROADMAP and this plan. Capture sanitized boundary events,
diagnose current-versus-superseded reads and session recovery with the existing controlled issuer
and a uniquely owned disposable test database. Keep all original real-expiry, Sign in,
NIST-context clearing and old-context 401 assertions. A justified fix may bind waits to the
current refresh and explicitly verify anonymous session recovery; it may not add retries/skips,
inflate timeouts or treat a cleared panel/old 401 as completed recovery.

App, session/authentication policy, API/BFF, migrations, dependencies, fixture servers, browser
configuration and credentials may not change. Any evidence requiring such a change must be
reported as a separate design/implementation gate. Never read or reuse operator secrets/data,
stop existing servers or use live AWS/production. Preserve failed/limited receipts and existing
worktrees/branches and parent `.agents/` files. No new agent; reuse the existing authorized reviewer
after a completed frozen candidate. Targeted diagnosis/security tests, full backend/PostgreSQL,
frontend typecheck/lint/unit/build, Chromium/Firefox acceptance, quality/Compose/image, exact
independent review, both new exact-head CI runs, ordinary guarded merge and exact-main CI remain
required. 8A/B1 COMPLETE, Sprint 8/8B IN PROGRESS, 8B2+ PLANNED and Sprint 9+ unstarted.

The diagnostic baseline kept the original waits/assertions and passed one native Chromium case
in 14.7s (journey 1.2s). Sanitized events showed two current 401s, two session requests and two
200 anonymous recoveries before Sign in appeared. This confirms concurrent rejection/recovery
activity and an incomplete original synchronization point, not the historical CI failure's exact
cause or a transient classification. The synchronization-only change binds rejected/recovery
responses to refresh-started requests and additionally requires recovery status 200 with
`authenticated=false` before the unchanged Sign in, empty NIST panel and old-context 401 checks.
It follows the accepted combined-expiry observation contract. No timeout, retry, launch preference,
cookie, authentication generation or application behavior changed.

The corrected focused Chromium case passed in 10.7s (journey 857ms); typecheck/lint/whitespace
passed. Both runs used separate uniquely owned loopback/tmpfs databases and native temporary
output directories; cleanup and wrappers exited 0. Diagnostics expose only boundary labels,
current-request booleans, status/authenticated booleans and button counts, never URLs, headers,
cookies, CSRF, identities or evidence. These are focused receipts, not full acceptance. Full
frontend/native browsers/backend/PostgreSQL/quality/image and exact review/delivery remain gates;
earlier local Firefox limitations and both historical failed CI runs remain retained.

### 8B1 browser follow-up local validation — 2026-10-08, not acceptance

The bounded synchronization-only test and both owner documents were held unchanged throughout
the full runs. All five source fingerprints were reverified after both commands terminated;
the two previously reviewed Python files remain byte-for-byte unchanged from `c2ef20e`.
No application, authentication, API/BFF, migration, fixture, browser preference, dependency,
script or CI changes were made. The historical CI failure was not reproduced or classified
as transient, and no runtime-fix claim is made.

Backend used the existing `python -m scripts.validate --focused` runner with security,
dashboard/investigation/Sprint 7 API, contract, admission-config, unresolved-region and
governance-migration selections, then its complete regression, quality and container gates:

- 258 focused checks passed in 90.50s; 3,024 full tests passed in 1049.65s, including all 402
  PostgreSQL cases and all five fresh-schema downgrade/writer races, no skips, 19 existing
  SQLite datetime-adapter warnings.
- `python -m ruff check .` passed; `python -m ruff format --check .` reported 402 files already
  formatted. Whitespace, `docker compose config --quiet` and the API/dashboard image build passed.
- Its uniquely owned loopback/tmpfs database and native temporary fixture directory were removed;
  wrapper exit 0. User databases, branches, worktrees, servers and parent `.agents/` were untouched.

The separate frontend run used the provided validation primitives, a separately owned test
database, the unchanged controlled issuer and native temporary browser output. Typecheck, lint,
build and all 133 unit tests/seven files passed. The unchanged zero-retry two-browser command
reported 37 passed and 37 failed in 1.1m: all 37 Chromium journeys passed, including the strengthened
real-expiry test; every Firefox case failed at `browserType.launch: spawn UNKNOWN` before reaching
the application. The pinned Firefox executable exists; this matches the previously retained
native launcher limitation, not proof of an application/authentication defect. No browser
configuration change or repeated unchanged launch attempt was made. The full browser command
and outer wrapper exited 1, not 0; both its owned database and temporary output were removed.

Native Firefox coverage is therefore absent, not skipped or passed. Complete fresh Linux
Chromium/Firefox acceptance on both new exact-head CI runs remains mandatory before any merge;
neither the passing local Chromium/backend results nor the older passing companion CI waive a
failed result. Diagnostics remain boundary labels, current-request and authenticated booleans,
status codes and button counts only. Scanner access, technical/finding/remediation lifecycles, production
authentication, migration head `20261007_0008` and the three-human execution boundary are unchanged.

This receipt is on `codex/sprint-8b1-test-synchronization` at `c2ef20e`, three unstaged follow-up
files (five aggregate PR files). Only these two Markdown owners may now gain receipts before
documentation-contract/quality rechecks and a scoped commit. Reuse the existing reviewer for
that exact new commit; publication must update the existing PR #57 without force or duplicate PRs.
Review, both fresh exact-head CI runs, ordinary expected-head guarded merge and exact-main CI are
pending. Sprint 8/8B remain IN PROGRESS, 8A/B1 COMPLETE, 8B2+ PLANNED and Sprint 9+ unstarted.
No live IdP/AWS/production operation, write credential, worker, rescan or dashboard mutation began.

### 8B1 accepted repair and documentary reconciliation — 2026-10-08

[PR #57](https://github.com/jnc247s/cloud-security-automation/pull/57) is MERGED, not pending.
Its final head `880380eedc26e851e19481b83f47d241a4667ec8`, tree
`ad1a43d905823356b2745611cb7b472501e0b379`, received exact-commit independent REVIEW_PASS,
zero actionable findings. Independent validation passed one targeted Chromium expiry journey
in 10.4s (661ms, zero retries), 127 contracts/config checks in 0.42s, frontend typecheck/lint,
ten request-correlation assertions and four diagnostic/error-preservation scenarios, Ruff,
402-file formatting and incremental/aggregate whitespace. The two Python files remained identical
to previously reviewed `c2ef20e`; snapshot AST, all five fingerprints, normalized blobs and clean
index/worktree were verified. Root full/image receipts were carried evidence, not independent
reruns. The first selector matched no tests and an initial probe hit sandbox child-process EPERM;
neither was passing coverage. Corrected exact selection/local inspection passed, and both newly
owned PostgreSQL containers/native TEMP directories were removed. No user service was reused.

The new test excludes superseded requests and additionally requires current recovery
`200/authenticated=false` before all original real-expiry, Sign in, NIST-panel clearing and
old-context 401 assertions. Diagnostics are sanitized, optional and cannot mask primary errors.
No assertion, configured timeout, retry, authentication policy or browser preference weakened.
The historical NIST CI failure was not reproduced or established as transient/runtime-fixed.

All three attempt-1 CI runs were verified by exact SHA/event/branch, every mandatory step and
complete log counts; no failed-run rerun or passing-companion waiver was used:

| Verified run | Exact head | Backend receipt | Remaining gates |
| --- | --- | --- | --- |
| [Push 37823481996](https://github.com/jnc247s/cloud-security-automation/actions/runs/37823481996) PASSED | `880380e` | 3,024 passed in 1281.46s | frontend, both browsers, quality, image, cleanup passed |
| [PR 37823491446](https://github.com/jnc247s/cloud-security-automation/actions/runs/37823491446) PASSED | `880380e` | 3,024 passed in 1239.13s | frontend, both browsers, quality, image, cleanup passed |
| [Main 37827101059](https://github.com/jnc247s/cloud-security-automation/actions/runs/37827101059) PASSED | `890b4d5` | 3,024 passed in 1258.12s | frontend, both browsers, quality, image, cleanup passed |

Each includes all 402 PostgreSQL cases, no skips, 19 existing SQLite warnings, 133 frontend
tests/seven files, 74 browser journeys (37 Chromium/37 Firefox, zero retries), Ruff/402-file
formatting, image and cleanup. Existing CI action/runtime and runner-migration notices remain;
no dependency/CI change or warning suppression occurred. Linux acceptance does not waive the
retained native Firefox launcher failure or repair the untriaged local scan-picker/navigation
report. The earlier failed exact-main 37734136435 and push 37802803710, with their real faults,
remain in the historical sections above and public receipts.

Ordinary expected-head guarded merge completed at 2026-10-08T18:48:15Z as
`890b4d58f725f164600a73cf0aee1c173f6f65f0`, with parents
`[1478361d395c66e8bb5a6c7454f1c791ce8acdcd, 880380eedc26e851e19481b83f47d241a4667ec8]`
and exactly reviewed tree `ad1a43d905823356b2745611cb7b472501e0b379`. No admin/bypass/force/delete
was used. After exact-main success the reused worktree normally fast-forwarded to that clean
main, preserving every branch/worktree and parent untracked `.agents/`; all five fingerprints
still matched. The [final public acceptance receipt](https://github.com/jnc247s/cloud-security-automation/pull/57#issuecomment-6067263151)
retains identities, counts, limitations and the next documentation gate. The immediate post-push
PR read had not confirmed the new head; a later exact remote read did so without a duplicate push.

This closes the test-only repair gate, not the whole sprint. Standing routine workflow approval
now reconciles only ROADMAP and this active plan on `codex/sprint-8b1-repair-closeout`, starting
from clean accepted main `890b4d5`; the original predictions and failed receipts are preserved.
No preflight/architecture/security/API/operations/changelog owner changes are needed because no
accepted runtime, interface, schema or security boundary changes. Validate contracts/config,
Ruff/format/whitespace, full regression with an explicitly owned disposable PostgreSQL, Compose
and image; required frontend/both-browser coverage also remains a fresh CI delivery gate.
Freeze a two-file candidate and reuse the existing authorized reviewer, without new agents.
Then ordinary scoped publication, both exact-head CI runs, guarded merge and exact-main CI.
These documentary gates are pending at this receipt; this is not authority to implement 8B2.

Sprint 8/8B remain IN PROGRESS, 8A/B1 COMPLETE, 8B2/8B3/8C--8E PLANNED and Sprint 9+ unstarted.
Catalog `0.13.0`, five-control default, migration head `20261007_0008`, scanner read-only access,
separate findings/technical/remediation lifecycles and three-human authority remain unchanged.
No AWS worker, write credentials, remediation execution, rescan or dashboard mutation is added;
no live IdP/AWS/IAM/secret/production operation or production migration occurred.

### 8B1 repair-receipt reconciliation local validation — 2026-10-08

Only ROADMAP and this active plan changed from accepted `890b4d5`; the first updates reconcile
current acceptance, and historical predictions/failed receipts remain intact. During full
validation both owner documents and all three accepted test-source fingerprints stayed unchanged.
All five were reverified after the runs; no runtime, source-test, schema, dependency or CI change.

Restricted execution failed before backend test gates because local Docker API access was denied;
its owned empty TEMP directory was removed, exit 1, no database or passing coverage. Frontend
typecheck/lint passed there, but Vitest configuration hit child-process `spawn EPERM` before tests,
exit 1; build was not reached. Read-only probes confirmed both direct and Python-child Docker
reads were denied on `desktop-linux`. These are retained tooling outcomes, not hidden test passes.

Permission-reviewed execution explicitly selected the local `desktop-linux` context; Docker
29.5.2 was reachable. The same provided isolated validation runner then passed:

- `python -m scripts.validate --focused tests/unit/contracts tests/unit/test_config.py
  tests/unit/test_execution_admission_config.py`: 127 focused passed in 1.56s, followed by 3,024
  full tests passed in 1052.80s, all 402 PostgreSQL cases/five fresh-schema downgrade races,
  no skips, 19 existing SQLite datetime-adapter warnings.
- Ruff passed; 402 files already formatted; whitespace, quiet Compose validation and cached-source
  API/dashboard image build passed. Its uniquely owned loopback/tmpfs database and native TEMP
  subtree were removed; wrapper exit 0. No user database/service or operator secret was used.
- Fresh permission-reviewed frontend typecheck/lint, 133 unit tests/seven files (Vitest 21.60s)
  and production bundle build passed, wrapper exit 0. No source or security setting changed to
  obtain these passes. Native browser coverage was not rerun; prior exact-main Linux 74-browser
  acceptance is carried evidence, while both new final-head and merged-main browser gates remain
  mandatory. No local Firefox pass is claimed and no failed CI was rerun.

Only these documentation receipts may now be added, then contracts/quality/whitespace and the
unchanged three test fingerprints rechecked before a scoped two-file commit. Exact independent
review by the existing reviewer, ordinary publication, both final-head CI, guarded merge and
exact merged-main CI remain pending. No worker/later slice or Sprint 9+ work starts here.

### Approved 8B2 worker implementation and credential source — 2026-10-08

PR #58 completed the preceding two-file reconciliation at main
`cfd1fcba87dee504df9adc21c3f7382370ee5af2`; exact merged-main CI 37838138349 passed.
Earlier preparation-time pending gates and failed receipts above remain historical, not current
blocks. The user approved 8B2's disabled-by-default isolated worker implementation with offline
tests, then explicitly approved ECS task-role-only credentials as its initial source. This
resolves the provider design gate; routine delivery remains covered by the standing workflow.
No ECS resources, IAM policy/role, credential issuance, deployment or live operation is authorized.

8B2 starts from that freshly verified clean local/remote main on
`codex/sprint-8b2-isolated-worker`, reusing this checkout. Existing branches/worktrees and the
parent's three unrelated untracked skill files remain preserved and excluded. 8B2 is IN PROGRESS,
not accepted; 8A/B1 remain COMPLETE, 8B3/8C--8E PLANNED and Sprint 9+ unstarted.

Implement the approved preflight's decisions 1--5 within this slice: a separately launched
default-off worker for exactly configured account/Region/expected role; exclusive ECS temporary
task credentials, no static/profile/host-role/scanner fallback or custom endpoint; fresh STS and
strict regional false/KMS preconditions; fenced pre-intent claims; short guard-first ordered
transactions committing WRITE_INTENT and audit before at most one SDK write; bounded readback;
read-only unknown-effect recovery with sticky quarantine and reservation. Keep the five-minute
dispatch grant, no post-intent owner reclaim/repeat write/TTL release/rollback, and no network
inside database transactions. Readback and acknowledgment are unverified observations, not
technical PASS, finding resolution or a rescan. Keep scanner authentication and retry policy intact.

Add worker states atomically across contracts, model, a new Alembic revision, service, READ API
and owning documentation; retain old immutable request/event bytes and predecessor migrations.
Recheck every caller and enum consumer. Tests use fakes/Stubber and synthetic credentials only,
including actual transport-attempt limits, scope/provider/endpoint negatives, authority races,
claim fencing, crash/recovery, paired audit rollback, populated upgrades and pre-DDL full-path
downgrade refusal on SQLite/disposable PostgreSQL. Run targeted tests, Ruff/format, full regression,
runtime/Compose/image and relevant security acceptance. Required independent exact-head review,
ordinary publication, both final-head CI runs, guarded merge and exact-main CI remain acceptance
gates. Reuse the existing authorized reviewer only when a complete frozen candidate is ready.

The configuration and backend skills preserve process separation and existing Python/container
architecture; PostgreSQL guidance keeps AWS outside short consistently ordered transactions.
The documentation skill preserves original predictions and distinguishes this approval from
implementation/acceptance. ECS task credentials alone do not prove deployment-level isolation;
API/scanner and worker must not share a writer-enabled task, and production isolation needs
separately authorized deployment evidence. No exact-policy scan or UI mutation belongs in 8B2.

### 8B2 local construction and initial validation receipts — 2026-10-08

Implementation remains a local, uncommitted candidate on the scoped branch. Added independent
worker settings/factory/one-job entry point, private fenced coordination, linked version-2 service
events, one SDK dispatch after committed intent, sticky recovery and durable readback budget/window.
Candidate revision is `20261008_0009`; accepted-main head is still 0008. SDK host model directories
and AWS_DATA_PATH are excluded, endpoints are fixed/regional, CSM telemetry is disabled and process
dependency logging is suppressed. No API/scanner factory startup, new public launch route, default
policy, credential issuance, IAM/Compose startup, rescan or UI change. Owning domain documents now
describe this candidate and its compatibility/operational limits, not accepted/live behavior.

Retain initial outcomes rather than calling them passes:

- System-Python adapter selection first had three constructor-flag assertion failures and test
  setup errors; the SDK consumes the ignore-endpoint flag rather than retaining it in client
  metadata. Corrected tests assert the constructor flag plus actual fixed endpoint routing after
  hostile late environment changes. Isolated rerun passed 137 checks, then legacy SQLite/schema/
  adapter selection passed 179. These used synthetic credentials, no AWS transport.
- The first new worker suite had seven failures/22 passes: six test setup/assertion issues and one
  implementation issue where an expired pre-intent lease bypassed safe no-write termination.
  Fixed the expiry ordering without weakening assertions; 29 worker checks then passed. A new
  migration test initially tried current code against missing 0009 schema; populated B1 is now
  seeded before safe downgrade, then upgraded/revalidated. Reflected SQLite CHECK clause order
  is not stable; round-trip compares every column/constraint/FK/index and exact triggers/rows,
  while refused downgrade still compares byte-identical complete DDL and rows. Combined offline
  selection passed 231; subsequent source additions still require fresh complete gates.
- A disposable PostgreSQL/API attempt stopped at collection: system Python lacked the already
  required httpx2 dependency. It ran no tests and cleaned its owned database/TEMP. Correct project
  interpreter is the existing parent `.venv\Scripts\python.exe`, not a dependency installation.
  Corrected selection passed 260 and failed one protected signed-API enum expectation that still
  described admission-only phases. Updated the exact expectation atomically with the approved
  worker vocabulary, adding explicit old version-1 phase/bytes and closed-input/version assertions.
  A subsequent native attempt passed 34 worker cases but API setup failed on shared pytest TEMP
  permissions; it is not API coverage. All subsequent gates use uniquely owned native TEMP.
- Correct project SDK 1.43.87 adapter rerun passed 127 checks, including actual single transport
  attempts, exclusive provider/host model/endpoint/telemetry negatives; no warnings or live AWS.
  Ruff and format passed (415 files) before additional PostgreSQL fault/rollback cases were added.

Next run the unchanged provided validator with that interpreter, an explicitly owned disposable
PostgreSQL and native TEMP, targeted checks then complete regression, quality/Compose/image.
Also validate the separate process/image offline and fresh frontend quality/bundle. Existing native
Firefox launch failure is not rerun unchanged; required fresh Linux CI/both-browser gates remain.
No independent review, commit, push, PR or merge has occurred for this candidate yet. Freeze only
after all local gates, reuse the existing authorized reviewer, and preserve every branch/worktree/
unrelated skill. 8B2/8B remain IN PROGRESS; 8B3/8C--8E and Sprint 9+ are unstarted.

### 8B2 first complete local regression and corrected dependency — 2026-10-08

The expanded offline/disposable-PostgreSQL selection passed 285 tests in 173.06s. Fresh frontend
typecheck/lint, 133 unit tests/seven files (3.81s) and production bundle passed; no frontend source
changed and no native browser pass is claimed. The unchanged isolated validator then passed 353
focused tests in 123.79s, Ruff and formatting (415 files), but complete regression ended with two
failures, 3,252 passes and 19 existing SQLite datetime-adapter warnings in 1313.54s. All 441
PostgreSQL cases ran with no skips; the owned loopback/tmpfs database and native TEMP were removed.
Compose/image gates were not reached, and this failed run is not acceptance.

Both failures were `test_failed_transition_is_atomic_and_retryable[upgrade]` in the PostgreSQL and
SQLite unresolved-region suites. Their shared helper's exact added-table set omitted the new
approved `remediation_worker_claims` table. Failure injection, complete atomic rollback, retained
rows and successful retry had already passed before that final set comparison. Initial progress
output was mistaken for a concurrency failure; the final traces establish this schema-expectation
cause instead. All five existing writer/downgrade races passed. All 37 candidate-file fingerprints
matched before any correction. Add only the worker table to the exact set, retaining empty-table,
guard-row, original-history, DDL rollback and all other assertions; no runtime/migration change,
timeout increase, skip, retry waiver or weakened assertion. This adds one protected-test caller to
the 38-file candidate. Include both affected suites in fresh focused checks and then rerun every
required local gate before freeze/review/publication. 8B2 remains unaccepted and no later slice,
credential issuance or live operation has started.

### 8B2 corrected complete local validation — 2026-10-08

Fresh permission-reviewed execution used the existing project interpreter and unchanged provided
validator, a newly owned loopback/tmpfs PostgreSQL 16 database and uniquely owned native TEMP.
The focused selection included both corrected migration suites and passed 373 tests in 146.91s.
Ruff passed; all 415 files were already formatted. Complete regression passed all 3,254 tests in
1304.43s, including all 441 PostgreSQL cases, no skips and the 19 existing SQLite datetime-adapter
warnings. Both previously failing upgrade-retry cases and all five protected downgrade races
passed. Whitespace, quiet Compose validation and a fresh-source API/dashboard image build passed,
wrapper exit 0. Only this run's database and TEMP subtree were removed; user databases were untouched.

All 38 candidate fingerprints matched after validation. All three existing worktrees, 67 local
branches and the parent's three unrelated untracked `.agents/` skill files remain preserved and
excluded. No dependency, CI, frontend, scanner, collector, rule or frozen predecessor migration
changed. The independent frontend quality/unit/bundle receipt above remains applicable to those
unchanged sources; fresh exact-head Linux CI/both-browser gates are still required.

Pinned the freshly built image by immutable ID
`sha256:c5634da2dfe6fb1012d4117ebc460daade45e6ea29ac70a04b884864a4d5eb6c` and ran three separate
containers with `--network none`, no host mounts, no operator database or real credentials:

- The standalone worker returned `WORKER_DISABLED`, exit 0, before database/credential lookup.
- The installed image SDK (boto3/botocore 1.43.110) passed synthetic ECS metadata, built-in-only
  models, fixed regional endpoints, disabled CSM/smart-defaults probing, fresh STS and strict
  observations/acknowledgment, plus actual one-attempt timeout and 503 transports, exit 0.
- API import/OpenAPI registration passed with explicit test/development and SQLite settings:
  old version-1 event schema, version-2 discriminator, unchanged closed three-field admission
  input, health route and no public worker route/factory import, exit 0. This is an image
  import/schema check, not a running HTTP/lifespan or whole-worker 8B3 acceptance claim.

Only this receipt is added after the full run; recheck contracts, quality, whitespace and unchanged
source fingerprints before a scoped freeze/commit. Independent exact-head review by the existing
authorized reviewer, ordinary publication, both final-head CI runs, guarded merge and exact-main
CI remain pending. No worker is enabled or deployed, and no live IdP/AWS/IAM/secret/production
operation, operator migration, rescan, dashboard mutation, later slice or Sprint 9+ work occurred.
8B2 and Sprint 8 remain IN PROGRESS, not COMPLETE; accepted-main migration remains 0008 until
the candidate's required acceptance gates succeed.

### 8B2 independent review and exact-main implementation acceptance — 2026-10-08

The completed 38-file candidate was frozen at
`398747ba089e70f8042b1761782d3e1fd9739761`, tree
`56eadb5741261904f65df09d3e2425ff799dce3e`, sole parent
`cfd1fcba87dee504df9adc21c3f7382370ee5af2`. Only the final receipt changed after the complete
local run; refreshed contracts passed 92 in 0.39s, Ruff/415-file formatting and whitespace passed,
and all other 37 fingerprints matched. No runtime source changed during validation or delivery.

The existing authorized reviewer returned **REVIEW_PASS**, with no actionable findings:
348 offline checks in 87.98s and 84 newly owned disposable-PostgreSQL checks in 209.38s
(all 39 new worker and 45 legacy admission cases), 432 total with no skips. Fresh-process
default-off probes replaced application-settings/database/credential lookup with failure sentinels
and still passed.
Quality/415-file formatting, whitespace, clean exact branch/head/tree, all 38 fingerprints and
normalized committed bytes matched. Only the reviewer's own database and native TEMP subtrees
were removed. No new reviewer was launched or live operation performed.

Ordinary publication created [PR #59](https://github.com/jnc247s/cloud-security-automation/pull/59).
Both exact-final-head first-attempt runs passed:

| Run | Backend receipt | Other passed mandatory gates |
| --- | --- | --- |
| [Push 37861202543](https://github.com/jnc247s/cloud-security-automation/actions/runs/37861202543) | 3,254 passed, 19 existing warnings, 1469.35s | 133 frontend units/seven files, 74 Chromium/Firefox journeys, Ruff/415-file formatting, image and cleanup |
| [PR 37861227043](https://github.com/jnc247s/cloud-security-automation/actions/runs/37861227043) | 3,254 passed, 19 existing warnings, 1500.84s | Same mandatory frontend/browser/quality/image/cleanup gates |
| [Exact main 37864100728](https://github.com/jnc247s/cloud-security-automation/actions/runs/37864100728) | 3,254 passed, 19 existing warnings, 1414.80s | Same mandatory gates; all 18 job steps succeeded |

Every complete CI suite ran all 441 PostgreSQL cases, no skips, and both browser projects with
zero configured retries. These final-head/main CI runs passed on attempt 1; no failed-CI rerun
or passing companion substitutes for a required gate.
The earlier failed local 3,252-pass run and all historical failures remain intact above.
Native Windows Firefox launch and the local scan-picker/navigation report are not fixed or waived.

Fresh checks reverified clean local reviewed head/tree, OPEN/CLEAN PR with both required checks,
remote main at cfd1fcb and feature at 398747b before guarded ordinary merge with exact-head
matching; no admin/protection bypass, force or branch deletion. Merge main is
`7a36ddde20aafc60712b38165acd25460418ab92`, retaining tree 56eadb5 and exact parents
`cfd1fcba87dee504df9adc21c3f7382370ee5af2` and
`398747ba089e70f8042b1761782d3e1fd9739761`. Exact-main run 37864100728 is push/main/that SHA/
attempt 1, completed SUCCESS; actual logs and every mandatory/cleanup step were inspected.
The [final public receipt](https://github.com/jnc247s/cloud-security-automation/pull/59#issuecomment-6071961094)
supersedes delivery-pending checkpoints, not their original predictions or failed evidence.

**8B2 is COMPLETE** as accepted disabled-by-default code; migration head is `20261008_0009`.
Updated execution-history readers require 0009 even while the worker is disabled: apply schema
before updated code only in a separately authorized environment. Strict READ clients must accept
retained v1/new v2 events and expanded phases before worker enablement. No operator database is
auto-migrated. ACK/readback is unverified, not PASS, finding resolution or an exact-policy rescan.
Sticky quarantine, no AWS CAS/cancellation guarantee, same-role-name recreation, physical task/
IAM/network/DB isolation, IdP human-account governance and privileged operator trust remain
explicit limits. No credentials/resources are provisioned and no live operation is authorized.

### 8B2 bounded documentary closeout entry — 2026-10-08

Only after the exact-main gate passed, clean local main was normally fast-forwarded to 7a36ddd
and `codex/sprint-8b2-documentary-closeout` created, preserving the implementation branch,
all other branches/worktrees and the parent's three unrelated untracked skill files.
Reconcile the twelve owning Markdown documents (including README's stale current-head/no-worker
statements) and the matching current-status assertions in the progress-contract test. Retain all
historical predictions/failed receipts, existing published heading anchors, B1 introduction of 0008,
unknown-effect/production limits and default-off read-only-scanner boundaries. No runtime, schema,
API shape, authentication,
frontend, dependency, CI, scanner/rule or operational configuration change belongs in this branch.

The documentation skill preserves historical evidence and separates accepted code from deployment;
backend/configuration/short ordered PostgreSQL transaction decisions remain unchanged. Record the
0009-before-code compatibility requirement even with the worker off and strict-client coordination.
Run targeted contracts, Ruff/format, complete regression with newly owned disposable PostgreSQL,
whitespace/Compose/fresh-source image and unchanged-source fingerprints. Freeze a scoped candidate,
reuse only the existing authorized reviewer, then ordinary publication, both final-head first-
attempt CI runs, guarded merge and exact-main CI. These documentary gates are pending at entry;
8B3 cannot advance until they pass. 8A/B1/B2 are COMPLETE; Sprint 8/8B and the whole goal remain
IN PROGRESS; 8B3/8C--8E remain PLANNED and Sprint 9+ unstarted. No live IdP/AWS/IAM/secret/
deployment/production operation, operator migration, rescan or dashboard mutation is introduced.

### 8B2 documentary closeout local validation — 2026-10-08

The unchanged provided validator used the existing project interpreter, a newly owned loopback/
tmpfs PostgreSQL 16 database and uniquely owned native TEMP. Targeted contracts/link/status checks
passed all 92 in 0.43s. Ruff and 415-file formatting passed. Full regression passed all 3,254 in
1310.29s (21:50), including all 441 PostgreSQL cases, no skips and 19 existing SQLite datetime-
adapter warnings. The protected migration races and both previously corrected retry cases passed.
Whitespace, quiet Compose and a fresh-source image build passed, wrapper exit 0; only the
run-owned database and TEMP subtree were removed. No user database was touched.

All thirteen frozen candidate fingerprints matched after that complete validation. All three
worktrees, 68 local branches (only one new scoped closeout branch) and the parent's three unrelated
untracked skill files remain preserved/excluded. The 242 tracked runtime/frontend/migration/
script/CI/dependency fingerprints are retained for final unchanged-source comparison.
Fresh-source image dependencies resolved boto3/botocore 1.43.110; no host dependencies were
installed or changed. Unchanged frontend/browser and network-disabled worker/image acceptance
from PR #59 are carried evidence, not new native browser or whole-8B3 coverage. Both fresh
exact-final-head CI suites and exact merged-main CI remain mandatory for this closeout.

Only this receipt and neutral entry-time-gate wording in ROADMAP/README/SECURITY/THREAT_MODEL
change after the full run; no status, runtime, security boundary, compatibility requirement,
contract assertion, historical prediction or failed receipt changes. This avoids leaving the
same closeout's entry-time gates described as permanently pending after its own acceptance.
Recheck every targeted contract, quality/whitespace, all unchanged validated/protected fingerprints
and the final-metadata source image before freezing. Independent existing-reviewer review,
publication, both first-attempt final-head CI runs, guarded ordinary merge and exact-main CI
are still pending here. 8A/B1/B2 are COMPLETE as code; Sprint 8/8B remain IN PROGRESS, 8B3/8C--8E
PLANNED and Sprint 9+ unstarted. No new agent, live IdP/AWS/IAM/secret/deployment/production
operation, credential issuance, operator migration, rescan or dashboard mutation occurred.

### 8B2 documentary review findings and bounded repair — 2026-10-08

The existing reviewer returned **REVIEW_FAIL** for exact frozen head
`c01509603286882ac35406bda4e133da2e7c4cff`, tree
`249fa4f74826d489564251cddba37695eeb0f51e`: three LOW documentation findings, no runtime defect.
Independent 92 contracts passed in 0.35s, Ruff/415-file formatting and committed whitespace passed.
Fresh provider metadata confirmed PR #59 ancestry, all three first-attempt successful runs and
all 18 exact-main job steps. All thirteen candidate/242 protected fingerprints and normalized
committed bytes matched; clean index/worktree, 68 branches/three worktrees/parent skills were
preserved. Only the reviewer's owned native TEMP was removed. No publication occurred.

The findings are unqualified current owner openings that retain accepted PR #55/8A/B1 instead
of PR #59/8B2; current summaries that deny an execution-admission route/worker implementation;
and the operations audit paragraph that incorrectly applies human issuer/subject/roles/capability
to worker service attribution. Explicit old slice-specific 8A/B1 boundaries and README's 7B
paragraph remain valid history; the latter is only clarified as "7B itself."

Standing approval covers this bounded documentary repair without an architectural decision.
Reconcile current ARCHITECTURE/SECURITY/THREAT_MODEL/known-limitations openings and summaries,
preserving undeployed/default-off/live-authorization limits. Describe human authority/admission
audit separately from `actor_type="service"` and canonical `WorkerActor(service_id,
expected_role_arn)` hashing, not a fourth human. No implementation, schema, API or permission
change is needed. Add five strict documentation regression cases in the already-owned contract
test: three owner headers against ROADMAP's current accepted baseline, limitations scope and
human/service audit distinction. All five failed against the pre-repair documents in 0.47s
(12 existing cases deselected); this is intentional reproduction, not a passing run or a test
waiver. Their owned TEMP was removed.

The repair remains within the same thirteen owned paths and original accepted design. Run all
targeted contracts and a fresh complete disposable-PostgreSQL/quality/Compose/image validation,
capture unchanged-source fingerprints and freeze a new scoped commit retaining c015096 history.
Only then reuse the existing reviewer for exact-new-head review; publication, both fresh
first-attempt final-head CI runs, guarded merge and exact-main CI remain required. The failed
review and previous receipts remain intact. No runtime/auth/scanner/default/credential/frontend/
dependency/CI or production boundary changes, new agent, live operation or later slice is started.
8A/B1/B2 are COMPLETE as code; Sprint 8/8B remain IN PROGRESS; 8B3/8C--8E PLANNED and 9+ unstarted.

### 8B2 documentary repair fresh local validation — 2026-10-08

The unchanged validator used the existing project interpreter, a newly owned loopback/tmpfs
PostgreSQL 16 database and uniquely owned native TEMP. All 97 targeted contracts passed in
0.40s, including the five new guards; Ruff and 415-file formatting passed. Fresh full regression
passed all 3,259 tests in 1302.80s (21:42), including all 441 PostgreSQL cases, no skips and
19 existing SQLite datetime-adapter warnings. Protected migration races, authority/admission,
worker claim/recovery and read-only scanner/assessment checks passed without runtime changes.
Whitespace, quiet Compose and a fresh-source image build passed; wrapper exit 0. Image SDK
boto3/botocore resolved 1.43.110. Only the run-owned database and native TEMP subtree were removed.

All thirteen candidate fingerprints and 242 protected runtime/frontend/migration/script/CI/
dependency fingerprints matched after the run. All 68 local branches, three worktrees and the
parent's three unrelated untracked skill files remain preserved/excluded. Only this exact receipt
is appended after the full run; repeat targeted/quality/whitespace and fingerprint checks before
freezing. Unchanged frontend/browser and prior image probes remain explicitly carried evidence,
not a new whole-8B3 or live acceptance claim.

Post-receipt 97 contracts passed again in 0.40s; Ruff/415-file formatting, whitespace,
Compose and the final-metadata image build passed. The immutable image
`sha256:2c98397e5c28b2586e1064773635b7c2e1e5edd344ed5a3961bae357c2ed1faf`
returned `WORKER_DISABLED`, exit 0, with the required synthetic UUID, no network, host mounts,
credentials or database. The first probe omitted that required argument and correctly returned
`WORKER_INVALID_ARGUMENT`, worker exit 2; the corrected invocation is not a runtime repair or
a waiver. This is a default-off entry-point check, not enabled-worker or whole-HTTP acceptance.

The initial REVIEW_FAIL and intentional five-case red reproduction remain historical evidence.
Fresh exact-new-head review by the existing reviewer, both first-attempt final-head CI runs,
guarded ordinary merge and exact merged-main CI are still required. No new architecture, runtime,
schema, API, permission, credential, default, deployment, live operation or later slice is added.
8A/B1/B2 remain COMPLETE as code; Sprint 8/8B IN PROGRESS; 8B3/8C--8E PLANNED and 9+ unstarted.

### 8B2 documentary acceptance and 8B3 analysis entry — 2026-10-11

PR #60 is accepted at `04803adbb8baf825ec62f19c5b2bea015f907277`, retaining reviewed head
`c17d47dc2f57b8e38f5c2faf363ca0561b58d79d`, tree
`5320218b39707d353fe96f91413ab1dc7f9b4099`, and exactly parents accepted implementation `7a36ddde`
and reviewed documentary head. Exact-head REVIEW_PASS closes all three earlier LOW documentation
findings; the failed review and intentional red reproduction above remain historical evidence.
The user's 2026-10-11 confirmation approved the exact twelve-documents/one-contract-test public
push and PR. Both first-attempt final-head CI runs passed, followed by an expected-head guarded
ordinary merge and green exact-main CI. No admin bypass, force push or branch deletion occurred.

| Verified CI | Backend result | Other gates |
| --- | --- | --- |
| Push 38168820905 | 3,259 passed / 19 existing warnings / 1457.07s | All 441 PostgreSQL cases; 133 frontend units/seven files; 74 browsers (37 Chromium/37 Firefox), zero configured retries; quality/image/cleanup and all 18 job steps |
| PR 38168905080 | 3,259 passed / 19 existing warnings / 1494.20s | Same complete gates |
| Exact main 38171117595 at 04803ad | 3,259 passed / 19 existing warnings / 1464.94s | Same complete gates |

Provider job logs/counts and terminal metadata were checked, not inferred from a green summary.
The documentary prerequisite is closed; its earlier pending descriptions are preparation-time
history. This acceptance changes no runtime, schema, API, permission or production authority.
All 68 pre-existing local branches, three worktrees and unrelated parent skills were preserved.

Clean local/remote main at the accepted merge was reverified before creating the scoped
`codex/sprint-8b3-preflight` branch. The [8B3 preflight](../../sprint-8b3-preflight.md) inspects
signed authority/API callers, worker/closed adapter, audit/history/claim persistence, scanner and
finding ownership, separate existing tests and runtime packaging. Recommended bounded delivery:
8B3.1 integrated signed HTTP/real PostgreSQL/offline adapter/READ coverage; 8B3.2 combined faults,
races and conservative recovery; 8B3.3 installed-image/process/security acceptance and 8B closeout.
Accept one delivery slice before advancing. No new architectural decision is identified for the
test-only first slice; standing implementation workflow applies only within accepted design.
Stop before a new credential source, recovery policy, API/schema/topology or success definition.

Only analysis/progress Markdown is changed at this checkpoint. No implementation, application
launch, new reviewer, commit, push, PR or merge in 8B3; no live IdP/AWS/IAM/secret/deployment,
operator migration, production operation, rescan or dashboard mutation. 8A/B1/B2 remain COMPLETE;
Sprint 8/8B IN PROGRESS; 8B3/8C--8E PLANNED; Sprint 9+ unstarted. Native Firefox launch and the
user's local picker/back-navigation report remain limitations, not fixes claimed from Linux CI.

Analysis validation: `python -m pytest tests/unit/contracts -q -p no:cacheprovider` with a freshly
owned workspace basetemp passed all 98 cases in 3.67s. Ruff check and formatting passed; the latter
reported 416 files. A nonfatal cache-write access warning was followed by a no-cache formatting
check, also passed/416. The existing Python launcher-location warning remains visible; no repair
or environment installation is claimed. Whitespace passed, and only the owned TEMP subtree was
removed. All prior branch refs/worktrees and the parent's three skill hashes/status remain intact.
No fresh full regression, PostgreSQL, image, application or browser acceptance ran in this analysis;
those remain implementation gates. Only ROADMAP, this active plan and the new preflight are edited.
The verification/backend/database/documentation skills kept the plan within existing FastAPI/ECS
and short transactions, traced the whole signed-to-history journey and preserved owning documents
and historical receipts; no platform migration, external Page write or runtime change was made.

### 8B3.1 test-only execution plan and implementation entry — 2026-10-11

The user requested continued Sprint 8 goal work; standing routine authority applies within the
approved 8B design and completed [8B3 preflight](../../sprint-8b3-preflight.md). No new architectural
decision is introduced. Remote main and successful exact-main CI were reverified at accepted
04803ad before implementation. Reuse the scoped `codex/sprint-8b3-preflight` branch and preserve
its three owned analysis Markdown changes; do not develop on main or replace any worktree.

| Bounded acceptance slice | Status | Scope |
| --- | --- | --- |
| 8B3.1 | IN PROGRESS | Signed human proposal/approval/admission, real migrated DB, offline real worker/closed adapter, public READ/replay and unchanged technical/finding history |
| 8B3.2 | PLANNED | Combined deterministic fault/race/recovery acceptance |
| 8B3.3 | PLANNED | Installed-image/separate-process/security acceptance and 8B closeout |

Predictions: add a focused shared test helper and SQLite/explicit disposable-PostgreSQL journeys
for expected-absence, ARN and exact legacy non-ARN key contexts; already-enabled and changed-key/
absence no-write behavior; three signed human identities with real production-mode authorization;
durable intent/audit before one offline SDK write; v1/v2 READ/audit digest fidelity; no autoflush/
mutation from history/replay; no provider/worker construction from API startup/admission; no scan,
assessment, finding/exception/governance or protected evidence changes. Intercept synthetic ECS
metadata and every SDK transport, forbid ambient host AWS configuration, and assert closed API/
worker/engine transactions plus separate PostgreSQL NOWAIT lock probes at provider/AWS/close.
No application, migration, dependency, IAM, frontend or CI change is planned. Update only the
current progress contract to reflect 8B3 IN PROGRESS; preserve old predictions/receipts.

Validate new journeys first, affected API/worker/security/history/migration tests, then Ruff,
formatting, complete regression with a freshly owned disposable PostgreSQL, Compose/image and
documentation. Freeze for the existing authorized reviewer, resolve actionable findings, require
both first-attempt final-head CI runs, expected-head guarded ordinary merge and green exact-main
CI before the next delivery slice. 8B3/8B/Sprint 8 stay incomplete; 8C--8E/Sprint 9+ do not start.
No live AWS/IdP/IAM/secret/deployment/production operation, operator DB migration, additional
reviewer, force clear, rescan or dashboard mutation is authorized or performed.

Initial local implementation adds the three focused test files and current progress-contract
assertions only; runtime/schema/API/security/defaults remain unchanged. Seven migrated-SQLite
journeys passed in 15.30s with reviewed local socket access. Subsequent stricter human audit and
closed-input assertions still require fresh validation. Initial lint found only newly added long
lines; formatting and a bounded line wrap corrected them without assertion changes.

The first restricted native test session produced no result and was interrupted (exit 1).
A single-case diagnostic then emitted a 30-second thread dump: Windows socket.py accept/
_fallback_socketpair -> ProactorEventLoop self-pipe -> AnyIO/TestClient.__enter__, before HTTP
or worker execution. That session was also stopped (exit 1), not called a passing or transient
application run. Reviewed local-socket permission allowed the unchanged journey to run; no
authentication, production configuration, timeout/assertion waiver or runtime repair was added.
Both interrupted sessions' uniquely owned TEMP subtrees are cleaned separately after exact-path
validation; no user files, credentials, database or worktree is removed. Targeted PostgreSQL,
full regression, independent exact-head review and delivery remain pending at this checkpoint.

Fresh validation of the strengthened candidate passed all 335 focused API/worker/security/
contract cases in 68.30s, including the seven signed-HTTP/migrated-SQLite journeys. Exact focused
paths: `tests/api/test_remediation_worker_acceptance.py`, `test_remediation_executions.py` and
`test_remediations.py` in the same API directory; `tests/unit/test_remediation_worker_aws.py`,
`test_remediation_worker_process.py`, `services/test_remediation_worker.py`,
`database/test_remediation_worker_migration.py`, `database/test_execution_admission_migration.py`,
`contracts/` and `security/` under `tests/unit/`. Ruff check, 419-file formatting and whitespace
passed. Formatting emitted a nonfatal cache-write access warning; an additional `--no-cache`
formatting check also passed, all 419 files. Only the uniquely owned test TEMP was removed.
SHA-256 comparisons confirm all nine candidate files and 485 other tracked files were unchanged
through that test run. These are focused results, not complete PostgreSQL or regression acceptance.

The provided full validator's first attempt exited 1 before creating PostgreSQL or running its
focused/full suites because the local Docker engine was unavailable. Its owned TEMP was removed;
no validation database was created and no user database/container was touched. Read-only checks
verified context `desktop-linux` and the local named-pipe endpoint, not a remote Docker host.
The exact installed Docker Desktop executable was started hidden as a local test prerequisite.
Desktop/backend processes started, but the engine and Desktop status requests remained
unresponsive; categorized startup diagnostics contained deadline errors. `wsl --status` reported
version 2 and `wsl --list --verbose` showed `docker-desktop` stopped. The two tracked read-only
diagnostic clients were interrupted (exit 1), not reported as engine readiness. No service change,
WSL shutdown/reset, reinstall, container/volume deletion, database migration or credential action
was attempted. Local engine readiness is required before retrying the unchanged owned disposable
PostgreSQL/full/container validation; none of those gates is waived. Independent frozen-candidate
review and publication remain pending, and 8B3.1/8B3/Sprint 8 are not complete.

### 8B3.1 local validation and review preparation — 2026-10-11

After the user resumed the goal, local Docker engine 29.5.2 responded successfully. The client
still targeted `desktop-linux`/its local named pipe, with no host/context override to a remote
engine. Remote main remained accepted 04803ad; all existing branches, three worktrees and the
parent's three unrelated skill files/status were preserved. The earlier stopped-engine and
restricted-socket failures above remain historical evidence, not passing runs or waived gates.

The unchanged candidate passed all 491 focused cases in 419.51s, with an explicitly owned
loopback/tmpfs PostgreSQL (verified version 16.15), including all fourteen new SQLite/PostgreSQL
journeys. The run then exited 1 because the root's run-only `RUFF_NO_CACHE=1` was invalid: this
installed Ruff accepts `true`/`false`. No lint/full-regression success is claimed for that run.
Its owned database and TEMP were removed. SHA-256 checks confirmed all nine candidate files and
485 other tracked files were unchanged, retaining the exact-source focused evidence.

Correcting only that process cache setting to `true`, the provided validator continued the
remaining gates on another fresh owned PostgreSQL 16 container. It did not reuse an operator
DATABASE_URL/TEST_DATABASE_URL, weaken assertions, change source or repeat a cloud write.
`python -m ruff check .` and `python -m ruff format --check .` passed (419 files formatted);
complete `python -m pytest` passed 3,274 cases in 1370.08s, no skips, including all 448 PostgreSQL
cases across 24 files. The 19 existing warnings are SQLite datetime-adapter deprecations in the
protected migration tests. Whitespace and quiet Compose validation passed; the image build
passed using cached layers. Validator exit was 0, followed by exact owned-database/TEMP cleanup.
Separate checks found no remaining labeled validation container or either owned TEMP subtree.

The actual built immutable image is
`sha256:4f5fe51eca6bb118982e7422c08248559191c6b38438fdafa347b76f4a33b801`.
Networkless, read-only, unprivileged probes without host mounts, credentials or a database verified
Python 3.12.15, boto3/botocore 1.43.110 and `WORKER_DISABLED`, exit 0, with the required synthetic
UUID. These are installed-version/default-off probes, not enabled separate-process/whole-8B3,
deployment or physical-isolation acceptance. Frontend/browser regressions remain CI gates; no
new native Firefox coverage or picker/navigation repair is claimed.

All nine candidate and 485 protected tracked-file hashes remained identical through focused/full/
image validation, before these receipt-only owner updates. No runtime, API, schema, migration,
permission, credential, dependency, scanner, frontend or CI behavior changes. Migration head
0009, accepted catalogs/profile, separate remediation/finding/technical lifecycles and all live/
production authorization limits are unchanged. The verification/database/documentation skills
kept the signed-to-history story offline, checked short transaction/lock boundaries and preserved
actual failures and original predictions in their owning records. Validate final receipts, freeze
the exact candidate for the existing reviewer and resolve findings before final-head CI, guarded
ordinary merge and exact-main acceptance. 8B3.1/8B3/Sprint 8 stay IN PROGRESS; 8B3.2/8B3.3 and
8C--8E remain PLANNED, and Sprint 9+ remains unstarted.

### 8B3.1 exact source review and final receipt preparation — 2026-10-11

The existing authorized reviewer returned REVIEW_PASS with no actionable HIGH/MEDIUM/LOW
findings for exact head `daff23a0b43e4e2081f5ba436be3be546309d1e6`, tree
`e51a1acb858588659bbe3696b95175393a5696d8`, sole parent accepted `04803ad`. The scoped local
commit contains exactly five Markdown/four test files and the worktree/index are clean.
Independent targeted validation passed 335 affected offline cases in 66.22s (including the
seven new SQLite journeys and 98 contracts), all seven new PostgreSQL journeys in 31.52s
with no skips on separately owned loopback/tmpfs PostgreSQL 16.15, Ruff/419-file formatting
and committed whitespace. Only that reviewer's exact database and two owned TEMP subtrees
were removed. Before/after all nine candidate and 485 other tracked fingerprints, normalized
committed blobs, 69 branch refs, three worktrees and the three parent skill hashes matched.

The reviewer inspected, but did not independently rerun, root's complete 3,274-case/448-PG
regression and Compose/product-image/default-off evidence. No enabled separate process,
frontend/browser, physical-isolation or live-provider acceptance is claimed. This receipt
updates only owning Markdown; all tested source, protected interfaces, accepted design and
operational limits remain unchanged. Validate the receipt-only final tree and obtain the same
reviewer's exact-head confirmation before publishing its scoped PR. Both first-attempt
final-head CI runs, guarded ordinary merge and exact merged-main CI remain required for
acceptance. No push, PR, merge, new reviewer or later-slice/live operation has occurred at
this preparation checkpoint; 8B3.1/8B3/8B/Sprint 8 remain IN PROGRESS.

### Accepted 8B3.1 integrated offline tests — 2026-10-11

[PR #61](https://github.com/jnc247s/cloud-security-automation/pull/61) is accepted at
`eea2f0c48a72cd14c0184a332f535ef315855b86`, retaining reviewed head
`c1323437931fd198ac1309bc40ebb9c0b6d56ebe`, tree
`81788a08b114e3e38f41ac43dd4ea6a57eff228c` and exactly parents accepted `04803ad` and reviewed
head. The existing reviewer returned exact final-head REVIEW_PASS with no actionable findings.
Independent final receipt checks passed 98 contracts in 2.66s, Ruff/419-file formatting and
incremental/aggregate whitespace checks. The previously reviewed test source and all 485 other
tracked files stayed unchanged; earlier independent 335 offline/seven PostgreSQL results and
root's complete local validation are carried evidence, not new independent full-suite runs.

Both first-attempt final-head CI runs passed, followed by an expected-head guarded ordinary
merge and green exact-main CI. Complete provider logs, checkout commits, test counts and all
terminal steps were inspected. The PR's tested merge `503c2c99` had the same reviewed tree and
parents as the delivered merge. No admin bypass, force push or branch deletion occurred.

| Verified CI | Backend result | Other gates |
| --- | --- | --- |
| [Push 38182744106](https://github.com/jnc247s/cloud-security-automation/actions/runs/38182744106) | 3,274 passed / 19 existing warnings / 1510.16s | All 448 PostgreSQL cases/24 files, no skips; 133 frontend tests/seven files; 74 browsers (37 Chromium/37 Firefox), one worker/zero retries; quality/image/cleanup and all 18 job steps |
| [PR 38183014262](https://github.com/jnc247s/cloud-security-automation/actions/runs/38183014262) | 3,274 passed / 19 existing warnings / 1475.02s | Same complete gates |
| [Exact main 38185057377](https://github.com/jnc247s/cloud-security-automation/actions/runs/38185057377) at eea2f0c | 3,274 passed / 19 existing warnings / 1001.16s | Same complete gates |

This accepts only the seven SQLite/seven PostgreSQL signed-human/real-database/offline-worker/
closed-adapter/READ journeys and their protected regressions. No application, schema, migration,
API, authentication, permission, credential, dependency, frontend or CI behavior changes. Runtime
baseline 7a36ddde, migration 0009 and accepted catalog/profile remain unchanged. ACK/readback
is unverified, not PASS, attributed verification or finding resolution. Combined signed fault/
race/recovery and enabled installed-image/separate-process acceptance remain later 8B3 slices;
physical isolation, deployment, operator migration and live IdP/AWS/IAM/secret/production
operations are not proved or authorized. Native Firefox launch remains a validation limitation;
the local picker/navigation report remains untriaged. Neither is repaired by Linux browser regression.

### Current 8B3 acceptance status

The dated preparation tables and predictions above remain historical and are not rewritten.
This table is the current bounded status, consistent with ROADMAP.

| Bounded acceptance slice | Status | Scope |
| --- | --- | --- |
| 8B3.1 | COMPLETE | Accepted integrated signed HTTP, migrated database, offline worker/closed adapter and authorized READ/replay tests through PR #61 |
| 8B3.2 | COMPLETE | Accepted combined signed fault/race/recovery tests through PR #63 and test-only repair PR #64 |
| 8B3.3 | COMPLETE | Installed-image/separate-process/security acceptance and 8B closeout |

The user requested continued goal work under standing accepted-design workflow authority.
Clean accepted main was ordinarily fast-forwarded to eea2f0c only after exact-main CI passed,
then `codex/sprint-8b31-closeout` was created for five owning Markdown files and a narrowly
scoped current-status contract. All 69 existing local branches, three worktrees and unrelated
parent skill files are preserved; only the new closeout branch is added. No new reviewer or
next-slice implementation is started by this preparation. Targeted contracts, Ruff/formatting,
complete disposable-PostgreSQL regression, exact independent review, both first-attempt
final-head CI runs, guarded ordinary merge and exact-main CI are required for this reconciliation
before 8B3.2 advances. Sprint 8/8B/8B3 remain IN PROGRESS, 8C--8E PLANNED and Sprint 9+ unstarted.

### 8B3.1 documentary local validation and review preparation — 2026-10-11

The six-path closeout preserves dated predictions and failed receipts, adds an explicit current
status table and scopes its progress contract to that table. Five Markdown files and one contract
test change; application/runtime/schema/API/authentication/credentials/frontend/CI are untouched.
The initial restricted 98-contract run passed in 2.91s with the existing nonfatal Python launcher
location warning; no runtime repair or waived test is claimed. After prose-only refinements, the
unchanged validator ran fresh targeted contracts and full regression on its own loopback/tmpfs
PostgreSQL 16 with an explicit disposable TEST_DATABASE_URL, not an operator database.

Fresh targeted 98 contracts passed in 0.40s, Ruff/419-file formatting passed, and complete
`python -m pytest` passed all 3,274 cases in 1371.91s with no skips, including all 448 PostgreSQL
cases across 24 files. The 19 existing warnings are SQLite datetime-adapter deprecations.
Whitespace, quiet Compose and the cached-layer image build passed; validator/wrapper exit was 0.
Its exact owned database and TEMP were removed. Read-only follow-up confirmed TEMP absence and
zero labeled validation containers; no user database, container, branch or worktree was deleted.

The actual immutable image `sha256:73a0b1dd9f58720747fd3c3d05ba6e94fc9ab77e481136ecd9a92e23cf6b87ae`
verified Python 3.12.15, boto3/botocore 1.43.110 and `WORKER_DISABLED`, exit 0, in networkless,
read-only, unprivileged ephemeral probes without host mounts, credentials or a database. This is
installed-version/default-off evidence, not enabled separate-process, deployment or physical
isolation acceptance. Frontend/browser coverage remains a fresh final-head CI gate, not a local
Firefox or picker/navigation repair. All six candidate and 488 other tracked SHA-256 hashes
matched before/after full validation, prior to this receipt-only append. Validate final receipts,
freeze the exact scoped commit for the existing reviewer and resolve findings before both
final-head CI runs, guarded ordinary merge and exact-main acceptance of this reconciliation.
No new reviewer, next-slice implementation, live/production operation or Sprint 9+ work started.

### 8B3.1 documentary review correction — 2026-10-11

The existing reviewer returned REVIEW_FAIL for frozen closeout head
`82868fce811cdf6774f4256cdc9dfdddacdae81a`, tree
`74cab3547e46481415704c350ad37ba9f8ab3470`, with one LOW current-owner reconciliation gap:
README still called 8B3 PLANNED while ROADMAP and the active current-status table correctly
recorded it IN PROGRESS and 8B3.1 COMPLETE. The independent six-path review otherwise passed
98 contracts in 2.68s, Ruff/419-file formatting, committed whitespace and fragment checks.
All six candidate/488 protected hashes, clean checkout, 70 branch refs, three worktrees and
three unrelated parent skill hashes were preserved. The nonfatal Python launcher location
warning remains; full regression, provider CI and image results were carried evidence, not
independently rerun. This failed receipt is retained, not waived or called REVIEW_PASS.

The bounded repair adds README as a seventh scoped path: six Markdown files and the current-status
contract. Its current summary now records accepted PR #61 and the remaining planned slices;
its remediation documentation/structure labels now reflect accepted default-off worker code.
The contract additionally checks that current README status agrees with ROADMAP and this plan.
This is accepted-design documentation/test reconciliation, not runtime, schema, API, authentication,
credential, frontend, CI or later-slice implementation. Historical predictions and prior receipts
remain unchanged. Because README is package/image input, fresh targeted/full disposable-PostgreSQL
regression, quality, Compose, rebuilt-image/installed-version/default-off probes and exact-head
independent review are required before publication. Both final-head CI runs, guarded ordinary
merge and exact-main CI remain acceptance gates. Scanner credentials remain read-only;
ACK/readback is not PASS, verification or finding resolution. No enabled-process, physical
isolation, deployment, operator migration or live operation is proved or authorized by this repair.

The first fresh repair validator passed 98 focused contracts in 0.38s and Ruff lint, then stopped
at formatting: the new README-status assertion required Ruff's parenthesized expression layout
(one file would be reformatted, 418 already formatted). Full regression, Compose and image gates
did not run, so no full success is claimed. Validator/wrapper returned 1 and removed only their
exact owned test database and TEMP. The assertion was reformatted without weakening its checks;
fresh validation is required on the corrected candidate. No operator database or user file changed.

### Corrected 8B3.1 documentary repair validation — 2026-10-11

After the formatting correction, the unchanged validator passed fresh targeted 98 contracts
in 0.39s, Ruff/419-file formatting and all 3,274 regression tests in 1363.14s, with no skips.
All 448 PostgreSQL cases across 24 files passed; file-by-file counts match accepted PR #61,
including its seven signed HTTP/database/offline-worker journeys. The 19 existing warnings are
SQLite datetime-adapter deprecations. Whitespace, quiet Compose and the fresh image rebuild
passed; validator/wrapper exit was 0. Its exact owned database and TEMP were removed.
Read-only follow-up confirmed both failed/successful owned TEMP paths absent and zero labeled
validation containers. All seven candidate/487 protected hashes, 70 branch refs, three worktrees
and three unrelated parent skill hashes matched before/after; no user resource was removed.

The actual immutable rebuilt image
`sha256:51e6b9d682481bf9adeef0ca2e1e208126fcab1b3a17d28dc8c088e291109a42`
contains the exact corrected README SHA-256
`9831026f3d53663601921f2ac1b91b81555ded2956c9139e28fd80c78950192b`.
Networkless, read-only ephemeral probes without host mounts, credentials or a database verified
Python 3.12.15, boto3/botocore 1.43.111 and WORKER_DISABLED/exit 0. Dependencies resolved within
unchanged declared ranges; no manifest was changed. These are installed-version/README/default-off
checks, not enabled separate-process, physical-isolation, live-provider or deployment proof.
Only this receipt is appended after the full frozen validation; README, test source and all
487 protected files remain unchanged. Final receipt contracts/quality/whitespace, exact-head
independent review, both final-head CI suites, guarded merge and exact-main CI remain required
before 8B3.2 advances. The native Firefox/picker limitations and failed receipts remain retained;
no new reviewer, runtime behavior, later slice, live operation or Sprint 9+ work started.

### Accepted 8B3.1 documentary reconciliation — 2026-10-11

The existing reviewer returned REVIEW_PASS for final head
`e64ccd1d3cb44b9c325c7b3ca667a7a2b115fb43`, tree
`1d713ea298359373f5ff20c851b2b89198d7ba45`, with no HIGH/MEDIUM/LOW findings. Fresh independent
98 contracts, Ruff/419-file formatting, whitespace, current-owner guards and retained anchors
passed. Local full/image results above are carried evidence, not an independent full rerun.

Both final-head first-attempt CI runs passed: push
[38192513354](https://github.com/jnc247s/cloud-security-automation/actions/runs/38192513354)
(job 114628098118, backend 1470.80s) and PR
[38192586748](https://github.com/jnc247s/cloud-security-automation/actions/runs/38192586748)
(job 114628324883, backend 1230.88s). The PR's actual synthetic checkout was
`63a02045867550d468778aba02c48867099aedd6`, with the reviewed tree and parents accepted main
`eea2f0c48a72cd14c0184a332f535ef315855b86` plus final head `e64ccd1`. Complete primary logs,
not check summaries alone, prove 3,274 backend cases with 19 existing SQLite warnings, all
448 PostgreSQL cases/24 files without skips, 133 frontend tests/seven files, and 74 browser
journeys (37 Chromium/37 Firefox, one worker, zero retries), quality/image/cleanup and all
18 successful job steps. The native push watch exited 1 on a TCP connection timeout while
browser coverage was pending; the same underlying run completed SUCCESS on attempt 1. This
was a watch transport interruption, not a failed CI test, rerun or waived acceptance defect.

After fresh CLEAN/MERGEABLE/head/base and both success checks, the ordinary expected-head guarded
merge preserved the reviewed tree and branches. [PR #62](https://github.com/jnc247s/cloud-security-automation/pull/62)
merged at `01db441ddeee8466e068b30f0547f29a3906f4e7` on 2026-10-12T02:09:16Z (Chicago 2026-10-11),
with parents `eea2f0c` and `e64ccd1`. Exact-main
[CI 38194672821](https://github.com/jnc247s/cloud-security-automation/actions/runs/38194672821)
(job 114634610935, backend 931.15s) passed the same complete counts and all 18 steps on attempt 1,
at that exact merge/tree/parent pair. No CI rerun, forced merge, branch/worktree deletion or
optional public-comment retry was performed. These gates supersede preparation-time pending
statements without erasing failed receipts. Runtime `7a36ddde`, migration 0009 and accepted
design are unchanged; enabled process, physical isolation, deployment, operator migration and
live IdP/AWS/IAM/secret/production operations remain unproved and unauthorized.

### 8B3.2 analysis preflight — 2026-10-11

Only after PR #62 exact-main acceptance, clean local main was ordinarily fast-forwarded to
`01db441d` and scoped branch `codex/sprint-8b32-preflight` created. All prior 70 local branches,
three worktrees and unrelated parent skill files are preserved; the single new branch makes 71.
The [8B3.2 preflight](../../sprint-8b32-preflight.md) maps signed routes and callers, approval/
admission/history services, driver/adapter, coordination/audit persistence, evidence/findings,
existing signed/seeded fault tests and deterministic test seams.

Its test-only matrix covers pre-intent authority/evidence failures, competing/reclaimed owners,
real PostgreSQL expiry/governance/revocation lock waits, actual one-attempt ambiguous transport,
death/result-persistence uncertainty, late receipt and read-only restart, global readback limits,
sticky target/actual capacity retention, and signed READ/replay/denial with immutable history.
Existing seven signed journeys and all protected tests remain strict. Shared domain clock,
explicit revocation audit accounting and separate lock-holder transactions avoid test-only
authentication bypass, relaxed assertions or false transaction proof. No runtime, schema,
credential, endpoint, dependency, CI or frontend change is predicted.

No new design decision is identified. Standing accepted-design authority permits the bounded
test implementation after the recorded analysis; any required new design still stops for approval.
This checkpoint contains analysis/owner documentation only, not implemented fault tests or fresh
whole-slice acceptance. 8B3.2 remains PLANNED until implementation begins; 8B3.3/8C--8E and Sprint
9+ have not started. Whole Sprint 8 remains active and incomplete. Targeted documentation checks
are followed by targeted/new plus full PostgreSQL regression, exact existing-reviewer review,
both final-head CI runs, guarded ordinary merge and exact-main CI for implementation acceptance.

### 8B3.2 test-only implementation entry — 2026-10-11

The recorded preflight identifies no new design choice. Under standing accepted-design workflow
authority, 8B3.2 is now IN PROGRESS for the complete bounded matrix, not accepted or COMPLETE.
Its analysis-only checkpoint passed 17 targeted current-status contracts in 0.25s, Ruff lint,
420-file formatting and whitespace; the existing nonfatal native Python launcher location warning
remains. These are documentation checks only, not fault/runtime/full-regression acceptance.
The current status table, ROADMAP, README and their status guard are updated atomically at entry.
Implement only test helpers/wrappers and owning receipts; preserve existing strict assertions.
Runtime/schema/API/authentication/credentials/scanner behavior remain unchanged. No 8B3.3,
8C--8E, live operation or Sprint 9+ work starts. Full-slice acceptance still requires every
preflight family and all targeted/full/integration/review/CI/merge/main gates.

### 8B3.2 local fault candidate and targeted checks — 2026-10-11

The test-only candidate adds `tests/worker_fault_http.py` and thin API/PostgreSQL wrappers.
It creates all human authority/revocation via signed production-mode HTTP, shares only domain
time through the existing constructor clock, and retains real JWT verification, worker SQL,
ECS-only factory, SDK serialization/transport/parsing and public READ/replay. Every transport
is intercepted; unexpected destinations/operations/attempts and host AWS files fail. Existing
seven signed cases remain unchanged. The shared history assertion retains its exact two-audit
default and accepts an explicit third REVOKE audit only with exact actor/content validation.

New combined cases cover expiry/revocation/governance/newer evidence, read failures/budget,
changed preconditions, one SDK/wire enable for timeout/503/malformed/invalid XML, death before/
inside dispatch, acknowledgment rollback/lost committed return, late dispatch/receipt, fenced
reclaim, global readback poll/window limits, post-intent revocation and actual 32-slot capacity.
The PostgreSQL wrapper additionally has real competing-claim and expiry/governance/signed-revoke
Resource lock barriers after the adapter read returns. No external test lock spans worker AWS I/O.
All relevant phases retain signed READ/list/replay/denial, paired audit/private-field checks and
full protected persistence comparisons. Deliberate offline evidence/governance fixture work is
separate from worker effects. No runtime/schema/API/security/credential/default change is made.

Initial targeted runs stopped on new harness errors: nonexistent audit `created_at` (1 failed),
worker-only `polls` accessed on v1 admission (16 passed/1 failed in 32.30s), and the capacity
test's incorrect `error` envelope instead of accepted `detail` (20 passed/1 failed in 40.42s).
Each was corrected in test code without weakening assertions or changing runtime; no failed
receipt is waived. Exact owned temporary SQLite paths were removed after every run.

Fresh corrected targeted validation passed 46 cases in 71.87s: all 22 new SQLite fault cases,
the seven protected signed-worker cases and 17 current-status contracts. Ruff lint, 423-file
formatting and whitespace passed. Native launcher location warnings remain nonfatal and are
not runtime repairs. All 489 other tracked hashes, 71 branch refs, three worktrees and the three
unrelated parent skill hashes are preserved; no temporary task SQLite directories remain.
These results do not prove new PostgreSQL races or complete regression. Fresh targeted/full
disposable-PostgreSQL, Compose/image, independent review, both final-head CI, ordinary guarded
merge and exact-main gates remain pending. 8B3.2/8B3/Sprint 8 remain IN PROGRESS, not accepted;
8B3.3/8C--8E and Sprint 9+ have not started. No enabled-process, physical-isolation, deployment,
operator migration or live AWS/IdP/IAM/secret/production authority is inferred.

### 8B3.2 fresh local full validation — 2026-10-11

The unchanged validator ran against its own loopback/tmpfs PostgreSQL 16 and an explicit,
freshly generated TEST_DATABASE_URL, never an operator database. Targeted new/affected signed
API/PostgreSQL/worker/SDK/authorization/history/contracts passed all 363 cases in 363.74s,
then Ruff lint/423-file formatting passed. Complete `python -m pytest` passed all 3,323 cases
in 1582.87s with no skips. All 474 PostgreSQL cases across 25 files passed; each protected
24-file/448-case count matches accepted PR #61, with 26 new combined fault/race cases added.
The 49 additional collected cases are 22 new SQLite journeys, 26 new PostgreSQL journeys and
one automatic Markdown-link check for the new preflight. The 19 existing warnings remain
SQLite datetime-adapter deprecations, not new faults or waived assertions.

Whitespace, quiet Compose and the fresh image build passed; validator/wrapper exit was 0.
The exact owned database and temporary subtree were removed; read-only follow-up found zero
validation-labeled containers and no task SQLite/validation temporary directories. All eleven
candidate hashes and 487 other tracked hashes matched before/after the frozen run. Fresh remote
main remains accepted `01db441d`; all 71 local branch refs, three worktrees and three unrelated
parent skill hashes are preserved. No user data, branch, worktree or operator database was removed.

Actual immutable image
`sha256:47b00d9a5a7d0fb0852adfff53ad78278c25ca70bd32bc91bf776d68dcfae500`
contains exact README SHA-256
`70a338da970fa813dc9d914189ce5f19cfa1c59344080fead127f8ae3da5d57d`.
Networkless, read-only, unprivileged ephemeral probes without host mounts, credentials or
database verified Python 3.12.15, boto3/botocore 1.43.111 and WORKER_DISABLED/exit 0. These are
packaged-version/README/default-off checks, not enabled separate-process, physical isolation,
deployment, operator migration, attributed verification or live AWS/IdP/IAM/secret evidence.
No manifest, application, schema, API, authentication, credential, frontend or CI source changed.

Only owning result receipts are reconciled after this frozen run; tested source and README stay
unchanged. Final documentation/quality/whitespace checks, exact-commit existing-reviewer review,
both final-head CI suites including frontend/browser regression, guarded ordinary merge and
exact-main CI remain required. 8B3.2/8B3/Sprint 8 remain IN PROGRESS, not accepted/COMPLETE;
8B3.3/8C--8E and Sprint 9+ have not started. Native Firefox launch and the local picker/navigation
limitations remain retained, and optional public-comment retry is not authorized or performed.

### 8B3.2 failed independent review and bounded test repair — 2026-10-12

The scoped eleven-file candidate was frozen at `1f40aa9a4cb92a4a231ff84116bc90139f110260`,
tree `6b54c192b99c6b43e93357977bb71915eb0a551f`, sole parent accepted `01db441d`.
Final receipt checks passed 99 contracts in 2.80s, Ruff/423-file formatting and whitespace;
the known nonfatal native launcher warning remains. Commit/index/worktree were clean; all
other 70 refs, three worktrees and unrelated parent skills were preserved. It was not published.

The existing independent reviewer returned REVIEW_FAIL with three MEDIUM validation defects:
the newer-assessment case actually persisted equal-time evidence, PostgreSQL governance audit
rebaselining after worker completion absorbed unrelated effects, and capacity rebaselining after
denial absorbed original-finding timestamp/unrelated audit changes. These are test-guard defects,
not production/runtime defects or a new architectural decision. No acceptance gate is waived.

Independent ordinary checks passed 255 cases in 67.32s (22 new SQLite faults, seven protected
signed cases, 127 SDK cases, 99 contracts), plus all 33 PostgreSQL cases in 178.36s (26 new and
seven protected) on the reviewer's sole loopback/tmpfs PostgreSQL 16.15. Ruff/423-file formatting,
committed whitespace and historical-plan preservation passed. Root's full 3,323/474-PG and
image results above are carried, not independently rerun; normal passes do not close the findings.

Three negative in-process probes independently confirmed false positives: equal-time-only
detection still passed the supposed newer case (1.51s); an original-finding last_detected_at
change plus unrelated SCAN_STARTED at the 503 capacity boundary still passed (14.78s); an
unrelated worker SCAN_STARTED at governance NO_WRITE still passed (3.99s). These expose guard
failures, not additional acceptance passes. Each probe emitted one already-imported AnyIO rewrite
warning, distinct from normal acceptance warnings. All eleven/487 fingerprints, normalized blobs,
71 refs, three worktrees and parent skill hashes stayed unchanged. The exact reviewer-owned
database and both UUID temporary subtrees were removed; no user resource was deleted.

Standing accepted-design workflow authority covers this bounded test-only correction: prove
strictly newer persisted timestamps and exact STALE_TARGET while preserving a distinct equal-time
case; extend the original governance audit baseline with only its two known fixture additions;
compare complete before/after admission state so failed admission permits no change; separate
trusted source fixture deltas from signed RPC effects; and add explicit negative guard regressions.
Do not alter accepted services, authentication, schema, actions, credentials, recovery or success.

Fresh targeted, Ruff/format, complete disposable-PostgreSQL, Compose/image and exact repair review
are required before publication. Retain the failed candidate/probe receipts and use a new logical
repair commit without amend/reset/discard. 8B3.2/8B3/8B/Sprint 8 remain IN PROGRESS, not accepted;
8B3.3/8C--8E and Sprint 9+ have not started. No new reviewer, live operation, deployment, operator
migration, optional public-comment retry or production authority is granted by the repair.

The first repair-focused SQLite run stopped at a new exact-delta test assumption (1 failed in
1.99s): execution admission stores idempotency in its execution row, not another proposal/
approval request-ledger row. Source inspection confirmed the accepted behavior; the guard now
requires exactly two authority ledger additions and the distinct execution/journal additions,
without weakening any invariant or changing runtime. Its exact owned UUID temporary subtree
was removed. Fresh corrected checks passed 131 cases in 95.59s: 25 new/repaired SQLite cases,
seven protected signed journeys and 99 contracts. This includes genuinely newer/equal-time
cases and regressions requiring rejection of weakened detection and injected denial effects.
New PostgreSQL governance/audit and matching negative regressions remain unvalidated here;
fresh targeted/full PostgreSQL, quality, Compose/image and exact repair review are still required.

### 8B3.2 corrected full validation — 2026-10-12

The same fresh validator completed without restart against its sole loopback/tmpfs PostgreSQL 16,
with its own explicit TEST_DATABASE_URL and isolated SQLite paths, never an operator database.
The repaired focused selection passed 370 cases in 462.65s, followed by Ruff lint and 423-file
formatting. Complete pytest passed all 3,330 cases in 1680.03s without skips. The 19 warnings
remain the existing SQLite datetime-adapter deprecations; no failure or assertion was waived.

All 478 PostgreSQL cases across 25 files passed. Each protected 24-file/448-case count matches
accepted PR #61; the new fault file contributes 30. The new SQLite file contributes 25, and the
new preflight contributes one Markdown-link case: 56 additional cases over accepted 3,274.
These include five explicit negative guard regressions across SQLite/PostgreSQL. Strictly newer
and distinct equal-time evidence, exact governance fixture additions and complete failed-admission
state checks passed; independent review must still confirm the three MEDIUM findings are closed.

Whitespace, quiet Compose and the fresh image build passed; validator/wrapper exit was 0.
The exact owned database and UUID temporary subtree were removed. Read-only follow-up found
zero validation-labeled containers and no owned SQLite/validation temporary directories. All
eleven frozen candidate hashes and 487 other tracked hashes matched before/after the full run.
All 71 expected local branch refs, three worktrees and unrelated parent skills were preserved;
fresh remote main remains accepted `01db441d`, with no existing PR for this candidate branch.
No user data, branch, worktree or operator database was removed.

The actual immutable fresh image is
`sha256:b40eedba19687b1e6bbb447ead69a47dbd51b76fae5c579a68378cd343534486`.
Networkless, read-only, unprivileged ephemeral probes without host mounts, credentials or database
verified Python 3.12.15, boto3/botocore 1.43.111, exact packaged README SHA-256
`70a338da970fa813dc9d914189ce5f19cfa1c59344080fead127f8ae3da5d57d`, and WORKER_DISABLED/exit 0.
These do not prove enabled separate-process or physical isolation, deployment, operator migration,
attributed verification, or live AWS/IdP/IAM/secret behavior. Runtime, migration 0009, interfaces,
authentication, scanner credentials, dependency manifests, frontend and CI source stay unchanged.

Only owning result receipts change after this frozen run; tested source and README stay unchanged.
Final contracts/quality/whitespace, a new logical repair commit and exact existing-reviewer review,
both final-head CI suites including frontend/browser regression, ordinary guarded merge and exact
main CI remain required. Retain the failed candidate and all diagnostic receipts without amend,
reset or discard. 8B3.2/8B3/8B/Sprint 8 remain IN PROGRESS, not accepted or COMPLETE; 8B3.3/8C--8E
and Sprint 9+ remain unstarted. Native Firefox launch and local picker/navigation limits remain;
no optional public-comment retry, live operation or production authorization is inferred.

### 8B3.2 failed exact main and browser repair preflight — 2026-10-12

The corrected test candidate `0f34006394b4fca56d6aed350567247a0ca42c3f`, tree
`1f9eaf3692e82440c9475ea15ecac73b1a8e2386`, received exact-head independent REVIEW_PASS:
all three MEDIUM guards closed, no new actionable findings. Independent normal checks passed
258 SQLite/contract/SDK cases in 91.90s and 37 PostgreSQL cases in 250.41s. Each original adverse
diagnostic now failed at the intended strengthened guard; those intentional failures are not
normal acceptance failures and the original failed review remains retained.

Both first-attempt candidate CI runs passed complete primary-log checks: push 38211966967
(job 114687932198; backend 1775.03s) and PR 38212044406 (job 114688170968; backend 1792.70s).
Each passed all 3,330 backend tests with 19 existing warnings, 478 PostgreSQL cases across 25
files without skips, 133 frontend tests across seven files, 74 Chromium/Firefox journeys,
423-file Ruff formatting, image, cleanup and all 18 steps. The PR checkout was synthetic
`0b54ddd7d151976eb0aff8e1a933f7be256fffd3`, with the exact reviewed tree and parents accepted
`01db441d` plus `0f34006`. CLI progress watchers ended with TLS handshake errors; the underlying
same first attempts completed successfully, without a CI rerun or waiver.

[PR #63](https://github.com/jnc247s/cloud-security-automation/pull/63) merged ordinarily with the
exact-head guard at 2026-10-12 07:00:42 UTC. Actual merged-main
`59bb9c9b294e2b18aae20fd5d6f7297d3ab2832a` retains tree `1f9eaf3` and parents `01db441d`/`0f34006`.
Exact-main first-attempt [CI 38215419817](https://github.com/jnc247s/cloud-security-automation/actions/runs/38215419817),
job 114698895732, FAILED. Backend 3,330/1625.40s, all 478 PostgreSQL cases and frontend 133 passed.
Browser results were 37 Chromium plus 36 Firefox passes and one Firefox failure; workers one,
retries zero. `shell.spec.ts:50` failed its line-73 RUNNING lifecycle assertion after Open scan,
with the existing 5,000ms timeout. The image step was skipped and cleanup passed. No diagnostic
artifact was retained by that run. No acceptance or closeout is inferred from the successful
candidate runs or merge, and no blind rerun is authorized by these receipts.

The failure was investigated without editing the reviewed tree. A tracked-only archive excluded
untracked files, host credentials, `.git`, operator databases and parent skills. An owned Linux
image used Playwright 1.63.0/Firefox build 1543, Node 24.19.0, pnpm 11.19.0 and Python 3.12.3;
the Python patch version differs from the earlier installed-image probe, so this is diagnostic
evidence, not a replacement exact-main or production-image receipt. Real test login/BFF/bearer
checks and a fresh migrated tmpfs PostgreSQL 16 ran on an internal network. Boto clients remained
forbidden, no authentication dependencies were overridden and no host credential mount existed.
Browser preferences, original actions/assertions and timeouts were unchanged. Source and a
renamed original test copy had identical SHA-256 `c360c4c18301eec56606ea796c0b2360c316dc58eee6d858eb0b51af56bb75b4`.
Two observed replays passed in 15.9s: pagination completed before native selection, both exact
detail/posture responses were 200 and schema-valid, and RUNNING/FAILED rendered. These passes
do not reproduce or waive the failed CI case. Bounded probes logged only synthetic transition
categories and scan data, never cookies, tokens, headers, secrets or raw payloads.

A separate controlled route gate returned the real authorized history response at two different
pointer boundaries. Both used a diagnostic-only 250ms mouse dwell to separate down/up, not a
production change or an accepted test repair. Release before pointer-down passed; release after
pointer-down failed the unchanged 5,000ms RUNNING assertion (one pass/one failure, 17.5s).
The latter retained the correct input but `scan=latest`, with no submit, no detail/posture reads
and no session loss. History repopulation moved Open scan after pointer-down. This demonstrates
a lost-click mechanism capable of the symptom, not the actual artifact-free historical cause.
All owned test containers, databases, internal networks and in-memory credentials were removed.
All 498 tracked hashes, 71 local branches, three worktrees and parent skill hashes remained intact.
The initial image probe lacked venv/ensurepip; only the disposable image received the required
package. Native dashboard checks also stopped at sandbox path access and then the installed
pnpm 11.25.0 mismatch; no global tooling, engine guard or dependency pin was changed or waived.

The existing independent reviewer supports a bounded test-only settlement repair under standing
accepted-design authority, not REVIEW_PASS for unimplemented source. It must correlate a new
exact GET history request to the pagination action, reject old matching responses, require 200,
`isPage`, limit 25/expected offset/bounded item count, then await the exact ordered rendered UUID
list and removal of the history loading indicator. Native clicks, original lifecycle/navigation/
security checks, both browsers, existing timeouts and zero retries remain. A held-response
regression must establish actual interception and prove no helper completion, selection or scan
reads before release; after release it must require settlement and original RUNNING assertions.
Its gate must always release on failure. No forced click, sleep, timeout increase, retry, relaxed
assertion, auth bypass or runtime change belongs to the repair.

The clean new branch `codex/sprint-8b32-browser-repair` starts from freshly fetched remote main
`59bb9c9b`, not an assertion that the failed merge is accepted. Local accepted `main` stays at
`01db441d`, the prior feature branch stays at `0f34006`, and all 71 pre-existing branches and
three worktrees remain. This repair adds one branch and touches only browser-test helper/caller
and owning status/receipt documentation. Targeted browser, complete pinned frontend/browser,
Ruff/whitespace, complete backend/disposable-PostgreSQL, Compose/image, exact independent repair
review, final-head CI, guarded ordinary merge and exact-main CI are still required. Until then
8B3.2/8B3/8B/Sprint 8 remain IN PROGRESS, with 8B3.3/8C--8E PLANNED and Sprint 9+ unstarted.

The observed application pagination/layout race remains an unfixed user-interaction limitation;
test settlement is not a UI repair. Revisit it with the separately scoped 8D dashboard preflight,
alongside the user's still-untriaged picker/back-navigation report. Its eventual application
behavior/design cannot be silently chosen here. Historical CI attribution remains unconfirmed;
future failures must be diagnosed at their actual boundary rather than relabeled as this race.
No live AWS/IdP/IAM/secret operation, deployment, operator migration, production change, optional
denied public-comment retry or later-sprint implementation is authorized or performed.

### 8B3.2 browser repair local targeted and browser validation — 2026-10-12

The bounded test helper and shell caller now implement the preflight's exact new-request,
response-shape/limit/offset and ordered rendered-page guards. Both original pagination clicks
are still native; all original lifecycle/navigation/security assertions remain. The new held
response case proves no helper completion, subsequent selection or exact detail/posture request
while the real signed history response is held. Release then requires the exact current page,
RUNNING availability text and both exact scan reads. Cleanup always releases the gate.

Pinned Linux checks passed typecheck, lint, all 133 client tests in seven files and the frontend
build. Targeted modified lifecycle plus held-response regression passed four cases across both
Chromium and Firefox in 14.9s. A fresh disposable fixture then passed the full 76-journey browser
suite in 1.6 minutes, including the original 74 journeys and the new case in both projects, with
one worker and zero retries. Its aggregate result and terminal exit 0 are retained; the local
console transport truncated some individual progress lines, so this is not an individually
enumerated 76-line primary-log audit. Future exact-head/exact-main CI must supply complete logs.
All owned databases, test containers, networks and in-memory credentials were removed again.

The browser image tested exact shell SHA-256
`ae566f3d4d7ff3da8e6b2c4cefe0a8a557ebc1fa48c9219ebef666e4ed64f5df` and helper SHA-256
`a3a94f1585a72c07f634a20495e1e6f7f2abcd97d6e06c9a4394ba7326c5fcc8`; only those two test
files were overlaid on the reviewed tracked-source image, with temporary diagnostic wrappers
removed. Application/browser configuration, dependencies, authentication and fixture remain
unchanged. These local passes do not waive failed exact-main CI or prove a repaired user layout.
Complete fresh backend/PostgreSQL, Ruff/whitespace, Compose/image, exact repair review and all
delivery/main-CI gates remain pending. No acceptance, closeout, live operation or later slice
is inferred. Changes are limited to two browser-test files and four owning Markdown files.

### 8B3.2 resumed cleanup repair and fresh validation — 2026-10-12

The user explicitly authorized starting Docker and resuming the full Sprint 8 goal, with ordinary
approved workflow automatic and only new architectural/design decisions escalated. This does not
authorize live AWS, IAM/secrets, deployment, operator databases, production or Sprint 9+. Docker's
Linux engine was available at the resumed check (29.5.2); an existing Desktop process was reused,
not duplicated. No old validation process, test container or owned test network remained. The two
unrelated stopped containers, all 72 branches, three worktrees and parent skills were preserved.

The prior local full-regression handle was unavailable and its final result could not be verified.
Earlier observed pass markers, including all 478 PostgreSQL cases, are not a completed full-run
receipt. No partial checkpoint is reused as success; fresh validation is required. The historical
exact-main Firefox failure, diagnostic timing limits and unfixed UI layout race remain unchanged.

Preliminary independent source inspection of the six-file frozen repair found one LOW issue in
the held-response test: `page.unroute` rejecting in `finally` could replace the original body
assertion. Other response/DOM guards, native clicks, original assertions and honest documentation
were sound. This was not an immutable-commit REVIEW_PASS, and no tests were run by that reviewer.
A networkless, read-only source-fragment probe of exact pre-fix shell SHA `ae566f3d` confirmed four
error combinations: success, primary-only and cleanup-only were correct; both errors reported
cleanup instead of the primary. Gate release and cleanup attempt occurred once in every case.
This proves source error propagation, not a browser failure or historical CI cause.

`runWithHistoryCleanup` is a private test helper, not application/runtime policy. It captures the
body outcome, always attempts cleanup, then rethrows the original failed value or, after a
successful body, the cleanup error. Both failures emit only a fixed secondary classification;
even diagnostic failure cannot replace the primary. Boolean failure markers preserve falsy thrown
values without converting them to success. The caller's gate release, journey handling, route
cleanup and every original assertion stay intact. Six permanent unit cases cover all these paths;
five falsy values are checked within the sixth case. Scope is three test files plus the four
owning Markdown files, with no application, schema, API, authentication, dependency, configuration,
browser security preference, credential or CI change.

The initial attempted guard's throw in `finally` correctly failed ESLint `no-unsafe-finally` before
tests. No rule was suppressed; the corrected guard defers propagation until after cleanup without
throwing from `finally`. Corrected pinned typecheck, lint, six cleanup unit cases and frontend build
passed. The affected original lifecycle plus held-response journeys passed four cases across both
Chromium and Firefox in 16.0s, with one worker/zero retries. Complete sanitized logs are saved only
in the owned ignored diagnostic directory; all its temporary databases/containers/networks were
removed. These receipts replace no historical failed attempt and are not full acceptance.

Fresh full pinned frontend/browser, complete native backend/disposable-PostgreSQL, Ruff/whitespace,
Compose/image, exact independent repair review, final-head CI, guarded ordinary merge and exact
merged-main CI remain required. Expected frontend total is 139 across eight files; browser total
remains 76. Backend 3,330/25-file PostgreSQL 478 and 423-file Ruff expectations are unchanged.
No full result, commit, publication, merge, acceptance, closeout or later slice is inferred here.

### 8B3.2 resumed cleanup repair full local receipt — 2026-10-12

Fresh pinned frontend validation passed typecheck, lint, all 139 unit cases across eight files,
build and all 76 browser journeys in 1.9 minutes. The saved primary log contains every unique
case index 1--76, with 38 Chromium and 38 Firefox passes; one worker, zero retries and no skips.
The complete local log SHA-256 is `abb1c25d005c7ae6f0c6b042f9a16a88c4907e92c38daef67287b799bed66e41`.
This post-cleanup-fix result replaces no historical failed attempt and requires no CI rerun.

Fresh native validation completed with exit 0 on Python 3.14.5/pytest 9.1.1/AnyIO 4.14.2, using
the unchanged repository runner and its own loopback/tmpfs PostgreSQL 16 URL, never an operator
database. Focused contracts passed 99 cases in 0.44s, followed by Ruff and 423-file formatting.
Complete pytest passed 3,330 cases in 1794.79s; all individual case markers are retained and
audited as passes. All 478 PostgreSQL cases across 25 files passed without skips: the protected
24-file/448-case expectations matched, plus 30 fault cases. The 19 warnings remain the existing
SQLite datetime-adapter deprecations, not suppressed errors. Whitespace, Compose and fresh image
build passed; the exact owned database was removed and the runner's final success marker was
retained. The complete local log SHA-256 is `9956a79a4c9f6d7ca096d5ed5cc51c0789a5aada53beeb4f2e30ca1dd2768efe`.

Read-only follow-up found only the two preserved unrelated stopped containers, no validation/
diagnostic containers or owned internal network. All 500 frozen hashes, 72 branch refs, three
worktrees and parent three skill hashes matched before/after. The seven scoped files are three
tests and four owning Markdown files; the other 493 files are unchanged. No user data or existing
branch/worktree was removed. The prior unavailable native run remains unverified, not retrospectively
accepted by this fresh result.

The actual built image is `sha256:dbfe8befe3c7618990debdecfe0ec646ac700121719c1f6e4085b98a35eb00b9`.
Networkless, read-only, non-root probes without mounts, credentials or database confirmed Python
3.12.15, boto3/botocore 1.43.111, packaged README SHA-256
`70a338da970fa813dc9d914189ce5f19cfa1c59344080fead127f8ae3da5d57d` and WORKER_DISABLED/exit 0.
Frontend output assets remained unchanged. These do not establish enabled separate-process or
physical isolation, live AWS/IdP/IAM behavior, deployment, operator migration or verification.

Only result receipts change after this run; tested source remains frozen. Final lightweight
contracts/quality/whitespace, a logical scoped commit, immutable-commit independent review by one
necessary replacement reviewer (the old reviewer is unavailable), both candidate CI runs, guarded
ordinary merge and exact-main CI remain required. Source diagnostics/normal passing unit tests
are evidence for the LOW repair, not an independent closure verdict. 8B3.2/8B3/8B/Sprint 8 remain
IN PROGRESS; 8B3.3/8C--8E stay PLANNED and Sprint 9+ unstarted. No live operation is authorized.

### 8B3.2 accepted combined fault tests and cleanup repair — 2026-10-12

The complete bounded [fault/recovery matrix](../../sprint-8b32-preflight.md) is accepted through
PR #63 and its browser-test/cleanup repair [PR #64](https://github.com/jnc247s/cloud-security-automation/pull/64).
This supersedes the prior current-state pending gates, not dated preparation predictions or
failed receipts. **8B3.2 is COMPLETE** as test-only acceptance; 8B3/8B/Sprint 8 remain IN PROGRESS.
8B3.3/8C--8E remain PLANNED and Sprint 9+ is unstarted. Runtime baseline `7a36ddde`, accepted
migration `20261008_0009`, catalog/profile defaults and all operator boundaries are unchanged.

The corrected signed fault suite received exact-head REVIEW_PASS at `0f34006`; its source is
unchanged by the browser repair. The one necessary replacement reviewer returned immutable-head
REVIEW_PASS at `34a40d5ef36432d3105187c792d3e972e4321098`, tree
`6c5638db7ec1230653d332ba334c73e06897b6f7`, parent `59bb9c9b`, with no actionable findings.
All three original MEDIUM guard findings remain closed; the preliminary LOW primary-error
masking issue is independently closed. The reviewer ran six cleanup unit cases in 1.94s and
four affected browser journeys in 15.0s, using the immutable pinned image and unchanged browser
configuration, one worker/zero retries/no skips. Typecheck/lint/build passed. The reviewer also
audited the root's complete full-run hashes, all 3,330 backend markers and all 76 browser rows;
that is an independent log audit, not another independently executed full backend suite.
Independent targeted-log SHA-256 is `ee5ed31265320133591651ef3f42a2807d699d438dc463ad75030e26d10d3834`.

Both first-attempt repair-head CI runs passed. The PR tested synthetic merge `37a9aa10817c3d54879d2874e5e660a1d99e7a98`,
with exactly the reviewed tree and parents `59bb9c9b`/`34a40d5`. Fresh PR/head/base/check/settings
guards preceded the ordinary exact-head merge, without admin bypass, force push or branch deletion.
The delivered merge `9c3df3256f81edf85a262b55b949c38b43d6d226` has that same tree and those
parents; first-attempt exact-main CI passed. Complete provider logs, checkout SHAs, individual
backend/browser cases and all terminal quality/image/cleanup steps were audited.

| Verified first-attempt CI | Backend result | Other complete gates |
| --- | --- | --- |
| [Push 38290690632](https://github.com/jnc247s/cloud-security-automation/actions/runs/38290690632) | 3,330 passed / 19 existing warnings / 1636.47s | All 478 PostgreSQL cases in 25 files, no skips; 139 frontend cases/eight files; 76 browser journeys (38 Chromium/38 Firefox), one worker/zero retries; Ruff/423-file formatting, image/cleanup and all 18 steps |
| [PR 38290762618](https://github.com/jnc247s/cloud-security-automation/actions/runs/38290762618) | 3,330 passed / 19 existing warnings / 1569.16s | Same complete gates |
| [Exact main 38294459508](https://github.com/jnc247s/cloud-security-automation/actions/runs/38294459508) at 9c3df32 | 3,330 passed / 19 existing warnings / 1835.07s | Same complete gates |

The protected 24-file/448-case PostgreSQL counts match, plus 30 fault/race cases. The 19 backend
warnings are the existing SQLite datetime-adapter deprecations; none were suppressed. All seven
approved fault families are covered, with signed authority/denial/replay, actual one-send ceilings,
durable intent and paired audit, conservative recovery, strict evidence/governance/capacity guards
and unchanged findings/technical data. Passing receipts do not waive failed main `59bb9c9b`.
Its artifact-free Firefox cause remains unconfirmed; the separately demonstrated pagination
layout/pointer race remains unfixed for 8D, alongside the untriaged scan-picker/navigation report.
The interrupted old native result remains unverified. No live or physical isolation, enabled
installed-process, deployment, operator migration or rescan-attribution proof is inferred.

### 8B3.2 documentary reconciliation entry — 2026-10-12

Only after successful exact-main audit, clean local main was normally fast-forwarded from
`01db441d` to `9c3df32`, then `codex/sprint-8b32-closeout` was created for five owning Markdown
files and the matching current-status contract. The prior 72 branches are preserved, with only
the accepted main advance and one new scoped branch; all three worktrees and unrelated parent
skill files are preserved and excluded. No application, schema, credential, API, authentication,
frontend, dependency or CI change belongs to this reconciliation. Historical headings/receipts
remain addressable; only current status and acceptance context change.

Targeted contracts, Ruff/format/whitespace, fresh full disposable-PostgreSQL regression,
Compose/image, immutable-head independent review, both first-attempt candidate CI runs, ordinary
guarded merge and green exact-main CI remain required for this closeout before 8B3.3 preflight.
The Sprint 8 plan remains active; Sprint 8/8B/8B3 stay IN PROGRESS. No 8B3.3/8C--8E implementation,
live AWS/IdP/IAM/secrets, operator database, deployment, production operation or Sprint 9+ work
is started or authorized here.

### 8B3.2 documentary closeout local validation — 2026-10-12

The frozen six-path reconciliation passed 99 targeted contracts in 0.43s, Ruff and 423-file
formatting, then all 3,330 backend cases in 1623.43s with 19 existing SQLite datetime-adapter
warnings and no skips. The complete saved primary log accounts for all 150 test files and
all 478 PostgreSQL cases across 25 files; every protected 24-file/448-case count matches, plus
the 30 fault/race cases. Whitespace, Compose configuration and fresh image build passed.
The unchanged validation runner exited 0, removed only its owned disposable database and retained
its final success marker. Primary-log SHA-256 is `adab60548c273bf7e52778c006e3b64d7c2b6d12b6564273dc09b5949ededdb2`.

The same native interpreter reports Python 3.14.5 and boto3/botocore 1.43.87; the full-run header
records pytest 9.1.1/AnyIO 4.14.2. The separately built immutable image
`sha256:25e16176c7e431792d6f1cac197a8046bd07dcaea0aabbcf361f6c104a68df15` resolved
Python 3.12.15 and boto3/botocore 1.43.112 within unchanged dependency ranges. Non-root UID 100,
networkless, read-only probes without mounts, credentials or database verified the built-in
encryption/key/STS output-model shapes, packaged README SHA-256
`ef1fac350bd2a826c2669ced864d1b481a7bf3eb7b17a1028ac209f853aebc19`, and
WORKER_DISABLED/exit 0. Model/default-off probes are not a full regression under the image's
resolved SDK, enabled installed-worker/process proof, physical isolation or live operation.
Final-head CI still must run the full backend/client/browser/image pipeline in its own environment.

All 500 frozen file hashes, 73 branch refs, three worktrees and three parent skill hashes matched
before/after validation. The two unrelated stopped containers and pre-existing networks remained
preserved; no test database or probe container remained. Only this result receipt changes after
the run; tested source and packaged README stay frozen. No user data or branch/worktree was removed.

Final receipt contracts/quality/whitespace, a logical scoped commit, immutable-head independent
review, both first-attempt candidate CI runs, ordinary guarded merge and green exact-main CI
remain required for documentary acceptance before 8B3.3 preflight. No reviewer clearance,
publication, merge or next-slice work is inferred from these local passes. Sprint 8 remains active
and IN PROGRESS; later slices and live/production operations remain separately gated.

Final receipt checks passed 99 contracts in 2.68s, Ruff/423-file formatting and whitespace.
The existing native launcher warning about the installed Python-core location remained visible;
the interpreter and all checks completed successfully. No warning, assertion, skip or security
boundary was suppressed. Only the active-plan result receipt differs from the full-run freeze.

### 8B3.2 documentary acceptance and 8B3.3 analysis entry — 2026-10-12

The six-path documentary head `a050d70859be73320de2967fc1f9048422160e79`, tree
`b6d202329f11dbc76b02db72fb3a00c7083126bb`, received immutable-head REVIEW_PASS from the
existing reviewer with no actionable findings. Independent receipt checks passed 99 contracts
in 2.70s, Ruff/423-file formatting and whitespace; the complete local and prior repair/provider
logs were independently audited, not independently rerun as full backend suites.
Independent check-log SHA-256 is `ba442be889b79c664c418c9d412d28b117a87f46a804d30e24746a9ac52182ae`.

Both first-attempt candidate CI runs passed complete primary-log audits. The PR tested synthetic
merge `427a45f63e5f6aa9dce3154f6a74bb8ef61ad00e` with exactly the reviewed tree and parents
`9c3df3256f81edf85a262b55b949c38b43d6d226`/`a050d70`. Fresh exact head/base/check/settings and
preservation guards preceded ordinary [PR #65](https://github.com/jnc247s/cloud-security-automation/pull/65)
merge, without admin bypass, force push or branch deletion. Delivered merge
`489b047562005a766734e9b571f7e307f8506102` retains that same tree and parents; its first-attempt
exact-main CI passed and every individual backend/browser marker plus all 18 steps was audited.

| First-attempt CI | Backend complete result | Other complete gates |
| --- | --- | --- |
| [Push 38304816695](https://github.com/jnc247s/cloud-security-automation/actions/runs/38304816695) | 3,330 passed / 19 existing SQLite warnings / 1807.35s | All 478 PostgreSQL cases/25 files, no skips; 139 frontend cases/eight files; 76 unique browser indices, 38 Chromium/38 Firefox, one worker/zero retries; Ruff/423-file formatting, image/cleanup and all 18 steps |
| [PR 38305061535](https://github.com/jnc247s/cloud-security-automation/actions/runs/38305061535) | 3,330 passed / 19 existing warnings / 1580.96s | Same complete gates |
| [Exact main 38308762804](https://github.com/jnc247s/cloud-security-automation/actions/runs/38308762804) at 489b047 | 3,330 passed / 19 existing warnings / 1755.33s | Same complete gates |

All protected 24-file/448-case PostgreSQL counts match, plus 30 fault cases. Main's installed
CI interpreter was Python 3.12.15 with boto3/botocore 1.43.112; its actual built image is
`sha256:aacc010f98320d350518470d1d36cdef145767f3a842bae9152dd314e07635f3`.
Host CI regression and image build are not an enabled installed-process run or physical/live
isolation proof. The existing native SDK/environment distinction, launcher warning, unconfirmed
old Firefox cause, unfixed application layout race, untriaged picker/navigation report and old
interrupted native result remain unchanged. No failure or scope limitation is waived.

The first precommit freshness check had stopped before tests/staging/commit when read-only Git
transport reset. Normal provider API freshness proved the same base before the successful scoped
guarded commit; no full regression was restarted. One later MCP push-job status poll failed in
transport; re-polling that same handle confirmed terminal success. Neither observation failure
restarted/re-ran CI, and no optional denied public-comment retry was performed.

Only after complete exact-main acceptance, clean local main was normally fast-forwarded from
`9c3df32` to `489b047`, then `codex/sprint-8b33-preflight` was created for analysis. All 500
starting tracked hashes matched; 72 non-main branches and all three worktrees/parent skill hashes
were preserved. The only local ref changes are the accepted main advance and one new branch,
bringing the total to 74. Parent status remains only unrelated untracked `.agents/`, excluded.

The [8B3.3 preflight](../../sprint-8b33-preflight.md) inspects installed CLI/settings, real exclusive
provider/SDK, guard-first SQL/audit, signed HTTP helpers/callers, prior fault guards, complete
protected-state comparison, packaging/Compose, existing validation ownership and operator limits.
Recommend one complete test-only installed-image/separate-process/security acceptance slice.
First implement narrow owned test resources and the signed installed-process success/no-write
journey; then complete source/scope/configuration/leakage negatives and fresh-process conservative
recovery before whole-8B acceptance. Existing 8B3 scope already permits a mounted transport harness
before the unchanged module entrypoint; no production test mode, endpoint or packaging change.
No new product architecture/design decision is identified. Standing routine authority covers
accepted-design implementation; any required new boundary/policy/topology still needs approval.

Only ROADMAP, this active plan and the new preflight change at this analysis checkpoint.
8B3.3 remains PLANNED until test implementation begins; 8B3/8B/Sprint 8 remain IN PROGRESS.
No runtime/test/schema/API/credential/CI/frontend change, enabled worker, database/container
provisioning, new reviewer, commit/publication or later-slice work is performed by this analysis.
Physical/live IdP/AWS/IAM/secret isolation, deployment, operator migration and production operation
remain unproved and unauthorized. 8C--8E remain required and Sprint 9+ unstarted.

### 8B3.3 analysis validation — 2026-10-12

The three-path analysis passed 100 contracts in 2.92s, Ruff lint, 424-file formatting and
tracked/new-Markdown whitespace checks. The new preflight adds one automatically parametrized
documentation-link case in `test_markdown_links.py`; the 99 baseline contracts remain intact.
Formatting includes Markdown: verbose discovery confirms the new preflight path, explaining
423 -> 424 without a Python-source addition. All 370 lint-enumerated paths belong to the starting
baseline, including project metadata. The existing native Python launcher-location warning stayed
visible; every check exited successfully, with no skip, assertion or warning suppression.

Only a newly owned UUID analysis TEMP subtree was removed after resolved-path boundary checks;
cleanup preserves any primary validation failure. No database, container, image, application or
browser acceptance ran in this analysis. Those remain mandatory implementation gates, not implied
by baseline PR #65 success or lightweight document checks. The documentation skill keeps accepted
receipts separate from predictions/proof limits; PostgreSQL guidance keeps the proposed process
probes outside short consistently ordered worker transactions, without changing accepted intent.

### 8B3.3 test-only execution plan and implementation entry — 2026-10-12

The user requested continued full Sprint 8 goal work under standing routine authority. The
completed [8B3.3 preflight](../../sprint-8b33-preflight.md) identifies no new product design
decision. Fresh provider metadata reverified remote main `489b047` and its completed first-attempt
exact-main CI 38308762804 before implementation. Reuse `codex/sprint-8b33-preflight`, preserving
the three owned analysis Markdown changes, all existing branches/worktrees and parent skills.
8B3.3 is now IN PROGRESS, not accepted; 8B3/8B/Sprint 8 remain IN PROGRESS. The dated analysis
PLANNED checkpoint remains historical. README/current progress-contract callers update atomically.

Predictions for the one complete bounded slice:

- Add private UUID-owned Docker resource/process helpers, a narrowly mounted test-only harness,
  migrated disposable PostgreSQL and ordinary integration/guard tests. No production packaging,
  dependency, CI, application, schema or operator configuration change is planned.
- Start with ownership/cleanup guard regressions and the signed HTTP -> own migrated database ->
  unchanged installed module/real exclusive adapter/closed synthetic transport -> signed READ
  success and no-write journeys. Keep all seven existing key/precondition cases and strict
  identity, digest, audit, protected-table and no-start assertions.
- Complete every preflight source/scope/configuration/leakage family and separate-process
  unknown-effect recovery. Count real enable transports, prove committed intent and free SQL locks,
  validate installed source/runtime, fail on unarmed/unexpected/unused transport and corroborate
  process reports through independent retained history. Do not replace worker/auth/persistence.
- Use only exact owned internal-network/tmpfs database/worker resources, environment-only temporary
  passwords and narrow read-only harness/scenario mounts. Never use host networking, Docker-socket/
  host-credential mounts, arbitrary operator URLs or broader credentials. Preserve primary failures
  through cleanup; cleanup-only failure is not success.
- Run targeted new/affected tests, Ruff/format, complete configured PostgreSQL regression, exact
  image/Compose, full pinned frontend/browser gates, immutable-commit independent review, both
  first-attempt candidate CI runs, ordinary guarded merge and complete exact-main CI before 8B
  closeout or 8C preflight. Derive expanded counts from actual collection and full primary logs.

Only test/progress changes are authorized here. No new handler, production test mode, endpoint,
rescan, dashboard mutation, live AWS/IdP/IAM/secrets, deployment, operator migration or production
operation is authorized. Stop for any new architectural/design decision. A first passing helper
or process journey does not complete 8B3.3, 8B or Sprint 8; 8C--8E remain required and Sprint 9+
unstarted. Reuse the existing reviewer only after the complete candidate is frozen.

### 8B3.3 resource and mounted-harness construction checkpoint — 2026-10-12

Three private test files now implement the owned runtime, mounted transport observer and 49
resource/cleanup/environment guard cases. The controller verifies a local Linux Docker endpoint,
pins it across later environment changes, rejects remote/ambiguous targets, verifies exact names
and labels before removal, derives URLs only for its live owned schemas and keeps passwords out
of argv. Cleanup-only failure fails; body/start failures retain their original exception even if
cleanup or warning emission also fails. No Docker/database/image/process was provisioned yet.

The mounted harness invokes the unchanged installed module, uses the real adapter/SDK and
intercepts synthetic transport. It checks mandatory installed-source hashes, non-root runtime,
fixed clients/models/retries, independent six-coordinate PostgreSQL NOWAIT probes and committed
paired intent before enable, strict operation queues and sanitized output/proof separation.
Its process invocation helper accepts only owned URLs, narrow mounts and closed test inputs.
This is constructed code, not an executed installed-process acceptance result: the signed parent
journey, complete process/security/recovery matrix and whole acceptance remain pending.

The first focused run ended 11 failed/130 passed in 8.50s: an accidental indentation edit placed
URL parsing after a raise, so string endpoint guards raised UnboundLocalError. Correcting that
helper and adding endpoint/context negatives passed 148 in 2.78s. Initial harness lint correctly
found one import-order and seven long-line errors; they were repaired without rule suppression.
After endpoint pinning, current focused checks passed all 149 in 2.79s (49 new resource guards
plus 100 contracts), followed by Ruff/427-file formatting and whitespace. The existing native
launcher-location warning remains visible. No valid test/assertion was removed or relaxed.

No complete fresh regression, PostgreSQL/process/image/browser acceptance, independent review,
commit/publication/merge or 8B closeout is claimed. Runtime/schema/API/credentials/frontend/CI
are unchanged. This checkpoint does not shrink the preflight matrix or complete 8B3.3/Sprint 8;
standing workflow continues with the signed installed-process integration. All later-stage/live/
operator boundaries and historical UI/provider limitations remain unchanged.

### 8B3.3 initial process journeys and failed native regression — 2026-10-12

The signed parent now composes the real HTTP authority, its own migrated schema, unchanged
installed module and real exclusive SDK adapter, synthetic transport, independent committed-intent/
six-lock probes and authorized history/replay checks. All seven retained success/no-write key
contexts ran in fresh non-root containers; no live credentials or AWS operation were used.

The first process-focused attempt failed before any worker ran: 149 checks passed, seven setup
errors and one warning in 37.45s. The tested local Docker engine did not expose the PostgreSQL
loopback port on the internal-only network. A separate credential-free, owned probe confirmed
empty effective port bindings despite the requested loopback mapping. Its first cleanup guard
failed; fresh exact-name/JSON-label inspection then permitted removal of only that probe container
and network. This is not a general Docker regression claim or a passing process receipt.
The same attempt exposed Windows cp1252 decoding of captured Docker output. The private helper
now explicitly decodes UTF-8. Only its test database joins the ordinary bridge for loopback
publishing and the owned internal network under alias `pg`; worker containers remain internal-only.
This material test-topology difference supersedes the predicted internal-only database, not any
production topology, provider endpoint or credential boundary. Two permanent guards retain both
repairs. A standalone guard attempt passed 150 but had one setup error in 8.79s because the shared
pytest temporary directory was inaccessible; fresh workspace-owned TEMP/TMP was used thereafter.

The second unchanged validation attempt passed all 158 focused checks in 51.34s: 100 contracts,
51 resource guards and seven installed-process journeys. Ruff and 429-file formatting passed.
Its full run collected 3,389 tests and again passed all seven process journeys, then terminated
at 90% with a Windows native access violation while garbage-collecting during
`test_changed_precondition_never_dispatches_or_claims_success`. There is no full-suite summary,
warning total or successful full/image/Compose gate; validator exit was 1 and its outer disposable
database cleanup completed. The crashed pytest session did not run its process-fixture teardown.
Fresh exact-name/ownership-label checks authorized removal of only its remaining tmpfs database
and private network; unrelated stopped containers were preserved. Test data in these throwaway
resources is discarded; no operator database, persistent volume or user resource is removed.

Native versions were Python 3.14.5, Pydantic 2.13.5/core 2.46.5 and pytest 9.1.1. The underlying
crash cause is unconfirmed. An isolated diagnostic initially stopped in conftest because its
launcher incorrectly supplied `AUTH_MODE=dev`; correcting only the launcher to the accepted
`development` value ran all 34 original worker-service tests successfully in 37.09s. This neither
repairs nor waives the full-run crash. No dependency pin, garbage-collection suppression, test
skip or application/assertion change is introduced. Complete fresh validation remains required.

All ten owned source hashes remained frozen throughout the failed full run; 496 other baseline
tracked hashes, all 74 branch refs, three worktrees and three parent skill hashes were reverified
unchanged afterward. The private parent proof validator is subsequently being strengthened with
closed fields, strict types, fixed output, installed-source/path identity and independently
cross-checked operation/write/intent counts plus permanent negative guards. These test-only
changes require new validation and do not accept a self-reported process success.

8B3.3/8B3/8B/Sprint 8 remain IN PROGRESS. The full preflight source/configuration/identity/leakage/
fresh-process recovery/packaging matrix, complete local/frontend/browser gates, exact independent
review, candidate CI, ordinary guarded merge and exact-main CI remain pending. No reviewer,
commit, publication, 8C--8E implementation, Sprint 9+ or live/operator operation is started here.

### 8B3.3 process report guards and source negatives — 2026-10-12

The parent now rejects open/incomplete report fields, boolean or malformed counters/identity,
unapproved output, mismatched installed fingerprints/paths, unpaired lock probes, unexpected wire
sequences and inconsistent SDK-enable/wire-enable/committed-intent counts. Thirty permanent
negative/acceptance guards complement the original 51 resource guards. All 181 guard/contract
checks passed in 3.08s, then Ruff found two overlong fixed help strings. Splitting those literal
strings without changing their bytes passed all 181 again in 3.16s, Ruff, 429-file formatting
and whitespace. Complete collection found 3,498 cases in 1.81s; collection is not execution.

The installed-process wrapper now includes 79 additional cases alongside the retained seven:
all 21 forbidden source/endpoint/CA/model variables with empty and synthetic nonempty values,
ten missing/malformed relative metadata paths, malformed/unavailable metadata, wrong/incomplete
identity, incomplete/permanent/transient read failures, missing/malformed/scope-conflicting
configuration, invalid arguments, help and default-off scanner/application fallback traps.
Each case obtains its own signed admitted grant and owned schema; a terminal no-write result is
not reused to manufacture later source coverage. Exact history, blockers, retained technical/
finding state and independent transport counts remain required. These 86 process cases are
constructed, not yet validated together at this checkpoint.

The private orchestrator permits removal of its worker database environment field for the
missing-setting case, but accepts no caller-selected PostgreSQL target: only its derived live
schema or the two existing safe invalid URL sentinels. The signed parent can supply explicit
CLI arguments for cutoff tests; the production entrypoint is unchanged. Missing identity is a
synthetic wire response consumed by the unchanged SDK/adapter, not a replacement worker.
All changes remain test-only. No schema/dependency/authentication/runtime/frontend/CI change,
review clearance, commit or delivery is claimed. Next run these targeted process cases against
fresh disposable PostgreSQL, then finish the remaining strict pre-construction/.env/host-file
and independent-runtime/recovery/packaging families before the complete acceptance gates.
The failed native full regression remains unwaived and its cause unconfirmed. Sprint 8 remains
active/incomplete; 8C--8E remain required later, and Sprint 9+ and live operations are unstarted.

### 8B3.3 source and configuration process validation — 2026-10-12

The expanded focused run passed all 267 checks in 534.71s: all 86 installed-process journeys,
81 resource/report guards and 100 contracts. The real integration-enablement URL belonged to
a fresh owned outer PostgreSQL stack; the process fixture created a separate owned stack and
one migrated schema/signed grant per case. Neither reused an operator URL or a previous terminal
grant. Parent report guards, exact blockers, independent SQL/intent probes, signed history,
technical/finding preservation and all transport assertions passed. This is targeted evidence,
not a full regression or whole 8B3.3 acceptance receipt.

The wrapper exited 0 after cleanup. A fresh Docker label inventory found no owned process
containers/networks remaining and both unrelated stopped containers preserved. All ten frozen
owned hashes, 496 other baseline hashes, 74 branch refs, three worktrees and three parent skill
hashes matched afterward. The owned image retained its immutable identity, non-root `app` user
and default API command; test helpers remain outside production packaging.

A subsequent credential-free, networkless owned probe verified the Docker metadata needed for
independent launch checks: the narrow bind reports its exact native source, read-only access and
private propagation; capability drop, no-new-privileges and tmpfs settings match the requested
restrictions. `docker start --attach` and retained container state both report deliberate exit 47.
Exact owned probe cleanup completed. No database, credential or application worker was involved.

Next test-only additions inspect exact image/user/entrypoint, read-only/no-privilege/internal-network/
mount restrictions before process launch, then independently inspect its terminal exit state.
They observe real engine construction, forbid application/scanner settings and AWS host-file/
dotenv reads, check effective process privileges and suppress post-entrypoint dependency errors.
Only one explicitly selected, synthetic, read-only `.env` file may be added for its three ignored-
file cases; no host credential store or application/SDK source is mounted. Worker behavior,
credential sources, SQL ordering and intent-before-dispatch remain unchanged. Permanent negative
guards and fresh process validation are required for these additions.

The separate-process unknown-effect/death, persisted budget/window, sticky target/capacity and
whole protected-coordination/recovery/packaging families still remain, followed by complete
local/frontend/browser validation and every independent-review/delivery/exact-main gate.
The failed native full run is not waived or repaired by this pass. 8B3.3/Sprint 8 remain incomplete;
no 8C--8E/9+ implementation, reviewer, commit, publication, live or operator operation starts here.

### 8B3.3 independent runtime and construction guards — 2026-10-12

The private controller now creates without launching, verifies exact owned Docker metadata and
its owned internal network, attaches once, cross-checks terminal container state and removes the
exact worker in a primary-preserving cleanup path. Only immutable owned image identity, the
existing `app` user, unchanged mounted entrypoint, read-only root, no added capabilities,
no-new-privileges, unpublished ports and exact selected read-only private binds are accepted.
The validator rejects even broader caller-supplied expected networks/mount sets.

The mounted observer still calls the real installed entrypoint/engine/SDK. It counts real engine
construction, forbids application/scanner settings and AWS host-file/`.env` reads, verifies
effective no-new-privileges/zero capabilities and checks suppressed dependency ERROR output even
after help/default-off/error cutoffs. It does not change HOME, copy real credential stores or
replace authorization, worker decisions, SDK methods/parsers or database persistence. Three added
synthetic `.env` cases exercise ignored-file behavior with default-off, missing-database and
enabled settings; source, engine and history checks update atomically across private callers.

The first new guard/contract check passed all 208 in 3.34s, followed by Ruff/429-file formatting,
whitespace and 3,528-case collection. Six extra broader-expected-target regressions then passed
all 214 in 3.10s with Ruff/429-file formatting and whitespace; collection found 3,534 in 1.78s.
The 114 private guards and 100
contracts are targeted evidence; the modified 89-case process matrix has not run at this
checkpoint and still requires fresh validation. The previous 267-case pass applies only to its
frozen prior helper sources. No production source, schema, dependency, API or credential boundary
changes. Fresh recovery/packaging coverage, complete regression/frontend/browser gates and all
independent review/delivery/exact-main gates remain required before accepting 8B3.3 or Sprint 8.

### 8B3.3 runtime process validation and recovery construction — 2026-10-12

The strengthened frozen helper passed all 303 focused checks in 595.11s: all 89 process
journeys, 114 private guards and 100 contracts. Independent Docker restriction/terminal-state
checks, effective process privileges, exact engine counts, application/host-file/`.env` tripwires,
post-entrypoint dependency-error suppression, real worker/SDK, committed intent/free locks and
signed history assertions all passed. Wrapper exit was 0 after cleanup; fresh label inventory
found no owned containers/networks and preserved both unrelated stopped containers. All ten
owned/496 other baseline hashes, 74 refs, three worktrees and three parent skill hashes matched.
This is focused evidence, not full regression, packaging, review or whole-sprint acceptance.

Nine additional process scenarios now cover uncertain timeout/503/incomplete/malformed receipts,
owned death at committed intent, fresh read-only recovery, readback deaths consuming the durable
global budget, an expired original observation window, real pre-intent lease expiry/reclaim and
global three-read exhaustion, and sticky quarantine target/global capacity. The real 30-second
lease/window is exercised with bounded waits; no persisted clock/grant/budget is rewritten.
The target conflict uses a newly approved proposal for the same target: a second execution of
the same proposal would test the separate one-execution invariant, not reservation retention.
Capacity remains the accepted 32; additional evidence uses normal offline scan persistence and
every proposal, independent approval and admission uses signed human HTTP.

The parent reuses only the accepted pure authority/evidence/unrelated-audit guards from
`SignedFaultJourney`, not its worker runner, transport, clock or authentication replacements.
Initial and additional authority changes are checked before extending expectations. New own-
coordination checks require immutable authority/guard rows, retained journal bytes, exact target
ownership, no stray private claims, generation/lease/intent consistency and declared global
readback counts. Unknown-effect recovery must retain its grant and fencing identity and never
send enable again; observation does not clear quarantine or change findings/technical results.

All 214 existing guard/contract checks passed in 3.06s, followed by two import-order lint failures.
Correcting only imports passed the same 214 in 3.07s, Ruff/429-file formatting and whitespace.
The changed signed parent/recovery scenarios have not yet executed at this construction checkpoint;
fresh targeted process validation and remaining negative-guard/packaging/full acceptance gates
are required. No accepted production source, schema, credential, API, policy, retry or release
semantics changes. The native full-run crash remains unwaived/unconfirmed. Sprint 8 stays active;
8C--8E remain required later, and no reviewer/delivery, Sprint 9+ or live/operator operation begins.

### 8B3.3 focused recovery validation — 2026-10-12

All 312 focused checks passed in 875.79s: 98 installed-process scenarios, 114 private guards and
100 contracts. The four ambiguous receipt variants, deliberate post-intent death, persisted
readback budget across dying fresh processes, expired observation window, real pre-intent lease/
reclaim/read-budget limits and sticky target/32-slot capacity passed. Every process retained the
real installed worker/SDK, narrow owned resources, independent committed-intent/lock probes and
signed authority/history checks. The strengthened immutable authority, old journal, exact target,
private claim/generation/lease/intent/readback and declared unrelated-audit guards also passed.
No simulated observation verified remediation or rewrote findings/technical results.

The wrapper exited 0 after exact owned cleanup. Fresh Docker inventories found no owned process
containers/networks; both unrelated stopped containers remained. All ten frozen owned source
hashes, 496 other baseline hashes, 74 branch refs, three worktrees and three parent skill hashes
matched afterward. Collection was 3,543 at construction; this is not a complete regression receipt.

Permanent negative cases for the strengthened parent coordination/audit and strict transport
guards, independent installed-version/packaging/default-API/no-start evidence, the remaining
matrix audit, affected old regressions, complete backend/PostgreSQL/Compose/image and pinned
frontend/browser validation still precede exact independent review and every candidate/guarded-
merge/exact-main delivery gate. Production image dependencies do not include the development
`httpx`/TestClient extra; packaged smoke tests must use its actual installed runtime rather than
silently adding test dependencies to the released image. Existing startup tests and caller
search show no worker launch path, but source searches alone are not installed-startup proof.

The earlier Windows native full regression remains failed/unwaived with cause unconfirmed;
neither this targeted pass nor a future Linux pass is described as its fix. 8B3.3/8B/Sprint 8
remain incomplete; 8C--8E remain required later. No production/runtime/schema/authentication/
credential/dependency change, reviewer, commit/publication, Sprint 9+ or live operation occurs.

### 8B3.3 negative guards and packaged startup — 2026-10-12

Twenty permanent integration negatives now reject missing/stray immutable authority, guard,
journal, target and claim snapshots; corrupt claim identity/generation/lease/intent/budget fields;
unused/wrong transport queues; and a deliberately disarmed interceptor. The disarmed case installs
a deny-all transport and fails before the entrypoint; it never restores real network access.
All malformed snapshots are in-memory test inputs, with the real database required unchanged.

The narrowly mounted harness adds a private API-startup branch, not a production test mode.
It uses installed Uvicorn and proxy-free loopback HTTP without adding development dependencies,
verifies health/readiness/database/OpenAPI bearer declarations, and prohibits worker construction
or write-identity creation before importing the real API module. The parent checks the immutable
image's accepted default API command and user, exact restricted container metadata, all persisted
values, queued-grant history and zero provider/writer calls. The source manifest now includes
five API/database/scanner startup files alongside the nine worker files. API test configuration
is closed, explicit local/test-only and derived from the same owned migrated schema.

The first packaged probe failed one test in 12.52s at the proof boundary. One bounded diagnostic
failed in 12.11s with fixed POST_ENTRYPOINT_DIAGNOSTIC: the harness incorrectly applied the
dedicated worker's synthetic ERROR suppression probe to normal API logging. Restricting that
probe to worker mode retained every worker assertion and the API empty-stderr/no-dispatch checks.
A new unit mock initially replaced the root logger through pytest's own logging hooks, causing
a cascading TypeError without a trustworthy summary; restoring it inside a scoped context fixed
only the test. Fresh checks passed 216 in 4.30s with Ruff/429-file formatting and whitespace.

The first corrected API probe still failed one in 11.80s with fixed UNEXPECTED_CHILD_STDERR.
The remaining harness setup forced worker DEBUG logging before API configuration. Its API
branch now starts at the explicitly configured CRITICAL level, while worker mode retains DEBUG
injection and the unchanged worker's suppression contract. Permanent guards cover both
boundaries. No application logger, production dependency, assertion, authorization or handler
was weakened or changed. Fresh guards/contracts passed all 217 in 4.32s, with Ruff/429-file
formatting and whitespace.

Corrected packaged startup and all twenty negatives passed: 21 passed, 98 deliberately
deselected in 128.83s. The wrapper exited 0 after cleanup; fresh inventories found no owned
containers/networks and both unrelated stopped containers preserved. All ten owned/496 other
baseline hashes, 74 refs, three worktrees and three parent skill hashes matched afterward.
This targeted selection is not a whole 119-scenario matrix or full regression receipt. Complete
new/affected old targeted checks, regression/PostgreSQL/Compose/image, pinned frontend/browsers,
exact independent review and every delivery/exact-main gate remain before acceptance. The
earlier Windows native crash and historical browser failures remain unwaived; no later sprint,
live operation, reviewer, commit or publication is started by this checkpoint.

### 8B3.3 complete local validation — 2026-10-12

The unchanged validation runner completed the new and affected old focused checks: 615 passed
in 1354.00s. Ruff passed, 429 files passed formatting, and complete native regression passed
all 3,567 cases in 2765.97s with the 19 existing SQLite datetime-adapter deprecation warnings.
Whitespace, quiet Compose validation and the exact production-image build passed; the wrapper
exited 0 after removing its disposable database. Independent collection confirms 152 backend
files and all 597 PostgreSQL cases across 26 files, with no skipped cases in the full result.
The new integration file has 119 cases, including eight parent-only malformed-snapshot negatives
and packaged API startup; this does not mean 119 worker entrypoint journeys. All 117 private
guard cases and 100 contracts also ran. The entire new matrix and affected retained signed
fault/recovery, worker, authorization, startup and migration tests are covered, not a selected
success subset. No production application, interface, schema, credential or dependency changes.

Fresh inventories after backend validation found no owned containers or networks. All ten
frozen owned hashes, 496 other baseline hashes, 74 branch refs, three worktrees and three parent
skill hashes matched. Both unrelated baseline containers remained. The earlier native access
violation retains its failed receipt and unconfirmed cause: this fresh native pass is not its
diagnosis or a claim of repair, and no dependency pin, GC workaround, skip or assertion waiver
was added.

Network-disabled, read-only probes recorded actual installed metadata. The current validation
image uses Python 3.12.15, boto3/botocore 1.43.112 and non-root `app` UID 100; the pinned browser
image uses Python 3.12.3, boto3/botocore 1.43.111 and non-root `pwuser` UID 1001. Both report
SQLAlchemy 2.1.4 and psycopg 3.3.6. These are separate environments, not native SDK 1.43.87 or
interchangeable version evidence. The validation image is `sha256:68941cb9d083b4b64550264c9bf19befef968e62a35015c248989fd9c81dd693`;
the existing pinned browser image is `sha256:aad7a3f33abd1eecef2f95c6d95b477b7b778318e0142073c9e4c07cf97c4349`.
A network-disabled source probe matched all 247 current application, frontend, migration and
browser-fixture files before reuse. Its initial PowerShell report incorrectly used `true`
instead of `$true`; correcting only report formatting produced the complete matching receipt.
No application or tested source was edited, and every probe removed its own container.

The approved pinned Linux browser runner passed typecheck, lint, all 139 frontend tests/eight
files, build and all 76 Chromium/Firefox journeys. Node 24.19.0 and pnpm 11.19.0 were observed.
The first passing run's repetitive informational output exceeded one console chunk; a second
fresh owned run on the same frozen source retained complete primary per-case results. Only
repetitive already-sanitized informational display was filtered; no application logger, test,
timeout, retry, browser flag or assertion changed. Both runs exited 0 and reported 76 passed
in 1.7m. The second audit retained all 76 unique, consecutively numbered results, 38 per browser,
one worker and zero retries/skips, along with all eight frontend file counts. Controlled signed
login, bearer API, disposable PostgreSQL, scan/evidence/NIST rendering, expiry and logout passed.
The accepted cleanup helper's six permanent unit cases remained in the full frontend gate.

Fresh post-browser inventories found no owned validation/process/browser/probe resources or
networks. The two unrelated baseline containers were preserved; a newly present unrelated
application-test container was also left untouched. The old artifact-free main Firefox cause
remains unconfirmed, the demonstrated layout/pointer race remains unfixed and the original
scan-picker/back-navigation report remains for 8D. Linux browser passes do not repair them.

The complete local gates precede exact-candidate independent review, both final-head candidate
CI audits, ordinary expected-head guarded merge, exact-main CI and 8B closeout. This receipt
does not accept 8B3.3/8B3/8B or complete Sprint 8. The worker remains default-off, scanner
credentials read-only and finding/technical/remediation lifecycles separate; migration 0009,
the approved handler, distinct authority, bounded global budgets and sticky quarantine are
unchanged. No live AWS/IdP/IAM/secrets, operator database, deployment, rescan/UI implementation
or Sprint 9+ work starts. Verification and document-writing skills guided the end-to-end gate
and the evidence-qualified receipt while preserving repository history and identifiers.

### 8B3.3 independent review and exact-main acceptance — 2026-10-13

The existing authorized reviewer returned REVIEW_PASS, no findings, for immutable test head
`5909ffdd21489e709918d89ca952c6df8cdac1ef`, tree
`08bcaae8d3c5ab9a50e7d1dcffc0a5b0a28c2ed4`, parent `489b047562005a766734e9b571f7e307f8506102`.
Independent checks passed 217 private guards/contracts in 2.80s and seven selected installed
process cases in 73.18s, with 112 intentionally deselected, no skips or warnings. Those seven
cover three signed key-context acknowledgments, packaged API startup, disarmed interception,
timeout recovery and post-intent death. Ruff/429-file formatting, whitespace and exact collection
also passed independently. The reviewer independently audited the retained primary log for all
139 frontend cases/eight files and all 76 unique browser results; it did not execute a fresh
frontend/browser rerun. Those results are explicitly carried unchanged-source evidence.
The reviewer did not independently rerun the entire native regression; its unavailable complete
native per-file primary log remains a local evidence limit. Complete provider primary audits
below independently retain every backend/PostgreSQL/browser result, not just global summaries.
All 506 tracked hashes, 74 branch refs, three worktrees and three parent skill files were preserved
during review, with no tracked/index/ref/publication writes; owned review resources were removed.

Both first-attempt final-head candidate runs passed complete primary audits:

| Gate | Run / job | Actual checkout | Complete backend duration |
| --- | --- | --- | --- |
| Feature push | [38341868908](https://github.com/jnc247s/cloud-security-automation/actions/runs/38341868908) / 115114449456 | `5909ffdd` | 2537.79s |
| Pull request | [38342075419](https://github.com/jnc247s/cloud-security-automation/actions/runs/38342075419) / 115115079493 | Synthetic `d7ecd746`, tree `08bcaae8`, parents `489b0475` + `5909ffdd` | 1795.42s |
| Exact merged main | [38346013358](https://github.com/jnc247s/cloud-security-automation/actions/runs/38346013358) / 115127490368 | `d3380402`, same reviewed tree | 2890.11s |

Each audit retained all 3,567 passing cases across 152 backend files, all 597 PostgreSQL cases
across 26 files, the 19 existing SQLite datetime-adapter warnings, all 139 frontend cases/eight
files, and all 76 unique consecutively numbered browser results: 38 Chromium, 38 Firefox,
one worker, zero retries/skips/non-pass markers. All 18 job steps, Ruff/429-file formatting,
type/lint/build, image and cleanup passed. Checkout/tree/parents were verified from provider
metadata and primary logs. No rerun, weakened assertion, skip, dependency pin or protection bypass.

The PR connector rejected creation with integration HTTP 403; the already authorized CLI then
created [PR #66](https://github.com/jnc247s/cloud-security-automation/pull/66) without changing
credentials or permissions. This was an API integration failure, not a policy denial. A premerge
read-only query initially used an unsupported field; the corrected query verified ordinary merge
commits allowed and automatic branch deletion disabled. No previously denied optional comment
was retried. Ordinary merge guarded by exact head `5909ffdd` completed at 2026-10-13T04:20:59Z,
producing `d338040260de3954065a46041118504134bc320c` with parents `489b0475` + `5909ffdd` and
unchanged reviewed tree. The remote feature branch was preserved. Exact-main CI then passed;
its complete audit and current remote tip were verified at 2026-10-13T05:14:19Z.

### 8B documentary closeout preparation — 2026-10-13

Only after exact-main acceptance, clean local main was normally fast-forwarded from `489b0475`
to `d3380402`, then scoped branch `codex/sprint-8b33-closeout` was created. All existing branches,
three worktrees and unrelated parent skills were preserved; the branch count is now 75.
The initial patch was rejected for a mismatched receipt context and made no edits; no user change
was discarded. The bounded closeout updates nine owning Markdown files and the current-stage
contract atomically, preserving historical predictions, anchors, failures and their original limits.
It records 8B3.3/8B3/8B COMPLETE as offline code/test acceptance, not deployment or live authority.
This closeout candidate still requires targeted contracts, Ruff/formatting, complete fresh
disposable-PostgreSQL regression, Compose/image, relevant frontend/browser checks, exact independent
review, both final-head CI audits, ordinary expected-head guarded merge and complete exact-main CI
before 8C preflight. No next-slice implementation begins from an unaccepted documentary candidate.

Application/runtime/schema/API/authentication/dependencies/frontend/IAM/CI and scanner access are
unchanged. Accepted runtime remains `7a36ddde`, migration `20261008_0009`, opt-in catalog `0.13.0`,
default `0.2.1` and profile `1.0.0`. Three distinct human authorities and separate worker service
identity remain enforced; worker/admission stay default off. Synthetic installed-process proofs
do not establish physical ECS task/host/network/IAM isolation or distinct physical humans.
Intent is the cancellation cutoff; no AWS CAS/hard cancellation, post-intent resend, TTL unlock,
quarantine clearing, rollback or incident-force endpoint is added. Readback is not causation,
key/workload usability, attributed verification, technical PASS or finding resolution.
Historical native/browser failures retain their unconfirmed causes; demonstrated layout/pointer
and reported scan-picker/back-navigation limitations remain for 8D preflight. Documentary work
does not repair them. Sprint 8 remains IN PROGRESS; 8C--8E are required and PLANNED. The plan stays
active. No Sprint 9+, live AWS/IdP/IAM/secrets, operator database, deployment or production operation.

### 8B closeout targeted correction — 2026-10-13

The initial targeted run failed three owner-opening checks, with 97 passed in 10.31s: changing
ROADMAP's established baseline label and leaving the architecture/security/threat openings on
the runtime-only baseline broke their existing consistency contract. No full or quality gate ran
past that failed boundary. The correction preserves the original contract and baseline label,
updates all three openings to accepted test main `d3380402`, and explicitly retains unchanged
runtime `7a36ddde`. No assertion, runtime, interface or acceptance requirement is weakened.
Fresh targeted checks and all remaining closeout gates precede acceptance.

The corrected targeted run passed all 100 contracts in 2.74s; Ruff, 429-file formatting and
whitespace passed. Before full validation, all ten owned/496 other tracked hashes, 75 refs,
three worktrees and three parent skills matched the frozen candidate/baseline. The first full
runner stopped before any test result, exit 1, and removed only its own TEMP. Docker had become
unavailable after the initial successful inventory: the CLI reported the desktop engine stopped
and WSL docker-desktop stopped despite the desktop application still running. A normal start
reported already running; the supported detached graceful restart then reported Starting Docker
Desktop. No Docker reset, WSL-wide shutdown, container/volume pruning, data deletion or config
change was used. This failed setup is not a regression pass or a diagnosis of why Docker stopped;
fresh engine inventory and full validation remain required.

### 8B closeout unavailable native result and durable logging — 2026-10-13

After Docker recovery, fresh focused validation passed all 100 contracts in 0.37s, Ruff/429-file
formatting passed and full regression collected 3,567 cases. The pinned Linux frontend gate
independently passed type/lint/build, all 139 units/eight files and all 76 unique consecutive
browser journeys (38 per project, one worker/zero retries/skips), exit 0. All 247 selected current
application/frontend/Alembic/browser-fixture hashes matched the immutable image before reuse;
its owned database/network were removed. Its complete per-case audit was observed; the saved
aggregate remains recorded, with raw-retention limits qualified in the final receipt below.

The user's resumed Continue found observation cell 526 missing and native session 71244 unknown.
Read-only host checks found no validation process, owned validation/process/browser containers
or networks, or its owned TEMP; the two unrelated stopped containers were preserved. The old
native run is no longer live, but its terminal result was not retained: neither cleanup nor
partial passing output proves full success. Completion is unverified, not accepted or relabeled
as a diagnosed test failure. No concurrent run was restarted solely from an observation timeout.

A private ignored PowerShell transcript wrapper records terminal/cleanup classifications while
invoking the existing isolated-environment wrapper and unchanged repository
validator. It refuses log/TEMP collisions, pins the local Docker endpoint, removes only its exact
validated owned TEMP, and preserves native failure when secondary cleanup fails. It supplies no
new production mode, dependency, retry, auth override or test waiver. A fresh full gate is required
because the prior handle is missing and actual work stopped without a verifiable terminal result.
The receipt is frozen before new targeted/full checks; frontend/browser acceptance is carried only
for its unchanged fingerprint-matched sources, not as proof of backend completion. Review,
candidate CI, guarded merge and exact-main acceptance still precede 8C preflight.

### 8B closeout complete local validation and review preparation — 2026-10-13

The fresh isolated wrapper passed 100 focused contracts in 0.38s, Ruff and 429-file formatting,
then complete native regression: all 3,567 cases in 2705.23s with only the 19 existing SQLite
datetime-adapter warnings. Exact current collection confirms 152 files and all 597 PostgreSQL
cases/26 files. Collection's first JSON report parser encountered the nonfatal native launcher
location warning; a corrected bounded report parse retained the warning and confirmed the same
scope without changing tests. Collection is not execution. Complete primary execution audit
now matches every expected file count, all 597 PostgreSQL passes, all 119 process-file cases and
all 117 private guards, with zero non-pass/skip/failure markers and one matching full footer.
The private audit parser's missing-file, skip, duplicate-footer and unexpected-file probes are
synthetic guard tests, not application acceptance evidence.

Whitespace, quiet Compose and the exact image build passed. Native, cleanup and wrapper terminal
exits are all 0. PowerShell's transcript retained terminal/cleanup classifications but not the
child's direct native console stream; exact raw chunks were therefore saved separately as
consecutive JSON records, preserving partial-line boundaries. All 23 chunks and the transcript
end marker remain on disk. The earlier unavailable session remains unverified, not retrospectively
accepted or diagnosed by this new pass. No test, retry, timeout, assertion, dependency or runtime
configuration was weakened.

All 506 frozen tracked hashes, 75 refs, three worktrees and three parent skill hashes matched
after the full gate. The wrapper TEMP, validation database and all process/browser/probe-owned
containers/networks were absent; both unrelated stopped containers and their network remained.
The exact newly built image is `sha256:b51af62369de7d1fd611d76158e27d430bd8acf2831e90d52cab76c5a1236741`.
Network-disabled/read-only/non-root probes recorded Python 3.12.15, boto3/botocore 1.43.112,
SQLAlchemy 2.1.4, psycopg 3.3.6, UID 100 and WORKER_DISABLED/exit 0. These actual image versions
are not interchangeable with native Python 3.14.5 or the older pinned browser environment.

The preceding closeout frontend gate passed all 139 units/eight files and all 76 unique browser
journeys, one worker/zero retries/skips, after matching 247 source hashes. Its complete per-case
audit was observed and its aggregate saved. Resumed input cleared the in-memory raw local browser
log; raw retention of that particular closeout run is now unproven. The earlier complete pinned
browser primary log remains on disk for identical application/frontend/Alembic/browser-fixture
sources. Independent review may carry that explicitly unchanged-source evidence, not describe it
as a fresh rerun. Both upcoming candidate CI audits and exact-main CI must independently retain
all backend/PostgreSQL/frontend/browser primary results for this closeout candidate.

After full validation, only accepted-state prose/receipt corrections change: the 8A architecture
tail and T20 residual now distinguish their original slice from accepted default-off 8B worker
code, rather than incorrectly call the worker future/unimplemented. No application, test body,
API/schema/security boundary, SDK, frontend, IAM or CI source changes after the full gate.
Fresh targeted contracts, Ruff/formatting and whitespace validate final prose, then freeze one
logical ten-path exact commit for the existing authorized reviewer. Findings, both final-head CI,
ordinary guarded merge and complete exact-main remain gates before 8C preflight. Sprint 8 stays
IN PROGRESS; 8C--8E remain required and PLANNED. Physical isolation, live providers, key/workload
compatibility, production, historical native/browser causes and dashboard interaction limits remain
unvalidated/unfixed as recorded. No live AWS/IdP/IAM/secrets, operator database, deployment or 9+.

Final prose follow-up passed 100 contracts in 2.66s, Ruff/429-file formatting and whitespace.
Repeat the same lightweight checks after this receipt before freezing the scoped commit; full
tested application/test source remains unchanged and both upcoming candidate CI gates remain full.

### 8B closeout independent review correction — 2026-10-13

Exact candidate `bcf2a47519d3cf132a9c2045fe4b3a064bd4efd2`, tree
`5f6507994bd5fe2c0bc81690235407a5467eda11`, received REVIEW_FAIL with one LOW finding and no
other actionable findings: the earlier 8B3.3 receipt's phrase "also passed independently" could
misrepresent an independent frontend/browser primary-log audit as a fresh independent execution.
The correction explicitly distinguishes executed 217 guards/contracts and seven process cases
from audited/carried 139-unit/76-browser evidence. It changes only this receipt, not tests or code.
The failed verdict is retained; exact corrected-head follow-up is still required before publication.

Independent closeout checks passed 100 contracts in 3.03s, Ruff/429-file formatting and committed
whitespace, with no skips or pytest warnings; the existing native launcher warning stayed visible.
All 20 pre-existing explicit anchors remain and the new acceptance link resolves. The reviewer
independently concatenated all 23 raw chunks and verified every expected count: 3,567 passes/152
files, all 597 PostgreSQL cases/26 files, 119 process-file cases and 117 guards, zero non-pass
markers, one 2705.23s footer and 19 existing SQLite warnings, plus exit-zero cleanup/terminal
receipts. Only the three recorded prose files differed after full validation; all other 503 hashes
and every test body matched. Before/after checks preserved all 506 hashes, index entries, 75 refs,
three worktrees and three parent skills. No tracked/index/ref/publication/live-operation writes.
Fresh targeted/quality/whitespace checks precede a normal receipt-only correction commit and
reused exact-head review. Both candidate CI audits, guarded ordinary merge and exact-main remain
required; Sprint 8 is not complete and 8C--8E/9+ work remains unstarted.

### 8B documentary closeout acceptance and 8C analysis entry — 2026-10-13

The preceding documentary candidate is accepted through
[PR #67](https://github.com/jnc247s/cloud-security-automation/pull/67), ordinarily merged at
`771d630c9385c1155f981bd47e18d43e87fb2290`. This supersedes its pending gates, not original
predictions, failed receipts, evidence limits or unfixed dashboard behavior. Sprint 8 stays
IN PROGRESS; 8C--8E remain required and PLANNED, and this plan stays active.

The existing authorized reviewer returned exact corrected-head REVIEW_PASS for
`098111b701827f10b062a06a6a57042a59408a59`, tree `87080be23d635b926191965874b3a3d45fbd50e2`,
parent failed-review `bcf2a475`: no actionable findings; the LOW attribution finding is closed.
Independent follow-up executed 100 contracts in 2.68s, Ruff/429-file formatting and whitespace.
It carried its previous full backend primary audit and unchanged-source frontend/browser log
audit; neither full suite was independently rerun. Root's receipt-only correction passed 100
contracts in 2.89s and quality/whitespace, with no application/test-body change after full validation.

Fresh provider primary logs were audited in full for every expected file and browser identity:

| Event | First-attempt run | Job | Actual checkout | Backend seconds |
| --- | --- | --- | --- | --- |
| Feature push | [38415227815](https://github.com/jnc247s/cloud-security-automation/actions/runs/38415227815) | 115357775212 | `098111b701827f10b062a06a6a57042a59408a59` | 2741.96 |
| PR | [38415312678](https://github.com/jnc247s/cloud-security-automation/actions/runs/38415312678) | 115358080137 | `2008cf97ff4bf388b4f14c4565f1c48aabe6a7ca` | 2794.91 |
| Exact merged main | [38423060289](https://github.com/jnc247s/cloud-security-automation/actions/runs/38423060289) | 115385169957 | `771d630c9385c1155f981bd47e18d43e87fb2290` | 2820.45 |

Each passed all 3,567 backend cases/152 files, including all 597 PostgreSQL cases/26 files,
119 process-file cases and 117 guards, no non-pass/skip markers and one full footer with only
19 existing SQLite warnings. Each passed 139 frontend cases/eight files, all 76 unique consecutive
browser results (38 Chromium/38 Firefox, one worker/zero retries), and all 18 quality/image/
cleanup steps. Exact collection is not substituted for execution; aggregate green is not
substituted for per-file/per-case primary evidence. Complete provider logs/audits are retained
in the private task evidence directory.

Both the PR synthetic checkout and ordinary merge retain reviewed tree `87080be2` and exactly
parents `[d338040260de3954065a46041118504134bc320c, 098111b701827f10b062a06a6a57042a59408a59]`.
The ordinary merge completed at 15:33:13 UTC with explicit expected-head guard, unchanged base
and clean PR state, no admin/force/protection bypass or branch deletion. Complete exact-main
audit passed at 16:25:43 UTC. No old CI was rerun or failed evidence waived.

Clean local main then normally fast-forwarded to the accepted merge; scoped
`codex/sprint-8c-preflight` was created. All 76 local branches (75 preserved plus this one),
three worktrees and three parent skills remain. Runtime `7a36ddde`, migration
`20261008_0009`, catalogs/profiles, API/authorization, read-only scanner credentials,
worker/quarantine semantics and finding/technical lifecycles are unchanged. Physical isolation,
live providers, key/workload compatibility, production and historical/dashboard limitations
remain unvalidated/unfixed as recorded. No live AWS/IdP/IAM/secrets, operator database,
deployment, production or Sprint 9+ operation occurred.

The [8C analysis-only preflight](../../sprint-8c-preflight.md) proposes a complete bounded linked
verification slice followed by fault/recovery/compatibility acceptance. Its R1 initiation/
eligibility, R2 exact-scope/verdict and R3 receipt/retry choices require explicit user decisions.
No approved 8C execution predictions, code, migration, new route, reviewer or publication begins
from these proposals. The standing workflow resumes implementation only within an approved
design; 8D/8E remain required afterward.

The first analysis-document readiness run passed 100 and failed one existing historical-CI
reference assertion in 8.58s after the baseline header moved to PR #67. Restoring the explicit
PR #66 CI 38346013358 citation preserves its separate implementation receipt and the unchanged
assertion. No quality/full gate ran past that failed boundary; fresh checks are required at
this correction checkpoint. Initial whitespace checking also found one extra EOF blank line,
removed before the targeted run. No code, migration or test assertion was changed or waived.

Corrected analysis-document checks passed all 101 contracts in 2.73s, including the new Markdown
link case, Ruff lint, 430-file formatting and whitespace. The existing native launcher warning
remained visible; no pytest warnings/skips. All 498 protected tracked hashes, unchanged index,
76 local refs, three worktrees and three parent skill hashes match the frozen preflight baseline.
Remote main still matches `771d630c`. These are preflight-document checks, not an 8C runtime or
fresh complete regression acceptance claim. No application/test body, schema, API, credential,
worker, CI, policy or frontend source changed. R1--R3 remain unapproved; implementation and all
new-slice full/integration/security/review/delivery gates remain future required work.

### Approved 8C predictions

On 2026-10-13 the user replied **Approve and continue** to the recommended R1--R3 package.
This supersedes the preceding pending-decision checkpoint, not its original analysis or receipts.
8C/8C1 are IN PROGRESS; 8C2 and 8D/8E remain PLANNED. Standing routine implementation,
validation, existing independent review and guarded delivery approval applies within this design.
No live operation or later-sprint authority is added.

- R1: manual current EXECUTE requests by any EXECUTE principal, normal ACKNOWLEDGED only;
  separately default-off explicit account/Region verification scope. Preserve three-human write
  authority and read-only scanner credentials. Later original expiry/revocation/staleness is not
  a reason to deny observation of an acknowledged write; quarantine is never cleared.
- R2: a new full-original-scope scan under the complete retained profile, artifacts, catalog and
  control. Verify STS account and provider Region before collection, then independently check
  bundle identity before persistence. A separate versioned receipt is VERIFIED only for complete,
  strictly later exact-target EC2-004 PASS with complete unchanged present/expected-absent KMS
  context. Equally valid FAIL is NOT_VERIFIED; other states/context drift are INCONCLUSIVE.
  Unchanged normal finding reconciliation may legitimately differ from this historical verdict.
- R3: immutable audited requests/new-scan links and sealed terminal receipts; three explicit
  accepted attempts per execution, one active. Actor/operation UUID replay returns the original
  attempt without submission or renewed authority; changed input conflicts. No automatic
  post-terminal attempt. RUNNING startup recovery reuses the same scan ID and read-only contract.

8C1 implements the complete vertical path before delivery. Add generic
`POST /api/v1/remediation-executions/{execution_id}/verifications` (EXECUTE, reason-only body,
UUID Idempotency-Key), and READ list/detail at `/api/v1/remediation-verifications` with optional
execution filter. New responses carry immutable request, linked scan ID, and optional terminal
receipt; old scan/remediation/worker bodies and enums remain unchanged. Use a new contract version
`1.0.0` and additive migration `20261013_0010`; never rewrite 0001--0009 or old journal/audit bytes.

A separate singleton verification coordination guard serializes admission and terminal writes.
Lock order is verification guard -> Scan -> Resource -> Finding; execution/proposal/history reads
take no write locks. Never acquire execution/authority locks after scan/history locks. Commit
intent/link/RUNNING identity and full attributed start/request audit before executor submission.
Scan terminal result or failure and receipt/audit commit together. No SQL transaction crosses
provider construction, STS, collection or submission. READ rejects pending caller changes before
SQL, suppresses autoflush, preserves transaction ownership and never seals a receipt on demand.

Required 8C1 gates: focused strict contract and postcondition tests; authorized signed API;
disposable PostgreSQL admission/replay/bounds/atomicity/recovery; populated 0009 upgrade and
immutable/cross-reference/pre-DDL whole-path downgrade guards; retained-policy/scanner/worker
regressions; Ruff lint/format; complete pytest with all PostgreSQL cases; Compose/image/startup/
OpenAPI; relevant unchanged browser regression; existing exact-head independent review; both
candidate CI, ordinary expected-head guarded merge and full exact-main CI. No partial admission
is released before identity and atomic terminalization safeguards are complete.

8C2 then deepens integrated race/fault/restart, deployment-policy and historical-scope compatibility
acceptance against the implemented path before 8C is COMPLETE. Browser/BFF mutations and the
reported general scan-start/picker/back-navigation behavior remain 8D, not silently included here.

### 8C1 local implementation checkpoint — 2026-10-13, not accepted

Implemented the approved single-action linked-verification candidate on preserved scoped branch
`codex/sprint-8c-preflight`, HEAD still accepted `771d630c`. New closed contracts/ORM and additive
0010 protect request/scan links, terminal receipts and paired audit. The generic bearer APIs are
independently default-off/scoped. The existing scanner checks expected identity before collection;
normal persistence independently checks intent and atomically seals result/failure receipts.
Legacy interfaces/constructor/executor methods, worker/quarantine behavior, controls/profiles,
scanner credentials and finding/technical lifecycles remain unchanged. No partial release.

The immutable SCAN_STARTED audit marker distinguishes linked scans without altering old Scan
columns/DTOs; unlinked scans retain old-schema behavior. A missing/tampered trusted binding
fails closed before AWS; if it cannot support a trusted terminal receipt, RUNNING/active history
remains for separately reviewed maintenance. READ never repairs it. New public audit types are
additive; strict clients enumerating all audit types must account for verification events.
The separate guard serializes short admission/terminal transactions, not external reads. Whole-
path migration checks acquire verification -> admission -> scan/resource/finding/history -> audit
locks before DDL, including existing writers; no lower-lock inversion is introduced.

First focused gate failed one admission test after five passes (8.97s): request referenced an
audit UUID before its default had been generated. Explicit audit-phase flushes corrected the
implementation; insertion guards and assertions were unchanged. Corrected gate passed all 25
cases in 45.95s, including SQLite upgrade/downgrade/autogeneration schema drift checks.
The first signed-API selection encountered one native temporary-directory setup error (7.90s).
An owned workspace-TEMP rerun yielded no retained terminal test result and was interrupted;
it is not a passing or diagnosed application failure. An escalated diagnostic then exposed the
offline scanner fixture forcing development auth while inheriting production/dashboard settings:
one failure in 2.11s, followed by another dashboard-setting conflict in 2.08s. The fixture now
copies the API's validated settings; signed production authentication and negative assertions
remain active. No result was relabeled or assertion/security boundary weakened.

Corrected signed API, new migration, old scanner/migration/worker and status tests passed all 92
cases in 53.45s with only 19 existing SQLite datetime-adapter warnings. Expanded verification
tests passed 30 cases in 32.59s. Owner-document/contracts plus signed API/verification/migration
selection passed all 147 in 51.21s. Ruff lint/442-file formatting and whitespace passed. Later
independent-result-account and PostgreSQL history-guard cases still require their first execution.
No PostgreSQL/full/image/browser acceptance, independent review or delivery is claimed yet.
The planned disposable database/full acceptance gate is next; preserve both unrelated stopped
containers, all branches/worktrees and parent skills. 8C2/8D/8E remain required and PLANNED.
No live AWS/IdP/IAM/secrets, operator database, deployment, production or Sprint 9+ action occurred.

### 8C1 first PostgreSQL gate and local tool correction — 2026-10-13

The first validator passed all 76 focused cases in 157.29s, including all 29 new PostgreSQL cases.
It then stopped before frontend checks/full regression because the local pnpm default had become
11.25.0 while the unchanged frontend contract requires 11.19.0. Validator exit was 1 and its exact
disposable PostgreSQL container was removed; this is not full acceptance. Existing containers,
global tools, application dependencies and pin assertions were not changed or weakened.
An ignored workspace-owned tool directory now supplies pnpm 11.19.0; Node remains the required
24.19.0. Package scripts were disabled during its one-package installation.

Lock-order inspection found that the new immutable audit lookup could precede the verification
guard's schema-maintenance relation lock. The correction reads the guard relation first without
a row lock, then performs marker/history reads; linked terminal writes still acquire the guard
row before Scan/Resource/Finding. Ordinary writers remain mutually parallel. Older schemas skip
both new guard and marker lookup, retaining accepted paths. Executor preparation and new READ
routes enter this same relation-order fence before scan/history reads. This is a short SQL-only
schema fence, never an AWS/transaction crossover or a new worker reservation.
Two disposable-PostgreSQL concurrent downgrade/terminalization tests are added for ordinary and
linked scans. Fresh focused/full/quality/browser/image/review/delivery gates remain required for
this correction. The prior frozen hash receipt covers the pre-correction candidate, not these
new source bytes. Current acceptance is still pending; no 8C2/later-sprint/live operation starts.

The schema-fence follow-up passed 203 focused cases in 69.15s, including legacy ordinary scan,
metadata-only READ/evidence/governance fixtures, scanner contracts, new verification and migration,
signed API and repository documentation contracts. No warning/skip footer. A metadata-only test
schema need not seed the new singleton to use ordinary scans; linked requests/reads still require
the singleton, and migration 0010 seeds/protects it. This preserves the accepted constructor/test
contracts without weakening verification coordination. Ruff/442-file format and whitespace remain
required on the refreshed candidate; fresh PostgreSQL concurrency/full/browser/image gates follow.

### 8C1 browser environment and unavailable-scanner replay — 2026-10-13

The corrected native validator passed all 78 focused cases in 169.96s, including 31 PostgreSQL
cases and both ordinary/linked concurrent downgrade fences. Pinned Node 24.19.0/pnpm 11.19.0
passed frontend typecheck/lint, all 139 units/eight files and build. Chromium passed 38 journeys;
all 38 native Firefox cases failed before navigation with `browserType.launch: spawn UNKNOWN`.
Validator exit was 1; exact disposable PostgreSQL cleanup succeeded. Full backend/quality/image
steps after the browser boundary did not run. The large native primary chunk was truncated;
aggregate counts/footer are retained, not a complete independent per-case primary audit.

A source-matched Linux test image uses the existing pinned tooling substrate `aad7a3f3`, Node
24.19.0/pnpm 11.19.0/Python 3.12.3 and a 519-file tracked/task-owned archive; no host credentials
or untracked parent skills. Artifact `e261a289` completed despite loss of the build tool handle;
image inspection and exact runtime/test source probes confirm the completed artifact, not a
retained CLI exit. Its isolated non-root full browser run passed 72 and failed four Firefox
journeys with intercepted-channel `NS_BINDING_ABORTED` errors during login/navigation. Exact
owned internal network/database cleanup succeeded. This is not acceptance or evidence of a
specific application cause; assertions, headers, pins, retry count and browser configuration
remain unchanged. Browser environment diagnosis and full backend gates remain required.

A new signed API assertion confirmed another replay defect: unconditional executor dependency
returned 503 when a current EXECUTE caller replayed an accepted request while the scanner was
unavailable (one failure in 2.32s). The route now supplies its managed executor without admitting
work; the service checks availability only after authorized replay lookup. New unavailable
requests reject before persistence with fixed `remediation_verification_executor_unavailable`;
replay returns original history without submission. The unchanged new assertions then passed
one signed API case in 2.51s. This repair needs fresh PostgreSQL/full/review/delivery validation;
previous full-source freezes predate it. No later-sprint or live operation is authorized or started.

### 8C1 headed browser gate and legacy synchronization follow-up — 2026-10-13

The same pinned Linux image's first failed Firefox journey passed under Xvfb headed mode
(one case, 12.0s); the full headed gate then passed 139 units/eight files and all 76 journeys
(38 Chromium/38 Firefox, one worker/zero retries, 1.9m). Typecheck/lint/build and exact owned
database/network cleanup passed. Every application header, browser preference, assertion and
dependency pin stayed unchanged. This is an environment-specific local pass, not proof of the
cause of either earlier failure. Its second primary output chunk was truncated: 57 per-case rows
and the complete 76-pass footer are retained, not a complete per-case local primary audit. Both
candidate CI and exact-main must independently retain complete primary evidence.

The independent backend lane passed fresh 78 focused cases in 166.84s, Ruff/442-file formatting,
then started the complete 3,646-case/156-file regression (628 PostgreSQL/27 files). It reported an
execution-admission PostgreSQL failure. The lane was interrupted at 9%, exit 1; no complete
result or acceptance is claimed. Inspection found the final legacy downgrade synchronization
still waited for the old first admission-guard table lock. 0010 now fences with verification guard
first, so the writer paused waiting for an observer that could not yet be reached. Matching old
authority/graph test observers had the same obsolete prefix. All three now observe the actual
first verification-guard lock; wait bounds and no-DDL/no-partial-effect assertions are unchanged.
Fresh targeted execution is required to confirm the diagnosis, then complete regression.

Interrupting bypassed validator's normal finally cleanup. The exact owned database
`cloudsec-validation-1ef1c970608c4320b9b6c31cb06dd4f9` was verified against its equal ownership
label, creation nine seconds before the first primary chunk and tmpfs-only data, then removed.
Its synthetic test data is disposable/re-creatable. Both unrelated stopped containers and the
unrelated running budget-test container were preserved; no user database or volume was touched.
The new full gate will retain direct native output durably as well as tool chunks. No assertion,
test, timeout, auth, SDK pin or security boundary is waived; C1 acceptance/review/delivery remains
pending and 8C2/8D/8E remain required. No live or later-sprint operation occurred.

### 8C1 complete failed regression and additive schema expectation repair

The next native validator passed 81 focused cases in 184.02s, including all three corrected
legacy downgrade synchronization observers and all 31 verification PostgreSQL cases. Ruff lint
and 442-file formatting passed. Its complete regression executed all 3,646 cases/156 files,
including all 628 PostgreSQL cases/27 files, and finished with **3,644 passed, two failed**,
19 existing SQLite adapter warnings, in 3,507.19s. Exit was 1. Compose/image gates after pytest
did not run. The direct durable primary log retains both full traces despite truncation of the
terminal tool-output chunk; this is a complete failed execution, never an acceptance receipt.

Both failures were the shared unresolved-region migration upgrade-retry expectation, on SQLite
and PostgreSQL. Injected-transition rollback, original-row equality and schema drift checks had
passed; the exact added-table assertion omitted the new verification guard, requests and receipts.
The test now enumerates those three additive tables, requires request/receipt tables to be empty,
and checks the exact singleton seed row for both coordination guards. Historical migrations,
transition injection, history equality, empty-table assertions and rollback checks are unchanged.
The correction requires focused validation and a fresh complete run before review or delivery.

All 519 source hashes matched the frozen input before the repair. Normal cleanup removed both
owned disposable validation/process databases; independent name checks confirmed their absence
and preservation of the unrelated stopped database and welcome container. All 76 branches,
three worktrees and three unrelated skill hashes remained intact. No files were staged; the raw
index hash differed from the preflight snapshot, but staged-content comparison remained empty.
No implementation acceptance, image/startup claim, independent review, commit, publication,
merge, 8C2/8D/8E implementation, live operation or later-sprint work is inferred from this run.

### 8C1 local validation receipt

The corrected candidate passed the complete local backend gate, exit 0, with direct primary
output retained. This supersedes the preceding pending-local-validation checkpoint, not its
failed receipts or original predictions. 8C1/Sprint 8 remain IN PROGRESS and unaccepted.

| Gate | Exact result |
| --- | --- |
| Expanded focused selection | 101 passed in 212.75s; no warnings or skips |
| Ruff lint and format | Passed; 442 files already formatted |
| Complete pytest | 3,646 passed in 3,412.83s; no skips; 19 existing SQLite adapter warnings |
| Executed scope audit | All 156 files match the exact collection; all 628 PostgreSQL cases/27 files; no non-pass markers, one complete footer |
| Whitespace and Compose configuration | Passed; no Compose service started |
| Runtime image build | Passed; immutable image `sha256:9f2d8f7a25dce141d0ed1877ae8c2311025509e06951498012892b188a87bbed` |
| Built-image source and startup | All 207 application/Alembic hashes match; fresh SQLite upgrade to 0010, actual server startup, health/readiness, three new bearer-protected OpenAPI routes, both admission and verification default-off |
| Cleanup and preservation | Owned validation/process databases absent; unrelated stopped containers, 76 branches, three worktrees and three parent skill hashes preserved; no staged changes at audit |

The exact focused selection extends the preceding 81-case set with the complete SQLite and
PostgreSQL unresolved-region migration files. Thus both repaired upgrade-retry cases and all
five PostgreSQL writer-exclusion repetitions run before full regression. Historical transition
checks, fault injection and history/guard-seed equality remain strict. All 519 source hashes
matched the frozen full-run input before this receipt; subsequent changes here are documentation
only and require fresh contract/quality/whitespace checks before a scoped commit.

Local backend gates used Python 3.14.5 and an explicitly disposable loopback/tmpfs PostgreSQL
16 database. The actual runtime image used Python 3.12.15, non-root `app`, read-only rootfs,
dropped capabilities, no-new-privileges, no network or host mounts, and its own disposable tmpfs
SQLite database. No AWS credential/provider or user/operator database was used by the image smoke.
Image export reused matching build cache; its emitted manifest digest and inspected image ID
agree. Native exit 0 proves the silent whitespace/Compose gates preceded successful build and
normal cleanup. No old CLI failure or partial primary output is relabeled as success.

The unchanged frontend retains its separately qualified local result: 139 units/eight files
and all 76 journeys under Xvfb headed mode, with no assertion/header/pin/retry changes. Only
57 per-case rows plus the complete footer were retained, so this is not a complete local primary
case audit. Native Firefox launch and four Linux headless failures remain historical with
unproven causes. Both candidate CI and exact-main must independently retain/audit the complete
139/76 scope in the unchanged configured CI mode; local headed-mode success cannot substitute.

Next gates are frozen exact-commit independent review, any required bounded repairs, ordinary
publication and both candidate primary CI audits, expected-head guarded merge, then complete
exact-main primary audit. The reviewed/merged source tree must match. 8C2 deep acceptance and
8D/8E remain required afterward. No live AWS/IdP/IAM/secrets, operator migration, deployment,
production or Sprint 9+ operation is authorized or performed.

### 8C1 independent review correction

Independent review of commit `213422201444d3a00f5734f0004bf3e77d30297e`, tree
`4f7442178a427bc2564e64b1d84f098200e5088b`, returned REVIEW_FAIL with one LOW documentary
finding. README's current status still described pending design decisions and unimplemented linked
verification, contradicting the approved R1--R3 design and implemented-but-unaccepted 8C1 candidate.
The current paragraph now distinguishes the historical preflight, approved design, unaccepted
candidate and unimplemented UI. Original predictions and all failed validation receipts remain.
No additional correctness, security or data-integrity finding was identified across the 44 paths.

The reviewer independently passed 64 verification/service/migration/signed-API/status cases in
53.04s, 101 repository contract/link cases in 0.37s, and 31 fresh disposable PostgreSQL cases in
109.26s, with no pytest warnings or skips. Ruff, 442-file formatting and committed whitespace
passed. Independent audit, not a rerun, confirmed the complete local 3,646-case/156-file primary,
all 628 PostgreSQL cases/27 files, 119 installed-process and 117 guard cases, matching per-file
counts, one 3,412.83s footer and 19 existing SQLite warnings. All 207 image-source hashes matched;
only ROADMAP/active-plan prose differed from the full-run freeze at review entry.

The first restricted review selection had no terminal result; the first internal-network database
setup ran no tests. Neither is counted as passing. Owned database/network and ephemeral review
directory cleanup passed; ignored primary logs remain. All 519 tracked hashes/index entries,
147 existing refs (76 branches), three worktrees and three parent skills were preserved during
review. The correction changes only README and this receipt; fresh contract/quality/whitespace
checks and exact corrected-commit review remain required before publication. The qualified local
browser evidence is unchanged; both complete candidate CI audits, ordinary guarded merge and
exact-main CI remain required. 8C1/Sprint 8 remain IN PROGRESS and unaccepted; 8C2/8D/8E, operator
migration, deployment, live providers and Sprint 9+ were not started.

### 8C1 exact-head review and exact-main acceptance

The corrected documentation-only commit `bbb0f6aceea6f4454e5b8a93f2ccb8e38c0928e6`, tree
`6d263beaa6b0d8533c002e8a11050110cb89d624`, received independent REVIEW_PASS: the LOW README
finding was closed with no new findings. The original REVIEW_FAIL remains above. Independent
follow-up passed 101 contracts/link cases in 0.37s, Ruff, 442-file format and committed whitespace,
with no pytest warnings/skips. All runtime/test/migration/config/frontend bytes remained identical
to the original reviewed/full-validated candidate; the earlier 64-case/31-case independent runs
and complete backend primary audit carry forward, not a rerun. Root's corrected-head 101 contracts
passed in 2.90s, with quality/whitespace and all 519 source hashes qualified for the two prose edits.

Both first-attempt candidate primary audits passed. Ordinary expected-head guarded PR #68 merge
produced `76e0f7866dddb41d3ccd61913fbbeb36d594808e`; parents are exact baseline `771d630c` and
reviewed head `bbb0f6a`. The merged tree equals the reviewed tree. Complete first-attempt exact-main
CI and its primary audit passed on 2026-10-14 UTC (job completed 00:18:50 UTC).

| Primary audit | Actual checkout | Backend seconds |
| --- | --- | --- |
| [Candidate push 38477401446](https://github.com/jnc247s/cloud-security-automation/actions/runs/38477401446) | `bbb0f6a` | 3,089.18 |
| [Candidate PR 38477503709](https://github.com/jnc247s/cloud-security-automation/actions/runs/38477503709) | Synthetic `83b72a6e`, verified parents `771d630c`/`bbb0f6a` and reviewed tree | 3,075.02 |
| [Exact main 38483896952](https://github.com/jnc247s/cloud-security-automation/actions/runs/38483896952) | `76e0f786` | 3,099.75 |

Each complete primary independently matches all 3,646 backend cases/156 files, all 628 PostgreSQL
cases/27 files, 119 installed-process file cases and 117 guards, one complete footer and 19 existing
SQLite warnings, with no non-pass/skip markers. All 139 frontend cases/eight files and 76 unique
configured browser journeys (38 per project, one worker/zero retries), quality/image/cleanup and
all 18 job steps passed. Exact checkout, per-file/per-case identities and source tree were audited,
not inferred from green summaries. All decoded primaries and metadata/hashes remain in ignored
local receipts. CLI initially refused terminal control sequences on the historical log-download
probe; file-only decoded capture then matched that retained primary exactly after newline
normalization. Raw control sequences were never rendered; no candidate failure or rerun occurred.

These fresh configured-CI browser passes do not prove the causes of the earlier native Firefox
launch or four Linux headless failures. The local headed run still has only 57 retained primary
rows, and the user's picker/back-navigation report remains untriaged. No header, browser preference,
assertion, pin, retry count or source was changed to obtain these passes.

8C1 is COMPLETE as default-off offline code. 8C remains IN PROGRESS; 8C2, 8D and 8E remain required.
Migration 0010 is the accepted head, but no operator database is automatically migrated or live
scope enabled. Physical IAM/task/network isolation, live-provider/key/workload compatibility,
deployment and production remain separately authorized and unvalidated. No Sprint 9+ work started.
All original predictions and failed receipts remain intact.

The clean existing worktree was fast-forwarded to exact accepted main and moved to scoped branch
`codex/sprint-8c2-preflight` for owning-document reconciliation and the next bounded analysis.
Prior branches, three worktrees and unrelated parent skills are preserved. No 8C2 implementation
has started; its preflight must inspect integration contracts, callers, tests, risks and validation
before accepted-design workflow can proceed or new architectural/design choices are presented.

The first owning-document contract run passed 100 and failed one case in 9.42s: the historical
closure assertion still expected accepted head 0009. Quality/full steps after that failure did
not run. The contract now expects accepted 0010, retains the execution-history 0009 compatibility
requirement, and additionally checks exact accepted main/CI, 8C1 COMPLETE and 8C2 PLANNED across
roadmap/plan/README. This aligns the acceptance assertion with earned gates, not a weakened test.
No application, migration, API, frontend, configuration or worker bytes change in this follow-up.
Fresh focused/quality validation is required; full validation belongs to the bounded delivery
candidate before review/publication. Original failures and acceptance limitations remain intact.

During the 8C2 analysis entry check, the limitation register still globally deferred linked scans
and described every scan request as lacking idempotency. Those current claims are reconciled with
accepted 8C1 while preserving ordinary-scan limits, unverified worker readback, physical deployment
risks and the untriaged dashboard report. Planning paused at that documentary boundary; no runtime
behavior was invented or changed. The scoped 8C2 analysis then resumes from consistent owners.

### 8C2 analysis preflight

The [scoped preflight](../../sprint-8c2-preflight.md) inspects current contracts, callers,
authorization, migration/history/audit, normal findings, scan submission/recovery and test helpers
against accepted main `76e0f786`. It recommends one complete test-only acceptance slice under the
approved R1--R3 semantics, with the signed full-path PostgreSQL journey as the first work unit,
then outcome/authority/replay, fault/race/restart and retained-policy/installed-process closure.
No work unit alone is 8C2 acceptance. New architecture/product choices are not identified;
standing accepted-design workflow applies only after this completed analysis checkpoint.

Concrete helper gaps: current C1 HTTP records submission then calls private scan execution and
starts from service-built worker acknowledgment; older installed-worker seeds are EC2-only and
ineligible for attributed verification; old worker final guards forbid normal verification
finding changes; the packaged API no-work probe retains worker environment, which cannot be
reused as reader credential-isolation evidence. New sibling test guards/full-scope seed/managed
executor/closed reader-only installed shim must preserve all existing accepted assertions and
production hooks. No new API, schema, role, credential mode, queue or public worker launch.

8C2 remains PLANNED at analysis. No new runtime, test-matrix implementation, reviewer launch,
commit, push/PR/merge, live scope, operator migration or Sprint 9+ operation occurred. Original
C1 owner reconciliation and the strengthened accepted-status contract remain task-owned.

The analysis artifact and reconciled owners passed 102 contract/link checks in 3.65s, Ruff,
443-file format and whitespace checks, native exit 0. The added Markdown file accounts for the
additional link case; no new runtime or matrix test was added. Full new-candidate validation,
review and delivery remain required after implementation. Existing task changes and all historical
failed/qualified receipts are preserved.

### Approved 8C2 predictions and implementation checkpoint

The user approved continuation after the completed [8C2 preflight](../../sprint-8c2-preflight.md).
Standing routine workflow authorizes this accepted-design test-only slice; no new architectural
or design choice is identified. 8C2 is now IN PROGRESS, not accepted or published.

Implement the complete preflight matrix in four internal work units: signed full-path PostgreSQL
journey; outcome/authority/replay; fault/race/restart and caller ownership; retained-policy and
installed-process closure. The first joins genuine signed three-human API authority and the
installed offline worker to real managed scan submission, normal collection/rules/persistence and
READ receipt history. Independent connections must observe committed intent/audits and released
guard/scan/target locks before submission/provider construction. Preserve original history and
worker journal; normal findings may change only through unchanged scan reconciliation.

Use sibling test helpers and existing application/executor factories. Preserve every old accepted
worker guard and all production interfaces, schema, roles, credential modes and defaults. No
individual work unit completes 8C2. Targeted/full/PostgreSQL/security/container/browser validation,
exact-commit independent review and ordinary guarded delivery/exact-main gates remain required.
No live AWS/IdP/IAM/secrets/operator migration/deployment/production or Sprint 9+ is authorized.

First internal work-unit receipts: focused v1 stopped on the new test's incorrect phase name
(`ACKNOWLEDGED_UNVERIFIED` is worker output, not an API enum); no runtime failure or change.
The test now asserts the accepted `ACKNOWLEDGED` API phase. Focused v2 passed 21 cases in 66.62s:
four signed authority -> installed worker -> genuinely managed read-only scan -> sealed receipt
journeys (PASS/FAIL crossed with present/expected-absent KMS) and 17 status contracts. Independent
connections observed committed request/start audits and acquired guard/scan/target locks at both
submission and provider construction. Exactly one synthetic worker write, unchanged old immutable
history/journal, normal finding reconciliation and identical current-authorized replay were checked.
Owned temporary database cleanup succeeded; unrelated containers/data remained untouched. These
targeted receipts do not complete 8C2 or replace the remaining full matrix/delivery gates.

Subsequent local fault receipts remain retained. Focused v3 passed seven cases then failed the
new partial-scan finding expectation; accepted persistence requires complete-scan PASS to resolve,
so partial findings remain OPEN even when EC2-004 technically passes. V4 again passed seven then
stopped at the new assessment query's missing explicit composite identity; the test now uses exact
scan/control/resource IDs. V5 stopped before cases on a sanitized Docker build setup error. A
separate build of the unchanged Dockerfile passed; the original build cause is unconfirmed. Only
the uniquely labelled diagnostic image was removed, after ownership verification; it is rebuildable.

V6 passed 18 cases then stopped at the new immediate NOWAIT observer racing a legitimate replay
guard owner (200/503 instead of required 200/202). The observer now waits at most three seconds in
PostgreSQL; an admission caller retaining locks across submission still deadlocks its own probe
and must fail the SQL timeout. V7 passed both signed managed concurrency cases and caller ownership
in 31.68s (three cases). READ/list/request preserved pending inserts, updates and deletes with
zero service SQL and unchanged caller transactions; clean READ retained the caller transaction.
V8 passed 20 cases then stopped at the added negative probe's incorrect history-baseline placement.
The negative probe did raise PostgreSQL 55P03 while the guard was retained and succeed after release;
its final history comparison now uses pre-admission history, not the legitimately mutable RUNNING
scan. The neighboring concurrency receipt/history checks remain present. None of these repairs
changes runtime, auth, schema, credentials, verdicts, finding policy or any old accepted assertion.

The current 22-case PostgreSQL work-unit scope covers full signed/installed-worker/managed-reader
journeys, basic complete/inconclusive outcomes, identity denial, replay/active/attempt bounds,
admission commit loss with same-ID fresh application startup, one-shot/persistent receipt-audit
atomic rollback, concurrent signed admission and caller/lock-probe guards. Fresh application startup
is not fresh installed reader-process proof. Additional proof-substitution/time/mixed-findings,
cross-execution authority and quarantine, submission/capacity/terminal-commit loss, all four retained
scope generations/deployment-policy and installed reader-only API/scanner closure remain required.
Whole-candidate validation/review/delivery and 8D/8E are still outstanding; no live scope or later
sprint started. Current repository-wide lint, 446-file format and whitespace checks passed.

Corrected current-work-unit focused v9 passed **165 cases in 248.30s**, native exit 0 and no skips:
14 in `tests/integration/test_remediation_verification_acceptance_postgres.py`, eight in
`tests/integration/test_remediation_verification_recovery_postgres.py`, one in
`tests/api/test_remediation_verifications.py`, 40 in `tests/api/test_dashboard_api.py`, and all
102 in `tests/unit/contracts/` (57 Markdown links, two NIST display, 26 S3 contract and 17
readiness/status). The local runner uses `-x -vv --tb=short` and an explicitly self-owned disposable
TEST_DATABASE_URL; installed-worker cases own an additional isolated image/network/tmpfs database.
All 165 retained primary case rows are unique and passed. Ownership-checked database/process/network
cleanup succeeded; the two unrelated stopped containers remained untouched. All three worktrees,
77 branches and parent untracked skills remain preserved.

This is targeted work-unit acceptance only, not full regression, full 8C2 acceptance or publication.
Application, migrations, frontend, deployment configuration and worker runtime bytes remain
unchanged. Task changes are uncommitted on `codex/sprint-8c2-preflight` at accepted main `76e0f786`.
Continue the remaining matrix above, then freeze and run every whole-candidate gate before review
and delivery. Sprint 8/8C/8C2 remain IN PROGRESS; 8D/8E remain PLANNED and Sprint 9+ unstarted.

### Retained policy and scope work unit

The next test-only work unit extends the sibling full-scope seed with optional retained profile
and requested-service generation; default behavior and every earlier assertion remain intact.
`tests/integration/test_remediation_verification_policy_postgres.py` independently specifies all
four service/collector/resource-type contracts. The initial eight PASS/FAIL cases passed in 76.80s.
The completed 16-case module also checks same-ID fresh-application restart after lost admission
commit response for every generation, and disabled/mismatched scope or unsupported retained
catalog support before provider construction. Unsupported support is an explicit executor-resolver
fault, not corruption of persisted history or a new production catalog registration.

A real local deployment-policy file selects profile 8.2.0, catalog 0.13.0, GOV-001 instead of the
original EC2 controls, and changed S3 exposure/sensitive-bucket artifact content/versions. Manual
and restarted verification retain original profile 6.3.0/catalog 0.5.0, artifacts 1.0.0, exact
collectors and resource types. No latest-policy fallback or new artifact/profile insertion occurs.
Requests, receipts, signed READ/replay, actual normal assessment/finding outcomes, old immutable
history and the unchanged write journal are checked. Disabled/account/Region/catalog-support
recovery failures retain the original request/scan IDs and seal trusted FAILED/INCONCLUSIVE without
any reader-provider/fact call or writer resend. This is fresh application proof, not installed
reader-process proof or physical credential isolation.

Focused v10 passed **181 unique cases in 410.76s**, native exit 0 and no skips: 16 new policy cases,
the previous 22 integrated workflow/fault/concurrency/caller cases, 41 existing API checks and all
102 contract/link checks. Primary per-file/per-case rows match that scope. Ownership-checked
temporary database/process/network cleanup succeeded and unrelated stopped containers remain.
Application, worker, migration, frontend and deployment runtime sources remain unchanged.

8C2 remains IN PROGRESS. Next required work is the separately installed reader-only API/scanner
journey and fresh-process recovery, with exact source identity and a closed synthetic transport;
do not reuse the old packaged no-work probe's writer environment. Remaining forged proof/history,
cross-execution authority/quarantine and submission/capacity/terminal-commit fault coverage also
remain required, followed by whole-candidate regression/integration/security/container/browser,
exact-commit independent review and ordinary guarded delivery/exact-main gates. 8D/8E and the full
Sprint 8 goal remain outstanding; no live enablement or Sprint 9+ work has begun.

### Installed reader and bounded coherence repair

New sibling test-only `verification_process_harness.py` and `verification_process_runtime.py`
launch the unchanged installed API over local HTTP in the owned restricted image/network/schema.
They mount only the reader shim and closed scenario as read-only files, retain the existing
non-root/read-only/no-capability/no-new-privileges/no-published-port/ownership/cleanup guards,
and leave the old worker harness/runtime untouched. Exact installed hashes cover every app Python
and packaged JSON source, including authentication, routes, executor, collectors, rules, persistence
and receipt proof. Production images still contain no tests/scripts.

The real production OIDC verifier checks signed bearer tokens against controlled public JWKS.
The real managed executor, AWS session/client factory, normal SDK credential chain, collectors,
rules, persistence and READ/replay/list paths remain active. A fresh synthetic reader ECS metadata
URI/role supplies ephemeral credentials distinct from the writer; no worker configuration, static
keys, profiles, shared credential files or write factory is provided. SDK response stubbing replaces
only cloud response I/O and still validates SDK parameters/response shapes. Closed HTTP/socket
transport forbids external provider access; metadata, submission, provider and every SDK boundary
use independent PostgreSQL intent/audit/guard/scan/target-lock probes with closed managed sessions.
Synthetic isolation is not physical deployed ECS/IAM/network or live-provider proof.

Initial installed-reader v1 passed five cases in 69.15s: complete PASS/FAIL, STS-account denial before
facts, production-OIDC default-off admission without worker environment, and same-ID recovery in a
fresh installed process after deliberate pre-provider interruption (owned child exit 90). Added
independent guards cover 24 malformed report boundaries and ten unsafe container/mount variants.
Their initial focused run passed 34 cases in 3.55s. Strengthened installed v2 passed two cases then
stopped at a generic wrong-account harness guard; its exact original cause is unconfirmed. A
sanitized one-case v3 rerun passed in 20.05s and does not establish the cause of v2.

A separate controlled interleaving produced concrete evidence: valid atomic terminal scan/receipt
history was read using cached RUNNING scan state and returned 409 `remediation_provenance_conflict`
instead of 200. The first fixture attempt had a missing Scan import; after that test-only correction,
the unfixed runtime regression failed deterministically in 14.20s. The bounded accepted-contract
repair in `RemediationVerificationService._receipt` refreshes only the cached mutable scan when
a committed receipt is visible. It adds no writes, row locks, retries, caller commit/rollback,
schema, role, credentials, API fields or new verdict semantics. It keeps genuine inconsistent
RUNNING/receipt history fail-closed. This material runtime difference from the original test-only
prediction is a repair, not an architectural change or a claim that the v2 cause is proven.

Repair-focused v1 passed **220 unique cases in 264.79s**, native exit 0/no skips: both signed
COMPLETED/FAILED read-interleaving regressions, five installed reader journeys, 34 new report/
container guards, 31 existing verification unit cases, 31 PostgreSQL verification/history cases
and all 117 existing worker-runtime guards. Primary case rows/per-file counts match; owned
temporary database/process/network cleanup succeeded and unrelated stopped containers remain.
Full new-candidate regression, remaining matrix, exact-commit review and delivery are still required.

### 8C2 authority and fault matrix continuation — 2026-10-14

Signed authority v1 passed one case then failed a new fixture's UUID JSON serialization
(25.30s). After that test-only correction, all five cases passed in 48.95s, with current-role,
actor/operation/key, original expiry/revocation and quarantine/late-ACK boundaries intact.
Owned temporary database/process/network cleanup succeeded; the write grant was never renewed.

Fault-fixture failures remain historical: v1 intercepted a SQLAlchemy flush child rather than
the root SQL commit (three passed/one failed, 41.57s); v2 then exposed weak identity-map references
at the root boundary (two passed/one failed, 29.32s); v3 omitted the normal FINDING_RESOLVED audit
from its complete-scan expectation (three passed/one failed, 38.47s). Corrected root before/after
commit cases passed in v4, which stopped on a clock fixture using later worker readback instead
of the ACK event (two passed/one failed, 31.41s; two deselected). No application repair was needed
for these new fixture errors, and valid assertions/history guards were not removed or bypassed.

Fault v5 passed equal/older collection and all six forged incoming assessment-proof cases before
stopping on omitted required null receipt fields in the corrupt-intent fixture (eight passed/
one failed, 80.31s; four deselected). Corrected v6 passed all four rehashed corrupt-request
READ/replay/startup cases and mixed historical/current findings in 52.58s (12 deselected).
Each run cleaned only its owned disposable database/process resources. No subset is represented
as the full matrix or full regression; [coverage and test-boundary qualifications](../../sprint-8c2-preflight.md#implementation-coverage-after-approval)
map the local candidate to the approved predictions.

The remaining planned restart boundary adds a test-only installed reader interruption during
fact collection, alongside the original pre-provider case, with six independent malformed-report
negatives. The complete combined matrix is now running before source freeze and full acceptance.
8C2/8C/Sprint 8 remain IN PROGRESS; 8D/8E and Sprint 9+ have not started. Accepted main, migration
0010, defaults, credentials and all production/live-operation boundaries remain unchanged.

### 8C2 complete targeted matrix and source freeze — 2026-10-14

Combined matrix v1 passed **170 unique cases in 810.53s**, native exit 0, no warnings or skips:
68 new PostgreSQL journeys across six files, 40 independent reader-report/container guards,
31 existing verification unit cases and 31 existing PostgreSQL verification/history cases.
The primary audit matches every collected identity and per-file count (99 PostgreSQL cases/
seven files), with SHA-256 `674ded4285f32419d31367f93ca0e45997cab8c68d7cb51bc952fad490665e56`.
Both installed restart boundaries passed, including real STS and a read-only fact call before
interruption. Owned temporary database/process/network cleanup succeeded. This completes the
targeted matrix, not full C2 acceptance or delivery.

Unchanged pinned Node 24.19.0/pnpm 11.19.0 dashboard typecheck, lint, 139 unit cases/eight files
and production build passed. Owner/link checks passed 74 cases in 3.77s; Ruff and 453-file
formatting and whitespace checks passed. Compose config validated without an operator env file.
Local image `sha256:6d8d10534eca7eccc8ee173056ef2e19f4ea28e90b07e61ef9a99b3a09be5f1a`
passed network-disabled/read-only/non-root Python 3.12.15 startup with fresh temporary SQLite:
migration 0010, health/readiness, all three verification bearer routes and both default-off
admissions. No operator database, live provider, IAM or deployment is involved.

Current collection is frozen at **3,755 backend cases/163 files**, including **696 PostgreSQL
cases/33 files**. The next full run must execute that entire scope without skips and preserve
the frozen source. Browser acceptance, full regression, exact-commit independent review and all
candidate/exact-main delivery audits remain open. The current 25 task paths remain unstaged on
`codex/sprint-8c2-preflight`; remote accepted main is still `76e0f786`, all three worktrees and
existing branches/skills are preserved. 8C2/8C/Sprint 8 remain IN PROGRESS; no 8D/8E or Sprint 9+
implementation, commit, publication, merge or live operation occurred in this checkpoint.

### 8C2 complete local regression and browser acceptance — 2026-10-14

Full regression v1 passed **3,755 unique cases/163 files in 3796.80s**, native exit 0, including
all **696 PostgreSQL cases/33 files** without skips. The same 19 existing SQLite datetime-adapter
warnings remain. The complete primary case/per-file audit passed with SHA-256
`dec191dd9c68f49790cff45dd5f34e6014ca95cee168f8f7e9dfb6b8985887b8` and successful owned temporary
database cleanup. All **530 frozen repository files** matched their pre-run hashes before any
receipt prose changed. Runtime, tests, migrations, configuration and frontend stayed unchanged.

The initial audit helper incorrectly normalized backslashes inside 52 parameter IDs as path
separators. Correcting only filename normalization preserved those literal hostile/control-input
labels. Recollection then exposed one existing `test_ec2` case's collection-time `str(uuid4())`
parameter. A closed, source-proven semantic identity handles only that exact UUID4 case; exactly
one occurrence is required and normalized duplicates remain failures. Eight positive/negative
identity checks passed. Both failed audit receipts, original collection, corrected collection
and original primary log remain retained. Per-file scope never changed; no application test,
assertion, skip or execution result was modified to obtain a passing audit.

Current-source Linux headless browser v3 passed **all 76 unique journeys in 1.7m**, native exit 0:
38 Chromium and 38 Firefox cases, one worker, zero retries/skips, through genuine controlled
OIDC login, bearer API, disposable PostgreSQL, rendering, navigation, logout and expiry. Every
retained primary case identity matches the unchanged native collection. Primary SHA-256 is
`19c529894fb554fa3107586c96d6b36de2635e1977eba745e91e2adb1bc61dd1`. All 529 included frozen
source paths matched inside the non-root isolated image; only the `.env.example` template was
excluded. Node 24.19.0, pnpm 11.19.0 and Playwright 1.63.0 remain pinned; this browser-test runtime
used Python 3.12.3, distinct from the API image's 3.12.15 and host regression's 3.14.5.
Owned browser database/process/internal network cleanup succeeded; operator resources were untouched.

Browser setup failures remain retained: a raw local image SHA was initially interpreted as a
registry name; a collision-checked alias preserved the existing base image. The first browser
wrapper passed source/version probes but stopped before browser launch on pnpm's non-interactive
reinstall after workspace relocation. A YAML-as-JavaScript metadata probe failed; plain metadata
inspection succeeded. A second wrapper was started while its corrected image build was still
live and failed closed before probe success; its exact original classification is unconfirmed.
After terminal build success at the original tooling path, the full v3 acceptance above passed.
The first native case collection was sandbox-denied before cases ran; the separately authorized
read-only collection passed. No dependency, security header, browser configuration, retry,
timeout or valid assertion was changed. Current complete retained proof does not diagnose the
earlier native Firefox launch failure, four Linux navigation failures or generic reader-v2 guard.

The scoped delivery auditor now requires this complete 3,755/163/696/33 scope, protected old/new
process coverage, unchanged 139/76 frontend/browser identities, all 18 quality/image/cleanup
steps and exact checkout identity. Fourteen synthetic auditor checks passed; they are verifier
tests, not actual candidate CI. Receipt-only owner edits follow the frozen full run and need
fresh owner/quality checks. Exact-commit independent review, both complete candidate primary
audits, ordinary expected-head guarded merge and complete exact-main audit remain open.
8C2/8C/Sprint 8 stay IN PROGRESS; no 8D/8E or Sprint 9+ implementation, live AWS/IdP/IAM/secret,
operator-database, deployment or production operation is authorized or performed.

Post-receipt owner checks passed **102 cases in 3.16s**; Ruff, 453-file formatting and whitespace
checks passed. Hash comparison confirms only CHANGELOG, ROADMAP and this plan differ from the
530-file full-run freeze; every runtime/test/migration/config/frontend byte is unchanged. The
25-path candidate is ready for a logical scoped commit and exact-commit independent review,
not publication or acceptance before that review and the remaining delivery gates succeed.

### Accepted 8C2 integrated verification acceptance — 2026-10-14

**8C2 and 8C are COMPLETE** as default-off offline code/test acceptance through
[PR #69](https://github.com/jnc247s/cloud-security-automation/pull/69), ordinarily merged at
`599e155090b654f09987f3d48e8c431b116ba7c4`. Original test-only predictions, material bounded
READ-COMMITTED repair, failed fixtures/helpers/setup runs and qualified historical evidence
remain intact. This receipt supersedes their pending gates, not their original scope or limits.
Sprint 8 remains IN PROGRESS; 8D/8E remain PLANNED, and this plan remains active.

Exact-commit independent REVIEW_PASS covers `d7d421eaf8afd06c474b210c4ff776339c471f01`, reviewed
tree `6cc196972e4d236a93bcf58d9b081bbff01c8854`, with no actionable findings after all 25 paths
and receipt-refresh callers were inspected. Fresh independent executions passed 142 reader
guards/contracts in 3.30s and 29 PostgreSQL/installed cases in 308.29s, without warnings/skips,
plus Ruff, 453-file formatting and committed whitespace. Saved 170-case matrix, complete
3,755-case backend and 76-case browser primaries were independently audited, not rerun.
Frontend/image/Compose/startup remained the carried local receipts, not independent reruns.

| Delivery gate | Complete first-attempt primary result |
| --- | --- |
| [Push CI 38516828748](https://github.com/jnc247s/cloud-security-automation/actions/runs/38516828748), job 115697407639 | 3,755 backend cases in 3671.23s; reviewed feature checkout `d7d421e` |
| [PR CI 38516850088](https://github.com/jnc247s/cloud-security-automation/actions/runs/38516850088), job 115697473180 | 3,755 backend cases in 3689.49s; synthetic checkout `3f928d1`, exact C1/feature parents |
| [Exact-main CI 38523209002](https://github.com/jnc247s/cloud-security-automation/actions/runs/38523209002), job 115717457610 | 3,755 backend cases in 3632.57s; exact merged checkout `599e155` |

Each full primary matched all 163 backend files, all 696 PostgreSQL cases/33 files without
skips, protected old/new process coverage, 19 existing SQLite warnings, unchanged 139 frontend
cases/eight files and all 76 unique browser identities (38 Chromium/38 Firefox, one worker,
zero retries), Ruff/453-file formatting, image build and all 18 successful job/cleanup steps.
Primary SHA-256 values, in table order, are
`dfd36f8e3c262900abb141f364e82d35bb5f28f8ba18d2c15ba0056ec679374f`,
`53fc6ac18113e5495547e2217bc756a9ff890cc6a549f3f426ce26770338931c` and
`9d62c614dd6077d7c9eeb033820c6a517c863644daae496e8507ebaf5cec90c0`.

The standing-authorized merge used the exact reviewed head without force/admin/protection
bypass or branch deletion. Merged tree equals the reviewed tree; its parents are exactly
`76e0f7866dddb41d3ccd61913fbbeb36d594808e` and the reviewed feature head. The feature branch,
all existing worktrees and unrelated parent skills were retained. Clean local main was normally
fast-forwarded to the accepted merge, then `codex/sprint-8d-preflight` began owner reconciliation
and analysis preparation only; no 8D runtime/UI implementation or design approval is inferred.

Migration 0010, schemas, API bodies, roles, credentials, worker runtime, technical results and
finding/remediation lifecycle separation remain unchanged. Current-source browser proof does
not diagnose earlier Firefox/navigation/reader failures or repair the user's scan-picker/back-
navigation report. Physical ECS/IAM/network isolation, live-provider/key/workload compatibility,
operator migrations, deployment and production remain separately authorized and unperformed.
No live AWS/IdP/IAM/secret operation or Sprint 9+ work occurred. Next: separate 8D preflight,
stop for newly required architecture/design choices, then accepted dashboard work and 8E.

### 8D analysis preflight and pending design decision — 2026-10-14

The [8D preflight](../../sprint-8d-preflight.md) inspects the current React/Vite/FastAPI
session/BFF/API/service/history/audit boundaries, callers and accepted tests. It recommends
sequential READ history/navigation, a narrowly opt-in prepared-operation/manual workflow, then
complete integrated UI acceptance. D1--D3 are proposed browser authority/recovery/scope choices,
not approved predictions. Standing routine workflow cannot decide them; stop before implementing
the new contracts. 8D/8E remain PLANNED, Sprint 8 IN PROGRESS and the full goal ACTIVE.

Source triage confirms persistent history/UUID selection and browser Back but no explicit
clear/focus-return control or browser scan POST. Mobile sections stack and the previously
demonstrated pointer/layout race remains. The original operator build/data/cause is not
reproduced or attributed. No general scan launcher, worker launch, API/schema/default/credential
change, live provider or later-sprint implementation is inferred from the preflight.

Fresh existing checks passed 219 dashboard/investigation/remediation API, security and owner
cases in 70.14s, without warnings/skips, and 139 frontend cases/eight files in 26.63s using the
already-installed exact Node/pnpm pins. These are not tests of the proposed browser mutations.
The global pnpm mismatch stopped before tests; an isolated async probe reproduced restricted
startup stalling and completed outside that environment. Only revalidated owned test/probe
children were stopped; unchanged authorized-local tests passed. Original receipts remain and
no application defect/platform mechanism is claimed. Final post-preflight contracts/quality
passed 103 cases in 0.43s, plus Ruff/454-file formatting/whitespace. Documentation-only current-scope/migration/API-index discrepancies were
reconciled without rewriting old predictions or modifying runtime. Existing branches/worktrees/
skills and the uncommitted acceptance-owner refresh remain preserved; no new agent, commit,
publication, merge, live AWS/IdP/IAM/secret/operator-database/deployment or Sprint 9+ action.

## Approved 8D predictions

On 2026-10-14, after receiving the D1--D3 design summary and full preflight, the user requested
“Continue and implement”. This approves that package and the following sequential plan; it
does not authorize live AWS, worker operation, deployment, IAM/secrets or operator databases.
The original analysis checkpoint remains historical. The full Sprint 8 goal is active again.

- D1: reuse React/TypeScript/Vite and the authenticated FastAPI READ/bearer boundary. Add six
  typed history GETs. Browser writes are independently default-off and require enabled OIDC,
  exact Origin/fetch-site, CSRF/session context, fresh identity/capability, fixed typed operations,
  bounded input and renewed API checks. Only verified non-secret issuer/feature hints are additive.
- D2: prepare a server UUID and frozen operation in bounded session-scoped process-local memory
  (16/session, 256 total, five-minute preparation/session deadline); explicitly confirm/submit.
  Same-session reload recovers coordination without Web Storage. Explicit retry preserves actor,
  key and input. No automatic retry, replacement intent or renewed grant. Forwarded uncertainty
  is not cancellation; process/session loss requires manual immutable-history reconciliation.
- D3: bounded scan selection/back/focus/stable-control repair and remediation workflow only.
  Ordinary Start scan remains excluded. Separate historical approval/current blockers, execution
  phase/reservation, verification verdict, technical results and finding disposition. Browser
  admission never launches the isolated worker; quarantine/late ACK never becomes verified.

### Sequential implementation and acceptance

1. **8D1 IN PROGRESS:** six typed READ adapters; guarded proposal/decision, v1/v2 execution and
   verification views; exact finding/occurrence bindings; separate states; explicit navigation
   clearing/focus return and stable scan controls. No mutations, schema/default/credential changes.
2. **8D2 PLANNED:** approved default-off preparation/confirmation/manual proposal, decision,
   revocation, admission and linked-verification forms, bounded recovery and signed three-human
   API/history path. No generic POST proxy, public worker launcher or ordinary scan POST.
3. **8D3 PLANNED:** full authority/replay/expiry/logout/cross-tab/response-loss/reload/capacity/race
   acceptance; offline installed worker, managed read-only verification, disposable PostgreSQL;
   two-browser, keyboard/mobile and retained-history/default-off compatibility.

Each slice requires targeted tests followed by Ruff/format/full backend regression, relevant
disposable PostgreSQL, frontend type/lint/unit/build, browser and Compose/image validation;
exact-commit independent review and required delivery/CI/merge/exact-main gates precede the next
slice. Reuse the existing reviewer under standing authorization, without new parallel agents.
8E whole-sprint acceptance/closeout remains required. Preserve every failed receipt, old
prediction, unrelated skill, existing branch/worktree and accepted 0--7/8A--8C contract.

### Local 8D1 implementation checkpoint

Implemented the six fixed typed BFF GETs through `Dashboard.read`, on-demand proposal/decision,
v1-human/v2-worker execution and verification history from exact assessment/finding context,
closed display schemas and immutable selection/cross-history bindings. Approval/current blockers,
phase/reservation, verification verdict, technical results and finding handling stay separate.
Other retained occurrences are explicitly labeled instead of substituted. Added explicit Back
and focus return, stable UUID/paging placement above changing history and informative empty states.
No browser POST, bootstrap fields, new flags, schemas/defaults, service interfaces, credentials,
worker operation or ordinary Start scan is included. Existing React/Vite/FastAPI remains intact.

Added signed all-role READ, typed injection, expiry/forged-token/context, in-flight logout,
unchanged SQLite history and default-off coverage; frontend guard/UI/navigation regressions;
12 intended new browser cases across both projects, using real services and disposable PostgreSQL
with AWS offline. The browser fixture adds authority/verification history before legacy scans
can stale its baseline and scopes the old resolved-finding selector to its original scan. Old
browser cases/assertions/retries/timeouts remain unchanged. New browser journeys are not run yet.

Local checks passed, without skips/warnings:

- `pytest tests/api/test_dashboard_remediation_api.py -q`: initial 37 cases in 28.67s.
- `pytest tests/api/test_dashboard_remediation_api.py tests/api/test_dashboard_api.py
  tests/api/test_dashboard_investigation_api.py tests/unit/security tests/unit/contracts -q`:
  254 cases in 92.58s before 18 additional session-denial cases.
- `pytest tests/api/test_dashboard_remediation_api.py tests/unit/test_dashboard_config.py -q`:
  expanded 74 cases in 39.04s; added default-off route-installation case separately passed in 0.57s.
- Pinned Node 24.19.0/pnpm 11.19.0 focused frontend: 73 cases in 3.74s; complete frontend:
  208 cases/10 files in 8.26s, typecheck/lint/build passed (build 602ms). Final e2e edits passed
  typecheck/lint. Ruff, 456-file format check and whitespace passed.

Preserved setup failures: global Python collection lacked the existing pinned `httpx2` (no tests
ran); corrected to the existing parent virtual environment without installing/changing packages.
An explicit phase-helper type corrected two TypeScript inference diagnostics. Restricted temporary
storage caused ENOENT in two frontend suites; the unchanged tests passed with an owned stable TEMP.
Python formatting/import diagnostics were corrected, not suppressed. These are not full acceptance.

Docker-dependent verification is stopped at engine readiness. Desktop start reports already
running, but its local engine/status requests stalled; the Docker WSL VM was stopped and its
socket absent. Ordinary restart requested a 45-second bound but did not return after more than
two minutes; its operation outcome is unconfirmed. Only precisely revalidated owned diagnostic
clients were stopped, not Desktop/backend/WSL/user containers. A fresh owner-bounded local engine
probe timed out after 15 seconds. No disposable database/container has been created in this slice;
no Docker reset/data deletion occurred. Docker must become ready before complete regression,
PostgreSQL, two-browser, Compose/image/startup, exact-commit independent review and delivery gates.
Do not run the full suite with PostgreSQL skipped or advance to 8D2 to bypass this dependency.

Current branch is `codex/sprint-8d-preflight`, still at accepted `599e1550`; remote main was checked
and matches. The original 14 task-owned dirty paths plus scoped implementation remain uncommitted,
unstaged and unpublished. All 78 branches/three worktrees are preserved, and unrelated skills
were untouched/excluded. No new reviewer, live AWS/IdP/IAM/secret/operator-database/deployment,
production operation or Sprint 9+ work occurred. 8D1/8D/Sprint 8 are not accepted or complete.

### Complete local 8D1 validation 2026-10-15

After the user reported Docker running and requested continuation, the explicitly local engine
responded with version 29.5.2 outside the restricted sandbox. The restricted probe was denied
permission; it is not evidence that the restored engine was unhealthy. Earlier Docker startup
failures, stop/restart attempts and recoverable socket-only folder preservation remain historical.
The second socket-folder rename was denied and made no change. Its Administrator prompt was
never authorized or launched; the existing recoverable backup remains preserved. No reset,
permission change or deletion of operator data occurred in this workflow. The user's subsequent
engine recovery is observed, not attributed to an unproven repair cause.

Current-source focused dashboard/remediation/investigation/security/owner checks passed
**273 cases in 119.92s**, without warnings/skips. Pinned Node 24.19.0/pnpm 11.19.0 frontend
typecheck/lint, **208 cases/10 files in 34.26s**, and build (693ms) passed using an owned TEMP.
Ruff, 456-file formatting and whitespace checks passed. No dependency or tool pin changed.

Complete regression passed **3,812 unique cases/164 files in 4029.21s**, native exit 0, including
all **696 PostgreSQL cases/33 files** without skips. The same 19 existing SQLite datetime-adapter
warnings remain. Every primary case identity and per-file count matched the current collection;
the closed semantic identity for the one existing collection-generated UUID4 parameter remains
unchanged. Primary SHA-256 is
`d4b603fd5fe4312b23d74758942ba353772e9f2c3fbfd618a830d2f2c4e0c1b7`.
Owned temporary database/process/network cleanup succeeded. All **539 frozen source paths**
matched their path sets and bytes before these receipt edits; runtime/tests/migrations/configuration
and frontend were unchanged throughout the full run.

The 12 new signed READ/history/verdict/keyboard Back and desktop/mobile pointer journeys passed
in 32.6s. The first complete browser run failed: 18 passed, one existing NIST session-expiry test
timed out at 30 seconds, 69 did not run, and one secondary error was reported. Diagnostics saw a
current report 401 and session request without its response. The unchanged isolated expiry
journey subsequently passed in both browsers (13.7s), observing session 200/authenticated false
and cleared UI. One bounded complete recheck then passed **all 88 unique journeys in 2.1m**:
44 Chromium/44 Firefox, one worker, zero retries/skips. Every native case identity matched,
including all 76 accepted journeys and 12 additions. Assertions, timeouts, security headers and
browser settings were unchanged. Primary SHA-256 is
`b3638bd522140b149a4e28570b2acbaecf4297ffe9186c13e5182530ba2b45a3`.
The first failure remains retained; later passes do not establish its cause or an application
repair. No further browser rerun is inferred. Owned browser database/process/network cleanup
succeeded. The non-root offline image verified all 538 included frozen paths and exact Node/pnpm/
Playwright 1.63.0; only `.env.example` was excluded. Its Python was 3.12.3, distinct from host
regression 3.14.5 and the API image's 3.12.15.

Compose configuration passed without an operator env file. API image
`sha256:2e84ec243bc1d2cfbaa5b70f4f31b65842933e95b90424bf8d4c407bf19f6cca` passed non-root,
network-disabled, read-only-root startup with fresh temporary SQLite: migration 0010,
health/readiness, bearer-protected verification routes and default-off admission/verification.
These are offline/local gates, not physical ECS/IAM/network isolation or live-provider proof.

The scoped delivery verifier requires complete 3,812/164/696/33 backend scope, 208 frontend cases,
88 browser identities, protected process/verification coverage and all 18 quality/image/cleanup
steps with exact checkout identity. Seventeen synthetic verifier checks passed; they are not
actual candidate CI. The scoped observer/watch scripts passed syntax checks without launching CI.
Receipt-only owner edits require fresh owner/quality checks. Then a logical scoped commit and
exact-commit independent review precede both complete candidate primary audits, ordinary
expected-head guarded merge and complete exact-main audit. Those gates remain open.

The same 27 task paths remain on `codex/sprint-8d-preflight`, with accepted main still `599e1550`.
All 78 branches/three worktrees and unrelated parent skill files are preserved. No new reviewer,
commit, push, PR, merge, browser mutation, live AWS/IdP/IAM/secret, operator-database, deployment
or Sprint 9+ operation occurred in this checkpoint. **8D1/8D/Sprint 8 remain IN PROGRESS**;
8D2/8D3 and 8E have not started. No local receipt alone accepts the slice or completes the goal.

Post-receipt owner checks passed 103 cases in 0.79s without warnings/skips; Ruff, 456-file
formatting and whitespace passed. Hash/path comparison confirms that only CHANGELOG, ROADMAP
and this plan differ from the full-run freeze. Every runtime/test/migration/configuration and
frontend byte remains unchanged. This is ready for scoped commit and exact-commit review,
not publication or slice acceptance before the remaining gates pass.
