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
| 8B | Isolated single-action worker, fresh preconditions, recovery | IN PROGRESS |
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
| 8B2 | PLANNED | Isolated disabled single-action AWS worker and fresh checks/dispatch/recovery, after accepted 8B1 |
| 8B3 | PLANNED | Integrated offline fault/security/container acceptance and 8B closeout, after accepted 8B2 |

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
