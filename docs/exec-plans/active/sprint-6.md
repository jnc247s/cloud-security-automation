# Sprint 6 — Production Security Controls

Plan state: 6A through 6E COMPLETE and merged. 6F.1 is authorized and IN PROGRESS;
6F.2, 6G and 6H remain unstarted.

## 6F.1 publication authorization — 2026-10-01

After independent REVIEW_PASS and the successful final local acceptance checkpoint below,
the user approved committing, pushing and opening the 6F.1 pull request. Publish only the
reviewed LOG-002/003 slice, its separately approved persistence repair, tests and owner
documentation on `codex/sprint-6f1-cloudtrail-coverage-integrity`, based on accepted
`49500c95c78870d72e6179882bae4e6379cdd6d0`. The 35-file scope excludes the unrelated
parent-checkout skill files and preserves the accepted 6E.3 checkout. Use a normal push;
do not force-push or merge. Main, production, live AWS and later slices remain out of scope.

Publication is pending. The recorded 274 focused / 2,125 full / 171 PostgreSQL no-skip result,
quality/container gates and independent review remain applicable to unchanged runtime/tests;
authorization-only documentation edits require fresh contract/link and whitespace checks.
Verify final-commit GitHub CI before human merge acceptance. This supersedes earlier publication
authorization blockers only; 6F.1 stays IN PROGRESS until the remaining acceptance gates pass.

## 6F.1 independent review and final local checkpoint — 2026-10-01

The single user-authorized read-only reviewer inspected all 35 changed files, including every
untracked source/test/documentation file, and the relevant source-of-truth contracts. Initial
result: **0 CRITICAL, 0 HIGH, 1 MEDIUM, 0 LOW**. Ordinary Python equality admitted integer or
floating-point substitutes for boolean projection/proof values. The reviewer reproduced both
a malformed projection still producing a decisive result and a rehashed LOG-003 proof containing
integer `1` being persisted. This broke exact JSON type binding, not the underlying source's
explicit enabled/disabled setting. No other actionable finding was identified.

The correction uses strict boolean projection identity, recursively type-sensitive selector
projection comparison, and exact JSON type comparison for candidate proofs only in new schema
`1.8.0`. Immutable evidence containers remain supported; historical schema comparison behavior
is unchanged. No contract/profile/catalog/evaluator version, source requirement, collector,
permission, API/auth interface or migration changed. Regression coverage adds **52 tests**:
20 engine projection cases, 16 SQLite atomic rehashed-proof rejection cases and 16 equivalent
PostgreSQL cases, covering integer/float substitutes for true/false and nested selector values.
All **36 new engine/SQLite tests failed before the correction**, then passed after it.

The same reviewer independently passed **36 correction tests**, replayed the original
reproducers, inspected the complete correction and returned **REVIEW_PASS with zero unresolved
findings**. Its original bounded diagnostic run also passed 55 rule/migration tests. Each
reviewer test run reported one existing Starlette warning. The reviewer made no checkout edits,
created no container, accessed no live AWS/operator database, and did not delegate further.

After the runtime correction, the unchanged `scripts.validate` runner reran the complete
focused command recorded below with a fresh task-owned temporary directory and its own
loopback-only disposable PostgreSQL 16 runtime. **274 focused checks passed**, no skips:
150 rule/SQLite/HTTP/migration/foundation checks, 42 PostgreSQL control/persistence/HTTP checks,
seven PostgreSQL migration checks and 75 documentation/contract checks. Ruff lint and formatting
passed (**312 Python files**). The full `python -m pytest` run passed **2,125 tests**, including
all **171 PostgreSQL integration cases**, **no skips**, in 258.04 seconds. Focused and full
runs each reported 20 existing dependency warnings. Whitespace, Compose and the API image build
passed. The runner removed only its uniquely named disposable database; no user database,
production migration or live AWS operation was performed. No runtime/test file changed after
this successful run; only final documentation closeout follows it.

This supersedes the pending-review and earlier 2,073-test checkpoint without rewriting those
historical records. Current README, roadmap, metadata and design/security owners distinguish
the reviewed local implementation from the accepted baseline. Final closeout passed **75
documentation/contract checks** (one existing Starlette warning), Ruff lint, formatting and
tracked/untracked whitespace across all 35 changed files. Private-key/AWS-key marker inspection
found no matches, and the exact subset-10 manifest hash matched. The README-inclusive local
image rebuild passed. The same reviewer checked final documentation/governance consistency
and confirmed prior REVIEW_PASS remains applicable with zero unresolved findings. These
documentation-only edits do not invalidate the recorded runtime/PostgreSQL regression result.

Git remains local/uncommitted on `codex/sprint-6f1-cloudtrail-coverage-integrity`, HEAD/base
`49500c95c78870d72e6179882bae4e6379cdd6d0`. The unrelated parent skill files and accepted 6E.3
checkout remain preserved. Local migration head is `20261001_0005`; accepted baseline head is
still `20260924_0004`. No commit, push, PR or merge occurred. Publication is unauthorized;
final-commit CI and human merge acceptance remain pending. 6F.1 remains IN PROGRESS, not
COMPLETE; 6F.2, 6G, 6H and later work were not started.

## 6F.1 independent review authorization — 2026-10-01

After all local validation gates passed, the user answered yes to launching one read-only
independent reviewer for 6F.1 and its separately approved persistence repair. Review all
tracked changes and untracked source/test/documentation files against accepted base
`49500c95c78870d72e6179882bae4e6379cdd6d0`, covering correctness, security, data integrity,
historical compatibility, migration safety, acceptance coverage and documentation consistency.
The reviewer may report findings and perform safe diagnostic checks, but must not edit the
checkout, publish, merge, touch production/live AWS, start later slices or delegate further.
Review is pending. This supersedes earlier review-authorization blockers only; publication,
merge approval and later-slice authorization remain separate. 6F.1 stays IN PROGRESS.

## 6F.1 PostgreSQL and container validation checkpoint — 2026-10-01

The user reported that Docker was running. The engine responded successfully (29.5.2), and
the preserved branch, HEAD/base and uncommitted changes matched the persistence-repair
checkpoint below. This checkpoint supersedes its Docker/PostgreSQL/image blocker; it does not
change earlier validation records or authorize review, publication, merging or later slices.

The unchanged `scripts.validate` runner completed the exact focused command recorded below,
using a fresh task-owned pytest temporary directory and its own loopback-only, disposable
PostgreSQL 16 container. It never reused an operator `DATABASE_URL` or `TEST_DATABASE_URL`.
All **222 focused checks passed**, no skips: 114 rule/SQLite control/HTTP/migration/foundation
checks, 26 PostgreSQL control/persistence/HTTP checks, seven PostgreSQL migration checks and
75 documentation/contract checks. Ruff lint passed and formatting passed for **312 Python files**.
The complete `python -m pytest` regression passed **2,073 tests**, including all **155
PostgreSQL integration cases**, **no skips**, in 242.40 seconds. Focused and full runs each
reported 20 existing dependency warnings (one Starlette and 19 SQLite datetime-adapter warnings).

Tracked whitespace, Docker Compose configuration and the API image build passed. The runner
removed only its uniquely named disposable database; no user database, Docker data reset,
production migration or live AWS operation occurred. No runtime or test correction was needed
after the recorded repair. Post-run README/roadmap/plan/metadata closeout passed all **75
documentation/contract checks**, one existing Starlette warning, Ruff lint and formatting.
Tracked/untracked whitespace and private-key/AWS-key marker inspection passed for all **35
changed files**, and the subset-10 hash matched its exact manifest. Documentation-only edits
do not invalidate the recorded full runtime/PostgreSQL result; the local image was rebuilt
to include the final README.

LOG-002/003 remain opt-in in `0.11.0`, with shared engine/persistence source proofs. Default
and historical releases, collectors, AWS permissions, authentication and generic API fields
remain unchanged. Local migration head is `20261001_0005`; accepted baseline head remains
`20260924_0004` until this slice is accepted and merged. The earlier four migrations remain
unchanged. The unrelated parent-checkout skill files and accepted 6E.3 checkout are preserved.

Git remains uncommitted on `codex/sprint-6f1-cloudtrail-coverage-integrity`, HEAD/base
`49500c95c78870d72e6179882bae4e6379cdd6d0`, in the reused worktree. No agent was launched,
and independent review remains separately unauthorized and pending. No commit, push, PR or
merge occurred. 6F.1 remains IN PROGRESS, not COMPLETE; 6F.2, 6G, 6H and later work were not
started. The next gate is explicit authorization for independent read-only review.

## 6F.1 bounded persistence repair authorization — 2026-10-01

The user approved the proposed narrowly scoped shared persistence fix, including an additive
migration if needed, and continuation of 6F.1 validation. This supersedes the earlier stop gate
only for the unresolved regional relationship mismatch. Permit a null target Region for an
explicitly unresolved reference, retain strict complete identity/provenance and immutability,
preserve every retained fact and established migration, and add pre-DDL downgrade protection
for newly representable history. Validate populated upgrade, atomic failure/retry, constraints,
SQLite/PostgreSQL history and authenticated HTTP, then full regression/quality/container gates.
Planned additive revision: `20261001_0005`, after `20260924_0004`.
No production migration, publishing, reviewer agent, LOG-004 or later-slice work is authorized.

### 6F.1 persistence-repair checkpoint — 2026-10-01

The authorized repair is implemented in additive revision `20261001_0005`; the established
four migrations remain byte-unchanged. The ORM matches the new CHECK, allowing an unknown
Region only for unresolved regional references. Complete identities, provenance, FKs and
append-only guards remain strict. SQLite uses a transactionally rebuilt child table with FK
enforcement enabled and exact triggers restored; PostgreSQL changes only the constraint.
Online downgrade preflight serializes graph writers in parent-to-child order and blocks
incompatible retained history before any DDL. Offline downgrade is blocked. The collector,
mapper, AWS permissions, authentication and generic service/API fields remain unchanged.
LOG-002/003 proof/evaluator/catalog metadata and old releases are unchanged from the approved
bundle. The empty LOG-003 fallback also checks exact account identity explicitly.

The targeted rule, SQLite control/persistence/real HTTP, new migration and established migration/
foundation checks passed **114 tests**, no skips, with 20 existing dependency warnings.
This includes the four original acceptance failures, populated migration preservation,
compatible round-trip, incompatible/sanitized downgrade, strict identity scope and atomic
failed-transition/retry tests. New HTTP acceptance retrieves the retained unresolved
destination through the real relationship API without inventing a target resource.

The full collected suite (`python -m pytest -q --tb=short -p no:cacheprovider`, with a fresh
task-owned base-temp folder and unavailable `TEST_DATABASE_URL`) passed **1,918 tests**,
**155 skipped**, 20 existing warnings, no failures. The skips are the established PostgreSQL
availability gate, not new skip annotations. This is not PostgreSQL acceptance. Docker Desktop
was installed but stopped; starting it hidden crashed the backend while initializing its
`dockerInference` socket. Read-only diagnostics confirmed the startup error and no native
PostgreSQL alternative. Only the two hung task-owned diagnostic clients were stopped.
No Docker reset/data deletion, installation or configuration change was attempted. The user
was asked to restore the engine; disposable PostgreSQL and image build remain unverified.
The unchanged acceptance runner is ready to perform these gates once the engine is available.

Ruff lint and formatting passed (**312 Python files**); documentation/contract checks passed
**75 tests**, and tracked whitespace plus the exact subset-10 manifest hash passed.
Compose configuration also passed via the installed standalone Compose executable (no daemon
required). Tracked/untracked whitespace checks passed for all 35 changed files, and changed-file
private-key/AWS-key marker inspection found no matches. No API image build is claimed.
Documentation owners and README now record the authorized migration and local, unaccepted
6F.1 implementation. Changes after the full collected suite are documentation-only.
Self-review is not independent reviewer approval: no agent was launched, and independent
review remains separately authorized/pending.

Git remains local/uncommitted on `codex/sprint-6f1-cloudtrail-coverage-integrity`, HEAD/base
`49500c95c78870d72e6179882bae4e6379cdd6d0`, in the reused worktree. Original unrelated skill
files and the accepted 6E.3 checkout are preserved. No commit, push, PR, merge, production
migration or live AWS operation occurred. Local migration head is `20261001_0005`, accepted
baseline head remains `20260924_0004`. 6F.1 remains IN PROGRESS; 6F.2, 6G, 6H and later work
were not started. Do not mark COMPLETE before missing acceptance, review and merge gates.

When the local Docker engine is restored, resume the unchanged acceptance runner with a fresh
task-owned pytest temporary directory. It creates and removes only its own disposable database:

```text
python -m scripts.validate --focused tests/unit/rules/test_cloudtrail_controls.py tests/unit/database/test_cloudtrail_controls.py tests/unit/database/test_unresolved_region_migration.py tests/unit/database/test_migrations.py tests/unit/database/test_assessment_foundation.py tests/integration/test_cloudtrail_controls_postgres.py tests/integration/test_unresolved_region_migration_postgres.py tests/unit/contracts
```

Resolve any new PostgreSQL/full-regression failure and rerun invalidated gates. Only after all
local gates succeed request separate authorization for independent read-only review; do not
publish or advance 6F.2 based on this checkpoint.

## 6F.1 implementation authorization — 2026-10-01

The user's `implement 6f1` request, following the prepared bundle/implementation approval prompt,
approves LOG-002 HIGH / PR.PS-04 and LOG-003 MEDIUM / PR.DS-01, evaluator `1.0.0`, opt-in
catalog `0.11.0`, closed schema `1.8.0` and separately checksummed local NIST subset
`2.0+subset.10`. Implement the canonical coverage/integrity truth tables and shared engine/
persistence proofs only. There are no new organization inputs for these two controls.
Preserve collectors, permissions, default/historical catalogs, LOG-001, pending-scan intent,
authentication, generic APIs and migration head `20260924_0004`.

Origin main was rechecked at accepted `49500c95c78870d72e6179882bae4e6379cdd6d0`.
Scoped branch `codex/sprint-6f1-cloudtrail-coverage-integrity` starts at that SHA in the reused
worktree, carrying only the known local preparation documents forward without discarding them.
Original unrelated skill files and the 6E.3 checkout remain untouched. This request does not
approve LOG-004 or its empty-population clarification, reviewer agents, publication or merging.
Run focused/full, disposable PostgreSQL, real authenticated HTTP/history/integrity, quality and
container gates; independent review remains a separate authorization/acceptance gate.

### 6F.1 local implementation checkpoint — 2026-10-01

Local opt-in `0.11.0` now registers LOG-002/003 with closed proof/execution `1.8.0`,
evaluator `1.0.0` and separately checksummed NIST subset `2.0+subset.10`.
[Implementation metadata](../../controls/sprint-6f1-metadata.md) records exact approved
severities, mappings, required source/target bindings, canonical selector aggregation and limits.
The shared reader and pure evaluator are used by both engine and persistence. Account coverage
does not create a collected graph endpoint; integrity emits a result per observed trail.
No collector, AWS permission, service/API/auth interface, default/historical catalog, mapper,
ORM constraint or migration was changed. LOG-001 and partial-scan resolution guards remain.

Final bounded checkpoint command:

```text
python -m pytest tests/unit/rules/test_cloudtrail_controls.py tests/unit/database/test_cloudtrail_controls.py tests/unit/contracts -q --tb=no -p no:cacheprovider --basetemp <fresh-task-owned-folder>
```

Result: **144 passed, 4 failed, no skips** (47 new rule tests, 22 successful SQLite
persistence/rejection checks and 75 documentation/contract checks). The four failing SQLite
tests are history, lifecycle, recovery and real authenticated HTTP. They expose the same
pre-existing accepted-baseline persistence mismatch: an unresolved regional destination bucket
has no known Region, but `ck_resource_relationship_observations_target_scope_region_consistent`
requires a Region even for unresolved references. The domain permits the exact partial
identity emitted by the unchanged CloudTrail collector. ORM and migration `20260915_0003`
have the same conflicting constraint at accepted base `49500c95c78870d72e6179882bae4e6379cdd6d0`.
Persistence rolls back; HTTP retains sanitized `SCAN_EXECUTION_FAILED`. No failing test was
deleted, skipped or weakened, and no relationship/identity was dropped or invented.

Initial new-test failures caused by frozen-JSON inspection, artifact-constructor enum handling
and the empty-target guard's exact diagnostic were corrected. The final failures above remain
real integration failures. Ruff lint and formatting (**309 Python files**) passed, as did
tracked whitespace checks and the framework manifest hash. The one reported warning is the
existing Starlette TestClient deprecation. README, architecture, security/threat owners,
catalog/framework documentation, evidence readiness, persistence and the limitations register
now distinguish this unaccepted local slice from the accepted baseline.

Per the approved no-schema-change boundary and the preflight's explicit stop gate, implementation
stops pending approval of a narrowly scoped shared persistence repair, potentially an additive
migration with upgrade/regression validation. Alembic head remains `20260924_0004`.
Full regression, PostgreSQL, Compose/image and independent review gates have not completed for
this slice; historical 6E.3 green results do not validate the new runtime. New PostgreSQL
acceptance tests are present but not yet run. No reviewer agent was launched.

All changes remain local and uncommitted on `codex/sprint-6f1-cloudtrail-coverage-integrity`,
HEAD/base `49500c95c78870d72e6179882bae4e6379cdd6d0`, in the reused
`.tmp/sprint-6e3-readme-closeout` worktree. Original untracked skill files and the clean 6E.3
checkout are preserved. No push, PR, merge, live AWS or production operation occurred.
6F.1 remains IN PROGRESS, not COMPLETE; 6F.2/LOG-004, 6G, 6H and later sprints were not started.

## 6F implementation preparation — 2026-10-01

The user requested preparation, not implementation. PR #36 merged the separate README and
documentation closeout into `main` at `49500c95c78870d72e6179882bae4e6379cdd6d0`;
[merged-main CI passed](https://github.com/jnc247s/cloud-security-automation/actions/runs/36900929958).
Runtime remains the accepted PR #35 implementation at `c861713a665669da09d5bc7b5b282b04c16cac1d`.
This supersedes the earlier README-pending text without rewriting historical checkpoints.

The [6F preflight](../../controls/sprint-6f-preflight.md) records source/target contracts,
canonical truth tables, callers, integration risks and acceptance requirements. Recommend
6F.1 LOG-002/003 first, then accepted-baseline 6F.2 LOG-004. Retained 5F facts already suffice;
no collector, permission, dependency package, API/auth or migration change is planned.
LOG-004 requires a bounded internal dependency/context seam and shared engine/persistence
validation of the exact same-scan S3-002 destination result. It cannot duplicate exposure logic,
load historical results, silently enable S3-002 or relax its complete-collector requirements.

The proposed bundle awaits approval: LOG-002 HIGH / PR.PS-04, LOG-003 MEDIUM / PR.DS-01,
LOG-004 HIGH / PR.AA-05; evaluator `1.0.0`; cumulative opt-in catalogs `0.11.0` then `0.12.0`;
closed schemas `1.8.0` then `1.9.0`; independently sourced local NIST subsets `2.0+subset.10`
then `2.0+subset.11`; unchanged canonical selector subset and explicit retained S3 approval
policy. Also approve the preflight's proposed LOG-004 account N/A fallback for complete empty
trail discovery, distinct from its prohibition of N/A for an observed trail. No release or
deployment policy is registered by preparation; default `0.2.1` and migration head
`20260924_0004` remain unchanged.

The reused clean worktree `.tmp/sprint-6e3-readme-closeout` was switched from accepted main to
`codex/sprint-6f-logging-preflight` at `49500c95c78870d72e6179882bae4e6379cdd6d0`.
Preparation edits remain local/uncommitted. Original untracked `.agents/` skill files and the
existing `.tmp/sprint-6e3` checkout remain untouched. No independent agents, publication, merge,
live AWS or later-slice implementation is authorized by this request.

Preparation baseline checks: **245 tests passed**, no skips, covering CloudTrail collection,
LOG-001, engine/registry/four-state contracts, S3-002 and foundation/SQLite recovery/authenticated
HTTP acceptance. One existing Starlette deprecation remains. The initial sandboxed run had
seven temporary-folder permission setup errors; the same tests passed using an isolated
task-owned folder without runtime/test changes. Documentation closeout passed **74 contract/link
tests**, with the same existing warning and no skips. Ruff lint, format checking (**300 Python
files**) and tracked/untracked whitespace checks passed. No runtime/test file changed.
Recorded 6E.3 full regression/PostgreSQL/container acceptance remains applicable to unchanged
runtime; implementation must run fresh targeted/full and relevant integration gates.

Stop after preparation until the user approves the bundle and requests implementation.
Independent review and publication require their own authorization; merge remains human-controlled.

## 6E.3 implementation authorization — 2026-09-30

The user requested implementation of 6E.3. PR #34 merged 6E.2 at
`3eddcaf74fd26e08428464780a2c1a6dd7f6c1bf`; [merged-main CI passed](https://github.com/jnc247s/cloud-security-automation/actions/runs/36776996492).
This supersedes the pending-merge notes below. The prepared policy bundle and decision table
are approved by the 2026-09-30 checkpoint below. Implement S3-004 only in opt-in `0.10.0`,
closed proof `1.7.0`, evaluator `1.0.0`, HIGH severity and sourced reporting subset
`2.0+subset.9` / PR.DS-01. Preserve the classifier schema, historical/default catalogs,
collectors, permissions, migrations, generic API and authentication.

A clean worktree on `codex/sprint-6e3-sensitive-bucket-kms` starts at the merged SHA; the
uncommitted repository skill remains untouched in the original checkout. Migration head stays
`20260924_0004`. Run focused/full regression, disposable PostgreSQL, HTTP/history/integrity,
Ruff, documentation/container gates and required independent review before acceptance.
No merge, live AWS, remediation or later-slice implementation is authorized.

### 6E.3 implementation checkpoint — 2026-09-30

Implemented the approved S3-004-only release; [metadata](../../controls/sprint-6e3-metadata.md)
records policy, truth table, provenance and limits. Catalog `0.10.0` / proof `1.7.0` reuse
the unchanged classifier and shared engine/persistence validation. Explicit referenced keys
require their own DescribeKey/source and resolved same-scan relationship, exact owner and
bucket home Region. The implicit AWS-managed case creates no key/edge. N/A/insufficient retain
the established artifact convention and exact immutable classifier/profile history.

The existing acceptance runner passed **156 focused checks** (43 rule, 20 SQLite
persistence/HTTP, 20 PostgreSQL persistence/HTTP, 73 documentation/contract checks) and
**1,957 full regression tests**, including all **122 PostgreSQL integration cases**, with
no skips. The full run reported 20 existing dependency deprecation warnings: one Starlette
TestClient warning and 19 SQLite datetime-adapter warnings. Ruff lint passed; formatting
passed for 299 files. Markdown/local links, whitespace, Compose validation and the API image
build passed. Credential/private-key pattern inspection found no matches in changed files.
The isolated test container was removed; no operator database or live AWS account was used.

Initial focused failures exposed fixture-shape/digest construction mistakes and stale
preflight wording, corrected without weakening accepted assertions or production boundaries.
The successful results above apply after those corrections. Earlier catalog/framework
content, collectors, AWS permissions, API/auth contracts and migration head `20260924_0004`
remain unchanged.

The single authorized independent read-only reviewer examined every tracked diff and untracked
file. Initial result: **0 CRITICAL, 0 HIGH, 0 MEDIUM and 2 LOW** findings, both documentation
governance inconsistencies. The authoritative NIST document now records subset `2.0+subset.9`,
its exact manifest hash/source and S3-004 -> PR.DS-01 scope. Architecture no longer describes
S3-004 as pre-implementation or uninvoked, and the threat-model review date is current. The same
reviewer verified both corrections and returned **REVIEW_PASS with zero unresolved findings**.
No runtime or test file changed after the successful validation above.

Post-review documentation closeout passed all **73 contract/Markdown-link tests**, Ruff lint,
Ruff formatting (**299 Python files**) and whitespace checks. The run reported the existing
Starlette dependency warning plus a local pytest-cache warning; neither affected assertions.
Because the verified corrections changed documentation only, the recorded 1,957-test full run
and 122 PostgreSQL cases remain applicable under the validation policy.

At this implementation checkpoint the change was local and uncommitted on
`codex/sprint-6e3-sensitive-bucket-kms` in `.tmp/sprint-6e3`, based on accepted
`3eddcaf74fd26e08428464780a2c1a6dd7f6c1bf`. The original checkout's untracked repository skill
was preserved. The publication checkpoint below supersedes the original no-commit/no-push state.
This checkpoint does not mark 6E.3 COMPLETE or start 6F--6H.

### 6E.3 publication checkpoint — 2026-10-01

The user authorized GitHub publication. The complete reviewed implementation and documentation
were committed as `66f39f5` (`feat: implement Sprint 6E.3 sensitive bucket KMS control`) and
pushed without force to `origin/codex/sprint-6e3-sensitive-bucket-kms`; the local branch now
tracks that remote branch. The original checkout's unrelated untracked repository skill remains
separate and was not committed.

GitHub returned a [new-PR link](https://github.com/jnc247s/cloud-security-automation/compare/main...codex/sprint-6e3-sensitive-bucket-kms?expand=1),
but no PR was created and no merge occurred. This documentation-only publication record follows
the reviewed implementation commit. Verify CI for the final pushed branch head, including this
record, before human merge acceptance. No 6F or later-slice work is authorized or started.

### 6E.3 acceptance checkpoint — 2026-10-01

PR #35 was subsequently created and human-merged. It merged the reviewed branch through
publication commit `447eeb1` into `main` at
`c861713a665669da09d5bc7b5b282b04c16cac1d`, superseding the publication checkpoint's
no-PR/no-merge state. No automatic merge was performed.

The [merged-main CI run](https://github.com/jnc247s/cloud-security-automation/actions/runs/36825207102)
completed successfully on attempt 2. Attempt 1 completed the code and PostgreSQL gates but its
API image build timed out while downloading a build dependency from `files.pythonhosted.org`.
The failed job was rerun unchanged and passed, including the image build. The reviewed local
acceptance remains **156 focused checks** and **1,957 full regression tests**, including all
**122 PostgreSQL integration cases**, with no skips; independent review has zero unresolved
findings. Migration head remains `20260924_0004`, and default catalog `0.2.1` is unchanged.

The separate README commit `949ce48` postdated PR #35 and therefore was not part of its merge.
The focused closeout branch carries that README content forward from clean merged main and updates
the roadmap, active plan and catalog status to the accepted state. This documentation repair does
not alter runtime or tests. With review, merge and merged-main CI complete, 6E.3 and all of 6E are
COMPLETE. No 6F or later-slice implementation has started.

## 6E.2 closeout and 6E.3 policy approval — 2026-09-30

The user's instruction to proceed approves the preparation's bounded 6E.3 bundle: explicit
`DataClassification=Restricted` classifier with no patterns/overrides, both AWS-managed and
customer-managed KMS, `restricted_data_requires_kms=true`, and the proposed release metadata
and decision table below. Recheck release availability and the sourced framework mapping before
registration. This approval supersedes the preparation's pending-policy gate, not its baseline
acceptance requirement. No classifier policy file or S3-004 runtime implementation is created.

The same instruction authorizes one read-only independent 6E.2 review, necessary corrections,
commit/push and PR publication, but not merging. The initial checkpoint is clean branch
`codex/sprint-6e2-s3-exposure-control` at `d887d18a792e2261b13e6fd0236dc0f34a90442b`;
live origin/main remains `4b3d7355dafe6eceab50214ee2281b0b4f96fa81`, and 6E.2 is not yet
published. Keep 6E.2 IN PROGRESS and
6E.3 unstarted until the accepted-baseline workflow below is satisfied.

One independent read-only reviewer returned **REVIEW_PASS: 0 CRITICAL, 0 HIGH, 0 MEDIUM,
0 LOW findings**, covering the 6E.2 diff against `4b3d7355` through `d887d18`. It verified the
canonical channel cases, exact source/identity/approval binding, shared persistence validation,
history/recovery, real authenticated HTTP acceptance and compatibility boundaries. No runtime or
test correction was required. The earlier pending-review checkpoint below is superseded.

The recorded 153 focused / 1,873 full / 102 PostgreSQL results remain applicable to unchanged
runtime/test code. Closeout validation passed all 72 contract/link tests (one existing dependency
warning), Ruff lint, formatting (291 files) and whitespace checks. Credential-pattern inspection
found no newly introduced credentials: its sole whole-file match was the unchanged documented
`change-me` database placeholder. No environment, local policy, cache or database file is included.
Publication and final-head CI are still separate gates; human merge acceptance is required.

Publication checkpoint: implementation, preparation and review/approval commits through
`7a70cbed8aca7b8316b37e2f6688804db0f028f0` were pushed to the matching origin branch with
upstream tracking and no force-push. GitHub again refused PR creation with HTTP 403,
`Resource not accessible by integration`; no PR exists at this checkpoint and no credentials or
permissions were changed. [Open the 6E.2 PR manually](https://github.com/jnc247s/cloud-security-automation/compare/main...codex/sprint-6e2-s3-exposure-control?expand=1).
The [initial push CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/36766067251)
was in progress when this publication note was written. Verify CI for the final pushed HEAD,
including this documentation-only note, before merge; do not infer success from older results.
No merge occurred, and 6E.3 implementation remains unstarted.

## 6E.3 implementation preparation — 2026-09-30

Analysis only, requested by the user; no S3-004 rule or deployment policy is approved by this
section. The roadmap and current plan agree: 6E.2 remains IN PROGRESS, 6E.3 is unstarted.
The inspected working tree was clean on `codex/sprint-6e2-s3-exposure-control` at
`ea6dd6ea2540b0248bfb4eebcfe1ac3fa5bb94d0`. A live remote-reference check still reports main at
`4b3d7355dafe6eceab50214ee2281b0b4f96fa81` and no published 6E.2 branch. Migration head is
`20260924_0004`. Finish 6E.2 independent review, publication/CI and human merge acceptance first.
Then synchronize clean main, verify the merged SHA/CI and create
`codex/sprint-6e3-sensitive-bucket-kms`. Do not stack implementation on this unaccepted branch.

### Bounded scope and inspected integration

Implement **S3-004 only**, preserving S3-900, S3-001/002/003, prior catalogs and default `0.2.1`.
Use the [canonical classifier](../../controls/s3-004-sensitive-bucket-classifier.md) unchanged:
exact owner/home-Region/ARN/stable identity, reviewed overrides, restricted name patterns and
exact tag pairs. Missing tags differ from complete empty tags; a positive identity/name signal
does not become unknown merely because tag collection failed. Never accept a caller-supplied
classification without recomputing its sensitivity, reason and matches from historical inputs.

Inspected seams: `SensitiveBucketClassifier.classify`, `SensitiveBucketEvidence`, schema-2
profiles, immutable classifier registration/loading in `app/database/catalogs.py`, S3 source
normalization and `encrypted_with` edges, the shared evidence reader/execution contracts,
catalog registry, pending-scan recovery and existing classifier/persistence/HTTP test fixtures.
The [6E preflight](../../controls/sprint-6e-preflight.md#authoritative-contracts) already resolves
the old classifier document's future-tense profile/storage narrative: accepted 6A supplies that
storage. Reuse it, not another registry or a rewritten migration.

The evidence matrix already covers discovery/location, tags, default-encryption rules and
referenced KMS metadata. Bind every required observation to exact same-scan source IDs/digests.
For explicit KMS references, verify the matching declared DescribeKey evidence, resolved
`encrypted_with` edge and exact key identity/home Region; never guess the owner or key manager.
The implicit AWS-managed path has no fabricated KMS resource or required fictitious edge.
Introduce a closed, separately versioned classifier/KMS proof, shared by engine and persistence,
including applicability checks. Do not modify earlier proof strategies or add a scheduler.
No new dependency, collector, AWS permission, API/auth change or migration is currently needed.

### Proposed policy bundle for approval

These are proposals, not defaults or approved control semantics:

- Classifier: require an explicit nonempty schema `1.0.0` artifact and new profile version.
  Candidate initial rule: exact `DataClassification=Restricted`, no name patterns or exact
  overrides. This is not an inferred organization convention: the user must approve it or
  provide the actual tag pairs, patterns or exact bucket identities. Do not read/commit live
  policy data or use an empty classifier as a workaround.
- KMS requirement: accept both AWS-managed and customer-managed KMS; do not silently interpret
  the existing boolean as a customer-managed-only requirement. Keep
  `restricted_data_requires_kms=true` in the proposed initial profile. If a stricter manager
  policy is selected, revisit versioned policy serialization before implementation.
- Release proposal: HIGH severity, evaluator `1.0.0`, opt-in catalog `0.10.0`, closed execution
  schema `1.7.0`, independently checksummed NIST subset `2.0+subset.9`, proposed PR.DS-01 mapping.
  Recheck availability and source/approve the mapping before registration. Configuration
  evidence contributes data-at-rest context, never a complete compliance claim.
- Guidance: review workload compatibility and key access before any separately authorized
  encryption change. This slice performs no AWS writes or object re-encryption.

Proposed decision order, after complete identity/discovery and valid classifier/profile binding:

| Condition | Proposed result |
| --- | --- |
| Complete empty bucket population | NOT_APPLICABLE |
| Classifier lacks required evidence | INSUFFICIENT_EVIDENCE, even if the KMS boolean is false |
| Proven NOT_SENSITIVE | NOT_APPLICABLE; do not require irrelevant encryption/key evidence |
| Proven SENSITIVE and `restricted_data_requires_kms=false` | NOT_APPLICABLE, not PASS |
| SENSITIVE, requirement true, complete SSE-KMS or DSSE-KMS with no explicit key reference | PASS for the retained implicit AWS-managed configuration; no invented DescribeKey result |
| Same, with an explicit reference | PASS only with the exact resolved key/source proof and supported AWS/CUSTOMER manager; incomplete/mismatched proof is INSUFFICIENT_EVIDENCE |
| SENSITIVE, requirement true, complete SSE-S3 or confirmed absence of a KMS default | FAIL; this does not claim the bucket is unencrypted |
| Missing, denied, malformed, conflicting, disappeared or unsupported required evidence | INSUFFICIENT_EVIDENCE; never select the first conflicting encryption rule |

Preserve all encryption rules. A blocked-encryption-only rule is not a KMS default;
`NONE`/`SSE-C` blocking and Bucket Keys are retained context, not substitute proof. The proposed
scope checks default configuration, not existing object encryption, upload-policy enforcement,
key-policy permissions, key availability or rotation. These limits prevent an overbroad PASS claim.
AWS's [default-encryption API](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ServerSideEncryptionByDefault.html)
and [DSSE-KMS guidance](https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingDSSEncryption.html)
were checked for algorithm, key-reference and Region distinctions; those facts do not approve
the organization's classifier or KMS acceptance policy.

### Implementation and acceptance sequence

1. After baseline acceptance and bundle approval, register a new opt-in contract/catalog/profile;
   keep classifier schema/semantics and historical bytes unchanged.
2. Bind classification and conditional encryption/key evidence in one bounded pure evaluator;
   share recomputation and exact profile/classifier checksums with persistence, including N/A.
3. Cover canonical classifier precedence, unavailable/empty tags, both algorithms/managers,
   implicit/explicit references, denied/malformed/disappeared sources, ambiguous rules,
   exact owner/Region identity and resolved/unresolved key relationships with offline AWS.
4. Prove immutable classifier history, forged classification/result/proof rejection with rollback,
   pending-scan recovery, finding lifecycle and real bearer/capability HTTP-to-PostgreSQL reads.
5. Run targeted then full regression, disposable PostgreSQL, Ruff, docs/whitespace and container
   gates; complete one authorized independent review, final CI and human merge acceptance.

This preparation adds no runtime or test code, does not repeat the 6E.2 full suite, and does not
authorize review agents, publication or merge. 6E.3 and 6F--6H remain unstarted. Only lightweight
documentation validation is required for this preparation itself.

Preparation validation: 72 contract/link tests passed (one existing deprecation warning);
Ruff lint, formatting (291 files) and whitespace checks passed. The recorded 6E.2 full-regression
results apply to unchanged runtime/test code; no new full-regression or CI result is claimed.

## 6E.1 acceptance and 6E.2 authorization — 2026-09-29

### 6E.2 implementation checkpoint

S3-002 is implemented in opt-in `0.9.0` with closed proof `1.6.0`, explicit immutable
approval/profile binding and separately checksummed NIST subset `2.0+subset.8`. See
[approved release metadata](../../controls/sprint-6e2-metadata.md). All 21 canonical cases run
through the unchanged collectors. Same-owner/service exclusions, exact scoped approvals,
unknown-plus-confirmed aggregation, deletion/conflicts, version substitution, source/result
forgery, history/recovery, finding lifecycle and real bearer/capability HTTP are covered.
Only AWS is replaced in acceptance; no live policy file, migration, collector, permission,
service, route or authentication change. Default `0.2.1` and historical catalogs are preserved.

Final automated validation: **153 focused tests passed**, followed by **1,873 full tests
passed, zero skipped, 20 existing deprecation warnings**, including **102 disposable PostgreSQL
tests** (14 new S3-002 cases). Ruff lint and formatting passed (291 Python files), all 72
contract/link checks passed, whitespace and Compose configuration passed, and the API image
built successfully. The runner removed its disposable database; user databases were untouched.
Changed-file credential-pattern checks found zero matches; no secrets/local policy were added.

The initial full run caught the old documentation assertion that S3-002 was not implemented;
that assertion now verifies the explicit new release and absence from historical/default
registries. Final validation above includes that correction and closed AWS-principal syntax
and independent canonical-user ownership proof fixes. No failing acceptance was suppressed.

Independent review remains pending the requested authorization for one read-only reviewer.
Do not claim REVIEW_PASS, PR readiness, CI success for this branch or merge acceptance yet.
Keep 6E.2 IN PROGRESS. No push/PR/merge or 6E.3, 6F or later-sprint work in this checkpoint.

PR #33 merged 6E.1 at `4b3d7355dafe6eceab50214ee2281b0b4f96fa81`.
[Merged-main CI passed](https://github.com/jnc247s/cloud-security-automation/actions/runs/36611975078).
This supersedes the earlier pending-PR/CI/merge checkpoints; zero independent-review findings
remain. Clean main was synchronized before creating `codex/sprint-6e2-s3-exposure-control`.

After the explicit approval prompt the user repeated the instruction to implement 6E.2; proceed
with the presented bundle: explicit empty exposure approvals (schema/policy `1.0.0`), HIGH
severity, evaluator `1.0.0`, opt-in catalog `0.9.0`, independently checksummed reporting subset
`2.0+subset.8` and PR.AA-05 metadata/guidance from the preparation. This policy is explicit
operator input, never an implicit default when the artifact is missing.

Implement S3-002 only under its canonical channel tables and bounded same-scan proofs. Preserve
all prior catalogs/defaults, finding resolution, exact policy recovery and generic authenticated
API/persistence. No collectors, permissions, migrations or later controls are authorized. Run
targeted and full automated acceptance, one consolidated independent review, and final CI before
human merge acceptance. S3-004/LOG-004 and all later slices remain unstarted.

## 6E.1 publication and 6E.2 preparation — 2026-09-29

The user requested closing 6E.1 and preparing 6E.2. This authorizes branch publication and a PR,
not automatic merge or 6E.2 implementation. The clean branch's three reviewed commits were pushed:
`ce49f3b` migration comparison, `8b12191` validation automation, and
`f2b57d514a9eb20d4b7d7a21dc35626bc4f6ca5a` S3-001/003. Accepted origin/main remains
`9ad7feab10d8f87f91d878920c6cf40a5d6fe51b`. No force-push, credentials change or merge occurred.

GitHub's integration refused PR creation with HTTP 403, `Resource not accessible by integration`.
[Open the 6E.1 PR manually](https://github.com/jnc247s/cloud-security-automation/compare/main...codex/sprint-6e1-s3-bpa-transport-controls?expand=1).
The [implementation push CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/36586631570)
was running at publication; do not infer final-HEAD CI success from local validation. The existing
1,790-test local acceptance and zero-finding review apply to unchanged runtime code. Only
publication/preparation documentation is added in this handoff; run lightweight documentation
checks, not a redundant local full suite. The final documentation push receives its own CI.

[6E.2 preparation](../../controls/sprint-6e2-preflight.md) records inspected integration seams,
the bounded S3-002 scope, canonical result-sensitive semantics, test plan and one consolidated
policy/metadata proposal. It enables no control and changes no contract. Start its scoped branch
only after 6E.1 is accepted on clean synchronized main and its proposal is explicitly approved.
6E.1 stays IN PROGRESS until CI and human merge acceptance; 6E.2 is prepared, not implemented.

Documentation-only validation: **71 contract/link tests passed, 1 existing warning**; Ruff lint,
formatting and whitespace checks passed. No runtime/test changes or additional review agents were
needed for this preparation. No new full local regression is claimed for the documentation commit.

### Historical 6D acceptance and 6E.1 authorization checkpoint

PR #32 merged both 6D implementation commits into main at
`9ad7feab10d8f87f91d878920c6cf40a5d6fe51b`. This supersedes the earlier proposed two-PR
acceptance sequence; no separate #31 merge is required to obtain the accepted code.
The combined independent review below passed, final branch CI passed, and
[merged-main CI passed](https://github.com/jnc247s/cloud-security-automation/actions/runs/36532277234).
Local main was fast-forwarded from a clean tree before creating
`codex/sprint-6e1-s3-bpa-transport-controls`. Migration head remains `20260924_0004`.
Historical checkpoints below retain their original state.

The user requested 6E implementation and explicitly selected effective combined account/bucket
Block Public Access for S3-001 and bounded explicit HTTPS-denial evaluation for S3-003.
These choices are recorded in the [6E.1 approved metadata](../../controls/sprint-6e1-metadata.md).
The user subsequently explicitly approved metadata (severity, guidance, release identities and
sourced mappings). This authorizes S3-001 HIGH and S3-003 MEDIUM in opt-in `0.8.0`, evaluator
`1.0.0`, with reporting subset `2.0+subset.7` for PR.AA-05 and PR.DS-02. Implement 6E.1 using
existing facts, exact historical source proofs and the generic API/persistence boundaries.
Preserve earlier catalogs and default `0.2.1`, authentication, collectors and AWS permissions.

6E.2 and 6E.3 remain separately reviewed slices with the approval/classifier/encryption decisions
in the preflight. Do not infer those inputs or combine all S3 work into this branch. No 6F,
dashboard, remediation, live AWS action or production database operation is authorized.

Runtime implementation must pass the full validation and review gates. Bounded execution schema
`1.5.0` supports only S3 configuration proofs, including result-sensitive BPA observations;
the existing all-required-source strategies remain unchanged. Engine and persistence recompute
the exact result and verify retained proof/evaluator content. No migration is planned or added.

## 6E.1 local implementation and validation checkpoint — 2026-09-29

S3-001 and S3-003 are implemented locally on `codex/sprint-6e1-s3-bpa-transport-controls`,
based on accepted main `9ad7feab10d8f87f91d878920c6cf40a5d6fe51b`. Opt-in catalog `0.8.0`
uses the approved metadata and bounded execution schema `1.5.0`. Default catalog `0.2.1`,
earlier releases, collectors, AWS permissions, API routes, authentication and database schema
remain unchanged. Migration head remains `20260924_0004`.

The new tests cover combined BPA truth tables, explicit transport-denial proof, incomplete and
empty discovery, provenance, old/new historical catalogs, exact pending-scan recovery, forged
assessment rollback, finding lifecycle and real bearer-authenticated HTTP acceptance. HTTP tests
retain routing, capability enforcement, executor, collectors, rules and persistence; only AWS is
replaced. A bounded event gate proves nonblocking scan submission before persisted public reads.

Latest validation results:

- New rules and local persistence/recovery/HTTP acceptance: **42 passed, 1 warning**, 5.21 seconds.
- New disposable PostgreSQL integration module: **10 passed, 1 warning**, 9.95 seconds.
- Complete regression with disposable PostgreSQL: **1,774 passed, 10 failed, zero skipped,
  20 warnings**, 133.11 seconds. All ten failures are existing migration/autogeneration checks
  comparing PostgreSQL-shortened relationship constraint names with long model names.
- The same `test_postgres_legacy_downgrade_and_upgrade` failure was reproduced in a clean,
  detached worktree of accepted main with the same environment: **1 failed, 1 warning**,
  1.30 seconds. This establishes a baseline failure, not a passing regression or a proven
  dependency-version root cause. No migration, model or existing test was changed to hide it.
- Ruff lint and formatting passed (**277 local Python files**); whitespace checks passed.
  Docker Compose configuration and the API image build passed.
- Final contract/Markdown-link checks after recording this checkpoint: **70 passed, 1 warning**.

The PostgreSQL runtime is isolated, disposable and unrelated to the user's demonstration
database; no live AWS or production database was used. The baseline migration-check defect
requires separately scoped investigation/repair before the full-regression gate can pass.
Independent review permission was requested and remains pending; no 6E reviewer was launched.
No 6E commit, push, PR, CI result or merge is claimed. These outstanding gates prevent a COMPLETE
or PR-ready declaration. Slices 6E.2/6E.3 and all later work remain unstarted.

## 6E.1 authorized repair and streamlined validation — 2026-09-29

The user approved repairing the reproduced baseline migration-check defect and one read-only
independent reviewer, and requested automatic routine progression without repeated permissions.
This supersedes the pending repair/review permission checkpoint above, not human merge approval
or production safety boundaries. Keep 6E.2/6E.3 and later slices outside this change.

Investigation identified Alembic 1.19.1's name-only CHECK comparison against SQLAlchemy-generated
PostgreSQL-truncated names. The repair requires Alembic >=1.20, explicitly enables its named CHECK
comparison plugin, and supplies a dialect-rendered private metadata copy. It neither disables
comparison nor modifies historical migrations, ORM names, constraints, expressions or data.
New tests prove equivalent emitted DDL, unchanged shared metadata, and detection of real missing
and extra constraints. The documented name-only expression-comparison limitation is unchanged.

`python -m scripts.validate` automates focused tests when supplied, mandatory full PostgreSQL
regression, Ruff/formatting, whitespace, Compose and image validation with a task-owned disposable
database and cleanup. Tests check isolation, cleanup and failure propagation. It never commits,
pushes, merges or deploys. Routine in-scope repairs and validation proceed without another
permission prompt; new policy/scope, destructive user-data actions and production/merge authority
remain human decisions. One consolidated independent review covers 6E.1 and these repair/tools.

### Reviewed local checkpoint

The single authorized read-only reviewer returned **REVIEW_PASS**, with **0 CRITICAL, 0 HIGH,
0 MEDIUM and 0 LOW** findings, covering the complete 6E.1 diff, comparison repair, validation
runner and documentation. No further reviewer or specialty review was launched.

The final automated run passed **108 focused tests, 20 warnings**, followed by **1,790 full
regression tests, zero failures, zero skips, 20 warnings**, in 142.08 seconds for the full suite.
This includes **88 PostgreSQL integration cases**, the S3 HTTP-to-persistence acceptance and all
previously failing migration checks. Existing warnings concern TestClient/httpx and SQLite datetime
deprecations. Ruff lint/format (**282 Python files**), whitespace, Compose configuration and the
API image build passed. Scoped changed-file AWS-key/private-key and sensitive/local-path checks
found no matches; this is not an exhaustive secret-scan guarantee.

The first combined focused run also exposed nine new SQLite-test fixture lookup errors when
explicit test paths mixed integration and unit collection. Explicitly registering the existing
fixture in the new S3 module fixes independent collection without weakening any assertion; the
subsequent focused and full runs above pass. The runner also waits for TCP readiness rather than
PostgreSQL's initialization-only Unix socket. Its disposable database is removed after validation;
the user's demonstration database and all live AWS/production systems remain untouched.

This supersedes the earlier local failure/review-permission checkpoint, not the acceptance gates:
no push, PR, new CI success or merge is claimed. Local reviewed changes may be checkpointed in
logical commits. 6E.1 remains IN PROGRESS pending publication/CI and human acceptance. 6E.2/6E.3,
6F and later sprints remain unstarted. Migration head is unchanged at `20260924_0004`.

## 6D publication authorization — 2026-09-29

The user explicitly authorized pushing 6D. Commit the reviewed 6D.2 implementation and existing
analysis-only 6E preparation, then publish both scoped 6D branches without force-pushing or merging.
This supersedes the earlier no-push checkpoint, not the required CI and human acceptance gates.
The combined independent review and full local regression below remain applicable; only
documentation has changed since review. Final pushed-HEAD PostgreSQL and image CI must pass
before acceptance. 6E implementation and all later work remain unstarted.

## 6D finalization and 6E preparation — 2026-09-28

The user requested finishing 6D and preparing 6E. Runtime implementation and combined read-only
review are complete locally; the validation checkpoint below remains applicable. No application
or test behavior is changed by this preparation. Final publication/CI and human acceptance are
still required before 6D is marked COMPLETE. Commit/push/stacked-PR approval has been requested;
the earlier no-push/no-merge restriction is not silently waived.

The [6E preflight](../../controls/sprint-6e-preflight.md) records inspected integration seams,
the three bounded S3 slices, existing policy decisions and validation gates. It is analysis-only,
not implementation approval or a new control contract. Start 6E.1 from clean synchronized main
after 6D acceptance and approval of the missing S3-001/S3-003 truth tables and metadata.
6E remains proposed; S3-001 through S3-004 stay unregistered. Do not implement 6F composition.

## 6D.2 authorization and workflow amendment — 2026-09-28

The user approved a local 6D.1 checkpoint (`215abcf6f2690f93f623db0f3f30fd85cdba2f5d`)
and stacked branch `codex/sprint-6d2-vpc-flow-log-control`. This is an explicit bounded
exception to starting each slice from main, not acceptance of 6D.1. The combined base is
`c7d85e2a36a8e8aa0bc044a9fc22b7ea8cdbf01c`. No push or merge is authorized.

Implement NET-006 only: explicit case-sensitive `Environment=production`, acceptable traffic
types `REJECT` or `ALL`, MEDIUM severity, catalog `0.7.0`, evaluator `1.0.0`, and scoped
PR.PS-04 mapping for log-generation configuration evidence only. Guidance requires an authorized
operator to review dependencies and costs before enabling logging; no AWS writes are included.
Missing policy is rejected, never defaulted. Preserve all older releases and default `0.2.1`.

Use a bounded VPC/Flow Log join that proves both matching membership and complete empty results;
do not weaken the generic required-edge strategy or treat subnet/interface logs as VPC logs.
No collector, permission, schema, API or authentication redesign is approved. Run targeted,
history/recovery/HTTP, PostgreSQL where available, full regression, Ruff and relevant container
checks. One read-only reviewer is authorized for combined 6D.1/6D.2 after validation. Neither
slice is complete until its remaining acceptance gates succeed. Later slices are excluded.

### 6D.2 local implementation checkpoint — 2026-09-28

NET-006 is implemented in explicitly selected catalog `0.7.0` with approved MEDIUM severity,
evaluator `1.0.0`, explicit environment/traffic policy and independently checksummed NIST subset
`2.0+subset.6`. Bounded execution schema `1.4.0` proves complete VPC/Flow Log populations and
exact zero-or-more relationship membership. Engine and persistence share result/proof validation.
External-owner VPC coverage remains insufficient under collection-account Flow Log discovery.
No collector, AWS permission, migration, route, authentication or default-catalog change was made.
Migration head remains `20260924_0004`; all earlier releases remain supported.

Validation before the combined independent review:

- Combined 6D rules, persistence, recovery, real HTTP acceptance and contracts/Markdown links:
  **150 passed, 2 warnings**. NET-006 rule cases: **29**; local storage/recovery cases: **10**;
  local HTTP cases: **1** in addition to the preserved 6D.1 acceptance.
- Complete regression: **1,654 passed, 76 skipped, 21 warnings**, 66.20 seconds. Every skip is an
  unconfigured disposable PostgreSQL case, including the **11** new NET-006 integration cases.
  Existing dependency and SQLite datetime deprecations remain.
- Ruff lint passed; formatting passed (**267 local Python files**); whitespace checks passed.
  Scoped AWS-key/private-key and sensitive-path checks found no matches; this is not a claim of
  exhaustive secret scanning. Docker Compose configuration passed.
- Docker's Linux engine is unavailable. PostgreSQL execution and the API image build remain
  authoritative CI gates, not claimed local successes. CI already provisions disposable PostgreSQL.
  No live AWS or production database was used.

HTTP acceptance keeps real bearer authentication/capabilities, routes, executor, collectors, rules,
transactions and public read APIs; only AWS is fake. It verifies nonblocking 202 with a bounded
gate, persisted IDs, history, sources, relationships, findings, framework metadata and audit.
Recovery retains the exact catalog/profile despite different deployment defaults. Source failure
tests preserve independent results without allowing a partial scan to resolve a finding.

The approved single read-only reviewer completed combined 6D.1/6D.2 review against accepted main
`c7d85e2a36a8e8aa0bc044a9fc22b7ea8cdbf01c`, including untracked files: **REVIEW_PASS**, zero
CRITICAL/HIGH/MEDIUM/LOW findings. The review covered canonical truth tables, owner/Region/source
proof, complete absence versus missing evidence, exact historical policy/recovery, atomic rejection,
finding lifecycle, real authenticated HTTP acceptance, compatibility and documentation. No code
repair was required. Final documentation contracts/Markdown validation: **68 passed, 2 warnings**.

6D.2 changes remain uncommitted on `codex/sprint-6d2-vpc-flow-log-control`; only the approved
6D.1 checkpoint exists. PostgreSQL, image/CI and human merge approval remain outstanding gates.
No push, PR, merge or new CI result is claimed. Both slices remain IN PROGRESS until their gates
and human acceptance succeed. No later slice or sprint was started.

Prepared: 2026-09-24.
Current checkpoint verified: 2026-09-28. Historical checkpoints below retain their original state.

## 6C authorization and integration checkpoint — 2026-09-28

Superseding checkpoint: PR #30 merged 6C at `c7d85e2a36a8e8aa0bc044a9fc22b7ea8cdbf01c`;
[merged-main CI passed](https://github.com/jnc247s/cloud-security-automation/actions/runs/36477059926).
The following 6C implementation checkpoints retain their original predictions.

## 6D.1 authorization — 2026-09-28

The user approved [6D.1 metadata](../../controls/sprint-6d1-metadata.md) and implementation of
NET-003/004/005 only. Clean main was fast-forwarded to the accepted 6C merge before creating
`codex/sprint-6d1-security-group-controls`. No 6D.2 Flow Log control is included.

Reuse retained security-group/VPC evidence, exact versioned profiles, generic API and persistence.
Add a bounded versioned security-group proof binding discovery membership, admitted facts and the
same-scan VPC edge; preserve legacy schemas and NET-001/002. Profile-dependent empty-port N/A
requires exact policy at both engine and persistence boundaries. No collector, permission, schema
migration, authentication or route change is planned. Default catalog remains 0.2.1.

Validate canonical truth tables, empty versus unavailable evidence, source and relationship
integrity, partial-source isolation, old/new history, profile recovery, finding lifecycle and real
authenticated HTTP-to-persistence/public reads with offline AWS only. Run targeted tests, full
pytest, Ruff, disposable PostgreSQL, applicable container and documentation checks, followed by one
consolidated independent review. CI and human merge remain gates; do not mark 6D.1 COMPLETE early.

### 6D.1 local implementation checkpoint — 2026-09-28

NET-003/004/005 are implemented in opt-in catalog `0.6.0`, evaluator `1.0.0`, using bounded
execution schema `1.3.0` and separately checksummed framework subset `.5`. Earlier releases,
profiles, defaults, NET-001/002, collectors, permissions, API/auth and migration head are unchanged.
The optional profile argument on shared candidate validation is supplied by engine and persistence;
it is mandatory for new network proofs and leaves old callers/schema behavior intact.

Focused rules, history/recovery, atomic forgery rejection, finding lifecycle and real authenticated
HTTP acceptance: **42 passed**. With contract/Markdown/link checks: **109 passed, 2 warnings**.
Full local regression: **1,613 passed, 65 skipped, 21 warnings**, 44.26 seconds; skips exclusively
require disposable PostgreSQL. After that run, the forged-PASS test was strengthened to retain
valid evidence and assert rejection specifically at the source/result boundary; all 109 focused
checks passed again. No runtime behavior changed after the full run.

Ruff lint/format (259 Python files), whitespace and Compose configuration passed. Docker's Linux
engine is unavailable and TEST_DATABASE_URL is unconfigured; the 11 new PostgreSQL cases skip
locally. No PostgreSQL execution or image-build success is claimed. AWS is offline fake data only;
real routing, bearer backend/capability enforcement, executor, collectors, rules and transactions
remain intact. Findings resolve only after a later sufficiently complete PASS, not a partial scan.

One read-only reviewer was requested; approval/review remains pending. No commit, push, new CI,
PR or merge is claimed. PostgreSQL/image CI and human merge remain acceptance gates. This is not
6D.1 completion. NET-006/6D.2 and later-sprint work were not started.

### Historical 6C implementation authorization

PR #29 merged 6B.2 into 6B.1, then PR #28 merged both at
`42cc65366ed4d6e1fe14aa28e2650a62280cba8b`. Merged-main
[CI passed](https://github.com/jnc247s/cloud-security-automation/actions/runs/36464517181).
This supersedes historical 6B pending-merge notes. The clean baseline was fast-forwarded before
creating `codex/sprint-6c-ec2-ebs-controls`; migration head remains `20260924_0004`.

The user approved implementation and [6C metadata](../../controls/sprint-6c-metadata.md), including
catalog `0.5.0`, evaluator `1.0.0`, severities, scoped mappings, stable-resource UUID allowlisting,
human-approved operator guidance and one read-only reviewer after validation. Scope is exactly
EC2-001/002/003/004; no collector, permission, schema, API/auth or later-slice change is authorized.

Implementation reuses execution schema `1.0.0`, exact source coverage and admitted snapshots.
A shared EC2 fact/applicability validator additionally binds complete discovery membership and
configuration to retained source payloads. Missing/ambiguous evidence cannot become empty N/A.
EC2-004 remains a requested-Region assessment-only account target, never a collector resource.
Optional KMS evidence and contextual topology do not determine these results. Profile validation
rejects noncanonical UUID approvals only when EC2-002 is enabled, including before AWS work and
on recovery; old profile bytes remain valid. Framework subset `.4` is independently checksummed.

Validate truth tables, source isolation, empty/missing distinctions, identity/Region safety,
forged evidence and N/A rejection, old/new history, exact pending-scan recovery and real authenticated
HTTP-to-persistence/public reads. Run focused tests then Ruff/full regression, disposable PostgreSQL,
container checks and the approved independent review. CI and human merge remain acceptance gates.
No 6C completion or later-slice implementation is claimed at this authorization checkpoint.

### Reviewed 6C implementation checkpoint — 2026-09-28

EC2-001 through EC2-004 are implemented in explicit catalog `0.5.0` with the approved metadata
and independently hashed framework subset `.4`. Source/fact/applicability checks are shared by
engine and persistence. Default catalog `0.2.1`, earlier releases, profile bytes, source manifests,
collectors, API/auth and migrations are unchanged. Migration head remains `20260924_0004`.

Validation of the final local implementation: **43 targeted tests passed**; targeted plus
contract/Markdown/link checks **109 passed, 2 warnings**. Complete regression: **1,570 passed,
54 skipped, 21 warnings** in 45.24 seconds. The skips are exclusively unconfigured PostgreSQL
cases, including eight new 6C cases. Ruff lint and format passed (249 local Python files),
whitespace and changed-file sensitive-path/AWS-key/private-key pattern checks passed. These
are scoped checks, not a comprehensive secret-scan guarantee. Compose configuration passed;
Docker's Linux engine is unavailable locally. No live AWS or production database was used.

The single approved independent reviewer returned REVIEW_PASS with zero unresolved findings.
One LOW stale catalog summary was corrected and independently verified; no runtime issue was
identified. The reviewer independently ran 35 rule tests. Documentation links were rechecked
after the correction: **66 passed, 2 warnings**.

The user explicitly approved committing and pushing after review for authoritative PostgreSQL
acceptance and image-build CI. CI on the pushed commit and human merge remain required before
acceptance. This checkpoint does not claim 6C COMPLETE, a PR merge, or any 6D/later work.

Sprint state: `IN PROGRESS`, as owned exclusively by [ROADMAP.md](../../../ROADMAP.md).
The user authorized 6A implementation and a combined planning/implementation PR on 2026-09-24.

## Verified starting checkpoint

- Clean merged `main` and `origin/main`: `e71c4db0915574547d9258ab80948619621fe05c`.
- Planning branch: `codex/sprint-6-preflight`, created from that checkpoint.
- Accepted Sprint 5 implementation baseline: `ef4543d439ed3a33064c6bcf383db201a94d2881`;
  the later merge above closes out documentation and archives its plan.
- Alembic head: `20260915_0003`; no migration is introduced during preparation.
- Sprints 0–5 are `COMPLETE`, Sprint 6 is `NEXT`, Sprints 7–10 are `PLANNED`.
- All 25 evidence-matrix rows are `CURRENT`; `SPRINT_5_CONTROL_CONTRACTS_READY` remains canonical.
- [Merged-main CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/35949472681)
  succeeded, including tests with disposable PostgreSQL, Ruff lint/format, and API image build.
  This is baseline evidence, not validation of future Sprint 6 changes.

There is no active implementation plan conflicting with this draft. The
[completed Sprint 5 plan](../completed/sprint-5.md) retains its historical stage predictions;
its closeout and the roadmap own the accepted outcome.

## Objective and boundaries

Implement the 25 canonical production controls using the accepted normalized Sprint 5 evidence,
with deterministic four-state results, versioned policy, structured evidence, historical
persistence, findings, and authorized generic API retrieval.

Four core controls already execute: IAM-001, NET-001, NET-002, and LOG-001. Preserve their
accepted semantics. Add the other 21 core controls. Preserve S3-900 as a separate legacy,
non-core contract; do not rename it, repurpose its history, or silently retire it. The resulting
supported catalog can therefore contain 25 core controls plus that legacy control; enabled
controls remain an explicit versioned profile choice.

No collector expansion, new AWS permissions, frontend, remediation, deployment, AI, tenant
isolation, distributed execution, or unrelated Sprint 9 hardening is included. A concrete evidence
defect discovered during implementation must be reported separately, not silently folded into a
rule or worked around by an AWS call from a rule.

## Sources of truth

- [Repository governance](../../../AGENTS.md), [product requirements](../../../PRODUCT_REQUIREMENTS.md),
  [architecture](../../../ARCHITECTURE.md), [security](../../../SECURITY.md), and
  [threat model](../../../THREAT_MODEL.md).
- [Control catalog](../../controls/catalog.md) and
  [25-control evidence matrix](../../controls/sprint-5-evidence-readiness.md).
- [S3 exposure aggregation](../../controls/s3-002-exposure-aggregation.md) and
  [sensitive-bucket classifier](../../controls/s3-004-sensitive-bucket-classifier.md).
- [Generic relationships](../../design-decisions/0001-generic-resource-relationships.md) and
  [result-sensitive evidence outcomes](../../design-decisions/0002-result-sensitive-evidence-outcomes.md).
- [Assessment framework](../../assessment-framework.md), [framework mappings](../../frameworks/nist-csf-2.0.md),
  [persistence](../../persistence.md), [API](../../api.md), and
  [known limitations](../../operations/known-limitations.md).

These owners retain their authority. This plan identifies implementation gaps; it does not
replace approved truth tables or assign previously unapproved organization policy.

## Integration preflight findings and proposed design

The existing component boundaries remain suitable. The following bounded extensions are required
before the corresponding new controls can be enabled. They are future integration work, not
claims of a defect in the accepted five-control runtime.

| Boundary inspected | Existing behavior and concrete integration risk | Proposed bounded treatment |
| --- | --- | --- |
| `app/assessment/profiles.py`, `app/models/profile.py`, `app/database/catalogs.py` | The strict model, checksum, stored columns, and loader enumerate only existing fields. Adding policy defaults or changing checksum input can invalidate historical definitions. | Preserve the legacy serializer/checksum and exact profile loading. Introduce an explicit new schema with complete persisted extension content and strict version/checksum validation. Prefer an additive versioned payload for the finite approved fields; finalize its shape and new Alembic migration together with writer, reader, guards, and PostgreSQL tests in 6A. Never infer schema from an arbitrary organization policy version. |
| `app/services/scan_service.py`, `app/services/scan_executor.py`, `app/rules/engine.py` | Creation and assessment build the current catalog; the executor rejects a pending scan if its recorded catalog differs. Merely replacing the default catalog would strand older pending scans. | Resolve exact supported catalog/registry versions from persisted scan intent, retain catalog 0.2.1 and its rules, and reject unsupported versions before AWS work. Never select the latest catalog for recovery. Preserve all existing requested-service tuples. |
| `app/database/validation.py`, `app/database/persistence.py`, `app/rules/base.py` | Targets assume one resource type per control, global account fallbacks, and known legacy collector ownership. EC2-004 is Regional account evidence; IAM-004 and GOV-001 span multiple normalized types. | Add explicit version-bound target and coverage descriptions consumed consistently by assessment and persistence. Preserve exact target-matrix checks and canonical IDs. Regional account-setting assessments must not fabricate collector resources or masquerade as global settings. Specify their historical target representation before enabling EC2-004. |
| `app/database/persistence.py`, legacy rule helpers | Decisive artifacts currently require a successful whole collector. Applying that unchanged to canonical S3-002 rejects an allowed coherent FAIL with a different unavailable source; removing it globally weakens accepted controls. | Keep legacy guards. Add a narrowly versioned source-aware validation path that verifies exact same-scan declarations, outcome/artifact digests, admission gaps, required edges, and the control's declared result-sensitive contract. Reuse pure rule/evidence validation, not a second policy engine in persistence. |
| `app/rules/registry.py`, `app/rules/engine.py` | Execution is lexical by control ID, and each rule receives only inventory/profile. LOG-004 sorts before S3-002 and cannot consume its exact result through the current interface. | Provide bounded dependency-aware orchestration for the declared S3-002 → LOG-004 dependency, retaining stable final output ordering and legacy callers. Use the same scan/profile/destination snapshot result, never a previous scan or duplicate exposure implementation. Missing/disabled required results remain insufficient. No general workflow framework is needed. |
| `app/assessment/controls.py`, framework loader and catalog persistence | New severities/mappings are unassigned. Composed `ControlContract` currently requires at least one mapping. Fabricated mappings or an unreviewed validator relaxation are not acceptable. | Retain independent technical evaluation. Supply reviewed, sourced mappings with each new executable catalog slice under the existing composed-catalog contract. Any proposed support for unmapped catalog entries requires separate explicit contract approval; do not silently bypass validation. Preserve old framework artifacts and catalog checksums. |

The profile/schema transition must also durably preserve complete S3 approval/classifier artifacts,
their own IDs/versions/checksums, and reject changed content under reused artifact versions even
across profile versions. Historical S3 classification must be recomputed against exact retained
policy and bucket evidence as required by the accepted classifier contract.

No generic API redesign is proposed. Resource ownership remains distinct from collection account;
global, requested Regional, and proven supplemental scope remain unchanged. Missing required
edges and evidence remain `INSUFFICIENT_EVIDENCE`. An operational exception never rewrites FAIL,
and finding resolution still requires the accepted sufficient later PASS. Audit and findings stay
inside the existing transaction; database transactions never span AWS collection.

## Decisions required before enabling affected controls

These are approval gates for their slices, not reasons to reopen Sprint 5 evidence collection.

1. **Versioned deployment policy:** approve the new profile schema/configuration path and explicit
   catalog selection, retaining old formats and pending scans. Do not introduce new controls into
   a previously stored profile or reuse a catalog version with changed content.
2. **Organization inputs:** approve `max_unused_access_key_days`, high-risk TCP ports, exact
   Flow Log environment values and acceptable traffic types, governed resource types, and the
   deployment's S3 approval/classification artifacts. Existing `stale_key_days`, `required_tags`,
   and `public_ec2_exceptions` retain their documented meanings. Candidate ports in the matrix
   are not approved deployment defaults. A missing classifier cannot become an empty allow-all
   classification policy.
3. **S3-001 and S3-003 executable detail:** names and factual evidence are canonical, but the
   catalog has no full executable truth tables for these two IDs. Before the S3 slice, approve
   whether S3-001 requires settings independently at both levels or effective account/bucket
   protection, and the bounded secure-transport policy proof subset for S3-003, including
   unsupported-policy uncertainty. Do not infer these choices solely from control titles.
4. **S3-004 result policy:** approve AWS-managed versus customer-managed KMS acceptance and the
   result when `restricted_data_requires_kms` is false. Keep the approved classifier unchanged;
   version any additional policy field and exact encryption-result table before registration.
5. **New technical contracts:** approve severity, impact/guidance, exact evaluation version, and
   independently sourced mapping rationale for each added control before its catalog is enabled.
   NIST does not set project thresholds, severity, or technical results.

## Proposed execution slices

The labels and sequence below are proposals, not an implementation authorization. Keep PRs
bounded; split the named IAM, network, and S3 groups at the listed seams when needed. Every
implementation PR must leave the system coherent and pass the full required gate.

| Slice | Scope | Dependency and acceptance focus |
| --- | --- | --- |
| 6A — Versioned assessment integration | Legacy/new profile serialization and storage, exact catalog/registry selection, explicit target/coverage contract, and narrowly scoped source-aware assessment validation | No new control enabled merely by adding foundation. Prove old pending scans and history survive new versions; test the Regional and multi-type target representation. New migration only, never edit accepted migrations. |
| 6B — IAM | IAM-002/003 key age/use; IAM-005/006 root flags; IAM-004 permissions-policy syntax as a separate bounded PR | 6A; approved thresholds/severity/mappings. Preserve IAM-001. Same-scan key/policy relationships, observation-time thresholds, complete enumeration, boundary-only policy context, no effective-authorization claims. |
| 6C — EC2/EBS | EC2-001 through EC2-004 | 6A; approved catalog entries. IMDS state, all normalized public IPv4 locations, volume encryption, Regional default setting, and exact policy allowlist semantics. |
| 6D — Network | NET-003/004 ingress; NET-005 default groups; NET-006 VPC Flow Logs | 6A; profile choices. Preserve NET-001/002. Keep group checks and joined Flow Log coverage as separable PRs. |
| 6E — S3 | S3-001/003 configuration and transport; S3-002 exposure; S3-004 classified KMS requirement | 6A plus the S3 decision gates. Separate exposure aggregation and classifier/KMS integration into bounded PRs. Retain S3-900 unchanged and Analyzer as supplementary, non-decisive evidence. |
| 6F — Logging | LOG-002 selectors, LOG-003 validation, LOG-004 destination exposure | 6A; LOG-004 additionally requires accepted 6E S3-002 and exact result composition. Preserve LOG-001; use the canonical selector table, not a general selector solver. |
| 6G — Governance | GOV-001 across the exact governed tag-source vocabulary | 6A and approved required tags/types. Complete empty tags differ from unavailable tags; retain original case/whitespace and exclude aws:-prefixed keys from satisfying required ownership tags. |
| 6H — Acceptance and closeout | All 25 core controls, supported legacy behavior, version transitions, history, findings, and API integration | All prior slices accepted. Complete validation/review/CI and human merge approval before marking Sprint 6 COMPLETE and promoting Sprint 7. |

IAM, EC2, network, and governance do not depend on one another after 6A; the proposed serial order
keeps integration and review manageable. The hard cross-control dependency is S3-002 before
LOG-004, not arbitrary lexical rule order. No parallel agent team is required by this plan.

## 6A detailed plan — Versioned assessment integration

Plan date: 2026-09-24. Approved; 6A implementation is IN PROGRESS.
This section refines 6A only. It does not approve later control or organization-policy choices.

### Outcome and scope limit

Make the existing execution/persistence path capable of accepting explicitly versioned future
assessment inputs without changing the five accepted rules, default enabled IDs, catalog 0.2.1,
legacy checksums, historical IDs, or accepted pending-scan service intent.

Use one scoped implementation PR with the four logical work packages below. They are not four
new sprints or permission to ship partially integrated persistence. No new dependency, collector,
AWS call, permission, severity, mapping, or production control is needed for 6A. In particular,
do not implement S3-002 aggregation, S3-004 encryption policy, or LOG-004 composition here.

### A1 — Explicit profile and catalog selection

- Preserve `AssessmentProfile`'s legacy serialized document and checksum algorithm, including
  every existing organization-selected version, not only the literal default `1.0.0`.
- Add an explicitly schema-versioned extended profile alongside the legacy representation.
  Distinguish serialization schema from operator-selected policy version; dispatch validators
  and serializers explicitly. New optional fields must never appear in old canonical content.
- The extension supports only the already named future inputs: unused-key days, high-risk TCP
  ports, Flow Log environments/traffic types, governed resource types, and the two approved S3
  policy artifacts. Reuse their strict existing schemas. No inferred classifier, threshold,
  empty-policy fallback, or organization default is introduced. Future controls must require
  their named inputs before enablement; 6A cannot enable unregistered controls.
- Proposed configuration: optional `ASSESSMENT_PROFILE_FILE` pointing to one local UTF-8 JSON
  profile envelope containing schema, complete profile content, and exact catalog ID/version.
  Load/validate it once per application configuration lifecycle; no URL fetching, request-supplied
  path, or hot reload. Its profile version must match explicit `ASSESSMENT_PROFILE_VERSION`.
  File content owns all policy fields in this mode; legacy tag/age settings do not merge into it.
  Without a file, retain the existing environment-based profile factory unchanged. Invalid file
  content fails closed with sanitized diagnostics, never fallback policy.
- Add a small explicit supported-catalog resolver, keyed by catalog ID/version, returning the
  exact reviewed catalog and matching rule registry. Keep the default helpers and legacy callers
  compatible. Initially the production resolver still supports only catalog 0.2.1; future slices
  add their reviewed releases, while tests exercise multiple isolated fixture releases.
- Pass the selected catalog through engine validation rather than rebuilding a global default
  inside `assess`. Resolve and verify persisted catalog membership/content checksum, profile,
  enabled IDs, and service intent before constructing the AWS provider during restart. Unknown
  catalog/schema versions fail closed; never use current deployment policy for pending work.

### A2 — Additive storage and migration

- Add one new Alembic revision after `20260915_0003`; allocate its concrete revision ID during
  implementation. Never edit revisions 0001–0003.
- Proposed profile storage: retain existing columns and add a nullable schema discriminator plus
  nullable JSON extension payload. Both null means the exact legacy format; both populated means
  a supported new format. New-profile checksums bind the discriminator, common policy fields,
  and the complete extension. Old rows require no content/checksum backfill or rewrite.
- Store complete S3 artifact bodies in the extended profile, including their own versions and
  checksums. Add one closed-kind immutable policy-artifact registry with unique
  `(artifact_kind, artifact_id, version)` identity and full canonical content/checksum. Ensure it
  transactionally before the profile; verify it on load. This prevents a changed classifier or
  approval artifact from reusing its version through a different profile. It is not a general
  plugin/configuration store, and it gets no public mutation endpoint.
- Add nullable, schema-versioned `execution_contract` JSON to new control-version definitions
  for A3/A4 metadata. Preserve the old technical serialization and all old definition/catalog
  digests when that field is absent. New content participates in new version checksums, is
  immutable, and is loaded/verified with the exact catalog. No existing catalog is relabelled.
- Implement models, strict writer/reader dispatch, immutable guards, and migration tests in the
  same PR. Preserve database-enforced scan/profile/catalog references and append-only history.
  New columns do not authorize changing old terminal scans or profile rows.
- Extend the existing downgrade preflight before any DDL. Retained extended profiles, artifact
  registry entries, execution metadata, or assessment history requiring the new target semantics
  must block a lossy downgrade. Compatible legacy-only data may follow the existing path.
  PostgreSQL checks and transition must exclude concurrent writers; preserve SQLite atomicity
  and fail closed for offline downgrade across the new boundary. Never delete history to roll back.

### A3 — Explicit assessment targets and coverage

- Introduce a small typed execution contract, not an expression language. It names target kind
  (global account, requested-Region account setting, or an exact resource family/set), accepted
  service/type identities, versioned target-selection policy, and source/coverage requirements.
  It is bound to the new control version; unknown selectors or strategies are rejected.
- Use one shared pure target-selection boundary in engine checks and persistence validation.
  Preserve legacy target enumeration exactly. New paths must reject omitted/extra/duplicate
  targets and may not use an unrelated collector failure to excuse missing results.
- For Regional account settings, reuse the existing assessment-only account-target convention
  with service `ec2`, type `aws_account`, verified account ID, `regional` scope, and the requested
  Region. Existing identity helpers already include scope/Region. This is a persisted assessment
  target, not a collector-discovered AWS resource or graph endpoint; global account IDs do not
  change. Validate the extension through Python guards, database constraints, and read APIs.
- For future IAM/GOV multi-type controls, retain each actual resource's canonical identity/type
  rather than inventing a generic resource. The new execution contract owns the type set and
  allowlisted selector; no IAM policy selection or GOV rule is implemented in 6A. Synthetic test
  contracts prove target-set behavior without registering planned production IDs.
- Preserve existing API fields and route/capability behavior. Add only an optional execution-
  contract projection to generic control-version detail if needed to expose the new definition;
  absence remains legacy behavior. Resource-type filters must match the declared supported types
  for extended definitions without changing legacy matching. Document/test this additive change
  atomically; do not add per-control routes, profile-edit APIs, or a frontend.

### A4 — Source-aware evidence validation, without new rule logic

- Build a pure, per-assessment-invocation evidence reader over the validated inventory graph,
  reusing existing target/provenance indexes. It resolves exact declarations, source outcomes,
  artifact IDs/digests, admission completeness, and same-scan relationships. It has no AWS,
  database, HTTP, mutable global cache, or policy-evaluation responsibility.
- New structured assessment evidence cites the source identities and digests it actually uses.
  Validate those references against the retained graph at persistence; supplied proof text,
  `PRESENT` alone, or a fabricated collector name is not a completeness guarantee.
- Keep the five legacy rules on whole-collector guards. For a versioned source-aware contract,
  generic 6A validation requires its declared decision-required sources to be complete/coherent;
  unrelated failures do not automatically invalidate those sources. Missing required evidence
  must still produce an explicit insufficient result, and incomplete enumeration must be visible.
- There is no generic `allow_partial` switch. Result-sensitive exceptions such as S3-002's
  confirmed violation with an unknown sibling source are implemented and validated only in that
  later control slice, against its approved truth table. Unknown validation strategies fail closed.
- Do not change finding resolution: a source-sufficient assessment in a partial scan does not
  automatically become eligible to resolve an existing finding. Preserve the accepted full-scope
  resolution gate, exceptions, occurrence history, and audit behavior.
- Defer dependency scheduling and S3-002 → LOG-004 result consumption to their first concrete
  consumer in 6F. The 6A catalog-selection/target interfaces must not preclude that extension,
  but no speculative dependency engine is added now.

### Atomic callers and tests

Expected implementation touch points: `app/assessment/` profile/control/provenance contracts,
`app/config.py`, `app/models/profile.py` and control/policy storage, `app/database/catalogs.py`,
`validation.py` and `persistence.py`, `app/rules/engine.py`/registry/base integration,
`app/services/scan_service.py` and `scan_executor.py`, generic control projections/filters,
Alembic, and their existing tests. Recheck callers before edits. Legacy rule modules change only
if necessary for compatible typing; their decision logic must remain unchanged.

Required acceptance cases:

1. Old serialized profiles/catalogs and checksums remain identical; old scans load after upgrade.
   Changing content under an existing profile/catalog/artifact identity is rejected.
2. New profile fields/artifacts round-trip exactly; omitted, malformed, or checksum-inconsistent
   persisted content is rejected rather than rebuilt from deployment settings. Concurrent reuse
   of one artifact version cannot persist conflicting content.
3. Retained pending scans resume with their exact profile, catalog, and collection intent after
   configuration changes; unsupported versions fail before any AWS call.
4. Regional setting identities differ by Region and from global account targets; resource-family
   targets retain exact observed IDs. Omission, wrong owner/scope, and extra targets are rejected.
5. Source references resolve only to same-scan, digest-bound declared evidence. Missing required
   sources/edges and admission gaps cannot yield unsupported decisive results or absence claims.
   Legacy partial-collector behavior and partial-scan finding-resolution behavior stay unchanged.
6. PostgreSQL and SQLite populated upgrade/compatible downgrade work; incompatible downgrade
   leaves revision, schema, rows, values, and history guards unchanged. Test PostgreSQL writer
   exclusion and transaction rollback using the existing disposable-schema conventions.
7. Real authenticated HTTP → real executor → offline fake AWS → existing five rules → PostgreSQL
   → public reads works under both legacy and explicitly selected extended profile configuration.
   No authentication/service/persistence mock shortcuts. No new production control is required.

Run targeted tests, then Ruff lint/format, full pytest, PostgreSQL integration/HTTP acceptance,
and relevant Compose/image checks. Existing baseline results are not substitutes for 6A
validation. Perform one consolidated independent review, resolve CRITICAL/HIGH findings, and
obtain green CI and human merge approval. Update architecture, persistence, assessment-framework,
API/configuration documentation, and security/threat documentation for material boundary changes.

### Approval, Git, and stopping point

Approve A1–A4 as the 6A design, including the explicit profile-file configuration and additive
storage approach, before implementation. Organization thresholds, S3-001/003 truth tables,
S3-004 KMS choices, and new mappings/severities remain later-slice gates, not prerequisites to
this foundation PR. No existing evidence contract is redefined by this proposal.

Workflow amendment approved by the user on 2026-09-24: retain the planning documents and 6A
implementation in one scoped PR. The documents were temporarily stashed, clean current `main`
was checked out, and `codex/sprint-6a-assessment-foundation` was created before restoring the
documents. A separate planning PR is not required. Human merge approval remains mandatory.

6A is complete only after its implementation/compatibility gates and approved merge. Its handoff
must show unchanged default executable IDs and identify the exact new migration/profile schemas.
Then stop; do not begin IAM controls or mark the whole Sprint 6 complete.

## Validation and definition of done

For each implementation slice:

1. Run targeted rule/contract tests first: each documented result path, complete empty versus
   unavailable evidence, deterministic replay/order, exact target IDs, source provenance, and
   only the policy cases required by that slice's accepted contract.
2. Run `python -m ruff check .`, `python -m ruff format --check .`, and `python -m pytest`.
   Preserve valid legacy and boundary assertions; evolve sprint-status guards only when the
   approved implementation actually changes the documented boundary.
3. For persistence changes, run the existing integration conventions against an explicitly
   configured disposable PostgreSQL database. Include populated old/new profile and pending-scan
   history, upgrade, immutable artifacts, rollback safety, and transaction atomicity. SQLite
   unit tests do not substitute for PostgreSQL.
4. Reuse/extend the existing authenticated HTTP acceptance in
   `tests/integration/test_persistence_postgres.py`: real bearer backend and capability enforcement
   → POST scan → service → executor → offline AWS fakes → collectors → rules → persistence →
   terminal scan → public read APIs. ADMIN can scan; ANALYST remains denied. Poll with a bound,
   not arbitrary sleeps. Verify exact IDs for resources/history, assessments/evidence, source
   outcomes, relationships, findings/occurrences, and framework context.
5. Preserve finding resolution/exception behavior, no-AWS rule execution, sanitized errors,
   owner/scope checks, and source-graph operation/query-count regressions. Validate Compose/image
   when runtime/container behavior changes; CI retains its image build.
6. Complete one consolidated independent review at the PR boundary; fix CRITICAL/HIGH findings,
   rerun affected validation, obtain green CI, and await human merge approval. Do not repeatedly
   launch specialty reviews without a concrete reason.

Sprint closure additionally verifies the complete 25-control matrix through persisted workflows,
including canonical S3-002 → LOG-004 composition and historical policy roll-forward. Later UI
consumers use existing services/API, not direct database queries. No Sprint 7 implementation is
part of this acceptance work.

## Git workflow and handoff

The approved 6A workflow combines planning and implementation on
`codex/sprint-6a-assessment-foundation`, based on clean `main` at the verified checkpoint above.
Do not build an implementation stack on the old Sprint 5 closeout branch. Subsequent slices
also start from clean, current accepted `main`; merging remains a human approval gate.

Keep one logical implementation task per bounded PR. Record only the current branch/base/HEAD,
approved decisions, changed interfaces, exact tests tied to the tested commit, review findings,
and next action in this plan. Use targeted tests during edits and required full validation at
the stable slice gate; rerun whenever later changes invalidate results. Do not trade security or
validation for usage savings.

## Preparation validation and next action

Preflight on the merged baseline: **234 passed, 3 warnings** using existing contracts, profile,
control, rule, persistence-validation, and scan-service tests. The warnings were two dependency
deprecations and a local pytest-cache warning; no assertion failed. The command was:

```text
python -m pytest tests/unit/contracts tests/unit/assessment/test_profiles.py tests/unit/assessment/test_controls.py tests/unit/rules tests/unit/database/test_validation.py tests/unit/services/test_scan_service.py -q
```

Merged-main CI's quality job and each lint/format/test/image step were queried and confirmed
successful. Its job log records **1,396 passed, 20 warnings**, with no skips; this includes the
20 PostgreSQL integration cases. Full regression and PostgreSQL are reused from that green
baseline run, not claimed as newly executed locally.

Documentation validation after adding this plan: **62 contract/link tests passed, 3 warnings**;
Ruff lint passed; Ruff format check passed (211 local Python files); tracked diff and the new
plan's whitespace checks passed. Only this plan and its roadmap link/preflight description changed.
A final read-only self-check found no scope/status conflict; no independent reviewer was launched
and no implementation-review approval is claimed. No new full regression was run for this
documentation-only preparation.

**Current action:** implement and validate approved 6B.2 as recorded below. Organization-specific
and S3 decisions must be approved before their dependent slices; they must not be silently supplied
by code. Earlier preparation and implementation checkpoints below are historical evidence.

## 6A implementation checkpoint — 2026-09-24

Branch: `codex/sprint-6a-assessment-foundation`, based on merged `main`
`e71c4db0915574547d9258ab80948619621fe05c`. A1–A4 are implemented for validation/review:
explicit legacy/extended profile dispatch and file selection; exact catalog recovery;
additive migration `20260924_0004` with immutable policy artifact registry and downgrade guard;
shared target/source-proof validation and additive generic control projections/filters.
No production catalog release, new rule, collector, AWS permission, or later slice was added.

The only new source strategy requires all named sources and edges to be complete. Resource
enrichment without source-level completeness flags uses authoritative same-scan admitted-resource
proof plus required account coverage; account settings/enumeration require normalized flags.
The existing result-sensitive S3 exception and LOG-004 dependency scheduling remain deferred.

Validation before independent review: focused contracts/storage/recovery/documentation **115 passed,
2 warnings**; subsequent populated rollback/forgery tests **11 passed, 2 warnings**; complete pytest
**1,414 passed, 29 skipped, 21 warnings**. The skips are exclusively PostgreSQL integration cases
with no `TEST_DATABASE_URL`. Ruff lint passed, format check passed (221 local Python files),
tracked whitespace checks passed, and Docker Compose configuration validated. Local Docker Desktop
could not expose its Linux engine, so the image build and PostgreSQL execution remain CI gates,
not claimed successes. No production database or live AWS was used.

The user approved one read-only independent reviewer. Review and branch CI are pending at this
checkpoint; do not mark 6A complete or merge until required gates and human approval succeed.

### Reviewed implementation follow-up

Initial implementation commit: `b03eaab3df54af8d24d40c481fd745c023f3389c`.
The single independent reviewer found zero CRITICAL/HIGH and three MEDIUM issues: an artifact-free
N/A compatibility conflict, non-atomic SQLite upgrade DDL, and PostgreSQL artifact-guard SQLSTATE.
All three were corrected and the same reviewer independently verified their resolution, with no
unresolved findings. Added tests cover complete/incomplete empty populations, populated failed
upgrade rollback/retry, and admitted-resource proof with resolved/missing/unresolved required edges.

First branch CI ran all PostgreSQL cases, including both real HTTP profile variants: **1,442 passed,
1 failed, 20 warnings**. Its sole failure was the old graph-writer concurrency test waiting for the
second migration lock, while the new guard now blocks at the first. The synchronization point was
updated without weakening its writer-release, blocked-downgrade, or history-preservation assertions;
the reviewer verified this adjustment.

After these corrections, focused foundation tests: **41 passed, 2 warnings**. Full local regression:
**1,421 passed, 32 skipped, 21 warnings**; all skips are unconfigured disposable PostgreSQL cases.
Ruff lint, formatting (221 local files), whitespace, and scoped credential-pattern checks passed.
Migration head is `20260924_0004`. The follow-up commit requires a new green CI run including
PostgreSQL and the API image; human review/merge approval remains outstanding. Slices 6B onward
remain unstarted. This is a reviewed implementation checkpoint, not a sprint-completion declaration.

## 6B.1 implementation authorization — 2026-09-27

The user approved the remaining metadata and requested implementation of IAM-002/003/005/006.
The preparation notes below retain their original approval checkpoint; their pending-approval
statements are superseded by this authorization. Catalog `0.3.0`, evaluation version `1.0.0`,
framework subset release `2.0+subset.2`, guidance, and scoped mappings are approved. Default
catalog `0.2.1` and its five controls remain unchanged. No migration or collector change is planned.

The user subsequently directed that independent review wait until 6B as a whole is done.
Do not launch a 6B.1 reviewer or claim the review gate has passed. This does not authorize IAM-004
implementation in this task, waive validation, or permit merging. Stop after the 6B.1 handoff.

## 6A acceptance and 6B.1 preparation — 2026-09-27

PR #27 merged 6A into `main` at `1900dd4fd0968de5c130a65265ce2c8670a51a09`.
[Merged-main CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/36168438181)
is successful. The previously recorded independent review has no unresolved findings; the
pending-CI/merge statements above describe earlier checkpoints, not the current state.
Migration head remains `20260924_0004`; no new rule was enabled by 6A.

Clean local `main` was fast-forwarded to that accepted commit before creating
`codex/sprint-6b-iam-key-root-controls`. Scope is IAM-002/003/005/006 only. The user approved
`max_unused_access_key_days = 90` as explicit versioned profile policy, MEDIUM severity for
IAM-002/003, and HIGH severity for IAM-005/006. Existing `stale_key_days` semantics and values
are unchanged. No hard-coded unused-key default is authorized.

The [metadata proposal](../../controls/sprint-6b1-metadata.md) contains the remaining impact,
guidance, evaluation-version, and sourced mapping decisions for approval. Do not treat these
draft definitions as approved or enable the catalog before approval. IAM-004, collector changes,
new AWS permissions, remediation execution, and later-sprint work are excluded.

After approval, implement the bounded same-scan user/key evidence proof, four deterministic
rules, exact catalog/profile selection, and persistence/API acceptance described in the 6B plan.
Preserve empty-set versus unavailable-evidence distinctions, old catalog/profile checksums and
pending scans, source-proof validation, and finding-resolution gates. Follow the full slice
validation/review/CI/human-merge gates above. No runtime implementation is claimed at this checkpoint.

Documentation-only validation: `python -m pytest tests/unit/contracts -q` passed **64 tests,
3 warnings** (two dependency deprecations and a local pytest-cache warning). Ruff lint passed;
format check passed (222 local Python files); whitespace checks passed. No full regression,
PostgreSQL rerun, or new independent reviewer was needed for this metadata preparation. These
results do not validate future 6B.1 runtime changes. The three documentation files remain
uncommitted; no push or merge was performed.

## 6B.1 implementation checkpoint — 2026-09-27

Branch: `codex/sprint-6b-iam-key-root-controls`; base/HEAD before implementation commit:
`1900dd4fd0968de5c130a65265ce2c8670a51a09`. The four approved IAM controls are implemented in
explicit catalog `0.3.0`, with the approved metadata and separately checksummed NIST subset.
Existing catalog `0.2.1`, default configuration, old control definitions/mappings, collectors,
authentication, routes, schema, and migration head `20260924_0004` remain unchanged.

Execution schema `1.1.0` supports only the bounded IAM key-age/key-use proofs. The proof verifies
complete user/key identity sets, same-scan resolved relationships, exact admission provenance,
key status/chronology and active-key usage. Empty active-key sets retain artifact-free N/A only
after complete coverage. Root flags use the existing global account-target/source-proof path.
Missing declared profile inputs are rejected before collection and on exact-profile recovery.
Rule evidence records evaluation version `1.0.0`; finding-resolution gates remain unchanged.

Validation of the implementation working tree:

- Focused IAM rules, storage, recovery, local HTTP acceptance and 6A foundation: **62 passed,
  2 warnings**. This includes 31 IAM rule cases and five local storage/HTTP/recovery cases.
- Complete pytest: **1,458 passed, 37 skipped, 21 warnings**. All skips are PostgreSQL cases
  without `TEST_DATABASE_URL`. Warnings are existing dependency/SQLite datetime deprecations.
- New PostgreSQL module: **5 skipped**, explicitly requiring disposable `TEST_DATABASE_URL`.
  It covers populated legacy/new history, forged-proof rollback, complete empty-key history,
  exact pending-scan recovery, and real bearer HTTP-to-persistence/public-read acceptance.
- Contract/Markdown links: **64 passed, 3 warnings**, including the local cache warning.
- Ruff lint passed; format check passed (**231 local Python files**); diff whitespace passed.
- Docker Compose configuration passed. Docker's Linux engine was unavailable; a local startup
  attempt timed out. Neither PostgreSQL execution nor an image build is claimed as successful.

HTTP acceptance preserves real routing, bearer authentication, capability enforcement, executor,
collectors, rules, transactions, and public read projections. Only AWS is replaced, with a bounded
gate proving HTTP 202 is nonblocking. ADMIN can scan; ANALYST cannot. The test checks exact persisted
assessment/evidence/source/relationship/resource-history/finding/framework IDs and scan audit.
Local SQLite execution is supplemental; PostgreSQL execution remains the authoritative CI gate.

No independent reviewer was launched, as directed by the user. Review is deferred until whole-6B
readiness, not passed or waived. Commit/push permission was requested to obtain PostgreSQL/image
CI validation; no push or merge is claimed here. The change remains uncommitted at this checkpoint.
IAM-004 (6B.2), later slices, remediation, and deployment were not started. 6B.1 is not marked
COMPLETE while validation/review/merge gates remain outstanding.

## 6B.2 authorization and workflow amendment — 2026-09-27

The user approved IAM-004 implementation, HIGH severity, evaluator `1.0.0`, opt-in catalog
`0.4.0`, scoped PR.AA-05 mapping, and impact/guidance described in
[6B.2 metadata](../../controls/sprint-6b2-metadata.md). Preserve all earlier catalog/framework
bytes and defaults. Scope is permissions-policy syntax only, not effective authorization.

The user explicitly approved stacking this slice before 6B.1 is accepted: checkpoint 6B.1 on
`codex/sprint-6b-iam-key-root-controls`, then branch `codex/sprint-6b-iam-policy-controls` from it.
The checkpoint is `e242e64f2feb6c69ffbee0b00b8cc88e2064a54c`, based on merged 6A
`1900dd4fd0968de5c130a65265ce2c8670a51a09`. This is a bounded exception to the clean-main
per-slice rule, not acceptance of 6B.1. Keep separate PRs and review all of 6B together.
No push, merge, or reviewer launch is authorized by this approval.

Reuse existing managed/default-version and inline-policy evidence. Version the bounded
multi-family target/proof strategy; incomplete enumeration, missing document/version/owner/digest
or unresolved usage must fail safely. Preserve boundary-only context and deduplicate documents
across usage. No collector, permission, schema, route, authentication, or later-slice change is
planned. Run targeted, history/recovery/HTTP, PostgreSQL where available, full regression, Ruff,
and applicable container checks. Review/CI/merge gates remain outstanding.

## 6B.2 implementation checkpoint — 2026-09-27

Branch: `codex/sprint-6b-iam-policy-controls`, stacked on local 6B.1 commit
`e242e64f2feb6c69ffbee0b00b8cc88e2064a54c`. IAM-004 is implemented in explicit catalog `0.4.0`
with approved HIGH severity, evaluator `1.0.0`, and independently versioned PR.AA-05 metadata.
The new execution schema `1.2.0` shares target/proof validation across engine and persistence.
It deduplicates policy documents while retaining usage, verifies enumeration/relationships and
document identity/digest, and keeps missing managed versions visible as insufficient targets.
Conditions do not erase literal matches; boundary-only policies are not described as grants.

No collector, AWS permission, migration, API request/route, authentication or authorization
change was made. Defaults and catalogs `0.2.1`/`0.3.0` remain unchanged. Migration head remains
`20260924_0004`. Architecture, control/framework, persistence, API and security owners document
the bounded extension. The original inventory digest's graph-order semantics were preserved;
reordered evidence retains identical technical results and canonical proofs, not a fabricated
claim that every raw inventory serialization is byte-identical.

Validation of the implementation tree before its local commit:

- Combined 6B rules, history, recovery and real authenticated HTTP: **80 passed, 2 warnings**.
- Final IAM-004 rules/history after correcting the fixture to roll both managed-policy version
  IDs with changed documents: **43 passed, 2 warnings**.
- Final full regression: **1,503 passed, 42 skipped, 21 warnings** in 36.59 seconds. All skips
  are disposable PostgreSQL tests without `TEST_DATABASE_URL`; deprecations are unchanged.
- Contract/Markdown/link validation: **65 passed**; the five new PostgreSQL cases explicitly
  skip locally. Those cover old/new catalog history, forged-proof atomic rejection, pending-scan
  recovery, real HTTP-to-persistence/public reads, and managed/inline document version history.
- Ruff lint and formatting passed (**239 local Python files**); whitespace and changed-file
  AWS-key/private-key pattern checks passed. These are scoped checks, not a secret-scan guarantee.
- Compose configuration passed. Docker Linux engine is unavailable; PostgreSQL execution and
  image build are not claimed. No live AWS or production database was used.

No independent reviewer was launched, no push/PR/merge was performed, and no CI result is claimed
for these local commits. The whole-6B review, authoritative PostgreSQL/image CI and human merge
approval are outstanding. Neither 6B slice nor Sprint 6 is COMPLETE. Next action requires
authorization to push the separate stacked branches and run the consolidated review; do not
start 6C or later work as part of this handoff.

## Whole-6B reviewed finalization — 2026-09-27

The user authorized finalization and pushing both existing feature branches. This supersedes the
earlier no-push/reviewer stopping point; no automatic merge or later-slice work is authorized.
The single previously deferred independent reviewer reviewed both slices against merged 6A.
Initial result: zero CRITICAL/HIGH, two MEDIUM findings. Both are fixed and the same reviewer
verified `REVIEW_PASS`, with zero unresolved findings of any severity:

1. IAM-004 now validates nested Condition structure without evaluating condition semantics.
   Malformed conditions cannot produce a decisive assessment; valid conditions do not erase
   the literal wildcard match. Collectors and approved control truth tables remain unchanged.
2. Shared candidate validation rejects false N/A for nonempty IAM key populations and root
   controls. Genuine complete-empty key N/A and unrelated legacy schema behavior are preserved.
   The fix is on 6B.1 as `e7e40e442687c9192d611a162e7b140d14150d37`, carried into 6B.2 by
   cherry-pick `28c79267f44bd0dc2e31a072655848e7129f907c`. Both guards were preserved during
   conflict resolution. No published history was rewritten or branch automatically merged.

Final local validation after repairs: combined focused tests **103 passed, 2 warnings**; full
regression **1,526 passed, 46 skipped, 21 warnings**. The 46 skips are explicitly unconfigured
disposable PostgreSQL cases. 6B.1 independently passed **44 focused** and **1,466 full tests**
with 41 local PostgreSQL skips. Ruff lint/format (239 local Python files), whitespace, scoped
credential-pattern checks and Compose configuration passed. No live AWS or production DB was used.

GitHub CI on the original combined implementation ran **1,545 tests with no skips**, including
PostgreSQL acceptance, and built the image. The repaired 6B.1 runtime also passed
[CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/36362683825).
Final pushed-HEAD CI remains mandatory before human merge; current results are owned by GitHub,
not inferred from the earlier successful runs. Local Docker is still unavailable.

Git push works, but GitHub's PR-creation integration returned HTTP 403 (resource not accessible
by integration). No PR was created and no credential/access-policy workaround was attempted.
Open separate PRs manually: 6B.1 -> main, then 6B.2 -> 6B.1; merge the base first and retarget
the second PR to main before its merge. The identical applicability repair appears in both
histories intentionally, via cherry-pick rather than a force-push or automatic merge.
All implementation/review work is ready for these acceptance gates. Sprint 6 and its 6B slices
remain IN PROGRESS until required human merge approval/merge; no 6C work was started.

## Reviewed 6B.1 finalization — 2026-09-27

The user authorized finalizing and pushing the two 6B feature branches. The single deferred
whole-6B reviewer found zero CRITICAL/HIGH and two MEDIUM issues. Both were fixed and the same
reviewer verified REVIEW_PASS, with zero unresolved findings. This supersedes the earlier
review/push stopping points; no automatic merge or later-slice work is authorized.

This branch's applicability repair is `e7e40e442687c9192d611a162e7b140d14150d37`: shared
engine/persistence validation rejects false N/A for nonempty IAM key sets and the never-N/A
root controls. Complete-empty key N/A and unrelated legacy behavior remain valid. The other
finding, malformed nested Condition structure, is repaired only on the separate IAM-004 branch
`codex/sprint-6b-iam-policy-controls`. That branch also carries the applicability repair through
a cherry-pick without rewriting published commits or automatically merging branches.

Final local 6B.1 validation: **44 focused tests passed, 2 warnings**; full regression
**1,466 passed, 41 skipped, 21 warnings**. Skips are unconfigured disposable PostgreSQL cases.
Ruff lint/format passed (231 local Python files). The repaired runtime passed
[GitHub CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/36362683825),
including PostgreSQL integration, real authenticated HTTP acceptance and the API image build.
Final pushed-HEAD CI remains mandatory before human merge. No live AWS or production DB was used.

Both feature branches are pushed. PR creation was refused by the GitHub integration with HTTP
403; no credentials/access-policy workaround was attempted. Open 6B.1 -> main first, then
6B.2 -> 6B.1, and retarget the second to main after the base merges. Human merge approval remains
required; no slice completion or merge is claimed here. IAM-004 is not part of this base PR;
6C and later work were not started.

## Authorized feature-branch synchronization — 2026-09-27

The user explicitly approved merging 6B.1 into 6B.2 only to synchronize their shared repair and
closeout history. This narrowly supersedes the earlier no-branch-merge stopping point; it does
not authorize merging either PR into main, rewriting published history, or starting 6C.
The preceding 6B.1 checkpoint describes the base branch, not the combined branch's runtime.
Conflict resolution preserves the exact reviewed combined application and tests from
`ff46041918fffe2a902bba267b83aa4f6feffb19`, including both applicability guards, and retains both
slices' execution history. The combined roadmap remains authoritative for this stacked branch.

The repaired combined implementation passed
[CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/36362960955):
**1,572 passed, zero skipped, 20 warnings**, with disposable PostgreSQL acceptance, Ruff, and
the API image build. Final synchronization-commit CI remains required before human merge.
The approved feature merge removes the stacked-branch conflict without changing runtime behavior.
Post-resolution contract/link, IAM rule, persistence and authenticated HTTP checks passed:
**168 passed, 2 warnings**. Ruff lint/format (239 files) and whitespace checks passed. Application
and test files match the reviewed, fully validated combined commit byte-for-byte; final CI
reruns the full regression with PostgreSQL on the synchronization commit.
