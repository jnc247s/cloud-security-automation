# Sprint 7 dashboard and technical posture

Plan state: 7A APPROVED and IN PROGRESS; 7B and later slices remain PROPOSED.
Sprint 7 is IN PROGRESS, not complete.
Prepared: 2026-10-02, after the user's analysis-only preflight request.
Current 7A gates: local validation and independent review passed; commit/push/PR authorized;
acceptance and merge remain pending. No merge or 7B implementation authority.

The [preflight](../../sprint-7-preflight.md) records inspected interfaces, callers, tests,
reporting semantics, browser security decisions and scope limits. [ROADMAP.md](../../../ROADMAP.md)
alone owns status. The subsequent 7A confirmation below supplies its scoped authorization;
the original preflight and goal creation did not authorize implementation.

## Accepted baseline and authority

Analysis began from clean current main
`bafa0783d347ef8b6c5e1182d4c2dd86119b412d`, with
[merged-main CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/36957670046)
passing 2,533 tests, 252 PostgreSQL cases, no skips, 20 existing warnings and quality/image gates.
Those recorded Sprint 6 results remain baseline evidence, not new Sprint 7 acceptance.
Defaults remain catalog `0.2.1`, profile `default/1.0.0`, migration `20261001_0006`;
all 25 core controls plus legacy S3-900 remain explicitly opt-in in latest `0.13.0`.

The original preflight request authorized local analysis and preparation only. The user's
subsequent "Confirm" authorizes implementation of the proposed 7A READ reporting contract,
with exact-scan counts/coverage/provenance and no compliance score, plus its required validation
and documentation. It does not authorize 7B design choices, reviewer agents, commit, push, PR,
merge or production operations. The completed Sprint 6 Goal and its
conditional publication/merge permission do not carry forward.
The later scoped review and publication approvals below supersede the earlier prohibition only
for the single read-only 7A reviewer and 7A checkpoint/commit/push/PR; merge remains unauthorized.
Reuse the existing worktree; preserve unrelated parent skills and the original 6E.3 checkout.

## Current goal

On 2026-10-02 the user requested a smaller persistent goal: complete 7A and then 7B only.
The implementation-approval blocker persisted for three goal turns, then the user's "Confirm"
resolved it for 7A. Work resumes on `codex/sprint-7a-reporting`, from the verified unchanged main
base, preserving the uncommitted preflight. Browser UI/toolchain and authentication remain
decisions required before 7B. Goal creation does not supply those decisions or authorize reviewer
agents or publication.
The subsequent explicit 7A approvals authorize one read-only independent reviewer and scoped
publication without merge; they do not approve a browser architecture or advance 7B.

Stop after 7A/7B deliverables and their required slice validation, documentation and acceptance
gates. Do not begin 7C, 7D, the whole-dashboard 7E slice or later-sprint work under this goal.
The later slices below remain the proposed full-sprint dependency map, not the current work scope.

## Objective and non-goals

Expose a read-only dashboard for exact-scan technical assessments and investigation, with
version-bound NIST context and explicit collection/assessment coverage.
Use generic services/API, never direct database access from a client.
Do not calculate organization-wide compliance or rewrite technical results through exceptions.

No new collector, AWS permission/control, assessment policy, default catalog, framework artifact,
remediation, governance mutation, tenant isolation, distributed executor, production deployment
or AI runtime. Baseline limitations remain documented and outside this plan unless separately
authorized after a specific finding.

## Approval decisions

1. APPROVED for 7A: the preflight's exact-scan counts/coverage and no compliance-score approach.
2. APPROVED for 7A: an additive generic READ projection,
   `GET /api/v1/scans/{scan_id}/technical-posture`, without changing existing API fields/enums.
3. Before 7B, select UI/toolchain and approve browser authentication/token handling. The existing
   API verifies bearer tokens but does not provide browser login or sessions.
4. Separately authorize implementation, independent review and publication/merging as needed.

## Proposed implementation sequence

| Slice | State | Scope and exit gate |
| --- | --- | --- |
| 7A reporting foundation | IN PROGRESS | Generic service and additive READ schema/route; exact historical/profile/catalog/mapping joins; partial/missing/disabled coverage, bounded bulk queries, SQLite/PostgreSQL/authenticated HTTP and compatibility tests; local validation and independent review passed; acceptance and merge pending |
| 7B authenticated shell | PLANNED | Approved client/auth architecture; same-origin read-only shell, explicit scan selection, login/expiry/logout and lifecycle/error handling; frontend security/build/browser tests |
| 7C investigation views | PLANNED | Assessments, current findings and time-aware exception badges kept distinct; exact scan snapshots/evidence/source/relationship drill-down through accepted APIs; no mutations |
| 7D NIST context views | PLANNED | Exact mapped subset hierarchy and provenance, four-state counts and unassessed coverage; no score or outcome-compliance claim; historical-version browser tests |
| 7E acceptance and closeout | PLANNED | Whole browser-to-API-to-database acceptance with AWS offline, accessibility, security, deterministic scaling, regression, independent review, documentation and required merge approval |

7A precedes 7B; accepted 7A/7B precede 7C and 7D; 7E follows both.
Only after contracts are accepted and explicit user delegation approval may 7C/7D run in parallel.
No independent reviewer was launched for this analysis.

## Compatibility and validation

Preserve all accepted enum values, stable IDs, constructors, ORM/transaction ownership,
response fields, role/capability checks, historical catalogs/profiles/mappings and error meanings.
New reporting models are separate from the four technical result states.
No migration is currently justified; a measured index/schema need requires an additive reviewed
Alembic migration and populated upgrade/downgrade validation on disposable PostgreSQL.

For each requested implementation slice, run targeted tests first, then:

```text
python -m ruff check .
python -m ruff format --check .
python -m pytest
```

Use an explicitly disposable TEST_DATABASE_URL for PostgreSQL validation; never an operator
database. Add the selected frontend's build/type/lint/unit/browser checks before frontend
acceptance. Validate Compose and image whenever runtime/container behavior changes.
Require actual authenticated HTTP and browser journeys, adverse coverage/security states,
no AWS calls from reporting and deterministic query/operation-count tests.
Independent review and human publication/merge approval remain required, not assumed.

## Documentation owners

Update [API](../../api.md) for approved reporting interfaces,
[framework interpretation](../../frameworks/nist-csf-2.0.md) for approved reporting semantics,
[architecture](../../../ARCHITECTURE.md), [security](../../../SECURITY.md) and
[threat model](../../../THREAT_MODEL.md) when the approved client/auth boundary is implemented.
Keep limitations and README current without claiming accepted behavior before gates pass.
Record exact implementation differences and validation/review/publication checkpoints here.

## Original analysis checkpoint

The preflight and draft plan are local documentary work on `codex/sprint-7-preflight`,
base `bafa0783d347ef8b6c5e1182d4c2dd86119b412d`. The roadmap remains Sprint 6 COMPLETE /
Sprint 7 NEXT. The single stale CloudTrail planned-status sentence in known limitations is
reconciled against accepted 6F; operational limitations themselves are not changed.
No application, schema, dependency, runtime, configuration, test or default changes.

Fresh proportionate diagnostics on 2026-10-02:

```text
python -m pytest tests/unit/contracts tests/unit/assessment/test_frameworks.py tests/unit/services/test_read_services.py tests/unit/security -q
116 passed, no skips, 1 existing Starlette/httpx deprecation warning (2.82s)
python -m ruff check .
All checks passed!
python -m ruff format --check .
343 files already formatted
git diff --check
PASS
python -m alembic heads
20261001_0006 (head)
```

The new Markdown files are included in the documentation-link and formatting checks.
Recorded 2,533-test full regression, 252 PostgreSQL cases and container CI remain applicable
to the unchanged application. They were not rerun for this analysis-only documentation delta;
they are not represented as fresh Sprint 7 acceptance and must be rerun for implementation.
Four documentation files are locally uncommitted: this proposed plan, the preflight, ROADMAP.md
and the surgical limitations correction. No commit, push, PR or merge has occurred.
No Sprint 7 implementation or Sprint 8 or later work has started.

## 7A implementation checkpoint — 2026-10-02

User confirmation approved 7A implementation, not the remaining slices or publication.
Local branch `codex/sprint-7a-reporting` reuses the preflight worktree and unchanged verified
main base `bafa0783d347ef8b6c5e1182d4c2dd86119b412d`. Parent skill files and the original
6E.3 checkout remain untouched. All changes remain uncommitted.

The additive generic READ contract is now frozen in [docs/api.md](../../api.md):
`GET /api/v1/scans/{scan_id}/technical-posture`, reporting schema `1.0.0`,
`TECHNICAL_CONTEXT_ONLY`, exact retained scan/profile/catalog/control/framework provenance,
four-state unique assessment counts, definition coverage and assessed-snapshot groups.
Availability is IN_PROGRESS / AVAILABLE / UNAVAILABLE, distinct from assessment/lifecycle states.
Unavailable counts are null; disabled/unassessed rows are not PASS or N/A. Mapped framework
parents union contributing control-version IDs before counting; equal display keys from different
subset releases never merge, and overlapping rows are not additive global totals.
There is no overall technical/framework result, score, manual attestation or compliance claim.

The report reads without AWS, rule evaluation, transaction writes or autoflush. It does not
hydrate configurations, tags or evidence payloads, or combine live exceptions with historical
counts. Tested available mapped reports use ten SELECTs independent of target count; relevant
PostgreSQL plans will be measured on disposable data. No schema/index, dependency, collector,
permission, control, mapping artifact, deployed policy/default or accepted API field changes.
The new provenance-conflict 409 is fixed/sanitized; success and that conflict are no-store.
The existing production bearer verifier and READ/EXECUTE capability separation are unchanged.

Material inspected constraint: accepted `ScanScopeManifestInput` requires nonempty enablement,
and normal persistence requires an explicit result for every enabled control. The proposed
coverage/empty-set semantics do not relax these contracts. A pending row can retain an empty
profile but has unavailable counts; tests assert that an empty completed bundle is rejected.
UNASSESSED remains defensive reporting coverage, not permission to omit required assessments.
The reused scan-detail generic failure prose is not the new availability indicator; retained
PARTIAL/FAILED bundle facts remain visible without changing the established ScanDetail contract.

Tests cover all twelve supported historical catalogs after newer registration, four-state truth
tables, disabled/empty pending coverage, retained partial/failed results, independently valid PASS
under an unrelated collection failure, production-authenticated HTTP roles/token rejection and
lifecycle, exceptions, exact owner/home-Region grouping, synthetic unmapped hierarchy and mapping
fan-out, no AWS/writer calls and fixed query counts. PostgreSQL/full/container gates are pending
at this checkpoint; earlier Sprint 6/preflight totals are not claimed as new acceptance.

Documentation updated: README, roadmap/active plan, API, architecture, security/threat model,
framework interpretation, limitations and the readiness matrix's stale sprint-status sentences.
The existing documentation contract test now asserts the approved Sprint 7 IN PROGRESS state
while preserving accepted Sprint 5/6 closure checks. Released history is not rewritten.

Independent review is pending and no reviewer agent is authorized/launched. No commit, push,
PR or merge. 7B UI/toolchain/browser auth remains a separate user decision after 7A acceptance;
7B, 7C, 7D, 7E and Sprint 8+ implementation have not started.

### Fresh local validation — review still pending

The repository's unchanged `scripts/validate.py` created a new uniquely named PostgreSQL 16
container, bound only to a dynamic loopback port with a temporary in-memory database. Its child
TEST_DATABASE_URL was explicitly generated for that container; operator DATABASE_URL and
TEST_DATABASE_URL were not reused. Random credentials were not printed or placed in argv.
The exact created container was removed in `finally`; disposable test data is gone and user
databases were untouched. The local validation image/cache is retained.

Exact gates on 2026-10-02:

```text
python scripts/validate.py --focused tests/unit/services/test_technical_posture_service.py tests/api/test_technical_posture_api.py tests/integration/test_technical_posture_postgres.py tests/unit/contracts tests/unit/assessment/test_frameworks.py tests/unit/services/test_read_services.py tests/unit/security
Focused: 182 passed, no skips, 1 existing Starlette/httpx warning (62.29s)
python -m ruff check .
All checks passed!
python -m ruff format --check .
348 files already formatted
python -m pytest  [explicit disposable TEST_DATABASE_URL]
2601 passed, no skips, 20 existing warnings (543.95s / 0:09:03)
git diff --check
PASS
docker compose config --quiet
PASS
docker build -t cloud-security-automation:validation .
PASS
python -m alembic heads
20261001_0006 (head)
python -m pytest tests/integration --collect-only -q
277 tests collected (all included in the passing full regression)
```

The 25 new PostgreSQL cases include production-authenticated READ/lifecycle, all historical
releases, four-state counts, disabled/empty pending coverage, owner/home-Region preservation,
fixed ten-SELECT reports at 16/32 targets and real `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)`
plans for both aggregates at 128/512 targets. Aggregate output stays one group in those datasets;
diagnostic timing is not an SLA. No new index/migration was justified for this slice.
The full regression includes the new documentation files and link/contract checks.
Warnings remain the existing one Starlette/httpx deprecation and 19 SQLite datetime-adapter
deprecations. Earlier sandbox-only checks also emitted a pytest-cache access warning; the final
approved validation run had no cache warning. No test or assertion was disabled to get green.

An extra image smoke check ran with no network, no host mounts/ports, a read-only filesystem,
all capabilities dropped and no-new-privileges, under explicit test/development auth and neutral
SQLite settings. Application import, the public OpenAPI reporting operation, bearer security
and the 409 declaration passed. Its first command incorrectly assumed all internal app.routes
entries expose .path; the image's FastAPI includes router wrappers. The diagnostic was corrected
to the public OpenAPI contract, without changing production code or dependencies.
This is an import/schema smoke check, not a production deployment or a browser/HTTP runtime test;
the full API tests above validate real routes, database reads and authentication separately.

All implementation and preflight changes remain local and uncommitted on
`codex/sprint-7a-reporting`, HEAD/base `bafa0783d347ef8b6c5e1182d4c2dd86119b412d`.
7A remains IN PROGRESS pending independent review and acceptance; no reviewer approval,
commit, push, PR or merge is claimed. Next gate: explicit authorization for an independent
read-only 7A review. 7B still needs the separate UI/toolchain/browser-auth decision.

After recording the successful gates, documentation-only checkpoint/status text was updated.
Fresh `python -m pytest tests/unit/contracts -q` passed all 80 checks (0.24s, one existing
Starlette/httpx warning), Ruff passed, all 348 files remained formatted and whitespace passed.
No application/test/runtime change invalidated the complete regression recorded above.

## 7A independent review and publication authorization

Recorded 2026-10-02. After local validation, the user explicitly authorized one independent
read-only 7A reviewer. Agent `/root/review_7a` inspected the frozen 21-file snapshot on
`codex/sprint-7a-reporting`, HEAD/base `bafa0783d347ef8b6c5e1182d4c2dd86119b412d`.
The canonical sorted path/SHA-256 manifest digest was
`19A99B4DE000E146E053EF7AD055C805A7E10FE528E881C90C669692C7D73D9A`, verified unchanged
before and after review by both reviewer and implementer. This identifies the original review
snapshot, not the subsequent documentation-only checkpoint delta.

Verdict: REVIEW_PASS. Unresolved findings: CRITICAL 0, HIGH 0, MEDIUM 0, LOW 0.
Independent validation used the repository interpreter, explicit neutral test/development
settings and disposable in-memory fixtures, with operator TEST_DATABASE_URL removed:

```text
python -m pytest tests/unit/services/test_technical_posture_service.py tests/api/test_technical_posture_api.py tests/unit/contracts tests/unit/assessment/test_frameworks.py tests/unit/services/test_read_services.py tests/unit/security -q -p no:cacheprovider
157 passed, no skips, 1 existing Starlette/httpx warning (24.59s)
python -m ruff check .
All checks passed!
python -m ruff format --check .
348 files already formatted
git diff --check
PASS
python -m alembic heads
20261001_0006 (head)
```

Three additional independent in-memory diagnostics passed: historical scan isolation with SQL
count oracles, malformed framework-parent rejection, and ten bulk SELECTs with exact
snapshot-to-scan joins and no mapping join in assessment aggregates. The reviewer inspected
the PostgreSQL cases and reused the recorded 2,601-test regression, 277 PostgreSQL cases and
container results; those gates were not independently rerun. No implementation correction was
required and no application, test or runtime change invalidated that recorded validation.

After recording the review and reconciling the current-status documentation, fresh
`python -m pytest tests/unit/contracts -q -p no:cacheprovider` passed all 80 checks (0.25s,
one existing Starlette/httpx warning). Ruff passed, all 348 files remained formatted and
`git diff --check` passed. Only ten Markdown files changed from the frozen review snapshot;
all source/test files and the preflight remained byte-identical.

The latest user "Yes" explicitly authorizes recording this checkpoint, committing the scoped
7A work, pushing `codex/sprint-7a-reporting` and opening a PR against `main`, without merging.
The same reviewer will verify the checkpoint/status-only documentation delta and exact committed
HEAD before publication. At this checkpoint no 7A commit, push, PR or merge has occurred;
publication authorization is not a claim that those operations succeeded. Unrelated parent
skill files and the original 6E.3 checkout remain excluded and preserved.

7A and Sprint 7 remain IN PROGRESS pending acceptance and required merge approval. No merge,
auto-merge, release, production operation or additional reviewer is authorized. 7B still needs
the separate UI/toolchain/browser-auth decisions; no 7B, 7C, 7D, 7E or Sprint 8+ implementation
has started.
