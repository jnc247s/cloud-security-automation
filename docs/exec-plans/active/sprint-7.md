# Sprint 7 dashboard and technical posture

Plan state: 7A COMPLETE; 7B APPROVED and IN PROGRESS; later slices remain PROPOSED.
Sprint 7 is IN PROGRESS, not complete.
Prepared: 2026-10-02, after the user's analysis-only preflight request.
Current 7A gates: local validation, exact-head independent review, human merge and merged-main
CI passed. Subsequent confirmations approve the 7B UI/BFF/session design, Cognito target and
controlled local issuer, and implementation. The 2026-10-04 confirmation authorizes one read-only
independent 7B reviewer. The subsequent "Yes" authorizes scoped commit, push and PR creation;
merge, live operations and later slices remain unapproved.
All three initial findings are repaired; final local validation and the same reviewer's technical
re-review passed. Documentary verification, publication, exact-head/main CI and acceptance remain gates.

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
for the single read-only 7A reviewer and 7A checkpoint/commit/push/PR. The owner then merged
PR #42 manually; this does not supply agent merge authority for new work.
Reuse the existing worktree; preserve unrelated parent skills and the original 6E.3 checkout.

## Current goal

On 2026-10-02 the user requested a smaller persistent goal: complete 7A and then 7B only.
The implementation-approval blocker persisted for three goal turns, then the user's "Confirm"
resolved it for 7A. Implementation resumed on `codex/sprint-7a-reporting`, from the verified main
base, preserving the preflight. Browser UI/toolchain and authentication remain
decisions required before 7B. Goal creation does not supply those decisions or authorize reviewer
agents or publication.
The subsequent explicit 7A approvals authorize one read-only independent reviewer and scoped
publication without agent merge; they did not approve a browser architecture or advance 7B.
After the owner merged 7A, the user requested a 7B-only completion goal. The tracker rejected
a second goal because the earlier 7A/7B goal was unfinished; it was not falsely completed.
The user's subsequent "Yes" continues that existing goal toward 7B, starting with local 7A
documentary closeout and the analysis-only [7B design proposal](../../sprint-7b-preflight.md).
No UI/toolchain/authentication choice or 7B coding is authorized by that continuation.

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
3. APPROVED for 7B: React/TypeScript/Vite and the documented BFF/session security contract,
   with Cognito User Pools Essentials as target and a controlled local issuer for tests.
4. APPROVED: 7B implementation only. Independent review and publication/merging remain separate.
5. APPROVED on 2026-10-04: one read-only independent 7B reviewer; no publication/merge authority.
6. APPROVED on 2026-10-04: scoped 7B commit, push and PR creation; no merge/auto-merge,
   additional reviewer, live IdP/AWS/secret/production operation or 7C+ authority.

## Proposed implementation sequence

| Slice | State | Scope and exit gate |
| --- | --- | --- |
| 7A reporting foundation | COMPLETE | Generic service and additive READ schema/route; exact historical/profile/catalog/mapping joins; partial/missing/disabled coverage, bounded bulk queries, SQLite/PostgreSQL/authenticated HTTP and compatibility tests; local validation and exact-head independent review passed; PR #42 manually merged with green merged-main CI |
| 7B authenticated shell | IN PROGRESS | Approved client/auth architecture; same-origin read-only shell, explicit scan selection, login/expiry/logout and lifecycle/error handling; frontend security/build/browser tests |
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

## 7A acceptance and 7B preparation checkpoint

Verified 2026-10-03. The single authorized reviewer returned REVIEW_PASS for final committed
head `333aefdd9032057ad49701271030e0047ce99601`, with zero unresolved findings at every severity.
The unchanged six application files, four test files and original preflight matched their
frozen review hashes. The ten documentation-only updates preserved history and accurately
recorded scoped publication authority. Its fresh independent follow-up passed 80 contracts
(0.23s, one existing warning), Ruff, 348-file formatting and base-to-head whitespace.
No full/PostgreSQL/container run was repeated during that documentation verification.

The agent published the reviewed branch and opened [PR #42](https://github.com/jnc247s/cloud-security-automation/pull/42)
under the user's 7A-only commit/push/PR approval, without merging or enabling auto-merge.
The repository owner `jnc247s` subsequently merged it manually at `2026-10-03T23:21:30Z`,
producing main `bd639f48095ef63e658abd284ce25c927998c0fb`. The verified parents are accepted
base `bafa0783d347ef8b6c5e1182d4c2dd86119b412d` and reviewed head
`333aefdd9032057ad49701271030e0047ce99601`; the merged tree equals the reviewed head's tree.
Both [push CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/37098266021)
and [PR CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/37098276786) passed.
[Merged-main CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/37161516904)
passed all 2,601 tests (277 PostgreSQL cases included, no skips, 20 existing warnings;
651.70s / 0:10:51), Ruff, 348-file formatting and the API image build.
These observations supersede the earlier pending-acceptance checkpoints; those historical
predictions and approval limits remain preserved above. 7A is COMPLETE; Sprint 7 is not.

The user's new goal request and subsequent "Yes" authorize continuing toward 7B through local
7A documentary reconciliation and analysis-only design preparation. After verifying clean,
current main and successful CI, the same preserved worktree switched to a new local branch
`codex/sprint-7b-preflight`, base `bd639f48095ef63e658abd284ce25c927998c0fb`.
The original 7A branch/commit, parent skills and original 6E.3 checkout are preserved.
The [7B preflight](../../sprint-7b-preflight.md) records the inspected browser/API/authentication
contracts, recommended UI/toolchain and alternative authentication boundaries for approval.
The existing documentation-contract assertion is reconciled to accepted 7A status while retaining
Sprint 5/6 closure and the parent's Sprint 7 IN PROGRESS guard; no application behavior changes.

7B remains PROPOSED/PLANNED until the UI/toolchain/browser-auth choice and implementation request.
No frontend dependency or runtime is installed, no browser/IdP/session/API/security boundary is
implemented, and no new reviewer, commit, push, PR, merge or production operation is authorized
for this preparation. No 7C, 7D, 7E or later-sprint work has started.

Fresh local closeout/preparation diagnostics on 2026-10-03, using explicit test/development
authentication, neutral SQLite settings and no operator TEST_DATABASE_URL:

```text
python -m pytest tests/unit/contracts tests/unit/assessment/test_frameworks.py tests/unit/services/test_read_services.py tests/unit/security tests/api/test_technical_posture_api.py -q -p no:cacheprovider
133 passed, no skips, 1 existing Starlette/httpx warning (9.18s)
python -m ruff check .
All checks passed!
python -m ruff format --check .
349 files already formatted
git diff --check
PASS
python -m alembic heads
20261001_0006 (head)
```

The new proposal participates in Markdown-link/contract validation. The only test edit updates
and strengthens the current documentary state assertions; application, schema, dependencies,
runtime, auth and framework/control bytes remain unchanged. The recorded main 2,601-test
regression, 277 PostgreSQL cases and container validation remain applicable to that unchanged
accepted implementation; they were not rerun for this documentary/test-contract delta and are
not represented as post-delta full-suite or new 7B acceptance. Full relevant validation must be
run for the subsequently approved implementation, especially the new browser/session boundary.

Local work is uncommitted: twelve modified documentation/contract files plus the new 7B preflight,
on `codex/sprint-7b-preflight`, HEAD/base `bd639f48095ef63e658abd284ce25c927998c0fb`.
No new reviewer approval, commit, push, PR or merge is claimed. UI/authentication approval and
implementation authority are the next gate; the 7B completion goal remains unfinished.

## 7B design and implementation authorization

The user's subsequent two confirmations approve the documented React/TypeScript/Vite client,
same-origin FastAPI BFF, bounded process-local session store, cookie/CSRF/PKCE/nonce policy and
7B implementation. Cognito User Pools Essentials is the target provider; a controlled local
issuer is approved for automated integration/browser tests. Configure resource binding for
the exact API `aud` and `OIDC_ROLES_CLAIM=cognito:groups`, with only the four recognized groups.
Existing bearer verification, READ capabilities, APIs, defaults and migration head stay unchanged.
The implementation branch is `codex/sprint-7b-authenticated-shell`, retaining preparation changes.
Earlier preparation-only statements remain historical; this authorization supersedes them only
for this slice. No reviewer agent, commit, push, PR, merge, live registration, AWS resource,
secret/IAM change, production operation or 7C+ implementation is authorized.

## 7B implementation checkpoint — 2026-10-03

Local implementation and validation are complete on `codex/sprint-7b-authenticated-shell`,
HEAD/base `bd639f48095ef63e658abd284ce25c927998c0fb`; no changes are staged or committed.
7B and Sprint 7 remain IN PROGRESS pending independent review and required acceptance/merge.
Earlier preparation-only predictions are preserved above, not current authority.

The opt-in React/TypeScript/Vite shell provides server-issued login/session, bounded scan pages,
explicit UUID selection, back/reload/refresh, exact retained scope/profile/catalog/lifecycle,
failure context and report availability. No assessment/evidence/finding/NIST investigation view,
mutation, scan execution, compliance score, latest-scan substitution or account isolation is added.
Types are narrow runtime-validated projections of accepted schemas, not a generated replacement
for the API. Independent detail/posture reads run concurrently; the report's exact scan projection
owns displayed context. Superseded responses and expired/signed-out identities cannot restore data.

The same-process BFF uses Authlib Code/S256 PKCE and joserfc/Authlib ID-token validation, plus the
existing access-token verifier and real API READ dependencies. Random browser-bound state is
consumed once; nonce/verifier/tokens/client credential stay server-side. Opaque cookies are
host-only HttpOnly, Secure under HTTPS, with Strict session/Lax login correlation and exact
Origin/CSRF enforcement. Bounded memory, rotation, idle/absolute/token expiry, restart clearing,
no-store/CSP, sanitized logs/callbacks and in-flight logout checks implement the approved boundary.
No refresh token, development fallback, arbitrary proxy, new capability, migration or AWS call.
Cognito Essentials remains a target registration contract, not a configured production tenant.

Implementation differences from the original proposal: Authlib 1.8.0 uses httpx2 2.13.1 rather
than the existing test-only httpx; joserfc 1.7.5 verifies ID-token signatures. These new runtime
dependencies are exact-pinned without upgrading the existing local backend dependencies.
Node 24.19.0/pnpm 11.19.0, exact frontend releases and its lockfile are selected during approved
implementation. The image builds assets in a Node stage and runs only Python/non-root afterward.
Compose stays loopback and opt-in. CI adds frozen frontend and controlled-issuer real-browser gates;
no published 7B CI run is claimed. Existing protected APIs/defaults/control/framework bytes,
generic services, persistence/transactions and migration head `20261001_0006` are unchanged.

Fresh local validation, with generated disposable PostgreSQL supplied only by the harness:

```text
pnpm --dir frontend install --frozen-lockfile
PASS (pnpm 11.19.0)
python scripts/validate.py --dashboard --focused tests/api/test_dashboard_api.py tests/unit/security tests/unit/test_config.py tests/unit/test_dashboard_config.py tests/api/test_technical_posture_api.py tests/unit/contracts
195 focused passed, no skips (15.95s)
frontend typecheck / lint / build: PASS
frontend units: 7 passed (1.69s)
Playwright: 12 passed, no skips (18.8s), Chromium and Firefox
python -m ruff check .
All checks passed!
python -m ruff format --check .
362 files already formatted
python -m pytest
2666 passed, no skips, 19 existing SQLite deprecation warnings (552.52s / 0:09:12)
277 PostgreSQL integration cases included (collection count separately confirmed)
git diff --check / docker compose config --quiet / multi-stage image build: PASS
python -m pip check: No broken requirements found
pnpm --dir frontend audit: No known vulnerabilities found
python -m alembic heads: 20261001_0006 (head)
```

An initial Firefox launch failed before application execution because the pre-existing Windows
browser cache could not load its mozglue assembly. A fresh isolated installation of the same pinned
Playwright browser launched successfully; both browser suites above passed using that ignored
local cache. No test was removed, skipped or weakened, and the original cache was not overwritten.
Browser journeys use actual built assets, controlled signed OIDC/code/PKCE, real bearer/READ API
and real PostgreSQL, without authentication dependency overrides or AWS. All four recognized
roles, bounded pages, completed/partial/running/failed/no-bundle context, navigation, cookie-only
API denial, CSRF, logout, expiry, keyboard controls and mobile layout are exercised. Backend tests
also deny forged signatures/issuer/audience/roles/nonce/PKCE/browser substitution, callback replay,
injected/duplicate queries, session fixation and stale in-flight reads. Hostile text is escaped.

The browser-verification skill drove an additional isolated agent-browser visual check of the
built shell and exact synthetic historical scan at desktop/mobile widths; no JavaScript errors
or horizontal mobile overflow. Only synthetic screenshots were generated, outside tracked files;
automated browser traces/videos/screenshots remain disabled. The documentation skill preserved
historical checkpoints while updating the responsible owners; React guidance informed concurrent
reads, stable components and abort/generation guards.

The built non-root Python 3.12 image also passed isolated runtime smoke with networking disabled,
generated in-container disposable SQLite upgraded to head, and AWS calls forbidden. Disabled and
enabled lifespans, health/readiness, static assets, opaque secure cookies, real bearer/CSRF denial,
identical public OpenAPI and session clearing passed. Node, tests and the controlled issuer are
absent from the final image. All owned disposable database/inspection/smoke containers were removed;
operator databases and credentials were untouched. Full regression ran locally on Python 3.14.5;
the updated Python 3.12/Linux CI remains a publication gate, not a claimed execution here.

README, roadmap, architecture, API/browser contract, security, threat model, operations and
limitations reflect local work pending acceptance. Accepted 7A history/documentary reconciliation
is retained; no 7B release is claimed in CHANGELOG. The parent checkout still contains only its
unrelated untracked skill files; the original 6E.3 checkout remains clean. All scoped source/test
and documentation changes, including new untracked files, are preserved locally.

Next gate: obtain separate authorization for one read-only independent 7B reviewer. Resolve its
findings and repeat any invalidated checks, then obtain separate commit/push/PR and required merge
approval and verify exact-head/main CI before marking 7B COMPLETE. No reviewer was launched;
no 7B commit, push, PR, merge, live IdP/AWS/IAM/secret or production operation occurred.
No 7C, 7D, whole-sprint 7E or later-sprint implementation was started.

Final checkpoint-only documentation verification: 82 contract/link checks passed, no skips
(0.25s), plus Ruff, 362-file formatting and whitespace. All 42 changed non-Markdown source,
test, dependency, build and configuration files matched their frozen acceptance-run SHA-256
hashes. No full/browser/container run was repeated for this prose-only delta; their unchanged
implementation validation above is reused. Git confirms no staged paths and unchanged HEAD.

## 7B independent review authorization — 2026-10-04

The user's "Yes" answers the explicit request for one read-only independent 7B reviewer.
Independent review is required by AGENTS.md and the approved acceptance plan; skills do not
override the user's separate-approval boundary for launching agents. The add-security-control
skill covers deterministic assessment-control work, not this UI/login slice. This approval
supersedes the earlier reviewer prohibition only for that single review and its follow-up.

Review the entire preserved uncommitted 7B diff, including untracked source/tests and 7A
documentary reconciliation, against base `bd639f48095ef63e658abd284ce25c927998c0fb`. Verify
security, correctness, compatibility, data integrity, scope, documentation and recorded tests.
The reviewer may run relevant safe diagnostics/tests using controlled identities and disposable
databases, but may not edit/stage/commit/publish/merge, launch another agent, touch production or
create live IdP/AWS/IAM/secrets. Prior full validation is recorded evidence, not an independent
rerun. Freeze current review inputs and report exact findings, validation and coverage limits.

7B remains IN PROGRESS, uncommitted and unpublished. Review approval is not REVIEW_PASS or
slice acceptance. No later-sprint work or publication/merge authority is supplied.

## 7B initial review and focused repairs — 2026-10-04

The single authorized read-only reviewer froze all 55 changed tracked/untracked files against
base `bd639f48095ef63e658abd284ce25c927998c0fb` and confirmed unchanged inputs throughout
review (manifest SHA-256 `028ACEB14A6F8DE856F19B06EF4DAE8A825838472AB6A9D8F0653FD15D5E74F1`).
Verdict: REVIEW_CHANGES_REQUIRED, two MEDIUM and one LOW; no HIGH or CRITICAL findings.

1. MEDIUM: non-ASCII state/CSRF caused uncaught comparisons; dashboard outer 500 paths could
   omit security headers and expose callback queries to access logging.
2. MEDIUM: another tab could logout/replace the shared cookie while the shell retained a
   previous identity/report, including successful reads under the new identity.
3. LOW: response guards coerced lifecycle arrays and accepted missing/malformed available counts.

Independent checks passed 195 focused backend tests, 64 additional established service/framework
tests, frontend type/lint/seven units/build, Ruff/362-file formatting, whitespace and Compose.
Adverse HTTP, actual Chromium/controlled signed issuer/real bearer READ/disposable migrated SQLite
and actual compiled client-guard diagnostics reproduced the findings. The reviewer inspected,
but did not rerun, the recorded full/PostgreSQL/two-browser/image/smoke acceptance.
No reviewer edits, publication, live provider/AWS or operator database changes occurred.

Local repairs stay within 7B: bounded ASCII opaque-value comparisons; secured fixed 500s with
callback-query redaction and re-raised programming failures; dedicated public session_context
and mandatory X-Dashboard-Context on the three BFF reads before real bearer forwarding;
credential-free ephemeral cross-tab invalidation with logout-in-flight and generation guards;
exact string enums and four finite nonnegative integer count fields (null remains unavailable).
The context is not a token or capability. All established /api/v1 contracts, four READ roles,
defaults, control/framework bytes, persistence and migration head remain unchanged.
Tests cover malformed authentication/errors, missing/stale correlation without invalidating
the current session, two identities/tabs, superseded work and malformed/real-zero projections.

Fresh targeted fixes currently pass 54 backend checks and 14 frontend units/type/lint. Formatting
and frozen install pass. These are not final acceptance: remaining source adjustments require
the complete regression, PostgreSQL/browser/container/security gates and the same reviewer's
follow-up before REVIEW_PASS. Earlier checkpoints remain historical evidence, not a claim that
the changed implementation is validated. No new reviewer, 7C+ work or publication is authorized.

## 7B post-review validation and independent closeout — 2026-10-04

All three findings above are resolved. The same authorized read-only reviewer returned
REVIEW_PASS with zero unresolved findings at any severity, and no introduced product findings.
This is technical review of the preserved uncommitted implementation, not slice acceptance,
publication authority or a review claim about a future commit. 7B/Sprint 7 remain IN PROGRESS.

Fresh final parent-run acceptance after the repairs:

```text
pnpm --dir frontend install --frozen-lockfile
PASS, pinned pnpm 11.19.0, no dependency upgrades
python scripts/validate.py --dashboard --focused tests/api/test_dashboard_api.py tests/unit/security tests/unit/test_config.py tests/unit/test_dashboard_config.py tests/api/test_technical_posture_api.py tests/unit/contracts
205 focused passed, no skips (17.33s)
frontend typecheck / lint / build: PASS
frontend units: 15 passed (1.82s)
Playwright: 14 passed, no skips (20.1s), Chromium and Firefox
python -m ruff check .
All checks passed!
python -m ruff format --check .
362 files already formatted
python -m pytest [harness-generated disposable TEST_DATABASE_URL]
2676 passed, no skips, 19 existing SQLite deprecation warnings (569.01s / 0:09:29)
277 PostgreSQL integration cases included; collection count confirmed separately
git diff --check / docker compose config --quiet / multi-stage image build: PASS
python -m pip check: No broken requirements found
pnpm --dir frontend audit: No known vulnerabilities found
python -m alembic heads: 20261001_0006 (head), unchanged
```

The browser suite adds two-tab tests in both engines: held logout HTTP still clears both tabs,
opening a same-session tab does not reset a selected report, replacement identity B synchronizes,
and old-context reads cannot return data under B's cookie. Frontend units also reject delayed
old-identity results, superseded bootstrap/logout errors, stale tab announcements, malformed
notifications and unsupported count/lifecycle shapes. No assertion, skip or auth bypass was added
to avoid a failure. Required controls/framework artifacts and accepted API fields remain unchanged.

The browser-verification skill drove another agent-browser inspection of actual rebuilt assets,
synthetic signed login and an exact retained report at desktop and 390-pixel mobile widths.
Meaningful content, correct historical context, no error overlay/page error and no horizontal
overflow were verified; only synthetic screenshots were inspected. The separate owned
PostgreSQL fixture and browser session were closed/removed. An initial CLI argument-quoting error
was corrected by passing evaluation through standard input; it was not an application failure.

The freshly rebuilt non-root Python 3.12 image passed another disposable smoke with networking
disabled, generated in-container SQLite migrated to head, and AWS forbidden. Disabled/enabled
actual lifespans, health/readiness, real bearer/CSRF denial, built static assets, secure opaque
cookies, no-store/CSP, fixed unexpected callback 500, identical public OpenAPI and shutdown
clearing passed. No Node/tests/controlled issuer are in the final image. All parent-owned
containers were removed, with no operator database or live credential/provider/AWS operation.
Full regression remains Windows/Python 3.14.5; Linux/Python 3.12 exact-head CI is still a gate.

Independent follow-up (not a rerun of the parent's full acceptance): 205 focused backend tests
passed (23.63s), frontend type/lint/build and 15 units passed (1.86s), six adverse HTTP cases and
18 actual compiled guard checks passed, plus Ruff/362-file formatting/whitespace/Compose.
Four additional Chromium/Firefox journeys used real signed OIDC/JWKS, actual bearer/READ and
an owned migrated SQLite database. They proved immediate cross-tab clearing while logout was
pending, held outgoing-context announcement rejection, A-to-B identity synchronization, all
three stale-context BFF denials, valid current-context reads, cookie-only API denial, no Web
Storage/page errors, and correct fail-closed recovery on the next read when notifications were
deliberately missed. The reviewer also inspected a native browser snapshot/screenshot.
Windows CLI capture handling and an in-memory SQLite shared-connection diagnostic failure were
corrected in its temporary tooling/fixture, without source edits or weakened application checks.
Its owned servers, browser sessions and temporary databases were removed.

The reviewer verified all 56 frozen review inputs unchanged (manifest SHA-256
`78EAE79059353608C7042A96746919BE2A2E3170CF8DDABA980CDF7ABA3263FF`). The independently
verified 43-file non-Markdown implementation/test/build/config/dependency fingerprint is
`AEC14F9E3CAF5F72E79B2C2BFAC95A99DF0B658331D38DC32936CBD461F04152`.
Reproduce the latter from the union of `git diff --name-only` and
`git ls-files --others --exclude-standard`, PowerShell-sorted unique paths excluding `.md`;
each line is path, TAB, uppercase file SHA-256; UTF-8 LF-delimited with no trailing LF, then SHA-256.
This final closeout changes prose only; unchanged code validation is reused, with fresh
contract/link/whitespace checks and the same reviewer's documentary verification still required.
React guidance informed the scoped effect cleanup/generation handling and single tab listener;
documentation guidance preserved historical predictions and separate approval records.

Git remains `codex/sprint-7b-authenticated-shell`, HEAD/base
`bd639f48095ef63e658abd284ce25c927998c0fb`, with no staged changes, 7B commit, push, PR or merge.
The parent has only its unrelated untracked skill files, and the original 6E.3 checkout is clean;
all product changes, including new source/tests, are preserved. Live Cognito/MFA/ingress/TLS,
production deployment, shared sessions, tenant isolation and global IdP logout remain unvalidated
or deliberately outside this slice. No 7C, 7D, whole-sprint 7E or later implementation started.

Next minimum gates: final documentary verification; separate scoped commit/push/PR approval;
review of the exact committed inputs and green exact-head CI; required human merge approval and
green merged-main CI before marking 7B COMPLETE. The existing goal remains unfinished. No new
reviewer or publication/merge/live-operation authority is inferred from REVIEW_PASS.

## 7B final documentary review and publication authorization — 2026-10-04

The same read-only reviewer returned final REVIEW_PASS with zero unresolved findings for the
post-review documentary closeout. Reversing only the declared roadmap addition, threat/current-risk
updates and active-plan current-state replacement/appendix reproduced each previous file hash;
the other 53 files, including all 43 non-Markdown inputs, were unchanged. Fresh independent
82 contract/link checks (0.24s), Ruff, 362-file formatting and whitespace passed. Full/browser/image
checks were not repeated for this prose-only delta; the unchanged implementation validation is reused.
The final 56-file review manifest is
`400E67F39E51C36729A86BBCE38624DBDFDCE043621773FA7443825BE1489AB5`
(PowerShell-sorted path/TAB/uppercase file SHA-256, UTF-8 LF-delimited with a trailing LF).
Its non-Markdown fingerprint remains
`AEC14F9E3CAF5F72E79B2C2BFAC95A99DF0B658331D38DC32936CBD461F04152`
(the earlier 43-file format has no trailing LF).

The user's "Yes" answers the explicit request to commit 7B, push its scoped branch and open a
PR. This supersedes the earlier publication prohibition only for those actions. It does not
authorize merging/auto-merge, another reviewer, live Cognito/IdP registration, secret/IAM/AWS or
production changes, or 7C+ implementation. The purpose question requests an explanation of the
existing authenticated shell, not expanded dashboard scope.

Before publication, the parent verified the exact reviewed 56-file manifest and unchanged
implementation fingerprint. Git remains `codex/sprint-7b-authenticated-shell`, with base/HEAD
`bd639f48095ef63e658abd284ce25c927998c0fb`, empty staging and preserved untracked source/tests.
GitHub origin is the expected `jnc247s/cloud-security-automation`; current remote main is still
that base, and no PR already exists for this branch. No commit/push/PR has occurred at this
authorization checkpoint. Only this documentary authorization delta is new; technical validation
and review remain applicable after fresh documentary checks and same-reviewer input verification.

Publish only the 56 scoped files. Parent-checkout untracked skills, ignored browser/build/cache
artifacts and the original clean 6E.3 worktree remain excluded and untouched. Verify the exact
committed inputs and exact-head CI, and record the actual PR without claiming acceptance. Human
merge approval and green merged-main CI remain required before 7B COMPLETE; the goal is unfinished.
