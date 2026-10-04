# Sprint 7 dashboard and technical posture

Plan state: 7A COMPLETE; 7B COMPLETE; 7C IN PROGRESS; later slices remain PROPOSED.
Sprint 7 is IN PROGRESS, not complete.
Prepared: 2026-10-02, after the user's analysis-only preflight request.
Current 7A gates: local validation, exact-head independent review, human merge and merged-main
CI passed. Subsequent confirmations approve the 7B UI/BFF/session design, Cognito target and
controlled local issuer, and implementation. The 2026-10-04 confirmation authorizes one read-only
independent 7B reviewer. The subsequent "Yes" authorizes scoped commit, push and PR creation;
the subsequent confirmation approves PR #43's merge after green final-head CI.
The latest request supplies the sequential remaining-Sprint-7 goal recorded below;
live operations and later-sprint work remain unapproved.
All three initial findings are repaired; final local validation, documentary verification and
the same reviewer's exact-commit review passed. Both final-head CI runs passed. The subsequent
"Yes" approved merging PR #43 after those gates; it is merged at `9ace4e65f15be678d3f05c4b5ef3a9896d4ea187`.
Merged-main CI passed; 7B is COMPLETE. The separate acceptance-record closeout has scoped
publication and guarded merge approval through the latest "Yes merge"; its checkpoints below
record actual commit/publication/merge gates rather than infer completion from permission.
The new request authorizes the gated 7C, 7D and final Sprint 7 workflow, not live operations.
The same confirmation approves the proposed 7C additive read contracts and one read-only
independent reviewer agent per 7C, 7D and final Sprint 7 review. The 7B closeout requires
exact-input review, final-head CI, guarded merge and merged-main CI before implementation.

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

On 2026-10-04 the user requested a persistent goal for 7C preflight, implementation, review,
push and merge, then the same sequence for 7D, followed by whole-Sprint-7 correctness review
and closeout. The tracker accepted this new goal as ACTIVE. The unpublished 7B acceptance record
remains a prerequisite; the earlier goal is not declared complete merely to create this one.
See the [goal-setup checkpoint](#remaining-sprint-7-goal-setup--2026-10-04) for scope and gates.
The earlier 7A/7B goal history below retains its original restrictions; the latest request
supersedes its slice boundary only for the newly requested remaining-Sprint-7 workflow.
The user's subsequent "Yes merge" confirms the requested approval bundle and continuation:
finish the reviewed 7B documentary prerequisite, implement 7C using its approved additive read
contracts, then complete 7D and 7E sequentially through all review/publication/merge gates.
No deliverable is accepted merely because its implementation or merge is authorized.
The latest observed tracker status is BLOCKED from the preceding approval audit; approval 9
resolves the permission questions but has not reactivated the tracker. User-controlled resumption
of that existing goal is needed for automatic continuation, not a replacement goal or renewed
publication/design approval. The [handoff checkpoint](#7b-closeout-main-ci-and-remaining-sprint-7-handoff--2026-10-04)
records the completed prerequisite and remaining work without marking the objective complete.

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

Under that earlier goal, stop after 7A/7B deliverables and their required slice validation,
documentation and acceptance gates. Do not begin 7C, 7D, the whole-dashboard 7E slice or
later-sprint work under that earlier goal.
That historical boundary does not grant authority; the latest request above supplies the new scope.

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
7. APPROVED on 2026-10-04: merge PR #43 only after green final-head CI and the existing
   independent review. The merge is complete and merged-main CI passed.
   This is not authority for another PR/merge, auto-merge, live operations or later slices.
8. REQUESTED on 2026-10-04: complete 7C, then 7D, then whole-Sprint-7 review and closeout,
   with preflight before each implementation and review, scoped publication and guarded merge
   before proceeding. Material unresolved design/policy choices require guidance.
   The separate 7B acceptance-record publication and use of one read-only independent reviewer
   agent per 7C, 7D and final Sprint 7 review require explicit confirmation.
   No parallel implementation, auto-merge, live operation or Sprint 8 work is authorized.
9. APPROVED on 2026-10-04: the user's "Yes merge" answers the pending bundle question:
   publish and conditionally merge the reviewed 7B acceptance record; use one read-only
   independent reviewer agent per 7C, 7D and final Sprint 7 review; add the optional UUID scan_id
   resource-history filter and server UTC reference-time metadata for exception display.
   Existing callers without that filter, upstream API bodies/statuses, real bearer/READ
   enforcement and technical results remain unchanged. This resolves the preceding permission
   gate, not validation, acceptance or future material design choices.
   Preserve exact-head review/green CI/guarded ordinary merge/merged-main CI for each slice.

## Proposed implementation sequence

| Slice | State | Scope and exit gate |
| --- | --- | --- |
| 7A reporting foundation | COMPLETE | Generic service and additive READ schema/route; exact historical/profile/catalog/mapping joins; partial/missing/disabled coverage, bounded bulk queries, SQLite/PostgreSQL/authenticated HTTP and compatibility tests; local validation and exact-head independent review passed; PR #42 manually merged with green merged-main CI |
| 7B authenticated shell | COMPLETE | Same-origin read-only shell, explicit scan selection, login/expiry/logout and lifecycle/error handling; local/security/build/browser validation and exact-head independent review passed; PR #43 merged under explicit approval with green merged-main CI |
| 7C investigation views | IN PROGRESS | Assessments, current findings and time-aware exception badges kept distinct; exact scan snapshots/evidence/source/relationship drill-down through accepted APIs; no mutations |
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

## 7B publication checkpoint — 2026-10-04

The authorized 56-file implementation was committed at
`ff2088be98928fdf87ca0bc9216c722e71713ec2`, with sole parent
`bd639f48095ef63e658abd284ce25c927998c0fb`. The same read-only reviewer returned exact-commit
REVIEW_PASS with zero unresolved findings. Every committed blob matches its frozen reviewed
working-file hash; no newline normalization was needed despite `core.autocrlf=true`.
Its 56-file manifest is
`97DE51C2186E2678E88D541BBAACB63849AB8A2D70B98D59047B01436EE8926B`
(the all-file format above includes a trailing LF). The 43-file implementation fingerprint
remains `AEC14F9E3CAF5F72E79B2C2BFAC95A99DF0B658331D38DC32936CBD461F04152`.
Fresh independent 82 contract/link checks, Ruff, 362-file formatting and committed whitespace
passed. Prior full/PostgreSQL/browser/container/security validation remains applicable to
these identical implementation inputs; commit creation did not require rerunning it locally.

The branch was pushed normally, without force, to the verified origin and
[PR #43](https://github.com/jnc247s/cloud-security-automation/pull/43) opened against `main`.
Readback confirms the exact head above, OPEN state and no auto-merge request. Both exact-head
Linux/Python 3.12 CI runs are in progress at this checkpoint:
[push run](https://github.com/jnc247s/cloud-security-automation/actions/runs/37186469092) and
[PR run](https://github.com/jnc247s/cloud-security-automation/actions/runs/37186471380).
No CI success or slice acceptance is claimed before those gates finish. This publication
record is a subsequent prose-only closeout delta requiring fresh documentary checks and the
same reviewer's verification before its own normal push; prior technical validation is reused
only while the implementation fingerprint remains unchanged.

The committed worktree was clean and tracking its scoped origin branch. Unrelated parent
skill files, ignored generated/build/browser/cache files and the original 6E.3 checkout remain
excluded and untouched. The documentation guidance keeps earlier pre-publication checkpoints
historical rather than rewriting their predictions or approval limits.
The README's current 7B summary is reconciled with the final post-review test totals,
independent REVIEW_PASS and actual PR; its earlier pre-review/publication wording was stale.
The known-limitations CI summary likewise describes the published branch while retaining
the exact-head acceptance gate and supply-chain coverage limits.
The security owner's current validation summary and the preflight's superseding-authority
header are reconciled as well; the original analysis, approval limits and security design remain
unchanged. These documentary corrections do not alter the implementation fingerprint.

7B/Sprint 7 remain IN PROGRESS and the existing goal unfinished. The user authorized commit,
push and PR creation only. Do not merge or enable auto-merge without separate human authority;
require green final-head CI, independent final-input review, required human merge approval
and green merged-main CI before 7B COMPLETE. Live Cognito/MFA/TLS/production setup remains
unvalidated; no IdP/secret/IAM/AWS operation or 7C+ implementation occurred.

## 7B merge authorization and main CI — 2026-10-04

The user's subsequent "Yes" answers the explicit request to merge PR #43 once final-head CI
is green. Before merging, the parent verified PR #43 OPEN/MERGEABLE/CLEAN against the unchanged
accepted main base, no auto-merge request, both final-head CI runs COMPLETED/SUCCESS, and all
56 final working inputs matching the independent-review manifest. The same reviewer returned
REVIEW_PASS with zero unresolved findings for exact final head
`f7e842c2c2075b280c3046ee65a3ee5463130d81`. All six final documentary owners were reconciled,
all 43 implementation inputs were unchanged, and fresh independent 82 contract/link checks,
Ruff, 362-file formatting and combined whitespace passed. Final manifest SHA-256:
`2DA7E5E946ED044B3BA7CDB9A61446C980C055AF11C8E8EA93FF0E0786E5C885`.

Both exact-head Linux/Python 3.12 runs passed:
[push CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/37187395768) and
[PR CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/37187398112).
The inspected PR run passed all 2,676 backend tests, including the 277 PostgreSQL cases,
with no skips and 19 existing warnings (416.92s / 0:06:56), frontend type/lint/build and
15 units, 14 Chromium/Firefox journeys (16.1s), Ruff/362-file formatting and the image build.
These are fresh CI results, distinct from the earlier local acceptance and reviewer checks.

The parent used a normal merge with an exact-head guard, without auto-merge, administrator
bypass, force-push or branch deletion. Readback confirms PR #43 MERGED at 2026-10-04 08:36:29 UTC,
merge commit `9ace4e65f15be678d3f05c4b5ef3a9896d4ea187`. Its parents are the accepted 7A main
`bd639f48095ef63e658abd284ce25c927998c0fb` and exact reviewed head `f7e842c`; its tree
`8bde0f05e68c517caa2c4d424dc2c35e8ebb2c0d` equals the reviewed head's tree.
Fetching main changed only local remote-tracking metadata; no checkout/reset/clean occurred.

[Merged-main CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/37189473834)
is running at this checkpoint. 7B remains IN PROGRESS until that gate and documentary closeout
pass; Sprint 7 is not complete. The approval covers PR #43 only, not another PR/merge or
live Cognito/MFA/TLS/secret/IAM/AWS/production operations. No 7C+ work started. The existing
7A/7B goal is not falsely completed while acceptance gates remain. Earlier prohibitions and
running-state checkpoints remain historical; this section records their scoped supersession.

## 7B acceptance and scoped goal boundary — 2026-10-04

[Merged-main CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/37189473834)
completed SUCCESS for exact merge `9ace4e65f15be678d3f05c4b5ef3a9896d4ea187`.
Fresh Linux/Python 3.12 results: 2,676 backend tests passed, including all 277 PostgreSQL
integration cases, no skips and 19 existing warnings (654.94s / 0:10:54); frontend type/lint/build,
15 units and 14 Chromium/Firefox journeys (23.4s) passed, as did Ruff, 362-file formatting and
the multi-stage image build. The job completed in 13m45s. Its Node-action deprecation and
future ubuntu-latest migration annotations are non-failing supply-chain/runtime notices,
not a new permission to upgrade CI dependencies or start hardening work.

All implementation gates now passed: approved scope/design, local targeted/full/PostgreSQL/
browser/runtime/security validation, independent REVIEW_PASS with zero unresolved findings,
reviewed exact final head, green final-head CI, explicit user merge approval, verified normal
merge and green merged-main CI. 7A and 7B are COMPLETE; Sprint 7 remains IN PROGRESS.
The plan stays active because 7C, 7D and 7E remain PLANNED and unimplemented. Stop at the
approved 7A/7B boundary; no later-slice authority is inferred from acceptance or the goal.

This local closeout reconciles README, roadmap/plan, accepted architecture/security/threat/API
and operation/limitation summaries, preflight's superseding header and accepted CHANGELOG history.
Original predictions, approval restrictions and pending-gate checkpoints remain historical.
The existing documentation-state test now checks the first normative Plan state line for
accepted 7A/7B and retains the Sprint 7 IN PROGRESS / 7C--7E PLANNED guards. This is a stronger
current-state assertion, not a skip or weakened acceptance check.

No runtime, frontend, API field, role, capability, migration, collector, control, framework
artifact, default, dependency, configuration or deployment behavior changes. The 42 unchanged
non-Markdown source/test/build/configuration inputs (excluding that documentation-state test)
retain fingerprint `2EC02873F4657B6E5F2D9B678073F08A56E039B1551C9D56AB3EBA3A72867840`
(sorted path/TAB/uppercase SHA-256, UTF-8 LF-delimited without a trailing LF).
The former 43-file fingerprint is historical; it is not asserted for the changed test guard.
Accepted full/browser/image validation applies to the unchanged application; fresh documentary
checks and the same reviewer's closeout verification remain required for this local delta.

At this writing, the acceptance record and matching test guard are uncommitted and unpublished
in the preserved worktree. The user approved merging PR #43 only. A separate question asks
whether to publish and conditionally merge this bounded acceptance-closeout PR; no answer
or additional PR/merge authority is assumed. The implementation portion of the 7A/7B goal
is delivered; final closeout/publication remains outstanding, so the goal is not falsely completed.
Parent skills and the original 6E.3 checkout remain untouched. Live Cognito/MFA/TLS, production
setup, shared sessions, tenant isolation and global IdP logout remain unvalidated or excluded.

Fresh local closeout verification: `python -m pytest tests/unit/contracts -q -p no:cacheprovider`
passed all 82 checks, no skips (0.28s); `python -m ruff check .`,
`python -m ruff format --check .` (362 files) and `git diff --check` passed. The changed test
only strengthens the documentation-state assertion and is fully exercised by those checks.
The 42-file fingerprint above is rechecked before independent review; all application/frontend/
dependency/build/configuration inputs remain unchanged. No local full/browser/container rerun
is claimed for this documentary delta; the passing exact merged-main implementation validation
above is reused. Same-reviewer documentary verification and separate closeout publication
authority remain pending at this local checkpoint.

## Remaining Sprint 7 goal setup — 2026-10-04

The user's new request sets the sequence: 7C investigation preflight -> implementation ->
independent review -> scoped push/PR/merge; then 7D version-bound NIST context through the same
gates; then 7E whole-Sprint-7 correctness, security, compatibility and acceptance review and
closeout. The tracker returned an ACTIVE goal without a requested token budget. Creation is
not evidence of delivered work or completion of the earlier unpublished 7B acceptance record.
7A/7B remain COMPLETE, Sprint 7 remains IN PROGRESS, and 7C/7D/7E remain PLANNED.

Before starting implementation, publish the reviewed 7B acceptance record only after its
separate approval, then establish a scoped branch from verified clean, current main without
discarding any preserved work. Inspect accepted contracts, callers, tests and security/history
risks during each preflight; resolve material new design or policy choices before coding.
Preserve read-only investigation, distinct assessment/finding/exception semantics, exact-scan
evidence and version-bound reporting-only NIST mappings. Do not add a compliance score.

Each implementation requires targeted tests, Ruff/formatting, full regression, applicable
disposable PostgreSQL, frontend/browser/security and Compose/image validation, documentation
and independent review with all findings resolved. Reuse recorded validation only when inputs
and governance permit it. Publish scoped reviewed inputs; merge only the exact reviewed head
after green final-head CI, without force/admin bypass or auto-merge. Verify merged-main CI
before advancing. The final acceptance review covers the whole Sprint 7 flow and accepted
baselines; reconcile README and all authoritative owners, and archive the plan only after
the required closeout gates succeed.

One read-only independent reviewer agent for each new review and publication of the pending
7B closeout are awaiting explicit confirmation. No new reviewer, 7C/7D implementation,
publication or merge occurred during goal setup. These two owner-file updates are a new
documentary delta, not part of the previously frozen 7B closeout review inputs.
Preserve parent skill files and the original 6E.3 checkout. Stop for conflicting sources,
missing authority or material choices requiring guidance. No live IdP/AWS/IAM/secret change,
production deployment/mutation, remediation, parallel implementation or later-sprint work.

## 7B closeout publication approval and remaining scope — 2026-10-04

The user's "Yes merge" confirms the preceding approval bundle. Scoped 7B acceptance-record
commit/push/PR and conditional merge are authorized, together with one read-only independent
reviewer agent for each of 7C, 7D and final Sprint 7 review. The two prepared 7C additions are
approved: optional exact-scan history filtering and a server UTC reference time for operational
exception display. No new policy, migration, credential, live IdP/AWS/IAM/secret/deployment,
remediation or later-sprint operation is approved.

Readback confirms PR #43 is already MERGED at `9ace4e65f15be678d3f05c4b5ef3a9896d4ea187`
and its merged-main CI is COMPLETED/SUCCESS. A fresh fetch finds main unchanged; the current
implementation HEAD `f7e842c2c2075b280c3046ee65a3ee5463130d81` has the identical accepted tree.
No open PR exists at this checkpoint. Publication is not repeated for the already merged code.

The pending closeout is the preserved 12-file documentation/current-state-guard delta, with
new goal/approval metadata in roadmap/plan. The separate local 7C analysis file must stay out
of a 7B-only commit; it will be retained for the subsequent scoped 7C branch. The existing 7B
reviewer must verify the final closeout inputs, then the parent can publish only those reviewed
inputs, wait for green exact-head CI and merge normally with an exact-head guard. Verify main CI
before starting implementation from a clean, current accepted baseline.

Status remains 7A/7B COMPLETE, Sprint 7 IN PROGRESS, 7C/7D/7E PLANNED. 7C has a local
analysis-only preflight, not implementation. 7D and whole-Sprint-7 acceptance have only the
existing full-sprint dependency/scope proposal; their separate preflights and implementation/
review are not completed. The latest approval permits work through the requested sequence,
not a claim that those deliverables already exist. All historical restrictions/checkpoints
remain intact with their explicit scoped supersession here.

## 7B closeout committed inputs — 2026-10-04

The scoped closeout is committed at `cb4f320442cd43c8bdc6d04dfb4fe90d2569a4cd` on
`codex/sprint-7b-acceptance-closeout`, with sole parent accepted main
`9ace4e65f15be678d3f05c4b5ef3a9896d4ea187`. Exactly the 12 reviewed documentation/status-guard
files are included. The only untracked task input is the separate 7C preflight; its unchanged
SHA-256 is `C6E934C5AF3DB947C436F081CEF09FB1035414F16B2C0CAA0D90EAFD3348E318`.
Parent skills and the original 6E.3 checkout remain untouched.

The same reviewer returned independent REVIEW_PASS with zero unresolved findings for those
working inputs, manifest `A5C8839B0C65DACE1EC3625193B5B3EB3D4D0A48E45784B12DA9DE3A7AB1D8AB`
(sorted paths, TAB/uppercase file SHA-256, UTF-8 LF, trailing LF). Independent 83 contracts,
seven adverse status mutations, 138 scoped tracked links, Ruff, formatting and whitespace passed;
the extra local contract case belongs to the excluded 7C Markdown file. The 42 unchanged
implementation inputs retain fingerprint `2EC02873F4657B6E5F2D9B678073F08A56E039B1551C9D56AB3EBA3A72867840`.
Recorded accepted-main full/PostgreSQL/frontend/browser/image validation is reused for unchanged
application behavior; no new full-suite run is claimed here.

This narrow roadmap/plan update records committed rather than uncommitted inputs and removes
a stale normative uncommitted claim. Exact-commit readback and review of this documentary delta
remain required before publication. Final-head CI, guarded ordinary merge and merged-main CI
are still pending at this checkpoint. No 7C/7D/7E code or production operation has occurred.

## 7B documentary closeout merge and 7C preparation — 2026-10-04

The same reviewer returned exact-head REVIEW_PASS with zero divergence or unresolved findings
for `7e75e96e328ef61de61556fd54d2357d4e3ad54b`, including its two-document status correction.
All 12 committed blobs matched final manifest
`31C13F73A9FFD059661CF30258BC050ACD5FC45D8226DC59C10260DDF89DBAB6`.
The excluded 7C preflight retained its original digest through publication and merge preparation.

[PR #44](https://github.com/jnc247s/cloud-security-automation/pull/44) contained exactly those
12 files and two reviewed commits. Both exact-head runs passed:
[push CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/37223426523) and
[PR CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/37223429486).
Fresh inspected PR results: 2,676 backend tests, no skips, 19 existing warnings
(693.97s / 0:11:33), including the unchanged 277 PostgreSQL cases; 15 frontend units and
14 Chromium/Firefox journeys (23.2s); type/lint/build, Ruff, 362-file formatting and image build.
The quality job completed in 14m7s. Existing non-failing Node-action and future runner notices
do not authorize dependency or hardening changes.

Before merging, the parent rechecked both successful exact-head runs, unchanged main base,
clean tracked inputs, PR OPEN/MERGEABLE/CLEAN and absent auto-merge. The approved ordinary merge
used an exact-head guard, no force/admin bypass or branch deletion. Readback confirms MERGED
at 2026-10-04 18:27:10 UTC, commit `f14d8610eefa9b3e20c11aab50c4b0a4e16ab15c`, parents
`9ace4e65f15be678d3f05c4b5ef3a9896d4ea187` and reviewed `7e75e96`.
Tree `3c96d37a0c3ecf54e8490826ca74a0482c875cc1` equals the reviewed head's tree.

[Merged-main CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/37224494667)
is IN PROGRESS at this checkpoint. The parent prepared `codex/sprint-7c-investigation` from
verified clean tracked main at `f14d861`, preserving the sole untracked 7C preflight. No code
is changed while that gate runs. The [7C preflight](../../sprint-7c-preflight.md) now records the
approved additive contracts and preserves its original analysis. This link is part of the
new local 7C documentary slice, not the merged 7B-only PR.
7A/7B remain COMPLETE, Sprint 7 IN PROGRESS, 7C/7D/7E PLANNED; the final review is not performed.
No live IdP/AWS/IAM/secret/deployment/remediation or later-sprint operation occurred.

## 7B closeout main CI and remaining Sprint 7 handoff — 2026-10-04

[Merged-main CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/37224494667)
completed SUCCESS for exact merge `f14d8610eefa9b3e20c11aab50c4b0a4e16ab15c`.
Fresh readback confirms PR #44 MERGED with reviewed head `7e75e96`, and remote main still at
that exact merge. The earlier verified parent/tree bindings remain unchanged. Linux/Python 3.12
passed 2,676 backend tests, including the unchanged 277 PostgreSQL cases, no skips and 19
existing warnings (666.54s / 0:11:06); frontend type/lint/build and 15 units, 14 Chromium/Firefox
journeys (23.8s), Ruff, 362-file formatting and the API image build passed. The quality job
completed in 13m43s. Existing non-failing Node-action and future runner annotations remain
limitations, not permission to upgrade dependencies or start later-sprint hardening.

The reviewed 7B acceptance-record prerequisite is delivered through PR #44, including README
and its accepted-state owners. All its review, exact-head CI, explicit merge approval, guarded
ordinary merge and merged-main CI gates passed. This does not implement or accept 7C, 7D or 7E.
7C has an approved analysis-only preflight and scoped branch at accepted main; 7D and whole-sprint
7E have only their scope/dependency proposal, not completed separate preflights or implementation/
review. Next is 7C implementation through the approved sequential gates, then 7D, then 7E.

At handoff, `codex/sprint-7c-investigation` remains at `f14d861`, with empty staging and only
local uncommitted ROADMAP.md, this plan and the untracked 7C preflight as documentary preparation.
No 7C application, frontend, API field, schema, dependency, default or configuration change
occurred. The parent checkout still has only its unrelated untracked `.agents/` work; the original
6E.3 checkout is clean. Neither was modified or included in a closeout commit.
Recorded full/frontend/browser/image validation is evidence for the unchanged accepted baseline;
all required implementation gates must run freshly for subsequent 7C code changes.

The goal tracker still reports BLOCKED after the previous approval audit. The latest user
confirmation resolves those permission questions but does not change the observed lifecycle.
The model's goal tools do not expose reactivation, and the objective is not complete; it was not
reset, replaced or falsely completed. Resume the existing goal through its user-controlled
lifecycle to enable automatic continuation. No additional scope or publication authority is
required for the already approved bundle; material new choices still require guidance.
Sprint 7 remains IN PROGRESS, 7C/7D/7E PLANNED. No new reviewer, live IdP/AWS/IAM/secret/
deployment/remediation operation, parallel implementation or Sprint 8+ work occurred.

Fresh local handoff checks: `python -m pytest tests/unit/contracts -q -p no:cacheprovider`
passed 83 checks, no skips (0.25s); Ruff, 363-file format checking and `git diff --check` passed.
The extra local contract case covers the untracked 7C Markdown file; merged-main CI above
validates the exact committed PR #44 inputs. No new local full/browser/image rerun is claimed
for this documentary preparation, and no 7C implementation acceptance is inferred from it.

## 7C implementation start — 2026-10-04

The user's "Complete 7c" requests completion of the approved 7C slice through its validation,
single read-only independent reviewer, scoped publication and guarded merge/main-CI gates.
The parent reverified remote main and successful prerequisite CI at exact `f14d861`; the
prepared feature branch retains all three local documentary inputs. This request authorizes
task work despite the tracker still reporting BLOCKED; no goal reset or false completion occurs.
7C is IN PROGRESS, not accepted. 7D/7E remain PLANNED and unstarted in this slice.

Implementation starts with the optional scan_id history predicate and explicit typed dashboard
GET allowlist, preserving generic services, upstream bodies/statuses, real bearer/READ,
session/context/final-read guards and server-only credentials. Operational success responses
add X-Dashboard-Read-At in UTC; it never supplies authentication or scan-time exception history.
No migration, control, collector, default, live operation or later-sprint behavior is introduced.
New code invalidates earlier implementation acceptance; run all mandatory gates freshly.

## 7C implementation and browser validation checkpoint — 2026-10-04

Implemented additive optional exact-scan resource history, an explicit typed GET-only BFF
investigation allowlist and successful operational UTC response-time metadata. The React client
uses bounded 25-row pages and on-demand exact assessment/snapshot/profile/control-definition/
checksum/evidence/source/relationship bindings. Current findings and server-time exception
eligibility remain separately labeled; unknown proofs/unresolved endpoints have no inferred
navigation. Invalid filters and superseded selections clear prior data. Text disclosures have
explicit limits and never execute HTML or follow metadata URLs. API/schema/auth/default/catalog/
profile/control/migration compatibility and detail/pagination limitations are documented.

Fresh validation command:
`python scripts/validate.py --dashboard --focused tests/unit/services/test_investigation_history.py
tests/api/test_dashboard_investigation_api.py tests/integration/test_investigation_postgres.py
tests/api/test_dashboard_api.py tests/unit/security tests/unit/contracts tests/api/test_read_api.py`.
The harness generated its own disposable loopback PostgreSQL URL, never an operator database.
207 focused checks passed, no skips (39.18s), including real signed bearer/BFF reads and six new
PostgreSQL exact-history/READ/index-plan cases. The history read has three SELECTs (identity/count/
page), and both history count/page plans use existing indexes against representative 512-row data.
Frontend type/lint/build and 49 units passed; all 32 Chromium/Firefox journeys passed (42.9s),
with AWS forbidden and real controlled-issuer → BFF → bearer API → retained PostgreSQL reads.
Ruff passed; the run stopped at one formatting-only assertion wrap before full regression/image.
The formatter corrected that test; fresh regression/container validation remains pending.

Earlier diagnostics are not acceptance: a comparison initially omitted the BFF's default limit 25
on its direct-API test input; only the test input was corrected. A synthetic ACCEPTED_RISK fixture
initially retained resolved_at, correctly rejected by the established database CHECK; the fixture
now keeps status/time consistent. Browser tests initially failed to open the tags disclosure.
The shared Firefox cache failed Windows side-by-side activation for mozglue; locked browser
revisions were downloaded to a separate ignored workspace cache without replacing/deleting the
shared cache or upgrading dependencies. Firefox launch and every browser journey then passed.
Windows sandbox private pytest/runner-process restrictions required approved scoped unsandboxed
validation. No test deletion, skip, weaker assertion, authentication override or production fix.
Every harness run removed only its own created database; user databases and parent skills remain.

README/API/architecture/security/threat/operations/preflight owners describe local implementation
with acceptance pending. The React/PostgreSQL skill checks informed stable effect dependencies,
parallel on-demand reads and measured reuse of the existing index; the browser skills used the
repository's pinned Playwright fallback because agent-browser was absent. No new schema/index/
package or external Pages operation. Independent review, commit/publication, guarded merge and
merged-main CI are still pending. 7C IN PROGRESS; 7D/7E remain PLANNED and unstarted.

## 7C review repair and final local validation — 2026-10-04

The single approved read-only reviewer independently inspected all 31 scoped inputs, matched
initial manifest `308427D474C639061E2BFBF962BF0AD357AFEBDF16A3E25F0C73DFBEB3D56EA8` and
passed 201 SQLite/auth/security/documentation checks, no skips (40.07s). It found one MEDIUM
issue: coercive String(...) runtime guards admitted singleton arrays as enum/proof schema values,
including source_proof.schema_version ["1.0.0"], which incorrectly enabled typed citation links.
No other introduced finding was identified. REVIEW_PASS was correctly withheld.

The parent repaired every coercive enum/proof guard to require actual strings and added five
array/object/null/boolean/number adversarial cases across resource/endpoint/status/source/
relationship/proof fields. Fresh frontend type/lint/build and all 54 units passed (2.63s).
All 32 Chromium/Firefox journeys passed again (42.2s) on the rebuilt repaired client through
a separately owned disposable loopback PostgreSQL instance and the real controlled issuer/BFF/
bearer API. No test/auth/default/persistence weakening. That database was removed; operator
databases were untouched.

Fresh remaining acceptance:
`python scripts/validate.py --focused tests/unit/services/test_investigation_history.py
tests/api/test_dashboard_investigation_api.py tests/integration/test_investigation_postgres.py
tests/unit/contracts` passed 134 focused checks, no skips (26.43s), Ruff, 367-file formatting,
the full 2,728-test regression including 283 PostgreSQL cases, no skips, 19 existing SQLite
deprecation warnings (592.54s / 0:09:52), whitespace, Compose configuration and image build.
The backend stayed unchanged during the frontend-only review repair; the final image build
included that repair. Independent collection confirmed all 283 PostgreSQL cases.
Dependency consistency passed; locked frontend audit reported no known vulnerabilities;
migration head remains `20261001_0006`.

The final image runs as app, with manifest
`sha256:4b85fb07439256c9ca26ed4136333d383e6bbdf61e7cfbf17411485936a2026b`.
Offline disposable image smoke passed health and disabled-dashboard 404 behavior, then built
assets/no-store bootstrap and unauthorized 7C reads with explicit test OIDC configuration,
read-only filesystem, tmpfs and networking disabled. No mounts/ports/live provider or AWS.
An initial diagnostic assumed every FastAPI route entry exposed .path; actual HTTP probes
corrected that diagnostic without changing application behavior. Test fixtures/issuer are
absent from the runtime image; all owned smoke containers were automatically removed.

The same reviewer's repair/exact-input follow-up remains pending, as do scoped commit/publication,
green exact-head CI, guarded merge and merged-main CI. No acceptance is inferred from local green
checks alone. 7C remains IN PROGRESS; 7D/7E and later-sprint work were not started.

## 7C independent working-input review — 2026-10-04

The same single authorized read-only reviewer returned REVIEW_PASS for all 31 scoped files,
exact working manifest `5AC84BDC35CE8292133659BCFBCFFC0D8BDA57C1E5E8383749C02D834E51595C`.
The MEDIUM malformed-type guard issue is resolved; zero unresolved findings at any severity.
Independent follow-up passed 36 malformed-input assertions and four valid controls, frontend
type/lint and all 54 units, 83 documentation/status contracts, whitespace and unchanged migration
head. The manifest stayed unchanged after its diagnostics. No additional local validation gap.

This narrow documentary checkpoint records that observed review, not a future commit or
publication result. Under approval 9 and the current "Complete 7c" request, next freeze/commit
only the scoped files, obtain the same reviewer's exact-commit/doc-delta review, publish a scoped
PR and wait for green final-head CI before guarded ordinary merge and merged-main CI.
No auto-merge/force push/branch deletion, live operation or 7D/7E implementation is authorized.
7C remains IN PROGRESS until those gates pass; parent skills and original checkout are preserved.

## 7C publication CI expiry-test repair — 2026-10-04

The same reviewer passed exact commit `6e781acf20325b4a74ace4f5b593d0ad6a13f10e`, sole parent
`f14d861`, tree `59be59d7c9e184960106974010de8f093aff60cf`, all 31 committed/working blobs equal
and final manifest `B6A627AC3A5B73080B009CBCF3224D3C61D1E9BC5C574767536F3705C8BD3DA3`.
Zero unresolved findings; independent final 83 contracts and whitespace passed.
The parent published [PR #45](https://github.com/jnc247s/cloud-security-automation/pull/45)
under approval 9. Main remained unchanged at `f14d861`; no merge occurred.

[First PR CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/37232207705)
passed on exact `6e781`: 2,728 backend tests, no skips, 19 existing warnings (502.21s / 0:08:22),
54 frontend units, 32 Chromium/Firefox journeys (37.6s), Ruff, 367-file formatting, type/lint/build
and image build. [First push CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/37232199982)
passed backend/client gates but failed one Chromium expiry journey, with 31 browser cases passing;
image build was not run. It is a failed gate, not acceptance, and was not simply retried.

The old shell expiry test forced server expiry after AVAILABLE while the new assessment read
could still be in flight. That real read returned 401 and correctly unmounted the shell before
the subsequent Refresh click; Playwright reported a detached button and timed out. Independent
review confirmed the ordering race and the analogous pending-read risk in investigation expiry.
Both journeys now settle their initial reads, click while authenticated, expire the real server
store inside a one-shot refreshed-list interception (asserting 200), then continue the untouched
browser request. They assert actual browser BFF 401, Sign in, prior sensitive-data removal,
old-context BFF 401 and cookie-only API 401. No mocked authorization, swallowed click failure,
retry, sleep, timeout increase, skip or application/session behavior change.

Finalized repair validation passed type/lint, the unchanged 54 frontend units, 83 contracts,
Ruff/367-file format/whitespace, 20 repeated expiry journeys (five per test per browser, 37.7s)
and all 32 Chromium/Firefox journeys (42.2s). The real controlled issuer/BFF/bearer API/PostgreSQL
path remained intact, AWS forbidden, traces/videos/screenshots disabled. Repeated and full runs
used separate freshly created, owned loopback/tmpfs databases, removed after each run; no user DB.
An earlier attempt to launch the fixture twice on one already-seeded disposable database failed
setup with NoResultFound before executing tests. Fresh isolation corrected that diagnostic,
without altering the non-idempotent test fixture or application. A final readiness assertion
invalidated an intermediate browser run; the finalized 20/32 runs above were fresh afterward.

Only two browser tests and documentary records changed after `6e781`. The reviewed runtime,
backend tests, dependencies, migrations and final image are unchanged; their recorded local full
2,728/283-PostgreSQL/no-skip and image validation remain applicable, not newly repeated claims.
Fresh exact-head CI must validate every gate again. The same single reviewer must approve the
new committed test/documentary delta before publication. Guarded merge and successful main CI
remain required. 7C IN PROGRESS; 7D/7E and later-sprint/live operations remain unstarted.

## 7C main CI expiry-completion repair — 2026-10-04

The same single reviewer returned exact-head REVIEW_PASS for `644432736ef84b0f88f12aaf7ff3f14eb293d446`,
zero unresolved findings, final 32-file manifest
`3628AA67FC75FC01414D782F815D30F8804CA297E0837EE7E5E4D3836CD0FADA`. Independent type/lint,
83 contracts and whitespace passed; all committed blobs equaled LF-only reviewed inputs.
Both final-head runs passed: [push CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/37234043239)
and [PR CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/37234046136).
Fresh PR results: 2,728 backend tests, no skips, 19 existing warnings (612.24s / 0:10:12),
54 frontend units, 32 Chromium/Firefox journeys (45.0s), Ruff/367-file format/type/lint/build/image.
The parent checked OPEN/not draft/MERGEABLE/CLEAN/no auto-merge, both successful exact-head runs,
unchanged main `f14d861` and clean reviewed local inputs before the approved ordinary exact-head
guarded merge. No admin/force/auto/branch deletion. PR #45 merged at 2026-10-04 21:12:40 UTC,
commit `39af583186fb2857c9eba9e6d75fe7da0e897cd8`, parents `f14d861` and reviewed `6444327`,
tree `6eb34acbf6cef4f3ae0336c41218db7c9cf4976c` equal to the reviewed tree.

[Main CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/37235162974) failed
at that exact merge after passing backend/quality/frontend gates. It passed 31 browser cases
but failed the Firefox shell expiry assertion expired == true (40.0s); image was not built.
This failed acceptance gate was not rerun away, and no 7C COMPLETE/accepted documentary update
was applied. The prepared acceptance patch remained in memory only. No merge history was rewritten.

Independent source inspection and an async-order diagnostic confirmed the new test race:
the fixture clears its real store synchronously before its HTTP200 reaches Playwright. A parallel
refreshed BFF read can therefore return 401 before the route handler sets its completion boolean.
Runtime correctly unmounts sensitive data. Both test journeys now await a completion promise
resolved only after the real expiry POST200 assertion; control-call failures reject that promise
and rethrow. The already-armed actual browser401 and all Sign in/data removal/old-context BFF401/
cookie-only API401 assertions remain intact. No runtime, fixture, auth-policy, sleep, timeout,
retry, skip, dependency or migration change. This is synchronization, not relaxed assertions.

The parent created `codex/sprint-7c-expiry-ci-repair` from verified clean current main `39af583`,
preserving both earlier scoped branches and all unrelated user work. Final local type/lint and
54 units passed (2.61s); 83 contracts/Ruff/367-file format/whitespace passed. Fresh 20 repeated
expiry journeys (five per test per engine, 37.5s) and all 32 browser journeys (42.2s) passed on
separate fresh owned loopback/tmpfs PostgreSQL databases through real controlled OIDC/BFF/bearer
API; AWS forbidden, no traces/videos/screenshots, only those created databases removed.
The unchanged backend/full/PostgreSQL/image validation remains applicable; no new local full
regression or image run is claimed for test-only changes. New exact-head CI must rerun all gates.

The same reviewer's final committed test/documentary review is pending, followed by scoped
publication, both green final-head CI runs, ordinary exact-head guarded merge and successful main
CI before acceptance. 7C remains IN PROGRESS; 7D/7E and later-sprint/live operations are unstarted.
