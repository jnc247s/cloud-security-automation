# Sprint 6H — whole-sprint acceptance and closeout

State: COMPLETE. Whole-sprint 6H acceptance merged in
[PR #40](https://github.com/jnc247s/cloud-security-automation/pull/40) at
`19c4cd10d0e22ca526fb9a6e94af967cc8ff0a97`; exact-head review, both final-head CI runs and
[merged-main CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/36954205010)
passed. Its accepted base was `5043f61b384c8c4499710d2033f7636676705deb` (6G / PR #39).
This test/documentation-only slice adds no application behavior, controls, migrations, deployed
policy or permissions. Sprint status belongs to [ROADMAP.md](../../ROADMAP.md); authorization,
original predictions, implemented differences and historical checkpoints remain in the completed
execution plan. Subsequent documentary closure archives that plan and promotes Sprint 7 NEXT
without implementation. Its own exact-head review/CI/merge gates remain mandatory before the
unattended Goal is complete; no documentary publication result is claimed in advance.

Implementation/tests and the 16-document owner reconciliation are committed as
`bf4a6cc54d34b543db56791952166e9a145de8ec`, parent that accepted base, on
`codex/sprint-6h-acceptance-closeout`. The
[commit checkpoint](../exec-plans/completed/sprint-6.md#6h-commit-checkpoint--2026-10-01) records scope
and the historical pre-publication gates. Final reviewed head was
`7d80c57b21a62672a4404bd2af4d077d3990ec52`; verified merge parents are that head and the accepted
6G base. Earlier no-publication/no-merge checkpoints are historical.

## Acceptance scope

All 25 core IDs (`IAM-001`–`006`, `EC2-001`–`004`, `NET-001`–`006`, `S3-001`–`004`,
`LOG-001`–`004`, `GOV-001`) plus supported legacy `S3-900` run through unchanged real collectors,
rules, persistence, executor and generic APIs. Only AWS responses are offline. The default
catalog remains `0.2.1`, and default profile identity/version remains `default/1.0.0`;
latest catalog `0.13.0` remains explicitly opt-in. Test-only policy enables
all supported controls with the previously approved inputs, without replacing operator files or
immutable exposure/classifier artifacts. Accepted migration head remains `20261001_0006`.

| Acceptance concern | New executable coverage |
| --- | --- |
| Immutable catalog releases and canonical IDs | Golden checksums for all 12 supported versions `0.2.1` through `0.13.0`; exact registry/catalog membership and unchanged five-control default |
| Combined deterministic assessment | 26 controls / 39 target assessments, exact PASS/FAIL/N/A distribution, same scan/profile, reversed rule/resource order, no AWS rule calls, unchanged non-GOV results when GOV is disabled |
| Historical rollforward | Persist every supported release, then replay retained exact policies and verify historical results, evidence IDs/payloads/digests, source artifacts, mappings and FAIL occurrences after latest registration |
| Pending recovery | Public executor restart for each actual supported catalog using retained profile/catalog, with original policy file absent and deployment defaults changed; completed work is not recollected |
| Authenticated API workflow | ANALYST read allowed / scan execution denied; unauthenticated reads denied; ADMIN HTTP 202 returns while AWS is gated; terminal scan and all 39 assessments read through public endpoints |
| Evidence/dependency readback | Public resources/history, controls, source outcomes/artifacts, relationships, framework references, evidence digests and exact LOG-004→S3-002 dependency IDs |
| Finding/exception separation | Public FAIL occurrences and OPEN findings; accepted governance service creates a bounded exception without changing assessment or evidence, with public exception readback and scan audit identity |

The persistence, restart and HTTP cases run identically on foreign-key-enabled SQLite and
explicitly disposable PostgreSQL. SQLite worker tests use file-backed independent connections,
not concurrent access to an in-memory StaticPool. Integration fixtures require an explicit
`TEST_DATABASE_URL`; the full validation runner supplies a unique loopback-only PostgreSQL
container, then removes only that container. It never uses an operator database.

Sources:

- [combined fixtures and accepted golden catalog digests](../../tests/sprint6_fixtures.py)
- [determinism and immutable-release checks](../../tests/unit/rules/test_sprint6_acceptance.py)
- [retained history and public restart](../../tests/unit/database/test_sprint6_acceptance.py)
- [whole-sprint real HTTP exercise](../../tests/sprint6_http.py)
- [identical PostgreSQL acceptance](../../tests/integration/test_sprint6_acceptance_postgres.py)

## Reused accepted gates and boundaries

Unchanged per-control truth tables, four-state evidence handling, strict source/edge/proof
forgery rejection, finding lifecycle, immutable history, rollback/migration safety, production
authentication safeguards, and deterministic operation-count gates remain in the complete
regression suite. The accepted 6G gate passed 2,491 tests including 238 PostgreSQL cases with no
skips. New 6H coverage complements those tests; it does not substitute for fresh full regression.

Real HTTP uses the supported explicit test-only development bearer backend. There are no
FastAPI dependency overrides or authorization bypasses. Production OIDC behavior and capability
separation are unchanged. No live AWS call, remediation, production mutation/deployment, secret
change, operator-policy installation, new framework-compliance claim or later-sprint code.
See [accepted limitations](../operations/known-limitations.md) and
[security policy](../../SECURITY.md).

## Validation and remaining gates

Initial new golden/combined checks passed 13 tests. The first expanded local run also exposed a
new test's tuple-versus-JSON-list comparison error, corrected by comparing the source model's
canonical JSON projection without changing application behavior. Its temporary-folder errors
were sandbox access failures, not application failures; rerun with ordinary temporary-directory
access passed history and all 12 restart cases. The expanded HTTP test also initially assumed
every historical proof schema had a profile-checksum field. The corrected check explicitly
preserves the older field shapes and verifies the checksum only where that accepted schema owns
it, including the LOG-004 dependency. No failing accepted assertion was removed or weakened.

Fresh validation completed with exit 0: **138 focused checks** in 85.22 seconds, **2,533 full
tests** in 524.79 seconds including **252 disposable PostgreSQL cases**, no skips and 20 existing
warnings. Ruff, 341-file formatting, contracts/links, whitespace, Compose and image build passed.
Both database backends passed the real bearer-authenticated HTTP cases. The disposable container
was removed; operator databases were untouched. Exact command paths and five-test-file fingerprint
are recorded in the [validation checkpoint](../exec-plans/completed/sprint-6.md#6h-validation-and-review-correction-checkpoint--2026-10-01).

The one authorized read-only reviewer independently passed 105 rule/SQLite/contract checks and
14 PostgreSQL cases on a separate owned disposable container, subsequently removed. Both LOW
documentary findings (stale owner state and conflated default catalog/profile version) were
corrected and independently verified. Exact final head `7d80c57` received REVIEW_PASS, zero
unresolved/new findings at every severity; final 78 contracts/links and whitespace passed.
All independent runs had no skips and one existing warning. The historical review/correction
checkpoints retain exact diagnostics.

Final-head push CI [36953191107](https://github.com/jnc247s/cloud-security-automation/actions/runs/36953191107)
and PR CI [36953194830](https://github.com/jnc247s/cloud-security-automation/actions/runs/36953194830)
passed all 2,533 tests (20 existing warnings, no skips), Ruff, 341-file formatting and image build.
Conditional merge rechecked exact head/base, both current CI results, zero human-review requests /
comments and clean mergeability, with no bypass/force push. Merge occurred 2026-10-02T02:08:02Z
(2026-10-01 America/Chicago). Merged-main CI passed all 2,533 tests in 522.00 seconds, no skips,
20 existing warnings and every quality/image step before documentary closure began.

The post-merge documentary closeout marks Sprint 6 COMPLETE, archives the plan while retaining
original predictions and implemented differences, and promotes Sprint 7 NEXT without starting
implementation. Unrelated parent skill files and original clean 6E.3 checkout remain preserved.
The completed plan records the separate documentary review/publication gates. Only the existing
documentary status guard evolves to COMPLETE/NEXT and verifies plan archival; accepted control /
workflow tests and application behavior remain unchanged. Fresh full validation covers this guard
change. Known limitations remain explicit.

Fresh closeout validation passed 78 targeted contracts and all 2,533 regression tests in
478.49 seconds, including 252 disposable PostgreSQL cases, no skips and 20 existing warnings.
Ruff, 341-file formatting, links, whitespace, Compose and image build passed; its owned database
was removed. The same reviewer passed 91 independent contracts/catalog-golden checks and 78
post-correction contracts, no skips and one existing warning per run. One LOW stale owner-state /
archived-plan-label finding was corrected and verified; stable-tree REVIEW_PASS has zero unresolved
introduced findings at every severity. Exact committed-head recheck and the documentary
publication/CI/conditional-merge/merged-main gates are still required at this recorded checkpoint.
