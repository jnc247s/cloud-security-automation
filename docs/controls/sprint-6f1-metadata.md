# Sprint 6F.1 — approved CloudTrail coverage and integrity metadata

Approved by the user's `implement 6f1` request on 2026-10-01 following the
[6F preflight](sprint-6f-preflight.md). [ROADMAP.md](../../ROADMAP.md) owns progress;
the [active plan](../exec-plans/active/sprint-6.md) records authorization and validation.
Local implementation acceptance checks and independent review pass with zero unresolved findings.
The reviewed slice merged in [PR #37](https://github.com/jnc247s/cloud-security-automation/pull/37)
at `3a053ff396a2c112aa254842cb25730fe3879ecc` under the user's conditional merge approval.
[Merged-main CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/36930583998)
passed all 2,125 tests (20 existing warnings, no skips), lint/format and image build.
6F.1 is accepted; the active plan retains the superseded historical pending checkpoints.
No deployment policy was enabled.

## Approved immutable bundle

| Field | LOG-002 | LOG-003 |
| --- | --- | --- |
| Target | Collection account, global `cloudtrail/aws_account` | Each admitted `cloudtrail/cloudtrail_trail` in its home Region |
| Severity | HIGH | MEDIUM |
| Profile inputs | `enabled_controls` only | `enabled_controls` only |
| Catalog | Opt-in `aws-cloud-security-controls/0.11.0` | Same |
| Evaluator | `1.0.0` | Same |
| Closed proof/execution schema | `1.8.0`, `cloudtrail_management_coverage_v1` | `1.8.0`, `cloudtrail_integrity_v1` |
| Reporting mapping | NIST local `2.0+subset.10`, PR.PS-04 | Same subset, PR.DS-01 |

Default `0.2.1`, catalogs through `0.10.0`, LOG-001, earlier framework artifact bytes,
collector behavior, scanner permissions, generic API and authentication remain unchanged.
LOG-004 and GOV-001 are not registered. No dependency scheduler or remediation was added.

## Required proofs and decisions

The unchanged accepted 5F source bundle supplies retained discovery, identity, configuration,
status and event selectors. Shared engine/persistence validation checks exact source
contracts/versions, same-scan artifact IDs/digests, collection account and admitted population,
trail ARN/partition/owner/home Region and normalized snapshot projection. No rule calls AWS.
The account target is assessment-only, never a collected resource or relationship endpoint.

LOG-002 first requires complete discovery/admission and every required identity/configuration/
status/selector lookup for every relevant trail. A required-source failure or malformed fact
is insufficient even with a qualifying sibling. Otherwise an active multi-Region trail must
independently prove both management read and write coverage under the
[canonical bounded selector table](catalog.md#log-002--required-multi-region-cloudtrail-management-event-coverage-is-missing).
No qualifying trail plus unknown selector coverage is insufficient; complete deterministic
noncoverage, including empty enumeration, fails. Normal account applicability is never N/A.
Union selectors within one trail, never across trails. Preserve basic optional defaults and
raw-presence markers; advanced evaluation does not solve general restrictive expressions.

LOG-003 requires complete discovery/admission, exact identity/configuration and an explicit
integrity boolean. True passes, false fails, unavailable or malformed evidence is insufficient.
Complete empty discovery emits the established account N/A fallback; failed discovery does not.
Emit one assessment per observed trail. Tags, status, selectors, destination and KMS facts do
not decide the integrity setting. A partial scan still cannot resolve an existing finding.
PASS/FAIL artifacts retain source proofs and evaluator version; N/A/insufficient follow the
existing artifact convention and retain profile/scan history.

Operators may review active multi-Region management coverage or enabling integrity validation
with appropriate costs, delivery dependencies and a separate digest-verification process.
These controls never change AWS configuration, prove log delivery/retention/alerting/data-event
or organization-wide coverage, or establish that digests were verified.

## Sourced reporting metadata

Source: [official NIST CSWP 29](https://doi.org/10.6028/NIST.CSWP.29), version 2.0,
Appendix A, Protect / Platform Security and Data Security, verified 2026-10-01.
Local files: `app/assessment/data/nist_csf_2_0_subset_10.json` and its `_manifest.json` companion.
Exact subset SHA-256: `21a393bdce87a3417134a1c4b9cd9c0c2cc1d49ef2a41e0259d4ec39342e3282`.
Mappings are project inferences: management logging contributes monitoring context, and the
integrity setting contributes data-at-rest context. Neither proves the complete NIST outcome
or determines technical results or severity. Earlier mapping artifacts are immutable.

## Acceptance blocker — 2026-10-01

This records the original stopped checkpoint; the subsequently approved repair below supersedes
its current blocker/no-migration status without changing the historical failure record.

The new real persistence/HTTP tests expose a pre-existing accepted-baseline inconsistency.
`CloudTrailEvidenceCollector` emits `DELIVERS_TO_BUCKET` with an unresolved regional bucket
reference whose owner and Region are unknown. The domain explicitly permits this partial
identity, but ORM and migration `20260915_0003` constraint
`ck_resource_relationship_observations_target_scope_region_consistent` reject regional
targets with a null Region, including unresolved references. An ordinary scan with an
unobserved destination therefore rolls back; HTTP reports sanitized `SCAN_EXECUTION_FAILED`.
Neither the collector, mapper, constraint nor established migration was changed by 6F.1.

The [repaired limitation](../operations/known-limitations.md#unresolved-regional-relationship-persistence--repaired)
records the discrepancy. Per repository/preflight instructions, stop for a separately scoped
shared persistence fix, potentially an additive migration, rather than inventing a Region,
dropping relationships or changing fixtures to hide the failure. Migration head remains
`20260924_0004`. Full regression/PostgreSQL/container acceptance and independent review are
not complete. No acceptance, commit, push, PR or merge is claimed.

## Approved persistence repair — 2026-10-01

The user approved the narrowly scoped fix, including an additive migration, and continuation
of 6F.1 validation. Revision `20261001_0005` follows `20260924_0004`; original migration bytes
are unchanged. It allows a null Region only for an explicitly unresolved regional target.
Stable regional targets still require a Region, global targets forbid a Region, and the
existing identity union/provenance/FK/append-only constraints remain intact. No owner, Region,
stable ID, snapshot or relationship is fabricated or dropped. Collectors and mapper are unchanged.

PostgreSQL replaces the single CHECK transactionally. SQLite recreates the unreferenced child
table inside the caller's transaction with FK enforcement enabled and exact trigger definitions
restored. Failed upgrade/downgrade attempts roll back and are retryable. The online downgrade
preflight excludes writers in fixed parent-to-child order and rejects retained regional targets
whose Region is unknown before any DDL. Errors reveal no identities or connection values.
Offline downgrades are blocked; the SQLite constraint transition requires online execution.
See [recovery guidance](../operations/known-limitations.md#unresolved-regional-relationship-persistence--repaired).

Targeted control/history/HTTP and migration compatibility checks passed **114 tests** after the
repair. The initial new HTTP test used a resource-type attribute on the snapshot instead of
its stable resource; correcting that test lookup preserved the full assertion. Fresh full
regression, disposable PostgreSQL, container and independent review gates remain required.
No production migration, reviewer agent, publishing or later-slice work is authorized.

## Validation checkpoint after repair

The complete collected regression suite passed **1,918 tests**, with **155 existing
PostgreSQL-availability skips** and 20 existing dependency warnings. No test assertion failed.
This is not a no-skip PostgreSQL acceptance result: Docker Desktop crashed while starting its
local inference manager (`dockerInference` socket inaccessible), and no native PostgreSQL
installation was available. No reset, Docker-data deletion or settings change was performed.
The project acceptance runner could not obtain its disposable database/image runtime.

Ruff lint, formatting (312 Python files), 75 documentation/contract tests, tracked whitespace
and exact framework hash passed. Compose configuration passed without a running daemon;
the API image build remains unverified. Whitespace checks covered all 35 changed tracked/untracked
files; private-key/AWS-key marker inspection found no matches. New PostgreSQL tests cover 26 control/persistence/HTTP cases
and seven migration/constraint/concurrent-writer cases; all still require the disposable runtime.
Independent review is separately unauthorized and pending. The slice remains IN PROGRESS,
uncommitted and unpublished; no later slice was started.

## PostgreSQL and container validation checkpoint — 2026-10-01

After the user restored Docker, the unchanged acceptance runner passed **222 focused checks**
and **2,073 full regression tests**, including all **155 PostgreSQL integration cases**,
with **no skips**. The focused run includes 26 PostgreSQL control/persistence/real authenticated
HTTP cases and seven PostgreSQL migration/constraint/concurrent-writer cases. Both runs reported
20 existing dependency warnings. Ruff lint, formatting (312 Python files), documentation
contracts, tracked whitespace, Compose configuration and the API image build passed.
The runner removed its uniquely named disposable PostgreSQL database; no operator database,
live AWS account or production migration was used. No runtime/test change was required.

This supersedes the environment blocker in the preceding checkpoint without rewriting its
historical results. The default/historical catalogs and shared security boundaries are unchanged;
local migration head remains `20261001_0005`, accepted baseline head `20260924_0004`.
Independent review remains separately unauthorized and pending. All changes are local,
uncommitted and unpublished; 6F.1 remains IN PROGRESS and later slices remain unstarted.

## Independent review authorization — 2026-10-01

The user subsequently authorized one read-only independent reviewer for the complete local
6F.1 slice and approved persistence repair. Review is pending; the preceding authorization
blocker is historical. No publishing, merging, production operation or later-slice work is authorized.

## Independent review and final local checkpoint — 2026-10-01

The single reviewer found one MEDIUM exact-type binding defect: Python equality treated
numeric `1`/`0` as equal to boolean facts in projections and rehashed proofs. The correction
requires exact boolean projections and recursive JSON scalar types, restricted to new schema
`1.8.0`; historical schemas remain unchanged. It adds 20 engine, 16 SQLite and 16 PostgreSQL
regression cases. All 36 new engine/SQLite cases failed before the fix and passed afterward.
The same reviewer independently verified the correction and returned **REVIEW_PASS with zero
unresolved findings**. No other actionable finding was identified.

Fresh post-review acceptance passed **274 focused checks** and **2,125 regression tests**,
including all **171 PostgreSQL integration cases**, with **no skips** and 20 existing warnings.
Ruff lint, formatting (312 Python files), documentation contracts, whitespace, Compose and the
API image build passed. The disposable database was removed; no operator database, live AWS
or production migration was used. No runtime/test correction followed this successful run.
Final documentation closeout passed 75 contract/link checks and quality/whitespace gates;
the README-inclusive image rebuild passed. The same reviewer verified documentation consistency
and confirmed REVIEW_PASS remains applicable with zero unresolved findings.

The approved bundle, collectors, permissions, generic APIs/auth and historical releases remain
unchanged. Local migration head is `20261001_0005`, accepted baseline head `20260924_0004`.
This supersedes earlier pending-review checkpoints, not their historical validation records.
Changes remain uncommitted and unpublished. Publication, final-commit CI and human merge
acceptance remain pending; 6F.1 is IN PROGRESS and later slices remain unstarted.

## Publication authorization — 2026-10-01

The user subsequently approved committing, pushing and opening the reviewed 6F.1 pull request.
Only the existing 35-file slice may be published; unrelated skill files remain excluded.
No force-push, merge, production operation or later-slice work is authorized. Publication,
final-commit CI and human merge acceptance remain pending; recorded validation/review remains
applicable to unchanged runtime/tests. 6F.1 remains IN PROGRESS.

## Publication checkpoint — 2026-10-01

The authorized 35-file implementation is committed as `f299966f7166a202922341bc5c05f56f962a41ad`
and normally pushed on `codex/sprint-6f1-cloudtrail-coverage-integrity`.
[PR #37](https://github.com/jnc247s/cloud-security-automation/pull/37) is open against `main`,
with auto-merge disabled. Unrelated parent skill files are excluded and preserved; the accepted
6E.3 checkout is unchanged. No force-push, merge, live AWS or production operation occurred.
Publication metadata is a separate documentation-only commit; runtime/tests remain unchanged.

Local 274 focused / 2,125 full / 171 PostgreSQL no-skip validation and independent REVIEW_PASS
remain applicable. Final-head GitHub CI is tracked on the pull request and must succeed before
human merge acceptance. Earlier uncommitted/unpublished notes are historical checkpoints.
6F.1 remains IN PROGRESS; later slices remain unstarted. The accepted migration baseline stays
`20260924_0004` until acceptance/merge; the published slice adds `20261001_0005`.
