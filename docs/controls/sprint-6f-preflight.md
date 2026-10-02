# Sprint 6F — CloudTrail control implementation preparation

Current follow-up: 6F.1 is accepted through PR #37 with green merged-main CI. The user
subsequently approved the remaining Sprint 6 bundle, including 6F.2 metadata, the bounded
composition seam and complete-empty account N/A clarification. 6F.2 is COMPLETE through
PR #38 with green merged-main CI; 6G is IN PROGRESS. See
[6F.2 metadata](sprint-6f2-metadata.md).
The [active plan](../exec-plans/active/sprint-6.md) records authorization and the
[6F.1 metadata](sprint-6f1-metadata.md) records the accepted implementation and repaired blocker.
The original analysis and proposed decisions below are preserved as historical predictions.
The user separately approved the narrowly
scoped repair of the discovered persistence constraint mismatch and resumption of 6F.1 checks.
The additive `20261001_0005` repair is the recorded implemented difference from the original
no-migration prediction below; collectors, APIs and permission scope remain unchanged.

Prepared: 2026-10-01. Analysis only; no new control, policy, release or implementation is
authorized by this document. [ROADMAP.md](../../ROADMAP.md) owns progress and the
[active plan](../exec-plans/active/sprint-6.md) owns task scope. The canonical
[LOG-002/003/004 contracts](catalog.md#log-002--required-multi-region-cloudtrail-management-event-coverage-is-missing)
and [evidence matrix](sprint-5-evidence-readiness.md#logging-controls) remain authoritative.

## Verified starting gate

Slices 6A through 6E are accepted. PR #35 accepted S3-004 at runtime baseline
`c861713a665669da09d5bc7b5b282b04c16cac1d`; PR #36 subsequently merged the README and
documentation closeout into main at `49500c95c78870d72e6179882bae4e6379cdd6d0`.
Its [merged-main CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/36900929958)
passed. That accepted documentation-only successor is this preparation's base.

The reused clean worktree `.tmp/sprint-6e3-readme-closeout` is now on scoped branch
`codex/sprint-6f-logging-preflight`, based on that main SHA. The original checkout's unrelated
untracked `.agents/` skill and the existing `.tmp/sprint-6e3` implementation checkout are
preserved; neither belongs in a preparation commit. This preparation is local and uncommitted.
Do not publish or launch independent reviewers without authorization.

Default catalog `aws-cloud-security-controls/0.2.1`, cumulative opt-in releases through
`0.10.0`, execution schemas through `1.7.0`, local NIST subsets through `2.0+subset.9`, and
Alembic head `20260924_0004` are unchanged. Recheck remote main, CI and release availability
before implementation; use a clean accepted baseline rather than an unaccepted stack.

## Recommended bounded sequence

| Slice | Proposed implementation | Integration boundary |
| --- | --- | --- |
| 6F.1 | LOG-002 account management-event coverage and LOG-003 per-trail integrity setting | Shared retained CloudTrail proofs and deterministic evaluators; no cross-control scheduling |
| 6F.2 | LOG-004 per-trail destination exposure | Exact same-scan S3-002 result composition, after 6F.1 acceptance |

Each implementation slice requires its own targeted/full acceptance gates. A separately
authorized combined PR is possible, but must validate the entire combined diff and does not
remove dependency ordering or approval gates. Serial integration is recommended; parallel
agents are neither required nor authorized by this preparation.

No collector expansion, AWS permission, API/authentication redesign, remediation, infrastructure,
deployment, dependency package or migration is currently needed. Do not start 6G, 6H or Sprint 7.
If implementation discovers that an established schema/interface cannot represent the approved
contract, stop and scope that change explicitly rather than weakening validation.

## Evidence availability and exact binding

The accepted 5F shared `CloudTrailCollectionBundle` already supplies facts to the legacy
`cloudtrail_trails` projection and the `cloudtrail_evidence` graph without duplicate AWS calls.
The persisted `cloudtrail-evidence` execution marker selects this behavior. Preserve pre-5F
pending-scan service tuples: recovering an older scan must not add selector calls.

| Retained source | Required consumer | Binding requirement |
| --- | --- | --- |
| `cloudtrail.trails.discovery` / `cloudtrail:ListTrails` | All three controls | Exact collection account, complete/admitted enumeration, zero discarded identities and exact ARN/resource membership |
| `cloudtrail.trail.identity` / `cloudtrail:ListTrails` | All three controls | Authoritative trail ARN, real owner, partition, name and home Region; exact admitted snapshot |
| `cloudtrail.trail.configuration` / `cloudtrail:GetTrail` | All three controls | LOG-002 multi-Region/organization flags; LOG-003 explicit integrity boolean; LOG-004 destination name |
| `cloudtrail.trail.status` / `cloudtrail:GetTrailStatus` | LOG-002 | Exact trail/home Region and explicit active-logging boolean |
| `cloudtrail.trail.event-selectors` / `cloudtrail:GetEventSelectors` | LOG-002 | Complete single selector form, raw-presence/default facts, all retained fields/operators |
| Resolved `DELIVERS_TO_BUCKET` from GetTrail, plus canonical S3-002 assessment | LOG-004 | Exact same-scan destination snapshot, stable bucket identity and provenance; bucket Region may differ from trail Region |

Bind declared source contract/version, source outcome ID, artifact ID/digest, scan, observation
time, normalized payload and snapshot projection consistently. `PRESENT` alone is insufficient.
Do not trust copied `configuration.source_states`, caller-supplied coverage booleans or free-form
evidence references. Account coverage is an assessment-only target, not a collector resource or
graph endpoint. Trail owner is not collection account; organization visibility is not proof of
organization-wide coverage. Unadmitted external-owner trails make discovery incomplete, never
an empty population. Do not relax accepted exceptional-owner admission.

LOG-002/003 require their named sources, not an unrelated tags failure. A required-source
failure must still remain insufficient. LOG-004 has the additional canonical complete-collector
gate: for an observed trail, require `SUCCEEDED` for `cloudtrail_trails`, `cloudtrail_evidence`,
`s3_buckets` and `s3_evidence`, plus exact required source proofs. An unrelated EC2/IAM/Analyzer
failure does not automatically invalidate a technical result, but a partial scan still cannot
resolve an existing finding. In particular, a decisive S3-002 result from partial S3 collection
does not remove LOG-004's stricter completeness requirement.

## Required truth tables

### LOG-002: account-level management-event coverage

Use the canonical table unchanged. First prove complete enumeration and every required lookup
for every relevant trail; a stopped or single-Region trail cannot excuse a missing required
lookup. Then evaluate each trail's selector coverage and aggregate:

| Condition | Result |
| --- | --- |
| Missing graph, incomplete discovery/admission, failed/partial required lookup, malformed required fact | INSUFFICIENT_EVIDENCE, even with a qualifying sibling |
| Complete population with at least one actively logging multi-Region trail proving both management read and write coverage | PASS |
| No qualifying trail and a relevant trail has unknown selector semantics | INSUFFICIENT_EVIDENCE |
| Complete population and every trail deterministically non-qualifying, including complete empty discovery | FAIL |
| Normal AWS account | NOT_APPLICABLE is unreachable |

Basic selectors contribute separately to read/write dimensions. For each dimension, there must
be at least one management-enabled contributor and the intersection of its contributors'
exclusion sets must be empty. ReadOnly plus WriteOnly can qualify one trail; disjoint exclusions
can also restore full source coverage. Never combine different trails' partial read/write
coverage into a qualifying trail. Allowed exclusions are exactly `kms.amazonaws.com` and
`rdsdata.amazonaws.com`; malformed/duplicate/unknown values are insufficient. Keep accepted AWS
optional defaults and raw-presence markers, rather than treating omitted defaults as failure.
These defaults and selector-union semantics were checked against the
[AWS EventSelector reference](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_EventSelector.html).

Advanced v1 proves only exact `eventCategory Equals ["Management"]` with no other restricting
field, optionally exact `readOnly Equals ["true"]`, `["false"]` or both. Union supported
selectors within one trail. Structurally valid extra restrictions are unknown unless another
independently sufficient unrestricted selector proves coverage. Preserve operators outside this
subset, but do not solve their combined coverage. Malformed/mixed forms or unsupported
category/readOnly expressions remain insufficient under the canonical contract. The
[AWS AdvancedFieldSelector reference](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_AdvancedFieldSelector.html)
supports the exact category/readOnly distinction; the narrower proof subset is project policy,
not a claim that AWS cannot express other selectors.

### LOG-003: per-trail integrity setting

| Condition | Result |
| --- | --- |
| Complete exact identity/discovery/configuration, `log_file_validation_enabled=true` | PASS |
| Same proof, explicit `false` | FAIL |
| Complete empty admitted trail discovery | Account fallback NOT_APPLICABLE |
| Incomplete discovery/identity/configuration or absent/null/wrong-type boolean | INSUFFICIENT_EVIDENCE |

Emit one result for every observed trail even when required evidence is unavailable. Selector,
logging-status, tag, S3 relationship and KMS evidence do not decide this setting. An unavailable
unrelated source is not a required-source failure; a failed GetTrail source cannot be replaced
by an unproven configuration copy. Preserve LOG-001's accepted behavior unchanged.
This flag does not establish that digest files were checked or delivery succeeded; see
[AWS integrity-validation guidance](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html).

### LOG-004: exact destination result composition

For each observed trail, first prove complete collector/source coverage, exact configuration,
one coherent resolved destination relationship and the matching bucket snapshot. Only then
consume the validated canonical S3-002 result from the same assessment invocation:

| Destination/dependency condition | Result |
| --- | --- |
| Complete exact relationship and matching canonical S3-002 PASS | PASS |
| Same complete relationship and matching canonical S3-002 FAIL | FAIL |
| Missing/unresolved/ambiguous destination, incomplete required collectors/sources, absent/disabled S3-002, or matching S3-002 insufficient/N/A | INSUFFICIENT_EVIDENCE |
| An observed trail without a provable destination | Never NOT_APPLICABLE |
| Complete empty admitted trail discovery | Proposed account fallback NOT_APPLICABLE; approve the clarification below before implementation |

The last row is a proposed clarification, not an already executable canonical result: the
catalog forbids N/A **for a trail**, while existing `validate_execution_targets` requires one
explicit N/A or insufficient account fallback for an empty resource population. Recommend N/A
only for proven empty trail coverage, with no invented destination/dependency; failed or
unadmitted enumeration remains insufficient. After approval, record this distinction in the
catalog owner before enabling LOG-004. Empty-population applicability does not require a
fictitious S3 target; the complete-collector gate above governs observed-trail composition.

Never rerun S3 exposure independently inside LOG-004, read an earlier scan's result, infer PASS
from a destination name, use an account aggregate instead of the destination result, or silently
enable S3-002. Multiple trails may cite the same exact destination assessment. Preserve the
[S3-002 limitations and approval semantics](s3-002-exposure-aggregation.md), including no
access-point/object-ACL/full effective-IAM proof. Log delivery, retention, digest verification,
KMS protection and operational exceptions remain outside this composed result.

## Inspected integration and proposed implementation

| Existing seam | Proposed bounded extension |
| --- | --- |
| `app/assessment/execution.py`, `evidence_reader.py` | Closed CloudTrail strategies and shared result/proof validation for 6F.1; a separate closed composition strategy for 6F.2. Earlier schemas remain unchanged. |
| `app/rules/base.py`, `engine.py`, `registry.py` | Retain `assess(snapshot, profile)` and legacy `evaluate` callers. Add an internal context-aware extension only for composed assessment; default behavior delegates to the old method. Preserve legacy lexical order where no dependency exists and final stable output ordering. |
| `app/database/validation.py`, `persistence.py` | Reuse exact target matrices and preflight all candidates before SQL. For composition, construct context only from identity/profile/catalog/inventory/proof-validated prerequisites; never trust input tuple order or a caller-supplied context. |
| `controls.py`, matching new control/evidence modules, `frameworks.py` and `data/` | New opt-in releases and separately checksummed reporting artifacts; preserve every earlier serialized definition and default helper. |
| `extended_profiles.py`, `deployment_policy.py`, `app/database/catalogs.py` | LOG-004 already requires explicit `s3_exposure_approvals`. Reuse schema-2 serialization, immutable policy/profile history and startup validation; no new policy schema is planned. |
| Scan service/executor, generic API projections | Keep exact persisted catalog/profile/service intent and real capability checks. No per-control route/service or new public request field. |

LOG-002 needs a specialized bounded account proof: the current generic account reader does not
traverse and validate all child trails. Declare complete account discovery and bind the exact
per-trail identity/configuration/status/selector declarations through the closed strategy; do not
interpret an account target as a resource-subject source or fabricate account-to-trail edges.
LOG-003 uses the existing resource/empty-population target convention with a narrowly scoped
shared boolean evaluator. Both engine and persistence recompute result, applicability and proof.
Decisive artifacts retain evaluator version and exact source proof; nondecisive artifacts follow
the established no-decisive-artifact convention while graph/profile history retains replay inputs.

LOG-004 is the first cross-control result consumer. Today the registry sorts IDs lexically,
so LOG-004 would run before S3-002, and `validate_candidate` receives only one candidate/profile.
The required extension is a closed dependency declaration for LOG-004 -> S3-002 and a read-only,
invocation-local index of validated assessment candidates, keyed by control and exact snapshot.
Only enabled prerequisites run; missing/disabled prerequisites produce insufficient evidence.
Reject unsupported dependency declarations and inconsistent registry/catalog bindings. Additive
metadata must be omitted from historical serialization, not inserted as empty/null fields that
change old checksums. No general workflow engine, asynchronous rule workers or database lookup.

Publish a prerequisite into context only after existing source/result, target, owner, scan,
inventory, catalog and profile checks pass and engine digests are bound. Persistence must validate
the same prerequisites before composed candidates, regardless of caller order, before any write.
Bind the LOG-004 proof to the destination key, source/edge IDs, exact S3-002 result/evidence
IDs/digests, evaluator and historical approval/profile identity. Reject rehashed forgeries and
substituted scan, bucket, owner/Region, catalog, profile or policy. Reuse S3-002's existing shared
validator; a second exposure evaluator is not acceptable. A direct composed-rule call without
validated context must fail closed as insufficient, never silently assess the dependency.

## Proposed bundle requiring approval

These are proposed project metadata, not runtime defaults or NIST requirements:

| Field | 6F.1 proposal | 6F.2 proposal |
| --- | --- | --- |
| Controls / severity | LOG-002 HIGH; LOG-003 MEDIUM | LOG-004 HIGH |
| Category / evaluator | LOGGING / `1.0.0` | LOGGING / `1.0.0` |
| Cumulative opt-in catalog | `0.11.0`, extending `0.10.0` | `0.12.0`, extending accepted `0.11.0` |
| Closed execution schema | `1.8.0`: management-coverage/integrity only | `1.9.0`: destination-exposure composition only |
| Strategy names | `cloudtrail_management_coverage_v1`, `cloudtrail_integrity_v1` | `cloudtrail_destination_exposure_v1` |
| Separate local NIST subset | `2.0+subset.10` | `2.0+subset.11` |
| Proposed mappings | LOG-002 -> PR.PS-04; LOG-003 -> PR.DS-01 | LOG-004 -> PR.AA-05 |

All proposed release slots are absent at the verified base; recheck before registration. Generate
and verify exact new artifact hashes during implementation rather than inventing them now.
Mapping source is [NIST CSWP 29, version 2.0](https://doi.org/10.6028/NIST.CSWP.29), published
2024-02-26, Appendix A, printed page 20 (PDF index 24), inspected 2026-10-01. Proposed rationales:
LOG-002 contributes management-log generation coverage context, not continuous monitoring;
LOG-003 contributes integrity-check configuration for stored logs, not verified data integrity;
LOG-004 contributes destination access-policy context, not complete least privilege. These are
project inferences from the source outcomes, not official NIST endorsements. Removing mappings
must not change technical results, severity or policy.

Proposed impact/guidance: LOG-002 gaps reduce audit visibility; review complete management
read/write coverage on an actively logging multi-Region trail, with authorized cost/dependency
review before changes. LOG-003's disabled flag removes digest-generation support; review enabling
validation and a separate operational verification process without claiming existing logs are
retroactively validated. LOG-004 exposure can disclose security logs; review the exact bucket
policy/ACL and legitimate delivery dependencies before a separately approved restriction.
The scanner performs no AWS writes and must not recommend removing essential service access
without review.

No new organization threshold is needed for LOG-002/003. LOG-004 must use an explicit retained
schema-2 approval artifact, including an explicitly empty no-exemption artifact where selected;
absence never means empty. Recommend continuing the approved 6E.2 no-exemption initial policy,
without overwriting any deployed approval content. Changed approvals/enabled controls require a
new profile version, and changed approval content a new policy version. No operator policy is
installed, fetched, logged or committed by this preparation.

Implementation approval must cover this metadata/guidance, the bounded engine/persistence seam,
unchanged canonical truth tables, explicit policy binding, and the empty-population LOG-004
clarification. Preparation does not itself grant implementation, reviewer, publication or merge
permission.

## Acceptance plan and risks

1. Add offline collector-to-engine fixtures and rule tests for every table row. For LOG-002,
   cover optional defaults/raw presence, dimension/exclusion unions, advanced unions/restrictions,
   unsupported operators, all non-qualifying/empty populations and required failure outranking
   a qualifying sibling. For LOG-003, cover explicit booleans, missing/malformed settings,
   complete empty versus incomplete discovery and unrelated-source isolation.
2. For LOG-004, cover multiple trails/buckets, shared destinations, different home Regions,
   approved/unapproved exposure, disabled/missing/insufficient dependencies, partial collectors,
   missing/unresolved/conflicting/substituted edges, and exact owner/snapshot/approval matching.
   Prove reversed registration/candidate order does not change results and no extra AWS calls occur.
3. Extend SQLite and disposable PostgreSQL acceptance for old/new catalog coexistence,
   immutable policy/profile history, replay/recovery, source/result/edge/dependency forgeries,
   atomic rejection and finding lifecycle. Old pending scans retain exact pre-5F intent;
   partial scans and operational exceptions cannot resolve/rewrite technical failures.
4. Use real authenticated HTTP scan creation/execution/readback: ADMIN executes, ANALYST is
   denied, nonblocking 202 uses an event gate and bounded terminal polling. Only AWS is offline;
   authentication, services, executor, collectors, engine and persistence stay real. Retrieve
   exact assessments/proofs, destination relationships, snapshots/history, findings, framework
   context and audit by stable IDs.
5. Run targeted tests first, then the existing `scripts.validate` full-regression/disposable
   PostgreSQL, Ruff, formatting, whitespace, Compose and image gates. Independent review requires
   explicit authorization; resolve findings, verify final-head CI and obtain human merge approval.
   Each unaccepted slice stays in progress rather than advancing the roadmap from unit results.

Relevant existing test homes are `tests/unit/collectors/test_cloudtrail.py`, rule engine/registry/
assessment tests, `tests/unit/rules/test_s3_exposure.py`, `tests/unit/assessment/`,
`tests/unit/database/test_s3_exposure.py` and `tests/integration/test_s3_exposure_postgres.py`.
Reuse their migrations, historical fixtures and `tests/s3_configuration_http.py` acceptance
patterns; add focused logging modules rather than replacing accepted assertions.

Principal risks are false completeness from a pruned discovery set, hidden required failure
behind a qualifying trail, overbroad advanced-selector proofs, implicit dependency enablement,
lexical evaluation order, trusting forged dependency results, and changing historical metadata
bytes. The boundaries and tests above address each. Residual limitations are the canonical
configuration-only coverage/integrity/exposure claims, not delivery, effective authorization,
organization-wide assurance or compliance.

During implementation update the control catalog/evidence matrix, framework owner, architecture,
security/threat model, roadmap/active plan and README if supported releases change. This preparation
changes only planning documentation; it does not assert that those future interfaces exist.

## Preparation validation

The unchanged-baseline focused run passed **245 tests**, no skips: CloudTrail collector,
LOG-001, engine, registry, four-state assessments, S3-002, assessment foundation and S3-002
SQLite persistence/recovery/authenticated HTTP acceptance. One existing Starlette deprecation
warning remains. An initial sandboxed run passed 238 but had seven temporary-folder permission
setup errors; the identical test set passed in an isolated task-owned folder without code/test
changes. **74 contract/link tests** also passed, with the same warning and no skips. Ruff lint,
format checking (**300 Python files**) and tracked/untracked whitespace checks passed.

Exact baseline modules were:

```text
python -m pytest tests/unit/collectors/test_cloudtrail.py tests/unit/rules/test_audit_logging.py tests/unit/rules/test_engine.py tests/unit/rules/test_registry.py tests/unit/rules/test_assessments.py tests/unit/rules/test_s3_exposure.py tests/unit/assessment/test_assessment_foundation.py tests/unit/database/test_s3_exposure.py -q
python -m pytest tests/unit/contracts -q
python -m ruff check . --no-cache
python -m ruff format --check . --no-cache
git diff --check
```

Both pytest runs used the repository Python environment and new isolated task-owned temporary/
cache folders. The new untracked Markdown file was also checked for trailing whitespace.

The accepted 6E.3 **1,957 regression / 122 PostgreSQL** run and the successful merged-main CI
remain evidence for unchanged runtime/test code, not evidence that 6F has been implemented or
reviewed. A prose-only preparation does not invalidate them; future implementation must run
the gates above. No live AWS, operator database, credential change or later-slice implementation.
