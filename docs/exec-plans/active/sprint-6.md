# Sprint 6 — Production Security Controls

Plan state: 6A approved and IN PROGRESS; later implementation slices remain proposed.
Prepared: 2026-09-24.
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

**Current action:** implement approved 6A only. Organization-specific and S3 decisions must be
approved before their dependent slices; they must not be silently supplied by code. The preparation
results above are historical baseline evidence, not validation of the ongoing implementation.

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
