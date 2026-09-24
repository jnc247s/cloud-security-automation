# Sprint 5 — AWS Evidence Expansion

Status: **IN PROGRESS**

Current slice: **5G closure — IMPLEMENTED; PENDING ACCEPTANCE**

Accepted prerequisites: **5G shared relationship/source-outcome evidence foundation — FOUNDATION_READY_FOR_5A**;
**5A EC2 and EBS evidence — COMPLETE**; **5B VPC, subnet, Flow Log, and network evidence — COMPLETE**;
**5C IAM account and IAM policy evidence — COMPLETE**;
**5D IAM Access Analyzer evidence — COMPLETE**; **5E S3 evidence expansion — COMPLETE**;
**5F CloudTrail evidence expansion — COMPLETE**

Canonical scope and project state: [ROADMAP.md](../../../ROADMAP.md)

## Phase 0 gate

Result: `SPRINT_5_GO`

Verified: 2026-09-15

Baseline: `main` commit `feb0b5c2b517f51dd6c7b48eb38513cf92306164`

Starting migration head: `20260904_0002`

The gate confirms that Sprints 0--4 are accepted, the 25-control evidence-readiness matrix is
complete, `SPRINT_5_CONTROL_CONTRACTS_READY` is canonical, the pre-Sprint-5 repairs are merged,
and the baseline CI is green. No unresolved `CRITICAL` or `HIGH` finding blocks implementation.
The dependency-approved first implementation slice is the 5G foundation described below. This
gate did not itself start Sprint 5, add a collector, or authorize any production action. The
subsequent approved start of the 5G foundation changed Sprint 5 to `IN PROGRESS`.

## Planning state

The requirements below are approved roadmap scope. They are recorded here so implementation does
not depend on chat history. The repository preflight required by `AGENTS.md` is complete, the
reviewed slice sequence is approved, and the shared 5G relationship/source-outcome evidence
foundation has passed its acceptance gate as `FOUNDATION_READY_FOR_5A`. Slice 5A passed its
acceptance gates and merged in pull request 16. Slice 5B passed its acceptance gates and merged in
pull request 17. Slice 5C passed its acceptance gates and merged in pull request 18. Slice 5D is
accepted and merged in pull request 20. Slice 5E passed its acceptance gates and merged in pull
request 22. Slice 5F passed its acceptance gates and merged in pull request 24. The bounded 5G
closure implementation is on its feature branch, pending acceptance and merge.
Later sprints remain unstarted.

The two remaining `MEDIUM` roadmap items are explicitly triaged accepted limitations, not hidden
Sprint 5 blockers. Sprint 5 adds no governance mutation route, so audit principal-context
expansion remains deferred to a separately authorized governance/authentication change. The
deployment remains one trusted security domain: new cross-account evidence does not create tenant
isolation, change `READ` authorization, or make an observed resource owner a caller principal.
The authorization-scope limitation must be resolved before any multi-tenant deployment. Sprint 5
must preserve these boundaries and may not claim either limitation is fixed.

The planned control meanings and the evidence contracts needed to implement Sprint 5 are
canonical in the
[control catalog](../../controls/catalog.md), with their planned collection sources, permissions,
scope, normalized facts, relationships, and failure behavior in the
[Sprint 5 evidence-readiness matrix](../../controls/sprint-5-evidence-readiness.md). The dedicated
preflight review has now approved four previously missing design inputs without enabling them:

- the [generic relationship contract](../../design-decisions/0001-generic-resource-relationships.md);
- the [result-sensitive source-outcome contract](../../design-decisions/0002-result-sensitive-evidence-outcomes.md);
- the [S3-002 exposure aggregation](../../controls/s3-002-exposure-aggregation.md); and
- the [S3-004 sensitive-bucket classifier](../../controls/s3-004-sensitive-bucket-classifier.md).

Before Sprint 5 began, their standalone schemas and contract tests did not implement an AWS
collector, executable rule, profile registration, database table, API route, or remediation
behavior. The accepted 5G foundation is limited to the approved shared persistence, domain,
projection, authorization, and migration boundary. Sprint 5 is `IN PROGRESS`; accepted slices 5A
through 5F use that boundary without enabling Sprint 6 rules.

The S3-004 approval here is the versioned sensitive-bucket classifier and its evidence boundary,
not an invented final Sprint 6 KMS result policy. Sprint 5 preserves distinct absent, `AES256`,
AWS-managed KMS, customer-managed KMS, unavailable, and malformed facts. A later reviewed Sprint
6 contract must decide whether AWS-managed versus customer-managed KMS satisfies organization
policy and the result when `restricted_data_requires_kms` is false before registering the rule.
Those choices are not needed to collect the complete factual superset and are intentionally not
made in this plan.

The source-outcome contract is required because planned collectors have independent discovery and
enrichment calls. It retains valid facts and explicit source uncertainty without treating a
collector's `PARTIAL` rollup as permission to pass. Remaining graphless Sprint 0--4 collector
paths retain all-or-nothing behavior. Source-level runtime and persistence integration belongs to
the applicable Sprint 5 slices and must be atomic. The 5A EC2/EBS producer was the first such
integration; the accepted 5B network producers use the same boundary. No Sprint 6 rule consumes
either slice's outcomes yet.

The reviewed implementation order uses 5G as a foundation-and-closure bookend. This is the
dependency-driven exception to the earlier recommended collector-first order: 5C must emit
AWS-managed IAM policies with owner `aws`, and several slices must emit relationships and
source-level outcomes. Before the 5G foundation, the persistence boundary permitted snapshots only
when resource owner equaled scan account. Implementing a producer before the controlled owner and
graph boundary would have lost evidence or forced that slice to invent a representation.

1. **FOUNDATION_READY_FOR_5A — 5G foundation** — the generic source-outcome/relationship
   persistence and projections atomically replace the same-account Python and database-trigger
   assumptions with the closed collection-account/resource-owner admission contract in ADR 0001;
2. **COMPLETE — 5A** — EC2 and EBS evidence;
3. **COMPLETE — 5B** — VPC, subnet, Flow Log, and network evidence;
4. **COMPLETE — 5C** — IAM account and policy evidence;
5. **COMPLETE — 5D** — IAM Access Analyzer evidence;
6. **COMPLETE — 5E** — S3 evidence expansion;
7. **COMPLETE — 5F** — CloudTrail evidence expansion; and
8. **IMPLEMENTED; PENDING ACCEPTANCE — 5G closure** — Sprint-wide relationship,
   persistence, API, acceptance, and performance validation.

The foundational 5G change is not permission for an empty table or a relaxed account check. Its
migration, domain integration, writer, reader, API projection, authorization behavior, and
PostgreSQL/SQLite upgrade/downgrade tests are one reviewable atomic slice. That gate is now
satisfied; later evidence producers may depend on the accepted boundary only when their own slice
is separately authorized.

Sprint 5 remains `IN PROGRESS`, with the shared 5G foundation accepted as
`FOUNDATION_READY_FOR_5A` and 5A through 5F accepted on `main`. The bounded 5G closure is implemented
on its feature branch, pending acceptance and merge. This does not
authorize executable Sprint 6 rules, remediation, or later-sprint work.

## Accepted 5A implementation state

The 5A implementation was accepted and merged in pull request 16 at `main` commit
`5fccdf9f78ea35ead9b40ffe5a6e6367ef110e8d` after validation, independent review, approval, and
merge.

- One fact-only `ec2_ebs_evidence` collector uses the existing Regional client/provider boundary.
- `DescribeInstances` and `DescribeVolumes` are independently paginated. Instances retain state,
  metadata options, public/private IPv4s, VPC/subnet/security-group IDs, attached volume IDs, and
  tags. Volumes retain state, strict encryption state, optional KMS key ID, attachments, and tags.
- `GetEbsEncryptionByDefault` and `GetEbsDefaultKmsKeyId` are independent account/Region source
  observations. They do not create a synthetic resource, and absent default-KMS configuration is
  explicit expected absence.
- Discovery and per-resource enrichment declarations bind normalized artifacts and controlled
  outcomes to the preallocated scan/account/Region/time context. Valid sibling facts survive a
  partial source; malformed or unavailable evidence remains explicit in the collector rollup.
- Instances emit relationship observations to security groups, volumes, subnets, and VPCs. A
  same-scan volume can resolve. Security-group, subnet, and VPC owner identity is not present in
  `DescribeInstances`, so those references remain `TARGET_IDENTITY_INCOMPLETE` rather than
  fabricating the collection account as owner.
- This slice adds no migration, service-specific API route, executable EC2 control, profile
  registration, finding policy, AWS write permission, or 5B--5F behavior.

## Accepted 5B implementation state

The 5B implementation was accepted and merged in pull request 17 at `main` commit
`66cadb20cd6a469d5a656628c27ae8cb569d8c69` after validation, independent review, approval, and
merge.

- The existing `security_groups` collector retains its accepted name, direct graphless behavior,
  and NET-001/NET-002 configuration shape. Its graph-aware path adds authoritative `OwnerId`,
  exact `group_name`, a default-group fact derived only from `GroupName == "default"` with a
  valid VPC ID, complete ingress and egress structures, case-sensitive tags, declared source
  outcomes, and security-group -> VPC observations.
- One separate fact-only `vpc_network_evidence` collector independently paginates Regional
  `DescribeVpcs`, `DescribeSubnets`, and `DescribeFlowLogs`. Keeping these sources separate from
  the `security_groups` rollup prevents a VPC, subnet, or Flow Log failure from changing accepted
  NET-001/NET-002 completeness for independently admissible same-account groups. An external-owner
  group whose mandatory resolved-edge proof is unavailable is the explicit exception: it is
  pruned and `security_groups` becomes `PARTIAL`.
- VPC resources retain owner, state, CIDR, DHCP, tenancy, default-VPC context, and tags. Subnets
  retain owner, VPC ID, address and Availability Zone context, public/IPv6 assignment settings,
  default-AZ/IPv6-native context, and tags. Flow Logs retain their ID, `ResourceId`, status,
  traffic type, destination context, delivery context, aggregation interval, and tags.
- Each of the four AWS APIs has its own Regional discovery contract, normalized artifact, and
  typed source outcome. Each retained resource has an identity-authoritative enrichment contract.
  Valid siblings remain available when a source is partial; unavailable, malformed, or
  conflicting evidence stays explicit and sanitized. `OwnerId` remains distinct from the
  verified collection account, including controlled shared/external VPC, subnet, and security-
  group observations.
- Inventory assembly admits an external-owner network resource only when it participates in an
  exact resolved same-scan edge. An unlinked external observation is removed with its
  resource-scoped evidence; its complete discovery artifact preserves the AWS-observed ID and
  records the canonical admission gap without changing the successful source state. Its collector
  derives `PARTIAL` from the digest-bound admission metadata while preserving independent/same-
  account siblings without weakening admission.
- Security-group -> VPC, VPC -> subnet, and VPC -> VPC-scoped Flow Log observations use the
  accepted generic relationship boundary. Subnet and Flow Log edges require an exact collected
  VPC identity in the same owner/collection context and Region; a subnet-, interface-, or transit-
  gateway-scoped Flow Log never fabricates a VPC edge. The inventory resolver supplies exact
  same-scan target snapshots for resolved relationships and preserves typed uncertainty when a
  target source is incomplete.
- The accepted implementation supplies the factual inputs for NET-003 through NET-006 and the VPC,
  subnet, security-group, and Flow Log tag inputs for GOV-001. NET-003 through NET-006 remain
  unregistered Sprint 6 rules, and their planned profile fields remain deferred to the reviewed
  Sprint 6 profile transition.
- This slice adds no migration, service-specific API route, executable network control, profile
  registration, finding policy, AWS write permission, or 5C--5F behavior.

## Authorized 5C preflight state

The bounded 5C preflight completed against the accepted 5B baseline at `main` commit
`66cadb20cd6a469d5a656628c27ae8cb569d8c69`. IAM-001 through IAM-006 and the IAM portion of
GOV-001 have authoritative evidence contracts covering AWS APIs and read permissions,
account-global scope, normalized facts, relationships, provenance, missing-evidence behavior, and
5C ownership. No unresolved contract, provider, persistence, migration, API, authentication,
authorization, or security blocker requires redesign before implementation.

The implementation is authorized only within these boundaries:

- Preserve the existing `iam_users` collector name, direct compatibility behavior, embedded MFA
  and access-key configuration, and current IAM-001 evidence semantics. Its graph-aware path will
  add the approved user, group, role, membership, MFA-device, access-key, managed-policy,
  managed-policy-version, inline-policy, trust-policy, permissions-boundary, and tag evidence.
- Add a separate graph-aware `iam_account_evidence` collector for `GetAccountSummary`. An account-
  summary denial or malformed response must not erase or misstate independently valid IAM-001
  user evidence. The new requested-collector marker gates the exact 5C source manifest while
  preserving accepted pre-5C history whose `iam_users` collector was graphless.
- Execute IAM collection once per scan as account-global work. Use the accepted response-boundary
  validation, pagination, source-manifest, artifact, outcome, stable-identity, relationship, and
  collection-account/resource-owner contracts. Customer-managed resources use their 12-digit
  owner account; referenced AWS-managed policies use only the controlled `aws` owner sentinel.
- Discover local managed policies, then retrieve only AWS-managed policies referenced by an
  attachment or permissions boundary. Validate partition-aware ARNs; do not hardcode `arn:aws` or
  enumerate every AWS-managed policy.
- Preserve explicit no-recorded-use facts for access keys and strict integer `0`/`1` account-
  summary indicators. Decode policy documents strictly, retain the complete normalized policy
  structure and digest, and never weaken the sensitive-key guard or persist credential secrets.
- Emit top-level same-scan resources for every resolved relationship endpoint. Use the canonical
  relationship vocabulary and collision-safe identities for inline policies and managed-policy
  versions. Role trust policy is retained as evidence and is not treated as an identity-
  permissions policy or a complete IAM authorization decision.
- Reuse the generic `Resource`/`ResourceSnapshot`, evidence graph, persistence, `ScanExecutor`,
  service, and authenticated `/api/v1` boundaries. No migration or service-specific route is
  planned unless implementation exposes a concrete contract mismatch requiring a new review.
- Add controlled-fake collector tests, executor/service coverage, and authenticated disposable-
  PostgreSQL acceptance proving persistence and generic retrieval. Do not contact live AWS.
- Do not register IAM-002 through IAM-006 or GOV-001 as executable Sprint 6 rules, change the
  assessment profile, add finding policy, broaden AWS write permissions, or begin 5D--5F work.

Acceptance of the 5C producer moves IAM-003 through IAM-006 to `CURRENT` evidence state alongside
IAM-001, IAM-002, and the implemented IAM portion of GOV-001. This records available facts only;
it does not register the planned Sprint 6 rules or profile policy. Sprint 6 remains `PLANNED`.

### Accepted 5C implementation state

The authorized fact-only implementation passed complete validation, independent review, CI, and
merge approval in pull request 18 at `main` commit
`819f9ba3b26490ca23c69a6665b1baf9d7948975`. It keeps legacy direct `iam_users` collection
behavior, adds a separately attributable `iam_account_evidence` source, and uses the existing
evidence graph for IAM resources, normalized artifacts, source outcomes, and relationships. The
implementation adds no schema migration, service-specific API, assessment-profile change,
executable IAM-002 through IAM-006 or GOV-001 rule, finding policy, AWS write permission, or
5D--5F behavior.

## Authorized 5D preflight state

The bounded 5D preflight completed against the accepted 5C baseline at `main` commit
`819f9ba3b26490ca23c69a6665b1baf9d7948975`. The canonical Access Analyzer contract covers the
AWS APIs and read permissions, Regional scope, normalized facts, relationship, provenance, and
missing-evidence behavior needed for the supplementary S3-002 investigation evidence. No policy,
provider, persistence schema, migration, API, authentication, authorization, or security redesign
blocks implementation.

One current in-memory boundary requires a narrow 5D extension. Access Analyzer must run in the
explicitly requested Region and every distinct Region of a successfully normalized S3 bucket, but
the current evidence graph rejects account-level Regional discovery outside the requested Region
and the collector context cannot yet receive the bucket-derived Region set. Revision
`20260915_0003` already persists the `allows_supplemental_region` contract flag, so this is not a
schema change. The 5D implementation is authorized to extend only the in-memory contract and
orchestration needed to prove those exact bucket-backed Regions; arbitrary supplemental discovery
must remain rejected.

The implementation is authorized only within these boundaries:

- Add one fact-only, graph-aware `access_analyzer_evidence` collector after S3 inventory. Its
  immutable execution input is the sorted unique union of the requested Region and Regions from
  successfully normalized `s3_bucket` resources. It must not make S3 calls, duplicate 5E evidence,
  or infer a Region when S3 evidence is unavailable.
- Treat the `s3_buckets` discovery outcome as an input to coverage, not merely as an optional
  source of Regions. A failed, partial, or otherwise incomplete bucket inventory means incomplete
  bucket-Region discovery makes Analyzer coverage incomplete (`FAILED` or `PARTIAL`, as the
  retained source facts warrant), even if the requested Region was scanned successfully. Retain
  valid requested-Region facts, but never emit a complete no-analyzer or no-finding claim. Persist
  the source inputs and outcomes needed to reconstruct that coverage decision.
- Permit supplemental Regional discovery only for the controlled Access Analyzer sources and
  only when the exact Region is backed by a same-scan normalized S3 bucket. Preserve the existing
  rejection for every other unrequested discovery Region. Multiple Regional source declarations
  must remain deterministic, collision-safe, and reconstructable from persisted artifacts.
- Fully paginate unfiltered `ListAnalyzers`, retaining analyzer ARN, name, type, status, and actual
  Region. Only external-access analyzers (`ACCOUNT` and `ORGANIZATION`) are relevant to this slice.
  A complete Region with no such analyzer is explicit absence, never proof that a bucket has no
  external access.
- For every relevant analyzer, fully paginate `ListFindingsV2` for external-access S3 bucket
  findings and then fully paginate `GetFindingV2` for every discovered finding. Retain the
  analyzer identity, composite analyzer/finding identity, status, bucket ARN, owner account,
  timestamps, and every detail item including principal, action, condition, `isPublic`, sources,
  and resource-specific detail. Never infer detail from the summary.
- Normalize each finding as one Regional `access_analyzer_finding` resource owned by the verified
  collection account. Its collision-safe AWS resource ID must encode both analyzer ARN and finding
  ID canonically. Analyzer summaries remain normalized source evidence rather than invented
  control-plane findings or a service-specific persistence model.
- Emit the canonical finding -> S3 bucket `references_resource` observation. Resolve only an exact
  same-scan bucket identity and snapshot; otherwise retain the complete stable target or typed
  unresolved reference without fabricating a bucket. Keep collection account, analyzer owner, and
  `resourceOwnerAccount` distinct.
- Use independent source artifacts and outcomes so a denied, malformed, conflicting, disappeared,
  or pagination-incomplete analyzer/finding does not erase valid siblings. Repeated,
  non-progressing, or unconsumed tokens from any of the three operations fail closed and routine
  errors remain sanitized.
- Reuse the existing AWS client provider, generic evidence graph, transactional persistence,
  `ScanExecutor`, services, and authenticated `/api/v1` reads. No migration or service-specific
  route is planned.
- Add `access-analyzer` only to the intent of newly created scans and make executor collection and
  scope construction honor each pending scan's persisted `requested_services`. A pre-5D
  `RUNNING` scan that lacks that marker must resume with the accepted pre-5D collector set rather
  than silently gaining the new collector or failing after AWS work. Cover both new and legacy
  pending-scan paths without weakening exact pending-intent validation or rewriting history.
- Keep completed pre-5D source manifests and evidence graphs valid when Access Analyzer is neither
  requested nor represented. Register the collector and its dynamic per-Region discovery checks
  conditionally from the immutable scan manifest; do not make a new static required-source set
  invalidate accepted 5A--5C history. Add persisted readback coverage for that compatibility path.
- Add controlled-fake pagination/validation tests, inventory/executor coverage, generic API tests,
  and authenticated disposable-PostgreSQL acceptance for artifacts, outcomes, findings-as-
  resources, and resolved/unresolved relationships. Do not contact live AWS.
- Do not treat Analyzer evidence as a v1 S3-002 decision or approval, create executable Sprint 6
  rules, change the assessment profile, implement direct 5E S3 evidence, add finding policy,
  broaden AWS write permissions, or begin 5F work.

The evidence-readiness state for S3-002 does not change merely because 5D has started. It remains
`CONTRACT_READY` until the separately accepted direct 5E evidence producer exists, and Analyzer
evidence remains supplementary and non-decisive. Sprint 6 remains `PLANNED`.

## Accepted 5D implementation state

The authorized fact-only implementation was merged in pull request 20 at `main` commit
`1a355107eb7a3ed7845fa3a569dbff80da2778bb`; the merged-main CI quality job succeeded.

- One fact-only `access_analyzer_evidence` collector runs after S3 and uses the existing AWS client
  provider. It scans the requested Region plus the sorted unique Regions of exact normalized
  same-scan S3 buckets; it makes no S3 call and cannot authorize an arbitrary supplemental Region.
- Per-Region `ListAnalyzers`, per-relevant-analyzer `ListFindingsV2`, and per-finding
  `GetFindingV2` are fully paginated and independently represented by normalized artifacts and
  controlled outcomes. `ACCOUNT` and `ORGANIZATION` analyzers are the only external-access types
  used by this slice. Operational, malformed, conflicting, disappeared, or pagination-incomplete
  evidence remains sanitized and incomplete while independently valid siblings survive.
- Analyzer discovery artifacts bind the exact required-Region set and the completeness of the S3
  bucket discovery that supplied it. Incomplete bucket discovery keeps Analyzer coverage
  incomplete even when requested-Region facts were retained; complete empty enumeration is an
  explicit absence, not an exposure decision.
- Each retained finding is a Regional `access_analyzer_finding` owned by the verified collection
  account with a collision-safe composite analyzer-ARN/finding-ID resource identity. Analyzer
  summaries remain source artifacts, not top-level resources or control-plane findings.
- A finding emits the canonical `references_resource` observation to the S3 bucket named by the
  finding. Only an exact same-scan bucket identity and snapshot resolve; otherwise the complete
  stable target or typed unresolved reference is retained. Collection account, analyzer owner,
  and `resourceOwnerAccount` remain distinct.
- Newly created scans persist `access-analyzer` service intent. Executor orchestration selects the
  5D or pre-5D collector/resource-type set from each pending scan's immutable
  `requested_services`, so an existing pre-5D `RUNNING` scan neither gains new AWS work nor fails
  after collection. Completed pre-5D manifests and graphs remain valid when Analyzer evidence is
  absent.
- The implementation reuses generic resources, snapshots, evidence artifacts/outcomes,
  relationships, transactional persistence, `ScanExecutor`, services, authentication,
  authorization, and `/api/v1` reads. Revision `20260915_0003` already stores the required graph
  fields, so 5D adds no migration and no service-specific API.
- The scanner permission delta is read-only:
  `access-analyzer:ListAnalyzers`, `access-analyzer:ListFindings` (for `ListFindingsV2`), and
  `access-analyzer:GetFinding` (for `GetFindingV2`).
- Controlled-fake collector, graph, inventory/executor, compatibility, generic read, and
  disposable-PostgreSQL acceptance coverage is part of the accepted baseline. No test contacts
  live AWS.
- At 5D acceptance, `S3-002` remained `CONTRACT_READY` and non-decisive until direct 5E S3
  evidence was separately accepted. The accepted 5D slice did not implement 5E, 5F, a Sprint 6
  rule, remediation, dashboard, production deployment, or AI behavior.

## Authorized 5E preflight state

The bounded 5E preflight completed on 2026-09-17 against the accepted 5D baseline at `main`
commit `1a355107eb7a3ed7845fa3a569dbff80da2778bb`, with migration head `20260915_0003` and green
merged-main CI. The canonical control catalog, S3-002 exposure aggregation, S3-004 classifier,
and evidence-readiness matrix already define the required direct S3 and referenced-KMS factual
superset. The existing evidence graph, generic persistence and authenticated API projections,
AWS client provider, and relationship vocabulary carry that evidence without a migration or
service-specific route. The implementation described below is accepted on `main`.

The implementation is authorized only within these boundaries:

- Preserve immutable pending-scan execution intent. Newly created 5E scans use exact service intent
  `("access-analyzer", "cloudtrail", "ec2", "iam", "kms", "s3")`; `kms` is the 5E marker and
  also admits canonical top-level `kms_key` resources. `ScanExecutor` must retain distinct
  supported paths for that intent, accepted 5D intent without `kms`, and accepted pre-5D intent
  without `access-analyzer` or `kms`. Unknown tuples must fail before AWS work. Existing pending
  scans and historical manifests must not be rewritten or silently gain AWS work, source
  contracts, or resource types.
- Preserve the accepted `s3_buckets` collector name, direct behavior, normalized configuration,
  and `S3-900` completeness semantics. Full graph-aware 5E coverage belongs to a separate
  `s3_evidence` operational outcome. Both projections must consume one shared per-scan collection
  bundle so each AWS operation runs once and provenance is not fabricated. An unrelated policy,
  ACL, account-BPA, versioning, ownership-control, or KMS failure must not make otherwise complete
  `S3-900` encryption evidence unavailable.
- Replace the 5D runtime shortcut that equates bucket-Region discovery completeness with the
  whole `s3_buckets` rollup for new 5E scans. Access Analyzer coverage must use the exact same-scan
  S3 discovery and authoritative bucket-location outcomes. Unrelated 5E enrichment failures must
  not make Analyzer Region coverage incomplete; incomplete bucket discovery or location evidence
  must. Accepted pre-5E persisted graphs retain their existing validated fallback semantics.
- Keep supplemental-Region admission closed and proof-bound. An S3 bucket outside the requested
  Region is admissible only in the home Region established by its authoritative same-scan S3
  location evidence. A `kms_key` is admissible only when authoritative same-scan `DescribeKey`
  evidence and an explicit bucket encryption reference support the canonical
  `s3_bucket --encrypted_with--> kms_key` relationship. A general
  `allows_supplemental_region` flag is not sufficient proof.
- Use validated `DescribeKey.KeyMetadata.Arn` as both canonical `kms_key.aws_resource_id` and ARN.
  Verify the returned `AWSAccountId`, partition, Region, `KeyId`, and `KeyManager`; retain the
  12-digit resource owner even when `KeyManager == AWS`. Cache lookups by Region and supplied
  reference, coalesce identical canonical keys, and reject conflicting metadata. ARN references
  select their stated Region; local IDs and aliases use the bucket home Region until
  `DescribeKey` supplies canonical identity. An incomplete lookup retains the supplied reference
  as typed unresolved evidence but emits no invented `kms_key`. Never fabricate a key, owner,
  Region, ARN, or manager.
- Run paginated `ListBuckets` and account `s3control.GetPublicAccessBlock` once. Establish every
  bucket's authoritative home Region with `GetBucketLocation` before per-bucket enrichment, then
  normalize a null `LocationConstraint` to `us-east-1` and the legacy `EU` value to `eu-west-1`.
  A contradiction with any independently returned bucket Region fails closed. Then collect tags,
  bucket Public Access Block, policy, policy status, ACL, versioning, encryption, and ownership
  controls in that Region. Keep the accepted `HeadBucket` recovery path distinct from the
  canonical 5E source. Deduplicate `DescribeKey` for explicit KMS references only.
- Retain independent, digest-bound source artifacts and outcomes. Expected no-policy, no-Public-
  Access-Block, no-tags, no-encryption-configuration, no-ownership-controls, and unversioned
  responses are explicit complete factual states. Access denial, throttling, service failure,
  malformed or contradictory data, failed authoritative Region resolution, and resource
  disappearance remain distinct uncertainty while valid sibling facts survive.
- Decode bucket policies strictly, reject duplicate JSON keys and malformed structures, retain
  complete effects, principals, actions, resources, conditions, and a deterministic digest.
  Preserve ACL owner and every grant, all four account and bucket Public Access Block flags,
  exact case-sensitive tags, encryption algorithm and bucket-key state, each rule's optional exact
  `BlockedEncryptionTypes.EncryptionType` value (`NONE` or `SSE-C`), and KMS manager/ownership
  facts. Treat policy, ACL, topology, tag, and encryption evidence as sensitive `READ` data and
  never place it in routine logs or raw errors.
- Keep collectors fact-only. Access Analyzer remains supplementary and non-decisive for S3-002.
  Do not register `S3-001` through `S3-004`, change the assessment profile, implement 5F, add
  remediation or AWS writes, or begin dashboard, deployment, or AI work. At the 5E acceptance
  boundary, 5F remained unstarted.

Acceptance requires deterministic fake-AWS coverage for pagination, source independence,
expected absence, malformed/conflicting evidence, policy and ACL normalization, encryption
variants, KMS deduplication and identity, resolved/unresolved relationships, exact Region
admission including the null and legacy `EU` location mappings, Analyzer discovery completeness,
pending-scan compatibility, and unchanged `S3-900` behavior. It also requires generic
persistence/API readback, authenticated disposable-PostgreSQL
HTTP acceptance, targeted and full regression tests, Ruff lint/format, container validation,
independent review, green CI, approval, and merge. No test may contact live AWS.

## Accepted 5E implementation state

The accepted implementation adds one shared per-scan S3 collection bundle with two projections: the
accepted `s3_buckets` collector retains its name, `S3-900` input shape, and independent rollup,
while `s3_evidence` emits the 5E source graph and referenced `kms_key` resources. The bundle calls
`ListBuckets` and account Block Public Access once, establishes each bucket's authoritative home
Region, independently collects tags, bucket Block Public Access, policy and status, ACL,
versioning, encryption, and ownership controls, and deduplicates `DescribeKey` by Region plus the
supplied explicit reference.

Every source has a digest-bound normalized artifact and typed outcome. Expected absence remains a
complete factual state; malformed, conflicting, denied, throttled, disappeared, and unavailable
sources stay distinct without erasing valid siblings. Bucket policy parsing rejects duplicate
keys and invalid structures, bucket and account Block Public Access retain all four flags, and
encryption rules retain an optional single `NONE` or `SSE-C` blocked-encryption-type fact. KMS
resources use only validated returned `KeyMetadata.Arn`, account, partition, Region, key ID, and
manager. A successful explicit key reference emits the canonical resolved
`s3_bucket --encrypted_with--> kms_key` edge; a failed lookup retains a typed unresolved
reference and never fabricates a key.

New scans use the `kms` service-intent marker. The executor separately recognizes the accepted
5D and pre-5D intent tuples, and those paths retain the legacy S3 collector without any 5E S3
Control or KMS calls. New Access Analyzer coverage uses exact 5E `ListBuckets` and bucket-location
completeness; accepted pre-5E graphs retain their original `s3_buckets` fallback. No migration,
service-specific API, assessment-profile change, executable Sprint 6 rule, finding policy, AWS
write permission, 5F collector, remediation, dashboard, deployment, or AI behavior is included.

Slice 5E passed its acceptance gates and was merged in pull request 22 at `main` commit
`8ea9df86f8c6ae623ef41ebb836e6b3b7d052393`. Pull-request CI succeeded. No Sprint 6 rule was
enabled.

## Authorized 5F preflight state

The bounded 5F preflight completed on 2026-09-22 against the accepted 5E baseline at `main`
commit `8ea9df86f8c6ae623ef41ebb836e6b3b7d052393`, with migration head `20260915_0003` and green
pull-request CI. The control catalog and evidence-readiness matrix already define the CloudTrail
facts required by `LOG-001` through `LOG-004` and the CloudTrail portion of `GOV-001`. The
existing AWS client provider, evidence graph, generic persistence and authenticated API
projections, executor, and relationship vocabulary can carry this evidence without a migration,
new dependency, service-specific route, or authentication change. This preflight adds no
collector and does not start 5F.

The explicit implementation request has been received. The implementation remains bounded by
these contracts:

- Preserve immutable pending-scan execution intent. Newly created 5F scans use exact service
  intent `("access-analyzer", "cloudtrail", "cloudtrail-evidence", "ec2", "iam", "kms", "s3")`.
  `cloudtrail-evidence` is a persisted execution-version marker, not an AWS service or permission.
  The accepted 5E tuple without that marker remains a distinct pre-5F path and must make no new
  `GetEventSelectors` call or gain a CloudTrail graph manifest. Accepted 5D and pre-5D paths also
  remain supported. Unknown tuples fail before AWS work; existing scan rows and historical
  manifests are never rewritten.
- Preserve the accepted `cloudtrail_trails` collector name, direct behavior, normalized
  configuration, and `LOG-001` input semantics. Full graph-aware 5F coverage belongs to a
  separate `cloudtrail_evidence` operational outcome. Both projections consume one shared
  per-scan collection bundle so the accepted sources are not called twice and a selector-only or
  tag-only failure cannot erase independently complete legacy logging evidence. The direct
  pre-5F collector path remains unchanged. On the 5F path, both projections use the validated ARN
  owner; an unadmitted external-owner trail is omitted from both resource projections and makes
  `cloudtrail_trails` and `cloudtrail_evidence` incomplete, so unchanged `LOG-001` semantics yield
  `INSUFFICIENT_EVIDENCE` rather than evaluating a fabricated collection-account owner.
- Run paginated `ListTrails` once for the collection account. The API accepts only its pagination
  token and returns stable trail summaries rather than a per-Region `DescribeTrails` shadow-copy
  view, so no unsupported shadow-trail filter is supplied. Deduplicate exact records by trail ARN
  and reject conflicting duplicates. Validate the trail ARN partition, CloudTrail service,
  home Region, 12-digit owner, and name consistently. Enrich each admitted trail in its actual
  home Region with independent `GetTrail`, `GetTrailStatus`, and non-paginated
  `GetEventSelectors` outcomes. Group `ListTags` calls by home Region, submit no more than 20 ARNs
  per request, paginate each batch, and preserve deterministic per-trail attribution.
- Keep the verified collection account separate from actual trail ownership. A member-visible
  organization trail keeps the management-account owner parsed from its validated ARN and its
  organization context; it never pretends to belong to the collecting member or proves
  organization-wide coverage. An externally owned trail becomes a top-level resource only when
  it satisfies the existing ADR 0001 exceptional-owner admission rule, including
  identity-authoritative evidence and an exact resolved same-scan relationship. Otherwise retain
  its complete normalized source artifact, mark the affected account coverage incomplete, and do
  not fabricate, delete, or silently relabel the trail.
- Treat “account to trails” in `LOG-001` and `LOG-002` as the complete collection-account coverage
  set established by the scan, source manifest, and discovery outcome. It is not a new persisted
  generic resource relationship. Do not invent a synthetic AWS account resource or add a new
  relationship type.
- Normalize facts without evaluating them. Retain explicit logging, multi-Region,
  organization-trail, global-service-event, log-file-validation, CloudWatch Logs, KMS, S3
  destination/prefix, sanitized status, and complete case-sensitive tag facts. Exactly one
  non-empty event-selector form is valid. Basic selectors retain raw field presence, documented
  defaults, every data-resource value, and only the supported management-event exclusions.
  Advanced selectors retain every field selector and all six operator arrays. Mixed, empty,
  malformed, contradictory, or unsupported response structures remain explicit uncertainty;
  the collector does not decide `PASS` or `FAIL`.
- Emit `cloudtrail_trail --delivers_to_bucket--> s3_bucket` only from complete `GetTrail`
  evidence. Resolve it only through the exact same-scan accepted 5E bucket identity and snapshot;
  otherwise retain the supplied bucket name as a typed identity-incomplete reference without
  inventing owner or Region. Source and destination Regions may differ.
- Retain a validated full `KmsKeyId` ARN and emit
  `cloudtrail_trail --encrypted_with--> kms_key` from complete `GetTrail` evidence. Resolve it only
  when an exact canonical 5E KMS resource and snapshot already exist; otherwise retain the
  complete canonical target with an appropriate unresolved resolution state. 5F does not add a
  second unconditional `DescribeKey` producer, fabricate a key, or broaden the accepted KMS
  admission contract.
- Declare an exact dynamic source manifest with one account discovery source and independent
  per-trail identity, configuration, status, selector, and tag outcomes. Bind every admitted
  normalized fact and relationship to digest-verified artifacts so graph replay and persistence
  readback reject omission, substitution, or mutation. A completely unavailable discovery is
  `FAILED`; partial enumeration or per-trail failures retain valid siblings with incomplete
  coverage. A disappeared trail, malformed identity, conflict, denial, throttling, and service
  failure remain distinct sanitized outcomes.
- Use only read actions: `cloudtrail:ListTrails`, `cloudtrail:GetTrail`,
  `cloudtrail:GetTrailStatus`, `cloudtrail:GetEventSelectors`, and `cloudtrail:ListTags`. Do not
  broaden scanner credentials or contact live AWS in tests.
- Keep collectors fact-only. Do not register `LOG-002` through `LOG-004`, change `LOG-001`, extend
  the assessment profile, create findings, add a migration or service-specific API, implement
  remediation or AWS writes, or begin dashboard, deployment, AI, Sprint 6, or 5G-closure work.

Acceptance requires deterministic fake-AWS coverage for pagination, duplicate shadow/home-record
exclusion through stable-ARN deduplication,
duplicate handling,
home-Region routing, tag batching and attribution, selector forms and defaults, malformed and
conflicting evidence, independent source failures, organization-trail ownership, exact account
coverage, resolved/unresolved S3 and KMS relationships, immutable pending-scan compatibility, and
unchanged `LOG-001` behavior. It also requires exact graph replay and tamper tests, generic
persistence/API readback, authenticated disposable-PostgreSQL HTTP acceptance, targeted and full
regression tests, Ruff lint/format, container validation, independent review, green CI, approval,
and merge. No test may contact live AWS.

## Accepted 5F implementation state

Implementation started from the merged preflight baseline at `main` commit
`349f57ebe8fb8ad6c4e4e6e01a8d6262394f8805`. The bounded implementation added the fact-only
CloudTrail expansion described above:

- New scans persist the exact service intent
  `("access-analyzer", "cloudtrail", "cloudtrail-evidence", "ec2", "iam", "kms", "s3")`.
  `cloudtrail-evidence` is an execution-version marker, not an AWS service or permission. The
  accepted 5E tuple remains a distinct path and makes no new selector call or CloudTrail graph.
- The accepted `cloudtrail_trails` projection and the graph-aware `cloudtrail_evidence` projection
  share one per-scan collection bundle. Direct and persisted pre-5F paths retain their accepted
  behavior, while selector- or tag-only uncertainty cannot erase independently complete legacy
  logging evidence.
- The bundle calls paginated `ListTrails` once without an unsupported shadow-trail argument,
  validates and deduplicates stable ARNs, and routes `GetTrail`, `GetTrailStatus`,
  `GetEventSelectors`, and batched/paginated `ListTags` to each trail's validated home Region.
- The graph declares account discovery plus per-trail identity, configuration, status,
  event-selector, and tag source families. Artifacts and outcomes remain digest-bound, facts-only,
  and independently incomplete when an AWS response is denied, malformed, contradictory,
  unavailable, or disappears.
- A trail retains the owner parsed from its validated ARN; collection account, organization
  context, and resource ownership remain separate. Unadmitted external-owner trails stay in
  source evidence, are omitted from both resource projections, and make coverage incomplete.
- Complete configuration evidence may emit `delivers_to_bucket` and `encrypted_with`
  observations. S3 resolution uses exact same-scan 5E bucket evidence; KMS resolution reuses an
  exact already-collected 5E key. Missing matches remain typed unresolved references, and 5F adds
  no `DescribeKey` producer.
- The only permission delta is read-only `cloudtrail:GetEventSelectors`. The slice adds no
  dependency, migration, route, authentication/authorization change, assessment-profile change,
  executable Sprint 6 rule, finding behavior, AWS write, or later-sprint implementation.

Slice 5F passed its deterministic fake-AWS, graph replay/tamper, generic persistence/API readback,
authenticated disposable-PostgreSQL HTTP acceptance, targeted/full regression, Ruff,
container-build, independent-review, CI, approval, and merge gates. It was accepted and merged in
pull request 24 at `main` commit `29aeea59b9cceff957adac4fba75cb8ca2c4a592`; the final feature
commit was `78ca8afa4d2051c69cde5b595c0bb4a90a1a4c3b`. Slice 5F is **COMPLETE**. Sprint 5 remains
`IN PROGRESS`; Sprint 6 remains `PLANNED`.

## Approved 5G closure scope

State: **IMPLEMENTED; PENDING ACCEPTANCE**

The approved closure scope is bounded to Sprint-wide validation of the
accepted 5G foundation and 5A through 5F evidence producers across relationships, transactional
persistence, generic authenticated API readback, acceptance coverage, and performance behavior.
It does not add a new collector, executable Sprint 6 rule, schema, API, dependency, assessment
profile, finding policy, AWS permission, remediation behavior, dashboard, deployment, or AI
functionality. If validation exposes a concrete defect that requires one of those changes, stop
and obtain a separate architecture and implementation review rather than expanding closure scope
silently.

The existing authenticated disposable-PostgreSQL HTTP acceptance test remains authoritative for
the real routing, authentication, authorization, service, executor, normalization, graph,
transactional persistence, and generic readback path; only AWS is replaced by deterministic
fakes. Do not duplicate that acceptance test. Add only the missing deterministic performance
gates and the behavior-preserving in-memory lookup indexes needed to satisfy them:

- with representative synthetic graphs of size `N` and `2N`, prove target resolution,
  relationship-provenance validation, and persistence provenance lookup work grows linearly rather
  than rescanning every resource or source outcome for every relationship; and
- on disposable PostgreSQL, prove the generic relationship and source-outcome list operations use
  a constant two SQL statements (count plus bounded page) and their detail operations use a
  constant statement count, independent of stored graph size and requested page size.

These are operation/query-count invariants, not a wall-clock SLA or environment-dependent
benchmark. Closure acceptance requires its focused tests, the complete regression suite,
disposable-PostgreSQL acceptance/integration tests, container validation, Ruff lint and format,
independent correctness/security/data-integrity review, green CI, explicit approval, and merge.
No test contacts live AWS.

Only a separate post-merge closeout may mark Sprint 5 `COMPLETE`, move this plan to
`docs/exec-plans/completed/`, promote Sprint 6 from `PLANNED` to `NEXT`, and update released
history. Until then, Sprint 5 remains `IN PROGRESS`, Sprint 6 remains `PLANNED`, and 5G closure
requires acceptance and merge.

## 5G closure implementation — pending acceptance

The implementation branch `codex/sprint-5g-closure` starts from the accepted 5F `main` baseline
`29aeea59b9cceff957adac4fba75cb8ca2c4a592` and carries the reviewed closure-preflight documentation
commit before the bounded implementation. No merge into `main` is implied.

- Target resolution builds an operation-local index of authoritative identities. Partial target
  keys retain owner/scope/Region distinctions and ambiguous matches remain unresolved. Source
  uncertainty precedence is indexed without changing resolution semantics.
- Graph validation, resource binding, and persistence build operation-local provenance indexes
  using the existing six-field tuple. Multiple matches remain visible and are rejected; indexes
  are never persisted or used to bypass graph reconstruction, digest validation, or transactions.
- Deterministic synthetic graphs of 16 and 32 relationships exercise real resolution, validation,
  persistence, and replay. Model-access counts detect repeated full scans without a timing SLA.
  The tests failed against the original repeated-scan implementation before the indexes were added.
- Disposable-PostgreSQL tests count real SQL through serialization with fresh sessions: list
  operations require exactly two statements, relationship details one, and source details two,
  across graph sizes, page sizes, and the source-contract filter.
- The existing authenticated HTTP-to-PostgreSQL acceptance test remains authoritative and is not
  duplicated. It exercises accepted 5A through 5F facts and relationships with only AWS replaced.

No collector, schema, migration, API, dependency, permission, profile, executable control, or
later-sprint behavior is added. Migration head remains `20260915_0003`. Final validation, review,
CI, and merge evidence belongs to the closure PR; sprint closeout remains a separate post-merge
action.

Local validation on 2026-09-23: focused closure/graph/contract tests **125 passed**; full regression
**1376 passed, 20 skipped** (the established PostgreSQL skips without `TEST_DATABASE_URL`). Ruff
lint and format checks passed. An independent read-only correctness/security/integrity review
returned `REVIEW_PASS` with no findings. Local Docker Desktop did not provide a usable engine;
PostgreSQL integration/HTTP acceptance and the image build therefore still require the authoritative
CI run before acceptance. Docker Compose configuration validation passed.

## Objective and boundary

Collect the normalized AWS evidence required by the planned Sprint 6 production control library.
Sprint 5 does not implement new security controls, framework scoring, remediation, dashboard,
Terraform deployment, or AI behavior. Collectors remain fact-only; rules remain deterministic and
AWS-independent.

## Approved evidence scope

- Formalize account/global, regional, and bucket-region execution scope. Do not duplicate global
  resources once per configured Region.
- EC2: instance identity and state, public/private addresses, VPC, subnet, security groups,
  metadata options including IMDS `HttpTokens`, attached EBS volumes, and tags.
- EBS: volume identity, encryption, KMS key, attachments, tags, and account/Region EBS default
  encryption evidence.
- Network/VPC: VPCs, flow logs, subnets, public-IP auto-assignment, default security groups, and
  relationships needed by later controls.
- IAM account security: supported MFA, root access-key, password, and root credential indicators.
  Never create root credentials for testing.
- IAM policy evidence: users, groups, roles, memberships, attached and inline policies, managed
  policy default versions and documents, and relevant role trust policies. Normalize `Effect`,
  `Action`, `NotAction`, `Resource`, `NotResource`, and `Condition`. Document that this is not a
  reimplementation of the complete IAM authorization engine.
- IAM Access Analyzer, where enabled: analyzer existence/status and relevant external-access
  findings. Missing analyzers may be evidence but need not become a v1 core control.
- S3: account and bucket Block Public Access, policies and policy status, ACL/public and supported
  external-account exposure, secure-transport policy, versioning, encryption mode, and KMS key.
  Preserve the distinction between default encryption and an organization-specific KMS
  requirement; do not restore an obsolete generic encryption rule or reuse reserved control IDs.
- CloudTrail: logging, multi-Region status, event selectors, read/write management-event coverage,
  log-file validation, CloudWatch Logs integration, KMS information, and S3 destination.
- Resource relationships useful for investigation, including EC2-to-security-group,
  EC2-to-EBS, CloudTrail-to-S3, and S3-to-KMS links.

## Definition of done

For every planned Sprint 6 core control, Sprint 5 identifies and validates:

- its AWS API source and least-privilege read permission;
- normalized, versioned evidence and relevant resource relationships;
- collection/provenance and regional-scope behavior;
- AWS error and missing-evidence behavior, with missing required evidence never becoming `PASS`;
- automated collector and integration tests that use controlled fakes rather than a real or
  intentionally vulnerable AWS account; and
- corresponding architecture, operations, API, security, and evidence-contract documentation.

Completion also requires targeted tests, the complete regression suite, relevant PostgreSQL and
container validation, independent review, a clean feature-branch history, CI success, and explicit
merge approval. At completion, move this file to `docs/exec-plans/completed/` and reconcile
`ROADMAP.md` without rewriting the plan's original predictions.
