# Sprint 5 — AWS Evidence Expansion

Status: **IN PROGRESS**

Current slice: **5D IAM Access Analyzer evidence — IN PROGRESS**

Accepted prerequisites: **5G shared relationship/source-outcome evidence foundation — FOUNDATION_READY_FOR_5A**;
**5A EC2 and EBS evidence — COMPLETE**; **5B VPC, subnet, Flow Log, and network evidence — COMPLETE**;
**5C IAM account and IAM policy evidence — COMPLETE**

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
now separately authorized and in progress; later collector slices remain unstarted.

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
through 5C use that boundary, and current slice 5D must use it without enabling Sprint 6 rules.

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
5. **IN PROGRESS — 5D** — IAM Access Analyzer evidence;
6. 5E — S3 evidence expansion;
7. 5F — CloudTrail evidence expansion; and
8. 5G closure — Sprint-wide relationship, persistence, API, acceptance, and performance
   validation.

The foundational 5G change is not permission for an empty table or a relaxed account check. Its
migration, domain integration, writer, reader, API projection, authorization behavior, and
PostgreSQL/SQLite upgrade/downgrade tests are one reviewable atomic slice. That gate is now
satisfied; later evidence producers may depend on the accepted boundary only when their own slice
is separately authorized.

Sprint 5 remains `IN PROGRESS`, with the shared 5G foundation accepted as
`FOUNDATION_READY_FOR_5A`, 5A through 5C accepted on `main`, and the separately authorized 5D
slice now in progress. This does not authorize executable Sprint 6 rules, remediation, or later-
sprint work.

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

## Current 5D implementation state

The current feature branch implements the authorized 5D boundary for review against the accepted
5C baseline at `819f9ba3b26490ca23c69a6665b1baf9d7948975`. It is not accepted or complete until
validation, independent review, CI, approval, and merge succeed.

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
  disposable-PostgreSQL acceptance coverage belongs to this branch. No test contacts live AWS.
- `S3-002` remains `CONTRACT_READY` and non-decisive until direct 5E S3 evidence is separately
  accepted. This branch does not implement 5E, 5F, a Sprint 6 rule, remediation, dashboard,
  production deployment, or AI behavior.

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
