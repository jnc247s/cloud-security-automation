# Sprint 5 — AWS Evidence Expansion

Status: **IN PROGRESS**

Current slice: **5B VPC, subnet, Flow Log, and network evidence — IN PROGRESS**

Accepted prerequisites: **5G shared relationship/source-outcome evidence foundation — FOUNDATION_READY_FOR_5A**;
**5A EC2 and EBS evidence — COMPLETE**

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
acceptance gates and merged in pull request 16. Slice 5B is now separately authorized and in
progress; later collector slices remain unstarted.

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
projection, authorization, and migration boundary. Sprint 5 is `IN PROGRESS`; accepted slice 5A
and in-progress slice 5B use that boundary without enabling Sprint 6 rules.

The S3-004 approval here is the versioned sensitive-bucket classifier and its evidence boundary,
not an invented final Sprint 6 KMS result policy. Sprint 5 preserves distinct absent, `AES256`,
AWS-managed KMS, customer-managed KMS, unavailable, and malformed facts. A later reviewed Sprint
6 contract must decide whether AWS-managed versus customer-managed KMS satisfies organization
policy and the result when `restricted_data_requires_kms` is false before registering the rule.
Those choices are not needed to collect the complete factual superset and are intentionally not
made in this plan.

The source-outcome contract is required because planned collectors have independent discovery and
enrichment calls. It retains valid facts and explicit source uncertainty without treating a
collector's `PARTIAL` rollup as permission to pass. Current Sprint 0--4 collectors remain
all-or-nothing; source-level runtime and persistence integration belongs to the applicable Sprint
5 slices and must be atomic. The 5A EC2/EBS producer was the first such integration; the 5B
network producers now use the same boundary while undergoing acceptance. No Sprint 6 rule
consumes either slice's outcomes yet.

The reviewed implementation order uses 5G as a foundation-and-closure bookend. This is the
dependency-driven exception to the earlier recommended collector-first order: 5C must emit
AWS-managed IAM policies with owner `aws`, and several slices must emit relationships and
source-level outcomes, but the accepted persistence boundary currently permits snapshots only
when resource owner equals scan account. Implementing a producer before the controlled owner and
graph boundary would either lose evidence or force that slice to invent a representation.

1. **FOUNDATION_READY_FOR_5A — 5G foundation** — the generic source-outcome/relationship
   persistence and projections atomically replace the same-account Python and database-trigger
   assumptions with the closed collection-account/resource-owner admission contract in ADR 0001;
2. **COMPLETE — 5A** — EC2 and EBS evidence;
3. **IN PROGRESS — 5B** — VPC, subnet, Flow Log, and network evidence;
4. 5C — IAM account and policy evidence;
5. 5D — IAM Access Analyzer evidence;
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
`FOUNDATION_READY_FOR_5A`, 5A accepted on `main`, and the separately authorized 5B slice now in
progress. This does not authorize executable Sprint 6 rules, remediation, or later-sprint work.

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

## Current 5B implementation state

The 5B implementation starts from the accepted 5A merge at `main` commit
`5fccdf9f78ea35ead9b40ffe5a6e6367ef110e8d`. Its code and tests are present on the scoped feature
branch and are undergoing the slice acceptance gates; this plan does not mark 5B complete before
validation, independent review, approval, and merge.

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
- The current branch supplies the factual inputs for NET-003 through NET-006 and the VPC, subnet,
  security-group, and Flow Log tag inputs for GOV-001. NET-003 through NET-006 remain unregistered
  Sprint 6 rules, and their planned profile fields remain deferred to the reviewed Sprint 6
  profile transition.
- This slice adds no migration, service-specific API route, executable network control, profile
  registration, finding policy, AWS write permission, or 5C--5F behavior.

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
