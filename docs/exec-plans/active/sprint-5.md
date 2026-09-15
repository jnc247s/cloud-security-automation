# Sprint 5 — AWS Evidence Expansion

Status: **NEXT**

Canonical scope and project state: [ROADMAP.md](../../../ROADMAP.md)

## Planning state

The requirements below are approved roadmap scope. They are recorded here so implementation does
not depend on chat history. Sprint 5 has not begun: its reviewed slice sequence is documented for
planning, the roadmap remains `NEXT`, and no implementation work is authorized by this plan alone.

Before changing code, perform the repository preflight required by `AGENTS.md`: reconcile this
plan with the roadmap, inspect the protected contracts and all relevant callers and tests, and
triage every pre-Sprint 5 attention item as either resolved before the sprint or explicitly
retained within an approved boundary. Then turn these requirements into reviewable implementation
slices, record material design decisions, and obtain implementation approval before changing the
status to `IN PROGRESS`.

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

Their standalone schemas and contract tests do not implement an AWS collector, executable rule,
profile registration, database table, API route, or remediation behavior. Sprint 5 remains
`NEXT`; starting slice 5A still requires the roadmap start protocol and explicit implementation
authorization.

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
5 slices and must be atomic.

The reviewed implementation order uses 5G as a foundation-and-closure bookend. This is the
dependency-driven exception to the earlier recommended collector-first order: 5C must emit
AWS-managed IAM policies with owner `aws`, and several slices must emit relationships and
source-level outcomes, but the accepted persistence boundary currently permits snapshots only
when resource owner equals scan account. Implementing a producer before the controlled owner and
graph boundary would either lose evidence or force that slice to invent a representation.

1. 5G foundation — add the generic source-outcome/relationship persistence and projections, and
   atomically replace the same-account Python and database-trigger assumptions with the closed
   collection-account/resource-owner admission contract in ADR 0001;
2. 5A — EC2 and EBS evidence;
3. 5B — VPC, subnet, Flow Log, and network evidence;
4. 5C — IAM account and policy evidence;
5. 5D — IAM Access Analyzer evidence;
6. 5E — S3 evidence expansion;
7. 5F — CloudTrail evidence expansion; and
8. 5G closure — Sprint-wide relationship, persistence, API, acceptance, and performance
   validation.

The foundational 5G change is not permission for an empty table or a relaxed account check. Its
migration, domain integration, writer, reader, API projection, authorization behavior, and
PostgreSQL/SQLite upgrade/downgrade tests are one reviewable atomic slice. Only then may evidence
producers depend on it.

Sprint 5 remains `NEXT` until the roadmap start protocol is followed. This plan alone does not
authorize collectors, permissions, executable Sprint 6 rules, or a status change.

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
