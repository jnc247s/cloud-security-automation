# Sprint 5 — AWS Evidence Expansion

Status: **NEXT**

Canonical scope and project state: [ROADMAP.md](../../../ROADMAP.md)

## Planning state

The requirements below are approved roadmap scope. They are recorded here so implementation does
not depend on chat history. Sprint 5 has not begun: its reviewed slice sequence is documented for
planning, the roadmap remains `NEXT`, and no implementation work is authorized by this plan alone.

Before changing code, perform the repository preflight required by `AGENTS.md`: reconcile this
plan with the roadmap, inspect the protected contracts and all relevant callers and tests, resolve
the pre-Sprint 5 attention items, and turn these requirements into reviewable implementation
slices. Record material design decisions and obtain implementation approval before changing the
status to `IN PROGRESS`.

The requested missing Sprint 6 technical meanings are now canonical in the
[control catalog](../../controls/catalog.md), with their planned collection sources, permissions,
scope, normalized facts, relationships, and failure behavior in the
[Sprint 5 evidence-readiness matrix](../../controls/sprint-5-evidence-readiness.md). Review also
found that the accepted catalog reserves `S3-002` and `S3-004` by immutable title but does not
define S3-002's detailed approval/evidence aggregation or S3-004's sensitive-bucket classifier.
Because this task prohibits redefining existing S3 controls, those dependencies—and therefore
decisive `LOG-004` evidence—remain blocked pending a separately authorized S3 contract review.
These documentation contracts do not implement or enable a control and do not yet unblock the
complete Sprint 5 preflight.

The reviewed implementation order for a later Sprint 5 execution request is:

1. 5A — EC2 and EBS evidence;
2. 5B — VPC, subnet, Flow Log, and network evidence;
3. 5C — IAM account and policy evidence;
4. 5D — IAM Access Analyzer evidence;
5. 5E — S3 evidence expansion;
6. 5F — CloudTrail evidence expansion; and
7. 5G — typed relationships and Sprint-wide integration validation.

Sprint 5 remains `NEXT` until the remaining implementation preflight—including the generic typed
relationship representation—is reviewed and the roadmap start protocol is followed. This plan
alone does not authorize collectors, permissions, executable Sprint 6 rules, or a status change.

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
