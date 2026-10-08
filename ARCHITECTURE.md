# Architecture

This document describes accepted Sprints 0--7 and the accepted Sprint 8A/8B1 extensions
below. The accepted baseline is `main` commit `0c6005827ae765fe2b2669e4f503af6ca58cdc15`
(8B1 admission PR #55; exact-commit independent review, both final-head CI runs and
merged-main CI 37726113041), after the Sprint 5
evidence expansion and all Sprint 6 controls. 6H added acceptance tests and documentation,
not application behavior. 7A adds exact-scan READ reporting; independent review and merged-main
CI passed. 7B's opt-in client/session boundary is accepted with green merged-main CI;
7C's exact-scan investigation and client-only 7D NIST hierarchy are accepted with green main CI.
7E whole-sprint acceptance is COMPLETE with exact-head independent review and green main CI;
it changes no application runtime architecture. Its bounded Firefox test-launch configuration
restores normal site isolation without weakening application headers or assertions.
The [acceptance matrix](docs/sprint-7e-acceptance.md) records offline evidence and explicit limits.
The separate documentary closeout also passed exact-head review, both final-head CI runs,
guarded ordinary merge and final merged-main CI. All 7A--7E states are COMPLETE. Current Sprint 8
scope/status is owned by [ROADMAP](ROADMAP.md) and the [active plan](docs/exec-plans/active/sprint-8.md).
Production setup remains unimplemented.
All Sprint 6
controls remain opt-in; the five-control default catalog is unchanged.

Accepted 6G adds GOV-001 in opt-in `0.13.0` and closed execution/proof `1.10.0`.
All 11 exact governed families reuse existing discovery/admission/tag sources and the shared
engine/persistence result computation. A complete governed-population gate prevents failed-family
enumeration from disappearing behind other successful targets. Ungoverned targets are N/A;
complete empty populations reuse the existing global IAM account assessment-only namespace.
The new `governance_tags_v1` target selector also requires that account coverage result when only
ungoverned canonical resources are observed, so failed governed discovery remains insufficient.
The shared target matrix binds the exact retained profile. Reader-private sealed family indexes
and population caches avoid repeated inventory scans without caching target-specific tag checks.
Lossless UTF-8 hex tag pairs preserve whitespace without changing the accepted assessment
envelope; original tags remain in cited sources/snapshots. The explicitly approved additive
category `governance` and migration `20261001_0006` change only the category CHECK, preserving
history, foreign keys, exact triggers and caller transaction ownership. No collector, permission,
deployment or new route. See [6G metadata](docs/controls/sprint-6g-metadata.md).

Accepted 6F.2 adds LOG-004 in opt-in `0.12.0` with closed execution/proof `1.9.0` and only
the S3-002 prerequisite. The internal context-aware adapter preserves `assess(snapshot, profile)`
for existing rules; only enabled prerequisites run and final results retain stable ordering.
The invocation-local read-only context contains identity/profile/catalog/inventory/source/result-
validated prerequisites. Persistence independently constructs it before SQL regardless of tuple
order. Composition seals only its revalidated reader's private resource JSON and binds the
inventory digest once per reader, without mutating caller resources or changing legacy readers.
Exact trail discovery/configuration, one resolved GetTrail-provenance edge and complete
CloudTrail/S3 collector outcomes bind the destination. No historical result lookup, duplicate
exposure evaluator, workflow engine, collector, permission, public API or migration is added.
All acceptance, review and merged-main gates passed; see [6F.2 metadata](docs/controls/sprint-6f2-metadata.md).

## Sprint 6A assessment integration

The [assessment foundation](docs/assessment-foundation.md) adds explicit legacy/schema-2 policy
dispatch, exact catalog/registry selection, immutable policy-artifact storage, and nullable
version-bound execution metadata. Restart verifies the persisted catalog and complete profile
before AWS work; it never substitutes current deployment policy. Migration `20260924_0004` is
additive and preserves legacy definitions/checksums.

Extended definitions use a shared pure target enumerator and evidence reader at engine and
persistence boundaries. Regional account settings are assessment-only `ec2/aws_account` targets,
not collector resources or graph endpoints. Exact resource families retain observed identities.
All declared required sources and edges must be complete; legacy whole-collector guards and
full-scope finding resolution are unchanged. This adds no control, collector, permission, or
dependency scheduler. The foundation passed its validation, independent-review, and merged-main
gates before later control slices were accepted.

## Sprint 6B.1 opt-in IAM controls

Catalog `0.3.0` adds IAM-002/003/005/006 over retained IAM evidence, without collector, AWS
permission, API route, or schema changes. The original `0.2.1` catalog remains the default and
recoverable by exact identity. Versioned IAM user/key proofs establish complete enumeration,
same-scan endpoint/provenance binding, and active-key usage facts before evaluation or persistence.
Thresholds use retained observation time, never wall-clock time. Root flags remain global account
assessments. See [assessment foundation](docs/assessment-foundation.md#6b1-iam-evidence-joins)
and [approved control metadata](docs/controls/sprint-6b1-metadata.md). Source sufficiency does not
weaken whole-scan finding-resolution requirements; framework metadata never controls results.

## System context

Accepted 6F.1 adds LOG-002/003 in opt-in catalog `0.11.0`, closed execution/proof `1.8.0`.
Shared pure evidence/result validation binds complete admitted trail discovery, exact owner/home
Region and the named required sources; coverage is account-scoped, integrity per-trail.
New-schema projection/proof comparisons preserve exact JSON scalar types, including booleans;
historical schema comparison behavior is unchanged.
LOG-001, collectors, permissions and generic APIs are unchanged. Acceptance exposed a
pre-existing mismatch between allowed unresolved regional relationships and the persisted
scope/Region constraint. The separately authorized additive migration `20261001_0005`
allows unknown Regions only for unresolved references, preserving complete-identity rules,
original triggers and retained facts. Pre-DDL downgrade guards serialize writers and block
incompatible history. Earlier migrations and collector/API behavior are unchanged; see
[6F.1 metadata](docs/controls/sprint-6f1-metadata.md).

Approved 6E.3 adds S3-004 in opt-in catalog `0.10.0`, closed proof `1.7.0`.
The unchanged classifier runs before conditional encryption/KMS requirements. Exact referenced
DescribeKey/ENCRYPTED_WITH proofs preserve key ownership and home Region; implicit AWS-managed
defaults never fabricate key resources. Engine and persistence recompute applicability,
classification matches and result against immutable policy/profile and same-scan inputs.
Existing policy storage/recovery and generic APIs are reused without migration, collector,
permission or authentication changes. See [6E.3 metadata](docs/controls/sprint-6e3-metadata.md).

Approved 6E.2 adds S3-002 only in opt-in catalog `0.9.0`. Closed proof schema `1.6.0`
retains direct policy/ACL channels, exact bucket/home-Region source bindings, effective
neutralizers and immutable approval/profile checksums. Engine and persistence recompute the
same result; a known unapproved channel outranks another unknown channel, while disappearance
invalidates the bucket snapshot. No collector, permission, migration, API or auth change.
See [6E.2 metadata](docs/controls/sprint-6e2-metadata.md).

Approved 6E.1 adds opt-in S3-001/003 in catalog `0.8.0`, evaluator `1.0.0`. Closed execution
schema `1.5.0` binds global bucket discovery, exact bucket-home Region/owner admission and
the required account/bucket configuration source IDs, states and artifact digests. BPA combines
each flag across account and bucket, retaining unavailable outcomes without treating them as
false. HTTPS evaluation uses only the bounded explicit-Deny contract. Engine and persistence
recompute the same result; older evidence strategies remain unchanged. No collector, AWS
permission, migration, service, route or authentication change is introduced. See
[6E.1 contract](docs/controls/sprint-6e1-metadata.md). Its historical release remains unchanged.

Approved 6D.1 adds opt-in NET-003/004/005 in catalog `0.6.0`. Execution schema `1.3.0`
binds complete security-group/VPC discovery, exact admitted configuration and the same-scan
`in_vpc` relationship. The engine and persistence use the same proof and pure truth table,
with the exact profile passed for empty-port applicability. Old execution schemas and NET-001/002
are unchanged. No collector, permission, migration, API or authentication change is introduced.
See [6D.1 metadata](docs/controls/sprint-6d1-metadata.md).

Approved 6D.2 adds opt-in NET-006 in catalog `0.7.0`. Bounded execution schema `1.4.0`
proves complete VPC and Flow Log populations, exact source facts, owner/Region identity and
zero-or-more `HAS_FLOW_LOG` membership. No logs is a proved result, not a waived required edge.
Missing matching edges are insufficient. External-owner VPC coverage is insufficient because
Flow Log discovery is collection-account scoped. Earlier strategies and default `0.2.1` remain
unchanged. See [6D.2 metadata](docs/controls/sprint-6d2-metadata.md).

Approved 6C adds EC2-001 through EC2-004 in opt-in catalog `0.5.0`. It reuses execution schema
`1.0.0`, with shared EC2 discovery/admission/fact and applicability checks at engine and storage
boundaries. The public-address allowlist uses the existing stable resource UUID, not a bare AWS
instance ID. Regional default encryption is an assessment-only account target; its API/history
identity remains distinct across Regions. No collector, route, authentication or migration changes
are introduced. Old catalogs and defaults remain exact; see [6C metadata](docs/controls/sprint-6c-metadata.md).

The 6B.2 permissions-policy evaluator uses execution schema `1.2.0`: complete global discovery
and same-scan owner/usage proofs, one target per managed default-version or inline document,
and explicit insufficient parent targets when managed versions are unavailable. It retains
boundary-only context without computing effective permissions. The shared engine/persistence
reader binds document digests, immutable snapshot IDs and source/edge provenance. See
[policy evidence joins](docs/assessment-foundation.md#6b2-iam-policy-document-joins).
No collector, AWS permission, database migration, route, or authentication change is introduced.

```text
AWS environment
    -> standard AWS credential chain and STS identity
    -> fact-only boto3 collectors
    -> explicit AWS response-boundary validation
    -> normalized InventorySnapshot
       -> optional versioned evidence graph
          (declared sources, normalized artifacts, source outcomes, relationship observations)
    -> deterministic rules + versioned AssessmentProfile
    -> ControlAssessment candidates + structured EvidenceArtifacts
    -> transactional PostgreSQL persistence
    -> query and scan services
    -> authentication + capability authorization
    -> FastAPI /api/v1
    -> trusted CLI, dashboard, integration, or future tool adapter

versioned NIST CSF catalog
    -> ControlFrameworkMapping metadata
    -> reporting context only
```

The NIST path is parallel to technical evaluation. A framework mapping cannot set severity or
change a technical result. The application performs NIST CSF 2.0-aligned AWS technical security
assessment; it does not certify organization-wide NIST compliance.

## Component boundaries

| Component | Responsibility | Must not do |
| --- | --- | --- |
| `app/aws/` | Lazy boto3 session/client access, timeouts/retries, cached STS identity | Store static credentials or make security decisions |
| `app/collectors/` | Collect and normalize AWS facts | Assign severity, PASS/FAIL, NIST status, findings, or remediation |
| `InventoryService` | Run independent collectors and build a deterministic snapshot | Persist or evaluate controls |
| `app/rules/` | Evaluate normalized evidence against technical contracts | Call AWS, persist data, or use framework mappings as policy |
| `app/assessment/` | Four-state result, evidence, profile, control, framework, source-outcome, and relationship contracts | Claim full framework compliance or turn collection state into policy |
| `app/database/` and `app/models/` | Validate and persist versioned history and the optional evidence graph in caller-owned transactions | Call AWS or hide partial scope |
| `app/services/` | Own query projections, generic evidence-graph reads, and scan transaction/orchestration boundaries | Put HTTP concerns into domain logic |
| `app/security/` | Normalize a verified `Principal` and enforce capability policy | Issue tokens or store passwords |
| `app/api/` | Validate HTTP input and delegate to services | Contain core scanning or persistence logic |

Collector validation is deliberately small and explicit. Shared helpers validate response
mappings, lists, required non-empty strings, booleans, integers, timestamps, and tags; each
collector validates its own promoted and decision-relevant nested facts before constructing a
`NormalizedResource`. Required identities are never coerced with `str(...)`. Exact repeated
resource records from pagination are collected once, while conflicting records for one stable
identity are treated as ambiguous evidence.

The failure boundary preserves three distinct categories:

- botocore and AWS service failures are operational collection failures (`FAILED`);
- malformed required AWS evidence raises a sanitized `CollectorEvidenceError` and marks only that
  collector `PARTIAL`; and
- application defects are not caught as evidence errors and remain visible to executor
  observability and tests.

The Sprint 0--4 collector result boundary remains all-or-nothing per legacy collector. A malformed
item discards that collector's in-memory results, independent collectors continue, and
deterministic assessment receives incomplete coverage. The graph-aware 5A EC2/EBS producer uses a
narrower source boundary: independently paginated instance and volume discovery plus the two EBS
default-setting calls each retain a typed outcome and sanitized artifact. The 5B implementation
uses the same result-sensitive pattern while keeping `security_groups` independent from
`vpc_network_evidence`; a VPC, subnet, or Flow Log failure therefore cannot erase independently
admissible same-account security-group evidence used by the accepted NET-001/NET-002 rules. The
exception is an external-owner group whose mandatory resolved-edge admission proof depends on the
unavailable VPC source; that group is pruned and `security_groups` becomes `PARTIAL`. Valid sibling
resources remain available when another item or source is incomplete, while each collector rollup remains
`PARTIAL` or `FAILED` as appropriate. Malformed STS caller identity still has its own sanitized
identity-evidence failure because a snapshot cannot be attributed safely without an account
identity.

The shared Sprint 5 foundation validates and persists declared per-source contracts,
normalized source artifacts, source outcomes, and resource relationships as one optional
`EvidenceGraph` attached to an inventory snapshot. Every declaration has exactly one outcome and
an exact reference to a digest-bound normalized artifact; every relationship is backed by exactly
one `PRESENT` outcome. The accepted 5A producer is the first AWS collector to populate that
boundary; 5B extends it to security groups, VPCs, subnets, and Flow Logs without changing the
generic persistence or API model. Remaining Sprint 0--4 collectors retain the all-or-nothing
behavior above and emit no graph fragment. Accepted opt-in Sprint 6 rules consume graph evidence
only through their closed, versioned source-proof strategies.

## Scan execution

```text
POST /api/v1/scans (EXECUTE)
    -> ScanService validates and persists the configured immutable profile version
    -> creates RUNNING scan referencing that exact profile + SCAN_STARTED audit event
    -> transaction commits durable scan ID
    -> ScanExecutor.submit(scan_id)
    -> HTTP 202 response

InProcessScanExecutor worker
    -> reload RUNNING scan
    -> load and checksum-verify the exact persisted profile referenced by that scan
    -> build region-bound AWS provider
    -> InventoryService.collect(scan_id)
    -> RuleEngine.assess(snapshot, profile)
    -> build exact scope manifest
    -> persist_scan_result, including an optional evidence graph, in one transaction
    -> COMPLETED, PARTIAL, or FAILED + audit

unhandled execution failure
    -> fail_pending_scan in a separate transaction
    -> FAILED + sanitized failure metadata + audit
```

The accepted executor is a replaceable protocol backed by a two-worker, 32-outstanding in-process
thread pool. The production application resubmits persisted `RUNNING` scans once at startup and
drains a bounded backlog. It waits for accepted work during graceful shutdown. It is not a
distributed queue: run one API process, and replace the adapter before horizontal or multi-process
execution.

Configuration selects the profile used only when a new scan is created. The executor never
reconstructs policy for a pending scan from current environment settings and never selects a
"latest" profile. Startup recovery therefore evaluates a retained `RUNNING` scan with the exact
policy accepted at creation, even when a deployment has since rolled forward to another profile
version. Missing, malformed, or checksum-inconsistent stored provenance fails closed before AWS
collection.

The executor scans one requested Region with account-global discovery and source-proven
supplemental/home-Region collection as described below. Full multi-Region orchestration remains
outside the accepted request model.

## Persistence and history

`Resource` is deterministic stable identity. `ResourceSnapshot` is immutable state observed in one
scan. Assessments, evidence, finding occurrences, exact profile/control/framework versions, scan
scope, collection outcomes, source contracts, normalized source artifacts, source outcomes,
relationship observations, exceptions, and audit events are retained separately. Repeated failed
assessments reuse a deterministic finding fingerprint and append occurrences. Only an explicit
later `PASS` from complete coverage can resolve a finding; missing resources, partial scans,
`NOT_APPLICABLE`, and `INSUFFICIENT_EVIDENCE` cannot.

The database transaction boundary never spans AWS calls. Alembic owns schema evolution; startup
does not call `metadata.create_all()`. Revisions are linear:

```text
20260903_0001  canonical assessment history
    -> 20260904_0002  pending scan before AWS identity/inventory
    -> 20260915_0003  shared source-outcome and relationship evidence graph
    -> 20260924_0004  immutable extended policy and execution-contract storage
    -> 20261001_0005  unresolved regional relationship preservation
    -> 20261001_0006  additive governance category (accepted predecessor)
    -> 20261006_0007  append-only remediation authority (accepted predecessor)
    -> 20261007_0008  execution admission and journal (accepted-main head)
    -> 20261008_0009  private worker coordination/versioned journal (8B2 candidate)
```

The established revisions remain unchanged. The Alembic execution environment preflights any
downgrade path that crosses `20260915_0003` or `20260904_0002` before running a migration step.
It blocks a `0003` downgrade when any graph/source-manifest history or snapshot admitted only by
the new owner/Region provenance contract exists. It blocks a `0002` downgrade when retained scan
history cannot satisfy the older identity/digest `NOT NULL` contract. PostgreSQL excludes
concurrent writers while making either compatibility decision and applying the corresponding
DDL; offline downgrade generation across either boundary fails closed. See `docs/persistence.md`
and `docs/operations/known-limitations.md` for the complete model and operator runbooks.

Assessment-profile roll-forward uses the existing immutable profile table and scan foreign-key
contract; it requires no new migration. A `(profile_id, version)` pair names exactly one policy
definition. New content requires an operator-selected new numeric version, while old profiles,
scans, and assessments remain unchanged.

## Sprint 5 evidence graph and 5A--5F producers

The bounded 5G closure adds operation-local target and provenance indexes, not a new graph
representation or cache. Canonical identities, owner/scope/Region ambiguity, exact provenance
uniqueness, full reconstruction validation, and transactional persistence remain unchanged.
Deterministic operation-count and PostgreSQL query-count tests guard these generic paths.

The accepted 5G foundation implements the shared contracts required before Sprint 5 collectors may
emit graph evidence:

- A graph-enabled `InventorySnapshot` carries one versioned, immutable `EvidenceGraph` bound to
  its scan ID, verified collection account, and collection time. Its source contracts form an
  exact declared-source manifest whose schema version and SHA-256 checksum are recorded on the
  scan scope. Graphless Sprint 0--4 snapshots remain compatible and retain null manifest fields.
- Each declared source has one strict discovery or enrichment subject, one result-sensitive
  outcome, and one normalized, sanitized JSON artifact whose content digest matches the outcome.
  Missing declarations, outcomes, or artifacts; unreferenced artifacts; conflicting duplicates;
  and cross-scan provenance are rejected.
- [Generic resource relationships](docs/design-decisions/0001-generic-resource-relationships.md)
  are persisted as append-only, directional, per-scan observations with a stable logical
  relationship ID, explicit endpoint scope and Region, typed resolution, and source provenance.
  The source always names an observed snapshot. A `RESOLVED` target names its exact same-scan
  snapshot; an incomplete target remains a deterministic unresolved reference and never creates
  a placeholder resource.
- Four append-only tables—`scan_source_contracts`, `source_evidence_artifacts`,
  `source_evidence_outcomes`, and `resource_relationship_observations`—are written and read as
  part of the existing scan transaction. Database guards require a `RUNNING` parent, enforce
  provenance, prevent graph updates/deletes, and reject terminalization of an incomplete graph.
- Collection account and resource-owner identity remain separate. Same-account resources remain
  the default. The `aws` owner is admitted only for controlled AWS-managed IAM policy types with
  identity-authoritative `PRESENT` source evidence. A different 12-digit owner additionally
  requires identity-authoritative evidence and a same-scan resolved relationship. Supplemental
  Regions require explicit source-contract proof. None of these cases expands API authorization
  or scan scope.
- `EvidenceGraphService` and authenticated generic read routes expose source outcomes (with the
  normalized artifact only on detail) and relationship observations without service-specific
  traversal logic or raw provider failures.

The 5A `EC2EbsCollector` now emits the first production graph fragment. Once per requested Region,
it independently paginates `DescribeInstances` and `DescribeVolumes` and calls
`GetEbsEncryptionByDefault` and `GetEbsDefaultKmsKeyId`. It normalizes top-level `ec2_instance`
and `ebs_volume` resources, complete tags, addresses, instance metadata settings, attachment facts,
encryption state, and Regional EBS defaults. The defaults remain account-and-Region source
observations rather than fabricated resources.

Each instance and volume has identity-authoritative enrichment evidence in addition to its
discovery outcome. Instance observations emit directional references to security groups, EBS
volumes, subnets, and VPCs. A volume target can resolve against the independently observed
same-scan EBS resource. `DescribeInstances` does not prove the owner account of a referenced
security group, subnet, or VPC, so those references remain typed
`TARGET_IDENTITY_INCOMPLETE` at the 5A collector boundary; 5A never substitutes the collection
account as an unverified owner.

The 5B implementation keeps the established `security_groups` collector outcome separate from a
new `vpc_network_evidence` outcome. Across those boundaries it independently paginates exactly
four Regional APIs: `DescribeSecurityGroups`, `DescribeVpcs`, `DescribeSubnets`, and
`DescribeFlowLogs`. Security groups retain normalized ingress/egress facts, exact group name, the
derived default-group indicator, tags, and their VPC reference. `VPCNetworkCollector`
normalizes top-level `vpc`, `subnet`, and `vpc_flow_log` resources, including VPC/subnet tags,
subnet public-IP auto-assignment, and Flow Log status, traffic type, and destination context.

Security-group, VPC, and subnet ownership comes only from the validated AWS `OwnerId`; it is not
copied from the collection account. Their enrichment declarations record the corresponding
identity-authoritative owner mode. During graph assembly, a partial 5A target may become
`RESOLVED` only when exactly one resource identity matches every supplied reference component and
that resource has a matching same-scan `PRESENT`, identity-authoritative contract/outcome pair.
No proof or multiple owner candidates leaves the original reference
`TARGET_IDENTITY_INCOMPLETE`. This refinement supplies missing endpoint identity; it never infers
an edge whose source observation was absent or incomplete.

Graph assembly then applies the accepted exceptional-owner admission rule. An external-owner
resource that participates in no exact `RESOLVED` same-scan edge is excluded together with its
resource-scoped enrichment records. The complete discovery artifact preserves every AWS-observed
ID and records the canonical rejected identity in `unadmitted_resources` with
`admission_complete = false`; its successful AWS source outcome remains `PRESENT`. The shared
rollup derives the originating collector's `PARTIAL` state from source outcomes plus this
digest-bound admission gap. Same-account siblings and independent collector fragments remain
available, so an unadmitted external observation cannot abort the entire scan or be misread by
NET-001/NET-002 as complete coverage.

5B emits security group -> VPC, VPC -> subnet, and VPC -> Flow Log observations. A Flow Log edge
exists only when its exact `ResourceId` matches a collected VPC in the same account and Region;
subnet, network-interface, and transit-gateway Flow Logs remain collected facts but cannot satisfy
that VPC-scoped relationship. The existing generic graph, transactional persistence, and
authenticated read APIs require no service-specific table or route.

The accepted 5A and 5B producers add only approved read actions and policy-neutral evidence. They
do not register `EC2-001` through `EC2-004` or `NET-003` through `NET-006`, change assessment-
profile policy, or make any Sprint 6 rule executable. Sprint 5 is `COMPLETE`.

The accepted 5C implementation preserves the established `iam_users` direct-collection contract
and embedded MFA/access-key facts while its scan path emits account-global evidence graph
fragments. A separate `iam_account_evidence` collector records strictly validated root access-key
and root-MFA presence flags so account-summary failure cannot erase otherwise valid user
evidence. The IAM graph normalizes users, groups, roles, MFA devices, access keys, customer-managed
and referenced AWS-managed policies, default policy versions, inline policies, permissions
boundaries, tags, trust policy, and their directional relationships. Local policies are discovered
with `Scope=Local`; AWS-managed policies are fetched only when an attachment or boundary references
them. Policy documents are strictly decoded and preserved as normalized facts, never interpreted
as a complete authorization decision. Collection account identity remains distinct from policy
ownership, and the controlled `aws` owner is used only for validated AWS-managed policy resources.
The slice reuses generic persistence and authenticated read APIs, adds no migration or
service-specific route, and registers no Sprint 6 rule.

The accepted 5D implementation adds one fact-only `access_analyzer_evidence` producer after S3
inventory. It scans the requested Region and the sorted unique bucket-home Regions proven by
same-scan normalized S3 resources, while every other unrequested Regional discovery remains
rejected. Complete S3 discovery is part of Analyzer coverage: incomplete S3 collection retains
valid requested-Region facts but makes the Analyzer rollup incomplete. Dynamic per-Region and
per-analyzer source manifests preserve `ListAnalyzers`, filtered `ListFindingsV2`, and fully
paginated `GetFindingV2` evidence with sanitized result-sensitive outcomes.

Each discovered S3 external-access finding is a Regional `access_analyzer_finding` resource owned
by the verified collection account and identified by a collision-safe analyzer-ARN/finding-ID
composite. Analyzer identity, the finding's reported `resourceOwnerAccount`, and collection
account stay distinct. A finding emits a canonical `references_resource` edge to the reported S3
bucket; only an exact same-scan bucket resolves, while other complete identities remain typed
unresolved references. The implementation reuses generic persistence and authenticated reads,
adds no schema or service-specific route, and does not interpret Analyzer evidence as an S3-002
result.

The accepted 5E implementation adds a shared per-scan S3 bundle projected through the
accepted `s3_buckets` collector and a new graph-aware `s3_evidence` collector. One account-global
enumeration and account Block Public Access call feed independent authoritative bucket-location,
tag, bucket Block Public Access, policy/status, ACL, versioning, encryption, and ownership-control
observations in each bucket's home Region. The legacy projection retains its existing
configuration and `S3-900` completeness contract; unrelated 5E source failures affect only the
new graph-aware rollup.

Explicit KMS references are looked up once per `(Region, supplied reference)`. A `kms_key`
resource exists only after `DescribeKey` proves its returned canonical ARN, 12-digit owner,
partition, Region, key ID, and manager. The bucket-to-key `encrypted_with` edge carries encryption
source provenance; unavailable lookups remain typed unresolved references. S3 bucket admission
outside the requested Region is bound to exact same-scan location evidence, and Access Analyzer
Region coverage consumes discovery/location completeness rather than unrelated S3 enrichment
status. Older pending scans are selected by their persisted service tuple and make no new 5E
calls. The slice adds no migration or service-specific route. All Sprint 6 rule execution remains
outside the fact-only collector; accepted opt-in 6E rules consume these facts through the shared
assessment engine.

The accepted 5F implementation preserves the accepted `cloudtrail_trails` projection and
adds a separate graph-aware `cloudtrail_evidence` projection over one shared per-scan collection
bundle. One paginated account `ListTrails` discovery, called without an unsupported shadow-trail
argument, is validated and deduplicated by stable ARN. Each admitted trail is enriched in its
validated home Region through independent identity, configuration, status, event-selector, and
batched tag sources. A new persisted `cloudtrail-evidence` intent marker selects this path without
changing accepted pending 5E scans.
“Account to trails” is a coverage association carried by the scan, source manifest, and discovery
outcome—not a generic resource edge or synthetic account resource.

The exact source families are `cloudtrail.trails.discovery`, `cloudtrail.trail.identity`,
`cloudtrail.trail.configuration`, `cloudtrail.trail.status`,
`cloudtrail.trail.event-selectors`, and `cloudtrail.trail.tags`. They preserve independent,
digest-bound outcomes so one selector or tag failure does not erase complete configuration or
status evidence.

New scan intent is exactly
`("access-analyzer", "cloudtrail", "cloudtrail-evidence", "ec2", "iam", "kms", "s3")`.
The marker is an execution version, not an AWS service or permission. The executor retains the
accepted 5E tuple without the marker as a separate path, so retained pending scans neither call
`GetEventSelectors` nor gain a CloudTrail source manifest.

Collection account identity remains distinct from the owner encoded by a validated trail ARN.
Member-visible organization trails retain management-account ownership and organization context;
they never imply organization-wide collection. An externally owned trail is admitted as a
top-level resource only through the existing exceptional-owner proof, otherwise its source
artifact is retained, both 5F resource projections omit it, and coverage remains incomplete.
The unchanged `LOG-001` rule therefore receives incomplete collection instead of a fabricated
same-account trail. Complete `GetTrail` evidence may emit the
accepted `delivers_to_bucket` and `encrypted_with` observations. S3 resolution uses exact
same-scan 5E bucket evidence; KMS resolution reuses an exact already-collected 5E key and 5F does
not add a second `DescribeKey` producer. All 5F sources produce normalized facts and provenance,
not assessment results. The implementation adds no schema, dependency, route, authentication
change, assessment-profile change, or Sprint 6 rule. It is accepted architecture on `main` at the
baseline above.

Two approved S3 policy artifacts remain separate from collection and drive only their bounded,
explicitly selected assessments:

- [S3-002 exposure aggregation](docs/controls/s3-002-exposure-aggregation.md) defines the
  deterministic policy/ACL/Block Public Access combination and its immutable,
  bucket-scoped approval artifact. Exact decisions bind account, bucket-home Region, ARN/name,
  and canonical stable resource ID rather than the account-less ARN alone. Opt-in catalog `0.9.0`
  evaluates it without making AWS calls from the rule.
- [S3-004 sensitive-bucket classification](docs/controls/s3-004-sensitive-bucket-classifier.md)
  defines a pure versioned classifier over exact full bucket identities, restricted name
  patterns, and exact tags. It assigns applicability only—not compliance, severity, or framework
  status. Opt-in catalog `0.10.0` loads its exact artifact from the accepted 6A profile/registry,
  then conditionally evaluates retained encryption and referenced-KMS evidence.

The foundation preserves the collector/rule boundary defined by the
[result-sensitive source-outcome decision](docs/design-decisions/0002-result-sensitive-evidence-outcomes.md).
Sprint 5 collectors continue to collect only the versioned facts and provenance named by the
evidence-readiness matrix. Approved 6E.2 and 6E.3 rules apply the selected policy artifacts;
the authorized local LOG-004 composes that exact validated same-invocation S3-002 result.
Missing required facts and unresolved required edges remain `INSUFFICIENT_EVIDENCE`; neither a
policy artifact nor a relationship authorizes a fabricated resource, inferred AWS state, or
historical rewrite.

## Authentication and authorization

All `/api/v1` routes use HTTP bearer authentication. Production mode verifies a signed OIDC JWT
against configured JWKS, issuer, audience, expiration, subject, asymmetric algorithm allowlist,
and roles claim. Development mode accepts only the documented local marker and is rejected unless
`APP_ENV` explicitly names a local/development/test environment. Production configuration fails
closed unless OIDC is complete.

The normalized principal contains subject, issuer, and roles. Roles map to capabilities:

```text
VIEWER    -> READ
ANALYST   -> READ, PROPOSE
APPROVER  -> READ, PROPOSE, APPROVE
ADMIN     -> READ, PROPOSE, APPROVE, EXECUTE
```

Current read routes require `READ`; scan creation requires `EXECUTE`, so only `ADMIN` can start a
scan. Accepted 8A proposal creation requires `PROPOSE`; approval/rejection/revocation requires
`APPROVE`. No finding/exception mutation or remediation execution route exists. Authorization
remains control-plane-wide, not tenant/account-scoped; see `THREAT_MODEL.md`.

<a name="sprint-8a-remediation-authority--local-pending-acceptance"></a>

## Sprint 8A remediation authority — accepted

The proposal/approval foundation is accepted through PR #53 at
`691d8814c785feafc0d9d3b3b43d7d1af89542a0`, with exact-commit independent review, both final-head
CI runs and green exact main CI 37693245169. This is accepted code, not deployment or execution
authority. The active Sprint 8 plan retains historical receipts and the remaining slice gates.

The generic bearer API calls `RemediationService`, which reads accepted immutable history and
appends proposal, decision and idempotency records with paired audit events. It has no AWS,
credential-provider, scan-executor or dashboard mutation dependency. Proposal-only action metadata
permits only `aws.ec2.enable-ebs-encryption-by-default` version `1.0.0`, EC2-004, fixed false-to-true.
It does not change control evaluation, enable a profile, resolve a finding or alter an exception.

Immutable proposal content binds the exact occurrence, assessment, snapshot, policy/catalog/
control versions and checksums, source proofs, EBS setting and default KMS context. Creation needs
a completed explicit FAIL and an eligible OPEN/ACKNOWLEDGED finding without an active unexpired
exception. Approval revalidates those bindings, current governance and the 24-hour lifetime.
Any other target/control assessment at a later or equal observation time invalidates the proposal,
regardless of result; omission of that control alone does not invent an assessment or resolve it.
Approval history and derived stale/expiry reasons are separate, and GETs never update records.
Governance binds sorted append-only finding audit-event IDs as well as current disposition and
exception state. Returning to a prior status cannot restore authority, including equal-time
events. Pre-repair local proposals fail the tightened digest check without rewriting history.

Mutations require an idle session and reject an active caller transaction without ending it.
READ rejects pending caller inserts/updates/deletes before any query and suppresses autoflush
throughout traversal; clean caller-owned transactions remain open and usable.
They lock Resource, then Finding, then proposal on PostgreSQL; SQLite reserves
the writer. They do not hold a transaction across a network/AWS call or subsequently lock Scan.
Initial APPROVE/REJECT is unique and requires a different verified issuer/subject pair from the
proposer, including ADMIN. Any APPROVE principal can append one terminal revocation of an approval;
there is no withdrawal. Exact authorized retries return the original record, while conflicting
normalized input under the same identity/operation/key fails without partial writes. Database
history guards protect the new rows; migration downgrade refuses populated authority history
before any DDL. See [persistence](docs/persistence.md) for the privilege-boundary limitations.

The third distinct execution requester is implemented by accepted 8B1 below, not 8A.
The isolated worker/write identity, fresh live preconditions, crash recovery and exact-policy
read-only rescan remain later bounded slices. Stored approval is not permission to call AWS. See
[remediation operations](docs/operations/remediation.md).

<a name="sprint-8b1-execution-admission--approved-local-candidate-pending-acceptance"></a>

## Sprint 8B1 execution admission — accepted

The third-human bearer request now calls a separate `RemediationExecutionService`, composing
8A's retained authority/provenance checks without changing `ProposalView`, old service callers,
assessment/profile contracts or finding lifecycle. Admission requires current EXECUTE, distinct
verified proposer/approver/requester pairs, unrevoked exact approval, fresh retained eligibility
and explicit default-off account/Region scope. It records authority; no AWS handler or worker runs.

Accepted migration 0008 adds immutable execution requests and SHA-linked paired-audit journals,
a protected singleton admission guard, and retained unique target coordinates. Short transactions
lock the singleton before Resource → Finding → proposal and target reservation. At most one request
per proposal, one outstanding per target and 32 globally are admitted. Only no-dispatch QUEUED
requests can be terminally EXPIRED/BLOCKED and released; READ/replay only derives validity.
All future worker mutations must participate in the same guard order, with no transaction across
AWS calls. The five-minute grant is not an unknown-effect lease or proof of safe replay.

The API/operations/persistence owners define exact contracts. Admission remains disabled by
default. No write identity/configuration, worker startup, WRITE_INTENT, reconciliation/quarantine,
verification scan, BFF mutation or general scan-start UI exists in this slice. These are later
bounded Sprint 8 slices; acceptance authorizes no live or production operation.

## API boundary

### Sprint 8B2 isolated worker — implementation candidate, acceptance pending

The separately launched `python -m app.remediation.worker UUID` process is default off and is
not imported/started by API or scanner runtime. It handles only the approved EC2-004 enable-default
action; no generic dispatch, disabling, key changes or existing-volume conversion. Independent
`REMEDIATION_WORKER_*` environment settings never read `.env`, application/scanner settings or
caller-supplied AWS parameters. Enabled runtime requires its own PostgreSQL URL and one explicit
account/Region/expected IAM role. Initial credentials are exclusively ECS task-role temporary
credentials from the fixed relative metadata source, with no static/profile/host-role fallback.
Code separation is not proof that deployed tasks/identities are isolated; deployment remains gated.

`RemediationWorkerService` uses short admission-guard-first Resource → Finding → proposal → target
→ claim transactions. Credential construction, STS, EC2 and client shutdown occur only after those
transactions close. A private 30-second pre-intent claim can be reclaimed with a new fenced nonce;
the three-read budget persists across owners. Fresh complete boolean false and exact present/absent
KMS context must match approved intent. Authority and expiry are rechecked after lock waits.
WRITE_INTENT and paired service audit commit before one SDK write, with `total_max_attempts=1`.
Intent commit is the revocation cutoff; the original caller checks its grant immediately before
dispatch. No SQL/AWS compare-and-swap exists, and a pause after that final check remains a race.

Revision 0009 retains version-1 admission/event bytes and adds version-2 worker events plus private
claim coordinates. Post-intent owner/lease cannot be reclaimed. Crashes, missing/malformed responses
or ambiguous commits retain intent or sticky quarantine and the reservation/capacity. A conclusive
completed call with a durable acknowledgment releases only ordinary ownership; a late acknowledgment
never clears prior quarantine. Read-only recovery may observe after authority expiry; its global
three-poll, thirty-second window persists across restarts. Readback does not prove causation, key
usability, PASS, verification or finding resolution. 8C exact-policy rescan is not implemented here.
0009 downgrades require online compatibility checks before any DDL; worker history refuses rollback.
Current acceptance and later-slice gates remain owned by ROADMAP and the active plan.

Health and readiness remain unversioned and unauthenticated. The authenticated interface lives at
`/api/v1` and exposes scans, resources/history, assessments/evidence, source outcomes/artifacts,
resource-relationship observations, findings/occurrences, controls, frameworks/mappings, and
exceptions. Routes delegate to `ScanService`, `ResourceService`, `AssessmentService`,
`EvidenceGraphService`, `TechnicalPostureService` (accepted 7A),
`FindingService`, `ControlService`, `FrameworkService`, and
`ExceptionService`. `AuditService` exists as a service abstraction but has no public route. There
is no standalone source-contract or source-artifact list route; the source manifest is identified
on scan detail, and an artifact is returned only with its source-outcome detail.

`docs/api.md` is the authoritative interface document. Future clients must use services/API data,
not direct database access.

### Accepted 7A reporting foundation

The additive `GET /api/v1/scans/{scan_id}/technical-posture` READ projection uses one exact
retained scan/profile/catalog and its exact control/framework versions. Reporting models remain
separate from assessment enums. Four-state assessment counts, definition enablement/coverage
and assessed-snapshot owner/service/type/scope/Region groups are separate dimensions.
Partial/failed retained results remain facts; running or no-bundle scans have null counts,
not a safe zero-failure summary. Disabled/unassessed context never creates PASS or N/A.

Bulk assessment/target aggregates avoid payload hydration and per-assessment detail reads.
Mapped references roll up a unique control-version union within each exact framework, never
merge equal display keys across releases, and never create a NIST outcome result/score.
The service performs no AWS/evaluator/writer calls, including autoflush of caller-owned pending
objects. Ten SELECTs cover the tested available mapped-report path independent of target count;
unavailable reports omit assessment/target queries. No index/schema migration is introduced.

Scope/outcomes and sanitized failures reuse `ScanDetail`; normalized configurations, tags,
evidence payloads and mutable finding/exception state are excluded. Successful and report-specific
409 responses are no-store. Auth, defaults, accepted API fields, persistence and transaction
ownership remain unchanged. 7A itself introduced no browser client/login/session; the separately
approved 7B boundary below is accepted through PR #43. See the
[API contract](docs/api.md#exact-scan-technical-posture--7a)
and [completed plan](docs/exec-plans/completed/sprint-7.md) for validation and acceptance gates.
The [7B preflight](docs/sprint-7b-preflight.md) preserves the original browser/session proposal,
subsequently approved and accepted through PR #43. The `/api/v1` bearer contract stays unchanged.

### Accepted opt-in 7B browser shell

React/TypeScript/Vite assets are built in a pinned Node/pnpm stage and served by the existing
non-root FastAPI image, only with explicit `DASHBOARD_ENABLED`. Disabled startup and routes
remain unchanged. A dedicated `app/dashboard/` boundary performs provider-issued Code/S256-PKCE
login using Authlib, validates OIDC identity using joserfc/Authlib and reuses the established
bearer verifier for access-token signature/issuer/audience/expiry/roles. Tokens are not issued here.
The browser gets an opaque HttpOnly session ID, not provider tokens or a readable signed session.

A bounded thread-safe process-local store retains tokens and correlation state only in memory.
Every allowed read crosses `/api/v1` with that user's bearer token using an in-process ASGI HTTP
transport; it never invokes a service or database directly or overrides API dependencies.
7B exposes scan list/detail/posture GETs. The accepted 7C extension below adds explicit investigation
GETs through the same boundary. Dashboard cookies cannot authenticate `/api/v1`.
Logout/expiry revoke sessions, and late-read guards prevent returning or rendering a prior
selection/identity. Each browser read must also present the public `session_context` issued by
session bootstrap as `X-Dashboard-Context`; a shared cookie changing in another tab cannot
silently change a retained shell's principal. Same-origin BroadcastChannel messages contain
only this non-authorizing correlation value and invalidation type, never credentials or data.
They clear/unmount pending UI before logout completes and rebootstrap after a session change;
the server cookie, real bearer verifier and READ remain authoritative. No new model, migration,
capability, scan operation or AWS permission.
7B's original scope ends at scan selection, exact historical context and report availability, not
investigation/NIST hierarchy views. [Operations](docs/operations/dashboard.md) owns configuration;
security and threat owners document the new boundary and its one-process/IdP limitations.

### Accepted 7C investigation extension

The approved [preflight](docs/sprint-7c-preflight.md) adds typed, bounded assessment, exact resource
history, control, finding/exception and source-outcome/relationship reads to the existing BFF.
Every read re-enters the authenticated bearer API; no direct service/DB shortcut or generic proxy.
The additive optional `scan_id` UUID filter on resource history uses the existing unique
`(scan_id, resource_id)` index. Omitting it preserves ordering, pagination, schema and errors.
At 7C acceptance, migration head was `20261001_0006`; 7C introduced no migration, model,
catalog, profile or dependency changes. The current accepted head is recorded in the chain above.

The React client loads 25-row lists and details on demand. It binds historical assessment,
profile/control versions, definition checksum, evidence and snapshot IDs to the selected scan.
Stable identity/first-seen ARN never replace that snapshot's observed ARN/configuration.
Only known typed evidence source proofs produce links; artifact IDs/digests and directional
relationship endpoints are checked. Unresolved references remain references, not fabricated
resources. Payloads are text-only bounded disclosures with explicit truncation, not exports
or a full evidence-review claim. Account/global/external-owner targets retain their own scope.

Current findings/exceptions are a separate mutable view. Successful operational BFF responses
add `X-Dashboard-Read-At` UTC production-time metadata without changing the upstream JSON/status.
Eligibility uses explicit-offset timestamps and that server reference, never browser wall time;
missing/malformed times are unavailable, expiry at the reference is expired. Stored ACTIVE or
ACCEPTED_RISK does not rewrite historical FAIL. Mixed reads are not a frozen report.
Selection/identity changes clear details and abort or ignore outstanding responses.
NIST hierarchy rendering, aggregate scores, writes and later-sprint behavior are not included.

### 7D NIST context — accepted

The approved client-only extension consumes the same selected-scan posture response already
fetched by ScanShell. It adds no API/BFF allowlist entry, backend query, model, migration,
dependency, evaluator, mapping or default change. A separate runtime validator composes the
existing scan/scope guards without making valid investigation depend on supported NIST data.
It checks canonical UUID identities, retained catalog/profile enablement, safe four-state counts,
coverage, release-local parent levels, exact mapping provenance and unique direct/descendant
control-version unions. Unsupported or inconsistent nested context shows a separate error.

Release-local Maps are constructed once per report. Native disclosures mount selected hierarchy
and mapping detail on demand. Framework selection and expansion issue zero requests; there is
no latest-release fallback or cross-release reference-key merge. The unique headline is separate
from overlapping reference coverage, and unavailable counts remain null. Selection/refresh/session
replacement resets release/disclosure state through the existing abort/generation/unmount path.
Metadata is escaped text with bounded display truncation, never navigated. Source digests are
provenance, not client-side verification of absent source bytes. No NIST outcome result, full-Core
coverage claim, manual attestation, percentage or exception-based assessment rewrite is added.
See [7D preflight and acceptance](docs/sprint-7d-preflight.md). Local validation, exact-head
independent review, both final-head CI runs, guarded ordinary merge and merged-main CI passed.

## Runtime and deployment

Local Compose starts PostgreSQL 16, runs `alembic upgrade head` as a one-shot service, then starts
one API process. API and database ports bind to loopback by default. `/ready` verifies database
connectivity with `SELECT 1`; it does not verify migration head. Compose does not mount host AWS
credentials. Production TLS, ingress, identity provider, secret storage, database backups, and
workload-role configuration remain deployment responsibilities.

## Accepted limitations

- No tenant/account object authorization, request rate limiting, scan cancellation, timeout, or
  caller idempotency key.
- Startup-only pending-scan recovery and no multi-process claim/lease protocol.
- Scan audit attribution stores subject but not issuer, roles, or authorizing capability.
- Stable `Resource.arn` is first-seen data; each snapshot carries the actually observed ARN.
- Evidence-graph reads are filtered list/detail queries, not arbitrary or multi-hop graph
  traversal. The merged 5A through 5F producers emit graph records.
- The accepted opt-in 7B/7C/7D shell provides read-only exact-scan investigation and retained
  NIST mapped-subset context. Whole-Sprint-7 acceptance is COMPLETE with scoped offline evidence.
  Production setup remains unimplemented.
- No Terraform deployment, remediation execution or AI runtime. Accepted 8A authority records/API
  passed exact-commit independent review and delivery/main-CI gates through PR #53;
  no remediation dashboard or worker is added.

Operational detail and required follow-up are recorded in
`docs/operations/known-limitations.md` and `ROADMAP.md`.
