# Canonical generic AWS resource relationships

Status: accepted
Date: 2026-09-13

Implementation update: the Sprint 5 shared foundation implements this decision in Alembic
revision `20260915_0003`, the inventory/persistence boundary, and authenticated generic read
services. Current AWS collectors remain graphless; collector production starts with slice 5A,
and no Sprint 6 rule consumes these relationships yet.

## Context

Sprint 5 needs directional relationships that cross AWS services and execution scopes. Examples
include an EC2 instance using an EBS volume, an IAM role using a permissions boundary, and a
CloudTrail trail delivering to an S3 bucket. The accepted persistence model keeps stable
`Resource` identity separate from immutable per-scan `ResourceSnapshot` state, but it has no
generic edge representation.

Embedding identifiers in each resource's untyped configuration would hide direction,
resolution, provenance, and history behind service-specific JSON. Creating one table per edge
would multiply schemas and query paths. A graph database is not justified by the current bounded
query and traversal requirements.

This preflight must approve the domain contract without starting Sprint 5 collectors or changing
the accepted Sprint 0--4 persistence and API behavior.

## Decision

Use the immutable `ResourceRelationship` contract in
`app/assessment/relationships.py` as the canonical normalized relationship observation. It is a
first-class domain object, not an embedded configuration member. The shared Sprint 5 foundation
adds one
generic Alembic-backed persistence representation and integrates it with inventory, persistence,
services, and API projections atomically.

The version 1 contract contains:

- `relationship_id`: UUIDv5 over source stable resource ID, controlled relationship type, and
  either the target stable resource ID or a namespaced unresolved-reference ID; it identifies one
  logical, directional edge across scans at that identity resolution level;
- `observation_id`: UUIDv5 over scan ID and relationship ID; it separates immutable historical
  observations of that edge;
- the scan ID and verified 12-digit collection account ID;
- a controlled `RelationshipType`, whose endpoint signatures enforce direction;
- a complete source endpoint containing provider, resource-owner account, service, resource type,
  AWS resource
  identifier, explicit global/Regional scope and Region, the existing deterministic stable
  resource ID, and its required snapshot ID;
- either a complete target endpoint with the same identity fields and optional snapshot ID, or a
  strict unresolved target reference containing the returned AWS identifier, service and type,
  every account/scope/Region component actually known, a deterministic reference ID, and explicit
  null stable-resource and snapshot IDs;
- a typed resolution state;
- collector identity and version, AWS API, timezone-aware collection time, and an opaque
  sanitized reference to the normalized evidence that established the relationship; and
- the normalized relationship schema version.

The source must have a snapshot in the relationship's scan. `RESOLVED` means the target also has
the exact deterministic snapshot ID for that scan. A canonical target that was not observed may
retain its calculable stable identity without a target snapshot. When AWS has not supplied all
stable identity components, `TARGET_IDENTITY_INCOMPLETE` instead retains a deterministic partial
reference whose stable-resource and snapshot IDs are null. These serialized endpoint values are
not themselves ORM rows, and the partial form never authorizes creating a fabricated `Resource`.

At the persistence boundary, every endpoint of a `RESOLVED` relationship must reference a
top-level normalized `Resource` and its exact `ResourceSnapshot` for the relationship's scan.
This invariant applies to every relationship type, including IAM access keys, MFA devices,
groups, managed policies, inline policies, permissions-boundary targets, and policy versions.
An identifier or object embedded only inside another resource's configuration is evidence input,
not a canonical relationship endpoint. Existing Sprint 0--4 embedded IAM configuration may
remain temporarily for compatibility while Sprint 5 adds normalized resources and edges
atomically; it cannot substitute for either persisted endpoint and is removed only through a
separately reviewed atomic consumer transition.

An unresolved-reference ID is UUIDv5 over canonical JSON containing provider, every known
account/scope/Region value, service, type, the identifier AWS returned, and explicit nulls for
unknown fields. Repeating the same partial fact produces the same reference and relationship IDs.
Learning the missing canonical identity later produces the canonical stable edge; it does not
mutate, alias, or delete the earlier partial observation. The two IDs are intentionally different
because claiming they name one stable resource before resolution would fabricate identity.

When Sprint 5 integrates this contract into `InventorySnapshot`, inventory validation must require
the provenance collection time to equal that snapshot's collection time and the evidence
reference to address normalized evidence from the same scan. Those invariants cannot be checked by
the standalone relationship value without introducing a dependency on a producer that does not
yet exist.

The controlled v1 directions are:

| Relationship type | Allowed source | Allowed target |
| --- | --- | --- |
| `uses_volume` | EC2 instance | EBS volume |
| `attached_to_security_group` | EC2 instance | security group |
| `in_subnet` | EC2 instance | subnet |
| `in_vpc` | EC2 instance or security group | VPC |
| `contains_subnet` | VPC | subnet |
| `has_flow_log` | VPC | VPC Flow Log |
| `member_of_group` | IAM user | IAM group |
| `has_access_key` | IAM user | IAM access key |
| `has_mfa_device` | IAM user | IAM MFA device |
| `attached_managed_policy` | IAM user, group, or role | AWS- or customer-managed IAM policy |
| `attached_inline_policy` | IAM user, group, or role | IAM inline policy |
| `permissions_boundary` | IAM user or role | AWS- or customer-managed IAM policy |
| `selects_default_version` | AWS- or customer-managed IAM policy | IAM policy version |
| `references_resource` | Access Analyzer finding | any validated AWS resource reference |
| `encrypted_with` | S3 bucket or CloudTrail trail | KMS key |
| `delivers_to_bucket` | CloudTrail trail | S3 bucket |

Relationship direction is never inferred by reversing an edge. A future type is added to the
controlled vocabulary with endpoint validation and tests. A semantic reinterpretation requires a
new relationship schema version; it may not silently change historical v1 observations.

### Region and execution scope

Each complete endpoint owns its scope and Region. The v1 contract has a closed scope map for every
approved endpoint type: IAM resources are global, while the approved EC2, S3, KMS, CloudTrail,
and Access Analyzer resources are Regional. Known types cannot choose a different scope. Global
endpoints require a null Region, and Regional endpoints require their actual resource Region.
Bucket and KMS Regions are their own endpoint values and are never inherited from the executor's
requested Region. Source and target Regions may differ, so bucket-home-Region and cross-Region
references remain explicit.

A partial target records account, scope, and Region as independently optional knowledge, except
that a controlled known resource type must retain its already-defined global/Regional scope and a
known Region always requires Regional scope. It never fills a missing target Region from the
executor or source Region. For example, a CloudTrail
`GetTrail` response can establish a destination bucket name while bucket owner and home Region
remain unknown; that is a `TARGET_IDENTITY_INCOMPLETE` CloudTrail-to-S3 reference, not a bucket
resource and not confirmed absence. A complete identity is rejected from the partial form and
must use the canonical endpoint form.

The top-level `collection_account_id` is the verified 12-digit account whose credentials and scan
scope produced the observation. It is not a resource-owner field. Each endpoint independently
retains its controlled owner identity, so an organization or cross-account observation need not
pretend that the resource belongs to the collecting account. AWS-managed IAM policies use the
explicit `aws` owner sentinel (including their versions); that sentinel is invalid for all other
resource types. Customer-owned resources require a 12-digit owner account. Discovery and future
authorization remain bound to the collection account even when a relationship endpoint has a
different owner.

Every string used by the accepted delimiter-based stable-resource and snapshot-ID helpers rejects
the U+001F unit separator before identifier calculation. This standalone preflight validation
closes delimiter-collision aliases without changing the accepted Sprint 0--4 helper or existing
resource IDs.

### Missing and duplicate evidence

Use these resolution states only when a complete source observation supplies a trustworthy target
identity:

- `TARGET_NOT_COLLECTED`: the target family was not collected in this scan;
- `TARGET_OUTSIDE_SCAN_SCOPE`: the identifier is valid but its account or Region was outside the
  declared scan scope;
- `TARGET_ACCESS_DENIED`: the identifier is known but permissions prevented target collection;
- `TARGET_EVIDENCE_INCOMPLETE`: target normalization failed or was partial after its identity was
  established;
- `TARGET_IDENTITY_INCOMPLETE`: AWS supplied a real target reference but not every account,
  scope, or Region component required to calculate canonical stable identity.

The first four states use a complete, canonical target identity with no target snapshot.
`TARGET_IDENTITY_INCOMPLETE` uses only the strict partial-reference form. This keeps "known target
identity, target not observed" separate from "AWS reference exists, canonical target identity not
yet knowable."

If source edge evidence is incomplete, no positive relationship is emitted even when the target
resource independently exists in the same scan. The collector outcome remains `PARTIAL` or
`FAILED`, the target's independent snapshot remains intact, and any joined control must return
`INSUFFICIENT_EVIDENCE`. A target's existence never proves an edge. Absence of an edge is also not
proof that a relationship is absent. A source that names no target after complete enumeration is
the only confirmed absence case, represented by complete source evidence rather than a fabricated
edge.

Exact repeated AWS API records for one per-scan observation are coalesced. Different provenance,
direction, target, or resolution under the same observation ID is a conflict and fails
validation; the system never chooses one record and silently discards the other. Each v1 edge has
one designated authoritative source API. Supplementary corroborating facts remain versioned
resource evidence unless a later relationship schema explicitly supports multiple provenance
records.

### Planned first-class persistence

The foundational portion of slice 5G will introduce one append-only generic relationship-
observation table before any collector emits graph data. Its reviewed migration must preserve at
least the complete domain fields above, a uniqueness constraint on
`(scan_id, relationship_id)`, the mandatory source resource/snapshot references, and an optional
target snapshot reference. Target identity uses a checked union: either canonical target stable ID
and complete identity fields, or unresolved reference ID and nullable account/scope/Region fields,
never both. Stable-resource and snapshot IDs are null for the partial form. A composite target
snapshot constraint can apply only when resolved, so either unresolved form does not require or
create a target `Resource` row.

`InventorySnapshot.account_id`, `Scan.aws_account_id`, and the scan-scope account remain the
verified collection account. `NormalizedResource.account_id` and persisted
`Resource.aws_account_id` remain resource-owner identity. Slice 5G must replace the current blanket
same-account persistence check only as part of atomic graph integration, using this closed
admission rule:

1. A customer-owned resource normally has the same 12-digit owner as the collection account.
2. The `aws` owner is accepted only for the controlled AWS-managed IAM policy and matching policy-
   version resource types, with same-scan identity-authoritative source evidence.
3. A different 12-digit owner is accepted only when the reviewed collector contract can establish
   that exact owner, a same-scan source outcome preserves the identity-authoritative evidence, and
   any resolved edge references that exact top-level resource and snapshot.
4. Every relationship and source outcome has a `collection_account_id` equal to the scan's
   verified account. A cross-account owner never expands caller authorization or scan scope.

An external identifier without that complete proof remains an unresolved relationship reference;
it cannot create a cross-account `Resource`. The scope manifest continues to authorize the
collection account, requested services, resource types, and Regions rather than treating observed
owners as new scan principals. Future persistence tests must retain the current rejection for an
unproven different owner, accept the two explicit owner forms above, verify exact stable/snapshot
IDs, and round-trip collection account separately from owner account. These changes must land with
a new Alembic revision that replaces the accepted database `snapshot_provenance` trigger's blanket
resource-owner/scan-account equality, plus every in-memory inventory, persistence,
assessment-validation, writer, reader, service/API, and query assumption, with PostgreSQL and
SQLite rollback validation. Relaxing either the Python guard or database trigger alone is
prohibited.

The source foreign key always binds `(scan_id, source_stable_resource_id,
source_resource_snapshot_id)`. When resolution is `RESOLVED`, a second mandatory composite foreign
key binds `(scan_id, target_stable_resource_id, target_resource_snapshot_id)`; no resource type,
including IAM types, is exempt. Other resolution states may omit the target snapshot only
according to the typed union above. These constraints prevent embedded child data from posing as
a persisted edge endpoint.

The table will be indexed for scan, source stable ID, target stable/reference ID, and relationship
type.
Persistence validation must reconstruct and validate the domain contract before write and after
read. API and service projections will expose the same controlled direction, resolution, scope,
Region, version, and provenance rather than service-specific relationship shapes. Future controls
and investigation clients will traverse this generic boundary; they will not parse nested
configuration to rediscover edges.

The preflight intentionally deferred migration and runtime integration to Sprint 5. The shared
foundation now supplies the reviewed end-to-end writer/read path rather than an empty table.
AWS evidence producers remain deferred to 5A--5F and may not invent another representation.

## Alternatives considered

- **Embed typed edge documents in `NormalizedResource.configuration`.** Rejected because edges
  would be coupled to one endpoint, difficult to query, and easy to lose or reinterpret across
  snapshots.
- **Store only target identifiers in service-specific configuration.** Rejected because it has no
  generic direction, resolution, or provenance contract and makes cross-service joins bespoke.
- **Create service- or relationship-specific tables.** Rejected because every new AWS edge would
  require new persistence and API structures.
- **Adopt a graph database.** Rejected because PostgreSQL can satisfy the bounded historical and
  traversal queries without another datastore or operational trust boundary.
- **Create placeholder targets for unresolved identifiers.** Rejected because it fabricates
  collected resources and converts uncertainty into false inventory evidence.

## Security and data-integrity consequences

Strict models reject unknown relationship types, reversed endpoint signatures, ambiguous Regions,
forged stable or snapshot IDs, naive timestamps, invalid collection/owner account forms, invalid
resolution state, fabricated stable IDs on partial targets, complete identities disguised as
partial, and extra unreviewed metadata. Provenance uses a bounded single-line reference so callers
do not need to put raw AWS payloads or credentials in relationship rows or routine errors.

Stable logical identity plus per-scan identity prevents history from being overwritten. Explicit
unresolved states preserve uncertainty; joined controls must treat missing or unresolved required
edges as `INSUFFICIENT_EVIDENCE`. The relationship model carries no severity, control result,
framework mapping, remediation instruction, or free-form metadata policy.

## Compatibility and migration

The shared foundation now has validated inventory, persistence, service, and API callers while
preserving graphless Sprint 0--4 serialization and runtime behavior. Existing
`stable_resource_id` and `resource_snapshot_id` algorithms are reused without modification.
Revision `20260915_0003` adds first-class immutable persistence and a safe-blocking downgrade;
accepted earlier revisions remain unchanged. No current AWS collector emits a relationship.

## Validation

Contract tests cover the complete controlled vocabulary, valid and reversed directions,
deterministic IDs, exact duplicate handling, conflicting duplicates, global and cross-Region
endpoints, every unresolved state, forged identities, source/target snapshot consistency,
provenance, historical scan separation, strict immutability, JSON round trips, stable partial
references, CloudTrail-to-S3 identity gaps, and later canonical resolution without history
mutation.
