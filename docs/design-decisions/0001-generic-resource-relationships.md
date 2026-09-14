# Canonical generic AWS resource relationships

Status: accepted
Date: 2026-09-13

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
first-class domain object, not an embedded configuration member. Sprint 5 slice 5G will add one
generic Alembic-backed persistence representation and integrate it with inventory, persistence,
services, and API projections atomically.

The version 1 contract contains:

- `relationship_id`: UUIDv5 over source stable resource ID, controlled relationship type, and
  either the target stable resource ID or a namespaced unresolved-reference ID; it identifies one
  logical, directional edge across scans at that identity resolution level;
- `observation_id`: UUIDv5 over scan ID and relationship ID; it separates immutable historical
  observations of that edge;
- the scan ID and collecting AWS account ID;
- a controlled `RelationshipType`, whose endpoint signatures enforce direction;
- a complete source endpoint containing provider, account, service, resource type, AWS resource
  identifier, explicit global/Regional scope and Region, the existing deterministic stable
  resource ID, and its required snapshot ID;
- either a complete target endpoint with the same identity fields and optional snapshot ID, or a
  strict unresolved target reference containing the returned AWS identifier, service and type,
  every account/scope/Region component actually known, a deterministic reference ID, and explicit
  null stable-resource and snapshot IDs;
- a typed resolution state;
- collector, AWS API, timezone-aware collection time, and an opaque sanitized reference to the
  normalized evidence that established the relationship; and
- the normalized relationship schema version.

The source must have a snapshot in the relationship's scan. `RESOLVED` means the target also has
the exact deterministic snapshot ID for that scan. A canonical target that was not observed may
retain its calculable stable identity without a target snapshot. When AWS has not supplied all
stable identity components, `TARGET_IDENTITY_INCOMPLETE` instead retains a deterministic partial
reference whose stable-resource and snapshot IDs are null. Neither target form is a `Resource`
object or authorizes creating a fabricated resource row.

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

Each complete endpoint owns its scope and Region. Global endpoints, including IAM resources,
require a null Region. Regional endpoints require their actual resource Region. Bucket and KMS
Regions are their own endpoint values and are never inherited from the executor's requested
Region. Source and target Regions may differ, so bucket-home-Region and cross-Region references
remain explicit.

A partial target records account, scope, and Region as independently optional knowledge. It never
fills a missing target Region from the executor or source Region. For example, a CloudTrail
`GetTrail` response can establish a destination bucket name while bucket owner and home Region
remain unknown; that is a `TARGET_IDENTITY_INCOMPLETE` CloudTrail-to-S3 reference, not a bucket
resource and not confirmed absence. A complete identity is rejected from the partial form and
must use the canonical endpoint form.

The relationship's AWS account identifies the source/collection account. The source endpoint must
match it. A target endpoint retains its own account so supported cross-account references are not
misattributed.

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

Slice 5G will introduce one append-only generic relationship-observation table. Its reviewed
migration must preserve at least the complete domain fields above, a uniqueness constraint on
`(scan_id, relationship_id)`, the mandatory source resource/snapshot references, and an optional
target snapshot reference. Target identity uses a checked union: either canonical target stable ID
and complete identity fields, or unresolved reference ID and nullable account/scope/Region fields,
never both. Stable-resource and snapshot IDs are null for the partial form. A composite target
snapshot constraint can apply only when resolved, so either unresolved form does not require or
create a target `Resource` row.

The table will be indexed for scan, source stable ID, target stable/reference ID, and relationship
type.
Persistence validation must reconstruct and validate the domain contract before write and after
read. API and service projections will expose the same controlled direction, resolution, scope,
Region, version, and provenance rather than service-specific relationship shapes. Future controls
and investigation clients will traverse this generic boundary; they will not parse nested
configuration to rediscover edges.

The migration and runtime integration are intentionally deferred to Sprint 5. There is no current
producer, consumer, or public route for relationship observations, and adding a table alone would
change the protected persistence contract without an end-to-end writer/read path. Deferral keeps
this preflight test-only at runtime while still fixing the schema and persistence decision Sprint
5 must implement. It does not permit Sprint 5 collectors to invent another representation.

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
forged stable or snapshot IDs, naive timestamps, inconsistent accounts, invalid resolution state,
fabricated stable IDs on partial targets, complete identities disguised as partial, and extra
unreviewed metadata. Provenance uses a bounded single-line reference so callers do not need to put
raw AWS payloads or credentials in relationship rows or routine errors.

Stable logical identity plus per-scan identity prevents history from being overwritten. Explicit
unresolved states preserve uncertainty; joined controls must treat missing or unresolved required
edges as `INSUFFICIENT_EVIDENCE`. The relationship model carries no severity, control result,
framework mapping, remediation instruction, or free-form metadata policy.

## Compatibility and migration

The standalone domain module has no callers and changes no Sprint 0--4 behavior, database schema,
API schema, collector output, or persisted history. Existing `stable_resource_id` and
`resource_snapshot_id` algorithms are reused without modification. Sprint 5 must use a new Alembic
revision for first-class persistence; accepted revisions must not be rewritten.

## Validation

Contract tests cover the complete controlled vocabulary, valid and reversed directions,
deterministic IDs, exact duplicate handling, conflicting duplicates, global and cross-Region
endpoints, every unresolved state, forged identities, source/target snapshot consistency,
provenance, historical scan separation, strict immutability, JSON round trips, stable partial
references, CloudTrail-to-S3 identity gaps, and later canonical resolution without history
mutation.
