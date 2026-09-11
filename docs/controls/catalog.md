# Control catalog

This file is the authoritative catalog for immutable control identifiers and technical meanings.
It distinguishes the five executable controls accepted through Sprint 4 from canonical contracts
planned for Sprint 6. A planned contract defines what evidence Sprint 5 must make available; it is
not an implemented rule, an enabled assessment, or a claim that the current runtime evaluates it.

Sprint 2.1 kept the five deterministic technical checks introduced in Sprint 2 and gave each one
a versioned executable contract. It did not add controls, AWS calls, persistence, API endpoints,
or remediation execution. Sprint 3 subsequently persisted those results, and Sprint 4 now exposes
them through authorized read APIs without changing the control logic. The pre-Sprint-5 contracts
below are documentation-only and do not change catalog version `0.2.1` or application behavior.

The default control catalog is `aws-cloud-security-controls` version `0.2.1`:

| Control | Target | Failure condition | Severity |
| --- | --- | --- | --- |
| `IAM-001` | IAM user | The collected MFA device list is empty | `MEDIUM` |
| `LOG-001` | AWS account | No collected CloudTrail has logging explicitly active | `HIGH` |
| `NET-001` | EC2 security group | Public ingress effectively exposes TCP port 22 | `HIGH` |
| `NET-002` | EC2 security group | Public ingress effectively exposes TCP port 3389 | `HIGH` |
| `S3-900` | S3 bucket | The explicit default-encryption configuration is `null` | `MEDIUM` |

## Permanent S3 identifier safety

Only `S3-900` is implemented today. The canonical Sprint 6 identifiers below are reserved now so
historical findings and integrations cannot acquire conflicting meanings:

| Control ID | Permanent semantic meaning | Current state |
| --- | --- | --- |
| `S3-001` | Required Block Public Access configuration missing | Reserved; not implemented |
| `S3-002` | Unapproved public/external bucket exposure | Reserved; not implemented |
| `S3-003` | Secure transport not enforced | Reserved; not implemented |
| `S3-004` | Sensitive-data KMS requirement not met | Reserved; not implemented |
| `S3-900` | Legacy explicit default-encryption configuration prototype | Implemented, non-core |

Never reuse a reserved ID for another meaning. In particular, the obsolete prototype meaning
`S3-002 = missing default encryption` must not return.

The accepted catalog does not yet define how `S3-002` aggregates policy status, ACLs, Block Public
Access, conditions, external-principal approvals, or Access Analyzer facts. It also lacks a
versioned classification selector that determines which buckets are sensitive for `S3-004`;
`restricted_data_requires_kms` defines the consequence after classification, not classification
itself. This task is not authorized to redefine existing S3 controls, so those details remain
separately owned contract dependencies for Sprint 5 and `LOG-004`; none of the permanent S3
meanings above changes here.

## Planned-contract interpretation

The following contracts are canonical designs for Sprint 6 but are not executable. Every planned
assessment uses the established `PASS`, `FAIL`, `INSUFFICIENT_EVIDENCE`, and `NOT_APPLICABLE`
states. Missing required evidence or incomplete collector coverage never becomes `PASS`.
Exceptions and profile allowlists remain distinct: an operational Finding Exception cannot
rewrite the technical result, while a versioned Assessment Profile input is part of the rule's
reproducible policy definition.

Unless a contract says otherwise, its evidence must retain the scan ID, AWS account, Region or
explicit global scope, stable resource identity, collector and AWS API source, collection time,
schema/version, and collector-completeness outcome. The companion
[Sprint 5 evidence-readiness matrix](sprint-5-evidence-readiness.md) owns API, permission, field,
relationship, and sub-sprint planning detail.

New contracts deliberately have no severity or NIST mapping yet. Severity is project policy and
must not be inferred from NIST. A future mapping requires separate authoritative provenance and
review; no mapping metadata is needed to collect Sprint 5 facts.

## Canonical planned Sprint 6 contracts

### `IAM-002` — Active IAM access key exceeds maximum age

- **Status:** canonical design; not implemented or enabled.
- **Scope/resource type:** one IAM user, using the complete set of that user's active access keys.
- **Required evidence:** user identity; access-key identifier; key status; key creation timestamp;
  deterministic observation time; complete key enumeration; and common provenance.
- **Relationships:** IAM user -> access key. The key may remain structured child evidence rather
  than a top-level resource if stable identity and history are preserved.
- **Assessment Profile:** `enabled_controls` and the approved semantic input
  `max_access_key_age_days`. The current serialized profile field `stale_key_days` already carries
  this policy and defaults to 90; preserving that field avoids silently changing profile `1.0.0`.
  A future rename requires an explicit profile-schema/version transition.
- **PASS:** every active key is no older than the configured threshold at the evidence observation
  time.
- **FAIL:** at least one active key is older than the configured threshold.
- **NOT_APPLICABLE:** the user has no active access keys.
- **INSUFFICIENT_EVIDENCE:** active-key enumeration is incomplete, or an active key lacks a
  trustworthy identifier, status, creation timestamp, or observation time.
- **Limitations:** key creation time is the available age anchor; the contract does not prove that
  a credential was distributed safely or that an external secret was rotated.
- **AWS references:** [ListAccessKeys](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListAccessKeys.html)
  and [IAM access-key management](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html).

### `IAM-003` — Active IAM access key unused beyond allowed period

- **Status:** canonical design; not implemented or enabled.
- **Scope/resource type:** one IAM user, using the complete set of that user's active access keys.
- **Required evidence:** key identifier, status, creation timestamp, last-used timestamp when
  present, an explicit `no_recorded_use` state after a successful lookup returns no
  `LastUsedDate`, deterministic observation time, complete enumeration, and common provenance.
- **Relationships:** IAM user -> access key.
- **Assessment Profile:** `enabled_controls` and a future versioned
  `max_unused_access_key_days` input. It must be added only with a reviewed new profile schema and
  profile version; it is not hard-coded by the control.
- **PASS:** every active key was used within the threshold, or has `no_recorded_use` but is no
  older than the threshold.
- **FAIL:** at least one active key was last used before the threshold boundary, or has
  `no_recorded_use` and is older than the threshold.
- **NOT_APPLICABLE:** the user has no active access keys.
- **INSUFFICIENT_EVIDENCE:** enumeration or last-use lookup is incomplete, or a required status,
  creation time, last-used/`no_recorded_use` distinction, or observation time is unavailable.
- **Limitations:** AWS last-used data can lag and does not prove who used a credential or whether
  use was authorized. For a key old enough to predate AWS tracking, no returned `LastUsedDate`
  means no recorded use since tracking began, not proof that the key was literally never used.
- **AWS references:** [GetAccessKeyLastUsed](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccessKeyLastUsed.html)
  and [ListAccessKeys](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListAccessKeys.html).

### `IAM-004` — IAM policy grants explicit full administrative access

- **Status:** canonical design; not implemented or enabled.
- **Scope/resource type:** one complete in-scope IAM permissions-policy document. V1 scope covers
  customer-managed policies, AWS-managed policies referenced by an identity attachment or
  permissions-boundary ARN, and user, group, or role inline identity policies. Role trust policies
  and other policy families are retained as evidence but are not evaluated by this syntactic
  control. The assessment unit is one stable policy-document representation, deduplicated across
  its usage relationships. A managed policy is identified by ARN plus selected default
  `VersionId`; an inline policy has no AWS policy version and is identified by owner identity plus
  policy name, with history bound to the immutable snapshot and document digest. A managed
  document remains in scope when used only as a permissions boundary; if the same version is both
  attached and used as a boundary, it still receives one syntactic assessment with both contexts
  retained.
- **Required evidence:** policy identity and type; owner/attachment and boundary context; managed
  policy default `VersionId` and decoded default-version document, or inline owner identity,
  policy name, decoded document, snapshot identity, and content digest; decoded `Statement`
  entries; and exact `Effect`, `Action`, `NotAction`, `Resource`, `NotResource`, and `Condition`
  structures with common provenance.
- **Relationships:** IAM user/group/role -> attached managed policy; IAM identity -> inline policy;
  identity -> permissions boundary; and managed policy -> default version. Trust policies remain
  related to roles without being silently treated as identity permissions policies.
- **Assessment Profile:** `enabled_controls` only. The v1 match is not threshold-based.
- **PASS:** complete in-scope policy evidence contains no statement with `Effect` equal to the
  exact string `Allow`, an `Action` string equal to `*` or list containing the exact `*` element,
  and a `Resource` string equal to `*` or list containing the exact `*` element. Service wildcards
  such as `s3:*` are not the literal full-administrator pattern.
- **FAIL:** at least one complete statement matches all three exact syntactic conditions. A
  retained `Condition` does not erase this syntactic match or justify an effective-access claim;
  `NotAction` or `NotResource` does not substitute for a missing `Action` or `Resource` match.
- **NOT_APPLICABLE:** the document is outside the explicitly stated v1 permissions-policy scope,
  such as a role trust policy or another resource-policy family. Boundary-only usage is not a
  separate policy type and does not change applicability.
- **INSUFFICIENT_EVIDENCE:** the document is missing, malformed, cannot be decoded, has incomplete
  required statement structure, or its enumeration is incomplete; managed policy evidence also
  requires complete default-version retrieval, while inline evidence requires complete owner,
  name, snapshot, and digest identity. No synthetic AWS version is assigned to an inline policy.
- **Limitations:** this detects only the explicit full-administrator pattern. It does not compute
  effective authorization across SCPs, permissions boundaries, session policies, resource
  policies, explicit denies, service condition semantics, or cross-account interactions. A
  boundary can limit permissions but never grants them, so a match in a boundary-only document is
  a policy-pattern result and must not be described as an attached or effective administrator.
- **AWS references:** [GetPolicyVersion](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetPolicyVersion.html),
  [GetUser](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetUser.html),
  [GetRolePolicy](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetRolePolicy.html),
  [IAM JSON policy elements](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html),
  and [policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html).

### `IAM-005` — Root account access key exists

- **Status:** canonical design; not implemented or enabled.
- **Scope/resource type:** AWS account; global IAM evidence.
- **Required evidence:** a complete account summary containing the authoritative
  `AccountAccessKeysPresent` value, plus common global provenance.
- **Relationships:** none; this is account-level evidence and must not be duplicated per Region.
- **Assessment Profile:** `enabled_controls` only.
- **PASS:** the complete summary reports the validated AWS presence flag `0`.
- **FAIL:** the complete summary reports the validated AWS presence flag `1`.
- **NOT_APPLICABLE:** never for a normal AWS account assessment.
- **INSUFFICIENT_EVIDENCE:** the account summary cannot be retrieved or the required value is
  missing, malformed, or otherwise incomplete.
- **Limitations:** the setting establishes presence, not whether a key has been exposed or used.
  Tests must use synthetic responses and must never create a root credential.
- **AWS reference:** [GetAccountSummary](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountSummary.html).

### `IAM-006` — Root account MFA is not enabled

- **Status:** canonical design; not implemented or enabled.
- **Scope/resource type:** AWS account; global IAM evidence.
- **Required evidence:** a complete account summary containing authoritative
  `AccountMFAEnabled`, plus common global provenance.
- **Relationships:** none; this is account-level evidence and must not be duplicated per Region.
- **Assessment Profile:** `enabled_controls` only.
- **PASS:** the validated AWS presence flag is `1` and normalizes to enabled.
- **FAIL:** the validated AWS presence flag is `0` and normalizes to disabled.
- **NOT_APPLICABLE:** never for a normal AWS account assessment.
- **INSUFFICIENT_EVIDENCE:** the summary cannot be retrieved or the MFA value is missing,
  malformed, or incomplete.
- **Limitations:** this checks MFA presence only; it is not a hardware-MFA-only control and does
  not assess device health. Tests must never weaken root security.
- **AWS reference:** [GetAccountSummary](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountSummary.html).

### `NET-003` — Security group permits unrestricted all-protocol public ingress

- **Status:** canonical design; not implemented or enabled.
- **Scope/resource type:** EC2/VPC security group.
- **Required evidence:** complete normalized ingress permissions including protocol, ports when
  applicable, IPv4 and IPv6 CIDRs, security-group references, and prefix-list references, with
  common regional provenance.
- **Relationships:** security group -> VPC.
- **Assessment Profile:** `enabled_controls` only.
- **PASS:** complete ingress evidence contains no all-protocol (`IpProtocol = -1`) rule sourced
  from `0.0.0.0/0` or `::/0`.
- **FAIL:** at least one ingress rule permits all protocols from either public `/0` range.
- **NOT_APPLICABLE:** no security-group resources are present.
- **INSUFFICIENT_EVIDENCE:** ingress enumeration or any decision-relevant protocol/source
  structure is missing, malformed, or incomplete.
- **Limitations:** this control does not infer reachability through route tables, network ACLs,
  firewalls, load balancers, or host controls. Overlap with `NET-004` is intentional when one rule
  exposes both all protocols and a configured high-risk port.
- **AWS reference:** [DescribeSecurityGroups](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSecurityGroups.html).

### `NET-004` — Security group exposes a high-risk port publicly

- **Status:** canonical design; not implemented or enabled.
- **Scope/resource type:** EC2/VPC security group.
- **Required evidence:** complete ingress protocol, start/end port, and IPv4/IPv6 CIDR evidence,
  including AWS all-protocol semantics, with common regional provenance.
- **Relationships:** security group -> VPC.
- **Assessment Profile:** `enabled_controls` and a future versioned
  `high_risk_public_tcp_ports` list. The initial reviewed candidate set is `3306`, `5432`, `6379`,
  `9200`, and `27017`; ports 22 and 3389 remain under `NET-001` and `NET-002` unless a later
  profile explicitly includes them.
- **PASS:** complete evidence shows that no public IPv4/IPv6 `/0` permission allows a configured
  high-risk TCP port, directly or through a containing range/all-protocol rule.
- **FAIL:** at least one public `/0` permission permits a configured high-risk TCP port.
- **NOT_APPLICABLE:** no security-group resources are present, or the reviewed profile contains no
  high-risk ports.
- **INSUFFICIENT_EVIDENCE:** the profile input or required protocol/port/source evidence is
  missing, malformed, or incomplete.
- **Limitations:** this is a configured-port screen, not full network reachability or service
  discovery.
- **AWS reference:** [DescribeSecurityGroups](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSecurityGroups.html).

### `NET-005` — Default VPC security group permits traffic

- **Status:** canonical design; not implemented or enabled.
- **Scope/resource type:** EC2/VPC security group.
- **Required evidence:** group and VPC identity; the exact AWS `GroupName`; and complete ingress
  and egress permissions, including referenced groups, CIDRs, protocols, and ports. The normalized
  default-group indicator is derived only from `GroupName == "default"` together with a valid
  `VpcId`; `DescribeSecurityGroups` does not return a separate `IsDefault` field.
- **Relationships:** default security group -> owning VPC.
- **Assessment Profile:** `enabled_controls` only.
- **PASS:** the default security group has no ingress and no egress permissions.
- **FAIL:** the default security group contains any ingress or egress permission.
- **NOT_APPLICABLE:** the security group is not the default group for its VPC; no security groups
  overall also yields no applicable resource assessments.
- **INSUFFICIENT_EVIDENCE:** default-group identity, VPC ownership, or complete ingress/egress
  evidence cannot be determined.
- **Limitations:** the control evaluates only rules on the default group, not whether resources
  are currently associated with it.
- **AWS reference:** [DescribeSecurityGroups](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSecurityGroups.html).

### `NET-006` — Required VPC Flow Logs are missing

- **Status:** canonical design; not implemented or enabled.
- **Scope/resource type:** one VPC in one AWS account and Region.
- **Required evidence:** VPC identity, account, Region, complete tags/context, and complete VPC
  Flow Log records containing identity, `ResourceId`, `FlowLogStatus`, `TrafficType`, destination
  context, and common provenance. AWS does not return a Flow Log `ResourceType` member.
- **Relationships:** VPC -> VPC-scoped Flow Log only when the Flow Log `ResourceId` exactly equals
  the validated ID of that collected VPC. Subnet, interface, and transit-gateway flow logs do not
  silently satisfy this VPC-scoped contract.
- **Assessment Profile:** `enabled_controls`; future versioned, non-empty
  `vpc_flow_log_required_environments`; and future versioned, non-empty
  `acceptable_vpc_flow_log_traffic_types`. V1 applicability uses the exact case-sensitive VPC tag
  key `Environment` and exact case-sensitive values in the environment tuple. Acceptable traffic
  values are a non-empty subset of AWS's exact `REJECT` and `ALL` values. These choices must be
  persisted in the selected profile rather than assumed by code.
- **PASS:** the VPC is in profile scope and at least one matching `ACTIVE` VPC Flow Log has an
  acceptable traffic type.
- **FAIL:** applicability and collection are complete, but an in-scope VPC has no qualifying Flow
  Log.
- **NOT_APPLICABLE:** a complete, usable `Environment` tag value is not in the profile's exact
  required-environment tuple.
- **INSUFFICIENT_EVIDENCE:** the profile is invalid; the `Environment` tag is absent, empty, or
  malformed; tag collection is incomplete; or VPC/Flow Log enumeration or a decision-relevant
  value is incomplete or malformed. Missing applicability context is never treated as out of
  scope.
- **Limitations:** presence does not prove destination delivery, retention, alerting, or analysis.
- **AWS references:** [DescribeVpcs](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeVpcs.html)
  and [DescribeFlowLogs](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeFlowLogs.html).

### `EC2-001` — EC2 instance does not require IMDSv2

- **Status:** canonical design; not implemented or enabled.
- **Scope/resource type:** EC2 instance.
- **Required evidence:** instance identity and complete `MetadataOptions.State`,
  `MetadataOptions.HttpEndpoint`, and `MetadataOptions.HttpTokens`, with common regional
  provenance.
- **Relationships:** instance -> VPC and subnet are useful context but do not determine this
  result.
- **Assessment Profile:** `enabled_controls` only.
- **PASS:** metadata-option state is `applied`, the endpoint is enabled, and `HttpTokens` is
  `required`.
- **FAIL:** metadata-option state is `applied`, the endpoint is enabled, and `HttpTokens` is
  `optional`.
- **NOT_APPLICABLE:** metadata-option state is `applied` and the endpoint is explicitly disabled.
- **INSUFFICIENT_EVIDENCE:** state/endpoint/token configuration is absent, unknown, malformed, or
  collected incompletely, or state is `pending`. A selected but not-yet-applied configuration and
  absent evidence never imply `PASS`.
- **Limitations:** this does not assess hop limit, metadata tags, application compatibility, or
  credential exposure already incurred.
- **AWS reference:** [DescribeInstances](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html).

### `EC2-002` — EC2 instance has an unapproved public IPv4 address

- **Status:** canonical design; not implemented or enabled.
- **Scope/resource type:** EC2 instance.
- **Required evidence:** instance/account/Region identity, complete public-IPv4 assignment state
  across the instance-level address, every attached network interface association, and every
  nested private-address association; instance state/context when policy needs it; selected
  profile policy; and common provenance.
- **Relationships:** instance -> subnet and VPC provide context; instance -> security groups does
  not by itself approve a public address.
- **Assessment Profile:** `enabled_controls` and the established versioned
  `public_ec2_exceptions` resource allowlist. Despite its historical field name, this is
  assessment policy and is separate from the Finding Exception lifecycle.
- **PASS:** no public IPv4 is assigned, or the stable instance identity is explicitly allowed by
  the selected profile.
- **FAIL:** a public IPv4 is assigned and the stable identity is not allowed by policy.
- **NOT_APPLICABLE:** no EC2 instance resources are present.
- **INSUFFICIENT_EVIDENCE:** public-IP state or required policy context cannot be determined.
- **Limitations:** public addressing does not prove end-to-end reachability, and a Finding
  Exception cannot convert a technical failure into `PASS`.
- **AWS reference:** [DescribeInstances](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html).

### `EC2-003` — EBS volume is not encrypted

- **Status:** canonical design; not implemented or enabled.
- **Scope/resource type:** EBS volume.
- **Required evidence:** volume/account/Region identity, `Encrypted`, KMS key ID when present,
  attachments, and common regional provenance.
- **Relationships:** EC2 instance -> attached EBS volume; the volume retains the corresponding
  attachment instance IDs as inverse investigation context. The edge does not change the
  encryption result.
- **Assessment Profile:** `enabled_controls` only.
- **PASS:** `Encrypted` is explicitly `true`.
- **FAIL:** `Encrypted` is explicitly `false`.
- **NOT_APPLICABLE:** no EBS volume resources are present.
- **INSUFFICIENT_EVIDENCE:** encryption state is missing, malformed, or incompletely collected.
- **Limitations:** KMS identity is retained but not required merely to decide encryption; the
  control does not assess key policy, rotation, or snapshot history.
- **AWS reference:** [DescribeVolumes](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeVolumes.html).

### `EC2-004` — EBS encryption by default is disabled

- **Status:** canonical design; not implemented or enabled.
- **Scope/resource type:** AWS account + Region setting, not an EBS volume.
- **Required evidence:** account, Region, explicit `EbsEncryptionByDefault`, optional default KMS
  key ID for context, and common regional provenance.
- **Relationships:** none required; a setting may be related to its account/Region scope but must
  not be attached to one volume.
- **Assessment Profile:** `enabled_controls` only.
- **PASS:** `EbsEncryptionByDefault` is explicitly `true`.
- **FAIL:** `EbsEncryptionByDefault` is explicitly `false`.
- **NOT_APPLICABLE:** never for a requested, supported AWS Region.
- **INSUFFICIENT_EVIDENCE:** the Region-level setting cannot be retrieved or is malformed.
- **Limitations:** the setting affects newly created volumes and does not prove existing volumes
  are encrypted or that the default KMS key meets organization policy.
- **AWS references:** [GetEbsEncryptionByDefault](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_GetEbsEncryptionByDefault.html)
  and [GetEbsDefaultKmsKeyId](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_GetEbsDefaultKmsKeyId.html).

### `LOG-002` — Required multi-Region CloudTrail management-event coverage is missing

- **Status:** canonical design; not implemented or enabled.
- **Scope/resource type:** AWS account, using all relevant trails without an ambiguous "primary
  trail" concept.
- **Required evidence:** complete trail identity/home Region, `IsMultiRegionTrail`,
  `IsOrganizationTrail`, active logging status, and the complete selector form returned by AWS.
  Basic selectors retain both raw presence and normalized values for `IncludeManagementEvents`,
  `ReadWriteType`, and the complete `ExcludeManagementEventSources` list. Advanced selectors
  retain every `FieldSelectors` entry and its `Field`, `Equals`, `StartsWith`, `EndsWith`,
  `NotEquals`, `NotStartsWith`, and `NotEndsWith` operators, including `eventCategory` and
  `readOnly` filters. Evidence also retains common provenance/completeness.
- **Relationships:** account -> trails; trail destinations are context but do not determine this
  coverage result.
- **Assessment Profile:** `enabled_controls` only.
- **PASS:** at least one qualifying trail is logging, is multi-Region, and complete selectors
  prove both read and write management-event coverage under the truth table below.
- **FAIL:** complete account-wide CloudTrail evidence exists and no trail meets all conditions.
- **NOT_APPLICABLE:** never for a normal AWS account assessment.
- **INSUFFICIENT_EVIDENCE:** trail enumeration, status, home-Region enrichment, or event-selector
  evidence is incomplete or malformed. An advanced-selector combination outside the future
  evaluator's explicitly supported semantics is also insufficient; partial or simplified
  selector data cannot produce `PASS` or `FAIL`.
- **Limitations:** this does not prove delivery, retention, alerting, data-event coverage, or
  organization-wide coverage from a member account.
- **AWS references:** [ListTrails](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_ListTrails.html),
  [GetTrail](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetTrail.html),
  [GetTrailStatus](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetTrailStatus.html),
  [GetEventSelectors](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetEventSelectors.html),
  and [EventSelector](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_EventSelector.html).

For one trail, the selector form and coverage are evaluated as follows:

| Returned selector fact | Read coverage | Write coverage | Deterministic treatment |
| --- | --- | --- | --- |
| Basic selector: management events excluded | no | no | Complete non-qualifying selector |
| Basic selector: management events included, empty exclusions, `ReadWriteType = All` | yes | yes | Qualifies by itself |
| Basic selector: management events included, empty exclusions, `ReadOnly` | yes | no | May combine with another basic selector |
| Basic selector: management events included, empty exclusions, `WriteOnly` | no | yes | May combine with another basic selector |
| Basic selector: management events included, non-empty valid `ExcludeManagementEventSources` | according to `ReadWriteType` | according to `ReadWriteType` | Partial source coverage; combine by the set rule below |
| Advanced selector: exact `eventCategory Equals ["Management"]`, no other restricting field, no `readOnly` field | yes | yes | Qualifies by itself |
| Same advanced form with `readOnly Equals ["true"]` | yes | no | May combine with another advanced selector |
| Same advanced form with `readOnly Equals ["false"]` | no | yes | May combine with another advanced selector |
| Same advanced form with both exact boolean strings | yes | yes | Qualifies by itself |
| Valid advanced selector with another restricting field | unknown | unknown | Outside v1's proof subset unless another unrestricted selector independently qualifies |
| Malformed value/operator, mixed non-empty basic and advanced forms, or unsupported `eventCategory`/`readOnly` expression | unknown | unknown | `INSUFFICIENT_EVIDENCE` |

Within an advanced selector, field selectors are intersected; separate advanced selectors are
unioned. Separate basic selectors are also unioned because CloudTrail records an event when any
selector matches. For each of the read and write dimensions independently, take every included
basic selector whose `ReadWriteType` covers that dimension and intersect their normalized
exclusion sets. The dimension has full management-source coverage when at least one selector
contributes and that intersection is empty. Thus one empty-exclusion selector proves its covered
dimension, and two selectors excluding disjoint sources can jointly prove it. Valid exclusion
values are the exact AWS values `kms.amazonaws.com` and `rdsdata.amazonaws.com`; an unknown,
duplicate, non-string, or malformed value makes selector evidence `INSUFFICIENT_EVIDENCE`.

The future evaluator must aggregate read and write coverage across every selector of the one valid
returned form. `NotEquals`, `StartsWith`,
`EndsWith`, `NotStartsWith`, and `NotEndsWith` values are preserved, but a valid trail whose
coverage relies on one of those operators for `eventCategory` or `readOnly` is outside v1's proof
subset and yields `INSUFFICIENT_EVIDENCE`, not a guessed result. A complete valid set with only
advanced restricting selectors also yields `INSUFFICIENT_EVIDENCE`: ORed restrictions can have
complex combined coverage that v1 does not claim to solve. For a structurally valid basic
selector, AWS's documented optional defaults are canonical: absent `IncludeManagementEvents`
normalizes to `true`, absent `ReadWriteType` to `All`, and absent
`ExcludeManagementEventSources` to an empty tuple. Raw omission is preserved. Non-empty valid
exclusion lists are retained and evaluated by the source-set rule above.

Account-level result precedence is explicit: any failed/partial trail enumeration or required AWS
lookup yields `INSUFFICIENT_EVIDENCE`; otherwise, one complete actively logging multi-Region trail
with proven read and write coverage yields `PASS`. If none qualifies and any relevant trail has an
unknown selector result, the account result is `INSUFFICIENT_EVIDENCE`. `FAIL` is valid only when
enumeration is complete and every relevant trail is deterministically non-qualifying.

### `LOG-003` — CloudTrail log-file integrity validation is disabled

- **Status:** canonical design; not implemented or enabled.
- **Scope/resource type:** CloudTrail trail.
- **Required evidence:** stable trail identity and explicit `LogFileValidationEnabled`, with
  common trail/home-Region provenance.
- **Relationships:** trail -> S3 destination is useful investigation context but is not required
  for this setting.
- **Assessment Profile:** `enabled_controls` only.
- **PASS:** log-file validation is explicitly enabled.
- **FAIL:** log-file validation is explicitly disabled.
- **NOT_APPLICABLE:** no CloudTrail trail resources are present.
- **INSUFFICIENT_EVIDENCE:** the setting is absent, malformed, or incompletely collected.
- **Limitations:** enabling validation does not prove that operators validate digest files or that
  the destination is available.
- **AWS reference:** [GetTrail](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetTrail.html).

### `LOG-004` — CloudTrail log storage has unapproved public/external exposure

- **Status:** canonical design; not implemented or enabled.
- **Scope/resource type:** CloudTrail trail joined to its S3 destination.
- **Required evidence:** trail identity and S3 bucket name; resolved stable bucket identity;
  complete canonical S3 public/external-exposure evidence; relationship provenance; and complete
  CloudTrail and S3 collector outcomes.
- **Relationships:** CloudTrail trail -> S3 bucket. The relationship must resolve by stable bucket
  identity rather than copying a contradictory exposure interpretation into CloudTrail facts.
- **Assessment Profile:** `enabled_controls` plus only the versioned inputs eventually authorized
  by the separate canonical `S3-002` contract. This task does not invent that policy. A Finding
  Exception remains separate.
- **PASS:** the relationship is complete and the canonical technical `S3-002` assessment for that
  exact persisted destination bucket snapshot is `PASS`.
- **FAIL:** the relationship is complete and that exact canonical `S3-002` assessment is `FAIL`.
- **NOT_APPLICABLE:** never for a trail; a missing destination is uncertainty, not
  non-applicability.
- **INSUFFICIENT_EVIDENCE:** destination identity or relationship resolution is unavailable, or
  the corresponding canonical S3-002 assessment is unavailable or `INSUFFICIENT_EVIDENCE`.
- **Limitations:** the rule composes the S3-002 result and does not independently evaluate or
  duplicate S3 exposure, log delivery, object ownership, retention, or KMS protection. The
  repository currently reserves S3-002's immutable meaning without a detailed approval and source
  aggregation contract. That pre-existing gap must be resolved in a separately authorized S3
  contract review before LOG-004 or its decisive Sprint 5 evidence set can be implemented.
- **AWS references:** [GetTrail](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetTrail.html)
  and [Amazon S3 Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html).

### `GOV-001` — Required ownership or context tags are missing

- **Status:** canonical design; not implemented or enabled.
- **Scope/resource type:** each resource type explicitly governed by the selected profile.
- **Required evidence:** stable resource identity/type and complete, case-sensitive resource tags
  with collector completeness and common provenance.
- **Relationships:** none required for the result; resource relationships remain investigation
  context.
- **Assessment Profile:** `enabled_controls`, existing non-empty `required_tags`, and a future
  versioned, non-empty `governed_resource_types` tuple of exact canonical normalized resource-type
  identifiers. The first supported selector vocabulary is `ec2_instance`, `ebs_volume`, `vpc`,
  `subnet`, `security_group`, `vpc_flow_log`, `s3_bucket`, `iam_user`, `iam_role`,
  `iam_customer_managed_policy`, and `cloudtrail_trail`. Within IAM policy evidence, only
  customer-managed policies are taggable. A profile enabling this control must reject unknown or
  unsupported selectors
  rather than silently evaluating partial tag sources. New keys or types require a new immutable
  profile version. Keys prefixed `aws:` do not satisfy project-required ownership tags.
- **PASS:** every exact case-sensitive required key is present and its string value contains at
  least one non-whitespace character. Normalization preserves the original value.
- **FAIL:** tag evidence is complete and one or more required keys are absent or unusable.
- **NOT_APPLICABLE:** the resource type is outside the profile's governed set, or there are no
  governed resources.
- **INSUFFICIENT_EVIDENCE:** tag collection is incomplete, so absence cannot be distinguished from
  collection failure, or the tag structure is malformed.
- **Limitations:** this checks presence and usable values, not truth, ownership authorization, or
  consistency with an external CMDB. Tag keys and governed resource-type identifiers are
  case-sensitive; IAM groups, AWS-managed policies, access-key child facts, and account/Region
  setting observations are outside the initial taggable vocabulary.
- **AWS reference:** [Tagging AWS resources](https://docs.aws.amazon.com/tag-editor/latest/userguide/tagging.html).

Every executable contract defines a stable control ID, title, resource type, assessment type,
required evidence, result logic, severity, impact, remediation guidance, profile parameters,
limitations, and framework mappings. The documentation-only planned contracts above intentionally
defer severity, impact/remediation copy, and mappings while defining the evidence and deterministic
result semantics needed for Sprint 5 planning. Their technical meaning remains valid without NIST
metadata; framework mappings never drive a technical result.

## Evaluation

Collect facts first and then assess the completed snapshot with an explicit policy profile:

```python
from app.assessment.profiles import create_default_assessment_profile
from app.aws.client import Boto3ClientProvider
from app.rules.engine import RuleEngine
from app.rules.registry import build_default_registry
from app.services.inventory_service import InventoryService

provider = Boto3ClientProvider.from_settings()
snapshot = InventoryService(provider).collect()
profile = create_default_assessment_profile()
assessments = RuleEngine(build_default_registry()).assess(snapshot, profile)
```

`RuleEngine.assess` returns a deterministic tuple of `AssessmentCandidate` values. Each enabled
control explicitly returns one of:

- `PASS` when sufficient evidence satisfies the control;
- `FAIL` when sufficient evidence violates the control;
- `INSUFFICIENT_EVIDENCE` when a required fact is absent or malformed; or
- `NOT_APPLICABLE` when a resource-scoped control has no matching resources.

Missing evidence is never interpreted as a pass. `PASS` and `FAIL` results carry a structured
`EvidenceArtifact`; insufficient results identify the missing fact paths without exposing raw AWS
responses. Each assessment also records the exact profile checksum. Resource controls return one
result per applicable resource. `LOG-001` remains an account-level control and is always
applicable.

The legacy `RuleEngine.evaluate(snapshot)` interface is preserved for callers built against
Sprint 2. It returns failure-only `FindingCandidate` values and raises a sanitized
`RuleEvaluationError` when required facts are missing or malformed or required collection is
incomplete. New integrations should use `assess` so that pass, insufficient-evidence, and
non-applicable states are not discarded.

## `NET-001` — Public SSH

`NET-001` fails when at least one inbound rule effectively allows TCP port 22 from the public IPv4
or IPv6 network.

- `0.0.0.0/0` and `::/0` are public; CIDRs are parsed as networks.
- Named `tcp` rules match when their inclusive port range contains port 22.
- Protocol number `6` and all protocols (`-1`) effectively include TCP according to EC2 security
  group semantics.
- Egress, security-group references, and prefix lists are not treated as public CIDRs.

Evidence includes the group, VPC, region, target port, and normalized matching ingress rules. A
valid security group without a public match passes. Missing or malformed decision-relevant
ingress facts are insufficient evidence. If the inventory has no security groups, the control is
not applicable.

## `NET-002` — Public RDP

`NET-002` uses the same address-family, protocol, port-range, evidence, and uncertainty rules as
`NET-001`, with target port 3389. A public match fails; a valid configuration without a match
passes; no security groups is not applicable.

## `S3-900` — Missing explicit bucket encryption

`S3-900` fails when `configuration.default_encryption` is explicitly `null`. A valid, non-empty
encryption `Rules` list passes only when each rule supplies a supported `SSEAlgorithm`. Missing
fields, unexpected types, and structurally invalid values produce insufficient evidence. No S3
buckets makes the control not applicable.

This is legacy prototype behavior from Sprint 2, not a canonical future control. Before any
persistence existed, Sprint 2.1 deliberately migrated its ID from `S3-002` to the non-core
`S3-900`. This preserves the implemented behavior while reserving canonical `S3-002` for the
roadmap's future unapproved public/external bucket-exposure control. The IDs must not be silently
repurposed.

Amazon S3 already provides SSE-S3 baseline encryption for new uploads, so the absence of an
explicit bucket default does not prove that objects are unencrypted. This prototype also does not
assess algorithm, KMS key ownership, bucket-policy enforcement, sensitive-data classification, or
existing object history. A future KMS requirement must use the assessment profile's organization
policy and its own canonical control semantics.

## `IAM-001` — IAM user without MFA

`IAM-001` fails when an IAM user's collected `mfa_devices` list is valid and empty. A valid
non-empty list passes. Missing or malformed device evidence is insufficient; no IAM users is not
applicable.

Sprint 1 does not collect policies, groups, effective permissions, console-login state, or device
health. The control therefore assigns `MEDIUM` severity without guessing whether a user is
privileged. Evidence records that privilege assessment is unavailable.

## `LOG-001` — CloudTrail missing

`LOG-001` assesses the AWS account once. It passes when any normalized `cloudtrail_trail` has
`configuration.is_logging` explicitly set to `true`. Zero trails or only inactive trails fails.
A returned trail with a missing or non-boolean status produces insufficient evidence.

The current definition does not require multi-Region coverage, global service events, management
event coverage, log-file validation, KMS encryption, CloudWatch Logs delivery, organization-trail
ownership, or destination health. Those are distinct future controls or refinements.

## Collection boundary and limitations

Collectors remain facts-only: they do not assign severity, make pass/fail decisions, attach NIST
metadata, claim compliance, or recommend remediation. Rules consume normalized facts and do not
call AWS.

The current `InventoryService` records each requested collector as `SUCCEEDED`, `FAILED`, or
`PARTIAL` and continues independent collectors after sanitized collection failures. A rule whose
required collector was not requested or did not succeed returns `INSUFFICIENT_EVIDENCE`; it cannot
turn unknown coverage into `PASS`, `FAIL`, or `NOT_APPLICABLE`. The legacy failure-only interface
raises instead. Persisted scan-level collection status and provenance belong to Sprint 3.

Sprint 2.1 intentionally excluded assessment persistence, lifecycle management, scan/control API
endpoints, and authentication; Sprints 3 and 4 now supply those foundations. AWS resource/API
scope expansion, additional controls, Terraform, remediation, frontend work, and AI functionality
remain deferred.
