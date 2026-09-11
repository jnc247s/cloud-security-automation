# Sprint 5 control-to-evidence readiness

Status: canonical pre-implementation plan; no Sprint 5 collector or Sprint 6 rule is implemented
by this document.

This matrix connects the immutable meanings in the [control catalog](catalog.md) to the factual
AWS evidence Sprint 5 must collect. `CURRENT` means the accepted Sprint 1 collector already
provides the decision-relevant fact; `EXPAND` means the API and normalized contract are identified
but the evidence is not available until its named Sprint 5 slice is implemented and accepted.
Neither status means the corresponding Sprint 6 rule exists.

## Common evidence and failure contract

Every normalized observation must retain:

- preallocated scan ID and AWS account from verified STS identity;
- stable resource identity and resource type;
- `global`, requested Regional, or bucket-home-Region scope;
- collector name, AWS service/API source, and timezone-aware collection time;
- validated, versioned normalized configuration and its digest; and
- the collector outcome needed to distinguish complete empty evidence from failed or partial
  collection.

All listed APIs are read-only. A denied/throttled AWS operation remains an operational collection
failure; malformed required responses use the sanitized evidence-error boundary; programming
defects remain visible. A control that depends on an unrequested, `FAILED`, or `PARTIAL` collector
must later return `INSUFFICIENT_EVIDENCE`, never `PASS`. An empty successful resource list can
produce `NOT_APPLICABLE` only for a resource-scoped control whose contract permits it.

## IAM controls

| Control | AWS APIs and read permissions | Scope | Normalized evidence and relationships | Missing-evidence behavior | Slice / state |
| --- | --- | --- | --- | --- | --- |
| `IAM-001` | `ListUsers`, `ListMFADevices`; `iam:ListUsers`, `iam:ListMFADevices` | IAM global; users emitted once per account | `iam_user.user_id`, ARN, complete `mfa_devices[]`; user -> MFA-device child evidence | Incomplete user/MFA enumeration or malformed device identity -> `INSUFFICIENT_EVIDENCE` | Existing Sprint 1 / `CURRENT` |
| `IAM-002` | `ListAccessKeys`; `iam:ListAccessKeys` | IAM global | user identity; complete access-key IDs, `status`, `create_date`; user -> access-key child evidence; snapshot collection time is the age anchor | Incomplete enumeration or missing active-key status/date -> `INSUFFICIENT_EVIDENCE` | 5C verification/expansion / `CURRENT` facts |
| `IAM-003` | `ListAccessKeys`, `GetAccessKeyLastUsed`; `iam:ListAccessKeys`, `iam:GetAccessKeyLastUsed` | IAM global | key creation date/status; last-used date; explicit successful `no_recorded_use` state; user -> access key; observation time | Failed lookup or ambiguous missing last-use/creation state -> `INSUFFICIENT_EVIDENCE` | 5C / `EXPAND` completeness semantics |
| `IAM-004` | `ListUsers`, `GetUser`, `ListGroups`, paginated `GetGroup`, `ListRoles`, `GetRole`, `ListPolicies(Scope=Local)`, `GetPolicy`, `GetPolicyVersion`, all `ListAttached*Policies`, all `List*Policies`, `GetUserPolicy`, `GetGroupPolicy`, `GetRolePolicy`, and `ListPolicyTags`/`ListRoleTags`; corresponding `iam:` actions | IAM global | managed policy ARN + default VersionId/document; inline owner + policy name/document + snapshot/content digest; customer-managed, AWS-managed referenced by attachment or boundary, trust, and boundary context; exact policy structures; identity -> managed/inline policy and boundary, managed policy -> default version, user -> group | Incomplete enumeration, undecodable/malformed document, missing managed default version, missing inline owner/name/snapshot/digest, or unresolved in-scope relationship -> `INSUFFICIENT_EVIDENCE` | 5C / `EXPAND` |
| `IAM-005` | `GetAccountSummary`; `iam:GetAccountSummary` | Account/global; one observation per account | `AccountAccessKeysPresent` strictly validated as AWS's integer `0`/`1` presence flag, then normalized to boolean | Missing key, any value other than integer `0`/`1`, or failed summary call -> `INSUFFICIENT_EVIDENCE` | 5C / `EXPAND` |
| `IAM-006` | `GetAccountSummary`; `iam:GetAccountSummary` | Account/global; one observation per account | `AccountMFAEnabled` strictly validated as AWS's integer `0`/`1` presence flag, then normalized to boolean | Missing key, any value other than integer `0`/`1`, or failed summary call -> `INSUFFICIENT_EVIDENCE` | 5C / `EXPAND` |

IAM policy collection is intentionally evidence preservation, not an implementation of AWS's
authorization engine. Customer-managed, referenced AWS-managed, and inline identity policies are
the initial `IAM-004` scope. Use `ListPolicies(Scope=Local)` for account-managed discovery, then
add only AWS-managed policy ARNs referenced by collected identity attachments or user/role
permissions-boundary ARNs before
`GetPolicy` and `GetPolicyVersion`; do not enumerate every AWS-managed policy. Paginated
`ListGroups` plus paginated `GetGroup` is the single membership strategy. `GetUser` and `GetRole`
supply permissions-boundary context that their list responses do not guarantee. Role trust
policies remain outside v1 and can return `NOT_APPLICABLE`. A boundary-only customer-managed
policy remains an in-scope permissions-policy document; its one policy-version assessment retains
the boundary relationship and must not be presented as attached or effective administrator access.

## Network controls

| Control | AWS APIs and read permissions | Scope | Normalized evidence and relationships | Missing-evidence behavior | Slice / state |
| --- | --- | --- | --- | --- | --- |
| `NET-001` | `DescribeSecurityGroups`; `ec2:DescribeSecurityGroups` | Regional | stable group/VPC IDs; complete ingress protocol, ports, IPv4/IPv6 CIDRs, group and prefix references; security group -> VPC | Incomplete/malformed ingress or collector coverage -> `INSUFFICIENT_EVIDENCE` | Existing Sprint 1 / `CURRENT` |
| `NET-002` | `DescribeSecurityGroups`; `ec2:DescribeSecurityGroups` | Regional | same complete ingress structure as `NET-001`; security group -> VPC | Same fail-closed behavior as `NET-001` | Existing Sprint 1 / `CURRENT` |
| `NET-003` | `DescribeSecurityGroups`; `ec2:DescribeSecurityGroups` | Regional | ingress `ip_protocol`, ports where applicable, `/0` IPv4/IPv6 sources, group/prefix sources; security group -> VPC | Missing or malformed all-protocol/source evidence -> `INSUFFICIENT_EVIDENCE` | 5B validation / `CURRENT` facts |
| `NET-004` | `DescribeSecurityGroups`; `ec2:DescribeSecurityGroups` | Regional | complete protocol/port-range/public-CIDR evidence; profile-supplied high-risk ports; security group -> VPC | Missing profile or decision-relevant rule fact -> `INSUFFICIENT_EVIDENCE` | 5B validation plus Sprint 6 profile extension / `CURRENT` facts |
| `NET-005` | `DescribeSecurityGroups`, `DescribeVpcs`; `ec2:DescribeSecurityGroups`, `ec2:DescribeVpcs` | Regional | exact `group_name`; `is_default` derived from `GroupName == "default"` plus valid VPC ID; complete ingress/egress; default security group -> VPC | Uncertain group/VPC identity or incomplete ingress/egress -> `INSUFFICIENT_EVIDENCE` | 5B / `EXPAND` explicit default context |
| `NET-006` | one paginated Regional `DescribeVpcs` and one paginated Regional `DescribeFlowLogs`; `ec2:DescribeVpcs`, `ec2:DescribeFlowLogs` | Regional | VPC identity and complete case-sensitive tags; Flow Log ID, `ResourceId`, `FlowLogStatus`, `TrafficType`, destination type/name/ARN; exact Flow Log `ResourceId` -> collected VPC ID | Absent/blank `Environment`, invalid profile, or incomplete VPC/Flow Log evidence -> `INSUFFICIENT_EVIDENCE`; complete environment outside policy -> `NOT_APPLICABLE` | 5B / `EXPAND` |

The security-group contracts do not claim end-to-end reachability. Route tables, network ACLs,
firewalls, load balancers, and host controls are outside these initial syntactic rules.

For `NET-006`, v1 applicability is the exact case-sensitive value of the VPC tag named
`Environment`. A complete non-empty value outside `vpc_flow_log_required_environments` is
`NOT_APPLICABLE`; an absent, non-string, or whitespace-only value is
`INSUFFICIENT_EVIDENCE`. An applicable VPC qualifies only through a Flow Log whose
`ResourceId` exactly matches a validated VPC ID collected in the same account and Region, whose
`FlowLogStatus` is `ACTIVE`, and whose exact `TrafficType` appears in the profile's non-empty
subset of `REJECT` and `ALL`. AWS does not return a Flow Log `ResourceType`; the exact identity
join supplies the VPC scope. Subnet/interface Flow Logs and `ACCEPT`-only coverage do not satisfy
this contract.

## EC2 and EBS controls

| Control | AWS APIs and read permissions | Scope | Normalized evidence and relationships | Missing-evidence behavior | Slice / state |
| --- | --- | --- | --- | --- | --- |
| `EC2-001` | `DescribeInstances`; `ec2:DescribeInstances` | Regional | instance ID/ARN and `metadata_options.state`, `http_endpoint`, `http_tokens`; instance -> VPC/subnet context | Missing/malformed options or `state = pending` -> `INSUFFICIENT_EVIDENCE`; only `state = applied` permits PASS/FAIL or disabled-endpoint `NOT_APPLICABLE` | 5A / `EXPAND` |
| `EC2-002` | `DescribeInstances`; `ec2:DescribeInstances` | Regional | deduplicated public IPv4s from instance `PublicIpAddress`, every `NetworkInterfaces[].Association.PublicIp`, and every `NetworkInterfaces[].PrivateIpAddresses[].Association.PublicIp`; a complete empty set is explicit absence; instance/account/Region/state/tags; instance -> subnet/VPC/all interface security groups | Malformed/incomplete instance or ENI association structure, or unavailable profile allowlist -> `INSUFFICIENT_EVIDENCE` | 5A / `EXPAND` |
| `EC2-003` | `DescribeVolumes`; `ec2:DescribeVolumes` | Regional | volume ID/ARN, state, `encrypted`, optional KMS key ID, attachment instance IDs; EC2 instance -> EBS volume | Missing/malformed encryption state -> `INSUFFICIENT_EVIDENCE` | 5A / `EXPAND` |
| `EC2-004` | `GetEbsEncryptionByDefault`, `GetEbsDefaultKmsKeyId`; `ec2:GetEbsEncryptionByDefault`, `ec2:GetEbsDefaultKmsKeyId` | Account + Region setting | synthetic account/Region evidence identity; `ebs_encryption_by_default`; optional default KMS key ID | Failed/malformed Regional setting -> `INSUFFICIENT_EVIDENCE` | 5A / `EXPAND` |

5A must also retain instance -> security group, instance -> EBS volume, instance -> subnet, and
instance -> VPC edges for later investigation and joined controls. Instances and volumes are
paginated independently. The Regional EBS default is one account/Region observation, not a volume
and not a global resource.

## S3 controls

| Control | AWS APIs and read permissions | Scope | Normalized evidence and relationships | Missing-evidence behavior | Slice / state |
| --- | --- | --- | --- | --- | --- |
| `S3-001` | `ListBuckets`; bucket-client `GetPublicAccessBlock`; account-level `s3control.GetPublicAccessBlock(AccountId=...)`; `s3:ListAllMyBuckets`, `s3:GetBucketPublicAccessBlock`, `s3:GetAccountPublicAccessBlock` | Account discovery once; account BPA once; bucket follow-up in bucket Region | all four account and bucket BPA booleans plus explicit absent configuration; account -> bucket context | Expected `NoSuchPublicAccessBlockConfiguration` is a complete all-false factual state, not a collection failure; denied, partial, malformed, or unexpected failures -> `INSUFFICIENT_EVIDENCE` | 5E / `EXPAND` account BPA |
| `S3-002` | Candidate direct sources: `GetBucketPolicy`, `GetBucketPolicyStatus`, `GetBucketAcl`, and both BPA calls; `s3:GetBucketPolicy`, `s3:GetBucketPolicyStatus`, `s3:GetBucketAcl`, `s3:GetBucketPublicAccessBlock`, `s3:GetAccountPublicAccessBlock`; Analyzer facts where available | Bucket-home-Region facts plus account BPA and Regional analyzer context | decoded policy/principals/actions/resources/conditions; `IsPublic`; ACL owner/grants; account+bucket BPA; analyzer finding edge | Operational/malformed sources remain incomplete. The accepted catalog does not yet define exact approval or source-aggregation semantics, so the minimum decisive evidence set cannot be declared here | Separate S3 contract review required before 5D/5E acceptance / `BLOCKED` |
| `S3-003` | `GetBucketPolicy`; `s3:GetBucketPolicy` | Bucket-home Region | `policy_present`; complete decoded statements preserving effect, principal, actions, bucket/object resources, and `aws:SecureTransport` conditions | Expected `NoSuchBucketPolicy` is complete `policy_present = false`, not a collection failure; denied, undecodable, malformed, or partial evidence -> `INSUFFICIENT_EVIDENCE` | 5E / `EXPAND` |
| `S3-004` | Candidate sources: `GetBucketEncryption`, `GetBucketTagging`, and deduplicated `DescribeKey` for each explicit KMS key reference; `s3:GetEncryptionConfiguration`, `s3:GetBucketTagging`, `kms:DescribeKey` | Bucket-home Region; referenced KMS key Region | explicit encryption-present state, `SSEAlgorithm`, bucket-key flag, KMS key ID/ARN and `KeyManager`, complete tags; S3 bucket -> KMS key | Expected no-encryption/no-tag responses and SSE-S3/AWS-managed-KMS states are explicit facts; operational/malformed evidence is incomplete. The repository lacks a versioned sensitive-bucket classification selector, so decisive evidence cannot be finalized | Separate S3 contract review required before 5E acceptance / `BLOCKED` |

Supporting S3 context uses `GetBucketLocation` (`s3:GetBucketLocation`), `GetBucketVersioning`
(`s3:GetBucketVersioning`), and `GetBucketOwnershipControls`
(`s3:GetBucketOwnershipControls`). These facts support investigation and future refinements even
when they are not the minimum input to one of the four canonical results. The exposure evidence
must preserve raw normalized principals and policy structure so a later separately approved
`S3-002` contract does not require recollection. An operational Finding Exception never turns an
exposed bucket into `PASS`. A successful expected-absence response is a normalized fact, while
AccessDenied, throttling, transport failure, unexpected service errors, or malformed content are
collection failures. KMS key descriptions are cached by Region and key reference so shared keys
are not queried once per bucket. This matrix deliberately does not invent S3-002 approval,
condition, Block Public Access aggregation, or Access Analyzer decision semantics, and it does not
invent a sensitive-bucket classifier for S3-004. Because the accepted catalog has only those
immutable one-line meanings, S3-002, S3-004, and therefore LOG-004 still need a separately
authorized canonical-contract review before Sprint 5 evidence readiness is complete.

## Logging controls

| Control | AWS APIs and read permissions | Scope | Normalized evidence and relationships | Missing-evidence behavior | Slice / state |
| --- | --- | --- | --- | --- | --- |
| `LOG-001` | `ListTrails`, `GetTrail`, `GetTrailStatus`; `cloudtrail:ListTrails`, `cloudtrail:GetTrail`, `cloudtrail:GetTrailStatus` | Account discovery with per-trail home-Region enrichment | trail ARN/home Region and explicit `is_logging`; account -> trail | Incomplete enumeration/status -> `INSUFFICIENT_EVIDENCE` | Existing Sprint 1 / `CURRENT` |
| `LOG-002` | `ListTrails`, `GetTrail`, `GetTrailStatus`, `GetEventSelectors`; `cloudtrail:ListTrails`, `cloudtrail:GetTrail`, `cloudtrail:GetTrailStatus`, `cloudtrail:GetEventSelectors` | Account outcome; trails deduplicated by ARN and enriched in home Region | `is_logging`, `is_multi_region_trail`, `is_organization_trail`; exactly one non-empty selector form; basic raw presence plus defaults (`true`, `All`, empty exclusions) and source-set union, or advanced `FieldSelectors` with all operators; account -> trails | Incomplete/mixed selectors, malformed or unknown exclusions/values, or an advanced set outside the catalog's exact unrestricted-management/readOnly proof subset (including another restricting field) yields `INSUFFICIENT_EVIDENCE` | 5F / `EXPAND` selectors |
| `LOG-003` | `GetTrail`; `cloudtrail:GetTrail` | Trail/home Region | explicit `log_file_validation_enabled` | Missing/malformed setting -> `INSUFFICIENT_EVIDENCE` | 5F / `EXPAND` validated contract |
| `LOG-004` | `ListTrails`, `GetTrail`; `cloudtrail:ListTrails`, `cloudtrail:GetTrail`; plus the eventual canonical S3-002 evidence set | Cross-service join: trail home Region -> global S3 bucket identity | trail `s3_bucket_name`; resolved bucket stable ID; shared S3-002 evidence; trail -> S3 bucket | Missing destination or unresolved edge -> `INSUFFICIENT_EVIDENCE`; decisive S3 completeness cannot be finalized before the separate S3-002 contract review | 5E + 5F + 5G / `BLOCKED` by S3-002 contract detail |

CloudTrail-to-KMS evidence uses trail `KmsKeyId` and, where inspected, cached
`kms:DescribeKey` evidence;
CloudTrail-to-S3 uses the exact bucket identity discovered by S3. Organization trails visible from
member accounts must retain ownership/type context and must not be presented as complete
organization-wide coverage when the scanner cannot establish that scope. `ListTags` requests are
batched by the API's `ResourceIdList` limit and the result remains attributable to each trail ARN.

## Governance control

| Control | AWS APIs and read permissions | Scope | Normalized evidence and relationships | Missing-evidence behavior | Slice / state |
| --- | --- | --- | --- | --- | --- |
| `GOV-001` | EC2 response tags for instance, volume, VPC, subnet, security group, and Flow Log; S3 `GetBucketTagging`; IAM `ListUserTags`, `ListRoleTags`, `ListPolicyTags`; batched CloudTrail `ListTags`; and matching read permissions | Per resource; only exact profile-governed selectors from the catalog vocabulary | stable resource identity/type; complete case-sensitive tag map; explicit empty tags; `aws:` keys retained but ineligible; usable value is a string containing a non-whitespace character | Failed/partial source or malformed tags -> `INSUFFICIENT_EVIDENCE`; successful empty/no-tag response is complete and can produce missing-tag `FAIL` | 5A–5F collection, 5G completeness validation / `EXPAND` |

The initial governed-type vocabulary has one complete factual source per selector:

| Governed resource type | Complete tag source |
| --- | --- |
| `ec2_instance` | `DescribeInstances.Instances[].Tags` |
| `ebs_volume` | `DescribeVolumes.Volumes[].Tags` |
| `vpc` | `DescribeVpcs.Vpcs[].Tags` |
| `subnet` | `DescribeSubnets.Subnets[].Tags` |
| `security_group` | `DescribeSecurityGroups.SecurityGroups[].Tags` |
| `vpc_flow_log` | `DescribeFlowLogs.FlowLogs[].Tags` |
| `s3_bucket` | `GetBucketTagging.TagSet`; expected `NoSuchTagSet` is an explicit empty map |
| `iam_user` | paginated `ListUserTags.Tags` |
| `iam_role` | paginated `ListRoleTags.Tags` |
| `iam_customer_managed_policy` | paginated `ListPolicyTags.Tags` |
| `cloudtrail_trail` | batched, paginated `ListTags.ResourceTagList` joined by trail ARN |

When `GOV-001` is enabled, future profile validation must require non-empty, unique
`required_tags` and `governed_resource_types`, and reject any governed selector without one of the
complete sources above. Tags are compared using exact key spelling. A value is usable only when it
is a string containing at least one non-whitespace character; the stored evidence is not silently
trimmed or case-folded.

## IAM Access Analyzer supporting evidence

5D is a fact source and is not, by itself, a complete S3 exposure decision engine. The separately
authorized S3-002 contract must decide whether Analyzer evidence is required or supplemental.
`ListAnalyzers` (`access-analyzer:ListAnalyzers`) records analyzer ARN, name, type, status, and
Region; the type captures its zone-of-trust scope. `ListFindingsV2` uses
`access-analyzer:ListFindings` for discovery and records finding ID, type, status, resource
ARN/type, owner account, and timestamps. In each Region, paginate `ListAnalyzers` to token
exhaustion, then paginate `ListFindingsV2` to token exhaustion for each relevant analyzer. Each
discovered relevant finding is then enriched with fully paginated `GetFindingV2` calls
(`access-analyzer:GetFinding`) using the same analyzer ARN and finding ID until `nextToken` is
absent, so every `findingDetails` item is retained and principal, action, condition, `isPublic`,
source, and resource-specific detail are not inferred from a summary.

Access Analyzer is a Regional API; `ACCOUNT` and `ORGANIZATION` describe the analyzer's zone of
trust, not a global endpoint. Query each explicitly requested Region and each additional unique S3
bucket-home Region. Results are deduplicated by analyzer/finding identity and related to matching
stable resources. An absent analyzer after complete Regional enumeration is an explicit fact, not
proof that a resource lacks external access. AccessDenied, incomplete detail, or malformed
pagination—including a repeated, non-progressing, or unconsumed token from any of the three
operations—makes Analyzer evidence incomplete and can never be interpreted as `PASS`; its exact
effect on S3-002 completeness remains part of the blocked S3 contract decision.

## Assessment Profile planning

The documentation task does not alter the immutable `AssessmentProfile` model or profile
`1.0.0`. Sprint 5 collects policy-neutral facts. Sprint 6 must introduce any new serialized fields
with a reviewed schema/version transition and a new profile version.

| Policy meaning | Serialized field | State before Sprint 5 | Controls |
| --- | --- | --- | --- |
| Enabled catalog entries | `enabled_controls` | Existing | all controls |
| Maximum active-key age | existing `stale_key_days` (approved semantic name `max_access_key_age_days`) | Existing, default 90 | `IAM-002` |
| Maximum unused-key period | `max_unused_access_key_days` | Planned profile extension | `IAM-003` |
| High-risk public TCP ports | `high_risk_public_tcp_ports` | Planned profile extension; candidate set is not yet an enabled default | `NET-004` |
| Environments requiring VPC Flow Logs | `vpc_flow_log_required_environments` | Planned non-empty tuple; exact case-sensitive values of VPC tag `Environment` | `NET-006` |
| Acceptable Flow Log traffic coverage | `acceptable_vpc_flow_log_traffic_types` | Planned non-empty tuple constrained to exact `REJECT` and/or `ALL` | `NET-006` |
| Public EC2 allowlist | `public_ec2_exceptions` | Existing policy field; not a Finding Exception | `EC2-002` |
| Required tag keys | `required_tags` | Existing | `GOV-001` |
| Resource types governed by required tags | `governed_resource_types` | Planned non-empty tuple restricted to the catalog's exact tag-source vocabulary | `GOV-001` |
| Sensitive-bucket classification | not defined in the accepted profile | `BLOCKED`; requires separately approved typed/versioned policy rather than an invented tag/value convention | `S3-004` |
| Restricted-data KMS consequence | `restricted_data_requires_kms` | Existing boolean; does not itself classify a bucket | `S3-004` |

No new severity is assigned here. New controls also have no NIST mapping until a separate review
can provide authoritative mapping provenance and scope rationale. Those gaps do not change the AWS
facts Sprint 5 must preserve.

## Global and Regional execution plan

- Resolve STS caller identity once per scan and bind every observation to that account.
- Run IAM and its account summary once with global scope; never once per requested Region.
- Discover S3 buckets and account BPA once, then use a bucket-Region client for bucket APIs.
- Run EC2 instances, EBS, VPCs, subnets, security groups, one paginated Flow Log inventory, and
  Regional EBS defaults once per explicitly requested Region.
- Run IAM Access Analyzer once per explicitly requested Region and each additional unique S3
  bucket-home Region; its eventual decision role remains owned by the blocked S3-002 contract.
- Discover CloudTrail account trails without duplicating shadow/home records; enrich each stable
  trail ARN in its home Region.
- The current Sprint 4 API remains single-Region. Formal scope prevents global duplication now and
  permits a later reviewed multi-Region request model without changing stable identities.

## Relationship requirements

Sprint 5 must preserve these stable typed edges with scan/snapshot provenance:

- EC2 instance -> security group, EBS volume, subnet, and VPC;
- security group -> owning VPC;
- VPC -> subnet and VPC-scoped Flow Log;
- IAM user -> group and access key;
- IAM user/group/role -> managed or inline policy;
- IAM user/role -> permissions boundary;
- managed policy -> selected default version;
- Access Analyzer finding -> referenced AWS resource;
- S3 bucket -> KMS key;
- CloudTrail trail -> S3 bucket and KMS key.

The accepted database has no first-class resource-edge table. Sprint 5 preflight must choose a
single generic representation—versioned typed edges in normalized snapshot configuration or a
justified generic Alembic-backed relationship model—and update persistence/API documentation and
tests atomically. It must not create service-specific tables or a graph database. Joined controls
must resolve stable identities and treat a missing/unresolved edge as insufficient evidence.

## Read-only permission inventory

The exact implementation may omit an action when a slice proves it unnecessary, but it may not
add write actions or wildcards beyond APIs that require resource `*`. The anticipated union is:

```text
sts:GetCallerIdentity

ec2:DescribeInstances
ec2:DescribeVolumes
ec2:GetEbsEncryptionByDefault
ec2:GetEbsDefaultKmsKeyId
ec2:DescribeVpcs
ec2:DescribeSubnets
ec2:DescribeFlowLogs
ec2:DescribeSecurityGroups

iam:GetAccountSummary
iam:ListUsers
iam:GetUser
iam:ListUserTags
iam:ListMFADevices
iam:ListAccessKeys
iam:GetAccessKeyLastUsed
iam:ListGroups
iam:GetGroup
iam:ListRoles
iam:GetRole
iam:ListRoleTags
iam:ListPolicies
iam:GetPolicy
iam:GetPolicyVersion
iam:ListPolicyTags
iam:ListAttachedUserPolicies
iam:ListAttachedGroupPolicies
iam:ListAttachedRolePolicies
iam:ListUserPolicies
iam:ListGroupPolicies
iam:ListRolePolicies
iam:GetUserPolicy
iam:GetGroupPolicy
iam:GetRolePolicy

access-analyzer:ListAnalyzers
access-analyzer:ListFindings
access-analyzer:GetFinding

s3:ListAllMyBuckets
s3:GetBucketLocation
s3:GetBucketTagging
s3:GetBucketPublicAccessBlock
s3:GetAccountPublicAccessBlock
s3:GetBucketPolicy
s3:GetBucketPolicyStatus
s3:GetBucketAcl
s3:GetBucketVersioning
s3:GetEncryptionConfiguration
s3:GetBucketOwnershipControls

cloudtrail:ListTrails
cloudtrail:GetTrail
cloudtrail:GetTrailStatus
cloudtrail:GetEventSelectors
cloudtrail:ListTags

kms:DescribeKey
```

## Authoritative AWS sources

- [IAM API operations](https://docs.aws.amazon.com/IAM/latest/APIReference/Welcome.html),
  [GetAccountSummary](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountSummary.html),
  and [GetPolicyVersion](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetPolicyVersion.html)
- [EC2 API operations](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/),
  [DescribeInstances](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html),
  and [DescribeSecurityGroups](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSecurityGroups.html)
- [IAM Access Analyzer ListFindingsV2](https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_ListFindingsV2.html)
  and [GetFindingV2](https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_GetFindingV2.html)
- [S3 required API permissions](https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-policy-actions.html)
  and [Block Public Access evaluation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- [CloudTrail GetEventSelectors](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetEventSelectors.html)
  and [CloudTrail identity-policy examples](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/security_iam_id-based-policy-examples.html)

## Preflight conclusion

The requested IAM, network, EC2/EBS, logging, and governance meanings are now canonical, except
that LOG-004 intentionally composes the separately owned S3-002 result. Repository review found no
detailed S3-002 approval/source-aggregation contract or S3-004 sensitive-bucket classifier beyond
their immutable reserved meanings. This task was not authorized to redefine existing S3 controls,
so S3-002, S3-004, and decisive LOG-004 evidence remain `BLOCKED`. Sprint 5 preflight is therefore
not fully unblocked. It also still must approve the generic relationship representation before
implementation. Sprint 5 remains `NEXT`, Sprint 6 remains `PLANNED`, and this matrix introduces no
collector, permission, executable rule, or runtime behavior.
