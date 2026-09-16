# Sprint 5 control-to-evidence readiness

Status: canonical evidence-readiness plan with accepted 5A evidence and the in-review 5B evidence
producer reflected; this document does not enable any Sprint 6 rule.

This matrix connects the immutable meanings in the [control catalog](catalog.md) to the factual
AWS evidence Sprint 5 must collect. The final token in every `Slice / state` cell uses this closed
vocabulary; the scheduling text before the slash is not a state:

| State | Exact meaning |
| --- | --- |
| `CURRENT` | The current runtime provides the named decision-relevant fact. Only that fact is current; any separately named later-slice normalization, relationship, enrichment, or executable rule remains unimplemented unless stated otherwise. This state never claims a rule exists beyond the accepted Sprint 0--4 controls. |
| `EXPAND` | The required AWS source and normalized evidence contract are identified, but the Sprint 5 collector, persistence, and integration work has not been implemented or accepted. |
| `CONTRACT_READY` | A formerly blocking domain or policy decision has an accepted standalone contract. This is not an implementation-completion state: the Sprint 5 evidence producer/persistence and Sprint 6 executable rule remain unimplemented unless separately identified as accepted behavior. |

No other matrix state is valid. `CONTRACT_READY` is orthogonal to evidence implementation and is
not a successor to `EXPAND`; it records that Sprint 5 can implement against an approved decision.

## Common evidence and failure contract

Every normalized observation must retain:

- preallocated scan ID and verified 12-digit collection account from STS identity;
- stable resource identity, resource type, and the separately controlled resource-owner account
  where it differs from the collection account;
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

That collector-level rule describes the Sprint 0--4 legacy runtime. Expanded collectors must use
the accepted [result-sensitive source-outcome contract](../design-decisions/0002-result-sensitive-evidence-outcomes.md)
to separate account-scope discovery from resource enrichment, retain valid facts when another
source is incomplete, and record a typed outcome for every promised source. A `PASS` still
requires every source that its versioned control declares decision-required. A coherent fact may
produce `FAIL` despite a different unknown source only when the control's exact aggregation
contract permits it, as S3-002 does; `PARTIAL` is never a generic completeness bypass. The shared
domain/persistence boundary, the accepted 5A EC2/EBS producer, and the in-review 5B network
producers are integrated; no Sprint 6 rule consumes source outcomes yet.

## IAM controls

| Control | AWS APIs and read permissions | Scope | Normalized evidence and relationships | Missing-evidence behavior | Slice / state |
| --- | --- | --- | --- | --- | --- |
| `IAM-001` | `ListUsers`, `ListMFADevices`; `iam:ListUsers`, `iam:ListMFADevices` | IAM global; users emitted once per account | accepted complete `mfa_devices[]` remains embedded for Sprint 0--4 compatibility; 5C normalizes each observed device as a top-level `iam_mfa_device` `Resource` + `ResourceSnapshot` and emits user -> MFA-device | Incomplete user/MFA enumeration or malformed device identity -> `INSUFFICIENT_EVIDENCE` | Existing Sprint 1; 5C relationship normalization / `CURRENT` |
| `IAM-002` | `ListAccessKeys`; `iam:ListAccessKeys` | IAM global | accepted key facts remain embedded for Sprint 0--4 compatibility; 5C normalizes each observed key ID, `status`, and `create_date` as a top-level `iam_access_key` `Resource` + `ResourceSnapshot`, emits user -> access-key, and uses snapshot collection time as the age anchor | Incomplete enumeration or missing active-key status/date -> `INSUFFICIENT_EVIDENCE` | 5C verification and relationship normalization / `CURRENT` |
| `IAM-003` | `ListAccessKeys`, `GetAccessKeyLastUsed`; `iam:ListAccessKeys`, `iam:GetAccessKeyLastUsed` | IAM global | access-key `Resource` + `ResourceSnapshot`; key creation date/status; last-used date; explicit successful `no_recorded_use` state; user -> access key; observation time | Failed lookup or ambiguous missing last-use/creation state -> `INSUFFICIENT_EVIDENCE` | 5C / `EXPAND` |
| `IAM-004` | `ListUsers`, `GetUser`, `ListGroups`, paginated `GetGroup`, `ListRoles`, `GetRole`, `ListPolicies(Scope=Local)`, `GetPolicy`, `GetPolicyVersion`, all `ListAttached*Policies`, all `List*Policies`, `GetUserPolicy`, `GetGroupPolicy`, `GetRolePolicy`, and `ListPolicyTags`/`ListRoleTags`; corresponding `iam:` actions | IAM global | every user, group, role, managed policy, inline policy, permissions boundary target, and policy version used by an edge is a top-level `Resource` + `ResourceSnapshot`; managed policy ARN + default VersionId/document; inline owner + policy name/document + snapshot/content digest; exact policy structures; identity -> managed/inline policy and boundary, managed policy -> default version, user -> group | Incomplete enumeration, undecodable/malformed document, missing managed default version, missing inline owner/name/snapshot/digest, or unresolved in-scope relationship -> `INSUFFICIENT_EVIDENCE` | 5C / `EXPAND` |
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
| `NET-003` | `DescribeSecurityGroups`; `ec2:DescribeSecurityGroups` | Regional | ingress `ip_protocol`, ports where applicable, `/0` IPv4/IPv6 CIDRs, group/prefix sources; security group -> VPC | Missing or malformed all-protocol/source evidence -> `INSUFFICIENT_EVIDENCE` | 5B evidence validation current; Sprint 6 rule pending / `CURRENT` |
| `NET-004` | `DescribeSecurityGroups`; `ec2:DescribeSecurityGroups` | Regional | complete protocol/port-range/public-CIDR evidence; profile-supplied high-risk ports; security group -> VPC | Missing profile or decision-relevant rule fact -> `INSUFFICIENT_EVIDENCE` | 5B evidence validation current; Sprint 6 rule/profile extension pending / `CURRENT` |
| `NET-005` | `DescribeSecurityGroups`, `DescribeVpcs`; `ec2:DescribeSecurityGroups`, `ec2:DescribeVpcs` | Regional | exact `group_name`; `is_default` derived from `GroupName == "default"` plus valid VPC ID; complete ingress/egress; default security group -> VPC | Uncertain group/VPC identity or incomplete ingress/egress -> `INSUFFICIENT_EVIDENCE` | 5B evidence current; Sprint 6 rule pending / `CURRENT` |
| `NET-006` | one paginated Regional `DescribeVpcs` and one paginated Regional `DescribeFlowLogs`; `ec2:DescribeVpcs`, `ec2:DescribeFlowLogs` | Regional | VPC identity and complete case-sensitive tags; Flow Log ID, `ResourceId`, `FlowLogStatus`, `TrafficType`, destination type/name/ARN; exact Flow Log `ResourceId` -> collected VPC ID | Absent/blank `Environment`, invalid profile, or incomplete VPC/Flow Log evidence -> `INSUFFICIENT_EVIDENCE`; complete environment outside policy -> `NOT_APPLICABLE` | 5B evidence current; Sprint 6 rule/profile extension pending / `CURRENT` |

The security-group contracts do not claim end-to-end reachability. Route tables, network ACLs,
firewalls, load balancers, and host controls are outside these initial syntactic rules.

The in-review 5B runtime keeps `DescribeSecurityGroups` in the accepted `security_groups`
collector so independent VPC, subnet, or Flow Log failures cannot erase independently admissible
same-account NET-001/NET-002 evidence. An external-owner group whose resolved-edge proof is
unavailable is pruned and makes that collector `PARTIAL`. The graph path emits top-level
`security_group` resources with authoritative `OwnerId`,
exact `group_name`/derived `is_default`, complete ingress and egress structures, tags, and
security-group -> VPC observations. A separate `vpc_network_evidence` collector emits top-level
`vpc`, `subnet`, and `vpc_flow_log` resources from independently paginated `DescribeVpcs`,
`DescribeSubnets`, and `DescribeFlowLogs`. It preserves VPC owner/state/CIDR/default context,
subnet owner/VPC/Availability Zone/public-IP-assignment context, and complete Flow Log status,
traffic, destination, delivery, and aggregation context.

All four Regional APIs produce declared discovery artifacts/outcomes, and every retained resource
has an identity-authoritative enrichment artifact/outcome. Valid siblings survive partial sources;
operational, malformed, and conflicting evidence remains typed and sanitized. Relationships are
security group -> VPC, VPC -> subnet, and VPC -> VPC-scoped Flow Log with same-scan provenance.
Subnet and Flow Log edges require an exact collected VPC identity in the same owner/collection
context and Region. A Flow Log whose `ResourceId` names a subnet, interface, or transit gateway is
retained as evidence but does not produce a VPC edge. These facts are in acceptance; they do not
register or execute NET-003 through NET-006.

An external-owner resource without any exact resolved same-scan edge cannot satisfy the accepted
exceptional-owner admission contract. Assembly excludes that resource and its resource-scoped
enrichment records. Its complete discovery artifact preserves the AWS-observed ID, records the
canonical rejected identity in `unadmitted_resources`, and sets `admission_complete = false`
without changing the truthful `PRESENT` source state. The shared evidence rollup derives
`PARTIAL` from that digest-bound gap. Valid same-account siblings remain available, but
NET-001/NET-002 and future joined controls cannot treat either the pruned projection or the
`PRESENT` discovery state alone as complete admitted coverage.

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
| `EC2-001` | `DescribeInstances`; `ec2:DescribeInstances` | Regional | instance ID/ARN and `metadata_options.state`, `http_endpoint`, `http_tokens`; typed instance -> VPC/subnet references | Missing/malformed options or `state = pending` -> `INSUFFICIENT_EVIDENCE`; only `state = applied` permits PASS/FAIL or disabled-endpoint `NOT_APPLICABLE` | 5A evidence; Sprint 6 rule pending / `CURRENT` |
| `EC2-002` | `DescribeInstances`; `ec2:DescribeInstances` | Regional | deduplicated public IPv4s from instance `PublicIpAddress`, every `NetworkInterfaces[].Association.PublicIp`, and every `NetworkInterfaces[].PrivateIpAddresses[].Association.PublicIp`; a complete empty set is explicit absence; instance/account/Region/state/tags; typed instance -> subnet/VPC/all interface security-group references | Malformed/incomplete instance or ENI association structure, or unavailable profile allowlist -> `INSUFFICIENT_EVIDENCE` | 5A evidence; Sprint 6 rule pending / `CURRENT` |
| `EC2-003` | `DescribeVolumes`; `ec2:DescribeVolumes` | Regional | volume ID/ARN, state, `encrypted`, optional KMS key ID, attachment instance IDs; same-scan EC2 instance -> EBS volume | Missing/malformed encryption state -> `INSUFFICIENT_EVIDENCE` | 5A evidence; Sprint 6 rule pending / `CURRENT` |
| `EC2-004` | `GetEbsEncryptionByDefault`, `GetEbsDefaultKmsKeyId`; `ec2:GetEbsEncryptionByDefault`, `ec2:GetEbsDefaultKmsKeyId` | Account + Region setting | account/Region source observations, not synthetic resources; `ebs_encryption_by_default`; optional default KMS key ID with explicit expected absence | Failed/malformed Regional setting -> `INSUFFICIENT_EVIDENCE` | 5A evidence; Sprint 6 rule pending / `CURRENT` |

5A retains instance -> security group, instance -> EBS volume, instance -> subnet, and instance ->
VPC observations for later investigation and joined controls. Instances and volumes are paginated
independently. A same-scan volume can resolve; security-group, subnet, and VPC targets remain typed
owner-unresolved references because `DescribeInstances` does not establish their owner account.
The Regional EBS default is one account/Region observation, not a volume and not a global
resource.

## S3 controls

| Control | AWS APIs and read permissions | Scope | Normalized evidence and relationships | Missing-evidence behavior | Slice / state |
| --- | --- | --- | --- | --- | --- |
| `S3-001` | `ListBuckets`; bucket-client `GetPublicAccessBlock`; account-level `s3control.GetPublicAccessBlock(AccountId=...)`; `s3:ListAllMyBuckets`, `s3:GetBucketPublicAccessBlock`, `s3:GetAccountPublicAccessBlock` | Account discovery once; account BPA once; bucket follow-up in bucket Region | all four account and bucket BPA booleans plus explicit absent configuration; account -> bucket context | Expected `NoSuchPublicAccessBlockConfiguration` is a complete all-false factual state, not a collection failure; denied, partial, malformed, or unexpected failures -> `INSUFFICIENT_EVIDENCE` | 5E account BPA / `EXPAND` |
| `S3-002` | `GetBucketPolicy`, `GetBucketPolicyStatus`, `GetBucketAcl`, bucket `GetPublicAccessBlock`, and account-level `s3control.GetPublicAccessBlock(AccountId=...)`; `s3:GetBucketPolicy`, `s3:GetBucketPolicyStatus`, `s3:GetBucketAcl`, `s3:GetBucketPublicAccessBlock`, `s3:GetAccountPublicAccessBlock`; Analyzer facts remain supplementary | Bucket-home-Region direct facts; account BPA once; Regional analyzer context is non-decisive | complete decoded policy/principals/actions/resources/conditions and digest; `IsPublic`; ACL owner/grants; four account+bucket BPA flags; exact versioned `s3_exposure_approvals`; stable policy/ACL evidence references | Expected no-policy/no-BPA responses are explicit absence/all-false facts. One coherent unapproved channel can `FAIL`; otherwise any denied, malformed, contradictory, unsupported, or required-missing channel -> `INSUFFICIENT_EVIDENCE` under the canonical table | 5E direct collection; 5D supplementary context / `CONTRACT_READY` |
| `S3-003` | `GetBucketPolicy`; `s3:GetBucketPolicy` | Bucket-home Region | `policy_present`; complete decoded statements preserving effect, principal, actions, bucket/object resources, and `aws:SecureTransport` conditions | Expected `NoSuchBucketPolicy` is complete `policy_present = false`, not a collection failure; denied, undecodable, malformed, or partial evidence -> `INSUFFICIENT_EVIDENCE` | 5E / `EXPAND` |
| `S3-004` | `GetBucketEncryption`, `GetBucketTagging`, and deduplicated `DescribeKey` for each explicit KMS key reference; `s3:GetEncryptionConfiguration`, `s3:GetBucketTagging`, `kms:DescribeKey` | Bucket-home Region; referenced KMS key Region | exact account/Region/ARN/stable bucket identity and complete tags consumed by classifier schema `1.0.0`; explicit no-configuration versus `AES256`, `aws:kms`, or `aws:kms:dsse`; bucket-key flag; KMS key ID/ARN and `KeyManager`; S3 bucket -> KMS key | Expected no-encryption/no-tag responses, SSE-S3, AWS-managed KMS, and customer-managed KMS are distinct facts. Missing configured classification metadata -> classifier `INSUFFICIENT_EVIDENCE`; operational/malformed encryption or KMS evidence remains incomplete. No encryption state maps to Sprint 6 `PASS`/`FAIL` in this preflight | 5E classifier prerequisite / `CONTRACT_READY` |

Supporting S3 context uses `GetBucketLocation` (`s3:GetBucketLocation`), `GetBucketVersioning`
(`s3:GetBucketVersioning`), and `GetBucketOwnershipControls`
(`s3:GetBucketOwnershipControls`). These facts support investigation and future refinements even
when they are not the minimum input to one of the four canonical results. The exposure evidence
must preserve normalized principals and complete policy structure required by the canonical
[S3-002 aggregation contract](s3-002-exposure-aggregation.md). An operational Finding Exception
never turns an exposed bucket into `PASS`. A successful expected-absence response is a normalized
fact, while
AccessDenied, throttling, transport failure, unexpected service errors, or malformed content are
collection failures. KMS key descriptions are cached by Region and key reference so shared keys
are not queried once per bucket. The approved
[S3-004 classifier contract](s3-004-sensitive-bucket-classifier.md) limits classification inputs
to exact full bucket identities, restricted full-name patterns, and exact tags; Sprint 5 collects
those facts without classifying the bucket. Its `CONTRACT_READY` state refers only to this
evidence-facing classifier prerequisite, not final Sprint 6 KMS `PASS`/`FAIL` semantics. Sprint 5
must preserve no-explicit-configuration, `AES256`, AWS-managed KMS, customer-managed KMS,
unavailable, and malformed states without assigning compliance. Neither S3 contract enables a
rule or changes an existing control.

## Logging controls

| Control | AWS APIs and read permissions | Scope | Normalized evidence and relationships | Missing-evidence behavior | Slice / state |
| --- | --- | --- | --- | --- | --- |
| `LOG-001` | `ListTrails`, `GetTrail`, `GetTrailStatus`; `cloudtrail:ListTrails`, `cloudtrail:GetTrail`, `cloudtrail:GetTrailStatus` | Account discovery with per-trail home-Region enrichment | trail ARN/home Region and explicit `is_logging`; account -> trail | Incomplete enumeration/status -> `INSUFFICIENT_EVIDENCE` | Existing Sprint 1 / `CURRENT` |
| `LOG-002` | `ListTrails`, `GetTrail`, `GetTrailStatus`, `GetEventSelectors`; `cloudtrail:ListTrails`, `cloudtrail:GetTrail`, `cloudtrail:GetTrailStatus`, `cloudtrail:GetEventSelectors` | Account outcome; trails deduplicated by ARN and enriched in home Region | `is_logging`, `is_multi_region_trail`, `is_organization_trail`; exactly one non-empty selector form; basic raw presence plus defaults (`true`, `All`, empty exclusions) and source-set union, or advanced `FieldSelectors` with all operators; account -> trails | Incomplete/mixed selectors, malformed or unknown exclusions/values, or an advanced set outside the catalog's exact unrestricted-management/readOnly proof subset (including another restricting field) yields `INSUFFICIENT_EVIDENCE` | 5F / `EXPAND` |
| `LOG-003` | `GetTrail`; `cloudtrail:GetTrail` | Trail/home Region | explicit `log_file_validation_enabled` | Missing/malformed setting -> `INSUFFICIENT_EVIDENCE` | 5F / `EXPAND` |
| `LOG-004` | `ListTrails`, `GetTrail`; `cloudtrail:ListTrails`, `cloudtrail:GetTrail`; plus the canonical S3-002 direct evidence set above | Cross-service join: trail home Region -> bucket home Region, which may differ | trail `s3_bucket_name`; typed `delivers_to_bucket` edge; resolved stable bucket ID and exact bucket snapshot; shared S3-002 assessment/evidence | Missing destination, incomplete target identity, unresolved edge, incomplete S3 channel, or unavailable matching S3-002 result -> `INSUFFICIENT_EVIDENCE` | 5E + 5F + 5G / `CONTRACT_READY` |

CloudTrail-to-KMS evidence uses trail `KmsKeyId` and, where inspected, cached
`kms:DescribeKey` evidence;
CloudTrail-to-S3 uses the exact bucket identity discovered by S3. Organization trails visible from
member accounts must retain ownership/type context and must not be presented as complete
organization-wide coverage when the scanner cannot establish that scope. `ListTags` requests are
batched by the API's `ResourceIdList` limit and the result remains attributable to each trail ARN.

## Governance control

| Control | AWS APIs and read permissions | Scope | Normalized evidence and relationships | Missing-evidence behavior | Slice / state |
| --- | --- | --- | --- | --- | --- |
| `GOV-001` | EC2 response tags for instance, volume, VPC, subnet, security group, and Flow Log; S3 `GetBucketTagging`; IAM `ListUserTags`, `ListRoleTags`, `ListPolicyTags`; batched CloudTrail `ListTags`; and matching read permissions | Per resource; only exact profile-governed selectors from the catalog vocabulary | stable resource identity/type; complete case-sensitive tag map; explicit empty tags; `aws:` keys retained but ineligible; usable value is a string containing a non-whitespace character | Failed/partial source or malformed tags -> `INSUFFICIENT_EVIDENCE`; successful empty/no-tag response is complete and can produce missing-tag `FAIL` | 5A instance/volume and 5B VPC/subnet/security-group/Flow Log tags current; 5C--5F expansion and Sprint 6 rule/profile extension pending / `CURRENT` |

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

5D is a fact source and is not, by itself, a complete S3 exposure decision engine. The canonical
S3-002 contract makes Analyzer evidence supplementary and non-decisive for v1.
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
operations—makes Analyzer evidence incomplete and can never itself be interpreted as `PASS` or an
approval. Direct S3 policy, ACL, and BPA evidence remains the v1 decision surface; Analyzer facts
are retained for investigation and a future separately versioned expansion.

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
| Approved public/external S3 exposure | `s3_exposure_approvals` | Approved strict versioned artifact; exact account/Region/ARN/stable bucket identity plus separate public flag and principal tokens | `S3-002`, `LOG-004` |
| Sensitive-bucket classification | `sensitive_bucket_classifier` | Approved classifier schema `1.0.0`; exact account/Region/ARN/stable bucket identities, restricted name patterns, and exact tag pairs only | `S3-004` |
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
  bucket-home Region; retain it as supplementary investigation evidence for S3-002 v1.
- Discover CloudTrail account trails without duplicating shadow/home records; enrich each stable
  trail ARN in its home Region.
- The current Sprint 4 API remains single-Region. Formal scope prevents global duplication now and
  permits a later reviewed multi-Region request model without changing stable identities.

## Relationship requirements

Sprint 5 must preserve these stable typed edges with scan/snapshot provenance:

- EC2 instance -> security group, EBS volume, subnet, and VPC;
- security group -> owning VPC;
- VPC -> subnet and VPC-scoped Flow Log;
- IAM user -> group, access key, and MFA device;
- IAM user/group/role -> managed or inline policy;
- IAM user/role -> permissions boundary;
- managed policy -> selected default version;
- Access Analyzer finding -> referenced AWS resource;
- S3 bucket -> KMS key;
- CloudTrail trail -> S3 bucket and KMS key.

Every endpoint of a persisted `RESOLVED` relationship is a top-level normalized `Resource` with
the exact `ResourceSnapshot` observed in that scan. This applies uniformly, including IAM access
keys, MFA devices, groups, inline and managed policy records, permissions-boundary targets, and
policy versions; none is a canonical edge endpoint when present only as an embedded child object.
Accepted Sprint 0--4 embedded IAM configuration remains available to existing consumers during an
atomic Sprint 5 transition, but it is compatibility evidence rather than the generic
relationship representation. It may be removed only in a separately reviewed atomic migration
after every consumer has moved to the normalized resources and edges.

The accepted [generic relationship decision](../design-decisions/0001-generic-resource-relationships.md)
uses first-class, versioned, directional observations with stable logical IDs, per-scan IDs,
explicit endpoint account/scope/Region, typed unresolved references, and normalized-evidence
provenance. The Sprint 5 shared foundation implements one generic Alembic-backed representation
and its persistence/service/API integration atomically. It adds no service-specific tables or
graph database. Joined controls must resolve stable identities. A missing, incomplete, or unresolved required edge is treated as `INSUFFICIENT_EVIDENCE`.

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
  [DescribeVolumes](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeVolumes.html),
  [GetEbsEncryptionByDefault](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_GetEbsEncryptionByDefault.html),
  [GetEbsDefaultKmsKeyId](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_GetEbsDefaultKmsKeyId.html),
  and [DescribeSecurityGroups](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSecurityGroups.html)
- [IAM Access Analyzer ListFindingsV2](https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_ListFindingsV2.html)
  and [GetFindingV2](https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_GetFindingV2.html)
- [S3 required API permissions](https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-policy-actions.html)
  and [Block Public Access evaluation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- [CloudTrail GetEventSelectors](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetEventSelectors.html)
  and [CloudTrail identity-policy examples](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/security_iam_id-based-policy-examples.html)

## Phase 0 preflight conclusion and implementation update

The requested IAM, network, EC2/EBS, S3, logging, and governance evidence meanings are canonical.
`LOG-004` composes the separately owned S3-002 result rather than duplicating exposure logic. The
detailed S3-002 aggregation, S3-004 classifier, and generic relationship representation are now
approved and linked above. At the Phase 0 gate, the preflight added no collector, permission,
executable rule, profile registration, database table, API route, or runtime behavior. The
subsequently approved Sprint 5 shared foundation supplies the generic persistence and read-only
API boundary. The accepted 5A EC2/EBS producer supplies its named evidence, and the 5B VPC,
subnet, Flow Log, and security-group graph producers now supply their named evidence while
undergoing acceptance. The 5C--5F producers and every Sprint 6 rule consumer remain in their named
future slices.

Sprint 5 is `IN PROGRESS`, 5A is accepted, 5B is in acceptance, and Sprint 6 remains `PLANNED`.
The complete Phase 0 validation and independent-review gates passed. The canonical
control-contract readiness marker remains:

`SPRINT_5_CONTROL_CONTRACTS_READY`
