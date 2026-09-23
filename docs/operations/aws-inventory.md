# AWS inventory operations

The accepted Sprint 1 inventory and accepted Sprint 5A EC2/EBS, 5B network, 5C IAM, 5D IAM
Access Analyzer, 5E S3/referenced-KMS, and 5F CloudTrail evidence producers provide a read-only,
on-demand AWS inventory run. The bounded 5F producer was accepted and merged in pull request 24 at
`main` commit `29aeea59b9cceff957adac4fba75cb8ca2c4a592`. Sprint 5 remains `IN PROGRESS`, its 5G
closure remains unstarted, and Sprint 6 remains `PLANNED`. The
standalone command returns a normalized in-memory snapshot and prints only an aggregate summary.
It does not judge compliance, create
control-plane findings, write to PostgreSQL, or modify AWS; the authorized scan executor
separately persists the same snapshot through its existing transaction boundary.

## Real-world operator flow

1. A cloud administrator creates or selects a dedicated read-only audit role.
2. The administrator attaches only the API permissions used by the collectors.
3. An operator authenticates with short-lived credentials, preferably through AWS IAM Identity
   Center, role assumption, or the compute platform's workload identity.
4. The operator verifies the active identity with `aws sts get-caller-identity`.
5. The operator sets `AWS_REGION` and optionally `AWS_PROFILE`.
6. The operator runs `python scripts/run_inventory.py` from the project environment.
7. The application asks STS for the caller account once, then collects:
   - EC2 instances, EBS volumes, and Regional EBS default settings from the configured region;
   - security groups, VPCs, subnets, and VPC Flow Logs from the configured region;
   - all account S3 buckets, account Block Public Access, each bucket's authoritative home Region,
     direct bucket configuration, and explicitly referenced KMS keys;
   - IAM Access Analyzer facts from the configured region and every additional unique Region
     proved by a normalized same-scan S3 bucket;
   - global IAM account-summary, identity, authentication, tag, attachment, inline-policy,
     managed-policy, and default policy-version evidence;
   - account CloudTrail trails, enriched through each trail's home region.
8. Each AWS response crosses explicit structural and typed validation before it is transformed
   into the common `NormalizedResource` contract. AWS timestamps and other SDK values are then
   converted to JSON-safe values.
9. The inventory service records each requested collector as `SUCCEEDED`, `FAILED`, or `PARTIAL`,
   then sorts available resources by stable account/service/scope/region/resource identity and
   returns one `InventorySnapshot`. The 5A through 5F producers also declare
   source contracts and record digest-bound artifacts, typed source outcomes, and relationship
   observations in the optional evidence graph.
10. The command prints collection outcomes and counts by service. Raw resource data is kept out
    of console logs.

The Sprint 4 executor consumes the same snapshot through the rule and persistence layers without
coupling those responsibilities to boto3 collectors. The standalone command remains an
inventory-only diagnostic and does not evaluate or persist results.

## Read-only policy baseline

The following policy is a practical baseline for the exact calls made by the current runtime,
including accepted 5F evidence collection. Review and scope it for your partition, account,
buckets, trails, KMS keys,
permission boundaries, service control policies, and role-assumption model before production use.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "InventoryDiscovery",
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity",
        "ec2:DescribeInstances",
        "ec2:DescribeVolumes",
        "ec2:GetEbsEncryptionByDefault",
        "ec2:GetEbsDefaultKmsKeyId",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeFlowLogs",
        "s3:ListAllMyBuckets",
        "s3:GetAccountPublicAccessBlock",
        "iam:GetAccountSummary",
        "iam:ListUsers",
        "iam:ListGroups",
        "iam:ListRoles",
        "iam:ListPolicies",
        "access-analyzer:ListAnalyzers",
        "access-analyzer:ListFindings",
        "access-analyzer:GetFinding",
        "cloudtrail:ListTrails"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ReadBucketConfiguration",
      "Effect": "Allow",
      "Action": [
        "s3:GetBucketTagging",
        "s3:GetBucketLocation",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketPolicy",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketAcl",
        "s3:GetBucketVersioning",
        "s3:GetBucketOwnershipControls",
        "s3:ListBucket"
      ],
      "Resource": "arn:aws:s3:::*"
    },
    {
      "Sid": "ReadReferencedKmsKeys",
      "Effect": "Allow",
      "Action": "kms:DescribeKey",
      "Resource": "arn:aws:kms:*:*:key/*"
    },
    {
      "Sid": "ReadIamEvidence",
      "Effect": "Allow",
      "Action": [
        "iam:GetUser",
        "iam:ListUserTags",
        "iam:ListMFADevices",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed",
        "iam:GetGroup",
        "iam:GetRole",
        "iam:ListRoleTags",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:ListPolicyTags",
        "iam:ListAttachedUserPolicies",
        "iam:ListAttachedGroupPolicies",
        "iam:ListAttachedRolePolicies",
        "iam:ListUserPolicies",
        "iam:ListGroupPolicies",
        "iam:ListRolePolicies",
        "iam:GetUserPolicy",
        "iam:GetGroupPolicy",
        "iam:GetRolePolicy"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ReadTrailConfiguration",
      "Effect": "Allow",
      "Action": [
        "cloudtrail:GetTrail",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:GetEventSelectors",
        "cloudtrail:ListTags"
      ],
      "Resource": "arn:aws:cloudtrail:*:*:trail/*"
    }
  ]
}
```

`s3:ListBucket` is used only by the legacy `HeadBucket` compatibility fallback. A 5E scan instead
uses `GetBucketLocation` as its authoritative Region source. `kms:DescribeKey` is called only for
an explicit KMS reference returned by bucket encryption configuration; broaden or narrow its
resource scope only after testing the intended key/alias policy in the target account.

## Credentials and configuration

The application delegates credentials to the
[standard boto3 credential provider chain](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html).
It never accepts access-key values as application settings.

For a local IAM Identity Center profile:

```powershell
aws sso login --profile security-audit
$env:AWS_PROFILE = "security-audit"
$env:AWS_REGION = "us-east-1"
aws sts get-caller-identity --profile security-audit
python scripts/run_inventory.py
```

For an EC2, ECS, EKS, or other AWS workload role, leave `AWS_PROFILE` unset and set only the
region. Boto3 resolves the workload identity through its normal chain.

Do not store `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, session tokens, credential-process
output, or SSO cache contents in the repository. `.env` is ignored and should contain only
non-secret local configuration.

## Successful output

The command emits a deliberately small JSON document:

```json
{
  "scan_id": "77f0d7c3-d67e-4e65-9bbf-783414355fdb",
  "account_id": "123456789012",
  "requested_region": "us-east-1",
  "collected_at": "2026-09-02T18:30:00+00:00",
  "collector_outcomes": {
    "access_analyzer_evidence": "SUCCEEDED",
    "cloudtrail_evidence": "SUCCEEDED",
    "cloudtrail_trails": "SUCCEEDED",
    "ec2_ebs_evidence": "SUCCEEDED",
    "iam_account_evidence": "SUCCEEDED",
    "iam_users": "SUCCEEDED",
    "s3_buckets": "SUCCEEDED",
    "s3_evidence": "SUCCEEDED",
    "security_groups": "SUCCEEDED",
    "vpc_network_evidence": "SUCCEEDED"
  },
  "resource_count": 28,
  "resources_by_service": {
    "access-analyzer": 1,
    "cloudtrail": 2,
    "ec2": 8,
    "iam": 5,
    "kms": 1,
    "s3": 12
  }
}
```

Exit code `0` means every collector completed. A successful result with zero resources is
different from a failed collection.

## Failure behavior

An expired login, missing permission, throttling after retries, or a declared incomplete collector
response marks that collector `FAILED` or `PARTIAL`. Independent collectors keep running, and the
command returns exit code `1` whenever any requested collector is incomplete. The sanitized
summary identifies collection coverage without dumping exception text, AWS responses, or resource
configuration. No partial result is presented as complete.

The accepted response boundary separates three cases. Botocore `ClientError`/`BotoCoreError`
means an AWS operational failure. Missing, null, wrong-type, or otherwise unusable required
evidence raises a sanitized `CollectorEvidenceError`. Genuine application defects are not broadly
caught or mislabeled and remain visible to tests and executor observability. A malformed STS
caller-identity response prevents safe account attribution and therefore fails the overall run
with a sanitized identity message.

Validation errors contain only the AWS operation and a structural fact path; they do not echo the
rejected value, response, resource identifier, or credentials. Most Sprint 0--4 legacy collectors
are collector-granular: one malformed item discards results from that collector. The accepted 5A
EC2/EBS, 5B network, 5C IAM, 5D Access Analyzer, 5E S3/KMS, and 5F CloudTrail producers instead
record independent outcomes for each declared discovery or enrichment source. They retain
independently validated resources and report discarded items, while any incomplete source keeps
the rollup `PARTIAL` unless every source is unavailable, which is `FAILED`. They never convert
missing evidence into a clean result. The graph-aware
security-group and IAM-user collectors preserve their accepted names. IAM account-summary
evidence is isolated in its own collector so its failure cannot erase complete user/MFA evidence.
The external-owner admission exception is described below.

An observed external-owner resource is retained as a top-level resource only when an exact
same-scan resolved edge supplies the accepted admission proof. If that proof is unavailable,
assembly excludes only that external resource and its enrichment records. The discovery artifact
preserves the full AWS-observed ID list, records the canonical rejected identity under
`unadmitted_resources`, and sets `admission_complete = false` while its complete AWS source stays
`PRESENT`. The owning collector derives `PARTIAL` from the persisted outcome plus digest-bound
admission metadata; independent and same-account sibling facts remain available. This prevents
either a scan-wide graph failure, false AWS failure attribution, or a false complete result.

Paginator token handling and retry behavior remain boto3/botocore responsibilities. Each yielded
page and item is validated. Exact repeated resource entries across pages are collected once;
conflicting entries for the same stable identity make the relevant source and collector
incomplete. An explicit empty result list remains a successful zero-resource inventory.

5A declares `ec2.instances.discovery`, `ec2.volumes.discovery`,
`ec2.ebs-encryption-default`, and `ec2.ebs-default-kms-key` account/Region sources, plus one
identity-authoritative enrichment source for each retained instance and volume. A missing default
KMS key is an explicit `EXPECTED_ABSENCE`; the EBS defaults are normalized source artifacts, not
synthetic resources. 5B declares independent `ec2.security-groups.discovery`,
`ec2.vpcs.discovery`, `ec2.subnets.discovery`, and `ec2.flow-logs.discovery` sources, plus an
identity-authoritative source for every retained network resource. Raw provider exception text is
never persisted.

5D declares one `ListAnalyzers` discovery source per required Region, one `ListFindingsV2`
discovery source per relevant `ACCOUNT` or `ORGANIZATION` analyzer, and summary/detail sources for
each retained external-access S3 finding. It fully consumes `ListAnalyzers`, `ListFindingsV2`, and
`GetFindingV2` pagination. A complete Region without a relevant analyzer, or a complete analyzer
without a matching finding, is explicit expected absence. Repeated/non-progressing pagination,
malformed evidence, denied calls, or a disappeared finding remains incomplete and sanitized while
valid siblings survive. A 5E scan derives Analyzer coverage from exact `ListBuckets` and one
authoritative location outcome per bucket; unrelated policy, ACL, encryption, or tag failures do
not make its Region set incomplete. Accepted older scans retain their `s3_buckets` rollup fallback.

5E declares account-global bucket discovery and account Block Public Access sources, one
authoritative location source and eight independent configuration sources per located bucket, and
one dynamic `kms:DescribeKey` source per unique `(Region, supplied reference)`. A location failure
prevents fabrication of that bucket's Regional resource while preserving discovery evidence.
Successful `DescribeKey` metadata creates a canonical `kms_key` resource and resolved
`encrypted_with` edge; a failed lookup preserves an unresolved typed reference.

5F declares one account `cloudtrail.trails.discovery` source. The API accepts only its pagination
token, so the collector does not send the `DescribeTrails`-only `IncludeShadowTrails` option. Each
trail then has independent `cloudtrail.trail.identity`, `cloudtrail.trail.configuration`,
`cloudtrail.trail.status`, `cloudtrail.trail.event-selectors`, and `cloudtrail.trail.tags` outcomes
in its validated home Region. `ListTags` is grouped by Region, limited to 20 ARNs per request, and
paginated to exhaustion. The exact new scan intent adds `cloudtrail-evidence`; accepted pending
scans without that marker make no new selector call or gain a CloudTrail graph. The policy JSON
above includes the only permission delta, read-only `cloudtrail:GetEventSelectors`.

Expected S3 absence responses are facts, not failures:

- no bucket tags becomes an empty tag map;
- no account or bucket Public Access Block configuration becomes an explicit all-false map;
- no bucket policy paired with either expected no-policy status or successful `IsPublic=false`
  remains coherent explicit absence; absence paired with `IsPublic=true` is a conflict;
- no versioning becomes explicit unversioned facts;
- no ownership controls or default-encryption configuration remains explicit complete absence.

Within a present encryption configuration, each rule retains its exact default algorithm, KMS
reference, key-management classification, bucket-key flag, and optional
`BlockedEncryptionTypes.EncryptionType` list. The latter is normalized as exactly one `NONE` or
`SSE-C` value in `blocked_encryption_types`, including when that rule has no default algorithm;
empty, multi-value, or unknown states are malformed rather than guessed. These are collected
facts, not Sprint 6 assessment results.

AWS now applies SSE-S3 as baseline encryption to new and existing general-purpose buckets.
Before implementing the future S3 encryption control, its policy should express the desired
encryption standard (for example, customer-managed KMS) rather than assuming unencrypted modern
buckets are common.

## Inventory boundaries

- EC2 instances, EBS volumes, EBS default settings, security groups, VPCs, subnets, and VPC Flow
  Logs are collected only in `AWS_REGION`. Multi-region EC2 orchestration is a later feature.
- S3 and IAM discovery is account-wide; each bucket retains its actual region and IAM resources
  use global scope.
- 5E follows a bucket only in the Region established by same-scan location evidence. Explicit KMS
  references are described in their ARN Region or, for local IDs/aliases, the bucket home Region.
- CloudTrail discovery is account-wide. Status, tags, and accepted 5F selector evidence are
  requested from each trail's home Region. The runtime
  deduplicates exact repeated records by validated trail ARN.
- CloudTrail account coverage is carried by the verified scan account, source manifest, and
  discovery outcome, not a synthetic account resource. A member-visible organization trail keeps
  its ARN owner distinct from the collection account. Without the existing exact external-owner
  admission proof, its source artifact remains available but its top-level resource is excluded
  from both 5F projections and coverage remains incomplete; unchanged `LOG-001` semantics then
  return `INSUFFICIENT_EVIDENCE`.
- IAM Access Analyzer runs in the requested Region and the sorted unique Regions of exact
  same-scan normalized S3 buckets. Only those bucket-backed supplemental Regions are admitted;
  this is not general multi-Region orchestration.
- Collectors validate facts only; response validation does not assign severity or decide a
  technical assessment result.
- Cross-account and AWS Organizations role orchestration are not implemented. Run once per
  explicitly assumed account role.
- 5A normalizes `ec2_instance` and `ebs_volume` resources. 5B normalizes `security_group`, `vpc`,
  `subnet`, and `vpc_flow_log` resources. 5C normalizes IAM users, groups, roles, managed
  policies, and managed-policy versions. The accepted 5D producer normalizes each relevant
  external-access finding as an `access_analyzer_finding`; analyzer summaries remain source
  artifacts rather than resources. Accepted 5E expands `s3_bucket` snapshots and normalizes
  validated referenced keys as `kms_key`; accepted 5F adds fact-only CloudTrail source evidence.
- Same-scan, identity-authoritative network evidence can resolve instance-to-security-group,
  instance-to-subnet, instance-to-VPC, security-group-to-VPC, VPC-to-subnet, and VPC-to-Flow-Log
  observations. Missing, ambiguous, or non-authoritative ownership evidence remains
  `TARGET_IDENTITY_INCOMPLETE`; the collector never substitutes the collection account.
- EC2/EBS facts are evidence only. `EC2-001` through `EC2-004` remain non-executable until Sprint
  6 supplies separately reviewed deterministic rules and profile integration.
- The 5B network facts are evidence only. `NET-003` through `NET-006` and network-tag use by
  `GOV-001` remain non-executable until Sprint 6 supplies separately reviewed deterministic rules
  and profile integration. Existing `NET-001` and `NET-002` behavior is unchanged.
- The 5D Analyzer facts are supplementary investigation context only. Their
  `references_resource` relationship resolves only to an exact same-scan S3 bucket; unresolved
  targets are retained without fabrication. They do not decide `S3-002`. Accepted 5E
  supplies its direct evidence but still does not register or execute the control.
- `POST /api/v1/scans` invokes this inventory through the authorized background executor;
  resource API routes query only persisted results. `/health` and `/ready` never trigger AWS calls.
- Docker Compose does not mount local AWS credential files. This avoids silently exposing host
  credentials to a container; use host execution or an explicitly configured workload role.

## Troubleshooting

- `ProfileNotFound`: unset an incorrect `AWS_PROFILE`, or configure that profile first.
- `ExpiredToken` or SSO expiration: authenticate again, then rerun `aws sts get-caller-identity`.
- `AccessDenied`: compare the denied operation with the policy baseline and inspect any
  permission boundary or organization SCP.
- Endpoint or region errors: verify `AWS_REGION` is enabled for the account and partition.
- One inaccessible S3 bucket: confirm both the identity policy and bucket policy permit the
  documented reads. The graph-aware S3 collector records the affected source as incomplete,
  retains independently valid sibling facts, and never converts the denied source into absence;
  later assessment therefore fails closed where that fact is required.
- Access Analyzer `AccessDenied`: grant only `access-analyzer:ListAnalyzers`,
  `access-analyzer:ListFindings`, and `access-analyzer:GetFinding` to the scanner role, then verify
  the requested or bucket-home Region is enabled. A missing analyzer after a successful complete
  Regional enumeration is a recorded absence; a denied or incomplete enumeration is not.
- CloudTrail selector `AccessDenied`: grant only the documented read actions, including
  `cloudtrail:GetEventSelectors`, and verify the trail's home Region. A denied selector source is
  incomplete evidence; it is never normalized as an empty or permissive selector set.
