# AWS inventory operations

Sprint 1 provides a read-only, on-demand AWS inventory run. It discovers resource facts and
returns a normalized in-memory snapshot. It does not judge compliance, create findings, write
to PostgreSQL, or modify AWS.

## Real-world operator flow

1. A cloud administrator creates or selects a dedicated read-only audit role.
2. The administrator attaches only the API permissions used by the collectors.
3. An operator authenticates with short-lived credentials, preferably through AWS IAM Identity
   Center, role assumption, or the compute platform's workload identity.
4. The operator verifies the active identity with `aws sts get-caller-identity`.
5. The operator sets `AWS_REGION` and optionally `AWS_PROFILE`.
6. The operator runs `python scripts/run_inventory.py` from the project environment.
7. The application asks STS for the caller account once, then collects:
   - security groups from the configured region;
   - all account S3 buckets and selected bucket configuration;
   - global IAM users and authentication metadata;
   - account CloudTrail trails, enriched through each trail's home region.
8. Each AWS response is transformed into the common `NormalizedResource` contract. AWS
   timestamps and other SDK values are converted to JSON-safe values.
9. The inventory service records each requested collector as `SUCCEEDED`, `FAILED`, or `PARTIAL`,
   then sorts available resources by stable account/service/scope/region/resource identity and
   returns one `InventorySnapshot`.
10. The command prints collection outcomes and counts by service. Raw resource data is kept out
    of console logs.

The Sprint 4 executor consumes the same snapshot through the rule and persistence layers without
coupling those responsibilities to boto3 collectors. The standalone command remains an
inventory-only diagnostic and does not evaluate or persist results.

## Read-only policy baseline

The following policy is a practical baseline for the exact calls made by Sprint 1. Review and
scope it for your partition, account, buckets, permission boundaries, service control policies,
and role-assumption model before production use.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "InventoryDiscovery",
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity",
        "ec2:DescribeSecurityGroups",
        "s3:ListAllMyBuckets",
        "iam:ListUsers",
        "iam:GetAccessKeyLastUsed",
        "cloudtrail:ListTrails"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ReadBucketConfiguration",
      "Effect": "Allow",
      "Action": [
        "s3:GetBucketTagging",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketPublicAccessBlock",
        "s3:ListBucket"
      ],
      "Resource": "arn:aws:s3:::*"
    },
    {
      "Sid": "ReadUserAuthenticationMetadata",
      "Effect": "Allow",
      "Action": [
        "iam:ListUserTags",
        "iam:ListMFADevices",
        "iam:ListAccessKeys"
      ],
      "Resource": "arn:aws:iam::*:user/*"
    },
    {
      "Sid": "ReadTrailConfiguration",
      "Effect": "Allow",
      "Action": [
        "cloudtrail:GetTrail",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:ListTags"
      ],
      "Resource": "arn:aws:cloudtrail:*:*:trail/*"
    }
  ]
}
```

`s3:ListBucket` is used only by the `HeadBucket` compatibility fallback when a paginated
`ListBuckets` response does not include the bucket region.

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
    "cloudtrail_trails": "SUCCEEDED",
    "iam_users": "SUCCEEDED",
    "s3_buckets": "SUCCEEDED",
    "security_groups": "SUCCEEDED"
  },
  "resource_count": 27,
  "resources_by_service": {
    "cloudtrail": 2,
    "ec2": 8,
    "iam": 5,
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

The accepted error-isolation contract catches botocore `ClientError`/`BotoCoreError` and explicit
`CollectorEvidenceError`. An unexpected malformed response that escapes those boundaries can
abort the entire scan or CLI process. Expanding and normalizing that failure contract is a known
pre-Sprint 5 concern; do not describe every malformed payload as safely isolated today.

Expected S3 absence responses are facts, not failures:

- no bucket tags becomes an empty tag map;
- no bucket-level public-access-block configuration becomes `null`;
- a legacy missing default-encryption response becomes `null`.

AWS now applies SSE-S3 as baseline encryption to new and existing general-purpose buckets.
Before implementing the future S3 encryption control, its policy should express the desired
encryption standard (for example, customer-managed KMS) rather than assuming unencrypted modern
buckets are common.

## Inventory boundaries

- EC2 security groups are collected only in `AWS_REGION`. Multi-region EC2 orchestration is a
  later feature.
- S3 and IAM discovery is account-wide; each bucket retains its actual region and IAM resources
  use global scope.
- CloudTrail discovery is account-wide. Status and tags are requested from each trail's home
  region.
- Cross-account and AWS Organizations role orchestration are not implemented. Run once per
  explicitly assumed account role.
- Directory buckets, S3 access points, IAM roles/groups/policies, VPCs, instances, and other AWS
  resource types are outside Sprint 1.
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
  documented reads. The S3 collector is marked incomplete, its uncertain results are discarded,
  and independent collectors continue; assessment therefore fails closed with insufficient
  evidence instead of silently omitting the bucket.
