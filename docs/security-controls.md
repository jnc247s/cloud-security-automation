# Security controls

Sprint 2 adds deterministic, in-memory evaluation of the normalized AWS inventory produced by
Sprint 1. The rule engine does not call AWS, write to PostgreSQL, or modify infrastructure.

The default registry contains exactly five controls:

| Control | Target | Failure condition | Severity |
| --- | --- | --- | --- |
| `NET-001` | EC2 security group | Public ingress effectively exposes TCP port 22 | `HIGH` |
| `NET-002` | EC2 security group | Public ingress effectively exposes TCP port 3389 | `HIGH` |
| `S3-002` | S3 bucket | Collected default-encryption configuration is explicitly `null` | `MEDIUM` |
| `IAM-001` | IAM user | Collected MFA device list is empty | `MEDIUM` |
| `LOG-001` | AWS account | No collected CloudTrail has logging explicitly active | `HIGH` |

## Evaluation flow

Collect facts first, then pass the complete snapshot to the rule engine:

```python
from app.aws.client import Boto3ClientProvider
from app.rules.engine import RuleEngine
from app.rules.registry import build_default_registry
from app.services.inventory_service import InventoryService

provider = Boto3ClientProvider.from_settings()
snapshot = InventoryService(provider).collect()
findings = RuleEngine(build_default_registry()).evaluate(snapshot)
```

`findings` is a deterministic tuple of validated `FindingCandidate` values. Each candidate
contains:

- control identifier, title, category, and severity;
- stable account and resource identity;
- structured, allow-listed evidence;
- impact and remediation guidance.

The registry prevents duplicate control identifiers. Rules evaluate the entire
`InventorySnapshot`, which allows both resource controls and absence-based account controls such
as `LOG-001`. Unsupported resource types are ignored. An applicable resource with a missing or
malformed required fact raises a sanitized `RuleEvaluationError`; the engine does not silently
turn uncertain input into a pass or a finding.

Rules are pure evaluation components. They do not own boto3 clients, mutate normalized resources,
persist candidates, or execute their remediation guidance.

## `NET-001` — Public SSH

`NET-001` produces one finding for a security group when at least one inbound rule effectively
allows TCP port 22 from a public IPv4 or IPv6 network.

Network matching uses these semantics:

- `0.0.0.0/0` and `::/0` are public; CIDRs are interpreted as networks rather than compared only
  as strings.
- Named `tcp` uses its inclusive start and end ports; a range matches when it contains port 22,
  so a broad range is detected as well as an exact `22`–`22` rule.
- IP protocol number `6` and all protocols (`-1`) effectively include TCP on all ports. EC2
  security-group semantics allow all ports when a protocol is specified by number rather than by
  the name `tcp`, regardless of a supplied port range. See the
  [EC2 `IpPermission` reference](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_IpPermission.html).
- Only ingress CIDR ranges are evaluated. Egress rules, security-group references, and prefix
  lists are not treated as public CIDRs.

Evidence contains `group_id`, `vpc_id`, `region`, `target_port`, and a deterministic
`matched_ingress` list. Each matched entry records the observed protocol, start and end port,
effective port coverage, source address family, CIDR, and optional description. Multiple matching
ingress entries are aggregated into one candidate for the control/resource pair.

Recommendation: restrict administrative access to approved management networks or use controlled
remote-management mechanisms.

## `NET-002` — Public RDP

The master specification defines this condition as “TCP/3389 exposed publicly” but does not
separately define its address-family or evidence behavior. Sprint 2 intentionally interprets
“publicly” symmetrically with `NET-001`: either the IPv4 `0.0.0.0/0` network or IPv6 `::/0` is
public. Effective-TCP and inclusive-range matching are also the same, with target port 3389.

The evidence shape is the same as `NET-001`, and multiple matches produce one `HIGH` candidate per
security group. The recommendation is informational: restrict RDP to approved management networks
or a controlled remote-management path.

## `S3-002` — Missing bucket encryption configuration

`S3-002` produces one `MEDIUM` finding when the collector has positively represented
`configuration.default_encryption` as `null`. A valid, non-empty encryption `Rules` list passes.
Missing fields, unexpected types, and structurally invalid configuration raise an evaluation error
instead of being classified as missing encryption. Evidence identifies the bucket and the observed
null configuration.

This control measures the configured fact required by the project specification; it is not proof
that an object is stored unencrypted. Since January 5, 2023, Amazon S3 applies SSE-S3 as baseline
encryption for new uploads even when a customer has not selected a different default. See the
[Amazon S3 default-encryption FAQ](https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-encryption-faq.html).
Consequently, a future production policy should define the desired standard—such as a specific
SSE-KMS key—and evaluate that policy explicitly. Sprint 2 does not assess encryption algorithm,
key ownership, bucket-policy enforcement, or existing object history.

## `IAM-001` — IAM user without MFA

`IAM-001` produces one finding when an IAM user's collected `mfa_devices` list is explicitly empty.
A non-empty list passes. Evidence contains the user ID, user name, MFA device count, and an
explicit marker that privilege assessment is not implemented.

The specification allows `HIGH` for privileged users and `MEDIUM` for standard users when
privilege analysis is unavailable. Sprint 1 does not collect policies, groups, roles, or effective
permissions, so Sprint 2 assigns `MEDIUM` to every finding and documents that limitation rather
than guessing privilege. It also does not determine whether the user has console access or whether
a registered device is operational.

## `LOG-001` — CloudTrail missing

`LOG-001` is evaluated once against the account snapshot, not once per trail. Sprint 2 defines a
“suitable active CloudTrail” narrowly and deterministically as any normalized
`cloudtrail_trail` whose `configuration.is_logging` value is explicitly `true`.

- Zero collected trails produces one account-scoped `HIGH` finding.
- Trails exist but none is actively logging produces one account-scoped `HIGH` finding.
- At least one actively logging trail passes the control.
- A missing or non-boolean `is_logging` fact is an evaluation error, not evidence of a pass or
  failure.

Evidence contains the account ID, requested collection region, total and active trail counts, a
machine-readable reason, and deterministic details for inactive trails. The account-scoped target
uses the account ID as its stable resource identifier.

This Sprint 2 definition does not require the active trail to be multi-region, include global
service events, use log-file validation or KMS encryption, deliver to CloudWatch Logs, belong to
an organization, or prove destination health. Those are distinct controls or future refinements.

## Determinism and error behavior

Given the same validated snapshot and registry, evaluation returns value-equal candidates in the
same order. Evidence lists are normalized before output, and one control/resource pair yields at
most one candidate. Sprint 3 consumes that stable identity to reconcile a single durable finding
for each control/resource pair.

Malformed applicable facts stop evaluation with an error that identifies the control, resource,
and fact path without dumping the resource's raw AWS response. This fail-closed behavior prevents
incomplete collection data from being reported as a clean security result.

## Explicit exclusions

Sprint 2 intentionally does not provide:

- database models, migrations, finding persistence, deduplication, acknowledgement, or resolution;
- scan, finding, resource, or control API endpoints;
- Terraform resources or changes to AWS collector permissions;
- remediation proposals, approvals, execution, or AWS mutations;
- a dashboard, frontend, authentication, authorization, AI, or risk scoring;
- multi-account orchestration or AWS Organizations support;
- controls beyond the five listed here, including public S3 access, stale IAM keys, required tags,
  unrestricted generic ingress, or stronger CloudTrail posture checks;
- live-AWS unit tests.

The existing `scripts/run_inventory.py` command remains inventory-only and prints an aggregate
summary. It does not run controls or print finding evidence. Ordinary rule tests use fixture
snapshots and require no AWS account or network access.
