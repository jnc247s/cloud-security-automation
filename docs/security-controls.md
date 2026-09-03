# Security controls

Sprint 2.1 keeps the five deterministic technical checks introduced in Sprint 2 and gives each
one a versioned control contract. It does not add controls, AWS calls, persistence, API endpoints,
or remediation execution.

The default control catalog is `aws-cloud-security-controls` version `0.2.1`:

| Control | Target | Failure condition | Severity |
| --- | --- | --- | --- |
| `IAM-001` | IAM user | The collected MFA device list is empty | `MEDIUM` |
| `LOG-001` | AWS account | No collected CloudTrail has logging explicitly active | `HIGH` |
| `NET-001` | EC2 security group | Public ingress effectively exposes TCP port 22 | `HIGH` |
| `NET-002` | EC2 security group | Public ingress effectively exposes TCP port 3389 | `HIGH` |
| `S3-900` | S3 bucket | The explicit default-encryption configuration is `null` | `MEDIUM` |

Every contract defines a stable control ID, title, resource type, assessment type, required
evidence, `PASS` logic, `FAIL` logic, insufficient-evidence behavior, non-applicability logic,
severity, impact, remediation guidance, profile parameters, limitations, and framework mappings.
The technical contract remains valid without its NIST metadata; framework mappings never drive a
technical result.

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

Sprint 2.1 intentionally excludes assessment persistence, lifecycle management, scan/control API
endpoints, authentication, AWS resource/API scope expansion, additional controls, Terraform, remediation,
frontend work, and AI functionality.
