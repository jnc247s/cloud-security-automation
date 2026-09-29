"""Exact same-scan exposure inputs and immutable approval binding; no AWS calls."""

from pydantic import ValidationError

from app.assessment.evidence_reader import IncompleteAssessmentEvidence
from app.assessment.s3_configuration_evidence import (
    ACCOUNT_BPA,
    BUCKET_BPA,
    DISCOVERY,
    LOCATION,
    POLICY,
    _observation,
    require,
    s3_configuration_proof,
    source,
)
from app.assessment.s3_exposure import S3ExposureApprovalPolicy
from app.assessment.s3_identity import S3BucketIdentity
from app.assessment.source_outcomes import EvidenceSourceState

STATUS = source("s3.bucket-policy-status", "s3:GetBucketPolicyStatus")
ACL = source("s3.bucket-acl", "s3:GetBucketAcl")
OWNERSHIP = source("s3.bucket-ownership-controls", "s3:GetBucketOwnershipControls")
EXPOSURE_SOURCES = (DISCOVERY, LOCATION, ACCOUNT_BPA, BUCKET_BPA, POLICY, STATUS, ACL, OWNERSHIP)


def exposure_proof(reader, contract, target):
    # Reuse the accepted exact discovery/location/source bindings, not their evaluator.
    proof = s3_configuration_proof(reader, contract, target)
    proof["schema_version"] = "1.6.0"
    facts = proof.pop("s3_configuration")
    proof["s3_exposure"] = facts
    if facts.get("empty_population"):
        return proof
    bucket = reader.resources[reader._target_id(target)]
    facts["bucket_identity"] = S3BucketIdentity.for_bucket(
        aws_account_id=bucket.account_id, bucket_region=bucket.region, bucket_arn=bucket.arn
    ).model_dump(mode="json")
    # A disappearance from even a supplementary call invalidates the bucket snapshot.
    require(
        not any(
            o.state is EvidenceSourceState.RESOURCE_DISAPPEARED
            and getattr(o.subject, "resource_snapshot_id", None) == reader._target_id(bucket)
            for o in reader._outcomes.values()
        )
    )
    _, outcome, payload, _ = _observation(reader, ACL, bucket)
    if outcome.state is EvidenceSourceState.CONFLICT:
        # Retain validated conflicting ACL facts: a public-group conflict cannot hide a
        # separate external canonical-user grant. The evaluator distinguishes ownership.
        facts["observations"][ACL.evidence_kind]["value"] = payload["value"]
    return proof


def bind_approvals(proof, profile):
    """Reject missing/forged artifacts; bind exact historical policy and profile content."""
    policy = getattr(profile, "s3_exposure_approvals", None)
    require(policy is not None)
    try:
        policy = S3ExposureApprovalPolicy.model_validate_json(policy.model_dump_json())
    except ValidationError:
        raise IncompleteAssessmentEvidence("S3 exposure approval content is invalid") from None
    proof["approval_policy"] = policy.model_dump(mode="json", exclude={"bucket_approvals"})
    proof["profile_checksum"] = profile.content_checksum
    return policy
