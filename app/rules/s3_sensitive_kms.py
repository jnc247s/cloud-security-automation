"""S3-004: deterministic classification followed by bounded default-KMS evaluation."""

import json

from pydantic import ValidationError

from app.assessment.evidence_reader import AssessmentEvidenceReader, IncompleteAssessmentEvidence
from app.assessment.execution import account_target, assessment_targets
from app.assessment.models import AssessmentResult as R
from app.assessment.s3_configuration_evidence import require
from app.assessment.s3_identity import S3BucketIdentity
from app.assessment.sensitive_buckets import (
    BucketSensitivity,
    BucketTag,
    SensitiveBucketClassifier,
    SensitiveBucketEvidence,
)
from app.rules.base import SecurityRule


def sensitive_kms_result(proof, profile):
    """Recompute applicability and decision for both the engine and persistence."""
    classifier = getattr(profile, "sensitive_bucket_classifier", None)
    require(classifier is not None)
    try:
        classifier = SensitiveBucketClassifier.model_validate_json(classifier.model_dump_json())
    except ValidationError:
        raise IncompleteAssessmentEvidence("sensitive-bucket policy content is invalid") from None
    required = getattr(profile, "restricted_data_requires_kms", None)
    require(type(required) is bool)
    proof["classifier"] = {
        "classifier_id": classifier.classifier_id,
        "version": classifier.version,
        "content_checksum": classifier.content_checksum,
    }
    proof["profile_checksum"] = profile.content_checksum
    proof["restricted_data_requires_kms"] = required
    facts = proof["s3_sensitive_kms"]
    if facts.get("empty_population"):
        return R.NOT_APPLICABLE
    identity = S3BucketIdentity.model_validate_json(json.dumps(facts["bucket_identity"]))
    tags = facts["observations"]["s3.bucket-tags"]
    classification = classifier.classify(
        SensitiveBucketEvidence(
            bucket_identity=identity,
            tags=tuple(BucketTag(key=t["key"], value=t["value"]) for t in (tags["value"] or ()))
            if tags["state"] in {"PRESENT", "EXPECTED_ABSENCE"}
            else None,
        )
    )
    proof["classification"] = classification.model_dump(mode="json")
    if classification.sensitivity is BucketSensitivity.INSUFFICIENT_EVIDENCE:
        return R.INSUFFICIENT_EVIDENCE
    if classification.sensitivity is BucketSensitivity.NOT_SENSITIVE or not required:
        return R.NOT_APPLICABLE
    encryption = facts["observations"]["s3.bucket-encryption"]
    if encryption["state"] == "EXPECTED_ABSENCE":
        return R.FAIL
    if encryption["state"] != "PRESENT":
        return R.INSUFFICIENT_EVIDENCE
    defaults = [r for r in encryption["value"]["rules"] if r["sse_algorithm"] is not None]
    # Retain every rule, but never choose a first default from ambiguous configuration.
    if not defaults:
        return R.FAIL
    if len(defaults) != 1:
        return R.INSUFFICIENT_EVIDENCE
    default = defaults[0]
    if default["sse_algorithm"] == "AES256":
        return R.FAIL
    if default["sse_algorithm"] not in {"aws:kms", "aws:kms:dsse"}:
        return R.INSUFFICIENT_EVIDENCE
    if not default["kms_reference_explicit"]:
        return R.PASS
    key = facts["keys"].get(default["kms_key_reference"])
    return R.PASS if key and key["complete"] else R.INSUFFICIENT_EVIDENCE


class S3SensitiveKMSRule(SecurityRule):
    def __init__(self):
        from app.assessment.s3_sensitive_kms_control import sensitive_kms_contract

        self.contract = sensitive_kms_contract().technical
        for name, value in {
            "control_id": "S3-004",
            "title": self.contract.title,
            "category": self.contract.category,
            "default_severity": self.contract.severity,
            "impact": self.contract.impact,
            "recommendation": self.contract.remediation_guidance,
        }.items():
            setattr(self, name, value)

    def evaluate(self, snapshot):
        raise ValueError("S3 sensitive KMS requires explicit catalog/profile selection")

    def assess(self, snapshot, profile):
        reader = AssessmentEvidenceReader(snapshot)
        contract = self.contract.execution_contract
        results = []
        for target in assessment_targets(snapshot, contract) or (
            account_target(snapshot, contract),
        ):
            evidence = None
            try:
                proof = reader.proof(contract, target)
                result = sensitive_kms_result(proof, profile)
                if result in {R.PASS, R.FAIL}:
                    evidence = {"source_proof": proof, "evaluation_version": "1.0.0"}
            except IncompleteAssessmentEvidence:
                result = R.INSUFFICIENT_EVIDENCE
            reasons = {
                R.PASS: "Sensitive bucket default configuration uses supported KMS encryption.",
                R.FAIL: "Sensitive bucket default configuration does not meet the KMS requirement.",
                R.NOT_APPLICABLE: "No classified bucket requires the configured KMS check.",
                R.INSUFFICIENT_EVIDENCE: (
                    "Required classifier, bucket or key evidence is unavailable, "
                    "inconsistent or unsupported."
                ),
            }
            results.append(
                self.assessment_for_resource(
                    snapshot,
                    profile,
                    target,
                    result=result,
                    evidence=evidence,
                    reason=reasons[result],
                    collector="s3_evidence",
                    source_api="s3:GetEncryptionConfiguration",
                    missing_evidence=("s3_sensitive_kms.required_evidence",)
                    if result is R.INSUFFICIENT_EVIDENCE
                    else (),
                )
            )
        return tuple(results)
