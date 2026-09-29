"""Approved effective BPA and bounded explicit secure-transport Deny evaluation."""

from app.assessment.evidence_reader import AssessmentEvidenceReader, IncompleteAssessmentEvidence
from app.assessment.execution import account_target, assessment_targets
from app.assessment.models import AssessmentResult as R
from app.assessment.s3_configuration_evidence import require
from app.rules.base import SecurityRule

BPA_FLAGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


def _flags(observation):
    if observation["state"] == "EXPECTED_ABSENCE":
        return dict.fromkeys(BPA_FLAGS, False)
    if observation["state"] != "PRESENT":
        return dict.fromkeys(BPA_FLAGS, None)
    value = observation["value"]
    require(isinstance(value, dict) and all(type(value.get(k)) is bool for k in BPA_FLAGS))
    return value


def _values(value):
    return [value] if isinstance(value, str) else value if isinstance(value, list) else []


def _transport_result(observation, arn):
    if observation["state"] == "EXPECTED_ABSENCE":
        return R.FAIL
    if observation["state"] != "PRESENT":
        return R.INSUFFICIENT_EVIDENCE
    value = observation["value"]
    require(isinstance(value, dict) and isinstance(value.get("document"), dict))
    statements = value["document"].get("Statement")
    require(isinstance(statements, list) and bool(statements))
    required_resources = {arn, f"{arn}/*"}
    covered, unsupported = set(), False
    for statement in statements:
        require(isinstance(statement, dict) and statement.get("Effect") in {"Allow", "Deny"})
        if statement["Effect"] == "Allow":
            continue
        principal = statement.get("Principal")
        universal = principal == "*" or (
            isinstance(principal, dict)
            and set(principal) == {"AWS"}
            and _values(principal["AWS"]) == ["*"]
        )
        condition = statement.get("Condition")
        supported_condition = (
            isinstance(condition, dict)
            and set(condition) == {"Bool"}
            and isinstance(condition["Bool"], dict)
            and set(condition["Bool"]) == {"aws:SecureTransport"}
            and _values(condition["Bool"]["aws:SecureTransport"]) == ["false"]
        )
        if not (
            universal
            and supported_condition
            and {"*", "s3:*"}.intersection(_values(statement.get("Action")))
            and not {"NotPrincipal", "NotAction", "NotResource"}.intersection(statement)
        ):
            unsupported = True
            continue
        resources = set(_values(statement.get("Resource")))
        covered.update(required_resources if "*" in resources else required_resources & resources)
        if not required_resources <= covered:
            unsupported = True
    if required_resources <= covered:
        return R.PASS
    return R.INSUFFICIENT_EVIDENCE if unsupported else R.FAIL


def s3_configuration_result(control_id, facts):
    require(control_id in {"S3-001", "S3-003"})
    if facts.get("empty_population") is True:
        return R.NOT_APPLICABLE
    observations = facts["observations"]
    if control_id == "S3-003":
        return _transport_result(observations["s3.bucket-policy"], facts["bucket_arn"])
    account = _flags(observations["s3.account-public-access-block"])
    bucket = _flags(observations["s3.bucket-public-access-block"])
    if any(account[k] is False and bucket[k] is False for k in BPA_FLAGS):
        return R.FAIL
    if all(account[k] is True or bucket[k] is True for k in BPA_FLAGS):
        return R.PASS
    return R.INSUFFICIENT_EVIDENCE


class S3ConfigurationRule(SecurityRule):
    def __init__(self, control_id):
        from app.assessment.s3_configuration_controls import s3_configuration_contract

        self.contract = s3_configuration_contract(control_id).technical
        for name, value in {
            "control_id": control_id,
            "title": self.contract.title,
            "category": self.contract.category,
            "default_severity": self.contract.severity,
            "impact": self.contract.impact,
            "recommendation": self.contract.remediation_guidance,
        }.items():
            setattr(self, name, value)

    def evaluate(self, snapshot):
        raise ValueError("S3 configuration controls require explicit catalog/profile selection")

    def assess(self, snapshot, profile):
        reader = AssessmentEvidenceReader(snapshot)
        contract = self.contract.execution_contract
        results = []
        for target in assessment_targets(snapshot, contract) or (
            account_target(snapshot, contract),
        ):
            evidence, missing = None, ()
            try:
                proof = reader.proof(contract, target)
                result = s3_configuration_result(self.control_id, proof["s3_configuration"])
                if result in {R.PASS, R.FAIL}:
                    evidence = {"source_proof": proof, "evaluation_version": "1.0.0"}
            except IncompleteAssessmentEvidence:
                result = R.INSUFFICIENT_EVIDENCE
            if result is R.INSUFFICIENT_EVIDENCE:
                missing = ("s3_configuration.required_evidence",)
            reasons = {
                R.PASS: "Retained S3 configuration proves the required safeguards.",
                R.FAIL: "Retained S3 configuration does not meet the required safeguards.",
                R.NOT_APPLICABLE: "Complete bucket discovery contains no buckets.",
                R.INSUFFICIENT_EVIDENCE: (
                    "Required S3 evidence is unavailable, inconsistent or unsupported."
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
                    source_api="s3:GetBucketPublicAccessBlock"
                    if self.control_id == "S3-001"
                    else "s3:GetBucketPolicy",
                    missing_evidence=missing,
                )
            )
        return tuple(results)
