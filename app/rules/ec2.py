"""Four deterministic 6C controls over retained EC2/EBS evidence."""

from app.assessment.ec2_controls import ec2_contract
from app.assessment.ec2_evidence import ec2_facts, ec2_not_applicable, validate_public_ec2_allowlist
from app.assessment.evidence_reader import AssessmentEvidenceReader, IncompleteAssessmentEvidence
from app.assessment.execution import account_target, assessment_targets
from app.assessment.models import AssessmentResult
from app.rules.base import SecurityRule


class EC2Rule(SecurityRule):
    def __init__(self, control_id):
        self.contract = ec2_contract(control_id).technical
        self.control_id = control_id
        self.title = self.contract.title
        self.category = self.contract.category
        self.default_severity = self.contract.severity
        self.impact = self.contract.impact
        self.recommendation = self.contract.remediation_guidance

    def evaluate(self, snapshot):
        raise ValueError("EC2 controls require assess with explicit versioned policy")

    def assess(self, snapshot, profile):
        if self.control_id == "EC2-002":
            validate_public_ec2_allowlist(profile.public_ec2_exceptions)
        contract = self.contract.execution_contract
        reader = AssessmentEvidenceReader(snapshot)
        targets = assessment_targets(snapshot, contract) or (account_target(snapshot, contract),)
        results = []
        for target in targets:
            evidence, missing = None, ()
            try:
                proof = reader.proof(contract, target)
                facts = ec2_facts(reader, contract, target, self.control_id)
                if ec2_not_applicable(facts):
                    result = AssessmentResult.NOT_APPLICABLE
                else:
                    passing = self._passes(facts, profile)
                    result = AssessmentResult.PASS if passing else AssessmentResult.FAIL
                    evidence = {"source_proof": proof, "evaluation_version": "1.0.0", **facts}
                reason = {
                    AssessmentResult.PASS: (
                        "Complete EC2 evidence satisfies the selected control policy."
                    ),
                    AssessmentResult.FAIL: (
                        "Complete EC2 evidence violates the selected control policy."
                    ),
                    AssessmentResult.NOT_APPLICABLE: (
                        "Complete evidence proves no applicable target or an explicitly "
                        "disabled metadata endpoint."
                    ),
                }[result]
            except IncompleteAssessmentEvidence:
                result = AssessmentResult.INSUFFICIENT_EVIDENCE
                reason = (
                    "Required EC2 evidence is unavailable, incomplete, pending or inconsistent."
                )
                missing = ("ec2.required_evidence",)
            source = contract.required_sources[0]
            results.append(
                self.assessment_for_resource(
                    snapshot,
                    profile,
                    target,
                    result=result,
                    evidence=evidence,
                    reason=reason,
                    collector=source.collector,
                    source_api=source.source_api,
                    missing_evidence=missing,
                )
            )
        return tuple(results)

    def _passes(self, facts, profile):
        if self.control_id == "EC2-001":
            return facts["metadata_options"]["http_tokens"] == "required"
        if self.control_id == "EC2-002":
            return (
                not facts["public_ipv4_addresses"]
                or facts["stable_resource_id"] in profile.public_ec2_exceptions
            )
        return facts["encrypted" if self.control_id == "EC2-003" else "ebs_encryption_by_default"]
