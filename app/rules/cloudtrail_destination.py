"""LOG-004 composes only a validated same-invocation destination S3-002 result."""

from app.assessment.cloudtrail_destination_evidence import destination_result
from app.assessment.evidence_reader import AssessmentEvidenceReader, IncompleteAssessmentEvidence
from app.assessment.execution import account_target, assessment_targets
from app.assessment.models import AssessmentResult as R
from app.rules.base import SecurityRule


class CloudTrailDestinationRule(SecurityRule):
    def __init__(self):
        from app.assessment.cloudtrail_destination_control import destination_contract

        self.contract = destination_contract().technical
        for name, value in {
            "control_id": "LOG-004",
            "title": self.contract.title,
            "category": self.contract.category,
            "default_severity": self.contract.severity,
            "impact": self.contract.impact,
            "recommendation": self.contract.remediation_guidance,
        }.items():
            setattr(self, name, value)

    def evaluate(self, snapshot):
        raise ValueError("destination composition requires explicit catalog/profile selection")

    def assess(self, snapshot, profile):
        return self.assess_with_context(snapshot, profile)

    def assess_with_context(self, snapshot, profile, *, context=None):
        reader = AssessmentEvidenceReader(snapshot)
        contract = self.contract.execution_contract
        results = []
        for target in assessment_targets(snapshot, contract) or (
            account_target(snapshot, contract),
        ):
            evidence = None
            try:
                proof = reader.proof(contract, target, context=context, profile=profile)
                result = destination_result(proof)
                if result in {R.PASS, R.FAIL}:
                    evidence = {"source_proof": proof, "evaluation_version": "1.0.0"}
            except IncompleteAssessmentEvidence:
                result = R.INSUFFICIENT_EVIDENCE
            results.append(
                self.assessment_for_resource(
                    snapshot,
                    profile,
                    target,
                    result=result,
                    evidence=evidence,
                    reason={
                        R.PASS: "Exact destination S3-002 result is PASS.",
                        R.FAIL: "Exact destination S3-002 result is FAIL.",
                        R.NOT_APPLICABLE: "Complete discovery contains no CloudTrail trails.",
                        R.INSUFFICIENT_EVIDENCE: "Required destination evidence or validated "
                        "dependency is unavailable.",
                    }[result],
                    collector="cloudtrail_evidence",
                    source_api="cloudtrail:ListTrails,cloudtrail:GetTrail",
                    missing_evidence=("cloudtrail.destination_dependency",)
                    if result is R.INSUFFICIENT_EVIDENCE
                    else (),
                )
            )
        return tuple(results)
