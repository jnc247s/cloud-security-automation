"""Deterministic GOV-001 required tags over exact retained normalized sources."""

from app.assessment.evidence_reader import AssessmentEvidenceReader, IncompleteAssessmentEvidence
from app.assessment.execution import account_target, assessment_targets
from app.assessment.governance_evidence import governance_result
from app.assessment.models import AssessmentResult as R
from app.rules.base import SecurityRule


class RequiredTagsRule(SecurityRule):
    def __init__(self):
        from app.assessment.governance_control import governance_contract

        self.contract = governance_contract().technical
        for name, value in {
            "control_id": self.contract.control_id,
            "title": self.contract.title,
            "category": self.contract.category,
            "default_severity": self.contract.severity,
            "impact": self.contract.impact,
            "recommendation": self.contract.remediation_guidance,
        }.items():
            setattr(self, name, value)

    def evaluate(self, snapshot):
        raise ValueError("required tags require explicit catalog/profile selection")

    def assess(self, snapshot, profile):
        reader = AssessmentEvidenceReader(snapshot)
        contract = self.contract.execution_contract
        assessments = []
        for target in assessment_targets(snapshot, contract, profile=profile) or (
            account_target(snapshot, contract),
        ):
            evidence = None
            try:
                proof = reader.proof(contract, target, profile=profile)
                result = governance_result(proof, profile)
                if result in {R.PASS, R.FAIL}:
                    evidence = {"source_proof": proof, "evaluation_version": "1.0.0"}
            except IncompleteAssessmentEvidence:
                result = R.INSUFFICIENT_EVIDENCE
            assessments.append(
                self.assessment_for_resource(
                    snapshot,
                    profile,
                    target,
                    result=result,
                    evidence=evidence,
                    reason={
                        R.PASS: "Complete tags contain all exact required keys with usable values.",
                        R.FAIL: "Complete tags lack a usable value for at least one required key.",
                        R.NOT_APPLICABLE: "Target is ungoverned or complete discovery proves "
                        "no governed resources.",
                        R.INSUFFICIENT_EVIDENCE: "Required tag, identity or population evidence "
                        "is unavailable.",
                    }[result],
                    collector="governance_evidence",
                    source_api="normalized:RequiredTags",
                    missing_evidence=("governance.required_sources",)
                    if result is R.INSUFFICIENT_EVIDENCE
                    else (),
                )
            )
        return tuple(assessments)
