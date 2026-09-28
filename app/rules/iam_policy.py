"""IAM-004 exact syntactic evaluation of proven retained documents, never AWS access."""

from app.assessment.evidence_reader import AssessmentEvidenceReader, IncompleteAssessmentEvidence
from app.assessment.execution import account_target, assessment_targets
from app.assessment.iam_policy_control import iam_policy_contract
from app.assessment.iam_policy_evidence import _statements
from app.assessment.models import AssessmentResult
from app.rules.base import SecurityRule


class IAMPolicyRule(SecurityRule):
    def __init__(self):
        self.contract = iam_policy_contract().technical
        self.control_id = self.contract.control_id
        self.title = self.contract.title
        self.category = self.contract.category
        self.default_severity = self.contract.severity
        self.impact = self.contract.impact
        self.recommendation = self.contract.remediation_guidance

    def evaluate(self, snapshot):
        raise ValueError("IAM policy control requires assess with an explicit profile")

    def assess(self, snapshot, profile):
        execution = self.contract.execution_contract
        reader = AssessmentEvidenceReader(snapshot)
        targets = assessment_targets(snapshot, execution) or (account_target(snapshot, execution),)
        results = []
        for target in targets:
            evidence, missing = None, ()
            try:
                proof = reader.proof(execution, target)
                fact = proof["iam_policy_document"]
                if fact is None:
                    result = AssessmentResult.NOT_APPLICABLE
                    reason = (
                        "Complete enumeration contains no in-scope permissions-policy documents."
                    )
                else:
                    kind = (
                        "iam.inline-policy.document"
                        if target.resource_type == "iam_inline_policy"
                        else "iam.managed-policy-version.document"
                    )
                    payloads = reader.source_payloads(proof, kind)
                    if len(payloads) != 1:
                        raise IncompleteAssessmentEvidence("ambiguous policy document proof")
                    matches = [
                        i
                        for i, statement in enumerate(_statements(payloads[0]["document"]))
                        if statement["Effect"] == "Allow"
                        and _star(statement.get("Action"))
                        and _star(statement.get("Resource"))
                    ]
                    result = AssessmentResult.FAIL if matches else AssessmentResult.PASS
                    reason = (
                        "Literal unrestricted Allow statement found; "
                        "effective access is not assessed."
                        if matches
                        else "Complete document has no literal unrestricted Allow statement."
                    )
                    evidence = {
                        "source_proof": proof,
                        "evaluation_version": "1.0.0",
                        "matching_statement_indexes": matches,
                    }
            except IncompleteAssessmentEvidence:
                result = AssessmentResult.INSUFFICIENT_EVIDENCE
                missing = ("iam.permissions-policy.required_evidence",)
                reason = "Required policy identity, enumeration, usage or document is incomplete."
            results.append(
                self.assessment_for_resource(
                    snapshot,
                    profile,
                    target,
                    result=result,
                    evidence=evidence,
                    reason=reason,
                    collector="iam.policies",
                    source_api="normalized IAM permissions-policy evidence",
                    missing_evidence=missing,
                )
            )
        return tuple(results)


def _star(value):
    return value == "*" or isinstance(value, list | tuple) and "*" in value
