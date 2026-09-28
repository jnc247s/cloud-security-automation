"""6B.1 deterministic rules over retained IAM facts; no AWS calls or mutations."""

from datetime import timedelta

from app.assessment.evidence_reader import AssessmentEvidenceReader, IncompleteAssessmentEvidence
from app.assessment.execution import account_target, assessment_targets
from app.assessment.iam_controls import iam_contract
from app.assessment.iam_key_evidence import evidence_time
from app.assessment.models import AssessmentResult
from app.rules.base import SecurityRule


class IAMCredentialRule(SecurityRule):
    """One bounded evaluator for the four explicitly versioned IAM credential controls."""

    def __init__(self, control_id):
        self.contract = iam_contract(control_id).technical
        self.control_id = control_id
        self.title = self.contract.title
        self.category = self.contract.category
        self.default_severity = self.contract.severity
        self.impact = self.contract.impact
        self.recommendation = self.contract.remediation_guidance

    def evaluate(self, snapshot):
        raise ValueError("IAM credential controls require assess with explicit versioned policy")

    def assess(self, snapshot, profile):
        execution = self.contract.execution_contract
        reader = AssessmentEvidenceReader(snapshot)
        threshold = None
        if self.control_id in {"IAM-002", "IAM-003"}:
            field = (
                "stale_key_days" if self.control_id == "IAM-002" else "max_unused_access_key_days"
            )
            threshold = getattr(profile, field, None)
            if type(threshold) is not int or threshold < 1:
                raise ValueError("IAM credential control requires explicit positive policy input")
        targets = assessment_targets(snapshot, execution) or (account_target(snapshot, execution),)
        results = []
        for target in targets:
            evidence = None
            missing = ()
            try:
                proof = reader.proof(execution, target)
                result, facts = self._result(reader, proof, threshold)
                if result is not AssessmentResult.NOT_APPLICABLE:
                    evidence = {"source_proof": proof, "evaluation_version": "1.0.0", **facts}
                reason = {
                    AssessmentResult.PASS: "Complete IAM evidence satisfies the control.",
                    AssessmentResult.FAIL: "Complete IAM evidence violates the configured control.",
                    AssessmentResult.NOT_APPLICABLE: "Complete enumeration has no active keys.",
                }[result]
            except IncompleteAssessmentEvidence:
                result = AssessmentResult.INSUFFICIENT_EVIDENCE
                missing = ("iam.required_evidence",)
                reason = "Required IAM evidence is unavailable, incomplete, or inconsistent."
            results.append(
                self.assessment_for_resource(
                    snapshot,
                    profile,
                    target,
                    result=result,
                    evidence=evidence,
                    reason=reason,
                    collector="iam.users" if threshold is not None else "iam.account-summary",
                    source_api="iam:ListAccessKeys"
                    if threshold is not None
                    else "iam:GetAccountSummary",
                    missing_evidence=missing,
                )
            )
        return tuple(results)

    def _result(self, reader, proof, threshold):
        if threshold is not None:
            keys = proof["iam_active_keys"]
            if not keys:
                return AssessmentResult.NOT_APPLICABLE, {}
            failed = []
            for key in keys:
                anchor = key["created_at"]
                if self.control_id == "IAM-003" and key["last_used_state"] == "recorded_use":
                    anchor = key["last_used_at"]
                # Integer microseconds preserve exact boundaries and support unbounded policy ints.
                age = evidence_time(key["observed_at"]) - evidence_time(anchor)
                if age // timedelta(microseconds=1) > threshold * 86_400_000_000:
                    failed.append(key["resource_snapshot_id"])
            return (AssessmentResult.FAIL if failed else AssessmentResult.PASS), {
                "threshold_days": threshold,
                "violating_key_snapshot_ids": sorted(failed),
            }
        payloads = reader.source_payloads(proof, "iam.account-summary")
        field = (
            "account_access_keys_present" if self.control_id == "IAM-005" else "account_mfa_enabled"
        )
        if len(payloads) != 1 or type(payloads[0].get(field)) is not bool:
            raise IncompleteAssessmentEvidence("required account-summary flag is invalid")
        value = payloads[0][field]
        fails = value if self.control_id == "IAM-005" else not value
        return (AssessmentResult.FAIL if fails else AssessmentResult.PASS), {field: value}
