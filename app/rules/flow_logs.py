"""NET-006: explicit environment and traffic policy over retained VPC-scoped facts."""

from app.assessment.evidence_reader import AssessmentEvidenceReader, IncompleteAssessmentEvidence
from app.assessment.execution import account_target, assessment_targets
from app.assessment.flow_log_control import flow_log_contract
from app.assessment.models import AssessmentResult
from app.assessment.security_group_evidence import require
from app.rules.base import SecurityRule


def flow_log_result(facts, profile):
    environments = getattr(profile, "vpc_flow_log_required_environments", None)
    traffic = getattr(profile, "acceptable_vpc_flow_log_traffic_types", None)
    require(isinstance(environments, tuple) and bool(environments))
    require(all(isinstance(e, str) and bool(e.strip()) and e == e.strip() for e in environments))
    require(isinstance(traffic, tuple) and bool(traffic) and set(traffic) <= {"REJECT", "ALL"})
    if facts.get("empty_population") is True:
        return AssessmentResult.NOT_APPLICABLE
    environment = facts["tags"].get("Environment")
    require(isinstance(environment, str) and bool(environment.strip()))
    if environment not in environments:
        return AssessmentResult.NOT_APPLICABLE
    eligible = False
    for log in facts["flow_logs"]:
        config = log["configuration"]
        require(config.get("flow_log_status") == "ACTIVE")
        require(config.get("traffic_type") in {"ACCEPT", "REJECT", "ALL"})
        destination = config.get("log_destination_type")
        require(destination in {"cloud-watch-logs", "s3", "kinesis-data-firehose"})
        values = [config.get("log_destination")]
        if destination == "cloud-watch-logs":
            values.append(config.get("log_group_name"))
        require(any(isinstance(v, str) and bool(v.strip()) for v in values))
        eligible |= config["traffic_type"] in traffic
    return AssessmentResult.PASS if eligible else AssessmentResult.FAIL


class VPCFlowLogRule(SecurityRule):
    def __init__(self):
        self.contract = flow_log_contract().technical
        self.control_id = self.contract.control_id
        self.title = self.contract.title
        self.category = self.contract.category
        self.default_severity = self.contract.severity
        self.impact = self.contract.impact
        self.recommendation = self.contract.remediation_guidance

    def evaluate(self, snapshot):
        raise ValueError("NET-006 requires explicit versioned policy")

    def assess(self, snapshot, profile):
        contract = self.contract.execution_contract
        reader = AssessmentEvidenceReader(snapshot)
        results = []
        for target in assessment_targets(snapshot, contract) or (
            account_target(snapshot, contract),
        ):
            evidence, missing = None, ()
            try:
                proof = reader.proof(contract, target)
                result = flow_log_result(proof["vpc_flow_logs"], profile)
                if result in {AssessmentResult.PASS, AssessmentResult.FAIL}:
                    evidence = {"source_proof": proof, "evaluation_version": "1.0.0"}
                reason = "Complete VPC-scoped Flow Log evidence evaluated against selected policy."
            except IncompleteAssessmentEvidence:
                result = AssessmentResult.INSUFFICIENT_EVIDENCE
                reason = "Required VPC Flow Log evidence is unavailable or inconsistent."
                missing = ("vpc_flow_logs.required_evidence",)
            results.append(
                self.assessment_for_resource(
                    snapshot,
                    profile,
                    target,
                    result=result,
                    evidence=evidence,
                    reason=reason,
                    collector="ec2.flow-logs",
                    source_api="ec2:DescribeFlowLogs",
                    missing_evidence=missing,
                )
            )
        return tuple(results)
