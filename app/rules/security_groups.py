"""6D.1 pure security-group evaluations; legacy SSH/RDP rules remain untouched."""

from app.assessment.evidence_reader import AssessmentEvidenceReader, IncompleteAssessmentEvidence
from app.assessment.execution import account_target, assessment_targets
from app.assessment.models import AssessmentResult
from app.assessment.security_group_controls import network_contract
from app.assessment.security_group_evidence import permissions, public_permission, require
from app.rules.base import SecurityRule


def network_result(control_id, facts, profile):
    """One deterministic truth table reused for assessment and persisted result validation."""
    if control_id == "NET-004":
        ports = getattr(profile, "high_risk_public_tcp_ports", None)
        require(isinstance(ports, tuple) and all(type(p) is int and 1 <= p <= 65535 for p in ports))
    if facts.get("empty_population") is True:
        return AssessmentResult.NOT_APPLICABLE
    config = facts["configuration"]
    ingress = permissions(config.get("ingress_rules"), ports_required=control_id != "NET-003")
    if control_id == "NET-005":
        name = config.get("group_name")
        require(isinstance(name, str) and bool(name.strip()))
        require(
            type(config.get("is_default")) is bool and config["is_default"] == (name == "default")
        )
        egress = permissions(config.get("egress_rules"), ports_required=True)
        if not config["is_default"]:
            return AssessmentResult.NOT_APPLICABLE
        fail = bool(ingress or egress)
    elif control_id == "NET-003":
        fail = any(rule["protocol"] == "-1" and public_permission(rule) for rule in ingress)
    else:
        if not ports:
            return AssessmentResult.NOT_APPLICABLE
        fail = any(
            public_permission(rule)
            and (
                rule["protocol"] in {"-1", "6"}
                or rule["protocol"] == "tcp"
                and any(rule["from_port"] <= p <= rule["to_port"] for p in ports)
            )
            for rule in ingress
        )
    return AssessmentResult.FAIL if fail else AssessmentResult.PASS


class SecurityGroupRule(SecurityRule):
    def __init__(self, control_id):
        self.contract = network_contract(control_id).technical
        self.control_id = control_id
        self.title = self.contract.title
        self.category = self.contract.category
        self.default_severity = self.contract.severity
        self.impact = self.contract.impact
        self.recommendation = self.contract.remediation_guidance

    def evaluate(self, snapshot):
        raise ValueError("network controls require assess with explicit versioned policy")

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
                result = network_result(self.control_id, proof["security_group"], profile)
                if result in {AssessmentResult.PASS, AssessmentResult.FAIL}:
                    evidence = {"source_proof": proof, "evaluation_version": "1.0.0"}
                reason = (
                    "Complete security-group evidence evaluated against the exact selected policy."
                )
            except IncompleteAssessmentEvidence:
                result = AssessmentResult.INSUFFICIENT_EVIDENCE
                reason = "Required security-group evidence is unavailable or inconsistent."
                missing = ("security_group.required_evidence",)
            results.append(
                self.assessment_for_resource(
                    snapshot,
                    profile,
                    target,
                    result=result,
                    evidence=evidence,
                    reason=reason,
                    collector="ec2.security-groups",
                    source_api="ec2:DescribeSecurityGroups",
                    missing_evidence=missing,
                )
            )
        return tuple(results)
