"""LOG-002/003: bounded deterministic CloudTrail coverage and integrity settings."""

import json

from app.assessment.cloudtrail_evidence import require
from app.assessment.evidence_reader import AssessmentEvidenceReader, IncompleteAssessmentEvidence
from app.assessment.execution import account_target, assessment_targets
from app.assessment.models import AssessmentResult as R
from app.rules.base import SecurityRule

OPERATORS = ("equals", "starts_with", "ends_with", "not_equals", "not_starts_with", "not_ends_with")
EXCLUSIONS = {"kms.amazonaws.com", "rdsdata.amazonaws.com"}


def _strings(value, *, nonempty=False):
    require(isinstance(value, list) and (not nonempty or bool(value)))
    require(all(isinstance(v, str) and v.strip() == v and bool(v) for v in value))
    require(len(set(value)) == len(value))
    return set(value)


def _documents(value):
    require(isinstance(value, list))
    require(all(isinstance(v, dict) for v in value))
    require(len({json.dumps(v, sort_keys=True) for v in value}) == len(value))
    return value


def selector_coverage(value):
    """Return read/write coverage or unknown; malformed evidence raises typed insufficiency."""
    require(isinstance(value, dict))
    require(set(value) == {"selector_form", "basic_selectors", "advanced_selectors"})
    basic = _documents(value["basic_selectors"])
    advanced = _documents(value["advanced_selectors"])
    require(bool(basic) != bool(advanced))
    require(value["selector_form"] == ("BASIC" if basic else "ADVANCED"))
    if basic:
        dimensions = {"read": [], "write": []}
        for selector in basic:
            require(
                set(selector)
                == {
                    "raw_presence",
                    "include_management_events",
                    "read_write_type",
                    "exclude_management_event_sources",
                    "data_resources",
                }
            )
            presence = selector["raw_presence"]
            require(isinstance(presence, dict))
            require(
                set(presence)
                == {
                    "include_management_events",
                    "read_write_type",
                    "exclude_management_event_sources",
                    "data_resources",
                }
            )
            require(all(type(v) is bool for v in presence.values()))
            included = selector["include_management_events"]
            mode = selector["read_write_type"]
            require(type(included) is bool and isinstance(mode, str))
            require(mode in {"All", "ReadOnly", "WriteOnly"})
            excluded = _strings(selector["exclude_management_event_sources"])
            require(excluded <= EXCLUSIONS)
            for resource in _documents(selector["data_resources"]):
                require(set(resource) == {"type", "values"})
                require(isinstance(resource["type"], str) and bool(resource["type"].strip()))
                _strings(resource["values"], nonempty=True)
            defaults = {
                "include_management_events": True,
                "read_write_type": "All",
                "exclude_management_event_sources": [],
                "data_resources": [],
            }
            require(all(presence[k] or selector[k] == default for k, default in defaults.items()))
            if included:
                if mode in {"All", "ReadOnly"}:
                    dimensions["read"].append(excluded)
                if mode in {"All", "WriteOnly"}:
                    dimensions["write"].append(excluded)
        return tuple(bool(sets) and not set.intersection(*sets) for sets in dimensions.values())

    covered = set()
    unknown = False
    for selector in advanced:
        require(set(selector) == {"name", "field_selectors"})
        require(
            selector["name"] is None
            or (isinstance(selector["name"], str) and bool(selector["name"].strip()))
        )
        fields = _documents(selector["field_selectors"])
        require(bool(fields))
        category_seen = False
        restricted = False
        dimensions = {"true", "false"}
        for field in fields:
            require(set(field) == {"field", *OPERATORS})
            require(isinstance(field["field"], str) and bool(field["field"].strip()))
            operators = {k: _strings(field[k]) for k in OPERATORS}
            require(any(operators.values()))
            if field["field"] in {"eventCategory", "readOnly"}:
                # These expressions are outside the approved proof subset, not guessed false.
                if any(operators[k] for k in OPERATORS if k != "equals"):
                    raise IncompleteAssessmentEvidence("unsupported CloudTrail selector expression")
                if field["field"] == "eventCategory":
                    require(operators["equals"] == {"Management"})
                    category_seen = True
                else:
                    require(bool(operators["equals"]) and operators["equals"] <= {"true", "false"})
                    dimensions &= operators["equals"]
            else:
                restricted = True
        require(category_seen)
        if restricted:
            unknown = True
        else:
            covered |= dimensions
    if covered == {"true", "false"}:
        return True, True
    return None if unknown else ("true" in covered, "false" in covered)


def cloudtrail_result(control_id, proof):
    """One pure evaluator shared by rule execution and persistence validation."""
    facts = proof["cloudtrail"]
    if control_id == "LOG-003":
        if facts["empty_population"]:
            return R.NOT_APPLICABLE
        require(len(facts["trails"]) == 1)
        return R.PASS if facts["trails"][0]["log_file_validation_enabled"] else R.FAIL
    if control_id != "LOG-002":
        raise ValueError("unsupported CloudTrail control")
    outcomes = []
    for trail in facts["trails"]:
        coverage = selector_coverage(trail["event_selectors"])
        outcomes.append(
            None
            if coverage is None
            else trail["is_logging"] and trail["is_multi_region_trail"] and all(coverage)
        )
    if any(value is True for value in outcomes):
        return R.PASS
    return R.INSUFFICIENT_EVIDENCE if None in outcomes else R.FAIL


class CloudTrailRule(SecurityRule):
    def __init__(self, control_id):
        from app.assessment.cloudtrail_controls import cloudtrail_contract

        self.contract = cloudtrail_contract(control_id).technical
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
        raise ValueError("CloudTrail controls require explicit catalog/profile selection")

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
                result = cloudtrail_result(self.control_id, proof)
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
                        R.PASS: "Retained CloudTrail evidence satisfies the control.",
                        R.FAIL: "Complete CloudTrail evidence does not satisfy the control.",
                        R.NOT_APPLICABLE: "Complete discovery contains no CloudTrail trails.",
                        R.INSUFFICIENT_EVIDENCE: "Required CloudTrail evidence is incomplete "
                        "or unsupported.",
                    }[result],
                    collector="cloudtrail_evidence",
                    source_api="cloudtrail:ListTrails,cloudtrail:GetTrail,cloudtrail:GetTrailStatus,cloudtrail:GetEventSelectors"
                    if self.control_id == "LOG-002"
                    else "cloudtrail:ListTrails,cloudtrail:GetTrail",
                    missing_evidence=("cloudtrail.required_evidence",)
                    if result is R.INSUFFICIENT_EVIDENCE
                    else (),
                )
            )
        return tuple(results)
