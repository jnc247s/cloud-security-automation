"""Bounded S3-002 policy/ACL aggregation, not an effective-permissions simulator."""

import json
import re
from enum import StrEnum

from app.assessment.evidence_graph import s3_acl_ownership_conflicts
from app.assessment.evidence_reader import AssessmentEvidenceReader, IncompleteAssessmentEvidence
from app.assessment.execution import account_target, assessment_targets
from app.assessment.models import AssessmentResult as R
from app.assessment.s3_exposure import _canonical_principal_token
from app.assessment.s3_exposure_evidence import bind_approvals
from app.assessment.s3_identity import S3BucketIdentity
from app.rules.base import SecurityRule
from app.rules.s3_configuration import _flags, _values


class Channel(StrEnum):
    NONE = "NO_EXPOSURE"
    APPROVED = "APPROVED_EXPOSURE"
    UNAPPROVED = "CONFIRMED_UNAPPROVED"
    UNKNOWN = "UNKNOWN"


PUBLIC_GROUPS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}
LOG_DELIVERY = "http://acs.amazonaws.com/groups/s3/LogDelivery"


def _combine(channels):
    for channel in (Channel.UNAPPROVED, Channel.UNKNOWN, Channel.APPROVED):
        if channel in channels:
            return channel
    return Channel.NONE


def _grant(token, approval):
    approved = approval and (
        approval.allow_public if token == "*" else token in approval.approved_external_principals
    )
    return Channel.APPROVED if approved else Channel.UNAPPROVED


def _principal(kind, value, owner_account, owner_id):
    """None means same-owner/service, '?' unsupported, '*' public, else exact token."""
    if kind == "Service":
        return (
            None
            if re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)*\.amazonaws\.com(?:\.cn)?", value)
            else "?"
        )
    if kind == "CanonicalUser":
        if owner_id is None:
            return "?"
        if value == owner_id:
            return None
        value = f"canonical-user:{value}"
    elif kind == "AWS":
        if value == "*":
            return "*"
        if re.fullmatch(r"[0-9]{12}", value):
            value = f"account:{value}"
        elif not value.startswith("arn:"):
            # Approval tokens are an internal format, not valid AWS Principal syntax.
            return "?"
    else:
        return "?"
    try:
        token = _canonical_principal_token(value)
    except ValueError:
        return "?"
    account = (
        token.split(":")[1]
        if token.startswith("account:")
        else (token.split(":")[4] if token.startswith("arn:") else None)
    )
    return None if account is not None and account == owner_account else token


def _policy_principals(document, arn, owner_account, owner_id):
    tokens = []
    for statement in document["Statement"]:
        if statement["Effect"] == "Deny":
            continue
        actions, resources = _values(statement.get("Action")), _values(statement.get("Resource"))
        # Bounded attribution: exact bucket, its objects, or all resources. Other forms
        # remain uncertain; conditions/denies are retained, never used as exemptions.
        if (
            {"NotPrincipal", "NotAction", "NotResource"}.intersection(statement)
            or not actions
            or not all(re.fullmatch(r"(?:\*|s3:[A-Za-z*]+)", a, re.IGNORECASE) for a in actions)
            or not resources
            or not all(
                r in {"*", arn} or r.startswith(f"{arn}/") and "${" not in r for r in resources
            )
        ):
            tokens.append("?")
            continue
        principal = statement.get("Principal")
        if principal == "*":
            tokens.append("*")
        elif isinstance(principal, dict):
            for kind, values in principal.items():
                tokens.extend(_principal(kind, v, owner_account, owner_id) for v in _values(values))
        else:
            tokens.append("?")
    return tokens


def _policy_channel(observations, identity, restrict, approval, owner_id):
    body, status = observations["s3.bucket-policy"], observations["s3.bucket-policy-status"]
    if "CONFLICT" in {body["state"], status["state"]}:
        return Channel.UNKNOWN
    if status["state"] not in {"PRESENT", "EXPECTED_ABSENCE"}:
        return Channel.UNKNOWN
    public = status["value"]["is_public"]
    if body["state"] == "EXPECTED_ABSENCE":
        return Channel.UNKNOWN if public else Channel.NONE
    if public and restrict is False and not (approval and approval.allow_public):
        return Channel.UNAPPROVED
    if body["state"] != "PRESENT":
        return Channel.UNKNOWN
    if public and restrict is True:
        return Channel.NONE
    if public and restrict is None:
        return Channel.UNKNOWN
    tokens = _policy_principals(
        body["value"]["document"], identity.bucket_arn, identity.aws_account_id, owner_id
    )
    channels = [_grant("*", approval)] if public else []
    for token in tokens:
        if token is None:
            continue
        if token == "?":
            channels.append(Channel.UNKNOWN)
        elif token != "*":
            channels.append(_grant(token, approval))
        # Conditional wildcard grants are classified by S3, not a home-grown trust solver.
    return _combine(channels)


def _acl_channel(observations, ignore, approval):
    acl = observations["s3.bucket-acl"]
    if acl["state"] not in {"PRESENT", "CONFLICT"}:
        return Channel.UNKNOWN
    value = acl["value"]
    ownership = observations["s3.bucket-ownership-controls"]
    if s3_acl_ownership_conflicts(acl_value=value, ownership_controls_value=ownership["value"]):
        return Channel.UNKNOWN
    channels = []
    for grant in value["grants"]:
        grantee = grant["grantee"]
        if grantee["type"] == "CanonicalUser":
            token = _principal("CanonicalUser", grantee["id"], None, value["owner"]["id"])
            channels.append(
                Channel.UNKNOWN
                if token == "?"
                else _grant(token, approval)
                if token
                else Channel.NONE
            )
        elif grantee["type"] == "Group" and grantee["uri"] in PUBLIC_GROUPS:
            channels.append(Channel.UNKNOWN if ignore is True else _grant("*", approval))
        elif grantee["type"] != "Group" or grantee["uri"] != LOG_DELIVERY:
            channels.append(Channel.UNKNOWN)
    return _combine(channels)


def exposure_result(proof, profile):
    """Recompute and retain the decision facts and exact policy, shared with persistence."""
    policy = bind_approvals(proof, profile)
    facts = proof["s3_exposure"]
    if facts.get("empty_population"):
        return R.NOT_APPLICABLE
    identity = S3BucketIdentity.model_validate_json(json.dumps(facts["bucket_identity"]))
    approval = policy.get_bucket_approval(identity)
    observations = facts["observations"]
    account = _flags(observations["s3.account-public-access-block"])
    bucket = _flags(observations["s3.bucket-public-access-block"])
    effective = {
        key: True
        if account[key] is True or bucket[key] is True
        else False
        if account[key] is False and bucket[key] is False
        else None
        for key in ("RestrictPublicBuckets", "IgnorePublicAcls")
    }
    acl = observations["s3.bucket-acl"]
    owner_id = None
    if acl["state"] in {"PRESENT", "CONFLICT"} and not s3_acl_ownership_conflicts(
        acl_value=acl["value"],
        ownership_controls_value=observations["s3.bucket-ownership-controls"]["value"],
    ):
        # A public-group/BPA contradiction does not invalidate the independently retained
        # owner ID used to distinguish fixed canonical-user policy principals.
        owner_id = acl["value"]["owner"]["id"]
    channels = (
        _policy_channel(
            observations, identity, effective["RestrictPublicBuckets"], approval, owner_id
        ),
        _acl_channel(observations, effective["IgnorePublicAcls"], approval),
    )
    proof["exposure_decision"] = {
        "policy_channel": channels[0].value,
        "acl_channel": channels[1].value,
        "effective_bpa": effective,
    }
    combined = _combine(channels)
    return (
        R.FAIL
        if combined is Channel.UNAPPROVED
        else R.INSUFFICIENT_EVIDENCE
        if combined is Channel.UNKNOWN
        else R.PASS
    )


class S3ExposureRule(SecurityRule):
    def __init__(self):
        from app.assessment.s3_exposure_control import exposure_contract

        self.contract = exposure_contract().technical
        for name, value in {
            "control_id": "S3-002",
            "title": self.contract.title,
            "category": self.contract.category,
            "default_severity": self.contract.severity,
            "impact": self.contract.impact,
            "recommendation": self.contract.remediation_guidance,
        }.items():
            setattr(self, name, value)

    def evaluate(self, snapshot):
        raise ValueError("S3 exposure requires explicit catalog/profile selection")

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
                result = exposure_result(proof, profile)
                if result in {R.PASS, R.FAIL}:
                    evidence = {"source_proof": proof, "evaluation_version": "1.0.0"}
            except IncompleteAssessmentEvidence:
                result = R.INSUFFICIENT_EVIDENCE
            reasons = {
                R.PASS: "Both direct S3 exposure channels are safe or explicitly approved.",
                R.FAIL: "At least one direct S3 channel proves unapproved exposure.",
                R.NOT_APPLICABLE: "Complete bucket discovery contains no buckets.",
                R.INSUFFICIENT_EVIDENCE: (
                    "Required S3 exposure evidence or approval policy is unavailable, "
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
                    source_api="s3:GetBucketPolicyStatus",
                    missing_evidence=("s3_exposure.required_evidence",)
                    if result is R.INSUFFICIENT_EVIDENCE
                    else (),
                )
            )
        return tuple(results)
