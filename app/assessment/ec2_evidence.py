"""Bounded 6C fact validation shared by rules and persistence; no AWS calls."""

import json
from ipaddress import IPv4Address
from uuid import UUID

from app.assessment.evidence_reader import IncompleteAssessmentEvidence
from app.assessment.identities import stable_resource_id
from app.schemas.resource import ResourceScope

EC2_CONTROL_IDS = ("EC2-001", "EC2-002", "EC2-003", "EC2-004")


def validate_public_ec2_allowlist(values):
    """Do not reinterpret old profiles; call only when EC2-002 is enabled."""
    for value in values:
        try:
            valid = str(UUID(value)) == value and UUID(value).version == 5
        except (ValueError, TypeError, AttributeError):
            valid = False
        if not valid:
            raise ValueError("EC2-002 requires canonical stable resource UUID approvals")


def _require(condition):
    if not condition:
        raise IncompleteAssessmentEvidence("required EC2 evidence is inconsistent or unavailable")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def ec2_facts(reader, contract, target, control_id):
    """Validate retained source facts, admission and applicability, not organization policy."""
    snapshot = reader.snapshot
    _, payload, _ = reader.resolve_source(contract.required_sources[0], target)
    _require(payload.get("account_id") == snapshot.account_id)
    _require(payload.get("region") == snapshot.requested_region)
    if control_id == "EC2-004":
        value = payload.get("ebs_encryption_by_default")
        _require(type(value) is bool)
        return {"ebs_encryption_by_default": value}

    family = contract.resource_families[0]
    resources = tuple(
        r
        for r in snapshot.resources
        if (r.service, r.resource_type) == (family.service, family.resource_type)
    )
    _require(
        all(
            r.account_id == snapshot.account_id
            and r.scope is ResourceScope.REGIONAL
            and r.region == snapshot.requested_region
            for r in resources
        )
    )
    ids = sorted(r.aws_resource_id for r in resources)
    _require(canonical(payload.get("resource_ids")) == canonical(ids))
    _require(type(payload.get("resource_count")) is int and payload["resource_count"] == len(ids))
    if target.resource_type == "aws_account":
        _require(not resources)
        return {"empty_population": True}

    admitted = reader.resources.get(reader._target_id(target))
    _require(admitted is not None)
    _, payload, _ = reader.resolve_source(contract.required_sources[1], target)
    expected = {
        "account_id": admitted.account_id,
        "region": admitted.region,
        "resource_type": admitted.resource_type,
        "resource_id": admitted.aws_resource_id,
        "arn": admitted.arn,
        "tags": [{"key": k, "value": v} for k, v in sorted(admitted.tags.items())],
        "configuration": admitted.configuration,
    }
    _require(canonical(payload) == canonical(expected))
    config = admitted.configuration
    if control_id == "EC2-001":
        options = config.get("metadata_options")
        _require(isinstance(options, dict))
        _require(options.get("state") == "applied")
        _require(
            options.get("http_endpoint") in {"enabled", "disabled"}
            if isinstance(options.get("http_endpoint"), str)
            else False
        )
        _require(
            options.get("http_tokens") in {"required", "optional"}
            if isinstance(options.get("http_tokens"), str)
            else False
        )
        return {"metadata_options": options}
    if control_id == "EC2-002":
        addresses = config.get("public_ipv4_addresses")
        _require(isinstance(addresses, list) and all(isinstance(a, str) for a in addresses))
        try:
            _require(all(str(IPv4Address(a)) == a for a in addresses))
        except ValueError:
            raise IncompleteAssessmentEvidence("invalid public IPv4 evidence") from None
        _require(addresses == sorted(set(addresses)))
        identity = stable_resource_id(
            provider="aws",
            aws_account_id=admitted.account_id,
            service=admitted.service,
            resource_type=admitted.resource_type,
            scope=admitted.scope,
            region=admitted.region,
            aws_resource_id=admitted.aws_resource_id,
        )
        return {"public_ipv4_addresses": addresses, "stable_resource_id": str(identity)}
    value = config.get("encrypted")
    _require(type(value) is bool)
    return {"encrypted": value}


def ec2_not_applicable(facts):
    return facts.get("empty_population") is True or (
        facts.get("metadata_options", {}).get("http_endpoint") == "disabled"
    )
