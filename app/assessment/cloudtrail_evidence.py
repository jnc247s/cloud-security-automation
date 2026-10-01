"""Closed 6F.1 proofs over retained CloudTrail sources; no AWS or policy evaluation."""

import re

from app.assessment.evidence_reader import IncompleteAssessmentEvidence
from app.assessment.execution import RequiredSource
from app.schemas.resource import ResourceScope


def require(condition):
    if not condition:
        raise IncompleteAssessmentEvidence("required CloudTrail evidence is incomplete")


def exact_json_equal(left, right):
    """Compare JSON structure and scalar types, including immutable evidence containers."""
    if isinstance(left, dict) and isinstance(right, dict):
        return left.keys() == right.keys() and all(
            exact_json_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(
            exact_json_equal(a, b) for a, b in zip(left, right, strict=True)
        )
    return type(left) is type(right) and left == right


def source(kind, api, *, collector, account=False, identity=False):
    return RequiredSource(
        collector=collector,
        evidence_kind=kind,
        source_api=api,
        subject="global_account" if account else "target",
        contract_version="1.0.0",
        completion="admitted_resource_v1" if identity else "payload_flags_v1",
        completeness_fields=()
        if identity
        else ("complete", "admission_complete")
        if account
        else ("complete",),
    )


DISCOVERY = source(
    "cloudtrail.trails.discovery",
    "cloudtrail:ListTrails",
    collector="cloudtrail.trails",
    account=True,
)
IDENTITY = source(
    "cloudtrail.trail.identity",
    "cloudtrail:ListTrails",
    collector="cloudtrail.trails",
    identity=True,
)
CONFIGURATION = source(
    "cloudtrail.trail.configuration",
    "cloudtrail:GetTrail",
    collector="cloudtrail.trail-configuration",
)
STATUS = source(
    "cloudtrail.trail.status", "cloudtrail:GetTrailStatus", collector="cloudtrail.trail-status"
)
SELECTORS = source(
    "cloudtrail.trail.event-selectors",
    "cloudtrail:GetEventSelectors",
    collector="cloudtrail.trail-event-selectors",
)
CLOUDTRAIL_SOURCES = {
    # Child sources are bound to every exact discovery member by the closed account proof.
    "cloudtrail_management_coverage_v1": (DISCOVERY,),
    "cloudtrail_integrity_v1": (DISCOVERY, IDENTITY, CONFIGURATION),
}


def _resolved(reader, required, target):
    outcome, _, citation = reader.resolve_source(required, target)
    # Source artifacts freeze JSON arrays as tuples; inspect their canonical JSON view.
    payload = reader._artifacts[outcome.evidence_reference].model_dump(mode="json")[
        "normalized_payload"
    ]
    return payload, citation


def cloudtrail_proof(reader, contract, target, *, destination=False):
    """Bind coverage and decision facts to exact admitted trail snapshots and source digests."""
    discovery, citation = _resolved(reader, DISCOVERY, target)
    resources = tuple(
        sorted(
            (
                r
                for r in reader.snapshot.resources
                if r.service == "cloudtrail" and r.resource_type == "cloudtrail_trail"
            ),
            key=lambda r: r.identity,
        )
    )
    arns = [r.aws_resource_id for r in resources]
    require(discovery.get("collection_account_id") == reader.snapshot.account_id)
    require(discovery.get("invocation_region") == reader.snapshot.requested_region)
    require(isinstance(discovery.get("trail_arns"), list))
    require(all(isinstance(a, str) for a in discovery["trail_arns"]))
    require(sorted(discovery["trail_arns"]) == sorted(arns))
    require(len(set(arns)) == len(arns))
    require(type(discovery.get("trail_count")) is int and discovery["trail_count"] == len(arns))
    require(discovery.get("unadmitted_resources") == [])
    citations = [citation]
    account = contract.target_kind == "global_account"
    if account or target.resource_type == "aws_account":
        require(
            target.resource_type == "aws_account"
            and target.account_id == reader.snapshot.account_id
            and target.aws_resource_id == reader.snapshot.account_id
            and target.service == "cloudtrail"
            and target.scope is ResourceScope.GLOBAL
            and target.region is None
        )
        require(account or not resources)
        selected = resources if account else ()
    else:
        retained = reader.resources.get(reader._target_id(target))
        require(retained is not None and retained in resources)
        selected = (retained,)

    facts = []
    for trail in selected:
        identity, citation = _resolved(reader, IDENTITY, trail)
        parts = trail.aws_resource_id.split(":", maxsplit=5)
        require(
            len(parts) == 6
            and parts[0] == "arn"
            and parts[1] in {"aws", "aws-cn", "aws-us-gov"}
            and parts[2] == "cloudtrail"
            and parts[3] == trail.region
            and parts[4] == trail.account_id
            and re.fullmatch(r"[0-9]{12}", parts[4]) is not None
            and parts[5] == f"trail/{trail.name}"
            and trail.arn == trail.aws_resource_id
            and trail.scope is ResourceScope.REGIONAL
        )
        require(identity.get("complete") is True)
        require(
            all(
                identity.get(k) == v
                for k, v in {
                    "collection_account_id": reader.snapshot.account_id,
                    "owner_account_id": trail.account_id,
                    "partition": parts[1],
                    "trail_arn": trail.arn,
                    "name": trail.name,
                    "home_region": trail.region,
                }.items()
            )
        )
        require(trail.configuration.get("home_region") == trail.region)
        citations.append(citation)
        sources = (CONFIGURATION, STATUS, SELECTORS) if account else (CONFIGURATION,)
        values = {}
        for required in sources:
            payload, citation = _resolved(reader, required, trail)
            require(payload.get("trail_arn") == trail.arn)
            require(payload.get("home_region") == trail.region)
            require(isinstance(payload.get("value"), dict))
            values[required.evidence_kind] = payload["value"]
            citations.append(citation)
        configuration = values[CONFIGURATION.evidence_kind]
        require(configuration.get("name") == trail.name)
        fields = (
            ("s3_bucket_name",)
            if destination
            else ("is_multi_region_trail", "is_organization_trail")
            if account
            else ("log_file_validation_enabled",)
        )
        for field in fields:
            if destination:
                require(isinstance(configuration.get(field), str) and bool(configuration[field]))
                require(trail.configuration.get(field) == configuration[field])
            else:
                require(type(configuration.get(field)) is bool)
                require(trail.configuration.get(field) is configuration[field])
        item = {
            "resource_snapshot_id": str(reader._target_id(trail)),
            "trail_arn": trail.arn,
            "owner_account_id": trail.account_id,
            "home_region": trail.region,
            **{field: configuration[field] for field in fields},
        }
        if account:
            status = values[STATUS.evidence_kind]
            selectors = values[SELECTORS.evidence_kind]
            require(type(status.get("is_logging")) is bool)
            require(trail.configuration.get("is_logging") is status["is_logging"])
            require(exact_json_equal(trail.configuration.get("event_selectors"), selectors))
            item.update(is_logging=status["is_logging"], event_selectors=selectors)
        facts.append(item)
    return {
        "schema_version": "1.8.0",
        "scan_id": str(reader.snapshot.scan_id),
        "sources": sorted(citations, key=lambda c: c["source_outcome_id"]),
        "relationship_observation_ids": [],
        "cloudtrail": {"empty_population": not resources, "trails": facts},
    }
