"""Closed required-tag source proofs, shared by assessment and persistence; no AWS calls."""

import re
from types import MappingProxyType

from app.assessment.cloudtrail_evidence import (
    DISCOVERY as TRAIL_DISCOVERY,
)
from app.assessment.cloudtrail_evidence import (
    IDENTITY as TRAIL_IDENTITY,
)
from app.assessment.cloudtrail_evidence import (
    exact_json_equal,
)
from app.assessment.cloudtrail_evidence import (
    source as trail_source,
)
from app.assessment.ec2_controls import ec2_execution
from app.assessment.evidence_reader import IncompleteAssessmentEvidence
from app.assessment.execution import RequiredSource, ResourceFamily
from app.assessment.extended_profiles import ExtendedAssessmentProfile
from app.assessment.iam_policy_evidence import policy_source
from app.assessment.models import AssessmentResult as R
from app.assessment.s3_configuration_evidence import DISCOVERY as BUCKET_DISCOVERY
from app.assessment.s3_configuration_evidence import LOCATION
from app.assessment.security_group_evidence import (
    GROUP_DISCOVERY,
    GROUP_FACTS,
    VPC_DISCOVERY,
    VPC_FACTS,
)
from app.assessment.security_group_evidence import (
    source as ec2_source,
)
from app.assessment.source_outcomes import EvidenceCollectionPhase, EvidenceSourceState
from app.schemas.resource import ResourceScope


def _tag_source(collector, kind, api, *, absence=False):
    return RequiredSource(
        collector=collector,
        evidence_kind=kind,
        source_api=api,
        subject="target",
        contract_version="1.0.0",
        completeness_fields=("complete",),
        expected_absence_is_complete=absence,
    )


# Each tuple is the exact discovery/admission/tag chain for one initial selector.
# Embedded EC2 tags share their authoritative admission source; no invented tag API.
GOVERNANCE_SOURCES_BY_TYPE = {
    "ec2_instance": ec2_execution("EC2-001").required_sources,
    "ebs_volume": ec2_execution("EC2-003").required_sources,
    "vpc": (VPC_DISCOVERY, VPC_FACTS),
    "subnet": (
        ec2_source("ec2.subnets", "ec2.subnets.discovery", "ec2:DescribeSubnets"),
        ec2_source("ec2.subnets", "ec2.subnet", "ec2:DescribeSubnets", resource=True),
    ),
    "security_group": (GROUP_DISCOVERY, GROUP_FACTS),
    "vpc_flow_log": (
        ec2_source("ec2.flow-logs", "ec2.flow-logs.discovery", "ec2:DescribeFlowLogs"),
        ec2_source("ec2.flow-logs", "ec2.vpc-flow-log", "ec2:DescribeFlowLogs", resource=True),
    ),
    "s3_bucket": (
        BUCKET_DISCOVERY,
        RequiredSource(
            collector=LOCATION.collector,
            evidence_kind=LOCATION.evidence_kind,
            source_api=LOCATION.source_api,
            subject="target",
            contract_version="1.0.0",
            completion="admitted_resource_v1",
        ),
        _tag_source("s3.bucket-tags", "s3.bucket-tags", "s3:GetBucketTagging", absence=True),
    ),
    "iam_user": (
        policy_source("users", "users.discovery", "ListUsers", global_scope=True),
        policy_source("users", "user", "ListUsers", admitted=True),
        _tag_source("iam.users", "iam.user.tags", "iam:ListUserTags"),
    ),
    "iam_role": (
        policy_source("roles", "roles.discovery", "ListRoles", global_scope=True),
        policy_source("roles", "role", "ListRoles", admitted=True),
        _tag_source("iam.roles", "iam.role.tags", "iam:ListRoleTags"),
    ),
    "iam_customer_managed_policy": (
        policy_source(
            "policies", "customer-managed-policies.discovery", "ListPolicies", global_scope=True
        ),
        policy_source("policies", "customer-managed-policy", "ListPolicies", admitted=True),
        _tag_source("iam.policies", "iam.customer-managed-policy.tags", "iam:ListPolicyTags"),
    ),
    "cloudtrail_trail": (
        TRAIL_DISCOVERY,
        TRAIL_IDENTITY,
        trail_source(
            "cloudtrail.trail.tags", "cloudtrail:ListTags", collector="cloudtrail.trail-tags"
        ),
    ),
}
GOVERNANCE_FAMILIES = tuple(
    ResourceFamily(
        service="s3"
        if kind == "s3_bucket"
        else "iam"
        if kind.startswith("iam_")
        else "cloudtrail"
        if kind == "cloudtrail_trail"
        else "ec2",
        resource_type=kind,
    )
    for kind in sorted(GOVERNANCE_SOURCES_BY_TYPE)
)
GOVERNANCE_SOURCES = tuple(
    source
    for family in GOVERNANCE_FAMILIES
    for source in GOVERNANCE_SOURCES_BY_TYPE[family.resource_type]
)


def validate_governance_policy(profile):
    """Reject missing/invalid policy without changing any historical profile serialization."""
    if (
        not isinstance(profile, ExtendedAssessmentProfile)
        or not profile.required_tags
        or any(not key.strip() for key in profile.required_tags)
        or not profile.governed_resource_types
        or set(profile.governed_resource_types) - GOVERNANCE_SOURCES_BY_TYPE.keys()
        or profile.content_checksum != profile.calculate_content_checksum()
    ):
        raise ValueError("GOV-001 requires an exact explicit extended tag policy")


def require(condition):
    if not condition:
        raise IncompleteAssessmentEvidence("required governance evidence is incomplete")


def _resolved(reader, required, target, citations):
    outcome, _, citation = reader.resolve_source(required, target)
    artifact = reader._artifacts[outcome.evidence_reference]
    require(
        artifact.evidence_schema == required.evidence_kind
        and artifact.evidence_schema_version == "1.0.0"
    )
    require(
        outcome.phase
        is (
            EvidenceCollectionPhase.ENRICHMENT
            if required.subject == "target"
            else EvidenceCollectionPhase.DISCOVERY
        )
    )
    if required.subject != "target":
        require(outcome.state is EvidenceSourceState.PRESENT)
    citations[citation["source_outcome_id"]] = citation
    return artifact.model_dump(mode="json")["normalized_payload"]


def _population(reader, family, target, citations):
    payload = _resolved(
        reader, GOVERNANCE_SOURCES_BY_TYPE[family.resource_type][0], target, citations
    )
    resources = reader.governance_resource_families().get(
        (family.service, family.resource_type), ()
    )
    ids = sorted(r.aws_resource_id for r in resources)
    require(len(ids) == len(set(ids)))
    require(
        type(payload.get("discarded_item_count")) is int and payload["discarded_item_count"] == 0
    )
    if family.service == "cloudtrail":
        require(payload.get("collection_account_id") == reader.snapshot.account_id)
        require(payload.get("invocation_region") == reader.snapshot.requested_region)
        id_field, count_field = "trail_arns", "trail_count"
    else:
        require(payload.get("account_id") == reader.snapshot.account_id)
        id_field, count_field = (
            "bucket_names" if family.service == "s3" else "resource_ids",
            "resource_count",
        )
        if family.service == "ec2":
            require(payload.get("region") == reader.snapshot.requested_region)
            require(
                all(
                    r.scope is ResourceScope.REGIONAL
                    and r.region == reader.snapshot.requested_region
                    for r in resources
                )
            )
        elif family.service == "iam":
            require(payload.get("scope") == ResourceScope.GLOBAL.value)
            require(
                all(
                    r.account_id == reader.snapshot.account_id
                    and r.scope is ResourceScope.GLOBAL
                    and r.region is None
                    for r in resources
                )
            )
        else:
            require(
                all(
                    r.account_id == reader.snapshot.account_id and r.scope is ResourceScope.REGIONAL
                    for r in resources
                )
            )
    observed_ids = payload.get(id_field)
    require(
        isinstance(observed_ids, list) and all(isinstance(value, str) for value in observed_ids)
    )
    require(sorted(observed_ids) == ids)
    require(type(payload.get(count_field)) is int and payload[count_field] == len(ids))
    if "unadmitted_resources" in payload:
        require(payload["unadmitted_resources"] == [])
    return MappingProxyType({reader._target_id(r): r for r in resources})


def _governed_populations(reader, contract, target, profile):
    """Validate invariant coverage once per sealed reader and exact immutable policy.

    Cache failures too: an outage cannot turn into a decisive result on another target.
    Target admission/tag sources remain independently checked for every assessment.
    """
    key = (contract, profile.content_checksum)
    cache = reader._governance_population_cache
    if key not in cache:
        populations, citations = {}, {}
        try:
            for family in contract.resource_families:
                if family.resource_type in profile.governed_resource_types:
                    populations[family.resource_type] = _population(
                        reader, family, target, citations
                    )
        except IncompleteAssessmentEvidence:
            cache[key] = None
            raise
        cache[key] = (
            MappingProxyType(populations),
            tuple(MappingProxyType(citations[k]) for k in sorted(citations)),
        )
    if cache[key] is None:
        raise IncompleteAssessmentEvidence("required governance population evidence is incomplete")
    return cache[key]


def _tags(value):
    """Malformed source structures are gaps; complete blank string values remain failures."""
    require(isinstance(value, list))
    require(
        all(
            isinstance(item, dict)
            and item.keys() == {"key", "value"}
            and isinstance(item["key"], str)
            and isinstance(item["value"], str)
            for item in value
        )
    )
    keys = [item["key"] for item in value]
    require(keys == sorted(set(keys)))
    return {item["key"]: item["value"] for item in value}


def _resource_tags(reader, family, resource, citations):
    sources = GOVERNANCE_SOURCES_BY_TYPE[family.resource_type]
    identity = _resolved(reader, sources[1], resource, citations)
    if family.service == "ec2":
        require(
            exact_json_equal(
                identity,
                {
                    "account_id": resource.account_id,
                    "region": resource.region,
                    "resource_type": resource.resource_type,
                    "resource_id": resource.aws_resource_id,
                    "arn": resource.arn,
                    "tags": [{"key": k, "value": v} for k, v in sorted(resource.tags.items())],
                    "configuration": resource.configuration,
                },
            )
        )
        value = identity.get("tags")
    elif family.service == "iam":
        # Identity is captured before tag enrichment: bind immutable identity fields, not
        # the identity observation's necessarily older tags/configuration projection.
        require(
            all(
                identity.get(k) == v
                for k, v in {
                    "account_id": resource.account_id,
                    "resource_type": resource.resource_type,
                    "resource_id": resource.aws_resource_id,
                    "arn": resource.arn,
                    "name": resource.name,
                }.items()
            )
        )
        payload = _resolved(reader, sources[2], resource, citations)
        require(
            type(payload.get("discarded_item_count")) is int
            and payload["discarded_item_count"] == 0
        )
        require(
            all(
                payload.get(k) == v
                for k, v in {
                    "account_id": resource.account_id,
                    "resource_type": resource.resource_type,
                    "resource_id": resource.aws_resource_id,
                }.items()
            )
        )
        value = payload.get("tags")
    elif family.service == "s3":
        require(
            all(
                identity.get(k) == v
                for k, v in {
                    "account_id": resource.account_id,
                    "bucket_name": resource.aws_resource_id,
                    "bucket_arn": resource.arn,
                    "bucket_region": resource.region,
                }.items()
            )
        )
        require(identity.get("complete") is True)
        payload = _resolved(reader, sources[2], resource, citations)
        require(
            all(
                payload.get(k) == v
                for k, v in {
                    "account_id": resource.account_id,
                    "bucket_name": resource.aws_resource_id,
                    "bucket_arn": resource.arn,
                    "bucket_region": resource.region,
                }.items()
            )
        )
        value = payload.get("value")
    else:
        parts = resource.aws_resource_id.split(":", maxsplit=5)
        require(
            len(parts) == 6
            and parts[0] == "arn"
            and parts[1] in {"aws", "aws-cn", "aws-us-gov"}
            and parts[2] == "cloudtrail"
            and parts[3] == resource.region
            and parts[4] == resource.account_id
            and re.fullmatch(r"[0-9]{12}", parts[4]) is not None
            and parts[5] == f"trail/{resource.name}"
            and resource.arn == resource.aws_resource_id
            and resource.scope is ResourceScope.REGIONAL
        )
        require(identity.get("complete") is True)
        require(
            all(
                identity.get(k) == v
                for k, v in {
                    "collection_account_id": reader.snapshot.account_id,
                    "owner_account_id": resource.account_id,
                    "partition": parts[1],
                    "trail_arn": resource.arn,
                    "name": resource.name,
                    "home_region": resource.region,
                }.items()
            )
        )
        payload = _resolved(reader, sources[2], resource, citations)
        require(
            payload.get("trail_arn") == resource.arn
            and payload.get("home_region") == resource.region
        )
        value = payload.get("value")
    tags = _tags(value)
    require(exact_json_equal(tags, resource.tags))
    # The accepted assessment-artifact envelope trims nested strings. Preserve exact
    # tag keys/values losslessly without changing that historical interface. Original
    # strings remain in the cited source artifacts and resource snapshot.
    try:
        return [
            {"key_utf8_hex": k.encode("utf-8").hex(), "value_utf8_hex": v.encode("utf-8").hex()}
            for k, v in sorted(tags.items())
        ]
    except UnicodeEncodeError:
        raise IncompleteAssessmentEvidence(
            "required governance tag encoding is malformed"
        ) from None


def governance_proof(reader, contract, target, *, profile):
    """Conditional source requirements are closed per exact governed resource family."""
    validate_governance_policy(profile)
    citations = {}
    populations = {}
    # A multi-family control must not hide a failed family's enumeration behind
    # successful targets in another family. Prove the whole governed population;
    # only target-specific identity/tag enrichment is conditional per family.
    if (
        target.resource_type == "aws_account"
        or target.resource_type in profile.governed_resource_types
    ):
        populations, population_citations = _governed_populations(reader, contract, target, profile)
        citations.update({c["source_outcome_id"]: dict(c) for c in population_citations})
    facts = {"applicable": False, "empty_population": False, "tags": []}
    if target.resource_type == "aws_account":
        require(
            target.service == "iam"
            and target.account_id == reader.snapshot.account_id
            and target.aws_resource_id == reader.snapshot.account_id
            and target.scope is ResourceScope.GLOBAL
            and target.region is None
        )
        for family in contract.resource_families:
            if family.resource_type in profile.governed_resource_types:
                require(not populations[family.resource_type])
        facts["empty_population"] = True
    else:
        family = next(
            (
                f
                for f in contract.resource_families
                if (f.service, f.resource_type) == (target.service, target.resource_type)
            ),
            None,
        )
        resource = reader.resources.get(reader._target_id(target))
        require(family is not None and resource is not None)
        if target.resource_type in profile.governed_resource_types:
            require(reader._target_id(resource) in populations[family.resource_type])
            facts = {
                "applicable": True,
                "empty_population": False,
                "tags": _resource_tags(reader, family, resource, citations),
            }
    return {
        "schema_version": "1.10.0",
        "scan_id": str(reader.snapshot.scan_id),
        "sources": [citations[key] for key in sorted(citations)],
        "relationship_observation_ids": [],
        "profile_checksum": profile.content_checksum,
        "governance": facts,
    }


def governance_result(proof, profile):
    """One pure evaluator for engine and persistence; NIST metadata is never consulted."""
    if not proof["governance"]["applicable"]:
        return R.NOT_APPLICABLE
    tags = {
        bytes.fromhex(item["key_utf8_hex"]).decode("utf-8"): bytes.fromhex(
            item["value_utf8_hex"]
        ).decode("utf-8")
        for item in proof["governance"]["tags"]
    }
    return (
        R.PASS
        if all(
            not key.startswith("aws:")
            and isinstance(tags.get(key), str)
            and bool(tags[key].strip())
            for key in profile.required_tags
        )
        else R.FAIL
    )
