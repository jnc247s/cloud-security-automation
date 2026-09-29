"""Bounded same-scan S3 configuration proofs; unavailable sources remain explicit."""

from app.assessment.evidence_reader import IncompleteAssessmentEvidence
from app.assessment.execution import RequiredSource
from app.assessment.source_outcomes import EvidenceSourceState
from app.schemas.resource import ResourceScope

S3_CONFIGURATION_IDS = ("S3-001", "S3-003")


def require(condition):
    if not condition:
        raise IncompleteAssessmentEvidence("required S3 configuration evidence is incomplete")


def source(kind, api, *, account=False, collector=None):
    return RequiredSource(
        collector=collector or kind,
        evidence_kind=kind,
        source_api=api,
        subject="global_account" if account else "target",
        contract_version="1.0.0",
        completeness_fields=("complete",),
        expected_absence_is_complete=True,
    )


DISCOVERY = source(
    "s3.buckets.discovery", "s3:ListAllMyBuckets", account=True, collector="s3.buckets"
)
LOCATION = source("s3.bucket-location", "s3:GetBucketLocation")
ACCOUNT_BPA = source(
    "s3.account-public-access-block", "s3:GetAccountPublicAccessBlock", account=True
)
BUCKET_BPA = source("s3.bucket-public-access-block", "s3:GetBucketPublicAccessBlock")
POLICY = source("s3.bucket-policy", "s3:GetBucketPolicy")
S3_SOURCES = {
    "s3_bpa_v1": (DISCOVERY, LOCATION, ACCOUNT_BPA, BUCKET_BPA),
    "s3_transport_v1": (DISCOVERY, LOCATION, POLICY),
}


def _observation(reader, required, target):
    """Bind all states to retained citations without relaxing the generic complete reader."""
    matches = [
        s
        for s in reader._sources.get(
            (required.collector, required.evidence_kind, required.source_api), ()
        )
        if s.contract_version == required.contract_version
        and reader._subject_matches(s.subject, required, target)
    ]
    require(len(matches) == 1)
    declaration = matches[0]
    outcome = reader._outcomes[declaration.source_outcome_id]
    artifact = reader._artifacts[outcome.evidence_reference]
    return (
        declaration,
        outcome,
        artifact.model_dump(mode="json")["normalized_payload"],
        {
            "source_outcome_id": str(outcome.source_outcome_id),
            "artifact_id": str(artifact.artifact_id),
            "evidence_sha256": artifact.evidence_sha256,
        },
    )


def s3_configuration_proof(reader, contract, target):
    _, discovery, payload, citation = _observation(reader, DISCOVERY, target)
    reader._citation(discovery)
    require(payload.get("account_id") == reader.snapshot.account_id)
    resources = tuple(
        r for r in reader.snapshot.resources if r.service == "s3" and r.resource_type == "s3_bucket"
    )
    names = sorted(r.aws_resource_id for r in resources)
    require(sorted(payload.get("bucket_names", ())) == names)
    require(type(payload.get("resource_count")) is int and payload["resource_count"] == len(names))
    require(len(names) == len(set(names)))
    require(
        all(
            r.account_id == reader.snapshot.account_id and r.scope is ResourceScope.REGIONAL
            for r in resources
        )
    )
    citations = [citation]
    facts = {"empty_population": True}
    if target.resource_type == "aws_account":
        require(not resources)
    else:
        bucket = reader.resources.get(reader._target_id(target))
        require(bucket is not None and bucket in resources)
        declaration, outcome, location, citation = _observation(reader, LOCATION, bucket)
        reader._citation(outcome)
        require(declaration.identity_authoritative)
        require(location.get("bucket_region") == bucket.region)
        require(location.get("bucket_name") == bucket.aws_resource_id)
        require(location.get("bucket_arn") == bucket.arn)
        require(location.get("account_id") == bucket.account_id)
        citations.append(citation)
        facts = {"bucket_arn": bucket.arn, "observations": {}}
        for required in contract.required_sources[2:]:
            _, outcome, payload, citation = _observation(reader, required, bucket)
            require(payload.get("account_id") == bucket.account_id)
            if required.subject == "target":
                require(payload.get("bucket_name") == bucket.aws_resource_id)
                require(payload.get("bucket_region") == bucket.region)
                require(payload.get("bucket_arn") == bucket.arn)
            usable = outcome.state in {
                EvidenceSourceState.PRESENT,
                EvidenceSourceState.EXPECTED_ABSENCE,
            }
            if usable:
                reader._citation(outcome, allow_absence=True)
            facts["observations"][required.evidence_kind] = {
                "state": outcome.state.value,
                "value": payload.get("public_access_block" if required == ACCOUNT_BPA else "value")
                if usable
                else None,
            }
            citations.append(citation)
    return {
        "schema_version": "1.5.0",
        "scan_id": str(reader.snapshot.scan_id),
        "sources": sorted(citations, key=lambda c: c["source_outcome_id"]),
        "relationship_observation_ids": [],
        "s3_configuration": facts,
    }
