"""Same-scan classifier/KMS inputs; conditional sources never imply compliance."""

import hashlib

from app.assessment.evidence_graph import _s3_kms_reference_region, s3_encryption_kms_references
from app.assessment.evidence_reader import IncompleteAssessmentEvidence
from app.assessment.relationships import RelationshipResolution, RelationshipType
from app.assessment.s3_configuration_evidence import (
    DISCOVERY,
    LOCATION,
    _observation,
    require,
    s3_configuration_proof,
    source,
)
from app.assessment.s3_identity import S3BucketIdentity
from app.assessment.source_outcomes import EvidenceSourceState

TAGS = source("s3.bucket-tags", "s3:GetBucketTagging")
ENCRYPTION = source("s3.bucket-encryption", "s3:GetEncryptionConfiguration")
SENSITIVE_KMS_SOURCES = (DISCOVERY, LOCATION, TAGS, ENCRYPTION)


def _key_proof(reader, bucket, reference, encryption):
    """Require this exact lookup, not a sibling key observation or unresolved edge."""
    region = _s3_kms_reference_region(
        reference=reference, bucket_region=bucket.region, partition=bucket.arn.split(":")[1]
    )
    kind = "kms.key." + hashlib.sha256(f"{region}\x00{reference}".encode()).hexdigest()
    declarations = reader._sources.get(("kms.keys", kind, "kms:DescribeKey"), ())
    require(len(declarations) == 1)
    declaration = declarations[0]
    require(declaration.contract_version == "1.0.0" and declaration.identity_authoritative)
    outcome = reader._outcomes[declaration.source_outcome_id]
    citation = reader._citation(outcome)
    payload = reader._artifacts[outcome.evidence_reference].model_dump(mode="json")[
        "normalized_payload"
    ]
    require(
        payload["region"] == region == bucket.region
        and payload["supplied_reference"] == reference
        and bucket.aws_resource_id in payload["source_bucket_names"]
    )
    key = reader.resources.get(getattr(outcome.subject, "resource_snapshot_id", None))
    require(key is not None)
    value = payload["key"]
    require(
        key.service == "kms"
        and key.resource_type == "kms_key"
        and key.account_id == value["aws_account_id"]
        and key.region == value["region"] == bucket.region
        and key.aws_resource_id == key.arn == value["arn"]
        and key.configuration == value
        and value["key_manager"] in {"AWS", "CUSTOMER"}
    )
    edges = [
        edge
        for edge in reader._edges.get(
            (reader._target_id(bucket), RelationshipType.ENCRYPTED_WITH), ()
        )
        if edge.resolution is RelationshipResolution.RESOLVED
        and edge.target.resource_snapshot_id == reader._target_id(key)
        and edge.provenance.evidence_reference == encryption.evidence_reference
    ]
    require(len(edges) == 1)
    return {
        "complete": True,
        "key": value,
        "source": citation,
        "relationship_observation_id": str(edges[0].observation_id),
    }


def sensitive_kms_proof(reader, contract, target):
    proof = s3_configuration_proof(reader, contract, target)
    proof["schema_version"] = "1.7.0"
    facts = proof.pop("s3_configuration")
    proof["s3_sensitive_kms"] = facts
    if facts.get("empty_population"):
        return proof
    bucket = reader.resources[reader._target_id(target)]
    facts["bucket_identity"] = S3BucketIdentity.for_bucket(
        aws_account_id=bucket.account_id, bucket_region=bucket.region, bucket_arn=bucket.arn
    ).model_dump(mode="json")
    require(
        not any(
            outcome.state is EvidenceSourceState.RESOURCE_DISAPPEARED
            and getattr(outcome.subject, "resource_snapshot_id", None) == reader._target_id(bucket)
            for outcome in reader._outcomes.values()
        )
    )
    _, encryption, payload, _ = _observation(reader, ENCRYPTION, bucket)
    facts["keys"] = {}
    if encryption.state is EvidenceSourceState.PRESENT:
        for reference in s3_encryption_kms_references(payload["value"]):
            try:
                key = _key_proof(reader, bucket, reference, encryption)
            except IncompleteAssessmentEvidence:
                # A denied key is required only after a sensitive classification and an
                # explicit KMS requirement; it cannot invalidate a proven N/A.
                key = {"complete": False}
            facts["keys"][reference] = key
            if key["complete"]:
                proof["sources"].append(key["source"])
                proof["relationship_observation_ids"].append(key["relationship_observation_id"])
    proof["sources"] = sorted(
        {s["source_outcome_id"]: s for s in proof["sources"]}.values(),
        key=lambda s: s["source_outcome_id"],
    )
    proof["relationship_observation_ids"] = sorted(set(proof["relationship_observation_ids"]))
    return proof
