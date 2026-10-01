"""Exact retained destination and validated dependency proofs, not an exposure evaluator."""

from app.assessment.cloudtrail_evidence import CONFIGURATION, cloudtrail_proof, require
from app.assessment.composition import ValidatedAssessmentContext
from app.assessment.evidence_graph import source_provenance_key
from app.assessment.models import AssessmentResult as R
from app.assessment.relationships import RelationshipType
from app.assessment.s3_identity import S3BucketIdentity
from app.schemas.inventory import CollectionStatus


def destination_proof(reader, contract, target, *, context=None, profile=None):
    proof = cloudtrail_proof(reader, contract, target, destination=True)
    proof["schema_version"] = "1.9.0"
    proof["destination_dependency"] = None
    if proof["cloudtrail"]["empty_population"]:
        return proof
    require(
        all(
            reader.snapshot.collection_status(name) is CollectionStatus.SUCCEEDED
            for name in ("cloudtrail_trails", "cloudtrail_evidence", "s3_buckets", "s3_evidence")
        )
    )
    require(isinstance(context, ValidatedAssessmentContext) and profile is not None)
    require(context.matches(reader, profile))
    edges = reader._edges.get((reader._target_id(target), RelationshipType.DELIVERS_TO_BUCKET), ())
    require(len(edges) == 1 and edges[0].is_resolved)
    edge = edges[0]
    bucket = reader.resources.get(edge.target.resource_snapshot_id)
    trail = proof["cloudtrail"]["trails"][0]
    require(
        bucket is not None
        and bucket.service == "s3"
        and bucket.resource_type == "s3_bucket"
        and bucket.aws_resource_id == trail["s3_bucket_name"]
        and bucket.name == trail["s3_bucket_name"]
    )
    identity = S3BucketIdentity.for_bucket(
        aws_account_id=bucket.account_id, bucket_region=bucket.region, bucket_arn=bucket.arn
    )
    outcomes = reader._provenance.get(source_provenance_key(edge.provenance), ())
    require(len(outcomes) == 1)
    configuration, _, _ = reader.resolve_source(CONFIGURATION, target)
    require(outcomes[0].source_outcome_id == configuration.source_outcome_id)
    dependency = context.prerequisites.get(("S3-002", reader._target_id(bucket)))
    require(dependency is not None and dependency.result in {R.PASS, R.FAIL})
    proof["relationship_observation_ids"] = [str(edge.observation_id)]
    proof["destination_dependency"] = {
        "bucket_identity": identity.model_dump(mode="json"),
        "control_id": dependency.control_id,
        "result": dependency.result.value,
        "resource_snapshot_id": str(dependency.resource_snapshot_id),
        "scan_id": str(dependency.scan_id),
        "inventory_sha256": dependency.inventory_sha256,
        "control_catalog_sha256": dependency.control_catalog_sha256,
        "profile_id": dependency.profile_id,
        "profile_version": dependency.profile_version,
        "profile_checksum": dependency.profile_checksum,
        "evaluation_version": "1.0.0",
        "evidence": sorted(
            (
                {"evidence_id": str(a.evidence_id), "payload_sha256": a.payload_sha256}
                for a in dependency.evidence_artifacts
            ),
            key=lambda a: a["evidence_id"],
        ),
        "approval_policy": profile.s3_exposure_approvals.model_dump(
            mode="json", exclude={"bucket_approvals"}
        ),
    }
    return proof


def destination_result(proof):
    if proof["cloudtrail"]["empty_population"]:
        return R.NOT_APPLICABLE
    return R(proof["destination_dependency"]["result"])
