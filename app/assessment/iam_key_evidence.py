"""Complete same-scan IAM key facts and provenance; no threshold or security decisions."""

from collections.abc import Mapping
from datetime import datetime

from app.assessment.evidence_graph import source_provenance_key
from app.assessment.evidence_reader import IncompleteAssessmentEvidence
from app.assessment.execution import RequiredSource
from app.assessment.relationships import RelationshipType
from app.assessment.source_outcomes import EvidenceSourceState
from app.schemas.resource import ResourceScope


def iam_source(kind, api, *, subject="target", admitted=False, absence=False):
    return RequiredSource(
        collector="iam.users",
        evidence_kind=kind,
        source_api=f"iam:{api}",
        subject=subject,
        contract_version="1.0.0",
        completeness_fields=() if admitted else ("complete",),
        completion="admitted_resource_v1" if admitted else "payload_flags_v1",
        expected_absence_is_complete=absence,
    )


USER_DISCOVERY = iam_source("iam.users.discovery", "ListUsers", subject="global_account")
USER_IDENTITY = iam_source("iam.user", "ListUsers", admitted=True)
KEY_ENUMERATION = iam_source("iam.user.access-keys", "ListAccessKeys")
KEY_IDENTITY = iam_source("iam.access-key", "ListAccessKeys", admitted=True)
KEY_USAGE = iam_source("iam.access-key.last-used", "GetAccessKeyLastUsed", absence=True)


def evidence_time(value):
    """Accept an aware normalized timestamp, never a guessed time or local clock."""
    try:
        parsed = datetime.fromisoformat(value) if isinstance(value, str) else None
    except ValueError:
        parsed = None
    if parsed is None or parsed.tzinfo is None or parsed.utcoffset() is None:
        raise IncompleteAssessmentEvidence("required IAM timestamp is unavailable")
    return parsed


def _ids(payload, field, count):
    values = payload.get(field)
    if (
        not isinstance(values, list | tuple)
        or any(not isinstance(value, str) or not value for value in values)
        or len(set(values)) != len(values)
        or type(payload.get(count)) is not int
        or payload[count] != len(values)
    ):
        raise IncompleteAssessmentEvidence("IAM enumeration identity set is invalid")
    return set(values)


def iam_key_proof(reader, contract, target):
    """Bind enumeration, child admission and optional active-key usage to exact edges."""
    if contract.required_sources != (USER_DISCOVERY, USER_IDENTITY, KEY_ENUMERATION):
        raise IncompleteAssessmentEvidence("unsupported IAM key source contract")
    citations = {}

    def source(required, resource):
        outcome, payload, citation = reader.resolve_source(required, resource)
        citations[str(outcome.source_outcome_id)] = citation
        return outcome, payload

    _, discovery = source(USER_DISCOVERY, target)
    user_ids = _ids(discovery, "resource_ids", "resource_count")
    observed_users = {
        r.aws_resource_id
        for r in reader.snapshot.resources
        if r.service == "iam" and r.resource_type == "iam_user"
    }
    if user_ids != observed_users:
        raise IncompleteAssessmentEvidence("IAM user enumeration differs from retained resources")
    edges = []
    active_keys = []
    if target.resource_type == "aws_account":
        if user_ids:
            raise IncompleteAssessmentEvidence("IAM empty population is not established")
    else:
        if (
            target.account_id != reader.snapshot.account_id
            or target.scope is not ResourceScope.GLOBAL
            or target.aws_resource_id not in user_ids
        ):
            raise IncompleteAssessmentEvidence("IAM user identity is outside collection scope")
        source(USER_IDENTITY, target)
        _, enumeration = source(KEY_ENUMERATION, target)
        key_ids = _ids(enumeration, "key_resource_ids", "key_count")
        observed_keys = {
            resource.aws_resource_id
            for resource in reader.snapshot.resources
            if resource.service == "iam"
            and resource.resource_type == "iam_access_key"
            and resource.account_id == target.account_id
            and resource.configuration.get("user_id") == target.aws_resource_id
        }
        if key_ids != observed_keys:
            raise IncompleteAssessmentEvidence(
                "IAM key enumeration differs from retained resources"
            )
        relationships = reader._edges.get(
            (reader._target_id(target), RelationshipType.HAS_ACCESS_KEY), ()
        )
        if (
            any(not edge.is_resolved for edge in relationships)
            or len(relationships) != len(key_ids)
            or {edge.target.aws_resource_id for edge in relationships} != key_ids
        ):
            raise IncompleteAssessmentEvidence("IAM key enumeration/relationships are incomplete")
        for edge in sorted(relationships, key=lambda item: str(item.observation_id)):
            key = reader.resources.get(edge.target.resource_snapshot_id)
            if key is None or key.account_id != target.account_id:
                raise IncompleteAssessmentEvidence("IAM key endpoint is unavailable")
            outcome, identity = source(KEY_IDENTITY, key)
            provenance = reader._provenance[source_provenance_key(edge.provenance)]
            if len(provenance) != 1 or provenance[0].source_outcome_id != outcome.source_outcome_id:
                raise IncompleteAssessmentEvidence("IAM key edge has different identity evidence")
            config = identity.get("configuration")
            if (
                not isinstance(config, Mapping)
                or config.get("user_id") != target.aws_resource_id
                or identity.get("resource_id") != key.aws_resource_id
                or config.get("status") not in {"Active", "Inactive"}
            ):
                raise IncompleteAssessmentEvidence("IAM key identity/status is unavailable")
            for field in ("user_id", "status", "created_at", "observed_at"):
                if key.configuration.get(field) != config.get(field):
                    raise IncompleteAssessmentEvidence(
                        "IAM key facts differ from identity evidence"
                    )
            edges.append(str(edge.observation_id))
            if config["status"] != "Active":
                continue
            created = evidence_time(config.get("created_at"))
            observed = evidence_time(config.get("observed_at"))
            if observed != reader.snapshot.collected_at or created > observed:
                raise IncompleteAssessmentEvidence("IAM key chronology is inconsistent")
            fact = {
                "resource_snapshot_id": str(edge.target.resource_snapshot_id),
                "created_at": created.isoformat(),
                "observed_at": observed.isoformat(),
            }
            if contract.validation_strategy == "iam_active_key_usage_v1":
                usage_outcome, usage = source(KEY_USAGE, key)
                state = usage.get("last_used_state")
                last_used = usage.get("last_used_at")
                if (
                    state not in {"recorded_use", "no_recorded_use"}
                    or evidence_time(usage.get("observed_at")) != observed
                    or (state == "no_recorded_use")
                    != (usage_outcome.state is EvidenceSourceState.EXPECTED_ABSENCE)
                    or (state == "no_recorded_use" and last_used is not None)
                    or any(
                        key.configuration.get(field) != usage.get(field)
                        for field in ("last_used_state", "last_used_at", "observed_at")
                    )
                ):
                    raise IncompleteAssessmentEvidence("IAM key last-use state is inconsistent")
                if state == "recorded_use":
                    used = evidence_time(last_used)
                    if not created <= used <= observed:
                        raise IncompleteAssessmentEvidence(
                            "IAM last-use chronology is inconsistent"
                        )
                fact.update(last_used_state=state, last_used_at=last_used)
            active_keys.append(fact)
    return {
        "schema_version": "1.1.0",
        "scan_id": str(reader.snapshot.scan_id),
        "sources": [citations[key] for key in sorted(citations)],
        "relationship_observation_ids": sorted(edges),
        "iam_active_keys": sorted(active_keys, key=lambda item: item["resource_snapshot_id"]),
    }
