"""Contract tests for normalized per-source AWS evidence outcomes."""

import subprocess
import sys
from datetime import UTC, datetime
from uuid import UUID

import pytest
from pydantic import ValidationError

from app.assessment.source_outcomes import (
    SOURCE_OUTCOME_SCHEMA_VERSION,
    AccountEvidenceSubject,
    EvidenceCollectionPhase,
    EvidenceFailureCategory,
    EvidenceSourceState,
    ResourceEvidenceSubject,
    SourceEvidenceOutcome,
)
from app.schemas.resource import ResourceScope

ACCOUNT_ID = "123456789012"
SCAN_ID = UUID("881a3ce3-b562-50ba-9c11-a57e523f038f")
OTHER_SCAN_ID = UUID("d8b758f4-71dd-5024-9140-150b271b4e66")
COLLECTED_AT = datetime(2026, 9, 14, 10, 30, tzinfo=UTC)
DIGEST = "a" * 64


def _account_subject(
    *,
    account_id: str = ACCOUNT_ID,
    scope: ResourceScope = ResourceScope.REGIONAL,
    region: str | None = "us-east-1",
) -> AccountEvidenceSubject:
    return AccountEvidenceSubject(
        aws_account_id=account_id,
        scope=scope,
        region=region,
    )


def _resource_subject(
    *,
    scan_id: UUID = SCAN_ID,
    account_id: str = ACCOUNT_ID,
    service: str = "s3",
    resource_type: str = "s3_bucket",
    aws_resource_id: str = "example-sensitive-bucket",
    scope: ResourceScope = ResourceScope.REGIONAL,
    region: str | None = "us-east-1",
) -> ResourceEvidenceSubject:
    return ResourceEvidenceSubject.for_aws_resource(
        scan_id=scan_id,
        aws_account_id=account_id,
        service=service,
        resource_type=resource_type,
        aws_resource_id=aws_resource_id,
        scope=scope,
        region=region,
    )


def _outcome(
    *,
    scan_id: UUID = SCAN_ID,
    phase: EvidenceCollectionPhase = EvidenceCollectionPhase.ENRICHMENT,
    subject: AccountEvidenceSubject | ResourceEvidenceSubject | None = None,
    state: EvidenceSourceState = EvidenceSourceState.PRESENT,
    failure_category: EvidenceFailureCategory | None = None,
    **overrides: object,
) -> SourceEvidenceOutcome:
    values: dict[str, object] = {
        "scan_id": scan_id,
        "collection_account_id": ACCOUNT_ID,
        "phase": phase,
        "subject": subject or _resource_subject(scan_id=scan_id),
        "evidence_kind": "s3.bucket-policy",
        "state": state,
        "failure_category": failure_category,
        "collector": "S3BucketCollector",
        "collector_version": "1.0.0",
        "source_api": "s3:GetBucketPolicy",
        "collected_at": COLLECTED_AT,
        "evidence_reference": "normalized://s3/bucket/example-sensitive-bucket/policy",
        "evidence_sha256": DIGEST,
    }
    values.update(overrides)
    return SourceEvidenceOutcome.for_observation(**values)  # type: ignore[arg-type]


def test_source_states_are_closed_and_explicit() -> None:
    assert {state.value for state in EvidenceSourceState} == {
        "PRESENT",
        "EXPECTED_ABSENCE",
        "UNAVAILABLE",
        "MALFORMED",
        "CONFLICT",
        "RESOURCE_DISAPPEARED",
    }


def test_complete_discovery_is_account_scoped_and_deterministic() -> None:
    first = _outcome(
        phase=EvidenceCollectionPhase.DISCOVERY,
        subject=_account_subject(),
        evidence_kind="ec2.instances",
        collector="Ec2InstanceCollector",
        source_api="ec2:DescribeInstances",
    )
    second = SourceEvidenceOutcome.model_validate_json(first.model_dump_json())

    assert first == second
    assert first.source_outcome_id == second.source_outcome_id
    assert first.schema_version == SOURCE_OUTCOME_SCHEMA_VERSION
    assert isinstance(second.subject, AccountEvidenceSubject)


def test_discovery_subject_must_match_collection_account() -> None:
    with pytest.raises(ValidationError, match="must match.*collection account"):
        _outcome(
            phase=EvidenceCollectionPhase.DISCOVERY,
            subject=_account_subject(account_id="999900001111"),
        )


def test_enrichment_owner_can_differ_from_collection_account() -> None:
    outcome = _outcome(subject=_resource_subject(account_id="999900001111"))

    assert outcome.collection_account_id == ACCOUNT_ID
    assert isinstance(outcome.subject, ResourceEvidenceSubject)
    assert outcome.subject.aws_account_id == "999900001111"


def test_aws_managed_iam_resource_uses_owner_sentinel() -> None:
    subject = _resource_subject(
        account_id="aws",
        service="iam",
        resource_type="iam_aws_managed_policy",
        aws_resource_id="arn:aws:iam::aws:policy/ReadOnlyAccess",
        scope=ResourceScope.GLOBAL,
        region=None,
    )
    outcome = _outcome(subject=subject)

    assert outcome.collection_account_id == ACCOUNT_ID
    assert isinstance(outcome.subject, ResourceEvidenceSubject)
    assert outcome.subject.aws_account_id == "aws"


@pytest.mark.parametrize(
    ("state", "category"),
    [
        (EvidenceSourceState.PRESENT, None),
        (EvidenceSourceState.EXPECTED_ABSENCE, None),
        (EvidenceSourceState.UNAVAILABLE, EvidenceFailureCategory.ACCESS_DENIED),
        (EvidenceSourceState.UNAVAILABLE, EvidenceFailureCategory.AUTHENTICATION_FAILED),
        (EvidenceSourceState.UNAVAILABLE, EvidenceFailureCategory.THROTTLED),
        (EvidenceSourceState.UNAVAILABLE, EvidenceFailureCategory.TIMEOUT),
        (EvidenceSourceState.UNAVAILABLE, EvidenceFailureCategory.SERVICE_ERROR),
        (EvidenceSourceState.UNAVAILABLE, EvidenceFailureCategory.UNSUPPORTED_OPERATION),
        (EvidenceSourceState.MALFORMED, EvidenceFailureCategory.MALFORMED_RESPONSE),
        (EvidenceSourceState.CONFLICT, EvidenceFailureCategory.CONFLICTING_EVIDENCE),
        (
            EvidenceSourceState.RESOURCE_DISAPPEARED,
            EvidenceFailureCategory.RESOURCE_NOT_FOUND,
        ),
    ],
)
def test_every_valid_state_and_failure_category_pair_is_accepted(
    state: EvidenceSourceState,
    category: EvidenceFailureCategory | None,
) -> None:
    outcome = _outcome(state=state, failure_category=category)

    assert outcome.state is state
    assert outcome.failure_category is category


@pytest.mark.parametrize(
    ("state", "category", "message"),
    [
        (
            EvidenceSourceState.PRESENT,
            EvidenceFailureCategory.ACCESS_DENIED,
            "failure_category does not match",
        ),
        (
            EvidenceSourceState.EXPECTED_ABSENCE,
            EvidenceFailureCategory.RESOURCE_NOT_FOUND,
            "failure_category does not match",
        ),
        (EvidenceSourceState.UNAVAILABLE, None, "availability failure category"),
        (
            EvidenceSourceState.UNAVAILABLE,
            EvidenceFailureCategory.MALFORMED_RESPONSE,
            "availability failure category",
        ),
        (EvidenceSourceState.MALFORMED, None, "failure_category does not match"),
        (
            EvidenceSourceState.CONFLICT,
            EvidenceFailureCategory.SERVICE_ERROR,
            "failure_category does not match",
        ),
        (
            EvidenceSourceState.RESOURCE_DISAPPEARED,
            EvidenceFailureCategory.ACCESS_DENIED,
            "failure_category does not match",
        ),
    ],
)
def test_invalid_state_and_failure_category_pairs_are_rejected(
    state: EvidenceSourceState,
    category: EvidenceFailureCategory | None,
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        _outcome(state=state, failure_category=category)


def test_discovery_requires_account_subject() -> None:
    with pytest.raises(ValidationError, match="discovery outcomes require an account"):
        _outcome(phase=EvidenceCollectionPhase.DISCOVERY)


def test_enrichment_requires_resource_subject() -> None:
    with pytest.raises(ValidationError, match="enrichment outcomes require a resource"):
        _outcome(subject=_account_subject())


def test_resource_disappeared_cannot_be_account_discovery() -> None:
    with pytest.raises(ValidationError, match="valid only for resource enrichment"):
        _outcome(
            phase=EvidenceCollectionPhase.DISCOVERY,
            subject=_account_subject(),
            state=EvidenceSourceState.RESOURCE_DISAPPEARED,
            failure_category=EvidenceFailureCategory.RESOURCE_NOT_FOUND,
        )


def test_resource_subject_ids_are_bound_to_exact_identity_and_scan() -> None:
    valid = _resource_subject()
    forged_stable = valid.model_dump(mode="python")
    forged_stable["stable_resource_id"] = UUID("b4ca2162-0d92-57ec-8357-c930a4656414")

    with pytest.raises(ValidationError, match="stable_resource_id does not match"):
        ResourceEvidenceSubject.model_validate(forged_stable)

    with pytest.raises(ValidationError, match="resource_snapshot_id must identify"):
        _outcome(scan_id=OTHER_SCAN_ID, subject=valid)


@pytest.mark.parametrize(
    ("region", "aws_resource_id"),
    [
        ("us-east-1\x1fresource", "b"),
        ("us-east-1", "a\x1fb"),
    ],
)
def test_resource_subject_rejects_identity_delimiter_collisions(
    region: str,
    aws_resource_id: str,
) -> None:
    with pytest.raises(ValidationError, match="must not contain unit separators"):
        _resource_subject(
            service="future-service",
            resource_type="future_resource",
            region=region,
            aws_resource_id=aws_resource_id,
        )


@pytest.mark.parametrize(
    ("subject_factory", "message"),
    [
        (
            lambda: _account_subject(scope=ResourceScope.REGIONAL, region=None),
            "regional account evidence subjects require a region",
        ),
        (
            lambda: _account_subject(scope=ResourceScope.GLOBAL, region="us-east-1"),
            "global account evidence subjects must not define a region",
        ),
        (
            lambda: ResourceEvidenceSubject.for_aws_resource(
                scan_id=SCAN_ID,
                aws_account_id=ACCOUNT_ID,
                service="iam",
                resource_type="iam_user",
                aws_resource_id="alice",
                scope=ResourceScope.GLOBAL,
                region="us-east-1",
            ),
            "global resource evidence subjects must not define a region",
        ),
    ],
)
def test_subject_scope_and_region_must_be_coherent(subject_factory: object, message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        subject_factory()  # type: ignore[operator]


def test_subject_requires_twelve_digit_aws_account_id() -> None:
    for invalid_account_id in ("not-an-account", "123", "١٢٣٤٥٦٧٨٩٠١٢"):
        with pytest.raises(ValidationError):
            AccountEvidenceSubject(
                aws_account_id=invalid_account_id,
                scope=ResourceScope.GLOBAL,
            )

    with pytest.raises(ValidationError, match="collection_account_id"):
        _outcome(collection_account_id="not-an-account")


@pytest.mark.parametrize(
    ("service", "resource_type", "account_id", "scope", "region", "message"),
    [
        (
            "iam",
            "iam_aws_managed_policy",
            ACCOUNT_ID,
            ResourceScope.GLOBAL,
            None,
            "must use the aws owner sentinel",
        ),
        (
            "iam",
            "iam_customer_managed_policy",
            "aws",
            ResourceScope.GLOBAL,
            None,
            "aws owner sentinel is valid only",
        ),
        (
            "iam",
            "iam_user",
            ACCOUNT_ID,
            ResourceScope.REGIONAL,
            "us-east-1",
            "must use global scope",
        ),
    ],
)
def test_resource_subject_rejects_invalid_owner_or_known_scope(
    service: str,
    resource_type: str,
    account_id: str,
    scope: ResourceScope,
    region: str | None,
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        _resource_subject(
            service=service,
            resource_type=resource_type,
            account_id=account_id,
            scope=scope,
            region=region,
        )


def test_source_outcome_id_changes_across_scans_but_not_result_states() -> None:
    present = _outcome()
    unavailable = _outcome(
        state=EvidenceSourceState.UNAVAILABLE,
        failure_category=EvidenceFailureCategory.ACCESS_DENIED,
    )
    other_scan = _outcome(scan_id=OTHER_SCAN_ID)

    assert present.source_outcome_id == unavailable.source_outcome_id
    assert present.source_outcome_id != other_scan.source_outcome_id


def test_source_outcome_id_changes_with_declared_source_contract() -> None:
    baseline = _outcome()
    variants = (
        _outcome(evidence_kind="s3.bucket-acl"),
        _outcome(collector="ExpandedS3BucketCollector"),
        _outcome(collector_version="1.1.0"),
        _outcome(source_api="s3:GetBucketAcl"),
        _outcome(collection_account_id="999900001111"),
        _outcome(
            subject=ResourceEvidenceSubject.for_aws_resource(
                scan_id=SCAN_ID,
                aws_account_id=ACCOUNT_ID,
                service="s3",
                resource_type="s3_bucket",
                aws_resource_id="another-sensitive-bucket",
                scope=ResourceScope.REGIONAL,
                region="us-east-1",
            )
        ),
    )

    assert len({variant.source_outcome_id for variant in variants}) == len(variants)
    assert all(variant.source_outcome_id != baseline.source_outcome_id for variant in variants)


def test_forged_source_outcome_id_is_rejected() -> None:
    values = _outcome().model_dump(mode="python")
    values["source_outcome_id"] = UUID("aacb431f-18e9-5541-bfe8-ebca7957a163")

    with pytest.raises(ValidationError, match="source_outcome_id does not match"):
        SourceEvidenceOutcome.model_validate(values)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("collected_at", datetime(2026, 9, 14, 10, 30), "timezone-aware"),
        ("evidence_reference", "normalized://safe\nsecret", "String should match pattern"),
        ("evidence_sha256", "not-a-digest", "String should match pattern"),
    ],
)
def test_invalid_provenance_is_rejected(field: str, value: object, message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        _outcome(**{field: value})


def test_unknown_schema_version_is_rejected() -> None:
    values = _outcome().model_dump(mode="python")
    values["schema_version"] = "2.0.0"

    with pytest.raises(ValidationError, match="Input should be '1.0.0'"):
        SourceEvidenceOutcome.model_validate(values)


def test_models_are_strict_frozen_and_forbid_extra_fields() -> None:
    outcome = _outcome()

    with pytest.raises(ValidationError, match="frozen"):
        outcome.state = EvidenceSourceState.CONFLICT  # type: ignore[misc]

    values = outcome.model_dump(mode="python")
    values["unexpected"] = True
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        SourceEvidenceOutcome.model_validate(values)

    with pytest.raises(ValidationError):
        SourceEvidenceOutcome.model_validate(
            {**outcome.model_dump(mode="python"), "state": "PRESENT"}
        )


def test_json_schema_exposes_collection_identity_and_complete_provenance() -> None:
    schema = SourceEvidenceOutcome.model_json_schema()

    assert set(schema["required"]) >= {
        "source_outcome_id",
        "scan_id",
        "collection_account_id",
        "phase",
        "subject",
        "evidence_kind",
        "state",
        "collector",
        "collector_version",
        "source_api",
        "collected_at",
        "evidence_reference",
        "evidence_sha256",
    }


def test_contract_has_no_collector_service_rule_or_persistence_import_dependency() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import app.assessment.source_outcomes; "
            "assert not any(name == 'app.collectors' or name.startswith('app.collectors.') "
            "or name == 'app.services' or name.startswith('app.services.') "
            "or name == 'app.database' or name.startswith('app.database.') "
            "or name == 'app.rules' or name.startswith('app.rules.') "
            "or name == 'app.aws' or name.startswith('app.aws.') for name in sys.modules)",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
