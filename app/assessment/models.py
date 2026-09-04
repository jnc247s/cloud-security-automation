"""Immutable contracts for deterministic technical assessment evidence and results."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Self
from uuid import UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from app.schemas.resource import ResourceScope

_EVIDENCE_ID_NAMESPACE = UUID("51240b60-0475-5f64-a840-41c9e05288c7")
ControlId = Annotated[str, Field(pattern=r"^[A-Z0-9]+-\d{3}$")]
NonEmptyString = Annotated[str, Field(min_length=1)]


class _FrozenJsonDict(dict[str, JsonValue]):
    """A JSON object that rejects mutation after evidence validation."""

    @staticmethod
    def _immutable(*_args: object, **_kwargs: object) -> None:
        raise TypeError("evidence payload is immutable")

    __delitem__ = _immutable
    __ior__ = _immutable
    __setitem__ = _immutable
    clear = _immutable
    pop = _immutable
    popitem = _immutable
    setdefault = _immutable
    update = _immutable

    def __copy__(self) -> Self:
        return self

    def __deepcopy__(self, _memo: dict[int, object]) -> Self:
        return self


class _FrozenJsonList(list[JsonValue]):
    """A JSON array that rejects mutation after evidence validation."""

    @staticmethod
    def _immutable(*_args: object, **_kwargs: object) -> None:
        raise TypeError("evidence payload is immutable")

    __delitem__ = _immutable
    __iadd__ = _immutable
    __imul__ = _immutable
    __setitem__ = _immutable
    append = _immutable
    clear = _immutable
    extend = _immutable
    insert = _immutable
    pop = _immutable
    remove = _immutable
    reverse = _immutable
    sort = _immutable

    def __copy__(self) -> Self:
        return self

    def __deepcopy__(self, _memo: dict[int, object]) -> Self:
        return self


class AssessmentResult(StrEnum):
    """Deterministic result states for an individual technical control."""

    PASS = "PASS"
    FAIL = "FAIL"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class EvidenceArtifact(BaseModel):
    """Structured, provenance-rich evidence used by one control assessment.

    The JSON payload deliberately preserves collector-defined structure. It is not
    flattened into an entity-attribute-value representation.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        str_strip_whitespace=True,
    )

    evidence_id: UUID
    resource_snapshot_id: UUID
    scan_id: UUID
    control_id: ControlId

    account_id: NonEmptyString
    service: NonEmptyString
    resource_type: NonEmptyString
    aws_resource_id: NonEmptyString
    arn: str | None = None
    scope: ResourceScope
    region: str | None = None

    collector: NonEmptyString
    source: NonEmptyString
    source_api: NonEmptyString
    collected_at: datetime
    schema_name: NonEmptyString
    schema_version: NonEmptyString
    evidence_key: NonEmptyString = "primary"
    payload: dict[str, JsonValue]
    payload_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_provenance(self) -> EvidenceArtifact:
        """Require unambiguous resource scope and an absolute collection time."""

        if self.scope is ResourceScope.REGIONAL and not self.region:
            raise ValueError("regional evidence requires a region")
        if self.scope is ResourceScope.GLOBAL and self.region is not None:
            raise ValueError("global evidence must not define a region")
        if self.collected_at.tzinfo is None or self.collected_at.utcoffset() is None:
            raise ValueError("evidence collected_at must be timezone-aware")

        payload_sha256 = _payload_sha256(self.payload)
        if self.payload_sha256 is None:
            object.__setattr__(self, "payload_sha256", payload_sha256)
        elif not hmac.compare_digest(self.payload_sha256, payload_sha256):
            raise ValueError("payload_sha256 does not match the evidence payload")

        expected_evidence_id = self.calculate_evidence_id(payload_sha256=payload_sha256)
        if self.evidence_id != expected_evidence_id:
            raise ValueError("evidence_id does not match evidence content and provenance")

        object.__setattr__(self, "payload", _freeze_json(self.payload))
        return self

    def calculate_evidence_id(self, *, payload_sha256: str | None = None) -> UUID:
        """Return the content- and provenance-bound identifier for this artifact."""

        digest = payload_sha256 or _payload_sha256(self.payload)
        return _build_evidence_id(
            resource_snapshot_id=self.resource_snapshot_id,
            scan_id=self.scan_id,
            control_id=self.control_id,
            account_id=self.account_id,
            service=self.service,
            resource_type=self.resource_type,
            aws_resource_id=self.aws_resource_id,
            arn=self.arn,
            scope=self.scope,
            region=self.region,
            collector=self.collector,
            source=self.source,
            source_api=self.source_api,
            collected_at=self.collected_at,
            schema_name=self.schema_name,
            schema_version=self.schema_version,
            evidence_key=self.evidence_key,
            payload_sha256=digest,
        )

    def verify_integrity(self) -> bool:
        """Return whether both the payload digest and evidence ID remain valid."""

        payload_sha256 = _payload_sha256(self.payload)
        return bool(
            self.payload_sha256
            and hmac.compare_digest(self.payload_sha256, payload_sha256)
            and self.evidence_id == self.calculate_evidence_id(payload_sha256=payload_sha256)
        )

    @classmethod
    def for_assessment(
        cls,
        *,
        resource_snapshot_id: UUID,
        scan_id: UUID,
        control_id: str,
        account_id: str,
        service: str,
        resource_type: str,
        aws_resource_id: str,
        arn: str | None,
        scope: ResourceScope,
        region: str | None,
        collector: str,
        source: str,
        source_api: str,
        collected_at: datetime,
        schema_name: str,
        schema_version: str,
        payload: dict[str, JsonValue],
        evidence_key: str = "primary",
    ) -> EvidenceArtifact:
        """Build an artifact whose ID is stable for the same assessment input.

        ``evidence_key`` lets a control attach multiple separately identified
        artifacts without introducing random identifiers.
        """

        payload_sha256 = _payload_sha256(payload)
        evidence_id = _build_evidence_id(
            resource_snapshot_id=resource_snapshot_id,
            scan_id=scan_id,
            control_id=control_id,
            account_id=account_id,
            service=service,
            resource_type=resource_type,
            aws_resource_id=aws_resource_id,
            arn=arn,
            scope=scope,
            region=region,
            collector=collector,
            source=source,
            source_api=source_api,
            collected_at=collected_at,
            schema_name=schema_name,
            schema_version=schema_version,
            evidence_key=evidence_key,
            payload_sha256=payload_sha256,
        )
        return cls(
            evidence_id=evidence_id,
            resource_snapshot_id=resource_snapshot_id,
            scan_id=scan_id,
            control_id=control_id,
            account_id=account_id,
            service=service,
            resource_type=resource_type,
            aws_resource_id=aws_resource_id,
            arn=arn,
            scope=scope,
            region=region,
            collector=collector,
            source=source,
            source_api=source_api,
            collected_at=collected_at,
            schema_name=schema_name,
            schema_version=schema_version,
            evidence_key=evidence_key,
            payload=payload,
            payload_sha256=payload_sha256,
        )

    @property
    def identity(self) -> tuple[UUID, UUID, str, str, str, str]:
        """Return the stable evidence identity and its primary provenance keys."""

        return (
            self.evidence_id,
            self.scan_id,
            self.control_id,
            self.account_id,
            self.resource_type,
            self.aws_resource_id,
        )


class AssessmentCandidate(BaseModel):
    """One non-persistent technical assessment produced by a control rule."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        str_strip_whitespace=True,
    )

    control_id: ControlId
    result: AssessmentResult
    profile_id: NonEmptyString
    profile_version: NonEmptyString
    profile_checksum: str = Field(pattern=r"^[0-9a-f]{64}$")
    scan_id: UUID
    resource_snapshot_id: UUID
    inventory_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    control_catalog_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    account_id: NonEmptyString
    service: NonEmptyString
    resource_type: NonEmptyString
    aws_resource_id: NonEmptyString
    arn: str | None = None
    name: str | None = None
    scope: ResourceScope
    region: str | None = None

    evidence_artifacts: tuple[EvidenceArtifact, ...] = ()
    missing_evidence: tuple[NonEmptyString, ...] = ()
    reason: NonEmptyString

    @model_validator(mode="after")
    def validate_result_and_evidence(self) -> AssessmentCandidate:
        """Keep result semantics separate and prevent missing evidence from passing."""

        if self.scope is ResourceScope.REGIONAL and not self.region:
            raise ValueError("regional assessment targets require a region")
        if self.scope is ResourceScope.GLOBAL and self.region is not None:
            raise ValueError("global assessment targets must not define a region")

        if len(set(self.missing_evidence)) != len(self.missing_evidence):
            raise ValueError("missing_evidence entries must be unique")

        artifact_ids = tuple(artifact.evidence_id for artifact in self.evidence_artifacts)
        if len(set(artifact_ids)) != len(artifact_ids):
            raise ValueError("evidence artifact IDs must be unique")

        for artifact in self.evidence_artifacts:
            if not artifact.verify_integrity():
                raise ValueError("evidence artifact integrity verification failed")
            if artifact.control_id != self.control_id:
                raise ValueError("evidence control_id must match the assessment control_id")
            if artifact.scan_id != self.scan_id:
                raise ValueError("evidence scan_id must match the assessment scan_id")
            if artifact.resource_snapshot_id != self.resource_snapshot_id:
                raise ValueError(
                    "evidence resource_snapshot_id must match the assessment resource_snapshot_id"
                )
            if artifact.account_id != self.account_id:
                raise ValueError("evidence account_id must match the assessment account_id")
            if artifact.service != self.service:
                raise ValueError("evidence service must match the assessment service")
            if artifact.resource_type != self.resource_type:
                raise ValueError("evidence resource_type must match the assessment resource_type")
            if artifact.aws_resource_id != self.aws_resource_id:
                raise ValueError(
                    "evidence aws_resource_id must match the assessment aws_resource_id"
                )
            if artifact.arn != self.arn:
                raise ValueError("evidence arn must match the assessment arn")
            if artifact.scope is not self.scope:
                raise ValueError("evidence scope must match the assessment scope")
            if artifact.region != self.region:
                raise ValueError("evidence region must match the assessment region")

        if self.result is AssessmentResult.INSUFFICIENT_EVIDENCE:
            if not self.missing_evidence:
                raise ValueError("INSUFFICIENT_EVIDENCE requires missing_evidence")
        elif self.missing_evidence:
            raise ValueError("only INSUFFICIENT_EVIDENCE may contain missing_evidence")

        if self.result in {AssessmentResult.PASS, AssessmentResult.FAIL}:
            if not self.evidence_artifacts:
                raise ValueError(f"{self.result.value} requires at least one evidence artifact")
        if self.result is AssessmentResult.NOT_APPLICABLE and self.evidence_artifacts:
            raise ValueError("NOT_APPLICABLE must not contain evidence artifacts")

        return self

    @property
    def identity(self) -> tuple[str, str, str, str, str, str, str]:
        """Return the stable target key used for ordering and deduplication."""

        return (
            self.control_id,
            self.account_id,
            self.service,
            self.resource_type,
            self.scope.value,
            self.region or "global",
            self.aws_resource_id,
        )


def _payload_sha256(payload: dict[str, JsonValue]) -> str:
    """Hash canonical JSON so key order cannot change evidence identity."""

    encoded = json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _freeze_json(value: JsonValue) -> JsonValue:
    """Deep-copy a validated JSON value into mutation-rejecting containers."""

    if isinstance(value, dict):
        return _FrozenJsonDict({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, list):
        return _FrozenJsonList(_freeze_json(item) for item in value)
    return value


def _build_evidence_id(
    *,
    resource_snapshot_id: UUID,
    scan_id: UUID,
    control_id: str,
    account_id: str,
    service: str,
    resource_type: str,
    aws_resource_id: str,
    arn: str | None,
    scope: ResourceScope,
    region: str | None,
    collector: str,
    source: str,
    source_api: str,
    collected_at: datetime,
    schema_name: str,
    schema_version: str,
    evidence_key: str,
    payload_sha256: str,
) -> UUID:
    """Bind an evidence identifier to all content and provenance that it identifies."""

    seed_parts = (
        str(scan_id),
        str(resource_snapshot_id),
        control_id,
        account_id,
        service,
        resource_type,
        scope.value,
        region or "global",
        aws_resource_id,
        arn or "",
        collector,
        source,
        source_api,
        collected_at.astimezone(UTC).isoformat(),
        schema_name,
        schema_version,
        evidence_key,
        payload_sha256,
    )
    return uuid5(_EVIDENCE_ID_NAMESPACE, "\x1f".join(seed_parts))
