"""In-memory history guards for planned immutable S3 policy artifacts.

The standalone preflight artifacts are not registered with the current AssessmentProfile or
database.  These strict history containers make their permanent version-reuse rule executable
without starting that later persistence integration.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.assessment.s3_exposure import S3ExposureApprovalPolicy
from app.assessment.sensitive_buckets import SensitiveBucketClassifier


class S3ExposureApprovalPolicyHistory(BaseModel):
    """Reconstructable policy history with one immutable artifact per logical version."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    artifacts: tuple[S3ExposureApprovalPolicy, ...] = Field(min_length=1)

    @field_validator("artifacts")
    @classmethod
    def reject_reused_versions(
        cls,
        artifacts: tuple[S3ExposureApprovalPolicy, ...],
    ) -> tuple[S3ExposureApprovalPolicy, ...]:
        """Reject duplicate or changed content under an already represented version."""

        seen: dict[tuple[str, str], str] = {}
        for artifact in artifacts:
            identity = (artifact.policy_id, artifact.version)
            checksum = artifact.content_checksum
            if identity in seen:
                if seen[identity] != checksum:
                    raise ValueError(
                        "S3 exposure approval policy version cannot be reused with different "
                        "content"
                    )
                raise ValueError("duplicate S3 exposure approval policy version")
            seen[identity] = checksum
        return tuple(sorted(artifacts, key=lambda item: (item.policy_id, item.version)))

    def get(self, *, policy_id: str, version: str) -> S3ExposureApprovalPolicy | None:
        """Return one exact historical definition without an implicit latest selection."""

        return next(
            (
                artifact
                for artifact in self.artifacts
                if artifact.policy_id == policy_id and artifact.version == version
            ),
            None,
        )


class SensitiveBucketClassifierHistory(BaseModel):
    """Reconstructable classifier history with immutable logical versions."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    artifacts: tuple[SensitiveBucketClassifier, ...] = Field(min_length=1)

    @field_validator("artifacts")
    @classmethod
    def reject_reused_versions(
        cls,
        artifacts: tuple[SensitiveBucketClassifier, ...],
    ) -> tuple[SensitiveBucketClassifier, ...]:
        """Require a version change whenever classifier policy content changes."""

        seen: dict[tuple[str, str], str] = {}
        for artifact in artifacts:
            identity = (artifact.classifier_id, artifact.version)
            checksum = artifact.content_checksum
            if identity in seen:
                if seen[identity] != checksum:
                    raise ValueError(
                        "sensitive bucket classifier version cannot be reused with different "
                        "content"
                    )
                raise ValueError("duplicate sensitive bucket classifier version")
            seen[identity] = checksum
        return tuple(sorted(artifacts, key=lambda item: (item.classifier_id, item.version)))

    def get(self, *, classifier_id: str, version: str) -> SensitiveBucketClassifier | None:
        """Return one exact historical definition without an implicit latest selection."""

        return next(
            (
                artifact
                for artifact in self.artifacts
                if artifact.classifier_id == classifier_id and artifact.version == version
            ),
            None,
        )
