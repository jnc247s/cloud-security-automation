"""Local deployment policy selection, separate from persisted scan recovery."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from app.assessment.controls import ControlCatalog
from app.assessment.extended_profiles import validate_profile_document
from app.assessment.profiles import AssessmentProfile, create_default_assessment_profile
from app.rules.registry import resolve_catalog


class PolicyConfigurationError(ValueError):
    """Sanitized local configuration failure; never includes policy content or paths."""


class _Envelope(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    catalog_id: str
    catalog_version: str
    profile: dict


@dataclass(frozen=True)
class DeploymentPolicy:
    profile: AssessmentProfile
    catalog: ControlCatalog


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate policy JSON key")
        result[key] = value
    return result


def load_deployment_policy(settings) -> DeploymentPolicy:
    """Resolve one immutable configuration snapshot; no network or fallback on file failure."""

    if settings.assessment_profile_file is None:
        catalog, _ = resolve_catalog("aws-cloud-security-controls", "0.2.1")
        return DeploymentPolicy(
            create_default_assessment_profile(
                version=settings.assessment_profile_version,
                required_tags=settings.required_tag_names,
                stale_key_days=settings.stale_access_key_days,
            ),
            catalog,
        )
    try:
        path = Path(settings.assessment_profile_file)
        if "://" in str(path) or str(path).startswith(("\\\\", "//")):
            raise ValueError("only local policy files are supported")
        with path.open("rb") as stream:
            raw = stream.read(1_048_577)
        if len(raw) > 1_048_576:
            raise ValueError("policy file exceeds limit")
        envelope = _Envelope.model_validate(
            json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
        )
        profile = validate_profile_document(envelope.profile, persisted=True)
        if profile.version != settings.assessment_profile_version:
            raise ValueError("configured profile version mismatch")
        catalog, registry = resolve_catalog(envelope.catalog_id, envelope.catalog_version)
        if set(profile.enabled_controls) - {rule.control_id for rule in registry.rules}:
            raise ValueError("profile enables an unsupported control")
        return DeploymentPolicy(profile, catalog)
    except (OSError, ValueError, TypeError, RecursionError):
        raise PolicyConfigurationError("Assessment policy configuration is invalid.") from None
