"""Tests for versioned assessment policy profiles."""

import pytest
from pydantic import ValidationError

from app.assessment.profiles import (
    DEFAULT_ASSESSMENT_PROFILE,
    DEFAULT_ENABLED_CONTROLS,
    AssessmentProfile,
    create_default_assessment_profile,
)


def _profile(**overrides: object) -> AssessmentProfile:
    values: dict[str, object] = {
        "profile_id": "production",
        "version": "2.1.0",
        "enabled_controls": DEFAULT_ENABLED_CONTROLS,
        "required_tags": ("Owner", "Environment"),
        "stale_key_days": 90,
        "approved_management_cidrs": ("10.0.0.0/8", "2001:db8::/32"),
        "public_ec2_exceptions": ("i-0123456789abcdef0",),
        "restricted_data_requires_kms": True,
    }
    values.update(overrides)
    return AssessmentProfile.model_validate(values)


def test_profile_requires_an_explicit_version() -> None:
    values = _profile().model_dump(exclude={"version", "content_checksum"})

    with pytest.raises(ValidationError, match="version"):
        AssessmentProfile.model_validate(values)


def test_default_profile_enables_all_existing_controls() -> None:
    assert DEFAULT_ASSESSMENT_PROFILE.enabled_controls == (
        "IAM-001",
        "LOG-001",
        "NET-001",
        "NET-002",
        "S3-900",
    )
    assert DEFAULT_ASSESSMENT_PROFILE.required_tags == ("Owner", "Environment")
    assert DEFAULT_ASSESSMENT_PROFILE.stale_key_days == 90
    assert DEFAULT_ASSESSMENT_PROFILE.content_checksum is not None


def test_profile_checksum_is_stable_for_equivalent_policy_ordering() -> None:
    first = _profile()
    second = _profile(
        enabled_controls=tuple(reversed(DEFAULT_ENABLED_CONTROLS)),
        required_tags=("Environment", "Owner"),
        approved_management_cidrs=("2001:db8::/32", "10.0.0.0/8"),
    )

    assert first.content_checksum == second.content_checksum


def test_profile_rejects_checksum_for_different_content() -> None:
    checksum = _profile().content_checksum

    with pytest.raises(ValidationError, match="content_checksum does not match"):
        _profile(stale_key_days=91, content_checksum=checksum)


def test_profile_version_changes_checksum() -> None:
    assert _profile(version="2.1.0").content_checksum != _profile(version="2.1.1").content_checksum


@pytest.mark.parametrize(
    "overrides, message",
    [
        ({"enabled_controls": ("NET-001", "NET-001")}, "entries must be unique"),
        ({"required_tags": ("Owner", "Owner")}, "entries must be unique"),
        ({"approved_management_cidrs": ("not-a-cidr",)}, "invalid approved"),
        ({"approved_management_cidrs": ("10.0.0.1/24",)}, "must be canonical"),
        ({"stale_key_days": 0}, "greater than or equal to 1"),
    ],
)
def test_profile_rejects_ambiguous_or_invalid_policy(
    overrides: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        _profile(**overrides)


def test_profile_is_strict_frozen_and_forbids_unknown_policy() -> None:
    profile = _profile()

    with pytest.raises(ValidationError, match="frozen"):
        profile.version = "3.0.0"

    with pytest.raises(ValidationError):
        _profile(stale_key_days="90")

    values = profile.model_dump(exclude={"content_checksum"})
    values["unversioned_policy"] = True
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        AssessmentProfile.model_validate(values)


def test_default_profile_factory_can_bind_foundation_settings() -> None:
    profile = create_default_assessment_profile(
        required_tags=("DataClassification",),
        stale_key_days=120,
    )

    assert profile.required_tags == ("DataClassification",)
    assert profile.stale_key_days == 120
