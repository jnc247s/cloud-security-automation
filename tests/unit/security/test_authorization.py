"""Tests for role and capability authorization policy."""

import pytest
from fastapi import HTTPException, status

from app.security.authentication import Principal
from app.security.authorization import (
    ROLE_CAPABILITIES,
    Capability,
    Role,
    capabilities_for,
    require_capability,
)


def _principal(*roles: Role) -> Principal:
    return Principal(
        subject="caller-123",
        role_names=frozenset(role.value for role in roles),
        issuer="https://identity.example.test",
    )


def test_role_capability_mapping_is_explicit_and_least_privilege() -> None:
    assert ROLE_CAPABILITIES == {
        Role.VIEWER: frozenset({Capability.READ}),
        Role.ANALYST: frozenset({Capability.READ, Capability.PROPOSE}),
        Role.APPROVER: frozenset({Capability.READ, Capability.PROPOSE, Capability.APPROVE}),
        Role.ADMIN: frozenset(Capability),
    }


def test_multiple_roles_receive_union_of_capabilities() -> None:
    principal = _principal(Role.VIEWER, Role.ANALYST)

    assert capabilities_for(principal) == frozenset({Capability.READ, Capability.PROPOSE})


def test_capability_dependency_returns_authorized_principal() -> None:
    principal = _principal(Role.APPROVER)

    result = require_capability(Capability.APPROVE)(principal=principal)

    assert result is principal


def test_capability_dependency_rejects_unauthorized_principal() -> None:
    principal = _principal(Role.VIEWER)

    with pytest.raises(HTTPException) as error:
        require_capability(Capability.EXECUTE)(principal=principal)

    assert error.value.status_code == status.HTTP_403_FORBIDDEN
    assert error.value.detail["code"] == "insufficient_capability"
