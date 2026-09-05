"""Role-to-capability policy and reusable FastAPI authorization dependencies."""

from collections.abc import Callable
from enum import StrEnum
from types import MappingProxyType
from typing import Annotated

from fastapi import Depends, HTTPException, status

from app.security.authentication import Principal, get_current_principal


class Role(StrEnum):
    """Application roles understood by authorization policy."""

    VIEWER = "VIEWER"
    ANALYST = "ANALYST"
    APPROVER = "APPROVER"
    ADMIN = "ADMIN"


class Capability(StrEnum):
    """Actions granted by one or more roles."""

    READ = "READ"
    PROPOSE = "PROPOSE"
    APPROVE = "APPROVE"
    EXECUTE = "EXECUTE"


ROLE_CAPABILITIES = MappingProxyType(
    {
        Role.VIEWER: frozenset({Capability.READ}),
        Role.ANALYST: frozenset({Capability.READ, Capability.PROPOSE}),
        Role.APPROVER: frozenset({Capability.READ, Capability.PROPOSE, Capability.APPROVE}),
        Role.ADMIN: frozenset(Capability),
    }
)


def capabilities_for(principal: Principal) -> frozenset[Capability]:
    """Return the union of capabilities granted to the principal's roles."""

    capabilities: set[Capability] = set()
    for role_name in principal.role_names:
        try:
            role = Role(role_name)
        except ValueError:
            continue
        capabilities.update(ROLE_CAPABILITIES[role])
    return frozenset(capabilities)


def require_capability(capability: Capability) -> Callable[..., Principal]:
    """Create a FastAPI dependency that requires one explicit capability."""

    def authorize(
        principal: Annotated[Principal, Depends(get_current_principal)],
    ) -> Principal:
        if capability not in capabilities_for(principal):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": "insufficient_capability",
                    "message": f"The {capability.value} capability is required.",
                },
            )
        return principal

    return authorize
