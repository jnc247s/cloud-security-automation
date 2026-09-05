"""Authentication and authorization boundary for the application."""

from app.security.authentication import Principal
from app.security.authorization import Capability, Role, require_capability

__all__ = ["Capability", "Principal", "Role", "require_capability"]
