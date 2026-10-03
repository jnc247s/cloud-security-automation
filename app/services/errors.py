"""Errors raised by the application service boundary."""


class AssessmentProfileConflictError(RuntimeError):
    """Configured policy content conflicts with an existing immutable version."""


class TechnicalPostureProvenanceError(RuntimeError):
    """Retained reporting identities disagree; never omit rows or select newer policy."""


class EntityNotFoundError(LookupError):
    """Raised when a caller requests a persisted entity that does not exist."""

    def __init__(self, entity: str, identifier: object) -> None:
        self.entity = entity
        self.identifier = str(identifier)
        super().__init__(f"{entity} {identifier} was not found")
