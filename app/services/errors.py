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


class RemediationError(RuntimeError):
    """Closed, sanitized errors; never retain SQL, credentials or evidence in messages."""

    RESPONSES = {
        "remediation_execution_disabled": (503, "Execution request admission is disabled."),
        "remediation_execution_capacity": (503, "Execution request capacity is unavailable."),
        "remediation_execution_scope_conflict": (
            409,
            "The approved target is outside the configured execution admission scope.",
        ),
        "remediation_execution_target_reserved": (
            409,
            "The target already has an outstanding execution request.",
        ),
        "insufficient_capability": (403, "The required remediation capability is missing."),
        "remediation_separation_required": (403, "A different verified principal is required."),
        "remediation_state_conflict": (
            409,
            "The remediation decision conflicts with current state.",
        ),
        "remediation_idempotency_conflict": (
            409,
            "The idempotency key has different request content.",
        ),
        "remediation_provenance_conflict": (
            409,
            "The retained remediation provenance is inconsistent.",
        ),
        "remediation_ineligible": (409, "The proposal is expired, stale or otherwise ineligible."),
        "remediation_database_unavailable": (
            503,
            "The remediation operation could not be completed.",
        ),
    }

    def __init__(self, code: str):
        self.code = code
        self.status_code, message = self.RESPONSES[code]
        super().__init__(message)
