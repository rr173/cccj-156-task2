"""Typed errors for the ceremony orchestrator."""


class CeremonyError(Exception):
    code = "CEREMONY_ERROR"
    http_status = 400

    def __init__(self, message: str = "", code: str | None = None):
        super().__init__(message or self.__class__.__doc__ or self.code)
        if code:
            self.code = code


class NotFound(CeremonyError):
    code = "NOT_FOUND"
    http_status = 404


class ConflictState(CeremonyError):
    """Ceremony or key is not in the required state for this action."""

    code = "CONFLICT_STATE"
    http_status = 409


class PolicyViolation(CeremonyError):
    """Fixed roles, threshold or quorum rules would be broken."""

    code = "POLICY_VIOLATION"
    http_status = 422


class AttestationError(CeremonyError):
    """Device quote failed: signature, measurement or replay checks."""

    code = "ATTESTATION_FAILED"
    http_status = 401


class AuthenticationError(CeremonyError):
    code = "AUTH_FAILED"
    http_status = 401


class DuplicateAction(CeremonyError):
    """A different action for this slot/stage was already recorded."""

    code = "DUPLICATE_ACTION"
    http_status = 409


class ReplayError(CeremonyError):
    """This nonce has already been spent."""

    code = "REPLAY_DETECTED"
    http_status = 409


class QuorumFailure(CeremonyError):
    code = "QUORUM_NOT_MET"
    http_status = 422


class SealError(CeremonyError):
    code = "SEAL_FAILED"
    http_status = 400


class TamperError(CeremonyError):
    """Tamper-evident audit chain failed verification."""

    code = "TAMPER_DETECTED"
    http_status = 409


class RaceLost(CeremonyError):
    """Another activation/publish committed first; retry against the new state."""

    code = "RACE_LOST"
    http_status = 409


class SessionError(CeremonyError):
    """Watchstander token missing, expired, revoked or bound to a dead terminal."""

    code = "SESSION_INVALID"
    http_status = 401


class Forbidden(CeremonyError):
    """Authenticated session lacks the duty/scope required for this action."""

    code = "FORBIDDEN"
    http_status = 403


class OrderError(CeremonyError):
    """Authorization order is not in a state that permits this decision."""

    code = "ORDER_DECIDED"
    http_status = 409
