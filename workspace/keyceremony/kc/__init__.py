"""kc - key management ceremony orchestration system.

Public surface:
    Orchestrator, Store, DeviceWallet, Policy, error types, ceremony/role constants.
"""

from . import crypto, ed25519, policy
from .attestation import DeviceWallet, EnrolledDevice, provision_device
from .ceremony import Orchestrator
from .directory import KeyDirectory
from .errors import (
    AttestationError, AuthenticationError, CeremonyError, ConflictState,
    DuplicateAction, NotFound, PolicyViolation, QuorumFailure, RaceLost,
    ReplayError, SealError, TamperError,
)
from .storage import AuditLog, Store

__all__ = [
    "Orchestrator", "Store", "AuditLog", "KeyDirectory",
    "DeviceWallet", "EnrolledDevice", "provision_device",
    "crypto", "ed25519", "policy",
    "CeremonyError", "ConflictState", "PolicyViolation", "AttestationError",
    "AuthenticationError", "DuplicateAction", "ReplayError", "QuorumFailure",
    "SealError", "TamperError", "NotFound", "RaceLost",
]
