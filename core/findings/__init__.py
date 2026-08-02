"""Evidence-only confirmation of defensive findings.

This package records bounded observations. It does not execute tests, select
targets, grant authority, or promote findings beyond their supporting evidence.
"""

from .confirmation import (
    AuthorizedScope,
    ConfirmationResult,
    FindingRegistry,
    Observation,
    confirm_finding,
    finding_fingerprint,
)

__all__ = [
    "AuthorizedScope",
    "ConfirmationResult",
    "FindingRegistry",
    "Observation",
    "confirm_finding",
    "finding_fingerprint",
]
