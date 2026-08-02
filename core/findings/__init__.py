"""Evidence-only confirmation of defensive findings.

This package records bounded observations. It does not execute tests, select
targets, grant authority, or promote findings beyond their supporting evidence.
"""

from .confirmation import (
    ConfirmationResult,
    FindingRegistry,
    Observation,
    ScopeBoundary,
    confirm_finding,
    finding_fingerprint,
)

__all__ = [
    "ConfirmationResult",
    "FindingRegistry",
    "Observation",
    "ScopeBoundary",
    "confirm_finding",
    "finding_fingerprint",
]
