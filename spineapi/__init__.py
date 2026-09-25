"""SpineAPI — defensive API security posture auditor."""

__version__ = "1.0.0"

from spineapi.audit import run_audit
from spineapi.models import APIEndpoint, AuditReport, CoverageGap, RateLimitRule

__all__ = [
    "APIEndpoint",
    "AuditReport",
    "CoverageGap",
    "RateLimitRule",
    "run_audit",
    "__version__",
]
