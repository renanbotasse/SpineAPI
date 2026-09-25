"""Shared data models for SpineAPI."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass(frozen=True)
class APIEndpoint:
    method: str
    path: str
    handler: Optional[str] = None
    requires_auth: bool = False
    integration: Optional[str] = None  # partners | payments | kyc | None
    source: str = "swagger"  # swagger | source_code | catalog
    file_location: Optional[str] = None
    operation_id: Optional[str] = None
    description: Optional[str] = None
    accepts_partner_id: bool = False
    requires_idempotency_key: bool = False
    handles_file_upload: bool = False
    is_webhook: bool = False

    def key(self) -> Tuple[str, str]:
        return (self.method.upper(), self._normalize_path(self.path))

    @staticmethod
    def _normalize_path(path: str) -> str:
        normalized = path if path.startswith("/") else f"/{path}"
        return re.sub(r"/+", "/", normalized).rstrip("/") or "/"


@dataclass
class RateLimitRule:
    pattern: str
    limit_expression: str
    file_location: str
    line_number: int
    framework: str  # django | flask | drf | custom


@dataclass
class CoverageGap:
    endpoint: APIEndpoint
    gap_type: str
    severity: str
    description: str
    recommendation: str


@dataclass
class AuditReport:
    scan_date: str
    project_root: str
    endpoints: List[APIEndpoint] = field(default_factory=list)
    rate_limit_rules: List[RateLimitRule] = field(default_factory=list)
    gaps: List[CoverageGap] = field(default_factory=list)
    metrics: Dict[str, object] = field(default_factory=dict)
