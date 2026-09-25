"""Orchestrate discovery + static analysis into an audit report."""

from __future__ import annotations

from typing import Optional

from spineapi.analyzer import StaticRateLimitAnalyzer
from spineapi.discovery import EndpointDiscovery
from spineapi.models import AuditReport
from spineapi.reporter import SecurityPostureReporter


def run_audit(
    project_root: str,
    swagger: Optional[str],
    include_integrations: bool,
    include_source: bool,
) -> AuditReport:
    discovery = EndpointDiscovery(project_root)
    endpoints = discovery.discover_all(
        swagger_file=swagger,
        include_integrations=include_integrations,
        include_source=include_source,
    )
    analyzer = StaticRateLimitAnalyzer(project_root)
    rules = analyzer.find_rate_limit_rules()
    gaps = analyzer.analyze_coverage(endpoints)
    return SecurityPostureReporter.build(project_root, endpoints, rules, gaps)
