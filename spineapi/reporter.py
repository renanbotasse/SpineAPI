"""JSON and Markdown security posture reports."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List

from spineapi.models import APIEndpoint, AuditReport, CoverageGap, RateLimitRule


class SecurityPostureReporter:
    def __init__(self, report: AuditReport) -> None:
        self.report = report

    @staticmethod
    def build(
        project_root: str,
        endpoints: Iterable[APIEndpoint],
        rules: List[RateLimitRule],
        gaps: List[CoverageGap],
    ) -> AuditReport:
        endpoint_list = sorted(endpoints, key=lambda item: (item.method, item.path))
        return AuditReport(
            scan_date=datetime.now(timezone.utc).isoformat(),
            project_root=str(Path(project_root).resolve()),
            endpoints=endpoint_list,
            rate_limit_rules=rules,
            gaps=gaps,
            metrics=SecurityPostureReporter._compute_metrics(
                endpoint_list, rules, gaps
            ),
        )

    @staticmethod
    def _compute_metrics(
        endpoints: List[APIEndpoint],
        rules: List[RateLimitRule],
        gaps: List[CoverageGap],
    ) -> Dict[str, object]:
        total = len(endpoints)
        by_integration: Dict[str, int] = {}
        for endpoint in endpoints:
            key = endpoint.integration or "general"
            by_integration[key] = by_integration.get(key, 0) + 1

        no_rate = {id(gap.endpoint) for gap in gaps if gap.gap_type == "NO_RATE_LIMIT"}
        covered = max(total - len(no_rate), 0)
        severity: Dict[str, int] = {}
        for gap in gaps:
            severity[gap.severity] = severity.get(gap.severity, 0) + 1

        return {
            "total_endpoints": total,
            "endpoints_by_integration": by_integration,
            "rate_limit_rules_found": len(rules),
            "endpoints_with_rate_limit_evidence": covered,
            "rate_limit_coverage_pct": (
                round((covered / total) * 100, 1) if total else 0.0
            ),
            "gap_count": len(gaps),
            "gaps_by_severity": severity,
            "webhook_endpoints": sum(1 for item in endpoints if item.is_webhook),
            "upload_endpoints": sum(1 for item in endpoints if item.handles_file_upload),
            "idempotency_required_endpoints": sum(
                1 for item in endpoints if item.requires_idempotency_key
            ),
        }

    def to_json(self) -> str:
        payload = {
            "scan_date": self.report.scan_date,
            "project_root": self.report.project_root,
            "metrics": self.report.metrics,
            "rate_limit_rules": [asdict(rule) for rule in self.report.rate_limit_rules],
            "gaps": [
                {**asdict(gap), "endpoint": asdict(gap.endpoint)}
                for gap in self.report.gaps
            ],
            "endpoints": [asdict(endpoint) for endpoint in self.report.endpoints],
        }
        return json.dumps(payload, indent=2, default=str)

    def to_markdown(self) -> str:
        metrics = self.report.metrics
        lines = [
            "# API Security Posture Report (Defensive)",
            f"Generated: {self.report.scan_date}",
            f"Project: `{self.report.project_root}`",
            "",
            "## Summary",
            f"- Total endpoints: **{metrics.get('total_endpoints', 0)}**",
            f"- Rate-limit rules found: **{metrics.get('rate_limit_rules_found', 0)}**",
            f"- Rate-limit coverage: **{metrics.get('rate_limit_coverage_pct', 0)}%**",
            f"- Gaps: **{metrics.get('gap_count', 0)}**",
            "",
            "### Endpoints by integration",
        ]
        for name, count in sorted(
            (metrics.get("endpoints_by_integration") or {}).items()
        ):
            lines.append(f"- {name}: {count}")

        lines.extend(["", "### Gaps by severity"])
        for severity_name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            count = (metrics.get("gaps_by_severity") or {}).get(severity_name)
            if count:
                lines.append(f"- {severity_name}: {count}")

        lines.extend(["", "## Rate-limit rules (static)"])
        if not self.report.rate_limit_rules:
            lines.append("_No rate-limit decorators/middleware patterns detected._")
        else:
            for rule in self.report.rate_limit_rules:
                lines.append(
                    f"- `{rule.framework}` `{rule.limit_expression}` "
                    f"@ {rule.file_location}:{rule.line_number}"
                )

        lines.extend(["", "## Coverage gaps"])
        if not self.report.gaps:
            lines.append("_No gaps detected by static heuristics._")
        else:
            for gap in sorted(self.report.gaps, key=lambda item: item.severity):
                endpoint = gap.endpoint
                lines.extend(
                    [
                        f"### [{gap.severity}] {endpoint.method} {endpoint.path}",
                        f"- Type: `{gap.gap_type}`",
                        f"- {gap.description}",
                        f"- Recommendation: {gap.recommendation}",
                        "",
                    ]
                )

        lines.extend(
            [
                "## Methodology",
                "- Endpoint inventory from OpenAPI JSON, Django/Flask routes, and catalogs.",
                "- Rate-limit coverage from static decorator/middleware pattern matching.",
                "- No live traffic, brute force, or DDoS simulation is performed.",
                "",
                "## Next steps for runtime proof",
                "- Use k6/Locust for authorized load verification.",
                "- Use OWASP ZAP/Burp for authorized security scanning.",
                "- Keep CI green on the generated defensive pytest stubs.",
            ]
        )
        return "\n".join(lines)

    def write(self, output_dir: str) -> None:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        json_body = self.to_json()
        md_body = self.to_markdown()
        for stem in ("endpoints", "security-posture"):
            (out / f"{stem}.json").write_text(json_body, encoding="utf-8")
            (out / f"{stem}.md").write_text(md_body, encoding="utf-8")
