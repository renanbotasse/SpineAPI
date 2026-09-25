"""Static rate-limit and security-hint analysis."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, List, Set

from spineapi.constants import is_noise_path, read_text
from spineapi.models import APIEndpoint, CoverageGap, RateLimitRule


class StaticRateLimitAnalyzer:
    """Find rate-limit decorators/middleware and coverage gaps in source."""

    RULE_PATTERNS = [
        (
            "django",
            re.compile(
                r"""@ratelimit\s*\(\s*[^)]*rate\s*=\s*['"]([^'"]+)['"]""",
                re.IGNORECASE,
            ),
        ),
        (
            "django",
            re.compile(r"""@rate_limit\s*\(\s*['"]([^'"]+)['"]""", re.IGNORECASE),
        ),
        (
            "drf",
            re.compile(r"""throttle_classes\s*=\s*\[([^\]]+)\]""", re.IGNORECASE),
        ),
        (
            "drf",
            re.compile(r"""@throttle\s*\(\s*['"]?([^'")\]]+)['"]?""", re.IGNORECASE),
        ),
        (
            "flask",
            re.compile(r"""@limiter\.limit\s*\(\s*['"]([^'"]+)['"]""", re.IGNORECASE),
        ),
        (
            "custom",
            re.compile(
                r"""@(?:throttle|rate_limited|with_rate_limit)\s*\(\s*['"]([^'"]+)['"]""",
                re.IGNORECASE,
            ),
        ),
    ]

    HMAC_HINTS = re.compile(
        r"hmac|x-signature|webhook.?secret|verify_signature|signature_header",
        re.IGNORECASE,
    )
    IDEMPOTENCY_HINTS = re.compile(
        r"idempotency|Idempotency-Key|idempotent",
        re.IGNORECASE,
    )

    def __init__(self, project_root: str = ".") -> None:
        self.project_root = Path(project_root).resolve()

    def find_rate_limit_rules(self) -> List[RateLimitRule]:
        rules: List[RateLimitRule] = []
        for py_file in self._iter_python_files():
            text, _err = read_text(py_file)
            if text is None:
                continue
            for idx, line in enumerate(text.splitlines(), start=1):
                for framework, pattern in self.RULE_PATTERNS:
                    match = pattern.search(line)
                    if not match:
                        continue
                    rules.append(
                        RateLimitRule(
                            pattern=line.strip()[:200],
                            limit_expression=match.group(1).strip(),
                            file_location=str(py_file),
                            line_number=idx,
                            framework=framework,
                        )
                    )
        return rules

    def code_has_hmac_validation(self) -> bool:
        return self._any_file_matches(self.HMAC_HINTS)

    def code_has_idempotency_handling(self) -> bool:
        return self._any_file_matches(self.IDEMPOTENCY_HINTS)

    def analyze_coverage(self, endpoints: Iterable[APIEndpoint]) -> List[CoverageGap]:
        rules = self.find_rate_limit_rules()
        rule_files = {Path(rule.file_location).resolve() for rule in rules}
        rule_text = " ".join(
            f"{rule.pattern} {rule.limit_expression}".lower() for rule in rules
        )
        has_any_rules = bool(rules)
        has_hmac = self.code_has_hmac_validation()
        has_idempotency = self.code_has_idempotency_handling()

        gaps: List[CoverageGap] = []
        for endpoint in endpoints:
            covered = self._endpoint_likely_covered(
                endpoint, rules, rule_files, rule_text, has_any_rules
            )
            if not covered:
                gaps.append(
                    CoverageGap(
                        endpoint=endpoint,
                        gap_type="NO_RATE_LIMIT",
                        severity=(
                            "HIGH"
                            if endpoint.integration or endpoint.is_webhook
                            else "MEDIUM"
                        ),
                        description=(
                            "No static rate-limit evidence linked to "
                            f"{endpoint.method} {endpoint.path}"
                        ),
                        recommendation=(
                            "Add framework throttling (DRF throttle / Flask-Limiter / "
                            "django-ratelimit) or gateway rate limits for this route."
                        ),
                    )
                )

            if endpoint.is_webhook and not has_hmac:
                gaps.append(
                    CoverageGap(
                        endpoint=endpoint,
                        gap_type="WEBHOOK_NO_HMAC_HINT",
                        severity="HIGH",
                        description=(
                            f"Webhook {endpoint.path} found but no HMAC/signature "
                            "validation hints in codebase"
                        ),
                        recommendation=(
                            "Validate webhook signatures (HMAC) before processing payloads."
                        ),
                    )
                )

            if endpoint.requires_idempotency_key and not has_idempotency:
                gaps.append(
                    CoverageGap(
                        endpoint=endpoint,
                        gap_type="NO_IDEMPOTENCY_HINT",
                        severity="HIGH",
                        description=(
                            f"Payment-like endpoint {endpoint.path} expects idempotency "
                            "but no idempotency handling hints found"
                        ),
                        recommendation=(
                            "Require and enforce Idempotency-Key on payment mutations."
                        ),
                    )
                )

            if endpoint.handles_file_upload and not covered:
                gaps.append(
                    CoverageGap(
                        endpoint=endpoint,
                        gap_type="UPLOAD_NO_LIMIT_HINT",
                        severity="HIGH",
                        description=(
                            f"Upload endpoint {endpoint.path} has no linked "
                            "rate-limit evidence"
                        ),
                        recommendation=(
                            "Apply strict per-user/per-partner upload quotas and size limits."
                        ),
                    )
                )

            if (
                not endpoint.requires_auth
                and not endpoint.is_webhook
                and endpoint.path.startswith("/api/")
            ):
                gaps.append(
                    CoverageGap(
                        endpoint=endpoint,
                        gap_type="NO_AUTH",
                        severity="MEDIUM",
                        description=(
                            f"API endpoint {endpoint.method} {endpoint.path} "
                            "marked without auth"
                        ),
                        recommendation=(
                            "Confirm intentionally public; otherwise require auth."
                        ),
                    )
                )

        return gaps

    def _endpoint_likely_covered(
        self,
        endpoint: APIEndpoint,
        rules: List[RateLimitRule],
        rule_files: Set[Path],
        rule_text: str,
        has_any_rules: bool,
    ) -> bool:
        if not has_any_rules:
            return False

        if endpoint.handler and endpoint.handler.lower() in rule_text:
            return True

        if endpoint.file_location:
            try:
                if Path(endpoint.file_location).resolve() in rule_files:
                    return True
            except OSError:
                pass

        tokens = [
            token
            for token in re.split(r"[/\{\}_.-]+", endpoint.path.lower())
            if len(token) > 2
        ]
        if tokens and any(token in rule_text for token in tokens):
            return True

        return any(
            "middleware" in rule.file_location.lower()
            or "settings" in rule.file_location.lower()
            for rule in rules
        )

    def _iter_python_files(self) -> Iterable[Path]:
        for py_file in self.project_root.rglob("*.py"):
            if not is_noise_path(py_file):
                yield py_file

    def _any_file_matches(self, pattern: re.Pattern[str]) -> bool:
        for py_file in self._iter_python_files():
            text, _err = read_text(py_file)
            if text is not None and pattern.search(text):
                return True
        return False
