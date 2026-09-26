"""Command-line interface for SpineAPI."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import List, Optional

from spineapi.audit import run_audit
from spineapi.reporter import SecurityPostureReporter
from spineapi.testgen import DefensiveTestGenerator


def package_fixtures_dir() -> Path:
    return Path(__file__).resolve().parent / "fixtures"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="spineapi",
        description=(
            "SpineAPI — defensive API security posture auditor: discover endpoints, "
            "analyze rate-limit coverage statically, report gaps, generate defensive tests."
        ),
    )
    parser.add_argument(
        "action",
        choices=["discover", "analyze", "report", "generate-tests"],
        help="Action to perform",
    )
    parser.add_argument(
        "--source-code",
        default=".",
        help="Path to application source root",
    )
    parser.add_argument(
        "--swagger",
        help="Path to OpenAPI/Swagger JSON (YAML not supported without deps)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="api-security-report",
        help="Output directory",
    )
    parser.add_argument(
        "--no-integrations",
        action="store_true",
        help="Skip built-in partners/payments/KYC catalog endpoints",
    )
    parser.add_argument(
        "--no-source",
        action="store_true",
        help="Skip source-code route discovery",
    )
    parser.add_argument(
        "--tests-out",
        default=None,
        help="Path for generated defensive tests (generate-tests)",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Use packaged sample app + openapi.json fixtures",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    source_code = args.source_code
    swagger = args.swagger
    if args.demo:
        fixtures = package_fixtures_dir()
        source_code = str(fixtures / "sample_app")
        swagger = str(fixtures / "openapi.json")
        print(f"[*] Demo mode: {source_code}")
        print(f"[*] Demo OpenAPI: {swagger}")

    print("[*] Running SpineAPI defensive audit...")
    report = run_audit(
        project_root=source_code,
        swagger=swagger,
        include_integrations=not args.no_integrations,
        include_source=not args.no_source,
    )
    print(f"[+] Endpoints: {report.metrics.get('total_endpoints')}")
    print(f"[+] Rate-limit rules: {report.metrics.get('rate_limit_rules_found')}")
    print(f"[+] Coverage: {report.metrics.get('rate_limit_coverage_pct')}%")
    print(f"[+] Gaps: {report.metrics.get('gap_count')}")

    reporter = SecurityPostureReporter(report)
    os.makedirs(args.output, exist_ok=True)

    if args.action in {"discover", "analyze", "report"}:
        reporter.write(args.output)
        print(f"[+] Reports written to {args.output}/")

    if args.action in {"generate-tests", "report"}:
        tests_path = args.tests_out or os.path.join(
            args.output, "test_api_security_defensive.py"
        )
        DefensiveTestGenerator(report.endpoints).write(tests_path)
        print(f"[+] Defensive tests written to {tests_path}")

    print("[+] Done (no live attack traffic was sent).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
