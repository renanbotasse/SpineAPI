"""Endpoint discovery from OpenAPI, source routes, and catalogs."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

from spineapi.catalogs import (
    KYC_CATALOG,
    PARTNER_CATALOG,
    PAYMENTS_CATALOG,
    catalog_endpoints,
)
from spineapi.constants import (
    HTTP_METHODS,
    SOURCE_RANK,
    is_noise_path,
    read_text,
    should_skip_path,
)
from spineapi.models import APIEndpoint


class EndpointDiscovery:
    """Discover API endpoints from OpenAPI specs, source routes, and catalogs."""

    def __init__(self, project_root: str = ".") -> None:
        self.project_root = Path(project_root).resolve()
        self.endpoints: Set[APIEndpoint] = set()

    def discover_from_swagger(self, swagger_file: str) -> Set[APIEndpoint]:
        endpoints: Set[APIEndpoint] = set()
        swagger_path = self._resolve_swagger_path(swagger_file)

        if not swagger_path.exists():
            print(f"Warning: Swagger file not found: {swagger_path}", file=sys.stderr)
            return endpoints

        if swagger_path.suffix.lower() in {".yaml", ".yml"}:
            print(
                "Warning: YAML OpenAPI is not supported (stdlib only). "
                "Convert to JSON and re-run.",
                file=sys.stderr,
            )
            return endpoints

        try:
            with open(swagger_path, encoding="utf-8") as handle:
                spec = json.load(handle)
        except Exception as exc:
            print(f"Warning: Could not parse Swagger file: {exc}", file=sys.stderr)
            return endpoints

        global_security = bool(spec.get("security"))
        components_security = (
            spec.get("components", {}).get("securitySchemes")
            or spec.get("securityDefinitions")
            or {}
        )

        for path, methods in (spec.get("paths") or {}).items():
            if should_skip_path(path) or not isinstance(methods, dict):
                continue
            for method, details in methods.items():
                method_u = method.upper()
                if method_u not in HTTP_METHODS:
                    continue
                if not isinstance(details, dict):
                    details = {}

                op_security = details.get("security", None)
                requires_auth = (
                    global_security
                    or bool(op_security)
                    or self._security_mentions_auth(details, components_security)
                )
                if op_security == []:
                    requires_auth = False

                endpoints.add(
                    APIEndpoint(
                        method=method_u,
                        path=path,
                        handler=details.get("operationId"),
                        requires_auth=requires_auth,
                        source="swagger",
                        file_location=str(swagger_path),
                        operation_id=details.get("operationId"),
                        description=(details.get("summary") or details.get("description")),
                        is_webhook="/webhook" in path.lower(),
                    )
                )

        return endpoints

    def discover_from_source_code(self) -> Set[APIEndpoint]:
        endpoints: Set[APIEndpoint] = set()

        for url_file in self.project_root.rglob("urls.py"):
            if not is_noise_path(url_file):
                endpoints.update(self._parse_django_urls(url_file))

        for py_file in self.project_root.rglob("*.py"):
            if not is_noise_path(py_file):
                endpoints.update(self._parse_flask_routes(py_file))

        return endpoints

    def discover_partner_endpoints(self) -> Set[APIEndpoint]:
        return catalog_endpoints("partners", PARTNER_CATALOG)

    def discover_payment_endpoints(self) -> Set[APIEndpoint]:
        return catalog_endpoints("payments", PAYMENTS_CATALOG)

    def discover_kyc_endpoints(self) -> Set[APIEndpoint]:
        return catalog_endpoints("kyc", KYC_CATALOG)

    def discover_all(
        self,
        swagger_file: Optional[str] = None,
        include_integrations: bool = True,
        include_source: bool = True,
    ) -> Set[APIEndpoint]:
        all_endpoints: Dict[Tuple[str, str], APIEndpoint] = {}

        def merge(batch: Iterable[APIEndpoint]) -> None:
            for endpoint in batch:
                key = endpoint.key()
                existing = all_endpoints.get(key)
                all_endpoints[key] = (
                    endpoint
                    if existing is None
                    else self._merge_endpoints(existing, endpoint)
                )

        if swagger_file:
            merge(self.discover_from_swagger(swagger_file))
        if include_source:
            merge(self.discover_from_source_code())
        if include_integrations:
            merge(self.discover_partner_endpoints())
            merge(self.discover_payment_endpoints())
            merge(self.discover_kyc_endpoints())

        self.endpoints = set(all_endpoints.values())
        return self.endpoints

    def _resolve_swagger_path(self, swagger_file: str) -> Path:
        swagger_path = Path(swagger_file)
        if swagger_path.is_absolute():
            return swagger_path
        cwd_candidate = Path.cwd() / swagger_path
        root_candidate = self.project_root / swagger_path
        if cwd_candidate.exists():
            return cwd_candidate
        if root_candidate.exists():
            return root_candidate
        return cwd_candidate

    @staticmethod
    def _merge_endpoints(left: APIEndpoint, right: APIEndpoint) -> APIEndpoint:
        preferred_source = (
            left.source
            if SOURCE_RANK.get(left.source, 0) >= SOURCE_RANK.get(right.source, 0)
            else right.source
        )

        file_location = next(
            (
                candidate.file_location
                for candidate in (left, right)
                if candidate.source == "source_code" and candidate.file_location
            ),
            None,
        ) or left.file_location or right.file_location

        swagger_side = (
            left if left.source == "swagger" else right if right.source == "swagger" else None
        )
        description = (
            (swagger_side.description if swagger_side else None)
            or left.description
            or right.description
        )
        operation_id = (
            (swagger_side.operation_id if swagger_side else None)
            or left.operation_id
            or right.operation_id
        )

        return APIEndpoint(
            method=left.method.upper(),
            path=APIEndpoint._normalize_path(left.path),
            handler=left.handler or right.handler,
            requires_auth=left.requires_auth or right.requires_auth,
            integration=left.integration or right.integration,
            source=preferred_source,
            file_location=file_location,
            operation_id=operation_id,
            description=description,
            accepts_partner_id=left.accepts_partner_id or right.accepts_partner_id,
            requires_idempotency_key=(
                left.requires_idempotency_key or right.requires_idempotency_key
            ),
            handles_file_upload=left.handles_file_upload or right.handles_file_upload,
            is_webhook=left.is_webhook or right.is_webhook,
        )

    def _parse_django_urls(self, url_file: Path) -> Set[APIEndpoint]:
        endpoints: Set[APIEndpoint] = set()
        content, err = read_text(url_file)
        if content is None:
            print(f"Warning: Could not read {url_file}: {err}", file=sys.stderr)
            return endpoints

        for match in re.finditer(
            r"""(?:path|re_path)\(\s*['"]([^'"]+)['"]\s*,\s*([A-Za-z0-9_.'"]+)""",
            content,
        ):
            raw_path, handler = match.groups()
            if should_skip_path(raw_path):
                continue
            path = raw_path if raw_path.startswith("/") else f"/{raw_path}"
            endpoints.add(
                APIEndpoint(
                    method="GET",
                    path=path,
                    handler=handler.strip("'\""),
                    source="source_code",
                    file_location=str(url_file),
                    description="Django URL route (method may vary at view layer)",
                )
            )
        return endpoints

    def _parse_flask_routes(self, py_file: Path) -> Set[APIEndpoint]:
        endpoints: Set[APIEndpoint] = set()
        content, _err = read_text(py_file)
        if content is None:
            return endpoints

        pattern = re.compile(
            r"""@(?:app|bp|blueprint|api|router)\.route\(\s*['"]([^'"]+)['"]"""
            r"""(?:[^)]*methods\s*=\s*\[([^\]]+)\])?""",
            re.IGNORECASE,
        )
        for match in pattern.finditer(content):
            path, methods_str = match.groups()
            if should_skip_path(path):
                continue
            methods = self._parse_methods_list(methods_str) if methods_str else ["GET"]
            for method in methods:
                endpoints.add(
                    APIEndpoint(
                        method=method,
                        path=path,
                        source="source_code",
                        file_location=str(py_file),
                    )
                )
        return endpoints

    @staticmethod
    def _parse_methods_list(methods_str: str) -> List[str]:
        methods: List[str] = []
        for raw in methods_str.split(","):
            method = raw.strip().strip("'\"").upper()
            if method in HTTP_METHODS:
                methods.append(method)
        return methods

    @staticmethod
    def _security_mentions_auth(details: dict, schemes: dict) -> bool:
        text = json.dumps({"op": details, "schemes": schemes}).lower()
        return any(
            token in text
            for token in ("bearer", "apikey", "api_key", "oauth", "http", "basic", "jwt")
        )
