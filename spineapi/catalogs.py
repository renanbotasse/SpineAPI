"""Built-in generic endpoint catalogs (partners, payments, KYC)."""

from __future__ import annotations

from typing import Dict, Iterable, Set, Tuple

from spineapi.models import APIEndpoint

CatalogRow = Tuple[str, str, str, Dict[str, object]]

PARTNER_CATALOG: Tuple[CatalogRow, ...] = (
    ("GET", "/api/partners", "List partners", {}),
    ("POST", "/api/partners", "Create partner", {}),
    ("GET", "/api/partners/{id}", "Get partner by id", {"accepts_partner_id": True}),
    ("PUT", "/api/partners/{id}", "Update partner", {"accepts_partner_id": True}),
    ("POST", "/api/partners/{id}/verify", "Verify partner", {"accepts_partner_id": True}),
    ("GET", "/api/partners/{id}/loans", "List partner loans", {"accepts_partner_id": True}),
    ("GET", "/api/partners/stats", "Partner stats", {}),
    (
        "POST",
        "/webhooks/partners/events",
        "Partner event webhook",
        {"requires_auth": False, "is_webhook": True},
    ),
)

PAYMENTS_CATALOG: Tuple[CatalogRow, ...] = (
    (
        "POST",
        "/api/payments/initiate",
        "Initiate payment",
        {"requires_idempotency_key": True},
    ),
    ("GET", "/api/payments/{payment_id}", "Get payment", {}),
    (
        "POST",
        "/api/payments/{payment_id}/capture",
        "Capture payment",
        {"requires_idempotency_key": True},
    ),
    (
        "POST",
        "/api/payments/{payment_id}/refund",
        "Refund payment",
        {"requires_idempotency_key": True},
    ),
    (
        "POST",
        "/webhooks/payments/payment-callback",
        "Payment callback webhook",
        {"requires_auth": False, "is_webhook": True},
    ),
    (
        "POST",
        "/webhooks/payments/status-update",
        "Payment status update webhook",
        {"requires_auth": False, "is_webhook": True},
    ),
    ("GET", "/api/payments/transactions", "List transactions", {}),
)

KYC_CATALOG: Tuple[CatalogRow, ...] = (
    (
        "POST",
        "/api/kyc/documents/upload",
        "Upload KYC document",
        {"handles_file_upload": True},
    ),
    ("GET", "/api/kyc/documents/{doc_id}", "Get KYC document", {}),
    ("POST", "/api/kyc/verify", "Verify KYC", {}),
    ("GET", "/api/kyc/status/{user_id}", "KYC status", {}),
    (
        "POST",
        "/webhooks/kyc/document-processed",
        "KYC document processed webhook",
        {"requires_auth": False, "is_webhook": True},
    ),
    (
        "POST",
        "/webhooks/kyc/signature-complete",
        "KYC signature complete webhook",
        {"requires_auth": False, "is_webhook": True},
    ),
    ("GET", "/api/kyc/documents/{user_id}/list", "List user KYC documents", {}),
)


def catalog_endpoints(integration: str, rows: Iterable[CatalogRow]) -> Set[APIEndpoint]:
    endpoints: Set[APIEndpoint] = set()
    for method, path, description, flags in rows:
        endpoints.add(
            APIEndpoint(
                method=method,
                path=path,
                requires_auth=bool(flags.get("requires_auth", True)),
                integration=integration,
                source="catalog",
                description=description,
                accepts_partner_id=bool(flags.get("accepts_partner_id", False)),
                requires_idempotency_key=bool(flags.get("requires_idempotency_key", False)),
                handles_file_upload=bool(flags.get("handles_file_upload", False)),
                is_webhook=bool(flags.get("is_webhook", False)),
            )
        )
    return endpoints
