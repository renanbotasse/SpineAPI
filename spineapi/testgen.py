"""Generate defensive pytest stubs from discovered endpoints."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, List

from spineapi.models import APIEndpoint

DEFENSIVE_TEST_TEMPLATE = '''\
"""
Defensive API security tests (generated).
Wire these to your app test client / factories.
They assert secure behavior — they do not simulate attacks.
"""

from __future__ import annotations

import hashlib
import hmac

import pytest


@pytest.fixture
def api_client():
    """Return your framework test client."""
    raise NotImplementedError("Provide your test client fixture")


@pytest.fixture
def auth_headers():
    return {"Authorization": "Bearer test-token"}


@pytest.fixture
def webhook_secret():
    return b"test-webhook-secret"


@pytest.mark.parametrize(
    "method,path",
    [
__RATE_LIMIT_CASES__
    ],
)
def test_rate_limited_endpoint_returns_429_when_quota_exhausted(
    api_client, method, path, auth_headers
):
    """
    Precondition: test env rate limit should be low (e.g. 3/min) for this route.
    Drive enough legitimate requests via the test client until the app returns 429.
    """
    status_codes = []
    for _ in range(20):
        response = api_client.open(path, method=method, headers=auth_headers)
        status_codes.append(response.status_code)
        if response.status_code == 429:
            break
    assert 429 in status_codes, f"Expected 429 for {method} {path}, got {status_codes}"


@pytest.mark.parametrize(
    "path",
    [
__WEBHOOK_CASES__
    ],
)
def test_webhook_rejects_invalid_hmac(api_client, path, webhook_secret):
    body = b'{"event":"test"}'
    bad_sig = "sha256=" + ("0" * 64)
    response = api_client.open(
        path,
        method="POST",
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-Signature": bad_sig,
        },
    )
    assert response.status_code in {401, 403}, (
        f"Invalid HMAC must be rejected for {path}, got {response.status_code}"
    )


@pytest.mark.parametrize(
    "path",
    [
__WEBHOOK_CASES__
    ],
)
def test_webhook_accepts_valid_hmac(api_client, path, webhook_secret):
    body = b'{"event":"test"}'
    digest = hmac.new(webhook_secret, body, hashlib.sha256).hexdigest()
    response = api_client.open(
        path,
        method="POST",
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-Signature": f"sha256={digest}",
        },
    )
    assert response.status_code < 500
    assert response.status_code not in {401, 403}


@pytest.mark.parametrize(
    "method,path",
    [
__IDEMPOTENCY_CASES__
    ],
)
def test_duplicate_idempotency_key_is_safe(api_client, method, path, auth_headers):
    headers = {
        **auth_headers,
        "Idempotency-Key": "defensive-test-key-1",
        "Content-Type": "application/json",
    }
    payload = b"{}"
    first = api_client.open(path, method=method, data=payload, headers=headers)
    second = api_client.open(path, method=method, data=payload, headers=headers)
    assert first.status_code < 500
    assert second.status_code < 500
    assert second.status_code in {first.status_code, 409, 422}


def test_partner_rate_limit_buckets_are_isolated(api_client):
    """
    Exhaust partner A's quota, then confirm partner B still succeeds.
    Requires test knobs that set a very low per-partner limit.
    """
    partner_a = {"Authorization": "Bearer partner-a-token"}
    partner_b = {"Authorization": "Bearer partner-b-token"}
    path = "/api/partners/stats"

    for _ in range(50):
        resp = api_client.open(path, method="GET", headers=partner_a)
        if resp.status_code == 429:
            break
    else:
        pytest.skip("Could not exhaust partner A quota in test env")

    other = api_client.open(path, method="GET", headers=partner_b)
    assert other.status_code != 429, (
        "Partner B must not share Partner A's rate-limit bucket"
    )
'''


class DefensiveTestGenerator:
    def __init__(self, endpoints: Iterable[APIEndpoint]) -> None:
        self.endpoints = list(endpoints)

    def generate(self) -> str:
        rate_cases = (
            self._cases(
                [
                    endpoint
                    for endpoint in self.endpoints
                    if endpoint.path.startswith("/api/") and not endpoint.is_webhook
                ][:12]
            )
            or '        ("GET", "/api/health"),'
        )
        webhook_cases = (
            self._path_cases(
                [endpoint for endpoint in self.endpoints if endpoint.is_webhook][:8]
            )
            or '        "/webhooks/example",'
        )
        idem_cases = (
            self._cases(
                [
                    endpoint
                    for endpoint in self.endpoints
                    if endpoint.requires_idempotency_key
                ][:8]
            )
            or '        ("POST", "/api/payments/initiate"),'
        )

        return (
            DEFENSIVE_TEST_TEMPLATE.replace("__RATE_LIMIT_CASES__", rate_cases)
            .replace("__WEBHOOK_CASES__", webhook_cases)
            .replace("__IDEMPOTENCY_CASES__", idem_cases)
        )

    @staticmethod
    def _cases(endpoints: List[APIEndpoint]) -> str:
        return "\n".join(
            f'        ("{endpoint.method}", "{endpoint.path}"),'
            for endpoint in endpoints
        )

    @staticmethod
    def _path_cases(endpoints: List[APIEndpoint]) -> str:
        return "\n".join(f'        "{endpoint.path}",' for endpoint in endpoints)

    def write(self, output_path: str) -> None:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.generate(), encoding="utf-8")
