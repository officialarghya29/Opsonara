"""Tests for inbound webhook ingest: signature verification and endpoints."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

from fastapi.testclient import TestClient

from opsonara.connectors import verify_generic_webhook, verify_shopify_webhook
from opsonara.main import create_app

SECRET = "whsec_test_123"


def _register_connector(client: TestClient) -> None:
    """Register a connector backed by a dry-run executor via the app state."""
    from opsonara.connectors import ShopifyExecutor

    app = client.app
    service = app.state.connector_service
    service.register(
        "conn_hook_test",
        platform="shopify",
        brand_id="brand_test",
        executor=ShopifyExecutor(
            "myshop.myshopify.com", "shpat_x", transport=lambda *a, **k: (200, {}), dry_run=True
        ),
    )


def _evaluate_request() -> dict[str, object]:
    return {
        "action": {
            "type": "refund",
            "order_id": "o1",
            "customer_id": "c1",
            "amount": "500.00",
            "currency": "INR",
            "reason": "webhook test",
        },
        "agent": {"id": "agt_w", "name": "W", "permission_level": 1},
        "customer": {
            "id": "c1",
            "name": "T",
            "email": "c@e.com",
            "lifetime_orders": 5,
            "lifetime_value": "5000.00",
            "previous_refunds": 0,
            "chargebacks": 0,
            "account_age_days": 400,
        },
        "order": {
            "id": "o1",
            "customer_id": "c1",
            "total": "500.00",
            "currency": "INR",
            "status": "delivered",
            "item_count": 1,
        },
        "policy": {
            "brand_id": "brand_test",
            "auto_approve_limit": "2000.00",
            "human_review_limit": "10000.00",
            "block_limit": "25000.00",
        },
    }


class TestSignatureVerification:
    def test_shopify_valid(self) -> None:
        body = b'{"hello": "world"}'
        sig = base64.b64encode(
            hmac.new(SECRET.encode(), body, hashlib.sha256).digest()
        ).decode()
        assert verify_shopify_webhook(body, secret=SECRET, header_value=sig) is True

    def test_shopify_tampered_body_fails(self) -> None:
        body = b'{"hello": "world"}'
        sig = base64.b64encode(
            hmac.new(SECRET.encode(), body, hashlib.sha256).digest()
        ).decode()
        assert (
            verify_shopify_webhook(body + b" ", secret=SECRET, header_value=sig) is False
        )

    def test_shopify_missing_header_or_secret(self) -> None:
        body = b"{}"
        assert verify_shopify_webhook(body, secret=SECRET, header_value=None) is False
        assert verify_shopify_webhook(body, secret="", header_value="x") is False

    def test_generic_valid_with_timestamp(self) -> None:
        body = b'{"k": 1}'
        ts = str(int(time.time()))
        sig = hmac.new(
            SECRET.encode(), f"{ts}.".encode() + body, hashlib.sha256
        ).hexdigest()
        assert (
            verify_generic_webhook(
                body, secret=SECRET, timestamp=ts, signature=sig
            )
            is True
        )

    def test_generic_replay_rejected(self) -> None:
        body = b"{}"
        old_ts = str(int(time.time()) - 10_000)
        sig = hmac.new(
            SECRET.encode(), f"{old_ts}.".encode() + body, hashlib.sha256
        ).hexdigest()
        assert (
            verify_generic_webhook(
                body, secret=SECRET, timestamp=old_ts, signature=sig
            )
            is False
        )

    def test_generic_garbage_timestamp(self) -> None:
        assert (
            verify_generic_webhook(
                b"{}", secret=SECRET, timestamp="not-a-number", signature="x"
            )
            is False
        )


class TestIngestEndpoints:
    def _client(self) -> TestClient:
        app = create_app(
            {
                "seed_demo_data": False,
                "store_backend": "memory",
                "webhook_secrets": f"shopify={SECRET}",
            }
        )
        client = TestClient(app)
        _register_connector(client)
        return client

    def test_shopify_ingest_unauthenticated_rejected(self) -> None:
        client = self._client()
        resp = client.post(
            "/v1/webhooks/shopify",
            json={"connector_id": "conn_hook_test", "request": _evaluate_request()},
        )
        assert resp.status_code == 401

    def test_shopify_ingest_signed_roundtrip(self) -> None:
        client = self._client()
        payload = json.dumps(
            {"connector_id": "conn_hook_test", "request": _evaluate_request()}
        ).encode()
        sig = base64.b64encode(
            hmac.new(SECRET.encode(), payload, hashlib.sha256).digest()
        ).decode()
        resp = client.post(
            "/v1/webhooks/shopify",
            content=payload,
            headers={"Content-Type": "application/json", "X-Shopify-Hmac-Sha256": sig},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["outcome"] == "executed"
        assert body["decision"] == "ALLOW"

    def test_generic_ingest_signed_roundtrip(self) -> None:
        client = self._client()
        payload = json.dumps(
            {"connector_id": "conn_hook_test", "request": _evaluate_request()}
        ).encode()
        ts = str(int(time.time()))
        sig = hmac.new(
            SECRET.encode(), f"{ts}.".encode() + payload, hashlib.sha256
        ).hexdigest()
        resp = client.post(
            "/v1/webhooks/generic",
            content=payload,
            headers={
                "Content-Type": "application/json",
                "X-Opsonara-Timestamp": ts,
                "X-Opsonara-Signature": sig,
            },
        )
        assert resp.status_code == 200
        assert resp.json()["outcome"] == "executed"

    def test_unknown_connector_after_valid_signature(self) -> None:
        client = self._client()
        payload = json.dumps(
            {"connector_id": "conn_missing", "request": _evaluate_request()}
        ).encode()
        sig = base64.b64encode(
            hmac.new(SECRET.encode(), payload, hashlib.sha256).digest()
        ).decode()
        resp = client.post(
            "/v1/webhooks/shopify",
            content=payload,
            headers={"Content-Type": "application/json", "X-Shopify-Hmac-Sha256": sig},
        )
        assert resp.status_code == 404
