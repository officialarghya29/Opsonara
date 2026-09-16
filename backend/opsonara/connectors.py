"""Platform connectors — route native commerce actions through the firewall.

Flow: agent proposes an action on the platform → the connector intercepts
the platform's native API call → runs :meth:`FirewallEngine.evaluate` →
ALLOW decisions execute against the platform API, REVIEW decisions are
held in the human review queue, BLOCK decisions are refused.

Every connector is built on :class:`ActionExecutor` (the only
platform-specific code) so new platforms are one class away.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Protocol

from opsonara.core.models import Decision

# ---------------------------------------------------------------------------
# executors
# ---------------------------------------------------------------------------


class ActionExecutor(Protocol):
    """Executes an ALLOW decision against a platform. Platform-specific."""

    def execute(self, request: dict[str, Any], decision: dict[str, Any]) -> dict[str, Any]: ...

    def hold(self, request: dict[str, Any], decision: dict[str, Any]) -> dict[str, Any]: ...

    def refuse(self, request: dict[str, Any], decision: dict[str, Any]) -> dict[str, Any]: ...


@dataclass
class ExecutionResult:
    action: str  # executed | held | refused
    platform: str
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"action": self.action, "platform": self.platform, **self.detail}


class ShopifyExecutor:
    """Executes refunds/order-holds via the Shopify REST Admin API.

    ``access_token`` is a per-store Admin API access token. Network calls
    are injectable (``transport``) for hermetic tests and offline dry-run.
    """

    def __init__(
        self, shop_domain: str, access_token: str, *, transport: Any = None, dry_run: bool = False
    ) -> None:
        self.shop_domain = shop_domain
        self.access_token = access_token
        self.dry_run = dry_run
        self._transport = transport or _default_transport

    def execute(self, request: dict[str, Any], decision: dict[str, Any]) -> dict[str, Any]:
        action = request["action"]
        if self.dry_run:
            return {"simulated": True, "endpoint": self._endpoint_for(action)}
        status, body = self._transport(
            self._endpoint_for(action), method="POST", payload=action, token=self.access_token
        )
        return {"status": status, "response": body}

    def hold(self, request: dict[str, Any], decision: dict[str, Any]) -> dict[str, Any]:
        # REVIEW: place the order on hold via a note + risk flag, don't refund.
        if self.dry_run:
            return {"simulated": True, "held": True, "review_id": decision.get("review_id")}
        status, body = self._transport(
            f"https://{self.shop_domain}/admin/api/2024-10/orders/{request['action']['order_id']}.json",
            method="PUT",
            payload={"order": {"id": request["action"]["order_id"], "note": "Opsonara review hold"}},
            token=self.access_token,
        )
        return {"status": status, "response": body, "review_id": decision.get("review_id")}

    def refuse(self, request: dict[str, Any], decision: dict[str, Any]) -> dict[str, Any]:
        return {"blocked": True, "reasons": decision.get("reasons", [])}

    def _endpoint_for(self, action: dict[str, Any]) -> str:
        kind = action.get("type", "refund")
        if kind == "refund":
            return (
                f"https://{self.shop_domain}/admin/api/2024-10/orders/"
                f"{action['order_id']}/refunds.json"
            )
        if kind == "cancel_order":
            return (
                f"https://{self.shop_domain}/admin/api/2024-10/orders/"
                f"{action['order_id']}/cancel.json"
            )
        return f"https://{self.shop_domain}/admin/api/2024-10/orders/{action['order_id']}.json"


class WooCommerceExecutor:
    """Executes refunds/order updates via the WooCommerce REST API v3."""

    def __init__(
        self,
        store_url: str,
        consumer_key: str,
        consumer_secret: str,
        *,
        transport: Any = None,
        dry_run: bool = False,
    ) -> None:
        self.store_url = store_url.rstrip("/")
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret
        self.dry_run = dry_run
        self._transport = transport or _default_transport

    def execute(self, request: dict[str, Any], decision: dict[str, Any]) -> dict[str, Any]:
        action = request["action"]
        if self.dry_run:
            return {"simulated": True, "endpoint": self._endpoint_for(action)}
        status, body = self._transport(
            self._endpoint_for(action),
            method="POST",
            payload=action,
            auth=(self.consumer_key, self.consumer_secret),
        )
        return {"status": status, "response": body}

    def hold(self, request: dict[str, Any], decision: dict[str, Any]) -> dict[str, Any]:
        if self.dry_run:
            return {"simulated": True, "held": True, "review_id": decision.get("review_id")}
        status, body = self._transport(
            f"{self.store_url}/wp-json/wc/v3/orders/{request['action']['order_id']}",
            method="PUT",
            payload={"status": "on-hold", "customer_note": "Opsonara review hold"},
            auth=(self.consumer_key, self.consumer_secret),
        )
        return {"status": status, "response": body, "review_id": decision.get("review_id")}

    def refuse(self, request: dict[str, Any], decision: dict[str, Any]) -> dict[str, Any]:
        return {"blocked": True, "reasons": decision.get("reasons", [])}

    def _endpoint_for(self, action: dict[str, Any]) -> str:
        kind = action.get("type", "refund")
        order_id = action.get("order_id", "")
        if kind == "refund":
            return f"{self.store_url}/wp-json/wc/v3/orders/{order_id}/refunds"
        if kind == "cancel_order":
            return f"{self.store_url}/wp-json/wc/v3/orders/{order_id}"
        return f"{self.store_url}/wp-json/wc/v3/orders/{order_id}"


class WebhookExecutor:
    """Generic adapter: forwards ALLOW decisions to any webhook endpoint."""

    def __init__(self, target_url: str, *, secret: str | None = None, transport: Any = None,
                 dry_run: bool = False) -> None:
        self.target_url = target_url
        self.secret = secret
        self.dry_run = dry_run
        self._transport = transport or _default_transport

    def execute(self, request: dict[str, Any], decision: dict[str, Any]) -> dict[str, Any]:
        if self.dry_run:
            return {"simulated": True, "target": self.target_url}
        headers = {}
        if self.secret:
            import hashlib
            import hmac as _hmac
            import time as _time

            ts = str(int(_time.time()))
            sig = _hmac.new(
                self.secret.encode(), ts.encode() + json.dumps(request).encode(), hashlib.sha256
            ).hexdigest()
            headers = {"X-Opsonara-Timestamp": ts, "X-Opsonara-Signature": sig}
        status, body = self._transport(
            self.target_url, method="POST", payload=request, headers=headers
        )
        return {"status": status, "response": body}

    def hold(self, request: dict[str, Any], decision: dict[str, Any]) -> dict[str, Any]:
        return {"held": True, "review_id": decision.get("review_id")}

    def refuse(self, request: dict[str, Any], decision: dict[str, Any]) -> dict[str, Any]:
        return {"blocked": True, "reasons": decision.get("reasons", [])}


def verify_shopify_webhook(
    raw_body: bytes, *, secret: str, header_value: str | None
) -> bool:
    """Verify an inbound Shopify webhook's ``X-Shopify-Hmac-Sha256`` header.

    Shopify signs the *raw* request body with base64(HMAC-SHA256(secret, body)).
    Timing-safe compare; returns False for missing/garbled headers so a
    forged webhook can never reach the firewall unauthenticated.
    """
    import base64
    import hashlib
    import hmac as _hmac

    if not header_value or not secret:
        return False
    try:
        expected = base64.b64encode(
            _hmac.new(secret.encode(), raw_body, hashlib.sha256).digest()
        ).decode()
    except Exception:  # pragma: no cover - defensive
        return False
    return _hmac.compare_digest(expected, header_value)


def verify_generic_webhook(
    raw_body: bytes, *, secret: str, timestamp: str | None, signature: str | None
) -> bool:
    """Verify an inbound generic webhook (hex HMAC over ``{ts}.{body}``).

    Mirrors the outbound signing the :class:`WebhookExecutor` performs, so
    the same secret works both directions. Timestamp tolerance is ±5 min.
    """
    import hashlib
    import hmac as _hmac
    import time as _time

    if not signature or not secret:
        return False
    try:
        ts = int(timestamp or "")
    except ValueError:
        return False
    if abs(_time.time() - ts) > 300:
        return False
    expected = _hmac.new(
        secret.encode(), f"{ts}.".encode() + raw_body, hashlib.sha256
    ).hexdigest()
    return _hmac.compare_digest(expected, signature)


def _default_transport(
    url: str,
    *,
    method: str = "POST",
    payload: Any = None,
    token: str | None = None,
    auth: tuple[str, str] | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    """Blocking HTTPS call used in production (tests inject fakes)."""
    data = json.dumps(payload).encode() if payload is not None else b""
    req_headers = {"Content-Type": "application/json"}
    if token:
        req_headers["X-Shopify-Access-Token"] = token
    if auth:
        import base64

        req_headers["Authorization"] = "Basic " + base64.b64encode(
            f"{auth[0]}:{auth[1]}".encode()
        ).decode()
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, data=data if method != "GET" else None,
                                 method=method, headers=req_headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as exc:
        return exc.code, {"error": str(exc.reason)}


# ---------------------------------------------------------------------------
# connector service
# ---------------------------------------------------------------------------


class ConnectorService:
    """Routes evaluate requests through the firewall and executes outcomes."""

    def __init__(
        self,
        firewall: Any,
        review_store: Any,
        *,
        verifier: Any = None,
    ) -> None:
        """``verifier``: optional :class:`~opsonara.verification.ExecutionVerifier`.
        When set, ALLOW executions are post-verified against the platform's
        reported result (spec §24)."""
        self._firewall = firewall
        self._review_store = review_store
        self._verifier = verifier
        self._lock = threading.Lock()
        self._connectors: dict[str, dict[str, Any]] = {}

    def register(self, connector_id: str, *, platform: str, executor: ActionExecutor,
                 brand_id: str) -> dict[str, Any]:
        entry = {
            "connector_id": connector_id,
            "platform": platform,
            "brand_id": brand_id,
            "executor": executor,
        }
        with self._lock:
            self._connectors[connector_id] = entry
        return {k: v for k, v in entry.items() if k != "executor"}

    def get(self, connector_id: str) -> dict[str, Any]:
        with self._lock:
            return self._connectors[connector_id]

    def list(self) -> list[dict[str, Any]]:
        with self._lock:
            return [
                {k: v for k, v in e.items() if k != "executor"}
                for e in self._connectors.values()
            ]

    def process(self, connector_id: str, request: dict[str, Any]) -> dict[str, Any]:
        """Evaluate, then dispatch to the platform executor by decision.

        ALLOW executions are post-verified (spec §24): the executor's actual
        result is compared with the requested amount and a tamper-evident
        ``execution_verification`` audit record is appended. A mismatch sets
        ``verification.mismatch`` and carries a HIGH-band BLOCK record — the
        caller (dashboard/alerting) decides on containment.
        """
        with self._lock:
            entry = self._connectors.get(connector_id)
        if entry is None:
            raise KeyError(f"unknown connector '{connector_id}'")
        executor: ActionExecutor = entry["executor"]
        verdict = self._firewall.evaluate_request(request)
        decision = verdict.decision.value if hasattr(verdict.decision, "value") else verdict.decision
        verification: dict[str, Any] | None = None
        if decision == Decision.ALLOW.value:
            detail = executor.execute(request, {"decision": decision})
            outcome = "executed"
            if self._verifier is not None:
                result = self._verifier.verify(
                    request=request,
                    execution=detail,
                    audit_id=verdict.audit_id,
                    connector_id=connector_id,
                )
                verification = {
                    "status": result.status,
                    "requested": str(result.requested_amount),
                    "executed": str(result.executed_amount)
                    if result.executed_amount is not None
                    else None,
                    "difference": str(result.difference)
                    if result.difference is not None
                    else None,
                    "mismatch": result.mismatch,
                    "audit_id": result.audit_id,
                }
                if result.mismatch:
                    outcome = "executed_with_mismatch"
        elif decision == Decision.REVIEW.value:
            review_id = self._hold_for_review(verdict, request)
            detail = executor.hold(request, {"decision": decision, "review_id": review_id})
            outcome = "held"
        else:
            detail = executor.refuse(request, {"decision": decision, **verdict.audit})
            outcome = "refused"
        return {
            "connector_id": connector_id,
            "platform": entry["platform"],
            "outcome": outcome,
            "decision": decision,
            "audit_id": verdict.audit_id,
            "review_id": verdict.review_id,
            "reasons": verdict.reasons,
            "execution": detail,
            "verification": verification,
        }

    def _hold_for_review(self, verdict: Any, request: dict[str, Any]) -> str | None:
        # The firewall already enqueued the review when the decision was
        # REVIEW; verdict.review_id carries it.
        return str(verdict.review_id) if verdict.review_id else None


__all__ = [
    "ConnectorService",
    "ExecutionResult",
    "ShopifyExecutor",
    "WebhookExecutor",
    "WooCommerceExecutor",
    "verify_generic_webhook",
    "verify_shopify_webhook",
]
