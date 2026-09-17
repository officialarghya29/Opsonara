"""Opsonara Python SDK — the five-minute developer path (spec §46, §90).

::

    from opsonara_sdk import Opsonara

    ops = Opsonara(
        base_url="https://firewall.example.com",
        api_key="opsk_...",
    )

    result = ops.evaluate(
        action={"type": "refund", "amount": "1500", "currency": "INR"},
        agent={"id": "support-bot", "name": "Support Bot", "permission_level": 2},
        customer={"id": "C92821"},
        order={"id": "ORD-9281", "customer_id": "C92821",
               "status": "delivered", "total": "1500"},
        policy={"brand_id": "my-brand"},
    )

    if result.allowed:
        ...
    elif result.review_required:
        ...
    else:  # blocked
        ...

Design notes:

* stdlib-only (``urllib``) — no dependencies, installs anywhere;
* automatic retries with exponential backoff on 429/5xx/network errors
  (idempotent POSTs only, honoring ``Retry-After``);
* optional HMAC request signing (mirrors the gateway's verification);
* ``execute()`` = evaluate + connector dispatch, so developers never write
  the ``if allowed: execute()`` foot-gun themselves (spec §23).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

__version__ = "0.1.0"

_RETRYABLE = {429, 500, 502, 503, 504}


class OpsonaraError(RuntimeError):
    """Base SDK error; ``status_code`` is set for HTTP failures."""


class ActionBlocked(OpsonaraError):
    """The firewall BLOCKed the action — do not execute it."""


class ReviewRequired(OpsonaraError):
    """The firewall routed the action to human review.

    ``review_id`` identifies the pending item; poll
    ``GET /v1/reviews/{review_id}`` until it resolves.
    """


@dataclass(frozen=True)
class Decision:
    """One firewall verdict (mirrors ``FirewallResponse``)."""

    decision: str  # ALLOW | REVIEW | BLOCK
    authorization: str
    reasons: list[str]
    risk_score: str
    risk_band: str
    blast_radius: dict[str, Any]
    audit_id: str
    review_id: str | None
    raw: dict[str, Any]

    @property
    def allowed(self) -> bool:
        return self.decision == "ALLOW"

    @property
    def review_required(self) -> bool:
        return self.decision == "REVIEW"

    @property
    def blocked(self) -> bool:
        return self.decision == "BLOCK"

    @property
    def max_hourly_exposure(self) -> Decimal | None:
        """Blast-radius headline number, parsed for convenience."""
        value = self.blast_radius.get("max_hourly_exposure")
        return Decimal(str(value)) if value is not None else None


def _sign(secret: str, body: bytes, timestamp: str) -> str:
    message = timestamp.encode() + b"." + body
    return hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()


class Opsonara:
    """Client for the Opsonara Agent Firewall API."""

    def __init__(
        self,
        *,
        base_url: str = "http://localhost:8000",
        api_key: str | None = None,
        signing_secret: str | None = None,
        admin_token: str | None = None,
        timeout: float = 10.0,
        max_retries: int = 3,
        backoff_base: float = 0.4,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._signing_secret = signing_secret
        self._admin_token = admin_token
        self._timeout = timeout
        self._max_retries = max_retries
        self._backoff_base = backoff_base

    # -- public surface -------------------------------------------------------

    def evaluate(
        self,
        *,
        action: dict[str, Any],
        agent: dict[str, Any],
        customer: dict[str, Any],
        policy: dict[str, Any],
        order: dict[str, Any] | None = None,
        conversation: list[dict[str, str]] | None = None,
        metadata: dict[str, Any] | None = None,
        agent_credential: str | None = None,
        mandate: dict[str, Any] | None = None,
        raise_on_block: bool = False,
        idempotency_key: str | None = None,
    ) -> Decision:
        """Evaluate one proposed action through the firewall.

        With ``raise_on_block=True`` a BLOCK raises :class:`ActionBlocked`
        and a REVIEW raises :class:`ReviewRequired` — the "can't mis-handle
        the verdict" style. Default returns the :class:`Decision` either way.

        ``idempotency_key``: send a unique key per logical action (e.g. the
        support ticket id). Retries with the same key replay the original
        verdict instead of executing twice — a timeout can never cause a
        second refund.
        """
        payload: dict[str, Any] = {
            "action": action,
            "agent": agent,
            "customer": customer,
            "policy": policy,
            "conversation": conversation or [],
            "metadata": metadata or {},
        }
        if order is not None:
            payload["order"] = order
        if agent_credential is not None:
            payload["agent_credential"] = agent_credential
        if mandate is not None:
            payload["mandate"] = mandate
        decision = self._decision_from(
            self._request(
                "POST",
                "/v1/evaluate",
                payload,
                idempotency_key=idempotency_key,
            )
        )
        if raise_on_block and decision.blocked:
            raise ActionBlocked(
                f"action blocked by Opsonara: {'; '.join(decision.reasons)}"
            )
        if raise_on_block and decision.review_required:
            raise ReviewRequired(
                f"human review required: {'; '.join(decision.reasons)}",
            )
        return decision

    def execute(
        self,
        *,
        connector_id: str,
        action: dict[str, Any],
        agent: dict[str, Any],
        customer: dict[str, Any],
        policy: dict[str, Any],
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Evaluate + dispatch through a registered connector (spec §23).

        This is the one-call developers should use instead of writing
        ``if allowed: execute()`` themselves — the firewall stays in the
        execution path and post-execution verification runs automatically.
        """
        request = {
            "action": action,
            "agent": agent,
            "customer": customer,
            "policy": policy,
            **kwargs,
        }
        return self._request(
            "POST", f"/v1/connectors/{connector_id}/process", request
        )

    def review(self, review_id: str) -> dict[str, Any]:
        """Fetch one pending review (poll until ``status != 'pending'``)."""
        return self._request("GET", f"/v1/reviews/{review_id}")

    def decide_review(self, review_id: str, *, approved: bool, reviewer: str) -> dict[str, Any]:
        """Resolve a pending review as a human operator."""
        return self._request(
            "POST",
            f"/v1/reviews/{review_id}/decision",
            {"approved": approved, "reviewer": reviewer},
        )

    def audit(self, *, limit: int = 50, decision: str | None = None) -> dict[str, Any]:
        """List audit trail entries."""
        query = f"?limit={int(limit)}" + (f"&decision={decision}" if decision else "")
        return self._request("GET", f"/v1/audit{query}")

    def verify_chain(self) -> dict[str, Any]:
        """Authoritative hash-chain verification."""
        return self._request("GET", "/v1/audit/verify")

    def stats(self) -> dict[str, Any]:
        return self._request("GET", "/v1/stats")

    def health(self) -> dict[str, Any]:
        return self._request("GET", "/health")

    # -- transport -------------------------------------------------------------

    def _decision_from(self, body: dict[str, Any]) -> Decision:
        return Decision(
            decision=str(body.get("decision", "")),
            authorization=str(body.get("authorization", "")),
            reasons=[str(r) for r in body.get("reasons", [])],
            risk_score=str(body.get("risk_score", "0")),
            risk_band=str(body.get("risk_band", "")),
            blast_radius=body.get("blast_radius") or {},
            audit_id=str(body.get("audit_id", "")),
            review_id=body.get("review_id"),
            raw=body,
        )

    def _request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        body = json.dumps(payload).encode() if payload is not None else None
        last_error: Exception | None = None
        for attempt in range(self._max_retries + 1):
            try:
                return self._request_once(
                    method, path, body, idempotency_key=idempotency_key
                )
            except OpsonaraError as exc:
                last_error = exc
                status = getattr(exc, "status_code", None)
                retryable = status in _RETRYABLE or status is None
                if not retryable or attempt >= self._max_retries:
                    raise
                retry_after = float(getattr(exc, "retry_after", 0) or 0)
                delay = max(retry_after, self._backoff_base * (2**attempt))
                time.sleep(min(delay, 5.0))
        raise last_error if last_error else OpsonaraError("unreachable")  # pragma: no cover

    def _request_once(
        self,
        method: str,
        path: str,
        body: bytes | None,
        *,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        headers = {"Content-Type": "application/json"}
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        if self._api_key:
            headers["X-Api-Key"] = self._api_key
        if self._admin_token:
            headers["X-Admin-Token"] = self._admin_token
        if self._signing_secret and body is not None:
            timestamp = str(int(time.time()))
            headers["X-Opsonara-Timestamp"] = timestamp
            headers["X-Opsonara-Signature"] = _sign(self._signing_secret, body, timestamp)
        req = urllib.request.Request(
            f"{self._base_url}{path}", data=body, method=method, headers=headers
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                raw = resp.read().decode()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            error = OpsonaraError(f"HTTP {exc.code} on {method} {path}: {exc.reason}")
            error.status_code = exc.code  # type: ignore[attr-defined]
            retry_header = exc.headers.get("Retry-After") if exc.headers else None
            if retry_header:
                error.retry_after = retry_header  # type: ignore[attr-defined]
            raise error from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            error = OpsonaraError(f"network error on {method} {path}: {exc}")
            error.status_code = None  # type: ignore[attr-defined]
            raise error from exc


__all__ = [
    "ActionBlocked",
    "Decision",
    "Opsonara",
    "OpsonaraError",
    "ReviewRequired",
]
