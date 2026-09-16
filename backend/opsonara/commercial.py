"""Commercial layer — usage metering, billing hooks, customer explainer.

* **Metering** — every protected API call records a usage event per brand.
* **Billing** — usage rolls up into billing periods; when a Stripe secret
  key is configured and ``billing_dry_run`` is off, the period summary is
  POSTed to Stripe meter events; otherwise it is reported locally only.
* **Explainer** — a stripped-down, non-internal version of an audit record
  safe to show the end customer ("your refund needs a quick review
  because..."). Internal details (policy ids, factor internals, agent
  internals) never leak.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from opsonara.core.models import Decision

# ---------------------------------------------------------------------------
# metering
# ---------------------------------------------------------------------------


@dataclass
class UsageEvent:
    brand_id: str
    endpoint: str
    decision: str | None
    at: datetime = field(default_factory=lambda: datetime.now(UTC))


class UsageMeter:
    """Thread-safe, in-memory usage meter with monthly roll-ups."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: list[UsageEvent] = []
        self._by_period: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        """period (YYYY-MM) -> brand_id -> count."""

    def record(self, brand_id: str, endpoint: str, decision: str | None = None) -> UsageEvent:
        event = UsageEvent(brand_id=brand_id, endpoint=endpoint, decision=decision)
        period = event.at.strftime("%Y-%m")
        with self._lock:
            self._events.append(event)
            self._by_period[period][brand_id] += 1
        return event

    def usage(self, brand_id: str | None = None, period: str | None = None) -> dict[str, Any]:
        with self._lock:
            if period is None:
                period = datetime.now(UTC).strftime("%Y-%m")
            counts = dict(self._by_period.get(period, {}))
            if brand_id is not None:
                counts = {b: c for b, c in counts.items() if b == brand_id}
            total = sum(counts.values())
            decisions: dict[str, int] = defaultdict(int)
            for e in self._events:
                if e.at.strftime("%Y-%m") == period and (brand_id is None or e.brand_id == brand_id):
                    if e.decision:
                        decisions[e.decision] += 1
            return {
                "period": period,
                "total": total,
                "by_brand": counts,
                "by_decision": dict(decisions),
            }


# ---------------------------------------------------------------------------
# billing
# ---------------------------------------------------------------------------


class StripeBilling:
    """Usage-based billing hook (Stripe meter events), dry-run by default."""

    def __init__(
        self,
        meter: UsageMeter,
        *,
        api_key: str = "",
        dry_run: bool = True,
        unit_amount_cents: int = 1,
        transport: Any = None,
    ) -> None:
        self._meter = meter
        self._api_key = api_key
        self._dry_run = dry_run
        self._unit_amount_cents = unit_amount_cents
        self._transport = transport or _stripe_transport

    def invoice_preview(self, brand_id: str, *, period: str | None = None) -> dict[str, Any]:
        usage = self._meter.usage(brand_id=brand_id, period=period)
        amount = usage["total"] * self._unit_amount_cents
        return {
            "brand_id": brand_id,
            "period": usage["period"],
            "evaluate_calls": usage["total"],
            "unit_amount_cents": self._unit_amount_cents,
            "amount_cents": amount,
            "mode": "dry_run" if self._dry_run else "live",
        }

    def report_period(self, brand_id: str, *, period: str | None = None) -> dict[str, Any]:
        """Roll up one brand-period and (optionally) send it to Stripe."""
        preview = self.invoice_preview(brand_id, period=period)
        if self._dry_run or not self._api_key:
            return {**preview, "sent": False, "reason": "dry_run" if self._dry_run else "no_api_key"}
        status, body = self._transport(
            "https://api.stripe.com/v1/billing/meter_events",
            api_key=self._api_key,
            payload={
                "event_name": "opsonara_evaluate",
                "payload": {
                    "value": str(preview["evaluate_calls"]),
                    "stripe_customer_id": brand_id,
                },
            },
        )
        return {**preview, "sent": 200 <= status < 300, "status": status, "response": body}


def _stripe_transport(url: str, *, api_key: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as exc:
        return exc.code, {"error": str(exc.reason)}


# ---------------------------------------------------------------------------
# customer-facing explainer
# ---------------------------------------------------------------------------

_INTERNAL_HINTS = ("policy_pack", "pack_", "agt_", "level", "fw", "credential")


class DecisionExplainer:
    """Public-safe view of a decision for the brand's support flow."""

    _FRIENDLY_ACTIONS = {
        "refund": "refund",
        "store_credit": "store credit",
        "price_override": "price change",
        "update_shipping": "shipping update",
        "cancel_order": "order cancellation",
        "discount": "discount",
        "replacement": "replacement",
    }
    _DECISION_LEAD = {
        Decision.ALLOW.value: "has been approved automatically",
        Decision.REVIEW.value: "needs a quick human review",
        Decision.BLOCK.value: "could not be approved",
    }

    def explain(self, audit: dict[str, Any]) -> dict[str, Any]:
        """Return a customer-safe explanation from an audit dict."""
        action = str(audit.get("action", "request"))
        friendly = self._FRIENDLY_ACTIONS.get(action, action)
        decision = str(audit.get("decision", ""))
        lead = self._DECISION_LEAD.get(decision, "is being processed")

        # Filter reasons: keep the human-meaningful prefix, drop internals.
        reasons = [
            r
            for r in audit.get("reasons", [])
            if isinstance(r, str) and not any(h in r.lower() for h in _INTERNAL_HINTS)
        ]
        # Strip engine-technical prefixes like "amount 799.00 within ...".
        clean_reasons = [r.split(" within ")[0] if " within " in r else r for r in reasons][:3]

        amount = audit.get("amount")
        currency = audit.get("currency", "")
        headline = f"Your {friendly} request"
        if amount is not None:
            try:
                headline += f" for {currency} {amount}"
            except (TypeError, ValueError):
                pass
        headline += f" {lead}."

        return {
            "headline": headline,
            "status": {"ALLOW": "approved", "REVIEW": "in_review", "BLOCK": "declined"}.get(
                decision, "processing"
            ),
            "reasons": clean_reasons,
            "next_step": self._next_step(decision),
        }

    @staticmethod
    def _next_step(decision: str) -> str:
        if decision == Decision.REVIEW.value:
            return "A specialist will look at this shortly — no action needed from you."
        if decision == Decision.BLOCK.value:
            return "Please contact support so we can help you directly."
        return "Nothing further is needed — you're all set."


__all__ = ["DecisionExplainer", "StripeBilling", "UsageEvent", "UsageMeter"]
