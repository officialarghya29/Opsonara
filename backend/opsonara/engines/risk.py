"""Risk Engine — "Could this be dangerous?"

Computes a composite transaction risk score from transparent, weighted
signals:

  ┌────────────────────────┬────────┬───────────────────────────────────┐
  │ Signal                 │ Weight │ Captures                          │
  ├────────────────────────┼────────┼───────────────────────────────────┤
  │ value_size             │  0.30  │ transaction value vs brand limit  │
  │ customer_history       │  0.20  │ trust, account age, chargebacks   │
  │ injection              │  0.25  │ prompt-injection / manipulation   │
  │ behavioral             │  0.15  │ refund frequency/intensity,       │
  │                        │        │ unusual action sequences          │
  │ action_sensitivity     │  0.10  │ how dangerous the action type is  │
  └────────────────────────┴────────┴───────────────────────────────────┘

The composite is a weighted mean, then banded: low < 0.30, medium < 0.55,
high < 0.80, critical ≥ 0.80. Two deterministic escalations apply:

* a confirmed injection verdict forces the band to at least HIGH;
* a near-certain injection (score ≥ 0.80) forces CRITICAL — manipulation
  plus anything else must never sail through.

Every factor carries a human-readable detail string so the audit trail can
explain *why* the score is what it is.
"""

from __future__ import annotations

from decimal import Decimal

from opsonara.core.injection import InjectionReport, analyze_conversation
from opsonara.core.models import (
    HIGH_VALUE_ACTIONS,
    ActionType,
    Decision,
    InjectionVerdict,
    RiskBand,
    RiskFactor,
    RiskResult,
)
from opsonara.engines.context import RequestContext

_WEIGHT_VALUE = Decimal("0.30")
_WEIGHT_CUSTOMER = Decimal("0.20")
_WEIGHT_INJECTION = Decimal("0.25")
_WEIGHT_BEHAVIORAL = Decimal("0.15")
_WEIGHT_SENSITIVITY = Decimal("0.10")

# Baseline sensitivity per action type (how much damage a wrong call does).
_SENSITIVITY: dict[ActionType, Decimal] = {
    ActionType.REFUND: Decimal("0.40"),
    ActionType.STORE_CREDIT: Decimal("0.40"),
    ActionType.PRICE_OVERRIDE: Decimal("0.50"),
    ActionType.UPDATE_SHIPPING: Decimal("0.35"),
    ActionType.CANCEL_ORDER: Decimal("0.30"),
    ActionType.DISCOUNT: Decimal("0.30"),
    ActionType.REPLACEMENT: Decimal("0.20"),
}

_BANDS: tuple[tuple[Decimal, RiskBand], ...] = (
    (Decimal("0.30"), RiskBand.LOW),
    (Decimal("0.55"), RiskBand.MEDIUM),
    (Decimal("0.80"), RiskBand.HIGH),
    (Decimal("1.01"), RiskBand.CRITICAL),
)


def band_for(score: Decimal) -> RiskBand:
    for ceiling, band in _BANDS:
        if score < ceiling:
            return band
    return RiskBand.CRITICAL


def _band_index(band: RiskBand) -> int:
    return list(RiskBand).index(band)


class RiskEngine:
    """Stateless risk scorer — one :meth:`evaluate` call per decision."""

    def evaluate(self, ctx: RequestContext) -> RiskResult:
        injection_report = analyze_conversation(ctx.conversation)
        factors = [
            self._factor_value_size(ctx),
            self._factor_customer_history(ctx),
            self._factor_injection(injection_report),
            self._factor_behavioral(ctx),
            self._factor_sensitivity(ctx),
        ]

        total_weight = sum((f.weight for f in factors), Decimal("0"))
        total = sum((f.score * f.weight for f in factors), Decimal("0")) / total_weight
        total = min(max(total, Decimal("0")), Decimal("1"))

        band = band_for(total)

        # Deterministic escalation: manipulation never sails through.
        reasons: list[str] = []
        if injection_report.verdict == "injected":
            floor = (
                RiskBand.CRITICAL
                if injection_report.score >= Decimal("0.80")
                else RiskBand.HIGH
            )
            if _band_index(band) < _band_index(floor):
                band = floor
            reasons.append(
                "prompt-injection patterns detected in customer conversation"
            )
        elif injection_report.verdict == "suspicious":
            reasons.append("weak manipulation signals present in conversation")

        reasons.extend(
            f.detail for f in factors if f.score >= Decimal("0.35") and f.name != "injection"
        )
        if not reasons:
            reasons.append("all risk signals within normal range")

        return RiskResult(
            total=total.quantize(Decimal("0.0001")),
            band=band,
            factors=factors,
            injection_verdict=InjectionVerdict(injection_report.verdict),
            injection_score=injection_report.score,
            reasons=reasons,
        )

    # ------------------------------------------------------------------
    # factors
    # ------------------------------------------------------------------

    def _factor_value_size(self, ctx: RequestContext) -> RiskFactor:
        """Transaction value relative to the brand's human-review limit.

        Value risk scales with the amount itself — a full refund of a small
        order is routine commerce, while a refund *above* the order total is
        a genuine red flag (double-refund attempt) and maxes the factor.
        """
        limit = ctx.policy.human_review_limit
        amount = ctx.amount
        score = min(amount / limit, Decimal("1")) if limit > 0 else Decimal("1")
        detail = (
            f"amount {amount} {ctx.action.currency} is {score:.0%} of the "
            f"human-review limit {limit}"
        )
        if (
            ctx.order is not None
            and ctx.action.type in HIGH_VALUE_ACTIONS
            and ctx.refund_ratio > Decimal("1")
        ):
            score = Decimal("1")
            detail += "; requested amount exceeds the order total"
        return RiskFactor(
            name="value_size",
            score=score.quantize(Decimal("0.0001")),
            weight=_WEIGHT_VALUE,
            detail=detail,
        )

    def _factor_customer_history(self, ctx: RequestContext) -> RiskFactor:
        """Inverse of the derived trust score plus hard flags."""
        score = Decimal("1") - ctx.history.trust_score
        if "new_account" in ctx.history.flags:
            score = min(score + Decimal("0.10"), Decimal("1"))
        detail = (
            f"trust score {ctx.history.trust_score}, account age "
            f"{ctx.customer.account_age_days}d, {ctx.customer.lifetime_orders} "
            f"lifetime orders"
        )
        if "chargeback_history" in ctx.history.flags:
            detail += f"; {ctx.customer.chargebacks} chargeback(s) on record"
        return RiskFactor(
            name="customer_history",
            score=score.quantize(Decimal("0.0001")),
            weight=_WEIGHT_CUSTOMER,
            detail=detail,
        )

    def _factor_injection(self, report: InjectionReport) -> RiskFactor:
        verdict_detail = {
            "clean": "no manipulation patterns in conversation",
            "suspicious": "weak manipulation signals in conversation",
            "injected": "prompt-injection patterns matched in conversation",
        }[report.verdict]
        return RiskFactor(
            name="injection",
            score=report.score,
            weight=_WEIGHT_INJECTION,
            detail=verdict_detail,
        )

    def _factor_behavioral(self, ctx: RequestContext) -> RiskFactor:
        """Refund frequency/intensity and unusual action sequences."""
        score = max(ctx.history.refund_frequency, ctx.history.refund_intensity * Decimal("0.8"))
        bits: list[str] = [
            f"refund frequency {ctx.history.refund_frequency:.0%}, refund "
            f"intensity {ctx.history.refund_intensity:.0%}"
        ]
        if ctx.customer.previous_refunds >= 2:
            score = min(score + Decimal("0.10"), Decimal("1"))
            bits.append(f"{ctx.customer.previous_refunds} prior refunds")
        # Unusual action sequences from caller-supplied telemetry. The
        # payload is caller-controlled: anything that is not a dict of
        # counts is ignored rather than crashing the evaluate path.
        recent_raw = ctx.metadata.get("recent_action_counts")
        recent: dict[str, int] = recent_raw if isinstance(recent_raw, dict) else {}
        try:
            refunds_24h = int(recent.get("refund", 0))
        except (TypeError, ValueError):
            refunds_24h = 0
        if refunds_24h >= 3:
            score = min(score + Decimal("0.20"), Decimal("1"))
            bits.append(f"unusual sequence: {refunds_24h} refund actions in 24h")
        return RiskFactor(
            name="behavioral",
            score=score.quantize(Decimal("0.0001")),
            weight=_WEIGHT_BEHAVIORAL,
            detail="; ".join(bits),
        )

    def _factor_sensitivity(self, ctx: RequestContext) -> RiskFactor:
        score = _SENSITIVITY.get(ctx.action.type, Decimal("0.20"))
        return RiskFactor(
            name="action_sensitivity",
            score=score,
            weight=_WEIGHT_SENSITIVITY,
            detail=f"action type '{ctx.action.type.value}' baseline sensitivity",
        )


# Composite → decision guidance exported for the decision engine.
RISK_TO_DECISION: dict[RiskBand, Decision] = {
    RiskBand.LOW: Decision.ALLOW,
    RiskBand.MEDIUM: Decision.REVIEW,
    RiskBand.HIGH: Decision.REVIEW,
    RiskBand.CRITICAL: Decision.BLOCK,
}
